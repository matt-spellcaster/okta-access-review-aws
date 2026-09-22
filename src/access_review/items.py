"""Review items: every piece of access the reviewer has to confirm, with a
proposed decision.

One item per app a person can reach (and by which route), per admin role they
hold, and per admin group they are in. Each carries a proposal, but proposals
are only proposals: the CISO, the single reviewer, confirms or overrides them
in Slack and then signs off on the result.

Proposals follow one rule for judgment calls -- revoke direct app access that
has not been used in `app_unused_days` -- and never propose revoking anything
on missing or incomplete data. When unsure, the item is left for a person to
decide.
"""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, timedelta

from .checks import (
    GRAPH_CHECKS,
    SEVERITIES,
    Finding,
    ReviewContext,
    app_usage_covers,
    graph_findings_by_identity,
    records_sign_ins,
)
from .identity import OKTA, Link, LinkMethod, identity_key
from .models import App, User

KEEP, REVOKE, DECIDE = "keep", "revoke", "decide"
PROPOSALS = (KEEP, REVOKE, DECIDE)
# An account with no HR record (AR-03) is its own item: the CISO acknowledges it
# and raises it with HR. It is settled outside the review, so acknowledging is
# recorded as "keep" and no ticket is ever opened for it.
HR_RECORD = "hr_record"
HR_REASON = ("No HR record. Raise it with HR: add them to the roster, list them as a service account in the "
             "config, or have the account deactivated. This is handled outside the review, and no ticket is "
             "opened for it.")
# A person whose only problem is in another source. Review items are built from
# Okta access, so someone whose Okta offboarding actually completed has no items
# at all -- and their cross-source finding, which is exactly what this tool
# exists to surface, would reach no decision screen. The better the Okta
# hygiene, the more certain the finding is to be invisible. This item exists so
# that person still appears.
CROSS_SOURCE = "cross_source"
CROSS_SOURCE_TARGET = "Access outside Okta"
CROSS_SOURCE_REASON = ("They hold no access in Okta, but another source still does. This review cannot change "
                       "access outside Okta: acknowledge it here, and the finding's own ticket tracks the fix.")
# Kinds settled by acknowledging rather than by keep/revoke: the review records
# that the reviewer saw them, and the work happens elsewhere.
ACKNOWLEDGE_ONLY = (HR_RECORD, CROSS_SOURCE)
# Reviewer roles. Every new item goes to the CISO; "admin" only appears in item
# files from reviews run before there was a single reviewer.
ADMIN, CISO = "admin", "ciso"
ITEMS_FILE = "review_items.json"
FORMAT = 3  # 2 added name, facts and concerns; 3 split outside_okta out of concerns
READABLE_FORMATS = (1, 2, 3)
# The phrase `outside_okta_concerns` writes into every line it produces. Named
# because `load_items` reads it back to split a format 2 file, and a marker the
# writer and the reader spell separately is a marker that drifts.
LINK_MARKER = "; tied to them by "
# Findings about a person that matter for every piece of their access. AR-11
# (admin user) only matters on admin items, AR-14 on the one unused app, and
# AR-10 is about API clients, not people.
PERSON_CHECKS = ("AR-01", "AR-02", "AR-03", "AR-04", "AR-05", "AR-06", "AR-07", "AR-08", "AR-09", "AR-12", "AR-13")
# What a link method means, for a reviewer deciding how much weight to give it.
# The ladder is named evidence rather than a score precisely so this can be
# said in words at the point where someone acts on it.
LINK_BASIS = {
    LinkMethod.SSO_IDENTITY: "the identity provider's own assertion",
    LinkMethod.VERIFIED_EMAIL: "an email address the source itself states is verified",
    LinkMethod.DECLARED: "a register entry someone signed up to",
    LinkMethod.CREATOR: "an audit record of who created it, so accountable rather than necessarily the owner",
}


class ItemsError(ValueError):
    pass


@dataclass(frozen=True)
class ReviewItem:
    key: str  # stable across runs for the same access, so decisions and tickets line up
    kind: str  # "app", "admin_role", "admin_group", "hr_record" or "cross_source"
    user_id: str
    user: str  # Okta login
    target_id: str
    target: str  # app label, role label or group name
    via: str  # "direct", "group:<name>" or "role"
    proposed: str  # keep, revoke or decide
    reason: str
    reviewer: str  # always ciso for new reviews
    # What the reviewer is shown: the person's name, the facts, and why it could
    # be an issue. Saved with the items, so the evidence shows what they saw.
    name: str = ""
    facts: tuple[str, ...] = ()
    concerns: tuple[str, ...] = ()
    # Concerns about access in another source, kept apart from `concerns`
    # because deciding this item cannot settle any of them. Everything in
    # `concerns` is either about this access or about the person in Okta, so a
    # revoke ticket can carry it and the daily Okta re-check can close it.
    # These cannot be closed that way, and a ticket listing them alongside the
    # rest asserts that removing an Okta assignment dealt with a credential
    # Okta has never been able to see.
    outside_okta: tuple[str, ...] = ()
    # Why `outside_okta` may be short, empty when nothing is missing. An empty
    # list has three causes -- no other source was read, one was read and this
    # person could not be joined to it, or one was read completely and found
    # nothing -- and only the last is evidence a departure finished. Without
    # this the card renders "Nothing flagged" and the ticket says nothing, which
    # is the review asserting a clean bill of health it never checked.
    outside_okta_gap: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> ReviewItem:
        fields = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        for k in ("facts", "concerns", "outside_okta"):
            fields[k] = tuple(fields.get(k, ()))
        item = cls(**fields)
        if item.proposed not in PROPOSALS or item.reviewer not in (ADMIN, CISO):
            raise ItemsError(f"item {item.key}: bad proposal or reviewer")
        return item


def item_key(kind: str, user_id: str, target_id: str, via: str) -> str:
    return hashlib.sha256(f"{kind}\x1f{user_id}\x1f{target_id}\x1f{via}".encode()).hexdigest()[:16]


def _app_proposal(ctx: ReviewContext, user: User, app: App, via: str) -> tuple[str, str]:
    cfg = ctx.config
    entry = ctx.roster_entry(user)
    if user.status == "DEPROVISIONED":
        return REVOKE, "Account is deactivated; remove so reactivating it doesn't restore access."
    if entry and entry.is_gone(ctx.as_of):
        when = f" ({entry.end_date})" if entry.end_date else ""
        return REVOKE, f"HR shows they have left{when}."
    if user.status == "SUSPENDED":
        return DECIDE, "Account is suspended; decide whether access should remain while it is."
    if ctx.is_service_account(user):
        return DECIDE, "Service account; its use doesn't show up as sign-ins."
    if not records_sign_ins(app):
        return DECIDE, "This app doesn't record sign-ins in Okta, so usage can't be checked."
    if app.label.lower() in {a.lower() for a in cfg.activity_exempt_apps}:
        return DECIDE, "This app is exempt from the usage rule in the config."
    if not app_usage_covers(ctx.snapshot, cfg.app_unused_days, ctx.as_of):
        return DECIDE, "App sign-in data is missing or incomplete for this review."

    cutoff = ctx.as_of - timedelta(days=cfg.app_unused_days)
    last = ctx.snapshot.last_app_sign_in(user.id, app.id)
    if last and last.date() >= cutoff:
        return KEEP, f"Signed in {last.date()}."
    unused = f"No sign-in in {cfg.app_unused_days} days"
    if via != "direct":
        return DECIDE, f"{unused}, but access comes from {via.removeprefix('group:')}; removing them from the group may change other access."
    assigned = app.assigned.get(user.id)
    if assigned is None:
        return DECIDE, f"{unused}; the assignment date is unknown."
    if assigned.date() >= cutoff:
        return KEEP, f"Assigned {assigned.date()}, less than {cfg.app_unused_days} days ago."
    return REVOKE, f"{unused} (assigned {assigned.date()})."


def _day(value) -> str:
    return value.date().isoformat() if value else "never"


def person_facts(ctx: ReviewContext, user: User) -> list[str]:
    """What Okta and HR say about the person, one line each."""
    mfa = "unknown" if user.factors is None else (", ".join(user.factors) if user.factors else "none")
    okta = f"Okta: {user.status} · last sign-in {_day(user.last_login)} · MFA: {mfa}"
    entry = ctx.roster_entry(user)
    if entry is None:
        hr = "HR: no record" + (" (listed as a service account)" if ctx.is_service_account(user) else "")
    else:
        hr = f"HR: {entry.employment_type}, {entry.status}"
        if entry.end_date:
            hr += f" · end date {entry.end_date}"
        manager = entry.manager or user.manager
        hr += f" · manager {manager}" if manager else " · no manager"
    if user.department:
        hr += f" · {user.department}"
    return [okta, hr]


def access_fact(ctx: ReviewContext, user: User, kind: str, target: str, via: str, app: App | None) -> str:
    route = "assigned directly" if via == "direct" else ("admin role" if via == "role" else
                                                         f"through group {via.removeprefix('group:')}")
    line = f"Access: {target} ({route})"
    if app is not None:
        if via == "direct" and app.assigned.get(user.id):
            line += f" · assigned {_day(app.assigned[user.id])}"
        if records_sign_ins(app) and ctx.snapshot.app_usage_since is not None:
            last = ctx.snapshot.last_app_sign_in(user.id, app.id)
            line += f" · last used {_day(last)}" if last else \
                f" · not used since at least {ctx.snapshot.app_usage_since.date()}"
    return line


def _worst_first(concerns: list[tuple[str, str]]) -> list[str]:
    """Order finding-derived concerns by severity, worst first.

    The reviewer reads the top of the list. A critical finding about access
    Okta cannot reach is the single most useful thing on the screen and must
    not sit below three medium notes. Stable within a severity, so the order
    findings already came in is kept.
    """
    return [text for _, text in sorted(concerns, key=lambda c: SEVERITIES.index(c[0]))]


def concerns_for(findings, user: User, kind: str, app: App | None) -> list[str]:
    """Why this access could be an issue, from what Okta and HR say: the
    findings about this person and the findings about this access specifically.

    Only findings a decision here can act on. What the person holds in another
    source goes to `outside_okta_concerns`, which the reviewer sees just as
    plainly and a ticket treats differently.
    """
    login = user.login.lower()
    out: list[tuple[str, str]] = []
    for f in findings:
        subject = f.subject.lower()
        if f.check_id in PERSON_CHECKS and subject == login:
            out.append((f.severity, f"{f.detail} ({f.check_id} {f.title})"))
        elif f.check_id == "AR-11" and subject == login and kind in ("admin_role", "admin_group"):
            out.append((f.severity, f"{f.detail} ({f.check_id} {f.title})"))
        elif f.check_id == "AR-14" and app is not None and subject == f"{login} / {app.label.lower()}":
            out.append((f.severity, f"{f.detail} ({f.check_id} {f.title})"))
    return _worst_first(out)


def outside_okta_gap(graph) -> str:
    """Why what someone holds outside Okta may be unknown, or "" when it is not.

    Emptiness is only evidence when the read that would have said so ran. This
    is the sentence that says which of the three it is, so a card showing no
    cross-source concern is not read as a clean bill of health.
    """
    if graph is None:
        return ("No source other than Okta was read in this review, so what they hold elsewhere "
                "is not known.")
    others = [m for m in graph.sources if m.source != OKTA]
    if not others:
        return ("No source other than Okta was read in this review, so what they hold elsewhere "
                "is not known.")
    short = sorted(m.source for m in others if not m.complete)
    if short:
        return (f"The {', '.join(short)} read did not complete, so what they hold there may be "
                f"missing from this list.")
    return ""


def outside_okta_concerns(
    user: User, graph_by_identity: dict[str, list[tuple[Finding, Link]]] | None
) -> list[str]:
    """What this person holds in another source entirely.

    The point of the cross-source checks. A reviewer approving someone's Okta
    access while they still hold a write-capable credential somewhere Okta
    deactivation never reaches is approving half a picture, and this is the only
    screen where the decision is actually made -- so it belongs on every one of
    their items.

    It is a separate list because appearing on every item also means appearing
    in every revoke ticket built from one, and those close when the daily check
    re-reads Okta. Okta cannot show whether a GitHub owner role is gone, so a
    ticket that listed this with the rest and then closed on an Okta re-check
    would be signing off a fix nothing verified.
    """
    identity = identity_key(user)
    if not identity or not graph_by_identity:
        return []
    return _worst_first([
        (f.severity, f"{f.detail} ({f.check_id} {f.title}{LINK_MARKER}"
                     f"{LINK_BASIS.get(link.method, str(link.method))})")
        for f, link in graph_by_identity.get(identity, ())
    ])


# What an admin role lets someone do, said plainly, for the reviewer.
ROLE_POWER = {
    "super administrator": "Full control of Okta, including other admins, all apps and security settings.",
    "organization administrator": "Can manage all users, groups and most org settings.",
    "application administrator": "Can change how apps are set up and who can use them.",
    "group administrator": "Can change group memberships, and so the app access groups grant.",
    "help desk administrator": "Can reset passwords and MFA, which lets them take over accounts.",
    "read-only administrator": "Can see all users, groups and apps, but change nothing.",
    "report administrator": "Can see reports and the System Log, but change nothing.",
}


def role_concern(kind: str, target: str) -> list[str]:
    if kind == "admin_role":
        return [ROLE_POWER.get(target.lower(), "An Okta admin role: it can change parts of Okta's configuration.")]
    if kind == "admin_group":
        return [f"Membership of {target} grants Okta admin rights."]
    return []


def build_items(ctx: ReviewContext, findings=()) -> list[ReviewItem]:
    """findings are this review's findings (run_checks); they become each item's concerns."""
    graph_by_identity = graph_findings_by_identity(ctx.graph, findings)
    gap = outside_okta_gap(ctx.graph)

    def item(kind: str, user: User, target_id: str, target: str, via: str, proposed: str, reason: str,
             app: App | None = None) -> ReviewItem:
        facts = person_facts(ctx, user)
        if kind != HR_RECORD:
            facts.append(access_fact(ctx, user, kind, target, via, app))
        return ReviewItem(
            item_key(kind, user.id, target_id, via), kind, user.id, user.login,
            target_id, target, via, proposed, reason, CISO,
            name=user.name, facts=tuple(facts),
            concerns=tuple(role_concern(kind, target) + concerns_for(findings, user, kind, app)),
            outside_okta=tuple(outside_okta_concerns(user, graph_by_identity)),
            outside_okta_gap=gap,
        )

    admin_groups = {n.lower() for n in ctx.config.admin_groups}
    no_hr_record = {f.subject.lower() for f in findings if f.check_id == "AR-03"}
    items: list[ReviewItem] = []
    for user in sorted(ctx.snapshot.users, key=lambda u: u.login.lower()):
        for app, via in ctx.snapshot.apps_for(user.id):
            if app.service_client:
                continue
            items.append(item("app", user, app.id, app.label, via, *_app_proposal(ctx, user, app, via), app=app))
        if user.status == "DEPROVISIONED":
            continue  # Okta drops admin roles on deactivation; AR-09 covers leftover groups
        for role in user.admin_roles or []:
            items.append(item("admin_role", user, role, role, "role", DECIDE, "Admin role; confirm it is still needed."))
        for group in ctx.snapshot.groups_for(user.id):
            if group.name.lower() in admin_groups:
                items.append(item(
                    "admin_group", user, group.id, group.name, "direct", DECIDE,
                    "Member of an admin group; confirm it is still needed.",
                ))
        if user.login.lower() in no_hr_record:
            items.append(item(HR_RECORD, user, "hr-record", "HR record", "none", DECIDE, HR_REASON))

    # Anyone carrying a cross-source finding who got no item above. Appended
    # after the loop rather than inside it because whether a person has any
    # other item is only known once their apps, roles and groups have been
    # walked, and a DEPROVISIONED user skips most of that.
    with_items = {i.user_id for i in items}
    for user in sorted(ctx.snapshot.users, key=lambda u: u.login.lower()):
        if user.id in with_items or not graph_by_identity.get(identity_key(user)):
            continue
        items.append(item(CROSS_SOURCE, user, "cross-source", CROSS_SOURCE_TARGET, "none",
                          DECIDE, CROSS_SOURCE_REASON))

    keys = [i.key for i in items]
    if len(keys) != len(set(keys)):
        raise ItemsError("duplicate review item keys")
    return items


def outside_okta_by_login(items: list[ReviewItem]) -> dict[str, tuple[tuple[str, ...], str]]:
    """Per Okta login: what they hold in another source, and why that may be short.

    For the ticket builders, which are given findings and logins rather than
    items. Keyed on the lowercased login because that is what a leaver finding's
    subject is.
    """
    out: dict[str, tuple[tuple[str, ...], str]] = {}
    for i in items:
        held, gap = out.get(i.user.lower(), ((), i.outside_okta_gap))
        out[i.user.lower()] = (tuple(dict.fromkeys([*held, *i.outside_okta])), gap)
    return out


def items_chunks(items: list[ReviewItem], as_of: date, unused_days: int) -> Iterator[str]:
    """The items file, a piece at a time: the envelope, then one chunk per item.

    Written lazily because this is by a wide margin the largest file a review
    produces -- one item per app a person can reach, so an org-wide group over
    250 apps is a quarter of a million of them -- and the whole point is that
    no caller ever holds the finished document. `write_report` writes these
    straight to the file, so the peak is one item, not the document. Joining
    them is `items_json`, which the tests and `load_items` round-trip through.

    Not `indent=2`. Indentation costs 21% of the bytes for nothing an auditor
    gains. It also costs the C encoder on Python 3.11 and 3.12, where
    `json.dumps(indent=...)` falls back to the pure-Python encoder and runs 4-6x
    slower; 3.13 taught `c_make_encoder` to indent and the Lambda image is 3.14,
    so that half only bites someone running the CLI on an older interpreter.

    One item per line rather than one long line, because the readability that
    `indent=` was there for is real: this is create-only evidence in S3 that a
    person may open, and a single seventy-megabyte line cannot be read, grepped
    or diffed. The document itself is unchanged -- same keys, same FORMAT --
    so `load_items`, `attest` and the manifest hash need nothing.

    `vars(i)`, not `asdict(i)`: `asdict` deep-copies every item into a second
    dict before a byte is encoded, which at 100k items is 70 MB of peak held
    only to be thrown away. Every `ReviewItem` field is a str or a tuple of str
    and json encodes both directly. A field holding a nested dataclass -- on its
    own or inside a tuple -- is the one case where the two differ: `asdict`
    flattens it and `vars` hands json something it cannot encode. A date or a
    set never worked under either. `vars` also needs a `__dict__`, so
    `ReviewItem` must not gain `slots=True`: it is the obvious thing to reach
    for on a class instantiated a quarter of a million times, and it is the one
    change that turns this line into a TypeError.
    """
    # `envelope` is a complete object, so dropping its closing brace and adding
    # one more key yields the same document with the items spliced in, without
    # ever building a dict that holds all of them. `', "items": ['` spells out
    # the separators `json.dumps` uses by default, so a `separators=` added to
    # either call below has to change this literal too.
    #
    # `ensure_ascii=True` is spelled out rather than left to the default,
    # because it is what keeps one item on one line: it escapes every non-ASCII
    # character, so a U+2028 in an app label or a name -- free text in Okta, and
    # a line break to `str.splitlines`, which is how this file's readers count
    # lines -- stays inside its row. It is also why `write_report` can write
    # this with no `encoding=`. `attest`, `decisions` and `store` all pass
    # `ensure_ascii=False`; this is the one writer here that must not.
    envelope = json.dumps({"format": FORMAT, "review_date": as_of.isoformat(),
                           "app_unused_days": unused_days}, ensure_ascii=True)
    yield envelope[:-1] + ', "items": ['
    # The separator leads the row rather than trailing it, so the empty case
    # needs no branch of its own: no items, no newline, and the file is the one
    # line `{...,"items": []}`. A trailing-comma form would have to look ahead
    # to know which row is last, which is the one thing a lazy writer cannot do.
    for n, item in enumerate(items):
        yield ("\n" if n == 0 else ",\n") + json.dumps(vars(item), ensure_ascii=True)
    yield "\n]}\n" if items else "]}\n"


def items_json(items: list[ReviewItem], as_of: date, unused_days: int) -> str:
    """The whole items file as one string. `items_chunks` is the layout.

    The reader's form: `load_items` takes text, and so does every test here.
    Nothing that writes a review uses it -- `write_report` takes the chunks --
    so the document is only ever materialised when something has already
    decided to hold it.

    One `io.StringIO`, never `"".join(...)`: join builds a list of every
    fragment first, which at 250k items is half a million live `str` objects at
    the moment the joined result is allocated beside them, and costs 48 MB over
    the buffer for byte-identical output in the same time.
    """
    buf = io.StringIO()
    for chunk in items_chunks(items, as_of, unused_days):
        buf.write(chunk)
    return buf.getvalue()


def _held_outside_okta(concern: str) -> bool:
    """Was this concern written by `outside_okta_concerns`?

    Two signals the writer put there and nothing in a person's own data can
    produce: the link-basis phrase, and a check id that reads the graph. Both
    are required, so the split cannot land on an Okta concern.
    """
    return LINK_MARKER in concern and any(f"({c} " in concern for c in GRAPH_CHECKS)


def load_items(text: str) -> list[ReviewItem]:
    data = json.loads(text)
    format_ = data.get("format")
    if format_ not in READABLE_FORMATS:
        raise ItemsError(f"unsupported {ITEMS_FILE} format {format_!r}")
    rows = data["items"]
    if format_ < 3:
        # A review opened before the split and remediated after it. Its concerns
        # still hold the cross-source ones, and `tickets.open_revokes` copies
        # that list as the work an Okta re-check will confirm -- so without this
        # the very defect format 3 exists to fix survives for every in-flight
        # review. Split on load; the file itself is never rewritten, because it
        # is create-only in S3 and hashed into a signed manifest.
        rows = [{**d,
                 "concerns": [c for c in d.get("concerns", ()) if not _held_outside_okta(c)],
                 "outside_okta": [c for c in d.get("concerns", ()) if _held_outside_okta(c)]}
                for d in rows]
    return [ReviewItem.from_dict(d) for d in rows]


def summary(items: list[ReviewItem]) -> dict[str, int]:
    """Counts only, safe for a Slack channel or Step Functions output."""
    counts = {p: 0 for p in PROPOSALS}
    for i in items:
        counts[i.proposed] += 1
    counts["total"] = len(items)
    return counts
