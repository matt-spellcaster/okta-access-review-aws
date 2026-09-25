"""Access review checks.

Each check takes a ReviewContext and returns Findings. Every check maps to the
SOC 2 and ISO 27001:2022 controls it provides evidence for.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import (
    CREDENTIAL_EVENTS,
    DISABLED_STATUSES,
    LIVE_STATUSES,
    READ_ONLY_ROLES,
    SIGN_IN_EVENTS,
    SIGN_IN_STATUSES,
    TOKEN_EVENTS,
    App,
    Snapshot,
    User,
)
from .identity import (
    OKTA,
    Credential,
    GrantKind,
    IdentityGraph,
    Link,
    Principal,
    PrincipalKey,
    PrincipalKind,
    Status,
    identity_key,
)
from .register import Register
from .roster import RosterEntry, entry_for

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# The full list is in snapshot.json; the finding shows the most important ones.
MAX_SCOPES_SHOWN = 5
# Same idea for what an account reaches: an org-wide group over 250 apps would
# otherwise put 250 labels in a ticket body and a PDF paragraph.
MAX_REACHED_SHOWN = 8
# Sign-on modes whose use can't be relied on to show up as SSO sign-in events
# (bookmarks, password-vault apps, apps with no sign-on mode set).
NO_SSO_MODES = {"BOOKMARK", "AUTO_LOGIN", ""}
HIGH_RISK_SCOPES = [
    "okta.roles.manage", "okta.apiTokens.manage", "okta.clients.manage", "okta.apps.manage",
    "okta.appGrants.manage", "okta.policies.manage", "okta.authenticators.manage",
    "okta.users.manage", "okta.groups.manage",
]


@dataclass
class Config:
    inactive_days: int = 90
    never_signed_in_grace_days: int = 14
    employee_only_groups: list[str] = field(default_factory=list)
    admin_groups: list[str] = field(default_factory=lambda: ["Okta Administrators"])
    # The service account register: accounts expected to be missing from the HR
    # roster (AR-03), and who is accountable for each (AR-15). A flat list of
    # logins is still read and means declared with nobody named. See register.py.
    service_accounts: Register = field(default_factory=Register)
    # How far back to read the System Log (AR-13, AR-18). Okta keeps 90 days.
    activity_lookback_days: int = 90
    # Where the org is, for resolving an end_date with no time on it (AR-13).
    org_timezone: str = "America/Chicago"
    # A direct app assignment with no sign-in for this long is unused (AR-14)
    # and proposed for revocation. The System Log only reaches back 90 days.
    app_unused_days: int = 90
    # App labels whose use doesn't show up as SSO sign-ins (long-lived sessions,
    # mobile tokens). Never flagged by AR-14; the reviewer decides instead.
    activity_exempt_apps: list[str] = field(default_factory=list)
    # How many earlier reviews in the output folder to read for findings history.
    history_reviews: int = 12
    # PDF look; see pdf.Branding. Empty means the plain layout.
    branding: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> Config:
        if path is None:
            return cls()
        data = json.loads(path.read_text())
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        config = cls(**data)
        config.timezone()  # fail fast on an unknown timezone
        if type(config.history_reviews) is not int or config.history_reviews < 1:
            raise ValueError(f"history_reviews must be a whole number of at least 1, not {config.history_reviews!r}")
        from .pdf import Branding  # late import: pdf imports this module

        Branding.from_config(config.branding)  # fail fast on bad colors or keys
        return config

    def __post_init__(self) -> None:
        # Coerced here rather than in `load`, so a Config built in code from a
        # list of logins -- a test, a caller wiring one by hand -- gets the same
        # register a config file does, and no caller can hold a half-parsed one.
        self.service_accounts = Register.from_config(self.service_accounts)

    def timezone(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.org_timezone)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise ValueError(f"unknown org_timezone {self.org_timezone!r}: {e}") from None


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    controls: list[str]
    subject: str
    detail: str
    remediation: str
    # Set by history.age_findings from earlier reviews; 0 means there was no history to read.
    first_seen: str = ""
    reviews_open: int = 0
    reopened: bool = False


@dataclass
class ReviewContext:
    snapshot: Snapshot
    roster: dict[str, RosterEntry] | None
    config: Config
    as_of: date
    # Every source composed into one graph. None for a review that read only
    # Okta, which is every review until the other sources have collectors, so
    # checks that need it are skipped rather than run against half an estate.
    graph: IdentityGraph | None = None
    # `leaver_accountable_accounts`, kept with the inputs it was computed from:
    # AR-09, AR-18 and `items.build_items` all read it, and each computation
    # scans the System Log once per leaver. Recomputed if any input is swapped,
    # which tests do to `graph` after construction.
    _accountable: tuple | None = field(default=None, init=False, repr=False, compare=False)

    def roster_entry(self, user: User) -> RosterEntry | None:
        return entry_for(self.roster, user.email, user.login)

    def is_service_account(self, user: User) -> bool:
        return self.config.service_accounts.entry(OKTA, user.login) is not None


class Disposition(StrEnum):
    """What a check's remediation assumes should happen to the account itself.

    Two findings on one account whose dispositions are REMOVE and RETAIN are
    two tickets telling one assignee opposite things, and the REMOVE one
    usually closes on a re-read that only the removal satisfies -- so the
    handover is recorded as done by something that asked for the opposite. That
    has now had to be partitioned by hand three times (AR-17, then AR-12, then
    AR-09), so the axis is declared here and
    `test_no_account_is_told_to_go_and_to_stay` reads it.

    The field has no default. A new check states its disposition at the point
    where its remediation sentence is written, which is the only place somebody
    can judge it, and the fourth collision is caught by the suite.
    """

    # Carried out as written, the access or the account goes. A documented
    # exception or an HR correction is a deviation from the ask, not an equal
    # branch of it: AR-07 and AR-14 are REMOVE, and so is AR-02.
    REMOVE = "remove"
    # Carried out as written, the account keeps working and who answers for it
    # changes. Its premise is that something still depends on the account.
    RETAIN = "retain"
    # Neither. The remediation is about something other than whether this
    # access survives -- enrolling MFA, filling in a profile -- or its first
    # ask is to find something out and what happens to the access follows from
    # the answer, which this review does not prejudge ("Confirm X, or
    # deactivate"). The question to ask is not whether the sentence contains
    # the word remove: it is whether **carrying out this remediation would undo
    # the other one's premise**. Narrowing an API client's scopes (AR-10) takes
    # access away and still leaves the client running, so it is NEITHER.
    NEITHER = "neither"


# A REMOVE check that stands down for the accounts a RETAIN check reports, as
# {standing down: taking over}. Its finding is absent from a review while the
# other check holds the account, which is not the same as having been fixed, so
# `history.age_findings` reads this before calling the finding "Back again".
STANDS_DOWN_FOR = {"AR-09": "AR-18"}


@dataclass
class Check:
    id: str
    title: str
    severity: str
    controls: list[str]
    remediation: str
    run: Callable[[ReviewContext, Check], list[Finding]]
    # Keyword and required: see Disposition.
    disposition: Disposition = field(kw_only=True)
    needs_roster: bool = False
    # Needs complete app sign-in data covering app_unused_days.
    needs_app_usage: bool = False
    # Reads ctx.graph rather than ctx.snapshot. run_review builds one on every
    # review (from Okta alone when nothing else was read), so this only skips
    # the check for a caller that built no graph.
    needs_graph: bool = False

    def finding(self, subject: str, detail: str, severity: str | None = None) -> Finding:
        return Finding(self.id, self.title, severity or self.severity, self.controls, subject, detail, self.remediation)


def _terminated_still_active(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        entry = ctx.roster_entry(u)
        if u.status in LIVE_STATUSES and entry and entry.status == "terminated":
            when = f" on {entry.end_date}" if entry.end_date else ""
            out.append(check.finding(u.login, f"HR shows terminated{when}; Okta status is {u.status}."))
    return out


def _contract_expired(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        entry = ctx.roster_entry(u)
        if (
            u.status in LIVE_STATUSES
            and entry
            and entry.status != "terminated"
            and entry.end_date
            and entry.end_date < ctx.as_of
        ):
            out.append(check.finding(u.login, f"End date {entry.end_date} has passed; Okta status is {u.status}."))
    return out


def _not_in_roster(ctx: ReviewContext, check: Check) -> list[Finding]:
    return [
        check.finding(u.login, f"No HR record for this {u.status} account.")
        for u in ctx.snapshot.users
        if u.status in LIVE_STATUSES and not ctx.is_service_account(u) and ctx.roster_entry(u) is None
    ]


def _mfa_missing(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        if u.status not in SIGN_IN_STATUSES:
            continue
        if u.factors is None:
            out.append(check.finding(u.login, "MFA enrollment could not be read.", severity="info"))
        elif not u.factors:
            out.append(check.finding(u.login, "Can sign in but has no MFA factor enrolled."))
    return out


def _inactive(ctx: ReviewContext, check: Check) -> list[Finding]:
    cutoff = ctx.as_of - timedelta(days=ctx.config.inactive_days)
    return [
        check.finding(u.login, f"Last sign-in {u.last_login.date()} ({_days_ago(u.last_login.date(), ctx.as_of)}).")
        for u in ctx.snapshot.users
        if u.status in SIGN_IN_STATUSES and u.last_login and u.last_login.date() < cutoff
    ]


def _never_signed_in(ctx: ReviewContext, check: Check) -> list[Finding]:
    cutoff = ctx.as_of - timedelta(days=ctx.config.never_signed_in_grace_days)
    return [
        check.finding(u.login, f"Created {u.created.date()}, status {u.status}, and has never signed in.")
        for u in ctx.snapshot.users
        if u.status in LIVE_STATUSES and u.last_login is None and u.created and u.created.date() < cutoff
    ]


def _contractor_in_employee_group(ctx: ReviewContext, check: Check) -> list[Finding]:
    restricted = {n.lower() for n in ctx.config.employee_only_groups}
    out = []
    for u in ctx.snapshot.users:
        if u.status not in LIVE_STATUSES:
            continue
        entry = ctx.roster_entry(u)
        kind = (entry.employment_type if entry else u.user_type).lower()
        if kind != "contractor":
            continue
        for g in ctx.snapshot.groups_for(u.id):
            if g.name.lower() in restricted:
                out.append(check.finding(u.login, f"Contractor is a member of employee-only group '{g.name}'."))
    return out


def _missing_owner(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        if u.status not in LIVE_STATUSES or ctx.is_service_account(u):
            continue
        entry = ctx.roster_entry(u)
        missing = []
        if not (u.manager or (entry and entry.manager)):
            missing.append("manager")
        if not u.department:
            missing.append("department")
        if missing:
            out.append(check.finding(u.login, f"Profile is missing: {', '.join(missing)}."))
    return out


def _disabled_with_access(ctx: ReviewContext, check: Check) -> list[Finding]:
    # A service account AR-18 reports is that check's, not this one's, for the
    # reason AR-17 and AR-12 leave those accounts alone. This one says "remove
    # the groups and apps so reactivation doesn't restore access" and settles on
    # a fresh Okta read; AR-18 says "hand it to somebody, or decommission it".
    # Two subjects for one account -- the login here, `okta/<id>` there -- so no
    # hashed ticket label could ever collapse them, and the reviewer got both.
    # AR-18 takes over the whole account and names the groups and apps this
    # finding would have listed, through the same `_leftover_access`, so
    # nothing is dropped by standing down.
    # `STANDS_DOWN_FOR` records this for history.
    #
    # Read from the one helper AR-18 itself walks rather than re-derived here:
    # the partition has to be the same computation or the two drift. It is
    # empty without a graph or a roster, which is the safe direction -- AR-18
    # reports nothing then, and this check keeps the finding.
    taken = leaver_accountable_accounts(ctx)
    out = []
    for u in ctx.snapshot.users:
        if u.status not in DISABLED_STATUSES or (OKTA, u.id) in taken:
            continue
        leftover = _leftover_access(ctx.snapshot, u)
        if leftover:
            out.append(check.finding(u.login, f"Status {u.status} but still has {leftover}."))
    return out


def _leftover_access(snapshot: Snapshot, user: User) -> str:
    """A disabled Okta user's groups and apps, in full, as AR-09 lists them;
    empty when it holds none.

    AR-18 lists them the same way for the disabled accounts AR-09 stands down
    for, so what the reviewer is told to remove on the decommission branch is
    exactly what AR-09 would have said. BUILT_IN groups are left out: nobody
    can remove a user from Everyone.
    """
    groups = sorted(g.name for g in snapshot.groups_for(user.id) if g.type != "BUILT_IN")
    apps = sorted({app.label for app, _ in snapshot.apps_for(user.id)})
    parts = []
    if groups:
        parts.append(f"groups: {', '.join(groups)}")
    if apps:
        parts.append(f"apps: {', '.join(apps)}")
    return "; ".join(parts)


def _privileged_service_app(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for app in ctx.snapshot.apps:
        if app.status != "ACTIVE" or not app.service_client:
            continue
        manage = sorted(
            (s for s in app.granted_scopes if s.endswith(".manage")),
            key=lambda s: (HIGH_RISK_SCOPES.index(s) if s in HIGH_RISK_SCOPES else len(HIGH_RISK_SCOPES), s),
        )
        roles = [r for r in app.admin_roles if r.lower() not in READ_ONLY_ROLES]
        if not (manage or roles):
            continue
        parts = []
        if roles:
            parts.append(f"admin roles: {', '.join(roles)}")
        if manage:
            shown = ", ".join(manage[:MAX_SCOPES_SHOWN])
            more = f" and {len(manage) - MAX_SCOPES_SHOWN} more" if len(manage) > MAX_SCOPES_SHOWN else ""
            label = "write scope" if len(manage) == 1 else f"{len(manage)} write scopes"
            parts.append(f"{label}: {shown}{more}")
        severity = "high" if "Super Administrator" in app.admin_roles else None
        out.append(check.finding(app.label, f"API client has {'; '.join(parts)}.", severity=severity))
    return out


def secrets_held_by(snapshot: Snapshot, user_id: str) -> list[tuple[App, datetime]]:
    """Live API clients whose credentials this person held -- created the
    client, added or activated a secret or key, or read the secret back -- as
    (app, when they last did), by label.

    Custody, not ownership: whoever did any of these may still have a working
    copy. Only as far back as the System Log reaches, so an empty answer is "no
    custody in the window", never "held nothing". Whether a copy was rotated
    since is not read here: Okta cannot show it reliably (a key published at a
    `jwks_uri` is invisible to it), so AR-18 asks for the rotation and a
    reviewer confirms it.
    """
    clients = [a for a in snapshot.apps if a.client_id and a.status == "ACTIVE"]
    last: dict[str, tuple[App, datetime]] = {}
    for event in snapshot.events_for_actor(user_id):
        if not event.published or not event.is_kind(CREDENTIAL_EVENTS):
            continue
        for target in event.targets:
            for app in clients:
                if app.matches(target.get("id")) and (app.id not in last or event.published > last[app.id][1]):
                    last[app.id] = (app, event.published)
    return sorted(last.values(), key=lambda p: p[0].label)


def _left_on(entry: RosterEntry) -> str:
    return f"Left {entry.end_date}" if entry.end_date else "HR shows terminated"


def _leavers(ctx: ReviewContext) -> list[tuple[User, RosterEntry]]:
    """Everyone the roster says is gone: terminated, or past their end date."""
    pairs = ((u, ctx.roster_entry(u)) for u in ctx.snapshot.users)
    return [(u, e) for u, e in pairs if e and e.is_gone(ctx.as_of)]


def _leaver_credentials(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for user, entry in _leavers(ctx):
        parts = []
        tokens = sorted(t.name or t.id for t in ctx.snapshot.tokens_for(user.id))
        if tokens:
            noun = "API token" if len(tokens) == 1 else "API tokens"
            parts.append(f"{noun} {', '.join(tokens)}")
        # Groups and apps are AR-09's job; this check is only about credentials
        # that keep working on their own, whatever the account status is. An
        # API client secret they held is AR-18's: rotating it is not something
        # the daily Okta re-read that closes this ticket can see.
        if parts:
            out.append(check.finding(user.login, f"{_left_on(entry)} but still holds {'; '.join(parts)}."))
    return out


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _days_ago(when: date, as_of: date) -> str:
    return _count((as_of - when).days, "day") + " ago"


def _activity_after_leaving(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for user, entry in _leavers(ctx):
        cutoff = entry.access_ends(ctx.config.timezone())
        if cutoff is None:
            out.append(check.finding(
                user.login,
                "HR shows terminated with no end date, so activity after they left cannot be identified.",
                severity="info",
            ))
            continue
        # Their own account only. An API client they built or held the secret of
        # goes on running after they leave -- that is what it is for -- so its
        # activity is not theirs: read as theirs, every such client was a
        # critical "possible incident, revoke it" in the leaver ticket while
        # AR-18 asked for it to be handed over. Whether they may still use it is
        # AR-18's held secret.
        after = sorted(
            (e for e in ctx.snapshot.events_for_actor(user.id) if e.published and e.published > cutoff),
            key=lambda e: e.published,
        )
        parts = []
        for events, noun in (
            ([e for e in after if e.is_kind(SIGN_IN_EVENTS)], "sign-in"),
            ([e for e in after if e.is_kind(TOKEN_EVENTS)], "token grant"),
            ([e for e in after if e.is_kind(CREDENTIAL_EVENTS)], "credential change"),
        ):
            if events:
                parts.append(_count(len(events), noun))
        if not parts:
            continue
        last = after[-1]
        where = next((t["label"] for t in last.targets if t.get("label")), last.event_type)
        left = cutoff.strftime("%Y-%m-%d %H:%M %Z") if entry.end_at else str(entry.end_date)
        out.append(check.finding(
            user.login,
            f"{', '.join(parts)} after {left}; last {last.published.date()} ({where}).",
        ))
    return out


def _admin_membership(ctx: ReviewContext, check: Check) -> list[Finding]:
    admin_groups = {n.lower() for n in ctx.config.admin_groups}
    out = []
    for u in ctx.snapshot.users:
        if u.status == "DEPROVISIONED":
            continue
        reasons = []
        if u.admin_roles:
            reasons.append(f"admin roles: {', '.join(u.admin_roles)}")
        groups = [g.name for g in ctx.snapshot.groups_for(u.id) if g.name.lower() in admin_groups]
        if groups:
            reasons.append(f"admin groups: {', '.join(groups)}")
        if reasons:
            out.append(check.finding(u.login, f"Has {'; '.join(reasons)}. Confirm this is still needed."))
    return out


def app_usage_covers(snapshot: Snapshot, days: int, as_of: date) -> bool:
    """True when app sign-in data was read in full and reaches back far enough
    to say "not used in `days` days". Anything less, and nobody is called unused."""
    since = snapshot.app_usage_since
    return since is not None and snapshot.app_usage_complete and since.date() <= as_of - timedelta(days=days)


def unused_direct_assignments(ctx: ReviewContext) -> list[tuple[User, App, datetime, datetime | None]]:
    """Direct assignments to people who use Okta but not this app, as
    (user, app, assigned, last_sign_in). Only when usage data covers the window,
    the assignment date is known and old enough, and the app records sign-ins.

    Accounts that are inactive altogether are AR-05/AR-06's finding, and
    service accounts don't sign in through SSO, so neither is listed here."""
    if not app_usage_covers(ctx.snapshot, ctx.config.app_unused_days, ctx.as_of):
        return []
    cutoff = ctx.as_of - timedelta(days=ctx.config.app_unused_days)
    inactive_cutoff = ctx.as_of - timedelta(days=ctx.config.inactive_days)
    users = {u.id: u for u in ctx.snapshot.users}
    exempt = {a.lower() for a in ctx.config.activity_exempt_apps}
    out = []
    for app in ctx.snapshot.apps:
        if not records_sign_ins(app) or app.label.lower() in exempt:
            continue
        for uid in sorted(app.users):
            user = users.get(uid)
            if (
                user is None
                or user.status not in SIGN_IN_STATUSES
                or ctx.is_service_account(user)
                or not user.last_login
                or user.last_login.date() < inactive_cutoff
            ):
                continue
            assigned = app.assigned.get(uid)
            if assigned is None or assigned.date() >= cutoff:
                continue
            last = ctx.snapshot.last_app_sign_in(uid, app.id)
            if last is None or last.date() < cutoff:
                out.append((user, app, assigned, last))
    return out


def records_sign_ins(app: App) -> bool:
    """Apps whose use reliably appears in the System Log as SSO sign-ins. For
    the rest (see NO_SSO_MODES, and API service clients) silence means nothing."""
    return app.status == "ACTIVE" and not app.service_client and app.sign_on_mode not in NO_SSO_MODES


def _unused_app_assignment(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for user, app, assigned, last in unused_direct_assignments(ctx):
        seen = f"last sign-in {last.date()}" if last else f"no sign-in since {ctx.snapshot.app_usage_since.date()}"
        out.append(check.finding(
            f"{user.login} / {app.label}",
            f"Assigned directly {assigned.date()}; {seen}.",
        ))
    return out


def graph_subject(principal: Principal) -> str:
    """Source-qualified, and keyed on the source's own id, always.

    Ticket identity is (check_id, subject) and `tickets.ticket_label` hashes it
    into a permanent Jira label, so the subject has to be stable and unique for
    as long as the problem exists. `label` is neither: a GitHub login can be
    renamed by its owner, and two Okta service clients can share an app label,
    which would collapse two unremediated problems onto one ticket. `id` is the
    uniqueness the graph already enforces. The readable name goes in the detail,
    which is what the ticket body and the PDF show.
    """
    return f"{principal.source}/{principal.id}"


def okta_user_subjects(graph: IdentityGraph | None, snapshot: Snapshot) -> dict[str, str]:
    """{casefolded login: graph subject} for every Okta user the graph holds.

    The Okta checks name a user account by its login and the graph checks by
    `graph_subject`, so one account wears two names; this is the one place that
    joins them, through the graph's own principal rather than a subject built
    by hand. Empty without a graph.
    """
    if graph is None:
        return {}
    out = {}
    for user in snapshot.users:
        principal = graph.principal((OKTA, user.id))
        if principal is not None:
            out[user.login.casefold()] = graph_subject(principal)
    return out


def graph_findings_by_identity(
    graph: IdentityGraph | None, findings
) -> dict[str, list[tuple[Finding, Link]]]:
    """Cross-source findings grouped by the person they are about.

    A graph finding's subject is `{source}/{principal.id}` and says nothing
    about who the principal belongs to, so getting from a finding back to a
    person means going through the graph: subject to principal, principal to
    its strongest link, link to an identity. Nothing is matched on a name or
    an email here -- the link already carries the evidence, and this only
    reads it.

    Subjects are compared against `graph_subject` over the graph's own
    principals rather than parsed. Splitting `{source}/{id}` back apart would
    be a second, separate opinion about the format, and the day a source name
    contains a slash it would be a wrong one.
    """
    out: dict[str, list[tuple[Finding, Link]]] = {}
    for f, link in _attributed(graph, findings):
        out.setdefault(link.identity, []).append((f, link))
    return out


def graph_findings_by_subject(
    graph: IdentityGraph | None, findings
) -> dict[str, list[tuple[Finding, Link]]]:
    """The same findings, keyed by the account they are **about**.

    `graph_findings_by_identity` answers "whose review item does this belong
    on", which for a service account is its owner's. This answers "which
    account is this about", which for an Okta account is one that has review
    items of its own -- and since AR-09 stands down for those, its item would
    otherwise say nothing is flagged while a high finding names it.

    An exact match on the principal id, not an inference: the subject is that
    principal. Both go through `_attributed`, so the two cannot disagree about
    which findings a reviewer may be shown.
    """
    out: dict[str, list[tuple[Finding, Link]]] = {}
    for f, link in _attributed(graph, findings):
        out.setdefault(f.subject, []).append((f, link))
    return out


def _attributed(graph: IdentityGraph | None, findings) -> Iterator[tuple[Finding, Link]]:
    """The graph findings a reviewer may be shown, each with the link that
    ties its principal to a person."""
    if graph is None:
        return
    principals = {graph_subject(p): p for p in graph.principals}
    for f in findings:
        if f.check_id not in GRAPH_CHECKS:
            continue
        principal = principals.get(f.subject)
        if principal is None:
            continue
        link = graph.link_for(principal.key)
        # Unlinked or contested, or declared with nobody named: there is no
        # person to show this to. It is still in the report and still gets a
        # ticket -- AR-15 exists for exactly this -- but it cannot be put on
        # somebody's review item without inventing the attribution the graph
        # deliberately refused to make.
        if link is None or not link.identity:
            continue
        yield f, link


def _credential_evidence_complete(graph: IdentityGraph, source: str) -> bool:
    """Whether this source's credential reads can be believed.

    `activity_complete`, not `complete`: a source records identity gaps (an
    unjoinable SAML attribute, two verified emails) that say nothing about
    whether the credential reads ran, and letting those suppress every
    credential answer org-wide would make the signal dead in a real tenant.
    A source the graph does not know is not a complete one.
    """
    meta = graph.source(source)
    return bool(meta and meta.activity_complete)


def _roles_evidence_complete(graph: IdentityGraph, source: str) -> bool:
    """Whether an empty role list from this source can be believed.

    Its own signal, and neither of the other two. `complete` is identity and
    `activity_complete` is credential activity; roles are a third read that
    fails on its own -- `okta.roles.read` in Okta, the organization-roles
    endpoints in GitHub -- and both sources hand back an empty list when it
    does. So a principal with no ROLE grant is "not known to hold one", not
    "holds none", and every severity that grades on roles asks this first. A
    source the graph does not know is not a complete one.
    """
    meta = graph.source(source)
    return bool(meta and meta.roles_complete)


def _roles_unread_note(source: str, roles: list[str], own: bool = False) -> str:
    """The sentence a finding carries when nobody read the roles.

    One helper for both leaver checks, alongside the credential one they each
    word themselves: an auditor reading "holding pat ...aa11" needs to be told
    that the account could be an organization owner and no one looked.

    "Further" when the finding already names a role: a source can return the
    base role and fail the read that would have returned the rest, and a
    sentence saying an elevated role is unknown directly after naming one
    reads as a contradiction rather than as what it is.

    `own` when the account itself says its roles were never read (an Okta user
    whose `admin_roles` is None); otherwise all that is known is that the
    source's read did not complete, and the sentence claims no more.
    """
    what = "any further elevated role" if roles else "an elevated role"
    if own:
        return f" Its {source} roles were not read, so whether it holds {what} is unknown."
    return f" The {source} role read did not complete, so whether the account holds {what} is unknown."


def _describe(credentials: list[Credential], as_of: date) -> str:
    """The credentials a principal holds, worst first, for a finding's detail."""
    parts = []
    for credential in sorted(credentials, key=lambda c: (c.write_access is not True, c.label)):
        notes = []
        if credential.write_access is True:
            notes.append("can write")
        elif credential.write_access is None:
            notes.append("write access unknown")
        if credential.last_used:
            notes.append(f"last used {credential.last_used.date()} ({_days_ago(credential.last_used.date(), as_of)})")
        elif not credential.usage_read:
            notes.append("use not read")
        else:
            notes.append("no record of use")
        parts.append(f"{credential.label} ({'; '.join(notes)})")
    return ", ".join(parts)


def _maybe_recent(credentials: list[Credential], as_of: date, days: int, evidence_complete: bool) -> bool:
    """True when something might have used one of these lately. False needs the
    activity evidence to be complete: without it, a missing last-used date is
    "not known to have been used", not "dormant", and dormant is the milder
    finding. Every dormancy judgement in this file reads completeness first
    (see `app_usage_covers`)."""
    if not evidence_complete or any(not c.usage_read and not c.last_used for c in credentials):
        return True
    cutoff = as_of - timedelta(days=days)
    return any(c.last_used and c.last_used.date() >= cutoff for c in credentials)


def _write_access(credentials: list[Credential], evidence_complete: bool = True) -> bool | None:
    """True if one of these can change something, None if the permissions were
    never read, False only when every credential is known to be read-only.

    The tri-state matters because severity reads it, and ranking an unread
    credential as harmless is how a review misses the one that mattered. An
    empty list under an incomplete read is None for the same reason
    `_scope_write_access` is: no credentials found is not no credentials.
    """
    if any(c.write_access is True for c in credentials):
        return True
    if not evidence_complete or any(c.write_access is None for c in credentials):
        return None
    return False


def _downgrade(severity: str) -> str:
    """One rung milder, never below `low`.

    What a register entry with no owner is worth. Somebody wrote the account
    down, so it is deliberate rather than a mystery, and that is the whole of
    the difference -- no one is named, so no one is accountable. `info` is the
    rung for things a reviewer confirms rather than fixes (AR-11), and a
    credential nobody answers for is always work, so the floor is `low`.
    """
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, SEVERITIES.index("low"))]


def _unowned_credentials(ctx: ReviewContext, check: Check) -> list[Finding]:
    """An account the source knows about, holding credentials, that no evidence
    ties to a person. The cross-source identity join is the heart of this tool,
    so this is the headline check, not an edge case.

    Two ways to get here, and they are reported apart. Nothing at all says who
    holds it (`unlinked`), or the register declares it and names no owner
    (`unattributed`). The second exists because adding an account to the
    register would otherwise delete this finding while leaving exactly as many
    people accountable for the credential as before: nobody. The two lists are
    disjoint -- one is principals with no best link, the other is principals
    whose best link carries no identity.
    """
    graph = ctx.graph
    out = []
    for principal, declared in ([(p, False) for p in graph.unlinked()]
                                + [(p, True) for p in graph.unattributed()]):
        # AR-16's case: the account itself is unknown to the source's own
        # member read, which is a different and sharper problem.
        if principal.kind is PrincipalKind.UNKNOWN:
            continue
        credentials = graph.credentials_for(principal.key)
        known = _credential_evidence_complete(graph, principal.source)
        # An empty credential list is only evidence of nothing held when the
        # read that would have said so actually ran. Otherwise an unowned,
        # write-capable bot disappears from the evidence because a call failed.
        if not credentials and known:
            continue
        held = _describe(credentials, ctx.as_of)
        whose = (
            "the review register declares this account and names no owner, so nobody is "
            "accountable for it"
            if declared else
            # Okta records who created a client only in the System Log, which
            # this review reads for leavers alone and which forgets after 90
            # days: "no evidence" there is also "nobody looked", and says so.
            "no evidence ties this account to a person (who created an Okta API client is only "
            "read for people who have left)"
            if principal.source == OKTA else
            "no evidence ties this account to a person"
        )
        detail = (
            f"{principal.label}: {whose}. Holds {held}."
            if credentials else
            f"{principal.label}: {whose}, and the {principal.source} credential read did not "
            f"complete, so what it holds is unknown."
        )
        writes = _write_access(credentials, known) is not False
        recent = _maybe_recent(credentials, ctx.as_of, ctx.config.inactive_days, known)
        # Recently used and nobody knows whose it is: the genuinely alarming
        # case. Dormant is a cleanup; this is an investigation. Unknown counts
        # as the worse branch on both axes -- see _write_access, _maybe_recent.
        severity = "high" if writes and recent else "medium" if writes or recent else "low"
        out.append(check.finding(graph_subject(principal), detail,
                                 severity=_downgrade(severity) if declared else severity))
    return out


def _access_without_an_account(ctx: ReviewContext, check: Check) -> list[Finding]:
    """Something holds access that the source's own user or member read never
    returned, so the review knows it exists only from what it can reach."""
    graph = ctx.graph
    out = []
    for principal in graph.principals:
        if principal.kind is not PrincipalKind.UNKNOWN:
            continue
        grants = graph.grants_for(principal.key)
        credentials = graph.credentials_for(principal.key)
        known = _credential_evidence_complete(graph, principal.source)
        held = _describe(credentials, ctx.as_of)
        parts = []
        if grants:
            parts.append("access to " + ", ".join(sorted({g.target_label or g.target for g in grants})))
        if held:
            parts.append(f"credentials: {held}")
        if not parts:
            continue
        out.append(check.finding(
            graph_subject(principal),
            f"{principal.label} holds {'; '.join(parts)}, but the account was not returned by the "
            f"{principal.source} user read.",
            # Unknown write access is not the milder case: see _write_access.
            severity="high" if _write_access(credentials, known) is not False else "medium",
        ))
    return out


def _elevated_roles(graph: IdentityGraph, principal: Principal) -> list[str]:
    """Role grants a source records for this principal.

    A projection only emits a ROLE grant where the role is above ordinary
    membership, so this is the power a departure leaves behind that no
    credential list shows. An organization owner can add collaborators, change
    settings and turn off branch protection whether or not any token they hold
    can write, so a finding that named only their credentials would describe
    the smaller half of the problem.
    """
    return sorted({g.target_label or g.target for g in graph.grants_for(principal.key)
                   if g.kind is GrantKind.ROLE})


def _leaver_access_outside_okta(ctx: ReviewContext, check: Check) -> list[Finding]:
    """Someone HR says is gone, still holding access somewhere Okta
    deactivation does not reach. This is the whole thesis of the tool: the long
    tail of a departure is not the account, it is everything the account was
    never the only way in to."""
    graph = ctx.graph
    out = []
    # By identity, not by leaver: Okta enforces a unique login, not a unique
    # profile email, so one person with two accounts would otherwise produce
    # the same finding twice -- two rows in findings.csv, one history key, one
    # ticket label, and an inflated critical count in the Slack summary.
    leavers: dict[str, RosterEntry] = {}
    for user, entry in _leavers(ctx):
        identity = identity_key(user)
        if identity:
            leavers.setdefault(identity, entry)
    for identity, entry in leavers.items():
        for principal in graph.principals_of(identity):
            # DISABLED means the source says sign-in is blocked. Any other
            # status, including UNKNOWN, is reported: a source that did not say
            # has not said the account is safe.
            if principal.source == OKTA or principal.status is Status.DISABLED:
                continue
            # A service account they were accountable for is not access they
            # held, and its remediation is the opposite of this one: the bot is
            # meant to go on running under a new owner, not be revoked. AR-18
            # reports those, across every source and every status, so it is a
            # strict superset of what is dropped here -- one principal, one
            # finding, and never two tickets telling one assignee to revoke and
            # reassign the same account.
            if principal.kind is PrincipalKind.SERVICE:
                continue
            credentials = graph.credentials_for(principal.key)
            known = _credential_evidence_complete(graph, principal.source)
            held = _describe(credentials, ctx.as_of)
            roles = _elevated_roles(graph, principal)
            roles_known = _roles_evidence_complete(graph, principal.source)
            detail = (f"{_left_on(entry)}, but {principal.source} still shows {principal.label} "
                      f"{principal.source_status or 'with access'}")
            carries = []
            if roles:
                carries.append(f"the {', '.join(roles)} role" if len(roles) == 1
                               else f"the {', '.join(roles)} roles")
            if held:
                carries.append(held)
            detail += f" holding {' and '.join(carries)}." if carries else "."
            if not roles_known:
                detail += _roles_unread_note(principal.source, roles)
            out.append(check.finding(
                graph_subject(principal), detail,
                # An elevated role is write access to the organization itself.
                # Grading on credentials alone ranked a departed organization
                # owner below a departed ordinary member holding one token,
                # because the owner's own token happened to be read-only.
                # Unknown write access is not the milder case: see _write_access.
                # Nor is an unread role list: see _roles_evidence_complete.
                severity=("critical" if roles or not roles_known
                          or _write_access(credentials, known) is not False else "high"),
            ))
    return out


def _reachable(graph: IdentityGraph, principal: Principal) -> list[str]:
    """What the sources say this principal can still reach, minus the roles,
    which are named separately.

    `_access_without_an_account` lists an account's grants for the same reason
    -- somebody deciding between handover and decommission is deciding about
    the blast radius, and an account described only by its roles and
    credentials does not show one -- but not the same list: that one includes
    ROLE grants and never truncates.

    Whatever the source stated, plus what its groups reach. Not used for a
    disabled Okta user: Okta has unassigned it from every app, so "reaches"
    would overstate it, and what its surviving groups give back on reactivation
    is `_leftover_access`, listed in full as AR-09 lists it.
    """
    return sorted({g.target_label or g.target
                   for g in graph.grants_for(principal.key)
                   if g.kind is not GrantKind.ROLE})


def leaver_accountable_accounts(ctx: ReviewContext) -> dict[PrincipalKey, dict[str, list[str]]]:
    """The accounts AR-18 reports, as {key: {person who left: [why]}}.

    Two reasons, one entry per account. *Ownership*: the strongest link for a
    service account names the leaver (the register, or the System Log's record
    of who created it). *Custody*: the System Log shows the leaver created an
    API client, added a secret or key, or read the secret back
    (`secrets_held_by`), so a copy may still work whoever owns it.

    AR-18 walks this; so does `_disabled_with_access`, which stands down for
    the Okta user accounts in it, and `items._app_proposal`, which stops
    proposing Revoke on them. The remediations contradict, and a partition
    re-derived at each of those places drifts. Empty when there is no graph or
    no roster, which is the direction that fails safe: AR-18 runs on neither,
    so nothing stands down for a check that did not report.

    A leaver's own Okta account is never in it: an account whose roster entry
    says it is gone. HR lists that account as a person who left, so a register
    entry calling it a service account is contradicted by the stronger record,
    and the account is the removal checks' to report (AR-01, AR-02, AR-09,
    AR-13) -- which they do, because every one of them fires on a gone entry, so
    it is not silence. Taken here, a leaver's own account declared with an owner
    was told to go by AR-13 and to stay by AR-18, and AR-09 went quiet.

    Only a *gone* entry, not any roster match. `entry_for` matches on the
    profile email, which a bot can share with a person still here, and for an
    active entry no removal check fires: excluding it dropped AR-18 from the
    whole review with no gap to say so.
    """
    inputs = (ctx.snapshot, ctx.roster, ctx.config, ctx.graph, ctx.as_of)
    if ctx._accountable is not None and all(a is b for a, b in zip(ctx._accountable[0], inputs)):
        return ctx._accountable[1]
    why = _leaver_accountable_accounts(ctx)
    ctx._accountable = (inputs, why)
    return why


def _leaver_accountable_accounts(ctx: ReviewContext) -> dict[PrincipalKey, dict[str, list[str]]]:
    if ctx.graph is None or ctx.roster is None:
        return {}
    graph = ctx.graph
    leavers_own = {(OKTA, u.id) for u, _ in _leavers(ctx)}
    # By identity, not by leaver, for the reason `_leaver_access_outside_okta`
    # gives: one person with two Okta logins would otherwise be two findings
    # about the one service account, and so two tickets. A leaver with no
    # identity still has custody, read off their own account.
    leavers: dict[str, tuple[RosterEntry, list[User]]] = {}
    for user, entry in _leavers(ctx):
        leavers.setdefault(identity_key(user) or f"user:{user.id}", (entry, []))[1].append(user)
    # Keyed by account across every leaver, not per leaver: two people who left
    # holding one client is one finding naming both. Per leaver it was two
    # findings on one subject, and ticket identity is (check, subject), so the
    # second person's reason never reached the ticket.
    why: dict[PrincipalKey, dict[str, list[str]]] = {}
    for who, (entry, users) in leavers.items():
        # Named, not `_left_on`: this detail opens with the account rather than
        # the person, so "Left 2026-08-29" would read as the account having
        # left. The roster's name, falling back to the identity the link
        # actually joined on -- never a name from the register entry, which is
        # a string somebody typed.
        gone = f"left {entry.end_date}" if entry.end_date else "is terminated in HR"
        person = f"{entry.name or (users[0].login if who.startswith('user:') else who)} {gone}"
        for principal in graph.principals_of(who):
            if principal.kind is not PrincipalKind.SERVICE or principal.key in leavers_own:
                continue
            link = graph.link_for(principal.key)
            if link is None:  # principals_of is built from these; belt and braces
                continue
            why.setdefault(principal.key, {}).setdefault(person, []).append(
                f"the strongest evidence of who answers for this {principal.source} service account "
                f"names them -- {link.evidence}")
        for user in users:
            for app, when in secrets_held_by(ctx.snapshot, user.id):
                why.setdefault((OKTA, app.id), {}).setdefault(person, []).append(
                    f"the System Log shows them holding its credentials on {when.date()}, so a copy "
                    f"may still work")
    return why


def _leaver_owned_service_accounts(ctx: ReviewContext, check: Check) -> list[Finding]:
    """A service account a leaver was accountable for, or held the credentials of.

    The other half of a departure, and the half no deactivation reaches. The
    bot is supposed to keep running -- something in CI depends on it -- so the
    fix is to make sure somebody still here answers for it and to rotate any
    secret or key the leaver held, or to decide it is finished and take it
    down. That is the opposite of AR-17, which asks for a leaver's own access
    to be removed, which is why the two are reported apart and why AR-17 leaves
    service accounts here. Custody used to be AR-12's, on the leaver ticket,
    but that ticket closes on a daily Okta re-read and Okta cannot show a
    rotation reliably, so the rotation is confirmed by a reviewer here instead.
    Which accounts, and why, is `leaver_accountable_accounts`.

    Okta's own service clients are what AR-17 structurally cannot see: it skips
    `source == OKTA` because Okta deactivation is what the rest of the review
    verifies, and an API client is not touched by anything that happens to the
    account of the person who owns it.

    Every source and every status, unlike AR-17. A disabled service account is
    not a settled one: `CredentialKind` is the set of things that outlive the
    account they were created under, so a blocked sign-in says nothing about
    the token, and somebody still has to decide between handover and shutdown.

    It takes the whole account, not just its credentials: `_disabled_with_access`
    stands down for these and `items._app_proposal` stops proposing Revoke on
    them, so the groups and apps a disabled one still holds are reported here or
    nowhere. That is what `_leftover_access` is for.

    The ownership half is disjoint from AR-15 by construction: it walks
    `principals_of`, indexed on identities some source attested, and AR-15
    walks the principals whose best link reaches nobody. The custody half can
    report an account AR-15 also reports; the two remediations agree.
    """
    graph = ctx.graph
    out = []
    apps = {a.id: a for a in ctx.snapshot.apps}
    users_by_id = {u.id: u for u in ctx.snapshot.users}
    for key, people in sorted(leaver_accountable_accounts(ctx).items()):
        said = "; ".join(f"{person}, and {'; and '.join(reasons)}" for person, reasons in people.items())
        principal = graph.principal(key)
        if principal is None:
            # A client with a secret that is not a service client -- a web or
            # native OIDC app -- is not in the graph, and its secret works just
            # as well. Reported ungraded rather than dropped: skipping it lost
            # the custody AR-12 used to report, with no gap.
            app = apps.get(key[1])
            label = app.label if app else key[1]
            out.append(check.finding(
                f"{key[0]}/{key[1]}",
                f"{label}: {said}. It is not a service client, so what it can reach was not graded.",
            ))
            continue
        credentials = graph.credentials_for(principal.key)
        known = _credential_evidence_complete(graph, principal.source)
        roles = _elevated_roles(graph, principal)
        user = users_by_id.get(principal.id) if principal.source == OKTA else None
        # An Okta user carries its own answer: `admin_roles` is None when its
        # roles were not read, which the collector never does for a
        # DEPROVISIONED user, and Okta keeps group-assigned admin roles
        # through deactivation and restores them on reactivation. The source
        # flag would be wrong both ways -- True over that None, and False
        # over a user whose roles were read before a client's roles call was
        # refused. An Okta client's list is one call that yields [] on any
        # failure, so a role in it proves that client's read ran; an empty one
        # and other sources fall back to the source.
        roles_known = (user.admin_roles is not None if user
                       else (principal.source == OKTA and bool(roles))
                       or _roles_evidence_complete(graph, principal.source))
        held = _describe(credentials, ctx.as_of)
        # The source's own word for the account's state, the way AR-17 reports
        # it. The remediation branches on it -- a live account is presumably
        # still being called, a deactivated one restores what it holds on
        # reactivation -- and for a deprovisioned Okta user this record replaced
        # AR-09's "Status DEPROVISIONED but still has ...".
        state = principal.source_status or ("disabled" if principal.status is Status.DISABLED else "")
        detail = f"{principal.label}{f' ({state})' if state else ''}: {said}."
        carries = []
        if roles:
            carries.append(f"the {', '.join(roles)} role" if len(roles) == 1
                           else f"the {', '.join(roles)} roles")
        if held:
            carries.append(held)
        if carries:
            detail += f" It holds {' and '.join(carries)}."
        # Independent of the line above, not an else: a principal can carry
        # a role the source did return and credentials it did not, and the
        # roles reading as the whole of what it holds is the same
        # silence-is-absence claim in a smaller place.
        if not credentials and not known:
            detail += (f" The {principal.source} credential read did not complete, so what it "
                       f"holds is unknown.")
        # Added whenever roles are unread, even beside a role that was
        # returned, unlike the credential sentence, which only has to cover
        # an empty list because `_describe` marks each unread credential.
        # Nothing marks an unread role, and a role the source did return says
        # nothing about the ones it never fetched.
        if not roles_known:
            detail += _roles_unread_note(principal.source, roles, own=user is not None)
        # The blast radius, which is the half of the decision the roles and
        # credentials do not show: handover or decommission turns on what
        # stops working. For a disabled Okta user it is what AR-09 would have
        # listed, and AR-09 stands down for these, so this sentence is the
        # only place that access is reported: in full, in AR-09's words, and
        # as what reactivation restores rather than what it reaches today.
        leftover = _leftover_access(ctx.snapshot, user) if user and user.status in DISABLED_STATUSES else None
        reaches = [] if leftover is not None else _reachable(graph, principal)
        if leftover:
            detail += f" Reactivating it restores {leftover}."
        elif reaches:
            shown = ", ".join(reaches[:MAX_REACHED_SHOWN])
            more = (f" and {len(reaches) - MAX_REACHED_SHOWN} more"
                    if len(reaches) > MAX_REACHED_SHOWN else "")
            detail += f" It reaches {shown}{more}."
        # Graded on what the account can change, not on the owner's rank.
        # `_elevated_roles` is "above ordinary membership", which for Okta
        # includes a read-only admin role that cannot change a thing, so
        # READ_ONLY_ROLES is filtered out; a role that is not one of them is
        # treated as elevated. Unknown write access is not the milder case:
        # see _write_access. What the account reaches is deliberately not
        # graded on: an account is not more dangerous for being in a group
        # everyone is in, and AR-09 never graded on it either. Nor is an
        # unread role list the milder case: see _roles_evidence_complete.
        elevated = [r for r in roles if r.lower() not in READ_ONLY_ROLES]
        writes = _write_access(credentials, known) is not False
        out.append(check.finding(
            graph_subject(principal), detail,
            severity="critical" if elevated or not roles_known or writes else "high",
        ))
    return out


CHECKS: list[Check] = [
    Check(
        "AR-01", "Terminated in HR but account still live", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Deactivate the Okta account and confirm app sessions are revoked.",
        _terminated_still_active, disposition=Disposition.REMOVE, needs_roster=True,
    ),
    Check(
        "AR-02", "Contract or end date has passed", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Deactivate the account or get the end date extended in HR.",
        # REMOVE: "deactivate" is the ask and an HR extension is the data
        # being corrected, not an equal branch -- which is why this is the one
        # of these in `URGENT_CHECKS` and `LEAVER_ACCESS_CHECKS`, opening a
        # ticket that closes on a fresh Okta read.
        _contract_expired, disposition=Disposition.REMOVE, needs_roster=True,
    ),
    Check(
        "AR-03", "Account has no HR record", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Raise with HR: add them to the roster, list them as a service account, or have the account "
        "deactivated. Handled outside the review; no ticket is opened.",
        _not_in_roster, disposition=Disposition.NEITHER, needs_roster=True,
    ),
    Check(
        "AR-04", "No MFA factor enrolled", "high",
        ["SOC 2 CC6.1", "ISO 27001 A.8.5"],
        "Require MFA enrollment through an authentication policy.",
        _mfa_missing, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-05", "Inactive account", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Confirm with the manager whether access is still needed; suspend if not.",
        _inactive, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-06", "Account never used", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Confirm the account is still needed, or deactivate it.",
        _never_signed_in, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-07", "Contractor in employee-only group", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.5.15"],
        "Remove the contractor from the group or document an approved exception.",
        _contractor_in_employee_group, disposition=Disposition.REMOVE,
    ),
    Check(
        "AR-08", "Missing manager or department", "low",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Fill in the profile so the account has an accountable reviewer.",
        _missing_owner, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-09", "Disabled account still holds access", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Remove group memberships and app assignments so reactivation doesn't restore access.",
        _disabled_with_access, disposition=Disposition.REMOVE,
    ),
    Check(
        "AR-10", "API client with admin access", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Confirm each .manage scope and admin role is needed; prefer a least-privilege custom role.",
        # Narrowing scopes is not removing the account, and does not
        # contradict handing it to somebody.
        _privileged_service_app, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-11", "Admin user", "info",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Reviewer confirms each admin still needs the role.",
        _admin_membership, disposition=Disposition.NEITHER,
    ),
    Check(
        "AR-12", "Leaver still holds a working credential", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Revoke the API token. Suspending the account doesn't delete it; deactivating does. An API "
        "client secret they held is AR-18's, because rotating it is confirmed by a reviewer, not by Okta.",
        _leaver_credentials, disposition=Disposition.REMOVE, needs_roster=True,
    ),
    Check(
        "AR-13", "Activity after the termination date", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC7.2", "ISO 27001 A.5.18", "ISO 27001 A.8.16"],
        "Treat as a possible incident: revoke the credential, review what it reached, "
        "and confirm the termination date with HR.",
        _activity_after_leaving, disposition=Disposition.REMOVE, needs_roster=True,
    ),
    Check(
        "AR-14", "App assignment unused", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Remove the direct app assignment in Okta, or record why it is still needed.",
        _unused_app_assignment, disposition=Disposition.REMOVE, needs_app_usage=True,
    ),
    Check(
        "AR-15", "Credential nobody is accountable for", "medium",
        # A.5.16 (identity management: the lifecycle of human and non-human
        # identities) and A.5.18 (access rights), not A.5.17: that control is
        # authentication information -- how secrets are generated, issued and
        # handled -- which is not what an ownerless account evidences. Matches
        # AR-12, the other credential check.
        ["SOC 2 CC6.1", "SOC 2 CC6.2", "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "Establish who owns this account, and revoke its credentials if nobody will own it. "
        "Record the owner in the service account register (config.service_accounts): an entry "
        "with an owner ties the account to that person, so it appears in their access review and "
        "in their departure bundle if they leave. An entry naming no owner declares the account "
        "without making anyone accountable, and is still reported here. So is one naming an owner "
        "no source evidences as a person -- a misspelled address reads as ownership and reaches "
        "nobody, which is why it is worth no more than leaving the field blank.",
        # NEITHER, not RETAIN, which is the near miss worth writing down. The
        # sentence looks like AR-18's -- find an owner, or revoke -- but AR-18
        # starts from an owner who was accountable and has gone, and its first
        # branch is to hand the account on with its access intact, which is
        # what AR-09 contradicts. This one asserts nothing about whether the
        # account survives: it asks who is accountable for the credential, and
        # establishing that is compatible with having removed the groups and
        # apps. The test is whether carrying out the other check's remediation
        # undoes this one's premise.
        _unowned_credentials, disposition=Disposition.NEITHER, needs_graph=True,
    ),
    Check(
        "AR-16", "Access held by an account the source never returned", "high",
        # CC6.2 is the criterion this fails against: access granted without a
        # registered, authorized user behind it. AR-03, the Okta-side sibling,
        # maps to it too.
        ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "Find out what this account is. It reaches things in the org while being absent from the "
        "user read, so neither joiner-mover-leaver automation nor this review can see it directly.",
        _access_without_an_account, disposition=Disposition.NEITHER, needs_graph=True,
    ),
    Check(
        "AR-17", "Someone who left still has access outside Okta", "critical",
        # A.5.18 (access rights, incl. removal on termination), not A.5.11
        # (return of assets): this evidences access that outlived a departure,
        # not equipment nobody handed back. Matches AR-01/AR-12/AR-13. A.8.2
        # (privileged access rights) because the check now reports the elevated
        # roles a departure leaves behind, which is what AR-10 and AR-11 map to.
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.16", "ISO 27001 A.5.18", "ISO 27001 A.8.2"],
        "Remove the access and revoke the credentials in that system. Deactivating the Okta "
        "account did not reach them, which is why they are still here.",
        _leaver_access_outside_okta, disposition=Disposition.REMOVE,
        needs_graph=True, needs_roster=True,
    ),
    Check(
        "AR-18", "Service account a leaver owned or held the credentials of", "high",
        # CC6.1 is the one this fails against most directly: a credential in
        # the estate with no authorized person behind it. CC6.2 and CC6.3
        # because a departure is what put it there and nothing in the
        # termination reached it. A.5.16 covers the lifecycle of non-human
        # identities; A.5.17 (authentication information) because the fix
        # includes rotating a secret the leaver held; A.5.18 the access it
        # still carries; A.8.2 because the finding reports the admin roles
        # these accounts hold, the same reason AR-17 has it.
        ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3",
         "ISO 27001 A.5.16", "ISO 27001 A.5.17", "ISO 27001 A.5.18", "ISO 27001 A.8.2"],
        "Make sure somebody still here answers for this account, and rotate every secret and key "
        "the leaver held or could have read; or decommission it: revoke its credentials and remove "
        "its access. Deactivating the leaver's own account did not touch this one. The finding "
        "says what state the account is in and what it still reaches: a live one is presumably "
        "still being called, and a deactivated one restores everything it holds the moment "
        "somebody reactivates it. Record the owner in the service account register "
        "(config.service_accounts), which ties it to that person's access review and to their "
        "departure bundle if they leave in turn.",
        _leaver_owned_service_accounts, disposition=Disposition.RETAIN,
        needs_graph=True, needs_roster=True,
    ),
]


# Checks that read the graph. Derived from the registry rather than listed, so a
# new one reaches everything downstream -- the reviewer's screen, the departure
# bundle -- without a second list to remember.
GRAPH_CHECKS = tuple(c.id for c in CHECKS if c.needs_graph)


def run_checks(ctx: ReviewContext) -> tuple[list[Finding], list[str]]:
    """Run every check. Returns findings (most severe first) and IDs of skipped checks."""
    findings, skipped = [], []
    for check in CHECKS:
        if check.needs_roster and ctx.roster is None:
            skipped.append(check.id)
            continue
        if check.needs_app_usage and not app_usage_covers(ctx.snapshot, ctx.config.app_unused_days, ctx.as_of):
            skipped.append(check.id)
            continue
        if check.needs_graph and ctx.graph is None:
            skipped.append(check.id)
            continue
        findings.extend(check.run(ctx, check))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check_id, f.subject))
    return findings, skipped
