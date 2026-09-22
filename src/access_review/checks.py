"""Access review checks.

Each check takes a ReviewContext and returns Findings. Every check maps to the
SOC 2 and ISO 27001:2022 controls it provides evidence for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
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
    PrincipalKind,
    Status,
    identity_key,
)
from .register import Register
from .roster import RosterEntry, entry_for

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# The full list is in snapshot.json; the finding shows the most important ones.
MAX_SCOPES_SHOWN = 5
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
    # How far back to read the System Log (AR-12, AR-13). Okta keeps 90 days.
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

    def roster_entry(self, user: User) -> RosterEntry | None:
        return entry_for(self.roster, user.email, user.login)

    def is_service_account(self, user: User) -> bool:
        return self.config.service_accounts.entry(OKTA, user.login) is not None


@dataclass
class Check:
    id: str
    title: str
    severity: str
    controls: list[str]
    remediation: str
    run: Callable[[ReviewContext, Check], list[Finding]]
    needs_roster: bool = False
    # Needs complete app sign-in data covering app_unused_days.
    needs_app_usage: bool = False
    # Reads ctx.graph rather than ctx.snapshot, so it only runs when sources
    # beyond Okta were collected.
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
        check.finding(u.login, f"Last sign-in {u.last_login.date()} ({(ctx.as_of - u.last_login.date()).days} days ago).")
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
    out = []
    for u in ctx.snapshot.users:
        if u.status not in DISABLED_STATUSES:
            continue
        groups = [g.name for g in ctx.snapshot.groups_for(u.id) if g.type != "BUILT_IN"]
        apps = sorted({app.label for app, _ in ctx.snapshot.apps_for(u.id)})
        if groups or apps:
            parts = []
            if groups:
                parts.append(f"groups: {', '.join(sorted(groups))}")
            if apps:
                parts.append(f"apps: {', '.join(apps)}")
            out.append(check.finding(u.login, f"Status {u.status} but still has {'; '.join(parts)}."))
    return out


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


def _clients_set_up_by(snapshot: Snapshot, user_id: str) -> dict[str, str]:
    """Active API clients this person created, rotated or read the secret of,
    as {client_id: label}. Okta keeps no owner field on a client, so the log is
    the only record of who set one up."""
    by_client = {a.client_id: a for a in snapshot.apps if a.client_id and a.status == "ACTIVE"}
    found = {}
    for event in snapshot.events_for_actor(user_id):
        if not event.is_kind(CREDENTIAL_EVENTS):
            continue
        for target in event.targets:
            app = by_client.get(target.get("id"))
            if app:
                found[app.client_id] = app.label
    return found


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
        clients = sorted(_clients_set_up_by(ctx.snapshot, user.id).values())
        if clients:
            noun = "API client" if len(clients) == 1 else "API clients"
            parts.append(f"{noun} they set up: {', '.join(clients)}")
        # Groups and apps are AR-09's job; this check is only about credentials
        # that keep working on their own, whatever the account status is.
        if parts:
            out.append(check.finding(user.login, f"{_left_on(entry)} but still holds {'; '.join(parts)}."))
    return out


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


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
        actors = {user.id} | set(_clients_set_up_by(ctx.snapshot, user.id))
        after = sorted(
            (e for a in actors for e in ctx.snapshot.events_for_actor(a) if e.published and e.published > cutoff),
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
    if graph is None:
        return {}
    principals = {graph_subject(p): p for p in graph.principals}
    out: dict[str, list[tuple[Finding, Link]]] = {}
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
        out.setdefault(link.identity, []).append((f, link))
    return out


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
            notes.append(f"last used {credential.last_used.date()} ({(as_of - credential.last_used.date()).days} days ago)")
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
    if not evidence_complete:
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
            credentials = graph.credentials_for(principal.key)
            known = _credential_evidence_complete(graph, principal.source)
            held = _describe(credentials, ctx.as_of)
            roles = _elevated_roles(graph, principal)
            detail = (f"{_left_on(entry)}, but {principal.source} still shows {principal.label} "
                      f"{principal.source_status or 'with access'}")
            carries = []
            if roles:
                carries.append(f"the {', '.join(roles)} role" if len(roles) == 1
                               else f"the {', '.join(roles)} roles")
            if held:
                carries.append(held)
            detail += f" holding {' and '.join(carries)}." if carries else "."
            out.append(check.finding(
                graph_subject(principal), detail,
                # An elevated role is write access to the organization itself.
                # Grading on credentials alone ranked a departed organization
                # owner below a departed ordinary member holding one token,
                # because the owner's own token happened to be read-only.
                # Unknown write access is not the milder case: see _write_access.
                severity="critical" if roles or _write_access(credentials, known) is not False else "high",
            ))
    return out


CHECKS: list[Check] = [
    Check(
        "AR-01", "Terminated in HR but account still live", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Deactivate the Okta account and confirm app sessions are revoked.",
        _terminated_still_active, needs_roster=True,
    ),
    Check(
        "AR-02", "Contract or end date has passed", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Deactivate the account or get the end date extended in HR.",
        _contract_expired, needs_roster=True,
    ),
    Check(
        "AR-03", "Account has no HR record", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Raise with HR: add them to the roster, list them as a service account, or have the account "
        "deactivated. Handled outside the review; no ticket is opened.",
        _not_in_roster, needs_roster=True,
    ),
    Check(
        "AR-04", "No MFA factor enrolled", "high",
        ["SOC 2 CC6.1", "ISO 27001 A.8.5"],
        "Require MFA enrollment through an authentication policy.",
        _mfa_missing,
    ),
    Check(
        "AR-05", "Inactive account", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Confirm with the manager whether access is still needed; suspend if not.",
        _inactive,
    ),
    Check(
        "AR-06", "Account never used", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Confirm the account is still needed, or deactivate it.",
        _never_signed_in,
    ),
    Check(
        "AR-07", "Contractor in employee-only group", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.5.15"],
        "Remove the contractor from the group or document an approved exception.",
        _contractor_in_employee_group,
    ),
    Check(
        "AR-08", "Missing manager or department", "low",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Fill in the profile so the account has an accountable reviewer.",
        _missing_owner,
    ),
    Check(
        "AR-09", "Disabled account still holds access", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Remove group memberships and app assignments so reactivation doesn't restore access.",
        _disabled_with_access,
    ),
    Check(
        "AR-10", "API client with admin access", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Confirm each .manage scope and admin role is needed; prefer a least-privilege custom role.",
        _privileged_service_app,
    ),
    Check(
        "AR-11", "Admin user", "info",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Reviewer confirms each admin still needs the role.",
        _admin_membership,
    ),
    Check(
        "AR-12", "Leaver still holds a working credential", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Revoke the API token and rotate or delete the client's credentials. "
        "Deactivating the account does not do either.",
        _leaver_credentials, needs_roster=True,
    ),
    Check(
        "AR-13", "Activity after the termination date", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC7.2", "ISO 27001 A.5.18", "ISO 27001 A.8.16"],
        "Treat as a possible incident: revoke the credential, review what it reached, "
        "and confirm the termination date with HR.",
        _activity_after_leaving, needs_roster=True,
    ),
    Check(
        "AR-14", "App assignment unused", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Remove the direct app assignment in Okta, or record why it is still needed.",
        _unused_app_assignment, needs_app_usage=True,
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
        _unowned_credentials, needs_graph=True,
    ),
    Check(
        "AR-16", "Access held by an account the source never returned", "high",
        # CC6.2 is the criterion this fails against: access granted without a
        # registered, authorized user behind it. AR-03, the Okta-side sibling,
        # maps to it too.
        ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "Find out what this account is. It reaches things in the org while being absent from the "
        "user read, so neither joiner-mover-leaver automation nor this review can see it directly.",
        _access_without_an_account, needs_graph=True,
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
        _leaver_access_outside_okta, needs_graph=True, needs_roster=True,
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
