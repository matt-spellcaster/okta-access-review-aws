"""Build a Snapshot from the live Okta API."""

from __future__ import annotations

import sys
from datetime import date, datetime, time, timedelta, timezone, tzinfo

from .models import (
    CREDENTIAL_EVENTS,
    SIGN_IN_STATUSES,
    ActivityEvent,
    ApiToken,
    App,
    Group,
    Snapshot,
    User,
    parse_time,
)
from .okta import OktaClient, OktaError
from .roster import RosterEntry, entry_for

PAGE = {"limit": 200}
# Per System Log query. A leaver with more activity than this is already the
# finding; the cap stops one noisy account from stalling the whole review.
MAX_EVENTS = 500
# For the org-wide SSO read behind AR-14 and review proposals. Sized for a
# small tenant; if it is ever hit, usage is marked incomplete and nothing is
# proposed for revocation on the strength of it.
MAX_SSO_EVENTS = 50_000
SSO_EVENT = "user.authentication.sso"


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


class _Optional:
    """Calls an endpoint that needs an extra scope or admin permission. After
    the first 403 it records a gap, warns once and stops calling, so the review
    still runs and the report says what is missing."""

    def __init__(self, client: OktaClient, what: str, scope: str, affects: str, gaps: list[str]):
        self.client = client
        self.what = what
        self.scope = scope
        self.affects = affects
        self.gaps = gaps
        self.allowed = True

    def get(self, path: str, missing_ok: bool = False) -> list | None:
        if not self.allowed:
            return None
        try:
            return self.client.get_all(path)
        except OktaError as e:
            if missing_ok and e.status == 404:
                return []
            self._refused(e)
            return None

    def get_capped(self, path: str, params: dict, max_items: int = MAX_EVENTS) -> tuple[list, bool] | None:
        if not self.allowed:
            return None
        try:
            return self.client.get_capped(path, params, max_items)
        except OktaError as e:
            self._refused(e)
            return None

    def _refused(self, e: OktaError) -> None:
        """Record the gap and stop calling. Anything but a 403 is a real error."""
        if e.status != 403:
            raise e
        gap = (
            f"Could not read {self.what}; {self.affects} may be incomplete. "
            f"Needs the {self.scope} scope and an admin role allowed to view this data. ({e})"
        )
        _warn(gap)
        self.gaps.append(gap)
        self.allowed = False


def _role_labels(assignments: list) -> list[str]:
    return sorted({a.get("label") or a.get("type", "unknown") for a in assignments})


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _collect_activity(
    logs_api: _Optional,
    users: list[User],
    apps: list[App],
    roster: dict[str, RosterEntry],
    as_of: date,
    lookback_days: int,
    tz: tzinfo,
    gaps: list[str],
) -> tuple[list[ActivityEvent], datetime | None]:
    """Read what the org's leavers, and the API clients they set up, have done.

    Queried per leaver rather than across the org, so the volume follows the
    number of people who left, not the size of the org.
    """
    horizon = datetime.combine(as_of - timedelta(days=lookback_days), time.min, tzinfo=timezone.utc)
    events: list[ActivityEvent] = []
    seen: set[str] = set()

    def fetch(actor_id: str, since: datetime, kinds: tuple[str, ...] | None = None) -> tuple[list[ActivityEvent], bool]:
        query = f'actor.id eq "{actor_id}"'
        if kinds:
            # Narrowed server-side. Asking for everything and filtering here
            # spends the cap on events no check will read.
            query += " and (" + " or ".join(f'eventType sw "{k}"' for k in kinds) + ")"
        result = logs_api.get_capped("/api/v1/logs", {"since": _iso(since), "filter": query})
        if result is None:
            return [], False
        raw, truncated = result
        fresh = [ActivityEvent.from_okta(e) for e in raw if e.get("uuid") not in seen]
        seen.update(e["uuid"] for e in raw if e.get("uuid"))
        return fresh, truncated

    def credentials(actor_id: str, who: str) -> None:
        """Who set up which API client. Needs the whole window, because they
        set it up while they still worked here."""
        found, truncated = fetch(actor_id, horizon, CREDENTIAL_EVENTS)
        events.extend(found)
        if truncated:
            gaps.append(
                f"More than {MAX_EVENTS} credential events for {who} since {horizon.date()}; "
                f"the API clients AR-12 lists for them may be incomplete."
            )

    def activity(actor_id: str, who: str, after: datetime) -> None:
        """What they did after leaving. Only the window AR-13 reads, so the cap
        is not spent on months of ordinary work before the end date."""
        found, truncated = fetch(actor_id, max(after, horizon))
        events.extend(found)
        if truncated:
            gaps.append(
                f"More than {MAX_EVENTS} System Log events for {who} after {after.date()}. "
                f"Okta returns the log oldest first, so AR-13 read the earliest {MAX_EVENTS}: "
                f"its counts and last-seen date are a lower bound, and later activity is not shown."
            )

    leavers = [(u, e) for u in users if (e := entry_for(roster, u.email, u.login)) and e.is_gone(as_of)]
    for user, entry in leavers:
        credentials(user.id, user.login)
        ends = entry.access_ends(tz)
        if ends:
            activity(user.id, user.login, ends)
        if entry.end_date and entry.end_date < horizon.date():
            gaps.append(
                f"{user.login} left on {entry.end_date}, before the {lookback_days}-day System Log "
                f"window opens on {horizon.date()}. Activity in between cannot be checked (AR-13)."
            )

    # An API client the leaver set up keeps working on its own credentials, so
    # its own activity counts as theirs.
    by_client = {a.client_id: a for a in apps if a.client_id and a.status == "ACTIVE"}
    owned: dict[str, datetime] = {}
    for user, entry in leavers:
        ends = entry.access_ends(tz)
        if ends is None:
            continue
        for event in events:
            if event.actor_id != user.id or not event.is_kind(CREDENTIAL_EVENTS):
                continue
            for target in event.targets:
                if target.get("id") in by_client:
                    owned[target["id"]] = min(owned.get(target["id"], ends), ends)
    for client_id, after in sorted(owned.items()):
        activity(client_id, by_client[client_id].label, after)

    return events, horizon


def _collect_app_usage(
    usage_api: _Optional, as_of: date, days: int, gaps: list[str]
) -> tuple[dict[tuple[str, str], datetime], datetime | None, bool]:
    """Last SSO sign-in per (user, app) over the window, from one org-wide query.

    Only the aggregate is kept; the raw events never reach the snapshot.
    Returns (usage, since, complete). since is None when the log could not be read.
    """
    since = datetime.combine(as_of - timedelta(days=days), time.min, tzinfo=timezone.utc)
    result = usage_api.get_capped(
        "/api/v1/logs",
        {"since": _iso(since), "filter": f'eventType eq "{SSO_EVENT}"'},
        max_items=MAX_SSO_EVENTS,
    )
    if result is None:
        return {}, None, False
    raw, truncated = result
    usage: dict[tuple[str, str], datetime] = {}
    for e in raw:
        event = ActivityEvent.from_okta(e)
        if event.event_type != SSO_EVENT or event.outcome != "SUCCESS" or not event.published:
            continue
        for target in event.targets:
            if target.get("type") != "AppInstance" or not target.get("id"):
                continue
            key = (event.actor_id, target["id"])
            if key not in usage or event.published > usage[key]:
                usage[key] = event.published
    if truncated:
        gaps.append(
            f"More than {MAX_SSO_EVENTS} app sign-in events since {since.date()}. Okta returns the log "
            f"oldest first, so recent sign-ins are missing: AR-14 is skipped and no app access is "
            f"proposed for revocation."
        )
    return usage, since, not truncated


def collect(
    client: OktaClient,
    roster: dict[str, RosterEntry] | None = None,
    as_of: date | None = None,
    lookback_days: int = 90,
    tz: tzinfo = timezone.utc,
    app_usage_days: int | None = None,
) -> Snapshot:
    """app_usage_days turns on the org-wide app sign-in read (AR-14 and review
    proposals). None leaves it off, and AR-14 is skipped."""
    collected_at = datetime.now(timezone.utc)
    gaps: list[str] = []
    factors_api = _Optional(client, "MFA factors", "okta.users.read", "AR-04", gaps)
    roles_api = _Optional(client, "admin role assignments", "okta.roles.read", "AR-10 and AR-11", gaps)
    grants_api = _Optional(client, "app API scope grants", "okta.appGrants.read", "AR-10", gaps)
    tokens_api = _Optional(client, "Okta API tokens", "okta.apiTokens.read", "AR-12", gaps)
    logs_api = _Optional(client, "System Log events", "okta.logs.read", "AR-12 and AR-13", gaps)
    usage_api = _Optional(
        client, "System Log app sign-ins", "okta.logs.read", "AR-14 and review proposals", gaps
    )

    # /users hides DEPROVISIONED users unless asked for them explicitly.
    raw_users = client.get_all("/api/v1/users", PAGE)
    raw_users += client.get_all("/api/v1/users", {**PAGE, "search": 'status eq "DEPROVISIONED"'})

    users = []
    for u in raw_users:
        user = User(
            id=u["id"],
            login=u["profile"]["login"],
            status=u["status"],
            created=parse_time(u.get("created")),
            last_login=parse_time(u.get("lastLogin")),
            profile=u["profile"],
        )
        if user.status in SIGN_IN_STATUSES:
            factors = factors_api.get(f"/api/v1/users/{user.id}/factors")
            if factors is not None:
                user.factors = sorted({f["factorType"] for f in factors if f.get("status") == "ACTIVE"})
        if user.status != "DEPROVISIONED":
            roles = roles_api.get(f"/api/v1/users/{user.id}/roles")
            if roles is not None:
                user.admin_roles = _role_labels(roles)
        users.append(user)

    groups = []
    for g in client.get_all("/api/v1/groups", PAGE):
        members = client.get_all(f"/api/v1/groups/{g['id']}/users", PAGE)
        groups.append(
            Group(id=g["id"], name=g["profile"]["name"], type=g.get("type", ""), members={m["id"] for m in members})
        )

    apps = []
    for a in client.get_all("/api/v1/apps", PAGE):
        app_users = client.get_all(f"/api/v1/apps/{a['id']}/users", PAGE)
        app_groups = client.get_all(f"/api/v1/apps/{a['id']}/groups", PAGE)
        grants = grants_api.get(f"/api/v1/apps/{a['id']}/grants") or []
        roles = []
        # Only OAuth service clients can hold admin roles.
        client_id = a.get("credentials", {}).get("oauthClient", {}).get("client_id")
        grant_types = a.get("settings", {}).get("oauthClient", {}).get("grant_types", [])
        service_client = bool(client_id) and "client_credentials" in grant_types
        if service_client:
            roles = roles_api.get(f"/oauth2/v1/clients/{client_id}/roles", missing_ok=True) or []
        direct = [u for u in app_users if u.get("scope", "USER") == "USER"]
        apps.append(
            App(
                id=a["id"],
                label=a["label"],
                status=a.get("status", ""),
                sign_on_mode=a.get("signOnMode", ""),
                # Group-based assignments show up here too; keep only direct ones.
                users={u["id"] for u in direct},
                groups={g["id"] for g in app_groups},
                granted_scopes=sorted({g["scopeId"] for g in grants if g.get("status", "ACTIVE") == "ACTIVE"}),
                admin_roles=_role_labels(roles),
                service_client=service_client,
                client_id=client_id or "",
                assigned={u["id"]: parse_time(u.get("created")) for u in direct},
            )
        )

    # The review app always exists, so if it's missing the admin role is hiding apps.
    if client.client_id not in {a.id for a in apps}:
        gap = (
            f"The app list does not include this review app ({client.client_id}), so the admin role is "
            f"hiding apps. App assignments, AR-09 and AR-10 are incomplete ({len(apps)} apps visible)."
        )
        _warn(gap)
        gaps.append(gap)

    raw_tokens = tokens_api.get("/api/v1/api-tokens") or []
    api_tokens = [ApiToken.from_dict(t) for t in raw_tokens if t.get("userId")]

    # Activity is only read for people the roster says have left, so without a
    # roster there is nobody to ask about and activity_since stays None.
    events: list[ActivityEvent] = []
    activity_since = None
    if roster is not None:
        events, activity_since = _collect_activity(
            logs_api, users, apps, roster, as_of or collected_at.date(), lookback_days, tz, gaps
        )

    usage: dict[tuple[str, str], datetime] = {}
    usage_since, usage_complete = None, True
    if app_usage_days is not None:
        usage, usage_since, usage_complete = _collect_app_usage(
            usage_api, as_of or collected_at.date(), app_usage_days, gaps
        )

    return Snapshot(
        org_url=client.org_url,
        collected_at=collected_at,
        users=users,
        groups=groups,
        apps=apps,
        gaps=gaps,
        api_tokens=api_tokens,
        events=events,
        activity_since=activity_since,
        app_usage=usage,
        app_usage_since=usage_since,
        app_usage_complete=usage_complete,
    )
