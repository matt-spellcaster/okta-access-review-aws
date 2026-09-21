"""Project an Okta `Snapshot` into the identity graph.

`Snapshot` is unchanged and stays the Okta source adapter's output: the
fourteen existing checks keep reading it directly. This module reads it and
writes the source-agnostic shapes, so a check about identity across sources
never has to know what Okta calls things.

Okta is the IdP, so its user accounts are where identities come from: every
other source's principals are linked back to one of these. That is why an Okta
user's own link is `sso_identity` -- it is not a match, it is the identity.
"""

from __future__ import annotations

from datetime import datetime

from ..models import (
    CREDENTIAL_EVENTS,
    DISABLED_STATUSES,
    LIVE_STATUSES,
    READ_ONLY_ROLES,
    TOKEN_EVENTS,
    ActivityEvent,
    App,
    Snapshot,
    User,
)
from .model import (
    Credential,
    CredentialKind,
    Grant,
    GrantKind,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKind,
    SourceMeta,
    Status,
)

OKTA = "okta"


def _status(okta_status: str) -> Status:
    if okta_status in LIVE_STATUSES:
        return Status.ACTIVE
    if okta_status in DISABLED_STATUSES:
        return Status.DISABLED
    return Status.UNKNOWN


def _write_access(app: App) -> bool | None:
    """Whether an API client can change anything: a write scope, or an admin
    role that is not one of the look-but-don't-touch ones.

    None when the client has neither scopes nor admin roles recorded. That is
    what an ungranted scope read looks like as well as a genuinely read-nothing
    client, and False would be a claim made from data nobody read.
    """
    if not app.granted_scopes and not app.admin_roles:
        return None
    return any(r.lower() not in READ_ONLY_ROLES for r in app.admin_roles) or any(
        not s.endswith(".read") for s in app.granted_scopes
    )


def _last_token_grant(events: list[ActivityEvent], client_id: str) -> datetime | None:
    """When this client last exchanged its credentials for access. Events are
    only collected for leavers and the clients they set up, so None here means
    no record, never 'idle'."""
    times = [
        e.published
        for e in events
        if e.actor_id == client_id and e.is_kind(TOKEN_EVENTS) and e.published
    ]
    return max(times, default=None)


def _creator(snapshot: Snapshot, client_id: str) -> tuple[ActivityEvent, User] | None:
    """The earliest credential-lifecycle event for this client, with the user
    who performed it.

    Okta keeps no owner field on an API client, so the System Log is the only
    record of who set one up. This generalises what AR-12 does for a single
    leaver. It establishes accountability, not ownership -- and the creator may
    themselves have left, which the checks treat as a worse finding.
    """
    by_id = {u.id: u for u in snapshot.users}
    found = None
    for event in snapshot.events:
        if not event.is_kind(CREDENTIAL_EVENTS) or not event.published:
            continue
        if not any(t.get("id") == client_id for t in event.targets):
            continue
        user = by_id.get(event.actor_id)
        if user and (found is None or event.published < found[0].published):
            found = (event, user)
    return found


def project_snapshot(snapshot: Snapshot, declared_services: list[str] | None = None) -> IdentityGraph:
    """Turn a snapshot into a one-source graph.

    `declared_services` is `Config.service_accounts`: logins someone has
    declared are not people. It is the only thing that makes an account a
    service account here -- an undeclared bot account is itself the finding
    (AR-03), so guessing from the login would hide it.
    """
    declared = {s.lower() for s in declared_services or []}
    principals: list[Principal] = []
    credentials: list[Credential] = []
    grants: list[Grant] = []
    links: list[Link] = []

    for user in snapshot.users:
        service = user.login.lower() in declared
        key = (OKTA, user.id)
        principals.append(
            Principal(
                source=OKTA,
                id=user.id,
                label=user.login,
                kind=PrincipalKind.SERVICE if service else PrincipalKind.HUMAN,
                status=_status(user.status),
                source_status=user.status,
                email=user.email,
                created=user.created,
                last_used=user.last_login,
            )
        )
        if service:
            links.append(Link(key, LinkMethod.DECLARED, "", "declared a service account in the review config"))
        elif user.email:
            links.append(Link(key, LinkMethod.SSO_IDENTITY, user.email, f"Okta user {user.login}"))
        for role in user.admin_roles or []:
            grants.append(Grant(OKTA, user.id, GrantKind.ROLE, role, role))

    for group in snapshot.groups:
        for member in sorted(group.members):
            grants.append(Grant(OKTA, member, GrantKind.GROUP, group.id, group.name))

    members_of = {g.id: (g.name, sorted(g.members)) for g in snapshot.groups}
    for app in snapshot.apps:
        for user_id in sorted(app.users):
            grants.append(Grant(OKTA, user_id, GrantKind.APP, app.id, app.label))
        for group_id in sorted(app.groups):
            name, members = members_of.get(group_id, (group_id, []))
            for user_id in members:
                grants.append(Grant(OKTA, user_id, GrantKind.APP, app.id, app.label, f"group:{name}"))

    for token in snapshot.api_tokens:
        credentials.append(
            Credential(
                source=OKTA,
                id=token.id,
                kind=CredentialKind.OKTA_API_TOKEN,
                label=token.name,
                holder=token.user_id,
                created=token.created,
                # Okta refreshes lastUpdated when a token is used -- it is the
                # closest thing to a last-used time the API exposes.
                last_used=token.last_updated,
                expires=token.expires,
            )
        )

    for app in snapshot.apps:
        if not (app.service_client and app.client_id):
            continue
        key = (OKTA, app.id)
        last_used = _last_token_grant(snapshot.events, app.client_id)
        principals.append(
            Principal(
                source=OKTA,
                id=app.id,
                label=app.label,
                kind=PrincipalKind.SERVICE,
                status=Status.ACTIVE if app.status == "ACTIVE" else Status.DISABLED,
                source_status=app.status,
                last_used=last_used,
            )
        )
        credentials.append(
            Credential(
                source=OKTA,
                id=app.client_id,
                kind=CredentialKind.OAUTH_CLIENT,
                label=app.label,
                holder=app.id,
                last_used=last_used,
                write_access=_write_access(app),
            )
        )
        for role in app.admin_roles:
            grants.append(Grant(OKTA, app.id, GrantKind.ROLE, role, role))
        found = _creator(snapshot, app.client_id)
        if found:
            event, creator = found
            links.append(
                Link(
                    key,
                    LinkMethod.CREATOR,
                    creator.email,
                    f"{event.event_type} by {creator.login} on {event.published.date()}",
                )
            )

    meta = SourceMeta(
        source=OKTA,
        org=snapshot.org_url,
        collected_at=snapshot.collected_at,
        gaps=list(snapshot.gaps),
        activity_since=snapshot.activity_since,
        # Reads that were cut short already appear in gaps; this is the one
        # completeness signal the snapshot carries separately.
        activity_complete=snapshot.app_usage_complete,
    )
    return IdentityGraph(
        sources=[meta],
        principals=principals,
        credentials=credentials,
        grants=grants,
        links=links,
    )
