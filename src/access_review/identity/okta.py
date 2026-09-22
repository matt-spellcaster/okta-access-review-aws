"""Project an Okta `Snapshot` into the identity graph.

`Snapshot` is unchanged and stays the Okta source adapter's output: the
fourteen existing checks keep reading it directly. This module reads it and
writes the source-agnostic shapes, so a check about identity across sources
never has to know what Okta calls things.

Okta is the IdP, so its user accounts are where identities come from: every
other source's principals are linked back to one of these. That is why an Okta
user's own link is `sso_identity` -- it is not a match, it is the identity.
Which is also why the key comes from the profile's email attribute and never
from the login: `User.email` falls back to the login when the profile has no
email, and an identity key built from a fallback is a guess wearing the label
of an authoritative join.

Nothing here turns an unread value into a claim. Where a read may not have
happened, the projection says unknown and records a gap.
"""

from __future__ import annotations

from datetime import datetime

from ..models import (
    APP_DISABLED_STATUSES,
    APP_LIVE_STATUSES,
    CREATION_EVENTS,
    DISABLED_STATUSES,
    LIVE_STATUSES,
    READ_ONLY_ROLES,
    TOKEN_EVENTS,
    ActivityEvent,
    App,
    Snapshot,
    User,
)
from ..register import Register
from .graph import (
    AppRef,
    Credential,
    CredentialKind,
    Grant,
    GrantKind,
    GroupKey,
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


def _app_status(okta_status: str) -> Status:
    """App statuses go through their own mapping with the same unknown branch
    users get. A service client is the principal holding a long-lived OAuth
    credential, so reading an unrecognised or unread status as 'disabled'
    would retire it on paper while it keeps working."""
    if okta_status in APP_LIVE_STATUSES:
        return Status.ACTIVE
    if okta_status in APP_DISABLED_STATUSES:
        return Status.DISABLED
    return Status.UNKNOWN


def _write_access(app: App, source_complete: bool) -> bool | None:
    """Whether an API client can change anything: a write scope, or an admin
    role that is not one of the look-but-don't-touch ones.

    Scopes and admin roles are fetched by two separate optional reads in
    collect.py (`okta.appGrants.read` and `okta.roles.read`) that fail
    independently and both come back as an empty list when they do. So an
    empty list is only evidence of "nothing granted" when the whole source read
    completed. Otherwise this is unknown, because reporting a client as unable
    to write when its scopes were never read is how a review misses the one
    credential that mattered.
    """
    if any(r.lower() not in READ_ONLY_ROLES for r in app.admin_roles) or any(
        not s.endswith(".read") for s in app.granted_scopes
    ):
        return True
    return False if source_complete else None


def _index_events(snapshot: Snapshot) -> tuple[dict[str, tuple[ActivityEvent, User]], dict[str, datetime]]:
    """One pass over the System Log for both things the projection needs.

    Returns the earliest creation event per target (with the user who performed
    it) and the last token grant per actor. Creation only: reading a client's
    secret or adding one is custody, which AR-12 reports as a secret to rotate,
    and counting it here named whoever once opened a colleague's client as the
    person who answers for it. One pass rather than
    two per service client, which at a few hundred clients is the difference
    between a scan and a cross product.

    Okta keeps no owner field on an API client, so the log is the only record
    of who set one up. It establishes accountability, not ownership -- and the creator may themselves
    have left, which the checks treat as a worse finding.
    """
    by_id = {u.id: u for u in snapshot.users}
    creators: dict[str, tuple[ActivityEvent, User]] = {}
    last_token: dict[str, datetime] = {}
    for event in snapshot.events:
        if not event.published:
            continue
        if event.is_kind(CREATION_EVENTS):
            user = by_id.get(event.actor_id)
            if user:
                for target in event.targets:
                    target_id = target.get("id")
                    if not target_id:
                        continue
                    found = creators.get(target_id)
                    if found is None or event.published < found[0].published:
                        creators[target_id] = (event, user)
        if event.is_kind(TOKEN_EVENTS):
            seen = last_token.get(event.actor_id)
            if seen is None or event.published > seen:
                last_token[event.actor_id] = event.published
    return creators, last_token


def identity_key(user: User) -> str:
    """The identity key an Okta user's principals link to.

    The profile's own email attribute, lowercased, and never `User.email`,
    which falls back to the login when the profile has no email. An identity
    key built from that fallback merges two accounts the moment one person's
    login is another person's email address, and a merged identity reports a
    credential as accounted for by the wrong person.

    Empty when the profile has no email: that is a user who cannot be joined
    across sources, not a user who owns every unattributed principal. Callers
    must treat "" as no identity rather than as a key.
    """
    return (user.profile.get("email") or "").strip().lower()


def project_snapshot(snapshot: Snapshot, register: Register | None = None) -> IdentityGraph:
    """Turn a snapshot into a one-source graph.

    `register` is `Config.service_accounts`: the accounts someone has declared
    are not people, and who answers for each. It is the only thing that makes an
    account a service account here -- an undeclared bot account is itself the
    finding (AR-03), so guessing from the login would hide it.

    An entry with an owner links the account to that person, so it reaches their
    review item and their departure bundle. An entry without one links it to
    nobody (`Link.identity` is empty), which is `graph.unattributed()` and a
    downgraded AR-15 rather than silence.
    """
    register = Register.from_config(register if register is not None else Register())
    matched: set[tuple[str, str]] = set()
    source_complete = not snapshot.gaps
    creators, last_token = _index_events(snapshot)
    principals: list[Principal] = []
    credentials: list[Credential] = []
    grants: list[Grant] = []
    links: list[Link] = []
    gaps = list(snapshot.gaps)

    for user in snapshot.users:
        # Matched on the login, which is what the register has always keyed on
        # and what a person writing an entry knows the account by.
        entry = register.entry(OKTA, user.login)
        service = entry is not None
        key = (OKTA, user.id)
        principals.append(
            Principal(
                source=OKTA,
                id=user.id,
                label=user.login,
                kind=PrincipalKind.SERVICE if service else PrincipalKind.HUMAN,
                status=_status(user.status),
                source_status=user.status,
                # The profile attribute only, for the same reason the link key is:
                # User.email falls back to the login, and a field named email that
                # holds a login is the join bug waiting to happen again.
                email=identity_key(user),
                created=user.created,
                last_used=user.last_login,
            )
        )
        if entry is not None:
            matched.add(entry.key)
            # No SSO_IDENTITY link for a declared account, even though it has a
            # profile email: that address is the account's own, so linking on it
            # would invent a person named svc-ci. The register is the only thing
            # that says who a service account belongs to.
            links.append(Link(key, LinkMethod.DECLARED, entry.owner, entry.evidence()))
        else:
            profile_email = identity_key(user)
            if profile_email:
                links.append(Link(key, LinkMethod.SSO_IDENTITY, profile_email, f"Okta user {user.login}"))
        for role in user.admin_roles or []:
            grants.append(Grant(OKTA, user.id, GrantKind.ROLE, role, role))

    # Access can be granted to an id the user read never returned -- a capped
    # page, a filtered query. Left as a bare grant it would be access held by
    # nobody: invisible to unlinked() and uncounted by coverage(). It becomes a
    # principal we know nothing about, which is a finding, plus a gap.
    known_ids = {u.id for u in snapshot.users}
    unknown_ids: set[str] = set()

    def note(user_id: str) -> str:
        if user_id not in known_ids:
            unknown_ids.add(user_id)
        return user_id

    for group in snapshot.groups:
        for member in sorted(group.members):
            grants.append(Grant(OKTA, note(member), GrantKind.GROUP, group.id, group.name))

    # App-via-group access is recorded once per group, not once per (member,
    # app) pair: an org-wide group over 250 apps is 250 entries here and 1.25M
    # grants materialised, which is the difference between fitting in the
    # collect Lambda and not. `grants_for` expands it against each member's own
    # GROUP grant, which is emitted above and is what says who is in the group.
    names_of = {g.id: g.name for g in snapshot.groups}
    group_apps: dict[GroupKey, list[AppRef]] = {}
    for app in snapshot.apps:
        for user_id in sorted(app.users):
            grants.append(Grant(OKTA, note(user_id), GrantKind.APP, app.id, app.label))
        for group_id in sorted(app.groups):
            name = names_of.get(group_id, "")
            if not name:
                gaps.append(
                    f"App {app.label!r} is assigned to group {group_id}, which the group read did "
                    f"not return. Who reaches it through that group is unknown."
                )
                continue
            group_apps.setdefault((OKTA, group_id), []).append((app.id, app.label))

    for user_id in sorted(unknown_ids):
        principals.append(
            Principal(source=OKTA, id=user_id, label=user_id, kind=PrincipalKind.UNKNOWN, status=Status.UNKNOWN)
        )
    if unknown_ids:
        gaps.append(
            f"{len(unknown_ids)} account(s) hold group or app access but were not returned by the "
            f"user read: {', '.join(sorted(unknown_ids))}. They are counted as unlinked."
        )

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

    # Two service clients can carry the same label -- the same reason ticket
    # identity is hashed from the stable id and not the name. A register entry
    # naming a label that fits both would vouch for two accounts where somebody
    # meant one, so it declares neither and says so. The client id is the way
    # out, and it is what the Okta console shows beside the app.
    # A deactivated client keeps its label and its client id, and the apps read
    # returns it: `collect` filters users to ACTIVE and filters apps not at all.
    # So the realistic way two clients share a label is a replacement -- the old
    # "Terraform Automation" deactivated, the new one created beside it -- and
    # counting the dead one made a correct entry declare neither, which put the
    # live client back into AR-15 at full severity for being undeclared while it
    # was declared. A label picks out one client when only one client is still
    # running, and a client that is the only one carrying its label is declared
    # whatever its status, so decommissioning does not undeclare it.
    # `_app_status` reads an unrecognised status as UNKNOWN rather than
    # DISABLED, so such a client stays in the count and keeps the label
    # ambiguous: the milder answer here is the one that vouches for a client
    # somebody may not have meant.
    by_label: dict[str, list[App]] = {}
    for app in snapshot.apps:
        if app.service_client and app.client_id:
            by_label.setdefault(app.label.lower(), []).append(app)
    declares = {}
    for label, sharing in by_label.items():
        running = [a for a in sharing if _app_status(a.status) is not Status.DISABLED]
        one = sharing if len(sharing) == 1 else running
        if len(one) == 1:
            declares[label] = one[0].id
    # Gathered before the loop and reported once per entry, not once per client
    # it could have meant: the register made one ambiguous claim, and an auditor
    # counting gaps should read one.
    ambiguous = {}
    for label, sharing in by_label.items():
        if label in declares:
            continue
        found = register.entry(OKTA, label)
        if found is not None:
            ambiguous[found.key] = (found, len(sharing))
    for found, count in ambiguous.values():
        matched.add(found.key)  # matched, just not usably: this gap, not the stale one
        gaps.append(
            f"The service account register declares {found.id!r}, which is the label of {count} API "
            f"service clients in this org. It declares none of them: vouching for the wrong one "
            f"would record a credential as accounted for while nobody is. Name the client id instead."
        )

    for app in snapshot.apps:
        if not (app.service_client and app.client_id):
            continue
        key = (OKTA, app.id)
        last_used = last_token.get(app.client_id)
        principals.append(
            Principal(
                source=OKTA,
                id=app.id,
                label=app.label,
                kind=PrincipalKind.SERVICE,
                status=_app_status(app.status),
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
                write_access=_write_access(app, source_complete),
                usage_read=snapshot.activity_actors is not None and app.client_id in snapshot.activity_actors,
            )
        )
        for role in app.admin_roles:
            grants.append(Grant(OKTA, app.id, GrantKind.ROLE, role, role))
        # A service client is declared by its client id, or by its app label
        # when that label picks out exactly one client. `graph_subject` still
        # uses the stable app id. A DECLARED entry that names an owner outranks
        # the CREATOR link below, which is the point -- an audit log says who
        # made it, the register says who answers for it. One that names nobody
        # does not, so declaring an account never erases its creator: see the
        # strength ordering in IdentityGraph.
        entry = register.entry(OKTA, app.client_id)
        if entry is None and declares.get(app.label.lower()) == app.id:
            entry = register.entry(OKTA, app.label)
        if entry is not None:
            matched.add(entry.key)
            links.append(Link(key, LinkMethod.DECLARED, entry.owner, entry.evidence()))
        # Events name an app by its app id or its client id depending on type.
        found = min((f for f in (creators.get(app.id), creators.get(app.client_id)) if f),
                    key=lambda f: f[0].published, default=None)
        if found:
            event, creator = found
            creator_email = identity_key(creator)
            if creator_email:
                links.append(
                    Link(
                        key,
                        LinkMethod.CREATOR,
                        creator_email,
                        f"{event.event_type} by {creator.login} on {event.published.date()}",
                    )
                )

    gaps.extend(register.stale(OKTA, matched))

    meta = SourceMeta(
        source=OKTA,
        org=snapshot.org_url,
        collected_at=snapshot.collected_at,
        gaps=gaps,
        activity_since=snapshot.activity_since,
        # activity_since is None when the System Log was not read at all, and
        # app_usage_complete is False when the usage read was cut short. Events
        # are only collected for rostered leavers and the clients they held the
        # credentials of, which is per credential and so not this flag's to say:
        # `Credential.usage_read` carries it.
        activity_complete=snapshot.activity_since is not None and snapshot.app_usage_complete,
    )
    return IdentityGraph(
        sources=[meta],
        principals=principals,
        credentials=credentials,
        grants=grants,
        links=links,
        group_apps=group_apps,
    )
