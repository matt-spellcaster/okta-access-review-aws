"""The GitHub source adapter: its own snapshot shape, and the projection of
that shape into the identity graph.

Model and projection live together here, unlike Okta's, because nothing else
reads a GitHub snapshot. `Snapshot` (models.py) sits on its own because
fourteen checks read it directly; this one is read only by `project_github`,
and it can move out the day a second reader exists.

**The shape here is the shape GitHub actually returns.** That constraint is
load-bearing for a fixture-first project: a hand-written fixture that invents
fields produces checks validated against data no collector could ever supply.
Each collection maps to a real endpoint:

- `members` -- `GET /orgs/{org}/members` joined with the GraphQL
  `membersWithRole` edges (for `role` and `state`) and `externalIdentities`
  (for the SAML identity). Owner-level credentials are needed for all three.
  There is no per-member "last active" anywhere in the API; it exists only in
  the audit log, so this snapshot does not carry one and a member's principal
  has no last_used.
- `credentials` -- `GET /orgs/{org}/credential-authorizations`, which is the
  only org-level view of members' classic PATs and SSH keys. It requires SAML
  SSO, is keyed by **login** rather than node id, and states no credential
  name and no creation date: `authorizedAt` is when the credential was
  authorized for SSO, not when it was made. The caller must be an organization
  owner (`read:org` for an OAuth app or a classic PAT).
- `fineGrainedTokens` -- `GET /orgs/{org}/personal-access-tokens`, which
  reports `permissions` rather than classic scopes. **Only GitHub Apps can
  call this endpoint**, so it needs an installed App's token, not the owner
  credential the collection above needs.
- `verifiedEmails` -- GraphQL `User.organizationVerifiedDomainEmails(login:)`,
  a per-user field, not part of the member read. It returns addresses only for
  domains the organization has **verified**, so an org with no verified domains
  gets an empty list for everyone. That is "not readable here", not "no
  verified email", and a collector must set `credentials_complete`/record a gap
  rather than let it read as absence.
- `accountCreatedAt` -- GraphQL `User.createdAt` on the member nodes. The
  Simple User objects `GET /orgs/{org}/members` returns carry no created_at.

Two collections, two credentials, one plan floor: credential-authorizations
needs an org owner, personal-access-tokens needs a GitHub App, and both exist
only on GitHub Enterprise Cloud with SAML SSO. A collector that can do one may
not be able to do the other, which is what the per-collection completeness
flags are for.

The join is the point of this module. Where the org is behind SSO, GitHub
states each member's SAML external identity, and that is an authoritative join
to the IdP rather than a guess about a name. But a SAML NameID is frequently
an opaque persistent GUID, so this projection joins on whichever stated
attribute is actually an address and links nothing when none is -- a GUID
cannot be matched to an Okta identity keyed on email, and pretending otherwise
would be the false link the layer exists to prevent.

Fields are defined here as an explicit allowlist. No raw GitHub payload passes
through this module yet, because no collector exists: the allowlist is the
requirement the collector must meet, projecting raw responses onto exactly
these fields and nothing else, for the reason `ActivityEvent.from_okta` gives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..models import format_time, parse_time
from ..register import Register, ServiceAccount
from .graph import (
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

# A classic OAuth scope that only reads. Everything else -- repo, workflow,
# gist, delete_repo, admin:*, write:* -- can change something.
READ_SCOPE_PREFIX = "read:"
# Fine-grained permission values that can change something.
WRITE_PERMISSIONS = {"write", "admin"}
# GitHub's own word for each credential type in a credential authorization.
PAT_CREDENTIAL = "personal access token"
SSH_CREDENTIAL = "SSH key"

# GET /orgs/{org}/memberships/{username} documents state as active|pending, and
# GET /orgs/{org}/members returns no state at all (it lists active members only).
# Nothing in either read, or in GraphQL's OrganizationMemberEdge, reports a
# suspended member: suspension is visible only through enterprise SCIM under
# Enterprise Managed Users, which is a different endpoint on a plan this tool
# cannot assume. Anything else the API starts returning reads as UNKNOWN, which
# is what a status nobody can interpret should be.
# Org roles that carry administrative power, and what GitHub's own interface
# calls them. `admin` is the API's word for what the UI and the docs call an
# organization owner: "Organization owners have complete administrative access
# to your organization."
# Deliberately not elevated: `member` (ordinary), `direct_member` (the
# invitations read's word for an ordinary invitee), and `billing_manager`, who
# per GitHub's docs cannot "create or access repositories in your
# organizations". Roles outside this vocabulary are recorded as they came, and
# treated as elevated: a role this adapter has never heard of is not evidence
# that it is harmless.
ROLE_LABELS = {"admin": "organization owner", "owner": "organization owner"}
ORDINARY_ROLES = frozenset({"member", "direct_member", "billing_manager"})

MEMBER_STATUSES = {"active": Status.ACTIVE, "pending": Status.UNKNOWN}


def source_name(org: str) -> str:
    """The graph's id for one GitHub org.

    Sources are named per org because two orgs are two estates and a principal
    id is only unique within one. The result is opaque: nothing parses it back,
    and the org is recovered from `SourceMeta.org`.
    """
    return f"github:{org}"


def _joinable(value: str) -> str:
    """An identity key other sources can join on, or "".

    Okta keys identities on an email address, so only an address is joinable.
    A persistent NameID GUID identifies the same person perfectly well and is
    still useless here, and saying so is better than inventing a match.
    """
    cleaned = (value or "").strip().lower()
    return cleaned if "@" in cleaned else ""


@dataclass
class SamlEmail:
    """GitHub's `UserEmailMetadata`: `{ value: String!, primary: Boolean, type:
    String }`. `primary` is nullable, and it is the only documented way to
    choose among several addresses -- the connection states no ordering."""

    value: str = ""
    primary: bool | None = None
    type: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> SamlEmail:
        return cls(value=d.get("value", ""), primary=d.get("primary"), type=d.get("type", ""))

    def to_dict(self) -> dict:
        return {"value": self.value, "primary": self.primary, "type": self.type}


@dataclass
class SamlIdentity:
    """GitHub's `ExternalIdentitySamlAttributes`. Three separate attributes,
    any of which may be the address and any of which may be a GUID. `emails` is
    a list of `UserEmailMetadata`, not of strings."""

    name_id: str = ""
    username: str = ""
    emails: list[SamlEmail] = field(default_factory=list)

    def unambiguous_email(self) -> str:
        """The one address this identity states, or "".

        GraphQL documents no ordering for the emails connection, so `emails[0]`
        was a guess about which person owns the account -- exactly the false
        link this layer exists to prevent, and the same coin flip the projection
        already refuses for two verified emails. Only the address marked primary,
        or a lone entry, counts as stated.
        """
        primary = [e.value for e in self.emails if e.primary]
        if len(primary) == 1:
            return primary[0]
        if not primary and len(self.emails) == 1:
            return self.emails[0].value
        return ""

    def joinable(self) -> tuple[str, str]:
        """The first attribute that is an address, with the attribute's name."""
        for attribute, value in (("emails", self.unambiguous_email()),
                                 ("username", self.username), ("nameId", self.name_id)):
            found = _joinable(value)
            if found:
                return found, attribute
        return "", ""

    @classmethod
    def from_dict(cls, d: dict | None) -> SamlIdentity | None:
        if not d:
            return None
        return cls(
            name_id=d.get("nameId", ""),
            username=d.get("username", ""),
            # nullable: [UserEmailMetadata!]
            emails=[SamlEmail.from_dict(e) for e in (d.get("emails") or [])],
        )

    def to_dict(self) -> dict:
        return {"nameId": self.name_id, "username": self.username,
                "emails": [e.to_dict() for e in self.emails]}


@dataclass
class Member:
    """One org member. `saml_identity` is None when the org has no SSO or the
    member has not linked. `verified_emails` are addresses GitHub itself
    verified against a domain the org owns -- not the self-asserted profile
    email, which proves nothing. It is a list, because a member can have
    several."""

    id: str
    login: str
    state: str = "active"  # active | pending (see MEMBER_STATUSES)
    role: str = "member"  # see ROLE_LABELS; normalised to lower case in from_dict
    saml_identity: SamlIdentity | None = None
    verified_emails: list[str] = field(default_factory=list)
    # GitHub's account creation date, NOT the org join date -- GitHub exposes
    # no join date outside the audit log, and a contractor's personal account
    # can predate the engagement by a decade.
    account_created: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Member:
        return cls(
            id=d["id"],
            login=d["login"],
            state=(d.get("state") or "active").strip().lower(),
            # Case-folded: the REST reads spell these lower case, GraphQL's
            # OrganizationMemberRole enum spells them ADMIN and MEMBER, and a
            # case-sensitive comparison against "member" makes every ordinary
            # member of a GraphQL-sourced org look like an elevated one.
            role=(d.get("role") or "member").strip().lower(),
            saml_identity=SamlIdentity.from_dict(d.get("samlIdentity")),
            verified_emails=[e.strip().lower() for e in (d.get("verifiedEmails") or [])],
            account_created=parse_time(d.get("accountCreatedAt")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "state": self.state,
            "role": self.role,
            "samlIdentity": self.saml_identity.to_dict() if self.saml_identity else None,
            "verifiedEmails": self.verified_emails,
            "accountCreatedAt": format_time(self.account_created),
        }


@dataclass
class Team:
    id: str
    slug: str
    name: str
    members: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, d: dict) -> Team:
        return cls(id=d["id"], slug=d.get("slug", ""), name=d["name"], members=set(d.get("members", [])))

    def to_dict(self) -> dict:
        return {"id": self.id, "slug": self.slug, "name": self.name, "members": sorted(self.members)}


@dataclass
class CredentialAuthorization:
    """One SSO-authorized credential, as `credential-authorizations` reports
    it. Keyed by login, with no name and no creation date: `authorized_at` is
    when it was authorized for SSO, which is not when it was made."""

    credential_id: int
    login: str
    credential_type: str
    token_last_eight: str = ""
    scopes: list[str] = field(default_factory=list)
    authorized_at: datetime | None = None
    accessed_at: datetime | None = None
    expires_at: datetime | None = None

    def label(self) -> str:
        """There is no name, so identify it the way GitHub's own UI does."""
        return f"{self.credential_type} …{self.token_last_eight}" if self.token_last_eight else self.credential_type

    @classmethod
    def from_dict(cls, d: dict) -> CredentialAuthorization:
        return cls(
            credential_id=d["credentialId"],
            login=d["login"],
            credential_type=d["credentialType"],
            token_last_eight=d.get("tokenLastEight", ""),
            # `or []`, not a default: the endpoint documents scopes as nullable,
            # and `d.get("scopes", [])` returns None when the key is present and null.
            scopes=list(d.get("scopes") or []),
            authorized_at=parse_time(d.get("authorizedAt")),
            accessed_at=parse_time(d.get("accessedAt")),
            expires_at=parse_time(d.get("expiresAt")),
        )

    def to_dict(self) -> dict:
        return {
            "credentialId": self.credential_id,
            "login": self.login,
            "credentialType": self.credential_type,
            "tokenLastEight": self.token_last_eight,
            "scopes": sorted(self.scopes),
            "authorizedAt": format_time(self.authorized_at),
            "accessedAt": format_time(self.accessed_at),
            "expiresAt": format_time(self.expires_at),
        }


@dataclass
class FineGrainedToken:
    """A fine-grained PAT from the org's PAT policy endpoint. Carries a
    permissions map rather than classic scopes, so the write test is different
    -- a fine-grained token with no scopes is not a token with no access."""

    id: int
    owner_login: str
    repository_selection: str = ""
    permissions: dict[str, dict[str, str]] = field(default_factory=dict)
    granted_at: datetime | None = None
    last_used: datetime | None = None
    expires_at: datetime | None = None

    def label(self) -> str:
        where = f" on {self.repository_selection} repositories" if self.repository_selection else ""
        return f"fine-grained token {self.id}{where}"

    @classmethod
    def from_dict(cls, d: dict) -> FineGrainedToken:
        return cls(
            id=d["id"],
            owner_login=d["ownerLogin"],
            repository_selection=d.get("repositorySelection", ""),
            permissions={k: dict(v) for k, v in (d.get("permissions") or {}).items()},
            granted_at=parse_time(d.get("accessGrantedAt")),
            last_used=parse_time(d.get("lastUsedAt")),
            expires_at=parse_time(d.get("expiresAt")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ownerLogin": self.owner_login,
            "repositorySelection": self.repository_selection,
            "permissions": self.permissions,
            "accessGrantedAt": format_time(self.granted_at),
            "lastUsedAt": format_time(self.last_used),
            "expiresAt": format_time(self.expires_at),
        }


@dataclass
class GitHubSnapshot:
    org: str
    collected_at: datetime
    members: list[Member] = field(default_factory=list)
    teams: list[Team] = field(default_factory=list)
    credentials: list[CredentialAuthorization] = field(default_factory=list)
    fine_grained_tokens: list[FineGrainedToken] = field(default_factory=list)
    # False when the org is not behind SSO. Then credential-authorizations does
    # not exist, so no member credential can be seen at all. Defaults False:
    # see from_dict.
    sso_enabled: bool = False
    # False when the credential reads did not run or were cut short, so a
    # credential's absence is not evidence that it is not there. The analogue
    # of Snapshot.app_usage_complete. Defaults False: see from_dict.
    credentials_complete: bool = False
    # False when the organization-roles reads did not run. The member `role`
    # field carries only the base role: security managers and custom
    # organization roles come from GET /orgs/{org}/organization-roles and its
    # /users sub-resource, so without them an elevated role is unknown rather
    # than absent. Defaults False: see from_dict.
    roles_complete: bool = False
    gaps: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> GitHubSnapshot:
        return cls(
            org=d["org"],
            collected_at=parse_time(d["collected_at"]),
            members=[Member.from_dict(x) for x in d.get("members", [])],
            teams=[Team.from_dict(x) for x in d.get("teams", [])],
            credentials=[CredentialAuthorization.from_dict(x) for x in d.get("credentials", [])],
            fine_grained_tokens=[FineGrainedToken.from_dict(x) for x in d.get("fineGrainedTokens", [])],
            # False by default, both: a truncated or partly-written collector
            # file must not assert that SSO was on and the credential reads
            # finished. A snapshot claims completeness explicitly or not at all.
            sso_enabled=d.get("sso_enabled", False),
            credentials_complete=d.get("credentials_complete", False),
            roles_complete=d.get("roles_complete", False),
            gaps=list(d.get("gaps", [])),
        )

    def to_dict(self) -> dict:
        return {
            "org": self.org,
            "collected_at": format_time(self.collected_at),
            "sso_enabled": self.sso_enabled,
            "credentials_complete": self.credentials_complete,
            "roles_complete": self.roles_complete,
            "gaps": self.gaps,
            "members": [x.to_dict() for x in self.members],
            "teams": [x.to_dict() for x in self.teams],
            "credentials": [x.to_dict() for x in self.credentials],
            "fineGrainedTokens": [x.to_dict() for x in self.fine_grained_tokens],
        }


def _scope_write_access(scopes: list[str], read_complete: bool) -> bool | None:
    """Classic PAT scopes. An empty list is not evidence of no access: a
    fine-grained token reports no scopes at all, and a failed read reports
    none either."""
    if any(not s.startswith(READ_SCOPE_PREFIX) for s in scopes):
        return True
    if not scopes:
        return None
    return False if read_complete else None


def _permission_write_access(permissions: dict[str, dict[str, str]], read_complete: bool) -> bool | None:
    """Fine-grained permissions. `{}` means the permissions were not read, not
    that the token can do nothing."""
    values = [v for group in permissions.values() for v in group.values()]
    if any(v in WRITE_PERMISSIONS for v in values):
        return True
    if not values:
        return None
    return False if read_complete else None


def _changed_hands(entry: ServiceAccount, member: Member) -> bool:
    """Whether the account now holding a declared login cannot be the account
    the entry was written about.

    GitHub frees a login the moment its owner renames it: the old name goes back
    into the pool and anyone can claim it. An Okta login that changes simply
    stops matching, and `Register.stale` says so -- here the entry goes on
    matching, a different account. That is worse than a miss, because a match is
    not a quiet no-op: it types the account SERVICE, takes the SSO branch away
    from a real person so their access joins to nobody, and attaches this
    entry's owner to somebody else's credentials.

    The evidence is the entry's own `reviewed` date against GitHub's account
    creation date. An account that did not exist when somebody last confirmed
    the entry is not the account they confirmed. That catches a freed login
    claimed by a new account, which is the common shape and the one an attacker
    can arrange; it does not catch a long-lived account renaming into a freed
    login, and nothing a register keyed by name carries would. An entry with no
    `reviewed` date has no evidence to check and gets no guard, which is the
    one thing that date buys beyond being read by a human.
    """
    if entry.reviewed is None or member.account_created is None:
        return False
    return member.account_created.date() > entry.reviewed


def project_github(snapshot: GitHubSnapshot, register: Register | None = None) -> IdentityGraph:
    """Turn a GitHub snapshot into a one-source graph.

    `register` is `Config.service_accounts`, the same register the Okta
    projection reads. Nothing else makes a member a service account: personhood
    is not implied by having an SSO link, because a machine user can be
    provisioned in the IdP too.

    Entries are scoped to this org's source name (`github:<org>`), so declaring
    an Okta login never declares a GitHub member that happens to share it. Two
    sources are two estates and a login is only a name within one.
    """
    source = source_name(snapshot.org)
    register = Register.from_config(register if register is not None else Register())
    matched: set[tuple[str, str]] = set()
    principals: list[Principal] = []
    credentials: list[Credential] = []
    grants: list[Grant] = []
    links: list[Link] = []
    gaps = list(snapshot.gaps)

    if not snapshot.sso_enabled:
        gaps.append(
            f"The {snapshot.org} org is not behind SSO, so GitHub states no SAML identity for anyone "
            f"and credential-authorizations does not exist. Members can only be joined by a verified "
            f"email, their credentials cannot be read at all, and both are unknown rather than absent."
        )
    # Scoped to the reads that actually feed a write-access judgement. The
    # identity gaps this projection goes on to record (an unjoinable SAML
    # attribute, an ambiguous verified email) say nothing about whether the
    # scopes were read, and letting them suppress every credential answer
    # org-wide would make the signal dead in any real tenant.
    if snapshot.sso_enabled and not snapshot.credentials_complete:
        gaps.append(
            f"The credential reads for the {snapshot.org} org did not run in full, so a member's "
            f"credentials are unknown rather than absent, and a credential with no record of use is "
            f"not known to be dormant."
        )
    if not snapshot.roles_complete:
        gaps.append(
            f"Organization roles for the {snapshot.org} org were not read, so a member holds no "
            f"elevated role as far as this review can tell rather than being known not to. Security "
            f"managers and custom organization roles are a separate read from the member list."
        )
    read_complete = snapshot.sso_enabled and snapshot.credentials_complete and not snapshot.gaps

    by_login = {m.login: m for m in snapshot.members}
    known_ids = {m.id for m in snapshot.members}

    for member in snapshot.members:
        key = (source, member.id)
        entry = register.entry(source, member.login)
        if entry is not None and _changed_hands(entry, member):
            # Matched, and not usable: this gap rather than the stale one, and
            # `entry` is dropped so everything below treats the account as what
            # it now is -- somebody else's, joined through their own SSO link.
            matched.add(entry.key)
            gaps.append(
                f"The service account register declares {entry.id!r} in {source}, but the account "
                f"holding that login was created on "
                f"{member.account_created.date().isoformat()}, after the entry was last reviewed on "
                f"{entry.reviewed.isoformat()}. A GitHub login returns to the pool when its owner "
                f"renames, so this is a different account wearing the same name: it is left "
                f"undeclared, and the entry declares nothing until somebody confirms it."
            )
            entry = None
        service = entry is not None
        principals.append(
            Principal(
                source=source,
                id=member.id,
                label=member.login,
                # Declared or not. An SSO link proves the IdP knows this
                # account, not that a person is behind it.
                kind=PrincipalKind.SERVICE if service else PrincipalKind.HUMAN,
                status=MEMBER_STATUSES.get(member.state, Status.UNKNOWN),
                source_status=member.state,
                email=member.verified_emails[0] if len(member.verified_emails) == 1 else "",
                created=member.account_created,
                # GitHub exposes no per-member activity outside the audit log,
                # so there is nothing honest to put here.
                last_used=None,
            )
        )
        if entry is not None:
            matched.add(entry.key)
            # Declared accounts take no SSO or verified-email link: those say
            # the IdP or GitHub knows the address, not that a person answers for
            # a machine account. The register is the only thing that says who.
            links.append(Link(key, LinkMethod.DECLARED, entry.owner, entry.evidence()))
        elif member.saml_identity:
            identity, attribute = member.saml_identity.joinable()
            if identity:
                links.append(Link(
                    key, LinkMethod.SSO_IDENTITY, identity,
                    f"SAML {attribute} for {member.login} in the {snapshot.org} org",
                ))
            else:
                gaps.append(
                    f"{member.login} has a SAML identity with no attribute this review can join on "
                    f"(every attribute is an opaque identifier, or it states several addresses with "
                    f"no primary), so it cannot be joined to an identity keyed on an email address."
                )
        elif len(member.verified_emails) == 1:
            links.append(Link(
                key, LinkMethod.VERIFIED_EMAIL, member.verified_emails[0],
                f"email verified by GitHub against an org-owned domain for {member.login}",
            ))
        elif len(member.verified_emails) > 1:
            # Picking one would be a coin flip between two people's worth of
            # accountability. Unlinked is the honest answer.
            gaps.append(
                f"{member.login} has {len(member.verified_emails)} verified emails and no SAML "
                f"identity, so which person holds this account is not evidenced."
            )
        grants.append(Grant(source, member.id, GrantKind.ORG, snapshot.org, snapshot.org))
        # Only above ordinary membership: `checks._elevated_roles` reads every
        # ROLE grant and AR-17 grades on it, so an ordinary member appearing
        # here would make every departure a critical finding.
        if member.role not in ORDINARY_ROLES:
            grants.append(Grant(source, member.id, GrantKind.ROLE, member.role,
                                ROLE_LABELS.get(member.role, member.role)))

    # Access granted to an id or login the member read never returned would
    # otherwise be access held by nobody: invisible to unlinked(), uncounted by
    # coverage(). Each becomes a principal we know nothing about, plus a gap.
    unknown: dict[str, str] = {}

    def note(principal_id: str, how: str) -> str:
        if principal_id not in known_ids:
            unknown[principal_id] = how
        return principal_id

    for team in snapshot.teams:
        for member_id in sorted(team.members):
            grants.append(Grant(source, note(member_id, "team membership"), GrantKind.TEAM, team.id, team.name))

    for authorization in snapshot.credentials:
        member = by_login.get(authorization.login)
        holder = member.id if member else note(authorization.login, "an SSO-authorized credential")
        ssh = authorization.credential_type == SSH_CREDENTIAL
        credentials.append(Credential(
            source=source,
            id=str(authorization.credential_id),
            kind=CredentialKind.SSH_KEY if ssh else CredentialKind.GITHUB_PAT,
            label=authorization.label(),
            holder=holder,
            # No creation date exists; authorized_at is the nearest thing and
            # means something different, so it is not put in `created`.
            created=None,
            last_used=authorization.accessed_at,
            expires=authorization.expires_at,
            # An account SSH key can always push. GitHub's read-only flag is a
            # deploy-key property and is not readable for a member's own key.
            write_access=True if ssh else _scope_write_access(authorization.scopes, read_complete),
        ))

    for token in snapshot.fine_grained_tokens:
        member = by_login.get(token.owner_login)
        holder = member.id if member else note(token.owner_login, "a fine-grained token")
        credentials.append(Credential(
            source=source,
            id=f"fg-{token.id}",
            kind=CredentialKind.GITHUB_PAT,
            label=token.label(),
            holder=holder,
            created=token.granted_at,
            last_used=token.last_used,
            expires=token.expires_at,
            write_access=_permission_write_access(token.permissions, read_complete),
        ))

    for principal_id, how in sorted(unknown.items()):
        principals.append(Principal(
            source=source, id=principal_id, label=principal_id,
            kind=PrincipalKind.UNKNOWN, status=Status.UNKNOWN,
        ))
        gaps.append(
            f"{principal_id} holds {how} in the {snapshot.org} org but was not returned by the "
            f"member read. It is counted as unlinked."
        )

    gaps.extend(register.stale(source, matched))

    meta = SourceMeta(
        source=source,
        org=snapshot.org,
        collected_at=snapshot.collected_at,
        gaps=gaps,
        # GitHub reports a last-accessed time per credential rather than over a
        # window, so there is no span to record here. activity_complete, not
        # this field, is what a dormancy judgement reads.
        activity_since=None,
        # Only believable when the reads that record use actually ran.
        activity_complete=read_complete,
        # Its own read again, and its own answer: the gap above says the
        # organization roles were never fetched, and this is what a check
        # grading on roles reads so that an empty list is not taken for an
        # ordinary member.
        roles_complete=snapshot.roles_complete,
    )
    return IdentityGraph(
        sources=[meta],
        principals=principals,
        credentials=credentials,
        grants=grants,
        links=links,
    )
