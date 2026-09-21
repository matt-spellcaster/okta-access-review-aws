"""The GitHub source adapter: its own snapshot shape, and the projection of
that shape into the identity graph.

Model and projection live together here, unlike Okta's, because nothing else
reads a GitHub snapshot. `Snapshot` (models.py) sits on its own because
fourteen checks read it directly; this one is read only by `project_github`,
and it can move out the day a second reader exists.

The join is the point of this module. If the org is behind Okta SSO, GitHub
states each member's SAML external identity, and that is an authoritative
join to the IdP rather than a guess about a name. Where GitHub states nothing,
this projection says nothing: a login that merely resembles an Okta user is
not that user, and the member becomes unlinked, which is a finding.

Fields are copied onto an explicit allowlist, following the
`ActivityEvent.from_okta` precedent. GitHub's member and token payloads carry
far more personal data than a review needs, and a snapshot is written to disk
and shared as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..models import format_time, parse_time
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

# A GitHub scope that only reads. Everything else -- repo, workflow, gist,
# delete_repo, admin:*, write:* -- can change something.
READ_SCOPE_PREFIX = "read:"


def source_name(org: str) -> str:
    """Sources are named per org, because two orgs are two estates and a
    principal id is only unique within one."""
    return f"github:{org}"


@dataclass
class Member:
    """One org member. `saml_identity` is GitHub's record of who the IdP says
    this is, and is empty when the org has no SSO or the member has not linked.
    `verified_email` is an address GitHub itself verified against a domain the
    org owns -- not the self-asserted profile email, which proves nothing."""

    id: str
    login: str
    name: str = ""
    saml_identity: str = ""
    verified_email: str = ""
    role: str = "member"  # member | admin
    two_factor: bool | None = None
    created: datetime | None = None
    last_active: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Member:
        return cls(
            id=d["id"],
            login=d["login"],
            name=d.get("name", ""),
            saml_identity=(d.get("samlIdentity") or "").strip().lower(),
            verified_email=(d.get("verifiedEmail") or "").strip().lower(),
            role=d.get("role", "member"),
            two_factor=d.get("twoFactorEnabled"),
            created=parse_time(d.get("createdAt")),
            last_active=parse_time(d.get("lastActive")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "name": self.name,
            "samlIdentity": self.saml_identity,
            "verifiedEmail": self.verified_email,
            "role": self.role,
            "twoFactorEnabled": self.two_factor,
            "createdAt": format_time(self.created),
            "lastActive": format_time(self.last_active),
        }


@dataclass
class Team:
    id: str
    name: str
    members: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, d: dict) -> Team:
        return cls(id=d["id"], name=d["name"], members=set(d.get("members", [])))

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "members": sorted(self.members)}


@dataclass
class Token:
    """A personal access token. It belongs to the person, not the org, and
    revoking their SSO session does not revoke it."""

    id: str
    name: str
    owner_id: str
    scopes: list[str] = field(default_factory=list)
    created: datetime | None = None
    last_used: datetime | None = None
    expires: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Token:
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            owner_id=d["ownerId"],
            scopes=list(d.get("scopes", [])),
            created=parse_time(d.get("createdAt")),
            last_used=parse_time(d.get("lastUsed")),
            expires=parse_time(d.get("expiresAt")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "ownerId": self.owner_id,
            "scopes": sorted(self.scopes),
            "createdAt": format_time(self.created),
            "lastUsed": format_time(self.last_used),
            "expiresAt": format_time(self.expires),
        }


@dataclass
class SshKey:
    id: str
    title: str
    owner_id: str
    read_only: bool = False
    created: datetime | None = None
    last_used: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> SshKey:
        return cls(
            id=d["id"],
            title=d.get("title", ""),
            owner_id=d["ownerId"],
            read_only=d.get("readOnly", False),
            created=parse_time(d.get("createdAt")),
            last_used=parse_time(d.get("lastUsed")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "ownerId": self.owner_id,
            "readOnly": self.read_only,
            "createdAt": format_time(self.created),
            "lastUsed": format_time(self.last_used),
        }


@dataclass
class GitHubSnapshot:
    org: str
    collected_at: datetime
    members: list[Member] = field(default_factory=list)
    teams: list[Team] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    ssh_keys: list[SshKey] = field(default_factory=list)
    # False when the org is not behind SSO, so no member can carry a SAML
    # identity and every join has to fall back down the ladder. That is a
    # property of the org, not a failed read, so it is not a gap.
    sso_enabled: bool = True
    gaps: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> GitHubSnapshot:
        return cls(
            org=d["org"],
            collected_at=parse_time(d["collected_at"]),
            members=[Member.from_dict(x) for x in d.get("members", [])],
            teams=[Team.from_dict(x) for x in d.get("teams", [])],
            tokens=[Token.from_dict(x) for x in d.get("tokens", [])],
            ssh_keys=[SshKey.from_dict(x) for x in d.get("sshKeys", [])],
            sso_enabled=d.get("sso_enabled", True),
            gaps=list(d.get("gaps", [])),
        )

    def to_dict(self) -> dict:
        return {
            "org": self.org,
            "collected_at": format_time(self.collected_at),
            "sso_enabled": self.sso_enabled,
            "gaps": self.gaps,
            "members": [x.to_dict() for x in self.members],
            "teams": [x.to_dict() for x in self.teams],
            "tokens": [x.to_dict() for x in self.tokens],
            "sshKeys": [x.to_dict() for x in self.ssh_keys],
        }


def _token_write_access(token: Token, source_complete: bool) -> bool | None:
    """Whether a token can change anything.

    An empty scope list is only evidence of "no access" when the read that
    would have listed the scopes completed. Otherwise this is unknown, for the
    same reason it is unknown on the Okta side.
    """
    if any(not s.startswith(READ_SCOPE_PREFIX) for s in token.scopes):
        return True
    return False if source_complete else None


def _link_for(member: Member, source: str, org: str) -> Link | None:
    """The strongest evidenced join for this member, or None.

    There is deliberately no fallback below a verified email. A GitHub login
    that looks like an Okta login is not evidence, and inventing a link here
    would mark this member's credentials as somebody's when they are nobody's.
    """
    key = (source, member.id)
    if member.saml_identity:
        return Link(
            key,
            LinkMethod.SSO_IDENTITY,
            member.saml_identity,
            f"SAML external identity for {member.login} in the {org} org",
        )
    if member.verified_email:
        return Link(
            key,
            LinkMethod.VERIFIED_EMAIL,
            member.verified_email,
            f"email verified by GitHub against an org-owned domain for {member.login}",
        )
    return None


def project_github(snapshot: GitHubSnapshot) -> IdentityGraph:
    """Turn a GitHub snapshot into a one-source graph."""
    source = source_name(snapshot.org)
    source_complete = not snapshot.gaps
    principals: list[Principal] = []
    credentials: list[Credential] = []
    grants: list[Grant] = []
    links: list[Link] = []
    gaps = list(snapshot.gaps)

    if not snapshot.sso_enabled:
        gaps.append(
            f"The {snapshot.org} org is not behind SSO, so GitHub states no SAML identity for "
            f"anyone. Members can only be joined by a verified email, and the rest are unlinked "
            f"for want of evidence rather than because nobody owns them."
        )

    for member in snapshot.members:
        link = _link_for(member, source, snapshot.org)
        principals.append(
            Principal(
                source=source,
                id=member.id,
                label=member.login,
                # A member the IdP vouches for is a person. Without that, this
                # could be a contractor's personal account or a machine user,
                # and guessing from the login is how a bot gets filed as staff.
                kind=PrincipalKind.HUMAN if link else PrincipalKind.UNKNOWN,
                # GitHub org membership has no suspended state that this read
                # can see: a member listed is a member who can act.
                status=Status.ACTIVE,
                source_status="member",
                email=member.verified_email,
                created=member.created,
                last_used=member.last_active,
            )
        )
        if link:
            links.append(link)
        grants.append(Grant(source, member.id, GrantKind.ORG, snapshot.org, snapshot.org))
        if member.role == "admin":
            grants.append(Grant(source, member.id, GrantKind.ROLE, "admin", "Organization owner"))

    for team in snapshot.teams:
        for member_id in sorted(team.members):
            grants.append(Grant(source, member_id, GrantKind.TEAM, team.id, team.name))

    for token in snapshot.tokens:
        credentials.append(
            Credential(
                source=source,
                id=token.id,
                kind=CredentialKind.GITHUB_PAT,
                label=token.name,
                holder=token.owner_id,
                created=token.created,
                last_used=token.last_used,
                expires=token.expires,
                write_access=_token_write_access(token, source_complete),
            )
        )

    for key in snapshot.ssh_keys:
        credentials.append(
            Credential(
                source=source,
                id=key.id,
                kind=CredentialKind.SSH_KEY,
                label=key.title,
                holder=key.owner_id,
                created=key.created,
                last_used=key.last_used,
                write_access=not key.read_only,
            )
        )

    meta = SourceMeta(
        source=source,
        org=snapshot.org,
        collected_at=snapshot.collected_at,
        gaps=gaps,
        # GitHub reports last-used per credential rather than an event log, so
        # there is no window to be partial about: a token either states a
        # last-used time or has never been used.
        activity_since=None,
        activity_complete=source_complete,
    )
    return IdentityGraph(
        sources=[meta],
        principals=principals,
        credentials=credentials,
        grants=grants,
        links=links,
    )
