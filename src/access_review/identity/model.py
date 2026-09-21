"""A source-agnostic view of who and what can hold access.

`Snapshot` (models.py) stays exactly what it is: the Okta source adapter's
output. This layer composes above it. An `IdentityGraph` holds `Principal`s,
`Credential`s and `Grant`s from any number of sources, with the `Link`s that
say which principal belongs to which person, and why.

Two rules shape everything here.

Nothing is fuzzy-matched. A link is evidenced or it is absent, and `LinkMethod`
is a ladder of named methods, not a score. A false link is worse than no link,
because it marks a credential as accounted for when nobody is accountable for
it -- the opposite of what this tool is for. The method travels into the
evidence bundle so an auditor can see why the tool believes what it believes.

Silence is not absence. Completeness is tracked per source (`SourceMeta`), so a
failed GitHub read reports as "GitHub is incomplete", never as "this person
holds no GitHub credentials".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from ..models import format_time, parse_time

# A principal is only unique within its source: two sources can both have an
# "alice", and an AWS key and a GitHub PAT are different things with the same id.
PrincipalKey = tuple[str, str]


class PrincipalKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    UNKNOWN = "unknown"


class Status(StrEnum):
    """Normalised account status. Sources have their own words for these, and
    `Principal.source_status` keeps the source's own."""

    ACTIVE = "active"  # exists, and is or can become usable
    DISABLED = "disabled"  # sign-in blocked, access still attached
    DELETED = "deleted"  # gone from the source, though its credentials may not be
    UNKNOWN = "unknown"


class CredentialKind(StrEnum):
    """Things that outlive the account they were created under: deactivating
    that account does not stop them working. This is the long tail a joiner /
    mover / leaver automation does not cover."""

    OKTA_API_TOKEN = "okta_api_token"
    GITHUB_PAT = "github_pat"
    AWS_ACCESS_KEY = "aws_access_key"
    SSH_KEY = "ssh_key"
    OAUTH_CLIENT = "oauth_client"


class GrantKind(StrEnum):
    GROUP = "group"
    APP = "app"
    ROLE = "role"
    ORG = "org"
    TEAM = "team"


class LinkMethod(StrEnum):
    """How a principal was tied to a person, strongest first.

    An enum rather than a confidence score: each value names evidence someone
    can check. SSO_IDENTITY is the IdP's own external identity (SAML or SCIM)
    and is authoritative. VERIFIED_EMAIL is an exact match on an address the
    source itself states. DECLARED is a register entry a person signed up to.
    CREATOR comes from an audit log and means accountable, not necessarily
    owner -- and the creator may themselves have left, which is a worse
    finding, not an answer.

    There is deliberately no method below CREATOR. A principal nothing here
    applies to is unlinked, and unlinked is a finding.
    """

    SSO_IDENTITY = "sso_identity"
    VERIFIED_EMAIL = "verified_email"
    DECLARED = "declared"
    CREATOR = "creator"

    @property
    def rank(self) -> int:
        """0 is strongest. For choosing between links, never for averaging them."""
        return METHOD_ORDER.index(self)


METHOD_ORDER = (
    LinkMethod.SSO_IDENTITY,
    LinkMethod.VERIFIED_EMAIL,
    LinkMethod.DECLARED,
    LinkMethod.CREATOR,
)
_METHOD_WORDS = {
    LinkMethod.SSO_IDENTITY: "SSO-linked",
    LinkMethod.VERIFIED_EMAIL: "email-matched",
    LinkMethod.DECLARED: "declared",
    LinkMethod.CREATOR: "creator-traced",
}


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


@dataclass
class Principal:
    """Anything that can hold access, within one source: a person's account, a
    service account, an automation acting on its own credentials."""

    source: str
    id: str
    label: str
    kind: PrincipalKind = PrincipalKind.UNKNOWN
    status: Status = Status.UNKNOWN
    # The source's own status word, kept because evidence should show what the
    # source actually said, not only how this tool read it.
    source_status: str = ""
    email: str = ""
    created: datetime | None = None
    # None means the source has no record of use, which is not "never used".
    last_used: datetime | None = None

    @property
    def key(self) -> PrincipalKey:
        return (self.source, self.id)

    @classmethod
    def from_dict(cls, d: dict) -> Principal:
        return cls(
            source=d["source"],
            id=d["id"],
            label=d.get("label", ""),
            kind=PrincipalKind(d.get("kind", "unknown")),
            status=Status(d.get("status", "unknown")),
            source_status=d.get("source_status", ""),
            email=d.get("email", ""),
            created=parse_time(d.get("created")),
            last_used=parse_time(d.get("last_used")),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "id": self.id,
            "label": self.label,
            "kind": str(self.kind),
            "status": str(self.status),
            "source_status": self.source_status,
            "email": self.email,
            "created": format_time(self.created),
            "last_used": format_time(self.last_used),
        }


@dataclass
class Credential:
    """A credential held in a source. `holder` is a principal id in the same
    source, and may name a principal that no longer exists: an API token whose
    owner was deleted keeps working, and that is exactly the case worth
    finding."""

    source: str
    id: str
    kind: CredentialKind
    label: str = ""
    holder: str = ""  # "" when the source records no holder at all
    created: datetime | None = None
    last_used: datetime | None = None
    expires: datetime | None = None
    # None means the source did not say. False is a claim, and a claim made
    # from data that was never read is how a review misses something.
    write_access: bool | None = None

    @property
    def key(self) -> PrincipalKey:
        return (self.source, self.id)

    @property
    def holder_key(self) -> PrincipalKey | None:
        return (self.source, self.holder) if self.holder else None

    @classmethod
    def from_dict(cls, d: dict) -> Credential:
        return cls(
            source=d["source"],
            id=d["id"],
            kind=CredentialKind(d["kind"]),
            label=d.get("label", ""),
            holder=d.get("holder", ""),
            created=parse_time(d.get("created")),
            last_used=parse_time(d.get("last_used")),
            expires=parse_time(d.get("expires")),
            write_access=d.get("write_access"),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "id": self.id,
            "kind": str(self.kind),
            "label": self.label,
            "holder": self.holder,
            "created": format_time(self.created),
            "last_used": format_time(self.last_used),
            "expires": format_time(self.expires),
            "write_access": self.write_access,
        }


@dataclass
class Grant:
    """Membership or assignment: a principal can reach a target, and `via` says
    how -- 'direct', or 'group:<name>' when it comes from a membership."""

    source: str
    principal: str
    kind: GrantKind
    target: str
    target_label: str = ""
    via: str = "direct"

    @property
    def principal_key(self) -> PrincipalKey:
        return (self.source, self.principal)

    @classmethod
    def from_dict(cls, d: dict) -> Grant:
        return cls(
            source=d["source"],
            principal=d["principal"],
            kind=GrantKind(d["kind"]),
            target=d["target"],
            target_label=d.get("target_label", ""),
            via=d.get("via", "direct"),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "principal": self.principal,
            "kind": str(self.kind),
            "target": self.target,
            "target_label": self.target_label,
            "via": self.via,
        }


@dataclass
class Link:
    """One piece of evidence tying a principal to a person.

    `identity` is empty when the evidence establishes accountability but names
    nobody -- a service account declared in the register with no owner recorded
    is declared, not unlinked, and not attributable either.
    """

    principal: PrincipalKey
    method: LinkMethod
    identity: str = ""
    evidence: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Link:
        return cls(
            principal=(d["source"], d["principal"]),
            method=LinkMethod(d["method"]),
            identity=d.get("identity", ""),
            evidence=d.get("evidence", ""),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.principal[0],
            "principal": self.principal[1],
            "method": str(self.method),
            "identity": self.identity,
            "evidence": self.evidence,
        }


@dataclass
class Identity:
    """A person across sources: the canonical key they are known by, and every
    principal linked to them with the method that did the linking."""

    key: str
    label: str = ""
    links: list[Link] = field(default_factory=list)

    @property
    def principals(self) -> list[PrincipalKey]:
        return [link.principal for link in self.links]


@dataclass
class SourceMeta:
    """What one source's read covered, and what it missed.

    Per source, because with three sources a single flat gaps list means the
    tool reports "no GitHub credentials" when the GitHub call simply failed.
    """

    source: str
    org: str = ""
    collected_at: datetime | None = None
    gaps: list[str] = field(default_factory=list)
    # Oldest point this source's activity evidence reaches. None means activity
    # was not collected at all, which is not the same as "nothing happened".
    activity_since: datetime | None = None
    # False when an activity read was cut short, so a missing record of use
    # cannot be read as "not used".
    activity_complete: bool = True

    @property
    def complete(self) -> bool:
        return not self.gaps

    @classmethod
    def from_dict(cls, d: dict) -> SourceMeta:
        return cls(
            source=d["source"],
            org=d.get("org", ""),
            collected_at=parse_time(d.get("collected_at")),
            gaps=list(d.get("gaps", [])),
            activity_since=parse_time(d.get("activity_since")),
            activity_complete=d.get("activity_complete", True),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "org": self.org,
            "collected_at": format_time(self.collected_at),
            "gaps": self.gaps,
            "activity_since": format_time(self.activity_since),
            "activity_complete": self.activity_complete,
        }


@dataclass
class Coverage:
    """How much of the estate is accounted for, as a number to trend across
    reviews. The trend going down is the point of the tool."""

    total: int
    by_method: dict[str, int]
    unlinked: int
    incomplete_sources: list[str] = field(default_factory=list)

    @property
    def reliable(self) -> bool:
        """False when a source read was incomplete. Then `unlinked` is a lower
        bound on a partial estate, not a count of what is out there."""
        return not self.incomplete_sources

    def summary(self) -> str:
        parts = [f"{n} {_METHOD_WORDS[LinkMethod(m)]}" for m, n in self.by_method.items() if n]
        parts.append(f"{self.unlinked} unlinked")
        line = f"{_count(self.total, 'principal')}: {', '.join(parts)}"
        if not self.reliable:
            line += (
                f" (incomplete: {', '.join(self.incomplete_sources)}, "
                f"so these counts cover only what could be read)"
            )
        return line

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_method": self.by_method,
            "unlinked": self.unlinked,
            "incomplete_sources": self.incomplete_sources,
            "reliable": self.reliable,
        }


@dataclass
class IdentityGraph:
    """Principals, credentials and grants from one or more sources, with the
    links between principals and people.

    Built by projecting each source's own output into it -- `Snapshot` through
    identity.okta, GitHub and AWS through their own adapters -- and composed
    with `compose`. Treat it as immutable once built: the lookups are indexed
    on construction, and `compose` returns a new graph rather than mutating one.
    """

    sources: list[SourceMeta] = field(default_factory=list)
    principals: list[Principal] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._principals: dict[PrincipalKey, Principal] = {p.key: p for p in self.principals}
        self._best: dict[PrincipalKey, Link] = {}
        for link in self.links:
            best = self._best.get(link.principal)
            if best is None or link.method.rank < best.method.rank:
                self._best[link.principal] = link

    @classmethod
    def compose(cls, *graphs: IdentityGraph) -> IdentityGraph:
        """Combine per-source graphs into one. Sources stay separate: two reads
        of the same source would make every count wrong, so that is an error."""
        seen: set[str] = set()
        for graph in graphs:
            for meta in graph.sources:
                if meta.source in seen:
                    raise ValueError(f"source {meta.source!r} appears in more than one graph")
                seen.add(meta.source)
        return cls(
            sources=[m for g in graphs for m in g.sources],
            principals=[p for g in graphs for p in g.principals],
            credentials=[c for g in graphs for c in g.credentials],
            grants=[x for g in graphs for x in g.grants],
            links=[x for g in graphs for x in g.links],
        )

    def principal(self, key: PrincipalKey) -> Principal | None:
        return self._principals.get(key)

    def source(self, name: str) -> SourceMeta | None:
        return next((m for m in self.sources if m.source == name), None)

    def link_for(self, key: PrincipalKey) -> Link | None:
        """The strongest link for this principal, or None if it is unlinked."""
        return self._best.get(key)

    def links_for(self, key: PrincipalKey) -> list[Link]:
        """Every link for this principal, strongest first. More than one is
        normal and worth showing: SSO says whose account it is, the audit log
        says who set it up."""
        return sorted((x for x in self.links if x.principal == key), key=lambda x: x.method.rank)

    def unlinked(self) -> list[Principal]:
        """Principals no evidence ties to anyone. The headline finding, not an
        edge case."""
        return [p for p in self.principals if p.key not in self._best]

    def holder_of(self, credential: Credential) -> Principal | None:
        """The principal holding a credential, or None when the source names a
        holder that no longer exists -- a credential outliving its account."""
        key = credential.holder_key
        return self._principals.get(key) if key else None

    def credentials_for(self, key: PrincipalKey) -> list[Credential]:
        return [c for c in self.credentials if c.holder_key == key]

    def grants_for(self, key: PrincipalKey) -> list[Grant]:
        return [g for g in self.grants if g.principal_key == key]

    def principals_of(self, identity: str) -> list[Principal]:
        """Everything this person holds, across sources -- including principals
        they are only accountable for, such as a bot they set up."""
        keys = [k for k, link in self._best.items() if link.identity == identity]
        return [p for k in sorted(keys) if (p := self._principals.get(k))]

    def identities(self) -> list[Identity]:
        """The people this graph knows about, each with their linked principals.

        A principal appears under one person only: the strongest link wins, so
        an account whose SSO identity is one person and whose audit-log creator
        is another belongs to the SSO identity.
        """
        grouped: dict[str, list[Link]] = {}
        for link in self._best.values():
            if link.identity:
                grouped.setdefault(link.identity, []).append(link)
        out = []
        for key, links in sorted(grouped.items()):
            links.sort(key=lambda x: (x.method.rank, x.principal))
            people = (self._principals.get(x.principal) for x in links)
            label = next(
                (p.label for p in people if p and p.kind is PrincipalKind.HUMAN and p.email == key), key
            )
            out.append(Identity(key=key, label=label, links=links))
        return out

    def incomplete_sources(self) -> list[str]:
        return [m.source for m in self.sources if not m.complete]

    def coverage(self) -> Coverage:
        counts = {str(m): 0 for m in METHOD_ORDER}
        for link in self._best.values():
            counts[str(link.method)] += 1
        return Coverage(
            total=len(self.principals),
            by_method=counts,
            unlinked=len(self.principals) - len(self._best),
            incomplete_sources=self.incomplete_sources(),
        )

    @classmethod
    def from_dict(cls, d: dict) -> IdentityGraph:
        return cls(
            sources=[SourceMeta.from_dict(x) for x in d.get("sources", [])],
            principals=[Principal.from_dict(x) for x in d.get("principals", [])],
            credentials=[Credential.from_dict(x) for x in d.get("credentials", [])],
            grants=[Grant.from_dict(x) for x in d.get("grants", [])],
            links=[Link.from_dict(x) for x in d.get("links", [])],
        )

    def to_dict(self) -> dict:
        return {
            "sources": [x.to_dict() for x in self.sources],
            "principals": [x.to_dict() for x in self.principals],
            "credentials": [x.to_dict() for x in self.credentials],
            "grants": [x.to_dict() for x in self.grants],
            "links": [x.to_dict() for x in self.links],
        }
