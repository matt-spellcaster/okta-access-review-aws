"""A source-agnostic view of who and what can hold access.

`Snapshot` (models.py) stays exactly what it is: the Okta source adapter's
output. This layer composes above it. An `IdentityGraph` holds `Principal`s,
`Credential`s and `Grant`s from any number of sources, with the `Link`s that
say which principal belongs to which person, and why.

Two rules shape everything here, and the graph enforces them rather than
merely documenting them.

Nothing is fuzzy-matched. A link is evidenced or it is absent, `LinkMethod` is
a ladder of named methods rather than a score, and two equally-strong links
naming different people leave the principal *unlinked* instead of picking one.
A false link is worse than no link, because it marks a credential as accounted
for when nobody is accountable for it.

Silence is not absence. Completeness is tracked per source (`SourceMeta`), so a
failed read reports as "incomplete", never as "this person holds nothing".
Counts are derived from the same predicates that produce the lists, so a
coverage number can never disagree with the principals behind it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from ..models import format_time

# A principal is only unique within its source: two sources can both have an
# "alice", and an AWS key and a GitHub PAT are different things with the same id.
PrincipalKey = tuple[str, str]

# A group, in the source that holds it: (source, group id). Same shape as
# PrincipalKey and deliberately not the same alias -- a group is not a principal.
GroupKey = tuple[str, str]

# An app a group reaches: (app id, app label).
AppRef = tuple[str, str]


class PrincipalKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    UNKNOWN = "unknown"


class Status(StrEnum):
    """Normalised account status. Sources have their own words for these, and
    `Principal.source_status` keeps the source's own."""

    ACTIVE = "active"  # exists, and is or can become usable
    DISABLED = "disabled"  # sign-in blocked, access still attached
    UNKNOWN = "unknown"  # the source did not say, or said something new


class CredentialKind(StrEnum):
    """Things that outlive the account they were created under: deactivating
    that account does not stop them working. This is the long tail a joiner /
    mover / leaver automation does not cover."""

    OKTA_API_TOKEN = "okta_api_token"
    GITHUB_PAT = "github_pat"
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
    can check. SSO_IDENTITY is the IdP's own identity assertion and is
    authoritative. VERIFIED_EMAIL is an exact match on an address the source
    itself states. DECLARED is a register entry a person signed up to. CREATOR
    comes from an audit log and means accountable, not necessarily owner -- and
    the creator may themselves have left, which is a worse finding, not an
    answer.

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
    # None means the source did not say, or a read that would have said failed.
    # False is a claim, and a claim made from data nobody read is how a review
    # misses a credential that can change things.
    write_access: bool | None = None

    @property
    def holder_key(self) -> PrincipalKey | None:
        return (self.source, self.holder) if self.holder else None

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
    # Oldest point this source's activity evidence reaches, for sources that
    # report use over a window (Okta's System Log). None where the source has
    # no window because it reports last-used per credential for all time
    # (GitHub), or where the read never happened. Those are different things,
    # so this field is NOT the trust signal -- activity_complete is.
    activity_since: datetime | None = None
    # Whether a missing record of use can be believed. False when the read did
    # not run or was cut short, so "no last-used" means "not known to have been
    # used" rather than "not used". Every dormancy judgement reads this first.
    activity_complete: bool = True

    @property
    def complete(self) -> bool:
        return not self.gaps

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
    """How much of the estate is accounted for, as numbers to trend across
    reviews. The trend going down is the point of the tool.

    Counts only -- no labels, no emails -- so this is the shape that can cross
    a Step Functions boundary or reach a Slack channel under the data-handling
    rules in CLAUDE.md.
    """

    total: int
    by_method: dict[str, int]
    unlinked: int
    contested: int
    incomplete_sources: list[str] = field(default_factory=list)

    @property
    def reliable(self) -> bool:
        """False when a source read was incomplete. Then `unlinked` is a lower
        bound on a partial estate, not a count of what is out there."""
        return not self.incomplete_sources

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_method": self.by_method,
            "unlinked": self.unlinked,
            "contested": self.contested,
            "incomplete_sources": self.incomplete_sources,
            "reliable": self.reliable,
        }


@dataclass(frozen=True)
class IdentityGraph:
    """Principals, credentials and grants from one or more sources, with the
    links between principals and people.

    Built by projecting each source's own output into it -- `Snapshot` through
    identity.okta, GitHub through its own adapter -- and composed with
    `compose`. Frozen, because every lookup is indexed on construction: a graph
    that could be appended to after the fact would answer `principal()` with
    None for a principal it contains, and no test would catch it.

    `grants` is what a source stated verbatim; it is NOT every grant in the
    graph. App-via-group access is held compressed in `group_apps` -- the apps
    a group reaches, once per group rather than once per (member, app) pair --
    and expanded on read by `grants_for`. One org-wide group over 250 apps is
    1.25M grants materialised against a 1024 MB Lambda; stored this way it is
    250 entries and the members' own GROUP grants. Ask `grants_for` for one
    principal's access and `all_grants()` for the whole set. Reading `grants`
    directly gets an answer that is short by every app anyone reaches through a
    group.
    """

    sources: tuple[SourceMeta, ...] = ()
    principals: tuple[Principal, ...] = ()
    credentials: tuple[Credential, ...] = ()
    grants: tuple[Grant, ...] = ()
    links: tuple[Link, ...] = ()
    # (source, group id) -> the apps that group reaches. Expanded against a
    # principal's own GROUP grants, which are what say who is in the group.
    group_apps: Mapping[GroupKey, tuple[AppRef, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        put = object.__setattr__  # frozen dataclass: the only way to fill fields
        for name in ("sources", "principals", "credentials", "grants", "links"):
            put(self, name, tuple(getattr(self, name)))
        put(self, "group_apps", {k: tuple(v) for k, v in dict(self.group_apps).items()})

        by_key: dict[PrincipalKey, Principal] = {}
        for principal in self.principals:
            if principal.key in by_key:
                raise ValueError(
                    f"principal {principal.id!r} appears twice in source {principal.source!r}; "
                    f"a duplicate would be counted once and looked up once, so every number "
                    f"derived from it would be wrong"
                )
            by_key[principal.key] = principal
        put(self, "_principals", by_key)

        # Strongest link wins. Two equally strong links naming different people
        # do NOT resolve to whichever adapter appended first -- the principal is
        # contested, which means unlinked, which means a finding.
        best: dict[PrincipalKey, Link] = {}
        contested: set[PrincipalKey] = set()
        for link in self.links:
            current = best.get(link.principal)
            if current is None:
                best[link.principal] = link
            elif link.method.rank < current.method.rank:
                best[link.principal] = link
                contested.discard(link.principal)
            elif link.method.rank == current.method.rank and link.identity != current.identity:
                contested.add(link.principal)
        for key in contested:
            best.pop(key, None)
        put(self, "_best", best)
        put(self, "_contested", frozenset(contested))

        # Indexed on construction: a check that walks principals and asks each
        # one for its grants is otherwise O(principals x grants), which is
        # invisible at 11 users and minutes of CPU at 5000.
        grants_by: dict[PrincipalKey, list[Grant]] = {}
        for grant in self.grants:
            grants_by.setdefault(grant.principal_key, []).append(grant)
        put(self, "_grants", {k: tuple(v) for k, v in grants_by.items()})

        creds_by: dict[PrincipalKey, list[Credential]] = {}
        for credential in self.credentials:
            key = credential.holder_key
            if key:
                creds_by.setdefault(key, []).append(credential)
        put(self, "_credentials", {k: tuple(v) for k, v in creds_by.items()})

        by_identity: dict[str, list[PrincipalKey]] = {}
        for key, link in best.items():
            if link.identity:
                by_identity.setdefault(link.identity, []).append(key)
        put(self, "_by_identity", by_identity)

    @classmethod
    def compose(cls, *graphs: IdentityGraph) -> IdentityGraph:
        """Combine per-source graphs into one.

        Sources stay separate: two reads of the same source would make every
        count wrong, so that is an error. So is a graph whose records name a
        source it does not declare -- that principal would be invisible to
        `incomplete_sources` while still inflating the totals.
        """
        seen: set[str] = set()
        for graph in graphs:
            declared = {m.source for m in graph.sources}
            if len(declared) != len(graph.sources):
                raise ValueError("a graph declares the same source twice")
            clash = seen & declared
            if clash:
                raise ValueError(f"source {sorted(clash)[0]!r} appears in more than one graph")
            seen |= declared
            for principal in graph.principals:
                if principal.source not in declared:
                    raise ValueError(
                        f"principal {principal.id!r} names source {principal.source!r}, "
                        f"which its graph does not declare"
                    )
        return cls(
            sources=tuple(m for g in graphs for m in g.sources),
            principals=tuple(p for g in graphs for p in g.principals),
            credentials=tuple(c for g in graphs for c in g.credentials),
            grants=tuple(x for g in graphs for x in g.grants),
            links=tuple(x for g in graphs for x in g.links),
            # Keys carry their source and compose rejects a source appearing
            # twice, so there is nothing to collide.
            group_apps={k: v for g in graphs for k, v in g.group_apps.items()},
        )

    def principal(self, key: PrincipalKey) -> Principal | None:
        return self._principals.get(key)

    def source(self, name: str) -> SourceMeta | None:
        return next((m for m in self.sources if m.source == name), None)

    def link_for(self, key: PrincipalKey) -> Link | None:
        """The strongest link for this principal, or None when it is unlinked
        or contested."""
        return self._best.get(key)

    def unlinked(self) -> list[Principal]:
        """Principals no evidence ties to anyone, including those whose
        attribution is contested. The headline finding, not an edge case."""
        return [p for p in self.principals if p.key not in self._best]

    def contested(self) -> list[Principal]:
        """Principals two equally strong links disagree about. Worse than
        unlinked: something claims to know who owns this, twice, differently."""
        return [p for p in self.principals if p.key in self._contested]

    def holder_of(self, credential: Credential) -> Principal | None:
        """The principal holding a credential, or None when the source names a
        holder that no longer exists -- a credential outliving its account."""
        key = credential.holder_key
        return self._principals.get(key) if key else None

    def credentials_for(self, key: PrincipalKey) -> list[Credential]:
        # A new list each call: handing back the index would let a caller append
        # to it and change what a frozen graph reports.
        return list(self._credentials.get(key, ()))

    def _via_group(self, grant: Grant) -> Iterator[Grant]:
        """The app grants a GROUP grant stands for.

        `via` is rebuilt from the group grant's own label, which is the group
        name the projection stored: an evidence bundle and a decision screen
        both print this string, so it has to come out exactly as it did when
        every pair was materialised.
        """
        if grant.kind is not GrantKind.GROUP:
            return
        for app_id, app_label in self.group_apps.get((grant.source, grant.target), ()):
            yield Grant(
                grant.source,
                grant.principal,
                GrantKind.APP,
                app_id,
                app_label,
                f"group:{grant.target_label}",
            )

    def grants_for(self, key: PrincipalKey) -> list[Grant]:
        """Everything this principal can reach: what the source stated, plus
        the apps its groups reach.

        A new list each call, and the expanded grants come last -- they are
        built here, not stored, so nothing can hold a reference to one.
        """
        stored = self._grants.get(key, ())
        out = list(stored)
        if self.group_apps:
            for grant in stored:
                out.extend(self._via_group(grant))
        return out

    def all_grants(self) -> Iterator[Grant]:
        """Every grant in the graph, expanded. This is the complete set;
        `grants` is only the part stored verbatim."""
        for grant in self.grants:
            yield grant
            yield from self._via_group(grant)

    def principals_of(self, identity: str) -> list[Principal]:
        """Everything this person holds, across sources -- including principals
        they are only accountable for, such as a bot they set up.

        An empty identity is nobody, not a person who owns every service
        account declared without an owner.
        """
        if not identity:
            return []
        keys = sorted(self._by_identity.get(identity, ()))
        return [p for k in keys if (p := self._principals.get(k))]

    def identities(self) -> list[Identity]:
        """The people this graph knows about, each with their linked principals.

        A principal appears under one person only: the strongest link wins, so
        an account whose SSO identity is one person and whose audit-log creator
        is another belongs to the SSO identity.
        """
        out = []
        for key in sorted(self._by_identity):
            links = sorted(
                (self._best[k] for k in self._by_identity[key]),
                key=lambda x: (x.method.rank, x.principal),
            )
            out.append(Identity(key=key, links=links))
        return out

    def incomplete_sources(self) -> list[str]:
        return [m.source for m in self.sources if not m.complete]

    def coverage(self) -> Coverage:
        """Counts derived from the same predicates that produce the lists, so
        the headline number can never disagree with the principals behind it."""
        counts = {str(m): 0 for m in METHOD_ORDER}
        for key, link in self._best.items():
            if key in self._principals:
                counts[str(link.method)] += 1
        return Coverage(
            total=len(self._principals),
            by_method=counts,
            unlinked=len(self.unlinked()),
            contested=len(self.contested()),
            incomplete_sources=self.incomplete_sources(),
        )

    def to_dict(self) -> dict:
        """The whole graph, for an evidence bundle.

        This carries personal data -- logins, emails, and the evidence strings
        that name people. It belongs where the CLAUDE.md rules allow personal
        data (the PDF, a JSM ticket, the CISO's DM), never in Step Functions
        input or output and never in a Slack channel post. `Coverage.to_dict`
        is the counts-only shape for those.
        """
        return {
            "sources": [x.to_dict() for x in self.sources],
            "principals": [x.to_dict() for x in self.principals],
            "credentials": [x.to_dict() for x in self.credentials],
            "grants": [x.to_dict() for x in self.all_grants()],
            "links": [x.to_dict() for x in self.links],
        }
