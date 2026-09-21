"""Per-departure evidence: everything one person still holds, in one place.

A review answers "is this access right?" across the whole org, fourteen checks
at a time. A transition answers a narrower and harder question about one
person -- "did their departure actually finish?" -- which is what an auditor
asks about a leaver, and what a quarterly review spread across a report, a CSV
and nine findings never assembles.

The unit is a `Transition` with a kind rather than a `Departure`, because a
mover is the same shape with a different effective date. Movers are the harder
and more valuable case: access accretes across role changes and nothing ever
triggers a removal. Only leavers are detected today, and `MOVER` exists so that
adding them does not change the file format or anything reading it.

Two honesty rules, both the repo's recurring defect class in a place where it
would do real damage. A bundle listing nothing is only evidence of a clean
departure when the reads that would have found something ran, so every
transition carries the review's own gaps and a `complete` flag, and a bundle
from an incomplete review says so in the file rather than reading as a clean
bill of health. And a principal reaches a person's bundle only through an
evidenced link, never a name or an email that looks similar, because a bundle
that claims someone's leftover credential has been accounted for is worse than
one that admits it does not know.

This file carries personal data -- logins, emails, link evidence naming people
-- so it belongs where CLAUDE.md allows that: the run folder, the PDF, a JSM
ticket, the CISO's DM. `summary` is the counts-only shape for a Slack channel
or Step Functions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from .checks import SEVERITIES, Finding, ReviewContext, graph_findings_by_identity
from .identity import OKTA, identity_key
from .roster import RosterEntry

TRANSITIONS_FILE = "transitions.json"
FORMAT = 1
READABLE_FORMATS = (1,)


class TransitionsError(ValueError):
    pass


class TransitionKind(StrEnum):
    """Why this person's access should have changed.

    LEAVER comes from the HR roster: terminated, or past their end date. MOVER
    is declared and not yet built -- see the module docstring.
    """

    LEAVER = "leaver"
    MOVER = "mover"


@dataclass
class Transition:
    """One person whose access should have changed, and what is still there."""

    kind: TransitionKind
    identity: str  # the join key across sources: the Okta profile email
    name: str
    okta_login: str
    effective: date | None  # what HR recorded; None when HR gave a status but no date
    roster_status: str
    manager: str
    # Every principal an evidenced link ties to them, Okta included: the Okta
    # account being deactivated is what makes the rest of the list the finding,
    # so a bundle that left it out would be arguing with half its own evidence.
    principals: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    # The review's gaps, copied per transition so a single bundle lifted out of
    # the run folder and attached to a ticket still says what was not read.
    gaps: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """False when a source read was incomplete. Then the principals below
        are a lower bound on what this person holds, not an inventory."""
        return not self.gaps

    @property
    def outside_okta(self) -> list[dict]:
        """What Okta deactivation does not reach, which is the whole point."""
        return [p for p in self.principals if p["source"] != OKTA]

    def to_dict(self) -> dict:
        return {
            "kind": str(self.kind),
            "identity": self.identity,
            "name": self.name,
            "okta_login": self.okta_login,
            "effective": self.effective.isoformat() if self.effective else "",
            "roster_status": self.roster_status,
            "manager": self.manager,
            "complete": self.complete,
            "gaps": self.gaps,
            "principals": self.principals,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Transition:
        kind = d.get("kind", "")
        if kind not in tuple(TransitionKind):
            raise TransitionsError(f"unknown transition kind {kind!r}")
        effective = d.get("effective") or ""
        return cls(
            kind=TransitionKind(kind),
            identity=d.get("identity", ""),
            name=d.get("name", ""),
            okta_login=d.get("okta_login", ""),
            effective=date.fromisoformat(effective) if effective else None,
            roster_status=d.get("roster_status", ""),
            manager=d.get("manager", ""),
            principals=list(d.get("principals") or []),
            findings=list(d.get("findings") or []),
            gaps=list(d.get("gaps") or []),
        )


def _finding_row(f: Finding) -> dict:
    return {
        "check_id": f.check_id,
        "title": f.title,
        "severity": f.severity,
        "subject": f.subject,
        "detail": f.detail,
        "remediation": f.remediation,
    }


def _held(ctx: ReviewContext, identity: str) -> list[dict]:
    """Every principal linked to this person, with the evidence that links it.

    The link is included, not just the principal: "this GitHub account is
    theirs" is a claim, and a bundle that makes it without showing which rung
    of `LinkMethod` it rests on is asking a reviewer to take it on trust.
    """
    graph = ctx.graph
    out = []
    for principal in graph.principals_of(identity):
        link = graph.link_for(principal.key)
        record = principal.to_dict()
        record["link"] = link.to_dict() if link else None
        record["credentials"] = [c.to_dict() for c in graph.credentials_for(principal.key)]
        record["grants"] = [g.to_dict() for g in graph.grants_for(principal.key)]
        out.append(record)
    # Okta last: the other sources are where the departure is unfinished, and a
    # reviewer reads the top of the list.
    out.sort(key=lambda p: (p["source"] == OKTA, p["source"], p["label"]))
    return out


def _findings_for(findings, login: str, graph_by_identity, identity: str) -> list[dict]:
    """Every finding about this person: the Okta ones keyed on their login, and
    the cross-source ones keyed on an evidenced identity.

    Worst first, and across both groups rather than within each: an Okta finding
    is not more important than a GitHub one just because Okta was read first,
    and whoever opens this bundle reads the top of the list.
    """
    login = login.lower()
    rows = [f for f in findings
            if f.subject.lower() == login or f.subject.lower().startswith(f"{login} / ")]
    rows += [f for f, _ in graph_by_identity.get(identity, ())]
    rows.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check_id))
    return [_finding_row(f) for f in rows]


def build_transitions(ctx: ReviewContext, findings, gaps: list[str]) -> list[Transition] | None:
    """One bundle per person the roster says has gone.

    `gaps` is the review's own completeness answer (`report.all_gaps` through
    `ReviewRun.gaps`), never recomputed here: a bundle that decided for itself
    whether the review was complete would be a seventh owner of the claim, and
    five of the first six were wrong.

    Everyone who has left gets a bundle, including those holding nothing. A
    departure that completed is evidence too, and it is the denominator that
    makes the ones with residue mean anything.

    None -- not an empty list -- when there is no graph or no roster, following
    `ReviewRun.items`. "Nobody left" and "nothing looked" are different answers,
    and `summary` of an empty list would report every departure clean and the
    review complete for a run that never ran this at all.
    """
    if ctx.graph is None or ctx.roster is None:
        return None
    graph_by_identity = graph_findings_by_identity(ctx.graph, findings)
    # By identity, not by account: one person with two Okta logins is one
    # departure. Keyed on identity so the residue is never counted twice, and
    # walked in login order so which of the two accounts names the bundle does
    # not depend on the order the API happened to return users in -- evidence
    # that changes between two reads of the same estate is not evidence.
    seen: dict[str, Transition] = {}
    for user in sorted(ctx.snapshot.users, key=lambda u: u.login.lower()):
        entry: RosterEntry | None = ctx.roster_entry(user)
        if entry is None or not entry.is_gone(ctx.as_of):
            continue
        identity = identity_key(user)
        if not identity or identity in seen:
            continue
        seen[identity] = Transition(
            kind=TransitionKind.LEAVER,
            identity=identity,
            name=entry.name or user.name,
            okta_login=user.login,
            effective=entry.end_date,
            roster_status=entry.status,
            manager=entry.manager or user.manager,
            principals=_held(ctx, identity),
            findings=_findings_for(findings, user.login, graph_by_identity, identity),
            gaps=list(gaps),
        )
    return [seen[k] for k in sorted(seen)]


def transitions_json(transitions: list[Transition], as_of: date) -> str:
    return json.dumps(
        {"format": FORMAT, "review_date": as_of.isoformat(),
         "transitions": [t.to_dict() for t in transitions]},
        indent=2,
    ) + "\n"


def load_transitions(text: str) -> list[Transition]:
    data = json.loads(text)
    if data.get("format") not in READABLE_FORMATS:
        raise TransitionsError(f"unsupported {TRANSITIONS_FILE} format {data.get('format')!r}")
    return [Transition.from_dict(d) for d in data["transitions"]]


def summary(transitions: list[Transition]) -> dict[str, int | bool]:
    """Counts only -- no names, no logins -- so this is the shape that can cross
    a Step Functions boundary or reach a Slack channel under CLAUDE.md's
    data-handling rules.

    `complete` is false when any bundle was built from an incomplete read, which
    makes `unfinished` a lower bound. A count of departures with leftover access
    that quietly omitted the ones nobody could check would be the exact defect
    this module's docstring warns about.
    """
    unfinished = [t for t in transitions if t.outside_okta]
    return {
        "total": len(transitions),
        "unfinished": len(unfinished),
        "clean": len(transitions) - len(unfinished),
        "complete": all(t.complete for t in transitions),
    }
