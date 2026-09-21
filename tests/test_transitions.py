import json
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import Config, ReviewContext, run_checks
from access_review.identity import (
    OKTA,
    GitHubSnapshot,
    IdentityGraph,
    project_github,
    project_snapshot,
)
from access_review.report import all_gaps
from access_review.roster import load_roster
from access_review.transitions import (
    Transition,
    TransitionKind,
    TransitionsError,
    build_transitions,
    load_transitions,
    summary,
    transitions_json,
)
from access_review.models import Snapshot

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)


@pytest.fixture
def demo():
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster = load_roster(FIXTURES / "demo_roster.csv", config.timezone())
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    graph = IdentityGraph.compose(
        project_snapshot(snapshot, config.service_accounts), project_github(github)
    )
    return ReviewContext(snapshot, roster, config, AS_OF, graph=graph)


def built(ctx):
    findings, _ = run_checks(ctx)
    return build_transitions(ctx, findings, all_gaps(ctx.snapshot, ctx.graph))


def by_login(transitions):
    return {t.okta_login.split("@")[0]: t for t in transitions}


def test_one_bundle_per_departure(demo):
    got = by_login(built(demo))
    assert set(got) == {"marcus.lee", "sofia.ramos", "victor.nguyen"}
    assert {t.kind for t in got.values()} == {TransitionKind.LEAVER}
    assert got["marcus.lee"].effective == date(2026, 8, 29)
    assert got["marcus.lee"].name == "Marcus Lee"


def test_the_bundle_gathers_what_okta_deactivation_does_not_reach(demo):
    """The whole question a departure bundle answers. Victor's Okta account was
    deactivated, so the JML automation did its job -- and he still holds a
    write-capable GitHub account nothing in Okta can see."""
    victor = by_login(built(demo))["victor.nguyen"]
    okta = [p for p in victor.principals if p["source"] == OKTA and p["label"].startswith("victor")]
    assert okta and okta[0]["status"] == "disabled"
    outside = {p["label"] for p in victor.outside_okta}
    assert outside == {"victor-nguyen"}
    held = [p for p in victor.principals if p["label"] == "victor-nguyen"][0]
    assert held["status"] == "active"
    assert len(held["credentials"]) == 2


def test_the_bundle_includes_what_they_were_accountable_for(demo):
    """The long tail of a departure is not only their own credentials. Victor set
    up an Okta service client, so it is in his bundle by CREATOR -- accountable
    rather than owner, which is why the link method travels with it."""
    victor = by_login(built(demo))["victor.nguyen"]
    bot = [p for p in victor.principals if p["label"] == "Reporting Bot"]
    assert bot, [p["label"] for p in victor.principals]
    assert bot[0]["link"]["method"] == "creator"
    assert "by victor.nguyen" in bot[0]["link"]["evidence"]


def test_every_principal_carries_the_evidence_that_links_it(demo):
    """A bundle asserting an account is someone's without showing which rung of
    LinkMethod that rests on is asking to be taken on trust."""
    for t in built(demo):
        for p in t.principals:
            assert p["link"] and p["link"]["method"], (t.okta_login, p["label"])


def test_a_bundle_from_an_incomplete_review_says_so(demo):
    """Silence is not absence, and here it would be a clean bill of health: a
    bundle listing nothing is evidence a departure finished only if the reads
    that would have found something actually ran."""
    ts = built(demo)
    assert all(not t.complete and t.gaps for t in ts), "the demo review has GitHub gaps"
    assert summary(ts)["complete"] is False
    # And the gaps survive the round trip, so a bundle attached to a ticket on
    # its own still carries the caveat.
    again = load_transitions(transitions_json(ts, AS_OF))
    assert again[0].gaps == ts[0].gaps and again[0].complete is False


def test_no_graph_is_not_the_same_as_nobody_left(demo):
    """None, not an empty list. `summary([])` reports every departure clean and
    the review complete, which for a run that never looked is a claim nobody
    checked -- the defect class this repo keeps producing."""
    okta_only = ReviewContext(demo.snapshot, demo.roster, demo.config, AS_OF)
    findings, _ = run_checks(okta_only)
    assert build_transitions(okta_only, findings, []) is None
    no_roster = ReviewContext(demo.snapshot, None, demo.config, AS_OF, graph=demo.graph)
    assert build_transitions(no_roster, findings, []) is None
    # An empty list is the other answer, and it does mean "nobody left".
    assert summary([]) == {"total": 0, "unfinished": 0, "clean": 0, "complete": True}


def test_findings_are_gathered_worst_first_across_sources(demo):
    """An Okta finding is not more important than a GitHub one because Okta was
    read first, and whoever opens the bundle reads the top."""
    from access_review.checks import SEVERITIES

    for t in built(demo):
        ranks = [SEVERITIES.index(f["severity"]) for f in t.findings]
        assert ranks == sorted(ranks), (t.okta_login, t.findings)
    sofia = by_login(built(demo))["sofia.ramos"]
    assert sofia.findings[0]["check_id"] == "AR-17"


def test_the_bundle_carries_both_okta_and_cross_source_findings(demo):
    marcus = by_login(built(demo))["marcus.lee"]
    ids = {f["check_id"] for f in marcus.findings}
    assert "AR-01" in ids, "the Okta side of his departure"
    assert "AR-17" in ids, "the GitHub side"


def test_summary_is_counts_only(demo):
    """It crosses a Step Functions boundary and reaches a Slack channel, where
    CLAUDE.md allows counts and completeness and nothing else."""
    ts = built(demo)
    got = summary(ts)
    assert got == {"total": 3, "unfinished": 3, "clean": 0, "complete": False}
    text = json.dumps(got)
    for secret in ("marcus", "victor", "sofia", "acme.example", "acme-eng"):
        assert secret not in text


def _with_second_account(demo, order):
    """The demo plus a second Okta account for Victor on the same profile email."""
    users = list(demo.snapshot.users)
    victor = next(u for u in users if u.login.startswith("victor"))
    second = type(victor)(**{**victor.__dict__, "id": f"{victor.id}-2", "login": "a.nguyen@acme.example"})
    snapshot = type(demo.snapshot)(**{**demo.snapshot.__dict__, "users": order([*users, second])})
    graph = IdentityGraph.compose(
        project_snapshot(snapshot, demo.config.service_accounts),
        project_github(GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))),
    )
    ctx = ReviewContext(snapshot, demo.roster, demo.config, AS_OF, graph=graph)
    findings, _ = run_checks(ctx)
    return build_transitions(ctx, findings, [])


def test_one_person_with_two_accounts_is_one_departure(demo):
    """Okta enforces a unique login, not a unique profile email. Two bundles for
    one person would double-count the residue in every number downstream."""
    ts = _with_second_account(demo, list)
    assert [t.identity for t in ts].count("victor.nguyen@acme.example") == 1


def test_which_account_names_the_bundle_does_not_depend_on_read_order(demo):
    """Evidence that changes between two reads of the same estate is not
    evidence. The accounts are walked in login order, so the same one names the
    bundle whichever order the user read returned them in."""
    forward = _with_second_account(demo, list)
    backward = _with_second_account(demo, lambda us: list(reversed(us)))
    picked = {t.identity: t.okta_login for t in forward}
    assert picked == {t.identity: t.okta_login for t in backward}
    assert picked["victor.nguyen@acme.example"] == "a.nguyen@acme.example"


def test_summary_separates_a_finished_departure_from_an_unfinished_one():
    """A departure that completed is evidence too, and it is the denominator
    that makes the unfinished ones mean anything. The demo's three leavers all
    have residue, so the distinction needs its own case."""
    def bundle(identity, sources):
        return Transition(
            kind=TransitionKind.LEAVER, identity=identity, name="", okta_login=identity,
            effective=None, roster_status="terminated", manager="",
            principals=[{"source": s, "label": "x"} for s in sources],
        )

    clean = bundle("done@acme.example", [OKTA])
    unfinished = bundle("left@acme.example", [OKTA, "github:acme-eng"])
    assert summary([clean, unfinished]) == {
        "total": 2, "unfinished": 1, "clean": 1, "complete": True,
    }
    assert clean.outside_okta == [] and len(unfinished.outside_okta) == 1


def test_a_tampered_bundle_is_rejected(demo):
    data = json.loads(transitions_json(built(demo), AS_OF))
    data["transitions"][0]["kind"] = "promoted"
    with pytest.raises(TransitionsError):
        load_transitions(json.dumps(data))
    bad_format = json.loads(transitions_json(built(demo), AS_OF))
    bad_format["format"] = 99
    with pytest.raises(TransitionsError):
        load_transitions(json.dumps(bad_format))
