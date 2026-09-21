import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import CHECKS, GRAPH_CHECKS, SEVERITIES, Config, ReviewContext, run_checks
from access_review.identity import GitHubSnapshot, IdentityGraph, project_github, project_snapshot
from access_review.items import (
    CISO,
    DECIDE,
    KEEP,
    REVOKE,
    ItemsError,
    build_items,
    items_json,
    load_items,
    summary,
)
from access_review.models import Snapshot
from access_review.roster import load_roster

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)


@pytest.fixture
def demo():
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster = load_roster(FIXTURES / "demo_roster.csv", config.timezone())
    return ReviewContext(snapshot, roster, config, AS_OF)


@pytest.fixture
def demo_graph(demo):
    """The same review with GitHub composed in, which is what the cross-source
    checks read and what the reviewer's screen has to show."""
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    graph = IdentityGraph.compose(
        project_snapshot(demo.snapshot, demo.config.service_accounts), project_github(github)
    )
    return ReviewContext(demo.snapshot, demo.roster, demo.config, AS_OF, graph=graph)


def proposals(ctx):
    return {(i.user.split("@")[0], i.target): i.proposed for i in build_items(ctx)}


def test_demo_proposals(demo):
    got = proposals(demo)
    # The usage rule: direct, old, unused.
    assert got[("lee.chen", "Salesforce")] == REVOKE
    assert got[("hannah.ortiz", "AWS")] == REVOKE
    # Leavers and deactivated accounts lose everything.
    assert got[("marcus.lee", "GitHub")] == REVOKE
    assert got[("victor.nguyen", "Salesforce")] == REVOKE
    # Used recently.
    assert got[("lee.chen", "GitHub")] == KEEP
    assert got[("grace.park", "Salesforce")] == KEEP
    # Admin access is always a person's call.
    assert got[("jordan.kim", "Help Desk Administrator")] == DECIDE
    assert got[("priya.shah", "Okta Administrators")] == DECIDE


def test_every_item_goes_to_the_ciso(demo):
    items = build_items(demo)
    assert {i.reviewer for i in items} == {CISO}
    assert summary(items) == {"keep": 6, "revoke": 7, "decide": 3, "total": 16}


def test_nothing_is_proposed_for_revocation_on_incomplete_usage(demo):
    demo.snapshot.app_usage_complete = False
    got = proposals(demo)
    assert got[("lee.chen", "Salesforce")] == DECIDE
    assert got[("hannah.ortiz", "AWS")] == DECIDE
    # Leavers don't depend on usage data.
    assert got[("marcus.lee", "GitHub")] == REVOKE
    # And AR-14 says nothing rather than guessing.
    _, skipped = run_checks(demo)
    assert "AR-14" in skipped


def test_nothing_is_proposed_when_usage_was_never_collected(demo):
    demo.snapshot.app_usage_since = None
    assert proposals(demo)[("lee.chen", "Salesforce")] == DECIDE


def test_usage_that_doesnt_reach_back_far_enough_is_not_trusted(demo):
    demo.snapshot.app_usage_since = datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert proposals(demo)[("lee.chen", "Salesforce")] == DECIDE


def test_unused_access_through_a_group_is_left_to_a_person(demo):
    del demo.snapshot.app_usage[("u05", "a01")]
    [item] = [i for i in build_items(demo) if i.user.startswith("lee.chen") and i.target == "GitHub"]
    assert item.proposed == DECIDE
    assert "Engineering" in item.reason


def test_a_recent_assignment_is_kept(demo):
    sf = next(a for a in demo.snapshot.apps if a.label == "Salesforce")
    sf.assigned["u05"] = datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert proposals(demo)[("lee.chen", "Salesforce")] == KEEP


def test_an_unknown_assignment_date_is_left_to_a_person(demo):
    sf = next(a for a in demo.snapshot.apps if a.label == "Salesforce")
    del sf.assigned["u05"]
    assert proposals(demo)[("lee.chen", "Salesforce")] == DECIDE


def test_exempt_and_non_sso_apps_are_left_to_a_person(demo):
    demo.config.activity_exempt_apps = ["salesforce"]
    assert proposals(demo)[("lee.chen", "Salesforce")] == DECIDE
    demo.config.activity_exempt_apps = []
    next(a for a in demo.snapshot.apps if a.label == "AWS").sign_on_mode = "BOOKMARK"
    assert proposals(demo)[("hannah.ortiz", "AWS")] == DECIDE


def test_keys_are_stable_and_round_trip(demo):
    first = build_items(demo)
    assert [i.key for i in first] == [i.key for i in build_items(demo)]
    assert load_items(items_json(first, AS_OF, 90)) == first


def test_a_tampered_proposal_is_rejected(demo):
    data = json.loads(items_json(build_items(demo), AS_OF, 90))
    data["items"][0]["proposed"] = "approve-everything"
    with pytest.raises(ItemsError):
        load_items(json.dumps(data))


def test_items_carry_the_facts_and_why_it_could_be_an_issue(demo):
    findings, _ = run_checks(demo)
    items = {(i.user.split("@")[0], i.target): i for i in build_items(demo, findings)}
    sf = items[("lee.chen", "Salesforce")]
    assert sf.name == "Lee Chen"
    assert sf.facts[0].startswith("Okta: ACTIVE") and "MFA: none" in sf.facts[0]
    assert sf.facts[1].startswith("HR: employee, active") and "manager Priya Shah" in sf.facts[1]
    assert "assigned 2025-06-02" in sf.facts[2]
    assert any("AR-04" in c for c in sf.concerns) and any("AR-14" in c for c in sf.concerns)
    # AR-14 is about the one unused app, not every app Lee has.
    assert not any("AR-14" in c for c in items[("lee.chen", "GitHub")].concerns)
    # Admin roles say what the role can do.
    assert "Full control of Okta" in items[("priya.shah", "Super Administrator")].concerns[0]
    # Nothing flagged means no concerns, not an empty placeholder.
    assert items[("priya.shah", "GitHub")].concerns == ()


def test_item_files_from_earlier_runs_still_load(demo):
    data = json.loads(items_json(build_items(demo), AS_OF, 90))
    data["format"] = 1
    for d in data["items"]:
        for k in ("name", "facts", "concerns"):
            d.pop(k)
    old = load_items(json.dumps(data))
    assert old and old[0].facts == () and old[0].name == ""


def graph_concerns(item):
    return [c for c in item.concerns if "tied to them by" in c]


def test_a_cross_source_finding_reaches_every_item_for_that_person(demo_graph):
    """The whole point of the cross-source checks. AR-17 says marcus.lee still
    holds GitHub access weeks after leaving; the CISO decides his Okta access on
    this screen, so it has to appear there and not only in the PDF."""
    findings, _ = run_checks(demo_graph)
    items = build_items(demo_graph, findings)
    mine = [i for i in items if i.user.startswith("marcus.lee")]
    assert mine, "marcus.lee has no review items"
    for item in mine:
        assert any("AR-17" in c for c in graph_concerns(item)), item.target
    # It names the GitHub account, which is not his Okta login, so the reviewer
    # can go and look at the right thing.
    assert any("marcus-lee" in c for c in graph_concerns(mine[0]))
    # And the elevated role, which no credential list would have shown.
    assert any("admin role" in c for c in graph_concerns(mine[0]))


def test_the_concern_says_how_the_account_was_tied_to_the_person(demo_graph):
    """LinkMethod is a ladder of named evidence rather than a score so that a
    human can weigh it. The reviewer is the human, so the screen says which
    rung this rests on."""
    findings, _ = run_checks(demo_graph)
    items = build_items(demo_graph, findings)
    victor = next(i for i in items if i.user.startswith("victor.nguyen"))
    assert any("tied to them by the identity provider's own assertion" in c
               for c in graph_concerns(victor))


def test_a_finding_about_an_unlinked_principal_reaches_nobody(demo_graph):
    """AR-15 is the finding that nobody is accountable for a credential. Putting
    it on somebody's item would assert the attribution the graph refused to
    make -- and would mark the credential as somebody's problem when the whole
    finding is that it is nobody's."""
    findings, _ = run_checks(demo_graph)
    concerns = [c for i in build_items(demo_graph, findings) for c in i.concerns]
    assert not any("AR-15" in c or "AR-16" in c for c in concerns)
    # It is still a finding, still in the report, still ticketed.
    assert any(f.check_id == "AR-15" for f in findings)


def test_nothing_is_matched_on_a_login_or_a_label(demo_graph):
    """github.com/marcus-lee and Okta's marcus.lee resolve to one person only
    because a SAML assertion says so. Strip the link and the finding must stop
    reaching him, rather than falling back to the names looking alike."""
    findings, _ = run_checks(demo_graph)
    graph = demo_graph.graph
    stripped = IdentityGraph(
        sources=graph.sources, principals=graph.principals, credentials=graph.credentials,
        grants=graph.grants, links=tuple(x for x in graph.links if x.principal[0] == "okta"),
    )
    ctx = ReviewContext(demo_graph.snapshot, demo_graph.roster, demo_graph.config, AS_OF, graph=stripped)
    items = build_items(ctx, findings)
    assert not any(graph_concerns(i) for i in items)


def test_the_worst_concern_comes_first(demo_graph):
    """The reviewer reads the top of the list, so a critical finding never sits
    below a medium one."""
    findings, _ = run_checks(demo_graph)
    order = {f"{f.check_id} {f.title}": f.severity for f in findings}
    for item in build_items(demo_graph, findings):
        ranks = [SEVERITIES.index(sev) for key, sev in order.items()
                 for c in item.concerns if key in c]
        assert ranks == sorted(ranks), item.concerns


def test_every_graph_check_reaches_the_decision_screen(demo_graph):
    """GRAPH_CHECKS is derived from the registry, not listed. A graph check
    added to CHECKS and forgotten here would be a finding the report prints and
    the screen that settles it never shows -- which is the defect this replaced."""
    assert set(GRAPH_CHECKS) == {c.id for c in CHECKS if c.needs_graph}
    assert GRAPH_CHECKS, "no graph checks found, so this guard proves nothing"
