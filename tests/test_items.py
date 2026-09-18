import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import Config, ReviewContext, run_checks
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
