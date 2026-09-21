import json
from collections import defaultdict
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import CHECKS, Config, ReviewContext, run_checks
from access_review.identity import GitHubSnapshot, IdentityGraph, project_github, project_snapshot
from access_review.models import Snapshot
from access_review.roster import load_roster

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


def by_check(findings):
    result = defaultdict(set)
    for f in findings:
        result[f.check_id].add(f.subject.split("@")[0])
    return dict(result)


def test_demo_findings_are_exactly_the_planted_ones(demo):
    findings, skipped = run_checks(demo)
    assert skipped == []
    assert by_check(findings) == {
        "AR-01": {"marcus.lee"},
        "AR-02": {"sofia.ramos"},
        "AR-03": {"jordan.kim"},
        "AR-04": {"lee.chen"},
        "AR-05": {"hannah.ortiz"},
        "AR-06": {"omar.haddad"},
        "AR-07": {"sofia.ramos"},
        "AR-08": {"grace.park"},
        "AR-09": {"victor.nguyen"},
        "AR-10": {"Terraform Automation"},
        "AR-11": {"priya.shah", "jordan.kim"},
        "AR-12": {"marcus.lee", "victor.nguyen"},
        "AR-13": {"marcus.lee", "victor.nguyen"},
        "AR-14": {"lee.chen"},
        "AR-15": {"github:acme-eng/acme-ci-bot", "github:acme-eng/dev-contractor-42",
                  "github:acme-eng/omar-haddad", "okta/Terraform Automation"},
        "AR-16": {"github:acme-eng/U_kgDOBq1zzz", "github:acme-eng/sam-departed"},
        "AR-17": {"github:acme-eng/marcus-lee", "github:acme-eng/sofia-ramos",
                  "github:acme-eng/victor-nguyen"},
    }


def test_super_admin_api_client_is_high_and_read_only_admin_is_ignored(demo):
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.check_id == "AR-10"]
    assert f.severity == "high"
    assert "Super Administrator" in f.detail and "okta.users.manage" in f.detail


def test_api_client_with_only_write_scopes_is_medium(demo):
    bot = next(a for a in demo.snapshot.apps if a.label == "Reporting Bot")
    bot.granted_scopes = ["okta.groups.manage"]
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.subject == "Reporting Bot"]
    assert f.severity == "medium"
    assert "Read-Only" not in f.detail


def test_view_only_roles_alone_are_not_flagged(demo):
    bot = next(a for a in demo.snapshot.apps if a.label == "Reporting Bot")
    bot.admin_roles = ["Read-Only Administrator", "Report Administrator"]
    findings, _ = run_checks(demo)
    assert not [f for f in findings if f.subject == "Reporting Bot"]


def test_view_only_roles_are_left_out_of_the_detail(demo):
    bot = next(a for a in demo.snapshot.apps if a.label == "Reporting Bot")
    bot.admin_roles = ["Report Administrator", "mcp-role"]
    bot.granted_scopes = ["okta.users.manage"]
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.subject == "Reporting Bot"]
    assert f.detail == "API client has admin roles: mcp-role; write scope: okta.users.manage."


def test_user_facing_app_with_write_scopes_is_ignored(demo):
    findings, _ = run_checks(demo)
    assert not [f for f in findings if f.subject == "Okta Dashboard"]


def test_long_scope_list_is_truncated_with_high_risk_first(demo):
    bot = next(a for a in demo.snapshot.apps if a.label == "Reporting Bot")
    bot.granted_scopes = [f"okta.z{i}.manage" for i in range(10)] + ["okta.roles.manage", "okta.users.read"]
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.subject == "Reporting Bot"]
    assert "11 write scopes: okta.roles.manage, okta.z0.manage," in f.detail
    assert f.detail.endswith("and 6 more.")


def test_admin_found_by_role_or_group(demo):
    findings, _ = run_checks(demo)
    details = {f.subject.split("@")[0]: f.detail for f in findings if f.check_id == "AR-11"}
    assert "admin roles: Super Administrator" in details["priya.shah"]
    assert "admin groups: Okta Administrators" in details["priya.shah"]
    assert "admin groups" not in details["jordan.kim"]


def test_every_check_is_covered_by_the_demo(demo):
    findings, _ = run_checks(demo)
    assert {c.id for c in CHECKS} == {f.check_id for f in findings}


def test_findings_sorted_most_severe_first(demo):
    findings, _ = run_checks(demo)
    assert findings[0].severity == "critical"
    assert findings[-1].severity == "info"


def test_roster_checks_skipped_without_roster(demo):
    demo.roster = None
    findings, skipped = run_checks(demo)
    assert skipped == ["AR-01", "AR-02", "AR-03", "AR-12", "AR-13", "AR-17"]
    assert not {"AR-01", "AR-02", "AR-03", "AR-12", "AR-13", "AR-17"} & {f.check_id for f in findings}


def test_cross_source_checks_skipped_without_a_graph(demo):
    # A review that read only Okta must not answer questions about GitHub by
    # finding nothing there.
    demo.graph = None
    findings, skipped = run_checks(demo)
    assert skipped == ["AR-15", "AR-16", "AR-17"]
    assert not {"AR-15", "AR-16", "AR-17"} & {f.check_id for f in findings}


def test_without_roster_contractor_type_comes_from_okta_profile(demo):
    demo.roster = None
    findings, _ = run_checks(demo)
    assert by_check(findings)["AR-07"] == {"sofia.ramos"}


def test_service_account_not_reported_as_missing_from_hr(demo):
    demo.config.service_accounts = []
    findings, _ = run_checks(demo)
    assert "svc-ci" in by_check(findings)["AR-03"]


def test_unknown_mfa_is_info_not_high(demo):
    lee = next(u for u in demo.snapshot.users if u.login.startswith("lee.chen"))
    lee.factors = None
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.check_id == "AR-04"]
    assert f.severity == "info"


def test_inactive_threshold_is_configurable(demo):
    demo.config.inactive_days = 200
    findings, _ = run_checks(demo)
    assert "AR-05" not in by_check(findings)


def test_suspended_user_without_access_is_clean(demo):
    findings, _ = run_checks(demo)
    assert not [f for f in findings if f.subject.startswith("nina.patel")]


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"inactive_dayz": 30}')
    with pytest.raises(ValueError, match="inactive_dayz"):
        Config.load(path)
