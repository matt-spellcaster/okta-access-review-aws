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
        # Graph subjects are the source's own id, not the login: see graph_subject.
        # The login is in the detail, and GRAPH_LOGINS maps them back here.
        "AR-15": {"github:acme-eng/U_kgDOBq1kh6", "github:acme-eng/U_kgDOBq1jg5",
                  "github:acme-eng/U_kgDOBq1gd2", "okta/a04"},
        "AR-16": {"github:acme-eng/U_kgDOBq1zzz", "github:acme-eng/sam-departed"},
        "AR-17": {"github:acme-eng/U_kgDOBq1bYx", "github:acme-eng/U_kgDOBq1daz",
                  "github:acme-eng/U_kgDOBq1cZy"},
    }


# The demo fixture's GitHub node ids, so the expectations above and the severity
# table below read as the people and bots they are.
GRAPH_LOGINS = {
    "github:acme-eng/U_kgDOBq1bYx": "marcus-lee",
    "github:acme-eng/U_kgDOBq1cZy": "victor-nguyen",
    "github:acme-eng/U_kgDOBq1daz": "sofia-ramos",
    "github:acme-eng/U_kgDOBq1gd2": "omar-haddad",
    "github:acme-eng/U_kgDOBq1jg5": "dev-contractor-42",
    "github:acme-eng/U_kgDOBq1kh6": "acme-ci-bot",
    "github:acme-eng/U_kgDOBq1zzz": "U_kgDOBq1zzz",
    "github:acme-eng/sam-departed": "sam-departed",
    "okta/a04": "Terraform Automation",
}


def test_cross_source_findings_carry_the_planted_severities(demo):
    """Severity is the whole judgement in these checks: write-capable and
    recently used is an investigation, dormant and read-only is a cleanup.
    Asserting subjects alone let all three severity expressions be replaced by
    constants with the suite still green."""
    findings, _ = run_checks(demo)
    graded = {
        (f.check_id, GRAPH_LOGINS[f.subject]): f.severity
        for f in findings if f.check_id in ("AR-15", "AR-16", "AR-17")
    }
    assert graded == {
        # A leaver whose credential can write is critical.
        ("AR-17", "victor-nguyen"): "critical",
        ("AR-17", "sofia-ramos"): "critical",
        # marcus-lee's PAT is read-only, so credentials alone would make this
        # high. He is still a GitHub organization owner, which can add
        # collaborators and turn off branch protection, so the role decides it.
        # This is the only planted case where the role is what carries the
        # grade: break the `roles or` branch and only this line moves.
        ("AR-17", "marcus-lee"): "critical",
        # Write-capable and unowned.
        ("AR-16", "sam-departed"): "high",
        ("AR-16", "U_kgDOBq1zzz"): "medium",  # grants, no credential
        ("AR-15", "acme-ci-bot"): "high",  # can write, used today
        ("AR-15", "dev-contractor-42"): "high",  # can write, used 2 days ago
        # Permissions were never readable, so write access is unknown -- which is
        # not the same as read-only, and must not be ranked as the mildest case.
        ("AR-15", "omar-haddad"): "medium",
        ("AR-15", "Terraform Automation"): "medium",
    }


def test_a_credential_whose_permissions_were_not_read_says_so(demo):
    findings, _ = run_checks(demo)
    [omar] = [f for f in findings
              if f.check_id == "AR-15" and f.subject == "github:acme-eng/U_kgDOBq1gd2"]
    assert "write access unknown" in omar.detail
    assert "omar-haddad" in omar.detail  # the readable name lives in the detail now


def test_two_principals_sharing_a_label_get_distinct_subjects(demo):
    """Ticket identity is (check_id, subject), hashed into a permanent Jira
    label. Two service clients with the same app label are two problems."""
    import copy
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    original = next(a for a in raw["apps"] if a["label"] == "Terraform Automation")
    twin = copy.deepcopy(original)
    twin["id"] = original["id"] + "-twin"
    raw["apps"].append(twin)
    snapshot = Snapshot.from_dict(raw)
    demo.snapshot = snapshot
    demo.graph = IdentityGraph.compose(
        project_snapshot(snapshot, demo.config.service_accounts),
        project_github(GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))),
    )
    findings, _ = run_checks(demo)
    subjects = [f.subject for f in findings if f.check_id == "AR-15"]
    assert len(subjects) == len(set(subjects)) == 5


def test_one_leaver_with_two_okta_accounts_is_reported_once(demo):
    """Okta enforces a unique login, not a unique profile email. Iterating
    leavers instead of identities emitted the same finding twice: two rows in
    findings.csv, one history key, one ticket label."""
    import copy
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    victor = next(u for u in raw["users"] if u["profile"]["email"] == "victor.nguyen@acme.example")
    second = copy.deepcopy(victor)
    second["id"] = victor["id"] + "-admin"
    second["login"] = "victor.nguyen.admin@acme.example"
    raw["users"].append(second)
    snapshot = Snapshot.from_dict(raw)
    demo.snapshot = snapshot
    demo.graph = IdentityGraph.compose(
        project_snapshot(snapshot, demo.config.service_accounts),
        project_github(GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))),
    )
    findings, _ = run_checks(demo)
    subjects = [f.subject for f in findings if f.check_id == "AR-17"]
    assert sorted(subjects) == sorted(set(subjects))


def _github_graph(demo, **overrides):
    raw = json.loads((FIXTURES / "demo_github.json").read_text())
    raw.update(overrides)
    return IdentityGraph.compose(
        project_snapshot(demo.snapshot, demo.config.service_accounts),
        project_github(GitHubSnapshot.from_dict(raw)),
    )


def test_ar15_still_names_an_unowned_account_when_the_credential_read_failed(demo):
    """The silence-is-absence bug this layer exists to prevent: an empty
    credential list is only evidence of nothing held when the read that would
    have said so actually ran."""
    demo.graph = _github_graph(demo, credentials_complete=False, credentials=[], fineGrainedTokens=[])
    findings, skipped = run_checks(demo)
    assert "AR-15" not in skipped
    subjects = {f.subject for f in findings if f.check_id == "AR-15"}
    assert "github:acme-eng/U_kgDOBq1kh6" in subjects  # acme-ci-bot, write-capable
    [bot] = [f for f in findings if f.subject == "github:acme-eng/U_kgDOBq1kh6"]
    assert "credential read did not complete" in bot.detail
    # An unread credential is not the mildest finding in the report.
    assert bot.severity == "high"


def test_a_credential_read_that_did_not_run_is_recorded_as_a_gap(demo):
    """SourceMeta.complete is `not gaps`, so a completeness flag that recorded
    no gap let the manifest say "complete" while a read never happened."""
    graph = _github_graph(demo, credentials_complete=False)
    [meta] = [m for m in graph.sources if m.source == "github:acme-eng"]
    assert any("did not run in full" in g for g in meta.gaps)
    assert meta.complete is False and meta.activity_complete is False


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


def test_cross_source_checks_map_to_the_controls_they_actually_evidence():
    """These IDs print into findings.csv, the report and the PDF as audit
    evidence, and a wrong one is what a compliance reviewer spots fastest.
    Pinned here rather than only in the golden PDF, whose failure message tells
    you to regenerate the artifact -- which blesses the regression.

    Each is the control the check evidences, and matches its Okta sibling:
    AR-15/AR-16 are identity-management and access-rights failures (A.5.16,
    A.5.18), not authentication-information ones (A.5.17, which covers how
    secrets are generated, issued and handled). AR-17 is access that outlived a
    departure (A.5.18), not equipment nobody returned (A.5.11). AR-17 also
    carries A.8.2 (privileged access rights), because it reports the elevated
    roles a departure leaves behind and not only credentials -- the control its
    Okta siblings AR-10 and AR-11 already map privileged access to.
    """
    controls = {c.id: c.controls for c in CHECKS if c.needs_graph}
    assert controls == {
        "AR-15": ["SOC 2 CC6.1", "SOC 2 CC6.2", "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "AR-16": ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3",
                  "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "AR-17": ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.16", "ISO 27001 A.5.18",
                  "ISO 27001 A.8.2"],
    }
    # A.5.17 and A.5.11 are the two that were wrong; neither belongs on a
    # cross-source check, and nothing else in CHECKS cites them either.
    cited = {control for c in CHECKS for control in c.controls}
    assert "ISO 27001 A.5.17" not in cited and "ISO 27001 A.5.11" not in cited


def test_ar15_does_not_promise_a_register_that_cannot_suppress_it():
    """The remediation told a human to record an owner in a register that
    project_github is never given, so following the instruction exactly could
    not change next quarter's result."""
    [ar15] = [c for c in CHECKS if c.id == "AR-15"]
    assert "the finding returns next quarter" in ar15.remediation
