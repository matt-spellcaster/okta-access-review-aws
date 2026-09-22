import copy
import json
from collections import defaultdict
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import CHECKS, Config, ReviewContext, run_checks
from access_review.identity import (
    Credential,
    CredentialKind,
    GitHubSnapshot,
    Grant,
    GrantKind,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKind,
    Status,
    project_github,
    project_snapshot,
)
from access_review.models import App, Snapshot
from access_review.register import Register
from access_review.roster import load_roster

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)


def _compose(ctx, snapshot=None, github=None):
    """The graph exactly as `review.run_review` builds it, register and all.

    Both projections get it. A fixture that passed it to Okta only would leave
    a declared GitHub bot reading as an unowned mystery here while production
    saw it declared, which is the bug this register change exists to close.
    """
    if github is None:
        github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    return IdentityGraph.compose(
        project_snapshot(snapshot or ctx.snapshot, ctx.config.service_accounts),
        project_github(github, ctx.config.service_accounts),
    )


@pytest.fixture
def demo():
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster = load_roster(FIXTURES / "demo_roster.csv", config.timezone())
    ctx = ReviewContext(snapshot, roster, config, AS_OF)
    ctx.graph = _compose(ctx)
    return ctx


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
        # victor held Reporting Bot's secret: custody, rotated not handed over.
        # The bot running after he left is not his activity.
        "AR-12": {"marcus.lee", "victor.nguyen"},
        "AR-13": {"marcus.lee"},
        "AR-14": {"lee.chen"},
        # Graph subjects are the source's own id, not the login: see graph_subject.
        # The login is in the detail, and GRAPH_LOGINS maps them back here.
        # okta/a04 (Terraform Automation) is not here: the register declares it
        # with an owner, which is the one thing that stops this check firing.
        # acme-ci-bot is still here, declared with no owner -- see the severity
        # table below, where declaring it moved the grade and not the finding.
        "AR-15": {"github:acme-eng/U_kgDOBq1kh6", "github:acme-eng/U_kgDOBq1jg5",
                  "github:acme-eng/U_kgDOBq1gd2"},
        "AR-16": {"github:acme-eng/U_kgDOBq1zzz", "github:acme-eng/sam-departed"},
        "AR-17": {"github:acme-eng/U_kgDOBq1bYx", "github:acme-eng/U_kgDOBq1daz",
                  "github:acme-eng/U_kgDOBq1cZy"},
        # The two service accounts whose only accountable person has left, and
        # the two ways a principal gets one: okta/a04 is declared to marcus.lee
        # in the register, okta/a05 is tied to victor.nguyen by nothing but the
        # System Log's record of who created it. Both are Okta API clients,
        # which is what AR-17 structurally cannot report -- it skips `okta`.
        "AR-18": {"okta/a04", "okta/a05"},
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
    "okta/a05": "Reporting Bot",
}


def test_cross_source_findings_carry_the_planted_severities(demo):
    """Severity is the whole judgement in these checks: write-capable and
    recently used is an investigation, dormant and read-only is a cleanup.
    Asserting subjects alone let all three severity expressions be replaced by
    constants with the suite still green."""
    findings, _ = run_checks(demo)
    graded = {
        (f.check_id, GRAPH_LOGINS[f.subject]): f.severity
        for f in findings if f.check_id in ("AR-15", "AR-16", "AR-17", "AR-18")
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
        # Can write, used today: high on the evidence. The register declares it
        # and names no owner, which is worth exactly one rung -- somebody wrote
        # the account down, and nobody is any more accountable for it.
        # dev-contractor-42 is the control: identical evidence, undeclared,
        # still high. Break the downgrade and only the first line moves.
        ("AR-15", "acme-ci-bot"): "medium",
        ("AR-15", "dev-contractor-42"): "high",  # can write, used 2 days ago
        # Permissions were never readable, so write access is unknown -- which is
        # not the same as read-only, and must not be ranked as the mildest case.
        ("AR-15", "omar-haddad"): "medium",
        # A write-capable client holding Super Administrator: nothing about the
        # account is read-only, and nobody is left to answer for it.
        ("AR-18", "Terraform Automation"): "critical",
        # The control for that one. Reporting Bot is every bit as orphaned --
        # it was used the day before this review, two months after its creator
        # left -- but its credential cannot write and Read-Only Administrator
        # is an admin role that cannot change a thing. Grade on what the
        # account can do, not on the fact that it has a role at all: put every
        # ROLE grant into the critical branch and only this line moves.
        ("AR-18", "Reporting Bot"): "high",
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
    demo.graph = _compose(demo, snapshot)
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
    demo.graph = _compose(demo, snapshot)
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
    assert skipped == ["AR-01", "AR-02", "AR-03", "AR-12", "AR-13", "AR-17", "AR-18"]
    assert not {"AR-01", "AR-02", "AR-03", "AR-12", "AR-13", "AR-17", "AR-18"} & \
        {f.check_id for f in findings}


def test_cross_source_checks_skipped_without_a_graph(demo):
    # A review that read only Okta must not answer questions about GitHub by
    # finding nothing there.
    demo.graph = None
    findings, skipped = run_checks(demo)
    assert skipped == ["AR-15", "AR-16", "AR-17", "AR-18"]
    assert not {"AR-15", "AR-16", "AR-17", "AR-18"} & {f.check_id for f in findings}


def test_without_roster_contractor_type_comes_from_okta_profile(demo):
    demo.roster = None
    findings, _ = run_checks(demo)
    assert by_check(findings)["AR-07"] == {"sofia.ramos"}


def test_service_account_not_reported_as_missing_from_hr(demo):
    demo.config.service_accounts = Register()
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
    Okta siblings AR-10 and AR-11 already map privileged access to. AR-18 is
    CC6.1 first (a credential in the estate with no authorized person behind
    it), CC6.2 and CC6.3 because a departure is what put it there, A.5.16 for
    the non-human identity lifecycle and A.8.2 for the same reason AR-17 has it.
    """
    controls = {c.id: c.controls for c in CHECKS if c.needs_graph}
    assert controls == {
        "AR-15": ["SOC 2 CC6.1", "SOC 2 CC6.2", "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "AR-16": ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3",
                  "ISO 27001 A.5.16", "ISO 27001 A.5.18"],
        "AR-17": ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.16", "ISO 27001 A.5.18",
                  "ISO 27001 A.8.2"],
        "AR-18": ["SOC 2 CC6.1", "SOC 2 CC6.2", "SOC 2 CC6.3",
                  "ISO 27001 A.5.16", "ISO 27001 A.5.18", "ISO 27001 A.8.2"],
    }
    # A.5.17 and A.5.11 are the two that were wrong; neither belongs on a
    # cross-source check, and nothing else in CHECKS cites them either.
    cited = {control for c in CHECKS for control in c.controls}
    assert "ISO 27001 A.5.17" not in cited and "ISO 27001 A.5.11" not in cited


def test_ar15s_remediation_is_an_instruction_that_works(demo):
    """It used to say that recording an owner would not stop the finding,
    because `project_github` was never given the register -- an instruction that
    could not change next quarter's result, printed in signed evidence.

    Asserted by following it rather than by reading it: the wording can be
    rewritten, and what has to stay true is that doing what it says works.
    """
    before = {f.subject for f in run_checks(demo)[0] if f.check_id == "AR-15"}
    assert "github:acme-eng/U_kgDOBq1jg5" in before, "dev-contractor-42 is the undeclared control"

    demo.config.service_accounts = Register.from_config([
        *demo.config.service_accounts.to_dict(),
        {"source": "github:acme-eng", "id": "dev-contractor-42", "owner": "priya.shah@acme.example"},
    ])
    demo.graph = _compose(demo)
    after = {f.subject for f in run_checks(demo)[0] if f.check_id == "AR-15"}
    assert before - after == {"github:acme-eng/U_kgDOBq1jg5"}, "the rest of the estate is untouched"
    assert demo.graph.link_for(("github:acme-eng", "U_kgDOBq1jg5")).identity == "priya.shah@acme.example"

GH = "github:acme-eng"
# A leaver the demo roster and the demo snapshot both know, so `_leavers` finds
# them and the identity is attested by their own Okta account rather than by the
# link these tests add.
LEFT = "marcus.lee@acme.example"


def _owns(demo, *, write_access=None, roles=(), status=Status.ACTIVE,
          kind=PrincipalKind.SERVICE, method=LinkMethod.DECLARED, identity=LEFT,
          credentials=True, activity_complete=True):
    """The demo graph with one more service account on it, owned by a leaver.

    The demo fixture's own two cases are Okta API clients, which is the shape
    AR-17 structurally cannot see. These are the shapes it could: a principal in
    another source, where the source reports roles apart from credentials and a
    status that is not ACTIVE. Hand-built because planting them in
    `demo_github.json` would mean a GitHub member who is really a bot, and every
    other check reads that fixture too.

    `replace`, never `IdentityGraph(...)`: `group_apps` defaults to empty, so a
    graph named field by field is short of everyone's app-via-group access while
    `incomplete_sources()` still reads clean.
    """
    graph = demo.graph
    principal = Principal(source=GH, id="bot-1", label="acme-release-bot", kind=kind, status=status)
    credential = Credential(source=GH, id="pat-1", kind=CredentialKind.GITHUB_PAT,
                            label="personal access token …aa11bb22", holder="bot-1",
                            write_access=write_access)
    demo.graph = replace(
        graph,
        principals=(*graph.principals, principal),
        credentials=(*graph.credentials, credential) if credentials else graph.credentials,
        grants=(*graph.grants, *(Grant(GH, "bot-1", GrantKind.ROLE, r.lower(), r) for r in roles)),
        links=(*graph.links, Link((GH, "bot-1"), method, identity,
                                  "declared a service account in the review register")),
        sources=tuple(replace(m, activity_complete=activity_complete) if m.source == GH else m
                      for m in graph.sources),
    )
    return [f for f in run_checks(demo)[0] if f.subject == f"{GH}/bot-1"]


def test_a_service_account_a_leaver_owned_is_reported_once_not_twice(demo):
    """AR-17 asks for a leaver's access to be revoked; AR-18 asks for their
    service account to be handed to somebody, because something in CI depends on
    it. Both firing on one principal is two tickets, one telling the assignee to
    revoke the bot and one telling them to keep it running, and neither closable
    without contradicting the other. AR-17 leaves service accounts to AR-18.

    Invisible in the demo fixture, where every service account a leaver owns is
    an Okta API client and AR-17 skips `okta` anyway, which is why this is here
    and not in the planted-findings table."""
    [found] = _owns(demo, write_access=True)
    assert found.check_id == "AR-18"
    # And the partition holds on everything the fixture does plant.
    findings, _ = run_checks(demo)
    by_check = {c: {f.subject for f in findings if f.check_id == c} for c in ("AR-17", "AR-18")}
    assert not by_check["AR-17"] & by_check["AR-18"]


def test_a_leavers_service_account_is_critical_on_an_elevated_role_alone(demo):
    """A source that reports roles apart from credentials makes the credential
    list the smaller half of what the account can do: a GitHub organization
    owner can add collaborators and turn off branch protection whatever its
    token is scoped to. Grade on write access alone and only this case moves."""
    [found] = _owns(demo, write_access=False, roles=("organization owner",))
    assert found.severity == "critical"
    assert "organization owner" in found.detail


def test_a_leavers_service_account_is_critical_on_write_access_alone(demo):
    """The other half. Grade on the roles alone and only this case moves."""
    [found] = _owns(demo, write_access=True)
    assert found.severity == "critical"


def test_a_leavers_service_account_that_can_change_nothing_is_still_high(demo):
    """The floor. Nobody is accountable for a live credential, which is work
    whatever it is scoped to -- and `_write_access` returning False here is a
    claim, not a silence: it took a read that completed to say so."""
    [found] = _owns(demo, write_access=False)
    assert found.severity == "high"


def test_a_leavers_service_account_whose_permissions_were_not_read_is_critical(demo):
    """Unknown write access is not the milder case. Ranked as read-only, an
    orphaned credential nobody could read the scopes of drops a rung on the
    strength of a read that failed."""
    [found] = _owns(demo, write_access=None)
    assert found.severity == "critical"


def test_a_disabled_service_account_a_leaver_owned_is_still_reported(demo):
    """AR-17 skips a DISABLED principal, because the source saying sign-in is
    blocked is that check's answer. It is not this one's: `CredentialKind` is
    the set of things that outlive the account they were created under, so a
    blocked sign-in says nothing about the token, and somebody still has to
    choose between handing the account over and shutting it down."""
    [found] = _owns(demo, write_access=True, status=Status.DISABLED)
    assert found.check_id == "AR-18"


def test_an_account_a_leaver_only_created_is_reported_like_one_they_declared(demo):
    """CREATOR is the audit log saying who set an account up. It establishes
    accountability rather than ownership, and the creator having left is a worse
    finding than a weak claim, not an answer -- so this check reads the link the
    graph chose, whatever method carried it. Counting register entries alone
    drops okta/a05 from the planted table, and this from here."""
    [found] = _owns(demo, write_access=True, method=LinkMethod.CREATOR)
    assert found.check_id == "AR-18"


def test_an_account_nobody_is_named_for_is_left_to_ar15(demo):
    """The two are disjoint by construction, not by a filter: this walks
    `principals_of`, which is indexed on identities a source attested, and AR-15
    walks the principals whose best link reaches nobody. A register entry naming
    no owner is AR-15's second branch and must not become a departure finding
    for a person the graph never named."""
    found = _owns(demo, write_access=True, identity="")
    assert [f.check_id for f in found] == ["AR-15"]


def test_a_leavers_service_account_whose_credential_read_failed_is_not_ranked_clean(demo):
    """The branch every other AR-18 test walks past, because the demo graph is
    complete and every hand-built case here carries a credential.

    An empty credential list is evidence of nothing held only when the read that
    would have said so ran. With `known` hard-coded True the whole suite stayed
    green: the account dropped to `high` and the detail stopped saying anything
    was unknown, which is the milder answer derived from a read that failed --
    the defect this repo has shipped four times. AR-15 has this guard; this is
    its AR-18 half.
    """
    original = demo.graph
    [found] = _owns(demo, credentials=False, activity_complete=False)

    assert found.check_id == "AR-18"
    assert found.severity == "critical", "unknown scopes are not the read-only case"
    assert "credential read did not complete" in found.detail

    # And with the same absence where the read did finish, the silence means it.
    demo.graph = original  # `_owns` adds to the graph it is handed
    [complete] = _owns(demo, credentials=False, activity_complete=True)
    assert complete.severity == "high"
    assert "did not complete" not in complete.detail


def test_one_leaver_with_two_okta_accounts_owns_their_service_account_once(demo):
    """Keyed on identity, not on leaver, for the reason AR-17 is. Iterate the
    roster pairs instead and one person with two Okta logins produces the same
    service account twice: two rows in findings.csv, two fix tickets, and a
    critical count that double-reports one bot. AR-17's version of this test
    duplicates victor, who owns okta/a05, but it filters to AR-17 and so said
    nothing about this check.
    """
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    victor = next(u for u in raw["users"] if u["profile"]["email"] == "victor.nguyen@acme.example")
    second = json.loads(json.dumps(victor))
    second["id"] = victor["id"] + "-admin"
    second["login"] = "victor.nguyen.admin@acme.example"
    raw["users"].append(second)
    snapshot = Snapshot.from_dict(raw)
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    ctx = ReviewContext(snapshot, demo.roster, demo.config, AS_OF, graph=IdentityGraph.compose(
        project_snapshot(snapshot, demo.config.service_accounts),
        project_github(github, demo.config.service_accounts),
    ))

    subjects = [f.subject for f in run_checks(ctx)[0] if f.check_id == "AR-18"]

    assert "okta/a05" in subjects, "victor owns it; this must not pass on an empty list"
    assert sorted(subjects) == sorted(set(subjects))


def _undeclared_client(demo, read_its_activity):
    """An Okta API client nobody who left ever touched, which is every AWS run's
    ordinary case now the graph is built without a second source."""
    snapshot = copy.deepcopy(demo.snapshot)
    snapshot.apps.append(App(id="a07", label="Datadog Sync", status="ACTIVE", service_client=True,
                             client_id="0oaDATADOG", granted_scopes=["okta.users.manage"]))
    if read_its_activity:
        snapshot.activity_actors = set(snapshot.activity_actors) | {"0oaDATADOG"}
    ctx = ReviewContext(snapshot, demo.roster, demo.config, AS_OF)
    ctx.graph = IdentityGraph.compose(project_snapshot(snapshot, demo.config.service_accounts))
    return next(f for f in run_checks(ctx)[0] if f.check_id == "AR-15" and f.subject == "okta/a07")


def test_an_okta_client_whose_use_nobody_read_is_not_described_as_idle(demo):
    """The collector reads a client's activity only when a leaver held its
    credentials. For the rest, a missing last-used date is "nobody asked", and
    reading it as "no record of use" graded a busy write-capable client as a
    dormant cleanup -- on every Okta-only run, which is every AWS run."""
    found = _undeclared_client(demo, read_its_activity=False)

    assert found.severity == "high"
    assert "use not read" in found.detail and "no record of use" not in found.detail
    # Nor does "no evidence" pass for "nobody looked" on who created it.
    assert "only read for people who have left" in found.detail

    # Where its activity was read and held nothing, that is evidence, and says so.
    idle = _undeclared_client(demo, read_its_activity=True)
    assert idle.severity == "medium" and "no record of use" in idle.detail


def test_a_leaver_with_no_end_date_still_owns_their_service_account(demo):
    """HR shows them terminated and gives no date, which AR-13 already treats as
    a real case. The finding still stands at full severity, and its detail --
    signed into the evidence -- never reads "left None"."""
    demo.roster = {k: replace(e, end_date=None, end_at=None) if k == LEFT else e
                   for k, e in demo.roster.items()}
    [found] = _owns(demo, write_access=True)
    assert found.check_id == "AR-18" and found.severity == "critical"
    assert "Marcus Lee is terminated in HR" in found.detail and "None" not in found.detail
