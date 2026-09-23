import copy
import json
import re
from collections import defaultdict
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from access_review import checks
from access_review.checks import (
    CHECKS,
    Config,
    STANDS_DOWN_FOR,
    Disposition,
    ReviewContext,
    leaver_accountable_accounts,
    run_checks,
)
from access_review.identity import (
    OKTA,
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
from access_review.items import REVOKE, build_items
from access_review.models import DISABLED_STATUSES, App, Snapshot
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
        # svc-legacy-etl is DEPROVISIONED and still in Sales with Salesforce,
        # which is this check exactly -- and it is not here. Its register owner
        # has left, so AR-18 has the account and this check stands down: the
        # two remediations contradict. AR-18's detail names the groups and apps
        # this line would have listed. See test_no_account_is_told_to_go_and_to_stay.
        "AR-09": {"victor.nguyen"},
        "AR-10": {"Terraform Automation"},
        "AR-11": {"priya.shah", "jordan.kim"},
        # victor held Reporting Bot's secret: custody, rotated not handed over.
        # The bot running after he left is not his activity.
        "AR-12": {"marcus.lee"},
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
        # The service accounts whose only accountable person has left, and the
        # two ways a principal gets one: okta/a04 is declared to marcus.lee in
        # the register, okta/a05 is tied to victor.nguyen by nothing but the
        # System Log's record of who created it. Both are Okta API clients,
        # which is what AR-17 structurally cannot report -- it skips `okta`.
        # okta/u12 is the third shape: an Okta *user* account the register
        # declares, deprovisioned but still holding groups and apps, whose
        # owner left. It is the one AR-09 would otherwise have reported under
        # its login with the opposite remediation.
        "AR-18": {"okta/a04", "okta/a05", "okta/u12"},
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
    "okta/u12": "svc-legacy-etl",
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
        # No role and no credential of its own -- it is an Okta user account,
        # not an API client -- so nothing it holds can write and it grades
        # high. What it *reaches* is deliberately not in the grade: a group
        # everybody is in does not make an account more dangerous, and AR-09
        # never graded on group membership either.
        ("AR-18", "svc-legacy-etl"): "high",
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
                  "ISO 27001 A.5.16", "ISO 27001 A.5.17", "ISO 27001 A.5.18", "ISO 27001 A.8.2"],
    }
    # A.5.11 is wrong everywhere. A.5.17 was wrong on AR-15-17 and stays off
    # them; AR-18 carries it because its fix includes rotating a secret a leaver
    # held, which is the handling of authentication information.
    cited = {control for c in CHECKS for control in c.controls}
    assert "ISO 27001 A.5.11" not in cited
    assert [c.id for c in CHECKS if "ISO 27001 A.5.17" in c.controls] == ["AR-18"]


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


# --- the partition: no account is told to go and to stay -------------------

LEAVER = "marcus.lee@acme.example"
# A leaver's own account, which the worst case also declares in the register.
LEAVERS_OWN = "victor.nguyen@acme.example"
# Every state an owned Okta service account can be bent into that some REMOVE
# check reads: each disabled status for AR-09, and active for AR-14.
WORST_CASE_STATUSES = sorted(DISABLED_STATUSES) + ["ACTIVE"]


def _worst_case(tmp_path, status="DEPROVISIONED"):
    """The demo, bent so that every account a RETAIN check can reach is also an
    account a REMOVE check can reach.

    The guard below is only worth what its fixture plants: run against the demo
    alone it would pass on a review where no two checks happened to overlap,
    which is how this collision reached production three times. So every
    register entry is owned by somebody HR says has left, every Okta account
    the register declares with an owner is put in `status`, and the register
    also declares a leaver's own account, owned by another leaver.

    The REMOVE checks that can reach an owned Okta user account are AR-09 when
    it is disabled and AR-14 when it is active, so `status` runs over both.
    AR-18's other accounts are out of every REMOVE check's reach by
    construction: AR-09 walks `snapshot.users` and cannot see an Okta API
    client, and AR-17 skips `PrincipalKind.SERVICE`. A REMOVE check that walks
    graph principals would add pairs here the moment it is written.

    Bent only as far as Okta can go. A deactivated user keeps its group
    memberships and loses everything else: Okta unassigns it from every app
    ("Okta unassigns the user from all applications, although group memberships
    remain intact") and deprovisions the API tokens it created ("If Okta
    deactivates a user account, Okta simultaneously deprovisions any API token
    created by that user account"). So a deprovisioned account's reach is
    app-via-group, and its factors and admin roles are not read. A suspended
    one keeps its groups too and has its admin roles read (`collect` skips
    them only for DEPROVISIONED). An active one gets the old, unused direct
    assignment AR-14 is about. The one ownerless entry is left ACTIVE and given
    a token, which is what makes AR-15 live here.
    """
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    config = json.loads((FIXTURES / "demo_config.json").read_text())

    entries = []
    for entry in config["service_accounts"]:
        entry = {"id": entry} if isinstance(entry, str) else dict(entry)
        if entry["id"] != "svc-ci@acme.example":  # left declaring nobody
            entry["owner"] = LEAVER
        entries.append(entry)
    declared = {e["id"].lower() for e in entries if not e.get("source", "").startswith("github")}
    owned = {e["id"].lower() for e in entries if e.get("owner")} & declared
    # Declared after `owned` is taken: this account keeps its own planted state.
    entries.append({"id": LEAVERS_OWN, "owner": LEAVER})
    config["service_accounts"] = entries

    sales = next(g for g in raw["groups"] if g["name"] == "Sales")  # reaches Salesforce
    salesforce = next(a for a in raw["apps"] if a["label"] == "Salesforce")
    for user in raw["users"]:
        login = user["login"].lower()
        if login in owned:
            user["status"] = status
            if status == "ACTIVE":
                user["lastLogin"] = "2026-09-14T09:00:00Z"
                user["factors"] = ["push"]
                user["adminRoles"] = []
                salesforce["users"].append(user["id"])
                salesforce["assigned"][user["id"]] = "2022-01-10T09:00:00Z"
            else:
                user["factors"] = None  # not read unless the account can sign in
                user["adminRoles"] = None if status == "DEPROVISIONED" else []
                sales["members"].append(user["id"])
        elif login in declared:  # ownerless, so left live and holding a credential
            raw["api_tokens"].append({
                "id": f"00T{user['id']}", "name": f"tok-{user['id']}", "userId": user["id"],
                "created": "2024-01-01T09:00:00Z", "lastUpdated": "2026-09-14T09:00:00Z",
                "expiresAt": "2026-10-14T09:00:00Z",
            })

    path = tmp_path / "worst_case_config.json"
    path.write_text(json.dumps(config))
    cfg = Config.load(path)
    snapshot = Snapshot.from_dict(raw)
    ctx = ReviewContext(snapshot, load_roster(FIXTURES / "demo_roster.csv", cfg.timezone()), cfg, AS_OF)
    ctx.graph = _compose(ctx, snapshot)
    return ctx


def _account_of(ctx, subject):
    """The account a finding is about, as a graph principal key, or None.

    Checks spell a subject four ways and the guard has to see through all of
    them, because the whole defect is that one account wears two names: AR-09
    reported `svc-legacy-etl@acme.example` while AR-18 reported `okta/u12`, and
    no hashed ticket label could ever have collapsed those. None is a failure,
    not a skip -- a check whose subject shape nobody taught this resolver is a
    check the guard silently stops covering.
    """
    head = subject.split(" / ")[0]  # AR-14's "<login> / <app label>"
    source, _, rest = head.partition("/")  # checks.graph_subject
    if rest and source in {s.source for s in ctx.graph.sources}:
        return (source, rest)
    for user in ctx.snapshot.users:
        if user.login.lower() == head.lower():
            return (OKTA, user.id)
    apps = [a for a in ctx.snapshot.apps if a.label.lower() == head.lower()]
    return (OKTA, apps[0].id) if len(apps) == 1 else None


def _by_account(ctx):
    findings, skipped = run_checks(ctx)
    assert skipped == []
    disposition = {c.id: c.disposition for c in CHECKS}
    out = defaultdict(set)
    for f in findings:
        account = _account_of(ctx, f.subject)
        assert account is not None, f"{f.check_id} subject {f.subject!r} resolves to no account"
        out[account].add((f.check_id, disposition[f.check_id]))
    return out


def test_every_check_says_what_its_remediation_does_to_the_account():
    """The half of the guard that makes a new check declare itself. `Check`
    gives `disposition` no default, so an unclassified check cannot be
    constructed at all; what is written down here is the classification itself,
    because REMOVE and RETAIN are the two that can contradict and a wrong
    NEITHER is how a collision walks past the guard below.

    The subset runs the other way on purpose: every member of the enum is used
    by some check, so a value nobody claims -- one added for a distinction that
    was then dropped -- shows up here rather than sitting in the enum implying
    the axis has a rung it does not.
    """
    assert set(Disposition) <= {c.disposition for c in CHECKS}
    assert {c.id for c in CHECKS if c.disposition is Disposition.RETAIN} == {"AR-18"}
    assert {c.id for c in CHECKS if c.disposition is Disposition.REMOVE} == {
        "AR-01", "AR-02", "AR-07", "AR-09", "AR-12", "AR-13", "AR-14", "AR-17"}


def test_only_a_remove_check_stands_down_and_only_for_a_retain_check():
    """`STANDS_DOWN_FOR` is what history reads to tell a stand-down from a fix,
    and it is written by hand. A pair the other way round, or with a check that
    no longer exists, would bridge streaks and hide reopens for nothing."""
    disposition = {c.id: c.disposition for c in CHECKS}
    for standing_down, holder in STANDS_DOWN_FOR.items():
        assert disposition[standing_down] is Disposition.REMOVE
        assert disposition[holder] is Disposition.RETAIN


def test_the_partition_is_computed_once_per_review(demo, monkeypatch):
    """AR-09, AR-18 and `build_items` all read it, and each computation scans
    the System Log once per leaver. Swapping an input recomputes it, so a stale
    partition cannot outlive the graph it was read from."""
    calls = []
    compute = checks._leaver_accountable_accounts
    monkeypatch.setattr(checks, "_leaver_accountable_accounts", lambda ctx: calls.append(1) or compute(ctx))
    findings, _ = run_checks(demo)
    build_items(demo, findings)
    assert len(calls) == 1
    demo.graph = replace(demo.graph)
    assert leaver_accountable_accounts(demo) and len(calls) == 2


@pytest.mark.parametrize("status", WORST_CASE_STATUSES)
def test_no_account_is_told_to_go_and_to_stay(demo, tmp_path, status):
    """One account, two findings, opposite remediations: the defect this repo
    has now partitioned by hand three times -- AR-17, then AR-12, then AR-09.
    Each was found by a person reading the two remediations side by side, so
    the rule is encoded here instead.

    REMOVE says the access or the account goes; RETAIN says it keeps running
    under somebody new. Both on one account is two tickets telling one assignee
    opposite things, and the REMOVE one closes on a fresh Okta read that only
    the removal satisfies -- so the handover is signed off as done by something
    that asked for the opposite.

    The guard keys on the finding's **subject**, which is what a ticket is
    identified by. A check that demands something about an account it does not
    name as its subject is outside it: that was AR-12's shape, which reported
    "API clients they set up" under the leaver's own login, and it had to be
    removed rather than partitioned. A new check makes the account it acts on
    its subject, or this test cannot see it.
    """
    for ctx in (demo, _worst_case(tmp_path, status)):
        for account, reported in sorted(_by_account(ctx).items()):
            kinds = {d for _, d in reported}
            assert not (Disposition.REMOVE in kinds and Disposition.RETAIN in kinds), \
                f"{account} is both removed and retained by {sorted(c for c, _ in reported)}"


@pytest.mark.parametrize("status", WORST_CASE_STATUSES)
def test_the_worst_case_really_does_put_the_two_checks_on_one_account(tmp_path, status):
    """The guard above is worth nothing if its fixture stopped planting the
    overlap, and a passing assertion would say the same either way. So: every
    account AR-18 takes over is one a REMOVE check would otherwise report --
    AR-09 for its groups when it is disabled, AR-14 for its old, unused direct
    assignment when it is active -- and AR-18 is what reports that access."""
    ctx = _worst_case(tmp_path, status)
    taken = leaver_accountable_accounts(ctx)
    users = {u.id: u for u in ctx.snapshot.users}
    stood_down = [users[pid] for source, pid in taken if source == OKTA and pid in users]
    assert stood_down, "no Okta user account is in the partition at all"
    findings, _ = run_checks(ctx)
    details = {f.subject: f.detail for f in findings if f.check_id == "AR-18"}
    for user in stood_down:
        assert user.status == status
        if status in DISABLED_STATUSES:
            assert ctx.snapshot.groups_for(user.id) and ctx.snapshot.apps_for(user.id)
            # AR-09's list, in AR-09's words: the group, and the app it gives
            # back on reactivation, which for a deactivated account is the
            # whole of what is left.
            groups, apps = _restores(details[f"{OKTA}/{user.id}"])
            assert "Sales" in groups and "Everyone" not in groups
            assert apps == ["Salesforce"]
        else:
            # Exactly AR-14's case, but for the register entry that exempts it.
            [salesforce] = [a for a in ctx.snapshot.apps if a.label == "Salesforce"]
            assert user.id in salesforce.users and salesforce.assigned[user.id].year == 2022
            assert ctx.snapshot.last_app_sign_in(user.id, salesforce.id) is None
            assert ctx.is_service_account(user)
            assert "Salesforce" in _reaches(details[f"{OKTA}/{user.id}"])
    assert not {f.subject for f in findings if f.check_id in {"AR-09", "AR-14"}} & {
        s for u in stood_down for s in (u.login, f"{u.login} / Salesforce")}


def test_a_register_entry_cannot_take_a_leavers_own_account(tmp_path):
    """The register can declare any Okta login, including a person's. Declared
    with an owner who left, a leaver's own account became AR-18's handover:
    AR-09 stood down and the Revoke proposal on its apps became "decide", so a
    register edit moved a human leaver's access from Okta-verified removal to a
    reviewer's say-so. An account HR lists as a person is the leaver checks' to
    report, whatever the register says."""
    ctx = _worst_case(tmp_path)
    victor = next(u for u in ctx.snapshot.users if u.login == LEAVERS_OWN)
    assert ctx.is_service_account(victor) and ctx.roster_entry(victor) is not None
    assert (OKTA, victor.id) not in leaver_accountable_accounts(ctx)
    findings, _ = run_checks(ctx)
    on_victor = {f.check_id for f in findings if f.subject in {LEAVERS_OWN, f"{OKTA}/{victor.id}"}}
    assert "AR-09" in on_victor and "AR-18" not in on_victor
    proposed = {i.target: i.proposed for i in build_items(ctx, findings) if i.user == LEAVERS_OWN}
    assert proposed["Salesforce"] == REVOKE


def test_a_bot_sharing_a_current_employees_email_keeps_its_ar18():
    """The leaver's-own-account exclusion keys on a roster entry that is gone,
    not on any roster match. `entry_for` matches on the profile email, which a
    bot can share with somebody still employed; excluded on that match, the bot
    lost AR-18 and, being active, was reported by no removal check either."""
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    bot = next(u for u in raw["users"] if u["id"] == "u12")
    bot["status"] = "ACTIVE"
    bot["profile"]["email"] = "priya.shah@acme.example"  # active in the roster
    cfg = Config.load(FIXTURES / "demo_config.json")
    snapshot = Snapshot.from_dict(raw)
    ctx = ReviewContext(snapshot, load_roster(FIXTURES / "demo_roster.csv", cfg.timezone()), cfg, AS_OF)
    ctx.graph = _compose(ctx, snapshot)
    user = next(u for u in snapshot.users if u.id == "u12")
    assert ctx.roster_entry(user) is not None and not ctx.roster_entry(user).is_gone(AS_OF)
    findings, _ = run_checks(ctx)
    assert f"{OKTA}/u12" in {f.subject for f in findings if f.check_id == "AR-18"}


def test_the_partition_says_what_state_the_account_is_in(demo):
    """AR-09's whole finding was the status -- "DEPROVISIONED but still has
    groups" -- and the threat it names is reactivation, not use. AR-18 takes
    that account, so if its record does not say the account is deactivated,
    nothing in the review does, while its remediation talks about an account
    that is still being called. AR-17 has reported `source_status` all along."""
    findings, _ = run_checks(demo)
    detail = {f.subject: f.detail for f in findings if f.check_id == "AR-18"}
    assert "(DEPROVISIONED)" in detail["okta/u12"]
    assert "(ACTIVE)" in detail["okta/a04"]
    remediation = next(c.remediation for c in CHECKS if c.id == "AR-18")
    assert "still running" not in remediation  # it is not, for the account above


def _restores(detail):
    """The (groups, apps) of AR-18's "Reactivating it restores ..." sentence."""
    match = re.search(r"Reactivating it restores (.*?)\.(?: |$)", detail)
    assert match, detail
    parts = dict(p.split(": ", 1) for p in match.group(1).split("; "))
    return parts.get("groups", "").split(", "), parts.get("apps", "").split(", ")


def _reaches(detail):
    match = re.search(r"It reaches (.*?)\.(?: |$)", detail)
    assert match, detail
    return match.group(1)


def test_a_taken_over_disabled_account_lists_what_ar09_would_have(demo, monkeypatch):
    """AR-09 stands down for these, so AR-18's sentence is the only place the
    leftover groups and apps are reported. In full, whatever MAX_REACHED_SHOWN
    says, because on the decommission branch it is the list of what to remove;
    without Everyone, which nobody can remove; and as what reactivation
    restores, because Okta has already unassigned a deactivated user from its
    apps and "reaches" would say otherwise."""
    monkeypatch.setattr(checks, "MAX_REACHED_SHOWN", 1)
    detail = {f.subject: f.detail for f in run_checks(demo)[0] if f.check_id == "AR-18"}
    assert "Reactivating it restores groups: Sales; apps: Salesforce." in detail["okta/u12"]
    assert "It reaches" not in detail["okta/u12"]
    assert "Reactivating" not in detail["okta/a04"]  # a live API client


def test_a_live_accounts_reach_is_truncated_and_says_so(tmp_path, monkeypatch):
    """An org-wide group over 250 apps would put 250 labels in a ticket body,
    so a live account's reach is cut -- and says so, or the cut list reads as
    the whole of it."""
    ctx = _worst_case(tmp_path, "ACTIVE")
    [user] = [u for u in ctx.snapshot.users if u.login == "svc-legacy-etl@acme.example"]
    full = _reaches(next(f.detail for f in run_checks(ctx)[0] if f.subject == f"{OKTA}/{user.id}"))
    reach = full.split(", ")
    assert "Salesforce" in reach and len(reach) > 1
    monkeypatch.setattr(checks, "MAX_REACHED_SHOWN", 1)
    cut = _reaches(next(f.detail for f in run_checks(ctx)[0] if f.subject == f"{OKTA}/{user.id}"))
    assert cut == f"{reach[0]} and {len(reach) - 1} more"


def test_a_state_the_source_did_not_word_still_reaches_the_record(demo):
    """AR-18's remediation branches on whether the account is live, so a
    principal the source gave no status word for still says it is disabled."""
    principals = tuple(replace(p, source_status="") if p.key == (OKTA, "u12") else p
                       for p in demo.graph.principals)
    demo.graph = replace(demo.graph, principals=principals)
    detail = {f.subject: f.detail for f in run_checks(demo)[0] if f.check_id == "AR-18"}
    assert detail["okta/u12"].startswith("svc-legacy-etl@acme.example (disabled):")


def test_the_partition_is_inert_without_a_graph(demo):
    """What `handlers.verify_daily` relies on (and
    `test_the_daily_recheck_keeps_an_ar09_ticket_open` checks at the handler):
    with no graph AR-18 does not run and AR-09 stands down for nothing, which is
    also what makes the partition safe on a roster-less run."""
    findings, _ = run_checks(replace(demo, graph=None))
    assert "svc-legacy-etl@acme.example" in {f.subject for f in findings if f.check_id == "AR-09"}
    assert not [f for f in findings if f.check_id == "AR-18"]
    assert not leaver_accountable_accounts(replace(demo, graph=None))
