import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import Config
from access_review.identity import (
    OKTA,
    CredentialKind,
    IdentityGraph,
    LinkMethod,
    PrincipalKind,
    Status,
    project_snapshot,
)
from access_review.identity.github import GitHubSnapshot, Member, project_github, source_name
from access_review.models import Snapshot

FIXTURES = Path(__file__).parent.parent / "fixtures"
GITHUB = source_name("acme-eng")


@pytest.fixture
def github_snapshot():
    return GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))


@pytest.fixture
def graph(github_snapshot):
    return project_github(github_snapshot)


@pytest.fixture
def both(github_snapshot):
    """Okta and GitHub composed, which is the point of the whole layer."""
    okta = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    return IdentityGraph.compose(project_snapshot(okta, config.service_accounts), project_github(github_snapshot))


def labels(principals):
    return {p.label for p in principals}


def github_snapshot_with(**kwargs):
    base = {"org": "acme-eng", "collected_at": datetime(2026, 9, 15, tzinfo=timezone.utc)}
    return GitHubSnapshot(**{**base, **kwargs})


# --- the join ----------------------------------------------------------------


def test_the_saml_identity_is_the_authoritative_join(graph):
    link = graph.link_for((GITHUB, "U_kgDOvictor"))
    assert link.method is LinkMethod.SSO_IDENTITY
    assert link.identity == "victor.nguyen@acme.example"
    assert "SAML external identity" in link.evidence


def test_a_verified_email_joins_when_there_is_no_saml_identity(graph):
    link = graph.link_for((GITHUB, "U_kgDOhannah"))
    assert link.method is LinkMethod.VERIFIED_EMAIL
    assert link.identity == "hannah.ortiz@acme.example"


def test_members_github_states_nothing_about_are_unlinked(graph):
    # A login that resembles an Okta user is not evidence. These two are the
    # headline finding, not an edge case.
    assert labels(graph.unlinked()) == {"dev-contractor-42", "acme-ci-bot"}
    assert graph.principal((GITHUB, "U_kgDOdev42")).kind is PrincipalKind.UNKNOWN
    assert graph.principal((GITHUB, "U_kgDOcibot")).kind is PrincipalKind.UNKNOWN


def test_a_member_the_idp_vouches_for_is_a_person(graph):
    assert graph.principal((GITHUB, "U_kgDOpriya")).kind is PrincipalKind.HUMAN
    assert graph.principal((GITHUB, "U_kgDOhannah")).kind is PrincipalKind.HUMAN


def test_an_org_without_sso_cannot_join_and_says_so():
    member = Member(id="1", login="someone")
    graph = project_github(github_snapshot_with(members=[member], sso_enabled=False))
    assert graph.link_for((GITHUB, "1")) is None
    assert not graph.source(GITHUB).complete
    assert any("not behind SSO" in g for g in graph.source(GITHUB).gaps)
    # Unlinked for want of evidence is not the same as nobody owning it, and
    # the coverage number has to say so.
    assert not graph.coverage().reliable


# --- credentials -------------------------------------------------------------


def test_tokens_and_ssh_keys_become_credentials(graph):
    kinds = {c.kind for c in graph.credentials}
    assert kinds == {CredentialKind.GITHUB_PAT, CredentialKind.SSH_KEY}
    victors = {c.label: c for c in graph.credentials_for((GITHUB, "U_kgDOvictor"))}
    assert set(victors) == {"victor-laptop-deploy", "victor-macbook"}
    assert victors["victor-laptop-deploy"].write_access is True
    assert victors["victor-laptop-deploy"].last_used == datetime(2026, 9, 10, 3, 12, tzinfo=timezone.utc)


def test_a_read_only_token_is_not_write_access(graph):
    [token] = [c for c in graph.credentials if c.id == "PAT_lee_readonly"]
    assert token.write_access is False
    assert token.expires == datetime(2027, 1, 19, 9, 0, tzinfo=timezone.utc)


def test_a_read_only_deploy_key_is_not_write_access(graph):
    [key] = [c for c in graph.credentials if c.id == "KEY_deploy_readonly"]
    assert key.write_access is False


def test_token_scopes_are_unknown_not_empty_when_the_read_failed():
    snapshot = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    snapshot.gaps = ["token scopes could not be read"]
    for token in snapshot.tokens:
        token.scopes = []
    graph = project_github(snapshot)
    assert {c.write_access for c in graph.credentials if c.kind is CredentialKind.GITHUB_PAT} == {None}


def test_a_token_can_outlive_the_account_that_made_it(graph):
    # PAT_ghost's owner is not in the member list at all.
    [orphan] = [c for c in graph.credentials if c.id == "PAT_ghost"]
    assert orphan.holder == "U_kgDOgone"
    assert graph.holder_of(orphan) is None
    assert orphan.write_access is True


# --- grants ------------------------------------------------------------------


def test_org_membership_teams_and_owner_role_are_all_grants(graph):
    priya = {(g.kind.value, g.target_label) for g in graph.grants_for((GITHUB, "U_kgDOpriya"))}
    assert priya == {("org", "acme-eng"), ("role", "Organization owner"), ("team", "Engineering")}
    contractor = {(g.kind.value, g.target_label) for g in graph.grants_for((GITHUB, "U_kgDOdev42"))}
    assert contractor == {("org", "acme-eng"), ("team", "Contractors")}


# --- coverage and composition ------------------------------------------------


def test_coverage_reports_how_much_of_the_org_is_accounted_for(graph):
    coverage = graph.coverage()
    assert coverage.total == 8
    assert coverage.by_method == {"sso_identity": 5, "verified_email": 1, "declared": 0, "creator": 0}
    assert (coverage.unlinked, coverage.contested) == (2, 0)
    assert coverage.reliable


def test_a_leaver_holds_access_in_both_sources(both):
    # The thesis: Okta offboarding deactivated the account, and none of this
    # went with it.
    victor = both.principals_of("victor.nguyen@acme.example")
    assert {p.source for p in victor} == {OKTA, GITHUB}
    assert both.principal((OKTA, "u09")).status is Status.DISABLED

    # One departure, three live credentials across two systems: the OAuth
    # client of the bot he set up in Okta, plus a GitHub token and an SSH key
    # that his Okta deactivation never touched.
    held = sorted((c.label, c.kind.value) for p in victor for c in both.credentials_for(p.key))
    assert held == [
        ("Reporting Bot", "oauth_client"),
        ("victor-laptop-deploy", "github_pat"),
        ("victor-macbook", "ssh_key"),
    ]
    # The two GitHub credentials can both write. The Okta bot cannot, which is
    # the only reason it is not the worst of the three.
    writable = {c.label for p in victor for c in both.credentials_for(p.key) if c.write_access}
    assert writable == {"victor-laptop-deploy", "victor-macbook"}


def test_composed_coverage_spans_both_sources(both):
    coverage = both.coverage()
    assert coverage.total == 13 + 8
    assert coverage.by_method["sso_identity"] == 10 + 5
    assert coverage.by_method["verified_email"] == 1
    assert coverage.unlinked == 1 + 2  # Terraform Automation, and the two GitHub members
    assert coverage.reliable


def test_nothing_joins_two_sources_by_a_similar_login(both):
    # marcus-lee on GitHub and marcus.lee@acme.example in Okta are only one
    # person because GitHub's SAML identity says so, never because the strings
    # look alike.
    marcus = both.principals_of("marcus.lee@acme.example")
    assert {p.label for p in marcus} == {"marcus.lee@acme.example", "marcus-lee"}
    assert both.link_for((GITHUB, "U_kgDOmarcus")).method is LinkMethod.SSO_IDENTITY

    stripped = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    for member in stripped.members:
        member.saml_identity = ""
        member.verified_email = ""
    only_okta = IdentityGraph.compose(
        project_snapshot(Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))),
        project_github(stripped),
    )
    assert only_okta.principals_of("marcus.lee@acme.example") == [only_okta.principal((OKTA, "u02"))]


# --- source metadata ---------------------------------------------------------


def test_source_metadata_travels_with_the_graph(graph, github_snapshot):
    meta = graph.source(GITHUB)
    assert (meta.org, meta.collected_at) == ("acme-eng", github_snapshot.collected_at)
    assert meta.complete
    # GitHub reports last-used per credential for all time, so there is no
    # window to be partial about. activity_complete, not activity_since, is
    # what a dormancy judgement reads.
    assert meta.activity_since is None
    assert meta.activity_complete


def test_the_github_snapshot_round_trips(github_snapshot):
    again = GitHubSnapshot.from_dict(github_snapshot.to_dict())
    assert again == github_snapshot
