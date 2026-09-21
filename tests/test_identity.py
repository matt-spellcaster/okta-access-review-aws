import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import Config
from access_review.identity import (
    OKTA,
    Credential,
    CredentialKind,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKind,
    SourceMeta,
    Status,
    project_snapshot,
)
from access_review.models import ApiToken, App, Group, Snapshot, User

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def demo_snapshot():
    return Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))


@pytest.fixture
def graph(demo_snapshot):
    config = Config.load(FIXTURES / "demo_config.json")
    return project_snapshot(demo_snapshot, config.service_accounts)


def labels(principals):
    return {p.label for p in principals}


def test_every_user_and_service_client_becomes_a_principal(graph, demo_snapshot):
    assert len(graph.principals) == len(demo_snapshot.users) + 2
    assert labels(graph.principals) >= {"marcus.lee@acme.example", "Terraform Automation", "Reporting Bot"}
    assert {p.source for p in graph.principals} == {OKTA}


def test_okta_users_are_linked_by_their_sso_identity(graph):
    link = graph.link_for((OKTA, "u02"))
    assert link.method is LinkMethod.SSO_IDENTITY
    assert link.identity == "marcus.lee@acme.example"
    assert "marcus.lee" in link.evidence


def test_declared_service_account_is_declared_not_a_person(graph):
    svc = graph.principal((OKTA, "u10"))
    assert svc.kind is PrincipalKind.SERVICE
    link = graph.link_for((OKTA, "u10"))
    assert link.method is LinkMethod.DECLARED
    # Declared, but the flat config list names no owner, so it is attributed to
    # nobody: the register that fixes this is a later step.
    assert link.identity == ""
    assert not any(i.key == "svc-ci@acme.example" for i in graph.identities())


def test_undeclared_accounts_are_people_not_guessed_service_accounts(graph):
    # jordan.kim has no HR record (AR-03 flags that). Reading the login as a
    # service account here would hide the finding.
    assert graph.principal((OKTA, "u04")).kind is PrincipalKind.HUMAN


def test_api_client_creator_comes_from_the_system_log(graph):
    link = graph.link_for((OKTA, "a05"))  # Reporting Bot
    assert link.method is LinkMethod.CREATOR
    assert link.identity == "victor.nguyen@acme.example"
    assert "app.oauth2.credentials.lifecycle.create by victor.nguyen@acme.example on 2026-05-04" == link.evidence


def test_creator_who_left_still_holds_the_client_in_their_identity(graph):
    # The whole thesis: victor left, and the bot he set up is part of what his
    # departure leaves behind.
    held = {p.label for p in graph.principals_of("victor.nguyen@acme.example")}
    assert held == {"victor.nguyen@acme.example", "Reporting Bot"}
    assert graph.principal((OKTA, "u09")).status is Status.DISABLED


def test_api_client_nobody_set_up_in_the_log_is_unlinked(graph):
    assert labels(graph.unlinked()) == {"Terraform Automation"}


def test_status_is_normalised_but_okta_s_own_word_is_kept(graph):
    assert (graph.principal((OKTA, "u11")).status, graph.principal((OKTA, "u11")).source_status) == (
        Status.DISABLED,
        "SUSPENDED",
    )
    assert graph.principal((OKTA, "u07")).status is Status.ACTIVE  # PROVISIONED
    assert graph.principal((OKTA, "u01")).status is Status.ACTIVE


def test_credentials_carry_holder_and_write_access(graph):
    [token] = [c for c in graph.credentials if c.kind is CredentialKind.OKTA_API_TOKEN]
    assert (token.label, token.holder) == ("ci-deploy", "u02")
    assert graph.holder_of(token).label == "marcus.lee@acme.example"

    clients = {c.label: c for c in graph.credentials if c.kind is CredentialKind.OAUTH_CLIENT}
    assert clients["Terraform Automation"].write_access is True  # okta.users.manage
    assert clients["Reporting Bot"].write_access is False  # read scope, read-only admin role
    assert clients["Reporting Bot"].last_used == datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc)


def test_write_access_is_unknown_when_nothing_was_read():
    app = App(id="a99", label="Unread Bot", status="ACTIVE", service_client=True, client_id="0oaUNREAD")
    snapshot = Snapshot(
        org_url="https://x.example", collected_at=datetime.now(timezone.utc), users=[], groups=[], apps=[app]
    )
    [client] = project_snapshot(snapshot).credentials
    assert client.write_access is None


def test_a_credential_can_outlive_its_holder():
    token = ApiToken(id="00Tgone", name="old-ci", user_id="u99")
    snapshot = Snapshot(
        org_url="https://x.example",
        collected_at=datetime.now(timezone.utc),
        users=[],
        groups=[],
        apps=[],
        api_tokens=[token],
    )
    graph = project_snapshot(snapshot)
    [held] = graph.credentials
    assert held.holder == "u99"
    assert graph.holder_of(held) is None


def test_grants_record_group_app_and_role_access(graph):
    grants = graph.grants_for((OKTA, "u09"))  # victor: Everyone, Finance, Salesforce direct
    assert {(g.kind.value, g.target_label, g.via) for g in grants} == {
        ("group", "Everyone", "direct"),
        ("group", "Finance", "direct"),
        ("app", "Salesforce", "direct"),
    }
    # priya reaches GitHub because she is in Engineering, and the grant says so.
    priya = graph.grants_for((OKTA, "u01"))
    assert ("app", "GitHub", "group:Engineering") in {(g.kind.value, g.target_label, g.via) for g in priya}
    assert ("role", "Super Administrator", "direct") in {(g.kind.value, g.target_label, g.via) for g in priya}


def test_coverage_counts_every_principal_once(graph):
    coverage = graph.coverage()
    assert coverage.total == len(graph.principals)
    assert coverage.by_method == {
        "sso_identity": 10,
        "verified_email": 0,
        "declared": 1,
        "creator": 1,
    }
    assert coverage.unlinked == 1
    assert coverage.reliable
    assert coverage.summary() == "13 principals: 10 SSO-linked, 1 declared, 1 creator-traced, 1 unlinked"


def test_coverage_from_an_incomplete_source_is_a_lower_bound(demo_snapshot):
    demo_snapshot.gaps = ["Okta API tokens could not be read."]
    coverage = project_snapshot(demo_snapshot).coverage()
    assert not coverage.reliable
    assert coverage.incomplete_sources == [OKTA]
    assert "incomplete: okta" in coverage.summary()


def test_source_metadata_travels_with_the_graph(graph, demo_snapshot):
    meta = graph.source(OKTA)
    assert meta.org == demo_snapshot.org_url
    assert meta.collected_at == demo_snapshot.collected_at
    assert meta.complete
    assert meta.activity_since == demo_snapshot.activity_since


def test_the_strongest_link_wins_and_a_principal_belongs_to_one_person():
    key = (OKTA, "a05")
    graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)],
        principals=[Principal(source=OKTA, id="a05", label="Reporting Bot", kind=PrincipalKind.SERVICE)],
        links=[
            Link(key, LinkMethod.CREATOR, "victor@acme.example", "set up by victor"),
            Link(key, LinkMethod.SSO_IDENTITY, "amy@acme.example", "SCIM external identity"),
        ],
    )
    assert graph.link_for(key).identity == "amy@acme.example"
    assert [x.method for x in graph.links_for(key)] == [LinkMethod.SSO_IDENTITY, LinkMethod.CREATOR]
    assert [i.key for i in graph.identities()] == ["amy@acme.example"]
    assert graph.coverage().by_method["sso_identity"] == 1


def test_sources_compose_and_a_source_cannot_be_read_twice(graph):
    other = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="1", label="mlee", email="marcus.lee@acme.example")],
        credentials=[Credential(source="github:acme", id="pat_1", kind=CredentialKind.GITHUB_PAT, holder="1")],
        links=[Link(("github:acme", "1"), LinkMethod.VERIFIED_EMAIL, "marcus.lee@acme.example", "SAML identity")],
    )
    both = IdentityGraph.compose(graph, other)
    assert both.coverage().total == len(graph.principals) + 1
    marcus = next(i for i in both.identities() if i.key == "marcus.lee@acme.example")
    assert {p[0] for p in marcus.principals} == {OKTA, "github:acme"}

    with pytest.raises(ValueError, match="more than one graph"):
        IdentityGraph.compose(graph, graph)


def test_graph_round_trips_through_json(graph):
    restored = IdentityGraph.from_dict(json.loads(json.dumps(graph.to_dict())))
    assert restored == graph
    assert restored.coverage() == graph.coverage()


def test_nothing_is_linked_by_name_similarity():
    # A GitHub member whose login looks like an Okta user is not that user.
    okta = project_snapshot(
        Snapshot(
            org_url="https://x.example",
            collected_at=datetime.now(timezone.utc),
            users=[User(id="u1", login="marcus.lee@acme.example", status="ACTIVE")],
            groups=[Group(id="g1", name="Everyone", type="BUILT_IN", members={"u1"})],
            apps=[],
        )
    )
    github = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="7", label="marcus-lee", kind=PrincipalKind.HUMAN)],
    )
    both = IdentityGraph.compose(okta, github)
    assert labels(both.unlinked()) == {"marcus-lee"}
