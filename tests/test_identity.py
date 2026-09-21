import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import Config
from access_review.identity import (
    OKTA,
    Credential,
    CredentialKind,
    Grant,
    GrantKind,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKind,
    SourceMeta,
    Status,
    project_snapshot,
)
from access_review.models import ActivityEvent, ApiToken, App, Group, Snapshot, User

FIXTURES = Path(__file__).parent.parent / "fixtures"
NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


@pytest.fixture
def demo_snapshot():
    return Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))


@pytest.fixture
def graph(demo_snapshot):
    config = Config.load(FIXTURES / "demo_config.json")
    return project_snapshot(demo_snapshot, config.service_accounts)


def labels(principals):
    return {p.label for p in principals}


def snapshot(**kwargs):
    base = {"org_url": "https://x.example", "collected_at": NOW, "users": [], "groups": [], "apps": []}
    return Snapshot(**{**base, **kwargs})


def person(user_id, login, status="ACTIVE", email=None, **kwargs):
    profile = {"email": login if email is None else email}
    return User(id=user_id, login=login, status=status, profile={k: v for k, v in profile.items() if v}, **kwargs)


def service_client(app_id="a99", label="Bot", status="ACTIVE", client_id="0oaBOT", **kwargs):
    return App(id=app_id, label=label, status=status, service_client=True, client_id=client_id, **kwargs)


# --- projection basics -------------------------------------------------------


def test_every_user_and_service_client_becomes_a_principal(graph, demo_snapshot):
    assert len(graph.principals) == len(demo_snapshot.users) + 2
    assert labels(graph.principals) >= {"marcus.lee@acme.example", "Terraform Automation", "Reporting Bot"}
    assert {p.source for p in graph.principals} == {OKTA}


def test_okta_users_are_linked_by_their_sso_identity(graph):
    link = graph.link_for((OKTA, "u02"))
    assert link.method is LinkMethod.SSO_IDENTITY
    assert link.identity == "marcus.lee@acme.example"
    assert "marcus.lee" in link.evidence


def test_the_identity_key_is_the_profile_email_never_the_login_fallback():
    # User.email falls back to the login. Keying on that merges two accounts
    # whenever one person's login is another person's email address.
    no_profile_email = User(id="u1", login="shared@acme.example", status="ACTIVE", profile={})
    other = person("u2", "real.login@acme.example", email="shared@acme.example")
    graph = project_snapshot(snapshot(users=[no_profile_email, other]))
    assert graph.link_for((OKTA, "u1")) is None
    assert labels(graph.unlinked()) == {"shared@acme.example"}
    assert [i.key for i in graph.identities()] == ["shared@acme.example"]
    assert [p.id for p in graph.principals_of("shared@acme.example")] == ["u2"]


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


def test_principal_timestamps_come_from_okta(graph, demo_snapshot):
    marcus = graph.principal((OKTA, "u02"))
    source = next(u for u in demo_snapshot.users if u.id == "u02")
    assert (marcus.created, marcus.last_used) == (source.created, source.last_login)


# --- status ------------------------------------------------------------------


def test_status_is_normalised_but_okta_s_own_word_is_kept(graph):
    assert (graph.principal((OKTA, "u11")).status, graph.principal((OKTA, "u11")).source_status) == (
        Status.DISABLED,
        "SUSPENDED",
    )
    assert graph.principal((OKTA, "u07")).status is Status.ACTIVE  # PROVISIONED
    assert graph.principal((OKTA, "u01")).status is Status.ACTIVE


def test_an_unrecognised_user_status_is_unknown_not_guessed():
    graph = project_snapshot(snapshot(users=[person("u1", "x@acme.example", status="SOMETHING_NEW")]))
    principal = graph.principal((OKTA, "u1"))
    assert (principal.status, principal.source_status) == (Status.UNKNOWN, "SOMETHING_NEW")


@pytest.mark.parametrize(
    "okta_status,expected",
    [("ACTIVE", Status.ACTIVE), ("INACTIVE", Status.DISABLED), ("", Status.UNKNOWN), ("NEW", Status.UNKNOWN)],
)
def test_service_client_status_has_an_unknown_branch_like_users_do(okta_status, expected):
    # Reading an unread status as "disabled" would retire a client on paper
    # while its OAuth credentials keep working.
    graph = project_snapshot(snapshot(apps=[service_client(status=okta_status)]))
    principal = graph.principal((OKTA, "a99"))
    assert (principal.status, principal.source_status) == (expected, okta_status)


# --- write access ------------------------------------------------------------


def test_write_access_is_true_from_an_admin_role_alone():
    app = service_client(granted_scopes=["okta.users.read"], admin_roles=["Super Administrator"])
    [client] = project_snapshot(snapshot(apps=[app])).credentials
    assert client.write_access is True


def test_write_access_is_true_from_a_scope_alone():
    app = service_client(granted_scopes=["okta.users.manage"], admin_roles=["Read-Only Administrator"])
    [client] = project_snapshot(snapshot(apps=[app])).credentials
    assert client.write_access is True


def test_write_access_is_false_only_when_the_whole_read_completed():
    app = service_client(granted_scopes=["okta.users.read"], admin_roles=["Read-Only Administrator"])
    [client] = project_snapshot(snapshot(apps=[app])).credentials
    assert client.write_access is False


def test_write_access_is_unknown_when_a_read_failed():
    # Scopes and admin roles are two independent optional reads in collect.py.
    # An empty list is only evidence of "nothing granted" when nothing failed.
    app = service_client(granted_scopes=[], admin_roles=["Read-Only Administrator"])
    incomplete = snapshot(apps=[app], gaps=["app API scope grants could not be read"])
    [client] = project_snapshot(incomplete).credentials
    assert client.write_access is None


# --- credentials -------------------------------------------------------------


def test_credentials_carry_holder_and_timestamps(graph, demo_snapshot):
    [token] = [c for c in graph.credentials if c.kind is CredentialKind.OKTA_API_TOKEN]
    source = demo_snapshot.api_tokens[0]
    assert (token.label, token.holder) == ("ci-deploy", "u02")
    assert (token.created, token.last_used, token.expires) == (source.created, source.last_updated, source.expires)
    assert graph.holder_of(token).label == "marcus.lee@acme.example"

    clients = {c.label: c for c in graph.credentials if c.kind is CredentialKind.OAUTH_CLIENT}
    assert clients["Terraform Automation"].write_access is True  # okta.users.manage
    assert clients["Reporting Bot"].write_access is False  # read scope, read-only admin role
    assert clients["Reporting Bot"].last_used == datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc)


def test_a_credential_can_outlive_its_holder():
    graph = project_snapshot(snapshot(api_tokens=[ApiToken(id="00Tgone", name="old-ci", user_id="u99")]))
    [held] = graph.credentials
    assert held.holder == "u99"
    assert graph.holder_of(held) is None


def test_a_credential_resolves_only_within_its_own_source():
    okta_graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)], principals=[Principal(source=OKTA, id="1", label="okta-one")]
    )
    github = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="1", label="gh-one")],
        credentials=[Credential(source="github:acme", id="pat_1", kind=CredentialKind.GITHUB_PAT, holder="1")],
    )
    both = IdentityGraph.compose(okta_graph, github)
    [pat] = both.credentials
    assert both.holder_of(pat).label == "gh-one"
    assert both.credentials_for((OKTA, "1")) == []


def test_credentials_for_is_scoped_to_the_holder(graph):
    assert [c.label for c in graph.credentials_for((OKTA, "u02"))] == ["ci-deploy"]
    assert graph.credentials_for((OKTA, "u01")) == []


# --- creator provenance ------------------------------------------------------


def test_api_client_creator_comes_from_the_system_log(graph):
    link = graph.link_for((OKTA, "a05"))  # Reporting Bot
    assert link.method is LinkMethod.CREATOR
    assert link.identity == "victor.nguyen@acme.example"
    assert link.evidence == "app.oauth2.credentials.lifecycle.create by victor.nguyen@acme.example on 2026-05-04"


def test_creator_who_left_still_holds_the_client_in_their_identity(graph):
    # The whole thesis: victor left, and the bot he set up is part of what his
    # departure leaves behind.
    held = {p.label for p in graph.principals_of("victor.nguyen@acme.example")}
    assert held == {"victor.nguyen@acme.example", "Reporting Bot"}
    assert graph.principal((OKTA, "u09")).status is Status.DISABLED


def test_the_earliest_credential_event_names_the_creator():
    def event(actor, day):
        return ActivityEvent(
            published=datetime(2026, 5, day, tzinfo=timezone.utc),
            event_type="app.oauth2.client.lifecycle.create",
            actor_id=actor,
            targets=[{"id": "0oaBOT"}],
        )

    users = [person("u1", "first@acme.example"), person("u2", "later@acme.example")]
    # Later event listed first, so list order cannot be doing the work.
    graph = project_snapshot(snapshot(users=users, apps=[service_client()], events=[event("u2", 9), event("u1", 4)]))
    link = graph.link_for((OKTA, "a99"))
    assert (link.method, link.identity) == (LinkMethod.CREATOR, "first@acme.example")


def test_a_client_created_by_someone_no_longer_in_okta_is_unlinked():
    event = ActivityEvent(
        published=datetime(2026, 5, 4, tzinfo=timezone.utc),
        event_type="app.oauth2.client.lifecycle.create",
        actor_id="u_gone",
        targets=[{"id": "0oaBOT"}],
    )
    graph = project_snapshot(snapshot(apps=[service_client()], events=[event]))
    assert graph.link_for((OKTA, "a99")) is None
    assert labels(graph.unlinked()) == {"Bot"}


def test_api_client_nobody_set_up_in_the_log_is_unlinked(graph):
    assert labels(graph.unlinked()) == {"Terraform Automation"}


# --- grants ------------------------------------------------------------------


def test_grants_record_group_app_and_role_access(graph):
    grants = graph.grants_for((OKTA, "u09"))  # victor: Everyone, Finance, Salesforce direct
    assert {(g.kind.value, g.target_label, g.via) for g in grants} == {
        ("group", "Everyone", "direct"),
        ("group", "Finance", "direct"),
        ("app", "Salesforce", "direct"),
    }
    priya = {(g.kind.value, g.target_label, g.via) for g in graph.grants_for((OKTA, "u01"))}
    assert ("app", "GitHub", "group:Engineering") in priya
    assert ("role", "Super Administrator", "direct") in priya


def test_every_way_a_user_reaches_an_app_is_its_own_grant():
    user = person("u1", "a@acme.example")
    groups = [Group(id="g1", name="Eng", type="OKTA_GROUP", members={"u1"})]
    app = App(id="a1", label="GitHub", status="ACTIVE", users={"u1"}, groups={"g1"})
    grants = project_snapshot(snapshot(users=[user], groups=groups, apps=[app])).grants_for((OKTA, "u1"))
    assert sorted(g.via for g in grants if g.kind.value == "app") == ["direct", "group:Eng"]


def test_two_distinct_groups_with_the_same_name_keep_both_access_paths():
    # Okta group names are not unique. Collapsing on the name would delete a
    # live path to the app and under-report who can reach it.
    groups = [
        Group(id="g1", name="Eng", type="OKTA_GROUP", members={"u1"}),
        Group(id="g2", name="Eng", type="OKTA_GROUP", members={"u1"}),
    ]
    app = App(id="a1", label="GitHub", status="ACTIVE", groups={"g1", "g2"})
    grants = project_snapshot(snapshot(users=[person("u1", "a@acme.example")], groups=groups, apps=[app]))
    rows = [(g.kind.value, g.target, g.via) for g in grants.grants_for((OKTA, "u1"))]
    assert rows.count(("app", "a1", "group:Eng")) == 2


def test_access_held_by_an_account_the_user_read_missed_is_not_invisible():
    # A capped or filtered user read leaves group members with no principal.
    # Left bare that is access held by nobody: uncounted, and unfindable.
    groups = [Group(id="g1", name="Eng", type="OKTA_GROUP", members={"u_missing"})]
    graph = project_snapshot(snapshot(groups=groups))
    ghost = graph.principal((OKTA, "u_missing"))
    assert (ghost.kind, ghost.status) == (PrincipalKind.UNKNOWN, Status.UNKNOWN)
    assert ghost.source_status == ""  # the projection does not invent a status word
    assert ghost in graph.unlinked()
    assert graph.coverage().unlinked == 1
    assert any("not returned by the user read" in g for g in graph.source(OKTA).gaps)
    assert not graph.source(OKTA).complete


def test_an_app_assigned_to_an_uncollected_group_records_a_gap():
    app = App(id="a1", label="Salesforce", status="ACTIVE", groups={"g_missing"})
    graph = project_snapshot(snapshot(users=[person("u1", "a@acme.example")], apps=[app]))
    assert any("g_missing" in g for g in graph.source(OKTA).gaps)
    assert not graph.source(OKTA).complete


# --- linking rules -----------------------------------------------------------


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
    assert [i.key for i in graph.identities()] == ["amy@acme.example"]
    assert graph.coverage().by_method["sso_identity"] == 1


def test_two_equally_strong_links_naming_different_people_leave_it_unlinked():
    # A coin flip between adapters is the false link the module exists to
    # prevent. Contested is worse than unlinked, not better.
    key = ("github:acme", "7")
    graph = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="7", label="ambiguous")],
        links=[
            Link(key, LinkMethod.VERIFIED_EMAIL, "amy@acme.example", "one adapter"),
            Link(key, LinkMethod.VERIFIED_EMAIL, "bob@acme.example", "another adapter"),
        ],
    )
    assert graph.link_for(key) is None
    assert labels(graph.contested()) == {"ambiguous"}
    assert labels(graph.unlinked()) == {"ambiguous"}
    assert graph.identities() == []
    coverage = graph.coverage()
    assert (coverage.unlinked, coverage.contested, coverage.by_method["verified_email"]) == (1, 1, 0)


def test_a_stronger_link_resolves_a_contested_principal():
    key = ("github:acme", "7")
    graph = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="7", label="resolved")],
        links=[
            Link(key, LinkMethod.VERIFIED_EMAIL, "amy@acme.example", "one adapter"),
            Link(key, LinkMethod.VERIFIED_EMAIL, "bob@acme.example", "another adapter"),
            Link(key, LinkMethod.SSO_IDENTITY, "carol@acme.example", "the IdP"),
        ],
    )
    assert graph.link_for(key).identity == "carol@acme.example"
    assert graph.contested() == []


def test_nobody_owns_every_unowned_service_account(graph):
    # Declared-with-no-owner links carry an empty identity. The empty string is
    # not a person who holds all of them.
    assert graph.principals_of("") == []


def test_nothing_is_linked_by_name_similarity():
    okta = project_snapshot(snapshot(users=[person("u1", "marcus.lee@acme.example")]))
    github = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="7", label="marcus-lee", kind=PrincipalKind.HUMAN)],
    )
    both = IdentityGraph.compose(okta, github)
    assert labels(both.unlinked()) == {"marcus-lee"}


# --- counting integrity ------------------------------------------------------


def test_coverage_counts_every_principal_once(graph):
    coverage = graph.coverage()
    assert coverage.total == len(graph.principals)
    assert coverage.by_method == {"sso_identity": 10, "verified_email": 0, "declared": 1, "creator": 1}
    assert (coverage.unlinked, coverage.contested) == (1, 0)
    assert coverage.reliable


def test_a_link_to_a_principal_that_is_not_here_cannot_bend_the_count():
    # Arithmetic over two differently-keyed collections used to report -1.
    graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)],
        principals=[Principal(source=OKTA, id="u1", label="real", kind=PrincipalKind.HUMAN)],
        links=[
            Link((OKTA, "u1"), LinkMethod.SSO_IDENTITY, "real@x.example", "ok"),
            Link((OKTA, "GHOST"), LinkMethod.SSO_IDENTITY, "ghost@x.example", "dangling"),
        ],
    )
    coverage = graph.coverage()
    assert (coverage.total, coverage.unlinked) == (1, 0)
    assert coverage.unlinked == len(graph.unlinked())
    assert coverage.by_method["sso_identity"] == 1


def test_a_duplicate_principal_is_rejected_not_silently_collapsed():
    with pytest.raises(ValueError, match="appears twice"):
        IdentityGraph(
            sources=[SourceMeta(source=OKTA)],
            principals=[
                Principal(source=OKTA, id="u1", label="first"),
                Principal(source=OKTA, id="u1", label="second"),
            ],
        )


def test_the_graph_cannot_be_mutated_out_of_step_with_its_indexes(graph):
    with pytest.raises(Exception):
        graph.principals = ()
    assert isinstance(graph.principals, tuple)


def test_coverage_from_an_incomplete_source_is_a_lower_bound(demo_snapshot):
    demo_snapshot.gaps = ["Okta API tokens could not be read."]
    coverage = project_snapshot(demo_snapshot).coverage()
    assert not coverage.reliable
    assert coverage.incomplete_sources == [OKTA]


# --- source metadata ---------------------------------------------------------


def test_source_metadata_travels_with_the_graph(graph, demo_snapshot):
    meta = graph.source(OKTA)
    assert meta.org == demo_snapshot.org_url
    assert meta.collected_at == demo_snapshot.collected_at
    assert meta.complete
    assert meta.activity_since == demo_snapshot.activity_since
    assert meta.activity_complete


def test_a_truncated_or_absent_activity_read_travels_as_incomplete(demo_snapshot):
    demo_snapshot.app_usage_complete = False
    assert not project_snapshot(demo_snapshot).source(OKTA).activity_complete

    demo_snapshot.app_usage_complete = True
    demo_snapshot.activity_since = None  # the System Log was never read
    assert not project_snapshot(demo_snapshot).source(OKTA).activity_complete


# --- composition -------------------------------------------------------------


def test_sources_compose_and_a_source_cannot_be_read_twice(graph):
    other = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="github:acme", id="1", label="mlee", email="marcus.lee@acme.example")],
        links=[Link(("github:acme", "1"), LinkMethod.VERIFIED_EMAIL, "marcus.lee@acme.example", "SAML identity")],
    )
    both = IdentityGraph.compose(graph, other)
    assert both.coverage().total == len(graph.principals) + 1
    marcus = next(i for i in both.identities() if i.key == "marcus.lee@acme.example")
    assert {p[0] for p in marcus.principals} == {OKTA, "github:acme"}

    with pytest.raises(ValueError, match="more than one graph"):
        IdentityGraph.compose(graph, graph)


def test_a_graph_cannot_smuggle_in_a_source_it_does_not_declare(graph):
    undeclared = IdentityGraph(
        sources=[SourceMeta(source="github:acme")],
        principals=[Principal(source="aws:prod", id="AIDA1", label="ci-user")],
    )
    with pytest.raises(ValueError, match="does not declare"):
        IdentityGraph.compose(graph, undeclared)


# --- serialisation -----------------------------------------------------------


def test_the_graph_serialises_for_an_evidence_bundle(graph):
    blob = graph.to_dict()
    assert set(blob) == {"sources", "principals", "credentials", "grants", "links"}
    assert len(blob["principals"]) == len(graph.principals)
    assert json.dumps(blob)  # no enum or datetime leaks through
    marcus = next(p for p in blob["principals"] if p["id"] == "u02")
    assert (marcus["kind"], marcus["status"]) == ("human", "active")


def test_coverage_serialises_counts_only(graph):
    # This is the shape that may cross a Step Functions boundary or reach a
    # Slack channel, where CLAUDE.md forbids personal data.
    blob = graph.coverage().to_dict()
    assert set(blob) == {"total", "by_method", "unlinked", "contested", "incomplete_sources", "reliable"}
    assert "@" not in json.dumps(blob)


def test_a_creator_with_no_profile_email_does_not_key_an_identity_on_their_login():
    event = ActivityEvent(
        published=datetime(2026, 5, 4, tzinfo=timezone.utc),
        event_type="app.oauth2.client.lifecycle.create",
        actor_id="u9",
        targets=[{"id": "0oaBOT"}],
    )
    creator = User(id="u9", login="admin.login", status="ACTIVE", profile={})
    graph = project_snapshot(snapshot(users=[creator], apps=[service_client()], events=[event]))
    assert graph.link_for((OKTA, "a99")) is None
    assert graph.principals_of("admin.login") == []


def test_the_identity_key_is_normalised_so_other_sources_can_join_on_it():
    user = User(id="u1", login="marcus.lee", status="ACTIVE", profile={"email": "  Marcus.Lee@Acme.Example "})
    graph = project_snapshot(snapshot(users=[user]))
    assert graph.link_for((OKTA, "u1")).identity == "marcus.lee@acme.example"
    assert graph.principal((OKTA, "u1")).email == "marcus.lee@acme.example"
    assert [p.id for p in graph.principals_of("marcus.lee@acme.example")] == ["u1"]


def test_principal_email_never_falls_back_to_the_login():
    # User.email falls back to the login; a field named email that holds a
    # login is the join bug this layer exists to avoid.
    user = User(id="u1", login="no-email-login", status="ACTIVE", profile={})
    assert project_snapshot(snapshot(users=[user])).principal((OKTA, "u1")).email == ""


def test_evidenced_write_access_survives_an_incomplete_read():
    app = service_client(granted_scopes=["okta.users.manage"])
    incomplete = snapshot(apps=[app], gaps=["Okta API tokens could not be read"])
    [client] = project_snapshot(incomplete).credentials
    assert client.write_access is True


def test_the_lookup_lists_cannot_be_used_to_mutate_the_graph(graph):
    key = (OKTA, "u09")
    before = len(graph.grants_for(key))
    graph.grants_for(key).append(Grant(OKTA, "u09", GrantKind.APP, "fake", "Fake"))
    assert len(graph.grants_for(key)) == before
    graph.credentials_for((OKTA, "u02")).clear()
    assert [c.label for c in graph.credentials_for((OKTA, "u02"))] == ["ci-deploy"]


def test_a_contested_link_to_a_principal_that_is_not_here_cannot_bend_the_count():
    # contested was counted off the raw link set while every other number was
    # filtered to principals actually in the graph.
    ghost = ("okta", "GHOST")
    graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)],
        principals=[Principal(source=OKTA, id="u1", label="real", kind=PrincipalKind.HUMAN)],
        links=[
            Link(ghost, LinkMethod.VERIFIED_EMAIL, "a@x.example", "one"),
            Link(ghost, LinkMethod.VERIFIED_EMAIL, "b@x.example", "two"),
        ],
    )
    coverage = graph.coverage()
    assert coverage.contested == len(graph.contested()) == 0
    assert (coverage.total, coverage.unlinked) == (1, 1)


def test_every_record_serialises_its_own_fields(graph):
    # from_dict is gone, so nothing round-trips these any more.
    blob = graph.to_dict()
    link = next(x for x in blob["links"] if x["principal"] == "a05")
    assert set(link) == {"source", "principal", "method", "identity", "evidence"}
    assert link["evidence"].startswith("app.oauth2.credentials.lifecycle.create by")
    github = next(g for g in blob["grants"] if g["principal"] == "u01" and g["target"] == "a01")
    assert github["via"] == "group:Engineering"
    terraform = next(c for c in blob["credentials"] if c["label"] == "Terraform Automation")
    assert (terraform["write_access"], terraform["kind"]) == (True, "oauth_client")
    assert set(blob["sources"][0]) == {
        "source", "org", "collected_at", "gaps", "activity_since", "activity_complete",
    }
