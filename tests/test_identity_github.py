import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import Config
from access_review.identity import (
    OKTA,
    CredentialKind,
    GitHubSnapshot,
    IdentityGraph,
    LinkMethod,
    PrincipalKind,
    Status,
    project_github,
    project_snapshot,
)
from access_review.identity.github import Member, SamlIdentity, source_name
from access_review.models import Snapshot
from access_review.register import Register

FIXTURES = Path(__file__).parent.parent / "fixtures"
GITHUB = "github:acme-eng"
NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


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


def gaps_mentioning(graph, text):
    return [g for g in graph.source(GITHUB).gaps if text in g]


# --- the source name ---------------------------------------------------------


def test_the_source_is_named_per_org():
    assert source_name("acme-eng") == "github:acme-eng"


def test_two_orgs_with_a_colliding_member_id_stay_two_principals():
    def org(name, login):
        return project_github(GitHubSnapshot(org=name, collected_at=NOW, members=[Member(id="U_1", login=login)]))

    composed = IdentityGraph.compose(org("acme-eng", "a"), org("acme-labs", "b"))
    assert composed.coverage().total == 2
    assert composed.principal(("github:acme-eng", "U_1")).label == "a"
    assert composed.principal(("github:acme-labs", "U_1")).label == "b"


# --- the join ----------------------------------------------------------------


def test_a_saml_identity_that_is_an_address_is_the_authoritative_join(graph):
    link = graph.link_for((GITHUB, "U_kgDOBq1aXw"))  # priya
    assert (link.method, link.identity) == (LinkMethod.SSO_IDENTITY, "priya.shah@acme.example")
    assert "SAML emails" in link.evidence


def test_an_opaque_name_id_falls_through_to_an_attribute_that_is_an_address(graph):
    # victor's NameID is a persistent GUID. The username attribute is the
    # address, and that is what the join uses.
    link = graph.link_for((GITHUB, "U_kgDOBq1cZy"))
    assert (link.method, link.identity) == (LinkMethod.SSO_IDENTITY, "victor.nguyen@acme.example")
    assert "SAML emails" in link.evidence


def test_a_saml_identity_with_no_address_anywhere_cannot_be_joined(graph):
    # nina's NameID and username are both GUIDs. A GUID identifies her
    # perfectly well and is still useless against an email-keyed identity.
    assert graph.link_for((GITHUB, "U_kgDOBq1if4")) is None
    assert gaps_mentioning(graph, "no attribute this review can join on")
    assert graph.principal((GITHUB, "U_kgDOBq1if4")) in graph.unlinked()


def test_several_saml_addresses_with_no_primary_are_not_joined_on():
    """GraphQL documents no ordering for the emails connection, so emails[0]
    was a guess about which person owns the account -- the same coin flip the
    projection already refuses for two verified emails."""
    def identity(emails, **rest):
        return SamlIdentity.from_dict({"nameId": "guid", "username": "guid", "emails": emails, **rest})

    two_no_primary = [{"value": "a@acme.example"}, {"value": "b@acme.example"}]
    assert identity(two_no_primary).unambiguous_email() == ""
    assert identity(two_no_primary).joinable() == ("", "")

    # One marked primary is a stated answer, not a guess.
    marked = [{"value": "a@acme.example"}, {"value": "b@acme.example", "primary": True}]
    assert identity(marked).joinable() == ("b@acme.example", "emails")

    # Two marked primary is GitHub contradicting itself: still not a guess to make.
    both = [{"value": "a@acme.example", "primary": True}, {"value": "b@acme.example", "primary": True}]
    assert identity(both).unambiguous_email() == ""

    # A lone address needs no primary flag to be unambiguous.
    assert identity([{"value": "a@acme.example"}]).joinable() == ("a@acme.example", "emails")


def test_the_join_key_is_normalised_so_other_sources_can_match_it(graph):
    # sofia's SAML attributes are mixed case with surrounding whitespace.
    link = graph.link_for((GITHUB, "U_kgDOBq1daz"))
    assert link.identity == "sofia.ramos@acme.example"
    assert "SAML username" in link.evidence


def test_one_verified_email_joins_when_there_is_no_saml_identity(graph):
    link = graph.link_for((GITHUB, "U_kgDOBq1fc1"))  # hannah
    assert (link.method, link.identity) == (LinkMethod.VERIFIED_EMAIL, "hannah.ortiz@acme.example")
    assert "verified by GitHub" in link.evidence


def test_two_verified_emails_are_not_a_coin_flip(graph):
    # omar has two. Picking one would be picking between two people's worth of
    # accountability.
    assert graph.link_for((GITHUB, "U_kgDOBq1gd2")) is None
    assert gaps_mentioning(graph, "2 verified emails")
    assert graph.principal((GITHUB, "U_kgDOBq1gd2")).email == ""


def test_members_github_states_nothing_about_are_unlinked(graph):
    assert {"dev-contractor-42", "acme-ci-bot", "grace-park"} <= labels(graph.unlinked())


def test_a_declared_service_account_is_declared_not_a_person(github_snapshot):
    graph = project_github(github_snapshot, Register.from_config([{"source": GITHUB, "id": "acme-ci-bot"}]))
    bot = graph.principal((GITHUB, "U_kgDOBq1kh6"))
    assert bot.kind is PrincipalKind.SERVICE
    assert graph.link_for(bot.key).method is LinkMethod.DECLARED


def test_an_okta_entry_does_not_declare_a_github_member_with_the_same_login(github_snapshot):
    """Entries are scoped to a source. Two sources are two estates and a login
    is only a name within one, so the flat list this register grew out of would
    have declared a GitHub bot because an Okta account happened to match."""
    unscoped = project_github(github_snapshot, Register.from_config(["acme-ci-bot"]))
    assert unscoped.link_for((GITHUB, "U_kgDOBq1kh6")) is None
    assert unscoped.principal((GITHUB, "U_kgDOBq1kh6")).kind is PrincipalKind.HUMAN
    assert gaps_mentioning(unscoped, "acme-ci-bot") == [], "an okta entry is not this source's problem"


def test_an_sso_link_does_not_make_a_principal_a_person(graph):
    # Personhood comes from the register, never from having an IdP account: a
    # machine user can be provisioned in the IdP too.
    assert graph.principal((GITHUB, "U_kgDOBq1kh6")).kind is PrincipalKind.HUMAN
    assert graph.principal((GITHUB, "U_kgDOBq1aXw")).kind is PrincipalKind.HUMAN


def test_an_org_without_sso_can_read_neither_identities_nor_credentials():
    graph = project_github(GitHubSnapshot(org="acme-eng", collected_at=NOW, sso_enabled=False,
                                          members=[Member(id="1", login="someone")]))
    assert graph.link_for((GITHUB, "1")) is None
    meta = graph.source(GITHUB)
    assert not meta.complete and not meta.activity_complete
    assert gaps_mentioning(graph, "not behind SSO")
    assert not graph.coverage().reliable


# --- membership state --------------------------------------------------------


@pytest.mark.parametrize(
    "member_id,expected,source_status",
    [
        ("U_kgDOBq1aXw", Status.ACTIVE, "active"),
        ("U_kgDOBq1he3", Status.UNKNOWN, "pending"),
    ],
)
def test_membership_state_is_mapped_and_the_source_word_kept(graph, member_id, expected, source_status):
    principal = graph.principal((GITHUB, member_id))
    assert (principal.status, principal.source_status) == (expected, source_status)


def test_a_state_github_does_not_document_reads_unknown_not_active():
    """The member reads return active|pending. If GitHub starts returning
    something else, the account's status is unknown -- never quietly ACTIVE,
    and never DISABLED, which is the one status that suppresses an AR-17
    finding for a leaver. "suspended" is pinned here on purpose: it was in the
    fixture and in MEMBER_STATUSES until the PR #17 review found that no
    endpoint this adapter reads returns it."""
    for state in ("deactivated", "suspended"):
        snapshot = GitHubSnapshot.from_dict({
            "org": "acme-eng", "collected_at": "2026-09-15T14:00:00Z",
            "members": [{"id": "U_new", "login": "someone", "state": state}],
        })
        [principal] = project_github(snapshot).principals
        assert (principal.status, principal.source_status) == (Status.UNKNOWN, state)


def test_an_unrecognised_membership_state_is_unknown():
    graph = project_github(GitHubSnapshot(org="acme-eng", collected_at=NOW,
                                          members=[Member(id="1", login="x", state="something_new")]))
    assert graph.principal((GITHUB, "1")).status is Status.UNKNOWN


def test_a_member_has_no_last_used_because_github_reports_none(graph):
    # There is no per-member activity outside the audit log. Inventing one
    # would let a dormancy check read "never active" from a field nobody read.
    assert all(p.last_used is None for p in graph.principals)
    assert graph.principal((GITHUB, "U_kgDOBq1aXw")).created == datetime(2019, 3, 14, 9, 0, tzinfo=timezone.utc)


# --- credentials -------------------------------------------------------------


def test_classic_scopes_decide_write_access(graph):
    victor = {c.label: c for c in graph.credentials_for((GITHUB, "U_kgDOBq1cZy"))}
    pat = victor["personal access token …71c3fc9c"]
    assert pat.write_access is True  # repo, workflow
    assert pat.last_used == datetime(2026, 9, 10, 3, 12, tzinfo=timezone.utc)
    assert pat.created is None  # credential-authorizations states no creation date

    [marcus] = graph.credentials_for((GITHUB, "U_kgDOBq1bYx"))
    assert marcus.write_access is False  # read:org, read:user
    assert marcus.expires == datetime(2027, 1, 19, 9, 0, tzinfo=timezone.utc)


def test_an_ssh_key_can_always_push(graph):
    keys = [c for c in graph.credentials if c.kind is CredentialKind.SSH_KEY]
    assert {c.holder for c in keys} == {"U_kgDOBq1cZy", "U_kgDOBq1daz"}
    assert all(c.write_access is True for c in keys)


def test_fine_grained_permissions_decide_write_access_not_scopes(graph):
    # A fine-grained token has no classic scopes at all. Reading that as "no
    # access" would file every one of them as harmless.
    [lee] = graph.credentials_for((GITHUB, "U_kgDOBq1eb0"))
    assert lee.write_access is False  # contents: read, metadata: read
    assert lee.label == "fine-grained token 88201 on subset repositories"

    [dev] = graph.credentials_for((GITHUB, "U_kgDOBq1jg5"))
    assert dev.write_access is True  # contents: write


def test_an_empty_permission_map_is_unknown_not_harmless(graph):
    [omar] = graph.credentials_for((GITHUB, "U_kgDOBq1gd2"))
    assert omar.write_access is None


def test_an_empty_scope_list_is_unknown_not_harmless(github_snapshot):
    for authorization in github_snapshot.credentials:
        authorization.scopes = []
    graph = project_github(github_snapshot)
    pats = [c for c in graph.credentials if c.kind is CredentialKind.GITHUB_PAT and c.id.isdigit()]
    assert pats and {c.write_access for c in pats} == {None}


def test_credentials_are_unknown_when_the_credential_read_did_not_run(github_snapshot):
    github_snapshot.credentials_complete = False
    graph = project_github(github_snapshot)
    assert graph.credentials_for((GITHUB, "U_kgDOBq1bYx"))[0].write_access is None
    assert not graph.source(GITHUB).activity_complete


def test_an_identity_gap_does_not_suppress_every_credential_answer(graph):
    # The fixture has identity gaps (an opaque SAML identity, an ambiguous
    # verified email). Those say nothing about whether scopes were read, and
    # letting them blank every write_access would kill the signal in any real
    # tenant.
    assert not graph.source(GITHUB).complete
    assert graph.credentials_for((GITHUB, "U_kgDOBq1bYx"))[0].write_access is False


def test_a_credential_can_outlive_the_account_that_made_it(graph):
    # sam-departed holds an SSO-authorized token but is not an org member.
    [orphan] = [c for c in graph.credentials if c.holder == "sam-departed"]
    assert orphan.write_access is True
    # The holder resolves to a principal the review knows nothing about rather
    # than to nothing at all: a write-capable token is held by *someone*, and
    # an account with no member record is a finding, not an absence.
    holder = graph.holder_of(orphan)
    assert (holder.kind, holder.status) == (PrincipalKind.UNKNOWN, Status.UNKNOWN)
    assert holder in graph.unlinked()
    assert gaps_mentioning(graph, "sam-departed")


# --- grants ------------------------------------------------------------------


def test_org_membership_teams_and_roles_are_all_grants(graph):
    priya = {(g.kind.value, g.target_label) for g in graph.grants_for((GITHUB, "U_kgDOBq1aXw"))}
    assert priya == {("org", "acme-eng"), ("role", "organization owner"), ("team", "Engineering")}
    lee = {(g.kind.value, g.target_label) for g in graph.grants_for((GITHUB, "U_kgDOBq1eb0"))}
    assert lee == {("org", "acme-eng"), ("team", "Engineering")}
    # The label is GitHub's own word for the role, for whoever reads the
    # finding; the target stays the API's value, because that is what is stable.
    role = next(g for g in graph.grants_for((GITHUB, "U_kgDOBq1aXw")) if g.kind.value == "role")
    assert role.target == "admin"


def test_only_a_role_above_ordinary_membership_is_a_grant():
    """`_elevated_roles` reads every ROLE grant and AR-17 grades on it, so an
    ordinary member here would make every departure critical. GraphQL spells
    the enum ADMIN/MEMBER, the invitations read says direct_member, and a
    billing manager cannot reach a repository at all."""
    def roles(role):
        graph = project_github(GitHubSnapshot.from_dict({
            "org": "acme-eng", "collected_at": "2026-09-15T14:00:00Z",
            "members": [{"id": "U_1", "login": "someone", "role": role}],
        }))
        return [g.target for g in graph.grants if g.kind.value == "role"]

    assert roles("MEMBER") == [] and roles("member") == []
    assert roles("direct_member") == [] and roles("billing_manager") == []
    assert roles("ADMIN") == ["admin"] and roles("admin") == ["admin"]
    # A role this adapter has never heard of is not evidence that it is safe.
    assert roles("security_manager") == ["security_manager"]


def test_unread_organization_roles_are_a_gap_not_an_absence():
    """The member role field carries only the base role. Security managers and
    custom organization roles are a separate read, so without it nobody holds
    an elevated role as far as the review can tell."""
    snapshot = GitHubSnapshot.from_dict({
        "org": "acme-eng", "collected_at": "2026-09-15T14:00:00Z",
        "sso_enabled": True, "credentials_complete": True, "members": [],
    })
    assert snapshot.roles_complete is False
    graph = project_github(snapshot)
    assert any("Organization roles" in g for g in graph.sources[0].gaps)


def test_team_access_held_by_an_account_the_member_read_missed_is_not_invisible(graph):
    ghost = graph.principal((GITHUB, "U_kgDOBq1zzz"))
    assert (ghost.kind, ghost.status) == (PrincipalKind.UNKNOWN, Status.UNKNOWN)
    assert ghost in graph.unlinked()
    assert [g.target_label for g in graph.grants_for(ghost.key)] == ["Release"]
    assert gaps_mentioning(graph, "U_kgDOBq1zzz")


# --- coverage and composition ------------------------------------------------


def test_coverage_reports_how_much_of_the_org_is_accounted_for(graph):
    coverage = graph.coverage()
    assert coverage.total == 13  # 11 members plus two accounts only their access reveals
    assert coverage.by_method == {"sso_identity": 5, "verified_email": 1, "declared": 0, "creator": 0}
    assert coverage.unlinked == 7
    # The fixture has identity gaps, so the unlinked count is a lower bound.
    assert not coverage.reliable


def test_a_leaver_holds_access_in_both_sources(both):
    victor = both.principals_of("victor.nguyen@acme.example")
    assert {p.source for p in victor} == {OKTA, GITHUB}
    assert both.principal((OKTA, "u09")).status is Status.DISABLED
    # Okta deactivated the account. GitHub still lists him as an active member.
    assert both.principal((GITHUB, "U_kgDOBq1cZy")).status is Status.ACTIVE

    held = sorted((c.kind.value, c.write_access) for p in victor for c in both.credentials_for(p.key))
    assert held == [("github_pat", True), ("oauth_client", False), ("ssh_key", True)]


def test_composed_coverage_spans_both_sources(both):
    coverage = both.coverage()
    assert coverage.total == 14 + 13
    assert coverage.by_method["sso_identity"] == 10 + 5
    assert coverage.by_method["verified_email"] == 1
    # 0 unlinked in Okta: the register declares its one unlinked principal.
    assert coverage.unlinked == 0 + 7


def test_nothing_joins_two_sources_by_a_similar_login(both):
    marcus = both.principals_of("marcus.lee@acme.example")
    # Terraform Automation is his because the register says so, which is
    # evidence someone signed; the GitHub account is his because SAML says so.
    # Neither is his because "marcus-lee" looks like "marcus.lee" -- which is
    # what the second half of this test takes away.
    assert {p.label for p in marcus} == {
        "marcus.lee@acme.example", "marcus-lee",
        "Terraform Automation", "svc-legacy-etl@acme.example"}

    stripped = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    for member in stripped.members:
        member.saml_identity = None
        member.verified_emails = []
    only_okta = IdentityGraph.compose(
        project_snapshot(Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))),
        project_github(stripped),
    )
    assert only_okta.principals_of("marcus.lee@acme.example") == [only_okta.principal((OKTA, "u02"))]


# --- source metadata and serialisation ---------------------------------------


def test_collected_at_is_read_from_the_snapshot(graph):
    meta = graph.source(GITHUB)
    assert meta.collected_at == datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)
    assert meta.org == "acme-eng"
    assert meta.activity_since is None


def test_optional_fields_default_to_the_safe_reading():
    member = Member.from_dict({"id": "1", "login": "a"})
    assert (member.role, member.state, member.saml_identity) == ("member", "active", None)
    assert SamlIdentity.from_dict(None) is None


def test_a_snapshot_that_does_not_claim_completeness_is_not_treated_as_complete():
    """A truncated or partly-written collector file must not assert that SSO
    was on and the credential reads finished. Defaulting these to True made an
    unfinished file read as a clean estate -- and flipped _scope_write_access
    from None ("unknown") to False ("cannot write")."""
    snapshot = GitHubSnapshot.from_dict({"org": "acme-eng", "collected_at": "2026-09-15T14:00:00Z"})
    assert snapshot.sso_enabled is False and snapshot.credentials_complete is False

    graph = project_github(snapshot)
    meta = graph.source(source_name("acme-eng"))
    assert meta.activity_complete is False and meta.complete is False
    assert graph.incomplete_sources() == [source_name("acme-eng")]


def test_the_snapshot_serialises_back_to_the_fixture_text(github_snapshot):
    # Pins from_dict and to_dict against the fixture file rather than only
    # against each other, so a field either side silently drops is caught.
    assert github_snapshot.to_dict() == json.loads((FIXTURES / "demo_github.json").read_text())


def test_the_projection_is_deterministic(github_snapshot):
    first = [g.to_dict() for g in project_github(github_snapshot).grants]
    second = [g.to_dict() for g in project_github(github_snapshot).grants]
    assert first == second


def test_a_null_role_does_not_reach_a_finding_as_None():
    """GraphQL declares OrganizationMemberEdge.role nullable, and
    `d.get("role", "member")` only defaults on an absent key, so a present null
    became a ROLE grant whose target is None. AR-17 joins role names into its
    detail, so the first leaver holding one crashed the check with a TypeError
    rather than reporting them."""
    member = Member.from_dict({"id": "U_1", "login": "someone", "role": None, "state": None})
    assert member.role == "member" and member.state == "active"
    graph = project_github(GitHubSnapshot.from_dict({
        "org": "acme-eng", "collected_at": "2026-09-15T14:00:00Z",
        "members": [{"id": "U_1", "login": "someone", "role": None, "state": None}],
    }))
    targets = [g.target for g in graph.grants]
    assert None not in targets, targets
    # and the join AR-17 performs cannot raise on them
    assert ", ".join(str(x) for x in targets) is not None


def test_documented_nullable_arrays_do_not_crash_the_reader():
    """The credential-authorizations response documents `scopes` as nullable,
    and GraphQL's ExternalIdentitySamlAttributes.emails is a nullable list.
    `d.get("scopes", [])` only defaults on an absent key, so a present null
    reached list() and raised TypeError."""
    snapshot = GitHubSnapshot.from_dict({
        "org": "acme-eng",
        "collected_at": "2026-09-15T14:00:00Z",
        # Stated, so the unknown write access below is the null scopes and not
        # an incomplete read.
        "sso_enabled": True, "credentials_complete": True,
        "members": [{
            "id": "U_null", "login": "someone", "verifiedEmails": None,
            "samlIdentity": {"nameId": None, "username": "someone", "emails": None},
        }],
        "credentials": [{
            "credentialId": 1, "login": "someone",
            "credentialType": "personal access token", "scopes": None,
        }],
    })
    graph = project_github(snapshot)
    [principal] = graph.principals
    [credential] = graph.credentials_for(principal.key)
    # No scopes read is not "cannot write": see _scope_write_access. (An SSH key
    # would be True regardless -- an account key can always push.)
    assert credential.write_access is None
    # The nullable identity arrays read as empty, so nothing joins and nothing
    # is invented: unlinked, not guessed.
    assert graph.unlinked() == [principal]
