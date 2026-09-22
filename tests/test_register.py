"""The service account register: declaring an account, and who answers for it.

The thing under test is a negative. Declaring an account used to make AR-15 go
quiet -- the principal picked up a link, dropped out of `unlinked()`, and the
finding vanished while exactly as many people were accountable for the
credential as before: nobody. Most of what is here exists to keep that from
coming back, so the assertions are about what a declaration may NOT do.
"""

import copy
import json
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import Config, ReviewContext, run_checks
from access_review.identity import (
    OKTA,
    GitHubSnapshot,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKind,
    SourceMeta,
    identity_key,
    project_github,
    project_snapshot,
    source_name,
)
from access_review.models import Snapshot
from access_review.register import OKTA as REGISTER_OKTA
from access_review.register import Register, RegisterError
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.transitions import build_transitions

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)
GITHUB = source_name("acme-eng")


def context(register=None, snapshot_raw=None):
    """A demo review context, optionally with the register replaced."""
    raw = snapshot_raw or json.loads((FIXTURES / "demo_snapshot.json").read_text())
    snapshot = Snapshot.from_dict(raw)
    config = Config.load(FIXTURES / "demo_config.json")
    if register is not None:
        config.service_accounts = register
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    ctx = ReviewContext(snapshot, load_roster(FIXTURES / "demo_roster.csv", config.timezone()),
                        config, AS_OF)
    ctx.graph = IdentityGraph.compose(
        project_snapshot(snapshot, config.service_accounts),
        project_github(github, config.service_accounts),
    )
    return ctx


def ar15(ctx):
    return {f.subject: f.severity for f in run_checks(ctx)[0] if f.check_id == "AR-15"}


# --- reading the config ------------------------------------------------------


def test_a_bare_login_is_still_read_and_means_nobody_named():
    """The flat list this grew out of. It kept an account out of AR-03 and said
    nothing about who owns it, so that is what it still means -- read, and
    reported as a declaration naming nobody rather than as ownership."""
    [entry] = Register.from_config(["svc-ci@acme.example"]).entries
    assert (entry.id, entry.source, entry.owner) == ("svc-ci@acme.example", OKTA, "")


def test_an_owner_is_normalised_the_way_an_identity_key_is():
    """The owner is joined against `identity_key`, which lowercases the Okta
    profile email. Stored as typed, `Marcus.Lee@Acme.Example` would link the
    account to an identity nobody has: it would read as owned, reach no one's
    review, and be in no one's departure bundle -- worse than undeclared,
    because undeclared at least reports itself.

    Compared against `identity_key` rather than against a lowercase literal, so
    changing how identities are keyed fails here instead of silently
    un-joining every register entry.
    """
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    marcus = Snapshot.from_dict(raw).users[1]
    [entry] = Register.from_config([{"id": "x", "owner": "  Marcus.Lee@Acme.Example  "}]).entries
    assert entry.owner == identity_key(marcus)


def test_one_account_cannot_have_two_owners():
    """Two entries for one account are two ownership claims, and the register is
    supposed to be the answer to who owns it. Last-wins would make the register
    itself the ambiguity it exists to remove."""
    with pytest.raises(RegisterError, match="one account has one owner"):
        Register.from_config([{"id": "bot", "owner": "a@x.example"},
                              {"id": "BOT", "owner": "b@x.example"}])
    # The source half of the key too. Compared exactly, `Okta` and `okta` are
    # two accounts, so the register would accept two owners for one bot and the
    # check that exists to remove that ambiguity would be bypassed by a capital.
    with pytest.raises(RegisterError, match="one account has one owner"):
        Register.from_config([{"source": "OKTA", "id": "bot", "owner": "a@x.example"},
                              {"source": "okta", "id": "bot", "owner": "b@x.example"}])
    # Same name in two sources is two accounts, and must still be allowed.
    assert len(Register.from_config([{"id": "bot"}, {"source": GITHUB, "id": "bot"}])) == 2


def test_a_source_is_matched_however_it_is_capitalised():
    """A GitHub org login displays in the casing it was created with, so
    `github:Acme-Eng` is what somebody copies out of the browser while
    `source_name` builds `github:acme-eng` from the API.

    Compared exactly, that entry matches nothing and -- unlike a misspelled id,
    which `stale` reports -- says nothing either, because `stale` only walks the
    entries whose source it was called for and is never called for a source no
    projection recognised. A register line that looks like a declaration and is
    silently inert is the claim-that-looks-like-coverage this file exists to
    prevent, so the casing must not be load-bearing.
    """
    subject = f"{GITHUB}/U_kgDOBq1kh6"
    for source in ("github:Acme-Eng", "GITHUB:ACME-ENG"):
        register = Register.from_config([{"source": source, "id": "acme-ci-bot"}])
        found = ar15(context(register))
        assert subject in found, f"{source} declares the bot, so it is reported as declared"
        detail = {f.subject: f.detail for f in run_checks(context(register))[0]}[subject]
        assert "register declares this account" in detail
    # And the same for the default source spelled loudly.
    assert Register.from_config([{"source": "Okta", "id": "x"}]).entry(OKTA, "X") is not None


@pytest.mark.parametrize("entry, message", [
    ({"id": "bot", "ownr": "a@x.example"}, "unknown keys: ownr"),
    ({"owner": "a@x.example"}, "has no id"),
    ({"id": "bot", "reviewed": "last July"}, "not a date"),
    ({"id": "bot", "source": " "}, "empty source"),
    ("", "is empty"),
    (42, "must be a login or an object"),
])
def test_an_unreadable_entry_says_which_one_it_is(entry, message):
    """`Config.load` fails fast on a bad config and this is part of one. The
    position is in the message because the id may be the broken part."""
    with pytest.raises(RegisterError, match=message) as e:
        Register.from_config([{"id": "fine"}, entry])
    assert "entry 2" in str(e.value)


def test_the_register_survives_the_manifest(tmp_path):
    """`write_report` signs the config it ran under, so who was declared and who
    answers for them is evidence an auditor reads back.

    Two things in the register are not JSON: the lookup index, whose keys are
    tuples, and `reviewed`, which is a date. Read off the file `write_report`
    actually wrote, not off a block assembled here -- assembling one here is
    what the implementation does, so a test shaped that way agrees with
    `report.py` about the config's shape no matter what either of them does.
    """
    config = Config.load(FIXTURES / "demo_config.json")
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     AS_OF, tmp_path, github_path=FIXTURES / "demo_github.json")

    manifest = json.loads((run.run_dir / "manifest.json").read_text())
    written = manifest["config"]["service_accounts"]
    assert Register.from_config(written) == config.service_accounts, "it signed a different register"
    assert {e["id"]: e["owner"] for e in written}["Terraform Automation"] == "marcus.lee@acme.example"
    assert {e["id"]: e["reviewed"] for e in written}["Terraform Automation"] == "2026-07-01"


def test_the_registers_default_source_is_the_identity_layers_okta_name():
    """register.py repeats the constant rather than importing it, because the
    identity layer imports the register. Two spellings of "okta" would declare
    nothing and report no error."""
    assert REGISTER_OKTA == OKTA


# --- what a declaration may not do -------------------------------------------


def test_declaring_an_account_with_no_owner_downgrades_the_finding_and_never_removes_it():
    """The whole reason this branch exists.

    An entry with no owner is a link, so the principal leaves `unlinked()` and
    AR-15 used to stop firing -- a config change that deletes a finding about a
    write-capable credential and makes nobody accountable for it. Asserted over
    every AR-15 subject at once rather than on one: declaring an account may
    move its grade, and may not move anyone else's or remove any subject.
    """
    plain = context()
    before = ar15(plain)
    undeclared = "github:acme-eng/U_kgDOBq1jg5"  # dev-contractor-42, high
    assert before[undeclared] == "high"

    # The demo register plus one entry, so nothing else in the estate moves.
    declared = context(Register.from_config([
        *plain.config.service_accounts.to_dict(),
        {"source": GITHUB, "id": "dev-contractor-42"},
    ]))
    after = ar15(declared)
    assert set(after) == set(before), "declaring an account removed a finding"
    assert after[undeclared] == "medium", "declared with nobody named is one rung, not silence"
    assert {s: g for s, g in after.items() if s != undeclared} == \
        {s: g for s, g in before.items() if s != undeclared}, "it graded somebody else's account"
    detail = next(f.detail for f in run_checks(declared)[0] if f.subject == undeclared)
    assert "nobody is accountable" in detail and "register declares this account" in detail


def test_an_owner_is_the_one_thing_that_clears_it():
    """The other half: the remediation is worth following. Same entry, same
    account, an owner added -- and only then does the finding go.

    The owner has to be a real person, and this says so, because "an owner
    clears it" is also true of an owner nobody has. See the test below for why
    that distinction is the whole of it.
    """
    entry = {"source": GITHUB, "id": "dev-contractor-42"}
    subject = "github:acme-eng/U_kgDOBq1jg5"
    assert subject in ar15(context(Register.from_config([entry])))
    assert subject not in ar15(context(Register.from_config([{**entry, "owner": "priya.shah@acme.example"}])))


def test_an_owner_nobody_can_be_reached_at_never_clears_the_finding():
    """A typo in `owner` must not be quieter than an honest blank.

    The register writes whatever is typed into `Link.identity`, and a non-empty
    identity used to be the whole test for "somebody is accountable". So
    `marcus.lee@acme.exmaple` -- one transposition -- read as ownership on every
    screen, joined to no person, reached no departure bundle, and *removed* the
    finding that naming nobody only downgrades. The register's one rule, that an
    entry which makes nobody accountable may not remove a finding, was defeated
    by a misspelling, and the incentive ran the wrong way: whoever wanted the
    finding gone was better off getting the address wrong than leaving it out.

    Parametrised over the two ways to be unreachable, and pinned to the severity
    of the blank-owner case rather than to "some finding exists": reporting a
    phantom owner *more* mildly than no owner would be the same inversion, one
    rung smaller, and an assertion on presence alone would pass through it.
    """
    entry = {"source": GITHUB, "id": "dev-contractor-42"}
    subject = "github:acme-eng/U_kgDOBq1jg5"
    nameless = ar15(context(Register.from_config([entry])))[subject]
    for owner in ("priya.shah@acme.exmaple",  # a transposition in a real person's address
                  "someone.who.never.existed@acme.example"):
        found = ar15(context(Register.from_config([{**entry, "owner": owner}])))
        assert found.get(subject) == nameless, (
            f"owner {owner!r} is evidenced by no source, so it is worth exactly what naming "
            f"nobody is worth -- and never less"
        )


def test_a_phantom_owner_does_not_invent_the_person_it_names():
    """The other half of the silence: an unreachable owner must not become a
    person in the report.

    `_by_identity` is built from the best link's identity, and `identities()`
    reads it -- so an unattested owner would appear as somebody holding one
    service account, and the account would read as reviewed by a person who does
    not exist. Worse than the missing finding, because it is a positive claim.
    """
    entry = {"source": GITHUB, "id": "dev-contractor-42", "owner": "priya.shah@acme.exmaple"}
    graph = context(Register.from_config([entry])).graph
    assert graph.principals_of("priya.shah@acme.exmaple") == []
    assert "priya.shah@acme.exmaple" not in {i.key for i in graph.identities()}
    # And the real person is untouched: the typo took nothing away from her.
    assert graph.principals_of("priya.shah@acme.example")


def test_a_phantom_owner_does_not_erase_who_created_it():
    """`strength` ranks a link that names somebody above one that does not, and
    an unattested name is not somebody.

    Without that, a misspelled owner -- DECLARED, so stronger on rank than
    CREATOR -- would outrank the audit log's "priya built this" and replace the
    only real attribution there was with one that reaches nobody. The ownerless
    form of this is already guarded; this is the same hazard wearing a name.
    """
    key = (OKTA, "a1")
    graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)],
        principals=[Principal(source=OKTA, id="a1", label="Bot", kind=PrincipalKind.SERVICE)],
        links=[
            Link(key, LinkMethod.DECLARED, "nobody@acme.exmaple", "declared, owner misspelled"),
            Link(key, LinkMethod.CREATOR, "priya.shah@acme.example", "created it"),
        ],
    )
    assert graph.link_for(key).method is LinkMethod.CREATOR
    assert graph.principals_of("priya.shah@acme.example") == list(graph.principals)
    assert graph.unattributed() == [], "the creator link reaches a person, so this is attributed"


def test_unlinked_and_unattributed_are_two_lists_and_never_the_same_principal():
    """AR-15 walks both, so a principal in both would be reported twice under
    one subject -- two rows in findings.csv, one ticket label. They are disjoint
    by construction (no best link, against a best link naming nobody) and this
    says so on real data rather than on the definition."""
    graph = context().graph
    unlinked = {p.key for p in graph.unlinked()}
    unattributed = {p.key for p in graph.unattributed()}
    assert unlinked & unattributed == set()
    assert unattributed, "the demo declares an account with no owner, or this proves nothing"
    # Together they are exactly the principals no identity can be reached from.
    assert unlinked | unattributed == {
        p.key for p in graph.principals
        if (link := graph.link_for(p.key)) is None or not link.identity
    }


def test_declaring_an_account_does_not_erase_who_created_it():
    """DECLARED outranks CREATOR, so an entry naming no owner would replace "the
    audit log says priya built this" with "somebody wrote it down" and lose the
    only attribution there was. A link that names a person beats one that does
    not, whatever the method -- rank orders evidence about *who*, and a nameless
    link carries none."""
    key = (OKTA, "a1")
    graph = IdentityGraph(
        sources=[SourceMeta(source=OKTA)],
        principals=[Principal(source=OKTA, id="a1", label="Bot", kind=PrincipalKind.SERVICE)],
        links=[
            Link(key, LinkMethod.DECLARED, "", "declared, no owner"),
            Link(key, LinkMethod.CREATOR, "priya.shah@acme.example", "created it"),
        ],
    )
    assert graph.link_for(key).method is LinkMethod.CREATOR
    assert graph.principals_of("priya.shah@acme.example") == list(graph.principals)
    assert graph.unattributed() == [], "a nameless link is not the best one here"


def test_a_register_entry_that_matches_nothing_is_a_gap_not_a_silence():
    """An entry names an account by a name a person typed. A rename, a typo or a
    deleted account leaves a claim that looks like coverage: the account is
    undeclared again and reported at full severity, while whoever wrote the
    entry believes it is handled."""
    ctx = context(Register.from_config([{"id": "svc-gone@acme.example", "owner": "priya.shah@acme.example"}]))
    [gap] = [g for g in ctx.graph.source(OKTA).gaps if "register" in g]
    assert "svc-gone@acme.example" in gap
    assert not ctx.graph.source(OKTA).complete


# --- naming a service client -------------------------------------------------


def _twinned():
    """The demo snapshot with a second API service client under the same label."""
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    original = next(a for a in raw["apps"] if a["label"] == "Terraform Automation")
    twin = copy.deepcopy(original)
    twin["id"], twin["clientId"] = original["id"] + "-twin", original["clientId"] + "TWIN"
    raw["apps"].append(twin)
    return raw


def test_a_label_two_service_clients_share_declares_neither():
    """A label is a display name -- the same reason ticket identity is hashed
    from the stable id. One entry fitting two clients would vouch for the wrong
    one, which records a credential as accounted for while nobody is. Both stay
    undeclared and the register says why."""
    ctx = context(Register.from_config([{"id": "Terraform Automation", "owner": "priya.shah@acme.example"}]),
                  snapshot_raw=_twinned())
    assert {"okta/a04", "okta/a04-twin"} <= set(ar15(ctx))
    [gap] = [g for g in ctx.graph.source(OKTA).gaps if "Terraform Automation" in g]
    assert "declares none of them" in gap and "client id" in gap


def test_a_service_client_can_be_declared_by_its_client_id():
    """The way out of an ambiguous label, so the gap above is an instruction
    someone can follow. The id is stable and the Okta console shows it."""
    ctx = context(Register.from_config([{"id": "0oaTERRAFORM", "owner": "priya.shah@acme.example"}]),
                  snapshot_raw=_twinned())
    assert ctx.graph.link_for((OKTA, "a04")).identity == "priya.shah@acme.example"
    assert "okta/a04" not in ar15(ctx)
    assert "okta/a04-twin" in ar15(ctx), "the twin is a different account and nobody declared it"
    assert [g for g in ctx.graph.source(OKTA).gaps if "register" in g] == []


# --- the loop --------------------------------------------------------------


def test_an_owner_who_leaves_takes_the_accounts_they_own_into_their_departure_bundle():
    """The point of putting an owner on the entry, and it needs no check of its
    own: a bundle is built from `principals_of(identity)`, so an evidenced link
    is all it takes. An ownership claim goes stale the moment the claimant
    leaves, and the long tail of a departure is not just their own credentials
    -- it is everything they were answerable for.
    """
    ctx = context()  # the demo register declares Terraform Automation to marcus, who has left
    findings, _ = run_checks(ctx)
    [marcus] = [t for t in build_transitions(ctx, findings, []) if t.identity == "marcus.lee@acme.example"]
    owned = {p["label"]: p for p in marcus.principals}
    assert "Terraform Automation" in owned, "an account he owns is part of his departure"
    link = owned["Terraform Automation"]["link"]
    assert link["method"] == "declared" and link["identity"] == "marcus.lee@acme.example"
    # The bundle shows the claim, not just the conclusion: an auditor reading it
    # can see it rests on a register entry and when that entry was last checked.
    assert "last reviewed 2026-07-01" in link["evidence"]


def test_an_entry_with_no_owner_reaches_nobodys_bundle():
    """The counterpart. Declared and unowned is not attributed, so it must not
    turn up in a departure bundle on the strength of having been written down."""
    ctx = context()
    assert ctx.graph.principals_of("") == []
    findings, _ = run_checks(ctx)
    for transition in build_transitions(ctx, findings, []):
        assert "svc-ci@acme.example" not in {p["label"] for p in transition.principals}


def test_a_declared_entry_is_not_a_service_account_in_another_source():
    """`is_service_account` (AR-03) asks the register for an Okta login. An
    entry scoped to GitHub must not answer for one."""
    ctx = context(Register.from_config([{"source": GITHUB, "id": "svc-ci@acme.example"}]))
    assert "svc-ci" in {f.subject.split("@")[0] for f in run_checks(ctx)[0] if f.check_id == "AR-03"}


def test_the_entry_is_the_only_thing_that_makes_an_account_a_service_account():
    """Never guessed from the login. An undeclared bot account is itself the
    finding (AR-03), so pattern-matching on "svc-" would hide it."""
    ctx = context(Register())
    assert ctx.graph.principal((OKTA, "u10")).kind is PrincipalKind.HUMAN
    assert "svc-ci" in {f.subject.split("@")[0] for f in run_checks(ctx)[0] if f.check_id == "AR-03"}


def test_a_review_hands_the_register_to_every_source_it_projects(tmp_path):
    """`run_review` composes the graph, and the GitHub projection took a
    register parameter that nothing ever passed. A bot could be declared in the
    config, kept out of AR-03, and still reported by AR-15 as an account no
    evidence ties to anyone -- the register was Okta-only in everything but its
    signature.

    Asserted through `run_review` rather than by composing a graph here, because
    composing one here is exactly what every other test in this file does and
    none of them touches the wiring. Dropping the argument in `review.py` leaves
    all of them green.
    """
    config = Config.load(FIXTURES / "demo_config.json")
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     AS_OF, tmp_path, github_path=FIXTURES / "demo_github.json")

    declared = [f for f in run.findings
                if f.check_id == "AR-15" and f.subject == f"{GITHUB}/U_kgDOBq1kh6"]
    assert declared, "acme-ci-bot is declared with no owner and is still reported"
    assert "register declares this account" in declared[0].detail, (
        "the review composed a graph that had never seen the register"
    )


def test_a_register_entry_the_review_could_not_check_is_a_gap(tmp_path):
    """Two entries that declare nothing, reported through `run_review` because
    neither is visible to a single projection.

    An owner no source evidences: the projection that reads the entry cannot
    know whether the name reaches a person, since the estate holding the account
    is usually not the estate the owner has an account in -- a GitHub bot owned
    by an Okta-only employee is the ordinary case. And a source the review never
    read: `stale` is called per source, so an entry for an org nobody projected
    is the one dead entry it structurally cannot see.

    Both are gaps rather than findings. AR-15 already reports the account; what
    these add is that the register is wrong rather than that nobody has claimed
    it, which is a different thing to go and fix.
    """
    config = Config.load(FIXTURES / "demo_config.json")
    config.service_accounts = Register.from_config([
        {"id": "Terraform Automation", "owner": "marcus.lee@acme.exmaple"},
        {"source": "github:a-repo-org-we-never-read", "id": "ghost-bot"},
    ])
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     AS_OF, tmp_path, github_path=FIXTURES / "demo_github.json")

    [owner_gap] = [g for g in run.gaps if "owned by" in g]
    assert "marcus.lee@acme.exmaple" in owner_gap and "Terraform Automation" in owner_gap
    [unread_gap] = [g for g in run.gaps if "did not read" in g]
    assert "github:a-repo-org-we-never-read" in unread_gap
    # A gap is not a substitute for the finding: the account is still reported.
    assert any(f.check_id == "AR-15" and f.subject == f"{OKTA}/a04" for f in run.findings)
    assert not run.complete, "a register nothing checked is not a complete review"


def _twinned_status(original_status="ACTIVE", twin_status="INACTIVE"):
    """The demo snapshot with a second client under the same label, and a status
    on each. The realistic shape: a client replaced by one with the same name."""
    raw = _twinned()
    for app in raw["apps"]:
        if app["label"] == "Terraform Automation":
            app["status"] = twin_status if app["id"].endswith("-twin") else original_status
    return raw


def test_a_label_the_client_it_replaced_left_behind_still_declares_the_live_one():
    """`collect` reads the apps endpoint with no status filter (the user read
    filters ACTIVE, that one does not), so a deactivated client is in the
    snapshot with its label and its client id intact. The ordinary way two
    clients share a label is exactly that -- switch the old one off, build the
    new one beside it -- and counting the dead one made a correct entry declare
    neither, so the live client came back at full severity for being undeclared
    while somebody had declared it and named an owner."""
    ctx = context(Register.from_config([{"id": "Terraform Automation", "owner": "priya.shah@acme.example"}]),
                  snapshot_raw=_twinned_status())
    assert ctx.graph.link_for((OKTA, "a04")).identity == "priya.shah@acme.example"
    assert "okta/a04" not in ar15(ctx)
    assert [g for g in ctx.graph.source(OKTA).gaps if "Terraform Automation" in g] == []
    # The one that was switched off is a different account and nobody declared
    # it, so it is still reported. Deactivated is not deleted.
    assert "okta/a04-twin" in ar15(ctx)


def test_a_label_an_unreadable_status_shares_declares_neither():
    """The other direction, and the one that matters more. `_app_status` refuses
    to read a status it does not recognise as disabled, because a service client
    is a live credential and retiring one on paper is how it keeps working
    unwatched. The same refusal belongs here: a client that may still be running
    keeps the label ambiguous rather than letting the entry vouch for a client
    nobody meant."""
    ctx = context(Register.from_config([{"id": "Terraform Automation", "owner": "priya.shah@acme.example"}]),
                  snapshot_raw=_twinned_status(twin_status="SOMETHING_NEW"))
    assert {"okta/a04", "okta/a04-twin"} <= set(ar15(ctx))
    [gap] = [g for g in ctx.graph.source(OKTA).gaps if "Terraform Automation" in g]
    assert "declares none of them" in gap


def test_a_client_that_was_switched_off_is_still_declared_by_its_label():
    """Nothing above may cost a lone client its declaration. One client carries
    the label, so the entry is unambiguous whatever its status -- an account
    that was decommissioned is the case a register is most likely to be right
    about, and undeclaring it would report it at full severity forever."""
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    next(a for a in raw["apps"] if a["label"] == "Terraform Automation")["status"] = "INACTIVE"
    ctx = context(Register.from_config([{"id": "Terraform Automation", "owner": "priya.shah@acme.example"}]),
                  snapshot_raw=raw)
    assert ctx.graph.link_for((OKTA, "a04")).identity == "priya.shah@acme.example"
    assert [g for g in ctx.graph.source(OKTA).gaps if "register" in g] == []


# --- a login that changed hands ----------------------------------------------


def _github(register, **patch):
    """The demo GitHub snapshot projected on its own, with one member's fields
    replaced. Projected alone because this is the GitHub adapter's judgement and
    nothing in the Okta snapshot bears on it."""
    raw = json.loads((FIXTURES / "demo_github.json").read_text())
    for login, fields in patch.items():
        next(m for m in raw["members"] if m["login"] == login).update(fields)
    return project_github(GitHubSnapshot.from_dict(raw), register)


# A real person who claimed the freed login, with the SSO link that makes them
# one: the account GitHub handed the name to next.
CLAIMED = {
    "accountCreatedAt": "2026-08-14T09:00:00Z",
    "samlIdentity": {"nameId": "dana.ruiz@acme.example", "username": "dana.ruiz@acme.example",
                     "emails": [{"value": "dana.ruiz@acme.example", "primary": True}]},
    "verifiedEmails": ["dana.ruiz@acme.example"],
}


def test_a_github_login_that_changed_hands_declares_nothing():
    """An Okta login that changes stops matching, and `stale` says so. A GitHub
    login goes back into the pool the moment its owner renames, so the entry
    goes on matching -- a different account under the same name.

    That is worse than a miss on every axis: the account is typed a service
    account, the SSO branch that would have joined a real person to their own
    access is skipped, and the entry's owner is attached to somebody else's
    credentials. The evidence against it is the entry's own `reviewed` date:
    an account created after somebody confirmed the entry is not the account
    they confirmed."""
    register = Register.from_config([
        {"source": GITHUB, "id": "acme-ci-bot", "owner": "priya.shah@acme.example",
         "reviewed": "2026-07-01"},
    ])
    graph = _github(register, **{"acme-ci-bot": CLAIMED})
    key = (GITHUB, "U_kgDOBq1kh6")

    assert graph.principal(key).kind is PrincipalKind.HUMAN, "a person, not a declared bot"
    link = graph.link_for(key)
    assert link.method is LinkMethod.SSO_IDENTITY and link.identity == "dana.ruiz@acme.example", (
        "the entry took the SSO branch away and joined this person's access to nobody"
    )
    assert key not in {p.key for p in graph.principals_of("priya.shah@acme.example")}, (
        "an owner must never end up answering for an account they never touched"
    )
    [gap] = [g for g in graph.source(GITHUB).gaps if "acme-ci-bot" in g]
    assert "2026-08-14" in gap and "2026-07-01" in gap
    assert "did not return" not in gap, "the entry matched a name; it is the account that is wrong"


def test_a_github_login_still_held_by_the_account_that_was_declared_is_declared():
    """The counterpart, because the guard above is only worth having if it fires
    on the rename and nothing else. The demo bot predates the entry's review, so
    it is the account somebody confirmed, and an entry with no `reviewed` date
    carries no evidence either way and keeps working as it always did."""
    dated = _github(Register.from_config([
        {"source": GITHUB, "id": "acme-ci-bot", "owner": "priya.shah@acme.example",
         "reviewed": "2026-07-01"}]))
    undated = _github(Register.from_config([{"source": GITHUB, "id": "acme-ci-bot"}]))
    key = (GITHUB, "U_kgDOBq1kh6")
    for graph in (dated, undated):
        assert graph.principal(key).kind is PrincipalKind.SERVICE
        assert graph.link_for(key).method is LinkMethod.DECLARED
        assert [g for g in graph.source(GITHUB).gaps if "acme-ci-bot" in g] == []
