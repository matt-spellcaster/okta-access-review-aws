import json
from dataclasses import asdict, replace
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from access_review.checks import (
    CHECKS,
    GRAPH_CHECKS,
    SEVERITIES,
    Config,
    Finding,
    ReviewContext,
    run_checks,
)
from access_review.identity import (
    GitHubSnapshot,
    IdentityGraph,
    Link,
    LinkMethod,
    identity_key,
    project_github,
    project_snapshot,
)
from access_review.items import (
    CISO,
    FORMAT,
    ACKNOWLEDGE_ONLY,
    CROSS_SOURCE,
    DECIDE,
    KEEP,
    LINK_BASIS,
    REVOKE,
    LINK_MARKER,
    ItemsError,
    build_items,
    items_chunks,
    items_json,
    load_items,
    outside_okta_concerns,
    summary,
)
from access_review.models import Snapshot, User
from access_review.roster import load_roster

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)


@pytest.fixture
def demo():
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster = load_roster(FIXTURES / "demo_roster.csv", config.timezone())
    return ReviewContext(snapshot, roster, config, AS_OF)


@pytest.fixture
def demo_graph(demo):
    """The same review with GitHub composed in, which is what the cross-source
    checks read and what the reviewer's screen has to show."""
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    graph = IdentityGraph.compose(
        project_snapshot(demo.snapshot, demo.config.service_accounts), project_github(github)
    )
    return ReviewContext(demo.snapshot, demo.roster, demo.config, AS_OF, graph=graph)


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


def test_items_carry_the_facts_and_why_it_could_be_an_issue(demo):
    findings, _ = run_checks(demo)
    items = {(i.user.split("@")[0], i.target): i for i in build_items(demo, findings)}
    sf = items[("lee.chen", "Salesforce")]
    assert sf.name == "Lee Chen"
    assert sf.facts[0].startswith("Okta: ACTIVE") and "MFA: none" in sf.facts[0]
    assert sf.facts[1].startswith("HR: employee, active") and "manager Priya Shah" in sf.facts[1]
    assert "assigned 2025-06-02" in sf.facts[2]
    assert any("AR-04" in c for c in sf.concerns) and any("AR-14" in c for c in sf.concerns)
    # AR-14 is about the one unused app, not every app Lee has.
    assert not any("AR-14" in c for c in items[("lee.chen", "GitHub")].concerns)
    # Admin roles say what the role can do.
    assert "Full control of Okta" in items[("priya.shah", "Super Administrator")].concerns[0]
    # Nothing flagged means no concerns, not an empty placeholder.
    assert items[("priya.shah", "GitHub")].concerns == ()


def test_item_files_from_earlier_runs_still_load(demo):
    data = json.loads(items_json(build_items(demo), AS_OF, 90))
    data["format"] = 1
    for d in data["items"]:
        for k in ("name", "facts", "concerns", "outside_okta"):
            d.pop(k)
    old = load_items(json.dumps(data))
    assert old and old[0].facts == () and old[0].name == "" and old[0].outside_okta == ()


def _as_format_2(items):
    """The same items as a review opened before the split would have written them."""
    data = json.loads(items_json(items, AS_OF, 90))
    data["format"] = 2
    for d in data["items"]:
        d["concerns"] = d["concerns"] + d.pop("outside_okta")
        d.pop("outside_okta_gap", None)
    return json.dumps(data)


def test_a_format_2_file_is_split_on_load(demo_graph):
    """A review opened before the split and remediated after it. Its items file
    is on S3, create-only and hashed into a signed manifest, so it still has the
    cross-source concern inside `.concerns` -- the list a revoke ticket copies as
    the work an Okta re-check will confirm. Loading it as written would keep the
    defect alive for every in-flight review."""
    findings, _ = run_checks(demo_graph)
    built = build_items(demo_graph, findings)
    loaded = load_items(_as_format_2(built))
    assert [(i.key, i.outside_okta) for i in loaded] == [(i.key, i.outside_okta) for i in built]
    assert any(i.outside_okta for i in loaded), "nothing was carried across"
    assert not any("AR-17" in c for i in loaded for c in i.concerns)
    # The Okta concerns stay put: the split needs two signals the writer put
    # there, so it cannot land on a finding about this person's Okta access.
    assert [i.concerns for i in loaded] == [i.concerns for i in built]


def test_the_split_on_load_needs_both_signals(demo_graph):
    """Neither half alone. A person's own data can contain the words "tied to
    them by", and an Okta concern names a check id -- either on its own would
    move an Okta finding out of the list its ticket is meant to settle."""
    from access_review.items import _held_outside_okta

    assert _held_outside_okta(f"holds owner (AR-17 Access outside Okta{LINK_MARKER}an assertion)")
    assert not _held_outside_okta("HR shows terminated (AR-01 Terminated in HR)")
    assert not _held_outside_okta(f"note{LINK_MARKER}an assertion")
    assert not _held_outside_okta("their bio says tied to them by nothing (AR-01 Terminated)")


def test_a_gap_says_which_kind_of_empty_this_is(demo_graph):
    """Three things produce an empty outside_okta: no other source was read, one
    was read and this person could not be joined to it, or one was read
    completely and found nothing. Only the last is evidence a departure
    finished, and the card and the ticket both go silent on all three."""
    from access_review.items import outside_okta_gap

    okta_only = ReviewContext(demo_graph.snapshot, demo_graph.roster, demo_graph.config, AS_OF)
    assert "not known" in outside_okta_gap(None)
    assert all("not known" in i.outside_okta_gap for i in build_items(okta_only, ()))
    # The demo's GitHub read has gaps, so the reviewer is told the list may be short.
    findings, _ = run_checks(demo_graph)
    assert all("did not complete" in i.outside_okta_gap
               for i in build_items(demo_graph, findings))


def test_what_the_reviewer_saw_survives_the_round_trip(demo_graph):
    """The items file is evidence of what was on the screen."""
    findings, _ = run_checks(demo_graph)
    built = build_items(demo_graph, findings)
    again = load_items(items_json(built, AS_OF, 90))
    assert [(i.concerns, i.outside_okta) for i in again] == [(i.concerns, i.outside_okta) for i in built]
    assert any(i.outside_okta for i in again)


def graph_concerns(item):
    """Every concern on the item that came from the graph, whichever list it is in.

    Not just `outside_okta`: the point of the callers below is that a graph
    finding must reach a person only through an evidenced link, and routing one
    into `.concerns` by login similarity is exactly the regression they guard.
    Looking in one list would let that pass.
    """
    return [c for c in (*item.concerns, *item.outside_okta) if "tied to them by" in c]


def test_a_cross_source_finding_reaches_every_item_for_that_person(demo_graph):
    """The whole point of the cross-source checks. AR-17 says marcus.lee still
    holds GitHub access weeks after leaving; the CISO decides his Okta access on
    this screen, so it has to appear there and not only in the PDF."""
    findings, _ = run_checks(demo_graph)
    items = build_items(demo_graph, findings)
    mine = [i for i in items if i.user.startswith("marcus.lee")]
    assert mine, "marcus.lee has no review items"
    for item in mine:
        assert any("AR-17" in c for c in graph_concerns(item)), item.target
        # And on no item does it sit in `concerns`, which is the list a revoke
        # ticket copies as the work that ticket's Okta re-check will confirm.
        assert not any("AR-17" in c for c in item.concerns), item.target
    # It names the GitHub account, which is not his Okta login, so the reviewer
    # can go and look at the right thing.
    assert any("marcus-lee" in c for c in graph_concerns(mine[0]))
    # And the elevated role, which no credential list would have shown.
    assert any("organization owner role" in c for c in graph_concerns(mine[0]))


def test_the_concern_says_how_the_account_was_tied_to_the_person(demo_graph):
    """LinkMethod is a ladder of named evidence rather than a score so that a
    human can weigh it. The reviewer is the human, so the screen says which
    rung this rests on."""
    findings, _ = run_checks(demo_graph)
    items = build_items(demo_graph, findings)
    victor = next(i for i in items if i.user.startswith("victor.nguyen"))
    assert any("tied to them by the identity provider's own assertion" in c
               for c in graph_concerns(victor))


def test_a_finding_about_an_unlinked_principal_reaches_nobody(demo_graph):
    """AR-15 is the finding that nobody is accountable for a credential. Putting
    it on somebody's item would assert the attribution the graph refused to
    make -- and would mark the credential as somebody's problem when the whole
    finding is that it is nobody's."""
    findings, _ = run_checks(demo_graph)
    concerns = [c for i in build_items(demo_graph, findings)
                for c in (*i.concerns, *i.outside_okta)]
    assert not any("AR-15" in c or "AR-16" in c for c in concerns)
    # It is still a finding, still in the report, still ticketed.
    assert any(f.check_id == "AR-15" for f in findings)


def test_nothing_is_matched_on_a_login_or_a_label(demo_graph):
    """github.com/marcus-lee and Okta's marcus.lee resolve to one person only
    because a SAML assertion says so. Strip the link and the finding must stop
    reaching him, rather than falling back to the names looking alike."""
    findings, _ = run_checks(demo_graph)
    graph = demo_graph.graph
    # replace(), not a hand-built IdentityGraph: every field this does not name
    # comes across on its own. Listing them by hand is how a derived graph ends
    # up without `group_apps` and quietly short of everyone's app access.
    stripped = replace(graph, links=tuple(x for x in graph.links if x.principal[0] == "okta"))
    ctx = ReviewContext(demo_graph.snapshot, demo_graph.roster, demo_graph.config, AS_OF, graph=stripped)
    items = build_items(ctx, findings)
    assert not any(graph_concerns(i) for i in items)


def test_the_worst_concern_comes_first(demo_graph):
    """The reviewer reads the top of the list, so a critical finding never sits
    below a medium one.

    Walks the concerns in the order the item presents them and looks each one's
    severity up, rather than walking the findings: findings arrive already
    sorted by severity, so iterating them outer made the assertion hold no
    matter what order the concerns were in.
    """
    findings, _ = run_checks(demo_graph)

    def severity_of(concern: str) -> int | None:
        hits = [f for f in findings if f.detail and f.detail in concern
                and f.check_id in concern]
        return min((SEVERITIES.index(f.severity) for f in hits), default=None)

    checked = 0
    for item in build_items(demo_graph, findings):
        for group in (item.concerns, item.outside_okta):
            ranks = [r for c in group if (r := severity_of(c)) is not None]
            assert ranks == sorted(ranks), group
            checked += len(ranks)
    assert checked, "no concern resolved to a finding, so this proves nothing"
    # A case where the order actually differs: sofia's critical AR-17 outranks
    # her medium AR-07. They are in separate lists now, and the card puts the
    # outside-Okta one first, so the critical one is still what she reads first.
    sofia = next(i for i in build_items(demo_graph, findings) if i.user.startswith("sofia"))
    assert "AR-17" in sofia.outside_okta[0], sofia.outside_okta


def test_the_worst_thing_held_outside_okta_comes_first():
    """The card puts this block above everything else, so its first line is the
    first thing the reviewer reads.

    A unit test with two findings, because no fixture can prove this: every
    identity in the demo holds exactly one cross-source finding, so the
    fixture-level ordering assertions run on one-element lists and cannot fail.
    Deleting the sort from `outside_okta_concerns` passed all 463 tests.
    """
    user = User(id="u1", login="marcus.lee@acme.example", status="ACTIVE",
                profile={"email": "marcus.lee@acme.example"})
    key = identity_key(user)
    link = Link(("github:acme-eng", "U_kg1"), LinkMethod.SSO_IDENTITY, key, "SAML assertion")

    def finding(check_id, severity, detail):
        return Finding(check_id, "Access outside Okta", severity, [],
                       "github:acme-eng/U_kg1", detail, "remove it")

    milder = finding("AR-16", "medium", "holds a read-only token")
    worst = finding("AR-17", "critical", "holds the organization owner role")
    # Worst second, so returning them in graph order would fail.
    got = outside_okta_concerns(user, {key: [(milder, link), (worst, link)]})
    assert [c.split(" (")[0] for c in got] == [worst.detail, milder.detail]


def _without_oktas_access(demo_graph, login_prefix):
    """The demo, with one person's Okta apps, groups and roles all removed:
    their offboarding worked."""
    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    uid = next(u["id"] for u in raw["users"] if u["login"].startswith(login_prefix))
    for app in raw.get("apps", []):
        app.get("assigned", {}).pop(uid, None)
        if "users" in app:
            app["users"] = [u for u in app["users"] if u != uid]
    for group in raw.get("groups", []):
        group["members"] = [m for m in group.get("members", []) if m != uid]
    for user in raw["users"]:
        if user["id"] == uid:
            user["admin_roles"] = []
    snapshot = Snapshot.from_dict(raw)
    github = GitHubSnapshot.from_dict(json.loads((FIXTURES / "demo_github.json").read_text()))
    graph = IdentityGraph.compose(
        project_snapshot(snapshot, demo_graph.config.service_accounts), project_github(github)
    )
    return ReviewContext(snapshot, demo_graph.roster, demo_graph.config, AS_OF, graph=graph)


def test_a_finding_still_reaches_someone_whose_okta_offboarding_worked(demo_graph):
    """The case this whole feature exists for, and the one it used to miss.
    Items are built from Okta access, so a leaver whose Okta offboarding
    actually completed had no items at all and their critical GitHub finding
    reached no decision screen. The better the Okta hygiene, the more certain
    the cross-source finding was to be invisible."""
    ctx = _without_oktas_access(demo_graph, "victor")
    findings, _ = run_checks(ctx)
    assert any(f.check_id == "AR-17" and f.severity == "critical"
               and "victor" in f.detail for f in findings)
    items = [i for i in build_items(ctx, findings) if i.user.startswith("victor")]
    assert items, "a critical cross-source finding reached no review item"
    assert [i.kind for i in items] == [CROSS_SOURCE]
    assert any("AR-17" in c for c in items[0].outside_okta)
    # It settles by acknowledging: this review cannot change GitHub, and the
    # finding's own ticket tracks the fix.
    assert items[0].proposed == DECIDE and CROSS_SOURCE in ACKNOWLEDGE_ONLY


def test_nobody_with_okta_access_gets_a_cross_source_item(demo_graph):
    """It is the fallback for people the screen would otherwise miss, not a
    second copy of every cross-source concern."""
    findings, _ = run_checks(demo_graph)
    items = build_items(demo_graph, findings)
    assert not [i for i in items if i.kind == CROSS_SOURCE], \
        "everyone in the demo still holds Okta access, so none is needed"


def test_every_link_method_can_be_said_in_words():
    """LINK_BASIS turns a rung of the ladder into a sentence the reviewer reads.
    A new LinkMethod with no entry falls back to the raw enum value, which puts
    `tied to them by creator` on the screen instead of what it means."""
    assert set(LINK_BASIS) == set(LinkMethod)


def test_every_graph_check_reaches_the_decision_screen(demo_graph):
    """GRAPH_CHECKS is derived from the registry, not listed. A graph check
    added to CHECKS and forgotten here would be a finding the report prints and
    the screen that settles it never shows -- which is the defect this replaced."""
    assert set(GRAPH_CHECKS) == {c.id for c in CHECKS if c.needs_graph}
    assert GRAPH_CHECKS, "no graph checks found, so this guard proves nothing"


def test_the_items_file_is_the_same_document_however_it_is_laid_out(demo):
    """The layout changed to fit the file in a Lambda; the document did not.

    `load_items`, `attest` and `slack_interact` all read this through
    `json.loads`, and format 3 did not become format 4, so the bytes may be
    arranged any way that parses to the same thing -- and must parse to exactly
    the same thing, or a review's own evidence stops matching what wrote it.
    """
    built = build_items(demo)
    text = items_json(built, AS_OF, 90)
    # The indented form this replaced, spelled out rather than imported, so the
    # comparison survives the next change to how the file is written.
    indented = json.dumps(
        {"format": FORMAT, "review_date": AS_OF.isoformat(), "app_unused_days": 90,
         "items": [asdict(i) for i in built]},
        indent=2,
    ) + "\n"
    assert json.loads(text) == json.loads(indented)
    assert load_items(text) == load_items(indented) == built


def test_the_items_file_stays_one_item_per_line(demo):
    """Not decoration. `indent=2` is what this replaced, and the reason it was
    there -- a file a person can open, grep and diff -- is real: this is
    create-only evidence in S3 and the largest file a review writes. Encoding it
    as one long line would pass every round-trip test above and hand an auditor
    seventy megabytes on a single line.
    """
    built = build_items(demo)
    text = items_json(built, AS_OF, 90)
    lines = text.splitlines()
    assert len(lines) == len(built) + 2, "one line per item, plus the envelope's two"
    assert [json.loads(line.rstrip(","))["key"] for line in lines[1:-1]] == [i.key for i in built]
    # No line carries a second item: that is what makes a line greppable.
    assert all(line.count('"key":') == 1 for line in lines[1:-1])
    # And the last line is a line: every other file this review writes ends in
    # exactly one newline, and a bundle where one file does not is a diff an
    # auditor has to ask about.
    assert text.endswith("]}\n") and not text.endswith("\n\n")


def test_a_review_with_nothing_to_decide_writes_no_item_lines():
    """One line per item means none when there are none.

    A blank line where an item would go still parses -- JSON does not care --
    so nothing else here would catch it, and it would read as a review that
    wrote a row it could not fill rather than one with nothing to decide.
    """
    text = items_json([], AS_OF, 90)
    assert text.splitlines() == [text.rstrip("\n")], "the whole document is one line"
    assert json.loads(text)["items"] == [] and load_items(text) == []


def test_the_items_file_stays_one_line_per_item_whatever_the_text_holds(demo):
    """One item per line is what `indent=2` was traded for, and it rests on one
    thing: `json.dumps` escaping every non-ASCII character.

    `str.splitlines` -- how this file's readers count lines, and how the test
    above counts them -- breaks on U+2028 and U+2029 as well as on `\n`, and an
    Okta app label or a person's name is free text that may carry either.
    `attest`, `decisions` and `store` all pass `ensure_ascii=False`; the day a
    consistency pass reaches this writer, the document still parses and still
    loads, so nothing else here would say a word.
    """
    one = replace(build_items(demo)[0], target="App\u2028Two", name="Zo\u00eb\nSecond Line")
    text = items_json([one], AS_OF, 90)
    assert len(text.splitlines()) == 3, "the envelope, the one item, the closing brace"
    assert text.isascii(), "a non-ASCII byte in this file is a line break waiting to happen"
    assert load_items(text) == [one], "escaped, not mangled"


def test_the_items_file_records_the_review_date_and_threshold_it_was_written_with(demo):
    """The envelope is evidence too: an auditor reads it as the date the review
    was as of and the unused-app threshold every proposal in the file was made
    under.

    Nothing reads either back, so a wrong value is silent in a create-only
    object. The layout test above cannot catch one either: it rebuilds the
    expected envelope from the same arguments it passed in. Deliberately not
    `AS_OF` and not 90.
    """
    data = json.loads(items_json(build_items(demo), date(2025, 3, 31), 30))
    assert data["review_date"] == "2025-03-31"
    assert data["app_unused_days"] == 30
    assert data["format"] == 3, "the literal `load_items` and `attest` read, not whatever FORMAT is"


def test_the_items_file_is_yielded_a_row_at_a_time_and_never_whole(demo):
    """`write_report` streams this file straight to disk, and that only works
    while the chunks stay rows.

    The mutation this catches is the tidy-up: `yield items_json(...)`. Every
    other test here passes under it, because the joined document is
    byte-identical -- and the whole document is back in memory at exactly the
    point the report, the access matrix and the PDF are all live, which is the
    whole reason this function is separate from `items_json` at all.
    """
    built = build_items(demo)
    chunks = list(items_chunks(built, AS_OF, 90))
    assert "".join(chunks) == items_json(built, AS_OF, 90), "same document either way"
    assert len(chunks) == len(built) + 2, "the envelope, one chunk per item, the closing brace"
    for chunk, item in zip(chunks[1:-1], built, strict=True):
        # Only the separator may ride along: a chunk carrying two items is a
        # writer that has started batching, and the peak comes back with it.
        assert chunk.lstrip(",\n") == json.dumps(vars(item), ensure_ascii=True)

    # The empty file is the branch with no loop to carry it: no items, no
    # newline after the bracket, and the document is one line.
    empty = ('{"format": 3, "review_date": "2026-09-15", "app_unused_days": 90, "items": [', "]}\n")
    assert list(items_chunks([], AS_OF, 90)) == list(empty)


def test_the_items_file_encodes_one_item_at_a_time_and_never_all_of_them_first(demo):
    """Yielding rows is not the same as encoding them lazily, and only the
    second one is worth anything.

    `rows = [json.dumps(vars(i)) for i in items]` above the first yield leaves a
    generator that yields exactly the same chunks in exactly the same order, so
    the test above passes, the report test passes, and the whole encoded
    document is live before a single byte reaches the disk -- which is the peak
    this function exists to avoid. The only place the difference shows is in
    when the items are pulled, so that is what this asserts.
    """
    pulled = []

    class Watched(list):
        def __iter__(self):
            for item in super().__iter__():
                pulled.append(item)
                yield item

    chunks = items_chunks(Watched(build_items(demo)), AS_OF, 90)
    assert pulled == [], "a generator body must not run before the first next()"
    assert next(chunks).endswith('"items": ['), "the envelope"
    assert pulled == [], "the envelope cost an encoded document"
    next(chunks)
    assert len(pulled) == 1, "one row out, more than one item in: the rows were encoded up front"
    next(chunks)
    assert len(pulled) == 2
