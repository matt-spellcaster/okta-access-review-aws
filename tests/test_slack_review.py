"""The review card and the sign-off list, as pure functions.

Only what a reviewer reads on the screen that settles an item. The rest of
slack_review is covered end to end through tests/test_workflow.py.
"""

from access_review.items import CISO, CROSS_SOURCE, DECIDE, KEEP, REVOKE, ReviewItem
import json

from access_review.slack_review import OUTSIDE, card_lines, checklist_message, decision_lines, describe

# The heading is read off slack_review rather than spelled again here: it is one
# wording used by the card, the item line and the sign-off list, and a test that
# spelled it itself would go on passing while two of the three had drifted.
HEADING = f"*{OUTSIDE}*"
HELD = ("They still hold GitHub organization owner (AR-17 Someone who left still has access "
        "outside Okta; tied to them by the identity provider's own assertion)")
CONCERN = "No MFA factor enrolled (AR-04 No MFA)"


def item(kind="app", concerns=(), outside_okta=(), proposed=KEEP, gap="") -> ReviewItem:
    return ReviewItem(
        "k1", kind, "u1", "marcus.lee@acme.example", "t1", "Salesforce", "direct",
        proposed, "Signed in 2026-09-01.", CISO, name="Marcus Lee",
        facts=("Okta: ACTIVE", "Access: Salesforce (assigned directly)"),
        concerns=concerns, outside_okta=outside_okta, outside_okta_gap=gap,
    )


def test_access_outside_okta_is_its_own_block_above_the_rest():
    """It is the part of the picture no other screen in this review reaches, and
    the part deciding this item cannot change. Below three Okta notes it reads
    as one more thing to tick off."""
    lines = card_lines(item(concerns=(CONCERN,), outside_okta=(HELD,)))
    outside = next(n for n, ln in enumerate(lines) if ln.startswith(HEADING))
    why = lines.index("*Why it could be an issue*")
    assert outside < why
    assert "does not change it" in lines[outside] and "its own ticket" in lines[outside]
    assert any("AR-17" in ln for ln in lines[outside:why])
    assert any("AR-04" in ln for ln in lines[why:])


def test_a_card_with_nothing_outside_okta_has_no_such_block():
    lines = card_lines(item(concerns=(CONCERN,)))
    assert not any(ln.startswith(HEADING) for ln in lines)
    assert "*Why it could be an issue*" in lines


def test_a_review_that_read_no_other_source_says_so_on_the_card():
    """The silence-is-not-absence trap, in the one place the decision is made.
    With no block at all the reviewer reads "Nothing flagged" and takes it as a
    clean bill of health, when nothing looked."""
    gap = "No source other than Okta was read in this review, so what they hold elsewhere is not known."
    lines = card_lines(item(concerns=(CONCERN,), gap=gap))
    assert any(ln.startswith(HEADING) for ln in lines)
    assert any(gap in ln for ln in lines)
    # A read that did not finish is its own answer, not the same as finding nothing.
    short = "The github:acme-eng read did not complete, so what they hold there may be missing from this list."
    held = card_lines(item(outside_okta=(HELD,), gap=short))
    assert any("AR-17" in ln for ln in held) and any(short in ln for ln in held)
    # And a complete read that found nothing says nothing, which is the only
    # case where the absence is evidence.
    assert not any(ln.startswith(HEADING) for ln in card_lines(item()))


def test_nothing_flagged_in_okta_does_not_read_as_nothing_flagged():
    """The Okta side being clean is exactly the case the cross-source checks
    exist for. "Nothing flagged." under a critical block above it would be the
    review contradicting itself on one screen."""
    lines = card_lines(item(kind=CROSS_SOURCE, outside_okta=(HELD,), proposed=DECIDE))
    assert "• Nothing else flagged." in lines
    assert "• Nothing flagged." not in lines
    # And with no graph at all, the plain wording is still what is shown.
    assert "• Nothing flagged." in card_lines(item())


def test_a_label_from_another_source_cannot_become_a_slack_mention():
    """This text is built from a foreign source's own values -- a GitHub login,
    a role label, a credential hint -- so it is settable by someone who is not
    in Okta at all. Unescaped, it can address the reviewer or fake a link on the
    card that settles the item."""
    hostile = ("github:acme-eng still shows <@U0CISO00001> active "
               "(AR-17 Access outside Okta; tied to them by an assertion)")
    lines = card_lines(item(outside_okta=(hostile,)))
    assert any("&lt;@U0CISO00001&gt;" in ln for ln in lines)
    assert not any("<@U0CISO00001>" in ln for ln in lines)
    mine = item(outside_okta=(hostile,), proposed=REVOKE)
    grouped = decision_lines([mine], {mine.key: {"decision": REVOKE, "reason": ""}})
    assert "<@U0CISO00001>" not in grouped[REVOKE][0]
    flagged = item(kind=CROSS_SOURCE, outside_okta=(hostile,), proposed=DECIDE)
    signed = decision_lines([flagged], {flagged.key: {"decision": KEEP, "reason": ""}})
    assert "<@U0CISO00001>" not in signed["flagged"][0]


def test_a_cross_source_item_is_signed_off_with_its_findings_shown():
    """The only item kind that exists to report access elsewhere. A one-line
    entry would have the CISO signing off the one thing the screen never showed."""
    mine = item(kind=CROSS_SOURCE, outside_okta=(HELD,), proposed=DECIDE)
    grouped = decision_lines([mine], {mine.key: {"decision": KEEP, "reason": ""}})
    line = grouped["flagged"][0]
    assert "acknowledged" in line and "AR-17" in line, line


def entry(ticket="UAR-9", todo="Unassign lee.chen from Salesforce", verify="okta",
          verified=None, accepted=False):
    return {"ticket": (ticket, f"https://acme.atlassian.net/browse/{ticket}"), "todo": todo,
            "due": "2026-09-23", "verified": verified, "accepted": accepted,
            "label": f"uar-key-{ticket}", "verify": verify}


def checklist_lines(entries):
    """The ticket lines only, not the trailing How context block.

    Asserting over the whole message JSON would match the How text, which names
    the same phrase -- so the per-line marker could vanish and the assertion
    would still hold.
    """
    msg = checklist_message("run-1", ("UAR-1", None), entries)
    return [ln for b in msg["blocks"] if b["type"] == "section"
            for ln in b["text"]["text"].split("\n") if "UAR-" in ln]


def test_the_checklist_says_which_lines_the_daily_check_will_not_confirm():
    """Before anything is ticked. A checklist that only distinguishes them after
    the fact leaves the reader assuming Okta gets consulted for every line, and
    for a cross-source finding it never can be."""
    okta = entry("UAR-9")
    word = entry("UAR-14", "Someone who left still has access outside Okta (AR-17) for github:acme-eng/U_1",
                 verify="reviewer")
    lines = checklist_lines([okta, word])
    marked = [ln for ln in lines if "taken on your word" in ln]
    assert len(marked) == 1 and "UAR-14" in marked[0], lines
    # And the Okta line carries no marker, so the mark means something.
    assert not any("taken on your word" in ln for ln in checklist_lines([okta]))


def test_the_checklist_explanation_covers_every_kind_taken_on_the_reviewers_word():
    """It enumerated the judgement calls (inactive accounts, contractor
    exceptions, API client scopes) and stopped there, so a GitHub ticket sat
    ticked among Okta-verified ones with the text implying Okta had confirmed it.

    AR-18 is the third kind and fits neither: a service account handed to a new
    owner, which can be an Okta API client, so "in another source" would be as
    wrong for it as the original enumeration was for GitHub. What the line may
    claim is the one thing true of all of them -- this review does not look
    again -- and it must not imply Okta cannot see the change.
    """
    how = json.dumps(checklist_message("run-1", ("UAR-1", None), [entry(verify="reviewer")]))
    assert "another source" in how and "service account" in how
    assert "does not re-read it" in how
    assert "cannot be checked in Okta" not in how


def test_the_checklist_still_distinguishes_them_after_ticking():
    done_in_okta = entry("UAR-9", verified="2026-09-18")
    on_word = entry("UAR-14", verify="reviewer", verified="2026-09-18", accepted=True)
    text = json.dumps(checklist_message("run-1", ("UAR-1", None), [done_in_okta, on_word]))
    assert "verified 2026-09-18" in text and "resolved 2026-09-18" in text


def test_the_signoff_list_says_which_concerns_the_decision_did_not_settle():
    """What the CISO is signing. A revoke line that lists an untouchable GitHub
    role among its reasons reads as though signing off dealt with it."""
    mine = item(concerns=(CONCERN,), outside_okta=(HELD,), proposed=REVOKE)
    grouped = decision_lines([mine], {mine.key: {"decision": REVOKE, "reason": ""}})
    line = grouped[REVOKE][0]
    assert "not changed by this decision:" in line
    assert "AR-17" in line.split("not changed by this decision:")[1]
    assert f":warning: {CONCERN}" in line


def test_none_of_the_wording_claims_the_finding_is_outside_okta():
    """What every other test here pins is placement, not the claim.

    They all read the heading off `OUTSIDE`, which is right -- one wording in
    three places, and a test spelling it again would pass while two of them
    drifted -- but it means reverting the constant to "Access outside Okta"
    leaves the suite green. That sentence is false for the case the block now
    exists for: AR-18's two demo subjects are Okta API clients, in Okta, which
    deactivating their owner's account does not touch. The card, the item
    written into the signed review_items.json and the ticket paragraph all have
    to say what is not settled, never where the account lives.
    """
    from access_review.items import CROSS_SOURCE_REASON, CROSS_SOURCE_TARGET
    from access_review.tickets import _scope_to_okta

    # An AR-18 concern, not AR-17's: the payload here is a finding about an Okta
    # API client, so anything the framing adds about "outside Okta" is the
    # review's own false claim rather than a check title quoted verbatim.
    owned = ("Terraform Automation: Marcus Lee left 2026-08-29 (AR-18 Service account owned by "
             "someone who left; declared a service account in the review register)")
    written = [OUTSIDE, CROSS_SOURCE_TARGET, CROSS_SOURCE_REASON]
    written += card_lines(item(outside_okta=(owned,)))
    # The lines themselves, not the group names: `decision_lines` returns a
    # dict, and adding one to a list adds its keys -- which is how a revert of
    # the sign-off wording once passed this test. With an outside_okta concern,
    # or the ":warning: not changed by this decision" line is never rendered.
    cross = item(kind=CROSS_SOURCE, outside_okta=(owned,), proposed=DECIDE)
    kept = item(outside_okta=(owned,), proposed=DECIDE)
    signoff = [line for lines in decision_lines([cross, kept], {i.key: {"decision": KEEP, "reason": ""}
                                                                for i in (cross, kept)}).values()
               for line in lines]
    assert any("AR-18" in line and "not changed by this decision" in line for line in signoff), signoff
    written += signoff
    written.append(describe(cross))
    written += _scope_to_okta((owned,), "", "Closing their way in through Okta")

    for text in written:
        assert "outside okta" not in json.dumps(text).lower(), text
    # And the heading and the stored target are the same words, so a reword
    # cannot land on the card and miss the file an auditor reads.
    assert CROSS_SOURCE_TARGET == OUTSIDE
