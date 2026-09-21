"""The review card and the sign-off list, as pure functions.

Only what a reviewer reads on the screen that settles an item. The rest of
slack_review is covered end to end through tests/test_workflow.py.
"""

from access_review.items import CISO, CROSS_SOURCE, DECIDE, KEEP, REVOKE, ReviewItem
from access_review.slack_review import card_lines, decision_lines

OUTSIDE = ("They still hold GitHub organization owner (AR-17 Someone who left still has access "
           "outside Okta; tied to them by the identity provider's own assertion)")
CONCERN = "No MFA factor enrolled (AR-04 No MFA)"


def item(kind="app", concerns=(), outside_okta=(), proposed=KEEP) -> ReviewItem:
    return ReviewItem(
        "k1", kind, "u1", "marcus.lee@acme.example", "t1", "Salesforce", "direct",
        proposed, "Signed in 2026-09-01.", CISO, name="Marcus Lee",
        facts=("Okta: ACTIVE", "Access: Salesforce (assigned directly)"),
        concerns=concerns, outside_okta=outside_okta,
    )


def test_access_outside_okta_is_its_own_block_above_the_rest():
    """It is the part of the picture no other screen in this review reaches, and
    the part deciding this item cannot change. Below three Okta notes it reads
    as one more thing to tick off."""
    lines = card_lines(item(concerns=(CONCERN,), outside_okta=(OUTSIDE,)))
    outside = next(n for n, ln in enumerate(lines) if ln.startswith("*Access outside Okta*"))
    why = lines.index("*Why it could be an issue*")
    assert outside < why
    assert "does not change it" in lines[outside] and "its own ticket" in lines[outside]
    assert any("AR-17" in ln for ln in lines[outside:why])
    assert any("AR-04" in ln for ln in lines[why:])


def test_a_card_with_nothing_outside_okta_has_no_such_block():
    lines = card_lines(item(concerns=(CONCERN,)))
    assert not any(ln.startswith("*Access outside Okta*") for ln in lines)
    assert "*Why it could be an issue*" in lines


def test_nothing_flagged_in_okta_does_not_read_as_nothing_flagged():
    """The Okta side being clean is exactly the case the cross-source checks
    exist for. "Nothing flagged." under a critical block above it would be the
    review contradicting itself on one screen."""
    lines = card_lines(item(kind=CROSS_SOURCE, outside_okta=(OUTSIDE,), proposed=DECIDE))
    assert "• Nothing else flagged." in lines
    assert "• Nothing flagged." not in lines
    # And with no graph at all, the plain wording is still what is shown.
    assert "• Nothing flagged." in card_lines(item())


def test_the_signoff_list_says_which_concerns_the_decision_did_not_settle():
    """What the CISO is signing. A revoke line that lists an untouchable GitHub
    role among its reasons reads as though signing off dealt with it."""
    mine = item(concerns=(CONCERN,), outside_okta=(OUTSIDE,), proposed=REVOKE)
    grouped = decision_lines([mine], {mine.key: {"decision": REVOKE, "reason": ""}})
    line = grouped[REVOKE][0]
    assert "outside Okta, not changed by this decision:" in line
    assert "AR-17" in line.split("outside Okta, not changed by this decision:")[1]
    assert f":warning: {CONCERN}" in line
