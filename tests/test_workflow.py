import hashlib
import hmac
import json
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fakes import FakeBot, FakeClientError, FakeS3, FakeSfn
from test_watch import FakeJira

from access_review import store, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import DECIDE, HR_RECORD, KEEP, REVOKE
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.slack import SlackError
from access_review.slack_interact import ItemCache, front, verify_signature, worker
from access_review.state import CLOSED, SIGNED_OFF, load_state
from access_review.tickets import Remediation

FIXTURES = Path(__file__).parent.parent / "fixtures"
R = Reviewers(ciso="U0CISO00001")
CISO_DM = "D0CISO00001"
STRANGER = "U0STRANGER1"
SECRET = "test-signing-secret-not-real"
NOW = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
SITE = "https://acme.atlassian.net/browse/"


@pytest.fixture
def env(tmp_path):
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True)
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    jira = FakeJira()
    jira.today = "2026-09-16"
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=FakeBot(), reviewers=R,
                         channel="C0REVIEW001", tickets=Remediation(jira, s3, "evidence", "Task", "Sub-task",
                                                                    now=lambda: NOW),
                         sfn=FakeSfn(), now=lambda: NOW, ticket_url=lambda key: SITE + key)
    return deps, run.run_dir.name, {i.key: i for i in run.items}


def posts_to(deps, channel):
    return [json.dumps(p) for c, p, _ in deps.bot.posts if c == channel]


def decide_everything(deps, run, items):
    src = {"team": "T0TEAM0001", "channel": CISO_DM, "message_ts": "1"}
    workflow.confirm(deps, run, R.ciso, src)
    for key, item in items.items():
        if item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], R.ciso, src)


def test_opening_posts_counts_to_the_channel_and_everything_else_to_the_ciso(env):
    deps, run, items = env
    out = workflow.open_review(deps, run, "token-1")

    assert out == {"run": run, "items": len(items), "urgent_tickets": 2}
    [channel] = posts_to(deps, deps.channel)
    assert "@acme.example" not in channel and "Salesforce" not in channel
    assert f"<{SITE}UAR-1|UAR-1>" in channel  # the tracking ticket, linked
    # One DM, to the CISO, with every item: nobody else is messaged.
    assert {c for c, _, _ in deps.bot.posts} == {deps.channel, CISO_DM}
    dm = " ".join(posts_to(deps, CISO_DM))
    for login in {i.user for i in items.values()}:
        assert login in dm
    # A leaver's items link straight to their leaver ticket.
    assert "marcus.lee@acme.example" in dm and f"Leaver ticket <{SITE}UAR-" in dm
    state, _ = load_state(deps.s3, "work", run)
    assert state["task_token"] == "token-1" and set(state["dms"]) == {"ciso"}
    # Retried by Step Functions: nothing is posted twice.
    before = len(deps.bot.posts)
    assert workflow.open_review(deps, run, "token-2")["reopened"]
    assert len(deps.bot.posts) == before


def test_the_signoff_message_lists_every_decision_next_to_the_button(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)

    [(channel, approve)] = [(c, p) for c, p, _ in deps.bot.posts if '"action_id": "approve"' in json.dumps(p)]
    text = json.dumps(approve)
    assert channel == CISO_DM
    for item in items.values():  # every item, in full, in the one message
        assert item.user in text and item.target in text
    assert "Revoke (7)" in text and "Keep (10)" in text
    assert f"<{SITE}UAR-1|UAR-1>" in text
    assert approve["blocks"][-1]["type"] == "actions"  # the button comes right after the list
    assert deps.bot.uploads and deps.bot.uploads[0][3] == b"%PDF"


def test_an_override_is_called_out_on_the_signoff_message(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    revoke_key = next(k for k, i in items.items() if i.proposed == REVOKE)
    workflow.record(deps, run, [(revoke_key, KEEP, "Needed for quarter-end reporting")], R.ciso, {})
    decide_everything(deps, run, items)
    [approve] = [json.dumps(p) for _, p, _ in deps.bot.posts if '"action_id": "approve"' in json.dumps(p)]
    assert "overrode proposed revoke" in approve and "Needed for quarter-end reporting" in approve


def test_full_review_finishes_with_a_summary_in_the_channel(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)

    out = workflow.approve(deps, run, R.ciso, {"team": "T0TEAM0001", "channel": CISO_DM, "message_ts": "9"})
    assert out["decided"] == out["total"] == len(items) and out["revoke"] == 7
    [(token, sent)] = deps.sfn.successes
    assert token == "token-1" and "@" not in sent  # counts and hashes only
    state, _ = load_state(deps.s3, "work", run)
    assert state["status"] == SIGNED_OFF and state["callback_sent"]

    workflow.remediate(deps, run)
    finished = posts_to(deps, deps.channel)[-1]
    assert "is finished" in finished and f"<@{R.ciso}>" in finished
    assert "AR-01" in finished and "7 revoke" in finished and f"<{SITE}UAR-1|UAR-1>" in finished
    assert "@acme.example" not in finished and "Salesforce" not in finished  # counts only

    with pytest.raises(workflow.ReviewClosed):
        workflow.approve(deps, run, R.ciso, {})
    with pytest.raises(workflow.ReviewClosed):
        workflow.record(deps, run, [(next(iter(items)), KEEP, "late")], R.ciso, {})


def test_signoff_is_refused_while_items_are_open(env):
    deps, run, _ = env
    workflow.open_review(deps, run, "token-1")
    with pytest.raises(workflow.DecisionError, match="still need a decision"):
        workflow.approve(deps, run, R.ciso, {})
    assert deps.sfn.successes == []


def test_a_stopped_review_is_closed_once(env):
    deps, run, _ = env
    workflow.open_review(deps, run, "token-1")
    assert workflow.close_review(deps, run, "stopped") is True
    assert load_state(deps.s3, "work", run)[0]["status"] == CLOSED
    assert workflow.close_review(deps, run, "stopped") is False
    assert workflow.close_review(deps, "20990101T000000Z", "never opened") is False


# --- the HTTP front end ---

def signed(payload, secret=SECRET, ts=None):
    ts = str(int(ts if ts is not None else time.time()))
    body = urlencode({"payload": json.dumps(payload)})
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
    return {"body": body, "headers": {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}}


def click(run, key, decision, user, chunk=0):
    return {"type": "block_actions", "user": {"id": user}, "team": {"id": "T0TEAM0001"}, "trigger_id": "trig",
            "container": {"channel_id": CISO_DM, "message_ts": "1758000000.000002"},
            "actions": [{"action_id": f"decide:{decision}",
                         "value": json.dumps({"r": run, "k": key, "c": chunk})}]}


@pytest.fixture
def frontend(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    queue = []

    def call(event, **kw):
        return front(event, SECRET, R, ItemCache(deps.s3, "evidence"), deps.bot, queue.append, **kw)

    return deps, run, items, queue, call


def test_bad_or_stale_signatures_get_a_bare_401(frontend):
    deps, run, items, queue, call = frontend
    key = next(iter(items))
    assert call(signed(click(run, key, KEEP, R.ciso), secret="wrong"))["statusCode"] == 401
    assert call(signed(click(run, key, KEEP, R.ciso), ts=time.time() - 600))["statusCode"] == 401
    assert call({"body": "payload=%7B%7D", "headers": {}})["statusCode"] == 401
    assert queue == []
    assert not verify_signature(SECRET, {"X-Slack-Request-Timestamp": "abc", "X-Slack-Signature": "v0=1"}, b"")


def test_anyone_but_the_ciso_is_ignored(frontend):
    deps, run, items, queue, call = frontend
    key = next(k for k, i in items.items() if i.proposed == KEEP)
    assert call(signed(click(run, key, KEEP, STRANGER)))["statusCode"] == 200
    assert queue == []
    call(signed(click(run, key, KEEP, R.ciso)))
    assert queue[0]["choices"] == [[key, KEEP, ""]]


def test_a_decision_needing_a_reason_opens_the_modal_first(frontend):
    deps, run, items, queue, call = frontend
    key = next(k for k, i in items.items() if i.proposed == REVOKE)

    call(signed(click(run, key, KEEP, R.ciso)))

    assert queue == []
    [(trigger, view)] = deps.bot.modals
    assert trigger == "trig" and view["callback_id"] == "reason"
    submit = {"type": "view_submission", "user": {"id": R.ciso}, "view": {
        "callback_id": "reason", "private_metadata": view["private_metadata"],
        "state": {"values": {"reason": {"text": {"value": "   "}}}}}}
    resp = call(signed(submit))
    assert json.loads(resp["body"])["response_action"] == "errors"
    submit["view"]["state"]["values"]["reason"]["text"]["value"] = "Needed for the Q4 audit"
    call(signed(submit))
    [job] = queue
    assert job["choices"] == [[key, KEEP, "Needed for the Q4 audit"]]

    assert worker(job, deps)["ok"]
    [(_, rec)] = store.list_records(deps.s3, "evidence", run, "decisions")
    assert rec["decisions"][0]["reason"] == "Needed for the Q4 audit"


def test_the_worker_rechecks_permissions_itself(frontend):
    deps, run, items, queue, call = frontend
    forged = {"action": "decide", "run": run, "choices": [[next(iter(items)), KEEP, "x"]], "user": STRANGER,
              "source": {"channel": CISO_DM}}
    assert worker(forged, deps) == {"ok": False, "run": run}
    assert store.list_records(deps.s3, "evidence", run, "decisions") == []
    assert worker({"action": "approve", "run": run, "user": STRANGER, "source": {}}, deps)["ok"] is False


def test_channel_posts_after_opening_go_in_the_reviews_thread(env):
    deps, run, items = env
    deps.channel_pdf = True
    workflow.open_review(deps, run, "token-1")
    state, _ = load_state(deps.s3, "work", run)
    thread = state["channel_ts"]
    # The report goes in the channel's thread as well as the approver's.
    assert (deps.channel, f"okta-access-review-{run}.pdf", thread, b"%PDF") in deps.bot.uploads
    decide_everything(deps, run, items)
    workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})
    workflow.remediate(deps, run)
    finished = [p for c, p, _ in deps.bot.posts if c == deps.channel][-1]
    assert finished["thread_ts"] == thread and finished["reply_broadcast"] is True
    assert "to fix findings" in json.dumps(finished)


def test_no_report_in_the_channel_unless_turned_on(env):
    deps, run, _ = env
    workflow.open_review(deps, run, "token-1")
    assert not [u for u in deps.bot.uploads if u[0] == deps.channel]


@pytest.fixture
def graph_env(tmp_path):
    """The same environment with GitHub read too, so items carry access Okta
    cannot see and the leaver tickets have to say what they do not cover."""
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True,
                     github_path=FIXTURES / "demo_github.json")
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    jira = FakeJira()
    jira.today = "2026-09-16"
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=FakeBot(), reviewers=R,
                         channel="C0REVIEW001", tickets=Remediation(jira, s3, "evidence", "Task", "Sub-task",
                                                                    now=lambda: NOW),
                         sfn=FakeSfn(), now=lambda: NOW, ticket_url=lambda key: SITE + key)
    return deps, run.run_dir.name, {i.key: i for i in run.items}


def test_a_cross_source_fix_ticket_is_marked_as_taken_on_your_word(graph_env):
    """The case the whole chain exists for, and the one the fixtures without a
    graph cannot reach. AR-15..AR-17 ask for a change in a source this review
    cannot re-read, so they settle on the reviewer's word -- and if they were
    ever counted as Okta-verified the closing claim would be back to asserting a
    check that never ran."""
    deps, run, items = graph_env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)
    workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})
    workflow.remediate(deps, run)
    entries = workflow.checklist_entries(deps, run)
    cross = [e for e in entries if "(AR-17)" in e["todo"]]
    assert cross, [e["todo"] for e in entries]
    assert all(e["verify"] == "reviewer" for e in cross), cross
    parent = load_state(deps.s3, "work", run)[0]["parent_issue"]
    checklist = [b for k, b in deps.tickets.jira.comments if k == parent and "To close" in b][-1]
    for e in cross:
        line = next(p for p in json.loads(checklist)["content"]
                    if e["ticket"][0] in json.dumps(p))
        assert "taken on your word" in json.dumps(line), line


def test_opening_a_review_tells_the_leaver_ticket_what_it_cannot_close(graph_env):
    """open_review builds the leaver tickets, and only it has the items that know
    what each person holds elsewhere. Wire that up wrong and the ticket goes back
    to promising it removes every way in, verified against Okta alone -- which is
    the whole defect, restored at the call site rather than in the builder."""
    deps, run, _ = graph_env
    workflow.open_review(deps, run, "token-1")
    marcus = next(f for f in deps.tickets.jira.issues.values()
                  if f["summary"] == "Remove access for leaver marcus.lee@acme.example")
    body = json.dumps(marcus["description"])
    assert "Not part of this ticket" in body, body
    assert "AR-17" in body, "the leaver ticket never names what it cannot close"


def test_the_closing_claim_counts_the_two_kinds_of_evidence_apart():
    """The sentence an auditor reads when a review closes. "Verified in Okta" and
    "the reviewer said so" are not the same evidence, and a single count cannot
    say which happened."""
    def e(verified, accepted):
        return {"verified": verified, "accepted": accepted}

    both = [e("2026-09-18", False), e("2026-09-18", False), e("2026-09-18", True), e(None, False)]
    assert workflow.settled_counts(both) == (2, 1, 1), "the unverified one is neither, and is counted"
    assert workflow.how_settled(2, 1) == (
        "2 verified against a fresh Okta snapshot, 1 resolved on the reviewer's word "
        "(this review does not re-read these to confirm the fix)")
    # Not a claim about where the finding lives or what kind of answer it wants:
    # AR-18 settles this way and can be an Okta API client.
    assert "another source" not in workflow.how_settled(0, 1)
    # All one kind: say that kind, and nothing about the other.
    assert workflow.how_settled(3, 0) == "3 verified against a fresh Okta snapshot"
    assert "Okta snapshot" not in workflow.how_settled(0, 3)
    assert workflow.how_settled(0, 3).startswith("3 resolved on the reviewer's word")
    # A review with nothing to fix must not report zero verifications as a check.
    assert workflow.how_settled(0, 0) == "there was nothing to fix"
    # A ticket with no verification record is named, not absorbed into either
    # count: the close decision is made over pending tickets, these counts are
    # over all of them, and the two can disagree.
    assert workflow.how_settled(2, 1, 1).endswith("1 with no verification record on file")
    assert workflow.how_settled(0, 0, 2) == "2 with no verification record on file"
    # "Every ticket is settled" is a claim about all of them, so it is printed
    # only when the counts add up to all of them.
    every = workflow.closing_claim([e("2026-09-18", False), e("2026-09-18", True)], "2026-09-18")
    assert every.startswith("Every ticket under this review is settled as of 2026-09-18:")
    short = workflow.closing_claim([e("2026-09-18", False), e(None, False)], "2026-09-18")
    assert short.startswith("This review is closing as of")
    assert "1 with no verification record on file" in short
    assert "Every ticket" not in short


def test_the_finished_post_does_not_say_every_ticket_ends_up_verified(env):
    """The widest audience of the four: the review channel. It said the tracking
    ticket "closes once all are verified" over a count that includes the fix
    tickets Okta is never consulted for."""
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)
    workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})
    workflow.remediate(deps, run)
    finished = [p for c, p, _ in deps.bot.posts if c == deps.channel][-1]
    text = json.dumps(finished)
    assert "closes once all are verified" not in text
    assert "resolved on the reviewer's word" in text and "settled" in text


def test_the_tracking_ticket_does_not_say_every_line_is_verified_in_okta(env):
    """post_checklist opened with "each of these must be done and verified in
    Okta" over a list that includes tickets Okta is never consulted for."""
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)
    workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})
    workflow.remediate(deps, run)
    parent = load_state(deps.s3, "work", run)[0]["parent_issue"]
    checklist = [b for k, b in deps.tickets.jira.comments if k == parent and "To close" in b][-1]
    assert "verified in Okta" not in checklist
    assert "its own ticket resolved" in checklist
    assert "taken on your word, not re-read in Okta" in checklist
    entries = workflow.checklist_entries(deps, run)
    assert {e["verify"] for e in entries} == {"okta", "reviewer"}, "both kinds in this run"
    # A revoke or leaver ticket asks for a change in Okta, so it is re-read there.
    assert all(e["verify"] == "okta" for e in entries if "Unassign" in e["todo"])


def test_item_cards_show_facts_then_why(env):
    deps, run, _ = env
    workflow.open_review(deps, run, "token-1")
    dm = " ".join(posts_to(deps, CISO_DM))
    assert "*Facts*" in dm and "*Why it could be an issue*" in dm
    assert dm.index("*Facts*") < dm.index("*Why it could be an issue*") < dm.index("*Proposed:")
    assert "Lee Chen" in dm and "MFA: none" in dm


# --- retries and failures part-way through ---

def test_a_retried_open_finishes_what_the_first_attempt_did_not(env):
    deps, run, items = env
    real, failed = deps.bot.post_message, []

    def flaky(channel, payload):
        if channel == CISO_DM and not failed:
            failed.append(True)
            raise RuntimeError("Slack is down")
        return real(channel, payload)

    deps.bot.post_message = flaky
    with pytest.raises(RuntimeError):
        workflow.open_review(deps, run, "token-1")
    # The tickets were opened, but nothing reached the CISO or the channel.
    state, _ = load_state(deps.s3, "work", run)
    assert state["parent_issue"] == "UAR-1" and state["dms"] == {} and "channel_ts" not in state
    opened = len(deps.tickets.jira.issues)

    out = workflow.open_review(deps, run, "token-2")

    assert out["reopened"] and out["items"] == len(items)
    state, _ = load_state(deps.s3, "work", run)
    assert state["task_token"] == "token-2" and set(state["dms"]) == {"ciso"} and state["channel_ts"]
    assert len(posts_to(deps, deps.channel)) == 1
    assert len(deps.tickets.jira.issues) == opened  # found by label, not opened again


def test_a_signoff_interrupted_after_its_first_write_finishes_on_retry(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    decide_everything(deps, run, items)
    real, failed = deps.s3.put_object, []

    def flaky(**kw):
        if kw["Key"].endswith("signoff/attestation.json") and not failed:
            failed.append(True)
            raise FakeClientError("InternalError")
        return real(**kw)

    deps.s3.put_object = flaky
    with pytest.raises(store.StoreError):
        workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})
    assert load_state(deps.s3, "work", run)[0]["status"] != SIGNED_OFF and deps.sfn.successes == []

    out = workflow.approve(deps, run, R.ciso, {"channel": CISO_DM})  # the CISO clicks again

    assert out["revoke"] == 7
    state, _ = load_state(deps.s3, "work", run)
    assert state["status"] == SIGNED_OFF and state["callback_sent"] and len(deps.sfn.successes) == 1


def test_the_approve_button_is_posted_even_if_redrawing_the_cards_fails(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    workflow.confirm(deps, run, R.ciso, {})
    undecided = [k for k, i in items.items() if i.proposed == DECIDE]
    for key in undecided[:-1]:
        workflow.record(deps, run, [(key, KEEP, "")], R.ciso, {})

    def broken(channel, ts, payload):
        raise SlackError("chat.update: ratelimited")

    deps.bot.update_message = broken
    with pytest.raises(SlackError):
        workflow.record(deps, run, [(undecided[-1], KEEP, "")], R.ciso, {})
    assert any('"action_id": "approve"' in json.dumps(p) for _, p, _ in deps.bot.posts)


def test_a_click_redraws_only_its_own_item_message(frontend):
    deps, run, items, queue, call = frontend
    key = next(k for k, i in items.items() if i.proposed == KEEP)
    call(signed(click(run, key, KEEP, R.ciso, chunk=0)))
    [job] = queue
    assert job["chunk"] == 0
    before = len(deps.bot.updates)
    worker(job, deps)
    dm = load_state(deps.s3, "work", run)[0]["dms"]["ciso"]
    assert [ts for _, ts, _ in deps.bot.updates[before:]] == [dm["summary_ts"], dm["chunks"][0]]


def test_messages_state_the_configured_windows(env):
    deps, run, items = env
    deps.revoke_days = 14
    workflow.open_review(deps, run, "token-1")
    assert "no sign-in in 90 days" in " ".join(posts_to(deps, CISO_DM))  # the demo config's app_unused_days
    decide_everything(deps, run, items)
    [approve] = [json.dumps(p) for _, p, _ in deps.bot.posts if '"action_id": "approve"' in json.dumps(p)]
    assert "due in 14 days" in approve


def test_an_account_with_no_hr_record_is_flagged_and_acknowledged_not_ticketed(env):
    deps, run, items = env
    [flag] = [i for i in items.values() if i.kind == HR_RECORD]
    assert flag.user == "jordan.kim@acme.example" and flag.proposed == DECIDE
    workflow.open_review(deps, run, "token-1")
    dm = " ".join(posts_to(deps, CISO_DM))
    assert "no ticket is opened for it" in dm and '"text": "Acknowledge"' in dm and "Flag for HR" in dm.replace("flag for HR", "Flag for HR")
    # Only an acknowledgement is accepted for it, and it is never confirmed in bulk.
    with pytest.raises(workflow.DecisionError, match="acknowledged"):
        workflow.record(deps, run, [(flag.key, REVOKE, "")], R.ciso, {})
    workflow.confirm(deps, run, R.ciso, {})
    assert flag.key not in workflow.current_decisions(deps, workflow.load_run(deps, run))

    for key, item in items.items():  # the CISO clicks Acknowledge along with the other calls
        if item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], R.ciso, {})
    [approve] = [json.dumps(p) for _, p, _ in deps.bot.posts if '"action_id": "approve"' in json.dumps(p)]
    assert "Flagged for HR (1), no ticket" in approve and "Keep (10)" in approve and "1 flagged for HR" in approve
    workflow.approve(deps, run, R.ciso, {})
    workflow.remediate(deps, run)
    assert not any("HR record" in f["summary"] for f in deps.tickets.jira.issues.values())
    finished = posts_to(deps, deps.channel)[-1]
    assert "10 keep, 7 revoke" in finished and "1 account(s) with no HR record" in finished and "no ticket" in finished
