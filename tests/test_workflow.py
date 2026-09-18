import hashlib
import hmac
import json
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fakes import FakeBot, FakeS3, FakeSfn
from test_watch import FakeJira

from access_review import store, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import DECIDE, KEEP, REVOKE
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
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

    assert out == {"run": run, "items": len(items), "urgent_tickets": 3}
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
    assert "Revoke (7)" in text and "Keep (9)" in text
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
