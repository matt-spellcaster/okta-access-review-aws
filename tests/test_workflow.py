import hashlib
import hmac
import json
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fakes import FakeBot, FakeS3, FakeSfn

from access_review import store, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import ADMIN, CISO, DECIDE, KEEP, REVOKE
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.slack_interact import ItemCache, front, verify_signature, worker
from access_review.state import SIGNED_OFF, load_state

FIXTURES = Path(__file__).parent.parent / "fixtures"
R = Reviewers(admin="U0ADMIN0001", ciso="U0CISO00001")
SECRET = "test-signing-secret-not-real"
NOW = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)


class FakeTickets:
    def __init__(self):
        self.parents, self.urgent = [], []

    def open_parent(self, run, manifest, manifest_sha, counts, due_at):
        self.parents.append((run, counts))
        return "UAR-1"

    def open_urgent(self, run, parent, findings):
        self.urgent.append((run, parent, sorted({(f["check_id"], f["subject"]) for f in findings})))
        return len(findings)


@pytest.fixture
def env(tmp_path):
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    config.admin_login = "priya.shah@acme.example"
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True)
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=FakeBot(), reviewers=R,
                         channel="C0REVIEW001", tickets=FakeTickets(), sfn=FakeSfn(), now=lambda: NOW)
    return deps, run.run_dir.name, {i.key: i for i in run.items}


def texts(payloads):
    return json.dumps(payloads)


def test_opening_posts_counts_to_the_channel_and_items_only_in_dms(env):
    deps, run, items = env
    out = workflow.open_review(deps, run, "token-1")

    assert out == {"run": run, "items": len(items), "urgent_tickets": 6}
    channel_posts = [p for c, p, _ in deps.bot.posts if c == deps.channel]
    assert len(channel_posts) == 1
    assert "@acme.example" not in texts(channel_posts) and "Salesforce" not in texts(channel_posts)
    dm_admin = [p for c, p, _ in deps.bot.posts if c == "D0ADMIN0001"]
    dm_ciso = [p for c, p, _ in deps.bot.posts if c == "D0CISO00001"]
    assert "lee.chen@acme.example" in texts(dm_admin) and "priya.shah" not in texts(dm_admin)
    assert "priya.shah@acme.example" in texts(dm_ciso) and "lee.chen" not in texts(dm_ciso)
    # Leaver tickets go out immediately.
    [(_, parent, urgent)] = deps.tickets.urgent
    assert parent == "UAR-1" and ("AR-01", "marcus.lee@acme.example") in urgent
    state, _ = load_state(deps.s3, "work", run)
    assert state["task_token"] == "token-1" and state["due_at"] == "2026-09-23T09:00:00Z"
    # Retried by Step Functions: nothing is posted twice.
    posts = len(deps.bot.posts)
    assert workflow.open_review(deps, run, "token-2")["reopened"]
    assert len(deps.bot.posts) == posts
    assert load_state(deps.s3, "work", run)[0]["task_token"] == "token-2"


def test_full_review_to_signoff(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    src = {"team": "T0TEAM0001", "channel": "D0ADMIN0001", "message_ts": "1"}

    workflow.confirm(deps, run, ADMIN, R.admin, src)
    for key, item in items.items():
        if item.reviewer == ADMIN and item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], R.admin, src)
    assert not [p for c, p, _ in deps.bot.posts if "approve" in texts(p)]  # CISO items still open

    workflow.confirm(deps, run, CISO, R.ciso, src)
    for key, item in items.items():
        if item.reviewer == CISO and item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "still the admin")], R.ciso, src)

    [approve_post] = [(c, p) for c, p, _ in deps.bot.posts if '"action_id": "approve"' in texts(p)]
    assert approve_post[0] == "D0CISO00001"
    assert deps.bot.uploads and deps.bot.uploads[0][3] == b"%PDF"

    out = workflow.approve(deps, run, R.ciso, {"team": "T0TEAM0001", "channel": "D0CISO00001", "message_ts": "9"})

    assert out["decided"] == out["total"] == len(items) and out["revoke"] == 7
    [(token, sent)] = deps.sfn.successes
    assert token == "token-1" and "@" not in sent  # counts and hashes only
    state, _ = load_state(deps.s3, "work", run)
    assert state["status"] == SIGNED_OFF and state["callback_sent"]
    with pytest.raises(workflow.ReviewClosed):
        workflow.approve(deps, run, R.ciso, {})
    with pytest.raises(workflow.ReviewClosed):
        workflow.record(deps, run, [(next(iter(items)), KEEP, "late")], R.admin, src)


def test_signoff_is_refused_while_items_are_open(env):
    deps, run, _ = env
    workflow.open_review(deps, run, "token-1")
    with pytest.raises(workflow.DecisionError, match="still need a decision"):
        workflow.approve(deps, run, R.ciso, {})
    assert deps.sfn.successes == []


# --- the HTTP front end ---

def signed(payload, secret=SECRET, ts=None):
    ts = str(int(ts if ts is not None else time.time()))
    body = urlencode({"payload": json.dumps(payload)})
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
    return {"body": body, "headers": {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}}


def click(run, key, decision, user, chunk=0):
    return {"type": "block_actions", "user": {"id": user}, "team": {"id": "T0TEAM0001"}, "trigger_id": "trig",
            "container": {"channel_id": "D" + user[1:], "message_ts": "1758000000.000002"},
            "actions": [{"action_id": f"decide:{decision}",
                         "value": json.dumps({"r": run, "k": key, "c": chunk})}]}


@pytest.fixture
def frontend(env):
    deps, run, items = env
    workflow.open_review(deps, run, "token-1")
    queue = []
    call = lambda event, **kw: front(event, SECRET, R, ItemCache(deps.s3, "evidence"), deps.bot, queue.append, **kw)
    return deps, run, items, queue, call


def test_bad_or_stale_signatures_get_a_bare_401(frontend):
    deps, run, items, queue, call = frontend
    key = next(k for k, i in items.items() if i.reviewer == ADMIN)
    assert call(signed(click(run, key, KEEP, R.admin), secret="wrong"))["statusCode"] == 401
    assert call(signed(click(run, key, KEEP, R.admin), ts=time.time() - 600))["statusCode"] == 401
    assert call({"body": "payload=%7B%7D", "headers": {}})["statusCode"] == 401
    assert queue == []
    assert not verify_signature(SECRET, {"X-Slack-Request-Timestamp": "abc", "X-Slack-Signature": "v0=1"}, b"")


def test_strangers_are_ignored_and_other_reviewers_items_refused(frontend):
    deps, run, items, queue, call = frontend
    admin_key = next(k for k, i in items.items() if i.reviewer == ADMIN and i.proposed == KEEP)
    ciso_key = next(k for k, i in items.items() if i.reviewer == CISO and i.proposed == KEEP)
    assert call(signed(click(run, admin_key, KEEP, "U0STRANGER1")))["statusCode"] == 200
    call(signed(click(run, ciso_key, KEEP, R.admin)))
    assert queue == []
    assert "other reviewer" in deps.bot.ephemeral[-1][2]


def test_a_decision_needing_a_reason_opens_the_modal_first(frontend):
    deps, run, items, queue, call = frontend
    key = next(k for k, i in items.items() if i.reviewer == ADMIN and i.proposed == REVOKE)

    call(signed(click(run, key, KEEP, R.admin)))

    assert queue == []
    [(trigger, view)] = deps.bot.modals
    assert trigger == "trig" and view["callback_id"] == "reason"
    submit = {"type": "view_submission", "user": {"id": R.admin}, "view": {
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
    ciso_key = next(k for k, i in items.items() if i.reviewer == CISO)
    forged = {"action": "decide", "run": run, "choices": [[ciso_key, KEEP, ""]], "user": R.admin,
              "source": {"channel": "D0ADMIN0001"}}
    assert worker(forged, deps) == {"ok": False, "run": run}
    assert store.list_records(deps.s3, "evidence", run, "decisions") == []
    assert worker({"action": "approve", "run": run, "user": R.admin, "source": {}}, deps)["ok"] is False
