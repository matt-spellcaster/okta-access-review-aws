import copy
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fakes import FakeBot, FakeS3, FakeSfn

from access_review import store, watch, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import DECIDE, KEEP
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.state import CLOSED, load_state
from access_review.tickets import Remediation

FIXTURES = Path(__file__).parent.parent / "fixtures"
R = Reviewers(ciso="U0CISO00001")
OPENED = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)


class FakeJira:
    """Just the JiraClient surface tickets.py and watch.py use."""

    project = "UAR"

    def __init__(self):
        self.issues, self.comments = {}, []

    def search(self, jql, fields, limit=1000):
        hits = []
        for key, f in self.issues.items():
            if 'labels = "uar-key-' in jql and jql.split('labels = "')[1].rstrip('"') not in f["labels"]:
                continue
            if "statusCategory = Done" in jql and not f.get("done"):
                continue
            if "statusCategory != Done" in jql and f.get("done"):
                continue
            if "duedate < startOfDay()" in jql and not (f.get("duedate") and f["duedate"] < self.today):
                continue
            hits.append({"key": key, "fields": {"labels": f["labels"], "duedate": f.get("duedate")}})
        return hits[:limit]

    def create_issue(self, fields):
        key = f"UAR-{len(self.issues) + 1}"
        self.issues[key] = dict(fields)
        return key

    def add_comment(self, key, body):
        self.comments.append((key, json.dumps(body)))


def leavers(snapshot):
    from access_review.checks import ReviewContext, run_checks

    config = Config.load(FIXTURES / "demo_config.json")
    ctx = ReviewContext(snapshot, load_roster(FIXTURES / "demo_roster.csv", config.timezone()), config,
                        date(2026, 9, 18))
    return watch.leaver_access(run_checks(ctx)[0], snapshot)


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def world(tmp_path):
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True)
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    clock = Clock(OPENED)
    jira = FakeJira()
    jira.today = "2026-09-16"
    tickets = Remediation(jira, s3, "evidence", "Task", "Subtask", now=clock)
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=FakeBot(), reviewers=R,
                         channel="C0REVIEW001", tickets=tickets, sfn=FakeSfn(), now=clock)
    workflow.open_review(deps, run.run_dir.name, "token-1")
    return deps, run.run_dir.name, {i.key: i for i in run.items}, clock, jira, snapshot


def dms_to(deps, user):
    return [json.dumps(p) for c, p, _ in deps.bot.posts if c == "D" + user[1:]]


def test_reminders_go_out_once_each(world):
    deps, run, _, clock, jira, _ = world
    before = len(dms_to(deps, R.ciso))
    clock.now = OPENED + timedelta(days=1)
    assert watch.hourly(deps, jira)["reminders"] == 0
    clock.now = OPENED + timedelta(days=3, hours=1)
    assert watch.hourly(deps, jira)["reminders"] == 1
    assert watch.hourly(deps, jira)["reminders"] == 0  # the next hour: nothing new
    assert "still need your decision" in dms_to(deps, R.ciso)[-1]
    assert len(dms_to(deps, R.ciso)) == before + 1


def test_an_overdue_review_escalates_to_the_ciso_once_then_reminds_daily(world):
    deps, run, _, clock, jira, _ = world
    clock.now = OPENED + timedelta(days=7, hours=1)
    sent = watch.hourly(deps, jira)
    assert sent["escalations"] == 1
    assert "is overdue" in dms_to(deps, R.ciso)[-1]
    channel = [json.dumps(p) for c, p, _ in deps.bot.posts if c == deps.channel]
    assert "past its deadline" in channel[-1] and "@acme" not in channel[-1]
    assert any("Review overdue" in body for _, body in jira.comments)
    assert watch.hourly(deps, jira)["escalations"] == 0
    clock.now += timedelta(days=1)
    assert watch.hourly(deps, jira)["reminders"] == 1


def test_overdue_tickets_are_sent_to_the_ciso_once_a_day(world):
    deps, run, _, clock, jira, _ = world
    clock.now = OPENED + timedelta(days=2)
    jira.today = "2026-09-18"  # the 24-hour leaver tickets were due on the 17th
    assert watch.hourly(deps, jira)["overdue_tickets"] == 3
    assert "UAR-2" in dms_to(deps, R.ciso)[-1]
    assert watch.hourly(deps, jira)["overdue_tickets"] == 0


def finish_review(deps, run, items):
    src = {"channel": "D", "message_ts": "1"}
    workflow.confirm(deps, run, R.ciso, src)
    for key, item in items.items():
        if item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], R.ciso, src)
    workflow.approve(deps, run, R.ciso, src)
    return workflow.remediate(deps, run)


def test_remediation_follows_the_signed_decisions(world):
    deps, run, items, _, jira, _ = world
    out = finish_review(deps, run, items)
    assert out["revoke_tickets"] == out["opened_now"] == 7
    parent = load_state(deps.s3, "work", run)[0]["parent_issue"]
    assert any(k == parent and "Signed off in Slack" in body for k, body in jira.comments)
    # Tampering with the signed decisions stops remediation.
    key = store.record_key(run, "signoff", "decisions.json")
    deps.s3.objects[("evidence", key)] = deps.s3.objects[("evidence", key)].replace(b'"keep"', b'"revoke"')
    with pytest.raises(store.StoreError, match="doesn't match its attestation"):
        workflow.remediate(deps, run)


def test_daily_verification_checks_resolved_tickets_against_okta(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    tickets = {r["label"]: r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")}
    lee = next(r for r in tickets.values() if r.get("item_key")
               and items[r["item_key"]].user.startswith("lee.chen") and items[r["item_key"]].target == "Salesforce")
    marcus = next(r for r in tickets.values() if r.get("subject", "").startswith("marcus"))
    for rec in (lee, marcus):
        jira.issues[rec["issue"]]["done"] = True

    # Lee's Salesforce assignment really was removed; Marcus's account is still active.
    fresh = copy.deepcopy(snapshot)
    next(a for a in fresh.apps if a.label == "Salesforce").users.discard("u05")
    clock.now = OPENED + timedelta(days=2)

    assert watch.daily(deps, jira, fresh, leavers(fresh)) == {"verified": 1, "still_present": 1}
    verifications = dict(store.list_records(deps.s3, "evidence", run, "verifications"))
    assert verifications[f"{lee['label']}-verified.json"]["result"] == "removed"
    assert any(k == marcus["issue"] and "still present" in body for k, body in jira.comments)
    assert marcus["issue"] in dms_to(deps, R.ciso)[-1]
    # Same day again: no repeat comments or alerts.
    comments = len(jira.comments)
    assert watch.daily(deps, jira, fresh, leavers(fresh)) == {"verified": 0, "still_present": 0}
    assert len(jira.comments) == comments


def test_a_review_closes_once_everything_is_verified(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    for rec in [r for _, r in store.list_records(deps.s3, "evidence", run, "tickets") if r["kind"] != "parent"]:
        jira.issues[rec["issue"]]["done"] = True
    gone = copy.deepcopy(snapshot)
    for app in gone.apps:
        app.users.clear()
        app.groups.clear()
    gone.users = [u for u in gone.users if not u.login.startswith(("marcus", "sofia", "victor"))]
    gone.events = []  # nobody left who set up an API client

    watch.daily(deps, jira, gone, leavers(gone))

    assert load_state(deps.s3, "work", run)[0]["status"] == CLOSED
    assert "verified in Okta" in json.dumps(deps.bot.posts[-1][1])


def test_a_leaver_with_a_working_api_client_is_not_cleared(world):
    """Victor's account is deactivated and holds no API tokens, but the API client
    he set up still works. That ticket must not be verified."""
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    victor = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
                  if r.get("subject", "").startswith("victor"))
    jira.issues[victor["issue"]]["done"] = True
    clock.now = OPENED + timedelta(days=2)

    assert watch.daily(deps, jira, snapshot, leavers(snapshot))["verified"] == 0
    # And if the System Log couldn't be read, nobody is cleared either way.
    unread = copy.deepcopy(snapshot)
    unread.gaps.append("Could not read System Log events; AR-12 and AR-13 may be incomplete.")
    assert leavers(unread) is None
    clock.now += timedelta(days=1)
    assert watch.daily(deps, jira, unread, None) == {"verified": 0, "still_present": 0}
