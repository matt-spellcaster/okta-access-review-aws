import copy
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fakes import FakeBot, FakeS3, FakeSfn

from access_review import store, watch, workflow
from access_review.workflow import load_run
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import DECIDE, KEEP
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.state import CLOSED, load_state, update_state
from access_review.tickets import Remediation, record_verify_mode

FIXTURES = Path(__file__).parent.parent / "fixtures"
R = Reviewers(ciso="U0CISO00001")
OPENED = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)


class FakeJira:
    """Just the JiraClient surface tickets.py and watch.py use."""

    project = "UAR"

    def __init__(self):
        self.issues, self.comments, self.closed = {}, [], []

    def search(self, jql, fields, limit=1000):
        hits = []
        for key, f in self.issues.items():
            if 'labels = "uar-key-' in jql and jql.split('labels = "')[1].rstrip('"') not in f["labels"]:
                continue
            if "labels in (" in jql:
                wanted = jql.split("labels in (")[1].split(")")[0].replace('"', "").split(", ")
                if not set(wanted) & set(f["labels"]):
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

    def close(self, key):
        if self.issues[key].get("done"):
            return False
        self.issues[key]["done"] = True
        self.closed.append(key)
        return True


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
                         channel="C0REVIEW001", tickets=tickets, sfn=FakeSfn(), now=clock,
                         ticket_url=lambda key: f"https://acme.atlassian.net/browse/{key}")
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
    # 7 revokes, plus a fix ticket for each finding that isn't an access decision.
    assert out["revoke_tickets"] == 7 and out["fix_tickets"] == 9 and out["opened_now"] == 16
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
    assert any(k == marcus["issue"] and "Okta still shows the problem" in body for k, body in jira.comments)
    assert marcus["issue"] in dms_to(deps, R.ciso)[-1]
    # Same day again: no repeat comments or alerts.
    comments = len(jira.comments)
    assert watch.daily(deps, jira, fresh, leavers(fresh)) == {"verified": 0, "still_present": 0}
    assert len(jira.comments) == comments


def test_a_revoke_is_not_verified_from_a_read_that_was_hiding_apps(world):
    """The worst shape this bug takes: the daily check closing an audit ticket and
    signing the evidence "done in Okta" because the admin role running the
    collection could not see the app. The collector already detects that and says
    so; nothing was reading it. Silence is not absence, in the one function that
    decides whether a fix happened."""
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    revoke = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
                  if r["kind"] == "revoke")
    loaded = load_run(deps, run).items
    assert loaded[revoke["item_key"]].kind == "app", "this guard is the app branch"
    jira.issues[revoke["issue"]]["done"] = True

    blind = copy.deepcopy(snapshot)
    blind.apps = []  # what a role-restricted read returns
    blind.apps_complete = False
    blind.gaps = ["The app list does not include this review app, so the admin role is hiding apps."]
    assert watch.still_present(revoke, blind, loaded, set()) == (None, {})
    watch.daily(deps, jira, blind, leavers(blind))
    settled = [n for n, _ in store.list_records(deps.s3, "evidence", run, "verifications")]
    assert f"{revoke['label']}-verified.json" not in settled, "closed on a read that saw no apps"

    # A complete read that shows the assignment gone is the real thing.
    gone = copy.deepcopy(snapshot)
    for app in gone.apps:
        app.users.clear()
        app.groups.clear()
    clock.now += timedelta(days=1)
    watch.daily(deps, jira, gone, leavers(gone))
    rec = dict(store.list_records(deps.s3, "evidence", run, "verifications"))[
        f"{revoke['label']}-verified.json"]
    assert rec["result"] == "removed"


def test_a_review_closes_its_tracking_ticket_once_everything_is_verified(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    parent = load_state(deps.s3, "work", run)[0]["parent_issue"]
    for rec in [r for _, r in store.list_records(deps.s3, "evidence", run, "tickets") if r["kind"] != "parent"]:
        jira.issues[rec["issue"]]["done"] = True
    gone = copy.deepcopy(snapshot)
    for app in gone.apps:
        app.users.clear()
        app.groups.clear()
    gone.users = [u for u in gone.users if not u.login.startswith(("marcus", "sofia", "victor"))]
    gone.events = []  # nobody left who set up an API client

    # Fix tickets aren't verified while their findings are still reported.
    watch.daily(deps, jira, gone, leavers(gone), current={("AR-04", "lee.chen@acme.example")})
    assert load_state(deps.s3, "work", run)[0]["status"] != CLOSED and jira.closed == []

    clock.now += timedelta(days=1)
    watch.daily(deps, jira, gone, leavers(gone), current=set())

    assert load_state(deps.s3, "work", run)[0]["status"] == CLOSED
    assert jira.closed == [parent]  # the one ticket the tool moves
    last = json.dumps(deps.bot.posts[-1][1])
    assert "is complete" in last and parent in last
    # The two kinds of evidence, counted apart. A single "everything was verified
    # in Okta" covered four tickets (AR-05/06/07/10) that settled on the
    # reviewer's word, and that sentence is the one an auditor reads.
    assert "13 verified against a fresh Okta snapshot" in last
    assert "6 resolved on the reviewer's word" in last  # AR-18's two among them
    assert "verified in Okta" not in last
    closing = [b for k, b in jira.comments if k == parent][-1]
    assert "13 verified against a fresh Okta snapshot" in closing
    assert "6 resolved on the reviewer's word" in closing
    assert "Everything under this review was verified in Okta" not in closing
    # 13 + 4 accounts for all 17, so "every ticket" is a claim the counts support.
    assert "Every ticket under this review is settled" in closing


def test_the_checklist_ticks_off_verified_tickets(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    state = load_state(deps.s3, "work", run)[0]
    [(channel, checklist, _)] = [(c, p, ts) for c, p, ts in deps.bot.posts if "To close" in json.dumps(p)]
    text = json.dumps(checklist)
    assert checklist["thread_ts"] == state["approve"]["ts"]  # in the approval message's thread
    assert "0 of 19 done" in text and "Unassign lee.chen@acme.example from the app Salesforce" in text
    assert any(k == state["parent_issue"] and "To close this ticket" in body for k, body in jira.comments)

    lee = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
               if r.get("item_key") and items[r["item_key"]].target == "Salesforce"
               and items[r["item_key"]].user.startswith("lee.chen"))
    jira.issues[lee["issue"]]["done"] = True
    fresh = copy.deepcopy(snapshot)
    next(a for a in fresh.apps if a.label == "Salesforce").users.discard("u05")
    watch.daily(deps, jira, fresh, leavers(fresh))

    ts = state["checklist"]["ts"] if "checklist" in state else load_state(deps.s3, "work", run)[0]["checklist"]["ts"]
    updated = [p for c, t, p in deps.bot.updates if t == ts][-1]
    assert "1 of 19 done" in json.dumps(updated) and ":white_check_mark:" in json.dumps(updated)


def test_a_fix_ticket_is_verified_when_its_finding_is_gone(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    mfa = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
               if r["kind"] == "finding" and r["check_id"] == "AR-04")
    jira.issues[mfa["issue"]]["done"] = True

    assert watch.daily(deps, jira, snapshot, leavers(snapshot), current={("AR-04", "lee.chen@acme.example")}) \
        == {"verified": 0, "still_present": 1}
    clock.now += timedelta(days=1)
    assert watch.daily(deps, jira, snapshot, leavers(snapshot), current=set())["verified"] == 1
    # Without fresh findings (e.g. the checks couldn't run), nothing is verified.
    assert watch.still_present(mfa, snapshot, {}, None, None) == (None, {})


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


def test_the_hourly_check_reposts_a_lost_approve_message(world):
    deps, run, items, clock, jira, snapshot = world
    src = {"channel": "D0CISO00001"}
    workflow.confirm(deps, run, R.ciso, src)
    for key, item in items.items():
        if item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], R.ciso, src)

    def approves():
        return [p for _, p, _ in deps.bot.posts if '"action_id": "approve"' in json.dumps(p)]

    assert len(approves()) == 1
    # As if a worker had claimed the post and died before sending it.
    update_state(deps.s3, "work", run, lambda s: s.update(approve={"claimed": "2026-09-16T09:00:00Z"}))
    clock.now = OPENED + timedelta(minutes=30)
    watch.hourly(deps, jira)
    assert len(approves()) == 1  # too soon: that worker may still be posting
    clock.now = OPENED + timedelta(hours=2)
    watch.hourly(deps, jira)
    assert len(approves()) == 2
    assert load_state(deps.s3, "work", run)[0]["approve"]["ts"]


def test_a_fix_ticket_is_not_verified_when_its_data_could_not_be_read(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    mfa = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
               if r["kind"] == "finding" and r["check_id"] == "AR-04")
    jira.issues[mfa["issue"]]["done"] = True
    unread = copy.deepcopy(snapshot)
    unread.gaps.append("Could not read MFA factors; AR-04 may be incomplete.")

    assert watch.daily(deps, jira, unread, leavers(unread), current=set())["verified"] == 0
    assert watch.daily(deps, jira, snapshot, leavers(snapshot), current=set())["verified"] == 1


def test_resolved_tickets_are_found_however_many_the_project_holds(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    old = {f"OLD-{n}": {"labels": ["access-review", f"uar-key-{n:012x}"], "done": True} for n in range(1200)}
    jira.issues = {**old, **jira.issues}  # years of resolved tickets, listed first
    lee = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
               if r.get("item_key") and items[r["item_key"]].target == "Salesforce"
               and items[r["item_key"]].user.startswith("lee.chen"))
    jira.issues[lee["issue"]]["done"] = True
    fresh = copy.deepcopy(snapshot)
    next(a for a in fresh.apps if a.label == "Salesforce").users.discard("u05")
    asked, real = [], jira.search
    jira.search = lambda jql, fields, limit=1000: asked.append(jql) or real(jql, fields, limit)

    assert watch.daily(deps, jira, fresh, leavers(fresh))["verified"] == 1
    assert asked and all("labels in (" in jql for jql in asked)  # by label, never the whole project


def test_a_judgement_call_ticket_is_taken_as_done_when_resolved(world):
    deps, run, items, clock, jira, snapshot = world
    finish_review(deps, run, items)
    scopes = next(r for _, r in store.list_records(deps.s3, "evidence", run, "tickets")
                  if r["kind"] == "finding" and r["check_id"] == "AR-10")
    assert scopes["verify"] == "reviewer"
    jira.issues[scopes["issue"]]["done"] = True
    # The reviewer decided the client's scopes are fine, so the finding is still reported.
    still = {("AR-10", scopes["subject"].lower())}

    assert watch.daily(deps, jira, snapshot, leavers(snapshot), current=still) == {"verified": 1, "still_present": 0}

    [(name, rec)] = store.list_records(deps.s3, "evidence", run, "verifications")
    assert name == f"{scopes['label']}-verified.json" and rec["result"] == "accepted"
    assert any(k == scopes["issue"] and "taken as done" in body for k, body in jira.comments)
    assert not any("Okta still shows the problem" in dm for dm in dms_to(deps, R.ciso))
    checklist = [p for c, t, p in deps.bot.updates if "To close" in json.dumps(p)][-1]
    assert f"resolved {rec['checked_at'][:10]}" in json.dumps(checklist)
    # Ticket records from before the "verify" field existed go by their check,
    # and only a fix ticket can be a judgement call at all.
    assert record_verify_mode({"kind": "finding", "check_id": "AR-05"}) == "reviewer"
    assert record_verify_mode({"kind": "finding", "check_id": "AR-04"}) == "okta"
    assert record_verify_mode({"kind": "revoke"}) == "okta"
    assert record_verify_mode({"kind": "leaver", "check_id": "AR-05"}) == "okta"
    # "okta" is the claim that something re-read the estate. A ticket kind added
    # later must say so deliberately rather than inherit it.
    assert record_verify_mode({"kind": "escalation"}) == "reviewer"
    assert record_verify_mode({}) == "reviewer"
