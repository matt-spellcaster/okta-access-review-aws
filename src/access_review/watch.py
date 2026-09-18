"""Deadlines and follow-through, run on a schedule.

hourly():
  - reviews still open: reminder DMs at 3 and 6 days, escalation to the CISO
    when the 7-day deadline passes (DM, channel note, JSM comment), then a daily
    reminder to whoever still has items;
  - signed-off reviews whose Step Functions callback didn't get through: retry;
  - remediation tickets past their due date: one DM digest to the CISO per day.

daily(snapshot):
  - every remediation ticket marked done in JSM is checked against a fresh
    Okta snapshot. Removed: a "verified" comment and an evidence record. Still
    there: a comment and an alert to the CISO. Can't tell from today's data
    (e.g. the System Log couldn't be read): nothing yet. Tickets are never moved.

Each notice is sent at most once, using create-only markers in the work
bucket, so running the watcher more often never repeats a message.
Channel posts carry counts only; ticket keys and names go to the CISO's DM.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from . import slack_review as msgs
from . import store
from .decisions import outstanding
from .items import ADMIN, CISO
from .jira import adf
from .models import LIVE_STATUSES, Snapshot
from .state import CLOSED, OPEN, SIGNED_OFF, claim_once, load_state, runs_with_status, update_state
from .workflow import Deps, current_decisions, load_run, send_callback

REMINDERS = ((3, "reminder"), (6, "due tomorrow"))


def _t(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _dm(deps: Deps, role: str, text: str) -> None:
    deps.bot.post_message(deps.bot.open_dm(deps.reviewers.slack_id(role)), msgs.channel_note(text))


def hourly(deps: Deps, jira=None) -> dict:
    now = deps.now()
    sent = {"reminders": 0, "escalations": 0, "callbacks": 0, "overdue_tickets": 0}

    for run in runs_with_status(deps.s3, deps.work_bucket, OPEN):
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        data = load_run(deps, run)
        final = current_decisions(deps, data)
        left = {role: len(outstanding(data.items, final, role)) for role in (ADMIN, CISO)}
        if not any(left.values()):
            continue  # waiting on the CISO's Approve, which has its own message
        opened, due = _t(state["opened_at"]), _t(state["due_at"])
        age = now - opened
        for days, what in REMINDERS:
            if age >= timedelta(days=days) and claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-day{days}"):
                for role, n in left.items():
                    if n:
                        _dm(deps, role, f":alarm_clock: Access review `{run}` {what}: {n} item(s) still need your "
                                        f"decision. Due {state['due_at'][:10]}.")
                        sent["reminders"] += 1
        if now > due:
            if claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-escalated"):
                _dm(deps, CISO, f":rotating_light: Access review `{run}` is overdue (due {state['due_at'][:10]}). "
                                f"Still open: {left[ADMIN]} with the admin, {left[CISO]} with you.")
                deps.bot.post_message(deps.channel, msgs.channel_note(
                    f":rotating_light: Access review `{run}` is past its deadline with "
                    f"{sum(left.values())} item(s) undecided. Escalated to the CISO."))
                if jira is not None and state.get("parent_issue"):
                    jira.add_comment(state["parent_issue"], adf(
                        f"Review overdue: due {state['due_at'][:10]}, {sum(left.values())} item(s) undecided on "
                        f"{now.date()}. Escalated to the CISO."))
                sent["escalations"] += 1
            elif claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-overdue-{now:%Y%m%d}"):
                for role, n in left.items():
                    if n:
                        _dm(deps, role, f":rotating_light: Access review `{run}` is overdue: {n} item(s) still "
                                        f"need your decision.")
                        sent["reminders"] += 1

    for run in runs_with_status(deps.s3, deps.work_bucket, SIGNED_OFF):
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        if not state.get("callback_sent"):
            att = store.get_record(deps.s3, deps.evidence_bucket, run, "signoff", "attestation.json")
            output = {"run": run, "manifest_sha256": att["manifest_sha256"],
                      "decisions_sha256": att["decisions_sha256"], "revoke": att["items_revoked"],
                      "total": att["items_decided"]}
            sent["callbacks"] += bool(send_callback(deps, state, output))

    if jira is not None:
        overdue = jira.search(
            f'project = "{jira.project}" AND labels = "access-review" AND statusCategory != Done '
            f'AND duedate < startOfDay()', ["duedate"], limit=200)
        if overdue and claim_once(deps.s3, deps.work_bucket, f"tickets-overdue-{now:%Y%m%d}"):
            lines = [f"{i['key']} (due {i['fields'].get('duedate')})" for i in overdue]
            _dm(deps, CISO, f":rotating_light: {len(overdue)} access review remediation ticket(s) are overdue: "
                            + ", ".join(lines))
            sent["overdue_tickets"] = len(overdue)
    return sent


# --- daily verification --------------------------------------------------------

# A leaver still has a way in while any of these report them.
LEAVER_ACCESS_CHECKS = ("AR-01", "AR-02", "AR-12")


def leaver_access(findings, snapshot: Snapshot) -> set[str] | None:
    """Logins the leaver checks still report on a fresh snapshot, or None when
    that can't be trusted: API clients a leaver set up are only found through
    the System Log, so if the log couldn't be read in full, nobody is cleared."""
    if snapshot.activity_since is None or any("System Log" in g or "AR-12" in g for g in snapshot.gaps):
        return None
    return {f.subject.lower() for f in findings if f.check_id in LEAVER_ACCESS_CHECKS}


def still_present(record: dict, snapshot: Snapshot, items: dict,
                  leavers: set[str] | None) -> tuple[bool | None, dict]:
    """Is the access a ticket asked to remove still there? (present, what was
    seen); present is None when it can't be told from today's data."""
    if record["kind"] == "leaver":
        if leavers is None:
            return None, {}
        user = next((u for u in snapshot.users if u.login.lower() == record["subject"].lower()), None)
        present = record["subject"].lower() in leavers
        return present, {"account_status": user.status if user else "not found",
                         "api_tokens": len(snapshot.tokens_for(user.id)) if user else 0,
                         "leaver_checks_clear": not present}
    item = items[record["item_key"]]
    user = next((u for u in snapshot.users if u.id == item.user_id), None)
    if user is None:
        return False, {"account_status": "not found"}
    if item.kind == "app":
        present = any(a.id == item.target_id and via == item.via for a, via in snapshot.apps_for(user.id))
    elif item.kind == "admin_role":
        if user.admin_roles is None:
            return None, {}
        present = item.target in user.admin_roles
    else:
        present = any(g.id == item.target_id for g in snapshot.groups_for(user.id))
    return present, {"account_status": user.status, "still_present": present}


def daily(deps: Deps, jira, snapshot: Snapshot, leavers: set[str] | None) -> dict:
    """leavers is leaver_access() for the same snapshot."""
    now = deps.now()
    done_labels = {
        label
        for issue in jira.search(f'project = "{jira.project}" AND labels = "access-review" AND statusCategory = Done',
                                 ["labels"], limit=1000)
        for label in issue["fields"].get("labels", []) if label.startswith("uar-key-")
    }
    result = {"verified": 0, "still_present": 0}
    for run in runs_with_status(deps.s3, deps.work_bucket, SIGNED_OFF, OPEN):
        tickets = [(n, r) for n, r in store.list_records(deps.s3, deps.evidence_bucket, run, "tickets")
                   if r.get("kind") in ("leaver", "revoke")]
        checked = {n for n, _ in store.list_records(deps.s3, deps.evidence_bucket, run, "verifications")}
        items = load_run(deps, run).items if any(r["kind"] == "revoke" for _, r in tickets) else {}
        unverified = 0
        for _, rec in tickets:
            label = rec["label"]
            if f"{label}-verified.json" in checked:
                continue
            unverified += 1
            if label not in done_labels:
                continue
            present, seen = still_present(rec, snapshot, items, leavers)
            if present is None:
                continue
            stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            if not present:
                store.put_record(deps.s3, deps.evidence_bucket, run, "verifications", f"{label}-verified.json", {
                    "issue": rec["issue"], "label": label, "checked_at": stamp, "result": "removed",
                    "observed": seen, "okta_collected_at": snapshot.to_dict()["collected_at"],
                })
                jira.add_comment(rec["issue"], adf(
                    f"Verified on {now.date()}: the access this ticket asked to remove is gone in Okta "
                    f"(snapshot collected {snapshot.to_dict()['collected_at']})."))
                result["verified"] += 1
                unverified -= 1
            elif claim_once(deps.s3, deps.work_bucket, f"{label}-present-{now:%Y%m%d}"):
                store.put_record(deps.s3, deps.evidence_bucket, run, "verifications",
                                 f"{label}-{now:%Y%m%d}-present.json", {
                                     "issue": rec["issue"], "label": label, "checked_at": stamp,
                                     "result": "still present", "observed": seen,
                                 })
                jira.add_comment(rec["issue"], adf(
                    f"Checked on {now.date()}: this ticket is resolved, but the access is still present in Okta. "
                    f"Please finish the change."))
                _dm(deps, CISO, f":warning: {rec['issue']} is marked done but the access is still in Okta.")
                result["still_present"] += 1
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        if state["status"] == SIGNED_OFF and state.get("remediated") and unverified == 0:
            update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(status=CLOSED))
            if state.get("parent_issue"):
                jira.add_comment(state["parent_issue"], adf(
                    f"All remediation for this review was verified in Okta by {now.date()}."))
            deps.bot.post_message(deps.channel, msgs.channel_note(
                f":white_check_mark: All remediation for access review `{run}` is verified in Okta."))
    return result

