"""Deadlines and follow-through, run on a schedule.

hourly():
  - reviews still open: reminder DMs to the CISO at 3 and 6 days; when the
    7-day deadline passes, an overdue DM, a channel note and a JSM comment, then
    a daily reminder;
  - signed-off reviews whose Step Functions callback didn't get through: retry;
  - remediation tickets past their due date: one DM digest to the CISO per day.

daily(snapshot):
  - every ticket marked done in JSM is checked against a fresh Okta snapshot:
    leaver and revoke tickets by looking for the access, fix tickets by re-running
    the checks. Done: a "verified" comment, an evidence record, and a tick in
    the approval thread's checklist. Still there: a comment and an alert to the
    CISO. Can't tell from today's data (e.g. the System Log couldn't be read):
    nothing yet.
  - once everything under a review is verified, its tracking ticket is closed:
    the only ticket the tool ever moves.

Each notice is sent at most once, using create-only markers in the work
bucket, so running the watcher more often never repeats a message.
Channel posts carry counts only; ticket keys and names go to the CISO's DM.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from . import slack_review as msgs
from . import store
from .decisions import outstanding
from .jira import adf
from .models import LIVE_STATUSES, Snapshot
from .state import CLOSED, OPEN, SIGNED_OFF, claim_once, load_state, runs_with_status, update_state
from .workflow import Deps, current_decisions, load_run, post_to_channel, refresh_checklist, send_callback

REMINDERS = ((3, "reminder"), (6, "due tomorrow"))


def _t(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _dm(deps: Deps, text: str) -> None:
    """A note to the reviewer, the CISO."""
    deps.bot.post_message(deps.bot.open_dm(deps.reviewers.ciso), msgs.channel_note(text))


def hourly(deps: Deps, jira=None) -> dict:
    now = deps.now()
    sent = {"reminders": 0, "escalations": 0, "callbacks": 0, "overdue_tickets": 0}

    for run in runs_with_status(deps.s3, deps.work_bucket, OPEN):
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        data = load_run(deps, run)
        final = current_decisions(deps, data)
        left = len(outstanding(data.items, final))
        if not left:
            continue  # waiting on the CISO's Approve, which has its own message
        opened, due = _t(state["opened_at"]), _t(state["due_at"])
        age = now - opened
        for days, what in REMINDERS:
            if age >= timedelta(days=days) and claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-day{days}"):
                _dm(deps, f":alarm_clock: Access review `{run}` {what}: {left} item(s) still need your "
                                f"decision. Due {state['due_at'][:10]}.")
                sent["reminders"] += 1
        if now > due:
            if claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-escalated"):
                _dm(deps, f":rotating_light: Access review `{run}` is overdue (due {state['due_at'][:10]}): "
                                f"{left} item(s) still need your decision.")
                post_to_channel(deps, run, msgs.channel_note(
                    f":rotating_light: Access review `{run}` is past its deadline with {left} item(s) undecided."),
                    broadcast=True)
                if jira is not None and state.get("parent_issue"):
                    jira.add_comment(state["parent_issue"], adf(
                        f"Review overdue: due {state['due_at'][:10]}, {left} item(s) undecided on {now.date()}."))
                sent["escalations"] += 1
            elif claim_once(deps.s3, deps.work_bucket, f"{run.lower()}-overdue-{now:%Y%m%d}"):
                _dm(deps, f":rotating_light: Access review `{run}` is overdue: {left} item(s) still "
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
            lines = [f"{msgs.ticket_link((i['key'], deps.ticket_url(i['key'])))} (due {i['fields'].get('duedate')})"
                     for i in overdue]
            _dm(deps, f":rotating_light: {len(overdue)} access review remediation ticket(s) are overdue: "
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


def finding_keys(findings) -> set[tuple[str, str]]:
    """(check_id, lowercased subject) for a fresh run of the checks: a fix
    ticket is done when its finding is no longer in here."""
    return {(f.check_id, f.subject.lower()) for f in findings}


def still_present(record: dict, snapshot: Snapshot, items: dict,
                  leavers: set[str] | None, current: set[tuple[str, str]] | None = None) -> tuple[bool | None, dict]:
    """Is what a ticket asked to fix still there? (present, what was seen);
    present is None when it can't be told from today's data."""
    if record["kind"] == "finding":
        if current is None:
            return None, {}
        present = (record["check_id"], record["subject"].lower()) in current
        return present, {"finding_still_reported": present}
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


def daily(deps: Deps, jira, snapshot: Snapshot, leavers: set[str] | None,
          current: set[tuple[str, str]] | None = None) -> dict:
    """leavers is leaver_access() and current is finding_keys() for the same snapshot."""
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
                   if r.get("kind") in ("leaver", "revoke", "finding")]
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
            present, seen = still_present(rec, snapshot, items, leavers, current)
            if present is None:
                continue
            stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            if not present:
                store.put_record(deps.s3, deps.evidence_bucket, run, "verifications", f"{label}-verified.json", {
                    "issue": rec["issue"], "label": label, "checked_at": stamp, "result": "removed",
                    "observed": seen, "okta_collected_at": snapshot.to_dict()["collected_at"],
                })
                jira.add_comment(rec["issue"], adf(
                    f"Verified on {now.date()}: what this ticket asked for is done in Okta "
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
                    f"Checked on {now.date()}: this ticket is resolved, but Okta still shows the problem. "
                    f"Please finish the change."))
                _dm(deps, f":warning: {msgs.ticket_link((rec['issue'], deps.ticket_url(rec['issue'])))} is marked "
                          f"done but Okta still shows the problem.")
                result["still_present"] += 1
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        if state.get("remediated"):
            refresh_checklist(deps, run)
        if state["status"] == SIGNED_OFF and state.get("remediated") and unverified == 0:
            update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(status=CLOSED))
            parent = state.get("parent_issue")
            closed = False
            if parent:
                jira.add_comment(parent, adf(
                    f"Everything under this review was verified in Okta by {now.date()}. Closing this ticket."))
                closed = jira.close(parent)
            link = msgs.ticket_link((parent, deps.ticket_url(parent))) if parent else ""
            post_to_channel(deps, run, msgs.channel_note(
                f":white_check_mark: Access review `{run}` is complete: every fix is verified in Okta"
                + (f" and {link} is closed." if closed else ".")), broadcast=True)
            result["closed"] = result.get("closed", 0) + 1
    return result

