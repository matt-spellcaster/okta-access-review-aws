"""The review workflow between collection and remediation.

    open_review     open the JSM parent and the urgent leaver tickets, DM the
                    review to the CISO (the single reviewer), remember the
                    task token
    record          the CISO's decisions (a click, a reason, or "confirm
                    proposed"), then refresh their messages and, once nothing
                    is left, post every decision with the Approve button
    approve         the CISO's sign-off: write it as evidence and resume the
                    Step Functions execution
    remediate       one ticket per revoke, then the finished summary in the
                    review channel
    close_review    mark a review that stopped early as closed

Everything that touches personal data stays in S3, the reviewers' DMs and JSM.
What this module returns (and so what reaches Step Functions) is IDs, hashes
and counts.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from . import slack_review as msgs
from . import store
from .csvsafe import read_rows
from .decisions import (
    DecisionError,
    Reviewers,
    build_signoff,
    confirm_proposed,
    consolidate,
    make_decision_record,
    outstanding,
    progress,
)
from .items import (
    CISO,
    HR_RECORD,
    ITEMS_FILE,
    REVOKE,
    ReviewItem,
    load_items,
    outside_okta_by_login,
    summary,
)
from .state import CLOSED, OPEN, SIGNED_OFF, create_state, load_state, update_state

# Findings that mean someone who has left can still get in: a ticket is opened
# for these as soon as the review opens, without waiting for sign-off.
URGENT_CHECKS = ("AR-01", "AR-02", "AR-12", "AR-13")


class ReviewClosed(DecisionError):
    pass


@dataclass
class Deps:
    s3: object
    evidence_bucket: str
    work_bucket: str
    bot: object  # slack.BotClient
    reviewers: Reviewers
    channel: str  # the review channel: counts only
    tickets: object | None = None  # tickets.Remediation
    sfn: object | None = None  # boto3 Step Functions client
    review_days: int = 7
    revoke_days: int = 7  # how long a remediation ticket gets; shown on the sign-off message
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))
    # A Jira ticket's page, or None when there is none to link to (see JiraClient.browse_url).
    ticket_url: Callable[[str], str | None] = field(default=lambda key: None)
    # Also post the report PDF in the review channel's thread (it holds personal data).
    channel_pdf: bool = False


@dataclass
class RunData:
    run: str
    manifest: dict
    manifest_sha256: str
    items: dict[str, ReviewItem]
    item_list: list[ReviewItem]
    app_unused_days: int = 90  # the usage rule this review's proposals followed


def _key(run: str, name: str) -> str:
    return f"{store.RUNS}{run}/{name}"


def load_run(deps: Deps, run: str) -> RunData:
    """The run's manifest and items from the evidence bucket, with the items
    checked against the manifest's hash before anything uses them."""
    manifest_bytes = store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, "manifest.json"))
    manifest = json.loads(manifest_bytes)
    items_bytes = store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, ITEMS_FILE))
    if hashlib.sha256(items_bytes).hexdigest() != manifest.get("files", {}).get(ITEMS_FILE):
        raise store.StoreError(f"{ITEMS_FILE} for {run} doesn't match its manifest")
    item_list = load_items(items_bytes.decode())
    unused_days = (manifest.get("config") or {}).get("app_unused_days", 90)
    return RunData(run, manifest, hashlib.sha256(manifest_bytes).hexdigest(),
                   {i.key: i for i in item_list}, item_list,
                   unused_days if type(unused_days) is int else 90)


def current_decisions(deps: Deps, data: RunData) -> dict[str, dict]:
    records = store.list_records(deps.s3, deps.evidence_bucket, data.run, "decisions")
    return consolidate(data.items, records, data.manifest_sha256, deps.reviewers)


def urgent_findings(deps: Deps, run: str) -> list[dict]:
    """Leaver findings from the run's findings.csv (hashed in the manifest)."""
    return [row for row in all_findings(deps, run) if row["check_id"] in URGENT_CHECKS]


def _due(deps: Deps) -> datetime:
    return deps.now() + timedelta(days=deps.review_days)


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ticket(deps: Deps, key: str | None) -> msgs.Ticket | None:
    return (key, deps.ticket_url(key)) if key else None


def leaver_tickets(deps: Deps, run: str) -> dict[str, msgs.Ticket]:
    """Each leaver's ticket in this review, by lowercased login, for linking from their items."""
    return {
        rec["subject"].lower(): (rec["issue"], deps.ticket_url(rec["issue"]))
        for _, rec in store.list_records(deps.s3, deps.evidence_bucket, run, "tickets")
        if rec.get("kind") == "leaver" and rec.get("subject") and rec.get("issue")
    }


def people(deps: Deps, run: str) -> dict[str, str]:
    """Okta user ID by lowercased login, from the run's snapshot, for admin console links."""
    snap = json.loads(store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, "snapshot.json")))
    return {u["login"].lower(): u["id"] for u in snap.get("users", [])}


def post_to_channel(deps: Deps, run: str, payload: dict, broadcast: bool = False) -> str:
    """Post in the review channel, as a reply in the review's thread once it has
    one. broadcast also shows the reply in the channel itself."""
    try:
        state, _ = load_state(deps.s3, deps.work_bucket, run)
        thread = state.get("channel_ts")
    except FileNotFoundError:
        thread = None
    if thread:
        payload = {**payload, "thread_ts": thread, **({"reply_broadcast": True} if broadcast else {})}
    return deps.bot.post_message(deps.channel, payload)


def _upload_pdf(deps: Deps, run: str, channel: str, thread_ts: str, comment: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pdf = Path(tmp) / "report.pdf"
        pdf.write_bytes(store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, "report.pdf")))
        deps.bot.upload_file(channel, pdf, filename=f"okta-access-review-{run}.pdf",
                             title=f"Okta access review ({run})", thread_ts=thread_ts, comment=comment)


def _post_dm(deps: Deps, data: RunData, final: dict, due: str, parent: str | None) -> dict:
    channel = deps.bot.open_dm(deps.reviewers.ciso)
    summary_ts = deps.bot.post_message(channel, msgs.summary_message(
        data.run, data.item_list, final, due, data.manifest_sha256, _ticket(deps, parent),
        unused_days=data.app_unused_days))
    tickets = leaver_tickets(deps, data.run)
    parts = msgs.chunks(data.item_list)
    chunk_ts = [
        deps.bot.post_message(channel, msgs.chunk_message(data.run, n, len(parts), part, final, tickets))
        for n, part in enumerate(parts)
    ]
    return {"channel": channel, "summary_ts": summary_ts, "chunks": chunk_ts}


def open_review(deps: Deps, run: str, task_token: str) -> dict:
    """Step Functions calls this with .waitForTaskToken; the execution then
    waits until approve() sends the token back. Safe to call again for the same
    run: a retry refreshes the task token and then finishes whichever of the
    steps below did not complete the first time. Each step checks the state
    field it fills in, so nothing is opened or posted twice."""
    data = load_run(deps, run)
    try:
        state, _ = load_state(deps.s3, deps.work_bucket, run)
    except FileNotFoundError:
        reopened = False
        due_at = _due(deps)
        state = {
            "run": run, "status": OPEN, "opened_at": _iso(deps.now()), "due_at": _iso(due_at),
            "manifest_sha256": data.manifest_sha256, "task_token": task_token,
            "dms": {}, "approve": None, "parent_issue": None, "notices": {},
        }
        create_state(deps.s3, deps.work_bucket, run, state)
    else:
        reopened = True
        state = update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(task_token=task_token))
        if state["status"] != OPEN:
            return {"run": run, "reopened": True, "status": state["status"]}
        due_at = datetime.fromisoformat(state["due_at"].replace("Z", "+00:00"))
    due = due_at.strftime("%Y-%m-%d")

    parent, urgent = state.get("parent_issue"), 0
    if deps.tickets is not None:
        if parent is None:
            parent = deps.tickets.open_parent(run, data.manifest, data.manifest_sha256, summary(data.item_list),
                                              due_at)
            update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(parent_issue=parent))
        # Looked up by label before being created, so a retry opens no second ticket.
        # outside_okta_by_login so the leaver ticket says which part of "every way
        # in" it does not cover: it closes on a fresh Okta read, and Okta cannot
        # see a role in another source.
        urgent = deps.tickets.open_urgent(run, parent, urgent_findings(deps, run), people(deps, run),
                                          outside_okta_by_login(data.item_list))

    if data.item_list and not state.get("dms"):
        dms = {CISO: _post_dm(deps, data, {}, due, parent)}
        update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(dms=dms))
    if not state.get("channel_ts"):
        # The review's thread in the channel: everything later about it goes under this post.
        channel_ts = deps.bot.post_message(deps.channel, msgs.channel_opened(
            run, summary(data.item_list), due, _ticket(deps, parent), urgent))
        update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(channel_ts=channel_ts))
        if deps.channel_pdf:
            _upload_pdf(deps, run, deps.channel, channel_ts,
                        ":page_facing_up: The full report. :lock: Contains names and access details.")
    maybe_ready(deps, data, {})  # a review with nothing to decide goes straight to sign-off
    out = {"run": run, "items": len(data.item_list), "urgent_tickets": urgent}
    return {**out, "reopened": True} if reopened else out


def refresh(deps: Deps, data: RunData, state: dict, final: dict, only_chunk: int | None = None) -> None:
    """Bring the reviewer's DM up to date with the latest decisions. With
    only_chunk, just the summary and that one item message: a single click
    changes one card, and updating every message per click would run into
    Slack's rate limit on a long review."""
    due = state["due_at"][:10]
    parent = _ticket(deps, state.get("parent_issue"))
    tickets = leaver_tickets(deps, data.run)
    is_open = state["status"] == OPEN
    parts = msgs.chunks(data.item_list)
    if type(only_chunk) is not int or not 0 <= only_chunk < len(parts):
        only_chunk = None
    for dm in state["dms"].values():
        deps.bot.update_message(dm["channel"], dm["summary_ts"], msgs.summary_message(
            data.run, data.item_list, final, due, data.manifest_sha256, parent, open_=is_open,
            unused_days=data.app_unused_days))
        for n, (part, ts) in enumerate(zip(parts, dm["chunks"])):
            if only_chunk is not None and n != only_chunk:
                continue
            deps.bot.update_message(dm["channel"], ts,
                                    msgs.chunk_message(data.run, n, len(parts), part, final, tickets))


def maybe_ready(deps: Deps, data: RunData, final: dict) -> bool:
    """Once every item is decided, post the Approve button (and the PDF) to the
    CISO, once."""
    if outstanding(data.items, final):
        return False
    posted: list[bool] = []

    def claim(s: dict) -> None:
        posted.append(s.get("approve") is None and s["status"] == OPEN)
        if posted[-1]:
            s["approve"] = {"claimed": _iso(deps.now())}  # watch.hourly reposts if this never gets its ts

    update_state(deps.s3, deps.work_bucket, data.run, claim)
    if not posted[-1]:
        return False
    state, _ = load_state(deps.s3, deps.work_bucket, data.run)
    channel = deps.bot.open_dm(deps.reviewers.ciso)
    ts = deps.bot.post_message(channel, msgs.approve_message(
        data.run, data.item_list, final, progress(data.items, final), data.manifest_sha256,
        _ticket(deps, state.get("parent_issue")), revoke_days=deps.revoke_days))
    _upload_pdf(deps, data.run, channel, ts, ":page_facing_up: The full report. :lock: Contains personal data.")
    update_state(deps.s3, deps.work_bucket, data.run, lambda s: s.update(approve={"channel": channel, "ts": ts}))
    return True


def record(deps: Deps, run: str, choices: list[tuple[str, str, str]], user: str, source: dict,
           chunk: int | None = None) -> dict:
    """Validate and store one reviewer action, then bring their messages up to
    date. chunk is the item message the click came from, when it was one click."""
    state, _ = load_state(deps.s3, deps.work_bucket, run)
    if state["status"] != OPEN:
        raise ReviewClosed("this review has already been signed off")
    data = load_run(deps, run)
    name, rec = make_decision_record(run, data.manifest_sha256, data.items, choices, user, deps.reviewers,
                                     source, deps.now())
    store.put_record(deps.s3, deps.evidence_bucket, run, "decisions", name, rec)
    final = current_decisions(deps, data)
    # The Approve message has to go out once every item is decided, even if
    # updating the cards fails (a Slack rate limit, say): nothing else posts it.
    try:
        refresh(deps, data, state, final, only_chunk=chunk)
    finally:
        maybe_ready(deps, data, final)
    return progress(data.items, final)


def confirm(deps: Deps, run: str, user: str, source: dict) -> dict:
    data = load_run(deps, run)
    if not deps.reviewers.may_decide(user):
        raise DecisionError("only the CISO can confirm proposals in this review")
    choices = confirm_proposed(data.items, current_decisions(deps, data))
    if not choices:
        raise DecisionError("there are no undecided proposals to confirm")
    return record(deps, run, choices, user, source)


def approve(deps: Deps, run: str, user: str, source: dict) -> dict:
    """The CISO's sign-off. Evidence first, then the Step Functions callback,
    so a sign-off that was recorded is never lost even if the callback fails
    (the callback is retried from the recorded state by watch)."""
    state, _ = load_state(deps.s3, deps.work_bucket, run)
    if state["status"] != OPEN:
        raise ReviewClosed("this review has already been signed off")
    data = load_run(deps, run)
    final = current_decisions(deps, data)
    decisions_bytes, attestation = build_signoff(
        run, data.manifest, data.manifest_sha256, data.manifest["files"][ITEMS_FILE], data.items, final,
        user, deps.reviewers, source, now=deps.now(),
    )
    decisions_key = store.record_key(run, "signoff", "decisions.json")
    try:
        store.put_create_only(deps.s3, deps.evidence_bucket, decisions_key, decisions_bytes, "application/json")
    except store.AlreadyExists:
        # An earlier attempt at this sign-off wrote the decisions and then failed
        # before the state changed. The same decisions: finish the job below.
        # Different ones: what was recorded stands, and a person has to look.
        if store.get_bytes(deps.s3, deps.evidence_bucket, decisions_key) != decisions_bytes:
            raise DecisionError("a sign-off with different decisions is already recorded for this review; "
                                "ask an operator to check signoff/decisions.json") from None
    try:
        store.put_record(deps.s3, deps.evidence_bucket, run, "signoff", "attestation.json", attestation)
    except store.AlreadyExists:
        attestation = store.get_record(deps.s3, deps.evidence_bucket, run, "signoff", "attestation.json")

    output = {
        "run": run, "manifest_sha256": data.manifest_sha256,
        "decisions_sha256": attestation["decisions_sha256"], **progress(data.items, final),
    }
    state = update_state(deps.s3, deps.work_bucket, run,
                         lambda s: s.update(status=SIGNED_OFF, signed_off_at=attestation["signed_at"]))
    send_callback(deps, state, output)
    if (state.get("approve") or {}).get("ts"):
        deps.bot.update_message(state["approve"]["channel"], state["approve"]["ts"], msgs.approve_message(
            run, data.item_list, final, progress(data.items, final), data.manifest_sha256,
            _ticket(deps, state.get("parent_issue")), signed=attestation, revoke_days=deps.revoke_days))
    refresh(deps, data, state, final)
    return output


def send_callback(deps: Deps, state: dict, output: dict) -> bool:
    """Resume the waiting execution. Returns False if it no longer exists
    (timed out or was stopped); the sign-off stands either way."""
    if deps.sfn is None or not state.get("task_token"):
        return False
    try:
        deps.sfn.send_task_success(taskToken=state["task_token"], output=json.dumps(output))
    except Exception as e:
        code = store._error_code(e)
        if code in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
            return False
        raise
    update_state(deps.s3, deps.work_bucket, state["run"], lambda s: s.update(callback_sent=True))
    return True


def remediate(deps: Deps, run: str) -> dict:
    """After sign-off: one ticket per Revoke decision, from the signed
    decisions.json (never recomputed), checked against the attestation first."""
    att = store.get_record(deps.s3, deps.evidence_bucket, run, "signoff", "attestation.json")
    decisions_bytes = store.get_bytes(deps.s3, deps.evidence_bucket, store.record_key(run, "signoff", "decisions.json"))
    if hashlib.sha256(decisions_bytes).hexdigest() != att["decisions_sha256"]:
        raise store.StoreError(f"signoff/decisions.json for {run} doesn't match its attestation")
    data = load_run(deps, run)
    if att["manifest_sha256"] != data.manifest_sha256:
        raise store.StoreError(f"the sign-off for {run} was made against a different manifest")
    final = json.loads(decisions_bytes)["decisions"]
    state, _ = load_state(deps.s3, deps.work_bucket, run)
    parent = state.get("parent_issue")
    opened = deps.tickets.open_revokes(run, parent, data.items, final)
    revokes = sum(1 for d in final.values() if d["decision"] == REVOKE)
    flagged = sum(1 for k in final if k in data.items and data.items[k].kind == HR_RECORD)
    rows = all_findings(deps, run)
    fixes = deps.tickets.open_findings(run, parent, rows, people(deps, run))
    deps.tickets.jira.add_comment(parent, _adf_signoff(att, opened, revokes))
    update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(remediated=True))
    post_checklist(deps, run)
    fix_count = sum(1 for _, r in store.list_records(deps.s3, deps.evidence_bucket, run, "tickets")
                    if r.get("kind") == "finding")
    post_to_channel(deps, run, msgs.channel_finished(
        run, data.manifest, check_counts(deps, run), att, len(final) - revokes - flagged, revokes,
        _ticket(deps, parent), deps.tickets.revoke_days, fix_count, flagged=flagged), broadcast=True)
    return {"run": run, "revoke_tickets": revokes, "opened_now": opened + fixes, "fix_tickets": fix_count}


def all_findings(deps: Deps, run: str) -> list[dict]:
    return read_rows(store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, "findings.csv")).decode())


def checklist_entries(deps: Deps, run: str) -> list[dict]:
    """Every ticket that must be done before the tracking ticket closes, and
    whether the daily check has verified it yet."""
    verified: dict[str, tuple[str, str]] = {}  # label -> (date, result)
    for name, rec in store.list_records(deps.s3, deps.evidence_bucket, run, "verifications"):
        if name.endswith("-verified.json"):
            verified[rec["label"]] = (rec.get("checked_at", "")[:10], rec.get("result", "removed"))
    return [
        {"ticket": _ticket(deps, rec["issue"]), "todo": rec.get("todo") or rec.get("kind", "ticket"),
         "due": rec.get("due"), "verified": verified.get(rec["label"], ("", ""))[0] or None,
         "accepted": verified.get(rec["label"], ("", ""))[1] == "accepted", "label": rec["label"]}
        for _, rec in store.list_records(deps.s3, deps.evidence_bucket, run, "tickets")
        if rec.get("kind") in ("leaver", "revoke", "finding")
    ]


def post_checklist(deps: Deps, run: str) -> None:
    """The action items, in the approval message's thread and on the tracking ticket."""
    from .jira import adf

    state, _ = load_state(deps.s3, deps.work_bucket, run)
    entries = checklist_entries(deps, run)
    message = msgs.checklist_message(run, _ticket(deps, state.get("parent_issue")), entries)
    approve_msg = state.get("approve") or {}
    if approve_msg.get("ts"):
        ts = deps.bot.post_message(approve_msg["channel"], {**message, "thread_ts": approve_msg["ts"]})
        update_state(deps.s3, deps.work_bucket, run,
                     lambda s: s.update(checklist={"channel": approve_msg["channel"], "ts": ts}))
    if state.get("parent_issue") and deps.tickets is not None:
        deps.tickets.jira.add_comment(state["parent_issue"], adf(
            "To close this ticket, each of these must be done and verified in Okta:",
            *[[(f"{e['ticket'][0]}: ", "strong"), (f"{e['todo']} (due {e.get('due')})", None)] for e in entries],
            "Resolve each sub-ticket once its change is made; the daily check verifies it and this ticket "
            "closes automatically when all are verified.",
        ))


def refresh_checklist(deps: Deps, run: str) -> None:
    """Tick off verified items in the approval thread's checklist."""
    state, _ = load_state(deps.s3, deps.work_bucket, run)
    checklist = state.get("checklist") or {}
    if checklist.get("ts"):
        deps.bot.update_message(checklist["channel"], checklist["ts"], msgs.checklist_message(
            run, _ticket(deps, state.get("parent_issue")), checklist_entries(deps, run)))


def check_counts(deps: Deps, run: str) -> list[tuple[str, str, str, int]]:
    """(check_id, title, severity, count) from findings.csv: counts only, for the channel."""
    counts: dict[tuple[str, str, str], int] = {}
    for row in all_findings(deps, run):
        k = (row["check_id"], row["title"], row["severity"])
        counts[k] = counts.get(k, 0) + 1
    return [(c, t, sev, n) for (c, t, sev), n in sorted(counts.items())]


def close_review(deps: Deps, run: str, reason: str) -> bool:
    """Mark a review that stopped before sign-off as closed, so the watcher
    stops chasing it. Returns False if there's nothing open to close."""
    closed: list[bool] = []

    def change(s: dict) -> None:
        closed.append(s["status"] == OPEN)
        if closed[-1]:
            s.update(status=CLOSED, closed_reason=reason)

    try:
        update_state(deps.s3, deps.work_bucket, run, change)
    except FileNotFoundError:
        return False
    return bool(closed and closed[-1])


def _adf_signoff(att: dict, opened: int, revokes: int) -> dict:
    from .jira import adf

    return adf(
        f"Signed off in Slack on {att['signed_at']} ({att['decision']}): {att['items_decided']} items decided, "
        f"{revokes} to revoke. {revokes} remediation ticket(s) are linked to this one.",
        [("Manifest SHA-256: ", None), (att["manifest_sha256"], "code")],
        [("Decisions SHA-256: ", None), (att["decisions_sha256"], "code")],
    )
