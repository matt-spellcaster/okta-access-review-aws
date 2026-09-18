"""The review workflow between collection and remediation.

    open_review     post the review to the admin and CISO, open the JSM parent
                    and the urgent leaver tickets, remember the task token
    record          one reviewer's decisions (a click, a reason, or
                    "confirm proposed"), then refresh their messages and, once
                    nothing is left, ask the CISO to sign off
    approve         the CISO's sign-off: write it as evidence and resume the
                    Step Functions execution

Everything that touches personal data stays in S3, the reviewers' DMs and JSM.
What this module returns (and so what reaches Step Functions) is IDs, hashes
and counts.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from . import slack_review as msgs
from . import store
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
from .items import ADMIN, CISO, ITEMS_FILE, ReviewItem, load_items, summary
from .state import OPEN, SIGNED_OFF, create_state, load_state, update_state

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
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))


@dataclass
class RunData:
    run: str
    manifest: dict
    manifest_sha256: str
    items: dict[str, ReviewItem]
    item_list: list[ReviewItem]


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
    return RunData(run, manifest, hashlib.sha256(manifest_bytes).hexdigest(),
                   {i.key: i for i in item_list}, item_list)


def current_decisions(deps: Deps, data: RunData) -> dict[str, dict]:
    records = store.list_records(deps.s3, deps.evidence_bucket, data.run, "decisions")
    return consolidate(data.items, records, data.manifest_sha256, deps.reviewers)


def urgent_findings(deps: Deps, run: str) -> list[dict]:
    """Leaver findings from the run's findings.csv (hashed in the manifest)."""
    text = store.get_bytes(deps.s3, deps.evidence_bucket, _key(run, "findings.csv")).decode()
    return [row for row in csv.DictReader(io.StringIO(text)) if row["check_id"] in URGENT_CHECKS]


def _due(deps: Deps) -> datetime:
    return deps.now() + timedelta(days=deps.review_days)


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _post_role(deps: Deps, data: RunData, role: str, final: dict, due: str) -> dict:
    user = deps.reviewers.slack_id(role)
    channel = deps.bot.open_dm(user)
    summary_ts = deps.bot.post_message(
        channel, msgs.summary_message(data.run, role, data.item_list, final, due, data.manifest_sha256))
    parts = msgs.chunks(data.item_list, role)
    chunk_ts = [
        deps.bot.post_message(channel, msgs.chunk_message(data.run, role, n, len(parts), part, final))
        for n, part in enumerate(parts)
    ]
    return {"channel": channel, "summary_ts": summary_ts, "chunks": chunk_ts}


def open_review(deps: Deps, run: str, task_token: str) -> dict:
    """Step Functions calls this with .waitForTaskToken; the execution then
    waits until approve() sends the token back. Safe to call again for the same
    run: a retry only refreshes the task token."""
    try:
        load_state(deps.s3, deps.work_bucket, run)
    except FileNotFoundError:
        pass
    else:
        update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(task_token=task_token))
        return {"run": run, "reopened": True}

    data = load_run(deps, run)
    due_at = _due(deps)
    due = due_at.strftime("%Y-%m-%d")
    create_state(deps.s3, deps.work_bucket, run, {
        "run": run, "status": OPEN, "opened_at": _iso(deps.now()), "due_at": _iso(due_at),
        "manifest_sha256": data.manifest_sha256, "task_token": task_token,
        "dms": {}, "approve": None, "parent_issue": None, "notices": {},
    })

    parent, urgent = None, 0
    if deps.tickets is not None:
        counts = summary(data.item_list)
        parent = deps.tickets.open_parent(run, data.manifest, data.manifest_sha256, counts, due_at)
        urgent = deps.tickets.open_urgent(run, parent, urgent_findings(deps, run))
        update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(parent_issue=parent))

    dms = {role: _post_role(deps, data, role, {}, due)
           for role in (ADMIN, CISO) if any(i.reviewer == role for i in data.item_list)}
    update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(dms=dms))
    deps.bot.post_message(deps.channel, msgs.channel_opened(run, summary(data.item_list), due, parent or "-", urgent))
    maybe_ready(deps, data, {})  # a review with nothing to decide goes straight to sign-off
    return {"run": run, "items": len(data.item_list), "urgent_tickets": urgent}


def refresh(deps: Deps, data: RunData, state: dict, final: dict, roles: tuple[str, ...]) -> None:
    due = state["due_at"][:10]
    for role in roles:
        dm = state["dms"].get(role)
        if not dm:
            continue
        is_open = state["status"] == OPEN
        deps.bot.update_message(dm["channel"], dm["summary_ts"], msgs.summary_message(
            data.run, role, data.item_list, final, due, data.manifest_sha256, open_=is_open))
        parts = msgs.chunks(data.item_list, role)
        for n, (part, ts) in enumerate(zip(parts, dm["chunks"])):
            deps.bot.update_message(dm["channel"], ts, msgs.chunk_message(data.run, role, n, len(parts), part, final))


def maybe_ready(deps: Deps, data: RunData, final: dict) -> bool:
    """Once every item is decided, post the Approve button (and the PDF) to the
    CISO, once."""
    if outstanding(data.items, final):
        return False
    posted: list[bool] = []

    def claim(s: dict) -> None:
        posted.append(s.get("approve") is None and s["status"] == OPEN)
        if posted[-1]:
            s["approve"] = {"claimed": True}

    update_state(deps.s3, deps.work_bucket, data.run, claim)
    if not posted[-1]:
        return False
    channel = deps.bot.open_dm(deps.reviewers.ciso)
    ts = deps.bot.post_message(channel, msgs.approve_message(data.run, progress(data.items, final),
                                                             data.manifest_sha256))
    with tempfile.TemporaryDirectory() as tmp:
        pdf = Path(tmp) / "report.pdf"
        pdf.write_bytes(store.get_bytes(deps.s3, deps.evidence_bucket, _key(data.run, "report.pdf")))
        deps.bot.upload_file(channel, pdf, filename=f"okta-access-review-{data.run}.pdf",
                             title=f"Okta access review ({data.run})", thread_ts=ts,
                             comment=":page_facing_up: The full report. :lock: Contains personal data.")
    update_state(deps.s3, deps.work_bucket, data.run, lambda s: s.update(approve={"channel": channel, "ts": ts}))
    return True


def record(deps: Deps, run: str, choices: list[tuple[str, str, str]], user: str, source: dict) -> dict:
    """Validate and store one reviewer action, then bring their messages up to date."""
    state, _ = load_state(deps.s3, deps.work_bucket, run)
    if state["status"] != OPEN:
        raise ReviewClosed("this review has already been signed off")
    data = load_run(deps, run)
    name, rec = make_decision_record(run, data.manifest_sha256, data.items, choices, user, deps.reviewers,
                                     source, deps.now())
    store.put_record(deps.s3, deps.evidence_bucket, run, "decisions", name, rec)
    final = current_decisions(deps, data)
    roles = tuple(sorted({data.items[k].reviewer for k, _, _ in choices}))
    refresh(deps, data, state, final, roles)
    maybe_ready(deps, data, final)
    return progress(data.items, final)


def confirm(deps: Deps, run: str, role: str, user: str, source: dict) -> dict:
    data = load_run(deps, run)
    if user != deps.reviewers.slack_id(role):
        raise DecisionError("you can only confirm proposals in your own review")
    choices = confirm_proposed(data.items, current_decisions(deps, data), role)
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
    try:
        store.put_create_only(deps.s3, deps.evidence_bucket, store.record_key(run, "signoff", "decisions.json"),
                              decisions_bytes, "application/json")
        store.put_record(deps.s3, deps.evidence_bucket, run, "signoff", "attestation.json", attestation)
    except store.AlreadyExists:
        raise ReviewClosed("this review has already been signed off") from None

    output = {
        "run": run, "manifest_sha256": data.manifest_sha256,
        "decisions_sha256": attestation["decisions_sha256"], **progress(data.items, final),
    }
    state = update_state(deps.s3, deps.work_bucket, run,
                         lambda s: s.update(status=SIGNED_OFF, signed_off_at=attestation["signed_at"]))
    send_callback(deps, state, output)
    if (state.get("approve") or {}).get("ts"):
        deps.bot.update_message(state["approve"]["channel"], state["approve"]["ts"], msgs.approve_message(
            run, progress(data.items, final), data.manifest_sha256, signed=attestation))
    refresh(deps, data, state, final, (ADMIN, CISO))
    deps.bot.post_message(deps.channel, msgs.channel_note(
        f":lock: Okta access review `{run}` was signed off by <@{user}>. "
        f"{output['revoke']} remediation ticket(s) will be opened."))
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
    revokes = sum(1 for d in final.values() if d["decision"] == "revoke")
    deps.tickets.jira.add_comment(parent, _adf_signoff(att, opened, revokes))
    update_state(deps.s3, deps.work_bucket, run, lambda s: s.update(remediated=True))
    deps.bot.post_message(deps.channel, msgs.channel_note(
        f":ticket: Access review `{run}`: {revokes} remediation ticket(s) under {parent}, due in "
        f"{deps.tickets.revoke_days} days."))
    return {"run": run, "revoke_tickets": revokes, "opened_now": opened}


def _adf_signoff(att: dict, opened: int, revokes: int) -> dict:
    from .jira import adf

    return adf(
        f"Signed off in Slack on {att['signed_at']} ({att['decision']}): {att['items_decided']} items decided, "
        f"{revokes} to revoke. {revokes} remediation ticket(s) are linked to this one.",
        [("Manifest SHA-256: ", None), (att["manifest_sha256"], "code")],
        [("Decisions SHA-256: ", None), (att["decisions_sha256"], "code")],
    )
