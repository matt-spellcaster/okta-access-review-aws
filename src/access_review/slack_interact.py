"""Slack interactivity: the public endpoint and the worker behind it.

front() runs behind the Lambda function URL that Slack calls. It must answer
within 3 seconds, so it only:
  1. verifies Slack's signature and rejects anything older than 5 minutes,
  2. ignores anyone who isn't the configured CISO (the single reviewer),
  3. opens the "reason" modal when a decision needs one (the trigger_id only
     lives for 3 seconds), or checks a submitted reason,
  4. hands the action to the worker and returns.

worker() does the real work asynchronously (workflow.record/confirm/approve),
and re-checks every permission itself: it never trusts that front() did.

The signing secret is the only authentication on the function URL, so a
request that fails the check gets a bare 401 and nothing else.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Callable
from urllib.parse import parse_qs

from . import slack_review as msgs
from .attest import MAX_NOTE, check_text
from .decisions import DecisionError, Reviewers, reason_required
from .items import ITEMS_FILE, ReviewItem, load_items
from .slack import SlackError
from .store import RUN_NAME, get_bytes

MAX_AGE = 300  # seconds
MAX_BODY = 64 * 1024
OK = {"statusCode": 200, "body": ""}
DENIED = {"statusCode": 401, "body": ""}


def verify_signature(secret: str, headers: dict, body: bytes, now: float | None = None) -> bool:
    """Slack's v0 request signature, with a 5-minute replay window."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    ts, sig = h.get("x-slack-request-timestamp", ""), h.get("x-slack-signature", "")
    if not ts.isdigit() or not sig.startswith("v0="):
        return False
    if abs((now if now is not None else time.time()) - int(ts)) > MAX_AGE:
        return False
    expected = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _body(event: dict) -> bytes:
    raw = event.get("body") or ""
    return base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode()


def _json(text: str) -> dict:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _run(value: dict) -> str:
    run = str(value.get("r", ""))
    if not RUN_NAME.match(run):
        raise DecisionError("that button doesn't belong to a review")
    return run


def _source(payload: dict) -> dict:
    container = payload.get("container") or {}
    return {
        "team": (payload.get("team") or {}).get("id", ""),
        "channel": container.get("channel_id") or (payload.get("channel") or {}).get("id", ""),
        "message_ts": container.get("message_ts", ""),
    }


class ItemCache:
    """Review items by run, read once per warm Lambda container."""

    def __init__(self, s3, bucket: str):
        self.s3, self.bucket, self.items = s3, bucket, {}

    def get(self, run: str) -> dict[str, ReviewItem]:
        if run not in self.items:
            text = get_bytes(self.s3, self.bucket, f"runs/{run}/{ITEMS_FILE}").decode()
            self.items[run] = {i.key: i for i in load_items(text)}
        return self.items[run]


def front(
    event: dict,
    secret: str,
    reviewers: Reviewers,
    items: ItemCache,
    bot,
    enqueue: Callable[[dict], None],
    now: float | None = None,
) -> dict:
    body = _body(event)
    if len(body) > MAX_BODY or not verify_signature(secret, event.get("headers") or {}, body, now):
        return DENIED
    payload = _json(parse_qs(body.decode(errors="replace")).get("payload", [""])[0])
    user = (payload.get("user") or {}).get("id", "")
    if not reviewers.may_decide(user):
        return OK  # a verified request from someone else in the workspace; nothing to do

    try:
        if payload.get("type") == "block_actions":
            return _block_action(payload, user, items, bot, enqueue)
        if payload.get("type") == "view_submission" and (payload.get("view") or {}).get("callback_id") == "reason":
            return _reason_submitted(payload, user, items, enqueue)
    except DecisionError as e:
        _tell(bot, payload, user, str(e))
    return OK


def _block_action(payload, user, items, bot, enqueue) -> dict:
    action = (payload.get("actions") or [{}])[0]
    action_id = action.get("action_id", "")
    value = _json(action.get("value", ""))
    run = _run(value)
    source = _source(payload)
    if action_id.startswith("decide:"):
        decision = action_id.removeprefix("decide:")
        item = items.get(run).get(str(value.get("k", "")))
        if item is None:
            raise DecisionError("that item isn't part of this review")
        if reason_required(item, decision):
            bot.open_modal(payload.get("trigger_id", ""), msgs.reason_modal(
                run, item, decision, {"ch": source["channel"], "ts": source["message_ts"], "t": source["team"]}))
            return OK
        enqueue({"action": "decide", "run": run, "choices": [[item.key, decision, ""]], "user": user,
                 "source": source})
    elif action_id == "confirm_proposed":
        enqueue({"action": "confirm", "run": run, "user": user, "source": source})
    elif action_id == "approve":
        enqueue({"action": "approve", "run": run, "user": user, "source": source})
    return OK


def _reason_submitted(payload, user, items, enqueue) -> dict:
    view = payload["view"]
    meta = _json(view.get("private_metadata", ""))
    run = _run(meta)
    text = (((view.get("state") or {}).get("values") or {}).get("reason") or {}).get("text", {}).get("value") or ""
    try:
        reason = check_text(text, "reason", MAX_NOTE, required=True)
    except ValueError as e:
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"response_action": "errors", "errors": {"reason": str(e)}})}
    key, decision = str(meta.get("k", "")), str(meta.get("d", ""))
    if key not in items.get(run):
        raise DecisionError("that item isn't part of this review")
    enqueue({"action": "decide", "run": run, "choices": [[key, decision, reason]], "user": user,
             "source": {"team": str(meta.get("t", "")), "channel": str(meta.get("ch", "")),
                        "message_ts": str(meta.get("ts", ""))}})
    return OK


def _tell(bot, payload: dict, user: str, text: str) -> None:
    channel = _source(payload)["channel"]
    if channel:
        try:
            bot.post_ephemeral(channel, user, f":warning: {text}")
        except SlackError:
            pass


def worker(event: dict, deps) -> dict:
    """Runs one queued action. Errors a reviewer can act on are shown to them
    in Slack; anything else is raised so it lands in the Lambda's logs."""
    from . import workflow

    action, run, user = event["action"], event["run"], event["user"]
    source = event.get("source") or {}
    try:
        if action == "decide":
            result = workflow.record(deps, run, [tuple(c) for c in event["choices"]], user, source)
        elif action == "confirm":
            result = workflow.confirm(deps, run, user, source)
        elif action == "approve":
            result = workflow.approve(deps, run, user, source)
        else:
            raise ValueError(f"unknown action {action!r}")
    except DecisionError as e:
        if source.get("channel"):
            try:
                deps.bot.post_ephemeral(source["channel"], user, f":warning: {e}")
            except SlackError:
                pass
        return {"ok": False, "run": run}
    return {"ok": True, "run": run, **{k: v for k, v in result.items() if isinstance(v, int)}}
