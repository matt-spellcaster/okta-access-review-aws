"""Slack messages for the review: what the admin and CISO see in their DMs,
and the counts-only posts in the review channel.

Pure functions that build Block Kit payloads; nothing here talks to Slack.
Personal data (logins, app names, reasons) only ever goes into the DM
builders. Channel builders take counts and IDs, never items.

Buttons carry only the run name, an item key and a chunk number. Everything
else is looked up again server-side, so a button can't smuggle in a decision
for an item the clicker isn't allowed to decide.
"""

from __future__ import annotations

import json

from .items import ADMIN, DECIDE, KEEP, REVOKE, ReviewItem

# Two blocks per item and Slack allows 50 per message, with room for a header.
CHUNK = 20
LABEL = {KEEP: "Keep", REVOKE: "Revoke", DECIDE: "Your call"}
KIND = {"app": "App", "admin_role": "Admin role", "admin_group": "Admin group"}
MAX_TEXT = 2900  # Slack's section limit is 3000


def value(**fields) -> str:
    return json.dumps(fields, separators=(",", ":"), sort_keys=True)


def _clip(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def _esc(text: str) -> str:
    """Escape Slack's control characters so names can't become mentions or links."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def chunks(items: list[ReviewItem], role: str) -> list[list[ReviewItem]]:
    mine = sorted((i for i in items if i.reviewer == role), key=lambda i: (i.user.lower(), i.kind, i.target, i.via))
    return [mine[n:n + CHUNK] for n in range(0, len(mine), CHUNK)]


def _route(item: ReviewItem) -> str:
    if item.via == "direct":
        return "direct"
    if item.via == "role":
        return "role"
    return "via group " + _esc(item.via.removeprefix("group:"))


def item_blocks(run: str, item: ReviewItem, chunk: int, decided: dict | None) -> list[dict]:
    head = (
        f"*{_esc(item.user)}* · {KIND.get(item.kind, item.kind)}: *{_esc(item.target)}* ({_route(item)})\n"
        f"Proposed: *{LABEL[item.proposed]}*. {_esc(item.reason)}"
    )
    section = {"type": "section", "block_id": f"i:{item.key}", "text": {"type": "mrkdwn", "text": _clip(head)}}
    if decided:
        why = f" · _{_esc(decided['reason'])}_" if decided.get("reason") else ""
        mark = ":white_check_mark:" if decided["decision"] == KEEP else ":no_entry:"
        return [section, {"type": "context", "elements": [{
            "type": "mrkdwn",
            "text": _clip(f"{mark} *{LABEL[decided['decision']]}* by <@{decided['decided_by']}>{why}"),
        }]}]
    buttons = []
    for decision in (KEEP, REVOKE):
        button = {
            "type": "button",
            "action_id": f"decide:{decision}",
            "text": {"type": "plain_text", "text": LABEL[decision]},
            "value": value(r=run, k=item.key, c=chunk),
        }
        if decision == item.proposed:
            button["style"] = "danger" if decision == REVOKE else "primary"
        buttons.append(button)
    return [section, {"type": "actions", "block_id": f"a:{item.key}", "elements": buttons}]


def chunk_message(run: str, role: str, index: int, count: int, chunk: list[ReviewItem],
                  final: dict[str, dict]) -> dict:
    blocks = [{"type": "context", "elements": [{
        "type": "mrkdwn", "text": f"Access review `{run}` · items {index + 1} of {count}",
    }]}]
    for item in chunk:
        blocks += item_blocks(run, item, index, final.get(item.key))
    return {"text": f"Access review items ({index + 1} of {count})", "blocks": blocks}


def summary_message(run: str, role: str, items: list[ReviewItem], final: dict[str, dict], due: str,
                    manifest_sha256: str, open_: bool = True) -> dict:
    mine = [i for i in items if i.reviewer == role]
    pending = [i for i in mine if i.key not in final]
    confirmable = [i for i in pending if i.proposed in (KEEP, REVOKE)]
    by = {p: sum(1 for i in mine if i.proposed == p) for p in (KEEP, REVOKE, DECIDE)}
    who = "your review" if role == ADMIN else "the admin's own access, which only you can review"
    lines = [
        f":clipboard: *Okta access review `{run}`* — {who}.",
        f"{len(mine)} items: {by[KEEP]} proposed keep, {by[REVOKE]} proposed revoke, {by[DECIDE]} need your call.",
        f"Due *{due}*. {len(mine) - len(pending)} of {len(mine)} decided.",
        "Revoke is proposed for direct app access with no sign-in in 90 days, and for people HR says have left. "
        "Keeping something proposed for revocation, or overriding a proposal, asks for a reason.",
    ]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]
    if open_ and confirmable:
        blocks.append({"type": "actions", "block_id": "confirm", "elements": [{
            "type": "button", "action_id": "confirm_proposed", "style": "primary",
            "text": {"type": "plain_text", "text": f"Confirm {len(confirmable)} proposed"},
            "value": value(r=run, role=role),
            "confirm": {
                "title": {"type": "plain_text", "text": "Confirm proposals?"},
                "text": {"type": "mrkdwn", "text": f"Accept the proposed keep/revoke for {len(confirmable)} items. "
                                                   "Items that need your call stay open."},
                "confirm": {"type": "plain_text", "text": "Confirm"},
                "deny": {"type": "plain_text", "text": "Cancel"},
            },
        }]})
    blocks.append({"type": "context", "elements": [{
        "type": "mrkdwn", "text": f"Manifest SHA-256 `{manifest_sha256}`"}]})
    return {"text": f"Okta access review {run}: {len(pending)} items left", "blocks": blocks}


def approve_message(run: str, progress: dict, manifest_sha256: str, signed: dict | None = None) -> dict:
    lines = [
        f":white_check_mark: *Every item in access review `{run}` has a decision.*",
        f"{progress['total']} items: {progress['keep']} keep, {progress['revoke']} revoke.",
        f"Manifest SHA-256 `{manifest_sha256}`",
    ]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]
    if signed:
        blocks.append({"type": "context", "elements": [{
            "type": "mrkdwn",
            "text": f":lock: Signed off by <@{signed['slack_user']}> at {signed['signed_at']}. "
                    f"Remediation tickets are being opened.",
        }]})
    else:
        blocks.append({"type": "actions", "block_id": "approve", "elements": [{
            "type": "button", "action_id": "approve", "style": "primary",
            "text": {"type": "plain_text", "text": "Approve review"},
            "value": value(r=run),
            "confirm": {
                "title": {"type": "plain_text", "text": "Sign off this review?"},
                "text": {"type": "mrkdwn", "text": "This records your sign-off against the manifest above and opens "
                                                   f"{progress['revoke']} remediation ticket(s). It can't be undone."},
                "confirm": {"type": "plain_text", "text": "Sign off"},
                "deny": {"type": "plain_text", "text": "Cancel"},
            },
        }]})
    return {"text": f"Access review {run} is ready for sign-off", "blocks": blocks}


def reason_modal(run: str, item: ReviewItem, decision: str, meta: dict) -> dict:
    """Asks why, when a reason is required. meta says where to post the result."""
    return {
        "type": "modal",
        "callback_id": "reason",
        "private_metadata": value(r=run, k=item.key, d=decision, **meta),
        "title": {"type": "plain_text", "text": "Reason needed"},
        "submit": {"type": "plain_text", "text": LABEL[decision]},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": _clip(
                f"*{LABEL[decision]}* {KIND.get(item.kind, item.kind).lower()} *{_esc(item.target)}* for "
                f"*{_esc(item.user)}*.\nProposed was *{LABEL[item.proposed]}*: {_esc(item.reason)}")}},
            {"type": "input", "block_id": "reason", "label": {"type": "plain_text", "text": "Why?"},
             "element": {"type": "plain_text_input", "action_id": "text", "max_length": 1000}},
        ],
    }


# --- channel: counts only ---------------------------------------------------

def channel_opened(run: str, counts: dict, due: str, parent_issue: str, urgent_tickets: int) -> dict:
    text = (
        f":clipboard: *Okta access review `{run}` is open.* Due {due}.\n"
        f"{counts['total']} items to review: {counts['keep']} proposed keep, {counts['revoke']} proposed revoke, "
        f"{counts['decide']} need a decision. {counts['for_ciso']} go to the CISO (the admin's own access).\n"
        f"Tracking ticket {parent_issue}. {urgent_tickets} urgent ticket(s) opened for people who have left."
    )
    return {"text": f"Okta access review {run} is open", "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": ":lock: Names and details are only in the reviewers' DMs, the report, and JSM."}]},
    ]}


def channel_note(text: str) -> dict:
    return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}

