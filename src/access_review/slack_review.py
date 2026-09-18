"""Slack messages for the review: what the CISO sees in their DM, and the
counts-only posts in the review channel.

Pure functions that build Block Kit payloads; nothing here talks to Slack.
Personal data (logins, app names, reasons) only ever goes into the DM
builders. Channel builders take counts, IDs and ticket links, never items.

Buttons carry only the run name, an item key and a chunk number. Everything
else is looked up again server-side, so a button can't smuggle in a decision
for an item the clicker isn't allowed to decide.

A ticket is passed around as (key, url); url is None when Jira is reached
through a gateway address that has no browsable page.
"""

from __future__ import annotations

import json

from .items import DECIDE, KEEP, REVOKE, ReviewItem

# Two blocks per item and Slack allows 50 per message, with room for a header.
CHUNK = 20
LABEL = {KEEP: "Keep", REVOKE: "Revoke", DECIDE: "Your call"}
KIND = {"app": "App", "admin_role": "Admin role", "admin_group": "Admin group"}
MAX_TEXT = 2900  # Slack's section limit is 3000
# Sections on the sign-off message; beyond this, the list points to the report.
MAX_LIST_SECTIONS = 40

Ticket = tuple[str, "str | None"]


def value(**fields) -> str:
    return json.dumps(fields, separators=(",", ":"), sort_keys=True)


def _clip(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def _esc(text: str) -> str:
    """Escape Slack's control characters so names can't become mentions or links."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def ticket_link(ticket: Ticket | None) -> str:
    """A ticket as a Slack link when it has a page, otherwise just its key."""
    if not ticket:
        return ""
    key, url = ticket
    return f"<{url}|{key}>" if url else key


def chunks(items: list[ReviewItem]) -> list[list[ReviewItem]]:
    ordered = sorted(items, key=lambda i: (i.user.lower(), i.kind, i.target, i.via))
    return [ordered[n:n + CHUNK] for n in range(0, len(ordered), CHUNK)]


def _route(item: ReviewItem) -> str:
    if item.via == "direct":
        return "direct"
    if item.via == "role":
        return "role"
    return "via group " + _esc(item.via.removeprefix("group:"))


def describe(item: ReviewItem) -> str:
    """One line naming the person, the access and how they have it."""
    return f"*{_esc(item.user)}* · {KIND.get(item.kind, item.kind)}: *{_esc(item.target)}* ({_route(item)})"


def item_blocks(run: str, item: ReviewItem, chunk: int, decided: dict | None,
                ticket: Ticket | None = None) -> list[dict]:
    lines = [describe(item), f"Proposed: *{LABEL[item.proposed]}*. {_esc(item.reason)}"]
    if ticket:
        lines.append(f":ticket: Leaver ticket {ticket_link(ticket)}")
    section = {"type": "section", "block_id": f"i:{item.key}",
               "text": {"type": "mrkdwn", "text": _clip("\n".join(lines))}}
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


def chunk_message(run: str, index: int, count: int, chunk: list[ReviewItem], final: dict[str, dict],
                  tickets: dict[str, Ticket] | None = None) -> dict:
    """tickets maps a lowercased login to that person's leaver ticket."""
    tickets = tickets or {}
    blocks = [{"type": "context", "elements": [{
        "type": "mrkdwn", "text": f"Access review `{run}` · items {index + 1} of {count}",
    }]}]
    for item in chunk:
        blocks += item_blocks(run, item, index, final.get(item.key), tickets.get(item.user.lower()))
    return {"text": f"Access review items ({index + 1} of {count})", "blocks": blocks}


def summary_message(run: str, items: list[ReviewItem], final: dict[str, dict], due: str,
                    manifest_sha256: str, parent: Ticket | None = None, open_: bool = True) -> dict:
    pending = [i for i in items if i.key not in final]
    confirmable = [i for i in pending if i.proposed in (KEEP, REVOKE)]
    by = {p: sum(1 for i in items if i.proposed == p) for p in (KEEP, REVOKE, DECIDE)}
    lines = [
        f":clipboard: *Okta access review `{run}`*: you're the reviewer for all {len(items)} items.",
        f"{by[KEEP]} proposed keep, {by[REVOKE]} proposed revoke, {by[DECIDE]} need your call.",
        f"Due *{due}*. {len(items) - len(pending)} of {len(items)} decided."
        + (f" Tracking ticket {ticket_link(parent)}." if parent else ""),
        "Revoke is proposed for direct app access with no sign-in in 90 days, and for people HR says have left. "
        "Keeping something proposed for revocation, or overriding a proposal, asks for a reason. "
        "When every item is decided, you get one message listing all of them with the *Approve review* button.",
    ]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]
    if open_ and confirmable:
        blocks.append({"type": "actions", "block_id": "confirm", "elements": [{
            "type": "button", "action_id": "confirm_proposed", "style": "primary",
            "text": {"type": "plain_text", "text": f"Confirm {len(confirmable)} proposed"},
            "value": value(r=run),
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


def decision_lines(items: list[ReviewItem], final: dict[str, dict]) -> dict[str, list[str]]:
    """Every decision as one line, grouped by outcome, for the sign-off message."""
    grouped: dict[str, list[str]] = {REVOKE: [], KEEP: []}
    for item in sorted(items, key=lambda i: (i.user.lower(), i.kind, i.target, i.via)):
        d = final.get(item.key)
        if not d:
            continue
        line = f"• {describe(item)}"
        notes = []
        if item.proposed not in (DECIDE, d["decision"]):
            notes.append(f"overrode proposed {LABEL[item.proposed].lower()}")
        if d.get("reason"):
            notes.append(f"reason: _{_esc(d['reason'])}_")
        elif item.proposed == d["decision"]:
            notes.append(_esc(item.reason))
        if notes:
            line += " — " + "; ".join(notes)
        grouped[d["decision"]].append(line)
    return grouped


def _sections(title: str, lines: list[str]) -> list[dict]:
    """A titled list split into sections under Slack's size limit."""
    out, current = [], f"*{title}*"
    for line in lines:
        if len(current) + 1 + len(line) > MAX_TEXT:
            out.append({"type": "section", "text": {"type": "mrkdwn", "text": current}})
            current = line
        else:
            current += "\n" + line
    out.append({"type": "section", "text": {"type": "mrkdwn", "text": current}})
    return out


def approve_message(run: str, items: list[ReviewItem], final: dict[str, dict], progress: dict,
                    manifest_sha256: str, parent: Ticket | None = None, signed: dict | None = None) -> dict:
    """Everything the CISO is signing off, in one place: each decision, the
    ticket, the manifest hash, and the button (or who signed, once done)."""
    head = [
        f":white_check_mark: *Every item in access review `{run}` has a decision.* Please check them and sign off.",
        f"{progress['total']} items: *{progress['revoke']} revoke*, {progress['keep']} keep."
        + (f" Tracking ticket {ticket_link(parent)}." if parent else ""),
        "Approving opens one Jira ticket per revoke, due in 7 days.",
    ]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(head)}}]
    grouped = decision_lines(items, final)
    listed: list[dict] = []
    if grouped[REVOKE]:
        listed += _sections(f":no_entry: Revoke ({len(grouped[REVOKE])})", grouped[REVOKE])
    if grouped[KEEP]:
        listed += _sections(f":white_check_mark: Keep ({len(grouped[KEEP])})", grouped[KEEP])
    if len(listed) > MAX_LIST_SECTIONS:
        listed = listed[:MAX_LIST_SECTIONS] + [{"type": "section", "text": {
            "type": "mrkdwn", "text": "…the list continues in the report PDF in this thread."}}]
    blocks += [{"type": "divider"}] + listed + [{"type": "divider"}]
    blocks.append({"type": "context", "elements": [{
        "type": "mrkdwn", "text": f"Manifest SHA-256 `{manifest_sha256}` · the report PDF is in this message's thread."}]})
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
                                                   f"{progress['revoke']} remediation ticket(s). It can't be undone. "
                                                   "To change a decision first, click its button again in the "
                                                   "item messages above."},
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

def channel_opened(run: str, counts: dict, due: str, parent: Ticket | None, urgent_tickets: int) -> dict:
    text = (
        f":clipboard: *Okta access review `{run}` is open.* Due {due}.\n"
        f"{counts['total']} items to review: {counts['keep']} proposed keep, {counts['revoke']} proposed revoke, "
        f"{counts['decide']} need a decision. The CISO reviews them in a DM.\n"
        f"Tracking ticket {ticket_link(parent) or '-'}. "
        f"{urgent_tickets} urgent ticket(s) opened for people who have left."
    )
    return {"text": f"Okta access review {run} is open", "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": ":lock: Names and details are only in the reviewer's DM, the report, and JSM."}]},
    ]}


def channel_note(text: str) -> dict:
    return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:",
                  "low": ":white_circle:", "info": ":large_blue_circle:"}


def channel_finished(run: str, manifest: dict, check_counts: list[tuple[str, str, str, int]], attestation: dict,
                     keeps: int, revokes: int, parent: Ticket | None, revoke_days: int) -> dict:
    """attestation is the signoff record; its manifest_sha256 is the hash shown."""
    """The finished review, for the channel: counts, check titles and links only."""
    counts = manifest.get("finding_counts") or {}
    total = sum(counts.values())
    by_sev = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)) or "none"
    gaps = manifest.get("data_gaps") or []
    lines = [
        f":white_check_mark: *Okta access review `{run}` is finished.*",
        f"Signed off by <@{attestation['slack_user']}> at {attestation['signed_at']} ({attestation['decision']}).",
        f"*Findings:* {total} ({by_sev})." + (f" :warning: Data incomplete: {len(gaps)} gap(s), see the report."
                                               if gaps else " Data complete."),
    ]
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for check_id, title, severity, n in sorted(check_counts, key=lambda c: (order.get(c[2], 9), c[0])):
        lines.append(f"{SEVERITY_EMOJI.get(severity, '•')}  `{check_id}` {_esc(title)} ×{n}")
    lines.append(
        f"*Decisions:* {keeps} keep, {revokes} revoke. "
        + (f"{revokes} remediation ticket(s) under {ticket_link(parent) or '-'}, due in {revoke_days} days."
           if revokes else f"No access to remove. Tracking ticket {ticket_link(parent) or '-'}.")
    )
    return {"text": f"Okta access review {run} is finished", "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": _clip("\n".join(lines))}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text":
            f"Manifest SHA-256 `{attestation['manifest_sha256']}` · :lock: Names and details are only in the "
            f"report and JSM."}]},
    ]}
