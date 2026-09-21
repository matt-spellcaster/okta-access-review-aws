"""Reviewer decisions and the final sign-off, as evidence records.

Every Slack click becomes one create-only record under runs/<run>/decisions/.
Nothing is edited: changing your mind adds a newer record, and the latest
record for an item wins. When every item is decided, the CISO's approval
writes two more records:

    signoff/decisions.json    the final decision for every item
    signoff/attestation.json  the sign-off, bound to the manifest's SHA-256 and
                              to decisions.json's SHA-256, in the same shape as
                              attest.py's records

Who may decide is fixed here, not in Slack: the CISO is the single reviewer,
deciding every item and signing off. Their Slack user ID is the identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__
from .attest import MAX_NOTE, check_text
from .items import ACKNOWLEDGE_ONLY, DECIDE, KEEP, REVOKE, ReviewItem

FORMAT = 1
DECISIONS = (KEEP, REVOKE)
SLACK_USER = re.compile(r"^[UW][A-Z0-9]{8,}$")


class DecisionError(ValueError):
    """A decision or sign-off that isn't allowed. The message is safe to show the clicking user."""


@dataclass(frozen=True)
class Reviewers:
    ciso: str  # Slack user ID of the single reviewer

    def __post_init__(self):
        if not SLACK_USER.match(self.ciso):
            raise ValueError("the CISO's Slack user ID must look like U0123ABCDEF (a member ID, not a D… DM ID)")

    def may_decide(self, user: str) -> bool:
        return user == self.ciso


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def reason_required(item: ReviewItem, decision: str) -> bool:
    """Keeping something proposed for revocation, or overriding any proposal, needs a reason."""
    return item.proposed != DECIDE and decision != item.proposed


def make_decision_record(
    run: str,
    manifest_sha256: str,
    items: dict[str, ReviewItem],
    choices: list[tuple[str, str, str]],
    slack_user: str,
    reviewers: Reviewers,
    source: dict,
    now: datetime | None = None,
) -> tuple[str, dict]:
    """Check one click's decisions and build its record. choices are
    (item_key, decision, reason). Returns (record file name, record)."""
    if not choices:
        raise DecisionError("nothing to record")
    entries = []
    for key, decision, reason in choices:
        item = items.get(key)
        if item is None:
            raise DecisionError("that item isn't part of this review")
        if decision not in DECISIONS:
            raise DecisionError(f"decision must be one of {', '.join(DECISIONS)}")
        if item.kind in ACKNOWLEDGE_ONLY and decision != KEEP:
            raise DecisionError(f"a {item.kind.replace('_', ' ')} item can only be acknowledged; "
                                "the work it points at happens outside this review")
        if not reviewers.may_decide(slack_user):
            raise DecisionError("only the CISO can decide items in this review")
        try:
            reason = check_text(reason or "", "reason", MAX_NOTE, required=reason_required(item, decision))
        except ValueError:
            raise DecisionError(
                "a reason is needed to keep access that was proposed for revocation, or to override a proposal"
                if reason_required(item, decision) and not (reason or "").strip()
                else f"the reason must be one line of at most {MAX_NOTE} characters"
            ) from None
        entries.append({"item_key": key, "decision": decision, "reason": reason})

    when = _now(now)
    record = {
        "format": FORMAT,
        "run": run,
        "manifest_sha256": manifest_sha256,
        "decisions": entries,
        "slack_user": slack_user,
        "slack_team": str(source.get("team", "")),
        "channel": str(source.get("channel", "")),
        "message_ts": str(source.get("message_ts", "")),
        "recorded_at": _stamp(when),
    }
    name = f"{when.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:12]}.json"
    return name, record


def confirm_proposed(items: dict[str, ReviewItem], final: dict[str, dict]) -> list[tuple[str, str, str]]:
    """The "Confirm proposed" button: accept every keep/revoke proposal that has
    no decision yet. Items marked decide are left alone."""
    return [
        (key, item.proposed, "")
        for key, item in sorted(items.items())
        if item.proposed in DECISIONS and key not in final
    ]


def consolidate(
    items: dict[str, ReviewItem], records: list[tuple[str, dict]], manifest_sha256: str, reviewers: Reviewers
) -> dict[str, dict]:
    """The current decision for each item: the latest valid record wins.

    Records are re-checked here rather than trusted because they were written:
    one made against another manifest, by the wrong person, or for an unknown
    item is ignored, so it can never count toward a sign-off."""
    final: dict[str, dict] = {}
    for name, rec in sorted(records, key=lambda r: (r[1].get("recorded_at", ""), r[0])):
        if rec.get("format") != FORMAT or rec.get("manifest_sha256") != manifest_sha256:
            continue
        for entry in rec.get("decisions", []):
            item = items.get(entry.get("item_key"))
            if item is None or entry.get("decision") not in DECISIONS:
                continue
            if item.kind in ACKNOWLEDGE_ONLY and entry.get("decision") != KEEP:
                continue
            if not reviewers.may_decide(rec.get("slack_user", "")):
                continue
            if reason_required(item, entry["decision"]) and not str(entry.get("reason", "")).strip():
                continue
            final[item.key] = {
                "decision": entry["decision"],
                "reason": entry.get("reason", ""),
                "decided_by": rec["slack_user"],
                "decided_at": rec.get("recorded_at", ""),
                "record": name,
            }
    return final


def outstanding(items: dict[str, ReviewItem], final: dict[str, dict]) -> list[ReviewItem]:
    return [i for k, i in sorted(items.items()) if k not in final]


def progress(items: dict[str, ReviewItem], final: dict[str, dict]) -> dict[str, int]:
    """Counts only, for Slack channel posts and Step Functions output."""
    decided = [final[k]["decision"] for k in items if k in final]
    return {
        "total": len(items),
        "decided": len(decided),
        "keep": decided.count(KEEP),
        "revoke": decided.count(REVOKE),
        "open": len(items) - len(decided),
    }


def build_signoff(
    run: str,
    manifest: dict,
    manifest_sha256: str,
    items_sha256: str,
    items: dict[str, ReviewItem],
    final: dict[str, dict],
    approver: str,
    reviewers: Reviewers,
    source: dict,
    note: str = "",
    now: datetime | None = None,
) -> tuple[bytes, dict]:
    """Returns (decisions.json bytes, attestation record). Refuses unless the
    approver is the CISO, the item list is the one the manifest hashed, and
    every item has a decision."""
    if approver != reviewers.ciso:
        raise DecisionError("only the CISO can sign off the review")
    if manifest.get("files", {}).get("review_items.json") != items_sha256:
        raise DecisionError("the review items don't match the manifest; not signed")
    missing = outstanding(items, final)
    if missing:
        raise DecisionError(f"{len(missing)} item(s) still need a decision")
    note = check_text(note, "note", MAX_NOTE, required=False)

    decisions_doc = {
        "format": FORMAT,
        "run": run,
        "manifest_sha256": manifest_sha256,
        "decisions": {k: final[k] for k in sorted(items)},
    }
    decisions_bytes = (json.dumps(decisions_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    revokes = sum(1 for k in items if final[k]["decision"] == REVOKE)
    record = {
        "reviewer": f"slack:{approver}",
        "decision": "approved-with-exceptions" if revokes else "approved",
        "note": note,
        "signed_at": _now(now).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "org_url": manifest.get("org_url"),
        "review_date": manifest.get("review_date"),
        "manifest_sha256": manifest_sha256,
        "files_verified": len(manifest.get("files", {})),
        "extra_files": [],
        "tool": f"okta-access-review-aws {__version__}",
        "prev": None,
        "decisions_sha256": hashlib.sha256(decisions_bytes).hexdigest(),
        "items_decided": len(items),
        "items_revoked": revokes,
        "slack_user": approver,
        "slack_team": str(source.get("team", "")),
        "channel": str(source.get("channel", "")),
        "message_ts": str(source.get("message_ts", "")),
    }
    return decisions_bytes, record


def signoff_problems(attestation: dict, decisions_bytes: bytes, manifest_sha256: str,
                     items: dict[str, ReviewItem]) -> list[str]:
    """What's wrong with a recorded sign-off, if anything. Used by attest to verify
    a downloaded run."""
    problems = []
    if attestation.get("manifest_sha256") != manifest_sha256:
        problems.append("the sign-off was made against a different manifest.json")
    if attestation.get("decisions_sha256") != hashlib.sha256(decisions_bytes).hexdigest():
        problems.append("signoff/decisions.json has changed since the sign-off")
    try:
        doc = json.loads(decisions_bytes)
    except ValueError:
        return problems + ["signoff/decisions.json can't be read"]
    if doc.get("manifest_sha256") != manifest_sha256:
        problems.append("signoff/decisions.json belongs to a different manifest.json")
    decided = doc.get("decisions", {})
    if set(decided) != set(items):
        problems.append("signoff/decisions.json doesn't cover exactly the review's items")
    return problems

