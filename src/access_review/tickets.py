"""Remediation tickets in JSM, one parent per quarterly review.

    open_parent    the review's tracking ticket, when the review opens
    open_urgent    one ticket per person who has left but can still get in
                   (AR-01/02/12/13), when the review opens, due in 24 hours
    open_revokes   one ticket per Revoke decision, after sign-off, due in 7 days
    open_findings  one ticket per finding that isn't an access decision (no MFA,
                   an inactive account, ...), after sign-off, due in 7 days

Tickets about a person link to their page in the Okta admin console.

Every ticket carries a label derived from what it is about (uar-key-...), and
Jira is searched for that label before anything is created, so running a step
again never opens a second ticket. Each ticket opened is also recorded as
evidence under runs/<run>/tickets/.

Tickets say what to change in Okta; a person does it. Nothing here changes
access or moves a ticket through its workflow.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Callable

from . import store
from .items import REVOKE, ReviewItem
from .jira import JiraClient, adf
from .okta import admin_url

LABEL = "access-review"
# Findings that need a fix but aren't a Keep/Revoke decision: each gets a ticket
# after sign-off. Leaver findings (AR-01/02/12/13) already have leaver tickets,
# AR-11 and AR-14 are decided as review items, and AR-03 (no HR record) is
# acknowledged by the CISO as a review item and raised with HR: never a ticket.
# AR-15..AR-17 are here rather than in workflow.URGENT_CHECKS: the urgent path
# promises "the next daily check confirms it in Okta", which is exactly what no
# graph-backed finding can offer until its source has a collector.
FIX_CHECKS = ("AR-04", "AR-05", "AR-06", "AR-07", "AR-08", "AR-09", "AR-10", "AR-15", "AR-16", "AR-17")
# A finding at this severity says something could not be checked (AR-04 when MFA
# enrollment can't be read, AR-13 when HR gave no end date), not that something
# is wrong. It stays in the report; nobody gets a ticket to "fix" it.
INFO = "info"
# Fix tickets whose remediation is a decision, not a change Okta can show: the
# reviewer may well keep things as they are (confirm an inactive account is
# still needed, document a contractor's exception, accept an API client's
# scopes). Resolving one of these is the reviewer's word
# that it is settled, and the daily check ticks it off without looking at
# Okta. The other fix checks (no MFA, a bare profile, a disabled account's
# leftover access) are checked against a fresh snapshot.
# AR-15 and AR-16 are judgement calls in the same way: they ask someone to
# establish what an account is, and the answer is a register entry, not a
# change Okta can show. AR-17 is not a judgement call -- it asks for access to
# be removed in another system -- but nothing can confirm that until that
# system has a collector, and claiming to have verified it would be worse than
# taking the reviewer's word. See the guard in tests/test_tickets.py.
REVIEW_CHECKS = ("AR-05", "AR-06", "AR-07", "AR-10", "AR-15", "AR-16", "AR-17")


def verify_mode(check_id: str) -> str:
    """How the daily check settles a fix ticket: "okta" or "reviewer"."""
    return "reviewer" if check_id in REVIEW_CHECKS else "okta"


def quarter(review_date: str) -> str:
    d = date.fromisoformat(review_date)
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


def ticket_label(*parts: str) -> str:
    return "uar-key-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:12]


@dataclass
class Remediation:
    jira: JiraClient
    s3: object
    evidence_bucket: str
    parent_type: str
    child_type: str
    leaver_hours: int = 24
    revoke_days: int = 7
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))
    okta_org_url: str = ""  # for links to people in the Okta admin console

    # --- helpers -------------------------------------------------------------

    def _okta_link(self, user_id: str | None, who: str) -> list | None:
        url = admin_url(self.okta_org_url, "user", user_id or "")
        return [("Okta: ", "strong"), (f"open {who} in the Okta admin console", ("link", url))] if url else None

    def _existing(self, label: str) -> str | None:
        found = self.jira.search(f'project = "{self.jira.project}" AND labels = "{label}"', ["summary"], limit=2)
        return found[0]["key"] if found else None

    def _create(self, run: str, label: str, record: dict, fields: dict) -> tuple[str, bool]:
        """(issue key, created). Looks for the label first; records the ticket as evidence."""
        existing = self._existing(label)
        if existing:
            return existing, False
        key = self.jira.create_issue({"project": {"key": self.jira.project},
                                      "labels": [LABEL, label, *fields.pop("extra_labels", [])], **fields})
        try:
            store.put_record(self.s3, self.evidence_bucket, run, "tickets", f"{label}.json", {
                **record, "issue": key, "label": label, "created_at": self.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        except store.AlreadyExists:
            pass
        return key, True

    # --- the three kinds of ticket ---------------------------------------------

    def open_parent(self, run: str, manifest: dict, manifest_sha256: str, counts: dict, due_at: datetime) -> str:
        q = quarter(manifest["review_date"])
        label = ticket_label("parent", run)
        gaps = manifest.get("data_gaps") or []
        key, _ = self._create(run, label, {"kind": "parent", "run": run}, {
            "issuetype": {"name": self.parent_type},
            "summary": f"Okta Access Review {q} ({run})",
            "duedate": due_at.date().isoformat(),
            "extra_labels": [f"uar-{q.lower()}"],
            "description": adf(
                f"Quarterly Okta user access review for {manifest.get('org_url')}, review date "
                f"{manifest.get('review_date')}. Review and sign-off happen in Slack; this ticket tracks it.",
                f"{counts['total']} items to review: {counts['keep']} proposed keep, {counts['revoke']} proposed "
                f"revoke, {counts['decide']} need a decision.",
                "Data complete." if not gaps else f"INCOMPLETE: {len(gaps)} data gap(s); see the report.",
                [("Manifest SHA-256: ", None), (manifest_sha256, "code")],
                [("Evidence: ", None), (f"s3://{self.evidence_bucket}/runs/{run}/", "code")],
            ),
        })
        return key

    def open_urgent(self, run: str, parent: str, findings: list[dict], people: dict[str, str] | None = None) -> int:
        """One ticket per person, listing every leaver finding about them.
        people maps a lowercased login to their Okta user ID, for the link."""
        people = people or {}
        by_subject: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            if f["severity"] != INFO:
                by_subject[f["subject"]].append(f)
        due = (self.now() + timedelta(hours=self.leaver_hours)).date().isoformat()
        created = 0
        for subject, rows in sorted(by_subject.items()):
            rows.sort(key=lambda r: r["check_id"])
            label = ticket_label("leaver", run, subject.lower())
            paragraphs: list = [
                f"HR shows {subject} has left, but they can still get in. Fix within {self.leaver_hours} hours."
            ]
            for r in rows:
                paragraphs.append([(f"{r['check_id']} {r['title']}: ", "strong"), (r["detail"], None)])
                paragraphs.append(f"To do: {r['remediation']}")
            link = self._okta_link(people.get(subject.lower()), subject)
            if link:
                paragraphs.append(link)
            paragraphs.append("Resolve this ticket once done; the next daily check confirms it in Okta.")
            _, new = self._create(run, label, {"kind": "leaver", "run": run, "subject": subject,
                                               "checks": [r["check_id"] for r in rows], "due": due,
                                               "todo": f"Remove every way in for leaver {subject} "
                                                       f"(account, API tokens, API clients they set up)"}, {
                "issuetype": {"name": self.child_type},
                "parent": {"key": parent},
                "summary": f"Remove access for leaver {subject}",
                "duedate": due,
                "description": adf(*paragraphs),
            })
            created += new
        return created

    def open_revokes(self, run: str, parent: str, items: dict[str, ReviewItem], final: dict[str, dict]) -> int:
        due = (self.now() + timedelta(days=self.revoke_days)).date().isoformat()
        created = 0
        for key in sorted(items, key=lambda k: (items[k].user.lower(), items[k].target, items[k].via)):
            if final.get(key, {}).get("decision") != REVOKE:
                continue
            item = items[key]
            _, new = self._create(run, ticket_label("revoke", run, key), {
                "kind": "revoke", "run": run, "item_key": key, "due": due,
                "todo": _sentence(what_to_do(item)),
            }, {
                "issuetype": {"name": self.child_type},
                "parent": {"key": parent},
                "summary": f"Revoke {item.target} for {item.user}",
                "duedate": due,
                "description": adf(*[p for p in (
                    [("Change in Okta: ", "strong"), (what_to_do(item), None)],
                    self._okta_link(item.user_id, item.user),
                    f"Why: {final[key].get('reason') or item.reason}",
                    *[f"Fact: {f}" for f in item.facts],
                    *[f"Concern: {c}" for c in item.concerns],
                    f"Decided in the access review {run} and signed off by the CISO.",
                    [("Review item: ", None), (key, "code")],
                    "Resolve this ticket once done; the next daily check confirms it in Okta.",
                ) if p]),
            })
            created += new
        return created


    def open_findings(self, run: str, parent: str, findings: list[dict], people: dict[str, str] | None = None) -> int:
        """One ticket per finding in FIX_CHECKS: the fixes the review found that
        aren't access decisions. Closed by the daily check once the finding is gone."""
        people = people or {}
        due = (self.now() + timedelta(days=self.revoke_days)).date().isoformat()
        created = 0
        for f in sorted(findings, key=lambda r: (r["check_id"], r["subject"].lower())):
            if f["check_id"] not in FIX_CHECKS or f["severity"] == INFO:
                continue
            subject = f["subject"]
            label = ticket_label("finding", run, f["check_id"], subject.lower())
            mode = verify_mode(f["check_id"])
            closing = (
                f"Found in the access review {run}. Resolve this ticket once you have decided. This is a "
                f"judgement call, so the daily check takes your word for it and does not look in Okta."
                if mode == "reviewer" else
                f"Found in the access review {run}. Resolve this ticket once done; "
                f"the next daily check confirms the finding is gone."
            )
            _, new = self._create(run, label, {
                "kind": "finding", "run": run, "check_id": f["check_id"], "subject": subject, "due": due,
                "todo": f"{f['title']} ({f['check_id']}) for {subject}: {f['remediation']}", "verify": mode,
            }, {
                "issuetype": {"name": self.child_type},
                "parent": {"key": parent},
                "summary": f"Fix: {f['title']} — {subject}",
                "duedate": due,
                "description": adf(*[p for p in (
                    [(f"{f['check_id']} {f['title']}: ", "strong"), (f["detail"], None)],
                    [("To do: ", "strong"), (f["remediation"], None)],
                    self._okta_link(people.get(subject.lower()), subject),
                    closing,
                ) if p]),
            })
            created += new
        return created


def _sentence(text: str) -> str:
    """Capitalise a to-do that starts with a verb; leave one that starts with a login alone."""
    return text[:1].upper() + text[1:] if text.split(" ", 1)[0] in ("unassign", "remove") else text


def what_to_do(item: ReviewItem) -> str:
    if item.kind == "app" and item.via == "direct":
        return f"unassign {item.user} from the app {item.target}."
    if item.kind == "app":
        group = item.via.removeprefix("group:")
        return (f"{item.user} gets {item.target} through the group {group}. Remove them from {group}, "
                f"or change the group's app assignment, and check what else that group grants.")
    if item.kind == "admin_role":
        return f"remove the admin role {item.target} from {item.user}."
    return f"remove {item.user} from the admin group {item.target}."
