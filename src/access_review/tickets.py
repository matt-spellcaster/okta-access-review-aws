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
from .items import ACKNOWLEDGE_ONLY, REVOKE, ReviewItem
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
# Ticket kinds that ask for a change in Okta, so `watch.still_present` can re-read
# it there. Everything else settles on the reviewer's word.
OKTA_VERIFIED_KINDS = frozenset({"leaver", "revoke"})


def verify_mode(check_id: str) -> str:
    """How the daily check settles a fix ticket: "okta" or "reviewer"."""
    return "reviewer" if check_id in REVIEW_CHECKS else "okta"


def record_verify_mode(record: dict) -> str:
    """How the daily check settles one ticket record: "okta" or "reviewer".

    The single answer, because three places word a claim off it: the daily
    check, the checklist in Slack and the checklist on the tracking ticket. Only
    a fix ticket can be a judgement call -- a revoke or leaver ticket asks for a
    change in Okta and is re-read there. Records written before the `verify`
    field existed go by their check.
    """
    if record.get("kind") == "finding":
        return record.get("verify") or verify_mode(record.get("check_id", ""))
    # Listed, not defaulted. "okta" is the claim that something re-read the
    # estate and confirmed the fix, so a ticket kind added later must say so
    # deliberately rather than inherit it.
    return "okta" if record.get("kind") in OKTA_VERIFIED_KINDS else "reviewer"


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

    def open_urgent(self, run: str, parent: str, findings: list[dict],
                    people: dict[str, str] | None = None,
                    outside: dict[str, tuple[tuple[str, ...], str]] | None = None) -> int:
        """One ticket per person, listing every leaver finding about them.

        people maps a lowercased login to their Okta user ID, for the link.
        outside maps a lowercased login to (what they hold in another source, why
        that may be unknown), from `items.outside_okta_by_login`. This ticket is
        the headline one for a departure and it closes on a fresh Okta read
        (`watch.still_present` runs LEAVER_ACCESS_CHECKS, all Okta), so without
        it a ticket asking to remove "every way in" is signed off as done while
        the leaver's GitHub owner role is untouched -- the same overclaim the
        revoke ticket carried, for the same people.
        """
        people = people or {}
        outside = outside or {}
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
            held, gap = outside.get(subject.lower(), ((), ""))
            paragraphs += _scope_to_okta(held, gap, "Closing their way in through Okta")
            paragraphs.append("Resolve this ticket once done; the next daily check confirms it in Okta.")
            _, new = self._create(run, label, {"kind": "leaver", "run": run, "subject": subject,
                                               "checks": [r["check_id"] for r in rows], "due": due,
                                               "outside_okta": list(held),
                                               "todo": f"Remove every way in through Okta for leaver "
                                                       f"{subject} (account, API tokens, API clients "
                                                       f"they set up)"}, {
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
                    # Access in another source is named but held outside this
                    # ticket's scope. The closing line below promises the daily
                    # check confirms the fix in Okta, and Okta cannot see
                    # whether a GitHub owner role is gone -- so listing these as
                    # plain concerns had this ticket close as verified over a
                    # credential nothing re-read. Each has its own ticket
                    # (FIX_CHECKS), which is what settles it.
                    *_outside_okta(item),
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


def _scope_to_okta(outside: tuple[str, ...] | list[str], gap: str, what: str) -> list:
    """The paragraphs saying what this ticket does not cover, or none.

    `what` names the change this ticket asks for. Shared by the revoke ticket and
    the leaver ticket because both close on a fresh read of Okta alone, and Okta
    cannot show whether a role in another source is gone.

    A gap with nothing listed still gets the paragraph. Saying nothing would let
    the assignee read the ticket as the whole picture, when the truth is that
    nothing looked.
    """
    if not outside and not gap:
        return []
    out: list = [[("Not part of this ticket: ", "strong"),
                  (f"{what} does not remove access held outside Okta, and the daily check that "
                   f"closes this ticket cannot see it. Resolve this ticket on the Okta change "
                   f"alone.", None)]]
    out += [f"Outside Okta: {c}" for c in outside]
    if outside:
        out.append("Each of those is tracked by its own ticket under the same review ticket.")
    if gap:
        out.append(f"Not known: {gap}")
    return out


def _outside_okta(item: ReviewItem) -> list:
    return _scope_to_okta(item.outside_okta, item.outside_okta_gap, "Making this Okta change")


def _sentence(text: str) -> str:
    """Capitalise a to-do that starts with a verb; leave one that starts with a login alone."""
    return text[:1].upper() + text[1:] if text.split(" ", 1)[0] in ("unassign", "remove") else text


def what_to_do(item: ReviewItem) -> str:
    if item.kind in ACKNOWLEDGE_ONLY:
        # Never reached today (these settle by acknowledging, so they are never
        # decided REVOKE), but the fallthrough below would otherwise tell someone
        # to remove them from an admin group that does not exist.
        return f"review {item.user}'s access outside Okta; this review cannot change it."
    if item.kind == "app" and item.via == "direct":
        return f"unassign {item.user} from the app {item.target}."
    if item.kind == "app":
        group = item.via.removeprefix("group:")
        return (f"{item.user} gets {item.target} through the group {group}. Remove them from {group}, "
                f"or change the group's app assignment, and check what else that group grants.")
    if item.kind == "admin_role":
        return f"remove the admin role {item.target} from {item.user}."
    return f"remove {item.user} from the admin group {item.target}."
