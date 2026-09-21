"""Findings history: how many reviews in a row each finding has been open.

Read from earlier review folders in the same output directory. A folder is only
believed after its findings.csv matches the hash in its own manifest.json, and a
review of this org that can't be verified ends a streak instead of being skipped
over, so the counts can come out too low but never too high. Nothing here writes.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import csvsafe
from .checks import Finding

MAX_FINDINGS_BYTES = 50 * 1024 * 1024


@dataclass
class PriorReview:
    review_date: str
    folder: str
    manifest_sha256: str
    # (check_id, normalized subject) of every finding; None when the findings couldn't be verified.
    keys: set[tuple[str, str]] | None
    problem: str = ""
    # Checks that review did not run. A check's absence from `keys` means "found
    # nothing" only for the checks that ran; for these it means "did not look".
    skipped: list[str] = field(default_factory=list)


@dataclass
class History:
    reviews: list[PriorReview] = field(default_factory=list)  # oldest first, one per review date
    skipped: list[dict] = field(default_factory=list)  # folders that aren't a usable review, and why
    superseded: list[str] = field(default_factory=list)  # earlier runs of a review that was run again
    not_read: int = 0  # older review dates beyond the window
    limit: int = 12

    @property
    def unverified(self) -> list[PriorReview]:
        return [r for r in self.reviews if r.keys is None]

    def manifest_block(self) -> dict:
        return {
            "method": "earlier review folders in the output directory, each verified against its manifest.json",
            "window": self.limit,
            "reviews": [
                {"review_date": r.review_date, "folder": r.folder, "manifest_sha256": r.manifest_sha256,
                 "verified": r.keys is not None, **({"problem": r.problem} if r.problem else {})}
                for r in self.reviews
            ],
            "older_reviews_not_read": self.not_read,
            "superseded_runs": self.superseded,
            "skipped": self.skipped,
        }

    def caveats(self) -> list[str]:
        """Plain-language limits on the counts, for the report."""
        lines = []
        if self.unverified:
            dates = ", ".join(r.review_date for r in self.unverified)
            lines.append(f"Could not verify the findings of the review(s) on {dates}; counts stop there.")
        if self.skipped:
            lines.append(f"{len(self.skipped)} folder(s) in the output directory were not counted; "
                         "see `history` in manifest.json.")
        return lines


def subject_key(subject: str) -> str:
    return subject.strip().casefold()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(folder: Path) -> tuple[dict, str] | None:
    path = folder / "manifest.json"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        data = path.read_bytes()
        manifest = json.loads(data)
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None
    return manifest, hashlib.sha256(data).hexdigest()


def _finding_keys(folder: Path, manifest: dict) -> tuple[set[tuple[str, str]] | None, str]:
    files = manifest.get("files")
    expected = files.get("findings.csv") if isinstance(files, dict) else None
    if not isinstance(expected, str):
        return None, "manifest.json doesn't list findings.csv"
    path = folder / "findings.csv"
    if path.is_symlink() or not path.is_file():
        return None, "findings.csv is missing"
    if path.stat().st_size > MAX_FINDINGS_BYTES:
        return None, "findings.csv is too large to read"
    if sha256_file(path) != expected:
        return None, "findings.csv doesn't match its manifest.json"
    try:
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not {"check_id", "subject"} <= set(reader.fieldnames or []):
                return None, "findings.csv has no check_id and subject columns"
            return {(csvsafe.value(row["check_id"]), subject_key(csvsafe.value(row["subject"] or "")))
                    for row in reader}, ""
    except (OSError, UnicodeDecodeError, csv.Error):
        return None, "findings.csv can't be read"


def load_history(out_dir: Path, current_folder: str, org_url: str, as_of: date, limit: int = 12) -> History:
    history = History(limit=limit)
    try:
        with os.scandir(out_dir) as it:
            entries = sorted(it, key=lambda e: e.name, reverse=True)  # newest run first
    except (FileNotFoundError, NotADirectoryError):
        return history

    # review date -> (folder, manifest, manifest hash) of the newest run for that date
    latest: dict[str, tuple[Path, dict, str]] = {}
    for entry in entries:
        if entry.name == current_folder:
            continue  # the run being written now (or the copy it replaces)
        if entry.is_symlink():
            history.skipped.append({"folder": entry.name, "reason": "symlink, not followed"})
            continue
        if not entry.is_dir(follow_symlinks=False):
            continue  # stray files such as .DS_Store
        read = _read_manifest(Path(entry.path))
        if read is None:
            history.skipped.append({"folder": entry.name, "reason": "no readable manifest.json"})
            continue
        manifest, manifest_hash = read
        if manifest.get("org_url") != org_url:
            history.skipped.append({"folder": entry.name, "reason": "a review of a different org"})
            continue
        try:
            reviewed = date.fromisoformat(manifest.get("review_date"))
        except (TypeError, ValueError):
            history.skipped.append({"folder": entry.name, "reason": "manifest.json has no review date"})
            continue
        if reviewed > as_of:
            history.skipped.append({"folder": entry.name, "reason": "reviewed after this review's date"})
        elif reviewed == as_of or reviewed.isoformat() in latest:
            history.superseded.append(entry.name)  # an earlier run of a review that was run again
        else:
            latest[reviewed.isoformat()] = (Path(entry.path), manifest, manifest_hash)

    dates = sorted(latest)
    history.not_read = max(0, len(dates) - limit)
    for review_date in dates[-limit:]:
        folder, manifest, manifest_hash = latest[review_date]
        keys, problem = _finding_keys(folder, manifest)
        history.reviews.append(PriorReview(review_date, folder.name, manifest_hash, keys, problem,
                                           list(manifest.get("skipped_checks") or [])))
    return history


def label(f: Finding) -> str:
    """The History cell for one finding; empty when there was no history to read."""
    if f.reviews_open == 0:
        return ""
    if f.reviews_open > 1:
        return f"{f.reviews_open} reviews in a row, first seen {f.first_seen}"
    return f"Back again, first seen {f.first_seen}" if f.reopened else "New"


def repeat_summary(findings: list[Finding]) -> str | None:
    """Counts only (no names), for email and Slack. None when there was no history to read."""
    if not findings or findings[0].reviews_open == 0:
        return None
    repeats = [f.reviews_open for f in findings if f.reviews_open > 1]
    if not repeats:
        return "Open since the last review: none"
    return f"Open since the last review: {len(repeats)} of {len(findings)} (longest: {max(repeats)} reviews in a row)"


def age_findings(findings: list[Finding], history: History, as_of: date) -> None:
    """Set first_seen, reviews_open and reopened on each finding. Leaves them unset with no history."""
    if not history.reviews:
        return
    previous = history.reviews[-1]
    for f in findings:
        key = (f.check_id, subject_key(f.subject))
        streak = 1  # this review
        for review in reversed(history.reviews):
            if review.keys is None or key not in review.keys:
                break
            streak += 1
        seen = [r.review_date for r in history.reviews if r.keys is not None and key in r.keys]
        f.reviews_open = streak
        f.first_seen = seen[0] if seen else as_of.isoformat()
        # Only when the last review is known to have been clear of it. A review
        # that skipped the check is not known to have been clear: "Back again"
        # asserts the problem was fixed and returned, and a skipped check is the
        # one case where nobody looked. --github is optional, so an omitted
        # quarter would otherwise make every open graph finding claim that.
        f.reopened = (
            bool(seen)
            and previous.keys is not None
            and key not in previous.keys
            and f.check_id not in previous.skipped
        )
