"""One review, from a snapshot to a finished run folder with review items.

Shared by the CLI and the collect Lambda, so both produce identical evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .checks import Config, Finding, ReviewContext, run_checks
from .history import age_findings, load_history
from .items import ITEMS_FILE, ReviewItem, build_items, items_json
from .models import Snapshot
from .report import run_dir_name, write_report
from .roster import RosterEntry


@dataclass
class ReviewRun:
    run_dir: Path
    findings: list[Finding]
    skipped: list[str]
    items: list[ReviewItem] | None  # None when no admin_login is configured (local CLI use)

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256((self.run_dir / "manifest.json").read_bytes()).hexdigest()


def run_review(
    snapshot: Snapshot,
    roster: dict[str, RosterEntry] | None,
    roster_path: Path | None,
    config: Config,
    as_of: date,
    out_dir: Path,
    require_items: bool = False,
) -> ReviewRun:
    """Checks, findings history from sibling folders in out_dir, review items,
    and the report. With require_items, a missing admin_login is an error
    rather than a review without items."""
    ctx = ReviewContext(snapshot, roster, config, as_of)
    findings, skipped = run_checks(ctx)
    history = load_history(out_dir, run_dir_name(snapshot), snapshot.org_url, as_of, config.history_reviews)
    age_findings(findings, history, as_of)
    items = build_items(ctx) if (require_items or config.admin_login) else None
    extra = {ITEMS_FILE: items_json(items, as_of, config.app_unused_days)} if items is not None else None
    run_dir = write_report(out_dir, snapshot, findings, skipped, config, as_of,
                           roster_path=roster_path, history=history, extra_files=extra)
    return ReviewRun(run_dir, findings, skipped, items)
