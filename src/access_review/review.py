"""One review, from a snapshot to a finished run folder with review items.

Shared by the CLI and the collect Lambda, so both produce identical evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .checks import Config, Finding, ReviewContext, run_checks
from .history import age_findings, load_history
from .identity import GitHubSnapshot, IdentityGraph, project_github, project_snapshot
from .items import ITEMS_FILE, ReviewItem, build_items, items_json
from .models import Snapshot
from .report import run_dir_name, write_report
from .roster import RosterEntry


@dataclass
class ReviewRun:
    run_dir: Path
    findings: list[Finding]
    skipped: list[str]
    items: list[ReviewItem] | None  # None for local CLI runs, which have no Slack review

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
    github_path: Path | None = None,
) -> ReviewRun:
    """Checks, findings history from sibling folders in out_dir, and the report.
    With require_items (the AWS review), also the review items for Slack.

    github_path adds a second source: the Okta snapshot and it are projected
    into one IdentityGraph, which is what the cross-source checks read. Without
    it those checks are skipped rather than run against half an estate.
    """
    graph = None
    if github_path is not None:
        github = GitHubSnapshot.from_dict(json.loads(github_path.read_text()))
        graph = IdentityGraph.compose(
            project_snapshot(snapshot, config.service_accounts), project_github(github)
        )
    ctx = ReviewContext(snapshot, roster, config, as_of, graph=graph)
    findings, skipped = run_checks(ctx)
    history = load_history(out_dir, run_dir_name(snapshot), snapshot.org_url, as_of, config.history_reviews)
    age_findings(findings, history, as_of)
    items = build_items(ctx, findings) if require_items else None
    extra = {ITEMS_FILE: items_json(items, as_of, config.app_unused_days)} if items is not None else None
    run_dir = write_report(out_dir, snapshot, findings, skipped, config, as_of,
                           roster_path=roster_path, history=history, extra_files=extra, graph=graph)
    return ReviewRun(run_dir, findings, skipped, items)
