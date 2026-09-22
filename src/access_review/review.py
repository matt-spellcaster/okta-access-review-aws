"""One review, from a snapshot to a finished run folder with review items.

Shared by the CLI and the collect Lambda, so both produce identical evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .checks import Config, Finding, ReviewContext, run_checks
from .history import age_findings, load_history
from .identity import OKTA, GitHubSnapshot, IdentityGraph, project_github, project_snapshot
from .items import ITEMS_FILE, ReviewItem, build_items, items_chunks
from .models import Snapshot
from .report import ReportError, all_gaps, run_dir_name, write_report
from .roster import RosterEntry
from .transitions import TRANSITIONS_FILE, Transition, build_transitions, transitions_json

# The evidence for a graph source, written into the run folder so the manifest
# hashes it. Not a RESERVED_FILES name: it goes through extra_files like
# review_items.json, which is the mechanism for "hashed with everything else".
GITHUB_SNAPSHOT_FILE = "github_snapshot.json"
# How far apart two sources' collection times may be before the review says so.
# One review date covering reads a fortnight apart is not one point in time,
# and nothing downstream could otherwise tell.
SOURCE_SKEW_DAYS = 7


@dataclass
class ReviewRun:
    run_dir: Path
    findings: list[Finding]
    skipped: list[str]
    items: list[ReviewItem] | None  # None for local CLI runs, which have no Slack review
    # Every source's gaps, already source-named. The one answer about
    # completeness: Slack, email, the CLI and the Step Functions output all read
    # this rather than snapshot.gaps, which speaks for Okta alone.
    gaps: list[str] = field(default_factory=list)
    # One per person the roster says has gone. None -- like `items` -- when the
    # review had no graph or no roster and never ran the analysis, which is a
    # different answer from a review that ran it and found nobody had left.
    transitions: list[Transition] | None = None

    @property
    def complete(self) -> bool:
        return not self.gaps

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
    # Values are text, or an iterable of chunks for a file too big to hold
    # whole. `write_report` writes either straight into the run folder.
    extra: dict[str, str | Iterable[str]] = {}
    if github_path is not None:
        github = _load_github(github_path)
        # The register reaches both projections. It used to reach only Okta,
        # so a declared GitHub bot was a service account in the config and an
        # unowned mystery in the graph.
        graph = IdentityGraph.compose(
            project_snapshot(snapshot, config.service_accounts),
            project_github(github, config.service_accounts),
        )
        _note_skew(graph, github, snapshot)
        # The data nine findings rest on, inside the bundle the manifest signs.
        # Without it `attest` can verify the report but not what it was read from.
        extra[GITHUB_SNAPSHOT_FILE] = json.dumps(github.to_dict(), indent=2) + "\n"
    ctx = ReviewContext(snapshot, roster, config, as_of, graph=graph)
    findings, skipped = run_checks(ctx)
    history = load_history(out_dir, run_dir_name(snapshot), snapshot.org_url, as_of, config.history_reviews)
    age_findings(findings, history, as_of)
    items = build_items(ctx, findings) if require_items else None
    if items is not None:
        # The chunks, not the document: this is the one file in the folder
        # whose size is a cross product, and holding it here keeps it live
        # through the access matrix, the PDF and the manifest.
        extra[ITEMS_FILE] = items_chunks(items, as_of, config.app_unused_days)
    # Computed once and handed to the bundles rather than recomputed there: the
    # answer about completeness has one owner, and a bundle is now a seventh
    # place that states it.
    gaps = all_gaps(snapshot, graph)
    transitions = build_transitions(ctx, findings, gaps)
    if transitions is not None:
        # Not `if transitions:` -- an empty list means the analysis ran and
        # nobody had left, which is the denominator that makes the bundles that
        # do exist mean something. Writing nothing would make that run folder
        # indistinguishable from one that never looked.
        extra[TRANSITIONS_FILE] = transitions_json(transitions, as_of)
    run_dir = write_report(out_dir, snapshot, findings, skipped, config, as_of,
                           roster_path=roster_path, history=history, extra_files=extra or None, graph=graph)
    return ReviewRun(run_dir, findings, skipped, items, gaps, transitions)


def _load_github(path: Path) -> GitHubSnapshot:
    """A ReportError, not a traceback: the path is operator input, and cli.py
    already turns ReportError into a one-line message. The path is named, the
    contents never are."""
    try:
        return GitHubSnapshot.from_dict(json.loads(path.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ReportError(f"{path}: not a readable GitHub snapshot ({type(e).__name__})") from e


def _note_skew(graph: IdentityGraph, github: GitHubSnapshot, snapshot: Snapshot) -> None:
    """A stale --github file otherwise produces critical findings dated by the
    Okta snapshot, with nothing in the evidence saying the two reads were weeks
    apart. Recorded on the source's own metadata, so it reaches the report, the
    PDF's Status row and the manifest's `complete` flag like any other gap.

    After composing, not before: a gap on the GitHubSnapshot would also clear
    `activity_complete`, and being read a fortnight early is not a credential
    read that failed.
    """
    meta = next((m for m in graph.sources if m.org == github.org and m.source != OKTA), None)
    if meta is None:
        return
    if github.collected_at is None:
        meta.gaps.append("The GitHub snapshot does not say when it was collected.")
        return
    days = abs((snapshot.collected_at.date() - github.collected_at.date()).days)
    if days > SOURCE_SKEW_DAYS:
        meta.gaps.append(
            f"This snapshot was collected {days} days from the Okta snapshot "
            f"({github.collected_at.date()} against {snapshot.collected_at.date()}), so the two "
            f"sources are not one point in time and a finding across them may already be stale."
        )
