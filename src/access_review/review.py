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

from .checks import Config, Finding, ReviewContext, okta_user_subjects, run_checks
from .history import age_findings, load_history
from .identity import OKTA, GitHubSnapshot, IdentityGraph, project_github, project_snapshot
from .items import ITEMS_FILE, ReviewItem, build_items, items_chunks
from .models import Snapshot
from .register import Register
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
    into one IdentityGraph alongside Okta's own projection, which is what the
    graph checks read.

    The graph is built either way. An estate of one is still an estate: the
    register declares service accounts in Okta too, and AR-18's whole case --
    an Okta API client whose accountable owner has left -- is built from the
    snapshot, the roster and the register, none of which need a second source.
    Gating the graph on `github_path` meant every graph check was skipped on
    an Okta-only run, which is every AWS run, so the one check written for
    Okta's own service clients could not fire where it was meant to. What a
    second source adds is the other estate, not the graph.
    """
    # Values are text, or an iterable of chunks for a file too big to hold
    # whole. `write_report` writes either straight into the run folder.
    extra: dict[str, str | Iterable[str]] = {}
    # The register reaches both projections. It used to reach only Okta, so a
    # declared GitHub bot was a service account in the config and an unowned
    # mystery in the graph.
    projections = [project_snapshot(snapshot, config.service_accounts)]
    if github_path is not None:
        github = _load_github(github_path)
        projections.append(project_github(github, config.service_accounts))
    graph = IdentityGraph.compose(*projections)
    # Every AWS run builds a graph now, in the 1024 MB collect Lambda. The
    # projections carry their own indexes, and left in scope they would stay
    # live through the checks, the items and the PDF beside the composed copy.
    del projections
    if github_path is not None:
        _note_skew(graph, github, snapshot)
        # The data nine findings rest on, inside the bundle the manifest signs.
        # Without it `attest` can verify the report but not what it was read from.
        extra[GITHUB_SNAPSHOT_FILE] = json.dumps(github.to_dict(), indent=2) + "\n"
    _note_register(graph, config.service_accounts)
    ctx = ReviewContext(snapshot, roster, config, as_of, graph=graph)
    findings, skipped = run_checks(ctx)
    history = load_history(out_dir, run_dir_name(snapshot), snapshot.org_url, as_of, config.history_reviews)
    age_findings(findings, history, as_of, okta_user_subjects(graph, snapshot))
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


def _note_register(graph: IdentityGraph, register: Register) -> None:
    """The two ways a register entry declares nothing that the projections
    cannot see for themselves, recorded as gaps on the sources they concern.

    After composing, like `_note_skew`, and for the same reason in reverse: both
    of these need the whole graph. An owner is an identity key, and the estate
    that evidences a person is usually not the estate holding the account they
    own -- a GitHub bot owned by someone whose only account is in Okta is the
    ordinary case, and neither projection can settle it alone. The set of
    sources actually read is likewise only knowable once they are all in.

    Gaps rather than findings. AR-15 already reports the account itself, at the
    severity an unowned credential deserves; what these add is the reason, which
    is that the register is wrong rather than that nobody has claimed the
    account. One is fixed by finding an owner, the other by correcting a line
    somebody already wrote, and an auditor reading `all_gaps` should be able to
    tell which review they are holding.
    """
    for principal, owner in graph.unattested_owners():
        meta = graph.source(principal.source)
        if meta is None:  # a principal naming an undeclared source cannot exist
            continue
        meta.gaps.append(
            f"The service account register declares {principal.label!r} is owned by {owner!r}, "
            f"which no source evidences as a person: no account in any estate this review read "
            f"belongs to them. The account is reported as unowned, because an owner who cannot be "
            f"reached is not accountable for it. Correct the owner, or remove it and say so."
        )
    read = {m.source.lower() for m in graph.sources}
    kinds_read = {_kind(s) for s in read}
    # An estate of a kind this run was never asked to read is out of scope, not
    # a hole in it: the AWS pipeline reads Okta alone, and a register that also
    # declares the GitHub bots would otherwise mark every one of its reviews
    # INCOMPLETE for good -- a banner nobody can clear teaches everyone to skip
    # it. What stays a gap is the dead entry: a kind nothing reads at all, or a
    # name that misses the estate of its kind that was read (a typo'd org).
    unread = [s for s in register.sources()
              if s.lower() not in read and (_kind(s) in kinds_read or _kind(s) not in SOURCE_KINDS)]
    if unread:
        # On Okta's metadata because every review has one and this is a
        # statement about the review rather than about any source in it.
        meta = graph.source(OKTA)
        if meta is not None:
            meta.gaps.append(
                f"The service account register declares accounts in {len(unread)} source(s) this "
                f"review did not read: {', '.join(sorted(unread))}. Those entries declare nothing "
                f"here, and nothing in this review checked them."
            )


# The kinds of estate this tool can read. A register source is `okta` or
# `github:<org>`; anything else names an estate no run will ever check.
SOURCE_KINDS = {"okta", "github"}


def _kind(source: str) -> str:
    return source.lower().split(":", 1)[0]


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
