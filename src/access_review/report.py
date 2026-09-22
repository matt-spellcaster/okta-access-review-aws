"""Write the review as audit evidence: a readable report, CSVs, the raw
snapshot, and a manifest with SHA-256 hashes of every file."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import NamedTuple

from . import __version__
from .checks import CHECKS, SEVERITIES, Config, Finding
from .csvsafe import cell
from .history import History, label
from .identity import OKTA, IdentityGraph
from .models import SIGN_IN_STATUSES, Snapshot, format_time
from .pdf import Branding, write_pdf

MATRIX_COLUMNS = [
    "login", "name", "status", "type", "department", "manager", "last_login",
    "mfa", "admin_roles", "groups", "apps", "decision", "reviewer", "reviewed_on", "notes",
]
# Spelled out so that adding a Finding field can't change the published CSV by accident.
FINDING_COLUMNS = [
    "check_id", "title", "severity", "controls", "subject", "detail", "remediation",
    "first_seen", "reviews_open", "reopened",
]
# Written after the manifest (or by it), so never hashed into it.
UNHASHED = {"manifest.json", "attestations.json"}
# Files write_report produces itself; extra_files may not replace them.
RESERVED_FILES = UNHASHED | {
    "roster.csv", "report.md", "findings.csv", "access_matrix.csv", "report.pdf", "snapshot.json",
}


class ReportError(Exception):
    pass


def run_dir_name(snapshot: Snapshot) -> str:
    return snapshot.collected_at.strftime("%Y%m%dT%H%M%SZ")


def access_matrix(snapshot: Snapshot) -> list[dict]:
    rows = []
    for u in sorted(snapshot.users, key=lambda u: u.login):
        groups = sorted(g.name for g in snapshot.groups_for(u.id) if g.type != "BUILT_IN")
        apps = sorted({f"{app.label} ({how})" for app, how in snapshot.apps_for(u.id)})
        # Factors are only collected for users who can sign in, and roles for users who aren't deprovisioned.
        if u.status not in SIGN_IN_STATUSES:
            mfa = "n/a"
        else:
            mfa = "unknown" if u.factors is None else (", ".join(u.factors) or "none")
        if u.status == "DEPROVISIONED":
            admin_roles = "n/a"
        else:
            admin_roles = "unknown" if u.admin_roles is None else "; ".join(u.admin_roles)
        rows.append({
            "login": u.login,
            "name": u.name,
            "status": u.status,
            "type": u.user_type,
            "department": u.department,
            "manager": u.manager,
            "last_login": u.last_login.date().isoformat() if u.last_login else "never",
            "mfa": mfa,
            "admin_roles": admin_roles,
            "groups": "; ".join(groups),
            "apps": "; ".join(apps),
            # Filled in by the reviewer: keep | revoke | modify
            "decision": "", "reviewer": "", "reviewed_on": "", "notes": "",
        })
    return rows


HISTORY_NOTE = (
    "History counts reviews in this output folder that were verified against their own manifest.json. "
    "A finding may be older than the oldest review kept here."
)



class SourceReport(NamedTuple):
    """One source beyond Okta, as the report, PDF and manifest name it."""

    source: str
    principals: int
    collected_at: str  # "" when the source did not say when it was read
    gaps: list[str]


def other_sources(graph: IdentityGraph | None) -> list[SourceReport]:
    """Sources beyond Okta, for the "Also read" line and the manifest block.

    Display only. `all_gaps` is what decides completeness and it reads every
    source including Okta, because a gaps list that skipped one would let the
    PDF say "Complete" while a whole source failed -- the one claim an evidence
    artifact must never make wrongly.
    """
    if graph is None:
        return []
    counts = Counter(p.source for p in graph.principals)
    return [
        SourceReport(m.source, counts.get(m.source, 0), format_time(m.collected_at), m.gaps)
        for m in graph.sources if m.source != OKTA
    ]


def all_gaps(snapshot: Snapshot, graph: IdentityGraph | None) -> list[str]:
    """Every gap from every source the review read, named with its source.

    With a graph this reads the graph's own per-source metadata rather than
    `snapshot.gaps`, because the Okta projection records gaps the snapshot
    never had: a group member no user read returned, an app assigned to a group
    that is not in the snapshot. Reading `snapshot.gaps` dropped those, so a
    review could be signed off "complete" while `graph.incomplete_sources()`
    said otherwise. One source of truth, and it is the graph.
    """
    if graph is None:
        return list(snapshot.gaps)
    return [f"{m.source}: {gap}" for m in graph.sources for gap in m.gaps]


def render_markdown(snapshot: Snapshot, findings: list[Finding], skipped: list[str], as_of: date,
                    graph: IdentityGraph | None = None,
                    roster: str = "not provided", history: History | None = None,
                    gaps: list[str] | None = None,
                    sources: list[SourceReport] | None = None) -> str:
    # Derived from the graph when the caller did not already do it, so there is
    # never a path where the markdown and the manifest disagree about gaps.
    gaps = all_gaps(snapshot, graph) if gaps is None else gaps
    sources = other_sources(graph) if sources is None else sources
    counts = Counter(f.severity for f in findings)
    live = sum(1 for u in snapshot.users if u.status != "DEPROVISIONED")
    activity = (
        snapshot.activity_since.strftime("%Y-%m-%d") if snapshot.activity_since
        else "not collected (AR-12 and AR-13 have no evidence to read)"
    )
    lines = [
        "# Okta user access review",
        "",
        f"- **Org:** {snapshot.org_url}",
        f"- **Data collected:** {snapshot.collected_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Review date:** {as_of.isoformat()}",
        f"- **Scope:** {len(snapshot.users)} users ({live} not deprovisioned), "
        f"{len(snapshot.groups)} groups, {len(snapshot.apps)} apps",
        f"- **Activity checked from:** {activity}",
        f"- **HR roster:** {roster}",
        *[f"- **Also read:** {s.source} ({s.principals} principals, read {s.collected_at[:10]})" for s in sources],
        f"- **Tool:** okta-access-review {__version__} (read-only)",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    lines += [f"| {s} | {counts.get(s, 0)} |" for s in SEVERITIES]
    if skipped:
        lines += ["", f"Skipped (needs data this run did not have): {', '.join(skipped)}"]
    if gaps:
        lines += ["", "## ⚠️ Data gaps", "", "This review is incomplete. Fix these before relying on it:", ""]
        lines += [f"- {g}" for g in gaps]

    lines += ["", "## Findings", ""]
    aged = bool(history and history.reviews)
    if history is not None:
        if aged:
            lines += [HISTORY_NOTE, ""]
        else:
            lines += ["No earlier review of this org was found in this output folder, so findings have no history yet.",
                      ""]
        lines += [f"- {c}" for c in history.caveats()]
        if history.caveats():
            lines.append("")
    if not findings:
        lines.append("No findings.")
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)
    for check in CHECKS:
        items = by_check.get(check.id)
        if not items:
            continue
        lines += [
            f"### {check.id} · {check.title}",
            "",
            f"**Controls:** {', '.join(check.controls)}  ",
            f"**Fix:** {check.remediation}",
            "",
        ]
        if aged:
            lines += ["| Severity | Subject | Detail | History |", "|---|---|---|---|"]
            lines += [f"| {f.severity} | `{f.subject}` | {f.detail} | {label(f)} |" for f in items]
        else:
            lines += ["| Severity | Subject | Detail |", "|---|---|---|"]
            lines += [f"| {f.severity} | `{f.subject}` | {f.detail} |" for f in items]
        lines.append("")

    lines += [
        "## Checks run",
        "",
        "| ID | Check | Default severity | Controls |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {c.id} | {c.title} | {c.severity} | {', '.join(c.controls)} |"
        + (" *(skipped)*" if c.id in skipped else "")
        for c in CHECKS
    ]
    lines += [
        "",
        "## Reviewer sign-off",
        "",
        "Record a decision for every row in `access_matrix.csv`, then sign below.",
        "",
        "- Reviewer: ____________________",
        "- Date: ____________________",
        "",
        "Or record the sign-off in this folder, bound to its manifest.json:",
        "`access-review attest <this folder> --decision approved --reviewer \"Your Name\"`. "
        "It checks every file against manifest.json first.",
        "",
    ]
    return "\n".join(lines)


def _finding_row(f: Finding) -> dict:
    row = {**asdict(f), "controls": "; ".join(f.controls)}
    if f.reviews_open == 0:  # no history was read: leave the columns blank rather than print a misleading 0
        row.update(first_seen="", reviews_open="", reopened="")
    else:
        row["reopened"] = "yes" if f.reopened else "no"
    return row


def _write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows({k: cell(v) for k, v in row.items()} for row in rows)


def _write_text(path: Path, content: str | Iterable[str]) -> None:
    """Write an evidence file that may arrive as a stream of chunks.

    `review_items.json` is handed over as an iterator (`items.items_chunks`),
    so the largest file in the folder is never a string anybody holds.
    `Path.write_text` costs the document twice over -- once for the string the
    caller built and once for the encoded copy it makes -- at the point in the
    run where the access matrix is still bound, on the peak the PDF has just
    set. Measured at 250k
    items, that write plus the manifest's read-back peaks 243 MB above the
    items themselves; a chunk at a time and a blockwise hash peak 15 MB, for
    the same bytes in the same wall time.

    Text mode with no `encoding=`, exactly as `Path.write_text` had it: these
    bytes go into a signed manifest and are read back by `attest`, so the codec
    and the newline translation must stay what they were. `items_chunks` passes
    `ensure_ascii=True`, which is what makes that safe for the one file here
    big enough to care.
    """
    with path.open("w") as fh:
        # A str is itself an iterable of str, and `writelines` would take it
        # one character at a time.
        fh.write(content) if isinstance(content, str) else fh.writelines(content)


def _sha256(path: Path) -> str:
    """The manifest hash of one file, read in blocks rather than whole.

    `read_bytes` on `review_items.json` is another full copy of the largest
    file in the folder, held for the one line that hashes it, and it lands
    while the access matrix is still bound. This is
    the other half of not materialising the file: writing it a chunk at a time
    buys nothing if the manifest then reads all of it back.
    """
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def roster_record(roster_path: Path | None) -> dict | None:
    """What the review compared against: the roster's file name, row count and hash."""
    if roster_path is None:
        return None
    data = roster_path.read_bytes()
    with roster_path.open(newline="") as f:
        rows = sum(1 for _ in csv.DictReader(f))
    # Only the file name: the full path could reveal a local username.
    return {"source_name": roster_path.name, "copied_as": "roster.csv", "rows": rows,
            "sha256": hashlib.sha256(data).hexdigest()}


def roster_label(roster: dict | None) -> str:
    if roster is None:
        return "not provided (AR-01 to AR-03, AR-12 and AR-13 skipped)"
    return f"{roster['source_name']}, {roster['rows']} people, SHA-256 {roster['sha256'][:12]}"


def write_report(
    out_dir: Path,
    snapshot: Snapshot,
    findings: list[Finding],
    skipped: list[str],
    config: Config,
    as_of: date,
    roster_path: Path | None = None,
    history: History | None = None,
    extra_files: dict[str, str | Iterable[str]] | None = None,
    graph: IdentityGraph | None = None,
) -> Path:
    """extra_files are {name: text} written into the run folder before the
    manifest, so they are hashed with everything else (e.g. review_items.json).
    A value may instead be an iterable of chunks, which is written a chunk at a
    time and never held whole -- see `_write_text`."""
    extra_files = extra_files or {}
    for name in extra_files:
        if name in RESERVED_FILES or Path(name).name != name or name.startswith("."):
            raise ReportError(f"extra file name {name!r} is not allowed")
    run_dir = out_dir / run_dir_name(snapshot)
    if (run_dir / "attestations.json").exists():
        raise ReportError(
            f"{run_dir} is signed off (attestations.json); refusing to overwrite it. "
            "Use a different --out, or move the folder, if you meant to redo this review."
        )
    run_dir.mkdir(parents=True, exist_ok=True)

    # Keep the exact roster this review used, so the evidence shows what it was compared against.
    roster = roster_record(roster_path)
    if roster_path is not None:
        shutil.copyfile(roster_path, run_dir / "roster.csv")
    else:
        (run_dir / "roster.csv").unlink(missing_ok=True)  # don't hash a stale copy from an earlier run
    roster_text = roster_label(roster)
    # Computed once. Every artifact this function writes -- the markdown, the
    # PDF and the manifest's signed `complete` flag -- is the same answer.
    gaps = all_gaps(snapshot, graph)
    sources = other_sources(graph)

    (run_dir / "report.md").write_text(
        render_markdown(snapshot, findings, skipped, as_of, roster=roster_text, history=history,
                        gaps=gaps, sources=sources)
    )
    finding_rows = [_finding_row(f) for f in findings]
    _write_csv(run_dir / "findings.csv", finding_rows, FINDING_COLUMNS)
    matrix = access_matrix(snapshot)
    _write_csv(run_dir / "access_matrix.csv", matrix, MATRIX_COLUMNS)
    write_pdf(run_dir / "report.pdf", snapshot, findings, skipped, as_of, matrix,
              Branding.from_config(config.branding), roster_label=roster_text,
              history_note=HISTORY_NOTE if history and history.reviews else "",
              gaps=gaps, sources=sources)
    (run_dir / "snapshot.json").write_text(json.dumps(snapshot.to_dict(), indent=2) + "\n")
    for name, content in extra_files.items():
        _write_text(run_dir / name, content)
    # An optional evidence file this run did not produce must not survive into
    # its manifest. Re-running into the same folder without --github otherwise
    # leaves the previous run's github_snapshot.json and transitions.json in
    # place, and the hashing below signs them as part of a review that never
    # read that source -- which `attest` then reports as a full match. Reserved
    # files are this function's own output and are rewritten above; anything
    # else in the folder came from extra_files, this run's or an earlier one's.
    for stale in run_dir.iterdir():
        if stale.is_file() and not stale.is_symlink() \
                and stale.name not in RESERVED_FILES and stale.name not in extra_files:
            stale.unlink()

    manifest = {
        "tool": f"okta-access-review {__version__}",
        "org_url": snapshot.org_url,
        "collected_at": snapshot.to_dict()["collected_at"],
        "review_date": as_of.isoformat(),
        "config": asdict(config),
        "roster": roster,
        "finding_counts": dict(Counter(f.severity for f in findings)),
        "skipped_checks": skipped,
        "activity_since": snapshot.to_dict()["activity_since"],
        "app_usage_since": snapshot.to_dict()["app_usage_since"],
        # Every source, not just Okta: a manifest that called a review complete
        # while another source failed would be signed-off evidence of a claim
        # nobody checked.
        "complete": not gaps,
        "data_gaps": gaps,
        "sources": [s._asdict() for s in sources],
        "history": history.manifest_block() if history is not None else None,
        "files": {
            p.name: _sha256(p)
            for p in sorted(run_dir.iterdir())
            if p.name not in UNHASHED and p.is_file() and not p.is_symlink()
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return run_dir
