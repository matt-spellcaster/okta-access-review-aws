"""Write the review as audit evidence: a readable report, CSVs, the raw
snapshot, and a manifest with SHA-256 hashes of every file."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections import Counter
from dataclasses import asdict
from datetime import date
from pathlib import Path

from . import __version__
from .checks import CHECKS, SEVERITIES, Config, Finding
from .identity import OKTA, IdentityGraph
from .csvsafe import cell
from .history import History, label
from .models import SIGN_IN_STATUSES, Snapshot
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



def other_sources(graph: IdentityGraph | None) -> list[tuple[str, int, list[str]]]:
    """Sources beyond Okta, as (name, principals, gaps).

    The report speaks for every source the review read. A gaps list that only
    covers Okta would let the PDF say "Complete" while a whole source failed,
    which is the one claim an evidence artifact must never make wrongly.
    """
    if graph is None:
        return []
    counts: dict[str, int] = {}
    for principal in graph.principals:
        counts[principal.source] = counts.get(principal.source, 0) + 1
    return [(m.source, counts.get(m.source, 0), m.gaps) for m in graph.sources if m.source != OKTA]


def all_gaps(snapshot: Snapshot, graph: IdentityGraph | None) -> list[str]:
    """Every gap, each named with the source it came from."""
    gaps = list(snapshot.gaps)
    for source, _, source_gaps in other_sources(graph):
        gaps += [f"{source}: {gap}" for gap in source_gaps]
    return gaps


def render_markdown(snapshot: Snapshot, findings: list[Finding], skipped: list[str], as_of: date,
                    graph: IdentityGraph | None = None,
                    roster: str = "not provided", history: History | None = None) -> str:
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
        *[f"- **Also read:** {name} ({n} principals)" for name, n, _ in other_sources(graph)],
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
    gaps = all_gaps(snapshot, graph)
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
    extra_files: dict[str, str] | None = None,
    graph: IdentityGraph | None = None,
) -> Path:
    """extra_files are {name: text} written into the run folder before the
    manifest, so they are hashed with everything else (e.g. review_items.json)."""
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

    (run_dir / "report.md").write_text(
        render_markdown(snapshot, findings, skipped, as_of, graph=graph, roster=roster_text, history=history)
    )
    finding_rows = [_finding_row(f) for f in findings]
    _write_csv(run_dir / "findings.csv", finding_rows, FINDING_COLUMNS)
    matrix = access_matrix(snapshot)
    _write_csv(run_dir / "access_matrix.csv", matrix, MATRIX_COLUMNS)
    write_pdf(run_dir / "report.pdf", snapshot, findings, skipped, as_of, matrix,
              Branding.from_config(config.branding), roster_label=roster_text,
              history_note=HISTORY_NOTE if history and history.reviews else "", graph=graph)
    (run_dir / "snapshot.json").write_text(json.dumps(snapshot.to_dict(), indent=2) + "\n")
    for name, text in extra_files.items():
        (run_dir / name).write_text(text)

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
        "complete": not all_gaps(snapshot, graph),
        "data_gaps": all_gaps(snapshot, graph),
        "sources": [{"source": name, "principals": n, "gaps": gaps} for name, n, gaps in other_sources(graph)],
        "history": history.manifest_block() if history is not None else None,
        "files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(run_dir.iterdir())
            if p.name not in UNHASHED and p.is_file() and not p.is_symlink()
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return run_dir
