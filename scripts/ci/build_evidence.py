"""Bundle CI check results into an evidence folder with a summary and a manifest.

    python3 scripts/ci/build_evidence.py results evidence --expect tests --expect secret-scan ...

Copies everything from the results folder, writes summary.md (also appended to
the GitHub job summary) and manifest.json with a SHA-256 hash of every file,
and exits 1 if any expected check failed or is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from record import run_metadata  # same folder


def load_results(results: Path) -> dict[str, dict]:
    found = {}
    for path in sorted(results.rglob("*.result.json")):
        record = json.loads(path.read_text())
        found[record["check"]] = record
    return found


def summarize(records: dict[str, dict], expected: list[str], run: dict[str, str]) -> tuple[str, bool]:
    rows = []
    ok = True
    for check in expected + sorted(set(records) - set(expected)):
        record = records.get(check)
        if record is None:
            ok = False
            rows.append(f"| ❌ missing | {check} | | | The job didn't run or didn't record a result |")
            continue
        passed = record["status"] == "pass"
        ok = ok and passed
        rows.append(
            f"| {'✅ pass' if passed else '❌ fail'} | {record['title']} | {', '.join(record['controls'])} "
            f"| {record['tool']} | {record['detail']} |"
        )
    lines = [
        "## Compliance checks",
        "",
        f"**Result:** {'all checks passed' if ok else 'at least one check failed'}  ",
        f"**Commit:** `{run.get('sha', '')[:12]}` on `{run.get('ref', '')}` ({run.get('event', '')})",
        "",
        "| Status | Check | Controls | Tool | Detail |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "Every file in this evidence bundle is listed with its SHA-256 hash in `manifest.json`.",
        "",
    ]
    return "\n".join(lines), ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("results", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("--expect", action="append", default=[], help="check that must be present (repeatable)")
    args = p.parse_args(argv)

    if args.out.exists():
        shutil.rmtree(args.out)
    if args.results.exists():
        shutil.copytree(args.results, args.out)
    else:
        args.out.mkdir(parents=True)

    records = load_results(args.out)
    run = run_metadata()
    summary, ok = summarize(records, args.expect, run)
    (args.out / "summary.md").write_text(summary)

    files = {
        str(path.relative_to(args.out)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(args.out.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "run": run,
        "all_passed": ok,
        "checks": [
            {k: records[c][k] for k in ("check", "title", "status", "controls", "tool")}
            for c in sorted(records)
        ],
        "missing": sorted(set(args.expect) - set(records)),
        "files": files,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as f:
            f.write(summary)
    print(summary)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
