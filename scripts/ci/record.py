"""Record the outcome of one CI compliance check as a JSON evidence file.

    python3 scripts/ci/record.py secret-scan "$code" --title "Secret scan" \
        --control "SOC 2 CC6.1" --tool gitleaks@8.30.1 --detail "..."

Standard library only, so it runs before (or without) the project's dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

RUN_ENV = {
    "repository": "GITHUB_REPOSITORY",
    "sha": "GITHUB_SHA",
    "ref": "GITHUB_REF",
    "event": "GITHUB_EVENT_NAME",
    "workflow": "GITHUB_WORKFLOW",
    "run_id": "GITHUB_RUN_ID",
    "run_attempt": "GITHUB_RUN_ATTEMPT",
    "actor": "GITHUB_ACTOR",
}


def run_metadata(env: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ if env is None else env
    return {key: env.get(var, "") for key, var in RUN_ENV.items()}


def build_record(check: str, exit_code: int, title: str, controls: list[str], tool: str, detail: str,
                 env: dict[str, str] | None = None) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", check):
        raise ValueError(f"check name must be lowercase letters, digits and dashes: {check!r}")
    return {
        "check": check,
        "title": title or check,
        "status": "pass" if exit_code == 0 else "fail",
        "exit_code": exit_code,
        "controls": controls,
        "tool": tool,
        "detail": detail,
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "run": run_metadata(env),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("check", help="short id, e.g. secret-scan")
    p.add_argument("exit_code", type=int, help="exit code of the check")
    p.add_argument("--title", default="")
    p.add_argument("--control", action="append", default=[], help="control id (repeatable)")
    p.add_argument("--tool", default="")
    p.add_argument("--detail", default="")
    p.add_argument("--out", type=Path, default=Path("results"))
    args = p.parse_args(argv)

    record = build_record(args.check, args.exit_code, args.title, args.control, args.tool, args.detail)
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{args.check}.result.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"{record['status'].upper()}: {record['title']} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
