"""Check that the default branch is protected by repository rules.

Reads GET /repos/{repo}/rules/branches/{branch}, which only needs read access,
so the workflow's GITHUB_TOKEN is enough. Writes the rules it found as evidence
and exits 1 if a required protection is missing.

    python3 scripts/ci/check_branch_rules.py --repo owner/name --branch master
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REQUIRED_RULES = {
    "pull_request": "Changes reach the branch only through a pull request",
    "required_status_checks": "Required checks must pass before merging",
    "non_fast_forward": "Force pushes are blocked",
    "deletion": "The branch can't be deleted",
}
# Job names from .github/workflows/compliance.yml that must be required checks.
REQUIRED_CHECKS = ["Tests", "Secret scan", "Dependency audit", "Workflow lint", "Terraform"]


def fetch_rules(repo: str, branch: str, token: str, api: str = "https://api.github.com") -> list[dict]:
    rules: list[dict] = []
    page = 1
    while True:
        req = urllib.request.Request(
            f"{api}/repos/{repo}/rules/branches/{branch}?per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            batch = json.load(resp)
        rules.extend(batch)
        if len(batch) < 100:
            return rules
        page += 1


def evaluate(rules: list[dict]) -> list[dict]:
    """One row per requirement: what's required, whether it's met, and why."""
    by_type: dict[str, list[dict]] = {}
    for rule in rules:
        by_type.setdefault(rule.get("type", ""), []).append(rule)

    rows = []
    for rule_type, description in REQUIRED_RULES.items():
        present = rule_type in by_type
        rows.append({"requirement": description, "rule": rule_type, "met": present,
                     "detail": "present" if present else "missing"})

    contexts = {
        check.get("context")
        for rule in by_type.get("required_status_checks", [])
        for check in rule.get("parameters", {}).get("required_status_checks", [])
    }
    for name in REQUIRED_CHECKS:
        met = name in contexts
        rows.append({"requirement": f"'{name}' is a required check", "rule": "required_status_checks",
                     "met": met, "detail": "required" if met else "not required"})
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    p.add_argument("--branch", required=True)
    p.add_argument("--out", type=Path, default=Path("results/branch-rules.json"))
    args = p.parse_args(argv)
    if not args.repo:
        p.error("--repo is required outside GitHub Actions")

    try:
        rules = fetch_rules(args.repo, args.branch, os.environ.get("GITHUB_TOKEN", ""))
    except urllib.error.HTTPError as e:
        print(f"could not read branch rules: HTTP {e.code}", file=sys.stderr)
        return 2
    rows = evaluate(rules)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"repo": args.repo, "branch": args.branch, "checks": rows, "rules": rules},
                                   indent=2) + "\n")
    for row in rows:
        print(f"{'ok     ' if row['met'] else 'MISSING'}  {row['requirement']}")
    return 0 if all(row["met"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
