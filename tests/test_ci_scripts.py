"""Tests for the helper scripts used by .github/workflows/compliance.yml."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
CI = ROOT / "scripts" / "ci"
sys.path.insert(0, str(CI))

import build_evidence  # noqa: E402
import check_branch_rules  # noqa: E402
import record  # noqa: E402

ENV = {
    "GITHUB_REPOSITORY": "acme/okta-access-review",
    "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
    "GITHUB_REF": "refs/heads/master",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_RUN_ID": "42",
}


def run_script(name, *args, env=None, cwd=None):
    return subprocess.run([sys.executable, str(CI / name), *map(str, args)], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **(env or {})}, cwd=cwd)


# --- record.py ---

def test_record_writes_result(tmp_path):
    proc = run_script("record.py", "secret-scan", 0, "--title", "Secret scan", "--control", "SOC 2 CC6.1",
                      "--control", "ISO 27001 A.8.12", "--tool", "gitleaks 8.30.1", "--detail", "0 leaks",
                      "--out", tmp_path, env=ENV)
    assert proc.returncode == 0, proc.stderr
    data = json.loads((tmp_path / "secret-scan.result.json").read_text())
    assert data["status"] == "pass"
    assert data["controls"] == ["SOC 2 CC6.1", "ISO 27001 A.8.12"]
    assert data["run"]["sha"] == ENV["GITHUB_SHA"]
    assert data["recorded_at"].endswith("Z")


def test_record_nonzero_exit_is_fail():
    assert record.build_record("tests", 3, "Tests", [], "", "", env={})["status"] == "fail"


@pytest.mark.parametrize("name", ["Secret Scan", "../evil", "a b", ""])
def test_record_rejects_unsafe_check_names(name):
    with pytest.raises(ValueError):
        record.build_record(name, 0, "", [], "", "", env={})


# --- check_branch_rules.py ---

FULL_RULES = [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
    {"type": "required_status_checks", "parameters": {"required_status_checks": [
        {"context": c} for c in check_branch_rules.REQUIRED_CHECKS
    ]}},
]


def test_all_rules_present():
    rows = check_branch_rules.evaluate(FULL_RULES)
    assert all(r["met"] for r in rows)
    assert len(rows) == len(check_branch_rules.REQUIRED_RULES) + len(check_branch_rules.REQUIRED_CHECKS)


def test_no_rules_fails_everything():
    rows = check_branch_rules.evaluate([])
    assert not any(r["met"] for r in rows)


def test_missing_required_check_is_reported():
    rules = [r for r in FULL_RULES if r["type"] != "required_status_checks"]
    rules.append({"type": "required_status_checks",
                  "parameters": {"required_status_checks": [{"context": "Tests"}]}})
    missing = [r["requirement"] for r in check_branch_rules.evaluate(rules) if not r["met"]]
    assert missing == ["'Secret scan' is a required check", "'Dependency audit' is a required check",
                       "'Workflow lint' is a required check", "'Terraform' is a required check"]


def test_branch_rules_main_writes_evidence(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(check_branch_rules, "fetch_rules", lambda repo, branch, token: FULL_RULES[:2])
    out = tmp_path / "branch-rules.json"
    assert check_branch_rules.main(["--repo", "acme/x", "--branch", "master", "--out", str(out)]) == 1
    data = json.loads(out.read_text())
    assert data["branch"] == "master" and data["rules"] == FULL_RULES[:2]
    assert "MISSING  Changes reach the branch only through a pull request" in capsys.readouterr().out


# --- build_evidence.py ---

def write_result(folder: Path, check: str, code: int):
    folder.mkdir(parents=True, exist_ok=True)
    rec = record.build_record(check, code, check.title(), ["SOC 2 CC8.1"], "tool 1.0", "detail", env=ENV)
    (folder / f"{check}.result.json").write_text(json.dumps(rec))


def test_evidence_bundle_passes_when_all_checks_pass(tmp_path):
    results = tmp_path / "results"
    write_result(results / "result-tests", "tests", 0)
    write_result(results / "result-secret-scan", "secret-scan", 0)
    (results / "result-secret-scan" / "secret-scan.json").write_text("[]")
    summary_file = tmp_path / "step-summary.md"
    proc = run_script("build_evidence.py", results, tmp_path / "evidence", "--expect", "tests",
                      "--expect", "secret-scan", env={**ENV, "GITHUB_STEP_SUMMARY": str(summary_file)})
    assert proc.returncode == 0, proc.stdout + proc.stderr

    evidence = tmp_path / "evidence"
    manifest = json.loads((evidence / "manifest.json").read_text())
    assert manifest["all_passed"] is True and manifest["missing"] == []
    assert manifest["run"]["sha"] == ENV["GITHUB_SHA"]
    assert "result-secret-scan/secret-scan.json" in manifest["files"]
    assert "summary.md" in manifest["files"]
    assert "✅ pass | Secret-Scan" in summary_file.read_text()


def test_evidence_bundle_fails_on_failed_or_missing_check(tmp_path):
    results = tmp_path / "results"
    write_result(results, "tests", 1)
    proc = run_script("build_evidence.py", results, tmp_path / "evidence", "--expect", "tests",
                      "--expect", "branch-rules", env=ENV)
    assert proc.returncode == 1
    manifest = json.loads((tmp_path / "evidence" / "manifest.json").read_text())
    assert manifest["all_passed"] is False
    assert manifest["missing"] == ["branch-rules"]
    summary = (tmp_path / "evidence" / "summary.md").read_text()
    assert "❌ fail | Tests" in summary and "❌ missing | branch-rules" in summary


def test_manifest_hashes_match_files(tmp_path):
    import hashlib

    results = tmp_path / "results"
    write_result(results, "tests", 0)
    build_evidence.main([str(results), str(tmp_path / "evidence"), "--expect", "tests"])
    evidence = tmp_path / "evidence"
    manifest = json.loads((evidence / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((evidence / name).read_bytes()).hexdigest() == digest


# --- the workflow itself ---

def test_workflow_pins_every_action_to_a_commit():
    text = (ROOT / ".github" / "workflows" / "compliance.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_required_checks_match_workflow_job_names():
    text = (ROOT / ".github" / "workflows" / "compliance.yml").read_text()
    names = set(re.findall(r"^    name: (.+)$", text, flags=re.M))
    assert set(check_branch_rules.REQUIRED_CHECKS) <= names
