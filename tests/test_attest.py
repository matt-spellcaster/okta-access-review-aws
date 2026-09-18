import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from access_review import attest
from access_review.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
    "--no-email", "--no-slack",
]
NOW = datetime(2026, 9, 16, 15, 30, tzinfo=timezone.utc)


@pytest.fixture
def run_dir(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    [d] = list(tmp_path.iterdir())
    return d


def sign(run_dir, *extra, reviewer="Priya Shah", decision="approved", when=NOW) -> int:
    return attest.main([str(run_dir), "--decision", decision, "--reviewer", reviewer, *extra], now=when)


def records(run_dir) -> list[dict]:
    return json.loads((run_dir / "attestations.json").read_text())


def manifest_hash(run_dir) -> str:
    return hashlib.sha256((run_dir / "manifest.json").read_bytes()).hexdigest()


def test_verifies_a_fresh_run(run_dir, capsys):
    assert main(["attest", str(run_dir)]) == 0
    out = capsys.readouterr().out
    assert "6 of 6 files match manifest.json" in out
    assert "No sign-offs recorded yet." in out
    assert not (run_dir / "attestations.json").exists()  # verifying never writes


def test_records_a_decision_bound_to_the_manifest_hash(run_dir, capsys):
    assert sign(run_dir, "--note", "AR-12 tickets raised") == 0
    [r] = records(run_dir)
    assert r == {
        "reviewer": "Priya Shah",
        "decision": "approved",
        "note": "AR-12 tickets raised",
        "signed_at": "2026-09-16T15:30:00Z",
        "org_url": "https://acme-demo.okta.com",
        "review_date": "2026-09-15",
        "manifest_sha256": manifest_hash(run_dir),
        "files_verified": 6,
        "extra_files": [],
        "tool": r["tool"],
        "prev": None,
    }
    assert "Recorded: approved by Priya Shah" in capsys.readouterr().out


def test_second_signature_chains_to_the_first(run_dir):
    sign(run_dir)
    assert sign(run_dir, reviewer="Hannah Ortiz", decision="approved-with-exceptions") == 0
    first, second = records(run_dir)
    assert second["prev"] == hashlib.sha256(attest.canonical(first)).hexdigest()
    assert main(["attest", str(run_dir)]) == 0


def test_modified_file_fails_and_is_not_signed(run_dir, capsys):
    with (run_dir / "findings.csv").open("a") as f:
        f.write("AR-99,planted\n")
    assert sign(run_dir) == 2
    err = capsys.readouterr().err
    assert "CHANGED   findings.csv" in err and "not signed" in err
    assert not (run_dir / "attestations.json").exists()


def test_missing_file_fails(run_dir, capsys):
    (run_dir / "report.pdf").unlink()
    assert main(["attest", str(run_dir)]) == 2
    assert "MISSING   report.pdf" in capsys.readouterr().err


def test_unlisted_extra_file_is_reported_but_not_a_failure(run_dir, capsys):
    (run_dir / ".DS_Store").write_bytes(b"\0")
    assert sign(run_dir) == 0
    assert "not in the manifest (ignored): .DS_Store" in capsys.readouterr().out
    assert records(run_dir)[0]["extra_files"] == [".DS_Store"]


def test_attest_does_not_modify_any_hashed_file(run_dir):
    before = {p.name: p.read_bytes() for p in run_dir.iterdir()}
    sign(run_dir)
    after = {p.name: p.read_bytes() for p in run_dir.iterdir() if p.name != "attestations.json"}
    assert after == before


def test_verify_only_mode_lists_existing_attestations(run_dir, capsys):
    sign(run_dir, "--note", "all good")
    capsys.readouterr()
    assert main(["attest", str(run_dir)]) == 0
    out = capsys.readouterr().out
    assert "1. 2026-09-16T15:30:00Z  approved  Priya Shah (all good)" in out


def test_stale_attestation_is_reported(run_dir, capsys):
    sign(run_dir)
    m = json.loads((run_dir / "manifest.json").read_text())
    m["review_date"] = "2026-09-01"
    (run_dir / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
    assert main(["attest", str(run_dir)]) == 2
    assert "sign-off 1 was made against a different manifest.json (stale)" in capsys.readouterr().err
    assert sign(run_dir, reviewer="Someone Else") == 2  # and nobody can sign on top of it
    assert len(records(run_dir)) == 1


def test_edited_sign_off_breaks_the_chain(run_dir, capsys):
    sign(run_dir, decision="rejected")
    sign(run_dir, reviewer="Hannah Ortiz")
    edited = records(run_dir)
    edited[0]["decision"] = "approved"
    (run_dir / "attestations.json").write_text(json.dumps(edited))
    assert main(["attest", str(run_dir)]) == 2
    assert "sign-off 2 doesn't follow the one before it" in capsys.readouterr().err


def test_unreadable_attestations_fail_verification(run_dir, capsys):
    (run_dir / "attestations.json").write_text('{"not": "a list"}')
    assert main(["attest", str(run_dir)]) == 2
    assert "isn't a list of sign-off records" in capsys.readouterr().err


def test_rerunning_a_review_over_a_signed_folder_is_refused(run_dir, capsys):
    sign(run_dir)
    signed = (run_dir / "attestations.json").read_bytes()
    manifest = (run_dir / "manifest.json").read_bytes()
    assert main(DEMO_ARGS + ["--out", str(run_dir.parent)]) == 1
    assert "is signed off (attestations.json); refusing to overwrite it" in capsys.readouterr().err
    assert (run_dir / "attestations.json").read_bytes() == signed
    assert (run_dir / "manifest.json").read_bytes() == manifest


def test_attestations_json_is_never_in_the_manifest(run_dir):
    sign(run_dir)
    assert "attestations.json" not in json.loads((run_dir / "manifest.json").read_text())["files"]
    assert attest.verify(run_dir).extra == []  # expected beside the manifest, not an unknown file


def test_not_a_review_folder(tmp_path, capsys):
    assert main(["attest", str(tmp_path / "nope")]) == 1
    assert main(["attest", str(tmp_path)]) == 1
    assert "has no readable manifest.json" in capsys.readouterr().err


def test_manifest_cannot_point_outside_the_folder(run_dir, capsys):
    m = json.loads((run_dir / "manifest.json").read_text())
    m["files"]["../secret"] = "0" * 64
    (run_dir / "manifest.json").write_text(json.dumps(m))
    assert main(["attest", str(run_dir)]) == 1
    assert "lists a file outside the folder" in capsys.readouterr().err


def test_flat_cli_is_unchanged_and_help_mentions_attest(tmp_path, capsys):
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "access-review attest <report folder>" in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    ["--decision", "approved"],  # no reviewer
    ["--reviewer", "Priya Shah"],  # no decision
    ["--decision", "lgtm", "--reviewer", "Priya Shah"],
    ["--decision", "approved", "--reviewer", "   "],
    ["--decision", "approved", "--reviewer", "Priya\nApproved by the CISO"],
    ["--decision", "approved", "--reviewer", "x" * 201],
    ["--decision", "approved", "--reviewer", "Priya Shah", "--note", "a\x1b[2Jb"],
    ["--note", "no decision"],
])
def test_decision_and_reviewer_are_validated(run_dir, args):
    with pytest.raises(SystemExit) as e:
        main(["attest", str(run_dir), *args])
    assert e.value.code == 2  # argparse usage error
    assert not (run_dir / "attestations.json").exists()
