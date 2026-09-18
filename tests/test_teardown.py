import json
import sys
from pathlib import Path

import pytest
from fakes import FakeS3

from access_review import store
from access_review.cli import main as review

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import teardown  # noqa: E402

FIXTURES = Path(__file__).parent.parent / "fixtures"
BUCKET = "uar-evidence-111122223333"


class Sts:
    def get_caller_identity(self):
        return {"Account": "111122223333"}


class Ssm:
    def __init__(self):
        self.deleted = []

    def delete_parameters(self, Names):
        self.deleted += Names


@pytest.fixture
def deployed(tmp_path):
    review(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--roster", str(FIXTURES / "demo_roster.csv"),
            "--config", str(FIXTURES / "demo_config.json"), "--as-of", "2026-09-15", "--out", str(tmp_path / "out"),
            "--no-email", "--no-slack"])
    [run_dir] = list((tmp_path / "out").iterdir())
    s3 = FakeS3()
    store.upload_run(s3, BUCKET, run_dir)
    return {"sts": Sts(), "s3": s3, "ssm": Ssm()}, run_dir.name


def test_dry_run_deletes_nothing(deployed, capsys):
    clients, _ = deployed
    before = dict(clients["s3"].objects)
    assert teardown.main([], clients) == 0
    assert clients["s3"].objects == before and clients["ssm"].deleted == []
    assert "Dry run" in capsys.readouterr().out


def test_the_wrong_account_stops_everything(deployed):
    clients, _ = deployed
    assert teardown.main(["--confirm-account", "999999999999"], clients) == 2
    assert clients["s3"].objects


def test_evidence_that_doesnt_verify_is_never_deleted(deployed, tmp_path, capsys):
    clients, run = deployed
    clients["s3"].objects[(BUCKET, f"runs/{run}/findings.csv")] = b"tampered"
    assert teardown.main(["--confirm-account", "111122223333", "--export-dir", str(tmp_path / "x")], clients) == 2
    assert clients["s3"].objects and clients["ssm"].deleted == []
    assert "findings.csv" in capsys.readouterr().err


def test_a_verified_export_then_empties_the_bucket(deployed, tmp_path):
    clients, run = deployed
    dest = tmp_path / "export"
    assert teardown.main(["--confirm-account", "111122223333", "--export-dir", str(dest)], clients) == 0
    assert json.loads((dest / run / "manifest.json").read_text())["files"]
    assert (tmp_path / "export.zip").exists()
    assert clients["s3"].objects == {}
    assert clients["s3"].deletes == [(BUCKET, True)]  # the only place retention is bypassed
    assert "/uar/okta/private_key" in clients["ssm"].deleted
