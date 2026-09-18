import json
from pathlib import Path

import pytest
from fakes import FakeS3

from access_review import store
from access_review.attest import verify
from access_review.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]
BUCKET = "evidence"


@pytest.fixture
def run_dir(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path / "out")]) == 0
    [d] = list((tmp_path / "out").iterdir())
    return d


def test_upload_is_create_only_and_verified(run_dir):
    s3 = FakeS3()
    sha = store.upload_run(s3, BUCKET, run_dir)

    assert all(p["IfNoneMatch"] == "*" and p["ChecksumAlgorithm"] == "SHA256" for p in s3.puts)
    # manifest.json goes last, so a prefix with a manifest is always complete.
    assert s3.puts[-1]["Key"] == f"runs/{run_dir.name}/manifest.json"
    assert len(sha) == 64
    with pytest.raises(store.AlreadyExists):
        store.upload_run(s3, BUCKET, run_dir)


def test_a_corrupted_upload_is_caught(run_dir):
    class Corrupting(FakeS3):
        def put_object(self, **kw):
            if kw["Key"].endswith("findings.csv"):
                kw["Body"] = b"tampered"
            return super().put_object(**kw)

    with pytest.raises(store.StoreError, match="findings.csv"):
        store.upload_run(Corrupting(), BUCKET, run_dir)


def test_write_errors_never_include_the_body_or_credentials(run_dir):
    s3 = FakeS3()
    s3.fail_puts = "AccessDenied"
    with pytest.raises(store.StoreError) as e:
        store.upload_run(s3, BUCKET, run_dir)
    assert "AccessDenied" in str(e.value)
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_download_round_trips_and_verifies(run_dir, tmp_path):
    s3 = FakeS3()
    store.upload_run(s3, BUCKET, run_dir)
    store.put_record(s3, BUCKET, run_dir.name, "decisions", "20260916T100000Z-abc.json", {"x": 1})

    folder = store.download_run(s3, BUCKET, run_dir.name, tmp_path / "dl")

    assert verify(folder).ok
    assert json.loads((folder / "decisions" / "20260916T100000Z-abc.json").read_text()) == {"x": 1}


def test_unexpected_objects_in_a_run_are_refused(run_dir, tmp_path):
    s3 = FakeS3()
    store.upload_run(s3, BUCKET, run_dir)
    s3.objects[(BUCKET, f"runs/{run_dir.name}/elsewhere/x.json")] = b"{}"
    with pytest.raises(store.StoreError, match="unexpected"):
        store.download_run(s3, BUCKET, run_dir.name, tmp_path / "dl")


def test_records_are_create_only_and_names_are_checked():
    s3 = FakeS3()
    store.put_record(s3, BUCKET, "20260915T140000Z", "tickets", "abc.json", {"issue": "UAR-1"})
    with pytest.raises(store.AlreadyExists):
        store.put_record(s3, BUCKET, "20260915T140000Z", "tickets", "abc.json", {"issue": "UAR-2"})
    for run, kind, name in [
        ("../x", "tickets", "a.json"),
        ("20260915T140000Z", "manifest", "a.json"),
        ("20260915T140000Z", "tickets", "../a.json"),
        ("20260915T140000Z", "tickets", "a.txt"),
    ]:
        with pytest.raises(store.StoreError):
            store.put_record(s3, BUCKET, run, kind, name, {})
    assert store.list_records(s3, BUCKET, "20260915T140000Z", "tickets") == [("abc.json", {"issue": "UAR-1"})]


def test_history_fetches_only_older_runs_and_only_two_files(tmp_path):
    s3 = FakeS3(page_size=2)
    for run in ("20260315T140000Z", "20260615T140000Z", "20260915T140000Z", "junk"):
        for name in ("manifest.json", "findings.csv", "snapshot.json"):
            s3.objects[(BUCKET, f"runs/{run}/{name}")] = b"{}"

    fetched = store.fetch_history(s3, BUCKET, tmp_path, before="20260915T140000Z", limit=12)

    assert fetched == ["20260315T140000Z", "20260615T140000Z"]
    assert sorted(p.name for p in (tmp_path / "20260615T140000Z").iterdir()) == ["findings.csv", "manifest.json"]
    assert store.fetch_history(s3, BUCKET, tmp_path / "b", before="20260915T140000Z", limit=1) == ["20260615T140000Z"]
