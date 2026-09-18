"""Evidence in S3.

The review itself is still written by report.write_report into a local folder
(/tmp in Lambda); this module moves it to S3 and back. Every write is
create-only (If-None-Match: *), so nothing already in the bucket can be
replaced, and an upload is only trusted after reading it back and matching the
manifest.

Layout, one prefix per review run:
    runs/<run>/<report files>          write_report output, hashed in manifest.json
    runs/<run>/decisions/<id>.json     one per Slack click
    runs/<run>/signoff/decisions.json  final decision per item
    runs/<run>/signoff/attestation.json
    runs/<run>/tickets/<item>.json     one per JSM ticket opened
    runs/<run>/verifications/<id>.json daily checks of resolved tickets

The S3 client is passed in (boto3's, or a fake in tests); this module never
creates one, so importing it never touches AWS.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

RUNS = "runs/"
RUN_NAME = re.compile(r"^\d{8}T\d{6}Z$")
RECORD_DIRS = ("decisions", "signoff", "tickets", "verifications")
RECORD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$")
# Only these come back for findings history; nothing else from old runs is read.
HISTORY_FILES = ("manifest.json", "findings.csv")


class StoreError(Exception):
    pass


class AlreadyExists(StoreError):
    pass


def _error_code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code", ""))


def _check_run(run: str) -> str:
    if not RUN_NAME.match(run):
        raise StoreError(f"not a review run name: {run!r}")
    return run


def record_key(run: str, kind: str, name: str) -> str:
    if kind not in RECORD_DIRS or not RECORD_NAME.match(name):
        raise StoreError(f"not an evidence record path: {kind}/{name}")
    return f"{RUNS}{_check_run(run)}/{kind}/{name}"


def put_create_only(s3, bucket: str, key: str, body: bytes, content_type: str) -> str:
    """Write one object that must not exist yet. Returns its SHA-256."""
    digest = hashlib.sha256(body).hexdigest()
    try:
        s3.put_object(
            Bucket=bucket, Key=key, Body=body, ContentType=content_type,
            IfNoneMatch="*", ChecksumAlgorithm="SHA256",
        )
    except Exception as e:
        code = _error_code(e)
        if code in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
            raise AlreadyExists(f"s3://{bucket}/{key} already exists") from None
        raise StoreError(f"could not write s3://{bucket}/{key} ({code or type(e).__name__})") from None
    return digest


def get_bytes(s3, bucket: str, key: str) -> bytes:
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as e:
        code = _error_code(e)
        if code in ("NoSuchKey", "404"):
            raise FileNotFoundError(f"s3://{bucket}/{key}") from None
        raise StoreError(f"could not read s3://{bucket}/{key} ({code or type(e).__name__})") from None


def list_keys(s3, bucket: str, prefix: str) -> list[str]:
    keys, token = [], None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        keys += [o["Key"] for o in page.get("Contents", [])]
        if not page.get("IsTruncated"):
            return keys
        token = page["NextContinuationToken"]


def list_runs(s3, bucket: str) -> list[str]:
    """Run names in the bucket, oldest first. Anything not shaped like a run is ignored."""
    runs, token = set(), None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": RUNS, "Delimiter": "/"}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        for p in page.get("CommonPrefixes", []):
            name = p["Prefix"][len(RUNS):].rstrip("/")
            if RUN_NAME.match(name):
                runs.add(name)
        if not page.get("IsTruncated"):
            return sorted(runs)
        token = page["NextContinuationToken"]


def upload_run(s3, bucket: str, run_dir: Path) -> str:
    """Upload a finished review folder and prove it arrived intact.

    Every file listed in manifest.json, then manifest.json itself last, so a run
    prefix with a manifest is always complete. Each object is read back and
    compared with the manifest. Returns the manifest's SHA-256.
    """
    run = _check_run(run_dir.name)
    manifest_bytes = (run_dir / "manifest.json").read_bytes()
    files = json.loads(manifest_bytes)["files"]
    for name in sorted(files):
        path = run_dir / name
        if Path(name).name != name or path.is_symlink() or not path.is_file():
            raise StoreError(f"manifest lists {name!r}, which is not a file in the run folder")
        put_create_only(s3, bucket, f"{RUNS}{run}/{name}", path.read_bytes(), _content_type(name))
    manifest_sha = put_create_only(s3, bucket, f"{RUNS}{run}/manifest.json", manifest_bytes, "application/json")

    for name, digest in files.items():
        if hashlib.sha256(get_bytes(s3, bucket, f"{RUNS}{run}/{name}")).hexdigest() != digest:
            raise StoreError(f"{name} in s3://{bucket}/{RUNS}{run}/ does not match the manifest")
    if hashlib.sha256(get_bytes(s3, bucket, f"{RUNS}{run}/manifest.json")).hexdigest() != manifest_sha:
        raise StoreError(f"manifest.json in s3://{bucket}/{RUNS}{run}/ does not match what was uploaded")
    return manifest_sha


def fetch_history(s3, bucket: str, dest: Path, before: str, limit: int) -> list[str]:
    """Download manifest.json and findings.csv of up to `limit` runs older than
    `before` into dest/<run>/, for history.load_history to verify and read.
    A run whose files can't be read is left out; load_history treats what it
    finds on its own terms, so this never vouches for anything."""
    runs = [r for r in list_runs(s3, bucket) if r < before][-limit:]
    fetched = []
    for run in runs:
        folder = dest / run
        folder.mkdir(parents=True, exist_ok=True)
        for name in HISTORY_FILES:
            try:
                (folder / name).write_bytes(get_bytes(s3, bucket, f"{RUNS}{run}/{name}"))
            except FileNotFoundError:
                pass
        fetched.append(run)
    return fetched


def download_run(s3, bucket: str, run: str, dest: Path) -> Path:
    """Everything under one run prefix, including records, into dest/<run>/."""
    prefix = f"{RUNS}{_check_run(run)}/"
    folder = dest / run
    for key in list_keys(s3, bucket, prefix):
        rel = key[len(prefix):]
        parts = rel.split("/")
        if any(p in ("", ".", "..") for p in parts) or len(parts) > 2:
            raise StoreError(f"unexpected object {key!r} in the run")
        if len(parts) == 2 and parts[0] not in RECORD_DIRS:
            raise StoreError(f"unexpected object {key!r} in the run")
        path = folder.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(get_bytes(s3, bucket, key))
    return folder


def put_record(s3, bucket: str, run: str, kind: str, name: str, record: dict) -> str:
    """Write one evidence record (create-only). Returns its SHA-256."""
    body = (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    return put_create_only(s3, bucket, record_key(run, kind, name), body, "application/json")


def get_record(s3, bucket: str, run: str, kind: str, name: str) -> dict:
    return json.loads(get_bytes(s3, bucket, record_key(run, kind, name)))


def list_records(s3, bucket: str, run: str, kind: str) -> list[tuple[str, dict]]:
    """(name, record) for every record of one kind, in key order."""
    prefix = f"{RUNS}{_check_run(run)}/{kind}/"
    if kind not in RECORD_DIRS:
        raise StoreError(f"unknown record kind {kind!r}")
    out = []
    for key in sorted(list_keys(s3, bucket, prefix)):
        name = key[len(prefix):]
        if RECORD_NAME.match(name):
            out.append((name, json.loads(get_bytes(s3, bucket, key))))
    return out


def _content_type(name: str) -> str:
    return {
        ".json": "application/json", ".csv": "text/csv", ".md": "text/markdown", ".pdf": "application/pdf",
    }.get(Path(name).suffix, "application/octet-stream")
