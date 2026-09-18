"""Record a reviewer's sign-off on a finished review, bound to its manifest.

    access-review attest <report folder> [--decision D --reviewer NAME [--note TEXT]]

Checks every file in the folder against manifest.json first. Only if they all
match does it append a record to attestations.json that carries the manifest's
SHA-256, so the sign-off can't be moved to a different report unnoticed. Each
record also carries the SHA-256 of the one before it. Without --decision it only
verifies and lists the sign-offs already recorded.

This is a record, not a cryptographic signature: no key is involved and the
reviewer name is whatever was typed (see docs/security.md). It never reads Okta,
never writes outside the folder, and never sends anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .history import sha256_file
from .report import UNHASHED
from .store import RECORD_DIRS

DECISIONS = ("approved", "approved-with-exceptions", "rejected")
MAX_REVIEWER = 200
MAX_NOTE = 1000


class AttestError(Exception):
    """The folder can't be read as a review at all."""


@dataclass
class Verification:
    manifest: dict
    manifest_sha256: str
    checked: int = 0
    missing: list[str] = field(default_factory=list)
    mismatched: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)  # in the folder but not in the manifest

    @property
    def ok(self) -> bool:
        return not self.missing and not self.mismatched


def verify(run_dir: Path) -> Verification:
    if not run_dir.is_dir():
        raise AttestError(f"{run_dir} is not a folder")
    path = run_dir / "manifest.json"
    try:
        data = path.read_bytes()
        manifest = json.loads(data)
    except (OSError, ValueError):
        raise AttestError(f"{run_dir} has no readable manifest.json") from None
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, dict) or not all(isinstance(v, str) for v in files.values()):
        raise AttestError(f"{path} has no list of file hashes")
    if any(Path(name).name != name or name in ("", ".", "..") for name in files):
        raise AttestError(f"{path} lists a file outside the folder")

    result = Verification(manifest, hashlib.sha256(data).hexdigest())
    for name, digest in sorted(files.items()):
        p = run_dir / name
        if p.is_symlink() or not p.is_file():
            result.missing.append(name)
        elif sha256_file(p) != digest:
            result.mismatched.append(name)
        else:
            result.checked += 1
    result.extra = sorted(
        p.name for p in run_dir.iterdir()
        if p.name not in files and p.name not in UNHASHED and not (p.is_dir() and p.name in RECORD_DIRS)
    )
    return result


def slack_signoff_problems(run_dir: Path, v: Verification) -> list[str] | None:
    """Check a Slack sign-off in a run downloaded from S3 (signoff/*). None when
    there is no Slack sign-off in the folder."""
    from .decisions import signoff_problems  # late import: decisions imports this module
    from .items import ITEMS_FILE, ItemsError, load_items

    att_path = run_dir / "signoff" / "attestation.json"
    if not att_path.exists():
        return None
    try:
        attestation = json.loads(att_path.read_text())
        decisions_bytes = (run_dir / "signoff" / "decisions.json").read_bytes()
        items = {i.key: i for i in load_items((run_dir / ITEMS_FILE).read_text())}
    except (OSError, ValueError, KeyError, ItemsError):
        return ["the Slack sign-off or the review items can't be read"]
    return signoff_problems(attestation, decisions_bytes, v.manifest_sha256, items)


def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_hash(record: dict) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def read_attestations(run_dir: Path) -> list[dict]:
    """The sign-offs so far. Raises ValueError if the file exists but isn't a list of records."""
    path = run_dir / "attestations.json"
    if path.is_symlink():
        raise ValueError("attestations.json is a symlink")
    if not path.exists():
        return []
    try:
        records = json.loads(path.read_text())
    except (OSError, ValueError):
        raise ValueError("attestations.json can't be read") from None
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise ValueError("attestations.json isn't a list of sign-off records")
    return records


def problems_with(records: list[dict], manifest_sha256: str) -> list[str]:
    """Broken links in the chain, and sign-offs made against a different manifest.json."""
    problems = []
    prev = None
    for i, r in enumerate(records, 1):
        if r.get("prev") != prev:
            problems.append(f"sign-off {i} doesn't follow the one before it (edited, removed or reordered)")
        if r.get("manifest_sha256") != manifest_sha256:
            problems.append(f"sign-off {i} was made against a different manifest.json (stale)")
        prev = record_hash(r)
    return problems


def check_text(value: str, what: str, limit: int, required: bool) -> str:
    value = value.strip()
    if required and not value:
        raise ValueError(f"{what} can't be empty")
    if len(value) > limit:
        raise ValueError(f"{what} is longer than {limit} characters")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise ValueError(f"{what} can't contain line breaks or control characters")
    return value


def sign(run_dir: Path, v: Verification, records: list[dict], reviewer: str, decision: str, note: str,
         now: datetime) -> dict:
    record = {
        "reviewer": reviewer,
        "decision": decision,
        "note": note,
        "signed_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "org_url": v.manifest.get("org_url"),
        "review_date": v.manifest.get("review_date"),
        "manifest_sha256": v.manifest_sha256,
        "files_verified": v.checked,
        "extra_files": v.extra,
        "tool": f"okta-access-review {__version__}",
        "prev": record_hash(records[-1]) if records else None,
    }
    tmp = run_dir / ".attestations.json.tmp"
    tmp.write_text(json.dumps(records + [record], indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, run_dir / "attestations.json")  # all or nothing
    return record


def main(argv: list[str], now: datetime | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="access-review attest",
        description="Check a finished review folder against its manifest.json and, with --decision, "
                    "record a sign-off bound to it. Without --decision, only checks and lists sign-offs.",
    )
    p.add_argument("run_dir", type=Path, help="the review folder, e.g. reports/20260915T140000Z")
    p.add_argument("--decision", choices=DECISIONS, help="the reviewer's conclusion")
    p.add_argument("--reviewer", help="who is signing off (name or work email)")
    p.add_argument("--note", default="", help=f"optional comment, up to {MAX_NOTE} characters")
    args = p.parse_args(argv)
    if bool(args.decision) != bool(args.reviewer):
        p.error("--decision and --reviewer go together")
    if args.note and not args.decision:
        p.error("--note needs --decision")
    try:
        reviewer = check_text(args.reviewer or "", "--reviewer", MAX_REVIEWER, required=bool(args.decision))
        note = check_text(args.note, "--note", MAX_NOTE, required=False)
    except ValueError as e:
        p.error(str(e))

    try:
        v = verify(args.run_dir)
    except AttestError as e:
        print(f"access-review: {e}", file=sys.stderr)
        return 1
    try:
        records = read_attestations(args.run_dir)
        problems = problems_with(records, v.manifest_sha256)
    except ValueError as e:
        records, problems = [], [str(e)]

    print(f"{args.run_dir}: {v.checked} of {len(v.manifest['files'])} files match manifest.json "
          f"(SHA-256 {v.manifest_sha256})")
    for name in v.missing:
        print(f"  MISSING   {name}", file=sys.stderr)
    for name in v.mismatched:
        print(f"  CHANGED   {name}", file=sys.stderr)
    for name in v.extra:
        print(f"  not in the manifest (ignored): {name}")
    if records:
        print("Sign-offs:")
        for i, r in enumerate(records, 1):
            comment = f" ({r['note']})" if r.get("note") else ""
            print(f"  {i}. {r.get('signed_at')}  {r.get('decision')}  {r.get('reviewer')}{comment}")
    slack = slack_signoff_problems(args.run_dir, v)
    if slack is not None:
        att = json.loads((args.run_dir / "signoff" / "attestation.json").read_text()) if not slack else None
        if att:
            print(f"Slack sign-off: {att.get('signed_at')}  {att.get('decision')}  {att.get('reviewer')}  "
                  f"({att.get('items_decided')} items, {att.get('items_revoked')} revoked)")
        problems = problems + slack
    for problem in problems:
        print(f"  PROBLEM   {problem}", file=sys.stderr)

    if not v.ok or problems:
        print("access-review: this review doesn't match its evidence" + ("; not signed." if args.decision else "."),
              file=sys.stderr)
        return 2
    if args.decision:
        record = sign(args.run_dir, v, records, reviewer, args.decision, note, now or datetime.now(timezone.utc))
        print(f"Recorded: {record['decision']} by {record['reviewer']} at {record['signed_at']} "
              f"in {args.run_dir / 'attestations.json'}")
    elif not records:
        print("No sign-offs recorded yet.")
    return 0
