"""Working state of a review in progress, kept in the work bucket.

This is bookkeeping, not evidence: where the Slack messages are, the Step
Functions task token, which reminders went out. It is the only thing the tool
ever overwrites, and each overwrite is conditional on the version it read
(If-Match), so two clicks landing at once can't lose each other's update.

Never put personal data here; it holds IDs, timestamps and counts.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .store import RUN_NAME, StoreError, _error_code, get_bytes, list_keys

PREFIX = "state/"
OPEN, SIGNED_OFF, CLOSED = "open", "signed_off", "closed"


class StateConflict(StoreError):
    pass


def state_key(run: str) -> str:
    if not RUN_NAME.match(run):
        raise StoreError(f"not a review run name: {run!r}")
    return f"{PREFIX}{run}.json"


def _encode(state: dict) -> bytes:
    return (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()


def create_state(s3, bucket: str, run: str, state: dict) -> None:
    try:
        s3.put_object(Bucket=bucket, Key=state_key(run), Body=_encode(state), ContentType="application/json",
                      IfNoneMatch="*")
    except Exception as e:
        raise StoreError(f"could not create review state for {run} ({_error_code(e) or type(e).__name__})") from None


def load_state(s3, bucket: str, run: str) -> tuple[dict, str]:
    """(state, etag). Raises FileNotFoundError if there is no such review."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=state_key(run))
    except Exception as e:
        if _error_code(e) in ("NoSuchKey", "404"):
            raise FileNotFoundError(f"no review state for {run}") from None
        raise StoreError(f"could not read review state for {run} ({_error_code(e) or type(e).__name__})") from None
    return json.loads(resp["Body"].read()), resp["ETag"]


def update_state(s3, bucket: str, run: str, change: Callable[[dict], None], attempts: int = 8) -> dict:
    """Apply change() to the latest state and write it back, retrying if
    someone else wrote in between."""
    for _ in range(attempts):
        state, etag = load_state(s3, bucket, run)
        change(state)
        try:
            s3.put_object(Bucket=bucket, Key=state_key(run), Body=_encode(state), ContentType="application/json",
                          IfMatch=etag)
            return state
        except Exception as e:
            if _error_code(e) not in ("PreconditionFailed", "412", "ConditionalRequestConflict", "409"):
                raise StoreError(f"could not update review state for {run} ({_error_code(e) or type(e).__name__})") from None
    raise StateConflict(f"review state for {run} kept changing; gave up after {attempts} attempts")


def runs_with_status(s3, bucket: str, *statuses: str) -> list[str]:
    out = []
    for key in list_keys(s3, bucket, PREFIX):
        run = key[len(PREFIX):].removesuffix(".json")
        if RUN_NAME.match(run) and json.loads(get_bytes(s3, bucket, key)).get("status") in statuses:
            out.append(run)
    return sorted(out)


MARKERS = "markers/"
MARKER_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$")


def claim_once(s3, bucket: str, name: str) -> bool:
    """True the first time a marker name is claimed, False ever after. Used so
    a reminder or escalation goes out once however often the watcher runs."""
    if not MARKER_NAME.match(name):
        raise StoreError(f"bad marker name {name!r}")
    try:
        s3.put_object(Bucket=bucket, Key=f"{MARKERS}{name}", Body=b"", IfNoneMatch="*")
    except Exception as e:
        if _error_code(e) in ("PreconditionFailed", "412", "ConditionalRequestConflict", "409"):
            return False
        raise StoreError(f"could not write marker ({_error_code(e) or type(e).__name__})") from None
    return True
