import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fakes import FakeS3

from access_review import store
from access_review.attest import main as attest_main
from access_review.checks import Config
from access_review.decisions import (
    DecisionError,
    Reviewers,
    build_signoff,
    confirm_proposed,
    consolidate,
    make_decision_record,
    outstanding,
    progress,
)
from access_review.items import ADMIN, CISO, DECIDE, KEEP, REVOKE, ITEMS_FILE
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)
R = Reviewers(admin="U0ADMIN0001", ciso="U0CISO00001")
T0 = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
SOURCE = {"team": "T0TEAM0001", "channel": "D0DM0001", "message_ts": "1758000000.000100"}
BUCKET = "evidence"


@pytest.fixture
def review(tmp_path):
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    config.admin_login = "priya.shah@acme.example"
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config, AS_OF,
                     tmp_path / "out", require_items=True)
    return run, {i.key: i for i in run.items}


def record(run, items, choices, user, now):
    return make_decision_record(run.run_dir.name, run.manifest_sha256, items, choices, user, R, SOURCE, now)


def decide_everything(run, items):
    """The admin confirms proposals and decides the rest; the CISO does the same for theirs."""
    records = []
    for i, (role, user) in enumerate(((ADMIN, R.admin), (CISO, R.ciso))):
        choices = confirm_proposed(items, {}, role)
        choices += [(k, KEEP, "") for k, it in items.items() if it.reviewer == role and it.proposed == DECIDE]
        records.append(record(run, items, choices, user, T0 + timedelta(minutes=i)))
    return records


def test_reviewers_must_be_two_different_slack_users():
    with pytest.raises(ValueError):
        Reviewers(admin="U0SAME00001", ciso="U0SAME00001")
    with pytest.raises(ValueError):
        Reviewers(admin="alice", ciso="U0CISO00001")


def test_the_admin_cannot_decide_their_own_access(review):
    run, items = review
    own = next(k for k, i in items.items() if i.reviewer == CISO)
    with pytest.raises(DecisionError, match="only the CISO"):
        record(run, items, [(own, KEEP, "")], R.admin, T0)
    # And the CISO doesn't decide the admin's items for them.
    other = next(k for k, i in items.items() if i.reviewer == ADMIN)
    with pytest.raises(DecisionError, match="reviewing admin"):
        record(run, items, [(other, KEEP, "")], R.ciso, T0)
    with pytest.raises(DecisionError):
        record(run, items, [(other, KEEP, "")], "U0STRANGER1", T0)


def test_keeping_a_proposed_revoke_needs_a_reason(review):
    run, items = review
    key = next(k for k, i in items.items() if i.proposed == REVOKE and i.reviewer == ADMIN)
    with pytest.raises(DecisionError, match="reason is needed"):
        record(run, items, [(key, KEEP, "  ")], R.admin, T0)
    _, rec = record(run, items, [(key, KEEP, "Quarter-end reporting needs it")], R.admin, T0)
    assert rec["decisions"][0]["reason"] == "Quarter-end reporting needs it"
    with pytest.raises(DecisionError, match="one line"):
        record(run, items, [(key, KEEP, "line\nbreak")], R.admin, T0)


def test_confirm_proposed_leaves_decide_items_alone(review):
    run, items = review
    choices = confirm_proposed(items, {}, ADMIN)
    assert choices and all(items[k].proposed in (KEEP, REVOKE) and items[k].reviewer == ADMIN for k, _, _ in choices)
    final = consolidate(items, [record(run, items, choices, R.admin, T0)], run.manifest_sha256, R)
    left = outstanding(items, final, ADMIN)
    assert left and all(i.proposed == DECIDE for i in left)
    assert confirm_proposed(items, final, ADMIN) == []


def test_latest_decision_wins_and_invalid_records_never_count(review):
    run, items = review
    key = next(k for k, i in items.items() if i.proposed == DECIDE and i.reviewer == ADMIN)
    first = record(run, items, [(key, KEEP, "")], R.admin, T0)
    second = record(run, items, [(key, REVOKE, "no longer on the team")], R.admin, T0 + timedelta(hours=1))
    stale = ("x.json", {**second[1], "manifest_sha256": "0" * 64, "recorded_at": "2027-01-01T00:00:00.000000Z"})
    forged = ("y.json", {**second[1], "slack_user": R.ciso, "decisions": [{"item_key": key, "decision": KEEP}],
                         "recorded_at": "2027-01-01T00:00:00.000000Z"})

    final = consolidate(items, [second, stale, first, forged], run.manifest_sha256, R)

    assert final[key]["decision"] == REVOKE and final[key]["record"] == second[0]


def test_signoff_needs_every_item_and_the_ciso(review):
    run, items = review
    manifest = json.loads((run.run_dir / "manifest.json").read_text())
    items_sha = hashlib.sha256((run.run_dir / ITEMS_FILE).read_bytes()).hexdigest()
    partial = consolidate(items, [record(run, items, confirm_proposed(items, {}, ADMIN), R.admin, T0)],
                          run.manifest_sha256, R)
    with pytest.raises(DecisionError, match="still need a decision"):
        build_signoff(run.run_dir.name, manifest, run.manifest_sha256, items_sha, items, partial, R.ciso, R, SOURCE)

    final = consolidate(items, decide_everything(run, items), run.manifest_sha256, R)
    assert progress(items, final)["decided"] == len(items)
    with pytest.raises(DecisionError, match="only the CISO"):
        build_signoff(run.run_dir.name, manifest, run.manifest_sha256, items_sha, items, final, R.admin, R, SOURCE)
    with pytest.raises(DecisionError, match="don't match the manifest"):
        build_signoff(run.run_dir.name, manifest, run.manifest_sha256, "0" * 64, items, final, R.ciso, R, SOURCE)


def test_a_signed_off_run_verifies_after_download(review, tmp_path, capsys):
    run, items = review
    s3 = FakeS3()
    manifest_sha = store.upload_run(s3, BUCKET, run.run_dir)
    for name, rec in decide_everything(run, items):
        store.put_record(s3, BUCKET, run.run_dir.name, "decisions", name, rec)

    records = store.list_records(s3, BUCKET, run.run_dir.name, "decisions")
    final = consolidate(items, records, manifest_sha, R)
    manifest = json.loads((run.run_dir / "manifest.json").read_text())
    decisions_bytes, attestation = build_signoff(
        run.run_dir.name, manifest, manifest_sha, manifest["files"][ITEMS_FILE], items, final, R.ciso, R, SOURCE,
        now=T0 + timedelta(days=1),
    )
    store.put_create_only(s3, BUCKET, store.record_key(run.run_dir.name, "signoff", "decisions.json"),
                          decisions_bytes, "application/json")
    store.put_record(s3, BUCKET, run.run_dir.name, "signoff", "attestation.json", attestation)
    assert attestation["decision"] == "approved-with-exceptions"
    assert attestation["reviewer"] == f"slack:{R.ciso}"

    folder = store.download_run(s3, BUCKET, run.run_dir.name, tmp_path / "dl")
    assert attest_main([str(folder)]) == 0
    assert "Slack sign-off" in capsys.readouterr().out

    # Changing a decision after the sign-off is caught.
    doc = json.loads((folder / "signoff" / "decisions.json").read_text())
    first = sorted(doc["decisions"])[0]
    doc["decisions"][first]["decision"] = KEEP if doc["decisions"][first]["decision"] == REVOKE else REVOKE
    (folder / "signoff" / "decisions.json").write_text(json.dumps(doc))
    assert attest_main([str(folder)]) == 2
    assert "changed since the sign-off" in capsys.readouterr().err
