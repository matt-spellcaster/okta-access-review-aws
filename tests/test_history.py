import csv
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import Config, Finding
from access_review.cli import main
from access_review.history import History, PriorReview, age_findings, label, load_history, repeat_summary

FIXTURES = Path(__file__).parent.parent / "fixtures"
ORG = "https://acme-demo.okta.com"


def review(tmp_path: Path, day: str, *, at: str = "14:00:00", org: str = ORG, config: Path | None = None,
           tweak=None, out: str = "out") -> Path:
    """Run a real demo review into tmp_path/out as if it were collected and reviewed on `day`."""
    snap = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    snap["collected_at"] = f"{day}T{at}Z"
    snap["org_url"] = org
    if tweak:
        tweak(snap)
    snaps = tmp_path / "snaps"
    snaps.mkdir(exist_ok=True)
    path = snaps / f"{day}-{at.replace(':', '')}-{len(list(snaps.iterdir()))}.json"
    path.write_text(json.dumps(snap))
    args = [
        "--snapshot", str(path),
        "--roster", str(FIXTURES / "demo_roster.csv"),
        "--config", str(config or FIXTURES / "demo_config.json"),
        "--as-of", day,
        "--out", str(tmp_path / out),
        "--no-email", "--no-slack",
    ]
    assert main(args) == 0
    return tmp_path / out / f"{day.replace('-', '')}T{at.replace(':', '')}Z"


def findings(run_dir: Path) -> dict[tuple[str, str], dict]:
    with (run_dir / "findings.csv").open(newline="") as f:
        return {(r["check_id"], r["subject"].split("@")[0]): r for r in csv.DictReader(f)}


def manifest(run_dir: Path) -> dict:
    return json.loads((run_dir / "manifest.json").read_text())


def enrol_lee(snap):
    """Clears AR-04 (no MFA) for lee.chen in that review."""
    for u in snap["users"]:
        if u["login"] == "lee.chen@acme.example":
            u["factors"] = ["push"]


LEE = ("AR-04", "lee.chen")


def test_no_prior_reviews_is_empty_history(tmp_path):
    d = review(tmp_path, "2026-09-15")
    row = findings(d)[LEE]
    assert (row["first_seen"], row["reviews_open"], row["reopened"]) == ("", "", "")
    history = manifest(d)["history"]
    assert history["reviews"] == [] and history["skipped"] == []
    assert "no history yet" in (d / "report.md").read_text()
    assert "| History |" not in (d / "report.md").read_text()


def test_finding_open_in_two_reviews_counts_two(tmp_path):
    june = review(tmp_path, "2026-06-15")
    d = review(tmp_path, "2026-09-15")
    lee = findings(d)[LEE]
    assert (lee["first_seen"], lee["reviews_open"], lee["reopened"]) == ("2026-06-15", "2", "no")
    new = findings(d).keys() - findings(june).keys()
    assert new  # some findings only exist on the later date
    for key in new:
        row = findings(d)[key]
        assert (row["first_seen"], row["reviews_open"], row["reopened"]) == ("2026-09-15", "1", "no")
    md = (d / "report.md").read_text()
    assert "| Severity | Subject | Detail | History |" in md
    assert "| 2 reviews in a row, first seen 2026-06-15 |" in md
    assert "verified against their own manifest.json" in md


def test_two_runs_on_the_same_day_are_one_review(tmp_path):
    review(tmp_path, "2026-06-15", at="09:00:00")
    review(tmp_path, "2026-06-15", at="14:00:00")
    d = review(tmp_path, "2026-09-15")
    assert findings(d)[LEE]["reviews_open"] == "2"
    history = manifest(d)["history"]
    assert [r["folder"] for r in history["reviews"]] == ["20260615T140000Z"]  # the later run of that day
    assert history["superseded_runs"] == ["20260615T090000Z"]


def test_rerunning_the_same_snapshot_does_not_count_itself(tmp_path):
    review(tmp_path, "2026-06-15")
    first = findings(review(tmp_path, "2026-09-15"))
    again = findings(review(tmp_path, "2026-09-15"))  # same collection time: overwrites the same folder
    assert again == first
    assert again[LEE]["reviews_open"] == "2"


def test_rerun_of_the_current_review_on_a_later_collection_is_superseded(tmp_path):
    review(tmp_path, "2026-09-15", at="09:00:00")
    d = review(tmp_path, "2026-09-15", at="14:00:00")
    assert findings(d)[LEE]["reviews_open"] == ""  # an earlier run of this review isn't a prior review
    assert manifest(d)["history"]["superseded_runs"] == ["20260915T090000Z"]


def test_absence_resets_the_streak_and_sets_reopened(tmp_path):
    review(tmp_path, "2026-06-15")
    review(tmp_path, "2026-07-15", tweak=enrol_lee)
    d = review(tmp_path, "2026-09-15")
    lee = findings(d)[LEE]
    assert (lee["first_seen"], lee["reviews_open"], lee["reopened"]) == ("2026-06-15", "1", "yes")
    assert "| Back again, first seen 2026-06-15 |" in (d / "report.md").read_text()


def test_unverifiable_findings_csv_breaks_the_streak(tmp_path):
    review(tmp_path, "2026-06-15")
    july = review(tmp_path, "2026-07-15")
    with (july / "findings.csv").open("a") as f:
        f.write("\n")
    d = review(tmp_path, "2026-09-15")
    lee = findings(d)[LEE]
    # Present in all three, but July can't be trusted, so the count stops at this review.
    assert (lee["first_seen"], lee["reviews_open"], lee["reopened"]) == ("2026-06-15", "1", "no")
    [june, july_entry] = manifest(d)["history"]["reviews"]
    assert june["verified"] is True
    assert july_entry == {
        "review_date": "2026-07-15", "folder": july.name,
        "manifest_sha256": hashlib.sha256((july / "manifest.json").read_bytes()).hexdigest(),
        "verified": False, "problem": "findings.csv doesn't match its manifest.json",
    }
    assert "Could not verify the findings of the review(s) on 2026-07-15" in (d / "report.md").read_text()


def test_review_folder_missing_findings_csv_is_unknown(tmp_path):
    review(tmp_path, "2026-06-15")
    july = review(tmp_path, "2026-07-15")
    (july / "findings.csv").unlink()
    d = review(tmp_path, "2026-09-15")
    assert findings(d)[LEE]["reviews_open"] == "1"
    assert manifest(d)["history"]["reviews"][1]["problem"] == "findings.csv is missing"


def test_other_orgs_and_junk_are_ignored(tmp_path):
    out = tmp_path / "out"
    review(tmp_path, "2026-06-15", org="https://other.okta.com")
    review(tmp_path, "2026-12-15")  # reviewed after the review being run
    (out / "notes.txt").write_text("not a review")
    (out / ".DS_Store").write_bytes(b"\0")
    (out / "empty").mkdir()
    (out / "broken").mkdir()
    (out / "broken" / "manifest.json").write_text("{")
    d = review(tmp_path, "2026-09-15")
    assert findings(d)[LEE]["reviews_open"] == ""
    history = manifest(d)["history"]
    assert history["reviews"] == []
    assert {s["folder"]: s["reason"] for s in history["skipped"]} == {
        "empty": "no readable manifest.json",
        "broken": "no readable manifest.json",
        "20260615T140000Z": "a review of a different org",
        "20261215T140000Z": "reviewed after this review's date",
    }
    assert "4 folder(s) in the output directory were not counted" in (d / "report.md").read_text()


def test_symlinked_folder_is_not_followed(tmp_path):
    elsewhere = review(tmp_path, "2026-06-15", out="elsewhere")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / elsewhere.name).symlink_to(elsewhere, target_is_directory=True)
    d = review(tmp_path, "2026-09-15")
    assert findings(d)[LEE]["reviews_open"] == ""
    assert manifest(d)["history"]["skipped"] == [{"folder": elsewhere.name, "reason": "symlink, not followed"}]


def test_subject_case_is_matched_case_insensitively(tmp_path):
    def shout(snap):
        for u in snap["users"]:
            if u["login"] == "lee.chen@acme.example":
                u["login"] = "Lee.Chen@acme.example"

    june = review(tmp_path, "2026-06-15", tweak=shout)
    assert ("AR-04", "Lee.Chen") in findings(june)
    d = review(tmp_path, "2026-09-15")
    assert findings(d)[LEE]["reviews_open"] == "2"


def test_window_is_capped_and_recorded(tmp_path):
    config = json.loads((FIXTURES / "demo_config.json").read_text())
    config["history_reviews"] = 2
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    for day in ("2026-06-15", "2026-07-15", "2026-08-15"):
        review(tmp_path, day, config=path)
    d = review(tmp_path, "2026-09-15", config=path)
    assert findings(d)[LEE]["reviews_open"] == "3"
    assert findings(d)[LEE]["first_seen"] == "2026-07-15"  # a lower bound: June is outside the window
    history = manifest(d)["history"]
    assert history["window"] == 2 and history["older_reviews_not_read"] == 1
    assert [r["review_date"] for r in history["reviews"]] == ["2026-07-15", "2026-08-15"]
    assert manifest(d)["config"]["history_reviews"] == 2


def test_manifest_sha256_recorded_matches_the_file(tmp_path):
    june = review(tmp_path, "2026-06-15")
    d = review(tmp_path, "2026-09-15")
    [entry] = manifest(d)["history"]["reviews"]
    assert entry["manifest_sha256"] == hashlib.sha256((june / "manifest.json").read_bytes()).hexdigest()


def test_missing_output_folder_is_empty_history(tmp_path):
    history = load_history(tmp_path / "nope", "20260915T140000Z", ORG, date(2026, 9, 15))
    assert history.reviews == [] and history.skipped == []


def test_aging_does_not_change_severity_or_fail_on(tmp_path):
    review(tmp_path, "2026-06-15")
    d = review(tmp_path, "2026-09-15")
    assert {r["severity"] for k, r in findings(d).items() if k == LEE} == {"high"}


def test_pdf_shows_history_only_when_a_prior_review_exists(tmp_path):
    from pypdf import PdfReader

    def text(run_dir):
        return "\n".join(page.extract_text() for page in PdfReader(run_dir / "report.pdf").pages)

    first = review(tmp_path, "2026-06-15")
    later = review(tmp_path, "2026-09-15")
    assert "History" not in text(first)
    assert "History" in text(later)
    assert "reviews in a row" in text(later)


@pytest.mark.parametrize("bad", [0, -1, "12", True, 1.5])
def test_history_window_is_validated(tmp_path, bad):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"history_reviews": bad}))
    with pytest.raises(ValueError, match="history_reviews"):
        Config.load(path)


# --- labels and summaries ---

def finding(**kw) -> Finding:
    return Finding("AR-04", "No MFA", "high", [], "lee.chen@acme.example", "", "", **kw)


def test_labels():
    assert label(finding()) == ""
    assert label(finding(reviews_open=1, first_seen="2026-09-15")) == "New"
    assert label(finding(reviews_open=1, first_seen="2026-06-15", reopened=True)) == "Back again, first seen 2026-06-15"
    assert label(finding(reviews_open=3, first_seen="2026-03-15")) == "3 reviews in a row, first seen 2026-03-15"


def test_repeat_summary_is_counts_only():
    assert repeat_summary([finding()]) is None
    assert repeat_summary([finding(reviews_open=1)]) == "Open since the last review: none"
    summary = repeat_summary([finding(reviews_open=3), finding(reviews_open=2), finding(reviews_open=1)])
    assert summary == "Open since the last review: 2 of 3 (longest: 3 reviews in a row)"
    assert "lee" not in summary


def test_unknown_previous_review_is_not_called_reopened():
    history = History(reviews=[
        PriorReview("2026-06-15", "a", "x", {("AR-04", "lee.chen@acme.example")}),
        PriorReview("2026-07-15", "b", "y", None, "findings.csv is missing"),
    ])
    f = finding()
    age_findings([f], history, date(2026, 9, 15))
    assert (f.reviews_open, f.first_seen, f.reopened) == (1, "2026-06-15", False)
