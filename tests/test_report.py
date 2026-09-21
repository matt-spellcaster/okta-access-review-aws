import csv
import hashlib
import json
from pathlib import Path

from access_review.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]


def run_dir(out: Path) -> Path:
    [d] = list(out.iterdir())
    return d


def test_writes_evidence_with_matching_hashes(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    d = run_dir(tmp_path)
    assert d.name == "20260915T140000Z"
    manifest = json.loads((d / "manifest.json").read_text())
    assert set(manifest["files"]) == {
        "report.md", "report.pdf", "findings.csv", "access_matrix.csv", "snapshot.json", "roster.csv",
    }
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest
    assert manifest["finding_counts"]["critical"] == 5


def test_access_matrix_shows_group_and_direct_app_access(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    rows = {r["login"]: r for r in csv.DictReader((run_dir(tmp_path) / "access_matrix.csv").open())}
    assert len(rows) == 11
    assert rows["hannah.ortiz@acme.example"]["apps"] == "AWS (direct)"
    assert rows["priya.shah@acme.example"]["groups"] == "Engineering"  # built-in groups hidden
    assert rows["omar.haddad@acme.example"]["mfa"] == "n/a"  # PROVISIONED: can't sign in yet
    assert rows["victor.nguyen@acme.example"]["admin_roles"] == "n/a"
    assert rows["lee.chen@acme.example"]["mfa"] == "none"
    assert rows["omar.haddad@acme.example"]["last_login"] == "never"
    assert rows["lee.chen@acme.example"]["decision"] == ""
    assert rows["priya.shah@acme.example"]["admin_roles"] == "Super Administrator"
    assert rows["lee.chen@acme.example"]["admin_roles"] == ""


def test_saved_snapshot_round_trips(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    saved = json.loads((run_dir(tmp_path) / "snapshot.json").read_text())
    original = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    assert saved["users"] == original["users"]


def test_report_lists_controls_and_findings(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    md = (run_dir(tmp_path) / "report.md").read_text()
    assert "### AR-01 · Terminated in HR but account still live" in md
    assert "SOC 2 CC6.2" in md
    assert "`marcus.lee@acme.example`" in md


def test_complete_review_has_no_gaps_section(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    d = run_dir(tmp_path)
    assert "Data gaps" not in (d / "report.md").read_text()
    assert json.loads((d / "manifest.json").read_text())["complete"] is True


def test_data_gaps_are_reported(tmp_path):
    snap = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    snap["gaps"] = ["Could not read admin role assignments; AR-10 and AR-11 may be incomplete."]
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    out = tmp_path / "out"
    main(["--snapshot", str(path), "--as-of", "2026-09-15", "--out", str(out)])
    d = run_dir(out)
    assert "## ⚠️ Data gaps" in (d / "report.md").read_text()
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert manifest["data_gaps"] == snap["gaps"]


def test_pdf_is_reproducible_and_contains_findings(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    main(DEMO_ARGS + ["--out", str(a)])
    main(DEMO_ARGS + ["--out", str(b)])
    pdf_a = (run_dir(a) / "report.pdf").read_bytes()
    assert pdf_a == (run_dir(b) / "report.pdf").read_bytes()
    assert pdf_a.startswith(b"%PDF")

    from pypdf import PdfReader

    text = "\n".join(page.extract_text() for page in PdfReader(run_dir(a) / "report.pdf").pages)
    assert "Okta user access review" in text
    assert "marcus.lee@acme.example" in text
    assert "Reviewer sign-off" in text
    assert "CONFIDENTIAL" in text


def test_mfa_unknown_only_for_users_who_can_sign_in(tmp_path):
    snap = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    for u in snap["users"]:
        u["factors"] = None
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    main(["--snapshot", str(path), "--out", str(tmp_path / "out")])
    rows = {r["login"]: r for r in csv.DictReader((run_dir(tmp_path / "out") / "access_matrix.csv").open())}
    assert rows["priya.shah@acme.example"]["mfa"] == "unknown"
    assert rows["nina.patel@acme.example"]["mfa"] == "n/a"  # SUSPENDED


def test_default_review_date_is_collection_date(tmp_path):
    main(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--out", str(tmp_path)])
    assert json.loads((run_dir(tmp_path) / "manifest.json").read_text())["review_date"] == "2026-09-15"


def test_manifest_records_the_roster_used(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    d = run_dir(tmp_path)
    source = FIXTURES / "demo_roster.csv"
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["roster"] == {
        "source_name": "demo_roster.csv",  # file name only, never the local path
        "copied_as": "roster.csv",
        "rows": 9,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    assert (d / "roster.csv").read_bytes() == source.read_bytes()
    assert manifest["files"]["roster.csv"] == manifest["roster"]["sha256"]
    assert str(FIXTURES) not in (d / "manifest.json").read_text()
    label = f"demo_roster.csv, 9 people, SHA-256 {manifest['roster']['sha256'][:12]}"
    assert f"- **HR roster:** {label}" in (d / "report.md").read_text()


def test_no_roster_is_recorded_and_stale_copy_removed(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])  # first run leaves roster.csv behind
    no_roster = [a for a in DEMO_ARGS if a not in ("--roster", str(FIXTURES / "demo_roster.csv"))]
    main(no_roster + ["--out", str(tmp_path)])  # same collection time, same folder
    d = run_dir(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["roster"] is None
    assert not (d / "roster.csv").exists() and "roster.csv" not in manifest["files"]
    assert "- **HR roster:** not provided (AR-01 to AR-03, AR-12 and AR-13 skipped)" in (d / "report.md").read_text()


def test_findings_csv_header_is_explicit(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    with (run_dir(tmp_path) / "findings.csv").open(newline="") as f:
        header = next(csv.reader(f))
    assert header == [
        "check_id", "title", "severity", "controls", "subject", "detail", "remediation",
        "first_seen", "reviews_open", "reopened",
    ]


def test_manifest_ignores_subdirectories(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    (run_dir(tmp_path) / "scratch").mkdir()
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    assert "scratch" not in json.loads((run_dir(tmp_path) / "manifest.json").read_text())["files"]


def test_fail_on_sets_exit_code(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path), "--fail-on", "critical"]) == 2


def test_fail_on_passes_when_nothing_that_severe(tmp_path):
    args = [
        "--snapshot", str(FIXTURES / "demo_snapshot.json"),
        "--config", str(FIXTURES / "demo_config.json"),
        "--as-of", "2026-09-15",
        "--out", str(tmp_path),
        "--fail-on", "critical",
    ]
    assert main(args) == 0  # AR-01 is the only critical check and needs a roster


def _demo_inputs():
    from datetime import date

    from access_review.checks import Config, ReviewContext, run_checks
    from access_review.models import Snapshot
    from access_review.roster import load_roster

    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    ctx = ReviewContext(snapshot, load_roster(FIXTURES / "demo_roster.csv", config.timezone()), config,
                        date(2026, 9, 15))
    findings, skipped = run_checks(ctx)
    return snapshot, findings, skipped, config, ctx.as_of


def test_extra_files_are_covered_by_the_manifest(tmp_path):
    from access_review.report import write_report

    snapshot, findings, skipped, config, as_of = _demo_inputs()
    d = write_report(tmp_path, snapshot, findings, skipped, config, as_of,
                     extra_files={"review_items.json": '{"items": []}\n'})
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["files"]["review_items.json"] == hashlib.sha256(b'{"items": []}\n').hexdigest()
    assert manifest["app_usage_since"] == "2026-06-17T00:00:00Z"


def test_extra_files_cannot_replace_evidence_or_escape_the_folder(tmp_path):
    import pytest

    from access_review.report import ReportError, write_report

    snapshot, findings, skipped, config, as_of = _demo_inputs()
    for name in ("findings.csv", "manifest.json", "../x.json", ".hidden"):
        with pytest.raises(ReportError):
            write_report(tmp_path, snapshot, findings, skipped, config, as_of, extra_files={name: "x"})
    assert list(tmp_path.iterdir()) == []


def test_spreadsheet_formulas_in_evidence_csvs_are_neutralised(tmp_path):
    from access_review import csvsafe
    from access_review.report import _write_csv

    rows = [{"a": '=HYPERLINK("http://x")', "b": "'quoted", "c": "-1", "d": "plain", "e": 3}]
    _write_csv(tmp_path / "t.csv", rows, ["a", "b", "c", "d", "e"])
    text = (tmp_path / "t.csv").read_text()
    assert "'=HYPERLINK" in text and ",''quoted," in text and ",'-1," in text and ",plain," in text
    [back] = csvsafe.read_rows(text)  # the tool always reads the original value back
    assert back == {"a": '=HYPERLINK("http://x")', "b": "'quoted", "c": "-1", "d": "plain", "e": "3"}


def _graph(snapshot=None, **github_overrides):
    """The demo Okta snapshot plus the demo GitHub snapshot, as one graph."""
    from access_review.checks import Config
    from access_review.identity import GitHubSnapshot, IdentityGraph, project_github, project_snapshot
    from access_review.models import Snapshot

    snapshot = snapshot or Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    raw = json.loads((FIXTURES / "demo_github.json").read_text())
    raw.update(github_overrides)
    graph = IdentityGraph.compose(
        project_snapshot(snapshot, config.service_accounts),
        project_github(GitHubSnapshot.from_dict(raw)),
    )
    return snapshot, config, graph


def test_the_report_speaks_for_every_source_it_read():
    """A manifest that called a review complete while another source failed
    would be signed-off evidence of a claim nobody checked."""
    from access_review.report import all_gaps, other_sources

    snapshot, _, graph = _graph()
    assert snapshot.gaps == []  # Okta alone would call this review complete

    gaps = all_gaps(snapshot, graph)
    assert [g.split(":")[0] for g in gaps] == ["github"] * 4
    assert any("omar-haddad has 2 verified emails" in g for g in gaps)
    assert any("was not returned by the member read" in g for g in gaps)

    [source] = other_sources(graph)
    assert (source.source, source.principals, source.collected_at) == (
        "github:acme-eng", 13, "2026-09-15T14:00:00Z"
    )
    assert len(source.gaps) == 4
    assert other_sources(None) == [] and all_gaps(snapshot, None) == []


def test_all_gaps_carries_the_okta_projections_own_gaps():
    """The Okta projection records gaps `snapshot.gaps` never had -- a group
    member no user read returned. Reading only `snapshot.gaps` dropped them, so
    a review could be signed off complete while the graph said otherwise."""
    from access_review.models import Snapshot
    from access_review.report import all_gaps

    raw = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    raw["groups"][0]["members"].append("00uNOTINTHEUSERREAD")
    snapshot = Snapshot.from_dict(raw)
    _, _, graph = _graph(snapshot)

    assert snapshot.gaps == []
    assert graph.incomplete_sources() == ["okta", "github:acme-eng"]
    gaps = all_gaps(snapshot, graph)
    assert any(g.startswith("okta: ") and "00uNOTINTHEUSERREAD" in g for g in gaps)


def test_a_failed_source_read_makes_the_manifest_incomplete(tmp_path):
    """The behaviour CLAUDE.md states: a run cannot be called complete while a
    source it read failed. Driven through write_report, because the manifest's
    `complete` flag is what gets signed."""
    from datetime import date

    from access_review.report import write_report

    snapshot, config, graph = _graph(gaps=["the member read returned 502 after 3 pages"])
    d = write_report(tmp_path, snapshot, [], [], config, date(2026, 9, 15), graph=graph)
    manifest = json.loads((d / "manifest.json").read_text())

    assert manifest["complete"] is False
    assert "github:acme-eng: the member read returned 502 after 3 pages" in manifest["data_gaps"]
    assert [s["source"] for s in manifest["sources"]] == ["github:acme-eng"]
    assert manifest["sources"][0]["collected_at"] == "2026-09-15T14:00:00Z"
    report = (d / "report.md").read_text()
    assert "the member read returned 502" in report
    assert "**Also read:** github:acme-eng (13 principals, read 2026-09-15)" in report


def test_an_okta_only_run_says_nothing_about_other_sources(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    manifest = json.loads((run_dir(tmp_path) / "manifest.json").read_text())
    assert manifest["complete"] is True and manifest["data_gaps"] == []
    assert manifest["sources"] == []
    assert "Also read" not in (run_dir(tmp_path) / "report.md").read_text()


def test_the_github_snapshot_is_hashed_into_the_manifest(tmp_path):
    """Nine findings rest on it. Without it in the bundle, `attest` can verify
    the report but not the data it was read from."""
    assert main(DEMO_ARGS + ["--github", str(FIXTURES / "demo_github.json"),
                             "--out", str(tmp_path)]) == 0
    d = run_dir(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    assert "github_snapshot.json" in manifest["files"]
    body = (d / "github_snapshot.json").read_bytes()
    assert hashlib.sha256(body).hexdigest() == manifest["files"]["github_snapshot.json"]
    assert json.loads(body)["org"] == "acme-eng"


def test_the_departure_bundles_are_hashed_into_the_manifest(tmp_path):
    """A bundle can be lifted out and attached to a JSM ticket, so it has to be
    in the signed set: an evidence file nothing hashes cannot be shown to be the
    one the review produced."""
    assert main(DEMO_ARGS + ["--github", str(FIXTURES / "demo_github.json"),
                             "--out", str(tmp_path)]) == 0
    d = run_dir(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    assert "transitions.json" in manifest["files"]
    body = (d / "transitions.json").read_bytes()
    assert hashlib.sha256(body).hexdigest() == manifest["files"]["transitions.json"]
    assert {t["okta_login"] for t in json.loads(body)["transitions"]} == {
        "marcus.lee@acme.example", "sofia.ramos@acme.example", "victor.nguyen@acme.example",
    }


def test_a_rerun_does_not_inherit_the_previous_run_evidence(tmp_path):
    """The worst failure this file can have. Re-running into the same folder
    without --github used to leave the earlier run's github_snapshot.json and
    transitions.json behind, and the new manifest hashed them -- so a signed
    manifest asserted a GitHub read and a departure bundle for a review whose
    own `sources` list was empty, and `attest` called it a full match."""
    args = DEMO_ARGS + ["--out", str(tmp_path)]
    assert main(args + ["--github", str(FIXTURES / "demo_github.json")]) == 0
    d = run_dir(tmp_path)
    assert (d / "transitions.json").exists() and (d / "github_snapshot.json").exists()

    assert main(args) == 0  # same folder, no --github this time
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["sources"] == [] and "AR-17" in manifest["skipped_checks"]
    assert not (d / "transitions.json").exists(), "a bundle from the previous run survived"
    assert not (d / "github_snapshot.json").exists()
    assert "transitions.json" not in manifest["files"]
    assert "github_snapshot.json" not in manifest["files"]


def test_an_okta_only_review_writes_no_departure_bundle(tmp_path):
    """Without a second source every leaver would read as a finished departure,
    which is the claim the file exists to stop anyone making."""
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    d = run_dir(tmp_path)
    assert not (d / "transitions.json").exists()
    assert "transitions.json" not in json.loads((d / "manifest.json").read_text())["files"]


def test_a_source_read_weeks_from_the_others_is_reported_as_a_gap(tmp_path):
    """One review date covering reads a fortnight apart is not one point in
    time, and nothing downstream could otherwise tell."""
    stale = json.loads((FIXTURES / "demo_github.json").read_text())
    stale["collected_at"] = "2026-07-01T14:00:00Z"
    path = tmp_path / "stale_github.json"
    path.write_text(json.dumps(stale))
    out = tmp_path / "out"
    assert main(DEMO_ARGS + ["--github", str(path), "--out", str(out)]) == 0
    manifest = json.loads((run_dir(out) / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert any("76 days from the Okta snapshot" in g for g in manifest["data_gaps"])


def test_a_malformed_github_snapshot_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "gh.json"
    bad.write_text('{"org": "acme-eng"}')  # no collected_at
    assert main(DEMO_ARGS + ["--github", str(bad), "--out", str(tmp_path / "out")]) == 1
    err = capsys.readouterr().err
    assert "not a readable GitHub snapshot" in err and "Traceback" not in err
