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
    # A register that declares only Okta accounts. The demo config also declares
    # a GitHub one, which an Okta-only run cannot check and now says so -- see
    # the test below. Completeness is the claim under test here, so the fixture
    # is one where it can honestly be true.
    config = json.loads((FIXTURES / "demo_config.json").read_text())
    config["service_accounts"] = [
        e for e in config["service_accounts"]
        # Entries are a bare id or an object; only the object form names a source.
        if isinstance(e, str) or not str(e.get("source", "")).startswith("github")
    ]
    path = tmp_path / "okta_only_config.json"
    path.write_text(json.dumps(config))
    out = tmp_path / "out"
    main(["--snapshot", str(FIXTURES / "demo_snapshot.json"),
          "--roster", str(FIXTURES / "demo_roster.csv"),
          "--config", str(path), "--as-of", "2026-09-15", "--out", str(out)])
    d = run_dir(out)
    assert "Data gaps" not in (d / "report.md").read_text()
    assert json.loads((d / "manifest.json").read_text())["complete"] is True


def test_a_register_entry_for_an_estate_this_run_does_not_read_is_out_of_scope(tmp_path):
    """The AWS pipeline reads Okta alone. A register that also declares the
    GitHub bots -- as the demo's does -- made every one of its reviews INCOMPLETE
    for good, a banner nobody could clear. An estate of a kind the run was never
    asked to read is out of scope; the review already says it read Okta alone.
    The dead entry that gap exists for is still one: see
    `test_a_register_entry_naming_an_estate_nothing_reads_is_still_a_gap`."""
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    manifest = json.loads((run_dir(tmp_path) / "manifest.json").read_text())
    assert not any("did not read" in g for g in manifest["data_gaps"])
    assert manifest["complete"] is True


def test_a_register_entry_naming_an_estate_nothing_reads_is_still_a_gap(tmp_path):
    """A source kind no collector reads can never be checked, whatever the run."""
    config = json.loads((FIXTURES / "demo_config.json").read_text())
    config["service_accounts"] = config.get("service_accounts", []) + [
        {"source": "gitlab:acme", "id": "deploy-bot", "owner": "priya.shah@acme.example"}]
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    args = [a if a != str(FIXTURES / "demo_config.json") else str(path) for a in DEMO_ARGS]
    main(args + ["--out", str(tmp_path / "out")])
    manifest = json.loads((run_dir(tmp_path / "out") / "manifest.json").read_text())
    [gap] = [g for g in manifest["data_gaps"] if "did not read" in g]
    assert "gitlab:acme" in gap and "github" not in gap
    assert manifest["complete"] is False


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
    # Named with its source, because `all_gaps` reads the graph's per-source
    # metadata and every run has a graph now, Okta-only ones included.
    assert manifest["data_gaps"] == [f"okta: {snap['gaps'][0]}"]


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
    """A graph is built either way now, so `sources` is what says whether a
    second estate was read -- it lists sources beyond Okta and nothing else.
    And no gap about the estate it did not read: the demo register's GitHub
    entries are out of scope on an Okta-only run, not a hole in it. Exact, not
    `all(...)`, which an empty list passes whatever it was meant to say."""
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    manifest = json.loads((run_dir(tmp_path) / "manifest.json").read_text())
    assert manifest["sources"] == []
    assert "Also read" not in (run_dir(tmp_path) / "report.md").read_text()
    assert manifest["data_gaps"] == []


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
    # AR-17 is no longer skipped -- it runs against the Okta-only graph and
    # finds nothing, because it skips Okta principals. `sources` is the claim
    # that matters here: no second estate was read on the rerun.
    assert manifest["sources"] == []
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


def test_an_extra_file_written_from_chunks_is_the_same_bytes_and_the_same_hash(tmp_path):
    """`review_items.json` arrives as an iterator so that the largest file in
    the folder is never a string anyone holds. The evidence must not notice:
    same bytes on disk, same SHA-256 in the signed manifest.

    Deliberately many chunks and larger than one read block. A writer that took
    only the first chunk, or a hash that read only the first block, both pass on
    a file small enough to arrive in one piece.
    """
    from access_review.report import write_report

    snapshot, findings, skipped, config, as_of = _demo_inputs()
    rows = [json.dumps({"key": f"app:{i:05d}", "target": "Application " * 20}) for i in range(1200)]
    chunks = ['{"items": ['] + [("\n" if i == 0 else ",\n") + r for i, r in enumerate(rows)] + ["\n]}\n"]
    text = "".join(chunks)
    assert len(text) > (1 << 18), "smaller than a read block would prove nothing"

    d = write_report(tmp_path, snapshot, findings, skipped, config, as_of,
                     extra_files={"review_items.json": iter(chunks)})
    written = (d / "review_items.json").read_bytes()
    assert written == text.encode()
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["files"]["review_items.json"] == hashlib.sha256(written).hexdigest()


def test_a_review_hands_the_items_file_over_as_chunks_not_as_a_document(tmp_path, monkeypatch):
    """The saving is in `review.py`, not only in `items.py`.

    `items_json` here instead of `items_chunks` rebuilds the whole document and
    keeps it live in `extra` through the access matrix, the PDF and the manifest
    -- 243 MB of peak at 250k items against 15 MB -- and nothing else in this
    suite would say a word, because the file written at the end is identical.
    """
    import inspect
    from datetime import date

    from access_review import review as review_module
    from access_review.checks import Config
    from access_review.items import ITEMS_FILE
    from access_review.models import Snapshot
    from access_review.roster import load_roster

    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    seen: list[str] = []
    real = review_module.write_report

    def spy(*args, **kwargs):
        extra = kwargs["extra_files"]
        stream = extra[ITEMS_FILE]
        # Not `not isinstance(stream, str)`: a list of rows, or a one-element
        # list holding the whole document, are both not-a-str and both put the
        # peak straight back. An unstarted generator is the only thing that
        # cannot already be holding it.
        assert inspect.isgenerator(stream), f"{type(stream).__name__}, where a stream was the point"
        assert inspect.getgeneratorstate(stream) == inspect.GEN_CREATED, "already run"

        def counted():
            for chunk in stream:
                seen.append(chunk)
                yield chunk

        extra[ITEMS_FILE] = counted()
        return real(*args, **kwargs)

    monkeypatch.setattr(review_module, "write_report", spy)
    run = review_module.run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path,
                                   config, date(2026, 9, 15), tmp_path, require_items=True)
    assert run.items, "the fixture has items to write"
    assert len(seen) == len(run.items) + 2, "the envelope, one chunk per item, the closing brace"


def test_a_chunked_extra_file_reaches_the_disk_before_the_last_chunk_is_asked_for(tmp_path):
    """Written a chunk at a time, not joined and then written.

    `"".join(chunks)` inside the writer is byte-identical, passes every other
    test in this file, and puts the whole document back in memory -- the one
    thing handing over an iterator was for. The only place the difference shows
    is from inside the iterator: by the time the second chunk is asked for, the
    first is already on disk.
    """
    import io
    import os

    from access_review.report import _write_text

    path = tmp_path / "review_items.json"
    on_disk = []
    # Twice the buffer the text layer actually flushes at, so the first chunk
    # really reaches the file rather than sitting in it. `open` takes that from
    # the filesystem's `st_blksize` and falls back to `DEFAULT_BUFFER_SIZE`,
    # which is itself 8 KB before 3.14 and 128 KB from it -- so neither number
    # alone is the buffer, and a literal would make this test fail on a correct
    # writer somewhere else.
    block = "x" * (max(io.DEFAULT_BUFFER_SIZE, os.stat(tmp_path).st_blksize) * 2)

    def chunks():
        yield block
        on_disk.append(path.stat().st_size if path.exists() else -1)
        yield block

    _write_text(path, chunks())
    assert on_disk and on_disk[0] > 0, "nothing reached the file until the last chunk"
    assert path.read_bytes() == (block * 2).encode()


def test_the_manifest_hash_never_reads_the_file_whole(tmp_path, monkeypatch):
    """Writing the largest file a chunk at a time buys nothing if the manifest
    then reads all of it back, so the hash has its own half of the invariant.

    `hashlib.sha256(path.read_bytes()).hexdigest()` is the mutation: same digest
    for every file, every other test in this suite green, and the full copy of
    `review_items.json` back in memory at the point the manifest is built. The
    only thing that separates the two is which call is made, so that is what
    this forbids.
    """
    from access_review.report import _sha256

    big = tmp_path / "review_items.json"
    big.write_bytes((b"x" * 4096 + b"\n") * 200)  # several read blocks
    empty = tmp_path / "github_snapshot.json"
    empty.write_bytes(b"")

    def refuse(self):
        raise AssertionError("the manifest read the whole file back into memory")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    assert _sha256(big) == hashlib.sha256((b"x" * 4096 + b"\n") * 200).hexdigest()
    assert _sha256(empty) == hashlib.sha256(b"").hexdigest(), "an empty file still hashes"


def test_a_string_extra_file_reaches_the_file_in_one_write_and_a_rewrite_truncates(tmp_path, monkeypatch):
    """The two ways `_write_text` can be tidied up without changing a byte.

    Dropping the `isinstance` branch (`fh.writelines(content)` for everything)
    is byte-identical, because a str is an iterable of str -- and it writes
    `github_snapshot.json` one character at a time. Opening `"a"` instead of
    `"w"` is byte-identical on a folder that does not exist yet, and on a rerun
    into one that does it leaves the previous review's bytes in front of this
    one's, inside a file the manifest then signs.
    """
    from access_review.report import _write_text

    calls: list[int] = []
    real_open = Path.open

    class Counting:
        def __init__(self, fh):
            self._fh = fh

        def write(self, s):
            calls.append(len(s))
            return self._fh.write(s)

        def writelines(self, chunks):
            for chunk in chunks:
                self.write(chunk)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()
            return False

    monkeypatch.setattr(Path, "open", lambda self, *a, **kw: Counting(real_open(self, *a, **kw)))
    _write_text(tmp_path / "github_snapshot.json", "x" * 5000)
    assert calls == [5000], "a str handed to writelines is written one character per call"
    monkeypatch.undo()

    rewritten = tmp_path / "review_items.json"
    _write_text(rewritten, "y" * 100)
    _write_text(rewritten, iter(["z" * 10]))
    assert rewritten.read_text() == "z" * 10, "append mode keeps the previous run's bytes"


def test_the_departures_line_says_what_is_unfinished_not_where_it_lives(tmp_path, capsys):
    """Counts only, and no "outside Okta": a leaver's Okta API client is
    unfinished too, and it is in Okta. The sentence names what deactivation did
    not reach instead."""
    main(DEMO_ARGS + ["--github", str(FIXTURES / "demo_github.json"), "--out", str(tmp_path)])
    out = capsys.readouterr().out
    [line] = [ln for ln in out.splitlines() if ln.startswith("Departures:")]
    assert line == "Departures: 3 checked, 3 with something deactivation did not reach. See transitions.json."
    assert "outside okta" not in out.lower()
