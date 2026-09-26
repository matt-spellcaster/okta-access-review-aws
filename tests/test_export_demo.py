"""scripts/export_demo.py: the demo review as data, which a page replays and has to match."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from access_review.items import ACKNOWLEDGE_ONLY, DECIDE, ITEMS_FILE, KEEP, REVOKE, role_concern

ROOT = Path(__file__).parent.parent


def load_script():
    spec = importlib.util.spec_from_file_location("export_demo", ROOT / "scripts" / "export_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VARIANTS = tuple(load_script().VARIANTS)


def export(out: Path, env: dict | None = None) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, str(ROOT / "scripts" / "export_demo.py"), "--out", str(out),
                             "--allow-dirty"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, **(env or {})})


@pytest.fixture(scope="module")
def exports(tmp_path_factory):
    """The whole export, twice, from two processes; the second with settings in
    its environment that ReportLab would otherwise make the PDF by."""
    dirs = [tmp_path_factory.mktemp("first"), tmp_path_factory.mktemp("second")]
    for proc in [export(dirs[0]), export(dirs[1], {"SOURCE_DATE_EPOCH": "1700000000", "RL_pageCompression": "0"})]:
        _, err = proc.communicate(timeout=600)
        assert proc.returncode == 0, err.decode()
    return dirs


@pytest.fixture(scope="module")
def data(exports):
    out = exports[0]
    return {v: (json.loads((out / f"{v}.json").read_text()), json.loads((out / f"{v}.golden.json").read_text()))
            for v in VARIANTS}


def created(scenario: dict) -> dict[str, dict]:
    """The scenario's new Jira tickets, by their evidence label."""
    records = {r["issue"]: r for r in map(json.loads, scenario["records"]["tickets"].values())}
    return {records[e["key"]]["label"]: e for e in scenario["jira"] if e["call"] == "create"}


def test_two_processes_write_the_same_bytes(exports):
    first, second = exports
    names = sorted(p.name for p in first.iterdir())
    assert names == sorted(p.name for p in second.iterdir())
    assert names == sorted(f"{v}{ext}" for v in VARIANTS for ext in (".json", ".golden.json", ".pdf"))
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_the_github_variants_report_is_the_readme_sample(exports):
    assert (exports[0] / "github.pdf").read_bytes() == (ROOT / "docs" / "sample-report.pdf").read_bytes()


def test_the_output_is_stamped_with_the_commit(data):
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    for page, golden in data.values():
        assert page["source"]["commit"].removesuffix("-dirty") == head
        assert golden["source"] == page["source"]


def test_a_dirty_tree_is_stamped_dirty(monkeypatch, tmp_path):
    script = load_script()
    stamps = []
    monkeypatch.setattr(script, "export", lambda variant, commit: stamps.append(commit) or {})
    monkeypatch.setattr(script, "git", lambda *a: " M src/x.py" if a[0] == "status" else "abc")
    assert script.main(["--out", str(tmp_path), "--allow-dirty", "--variant", "okta"]) == 0
    monkeypatch.setattr(script, "git", lambda *a: "" if a[0] == "status" else "abc")
    assert script.main(["--out", str(tmp_path), "--variant", "okta"]) == 0
    assert stamps == ["abc-dirty", "abc"]


def test_the_pinned_counts(data):
    def proposed(variant):
        items = data[variant][0]["items"]
        return tuple(sum(1 for i in items if i["proposed"] == p) for p in (KEEP, REVOKE, DECIDE))

    assert proposed("okta") == (6, 7, 5)
    assert proposed("incomplete") == (0, 5, 13)
    page, golden = data["okta"]
    summary = page["open"]["slack"][0]["payload"]
    assert "Confirm 13 proposed" in json.dumps(summary)
    assert [e["fields"]["summary"].split(" ")[0] for e in page["open"]["jira"]] == ["Okta", "Remove", "Remove"]
    assert page["open"]["result"]["urgent_tickets"] == 2
    assert len(page["fix_tickets"]) == 10
    assert golden["scenarios"]["A"]["steps"][-1]["result"]["remediate"]["fix_tickets"] == 10


def test_the_web_variant_is_five_items_from_two_people(data):
    page, golden = data["web"]
    items = [(i["user"], i["kind"], i["proposed"], i["target"]) for i in page["items"]]
    assert sorted(items) == [
        ("jordan.kim@acme.example", "admin_role", DECIDE, "Help Desk Administrator"),
        ("jordan.kim@acme.example", "app", KEEP, "Salesforce"),
        ("jordan.kim@acme.example", "hr_record", DECIDE, "HR record"),
        ("marcus.lee@acme.example", "app", REVOKE, "AWS"),
        ("marcus.lee@acme.example", "app", REVOKE, "GitHub"),
    ]
    # The leaver's API token and the service account he owned are still found.
    checks = {t["check_id"] for t in page["fix_tickets"]}
    assert {"AR-18"} <= checks and len(page["fix_tickets"]) == 3
    assert json.loads(page["run"]["manifest_text"])["finding_counts"]["critical"] == 4


def test_nobody_else_in_acme_is_in_the_web_variant(data, exports):
    script = load_script()
    snapshot = json.loads((ROOT / "fixtures" / "demo_snapshot.json").read_text())
    # The service-account register (the config) still names the accounts the leaver owned:
    # that's how AR-18 finds them.
    register = {a if isinstance(a, str) else a["id"]
                for a in json.loads((ROOT / "fixtures" / "demo_config.json").read_text())["service_accounts"]}
    others = {u["login"] for u in snapshot["users"]} - set(script.PEOPLE["web"]) - register
    assert len(others) == 8
    report = script.pdf_text((exports[0] / "web.pdf").read_bytes())
    assert "marcus.lee@acme.example" in report
    for text in (json.dumps(data["web"]), report):
        assert [login for login in others if login in text] == []
    # Cut in memory: okta is still the whole of Acme.
    assert len(data["okta"][0]["items"]) == 18


def test_only_the_scripted_refusals_are_refused(data):
    for _, golden in data.values():
        for name, scenario in golden["scenarios"].items():
            for step in scenario["steps"]:
                assert ("error" in step["result"]) == bool(step.get("refused")), (name, step)
    _, golden = data["okta"]
    steps = golden["scenarios"]["D"]["steps"]
    assert [s["result"]["error"] for s in steps if s.get("refused")] == [
        "a reason is needed to keep access that was proposed for revocation, or to override a proposal",
        "the reason must be one line of at most 1000 characters",
    ]
    names = sorted(golden["scenarios"]["D"]["records"]["decisions"])
    assert names[0].endswith("-000000000001.json")
    assert len(names) == sum(1 for s in steps if s["do"] in ("record", "confirm") and not s.get("refused"))
    rule = data["okta"][0]["settings"]["record_name"]
    assert names == [rule.format(n=n) for n in range(1, len(names) + 1)]


def test_every_concern_is_a_finding_or_what_the_role_can_do(data):
    for page, _ in data.values():
        for item in page["items"]:
            render = item["render"]
            for concern, finding in zip(item["concerns"], render["concerns"], strict=True):
                assert finding is not None or concern in role_concern(item["kind"], item["target"]), concern
            assert all(render["outside_okta"])
            assert len(render["outside_okta"]) == len(item["outside_okta"])


def test_each_card_is_the_one_the_review_posted(data):
    for page, _ in data.values():
        posted = [b["text"]["text"] for m in page["open"]["slack"] if m["call"] == "post"
                  for b in m["payload"].get("blocks", []) if b.get("block_id", "").startswith("i:")]
        assert [i["render"]["card"] for i in page["items"]] == posted


def test_each_signoff_piece_is_on_the_approve_message(data):
    for page, golden in data.values():
        [message] = [m for m in golden["scenarios"]["A"]["slack"] if m["call"] == "post"
                     and any(b.get("block_id") == "approve" for b in m["payload"]["blocks"])]
        sections = [b["text"]["text"] for b in message["payload"]["blocks"] if b.get("type") == "section"]
        for item in page["items"]:
            assert any("\n".join(item["render"]["signoff"]) in t for t in sections), item["key"]


def test_every_signoff_matches_its_decisions(data):
    for page, golden in data.values():
        for name, scenario in golden["scenarios"].items():
            attestation = json.loads(scenario["records"]["signoff"]["attestation.json"])
            assert scenario["records"]["signoff"]["decisions.json"] == scenario["decisions_text"]
            digest = hashlib.sha256(scenario["decisions_text"].encode()).hexdigest()
            assert digest == scenario["decisions_sha256"] == attestation["decisions_sha256"], name
            assert attestation["manifest_sha256"] == page["run"]["manifest_sha256"]
            assert scenario["attest"]["intact"].endswith("exit 0\n")


def test_the_approve_button_sits_under_what_was_signed(data):
    """Scenario D changes its mind after every item is decided: the Approve
    message is redrawn, so the last drawing with the button lists what was signed."""
    for _, golden in data.values():
        for name, scenario in golden["scenarios"].items():
            drawn = [json.dumps(m["payload"]) for m in scenario["slack"] if m["call"] in ("post", "update")
                     and any(b.get("block_id") == "approve" for b in m["payload"].get("blocks", []))]
            revoked = json.loads(scenario["records"]["signoff"]["attestation.json"])["items_revoked"]
            assert (f"Revoke ({revoked})" in drawn[-1]) if revoked else ("Revoke (" not in drawn[-1]), name
            assert len(drawn) == (2 if name == "D" else 1), name


def test_keeping_everything_revokes_nothing(data):
    for _, golden in data.values():
        scenario = golden["scenarios"]["E"]
        assert json.loads(scenario["records"]["signoff"]["attestation.json"])["decision"] == "approved"
        assert "0 revoked" in scenario["attest"]["intact"]
        assert not any("Revoke " in e["fields"]["summary"] for e in created(scenario).values())


def test_the_run_files_are_the_hashed_bytes(data):
    for page, _ in data.values():
        run = page["run"]
        manifest = json.loads(run["manifest_text"])
        assert hashlib.sha256(run["manifest_text"].encode()).hexdigest() == run["manifest_sha256"]
        assert manifest["files"][ITEMS_FILE] == run["items_sha256"]
        assert hashlib.sha256(run["items_text"].encode()).hexdigest() == run["items_sha256"]
        assert manifest["files"]["report.pdf"] == run["pdf"]["sha256"]


def test_each_tamper_is_one_byte_and_attest_catches_it(data):
    for page, golden in data.values():
        for scenario in golden["scenarios"].values():
            files = {"manifest.json": page["run"]["manifest_text"], ITEMS_FILE: page["run"]["items_text"],
                     "signoff/decisions.json": scenario["decisions_text"]}
            assert [t["file"] for t in scenario["tampers"]] == list(files)
            for change in scenario["tampers"]:
                body = files[change["file"]].encode()
                assert chr(body[change["offset"]]) == change["from"] != change["to"]
                printed = scenario["attest"][change["file"]]
                assert printed.endswith("exit 2\n")
                assert "doesn't match its evidence" in printed
            assert [{k: v for k, v in t.items() if k != "offset"} for t in scenario["tampers"]] == page["tampers"]


def test_a_revoke_ticket_is_its_template_with_the_reason_in(data):
    """The page builds revoke tickets from render.revoke. In every scenario, each
    real one must be exactly that with the reason put in (the proposal's when none
    was given), numbered by its order among the revoked items."""
    slot = load_script().SLOT
    for page, golden in data.values():
        revocable = [i for i in page["items"] if i["kind"] not in ACKNOWLEDGE_ONLY]
        assert revocable and all(i["render"]["revoke"] for i in revocable)
        for name, scenario in golden["scenarios"].items():
            final = json.loads(scenario["decisions_text"])["decisions"]
            tickets = created(scenario)
            records = {r["label"]: r for r in map(json.loads, scenario["records"]["tickets"].values())}
            revoked = sorted((i for i in revocable if final[i["key"]]["decision"] == REVOKE),
                             key=lambda i: i["render"]["revoke"]["order"])
            assert sum(1 for r in records.values() if r["kind"] == "revoke") == len(revoked), name
            first = min((int(tickets[i["render"]["revoke"]["label"]]["key"].split("-")[1]) for i in revoked),
                        default=None)
            for n, item in enumerate(revoked):
                template = item["render"]["revoke"]
                why = final[item["key"]]["reason"] or template["why_if_empty"]
                expected = json.loads(json.dumps(template["fields"]).replace(json.dumps(slot)[1:-1],
                                                                            json.dumps(why)[1:-1]))
                real = tickets[template["label"]]
                assert real["fields"] == expected, (name, item["key"])
                assert real["key"] == f"UAR-{first + n}", (name, item["key"])
                record = records[template["label"]]
                assert (record["todo"], record["due"]) == (template["todo"], template["due"]), (name, item["key"])


def test_the_fix_tickets_are_the_ones_remediation_opens(data):
    for page, golden in data.values():
        scenario = golden["scenarios"]["A"]
        tickets = created(scenario)
        records = {r["label"]: r for r in map(json.loads, scenario["records"]["tickets"].values())}
        fixes = [label for label in tickets if records[label]["kind"] == "finding"]
        assert [f["label"] for f in page["fix_tickets"]] == fixes
        for fix in page["fix_tickets"]:
            assert tickets[fix["label"]]["fields"] == fix["fields"]
            assert {k: records[fix["label"]][k] for k in ("todo", "due", "verify", "check_id")} == {
                k: fix[k] for k in ("todo", "due", "verify", "check_id")}


def test_the_tickets_opened_at_the_start_are_in_every_review(data):
    for page, golden in data.values():
        opened = page["open"]["records"]
        leavers_left = 1 if page["source"]["variant"] == "web" else 2  # web keeps one of the two leavers
        assert sorted(json.loads(r)["kind"] for r in opened.values()) == ["leaver"] * leavers_left + ["parent"]
        assert page["settings"]["parent_issue"] == "UAR-1"
        for scenario in golden["scenarios"].values():
            for name, record in opened.items():
                assert scenario["records"]["tickets"][name] == record
        leavers = {json.loads(r)["issue"] for r in opened.values() if json.loads(r)["kind"] == "leaver"}
        assert {i["render"]["leaver_ticket"] for i in page["items"]} - {None} == leavers


def test_nothing_from_this_machine_gets_out(monkeypatch):
    script = load_script()
    leaked = script.leaked
    assert leaked("see https://acme-demo.okta.com, and <https://acme-demo-admin.okta.com/admin|x>") is None
    assert leaked("in s3://acme-uar-evidence/runs/ by maria.lopez@acme.example") is None
    assert leaked(f"written in {ROOT}")
    assert leaked("/Users/someone/x") == "/Users/"
    assert leaked("see ~/code") == "~/"
    assert leaked("https://acme.atlassian.net/browse/UAR-1") == "https://acme.atlassian.net"
    assert leaked("https://acme-demo.okta.com@outside.example/x") == "https://acme-demo.okta.com@outside.example"
    assert leaked("https://someone@acme-demo.okta.com/x") == "https://someone@acme-demo.okta.com"
    assert leaked("https://acme-demo.okta.com:@outside.example/x") == "https://acme-demo.okta.com:@outside.example"
    assert leaked("https://acme-demo.okta.com:443/x") is None
    assert leaked("HTTPS://outside.example") == "HTTPS://outside.example"
    assert leaked("s3://my-real-bucket/x") == "s3://my-real-bucket"
    assert leaked("from someone@gmail.com") == "someone@gmail.com"
    monkeypatch.setattr(script, "ROOT", Path("/srv/checkout"))
    monkeypatch.setattr(script.tempfile, "gettempdir", lambda: "/scratch/t")
    assert leaked("made in /srv/checkout/x") == "/srv/checkout"
    assert leaked("see /scratch/t/abc") == "/scratch/t"


def test_the_leak_check_reads_the_reports(exports):
    pdf_text = load_script().pdf_text
    for variant in VARIANTS:
        text = pdf_text((exports[0] / f"{variant}.pdf").read_bytes())
        assert "https://acme-demo.okta.com" in text and "@acme.example" in text  # the report's own words
    with pytest.raises(SystemExit, match="can't read"):
        pdf_text(b"<< /Length 3 >>\nstream\nabc\nendstream")


def test_a_leak_in_a_report_writes_nothing(monkeypatch, tmp_path):
    script = load_script()
    monkeypatch.setattr(script, "git", lambda *a: "" if a[0] == "status" else "abc")
    real = script.leaked
    monkeypatch.setattr(script, "leaked", lambda text: "%PDF" in text and "/Users/" or real(text))
    out = tmp_path / "out"
    with pytest.raises(SystemExit, match=r"okta\.pdf would contain"):
        script.main(["--out", str(out), "--variant", "okta"])
    assert not out.exists()


def test_a_leak_in_any_variant_writes_nothing(monkeypatch, tmp_path):
    script = load_script()
    monkeypatch.setattr(script, "git", lambda *a: "" if a[0] == "status" else "abc")
    real = script.leaked
    monkeypatch.setattr(script, "leaked", lambda text: '"variant": "github-incomplete"' in text and "/Users/" or real(text))
    out = tmp_path / "out"
    with pytest.raises(SystemExit, match="nothing written"):
        script.main(["--out", str(out)])
    assert not out.exists()


def test_a_tree_that_changes_while_exporting_is_refused(monkeypatch, tmp_path, capsys):
    script = load_script()
    heads = iter(["abc", "def"])
    monkeypatch.setattr(script, "git", lambda *a: "" if a[0] == "status" else next(heads))
    monkeypatch.setattr(script, "export", lambda variant, commit: {f"{variant}.json": b"{}"})
    assert script.main(["--out", str(tmp_path / "out"), "--variant", "okta"]) == 1
    assert "changed while exporting" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_a_dirty_tree_is_refused(monkeypatch, tmp_path, capsys):
    script = load_script()
    monkeypatch.setattr(script, "git", lambda *args: " M src/x.py" if args[0] == "status" else "abc")
    assert script.main(["--out", str(tmp_path / "out")]) == 1
    assert "uncommitted changes" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
