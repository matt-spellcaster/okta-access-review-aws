"""scripts/export_demo.py: the demo review as data, which a page replays and has to match."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from access_review.items import ACKNOWLEDGE_ONLY, DECIDE, KEEP, REVOKE, role_concern

ROOT = Path(__file__).parent.parent
VARIANTS = ("okta", "github", "incomplete", "github-incomplete")


def load_script():
    spec = importlib.util.spec_from_file_location("export_demo", ROOT / "scripts" / "export_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def export(out: Path) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, str(ROOT / "scripts" / "export_demo.py"), "--out", str(out),
                             "--allow-dirty"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.fixture(scope="module")
def exports(tmp_path_factory):
    """The whole export, twice, from two processes."""
    dirs = [tmp_path_factory.mktemp("first"), tmp_path_factory.mktemp("second")]
    for proc in [export(d) for d in dirs]:
        _, err = proc.communicate(timeout=600)
        assert proc.returncode == 0, err.decode()
    return dirs


@pytest.fixture(scope="module")
def data(exports):
    out = exports[0]
    return {v: (json.loads((out / f"{v}.json").read_text()), json.loads((out / f"{v}.golden.json").read_text()))
            for v in VARIANTS}


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


def test_every_concern_is_a_finding_or_what_the_role_can_do(data):
    for page, _ in data.values():
        for item in page["items"]:
            render = item["render"]
            for concern, finding in zip(item["concerns"], render["concerns"], strict=True):
                assert finding is not None or concern in role_concern(item["kind"], item["target"]), concern
            assert all(render["outside_okta"])
            assert len(render["outside_okta"]) == len(item["outside_okta"])


def test_every_signoff_matches_its_decisions(data):
    for page, golden in data.values():
        for name, scenario in golden["scenarios"].items():
            [attestation] = [json.loads(scenario["records"]["signoff"]["attestation.json"])]
            assert scenario["records"]["signoff"]["decisions.json"] == scenario["decisions_text"]
            digest = hashlib.sha256(scenario["decisions_text"].encode()).hexdigest()
            assert digest == scenario["decisions_sha256"] == attestation["decisions_sha256"], name
            assert attestation["manifest_sha256"] == page["run"]["manifest_sha256"]
            assert scenario["attest"]["intact"].endswith("exit 0\n")


def test_the_run_files_are_the_hashed_bytes(data):
    for page, _ in data.values():
        run = page["run"]
        manifest = json.loads(run["manifest_text"])
        assert hashlib.sha256(run["manifest_text"].encode()).hexdigest() == run["manifest_sha256"]
        assert manifest["files"]["review_items.json"] == run["items_sha256"]
        assert hashlib.sha256(run["items_text"].encode()).hexdigest() == run["items_sha256"]
        assert manifest["files"]["report.pdf"] == run["pdf"]["sha256"]


def test_each_tamper_is_one_byte_and_attest_catches_it(data):
    for page, golden in data.values():
        for scenario in golden["scenarios"].values():
            files = {"manifest.json": page["run"]["manifest_text"], "review_items.json": page["run"]["items_text"],
                     "signoff/decisions.json": scenario["decisions_text"]}
            assert [t["file"] for t in scenario["tampers"]] == ["manifest.json", "review_items.json",
                                                                "signoff/decisions.json"]
            for change in scenario["tampers"]:
                body = files[change["file"]].encode()
                assert chr(body[change["offset"]]) == change["from"] != change["to"]
                printed = scenario["attest"][change["file"]]
                assert printed.endswith("exit 2\n")
                assert "doesn't match its evidence" in printed
            assert [{k: v for k, v in t.items() if k != "offset"} for t in scenario["tampers"]] == page["tampers"]


def test_a_revoke_ticket_is_its_template_with_the_reason_in(data):
    """The page builds revoke tickets from render.revoke; the real ones in C
    (everything revoked) must be exactly that with the reason put in."""
    slot = load_script().SLOT
    for page, golden in data.values():
        scenario = golden["scenarios"]["C"]
        final = json.loads(scenario["decisions_text"])["decisions"]
        created = {e["fields"]["labels"][1]: e for e in scenario["jira"] if e["call"] == "create"}
        revocable = [i for i in page["items"] if i["kind"] not in ACKNOWLEDGE_ONLY]
        assert revocable and all(i["render"]["revoke"] for i in revocable)
        first_key = min(int(e["key"].split("-")[1]) for e in created.values() if "Revoke " in e["fields"]["summary"])
        for item in revocable:
            template = item["render"]["revoke"]
            why = final[item["key"]]["reason"] or item["reason"]
            expected = json.loads(json.dumps(template["fields"]).replace(json.dumps(slot)[1:-1], json.dumps(why)[1:-1]))
            real = created[template["label"]]
            assert real["fields"] == expected
            assert real["key"] == f"UAR-{first_key + template['order']}"


def test_refused_reasons_record_nothing(data):
    _, golden = data["okta"]
    steps = golden["scenarios"]["D"]["steps"]
    refused = [s for s in steps if "error" in s["result"]]
    assert [s["result"]["error"] for s in refused] == [
        "a reason is needed to keep access that was proposed for revocation, or to override a proposal",
        "the reason must be one line of at most 1000 characters",
    ]
    names = sorted(golden["scenarios"]["D"]["records"]["decisions"])
    assert names[0].endswith("-000000000001.json")
    assert len(names) == sum(1 for s in steps if s["do"] in ("record", "confirm") and "error" not in s["result"])


def test_nothing_from_this_machine_gets_out():
    leaked = load_script().leaked
    org = "https://acme-demo.okta.com"
    assert leaked("see https://acme-demo.okta.com, and https://acme-demo-admin.okta.com/admin", org) is None
    assert leaked(f"written in {ROOT}", org)
    assert leaked("/Users/someone/x", org) == "/Users/"
    assert leaked("https://acme.atlassian.net/browse/UAR-1", org) == "acme.atlassian.net"


def test_a_dirty_tree_is_refused(monkeypatch, tmp_path, capsys):
    script = load_script()
    monkeypatch.setattr(script, "git", lambda *args: " M src/x.py" if args[0] == "status" else "abc")
    assert script.main(["--out", str(tmp_path / "out")]) == 1
    assert "uncommitted changes" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
