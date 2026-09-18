import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
import requests
from fakes import FakeS3

from access_review import store, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import KEEP, REVOKE
from access_review.jira import JiraClient, JiraConfigError, JiraError, adf, check_base_url
from access_review.models import Snapshot
from access_review.review import run_review
from access_review.roster import load_roster
from access_review.tickets import Remediation, quarter, what_to_do

FIXTURES = Path(__file__).parent.parent / "fixtures"
BASE = "https://acme.atlassian.net"
TOKEN = "ATATT3xFfGF0-very-secret-token"
NOW = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        if self._body is None:
            raise ValueError
        return self._body


class FakeJiraSession:
    """A tiny in-memory Jira: labels are searchable, issues get sequential keys."""

    def __init__(self):
        self.calls = []
        self.issues = {}
        self.fail = None

    def request(self, method, url, timeout, headers, json=None, params=None):
        self.calls.append((method, url.removeprefix(BASE), json, headers))
        if self.fail:
            return self.fail
        path = url.removeprefix(BASE + "/rest/api/3")
        if path == "/search/jql":
            label = json["jql"].split('labels = "')[1].rstrip('"')
            hits = [{"key": k} for k, f in self.issues.items() if label in f["labels"]]
            return Resp(body={"issues": hits, "isLast": True})
        if path == "/issue":
            key = f"UAR-{len(self.issues) + 1}"
            self.issues[key] = json["fields"]
            return Resp(201, {"key": key})
        if path.endswith("/comment"):
            return Resp(201, {"id": "1"})
        return Resp(404, {"errorMessages": ["nope"]})


def client(session=None):
    return JiraClient(BASE, "svc-uar@acme.example", TOKEN, "UAR", session=session or FakeJiraSession())


def test_only_jira_cloud_urls_are_accepted():
    assert check_base_url(BASE + "/") == BASE
    assert check_base_url("https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555")
    for bad in ("http://acme.atlassian.net", "https://acme.atlassian.net.evil.test", "https://evil.test",
                "https://user@acme.atlassian.net", "https://acme.atlassian.net/other"):
        with pytest.raises(JiraConfigError):
            check_base_url(bad)
    with pytest.raises(JiraConfigError):
        JiraClient(BASE, "svc@acme.example", TOKEN, "not a key")


def test_writes_are_confined_to_one_project():
    c = client()
    with pytest.raises(JiraError, match="outside project"):
        c.create_issue({"project": {"key": "HR"}, "summary": "x"})
    with pytest.raises(JiraError, match="outside project"):
        c.add_comment("HR-1", adf("x"))


def test_errors_never_carry_the_token_or_issue_content():
    s = FakeJiraSession()
    s.fail = Resp(400, {"errors": {"summary": "Summary for lee.chen@acme.example is too long"}})
    with pytest.raises(JiraError) as e:
        client(s).create_issue({"project": {"key": "UAR"}, "summary": "x"})
    assert "summary" in str(e.value) and "lee.chen" not in str(e.value) and TOKEN not in str(e.value)

    class Broken:
        def request(self, *a, **kw):
            raise requests.ConnectionError(f"failed for {BASE}?token={TOKEN}")

    with pytest.raises(JiraError) as e:
        client(Broken()).search("x", [])
    assert TOKEN not in str(e.value) and e.value.__cause__ is None


@pytest.fixture
def signed_review(tmp_path):
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True)
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    session = FakeJiraSession()
    rem = Remediation(client(session), s3, "evidence", "Task", "Subtask", now=lambda: NOW)
    return rem, session, run, s3


def test_parent_and_leaver_tickets_are_opened_once(signed_review):
    rem, session, run, s3 = signed_review
    manifest = json.loads((run.run_dir / "manifest.json").read_text())
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    findings = workflow.urgent_findings(deps, run.run_dir.name)
    counts = {"total": 16, "keep": 6, "revoke": 7, "decide": 3}

    parent = rem.open_parent(run.run_dir.name, manifest, run.manifest_sha256, counts, NOW)
    assert rem.open_urgent(run.run_dir.name, parent, findings) == 3  # 6 findings about 3 people
    # Running the step again finds the labels and opens nothing new.
    assert rem.open_parent(run.run_dir.name, manifest, run.manifest_sha256, counts, NOW) == parent
    assert rem.open_urgent(run.run_dir.name, parent, findings) == 0

    fields = session.issues
    assert fields[parent]["summary"].startswith("Okta Access Review 2026-Q3")
    assert fields[parent]["duedate"] == "2026-09-16"
    marcus = next(f for f in fields.values() if "marcus.lee" in f["summary"])
    assert marcus["parent"] == {"key": parent} and marcus["duedate"] == "2026-09-17"  # 24 hours
    body = json.dumps(marcus["description"])
    assert "AR-01" in body and "AR-12" in body and "AR-13" in body
    records = store.list_records(s3, "evidence", run.run_dir.name, "tickets")
    assert len(records) == 4 and {r["issue"] for _, r in records} == set(fields)


def test_revoke_tickets_follow_the_signed_decisions(signed_review):
    rem, session, run, _ = signed_review
    items = {i.key: i for i in run.items}
    final = {k: {"decision": i.proposed if i.proposed != "decide" else KEEP, "reason": ""} for k, i in items.items()}
    revoked = [k for k, d in final.items() if d["decision"] == REVOKE]

    assert rem.open_revokes(run.run_dir.name, "UAR-99", items, final) == len(revoked) == 7
    assert rem.open_revokes(run.run_dir.name, "UAR-99", items, final) == 0
    lee = next(f for f in session.issues.values() if f["summary"] == "Revoke Salesforce for lee.chen@acme.example")
    assert lee["duedate"] == "2026-09-23"  # 7 days
    assert "unassign lee.chen@acme.example from the app Salesforce" in json.dumps(lee["description"])


def test_group_access_tickets_explain_the_side_effects(signed_review):
    _, _, run, _ = signed_review
    marcus_github = next(i for i in run.items if i.user.startswith("marcus") and i.target == "GitHub")
    assert "Engineering" in what_to_do(marcus_github) and "what else" in what_to_do(marcus_github)


def test_quarters():
    assert quarter("2026-01-01") == "2026-Q1" and quarter("2026-09-15") == "2026-Q3"
    assert quarter("2026-12-31") == "2026-Q4"
