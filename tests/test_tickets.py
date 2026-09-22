import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
import requests
from fakes import FakeS3

from access_review import store, workflow
from access_review.checks import Config
from access_review.decisions import Reviewers
from access_review.items import KEEP, REVOKE, outside_okta_by_login
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


def _paragraphs(description: dict) -> list[str]:
    """Each paragraph of an ADF description as one string."""
    return ["".join(node.get("text", "") for node in para.get("content", []))
            for para in description["content"]]


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


def test_tickets_link_to_the_person_in_okta(signed_review):
    rem, session, run, s3 = signed_review
    rem.okta_org_url = "https://acme-demo.okta.com"
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    people = workflow.people(deps, run.run_dir.name)
    rem.open_urgent(run.run_dir.name, "UAR-99", workflow.urgent_findings(deps, run.run_dir.name), people)
    items = {i.key: i for i in run.items}
    rem.open_revokes(run.run_dir.name, "UAR-99", items,
                     {k: {"decision": REVOKE, "reason": ""} for k, i in items.items() if i.proposed == REVOKE})
    marcus = next(f for f in session.issues.values() if f["summary"] == "Remove access for leaver marcus.lee@acme.example")
    lee = next(f for f in session.issues.values() if f["summary"] == "Revoke Salesforce for lee.chen@acme.example")
    for fields, uid in ((marcus, "u02"), (lee, "u05")):
        body = json.dumps(fields["description"])
        assert f"https://acme-demo-admin.okta.com/admin/user/profile/view/{uid}" in body
        assert '"type": "link"' in body


def test_findings_that_are_not_access_decisions_get_fix_tickets(signed_review):
    rem, session, run, s3 = signed_review
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    rows = workflow.all_findings(deps, run.run_dir.name)

    assert rem.open_findings(run.run_dir.name, "UAR-99", rows) == 7
    assert rem.open_findings(run.run_dir.name, "UAR-99", rows) == 0  # never twice
    summaries = sorted(f["summary"] for f in session.issues.values())
    assert "Fix: No MFA factor enrolled — lee.chen@acme.example" in summaries
    # Leaver findings have leaver tickets, AR-11/AR-14 are review items, and no HR record is raised with HR.
    assert not any(s.startswith("Fix: ") and ("Terminated" in s or "Admin user" in s or "unused" in s
                                              or "HR record" in s)
                   for s in summaries)
    records = [r for _, r in store.list_records(s3, "evidence", run.run_dir.name, "tickets")]
    assert {r["check_id"] for r in records if r["kind"] == "finding"} == {
        "AR-04", "AR-05", "AR-06", "AR-07", "AR-08", "AR-09", "AR-10"}
    assert all(r.get("todo") for r in records)
    # Which ones the daily check can confirm in Okta, and which are the reviewer's call.
    assert {r["check_id"]: r["verify"] for r in records if r["kind"] == "finding"} == {
        "AR-04": "okta", "AR-05": "reviewer", "AR-06": "reviewer",
        "AR-07": "reviewer", "AR-08": "okta", "AR-09": "okta", "AR-10": "reviewer"}


class TransitionSession(FakeJiraSession):
    def __init__(self, status="new"):
        super().__init__()
        self.status = status
        self.moved = []

    def request(self, method, url, timeout, headers, json=None, params=None):
        path = url.removeprefix(BASE + "/rest/api/3")
        if path == "/issue/UAR-1" and method == "GET":
            return Resp(body={"fields": {"status": {"statusCategory": {"key": self.status}}}})
        if path == "/issue/UAR-1/transitions" and method == "GET":
            return Resp(body={"transitions": [
                {"id": "11", "to": {"statusCategory": {"key": "indeterminate"}}},
                {"id": "61", "to": {"statusCategory": {"key": "done"}}}]})
        if path == "/issue/UAR-1/transitions" and method == "POST":
            self.moved.append(json["transition"]["id"])
            return Resp(204)
        return super().request(method, url, timeout, headers, json, params)


def test_close_moves_only_its_own_project_to_done():
    s = TransitionSession()
    assert client(s).close("UAR-1") is True and s.moved == ["61"]
    assert client(TransitionSession(status="done")).close("UAR-1") is False
    with pytest.raises(JiraError, match="outside project"):
        client(TransitionSession()).close("HR-1")


def test_info_findings_get_no_tickets(signed_review):
    """Info means "could not be checked", not "fix this"."""
    rem, session, run, s3 = signed_review
    before = len(session.issues)
    rows = [
        {"check_id": "AR-04", "title": "No MFA factor enrolled", "severity": "info",
         "subject": "a@acme.example", "detail": "MFA enrollment could not be read.", "remediation": "-"},
        {"check_id": "AR-13", "title": "Activity after the termination date", "severity": "info",
         "subject": "b@acme.example", "detail": "HR shows terminated with no end date.", "remediation": "-"},
    ]
    assert rem.open_findings(run.run_dir.name, "UAR-99", rows) == 0
    assert rem.open_urgent(run.run_dir.name, "UAR-99", rows) == 0
    assert len(session.issues) == before


def test_every_graph_backed_check_can_actually_open_a_ticket():
    """A check in REVIEW_CHECKS but in neither FIX_CHECKS nor URGENT_CHECKS
    never reaches ticket creation: the finding lands in the report and then
    vanishes, and its verify_mode is configuration nothing consults."""
    from access_review.checks import CHECKS
    from access_review.tickets import FIX_CHECKS
    from access_review.workflow import URGENT_CHECKS

    graph_checks = [c.id for c in CHECKS if c.needs_graph]
    assert graph_checks, "expected at least one graph-backed check"
    for check_id in graph_checks:
        assert check_id in FIX_CHECKS or check_id in URGENT_CHECKS, (
            f"{check_id} findings would never reach open_findings or open_urgent"
        )


@pytest.fixture
def graph_review(tmp_path):
    """A review that read GitHub too, so AR-15..AR-17 actually have findings."""
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                     date(2026, 9, 15), tmp_path / "out", require_items=True,
                     github_path=FIXTURES / "demo_github.json")
    s3 = FakeS3()
    store.upload_run(s3, "evidence", run.run_dir)
    session = FakeJiraSession()
    rem = Remediation(client(session), s3, "evidence", "Task", "Subtask", now=lambda: NOW)
    return rem, session, run, s3


def test_cross_source_findings_get_remediation_tickets(graph_review):
    rem, session, run, s3 = graph_review
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    rows = workflow.all_findings(deps, run.run_dir.name)
    assert {"AR-15", "AR-16", "AR-17"} <= {r["check_id"] for r in rows}

    rem.open_findings(run.run_dir.name, "UAR-99", rows)
    records = [r for _, r in store.list_records(s3, "evidence", run.run_dir.name, "tickets")]
    opened = {r["check_id"] for r in records if r["kind"] == "finding"}
    assert {"AR-15", "AR-16", "AR-17"} <= opened
    # Every one of them takes the reviewer's word: nothing can re-verify a
    # GitHub finding against a fresh Okta snapshot.
    assert {r["verify"] for r in records if r["check_id"] in ("AR-15", "AR-16", "AR-17")} == {"reviewer"}
    # The subject is the source's own id; the readable login is in the body.
    victor = next(f for f in session.issues.values()
                  if "github:acme-eng/U_kgDOBq1cZy" in f["summary"])
    assert "victor-nguyen" in json.dumps(victor["description"])


def test_a_revoke_ticket_does_not_claim_to_settle_access_outside_okta(graph_review):
    """The ticket closes when the daily check re-reads Okta, and Okta cannot see
    whether a GitHub owner role is gone. marcus.lee's AR-17 concern is on every
    one of his items, so it used to be copied into every one of his revoke
    tickets as a plain "Concern:" -- each of them then closed as verified over a
    credential nothing re-read. It is still named, under its own heading, as work
    this ticket does not cover."""
    rem, session, run, _ = graph_review
    items = {i.key: i for i in run.items}
    mine = {k: i for k, i in items.items() if i.user.startswith("marcus.lee")}
    assert any(i.outside_okta for i in mine.values()), "no cross-source concern to scope"
    rem.open_revokes(run.run_dir.name, "UAR-99", items,
                     {k: {"decision": REVOKE, "reason": ""} for k in mine})
    tickets = [f["description"] for f in session.issues.values()
               if f["summary"].endswith("for marcus.lee@acme.example")]
    assert tickets, "marcus.lee got no revoke ticket"
    for description in tickets:
        lines = _paragraphs(description)
        assert any("AR-17" in ln for ln in lines), "the reviewer's evidence must not be dropped"
        # Not as a "Concern:", which is the list this ticket's Okta re-check settles.
        assert not [ln for ln in lines if ln.startswith("Concern: ") and "AR-17" in ln], lines
        assert [ln for ln in lines if ln.startswith("Still open: ") and "AR-17" in ln], lines
        assert any(ln.startswith("Not part of this ticket") for ln in lines), lines
        # The closing promise still stands, because it now covers only the Okta change.
        assert any("the next daily check confirms it in Okta" in ln for ln in lines)



def test_an_okta_only_review_says_it_never_looked_elsewhere(signed_review):
    """No graph, so the review has nothing to say about other sources -- which is
    not the same as saying there is nothing there. Silence would let the assignee
    read an Okta-only ticket as the whole picture."""
    rem, session, run, _ = signed_review
    items = {i.key: i for i in run.items}
    rem.open_revokes(run.run_dir.name, "UAR-99", items,
                     {k: {"decision": REVOKE, "reason": ""} for k, i in items.items()
                      if i.proposed == REVOKE})
    lines = [ln for f in session.issues.values() for ln in _paragraphs(f["description"])]
    assert lines
    assert any(ln.startswith("Not part of this ticket") for ln in lines)
    assert any(ln.startswith("Not known: ") and "No source other than Okta" in ln for ln in lines)
    # And nothing is listed as held, because nothing was read.
    assert not [ln for ln in lines if ln.startswith("Still open: ")]


def test_everything_named_as_out_of_scope_really_does_get_its_own_ticket(graph_review):
    """The scoping paragraph tells the assignee the finding is tracked elsewhere.
    If it is not, the review has moved a real problem off one ticket and onto no
    ticket, which is worse than the overclaim it replaced. Proved end to end
    against the run's own items rather than from the check tables, because
    open_findings also drops anything at INFO severity."""
    rem, session, run, s3 = graph_review
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    named = {c.split("(")[-1].split()[0]
             for i in run.items for c in i.outside_okta}
    assert named, "no item names anything this decision cannot settle, so this proves nothing"
    rem.open_findings(run.run_dir.name, "UAR-99", workflow.all_findings(deps, run.run_dir.name))
    ticketed = {r["check_id"] for _, r in store.list_records(s3, "evidence", run.run_dir.name, "tickets")
                if r["kind"] == "finding"}
    assert named <= ticketed, f"named as tracked elsewhere but never ticketed: {named - ticketed}"


def test_a_leaver_ticket_does_not_promise_to_close_a_way_in_it_cannot_see(graph_review):
    """The headline ticket for a departure, due in 24 hours, asking to remove
    "every way in". It closes when `watch.still_present` re-runs
    LEAVER_ACCESS_CHECKS against a fresh Okta snapshot -- all Okta. Every person
    AR-17 fires on also gets one of these, so the overclaim the revoke ticket
    carried was sitting in the more prominent ticket too, for the same people."""
    rem, session, run, s3 = graph_review
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=None,
                         reviewers=Reviewers("U0CISO00001"), channel="C0X00000001")
    outside = outside_okta_by_login(run.items)
    assert any(held for held, _ in outside.values()), "nothing held elsewhere to scope"
    rem.open_urgent(run.run_dir.name, "UAR-99", workflow.urgent_findings(deps, run.run_dir.name),
                    workflow.people(deps, run.run_dir.name), outside)
    marcus = next(f for f in session.issues.values()
                  if f["summary"] == "Remove access for leaver marcus.lee@acme.example")
    lines = _paragraphs(marcus["description"])
    assert [ln for ln in lines if ln.startswith("Still open: ") and "AR-17" in ln], lines
    assert any(ln.startswith("Not part of this ticket") for ln in lines), lines
    # The to-do recorded as evidence says Okta, because Okta is what gets checked.
    record = next(r for _, r in store.list_records(s3, "evidence", run.run_dir.name, "tickets")
                  if r.get("subject") == "marcus.lee@acme.example")
    assert "every way in through Okta" in record["todo"]
    assert record["outside_okta"], record


def test_a_graph_check_settles_through_its_own_fix_ticket_not_a_leaver_ticket():
    """`outside_okta` says each finding has its own ticket under the same parent,
    and only FIX_CHECKS produces one of those. A graph check in URGENT_CHECKS
    alone would not: urgent tickets are one per leaver keyed by Okta login, while
    a graph finding's subject is source/principal.id, so the finding would be
    folded into a ticket that never names it and that closes on an Okta re-read.
    """
    from access_review.checks import GRAPH_CHECKS
    from access_review.tickets import FIX_CHECKS

    assert GRAPH_CHECKS, "expected at least one graph-backed check"
    assert set(GRAPH_CHECKS) <= set(FIX_CHECKS), (
        f"{set(GRAPH_CHECKS) - set(FIX_CHECKS)} can reach a review item's outside_okta "
        f"but would get no fix ticket of its own"
    )


def test_cross_source_checks_settle_by_reviewer_until_their_sources_can_be_reverified():
    """watch.still_present re-verifies a finding against a fresh Okta snapshot
    and gates on snapshot.gaps. It cannot see a graph source's gaps, so a
    GitHub finding would be ticked off because the GitHub read failed -- the
    silence-is-absence bug. Until still_present takes the graph, every
    graph-backed check must settle by reviewer instead.

    If you remove one of these from REVIEW_CHECKS, widen still_present first.
    """
    from access_review.checks import CHECKS
    from access_review.tickets import verify_mode

    graph_checks = [c.id for c in CHECKS if c.needs_graph]
    assert graph_checks, "expected at least one graph-backed check"
    assert all(verify_mode(check_id) == "reviewer" for check_id in graph_checks)
