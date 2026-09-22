import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

from access_review import cli, slack
from access_review.checks import ReviewContext, run_checks
from access_review.models import Snapshot

FIXTURES = Path(__file__).parent.parent / "fixtures"
URL = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]


class FakeResponse:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append((url, json))
        if self.error:
            raise self.error
        return self.response


@pytest.fixture
def demo_run(tmp_path):
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path), "--no-email", "--no-slack"]) == 0
    [run_dir] = list(tmp_path.iterdir())
    snapshot = Snapshot.from_dict(json.loads((run_dir / "snapshot.json").read_text()))
    config = cli.Config.load(FIXTURES / "demo_config.json")
    findings, _ = run_checks(ReviewContext(
        snapshot, cli.load_roster(FIXTURES / "demo_roster.csv", config.timezone()),
        config, cli.date(2026, 9, 15),
    ))
    return run_dir, snapshot, findings


def all_text(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


# --- settings ---

def test_slack_off_when_unset():
    assert slack.webhook_from_env({}) is None
    assert slack.webhook_from_env({"SLACK_WEBHOOK_URL": " "}) is None


def test_accepts_slack_webhook():
    assert slack.webhook_from_env({"SLACK_WEBHOOK_URL": URL}) == URL
    gov = "https://hooks.slack-gov.com/services/T/B/X"
    assert slack.webhook_from_env({"SLACK_WEBHOOK_URL": gov}) == gov


@pytest.mark.parametrize("bad", [
    "http://hooks.slack.com/services/T/B/X",  # not https
    "https://evil.example/services/T/B/X",  # wrong host
    "https://hooks.slack.com.evil.example/services/T/B/X",  # lookalike host
    "https://hooks.slack.com/workflows/T/B/X",  # not an incoming webhook
    "xoxb-this-is-a-bot-token",  # wrong kind of secret
])
def test_rejects_non_webhook_urls_without_echoing_them(bad):
    with pytest.raises(slack.SlackConfigError) as e:
        slack.webhook_from_env({"SLACK_WEBHOOK_URL": bad})
    assert bad not in str(e.value)


# --- payload ---

def blocks_of(payload: dict) -> list[dict]:
    return payload["attachments"][0]["blocks"]


def test_payload_has_summary_and_no_personal_data(demo_run):
    run_dir, snapshot, findings = demo_run
    payload = slack.build_payload(snapshot, findings, run_dir, brand="Acme")
    assert payload["text"] == "Acme · Okta access review (complete): 4 critical, acme-demo.okta.com"
    text = all_text(payload)
    assert "*Critical*   4" in text and "*High*   4" in text and "*16* total" in text
    assert run_dir.name in text
    for user in snapshot.users:
        assert user.login not in text
        assert user.profile["lastName"] not in text
    for app in snapshot.apps:
        assert app.label not in text


def test_repeat_findings_line_is_counts_only(demo_run):
    run_dir, snapshot, findings = demo_run
    assert "Open since the last review" not in all_text(slack.build_payload(snapshot, findings, run_dir))
    for f in findings:
        f.reviews_open, f.first_seen = 2, "2026-06-15"
    text = all_text(slack.build_payload(snapshot, findings, run_dir))
    assert ":hourglass: Open since the last review: 16 of 16 (longest: 2 reviews in a row)" in text
    for user in snapshot.users:
        assert user.login not in text
    for app in snapshot.apps:
        assert app.label not in text


def test_attention_list_groups_by_check_worst_first(demo_run):
    run_dir, snapshot, findings = demo_run
    [attention] = [b for b in blocks_of(slack.build_payload(snapshot, findings, run_dir))
                   if b.get("text", {}).get("text", "").startswith("*What needs attention*")]
    lines = attention["text"]["text"].splitlines()[1:]
    assert len(lines) == 14  # one per check that fired
    assert lines[0] == ":red_circle:  `AR-01`  Terminated in HR but account still live"
    assert lines[-1] == ":large_blue_circle:  `AR-11`  Admin user  ×2"


def test_side_bar_color_follows_worst_severity(demo_run):
    run_dir, snapshot, findings = demo_run
    assert slack.build_payload(snapshot, findings, run_dir)["attachments"][0]["color"] == "#B42318"
    medium_only = [f for f in findings if f.severity == "medium"]
    assert slack.build_payload(snapshot, medium_only, run_dir)["attachments"][0]["color"] == "#F79009"
    assert slack.build_payload(snapshot, [], run_dir)["attachments"][0]["color"] == slack.CLEAN_BAR


def test_zero_severity_rows_are_dimmed(demo_run):
    run_dir, snapshot, findings = demo_run
    no_low = [f for f in findings if f.severity != "low"]
    text = all_text(slack.build_payload(snapshot, no_low, run_dir))
    assert ":white_circle: Low   –" in text


def test_collected_time_is_localized_for_each_reader(demo_run):
    run_dir, snapshot, findings = demo_run
    text = all_text(slack.build_payload(snapshot, findings, run_dir))
    epoch = int(snapshot.collected_at.timestamp())
    assert f"<!date^{epoch}^{{date_short_pretty}} at {{time}}|2026-09-15 14:00 UTC>" in text


def test_payload_is_valid_block_kit_shape(demo_run):
    run_dir, snapshot, findings = demo_run
    payload = slack.build_payload(snapshot, findings, run_dir, brand="Acme")
    blocks = blocks_of(payload)
    assert blocks[0]["type"] == "header"
    assert len(blocks[0]["text"]["text"]) <= 150  # Slack header limit
    assert len(blocks) <= 50
    for block in blocks:
        assert block["type"] in {"header", "section", "context", "divider"}
        if "text" in block and block["type"] == "section":
            assert len(block["text"]["text"]) <= 3000
        for field in block.get("fields", []):
            assert field["type"] == "mrkdwn" and len(field["text"]) <= 2000
        assert len(block.get("fields", [])) <= 10
    assert payload["attachments"][0]["color"].startswith("#")


def test_no_findings_message(demo_run):
    run_dir, snapshot, _ = demo_run
    payload = slack.build_payload(snapshot, [], run_dir)
    text = all_text(payload)
    assert "No findings." in text and "What needs attention" not in text
    assert "no findings" in payload["text"]


def test_incomplete_review_is_flagged(demo_run):
    run_dir, snapshot, findings = demo_run
    snapshot.gaps = ["a", "b"]
    payload = slack.build_payload(snapshot, findings, run_dir)
    assert "(INCOMPLETE)" in payload["text"]
    text = all_text(payload)
    assert "*Incomplete*: 2 data gap(s)" in text
    assert "may miss issues" in text


# --- posting ---

def test_post_sends_json():
    session = FakeSession()
    slack.post(URL, {"text": "hi"}, session=session)
    assert session.calls == [(URL, {"text": "hi"})]


def test_post_reports_slack_error_code():
    session = FakeSession(FakeResponse(404, "no_service"))
    with pytest.raises(slack.SlackError, match="HTTP 404: no_service"):
        slack.post(URL, {"text": "hi"}, session=session)


def test_network_error_does_not_leak_url():
    err = requests.ConnectionError(f"Max retries exceeded with url: {URL}")
    with pytest.raises(slack.SlackError) as e:
        slack.post(URL, {"text": "hi"}, session=FakeSession(error=err))
    assert "SECRET" not in str(e.value) and "hooks.slack.com" not in str(e.value)
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_post_over_real_http():
    """End to end through requests against a local server standing in for Slack."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers["Content-Type"], json.loads(body)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    try:
        slack.post(f"http://127.0.0.1:{server.server_port}/services/T/B/X", {"text": "hello"})
    finally:
        thread.join(5)
        server.server_close()
    assert received == [("/services/T/B/X", "application/json", {"text": "hello"})]


# --- CLI ---

def test_cli_posts_at_end_of_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)
    posted = []
    monkeypatch.setattr(slack, "post", lambda url, payload, session=None: posted.append((url, payload)))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    assert len(posted) == 1 and posted[0][0] == URL
    out = capsys.readouterr().out
    assert "Posted summary to Slack" in out
    assert URL not in out


def test_cli_no_slack_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)
    monkeypatch.setattr(slack, "post", lambda url, payload, session=None: pytest.fail("should not post"))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path), "--no-slack"]) == 0


def test_cli_bad_webhook_fails_before_running(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 1
    assert "Slack settings" in capsys.readouterr().err
    assert not any(tmp_path.iterdir())


def test_email_failure_still_posts_to_slack_and_exits_3(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)
    for k, v in {
        "REPORT_EMAIL_TO": "ciso@acme.example", "REPORT_EMAIL_FROM": "r@acme.example",
        "SMTP_HOST": "smtp.test", "SMTP_USERNAME": "u", "SMTP_PASSWORD": "p",
    }.items():
        monkeypatch.setenv(k, v)

    def broken_send(settings, msg):
        raise OSError("connection refused")

    posted = []
    monkeypatch.setattr(cli, "send", broken_send)
    monkeypatch.setattr(slack, "post", lambda url, payload, session=None: posted.append(payload))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 3
    assert len(posted) == 1
    assert "emailing it failed" in capsys.readouterr().err


def test_slack_failure_exits_3(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)

    def fail(url, payload, session=None):
        raise slack.SlackError("Slack returned HTTP 410: channel_is_archived")

    monkeypatch.setattr(slack, "post", fail)
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 3
    err = capsys.readouterr().err
    assert "channel_is_archived" in err and URL not in err


def test_slack_never_announces_complete_for_a_run_whose_manifest_says_otherwise(tmp_path):
    """The channel post, the email and the CLI line all derived completeness
    from snapshot.gaps, which speaks for Okta alone. A run whose GitHub source
    failed was announced as Complete while the report, PDF and manifest it
    links to said INCOMPLETE."""
    from access_review.mail import EmailSettings, build_message
    from access_review.report import run_dir_name
    from access_review.review import run_review

    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = cli.Config.load(FIXTURES / "demo_config.json")
    roster = cli.load_roster(FIXTURES / "demo_roster.csv", config.timezone())
    run = run_review(snapshot, roster, FIXTURES / "demo_roster.csv", config,
                     cli.date(2026, 9, 15), tmp_path, github_path=FIXTURES / "demo_github.json")
    manifest = json.loads((run.run_dir / "manifest.json").read_text())

    assert snapshot.gaps == []  # Okta alone would call this complete
    assert manifest["complete"] is False and run.complete is False
    assert run_dir_name(snapshot) == run.run_dir.name

    payload = slack.build_payload(snapshot, run.findings, run.run_dir, gaps=run.gaps)
    text = json.dumps(payload)
    assert "Incomplete" in text and "4 data gap(s)" in text
    # Counts and completeness only: the gap strings name accounts.
    assert "omar-haddad" not in text and "acme-ci-bot" not in text

    settings = EmailSettings(host="h", port=25, username="", password="",
                             sender="a@b.c", recipients=["d@e.f"])
    msg = build_message(settings, snapshot, run.findings, run.run_dir, gaps=run.gaps)
    body = msg.get_body(("plain",)).get_content()
    assert "INCOMPLETE" in msg["Subject"] and "4 data gap(s)" in body
    assert "omar-haddad" not in body
