"""Bot-token mode: summary via chat.postMessage, PDF uploaded into its thread."""

import json
from pathlib import Path

import pytest
import requests

from access_review import cli, slack

FIXTURES = Path(__file__).parent.parent / "fixtures"
TOKEN = "xoxb-000-000-FAKETOKENVALUE"
CHANNEL = "C0123456789"
UPLOAD_URL = "https://files.slack.com/upload/v1/PRESIGNED-SECRET"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]


class Resp:
    def __init__(self, status=200, body=None, text="", headers=None):
        self.status_code = status
        self._body = body
        self.text = text
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSlack:
    """Plays the Slack Web API. Override entries in `responses` to simulate errors."""

    def __init__(self, upload_url=UPLOAD_URL):
        self.calls = []
        self.responses = {
            "chat.postMessage": Resp(body={"ok": True, "ts": "1726400000.000100"}),
            "files.getUploadURLExternal": Resp(body={"ok": True, "upload_url": upload_url, "file_id": "F123"}),
            "upload": Resp(text="OK - 9000"),
            "files.completeUploadExternal": Resp(body={"ok": True, "files": [{"id": "F123"}]}),
        }

    def request(self, method, url, timeout=None, headers=None, json=None, data=None, files=None):
        name = url.rsplit("/", 1)[-1] if url.startswith(slack.API) else "upload"
        self.calls.append({"name": name, "url": url, "headers": headers or {}, "json": json, "data": data,
                           "files": files})
        response = self.responses[name]
        if isinstance(response, Exception):
            raise response
        return response

    def call(self, name):
        return next(c for c in self.calls if c["name"] == name)


def bot_env(**overrides):
    return {"SLACK_BOT_TOKEN": TOKEN, "SLACK_CHANNEL_ID": CHANNEL, "SLACK_ATTACH_PDF": "true", **overrides}


@pytest.fixture
def run_dir(tmp_path):
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path), "--no-email", "--no-slack"]) == 0
    [d] = list(tmp_path.iterdir())
    return d


# --- settings ---

def test_bot_settings():
    s = slack.settings_from_env(bot_env())
    assert s.uses_bot and s.channel_id == CHANNEL and s.attach_pdf


def test_attach_defaults_off():
    assert slack.settings_from_env(bot_env(SLACK_ATTACH_PDF="")).attach_pdf is False


@pytest.mark.parametrize("env, message", [
    (bot_env(SLACK_BOT_TOKEN="xoxp-user-token"), "must be a bot token"),
    (bot_env(SLACK_CHANNEL_ID="#access-reviews"), "channel ID like C0123456789"),
    (bot_env(SLACK_CHANNEL_ID=""), "channel ID"),
    (bot_env(SLACK_ATTACH_PDF="maybe"), "true or false"),
    (bot_env(SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"), "not both"),
    ({"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X", "SLACK_ATTACH_PDF": "true"}, "needs a bot token"),
])
def test_bad_settings(env, message):
    with pytest.raises(slack.SlackConfigError, match=message) as e:
        slack.settings_from_env(env)
    assert "FAKETOKEN" not in str(e.value) and "xoxp-user-token" not in str(e.value)


def test_webhook_mode_still_works():
    s = slack.settings_from_env({"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X"})
    assert not s.uses_bot and not s.attach_pdf


# --- posting and uploading ---

def test_posts_summary_then_uploads_pdf_in_thread(run_dir):
    fake = FakeSlack()
    payload = {"text": "summary", "attachments": []}
    done = slack.notify(slack.settings_from_env(bot_env()), payload, run_dir, title="Acme · Okta access review",
                        session=fake)
    assert done == ["Posted summary to Slack", "Attached report.pdf in the Slack thread"]
    assert [c["name"] for c in fake.calls] == [
        "chat.postMessage", "files.getUploadURLExternal", "upload", "files.completeUploadExternal",
    ]

    post = fake.call("chat.postMessage")
    assert post["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert post["json"] == {"channel": CHANNEL, **payload}

    pdf = (run_dir / "report.pdf").read_bytes()
    reserve = fake.call("files.getUploadURLExternal")
    assert reserve["data"] == {"filename": f"okta-access-review-{run_dir.name}.pdf", "length": len(pdf)}

    upload = fake.call("upload")
    assert upload["url"] == UPLOAD_URL
    assert "Authorization" not in upload["headers"]  # the pre-signed URL is the credential
    name, data, content_type = upload["files"]["file"]
    assert data == pdf and content_type == "application/pdf"

    complete = fake.call("files.completeUploadExternal")["data"]
    assert json.loads(complete["files"]) == [{"id": "F123", "title": f"Acme · Okta access review ({run_dir.name})"}]
    assert complete["channel_id"] == CHANNEL
    assert complete["thread_ts"] == "1726400000.000100"
    assert "personal data" in complete["initial_comment"]


def test_no_upload_unless_opted_in(run_dir):
    fake = FakeSlack()
    done = slack.notify(slack.settings_from_env(bot_env(SLACK_ATTACH_PDF="false")), {"text": "x"}, run_dir,
                        session=fake)
    assert done == ["Posted summary to Slack"]
    assert [c["name"] for c in fake.calls] == ["chat.postMessage"]


@pytest.mark.parametrize("url", [
    "https://evil.example/upload",
    "http://files.slack.com/upload",
    "https://files.slack.com.evil.example/upload",
])
def test_refuses_to_upload_outside_slack(run_dir, url):
    fake = FakeSlack(upload_url=url)
    with pytest.raises(slack.SlackError, match="not on slack.com"):
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)
    assert "upload" not in [c["name"] for c in fake.calls]


@pytest.mark.parametrize("error, hint", [
    ({"ok": False, "error": "not_in_channel"}, "/invite"),
    ({"ok": False, "error": "missing_scope", "needed": "files:write"}, "add the files:write scope"),
    ({"ok": False, "error": "invalid_auth"}, "check the bot token"),
    ({"ok": False, "error": "channel_not_found"}, "check SLACK_CHANNEL_ID"),
])
def test_api_errors_have_helpful_hints(run_dir, error, hint):
    fake = FakeSlack()
    fake.responses["chat.postMessage"] = Resp(body=error)
    with pytest.raises(slack.SlackError, match=hint) as e:
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)
    assert error["error"] in str(e.value)


def test_upload_failure_after_post_is_reported(run_dir):
    fake = FakeSlack()
    fake.responses["files.completeUploadExternal"] = Resp(body={"ok": False, "error": "missing_scope",
                                                                  "needed": "files:write"})
    with pytest.raises(slack.SlackError, match="files.completeUploadExternal: missing_scope"):
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)


def test_errors_never_contain_token_or_upload_url(run_dir):
    fake = FakeSlack()
    fake.responses["upload"] = requests.ConnectionError(f"Max retries exceeded with url: {UPLOAD_URL}")
    with pytest.raises(slack.SlackError) as e:
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)
    message = str(e.value)
    assert "PRESIGNED" not in message and "FAKETOKEN" not in message
    assert e.value.__suppress_context__


def test_rate_limit_and_non_json_responses(run_dir):
    fake = FakeSlack()
    fake.responses["chat.postMessage"] = Resp(status=429, headers={"Retry-After": "30"})
    with pytest.raises(slack.SlackError, match="retry after 30s"):
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)
    fake = FakeSlack()
    fake.responses["chat.postMessage"] = Resp(status=502, text="<html>bad gateway</html>")
    with pytest.raises(slack.SlackError, match="HTTP 502, not a JSON response"):
        slack.notify(slack.settings_from_env(bot_env()), {"text": "x"}, run_dir, session=fake)


# --- CLI ---

def test_cli_bot_mode_end_to_end(tmp_path, monkeypatch, capsys):
    for k, v in bot_env().items():
        monkeypatch.setenv(k, v)
    fake = FakeSlack()
    real_notify = slack.notify
    monkeypatch.setattr(slack, "notify", lambda *a, **kw: real_notify(*a, **kw, session=fake))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Posted summary to Slack" in out and "Attached report.pdf in the Slack thread" in out
    assert TOKEN not in out
    post = fake.call("chat.postMessage")["json"]
    assert post["text"].startswith("Acme · Okta access review")
    title = json.loads(fake.call("files.completeUploadExternal")["data"]["files"])[0]["title"]
    assert title.startswith("Acme · Okta access review (")


def test_cli_bad_bot_settings_fail_before_running(tmp_path, monkeypatch, capsys):
    for k, v in bot_env(SLACK_CHANNEL_ID="access-reviews").items():
        monkeypatch.setenv(k, v)
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 1
    assert "channel ID" in capsys.readouterr().err
    assert not any(tmp_path.iterdir())
