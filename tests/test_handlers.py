import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fakes import FakeBot, FakeClientError, FakeS3, FakeSfn
from test_watch import FakeJira

from access_review import settings
from access_review.aws import handlers
from access_review.models import Snapshot
from access_review.settings import Settings, SettingsError, get_secret

FIXTURES = Path(__file__).parent.parent / "fixtures"
ENV = {
    "EVIDENCE_BUCKET": "uar-evidence-test", "WORK_BUCKET": "uar-work-test",
    "SLACK_CHANNEL_ID": "C0REVIEW001", "SLACK_CISO_USER": "U0CISO00001",
    "OKTA_ORG_URL": "https://acme-demo.okta.com", "OKTA_CLIENT_ID": "0oaREVIEW", "OKTA_KEY_ID": "kid1",
    "OKTA_PRIVATE_KEY_PARAM": "/uar/okta/private_key", "SLACK_BOT_TOKEN_PARAM": "/uar/slack/bot_token",
    "SLACK_SIGNING_SECRET_PARAM": "/uar/slack/signing_secret", "JIRA_API_TOKEN_PARAM": "/uar/jira/api_token",
    "JIRA_BASE_URL": "https://acme.atlassian.net", "JIRA_EMAIL": "svc-uar@acme.example", "JIRA_PROJECT": "UAR",
    "WORKER_FUNCTION": "uar-worker",
}


class FakeSSM:
    def __init__(self, values):
        self.values = values

    def get_parameter(self, Name, WithDecryption):
        assert WithDecryption
        if Name not in self.values:
            raise FakeClientError("ParameterNotFound")
        return {"Parameter": {"Value": self.values[Name]}}


def test_parameter_names_outside_uar_are_refused_without_echo(monkeypatch):
    monkeypatch.setenv("X_PARAM", "arn:aws:ssm:us-east-1:111:parameter/prod/db-password")
    with pytest.raises(SettingsError) as e:
        get_secret(FakeSSM({}), "X_PARAM")
    assert "db-password" not in str(e.value)
    monkeypatch.setenv("X_PARAM", "/uar/missing")
    with pytest.raises(SettingsError, match="ParameterNotFound"):
        get_secret(FakeSSM({}), "X_PARAM")
    monkeypatch.setenv("X_PARAM", "/uar/unset")
    with pytest.raises(SettingsError, match="no value yet"):
        get_secret(FakeSSM({"/uar/unset": "placeholder"}), "X_PARAM")


def test_the_reviewer_must_be_a_member_id_not_a_dm(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    assert Settings.from_env().reviewers.ciso == "U0CISO00001"
    monkeypatch.setenv("SLACK_CISO_USER", "D0DMCHANNEL1")  # the mistake made during setup
    with pytest.raises(SettingsError, match="member ID"):
        Settings.from_env()


@pytest.fixture
def aws(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for fn in (handlers._settings, handlers._client, handlers._secret, handlers._items):
        fn.cache_clear()
    s3, sfn, bot, jira = FakeS3(), FakeSfn(), FakeBot(), FakeJira()
    jira.today = "2026-09-16"
    clients = {"s3": s3, "stepfunctions": sfn}
    monkeypatch.setattr(handlers, "_client", lambda name: clients[name])
    monkeypatch.setattr(handlers, "_secret", lambda name: "secret-" + name)
    monkeypatch.setattr(handlers, "BotClient", lambda token: bot)
    monkeypatch.setattr(handlers, "_jira", lambda: jira)
    monkeypatch.setattr(handlers, "JiraClient", None)
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    monkeypatch.setattr(handlers, "collect_okta", lambda *a, **kw: snapshot)
    monkeypatch.setattr(handlers, "_okta", lambda: None)
    config = json.loads((FIXTURES / "demo_config.json").read_text())
    s3.objects[("uar-work-test", "inputs/config.json")] = json.dumps(config).encode()
    s3.objects[("uar-work-test", "inputs/roster.csv")] = (FIXTURES / "demo_roster.csv").read_bytes()
    monkeypatch.setattr(handlers, "_deps", _deps_with(handlers._deps, jira))
    return s3, sfn, bot, jira


def _deps_with(real, jira):
    def deps(tickets=False, sfn=False):
        d = real(tickets=False, sfn=sfn)
        if tickets:
            from access_review.tickets import Remediation
            d.tickets = Remediation(jira, d.s3, d.evidence_bucket, "Task", "Subtask",
                                    now=lambda: datetime(2026, 9, 16, 9, tzinfo=timezone.utc))
        return d
    return deps


def no_personal_data(output):
    text = json.dumps(output)
    assert "@" not in text and "acme.example" not in text and "Salesforce" not in text, text


def test_step_functions_only_ever_see_ids_hashes_and_counts(aws):
    s3, sfn, bot, jira = aws
    out = handlers.collect({}, None)
    no_personal_data(out)
    # Complete although the register declares a GitHub account: this pipeline
    # reads Okta only, so that estate is out of scope rather than a gap. A gap
    # here would mark every AWS review incomplete, for good.
    assert out["items"]["total"] == 17 and out["complete"] is True
    assert ("uar-evidence-test", f"runs/{out['run']}/review_items.json") in s3.objects

    opened = handlers.open_review({"run": out["run"], "task_token": "tok"}, None)
    no_personal_data(opened)
    assert opened["urgent_tickets"] == 2


def test_settings_module_has_no_default_secret_values():
    source = Path(settings.__file__).read_text()
    assert "xoxb-" not in source and "ATATT" not in source
