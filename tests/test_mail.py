import hashlib
import json
import smtplib
from pathlib import Path

import pytest

from access_review import cli
from access_review.checks import ReviewContext, run_checks
from access_review.mail import EmailConfigError, EmailSettings, build_message, send

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]
ENV = {
    "REPORT_EMAIL_TO": "ciso@acme.example, auditor@acme.example",
    "REPORT_EMAIL_FROM": "Access Review <review@acme.example>",
    "SMTP_HOST": "smtp.test",
    "SMTP_USERNAME": "apikey",
    "SMTP_PASSWORD": "s3cret",
}


def settings(**overrides):
    return EmailSettings.from_env({**ENV, **overrides})


class FakeSMTP:
    instances = []

    def __init__(self, host, port, context=None, timeout=None, starttls=True):
        self.host, self.port, self.context = host, port, context
        self.calls = []
        self.offers_starttls = starttls
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.offers_starttls

    def starttls(self, context):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        self.calls.append(("send", msg))


@pytest.fixture(autouse=True)
def reset_fake():
    FakeSMTP.instances = []


# --- settings ---

def test_email_off_when_no_recipient():
    assert EmailSettings.from_env({}) is None
    assert EmailSettings.from_env({"REPORT_EMAIL_TO": "  "}) is None


def test_settings_parse_recipients_and_default_port():
    s = settings()
    assert s.recipients == ["ciso@acme.example", "auditor@acme.example"]
    assert s.port == 587


def test_missing_settings_are_named():
    with pytest.raises(EmailConfigError, match="SMTP_HOST, SMTP_PASSWORD"):
        EmailSettings.from_env({"REPORT_EMAIL_TO": "a@b.test", "SMTP_USERNAME": "u", "REPORT_EMAIL_FROM": "c@d.test"})


def test_plaintext_port_refused():
    with pytest.raises(EmailConfigError, match="587"):
        settings(SMTP_PORT="25")


@pytest.mark.parametrize("bad", ["not-an-address", "a@b.test\nBcc: evil@x.test"])
def test_bad_or_injected_addresses_refused(bad):
    with pytest.raises(EmailConfigError):
        settings(REPORT_EMAIL_TO=bad)


# --- message ---

@pytest.fixture
def demo_run(tmp_path):
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path), "--no-email"]) == 0
    [run_dir] = list(tmp_path.iterdir())
    snapshot = cli.Snapshot.from_dict(json.loads((run_dir / "snapshot.json").read_text()))
    config = cli.Config.load(FIXTURES / "demo_config.json")
    findings, _ = run_checks(
        ReviewContext(snapshot, cli.load_roster(FIXTURES / "demo_roster.csv", config.timezone()),
                          config, cli.date(2026, 9, 15))
    )
    return run_dir, snapshot, findings


def test_message_has_summary_and_pdf_but_no_personal_data(demo_run):
    run_dir, snapshot, findings = demo_run
    msg = build_message(settings(), snapshot, findings, run_dir)
    assert msg["Subject"] == "Okta access review (complete): 3 critical, acme-demo.okta.com"
    assert msg["To"] == "ciso@acme.example, auditor@acme.example"
    body = msg.get_body(("plain",)).get_content()
    assert "critical 3" in body and "total    16" in body
    for user in snapshot.users:
        assert user.login not in body
        assert user.profile["lastName"] not in body
    [attachment] = list(msg.iter_attachments())
    assert attachment.get_content_type() == "application/pdf"
    assert attachment.get_filename() == f"okta-access-review-{run_dir.name}.pdf"
    pdf = attachment.get_content()
    assert pdf.startswith(b"%PDF")
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["files"]["report.pdf"] == hashlib.sha256(pdf).hexdigest()
    assert manifest["files"]["report.pdf"] in body


def test_repeat_findings_line_is_counts_only(demo_run):
    run_dir, snapshot, findings = demo_run
    assert "Open since the last review" not in build_message(settings(), snapshot, findings, run_dir).get_body(
        ("plain",)).get_content()  # no history, no line
    for f in findings:
        f.reviews_open, f.first_seen = 1, "2026-09-15"
    findings[0].reviews_open, findings[0].first_seen = 3, "2026-03-15"
    body = build_message(settings(), snapshot, findings, run_dir).get_body(("plain",)).get_content()
    assert "Open since the last review: 1 of 16 (longest: 3 reviews in a row)" in body
    for user in snapshot.users:
        assert user.login not in body


def test_incomplete_review_says_so(demo_run):
    run_dir, snapshot, findings = demo_run
    snapshot.gaps = ["Could not read admin role assignments"]
    msg = build_message(settings(), snapshot, findings, run_dir)
    assert "(INCOMPLETE)" in msg["Subject"]
    assert "1 data gap(s)" in msg.get_body(("plain",)).get_content()


def test_no_findings_subject(demo_run):
    run_dir, snapshot, _ = demo_run
    assert "no findings" in build_message(settings(), snapshot, [], run_dir)["Subject"]


# --- sending ---

def test_send_uses_starttls_before_login(demo_run):
    run_dir, snapshot, findings = demo_run
    s = settings()
    send(s, build_message(s, snapshot, findings, run_dir), smtp=FakeSMTP)
    [server] = FakeSMTP.instances
    assert (server.host, server.port) == ("smtp.test", 587)
    names = [c if isinstance(c, str) else c[0] for c in server.calls]
    assert names == ["ehlo", "starttls", "ehlo", "login", "send", "quit"]
    assert server.calls[3] == ("login", "apikey", "s3cret")


def test_send_uses_implicit_tls_on_465(demo_run):
    run_dir, snapshot, findings = demo_run
    s = settings(SMTP_PORT="465")
    send(s, build_message(s, snapshot, findings, run_dir), smtp_ssl=FakeSMTP)
    [server] = FakeSMTP.instances
    assert server.port == 465 and server.context is not None
    assert "starttls" not in server.calls


def test_send_refuses_server_without_starttls(demo_run):
    run_dir, snapshot, findings = demo_run
    s = settings()

    def no_tls(*args, **kwargs):
        return FakeSMTP(*args, **kwargs, starttls=False)

    with pytest.raises(smtplib.SMTPNotSupportedError):
        send(s, build_message(s, snapshot, findings, run_dir), smtp=no_tls)
    assert not any(isinstance(c, tuple) and c[0] == "login" for c in FakeSMTP.instances[0].calls)


# --- CLI ---

def test_cli_emails_at_end_of_run(tmp_path, monkeypatch, capsys):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    sent = []
    monkeypatch.setattr(cli, "send", lambda s, msg: sent.append(msg))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    assert len(sent) == 1
    assert "Emailed report.pdf to ciso@acme.example, auditor@acme.example" in capsys.readouterr().out


def test_cli_no_email_flag(tmp_path, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(cli, "send", lambda s, msg: pytest.fail("should not send"))
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path), "--no-email"]) == 0


def test_cli_email_failure_keeps_report_and_exits_3(tmp_path, monkeypatch, capsys):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    def boom(s, msg):
        raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    monkeypatch.setattr(cli, "send", boom)
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 3
    assert "report saved, but emailing it failed" in capsys.readouterr().err
    [run_dir] = list(tmp_path.iterdir())
    assert (run_dir / "report.pdf").exists()


def test_cli_bad_email_config_fails_before_collecting(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_EMAIL_TO", "someone@acme.example")
    for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "REPORT_EMAIL_FROM"):
        monkeypatch.delenv(k, raising=False)
    assert cli.main(DEMO_ARGS + ["--out", str(tmp_path)]) == 1
    assert not tmp_path.exists() or not any(tmp_path.iterdir())
