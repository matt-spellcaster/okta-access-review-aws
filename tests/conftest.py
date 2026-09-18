import pytest


@pytest.fixture(autouse=True)
def no_real_services(monkeypatch):
    """Never send real email, Slack messages or Jira tickets, or reach AWS, from
    tests, even if the shell has settings for them."""
    monkeypatch.delenv("REPORT_EMAIL_TO", raising=False)
    for name in ("SLACK_WEBHOOK_URL", "SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID", "SLACK_ATTACH_PDF",
                 "SLACK_SIGNING_SECRET", "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN",
                 "AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    # If anything did build a real AWS client, it gets credentials that can't
    # sign a working request and an endpoint that doesn't exist.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
