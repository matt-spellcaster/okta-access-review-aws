import re
import sys
from pathlib import Path

import pytest
from fakes import FakeClientError
from test_okta import FakeResponse, FakeSession, keypair  # noqa: F401 (fixture)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import okta_auth_check  # noqa: E402

ORG = "https://example.okta.com"


class Ssm:
    def __init__(self, value):
        self.value = value

    def get_parameter(self, Name, WithDecryption):
        if self.value is None:
            raise FakeClientError("ParameterNotFound")
        return {"Parameter": {"Value": self.value}}


@pytest.fixture
def env(monkeypatch, keypair):
    monkeypatch.setenv("OKTA_ORG_URL", ORG)
    monkeypatch.setenv("OKTA_CLIENT_ID", "0oaSECRETCLIENT")
    monkeypatch.setenv("OKTA_KEY_ID", "kid-secret-1")
    monkeypatch.setenv("OKTA_PRIVATE_KEY_PARAM", "/uar/okta/private_key")
    return keypair[0]


def test_passes_and_prints_only_statuses(env, capsys):
    session = FakeSession({"/oauth2/v1/clients/0oaSECRETCLIENT/roles": FakeResponse({}, status=404)})
    assert okta_auth_check.main(Ssm(env), session) == 0
    out = capsys.readouterr().out
    assert out.count("PASS") == 8
    for value in ("0oaSECRETCLIENT", "kid-secret-1", "example.okta.com", "PRIVATE KEY"):
        assert value not in out
    assert not re.search(r"\btok\b", out)  # the fake access token
    # Read-only: the only POST is the token request.
    assert all(url.endswith("/oauth2/v1/token") for url, _ in session.posts)


def test_a_forbidden_api_fails_the_check(env, capsys):
    session = FakeSession({"/api/v1/logs": FakeResponse({"errorSummary": "nope"}, status=403)})
    assert okta_auth_check.main(Ssm(env), session) == 1
    assert "FAIL System Log (okta.logs.read): HTTP 403" in capsys.readouterr().out


def test_a_missing_key_fails_without_calling_okta(env, capsys):
    session = FakeSession({})
    assert okta_auth_check.main(Ssm(None), session) == 1
    assert "FAIL settings" in capsys.readouterr().out and session.posts == []
