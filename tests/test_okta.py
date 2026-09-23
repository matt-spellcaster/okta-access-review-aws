import base64
import hashlib
from datetime import date, datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from access_review.collect import collect
from access_review.models import Snapshot
from access_review.okta import OktaClient, OktaError

ORG = "https://example.okta.com"


class FakeResponse:
    def __init__(self, body, status=200, next_url=None, headers=None):
        self._body = body
        self.status_code = status
        self.links = {"next": {"url": next_url}} if next_url else {}
        self.headers = headers or {}
        self.text = str(body)

    def json(self):
        return self._body


class FakeSession:
    """Serves GET responses by URL; records every request.

    With token_type="DPoP" it behaves like Okta: the first token request and
    the first API request are rejected with a nonce challenge."""

    def __init__(self, routes, token_type="DPoP"):
        self.routes = routes
        self.token_type = token_type
        self.posts = []
        self.gets = []
        self.post_headers = []
        self.get_headers = []

    def post(self, url, data, headers, timeout):
        self.posts.append((url, data))
        self.post_headers.append(headers)
        if self.token_type == "DPoP" and len(self.posts) == 1:
            return FakeResponse({"error": "use_dpop_nonce"}, status=400, headers={"DPoP-Nonce": "token-nonce"})
        return FakeResponse({"access_token": "tok", "token_type": self.token_type, "expires_in": 3600})

    def get(self, url, params, headers, timeout):
        self.gets.append((url, params))
        self.get_headers.append(headers)
        if self.token_type == "DPoP" and len(self.gets) == 1:
            return FakeResponse(
                {}, status=401,
                headers={"DPoP-Nonce": "api-nonce", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'},
            )
        key = url.removeprefix(ORG)
        if params and "search" in params:
            key += "?deprovisioned"
        route = self.routes.get(key, [])
        return route if isinstance(route, FakeResponse) else FakeResponse(route)


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem.decode(), key.public_key()


def client(session, keypair):
    return OktaClient(
        ORG, "client123", "kid1", keypair[0], ["okta.users.read"],
        session=session, dpop=session.token_type == "DPoP",
    )


def verify_proof(proof):
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    key = jwt.PyJWK(header["jwk"]).key
    return header, jwt.decode(proof, key, algorithms=["ES256"])


def test_dpop_token_request_retries_with_nonce(keypair):
    session = FakeSession({"/api/v1/groups": []})
    client(session, keypair).access_token()
    assert len(session.posts) == 2
    _, first = verify_proof(session.post_headers[0]["DPoP"])
    _, second = verify_proof(session.post_headers[1]["DPoP"])
    assert first["htm"] == "POST" and first["htu"] == f"{ORG}/oauth2/v1/token"
    assert "nonce" not in first
    assert second["nonce"] == "token-nonce"
    # Each attempt uses a fresh client assertion (jti must not repeat).
    assert session.posts[0][1]["client_assertion"] != session.posts[1][1]["client_assertion"]


def test_dpop_api_request_binds_proof_to_token_and_url(keypair):
    session = FakeSession({"/api/v1/users": []})
    c = client(session, keypair)
    c.get_all("/api/v1/users", {"limit": 200})
    assert len(session.gets) == 2  # nonce challenge, then retry
    headers = session.get_headers[1]
    assert headers["Authorization"] == "DPoP tok"
    header, claims = verify_proof(headers["DPoP"])
    assert claims["htm"] == "GET"
    assert claims["htu"] == f"{ORG}/api/v1/users"
    assert claims["nonce"] == "api-nonce"
    assert claims["ath"] == base64.urlsafe_b64encode(hashlib.sha256(b"tok").digest()).rstrip(b"=").decode()
    # Token and API proofs are signed by the same per-run key.
    token_header, _ = verify_proof(session.post_headers[-1]["DPoP"])
    assert header["jwk"] == token_header["jwk"]
    assert "d" not in header["jwk"]  # public key only


def test_dpop_client_rejects_unbound_token(keypair):
    session = FakeSession({}, token_type="Bearer")
    c = OktaClient(ORG, "client123", "kid1", keypair[0], ["okta.users.read"], session=session, dpop=True)
    with pytest.raises(OktaError, match="DPoP"):
        c.access_token()


def test_bearer_mode_sends_no_dpop_header(keypair):
    session = FakeSession({"/api/v1/groups": []}, token_type="Bearer")
    client(session, keypair).get_all("/api/v1/groups")
    assert "DPoP" not in session.post_headers[0]
    assert session.get_headers[0]["Authorization"] == "Bearer tok"
    assert "DPoP" not in session.get_headers[0]


def test_client_assertion_is_signed_for_the_token_endpoint(keypair):
    c = client(FakeSession({}), keypair)
    token = c.client_assertion()
    assert jwt.get_unverified_header(token)["kid"] == "kid1"
    claims = jwt.decode(token, keypair[1], algorithms=["RS256"], audience=f"{ORG}/oauth2/v1/token")
    assert claims["iss"] == claims["sub"] == "client123"


def test_token_is_cached(keypair):
    session = FakeSession({"/api/v1/groups": []}, token_type="Bearer")
    c = client(session, keypair)
    c.get_all("/api/v1/groups")
    c.get_all("/api/v1/groups")
    assert len(session.posts) == 1
    assert session.posts[0][1]["scope"] == "okta.users.read"


def test_follows_next_links(keypair):
    session = FakeSession({
        "/api/v1/users": FakeResponse([{"n": 1}], next_url=f"{ORG}/api/v1/users/page2"),
        "/api/v1/users/page2": [{"n": 2}],
    }, token_type="Bearer")
    assert client(session, keypair).get_all("/api/v1/users", {"limit": 200}) == [{"n": 1}, {"n": 2}]
    assert session.gets[1][1] is None  # query not re-sent on next link


def test_raises_okta_error_with_summary(keypair):
    session = FakeSession({"/api/v1/users": FakeResponse({"errorSummary": "nope"}, status=403)})
    with pytest.raises(OktaError, match="403.*nope"):
        client(session, keypair).get_all("/api/v1/users")


def _user(uid, status, **profile):
    return {"id": uid, "status": status, "created": "2026-01-01T00:00:00.000Z", "lastLogin": None,
            "profile": {"login": f"{uid}@x.test", "email": f"{uid}@x.test", **profile}}


def test_collect_normalizes_okta_responses(keypair):
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE"), _user("u2", "STAGED")],
        "/api/v1/users?deprovisioned": [_user("u3", "DEPROVISIONED")],
        "/api/v1/users/u1/factors": [
            {"factorType": "push", "status": "ACTIVE"},
            {"factorType": "sms", "status": "PENDING_ACTIVATION"},
        ],
        "/api/v1/users/u1/roles": [{"type": "SUPER_ADMIN", "label": "Super Administrator"}],
        "/api/v1/groups": [{"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Eng"}}],
        "/api/v1/groups/g1/users": [{"id": "u1"}, {"id": "u3"}],
        "/api/v1/apps": [{
            "id": "a1", "label": "Svc", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT",
            "credentials": {"oauthClient": {"client_id": "a1"}},
            "settings": {"oauthClient": {"grant_types": ["client_credentials"]}},
        }],
        "/oauth2/v1/clients/a1/roles": [{"type": "CUSTOM", "label": "Okta MCP Role"}],
        "/api/v1/apps/a1/users": [{"id": "u1", "scope": "USER"}, {"id": "u3", "scope": "GROUP"}],
        "/api/v1/apps/a1/groups": [{"id": "g1"}],
        "/api/v1/apps/a1/grants": [
            {"scopeId": "okta.users.manage", "status": "ACTIVE"},
            {"scopeId": "okta.logs.read", "status": "REVOKED"},
        ],
    })
    snap = collect(client(session, keypair))
    users = {u.id: u for u in snap.users}
    assert set(users) == {"u1", "u2", "u3"}
    assert users["u1"].factors == ["push"]
    assert users["u2"].factors is None  # factors only fetched for users who can sign in
    assert snap.groups[0].members == {"u1", "u3"}
    assert snap.apps[0].users == {"u1"}
    assert snap.apps[0].granted_scopes == ["okta.users.manage"]
    assert users["u1"].admin_roles == ["Super Administrator"]
    assert users["u2"].admin_roles == []
    assert users["u3"].admin_roles is None  # not looked up for deprovisioned users
    assert snap.apps[0].admin_roles == ["Okta MCP Role"]
    assert snap.apps[0].service_client is True
    # Read-only: the only non-GET request is the token request.
    assert all(url.endswith("/oauth2/v1/token") for url, _ in session.posts)


def test_collect_marks_mfa_unknown_when_factors_forbidden(keypair):
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE"), _user("u2", "ACTIVE")],
        "/api/v1/users/u1/factors": FakeResponse({"errorSummary": "forbidden"}, status=403),
    })
    snap = collect(client(session, keypair))
    assert [u.factors for u in snap.users] == [None, None]
    # Stops asking after the first 403 instead of hitting it for every user.
    assert not any(url.endswith("/u2/factors") for url, _ in session.gets)


def test_collect_marks_roles_unknown_and_skips_grants_when_forbidden(keypair, capsys):
    forbidden = FakeResponse({}, status=403, headers={"WWW-Authenticate": 'error="insufficient_scope"'})
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE")],
        "/api/v1/users/u1/roles": forbidden,
        "/api/v1/apps": [{"id": "a1", "label": "A"}, {"id": "a2", "label": "B"}],
        "/api/v1/apps/a1/grants": forbidden,
    })
    snap = collect(client(session, keypair))
    assert snap.users[0].admin_roles is None
    assert [a.granted_scopes for a in snap.apps] == [[], []]
    assert not any(url.endswith("/a2/grants") for url, _ in session.gets)
    err = capsys.readouterr().err
    assert "okta.roles.read" in err and "okta.appGrants.read" in err and "insufficient_scope" in err
    assert len(snap.gaps) == 3
    assert "AR-10 and AR-11" in snap.gaps[0]
    assert "hiding apps" in snap.gaps[2]
    # As a flag, not only as prose: watch.still_present reads it to refuse to
    # verify a revoke from a read that could not see the app, and a gap string is
    # not something that function can be asked to parse.
    assert snap.apps_complete is False
    # And it survives being written and read back, which is how every consumer
    # after the collector gets it.
    assert Snapshot.from_dict(snap.to_dict()).apps_complete is False


def test_no_gap_when_review_app_is_visible(keypair):
    session = FakeSession({"/api/v1/apps": [{"id": "client123", "label": "Access Review"}]})
    snap = collect(client(session, keypair))
    assert snap.gaps == []
    assert snap.apps_complete is True
    assert Snapshot.from_dict(snap.to_dict()).apps_complete is True


def test_get_capped_stops_at_the_limit(keypair):
    session = FakeSession({
        "/api/v1/logs": FakeResponse([{"n": 1}, {"n": 2}], next_url=f"{ORG}/api/v1/logs/page2"),
        "/api/v1/logs/page2": [{"n": 3}, {"n": 4}],
    }, token_type="Bearer")

    items, truncated = client(session, keypair).get_capped("/api/v1/logs", {"since": "x"}, max_items=3)

    assert items == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert truncated is True


def test_get_capped_treats_an_empty_page_as_the_end(keypair):
    """The System Log always offers a next link, for polling. Only an empty page
    means there is no more data, so get_all would never finish."""
    session = FakeSession({
        "/api/v1/logs": FakeResponse([{"n": 1}], next_url=f"{ORG}/api/v1/logs/page2"),
        "/api/v1/logs/page2": FakeResponse([], next_url=f"{ORG}/api/v1/logs/page3"),
    }, token_type="Bearer")

    items, truncated = client(session, keypair).get_capped("/api/v1/logs", {"since": "x"}, max_items=500)

    assert items == [{"n": 1}]
    assert truncated is False


def _log(event_type, published, actor_id, targets=(), uuid=None):
    return {
        "uuid": uuid or f"{actor_id}-{event_type}-{published}",
        "published": published, "eventType": event_type,
        "actor": {"id": actor_id, "type": "User"}, "outcome": {"result": "SUCCESS"},
        "target": [{"id": t, "type": "AppInstance", "displayName": t} for t in targets],
    }


def _leaver_org(routes=None):
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE", email="gone@x.test"), _user("u2", "ACTIVE", email="here@x.test")],
        "/api/v1/apps": [{
            "id": "a1", "label": "Bot", "status": "ACTIVE",
            "credentials": {"oauthClient": {"client_id": "0oaBOT"}},
            "settings": {"oauthClient": {"grant_types": ["client_credentials"]}},
        }],
        "/api/v1/api-tokens": [{"id": "t1", "name": "ci-deploy", "userId": "u1"}],
        **(routes or {}),
    }, token_type="Bearer")
    return session


def _roster(end_date="2026-08-01"):
    from access_review.roster import RosterEntry, _parse_end
    ends, ends_at = _parse_end(end_date or "", timezone.utc, "gone@x.test")
    return {"gone@x.test": RosterEntry("gone@x.test", "Gone", "employee", "terminated",
                                       ends, "", end_at=ends_at)}


def test_activity_is_read_only_for_leavers(keypair):
    session = _leaver_org({"/api/v1/logs": [_log("user.session.start", "2026-09-01T10:00:00.000Z", "u1")]})

    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))

    assert [e.event_type for e in snap.events] == ["user.session.start"]
    assert snap.api_tokens[0].name == "ci-deploy"
    assert snap.activity_since == datetime(2026, 6, 17, tzinfo=timezone.utc)
    # Two queries, both for the leaver only. The person who still works here is
    # never queried. Credentials are narrowed server-side and read the whole
    # window; activity reads only what happened after they left.
    sent = [p for url, p in session.gets if url.endswith("/api/v1/logs")]
    assert all('actor.id eq "u1"' in p["filter"] for p in sent)
    credentials, activity = sent
    assert 'eventType sw "app.oauth2.credentials.lifecycle.create"' in credentials["filter"]
    # Switching a secret off shows nobody anything, so it is not custody.
    assert "lifecycle.delete" not in credentials["filter"]
    assert credentials["since"] == "2026-06-17T00:00:00Z"
    assert "eventType" not in activity["filter"]
    assert activity["since"] == "2026-08-01T23:59:59.999999Z"


def test_a_refused_log_read_reports_no_activity_window(keypair):
    """A 403 on the System Log means nothing was read, not that nothing happened.
    Reporting the horizon anyway lets a caller read silence as absence."""
    forbidden = FakeResponse({"errorSummary": "forbidden"}, status=403)
    session = _leaver_org({"/api/v1/logs": forbidden})

    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))

    assert snap.events == []
    assert snap.activity_since is None
    assert any("System Log" in g for g in snap.gaps)


def test_no_roster_means_no_activity_queries(keypair):
    session = _leaver_org()

    snap = collect(client(session, keypair))

    assert snap.events == []
    assert snap.activity_since is None
    assert not any("/logs" in url for url, _ in session.gets)


def test_a_client_the_leaver_set_up_is_queried_too(keypair):
    """The API client keeps working on its own credentials, so what it does counts."""
    session = _leaver_org()
    session.routes["/api/v1/logs"] = [
        _log("app.oauth2.credentials.lifecycle.create", "2026-07-02T10:00:00.000Z", "u1", targets=["0oaBOT"]),
        _log("app.oauth2.token.grant.access_token", "2026-09-01T10:00:00.000Z", "0oaBOT", uuid="grant-1"),
    ]

    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))

    actors = [p["filter"].split('"')[1] for url, p in session.gets if url.endswith("/api/v1/logs")]
    assert actors == ["u1", "u1", "0oaBOT"]
    # Every query returns the same rows; events are deduplicated by uuid.
    assert len(snap.events) == 2
    # Whose activity was read, so an unread client is never described as idle.
    assert snap.activity_actors == {"u1", "0oaBOT"}


def test_a_held_clients_secrets_are_never_read(keypair):
    """The secrets endpoint returns the secret itself. Whether a leaver's copy
    was rotated is AR-18's, confirmed by a reviewer, so nothing reads it."""
    session = _held_org()

    collect(client(session, keypair), _roster(), date(2026, 9, 15))

    assert not any("/credentials/" in url for url, _ in session.gets)


def test_a_termination_older_than_the_window_is_reported_as_a_gap(keypair):
    session = _leaver_org({"/api/v1/logs": []})

    snap = collect(client(session, keypair), _roster("2026-01-05"), date(2026, 9, 15))

    assert any("before the 90-day System Log window" in g for g in snap.gaps)


def test_truncated_activity_says_the_counts_are_a_lower_bound(keypair):
    """Okta returns the log oldest first, so a truncated read drops the most
    recent activity -- exactly what AR-13 is looking for. Say so."""
    events = [_log("user.session.start", "2026-09-01T10:00:00.000Z", "u1", uuid=f"e{i}") for i in range(600)]
    session = _leaver_org({"/api/v1/logs": events})

    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))

    assert len(snap.events) == 500
    [gap] = [g for g in snap.gaps if "lower bound" in g]
    assert "later activity is not shown" in gap


def test_an_hr_timestamp_narrows_the_activity_query(keypair):
    session = _leaver_org({"/api/v1/logs": []})

    collect(client(session, keypair), _roster("2026-08-01T14:05:00+00:00"), date(2026, 9, 15))

    _, activity = [p for url, p in session.gets if url.endswith("/api/v1/logs")]
    assert activity["since"] == "2026-08-01T14:05:00Z"


def test_a_leaver_with_no_end_date_is_still_checked_for_credentials(keypair):
    """AR-13 has no anchor without an end date, but AR-12 does not need one."""
    session = _leaver_org({"/api/v1/logs": []})

    collect(client(session, keypair), _roster(None), date(2026, 9, 15))

    sent = [p for url, p in session.gets if url.endswith("/api/v1/logs")]
    assert len(sent) == 1
    assert "eventType sw" in sent[0]["filter"]


def test_review_still_runs_when_logs_and_tokens_are_forbidden(keypair, capsys):
    forbidden = FakeResponse({"errorSummary": "forbidden"}, status=403)
    session = _leaver_org({"/api/v1/logs": forbidden, "/api/v1/api-tokens": forbidden})

    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))

    assert snap.events == [] and snap.api_tokens == []
    gaps = " ".join(snap.gaps)
    assert "okta.apiTokens.read" in gaps and "okta.logs.read" in gaps
    assert "AR-13 and AR-18" in gaps


def _usage_org(logs):
    return FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE"), _user("u2", "ACTIVE")],
        "/api/v1/apps": [{"id": "a1", "label": "Wiki", "status": "ACTIVE", "signOnMode": "SAML_2_0"}],
        "/api/v1/apps/a1/users": [
            {"id": "u1", "scope": "USER", "created": "2025-01-02T03:04:05.000Z"},
            {"id": "u2", "scope": "GROUP", "created": "2025-02-02T03:04:05.000Z"},
        ],
        "/api/v1/logs": logs,
    }, token_type="Bearer")


def test_app_usage_is_off_unless_asked_for(keypair):
    session = _usage_org([])

    snap = collect(client(session, keypair))

    assert snap.app_usage == {} and snap.app_usage_since is None
    assert not any("/logs" in url for url, _ in session.gets)


def test_app_usage_keeps_the_last_successful_sign_in_per_user_and_app(keypair):
    session = _usage_org([
        _log("user.authentication.sso", "2026-07-01T10:00:00.000Z", "u1", targets=["a1"], uuid="1"),
        _log("user.authentication.sso", "2026-09-01T10:00:00.000Z", "u1", targets=["a1"], uuid="2"),
        _log("user.authentication.sso", "2026-08-01T10:00:00.000Z", "u1", targets=["a1"], uuid="3"),
        {**_log("user.authentication.sso", "2026-09-10T10:00:00.000Z", "u2", targets=["a1"], uuid="4"),
         "outcome": {"result": "FAILURE"}},
    ])

    snap = collect(client(session, keypair), as_of=date(2026, 9, 15), app_usage_days=90)

    assert snap.app_usage == {("u1", "a1"): datetime(2026, 9, 1, 10, tzinfo=timezone.utc)}
    assert snap.app_usage_since == datetime(2026, 6, 17, tzinfo=timezone.utc)
    assert snap.app_usage_complete is True
    [(_, params)] = [(u, p) for u, p in session.gets if u.endswith("/api/v1/logs")]
    assert params["filter"] == 'eventType eq "user.authentication.sso"'
    assert params["since"] == "2026-06-17T00:00:00Z"
    # Only direct assignments are kept, each with the date it was made.
    assert snap.apps[0].assigned == {"u1": datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)}


def test_truncated_app_usage_is_marked_incomplete(keypair, monkeypatch):
    import access_review.collect as collect_module
    monkeypatch.setattr(collect_module, "MAX_SSO_EVENTS", 2)
    events = [_log("user.authentication.sso", "2026-09-01T10:00:00.000Z", "u1", targets=["a1"], uuid=f"e{i}")
              for i in range(3)]

    snap = collect(client(_usage_org(events), keypair), as_of=date(2026, 9, 15), app_usage_days=90)

    assert snap.app_usage_complete is False
    assert any("no app access is proposed for revocation" in g for g in snap.gaps)


def test_forbidden_app_usage_is_a_gap_not_an_error(keypair):
    snap = collect(
        client(_usage_org(FakeResponse({}, status=403)), keypair), as_of=date(2026, 9, 15), app_usage_days=90
    )

    assert snap.app_usage_since is None and snap.app_usage_complete is False
    assert any("AR-14 and review proposals" in g for g in snap.gaps)


def test_admin_console_links_only_for_okta_orgs():
    from access_review.okta import admin_url
    assert admin_url("https://acme.okta.com", "user", "00u1abcDEF") == \
        "https://acme-admin.okta.com/admin/user/profile/view/00u1abcDEF"
    assert admin_url("https://acme.oktapreview.com/", "group", "00g1abcDEF") == \
        "https://acme-admin.oktapreview.com/admin/group/00g1abcDEF"
    assert admin_url("https://evil.test", "user", "00u1abcDEF") is None
    assert admin_url("https://acme.okta.com", "user", "../../x") is None


def _held_org():
    return _leaver_org({
        "/api/v1/logs": [_log("app.oauth2.client.read_client_secret", "2026-07-02T10:00:00.000Z", "u1",
                              targets=["0oaBOT"])],
    })


def test_a_refused_log_read_records_no_actors(keypair):
    """Actors are the claim that someone's activity was read."""
    session = _leaver_org({"/api/v1/logs": FakeResponse({"errorSummary": "no"}, status=403)})
    snap = collect(client(session, keypair), _roster(), date(2026, 9, 15))
    assert not snap.activity_actors


def test_a_held_clients_last_use_is_one_newest_first_read_of_the_whole_window(keypair):
    """Oldest-first from the day they left spent the cap on a busy client's
    first calls, signed an understated date, and raised a gap that stopped every
    leaver ticket closing; and it never looked before they left at all."""
    session = _held_org()
    collect(client(session, keypair), _roster(), date(2026, 9, 15))
    [bot] = [p for url, p in session.gets if url.endswith("/api/v1/logs") and '"0oaBOT"' in p["filter"]]
    assert bot["sortOrder"] == "DESCENDING" and bot["limit"] == 1
    assert bot["since"] == "2026-06-17T00:00:00Z"
    assert "app.oauth2.token" in bot["filter"]
