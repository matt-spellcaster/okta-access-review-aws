"""Check that the deployed Okta settings can sign in and read what the review needs.

Runs in GitHub Actions (.github/workflows/okta-check.yml) with the real settings:
OKTA_ORG_URL, OKTA_CLIENT_ID and OKTA_KEY_ID from repository secrets, and the
private key from the SSM parameter named by OKTA_PRIVATE_KEY_PARAM. It does what
the collect Lambda does -- Private Key JWT, DPoP, the review's read-only scopes --
then makes one small read per API the review uses.

It prints only pass/fail and HTTP statuses: this repository's logs are public, so
no setting, token, or Okta data is ever printed. Exit 0 if everything passed.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from access_review.cli import DEFAULT_SCOPES  # noqa: E402
from access_review.okta import OktaClient, OktaError  # noqa: E402
from access_review.settings import OktaSettings, SettingsError, get_secret  # noqa: E402


def probes(client_id: str) -> list[tuple[str, str, dict]]:
    """(what, path, params): one small read per API the collector calls."""
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        ("users (okta.users.read)", "/api/v1/users", {"limit": 1}),
        ("groups (okta.groups.read)", "/api/v1/groups", {"limit": 1}),
        ("apps (okta.apps.read)", "/api/v1/apps", {"limit": 1}),
        ("app grants (okta.appGrants.read)", f"/api/v1/apps/{client_id}/grants", {}),
        ("admin roles (okta.roles.read)", f"/oauth2/v1/clients/{client_id}/roles", {}),
        ("API tokens (okta.apiTokens.read)", "/api/v1/api-tokens", {}),
        ("System Log (okta.logs.read)", "/api/v1/logs", {"since": since, "limit": 1}),
    ]


def main(ssm=None, session=None) -> int:
    try:
        okta = OktaSettings.from_env()
        if ssm is None:
            import boto3

            ssm = boto3.client("ssm")
        key = get_secret(ssm, "OKTA_PRIVATE_KEY_PARAM")
    except SettingsError as e:
        print(f"FAIL settings: {e}")
        return 1

    scopes = DEFAULT_SCOPES.split()
    client = OktaClient(okta.org_url, okta.client_id, okta.key_id, key, scopes, session=session, dpop=True)
    try:
        client.access_token()
    except OktaError as e:
        hint = {400: " (invalid_client: check OKTA_CLIENT_ID and OKTA_KEY_ID match the key in SSM; "
                     "invalid_scope: grant the app every okta.*.read scope)",
                401: " (the key in SSM doesn't match any public key on the app)"}.get(e.status, "")
        print(f"FAIL token: HTTP {e.status}{hint}")
        return 1
    except Exception as e:  # network, bad key format
        print(f"FAIL token: {type(e).__name__} (is the SSM value a PEM private key?)")
        return 1
    print(f"PASS token: DPoP-bound, {len(scopes)} read-only scopes granted")

    failed = 0
    for what, path, params in probes(okta.client_id):
        try:
            status = client._get(f"{okta.org_url}{path}", params).status_code
        except OktaError as e:
            status = e.status
        ok = status == 200 or (status == 404 and "roles" in path)  # a client with no roles answers 404
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'} {what}: HTTP {status}")
    if failed:
        print(f"{failed} check(s) failed. A 403 usually means the app's admin role can't see that data "
              "(docs/configuration.md#okta-app).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
