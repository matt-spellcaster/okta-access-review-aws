"""Minimal read-only Okta API client using Private Key JWT (client credentials)
and, optionally, DPoP-bound access tokens (RFC 9449).

The only non-GET request this client makes is the token request. There is no
code path that changes anything in Okta.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
import uuid

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec


class OktaError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"Okta HTTP {status}: {message}")
        self.status = status


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class DPoPKey:
    """Per-process P-256 key that access tokens are bound to. It exists only in
    memory, so a leaked access token can't be used after this process exits."""

    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }

    def proof(self, method: str, url: str, nonce: str | None = None, access_token: str | None = None) -> str:
        claims = {
            "htm": method,
            "htu": url.split("?", 1)[0].split("#", 1)[0],
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
        }
        if nonce:
            claims["nonce"] = nonce
        if access_token:
            claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
        return jwt.encode(claims, self._key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": self.jwk})


class OktaClient:
    def __init__(
        self,
        org_url: str,
        client_id: str,
        key_id: str,
        private_key_pem: str,
        scopes: list[str],
        session: requests.Session | None = None,
        max_retries: int = 3,
        dpop: bool = True,
    ):
        self.org_url = org_url.rstrip("/")
        self.client_id = client_id
        self.key_id = key_id
        self._private_key = private_key_pem
        self.scopes = scopes
        self.session = session or requests.Session()
        self.max_retries = max_retries
        self.dpop = DPoPKey() if dpop else None
        self._token: str | None = None
        self._token_type = "Bearer"
        self._token_expires = 0.0
        self._token_nonce: str | None = None
        self._api_nonce: str | None = None

    @property
    def token_url(self) -> str:
        return f"{self.org_url}/oauth2/v1/token"

    def client_assertion(self) -> str:
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.token_url,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(claims, self._private_key, algorithm="RS256", headers={"kid": self.key_id})

    def access_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        for attempt in range(2):
            headers = {"Accept": "application/json"}
            if self.dpop:
                headers["DPoP"] = self.dpop.proof("POST", self.token_url, nonce=self._token_nonce)
            resp = self.session.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "scope": " ".join(self.scopes),
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": self.client_assertion(),
                },
                headers=headers,
                timeout=30,
            )
            # Okta answers the first DPoP token request with a nonce to include.
            if attempt == 0 and self.dpop and _needs_nonce(resp):
                self._token_nonce = resp.headers["DPoP-Nonce"]
                continue
            break
        if resp.status_code != 200:
            raise OktaError(resp.status_code, _error_text(resp))
        body = resp.json()
        self._token = body["access_token"]
        self._token_type = body.get("token_type", "Bearer")
        if self.dpop and self._token_type != "DPoP":
            raise OktaError(200, f"expected a DPoP-bound token but got {self._token_type}; is DPoP required on the app?")
        self._token_expires = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _auth_headers(self, url: str) -> dict:
        token = self.access_token()
        headers = {"Authorization": f"{self._token_type} {token}", "Accept": "application/json"}
        if self._token_type == "DPoP":
            headers["DPoP"] = self.dpop.proof("GET", url, nonce=self._api_nonce, access_token=token)
        return headers

    def _get(self, url: str, params: dict | None) -> requests.Response:
        nonce_retried = False
        attempt = 0
        while True:
            resp = self.session.get(url, params=params, headers=self._auth_headers(url), timeout=30)
            if self.dpop and not nonce_retried and _needs_nonce(resp):
                self._api_nonce = resp.headers["DPoP-Nonce"]
                nonce_retried = True
                continue
            if resp.status_code == 429 and attempt < self.max_retries:
                attempt += 1
                reset = int(resp.headers.get("X-Rate-Limit-Reset", "0"))
                time.sleep(min(max(reset - time.time(), 1), 60))
                continue
            if resp.status_code >= 400:
                raise OktaError(resp.status_code, _error_text(resp))
            return resp

    def get_all(self, path: str, params: dict | None = None) -> list:
        """GET a collection, following Link rel="next" pagination."""
        url = f"{self.org_url}{path}"
        items: list = []
        while url:
            resp = self._get(url, params)
            body = resp.json()
            items.extend(body if isinstance(body, list) else [body])
            url = resp.links.get("next", {}).get("url")
            params = None  # the next link already carries the query
        return items

    def get_capped(self, path: str, params: dict | None = None, max_items: int = 1000) -> tuple[list, bool]:
        """GET a collection, stopping at max_items. Returns (items, truncated).

        Use this instead of get_all for the System Log, for two reasons. It can
        return far more than a review needs, and its next link is meant for
        polling, so it is always present -- get_all would never finish. An empty
        page is the real end of the data.
        """
        url = f"{self.org_url}{path}"
        items: list = []
        while url:
            resp = self._get(url, params)
            body = resp.json()
            page = body if isinstance(body, list) else [body]
            if not page:
                break
            items.extend(page)
            if len(items) >= max_items:
                return items[:max_items], True
            url = resp.links.get("next", {}).get("url")
            params = None  # the next link already carries the query
        return items, False


def _needs_nonce(resp: requests.Response) -> bool:
    if resp.status_code not in (400, 401) or "DPoP-Nonce" not in resp.headers:
        return False
    if "use_dpop_nonce" in resp.headers.get("WWW-Authenticate", ""):
        return True
    try:
        return resp.json().get("error") == "use_dpop_nonce"
    except ValueError:
        return False


def _error_text(resp: requests.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = {}
    text = body.get("errorSummary") or body.get("error_description") or body.get("error") if isinstance(body, dict) else None
    text = text or resp.text[:200].strip()
    # Okta often explains 401/403 only in this header (e.g. insufficient_scope).
    challenge = resp.headers.get("WWW-Authenticate")
    return "; ".join(p for p in (text, challenge) if p) or "no details"


def admin_url(org_url: str, kind: str, object_id: str) -> str | None:
    """A page in the Okta admin console, for a person ("user") or a group.
    https://acme.okta.com -> https://acme-admin.okta.com/admin/user/profile/view/<id>"""
    m = re.fullmatch(r"https://([a-z0-9-]+)\.(okta|oktapreview|okta-emea)\.com/?", org_url or "")
    if not m or not re.fullmatch(r"[A-Za-z0-9]{1,40}", object_id or ""):
        return None
    base = f"https://{m.group(1)}-admin.{m.group(2)}.com/admin"
    return {"user": f"{base}/user/profile/view/{object_id}", "group": f"{base}/group/{object_id}"}.get(kind)
