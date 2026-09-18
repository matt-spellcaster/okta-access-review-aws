"""The few Jira Cloud REST calls the review needs: search, create, comment.

Writes go to one project only: create_issue refuses any other project key.
The API token is a secret; it never appears in errors, and neither does
anything Jira echoes back from an issue (field values can hold personal data),
only the status and the names of the fields it complained about.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urlparse

import requests

API = "/rest/api/3"
PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,9}$")
ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,9}-\d+$")


class JiraConfigError(ValueError):
    pass


class JiraError(Exception):
    """A Jira call failed. Never includes the token or issue content."""


def check_base_url(url: str) -> str:
    """Jira Cloud only: https on *.atlassian.net, or the api.atlassian.com
    gateway that scoped API tokens use."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ok = parsed.scheme == "https" and not parsed.username and not parsed.query and (
        (host.endswith(".atlassian.net") and parsed.path in ("", "/"))
        or (host == "api.atlassian.com" and re.fullmatch(r"/ex/jira/[0-9a-f-]{36}/?", parsed.path or ""))
    )
    if not ok:
        raise JiraConfigError(
            "JIRA_BASE_URL must be https://<site>.atlassian.net or https://api.atlassian.com/ex/jira/<cloud id>"
        )
    return url.rstrip("/")


class JiraClient:
    def __init__(self, base_url: str, email: str, token: str, project: str, session: requests.Session | None = None):
        self.base_url = check_base_url(base_url)
        if not PROJECT_KEY.match(project):
            raise JiraConfigError("JIRA_PROJECT must be a project key like UAR")
        if "@" not in email:
            raise JiraConfigError("JIRA_EMAIL must be the service account's email address")
        self.project = project
        self._auth = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()
        self.session = session or requests.Session()

    def _request(self, method: str, path: str, what: str, **kwargs) -> dict:
        try:
            resp = self.session.request(
                method, f"{self.base_url}{API}{path}", timeout=30,
                headers={"Authorization": self._auth, "Accept": "application/json"}, **kwargs,
            )
        except requests.RequestException as e:
            raise JiraError(f"{what}: could not reach Jira ({type(e).__name__})") from None
        if resp.status_code == 429:
            raise JiraError(f"{what}: rate limited by Jira, retry after {resp.headers.get('Retry-After', '?')}s")
        if resp.status_code >= 400:
            fields = ""
            try:
                errors = resp.json().get("errors") or {}
                if isinstance(errors, dict) and errors:
                    fields = f" (problem with: {', '.join(sorted(map(str, errors)))})"
            except ValueError:
                pass
            hint = {401: " (check JIRA_EMAIL and the API token)",
                    403: " (the service account lacks permission in this project)"}.get(resp.status_code, "")
            raise JiraError(f"{what}: HTTP {resp.status_code}{fields}{hint}")
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            raise JiraError(f"{what}: HTTP {resp.status_code}, not a JSON response") from None

    def search(self, jql: str, fields: list[str], limit: int = 1000) -> list[dict]:
        """Every matching issue (up to limit), following nextPageToken."""
        issues: list[dict] = []
        token = None
        while len(issues) < limit:
            body = {"jql": jql, "fields": fields, "maxResults": min(100, limit - len(issues))}
            if token:
                body["nextPageToken"] = token
            page = self._request("POST", "/search/jql", "search", json=body)
            issues += page.get("issues", [])
            token = page.get("nextPageToken")
            if not token or page.get("isLast", True):
                break
        return issues

    def create_issue(self, fields: dict) -> str:
        if (fields.get("project") or {}).get("key") != self.project:
            raise JiraError(f"create_issue: refusing to create outside project {self.project}")
        key = self._request("POST", "/issue", "create issue", json={"fields": fields}).get("key", "")
        if not ISSUE_KEY.match(key):
            raise JiraError("create issue: Jira did not return an issue key")
        return key

    def add_comment(self, key: str, body: dict) -> None:
        if not ISSUE_KEY.match(key) or not key.startswith(self.project + "-"):
            raise JiraError(f"add comment: refusing to comment outside project {self.project}")
        self._request("POST", f"/issue/{key}/comment", "add comment", json={"body": body})

    def issue_types(self) -> list[str]:
        """Issue type names the service account can create in the project, for setup checks."""
        page = self._request("GET", f"/issue/createmeta/{self.project}/issuetypes", "issue types")
        return sorted(t.get("name", "") for t in page.get("issueTypes", page.get("values", [])))


def adf(*paragraphs: str | list[tuple[str, str | None]]) -> dict:
    """Atlassian Document Format from plain paragraphs. A paragraph is a string,
    or a list of (text, mark) pieces where mark is None, "strong" or "code"."""
    content = []
    for p in paragraphs:
        pieces = [(p, None)] if isinstance(p, str) else p
        nodes = []
        for text, mark in pieces:
            if not text:
                continue
            node = {"type": "text", "text": text}
            if mark:
                node["marks"] = [{"type": mark}]
            nodes.append(node)
        content.append({"type": "paragraph", "content": nodes} if nodes else {"type": "paragraph"})
    return {"type": "doc", "version": 1, "content": content}
