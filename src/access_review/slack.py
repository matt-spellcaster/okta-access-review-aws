"""Post a review summary to Slack.

Two ways to connect:
- Incoming webhook (SLACK_WEBHOOK_URL): posts the summary only.
- Bot token (SLACK_BOT_TOKEN + SLACK_CHANNEL_ID): posts the same summary and,
  if SLACK_ATTACH_PDF is true, uploads report.pdf as a reply in its thread.

Webhook URLs and bot tokens are secrets, so they come from the environment
(run.sh fetches them from 1Password) and never appear in output or errors.
The summary has counts and completeness only, no personal data. The PDF does
contain personal data, so uploading it is opt-in.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests

from .checks import SEVERITIES, Finding
from .history import repeat_summary
from .models import Snapshot

ALLOWED_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}
API = "https://slack.com/api"
CHANNEL_ID = re.compile(r"^[CG][A-Z0-9]{8,}$")
TRUE = {"1", "true", "yes", "on"}
FALSE = {"", "0", "false", "no", "off"}
SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
    "info": ":large_blue_circle:",
}
# Color of the bar down the left of the message: the worst severity found.
SEVERITY_BAR = {
    "critical": "#B42318",
    "high": "#E04F16",
    "medium": "#F79009",
    "low": "#98A2B3",
    "info": "#2E90FA",
}
CLEAN_BAR = "#12B76A"


class SlackConfigError(Exception):
    pass


class SlackError(Exception):
    """Posting failed. The message never includes a webhook URL or token."""


@dataclass
class SlackSettings:
    webhook_url: str = ""
    bot_token: str = ""
    channel_id: str = ""
    attach_pdf: bool = False

    @property
    def uses_bot(self) -> bool:
        return bool(self.bot_token)


def webhook_from_env(env: dict[str, str] | None = None) -> str | None:
    """None when SLACK_WEBHOOK_URL is unset."""
    env = os.environ if env is None else env
    url = env.get("SLACK_WEBHOOK_URL", "").strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or not parsed.path.startswith("/services/"):
        # Don't echo the value: it may be a real secret pasted into the wrong setting.
        raise SlackConfigError(
            "SLACK_WEBHOOK_URL must be a Slack incoming webhook (https://hooks.slack.com/services/...)"
        )
    return url


def settings_from_env(env: dict[str, str] | None = None) -> SlackSettings | None:
    """None when Slack is off (neither a bot token nor a webhook is set)."""
    env = os.environ if env is None else env
    token = env.get("SLACK_BOT_TOKEN", "").strip()
    webhook = webhook_from_env(env)
    attach_raw = env.get("SLACK_ATTACH_PDF", "").strip().lower()
    if attach_raw not in TRUE | FALSE:
        raise SlackConfigError("SLACK_ATTACH_PDF must be true or false")
    attach = attach_raw in TRUE

    if token and webhook:
        raise SlackConfigError("set either a Slack bot token or a webhook, not both")
    if token:
        if not token.startswith("xoxb-"):
            raise SlackConfigError("SLACK_BOT_TOKEN must be a bot token (starts with xoxb-)")
        channel = env.get("SLACK_CHANNEL_ID", "").strip()
        if not CHANNEL_ID.match(channel):
            raise SlackConfigError(
                "SLACK_CHANNEL_ID must be a channel ID like C0123456789 (channel details → About), not a name"
            )
        return SlackSettings(bot_token=token, channel_id=channel, attach_pdf=attach)
    if webhook:
        if attach:
            raise SlackConfigError("SLACK_ATTACH_PDF needs a bot token; incoming webhooks can't upload files")
        return SlackSettings(webhook_url=webhook)
    return None


def _mrkdwn(text: str) -> dict:
    return {"type": "mrkdwn", "text": text}


def _local_time(when) -> str:
    """Slack date token: each reader sees the time in their own time zone."""
    fallback = when.strftime("%Y-%m-%d %H:%M UTC")
    return f"<!date^{int(when.timestamp())}^{{date_short_pretty}} at {{time}}|{fallback}>"


def build_payload(snapshot: Snapshot, findings: list[Finding], run_dir: Path, brand: str = "") -> dict:
    counts = Counter(f.severity for f in findings)
    org = urlparse(snapshot.org_url).hostname or snapshot.org_url
    complete = not snapshot.gaps
    top = next((s for s in SEVERITIES if counts.get(s)), None)
    headline = f"{counts[top]} {top}" if top else "no findings"
    pdf_hash = hashlib.sha256((run_dir / "report.pdf").read_bytes()).hexdigest()

    title = f"{brand} · Okta access review" if brand else "Okta access review"
    if complete:
        status = ":white_check_mark: *Complete*"
    else:
        status = f":warning: *Incomplete*: {len(snapshot.gaps)} data gap(s)"

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f":shield: {title}", "emoji": True}},
        {
            "type": "section",
            "fields": [
                _mrkdwn(f"*Status*\n{status}"),
                _mrkdwn(f"*Org*\n`{org}`"),
                _mrkdwn(f"*Data collected*\n{_local_time(snapshot.collected_at)}"),
                _mrkdwn(f"*Findings*\n*{len(findings)}* total"),
            ],
        },
    ]
    if not complete:
        blocks.append({"type": "section", "text": _mrkdwn(
            ":warning: Some Okta data couldn't be read, so this review may miss issues. "
            "Check *Data gaps* in the report before relying on it."
        )})

    blocks.append({"type": "divider"})
    if findings:
        # Two-column grid of counts; zero rows are dimmed with a dash.
        grid = [
            _mrkdwn(f"{SEVERITY_EMOJI[s]} *{s.capitalize()}*   {counts[s]}" if counts.get(s)
                    else f"{SEVERITY_EMOJI[s]} {s.capitalize()}   –")
            for s in SEVERITIES
        ]
        blocks.append({"type": "section", "text": _mrkdwn("*Findings by severity*"), "fields": grid})

        # One line per check, worst first. Check titles contain no personal data.
        by_check: dict[str, list[Finding]] = {}
        for f in findings:
            by_check.setdefault(f.check_id, []).append(f)
        lines = []
        for check_id, items in by_check.items():  # findings are already sorted by severity
            worst = items[0].severity
            count = f"  ×{len(items)}" if len(items) > 1 else ""
            lines.append(f"{SEVERITY_EMOJI[worst]}  `{check_id}`  {items[0].title}{count}")
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": _mrkdwn("*What needs attention*\n" + "\n".join(lines))})
        if repeats := repeat_summary(findings):
            blocks.append({"type": "context", "elements": [_mrkdwn(f":hourglass: {repeats}")]})
    else:
        blocks.append({"type": "section", "text": _mrkdwn(":tada: *No findings.* Nothing needs attention.")})

    blocks.append({"type": "context", "elements": [_mrkdwn(
        f":page_facing_up: Report `{run_dir.name}`  ·  PDF SHA-256 `{pdf_hash[:12]}`  ·  "
        ":lock: Names and details are only in the report and email"
    )]})

    plain_status = "complete" if complete else "INCOMPLETE"
    return {
        # Shown in notifications and by clients that can't render blocks.
        "text": f"{title} ({plain_status}): {headline}, {org}",
        # An attachment gives the message a colored side bar.
        "attachments": [{
            "color": SEVERITY_BAR[top] if top else CLEAN_BAR,
            "fallback": f"{title}: {headline}",
            "blocks": blocks,
        }],
    }


def post(url: str, payload: dict, session: requests.Session | None = None) -> None:
    session = session or requests.Session()
    try:
        resp = session.post(url, json=payload, timeout=15)
    except requests.RequestException as e:
        # requests puts the URL in its messages, so report only the error type.
        raise SlackError(f"could not reach Slack ({type(e).__name__})") from None
    if resp.status_code != 200:
        # Slack returns short codes like invalid_payload, no_service, channel_is_archived.
        raise SlackError(f"Slack returned HTTP {resp.status_code}: {resp.text[:100].strip() or 'no details'}")


class BotClient:
    """The few Slack Web API calls needed to post a message and upload a file."""

    def __init__(self, token: str, session: requests.Session | None = None):
        self._token = token
        self.session = session or requests.Session()

    def _request(self, method: str, url: str, what: str, **kwargs) -> requests.Response:
        try:
            resp = self.session.request(method, url, timeout=30, **kwargs)
        except requests.RequestException as e:
            # Don't include the exception text: it can contain the (pre-signed) URL.
            raise SlackError(f"{what}: could not reach Slack ({type(e).__name__})") from None
        if resp.status_code == 429:
            raise SlackError(f"{what}: rate limited by Slack, retry after {resp.headers.get('Retry-After', '?')}s")
        return resp

    def call(self, api_method: str, *, json_body: dict | None = None, form: dict | None = None) -> dict:
        resp = self._request(
            "POST", f"{API}/{api_method}", api_method,
            headers={"Authorization": f"Bearer {self._token}"},
            json=json_body, data=form,
        )
        try:
            body = resp.json()
        except ValueError:
            raise SlackError(f"{api_method}: HTTP {resp.status_code}, not a JSON response") from None
        if not body.get("ok"):
            error = body.get("error", f"HTTP {resp.status_code}")
            hint = {
                "not_in_channel": " (invite the app to the channel: /invite @your-app)",
                "channel_not_found": " (check SLACK_CHANNEL_ID, and invite the app if the channel is private)",
                "missing_scope": f" (add the {body.get('needed', 'required')} scope and reinstall the app)",
                "invalid_auth": " (check the bot token)",
            }.get(error, "")
            raise SlackError(f"{api_method}: {error}{hint}")
        return body

    def post_message(self, channel: str, payload: dict) -> str:
        body = self.call("chat.postMessage", json_body={"channel": channel, **payload})
        return body["ts"]

    def open_dm(self, user: str) -> str:
        """The DM channel with one person (conversations.open, needs im:write)."""
        return self.call("conversations.open", json_body={"users": user})["channel"]["id"]

    def update_message(self, channel: str, ts: str, payload: dict) -> None:
        self.call("chat.update", json_body={"channel": channel, "ts": ts, **payload})

    def post_ephemeral(self, channel: str, user: str, text: str) -> None:
        self.call("chat.postEphemeral", json_body={"channel": channel, "user": user, "text": text})

    def open_modal(self, trigger_id: str, view: dict) -> None:
        self.call("views.open", json_body={"trigger_id": trigger_id, "view": view})

    def upload_file(self, channel: str, path: Path, filename: str, title: str, thread_ts: str, comment: str) -> None:
        data = path.read_bytes()
        # 1. Reserve an upload slot.
        slot = self.call("files.getUploadURLExternal", form={"filename": filename, "length": len(data)})
        upload_url, file_id = slot["upload_url"], slot["file_id"]
        # Never send personal data anywhere Slack didn't point us: the URL must be on slack.com over HTTPS.
        parsed = urlparse(upload_url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or not (host == "slack.com" or host.endswith(".slack.com")):
            raise SlackError("files.getUploadURLExternal: upload URL is not on slack.com; refusing to upload")
        # 2. Send the bytes.
        resp = self._request("POST", upload_url, "file upload", files={"file": (filename, data, "application/pdf")})
        if resp.status_code != 200:
            raise SlackError(f"file upload: HTTP {resp.status_code}")
        # 3. Share it as a reply in the summary's thread.
        self.call("files.completeUploadExternal", form={
            "files": json.dumps([{"id": file_id, "title": title}]),
            "channel_id": channel,
            "thread_ts": thread_ts,
            "initial_comment": comment,
        })


def notify(
    settings: SlackSettings,
    payload: dict,
    run_dir: Path,
    title: str = "Okta access review",
    session: requests.Session | None = None,
) -> list[str]:
    """Post the summary (and the PDF, if enabled). Returns what was done, for the console."""
    if not settings.uses_bot:
        post(settings.webhook_url, payload, session=session)
        return ["Posted summary to Slack"]
    bot = BotClient(settings.bot_token, session=session)
    ts = bot.post_message(settings.channel_id, payload)
    done = ["Posted summary to Slack"]
    if settings.attach_pdf:
        bot.upload_file(
            settings.channel_id,
            run_dir / "report.pdf",
            filename=f"okta-access-review-{run_dir.name}.pdf",
            title=f"{title} ({run_dir.name})",
            thread_ts=ts,
            comment=":page_facing_up: Full report. :lock: Contains personal data, so please don't share it outside this channel.",
        )
        done.append("Attached report.pdf in the Slack thread")
    return done
