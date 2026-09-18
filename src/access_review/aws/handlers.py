"""Lambda entry points. One container image; each function sets its handler.

    collect    Step Functions: read Okta, write the review to the evidence bucket
    open       Step Functions (.waitForTaskToken): open tickets, post to Slack
    interact   Function URL: Slack's interactivity endpoint (front end only)
    worker     async, invoked by interact: record decisions, sign off
    remediate  Step Functions, after sign-off: open revoke tickets
    failed     Step Functions catch: say in the channel that the run stopped
    watch      hourly schedule: reminders, escalations, overdue tickets
    verify     daily schedule: check resolved tickets against Okta

Handlers only wire settings, secrets and clients together; the logic lives in
the modules they call, which are tested without AWS. Return values reach
Step Functions, so they hold IDs, hashes and counts only.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from datetime import datetime, timezone
from functools import cache
from pathlib import Path

import boto3

from .. import slack_review as msgs
from .. import store, watch, workflow
from ..checks import Config, ReviewContext, run_checks
from ..cli import DEFAULT_SCOPES
from ..collect import collect as collect_okta
from ..items import summary
from ..jira import JiraClient
from ..okta import OktaClient
from ..report import run_dir_name
from ..review import run_review
from ..roster import load_roster
from ..settings import JiraSettings, OktaSettings, Settings, SettingsError, _env, get_secret
from ..slack import BotClient
from ..slack_interact import ItemCache, front, worker as run_worker
from ..tickets import Remediation

INPUTS = "inputs/"


@cache
def _settings() -> Settings:
    return Settings.from_env()


@cache
def _client(name: str):
    return boto3.client(name)


@cache
def _secret(env_name: str) -> str:
    return get_secret(_client("ssm"), env_name)


def _jira() -> JiraClient:
    j = JiraSettings.from_env()
    return JiraClient(j.base_url, j.email, _secret("JIRA_API_TOKEN_PARAM"), j.project)


def _deps(tickets: bool = False, sfn: bool = False) -> workflow.Deps:
    s = _settings()
    remediation = None
    if tickets:
        j = JiraSettings.from_env()
        remediation = Remediation(_jira(), _client("s3"), s.evidence_bucket, j.parent_type, j.child_type,
                                  s.leaver_ticket_hours, s.revoke_ticket_days)
    return workflow.Deps(
        s3=_client("s3"), evidence_bucket=s.evidence_bucket, work_bucket=s.work_bucket,
        bot=BotClient(_secret("SLACK_BOT_TOKEN_PARAM")), reviewers=s.reviewers, channel=s.slack_channel,
        tickets=remediation, sfn=_client("stepfunctions") if sfn else None, review_days=s.review_days,
    )


def _okta() -> OktaClient:
    o = OktaSettings.from_env()
    scopes = DEFAULT_SCOPES.split()
    if any(not s.endswith(".read") for s in scopes):  # the read-only rule, checked where it's used
        raise SettingsError("refusing to request a scope that doesn't end in .read")
    return OktaClient(o.org_url, o.client_id, o.key_id, _secret("OKTA_PRIVATE_KEY_PARAM"), scopes, dpop=True)


def _inputs(tmp: Path) -> tuple[Config, Path, dict]:
    """config.json and roster.csv from the work bucket's inputs/ prefix."""
    s3, bucket = _client("s3"), _settings().work_bucket
    config_path, roster_path = tmp / "config.json", tmp / "roster.csv"
    config_path.write_bytes(store.get_bytes(s3, bucket, f"{INPUTS}config.json"))
    roster_path.write_bytes(store.get_bytes(s3, bucket, f"{INPUTS}roster.csv"))
    config = Config.load(config_path)
    if not config.admin_login:
        raise SettingsError("inputs/config.json must set admin_login")
    return config, roster_path, load_roster(roster_path, config.timezone())


# --- Step Functions -------------------------------------------------------------

def collect(event, context):
    s = _settings()
    s3 = _client("s3")
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        config, roster_path, roster = _inputs(tmp)
        as_of = datetime.now(timezone.utc).date()
        snapshot = collect_okta(_okta(), roster, as_of, config.activity_lookback_days, config.timezone(),
                                app_usage_days=config.app_unused_days)
        out = tmp / "out"
        store.fetch_history(s3, s.evidence_bucket, out, before=run_dir_name(snapshot), limit=config.history_reviews)
        review = run_review(snapshot, roster, roster_path, config, as_of, out, require_items=True)
        manifest_sha = store.upload_run(s3, s.evidence_bucket, review.run_dir)
    return {
        "run": review.run_dir.name,
        "manifest_sha256": manifest_sha,
        "findings": dict(Counter(f.severity for f in review.findings)),
        "items": summary(review.items),
        "complete": not snapshot.gaps,
    }


def open_review(event, context):
    return workflow.open_review(_deps(tickets=True), event["run"], event["task_token"])


def remediate(event, context):
    return workflow.remediate(_deps(tickets=True), event["run"])


def failed(event, context):
    """The execution stopped before finishing (an error, or no sign-off within
    the wait limit). Counts only: the cause stays in the execution history."""
    run = str((event or {}).get("run") or "unknown")
    s = _settings()
    BotClient(_secret("SLACK_BOT_TOKEN_PARAM")).post_message(s.slack_channel, msgs.channel_note(
        f":x: Okta access review `{run}` stopped before it finished. Check the Step Functions execution."))
    return {"run": run, "notified": True}


# --- Slack ------------------------------------------------------------------------

@cache
def _items() -> ItemCache:
    return ItemCache(_client("s3"), _settings().evidence_bucket)


def interact(event, context):
    worker_name = _env("WORKER_FUNCTION")

    def enqueue(job: dict) -> None:
        _client("lambda").invoke(FunctionName=worker_name, InvocationType="Event", Payload=json.dumps(job).encode())

    s = _settings()
    return front(event, _secret("SLACK_SIGNING_SECRET_PARAM"), s.reviewers, _items(),
                 BotClient(_secret("SLACK_BOT_TOKEN_PARAM")), enqueue)


def worker(event, context):
    return run_worker(event, _deps(sfn=True))


# --- schedules --------------------------------------------------------------------

def watch_hourly(event, context):
    return watch.hourly(_deps(sfn=True), _jira())


def verify_daily(event, context):
    with tempfile.TemporaryDirectory() as tmp_name:
        config, _, roster = _inputs(Path(tmp_name))
    as_of = datetime.now(timezone.utc).date()
    snapshot = collect_okta(_okta(), roster, as_of, config.activity_lookback_days, config.timezone())
    findings, _ = run_checks(ReviewContext(snapshot, roster, config, as_of))
    return watch.daily(_deps(), _jira(), snapshot, watch.leaver_access(findings, snapshot))
