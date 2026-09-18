"""Settings for the AWS deployment, from Lambda environment variables, and
secrets from SSM Parameter Store.

Terraform sets the environment. Secrets are never in it: the environment holds
the *names* of SecureString parameters under /uar/, and each Lambda role can
read only the parameters it needs. A name outside /uar/ is refused without
being echoed, like run.sh does for 1Password references.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .decisions import Reviewers
from .jira import check_base_url
from .slack import CHANNEL_ID

PARAM = re.compile(r"^/uar/[a-z0-9_/-]{1,200}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


class SettingsError(ValueError):
    pass


def _env(name: str, required: bool = True, default: str = "") -> str:
    value = os.environ.get(name, default).strip()
    if required and not value:
        raise SettingsError(f"missing environment variable {name}")
    return value


def _int(name: str, default: int) -> int:
    raw = _env(name, required=False, default=str(default))
    if not raw.isdigit() or int(raw) < 1:
        raise SettingsError(f"{name} must be a whole number of at least 1")
    return int(raw)


def param_name(env_name: str) -> str:
    name = _env(env_name)
    if not PARAM.match(name):
        raise SettingsError(f"{env_name} must name an SSM parameter under /uar/ (value not shown)")
    return name


def get_secret(ssm, env_name: str) -> str:
    """Read one SecureString. Errors name the variable, never the value."""
    name = param_name(env_name)
    try:
        value = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except Exception as e:
        code = str(getattr(e, "response", {}).get("Error", {}).get("Code", "")) or type(e).__name__
        raise SettingsError(f"could not read the parameter named by {env_name} ({code})") from None
    if not value or value == "placeholder":
        raise SettingsError(f"the parameter named by {env_name} has no value yet; set it with aws ssm put-parameter")
    return value


@dataclass(frozen=True)
class Settings:
    evidence_bucket: str
    work_bucket: str
    slack_channel: str
    reviewers: Reviewers
    review_days: int
    leaver_ticket_hours: int
    revoke_ticket_days: int

    @classmethod
    def from_env(cls) -> Settings:
        evidence, work = _env("EVIDENCE_BUCKET"), _env("WORK_BUCKET")
        for name, bucket in (("EVIDENCE_BUCKET", evidence), ("WORK_BUCKET", work)):
            if not BUCKET.match(bucket):
                raise SettingsError(f"{name} is not a bucket name")
        channel = _env("SLACK_CHANNEL_ID")
        if not CHANNEL_ID.match(channel):
            raise SettingsError("SLACK_CHANNEL_ID must be a channel ID like C0123ABCDEF")
        try:
            reviewers = Reviewers(ciso=_env("SLACK_CISO_USER"))
        except ValueError as e:
            raise SettingsError(str(e)) from None
        return cls(evidence, work, channel, reviewers, _int("REVIEW_DAYS", 7),
                   _int("LEAVER_TICKET_HOURS", 24), _int("REVOKE_TICKET_DAYS", 7))


@dataclass(frozen=True)
class OktaSettings:
    org_url: str
    client_id: str
    key_id: str

    @classmethod
    def from_env(cls) -> OktaSettings:
        org = _env("OKTA_ORG_URL")
        if not re.fullmatch(r"https://[a-z0-9-]+\.(okta|oktapreview|okta-emea)\.com", org):
            raise SettingsError("OKTA_ORG_URL must be https://<org>.okta.com")
        return cls(org, _env("OKTA_CLIENT_ID"), _env("OKTA_KEY_ID"))


@dataclass(frozen=True)
class JiraSettings:
    base_url: str
    email: str
    project: str
    parent_type: str
    child_type: str

    @classmethod
    def from_env(cls) -> JiraSettings:
        return cls(check_base_url(_env("JIRA_BASE_URL")), _env("JIRA_EMAIL"), _env("JIRA_PROJECT"),
                   _env("JIRA_PARENT_TYPE", required=False, default="Task"),
                   _env("JIRA_CHILD_TYPE", required=False, default="Subtask"))
