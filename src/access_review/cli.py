"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import sys
from datetime import date
from pathlib import Path

from . import slack
from .checks import SEVERITIES, Config
from .history import label
from .items import ItemsError
from .mail import EmailConfigError, EmailSettings, build_message, send
from .models import Snapshot
from .okta import OktaClient, OktaError
from .report import ReportError
from .review import run_review
from .roster import RosterError, load_roster

REQUIRED_ENV = ["OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_KEY_ID", "OKTA_PRIVATE_KEY"]
DEFAULT_SCOPES = (
    "okta.users.read okta.groups.read okta.apps.read okta.appGrants.read okta.roles.read "
    "okta.logs.read okta.apiTokens.read"
)


def _client_from_env() -> OktaClient:
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        sys.exit(f"access-review: missing environment variables: {', '.join(missing)} (use ./run.sh)")
    scopes = os.environ.get("OKTA_SCOPES", DEFAULT_SCOPES).split()
    writable = [s for s in scopes if not s.endswith(".read")]
    if writable:
        sys.exit(f"access-review: refusing to request non-read scopes: {', '.join(writable)}")
    return OktaClient(
        org_url=os.environ["OKTA_ORG_URL"],
        client_id=os.environ["OKTA_CLIENT_ID"],
        key_id=os.environ["OKTA_KEY_ID"],
        private_key_pem=os.environ["OKTA_PRIVATE_KEY"],
        scopes=scopes,
        dpop=os.environ.get("OKTA_DPOP", "true").lower() != "false",
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # The review itself takes no positional arguments, so a leading word can only be a subcommand.
    if argv[:1] == ["attest"]:
        from .attest import main as attest

        return attest(argv[1:])

    p = argparse.ArgumentParser(
        prog="access-review", description=__doc__,
        epilog="To sign off a finished review: access-review attest <report folder> --decision approved "
               "--reviewer NAME (see access-review attest --help).",
    )
    p.add_argument("--snapshot", type=Path, help="review a saved snapshot JSON instead of calling Okta")
    p.add_argument("--roster", type=Path, help="HR roster CSV (enables AR-01..AR-03)")
    p.add_argument("--config", type=Path, help="review config JSON")
    p.add_argument("--github", type=Path, help="GitHub snapshot JSON (enables AR-15..AR-17)")
    p.add_argument("--out", type=Path, default=Path("reports"), help="output directory (default: reports)")
    p.add_argument(
        "--as-of", type=date.fromisoformat, help="review date, YYYY-MM-DD (default: UTC date the data was collected)"
    )
    p.add_argument(
        "--fail-on", choices=SEVERITIES,
        help="exit with status 2 if any finding is at this severity or worse",
    )
    p.add_argument("--no-email", action="store_true", help="don't email the report even if REPORT_EMAIL_TO is set")
    p.add_argument("--no-slack", action="store_true", help="don't post to Slack even if Slack is configured")
    args = p.parse_args(argv)

    try:
        config = Config.load(args.config)
    except (ValueError, OSError) as e:
        print(f"access-review: config {args.config}: {e}", file=sys.stderr)
        return 1
    try:
        roster = load_roster(args.roster, config.timezone()) if args.roster else None
    except (RosterError, OSError, KeyError) as e:
        print(f"access-review: roster {args.roster}: {e}", file=sys.stderr)
        return 1
    # Check notification settings before the (slow) collection, so mistakes fail fast.
    try:
        email = None if args.no_email else EmailSettings.from_env()
    except (EmailConfigError, ValueError) as e:
        print(f"access-review: email settings: {e}", file=sys.stderr)
        return 1
    try:
        slack_settings = None if args.no_slack else slack.settings_from_env()
    except slack.SlackConfigError as e:
        print(f"access-review: Slack settings: {e}", file=sys.stderr)
        return 1

    if args.snapshot:
        snapshot = Snapshot.from_dict(json.loads(args.snapshot.read_text()))
    else:
        from .collect import collect

        try:
            snapshot = collect(_client_from_env(), roster, args.as_of,
                               config.activity_lookback_days, config.timezone(),
                               app_usage_days=config.app_unused_days)
        except OktaError as e:
            print(f"access-review: {e}", file=sys.stderr)
            return 1

    # Default to the (UTC) collection date so the review date matches the data.
    as_of = args.as_of or snapshot.collected_at.date()
    try:
        review = run_review(snapshot, roster, args.roster, config, as_of, args.out,
                            github_path=args.github)
    except (ReportError, ItemsError) as e:
        print(f"access-review: {e}", file=sys.stderr)
        return 1
    run_dir, findings, skipped = review.run_dir, review.findings, review.skipped

    for f in findings:
        repeat = f"  [{label(f)}]" if f.reviews_open > 1 or f.reopened else ""
        print(f"{f.severity:<8} {f.check_id}  {f.subject:<32} {f.detail}{repeat}")
    print(f"\n{len(findings)} findings. Report: {run_dir / 'report.md'}")
    if skipped:
        print(f"Skipped (needs data this run did not have): {', '.join(skipped)}")
    if snapshot.gaps:
        print(f"INCOMPLETE: {len(snapshot.gaps)} data gap(s); see the report.")

    # Try every notification even if one fails; the report is already saved.
    notify_failed = False
    if email:
        try:
            send(email, build_message(email, snapshot, findings, run_dir))
            print(f"Emailed report.pdf to {', '.join(email.recipients)}")
        except (OSError, smtplib.SMTPException) as e:
            print(f"access-review: report saved, but emailing it failed: {e}", file=sys.stderr)
            notify_failed = True
    if slack_settings:
        brand = config.branding.get("name", "")
        try:
            payload = slack.build_payload(snapshot, findings, run_dir, brand=brand)
            title = f"{brand} · Okta access review" if brand else "Okta access review"
            for line in slack.notify(slack_settings, payload, run_dir, title=title):
                print(line)
        except slack.SlackError as e:
            print(f"access-review: report saved, but posting to Slack failed: {e}", file=sys.stderr)
            notify_failed = True
    if notify_failed:
        return 3

    if args.fail_on:
        limit = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= limit for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
