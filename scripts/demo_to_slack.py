"""Send a demo review, with the made-up fixture company, to the real Slack and JSM.

    uv run python scripts/demo_to_slack.py            # real Slack and JSM (asks first)
    uv run python scripts/demo_to_slack.py --dry-run  # fakes only, nothing leaves this machine

For README screenshots: every name comes from fixtures/ (acme.example), and the
messages and tickets are made by the same code the Lambdas run. It posts to the
deployed review channel and the CISO's DM, and opens tickets in the deployed JSM
project, reading those settings from the uar-remediate Lambda and the tokens
from SSM. Evidence and review state stay in memory: nothing is written to the
evidence bucket, and the hourly and daily jobs never see the demo.

It pauses between stages so you can take screenshots, and records the CISO's
decisions itself. Don't click the buttons on the demo messages: the live Slack
endpoint looks for the review in the evidence bucket and won't find it.
Needs AWS credentials for the account (AWS_PROFILE).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from fakes import FakeBot, FakeS3, FakeSfn  # noqa: E402

from access_review import store, workflow  # noqa: E402
from access_review.checks import Config  # noqa: E402
from access_review.decisions import Reviewers  # noqa: E402
from access_review.items import DECIDE, KEEP, REVOKE  # noqa: E402
from access_review.jira import adf, browse_url  # noqa: E402
from access_review.models import Snapshot  # noqa: E402
from access_review.review import run_review  # noqa: E402
from access_review.roster import load_roster  # noqa: E402
from access_review.tickets import Remediation  # noqa: E402

FIXTURES = ROOT / "fixtures"
REVIEW_DATE = date(2026, 9, 15)  # the fixtures are written for this review date
DEMO_OKTA = "https://acme-demo.okta.com"
OVERRIDE_REASON = "Needed for the quarter-end close; review again next quarter."


def pause(what: str, interactive: bool) -> None:
    print(f"\n>>> {what}")
    if interactive:
        input(">>> Take your screenshots, then press Enter to continue… ")


def deployed_settings() -> dict:
    """The review's settings as deployed, from the uar-remediate Lambda (it has both Slack and Jira)."""
    import boto3

    env = boto3.client("lambda").get_function_configuration(FunctionName="uar-remediate")["Environment"]["Variables"]
    os.environ.update({k: v for k, v in env.items() if k.endswith("_PARAM")})
    return env


def real_clients(env: dict):
    import boto3

    from access_review.jira import JiraClient
    from access_review.settings import get_secret
    from access_review.slack import BotClient

    ssm = boto3.client("ssm")
    bot = BotClient(get_secret(ssm, "SLACK_BOT_TOKEN_PARAM"))
    jira = JiraClient(env["JIRA_BASE_URL"], env["JIRA_EMAIL"], get_secret(ssm, "JIRA_API_TOKEN_PARAM"),
                      env["JIRA_PROJECT"])
    return bot, jira


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="fake Slack and Jira; nothing leaves this machine")
    args = p.parse_args(argv)

    if args.dry_run:
        from test_watch import FakeJira

        env = {"SLACK_CHANNEL_ID": "C0REVIEW001", "SLACK_CISO_USER": "U0CISO00001",
               "JIRA_BASE_URL": "https://acme.atlassian.net", "JIRA_PROJECT": "UAR",
               "JIRA_PARENT_TYPE": "Task", "JIRA_CHILD_TYPE": "Sub-task"}
        bot, jira = FakeBot(), FakeJira()
        jira.today = date.today().isoformat()
    else:
        env = deployed_settings()
        print(f"This sends a DEMO review (made-up names from fixtures/) to:\n"
              f"  - Slack channel {env['SLACK_CHANNEL_ID']} and the CISO's DM ({env['SLACK_CISO_USER']})\n"
              f"  - JSM project {env['JIRA_PROJECT']}: about 19 tickets\n"
              f"Nothing goes to AWS storage. Don't click the buttons on the demo messages.")
        if input("Type 'demo' to continue: ").strip() != "demo":
            print("Stopped; nothing was sent.")
            return 1
        bot, jira = real_clients(env)

    # The fixture company, reviewed as of the fixtures' date, but with a run name
    # from now so each demo gets its own tickets.
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    snapshot.collected_at = datetime.now(timezone.utc).replace(microsecond=0)
    config = Config.load(FIXTURES / "demo_config.json")
    roster_path = FIXTURES / "demo_roster.csv"
    s3 = FakeS3()
    with tempfile.TemporaryDirectory() as tmp:
        run_data = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                              REVIEW_DATE, Path(tmp), require_items=True)
        store.upload_run(s3, "evidence", run_data.run_dir)
    run = run_data.run_dir.name
    items = {i.key: i for i in run_data.items}

    reviewers = Reviewers(ciso=env["SLACK_CISO_USER"])
    tickets = Remediation(jira, s3, "evidence", env.get("JIRA_PARENT_TYPE", "Task"),
                          env.get("JIRA_CHILD_TYPE", "Sub-task"), okta_org_url=DEMO_OKTA)
    deps = workflow.Deps(
        s3=s3, evidence_bucket="evidence", work_bucket="work", bot=bot, reviewers=reviewers,
        channel=env["SLACK_CHANNEL_ID"], tickets=tickets, sfn=FakeSfn(), channel_pdf=True,
        ticket_url=lambda key: browse_url(env["JIRA_BASE_URL"], key),
    )
    interactive = not args.dry_run
    src = {"channel": "demo"}

    print(f"\nDemo review {run}: opening…")
    workflow.open_review(deps, run, "demo-task-token")
    pause("1. OPEN: the channel post (and the PDF in its thread), the CISO's DM with the undecided "
          "cards, and the tracking + leaver tickets in JSM.", interactive)

    # One override with a reason, so the sign-off shows how that reads.
    override = next((k for k, i in sorted(items.items(), key=lambda kv: kv[1].user)
                     if i.proposed == REVOKE and i.via == "direct" and "left" not in i.reason), None)
    if override:
        workflow.record(deps, run, [(override, KEEP, OVERRIDE_REASON)], reviewers.ciso, src)
    workflow.confirm(deps, run, reviewers.ciso, src)
    for key, item in items.items():
        if item.proposed == DECIDE:
            workflow.record(deps, run, [(key, KEEP, "")], reviewers.ciso, src)
    pause("2. DECIDED: the cards now show each decision, and the sign-off message with every decision "
          "and Approve review is in the CISO's DM (the PDF is in its thread).", interactive)

    workflow.approve(deps, run, reviewers.ciso, src)
    out = workflow.remediate(deps, run)
    records = [r for _, r in store.list_records(s3, "evidence", run, "tickets")]
    print(f"\n3. SIGNED OFF: {out['revoke_tickets']} revoke and {out['fix_tickets']} fix tickets; the checklist is "
          f"in the approval thread and the finished summary in the channel thread.")
    for r in sorted(records, key=lambda r: int(r["issue"].split("-")[1])):
        print(f"   {r['issue']:10} {r['kind']:7} {r.get('todo', '')[:90]}")

    if args.dry_run:
        print(f"\nDry run: {len(bot.posts)} Slack posts, {len(bot.updates)} updates, "
              f"{len(bot.uploads)} uploads, {len(jira.issues)} tickets (all fake).")
        return 0

    pause("3. Screenshot the checklist, the finished summary and the tickets.", interactive)
    if input(f"Close the {len(records)} demo tickets in {env['JIRA_PROJECT']} now? [y/N] ").strip().lower() == "y":
        note = adf("Demo data (made-up names from the fixtures) for README screenshots. Closed; not a real finding.")
        for r in sorted(records, key=lambda r: r["kind"] == "parent"):  # sub-tickets before the parent
            jira.add_comment(r["issue"], note)
            jira.close(r["issue"])
        print("Closed.")
    else:
        print("Left open. Close them later in JSM (they're labelled access-review).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
