"""Walk one whole review through the workflow locally, on the demo fixtures.

    uv run python scripts/e2e_local.py

Nothing leaves this machine: S3, Slack, Jira and Step Functions are the
in-memory fakes from tests/fakes.py. It prints what each system would have
received, so you can see the messages and tickets before deploying.
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from fakes import FakeBot, FakeS3, FakeSfn  # noqa: E402

from access_review import store, watch, workflow  # noqa: E402
from access_review.checks import Config  # noqa: E402
from access_review.decisions import Reviewers  # noqa: E402
from access_review.items import ADMIN, CISO, DECIDE, KEEP  # noqa: E402
from access_review.models import Snapshot  # noqa: E402
from access_review.review import run_review  # noqa: E402
from access_review.roster import load_roster  # noqa: E402
from access_review.tickets import Remediation  # noqa: E402

FIXTURES = ROOT / "fixtures"
R = Reviewers(admin="U0ADMIN0001", ciso="U0CISO00001")


class PrintingJira:
    project = "UAR"

    def __init__(self):
        self.issues = {}

    def search(self, jql, fields, limit=1000):
        if 'labels = "uar-key-' in jql:
            label = jql.split('labels = "')[1].rstrip('"')
            return [{"key": k, "fields": {}} for k, f in self.issues.items() if label in f["labels"]]
        return []

    def create_issue(self, fields):
        key = f"UAR-{len(self.issues) + 1}"
        self.issues[key] = fields
        parent = f" (under {fields['parent']['key']})" if "parent" in fields else ""
        print(f"  JSM  {key}{parent}  due {fields.get('duedate')}  {fields['summary']}")
        return key

    def add_comment(self, key, body):
        text = " ".join(n.get("text", "") for p in body["content"] for n in p.get("content", []))
        print(f"  JSM  comment on {key}: {text[:110]}")


def slack_text(payload: dict) -> str:
    parts = [b["text"]["text"] for b in payload.get("blocks", []) if b.get("type") == "section"]
    return (parts[0] if parts else payload.get("text", "")).replace("\n", " / ")[:150]


def main() -> int:
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    config.admin_login = "priya.shah@acme.example"
    roster_path = FIXTURES / "demo_roster.csv"
    now = [datetime(2026, 9, 15, 15, tzinfo=timezone.utc)]
    clock = lambda: now[0]  # noqa: E731

    with tempfile.TemporaryDirectory() as tmp:
        print("1. Collect (demo snapshot instead of Okta)")
        run = run_review(snapshot, load_roster(roster_path, config.timezone()), roster_path, config,
                         date(2026, 9, 15), Path(tmp), require_items=True)
        s3 = FakeS3()
        sha = store.upload_run(s3, "evidence", run.run_dir)
        print(f"  S3   runs/{run.run_dir.name}/  manifest {sha[:16]}…  {len(run.items)} review items")

    jira, bot = PrintingJira(), FakeBot()
    deps = workflow.Deps(s3=s3, evidence_bucket="evidence", work_bucket="work", bot=bot, reviewers=R,
                         channel="C0REVIEW001", sfn=FakeSfn(), now=clock,
                         tickets=Remediation(jira, s3, "evidence", "Task", "Subtask", now=clock))
    name = run.run_dir.name
    items = {i.key: i for i in run.items}

    def show_slack(since: int) -> None:
        for channel, payload, _ in bot.posts[since:]:
            where = "channel" if channel == deps.channel else ("admin DM" if channel == "D0ADMIN0001" else "CISO DM")
            print(f"  Slack {where:9} {slack_text(payload)}")

    print("\n2. Open the review (Step Functions now waits for the sign-off)")
    seen = len(bot.posts)
    workflow.open_review(deps, name, "task-token")
    show_slack(seen)

    print("\n3. Three days pass")
    now[0] += timedelta(days=3, hours=1)
    seen = len(bot.posts)
    watch.hourly(deps, jira)
    show_slack(seen)

    print("\n4. The admin and the CISO decide")
    seen = len(bot.posts)
    for role, user in ((ADMIN, R.admin), (CISO, R.ciso)):
        workflow.confirm(deps, name, role, user, {"channel": "D" + user[1:]})
        for key, item in items.items():
            if item.reviewer == role and item.proposed == DECIDE:
                workflow.record(deps, name, [(key, KEEP, "")], user, {"channel": "D" + user[1:]})
    show_slack(seen)
    print(f"  Slack uploads: {[u[1] for u in bot.uploads]}")

    print("\n5. The CISO approves")
    seen = len(bot.posts)
    out = workflow.approve(deps, name, R.ciso, {"channel": "D0CISO00001"})
    show_slack(seen)
    print(f"  Step Functions callback: {deps.sfn.successes[0][1]}")

    print("\n6. Remediate")
    seen = len(bot.posts)
    workflow.remediate(deps, name)
    show_slack(seen)

    records = {k.split("/")[2] for (_, k) in s3.objects if k.count("/") == 3}
    print(f"\nEvidence records written: {sorted(records)}; {out['revoke']} revoke decision(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
