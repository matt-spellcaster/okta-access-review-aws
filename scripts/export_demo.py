"""Export the Acme demo review, step by step, as data a web page can replay.

    uv run python scripts/export_demo.py --out <dir> [--variant okta|github|incomplete|github-incomplete|all]

Each variant writes three files into <dir>:

    <variant>.json          what a page needs to replay the review: the run's
                            review_items.json and manifest.json exactly as they
                            were hashed, every item with the pieces its Slack
                            card, sign-off line and revoke ticket are built
                            from, the messages and tickets that open the review,
                            the fix tickets, and the one-byte changes the
                            evidence check is shown with
    <variant>.golden.json   four scripted reviews run through the real workflow:
                            every Slack call, Jira call and evidence record, the
                            signed decisions.json, and what `access-review
                            attest` prints for the signed run, intact and with
                            one byte changed. A replay of the same steps has to
                            match it byte for byte.
    <variant>.pdf           the run's report

The variants: okta is the demo snapshot alone, as every AWS run reads it; github
adds the demo GitHub estate; incomplete and github-incomplete are those two with
the System Log's app sign-ins refused (a 403), so no unused access can be
proposed for revocation.

Nothing leaves this machine. The review runs on the fixtures, and S3, Slack,
Jira and Step Functions are the in-memory fakes from tests/fakes.py. The clocks
are fixed and the decision record IDs are counted, so one commit always writes
the same bytes. The output is stamped with that commit, so a tree with
uncommitted changes is refused.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import dataclasses
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "scripts")]

from demo_to_slack import OVERRIDE_REASON  # noqa: E402
from fakes import FakeBot, FakeS3, FakeSfn  # noqa: E402

from access_review import __version__, attest, collect, store, workflow  # noqa: E402
from access_review import slack_review as msgs  # noqa: E402
from access_review.checks import Config  # noqa: E402
from access_review.csvsafe import read_rows  # noqa: E402
from access_review.decisions import DecisionError, Reviewers  # noqa: E402
from access_review.items import ACKNOWLEDGE_ONLY, DECIDE, ITEMS_FILE, KEEP, LINK_MARKER, REVOKE  # noqa: E402
from access_review.models import Snapshot  # noqa: E402
from access_review.okta import OktaError, admin_url  # noqa: E402
from access_review.review import run_review  # noqa: E402
from access_review.roster import load_roster  # noqa: E402
from access_review.tickets import Remediation  # noqa: E402

FORMAT = 1
REPO = "matt-spellcaster/okta-access-review-aws"
FIXTURES = ROOT / "fixtures"
VARIANTS = {  # name: (read the GitHub estate, app sign-ins refused)
    "okta": (False, False),
    "github": (True, False),
    "incomplete": (False, True),
    "github-incomplete": (True, True),
}
REVIEW_DATE = date(2026, 9, 15)  # the fixtures are written for this review date
OPENED = datetime(2026, 9, 15, 15, tzinfo=timezone.utc)
DECIDED = datetime(2026, 9, 18, 16, tzinfo=timezone.utc)
CISO = "U0CISO00001"
CHANNEL = "C0REVIEW001"
EVIDENCE, WORK = "acme-uar-evidence", "acme-uar-work"
TASK_TOKEN = "demo-task-token"
# Stands in for a reason while the text around it is built, so the page can put
# the reviewer's own in its place. A private-use character: no text the tool
# writes contains one.
SLOT = "\ue000"
# Reasons for the scripted reviews. D's are the awkward ones: Slack's control
# characters, text that already looks escaped, spaces to strip, and characters
# outside the Basic Multilingual Plane, which count once here and twice in a
# UTF-16 string.
REVOKE_ALL_REASON = "Starting clean: everything is revoked this quarter and requested again."
D_REASONS = (
    "R&D <needs> it & so does Ops; &amp; is not an entity here",
    "   Signed off by the owner \U0001f510, see the <#C0REVIEW001> thread   ",
    # 160 code points, the most the demo page takes, and 272 UTF-16 units.
    "Kept \U0001f44d\U0001f3fd for the audit & the migration. " + "\u00e9" * 10 + " " + "\U0001f9ea" * 110,
)
BAD_REASONS = ("", "two\nlines")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True).stdout.strip()


def dumps(doc: object) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def sha256(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


# --- fakes ---------------------------------------------------------------------


class RecordingBot(FakeBot):
    """FakeBot, keeping every call in the order it was made."""

    def __init__(self):
        super().__init__()
        self.log: list[dict] = []

    def post_message(self, channel, payload):
        ts = super().post_message(channel, payload)
        self.log.append({"call": "post", "channel": channel, "ts": ts, "payload": copy.deepcopy(payload)})
        return ts

    def update_message(self, channel, ts, payload):
        super().update_message(channel, ts, payload)
        self.log.append({"call": "update", "channel": channel, "ts": ts, "payload": copy.deepcopy(payload)})

    def upload_file(self, channel, path, filename, title, thread_ts, comment):
        super().upload_file(channel, path, filename, title, thread_ts, comment)
        self.log.append({"call": "upload", "channel": channel, "thread_ts": thread_ts, "filename": filename,
                         "title": title, "comment": comment, "sha256": sha256(path.read_bytes())})


class DemoJira:
    """The JiraClient surface tickets.py uses, keeping every ticket and comment body."""

    project = "UAR"

    def __init__(self):
        self.issues: dict[str, dict] = {}
        self.log: list[dict] = []

    def search(self, jql, fields, limit=1000):
        label = jql.split('labels = "')[1].split('"')[0] if 'labels = "' in jql else None
        return [{"key": k, "fields": {}} for k, f in self.issues.items() if label in f["labels"]][:limit]

    def create_issue(self, fields):
        key = f"{self.project}-{len(self.issues) + 1}"
        self.issues[key] = copy.deepcopy(fields)
        self.log.append({"call": "create", "key": key, "fields": copy.deepcopy(fields)})
        return key

    def add_comment(self, key, body):
        self.log.append({"call": "comment", "key": key, "body": copy.deepcopy(body)})


class RefusingOkta:
    """An Okta client whose System Log read is refused, as it is without the scope or the admin role."""

    def get_capped(self, path, params=None, max_items=1000):
        raise OktaError(403, "You do not have permission to perform the requested action")


def counted_uuids():
    """uuid4 for decision record names: UUID(int=n << 80) puts n in the 12 hex
    digits the name keeps. UUID(int=n) would leave those all zero, and with the
    clock fixed, every record after the first would be refused as already written."""
    n = iter(range(1, 1 << 48))
    return mock.patch.object(uuid, "uuid4", lambda: uuid.UUID(int=next(n) << 80))


# --- the review ----------------------------------------------------------------


def review(variant: str, out: Path):
    github, refused = VARIANTS[variant]
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    config = Config.load(FIXTURES / "demo_config.json")
    if refused:
        # The read collect() makes, through the same wrapper, so the gap is worded as a live run words it.
        gaps: list[str] = []
        api = collect._Optional(RefusingOkta(), "System Log app sign-ins", "okta.logs.read",
                                "AR-14 and review proposals", gaps)
        with contextlib.redirect_stderr(io.StringIO()):
            usage, since, complete = collect._collect_app_usage(api, REVIEW_DATE, config.app_unused_days, gaps)
        snapshot = dataclasses.replace(snapshot, app_usage=usage, app_usage_since=since,
                                       app_usage_complete=complete, gaps=[*snapshot.gaps, *gaps])
    roster = FIXTURES / "demo_roster.csv"
    return run_review(snapshot, load_roster(roster, config.timezone()), roster, config, REVIEW_DATE, out,
                      require_items=True, github_path=FIXTURES / "demo_github.json" if github else None)


class Session:
    """One review in the in-memory workflow, from open to remediation."""

    def __init__(self, run_dir: Path, org_url: str):
        self.now = OPENED
        self.s3, self.bot, self.jira, self.sfn = FakeS3(), RecordingBot(), DemoJira(), FakeSfn()
        store.upload_run(self.s3, EVIDENCE, run_dir)
        self.run = run_dir.name
        clock = lambda: self.now  # noqa: E731
        self.deps = workflow.Deps(
            s3=self.s3, evidence_bucket=EVIDENCE, work_bucket=WORK, bot=self.bot, reviewers=Reviewers(ciso=CISO),
            channel=CHANNEL, sfn=self.sfn, now=clock,
            tickets=Remediation(self.jira, self.s3, EVIDENCE, "Task", "Sub-task", now=clock, okta_org_url=org_url))
        self.source = {"channel": self.bot.open_dm(CISO)}
        self.opened = workflow.open_review(self.deps, self.run, TASK_TOKEN)

    def step(self, step: dict) -> dict:
        self.now = DECIDED
        try:
            if step["do"] == "confirm":
                return workflow.confirm(self.deps, self.run, CISO, self.source)
            if step["do"] == "record":
                return workflow.record(self.deps, self.run, [tuple(c) for c in step["choices"]], CISO, self.source)
            if step["do"] == "approve":
                return {"approve": workflow.approve(self.deps, self.run, CISO, self.source),
                        "remediate": workflow.remediate(self.deps, self.run)}
        except DecisionError as e:
            return {"error": str(e)}
        raise ValueError(f"unknown step {step['do']!r}")

    def evidence(self, kind: str) -> dict[str, str]:
        prefix = f"{store.RUNS}{self.run}/{kind}/"
        return {k[len(prefix):]: body.decode() for (b, k), body in sorted(self.s3.objects.items())
                if b == EVIDENCE and k.startswith(prefix)}


# --- what the page is built from -------------------------------------------------


def card_order(items):
    return [i for part in msgs.chunks(items) for i in part]


def finding_for(text: str, rows: list[dict]) -> dict | None:
    """The finding a concern was written from, by the text items.py writes."""
    hits = {(r["check_id"], r["severity"]) for r in rows
            if text == f"{r['detail']} ({r['check_id']} {r['title']})"
            or text.startswith(f"{r['detail']} ({r['check_id']} {r['title']}{LINK_MARKER}")}
    if len(hits) > 1:
        raise SystemExit(f"a concern matches findings of different severities: {text!r}")
    return dict(zip(("check_id", "severity"), hits.pop())) if hits else None


def signoff_lines(item) -> list[str]:
    """The item's lines on the sign-off message, up to where the decision's own
    line goes. An item that is only acknowledged has no such line, so it is whole."""
    decision = {"decision": KEEP, "reason": SLOT, "decided_by": CISO, "decided_at": "", "record": ""}
    [entry] = [e for group in msgs.decision_lines([item], {item.key: decision}).values() for e in group]
    lines = entry.split("\n")
    if item.kind in ACKNOWLEDGE_ONLY:
        assert SLOT not in entry
        return lines
    assert SLOT in lines[-1] and not any(SLOT in line for line in lines[:-1])
    return lines[:-1]


def revoke_ticket(run: str, item, org_url: str) -> dict:
    """The ticket a Revoke of this item opens, with SLOT where the reason goes."""
    s3, jira = FakeS3(), DemoJira()
    tickets = Remediation(jira, s3, EVIDENCE, "Task", "Sub-task", now=lambda: DECIDED, okta_org_url=org_url)
    tickets.open_revokes(run, "UAR-1", {item.key: item}, {item.key: {"decision": REVOKE, "reason": SLOT}})
    [(_, fields)] = jira.issues.items()
    [(_, record)] = [r for r in store.list_records(s3, EVIDENCE, run, "tickets")]
    return {"fields": fields, "todo": record["todo"], "due": record["due"], "label": record["label"]}


def fix_tickets(session: Session) -> list[dict]:
    """The fix tickets remediation opens, in order; they don't depend on the decisions."""
    s3, jira = FakeS3(), DemoJira()
    tickets = Remediation(jira, s3, EVIDENCE, "Task", "Sub-task", now=lambda: DECIDED,
                          okta_org_url=session.deps.tickets.okta_org_url)
    tickets.open_findings(session.run, "UAR-1", workflow.all_findings(session.deps, session.run),
                          workflow.people(session.deps, session.run))
    records = {r["label"]: r for _, r in store.list_records(s3, EVIDENCE, session.run, "tickets")}
    return [{"fields": f, **{k: records[f["labels"][1]][k] for k in ("todo", "due", "verify", "check_id", "label")}}
            for f in jira.issues.values()]


def tampers(files: dict[str, str]) -> list[dict]:
    """One-byte changes to the signed run, each one a change somebody might want."""
    manifest = json.loads(files["manifest.json"])
    critical = manifest["finding_counts"]["critical"]
    decided = re.search(r'"decided_at": "\d{4}-\d\d-(\d\d)', files["signoff/decisions.json"])
    day = int(decided.group(1))
    wanted = [
        ("manifest.json", f'"critical": {critical},', f'"critical": {critical - 1},',
         "hide one critical finding"),
        (ITEMS_FILE, '"app_unused_days": 90,', '"app_unused_days": 30,',
         "change the rule the proposals followed"),
        ("signoff/decisions.json", decided.group(0), decided.group(0)[:-2] + f"{day - 1:02d}",
         "backdate a decision by a day"),
    ]
    out = []
    for name, find, replace, why in wanted:
        body = files[name].encode()
        at = body.find(find.encode())
        diff = [n for n, (a, b) in enumerate(zip(find.encode(), replace.encode())) if a != b]
        if at < 0 or len(find.encode()) != len(replace.encode()) or len(diff) != 1:
            raise SystemExit(f"can't make a one-byte change to {name}: {find!r}")
        offset = at + diff[0]
        out.append({"file": name, "offset": offset, "from": chr(body[offset]),
                    "to": chr(replace.encode()[diff[0]]), "why": why})
    return out


def attest_outputs(session: Session, changes: list[dict]) -> dict[str, str]:
    """What `access-review attest reports/<run>` prints for the signed run as
    downloaded from S3, intact and with each change made."""
    prefix = f"{store.RUNS}{session.run}/"
    out = {}
    for change in [None, *changes]:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "reports" / session.run
            for (bucket, key), body in session.s3.objects.items():
                if bucket == EVIDENCE and key.startswith(prefix):
                    path = folder / key[len(prefix):]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
            if change:
                path = folder / change["file"]
                body = bytearray(path.read_bytes())
                assert chr(body[change["offset"]]) == change["from"]
                body[change["offset"]] = ord(change["to"])
                path.write_bytes(bytes(body))
            printed = io.StringIO()
            cwd = Path.cwd()
            os.chdir(tmp)
            try:
                with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
                    code = attest.main([f"reports/{session.run}"])
            finally:
                os.chdir(cwd)
            out[change["file"] if change else "intact"] = f"{printed.getvalue()}exit {code}\n"
    return out


# --- the scripted reviews -------------------------------------------------------


def scenarios(items) -> dict[str, list[dict]]:
    """A: confirm the proposals, then keep what needed a call. B: first keep one
    proposed revoke, with a reason (as scripts/demo_to_slack.py does), then as A.
    C: revoke everything that can be revoked, one click at a time. D: awkward
    reasons, refused reasons, and a change of mind."""
    ordered = card_order(items)
    decide = [i for i in ordered if i.proposed == DECIDE]
    proposed_revoke = [i for i in ordered if i.proposed == REVOKE]
    override = next((i for i in sorted(items, key=lambda i: i.user)
                     if i.proposed == REVOKE and i.via == "direct" and "left" not in i.reason), proposed_revoke[0])
    approve = [{"do": "approve"}]

    def one(item, decision, reason=""):
        return {"do": "record", "choices": [[item.key, decision, reason]]}

    def keep_the_rest():
        return [one(i, KEEP) for i in decide]

    def revoke_all():
        out = []
        for i in ordered:
            if i.kind in ACKNOWLEDGE_ONLY:
                out.append(one(i, KEEP))
            else:
                out.append(one(i, REVOKE, REVOKE_ALL_REASON if i.proposed == KEEP else ""))
        return out

    first, second = proposed_revoke[0], proposed_revoke[1]
    changed_mind = next(i for i in ordered if i.kind not in ACKNOWLEDGE_ONLY and i.proposed == DECIDE)
    d = [
        one(first, KEEP, BAD_REASONS[0]),  # refused: keeping a proposed revoke needs a reason
        one(first, KEEP, BAD_REASONS[1]),  # refused: one line only
        one(first, KEEP, D_REASONS[0]),
        one(second, KEEP, D_REASONS[1]),
        one(changed_mind, REVOKE, D_REASONS[2]),
        {"do": "confirm"},
        *[one(i, KEEP) for i in decide if i is not changed_mind],
        one(changed_mind, KEEP),  # the latest decision wins
    ]
    return {"A": [{"do": "confirm"}, *keep_the_rest(), *approve],
            "B": [one(override, KEEP, OVERRIDE_REASON), {"do": "confirm"}, *keep_the_rest(), *approve],
            "C": [*revoke_all(), *approve],
            "D": [*d, *approve]}


def play(run_dir: Path, org_url: str, steps: list[dict]) -> dict:
    with counted_uuids():
        session = Session(run_dir, org_url)
        opened = (len(session.bot.log), len(session.jira.log))
        results = [session.step(s) for s in steps]
    signoff = session.evidence("signoff")
    files = {"manifest.json": (run_dir / "manifest.json").read_text(), ITEMS_FILE: (run_dir / ITEMS_FILE).read_text(),
             "signoff/decisions.json": signoff["decisions.json"]}
    changes = tampers(files)
    return {
        "session": session,
        "opened": opened,
        "golden": {
            "steps": [{**s, "result": r} for s, r in zip(steps, results)],
            "slack": session.bot.log[opened[0]:],
            "jira": session.jira.log[opened[1]:],
            "step_functions": [json.loads(output) for _, output in session.sfn.successes],
            "records": {kind: session.evidence(kind) for kind in ("decisions", "signoff", "tickets")},
            "decisions_text": signoff["decisions.json"],
            "decisions_sha256": sha256(signoff["decisions.json"]),
            "attest": attest_outputs(session, changes),
            "tampers": changes,
        },
    }


def export(variant: str, out: Path, commit: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run = review(variant, Path(tmp))
        run_dir = run.run_dir
        manifest_text = (run_dir / "manifest.json").read_text()
        items_text = (run_dir / ITEMS_FILE).read_text()
        rows = read_rows((run_dir / "findings.csv").read_text())
        org_url = json.loads(manifest_text)["org_url"]
        played = {name: play(run_dir, org_url, steps) for name, steps in scenarios(run.items).items()}
        first = played["A"]
        session, (bot_at, jira_at) = first["session"], first["opened"]
        leavers = workflow.leaver_tickets(session.deps, session.run)
        pdf = (run_dir / "report.pdf").read_bytes()

        items = []
        # The order open_revokes opens tickets in. Ticket keys are numbered in
        # this order over the items actually revoked.
        by_key = {i.key: i for i in run.items if i.kind not in ACKNOWLEDGE_ONLY}
        revoke_order = {k: n for n, k in enumerate(sorted(
            by_key, key=lambda k: (by_key[k].user.lower(), by_key[k].target, by_key[k].via)))}
        for n, part in enumerate(msgs.chunks(run.items)):
            for item in part:
                ticket = leavers.get(item.user.lower())
                items.append({
                    **{k: list(v) if isinstance(v, tuple) else v for k, v in vars(item).items()},
                    "render": {
                        "chunk": n,
                        "card": msgs.item_blocks(session.run, item, n, None, ticket)[0]["text"]["text"],
                        "leaver_ticket": ticket[0] if ticket else None,
                        "signoff": signoff_lines(item),
                        "concerns": [finding_for(c, rows) for c in item.concerns],
                        "outside_okta": [finding_for(c, rows) for c in item.outside_okta],
                        "revoke": None if item.kind in ACKNOWLEDGE_ONLY else {
                            "order": revoke_order[item.key], **revoke_ticket(session.run, item, org_url)},
                    },
                })

        page = {
            "format": FORMAT,
            "source": {"repo": REPO, "commit": commit, "tool": f"okta-access-review-aws {__version__}",
                       "variant": variant},
            "variant": dict(zip(("github", "failed_read"), VARIANTS[variant])),
            "clock": {"opened": OPENED.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "decided": DECIDED.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "settings": {"ciso": CISO, "dm": session.source["channel"], "channel": CHANNEL,
                         "evidence_bucket": EVIDENCE, "jira_project": DemoJira.project,
                         "review_days": session.deps.review_days, "revoke_days": session.deps.revoke_days,
                         "leaver_hours": session.deps.tickets.leaver_hours, "task_token": TASK_TOKEN},
            "run": {"name": session.run, "manifest_text": manifest_text, "manifest_sha256": sha256(manifest_text),
                    "items_text": items_text, "items_sha256": sha256(items_text), "gaps": run.gaps,
                    "check_counts": [list(c) for c in workflow.check_counts(session.deps, session.run)],
                    "pdf": {"file": f"{variant}.pdf", "sha256": sha256(pdf), "bytes": len(pdf)}},
            "items": items,
            "open": {"result": session.opened, "slack": session.bot.log[:bot_at], "jira": session.jira.log[:jira_at]},
            "fix_tickets": fix_tickets(session),
            "tampers": [{k: v for k, v in t.items() if k != "offset"} for t in first["golden"]["tampers"]],
            "scenarios": sorted(played),
        }
        golden = {"format": FORMAT, "source": page["source"],
                  "scenarios": {name: p["golden"] for name, p in played.items()}}

    texts = {f"{variant}.json": dumps(page), f"{variant}.golden.json": dumps(golden)}
    for name, text in texts.items():
        leak = leaked(text, org_url)
        if leak:
            raise SystemExit(f"{name} would contain {leak!r}; nothing written")
    for name, text in texts.items():
        (out / name).write_text(text)
    (out / f"{variant}.pdf").write_bytes(pdf)
    print(f"wrote {variant}.json, {variant}.golden.json and {variant}.pdf "
          f"({len(page['items'])} items, scenarios {', '.join(page['scenarios'])})")


def leaked(text: str, org_url: str) -> str | None:
    """A path from this machine, or a host other than the fixture org's and its admin console's."""
    hosts = {re.match(r"https://([^/]+)", url).group(1) for url in (org_url, admin_url(org_url, "user", "x"))}
    for marker in ("/Users/", "/home/", "/private/", "/var/folders/", "/tmp/", tempfile.gettempdir(), str(ROOT)):
        if marker in text:
            return marker
    for host in re.findall(r"https?://([A-Za-z0-9.-]+)", text):
        if host not in hosts:
            return host
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", type=Path, required=True, help="the folder to write into")
    p.add_argument("--variant", choices=[*VARIANTS, "all"], default="all")
    p.add_argument("--allow-dirty", action="store_true",
                   help="export from a tree with uncommitted changes (for tests); the commit is marked -dirty")
    args = p.parse_args(argv)
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        print("export_demo: the tree has uncommitted changes, so the output couldn't name the code that "
              "made it. Commit or stash them first.", file=sys.stderr)
        return 1
    commit = git("rev-parse", "HEAD") + ("-dirty" if dirty else "")
    args.out.mkdir(parents=True, exist_ok=True)
    for variant in VARIANTS if args.variant == "all" else [args.variant]:
        export(variant, args.out, commit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
