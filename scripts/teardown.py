"""Tear the deployment down, keeping a verified copy of the evidence.

    python scripts/teardown.py                              # dry run: shows what would go
    python scripts/teardown.py --confirm-account 123456789012
    python scripts/teardown.py --check                      # after destroy: anything left?

Run it with the apply role's credentials (the only principal the evidence
bucket lets bypass retention). In order:

  1. download every review run, and check each one against its manifest and
     Slack sign-off; stop, deleting nothing, if any check fails
  2. zip the export
  3. delete every object version and delete marker in the evidence bucket,
     bypassing governance retention (the one place anything does)
  4. delete the /uar/ SecureString parameters
  5. print the terraform destroy commands and the steps outside AWS

Nothing is deleted without --confirm-account matching the account the
credentials belong to. --check deletes nothing either: run it after both
terraform destroys to confirm the account is clean, if you keep the account.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from access_review import store  # noqa: E402
from access_review.attest import AttestError, slack_signoff_problems, verify  # noqa: E402

PARAMS = ["/uar/okta/private_key", "/uar/slack/bot_token", "/uar/slack/signing_secret", "/uar/jira/api_token"]
MANUAL_STEPS = """\
Outside AWS (the tool never writes to Okta, so these are yours):
  - Okta: deactivate and delete the access review API service app.
  - Slack: delete the Access Review app (api.slack.com/apps).
  - Jira: revoke the service account's API token; deactivate the account if nothing else uses it.
  - GitHub: delete the production environment and the repository secrets and variables.
  - AWS, if you keep the account: once both destroys finish, run
      python scripts/teardown.py --check
    to confirm nothing is left. Closing the account instead is optional.
"""
PROJECT_TAG = "okta-access-review"  # every Terraform resource carries Project = this (default_tags)
OIDC_HOST = "token.actions.githubusercontent.com"


def leftovers(clients: dict, prefix: str) -> list[str]:
    """Everything this project could have left in the account. The tagging API
    covers most resources; IAM isn't in it, and buckets and parameters are
    listed by name too, in case a tag was ever missed."""
    found = []
    tagging, token = clients["tagging"], None
    while True:
        kwargs = {"TagFilters": [{"Key": "Project", "Values": [PROJECT_TAG]}]}
        if token:
            kwargs["PaginationToken"] = token
        page = tagging.get_resources(**kwargs)
        found += [f"tagged: {r['ResourceARN']}" for r in page.get("ResourceTagMappingList", [])]
        token = page.get("PaginationToken")
        if not token:
            break

    iam, marker = clients["iam"], None
    while True:
        page = iam.list_roles(**({"Marker": marker} if marker else {}))
        found += [f"IAM role: {r['RoleName']}" for r in page.get("Roles", [])
                  if r["RoleName"].startswith(f"{prefix}-")]
        if not page.get("IsTruncated"):
            break
        marker = page["Marker"]
    found += [f"IAM OIDC provider: {p['Arn']}"
              for p in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
              if p["Arn"].endswith(OIDC_HOST)]

    found += [f"S3 bucket: {b['Name']}" for b in clients["s3"].list_buckets().get("Buckets", [])
              if b["Name"].startswith(f"{prefix}-")]
    params = clients["ssm"].describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "BeginsWith", "Values": ["/uar/"]}]).get("Parameters", [])
    found += [f"SSM parameter: {p['Name']}" for p in params]
    return sorted(set(found))


def check(clients: dict, prefix: str) -> int:
    """Report what's left; exit 0 only if nothing is."""
    left = leftovers(clients, prefix)
    if not left:
        print("Nothing from this project is left in the account.")
        return 0
    print(f"{len(left)} thing(s) from this project are still in the account:")
    for item in left:
        print(f"  {item}")
    print("Tagged resources can take a few minutes to drop out of the listing after they're deleted; "
          "re-run before removing anything by hand.")
    return 1


def all_versions(s3, bucket: str) -> list[dict]:
    out, kwargs = [], {"Bucket": bucket}
    while True:
        page = s3.list_object_versions(**kwargs)
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            out.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        if not page.get("IsTruncated"):
            return out
        kwargs["KeyMarker"] = page["NextKeyMarker"]
        kwargs["VersionIdMarker"] = page["NextVersionIdMarker"]


def export(s3, bucket: str, dest: Path) -> list[str]:
    """Download and verify every run. Returns problems; empty means all good."""
    problems = []
    runs = store.list_runs(s3, bucket)
    for run in runs:
        folder = store.download_run(s3, bucket, run, dest)
        try:
            v = verify(folder)
        except AttestError as e:
            problems.append(f"{run}: {e}")
            continue
        if not v.ok:
            problems.append(f"{run}: files missing {v.missing} or changed {v.mismatched}")
        for p in slack_signoff_problems(folder, v) or []:
            problems.append(f"{run}: {p}")
    print(f"Exported {len(runs)} review run(s) to {dest}")
    return problems


def empty_bucket(s3, bucket: str, versions: list[dict]) -> None:
    for n in range(0, len(versions), 1000):
        batch = versions[n:n + 1000]
        resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True},
                                 BypassGovernanceRetention=True)
        if resp.get("Errors"):
            first = resp["Errors"][0]
            raise SystemExit(f"could not delete {len(resp['Errors'])} object(s), e.g. {first.get('Key')}: "
                             f"{first.get('Code')}. Is this the apply role?")
    print(f"Deleted {len(versions)} object version(s) and delete marker(s) from {bucket}")


def main(argv=None, clients=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--confirm-account", help="the AWS account ID; without it, nothing is deleted")
    p.add_argument("--prefix", default="uar")
    p.add_argument("--export-dir", type=Path)
    p.add_argument("--check", action="store_true",
                   help="delete nothing; list anything this project left in the account")
    args = p.parse_args(argv)
    if args.check and args.confirm_account:
        p.error("--check and --confirm-account don't go together")

    if clients is None:
        import boto3

        clients = {name: boto3.client(name) for name in ("sts", "s3", "ssm", "iam")}
        clients["tagging"] = boto3.client("resourcegroupstaggingapi")
    if args.check:
        return check(clients, args.prefix)
    account = clients["sts"].get_caller_identity()["Account"]
    evidence = f"{args.prefix}-evidence-{account}"
    s3 = clients["s3"]
    versions = all_versions(s3, evidence)
    runs = store.list_runs(s3, evidence)

    print(f"Account {account}")
    print(f"  evidence bucket {evidence}: {len(runs)} review run(s), {len(versions)} object version(s)")
    print(f"  SecureString parameters: {', '.join(PARAMS)}")
    if args.confirm_account is None:
        print("\nDry run: nothing was deleted. Re-run with --confirm-account", account)
        return 0
    if args.confirm_account != account:
        print(f"--confirm-account {args.confirm_account} doesn't match these credentials ({account}); stopping.",
              file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = args.export_dir or Path(f"evidence-export-{account}-{stamp}")
    dest.mkdir(parents=True, exist_ok=False)
    problems = export(s3, evidence, dest)
    if problems:
        print("\nThe export didn't verify, so nothing was deleted:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 2
    archive = shutil.make_archive(str(dest), "zip", root_dir=dest)
    print(f"Verified every run; archive: {archive}")

    empty_bucket(s3, evidence, versions)
    clients["ssm"].delete_parameters(Names=PARAMS)
    print("Deleted the SecureString parameters")

    print(f"""
Now destroy the infrastructure (the work bucket and ECR images go with it):
  cd infra/main && terraform destroy
  cd ../bootstrap   # comment out the backend block in versions.tf, then:
  terraform init -migrate-state && terraform destroy
  python scripts/teardown.py --check   # if you keep the account

{MANUAL_STEPS}""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
