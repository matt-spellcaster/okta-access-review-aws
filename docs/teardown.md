# Tearing it down

Everything lives in one dedicated AWS account, so the last step is closing that account. Before
that, keep a verified copy of the evidence and clean up the services outside AWS.

## 1. Dry run

Use the apply role's credentials. It's the only principal the evidence bucket lets bypass retention.

```bash
uv run python scripts/teardown.py
```

This lists the review runs and object versions it would delete, and deletes nothing.

## 2. Export, verify, delete

```bash
uv run python scripts/teardown.py --confirm-account <account id>
```

It runs these steps in order, and stops before deleting anything if a step fails:

1. Downloads every review run, with its decisions, sign-off, ticket and verification records.
2. Verifies each run against its manifest and its Slack sign-off. One failure stops the whole
   teardown.
3. Writes `evidence-export-<account>-<time>.zip`. Keep it for as long as your retention policy says.
4. Deletes every object version in the evidence bucket, bypassing governance retention.
5. Deletes the `/uar/` SecureString parameters.

## 3. Destroy the infrastructure

```bash
cd infra/main && terraform destroy
cd ../bootstrap
# comment out the backend block in versions.tf, then:
terraform init -migrate-state   # moves state back to local before its bucket goes
terraform destroy
```

`infra/main` deletes the work bucket and the ECR images with it. The evidence bucket is already
empty. It refuses to be destroyed while it holds anything.

## 4. Outside AWS

The tool never writes to Okta, so these steps are manual:

- **Okta:** deactivate and delete the access review API service app.
- **Slack:** delete the Access Review app.
- **Jira:** revoke the service account's API token, and deactivate the account if nothing else
  uses it.
- **GitHub:** delete the `production` environment and the AWS, Okta, Slack and Jira repository
  variables.
- **AWS:** close the account (Organizations → Accounts → Close). This removes anything the steps
  above missed.
