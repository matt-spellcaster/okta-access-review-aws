# okta-access-review-aws

Quarterly Okta user access review that runs in AWS, is approved in Slack, and opens remediation
tickets in Jira Service Management. Produces SOC 2 / ISO 27001 audit evidence. Seeded from
`okta-access-review` at commit 1a20697.

## Commands

- Tests: `uv run pytest -q`
- Demo (no Okta needed): `uv run access-review --snapshot fixtures/demo_snapshot.json --roster fixtures/demo_roster.csv --config fixtures/demo_config.json --as-of 2026-09-15`
- Live, local: `./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json` (needs `env` and 1Password)
- Verify a run folder: `uv run access-review attest reports/<folder>`
- Whole AWS workflow in memory (no AWS/Slack/Jira): `uv run python scripts/e2e_local.py`
- Terraform: `terraform -chdir=infra/main fmt -check && terraform -chdir=infra/main validate`;
  scan with `uvx checkov@<pinned> -d infra --config-file infra/.checkov.yaml`
- Image: `scripts/build_image.sh <tag>`; teardown dry run: `uv run python scripts/teardown.py`
- Setup and operations: `docs/aws.md`; teardown: `docs/teardown.md`

## Rules

- Okta is read-only. `OktaClient` only sends GET requests, plus the token POST. Never add
  write calls, never request a scope that doesn't end in `.read`, and never use the Okta
  Terraform provider.
- Writes go only to: the configured Slack channel and DMs to the configured admin and CISO, one
  JSM project, and this project's own S3 buckets. Nothing else.
- Remediation is done by a person working a JSM ticket. The tool never changes anyone's access
  and never transitions tickets; it only creates them and comments on them.
- Slack channel posts and email bodies contain only counts and completeness. Personal data goes
  only in admin/CISO DMs, the PDF, and JSM tickets (the JSM project must restrict issue visibility).
- Step Functions input and output never carry personal data: IDs, hashes and counts only.
- Evidence objects in S3 are create-only (`If-None-Match: *`). Nothing except `scripts/teardown.py`
  may use `s3:BypassGovernanceRetention`, and no Lambda role is ever granted it.
- Never commit `env`, key files, `reports/`, Terraform state or `*.tfvars` with real values, or
  anything in `roster/` except its README.
- Never read `env` or print `OKTA_PRIVATE_KEY`, `SMTP_PASSWORD`, `SLACK_WEBHOOK_URL`,
  `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` or `JIRA_API_TOKEN` (webhook URLs and Slack's pre-signed
  upload URLs are credentials too; keep them out of error messages). Never pass an unchecked
  `*_REF` value to `op` or an unchecked `*_PARAM` name to SSM — both echo bad references.
- Tests never call real AWS, Slack, Jira or SMTP. `tests/conftest.py` clears those settings; inject
  fakes through `session=` / `client=` parameters like the existing tests do.
- A new check needs: an entry in `CHECKS` (`checks.py`) with SOC 2 and ISO 27001 control IDs, a planted
  case in `fixtures/demo_snapshot.json`, and an updated expectation in
  `test_demo_findings_are_exactly_the_planted_ones`.
- After changing the PDF layout or demo fixtures, run `uv run python scripts/render_samples.py`
  and look at `docs/images/*.png` before committing. The README sample must only ever use fixture data.
- Keep the snapshot format (`models.py`) the same for live and fixture data; checks only see `Snapshot`.
- Review proposals (`items.py`) never propose Revoke on missing or truncated data; the item becomes
  "decide" instead.
- Findings history (`history.py`) and `attest` never write outside the one report folder, never
  change a hashed file, and never send anything. History must never count a review it couldn't
  verify against its manifest; when unsure, count lower.
- `findings.csv` columns are fixed by `FINDING_COLUMNS` (`report.py`). A new `Finding` field changes
  them only if you add it there and update `test_findings_csv_header_is_explicit`.
- Never write anything at the top level of `--out`; tests and `render_samples.py` expect one folder per run.
- Python 3.11+, dependencies pinned by `uv.lock` and `exclude-newer` in `pyproject.toml`.
- Terraform (`infra/`): pin Terraform, provider and tflint versions, commit `.terraform.lock.hcl`
  (with linux_amd64, linux_arm64 and darwin_arm64 hashes), and declare every log group. Never let a
  secret reach state: Terraform doesn't create or read the `/uar/` SSM parameters at all; they are
  set with `aws ssm put-parameter` (docs/aws.md). A new checkov skip needs a reason in
  `infra/.checkov.yaml`.
- CI (`.github/workflows/compliance.yml`): pin every action to a full commit SHA with a version
  comment, keep `permissions: {}` at the top with per-job grants, never interpolate `${{ }}` into
  `run:` (pass it via `env:`), and run `uvx zizmor@<pinned> --offline .github/workflows` after
  editing. If a job is renamed, update `REQUIRED_CHECKS` in `scripts/ci/check_branch_rules.py`
  and the ruleset. See `docs/ci.md`.
