# Running the review in AWS

The quarterly review runs in a dedicated AWS account. It's approved in Slack, and fixes are tracked as
Jira Service Management tickets. Okta is only ever read. Writes go to three places only: Slack (one
channel, plus DMs to the CISO), one JSM project, and this deployment's S3 buckets.

## How a review runs

```
EventBridge Scheduler
  quarterly  → Step Functions "uar-review"
  hourly     → uar-watch    reminders, escalation, overdue tickets, sign-off callback retries
  daily      → uar-verify   checks tickets marked done against a fresh Okta snapshot

uar-review
  1. collect     read Okta (GET only), write the review to s3://uar-evidence-…/runs/<run>/
  2. open        JSM parent + 24-hour leaver tickets, Slack DMs, then wait (up to 30 days)
                 … the CISO decides every item in Slack, then approves …
  3. remediate   one 7-day JSM ticket per Revoke decision
  failed         any error, or no sign-off within the wait limit: a note in the channel

Slack → function URL → uar-interact   checks the signature, then hands the click to uar-worker
                       uar-worker     records the decision, updates the messages, signs off
```

| Who | Sees | Does |
|---|---|---|
| CISO (the only reviewer) | A DM with every item as a card: the **facts** (Okta status, last sign-in, MFA, HR record, the access and when it was last used), then **why it could be an issue** (the findings), then the proposal and the buttons. Once everything is decided: one message listing every decision the same way, the PDF and **Approve review**. After sign-off: the action checklist in that message's thread. | Clicks **Confirm N proposed**, then Keep or Revoke on what's left. A reason is required to keep something proposed for revocation, or to override any proposal. Then checks the list and signs off. Gets the reminders. |
| Review channel | One thread per review: "open" (counts and the tracking ticket), the PDF if `slack_channel_pdf` is on, overdue notes, the finished summary, and "complete" when every ticket is settled, with how many were verified in Okta and how many were taken on the reviewer's word. Counts, check titles and links only. | Nothing |
| JSM | A tracking ticket per review. Leaver tickets due in 24 hours; after sign-off, one ticket per revoke and one **fix ticket** per finding that isn't an access decision (no MFA, an inactive account, …), due in 7 days. An account with no HR record gets no ticket: the CISO acknowledges it in the review and raises it with HR. Each links to the person in the Okta admin console. | A person makes the change in Okta and resolves the ticket. The daily check confirms it, ticks the checklist, and closes the tracking ticket when every ticket is settled. Fix tickets that ask for a decision (inactive or unused accounts, contractor exceptions, API client scopes), and cross-source findings in a source this review cannot re-read, are ticked off as soon as they are resolved; the checklist marks them. |

**Proposals.**
- *Revoke:* direct app access with no SSO sign-in to that app for 90 days (`app_unused_days`), and
  everything held by people HR says have left.
- *Keep:* access used recently, and assignments made less than 90 days ago.
- *Your call:* everything else — admin roles and groups, access through a group (removing someone
  from a group affects their other access), apps that don't record sign-ins, service accounts,
  apps in `activity_exempt_apps`. If the sign-in data is missing or cut short, nothing is proposed
  for revocation; those items become *Your call*.

**Evidence.** Everything in `runs/<run>/` is written create-only and kept under Object Lock:

| Path | What |
|---|---|
| `report.pdf`, `findings.csv`, `access_matrix.csv`, `snapshot.json`, `roster.csv`, `review_items.json`, `manifest.json` | The review, with every file hashed in the manifest |
| `transitions.json` | One bundle per departure, when the review read a source beyond Okta. Hashed like the rest, so it can be shown to be the one the review produced. **Not produced by the AWS pipeline yet:** `handlers.collect` passes no GitHub snapshot, so cross-source checks are skipped there and this file appears only in CLI runs given `--github` |
| `decisions/<time>-<id>.json` | One record per click: who (Slack user ID), what, why, and the manifest hash |
| `signoff/decisions.json`, `signoff/attestation.json` | The final decision per item, and the CISO's sign-off, bound to both hashes |
| `tickets/<label>.json` | Each JSM ticket opened |
| `verifications/<label>-….json` | Each daily check of a resolved ticket |

To check a run: download it (`aws s3 cp --recursive s3://uar-evidence-<account>/runs/<run>/ <run>/`),
then run `uv run access-review attest <run>`. This verifies the files against the manifest, and the
Slack sign-off against both hashes.

## One-time setup

You need an AWS account used for nothing else, admin credentials for it, Terraform 1.10 or later,
Docker, and admin access to Okta, Slack and Jira.

### 1. Bootstrap (state bucket and CI roles)

The state bucket doesn't exist before the first apply, so that one apply uses local state:

```bash
cd infra/bootstrap
cp terraform.tfvars.example terraform.tfvars   # set github_repo, github_owner_id, github_repo_id
# comment out the backend "s3" block in versions.tf for this first apply
terraform init && terraform apply
cp backend.hcl.example backend.hcl             # bucket = the state_bucket output (git-ignored)
# restore the backend block, then move the state into the bucket:
terraform init -backend-config=backend.hcl -migrate-state
```

Once the state is in S3, delete the local `terraform.tfstate*` files.

The CI roles trust GitHub's immutable OIDC subject, `repo:<owner>@<owner id>/<name>@<repo id>:…`,
which new repositories use by default. Because it includes the numeric IDs, a repository deleted
and recreated under the same name can't assume the roles. Get the IDs with
`gh api users/<owner> --jq .id` and `gh api repos/<owner>/<name> --jq .id`.

### 2. Okta

Create the API Services app as in [configuration.md](configuration.md#okta-app), with the same
read-only scopes (`okta.logs.read` is required: app sign-ins come from the System Log). Store its
private key as a SecureString parameter, for example:

```bash
aws ssm put-parameter --name /uar/okta/private_key --type SecureString --value file://okta-key.pem
```

### 3. Slack

Create the app from [`slack/manifest.yaml`](../slack/manifest.yaml) as it is, and install it.
Interactivity starts off, because Slack only accepts a real Request URL; you turn it on after the
first deploy (step 6). Create a **private** review channel and invite the app.

Store the two credentials by pasting each at a hidden prompt, so they don't end up in shell history
or depend on what's on the clipboard. The bot token is under **OAuth & Permissions** (`xoxb-…`).
The signing secret is under **Basic Information → App Credentials**: 32 hex characters, not the
Client Secret or the Verification Token.

```bash
read -rs "V?Bot token: " && aws ssm put-parameter --name /uar/slack/bot_token --type SecureString --value "$V"; unset V
read -rs "V?Signing secret: " && aws ssm put-parameter --name /uar/slack/signing_secret --type SecureString --value "$V"; unset V
```

(Those are zsh prompts. In bash, use `read -rsp "Bot token: " V`.)

You'll need the channel ID (channel name → **About**), and the CISO's **member ID**: their profile →
⋯ → **Copy member ID**. It starts with `U`. A DM's ID (`D…`) looks similar but won't work.

### 4. Jira Service Management

- **Add JSM to the site**, if it isn't there already: admin.atlassian.com → **Apps** → **Add app** →
  Jira Service Management. The **Free** plan (up to 3 agents) is enough.
- **Create a service management project.** Jira now calls projects "spaces": sidebar → **Spaces** →
  **+** → **Service management**. Use any key, and put it in `JIRA_PROJECT`.
- **Create the account the review signs in as.** Use an Atlassian **service account**: admin.atlassian.com
  → **Directory** → **Service accounts**. Give it Jira Service Management access and an API token
  with at least `read:jira-work` and `write:jira-work`. A normal user with a JSM seat also works.
- **Add it to the project** under **Project settings → People**, with the role **Service Desk Team**.
  In JSM, only agents can browse every ticket, and the tickets name people.
- **Store its token**, pasted at a hidden prompt:

```bash
read -rs "V?Jira API token: " && aws ssm put-parameter --name /uar/jira/api_token --type SecureString --value "$V"; unset V
```

Two things differ from a normal user:

- **Base URL.** A service account's token only works through Atlassian's API gateway, so
  `JIRA_BASE_URL` is `https://api.atlassian.com/ex/jira/<cloud id>`, not `https://<site>.atlassian.net`.
  The cloud ID is at `https://<site>.atlassian.net/_edge/tenant_info`.
- **Email.** It's the service account's own address (`…@serviceaccount.atlassian.com`), shown on its
  page under Directory → Service accounts.

The parent ticket type is `JIRA_PARENT_TYPE` (default `Task`), and the child type is
`JIRA_CHILD_TYPE`. Service management templates usually call it **`Sub-task`**, with the hyphen;
team-managed Jira projects call it `Subtask`. Both types must exist in the project, and their
create screens must include summary, description, due date, labels and parent.

### 5. GitHub

The repository is public, and so are its workflow logs. Anything that names the AWS account or the
org is therefore a **secret**, which GitHub masks in logs. Only harmless settings are plain variables.
The plan and deploy jobs print totals only, never the full plan or apply output.

Repository **secrets** (Settings → Secrets and variables → Actions → Secrets):

| Secret | Value |
|---|---|
| `TF_STATE_BUCKET` | The bootstrap `state_bucket` output |
| `AWS_PLAN_ROLE_ARN` | The `plan_role_arn` output |
| `TEARDOWN_ROLE_ARN` | The `apply_role_arn` output |
| `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_KEY_ID` | The Okta app |
| `SLACK_CHANNEL_ID`, `SLACK_CISO_USER` | Slack IDs |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_PROJECT` | Jira |
| `BUDGET_EMAIL` | Where cost alerts go |

Repository **variables**:

| Variable | Value |
|---|---|
| `AWS_REGION` | e.g. `us-east-1` |
| `JIRA_PARENT_TYPE`, `JIRA_CHILD_TYPE` | e.g. `Task`, `Subtask` |
| `SLACK_CHANNEL_PDF` | `true` to also post the report PDF in the review channel's thread. It names people and their access, so only if everyone in the channel may see that. Default `false`. |
| `AWS_CONFIGURED` | `true` once the secrets above are set: turns on the plan job for pull requests |
| `DEPLOY_ENABLED` | `true` when you're ready to deploy |

Create an environment named **`production`**:
- add yourself as a required reviewer
- allow deployments only from `master`
- add the environment **secret** `AWS_APPLY_ROLE_ARN` (the `apply_role_arn` output)

Only the Deploy job runs in that environment, so only it can assume the apply role.

Create a branch ruleset on `master`:
- require a pull request before merging
- require these status checks: `Tests`, `Secret scan`, `Dependency audit`, `Workflow lint` and `Terraform`
- block force pushes
- restrict deletions

### 6. Deploy, then connect Slack

Set the `DEPLOY_ENABLED` variable to `true`, merge to `master`, and approve the Deploy job. It creates
the ECR repository, builds and pushes the image, and applies `infra/main`. From then on, every merge
to `master` deploys, each only after your approval. Then:

- in the Slack app, open **Interactivity & Shortcuts**, turn it **on**, and paste in the
  `slack_request_url` output (`terraform -chdir=infra/main output -raw slack_request_url`) as the
  **Request URL**. Slack checks the URL when you save.
- upload the inputs:

```bash
aws s3 cp roster.csv  s3://uar-work-<account>/inputs/roster.csv
aws s3 cp config.json s3://uar-work-<account>/inputs/config.json
```

### 7. First review

Don't wait for the quarter; start one by hand:

```bash
aws stepfunctions start-execution --state-machine-arn "$(terraform -chdir=infra/main output -raw state_machine_arn)"
```

To see the whole flow with no AWS at all, run `uv run python scripts/e2e_local.py`. It uses the demo
data and prints every Slack message and JSM ticket it would send.

## Operating it

Running a review, step by step, is in [runbook.md](runbook.md).

- **Roster changes:** upload a new `inputs/roster.csv`. Each run copies the roster it used into its
  evidence.
- **A review that stops:** the channel says so. The execution history has the cause (IDs and counts
  only). Start a new execution.
- **A sign-off that doesn't resume the workflow** (for example, the execution timed out): the
  sign-off is already recorded as evidence. The hourly watcher retries the callback. If the
  execution is gone, run remediation by hand:
  `aws lambda invoke --function-name uar-remediate --payload '{"run":"<run>"}' out.json`.
- **Changing a decision:** click again before the CISO approves. The newest click counts, and every
  click stays on record.
- **Lambda concurrency:** new AWS accounts may only run 10 Lambdas at once, and none can be
  reserved, so `reserve_concurrency` is off by default and that limit caps everything (including a
  flood of junk requests to the Slack endpoint). The review needs far less. If you ask AWS for more
  (Service Quotas → AWS Lambda → Concurrent executions), you can set `reserve_concurrency = true`.
- **Logs:** 30 days in CloudWatch. They never hold evidence, secrets or item details.

## Cost

About $1 a month, plus the ECR image (roughly $0.10 per GB-month). There are no KMS keys, no NAT
and no Secrets Manager. S3 SSE, SSM Parameter Store's standard tier and the AWS-managed keys are
free, and Lambda, Step Functions and the scheduler cost pennies at this volume. An AWS Budgets
alert fires at 80% of `budget_limit_usd` (default $5).

## Security choices

- **Okta is read-only.** Only `.read` scopes; GET requests only (the tests enforce it); the Okta
  Terraform provider is never used.
- **No long-lived AWS keys.** CI uses OIDC. The plan role is read-only and denied evidence objects
  and secrets. The apply role can only be assumed from the protected `production` environment.
- **Secrets stay out of Terraform.** Terraform never creates or reads the SSM parameters, so their
  values never reach its state.
- **One role per function.** Only `collect` and `verify` can read the Okta key, and only `interact`
  can read the Slack signing secret. No function can delete evidence or bypass retention.
- **Evidence is create-only and locked.**
  - The bucket policy refuses any PUT without `If-None-Match`.
  - Object Lock is in governance mode for `evidence_retention_days` (default 3 years), and
    lifecycle rules delete the objects afterwards.
  - Only the apply role may bypass the lock, and only [teardown](teardown.md) does.
  - The manifest hash is also posted in Slack and on the JSM parent ticket, so changing evidence
    in S3 would not go unnoticed.
- **Slack requests are authenticated by signature.** The function URL has no AWS auth (Slack can't
  sign AWS requests). Every request is checked against Slack's signing secret within a 5-minute
  window before anything else. Only the configured CISO can act, and the worker re-checks
  every permission itself.
- **No personal data in Step Functions, channel posts or logs.** Personal data is only in S3, the
  CISO's DM, and JSM, plus the report PDF in the channel if you turn on `SLACK_CHANNEL_PDF`.
- **One reviewer.** The CISO decides every item, including their own access. That keeps a small
  review simple, but an auditor will usually want someone else to approve the reviewer's own access;
  if you need that, have a second person confirm those items outside the tool and note it on the
  tracking ticket.
- **Accepted scanner findings.** The checkov findings accepted on purpose, mostly for cost, are
  listed with reasons in [`infra/.checkov.yaml`](../infra/.checkov.yaml).
