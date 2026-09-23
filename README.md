# okta-access-review-aws

A quarterly Okta user access review that runs in AWS. The CISO decides each item in Slack, fixes are
tracked as Jira Service Management tickets, and everything is kept as SOC 2 and ISO 27001 evidence.

It also follows a departure past Okta. Deactivating someone's Okta account doesn't touch the API
tokens they hold, the service accounts they own, or their access in GitHub. The review finds those
too.

<img src="docs/images/slack-review-finished.png" width="560" alt="Slack: the finished review, signed off, with 18 findings by check from critical to info, the decisions, and the tickets opened">

## What it does

- **Reads Okta and never writes to it.** Users, groups, apps, MFA, admin roles and the System Log,
  through read-only scopes, Private Key JWT and DPoP-bound tokens.
- **Runs 18 checks**, each mapped to SOC 2 and ISO 27001:2022 controls: a leaver whose account is
  still live, a missing MFA factor, an API token a leaver still holds, a service account whose owner
  left, and [more](#checks).
- **Puts every decision in front of a person.** The CISO keeps or revokes each item in Slack, and
  the sign-off is bound to the report's SHA-256.
- **Tracks the fixes.** One JSM ticket for each piece of access to remove and each finding to fix.
  When someone resolves a ticket, a daily job checks Okta to see whether the change really happened,
  and flags it if Okta still shows the problem. Tickets Okta can't show, like a decision to keep
  something, are taken on the reviewer's word. The quarter's tracking ticket closes once every
  ticket is settled.
- **Keeps the evidence.** A PDF, CSVs, the raw data and a hash manifest, stored create-only in S3
  under Object Lock.
- **Never calls a failed read clean.** If a source can't be read in full, the report is marked
  incomplete and says which source.

## Try it

No Okta, AWS, Slack or Jira needed:

```bash
uv run access-review \
  --snapshot fixtures/demo_snapshot.json \
  --roster fixtures/demo_roster.csv \
  --config fixtures/demo_config.json \
  --github fixtures/demo_github.json \
  --as-of 2026-09-15
```

That reviews **Acme**, a fictional company with at least one planted case for each check, and
writes the report to `reports/`. The tests confirm the review finds those cases and nothing else.
Leave out `--github` and it's an Okta-only review, without the cases planted in the GitHub fixture.

To run the whole AWS workflow in memory, Slack and Jira included, with nothing leaving your laptop:
`uv run python scripts/e2e_local.py`.

## How a review looks

Screenshots from a demo run with the fictional **Acme** company (`scripts/demo_to_slack.py`), which
sends the demo data through the same code the Lambdas run. The reviewer's name is blacked out.

**1. The review opens.** The review channel gets counts only and a link to the tracking ticket, with
the full report PDF in the thread.

![Slack channel: "Okta access review is open" with counts and the tracking ticket, and the report PDF in the thread](docs/images/slack-review-open.png)

**2. The CISO decides each item** in a DM. Each card shows the facts, anything the person holds in
another source that this decision cannot change, then why it could be an issue, then the proposal and
the buttons. **Confirm N proposed** accepts every proposal at once.

![Slack DM: summary with Confirm 13 proposed, then an item card with Facts, what the decision doesn't settle, Why it could be an issue, and Keep/Revoke buttons](docs/images/slack-review-cards.png)

**3. The CISO signs off.** Once every item is decided, one message lists every decision with its facts
and concerns, bound to the report's SHA-256, with **Approve review** below.

![Slack DM: the end of the decision list, including a service account AR-18 reports because its owner left, then the manifest hash and the Approve review button](docs/images/slack-signoff.png)

**4. The review finishes.** Tickets are opened and the channel thread gets the summary at the top
of this page: who signed off, findings by check, the decisions, and where the tickets are.

<details>
<summary>The tickets in Jira Service Management</summary>

One tracking ticket per review, with the manifest hash and where the evidence is:

![JSM tracking ticket "Okta Access Review 2026-Q3" with counts, manifest SHA-256 and evidence path](docs/images/jira-tracking-ticket.png)

Under it, one sub-ticket for each leaver, each revoke and each finding to fix. Each links to the
person in the Okta admin console. The tracking ticket closes itself once every ticket is settled:
checked in Okta where Okta can show the change, and on the reviewer's word where it can't.

![JSM sub-tickets: leaver removals, revokes and fixes for the Acme demo](docs/images/jira-subtasks.png)

</details>

## Sample report

Every run produces a PDF like this. All data is from **Acme**, a fictional company. The demo is
incomplete on purpose: the GitHub fixture plants four data gaps, and the report leads with them
rather than treating what it couldn't read as clean.

![Page 1 of the sample report: the summary by severity, then the four data gaps that mark the review incomplete](docs/images/report-page-1.png)

<details>
<summary>Page 2: the findings</summary>

![Page 2 of the sample report: the most severe findings, including AR-17 on departed GitHub members and AR-18 on service accounts whose owner left](docs/images/report-page-2.png)

</details>

[Full sample PDF](docs/sample-report.pdf) · The same run posted to Slack:

![Slack summary of the Acme demo review, with the PDF report attached in the thread](docs/images/slack-summary.png)

## Checks

| ID | Finds | Severity | Controls |
|---|---|---|---|
| AR-01 | Terminated in HR, but the account is still live | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.18 |
| AR-02 | Contract or end date has passed | high | SOC 2 CC6.2 · ISO A.5.18 |
| AR-03 | Account with no HR record (service accounts can be listed); acknowledged by the CISO and raised with HR, no ticket | high | SOC 2 CC6.2 · ISO A.5.16 |
| AR-04 | Can sign in, but has no MFA factor | high | SOC 2 CC6.1 · ISO A.8.5 |
| AR-05 | No sign-in for 90+ days | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-06 | Created 14+ days ago and never used | medium | SOC 2 CC6.2 · ISO A.5.16 |
| AR-07 | Contractor in an employee-only group | medium | SOC 2 CC6.3 · ISO A.5.15 |
| AR-08 | Missing manager or department | low | SOC 2 CC6.2 · ISO A.5.16 |
| AR-09 | Suspended or deprovisioned, but still in groups or apps (unless it is a service account AR-18 has) | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-10 | Service app with write scopes or an admin role that can make changes (high if Super Administrator) | medium | SOC 2 CC6.3 · ISO A.8.2 |
| AR-11 | Admin user, for the reviewer to confirm | info | SOC 2 CC6.3 · ISO A.8.2 |
| AR-12 | Leaver still holds a working API token | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.18 |
| AR-13 | Signed in, or used a credential, after their last working day | critical | SOC 2 CC6.2, CC7.2 · ISO A.5.18, A.8.16 |
| AR-14 | Directly assigned app with no sign-in to it for 90+ days (skipped if the System Log can't be read in full) | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-15 | A credential no evidence ties to a person, or one the register declares and names no owner for (a rung milder); high if it can write and may be in use | medium | SOC 2 CC6.1, CC6.2 · ISO A.5.16, A.5.18 |
| AR-16 | Something holds access that the source's own user or member read never returned | high | SOC 2 CC6.1, CC6.2, CC6.3 · ISO A.5.16, A.5.18 |
| AR-17 | Someone who left still has access in a system Okta deactivation doesn't reach | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.16, A.5.18, A.8.2 |
| AR-18 | Service account a leaver owned, or held the secret of (critical if it can change anything, or if that is unknown) | high | SOC 2 CC6.1, CC6.2, CC6.3 · ISO A.5.16, A.5.17, A.5.18, A.8.2 |

AR-01 to AR-03, AR-12, AR-13, AR-17 and AR-18 compare what the review found with an HR roster: a CSV
exported from the HR system and passed in with `--roster` (there's no live HR integration yet).
Without it they're skipped, and the report says so. Thresholds and group names are configurable.

AR-12, AR-13 and AR-18 cover the leaver cases an account status doesn't show:

- **AR-12:** an Okta API token keeps working after the account is deactivated. The daily check sees
  the revocation in Okta.
- **AR-18:** so does a copy of an API client secret the leaver created, added or read, and any
  client they owned. Somebody still here has to answer for it, and every secret they held has to be
  rotated. A reviewer confirms the rotation, because Okta can't show it reliably (a key published at
  a `jwks_uri` never appears there). Only the System Log records who created a client, so ownership
  comes from creation events alone. Reading a colleague's secret makes someone its custodian, and
  that's all.
- **AR-13:** reads the System Log for use of the leaver's own account after their last working day.
  A client they built going on running is what it's for, so it doesn't count. Okta keeps 90 days of
  log data, so a termination older than that is reported as a gap.

AR-09 stands down for a declared bot account that's deactivated and still holds groups and apps.
AR-18 takes the account, names its state, and lists the groups and apps that reactivating it would
restore, so the reviewer sees what's at stake while choosing between handover and decommission.
Every check declares whether its remediation removes the account's access, keeps the account
running, or neither, and a test asserts that no account is told both.

## Across sources

AR-15 to AR-18 reason over an identity graph rather than the Okta snapshot alone: the principals
that can hold access in each source, the credentials that keep working after the account they were
created under is deactivated, the grants each principal holds, and the links saying which principal
belongs to which person. Each source is projected into it (Okta from its snapshot, GitHub from its
own), and AR-17 and AR-18 match the graph against the roster's leavers. Three rules shape it.

**A link is evidenced or it is absent.** A principal is tied to a person by the IdP's own SSO
assertion, an email the source itself states as verified, a register entry somebody signed up to, or
an audit log's record of who created the account. Never by name or email similarity. The methods are
a ladder rather than a score, and two equally strong links naming different people leave the account
unlinked, which is itself a finding. A false link is worse than no link: it marks a credential as
accounted for when nobody is accountable for it.

**Completeness is tracked per source.** A read that failed is recorded against that source, so the
review never reports "no GitHub credentials" when the GitHub call simply failed. Emptiness is
evidence only when the read that would have said so actually ran: an unread scope list is unknown
write access rather than read-only, and an account with no credentials found under a failed read is
still reported. Unknown is never ranked as the milder case.

**The service account register records ownership. It can't silence a finding.** `config.service_accounts`
records which accounts are not people and who owns each. An entry with an owner ties the account to
that person, so it appears in their access review and in their departure bundle if they leave. An
entry naming nobody, or naming somebody no source evidences, is still reported one severity
milder: it declares the account without making anyone accountable for it. Details:
[docs/configuration.md](docs/configuration.md#the-service-account-register).

All four run on an Okta-only estate too, where AR-18 finds an API client a leaver owned or held the
secret of. What a second source adds is the other estate (the org roles, PATs and SSH keys a
departure leaves behind) and a per-departure bundle in `transitions.json`.

## Evidence produced

Each run writes a folder named after its collection time:

| File | For |
|---|---|
| `report.pdf` / `report.md` | Findings with fixes and control mapping, access by user, reviewer sign-off |
| `access_matrix.csv` | Every user's access, with blank `decision` and `reviewer` columns to fill in |
| `findings.csv` | Tracking remediation, with how long each finding has been open |
| `snapshot.json` | The exact Okta data the checks ran on |
| `github_snapshot.json` | The GitHub data, when `--github` was given: the cross-source findings rest on it |
| `transitions.json` | One bundle per departure (with `--github`): everything that person still holds across sources, the evidence linking each account to them, and every finding about them. A departure bundle needs a second estate to be worth writing, so an Okta-only run produces none |
| `roster.csv` | A copy of the HR roster export the review compared against |
| `manifest.json` | Config, roster name, row count and hash, completeness, the earlier reviews history was read from, and a SHA-256 hash of every file |
| `attestations.json` | Added by `access-review attest <folder> --decision approved --reviewer NAME`: sign-offs tied to the manifest's hash ([details](docs/configuration.md#sign-off-attest)) |

`--fail-on high` exits with status 2 when there's a high or critical finding, so a scheduled job or
CI pipeline can alert on it.

## Security design

The tool sees an identity provider with admin-level visibility and writes files full of personal
data. It assumes the laptop, repo or logs could leak, and limits what a leak is worth:

- **Read-only in three places:** Okta grants only `.read` scopes, the CLI refuses any other scope,
  and the client can only send GET requests (a test enforces it).
- **No shared secrets on disk:** Private Key JWT, with every secret fetched from 1Password at run
  time. A secret pasted into the wrong setting is rejected without being printed.
- **Stolen tokens are useless:** DPoP binds each access token to a key that exists only in memory
  for that run.
- **A tested admin-role tradeoff:** only Super Administrator can read admin role assignments. The
  app pairs it with read-only scopes and flags itself for review on every run.
- **Personal data stays in the report:** emails and Slack messages carry only counts, and uploading
  the PDF to Slack is opt-in. Credentials never appear in output or errors.
- **Pinned supply chain:** locked dependencies with a publish-date cutoff.

Details, including the admin-role test results: [docs/security.md](docs/security.md).

## Built with

| | Used for |
|---|---|
| **Okta** | The system being reviewed, read through its API with read-only scopes |
| **GitHub** | The optional second source: org membership and roles, SAML identities, PATs and SSH keys. Read from a snapshot file passed with `--github`; there's no collector for it yet |
| **Slack** | The review and sign-off: a bot posts to one channel and DMs the reviewer (the CISO), who decides with buttons |
| **Jira Service Management** | A tracking ticket per review, and a ticket for each piece of access to remove and each finding to fix |
| **AWS Lambda** | All of the compute and automation: collecting from Okta, posting to Slack, handling button clicks, opening tickets, reminders, and the daily check. Eight functions share one container image (Python, arm64). |
| **AWS Step Functions** | Runs the steps of a review in order and waits for the sign-off |
| **Amazon EventBridge Scheduler** | Starts the quarterly review and the hourly and daily jobs |
| **Amazon S3** | The evidence, kept create-only under Object Lock, and the review's working state |
| **AWS Systems Manager Parameter Store** | The four secrets: the Okta key, the Slack token and signing secret, and the Jira token |
| **Amazon ECR, IAM, CloudWatch Logs, AWS Budgets** | The container image, one least-privilege role per function, 30-day logs, and a cost alert |
| **Terraform** | **All of the AWS infrastructure.** A one-time bootstrap creates the state bucket and the CI roles; everything else is `infra/main`. The only AWS step done by hand is storing the four secret values, which Terraform deliberately never holds. |
| **GitHub Actions** | Tests, security checks and Terraform on every pull request; on `master`, builds the image and applies Terraform after an approval. It signs in to AWS through OIDC, so there are no stored AWS keys. |

## Run it in AWS

A scheduled Step Functions workflow runs the review each quarter, with eight Lambda functions in one
container image. All of it is Terraform, deployed from GitHub Actions through OIDC, and one script
removes it again. Setup: [docs/aws.md](docs/aws.md). Running a review step by step:
[docs/runbook.md](docs/runbook.md). Teardown: [docs/teardown.md](docs/teardown.md).

## Run it locally

The original command-line tool runs the same checks and writes the same report on a laptop:

1. Create an Okta API Services app with read scopes and DPoP
   ([step-by-step](docs/configuration.md#okta-app)), and store its key in 1Password.
2. Run `cp env.example env`, fill it in, and run `git config core.hooksPath .githooks`.
3. Put your HR roster and config in `roster/` (git-ignored), then run:

   ```bash
   ./run.sh --roster roster/hr-roster.csv --config roster/config.json
   ```

Email and Slack are optional: see [docs/notifications.md](docs/notifications.md). All settings,
PDF branding and the roster format are in [docs/configuration.md](docs/configuration.md).

## Limitations

- There's no collector for the second source yet. GitHub data is a snapshot file passed with
  `--github`, and the AWS pipeline doesn't pass one, so its runs are Okta-only.
- MFA status comes from enrolled factors. It doesn't check whether a sign-on policy requires MFA.
- Admin roles granted through a group aren't expanded to the group's members yet.
- Apps assigned through several groups are listed once per group.

## Development

```bash
uv run pytest -q
uv run python scripts/render_samples.py   # after changing the PDF layout or demo data
uv run python scripts/e2e_local.py        # one whole review through the AWS workflow, all in memory
```

The tests cover every check, the Okta client (including DPoP), the PDF, email and Slack, the Slack
review and sign-off, JSM tickets, the S3 evidence store and teardown, and they fail if the sample
report in this README is out of date. None of them reach AWS, Slack or Jira.

### Compliance workflow

Every pull request and push to `master` runs the [Compliance workflow](docs/ci.md):

| Check | SOC 2 | ISO 27001 |
|---|---|---|
| Tests, including the demo review | CC8.1 | A.8.29 |
| Secret scan of the full git history (gitleaks) | CC6.1 | A.8.12 |
| Dependency vulnerabilities and lockfile (pip-audit) | CC7.1 | A.8.8 |
| Workflow security lint (zizmor) | CC8.1 | A.8.9 |
| Terraform format, validation, lint and security scan (tflint, checkov) | CC8.1 | A.8.9 |
| Branch protection on `master` | CC8.1 | A.8.32 |

The results are bundled as evidence with SHA-256 hashes. On `master`, the bundle is signed with a
GitHub artifact attestation. All actions are pinned to commit SHAs, and jobs run with minimal
permissions.

Seeded from `okta-access-review` at commit 1a20697.

Related: [okta-mcp-local](https://github.com/matt-spellcaster/okta-mcp-local) connects an AI
assistant to Okta for interactive admin work, with the same credential handling.
