# okta-access-review-aws

A quarterly user access review of an Okta org that runs in AWS, is approved in Slack, and tracks fixes
as Jira Service Management tickets. It compares Okta users, groups, apps, MFA enrollment and admin
roles with an HR roster, flags access to remove or confirm, and saves the results as evidence for
SOC 2 (CC6.1–CC6.3) and ISO 27001:2022 (A.5.15–A.8.5). Okta is only ever read.

- **In AWS** ([docs/aws.md](docs/aws.md)): a scheduled Step Functions workflow collects the review,
  asks the admin to decide in Slack with proposals already filled in, and asks the CISO to sign off.
  It then opens a JSM ticket for each piece of access to remove, under one parent ticket per quarter.
  Reminders, escalation to the CISO, and a daily check that each resolved ticket really changed
  Okta are built in. Built with Terraform, and removed with one script ([docs/teardown.md](docs/teardown.md)).
- **Or locally**, as the original command-line tool: the same checks and report, run on a laptop.

Seeded from `okta-access-review` at commit 1a20697. The local tool below works the same way.

- 14 checks, such as leavers who still hold a working API credential, terminated users with live
  accounts, missing MFA, app assignments nobody uses, and API clients with write access.
- Read-only scopes, Private Key JWT, and DPoP-bound tokens.
- Output: a PDF with a sign-off page, CSVs, the raw data, and a manifest of SHA-256 hashes.
- Shows how many reviews in a row each finding has been open, from earlier report folders it has
  verified, and `access-review attest` records a sign-off tied to the report's manifest.
- The report is marked incomplete if Okta withholds any data.
- Optionally emails the PDF and posts a summary to Slack. Messages contain no personal data.

## Sample report

Every run produces a PDF like this. All data is from **Acme**, a fictional company.

![Page 1 of the sample report: summary and findings by severity](docs/images/report-page-1.png)

<details>
<summary>Page 2: remediation, control mapping and access by user</summary>

![Page 2 of the sample report: remediation, SOC 2 and ISO 27001 control mapping, and access by user](docs/images/report-page-2.png)

</details>

[Full sample PDF](docs/sample-report.pdf) · The same run posted to Slack:

![Slack summary of the Acme demo review, with the PDF report attached in the thread](docs/images/slack-summary.png)

## Try it without Okta

```bash
uv run access-review \
  --snapshot fixtures/demo_snapshot.json \
  --roster fixtures/demo_roster.csv \
  --config fixtures/demo_config.json \
  --as-of 2026-09-15
```

The demo org has exactly one planted issue for each check, and the tests confirm the review finds
those and nothing else.

## Checks

| ID | Finds | Severity | Controls |
|---|---|---|---|
| AR-01 | Terminated in HR, but the account is still live | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.18 |
| AR-02 | Contract or end date has passed | high | SOC 2 CC6.2 · ISO A.5.18 |
| AR-03 | Account with no HR record (service accounts can be listed) | high | SOC 2 CC6.2 · ISO A.5.16 |
| AR-04 | Can sign in, but has no MFA factor | high | SOC 2 CC6.1 · ISO A.8.5 |
| AR-05 | No sign-in for 90+ days | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-06 | Created 14+ days ago and never used | medium | SOC 2 CC6.2 · ISO A.5.16 |
| AR-07 | Contractor in an employee-only group | medium | SOC 2 CC6.3 · ISO A.5.15 |
| AR-08 | Missing manager or department | low | SOC 2 CC6.2 · ISO A.5.16 |
| AR-09 | Suspended or deprovisioned, but still in groups or apps | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-10 | Service app with write scopes or an admin role that can make changes (high if Super Administrator) | medium | SOC 2 CC6.3 · ISO A.8.2 |
| AR-11 | Admin user, for the reviewer to confirm | info | SOC 2 CC6.3 · ISO A.8.2 |
| AR-12 | Leaver still holds an API token, or an API client they set up | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.18 |
| AR-13 | Signed in, or used a credential, after their last working day | critical | SOC 2 CC6.2, CC7.2 · ISO A.5.18, A.8.16 |
| AR-14 | Directly assigned app with no sign-in to it for 90+ days (skipped if the System Log can't be read in full) | medium | SOC 2 CC6.2 · ISO A.5.18 |

AR-01 to AR-03, AR-12 and AR-13 compare Okta with an HR roster: a CSV exported from the HR system
and passed in with `--roster` (there's no live HR integration yet). Without it they're skipped, and
the report says so. Thresholds and group names are configurable.

AR-12 and AR-13 are about the leaver cases an account status doesn't show. An Okta API token keeps
working after the account is deactivated, and so does an API client the leaver set up, on its own
credentials. AR-13 reads the System Log to say whether any of it was actually used after their last
working day. Okta keeps 90 days of log data, so a termination older than that is reported as a gap
rather than as nothing to see.

## Evidence produced

Each run writes a folder named after its collection time:

| File | For |
|---|---|
| `report.pdf` / `report.md` | Findings with fixes and control mapping, access by user, reviewer sign-off |
| `access_matrix.csv` | Every user's access, with blank `decision` and `reviewer` columns to fill in |
| `findings.csv` | Tracking remediation, with how long each finding has been open |
| `snapshot.json` | The exact Okta data the checks ran on |
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

## Run it on your org

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

Related: [okta-mcp-local](https://github.com/matt-spellcaster/okta-mcp-local) connects an AI
assistant to Okta for interactive admin work, with the same credential handling.
