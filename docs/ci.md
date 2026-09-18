# Compliance workflow

[`.github/workflows/compliance.yml`](../.github/workflows/compliance.yml) runs on every pull request,
every push to `master`, weekly, and on demand. Each job runs one check, saves its result as JSON,
and fails if the check fails. The Evidence job bundles the results. On `master`, the Deploy job
then ships the change to AWS (see [aws.md](aws.md)).

## Checks

| Job | What it checks | Tool | SOC 2 | ISO 27001:2022 |
|---|---|---|---|---|
| Tests | The test suite passes, the demo review runs, and the README sample is current | pytest | CC8.1 | A.8.29 |
| Secret scan | No secrets anywhere in the git history (values are redacted in the report) | gitleaks | CC6.1 | A.8.12 |
| Dependency audit | `uv.lock` matches `pyproject.toml`, and no locked package has a known vulnerability | pip-audit | CC7.1 | A.8.8 |
| Workflow lint | The workflows themselves: pinned actions, minimal token permissions, no script injection, no leftover credentials | zizmor | CC8.1 | A.8.9 |
| Terraform | `infra/` is formatted, valid and lint-clean, and has no security finding that isn't accepted, with a reason, in `infra/.checkov.yaml` | terraform, tflint, checkov | CC8.1 | A.8.9 |
| Branch rules | `master` requires pull requests and the five checks above, and blocks force pushes and deletion | GitHub rulesets API | CC8.1 | A.8.32 |

Two more jobs don't produce evidence, and only run once the AWS repository variables exist:

| Job | When | What it does |
|---|---|---|
| Terraform plan | Pull requests from branches in this repository | Plans `infra/main` with the read-only plan role (no state lock, no writes) and shows the plan on the run's summary page |
| Deploy | Pushes to `master`, after an approval in the `production` environment | Builds the Lambda image, pushes it to ECR, and applies `infra/main` with the apply role |

The weekly run catches newly published vulnerabilities and changed repository settings, even when
nobody has committed.

## Evidence

The **Evidence** job runs even when a check fails. It:

1. collects every job's results and raw reports (JUnit XML, gitleaks and pip-audit JSON, zizmor
   findings, the branch rules it read, and the demo review's report)
2. writes `summary.md`, which also appears on the workflow run's page, and `manifest.json`, which
   holds the commit, run ID, each check's status and controls, and a SHA-256 hash of every file
3. on `master`, signs the bundle with a
   [GitHub artifact attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations),
   a Sigstore signature tied to this repository, workflow and commit
4. uploads `compliance-evidence-<commit>.tar.gz`, kept for 90 days
5. fails if any check failed or didn't report

To verify a downloaded bundle:

```bash
gh attestation verify compliance-evidence-<commit>.tar.gz --repo <owner>/okta-access-review-aws
```

## Hardening

- Every action is pinned to a full commit SHA, with the version in a comment. Dependabot proposes
  updates weekly, after a 7-day cooldown.
- The workflow starts with no token permissions. Each job gets only what it needs: `contents: read`,
  and the Evidence job also gets `id-token` and `attestations` to sign.
- Checkouts don't keep the token (`persist-credentials: false`), and dependency caching is off, so a
  pull request can't poison a cache used by `master`.
- gitleaks, Terraform and TFLint are downloaded from their releases and checked against pinned
  SHA-256s. pip-audit, zizmor and checkov run at pinned versions.
- AWS access uses GitHub's OIDC token; there are no AWS keys anywhere. Pull requests can only assume
  the read-only plan role, and only the `production` environment can assume the apply role.
- `master` runs are never cancelled by a newer push, so a deploy can't stop halfway through an apply.
- Pull requests from forks never get signing permissions: attestation runs only on `master`.

## Branch rules

The Branch rules check expects a repository ruleset on `master` with:

- **Require a pull request before merging** (0 approvals is fine for a single maintainer)
- **Require status checks to pass:** `Tests`, `Secret scan`, `Dependency audit`, `Workflow lint`,
  `Terraform`
- **Block force pushes**
- **Restrict deletions**

Set it up under **Settings → Rules → Rulesets → New branch ruleset**, targeting the default branch.
