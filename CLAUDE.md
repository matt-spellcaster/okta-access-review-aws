# okta-access-review-aws

Quarterly Okta user access review that runs in AWS, is approved in Slack, and opens remediation
tickets in Jira Service Management. Produces SOC 2 / ISO 27001 audit evidence. Seeded from
`okta-access-review` at commit 1a20697.

## Commands

- Tests: `uv run pytest -q`
- Demo (no Okta needed): `uv run access-review --snapshot fixtures/demo_snapshot.json --roster fixtures/demo_roster.csv --config fixtures/demo_config.json --github fixtures/demo_github.json --as-of 2026-09-15`
- Live, local: `./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json` (needs `env` and 1Password)
- Verify a run folder: `uv run access-review attest reports/<folder>`
- Whole AWS workflow in memory (no AWS/Slack/Jira): `uv run python scripts/e2e_local.py`
- Terraform: `terraform -chdir=infra/main fmt -check && terraform -chdir=infra/main validate`;
  scan with `uvx checkov@<pinned> -d infra --config-file infra/.checkov.yaml`
- Image: `scripts/build_image.sh <tag>`; teardown dry run: `uv run python scripts/teardown.py`;
  after teardown, confirm the account is clean: `uv run python scripts/teardown.py --check`
- Setup and operations: `docs/aws.md`; running a review: `docs/runbook.md`; teardown: `docs/teardown.md`

## Rules

- Okta is read-only. `OktaClient` only sends GET requests, plus the token POST. Never add
  write calls, never request a scope that doesn't end in `.read`, and never use the Okta
  Terraform provider.
- Writes go only to: the configured Slack channel and DMs to the configured CISO, one
  JSM project, and this project's own S3 buckets. Nothing else.
- Remediation is done by a person working a JSM ticket. The tool never changes anyone's access. In
  JSM it creates tickets and comments on them; the one move it makes is closing a review's tracking
  ticket once every ticket under it is verified in Okta (`JiraClient.close`).
- Slack channel posts and email bodies contain only counts, completeness, check titles and ticket
  links. Personal data goes only in the CISO's DM, the PDF, and JSM tickets (the JSM project must
  restrict issue visibility). The PDF goes to the review channel only when `slack_channel_pdf` is on,
  which is an explicit choice that everyone in the channel may see it.
- Step Functions input and output never carry personal data: IDs, hashes and counts only.
- Evidence objects in S3 are create-only (`If-None-Match: *`). Nothing except `scripts/teardown.py`
  may use `s3:BypassGovernanceRetention`, and no Lambda role is ever granted it.
- Never commit `env`, key files, `reports/`, Terraform state or `*.tfvars` with real values, or
  anything in `roster/` except its README.
- `.notes/` is local working material and never leaves this machine: never commit it, never quote
  or summarise it in a commit message, a PR description, an issue, a code comment or any other
  tracked file, and never paste it into a hosted tool. Treat it as private context that informs the
  work without appearing in it. This repo is public, so the same applies to anything derived from
  those notes: keep tracked content about the tool and its users, not about why it is being built.
- Never read `env` or print `OKTA_PRIVATE_KEY`, `SMTP_PASSWORD`, `SLACK_WEBHOOK_URL`,
  `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` or `JIRA_API_TOKEN` (webhook URLs and Slack's pre-signed
  upload URLs are credentials too; keep them out of error messages). Never pass an unchecked
  `*_REF` value to `op` or an unchecked `*_PARAM` name to SSM — both echo bad references.
- Tests never call real AWS, Slack, Jira or SMTP. `tests/conftest.py` clears those settings; inject
  fakes through `session=` / `client=` parameters like the existing tests do.
- A new check needs: an entry in `CHECKS` (`checks.py`) with SOC 2 and ISO 27001 control IDs, a planted
  case in the fixture for the source it reads (`fixtures/demo_snapshot.json`, or
  `fixtures/demo_github.json` for a `needs_graph` check), an updated expectation in
  `test_demo_findings_are_exactly_the_planted_ones` **and in
  `test_cross_source_findings_carry_the_planted_severities`** (severity is the judgement in these
  checks; asserting subjects alone lets a constant pass). A `needs_graph` check reads `ctx.graph`
  rather than `ctx.snapshot` and is skipped when no graph was built.
- A graph finding's subject is `{source}/{principal.id}` (`checks._subject`), never the label.
  Ticket identity is `(check_id, subject)` hashed into a permanent Jira label, and a label is a
  display name: a GitHub login can be renamed and two Okta service clients can share an app label,
  which would collapse two unremediated problems onto one ticket. The readable name goes in the
  detail, which is what the ticket body and the PDF show.
- A `needs_graph` check settles by reviewer (`REVIEW_CHECKS` in `tickets.py`) until `watch.still_present`
  can see that source's gaps. It re-verifies against a fresh Okta snapshot only, so a graph finding
  would otherwise be ticked off because the other source's read failed. It must also be in
  `FIX_CHECKS` or `workflow.URGENT_CHECKS`, or no ticket is ever opened and its `verify_mode` is
  configuration nothing consults. `tests/test_tickets.py` guards both.
- `report.all_gaps` is the single answer about completeness and it reads **every** `SourceMeta` in
  the graph, Okta included, because a projection records gaps the snapshot never had. Slack, email,
  the CLI and the Step Functions output take it from `ReviewRun.gaps`/`.complete`, never from
  `snapshot.gaps`, which speaks for Okta alone. `report.other_sources` is display only.
- Emptiness is only evidence when the read that would have said so ran. A check reading credentials
  asks `_credential_evidence_complete` first (`SourceMeta.activity_complete`, not `.complete` --
  identity gaps say nothing about whether the scopes were read), and `_write_access` returns None,
  not False, when they were not. Unknown is never ranked as the milder case.
- A graph source's own snapshot is written into the run folder through `extra_files` so the manifest
  hashes it (`review.GITHUB_SNAPSHOT_FILE`). Findings whose evidence is outside the bundle cannot be
  re-verified by `attest`. `review._note_skew` records a gap when two sources were read more than
  `SOURCE_SKEW_DAYS` apart, after composing so it does not also clear `activity_complete`.
- After changing the PDF layout or demo fixtures, run `uv run python scripts/render_samples.py`
  and look at `docs/images/*.png` before committing. README images use fixture data, or real
  screenshots with every name, email, org URL and ID blacked out, including inside PDF previews.
- Keep the snapshot format (`models.py`) the same for live and fixture data; the existing checks only
  see `Snapshot`. `Snapshot` is the Okta source adapter's output and never grows to fit another
  source: `identity/` composes above it, and cross-source checks read an `IdentityGraph` built by
  projecting each source into it.
- In `identity/`, a principal is tied to a person by an evidenced `LinkMethod` or not at all -- never
  by name or email similarity, because a false link marks a credential as accounted for when nobody
  is. Completeness is per source (`SourceMeta`): a read that failed is "incomplete", never "nothing
  found".
- A new source adapter in `identity/` needs: its own snapshot shape with `from_dict`/`to_dict`, a
  hand-written fixture in `fixtures/` with one planted case per thing a check will find, a
  projection into `IdentityGraph`, any new `CredentialKind` members it emits, a re-export from
  `identity/__init__.py`, and tests -- before any collector that talks to the live API. The model
  and the projection share the adapter module (`identity/github.py`) until a second reader of that
  snapshot exists; `models.py` is split out only because fourteen checks read it.
- **A fixture's shape is the shape the real API returns.** Check every field against the vendor's
  documentation before building on it: a hand-written fixture that invents fields yields checks
  validated against data no collector can supply. Where the API cannot provide something, the
  snapshot says so (`sso_enabled`, `credentials_complete`) rather than leaving it blank. The field
  allowlist here is the requirement the collector must meet, per `ActivityEvent.from_okta`.
- Review proposals (`items.py`) never propose Revoke on missing or truncated data; the item becomes
  "decide" instead.
- Findings history (`history.py`) and `attest` never write outside the one report folder, never
  change a hashed file, and never send anything. History must never count a review it couldn't
  verify against its manifest; when unsure, count lower. `reopened` ("Back again") asserts a
  problem was fixed and returned, so it is never set across a review that *skipped* the check --
  `PriorReview.skipped` comes off that review's `skipped_checks`.
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
