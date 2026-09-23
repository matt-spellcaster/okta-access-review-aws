# okta-access-review-aws

Quarterly Okta user access review that runs in AWS, is approved in Slack, and opens remediation
tickets in Jira Service Management. Produces SOC 2 / ISO 27001 audit evidence. Seeded from
`okta-access-review` at commit 1a20697.

Why each invariant below exists is in `docs/design.md`. Read the matching section before changing
that area.

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

## Hard rules

- Okta is read-only. `OktaClient` sends only GETs plus the token POST. No write calls, no scope
  that doesn't end in `.read`, no Okta Terraform provider.
- Writes go only to the configured Slack channel, DMs to the configured CISO, one JSM project, and
  this project's own S3 buckets.
- The tool never changes anyone's access. In JSM it creates tickets and comments; its one move is
  closing a review's tracking ticket once every ticket under it is settled (`JiraClient.close`).
- Slack channel posts and email bodies carry only counts, completeness, check titles and ticket
  links. Personal data goes only in the CISO's DM, the PDF and JSM tickets. The PDF reaches the
  channel only when `slack_channel_pdf` is on.
- Step Functions input and output carry IDs, hashes and counts only.
- Evidence objects in S3 are create-only (`If-None-Match: *`). Only `scripts/teardown.py` may use
  `s3:BypassGovernanceRetention`; no Lambda role is ever granted it.
- Never commit `env`, key files, `reports/`, Terraform state, `*.tfvars` with real values, or
  anything in `roster/` except its README.
- `.notes/` never leaves this machine: never commit, quote or summarise it in any tracked file,
  commit message, PR, issue or hosted tool. The repo is public; tracked content is about the tool
  and its users, not about why it is being built.
- Never read `env` or print `OKTA_PRIVATE_KEY`, `SMTP_PASSWORD`, `SLACK_WEBHOOK_URL`,
  `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` or `JIRA_API_TOKEN`. Webhook and Slack upload URLs are
  credentials too; keep them out of error messages. Never pass an unchecked `*_REF` to `op` or an
  unchecked `*_PARAM` to SSM.
- Tests never call real AWS, Slack, Jira or SMTP. `tests/conftest.py` clears those settings; inject
  fakes through `session=` / `client=`.

## Evidence and completeness

- Silence is never absence. A read that failed or never ran is a gap, `None` or "unknown", never
  "nothing found" or `False`, and unknown always ranks as the worse case.
- `report.all_gaps` is the only completeness answer (it reads every `SourceMeta`). Consumers use
  `ReviewRun.gaps` / `.complete`, never `snapshot.gaps`.
- `watch.still_present` returns `None` when the data behind a ticket wasn't read; each branch needs
  its own signal (`admin_roles is None`, `apps_complete`, `snapshot.gaps`, `leavers is None`).
- `items.py` never proposes Revoke on missing or truncated data; the item becomes "decide".
- `history.py` and `attest` never write outside the report folder, never change a hashed file,
  never send anything, and never count a review they couldn't verify. `reopened` is never set
  across a review that skipped the check.

## Identity graph

- `Snapshot` (`models.py`) is the Okta adapter's output, the same for live and fixture data, and
  never grows to fit another source. Other sources are projected into an `IdentityGraph` in `identity/`.
- A principal links to a person only through an evidenced `LinkMethod`, never by name or email
  similarity. Graph findings reach review items only via `checks.graph_findings_by_identity`
  (the owner's item) or `checks.graph_findings_by_subject` (the account's own item).
- A graph finding's subject is `{source}/{principal.id}` (`checks.graph_subject`), never a label.
- The graph is built on every review, from Okta alone if needed. `handlers.verify_daily` builds none.
- `IdentityGraph.grants` is only what a source stated verbatim: use `grants_for` / `all_grants`
  (call `all_grants` once rather than looping). Derive graphs with `dataclasses.replace`.
- A source adapter decides which of its roles are elevated; an unrecognised role counts as elevated.
- A graph source's own snapshot goes into the run folder through `extra_files` so it's hashed.

## Service account register

- An entry with no owner, or an owner no source evidences, never removes a finding: AR-15 reports
  it one severity milder, floored at `low`. Only an attested owner clears it.
- Entries are scoped to a source, case-folded on both halves, and must match exactly one live
  account; otherwise they declare nothing and record a gap.
- The register goes into the signed manifest, so it stays JSON-serialisable.

## Leaver checks

- A service account a leaver owned or held the secret of is AR-18's (answer for it, rotate what they
  held; settled by reviewer), never AR-17's (revoke) or AR-12's (API tokens only, verified in Okta).
  AR-13 reads the leaver's own account only. Any new check about an account a leaver was accountable
  for must fit this partition. Nothing reads the client secrets endpoint.
- AR-18's accounts come only from `checks.leaver_accountable_accounts`. AR-09 and
  `items._app_proposal` stand down for the Okta users in it; a leaver's own Okta account (its roster entry
  is gone) is never in it. Declare any new stand-down in `checks.STANDS_DOWN_FOR`.
- No account is the subject of both a REMOVE and a RETAIN finding
  (`test_no_account_is_told_to_go_and_to_stay`).

## Review items and tickets

- Ticket identity is `(check_id, subject)` hashed into a permanent Jira label.
- A `needs_graph` check is in `REVIEW_CHECKS` and in `FIX_CHECKS` (not only `URGENT_CHECKS`).
  `tests/test_tickets.py` guards this.
- Cross-source concerns go in `ReviewItem.outside_okta`, never `.concerns`. Reviewer-facing wording
  says what the decision doesn't settle, never "outside Okta" (`slack_review.OUTSIDE`).
- A ticket that closes on an Okta re-read states what it doesn't cover via `tickets._scope_to_okta`.
- How a ticket is verified comes only from `tickets.record_verify_mode`. Never write a blanket
  "verified in Okta".
- Departure bundles (`transitions.py`) are per identity, use the roster as the denominator, walk in
  login order, and don't exist (`None`) without a graph and a roster.
- `load_items` splits pre-format-3 files in memory only.

## review_items.json

- Streamed, never materialised: `items_chunks` → `extra_files` → `report._write_text` →
  `report._sha256` (`hashlib.file_digest`). One item per line, no `indent=`, `ensure_ascii=True`,
  rows from `vars(item)`. Six tests pin this; read `docs/design.md` before touching it.

## Adding things

- New check: a `CHECKS` entry with SOC 2 and ISO 27001 control IDs and a `disposition`, a planted
  case in the fixture it reads, and updated expectations in
  `test_demo_findings_are_exactly_the_planted_ones` and
  `test_cross_source_findings_carry_the_planted_severities`.
- New source adapter: snapshot shape with `from_dict`/`to_dict`, a hand-written fixture, a
  projection into `IdentityGraph`, any new `CredentialKind`s, a re-export from `identity/__init__.py`,
  and tests, all before a live collector. If it emits `GrantKind.GROUP`, it populates `group_apps`.
- Fixtures match the shape the real API returns; check the vendor docs for every field.
- `findings.csv` columns are `FINDING_COLUMNS`; changing them means updating
  `test_findings_csv_header_is_explicit`.
- After changing the PDF layout or demo fixtures, run `uv run python scripts/render_samples.py` and
  look at `docs/images/*.png`. README images use fixture data or fully redacted screenshots.
- Never write at the top level of `--out`; one folder per run.

## Toolchain

- Python 3.11+, dependencies pinned by `uv.lock` and `exclude-newer` in `pyproject.toml`.
- Terraform: pin Terraform, provider and tflint versions; commit `.terraform.lock.hcl` with
  linux_amd64, linux_arm64 and darwin_arm64 hashes; declare every log group. Terraform never
  creates or reads the `/uar/` SSM parameters. Every checkov skip has a reason in `infra/.checkov.yaml`.
- CI: pin actions to full SHAs with a version comment, `permissions: {}` at the top, no `${{ }}` in
  `run:`, and run `uvx zizmor@<pinned> --offline .github/workflows` after editing. Renaming a job
  means updating `REQUIRED_CHECKS` in `scripts/ci/check_branch_rules.py` and the ruleset. The
  `deploy` job never shares a concurrency group. See `docs/ci.md`.
