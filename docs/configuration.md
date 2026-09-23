# Configuration

## Okta app

1. In the Okta Admin Console, go to **Applications → Create App Integration → API Services** and
   name it, e.g. "Access Review (read-only)".
2. **Client authentication:** Public key / Private key. Generate a key, save it as PEM, and note its
   Key ID. Leave **Require DPoP header in token requests** on.
3. **Okta API Scopes:** grant only these:

   | Scope | Used for |
   |---|---|
   | `okta.users.read` | Users, last sign-in, MFA factors |
   | `okta.groups.read` | Groups and members |
   | `okta.apps.read` | Apps and their user and group assignments |
   | `okta.appGrants.read` | API scopes granted to other apps (AR-10) |
   | `okta.roles.read` | Admin roles of users and API apps (AR-10, AR-11) |
| `okta.logs.read` | System Log: what a leaver did after they left, and whose API client secrets they held (AR-13, AR-18) |
| `okta.apiTokens.read` | API tokens and who owns them (AR-12) |

4. **Admin roles:** Super Administrator for full coverage, or Read-Only Administrator for a review
   that skips admin roles. See [the tradeoff](security.md#admin-role-a-tested-tradeoff).
5. Optional: under **General**, limit token requests to a network zone.
6. Store the PEM in a 1Password Secure Note, then delete the downloaded file.

## `env`

Copy `env.example` to `env` (git-ignored). Secrets are always `op://` references.

| Setting | Required | Notes |
|---|---|---|
| `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_KEY_ID` | yes | From the Okta app |
| `OKTA_PRIVATE_KEY_REF` | yes | 1Password reference to the PEM |
| `OKTA_SCOPES` | yes | Read scopes only; the CLI refuses anything else |
| `OKTA_DPOP` | no | `true` (default); must match the app's DPoP setting |
| `REPORT_EMAIL_*`, `SMTP_*` | no | See [notifications](notifications.md#email) |
| `SLACK_*` | no | See [notifications](notifications.md#slack) |

## Review config (`--config`)

A JSON file. Every key is optional, and unknown keys are rejected.

| Key | Default | Meaning |
|---|---|---|
| `inactive_days` | `90` | AR-05 threshold |
| `never_signed_in_grace_days` | `14` | AR-06 threshold |
| `employee_only_groups` | `[]` | Groups contractors shouldn't be in (AR-07) |
| `admin_groups` | `["Okta Administrators"]` | Groups treated as admin access (AR-11) |
| `service_accounts` | `[]` | The service account register: accounts that are not people, and who owns each (AR-03, AR-15). Below |
| `activity_lookback_days` | `90` | How far back to read the System Log (AR-13, AR-18); Okta keeps 90 days |
| `org_timezone` | `"America/Chicago"` | Where the org is, for resolving an `end_date` with no time on it (AR-13) |
| `history_reviews` | `12` | How many earlier reviews to read for findings history, below |
| `branding` | none | PDF branding, below |

Example: [`fixtures/demo_config.json`](../fixtures/demo_config.json).

### The service account register

`service_accounts` is the register of accounts nobody signs in as. An entry is a bare login, or an
object naming an owner:

```json
"service_accounts": [
  "svc-legacy@acme.example",
  {
    "id": "Terraform Automation",
    "owner": "priya.shah@acme.example",
    "purpose": "Applies infrastructure changes from CI",
    "reviewed": "2026-07-01"
  },
  {"source": "github:acme-eng", "id": "acme-ci-bot", "purpose": "Publishes release artifacts"}
]
```

| Field | Meaning |
|---|---|
| `id` | The name a person knows the account by: an Okta login, an Okta API service client's app label or client ID, a GitHub member login |
| `source` | Which estate the entry is about. `okta` by default; a GitHub org is `github:<org>` |
| `owner` | The owner's email, matched against their Okta profile email. Optional, and the field that does the work |
| `purpose` | Free text, carried into the evidence an auditor reads |
| `reviewed` | `YYYY-MM-DD`, when someone last confirmed the entry is still true. Worth setting on a GitHub entry: see below |

What each field changes:

- **An entry** keeps the account out of AR-03 ("no HR record"), whatever else it says. That is all
  the bare-login form ever meant and all it still means.
- **An owner** ties the account to that person. It appears on their access review, and in their
  departure bundle if they leave — an ownership claim goes stale the moment the claimant does, so
  the long tail of a departure is not only their own credentials but everything they answered for.
  This is the only thing that stops AR-15 reporting the account.
- **An owner who has left** is AR-18, and the entry is what finds it: the review reads the HR roster,
  sees the person is gone, and reports the account as one nothing and nobody is now accountable for.
  The fix is to name a new owner here, or to decommission the account — not to revoke it, because
  something is presumably still calling it. An Okta API client is the case this exists for:
  deactivating the person who owned it does not touch it, and no other check asks who is now
  accountable for it. The same finding asks for every secret the leaver held to be rotated, which
  leaves the client running for its new owner.
  A `reviewed` date on the entry is what tells the reviewer how old the claim they are replacing is.
- **No owner** is reported by AR-15 one severity milder than an undeclared account, never silently.
  Somebody wrote the account down and named nobody; that is worth a rung and no more.
- **An owner nobody can be reached at** — a typo, or a person with no account in any source this
  review read — is worth exactly what no owner is worth, and reported the same way. An address is
  typed by hand, and one transposition would otherwise read as ownership on every screen while
  joining to no person and reaching no departure bundle. The review records a gap naming the entry,
  so the register can be corrected rather than quietly trusted.

Two entries for one account are rejected: one account has one owner, and picking between two claims
would make the register the ambiguity it exists to remove. Entries are scoped to a source, so
declaring an Okta login never declares a GitHub member with the same name.

An entry matching nothing in its source is recorded as a data gap rather than ignored — a renamed or
deleted account leaves a claim that looks like coverage and is not. The same applies to an app label
two service clients share: the entry declares neither, and the gap says to name the client ID
instead, and to an entry naming a source this review never read. `source` and `id` are both matched
without regard to case, so `github:Acme-Eng` and `github:acme-eng` are one estate.

Two more things a name can do that an ID cannot:

- **A replaced Okta service client.** Deactivating a client does not remove it from the org, so the
  old and the new "Terraform Automation" both come back in the read. A label picks out the client
  still running, so the entry keeps declaring the live one; the deactivated one is a separate
  account nobody declared, and is reported as such. If both are still running — or either has a
  status this review does not recognise — the label declares neither and the gap says to name the
  client ID.
- **A GitHub login its owner renamed.** GitHub puts a freed login back in the pool, so an entry can
  go on matching a *different* account that has since claimed the name. When the entry has a
  `reviewed` date and GitHub says the account was created after it, the entry declares nothing and
  the review records a gap. Without a `reviewed` date there is nothing to check it against, which is
  the practical reason to set one on a GitHub entry. An account that already existed and renamed
  into a freed login is beyond what matching on a name can see.

The register is written into `manifest.json` with the rest of the config, so who was declared and
who answers for them is part of the signed evidence.

### PDF branding

```json
"branding": {
  "name": "Acme",
  "tagline": "Security & Compliance",
  "primary": "#0B2545",
  "accent": "#F2A541",
  "footer": "Confidential",
  "logo": "acme"
}
```

- `primary` colors the header band, title and headings. `accent` colors the logo tile and the line
  under the band. Both must be `#rrggbb`.
- `logo` selects a built-in logo drawn in code. `acme` is the only one; there are no image files.
- Severity colors are fixed so they mean the same thing in every report.
- Without `branding`, the PDF uses a plain layout. Invalid branding stops the run before it
  contacts Okta.

## HR roster (`--roster`)

```csv
email,name,employment_type,status,end_date,manager
ana@example.com,Ana Diaz,employee,active,,Sam Lee
raj@example.com,Raj Rao,contractor,active,2026-12-31,Sam Lee
bo@example.com,Bo Kim,employee,terminated,2026-08-01,Sam Lee
cy@example.com,Cy Okoro,employee,terminated,2026-08-29T14:05:00,Sam Lee
```

- `employment_type`: `employee` or `contractor`
- `status`: `active`, `leave` or `terminated`
- `end_date`: termination date or contract end date (optional). Either a date, or an ISO timestamp
  if the HR system records the moment access was meant to stop.

### What `end_date` means to AR-13

AR-13 reports activity *after* someone left, so it needs to know when that was, to the minute.

- **A date** means the whole day was theirs to work. The cutoff is the end of that day in
  `org_timezone`, so someone working a late last evening isn't reported as an incident.
- **A timestamp** is used exactly as given. Prefer it for an involuntary termination, where the
  difference between 2pm and end of day is the whole point of the check. A timestamp with no UTC
  offset is read in `org_timezone`.

Everything else, including AR-02, only compares dates, so a timestamp changes nothing there.

Keep real rosters in `roster/`, which is git-ignored.

The roster is an export, not a live connection, so each report keeps a copy of it as `roster.csv`,
and `manifest.json` records its file name (not the full path), row count and SHA-256. An auditor
can then see exactly which HR data a review was compared against.

## Command-line options

| Option | Meaning |
|---|---|
| `--snapshot FILE` | Review a saved snapshot instead of calling Okta |
| `--roster FILE` | HR roster; enables AR-01 to AR-03, AR-12 and AR-13 |
| `--config FILE` | Review config |
| `--out DIR` | Output folder (default `reports/`) |
| `--as-of DATE` | Review date (default: UTC date the data was collected) |
| `--fail-on SEVERITY` | Exit with status 2 if any finding is at that severity or worse |
| `--no-email`, `--no-slack` | Skip a notification for one run |

Exit codes: `0` ok, `1` configuration or Okta error (or the report folder is already signed off),
`2` `--fail-on` threshold reached, `3` report saved but a notification failed. A mistyped option
also exits `2`, as with any command-line tool, so a job that alerts on `--fail-on` should also
check that a report was written.

## Findings history

Each run reads the earlier review folders in the same `--out` folder and adds a **History** column
to the report, PDF and `findings.csv`: "New", "3 reviews in a row, first seen 2026-03-15", or
"Back again" for a finding that was clear at the last review but has been seen before. Email and
Slack get a count only.

- A review is a review date, not a run. Several runs with the same `--as-of` count once, and only
  the newest is used.
- A folder is only used after its `findings.csv` matches the hash in its own `manifest.json`. A
  review of the same org that can't be verified ends the count there, so a count can come out too
  low but never too high. The report says when this happened.
- Folders for other orgs, symlinks and anything without a readable `manifest.json` are ignored and
  listed under `history` in the new `manifest.json`, with the reviews that were read.
- "First seen" is the earliest review still in the folder, within `history_reviews`. Deleting old
  report folders shortens the history.
- Findings are matched on check and subject, ignoring case. AR-10's subject is the app's label, so
  renaming an app starts its history again, and two apps with the same label share one.

History changes no severity and doesn't affect `--fail-on`. On a first run, or with a new `--out`,
there's no History column.

## Sign-off (`attest`)

The PDF ends with a sign-off block for a printed or PDF signature. To record the sign-off in the
report folder instead:

```
access-review attest reports/20260915T140000Z --decision approved --reviewer "Priya Shah"
```

This checks every file against `manifest.json`. Only if they all match does it append a record to
`attestations.json` in that folder: reviewer, decision, optional `--note`, time, and the SHA-256 of
`manifest.json`, so the sign-off can't be moved to a different report. Several people can sign
off; each record includes the hash of the one before it.

| Option | Meaning |
|---|---|
| `--decision` | `approved`, `approved-with-exceptions` or `rejected` |
| `--reviewer` | Who is signing off. Free text, one line, up to 200 characters |
| `--note` | Optional comment, one line, up to 1000 characters |

Without `--decision`, `attest` only checks the folder and lists the sign-offs so far, which is how an
auditor re-checks a folder. It reports a sign-off made against a different `manifest.json`, or
one that was edited, removed or reordered.

Exit codes: `0` verified (and signed), `1` not a readable review folder, `2` a file is missing or
changed, a sign-off is stale or broken, or the options were wrong. Nothing is signed unless the
exit code is `0`.

Once a folder has `attestations.json`, a review won't overwrite it. Re-running a saved snapshot into
the same `--out` exits `1`; use a different `--out` if you meant to redo the review.

`attest` is a record, not a cryptographic signature; see [security.md](security.md#evidence-integrity-and-sign-off).
