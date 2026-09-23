# Security design

The tool reads an identity provider with admin-level visibility and produces files full of
personal data, so it's built on one assumption: **the laptop, the repo or a log could leak, and
a leak should be worth as little as possible.**

## Access to Okta

### Read-only, enforced in three places

Okta allows an API call only if the token's scopes **and** the app's admin role both permit it.

1. **Okta:** the app is granted only `.read` scopes.
2. **CLI:** it refuses to start if `OKTA_SCOPES` contains anything that doesn't end in `.read`.
3. **Client:** `OktaClient` only sends GET requests, plus the token request. A test fails if any
   other request is made.

### Client secrets are never read

AR-18 asks for any API client secret a leaver held to be rotated. The review never reads the secrets
endpoint to check: `GET /api/v1/apps/{id}/credentials/secrets` returns the secret itself, and Okta
cannot show a rotation reliably anyway (a key published at a `jwks_uri` never appears there). A
reviewer confirms the rotation on the AR-18 ticket instead.

### Admin role: a tested tradeoff

Scopes decide *what kind* of call is allowed. The admin role decides *which data* the app can see.
All three built-in candidates were tested against a live dev org:

| Admin role | Sees API service apps | Reads app scope grants | Reads admin role assignments |
|---|---|---|---|
| Read-Only Administrator | yes | no | no |
| Organization Administrator | no (the app list comes back empty) | n/a | no |
| Super Administrator | yes | yes | yes |

Reviewing privileged access (AR-10, AR-11) is one of the most important access controls, and it
needs all three columns, so the review app uses **Super Administrator**. With read-only scopes,
the role can only widen what the app *reads*.

The remaining risk is that someone later grants the app a `.manage` scope, which would make it a
full admin. That's why **AR-10 flags the review app itself on every run**, so a reviewer confirms
it each time. Teams that prefer Read-Only Administrator can use it: the tool still runs and marks
the review incomplete (see below).

### Reports say when they're incomplete

A review that silently skips data is worse than no review. When the admin role blocks a call:

- the run continues, and each gap is recorded with the checks it affects and the permission it needs
- `report.md` and `report.pdf` show a **Data gaps** section, and the email and Slack summaries say
  "Incomplete"
- `manifest.json` records `"complete": false`

Organization Administrator returns an *empty* app list instead of an error, so the tool also checks
that it can see its own app. If it can't, the app list is marked as filtered.

## Credentials

- **No shared secret.** Client authentication is Private Key JWT: each token request is signed, and
  Okta keeps only the public key.
- **Secrets live in 1Password.** `env` holds only `op://` references, and `run.sh` fetches the Okta
  key, SMTP password and Slack token at startup. Nothing secret is written to disk.
- **`run.sh` rejects a secret pasted into a `*_REF` setting** without printing it. (The 1Password
  CLI repeats invalid references in its error messages, which would otherwise print the secret.)
- **Tokens bound to the run (DPoP).** Each run generates a P-256 key in memory. Okta binds the access
  token to that key, and every API call carries a signed proof for the token and URL. A token copied
  from a log or memory is useless without the key, which is gone when the process exits.
- **A separate app from the interactive MCP setup.** A leaked review key can't change anything,
  even though the [okta-mcp-local](https://github.com/matt-spellcaster/okta-mcp-local) app has
  write access.
- **Optional network restriction.** Token requests can be limited to an Okta network zone.

## Personal data

- `reports/` and `roster/` are git-ignored, and a pre-commit hook blocks `env` and private keys.
  Each report folder includes a copy of the HR roster it used, so treat report folders as
  confidential HR data.
- **Email and Slack messages contain only counts and completeness.** Names and details are only in
  the PDF.
- **System Log events are stripped before they are stored.** A raw Okta event carries far more than
  a review needs: `app.oauth2.credentials.lifecycle.create` includes the **new client secret in
  plain text**, and most events carry the actor's IP address, city and device. `ActivityEvent`
  copies six fields and nothing else -- timestamp, event type, actor id and type, outcome, and each
  target's id, type and label. It is an allowlist, so a new field Okta adds is dropped by default,
  and a test asserts that none of the discarded sections reach a snapshot. This matters because
  `snapshot.json` is written into every report folder and the demo one is committed.
- **Uploading the PDF to Slack is opt-in** and is meant for a private, need-to-know channel. The
  upload only goes to a URL on `slack.com`.
- Webhook URLs, bot tokens and Slack's pre-signed upload URLs never appear in output or error
  messages. Tests check this, and no test can send real email or Slack messages.
- The README samples use only the fictional Acme data, and a test keeps them in sync with the code.
- `attest` stores the reviewer's name in `attestations.json` in the report folder, and nowhere
  else: not in `manifest.json`, email or Slack. It sends nothing.

## Evidence integrity and sign-off

- **`manifest.json` makes changes detectable, not impossible.** Its hashes tie the files of one
  run together, so a changed file, a file swapped in from another run, or a missing file shows up.
  Nothing signs the manifest itself, so anyone who can edit the folder can change a file and
  recompute its hash.
- **`attest` is a record, not a cryptographic signature.** It ties a decision to the manifest's
  SHA-256, so a sign-off can't be moved to a different report unnoticed, and it refuses to sign a
  folder whose files don't match. But no key is involved, the reviewer name is whatever was typed,
  and `attestations.json` is an ordinary file in the same folder.
- **The chain inside `attestations.json` catches a sign-off edited, removed or reordered in place.**
  It can't catch the whole file being rewritten, because the chain lives in the file it protects.
- **For non-repudiation, put the manifest's SHA-256 somewhere the reviewer doesn't control**: a
  ticket, a write-once bucket, a signed git tag, or an e-signature over `manifest.json`.
- **Findings history only reads other folders; it never changes them.** It counts a review only
  after checking its `findings.csv` against its own manifest, stops counting at a review it can't
  verify, and records in `manifest.json` which folders it read and which it skipped. It can't tell
  that a whole folder was deleted, so a count can only be as long as the folders kept.
- Both are read-only as far as Okta is concerned: they run on files already on disk and make no API
  calls.

## Supply chain

- Dependencies are locked in `uv.lock`, and `exclude-newer` in `pyproject.toml` ignores packages
  published after a fixed date.
- `run.sh` uses `uv run --frozen`, so a live run never changes the dependencies.

## Known limitations

- The Okta key and other secrets are held in process memory while a run is active, where other
  processes running as the same macOS user could read them.
- The review app's Super Administrator role is a standing privilege; it relies on scopes, the key
  in 1Password, DPoP and AR-10 as controls.
- Okta keeps 90 days of System Log data, so AR-13 cannot see activity after a termination older
  than that, and AR-18 cannot see that someone held an API client secret more than 90 days before a
  review. The ticket for a secret it did see is settled by a reviewer, so the log forgetting never
  closes it. The review reports a gap rather than a clean result, but the answer for an older leaver
  is still "unknown", not "nothing happened".
- `attestations.json` shows who says they signed off, not proof that they did. Keep the manifest
  hash somewhere outside the report folder if an auditor needs more than that.
- Findings history is only as long as the report folders kept in `--out`, and it matches AR-10
  findings by app label, so renaming an app starts its history again.
