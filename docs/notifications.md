# Notifications

At the end of a live run, the tool can email the PDF and post a summary to Slack. They're
independent: if one fails, the other is still attempted, the report is kept, and the command exits
with status 3.

Both follow the same rule: **the message itself contains no personal data.** It shows the org,
whether the review is complete, and finding counts. Names and details are only in the PDF.

## Email

Set `REPORT_EMAIL_TO` in `env` to turn it on (comma-separate multiple recipients).

| Setting | Example |
|---|---|
| `REPORT_EMAIL_TO` | `security-team@example.com` |
| `REPORT_EMAIL_FROM` | `Access Review <access-review@example.com>` |
| `SMTP_HOST` | `smtp.example.com` |
| `SMTP_PORT` | `587` (STARTTLS) or `465` (TLS) |
| `SMTP_USERNAME` | provider-specific |
| `SMTP_PASSWORD_REF` | `op://vault/item/field` |

- The subject line gives the status and worst severity, e.g.
  `Okta access review (complete): 1 critical, example.okta.com`.
- The body has counts by severity and the PDF's SHA-256 hash, which matches `manifest.json`.
- TLS is required. Other ports, and servers that don't offer STARTTLS, are refused.
- Missing or invalid settings stop the run before it contacts Okta.

Any SMTP provider works. Typical settings (check your provider's docs):

| Provider | `SMTP_HOST` | Port | `SMTP_USERNAME` | Password |
|---|---|---|---|---|
| SendGrid | `smtp.sendgrid.net` | 587 | `apikey` | API key with Mail Send |
| Postmark | `smtp.postmarkapp.com` | 587 | Server API token | Same token |
| Amazon SES | `email-smtp.<region>.amazonaws.com` | 587 | SMTP username | SMTP password |
| Purelymail | `smtp.purelymail.com` | 465 | Full email address | Account or app password |

`REPORT_EMAIL_FROM` must be an address the provider lets that account send from.

## Slack

![Slack summary of the Acme demo review, with the PDF report attached in the thread](images/slack-summary.png)

The summary has a side bar colored by the worst severity (green when clean), the brand name,
status, the collection time in each reader's time zone, a grid of counts, and a "What needs
attention" list with one line per check. It never names people or apps.

### Choose a connection

| | Incoming webhook | Bot token |
|---|---|---|
| Settings | `SLACK_WEBHOOK_URL_REF` | `SLACK_BOT_TOKEN_REF`, `SLACK_CHANNEL_ID`, `SLACK_ATTACH_PDF` |
| Posts the summary | yes | yes |
| Attaches `report.pdf` | no (webhooks can't upload files) | optional, as a reply in the thread |

Use one or the other; setting both is an error.

### Bot token setup

1. At https://api.slack.com/apps, choose **Create New App → From a manifest** and paste:

   ```yaml
   display_information:
     name: Access Review
     description: Posts Okta access review summaries and reports
     background_color: "#0b2545"
   features:
     bot_user:
       display_name: Access Review
       always_online: false
   oauth_config:
     scopes:
       bot:
         - chat:write
         - files:write
   settings:
     org_deploy_enabled: false
     socket_mode_enabled: false
     token_rotation_enabled: false
   ```

2. **Install to Workspace**, then copy the **Bot User OAuth Token** (`xoxb-…`) from **OAuth &
   Permissions** into 1Password.
3. In the channel, run `/invite @Access Review`.
4. Copy the channel ID (channel details → **About**, starts with `C`). It isn't secret.
5. In `env`, set `SLACK_BOT_TOKEN_REF`, `SLACK_CHANNEL_ID`, and `SLACK_ATTACH_PDF="true"` if you
   want the PDF.

For a webhook instead, add one under **Incoming Webhooks** and put its 1Password reference in
`SLACK_WEBHOOK_URL_REF`.

### Safeguards

- Webhook URLs and bot tokens are credentials. They're only fetched from 1Password and never
  appear in output or errors.
- Only `https://hooks.slack.com/services/…` webhooks and `xoxb-` bot tokens are accepted.
  A channel name instead of an ID, or PDF attachment with a webhook, is rejected before the run.
- **Uploading the PDF is opt-in** because the PDF contains personal data. Use a private,
  need-to-know channel. Uploads use Slack's three-step external upload and only go to `slack.com`.
- Slack API errors come with a hint: `not_in_channel` suggests `/invite`, and `missing_scope` names
  the scope to add.
