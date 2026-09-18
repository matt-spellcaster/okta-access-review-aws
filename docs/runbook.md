# Running a review

A step-by-step guide to one quarterly review, from start to finished tickets. It assumes the
one-time setup in [aws.md](aws.md) is done. The **CISO** is the only reviewer: they decide every
item and sign off.

## Who sees what

| Where | What appears | Personal data? |
|---|---|---|
| **Review channel** | "Review is open", overdue notes, and a finished summary at the end. Ticket links. | No. Counts only. |
| **CISO's DM** with the Access Review app | Every item to decide, then one sign-off message listing all decisions | Yes |
| **JSM project** | A tracking ticket per review, leaver tickets, then one ticket per revoke | Yes |

In Slack, the DM is under **Apps → Access Review** in the sidebar (the app's **Messages** tab).

## Before the review (a few minutes)

1. **Update the roster** if anyone joined, left or changed since last time. It's a CSV with the
   columns `email,name,employment_type,status,end_date,manager` (see
   [configuration.md](configuration.md)). Upload it:
   ```bash
   aws s3 cp roster.csv s3://uar-work-<account>/inputs/roster.csv
   ```
   Everyone with an Okta account should be in it, unless they're listed as a service account in
   `config.json`. Anyone missing is flagged **AR-03, "Account has no HR record"**.
2. **Optional: check the Okta connection.** Run **Actions → Okta check → Run workflow** in GitHub,
   then approve it. Every line should say PASS.

## 1. Start the review

Reviews start automatically on the 15th of January, April, July and October. To start one by
hand:

```bash
aws stepfunctions start-execution --state-machine-arn "$(terraform -chdir=infra/main output -raw state_machine_arn)"
```

Within about a minute you'll see:

- **In the review channel:** *"Okta access review `<run>` is open. Due <date>."* with the item
  counts and a link to the tracking ticket.
- **In JSM:** the tracking ticket *"Okta Access Review <quarter> (<run>)"*, plus one *"Remove
  access for leaver …"* sub-ticket for each person HR says has left but who can still get in.
  Leaver tickets are due in 24 hours; they don't wait for the review.
- **In the CISO's DM:** a summary message with **Confirm N proposed**, followed by the item
  messages (20 items per message).

If the channel says *"stopped before it finished"* instead, see [If something goes wrong](#if-something-goes-wrong).

## 2. The CISO decides every item

Each item shows the person, the access (app, admin role or admin group, and whether it's direct or
through a group), the proposed decision with its reason, and a link to their leaver ticket if they
have one. Under it are the **Keep** and **Revoke** buttons; the proposed one is coloured.

1. **Accept the easy ones:** click **Confirm N proposed** in the summary message, then **Confirm**.
   This accepts every *Keep* and *Revoke* proposal at once. Items marked **Your call** stay open.
2. **Decide the rest:** click **Keep** or **Revoke** on each remaining item. Admin roles and
   admin groups are always *Your call*, as is access through a group, since removing someone from a
   group can take away other access too.
3. **Reasons:** if you keep something proposed for revocation, or override any proposal, a box asks
   why. Type a one-line reason and click the button in the box. The reason goes into the evidence
   and onto the sign-off message.
4. **Changed your mind?** Click the item's other button. The latest click counts, and every click
   stays on record.

After each click the messages update: the item shows ✅ Keep or ⛔ Revoke with who decided, and the
summary counts how many are done.

## 3. The CISO signs off

When the last item is decided, one more message arrives in the DM:

- *"Every item in access review `<run>` has a decision."*, with the totals and the tracking ticket
- **Every decision**, grouped: ⛔ **Revoke** first, then ✅ **Keep**. Each line shows the person,
  the access, and the reason. Overrides are marked *"overrode proposed …"*.
- The manifest SHA-256, with the report PDF in the message's thread
- **Approve review**

Read the list. To change something, click the item's button again in the item messages above; you
don't need to start over. Then click **Approve review** → **Sign off**.

Signing off records your approval against the exact report (by its hash), and can't be undone.

## 4. After sign-off

Within a minute:

- **JSM:** one *"Revoke <access> for <person>"* sub-ticket per revoke, under the tracking ticket,
  due in 7 days, each saying exactly what to change in Okta. The tracking ticket gets a comment with
  the sign-off.
- **Review channel:** the finished summary. It shows who signed off and when, findings by severity
  and by check, the keep and revoke totals, and a link to the tracking ticket. It contains no names.

Then do the work:

1. For each ticket, make the change in Okta. The tool never changes Okta itself.
2. Resolve the ticket in JSM.
3. The next morning's check compares the ticket with Okta:
   - **Removed:** a *"Verified…"* comment on the ticket, and a verification record in the evidence.
   - **Still there:** a comment on the ticket and a DM to the CISO. Finish the change; it's checked
     again daily.
4. When every ticket is verified, the channel says *"All remediation for access review `<run>` is
   verified in Okta."* The review is complete.

## Deadlines and reminders

| When | What happens |
|---|---|
| Day 3, day 6 | A reminder DM to the CISO if items are still undecided |
| Day 7 (the due date) | An overdue DM, a note in the channel, and a comment on the tracking ticket |
| Every day after that | A reminder DM until everything is decided |
| A ticket passes its due date | One DM per day listing the overdue tickets, with links |

If nobody signs off within 30 days, the run stops. The channel says so, and the review is closed.

## If something goes wrong

**The channel says *"Okta access review … stopped before it finished"*.** The run stopped and the
review has been closed, so there are no reminders for it. Find the cause in the AWS console under
**Step Functions → uar-review →** the execution → the red step → **Error** and **Cause**. Common
causes:

| Error | Fix |
|---|---|
| `JiraError … HTTP 401` | The Jira token or email is wrong. Re-set `/uar/jira/api_token`, or the `JIRA_EMAIL` secret and redeploy. |
| `JiraError … HTTP 400 (problem with: duedate)` | The Jira account isn't a JSM agent. Give it a Jira Service Management seat. |
| `SettingsError … member ID` | `SLACK_CISO_USER` isn't a `U…` member ID. Fix the secret and redeploy. |
| `OktaError …` | Run the **Okta check** workflow; it points at the problem. |

After fixing it, start a new review (step 1). Anything the stopped run already created stays as
it was, in S3 and in JSM. Close its tracking and leaver tickets in JSM by hand, since the new run
opens its own.

**Nothing happens when the CISO clicks a button.** Slack interactivity is off, or its Request URL
is wrong. Go to https://api.slack.com/apps → **Access Review** → **Interactivity & Shortcuts**: it
must be **On**, with the `slack_request_url` Terraform output as the Request URL.

**A button click shows a ⚠️ message.** That's a problem shown only to you, such as clicking in a
review that's already signed off. The message says what's wrong.

## Checking the evidence

Everything a review produced is in `s3://uar-evidence-<account>/runs/<run>/`: the report, every
click, the sign-off, and each ticket and verification. To check a finished review:

```bash
aws s3 cp --recursive s3://uar-evidence-<account>/runs/<run>/ <run>/
uv run access-review attest <run>
```

It checks every file against the manifest, and the Slack sign-off against both hashes. Any change
since the sign-off shows up as a problem.
