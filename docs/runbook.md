# Running a review

A step-by-step guide to one quarterly review, from start to finished tickets. It assumes the
one-time setup in [aws.md](aws.md) is done. The **CISO** is the only reviewer: they decide every
item and sign off.

## Who sees what

| Where | What appears | Personal data? |
|---|---|---|
| **Review channel** | One thread per review: "review is open", the report PDF (if turned on), overdue notes, the finished summary, and "complete" at the very end. | Counts and links in the posts; the PDF has names |
| **CISO's DM** with the Access Review app | Every item to decide, then one sign-off message listing all decisions, then the action checklist in its thread | Yes |
| **JSM project** | A tracking ticket per review; leaver tickets; after sign-off, revoke tickets and fix tickets | Yes |

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

Each item is a card, read top to bottom:

- **Who and what:** the person's name and login, and the access (app, admin role or admin group, and
  whether it's direct or through a group).
- **Facts:** Okta status, last sign-in and MFA; the HR record (employment type, status, end date,
  manager); and the access itself: when it was assigned and when it was last used.
- **Outside this decision**, when there is any: findings about this person that deciding this item
  cannot change, worst first. Usually that is access in another source the review read; it also
  covers a service account they owned and have left behind, which can be an Okta API client, since
  deactivating the person does not touch it. It appears above the rest for that reason. Each entry
  gets its own remediation ticket; this card only records that you saw it.
- **Why it could be an issue:** every finding about this person or this access (for example *no MFA
  enrolled*, *HR shows terminated*, *not used in 90 days*), and what an admin role can do. It says
  *Nothing flagged* when there's nothing, or *Nothing else flagged* when the only findings are in the
  block above. A leaver's ticket is linked here.
- **Proposed:** Keep, Revoke or Your call, with the reason. Under it are the **Keep** and **Revoke**
  buttons; the proposed one is coloured.

Someone whose Okta offboarding completed but who still has an open finding gets a card of its own,
**Outside this decision**, with one button, **Acknowledge**. They have no Okta access of their own
left to decide, so without it the finding would reach no decision screen at all. This review cannot
settle it: acknowledging records that you saw it, and the finding's own ticket tracks the fix.

An account with **no HR record** (AR-03) gets a card of its own with one button, **Acknowledge**.
It asks you to raise the account with HR (add them to the roster, list them as a service account,
or have the account deactivated). That happens outside the review, so **no ticket is opened for
it**; the finding stays in the report and the sign-off lists it under *Flagged for HR*.

1. **Accept the easy ones:** click **Confirm N proposed** in the summary message, then **Confirm**.
   This accepts every *Keep* and *Revoke* proposal at once. Items marked **Your call** stay open.
2. **Decide the rest:** click **Keep** or **Revoke** on each remaining item. Admin roles and
   admin groups are always *Your call*, as is access through a group, since removing someone from a
   group can take away other access too.
3. **Reasons:** if you keep something proposed for revocation, or override any proposal, a box asks
   why. Type a one-line reason and click the button in the box. The reason goes into the evidence
   and onto the sign-off message.
4. **Changed your mind?** Click the item's other button. The latest click counts, and every click
   stays on record. If the sign-off message (below) has already arrived, it updates to match.

After each click the messages update: the item shows ✅ Keep or ⛔ Revoke with who decided, and the
summary counts how many are done.

## 3. The CISO signs off

When the last item is decided, one more message arrives in the DM:

- *"Every item in access review `<run>` has a decision."*, with the totals and the tracking ticket
- **Every decision**, grouped: ⛔ **Revoke** first, then ✅ **Keep**. Each shows the person, their
  Okta facts, the access, every concern (⚠️), and why it was decided that way. Anything the decision
  does not reach is listed with *"not changed by this decision"*, because signing off does not
  settle it. Overrides are marked *"overrode proposed …"*.
- The manifest SHA-256, with the report PDF in the message's thread
- **Approve review**

Read the list. To change something, click the item's button again in the item messages above; you
don't need to start over. Then click **Approve review** → **Sign off**.

Signing off records your approval against the exact report (by its hash), and can't be undone.

## 4. After sign-off

Within a minute:

- **JSM:** under the tracking ticket, due in 7 days:
  - one *"Revoke <access> for <person>"* ticket per revoke, saying exactly what to change
  - one *"Fix: <finding> — <person>"* ticket per finding that isn't an access decision: no MFA,
    inactive or unused account, contractor in an employee-only group, missing manager, disabled
    account still holding access, or an API client with admin rights. Accounts with no HR record
    get no ticket: the CISO acknowledged them and raises them with HR.

  Every ticket links to the person's page in the Okta admin console.
- **The approval thread** (under the sign-off message): the **action checklist**. It lists every
  ticket that must be done to close the tracking ticket, with links and due dates, and it ticks
  itself off as the daily check settles each one. Lines marked *taken on your word* are ticked off
  as soon as you resolve them, without Okta being consulted. The same list is a comment on the
  tracking ticket.
- **Review channel:** the finished summary, in the review's thread (and shown in the channel). It
  shows who signed off, findings by severity and by check, the decisions, and the ticket counts. It
  contains no names.

Then work through the checklist:

1. For each ticket, make the change in Okta; the link on the ticket takes you to the person. The
   tool never changes Okta itself.
2. Resolve the ticket in JSM.
3. The next morning's check (07:00 Central) compares the ticket with Okta. It looks for the access
   on leaver and revoke tickets, and re-runs the check on fix tickets:
   - **Done:** a *"Verified…"* comment on the ticket, a verification record in the evidence, and a
     ✅ on the checklist.
   - **Not done:** a comment on the ticket and a DM to the CISO. Finish the change; it's checked
     again daily.
   - **Taken on your word** are different, and the checklist marks them as such before you start.
     Fix tickets for *inactive* or *never used* accounts (AR-05, AR-06), *contractor in an
     employee-only group* (AR-07) and *API client with admin access* (AR-10) ask you to decide, and
     deciding to leave things as they are is a valid answer. So do the cross-source findings
     (AR-15, AR-16, AR-17, AR-18): those ask for a change this review can read once but cannot
     re-read to confirm a fix -- a register entry naming a service account's new owner, or access
     in another source. For all of them, resolving the ticket is taken as done, with a
     *"Resolved…"* comment; nothing is checked in Okta. When the review closes, the tracking ticket
     and the channel say how many were verified in Okta and how many were taken on your word.
4. When every line is ✅, the **tracking ticket closes itself**, and the channel says *"Access review
   `<run>` is complete"*. That's the only ticket the tool ever moves.

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
