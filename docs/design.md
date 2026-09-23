# Design notes

The reasoning behind the rules in `CLAUDE.md`. Each section says what the rule is, what goes wrong
without it, and which test holds it in place. Read the matching section before changing that area.

Most of the rules come from one idea. An access review is audit evidence, so a read that failed or
never ran must never look like a clean result. "Nothing found" is a claim, and the tool makes it
only when the read that would have found something actually ran. The rest follows from that:
unknown ranks as the worse case, a link between an account and a person needs evidence, and a
ticket says it was verified only when something re-read the data.

- [Completeness](#completeness)
- [The identity graph](#the-identity-graph)
- [Adding checks and sources](#adding-checks-and-sources)
- [The service account register](#the-service-account-register)
- [Leaver checks: AR-12, AR-13, AR-17, AR-18](#leaver-checks-ar-12-ar-13-ar-17-ar-18)
- [No account is told to go and to stay](#no-account-is-told-to-go-and-to-stay)
- [Review items and cross-source findings](#review-items-and-cross-source-findings)
- [Departure bundles](#departure-bundles)
- [Tickets and verification claims](#tickets-and-verification-claims)
- [Streaming review_items.json](#streaming-review_itemsjson)
- [CI concurrency](#ci-concurrency)

## Completeness

`report.all_gaps` is the one answer to "is this review complete?". It reads every `SourceMeta` in
the graph, Okta's included, because projecting a source records gaps its snapshot never had: a
group member no user read returned, or an app assigned to a group that isn't in the snapshot.
Slack, email, the CLI and the Step Functions output all take it from `ReviewRun.gaps` /
`.complete`. None of them read `snapshot.gaps`, which speaks for Okta alone. `report.other_sources`
is for display only.

Each kind of read has its own completeness signal, because each one fails on its own:

| Signal | Covers | Asked through |
|---|---|---|
| `SourceMeta.complete` | Identities: users and members | `report.all_gaps` |
| `SourceMeta.activity_complete` | Credentials and their use | `_credential_evidence_complete` |
| `SourceMeta.roles_complete` | Role lists | `_roles_evidence_complete` |

A check grading on credentials or roles asks the matching helper first. `_write_access` returns
None rather than False when scopes weren't read. Roles need the same care: Okta
(`okta.roles.read`) and GitHub (the organization-roles endpoints) both return an empty list when the
roles call fails, so `_elevated_roles` alone can't tell "holds no elevated role" from "nobody
asked". Without the flag, a departed organization owner whose roles were never fetched would grade
`high`, with a detail naming only a read-only token. AR-17 and AR-18 grade `critical` on an unread
list and say so in the detail (`_roles_unread_note`).

An Okta user answers for itself. The collector never reads a DEPROVISIONED user's roles, and Okta
keeps group-assigned admin roles through deactivation and restores them on reactivation. So for a
user, AR-18 reads `User.admin_roles is None` rather than the source flag. The flag can be wrong in
either direction: True over that None, or False over a user whose roles were read before a
client's roles call was refused. An Okta client whose list names a role proves its own read ran.
The detail says "its roles were not read" only on the account's own evidence, and "the role read
did not complete" when only the source flag says so.

`Snapshot.from_dict` derives a missing `roles_complete` from those Nones and the refusal gap
instead of assuming the read ran. `collect` sets `Snapshot.roles_complete` from
`roles_api.allowed`, because `User.admin_roles` has a None for an unread list and
`App.admin_roles` doesn't. Each wiring point has a test that fails if it's removed. A projection
that drops the field falls back to the permissive default, and the fix stops working with the
suite still green.

Okta reads activity only for leavers and for the clients whose credentials they held, so
`activity_complete` can't speak for any other client. `Snapshot.activity_actors` records whose
activity was read and `Credential.usage_read` carries it per credential. An unread one shows as
"use not read" and counts as possibly recent.

An empty `outside_okta` on a review item can mean three things, and `items.outside_okta_gap` says
which: no source but Okta was read, a source was read but didn't complete, or a complete read found
nothing. Only the last makes the absence evidence. So the card block and the ticket paragraph
appear on the strength of the gap alone; a missing block would read as "they hold nothing
elsewhere" on the screen that settles the item.

## The identity graph

`Snapshot` (`models.py`) is the Okta adapter's output. It's the same for live and fixture data,
it's all the Okta checks see, and it never grows to fit another source. Other sources are projected
into an `IdentityGraph` in `identity/`, and the cross-source checks read that.

**The graph is built on every review**, from the Okta projection alone when no second source is
given. An estate of one is still an estate, and the register declares Okta service accounts too.
When the graph was gated on `--github`, AR-18 (written for Okta's own API clients) couldn't fire
on an Okta-only run, and every AWS run is Okta-only. A graph check is skipped only when it also
needs a roster and there isn't one. `handlers.verify_daily` builds no graph on purpose: every graph
check settles by reviewer, and a graph there would make AR-09 stand down (see
[AR-09 stands down for AR-18](#ar-09-stands-down-for-ar-18)).

**A principal links to a person only through an evidenced `LinkMethod`.** Strongest first:

1. `SSO_IDENTITY`: the IdP's own identity assertion.
2. `VERIFIED_EMAIL`: an exact match on an address the source itself states as verified.
3. `DECLARED`: a register entry.
4. `CREATOR`: an audit log's record of who created the account.

There's nothing below `CREATOR`. A name or email that merely looks similar never links, because a
false link marks a credential as accounted for when nobody is. The methods are a ranking, never
averaged into a score. Two equally strong links naming different people leave the account
contested, a contested account is unlinked, and AR-15 reports it.

**A graph finding's subject is `{source}/{principal.id}`** (`checks.graph_subject`), never a label.
Ticket identity is `(check_id, subject)` hashed into a permanent Jira label. A GitHub login can be
renamed and two Okta service clients can share an app label; either would collapse two separate
problems onto one ticket. The readable name goes in the detail, which is what the ticket and the
PDF show.

**A source adapter decides which of its roles are elevated**, never `checks.py`.
`identity/github.py` emits a `GrantKind.ROLE` grant only above ordinary membership
(`ORDINARY_ROLES`), case-folded, because GraphQL spells the enum `ADMIN`/`MEMBER` and the
invitations read says `direct_member`. `checks._elevated_roles` reads every ROLE grant and AR-17
grades critical on one, so an ordinary member slipping through would make every departure
critical. A role the adapter doesn't recognise counts as elevated.

A graph source's own snapshot goes into the run folder through `extra_files` so the manifest
hashes it (`review.GITHUB_SNAPSHOT_FILE`). A finding whose evidence is outside the bundle can't be
re-verified by `attest`. `review._note_skew` records a gap when two sources were read more than
`SOURCE_SKEW_DAYS` apart. It runs after composing, so it doesn't also clear `activity_complete`.

### Grants and group expansion

`IdentityGraph.grants` holds only what a source stated verbatim. App access through a group is
stored once per group (`group_apps`) and expanded on read. Materialising it doesn't fit: one
org-wide group over 250 apps is 1.25M grants and 535 MB RSS, against a 1024 MB collect Lambda.

Ask `grants_for(key)` for one principal's access and `all_grants()` for every grant in the graph.
Reading `.grants` for either is short by every app anyone reaches through a group. `compose`
carries both fields, or a second source would empty the first one's app access.
`test_grants_holds_only_what_the_source_stated_and_all_grants_holds_everything` pins the split.

Derive a graph from another with `dataclasses.replace`, never by naming its fields. `group_apps`
defaults to empty, so a hand-built `IdentityGraph(grants=..., links=...)` is missing everyone's
group-based app access while `incomplete_sources()` still reads clean.

`grants_for` pays the expansion on every call, so looping it over every principal is
O(principals × groups × apps). Call `all_grants()` once instead.

The expanded grant's `via` is rebuilt from the group grant's own label, so it's byte-identical to
the materialised form that `transitions.py` writes into the hashed departure bundle. `items.py`
never reads a graph grant. Its `via` comes from `Snapshot.apps_for`, which builds the same
`group:<name>` shape independently, so the two formats must not drift.

## Adding checks and sources

`CLAUDE.md` lists what a new check or source adapter needs. The reasons behind the less obvious
items:

- A new check updates `test_cross_source_findings_carry_the_planted_severities` as well as
  `test_demo_findings_are_exactly_the_planted_ones`. Severity is the judgement in these checks, and
  asserting subjects alone lets a constant pass.
- **A fixture's shape is the shape the real API returns.** Check every field against the vendor's
  documentation before building on it. A hand-written fixture that invents fields gives checks
  validated against data no collector can supply. Where the API can't provide something, the
  snapshot says so (`sso_enabled`, `credentials_complete`) instead of leaving it blank. The field
  list is the requirement a collector has to meet, as `ActivityEvent.from_okta` does for Okta.
- An adapter that emits `GrantKind.GROUP` grants also populates `group_apps`, or the apps those
  groups reach go missing and the suite stays green. The expansion is GROUP to APP only, so a
  source whose containers are `TEAM` (GitHub) can't use it and states its grants verbatim.
- An adapter's model and projection share one module (`identity/github.py`) until a second reader
  of that snapshot exists. `models.py` is split out only because fourteen checks read it.

## The service account register

The register (`register.py`, `Config.service_accounts`) records who owns an account that isn't a
person. It can't be used to silence a finding.

**An entry with no owner never removes a finding.** It emits `Link(key, DECLARED, "", ...)`, which
takes the principal out of `graph.unlinked()`. On its own that would delete the account's AR-15: a
config change that stops a write-capable credential being reported while exactly as many people are
accountable for it as before, which is nobody. Those principals are `graph.unattributed()`. AR-15
walks that list as well as `unlinked()` (the two are disjoint) and reports them one severity
milder, floored at `low`, since `info` is for what a reviewer confirms rather than fixes.

An owner is the only thing that clears the finding. It's normalised the way `identity_key`
normalises an Okta profile email, or it would join to nobody while reading as owned. The link also
puts the account in the owner's departure bundle through `principals_of`, which is the point of
the register.

**An owner counts only when some source evidences that person.** `IdentityGraph._attested` is the
set of identities named by a link whose method isn't DECLARED. Every other method is a source
speaking about its own data; DECLARED is somebody typing an address into a config file. An
unattested owner is `unattributed()`, ranks in `strength` the same as a nameless link, and stays
out of `_by_identity` so `identities()` can't invent the person. Otherwise a typo like
`marcus.lee@acme.exmaple` would read as ownership, join to nobody, reach no departure bundle, and
clear a finding that an honest blank only downgrades.

**A link naming somebody outranks one that doesn't, whatever the method** (`strength` in
`IdentityGraph`). DECLARED beats CREATOR on rank, so without this an ownerless entry would erase
the audit log's record of who built the account.

**Entries are scoped to a source** (`okta`, `github:<org>`), because a login is only a name within
one estate. `ServiceAccount.key` folds case on both halves. A GitHub org login displays in its
creation casing (`Acme-Eng`) while `source_name` builds it from the API, and comparing exactly made
such an entry do nothing and let two owners past the one-account-one-owner check.

**An entry must identify exactly one live account.** A service client matches by client id, or by
app label only when the label picks out exactly one client. Two clients can share a label, which is
also why ticket identity uses the stable id. An entry that matches nothing, or a label that matches
two, declares nothing and records a gap. Ignoring it would leave a claim that looks like coverage.

Names match against accounts that are still live, in both estates that can tell:

- `collect` reads `/api/v1/apps` with no status filter. The usual way two clients end up sharing a
  label is deactivating the old "Terraform Automation" and building a new one, which would make a
  correct entry declare neither. So a label picks out the one client still running. A lone client
  is declared whatever its status, and a status `_app_status` doesn't recognise keeps the label
  ambiguous.
- GitHub is the sharper case, because a freed login can be claimed by someone else. Matching the
  wrong account types it SERVICE, skips the `elif member.saml_identity` branch so a real person's
  access joins to nobody, and puts the entry's owner on somebody else's credentials.
  `identity/github.py._changed_hands` refuses an entry whose `reviewed` date is before the
  account's creation date, and records a gap. An old account renamed into a freed login is beyond
  what a register keyed on a name can see, and the docstring says so.

`review._note_register` records an unattested owner as a gap after composing, since an owner's
estate usually isn't the account's and no single projection can settle it. It also records a dead
entry: one naming a kind no collector reads (`review.SOURCE_KINDS`), or a name that misses the
estate of its kind that was read, such as a mistyped org. `Register.stale` can't see those,
because it runs per source and never runs for a source nothing projected. An entry for a kind this
run wasn't asked to read, like GitHub on an AWS run, is out of scope and not a gap. Counting it
would mark every AWS review INCOMPLETE for good, and people learn to ignore that banner.

The register is written into `manifest.json` inside the signed config, so it has to stay JSON. The
lookup index is set with `object.__setattr__` instead of being declared as a field (its keys are
tuples), and `reviewed` goes through `Register.to_dict` (it's a `date`).

## Leaver checks: AR-12, AR-13, AR-17, AR-18

Four checks cover what a departure leaves behind. They split it so that no account gets two
remediations that contradict each other.

| Check | Covers | Asks for | Settled by |
|---|---|---|---|
| AR-12 | The leaver's own Okta API tokens | Revoke | Okta re-read |
| AR-13 | Use of the leaver's own account after they left | Treat as an incident, revoke | Okta re-read |
| AR-17 | The leaver's own access in other sources | Remove | Reviewer |
| AR-18 | Service accounts the leaver owned or held a secret of, in any source | Hand over and rotate, or decommission | Reviewer |

**A service account a leaver was accountable for is AR-18's, never AR-17's.** AR-17 asks for a
leaver's own access to be removed. AR-18 asks for the account to be handed to somebody, because
something depends on it still running. Two findings on one principal would be two tickets with
opposite instructions. `_leaver_access_outside_okta` skips `PrincipalKind.SERVICE`, and AR-18 takes
those accounts across every source and every status. That's a strict superset of what AR-17 drops,
which is what makes the skip safe. A disabled service account isn't settled, because
`CredentialKind` is the set of things that outlive the account they were created under.

An Okta System Log credential event carries two facts:

- **Custody:** the leaver created the client, added or activated a secret or key, or read the
  secret back (`models.CREDENTIAL_EVENTS`), so they may hold a working copy. Deactivating or
  deleting a secret shows nobody anything, so it's left out.
- **Ownership:** only `models.CREATION_EVENTS`. This is the CREATOR link. Reading a secret never
  makes someone a CREATOR, or whoever once opened a colleague's client would be named as the person
  who answers for it.

Both land on AR-18, one finding per client with both reasons in the detail. It asks for somebody
still here to answer for the client and for every secret the leaver held to be rotated, and it
settles by reviewer because Okta can't show a rotation reliably. Custody used to sit on AR-12's
leaver ticket, which closes on a daily Okta re-read, and that failed both ways it was tried.
Re-deriving custody from the log closed the ticket once the event aged past 90 days. Reading
secret and key creation dates can never see a key published at a `jwks_uri`. Nothing reads the
client secrets endpoint now, and AR-12 is API tokens alone, which the re-read does see.

AR-13 reads the leaver's own account only. A client running after the person who built it leaves
is doing its job. Counting that as the leaver's activity raised a critical "possible incident,
revoke it" against AR-18's "hand it over".

AR-18's accounts come only from `checks.leaver_accountable_accounts`. Where the register names a
different owner, the account is that person's, which is the handover AR-18 asks for. Where it names
somebody no source evidences, it's AR-15's. The ownership half is disjoint from AR-15 by
construction: AR-18 walks `principals_of`, indexed on attested identities, and AR-15 walks the
principals whose best link reaches nobody. Any new check about an account a leaver was accountable
for has to fit this split.

AR-17 skips `source == OKTA`, so Okta's own API clients are exactly what it can't see. The demo
plants three AR-18 cases:

- `okta/a04` ("Terraform Automation"), declared to marcus.lee in the register.
- `okta/a05` ("Reporting Bot"), tied to victor.nguyen by nothing but the System Log's record of who
  created it. The check reads whatever link the graph chose, not DECLARED alone.
- `okta/u12` (`svc-legacy-etl`), a deprovisioned bot user declared to marcus.lee that still holds
  groups.

Severity grades on what the account can change. `_elevated_roles` means "above ordinary
membership", which for Okta includes Read-Only Administrator, so AR-18 filters `READ_ONLY_ROLES`
out and grades critical on an elevated role or on write access. Unknown on either counts as the
worse case.

## No account is told to go and to stay

Every check declares what its remediation does to the account (`Check.disposition`, no default).
REMOVE takes the access or the account away. RETAIN keeps it running under somebody new. NEITHER
takes no position.

REMOVE and RETAIN on one account are two tickets telling one assignee opposite things. Worse, the
REMOVE ticket closes on a fresh Okta read that only the removal satisfies, so the handover gets
signed off by something that asked for the opposite. It turned up three times (AR-17, AR-12,
AR-09), each time found by reading two remediations side by side, so
`test_no_account_is_told_to_go_and_to_stay` asserts it now.

When classifying a check, the question is whether carrying out its remediation undoes the other
one's premise. Whether the sentence says "remove" doesn't decide it. Narrowing an API client's
scopes (AR-10) leaves the client running, so it's NEITHER. AR-02's "or get the end date extended"
corrects the data rather than offering an equal branch, so it's REMOVE. AR-15 asks who is
accountable, which is compatible with the groups having gone, so it's NEITHER even though its
sentence reads like AR-18's.

The test keys on the finding's subject, which is what identifies a ticket, and resolves each
subject to an account. It fails on a subject shape it wasn't taught. It runs against the demo and
against worst cases that bend the fixture until AR-18's Okta user account is also reachable by a
removal check: deactivated in each of `DISABLED_STATUSES` (AR-09), and active with an old direct
assignment (AR-14, which exempts register-declared accounts; the test guards that exemption). The
demo alone would pass on a review where nothing happened to overlap.

### AR-09 stands down for AR-18

The register makes any Okta user it declares a service account. A declared bot that's deactivated
and still in groups would get AR-09's "remove them" under its login and AR-18's "hand it over"
under `okta/<id>`. `checks.leaver_accountable_accounts` is the one computation of AR-18's accounts.
AR-18 walks it, `_disabled_with_access` stands down for the Okta users in it, and
`items._app_proposal` proposes `decide` rather than Revoke on them, since approving a revoke would
sign off the decommission branch. Stand-downs are declared in `checks.STANDS_DOWN_FOR`. The set is
empty without a graph or a roster, so the split switches off instead of silencing anything.

Standing down is safe only because AR-18 names the account's state and, for a disabled Okta user,
lists the groups and apps AR-09 would have listed. It uses the same `_leftover_access`, in full and
without BUILT_IN groups. It says "reactivating it restores" rather than "reaches": Okta unassigns a
deactivated user from every app and keeps its group memberships, so the apps are what those groups
give back.

A leaver's own Okta account, one whose roster entry is gone, is never in the set. HR lists it as a
person who left, so the leaver checks report it, and a register entry can't move it from an
Okta-verified removal to a reviewer's handover. It has to be a gone entry, though. `entry_for`
matches on the profile email, and a bot can share one with somebody still employed. No removal
check fires for an active entry, so excluding those would drop AR-18 with nothing in its place.

Two consequences outside the checks:

- `history._held`: an AR-09 finding that disappeared while AR-18 held that account isn't "Back
  again", because it never went away, and it isn't "New" either. The held review bridges its
  streak, so `first_seen` and `reviews_open` carry across. It's only a bridge; a finding AR-09 never
  reported before is still new. The bridge is per check (`checks.STANDS_DOWN_FOR`) and per account
  (`checks.okta_user_subjects` joins the login to the graph subject). Keying it on "any AR-18
  finding last review" hid every genuine reopen on eight checks.
- `handlers.verify_daily` builds no graph. With one, AR-09 would stand down, an AR-09 ticket from an
  earlier review would read as absent, and `watch.daily` would close it as done in Okta for groups
  nobody touched. `test_the_daily_recheck_keeps_an_ar09_ticket_open` calls the handler.

Two known limits:

- The split holds within one review, not across reviews. Say an earlier review opened an AR-09
  ticket for an account that a later review hands to AR-18, because its owner left in between.
  That ticket stays open asking for the groups to go, next to AR-18's handover ticket, since
  `verify_daily` still sees AR-09. Nothing links or supersedes the older ticket yet.
- The register is trusted. An entry naming a leaver as owner moves a disabled account with no gone
  roster entry from AR-09, which closes on an Okta read, to AR-18, which closes on the reviewer's
  word. The account is still reported, at a higher severity, but the proof it was cleaned up is
  weaker. Anyone who can edit the register can already declare accounts, so this is a trust
  assumption about the register and not a new capability.

## Review items and cross-source findings

`items.py` never proposes Revoke on missing or truncated data; the item becomes "decide".

A cross-source finding reaches the reviewer one of two ways. `checks.graph_findings_by_identity`
goes from subject to principal to strongest link to identity, and puts the finding on the owner's
item. `checks.graph_findings_by_subject` matches the subject to that exact principal, for the
account's own item. Nothing matches a graph finding to a person by login, label or email
similarity, because the link already carries the evidence. A principal that's unlinked, contested,
or declared with nobody named reaches no one's review item. Putting it on somebody's screen would
assert the attribution the graph refused to make. `GRAPH_CHECKS` is derived from `CHECKS`, not
listed by hand, so a new graph check can't appear in the report and be missing from the screen that
settles it.

Review items are built from Okta access, so someone whose Okta offboarding finished has none. Their
cross-source finding would reach no decision screen, and that's the one case the check exists for.
`items.CROSS_SOURCE` is the person-level item that catches them. It settles by acknowledging
(`ACKNOWLEDGE_ONLY`, like `HR_RECORD`): this review can't change another source, and the finding's
own ticket tracks the fix.

**A cross-source concern goes in `ReviewItem.outside_okta`, never in `.concerns`.** It's on every
one of that person's items by design, and `.concerns` is what `tickets.open_revokes` copies as the
work a ticket covers. That ticket closes when the daily check re-reads Okta, which can't see whether
a GitHub owner role is gone. Listed in `.concerns`, one finding nobody could verify would be signed
off as fixed once per revoke ticket. The reviewer still sees it: `slack_review.card_lines` puts
`outside_okta` first, since no other screen shows it and the decision can't change it. The ticket
lists it under "Not part of this ticket".

Anything that can land there must be in `FIX_CHECKS`, not only in `URGENT_CHECKS`, or the claim
that it has its own ticket is false. An urgent ticket is one per leaver keyed on Okta login, so a
graph finding with a `{source}/{principal.id}` subject would be folded into a ticket that never
names it. `test_a_graph_check_settles_through_its_own_fix_ticket_not_a_leaver_ticket` and
`test_everything_named_as_out_of_scope_really_does_get_its_own_ticket` guard both halves.

The block says what the decision doesn't settle. It makes no claim about where the account lives.
Most of what lands there is in another source, but AR-18's main case is an Okta API client. That's
in Okta, and the daily re-read of the leaver's own access still can't see it. So
`slack_review.OUTSIDE` (one string, used by the card heading, the item line and the sign-off list),
`items.CROSS_SOURCE_TARGET` / `CROSS_SOURCE_REASON` and `tickets._scope_to_okta` never say
"outside Okta". The field and the file format keep the name `outside_okta`; the sentences a
reviewer reads don't. `items.outside_okta_gap` is the exception, since it really is about which
other sources were read.

`load_items` splits a pre-format-3 file instead of trusting its `concerns`. Otherwise a review
opened before the split and remediated after it would put a cross-source concern back into a
revoke ticket that closes on an Okta re-read. The split needs both signals the writer left
(`items.LINK_MARKER` and a check id in `GRAPH_CHECKS`), so it can't move an Okta finding. It
happens in memory only. The file is create-only in S3 and hashed into a signed manifest, so
nothing rewrites it.

## Departure bundles

A departure bundle (`transitions.py`) is per identity, never per account. It takes the review's
gaps from `ReviewRun.gaps` instead of deciding completeness itself.

`build_transitions` returns None when there's no roster or no source beyond Okta. "Nobody left" and
"nothing looked" are different answers, and an empty list would report every departure clean. The
bundle is about the estates Okta deactivation doesn't reach, so it needs a second source and asks
for one directly. Built from Okta alone, it would report every leaver's residue elsewhere as empty.

The denominator is the roster, not the Okta user list. A leaver whose account was deleted, or whose
profile has no email, still gets a bundle carrying its own gap. Walking accounts instead would
answer "which departures does Okta still know about" and drop the rest from the numerator and the
denominator at once.

Bundles carry personal data, so they stay in the run folder and the evidence bucket.
`transitions.summary` is the counts-only shape for Slack and Step Functions. Users are walked in
login order, because evidence that changes with API paging isn't evidence.

## Tickets and verification claims

A ticket settles one of two ways. A revoke or leaver ticket asks for a change in Okta and closes
when a fresh Okta read confirms it. A fix ticket for a check in `REVIEW_CHECKS` is taken on the
reviewer's word. `tickets.record_verify_mode` is the single answer to which one applies. The three
places that word a claim from it all read it:

- `watch.daily`'s closing comment and channel note, through `workflow.settled_counts` and
  `how_settled`, which count the two kinds separately.
- `workflow.post_checklist`.
- `slack_review.checklist_message`.

A blanket "verified in Okta" over a list that includes both kinds asserts a check that never ran,
and it's the sentence an auditor reads. `checklist_entries` carries `verify` as well as
`accepted`, so a line says how it'll be settled before anyone ticks it. `workflow.closing_claim`
says "every ticket is settled" only when the counts add up to every ticket on file.

Every `needs_graph` check settles by reviewer. `watch.still_present` re-verifies against a fresh
Okta snapshot only, so otherwise a graph finding would be ticked off because the other source's
read failed. Every check in `REVIEW_CHECKS` must also open a ticket (`FIX_CHECKS` or
`workflow.URGENT_CHECKS`), or its verify mode is configuration nothing reads.
`tests/test_tickets.py` guards both.

Every ticket that closes on a fresh Okta read says what it doesn't cover, through
`tickets._scope_to_okta`. That includes the leaver ticket. `open_urgent` asks for "every way in
through Okta", not "every way in", because `watch.still_present` settles it with
`LEAVER_ACCESS_CHECKS` against an Okta snapshot, and every person AR-17 fires on gets one. A new
ticket kind verified against Okta has to scope itself the same way.

`watch.still_present` returns None, never False, when the data behind a ticket wasn't read. False
is the claim that a fix happened, and it's written into a signed evidence record and a "done in
Okta" comment. Each branch has its own signal:

| Ticket is about | Unread when |
|---|---|
| A role | `user.admin_roles is None` |
| An app assignment | `snapshot.apps_complete` is False |
| A finding | `snapshot.gaps` names the check |
| A leaver | `leavers is None` |

`apps_complete` is False when the collecting admin role was hiding apps, which the collector
already detects. Without that guard, a revoke ticket closed as verified because the reader
couldn't see the app.

## Streaming review_items.json

`review_items.json` holds one item per app a person can reach, so it's a cross product. 5,000 users
over one org-wide group of 250 apps is 1.25M items, where `snapshot.json` at the same scale is
2.6 MB. So the file is never held in memory whole:

1. `items.items_chunks` yields the envelope, then one chunk per item.
2. `review.py` puts that iterator into `extra_files`.
3. `report._write_text` writes it a chunk at a time.
4. `report._sha256` hashes the result with `hashlib.file_digest` rather than `read_bytes`. Writing
   incrementally buys nothing if the manifest then reads the whole file back.

At 250k items the peak above the items themselves is 15 MB instead of 243 MB, and 220 MB instead of
448 MB overall, with byte-identical output in the same time. `items_json` is the reader's join over
the same chunks, used by `load_items` and the tests. It uses one `io.StringIO`, never `"".join`,
which costs 48 MB more at that size. Nothing that writes a review calls it.

`access_matrix.csv` is the other cross product. It's exempt only because it's smaller:
`report.access_matrix` joins every app a user reaches into one cell, and its `list[dict]` is held
through `_write_csv` and `write_pdf`. If the 1024 MB Lambda runs short again, look there first.

Every regression here is byte-identical on disk and invisible everywhere else, so each way of
undoing it has a test that fails. The assertions pin the property rather than one particular edit,
because an assertion shaped to one mutation lets its neighbours through.

| Test | Fails if |
|---|---|
| `test_the_items_file_is_yielded_a_row_at_a_time_and_never_whole` | The writer batches rows. |
| `test_the_items_file_encodes_one_item_at_a_time_and_never_all_of_them_first` | Rows are encoded into a list before the first `yield`. Same generator, same chunks, but the whole document is in memory before a byte is written; only when the items are pulled tells the two apart. |
| `test_a_chunked_extra_file_reaches_the_disk_before_the_last_chunk_is_asked_for` | `_write_text` joins the chunks before writing. |
| `test_a_review_hands_the_items_file_over_as_chunks_not_as_a_document` | `review.py` hands over the whole document. It asserts an unstarted generator and counts the chunks pulled, because `not isinstance(x, str)` would also accept `list(items_chunks(...))` and `[items_json(...)]`. |
| `test_the_manifest_hash_never_reads_the_file_whole` | `_sha256` goes back to `hashlib.sha256(path.read_bytes())`, which gives the same digest for every file. |
| `test_a_string_extra_file_reaches_the_file_in_one_write_and_a_rewrite_truncates` | `_write_text` loses its `isinstance` branch and writes `github_snapshot.json` one character at a time, or opens with `"a"` instead of `"w"`. That's identical until a rerun into an existing folder leaves the last review's bytes in a file the manifest then signs. |

Two hazards this doesn't close, though neither is reachable today. `_write_text` can't tell an
already-exhausted iterator from an empty file, so a stream something else consumed first is written
as 0 bytes, hashed to `e3b0c442...` and signed, and `attest` reports a full match. And a failure
mid-stream leaves a truncated file (which `attest` does catch) under the previous run's manifest.
Anything that reads `extra_files` values before `write_report` does, or any new writer here, has to
account for both.

**The layout is one item per line, with no `indent=`.** Indentation is 21% of the bytes. On the
Python 3.14 image that's the whole gain: peak memory is within a megabyte either way, and it's 1.7x
faster. On 3.11 and 3.12, `json.dumps(indent=...)` drops to the pure-Python encoder and peaks at
1.1 GB against 383 MB for the C one. 3.13 taught `c_make_encoder` to indent, so that half affects
the CLI and never the Lambda.

Each row's separator comes before it rather than after, so no row needs to know it's last. The
lookahead a trailing comma needs is the one thing a lazy writer can't do.

Rows come from `vars(item)`, not `dataclasses.asdict`, which deep-copies every item before a byte
is encoded. `vars` differs from `asdict` in two ways that matter. A field holding a dataclass, on
its own or inside a tuple, is flattened by `asdict` and handed to json unencodable by `vars`. And
`slots=True` on `ReviewItem`, the tempting fix for a class instantiated 250k times, leaves it no
`__dict__` at all. An int, bool, None, list or dict is fine under either; a date or a set never
worked under either. `test_the_items_file_is_the_same_document_however_it_is_laid_out` catches the
first by comparing against the `asdict` form.

Layout isn't format. It's the same document, still format 3, and `load_items`, `attest` and the
manifest hash need no change. One item per line matters for its own sake too: this is create-only
evidence someone may open, and a single 176 MB line can't be read, grepped or diffed. That only
holds because `json.dumps` escapes non-ASCII, so `items_chunks` passes `ensure_ascii=True`
explicitly. `str.splitlines` breaks on U+2028 as well as `\n`, and an Okta label is free text.
`attest`, `decisions` and `store` pass `ensure_ascii=False`; this one must not.
`test_the_items_file_stays_one_line_per_item_whatever_the_text_holds` enforces it.

## CI concurrency

The CI rules (pinned SHAs, `permissions: {}`, no `${{ }}` in `run:`, zizmor after every edit) are
in `CLAUDE.md` and `docs/ci.md`. One of them needs its reason here: a job behind an environment
approval (`deploy`) never shares a concurrency group with anything else. A run waiting for approval
owns its group, later runs queue behind it, and GitHub cancels the pending one each time a newer
run arrives. Commits lose their verification with no error, and the runs just read `cancelled`.
