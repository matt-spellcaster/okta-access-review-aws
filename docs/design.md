# Design notes

Why the invariants in `CLAUDE.md` exist. Each section records the failure a rule prevents; read
the relevant one before changing that area.

## The identity graph

A new check needs: an entry in `CHECKS` (`checks.py`) with SOC 2 and ISO 27001 control IDs, a planted
case in the fixture for the source it reads (`fixtures/demo_snapshot.json`, or
`fixtures/demo_github.json` for a `needs_graph` check), an updated expectation in
`test_demo_findings_are_exactly_the_planted_ones` **and in
`test_cross_source_findings_carry_the_planted_severities`** (severity is the judgement in these
checks; asserting subjects alone lets a constant pass). A `needs_graph` check reads `ctx.graph`
rather than `ctx.snapshot`. **The graph is built on every review**, from the Okta projection alone
when no second source was given: an estate of one is still an estate, the register declares Okta
service accounts too, and gating it on `--github` meant AR-18 -- written for Okta's own API
clients -- could not fire on an Okta-only run, which is every AWS run. What a second source adds
is the other estate, not the graph. A graph check is therefore only skipped by `run_review` when
there is no roster it also needs; `handlers.verify_daily` builds no graph on purpose, because every
graph check settles by reviewer and the daily read never re-runs one. The **departure bundle** is the artifact that does need a second source and
asks for one directly (`build_transitions` returns None without it): built from Okta alone it
would report every leaver's residue elsewhere as empty, which is the silence-as-absence claim the
file exists to stop. `_note_register` now runs on every review too. An entry naming a source this
run did not read is a gap only when it is dead -- a kind no collector reads (`review.SOURCE_KINDS`),
or a name that misses the estate of its kind that *was* read (a typo'd org). A GitHub entry on an
Okta-only run is out of scope, not a gap: the AWS pipeline never reads GitHub, and a gap there
marked every AWS review INCOMPLETE for good, which teaches everyone to ignore the banner.
Building the graph on Okta-only runs also exposed that Okta reads activity only for leavers and
the clients whose credentials they held, so `SourceMeta.activity_complete` cannot speak for any
other client: `Snapshot.activity_actors` says whose activity was read, `Credential.usage_read`
carries it per credential, and an unread one is "use not read" and counts as possibly recent.

A graph finding's subject is `{source}/{principal.id}` (`checks.graph_subject`), never the label.
Ticket identity is `(check_id, subject)` hashed into a permanent Jira label, and a label is a
display name: a GitHub login can be renamed and two Okta service clients can share an app label,
which would collapse two unremediated problems onto one ticket. The readable name goes in the
detail, which is what the ticket body and the PDF show.

Keep the snapshot format (`models.py`) the same for live and fixture data; the existing checks only
see `Snapshot`. `Snapshot` is the Okta source adapter's output and never grows to fit another
source: `identity/` composes above it, and cross-source checks read an `IdentityGraph` built by
projecting each source into it.
In `identity/`, a principal is tied to a person by an evidenced `LinkMethod` or not at all -- never
by name or email similarity, because a false link marks a credential as accounted for when nobody
is. Completeness is per source (`SourceMeta`): a read that failed is "incomplete", never "nothing
found".

A graph source's own snapshot is written into the run folder through `extra_files` so the manifest
hashes it (`review.GITHUB_SNAPSHOT_FILE`). Findings whose evidence is outside the bundle cannot be
re-verified by `attest`. `review._note_skew` records a gap when two sources were read more than
`SOURCE_SKEW_DAYS` apart, after composing so it does not also clear `activity_complete`.

A source adapter decides which of its roles are elevated, never `checks.py`: `identity/github.py`
emits a `GrantKind.ROLE` grant only above ordinary membership (`ORDINARY_ROLES`), case-folded,
because GraphQL spells the enum `ADMIN`/`MEMBER` and the invitations read says `direct_member`.
`checks._elevated_roles` reads every ROLE grant and AR-17 grades critical on it, so an ordinary
member appearing there makes every departure critical. A role the adapter does not recognise is
treated as elevated. Roles the snapshot never read are a gap (`roles_complete`), not an absence --
and a gap the severity itself reads, not only one the report prints: see Completeness.

## Completeness

`report.all_gaps` is the single answer about completeness and it reads **every** `SourceMeta` in
the graph, Okta included, because a projection records gaps the snapshot never had. Slack, email,
the CLI and the Step Functions output take it from `ReviewRun.gaps`/`.complete`, never from
`snapshot.gaps`, which speaks for Okta alone. `report.other_sources` is display only.
Emptiness is only evidence when the read that would have said so ran. A check reading credentials
asks `_credential_evidence_complete` first (`SourceMeta.activity_complete`, not `.complete` --
identity gaps say nothing about whether the scopes were read), and `_write_access` returns None,
not False, when they were not. Unknown is never ranked as the milder case.

The same holds for roles, through a **third** completeness signal: a check grading on a role list
asks `_roles_evidence_complete` (`SourceMeta.roles_complete`) first. `.complete` is identity,
`.activity_complete` is credential activity, and roles are their own optional read that fails on
its own -- `okta.roles.read` in Okta, the organization-roles endpoints in GitHub -- and both
sources hand back an empty list when it does. `_elevated_roles` therefore cannot tell "holds no
elevated role" from "nobody read the roles", so AR-17 and AR-18 grade `critical` on an unread list
exactly as they do on unknown write access, and say so in the detail (`_roles_unread_note`).
Otherwise a departed organization owner whose roles were never fetched grades `high` with a
detail naming only a read-only token. An Okta **user** answers for itself instead: AR-18 reads
`User.admin_roles is None`, because the collector never reads a DEPROVISIONED user's roles and Okta
keeps group-assigned admin roles through deactivation and restores them on reactivation, while
the source flag can be False over a user whose roles were read before a client's call was
refused. An Okta client whose list names a role proves its own read ran. The note says "its roles
were not read" only on the account's own evidence, and "the role read did not complete" on the
source's. `Snapshot.from_dict` derives a missing flag from those Nones and the refusal gap rather
than assuming the read ran. Both adapters populate the flag -- `Snapshot.roles_complete` comes off
`roles_api.allowed` in `collect`, because
`User.admin_roles` has a None for this and `App.admin_roles` does not -- and each wiring point has
a test that kills its removal, since a projection that drops the field falls back to the
permissive default and the whole fix goes silently inert.

An empty `outside_okta` is three different answers and `items.outside_okta_gap` says which:
no source but Okta was read, a source was read but did not complete, or a complete read found
nothing. Only the last makes the absence evidence, so the card block and the ticket paragraph
appear on the strength of the **gap alone** -- an absent block reads as "they hold nothing
elsewhere", which is the silence-is-absence bug on the screen that settles the item.

## Grants and group expansion

`IdentityGraph.grants` is only what a source stated verbatim, never the whole set. App-via-group
access is stored once per group (`group_apps`) and expanded on read, because one org-wide group
over 250 apps materialises 1.25M grants and 535 MB RSS against a 1024 MB collect Lambda. Ask
`grants_for(key)` for one principal's access and `all_grants()` for every grant in the graph;
reading `.grants` for either is short by every app anyone reaches through a group, and `compose`
carries both fields or a second source empties the first one's app access. The expanded grant's
`via` is rebuilt from the group grant's own label so it stays byte-identical to the materialised
form, which `transitions.py` writes into the hashed departure bundle. `items.py` never reads a
graph grant: its `via` comes from `Snapshot.apps_for`, which builds the same `group:<name>` shape
independently, so the two formats must not drift.
`test_grants_holds_only_what_the_source_stated_and_all_grants_holds_everything` pins the split.
Derive a graph from another with `dataclasses.replace`, never by naming its fields: `group_apps`
defaults to empty, so a hand-built `IdentityGraph(grants=..., links=...)` is short of everyone's
app-via-group access while `incomplete_sources()` still reads clean -- silence as absence, in the
bundle an auditor reads. `grants_for` now pays the expansion on every call rather than once at
projection, so a whole-graph walk is O(principals x groups x apps): call `all_grants()` once
instead of looping `grants_for` over every principal.

## Source adapters and fixtures

A new source adapter in `identity/` needs: its own snapshot shape with `from_dict`/`to_dict`, a
hand-written fixture in `fixtures/` with one planted case per thing a check will find, a
projection into `IdentityGraph`, any new `CredentialKind` members it emits, a re-export from
`identity/__init__.py`, and tests -- before any collector that talks to the live API. An adapter
that emits `GrantKind.GROUP` grants must also populate `group_apps`, or the apps those groups
reach are silently absent with a green suite; the expansion is GROUP -> APP only, so a source
whose containers are `TEAM` (GitHub) cannot use it and has to state its grants verbatim. The model
and the projection share the adapter module (`identity/github.py`) until a second reader of that
snapshot exists; `models.py` is split out only because fourteen checks read it.
**A fixture's shape is the shape the real API returns.** Check every field against the vendor's
documentation before building on it: a hand-written fixture that invents fields yields checks
validated against data no collector can supply. Where the API cannot provide something, the
snapshot says so (`sso_enabled`, `credentials_complete`) rather than leaving it blank. The field
allowlist here is the requirement the collector must meet, per `ActivityEvent.from_okta`.

## The service account register

The service account register (`register.py`, `Config.service_accounts`) is an ownership claim, not
a mute button. **An entry with no owner must never remove a finding.** It emits
`Link(key, DECLARED, "", ...)`, which takes the principal out of `graph.unlinked()` and used to
delete its AR-15 -- a config change that made a write-capable credential stop being reported while
exactly as many people were accountable for it as before: nobody. Those principals are
`graph.unattributed()`, AR-15 walks that list as well as `unlinked()` (the two are disjoint), and
reports them one severity milder, floored at `low` -- `info` is the rung for what a reviewer
confirms rather than fixes. An `owner` is the only thing that clears the finding, and it is
normalised the way `identity_key` normalises an Okta profile email or it joins to nobody while
reading as owned. That link is also what puts the account in the owner's departure bundle, through
`principals_of` -- no new check, and it is the loop the register exists for.
**An owner only counts when some source evidences that person.** `IdentityGraph._attested` is the
set of identities named by a link whose method is not DECLARED -- every other method is a source
speaking about its own data, while DECLARED is somebody typing an address into a config file. An
unattested owner is `unattributed()`, ranks in `strength` exactly as a nameless link does, and is
kept out of `_by_identity` so `identities()` cannot invent the person. Without all three,
`marcus.lee@acme.exmaple` read as ownership, joined to nobody, reached no departure bundle and
*cleared* the finding a blank owner only downgrades -- a typo quieter than an honest blank, which
inverts the rule above. `review._note_register` records it as a gap after composing (an owner's
estate is usually not the account's, so no single projection can settle it), along with a dead entry
naming a source the review never read -- an unknown kind, or a name that misses the estate of its
kind that was read -- the one dead entry `Register.stale` structurally cannot see, because `stale`
is called per source and never runs for a source nothing projected. An entry for a kind this run
was not asked to read (GitHub on an AWS run) is out of scope, not a gap.
`ServiceAccount.key` folds case on **both** halves: a GitHub org login displays in its creation
casing (`Acme-Eng`) while `source_name` builds it from the API, and comparing sources exactly made
such an entry silently inert and let two owners past the one-account-one-owner check.
Three more things it must not do. **A link naming somebody outranks one that does not, whatever
the method** (`strength` in `IdentityGraph`): DECLARED beats CREATOR on rank, so without that an
ownerless entry would erase the audit log's "priya built this". **Entries are scoped to a source**
(`okta`, `github:<org>`), because a login is only a name within one estate. And an entry must
identify **one** account: a service client is matched by client id, or by app label only when that
label picks out exactly one client, because two clients can share a label -- the same reason ticket
identity is hashed from the stable id. An entry that matches nothing, or a label that matches two,
declares nothing and records a gap; silently ignoring it leaves a claim that looks like coverage.
**A name is matched against the accounts that are still live**, in both estates that have a way to
tell. `collect` reads `/api/v1/apps` with no status filter, so the ordinary way two clients share a
label -- deactivate the old "Terraform Automation", build the new one -- made a correct entry
declare neither and put the live client back at full AR-15 severity; a label now picks out the one
client still running, while a lone client is declared whatever its status, and a status
`_app_status` does not recognise keeps the label ambiguous rather than vouching for a client nobody
meant. GitHub is the sharper case, because a freed login is claimable: an entry there can go on
matching a **different** account, and matching is not a quiet no-op -- it types the account SERVICE,
skips the `elif member.saml_identity` branch so a real person's access joins to nobody, and puts
the entry's owner on somebody else's credentials. `identity/github.py._changed_hands` refuses an
entry whose `reviewed` date predates GitHub's account creation date and records a gap, which is
what that date is for; an old account renaming into a freed login is past what a register keyed by
a name can see, and the docstring says so rather than implying the name is checked.
The register is written into `manifest.json` inside the signed config, so everything in it has to
stay JSON: the lookup index is set with `object.__setattr__` rather than declared as a field
(its keys are tuples) and `reviewed` goes through `Register.to_dict` (it is a `date`).

## Leaver checks: AR-12, AR-13, AR-17, AR-18

A service account a leaver owned is **AR-18's, never AR-17's**. AR-17 asks for a leaver's own
access to be revoked; AR-18 asks for the account to be handed to somebody, because something
depends on it still running, so two findings on one principal would be two tickets whose
remediations contradict. `_leaver_access_outside_okta` skips `PrincipalKind.SERVICE` and AR-18
takes it, across **every source and every status** -- a strict superset of what AR-17 drops, which
is what makes the skip safe. A System Log credential event carries two facts. *Custody* -- the
leaver created the client, added or activated a secret or key, or read the secret back
(`models.CREDENTIAL_EVENTS`; deactivating or deleting a secret shows nobody anything and is left
out) -- means they may hold a working copy. *Ownership* -- only `models.CREATION_EVENTS` -- is the
CREATOR link. Both land on **AR-18**, one finding per client with both reasons in the detail, and
its remediation asks for somebody still here to answer for the client and for every secret the
leaver held to be rotated. That settles by reviewer, and it has to: the first version put custody
on AR-12 and the leaver ticket, which closes on a daily Okta re-read, and Okta cannot show a
rotation reliably. Re-deriving custody from the log closed the ticket once the event aged past 90
days; reading secret and key creation dates instead could never see a key published at a
`jwks_uri`, left the ticket waiting forever on a read that 404'd, and told the CISO "Okta still
shows the problem" when it showed nothing. AR-12 is API tokens alone, which the re-read does see.
Reading a secret never makes anyone a CREATOR: that version named whoever once opened a colleague's
client as the person who answers for it. AR-13 reads the leaver's own account only: a client
running after its builder leaves is what it is for, and reading it as theirs raised a critical
"possible incident, revoke it" against AR-18's "hand it over". Where the register has since named
a different owner the account is that person's, which is the handover AR-18 asks for, and where it
names somebody no source evidences it is AR-15's. Anything else that reports an account a leaver
was accountable for has to join this partition or inherit the contradiction. Okta's own API clients are what AR-17 structurally cannot see (it
skips `source == OKTA`), and they are the demo's two planted cases: `okta/a04` declared to
marcus.lee in the register, `okta/a05` tied to victor.nguyen by nothing but the System Log's record
of who created it -- so the check reads whatever link the graph chose, not DECLARED alone. DISABLED
is not an answer here the way it is for AR-17: `CredentialKind` is the set of things that outlive
the account they were created under. Severity grades on what the **account** can change, not on it
having a role: `_elevated_roles` means "above ordinary membership", which for Okta includes
Read-Only Administrator, so AR-18 filters `READ_ONLY_ROLES` out of it and grades critical on an
elevated role **or** write access, unknown -- including an unread role list -- counting as the
worse case. The ownership half is disjoint from AR-15 by
construction, not by a filter -- AR-18 walks `principals_of`, indexed on attested identities, and
AR-15 walks the principals whose best link reaches nobody.

## No account is told to go and to stay

Every check declares what its remediation does to the account itself (`Check.disposition`, no
default): REMOVE takes the access or the account away, RETAIN keeps it running under somebody new,
NEITHER takes no position. REMOVE and RETAIN on one account are two tickets telling one assignee
opposite things, and the REMOVE one closes on a fresh Okta read that only the removal satisfies, so
the handover is signed off as done by something that asked for the opposite. That was found by a
person reading two remediations side by side three times (AR-17, AR-12, AR-09), so
`test_no_account_is_told_to_go_and_to_stay` asserts it instead. When classifying, the question is
not whether the sentence says "remove": it is whether carrying out this remediation undoes the other
one's premise. Narrowing an API client's scopes (AR-10) leaves the client running, so it is NEITHER;
AR-02's "or get the end date extended" corrects the data rather than offering an equal branch, so it
is REMOVE; AR-15 asks who is accountable, which is compatible with the groups having gone, so it is
NEITHER though its sentence looks like AR-18's.

The guard keys on the finding's **subject**, which is what a ticket is identified by, and resolves
each subject to an account, failing on a shape it was not taught. It runs against the demo and
against worst cases that bend the fixture until AR-18's Okta user account is also reachable by a
removal check: deactivated in each of `DISABLED_STATUSES` (AR-09), and active with an old direct
assignment (AR-14, which exempts register-declared accounts, and that exemption is what the test
guards). The demo alone would pass on a review where nothing happened to overlap.

**AR-09 stands down for AR-18.** The register makes any Okta user it declares a service account, so
a declared bot that is deactivated and still in groups got AR-09's "remove them" under its login and
AR-18's "hand it over" under `okta/<id>`. `checks.leaver_accountable_accounts` is the one computation
of AR-18's accounts; AR-18 walks it, `_disabled_with_access` stands down for the Okta users in it,
and `items._app_proposal` proposes `decide` rather than Revoke on them, because approving a revoke
would take the decommission branch as a signed decision. It is empty without a graph or a roster, so
the partition switches off rather than silencing anything. Standing down is safe only because AR-18
names the account's state and, for a disabled Okta user, lists the groups and apps AR-09 would have
listed, through the same `_leftover_access`, in full and without BUILT_IN groups. It says
"reactivating it restores" rather than "reaches": Okta unassigns a deactivated user from every app and
keeps its group memberships, so the apps are what those groups give back. A leaver's own Okta account,
one whose roster entry is gone, is never in the set: HR lists it as a person who left, so the leaver
checks report it, and a register entry declaring it cannot move it from Okta-verified removal to a
reviewer's handover. Only a gone entry: `entry_for` matches on the profile email, a bot can share one
with somebody still employed, and for an active entry no removal check fires, so excluding it would
drop AR-18 with nothing in its place.

Two consequences outside the checks. `history._held`: an AR-09 finding that vanished while AR-18
held **that** account is not "Back again" -- it never went -- and not "New" either: the held review
bridges its streak, so first_seen and reviews_open carry across it. Only as a bridge: a finding AR-09
never reported before is still new. It is per check (`checks.STANDS_DOWN_FOR`) and per account
(`checks.okta_user_subjects` joins the login to the graph subject); keyed on "any AR-18 finding last
review" it hid every genuine reopen on eight checks. And `handlers.verify_daily` builds no graph: with
one, AR-09 would stand down, an AR-09 ticket an earlier review opened would read as absent, and
`watch.daily` would close it as done in Okta for groups nobody touched.
`test_the_daily_recheck_keeps_an_ar09_ticket_open` calls the handler.

Two limits this leaves, stated rather than hidden. The partition holds within one review, not across
reviews: if an earlier review opened an AR-09 ticket for an account a later review hands to AR-18
(its owner left in between), that ticket stays open and keeps asking for the groups to go, next to
AR-18's handover ticket, because `verify_daily` still sees AR-09. Nothing yet links or supersedes the
older ticket. And the register is trusted: an entry naming a leaver as owner moves a disabled account
with no gone roster entry from AR-09, which closes on an Okta read, to AR-18, which closes on the
reviewer's word. The account is still reported, and at a higher severity, but the proof it was
cleaned up is weaker. Anyone who can edit the register can already declare accounts, so this is a
trust assumption about the register, not a new capability.

## Review items and cross-source findings

Review proposals (`items.py`) never propose Revoke on missing or truncated data; the item becomes
"decide" instead.
A cross-source finding reaches the reviewer through `checks.graph_findings_by_identity`, which goes
subject -> principal -> strongest link -> identity, or, on the account's own item, through
`checks.graph_findings_by_subject`, which matches the subject to that exact principal. Never match a graph finding to a person by
login, label or email similarity: the link already carries the evidence. A principal that is
unlinked or contested, or declared with nobody named, reaches no one's review item -- putting it
on somebody's screen would assert the attribution the graph refused to make. `GRAPH_CHECKS` is
derived from `CHECKS`, not listed, so a new graph check cannot be printed in the report and
missing from the screen that settles it.

Review items are built from Okta access, so someone whose Okta offboarding completed has none --
and their cross-source finding would reach no decision screen, which is the one case the check
exists for. `items.CROSS_SOURCE` is the person-level item that catches them. It settles by
acknowledging (`ACKNOWLEDGE_ONLY`, like `HR_RECORD`): this review cannot change another source,
and the finding's own ticket tracks the fix.
A cross-source concern goes in `ReviewItem.outside_okta`, never in `.concerns`. It is on every one
of that person's items by design, and `.concerns` is what `tickets.open_revokes` copies as the work
a ticket covers -- a ticket that closes when the daily check re-reads **Okta**, which cannot see
whether a GitHub owner role is gone. Listed there, one untouchable finding was signed off as fixed
once per revoke ticket by something that never looked. The reviewer still sees both
(`slack_review.card_lines` puts `outside_okta` first: it is the part no other screen in the review
reaches and the part the decision cannot change), and the ticket names it under "Not part of this
ticket". Anything that can land there must be in `FIX_CHECKS` specifically, not merely in
`URGENT_CHECKS`, or the claim that it has its own ticket is false: an urgent ticket is one per
leaver keyed by Okta login, so a graph finding whose subject is `{source}/{principal.id}` would be
folded into a ticket that never names it. `test_a_graph_check_settles_through_its_own_fix_ticket_not_a_leaver_ticket`
and `test_everything_named_as_out_of_scope_really_does_get_its_own_ticket` guard both halves.
That block is **not a claim about where the account lives**, and its wording must not make one.
Most of what lands there is in another source, but AR-18 reports a service account whose owner
left, and an Okta API client is the case it exists for: it is in Okta, and the daily re-read of the
leaver's own access still cannot see it. So `slack_review.OUTSIDE` (one string, used by the card
heading, the item line and the sign-off list), `items.CROSS_SOURCE_TARGET`/`CROSS_SOURCE_REASON`
and `tickets._scope_to_okta` all say what the decision and the ticket do not settle, never "outside
Okta". The field and the file format keep the name `outside_okta`; the sentences a reviewer reads
do not. `items.outside_okta_gap` is the exception and stays as it is -- it is specifically about
which other sources were read.

`load_items` splits a pre-format-3 file rather than trusting its `concerns`: a review opened before
the split and remediated after it would otherwise put a cross-source concern back into a revoke
ticket that closes on an Okta re-read. The split needs **both** signals the writer left
(`items.LINK_MARKER` and a check id in `GRAPH_CHECKS`), so it cannot move an Okta finding. It is
in memory only -- the object is create-only in S3 and hashed into a signed manifest, so nothing
rewrites the file.

## Departure bundles

A departure bundle (`transitions.py`) is per identity, never per account, and takes the review's
gaps from `ReviewRun.gaps` rather than deciding completeness itself. `build_transitions` returns
None when there was no graph or no roster: "nobody left" and "nothing looked" are different
answers, and an empty list reports every departure clean. The denominator is the **roster**, not
the Okta user list: a leaver whose account was deleted, or whose profile has no email, still gets
a bundle carrying its own gap, because walking accounts answers "which departures does Okta still
know about" and drops the rest from numerator and denominator at once. Bundles carry personal
data, so today they stay in the run folder and the evidence bucket; `transitions.summary` is the
counts-only shape for Slack and Step Functions. Walk users in login order -- evidence that changes
with API paging is not evidence.

## Tickets and verification claims

A `needs_graph` check settles by reviewer (`REVIEW_CHECKS` in `tickets.py`) until `watch.still_present`
can see that source's gaps. It re-verifies against a fresh Okta snapshot only, so a graph finding
would otherwise be ticked off because the other source's read failed. It must also be in
`FIX_CHECKS` or `workflow.URGENT_CHECKS`, or no ticket is ever opened and its `verify_mode` is
configuration nothing consults. `tests/test_tickets.py` guards both.

Every ticket that closes on a fresh Okta read says what it does not cover, through the one helper
`tickets._scope_to_okta`. That is both the revoke ticket and the **leaver** ticket: `open_urgent`
asks for "every way in through Okta" rather than "every way in", because `watch.still_present`
settles it with `LEAVER_ACCESS_CHECKS` against an Okta snapshot, and every person AR-17 fires on
gets one. A new ticket kind verified against Okta scopes itself the same way or it inherits the
overclaim.

A ticket settles one of two ways and nothing says otherwise. `tickets.record_verify_mode` is the
single answer -- a revoke or leaver ticket asks for a change in Okta and is re-read there, a fix
ticket in `REVIEW_CHECKS` is taken on the reviewer's word -- and the three places that word a claim
from it all read it: `watch.daily`'s closing comment and channel note (through
`workflow.settled_counts` and `how_settled`, which count the two apart), `workflow.post_checklist`
and `slack_review.checklist_message`. A blanket "verified in Okta" over a list that includes either
kind is the review asserting a check that never ran, and it is the sentence an auditor reads.
`checklist_entries` carries `verify` as well as `accepted`, so a line says which it will be before
anyone has ticked it, and `workflow.closing_claim` only says "every ticket is settled" when the
counts add up to every ticket on file.
`watch.still_present` returns **None**, never False, when the data behind a ticket was not read.
`False` is the claim that a fix happened, and it is written into a signed evidence record and a
"done in Okta" comment. Every branch needs its own signal: `user.admin_roles is None` for a role,
`snapshot.apps_complete` for an app assignment, `snapshot.gaps` naming the check for a finding, and
`leavers is None` for a leaver. `apps_complete` is False when the collecting admin role was hiding
apps, which the collector already detects; without that guard a revoke ticket closed as verified
because the reader could not see the app.

## Streaming review_items.json

`review_items.json` is the **largest** run-folder file holding a cross product -- one item per app
a person can reach, so 5000 users over one org-wide group of 250 apps is 1.25M of them, where
`snapshot.json` at the same scale is 2.6 MB. `access_matrix.csv` is the other one and is exempt
only because it is smaller: `report.access_matrix` joins every app a user reaches into one cell,
so its bytes are the same cross product, and the `list[dict]` is held live through `_write_csv`
**and** `write_pdf`. If the 1024 MB Lambda binds again, that is where to look, not here.
So this file is **never materialised**. `items.items_chunks` yields the envelope and then one
chunk per item; `review.py` puts that iterator into `extra_files`; `report._write_text` writes it
a chunk at a time; `report._sha256` hashes the result with `hashlib.file_digest` rather than
`read_bytes`, because writing it incrementally buys nothing if the manifest then reads all of it
back. Measured at 250k items: 15 MB of peak above the items themselves against 243 MB, 220 MB
against 448 MB overall, byte-identical output in the same wall time. `items_json` is the reader's
join over the same chunks -- `load_items` and every test take text -- and uses one `io.StringIO`,
never `"".join`, which costs 48 MB more at that size; nothing that writes a review calls it.
Every regression here is **byte-identical on disk and silent everywhere else**, so each way of
undoing it has one test that kills it, and the assertions pin the *property* rather than the exact
edit -- an assertion shaped to one mutation lets its neighbours walk through, which is how five of
these survived a green suite once already. Six mutants, six tests:
`test_the_items_file_is_yielded_a_row_at_a_time_and_never_whole` (a writer that batches rows);
`test_the_items_file_encodes_one_item_at_a_time_and_never_all_of_them_first` (rows encoded into a
list above the first `yield` -- same generator, same chunks, whole document live before a byte is
written, so only *when the items are pulled* can tell the two apart);
`test_a_chunked_extra_file_reaches_the_disk_before_the_last_chunk_is_asked_for` (a `"".join`
inside `_write_text`); `test_a_review_hands_the_items_file_over_as_chunks_not_as_a_document`
(`review.py` handing over the document again -- it asserts an **unstarted generator** and counts
the chunks pulled through it, because `not isinstance(x, str)` also accepts `list(items_chunks(
...))` and `[items_json(...)]`, which both put the peak straight back);
`test_the_manifest_hash_never_reads_the_file_whole` (`_sha256` back to
`hashlib.sha256(path.read_bytes())`, which yields an identical digest for every file); and
`test_a_string_extra_file_reaches_the_file_in_one_write_and_a_rewrite_truncates` (dropping
`_write_text`'s `isinstance` branch, which writes `github_snapshot.json` one character at a time,
and opening `"a"` instead of `"w"`, which is identical until a rerun into an existing folder
leaves the previous review's bytes in a file the manifest then signs).
Two hazards this does **not** close, both latent rather than reachable today: `_write_text` cannot
tell an already-exhausted iterator from an empty file, so a stream something else consumed first
is written as 0 bytes, hashed to `e3b0c442...` and signed, and `attest` reports a full match; and
a failure mid-stream leaves a truncated file (which `attest` does catch) under the previous run's
manifest. Anything that reads `extra_files` values before `write_report` does, or any writer added
here, has to reckon with both.
The layout is **one item per line, never `indent=`**. Indentation is 21% of the bytes on every
version, which is the whole of the win on the 3.14 image -- peak there is within a megabyte either
way, and the gain is 1.7x on time. The memory cliff is 3.11 and 3.12 only, where
`json.dumps(indent=...)` drops to the pure-Python encoder and peaks at 1.1 GB against 383 MB for
the C one; 3.13 taught `c_make_encoder` to indent, so that half bites the CLI and never the
Lambda. The row separator **leads** each row rather than trailing it, so no row has to know it is
last; the lookahead a trailing comma needs is the one thing a lazy writer cannot do. Rows come from `vars(item)`,
not `dataclasses.asdict`, which deep-copies every item before a byte is encoded. The two ways
`vars` can differ from `asdict` are a field holding a **dataclass** (on its own or inside a
tuple), which `asdict` flattens and `vars` hands json something it cannot encode, and
`slots=True` on `ReviewItem`, which leaves it no `__dict__` at all -- the tempting fix for a class
instantiated 250k times. An int, bool, None, list or dict is fine under either; a date or a set
never worked under either. `test_the_items_file_is_the_same_document_however_it_is_laid_out`
catches the first by comparing against the `asdict` form. Layout is not format: same document,
still FORMAT 3, and `load_items`, `attest` and the manifest hash need nothing. The line-per-item
part is load-bearing too -- this is create-only evidence someone may open, and one 176 MB line
cannot be read, grepped or diffed. It survives only because `json.dumps` escapes non-ASCII, so
**`items_chunks` passes `ensure_ascii=True` explicitly**: `str.splitlines` breaks on U+2028 as
well as `\n`, and an Okta label is free text. `attest`, `decisions` and `store` pass
`ensure_ascii=False`; this one must not, and
`test_the_items_file_stays_one_line_per_item_whatever_the_text_holds` is what says so.

## CI concurrency

CI (`.github/workflows/compliance.yml`): pin every action to a full commit SHA with a version
comment, keep `permissions: {}` at the top with per-job grants, never interpolate `${{ }}` into
`run:` (pass it via `env:`), and run `uvx zizmor@<pinned> --offline .github/workflows` after
editing. If a job is renamed, update `REQUIRED_CHECKS` in `scripts/ci/check_branch_rules.py`
and the ruleset. A job behind an environment approval (`deploy`) must never share a concurrency
group with anything else: a run waiting for approval owns its group, later runs queue behind it,
and GitHub cancels the pending one each time a newer run arrives, so commits lose their
verification silently and the runs read `cancelled`. See `docs/ci.md`.
