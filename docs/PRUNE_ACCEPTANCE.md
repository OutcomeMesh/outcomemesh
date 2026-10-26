# Pinned local archive-prune acceptance

Status: opt-in **library** vertical slice, not a public command, network grant or
production deployment. Do not use with production data or real value. This adds
actual replica replay and ticketed deletion to one original colocated runtime;
it does not complete audit/serve/prune integration or enable active cutover.

## Exact scope and pins

`PruneExecutor.ExecuteArchive` accepts an existing pinned executor, a concrete
position-pinned WorkChain, independently pinned `ArchivePrunePolicy`, a complete
selected set of `RequiredOperation` owners/tickets, replica directories and a
dedicated evidence destination. The caller retains ownership throughout the call.
No daemon, CLI Execute, live stdin action or remote effect endpoint is added.

The policy digest commits the original request ID, executor-pair binding,
WorkChain pair ID, exact signed checkpoint, trusted attestors and quorum,
trusted replica keys and quorum, maximum receipt age, minimum remaining term,
and replica-key-ordered assignment IDs. Assignment IDs include their archive
binding, initial receipt, generation, custody policy and consumers.

The inner archive policy domain is `OMESH/workgraph/archive/prune-policy/v0`; the
outer runtime policy domain is `OMESH/custody-prune/archive-acceptance-policy/v0`.
These are local configuration hashes, not signature or consensus domains. The
expected outer ID must come from independently reviewed protected configuration,
not from whatever configuration the runtime happens to read. The preparation-only
inventory below can retain exact configuration and historical admissions. The
opt-in prepared execution method binds it to a retained start. No policy bootstrap,
migration, hot-reload or inventory execution command is provided.
Retain the configuration and its external pins for later operator review.

Every receipt used in the request's availability bundle must have exactly one
selected assignment and admitted operation. Missing, extra or repeated owners
and replicas fail; supplying only one executor guard is insufficient. The operator
still chooses independently operated replicas; this does not discover every real
deployment or prove failure-domain independence.

The original `ExecuteArchive` accepts only exact version-0 **initial receipts**.
It still rejects renewals. Another generation cannot substitute merely because
keys match. Renewal acceptance uses the distinct mode below.

## Explicit renewal-prefix mode

`ExecuteArchiveWithLineage` requires `ArchivePrunePolicy.LineageID()` from protected
configuration. Its domain is `OMESH/custody-prune/archive-lineage-policy/v0`; it
commits the original policy ID plus the local aggregate evidence budgets. The
initial-only policy pin is not valid for this mode, or vice versa. The retained
request already fixes the selected availability bundle and receipt IDs; each
renewal receipt commits its predecessor and signed custody proof. No request,
signature, journal, terminal or consensus encoding changes.

Supply exactly one `CustodyReceiptLineage` per selected assignment, in any order.
Each contains the assignment ID, original initial receipt, exact custody policy,
existing canonical manifest bytes and the complete existing canonical journal-entry
prefix from sequence one. An initial selected receipt uses an empty prefix. The
verifier reconstructs the assignment's archive/receipt/policy/auditor bindings,
checks every sequence, entry hash, predecessor receipt, challenge, sample bytes,
proof and renewal, and requires the exact selected terminal receipt. It uses each
record's signed response time for historical verification, never as live freshness.

Across all assignments, this mode accepts at most 1,024 entries and 256 MiB of
encoded manifests plus entries. Existing per-manifest/per-entry codec bounds
also apply; metadata remains separately bounded by member/replica limits. The
aggregate check runs before copying large buffers. Accepted manifest, entry and
auditor slices are detached before waiting on coordinators. Callers must not
mutate inputs concurrently during entry/copying. Verification checks cancellation
between bounded entries and keeps all current authority guards through archive
replay, evidence publication, the final live-time storage check and result.

This is a historical prefix verifier, not proof of the latest or uniquely retained
journal head, independent storage durability, absence of forks, or live permission.
It does not prove historical Audit-ticket admission: managed audit/serve acceptance
remains a separate gate. The held current tickets authorize this Prune operation.
It opens/repairs no journal and never activates historical-only evidence. There
is no live-journal evidence extraction/publication CLI or new automatic recovery.
The separately pinned historical evidence file below now retains supplied complete
prefixes; it does not discover or select them from live owner journals. Full
operator ownership and CLI tooling remain open.
The unchanged primary effect record alone does not certify use of this lineage
mode. Historical recovery does not retroactively verify it. Only the explicit
inventory-bound start path below records that link; merely supplying the
preparation package later is not evidence that these checks ran.

## Prepared policy and operation inventory

`ArchivePruneInventory` is an offline preparation package, **not an authorization
or execution certificate**. It retains the full `ArchivePrunePolicy`, original
storage-bound `PruneRequest`, exact selected `AvailabilityBundle` and one original
co-signed Admit entry per selected assignment. The explicit mode is initial-only
or complete-lineage-required. It contains no private keys, local paths, live owner
handles, lineage bodies, storage effects or terminal acknowledgements.

Canonical validation requires every assignment, receipt and admission to share
the same strict replica-key ordering. It verifies checkpoint/receipt/command/
authority signatures, local trust/quorum policy, exact primary assignment and
consumer membership with Prune permission in **every** selected assignment.
Secondary admissions must name their own assignment, the original primary request
ID and its consumer; the request is not rewritten to derive a secondary operation
ID. The complete retained floor must match the checkpoint and availability bundle,
including the minimum receipt retention term. Availability is checked at the
request's retained `VerifiedAt`, not against a newly sampled clock.

Initial mode accepts only the assigned initial version-0 receipts. Lineage mode
declares the requirement to supply complete bounded prefixes separately; a renewed
receipt's signature is not a substitute for those proofs. Even in lineage mode,
a selected version-0 receipt must equal its assignment's initial receipt.

Format version 0 has a 1 MiB whole-package ceiling and existing nested codec bounds:

- magic `OMCPINVT`, version u16, mode u16 (0 initial, 1 lineage);
- length-prefixed canonical request, three fixed policy request/executor/storage
  pair IDs, length-prefixed canonical checkpoint;
- attestor quorum u16 and key list; replica quorum u16, maximum receipt age u64,
  minimum remaining term u64 and key list;
- assignment count and interleaved length-prefixed canonical assignment/Admit
  entries, followed by a length-prefixed canonical availability bundle.

Integers and minimal-varint lengths use the existing canonical codec. Key and
assignment lists are capped at 64 before allocation; truncated, overlong and
trailing input fails. The checkpoint statement supplies its already-validated
policy binding. The inventory ID domain is
`OMESH/custody-prune/prepared-inventory/id/v0`. Both the inventory ID and the
appropriate existing initial/lineage policy ID must be independently reviewed and
retained outside the package. Computing expected pins from an untrusted package
does not protect it. The frozen two-replica test vector has inventory ID
`e70f23ce82f121c5c8df04d35bf27e67b036b70516fa57083fd5397ae7175fc1`.
This preparation-only format does not change consensus, existing requests,
signatures, authority/executor journals, storage effects or terminal records.
The separate opt-in execution method below adds a versioned start record.

`SaveArchivePruneInventoryFile` validates both pins before publication, requires an
existing dedicated operator-controlled parent, syncs a private temporary file and
uses a no-replace hard link. Exact retries verify the same opened regular inode's
bytes and sync the file and parent. A conflicting package, corrupt/truncated file,
symlink or missing parent fails without replacement. Concurrent equal publishers
converge; different publishers cannot both claim the same name. An interruption
after linking can leave a complete destination with unconfirmed durability; retry
only the exact prepared package and pins. Process kills can leave orphan temporary
names; the loader never promotes or interprets them, and no broad cleanup runs.

`LoadArchivePruneInventoryFile` is bounded and read-only. It checks the independently
expected inventory ID before decoding and the mode-specific policy ID afterwards.
Neither save nor load opens or changes an executor, authority, database or replica.
A historical package may still load after a ticket has completed or receipts have
expired. This does not make those tickets pending again or receipts fresh, and
does not mean that the co-signed entries were durably admitted at any time.

The directory must remain controlled and inputs must not be concurrently mutated.
Content pins and fsync do not prove independent failure domains, latest-owner state,
physical durability, copy fencing or a unique approved inventory. Colocated
execution binding, historical lineage retention and colocated secondary admission
are described below. Explicit secondary completion is also available locally;
reviewed multi-owner CLI handoff remains open. Execute, Recover, completion and
network paths retain their own live/outcome checks; the package alone is no grant.

## Explicit secondary admission

`PruneExecutor.AdmitPreparedArchiveSecondary(ctx, primary, secondary, inventoryPath,
inventoryID, policyID, entry)` submits **one** already co-signed secondary candidate
from the retained package. It requires a storage-bound pinned executor with its
primary admission already independently confirmed, the exact original primary
coordinator, and one original selected secondary coordinator. The supplied entry
must equal that secondary's packaged entry byte-for-byte. Its OperationID stays
the **original primary request ID**; rewriting PruneRequest.AssignmentID would
create a different operation and is rejected. The package may be prepared before
the secondary is actually admitted: signed candidates alone are not permissions.

For the first secondary intent, the executor must still be PruneAdmitted and the
primary's exact ticket must be pending under its live guard. A primary already
Stopping may drain that admitted work; this does not bypass the secondary's own
phase/head checks. The method locks executor first, then the two coordinators in
immutable assignment-ID order, and holds all three through inventory re-sync,
secondary intent, authority decision and independent confirmation. The existing
dedicated inventory parent and all six owner roots must be disjoint. Missing or
changed inventory is not reconstructed. No secondary write precedes this check.
An unrelated retained secondary attempt blocks the call; there is no head refresh,
resigning, bootstrap, batch admission or automatic fallback.

An exact retained secondary intent can be explicitly resumed even after primary
drain or executor cancellation/success; a confirmed decision can be retried as
history after secondary completion/retirement. These branches do not create a
different signed attempt or authorize execution. `Commit.Appended` can still be
true when an old retained intent had not reached the authority decision before
the crash. False identifies an exact historical decision, not current permission.
Pending executor transitions must be recovered separately before either branch.
If the executor already has an inventory-bound start, only that exact inventory
is eligible; a different package cannot retroactively relabel it. Neither branch
proves that the old admission originally passed through this API.

There is no atomic all-secondary admission: earlier successful calls remain
retained if a later target fails. Keep each exact attempt and its independent
owner journal; do not delete/replace partially completed preparation. The method
never changes executor history, queries WorkChain, verifies live archive freshness,
opens replicas/lineages, executes deletion, or completes any ticket. Successful
admission only supplies one prerequisite to `ExecutePreparedArchive`, which still
checks the full assignment set, all original owners, storage pair, placement,
lineage/replay and final live policy. Other secondary roots and physical/copy
fencing are not owned or established by this two-coordinator call. Trusted exclusive
local ownership remains mandatory. No command/server/delivery route is silently
upgraded; secondary signing/transport/CLI remain gated.

## Explicit secondary completion

`PruneExecutor.CompletePreparedArchiveSecondary(ctx, secondary, inventoryPath,
inventoryID, policyID, entry)` submits one externally consumer-signed and
authority-co-signed Complete entry. The exact target admission must be selected
by the independently pinned inventory and present as a full operation in the
target's actual history: assignment, ticket, consumer, original primary request
ID and Prune purpose. A packaged candidate that was never admitted cannot drain.
The submitted entry must use that consumer, authority and ticket and the retained
primary outcome's ID as EvidenceID. Completed operations accept only the exact
historical completion and evidence. The target's compare-and-append checks still
decide current, retained, conflicting and historical requests.

The pinned storage-bound executor must have independently confirmed its terminal
record before this call. Success requires the **exact inventory ID retained in
the original version-1 Started record** and the matching effect. Supplying an
inventory after a version-0 success cannot add that provenance. Unresolved Started,
missing outcomes and pending executor transitions are rejected; use the separate
reviewed executor recovery first. Neither a database query nor absence of an
effect can substitute for this terminal history.

A confirmed pre-start cancellation uses its original primary request ID, primary
ticket and executor-pair binding. Cancellation records do not contain an inventory
ID: the supplied pinned inventory selects the secondary ticket to drain, and the
method does not certify that this inventory was used before cancellation. An
actually admitted secondary can be completed even if its exact retained admission
was reconciled after cancellation. This follows the existing trusted exclusive
executor contract; it does not assert global absence of effects from copied owners.

The method locks executor then target coordinator and retains both guards while
checking history, placement, exact package re-sync and the completion's durable
intent, authority decision and independent confirmation. The inventory parent
and all four owner roots must be disjoint. Missing/changed inventory is never
recreated. The primary coordinator and other secondary owners may be closed or
already drained: each completion is explicit and concerns only its own target.
Stopping targets may drain, and exact historical retries remain readable after
retirement. Unrelated retained target attempts require separate recovery.

An error may leave the same retained completion attempt or decision. Preserve
the entry and retry exactly after required reopen/recovery; a later open submits
nothing. Cancellation before the authority decision preserves uncertainty as
appropriate; once a decision is durable the existing coordinator completes its
independent confirmation. Each target is completed separately, so earlier results
survive a later target failure. There is no atomic whole-set completion.

Completion keeps executor history and database/replica contents unchanged. It
does not replay archive bodies, refresh receipt time, sign commands, choose a
new head, query WorkChain or re-execute deletion. Existing request, inventory,
start, authority, effect, cancellation and terminal encodings stay unchanged.
Retain independently protected owner roots, package and pins; the local journal
outcome is not a portable remote certificate. Operator signing/delivery and CLI
ownership remain separate plan gates.

## Inventory-bound execution and local inspection

`PruneExecutor.ExecutePreparedArchive` loads the already retained package using
both external pins. It accepts the existing local owners and replica directories;
the package's mode selects full initial-only or full lineage verification. In
initial mode, supplied lineage evidence is rejected rather than ignored. In
lineage mode, complete bounded prefixes are still mandatory, including empty
prefixes with their initial manifest/receipt/policy where appropriate.

Every live `RequiredOperation` must match the **exact ticket ID** of the package's
co-signed admission, not just its assignment/request/consumer. A different signed
candidate cannot borrow a real current ticket. Replica receipts must match the
package's exact bundle. Caller ordering of owners/replicas is irrelevant; strict
retained package ordering remains unchanged. The executor's original primary
admission and both storage-pair pins must still match.

All original authority guards remain held through complete archive/lineage replay,
availability publication, re-sync of the exact retained package, final live-time
checks, start, effect and result confirmation. The inventory has its own existing
parent, disjoint from every owner, database, replica and availability-evidence
root. Re-sync does not reconstruct a missing package from cached input. Changed
or missing content fails before start. A pre-existing database effect under the
ticket is rejected before replay and checked again before start; a cached
`Applied=false` primitive result is never returned as new prepared execution.

After verification, the new path publishes `OMCPSTRT`, version u16 **1**, followed
by the fixed request ID, primary ticket ID and inventory ID: 106 bytes total.
The normal pin-intent → executor record → pin-confirmation protocol covers those
exact bytes before any effect. Existing position hashes consequently commit the
inventory ID without a new hash domain. Only this verified opt-in path supplies a
nonzero inventory ID. Ordinary Execute/ExecuteArchive/ExecuteArchiveWithLineage
keep their exact 74-byte version-0 start format. Raw or storage-unbound journals
cannot accept an inventory-bound start. Old readers reject version 1; downgrade,
rewriting old records or attaching provenance to an old result is unsupported.
Requests, package format, authority signatures, database effects, completion
records and consensus encodings remain unchanged.
The start commits the package's mode, policy, selected receipts and tickets; it
does not embed or publish the supplied lineage bodies. Retain those independently
for later full verification. Bounded lineage-body preparation remains a next step.

`PruneExecution.ArchiveInventoryID` exposes the retained binding. A start intent
can be pending while the executor still reports Admitted; raw Snapshot diagnostics
must not be mistaken for confirmed provenance. `InspectArchiveInventory` loads
the externally pinned package and checks a fully confirmed local executor prefix
and its pair binding. It refuses pending transitions and old unbound starts/results.
It returns **Started** for an unresolved attempt and **Succeeded** only with the
confirmed exact executor effect record. Repeated inspection does not query or
modify the database, replay evidence, refresh time or change an authority.

Existing explicit recovery retains the original version-1 bytes: resuming a
pending start leaves Started and never executes; positive effect recovery may
retain an already committed matching result while preserving the inventory ID.
Absence remains unknown. Neither recovery nor completion can retrofit a binding
into a version-0 start. No authority ticket, including a secondary one, is
automatically completed.

This is **local journal provenance under the existing trusted, exclusive-owner
contract**, not a portable certificate that arbitrary software verified the
archive, or proof of the current database/replica state. Keep the package and its
independent pins alongside the independently protected owner roots. No raw owner
or copied executor/database may concurrently produce effects outside the managed
runtime. Shared rollback, malicious local file rewriting, copied owners and
physical failure-domain independence remain outside this guarantee. Supervised
operator handoff, remote acceptance, secondary tooling and activation remain gated.

## Retained historical lineage bodies

`PrepareArchivePruneLineageEvidence(ctx, inventory, inventoryID, policyID, lineages)`
requires an independently pinned **lineage-mode** inventory, checks the shared
1,024-entry / 256 MiB manifest-plus-entry budget before copying and reorders by its
exact assignments. It fully verifies each prefix, its original receipt/custody
policy and exact selected terminal receipt. Empty and mixed initial/renewed prefixes
are supported; an initial-only inventory is not silently switched to lineage mode.
The result is opaque and immutable. `ID()` supplies the evidence ID to review and
retain independently; `Lineages(ctx)` returns fresh detached copies, never internal
buffers. Preparation does no filesystem I/O and opens no owner or live journal.

`SaveArchivePruneLineageEvidenceFile(ctx, path, evidence, evidenceID)` publishes
without replacing an existing file. It streams to a private 0600 temporary file,
syncs it, hard-links the final name, verifies the exact bounded stream ID, then
syncs the same file and its parent. Exact retries use the existing inode. Failed
or cancelled calls after publication may leave a complete file: inspect with the
same external pins and retry exactly. Crash-left temporary files are never promoted
or automatically deleted by retries. The parent must already exist, be dedicated
and remain operator-controlled; symlink final files/parents are rejected.

`LoadArchivePruneLineageEvidenceFile(ctx, path, inventory, inventoryID, policyID,
evidenceID)` requires all three independent pins. It checks the file size and
stream hash **before allocating lineage bodies**, then bounds every field/count
before allocation, decodes, fully verifies all prefixes and checks canonical
re-encoding against the same evidence ID. It opens the same regular inode read-only
and checks file/parent identities. Concurrent mutation of inputs, files or their
parent is unsupported. Stream hashing/read/write check cancellation in 64 KiB
chunks; signature verification remains bounded per existing journal entry.

The local v0 envelope is `OMCPLEVD`, big-endian u16 version zero, fixed inventory
and policy IDs, and a u16 lineage count. Each ordered lineage contains its fixed
assignment ID, u32-length canonical manifest and initial receipt, three u64 custody
policy timing values, u16 auditor count and fixed keys, then u16 entry count and
u32-length canonical entries. Zero-length bodies, unsupported versions, trailing
bytes and noncanonical inner objects are rejected. The total file cap is 256 MiB
plus 256 KiB framing/metadata; the latter **does not enlarge the body budget**.
The ID is SHA-256 of `OMESH/custody-prune/lineage-evidence/id/v0` followed by the
exact envelope stream. No second full-envelope buffer is required for file I/O;
decoded bodies and explicit caller copies are still bounded in-memory values.
The frozen two-replica, one-renewal-each test vector has evidence ID
`9052483c729475add9d271a7039be21d6740a492f9d52a55b83e625a7326efca`.

For library execution, load the evidence against the same inventory/policy pins,
obtain `Lineages(ctx)` and pass them to `ExecutePreparedArchive`. That existing
adapter independently re-verifies them under all live authority guards. Preserve
the file and all pins outside owner/replica roots. **This is preparation/retention,
not a new file-backed execution contract:** the adapter does not own/re-sync this
file, and version-1 Started commits the inventory ID, **not the evidence file ID**.
No inventory, request, start, effect, authority or consensus encoding changes.
The file proves neither latest/unique journal head, historical Audit admission,
current pending authority, physical durability, successful execution nor cutover.
It remains historically readable after a ticket completes; it cannot authorize a
new execution in that state. No journal extraction, CLI or activation is added.

## One synchronous execution

1. Check healthy, fully confirmed executor state and the external policy ID.
   Detach bounded policy, owner and replica slices before waiting on owners.
   Only Admitted enters; pending, Started and terminal states cannot become a
   new live execution.
2. Require one already admitted Prune ticket per selected assignment, all naming
   the original request ID and consumer. The primary ticket must equal the
   executor's retained signed admission.
3. Lock all original coordinators in **immutable construction-assignment-ID order**.
   Input order is irrelevant; relabelled owners are rejected before locking.
   Check every fully confirmed current pending ticket under all locks. Stopping
   permits already admitted drain; unconfirmed, Completed and Retired do not.
4. Require the matching storage incarnation, independently pinned pair and no
   unresolved database position. All authority/executor roots, original database
   roots, replicas and the existing dedicated evidence directory must be disjoint.
5. Fully replay every replica against the exact checkpoint and policy. Compare
   the computed floor and availability ID to the retained request **before evidence
   publication**. Preserve its original VerifiedAt, which cannot be in the future.
6. Publish/reuse the exact immutable bundle and recheck live freshness/cancellation
   before retaining and independently confirming Started. Inside WorkChain's
   prepared deletion batch, after database-intent I/O, sample wall time again.
   Backward time, expiry, short retention or cancellation deny the commit.
7. Commit the original ticketed effect with deletion, confirm the independent
   database position, then retain and confirm the executor result. Keep **all**
   assignment locks until this final result boundary has drained.

Lock order is executor → coordinators in assignment-ID order → WorkChain.
Close/Stop/Complete cannot cross the guarded effect. No callback acquires another
coordinator. Inputs must not be concurrently modified at call entry; replica files
must remain immutable throughout. Local locks do not fence copied roots or keys.

`workarchive.VerifyCanonicalPruneRequest` supplies shared full-replay/exact-floor
verification and a synchronous live `Authorize` check, not current assignment
permission. It never executes work. The older standalone archive gate shares the
underlying verification path but does not acquire authority guards. `StorageRoots`
is read-only placement information, not physical identity or independent durability.

## Failure, recovery and completion

Wrong/incomplete policy, assignment, ticket, storage pair or replica fails before
a new start. Evidence may survive a later failure and is never a retry permit.
A retained Started is not cancelled or re-executed, even if no database result is
currently visible. A failed final check after a database intent can leave an
unresolved storage pin; existing explicit recovery rules still apply.

`PruneExecutor.Recover` may retrieve an already committed exact effect without
deleting again. Incomplete executor records require separate reviewed intent
recovery. Repeated ExecuteArchive after a terminal state fails, instead of
presenting cached historical evidence as live acceptance.

**No authority ticket is automatically completed**, including secondary assignments.
Existing atomic effect/terminal formats identify the primary request and ticket;
they are not portable certificates of every secondary permission. Colocated
secondary admission and explicit completion are available above. Operator signing,
delivery and reviewed multi-owner handoff remain open.

## Evidence and remaining gates

Tests exercise real two-replica replay and deletion on a position-pinned database,
independent confirmations and still-pending authority tickets. They reject wrong
sets/owners/pins/policy/receipts/placement, hold the secondary authority through
replay/start/effect/result confirmation, and cover reversed lock order, detached
inputs, Stopping drain and cancellation before/after Started. Six process kills
span pre-replay, post-evidence, Started/no effect, committed effect, pending result
confirmation and confirmed result. Reopening twice never advances execution.
The renewal mode adds seven process kills, including after full lineage
verification, alongside gap/substitution/policy/budget rejection, cancellation,
input detachment and real deletion with multiple renewals on two replicas.
The preparation package adds both-mode roundtrips, a frozen codec vector,
substitution/framing/pin rejection, equal/conflicting publication races and five
process kills around file sync/link/directory sync. Its historical readability
never bypasses a completed secondary ticket at the existing live adapter.
Inventory-bound execution adds exact-ticket/receipt matching, old-result refusal,
package re-sync under all guards, cancellation, retained intent recovery and
one-root downgrade rejection. Nineteen process kills (nine initial, ten lineage)
cover the existing stages plus package re-sync and both sides of start publication;
repeated reopen/inspection does not promote pending or unknown state.

Historical lineage retention adds empty/mixed/renewed-prefix execution, detached
buffers, wrong-pin/body/framing/budget rejection, equal/conflicting publishers,
cancellation, a frozen canonical vector and five publication process kills.
Loading retained bodies never bypasses a completed secondary admission.

Secondary admission adds real initial/lineage-mode execution after admission,
first-intent rejection after primary drain, exact recovery across cancellation,
historical retry after retirement, concurrent duplicate suppression, guarded
publication, inventory re-sync rejection and unchanged executor/database checks.
Fault injection spans all 21 intent/authority/confirmation publication boundaries.
Thirteen process kills cover eight first-attempt and five retained-retry boundaries;
opening twice never submits or confirms the secondary attempt.

Secondary completion covers both outcomes and both initial/lineage modes,
completion with primary/database closed, target Stopping/Retired history, signed
scope and actual-admission checks, legacy/unresolved/pending executor rejection,
package mutation, eight concurrent retries and exact admission reconciliation
after primary cancellation. Fault injection covers all 21 publication stages for
each outcome (42 cases). Twenty-six process kills cover eight first-attempt and
five retained-retry boundaries for each outcome; repeated opens preserve the
executor, primary, database history/effect and exact secondary uncertainty.

Still required: reviewed live-journal extraction, operator signing/delivery,
supervised ownership handoff, actual managed audit/serve
paths, cross-host/partition acceptance, copied-owner and physical-storage fencing,
exhaustion/power-loss/long-soak campaigns, independent review and public testnet.
Older raw library APIs and experimental CLI are not silently upgraded into this
managed acceptance boundary.
