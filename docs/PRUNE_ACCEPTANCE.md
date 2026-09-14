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
not from whatever configuration the runtime happens to read. No policy bootstrap,
persistence, migration or hot-reload command is provided. Retain that configuration
and its external pin for later operator review.

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
is no evidence extraction/publication CLI, new portable evidence format or new
automatic recovery. Prepare and retain the exact bounded evidence independently;
operator evidence/inventory tooling remains open.
The unchanged primary effect record alone does not certify use of this lineage
mode. Historical recovery does not retroactively verify it; protected inventory
for later policy/operation provenance review remains a separate requirement.

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
they are not portable certificates of every secondary permission. Typed secondary
admission/completion tooling, retained policy-to-operation inventory and reviewed
multi-owner handoff remain open. Raw signed Complete is not a substitute for the
missing secondary terminal adapter.

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

Still required: bounded lineage evidence preparation, protected policy/operation inventory and secondary
terminal adapters, supervised operator ownership handoff, actual managed audit/serve
paths, cross-host/partition acceptance, copied-owner and physical-storage fencing,
exhaustion/power-loss/long-soak campaigns, independent review and public testnet.
Older raw library APIs and experimental CLI are not silently upgraded into this
managed acceptance boundary.
