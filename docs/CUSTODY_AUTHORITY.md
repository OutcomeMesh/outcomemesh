# Custody acceptance and cross-host cutover boundary

Status: bounded reference admission/drain machine in `node/custodyauthority`,
local durable history and an independently retained intent/pin coordinator in
`node/custodyauthority/store` are implemented. WorkChain also has a trusted local
ticketed-prune result primitive. Network authority, consumer enforcement and
active rebaseline are not installed.

Local retirement serializes upgraded participants using the named journal
roots. It does not invalidate a previously extracted Ed25519 key, a copied
unretired journal, an old binary, or a receipt already delivered elsewhere.
A verifier supplied the old trusted keys can still verify those signatures.
This is why another signed retirement file, by itself, is not a global fence.

## Acceptance paths

| Path | Current enforcement | Required before active cross-host cutover |
| --- | --- | --- |
| Auditor challenge creation, result publication, journal append and artifact recovery | CLI holds artifact lock then active journal decision scope for the whole cycle | Bind the whole live operation to the current assignment; recovery must not promote historical validity to current acceptance |
| Replica fresh, cached and restart-recovered responses | Journal-backed sessions hold their current decision scope through response and stream retirement | Reject retired assignments even with copied keys/journals; drain operations admitted before retirement |
| Raw/record-backed sessions and signing helpers | Signature, binding and timing checks; no journal retirement guard | Remain ineligible for managed cutover or require the same authority protocol; no silent fallback |
| `CustodySession.Audit` live result acceptance | Rechecks returned renewal at current time under static keys | Hold a current assignment decision through durable acceptance, not just transport identity |
| `workarchive.PruneCanonicalPrefix` destructive maintenance | Full replica replay, static trusted keys, immutable evidence and final in-batch time/cancellation check | Hold current assignment authorization through storage transition; reject retired receipt keys regardless of their signatures |
| `workchain.Store.PruneCanonicalPrefix` low-level primitive | Chain ancestry, retained-depth policy and atomic persistence | Remain a trusted internal primitive; never expose it as a command bypassing archive/authority policy |
| Codecs, journal replay, pinned backups, historical application | Canonical signatures and exact historical links; explicit observation times where applicable | Keep historical verification independent of live authority so retirement does not destroy auditability |

`PruneCanonicalPrefixAuthorized` provides the final bounded callback inside the
prepared WorkChain batch. It is used for live freshness and cancellation, not
distributed revocation: the caller still supplies static replica policy, and
no policy-generation identifier has entered receipts. Reading mutable authority
once before the method, or inside its callback without a guard held through
completion, cannot establish ordering against a concurrent retirement.

### Implemented atomic local prune result

`workchain.Store.PruneCanonicalPrefixOnce` takes a `CanonicalPruneOperation`:
assignment ID, admission ticket ID and the exact requested `CanonicalFloor`,
including its initial `VerifiedAt`. The requested floor must not already contain
a `PruneTicketID`. These unsigned fields are caller-provided bindings, **not an
admission proof**. The method does not contact the authority, verify a signed
ticket, retain a consumer's pre-execution intent, or close an authority operation.
No existing CLI or live archive acceptance path calls it yet.

Under the chain's write lock, a new operation validates the same chain-local
ancestry and retention conditions as ordinary pruning, then prepares one Pebble
batch containing the deletion, retained state/floor, original operation/result,
byte accounting and optional schema upgrade. The bounded final authorization
callback still runs after all preparation. Its final time enters both the floor
and result; only fixed-width fields change before synchronous commit. The floor
gets the result's ticket ID in that same transaction. A successful return waits
for both persistence and the corresponding in-memory floor/index transition.

The result preserves the original removed/retained counts and byte accounting,
not a refreshed report about the current chain. Exact retry returns
`Applied=false` and those retained bytes without invoking authorization, deleting
anything or refreshing time. Different parameters or assignment under the same
ticket are rejected. Later ticketed or ordinary pruning, checkpoint rotation and
fork maintenance do not delete the result. `CanonicalPruneEffect(ticketID)` is a
read-only lookup, including after restart; an unknown ticket executes nothing.

Each effect is a bounded version-0 `OMWCPREF` envelope containing two 32-byte IDs,
a canonical length-prefixed requested floor, final time, and fixed-width report.
Its evidence ID uses `OMESH/workgraph/canonical-prune-effect/id/v0`. The golden
fixture is 490 bytes with ID
`31be0ab8508b95f9f49708ad5c18d2c28300354873e778ad9a1a8e85f044bd99`.
The maximum is 1,024 bytes per result and 65,536 retained results per database;
result keys/values count toward `MaxHistoryBytes`. Exhaustion rejects new
ticketed effects, not old result lookups. There is no result garbage collection,
reset or automatic ticket release; runtime admission must account for capacity.

Existing schema-4 stores/floor-v0 bytes are unchanged until the first ticketed
prune. That transaction opts the database into WorkChain schema 5, adds result
keys under `0x15 || ticketID`, and writes floor v1 with a nonzero ticket suffix.
This schema does not downgrade when later ordinary pruning writes a v0 floor.
Older schema-4-only binaries reject it instead of silently ignoring result
history. There is no automatic migration of unrelated databases or consensus,
receipt, authority-command or peer-wire format change.

Reopen replays the ordinary chain, checks bounded result shapes and key/binding
identity, exact logical-byte accounting, canonical anchor/previous-floor
positions, nonoverlapping prune intervals, and the latest result-to-floor link.
Historical external custody claims are not re-attested by this inspection.
An uncertain canonical commit returns no result and disables subsequent public
chain reads/writes until close and successful reopen; pre-commit denial leaves
the healthy old state untouched. Pebble's normal read/write recovery flushes
replayed WAL data before returning its handle. Tests cover both absent and
written outcomes of a failed commit result, malformed recovery, concurrent
retries and four additional process kills: prepared batch, final decision,
post-sync/pre-return, and an unsynced WAL attempt. The last case permits either
whole transaction, never a mixed floor/deletion/result/schema state. These are
process-death tests, not physical power-loss certification.

This primitive provides effect identity only within the intact owner-controlled
database. It cannot detect rollback or replacement of the entire store.
Missing schema metadata in a nonempty database is rejected, never reinitialized.
`OpenWithPolicy` still supports explicit database creation, so an empty newly
created database is not evidence that a previous effect never happened. A managed
consumer must retain its exact request independently, bind recovery to its
original storage and authority history, and keep the ticket pending until its
last effect has drained. Finding a result does not authorize another effect;
not finding one does not authorize a retry or a no-effect completion. Auditing,
serving and authority completion transport remain separate runtime gates.

## Implemented reference kernel

The version-0 kernel operates on one independently pinned immutable assignment.
It binds network/genesis/activation/base, manifest, statement, initial receipt,
custody policy, a separately selected incarnation ID, evidence roles and the
closed consumer-control-key list. `CreateCustodyAuthorityAssignment` checks the
archive/receipt/policy binding without claiming current availability. Changing
any binding, membership or limit changes the assignment ID. This bootstrap
format has no successor activation or membership-update operation.

Consumer control keys must be distinct from the authority key, replica evidence
key, every auditor key and each other. Each consumer has explicit `Audit`,
`Serve` and/or `Prune` purposes. Declared coverage must include all three, but
this does not prove the operator enumerated every real accepting deployment.
Unknown consumers and evidence keys cannot request admissions or close tickets.

Commands carry the exact assignment, expected sequence and expected head.
Consumers sign admission/completion commands; the assignment authority signs
stop/retire commands. Every accepted history entry also requires that pinned
authority's co-signature, in a separate domain. The first predecessor is the
assignment ID. Compare-and-append rejects stale or forked entries; neither
validation nor rejection changes state. This is one logical ordered authority,
not a replicated/BFT implementation or protection against a signing authority
that equivocates across independently forked stores.

| Command | Allowed effect in the reference machine |
| --- | --- |
| `Admit` | Only in `Accepting`; allocate one ticket for a permitted consumer/purpose and a never-before-admitted consumer operation ID |
| `Complete` | Only the admitted consumer can close its still-pending ticket, in `Accepting` or `Stopping`, with a nonzero terminal-effect/disposition commitment |
| `Stop` | Move `Accepting` to `Stopping`, preserving one signed stop-intent reference; reject every new admission from then on |
| `Retire` | Move `Stopping` to terminal `Retired` only with the exact stop entry ID and zero pending tickets |

No timer, cancellation, disconnect, missing response or replay closes a ticket.
There is no force-complete, resume, key-replacement or activation transition.
An unresolvable consumer can therefore block retirement indefinitely. The next
runtime layer must define safe evidence-backed recovery of that consumer; it
must not invent an expiry to restore availability. A completion commitment is
an assertion by the trusted consumer, not proof that its code has actually
finished every effect. The runtime adapter must enforce that ordering before
signing it and must prevent duplicate execution after a lost response/restart.

Limits are part of the assignment: up to 65,536 total admissions and 1,024
pending tickets, with 1–64 auditors and consumers. Completed operation IDs remain
retained, preventing reuse and keeping memory bounded. Admission exhaustion
does not consume completion/stop/retire capacity: the maximum accepted history
has `2 * MaximumOperations + 2` entries. It is not automatically compacted or
reset. `LookupOperation` distinguishes unknown, pending and completed work but
returns only a detached observation, never a reusable permission.

`Replay` requires independently retained assignment and exact sequence/head
pins. It rejects even a valid shorter prefix, or an extension beyond the selected
pin. Replaying an outstanding ticket leaves it outstanding; no snapshot import
exists. A historical pin still cannot prove there is no later remote stop.
`NewState` is bootstrap only, never a fallback when history is missing.

The kernel stays deliberately in-memory. `ValidateNext` followed by `Apply` is
not an external transaction, and a signed `Entry` is not a live grant. The
separate store described below owns that serialization and durability boundary.
A current-authority transport and per-consumer durable operation protocol must
still hold admission through the last acceptance effect. No existing custody
session, journal, pruning command or receipt parser consumes these entries yet.

### Canonical reference vectors

`TestAuthorityCanonicalGoldenHistory` freezes a 451-byte assignment, two
admissions, stop, two completions and retirement. Commands are exactly 276 bytes;
co-signed entries are exactly 382 bytes. Assignment bytes are bounded at 8 KiB.
Unused command fields, trailing bytes and unknown versions/kinds are rejected.
These are operational fixtures, not a consensus or peer-wire upgrade.

```text
assignment = 0a971f736838505235eef8d8f342e3370e574681f71cc3c3f033b459e40b9931
ticket_1   = a9054c2e49821a3dbe12bee0fced4616c2b7c211ef71ef52c99477643998cb6d
stop       = d8fb8af2bce85728f50eae473d9f1889927bfbd0742d61336b6ab4041d681779
retirement = 4ef0bac9e865e9b107fca609ed9c0134dcce41db3e094d4890ccac97347b9586
```

The signature domains are `OMESH/custody-authority/command/signature/v0` and
`OMESH/custody-authority/entry/signature/v0`; assignment and entry IDs have
separate `/id/v0` domains. Existing receipt, challenge and proposal signatures
and formats are unchanged.

## Implemented local durable history

`node/custodyauthority/store` wraps the unchanged reference machine without
introducing filesystem, transport or clock dependencies into the kernel. The
adapter accepts already co-signed entries; it neither holds signing keys nor
exposes a network service. Its private state cannot be mutated around storage.

```text
authority/
  authority.lock                  permanent, empty kernel-lock inode
  assignment.omcaa                 exact canonical assignment
  ready.omcas                      final version-0 initialization envelope
  entries/0000000000000001.omcae    immutable, contiguous entry files
  pending/entry-<decimal>          bounded uncommitted/crash leftovers
```

`Create` is explicit bootstrap of a new root under an existing parent. It
requires an independent assignment pin and refuses any existing root, including
an empty or partially initialized one. The 42-byte readiness envelope is
`OMCASTOR`, two zero version bytes, and the assignment ID. Its dependencies are
synced before it is published; readiness is not an authority entry or a permit.
Failed initialization remains inspectable. No missing marker, lock, directory
or assignment is automatically recreated by `Open` or `Recover`.

A successful handle owns the permanent kernel lock until `Close`; another
process or handle receives `ErrBusy`. An internal mutex covers the entire
validation/publication/apply decision, including exact retries and snapshots.
Closing or killing the process releases ownership without unlinking the lock.
Detecting replacement of a retained root/control inode poisons the old handle.

Each new append proceeds in this order:

1. Check the exact predecessor, signatures, roles, phase and operation limits
   under the serialization guard. Rejection publishes no history.
2. Write a fresh bounded temporary file and sync its contents.
3. Recheck cancellation, then hard-link it to the next immutable sequence name
   without replacing anything. No mutable head file needs a second commit.
4. Sync the entries directory, apply the already validated transition, and only
   then return a successful durable result. Cleanup of this attempt's temporary
   link is best-effort and cannot undo the committed record.

Cancellation before publication leaves the previous history current; after
publication the durability decision is no longer cancellable. A write,
publication or required-sync failure returns no result and poisons the handle,
even if the entry is visible on disk or already applied in memory. Snapshot and
append then fail with `ErrUncertain` until the handle is closed and history is
recovered. A failed cleanup can leave only the already committed temporary link;
it does not change the operation's outcome.

`Open` requires independently retained assignment and **exact** sequence/head
pins. It scans bounded canonical history, replays every transition, and rejects
shorter prefixes, forks, gaps, unexpected files and extensions beyond the pin.
It re-syncs accepted files and directories before returning a handle, so a
previous failed sync cannot be mistaken for durability just because bytes can
be read. Empty history is valid only for an initialized store pinned to the
assignment's sequence-zero position; missing history is never bootstrap.

`Recover` resolves one lost/uncertain append using an independently retained
pre-attempt position **and the exact co-signed attempted entry**. It accepts
only the pinned prefix or its one-entry extension by that candidate. It first
replays the old pin and validates that the attempt was admissible there. It
never publishes the attempt, chooses a different head, accepts a longer suffix,
or closes unresolved work. The caller can then retry `Append` exactly.

An exact previously committed entry returns `Appended=false` with its original
ID and a detached snapshot of the **current local state**, including later stop,
completion or retirement. Different bytes at that sequence are rejected. A
freshly signed reuse of an operation is still rejected by the reference kernel.
This resolves history identity, not consumer execution: neither a commit result,
an old admission nor a snapshot is a reusable permission to perform an effect.

The maximum history remains `2 * MaximumOperations + 2` entries (at most 131,074
files of 382 bytes). Pending files are separately capped at 128, each at most
382 bytes; partial or fully signed temporaries are retained but never promoted.
Exhausting that evidence budget blocks new writes, including drain writes, until
an explicitly reviewed recovery/maintenance procedure is available. No automatic
cleanup, compaction, reset, successor activation or missing-history fallback is
implemented. Logical bounds do not guarantee free inodes, physical space or
filesystem latency.

Unit tests cover exact replay/retries, retained pending operations, initialization
failure, malformed and substituted files, symlinks, replaced ownership inodes,
bounded leftovers, cancellation, I/O-failure poisoning and concurrent same-head
writers. `make test-process` adds 45 actual child-process kills: seven append
boundaries for each of six admission/drain transitions, plus three initialization
boundaries. Tests also check live cross-process exclusion and replay through the
original terminal retirement after every crash. These are local process-death
checks, not power-loss, hostile-filesystem or cross-host partition certification.

Deployment must provide owner-controlled stable paths and a local filesystem
with working kernel locks, hard links and file/directory fsync. Same-inode hostile
edits and unsupported/shared filesystems are outside this adapter's guarantee;
unsupported locking or required sync errors fail closed. Runtime tests currently
exercise macOS, not every platform build. Pins and pending attempts must be kept
independently of the authority root. The raw `Store` API does not persist them;
the optional coordinator below supplies their separate journal, not its physical
failure domain. A rolled-back pin and root can still agree,
and a copied root/key can still fork. No automatic selection of the latest remote
authority, high-availability replication, backup service, lease or fencing token
is installed by this store.

## Implemented retained intent and pin coordinator

`CreateCoordinator` attaches a new intent journal only to an existing initialized
sequence-zero authority under the independently trusted assignment ID. It cannot
derive a new bootstrap pin from an already used authority or replace an existing
or incomplete journal. Missing authority storage remains an error. Readiness is
published only after the authority's exact initial position has been verified
under its process lock. This is an optional local library, not a running daemon.

```text
intent-journal/
  intent.lock                     permanent ownership inode, acquired first
  assignment.omcaa                exact canonical assignment
  ready.omcai                     distinct intent-journal readiness marker
  intents/0000000000000001.omcae   exact co-signed attempted entry
  confirmed/0000000000000001.omcap independently retained confirmed position
  pending/entry-<decimal>         bounded temporary evidence, never promoted
```

The journal is not an authority store: its readiness magic is `OMCAINTS`, followed
by two zero version bytes and the assignment ID (42 bytes). A confirmation is
`OMCACONF`, two zero version bytes, assignment ID, big-endian uint64 sequence and
entry/head ID (82 bytes). Confirmation bytes must exactly match the corresponding
fully replayed signed intent. These local envelopes are unsigned operational
records, not consensus objects, network proofs, receipts or execution permits.

The coordinator owns both writers privately and serializes calls under one
mutex. Lock acquisition is always journal then authority; ordinary close releases
authority then journal. Root equality, containment, symlinks and known ancestor
aliases are rejected before creating files, including case-insensitive aliases.
Both roots remain protected against a second cooperating process for the entire
handle lifetime. Separate paths do not prove separate hardware or access control.

Each coordinated append has three durable decisions:

1. Validate the command against confirmed retained history and persist its exact
   co-signed bytes as the next immutable intent. Sync file and intent directory
   before attempting any authority mutation. There is at most one unconfirmed
   intent, and another command cannot replace or bypass it.
2. Submit that exact entry through the already pinned local authority store.
   Check the successful result's assignment, entry ID and exact next position.
   This result comes from the local synchronous store, not an untrusted remote
   acknowledgement supplied through a transport interface.
3. Publish and sync the independent confirmation before updating its in-memory
   confirmed state and returning success. A required I/O failure returns no
   result and makes the coordinator unusable until close and full replay.

Cancellation before intent publication leaves no retained request. Afterwards,
the intent survives cancellation and must be resolved exactly: cancellation is
not an abort record, permission to choose a sibling, or terminal completion.
If cancellation prevents the authority append, the healthy handle can expose
the pending intent and later resume it. Once the authority returns its durable
decision, confirmation publication is no longer cancelled by the caller. Storage
failure still prevents a successful result.

`OpenCoordinator` replays the independently configured journal first, verifies
contiguous intents and confirmations, then selects the authority's expected pin
from that journal. Confirmed history is fully replayed; an optional final intent
is validated but not applied to the confirmed reference state. Both retained
files and directories are re-synced before they are used for authority recovery.
There is no query that installs the authority's own head as its expected pin.

| Retained journal | Authority history | Allowed recovery |
| --- | --- | --- |
| Confirmed through `n`, no pending intent | Exactly `n` | Open without writing history; accept a new valid request or an exact historical retry |
| Confirmed through `n`, exact intent `n+1` | Exactly `n` | Expose the pending intent; explicit resume can submit only that entry and confirm its result |
| Confirmed through `n`, exact intent `n+1` | That exact `n+1` | Expose the still-unconfirmed attempt; explicit resume performs exact lookup and confirms the durable result |
| Confirmed through `n+1` | Exactly `n+1` | Open at the confirmed pin; a lost-response retry is lookup, not another admission |
| Any confirmed prefix | Shorter, forked, corrupted or unexplained longer history | Fail closed; never reconstruct confirmed missing decisions from intent bytes |

Opening does **not** submit an intent or publish a confirmation. `Snapshot`
returns detached `Confirmed`, `Pending` and observed `Authority` fields so a
caller can distinguish these states. `Resume` acts only on the retained attempt;
retrying `Append` with exactly that entry has the same effect. There is no abort,
force-complete, abandonment timeout, reset or alternate-attempt selection. After
confirmation, exact historical retries return current local state; they do not
permit a consumer to repeat its previously executed effect.

Each of `intents/` and `confirmed/` is bounded by the assignment's maximum
`2 * MaximumOperations + 2` history length. Intent files are 382 bytes and pins
82 bytes; confirmed records are never compacted away. Temporary evidence has a
separate 128-file, 382-byte-per-file cap. Reaching that cap can block completion
of confirmation as well as a new intent. No cleanup or history repair is
inferred from a need to restore availability.

Tests cover invalid commands/results before pin advancement, cancellation on
both sides of publication, malformed and substituted journal files, retained
intent identity, exact historical retries, full drain capacity, inode replacement,
root aliases and simultaneous writers. In addition to the raw store's 45 kill
cases, `make test-process` runs 129 coordinator kills: seven boundaries for each
of intent/authority/confirmation across six transitions, plus three initialization
boundaries. Reopening twice never submits or confirms work; explicit recovery
continues to the original terminal retirement after every append crash.

This closes the local retained-attempt/pin implementation gate, not deployment
or live acceptance. The operator must independently protect and back up the
journal; shared rollback of both roots can still agree, and copied roots/keys or
an equivocating signer are not fenced. No remote acknowledgement verification,
current-authority transport, consumer effect journal, operational CLI service,
lease, successor activation or automatic cross-host failover is installed.
Audit/serve/prune integration must use the complete protocol without falling
back to a raw store, cached snapshot or historical signature as a live permit.

## Required deployment ordering

1. Establish independently trusted assignment authority and enumerate every
   accepting consumer. Bind network/archive scope, generation, allowed evidence
   roles and policy, and exact predecessor. Do not infer the latest generation
   from candidate receipts or proposals.
2. Serialize the stop decision against admission of old-generation operations.
   Once stopping, admit no new old-generation decision. Preserve the original
   stop identity across crash/retry instead of issuing a new one.
3. Drain every admitted decision through its last observable effect: response
   delivery, artifact/journal publication, or storage commit. A disconnected
   consumer is not presumed stopped merely because it is silent.
4. Commit retirement only when the drain condition is established. A lease
   design must specify bounded clocks/skew, expiry enforcement, restart behavior
   and the point after which a stalled client cannot act. Short-lived signatures
   alone do not establish that condition.
5. Link exactly one activation to the reviewed full-replay proposal, historical
   reconstruction and retired predecessor. Persist the activation choice before
   new-generation effects. Partial activation may reduce availability but must
   not reopen the old generation or admit a second successor.

An online implementation must fail closed when it cannot establish current
authority. A cached signed snapshot proves what was signed, not that a later
retirement has not occurred. Partition-time availability must not be claimed
until the authority and drain protocol explicitly supports it.

This authority is operational custody policy, not a committee able to override
hard-PoW fork choice. The reference format uses one explicit authority signing
key; no hosted coordinator, replication architecture, external service,
consensus rule, real keys, or deployment is installed. The independent failure
domain, durability/rollback guarantees, authorization and distribution remain
architecture and deployment decisions to implement and review.

## Required negative tests

- Valid old/copy/restarted signatures fail at live acceptance once retired.
- A stale, rolled-back or partitioned consumer cannot resume or silently switch
  to an unguarded session when current authority is unavailable.
- Retirement racing a response or prepared database batch produces one ordered
  outcome: the operation drains first, or is denied before its live effect.
  A query/commit gap is not an accepted result.
- Death before/after admission, stop, drain, retirement and activation preserves
  one durable ordering and never selects two active successors.
- Keys, archive binding, policy generation, predecessor and proposal ID cannot
  be substituted; replaying the old generation fails live acceptance.
- Historical records remain replayable without re-dating proofs, resetting
  retention or reopening retired participants.

Existing local lock, retirement, freshness, reference-machine and process-kill
tests are building blocks, not closure of these cross-host gates. Rebaseline proposals
remain inactive; command output continues to report
`global_participants_fenced=false` and `active_cutover=false`.
