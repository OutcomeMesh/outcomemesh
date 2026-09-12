# Custody acceptance and cross-host cutover boundary

Status: bounded reference admission/drain machine in `node/custodyauthority`,
local durable history and an independently retained intent/pin coordinator in
`node/custodyauthority/store` are implemented. WorkChain also has a trusted local
ticketed-prune result primitive, now used by an optional one-assignment local
executor journal, optional independent stage pins and coordinator guard. An
explicit local completion adapter binds externally signed completion to retained
terminal evidence. Network authority, integration into existing live acceptance
paths, and active rebaseline are not installed.

An opt-in, completion-only QUIC endpoint now delivers an already co-signed
command to that original colocated executor/coordinator. It does not distribute
execution authority or install a default daemon service; see its scope below.
A separate one-command client outbox can retain that delivery and its checked
channel acknowledgement across local process crashes. Neither is a live grant.

The separate opt-in admission-only endpoint and its own client outbox deliver
an externally co-signed prune Admit for an already prepared server request.
They retain admission without remotely starting work or installing live handlers.

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

### Implemented local prune executor journal

`store.PruneExecutor` composes a concrete `workchain.Store` with the private local
`Coordinator`; it does not accept a generic effect callback or remote snapshot
as a substitute. This is one trusted, one-assignment library operation, not an
installed archive command. The caller must still perform full archive/replica
verification and provide the bounded final live-time authorization check. One
assignment's pending ticket is not authorization for every replica in a quorum.

`PruneRequest` commits the assignment, consumer control key and exact requested
floor, without a ticket. `CreatePruneExecutor` retains it in a new protected root;
the caller requests admission only after that succeeds. Its ID becomes the
signed admission's `OperationID`, avoiding a circular ticket preimage. Assignment
validation checks the consumer's prune role, base, manifest, statement, activation
height and ancestry count. The bounded `OMCPREQS` version-0 envelope has a 1 KiB
limit and domain `OMESH/custody-prune/request/id/v0`; the 377-byte golden request
has ID `5d1c7f0b6cf71484eee050f5e072b938f0fdb81bebe3a8f68b83ddf5505508ac`.

```text
prune-executor/
  prune.lock                     permanent process-ownership inode
  assignment.omcaa               exact independently selected assignment
  request.omcpr                  exact independently pinned request
  ready.omcpx                    42-byte OMCPINIT/version/request-ID marker
  records/01-admission.omcae     exact co-signed admission, 382 bytes
  records/02-started.omcps       74-byte OMCPSTRT/version/request-ID/ticket-ID
  records/03-result.omcpfx       exact bounded WorkChain prune effect
  pending/entry-<decimal>        at most 128 crash/failed temporary records
```

For the execution branch, the three record names must form an exact prefix;
the pinned cancellation branch below uses a distinct terminal second record.
Dependencies, bindings,
signatures, types, sizes and the final initialization marker are checked on open.
Required files/directories/locks are never recreated. Existing or partial roots
cannot be reinitialized. Accepted records and namespaces are re-synced before
returning a handle; temporary records are retained but never promoted. Each new
record uses file sync, no-replace hard-link publication and records-directory
sync before the in-memory stage changes or a successful result escapes. Required
I/O failure poisons the writer until close/reopen. Live control/record inode
replacement is rejected. Logical limits do not guarantee filesystem capacity.

| Retained stage | Permitted next action |
| --- | --- |
| `Prepared` | Bind the exact admission only after confirming that ticket is currently pending in the local coordinator |
| `Admitted` | Check chain network/activation/base, then persist `Started` under the current pending-ticket guard before calling atomic pruning; independently pinned executors may instead explicitly cancel before any start intent |
| `Started` | Explicit `Recover` may inspect the concrete chain's existing result; `Execute` never reruns this stage |
| `Succeeded` | Return detached original evidence without effect execution, time refresh or authority completion |
| `Cancelled` (pinned only) | Return retained pre-start cancellation evidence; never execute or invent a positive prune result |

`Coordinator.WithOperation` verifies the exact assignment/ticket/consumer/
operation/purpose against its private confirmed state. An unconfirmed retained
authority attempt, unknown/completed ticket, foreign assignment or retired phase
blocks the action. `Stopping` still allows previously admitted work to drain.
The coordinator mutex remains held until the synchronous action returns; stop,
completion and retirement cannot cross it. No permission object escapes. Callbacks
must not re-enter guarded objects or spawn effects that outlive the call.

Lock order is executor, coordinator, WorkChain. Binding/execution check that the
executor and both authority roots are disjoint. All directories must be selected
as separate owner-controlled roots before creation; those checks do not establish
physical failure domains. `Execute` keeps the authority guard through the durable
start, concrete atomic effect, and durable result publication. Context cancellation before
start publication preserves `Admitted`; cancellation or error after a retained
start leaves unresolved work. Once the effect succeeds, result publication finishes
despite caller cancellation. The successful result is still not a signed `Complete`.

Open never contacts authority or WorkChain, submits an admission, starts work, or
invents a terminal record. Explicit recovery accepts only the already persisted
effect with the exact assignment/ticket/request and a matching chain-local
network/activation/base. It does not call pruning or the final authorization
callback. A missing result, unavailable chain, mismatched record or uncertain
chain writer cannot become success. Even a known callback error before deletion
does not fabricate a durable no-effect disposition. Such tickets can block
retirement indefinitely until a separately reviewed recovery mechanism exists.

The raw version-0 journal does **not** have independently retained stage/head
history; the opt-in two-root mode below adds it. Neither mode has a physical
database anti-rollback pin. The raw mode's request ID authenticates the request,
not the newest journal prefix. A valid-prefix rollback or replacement of owner-
controlled storage is outside this local guarantee, including a recreated empty
WorkChain. Do not use missing records as evidence of no prior execution, recreate
an executor as recovery, or reuse its ticket against another database. The same
intact WorkChain retains ticket deduplication even if a caller has lost its reply;
that is not distributed exactly-once execution.

Tests exercise concrete chain deletion, 16 concurrent callers, signed request
binding, missing/unconfirmed/completed authority, cancellation, stop/result races,
malformed files, required sync failure, lock replacement and bounded leftovers.
Another 26 process kills cover initialization; all seven admission/start/result
publication boundaries; and the points immediately before/after the chain effect.
Positive outcomes recover to the original result and may be separately completed;
unresolved starts stay pending and block retirement. These do not certify physical
power loss, partitions, multi-assignment quorum coverage or live CLI enforcement.

### Independently retained prune stage intents and pins

`CreatePinnedPruneExecutor` creates two NEW disjoint roots. The independent pin
journal is locked first and keeps that lifetime lock through executor creation,
use and close. Existing roots (even a raw `Prepared` executor), overlapping paths
and known aliases are refused before initialization. Fresh pins cannot be attached
to prior work, and partial initialization is never repaired or reset.

The primary `ready.omcpx` uses `OMCPINIT` version 1: request ID plus a nonzero
random 32-byte pair binding, 74 bytes total. The pin journal's 74-byte `OMCPINSJ`
version-0 ready marker binds that same request and pair, and is published only
after the primary is initialized. Raw `OpenPruneExecutor` rejects the version-1
marker, including when pins are missing: the opt-in mode has no silent downgrade.
The binding prevents accidental pairing, not copied-root or physical-disk identity.

```text
independent-prune-pins/
  prune-pins.lock                 permanent ownership inode
  assignment.omcaa               independently selected exact assignment
  request.omcpr                  independently pinned exact request
  ready.omcpp                    OMCPINSJ/version/request-ID/pair-binding
  intents/01-admission.omcae      exact attempted executor records
  intents/02-started.omcps
  intents/03-result.omcpfx
  confirmed/01.omcpp             exact position after admission publication
  confirmed/02.omcpp             exact position after start publication
  confirmed/03.omcpp             exact position after result publication
  pending/entry-<decimal>         at most 128 bounded leftover temporary files
```

Each transition follows: independent intent sync, executor record sync,
independent confirmation sync. A transition is acknowledged only after the last
step. During `Execute`, the start is independently confirmed before WorkChain is
called, and the coordinator guard remains held through final result confirmation.
The pin journal keeps at most three intents and three confirmations, with at most
one intent beyond the confirmed prefix. Publication uses file sync, no-replace
hard links and directory sync. Required I/O errors poison the writer and require
close/reopen; accepted records are re-synced before selecting the primary history.

A `PrunePosition` has stage and head ID. `Prepared` starts at the request ID;
each next head hashes the prior head, one-byte next stage and exact record under
`OMESH/custody-prune/position/id/v0`. The 75-byte `OMCPPOSN` version-0 confirmation
binds request, stage and head. These unsigned local envelopes are not remote
acknowledgements, signed completions or execution grants.

`OpenPinnedPruneExecutor` reads the independent journal first. It accepts only:

| Independent state | Permitted primary history | Explicit recovery |
| --- | --- | --- |
| Confirmed through stage S, no pending intent | Exactly S, with every retained record identical | No transition to resume |
| Confirmed S, exact next intent T | Exactly S or exactly S plus T | `ResumePinnedTransition` retains/confirms T only |
| Confirmed history missing, altered, or unexplained longer primary history | None | Fail closed; never reconstruct confirmed missing records |

Open never publishes or confirms transitions. Diagnostics separate observed
`Stage`, confirmed position and pending position. Any pending pin blocks ordinary
bind/execute/effect-recovery calls, including historical retries, until explicitly
resumed. Resume never calls WorkChain, obtains authority or signs completion.
Resuming an admission retains historical evidence; later execution still needs
the current guard. Resuming a start leaves `Started`, which cannot execute again.
Resuming a result retains the exact outcome already obtained before its intent
was written, not a result fabricated from absence in another database.

Context cancellation before intent publication may leave only an unpromoted temporary
file. Once an intent exists it cannot be abandoned or replaced; even cancellation
before primary start publication requires explicit resume and may leave an
unresolved start indefinitely. Confirmation after durable primary publication
finishes despite caller cancellation. A missing chain effect remains unknown.

Independent pins detect rollback of the primary's confirmed prefix while the pin
root remains intact. Rolling both roots back together can still agree. Operators
must independently retain/protect the configured pin root; the library does not
prove storage/access-control failure domains. Separate modes below add pre-start
cancellation and local WorkChain position pins; they do not establish physical
identity, resolve unknown Started effects, fence copies, or install multi-replica
authority, transport and live runtime integration. No signing key is retained.

Tests cover 63 transition publication failures, stage-exact reopen, cancellation,
independent directory-sync failures, prefix rollback, missing/altered pins, wrong
pairs, raw-mode downgrade, ownership and resource bounds. Another 71 process kills
cover the three publications of every transition, both initialization sequences,
and the before/after-effect points. This is local crash evidence, not power-loss
or shared-storage rollback certification.

### Explicit cancellation before any start

`PruneExecutor.CancelBeforeStart(ctx, coordinator)` adds one narrow terminal
decision: an independently pinned `Admitted` executor may irrevocably choose
`Cancelled` **instead of** ever recording `Started`. It requires a currently
pending exact ticket in the private local coordinator and holds the same executor
and authority locks through independent intent, primary record and confirmation.
`Stopping` allows this admitted work to drain. Unknown/completed/retired tickets,
unconfirmed authority, missing stage pins and any pending executor transition
are refused. Raw executors cannot use or reopen this branch.

This API takes no database handle and never queries chain state or absence.
`Started` and `Succeeded` cannot transition to cancellation. In particular, a
retained **start intent** blocks cancellation even when the primary still says
`Admitted`: resuming that intent produces `Started`, not `Cancelled`. Expiry,
context cancellation, a known authorization error, process death and a missing
chain effect cannot turn an already-started operation into a no-effect outcome.
The existing unresolved-start rule remains unchanged.

The version-0 `OMCPCNCL` envelope is exactly 138 bytes: eight magic bytes, a
big-endian uint16 zero version, then 32-byte assignment, request, admission-ticket
and executor-pair-binding IDs. Every ID must be nonzero; replay checks all four
against the retained request/admission and independent pair. Its identity domain
is `OMESH/custody-prune/cancellation/id/v0`; the golden fixture is
`de61c6a6e5adc1af6e6dc172e71599c6023c4a9d12470c44756fd54ccd3277c3`.
This is an unsigned retained **decision**, not an independently verifiable proof
of global non-execution. Decoding or hashing these bytes does not establish that
the decision was ever durably made by the executor.

The independent intent is `intents/02-cancelled.omcpc`; the matching primary file
is `records/02-cancelled.omcpc`. Neither may coexist with `02-started.omcps`, and no
third record may follow cancellation. Confirmation remains `confirmed/02.omcpp`
but binds terminal stage 5 and the exact cancellation head. Stages 1–4, old
execution record names, request/effect bytes and position hashes are unchanged.
Older binaries reject the new second-record name instead of reopening a cancelled
operation as executable. No automatic migration or fresh pin attachment is added.

Open only checks the retained branch; it never chooses or confirms cancellation.
One unconfirmed cancellation intent requires `ResumePinnedTransition`, which can
only publish/confirm those exact retained bytes. After an intent exists, a caller
cannot change its mind and execute. Confirmation finishes despite caller context
cancellation after primary publication; I/O uncertainty still poisons the handle.
Snapshots expose detached `Cancellation` and independent `Protection` fields;
normal operations stay gated until confirmation. A confirmed retry returns the
original cancellation without needing a current coordinator. `Execute` and
positive-effect `Recover` return `ErrPruneCancelled` without touching WorkChain.

The ticket stays pending at the authority until a **separate** consumer-signed
`Complete` using the retained cancellation ID receives an authority decision.
Cancellation neither signs that command nor releases, re-admits or reuses the
operation. The deployment must trust and fence the actual consumer that makes
this acknowledgement; copied executor roots, shared rollback and remote old
consumers are not covered. Unknown Started effects, physical fencing, current
authority/completion transport and all live acceptance-path adapters remain open.

Tests cover execution/cancellation races, stopping drain, held guards, absent or
unconfirmed authority, start-intent refusal, mixed/rolled-back histories, wrong
pairs, raw-mode rejection, interrupted directory sync and caller cancellation.
The new branch has 21 publication-fault boundaries and 14 explicit-resume errors;
42 process-kill cases cover cancellation and both absent/present primary-record
resume paths. Tests separately sign completion and show that retirement cannot
proceed just because local cancellation succeeded. These are local process/fault
checks, not physical power-loss or global non-execution certification.

### Explicit local completion from retained terminal evidence

`PruneExecutor.Complete(ctx, coordinator, entry)` submits a **separate**, already
consumer-signed and authority-co-signed `Complete` entry. It checks the executor's
own retained state under its mutex, not a caller-supplied snapshot or generic
callback result. Independent stage pins are mandatory. The eligible states are
confirmed `Succeeded` and confirmed `Cancelled`; raw journals, `Prepared`,
`Admitted`, unresolved `Started`, uncertain handles and pending executor
transitions cannot use this adapter. Even an actual chain effect must first be
recovered into the executor and independently confirmed before completion.

The command must bind the exact assignment, consumer control key, admission
ticket and retained effect/cancellation ID. Both signatures and the configured
authority key are checked. The coordinator separately checks its own exact
signed compare-and-append head and ticket history. A valid signature over another
outcome is refused before any authority intent is retained. No key, signer,
database handle, effect callback or reusable current-state snapshot is accepted.
The method neither constructs a new command nor refreshes an outdated signature.

Lock order is executor then coordinator. Both guards remain held through the
existing authority publication protocol: exact intent, durable decision, then
independent confirmation before success. The executor and authority roots must
be disjoint. No fourth executor record, new terminal stage, new envelope or wire
format is introduced; the authority's retained Complete entry is the completion
decision. The original executor outcome remains immutable historical evidence.

Open still submits and confirms nothing. After a failed publication, close/reopen
and explicitly retry the **same entry**: it either resumes that retained attempt
or reads its already confirmed historical decision. A different pending attempt,
including Stop, blocks completion and must be resolved separately. If Stop wins
the signed head, completion needs a separately re-signed entry at the new head;
the existing pending ticket may drain while Stopping. A conflicting old Complete
cannot be replaced or repaired, even with a fresh signature. Exact historical
retries remain lookups after retirement and never reopen the ticket or execute
another effect.

Caller cancellation before publication returns no decision. A retained intent
is never discarded; cancellation after the durable authority decision does not
abandon its independent confirmation. I/O uncertainty returns no Commit and
requires successful reopen before retry. `Commit.Appended=false` means the
authority entry already existed, not that the local effect did not occur.

Tests cover both terminal branches in all three pinned executor/storage modes,
closed-database completion, exact binding/signature rejection, unknown and
unconfirmed outcomes, stopping/head conflicts, concurrent retries, held guards,
missing terminal records/pins, disjoint roots, caller cancellation and actual
injected directory-sync failures. There are 42
publication-fault cases and 70 process-kill cases: both initial completion and
retry of a previously retained intent. Reopen twice stays non-submitting; final
retry, retirement and historical lookup leave chain accounting and executor
evidence unchanged.

This adapter is **not installed in any live acceptance path**. The lower-level
coordinator still stores trusted signed commands and does not prove their external
effects. A deployment must route the real consumer through the concrete adapter,
fence copied/remote owners and cover all required assignments. The method does
not supply cross-host admission/completion transport, physical pin independence,
global non-execution proof or a resolution for unknown Started outcomes.

### Opt-in completion-only QUIC delivery

`/outcomemesh/prune-completion/0` is a separate, disabled-by-default protocol.
`Host.SetPruneCompletionHandler` requires one independently configured client
transport identity, checked before its own rate budget is consumed.
`Host.CompletePrune` requires the expected server identity; neither an advertised
address nor a request field can supply that trust pin. QUIC authenticates both
endpoints. Control/authority signatures remain separate from transport identity.
No existing daemon or audit/serve/prune path installs this handler automatically.

The concrete `store.NewPruneCompletionServer` retains references to the original
pinned executor and its local coordinator. It takes an explicit client peer pin
and timeout. The host supplies the **authenticated** peer ID to `Serve`, which
checks it again before reading a request. A generic host handler is not an outcome
verifier; deployments must compose this concrete adapter, not forward arbitrary
commands directly to the low-level coordinator. Executor/coordinator lifetime
ownership must cover every active handler. They are not moved to separate hosts
or replaced with remote snapshots by this protocol.

Exactly one 424-byte request carries `OMCPCREQ`, uint16 version zero, a nonzero
32-byte exchange nonce, and the unchanged 382-byte co-signed Complete entry.
Other command kinds, versions, signatures, truncation and trailing bytes fail.
The sender must close its write side; the server consumes EOF **before** calling
the local completion adapter. An unclosed or concatenated request cannot write
an authority intent. Fixed frame sizes bound reads and allocation without a
peer-controlled length or unbounded history response.

Only the existing `PruneExecutor.Complete` can change authority. It requires the
independently confirmed terminal outcome and exact entry binding, retains the
authority intent, commits its decision and independently confirms it. Only then
does the server emit a 74-byte `OMCPCACK`/version-zero reply containing the exact
nonce and entry ID, followed by write-side EOF. The client checks all of these,
including EOF, before returning success. Canonical request/reply fixtures are
frozen by `TestCompletionCanonicalFrames`. No receipt, authority command, effect,
executor-stage or consensus format changes.

Each exchange uses a fresh cryptographic random nonce, including retries of the
same entry. The reply is an authenticated-channel acknowledgement, **not** a
portable signed proof, current phase snapshot, reusable grant or durable client
record. Complete/partial response loss, mismatched nonce/entry, trailing response,
timeout and caller cancellation never establish non-commit. Exchange I/O failures
return `ErrUnconfirmed`; preserve the exact signed entry and resolve it explicitly.
There are no error frames asserting a no-effect outcome. A confirmed historical
retry can acknowledge the same entry after retirement, without reopening work.

The low-level `Host.CompletePrune` client does not sign, refresh stale heads,
discover another authority, automatically retry, or durably retain its
intent/acknowledgement. That independent client retention is provided only by
the explicit outbox below. Request timeouts are
100 ms–2 minutes, default 15 seconds, cover dial/exchange, and interrupt blocked
I/O when cancelled. A server that already made a durable authority decision still
finishes confirmation even if its client disappears. Timeouts do not revoke
pending tickets or resolve unknown Started effects.

Independent host limits default to two concurrent completion streams globally,
one per peer, eight requests per peer/minute and 32 globally/minute. Hard maxima
are 8/1/60/256 respectively. Protocol memory scopes are 512 KiB globally and
64 KiB per peer; node-wide connection/memory limits still apply. Completion and
custody/object/tie traffic have separate protocol budgets. These are bounded
research defaults, not calibrated production admission or filesystem latency
guarantees.

Tests use actual loopback QUIC for identity rejection, disabled negotiation,
resource scopes, EOF-before-mutation, wrong outcomes/consumers, incomplete work,
lost/partial replies, caller cancellation and exact retry after reopen/retirement.
Twelve separate-server-process kills bracket request validation, authority intent,
decision, confirmation and both sides of the response. The restart drill explicitly
closes the dead client connection and recreates both network endpoints with the
same independent identities; it does not test automatic failover or stale-connection
recovery. Existing local publication-fault suites cover the underlying journal
boundaries. Physical/shared rollback, copy fencing, cross-host admission/execution,
all-replica enforcement and default runtime integration remain open. This endpoint
alone cannot authorize active rebaseline.

### One-command completion client outbox

`store.CompletionOutbox` adds local delivery durability around the concrete
identity-pinned QUIC client. It owns one immutable `CompletionIntent`: the exact
already co-signed Complete plus independently selected client/server transport
IDs. Its ID commits all three and must be retained outside the journal before
creation/reopen. No private key is stored in this journal; the caller retains
the transport identity separately. The pinned assignment must match the command
and authority key, and the consumer must have declared prune rights. These static
checks do not verify an actual terminal effect or current head; the server's concrete executor
adapter remains responsible for those decisions.

`CreateCompletionOutbox` initializes only a new root, syncing the assignment and
456-byte intent before its final initialization marker. It does not dial.
`OpenCompletionOutbox` requires that external intent ID, validates existing files
and re-establishes their durability. It creates no files, submits no command and
does not promote staging files. A missing/partial root is an error, never an
invitation to recreate or change the signed command.

`Deliver` accepts a concrete `*libp2ptransport.Host`, checks its identity against
the retained client pin, and makes at most one exchange to the retained server
pin at an explicitly supplied address. The address can change for an explicitly
requested retry but cannot change the server identity. There is no automatic
retry, discovery, failover, signing, head refresh or arbitrary success callback.
Every network retry sends the exact same entry with a fresh wire nonce. The
lifetime process lock and in-process mutex cover the network call and receipt
publication; concurrent calls cannot replace the command or duplicate a locally
completed exchange. Close waits for that owner to drain.

After a complete nonce/entry-bound reply and EOF, the outbox publishes a 148-byte
checksummed local receipt using a synced staging file, no-replace hard link and
directory fsync. Only then can Deliver return success. Caller cancellation after
the checked reply does not discard it; the local write still finishes. A local
write/sync error returns no ACK and poisons the writer until close/reopen. A
visible exact final receipt is re-synced on reopen; a staging file alone never
becomes a confirmation. Temporary leftovers are bounded at 128 files of at most
148 bytes. Exhaustion refuses another send before contacting the server.

`Snapshot().Acknowledgement == nil` means **unresolved**, not unsent or remotely
uncommitted. Missing/partial replies, cancellation before a verified reply and
client death cannot clear the intent or authorize effect replay. Explicit retry
uses the original server's retained decision. A durable local ACK is historical:
later Deliver returns that same ACK without contacting the server, including
while it is offline. It does not claim the assignment is still active.

The receipt is an unsigned local observation, not a portable proof or execution
permission. Its checksum detects corruption, not a malicious journal writer.
Intent pinning catches replacement with a different command or peer binding;
it does not detect a copied whole journal, shared rollback, or lost ACK history.
ACK-only rollback may return the client to unresolved and require an exact
network retry. Independently retained server decisions, protected root ownership,
physical storage and copy fencing remain necessary external assumptions.
Timeouts bound dial/exchange, not filesystem fsync or time waiting for the mutex.
There is no queue, deletion/reset API, multi-operation scheduler or daemon wiring.

Tests cover fixed canonical intent/receipt vectors, bounded decoding, wrong
assignment/authority/consumer/peer bindings, malformed and replaced files,
concurrent delivery/close, caller cancellation and lost/partial QUIC replies.
Seven local receipt-publication faults recover only unresolved or exact delivered
state. Forty-one separate-client-process kills cover initialization, initial and
historical sends, in-flight server confirmation and every local receipt boundary.
Neither this journal nor those logical process tests close the live acceptance,
cross-host admission, independent deployment or physical power-loss gates.

### Admission-only QUIC and ordered executor binding

`PruneExecutor.Admit` joins local authority admission and executor binding for
one already retained, independently pinned request. The command remains externally
consumer-signed and authority-co-signed; its `OperationID` must be the exact
request ID. Assignment, purpose, consumer and authority must match before any
authority write. Raw executors are refused. No request upload, signing key,
new-head selection, chain handle or execution callback is accepted.

The executor mutex is acquired before the coordinator mutex, and both stay held
through the entire ordered publication:

1. Retain the exact authority intent.
2. Publish the authority's admission decision.
3. Independently confirm that authority position.
4. Retain the exact executor admission-transition intent.
5. Publish the executor's admission record.
6. Independently confirm that executor position, then return.

The existing record formats are unchanged. `Commit.Appended` describes only the
authority decision: a false value can accompany a newly finished executor
binding. Stop, Complete, Retire, Execute and Close cannot split the two locked
owners during this call. A Stop already committed before a retry can still let
the previously admitted ticket drain. It cannot admit a new operation.

A failure after the authority decision but before executor confirmation returns
no success. The authority ticket remains pending; there is no automatic rollback,
cancellation, completion or effect. Uncertain storage owners require close/reopen.
Open validates existing evidence without advancing either journal. An explicit
retry of the same signed entry may resume the coordinator's exact pending attempt
and the executor's exact admission intent, including a record already visible
but not confirmed. Another authority attempt or a pending start/result/cancellation
must be resolved separately. Missing confirmed evidence is not repaired.

When no executor admission intent exists, first binding still requires the
ticket to be currently pending. An existing exact admission intent may instead
be retained as historical evidence after the ticket closes; subsequent Execute
still takes the current coordinator guard. An exact previously confirmed admission
can return historical success after completion or retirement without reopening
the ticket or changing the executor. This is explicitly not a reusable permission.

The optional `/outcomemesh/prune-admission/0` protocol delivers this single command
to the original colocated executor/coordinator. It is disabled until a caller
installs `PruneAdmissionServer` with an independently pinned client identity.
`Host.AdmitPrune` pins the server identity. Neither transport identity substitutes
for either command signature. A 424-byte request contains `OMCPAREQ`, big-endian
uint16 version zero, a fresh 32-byte nonce and the exact 382-byte prune Admit.
The 74-byte response contains `OMCPAACK`, the same version, nonce and entry ID.
Completion frames, non-prune purposes and other command kinds are rejected.
Strict bounded decoding and actual request EOF precede any mutation; response
nonce, entry ID and EOF are mandatory before client success. That response follows
both independent confirmations, not just authority acceptance.

Admission has its own stream/rate budgets, separate from completion and custody:
defaults are 2 concurrent streams, 1 per peer, 8 per peer per minute and 32 globally
per minute; hard maxima are 8/1/60/256. Protocol memory is capped at 512 KiB and
protocol-peer memory at 64 KiB. Unauthorized peers are rejected before consuming
the rate budget. These research limits are not production capacity calibration.
The bounded exchange timeout is 100 ms–2 minutes, default 15 seconds, covering
dial/network I/O, not mutex wait or filesystem latency. Cancellation interrupts
I/O but cannot undo already retained decisions.

The low-level client has no durable intent/receipt, retries, failover, discovery
or signing. Callers must independently retain the exact command and peer pins
before using it. Lost/partial replies and disconnects remain unresolved, never
permission to choose a replacement operation. Every explicit exchange uses a
fresh nonce. ACKs are unsigned authenticated-channel observations, not portable
proofs, current-state grants or evidence that a remote executor may start.
The completion outbox does not accept admission entries. The separate admission
outbox below retains that exchange; managed runtime ownership remains open.

Tests cover 42 initial publication boundaries and 14 interrupted executor-resume
boundaries, canonical vectors and protocol separation, wrong bindings, cancellation,
concurrent exact retries, Stop serialization, missing/trailing EOF and lost/partial
QUIC replies. Forty-five separate-server-process kills cover all publication
boundaries plus request/confirmed/replied checkpoints. Each recovery opens twice
without submitting, then explicitly retries over QUIC and checks both confirmed
journals without a chain effect. A complete QUIC-admit / locally guarded effect /
QUIC-complete test covers the lifecycle; a historical admission ACK with a closed
ticket still cannot start the executor. None of this fences copied owners, proves
physical pin independence, enforces all replica assignments or installs live
audit/serve/prune handlers.

### One-command admission client outbox

`store.AdmissionOutbox` retains exactly one `AdmissionIntent`: an externally
co-signed prune Admit and the independently selected client/server transport IDs.
Its independently retained ID pins all three. The signed `OperationID` names the
server's separately prepared `PruneRequest`; this journal does not retain or
upload request bytes, create a request, or establish that the server has one.
The server must still validate its own request and current authority before
first binding. Local validation checks the assignment, authority key, declared
prune consumer and canonical signatures. It rejects sequences above
`2*(MaximumOperations-1)`: before a new Admit there can be at most N-1 prior
admissions and N-1 completions, and Stop forbids new admissions. Passing that
static bound is not a current-head check.

The new root layout is deliberately distinct from completion:

```text
admission.lock             empty lifetime process-lock file
assignment.omcaa           exact canonical assignment
intent.omcai               immutable 456-byte intent
ready.omcao                42-byte initialization marker
received/ack.omcar         optional 148-byte local acknowledgement receipt
pending/entry-*            bounded unpublished receipt files
```

Intent encoding is `OMCASEND`, big-endian uint16 version zero, client ID,
server ID and the exact 382-byte signed entry. Its ID domain is
`OMESH/custody-admission/intent/id/v0`. The ready marker is `OMCAINIT`,
the same version and intent ID. A receipt is `OMCADONE`, the same version,
intent ID, the 74-byte admission-wire ACK and a 32-byte checksum over the preceding
bytes under `OMESH/custody-admission/receipt/v0`. Neither completion envelopes
nor their embedded ACKs are interchangeable with these formats.

`CreateAdmissionOutbox` writes and syncs a new root before returning, without
sending. `OpenAdmissionOutbox` validates and re-syncs existing evidence against
the external intent ID; it creates no files, promotes no temporary receipt and
makes no network call. Missing/partial roots cannot be recreated as recovery.
`Deliver` accepts only the concrete identity-pinned QUIC host, not an arbitrary
success callback. A supplied address is a route, never a replacement trust pin.
The mutex and lifetime process lock span validation, exchange and receipt fsync;
concurrent deliveries serialize and Close waits for that owner.

A fully checked response and EOF precede the synced staging file, no-replace
receipt publication and directory fsync. Success is returned only after all
those steps. Cancellation after the checked response does not discard it.
Failed local publication returns no ACK and makes that writer unusable until
close/reopen. Recovery re-syncs a visible exact final receipt; a staging file
alone stays unresolved. At most 128 pending files of at most 148 bytes are
allowed; capacity exhaustion refuses a send before using the network.

A nil acknowledgement means unresolved, not unsent or rejected. An explicit
retry sends the same signed command with a fresh nonce; there is no signing,
head refresh, automatic retry/failover, queue, drop/reset API or request rewrite.
A retained acknowledgement returns offline with its original nonce. It records
historical delivery, even after Stop, completion and retirement; it cannot
authorize Execute or reopen a ticket. A server rejection likewise cannot turn
the original command into a newly signed request.

The receipt is an unsigned local channel observation, not portable proof.
Its checksum detects corruption, not a malicious root owner. Intent pinning
does not detect copied roots, shared rollback or ACK-only loss. Losing an ACK
can only make delivery unresolved and require an exact retry against retained
server history. Physical root protection, independent pins, server retention,
copy fencing and all-assignment live enforcement remain external/open gates.
Timeouts bound network I/O, not mutex waits or filesystem latency.

Tests cover strict canonical records and domain separation, sequence endpoints,
wrong bindings, malformed/replaced files, receipt faults, concurrency, cancellation
and lost/partial QUIC responses. Forty-one client-process kills cover four server
lifecycle phases (initial, admitted, stopping, retired), client receipt boundaries,
both in-flight server confirmations and initialization. Reopening twice must not
send; explicit exact retry preserves the lifecycle and never prunes chain data.
These logical process tests do not demonstrate power-loss durability or install
managed runtime services.

### Storage-incarnation-bound prune requests

An opt-in local database mode now distinguishes independently initialized
incarnations of the same logical chain. This is an intermediate gate: it does
**not** prove physical storage identity or detect a copied/rolled-back database
that retains the same ID.

`workchain.CreateBoundWithPolicy` accepts a caller-selected, fresh random nonzero
32-byte storage ID and creates only a new directory. Retain that ID independently
before admitting work; never derive a replacement pin from a recovered database.
The ID at metadata key `01 06`, schema 6, base state, configuration, initial tip and
accounting are committed in the same synchronous initialization batch. Existing
and incomplete roots cannot be recreated. `OpenBoundWithPolicy` requires the
expected ID and existing database, refuses legacy/missing/mismatched identity,
and cannot initialize an empty image. Raw `Open`/`OpenWithPolicy` refuse bound
schemas; no automatic migration or loss-recovery reattachment is supplied.

Set `PruneRequest.StorageID` before computing the request ID and requesting
admission. A nonzero ID selects `OMCPREQS` version 1: insert 32 storage-ID bytes
after the consumer key and before the floor field, under domain
`OMESH/custody-prune/request/id/v1`. The 409-byte request fixture has ID
`200f79ab68e679511d7732e45db5a642c660ec47ec146e8c5011583deceaba70`.
These requests require the independent stage-pin constructor; raw executors
refuse them. The signed operation ID and both retained request copies therefore
bind the incarnation before any start. Zero remains the unchanged version-0
unbound format, never a wildcard for bound storage.

Execution checks context and incarnation before retaining a start. WorkChain
checks it again under its own prune lock, before result lookup, authorization or
deletion. Bound databases refuse legacy unticketed pruning. A bound result uses
`OMWCPREF` version 1 with the storage ID after the ticket, and domain
`OMESH/workgraph/canonical-prune-effect/id/v1`. Its 522-byte fixture has ID
`4ee4404d3f5ce8106b8ab018585db43f0550c22d677b1f49d74ba26b4211c103`.
The first bound result atomically enables schema 7 with the deletion, floor and
accounting. Replay rejects missing or wrong-incarnation effects and schema
downgrade. Existing schema 4/5 databases and all version-0 bytes/IDs are unchanged;
new result bytes count toward the existing 1 KiB/result, 65,536-result and history
bounds. The fixed storage-ID metadata, like configuration metadata, is outside
the logical history byte count.

`Recover` checks the request's incarnation before looking up a Started result;
the result itself must contain that same ID. Absence in an old copy stays unknown,
never triggers deletion, and never authorizes completion. A retained Succeeded
result can still be read without any database handle: it is historical evidence,
not a fresh claim about the currently supplied database. Unit tests explicitly
show that copying a database preserves its ID and that an old copy cannot resolve
an uncertain executor outcome merely because its effect is missing.

This mode is a trusted library only, not installed in the activation/forest or CLI
runtime. Operators must not silently switch those raw open paths or reuse an ID
to restore lost storage. The separate position-pinned mode below adds a local
database rollback gate; it is not retrofitted to this incarnation-only mode.
Physical/copy fencing, safe no-effect disposition, all-replica authority and live
transport remain open. Process tests cover initialization on both sides of commit,
four bound effect boundaries, and the 71 independent executor-stage crash boundaries.

### Independently retained WorkChain database positions

`CreatePositionPinnedWithPolicy(databasePath, pinsPath, base, parameters, policy,
storageID)` creates two **new**, disjoint trusted-owner roots. The external storage
ID must already have been selected and retained as above. A fresh random pair ID
binds the journal identity to the database; it is not a physical-device identity.
`OpenPositionPinnedWithPolicy` requires both existing roots and the expected ID.
It acquires the journal's lifetime native lock before Pebble's lock. No migration,
fresh-pin attachment, missing-root reconstruction or journal reset is supplied.
The ready record is published only after synchronous database initialization;
an interrupted pair without ready cannot be opened in position-pinned mode.

Local schema 8 stores the incarnation at `01 06`, pair ID at `01 07`, and position
at `01 08` in the initial batch. The position is a big-endian uint64 sequence and
32-byte commit ID. Sequence zero derives from the pair's exact identity; later
commit IDs are fresh `crypto/rand` tokens. They identify logical batches, **not**
state content, consensus work, backup freshness or physical storage. The first
ticketed prune atomically selects schema 9. Raw schema 4/5 and incarnation-only
schema 6/7 retain their formats and do not acquire this guarantee. Their open
APIs refuse schema 8/9; the position-pinned API refuses the older modes. Request,
effect, block and consensus encodings are unchanged. The fixed pair/position
metadata is outside logical history accounting; journal filesystem costs are
separate as well.

Every actual block commit, stale-fork prune, replay-checkpoint rotation and
canonical-prefix prune follows this order under the chain lock:

1. Publish and sync the exact previous/next position intent in the independent
   journal. Never choose a successor from an unpinned database image.
2. Perform final authorization, if needed, **after** that I/O, then synchronously
   commit the position in the same Pebble batch as all logical changes. A failed
   final authorization still leaves an unresolved intent; it is not discarded.
3. Publish and sync independent confirmation for that same position before
   returning success or updating the usable in-memory chain state.

No-op maintenance and historical exact prune retries do not create positions.
Once publication/commit is uncertain, the live handle is poisoned; close/reopen
is required. Reopen verifies the complete bounded journal and normal full chain
recovery. It does not publish a missing confirmation or execute a batch:

| Retained journal | Database position | Result |
| --- | --- | --- |
| Confirmed C, no intent | Exactly C | Usable chain |
| Confirmed C, pending P | Exactly C | Gated, unresolved outcome |
| Confirmed C, pending P | Exactly P | Gated, explicit confirmation available |
| Either | Anything else | Refuse the database |

`StorageProtection()` returns detached local diagnostics even for a recovered
pending handle. Normal chain reads, commits and executor preflight are gated.
`ResumeStorageConfirmation()` works only when the fully recovered database
already contains P. It flushes that existing state, then independently confirms
P; it does not rerun a prune, create a new batch, change its result or sign
authority completion. If the database is still C, absence cannot distinguish
"never committed" from "committed and rolled back": the gap remains unresolved.
Neither this API nor prune recovery implements a safe no-effect disposition.

The journal contains exact `identity`/`ready` records, an empty permanent
`positions.lock`, `intents/`, `confirmed/` and bounded `pending/` directories.
Transition names are 20-digit sequences. Version-0 `OMWP` intent/confirmation
records carry a domain-separated identity context and checksum, with exact
150/110-byte encodings. These checksums are corruption checks, not signatures.
Files are completely written and synced before no-replace link publication and
directory sync. Reopen stabilizes already visible tail records before allowing
new work. Incomplete staging files are never interpreted as published records.
All records are bounded by 256 bytes, staging leftovers by 128 files, and journal
history by 65,536 transitions. Nothing is compacted, reset or deleted to bypass
that ceiling. Full replay is O(n); live checks verify permanent inodes, identity
and the exact retained tail under the immutable trusted-owner history contract.
This intentionally bounded research journal is not a production-scalable WAL.

Database-only snapshot rollback is detected **only if the independently retained
journal survives**. A current database copy carries the same position and can
open with that journal after the original owner closes. Copying both roots also
copies their pair binding and allows independent owners of the copies; rolling
back both roots can hide history. Privileged edits and incorrect durability
barriers are outside this local guarantee. Store pins in a genuinely independent
failure/access-control domain; a second directory alone does not establish that.
Physical fencing, safe no-effect disposition, power-loss/full-filesystem
validation, all-replica current authority and live runtime integration remain
deployment gates. The tests cover 56 injected mutation faults, 14 initialization
faults, eight explicit-resume errors, all four mutation paths, old/current copies,
journal damage, bounds, executor recovery and 79 process-death boundaries.

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
still cover every live acceptance effect. The optional local executor above
guards one concrete prune; existing custody sessions, archive journals, pruning
commands and receipt parsers are not integrated with authority entries yet.

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
current-authority transport, physical chain-storage identity/rollback pins,
operational CLI service, lease, successor activation or automatic cross-host
failover is installed.
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
