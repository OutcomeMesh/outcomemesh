# Security model

OutcomeMesh is pre-alpha research software. It must not be used to secure real
assets.

## Protected properties

The version-0 kernel aims to protect:

- conservation of resource amounts;
- authorization of every consumed resource;
- atomicity of a transaction;
- deterministic state roots;
- chain-local block network identifiers independent of transport checks;
- fail-closed GuardVM behavior;
- canonical and unambiguous signed encodings;
- bounded CPU and memory use for decoded transaction structures.

## Initial trust assumptions

- SHA-256 collision and preimage resistance.
- Ed25519 signature unforgeability.
- Correctness of the Go compiler and standard library implementation.
- Correctness of the isolated go-libp2p/quic-go transport stack; it does not
  define consensus serialization or state transition behavior.
- Honest construction of genesis during local development.

Local database correctness is not a consensus assumption. State can be rebuilt
from canonical history, and the persistent implementation is tested against an
independent in-memory implementation.

## Adversary capabilities

Tests assume an attacker can:

- submit arbitrary bytes to every decoder;
- create valid signatures over malicious transactions;
- reorder, duplicate, delay, and drop network messages;
- crash a node between storage writes;
- construct conflicting resources and transactions;
- trigger maximum-size programs and collections;
- control some miners and later some committee members;
- provide invalid solver plans, proofs, snapshots, and archive responses.

## Non-goals of version 0

Version 0 does not protect against:

- compromise of the root signing key;
- a user deliberately signing an unsafe GuardVM program;
- metadata leakage or transaction graph analysis;
- majority proof-of-work attacks;
- operating-system or hardware compromise;
- side channels in future Wasm or proving implementations;
- bridge or external-chain failures.

The standalone development chain additionally has unaudited PoW and timing
parameters, unpruned accepted block/delta history, no durable production-grade
Sybil-aware peer routing, and no pruning/finality policy. Signed peer
advertisements authenticate an assertion but do not prove address ownership or
reachability. Snapshot chunks are root-verified but are never imported because
an authenticated provider can lie about both its advertised tip and matching
state; full history replay remains mandatory. Its CLI reads raw private-key
seeds. These are explicit blockers for any public or value-bearing deployment.

The local peerbook limits total identities and IPv4 /16 or IPv6 /32 buckets,
but those are resource controls rather than Sybil resistance. An attacker with
addresses across many prefixes can still occupy multiple buckets. The
one-shot auto-sync path has single-flight and backoff controls. Continuous mode
is opt-in, requires a local CIDR→ASN table, caps attempts per resolved ASN, and
runs passes serially. This reduces correlated routing exposure but does not
prove ownership of an ASN or make a stale/malicious table trustworthy.

Header-first synchronization rejects invalid ancestry, network, time, target,
and PoW before requesting large bodies. It is only a resource-defense layer:
transactions and committed roots are trusted only after full deterministic
execution. Per-session message and request-class budgets bound repeated block,
header, peer, transaction, and snapshot work. Per-identity inbound and
attempted-outbound plaintext windows additionally bound response amplification
during each window. Accepted competing branches store deterministic resource
deltas rather than full state copies, so per-block fork amplification is bounded
by the consensus block/resource limits. Total valid-work history is still
unpruned. A persisted operator budget bounds immutable logical key/value bytes
and rejects an over-budget commit before mutation. It does not bound Pebble
WAL, compaction, obsolete-table, or filesystem overhead, which still requires a
physical reserve, monitoring, pruning, and checkpoints.

Persisted reputation is local policy, not portable identity trust. Its decoder,
record count, score range, timestamps, dial-failure count, latency EWMA, and
file size are bounded; writes use file fsync, atomic rename, and directory
fsync. Latency is measured locally only after authenticated QUIC stream setup,
uses integer milliseconds, and never affects protocol validity. Active sessions
and traffic windows are not restored. Deleting the file resets local history,
so it cannot be considered a security boundary against an operator or
filesystem attacker.

The draft WorkGraph kernel is not active in blocks. Its shares are bounded by
count, encoded bytes, parent fan-in, distinct reward miners, exact anchor,
timestamp window, and derived proof-of-work target. Canonical topological order
removes gossip-arrival nondeterminism. Fixed pay-per-share accounting is bounded
and makes the winner's payment independent of omitted foreign shares. It does
not solve relative-revenue omission, strategic withholding, or
transaction availability; those remain simulation and activation blockers.
The draft uses one WorkSeal/nonce space for weak shares and hard anchors and
only pays shares matching the winning payload. This avoids incentivizing a
second hash market whose work cannot secure the anchor chain. Delayed payout is
required to prevent circular state, reward, WorkGraph, and PoW commitments. The
isolated version-1 block prototype fixes the target from the parent timestamp
with lagged ASERT: a current miner cannot future-date its own header to receive
an easier target. Shares may differ from the winning timestamp only inside the
MTP-valid, winner-relative 120-second window and must still use the exact same
target and payload.
The live round now rolls its candidate timestamp after 60 seconds while keeping
the exact same parent/target/payload/MTP tuple. The old objective miner is
cancelled and drained before the pool's validation generation changes; the
pool then revalidates every retained share under the later timestamp. Concurrent
admission retries if it observed the old generation, so there is no copy window
or unlocked migration. Capability negotiation continues to use only the stable
network/height/parent/target/payload tuple, and gossip reseeds retained IDs after
each rollover. Coverage-ranked pool tips are re-sorted by Work ID before they
enter the strictly canonical parent vector. A parameterized four-node harness
now covers a 60-second clock spread, repeated rollovers, offline windows, stream
loss, convergence, and full final anchor closure. Public activation still
requires longer real-QUIC and rapid-parent-change tests of this boundary.

Directly paying current transaction fees to the current anchor creates a
separate payload-fragmentation incentive. Version 1 therefore prototypes a
strictly bounded, canonically encoded fee-delay queue. Its balance must equal
the checked sum of all slots; each transition replaces exactly one matured slot
with current fees and commits the next queue root and current award inside the
WorkSeal payload. Overflow, inconsistent balance, invalid cursor/delay, and
non-canonical encodings fail closed. This reduces fee internalization but does
not guarantee transaction inclusion or eliminate censorship; those remain
economic and availability gates.

Experimental share gossip is inventory-first and inactive. Its isolated
version-1 stream requires an exact-context/capability handshake and intersects
frame/count limits before accepting an inventory. Frames exceeding that
negotiated ceiling are rejected from their length prefix before allocation;
unknown IDs are requested once, and withheld or invalid bodies end in a bounded
rejection receipt rather than a retry loop. Its local pool does
full weak-PoW/context validation before bounded storage, counts pending
missing-parent children against the same limits, owns all admitted slices, and
reserves an anchor identity slot. Hard-target work is never admitted as an
ordinary paid share. Pending cycles or nonexistent parents can consume only
the published count/byte/edge bounds and still require valid proof of work.
The libp2p adapter registers the stream only through an explicit handler under
`/outcomemesh/workgraph/1`; default hosts and ordinary CLI commands leave it
unhandled, while the explicit work server and QUIC miner install it. Its
separate protocol/peer resource scope defaults to one concurrent
stream and has a hard maximum of four. Thus transport testing cannot activate
version-1 consensus accidentally or consume the chain session's allowance.
Sequential churn is bounded by fixed-window defaults of eight WorkGraph streams
per peer and 512 globally per minute. Since one full relay has an exact
630,258-byte application maximum, admitted averages are bounded to about 82.1
KiB/s per peer and 5.13 MiB/s globally. A fixed-window boundary can double the
short burst and QUIC retransmission is outside this application accounting;
operators still require physical bandwidth monitoring and peer bans.

The inactive versioned chain session has a distinct capability handshake and
requires exact network, genesis, and activation-height agreement. Its
negotiated frame ceiling is applied before allocation on reads and before any
bytes are emitted on writes. Defaults permit at most 64 header/body batches,
64 requests of each class, and 4,096 total inbound messages. Mixed v0/v1
headers must pass parent, height, activation, MTP, future-time, lagged-target,
and PoW checks before bodies are requested; body headers must then match byte
for byte and full replay still goes through the activation router. The responder
serves bodies only after pinning the exact preceding header batch and matching
the next locator/count request; body-first and request-substitution sequences
fail closed. A continuation locator is accepted only for a locally known
downloaded block, so
a long losing side branch can advance without unbounded prefix retries. The
final replayed ID, height, state root, and cumulative work must match the hello.
The QUIC adapter exposes the session only through an explicitly installed
`/outcomemesh/chain/1` handler; default hosts and ordinary CLI commands do not
advertise it. The experimental `work-serve-quic` command installs this chain
handler plus the separately scoped `/outcomemesh/workgraph/1` share handler;
`work-sync-quic` cannot fall back to `/outcomemesh/session/0`.
Its independent resource scope defaults to one concurrent stream
per peer and four globally, while a separate minute window admits four per peer
and 128 globally. The hard configurable maxima are two/64 concurrent and
30/1,024 per minute. These gates do not replace the protocol's frame and
message budgets.

Inbound WorkGraph shares terminate in an ephemeral best-parent round, never
directly in Pebble. Round construction rechecks the selected parent with three
bounded attempts. A parent change replaces the pool; an in-flight old session
may finish only against its detached old pool, which cannot be attached to the
new payload. Full share PoW, timestamp, context, DAG, identity-count, canonical
byte, stream, and peer-byte limits still apply before an anchor can reference a
share.

Outbound cooperative mining is fail-soft with respect to networking. The
publisher queues only IDs already admitted to its local pool, caps one selected
announcement at 1,024 IDs, and removes only the negotiated announced prefix.
Each of at most eight explicit peers owns an independent queue and worker; the
mining callback performs no network I/O. A slow peer therefore cannot block
hard search or another relay. A dial, timeout, resource, or context failure
retains that peer's unpublished IDs during the round but does not reject a
subsequently found hard anchor. Each worker flushes at the configured count or
at the mandatory 8-second..1-minute partial-batch deadline. The default avoids
the measured reward bias created when a low-hash miner cannot reach a 128-share
batch before the anchor. Honest context mismatch caused by a changed tip is
scored as stale data rather than an invalid-message attack. Explicit peers still
do not provide Sybil-resistant selection or production gossip coverage.

Multi-hop forwarding is admission-driven rather than inventory-driven. Only a
new share that has passed full context, PoW, size, miner-count, and pool-capacity
validation can fan out, at most once per node and round. The authenticated source
is excluded, and each accepted share creates at most eight bounded queue copies
if the source was not one of the configured peers (seven otherwise). Duplicate
inventories therefore cannot amplify recursively. The round-control handoff can
buffer at most the same 8,192-share consensus maximum and discards it on parent
change; callbacks only copy/enqueue and perform no network I/O.

Automatic WorkGraph peer selection is opt-in and cannot silently weaken network
diversity. It requires a non-stale operator ASN table, enforces a per-ASN attempt
cap, preserves signed-record address/identity binding, excludes self/explicit
duplicates, and requires every selected peer to complete an inventory-free
exact-context capability probe. Attempt and success counts are independently
bounded; incompatible peers enter persisted exponential dial backoff. The
selector does not treat a signed advertisement as proof of WorkGraph support.

WorkGraph servers and long-lived miners publish version-1 advertisements whose
feature mask and exact activation height are covered by the peer identity
signature, then renew them every 30 minutes with a monotonic sequence and a
one-hour expiry. Peer exchange runs only after a chain-v1 hello has bound the
network, genesis, activation height, and common discovery capability. Responses
contain at most 64 records, are shortened to the negotiated frame budget, and a
receiver validates and merges the entire batch atomically. A session accepts at
most eight discovery requests. Only exact-activation version-1 records claiming
versioned-chain support are served or admitted; a live WorkGraph probe remains
authoritative before selection.

Long-lived miners refresh again every 30 minutes through the selected peer set.
Selected bootstrap identities remain a separate first tier. Ordering within a
tier is keyed by local identity and the refresh epoch, preventing a bounded
attempt budget from selecting one permanent lexicographic prefix. Renewal and
learned-batch persistence share one process-local save lock so an older atomic
snapshot cannot win a concurrent rename. Periodic network failure is fail-soft;
a local persistence or manager failure cancels mining and is reported.
The adversarial bootstrap fixture returns one validly signed local-activation
record together with a validly signed foreign-activation record. Atomic
validation leaves neither record behind, and the bounded pass still reaches an
independent compatible bootstrap whose record survives persistence and reopen.

These constraints limit parsing, replay, and accidental cross-activation risks;
they do not make discovery Sybil-resistant. A bootstrap peer can still return a
biased or eclipse-oriented view, signed capabilities do not prove reachability,
and the ASN table is local operator input rather than a trusted network fact.
Independent seeds, monitoring, and adversarial multi-operator eclipse soaks
remain required.

Anchor notification is separated from ordinary chain pull at the libp2p
protocol ID, but deliberately reuses its verified session. The remote winner
cannot send an unsolicited block: it waits while the receiver sends hello and
bounded requests. The receiver performs cumulative-work comparison, all header
and body checks, replay, and router admission. Chain and notification protocols
have separate concurrent resource scopes but share the same inbound fixed-window
counter; total system/peer stream limits account for both. Neither handler is
installed on default hosts. Outbound notification workers coalesce repeated
wins to one pending prompt per peer and use a bounded total deadline. Each
responder serves the immutable canonical path advertised in its handshake, so
a concurrently mined anchor cannot splice a different tip into that session.

Optional multi-base recovery uses no mutable global-tip catalog. A schema-1
forest root contains only its fsynced manifest and canonical lowercase
activation-base hash directories. Unknown names, files, symlinks, bases absent
from the v0 ledger, wrong boundary heights, and a database moved under another
base name all fail closed. A complete pending manifest is finalized after a
crash; an empty but fsynced tree directory is safely initialized. Each nonempty
database must independently pass the WorkChain schema/config/history verifier
before any block ID is indexed or any tip enters global fork choice.

The forest defaults to 64 trees with a hard maximum of 1,024. Its configured
logical history budget is divided by that maximum and applied to every tree,
so aggregate admitted history cannot exceed the forest ceiling without a
cross-database counter. Reopen rejects a tree already above its newly assigned
partition. Pebble/WAL physical amplification, free space, directory ownership,
and archival policy remain separate operator concerns.

CLI activation is fail-closed per data directory. `work-enable` requires the
exact genesis ID, refuses an activation height at or below the current v0 tip,
checks the exact 512:1 target ratio and bounded reward split, validates/creates
the forest first, then atomically renames and fsyncs a fixed-size immutable
profile. A complete pending profile is recoverable; a conflicting or malformed
profile is not overwritten. The presence of either final or pending marker
blocks ordinary status, balance, verification, mining, transfer, sync, serving,
discovery, and snapshot commands, preventing an operator from extending v0
through the selected boundary or reading stale v0-only state accidentally.

The isolated WorkGraph Pebble schema stores one activation checkpoint and, for
each later block, exactly one parent delta or bounded full-state replay
checkpoint. It never stores both for one node. Explicit maintenance defaults to
a 2,048-height interval and four retained non-base checkpoints; rotation swaps
the new checkpoint in while rebuilding an evicted checkpoint's parent delta in
the same synchronous batch. Immutable node/block/recovery key/value bytes are
counted against a persisted atomic logical history counter with a 64-GiB default
local limit.

Process-level crash injection covers both sides of all four synchronous batch
classes: node commit, replay-checkpoint rotation, stale-fork pruning, and the
canonical retained-floor transition. Each case is compared against independently
built exact old/new fixtures using tip,
state root, cumulative work, logical history, node IDs, and checkpoint IDs.
Every recovered database must also accept a new valid child. This proves batch
atomicity at those hooks; it does not model torn hardware writes outside
Pebble/filesystem durability guarantees or physical disk exhaustion.
Logical-history exhaustion rejects before batch commit while reads and reopen
remain available.
Every restart reapplies deltas parent-first and verifies state roots, ancestry,
fee-queue roots, cumulative hard work, selected tip, and the recomputed byte
counter. WAL/LSM amplification and filesystem free space remain separate
operator limits. A real subprocess is killed before and after the synchronous
batch boundary and recovers only the old or new chain. Explicit maintenance can
atomically delete a complete stale side-fork subtree only after every canonical
node and every branch reaching the local retention window have been marked.
The default fork window is 4,096 heights and zero disables this local operation.
Canonical history pruning is implemented but disabled by default. A version-0
statement binds network/genesis/activation/tree-base identity, one exact
selected tip, its ordered ancestry commitment and length back to the immutable
base, a predecessor statement ID, and an archive-manifest ID. Between two and
64 sorted Ed25519 signatures are carried, while the operator supplies a sorted
trusted set and quorum of at least two. Local WorkChain verification rejects a
statement after its anchor leaves the selected hard-work ancestry.

These attestations are operational evidence, not consensus votes, Sybil
resistance, data-availability proofs, or finality. Colluding or compromised
trusted keys can attest a manifest and then withhold its bytes; signatures do
not prove continuing availability or independent operator control. The
versioned manifest and chunks are content addressed and strictly bounded.
Verification rejects non-regular/extra files and replays the complete ordered
activation-to-anchor block stream against the caller's independently verified
activation base and consensus parameters. Restore never imports an archived
state image: it creates a temporary Pebble WorkChain through ordinary commits,
closes and fully reopens it, verifies the final tip and ancestry, then uses a
directory rename and parent fsync without replacing an existing destination.
Real process kills immediately before rename and immediately after rename but
before parent fsync recover to no published destination or a fully reopenable,
extendable database respectively. Pre-rename crashes may leave an unreferenced
temporary sibling directory; it is not accepted as the destination and remains
an operator cleanup concern.
An export recheck is only a point-in-time observation and does not freeze fork
choice; operators must run `VerifyChain` immediately before attesting.

Deletion requires a separate replica policy with 2–64 sorted trusted Ed25519
keys, a quorum of at least two, bounded receipt age, and minimum remaining
retention. Each signed receipt binds the statement, manifest, anchor, replica
location commitment, replay time, and expiry. Receipt creation performs a full
archive replay; authorization repeats full replay for every distinct
non-symlink directory, rejects duplicate paths/inodes/keys/location IDs, and fsyncs the
canonical availability bundle before pruning. Its symlink-resolved destination
must be outside every replica tree, so publication cannot mutate a copy that
just passed replay. This is point-in-time trusted
custody, not proof that operators, devices, or failure domains are independent
or that bytes will remain online.

Destructive archive maintenance no longer accepts a caller-supplied fixed time.
`workarchive.PruneCanonicalPrefix` takes a context and samples the live wall
clock before and after replica replay, after durable evidence publication, and
at the final prepared-batch boundary. The last check runs with the WorkChain
lock held, after ancestry/index/state/accounting work, so waiting for the chain
or preparing a large batch cannot carry an expired authorization into the
commit. It rechecks receipt age, exclusive retention expiry, inclusive minimum
remaining term, cancellation, and backwards wall time, including subsecond
regressions. The cheap last gate does not repeat full signature verification.
Inputs, trust sets, and archive directories must remain immutable during the
operation. Cancellation is not per replayed block and cannot undo an issued
commit. `VerifiedAt` means the last authorization sample, not the completion
time of the disk write; process suspension or slow storage after that sample
cannot be certified away. There is no new consensus timestamp or wire format.

The lower-level `workchain.Store.PruneCanonicalPrefix` remains a trusted
chain-local primitive, not a policy-enforcing public maintenance command. Its
`PruneCanonicalPrefixAuthorized` counterpart rejects a nil callback and discards
the prepared batch if the callback fails or returns a regressed/expired time.
An external mutable authority must be guarded through method completion;
checking a revocation flag once in this callback would still race retirement.
The current high-level path enforces freshness under its supplied static key
policy, not global revocation. See `CUSTODY_AUTHORITY.md` for the unclosed paths.

The new `node/custodyauthority` package is a bounded in-memory reference machine,
not a revocation deployment. Its fixed-size commands and co-signed entries bind
an independently pinned assignment and exact predecessor position. Consumer
control keys are disjoint from all evidence keys and the authority key. Only
the consumer that owns a pending ticket may sign its terminal disposition;
stop forbids new admissions, and retirement requires zero pending tickets plus
the original stop entry ID. No clock, disconnect or replay can release work.
This deliberately sacrifices cutover liveness for an unresolved consumer; it
does not add force-complete, leases or an operator reset exception.

The format assumes trusted consumer behavior and one durably ordered authority.
Signatures cannot prove a consumer waited for its last effect or prevent an
authority from signing forks. Its `NewState` must never be used to recover lost
history; replay requires independent assignment and exact sequence/head pins,
which establish that selected history, not that it is the latest remote history.
`ValidateNext`/`Apply` alone are not a persistence transaction.

The separate `node/custodyauthority/store` now serializes local history under a
lifetime kernel lock. Entry content is synced before no-replace publication;
the entries directory is synced before state apply and successful return. A
required write/sync failure exposes no result and poisons the handle until full
pinned recovery. `Open` never initializes missing data, accepts an unpinned
suffix or resets pending work. `Recover` permits only an independently retained
pre-attempt pin or its extension by exactly one retained co-signed attempt. Old
exact retries return current local state, not a fresh execution permission.
Unknown/partial/symlinked history is refused; bounded temporary evidence is
retained without promotion or automatic repair. A full temporary-evidence budget
can block drain writes; it is not an excuse to discard outstanding work.

This local adapter assumes stable owner-controlled paths and working kernel
locks, hard links and file/directory fsync. It does not protect against hostile
same-inode edits, copied roots/keys, an equivocating signer, unsupported/shared
filesystem semantics or simultaneous rollback of the root and its pins. Caller
pins and uncertain attempts need independent durable retention before restart.
The optional local `Coordinator` now supplies a distinct intent/pin journal:
it syncs one exact signed intent before an authority mutation and advances its
confirmed pin only after checking the local store's durable result and syncing
the confirmation. The journal is locked before the authority, both locks last
until close, and neither underlying writer is exposed. Root overlap and known
directory aliases, including case aliases, are refused before initialization.

Open replays the retained journal first and uses its confirmed position plus at
most one exact attempted entry to select authority recovery. It never submits
or confirms work merely on open, derives a pin from the authority's own head,
attaches fresh pins to an already used authority, or reconstructs missing
confirmed history. A prepared intent survives cancellation and cannot be
replaced by another command. Explicit resume only settles that intent; it never
asserts that a consumer's real effect has completed. Required I/O errors poison
the coordinator and expose no successful result. A bad acknowledgement identity
or position cannot advance a pin; this adapter currently accepts results only
from its private local store, not from an untrusted remote transport.

The coordinator is not an independent storage deployment, authorization service
or protection against shared rollback of both roots. Its unsigned local pin
envelopes and diagnostic snapshots are not execution permits or remote freshness
proofs. Callers must not turn an exact retry into duplicate consumer execution.
Process-kill tests are not physical power-loss or multi-host partition evidence.
There is still no authority transport or installed live acceptance integration.
All old runtime acceptance paths remain under their existing policies until
explicitly integrated. No authority entry is accepted as a replica receipt,
challenge, availability bundle or rebaseline proposal.

The optional WorkChain ticketed-prune primitive now binds the exact requested
floor and original result to an assignment/ticket in the same synchronous batch
as deletion. Its unsigned parameters are not proof of admission. Exact retries
return retained historical evidence without executing or authorizing again;
conflicting ticket reuse fails, and later maintenance cannot remove completed
result records. The first such effect atomically enables schema 5 so older
schema-4-only binaries fail closed. Results count toward byte and fixed-count
limits; there is no automatic recycling. An uncertain canonical commit poisons
public chain access until successful reopen; no successful result escapes first.

Live runtime integration still needs consumer intent retention, admission
verification, independent storage identity/pins, and completion only after its
last effect drains. An effect lookup is local evidence, not a remote permission
or a durable consumer terminal decision. In particular, absent results in a
freshly created, replaced or rolled-back database cannot justify retry or no-effect
completion.
The new primitive is not used by the live archive CLI or raw custody sessions.
Canonical record recovery checks shape/accounting and local floor/ancestry
consistency, not historical external availability or trusted-owner tampering.

The optional local `PruneExecutor` now retains a request before admission, binds
its canonical ID to the signed prune operation, syncs a start before the concrete
chain call, and syncs its matching result after the effect. `WithOperation` checks
the private coordinator's fully confirmed pending ticket and holds its mutex
through the action; no remote/caller-supplied snapshot grants access. Unknown,
completed, foreign or unconfirmed authority cannot start work. A signed admission
alone is insufficient. Lock order is executor -> coordinator -> WorkChain, and
callbacks must be synchronous, bounded and non-reentrant.

A retained start is not automatically retried. Recovery only inspects an already
committed exact chain result; absence/error never fabricates success or no-effect
completion. Cancellation after a successful effect cannot abandon result retention.
The executor never signs completion, releases a ticket by time, or treats process
death as drain evidence. Missing-result starts may block retirement indefinitely.
Historical result retrieval after retirement remains distinct from live acceptance.

These guarantees require owner-controlled journal and chain storage. In raw mode,
the request pin is not an independent pin of the latest stage. The optional pinned
constructor now writes each exact transition intent to a separate journal before
primary publication and confirms its durable result afterwards. During execution,
the start pin is confirmed before the chain call; the current-authority guard
remains held through the final result pin. A pinned root requires its matching
independent journal; raw-mode reopening, fresh-pin attachment and partial-root
recreation are refused.

Pinned open accepts only the confirmed exact prefix or its one known next intent.
It never publishes/confirms, reconstructs missing confirmed history or chooses a
head from the primary. Pending pins block ordinary calls until explicit resume;
resume only retains/confirms that record, never executes pruning or signs ticket
completion. Even an intent for a never-executed start is irrevocable and can keep
the ticket pending indefinitely. A retained result intent comes from the prior
concrete effect, not from absence in a replacement chain.

Independent primary-prefix rollback detection depends on the pin root remaining
intact. Shared rollback, copied/replaced chain databases and same-inode hostile
edits remain outside the guarantee. A random pair binding is not physical storage
identity or fencing of copied roots. Independently protected storage/access-control
deployment is still required. Do not recreate journals as recovery or reuse tickets
on another chain database. A one-assignment guard does not establish the custody
quorum across every replica assignment. Physical storage identity/pins, durable
no-effect disposition for Started work, network authorization and all live
acceptance-path adapters remain deployment gates. Full archive verification/freshness
remains the trusted caller's obligation; the helper must not be exposed as a public
policy bypass.

An independently pinned executor can now explicitly cancel **before any start
intent** under its current pending-ticket guard. Independent intent, a distinct
terminal cancellation record and confirmation make that local branch irreversible;
raw journals cannot use it. It accepts no database handle, inspects no absence and
cannot cancel Started/Succeeded work. Unconfirmed start intent is also ineligible,
even if the primary still appears Admitted. Resume can finish an existing exact
cancellation, never replace a start with one or execute cancelled work. A separate
consumer-signed completion and authority decision are still required to close the
ticket. The retained cancellation ID is not itself a completion or a reusable grant.

The 138-byte version-0 cancellation binds assignment/request/ticket/pair but is
unsigned. Its decoder proves shape only, not that this decision was made or that
another copied executor never acted. Correctly retained independent pins detect
primary-only rollback; shared rollback, copied roots/keys, hostile owner edits and
unfenced remote consumers remain outside the guarantee. Mixed start/cancellation
branches and records following cancellation are rejected. Older binaries reject
the new terminal filename; no fallback, history repair or operation reuse is
permitted. Unknown Started outcomes can still block retirement indefinitely.

`PruneExecutor.Complete` adds a separate local completion boundary for independently
confirmed `Succeeded`/`Cancelled` executors. It accepts only an externally signed
Complete matching the exact assignment, consumer, ticket and retained outcome ID,
and holds executor/coordinator guards until the authority decision is independently
confirmed. It never signs, executes, queries database absence or updates a stale
signed head. Raw, Started and unconfirmed executors cannot complete through it;
even an existing chain effect first needs explicit executor recovery/confirmation.
An interrupted exact entry may be retried, never replaced by a different pending
command. Historical completion does not refresh authority or permit another effect.

This remains a trusted opt-in adapter. The low-level signed-command coordinator
can still be called directly and is not an external-effect verifier. No live
audit/serve/prune path or network service is switched to this adapter by its
existence. Copy fencing, all-replica coverage, remote transport and independent
deployment remain required; local completion is not distributed exactly-once.

The opt-in `/outcomemesh/prune-completion/0` protocol only delivers an already
co-signed completion to the original colocated pinned executor/coordinator.
It authenticates independently pinned transport peers, keeps a separate bounded
rate/concurrency/memory scope and remains disabled until explicitly installed.
Its concrete server waits for one fixed-size request and EOF before any authority
write. Only the terminal-outcome adapter may complete the ticket; a transport
allowlist alone does not verify effects or replace either control signature.

The response follows independent authority confirmation and binds the exact entry
to a fresh exchange nonce. It is not a signed portable proof, current-authority
snapshot or durable client receipt. Lost/partial/invalid replies, cancellation and
disconnection remain unresolved, never a no-effect disposition or permission to
reuse a ticket. A confirmed decision is not discarded when its reply is lost.
The low-level exchange supplies no remote admission/execution/signing/retirement,
stale-head refresh, automatic retry/failover, durable client outbox or daemon
handler. The live audit/serve/prune paths still require current-authority
integration across every required assignment; copied and independently running
owners remain unfenced.

The separate opt-in `CompletionOutbox` wraps that low-level client with one
immutable, externally ID-pinned command and both transport identity pins. It
retains the intent before sending and returns success only after a checked
QUIC response is locally published and synced. Open never sends, staging files
never become confirmations, and only an explicit exact retry can resolve a
missing reply. A retained local acknowledgement can be returned offline; this
is historical delivery, not evidence of current authority or another permission.
No arbitrary response callback, reset/drop API or automatic retry is exposed.
Failed local publication poisons the writer until exact reopen. The checksummed
receipt is not signed proof and cannot defend against a malicious journal owner,
copied roots, or shared rollback. Losing only an ACK may make the client retry
the original command; it cannot authorize a new effect. Physical separation,
all-assignment live enforcement and safe runtime wiring remain deployment gates.

The separate opt-in `/outcomemesh/prune-admission/0` protocol permits only an
externally co-signed prune Admit for the original executor's already retained
request. `PruneExecutor.Admit` validates that binding before authority mutation,
then holds executor/coordinator ownership across both independent confirmations:
authority admission first, executor admission binding second. A reply cannot
escape after only the authority step. Partial success leaves the ticket pending
and the exact command unresolved; it does not cancel, complete or run an effect.
Only the exact retained admission transition may resume through this API, never
a start, result, cancellation or unrelated authority attempt.

Fixed request/reply formats are distinct from completion, and actual request EOF
is mandatory before mutation. Peer identity pinning, both command signatures,
fresh nonce binding and independent rate/concurrency/memory budgets remain
required. Admission traffic cannot spend completion's budget. Historical ACKs
remain historical after Stop/Complete/Retire; Execute must still acquire the
original coordinator's live pending-ticket guard. No generic remote execution
grant, cached-state fallback, remote request creation or effect callback exists.
The low-level client does not retain intent/receipt or automatically retry.
The separate `AdmissionOutbox` retains one externally signed prune Admit and
both peer pins before sending, then syncs the checked ACK before success. Its
formats and typed ACK are distinct from completion. Open sends nothing; only
explicit retry can send the same command with a fresh nonce. It cannot replace
a rejected request/head or turn a historical ACK into an execution permission.
Request bytes remain in the separately prepared server executor; client intent
validation does not prove server preparation or current authority. A local
publication failure poisons the writer until reopen. A visible final receipt
is re-synced, never inferred from staging data. Receipt-only rollback remains
undetectable without an independent receipt-position pin: it makes delivery
unresolved, not permission to execute. The checksum is not malicious-root defense.
No live audit/serve/prune path is installed by these opt-in library APIs. Physical
root separation, copied/shared rollback, signing-key ownership, fencing and
all-required-assignment enforcement remain external/open gates.

The optional command runtime now owns all four existing coordinator/executor
roots and the dedicated transport, without exporting writer or host pointers.
Open neither listens nor resumes. Explicit Start validates the canonical key
against its external transport pin; both peer identities must be separate from
all assignment control/evidence roles. Cancellation and local storage uncertainty
close the handler-admission gate, interrupt the network and drain accepted
handlers before any journal lock is released. A failed command cannot trigger
automatic recovery, effect replay or cancellation. Malformed requests do not
turn into service-level storage failures.

Typed one-shot delivery runners own an existing outbox before opening transport
and close transport before releasing that journal. Cached ACKs need no socket
but still require the pinned client identity. Missing roots are never created.
Cleanup errors return no ACK and remain unresolved even if receipt/decision
history was already retained. No private key is persisted in these journals;
memory copying is not a secure-erasure guarantee.
This command-only runtime supplies no execution API or default operator/daemon
wiring. Physical isolation, copied keys/roots, all-assignment live enforcement
and active cutover remain open; closing a local runtime does not fence a copy.

The explicit command-only prune CLI requires canonical bounded assignment/seed
files, external assignment/request/intent IDs and prepared roots. Final-file
symlinks, malformed inputs, unknown/positional/repeated flags and key/pin
mismatches are rejected. It uses existing bounded transport settings, exposes
no signer or WorkChain handle and never creates a missing journal. SIGTERM or
interrupt follows the runtime's ordered shutdown. A stdout failure can follow
a durable receipt: it returns an error without erasing evidence or retrying.
The command lifetime subscribes to Unix SIGPIPE so a broken stdout returns EPIPE
through cleanup rather than terminating before journal owners are drained.
Printed/cached ACKs remain historical, not live execution grants. The input
reader does not establish OS owner/ACL protection, physical isolation or memory
zeroization. The operator boundary is documented in `PRUNE_COMMANDS.md`.

The explicit fixed-secondary service/CLI derives original primary and selected
target assignments from a bounded, independently pinned inventory. It checks
role separation across every assignment and archive trust key, and disjoint
existing owner roots plus the inventory parent before acquisition. Admit/both
own the executor and both coordinators; complete owns only executor and target.
Static content checks repeat before listening and each request keeps its existing
guarded live checks. Only selected protocols are installed. Ordered shutdown
stops new handlers, interrupts network I/O, waits for accepted handlers and then
releases all selected journal owners. Its private wrapper exposes no maintenance,
raw owners, signer or WorkChain. Stop/drain before separately owned offline work,
then explicitly reopen completion; no mode performs work or automatic recovery.
This is command ownership, not reviewed effect handoff or copied-owner fencing.

Offline preparation is a separate explicit boundary, not a transport fallback.
Bootstrap requires two absent, disjoint roots and holds pins before the writer;
it never reinitializes partial data or attaches fresh pins to an old authority.
Review checks placement only, even if existing journal contents are invalid.
Verify may re-sync retained evidence but cannot append/confirm/resume an attempt.
The two pair operations are not a four-root atomic transaction or physical fence.
Reviewed consumer signing and independent authority co-signing require exact
existing signature-message IDs, pinned request/evidence files and role-specific
seed paths. No key is read until the input and review IDs match. Signatures and
terminal files remain historical bytes, not proof of the executor's current or
durably committed state. An outbox review binds an already co-signed entry and
separate transport pins; explicit create accepts only a new typed root, and
verify cannot send. All owners close before success output. Failed stdout leaves
published artifacts/roots intact; it never triggers reset, replacement or retry.
The artifact publisher may create output parent directories; operators must
protect those paths. See `PRUNE_PREPARATION.md` for the trust and recovery rules.

The maintenance capability parks command transport without releasing
the four root locks. It does not expose raw owners or Execute. Review and local
CancelBeforeStart hold lifecycle -> executor -> coordinator guards, and the exact
review ID is recomputed under those guards before the existing pending-ticket
check and durable cancellation. Detached snapshots cannot replace that check.
Unknown Started outcomes and unconfirmed transitions remain ineligible; no timeout
or lost connection establishes cancellation. A successful cancellation changes the
review ID but still requires separate authority completion. Storage uncertainty
survives into Close. The caller must explicitly close a handed-off capability:
its lifetime is no longer tied to the former transport context. This local lock
continuity neither fences copies nor supplies all-assignment/physical-storage
authorization. Opt-in local operator wiring now uses an exclusively owned stdin
pipe on macOS/Linux, never a remotely reachable endpoint. The dedicated inherited
read endpoint is duplicated close-on-exec, made nonblocking and registered with
Go's poller before acquiring journals; otherwise inherited stdin can keep Close
blocked behind Read. Parent cancellation, service failure and EOF supervise the
same owners after transport handoff. Default mode does not adopt stdin, and
unsupported native platforms reject live control before opening roots.
The 96-byte LF-terminated grammar has no generic action or implicit review; a
bad command ends the local session without undoing earlier durable work.
Standalone offline maintenance takes no key/socket and requires an exact external
review ID for cancellation. Canonical terminal bytes printed on stdout remain
historical evidence, not portable current authority. Broken/short output after
cancellation preserves ambiguity and requires new review, never automatic retry.
Separate offline recovery requires a distinct review digest and explicit action.
The digest binds both independently confirmed and observed prefixes, pending
intent IDs/positions and retained terminal identity under the same owner guards.
Only one already retained transition on one layer may finish: exact-request Admit,
exact-terminal Complete or executor admission/start/result/cancellation. Unrelated
authority intents and simultaneous pending layers are blocked. No new command is
signed or inferred; recovered Started remains unknown and cannot execute or cancel.
This does not clear sticky errors, reset roots, fence copies or grant live storage
authority. A changed observed or confirmed prefix invalidates the review;
missing output does not authorize
automatic retry. Normal open, review/cancel and live stdin never initiate recovery.
Authority/executor on-disk, signed and wire encodings are unchanged; the new hash
domain is local historical review only. Actual archive acceptance remains gated;
see `PRUNE_MAINTENANCE.md` for the action matrix and failure procedure.

The opt-in local `ExecuteArchive` adapter pins exact checkpoint/trust/timing
configuration, request and independent executor/storage pair IDs, and every
selected initial-receipt assignment. It rejects incomplete/relabelled owners
before work, locks all coordinators using immutable constructor assignment IDs,
and keeps those guards through replica replay, final storage-time authorization
and independently confirmed executor result. Sorting caller labels alone would
allow inconsistent multi-lock order; the immutable owner pins are checked first.
Bounded input slices are detached before waiting. Position-pinned storage is
mandatory, and all original root paths, replica directories and the dedicated
evidence directory must be disjoint. `StorageRoots` is inspection, not a lease
or physical-identity proof. These checks neither fence copied pairs nor establish
physical failure-domain independence.

The original mode accepts only exact initial receipts; a renewal under an old key
cannot skip lineage/assignment review. Separate `ExecuteArchiveWithLineage` requires
a distinct protected policy ID and full canonical prefixes from each pinned initial
receipt to the exact selected request receipt. Reconstructed assignments bind the
manifest, custody policy and auditor set; every sequence, predecessor, challenge,
sample batch, proof and renewal is verified at its signed historical response time.
The aggregate cap (1,024 entries and 256 MiB encoded evidence) is checked before
large buffer copies. All accepted evidence slices are detached, and all live
authority guards remain held through verification and the final effect/result.
This is neither a latest-head/durability proof nor a journal activation path;
historical verification never substitutes for live freshness or authority.
The managed adapter shares full archive replay and
fresh wall-clock checks with the legacy gate, but matches every retained floor
field before publication, preserves original request VerifiedAt and samples again
inside the prepared deletion batch after storage-intent I/O. Errors after Started
remain unresolved; absence does not authorize no-effect completion or retry.
Archive execution leaves all authority tickets, including secondary ones, pending.
Explicit local completion adapters can separately drain each actually admitted
secondary from a confirmed primary success or pre-start cancellation. Success
requires the original retained inventory binding; cancellation retains its original
request/ticket/executor scope. Prepared inventory and lineage retention are also
implemented. These local records are not portable all-assignment certificates.

Reviewed lineage extraction now reads existing journals under every selected
source's permanent lock, with exact independently pinned journal-only checkpoints.
It verifies canonical scope, full tree and replayed state, budgets all selected
winning bodies before output allocation, copies detached bytes and rechecks the
trees before releasing ownership. Context-aware private helpers cancel lock
waiting, traversal, replay and streaming reads; existing callers keep their prior
behavior. Individual filesystem syncs and bounded verification remain synchronous.
The inventory wrapper derives assignments/selected receipts solely from external
inventory/policy pins. Source checkpoint IDs are retained separately: the unchanged
evidence envelope does not commit them or the source paths. Successful extraction
is a historical snapshot, not Audit admission, current permission, a unique-head
proof, repair, activation or an effect. Later evidence publication occurs after
source locks have released. See `PRUNE_ACCEPTANCE.md` for the exact boundary.

The offline lineage extraction command reads bounded strict source-path JSON
and existing canonical artifacts under independent inventory/checkpoint pins.
Assignments, selected receipts and auditor trust keys come from that inventory.
Review displays canonical scope and computes a local digest over its pins,
ordered source/input paths, output destination and resulting evidence ID. Extract
recomputes it before the existing no-replace publisher; the parent must exist
outside every source journal and input file. Verify is a separate content/pin
check and opens no source, so retained artifacts remain verifiable after journal
advance or removal. This local digest is neither a signature nor execution
authority and does not change the retained evidence format. Output failures
preserve published evidence for exact retry or explicit verify. No signing key,
current authority/executor/database owner, checkpoint capture or effect is added.

An opt-in owned prepared-archive effect service now opens the original protected
executor, all selected original coordinator pairs and position-pinned WorkChain
after preceding command owners have drained and closed. Canonical disjoint
placement is checked before acquiring owners; pins precede writers, coordinators
open in assignment-ID order, and partial failure releases in reverse. Its private
lifecycle holds every owner across explicit review and guarded effect/result,
with Close waiting for accepted synchronous execution. Caller configuration and
review slices are detached. The local comparison ID commits all paths, content
pins, activation/storage/replay configuration, tickets and confirmed positions.
It is rechecked under executor/all-coordinator guards before archive replay and
again after evidence fences, before the existing final live-time authorization.
Lineage bodies are reloaded, and the exact retained file is rechecked and synced
before start; cached bytes cannot replace missing evidence. Pending, Started and
terminal states cannot become new execution candidates. No raw owner, arbitrary
callback, automatic recovery, completion, new effect encoding or network endpoint
is exposed. This local lifetime does not certify current authority to a remote
consumer or fence copied owners, keys, databases or pin journals.

Operator CLI command/effect handoff, Audit/Serve acceptance and physical/cross-host
enforcement remain open. This is not a CLI or remotely exposed effect path; see
`PRUNE_EFFECT_RUNTIME.md` and `PRUNE_ACCEPTANCE.md` for the exact boundaries.

The opt-in storage-incarnation mode adds a narrower local guarantee. A fresh
caller-selected ID is atomically bound to a new schema-6 WorkChain database;
reopen needs the independently retained ID and never initializes missing data.
Bound requests require independent executor stage pins, commit that ID before
authority admission, and check it before start and under the actual prune lock.
The result retains the ID in the same deletion batch (schema 7); wrong-ID or
unbound effects cannot replay in that database. Legacy unbound pruning is refused
on bound handles. Existing raw schema 4/5 and version-0 evidence stay unchanged.
An ID copied with the database is still the same logical incarnation; reusing it
to initialize lost/replacement storage defeats this distinction. Tests explicitly
preserve an old copy, show its ID still matches, and verify that missing results
leave Started work pending without re-execution or completion. This is not a
physical-device identity, fencing token, monotonic database position or backup
freshness assertion. No-effect recovery and production runtime integration remain
open; historical Succeeded evidence is not live authority or current storage proof.

The separate opt-in schema-8/9 WorkChain mode retains an independent per-batch
position journal. Every logical mutation publishes a synced exact intent, commits
its fresh opaque position in the same Pebble batch, then confirms independently
before success. Final prune authorization follows intent I/O. New disjoint roots
have a random pair binding and two lifetime locks; raw/incarnation-only open APIs
cannot reopen this mode. Recovery verifies both the bounded journal and complete
database state. Database-only rollback or an unexplained extension is refused
when the independent journal remains intact. One exact unconfirmed successor
gates ordinary operations: explicit resume can only flush and confirm an already
present batch. A database still at the prior position stays unresolved, including
after authorization denial. Missing effects are never permission to repeat work,
discard the intent or sign completion. Executor preflight/recovery respect this
gate; historical Succeeded results remain historical evidence.

The commit token does not hash database content and is not a physical identity,
hardware monotonic counter or authenticated storage attestation. Current database
copies retain their positions; a copied pair can have independent owners, and
shared rollback can hide history. Journal checksums are not signatures. Full
history is verified at reopen; live checks rely on trusted-owner immutability of
earlier entries and verify the retained tail and permanent root inodes. Independent
deployment and correct file/directory sync semantics remain external assumptions.
The local journal has a hard 65,536-transition/128-staging-file ceiling with no
reset or garbage collection. It is library groundwork, not a production WAL,
power-loss validation, safe no-effect disposition or all-replica authorization.

Availability files now use no-replace publication. Exact retries verify and
fsync the existing regular inode; conflicting bundles, damaged files, and
symlinks are rejected without replacing the path. A failure after publication
preserves the evidence even though no floor advanced. Retry performs the full
live checks again; existence of the file cannot authorize deletion. Keep a
separate destination for each evidence ID. These guarantees assume exclusive
operator control over the containing directory; they do not prevent an owner
from replacing or rolling back the entire evidence tree.

Freshness renewal uses a distinct sorted trusted-auditor policy. The auditor
signs the statement, manifest, predecessor receipt, issuance/expiry times,
requested renewal deadline, a 32-byte `crypto/rand` nonce, and the resulting
sample IDs. Verifiers recompute those IDs by ranking every manifest descriptor
with a domain-separated hash of the manifest, predecessor receipt, nonce, and
descriptor ID, so the replica cannot substitute easier objects. At most eight
samples and 64 MiB are returned. The replica validates the challenge, returns
the exact manifest-checked batch, and signs its canonical digest and response
time. Receipt v1 then commits the predecessor-receipt ID, proof ID, response
time, and the deadline already signed by the auditor. This prevents one proof
from being attached to another receipt or a different retention term. Challenge
lifetime, response freshness, and renewal term are policy-bounded, and receipt
v0 decoding remains byte-compatible.

The dedicated `/outcomemesh/workarchive-custody/1` QUIC-v1 protocol is opt-in,
pins the replica transport identity, and admits only a canonical allowlist of
auditor transport identities before charging its independent rate window. One
finite stream carries exactly challenge, batch, proof, and renewed receipt,
each with a deadline and a type-specific pre-allocation bound. Transport keys
and portable auditor/replica signing keys are deliberately separate. After
verification the auditor closes the stream; the replica waits for that bounded
EOF before a one-shot process exits, avoiding loss of the final QUIC frames
without introducing another application message. A valid
exchange proves that the trusted replica key returned those sampled bytes at
that time; it does not prove physical storage, prevent proxy retrieval, establish
operator independence, or replace the full local replay required at pruning.
Within one replica session the signed response is cached before transmission;
the same challenge retries idempotently and a different challenge for that
predecessor cannot create a sibling receipt. The durable session persists the
complete verified challenge/batch/proof/renewal tuple before transmission using
a fsynced mode-0600 temporary file, atomic no-replace link, and directory fsync.
Restart accepts only a canonical record valid for the exact manifest,
predecessor receipt, and trusted-auditor policy. Thus a retry replays the first
signed outcome and a different challenge cannot create a sibling even across a
process crash. The auditor similarly persists its challenge before dialing and
its verified response before publishing the renewed receipt. Corrupt,
conflicting, symlink, and partial records fail closed.

Journal mode fixes the manifest, original receipt, and complete custody-policy
digest in an immutable header. Replay verifies every slot, content ID,
predecessor, signature, sampled batch, and receipt extension. A permanent file
lock serializes disk operations across processes and releases on process death;
the fixed sequence slot commits the first response before network transmission.
Body segmentation deletes no history and startup repairs an interrupted active
directory recreation. A retry after challenge expiry is restricted to an
already committed response that still passes the original proof-age limit.
The journal is local evidence, not a remote rollback anchor: deleting a complete
valid suffix or restoring an old complete copy requires an independently retained
checkpoint to detect. Operators must protect the journal and lock inode from external
mutation and use a filesystem supporting the documented durability primitives.
Local growth admission counts logical bytes and all journal paths, including
orphan bodies, duplicate hard links, pending files, and directories. Body/slot
temporary-link reserves are checked together while holding the journal lock;
reduced caps do not invalidate committed evidence. A streaming preflight imposes
a hard replay path ceiling before path/slot indexes are allocated. All writers
must use the intended local limits: they are per handle, not a volume quota or
an immutable protocol rule. Other disk consumers and filesystem metadata remain
outside these counters. External timers, physical free-space/inode monitoring,
scheduled backup/pin operations, and long-outage reconciliation remain deployment
concerns; see `CUSTODY.md`.

Custody checkpoints bind both the replayed journal and the entire auditor
artifact tree, not just the head. The permanent artifact lock precedes the
journal lock and covers the auditor's pre-dial signed request as well as its
local recovery. All writers must use the same artifact/journal pair and honor
these locks. The verifier requires an externally supplied nonzero checkpoint
ID, rejects substitutions and exact-inventory mismatches, and does not repair
the candidate. Artifact hashes preserve bytes; they do not validate arbitrary
pending files as decisions. Root names and file metadata are not authenticated,
and no protection against a hostile concurrent filesystem writer is claimed.
Standalone checkpointing does not provide external pin freshness, copying, storage
independence, or consensus finality. A stale or missing independent pin cannot
establish the latest state. A later known decision requires reconciliation,
even when an older backup verifies. Retain all evidence, including partial
files, and never run two restored copies as concurrent decision authorities.

Managed local backup creation now holds both source locks while copying all
evidence into independent file/lock inodes. The destination is reserved with a
no-replace mkdir; no existing directory is adopted. Files and directories are
synced and the copy is fully replayed before the final checkpoint marker is
published. Verification requires the independent pin, an existing bundle lock,
the bounded root layout, and an exact evidence inventory. Failed attempts are
preserved, not automatically resumed or deleted. Completed retries must also
match the current locked source. Per-tree byte/path ceilings bound the copy but
do not reserve physical space or inodes. This is a local point-in-time backup,
not a scheduler, independent pin service, remote-participant freeze, or safe
cutover protocol. Restore into a new location and leave the retained bundle
unchanged; power-loss, physical disk exhaustion, and cross-host campaigns remain.

The optional backup-pin journal is a separately managed operational authority.
Fixed-width records link checkpoint IDs through gapless, no-replace sequence
slots. A permanent pin lock spans head replay, bundle verification, evidence
comparison, and append; publishers must supply the previously observed pin ID.
Two different updates cannot silently overwrite each other. An exact retry of
the last checkpoint may use its current or immediately preceding pin ID and
still fully verifies the candidate. Promotion requires the prior pinned bundle:
same trust/header and scope, prior chain ancestry, all retained body IDs, and
unchanged old pending/artifact paths and bytes. Rotation can move bodies without
losing content. This check neither authorizes compaction nor turns arbitrary
artifact bytes into valid decisions.

Pin records are not signed; authorized storage writes and a genuinely independent
failure domain are trust assumptions. Path/alias separation rejects overlap with
the supplied backups, but cannot prove different devices, accounts, hosts, or
protection from a privileged concurrent filesystem writer. Keep pins outside
live evidence too. Latest-pin verification holds the pin lock and rejects any
different checkpoint, including a valid older backup. Rollback of both the pin
store and backup remains undetectable unless the caller supplies a newer pin ID
retained in another trusted domain. Missing or damaged pin stores never fall back
to candidate metadata or silently reinitialize. A completed backup is not the
current pinned backup until a separate pin append succeeds; newer unpinned local
or remote decisions still require reconciliation. No scheduling, storage service,
cleanup, authority fencing, or cutover is installed by these commands.

Read-only outage reconciliation accepts separately supplied checkpoint IDs for
an auditor bundle with artifacts and a replica-only bundle under the same trust
baseline. It verifies both bundles and keeps their existing locks throughout
comparison. Exact committed slot IDs determine the common prefix; a longer
divergent chain is never selected. Canonical historical artifacts are compared
byte-for-byte with committed decisions. A pending response must match the signed
intent and, when both copies contain it, the full response bytes. An orphan is
not a committed replica response. Unknown and partial files remain evidence for
review, not authorization to generate another request.

Historical verification uses the original signed response time. Separate report
fields evaluate proof age and retention expiry at the caller's assessment time;
they neither weaken live session checks nor attest that the clock or replica is
currently trustworthy. Reports always deny automatic resume and are not consumed
by writers. A missing response in a pinned snapshot is not proof that the remote
participant never committed one later. Even matching snapshots cannot authorize
cutover, historical import, or a new baseline without later-evidence collection
and fencing. No files, receipts, challenges, pins, or services are created or
changed by inspection; existing writable lock handles and fsync are still used.

The historical handoff command writes only a separately named package outside
both source bundles. Its unsigned envelope preserves the exact next committed
replica entry and binds both complete checkpoint values. It requires a matching
auditor prefix and retained intent, including byte equality of any local
response; absent intent, larger gaps, conflicts, unknown/temp evidence, missing
historical artifacts, and orphan bodies fail closed. The ID selects exact
historical evidence, not a signed approval or proof of an operator's review.
Export requires an explicit reviewed ID and revalidates both source bundles
under their existing locks before any destination creation. Verification needs
all three independent IDs and both source bundles; decoding an envelope alone
cannot verify local intent or reconstruct the whole committed prefix.

Publication uses independent file bytes, file/directory fsync, and a no-replace
link. Incomplete packages, including partial temporary writes, are retained and
cannot be resumed in place. A completed exact retry creates no new temp file;
at most one byte-identical abandoned commit link is accepted. Unknown package
files or changed payloads fail verification. Original response times and live
proof-age checks are unchanged. No journal is appended, no key is used, no pin
is promoted, and no old participant is fenced. The package is not a live record
or journal entry. It must not be manually unpacked into a decision directory as
a substitute for the separate historical-only application or future cutover
workflow.

Explicit historical application writes only a new directory, disjoint from the
handoff and both backups. All original bundle and package locks span creation.
The source header must be live v0; it is never copied as a live header. A new
historical-only v1 header preserves manifest, policy, and initial receipt while
binding the reviewed transfer ID. Journal payload copying and the single
private historical append occur only behind that header and the usual ordered
artifact/journal locks. Public initialization rejects it before repairing any
child directories; append, rotation, and journal-backed serving also reject it.
Older v0-only header decoders reject its version. There is no activation flag,
header downgrade, key rotation, pin promotion, or source retirement operation.

An application marker is published only after independent result replay and
exact source-plus-overlay verification. The only allowed differences are the
linked header, the original next entry/slot, and its canonical challenge, record,
and receipt artifacts. Extra paths, duplicate body locations, and changed earlier
files are not accepted merely because a replacement checkpoint hashes or replays
correctly. Completed retries recompute that exact delta; incomplete directories
are preserved and require a fresh destination. Source-based verification also
requires the independently retained application ID. A process kill before
completion leaves no usable live journal, even when a body or slot already
exists. This is not power-loss certification or a fence against another host.

The historical-only header is an accidental-use guard under the existing
exclusive-operator filesystem model, not access control against someone who can
rewrite/copy evidence and ignore independent pins. It does not stop a separately
running original participant or establish the latest remote decision. Do not
extract a receipt into an unjournaled service or downgrade the header to evade
it. Future linked rebaseline and enforceable cutover must establish fresh
authority separately; original proof age and receipt expiry are unchanged.

With an explicitly non-zero local canonical-retention policy, one synchronous
schema-4 batch may replace the strict prefix before the selected archive anchor
with validated headers, turn the anchor into a full-state retained floor,
persist the exact statement/manifest/availability IDs, and update the checked
history counter. It refuses a shallow anchor or any live side branch that does
not descend from the new floor. Reopen derives IDs, parent order, ASERT target,
timestamp history, cumulative work, ancestry commitment, and floor state before
accepting later deltas. Pre/post-batch process kills recover exactly the old or
new extendable database; injected pre-sync failure is atomic.

This operation creates a local finalization horizon: a future heavier fork
diverging below the floor is unavailable and rejected, even though the archive
signatures create no network consensus finality. A pruned node can build the
next complete archive through `ComposeDirectory`: it fully replays
the exact predecessor checkpoint/manifest recorded by the unchanged floor,
streams those content-addressed blocks followed by the selected locally
executable suffix, and rechecks floor metadata plus ancestry immediately before
non-replacing rename and parent fsync. Corruption, a nested destination, an
empty suffix, or a pre-publication reorganization fails without output. The
result is independently restorable and can authorize a later floor after new
attestation and custody receipts. Version-1 chunks omit the terminal archive
anchor from their own canonical bytes; network/base/index/first-height and full
block bytes remain bound, while the manifest binds their complete order to the
terminal anchor and ancestry commitment. Composition preserves every predecessor
chunk boundary, rejecting a smaller target chunk policy, so all prefix IDs stay
identical and only suffix content IDs are new. Ordinary replay still validates
the complete chain. Version-0 anchor-bound archives remain accepted. Standalone
directories still write all referenced files. A separate local object store
deduplicates immutable v1 chunks by content ID. Reopen rejects extra,
non-regular, non-canonical-name, hash-mismatched, or non-canonical chunk files
and enforces configured object and byte ceilings. Import first performs full
archive replay. Missing-object requests and responses are bound to one exact
manifest ID, strictly sorted and duplicate-free, limited to 64 objects and
64 MiB of chunk payload, and every received object is checked against the
manifest before no-replace publication. A complete archive is materialized
outside the store and fully replayed before atomic directory publication;
partial downloads never become an archive. The object store and serving peer
remain untrusted availability caches, not consensus or state-snapshot inputs.
The opt-in `/outcomemesh/workarchive/1` QUIC-v1 binding requires the client to
pin the server's authenticated Ed25519 transport identity and rejects clients
outside a canonical operator allowlist before consuming the protocol rate
budget. Archive streams have separate resource-manager scopes, one concurrent
stream per peer and four host-wide by default, plus fixed windows of one stream
per peer and 16 globally per minute. A stream is finite: at most four batches,
256 objects, and 256 MiB of chunk payload. Repeated request IDs and responses
that differ from the exact request fail closed. Valid objects preceding a bad
tail remain safe, reported, and resumable, while the session fails. These
ceilings limit protocol amplification but do not prove that an allowed peer is
an independent or durable replica. The server CLI reconstructs the activation
base from its local node, verifies the configured checkpoint under a 2–64 key
trust set/quorum, fully replays the exact source, and only then imports objects.
The pinned client persists every accepted object through the same no-replace
validator; incomplete runs are resumable, while complete runs materialize and
fully replay before atomic publication. Existing outputs are reverified rather
than overwritten. The fourth response is followed only by bounded client EOF,
preventing one-shot process exit from truncating final QUIC frames. Physical
disk-exhaustion tests, long filesystem soaks, and automated challenge
scheduling/evidence retention remain activation blockers.

The activation boundary is not a locally finalized block. The isolated router
can create a separate v1 tree for every known v0 node at height `H-1` and uses
the same cumulative-hard-work comparison across all of them. A more-work v1
branch rooted in a formerly losing v0 node can therefore reorganize the selected
chain. The router rejects v0 at or above `H`, v1 below `H`, unknown v1 parents,
and consensus-parameter disagreement between versions. This logic is not yet
connected to persistent multi-base recovery or the public chain session.

Controlled-tie campaign state is operational evidence, not consensus state,
but continuing from different observer tips would invalidate the calibration.
Checkpoint publication is a separate, explicit approval step. The local publisher
API and `work-telemetry-tie-campaign-publish` command require an independently
chosen checkpoint ID as well as the trusted plan binding; deriving an ID from an
unreviewed artifact is not independent approval. Complete checkpoint and marker
files are synced and linked without replacement, in that order, with a directory
sync after each. Exact retries recheck and sync existing bytes; a post-link error
may already be visible. Final paths are never truncated to publish an update.
Readers still reject an empty or malformed final marker rather than retrying it:
the 2026-09-07 process failure was traced to a test publisher exposing that empty
create/write interval, not a lost confirmation. This assumes trusted-owner local
directories and does not provide multi-directory atomic distribution, symlink
fencing, independent access control, shared-rollback or physical-media protection.
To prevent observer divergence, only a slot with no begun delivery may be skipped:
coordinator publication must remain unconfirmed, every observer waits through the same
receipt-closure grace, and the skipped sequence is fsynced before the next slot.
Once delivery begins, a missing ACK is treated as possibly admitted forever.
An observer that has persisted exactly one sibling also stops forever instead
of converting the slot to `NoPair`; an injected process kill after the first
block commit proves the pending candidate survives restart. Receipt commit and
coordinator knowledge use separate durable markers, so an ACK/confirmation
crash retries the receipt rather than the blocks. The observer now returns a
fourth protocol message only after its confirmation marker and containing
directory are durable; the coordinator does not journal that observer before
reading it. Unit writer faults and real separate-process permission faults cover
both pre-commit and rename/link-complete-but-directory-fsync-error boundaries in
the coordinator journal and observer marker. These checks still do not emulate
physical media corruption, kernel writeback loss, or a truly exhausted device.
When the marker is exact but its final ACK is absent, a read-only audit
identifies the one recoverable tail and an explicit offline command may journal
only that cryptographically and structurally proven ACK. It never advances the
chain and refuses all blocking evidence conflicts.
Between slots, an abruptly restarted observer can leave a reusable QUIC session
stale at the coordinator. Delivery permits exactly one reconnect after an I/O
failure: it closes only the route's identity-pinned peer, repeats the authenticated
handshake to the same advertised transport ID, and resends the immutable pair.
The durable observer path makes that resend idempotent. A two-observer process
campaign proves the restarted route completes without weakening peer pinning.
The converse crash boundary is also covered: with one observer deliberately
held before request decoding, the coordinator is killed only after the other
ACK appears in its fsynced journal. Its replacement reports one recovered ACK,
does not contact that completed observer again, and advances the local chain
only after the missing observer has acknowledged the same immutable pair.
The operator audit is intentionally read-only: unlike `OpenCampaign` it does
not create or migrate state, and it never opens a collector that could close an
expired slot. It authenticates signed receipt chains and checkpoints before
classifying operational drift. Retryable missing ACK/closure lag is distinct
from blocking evidence loss or observer divergence; a blocked result exits
non-zero so automation cannot interpret a printed warning as success.

## Consensus coding rules

- Never serialize a Go map.
- Never use floating point.
- Never use wall clock or random devices in state transition logic.
- Never ignore an arithmetic error.
- Never recover from a panic and continue consensus execution.
- Never accept unknown versions, fields, or opcodes by default.
- Never mutate persistent state until the entire transition is valid.
- Never treat a local database key order as a protocol order.
- Never add a new cryptographic construction without a written threat analysis.

## Testing requirements

- Native Go fuzzing for all untrusted parsers and GuardVM.
- Race-enabled test suite.
- Differential state testing between storage implementations.
- Golden encoding and hashing vectors.
- Crash testing around every atomic commit boundary.
- Network simulation before automatic public bootstrapping is enabled.
- Opt-in real-process QUIC restart/sync/replay soak, with longer fault-injected
  runs required before a public devnet.
- Formal model checking before committee signatures are exposed as
  preconfirmations.

## Disclosure

Before a public testnet, the repository must publish a security contact, encrypted
reporting channel, disclosure window, supported versions, and bounty policy.
