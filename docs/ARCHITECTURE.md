# Architecture

## System boundary

OutcomeMesh is an independent protocol and implementation. It does not embed an
EVM client or derive consensus rules from another chain.

The implementation reuses non-blockchain infrastructure where inventing a new
primitive would add risk without differentiating the protocol:

- the Go compiler and standard library;
- Ed25519 and SHA-256 implementations;
- a replaceable peer transport boundary (go-libp2p QUIC-v1 plus a
  standard-library TLS/TCP development fallback);
- Pebble local key-value storage;
- wazero for later deterministic Wasm execution.

Consensus semantics, signed encodings, state transitions, mining rules, fork
choice, fees, and rewards are specified and implemented in this repository.

## Layering

```text
Applications / wallet / solver
              |
       Outcome transaction
              |
   Resource model + GuardVM
              |
  Deterministic state transition
              |
 Block execution and state roots
              |
 Anchors / WorkGraph / committee
              |
      P2P and local storage
```

Dependencies point downward. Consensus packages must not import node, RPC,
network, database, CLI, or operating-system packages.

## Deterministic core

The core is a pure function conceptually equivalent to:

```text
Transition(pre_state, transaction, context) -> post_state | error
```

`context` contains only consensus-provided values such as network identifier,
height, fee schedule, and protocol version. It never exposes wall time, network
state, random devices, filesystem state, goroutine scheduling, or database
iteration order.

## Resource model

A version-0 resource is an owned, typed value:

```text
Resource {
    id
    version
    owner
    asset
    amount
    spend_after
    policy_hash
    payload_hash
}
```

Version 0 uses consume-and-create semantics. Updating a resource consumes the old
resource and creates a new one. Shared mutable objects and application resources
are deferred until their conflict and authorization rules are specified.

## Outcome transaction

A transaction identifies resources to consume, outputs to create, a maximum fee,
an expiry height, a nonce, and a GuardVM program. The owner signs the canonical
unsigned transaction. Output identifiers are derived from the unsigned
transaction identifier and output index.

## GuardVM

GuardVM is deliberately separate from the future application VM. It is bounded,
loop-free, typed, and able to inspect only transaction effects:

- balances before and after;
- fee paid;
- block height;
- declared resource and owner identifiers;
- the canonical state diff.

GuardVM cannot modify state. Any trap, invalid opcode, resource exhaustion, or
failed requirement rejects the entire transaction.

## State

Two ledger/state implementations are maintained:

- a simple in-memory reference state used for correctness testing;
- a persistent Pebble ledger used by nodes.

The consensus state root is computed from canonical resources, never from local
database pages or iteration order. Atomicity is enforced above the database: a
transition is validated against a snapshot and committed as one batch only after
all checks succeed. The persistent schema keeps one materialized canonical state
and an immutable create/delete resource delta for every accepted block ID. A
side-branch state is reconstructed by walking its verified parent chain from
genesis and checking the committed state root after every delta. A higher-work
reorganization atomically switches active resources, canonical height indices,
and tip while preserving the losing branch's blocks and deltas.

This makes storage amplification proportional to the resources changed by an
accepted block instead of the total state size. Canonical extension reads the
materialized state directly and atomically applies only its resource delta;
canonical reorganization applies the computed diff between old and winning
states. Side-branch reconstruction is deliberately slower.

Immutable block, node, and delta key/value bytes have an exact local admission
counter and a persisted operator limit (64 GiB CLI default). Exhaustion rejects
the whole commit before a batch is created without making the database
unreadable. The schema still retains all valid blocks and deltas. Pebble
WAL/LSM overhead is outside the logical counter, so physical free-space
reserves, checkpoints, and pruning remain required before public operation.

Pebble schema version 3 introduced this delta representation. Pre-alpha schema
version 2 databases fail closed and must be rebuilt by replay; there is no
in-place compatibility promise before the first public network.

## Peer boundary

Network frames, sessions, synchronization, peer policy, and encrypted transport
live under `node/` and never enter `core/`. The wire format is bounded and
versioned independently from consensus objects. Exponential locators discover a
canonical common ancestor; every received block still passes normal execution
and fork-choice validation. Mempool ordering and peer scores are explicitly
local policy and cannot make a transaction or block valid.

## Consensus evolution

The first consensus is a conventional cumulative-work anchor chain. WorkGraph is
added only after the ledger, blocks, recovery, fork choice, and bounded peer
devnet are stable. Its version-0 design is specified in `WORKGRAPH.md`: weak
shares form a bounded canonical DAG tied to one anchor parent, while anchor
proof of work remains the only fork-choice weight.

The current inactive prototype uses a separate version-1 block object instead
of reinterpreting version 0. Its target is precommitted with lagged ASERT from
the parent timestamp, its unified WorkSeal is both weak-share and hard-anchor
preimage, and its predecessor payout is materialized one height later. A
bounded fork-local fee queue separates transaction collection from the future
PoW winner receiving those fees; its root and matured award are part of the
payload commitment. This reduces the incentive to mine a private high-fee
payload while preserving exact conservation. Default storage, chain sessions,
and CLI commands remain on version 0. Explicit `work-*` commands can now open
the isolated activation router without changing those defaults.

The router accepts v0 only below the configured activation height and v1 only
at or above it. Every known v0 node at height `H-1` can independently seed a v1
tree; it does not freeze whichever v0 branch happened to be canonical first.
The global selected tip is the best cumulative hard-PoW tip across the legacy
ledger and every v1 tree. Strictly greater work replaces it; exact v1 ties keep
the local arrival incumbent instead of applying the grindable version-0 ID
tie-break. A test extends one activation base, then reorganizes through a
different base with more hard work. Both versions receive the same explicit
local admission-time sample. Canonical encodings remain unchanged and a strict
leading-version decoder rejects a format on the wrong side of `H`.

Optional router persistence composes those independent Pebble trees as a
bounded forest. The forest root has a synchronous schema-1 manifest, one
canonical lowercase base-hash directory per tree, and a mode-0600 `SELECTED`
checkpoint for the local incumbent. Creating a directory is fsynced before its
database is opened, so an interrupted first admission leaves either no
directory, a recoverable empty tree, or a complete WorkChain batch. On reopen,
every directory must resolve to a known v0 node at `H-1`; the child database
then revalidates its base/config binding and complete state history before the
router rebuilds `block ID → base ID`. A missing `SELECTED` file migrates by
choosing from verified tips; an unknown or malformed selection fails closed.
If the stored choice is no longer heaviest, strictly greater verified work
overrides it. This avoids requiring one atomic transaction across the separate
tree databases while preserving arrival order across clean restart.

The local forest defaults to at most 64 trees (hard maximum 1,024). Its 64 GiB
logical history ceiling is statically partitioned across that maximum, yielding
a hard aggregate bound without distributed counters between Pebble databases.
Lowering a partition below already stored history fails reopen. Operators can
inspect aggregate tree/node/history usage through the router. This layout is
still inactive unless an absolute forest root is supplied explicitly.

`omd work-enable` is the only CLI transition into that layout. Its immutable,
fsynced 64-byte profile binds the network, genesis ID, activation height, fee
delay, tree cap, and forest history budget. The exact genesis ID must be typed
back and the current v0 tip must remain below activation. A complete pending
profile can be finalized after interruption. Once either marker exists, all
ordinary commands capable of mutating or misreporting the mixed chain refuse
that data directory. `work-mine`, `work-status`, `work-balance`, `work-verify`,
`work-serve-quic`, and `work-sync-quic` are separate experimental entry points.

The strict block and header unions live below networking in `core/chainblock`.
The wire package has appended, inactive version-1 envelopes for one union block
and for a length-delimited contiguous union-header batch that may cross v0→v1.
This does not enlarge the active reader's 8 MiB ceiling: a versioned session
must opt into the WorkGraph maximum explicitly. Ordinary v0 status, locator,
sync, persistence-routing, and CLI paths still do not use it, so the codec alone
cannot place a v1 block on a default chain.

The accompanying inactive chain handshake refuses network, genesis, or
activation-height mismatch before locator exchange and intersects explicit
frame ceilings. Its locator requests and batch terminator have distinct v1
message IDs. This fixes the control-plane grammar without weakening the active
session's fail-closed dispatch. An isolated router-backed serving/download state
machine now validates mixed headers before bodies, continues along known losing
side branches, replays blocks through global hard-work fork choice, and binds
the completed state/work back to the hello. The QUIC adapter exposes it under
the distinct opt-in `/outcomemesh/chain/1` protocol and resource scope, while
default hosts and ordinary CLI commands leave it unregistered. Only
`work-serve-quic` installs the handler and only `work-sync-quic` dials it.

The isolated version-1 coordinator exercises each routed tree:
it derives branch-local MTP, targets, fee queues, states, and prior earnings and
uses only hard WorkSeal difficulty in cumulative-work fork choice. It is test
scaffolding, not an alternate consensus authority. Its schema-versioned Pebble
backend keeps one activation-base checkpoint and an immutable create/delete
resource delta per v1 block. Schema 4 permits a bounded replay checkpoint to
replace that node's delta, but requires exactly one representation for every
retained non-floor node. Maintenance
defaults to a 2,048-height selected-ancestry interval and four non-base full
states. Checkpoint creation and eviction are one synchronous batch; eviction
reconstructs the displaced node's exact delta from its still-validated parent
and state. Reopen verifies the XOR representation invariant, roots, ancestry,
fee queues, cumulative work, selected tip, and logical byte count. Schemas 2
and 3 fail closed and replay is the migration policy. Its non-consensus anchor
layer
canonically binds an exact selected tip and its full backward ancestry
commitment to network/genesis/activation/tree-base identity, a predecessor
statement, and an archive-manifest ID. It requires a locally configured quorum
of at least two among 2–64 sorted Ed25519 attestors and recomputes selection
against the live WorkChain, so signatures neither override hard-work fork
choice nor survive a reorganization of the named branch. The format and atomic
checkpoint-file publication are implemented. A separate content-addressed
manifest commits ordered bounded block chunks; verification replays those
blocks from the external activation base through ordinary WorkChain execution.
Persistent restore builds, closes, reopens, and verifies a temporary Pebble
tree before directory rename and parent fsync, and never replaces an existing
destination. A separate replica key set issues time-bounded custody receipts
only after full replay. Prune authorization replays every distinct replica
again and durably publishes the receipt bundle. Receipt v1 can extend one exact
predecessor only after a fresh signed random-sample challenge: sample IDs are
deterministically derived from the nonce, manifest, and predecessor receipt;
the signed response commits the canonical returned batch, and the renewal
commits both proof ID and requested deadline. Receipt v0 remains decodable.
With an explicit non-zero local
retention horizon, one Pebble batch replaces the prefix with canonical headers,
a full-state floor, and exact evidence IDs; reopen recomputes archived work and
ancestry before accepting descendants. The default remains disabled because
the floor intentionally rejects deeper reorganizations. A subsequent archive
can be composed without restoring the pruned database: the composer fully
verifies the exact predecessor manifest recorded by the floor, streams that
prefix plus the selected executable suffix into a fresh self-contained v0
archive, then rechecks the unchanged floor and ancestry before atomic rename.
Archive format v1 makes chunk IDs independent of the terminal archive anchor.
Composition freezes every predecessor chunk boundary, so those descriptors and
content IDs remain byte-identical and only suffix IDs are new. The manifest
still lists the complete ordered stream and each directory remains standalone;
v0 anchor-bound archives remain strictly decodable and restorable. A local
file-per-ID object store scans and verifies every canonical chunk on reopen and
enforces exact object and byte budgets. It imports an archive only after full
replay. Versioned request and batch objects bind the manifest ID, require 1–64
strictly hash-sorted unique IDs, and cap each response at 64 MiB of chunk data.
The receiver revalidates every chunk against its manifest descriptor before an
atomic no-replace insert. Materialization writes every referenced object into a
standalone temporary archive, fully replays it, and only then publishes the
directory. Thus a store seeded with the predecessor generation requests only
the new suffix while neither the cache nor its peer is a trust root. Physical
copy-on-write materialization remains an operator concern. Local maintenance
also marks canonical ancestry and every side branch reaching a configurable
cutoff,
then atomically removes only complete
stale subtrees while decrementing the exact logical history counter. Its default
window is 4,096 heights, zero disables it, and it does not prune canonical
history. Archive objects use a dedicated opt-in libp2p scope. Direct QUIC-v1
authenticates both Ed25519 transport identities; the dialer must pin the exact
server and the server admits only a sorted operator allowlist. One finite stream
serves at most four existing 64-object/64-MiB batches, rejects repeated IDs, and
has independent concurrent and per-peer/global fixed-window admission. A
receiver may resume on a new stream from its append-only store. A second
`/outcomemesh/workarchive-custody/1` scope admits only configured auditor
transport identities under separate limits. Its one-shot state machine is
challenge → sampled batch → signed proof → linked renewed receipt, with strict
frame sizes and deadlines. The replica commits the complete response tuple to
an immutable canonical record before sending and reloads it on restart; the
auditor commits the challenge before dialing and the verified response before
publishing the receipt. Separate one-shot `omd` commands expose both roles with
pinned/allowlisted transport identities and separate portable signing keys.
The bulk object scope also has isolated `work-archive-object-serve-quic` and
`work-archive-object-fetch-quic` commands. Both reconstruct the activation base
from local node data and verify the target manifest/checkpoint under an explicit
attestor trust set. The server fully replays before import; the client preserves
an incomplete resumable store and only publishes after materialization plus a
second full replay. Source restart and network-free client recovery are covered
by a real process test.
Custody journal mode fixes the initial receipt and auditor policy, derives the
current receipt from a gapless chain of immutable slots, and stores complete
entry bodies by content ID. A permanent kernel lock serializes disk operations
across processes. Rotation seals body directories without moving decision slots
or deleting history. One-cycle CLI invocations derive due times from replayed
receipts and recover incomplete output publication. `CUSTODY.md` documents the
timer integration, filesystem assumptions, and recovery limits.
Local journal growth limits charge logical bytes and paths, including temporary
links and unreferenced evidence. Append reserves body and slot publication under
the journal lock; rotation reserves one directory. Lowered limits preserve
historical replay and exact committed retries. A streaming inventory caps replay
metadata at 1,048,576 paths. These limits neither reserve physical filesystem
space nor cover the separate auditor artifacts or replica object store.
The auditor's permanent artifact lock covers the whole invocation, before any
journal lock. Paired custody checkpoints take those locks in the same order,
fully replay the journal, and commit to both complete directory inventories.
An independent checkpoint ID lets an operator reject a rolled-back cold copy,
including a same-head copy missing an uncommitted signed challenge. Exact-copy
verification never initializes or repairs evidence. The retention policy is to
keep all evidence. The separate managed-backup command holds the source locks,
streams each file into independent inodes, syncs and replays the destination,
then publishes the checkpoint as the final bundle commit. A no-replace directory
reservation prevents adopting an existing target; incomplete attempts remain
incomplete rather than being resumed or removed. Standalone bundle verification
requires an independent pin and does not need the original sources. An optional
independently stored pin journal links fixed-width checkpoint records through
no-replace sequence files under a permanent lock. Updates compare the observed
pin ID and fully verify both bundles before checking chain ancestry and retained
bodies, pending files, and auditor bytes. Exact last-update retries do not append;
latest-pin verification rejects older bundles even at the same custody head.
The pin store is a local operational authority, not a signed consensus object.
Its physical independence and freshness still need deployment; an external head
receipt is necessary to detect rollback of the entire pin store as well.
A read-only outage reconciler verifies one auditor and one replica-only bundle
against independently supplied checkpoint IDs. It compares the exact slot-ID
prefix without choosing a longer divergent history, checks canonical auditor
artifacts against committed records and the next signed intent, and distinguishes
historical response validity from assessment-time proof age and receipt expiry.
Retained orphan/temporary/unknown evidence remains a review blocker. Bounded
slot/body indexes avoid a segment scan for every cycle; payloads are loaded one
cycle at a time. Reports authorize no imports, fresh challenges, baseline changes,
or participant restart. Historical transfer, linked rebaseline, and fencing still
need separate implementation and review.
Cross-host cutover, compaction review, broader filesystem-fault
soaks, and outbound share publication remain. The libp2p
adapter carries both the
versioned chain and separate WorkGraph share sessions under distinct opt-in
protocol IDs and resource scopes. Ordinary CLI hosts leave both disabled. The
experimental `work-serve-quic` command enables both handlers, while
`work-sync-quic` still dials only the versioned chain protocol.

`node/workround` owns one immutable `(height, parent, target, payload)` context,
its bounded pool, unified miner, and finite relay session. A manager caches at
most the current best-parent round, rechecks the parent after preparation with
three bounded attempts, and replaces the entire pool on an anchor or reorg.
In-flight handlers may finish against the detached old round, but those shares
can never enter the replacement payload or persistent block state.

`work-mine-quic` attaches one bounded unpublished-ID queue and worker per
explicit peer, with a hard maximum of eight. The miner callback performs no
consensus mutation or network I/O: it only copies locally admitted IDs into the
bounded queues. Each worker opens only the exact WorkGraph protocol and removes
precisely the prefix that its negotiated relay reports as announced. Failed
attempts retain that peer's suffix without delaying healthy workers or hard-PoW
search. A count threshold and mandatory time threshold race on every worker, so
a small miner publishes a partial batch even when it cannot accumulate 128
shares in one round. The same host accepts reciprocal share sessions. A first
pool admission is forwarded through the same workers except to its authenticated
source; later copies stop at pool deduplication. Round control binds that path to
the exact mining context and buffers at most 8,192 admissions during publisher
handoff. The host also serves chain-v1 and renews an activation-bound signed
self-record, but automatic peer routing is not enabled unless explicitly
requested.

The opt-in startup selector can populate those same workers after a bounded
refresh of the signed peerbook from explicit and eligible activation bootstraps.
The chain-v1 exchange negotiates discovery independently, accepts only records
bound to the exact local activation height, and persists each validated batch
atomically. The generic router distinguishes attempt budget from required
successful connections and filters candidates before reserving dial state.
WorkGraph selection filters for identity-bound direct QUIC addresses and a
signed WorkGraph claim, uses score/latency/backoff plus mandatory ASN diversity,
and counts success only after a live no-inventory exact-context probe.
Reputation is persisted; bootstrap diversity remains local operator policy.
The long-lived miner repeats that refresh every 30 minutes through the selected
set. A local-identity/epoch keyed order rotates the bounded candidate prefix,
and serialized atomic peerbook saves prevent self-renewal from overwriting a
concurrently learned batch. Relay targets stay generation-stable during mining.

Pool tip selection ranks by bounded ancestor coverage, but ranking order never
enters consensus bytes. After choosing at most four tips, the pool re-sorts them
by Work ID before constructing a weak or hard share. A four-node deterministic
rollover harness exercises this boundary under skew, churn, and stream loss.

Anchor propagation uses a third opt-in protocol role without a second sync
grammar. On `/outcomemesh/chain-notify/1` the winning dialer runs the existing
versioned responder and the notified node runs the existing synchronizer. The
receiver still compares cumulative hard work, requests headers before bodies,
and submits through the activation router. Winning anchors are queued to
independent per-peer notification workers; a busy peer keeps at most one extra
prompt, which serves the newest selected tip. The responder pins the canonical
path advertised by its handshake so concurrent local mining cannot mutate the
session's header/body view. A changed selected tip invalidates the round manager
and cancels its active hash loop; an unchanged notification does neither.
The process fault suite kills a separate process immediately before and after
the synchronous Pebble batch for ordinary block commit, replay-checkpoint
creation/rotation, and stale-fork pruning. Reopen must match the complete old or
complete new tip, state root, cumulative work, logical history, node inventory,
and checkpoint inventory, then accept a fresh extension.

The later committee provides preconfirmations. It does not define the canonical
chain and cannot make an invalid transition valid. A full node independently
validates every state transition and selects the chain by protocol-defined proof
of work.

## Concurrency policy

Goroutines are allowed at service boundaries: networking, RPC, storage prefetch,
and independent transaction execution.

Consensus output cannot depend on completion order. Parallel results are
validated and committed in a canonical order derived from the block and declared
resource conflicts.

No signed or hashed structure contains a Go `map`. Maps are converted to sorted
slices before entering consensus code.

## Dependency policy

- Pure Go is preferred for the first devnet.
- `CGO_ENABLED=0` is a release requirement until an audited production PoW or
  proving system justifies an exception.
- Dependencies are pinned in `go.mod` and `go.sum`.
- A dependency cannot define consensus serialization implicitly.
- Consensus-critical dependency updates require replay tests and root comparison.
- New cryptographic primitives require external review.
