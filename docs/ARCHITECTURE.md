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
payload while preserving exact conservation. Active storage, chain sessions,
and CLI remain on version 0. An isolated activation router now supplies the
explicit block-version boundary and cross-version fork-choice suite without
enabling it in those paths.

The router accepts v0 only below the configured activation height and v1 only
at or above it. Every known v0 node at height `H-1` can independently seed a v1
tree; it does not freeze whichever v0 branch happened to be canonical first.
The global selected tip is the best cumulative hard-PoW tip across the legacy
ledger and every v1 tree, using the existing deterministic ID tie-break. A test
extends one activation base, then reorganizes through a different base with
more hard work. Both versions receive the same explicit local admission-time
sample. Canonical encodings remain unchanged and a strict leading-version
decoder rejects a format on the wrong side of `H`.

Optional router persistence composes those independent Pebble trees as a
catalog-free forest. The forest root has a synchronous schema-1 manifest and
one canonical lowercase base-hash directory per tree. Creating a directory is
fsynced before its database is opened, so an interrupted first admission leaves
either no directory, a recoverable empty tree, or a complete WorkChain batch.
On reopen, every directory must resolve to a known v0 node at `H-1`; the child
database then revalidates its base/config binding and complete state history
before the router rebuilds `block ID → base ID`. The global tip is recomputed
from verified tree tips rather than stored in a cross-database catalog, avoiding
a multi-DB commit point.

The local forest defaults to at most 64 trees (hard maximum 1,024). Its 64 GiB
logical history ceiling is statically partitioned across that maximum, yielding
a hard aggregate bound without distributed counters between Pebble databases.
Lowering a partition below already stored history fails reopen. Operators can
inspect aggregate tree/node/history usage through the router. This layout is
still inactive unless an absolute forest root is supplied explicitly.

The strict block and header unions live below networking in `core/chainblock`.
The wire package has appended, inactive version-1 envelopes for one union block
and for a length-delimited contiguous union-header batch that may cross v0→v1.
This does not enlarge the active reader's 8 MiB ceiling: a versioned session
must opt into the WorkGraph maximum explicitly. The active status, locator,
sync, persistence-routing, and CLI paths still do not use it, so the codec alone
cannot place a v1 block on the live chain.

The accompanying inactive chain handshake refuses network, genesis, or
activation-height mismatch before locator exchange and intersects explicit
frame ceilings. Its locator requests and batch terminator have distinct v1
message IDs. This fixes the control-plane grammar without weakening the active
session's fail-closed dispatch. An isolated router-backed serving/download state
machine now validates mixed headers before bodies, continues along known losing
side branches, replays blocks through global hard-work fork choice, and binds
the completed state/work back to the hello. The QUIC adapter exposes it under
the distinct opt-in `/outcomemesh/chain/1` protocol and resource scope, while
default hosts and the active CLI leave it unregistered.

The isolated version-1 coordinator exercises each routed tree:
it derives branch-local MTP, targets, fee queues, states, and prior earnings and
uses only hard WorkSeal difficulty in cumulative-work fork choice. It is test
scaffolding, not an alternate consensus authority. Its schema-versioned Pebble
backend keeps one activation-base checkpoint and an immutable create/delete
resource delta per v1 block. Schema 3 permits a bounded replay checkpoint to
replace that node's delta, but requires exactly one representation. Maintenance
defaults to a 2,048-height selected-ancestry interval and four non-base full
states. Checkpoint creation and eviction are one synchronous batch; eviction
reconstructs the displaced node's exact delta from its still-validated parent
and state. Reopen verifies the XOR representation invariant, roots, ancestry,
fee queues, cumulative work, selected tip, and logical byte count. Schema 2
fails closed and replay is the migration policy. Production activation still
requires an independently history-anchored archival pruning rule. Local
maintenance already marks canonical ancestry and every side
branch reaching a configurable cutoff, then atomically removes only complete
stale subtrees while decrementing the exact logical history counter. Its default
window is 4,096 heights, zero disables it, and it never creates local PoW
finality by pruning canonical history. Broader filesystem-fault soaks and CLI
registration of the versioned chain session remain. The libp2p adapter carries
both the versioned chain and separate WorkGraph share sessions under distinct opt-in protocol IDs and resource
scopes, while default hosts and the active CLI leave both disabled.
The current integration test kills a separate process immediately before and
after the synchronous Pebble batch and verifies old-or-new recovery.

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
