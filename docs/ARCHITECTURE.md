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
payload while preserving exact conservation. Storage, wire, and chain selection
remain on version 0 until an explicit activation rule and boundary-reorg suite
are integrated.

An isolated version-1 coordinator already exercises that boundary:
it derives branch-local MTP, targets, fee queues, states, and prior earnings and
uses only hard WorkSeal difficulty in cumulative-work fork choice. It is test
scaffolding, not an alternate consensus authority. Its schema-versioned Pebble
backend keeps one activation-base checkpoint and an immutable create/delete
resource delta per v1 block. The block, delta, branch history, fee queue,
cumulative work, logical-history counter, and selected tip change in one
synchronous batch. Reopen reconstructs parent-first states and verifies every
stored root and ancestry link. Schema 2 fails closed on the earlier pre-alpha
full-snapshot layout; replay is the migration policy. Production activation
still requires periodic checkpoint/pruning policy, broader filesystem-fault
soaks, and registration of the already isolated negotiated WorkGraph session.
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
