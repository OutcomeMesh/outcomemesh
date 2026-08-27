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
`/outcomemesh/workgraph/1`; default hosts and active CLI commands leave it
unhandled. Its separate protocol/peer resource scope defaults to one concurrent
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
Exhaustion rejects before batch commit while reads and reopen remain available.
Every restart reapplies deltas parent-first and verifies state roots, ancestry,
fee-queue roots, cumulative hard work, selected tip, and the recomputed byte
counter. WAL/LSM amplification and filesystem free space remain separate
operator limits. A real subprocess is killed before and after the synchronous
batch boundary and recovers only the old or new chain. Explicit maintenance can
atomically delete a complete stale side-fork subtree only after every canonical
node and every branch reaching the local retention window have been marked.
The default fork window is 4,096 heights and zero disables this local operation.
Canonical history remains intact: an independently history-anchored archival
pruning rule and broader filesystem fault/long-soak campaigns are still
required.

The activation boundary is not a locally finalized block. The isolated router
can create a separate v1 tree for every known v0 node at height `H-1` and uses
the same cumulative-hard-work comparison across all of them. A more-work v1
branch rooted in a formerly losing v0 node can therefore reorganize the selected
chain. The router rejects v0 at or above `H`, v1 below `H`, unknown v1 parents,
and consensus-parameter disagreement between versions. This logic is not yet
connected to persistent multi-base recovery or the public chain session.

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
