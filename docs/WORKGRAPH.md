# WorkGraph version-0 design

Status: Milestone 5 specification plus isolated version-1 block prototype; not activated

## Purpose

WorkGraph turns independently verifiable weak proof-of-work shares into native
chain accounting. A miner can publish useful evidence of partial work without
handing block-template control or payout custody to a pool operator. It does not
replace anchor proof of work, make computation subjective, or make an invalid
transaction valid.

A crucial invariant is **one nonce space**. A share is the same WorkSeal used by
an anchor candidate. Its header stores the hard anchor target; validators compare
the Work ID with the easier derived threshold for share admission and with the
hard target for anchor admission. A lucky share is therefore an immediately
usable anchor candidate, not work diverted from chain security.

The first implementation is deliberately small:

- one fixed share difficulty relative to the current anchor target;
- shares live for exactly one height/parent/target/payload template, with a
  bounded timestamp window;
- the winning hard-target WorkSeal commits up to four DAG tips; their exact
  transitive closure is carried by the winner and paid by the following block;
- rewards are computed from canonical included shares, not a server database;
- transaction inclusion commitments are informational until their later
  enforcement rule is separately specified.

## Weak share

A version-0 share contains, in canonical order:

```text
version          uint16 = 0
network_id       uint32
height           uint64
anchor_parent    hash32
timestamp        uint64
anchor_target    hash32
payload_root     hash32
miner            address32
inclusion_root   hash32
parent_count     canonical uvarint, 0..4
parents          parent_count * hash32, strictly increasing
nonce            uint64
```

The Work ID used by both weak-share and anchor thresholds is:

```text
SHA256("OMESH/workgraph/work/id/v0" || canonical_work_seal)
```

The inclusion root is a domain-separated Merkle root of ordered transaction IDs.
The empty list has its own non-zero root. A share cannot carry an arbitrary zero
commitment.

`payload_root` commits the candidate block's transaction, receipt, state, and
previous-interval WorkGraph/payout commitments. Every paid share must match the
winning anchor's network, height, parent, precommitted hard target, and payload
root exactly. Its timestamp must be greater than median-time-past and no more
than 120 seconds beyond the winner's timestamp; the winner itself must match
the block timestamp exactly. Miners may therefore have bounded clock skew, as
well as different payout addresses, nonces, parent-share links, and inclusion
commitments, without changing the executable payload.

## Difficulty and validity

Version 0 uses a fixed ratio `R = 512`. For hard anchor target `T`, the derived
share-admission threshold is:

```text
min(((T + 1) * R) - 1, 2^256 - 1)
```

This makes a share approximately 512 times easier than an anchor when the
target is not saturated. Integer arithmetic is exact; floating point is never
used. The WorkSeal stores `T`, not the easier threshold. A work ID at or below
the derived threshold is a share; the same ID at or below `T` is an anchor.
Activation additionally requires the genesis proof-of-work limit to preserve
the exact 512:1 ratio without saturating the derived 256-bit target. Because
ASERT only makes later targets harder than that limit, the invariant then holds
at every height.

The experimental version-1 block fixes `T` before current-height mining. It
uses lagged ASERT, evaluating the next target from the already committed parent
timestamp plus one ideal spacing:

```text
T(h) = ASERT(genesis_target, genesis_timestamp,
             h, parent_timestamp + target_spacing)
```

Unlike the active version-0 rule, the current miner's chosen timestamp is not
an input to its target. Moving a candidate timestamp toward the future cannot
make that candidate easier. This also lets shares inside the bounded timestamp
window use one target and one nonce-space rule; any one of them that reaches
`T(h)` remains a directly usable anchor candidate.

The validator also requires the exact network, height, anchor parent, winning
payload root and precommitted hard target, a bounded MTP-valid timestamp, a
non-zero miner, a valid inclusion root, and no duplicate or unsorted parents.
The block layer independently derives the lagged ASERT target from its validated
parent and applies MTP plus the local 120-second future-admission check before
requesting a body.

## Bounded DAG and canonical order

A child anchor may commit at most 8,192 shares, at most four parents per share,
at most 256 distinct reward miners, and at most 3 MiB of canonical share data.
Every referenced parent must be present in the same committed batch and must
name the same height/parent/target/payload template and remain inside the
winner-relative timestamp window. This makes validation independent from a
miner's private gossip database.

The committed list is the unique lexicographic Kahn topological order:

1. place every zero-indegree share in a min-heap keyed by share ID;
2. emit the smallest ID;
3. reduce its children's indegrees and enqueue newly eligible children;
4. reject a cycle, missing parent, duplicate ID, or list differing from this
unique order.

At constant hash rate the ratio yields approximately 512 shares per anchor. The
inter-anchor count is geometric, so the 8,192 count cap provides sixteenfold
headroom; its idealized overflow probability is about `exp(-16)`, near
`10^-7` per interval. The original ratio-4096/count-2048 draft was rejected
before activation because its expected honest load already exceeded the cap;
an intermediate fourfold cap was also rejected because its tail overflow was
about 1.8%.

The WorkGraph root is a domain-separated Merkle root over share IDs in that
order. Gossip arrival and goroutine completion order therefore cannot change an
anchor commitment.

The winning anchor seal's `parents` are commitment tips. Payout validation walks
their full transitive closure and requires it to equal the supplied canonical
batch exactly. A successor cannot omit a required ancestor, add an unreferenced
share, or choose a different payout set after hard proof of work was found. The
winning seal itself is not in the share pool and cannot be paid both as an
anchor and a share.

## Reward accounting

The original half-pool draft was rejected before activation. Under that rule a
winner could commit no share tips and receive the entire pool, making total
omission the rational strategy.

Version 0 of WorkGraph accounting instead fixes both rates before mining. Let
`E = R - 1 = 511`, the expected number of weak-only shares before one hard
anchor:

```text
share_reward   = floor(block_subsidy / (2 * E))
anchor_subsidy = block_subsidy - E * share_reward
anchor_reward  = anchor_subsidy + matured_fee_award
subsidy_issuance = anchor_subsidy + included_share_count * share_reward
```

Every included share contributes exactly `share_reward`, independent of batch
length and other miners. Amounts are aggregated by address and emitted in
increasing address order. At exactly `E` shares, subsidy issuance is precisely
`block_subsidy`. A short round mints less; a rare long round mints more because
it contains proportionally more objective work. The 8,192-share cap bounds the
latter. A matured fee award is a conserved transfer, not issuance. Parameter
validation rejects a zero share unit or any rate that could overflow even if
one miner owns the anchor and all maximum-count shares.

Omitting a foreign share no longer increases the winner's anchor reward or the
fixed reward of its own shares. Omission can still harm a competitor and alter
relative revenue, so propagation evidence and selection policy remain security
requirements rather than assumed honesty.

## Delayed fee relay

Paying current fees directly to the current anchor makes a private high-fee
payload more attractive than the common payload whose weak shares are most
likely to be paid. Version 1 instead uses an immutable fork-local ring of
`fee_delay` slots. At height `h`:

```text
fee_award(h) = queue[cursor]
queue[cursor] = fees_collected(h)
cursor = (cursor + 1) mod fee_delay
```

The checked queue balance always equals the sum of its slots. The new queue
root and `fee_award(h)` are committed by the height-`h` payload before mining;
neither depends on the current miner. The award belongs to the height-`h`
anchor and is materialized with its other delayed rewards at height `h+1`.
Consequently, a fee is paid exactly `fee_delay` anchor transitions after it was
collected, to a future PoW winner. A reorganization restores the queue of the
selected branch and cannot retain a losing branch's deposit or award.

This is economic de-correlation, not forced inclusion. A miner expects to earn
back only its future hash-proportional share of a private fee, which raises the
template-split threshold, but censorship and delayed-fee parameter selection
remain explicit review items.

A share is tied to the exact winning candidate at height `h`, reachable from
that winner's committed parent tips, and may only be included in the payout body
at height `h+1`. On a single canonical chain there is only one such successor,
so the same Work ID cannot be paid again later.
Competing successors may contain the same share, but ordinary proof-of-work fork
choice leaves only the canonical successor's state and rewards active after
reorganization.

Reward resources keep the existing maturity delay. WorkGraph does not create an
early-spend path.

Delayed issuance removes two commitment cycles: the height-`h` state root does
not depend on the unknown winning miner or unknown concurrent shares, and the
height-`h` WorkSeal does not depend on a WorkGraph root containing itself.

## Threats and explicit limits

- The winning anchor producer can omit shares from its parent tips. The closure
  makes the decision auditable and prevents its successor from changing it, but
  does not prove that the winner saw an omitted share. Fixed pay-per-share
  removes the direct pool-stealing gain but not a relative-revenue or censorship
  motive.
- A miner may withhold a near-anchor share or publish anchors strategically.
  The multi-seed 7 × 5 sweep places the first conservatively profitable tested
  point at 35% attacker hash for 0–25% honest tie adoption, 25% attacker hash
  for 50–75% tie adoption, and no higher than the grid's 15% floor under full
  adoption. WorkGraph does not remove the classic selfish-mining threshold;
  finer boundary search, richer adaptive strategies, and network calibration
  remain mandatory before parameter freeze.
- Sybil identities do not create weight without proof of work, but can consume
  the distinct-miner cap. Selection policy and propagation tests must cover it.
- Shares add bandwidth. All decode, batch, parent, miner, and byte limits are
  consensus constants and must be exercised at their maxima. The bounded-link
  model also shows that naive flooding can deliver several duplicate bodies per
  first copy, so production gossip requires inventory-first announcements,
  per-peer deduplication, and hard queues; raw share-body rate is not a complete
  bandwidth budget.
- Inclusion commitments do not yet force transaction inclusion or penalties.
  They become enforceable only with an explicit availability and expiry rule.
- Shares never add anchor-chain cumulative work and never participate directly
  in fork choice; only a Work ID meeting the hard target contributes anchor
  cumulative work.
- Paying only shares matching the winning payload discourages hash work on
  invalid or unavailable templates, but may concentrate miners on the most
  widely propagated valid template. The fixed-seed split-template model loses
  roughly half of otherwise valid shares when two equal miners use different
  payloads. Template propagation and censorship are explicit simulation gates.
- Delayed fees go to a future anchor producer, not weak shares. At high fee-to-
  subsidy ratios, native shares smooth subsidy income but do not reproduce a
  pool's fee sharing. Fee delay also changes miner cash flow and creates a
  bounded consensus balance that must be persisted and reorged atomically.

## Compatibility sequence

The pure share/DAG/accounting package, simulations, and an isolated version-1
block transition now exist. The prototype adds the unified WorkSeal, payload
commitment, previous-interval WorkGraph root/share body, canonical codec,
header-first proof checks, explicit activation height, a committed fee queue,
and delayed reward resources. Version-0 blocks are not silently reinterpreted.
The prototype now has isolated schema-versioned persistent storage, negotiated
relay, and a published local budget. A strict in-process activation router now
dispatches unchanged
canonical encodings by their leading version, rejects v0 at/above `H` and v1
below `H`, and compares cumulative hard work across independent v1 trees rooted
at every known v0 node on `H-1`. This avoids implicit finality at the initially
selected boundary parent. Multi-base persistence and the active wire/CLI path
are not yet enabled.

The transport-independent codec and an isolated finite session implement
inventory-first WorkGraph relay: 1,024 sorted IDs per announcement and at most
256 sorted IDs/bodies per request or response, all tied to one exact mining
context. A version-1 capability handshake intersects counts and frame sizes,
then clamps body batches against worst-case encoding. Oversized frames are
rejected before allocation, each unknown ID is requested once, invalid or
withheld bodies receive a bounded result, and all returned shares still pass
the full local pool validator. The libp2p adapter exposes it under the distinct
`/outcomemesh/workgraph/1` ID only when an operator installs a handler; default
hosts and the active CLI cannot negotiate it. Two-host QUIC tests cover peer-ID
pinning, a negotiated 512-byte frame, parent/child relay, context rejection, and
an independent one-stream-per-peer resource scope. The in-process block router
remains disconnected from this chain session.

One maximal 1,024-ID relay is bounded to exactly 630,258 bytes of bidirectional
application framing when a peer forces one maximum-size body per batch. The
QUIC adapter's fixed-window defaults admit eight such streams per peer and 512
globally per minute: approximately 82.1 KiB/s per peer and 5.13 MiB/s for the
node averaged across a window. Boundary bursts can be twice that average, and
transport headers/retransmission are outside the application counter. These
ceilings close unbounded sequential-stream admission; simulation still governs
the much lower target operating rate needed for fair propagation.

The corresponding local pool is also implemented but inactive. It verifies
weak PoW and exact context before storage, owns detached bodies, accepts bounded
out-of-order children, resolves them only after all parents are accepted, and
caps count/bytes at the consensus batch limits. It admits at most 255 distinct
weak-share miners, reserving the 256th reward identity for the still-unknown
anchor. Mining parents are selected from accepted tips with a saturating
O(parent-count) coverage score and deterministic Work-ID tie-break; after a hard
seal is found, the pool reconstructs and consensus-validates its exact canonical
closure. Hard-target shares are redirected to the block path rather than being
inserted and double-counted.

The fork coordinator integrates the activation boundary without changing active
version-0 storage. For every candidate branch it reconstructs resource
state, the last 11 timestamps, lagged target, fee queue, and predecessor earning;
only hard-target work is added to cumulative fork weight. Competing activation
anchors, equal-work tie-breaking, a higher-work side-branch reorganization, and
branch-local delayed rewards are executable tests. Its isolated Pebble schema
persists canonical block bytes, immutable resource deltas, history, fee queues,
cumulative work, a checked logical-history counter, and selected tip in one
synchronous batch. Schema 3 requires every non-base node to carry exactly one
recovery representation: an immutable parent delta or a full-state replay
checkpoint, never both. Explicit maintenance creates a checkpoint only after
2,048 selected-ancestry heights by default and retains at most four non-base
checkpoints. Creation atomically replaces that node's delta; rotation turns an
evicted checkpoint back into its exact parent delta in the same batch. Reopen
reconstructs every branch parent-first, verifies each delta/checkpoint root and
the exclusive representation rule, and rejects corrupted checkpoints. Pre-alpha
schema 2 fails closed and is rebuilt by replay rather than silently migrated.
The 64-GiB logical budget covers both representations, and an injected pre-sync
failure leaves memory and disk unchanged. Explicit maintenance can atomically
remove only side-fork subtrees whose highest node is behind a local retention
window (4,096 heights by default). It retains the entire canonical path plus
every ancestor of a side branch at the boundary, updates the logical byte
counter in the same synchronous batch, and is disabled by a zero local setting.
Canonical history is deliberately not pruned without a separately designed
history-anchor rule. History-anchored archival pruning and extended filesystem-
fault/soak campaigns still precede production activation.
The integration suite also kills a real subprocess on both sides of the
synchronous batch boundary and proves reopen yields the complete old or complete
new chain, never a partial node/delta/tip combination.

## Milestone-5 evidence required

- canonical share, ID, target, DAG-root, and payout vectors;
- strict decoder fuzzing and maximum-bound tests;
- proof that fixed rates match the published formula, cannot reward omission,
  and remain bounded at every allowed batch size;
- duplicate/cycle/missing-parent/non-canonical-order negative tests;
- simulations for honest proportionality, propagation delay, withholding,
  orphan anchors, competing forks, a multi-seed selfish-strategy grid, and
  bandwidth;
- explicit block-version and cross-boundary reorg tests proving no implicit
  activation checkpoint or double payout.
