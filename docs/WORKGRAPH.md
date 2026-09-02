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

The round manager advances its local candidate timestamp after 60 seconds,
halfway through the admission lead. It prepares a new payload for the same
parent, retires and drains objective work on the old timestamp, then atomically
rolls the existing DAG pool to the new validation generation. Every retained
share is revalidated. Network, height, parent, target, payload root, and MTP must
remain exact; any change requires an unrelated empty round. Because timestamp
is deliberately absent from the stable WorkGraph session context, in-flight
relay sessions keep using the same bounded pool. Local gossip reseeds all
retained IDs with per-peer deduplication, closing the snapshot/admission race.
A deterministic four-node harness now runs repeated timestamp generations with
a 60-second clock spread, two offline windows, and dropped relay streams before
requiring identical inventories and a final anchor closure. It exposed and now
guards the canonical boundary after coverage-ranked parent selection: selected
tips are re-sorted by Work ID before entering a share template. Longer real-QUIC
and rapid-parent-change campaigns remain activation gates.

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
selected boundary parent. Multi-base persistence is now optional and verified;
the ordinary v0 wire/CLI path remains unchanged. The shared wire package now also has
inactive, appended version-1 envelopes for either canonical block version and for a contiguous
mixed header batch. They preserve the old chain reader's 8 MiB default and
require explicit opt-in to the larger WorkGraph block ceiling. A separate
in-process versioned chain session now uses their status/locator grammar and the
activation router. The QUIC adapter can carry it under the explicit
`/outcomemesh/chain/1` protocol; default hosts and ordinary CLI routing do not.
The experimental `work-serve-quic` and `work-sync-quic` commands are the only
CLI registration/dial path.

The persistent router uses a schema-1 forest root and one canonical base-hash
directory per schema-4 WorkChain database, not a mutable global-tip catalog.
After restart it resolves every base against the v0 ledger, fully verifies each
tree, rebuilds block ownership, and recomputes global fork choice. The default
64-tree cap (hard maximum 1,024) and static division of the forest-wide history
budget bound aggregate storage without a cross-database counter. Interrupted
manifest creation and empty first-admission directories recover safely;
unknown, swapped, over-budget, or corrupt trees fail closed.

`work-enable` writes an immutable profile only after exact genesis confirmation,
target/reward compatibility checks, a boundary above the current v0 tip, and
successful forest validation. A final or pending profile blocks every ordinary
v0 command that could mutate or misreport the mixed state. Separate
`work-mine`, `work-status`, `work-balance`, and `work-verify` commands cross the
boundary and reopen through the same router. The development miner builds empty
payloads, then runs the unified miner against a bounded per-context pool. Weak
shares update the selected DAG parents and the eventual hard WorkSeal commits
their canonical closure in the exact same nonce space. The opt-in QUIC server
now admits remote shares into the same kind of round; outbound miner publication
is available through the separate bounded multi-peer `work-mine-quic`
experiment.

The transport-independent codec and an isolated finite session implement
inventory-first WorkGraph relay: 1,024 sorted IDs per announcement and at most
256 sorted IDs/bodies per request or response, all tied to one exact mining
context. A version-1 capability handshake intersects counts and frame sizes,
then clamps body batches against worst-case encoding. Oversized frames are
rejected before allocation, each unknown ID is requested once, invalid or
withheld bodies receive a bounded result, and all returned shares still pass
the full local pool validator. The libp2p adapter exposes it under the distinct
`/outcomemesh/workgraph/1` ID only when an operator installs a handler; default
hosts and ordinary CLI commands cannot negotiate it. `work-serve-quic`
explicitly installs it alongside, but independently from, chain-v1. Two-host
QUIC tests cover peer-ID pinning, a negotiated 512-byte frame, parent/child
relay, context rejection, and an independent one-stream-per-peer resource
scope. The parent-scoped round manager prepares through the in-process block
router and replaces its pool whenever the best parent changes. Shares remain
ephemeral until a hard anchor commits their closure; relay alone never writes
them to the chain forest. The separate header-first versioned chain session has
its own per-peer/global concurrency and admission scopes. Its multiple
activation trees are durably reopened and re-indexed by the optional
bounded forest, including the persisted local equal-work incumbent.

For outbound relay, a round can announce an explicit sorted subset after
proving every ID is locally owned. The remote negotiated inventory limit may
shorten it; returned statistics identify the exact announced prefix. The QUIC
miner therefore gives each of at most eight explicit authenticated peers an
independent bounded unpublished-ID queue and relay worker. Its mining callback
only enqueues an admitted ID; it never dials, blocks on a stream, or waits for
another peer. Each worker drops only successful prefixes and retries the suffix
after a fresh batch or periodic partial-batch tick without invalidating hard-PoW
progress. The CLI requires a timer from 8 seconds to 1 minute and defaults to 8
seconds; count-only batching measurably underpays a miner too small to reach 128
shares in one round. The miner also installs the inbound round and chain-v1
handlers. Activation-aware peer exchange and topology-derived peer choice
remain restricted to the explicit opt-in selector. A selected local anchor
schedules a coalesced chain-notify-v1 session per
configured peer in the background. Each receiver still initiates normal
verified synchronization. A chain responder pins the canonical path advertised
by its handshake, so mining the next anchor cannot change that in-flight
response. If synchronization changes a peer's selected parent, its round is
invalidated and stale hashing is canceled.

The active QUIC miner also uses first-admission forwarding. `ServeAccepted`
observes only a share newly inserted into the validated pool; idempotent
duplicates still complete the wire protocol but cannot trigger fanout again.
The publisher skips the authenticated source and sends the share through the
same per-target queues, timers, limits, and selected-inventory proof as local
work. A generation- and mining-context-bound buffer holds admissions that race
publisher attachment, capped at 8,192 and cleared on parent change. A two-hop
round fixture proves that the middle node can serve the exact admitted body to
the destination.

The experimental miner can replace explicit addresses with a bounded ranked
selection from its signed peerbook. It first refreshes that book from explicit
and eligible signed bootstraps using activation-bound chain-v1 peer exchange.
Version-1 records bind capability bits and one exact activation height to the
peer identity; batches are validated and persisted atomically. Selection then
shares the ordinary reputation, latency, exponential-backoff, and ASN-diversity
machinery and requires a live WorkGraph handshake against the current round
before a peer becomes a target. The handshake-only probe exposes no share
inventory. Explicit and automatic targets together remain capped at eight, and
startup fails if the requested compatible count is unavailable. Bootstrap view
bias and Sybil resistance remain operator/testnet concerns.

The selected set is reused for a bounded peerbook refresh every 30 minutes while
mining continues. Selected bootstraps and other learned records remain separate tiers;
each tier rotates by a local-identity/epoch keyed hash instead of a fixed peer-ID
prefix. Active relay targets are not swapped in the middle of a round.

One maximal 1,024-ID relay is bounded to exactly 630,258 bytes of bidirectional
application framing when a peer forces one maximum-size body per batch. The
QUIC adapter's fixed-window defaults admit eight such streams per peer and 512
globally per minute: approximately 82.1 KiB/s per peer and 5.13 MiB/s for the
node averaged across a window. Boundary bursts can be twice that average, and
transport headers/retransmission are outside the application counter. These
ceilings close unbounded sequential-stream admission; simulation still governs
the much lower target operating rate needed for fair propagation.

The corresponding local pool implementation verifies
weak PoW and exact context before storage, owns detached bodies, accepts bounded
out-of-order children, resolves them only after all parents are accepted, and
caps count/bytes at the consensus batch limits. It admits at most 255 distinct
weak-share miners, reserving the 256th reward identity for the still-unknown
anchor. Mining parents are selected from accepted tips with a saturating
O(parent-count) coverage score and deterministic Work-ID tie-break, then the
selected set is re-sorted into canonical Work-ID order before encoding. After a
hard seal is found, the pool reconstructs and consensus-validates its exact
canonical closure. Hard-target shares are redirected to the block path rather
than being inserted and double-counted.

The fork coordinator integrates the activation boundary without changing active
version-0 storage. For every candidate branch it reconstructs resource
state, the last 11 timestamps, lagged target, fee queue, and predecessor earning;
only hard-target work is added to cumulative fork weight. Competing activation
anchors, arrival-incumbent equal-work handling, a higher-work side-branch
reorganization, and branch-local delayed rewards are executable tests. Two
nodes may retain different exact-work tips until one is extended; this prevents
a late publisher from grinding one ID that deterministically displaces every
honest node. Its isolated Pebble schema
persists canonical block bytes, immutable resource deltas, history, fee queues,
cumulative work, a checked logical-history counter, and selected tip in one
synchronous batch. Schema 4 requires every retained non-floor node to carry
exactly one recovery representation: an immutable parent delta or a full-state
replay checkpoint, never both. Explicit maintenance creates a checkpoint only after
2,048 selected-ancestry heights by default and retains at most four non-base
checkpoints. Creation atomically replaces that node's delta; rotation turns an
evicted checkpoint back into its exact parent delta in the same batch. Reopen
reconstructs every branch parent-first, verifies each delta/checkpoint root and
the exclusive representation rule, and rejects corrupted checkpoints. Pre-alpha
schemas 2 and 3 fail closed and are rebuilt by replay rather than silently
migrated.
The 64-GiB logical budget covers both representations, and an injected pre-sync
failure leaves memory and disk unchanged. Explicit maintenance can atomically
remove only side-fork subtrees whose highest node is behind a local retention
window (4,096 heights by default). It retains the entire canonical path plus
every ancestor of a side branch at the boundary, updates the logical byte
counter in the same synchronous batch, and is disabled by a zero local setting.
Canonical history pruning is a disabled-by-default local operation with a
separate history-anchor and replica-custody rule. The isolated
`node/workarchive` version-0 statement binds network, genesis,
activation height, immutable tree base, an exact selected `storage.Tip`, the
ordered ancestry commitment and node count back to that base, a monotonically
linked predecessor statement, and a future archive-manifest ID. A canonical
checkpoint carries 2–64 sorted Ed25519 attestations and is accepted only under
an explicit sorted trusted-key policy with a quorum of at least two. Verification
recomputes the selected ancestry from local WorkChain data; a valid signature
cannot keep an anchor valid after its branch is reorganized away. Checkpoint
files use bounded strict decoding and atomic file/directory fsync publication.
The content-addressed archive manifest commits the exact binding, anchor,
ancestry root/count, total block/byte counts, and ordered chunk descriptors.
Every chunk binds network, tree base, index, first height, and up to 256
canonical blocks under a 64-MiB ceiling; legacy v0 chunks additionally bind the
terminal anchor while current v1 chunks derive that binding from the manifest.
Export snapshots only the
selected activation-to-anchor IDs, writes immutable 0600 files, and rechecks
the selected ancestry before directory fsync/rename. Verification rejects
unexpected or non-regular files, checks every chunk ID and boundary, and
replays every block through ordinary WorkChain execution from the separately
verified activation base. Persistent restore builds a new temporary Pebble
tree, closes and fully reopens it, checks the final tip/ancestry, then publishes
the directory with rename and parent fsync without replacing an existing path.
It never trusts an archived state image. A restore fixture excludes a retained
sibling branch, reopens, and mines another block; corruption, reorg-before-
publication, tight limits, symlinks, extra files, and pre-publication failure
all fail closed. A real subprocess is killed immediately before archive
directory rename and immediately after rename but before parent fsync; recovery
finds respectively no destination or a fully reopenable and extendable tree.
Replica custody is a second key set and policy. Between 2 and 64 canonical
Ed25519 receipts bind the exact statement, manifest, anchor, opaque location
commitment, verification time, and retention deadline. A receipt can be made
only after its replica passes full archive replay. Prune authorization rejects
duplicate keys, location IDs, paths, directory identities, stale receipts, or
insufficient remaining retention, then replays every distinct directory again
and fsyncs the exact availability-bundle ID before touching WorkChain. The
symlink-resolved evidence destination must lie outside every replica tree.
Fresh custody can extend a receipt without claiming a second full replay. A
trusted auditor signs a short-lived random nonce and an exact future retention
deadline; the sampled chunk IDs are derived deterministically from that nonce,
the manifest, and predecessor receipt. The replica returns every sampled chunk,
a signature over their canonical batch digest, and a receipt-v1 link to the
predecessor and proof. Legacy receipt v0 remains valid. A separate allowlisted,
identity-pinned `/outcomemesh/workarchive-custody/1` QUIC-v1 stream executes one
bounded challenge → batch → proof → renewal exchange under resource and rate
limits independent of bulk archive transfer.
The replica durably publishes the complete canonical exchange before its first
response byte and reloads it after restart, so the same challenge receives the
exact first proof/receipt while a sibling renewal is rejected. The auditor
publishes its signed challenge before dialing and its verified exchange before
the renewed receipt. One-shot `work-archive-custody-serve-quic` and
`work-archive-custody-challenge-quic` commands enforce pinned/allowlisted
transport peers and four-way transport/evidence key separation. Process tests
cover the publication crash boundary, replica restart, exact response replay,
and auditor recovery without a live replica.

The schema-4 pruning batch is permitted only with an explicitly non-zero local
`CanonicalRetention`; zero is the default. The archive anchor must remain on
the selected branch at least that many heights, and every remaining side branch
must descend from it. One synchronous batch replaces all earlier node/block/
recovery records with canonical header records, converts the anchor to a full-
state retained floor, persists the statement/manifest/availability IDs, and
updates the logical byte counter. The immutable activation `BaseID` is unchanged.
Reopen reconstructs every archived header from the external base and verifies
ID/parent order, ASERT target, timestamps, cumulative work, floor metadata,
ancestry root/count, and floor state before replaying descendant deltas. The
retained floor can advance again, and the recovered chain remains extendable.
A real subprocess killed on either side of this batch recovers exactly the old
or new database.

After the floor advances, `ComposeDirectory` can produce the next complete v0
archive without reconstructing the pruned WorkChain database. It requires the
exact predecessor checkpoint and manifest recorded by the floor, fully replays
that archive, and streams its blocks followed by the selected executable suffix
through the same bounded publisher. The source manifest/chunks are checked
again while streaming; immediately before rename the composer requires the
floor record, target tip, and full ancestry commitment to remain unchanged. The
result is a normal self-contained archive, so existing verification, restore,
attestation, replica custody, and the next floor transition need no alternate
trust path. In format v1 a chunk does not embed the terminal archive anchor;
instead, the manifest binds its ordered descriptor to the final tip and ancestry.
Composition freezes every predecessor chunk boundary, so all prior content IDs
remain identical and only suffix IDs are new. Network/base/index/height and the
canonical blocks remain inside each chunk, and replay still validates the full
chain. Legacy anchor-bound v0 archives remain accepted. Standalone directories
materialize every referenced file. The transport-neutral object exchange stores
canonical chunks under their exact lowercase content IDs, verifies the full
directory before import, and enforces exact object/byte budgets both on reopen
and insertion. Canonical request/batch messages bind one manifest, sort and
deduplicate at most 64 IDs, and carry at most 64 MiB of combined chunk data.
Each received object is validated against its descriptor. Once none are
missing, materialization builds a fresh standalone directory, fully replays it,
and atomically publishes it without replacing an existing destination. A
replica seeded from the predecessor archive therefore requests only the new
suffix objects; incomplete or corrupt caches cannot authorize restore or prune.
An opt-in `/outcomemesh/workarchive/1` libp2p QUIC-v1 stream now carries these
messages. The initiator pins the exact authenticated server identity; the
server uses a canonical explicit client allowlist and rejects outsiders before
its independent rate window. One stream carries at most four batches (256
objects and 256 MiB of chunk payload), forbids repeated IDs, and accepts only
the exact requested response. If more data remains, the receiver opens another
stream and recomputes only its still-missing set. A real loopback fixture starts
from the predecessor generation and proves that exactly one suffix object
crosses the authenticated stream before full materialization and replay.

This does not create network finality or prove independent failure domains.
After pruning, the local node deliberately rejects forks whose parent is below
its floor; enabling it is therefore an operator-selected local finalization
horizon. Automated custody scheduling and evidence rotation, bulk
archive-session CLI integration, disk-exhaustion campaigns, and longer physical-filesystem soaks remain before
public activation. The
integration suite now covers all four synchronous WorkChain batch classes:
commit, checkpoint rotation, stale-fork prune, and canonical-floor transition.

## Milestone-5 evidence required

- canonical share, ID, target, DAG-root, and payout vectors;
- strict decoder fuzzing and maximum-bound tests;
- proof that fixed rates match the published formula, cannot reward omission,
  and remain bounded at every allowed batch size;
- duplicate/cycle/missing-parent/non-canonical-order negative tests;
- simulations for honest proportionality, propagation delay, withholding,
  orphan anchors, competing forks, a multi-seed selfish-strategy grid, and
  bandwidth;
- a versioned activation-review document covering a one-percentage-point
  standard/bounded-trail selfish-mining grid and direct-versus-delayed
  private-fee fragmentation, with an exact reproducibility digest and explicit
  external gates;
- explicit block-version and cross-boundary reorg tests proving no implicit
  activation checkpoint or double payout.
