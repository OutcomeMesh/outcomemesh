# Protocol specification

Status: version 0 draft

This document describes the current deterministic standalone vertical slice. It
includes blocks, proof of work, atomic storage, and reward maturity; networking,
WorkGraph, committees, Wasm, privacy, and zero-knowledge proofs remain excluded.

## Numeric conventions

- All integers are unsigned unless explicitly stated.
- Consensus arithmetic is checked; overflow or underflow invalidates the object.
- Version 0 resource amounts are `uint64` raw asset units.
- Floating point is forbidden.
- Byte order is big-endian.

## Identifiers

All identifiers are 32-byte values:

- `Hash`
- `Address`
- `AssetID`
- `ResourceID`

An Ed25519 public key maps to an address as:

```text
Address = SHA256("OMESH/address/ed25519/v1" || public_key)
```

The native asset identifier is:

```text
AssetID = SHA256("OMESH/asset/native/v1")
```

## Canonical encoding

Every consensus object begins with an explicit version. Fixed-width integers use
big-endian encoding. Byte arrays and lists use an unsigned LEB128 length encoded
in the shortest possible form. A decoder rejects:

- truncated input;
- non-minimal variable integers;
- values exceeding configured limits;
- trailing bytes;
- unknown mandatory versions;
- unknown opcodes.

JSON, Go `gob`, database encoding, and protobuf are not consensus encodings.

## Resource

```text
Resource {
    id:           ResourceID
    version:      uint64
    owner:        Address
    asset:        AssetID
    amount:       uint64
    spend_after:  uint64
    policy_hash:  Hash
    payload_hash: Hash
}
```

Version 0 accepts only `version = 0`. The zero identifier is reserved and invalid
for stored resources. An input is spendable in block `height` only when
`height >= spend_after`. Ordinary transaction outputs may choose any
`spend_after`; zero means immediately spendable.

## Transaction

```text
Transaction {
    version:        uint16
    network_id:     uint32
    inputs:         list<ResourceRef>
    outputs:        list<ResourceOutput>
    guard_program:  GuardProgram
    fee:            uint64
    valid_until:    uint64
    nonce:          [32]byte
    signer_key:     [32]byte
    signature:      [64]byte
}
```

Version 0 limits:

- inputs: 1 to 256;
- outputs: 1 to 256;
- GuardVM instructions: 1 to 256;
- GuardVM stack depth: 64;
- one Ed25519 signer;
- every input must be owned by the signer address;
- fee is paid only in the native asset.

The unsigned transaction identifier is:

```text
tx_id = SHA256("OMESH/txid/v0" || canonical_unsigned_transaction)
```

The signature message is:

```text
SHA256("OMESH/sign/transaction/v0" || tx_id)
```

An output resource identifier is:

```text
resource_id = SHA256("OMESH/resource/output/v0" || tx_id || uint32(index))
```

The signature is excluded from `tx_id`. The nonce prevents otherwise identical
transactions from sharing an identifier.

## Conservation

For every non-native asset:

```text
sum(inputs.amount) = sum(outputs.amount)
```

For the native asset:

```text
sum(inputs.amount) = sum(outputs.amount) + fee
```

All sums use checked arithmetic. Zero-amount outputs are invalid.

## State transition

Validation order is consensus-critical:

1. Decode canonically and enforce structural limits.
2. Verify version and network identifier.
3. Verify expiry height.
4. Reject duplicate input identifiers.
5. Load every input from the pre-state.
6. Verify input version, signer ownership, and `height >= spend_after`.
7. Verify the Ed25519 signature.
8. Derive output identifiers and reject collisions.
9. Verify conservation and fee rules.
10. Build the complete candidate state diff.
11. Execute GuardVM against pre-state and candidate post-state.
12. Atomically consume inputs and create outputs.

Any failure leaves the pre-state unchanged.

## GuardVM version 0

GuardVM is a stack machine with typed `uint64` and `bool` values.

Initial opcodes:

```text
PUSH_U64
LOAD_BALANCE_BEFORE(owner, asset)
LOAD_BALANCE_AFTER(owner, asset)
LOAD_FEE
LOAD_HEIGHT
ADD_U64
SUB_U64
EQ_U64
LE_U64
GE_U64
AND
OR
NOT
REQUIRE
HALT
```

Arithmetic is checked. Type mismatch, underflow, overflow, stack underflow,
excessive stack depth, missing final `HALT`, instructions after `HALT`, or a false
`REQUIRE` invalidates the transaction.

`HALT` succeeds only with an empty stack. Each instruction costs one unit and the
instruction limit is also the initial gas limit in version 0.

## Reference state root

Milestone 1 uses a deterministic reference root, not the final sparse tree:

1. Encode every resource canonically.
2. Compute `leaf = SHA256("OMESH/state/leaf/v0" || resource)`.
3. Sort leaves by resource identifier.
4. Build a binary Merkle tree with domain-separated internal hashes.
5. Duplicate the last hash at an odd level.

The empty root is `SHA256("OMESH/state/empty/v0")`.

## Genesis document

The version-0 genesis document is encoded as:

```text
Genesis {
    version:      uint16
    network_id:   uint32
    timestamp:    uint64
    target:       Hash
    block_subsidy:uint64
    allocations:  list<Resource>
}
```

Allocations must contain unique, valid resources. `network_id` and `timestamp`
must be non-zero, `target` must be greater than zero, and `block_subsidy` must be
non-zero. The genesis state root is the reference state root of `allocations`.

```text
genesis_id = SHA256("OMESH/genesis/id/v0" || canonical_genesis)
```

Genesis is height zero and is not mined.

## Block and receipt

The version-0 development header is:

```text
Header {
    version:      uint16
    network_id:   uint32
    height:       uint64
    parent:       Hash
    timestamp:    uint64
    target:       Hash
    tx_root:      Hash
    receipt_root: Hash
    state_root:   Hash
    miner:        Address
    nonce:        uint64
}
```

A block is the canonical header followed by a list of canonical signed
transactions. Version 0 limits a block to 4,096 transactions and 8 MiB of
canonical bytes. The header `network_id` MUST equal the active genesis
`network_id`; checking only that it is non-zero is insufficient, and transport
handshake checks are never a substitute for this consensus rule. Transactions
execute in body order. A receipt is:

```text
Receipt {
    version:         uint16
    tx_id:           Hash
    post_state_root: Hash
    fee:             uint64
}
```

Transaction leaves commit to transaction identifiers. Receipt leaves commit to
canonical receipts. Both roots use order-preserving, domain-separated binary
Merkle trees and duplicate an odd final node. Empty transaction and receipt
roots have distinct domains.

After all transactions execute, the block creates exactly one native reward
resource:

```text
reward_amount = genesis.block_subsidy + sum(transaction fees)
reward_spend_after = height + 100
reward_id = SHA256(
    "OMESH/block/reward/v0" ||
    uint32(network_id) || uint64(height) || parent || miner
)
```

The integers in `reward_id` are big-endian. The reward ID deliberately excludes
the block nonce and final block hash, preventing a circular dependency between
the reward resource, state root, and proof-of-work seal. A reward ID must not
collide with the pre-state. Version 0 locks every subsidy-plus-fee reward for
exactly 100 block heights; spending it earlier invalidates the entire block.

The final state root includes the reward resource. The block identifier and
development proof of work are:

```text
block_id = SHA256("OMESH/block/id/v0" || canonical_header)
valid_pow = unsigned_big_endian(block_id) <= unsigned_big_endian(target)
```

The zero target is invalid. Fork weight contributed by a block is
`floor(2^256 / (target + 1))`; the chain with the greatest cumulative work wins,
with the lexicographically smaller tip identifier as the deterministic tie
breaker.

### Development ASERT

Version 0 computes every target from the genesis anchor. Consensus constants
are:

```text
target_spacing = 60 seconds
half_life      = 7,200 seconds
radix          = 65,536
pow_limit      = genesis.target
```

For candidate `height` and `timestamp`:

```text
schedule_error = (timestamp - genesis.timestamp) - target_spacing * height
exponent       = floor(schedule_error * radix / half_life)
shifts         = floor(exponent / radix)
fraction       = exponent - shifts * radix

factor = (((195766423245049 * fraction
          + 971821376 * fraction^2
          + 5127 * fraction^3
          + 2^47) >> 48) + radix)

target = genesis.target * factor * 2^shifts / radix
```

All operations are integer-only and divisions round toward negative infinity.
The result is clamped to `[1, genesis.target]`. Implementations must return the
clamped result before attempting attacker-controlled enormous bit shifts.

For timestamp validity, the candidate timestamp must be strictly greater than
the median of the latest 11 ancestor block timestamps (or all available blocks
near genesis). During admission it must also be at most 120 seconds ahead of the
validating node's clock. The clock bound is admission-dependent and is rechecked
when a previously-future block is reconsidered. Adversarial hash-rate and
timestamp simulations remain mandatory before a networked devnet.

## Experimental block version 1: WorkGraph activation

This section specifies an implemented, isolated prototype. It is not accepted
by active version-0 storage or session handlers. The isolated activation router
does enforce the transition and fork choice in-process. A separate version-1
WorkGraph stream negotiates and relays shares only between explicitly compatible
prototype peers; it does not reinterpret the version-0 chain session.

Activation occurs at one configured non-zero height. That first version-1 block
does not create a delayed WorkGraph payout because its version-0 parent already
issued its reward. Every later version-1 block must consume the validated
earning record of its direct version-1 parent; omitting it is invalid.

The routing rule is exact:

```text
height < activation_height  => version 0 only
height >= activation_height => version 1 only
```

The leading canonical `uint16` selects the unchanged version-specific decoder.
Every stored version-0 node at `activation_height-1`, including a non-canonical
side node, may anchor an independent version-1 tree. Fork choice compares the
best tip from every such tree and the pre-activation ledger by cumulative hard
proof of work, followed by the common lexicographic ID tie-break. Thus activation
does not turn the first observed boundary parent into an implicit checkpoint.

The inactive chain-protocol-v1 codec carries this same tagged union in appended
`VersionedBlock` and `VersionedHeaders` message types. Each object remains in
its unchanged consensus encoding; length-delimited headers allow one contiguous
batch to cross from v0 to v1. The codec checks basic syntax, ancestry, height,
and forbids a v1-to-v0 reversal, but it deliberately does not choose an
activation height. That stateful rule remains the activation router's job.
The ordinary chain reader retains its 8 MiB v0 payload ceiling. A future
versioned session must explicitly opt into the larger WorkGraph-block ceiling,
and the frame prefix is checked against that ceiling before allocation.
Versioned requests, status negotiation, and session routing are not active yet.

The appended control grammar is now canonical but still inactive.
`ChainHelloV1` carries the exact network ID, genesis ID, activation height,
`versioned_sync_v1` capability, tip ID/state root/height/cumulative hard work,
and maximum accepted frame body. A mismatch in network, genesis, or activation
height fails before locators. Compatible peers intersect frame ceilings.
`GetVersionedBlocksV1` and `GetVersionedHeadersV1` use 1–32 unique locators and
a 1–128 limit; `VersionedBatchDoneV1` binds a response to the responder tip.
These types do not yet have a router-backed serving/synchronization loop.

The next hard target is known before mining and is independent of the current
candidate timestamp:

```text
target(h) = ASERT(genesis.target, genesis.timestamp,
                  h, parent.timestamp + target_spacing)
```

The addition is checked. This lagged ASERT rule prevents a miner from choosing
a future timestamp to make its own proof easier. The candidate timestamp must
still exceed median-time-past and pass the ordinary local future-admission
bound. The configured proof-of-work limit must also keep
`((target+1)*512)-1 <= 2^256-1`; a saturated weak target is invalid because it
would break the fixed reward-rate assumption.

The canonical version-1 header is:

```text
WorkHeaderV1 {
    version:            uint16 = 1
    seal:               WorkSealV0
    tx_root:            Hash
    receipt_root:       Hash
    state_root:         Hash
    previous_work_root: Hash
    fee_queue_root:     Hash
    fee_award:          uint64
}
```

`seal.payload_root` is the domain-separated hash of the five roots plus the fee
award following the seal.
The block body is an ordered transaction list followed by the canonical
WorkGraph share list. Header ID and block ID are the WorkSeal ID itself: hashing
a second header preimage would make a lucky weak share unusable as an anchor.
The explicit economic and execution fields are nevertheless transitively committed by
`seal.payload_root`.

The winner's share parents commit the exact closure carried in its body. At
height `h+1`, replay revalidates that closure from block `h`, commits its root as
`previous_work_root`, and creates mature reward resources. For `E = 511`, the
fixed rates are `share_reward = floor(subsidy/(2E))` and
`anchor_subsidy = subsidy - E*share_reward`.

Transaction fees use a bounded fork-local delay queue. At activation the queue
is empty. Executing height `h` removes its fees from transaction inputs, takes
the amount already present at the queue cursor as `fee_award(h)`, replaces that
slot with the newly collected amount, advances the cursor, and commits the new
queue root. The award is independent of the current payload and current miner;
it is added to height `h`'s anchor earning and materialized at `h+1`. Thus a fee
is conserved, never minted, and is paid exactly `fee_delay` anchor transitions
after collection to a future PoW winner rather than the collecting producer.

Actual subsidy issuance is `anchor_subsidy + N*share_reward` for `N` included
shares; the matured `fee_award` is a transfer on top. Reward identifiers commit
the earning height, winning WorkSeal ID, recipient, and amount. A height-`h`
earning cannot be applied at any height other than `h+1`; fork-local state and
the fee queue remove abandoned-branch payouts and deposits on reorg.

Share gossip is inventory-first. `ShareInventory` announces at most 1,024
strictly increasing Work IDs for one exact network/height/anchor/target/payload
context. `GetShares` requests at most 256 missing IDs in that same context, and
`Shares` returns at most 256 ID-sorted canonical bodies. A response can contain
at most 81,664 bytes of raw share bodies before its bounded context/framing
overhead. The codec checks versions, counts, order, duplicates, exact context,
and canonical share syntax; the receiving WorkGraph pool must still verify PoW,
timestamp, DAG parents, and current-chain context before admission.

All three share messages require wire version 1. A WorkGraph stream begins with
a symmetric `WorkHelloV1` exchange carrying the exact share context, the
`share_relay_v1` capability bit, and the peer's frame/inventory/body maxima.
Contexts must be byte-identical and the negotiated limits are the intersection
of both advertisements, additionally clamped so a worst-case body batch fits
the negotiated frame. The reader rejects an oversized length prefix before body
allocation. A legacy version-0 peer therefore fails closed on the appended
message type instead of accidentally accepting WorkGraph data.

One stream carries one finite inventory relay. The receiver requests each
previously unknown ID at most once in bounded batches, admits every returned
body through full weak-PoW/context/DAG validation, and terminates with
`ShareResultV1 { accepted, rejected }`. Advertised-but-withheld bodies count as
rejected and are not requested forever. Repeated requests, unsolicited IDs,
mixed contexts, extra messages, and lack of progress close the stream.
