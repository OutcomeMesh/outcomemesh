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

Version-0 `policy_hash` and `payload_hash` are committed resource metadata.
Execution does not resolve `policy_hash` into a program or require ordinary
outputs to inherit those fields. The transaction's signed `guard_program`
applies to that transaction's pre-state and candidate post-state only. There is
no market-price opcode or implicit fiat-payment oracle. Persistent spending
policies and atomic multi-owner settlement require a separately specified
version; see [ownership and exchange](OWNERSHIP_AND_EXCHANGE.md).

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
proof of work. A strictly heavier tip replaces the selected version-1 tip; an
exact-work tie keeps the local incumbent. The incumbent is persisted and sync
does not fetch an equal-work version-1 peer solely because its ID is smaller.
Nodes may therefore hold different tips during a tie and converge when either
branch gains more hard work, as ordinary proof-of-work nodes do. This local rule
prevents a withheld publisher from revealing only IDs that win one universal,
grindable tie-break. Version-0 fork choice remains byte-for-byte compatible and
continues to use its lexicographic ID tie-break. Activation still does not turn
the first observed boundary parent into an implicit checkpoint.

The inactive chain-protocol-v1 codec carries this same tagged union in appended
`VersionedBlock` and `VersionedHeaders` message types. Each object remains in
its unchanged consensus encoding; length-delimited headers allow one contiguous
batch to cross from v0 to v1. The codec checks basic syntax, ancestry, height,
and forbids a v1-to-v0 reversal, but it deliberately does not choose an
activation height. That stateful rule remains the activation router's job.
The ordinary chain reader retains its 8 MiB v0 payload ceiling. The versioned
session explicitly opts into the larger WorkGraph-block ceiling, and the frame
prefix is checked against that ceiling before allocation. Versioned requests,
status negotiation, and session routing remain inactive by default.

The appended control grammar is now canonical but still inactive.
`ChainHelloV1` carries the exact network ID, genesis ID, activation height,
`versioned_sync_v1` capability, tip ID/state root/height/cumulative hard work,
and maximum accepted frame body. A mismatch in network, genesis, or activation
height fails before locators. Compatible peers intersect frame ceilings.
`GetVersionedBlocksV1` and `GetVersionedHeadersV1` use 1–32 unique locators and
a 1–128 limit; `VersionedBatchDoneV1` binds a response to the responder tip.
An isolated router-backed serving/synchronization loop now implements these
types. It applies the negotiated ceiling in both directions, validates the full
v0/v1 header context before requesting bodies, requires body/header identity,
and submits every block through the activation router. A continuation locator
can advance along a downloaded side branch before that branch has enough work
to become the selected local tip. At completion the replayed ID, height, state
root, and cumulative work must equal the hello. The responder pins the complete
canonical path used to construct its hello for the lifetime of that session;
later local anchors cannot change its headers, bodies, or batch-done tip. The
QUIC adapter registers the loop only through the opt-in
`/outcomemesh/chain/1` handler; default hosts and
ordinary v0 CLI commands do not install it. The experimental
`work-serve-quic`/`work-sync-quic` pair is protocol-exact and cannot negotiate
the version-0 session as a fallback.

The optional local activation forest does not add a consensus field. It stores
each v1 tree below the canonical hash of its v0 activation base, fully verifies
every child database on reopen, rebuilds block ownership, and recomputes the
winner by the fork-choice rule above. There is deliberately no persisted global
tip requiring an atomic commit across databases.

The local `work-activation.bin` profile is an operator safety boundary, not a
network or consensus message. Its fixed 64 bytes bind the network ID, genesis
ID, activation height, fee delay, tree cap, and forest-wide history budget.
Peers still compare the consensus-relevant network/genesis/height values in
`ChainHelloV1`; local storage limits are not negotiated as consensus.

Activation-aware discovery uses a backwards-compatible signed peer-record
version 1:

```text
PeerRecordV1 {
    version:           uint16 = 1
    network_id:        uint32
    sequence:          uint64
    expires_at:        uint64
    features:          uint64
    activation_height: uint64
    public_key:        [32]byte
    addresses:         list<bytes>
    signature:         [64]byte
}
```

The signature message is the domain-separated hash
`SHA256("OMESH/p2p/advertisement/v1" || canonical_unsigned_record)`. Known
feature bits advertise versioned-chain sync, WorkGraph relay, chain notify,
and activation peer exchange. Unknown bits, a zero feature mask, or a zero
activation height are invalid. These signed claims are routing hints, never
proof that a live service exists.

`ChainHelloV1` advertises a separate `peer_discovery_v1` capability. Only when
that bit, network, genesis, and activation height negotiate successfully may a
versioned session carry the existing bounded `GetPeers`/`Peers` exchange. A
response contains at most 64 records and is shortened to a deterministic prefix
that fits the chain-v1 frame limit negotiated by both peers. Each record must
validate cryptographically, belong to the negotiated network, advertise
versioned-chain support, and bind the exact negotiated activation height. The
receiver merges the whole batch or none of it. A responder serves only matching
v1 records from its bounded local book, and a session accepts at most eight
discovery requests. Automatic mining routing still confirms the signed
WorkGraph claim with a live inventory-free exact-context probe.

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

Candidate timestamp is a local objective generation, not part of the stable
WorkGraph session context. A node advances it after 60 seconds while the parent
is unchanged. Before publishing the new generation it cancels and drains the
old objective miner/finalizer, then atomically revalidates the existing share
pool under the later timestamp. Network, height, parent, target, payload root,
and median-time-past must be identical across this operation. Concurrent share
admission is generation-checked and retries validation if rollover won the
race. A changed stable field instead creates an unrelated empty pool. Retained
inventory is reannounced through bounded per-peer queues; the wire inventory
and request limits below do not change.

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

The opt-in CLI receiver binds the session to one ephemeral mining round. That
round owns the prepared payload, pool, miner surface, and relay node for one
exact best parent. Parent stability is rechecked after construction; at most
three builds are attempted during chain churn. A new parent or explicit local
anchor invalidates the entire round, so no uncommitted share is migrated across
payload contexts. The round itself is not consensus or persistent state.

An initiator may select a strict sorted subset of at most 1,024 locally owned
IDs instead of the pool's default first page. Selection is checked against the
pool before the stream exchange. Negotiation may reduce the announcement to a
prefix; relay statistics return its exact length so an outbound queue can drop
only attempted IDs and retain the suffix. This is local transport progress
accounting and does not alter `ShareInventoryV1` encoding or consensus. The
experimental miner applies it independently to at most eight explicit peers;
peer-local bounded queues and workers likewise add no wire or consensus rule.
On a first successful inbound pool admission, that miner may enqueue the same
locally owned ID to its other explicit peers. It excludes the authenticated
source and does not observe duplicate admission, so cycles terminate at the
round pool. This forwarding policy, its count/time thresholds, and its bounded
publisher-handoff buffer do not change any WorkGraph message or consensus rule.
An initiator may also close immediately after the symmetric hello exchange. The
responder treats that clean EOF as a finite capability probe; no inventory,
request, body, or result message is sent. Automatic peer selection uses this to
verify protocol support and byte-identical mining context without disclosing
the local pool. It adds no message type or feature bit.

The opt-in `/outcomemesh/chain-notify/1` protocol adds no message type and no
consensus rule. It reverses only stream roles: the node that found a selected
anchor dials and runs `ChainNode.Serve`, while the receiver runs
`ChainNode.Synchronize`. The receiver sends `ChainHelloV1`, independently
decides whether the advertised cumulative work is better, and if so performs
the same bounded header-first/body-second pull over the stream. A losing or
equal notification transfers no blocks. Local outbound workers may coalesce
multiple wins to one pending prompt per peer because every session advertises
the newest selected tip at its own handshake. Default hosts cannot negotiate
it.


## Experimental node-side custody V2 compatibility

The optional custody V2 assignment/job, session-bound fence V1, target protocol
and accepted-source receipt are specified in [CUSTODY_V2.md](CUSTODY_V2.md).
They do not change ledger consensus bytes or activate a fork. The V2 outer
assignment commits an immutable witness policy; signed jobs derive their scope.
The V2 effect and acceptance adapters reject legacy/no-quorum substitution.
Legacy V0 fence domains/bytes and existing custody V0/V1 histories remain
unchanged and are not migrated or resolved by this optional service.

## Experimental registry-bound custody profile

The off-chain [enrolled custody profile](CUSTODY_V2_ENROLLED.md) adds signed policy
version 4 and registry format 2. It mandates complete exact selection/admission
proofs at original owners and binds both into consumed/pending evidence. Registry
semantic identity keeps its version-1 domain across formats; old histories are
never reset or promoted. These operational formats do not change version-0
consensus, transactions, emission or account ownership.

The separate [format-4 proof transport](CUSTODY_V2_ENROLLED_DELIVERY.md) carries
both complete registry and admission proofs. Its receiver descriptor and signed
retention receipt bind the exact registry enrollment ID alongside the admitted
job. Receipt retention is not execution permission or a current-head assertion.
Legacy delivery-2 encodings and negotiated protocol remain unchanged.

## Disabled node-side legacy cutover review

The experimental [cutover review](CUSTODY_CUTOVER_REVIEW.md) adds separate
canonical historical evidence, original-source observations, a non-runtime
successor Blueprint and a three-role signed proposal. The node can retain this
preparation under exact original local pins. None of these objects is a V2 job,
admission genesis, registry selection, source import or execution permission.
Consensus bytes/rules and custody V0/V1, V2 policy 2/3/4 and registry 1/2 execution
semantics remain unchanged for those artifacts. The accounting extension below
implements spending carry-over; protected exclusion of old grants remains an
unimplemented activation gate.


## Inactive imported custody accounting

[Profile5](CUSTODY_IMPORTED_ACCOUNTING.md) deterministically derives a successor
from the complete signed legacy review and retains historical spending, the
accepted source predecessor and retention floor in the existing admission machine.
Its lifetime cap is old spending plus authorized remainder; ordinary closure never
refunds spending. Native Genesis2 cannot initialize the same profile5 at zero.
Policy5 commits the full Proposal ID and original resource/descriptor identities.
Genesis5 encodes the complete Proposal and validates every derived assignment field.

Registry Selection3 uses separate version-3 signature domains while sharing the
original Descriptor2 namespace, witness owners and one permanent choice with
Selection2. Descriptor3 does not exist. A pending/final native choice cannot be
reset to import, and an import cannot allocate another native budget in that slot.
The full Selection3 quorum is mandatory for imported admission witness creation,
open and recovery, and is retained with a format-5 ready marker.

The exact formats, bounds, role requirements and fixed vectors are specified in
the linked contract. Profile5 remains rejected by all execution owner constructors
and existing delivery profiles. No active source journal, legacy ticket exception,
key revocation or consensus change is introduced. Protected deployment, every-path
version enforcement and original-source handoff remain activation requirements.


## Sealed original custody sources

The [source handoff](CUSTODY_SOURCE_HANDOFF.md) binds the full selected import to
original A/B journal roots, spending, accepted source position and retention.
It publishes a permanent seal before the complete selected proof. Ordinary live
source access refuses either named handoff file, and exact recovery cannot select
another successor or discard pending/orphan evidence. Held source decisions and
current V2 execution, acceptance, Serve and proof-intake paths recheck that source
boundary. The new record/pair formats, strict bounds, domains and fixed vectors
are specified in the linked contract. Existing consensus and artifact bytes remain
unchanged. This is local original-source exclusion; protected independent version
authority and an active imported adapter remain activation requirements.


## Isolated custody source gateway

The experimental [gateway v1](CUSTODY_GATEWAY.md) has separate issuer-signed
source/root/key/ACL/UID descriptors, exact-position signed Inspect/ReadChunk/Revoke
requests and service-signed durable historical responses. A response head hashes
the unsigned response including its complete signed request and previous head;
sequence increments once per committed action. An exact active tip retry returns
identical bytes. Revocation is issuer-only and permanent; old read retries refuse.
Startup/recovery never adopts an unpinned tip. Linux kernel peer UID verification
and a separate private service UID protect original object/key access from old
participant copies. They do not fence host root or a complete service VM clone.

The wire contract bounds descriptors to 1024 bytes, requests to 241 bytes,
response data to 64 MiB, events to 256 and the response journal to 256 MiB. The
canonical vectors and malformed-input fuzz target are in gatewaywire. The base service
performs source inspection/original chunk reads and revocation. The explicit
protected runtime extension below adds versioned execution; the base descriptor
and request bytes remain compatible. Independent monotone/key deployment remains
an activation requirement.


## Protected profile-5 runtime

[Plan5 and protected effects](CUSTODY_PROFILE5_EXECUTION.md) add separate job
plan/signature domains, five-role deployment endorsement, typed runtime envelopes
and Result5/Receipt5/ServeReceipt5/AdmissionClosure5 wrappers. They require fresh
service signatures over exact completed core artifacts, scope, deployment and
full admission identity. Old Plan2/result/receipt/closure bytes and their domains
remain unchanged. Imported accounting-only Plan2 does not become executable;
ordinary profile-5 owner constructors remain closed.

Execution occurs only inside explicitly configured original service owners.
Durable intent and consumed session precede original object reads; the winning
volatile session cannot be imported/reconstructed after a crash. The sealed old
source plus protected continuation preserve sequence/head/current receipt and
retention. Unknown outcomes retain spending and obligations; full protected A/B
Serve receipts close the original admission with no refund. Gateway revocation
is permanent and local. Bounds, compatibility, clock/UID assumptions, vectors,
exact recovery and remaining activation gates are specified in the linked rules.
No consensus, coin issuance, raw legacy ticket or mainnet permission is changed.


## Profile-5 gateway transport

The opt-in `/outcomemesh/custody-gateway/5` QUIC protocol carries one length-prefixed
`OMCGXRQ5` signed Runtime envelope and one length-prefixed `OMCGRSP1` service
response, with complete EOF in both directions. It changes no artifact domain,
encoding, admission quorum or source/version rule. An unprivileged relay forwards
through the existing kernel-UID-checked Unix client; it has no execution owner.
Legacy custody protocols are not enabled as fallback. Independent peer/descriptor
pins, allowlist, request/response validation and exact cold recovery are specified
in [the network contract](CUSTODY_PROFILE5_WAN.md).


## Independent custody guard extension (experimental, 2026-10-29)

The optional [guarded Plan5 deployment](CUSTODY_INDEPENDENT_GUARD.md) changes no
consensus rule. Its nonzero Guard public key is included in a distinct deployment
body (`OMCGDG01`) endorsed by issuer, authority, control and both services. The
key must differ from gateway clients, services, participants, consumers, auditors
and witnesses. Derived execution and Serve scopes bind this same key; Serve
retains its underlying Version0 command semantics and execution Version1.

A guard request is `OMCGREQ1 || kind:u8 || subject:32 || namespace:32 || slot:u64
|| choice:32 || subject-signature:64` (177 bytes, big-endian slot). The subject
signs DomainHash(`OMESH/custody-guard/v1/request`, unsigned request). The guard
signs DomainHash(`OMESH/custody-guard/v1/seal`, unsigned request), only after
durably fixing that complete request. The slot ID hashes the unsigned request
without its final choice under `OMESH/custody-guard/v1/slot`. Kinds 1, 2, 3 mean
fence, service effect and admission. Their namespaces/slots/choices are fixed by
the table in the linked specification, not supplied by the seal recipient.

Guarded votes/effects retain their original inner signature domains, replace the
outer magic, and append exactly 64 bytes of seal. Guarded scope adds the key after
its witness list; guarded deployment adds it immediately after the magic. Guarded
quorums contain only guarded votes of the fixed extended size. Missing, all-zero,
foreign, mixed or rebound seals fail verification under a guarded policy. No
counter-signature supplied by an artifact can select the verifier's guard key.
Every certificate in a guarded admission binding must use that exact deployment
from its original genesis sequence zero; unguarded history cannot be grafted onto
it. Legacy bytes retain legacy meaning and no clone-protection claim.


### Permanent guard subject revocation (experimental, 2026-10-29)

An optional immutable `Config.Revoker` pins a separate Ed25519 administrative key,
unequal to every subject and the guard. Zero/omitted preserves old config JSON and
ConfigID bytes. ConfigID hashes canonical config JSON under
`OMESH/custody-guard/v1/config`. GuardID hashes `public-key:32 || RootID:32 ||
ConfigID:32` under `OMESH/custody-guard/v1/identity`; none may be zero.

`OMCGRVK1 || GuardID:32 || subject:32 || authority:32 || ReasonID:32 ||
authority-signature:64` is exactly 200 bytes. The authority signs DomainHash of
its unsigned body under `OMESH/custody-guard/v1/revocation`. All fields are nonzero;
subject differs from authority. The receiver requires the exact pinned authority,
listed subject and original GuardID. No time, expected-head or caller nonce is
accepted. The command permanently revokes that subject across all slot families.

`OMCGRCP1 || signed-command:200 || before-sequence:u32 || before-head:32 ||
guard-key:32 || guard-signature:64` is exactly 340 bytes. The guard signs the
unsigned receipt under `OMESH/custody-guard/v1/revocation-receipt`. Sequence is
big-endian, less than 4,128; zero sequence iff zero head. The guard key differs
from subject and authority. Verification requires the independently pinned guard
key, GuardID and exact signed command; a receipt never selects its own trust root.
After is `(before.sequence+1, DomainHash("OMESH/custody-guard/v1/event",
before.head, signed-command))`. It is the historical position of revocation,
not an assertion about the latest service tip.

Choices and revocations share one serialized fsynced event stream and hash chain.
The original `.choice` file names are retained; exact length and magic distinguish
records. At most Config.Limit normal choices (maximum 4,096) and one revocation
per listed subject (maximum 32) may appear. Revocation slots exist only when a
revoker was configured, and ordinary choices cannot use them. Duplicate records,
choice after subject revocation, invalid signature/authorization, partial records,
gaps or unknown trailing events refuse replay. Exact revocation retries add no
record and reproduce the original signed receipt. Different commands for an
already revoked subject refuse. All later Choose calls for that subject refuse,
including historical exact retries. Previously issued seals remain valid.

`POST /outcomemesh/custody-guard/revoke/1` requires request EOF before mutation and
returns the fixed receipt. Recovery admits only a retained cursor itself or one
exact matching signed command after it. It cannot skip an intervening choice,
adopt the current tip, replace a root/key, clear spending or refund unknown work.
The guard serializes signing and revocation, not packet arrival: a previously
signed seal may arrive after a revocation receipt. This extension changes no
consensus rule. Legacy roots cannot be upgraded by editing their config.

## Experimental custody signer replacement

The opt-in [custody replacement protocol](CUSTODY_KEY_REPLACEMENT.md) is outside
consensus activation. A guard-signed successor receipt changes the signer while
preserving the original subject's slots, quorum membership and obligations.
Legacy encodings remain unchanged; explicit new magic values carry replacement
proofs and guarded service responses. No balance, reward, genesis or network
version changes follow from this recovery mechanism.


## Guarded retained-result acceptance (experimental, 2026-10-29)

Guarded profile-5 services may accept an already completed and original-quorum
certified result after ordinary delivery age only under the separately signed,
bounded [retained acceptance](CUSTODY_RETAINED_ACCEPTANCE.md) rule. New command
kinds 9/10 and receipt magic OMCVLAC5 are opt-in and rejected by older readers.
Context, full bundle, both role signatures, source lineage and the independent
effect seal are mandatory. Unknown work has no closing authorization. The v0
state commitment and consensus receipt roots are unchanged by the accompanying
[index optimization](STATE_SCALING.md). No activation rule is waived.
