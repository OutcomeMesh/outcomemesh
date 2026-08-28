# OutcomeMesh implementation plan

Status: active
Protocol maturity: research / pre-alpha
Implementation language: Go 1.26.7
Initial build mode: pure Go, `CGO_ENABLED=0`

## Execution rules

This plan is intentionally gate-driven. A later milestone may be researched in
parallel, but it must not be integrated into the protocol until every exit gate
of the preceding milestone is satisfied.

Every consensus-affecting change must include:

1. a written rule in `docs/PROTOCOL.md`;
2. canonical encoding test vectors;
3. positive and negative unit tests;
4. a fuzz target for any new decoder or interpreter surface;
5. an explicit compatibility decision;
6. a security note when an invariant or trust assumption changes.

No milestone is complete because the code merely compiles. Completion requires
the stated safety properties and reproducible tests.

## Product thesis

The initial product is a native ledger where a user signs both a resource
transition and a bounded GuardVM program. The transaction is accepted only when
the actual post-state satisfies that program.

The long-term product is an agent-native settlement network with:

- open proof-of-work participation;
- protocol-accounted weak work shares;
- capability-limited accounts;
- encrypted outcome batches;
- permissionless solver competition;
- stateless verification;
- optional succinct execution proofs;
- paid archival storage.

The protocol must demonstrate value as a safe execution kernel before a public
token or mainnet launch is considered.

## Milestone 0: specification foundation

### Deliverables

- Architecture boundaries and dependency policy.
- Consensus and execution invariants.
- Versioned transaction and resource formats.
- Threat model and failure taxonomy.
- Repository layout and reproducible developer commands.

### Exit gates

- All consensus objects have an owner, version, and canonical representation.
- The state transition can be described without referencing a database, network,
  goroutine schedule, or wall clock.
- Deferred features are explicitly excluded from protocol version 0.

## Milestone 1: deterministic kernel

### Scope

Protocol version 0 supports a single-signer resource transfer with explicit
inputs, outputs, fee, expiry height, and a GuardVM program.

### Deliverables

- Fixed-size consensus primitives.
- Checked amount arithmetic.
- Canonical encoder and strict decoder.
- Resource and transaction validation.
- Ed25519 authorization.
- Bounded, loop-free GuardVM.
- Reference in-memory state.
- Atomic state transition and deterministic reference state root.
- Golden vectors, unit tests, and fuzz targets.

### Safety invariants

- A resource is consumed at most once.
- A transaction cannot create value.
- Every input is authorized.
- Failed execution changes no state.
- The state root is independent of insertion order.
- A GuardVM failure rejects the entire transaction.
- Unknown versions and opcodes fail closed.

### Exit gates

- `go test ./...` passes with the race detector.
- Fuzz smoke tests cover codec, transaction decode, and GuardVM decode/execute.
- Reordering map insertion produces the same state root.
- Random invalid transitions never mutate the pre-state.
- Test vectors are stable across repeated runs.

## Milestone 2: signed ledger and blocks

### Deliverables

- Genesis document and genesis state root.
- Block body and header formats.
- Transaction Merkle root and receipt root.
- Block execution over a state snapshot.
- Atomic block commit and crash recovery.
- Chain database schema using Pebble.
- Reference storage implementation for differential testing.

### Exit gates

- Killing the node at every write boundary recovers either the old or new block,
  never a partial state.
- Replaying the same chain from genesis produces identical roots.
- Pebble and reference storage produce identical results.

## Milestone 3: single-node proof of work

### Deliverables

- Replaceable PoW engine interface.
- SHA-256 development PoW.
- Header difficulty target validation.
- ASERT-style difficulty adjustment specification and implementation.
- Cumulative-work fork choice.
- Coinbase/resource issuance rules.
- Standalone node, miner, wallet, and CLI binaries.

### Exit gates

- A clean machine can create genesis, mine, transfer, restart, and resync.
- Invalid difficulty, timestamp, issuance, or state roots are rejected.
- Fork-choice simulations cover timestamp manipulation and variable hash rate.

## Milestone 4: peer-to-peer devnet

### Deliverables

- go-libp2p QUIC-v1 transport with authenticated peer identity. QUIC uses its
  native TLS 1.3 security; Noise is reserved for non-QUIC libp2p transports.
- Peer discovery, peer scoring, and connection limits.
- Transaction, block, header, and state synchronization protocols.
- Bounded mempool with deterministic admission rules.
- Snapshot sync with root verification.
- Four-to-seven-node local devnet harness.

### Exit gates

- Nodes converge after partitions, duplication, delay, and message reordering.
- Invalid peers cannot cause unbounded memory, CPU, disk, or goroutine growth.
- A new node syncs without trusting a snapshot provider.

## Milestone 5: WorkGraph and native share accounting

### Deliverables

- Weak Work Share format and difficulty.
- Recent-share DAG validation.
- Anchor commitment to accepted shares.
- Reward maturity and proportional payout calculation.
- Orphan, withholding, and selfish-mining simulator.
- Inclusion commitments carried by work shares.
- Bounded explicit multi-peer relay with independent backpressure and verified
  anchor synchronization.
- Count-or-time share flushing with a deterministic small-miner reward corpus.
- Admission-deduplicated multi-hop forwarding across the explicit peer graph.
- Reputation/latency/ASN-ranked peerbook selection with an inventory-free,
  exact-context WorkGraph capability probe.
- Same-parent timestamp generations with retire/drain semantics, atomic DAG
  revalidation, concurrent-admission linearization, and gossip handoff.
- Activation-bound peer exchange with signed height/capability records,
  atomic refresh, persistent sequence renewal, and live WorkGraph confirmation.
- Epoch-keyed bootstrap rotation and periodic long-lived miner refresh with
  serialized crash-safe peerbook persistence.
- Adversarial bootstrap failover: a mixed exact/foreign-activation response is
  rejected atomically without preventing the next independent bootstrap.
- Canonical Work-ID ordering after coverage-ranked parent selection and a
  parameterized four-node rollover/churn/loss convergence soak.
- Versioned PoW/economic activation-review packet with a deterministic result
  digest, fine standard/trail-retry selfish-mining and private-fee grids, and
  precommitted external pass/fail gates.
- Integer-only stochastic PoW paths for both target rules with canonical
  observation digests and timestamp/hash-rate regression corpora.

### Exit gates

- No share can be paid more than once.
- Reward calculation is deterministic and bounded.
- Honest small miners receive approximately proportional rewards in simulation.
- Share bandwidth remains within the published node budget.
- Long rounds preserve valid same-parent work across timestamp generations.
- Formal analysis documents the remaining fairness assumptions.
- Independent reviewers can reproduce the frozen corpus without trusting a
  generated summary; internal reproduction is not labeled as an audit.

## Milestone 6: committee preconfirmations

### Deliverables

- Committee eligibility and selection from mature PoW shares.
- Pure deterministic BFT state machine.
- Ed25519 multi-signature certificates with signer bitmap.
- Microblocks and preconfirmation receipts.
- Locked earned rewards as equivocation collateral.
- Evidence inclusion and slashing of immature rewards.
- PoW fallback when the committee stalls.

### Exit gates

- Committee signatures never override PoW fork choice.
- Safety holds below the documented Byzantine threshold.
- Liveness returns after committee rotation.
- Conflicting signatures create independently verifiable evidence.
- The protocol clearly distinguishes preconfirmation from PoW confirmation.

## Milestone 7: application and solver layer

### Deliverables

- Deterministic Wasm execution through wazero.
- Minimal host API with no WASI, clock, network, filesystem, floats, or threads.
- Declared read/write sets and parallel execution of disjoint transactions.
- Intent score functions and permissionless solver bids.
- Batch auction and deterministic winner selection.
- Capability accounts, session keys, spending limits, and recovery policies.
- Go/TinyGo SDK and contract examples.

### Exit gates

- Execution results are identical across supported operating systems and CPUs.
- Parallel and sequential execution produce identical ordered state diffs.
- A malicious solver cannot violate a signed outcome constraint.
- A compromised session key cannot exceed its capability.

## Milestone 8: privacy, data availability, and proving

### Deliverables

- Encrypted envelope and commit/decrypt/solve batch phases.
- Well-formedness and fee-reservation proof for encrypted envelopes.
- Plaintext escape path if decryption stalls.
- Erasure-coded batch data and availability sampling.
- Archive assignments, challenges, and storage rewards.
- Versioned execution-proof interface.
- Initial gnark or external zkVM proving adapter.

### Exit gates

- Encryption failure cannot halt plaintext transactions.
- Unavailable data cannot become an accepted anchor state.
- A proof system can be replaced through an explicit protocol upgrade.
- Full execution remains a safe fallback until proof-only validation is audited.

## Milestone 9: adversarial public testnet

### Deliverables

- Reproducible releases and signed binaries.
- Public explorer, faucet, wallet, and SDK documentation.
- Continuous network chaos testing.
- Independent implementation or independent consensus verifier.
- External audits for codec, GuardVM, state transition, PoW, and networking.
- Public bug bounty and incident response process.

### Exit gates

- At least six months without an unresolved consensus split.
- Successful recovery from intentionally induced partitions and database faults.
- No unaudited cryptographic construction in a consensus-critical path.
- Resource and bandwidth requirements match published limits.

## Milestone 10: mainnet readiness

Mainnet is a separate decision, not an automatic next step.

Required evidence:

- demonstrated user demand for outcome-safe execution;
- stable mining participation across independent operators;
- a credible security budget and issuance simulation;
- multiple wallet and node operators;
- completed external audits with resolved critical findings;
- documented upgrade and emergency response procedures;
- legal review for distribution, mining, and public interfaces.

## Explicitly deferred

The following do not belong in the first vertical slice:

- a public token sale;
- bridges;
- private balances;
- BLS aggregation;
- custom post-quantum cryptography;
- proof-only state validation;
- mobile mining;
- an unbounded general-purpose contract API;
- on-chain token voting over protocol rules.
