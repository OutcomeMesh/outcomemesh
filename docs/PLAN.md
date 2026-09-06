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
- A versioned multi-attestor archive anchor bound to the exact selected
  WorkChain ancestry, followed separately by a content-addressed restorable
  export, expiring independently keyed replica-custody receipts, and an atomic
  canonical retained-floor transition. Successive generations must be
  composable from the exact retained predecessor archive plus the executable
  suffix, without restoring pruned chain payloads. Published chunk boundaries
  and IDs must remain stable across those generations so a content-addressed
  replica transfers only missing suffix objects through bounded, canonical,
  manifest-bound requests and batches over identity-pinned, allowlisted,
  independently rate-limited transport sessions, then fully replays the
  materialized archive before publication. Fresh retention must be renewable
  only through a signed, freshness-bounded random-sample challenge whose
  deterministic manifest sample, returned-byte proof, predecessor receipt, and
  requested term are linked into a versioned receipt over a separate pinned,
  allowlisted, rate-limited transport scope. Repeated custody cycles must derive
  their state from an immutable policy-bound evidence journal, commit each
  response before delivery, recover interrupted publication, and serialize
  append/replay/segment rotation across processes. Timer-driven invocations must
  retry the exact unfinished challenge and preserve completed evidence during
  segmentation. Local disk growth must account for bodies, slots, temporary
  links, orphan evidence, and rotation directories before publication, preserve
  replay and committed retries after a limit reduction, and bound replay's path
  inventory. Evidence-retention policy and long-outage reconciliation remain
  separate gates. An anchor alone must never authorize deletion or override
  hard-work fork choice; canonical pruning is
  explicit local finalization and remains disabled by default.

  Custody storage follow-through:

  - [x] Journal byte/path admission limits, crash-completion reserve, usage
    reporting, and reduced-limit recovery tests.
  - [x] Define non-deleting evidence retention and cold-backup/independent-pin
    requirements, including the separate auditor artifact directory. Add paired
    canonical checkpoints, exact-copy verification without repair, whole-cycle
    auditor locking, and a pending-record restore drill. No automatic deletion.
  - [x] Managed local backup publication under the source locks: independent
    file copies, fsync and full replay before the final checkpoint marker,
    no-replace destinations, exact completed retries, preserved incomplete
    attempts, process-kill tests, and a pending-cycle restore drill.
  - [x] Local tooling for independently stored backup pins: bounded append-only
    pin history, explicit compare-and-append, exact committed retries, full
    verification of both bundles, and preservation of previously pinned chain,
    orphan bodies, pending files, and auditor artifacts. Add latest-pin CLI
    verification, concurrent-update and process-kill tests. No deletion or
    automatic fallback to an older backup.
  - [ ] Deploy and maintain the independent pin failure/access-control domain,
    cross-host cutover review, scheduled backup/pin operations, and deployment-
    scale restore drills. Local bundle and pin tooling do not establish physical
    independence, external freshness, or safe participant cutover.
  - [ ] Explicit long-outage reconciliation/rebaseline without silently replacing
    an expired challenge or discarding the previous evidence chain.
    - [x] Read-only comparison of independently pinned auditor/replica backups:
      exact common prefix, pending intent/response matching, retained-evidence
      blockers, and historical validity separated from proof/receipt freshness.
    - [x] Prepare, explicitly select by ID, export, and verify a bounded
      historical-response handoff package. Require the exact pinned common
      prefix, one replica-committed next entry, and matching auditor intent.
      Preserve source trees and incomplete attempts; test concurrent exports,
      tampering, and process kills before/after publication. This is offline
      packaging, not journal import or participant fencing.
    - [ ] Reviewed application of historical evidence and explicit linked
      rebaseline, including participant fencing and restart/crash recovery.
      Neither a comparison report nor a handoff package authorizes a new
      challenge or resumed authority.
  - [ ] Filesystem-full, inode-exhaustion, power-loss, and long-running retention
    campaigns before deployment claims.
  - [x] Isolate the 2026-09-06 tie-pair/campaign early-close race with a
    failing-before-fix process regression, add bounded EOF-based host/slot
    retirement, and distinguish nested transport timeouts from signed-slot
    expiry without changing pending-delivery safety rules.
  - [x] Close the between-slot observer readiness gap found by the 2026-09-06
    process gate: keep one authenticated handler installed, bound readiness
    waiting, and retire the old binding before stream close. A delayed second-
    slot regression fails before the fix and completes without reconnect after
    it; request budgets, signed slot times, and role ordering are unchanged.
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
  digest, fine standard/bounded-trail selfish-mining and private-fee grids, and
  precommitted external pass/fail gates. A global-ID selective-publication
  counterexample rejects deterministic v1 equal-work displacement; version 1
  persists the local arrival incumbent and switches only for strictly more
  cumulative hard work.
- Integer-only stochastic PoW paths for both target rules with canonical
  observation digests and timestamp/hash-rate regression corpora.
- Versioned public-testnet calibration evidence with integer-only one-sided 99%
  upper bounds, family-wise mining-cluster selection correction, a 30-day
  window gate, signed gapless hourly manifests, trusted deployment/policy
  bindings, published rollback checkpoints, a crash-safe first-admission hard-
  anchor collector, canonical tie plans precommitting miner and first-delivery
  roles, one signed raw receipt per planned slot with conservative failure
  accounting, a fail-closed dual-manifest evidence bundle, a crash-safe post-
  commit receipt writer, an isolated-pool two-miner producer with a one-slot
  persistent-router CLI harness plus wait/crash/restart process coverage, and a
  transport-neutral pair artifact with observer-side deterministic mining
  replay, a canonical digest, and version-2 plans sharing one campaign ID across
  up to 64 observer keys. A separately rate-limited authenticated QUIC pair
  protocol now pins both transport identities and published IDs, returns a
  durable signed-receipt acknowledgement, confirms its delivery, and recovers
  lost acknowledgements without duplicate admission. The ER-5 handoff now
  requires every version-2 observer chain, counts a campaign slot only once,
  and downgrades any valid block/selection disagreement to conservative
  `NoPair` without majority voting. The report commits the plan version, so the
  legacy single-view path cannot certify a version-2 plan. Coordinator-signed
  per-slot pair checkpoints now give the external publication channel a compact
  immutable binding, and a checksum-protected crash-safe campaign journal
  persists pair, publication, every observer acknowledgement, and advance
  boundaries. A resumable timed coordinator driver now writes immutable
  artifacts, waits for the separate publication gate, contacts all missing
  observers concurrently, and advances its local chain only after every ack.
  A long-lived observer receiver now validates numbered externally published
  checkpoints for the whole plan, records coordinator confirmation separately
  from signed receipt persistence, recovers the ACK/confirmation crash window,
  advances after completely empty `NoPair` slots, and stops on any partial pair.
  Coordinator publication waits are bounded by the signed slot; before any
  delivery it waits through the common receipt grace and journals the exact
  skipped sequence, while every state after publication is permanently
  non-skippable. A real coordinator/observer process regression proves an
  expired zero-delivery slot followed by a completed pair retains one parent
  and convergent tips. A second injected process crash after only the first
  sibling commit proves partial state survives and permanently stops the
  campaign; pre-commit and ambiguous post-commit write failures for skip and
  confirmation journals are idempotently recoverable.
  A read-only operator audit now reconciles coordinator state, immutable
  artifacts/publications, canonical observer receipt chains, confirmation
  markers, and cross-observer selected tips. It distinguishes healthy,
  retryable ACK/closure lag, and permanently blocked divergence without
  creating, advancing, or migrating any journal.
  A two-observer, two-slot version-2 process campaign now restarts one observer
  between slots at its stable pinned endpoint. A stale reused QUIC session is
  explicitly disconnected and retried once with a fresh authenticated
  handshake; both independent receipt chains, role order, selected tips, and a
  read-only healthy audit converge afterward.
  A separate exact-boundary process run blocks one observer before request
  decoding, waits for the other ACK to enter the fsynced journal, and kills the
  coordinator. Restart exposes `acknowledged=1`, delivers only to the missing
  observer, delays local advance until that ACK, and ends in a healthy audit.
  The pair stream is now version 2 and ends with an observer acknowledgement
  emitted only after its confirmation marker and directory fsync. Real
  coordinator/observer processes exercise pre-commit and ambiguous post-commit
  filesystem failures on both journals; no case advances the coordinator tip.
  An offline recovery command accepts only the audit's exact
  `unrecorded_observer_ack` proof, journals that tail without admitting blocks,
  and lets the ordinary coordinator resume from `AwaitingAdvance`.

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
