# Implementation status

Updated: 2026-10-27

This file records evidence against `PLAN.md`. A milestone remains open until all
of its exit gates pass; implementing most deliverables does not close it.

Full planned production readiness is approximately **44/100**, using the weighted
[readiness baseline](PRODUCTION_READINESS.md). This is an engineering estimate,
not an audit, task-count percentage or launch authorization. M5 and M6–10 remain
gated; local tests do not satisfy the public-testnet stability period.

## Milestone 0: specification foundation — complete

- Architecture, protocol, security model, dependency boundary, and gated plan
  are written.
- Consensus state transition has no database, network, clock, random, JSON, or
  goroutine dependency.

## Milestone 1: deterministic kernel — complete

- Fixed primitives, canonical codec, Resource/Outcome transactions, Ed25519,
  GuardVM, reference state, atomic execution, and deterministic roots exist.
- Golden vectors are in `VECTORS.md` and executable tests.
- Unit, negative, race, and fuzz-smoke tests pass.
- Fuzzing found and closed an allocation-before-EOF genesis decoder issue.

## Milestone 2: signed ledger and blocks — complete

Implemented:

- canonical genesis, headers, bodies, receipts, and ordered Merkle roots;
- sequential block replay and checked fee aggregation;
- one-batch Pebble block/state/tip commit with synchronous WAL durability;
- crash-clone recovery at every logical batch boundary, proving recovery to
  exactly the old or new state;
- stable block/genesis golden vectors;
- a 64-block transaction corpus with per-height Pebble/reference comparison and
  full deterministic replay.

## Milestone 3: single-node proof of work — complete

Implemented:

- SHA-256 target validation and cancelable nonce search;
- target-derived block work and persistent cumulative work;
- integer-only, genesis-anchored ASERT with published fractional vectors;
- 11-block median-time-past and a 120-second future-time admission bound;
- subsidy-plus-fee reward resources with a 100-height maturity lock and no
  state-root/hash cycle;
- persistent competing branches, deterministic cumulative-work selection,
  atomic canonical reorganization, and preserved losing-branch state;
- crash injection at every logical higher-work reorganization boundary;
- deterministic integer-only hash-rate and timestamp-manipulation simulations;
- standalone keygen, init, balance, transfer, mine, status, and replay verify;
- pure-Go `CGO_ENABLED=0` build.

## Milestone 4: peer-to-peer devnet — complete

Implemented:

- bounded mempool with full admission replay, input reservations,
  deterministic fee-rate eviction/selection, and reorg revalidation;
- strict length-prefixed Status/GetHeaders/Headers/GetBlocks/Block/Transaction/
  BatchDone/Result/GetPeers/Peers/GetSnapshot/SnapshotManifest/SnapshotChunk/
  SnapshotDone wire protocol with frame and per-message limits plus fuzz
  targets;
- exponential canonical locators and header-first bounded fork-aware batch
  sync; PoW/ASERT/MTP/network/ancestry/tip checks run before body requests, and
  full body replay remains mandatory;
- deadline session handshake, network/genesis rejection, block submission, and
  transaction relay;
- replaceable transports: a TLS 1.3/TCP fallback and an official go-libp2p
  v0.48.0 QUIC-v1 adapter with authenticated Ed25519 identities, independent
  OutcomeMesh peer-ID pinning, disabled relay, and bounded libp2p resource
  scopes;
- working `omd serve`/`omd sync`/`omd peers` and
  `serve-quic`/`sync-quic`/`peers-quic` commands with persistent
  seed-derived identity, optional peer-ID pinning, and a global
  concurrent-session limit; real two-Pebble-node sync and signed-discovery
  socket checks pass;
- bounded peer table, per-peer concurrent-session and inbound-byte windows,
  per-peer outbound-response windows, two-sided capped/decaying local score,
  typed behavior counters, bounded integer latency EWMA, retention pruning that
  preserves active dials, temporary abuse bans, clock-rollback-safe single-flight
  outbound dials, and capped exponential backoff; auto-sync
  score/backoff/counters/latency survive restart through an atomic bounded
  canonical file with offline decay, version-0 migration, and a fuzz target;
- signed short-lived Ed25519 peer advertisements, canonical IP:port or
  identity-matched QUIC multiaddresses, bounded anti-replay address book, and
  atomic discovery-batch admission; /16 IPv4-/32 IPv6-bucket caps and
  fsync/rename peerbook persistence preserve diversity and restart sequence;
- bounded chunked snapshot export/transport, exact ordering/count enforcement,
  and full state-root reconstruction; `omd snapshot-check` verifies but cannot
  import an untrusted snapshot;
- five-node partition/heal convergence over delayed fragmented streams,
  idempotent duplicate delivery, fail-closed reordered batches, and fixed-seed
  seven-node convergence under loss, churn, and asymmetric partitions;
- real `serve-quic`/`sync-quic` two-Pebble-node synchronization followed by
  full replay verification;
- bounded score-ranked `auto-sync-quic`; a persisted discovery record was used
  after process restart to sync a third Pebble node from height 0→3 and replay
  verify it without supplying the peer address again;
- optional bounded CIDR→ASN longest-prefix-match routing policy with a per-ASN
  attempt cap, plus an opt-in non-overlapping long-running scheduler that
  requires an ASN map, refreshes signed records on established sessions, and
  benefits from 30-minute server self-record renewal; bounded age-checked ASN
  file reload now runs before every watch pass and failed parsing preserves the
  last table but stops dialing. A real process test ran discovery, one-shot
  height 0→3 sync, multiple watch passes, SIGINT shutdown, and successful full
  replay verification;
- hard per-session request-class budgets, a 50,000-event peer-manager resource
  stress test, a state-machine fuzz target, exact QUIC stack validation, and a
  negative test proving invalid headers are rejected before block bodies are
  requested;
- consensus validation now independently rejects a header whose network ID
  differs from genesis, even if transport authentication and PoW are valid;
- Pebble schema 4 stores one materialized canonical state plus immutable
  create/delete deltas per accepted block; side branches reconstruct from
  the activation base or verified retained floor with a state-root check at
  every executable node, and a 256-resource regression
  test proves an empty competing block adds one reward delta rather than a full
  257-resource copy. Reorg/crash tests, the full race suite, and `CGO_ENABLED=0`
  tests pass with this schema;
- canonical extension/reorg now writes only the active resource diff instead of
  rewriting the full state. Immutable block/node/delta key/value bytes have an
  exact counter and persisted, init-configurable 64 GiB default budget;
  over-budget commits are rejected without mutation while the store remains
  readable. A real init→mine-two→status→replay smoke reported 1,702 logical
  bytes under a 64 MiB test policy and verified successfully;
- opt-in `make test-process` launches separate CLI processes and passed three
  mine→QUIC serve→sync→replay→SIGTERM/restart cycles over two Pebble nodes; the
  cycle count is configurable from 1 to 100 for longer local runs.

Exit-gate evidence:

- partition, duplication, delay, reordered-batch, churn, and asymmetric-network
  convergence tests pass;
- parser/session/peer/libp2p limits, behavioral bans, delta fork storage, and a
  fail-closed logical history budget bound attacker-controlled work;
- a new Pebble node synchronizes through independently validated headers and
  complete block execution, never importing the untrusted snapshot;
- full race, pure-Go, fuzz-smoke, real-process restart, and replay suites pass.

Public-network blockers retained beyond the M4 devnet gates:

- independently maintained production ASN-table source and provenance policy;
- independently history-anchored snapshot activation and persistent import;
- longer randomized/fault-injected process soaks, physical disk reserve/pruning
  for unpruned history, and broader resource-exhaustion fault injection.

## Milestone 5: WorkGraph — specification in progress

Implemented in an isolated, not-yet-activated consensus package:

- canonical weak-share format/strict decoder and domain-separated ID;
- unified WorkSeal semantics: the stored target is the hard anchor target and
  the same Work ID is checked against weak or anchor thresholds, so rewarded
  share hashing is reusable anchor security work;
- exact integer 1:512 derived target and weak-PoW validation; the initial 1:4096
  draft was rejected before activation because its expected honest share count
  exceeded the batch cap;
- bounded closed DAG with unique lexicographic Kahn order, root, count/byte/
  parent/miner limits, and detached validated batches; geometric-tail analysis
  raised the cap from 2,048 to 8,192 shares/3 MiB (16× the expected count)
  before block integration;
- winning hard-target seals commit DAG tips; delayed-payout validation requires
  the supplied batch to be exactly their transitive closure, preventing the
  successor from omitting ancestors or adding uncommitted shares;
- fixed pay-per-share subsidy accounting with address aggregation, checked
  arithmetic, maturity-preserving resources, and worst-case policy bounds; the
  earlier variable half-pool was rejected because it paid a winner to omit all
  foreign shares;
- executable share/ID/inclusion-root/batch-root/target vectors and decoder fuzz
  target;
- isolated canonical version-1 WorkGraph block/header codec and strict decoder,
  unified header/WorkSeal ID, header-first hard-PoW checks, MTP/future admission,
  and a fuzz target that passed more than one million generated inputs;
- parent-timestamp lagged ASERT fixes the next target before mining, preventing
  a current miner's timestamp from easing its own proof while allowing a
  bounded 120-second timestamp window for otherwise matching shares;
- stable WorkGraph negotiation excludes the local candidate timestamp; after
  60 seconds the round manager retires/drains old objective work and atomically
  advances the same pool's validation generation. Retained shares are
  revalidated, concurrent admissions retry across the generation boundary, and
  gossip reseeds retained IDs without duplicate per-peer copies;
- activation rejects a proof-of-work limit that would saturate the weak target,
  preserving the exact 512:1 rate assumed by pay-per-share issuance;
- an integer-only lagged-ASERT fluid model covers the baseline schedule, a 4x
  hash-rate step, full legal future bias, and slow-timestamp manipulation;
- explicit activation-height transition, two-block delayed-payout replay, and
  competing-branch tests prove that abandoned reward resources do not leak,
  reward IDs are fork-specific, and an earning cannot be applied twice;
- written omission, withholding, bandwidth, direct-child payment, and block
  activation rules in `WORKGRAPH.md`; payouts move to the following block so
  unknown concurrent shares/miner rewards cannot create a state/PoW root cycle;
- deterministic geometric simulations cover honest proportionality, an
  undersized-cap tail, 50% share withholding, 10% orphaning, bandwidth, and
  competing payload templates; the split-template case loses about half of
  otherwise valid share work and is documented as a centralization risk.
- a discrete-event topology model covers local DAG views, shortest-path delay,
  missing-parent queues, four-tip pressure, withholding, and deliberate
  foreign-tip omission; a delayed eight-node line retained about 94.7% of
  published shares while exposing 55/2,000 rounds above four winner tips.
- a multi-round public/private-fork model pays only the eventual canonical
  branch and enforces paid-shares <= discovered-shares: at 25% attacker hash
  withholding reduced reward share from 25.3954% to 21.6652%, while at 35%
  hash and 50% tie adoption it raised the share from 35.2656% to 40.9857%; this
  records, rather than assumes away, the remaining classic selfish-mining
  threshold;
- a deterministic 7 × 5 profitability grid now pairs honest publication and
  withholding over three common seeds per point. Requiring at least 5,000 ppm
  aggregate advantage and a win on every seed puts the first profitable tested
  point at 35% attacker hash for 0–25% tie adoption, 25% for 50–75%, and 15%
  at full adoption; all 35 reward shares and per-seed outcomes are golden
  regression values rather than one-run estimates;
- the same fork corpus proves deliberate omission does not increase the
  winner's absolute fixed-rate reward, although it lowers honest rewards and
  total issuance and therefore retains a relative-revenue/censorship motive.
- a production-ratio store-and-forward model now gives every directed link an
  independent byte rate, latency, and bounded FIFO: a provisioned six-node
  full mesh included all 271,199 shares, while a 32-byte/event eight-node line
  included 84,643/494,208 and respected its 732-byte link-queue cap; upgrading
  only its core links raised inclusion to 172,833 and exposed naive flooding's
  duplicate-message cost.
- an exact best-response payload market quantified direct-fee fragmentation:
  a 10% miner with a 3,000,000,000-unit private fee split from a
  5,000,000,000-unit-subsidy common template, reducing matching work to 82%
  and expected subsidy issuance to 91%; delaying fees to future hash-proportional
  winners kept the same fixture fully coordinated;
- the isolated v1 transition now implements that mitigation as a bounded,
  canonical, fork-local fee ring. Queue balance equals checked slot sum, the
  next root and matured award are inside the payload commitment, codecs have a
  golden vector and fuzz target, and an execution test carries a transaction
  fee through the exact delay into a future anchor's mature reward resource.
- the shared wire codec now has inactive inventory-first WorkGraph messages:
  1,024 sorted IDs per announcement and 256 requested/returned bodies per
  frame, with exact mining-context checks, strict decoding, and the existing
  wire fuzz surface.
- an isolated version-1 WorkGraph session now negotiates the exact mining
  context, capability, frame ceiling, inventory count, and worst-case-safe body
  batch. Its finite inventory/request/body/result state machine requests each
  unknown ID once, rejects unsolicited or repeated work, counts withheld and
  invalid bodies, enforces frame size before allocation, and sends every body
  through full pool PoW/DAG admission.
- the libp2p adapter now offers WorkGraph only as an explicitly installed
  `/outcomemesh/workgraph/1` handler, disabled by default and absent from the
  ordinary CLI. A real two-host QUIC test authenticates peer IDs, negotiates a
  512-byte receiver frame, relays a parent/child DAG in two batches, rejects a
  different payload context, and enforces a separate one-stream-per-peer scope.
  An exact worst-case relay is 630,258 application bytes; fixed-window defaults
  of 8 streams/peer/minute and 512 streams/node/minute bound averages to about
  82.1 KiB/s per peer and 5.13 MiB/s globally, excluding QUIC overhead and
  retransmission.
- an inactive concurrency-safe local WorkGraph pool now performs weak-PoW and
  context validation before bounded storage, resolves out-of-order parent DAGs,
  reserves one reward-miner slot for the future anchor, selects four tips
  without unbounded closure scans, and reconstructs the winner's exact batch;
  hard-target work is diverted to block processing and cannot enter both pools.
- an inactive unified mining coordinator now rebuilds WorkSeal parents after
  every admitted weak result, publishes detached shares, continues hard search
  under pool saturation, and sends a lucky seal directly through exact-closure
  block finalization; its deterministic integration fixture produced 228 weak
  shares followed by a valid replayable anchor with no double inclusion.
- an inactive fork-aware chain coordinator now reconstructs state, 11-sample
  MTP history, fee queue, lagged target, and predecessor earning independently
  for every branch. An activation fixture accepted two equal-height competitors,
  selected their tie lexicographically, reorganized to a higher-hard-work child,
  and proved that the abandoned branch's delayed payout was absent; weak shares
  never contributed fork weight.
- the coordinator now has an isolated schema-versioned Pebble store. Each
  accepted v1 block atomically persists its canonical bytes, immutable resource
  delta, timestamp history, fee queue, cumulative hard work, logical-history
  counter, and selected tip in one synchronous batch. A single activation-base
  checkpoint plus one recovery record per later node replaces the former
  full-state-per-branch layout. Restart walks the available parent deltas or
  verified replay checkpoints, recovering the canonical tip and competing side
  branches. Tests reject consensus-configuration and old-schema
  changes, corrupted deltas, and over-budget commits; injected pre-commit failure
  proves that neither memory nor disk observes a partial block. The process
  fault matrix now kills immediately before and after ordinary commit,
  checkpoint rotation, and stale-fork pruning batches. Every reopen must equal
  an independently built exact old/new fixture across tip, state root,
  cumulative work, history bytes, node IDs, and checkpoint IDs, then accept a
  fresh child. Ten repeated six-boundary runs passed. Strict metadata,
  checkpoint, and delta decoders are fuzz targets.
- explicit stale-fork maintenance now uses a 4,096-height default local window.
  It marks the canonical ancestry and every side branch reaching the window,
  then atomically deletes only unmarked complete subtrees together with an exact
  history-counter decrement. A boundary fixture preserves and extends a live
  side branch after restart, removes a two-block stale subtree, and proves an
  injected pre-sync failure changes neither memory nor disk. It does not prune
  canonical PoW history or introduce local finality.
- WorkChain schema 4 adds bounded replay-checkpoint rotation without duplicating
  state storage. Every retained non-floor node has exactly one delta or full-state
  checkpoint; after 2,048 selected-branch heights maintenance swaps the tip's
  delta for a checkpoint and keeps at most four. Eviction reconstructs the old
  node's exact parent delta in the same synchronous batch. Tests cover
  delta→checkpoint→delta rotation, exact byte accounting, pre-sync failure,
  corrupt checkpoint rejection, restart/extension, and pruning a checkpoint
  carried by a stale fork. Schemas 2 and 3 fail closed and require replay.
- a versioned, non-consensus WorkGraph archive checkpoint now binds the exact
  network/genesis/activation/tree base, selected `storage.Tip`, ordered ancestry
  commitment and node count, monotonic predecessor statement, and future
  archive-manifest ID. Checkpoints canonicalize 2–64 Ed25519 attestations and
  verify them against an explicit sorted trusted set with a quorum of at least
  two before atomic file/directory-fsync publication. Real WorkChain tests prove
  the same anchor survives database restart and extension of its branch but is
  rejected after a higher-work sibling reorganization. Golden codec, mutation,
  untrusted/duplicate/insufficient-quorum, strict-file, predecessor, fork, and
  decoder-fuzz tests pass.
- the checkpoint's manifest ID now resolves to a strict content-addressed
  archive: ordered descriptors commit up to 4,194,304 activation-to-anchor
  blocks across at most 65,536 chunks, while local block/chunk/byte limits may
  be lower. Chunks bind network/base/anchor/index/height and carry at most 256
  canonical blocks under 64 MiB. Export writes immutable regular files and
  rechecks selection before atomic directory publication. Verification checks
  exact directory membership, IDs, ordering, counts, and bytes, then executes
  every block from the external activation base. Persistent restore builds a
  fresh Pebble tree, closes/reopens it for full schema/state verification, and
  only then renames/fsyncs the non-replacing destination. A real fork fixture
  excludes the sibling, restores, reopens, and extends; corruption, symlink,
  extra-file, reorg, policy, and injected pre-publication failures are negative
  tests, and both new decoders are fuzzed. A subprocess killed immediately
  before rename recovers with no destination and can retry; one killed after
  rename but before parent fsync recovers a fully reopenable and extendable
  database.
- replica custody and the destructive local transition are now separate from
  archive attestation. A strict receipt binds one trusted replica key and
  location commitment to the exact statement/manifest/anchor plus replay and
  expiry times. A canonical bundle requires 2–64 sorted receipts under a local
  quorum, rejects duplicate identities/locations/directories, enforces bounded
  age and remaining retention, and is atomically fsynced. Authorization fully
  replays every replica again immediately before pruning. With an explicitly
  non-zero `CanonicalRetention` (zero by default), schema 4 then uses one
  synchronous batch to replace the strict pre-anchor node/block/recovery prefix
  with canonical headers, convert the anchor to a full-state retained floor,
  store the exact statement/manifest/bundle IDs, and update logical bytes.
  Reopen derives parent links, ASERT targets, timestamp history, cumulative
  work, ancestry commitment, and floor state before replaying descendants.
  Tests cover stale/missing/duplicate replicas, corrupt headers, unresolved
  side branches, repeat floor advancement, injected batch failure, restart and
  extension, race, decoder fuzzing, and real process kills on both sides of the
  batch. This is trusted point-in-time custody and an operator-selected local
  finalization horizon, not network availability or consensus finality.
  The destructive archive API now takes a context and uses the real clock,
  rather than accepting a fixed observation timestamp. It checks time again
  after replay and evidence publication, then inside the prepared WorkChain
  batch after lock acquisition and all deletion/accounting preparation.
  Expiry, insufficient remaining retention, cancellation, and wall-clock
  rollback (including subsecond rollback) discard the batch. The final sample
  is the persisted `VerifiedAt`, not a disk-completion timestamp. Availability
  publication is now no-replace: exact retries fsync the existing bytes, while
  another valid bundle or malformed/symlink destination is rejected. Tests
  cover each time boundary, inclusive age/remaining-term limits, cancellation,
  chain-lock waiting, failed-batch restart, concurrent publication, and process
  kills before/at authorization and after commit.
  End-to-end process kills also cover published evidence before chain mutation,
  the final in-batch sample, and completed deletion; an expired restarted
  attempt cannot use the leftover file as authorization. Independently deployed
  current authority and active cutover remain unimplemented; see
  `CUSTODY_AUTHORITY.md`.
- a pruned WorkChain can now produce its next independently restorable archive
  without restoring the prior database. `ComposeDirectory` requires the exact
  predecessor checkpoint and manifest IDs stored in the persistent floor,
  fully replays that archive, then streams its verified prefix and only the
  executable selected suffix through the same bounded v0 archive publisher.
  Before rename it rechecks the entire floor record, target tip, and ancestry
  commitment. An end-to-end test performs archive→custody→prune→compose→attest→
  verify→restore→custody→second-prune, while negative cases cover an empty
  suffix, corrupt source, nested destination, and a winning reorganization at
  the publication boundary.
- archive format v1 now gives composition stable cross-generation content IDs.
  A chunk no longer embeds the terminal archive anchor; it still binds version,
  network, immutable tree base, position, height, and canonical blocks. The
  manifest binds the ordered descriptors to the final tip and ancestry.
  Composition freezes all predecessor chunk boundaries and rejects a smaller
  chunk policy, with the end-to-end test requiring every prior descriptor to be
  exactly unchanged. Thus only suffix IDs are new to a content-addressed object
  set while every output directory remains a complete ordinary archive. Strict
  decoding, replay, restore, and fuzz seeds cover both legacy anchor-bound v0
  and v1.
- stable v1 IDs now have a bounded transport-neutral object exchange. A local
  append-only store accepts only canonical content-addressed chunks, rejects
  non-regular/extra/non-canonical files on reopen, and applies exact object and
  byte budgets. Archive import begins with full replay. Missing-object requests
  and batches bind the exact manifest, contain at most 64 strictly sorted unique
  IDs/objects, and cap combined chunk bytes at 64 MiB. Every received object is
  checked against its descriptor before atomic no-replace insertion. Complete
  materialization occurs outside the store, is fully replayed, and is renamed
  only after verification. The end-to-end fixture seeds both peers with the
  predecessor generation, proves that only one new suffix object crosses the
  exchange, restores the resulting standalone archive, and covers corruption,
  budget, nested-output, naming, codec, and concurrent-put failures. The codecs
  are registered in the common fuzz-smoke gate. No network peer is trusted and
  partial object sets never become restorable archives.
- archive-object exchange now runs over a distinct, opt-in
  `/outcomemesh/workarchive/1` libp2p QUIC-v1 protocol. The dialer must pin the
  exact authenticated server identity; the server requires 1–64 sorted unique
  client IDs and rejects an outsider before charging the archive rate window.
  Its resource scope defaults to one concurrent stream per peer and four
  host-wide (hard maxima two and 16), while an independent fixed window admits
  one stream per peer and 16 globally per minute by default (hard maxima four
  and 128). Each stream has per-frame deadlines and ends after at most four
  batches, 256 objects, and 256 MiB of chunk payload. Repeated IDs, truncated or
  oversize frames, wrong manifests, and incomplete/substituted responses fail
  closed. A 257-object test stops after exactly 256 and resumes with only the
  final object. The real QUIC fixture rejects an unauthorized identity and a
  wrong server pin, transfers exactly the one composed suffix object, then
  materializes and fully replays the complete archive. Concurrent, global-rate,
  corrupt-tail, canonical-allowlist, race, and frame-fuzz cases are separate
  gates. One-shot `work-archive-object-serve-quic` and
  `work-archive-object-fetch-quic` commands now expose only this isolated
  protocol. Both reconstruct the activation base from WorkGraph-enabled node
  data and verify the target checkpoint under an explicit trusted-attestor
  quorum. The source fully replays before importing into its persistent store;
  the pinned receiver preserves incomplete work in an append-only store and
  atomically publishes only after complete materialization and a second replay.
  A real process test restarts the source on the same key/store, materializes a
  second independent output, and proves a completed client recovers without
  network access. Fourth-batch completion waits for bounded client EOF so a
  one-shot source cannot truncate its final QUIC response. The commands remain
  outside ordinary v0 CLI and consensus paths.
- live replica freshness and receipt renewal now have strict canonical evidence.
  A trusted auditor creates a short-lived signed challenge from a 32-byte
  `crypto/rand` nonce and a requested future retention deadline. Up to eight
  chunk IDs are selected deterministically from the manifest, predecessor
  receipt, and nonce under the existing 64-MiB batch ceiling, so the replica
  cannot choose its sample. The replica returns the exact validated chunks and
  a signed proof over their canonical digest. Receipt v1 links the predecessor
  receipt and proof IDs, response time, and challenge-bound deadline; legacy v0
  receipt bytes and IDs remain unchanged. Freshness, replay, wrong-key,
  biased-ID, corrupt-byte, alternate-term, codec mutation, and v0→v1→v1 chain
  cases fail closed and both new decoders have fuzz gates and golden IDs.
- custody traffic runs over its own opt-in
  `/outcomemesh/workarchive-custody/1` libp2p QUIC-v1 scope. The auditor pins the
  replica transport ID; the replica requires a sorted auditor allowlist before
  charging an independent rate window. Defaults admit one concurrent custody
  stream per peer, two host-wide, one per peer and eight globally per minute;
  hard maxima are one, eight, two, and 64. One finite stream carries challenge,
  sampled batch, proof, and renewed receipt in strict order with per-frame
  deadlines and pre-allocation bounds. Real QUIC tests cover the complete
  renewal, outsider rejection, wrong server pin, independent rate accounting,
  reordered/truncated frames, and matching evidence IDs on both endpoints. The
  replica caches a signed response before writing it, returns the identical
  proof/receipt on an identical retry, and rejects a second challenge against
  the same predecessor instead of creating an in-process sibling renewal. The
  response cache now has a canonical durable form: a mode-0600 file commits the
  challenge, exact batch, proof, and renewal through fsync plus atomic
  no-replace link before the first network byte. Startup verifies and restores
  it, so idempotency and sibling rejection survive process restart. Crash tests
  cover both sides of publication, concurrent writers converge on one answer,
  corrupt records fail closed, and the decoder is in the fuzz-smoke gate.
  One-shot `omd` replica/auditor commands persist the challenge and response,
  enforce pinned/allowlisted QUIC identities plus four distinct
  transport/evidence keys, and recover the renewed receipt locally. A real
  two-process test restarts the replica and requires byte-identical evidence.
  Repeated cycles now use a policy-bound append-only journal with canonical
  header/entry/slot encodings, immutable sequence slots, content-addressed bodies,
  and complete receipt-chain replay. A permanent kernel lock serializes disk
  operations across processes; body and slot publication precede network output.
  Non-deleting segment rotation survives a crash before active-directory
  recreation. The CLI accepts journal/artifact paths, a renewal duration, an
  interval gate, and a rotation threshold for external timer invocations. It
  restores missing head artifacts locally and can redeliver a still-fresh
  journaled response after replica restart. Regression coverage includes two
  restarted cycles, lost-response redelivery, local artifact recovery, not-due
  exit without a server, same-challenge/sibling contention, append versus
  rotation, corrupt evidence, changed policy, and process kills after body,
  slot, and segment publication. See `CUSTODY.md` for the operator workflow and
  filesystem assumptions. Local journal limits now default to 4 GiB logical
  bytes and 262,144 paths. Admission counts active/sealed/orphan bodies, slots,
  directories, and temporary links under the process lock, reserving body and
  slot publication together. Rotation needs an additional directory allowance.
  Streaming inventory enforces a hard 1,048,576-path ceiling before replay builds
  its indexes. Reduced limits preserve replay, exact committed-response
  redelivery, and local artifact recovery. CLI flags expose the limits and a
  startup usage report. Boundary tests cover no-write refusals, abandoned-link
  completion, rotation repair, and overflow; real process tests exercise tight
  budgets, offline recovery after increasing a cap, and over-budget redelivery.
  This is logical accounting, not physical free-space reservation.
  The evidence-retention rule is now explicit: keep the full journal and auditor
  tree, including uncommitted and partial files; expiry does not authorize
  deletion. A permanent artifact lock serializes entire auditor invocations.
  New canonical custody checkpoints take artifact then journal locks, replay the
  chain, and hash both complete inventories with bounded streaming file reads.
  CLI capture publishes a no-replace checkpoint; verification requires an
  independently retained ID and never initializes or repairs the copy. Tests
  distinguish an older valid prefix and a same-head copy missing a later signed
  request, preserve orphans/empty/partial files, reject wrong trust and pins, and
  check lock ordering, path/byte/depth ceilings, case-insensitive directory
  aliases, and canonical encoding. A process
  restore drill verifies a new-directory cold copy and finishes its pending
  record offline with unchanged challenge/response bytes. Managed local backup
  creation now holds those source locks through copying and verification, writes
  independent inodes, and fsyncs all data/directories before publishing the final
  checkpoint. Existing empty, incomplete, conflicting, and aliased targets are
  never overwritten; identical completed retries reverify against the current
  source. The bundle verifier requires an independent pin and no original source
  access. Failure tests cover cancellation, altered copies, layout bounds, and
  missing completion markers. Process kills bracket the journal copy and final
  commit, including lost-success-output recovery. The CLI restore drill now also
  restores from a managed bundle and checks that offline continuation leaves
  the retained backup unchanged. Local backup-pin maintenance now uses bounded,
  append-only canonical records and an explicit previous-pin expectation.
  Promotion verifies both retained bundles, proves the earlier head remains in
  the new chain, and preserves orphan body IDs, pending files, and all auditor
  paths/bytes. Same-head pending-request updates are supported without allowing
  a lost request to be promoted. CLI commands initialize/update the journal,
  inspect its head, and verify only its latest pinned backup. Tests cover exact
  lost-response retries, concurrent identical and competing updates, divergent
  chains, missing evidence, malformed journals, capacity, decoder golden/fuzz
  checks, process kills before/after publication, and a real signed pending
  request through the CLI. Optional external head-ID verification detects a
  rolled-back pin store; absent that receipt, the store itself is trusted.
  Independent storage/access-control deployment and pin freshness, scheduled
  backups, cross-host cutover, compaction review,
  ENOSPC/inode-fault campaigns, and mutating long-outage recovery remain pending.
  The read-only reconciliation stage now compares independently pinned auditor
  and replica backups under their existing bundle locks. It reports the exact
  common prefix and first divergence, inspects committed auditor artifacts and
  the next signed challenge/response, and never selects the longer conflicting
  chain. Historical records remain verifiable after an outage while proof-age
  and receipt-expiry fields are evaluated separately at the declared time.
  Unknown/future-cycle artifacts, temporary files, and orphan bodies require
  review and are not promoted to decisions. Unit tests cover temporal boundaries,
  conflicting challenges and responses, prefix/rotation cases, incomplete scope,
  wrong trust/IDs, and unchanged evidence. A CLI process test repeats an offline
  stale-response assessment and proves it neither appends a record nor replaces
  the request; a focused fuzz target exercises pending-intent classification.
  Report success is not recovery approval. A separate historical handoff now
  packages one replica-committed next entry with both exact checkpoint values.
  The CLI defaults to a read-only plan; export requires that reviewed ID and a
  disjoint no-replace directory. Verification replays both pinned source bundles
  and checks the full pending intent/response and prefix again. Source files,
  original timestamps/signatures, and pins remain unchanged. Unknown/temporary
  evidence, larger gaps, divergent histories, and missing historical artifacts
  block export. Completed retries are exact; incomplete attempts are preserved.
  Unit/decoder tests, concurrent exports, pre/post-commit process kills, and the
  outage CLI process fixture cover this boundary. This is offline packaging,
  not import, a fresh availability claim, or fencing. Explicit application now
  reconstructs a new historical-only auditor journal and artifact tree from
  those exact sources. Its v1 header binds the reviewed transfer before journal
  payload copying; live open, append, rotation, and journal-backed serving
  reject it. Checkpoint replay still works, and v0 canonical vectors remain
  unchanged. The final application ID binds the complete reconstructed inventory.
  Verification permits exactly the linked header, selected next body/slot, and
  canonical pending-cycle artifacts as differences from the original auditor;
  even a rehashed extra file or changed earlier artifact is rejected. Source
  copies and the initial receipt remain unchanged. Tests cover rotated prefixes,
  reduced-limit retries, concurrent creation, decoder boundaries, seven process-
  kill points, and live auditor/replica CLI refusal without modifying recovery
  evidence. Incomplete attempts remain quarantined and cannot resume in place.
  Linked rebaseline proposals now require full verification of that pinned
  reconstruction and a fresh consensus replay of the complete archive. The
  replica signs a separate, fixed-size proposal, not a usable receipt. It binds
  the application, previous receipt, new replica/location, and new auditor policy;
  old/new evidence keys cannot overlap. Review requires independent IDs and the
  intended assignment, replays the archive again, and checks the signed short
  review window before and after replay. The CLI defaults to verification;
  creation is explicit and never overwrites or refreshes an existing proposal.
  Tests cover full replay/corruption, wrong trust and re-signed wrong bindings,
  key reuse, cancellation, expiry during replay, canonical byte mutations, and
  an actual CLI create/verify/refusal workflow with expired historical receipts.
  Local retirement now guards the entire auditor cycle and replica response
  with the permanent journal lock, including replies already cached in memory.
  It drains those scopes, requires the exact pinned auditor/artifact and replica
  inventories, then publishes one permanent proposal-linked marker per journal.
  A crash between markers leaves a partial retirement, not a successful fence;
  exact retry can finish the original intent after proposal expiry only if the
  other participant has not changed. Live opens, stale handles, append, rotation
  and cached serving reject retirement. Historical replay and backup preserve
  the marker and verify the journal's exact pre-retirement inventory. Unit tests
  cover cache draining, competing requests, drift, rehashed markers and time
  boundaries; six process-kill points and a real already-started QUIC replica
  plus refused auditor/replica restarts cover the runtime path. No source backup,
  historical reconstruction, receipt signature or proposal is rewritten.
  Cross-host authority/acceptance enforcement and active cutover remain open:
  local markers do not stop legacy binaries, copied/rolled-back directories,
  unjournaled signing or independent remote acceptance. Neither a proposal nor
  a local retirement pair is a new live receipt or global fence.
  A bounded in-memory reference kernel now lives in `node/custodyauthority`.
  Its immutable assignment binds exact archive/receipt/policy context and a
  separate set of consumer control keys. Signed compare-and-append admissions
  create unique operation tickets; stop rejects further admissions, and retire
  requires the exact stop entry plus explicit closure of every pending ticket
  by its own consumer. Time, disconnection and replay never close a ticket.
  Completed operation IDs remain retained, and exhausted admission capacity
  does not block draining. Exact independent sequence/head pins reject valid
  but incomplete replay. Tests cover detached state, wrong keys/roles/bindings,
  replay/duplicates, capacity limits, concurrent compare-and-append, golden
  encodings, decoder fuzzing and a separate small transition model.
  The separate `node/custodyauthority/store` now supplies local durable history:
  a lifetime process lock serializes validation, immutable file publication,
  directory sync and state application. Bootstrap refuses existing/partial
  roots; open performs exact independently pinned replay without repairing
  missing data. Required I/O failures poison the handle. Lost-response recovery
  allows only the prior pin or its one-entry extension by the exact retained
  attempt; old retries report current state without another admission. Bounded
  crash temporaries are retained, never promoted or automatically discarded.
  Unit tests cover malformed/substituted paths, independent pins, same-head
  concurrency, cancellation and persistence errors. Forty-five real child-process
  kills cover every admission/drain transition and initialization, including
  cross-process lock exclusion and continuation to the original retirement.
  An optional local `Coordinator` now adds the retained intent/pin journal. It
  syncs an admissible exact signed attempt before touching authority history,
  verifies the local durable result, then syncs independent confirmation before
  returning it. Reopen obtains its expected head from that retained journal,
  exposes at most one pending attempt without submitting it, and requires exact
  explicit resume. Confirmed missing history is never silently reconstructed.
  Separate role markers, disjoint root/ancestor identity checks and lifetime
  journal-before-authority locks prevent cooperating writers from bypassing the
  ordering. Unit tests cover malformed results/pins, cancellation, aliases,
  concurrent requests and exhausted admission capacity. Another 129 child-process
  kills cover intent, authority and confirmation publication for every transition
  plus initialization; all recover to the original retirement without duplicate
  admission or automatic submission on open. Independent storage deployment,
  power-loss campaigns, current-authority transport and durable consumer effects
  remain open. Runtime acceptance paths are not connected yet; reference entries
  and durable history results are not live permissions or activation evidence.
  Consumer-effect groundwork (2026-09-07): WorkChain now has an optional
  `PruneCanonicalPrefixOnce` primitive. An exact assignment/ticket/request and
  original completed result commit in the same synchronous batch as deletion,
  floor state and logical-byte accounting. Lost-result recovery is read-only;
  exact retries do not invoke authorization or repeat deletion, even after
  later pruning. Conflicting ticket reuse fails. Results are retained within
  65,536-record and byte budgets, and the first effect atomically opts only that
  database into schema 5, refusing older readers. Recovery rejects malformed or
  inconsistent result/floor history; uncertain canonical commits block chain
  access until close/reopen. Tests cover 16 concurrent retries, timestamp gates,
  ticket substitution, later maintenance, codecs, invalid recovery and four
  additional process-kill boundaries, including an unsynced ambiguous attempt.
  The primitive is not a live grant, consumer intent journal, completion service
  or anti-rollback storage identity. Current-authority transport and all live
  audit/serve/prune adapters remain open; existing CLI behavior is unchanged.
  Local executor follow-up (2026-09-07): an optional `PruneExecutor` now retains
  the exact request, binds its ID into a current signed admission, records start
  before calling the concrete atomic WorkChain primitive, and retains the result
  only after that effect drains. The private coordinator guards its confirmed
  pending ticket through execution/result publication; uncertain authority,
  completed tickets and foreign bindings cannot start work. Exact completed
  retries return evidence only. Started recovery never executes missing work:
  it accepts only an existing exact chain result, otherwise the ticket remains
  pending and retirement is blocked. No completion is signed automatically.
  Tests cover concurrent execution, cancellation, malformed records, sync failure,
  stop/result races and 26 more process kills. New request codecs have a canonical
  fixture and fuzz target. This is one-assignment local groundwork, not a complete
  consumer protocol: independent stage/database pins, no-effect recovery, all-
  replica authority coverage, networking and live CLI integration remain open.
  Validation: repository-wide tests, race detection and vet passed, as did the
  complete process gate (200 authority-store/coordinator/executor kill cases).
  The new 26-case executor process suite also passed with race detection; the
  request decoder completed 100,000 fuzz inputs. Integration test binaries build
  for Linux and Windows; process execution was verified on macOS, not those hosts.
  Independent stage-pin follow-up (2026-09-07): the opt-in pinned constructor now
  initializes two bound roots and orders exact transition intent, executor record,
  then confirmation. The chain effect waits for an independently confirmed start;
  its result pin stays inside the coordinator guard. Pinned open rejects rollback
  of confirmed primary records, unexplained extensions and raw-mode downgrade.
  One exact unconfirmed transition requires explicit resume without chain execution
  or ticket completion; missing effects remain unresolved. Tests cover 63 staged
  publication failures, 71 additional process kills, cancellation, sync failures,
  mismatched roots, bounded leftovers and canonical transition fuzzing. This closes
  the local consumer-stage pin implementation gate, not shared-rollback protection,
  physical chain-storage recovery, no-effect disposition or live network integration.
  Validation: repository-wide tests/race/vet passed. The 71 new process-kill cases
  also passed under race detection, and the repeated complete process gate passed
  all 271 authority/executor kill cases. Transition fuzzing completed 100,000
  inputs; integration test binaries built for Linux and Windows, with execution
  verified on macOS only. The first process run's separate failure is retained below.
  Storage-incarnation follow-up (2026-09-07): a new opt-in WorkChain mode binds
  a fresh caller-selected ID to database initialization, requires the independent
  pin on reopen, and refuses missing/legacy identity or raw-mode downgrade.
  Version-1 prune requests retain that ID before admission, require independent
  stage pins and carry it into the atomic version-1 effect. Another incarnation
  is rejected before start and under the chain prune lock; bound stores refuse
  unticketed pruning. Schema 6/7 separates these databases from unchanged raw
  schema 4/5; version-0 request/effect bytes and IDs remain unchanged. Both new
  formats have canonical fixtures and fuzz coverage. Recovery from an old copy
  with the same ID remains unresolved when its effect is missing: no re-execution,
  no fabricated no-effect disposition and no automatic completion. Copy retention
  is explicitly tested as a limitation, not advertised as physical/copy fencing.
  All 77 new process boundaries passed with race detection: two initialization,
  four atomic effect and 71 executor/pin publication cases. Each updated codec
  completed 100,000 fuzz inputs. Repository-wide tests, race detection and vet
  passed; the complete process gate now includes 342 authority/executor crash
  cases and the six new WorkChain cases. WorkChain and executor integration
  binaries built for Linux and Windows; execution was verified on macOS only.
  This is local library groundwork, not physical storage identity, independent
  database-position recovery or live CLI integration.
  Database-position follow-up (2026-09-07): an additional opt-in WorkChain mode
  now retains an exact independent intent and confirmation for every logical
  batch. Fresh position tokens share the actual block/prune/checkpoint batch;
  schema 8/9 and a random pair binding prevent silent raw-mode downgrade or
  mismatched-root recovery. Initialization requires two new disjoint roots,
  and the independent lock precedes Pebble ownership. Final authorization runs
  after intent I/O. A recovered one-intent gap gates ordinary operations; explicit
  resume only flushes/confirms an already present batch. The prior position stays
  unresolved, even after authorization denial or rollback of an actually committed
  prune. Database-only rollback and unexplained extensions are rejected. Current
  copies and independently running copied pairs remain an explicit limitation.
  This closes the local independent database-position implementation gate, not
  physical/copy fencing, shared-rollback detection, safe no-effect disposition,
  production-scalable retention, power-loss validation or live runtime integration.
  Targeted validation passed: 56 injected mutation faults, 14 initialization
  faults, eight resume errors, all four mutation paths, bounds/corruption/copy
  tests, executor recovery, and 79 process-death boundaries. The 79 process cases
  and resume-error regressions also passed with race detection. Canonical position
  records completed 100,000 fuzz inputs; repository-wide tests, race detection
  and vet passed. WorkChain and executor integration binaries built for Linux and
  Windows; execution was verified on macOS only.
  The complete process gate passed, including 100 WorkChain crash cases and all
  342 authority/executor cases, alongside the existing QUIC/archive restart gates.
  Pre-start cancellation follow-up (2026-09-07): an independently pinned executor
  can now choose an irreversible cancellation branch while Admitted, before any
  retained start intent. It holds the current pending-ticket guard through the
  independent intent, primary record and confirmation. No WorkChain handle or
  database absence is consulted. A retained or uncertain start cannot be cancelled;
  explicit resume only finishes the exact branch already chosen. The new 138-byte
  envelope binds assignment, request, ticket and executor pair; old execution
  formats and hashes are unchanged. Older readers reject the new terminal filename.
  The authority ticket stays pending until a separate consumer-signed completion
  receives an authority decision. Cancellation bytes alone prove neither durable
  publication nor global non-execution; copied roots, shared rollback, unfenced
  consumers, unknown Started outcomes and live completion transport remain open.
  Validation passed: execution/cancellation races, held guards, stopping drain,
  authority and start-intent refusal, rollback/mixed-history rejection, 21 injected
  publication faults, 14 resume errors, directory-sync and caller-cancellation
  cases. All 42 new process-kill cases passed with race detection. The cancellation
  codec and updated transition state machine each completed 100,000 fuzz inputs.
  Repository-wide tests, race detection and vet passed, as did the complete process
  gate with 100 WorkChain and 384 authority/executor crash cases plus the existing
  QUIC/archive suites. Executor integration binaries built for Linux and Windows;
  process execution was verified on macOS only.
  Outcome-bound completion follow-up (2026-09-07): `PruneExecutor.Complete` now
  submits a separately supplied consumer-signed, authority-co-signed completion
  only after the executor's exact effect or pre-start cancellation is independently
  confirmed. Assignment, consumer, ticket and outcome IDs must match retained
  evidence. Executor/coordinator guards cover authority intent, decision and
  independent confirmation. Raw or unresolved Started work cannot use this path;
  a pending executor transition must be explicitly resolved first. No database
  access, effect execution, key custody, new envelope or executor stage is added.
  Exact completion retry resumes its retained entry or returns historical evidence,
  including after retirement. A competing retained Stop blocks completion, and an
  outdated signed head requires a separately re-signed command, never automatic
  refresh. The lower-level coordinator remains a trusted signed-command store;
  this opt-in local adapter does not install remote authority or any live
  audit/serve/prune acceptance path, fence copies or resolve unknown Started work.
  Targeted validation passed: both terminal branches and all three pinned storage
  modes, 42 publication-fault cases, wrong bindings/signatures, raw/unconfirmed
  refusal, concurrent retries, held guards, stopping conflicts, caller cancellation,
  missing terminal records/pins, disjoint-root checks and directory-sync errors.
  All 70 new process-kill cases passed with race
  detection, including interrupted completion retries. Executor integration
  binaries built for Linux and Windows; process execution was verified on macOS
  only. Repository-wide tests, race detection and vet passed. The complete process
  gate passed with 454 authority/executor crash cases and 100 WorkChain cases,
  alongside the existing QUIC/archive suites. The independent authority drain
  model completed another 100,000 fuzz inputs; the final completion unit suite,
  including missing-evidence/root checks, also passed under race detection.
  Completion-only QUIC follow-up (2026-09-07): an opt-in protocol now carries one
  externally co-signed Complete to the original colocated pinned executor and
  coordinator. Both transport identities are independently selected; neither an
  advertised endpoint nor the request supplies its own trust pin. The concrete
  server waits for a fixed 424-byte request and EOF before calling the terminal
  outcome adapter. Its 74-byte reply follows independent authority confirmation
  and binds the exact entry to a fresh random exchange nonce. Lost/partial replies,
  cancellation and disconnects never imply non-commit or allow effect replay.
  Default-disabled handlers have separate bounded rate, stream and memory scopes.
  There is no remote admission/execution, signing, stale-head refresh, automatic
  retry/failover, durable client outbox or installed live acceptance path. Physical
  and copied-owner fencing, unknown Started outcomes and all-replica authority
  remain open. The request/reply codecs have fixed canonical vectors and completed
  100,000 fuzz inputs. Real loopback QUIC tests cover peer pins, disabled protocol,
  budgets, EOF/trailing data, wrong commands/outcomes, caller cancellation and
  lost-response retry. Twelve separate-server-process kill boundaries passed with
  race detection; explicit restart preserves both network identity pins and the
  exact signed command. Linux/Windows integration binaries built; execution was
  verified on macOS only.
  The first process-test harness reached its 3-minute suite timeout while waiting
  for a client reply after server death. The explicit restart drill now closes
  the old client host and recreates it under the same identity before retry,
  instead of accumulating dead-connection waits. All 12 cases passed with race
  detection in 35.696 seconds. This is not validation of automatic reconnect or
  failover; neither is implemented by the completion client.
  The first whole-repository normal test run also failed the existing
  `TestJournalCustodySessionCommitsBeforeSendAndRecoversExpiredChallenge` with
  `io: read/write on closed pipe`; the race-enabled run passed, as did 20 isolated
  repetitions. A deterministic stream gate then reproduced the failure in both
  fresh and recovered journal responses: the auditor fully validates/closes
  before the replica returns from its final successful Write, and the replica's
  subsequent SetDeadline fails on the closed pipe before it can observe EOF.
  Custody completion now keeps the deadline already installed for that last frame
  and reads actual EOF without resetting or extending it. Both deterministic
  regressions and the original case passed 20 repetitions with race detection;
  separate negative tests preserve deadline, trailing-data and local-close
  rejection. No generic closed-pipe error becomes a completion acknowledgement.
  A repeated full process run then failed the existing coordinator journal
  `after_rename` case: recovery found AwaitingPublication, not Delivering. The
  fixture observed the StagePair file after rename but could remove directory
  read permission before that same writer opened the directory for fsync. A
  deterministic post-rename checkpoint reproduced this earlier failure boundary
  in 20 race-enabled repetitions: the file is readable, StagePair still fails,
  and publication/delivery are never called. The process fixture now kills and
  drains that writer, then requires a recovered AwaitingPublication startup
  before changing permissions. The injected error therefore belongs to the next
  ConfirmPublication write. Expected phases, zero ACKs, unchanged local tips and
  recovery checks remain strict; no production error is ignored or retried.
  Both coordinator permission cases then passed ten process repetitions each
  with race detection (183.729 seconds) alongside the full process gate.
  Final validation: whole-repository `go test ./... -count=1` and
  `go test -race ./... -count=1` passed after the custody deadline fix. Following
  the additional campaign checkpoint/fixture change, both affected packages
  passed again normally and with race detection, and `go vet ./...` passed.
  The final `make test-process` passed all four suites: command processes
  (62.678 seconds), 100 WorkChain crash cases (27.109 seconds), archive crash
  recovery (17.462 seconds), and 466 authority/executor crash cases, including
  the 12 new QUIC cases (205.584 seconds). These are local logical crash and
  permission-fault checks, not physical power-loss or production readiness proof.
  Completion client outbox follow-up (2026-09-07): one immutable 456-byte intent
  retains the exact co-signed command and both independent transport pins before
  sending. Create/Open require an externally retained intent ID; open only
  validates/re-syncs local evidence and never contacts the server. Explicit
  Deliver uses the concrete pinned QUIC client, with no signing, head refresh,
  automatic retry/failover or effect callback. A verified response is retained in
  a 148-byte local checksummed receipt before success. Local write failures poison
  the owner; lost responses remain unresolved and exact network retries reuse the
  server decision. A durable local receipt returns offline historical delivery,
  not a live-authority assertion. Seven publication-fault cases, initial bootstrap
  failures, malformed/replaced files, peer/assignment binding, concurrent callers,
  cancellation and lost/partial real-QUIC replies are covered. Forty-one separate
  client-process crash cases passed with race detection in 27.060 seconds,
  including interrupted historical retries and a server still confirming after
  client death. The two canonical records completed 100,000 fuzz executions.
  Linux/Windows amd64 integration test binaries built with CGO disabled; runtime
  tests were executed on macOS only. The expanded outbox suite also passed with
  race detection after correcting the foreign-actor negative fixture to replace
  the original actor key before signing; that fixture must itself be canonical
  before the outbox's assignment-member rejection can be tested.
  The first whole-repository normal/race runs used the earlier fixture and
  reported the actor subcase failure. A further real-QUIC regression removes just the
  local ACK after successful delivery: reopen reports unresolved, an explicit
  retry uses a fresh nonce and the original entry, and neither the authority
  decision nor the retained executor effect is repeated.
  Final whole-repository normal and race-enabled tests passed (store package
  315.370 and 359.819 seconds respectively), and `go vet ./...` passed. The server
  pin regression was then strengthened to use an otherwise acceptable command
  and working concrete endpoint; it requires ErrUnexpectedPeer before any server
  handler or authority change and passed with race detection.
  One combined process-gate attempt ended at 301.112 seconds against the existing
  5-minute authority/executor suite limit while full normal/race suites were also
  running. The retained stack showed Pebble reopen waiting on flush/fsync. No
  orphan crash helper remained. The timeout and assertions were left unchanged;
  the process gate was rerun separately after those other suites finished.
  That complete five-suite run passed: command processes 65.997 seconds,
  100 WorkChain crash cases 28.952 seconds, archive recovery 17.076 seconds,
  466 authority/executor crash cases 200.085 seconds, and the 41 new outbox crash
  cases 20.336 seconds. The dedicated run met the same limits; it does not prove
  bounded filesystem latency under arbitrary concurrent load or physical failures.
  Protected root ownership, physical storage, copied/shared rollback, independent
  server retention, all-replica live enforcement and daemon integration remain
  separate gates. The client journal has no queue, reset or completion-signing API.
  Admission transport follow-up (2026-09-07): `PruneExecutor.Admit` now accepts
  one externally co-signed prune admission for an already retained pinned request,
  and holds executor/coordinator ownership until both the authority decision and
  executor binding are independently confirmed. Exact retry resumes only that
  authority/admission attempt. It cannot sign, refresh a head, replace the request,
  resume another transition, execute work or close a ticket. Historical admission
  remains observable after completion/retirement, but cannot bypass Execute's
  current pending-ticket guard. Existing journal formats are unchanged.
  The disabled-by-default `/outcomemesh/prune-admission/0` QUIC protocol exposes
  this ordered adapter with independently pinned peers, distinct fixed 424/74-byte
  frames, strict request/reply EOF and fresh exchange nonces. It has separate
  rate/concurrency/memory limits, including a check that exhausted admission
  traffic cannot spend completion's rate budget. There is no live handler wiring
  or durable admission client journal at that checkpoint; the completion outbox
  rejects Admit. The client-journal follow-up is recorded below.
  Tests cover all 42 initial publication faults, 14 interrupted executor resumes,
  cancellation at retained-intent boundaries, wrong signed bindings, concurrent
  retries/Stop, lost/partial replies and the QUIC-admit / locally guarded effect /
  QUIC-complete lifecycle. The expanded targeted race run passed (store 45.609
  seconds, transport 2.392 seconds, wire 2.186 seconds). All 45 separate-server-
  process crash cases passed with race detection in 34.329 seconds: two
  non-submitting opens followed by exact QUIC retry retain both confirmations
  without executing a chain effect. The new decoder completed 100,000 fuzz
  executions, `go vet ./...` passed, and Linux/Windows amd64 integration binaries
  compiled with CGO disabled. These were macOS runtime tests, not physical
  power-loss, copy-fencing or production deployment evidence.
  Whole-repository validation then found an existing archive rejection race:
  normal tests passed the authority store (471.108 seconds), but
  `TestCustodySessionRejectsReorderedAndTruncatedFrames` observed bare
  `io.ErrClosedPipe` instead of ErrCustodySession on the sibling-renewal rejection.
  The parallel whole-repository race run passed (store 511.567 seconds). A new
  deterministic test holds the auditor's final challenge Write until the replica
  rejects the sibling and closes. Both fresh and durably recovered sessions fail
  before the fix, proving that the next SetDeadline, not response decoding, loses
  the session error classification. A direct deadline-error test fails as well.
  The fix joins ErrCustodySession with the underlying deadline-setup error, just
  as frame Read/Write already do. Context cancellation remains recognizable; no
  I/O continues after a failed deadline, no closed pipe becomes success, and the
  original retained renewal is unchanged. Timeout and EOF rules are unchanged.
  The new deterministic regressions, original reordered/truncated-frame test and
  strict completion-EOF regressions passed 20 race-enabled repetitions (32.263
  seconds). The complete affected archive package then passed with race detection
  (241.736 seconds); vet and final Linux/Windows amd64 integration compilation
  also passed. The classification fix is isolated in commit `c55caea`.
  The final whole-repository normal run passed (authority store 267.829 seconds,
  archive 146.258 seconds). The earlier full race run plus the complete affected
  archive rerun cover the final production changes; no acceptance assertions or
  timeouts were relaxed to obtain these results.
  The final process gate ran separately with `make test-process
  GO=.tools/go/bin/go` (no system `go` was on this session's PATH). All six suites
  passed: command processes 65.596 seconds, 100 WorkChain crash cases 28.227
  seconds, archive recovery 16.114 seconds, 466 authority/executor crash cases
  204.191 seconds, 41 completion-outbox crash cases 22.152 seconds, and 45 new
  admission-server crash cases 28.470 seconds. Admission client durability was
  still open at that checkpoint. Managed ownership, all-assignment live
  enforcement and physical/copy-fencing guarantees remain open; these results
  do not promote the project to production.
  Admission client outbox follow-up (2026-09-12): one immutable 456-byte intent
  now retains an externally co-signed prune Admit and both transport identity
  pins before sending. Its externally retained ID binds the exact command and
  peers. It does not contain the PruneRequest bytes or prove server preparation;
  the signed OperationID binds the separately retained server request.
  Static validation checks assignment/authority/prune membership and rejects an
  ExpectedSequence above 2*(MaximumOperations-1), without refreshing the head.
  Create sends nothing. Open validates and re-syncs existing files without
  creating a root, promoting a staging receipt or submitting a command. Deliver
  uses only the concrete pinned QUIC client and returns success after a checked
  reply/EOF and durable 148-byte local receipt. Distinct magic, hash domains and
  typed wire ACKs prevent completion/admission format confusion.
  A lifetime process lock and mutex cover exchange/publication; Close waits,
  concurrent delivery serializes, and cancellation after a verified reply still
  allows recording it. Failed local publication returns no ACK and poisons the
  writer until reopen. Missing replies/receipts remain unresolved. Explicit
  retries send the same entry with a fresh nonce; a retained local ACK returns
  offline and stays historical after Stop, completion or retirement. There is
  no signing, request rewrite, reset/drop, queue or automatic retry/failover.
  Tests cover canonical records, domain separation, static sequence endpoints,
  malformed/replaced files, wrong bindings, receipt publication failures,
  cancellation, concurrent delivery/close and lost/partial QUIC replies. The
  initial targeted race-enabled integration run passed in 33.751 seconds,
  including 41 client-process kills: nine delivery/publication points in each
  of four server phases, both in-flight server confirmations, and three
  initialization points. Recovery opens twice without sending, then explicitly
  retries and checks the retained lifecycle with no chain prune effect.
  The final record decoder completed 100,000 fuzz executions (8.466 seconds);
  `go vet ./...` passed, and Linux/Windows amd64 integration binaries compiled
  with CGO disabled. Runtime checks were on macOS, not those target systems.
  Whole-repository normal tests passed (store 537.022 seconds, archive 290.019
  seconds). The concurrent whole-repository race run reached the unchanged
  10-minute store-package limit (604.115 seconds reported). Its active
  cancellation test had run for only two seconds; the retained stack showed
  fixture reopen waiting for Pebble Close while the WAL writer was in a write
  syscall. Other race-tested packages passed, including archive (389.378
  seconds). This was an aggregate suite timeout, not a reported failed
  acceptance assertion or detected data race. The complete store package then
  passed separately with race detection in 249.425 seconds, without concurrent
  test/build jobs and without extending its limit. The first combined run remains
  a timeout observation, not a successful aggregate-load latency claim.
  The final `go test -race ./...` check succeeded using those cached successful
  package results. Integration-tag vet also passed. The full process gate ran
  separately with `make test-process GO=.tools/go/bin/go`; all seven suites
  passed: command processes 64.084 seconds, 100 WorkChain crash cases 27.740
  seconds, archive recovery 15.672 seconds, 466 authority/executor cases 190.841
  seconds, 41 completion-client cases 16.078 seconds, 45 admission-server cases
  18.390 seconds and 41 admission-client cases 14.838 seconds. Test limits and
  acceptance assertions were not relaxed. The final 41-case admission-client
  process suite also passed with race detection in 22.199 seconds.
  Receipt-only rollback is not detected by the intent pin and may require an
  exact retry against independently retained server history. Checksums do not
  defend against a malicious journal owner. Managed runtime ownership, all
  required replica assignments, physical pin protection, copied-root fencing,
  power-loss/full-filesystem testing and active cutover remain separate gates.
  Command runtime ownership follow-up (2026-09-12): an optional
  PruneCommandService now exclusively owns four existing authority/executor
  roots and both concrete command handlers. Open checks external assignment,
  request and peer pins, rejects overlapping/aliased roots and loads retained
  state without listening or resuming an attempt. Partial open failure releases
  acquired owners. Explicit Start validates and copies the canonical transport
  key before creating a host; both transport peer identities must be separate
  from all assignment control/evidence roles. Neither raw writers nor the host
  are exposed. No command signer, request creator or effect API was added.
  A separate admission gate forbids new in-flight handlers once Close begins
  draining. Shutdown cancels/closes transport, waits for accepted handlers and
  only then releases executor/coordinator owners. Context cancellation follows
  the same path; concurrent/repeated Close returns the retained final error.
  Local storage uncertainty stops admission and drains the service without
  automatic reopen, retry, cancellation or rollback. Malformed/stale commands
  do not shut down a healthy service. Empty/nil runtime Close is safe.
  DeliverPruneAdmission and DeliverPruneCompletion are typed one-shot runners:
  own an existing ID-pinned outbox before transport creation, validate the
  retained peer roles/key, perform at most one explicit exchange and close
  transport before journal ownership. Cached ACKs return without a socket but
  still require the client identity. Missing roots are never initialized.
  Failures after acquiring the outbox retain Unconfirmed alongside their cause
  and return no ACK, including cleanup failures after a decision/receipt may
  already have committed. Journals store no private keys; memory copying is not
  a secure-erasure claim.
  The initial targeted runtime suite passed with race detection (7.571 seconds);
  all 16 separate-server-process recovery cases passed with race detection
  (25.688 seconds). The expanded runtime/integration suite then passed in
  33.817 seconds, including incomplete streams, concurrent Start/Close, both
  independent-confirmation shutdown barriers, competing client owners, local
  storage failures and exact retries after retirement. The process cases cover
  Open, Start and confirmed-before-reply checkpoints in prepared, admitted,
  succeeded, cancelled and retired phases, with two read-only recoveries and no
  repeated chain effect. Full and integration-tag vet passed.
  Final-source `go test ./...` and `go test -race ./...` both passed when run
  sequentially; the store package took 224.110 and 262.371 seconds respectively,
  with unchanged packages served from the test cache. No timeout was extended.
  The complete eight-suite `make test-process` gate passed sequentially with
  `-count=1`: node processes 63.624 seconds, chain 29.259, archive 15.958,
  authority/executor 195.050, completion outbox 17.101, admission server 18.248,
  admission outbox 14.781 and the new 16-case command runtime suite 20.467.
  Linux and Windows amd64 integration test binaries compiled with CGO disabled;
  this is build coverage, not non-macOS runtime or filesystem evidence. Full and
  integration-tag vet passed again on the final source.
  Operator CLI wiring and the actual audit/serve/prune lifecycle remain open.
  The command-only service must currently be closed for an explicit ownership
  handoff to the existing guarded local effect API. It does not own WorkChain,
  establish all-required-assignment enforcement or install a default daemon.
  Physical pin independence, copied-owner/key fencing, full-filesystem and
  power-loss evidence and active cutover are still deployment gates.
  Command-only operator follow-up (2026-09-12): three explicit omd commands now
  expose the owned Admit/Complete service and the two retained delivery runners.
  Each requires a canonical assignment, its independent ID and an explicit
  transport seed path. The server also requires four existing roots, request ID
  and both external peer pins; delivery requires an existing typed outbox, its
  external intent ID and an explicit route. The artifact reader bounds files and
  rejects final symlinks. Positional, unknown and repeated flags are rejected.
  No signer, request creator, missing-root initialization, WorkChain handle,
  effect API, daemon default or automatic retry was added.
  Signal shutdown drains accepted handlers before releasing roots. A failed
  readiness write closes acquired owners; a delivery stdout failure preserves
  Unconfirmed and never deletes an already retained receipt. Successful output
  explicitly identifies historical delivery, not execution authority or proof
  that a fresh connection occurred. Both cached paths still validate the key.
  The new targeted CLI suite passed with race detection in 3.426 seconds. Two
  real CLI-process campaigns passed with race detection in 21.092 seconds,
  covering SIGTERM/kill, exclusive ownership, restart, offline receipts and exact
  historical retry after retirement. Their command-only fixture has no chain
  database and makes no new chain-effect or power-loss claim. The new process
  gate is included in make test-process. PRUNE_COMMANDS.md documents prerequisites,
  flags, recovery and the distinction between command delivery and live authority.
  Final review added a failing-before-fix regression: making the disposable
  executor root unavailable stopped the service but returned nil because a local
  error shadowed the named result captured by deferred Close. The wrapper now
  retains the shutdown error; ten race-enabled repetitions passed in 3.615 seconds,
  and the expanded CLI/process suite passed in 22.889 seconds. A second real-process
  regression initially exited on SIGPIPE with no returned CLI error when stdout
  was already closed. A command-lifetime SIGPIPE subscription now keeps EPIPE on
  the cleanup path; it does not affect other command entry points. Closed-output
  tests cover readiness and both delivery types, preserving their durable receipts.
  After correcting the test's expected helper error exit code (2, not main's 1),
  three race-enabled closed-pipe repetitions passed in 22.900 seconds. The final
  expanded CLI/unit/process race suite then passed in 29.703 seconds.
  Final-source `go test ./...` and `go test -race ./...` passed sequentially;
  cmd/omd took 5.285 and 7.950 seconds, with unchanged packages using cached
  results. No consensus, journal encoding or peer protocol changed.
  The full nine-suite process gate passed with fresh runs: new CLI scenarios
  2.298 seconds, existing node processes 64.991, chain 29.504, archive 15.773,
  authority/executor 181.293, completion outbox 16.243, admission server 17.626,
  admission outbox 13.898 and owned runtime recovery 20.186. The suites ran
  sequentially, without extending any timeout.
  Full vet and integration-tag vet for cmd/omd passed. CGO-disabled omd builds
  succeeded for native macOS arm64, Linux amd64 and Windows amd64; both cross-OS
  integration test binaries also compiled. Native help exposed all three commands.
  The production builds emitted nonfatal sandbox warnings when Go tried to cache
  VCS module metadata outside the workspace, but returned success and produced
  the checked binaries. Cross-compilation is not non-macOS runtime evidence.
  Offline preparation follow-up (2026-09-12): six separate omd commands now
  expose three more functional stages. Explicit authority bootstrap creates two
  new disjoint roots under continuous pins-first ownership, then validates the
  combined snapshot. Executor preparation uses the existing pinned constructor
  with a separately retained storage-bound request. Both default to non-mutating
  placement review; explicit verify opens only existing roots, reports retained
  state and compares the full executor request without appending or resuming.
  Partial initialization is preserved, never reset or silently given fresh pins.
  These are independent pair operations, not an atomic four-root transaction.
  Consumer review/sign and independent authority review/co-sign bind the exact
  existing role-specific signature-message hash. They require explicit request,
  sequence/head and, for Complete, original admission/terminal artifacts and
  their independent IDs. Static role/sequence/linkage checks precede key reads;
  immutable artifact publication accepts only byte-identical retry. No signer
  opens a journal or discovers/refreshes a current head. Supplied cancellation
  or effect bytes remain historical input, not durable/live execution proof.
  Both typed outboxes now have offline review/create/verify commands binding an
  already co-signed entry and independently retained entry/endpoint/intent IDs.
  Review creates nothing; create accepts only a new root; verify compares the
  full retained intent and can report an offline historical ACK without sending.
  Owners close before output; lost stdout preserves roots and published bytes.
  The separate process suite runs all six commands through Admit delivery,
  explicit guarded offline cancellation, Complete delivery and repeated local
  verification. Real closed-stdout cases exercise both bootstrap pairs, both
  signing roles and both typed outbox publishers. The fixture has no WorkChain
  database and does not establish a live effect or physical independence.
  PRUNE_PREPARATION.md documents modes, independent review checkpoints, bounded
  artifact/key input, partial initialization and recovery. Ordinary daemon and
  transport entry points do not infer any preparation step. Consensus rules,
  signature domains and journal/wire encodings are unchanged.
  Cross-review also tightened the shared immutable artifact publisher's exact
  retry branch. Matching bytes previously caused only the parent directory to
  be synced, which did not establish file durability for an artifact originally
  written elsewhere. Retry now checks and syncs the same bounded regular inode,
  rechecks its path identity and returns Close errors before syncing the parent.
  Fault tests cover file-sync/close errors, conflicting bytes and an identical
  replacement inode, without removing the retained evidence. This is a local
  fsync contract, not proof of hardware power-loss behavior or copied-owner fencing.
  Final-source targeted CLI/artifact/process tests passed with race detection in
  47.867 seconds. Both full `go test ./...` and `go test -race ./...` passed;
  cmd/omd took 6.493 and 11.033 seconds after the publisher change, with unchanged
  packages using the cache. Earlier uncached store runs for this stage passed in
  275.002 and 286.410 seconds, and workarchive in 137.739 and 196.571 seconds.
  The suites ran sequentially; no timeout was extended.
  The complete ten-suite process gate passed with fresh runs: preparation CLI
  1.840 seconds, delivery CLI 2.506, existing node scenarios 65.237, chain 29.216,
  archive 16.183, authority/executor 210.286, completion outbox 24.837, admission
  server 19.007, admission outbox 14.749 and command runtime 20.335 seconds.
  Full vet and integration-tag vet for cmd/omd also passed.
  CGO-disabled builds with VCS stamping disabled succeeded for macOS arm64,
  Linux amd64 and Windows amd64. Linux/Windows integration test binaries also
  compiled; native `omd help` exposes all six preparation commands. This is
  cross-compilation coverage, not Linux/Windows runtime or filesystem evidence.
  Library maintenance follow-up (2026-09-13): EnterMaintenance parks the command
  transport and drains accepted handlers without releasing any of the four root
  locks. It issues one local maintenance capability; copied or closed handles
  cannot review/cancel, duplicate acquisition is refused, and a parked service
  cannot Start again. Done still
  waits for actual owner closure. Old transport-context cancellation cannot
  release a successfully handed-off owner; the new caller must supervise and
  explicitly Close it. An already scheduled shutdown cannot be commandeered.
  A combined review commits the confirmed authority/executor positions, phase,
  request, assignment, storage and binding IDs, admission and terminal history.
  Review and CancelBeforeStart hold lifecycle -> executor -> coordinator guards;
  the exact review ID is recomputed before the existing live pending-ticket check
  and cancellation publication/confirmation under those same guards. A changed
  history makes a previous review stale. Prepared, Started/unknown, Succeeded,
  raw/unbound or unconfirmed states do not become cancellable. A separately
  reviewed confirmed cancellation remains historical evidence, not completion.
  Storage uncertainty is retained and returned by subsequent Review/Close. The
  handle never repairs or resumes an attempt and exposes no raw owner, signer,
  generic action or Execute. Operator lifetime/control integration and actual
  all-required-assignment/live-storage enforcement remain open.
  Tests cover held confirmation barriers, exact review binding, stale heads,
  retained authority/executor attempts, cancellation/Close ordering and
  EnterMaintenance/Start/Close/context races. A drain test preserves a confirmed
  authority Admit with a still-Prepared executor when cancellation wins before
  binding; it does not automatically complete that transition. Four separate
  process kills cover drained, reviewed, cancellation-confirmation and confirmed
  cancellation boundaries, with two non-resuming reopens and unchanged chain
  accounting. The expanded maintenance/cancellation suite, including existing
  cancellation crash cases, passed with race detection in 72.519 seconds.
  Both full `go test ./...` and `go test -race ./...` passed on the final source:
  store took 263.949 and 282.659 seconds, and cmd/omd took 14.861 and 16.998
  seconds. The heavy suites ran sequentially with their existing timeouts.
  All ten process-gate groups passed with fresh runs: preparation CLI 2.073
  seconds, delivery CLI 2.093, existing node scenarios 63.930, chain 28.983,
  archive 16.312, authority/executor 200.993, completion outbox 16.425,
  admission server 19.493, admission outbox 16.381, and the expanded command
  runtime/maintenance group 23.398 seconds. Full vet and integration-tag vet
  for both store and cmd/omd also passed.
  CGO-disabled omd builds passed for macOS arm64, Linux amd64 and Windows amd64;
  the updated store integration test binaries also compiled for Linux/Windows.
  Native `omd help` passed. These are cross-build checks, not Linux/Windows
  runtime or filesystem guarantees; no new CLI command is introduced.
  Operator maintenance follow-up (2026-09-13): the command server now accepts
  explicit `--maintenance-control stdin` on macOS/Linux. Default `none` never
  reads or adopts stdin. The dedicated local pipe has a 96-byte LF-terminated
  grammar: review, cancel-before-start with one exact lowercase review ID, and
  close. First review enters the existing one-way capability without releasing
  any root lock; cancel cannot infer handoff or refresh a review. EOF, parent
  signal, service/storage failure, malformed input and output errors terminate
  the local session, join its input supervisor and close the same owners.
  An initial real SIGTERM process test exposed blocking inherited os.Stdin:
  closing it waited behind Read, so all three lifecycle phases timed out.
  The fix adopts an atomic close-on-exec duplicate in nonblocking mode and checks
  Go poller support before opening journals. It changes only the explicitly
  dedicated read endpoint. Real SIGTERM now drains serving, parked and cancelled
  processes with the writer still open; no test timeout was extended. Other
  native platforms refuse this live control mode before opening roots.
  The separate `work-prune-maintenance` command opens four existing owners
  without listening or reading a key. Default review appends/resumes nothing;
  cancel requires an independently supplied exact review ID. Both entry points
  use the existing same-guard cancellation method and print canonical historical
  terminal bytes for the separately reviewed Complete workflow. Neither signs,
  completes, executes, resumes uncertainty, repairs storage or fences copies.
  Cancellation output failure remains historically unresolved: a new explicit
  review can retrieve the original confirmed terminal, never reuse the old ID.
  The existing full preparation process fixture now goes from new-root bootstrap
  through admission, public-CLI-only cancellation, two-role Complete signing,
  outbox preparation, delivery and receipt verification without a private
  cancellation call. Its journal fixtures still contain no WorkChain database.
  Tests cover stale/partial/noncanonical/oversized input, EOF/context/close in
  three phases, input-close and short-output errors, loss of original storage,
  unconfirmed pins, rejection of competing owners and a fresh outbox unable to
  reach the parked listener. Nine process exits cover EOF/SIGTERM/kill in the
  same phases; actual SIGPIPE covers both live review/cancel and standalone
  cancellation. The expanded new CLI/unit/process race suite passed in 67.592
  seconds after the inherited-pipe fix. PRUNE_MAINTENANCE.md documents input
  ownership, platform limits, exact review, output ambiguity and remaining gates.
  The full prune operator subset (preparation, signing, delivery, maintenance and
  all corresponding process cases) passed with race detection in 143.380 seconds.
  Full `go test ./...` and `go test -race ./...` passed too: cmd/omd took 25.456
  and 31.497 seconds, with unchanged packages using their test cache.
  The complete ten-group process gate passed with fresh runs: preparation CLI
  3.293 seconds, command/maintenance CLI 11.243, existing node scenarios 66.874,
  chain 33.667, archive 23.625, authority/executor 296.009, completion outbox
  16.989, admission server 18.457, admission outbox 14.867 and runtime/maintenance
  21.809 seconds. Heavy suites ran sequentially within the existing gate
  timeouts. Full vet and integration-tag vet for cmd/omd and store passed.
  CGO-disabled omd builds passed for macOS arm64, Linux amd64 and Windows amd64;
  cmd/omd integration test binaries also compiled for Linux/Windows. Native
  `omd help` includes maintenance. These checks do not establish Linux/Windows
  runtime or filesystem behavior; Windows live stdin control remains disabled.
  Consensus rules, signature domains and journal/wire encodings are unchanged;
  no network handler or remote control protocol is added.
  Reviewed ownership handoff and actual audit/serve/prune integration with
  all-required-assignment and physical storage guards remain open. No active
  cross-host cutover or public-testnet readiness is claimed.

  Exact recovery follow-up (2026-09-13): the same maintenance capability now
  supports a separate ReviewRecovery/Recover boundary. Its local domain-separated
  digest binds confirmed and observed authority/executor prefixes, both retained
  intents, request/assignment/storage/binding IDs, phase and terminal identity.
  Recovery requires that exact digest AND an independently chosen action under
  lifecycle -> executor -> coordinator guards. It settles only one retained
  authority Admit/Complete or executor admission/start/result/cancellation.
  Authority completion reuses the terminal validation from the existing adapter;
  no signed command, wire encoding or journal format changes. Unrelated authority
  commands and two pending layers are blocked. A recovered start remains unknown;
  WorkChain is never called, no binding gap is filled, and no next step is inferred.
  Sticky storage errors require Close/reopen; failed output cannot erase history
  or make an old review usable. The offline maintenance CLI now has explicit
  recovery-review/recover modes and rejects missing/foreign action or review flags.
  Live stdin remains review/cancel-before-start/close, without recovery or a new
  network endpoint. PRUNE_MAINTENANCE.md records the action matrix and failure path.
  Core recovery/completion tests passed under race detection in 56.453 seconds.
  Focused CLI/unit and actual EPIPE process recovery passed with race detection
  in 10.341 seconds. Eighteen process kills across six actions (before writes,
  before confirmation and after confirmation) passed under race in 11.952 seconds;
  reopen preserves pending/confirmed distinctions and unchanged chain accounting.
  Full `go test ./...` passed: cmd/omd 38.057 seconds and authority/executor store
  277.610 seconds, with unchanged packages using their existing test cache.
  Full `go test -race ./...` passed too: cmd/omd 33.933 seconds and store 293.833
  seconds. Heavy suites ran sequentially.
  The complete ten-group process gate passed with fresh runs inside unchanged
  timeouts: preparation CLI 2.029 seconds, command/maintenance/recovery CLI 5.933,
  existing node scenarios 65.497, chain 30.753, archive 16.087, authority/executor
  198.124, completion outbox 23.197, admission server 19.235, admission outbox
  15.737 and runtime/maintenance/recovery 29.544 seconds. The two new process
  recovery tests are included in Makefile's permanent process gate.
  Full vet and integration-tag vet for cmd/omd and store passed.
  CGO-disabled omd builds passed for macOS arm64, Linux amd64 and Windows amd64;
  both cmd/omd and store integration test binaries compiled for Linux/Windows.
  Native help still exposes the maintenance command. These build checks are not
  Linux/Windows runtime, filesystem or power-loss evidence. Native Windows live
  stdin control remains disabled; its offline recovery build remains available.
  The first full-plan production readiness baseline is approximately 40/100;
  PRODUCTION_READINESS.md separates weighted implementation credit from independent
  audit, public-testnet and operational launch gates. This is not public-testnet
  activation or production authorization; live all-assignment/storage acceptance
  and the remainder of the full plan stay open.

  Local archive acceptance follow-up (2026-09-13): ExecuteArchive now composes
  an independently pinned archive/trust/timing policy, exact initial-receipt
  assignment coverage, one retained executor and concrete position-pinned WorkChain.
  It requires each selected assignment's original confirmed pending Prune ticket,
  locks all coordinators in immutable construction-ID order, replays all replicas,
  matches the retained floor before evidence publication, and keeps all guards
  through final live-time storage authorization and confirmed executor result.
  Relabelled/repeated/missing owners cannot change lock order or narrow coverage.
  Existing request/effect/terminal/signature/journal encodings remain unchanged.
  The legacy archive gate shares the factored replay/time path; no old CLI is
  silently upgraded and maintenance still exposes no Execute or raw-owner access.
  StorageRoots is read-only original placement inspection. All owner roots,
  replica directories and the existing dedicated evidence directory must be
  disjoint. The policy binds both executor and storage pairs, and pending database
  positions fail closed. Accepted policy/owner/replica slices are detached.
  The initial focused archive-acceptance race suite passed in 20.347 seconds;
  the expanded suite plus six process kills passed in 26.501 seconds. Shared
  exact-request, clock and policy-ID tests passed under race in 5.236 seconds;
  additional cancellation/drain/input-detachment tests passed in 4.081 seconds.
  Full-suite validation exposed two mistakes in the new StorageRoots test:
  comparing macOS's original /var temporary path with canonical /private/var,
  then closing an already closed fixture in its reopen helper. The test now
  compares resolved paths and opens the closed owner directly. The focused
  regression passed in 0.658 seconds; production path/close checks were not relaxed.
  Full `go test ./...` then passed: WorkChain reran in 37.618 seconds;
  cmd/omd, authority/executor store and archive reused this pass's successful
  70.499-, 377.580- and 180.979-second results. Heavy full suites ran sequentially.
  Full `go test -race ./...` passed: cmd/omd 60.678 seconds, store 354.174,
  archive 212.225 and WorkChain 67.131 seconds. No race detector report occurred.
  All ten fresh process groups passed inside unchanged timeouts: preparation CLI
  2.025 seconds, command/maintenance/recovery CLI 5.834, existing node scenarios
  65.858, chain 28.741, archive 15.726, authority/executor 218.743, completion
  outbox 17.746, admission server 18.360, admission outbox 14.963 and the expanded
  runtime/maintenance/recovery/archive group 33.759 seconds. The six new archive
  process-kill boundaries are part of Makefile's permanent gate.
  Full vet and integration-tag vet for cmd/omd, store, archive and WorkChain passed.
  CGO-disabled omd builds passed for macOS arm64, Linux amd64 and Windows amd64.
  Integration test binaries for cmd/omd, store, archive and WorkChain compiled
  for both Linux and Windows. These are build checks, not runtime/physical-storage
  evidence on those systems. Native Windows live stdin control remains disabled.
  Actual two-replica deletion confirms the database and executor but leaves every
  authority ticket pending. Process reopen preserves admitted/started/terminal
  states, and positive effect recovery never re-executes. Cancellation after a
  storage intent preserves an unresolved pin and never infers a no-effect result.
  PRUNE_ACCEPTANCE.md describes the exact boundary and remaining work: renewal
  lineage, protected policy/operation inventory, secondary admission/terminal
  adapters, multi-owner operator handoff, managed audit/serve, and cross-host/
  physical/copy fencing. Full-plan readiness remains approximately 40/100.
  Renewal-prefix follow-up (2026-09-14): a separate ExecuteArchiveWithLineage
  library mode now requires the independently pinned LineageID, which commits
  the original archive policy and aggregate evidence budgets. The original
  ExecuteArchive and its policy ID remain initial-only. Every selected assignment
  supplies one exact initial receipt, custody policy, canonical manifest and
  complete canonical journal-entry prefix from sequence one. The verifier
  reconstructs the assignment and checks every predecessor, signed challenge,
  sample batch, proof and renewal through the exact request receipt.
  All current Prune guards remain held through historical verification, live
  archive replay, evidence, final batch authorization and confirmed result.
  Aggregate limits of 1,024 entries and 256 MiB of encoded manifests/entries are
  checked before large buffer copies, including when evidence is split across
  replicas. Accepted buffers and auditor sets are detached; cancellation, terminal
  replay refusal and unresolved Started semantics are preserved.
  This verifies a historical prefix, not a latest/uniquely retained journal head,
  historical Audit-ticket admission, physical durability or permission to activate
  recovered evidence. No journal, command, signature, terminal or consensus
  format changes; no evidence-preparation CLI or automatic completion is added.
  Initial focused verifier tests passed in 1.062 seconds and new local acceptance
  tests in 13.082 seconds. The first combined race/integration run passed:
  workarchive 2.956 seconds and store 55.153 seconds, covering both modes and
  thirteen process kills (seven new renewal-mode boundaries). Makefile includes
  the renewal process test in its existing final group with the same timeout.
  The full normal regression passed: cmd/omd 51.714 seconds, store 353.500 and
  workarchive 165.091 seconds. Final review then moved assignment validation
  before its reconstruction/copy and added an oversized-consumer regression;
  subsequent verification covers that final preflight ordering.
  The full final `go test -race ./...` passed: cmd/omd 44.119 seconds, store
  349.248 and workarchive 200.801 seconds, with unchanged packages cached.
  The expanded final runtime/maintenance/recovery/archive process group passed
  afresh under race in 52.621 seconds inside its unchanged two-minute timeout.
  The other nine standalone process-gate groups were not rerun in this pass;
  their last complete gate remains the 2026-09-13 archive-acceptance run above.
  Full vet and integration-tag vet for cmd/omd, workarchive and store passed.
  CGO-disabled omd builds passed for macOS arm64, Linux amd64 and Windows amd64;
  integration test binaries for cmd/omd, workarchive and store compiled for Linux
  and Windows. Native help remains available. Linux/Windows execution and physical
  storage behavior were not tested by these cross-builds; live Windows stdin
  maintenance remains disabled. No public-testnet or production launch is implied.
  Bounded evidence preparation, retained policy/operation inventory, secondary
  admission/completion tooling, supervised multi-owner handoff and managed
  audit/serve remain open. Full-plan production readiness stays approximately 40/100.
  Prepared-inventory follow-up (2026-09-14): a separate bounded operator artifact
  now retains the exact initial/lineage mode, full policy/checkpoint and pair IDs,
  original storage-bound request, selected receipt bundle and one co-signed Admit
  per assignment. Canonical verification checks all signatures, strict aligned
  replica ordering, exact retained floor and the common original request/consumer
  across every primary and secondary admission. Availability is checked at the
  retained request time, not inferred as fresh now. Both inventory and mode-policy
  IDs must be independently retained. The 1 MiB codec rejects oversized, malformed,
  truncated and trailing input and has a frozen vector and a dedicated fuzz target.
  No-replace save and bounded read-only load preserve conflicting destinations,
  reject symlinks and allow only exact retries; equal concurrent publishers
  converge while differing packages cannot both claim the same name. Five
  process-kill boundaries cover file sync, publication and directory confirmation;
  orphan temporary files cannot become committed packages on load.
  This is preparation, not executed-policy provenance, historical Audit admission,
  latest pending state, lineage verification or independent physical durability.
  A completed secondary ticket does not invalidate historical reading of a
  package, but the existing live adapter still rejects execution. No executor,
  authority or database state is advanced by saving/loading; no command or network
  surface is added, and old journal/request/effect/terminal formats are unchanged.
  Full runtime binding, bounded lineage-body preparation, secondary tooling and
  supervised multi-owner handoff remain open. Readiness stays approximately 40/100.
  Verification: the initial focused race/integration run passed in 11.042 seconds,
  including the five new process kills. The final fixed-seed decoder fuzz smoke
  passed with two workers and a ten-second budget (11.836 seconds total); its
  ten reported executions are smoke evidence only, not broad fuzz coverage.
  The full `go test -race ./...` passed: store 365.832 seconds, cmd/omd 35.178,
  with unchanged packages cached. A final extra input-buffer detachment assertion
  was then added and passed together with all inventory tests, fuzz seeds and the
  expanded runtime/maintenance/recovery/archive process group under race in
  80.992 seconds, within the unchanged two-minute process-group timeout.
  Full vet and integration-tag store vet passed. The other nine standalone
  process-gate groups and the full normal suite were not rerun in this pass;
  earlier full-gate results remain recorded above, not claimed as fresh runs.
  CGO-disabled, trimpath omd builds passed for macOS arm64, Linux amd64 and
  Windows amd64; integration-tag store test binaries compiled for Linux/Windows.
  File headers confirm the intended architectures. The command-specific `-h`
  probe returned the existing `flag: help requested` error (exit 1), not a
  successful maintenance invocation. Native `omd help` exited successfully and
  listed the existing maintenance commands. Cross-builds are not Linux/Windows runtime
  or physical-storage evidence; no new CLI or live Windows stdin support is added.
  Inventory-bound execution follow-up (2026-09-14): ExecutePreparedArchive now
  loads the independently pinned retained package, matches every exact selected
  admission ticket and replica receipt, and runs the existing initial/lineage
  verifiers with every original authority guard held. It re-syncs the unchanged
  package before final live-time authorization; no missing package is recreated.
  A pre-existing database effect is rejected before replay and again before start.
  Version-1 Started records retain the inventory ID in both executor journals;
  version-0 starts remain unchanged, and older readers reject the new version.
  Raw/storage-unbound journals cannot accept bound starts. Requests, package codec,
  authority signatures, database effects, terminal and consensus formats are unchanged.
  Snapshot exposes ArchiveInventoryID; InspectArchiveInventory verifies the pinned
  package against a fully confirmed local executor prefix. It rejects pending or
  old unbound history and distinguishes unresolved Started from Succeeded with its
  exact confirmed effect. It never queries/mutates the database or refreshes live
  authority. Explicit pending-start/result recovery preserves the original ID and
  never re-executes or uses absence to settle unknown work. No automatic completion
  or retroactive provenance is added. This remains trusted exclusive-owner local
  history, not a remote certificate or protection from copied/raw concurrent owners.
  Both modes have real two-replica deletion, exact-ticket substitution rejection,
  package mutation/missing-file fences, cancellation, pending recovery, cached-effect
  rejection and one-root downgrade coverage. Nineteen process kills add nine
  initial and ten lineage cases; Makefile keeps these in a separate two-minute
  group so the old runtime/recovery/archive gate is not given a larger timeout.
  Bounded lineage-body preparation, secondary tooling, supervised multi-owner CLI
  handoff, managed audit/serve and physical/remote acceptance remain open. Full-plan
  production readiness stays approximately 40/100.
  Bound-execution verification: the initial combined focused race/integration run
  passed in 63.481 seconds, including 19 new process kills. After adding explicit
  pre-existing-effect fences and one-root downgrade coverage, the final focused
  race tests passed in 31.137 seconds. The full final `go test -race ./...` passed:
  store 533.197 seconds, cmd/omd 47.010, with unchanged packages cached. These are
  test-run durations, not performance benchmarks. Full vet and integration-tag
  store vet passed. No production or public-testnet credit is claimed.
  The complete final `make test-process` gate passed all eleven groups, using the
  existing individual timeouts plus a separate two-minute prepared-archive group.
  Group times in Makefile order were 2.123, 5.745, 65.796, 30.873, 17.030,
  205.052, 17.654, 19.240, 15.542, 41.644 and 16.110 seconds. The last group
  includes all 19 new process kills; the previous ten groups passed afresh.
  The updated FuzzPrunePinTransitions smoke passed with both start versions:
  955 reported executions, two workers, ten-second budget (11.865 seconds total).
  This is bounded smoke coverage, not a long fuzz campaign. CGO-disabled trimpath
  omd builds passed for macOS arm64, Linux amd64 and Windows amd64; integration-tag
  cmd/omd and store test binaries compiled for Linux and Windows. Native `omd help`
  exited successfully. Final full vet and integration-tag cmd/omd/store vet passed;
  formatting and diff checks were clean. The full normal suite was not separately
  rerun; the full race suite and all process groups above are fresh final runs.
  Cross-builds do not establish Linux/Windows runtime or physical-storage behavior,
  and native Windows live stdin maintenance remains disabled.
  Historical lineage retention follow-up (2026-09-14): an opaque, detached
  ArchivePruneLineageEvidence now retains supplied complete prefixes against the
  exact lineage-mode inventory and policy pins. Preparation checks one aggregate
  1,024-entry / 256 MiB body budget before copying, orders by pinned assignments
  and fully verifies each prefix/initial receipt/custody policy/selected receipt.
  A separately reviewed evidence ID commits the exact v0 envelope and both pins.
  Save/load use streaming I/O, bounded framing, regular-file identity checks and
  immutable no-replace publication with exact retry and file/parent sync. Loading
  authenticates the stream before body allocation and fully re-verifies historical
  evidence. File I/O does not concatenate a second evidence-sized buffer; explicit
  lineage getters still make bounded detached copies for the existing executor.
  No keys, live journal discovery, owner activation or new pruning permission is
  involved. Started still binds the inventory, not this separate evidence file;
  the executor does not own or re-sync that file. Preserve it and all external pins
  independently. Historical readability cannot bypass completed secondary tickets.
  Tests cover empty, mixed and renewed prefixes through actual guarded deletion,
  caller-buffer detachment, pin/body/framing/count/aggregate-budget rejection,
  cancellation between 64 KiB chunks, corrupt/symlink/oversized files, inode
  replacement rejection, equal/conflicting publishers and five process kills.
  A frozen one-renewal-per-replica vector and fixed-seed decoder fuzz target are
  included. Makefile adds this target to fuzz and the five kills to the existing
  prepared-archive process group without changing any timeout or removing tests.
  Reviewed live-journal extraction, secondary admission/completion, supervised
  multi-owner CLI handoff, managed audit/serve and physical/remote acceptance remain
  open. The weighted production readiness baseline stays approximately 40/100.
  Lineage-retention verification: focused race/integration tests passed in 39.228
  seconds, including all five new publication kills and 19 prepared-execution
  recovery cases. After adding the explicit mid-stream cancellation assertion,
  the full final `go test -race ./...` passed: store 390.744 seconds and cmd/omd
  36.559, with unchanged packages cached. The final expanded standalone process
  group passed all 24 kills in 16.866 seconds within its unchanged two-minute
  timeout. The other ten process groups and the full normal suite were not rerun
  in this pass; their previous results above are not claimed as fresh evidence.
  Decoder fuzz smoke passed with three fixed seeds, two workers and a ten-second
  budget: 5,765 reported executions, 11.829 seconds total. This is not a long fuzz
  campaign. Full vet and integration-tag cmd/omd/store vet passed. CGO-disabled
  trimpath omd builds passed for macOS arm64, Linux amd64 and Windows amd64;
  integration-tag store test binaries compiled for Linux/Windows, and native
  `omd help` exited successfully. Formatting/diff checks are clean. Cross-builds
  are not Linux/Windows runtime, physical-storage, audit or public-testnet evidence.
  Colocated secondary admission follow-up (2026-09-19): the explicit
  AdmitPreparedArchiveSecondary method now submits one exact co-signed packaged
  candidate without rewriting the primary request ID. The executor must have a
  confirmed storage-bound primary admission; a first secondary intent additionally
  requires its live primary ticket and pre-start executor stage. Executor plus
  both original coordinator guards remain held in canonical lock order through
  exact inventory re-sync and secondary intent/decision/confirmation. No executor
  history, database or replica content is changed. Independent pins, disjoint placement,
  exact tickets, pending attempts and the secondary's own phase/head checks remain
  mandatory. An already inventory-bound start cannot be relabelled by retry.
  Exact retained secondary attempts/history remain reconcilable after primary
  cancellation/drain or secondary retirement; acknowledgements are never execution
  permission. A retained intent may still append its original authority decision
  during explicit recovery. Unrelated secondary intents and pending executor
  transitions cannot be resumed by this method. There is no batch admission,
  signing, head refresh, remote route, completion or format/consensus change.
  Tests cover both modes through actual guarded deletion, primary Stopping drain,
  eight concurrent retries with one decision, first-intent rejection after terminal
  state or primary drain, exact retained recovery, inventory mutation/missing-file
  fences, owner/pin/ticket/scope/placement checks and guards through confirmation.
  All 21 publication fault boundaries are exercised. Thirteen process kills cover
  eight initial and five retained-retry boundaries; repeated open is non-submitting
  and history/effect checks confirm admission did not execute work. The new process
  group has its own two-minute timeout; existing groups/timeouts are unchanged.
  Secondary terminal handling, reviewed journal extraction, operator signing/
  delivery/CLI, managed audit/serve and physical/remote acceptance remain open.
  The full planned production readiness estimate remains approximately 40/100.
  Secondary-admission verification: focused race/integration tests passed in
  72.767 seconds, including all 13 new process kills. Additional Stopping/concurrent
  retry and pending-executor/closed-owner tests then passed under race in 4.485
  seconds. The full final `go test -race ./...` passed: store 588.879 seconds,
  cmd/omd 95.239, workarchive 311.384 and workgraphmodel 539.821. These are test-run
  durations, not benchmarks; no timeout was increased. Final standalone process
  groups passed: the existing prepared-execution/lineage-retention group (24 kills)
  in 16.893 seconds, and the new secondary-admission group (13 kills) in 10.371.
  The other ten process groups and the full normal suite were not rerun in this
  pass; earlier results above are not claimed as fresh checks. Full vet and
  integration-tag cmd/omd/store vet passed. The unchanged inventory decoder fuzz
  smoke passed with three seeds, two workers and a ten-second budget: only five
  reported executions, 12.182 seconds total. This is minimal smoke evidence,
  not broad fuzz coverage or a new codec campaign.
  CGO-disabled trimpath omd builds passed for macOS arm64, Linux amd64 and Windows
  amd64. Integration-tag store test binaries compiled for Linux/Windows; native
  `omd help` exited successfully. Formatting and diff checks are clean. These
  cross-builds do not establish Linux/Windows runtime or physical-storage behavior;
  no new CLI command or native Windows live stdin support is added.
  Secondary-completion follow-up (2026-10-26): CompletePreparedArchiveSecondary
  now submits one explicit co-signed Complete entry against the executor's
  independently confirmed terminal outcome. The target operation must actually
  exist with the exact packaged admission ticket, original primary request ID,
  consumer and Prune purpose. Success requires the original inventory-bound
  version-1 start and matching effect; an old unbound result cannot gain that
  provenance later. Pre-start cancellation instead checks its original request,
  primary ticket and executor pair. Cancellation has no inventory field and does
  not certify inventory use or secondary admission before the cancellation.
  Both guards remain held through exact package re-sync and the coordinator's
  intent, decision and independent confirmation. Missing/changed inventory,
  unrelated pending attempts, pending executor transitions and unresolved starts
  are rejected. The original primary and other secondary owners need not be open.
  Exact retained attempts and historical completions remain recoverable after
  retirement; each target drains separately. No automatic completion, new signing,
  command transport, terminal encoding, WorkChain query or repeated deletion is
  introduced. This preserves the trusted exclusive-owner scope and leaves copied
  owners, physical failure domains and remote certificates outside the guarantee.
  Operator signing/delivery/CLI, reviewed journal extraction, managed audit/serve
  and physical/remote acceptance remain open. Production readiness stays 40/100.
  Tests cover both initial/lineage modes and success/cancellation, primary and
  database closed during completion, target Stopping/Retired history, exact signed
  binding checks, never-admitted candidates, unresolved and legacy results,
  pending executor/authority work, inventory mutation/missing-file fences and
  eight concurrent retries. All 21 publication stages are fault-injected for
  each outcome (42 cases). Twenty-six process kills cover eight initial and five
  retained-retry stages per outcome, with two non-submitting reopens and unchanged
  executor/primary/database checks. Same-request cancellation can select a newly
  reviewed inventory without claiming earlier inventory use; success cannot swap
  its retained binding. A retained secondary admission reconciled after primary
  cancellation can then be explicitly drained with the same cancellation evidence.
  Race-gate sizing follow-up: the first unpartitioned custodyauthority race run
  reached Go's cumulative ten-minute package limit while the existing
  TestPinnedPruneExecutorPublicationFailures was reopening its database. No
  assertion failure or blocked mutex was reported at that point. The larger
  suite now runs in two complementary invocations of make test-race: all
  TestArchive-prefixed tests, then every remaining test/example/fuzz seed with
  that prefix skipped. The current store list is 32 plus 189 (221 total), with
  no overlap or omission. Each invocation retains Go's default timeout; the
  process-group timeouts are unchanged. This is an aggregate test-run budget
  adjustment, not performance or physical-storage acceptance evidence.
  Secondary-completion verification: the initial focused race/integration run
  exercised the new recovery cases but failed two new signed-binding test fixtures
  that retained the old actor key while changing signer. The fixtures were fixed;
  the complete signed-binding test then passed under race in 4.438 seconds.
  The final full make test-race passed both complementary groups across all
  packages. Store times were 233.663 seconds for the 32 archive tests and 496.627
  seconds for the remaining 189 tests/fuzz seeds; second-group cmd/omd was 81.641,
  workarchive 314.975 and workgraphmodel 573.750. These are test-run durations,
  not benchmarks. The earlier unpartitioned timeout is retained above rather than
  represented as a passing run. No test or process timeout was extended.
  Full vet and integration-tag cmd/omd/store vet passed. CGO-disabled trimpath omd
  builds passed for macOS arm64, Linux amd64 and Windows amd64; integration-tag
  store test binaries compiled for Linux/Windows, and native omd help succeeded.
  Cross-builds do not establish Linux/Windows runtime or physical-storage behavior.
  Existing fuzz seeds ran in the full race gate; no new decoder/format or separate
  fuzz campaign is introduced. The full normal suite is not claimed as a separate
  run. Operator CLI and native Windows live stdin support remain unchanged.
  Final standalone process groups passed with unchanged two-minute timeouts:
  prepared-execution/lineage retention (24 kills) in 17.441 seconds, secondary
  admission (13 kills) in 12.697, and new secondary completion (26 kills) in
  22.834. All 63 scenarios passed afresh. The other ten process groups were not
  rerun in this pass; their earlier results are not claimed as fresh checks.
  Formatting and diff checks are clean. No production, audit or public-testnet
  acceptance credit is added.
  Secondary offline signing follow-up (2026-10-26): two explicit commands now
  review/sign and review/co-sign secondary Admit/Complete without rewriting the
  original primary request. Both original primary and selected secondary
  assignments are independently pinned; distinct replica keys, exact shared
  network/genesis/activation/base/manifest/statement and consumer Prune permission
  are checked before key access. Receipt/policy/generation/auditor fields may
  legitimately differ across replicas. Signing precedes inventory construction,
  avoiding a circular requirement for already co-signed admissions.
  Complete separately pins primary and target admissions, checks the primary
  terminal bytes against the primary ticket and original request/storage/boundary,
  and uses the target ticket/history in the signed completion. Existing review
  hashes, signature domains, canonical encodings and immutable publication are
  reused. The original primary command flag/output surface remains unchanged;
  new flags and scope fields belong only to the two explicit secondary commands.
  All artifact/scope/review checks precede the role key read. No live owner,
  WorkChain or network is opened, and historical terminal validation does not
  establish executor confirmation or an inventory-bound start. Generic typed
  outbox review/create/verify can retain the signed secondary entries and transport
  pins without delivery. The current primary command server still cannot accept
  secondary operations; server/delivery and supervised multi-owner handoff remain
  open. No production, audit or public-testnet credit is added; readiness stays 40/100.
  Secondary-signing verification: combined old/new offline unit and process tests
  passed under race/integration in 105.600 seconds. They cover initial Admit and
  both terminal kinds through actual CLI review, consumer signing, authority
  co-signing, exact publication retries and typed outbox creation/verification.
  Nine new closed-stdout cases preserve consumer commands, authority entries and
  outboxes for exact recovery across all three phases. Negative coverage includes
  independently re-pinned archive scope changes, same-replica substitutions,
  consumer permission, rewritten request, primary/secondary admission or terminal
  confusion, stale target positions, role keys, review-before-key ordering and
  immutable output conflicts. No owner/network initialization is inferred.
  Full final make test-race passed: changed cmd/omd groups ran in 1.700 and 31.683
  seconds; unchanged packages, including both store groups, used valid cached
  results from the preceding gate. Full vet and integration-tag cmd/omd vet passed.
  Final standalone process groups passed with unchanged two-minute limits:
  original preparation 2.914 seconds, new secondary signing 2.287, and existing
  command/maintenance lifecycle 7.398. The other eleven process groups and a
  separate full normal suite were not rerun; earlier results are not claimed as
  fresh checks. Existing fuzz seeds ran in the race gate; no new decoder or
  separate fuzz campaign is introduced by these commands.
  CGO-disabled trimpath omd builds passed for macOS arm64, Linux amd64 and Windows
  amd64; integration-tag cmd/omd test binaries compiled for Linux/Windows. Native
  omd help succeeded and lists both explicit secondary signing commands.
  Formatting and diff checks are clean. Cross-builds are not Linux/Windows runtime
  or physical-storage evidence; native Windows live stdin remains unchanged.
  Fixed-secondary network follow-up (2026-10-26): explicit admission/completion
  session constructors now fix one target, inventory/policy pins and both peer
  identities. They reuse existing canonical request/EOF/deadline/ACK handling and
  privately dispatch to the concrete guarded secondary adapters. Default primary
  construction remains unchanged. Each request re-loads exact content pins;
  target writes and replies still wait for independent confirmation. No wire,
  journal or receipt format changes, generic callback or execution endpoint is
  added. Construction checks healthy retained owner diagnostics and static scope,
  while stage, pending attempts, actual admission and terminal checks stay live
  under the guarded operation. Completion handlers can be installed before the
  result exists and need no live primary owner after it drains.
  Transport pins are separated from all inventory assignments' roles plus pinned
  checkpoint-attestor and replica trust keys, including unselected trusted replicas.
  The caller must match actual host.ID to the configured server pin, supply the
  authenticated peer and retain owners until handlers drain. One target per host
  is explicit: registering another handler for the same protocol replaces it.
  Generic typed outboxes retain the original signed intent across lost/partial
  responses, restart and exact retry; cached ACKs remain historical observations.
  No supervised secondary daemon/CLI ownership or all-target multiplexing is added.
  The requested mainnet date is 2026-11-01, six days after this assessment. The
  existing 30-day public calibration, six-month stability, independent review,
  audit and release/operator gates are still unfulfilled. The target date does
  not waive them or change the 40/100 production-readiness estimate.
  Secondary-network verification: focused new race/integration tests passed in
  55.718 seconds, including all 18 real-QUIC child-process kills. Existing primary
  admission/completion unit sessions then passed under race in 15.328 seconds.
  Standalone new secondary process recovery passed in 17.381 seconds, and existing
  primary admission/completion QUIC process crash coverage passed in 25.256;
  all retained their original two-minute process-group bounds. The new process
  group is separate in Makefile; no older group or timeout was removed.
  Full final make test-race passed across both complementary groups: fresh store
  runs took 224.277 and 371.984 seconds, and fresh cmd/omd runs took 1.685 and
  43.268. Unchanged packages used valid cached results from the preceding gate.
  These are test-run durations, not performance benchmarks. Full vet and
  integration-tag store/cmd vet passed. CGO-disabled trimpath omd builds passed
  for macOS arm64, Linux amd64 and Windows amd64; integration-tag store test
  binaries compiled for Linux/Windows, and native omd help succeeded.
  The other process groups and a separate full normal suite were not rerun in
  this pass; their earlier evidence is not claimed as fresh. Existing fuzz seeds
  ran in the race gate; no new codec or separate fuzz campaign is introduced.
  Cross-builds establish compilation, not foreign-OS runtime, physical-storage,
  independent audit, public calibration or mainnet acceptance. Formatting and
  diff checks are clean; no production-readiness credit is added.
  Owned secondary-service follow-up (2026-10-26):
  OpenPruneSecondaryCommandService now owns one original pinned executor and
  selected secondary coordinator, plus the primary coordinator for admission.
  It derives both assignments and the request from the externally pinned
  inventory, checks full inventory peer-role separation and all selected root/
  inventory-parent placement before acquiring owners, then opens existing pins
  before writers and coordinators in immutable assignment-ID order. Partial
  failure releases acquired owners in reverse. Complete-only rejects primary
  roots and neither opens nor requires that coordinator.
  A private wrapper reuses the original runtime gate, wait group, context and
  shutdown ordering; no raw owner or primary maintenance capability escapes.
  Start repeats static content checks, verifies the actual transport-key pin
  and installs only the explicit admit/complete/both handlers. No mode resumes
  work or produces an outcome. Close/cancellation stops new handlers, interrupts
  transport, drains accepted handlers and only then releases every selected
  journal owner. Storage uncertainty stops the service and retains the original
  error/attempt for explicit recovery. The primary service keeps its existing
  public behavior, with a defensive secondary rejection in maintenance paths.
  The separate work-prune-secondary-command-serve-quic CLI validates scope and
  owners before reading its transport seed, shares the signal/SIGPIPE lifetime,
  and reports command-only readiness with both content pins and selected mode.
  Complete rejects even empty primary-root flags. Generic delivery/outbox
  formats remain unchanged. Stop/drain admission, perform separately owned
  offline work, close those owners and reopen complete-only; both is not an
  execution or cancellation surface. Completion can run with primary roots
  absent or held separately. Managed audit/serve, reviewed effect handoff,
  live-journal extraction and physical/cross-host fencing remain open.
  Initial secondary-service verification: seven new store tests passed under
  race/integration in 13.776 seconds. They exercise real initial/lineage replay,
  success/cancellation, typed QUIC outboxes, disabled protocols, missing/busy
  primary completion, key/role/path/pin failures, partial-open cleanup, corrected
  Start, concurrent Close/context cancellation, uncertainty without autoresume,
  and paused-handler ownership through drain. CLI integration unit tests passed
  in 3.587 seconds. A separate process group passed in 3.575 seconds with
  SIGTERM/kill, duplicate owner refusal, stopped-owner offline cancellation,
  completion-only delivery and closed readiness/delivery stdout. Exact cached
  receipts survive restart. These CLI fixtures use no WorkChain; they do not
  claim a remotely exposed archive effect or production storage acceptance.
  Full final make test-race passed across both complementary groups: fresh store
  runs took 249.329 and 357.682 seconds, and fresh cmd/omd runs took 2.320 and
  47.999. Other unchanged packages used valid cached evidence; these are test
  durations, not benchmarks. Full vet and integration-tag store/cmd vet passed.
  CGO-disabled trimpath omd builds passed for macOS arm64, Linux amd64 and
  Windows amd64. Integration-tag store and cmd test binaries compiled for Linux
  and Windows, and native help lists the new command. Formatting/diff checks
  are clean. Cross-compilation establishes no foreign-OS runtime or physical
  acceptance, and the weighted readiness score stays 40/100.
  Combined new CLI unit/process coverage also passed under race/integration in
  28.183 seconds, preserving the original two-minute group bound. The new
  separate CLI process group is added to Makefile without changing older groups
  or timeouts.
  Existing primary command/maintenance CLI process coverage passed in 6.231
  seconds; original runtime/maintenance/recovery process coverage passed in
  28.996, with the same two-minute bounds. A separate full normal suite, all
  other process groups and a standalone fuzz campaign were not rerun this pass.
  Existing fuzz seeds ran in the race gate; no codec or wire format was added.
  Reviewed source-extraction follow-up (2026-10-26):
  ExtractCustodyReceiptLineages now reads a batch of existing journal-only
  checkpoint sources. All external checkpoint/assignment/selected-receipt pins,
  aggregate entry counts and manifest lengths are checked before filesystem
  access. Full cryptographic scope checks precede ownership. Canonical root
  order, disjoint paths and distinct lock inodes avoid duplicate acquisition;
  existing permanent locks remain held together through exact tree/replay
  checks, all winning-body size checks, detached copies and final tree hashes.
  Only canonical sequence-slot winners become entries; valid losing bodies and
  identical rotated copies remain source history. Changed heads, tree layout,
  incomplete bodies or source pins fail without creation, repair or cleanup.
  Context-aware private lock/inventory/replay/retirement helpers preserve the
  old Background entry points and check cancellation between bounded operations
  and streaming chunks. Individual filesystem syncs and bounded signature/
  decoding calls are synchronous. Reverse lock cleanup preserves Close errors
  and no partial result escapes. Valid retired history remains non-active.
  ExtractArchivePruneLineageEvidence derives assignments and selected receipts
  only from the verified lineage inventory, orders the exact source set and
  transfers detached output to the existing opaque evidence value without a
  second full body copy. The envelope, frozen format and evidence ID are
  unchanged; source checkpoint IDs/path mapping must be retained separately.
  Source locks release before later artifact publication. No executor, current
  authority, WorkChain, CLI extraction, signing or execution surface is added.
  Focused normal tests passed: seven workarchive tests in 5.446 seconds and
  three store tests in 5.803. They cover mixed/empty prefixes, rotation and
  losing bodies, scope before filesystem access, source mutations, canonical
  path/lock aliases, aggregate entry preflight, waiting/copy cancellation,
  partial-lock cleanup and all-source ownership against append/rotation or
  retirement-marker publication. The retirement barrier uses a valid tombstone
  under the original lock, not a new end-to-end rebaseline workflow.
  Store roundtrips preserve exact existing evidence bytes/IDs and independent
  owner/database snapshots, then feed separate guarded real pruning. Newly
  extracted history still cannot bypass a completed secondary permission.
  A valid physical 256 MiB threshold/stress fixture was not generated; byte
  preallocation follows reviewed aggregate winning-size checks and existing
  evidence-budget tests. No physical-storage or public-testnet credit is added;
  the weighted readiness estimate remains 40/100.
  Full final make test-race passed in both complementary groups. Fresh store
  runs took 246.045 and 400.663 seconds; workarchive took 12.570 and 232.182;
  cmd/omd took 1.718 and 59.460. New extraction tests ran with race detection
  in the second group. Unchanged packages used valid cached results; these
  durations are test-run evidence, not performance benchmarks. Full vet and
  integration-tag workarchive/store/cmd vet passed. CGO-disabled trimpath omd
  builds passed for macOS arm64, Linux amd64 and Windows amd64. Integration-tag
  workarchive and store test binaries compiled for Linux/Windows. Formatting
  and diff checks are clean. These builds do not establish foreign-OS runtime,
  physical-storage acceptance or production activation.
  Existing journal/retirement process crash coverage passed in 7.220 seconds
  under its original two-minute bound. No new persistent source transition was
  added. Other process groups, a separate full normal suite and a standalone
  fuzz campaign were not rerun; existing fuzz seeds ran in the full race gate.
  Operator lineage-extraction follow-up (2026-10-26): the explicit offline
  work-prune-lineage-extract command now provides review/extract/verify. Review
  and extract read a bounded strict source-path JSON array and existing canonical
  inventory, checkpoint, manifest and initial-receipt files. Every descriptor
  must contain exactly the nine scalar fields; duplicate/unknown/case-changed
  keys, null/wrong types, missing fields, trailing data and cap violations fail.
  Relative source paths are anchored to the metadata parent. Assignments,
  selected receipts and auditor keys come solely from the externally pinned
  lineage inventory. Source sets are exact and ordered by that inventory.
  Placement and aggregate manifest/checkpoint bounds precede owner acquisition;
  actual reads retain the same aggregate budget. The concrete output parent
  must already exist outside every source journal/input file, with final
  symlinks and output/input inode aliases rejected before extraction.
  Review performs real guarded extraction and computes a local digest over
  content pins, canonical inventory/metadata/input/journal/output paths and
  resulting evidence ID. Its stable first result header is followed by readable
  scope JSON with source pins and timing policy. Extract requires the retained
  expected review ID, recomputes it and calls the existing immutable publisher.
  Exact retries keep the original file/inode; changed scope cannot publish under
  an older review. Source locks release before publication or any stdout write.
  Verify requires the independent evidence pin, forbids source/review flags and
  opens only retained inventory/evidence content. Source journals, metadata and
  input artifacts can be offline. It does not repeat publication placement review.
  The original envelope/evidence ID is unchanged; source review pins stay
  separate. The command adds no keys, host, current authority/executor/WorkChain,
  checkpoint capture, repair, automatic recovery or effect surface. Signal and
  SIGPIPE handling reuse the offline command lifetime; failed stdout preserves
  published evidence for explicit verify/retry.
  Initial operator verification: seven new unit tests passed normally with
  integration tags in 2.964 seconds. The new separate-process group passed in
  1.909 seconds, including review/extract/verify, frozen byte/ID compatibility,
  exact same-inode retry, changed source/scope rejection before publication,
  offline original inputs and closed stdout in all three modes. Unit barriers
  additionally cover cancelled partial-lock acquisition and second-write scope
  output failure, including canonical paths with spaces/equal signs. No new
  database/effect fixture or physical maximum-sized campaign is claimed.
  Full final make test-race passed in both complementary groups: changed cmd/omd
  ran in 2.442 and 47.767 seconds. Unchanged store/workarchive and other packages
  used valid cached results from the previous gate. Full vet and integration-tag
  cmd vet passed. CGO-disabled trimpath omd builds passed for macOS arm64, Linux
  amd64 and Windows amd64; native help lists the new command. Durations are test
  evidence, not benchmarks, and cross-compilation does not establish foreign-OS
  runtime or physical-storage acceptance. The weighted readiness stays 40/100.
  Combined new unit/process coverage also passed under race/integration in
  28.528 seconds with the original two-minute group bound. Existing primary
  preparation and secondary-signing process groups passed together in 4.577.
  Integration-tag cmd test binaries compiled for Linux/Windows. The new CLI
  process group is separate in Makefile; older groups/timeouts remain intact.
  A separate full normal suite, other process groups and standalone fuzz
  campaigns were not rerun. Existing codec seed evidence remains in the race
  gate; no evidence or wire encoding was changed. Formatting/diff checks are clean.
  Owned archive-effect follow-up (2026-10-26): the opt-in
  OpenPruneArchiveEffectService now opens the original pinned executor, every
  original coordinator selected by a retained inventory and the exact
  position-pinned WorkChain. Complete pairwise placement validation precedes
  ownership; pins precede writers, coordinators open in assignment-ID order and
  partial failure releases acquired owners in reverse. Replica receipts and
  original tickets are derived only from independently pinned inventory content.
  Initial mode rejects lineage inputs; lineage mode requires a separately pinned
  retained evidence file. Activation state, cumulative-work/timestamp slices,
  root lists and configuration are detached from callers.
  Explicit Review captures confirmed executor, all-authority and storage
  positions under the original guards. Its local comparison ID also binds every
  content pin, canonical input/output path, base/parameters, storage policy and
  archive limits. Execute compares that exact ID under the same all-owner
  guards before archive replay and again after inventory/lineage fences before
  final live authorization. Lost lineage evidence cannot be reconstructed from
  cached bodies; its exact file and parent are rechecked and synced before start.
  The lifecycle mutex retains all owners through the independently confirmed
  result; Close waits for a running effect. No raw handle, network endpoint,
  operator CLI, automatic recovery, Started retry or completion is exposed.
  Command owners must separately drain/close before this service opens.
  New unit tests passed normally with Go 1.26.7 in 24.444 seconds, with an
  additional real partial-open lock/cleanup test passing in 2.447 seconds.
  Initial, mixed-prefix and renewed-lineage fixtures perform real pruning.
  Tests cover placement/pin errors, stale Stop-head reviews, evidence loss even
  after archive replay, pending/Started/terminal rejection, detached inputs,
  eight concurrent Execute callers applying one effect and Close drain.
  Fourteen real process kills across both modes passed in 14.290 seconds.
  Ownership is checked while paused after Review, inventory sync, pending start,
  before/after atomic effect, pending result and returned success. Two subsequent
  runtime/raw reopens preserve exact stages, pending pins, inventory binding,
  database result and every original pending authority ticket without recovery.
  Consensus, wire, signature and retained journal/effect formats are unchanged.
  See PRUNE_EFFECT_RUNTIME.md for the exact lifecycle and recovery boundary.
  Operator command/effect handoff, managed Audit/Serve, remote partitions,
  physical/copy fencing and the parent M5 gate remain open; readiness stays 40/100.
  Full final Go 1.26.7 make test-all passed: formatting, full vet and both
  complementary race groups. Store runs took 235.496 and 501.182 seconds;
  workarchive took 13.786 and 233.653; cmd/omd took 4.139 and 89.359. New
  service unit tests ran in the second race group. These are test durations,
  not performance benchmarks. CGO-disabled trimpath omd builds passed for
  macOS arm64, Linux amd64 and Windows amd64. Cross-builds establish compilation,
  not foreign-OS runtime, physical storage or public-network acceptance.
  The strengthened process group also passed with race detection in 28.895
  seconds, requiring successful service reopen at all fourteen checkpoints
  rather than ignoring open errors. Integration-tag store vet passed and the
  native CGO-disabled binary's help command ran successfully. The new process
  group is included in Makefile with a separate unchanged two-minute bound.
  Other process groups and standalone fuzz campaigns were not rerun this pass;
  existing codec seeds ran in the full race gate. No new decoder was added.
  Supervised effect CLI follow-up (2026-10-26): work-prune-archive-effect now
  defaults to non-executing review and offers explicit control on macOS/Linux.
  The bounded strict root metadata names exactly all original assignments and
  replica directories; externally pinned inventory selects their tickets and
  receipts. Duplicate/unknown/case-changed/null/wrong-type fields, invalid UTF-8,
  noncanonical IDs, count/byte bounds, repeated flags and placement aliases fail.
  Activation configuration is derived from existing canonical genesis/profile
  and the exact legacy activation parent, through a new existing-read-only
  Pebble opener. Missing/empty/LOCKless/incomplete sources are rejected without
  initialization; its Commit is refused before batch work. Source ownership
  closes before the effect runtime opens. One-shot review releases every effect
  owner before any output, and reports that fact explicitly.
  Supervised control adopts inherited dedicated input/output pipes into
  interruptible nonblocking I/O before long-lived effect owners open. Its bounded
  LF commands are review, execute with the exact same-session reported ID, and
  close. No token becomes usable until its complete readable scope is written.
  A separate terminal-error channel lets EOF cancel an in-flight action even
  with a queued command; extra pipelining fails closed. Close drains accepted
  work; signals, channel failures and partial input preserve retained uncertainty.
  The scope displays sorted labelled paths, hex positions, full activation-base
  fields, effective parameters/storage policy and replay limits. Successful
  terminal bytes feed the existing separate reviewed Complete-signing pipeline;
  neither Execute nor restart completes a ticket. Lost stdout after the result
  preserves the independently confirmed atomic effect and blocks blind reruns.
  Unit/control tests passed in 18.797 seconds; final readable-scope assertions
  passed in 5.001. Metadata/config tests passed in 3.685 seconds and 5.759 with
  race detection. A three-second, two-worker metadata fuzz campaign passed
  3,421 executions. New existing-read-only storage tests passed in 1.658 seconds
  and 2.846 with race detection, including sixteen unchanged-tree negative cases.
  Real native CLI process tests cover initial and lineage modes, original command
  service stop/drain/close -> reviewed effect -> command-service reopen, duplicate
  ownership refusal, EOF/SIGTERM/kill, broken readiness and lost result output.
  A full native output pipe is interrupted by Close. Combined unit and process
  coverage passed with race/integration tags in 39.625 seconds. No test claims
  physical power-loss, copied-owner fencing or remote acceptance.
  Full final Go 1.26.7 make test-all passed: formatting, full vet and both
  complementary race groups. Fresh cmd/omd runs took 2.329 and 86.028 seconds;
  storage/pebble took 1.550 and 4.420. Unchanged store/workarchive/simulation
  packages used valid cached gate results. Durations are test evidence, not
  benchmarks. Makefile includes the new metadata fuzz target and a separate
  two-minute CLI process group; existing process groups/timeouts are unchanged.
  Managed Audit/Serve, in-place command-owner transfer, remote partitions and
  independent physical/copy fencing remain open. Weighted readiness stays 40/100.
  Final native process-only coverage passed with race detection in 35.100
  seconds; integration-tag cmd/omd vet passed. CGO-disabled trimpath omd builds
  passed for macOS arm64, Linux amd64 and Windows amd64, and native help lists
  the new command. Integration-tag cmd test binaries compiled for Linux/Windows
  after reclaiming temporary build/cache space. Cross-compilation establishes
  no foreign-OS runtime or physical-storage acceptance. Other process groups
  were not rerun; existing native library crash evidence remains unchanged.
  Managed Serve follow-up (2026-10-26): the opt-in library adapter binds one
  externally signed pending Serve ticket to the exact signed challenge ID and
  independently authenticated auditor peer. It rederives the pinned assignment
  from the original coordinator's retained bootstrap scope and opens only an
  existing active version-0 custody journal; missing, damaged, historical,
  retired or overlapping roots cannot initialize or repair evidence. The
  private session retains detached scope/key configuration. The original
  coordinator and object-store owners remain the caller's responsibility.
  Every call holds the original coordinator guard through fresh signing and
  journal publication, exact cached/recovered delivery, final auditor EOF,
  actual once-only stream Close and cancellation callback drain. Stop/Complete
  wait for accepted calls; Stopping allows a pending admission to drain and
  invalid/completed/retired/uncertain authority rejects before stream input.
  Wrong challenges fail before session/journal locks or any cached response.
  Delivery, failure and restart do not complete tickets or refresh proof time.
  Duplex Audit now acknowledges verified frames with CloseWrite, waits for
  replica EOF, then fully closes. This preserves the existing four-frame
  protocol while avoiding QUIC cancellation of the replica's graceful close;
  finite streams without half-close retain their Close/EOF path. Journal
  decision-close errors suppress constructor/Serve success and cleanup errors
  remain visible. The journal's existing bounded contention wait is retained;
  this does not claim instant cancellation of synchronous filesystem work.
  Real QUIC covers fresh, cached and reconstructed sessions, exact persisted
  responses and refusal after ticket completion. Five process-death checkpoints
  cover construction, first write, final EOF, actual close and returned success.
  Each reopens twice under the same admission, completing an uncommitted original
  exchange or replaying the exact committed response without authority changes.
  Makefile includes the new process group under its own two-minute bound.
  Managed Audit, owned serving runtime/CLI and handler drain, remote partitions,
  independent physical/copy fencing and the parent M5 gate remain open. No message
  encoding, signature, consensus or retained journal format changes. See
  CUSTODY_SERVE_ACCEPTANCE.md for the ownership and recovery contract.
  Targeted Go 1.26.7 managed Serve unit/QUIC/process coverage passed with race
  detection and integration tags in 29.909 seconds. Separate native QUIC and
  five-checkpoint process runs passed in 3.236 and 10.297 seconds. Existing-only
  opening/expected-ID and raw QUIC compatibility tests passed in 1.983 seconds;
  focused duplex-close validation passed in 1.547. These are test durations,
  not benchmarks. Weighted readiness remains 40/100.
  Integration-tag store vet passed. A CGO-disabled trimpath native omd build
  passed and its help command ran successfully. Other process groups, standalone
  fuzz campaigns and foreign-OS builds were not rerun in this pass; existing
  decoder seeds run in the full race gate. No new untrusted decoder was added.
  Full final Go 1.26.7 make test-all passed: formatting, full vet and both
  complementary race groups. Store runs took 235.243 and 496.804 seconds;
  workarchive took 13.454 and 241.593; cmd/omd took 1.701 and 156.093. These
  durations are validation evidence, not performance measurements. The new
  managed Serve and duplex-close unit tests ran in the second race group.
  Managed Audit and server follow-up (2026-10-26): a new fixed 268-byte unsigned
  version-0 intent commits the exact assignment, consumer/auditor keys, replica
  peer, predecessor sequence/head/receipt, nonce, times and samples. Its separate
  domain-hashed ID is retained and admitted before any challenge signature. The
  managed Audit library holds the original coordinator through deterministic
  challenge publication, verified network response, actual stream retirement,
  auditor-journal commit and immutable record/receipt publication. Existing-only
  construction signs and repairs nothing. Explicit recovery requires the exact
  prior+1 committed tuple and current authority/freshness; it does not promote a
  standalone record, search a newer head or refresh request/proof time. An output
  error after journal commit preserves uncertainty and leaves the ticket pending.
  The local Audit/Serve pair acquires the same original coordinator once, checks
  both exact tickets, challenge, distinct transport identities and disjoint
  participant roots, then concurrently runs private sessions. Both streams and
  cancellation callbacks drain before that guard exits. Fresh, cached, fully
  reopened and Stopping calls preserve identical signed records in two separate
  journals. Completed tickets fail before either input; a blocked Close cannot
  prevent the other stream closing or release the owner before both drain.
  A separate owned Serve service opens existing objects/journal/authority,
  validates all manifest objects, explicitly starts pinned QUIC and drains its
  accepted handlers before closing the original coordinator. The new
  work-archive-custody-managed-serve-quic command defaults to review, closing
  owners before readable scope output. Explicit serve adopts interruptible
  macOS/Linux control pipes before owner opening; close/EOF/signal/malformed input
  and failed readiness stop and drain. It requires independently pinned ticket,
  challenge, assignment and peer identities, with separate existing transport
  and proof seed files. Static public checks precede seed reads. No mode admits,
  completes, retires, imports missing objects or initializes missing journals.
  New native tests cover pinned Audit-only and paired real QUIC, exact retries,
  original-owner exclusion, server process restart/kill, EOF/SIGTERM and broken
  readiness. Five real audit-process checkpoints cover constructor, prepared
  challenge, verified transport before append, actual output publication denial
  after journal commit, and returned success. Two subsequent reopens preserve
  exact challenge/result bytes and original authority; uncommitted cycles may
  finish only their original operation. No physical power-loss claim is made.
  Targeted Go 1.26.7 race/integration store coverage passed in 60.987 seconds;
  all five audit process cases passed, including the permission-denial case.
  The separate CLI race/integration group passed in 21.740 seconds. Native
  pinned Audit/paired QUIC tests passed in 3.709 seconds; server process checks
  passed in 4.377. Intent golden/validation passed in 0.647 seconds and a short
  two-worker fuzz campaign completed 508 executions. Test durations are not
  performance benchmarks. Makefile includes the intent fuzz and both new process
  groups under separate two-minute bounds; existing bounds are unchanged.
  Audit operator CLI, owned paired transport lifetime, remote partitions,
  independently enforced physical/copy fencing and the broader launch gates
  remain open. This adds a local preparation format; existing network messages,
  challenge/proof/receipt encodings, journal history and consensus are unchanged.
  See CUSTODY_MANAGED_RUNTIME.md. Weighted readiness remains 40/100.
  The initial full Go 1.26.7 make test-all passed formatting, full vet and both
  race groups: store took 236.211 and 595.566 seconds, workarchive 16.229 and
  257.084, cmd/omd 4.550 and 160.363. The expanded store group finished within
  five seconds of its unchanged ten-minute timeout. The race target now uses
  three disjoint groups: archive tests, remaining tests excluding managed
  custody, and managed custody tests. All tests and decoder seeds remain covered
  exactly once per gate; no timeout is extended or test skipped from coverage.
  Integration-tag cmd/omd and store vet passed. A native omd build and its help
  command passed, including the new managed Serve command. Other process groups
  and foreign-OS builds were not rerun; the only standalone fuzz campaign this
  pass targeted the new intent decoder.
  Final Go 1.26.7 make test-all passed the three-group gate: formatting, full
  vet, cached valid archive results, the remaining group and managed custody.
  Fresh remaining runs took 464.045 seconds for store, 232.592 for workarchive
  and 145.529 for cmd/omd. The separate managed group took 91.889 seconds for
  store and 16.626 for cmd/omd. These are test durations, not benchmarks. The
  unchanged ten-minute bounds now retain headroom while preserving all standard
  test/subtest coverage and fuzz seeds. Integration process gates remain separate.
  Operator Audit/paired follow-up (2026-10-27): three explicit commands now
  review/publish/verify the unsigned intent, supervise owned Audit actions and
  control an owned local paired QUIC exchange. Intent fields and nonce source
  are fixed before publication, which requires the independently retained ID;
  neither review nor publish invents time/randomness, signs or admits anything.
  Reports omit raw nonce and private seed bytes. Exact publication retry and
  native output cancellation preserve retained bytes for separate verification.
  Audit control requires a fully reported same-session scope before prepare,
  recover or pinned network Audit. The token is consumed per action. The local
  comparison commits canonical original paths, externally pinned scope/peers,
  effective limits and confirmed authority/journal positions; route/listen
  options additionally enter the CLI scope. Current comparison occurs under
  the original guard before effects. Default review starts no listener, signs
  nothing and closes owners before output. Missing data never initializes.
  The paired runtime privately owns one original coordinator and both existing
  participants. An exchange creates two authenticated hosts, checks its review
  before transport setup and again under the joint guard before application I/O,
  then drains both hosts/streams/callbacks before owner release. The gate prevents
  callback Add after shutdown starts waiting. Active Close cancels admitted work;
  cleanup errors remain available from repeated Close. Scope/token/transport
  observations never become reusable current-authority grants.
  Native CLI processes exercise Audit prepare -> pinned exchange -> kill -> exact
  offline recovery, paired fresh/repeated/reopened exchange, owner exclusion,
  EOF/SIGTERM, partial control, another session's unreported token and lost stdout
  after both journal commits. The next reviewed exchange preserves those original
  proof/renewal IDs and journal heads without automatic authority completion.
  Root process coverage passed in 8.772 seconds without race detection. The final
  combined CLI unit/process group passed with race/integration tags in 64.144
  seconds. Core runtime/comparison tests passed with race detection in 18.166
  seconds; independent runtime coverage also passed in 16.275. These are test
  durations, not benchmarks. Makefile includes a separate two-minute operator
  process group; existing timeouts and the three disjoint standard race groups
  are unchanged. No new network, consensus or retained intent/receipt/journal
  encoding is introduced, and no new untrusted binary decoder requires fuzzing.
  Reviewed Audit/Serve admission and terminal tooling, remote partitions,
  physical/copy fencing and the broader launch evidence remain open. Existing
  local process/QUIC coverage adds no independent-audit or testnet-duration credit.
  See CUSTODY_OPERATOR_CLI.md. Weighted production readiness remains 40/100.
  Full final Go 1.26.7 make test-all passed: formatting, full vet and all three
  disjoint race groups. Fresh store runs took 240.645 seconds for archive,
  427.208 for remaining and 129.506 for managed custody. Corresponding cmd/omd
  runs took 1.723, 114.225 and 92.044 seconds. Unchanged workarchive/simulation
  packages used valid cached results. Durations are validation evidence, not
  benchmarks. Integration-tag cmd/omd and store vet passed. A native omd build
  and help command passed with all three new operator commands listed; no foreign
  runtime/build or independent physical/public-network evidence is claimed.
  Reviewed custody ticket follow-up (2026-10-27): four explicit commands now
  prepare consumer signatures, authority co-signatures, terminal capture and
  local application of Audit/Serve Admit/Complete. Static signing takes fixed
  sequence/head and independently pinned inputs; it opens no authority owner,
  reads no seed during review and reuses exact published signatures before a
  seed read. The existing signature domains and authority codecs are unchanged.
  Owned application retains one original coordinator and an active existing
  journal decision through append and independent confirmation. Open/Review
  never resume; Apply rejects every retained pending attempt, and separately
  reviewed Resume requires the exact retained entry and current source.

  A bounded canonical version-0 terminal envelope commits the selected signed
  admission, retained intent and full committed journal entry. Its ID becomes
  Complete EvidenceID. Capture requires the original pending ticket and exact
  immediate-result CURRENT head, retaining both guards through no-replace
  publication and sync. Historical verification preserves original RespondedAt.
  Advanced journals are rejected rather than searched for an older result.
  Audit and Serve close independently; exact confirmed retries preserve EntryID
  with Appended=false while Snapshot reports current authority, including later
  independent commands. Admit retries still require the original predecessor;
  Complete retries require the selected terminal at the current source head.

  A real-process CLI workflow begins at a newly bootstrapped position zero,
  reviews/signs/co-signs/applies Audit Admit, prepares its signed challenge,
  admits Serve, performs the owned paired QUIC exchange, captures both terminals,
  and independently completes Audit then Serve. It retries the first Complete
  after the second closes without appending. A separate real closed-output test
  verifies that a lost result retains the admission for exact reviewed retry.
  Eight real process kills cover Audit/Serve Admit/Complete after durable intent
  and after authority write before confirmation. Double read-only reopen retains
  both observed and confirmed positions; stale tokens and normal Apply fail,
  while a fresh explicit Resume confirms only the exact retained entry. Source
  decisions block competing access through the boundary and permanent ownership
  lock inodes survive process death. The focused non-race process run passed in
  9.641 seconds. This is process-death evidence, not physical power-loss coverage.
  The new terminal codec has a fixed canonical golden and decoder fuzz target;
  no consensus, network, receipt or journal format changes. The first local
  current-head ticket tooling slice is complete. Remote/partition enforcement,
  independent physical/copy fencing, independent audit and public-testnet duration
  remain launch gates. See CUSTODY_TICKET_WORKFLOW.md. Readiness remains 40/100.
  Final placement review replaced string-only overlap checks with existing inode
  ancestry checks, including case-insensitive macOS aliases. Regressions verify
  rejected metadata/capture placement leaves protected roots unchanged. Exact
  retained signing retries now compare and sync before allocating any temporary
  file; both role signatures can be reused with deleted seeds and a non-writable
  output directory. This does not claim physical device-exhaustion coverage.
  Final Go 1.26.7 CLI unit/process coverage passed with race/integration tags in
  54.442 seconds; focused evidence/owned-service/process coverage passed in
  72.858 seconds. Terminal decoder fuzzing passed 2,506 executions in its bounded
  three-second run. Full make test-all passed formatting, full vet and all three
  disjoint race groups, with no timeout changes. Store runs took 238.516, 484.634
  and 164.742 seconds; corresponding cmd/omd runs took 3.505, 171.055 and 89.583.
  These are validation durations, not benchmarks. Integration-tag vet for cmd/omd
  and store passed. A native trimmed-path build and help command passed with all
  four new commands listed. No foreign-runtime, independent-audit, public-network
  or physical-media acceptance is claimed.
  Two-host acceptance follow-up (2026-10-27): the production artifact from
  651cccf and one integration artifact were SHA256-pinned identically on two
  provided Linux x86-64 VPS instances (Ubuntu 22.04.5/24.04). Fresh role fixtures
  use different authority keys, consumers, assignment IDs and original local
  coordinators. Bootstrap happens once at destination; no active authority root
  or live ledger is copied. Five actual WAN custody scenarios passed: healthy
  exchange (36.711 seconds), full packet loss before the request (43.815), loss
  after B's durable journal commit plus B process kill (48.833), every-seventh
  packet loss with 40ms directional delay (42.846), and refusal after the original
  120-second proof age (144.792). These are test durations, not performance data.
  The post-commit gate is integration-only and pauses the first application
  response Write under B's original owner. After partition/kill, A remains at
  journal 0 and B at 1; a valid retry preserves B's exact head/proof/RespondedAt.
  Successful cases explicitly complete each local ticket and preserve an exact
  completion retry. The expired case deliberately leaves both tickets pending
  and unchanged, with no replacement proof or completion. Offline Recover passed
  after the replica and the relay route were both stopped.

  The ordinary v0 devnet also passed direct two-host QUIC sync, two actual server
  process kills, failure without client-history change, restart healing, and
  independent mining from one height-3 parent to distinct height-5/7 branches.
  Healing selected B's greater-work height-7 tip; full replay on both hosts
  agreed on tip/state/work/resources. The two losing A blocks remain retained,
  so history-byte totals correctly differ. Repeated sync after restart leaves
  both histories unchanged. This separate development-chain run took 46.253
  seconds and makes no monetary-value or production-throughput claim.

  Harness bring-up caught incomplete declared purpose coverage in the test
  fixture and macOS AppleDouble sidecars in platform-tar output. The fixture now
  declares the reference assignment's required coverage while admitting only
  Audit/Serve, and Python-generated archives preserve actual paths/bytes without
  sidecars. A bounded bulk review-frame RPC replaces per-line WAN round trips;
  partial frames cancel the child and never submit an action. Core validation,
  proof-age limits and protocol timeouts were not relaxed. Sixteen Python
  support/controller regressions pass. Gated loopback/control tests pass with
  macOS race detection (13.281 seconds) and natively on Linux; integration vet
  passes. Full Go 1.26.7 make test-all passes formatting, full vet and all three
  disjoint race groups with valid cached unchanged production results. Both
  servers were checked for remaining task children and test UDP listeners: none
  remained. No firewall/routing/tc or unrelated-service changes were made.
  See REMOTE_ACCEPTANCE.md and evidence/remote-acceptance-20261027.json for public
  source/artifact/state commitments. Deployment details, credentials, seeds and
  raw reports are excluded from the repository. This closes measured cross-host
  transport/recovery acceptance for independent local assignments; it does not
  close single-assignment distributed current authority, physical/copy fencing,
  independent review or sustained adversarial testnet duration. Readiness stays
  40/100.
  Remote authority foundation follow-up (2026-10-27): a new explicitly selected
  V1 assignment commits distinct B control/transport identities without changing
  the replica receipt/proof key. V0 canonical encodings and domains are unchanged;
  old binaries reject V1 even at sequence zero. Legacy reviewed signing,
  admission/completion intents, outboxes and wire requests refuse V1 rather than
  enabling an unimplemented remote runtime. The archive-facing constructor
  creates a detached fresh scope; it does not transfer or migrate an owner.
  RemoteBegin commits the exact pending Serve ticket, challenge and plan in the
  reference state. Its unresolved hold blocks all other new transitions and
  local effect callbacks through raw Store, Coordinator, replay and explicit
  uncertain-attempt recovery. Only the exact B-signed/authority-co-signed
  RemoteDrained clears the hold; retained remote history permanently prevents
  generic live Serve reuse. Neither transition completes any ticket. Replay
  retains space for Begin/Drained plus ordinary admission/completion and Stop/Retire.
  A separate bounded remoteworker journal pins the immutable plan and co-signed
  Begin proposal. Its Start/Sealing/Sealed methods are record-only: no network,
  signer, callback or execution grant is supplied. Sealing is irreversible even
  before its confirmation; Open preserves pending records without auto-confirm,
  repair or effect replay. Exact explicit retry settles only the same bytes. A sealed
  unseen branch rejects delayed Start forever, and a started NoResult means
  unknown outcome rather than proof of no effect or successful custody.
  Targeted integration/race checks pass for the reference state, raw/coordinated
  store, worker journal, archive-facing constructor and delivery packages. The
  store suite kills the original process at twelve Begin/Drained publication
  boundaries; a separate worker process is killed after unconfirmed Sealing.
  The joined original-owner/worker tests cover unseen delayed Start and started
  unknown outcomes, independent reopen of both journals, exact unsigned drain
  preparation, retained pending tickets and unchanged custody journals. Positive
  canonical fuzzing completed 297,170 authority and 228,501 worker executions;
  stable V1 assignment/history and worker plan/seal vectors are recorded.
  Final Go 1.26.7 make test-all passes formatting, full vet and all three
  disjoint race groups; store groups took 233.966, 491.132 and 146.017 seconds.
  Integration-tag vet for the authority packages and archive also passes.
  Native Linux verification found an unlink/recreate fixture that could reuse
  the original inode immediately. Retaining the original file outside the
  journal makes the replacement deterministic; production journal code is
  unchanged. The corrected worker integration/race suite passes (3.223 seconds),
  and full make test-all passes again with fresh worker results and valid cached
  unchanged packages. The six-package native Linux/amd64 integration suite also
  passes (7.603 seconds) using Go 1.26.7 and CGO_ENABLED=0 without downloads.
  Final 582-file Go source manifest matches across macOS and Linux; see the
  foundation guide. A root-only permission-removal test explicitly skips when
  UID 0 retains write access; it is not credited as physical write denial.
  See REMOTE_AUTHORITY_FOUNDATION.md. An owned authenticated Start after A's
  durable confirmation, actual B signing/handler drain, typed remote terminal
  validation and same-assignment WAN fault/soak acceptance remain open. These
  local foundations do not supply physical/copy fencing or independent audit;
  weighted readiness stays 40/100.
  Managed remote execution follow-up (2026-10-27): the opt-in V1 library now
  retains the original A coordinator through confirmed Begin, authenticated
  Start and exact remote Audit. B owns only its separate worker journal, original
  custody journal, object source and replica/control keys. A control and Audit
  transports are separate pinned roles; no A authority root or proof key is
  moved between participants. The 4-KiB bounded metadata protocol has separate
  stream/rate/memory budgets, canonical framing, complete EOF and no body import.
  B confirms Started before enabling one same-runtime fresh attempt. Reopened
  Started enables only an exact committed cached response, never fresh signing
  when the original result is missing. Seal durably freezes new data admission
  before cancellation and complete handler drain, then commits its immutable
  disposition before signing. Reconcile only reads confirmed state. Close retains
  a sealed/uncertain branch and drains both handler groups before owner release.
  The new RemoteCustodyTerminal commits B's signed seal/drain and the exact
  matching response accepted in A's PRIVATE original journal. Capture checks
  that source under its decision; both independent completions hold the same
  source decision through authority append and confirmation. The runtime rejects
  same-byte live source-directory/lock replacement.
  Unknown/unseen drains or a B result that A rejected as expired cannot produce
  successful terminals. Explicit pending Begin/Drain/Complete recovery confirms
  only the same bytes; exact historical Complete retries remain lookups after
  the other ticket closes, preserving original response time.
  The first full focused normal run exposed a QUIC cancellation cleanup race:
  after A rejected an expired proof, B's graceful Close could return a cancelled
  stream error and block Seal. The private stream now explicitly resets when
  graceful close fails, clearing cleanup failure only if actual Reset succeeds;
  handler drain remains mandatory. Three deterministic expiry/cleanup repeats
  pass. The coordinated integration/race suite passes (store 76.302 seconds,
  control wire 4.313, transport 3.996), including both real B SIGKILL boundaries
  and A owner reopen. Full transport/wire race also passes; native control and
  terminal fuzz smoke pass. The terminal golden is 3,809 bytes with a fixed ID.
  The same frozen suite passes natively on Linux/amd64, Go 1.26.7, CGO_ENABLED=0,
  offline dependencies and read-only modules (store 23.051 seconds, wire 0.374,
  transport 0.663). The 597-file Go source manifest matches before/after; all 39
  recorded task processes are gone and the temporary SSH master is closed.
  This is one-host native process acceptance, not same-assignment WAN evidence.
  Final Go 1.26.7 make test-all passes formatting, full vet and all three
  disjoint race groups; the store groups took 221.172, 493.024 and 151.868
  seconds. Integration-tag vet also passes. No timeout extension was used.
  See REMOTE_CUSTODY_EXECUTION.md for exact ownership, recovery and remaining
  CLI/WAN/physical-fencing boundaries. No independent audit, sustained testnet
  or parent production gate credit is added; readiness stays 40/100.
  Operator/server follow-up (2026-10-27): separate V1 A/B commands now default to
  non-executing review and require explicit supervised control over dedicated
  native pipes. B default inspection closes only the unused owner without
  sealing, while live control shutdown retains sealed/uncertain state and drains
  handlers. Both commands reject cross-role roots/keys and verify public pins
  before reading seeds. A complete displayed review binds paths, selected IDs,
  route, limits and observed authority/source positions; the one-use local token
  is consumed before action, with base-state comparison under the original owner.
  Durable normalized drain artifacts remove only the per-exchange nonce; their
  signed seal/command remains exact. Terminal publication holds the original
  source decision and authority through no-replace link plus durability checks.
  Historical Reconcile can recover lost Drain publication after confirmation,
  but never Start, sign, apply or implicitly resume an authority entry. Separate
  CLI processes prove broken-output recovery to the same artifact, explicit
  EOF/malformed-control shutdown, independent completions and exact recovery.
  Tagged race checks pass (cmd/omd 33.884 seconds, store 82.984). Native Linux,
  Go 1.26.7 with CGO_ENABLED=0 and offline modules also passes (cmd/omd 4.782,
  store 1.659 seconds; 22.917 seconds including orchestration/build). The exact
  603-file Go manifest matches before/after; no native task-group children remain.
  See REMOTE_CUSTODY_OPERATOR.md. V1 bootstrap/offline signing, same-assignment
  WAN/soak, negative dispositions and independent physical/copy fencing remain.
  The readiness accounting was reassessed separately: 43/100 now credits two
  previously omitted implemented criteria (owned local Audit/Serve: +2; fixed-
  session remote authority/execution/result validation: +1). This pass's CLI
  earns no automatic additional point; temporal/audit/physical gates stay open.
  Final Go 1.26.7 make test-all passes formatting, full vet and all three
  disjoint race groups (store 218.879, 531.899 and 148.600 seconds); integration
  vet passes too. No timeout extensions were used.
  V1 offline-preparation follow-up (2026-10-27): distinct commands now derive and
  immutably publish a V1 assignment and fixed session plan; review/create/verify
  fresh authority/pin and B-worker roots; and independently review/sign/co-sign
  Audit/Serve admissions, B Begin proposals and typed successful completions.
  Ordinary V1 signing uses the existing V1 signature domains and strict role/
  position checks through new APIs; V0 helpers and commands still reject V1.
  Complete requires the full selected terminal, original intent and exact ticket.
  Offline Drained signing is unavailable. Public scope is checked before seeds;
  exact existing output is verified and re-synced before seed access, preserving
  lost-output retry even when the key is unavailable. Bootstrap reviews bind
  canonical placement and session, create never resets existing roots, and B
  verify leaves a Started worker unsealed. Actual subprocesses exercise signing,
  co-signing, seed-free retry and fresh A roots. The real-QUIC CLI test now obtains
  both independent Complete entries through these commands. Focused integration/
  race checks pass (cmd/omd 25.331 seconds, authority 2.666, store 3.290).
  Native Linux/amd64 Go 1.26.7 with CGO_ENABLED=0 and offline/read-only modules
  passes the same selection including actual subprocesses (cmd/omd 3.738 seconds,
  authority 0.012, store 0.468). The exact 611-file Go manifest matches before/
  after; no task-group children remain and the temporary SSH master is closed.
  Final Go 1.26.7 make test-all passes formatting, full vet and all three
  disjoint race groups (store 220.276, 508.010 and 170.233 seconds), without a
  timeout extension. The pinned Go source manifest remains unchanged.
  Integration-tag vet passes as well.
  See REMOTE_CUSTODY_OFFLINE.md. Initial source-journal preparation and original-
  source guarded admission/challenge preparation before Plan/Begin remain SDK
  work; a full position-zero CLI-only workflow and same-assignment WAN acceptance
  remain open. This slice adds no weighted readiness point; the baseline is 43/100.
  Position-zero CLI follow-up (2026-10-27): a distinct source command now reviews,
  exclusively creates or verifies A/B source journals and A's artifact root.
  Existing/partial roots are never reinitialized; both A destinations are checked
  before creation, and uncertain failures retain their files. The source format
  stays V0. A separate V1 admission service checks the complete pinned intent/
  archive and original source before applying or explicitly resuming the exact
  signed admission, without widening the V0 constructor. The pre-Begin challenge
  service requires a confirmed pending Audit and holds original authority,
  artifact lock and source decision through deterministic publication, checking
  source/root/lock identities before and after. Default review uses no seed and
  signs nothing; managed controls include a fresh process nonce and consume each
  displayed comparison before action. Native CLI processes now create every V1
  session artifact/root/admission from zero, execute real QUIC, capture the same
  original-A result and independently sign/apply both completions. Lost first-
  admission output reopens to the exact same entry; final CLI inspection confirms
  sequence six, zero pending operations and no active remote obligation.
  Tests also cover exact pending Resume, active Begin refusal, wrong evidence
  key, replaced original artifacts, no-create inspection, source preflight and
  lost challenge output. A race in the new test observer was fixed with a
  pre-created channel; corrected focused integration/race tests, including the
  unchanged V0 process lifecycle, pass (cmd/omd 121.673 seconds, workarchive 3.769,
  store 9.954). Native Linux/amd64 Go 1.26.7 with CGO_ENABLED=0 and offline/read-only
  modules passes the same selection (cmd/omd 7.777 seconds, workarchive 0.128,
  store 1.625). Its exact 619-file source manifest matches before and after; no
  task-group children remain and the temporary SSH master is closed.
  See REMOTE_CUSTODY_BOOTSTRAP.md. Same-assignment
  WAN fault/soak, negative dispositions and independent copy fencing stay open;
  weighted production readiness remains approximately 43/100.
  Full-gate observation: the former combined race group hit its ten-minute
  package limit at a remote test that had run for one second, after Archive,
  formatting and vet had passed. The race target was split into five disjoint
  exhaustive groups (Archive, Prune, remaining, ManagedCustody, Remote), keeping
  the default timeout and every test. This is a test partition change, not a
  product-code or deadline relaxation.
  The partitioned Go 1.26.7 make test-all passes formatting, full vet and all five
  race groups: the unchanged Archive result was reused (prior store 266.936
  seconds), and fresh store groups took 323.574, 190.212, 154.074 and 79.510.
  Integration-tag vet passes; the 619-file Go source pin is unchanged.
  Same-assignment WAN follow-up (2026-10-27): eleven V1 scenarios passed on two
  explicitly selected Linux hosts with different observed kernel-boot hashes.
  Each independent scenario creates its assignment and all original roots via
  CLI; A retains the sole authority/pins, while B owns its separate worker/source
  and separate control/transport/evidence keys. No live owner or journal is copied.
  Ten individual scenarios cover healthy delivery, partition-before, packet
  loss/delay, A death before/after accepted data, B death before/after committed
  data, a lost sealed reply, expired B-only cache and Unseen seal. Private native
  B pause helpers isolate actual effect boundaries; killed helpers are replaced
  by the normal CLI server on the same retained worker. A sealed-reply error hook
  is private and unset in normal operation. The new race test retains A's active
  hold after a lost reply and recovers the exact same seal on explicit retry.
  Metadata-only Reconcile does not confirm A's Drain. Restart after Started
  without cache refuses fresh signing; committed-cache recovery preserves its
  original proof ID and RespondedAt. Expired/unseen/unknown branches reject
  successful capture and keep both ordinary tickets pending. Every completed
  cycle also sends the old Start through an authenticated live B connection and
  requires refusal without accepting a transport timeout as proof.
  The bounded reuse series completes 32 sequential cycles with one assignment,
  unchanged original source/authority/artifact roots and locks, and loss/delay
  every fourth cycle. Final A authority sequence is 192, both source sequences
  are 32, pending operations are zero and no remote hold remains. Across the
  campaign, 42 cycles completed; 39 successful cycles independently completed
  two tickets, while three negative scenarios preserved their ordinary tickets.
  The reporter checks retained state, original identities, distinct operation/
  result IDs, relay counters and common source/binary/controller pins rather
  than trusting passed flags. Raw role/config/seed/log/report files remain private;
  docs/evidence/remote-custody-wan-20261027.json is a sanitized digest-bound index.
  Initial rehearsals correctly refused a role root before its first admission
  because Python's archive data filter dropped private directory modes. The
  controller now restores 0700/0600 extraction modes and creates private logs;
  the regression check passes, and original root validation was not weakened.
  Native Linux/amd64 Go 1.26.7 builds used CGO_ENABLED=0, offline/read-only
  modules and two build workers (92.161 seconds). The exact 620-file Go/module
  source manifest remains unchanged. Go 1.26.7 make test-all passes formatting,
  full vet and all five disjoint race groups (store 239.156, 293.799, 151.987,
  151.863 and 80.388 seconds). Integration-tag vet, focused seal-reply race/native
  process checks and 25 Python supervisor/controller/reporter tests pass.
  Task processes and test UDP listeners are absent after cleanup, and both
  temporary SSH masters are closed. Earlier failed workspaces remain retained.
  See REMOTE_CUSTODY_WAN.md and the next REMOTE_CUSTODY_NEGATIVE_PLAN.md. This
  closes the reserved V1 operator/WAN criterion: storage/lifecycle credit rises
  from 11 to 12 of 15 and total readiness from 43 to approximately 44/100.
  Negative-disposition closure, independent key/root copy fencing, device-failure
  campaigns, external audits and sustained public-testnet gates remain open.
  Process-gate observation (2026-09-07): the first combined run stopped at
  `TestProcessTieCampaignStorageFailuresRecoverWithoutFalseAdvance/observer_confirmation_after_link`
  because the expected confirmation marker was absent. Five isolated repetitions
  passed. The failing assertion now includes both peers' output/errors, and the
  timeout helper waits for process exit and output drain before exposing buffers.
  At that point the cause was unestablished, so passing retries did not close it.
  Publication follow-up (2026-09-07): repeating the case under concurrent store
  crash-test load reproduced it. The newly retained peer logs showed observer
  `ErrCampaignState` before any connection, followed by coordinator dial timeout:
  it never reached the intended confirmation boundary. The fixture used direct
  `os.WriteFile` on the watched `.published` path, exposing an empty file between
  creation and writing. A deterministic split-create/write test reproduces that
  rejection in both readers. Fixtures now use `PublishCampaignCheckpoint`:
  validate independently supplied plan/checkpoint pins and signed context, sync
  and no-replace-publish the complete checkpoint, then do the same for the marker.
  The separate `work-telemetry-tie-campaign-publish` operator command exposes this
  protocol without private keys, chain execution or automatic coordinator approval.
  Tests inspect visibility at all ten file boundaries, interrupt and retry each,
  reject invalid pins before writes, preserve malformed/conflicting existing files,
  and exercise 16 concurrent exact publishers plus a conflicting link winner.
  Fifteen post-link process repetitions passed alongside 142 race-enabled pinned
  executor crash cases; five further post-link repetitions passed with race
  detection. Repository-wide tests/race/vet and the complete process gate passed,
  including all 271 authority/executor crash cases. Integration test binaries
  built for Linux and Windows; execution was verified on macOS only. This closes
  the reproduced publication race, not arbitrary future transport failures,
  independent-review enforcement or power-loss safety.
  QUIC follow-up (2026-09-06): the first combined process run failed in
  `TestProcessTiePairQUICReachesIndependentV2ObserversAndRecoversAck` with a
  remote QUIC close, and in the coordinator-journal-before-rename case of
  `TestProcessTieCampaignStorageFailuresRecoverWithoutFalseAdvance` with a
  slot-deadline error after a transport close. Investigation isolated an early
  host-shutdown race: both observer commands could exit after buffering the
  final ACK, before the coordinator read it. A new process regression fails
  against that old behavior in both modes. Receivers now wait for coordinator
  EOF before shutdown/slot handoff; coordinators half-close only after validating
  the final ACK and use a bounded terminal drain. Unit coverage checks EOF,
  trailing bytes, cancellation, deadlines, and post-ACK transport closure.
  A second issue mislabeled any nested transport timeout as signed-slot expiry;
  the driver now checks the campaign clock, preserving the pending delivery
  phase without a skip or local advance. These fixes change no wire encoding,
  signed slot, sibling ordering, or confirmation-file format. Broader network
  fault/long-soak and crash-after-confirmation reconciliation gates remain.
  A later full-process run exposed a separate between-slot readiness race in
  the two-observer restart campaign. While an observer waited for the next
  published checkpoint, a new request could reach the retired slot's handler,
  reset, and exhaust the default two-stream fixed-window allowance on retry.
  Campaign receivers now install one authenticated dispatcher before readiness
  output and wait at most 30 seconds for a slot handler. The old binding is
  retired before its completed stream closes; delayed cleanup cannot retire a
  successor. No payload is read or admitted during the wait. Existing identity,
  stream/rate, publication, slot-time, and signed role-order checks remain.
  The delayed-second-slot process regression fails on the former dispatch order
  and passes repeatedly after the fix, without reconnecting the delayed observer.
  This is fresh retrievability evidence from a trusted replica key, not proof of
  physical storage, non-proxying, independent operation, or consensus finality.
- an isolated activation router now owns strict v0/v1 block admission. It
  dispatches unchanged canonical encodings from their leading version, permits
  v0 only below `H` and v1 only from `H`, and lazily creates one WorkChain tree
  for every known v0 parent at `H-1`. Global fork choice compares their best
  tips by cumulative hard work; exact v1 ties preserve the persisted local
  incumbent while strictly more work reorganizes it. This replaces a globally
  grindable ID rule without changing v0 compatibility. The executable boundary
  fixture preserves a cross-base tie across restart, then reorganizes through
  a different v0 base with more work. Both validators consume one explicit
  admission-time sample, and routed/selection decoders are fuzz targets.
- strict block/header version dispatch now lives in consensus-pure
  `core/chainblock`, shared by the activation router and an inactive chain wire
  codec. Appended `VersionedBlock` and `VersionedHeaders` envelopes preserve the
  unchanged inner encodings; a 128-header batch can cross v0→v1 but cannot
  reverse version or break parent/height continuity. The active reader retains
  its 8 MiB ceiling, while the isolated versioned session explicitly opts into
  the larger WorkGraph-block ceiling before allocation. Union and frame decoders
  are fuzzed.
- the inactive chain-control grammar now adds `ChainHello`, distinct versioned
  block/header locator requests, and a versioned batch terminator. Negotiation
  requires exact network, genesis, and activation-height agreement plus the
  `versioned_sync_v1` capability, then intersects the advertised frame ceilings.
  Locator count, uniqueness, and batch bounds remain unchanged. A golden hello
  frame fixes the encoding; the active v0 session still cannot negotiate these
  types.
- an isolated router-backed versioned chain session now performs header-first
  sync across the activation boundary. It applies the negotiated frame ceiling
  to reads and writes, checks both versions' ancestry/MTP/target/future-time/PoW
  rules before bodies, requires byte-identical body headers, and replays through
  the activation router. Continuation locators make progress along a losing
  downloaded side branch instead of repeating its prefix. A two-block-batch
  fixture crosses v0→v1 through a different activation base: batch one remains
  below the local tip, later batches win and reorg. Final ID, height, state root,
  and cumulative work are bound back to `ChainHello`; a lying work advertisement
  is rejected after replay.
- the libp2p adapter now carries that session under the distinct opt-in
  `/outcomemesh/chain/1` protocol without fallback to `/outcomemesh/session/0`.
  Default hosts and ordinary v0 CLI commands do not install its handler; the
  explicit `work-serve-quic` command now does. A real two-host QUIC fixture pins
  peer identity and synchronizes a divergent activation fork with a negotiated
  1 KiB ceiling. Its independent scopes default to one
  concurrent stream per peer/four globally and four admitted streams per
  peer/128 globally per minute; tests exhaust every scope while proving a held
  versioned stream does not consume the v0 session allowance.
- the activation router now optionally persists all v1 trees as a catalog-free
  forest: one schema-1 root manifest and one base-hash directory per independently
  verified schema-4 WorkChain database. Reopen resolves each base against the
  v0 ledger, rebuilds block ownership only after full tree verification, and
  recomputes the global hard-work tip. A 64-tree default cap (hard maximum
  1,024) and static partitions of one forest-wide history budget bound aggregate
  storage without cross-database transactions. Real Pebble restart tests recover
  two activation bases, extend the recovered losing branch through a reorg, and
  recover it again. Empty crash-boundary directories are safe; pending/corrupt
  manifests, unknown or swapped bases, reduced budgets, and excess trees fail
  closed.
- `omd work-enable` now creates a fixed-size immutable activation profile only
  after exact genesis confirmation, target/reward compatibility checks, a
  future boundary, and forest validation. Final or pending markers block every
  ordinary command that could mutate or report stale v0-only state. Separate
  `work-mine/mine-quic/status/balance/verify/serve-quic/sync-quic` commands cross
  the boundary without changing v0 defaults. A real multi-process Pebble fixture
  enables three nodes, mines height 1 as v0 and heights 2–5 as v1, authenticates
  and synchronizes `/outcomemesh/chain/1`, replay-verifies the mixed ancestry,
  rejects legacy mining, and reopens the same receiver tips after shutdown.
- the explicit v1 CLI miner now uses the bounded WorkGraph pool and unified
  weak-share/hard-anchor nonce loop. Locally admitted shares form deterministic
  parent tips, are committed in canonical topological order by the hard seal,
  and become delayed rewards during the following transition. Mining output
  exposes discovered, included, and capacity-rejected share counts.
- `node/workround` now binds one prepared payload to its bounded pool, unified
  miner, hard-solution finalizer, and finite share session. Its manager caches
  at most one best-parent round, bounds rebuilds during chain churn, and drops
  the whole pool on parent change. `work-serve-quic` installs the independently
  scoped WorkGraph handler as well as chain-v1. The process fixture now relays
  and fully admits two weak shares after mixed-chain synchronization; default
  hosts remain unable to negotiate the protocol.
- `work-mine-quic` now publishes locally admitted weak shares to as many as
  eight explicit authenticated peers while mining the hard anchor, accepts
  reciprocal round shares, and serves chain-v1. Each peer has an independent
  8,192-ID queue and worker; the hash-loop callback only enqueues, so slow or
  incompatible peers cannot block healthy relay or hard work. A
  selected-inventory API checks local ownership and reports the exact negotiated
  prefix, allowing each queue to retain only its unsent suffix.
- relay workers now race the 128-share threshold against a mandatory partial
  flush (eight seconds by default). The topology/reward corpus reproduces the
  batch-only small-miner penalty at 10% hash share (73,611 ppm versus 104,349
  ppm with immediate relay) and restores it to 102,033 ppm with the timed flush.
- successful first admission of a remote share now feeds the same bounded
  publisher, excluding its authenticated source. Pool deduplication prevents
  repeated fanout, exact-context round control buffers the publisher handoff,
  and a two-hop fixture proves the middle node can serve the admitted body to a
  third node. The mining callback and admission observer remain network-free.
- `work-mine-quic --auto-peers` can fill the same eight-slot target set from
  fresh signed local peerbook records. It requires an age-checked operator ASN
  table, reuses reputation/latency/backoff ranking, separates bounded attempt
  and success targets, and admits a peer only after an inventory-free WorkGraph
  exact-context probe. Reputation persists across runs; selector integration
  tests reject a higher-ranked incompatible peer and stop after the requested
  compatible count.
- signed peer-record version 1 binds the activation height and chain/WorkGraph/
  notify/exchange capability mask under a new Ed25519 domain while preserving
  version-0 decoding. Chain-v1 negotiates peer exchange explicitly, serves only
  exact-activation records, admits each response atomically, and caps requests.
  Work servers renew their own record every 30 minutes; cooperative miners use
  explicit and signed bootstrap peers to refresh/persist the book before ASN-
  ranked selection, then confirm every WorkGraph claim with the existing live
  inventory-free probe. The process fixture covers compatible refresh plus a
  fail-closed authenticated legacy peer;
- long-lived cooperative miners repeat bounded refresh through their selected
  peers every 30 minutes. Selected-bootstrap and learned tiers use a local-identity/epoch
  keyed order, removing fixed peer-ID prefix starvation while preserving the
  operator tier. Peerbook saves are serialized across renewal and learned-batch
  persistence; rotation coverage and fatal maintenance shutdown run under race.
  A real in-process QUIC fixture proves that a mixed exact/foreign-activation
  signed batch is rejected atomically while the pass continues to an independent
  compatible bootstrap and persists only its learned WorkGraph record;
- the distinct opt-in `/outcomemesh/chain-notify/1` protocol now reverses only
  chain session roles: a winning dialer serves, while the receiver initiates
  the same cumulative-work/header-first/full-replay synchronization. A selected
  tip change invalidates the ephemeral round and cancels its stale hash loop.
  Ten consecutive two-process runs covered share rate exhaustion, notification,
  restart, and convergence. Transport resets no longer create a retry storm or
  count remote rate limiting as an invalid protocol message.
- winning-anchor prompts now fan out through independent per-peer workers and
  coalesce while a peer is busy. Versioned responders pin the canonical path
  advertised in their handshake, allowing the next mining round to start
  without changing an in-flight sync view. A real process fixture converges
  three persistent WorkGraph nodes at height 6 while a fourth authenticated
  v0-only peer rejects both optional protocols without delaying the compatible
  peers; all three mixed chains replay-verify and survive restart.
- a parameterized four-node rollover harness advances 32 generations by
  default (256 in the dedicated Make target) across a 60-second clock spread,
  offline windows, and deterministic stream loss, then requires identical DAG
  inventories and full final anchor closure. It found a ranked-parent ordering
  defect: coverage selection is now separated from canonical Work-ID encoding,
  with a focused regression and repeated race coverage.
- a versioned economic activation corpus now emits 155 standard-withholding,
  620 bounded trail-depth, 72 direct-versus-delayed private-fee points, and a
  10,000-race global-ID counterexample as deterministic JSON. Its version-4
  canonical SHA-256 digest is golden-tested. The counterexample publishes only
  4,959 favorable IDs and reaches 100% adoption among published ties, which is
  why v1 now keeps its incumbent. `ACTIVATION_REVIEW.md` separates internal
  reproduction from still-open independent review and testnet gates.
- the ER-5 public-testnet gate now has a versioned integer-only evaluator. It
  enforces the full 30-day window, conservative one-sided 99% Hoeffding bounds
  for controlled tie adoption and mining concentration, and a Bonferroni
  selection correction across preclassified coordination clusters. Its
  version-4 evidence path verifies a bounded Ed25519-signed chain of gapless
  hourly records, exact per-cluster work conservation, trusted network/genesis/
  activation/policy bindings, and a published tail ID before `EvidencePass`.
  A generated 720-record chain freezes the end-to-end digest. Live collection
  now has an opt-in `work-serve-quic` path: post-commit first-admission events
  enter a crash-safe unique-ID journal, completed/empty hours are signed, and a
  canonical published mapping places unknown payout addresses in a conservative
  catch-all cluster. Controlled races now have a separate coordinator-signed
  version-1 precommit fixing miner roles, first-delivery role, and up to 10,000
  time slots, plus an observer-
  signed receipt chain that explicitly closes every slot as completed or
  `NoPair`. Only a complete chain yields ER-5 inputs, and every `NoPair` is
  conservatively charged as an adoption so selective completion cannot improve
  the result. The final bundle requires externally published hourly-tail,
  plan-ID, and receipt-tail checkpoints, rejects any legacy/manual tie counters
  in hourly records, and binds all raw evidence into the report digest. The
  activation router now publishes selected IDs through commit-ordered callbacks;
  a crash-safe live writer records partial role-labelled pairs, closes every
  expired/ambiguous slot as `NoPair`, and reconciles receipt-versus-pending
  crashes. A two-miner producer core now freezes one parent/payload, mines the
  role-labelled siblings in isolated pools, and submits them solely in the
  precommitted role order. A one-shot CLI now exercises that path through a
  persistent router and the live signed-receipt callback; a separate-process
  wait/kill/restart test proves its empty pending state is recoverable.
  A bounded canonical pair artifact now separates coordinator mining from
  observer signing: its creation never mutates the chain, and admission
  independently replays plan-derived nonce searches before ordered Submit.
  Version-2 plans now bind 2–64 sorted independent observer keys under one plan
  ID while retaining separate signed receipt chains. A dedicated authenticated
  QUIC stream now distributes the identical published artifact to independently
  keyed observers with mutual transport pinning, pre-allocation bounds, separate
  rate/resource scopes, durable receipt acknowledgements, coordinator
  confirmation, and restart-safe lost-ack recovery. A separate-process fixture
  rejects an unlisted coordinator, reaches two version-2 observers, compares
  their role-labelled blocks and selected tips, and proves a retry returns the
  original receipt without duplicate admission. Multi-observer ER-5 evidence
  now requires the plan's complete canonical observer set and every published
  tail, counts correlated views as one slot, and fail-closed downgrades mixed
  status, anchor, or selected-tip views to `NoPair`. The version-4 report commits
  the plan version, observer/validated-receipt/disagreement counts, and the
  combined checkpoint digest; a lone version-2 view cannot enter its verified
  path. Coordinator-signed pair checkpoints now bind each dynamically mined
  artifact to its plan and sequence for external publication, and a crash-safe
  campaign journal refuses delivery before publication, persists every
  canonical observer acknowledgement, and advances only after the full set.
  Its timed coordinator driver stores immutable per-slot files, waits for a
  separate filesystem publication gate, retries only missing observers in
  parallel, and advances the persistent coordinator chain between slots.
  A long-lived observer campaign process now consumes numbered signed
  checkpoints for the whole plan, distinguishes durable receipt commit from
  coordinator confirmation with immutable checksummed markers, and resumes the
  exact old pair after a kill in that gap. It advances across completely empty
  missed slots only after the closure grace, while a partial or invalid sibling
  state stops without writing `NoPair`. A real process test exercises the
  ACK/kill/restart/confirmation boundary. Coordinator publication deadlines
  are now bound to the signed slot. Before delivery begins, the driver waits
  through the shared receipt grace and persists the exact skipped sequence in
  its migrated version-1 journal; after publication, every delivery phase is
  permanently non-skippable. A real coordinator/observer process run closes an
  expired first slot as `NoPair`, delivers the next pair, and verifies matching
  tips. Another process is killed after the first sibling and pending candidate
  commit; restart retains exactly one candidate and fails closed without a
  receipt, confirmation, or next-slot transition. Writer injection on both
  sides of campaign skip and observer-confirmation commit proves old/new-only
  reopen plus idempotent retry. The authenticated pair protocol is now version
  2: observer confirmation is followed by a final ACK only after marker and
  directory durability. Separate-process permission faults bracket rename/link
  in both the coordinator journal and observer marker and prove no false local
  advance. An exact post-link marker with a missing final ACK is classified by
  the read-only audit and repaired by a narrow offline command that journals
  only the proven receipt tail; normal coordinator restart performs admission
  and advance. Physical media corruption, real device exhaustion, observer
  honesty, and Sybil-cluster provenance remain open testnet work.
  A read-only campaign audit now verifies every durable layer and classifies
  `healthy`, `recoverable`, or `blocked`: it detects unrecorded but confirmed
  ACKs, observer closure lag, missing/corrupt artifacts, impossible ACKs,
  skipped-slot delivery, and cross-observer block/selection divergence. It
  reports all issues, exits non-zero for blocked state, and a real process test
  proves a healthy audit leaves coordinator journal bytes unchanged.
  A further two-observer process campaign completes two version-2 slots while
  killing and restarting one observer between them on the same pinned endpoint.
  The coordinator now discards a stale reused QUIC session and retries one
  fresh identity-pinned handshake; both role-ordered receipt chains and final
  tips match, and the multi-observer audit remains healthy and read-only.
  Coordinator restart now has an exact process boundary too: one observer is
  held before request decoding while the other's ACK becomes durable. The
  replacement reports that single recovered ACK, never contacts the completed
  observer, advances only after the missing ACK, and finishes with convergent
  tips and a healthy read-only audit.
- the PoW research harness now also has an integer-only, fixed-seed geometric
  solve process for active v0 and lagged v1. Golden observation digests cover
  baseline variance and an alternating 1x/4x campaign, while separate cases
  cover a 4x hash-rate step, timestamp manipulation, deterministic replay, and
  bounded no-solution behavior.

No WorkGraph field has entered a version-0 block yet. The v1 store and opt-in
QUIC session remain isolated from every ordinary v0 chain/CLI path and are
reachable only through the explicitly marked experimental commands;
adversarial discovery/eclipse and longer real-QUIC rapid-parent churn soaks,
topology-derived peer selection, custody backup operations/compaction and
long-outage reconciliation,
canonical-prune
disk-exhaustion/long-soak campaigns, production gossip-budget calibration, and
broader adaptive economic-strategy analysis remain before activation.

## Milestones 6–10 — not integrated

Committee finality, Wasm, solvers, privacy, data availability, proving,
adversarial testnet, and mainnet readiness remain gated exactly as described in
`PLAN.md`.
