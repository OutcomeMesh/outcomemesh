# Implementation status

Updated: 2026-09-12

This file records evidence against `PLAN.md`. A milestone remains open until all
of its exit gates pass; implementing most deliverables does not close it.

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
