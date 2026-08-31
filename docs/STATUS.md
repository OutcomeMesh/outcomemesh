# Implementation status

Updated: 2026-08-31

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
- Pebble schema 3 stores one materialized canonical state plus immutable
  create/delete deltas per accepted block; side branches reconstruct from
  genesis with a state-root check at every node, and a 256-resource regression
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
- WorkChain schema 3 adds bounded replay-checkpoint rotation without duplicating
  state storage. Every non-base node has exactly one delta or full-state
  checkpoint; after 2,048 selected-branch heights maintenance swaps the tip's
  delta for a checkpoint and keeps at most four. Eviction reconstructs the old
  node's exact parent delta in the same synchronous batch. Tests cover
  delta→checkpoint→delta rotation, exact byte accounting, pre-sync failure,
  corrupt checkpoint rejection, restart/extension, and pruning a checkpoint
  carried by a stale fork. Schema 2 fails closed and requires replay.
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
  verified schema-3 WorkChain database. Reopen resolves each base against the
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
  reopen plus idempotent retry. Physical disk-full/torn-write campaigns,
  observer honesty, and Sybil-cluster provenance remain open testnet work.
  A read-only campaign audit now verifies every durable layer and classifies
  `healthy`, `recoverable`, or `blocked`: it detects unrecorded but confirmed
  ACKs, observer closure lag, missing/corrupt artifacts, impossible ACKs,
  skipped-slot delivery, and cross-observer block/selection divergence. It
  reports all issues, exits non-zero for blocked state, and a real process test
  proves a healthy audit leaves coordinator journal bytes unchanged.
- the PoW research harness now also has an integer-only, fixed-seed geometric
  solve process for active v0 and lagged v1. Golden observation digests cover
  baseline variance and an alternating 1x/4x campaign, while separate cases
  cover a 4x hash-rate step, timestamp manipulation, deterministic replay, and
  bounded no-solution behavior.

No WorkGraph field has entered a version-0 block yet. The v1 store and opt-in
QUIC session remain isolated from every ordinary v0 chain/CLI path and are
reachable only through the explicitly marked experimental commands;
adversarial discovery/eclipse and longer real-QUIC rapid-parent churn soaks,
topology-derived peer selection,
history-anchored archival pruning, extended filesystem-fault/soak campaigns,
production gossip-budget calibration, and broader adaptive economic-strategy
analysis remain before activation.

## Milestones 6–10 — not integrated

Committee finality, Wasm, solvers, privacy, data availability, proving,
adversarial testnet, and mainnet readiness remain gated exactly as described in
`PLAN.md`.
