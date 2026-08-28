# PoW and WorkGraph activation review packet

Status: internally reproducible; independent review not yet completed

This packet is the hand-off boundary between OutcomeMesh implementation work
and an independent proof-of-work/economic review. It does not call an internal
test an audit. Public WorkGraph mining remains disabled until every external and
testnet gate below is closed with artifacts that can be published.

## Reproduce the frozen corpus

Use the repository Go toolchain and run:

```sh
make GO=.tools/go/bin/go test-economic-review
make GO=.tools/go/bin/go economic-review > economic-review.json
jq -r .digest_sha256 economic-review.json
```

The canonical compact document currently has SHA-256:

```text
8d20c51d815a2149d505b361b14840c087e587fdcdaa203060a9ff1c69c3bc16
```

`omreview` emits the complete configuration and all 848 aggregate result
points, not only the favorable boundaries. The document contains no wall-clock
time, platform metadata, maps, floating point, or random seed from the host.
Changing an assumption or result intentionally changes the digest.

The selfish-mining corpus covers 31 attacker shares from 15% through 45% in 1%
steps, five tie-adoption values, three fixed seeds, and 1,000 hard discoveries
per seed for standard lead withholding and bounded trail deficits from one
through four anchors. After losing a published tie, a trail strategy mines its
stale branch while the public lead remains inside its configured limit; a
catch-up creates a final equal-height race, while exceeding the limit ends the
attempt. Branch-local weak-share pools survive every intermediate anchor. A
point is called profitable only if its
aggregate advantage is at least 5,000 ppm and it beats its paired
immediate-publication baseline on every seed.

| Tie adoption | Standard | Trail 1 | Trail 2 | Trail 3 | Trail 4 | Conservative first |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0% | 34% | 37% | 38% | 38% | 40% | 34% |
| 25% | 33% | 33% | 34% | 36% | 38% | 33% |
| 50% | 27% | 27% | 31% | 33% | 36% | 27% |
| 75% | 23% | 23% | 25% | 25% | 25% | 23% |
| 100% | 16% | 16% | 16% | 16% | 16% | 16% |

These are discrete observations, not closed-form security thresholds. No tested
trail depth lowers the standard boundary; deeper trailing is generally less
profitable here. This does not cover lead-stubborn, equal-fork-stubborn,
unbounded/adaptive trailing, or combined policies. At some prior points an
attack failed the three-seed rule even when aggregate advantage was positive.
That sensitivity is one reason an independent, longer stochastic implementation
is mandatory.

### Rejected global ID tie-break

The version-4 corpus also freezes a selective-publication counterexample for
the former shared smaller-ID rule. From 10,000 deterministic equal-work ID
pairs, a withheld publisher exposes the 4,959 races whose attacker ID is
smaller and suppresses the other 5,041. Every exposed race is then selected by
every node applying the same global rule: conditional published-race adoption
is 1,000,000 ppm. Treating this as an ordinary propagation parameter would be
wrong because the attacker chooses whether the trial becomes visible after
learning both IDs.

The inactive version-1 fork coordinator therefore no longer changes tips on an
exact cumulative-work tie. It persists the local arrival incumbent and changes
only for strictly greater hard work; versioned sync likewise ignores a merely
smaller equal-work peer. Different nodes may temporarily mine different tips,
which is the propagation behavior ER-5 must measure, and the next strictly
heavier branch converges them. Version 0 retains its existing rule for
compatibility. The counterexample remains in the corpus so a future refactor
cannot silently reintroduce the rejected architecture.

The fee corpus compares direct fees and the implemented delayed fee pool for
one miner able to use a private template while all other hash remains on a
common template. The subsidy is 5,000,000,000 atomic units.

| Miner hash | First fragmenting direct fee | First fragmenting delayed fee | Delayed fee / subsidy |
| ---: | ---: | ---: | ---: |
| 1% | 2,500,000,000 | 250,000,000,000 | 50x |
| 5% | 2,500,000,000 | 50,000,000,000 | 10x |
| 10% | 2,500,000,000 | 25,000,000,000 | 5x |
| 20% | 2,000,000,000 | 10,000,000,000 | 2x |
| 30% | 2,000,000,000 | 6,000,000,000 | 1.2x |
| 40% | 2,000,000,000 | 4,000,000,000 | 0.8x |

Fee delay materially raises the private-template threshold but does not remove
fragmentation for a large miner or unbounded private order flow. This remains a
core economic assumption, not a solved theorem.

## Precommitted activation gates

All gates are conjunctive. A failure pauses activation and changes the model or
protocol; it is not waived by the other gates passing.

| Gate | Pass condition | Current state |
| --- | --- | --- |
| ER-1 deterministic reproduction | Clean checkout reproduces the checked-in digest and all golden tests | Passed internally |
| ER-2 independent PoW arithmetic | A reviewer independently derives ASERT, lagged target, MTP/future bounds, chain work, weak target, subsidy split, and overflow bounds; every discrepancy is resolved | Pending external work |
| ER-3 independent strategy model | A separately implemented stochastic/discrete-event model tests at least immediate publication, lead withholding, stubborn variants, eclipse/partition recovery, difficulty oscillation, and private-template selection | Pending external work |
| ER-4 conservative security margin | No reviewed strategy is profitable below 30% attacker hash when measured tie adoption is at most 25%; otherwise parameters or architecture change | Pending external work |
| ER-5 public testnet calibration | Thirty continuous days show a one-sided 99% upper confidence bound of at most 25% for controlled tie adoption and no coordinated miner above 25% of observed work | Verifier implemented; live telemetry pending |
| ER-6 fee-fragmentation stress | With a controlled miner up to 40% hash and an exclusive fee equal to 50% of subsidy, delayed fees retain the common template and matching-share inclusion; any split at or below that point fails | Pending public testnet |
| ER-7 finding closure | All critical/high findings are fixed and retested; unresolved medium findings have an owner, deadline, and explicit launch decision | Pending external work |

The 30%/25% selfish-mining gate leaves a measured gap below the internal 33%
boundary; the 25% concentration gate adds another operational margin. These
numbers are provisional engineering limits and must themselves be challenged by
the reviewer. Permissionless mining cannot guarantee future concentration, so
the same measurements continue after launch and feed the incident process.

### Executable ER-5 calculation

`omcalibrate` turns verified telemetry into a versioned, digestible pass/fail
document. It computes a one-sided Hoeffding upper bound in parts per million
with no floating point. Both the observed proportion and the margin round
upward. Rational upper approximations of `ln(100)` and `ln(2)` make the result
conservative at integer boundaries.

Mining concentration needs an additional selection correction: the largest
observed coordination cluster is chosen after comparing several clusters.
`CoordinatedClusters` therefore applies a Bonferroni correction, rounded up to
the next power-of-two family size. This keeps the family-wise one-sided
confidence at or above 99%, instead of incorrectly treating the selected
largest cluster as a single preselected series.

Run the focused golden tests with:

```sh
make GO=.tools/go/bin/go test-calibration
```

Raw counters can still preview the arithmetic, but cannot pass the evidence
gate:

```sh
.tools/go/bin/go run ./cmd/omcalibrate \
  --window-seconds 2592000 \
  --tie-adoptions 2000 --tie-trials 10000 \
  --coordinated-work 11000 --observed-work 50000 \
  --coordinated-clusters 64
```

It produces a tie-adoption upper bound of 215,175 ppm and a family-corrected
concentration upper bound of 229,362 ppm, while `EvidencePass` and the overall
`Pass` remain false.

The version-2 evidence path accepts a canonical manifest only with explicit
trusted network, genesis, activation, clustering-policy, observer-key, and
published-tail bindings:

```sh
.tools/go/bin/go run ./cmd/omcalibrate \
  --manifest telemetry.omtm \
  --network-id 20260826 \
  --genesis-id <64-lowercase-hex> \
  --activation-height <height> \
  --cluster-policy-id <64-lowercase-hex> \
  --coordinated-clusters 64 \
  --observer-public-key <64-lowercase-hex> \
  --evidence-tail-id <64-lowercase-hex>
```

Each signed record covers at most one hour; sequences, previous-record IDs, and
interval boundaries must be gapless. The generated 720-record/30-day golden
chain has tail
`c539440ac6d71c9178b2ab3d7815ed40c9ba502da5b00f33e2282dba7c7113ed`
and version-2 report digest
`a31031b36ad9d570cdd0882d419badd8893f091e668192831721e96ac21176a4`.
Reducing the window by one second, providing fewer than 720 records, omitting
manifest verification, or raising either bound above 250,000 ppm fails the
conjunctive result. The full format is specified in `TESTNET_TELEMETRY.md`.

The manifest proves which observer signed the gapless claimed history and makes
past mutation detectable; publication of its tail makes valid-prefix rollback
detectable. It does not prove observer honesty, statistical independence, or
that Sybil identities were grouped into the right coordination clusters.
Independent review must challenge those assumptions before ER-5 can pass.

An opt-in `work-serve-quic` collector now records only the router's first
successful admission of each version-1 hard anchor, persists unique event IDs
in a crash-safe current-hour journal, emits signed empty hours, and stops the
observer service on telemetry failure. The clustering policy and expected ID
are mandatory startup inputs; unknown miners enter one conservative catch-all.
Controlled tie experiments and multiple independent observer deployments are
still required before the 30-day clock can start.

## Reviewer scope

The review must cover the code, not only this report:

- `core/difficulty`, `core/pow`, `core/block`, and `sim/powmodel` for target,
  timestamp, cumulative-work, and difficulty feedback;
- `core/workgraph`, `core/workblock`, and `core/chainblock` for weak-work
  validation, canonical commitments, rewards, delayed fees, and versioning;
- `node/workchain`, `node/activation`, and `storage` for fork-local state,
  activation/reorg behavior, recovery, and replay;
- `sim/workgraphmodel` for assumptions, random processes, strategy completeness,
  integer accounting, the frozen activation corpus, and the ER-5 confidence
  calculation including its independence and cluster-selection assumptions.

The independent deliverable must publish the reviewed commit, tool versions,
full configuration, raw results, statistical method, discovered counterexamples,
and a finding ledger. A summary without reproducible inputs is not sufficient.

## Known model limits

The checked-in `sim/powmodel` now has deterministic whole-second geometric
discovery variance, but does not hash real nonces or model sub-second competing
discoveries. The wider corpus still lacks empirically calibrated Internet
propagation, miner entry/exit, pool payout and switching behavior, correlated
outages, private transaction arrival processes, bribery, and a complete
adaptive strategy/hash-hopping search. The exact-template market is a
deterministic best-response model, not evidence that private order flow can be
observed. These limits are explicit inputs to ER-3 through ER-6.
