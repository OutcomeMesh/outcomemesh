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
083a21ff5b3e06a9cddcf5f00203e4ec173b35f1bffed71ebeb70af7b9c0fd2c
```

`omreview` emits the complete configuration and all 227 aggregate result
points, not only the favorable boundaries. The document contains no wall-clock
time, platform metadata, maps, floating point, or random seed from the host.
Changing an assumption or result intentionally changes the digest.

The selfish-mining corpus covers 31 attacker shares from 15% through 45% in 1%
steps, five tie-adoption values, three fixed seeds, and 1,000 hard discoveries
per seed. A point is called profitable only if its aggregate advantage is at
least 5,000 ppm and it beats its paired immediate-publication baseline on every
seed.

| Honest hash adopting the attacker's tie | Prior tested point | First profitable point | Advantage at boundary | Orphan rate |
| ---: | ---: | ---: | ---: | ---: |
| 0% | 33% | 34% | +14,699 ppm | 245,666 ppm |
| 25% | 32% | 33% | +27,570 ppm | 237,333 ppm |
| 50% | 26% | 27% | +13,148 ppm | 197,000 ppm |
| 75% | 22% | 23% | +7,324 ppm | 172,666 ppm |
| 100% | 15% | 16% | +12,216 ppm | 129,000 ppm |

These are discrete observations, not closed-form security thresholds. At the
prior points the attack failed the three-seed rule even when aggregate advantage
was positive. That sensitivity is one reason an independent, longer stochastic
implementation is mandatory.

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
| ER-5 public testnet calibration | Thirty continuous days show a one-sided 99% upper confidence bound of at most 25% for controlled tie adoption and no coordinated miner above 25% of observed work | Pending public testnet |
| ER-6 fee-fragmentation stress | With a controlled miner up to 40% hash and an exclusive fee equal to 50% of subsidy, delayed fees retain the common template and matching-share inclusion; any split at or below that point fails | Pending public testnet |
| ER-7 finding closure | All critical/high findings are fixed and retested; unresolved medium findings have an owner, deadline, and explicit launch decision | Pending external work |

The 30%/25% selfish-mining gate leaves a measured gap below the internal 33%
boundary; the 25% concentration gate adds another operational margin. These
numbers are provisional engineering limits and must themselves be challenged by
the reviewer. Permissionless mining cannot guarantee future concentration, so
the same measurements continue after launch and feed the incident process.

## Reviewer scope

The review must cover the code, not only this report:

- `core/difficulty`, `core/pow`, `core/block`, and `sim/powmodel` for target,
  timestamp, cumulative-work, and difficulty feedback;
- `core/workgraph`, `core/workblock`, and `core/chainblock` for weak-work
  validation, canonical commitments, rewards, delayed fees, and versioning;
- `node/workchain`, `node/activation`, and `storage` for fork-local state,
  activation/reorg behavior, recovery, and replay;
- `sim/workgraphmodel` for assumptions, random processes, strategy completeness,
  integer accounting, and the frozen activation corpus.

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
