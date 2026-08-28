# Proof-of-work simulations

Status: deterministic research harness for active version 0 and inactive WorkGraph version 1

`sim/powmodel` is an integer-only fluid model of both the exact version-0 ASERT
and the experimental version-1 lagged ASERT, plus 11-block median-time-past,
the 120-second future bound, target-derived chain work, and variable hash rate.
It does not sample lucky or unlucky nonces. Instead, it finds the earliest whole
second at which expected supplied hashes cross the exact fractional target
difficulty:

```text
hash_rate * seconds >= (pow_limit + 1) / (target + 1)
```

The comparison is cross-multiplied with `math/big`; no floating point or random
source is used. This makes regressions reproducible while keeping stochastic
mining variance clearly outside the model.

## Executable scenarios

Run:

```sh
go test ./sim/powmodel -count=1 -v
go test ./sim/workgraphmodel -count=1 -v
```

## WorkGraph share model

`sim/workgraphmodel` is integer-only and fixed-seed. Its aggregate harness
models the geometric number of weak shares before each anchor, weighted miner
selection, per-miner withholding, propagation loss, anchor orphaning, random
share-ID ordering, canonical cap truncation, credited shares, and encoded
bandwidth. Each miner can also select a payload-template label; only shares
matching the winning anchor's label receive credit.

The current reproducible cases show:

- 5,000 honest intervals at ratio 512 produced 2,597,121 included shares
  (about 519 per anchor), a maximum interval of 3,985, zero overflows at the
  8,192 cap, and 475,273,143 modeled bytes total at 183 bytes/share; fixed-rate
  issuance was 25,206,071,390,407 units against a 25,000,000,000,000 schedule
  (0.82% high from the fixed-seed share-count variance);
- replacing the production cap with 2,048 overflowed 36 of 2,000 intervals,
  confirming that fourfold geometric headroom is inadequate;
- two equal-hash miners found comparable work and anchor counts, while a miner
  withholding 50% of its shares received roughly half the share credit; a 10%
  configured orphan rate produced 529 orphans in 5,000 intervals;
- two equal-hash miners using different payload templates produced 158,653
  included and 158,822 mismatched shares, quantifying the roughly 50% efficiency
  loss and the pressure to converge on a common valid template;
- at the production 512 ratio, the same 50/50 template split issued
  7,569,388,904,161 units against a 10,000,000,000,000 schedule: unavailable or
  mismatched work is under-issued rather than transferred to the winner;
- each honest miner's credited-share proportion remains within 20,000 ppm of
  its configured hash share in the fixed corpus.

The discrete-event topology corpus additionally models shortest-path link
delay, a separate DAG/tip view per miner, missing-parent queues, at most four
parents per new share/anchor, private withheld ancestors, and deliberate
foreign-tip omission. Its shortest-path propagation now has a concrete runtime
counterpart: active QUIC miners forward each first-admitted share across their
explicit peer graph, while per-round pool deduplication terminates cycles:

- an eight-miner full mesh with one-event propagation committed all 258,660
  published shares across 2,000 rounds and never had more than one winner tip;
- an eight-miner line with three-event delay per hop committed 239,736 of
  253,129 published shares; winners lacked 13,323 shares, left 70 known shares
  outside their four-tip closure, and saw more than four tips in 55/2,000
  rounds, with a maximum of seven;
- a four-miner adversarial fixture exercised 50% withholding by the largest
  miner and 1,008 deliberate foreign-tip omissions. Withheld shares could still
  be paid when their owner won, but poisoned public children with missing
  parents and lost credit on other winners.

The same topology harness now models relay queues, full-batch thresholds,
periodic partial flush, unreleased shares at the hard anchor, fixed WorkGraph
subsidy rates, and reward per miner. At the 512:1 production ratio, one discovery
event represents about 117 ms; the default eight-second flush is therefore the
fixed 69-event calibration. In a 1,000-round, two-miner corpus with 10%/90%
hash share and one-event link delay:

- immediate relay gave the small miner 104,349 ppm of issued reward and included
  496,602 shares;
- waiting only for 128-share batches reduced it to 73,611 ppm, included 455,372
  shares, and left 99,674 public-intended shares queued when anchors arrived;
- the same 128-share batches plus the 69-event partial flush restored the small
  miner to 102,033 ppm, included 490,321 shares, and reduced unreleased work to
  32,784 shares.

This fixed-seed result does not establish a universal fairness theorem, but it
does reject batch-only relay and makes the eight-second maximum wait a tested
economic invariant rather than a performance preference.

The topology model exposed and caused removal of the earlier variable half-pool
reward rule: a winner could maximize payment by committing an empty DAG. The
implemented fixed pay-per-share rate makes inclusion of a foreign share neutral
to the winner's absolute reward, while leaving relative-revenue censorship as a
documented threat.

The multi-round fork harness additionally keeps separate public and private
share pools, resolves equal-height races using a configurable honest-miner
adoption fraction, orphans losing anchors, and pays only candidates on the
eventual canonical branch. Shares visible before a fork can appear in both
candidates, but the accounting invariant requires total paid shares never to
exceed total discovered shares. In 10,000 fixed-seed hard discoveries:

- immediate publication at 25% attacker hash share produced a 25.3954% reward
  share, 10,000 canonical anchors, and 5,165,829 included weak shares;
- adaptive withholding at the same 25% and zero honest adoption reduced the
  attacker's reward share to 21.6652% and orphaned 1,814 anchors;
- at 35% attacker hash share and 50% honest adoption of an attacker's published
  tie, immediate publication produced 35.2656% while withholding produced
  40.9857% and orphaned 2,472 anchors;
- an upper-bound omission run left the attacker's absolute reward unchanged at
  14,494,019,663,505 units, reduced honest rewards from 20,869,502,638,473 to
  18,216,117,611,289, and reduced total issuance accordingly. Fixed rates
  remove direct theft from omission, but cannot remove its relative-revenue
  and censorship motive.

The baseline reproducible profitability sweep replaces inference from those
two points with a 7 × 5 parameter grid. It tests attacker hash shares from 15%
through 45%
in five-point increments, tie adoption from 0% through 100% in 25-point
increments, and pairs immediate publication with withholding over three common
random seeds and 2,000 hard discoveries per seed. A grid point is labelled
profitable only when aggregate reward-share advantage is at least 5,000 ppm
(0.5 percentage point) and withholding beats immediate publication on all
three seeds. The first profitable tested points are:

| Honest miners adopting attacker's tie | First profitable attacker hash | Advantage at boundary | Orphan-anchor rate |
| ---: | ---: | ---: | ---: |
| 0% | 35% | +23,367 ppm | 250,666 ppm |
| 25% | 35% | +47,327 ppm | 250,666 ppm |
| 50% | 25% | +8,191 ppm | 185,166 ppm |
| 75% | 25% | +25,121 ppm | 185,166 ppm |
| 100% | 15% | +9,147 ppm | 117,500 ppm |

All 35 aggregate reward shares, per-seed win counts, orphan rates, and boundary
values are exact golden-test inputs. These are discrete grid observations, not
closed-form thresholds: for example, the true boundary between 30% and 35% at
zero tie adoption is not identified by this corpus.

The activation-review corpus adds a finer 31 × 5 grid at one-percentage-point
hash increments. With three fixed seeds and 1,000 hard discoveries per seed,
its first profitable tested shares are 34%, 33%, 27%, 23%, and 16% at respective
tie-adoption values of 0%, 25%, 50%, 75%, and 100%. The full 155 points and
configuration are emitted by `omreview`. Four more 155-point grids keep mining
a losing branch up to public-lead deficits one through four. Their respective
threshold rows are `37/33/27/23/16`, `38/34/31/25/16`, `38/36/33/25/16`, and
`40/38/36/25/16`; no bounded trail depth lowers the conservative standard
boundary in this corpus. The frozen version-3 document digest and precommitted
launch gates are in `ACTIVATION_REVIEW.md`.

WorkGraph therefore does not eliminate the classic selfish-mining threshold;
the result is a measured protocol limit, not a failed invariant. The sweep also
shows that relay topology and tie adoption are security parameters rather than
mere performance details. The model still needs finer boundary calibration and
richer adaptive network strategies before Milestone 5 closes. Template
convergence and relative-revenue omission are explicit centralization risks,
not assumed away.

The exact-integer template market computes sequential miner best responses from
anchor subsidy, private fees, fixed share rewards, and hash already coordinated
on each payload. With ten equal miners, a 5,000,000,000-unit subsidy, and one
miner alone able to use a private template:

- a 500,000,000-unit private fee left all hash on the common template;
- a 3,000,000,000-unit private fee exceeded the direct-payment split threshold
  of 2,249,999,583 units and moved the 10% miner to its private template;
  expected matching weak work fell to 82%, expected subsidy issuance fell to
  91%, and its expected revenue share rose from 10% to 11.8556%;
- with fee-delay economics, the same miner internalizes only its expected
  future 10% share of a fee. The 3,000,000,000-unit case stayed entirely on the
  common payload with 100% matching work;
- an initially even split across equal-fee public templates converged to one
  template in two deterministic best-response passes, illustrating both useful
  coordination and the underlying network-effect centralization pressure.

The activation-review fee sweep expands the single 10% example to six miner
sizes and twelve private-fee levels. Direct-payment fragmentation first appears
at 2,000,000,000 or 2,500,000,000 units across the tested range. Fee delay moves
the first tested thresholds to 250,000,000,000 units at 1% hash,
25,000,000,000 at 10%, and 4,000,000,000 at 40%. It materially reduces the
incentive but does not eliminate fragmentation for a large miner or unbounded
private order flow.

The corresponding core prototype is stronger than an accounting assumption:
its bounded immutable ring conserves `deposits = awards + balance`, commits the
next root and current award into the payload, rejects arithmetic/codec faults,
and passes a transaction-to-future-anchor integration test. The market remains
a simplified expectation model; fee delay, miner entry/exit, private order flow,
and censorship require broader strategic sweeps before activation.

The bounded-bandwidth harness uses the production 512:1 ratio and 183-byte
modeled shares. Every directed link has independent serialization capacity,
latency, and a hard FIFO byte limit; complete messages are forwarded hop by
hop, first-copy reception is deduplicated, already queued duplicates still
consume bandwidth, and candidate-specific queues expire at the next anchor.
The fixed corpus shows:

- a six-miner full mesh provisioned at 1,464 bytes per discovery event per
  directed link included all 271,199 shares over 500 rounds with no queue
  drops; naive flooding still delivered 5,414,020 duplicate messages, proving
  that inventory/deduplication design materially affects the node budget;
- an eight-miner line limited to 32 bytes/event and four 183-byte shares per
  link queue included only 84,643 of 494,208 published shares over 1,000
  rounds, dropped 651,680 queued messages, and never exceeded the 732-byte
  per-link cap;
- raising only the four central directed links to 183 bytes/event and a
  sixteen-share queue increased inclusion to 172,833. Drop-message count rose
  because more unique work reached the still-slow edge links; inclusion and
  winner visibility, rather than raw duplicate-drop count, are the useful
  fairness measures.

One discovery event corresponds to approximately `60/512` seconds at the
target schedule, so 1,464 bytes/event is about 12.5 kB/s per directed peer and
32 bytes/event is about 273 B/s. These are deterministic workload fixtures,
not a production bandwidth recommendation: framing, inventory announcements,
signatures, retransmission, anchors, and transaction traffic must be added to
the final budget.

The implemented inventory-first session now supplies a separate hard admission
envelope. One complete relay can announce at most 1,024 IDs. Its exact maximum
bidirectional application framing is 630,258 bytes; the worst case is a peer
negotiating one maximum-size share per response, which repeats request/response
headers 1,024 times. The QUIC adapter defaults to one concurrent WorkGraph
stream, eight accepted WorkGraph streams per peer per fixed minute, and 512
accepted WorkGraph streams globally per fixed minute. Therefore its default
admission ceiling is 5,042,064 application bytes/minute per peer (about 82.1
KiB/s averaged over the window) and 322,692,096 bytes/minute globally (about
5.13 MiB/s). Fixed-window boundary bursts can approach twice the average;
QUIC/IP headers and retransmissions are not included. These are hard prototype
ceilings, not a recommendation to provision links at the ceiling. The topology
results above show that useful steady-state gossip should be far lower and that
deduplication, not allowed maximum traffic, determines fairness.

## PoW scenarios

The committed tests cover:

- 200 blocks at baseline hash rate: every expected interval is exactly 60
  seconds and the target remains at the genesis PoW limit;
- a `1x -> 4x` step: the first interval falls to 16 seconds, then the final
  100-block average returns to 55 seconds as ASERT hardens (whole-second model);
- a `4x -> 1x` return: the first interval is 223 seconds, the final 100-block
  average returns to exactly 60 seconds, and target eases to the PoW limit;
- a sustained legal `+120s` header bias under 4x hash rate: the final target
  ratio measured by the fixture is 10,003 basis points, well below the asserted
  10,120-basis-point safety bound;
- a `-3600s` slow-timestamp attempt, constrained by MTP: producing the same 300
  blocks commits 501 work units instead of 408 and takes 9,911 modeled seconds
  instead of 8,127; slow timestamps do not manufacture cheap height;
- rejection of any configured positive bias beyond the protocol's 120-second
  admission limit.

The experimental `RunLagged` corpus separately proves:

- 200 baseline blocks remain exactly on the 60-second schedule and every target
  equals an independent ASERT evaluation from the preceding timestamp;
- changing the current candidate from honest time to the full `+120s` bound
  changes its header timestamp but not its already fixed target or solve work;
- after a `1x -> 4x` step the first interval is 15 seconds and the last
  100-block average returns to 56 seconds in the whole-second model;
- a `-3600s` slow-timestamp strategy still requires both more cumulative work
  and more physical time for the same 300 heights.

The fixed-seed stochastic harness adds whole-second nonce-time variance to both
target rules. For each second it calculates the exact integer expected-work
fraction from hash rate and target, samples that rational probability with a
256-bit deterministic draw, and caps probability at one. It never uses floating
point or host randomness. Admission limits a corpus to 100,000 blocks and each
block to 30 days of sampled seconds. Canonical observation digests commit
height, wall and header time, solve duration, target, per-block work, and
cumulative work:

- active v0 over 2,048 baseline blocks had mean 62 seconds, median 43, p95 184,
  p99 271, and maximum 464; its observation digest is
  `be7e802166596c6c5bd6f226561056e412f623738462da910b5c89ec2956e8aa`;
- lagged v1 over 4,096 baseline blocks had mean 59 seconds, median 41, p95 179,
  p99 269, and maximum 560; its observation digest is
  `34be269d5b978372e5bc183bf46c46e2a27bf2a37216defb80b56d5413bcd187`;
- after a `1x -> 4x` step, the fixed v1 path solved its first stepped block in
  15 seconds and the final 100-block mean returned to 55 seconds;
- paired v1 runs at 4x hash showed that `-3600s` timestamps increased the
  300-height path from 423 to 534 cumulative work units and from 7,474 to 9,718
  physical seconds;
- after a 700-block 4x warmup, twelve alternating 32-block 1x/4x cycles gave
  active v0 2,561 work units in 88,750 seconds and lagged v1 2,574 units in
  88,791 seconds. Full-path digests make this basic oscillation fixture a
  regression corpus rather than a profitability claim.

This is a geometric whole-second model. It provides realistic discovery
variance at the protocol's timestamp resolution, but it does not hash actual
nonces, model sub-second multiple discoveries, or replace a network fork race.

## Interpretation and limits

These results validate feedback direction, arithmetic bounds, and deterministic
fork-weight accounting. They do not establish economic security. The repository
now covers network delay, bounded partitions/restarts, selfish anchor
withholding, heterogeneous clocks, and deterministic private-template markets,
but still lacks per-nonce/sub-second mining, empirically calibrated Internet
behavior, richer adaptive/stubborn and adaptive hash-hopping strategies, miner
entry/exit, pool switching, and private transaction arrival processes.
Parameters and model structure require independent review. Passing this harness
and reproducing its digest are milestone gates, not an audit; the complete
handoff and pass/fail rules are in `ACTIVATION_REVIEW.md`.
