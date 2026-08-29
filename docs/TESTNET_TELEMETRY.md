# Public-testnet calibration telemetry

Status: opt-in hard-anchor collector and canonical controlled-tie evidence
formats implemented; live tie harness and independent observers not yet deployed

This format supplies reproducible inputs to ER-5 without making telemetry part
of consensus. A valid manifest proves that one expected Ed25519 observer signed
one gapless sequence of interval counters under one exact deployment and
clustering policy. It does not prove that the observer measured honestly.

## Trust binding

A verifier supplies these values independently instead of learning them from
the file:

- network ID and genesis ID;
- WorkGraph activation height;
- digest of the published coordination-clustering policy;
- maximum number of clusters compared by that policy;
- observer Ed25519 public key;
- latest record ID published through an independent checkpoint channel.

The last item prevents an operator from replacing the file with an older valid
prefix. Without an external tail checkpoint, signatures and previous-record
links detect mutation and reordering but cannot detect truncation.

## Record version 0

The canonical big-endian/varint encoding contains, in order:

| Field | Meaning |
| --- | --- |
| version | fixed record version `0` |
| network ID, genesis ID, activation height | exact chain deployment |
| cluster-policy ID | digest of the external identity/coordination rules |
| cluster comparison budget | Bonferroni family bound, maximum 4,096 |
| sequence | starts at one and increments by exactly one |
| start, end | half-open Unix-second interval, at most one hour |
| previous record ID | zero at sequence one, exact signed predecessor later |
| tie adoptions, tie trials | controlled equal-height-race interval deltas |
| observed work | total independently classified work observations |
| sorted cluster work list | nonzero interval deltas summing exactly to observed work |
| observer public key | must equal the independently trusted key |
| Ed25519 signature | signature over the domain-separated unsigned-record hash |

Record IDs hash the full signed canonical record under a separate domain. A
manifest may contain at most 10,000 records, each record is limited to 192 KiB,
and the complete file is limited to 64 MiB. Decoders allocate cluster lists only
after checking their bounds.

## Chain verification

Verification is fail-closed and performs all of these checks before returning
an aggregate:

1. Validate every canonical shape and Ed25519 signature.
2. Match every deployment, policy, budget, and observer field to the trusted
   binding.
3. Require sequence `1..N`, an all-zero first predecessor, exact later
   predecessor IDs, and adjacent interval boundaries with no gaps or overlap.
4. Require tie successes not to exceed trials; require strictly ordered,
   nonzero cluster IDs and exact conservation of observed work.
5. Keep the union of cluster IDs inside the signed comparison budget.
6. Add every counter with checked `uint64` arithmetic and select the largest
   aggregated cluster only after the full chain verifies.
7. Match the final record ID to the separately published checkpoint.

The file is materialized through a mode-0600 temporary file, file `fsync`,
atomic rename, and directory `fsync`. This protects local crash recovery. The
cryptographic chain, not filesystem append semantics, provides historical
mutation detection.

## Precommitted controlled-tie trials

Controlled equal-work races use a separate signed raw-evidence chain. They are
not accepted as manually supplied success/trial counters. Before either sibling
anchor ID exists, a coordinator signs and externally publishes a version-0
`TiePlan` and its ID. The plan fixes:

- the network, genesis, and WorkGraph activation height;
- distinct tested and control miner payout addresses;
- the observer and coordinator Ed25519 public keys;
- at most 10,000 ordered, non-overlapping half-open time slots of at most one
  hour each;
- the maximum allowed delay between observing the two anchors.

The verifier obtains both public keys and the deployment binding independently.
The coordinator signature authenticates the plan but cannot by itself prove
that it was published before the experiment. A timestamped external publication
of the plan ID is therefore part of the operational protocol.

Every precommitted slot has exactly one observer-signed receipt. A completed
receipt commits to the plan ID, sequence, predecessor receipt, common parent,
height, role-labelled tested and control anchor IDs, their observation times,
and the locally selected anchor. Both observations must fall inside that slot,
their delay must be within the plan bound, and the selection must be one of the
two siblings. The adoption counter is derived from the selected and tested IDs;
there is no signed mutable `adopted` boolean.

If no valid pair was obtained, the observer must instead sign a `NoPair`
receipt whose anchor, parent, height, time, and selection fields are all zero.
It cannot silently omit the slot. Receipts form a sequence- and ID-linked chain;
the manifest embeds the signed plan and may hold an exact live prefix, but only
a chain with one receipt for every planned slot is `Complete`. Final ER-5
counters are fail-closed: every `NoPair` slot is charged as a tested-branch
adoption and the denominator is the full precommitted slot count. Selectively
turning unfavorable attempts into failures therefore cannot improve the bound.

The plan is limited to 256 KiB, a receipt to 1 KiB, and the raw manifest to
8 MiB. Canonical decoders enforce all bounds before allocation, and full-plan
verification hashes the plan once so 10,000 receipts remain linear-time.
Plan ID `897f6a1dd581297c763ef25ac908d2472cda297064e867a43dd464f498ca142e`
and receipt-chain tail
`11ec379be3bad4de59cf154c39e9678bdd59e90ac1d861876b83830af1ce7717`
are frozen deterministic test vectors.

These signatures prove provenance, binding, continuity, and explicit slot
closure—not observer honesty. An auditor still needs the underlying version-1
blocks to verify their common parent, height, PoW, and payout addresses, plus an
independently published receipt-tail checkpoint to detect rollback. Different
observers' correlated views must be reported separately; they are not
independent samples merely because they carry different signatures.

## Live hard-anchor collector

The opt-in collector is connected to the activation router's first-admission
boundary. A telemetry event is emitted only after a new version-1 block passes
full validation and durable WorkChain commit. Legacy blocks, rejected blocks,
and duplicate submissions emit nothing. The callback runs after the router lock
is released and cannot change admission or fork choice.

The current interval is a separate mode-0600 journal containing sorted unique
hard-anchor IDs and controlled-tie experiment IDs rather than mutable totals.
This makes repeated delivery idempotent and makes a conflicting classification
for the same event detectable. Each successful observation atomically replaces
and fsyncs this journal before returning. At an hour boundary the collector:

1. derives counters and sorted cluster totals from the journal;
2. signs the next record and atomically commits the extended manifest;
3. atomically creates the next empty pending interval;
4. reconciles a crash between steps two and three from the signed manifest tail
   on restart.

No-anchor hours still produce signed empty records. Clock rollback is rejected.
Any live telemetry failure poisons the collector and writes a separate
`.failed` marker when the filesystem permits it; `work-serve-quic` then exits,
and the marker prevents a silent restart of the same evidence window. This
includes disk errors, exhausted event bounds, and an admission that cannot be
classified. Consensus admission remains committed, so operators must start a
fresh calibration window after such a failure rather than pretending the
missed observation did not happen.

The collector currently counts first-admitted hard anchors as equal-difficulty
work observations. It does not mix weak shares into that denominator. This
keeps duplicate and difficulty semantics explicit, at the cost of a smaller
sample.

## Published clustering policy

The policy text file has one mandatory conservative catch-all plus optional
payout-address assignments:

```text
# unknown addresses are grouped together, never silently ignored
unknown,<64-hex-cluster-id>
miner,<64-hex-payout-address>,<64-hex-cluster-id>
miner,<64-hex-payout-address>,<64-hex-cluster-id>
```

Whitespace and comment lines are ignored. Assignments are canonically sorted by
miner address. Duplicate miners, zero IDs, or more distinct clusters than the
precommitted comparison budget are rejected. Unknown payout addresses all map
to the catch-all, which is deliberately conservative: unrelated new miners can
make concentration look worse, but cannot make it look safer.

Compute and publish the canonical policy ID before starting the window:

```sh
.tools/go/bin/go run ./cmd/omd work-telemetry-policy \
  --policy clusters.txt --clusters 64
```

Then enable collection on a persistent observer node with a key distinct from
its transport identity:

```sh
.tools/go/bin/go run ./cmd/omd work-serve-quic \
  --data observer-data \
  --key transport.key \
  --telemetry-key observer.key \
  --telemetry-policy clusters.txt \
  --telemetry-policy-id <published-policy-id> \
  --telemetry-clusters 64
```

The default outputs are `observer-data/work-telemetry.omtm` and
`observer-data/work-telemetry.pending`; both can be overridden explicitly. A
minute ticker closes every completed hour even when the node admits no block.
The startup line reports the current signed-record count, completed boundary,
pending boundary, and tail ID.

## ER-5 handoff

`omcalibrate --manifest` derives all observation counters from the verified
aggregate; command-line counter flags cannot override it. The report binds the
tail ID and record count. `EvidencePass` additionally requires at least one
record per hour of the claimed window, so a 30-day pass needs at least 720
records. Raw counter mode is retained for exploring statistical thresholds but
always leaves `EvidencePass=false`.

The generated end-to-end vector uses 720 signed hourly records, 10,000
controlled ties with 2,000 tested-branch adoptions, and 50,000 work observations
whose largest cluster has 11,000. Across a 64-cluster comparison budget its
tail is
`c539440ac6d71c9178b2ab3d7815ed40c9ba502da5b00f33e2282dba7c7113ed`
and its version-2 report digest is
`a31031b36ad9d570cdd0882d419badd8893f091e668192831721e96ac21176a4`.

## Remaining operational work

- connect the signed tie plan and receipt chain to a live two-miner harness and
  the hourly ER-5 collector. The existing record-v0 counters are not yet derived
  from raw receipts, so this document does not claim a deployable tie result;
- publish each plan ID before its first slot and publish the final receipt tail
  outside the manifest storage path;
- deploy and publish the clustering policy and its digest before each real
  observation window;
- operate multiple independently controlled observers and document how their
  correlated views are handled rather than naively pooling them;
- publish hourly telemetry tail checkpoints outside the manifest storage path;
- define privacy retention for the raw identifiers used to derive pseudonymous
  cluster IDs;
- chaos-test missed intervals, observer restart, disk-full behavior, and
  checkpoint disagreement. Local restart, duplicate, clock rollback,
  persistence failure, and concurrent-observation cases are already covered.
