# Public-testnet calibration telemetry

Status: format and verifier implemented; live collectors and independent
observers not yet deployed

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

- build the live collector that obtains controlled tie outcomes and canonical
  work classifications from node events;
- publish the clustering policy and its digest before each observation window;
- operate multiple independently controlled observers and document how their
  correlated views are handled rather than naively pooling them;
- publish signed tail checkpoints outside the manifest storage path;
- define privacy retention for the raw identifiers used to derive pseudonymous
  cluster IDs;
- chaos-test missed intervals, observer restart, disk-full behavior, and
  checkpoint disagreement.
