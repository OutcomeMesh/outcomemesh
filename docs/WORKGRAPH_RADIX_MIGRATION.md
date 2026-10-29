# WorkGraph radix activation and offline migration

WorkGraph block version 3 uses state commitment v1 from
[STATE_RADIX_V1.md](STATE_RADIX_V1.md). It is an explicit development-network
option. This procedure does not authorize mainnet activation or supply a public
upgrade vote, independent signature policy or checkpoint approval.

## Consensus boundary

The WorkGraph parameters pin two heights: `ActivationHeight` and
`RadixActivationHeight`. A radix height of zero retains block version 1. Otherwise
it must be at or after WorkGraph activation. Below the radix height, WorkGraph
requires block version 1 and commitment 0. At and above it, WorkGraph requires
block version 3 and commitment 1. The rule applies separately on every fork.

At the first v3 block, the executor builds the radix tree from the exact parent
resources before applying the predecessor's reward or executing transactions.
Resource bytes, IDs, owners, balances, maturity, the predecessor's earning and
the fee queue are preserved. Transaction receipts use version 2 with radix
post-state roots. Subsequent execution updates only affected state paths.
Reorganizations replay the same boundary on the alternative ancestry.

A protocol-2 genesis already has radix state. It may enter WorkGraph only when
the two activation heights are equal. A protocol-0 base may use that same schedule
and convert at its first WorkGraph block. A later boundary requires a commitment-0
parent; an already converted parent at that boundary is invalid.

V3 keeps the WorkGraph header layout, with leading `uint16_be(3)`. Its seal's
payload root hashes the same ordered fields as v1 under the separate domain
`OMESH/workgraph/payload/v3`: transaction root, receipt root, state root,
predecessor work root, fee queue root and `uint64_be(fee_award)`. The domain binds
the format to the proof of work. Changing only the header version invalidates
the seal commitment. Share encoding, work targets, reward rates, delay and fork
choice are unchanged.

## Stored profile and peer negotiation

The original 64-byte `OMWORK\0\1` activation profile is unchanged and means a
zero radix height. A nonzero height uses the 72-byte `OMWORK\0\2` profile: the
original fields followed by `uint64_be(radix_height)`. Both are strictly decoded.
The work-store configuration hash binds the nonzero schedule under
`OMESH/workchain/config/v3`. Editing an existing profile does not convert its
store; opening with a different schedule is refused.

Chain hello version 3 adds `uint64_be(radix_height)` after `MaxFrameBytes`. It
requires a nonzero height at least equal to WorkGraph activation. Hello version
1 has no appended height and means zero. Nodes require identical schedules
before exchanging chain data. Old nodes reject the new hello and block version.
The WorkGraph relay context already commits the payload root, so share relay
requires no new share encoding.

## Eligible source

The initial migration command accepts a stopped, unbound WorkGraph directory
with its original commitment and complete retained history. It refuses:

- an already scheduled radix chain;
- a radix height at or below any retained block, including nonselected forks;
- pruned WorkGraph history;
- storage bound to custody ownership, position pins or operational effects;
- missing or incomplete forest metadata and a pending activation;
- an existing destination or overlapping source and destination paths.

The source is opened read-only with its original database locks. No bootstrap,
metadata repair or key copying occurs. Keep its paths and contents under the
operator's exclusive control throughout the operation. Database locks do not
protect against privileged path replacement or copied directories.

The first implementation permits at most 4,096 retained blocks and 64 MiB of
canonical block bytes. A conservative resource-version work estimate is capped
at 1,000,000. These limits bound the replay request before destination creation;
opening an existing database still materializes its retained state. Larger
histories need a separately designed streaming migration.

Manifest v2 and statement/checkpoint v1 bind the new schedule. A separate
[archive and protected-storage procedure](RADIX_ARCHIVE_STORAGE_MIGRATION.md)
preserves old archive objects, retained effects and the original position journal.
The complete-history command above still refuses protected or pruned sources.
A separate [local custody transition](CUSTODY_RADIX_SCHEDULE.md) preserves
active Audit/Serve tickets and wraps original receipts with explicit schedule
consent. Reviewed completion, remote execution and canonical-prefix pruning
remain gated until their full admission and retention paths carry that scope.

## Operator procedure

Stop the source node. Choose a fresh destination with an existing parent directory
and a future height agreed by the operators of this development network. For a
source whose highest retained block is below 100:

```sh
omd work-migrate-radix --source ./data/work-old --out ./data/work-radix \
  --radix-height 100 --mode review
```

Review emits the source tip, maximum retained height, block count, profile IDs,
ordered inventory ID, history budget and a preview radix root. The preview only
re-encodes resources at the current selected tip; it is not the future activation
block root. The review ID also binds both resolved directory paths. Review does
not create the destination or contact peers.

Run with the exact returned ID:

```sh
omd work-migrate-radix --source ./data/work-old --out ./data/work-radix \
  --radix-height 100 --mode run --expected-review-id <review-id>
omd work-status --data ./data/work-radix
omd work-verify --data ./data/work-radix
```

Run recomputes the review while holding the source locks. A changed source,
height, destination or profile invalidates the pin. It then reserves the output
path exclusively and writes a durable pending activation before the genesis or
ledger. All retained legacy and WorkGraph blocks are replayed. The selected tree
and each tree's incumbent ancestry are replayed first to preserve exact-work
ties. After replay, the destination is closed and reopened read-only; its selected
tip and all retained block bytes must match the source inventory. Only then is
`radix-migration.json` written and the activation profile published.

The output contains chain history and the new activation profile. Wallet files,
daemon keys, peer books, telemetry, custody keys and operator journals are not
copied. Provision the node identity and network settings separately. The source
continues to represent the old schedule and remains available for inspection.

## Interrupted or uncertain completion

If replay stops before publication, `work-activation.pending` remains and ordinary
chain commands refuse the directory. `work-enable` cannot publish that pending
migration. Retain the incomplete directory for diagnosis and use a new destination
for another reviewed attempt. The command never overwrites or automatically
resumes a previous attempt.

A lost final reply may occur after the profile was published. Inspect the actual
output, `radix-migration.json`, `work-status` and `work-verify` before deciding
whether another attempt is needed. Do not infer failure or success from the lost
reply alone.

Migration does not revoke the source or stop an operator from running an old
copy. Schedule negotiation prevents those nodes from joining the new chain
session; it is not independent key or storage fencing. Network cutover and
rollback decisions remain explicit operator responsibilities. Do not run both
copies as the same operational participant.
