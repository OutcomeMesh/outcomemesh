# Archive and protected-storage migration

Status: experimental, local operator transition. This procedure does not approve
public activation or close a production launch gate.

## Scope

The migration schedules the new WorkGraph root at a future height. Historical
blocks and their roots remain unchanged. At activation, normal block execution
converts the parent resources before rewards and transactions, as specified in
[WorkGraph radix activation](WORKGRAPH_RADIX_MIGRATION.md).

Two procedures cover different retained objects:

| Object | Procedure | Preserved evidence |
| --- | --- | --- |
| Immutable archive v1 | Publish a signed v2 successor in a fresh directory | Original archive, checkpoint, chunk bytes and IDs |
| Position-pinned WorkChain | Commit a future schedule in the original database | Storage ID, pin identity and history, canonical floor, states, fee queues and prune effects |

Keep all original receipts, admission records, custody journals, outcome proofs
and retention deadlines. Neither procedure refunds spending, closes unknown
work, renews a receipt, creates a signing identity or transfers a live assignment.
Bound stores without independent position pins cannot use this transition.
Attaching a fresh journal to an existing database is not a migration procedure.

## Archive encoding and continuity

Manifest v0/v1 and statement/checkpoint v0 keep their canonical bytes. Manifest
v2 inserts `radix_height:u64_be` immediately after `Binding.BaseID`. The height
must be nonzero and at least the WorkGraph activation height. V2 manifests use
v1 chunks: chunks remain independent of the terminal anchor. All versioned
canonical bytes participate in the existing object ID and signature domains.

Statement v1 inserts the same field immediately after `BaseID`. Checkpoint v1
contains statement v1; mixed outer/inner versions are rejected. Statement v0
requires zero radix height. Manifest v0/v1 likewise require zero height.
Export and replay require exact agreement between the chain, manifest, trusted
policy and execution parameters. Legacy receipt v0/v1 cannot encode a nonzero
schedule and reject such bindings.

An archive migration starts from a fully replayed v1 archive. The new height is
strictly above its anchor. The proposal has:

* the same network, genesis, activation base, anchor, ancestry and chunks;
* statement sequence equal to the predecessor sequence plus one;
* `PreviousID` equal to the original statement ID;
* manifest v2, statement v1 and the chosen future radix height.

The original attestor trust set and quorum sign this proposal. The migration
verifier permits no replacement trust policy, skipped sequence, different
anchor, extra work or rewritten chunk. Ordinary checkpoint succession still
requires a strictly later anchor; the explicit migration verifier handles this
same-anchor transition. Old v0 chunks require a separate normalization design
and are not accepted by this migration command.

Publication revalidates every source chunk and uses a fresh temporary directory,
file fsync, rename and parent fsync. Existing destinations are refused. The source
is never overwritten. Keep both signed checkpoints outside immutable archive
directories, and retain the original archive until every original retention and
custody obligation is discharged under its original rules.

## Archive CLI

Use a stopped original node as the independently verified activation source.
Supply the original trusted keys explicitly. Review can emit a canonical proposal
file outside the immutable archive:

```sh
omd work-archive-migrate-radix --data ./original-node \
  --manifest ./archive-v1/manifest.omwm --checkpoint ./original-checkpoint.bin \
  --attestor-public-key <key-1> --attestor-public-key <key-2> \
  --radix-height 100 --mode review --statement-out ./proposal.bin
```

Attestors independently inspect and sign that exact statement using the existing
`workarchive.Attest` and `NewCheckpoint` APIs. The CLI does not collect private
keys or create signatures. Supply their canonical checkpoint for publication:

```sh
omd work-archive-migrate-radix --data ./original-node \
  --manifest ./archive-v1/manifest.omwm --checkpoint ./original-checkpoint.bin \
  --attestor-public-key <key-1> --attestor-public-key <key-2> \
  --radix-height 100 --mode run --new-checkpoint ./successor-checkpoint.bin \
  --out ./archive-v2
```

A lost publication reply requires inspecting the existing destination against the
signed manifest. Repeating the command never overwrites it. The successor can be
replayed and restored under the exact new schedule. The restored database is a
new unbound historical replica, not a replacement for an obligated protected
owner. Object transfer also retains the manifest's exact schedule binding.

## Protected storage review and application

Stop and drain the services that own the protected chain and journal. The CLI
acquires both original lifetime locks and opens the separate activation source
read-only. The source node, chain and pins must occupy disjoint existing paths.
The source profile retains the old zero radix height; the command does not edit it.

Review requires no pending position. It scans every database key, including all
retained effects and the canonical floor, with a 64 MiB logical byte ceiling.
The requested height must exceed every retained node and archived header,
including nonselected forks. Larger databases need a future streaming procedure.

```sh
omd work-storage-migrate-radix --data ./original-node \
  --base-id <activation-parent-id> --storage-id <original-storage-id> \
  --chain ./protected-chain --chain-pins ./independent-pins \
  --radix-height 100 --mode review
```

Retain the full review and its `review_id` independently. It binds the original
storage/pair IDs, canonical paths, old and new configurations, complete database
inventory, current position, selected tip, maximum retained height and schedule.
Any intervening write invalidates it. Use the same arguments with:

```sh
--mode run --expected-review-id <review-id>
```

One synchronous batch changes the configuration and adds a permanent migration
receipt plus the next storage position. All other keys retain their exact bytes.
The independent journal writes its intent before the batch and confirms it after
commit. Its original configuration-bound identity is never rewritten. The bounded
migration receipt is fixed metadata, not replay history subject to pruning.

A migrated owner must explicitly open through
`OpenRadixMigratedPositionPinnedWithPolicy` with the new parameters and retained
review ID. The loader verifies the original pin identity, migration receipt,
old/new configuration hashes and matching historical intent. An ordinary old
configuration open fails; an old database with advanced original pins fails.
A new database paired with old pins also fails.

## Interruption and recovery

Use the same paths, IDs and height for all inspection modes:

| Mode | Meaning |
| --- | --- |
| `inspect --expected-review-id ...` | Open the committed new configuration and report its exact database/confirmed/pending positions |
| `confirm --expected-review-id ...` | Flush and confirm only the already committed migration position; never execute migration again |
| `inspect-original` | Inspect the old configuration when the migration batch is absent; makes no disposition |

A failure before the independent intent is durable leaves no accepted migration.
A durable intent without the database batch remains held. Neither `run` nor
`confirm` cancels that intent, replaces pins or declares no effect. If the batch
committed but confirmation was interrupted, cold opening under the exact review
ID exposes the pending position; normal operations remain blocked until explicit
confirmation. A lost reply after confirmation is handled by inspection, not a
second migration. Repeated scheduling is refused even if activation is still
in the future.

## Compatibility and remaining work

This protects against a stale database used with the advancing original journal.
It does not distinguish a complete copy of both database and journal under an
administrator who controls both. The two current servers share administrative
control and do not provide an independent operator domain.

Migrated chains can execute through the scheduled height and reopen with the
original pruned floor and effects. New archive export, exact-schedule replay,
restoration and object transfer support v2 envelopes. Local custody owners can
append a [schedule transition](CUSTODY_RADIX_SCHEDULE.md) while retaining their
original assignment, active Audit/Serve tickets and receipt lineage. Reviewed
Audit/Serve admission and completion now preserve the same accounting. A dedicated
scheduled cleanup path consumes a pinned quorum inventory and rechecks retention
at the storage mutation. Its operator preparation/signing flow and remote/profile-5
cutover remain open. A local migration is not authorization to substitute
new archive IDs in an old inventory or erase an unresolved outcome.

## Canonical reference values

The deterministic archive fixture at height 3, re-bound to radix height 5, gives:

| Object | ID |
| --- | --- |
| Manifest v2 | `33f7bd5b4291c9d9b0d4c347cd2d55ba64ab416b6a77b2b0335445d0cec05ecb` |
| Successor statement v1 | `5e0e8e2ac43a9cb717d266bac439530536859d275730988c38adc8fb72af0257` |

The migration receipt encodes version 0 (`u16_be`), seven 32-byte hashes in order
(storage, pair, roots, old config, new config, inventory, tip), the original
40-byte position (`sequence:u64_be`, commit ID), radix height and maximum retained
height (`u64_be` each), then the next 40-byte position. Total length is 322 bytes.
The roots hash commits two canonical length-prefixed path byte fields, in
database/journal order, under `OMESH/workchain/radix-schedule/roots/v0`. The
inventory is SHA-256 of `OMESH/workchain/radix-schedule/inventory/v0` followed by
all sorted key/value pairs, each byte field preceded by its `u64_be` length.
The review ID hashes the first 282 bytes under
`OMESH/workchain/radix-schedule/review/v0`. The deterministic fixture with hash
first bytes 1 through 7, before `(2, hash-8)`, heights `(10,4)` and after
`(3, hash-9)` has review ID
`5ca7ffe2edaf7a437cebecb6f3ecaecf17900f8c23db0ae75fc7cde51822ef79`.

## Active local custody continuation

[Custody schedule migration](CUSTODY_RADIX_SCHEDULE.md) now provides a separate
original-history transition for local assignment v0. It keeps original tickets,
journals and retention terms while requiring explicit schedule consent on live
Audit/Serve actions. It does not yet enable the reviewed completion pipeline,
remote/profile-5 scope cutover or new canonical pruning.
