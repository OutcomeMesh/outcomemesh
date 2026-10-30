# Prune outcomes after schedule migration

This workflow resolves original archive-bound Prune obligations after their local
assignment v0 owners adopt a radix schedule. It preserves the old inventory,
request, admissions, executor pair and operation IDs. The final command is a
version 2 Complete carrying the selected owner's schedule ID, original ticket and
original effect or cancellation ID.

The commands operate on existing local owners under exclusive administration.
They neither execute deletion nor create replacement stores. Copied signing keys
and complete copies of owner/pin roots remain outside this local guarantee.
Remote assignment v1 and profile-5 migration are not supported by this adapter.

## Evidence and supported actions

| Original executor state | Allowed action |
| --- | --- |
| Confirmed Admitted, no retained start | Explicit cancellation before start; no ticket completes automatically. |
| Retained start, result or cancellation with an unconfirmed independent record | Explicit confirmation of that exact record. A confirmed start remains unresolved. |
| Confirmed Started, matching effect retained by the migrated protected database | Retain the old effect in the original executor. No deletion is repeated. |
| Confirmed Started, effect absent or inaccessible | Keep the obligation open. Absence, timeout and restart do not prove no effect. |
| Confirmed Succeeded or Cancelled | Export historical evidence, sign and apply completion separately for each selected original owner. |

Success must retain the original inventory-bound start and matching effect.
Cancellation keeps the original executor binding and has no start or inventory
binding added retroactively. An already confirmed result remains historical
on retry; it is not a new claim that archives are available now.

The selected original ticket must actually exist in the current owner history.
A co-signed inventory alone is insufficient. Scope proofs are checked against the
original inventory's attestor policy and checkpoint. Completion refuses a
changed ticket, different evidence, unrelated pending attempt or replaced owner.
Completed operation IDs remain spent; assignment limits are never increased.

## Inspect and retain the outcome

Use the original independently retained inventory and policy IDs. The schedule
proof selects one original assignment; use its corresponding authority roots.
The executor pair is always the original primary operation's pair.

```sh
omd work-prune-migrated-outcome \
  --inventory /operator/original.inventory \
  --inventory-id <original-inventory-id> --policy-id <original-policy-id> \
  --schedule-proof /operator/replica-a.schedule --schedule-id <schedule-id> \
  --authority /authority/original-a --authority-pins /pins/original-a \
  --executor /executor/original-prune --executor-pins /pins/original-prune
```

Review is the default and changes no business state. Reports include a hexadecimal
`review_id`, `confirmed_sequence`, `confirmed_head`, and, when eligible, an
`outcome_id` with `outcome_kind` equal to `effect` or `cancellation`. The reported
position describes the review before an action. Inspect again after mutation.

With a confirmed outcome and no pending authority attempt, repeat with
`--mode publish --expected-review-id <review-id> --out <outcome-file>`.
The file uses the existing effect or cancellation encoding. It is immutable;
lost output can be retried with the same content. Exporting evidence grants no
execution authority and completes no ticket.

Only the primary assignment may use these additional explicit modes:

- `cancel-before-start` requires confirmed Admitted state with no pending executor
  transition. It holds the original primary operation guard under its new scope
  through the existing cancellation intent, record and confirmation. A retained
  start, even an unconfirmed one, blocks this branch.
- `resume-executor` confirms one already retained start, result or cancellation.
  It never invents a branch or opens the chain. Review again before the next action.
- `recover-effect` requires the original migrated database and its position pins.
  First review with the storage arguments below, then repeat that exact input with
  `--mode recover-effect --expected-review-id <review-id>`.

Recovery storage arguments are `--data <separate-activation-source>`,
`--chain <original-chain>`, `--chain-pins <original-position-pins>` and
`--storage-migration-id <original-migration-review-id>`. Supply the original
storage policy where defaults differ: `--max-history-bytes`, `--fork-retention`,
`--checkpoint-every`, `--checkpoint-keep` and `--canonical-retention`.
The source ledger is opened read-only. The migrated database must match the
original storage pair, storage ID and reviewed radix height. Pending storage
confirmations require the existing storage recovery procedure first.

The other modes reject storage arguments. Recovery retains only a matching old
effect, so expired current receipt freshness does not turn this historical read
into a new cleanup grant. It never refreshes receipt deadlines.

## Sign and apply completion

For each original replica, inspect its current sequence/head. Consumer signing
uses these explicit values rather than finding a newer head automatically:

```sh
omd work-prune-migrated-command-sign \
  --inventory /operator/original.inventory \
  --inventory-id <original-inventory-id> --policy-id <original-policy-id> \
  --schedule-proof /operator/replica-a.schedule --schedule-id <schedule-id> \
  --outcome /operator/original.outcome --outcome-id <outcome-id> \
  --outcome-kind <effect-or-cancellation> \
  --expected-sequence <sequence> --expected-head <head-id>
```

Repeat with `--mode sign --expected-review-id <review-id>
--consumer-key <original-consumer-seed> --out <command-file>`.
Use `work-prune-migrated-command-cosign` with the same evidence and position,
plus `--command <command-file>`. Its signing mode requires its own review ID,
`--authority-key <original-authority-seed>` and `--out <entry-file>`.
Review mode rejects key/output flags, including empty ones. Wrong review IDs are
rejected before the key is read. Signature domains remain the existing v2 domains.

Review `work-prune-migrated-command` with the inventory/proof arguments, original
owner and executor roots, outcome arguments, and `--entry <entry-file>
--entry-id <entry-id>`. Repeat with `--mode apply --expected-review-id <review-id>`.
The original confirmed executor outcome is checked again before accepting the
entry. Only the selected ticket completes; other owners and pending work remain
unchanged. No source journal, private key or chain is needed for completion.

An exact retained authority attempt requires a new review and explicit
`--mode resume`. A confirmed exact historical retry can use `apply` after another
review; it does not append a second completion. A different completion of an
already completed ticket is refused. Output failure does not undo durable work.

## Compatibility and remaining work

No request, inventory, effect, cancellation or signature format changes. The
local review hash uses `OMESH/local/migrated-prune-review/v0` and commits the
original pins, reviewed positions, exact input paths and, for recovery, protected
storage position, migration ID and storage policy. It is not a network certificate.
Frozen completion signatures for both outcomes are in
`node/custodyauthority/store/testdata/migrated_prune_completion_v0.json`.

Unstarted operations without a prepared original inventory, raw unprotected
executors and unknown starts without a matching retained effect are not resolved
by this workflow. Full-copy fencing, independent deployment and the remote
schedule transition remain separate gates. This local slice does not authorize
a mainnet launch.
