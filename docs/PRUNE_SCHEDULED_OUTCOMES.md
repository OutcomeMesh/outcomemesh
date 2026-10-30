# Outcomes of scheduled Prune work

Request v3 tasks use [independent pre-deletion claims](PRUNE_FENCE.md).
Their missing-result and pre-start cancellation rules are stricter than the
legacy local workflow described below: a cold candidate stays held, and a bare
effect cannot recreate its session signature.

Status: local pre-alpha operator workflow for tasks admitted on the migrated
schedule. Use [the scheduled cleanup procedure](CUSTODY_RADIX_SCHEDULE.md) to
prepare, sign, admit and package a task. Pre-migration tasks use
[the original-ticket procedure](PRUNE_MIGRATED_OUTCOMES.md).

The original plan, inventory, executor, independent pins and authority journals
remain in place. These commands do not create owners, restore lost pins, renew
receipts or change storage schedules. Keep all roots under exclusive trusted
administration. Copying an entire owner/pins pair is outside this local protection;
independent remote fencing remains a separate deployment requirement.

## Review the original owners

Use the independently retained IDs and the original primary assignment:

```sh
omd work-prune-scheduled-outcome \
  --plan /srv/om-artifacts/cleanup.plan --plan-id <plan-id> \
  --inventory /srv/om-artifacts/cleanup.inventory --inventory-id <inventory-id> \
  --assignment-id <primary-assignment-id> \
  --authority /srv/om-authority --authority-pins /srv/om-authority-pins \
  --executor /srv/om-prune --executor-pins /srv/om-prune-pins
```

The default mode only reviews. It requires the exact accepted admission in the
selected authority history and its unchanged operation, plus the original
executor admission and binding. The report contains `review_id` and the retained
positions. A confirmed terminal result also has `outcome_kind` and `outcome_id`.
Review rejects output and action-only flags. Independently check the displayed
identities and positions before supplying that review ID to an action.

## Cancel before execution

Repeat the reviewed command with
`--mode cancel-before-start --expected-review-id <review-id>`. Only the primary
assignment can perform this action. The executor must have a confirmed admission
and no retained start or pending confirmation. No chain, archive body, source
journal or signing key is needed.

Cancellation retains the existing `PruneCancellation` bytes in the original
executor and independent pin history. Its request ID includes the schedule; its
other bindings identify the original primary assignment, ticket and executor
pair. No wire format or signing domain changes. Cancellation is terminal for
execution but leaves every replica ticket open until separately completed.

An already started operation cannot cancel, even when no effect can be found.
A timeout or missing file is not proof that the operation did nothing.

## Resume an interrupted executor record

Review the same primary owner again without storage arguments. If the report
shows a pending start, result or cancellation, use
`--mode resume-executor --expected-review-id <review-id>`.

This confirms only the exact retained transition. It does not open the chain,
execute deletion or close a ticket. A resumed start remains unresolved. A pending
authority command must be handled separately with its original co-signed entry
through `work-prune-scheduled-command --mode resume`.

## Recover a committed result

For a confirmed start, add these storage arguments to the initial review:

```sh
  --data /srv/om-activation-base \
  --chain /srv/om-chain --chain-pins /srv/om-chain-pins \
  --storage-migration-id <original-storage-migration-id>
```

Supply the original storage policy using `--max-history-bytes`,
`--fork-retention`, `--checkpoint-every`, `--checkpoint-keep` and
`--canonical-retention` where its values differ from the command defaults.
The history budget defaults to the retained activation profile. The activation
base is opened read-only and must match the original plan's network and base.
Storage roots must be separate from that base, owners and input artifacts.

Review binds the migration ID, original storage pair, confirmed database position,
paths and policy in a separate review domain. Repeat these same inputs with
`--mode recover-effect --expected-review-id <review-id>`.

Recovery reads only the exact committed effect for the original ticket and
retains it in the original executor. It does not repeat deletion and does not
require the archive bodies or source custody journals to be online. A missing
or unreadable effect leaves the executor unresolved. A pending storage position
must first follow the existing explicit storage-confirmation procedure; this
command cannot repair or infer that position. Lost command output does not undo
a retained result. Review again before retrying.

## Export and complete each replica separately

For a confirmed effect or cancellation, review without storage arguments and
repeat with `--mode publish --expected-review-id <review-id> --out <outcome-file>`.
The immutable file contains the original terminal bytes, not a new certificate.
An exact publication retry preserves those bytes. Output cannot overlap input
artifacts or the owner roots. The existing `work-prune-scheduled-effect` command
continues to export successful effects only.

Use `work-prune-scheduled-command-sign` and
`work-prune-scheduled-command-cosign` with `--kind complete`, the selected replica,
original plan/inventory and its explicitly reviewed sequence/head. Supply exactly
one evidence pair:

| Outcome | Signing inputs |
| --- | --- |
| Committed effect | `--effect <file> --effect-id <independent-id>` |
| Pre-start cancellation | `--cancellation <file> --cancellation-id <independent-id>` |

Each role reviews separately, then signs with its own key and exact review ID.
Apply the co-signed entry with `work-prune-scheduled-command`, the inventory and
original selected owner. Do not supply a source journal for completion.
Application verifies the terminal result in the original executor, not just the
exported file or signatures. A fabricated cancellation cannot close a ticket.

Completion changes only the selected ticket. Other replicas, old pending work,
spent operation IDs and evidence remain intact. Interrupted acceptance requires
an explicit exact `resume`; a confirmed retry does not spend or complete twice.
Remote schedule transitions and independently enforced resolution of unknown
starts remain open. This local procedure does not authorize mainnet launch.
