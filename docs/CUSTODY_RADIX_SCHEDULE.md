# Custody migration to a radix schedule

Status: implemented for an original local custody assignment v0.
Remote assignment v1, governed profile-5 cutover and canonical pruning remain
separate gates. This document does not authorize public network activation.

## Preserved state

The transition appends one record to the original authority history. It retains
the assignment ID, authority and replica keys, consumer membership, operation
limit, pending limit, admission IDs, spent operations, unresolved tickets, stop
intent and any completed results. A stopping assignment remains stopping.
An assignment can migrate once. A retired assignment cannot migrate.

The original archive, receipt and journal remain the physical evidence stream.
The target is a signed manifest v2 successor with exactly the same blocks,
anchor, chunk bytes and chunk IDs. Its activation height must follow that
anchor. Both checkpoints must satisfy the independently retained original
attestor policy. See [archive migration](RADIX_ARCHIVE_STORAGE_MIGRATION.md).

Migration does not renew storage, sample a chunk, release a ticket, credit a
reward or change `StoredAt` or `RetainUntil`. A later renewal still requires a
real custody exchange and an append to the original journal.

## Authority record

Command and entry version 2 use the existing magic and field order, with one
32-byte `ScheduleID` between `EvidenceID` and `ActorPublicKey` in the command.
The ID is mandatory and commits the canonical schedule proof. Command signatures,
entry signatures and entry IDs use their respective
`OMESH/custody-authority/.../v2` domains. Commands are 308 bytes; entries are
414 bytes. Versions 0 and 1 remain 276 and 382 bytes respectively, with unchanged
encodings and domains. Legacy fixed-width admission/completion frames remain
unchanged and reject version 2.

Kind 7, `MigrateSchedule`, has zero purpose, operation, ticket and evidence fields.
The original replica signs it; the original authority co-signs it. Its expected
sequence and head select the exact original authority position. It is accepted
only on assignment v0, in accepting or stopping phase, before any prior schedule
transition. The v0 history bound reserves one additional entry, `2*N+3`, without
increasing the `N` operation budget or consuming drain/retirement capacity.

After acceptance, subsequent commands must use version 2 and the exact schedule
ID. Existing tickets keep their IDs and actors. A live operation guard checks
the schedule on every action. Previously opened adapters and legacy reopen
requests have an empty schedule and are refused. An exact already committed
command retry is a historical lookup and cannot execute work.

The state machine verifies signatures and accounting. The original coordinator
adds source validation: generic `Append` refuses kind 7. The dedicated migration
method opens the original journal, checks its policy against the original
assignment, holds its decision lock, verifies the exact selected receipt and
journal cursor, then uses the existing intent-before-decision/confirmation path.
An advanced source invalidates an unapplied proposal. A missing owner or journal
is never initialized by migration.

## Proof and storage receipt

`CustodyScheduleProof` uses magic `OMWCSCH0`, version 0, followed by assignment ID,
original journal sequence and head, then six length-prefixed canonical values:
original manifest, target manifest, original checkpoint, target checkpoint,
initial receipt and selected receipt. Its ID domain is
`OMESH/workgraph/archive/custody-schedule/id/v0`. Existing manifest, checkpoint,
receipt and lineage bounds apply. Sequence zero requires the initial receipt
and a zero head. A later cursor requires a renewed receipt.

Portable verification requires the original independently trusted assignment and
attestor policy, plus the full original custody lineage. The selected receipt
must be at or after the migration cursor on that exact prefix. A signed receipt
alone does not establish this relationship. The proof is historical evidence,
not an execution grant or a current authority observation.

`ScheduledReplicaReceipt` uses magic `OMWSRCP0`, version 0, the schedule ID, a
length-prefixed original receipt and a 64-byte signature by that receipt's
original replica. Its signature domain is
`OMESH/workgraph/archive/scheduled-receipt/signature/v0`; its ID domain is
`OMESH/workgraph/archive/scheduled-receipt/id/v0`. It contains no independent
timestamp or retention term. Verification checks the proof and full lineage;
freshness and remaining retention are checked separately at the consuming
operation's time. Wrapping an expired receipt cannot make it current.

A scheduled journal handle pins the migration prefix during every replay,
including cached response delivery and later appends. An already-open handle
rejects replacement with a valid but shorter original journal. This is a local
owner guarantee: copying both the authority and its independent pin store, or
using raw keys outside these adapters, is not fenced by this transition.

## Operator workflow

Keep the original assignment, original archive, both signed checkpoints, initial
receipt, full journal, original authority and its independent intent directory.
Upgrade all local consumers before the transition. Older binaries cannot read
version 2 authority entries. Do not downgrade or restore a pre-transition copy
as a recovery procedure.

`omd work-archive-custody-migrate-radix` provides these modes:

| Mode | Required additional input | Result |
| --- | --- | --- |
| `prepare` | Original and target manifests/checkpoints, initial receipt, original journal, new output file | Immutable proof and schedule ID |
| `review` | Proof and independently retained schedule ID | Schedule, original receipt and migration cursor |
| `sign` | Proof, explicit expected sequence/head, original replica key, new output file | Replica-signed migration command |
| `cosign` | Proof, signed command, original authority key, new output file | Co-signed entry and its `artifact_id` |
| `apply` | Proof, entry and entry ID, original authority/pins/journal | One durable transition or exact retained retry |
| `inspect` | Proof and original authority/pins | Confirmed position, outstanding attempt and original obligations |
| `resume` | Proof, exact pending entry and entry ID, original authority/pins | Finishes only that retained migration attempt |
| `receipt` | Proof, original journal, exact selected receipt ID, original replica key, new output file | Signed schedule wrapper without changing the journal |

Every mode requires `--assignment` and `--assignment-id`. Supply original
attestors as one comma-separated `--schedule-attestors` value and retain their
original quorum with `--schedule-quorum`. Never take trust keys from the proposed
checkpoint. Existing custody policy limits must match the original assignment.

Prepare uses `--manifest`, `--checkpoint`, `--new-manifest`, `--new-checkpoint`,
`--receipt`, `--journal` and `--out`. Other modes use `--schedule-proof` and
`--schedule-id`. Signing requires `--expected-sequence`, `--expected-head`,
`--key` and `--out`; co-signing uses `--command`, `--key` and `--out`. Encrypted
keys use the existing `--key-password-file` option. Application/recovery require
`--entry`, the co-signing output's `--entry-id`, `--authority` and
`--authority-pins`; fresh application also requires `--journal`. Receipt mode
requires `--selected-receipt-id`. Artifact outputs must be new files outside
live owner roots. Retain the proof independently before signing or applying it.

The managed Audit, Serve and paired CLI commands accept `--schedule-proof`,
`--schedule-id`, `--schedule-attestors` and `--schedule-quorum`. Continue supplying
the original manifest and initial receipt. These commands reuse the original
admissions, journal and object store. Review IDs commit the schedule, and every
execution rechecks it. Receipt wrappers are explicit output artifacts; custody
wire messages and historical challenge/receipt signatures stay unchanged.

If output is lost, inspect the original owner. An unapplied durable intent stays
held until explicit recovery. A confirmed retry does not reapply migration.
Unknown custody execution outcomes remain pending; migration is not evidence
that they did or did not execute.

## Completing retained Audit and Serve tickets

The existing terminal and command CLI accepts the same four explicit schedule
flags as the managed pair: `--schedule-proof`, `--schedule-id`,
`--schedule-attestors`, and `--schedule-quorum`. The original manifest, assignment,
initial receipt, intent and immediate predecessor remain required. Each completion
uses its original admission; Audit and Serve drain independently.

1. Use `work-archive-custody-terminal` in review mode with the original authority,
   pins, journal and admission. Enter control mode and issue `review`, then
   `capture <review-id>` to publish the exact selected terminal to `--out`.
   Capture requires the original pending ticket and current journal head. It
   replays the complete original lineage, including the migration cursor.
2. Review `work-archive-custody-command-sign --kind complete` with the captured
   `--terminal` and `--terminal-id`, original `--admission` and `--admission-id`,
   and explicitly retained `--expected-sequence` and `--expected-head`.
   Sign only that review with the original consumer key.
3. Review and co-sign that command with `work-archive-custody-command-cosign`
   and the original authority key. Neither step opens an owner or selects a
   newer authority position.
4. Use `work-archive-custody-command-apply` with the exact entry and terminal.
   Review the owned service, then issue `apply <review-id>` in control mode.
   An outstanding retained intent requires `resume <review-id>` instead.
   Close the service before transferring its original roots to another process.

These commands use the existing CLI input and artifact rules described in the
[custody operator guide](CUSTODY_OPERATOR_CLI.md). Add the schedule flags to every
stage, including review, signing, capture, application and recovery. Omitting
those flags does not adopt the owner's current schedule implicitly.

Terminal version 1 retains magic `OMCATRM0` and adds the 32-byte schedule ID
immediately after the assignment ID. The original admission, intent and journal
entry follow as length-prefixed canonical values. Its ID domain is
`OMESH/custody-authority/custody-terminal/id/v1`. Version 0 is unchanged and cannot
carry a schedule ID. A version 1 terminal is evidence for its exact schedule;
it does not create a new response or change receipt dates.

Reviewed completion commands and entries use authority version 2 and its
signature domains. `EvidenceID` commits the complete version 1 terminal;
`TicketID` remains the original version 0 admission ID. Review limits include
the reserved migration entry. The local command-source identity adds the
schedule ID after assignment, intent and predecessor IDs, under
`OMESH/local/custody-command-scope/v1`. With no schedule the original v0 scope and
review behavior remain unchanged.

A fresh completion holds the original coordinator and source journal decision
through durable application. Recovery checks the exact retained intent and
schedule. A confirmed retry returns the retained entry, including after the
other ticket completes. It does not release another ticket or refund spent
operation capacity. Missing results, advanced unrelated heads and unknown
execution outcomes remain held.

## Inspecting storage quorum

`omd work-archive-custody-quorum` inspects existing owners and journals without
changing them. It requires an independently pinned target statement and explicit
original attestor and replica trust lists. For example:

```sh
omd work-archive-custody-quorum \
  --sources /operator/scheduled-sources.json \
  --checkpoint /operator/target.checkpoint \
  --checkpoint-id <target-statement-id> \
  --attestors <attestor-key-1>,<attestor-key-2> --attestor-quorum 2 \
  --replicas <replica-key-1>,<replica-key-2> --replica-quorum 2 \
  --max-receipt-age-seconds 1000 --min-remaining-term-seconds 100 \
  --max-challenge-lifetime-seconds 60 --max-proof-age-seconds 100 \
  --max-renewal-term-seconds 20000
```

The JSON source list contains between 2 and 64 objects. Each object supplies
these exact fields; use independently retained IDs and existing canonical paths:

```json
{
  "assignment": "/operator/replica-a.assignment",
  "assignment_id": "<original-assignment-id>",
  "authority": "/replica-a/authority",
  "authority_pins": "/replica-a/authority-pins",
  "journal": "/replica-a/custody",
  "schedule_proof": "/operator/replica-a.schedule",
  "schedule_id": "<replica-a-schedule-proof-id>",
  "scheduled_receipt": "/operator/replica-a.receipt",
  "scheduled_receipt_id": "<scheduled-receipt-id>"
}
```

The list is bounded to 1 MiB. Duplicate or unknown JSON fields, omitted required
fields, extra JSON values and duplicate flags are rejected. Each replica has its
own schedule proof ID because its assignment and journal cursor are distinct.
The original custody policy must match each assignment. A mixed policy requires
separate preparation; this command does not infer policy limits from evidence.

Inspection holds all original coordinators and journal decisions until the final
freshness check. Every owner must have confirmed the selected schedule, have no
unconfirmed authority intent and be unretired. Outstanding ordinary tickets are
allowed and remain unchanged. Each wrapped receipt must be the current receipt
in that original journal. All votes must name one exact original archive and
one target statement. Repeated keys, locations, assignments or schedule proofs
cannot count twice. Pending, missing, replaced, shortened and overlapping roots
are refused. Owners close before output, including output failure/cancellation.

`ScheduledAvailabilityBundle` is a separate canonical format: magic `OMWSAVL0`,
version 0, target statement ID, manifest ID, anchor ID, radix activation height,
a bounded count and length-prefixed scheduled receipts sorted by replica key.
Its ID domain is `OMESH/workgraph/archive/scheduled-availability/id/v0`.
The bundle is at most 64 KiB. Verification also requires the independently
retained original assignments, original attestor policy, replica policy and
complete lineage for each vote. The aggregate manifest and journal evidence
budget is 256 MiB; each lineage has at most 1,024 entries. No clocks enter
consensus: availability is evaluated at the caller's inspection time, using
only original signed receipt dates. The CLI samples time again after replay and
owner/source rechecks. Its JSON report includes the bundle, its ID and the final
`checked_at` time.

The report is historical evidence of this inspection. It grants no future
execution permission and is not accepted as a canonical pruning permit. Distinct
location commitments do not independently prove separate operators or machines.
Copying all original owner roots and their keys remains outside this local fence.

## New Audit/Serve admissions

The existing custody command preparation, consumer signing, authority co-signing
and controlled application commands accept new admissions when an explicit
schedule proof and ID are supplied. An Audit operation binds the new audit
intent; Serve binds the challenge produced from that intent. Both retain the
original assignment, initial receipt, journal and budget. The intent selects the
current original journal sequence, head and receipt. Use a new intent and a new
artifact directory for each cycle; do not initialize replacement journals.

The resulting command/entry uses v2 and the original assignment's schedule ID.
Static admission review requires sequence 1 through `2 * MaximumOperations - 1`.
The original coordinator still checks its actual position, phase, pending limit,
spent operations and current scope. A signed draft is not an accepted ticket.
Completing a previous ticket frees a pending slot without restoring spent
capacity. Reissuing a completed intent or challenge remains forbidden.

## Scheduled canonical cleanup

The cleanup path uses original assignment v0 owners after their explicit schedule
migration. It accepts same-prefix target archives, with each target manifest and
checkpoint bound to the configured radix height. It also works after the selected
chain crosses that activation height; replay keeps the current radix resources,
fee queue, balances and root intact.

`ScheduledPruneInventory` is a separate, immutable preparation artifact. Magic
`OMCSPINV`, version 0, precedes the canonical request, executor binding, storage
pair ID, target checkpoint, original attestor policy, replica policy and selected
replicas in strict original-key order. Each replica carries its original
assignment, schedule proof, wrapped current receipt and co-signed Prune admission.
The ID domain is `OMESH/custody-prune/scheduled-inventory/id/v0`; the maximum size
is 64 MiB. Full original journal lineages are read at execution rather than
trusted from a supplied report. Their aggregate replay budget remains 256 MiB.

The primary request v2 binds its original assignment and schedule, consumer,
protected StorageID and exact target floor. Every selected replica admits that
same request ID under its own original assignment and schedule. Duplicate keys,
locations, assignments, directories and overlapping owner roots are refused.
The package commits the independently retained executor and storage pair IDs.

Preparation currently uses `BuildScheduledPruneAdmission`, original coordinator
application, `CreatePinnedPruneExecutor`/`Admit` and `SaveScheduledPruneInventory`.
Create a separate executor pair for the new operation. Preserve every old
executor, original authority pair, pending ticket and journal. The legacy offline
executor preparation command can retain a v2 request, but legacy prune signing
and fixed-width delivery commands do not accept scheduled commands. A complete
reviewed CLI preparation/signing/application workflow is still a separate gate.

The owned execution CLI consumes an already prepared, independently pinned
inventory and existing original roots:

```sh
omd work-archive-prune-scheduled \
  --mode review \
  --inventory /operator/scheduled.inventory \
  --inventory-id <independently-retained-inventory-id> \
  --data /operator/activation-base \
  --sources /operator/scheduled-prune-sources.json \
  --executor /owners/prune-executor \
  --executor-pins /pins/prune-executor \
  --chain /owners/workchain \
  --chain-pins /pins/workchain \
  --storage-migration-id <original-storage-migration-review-id> \
  --canonical-retention <configured-retention> \
  --max-challenge-lifetime-seconds <original-policy-value> \
  --max-proof-age-seconds <original-policy-value> \
  --max-renewal-term-seconds <original-policy-value>
```

The source file is a bounded strict JSON array. Supply one entry per selected
original assignment, with these exact field names:

```json
[{
  "assignment_id": "<original-assignment-id>",
  "authority": "/owners/replica-a-authority",
  "authority_pins": "/pins/replica-a-authority",
  "journal": "/journals/replica-a",
  "directory": "/archives/replica-a-target"
}]
```

The actual quorum requires at least two distinct selected replicas. The example
shows the fields for one row. Storage policy and journal/replay limits must match
the retained deployment. `--data` supplies an existing read-only activation base;
it must be disjoint from all operational roots and input artifacts.

Review returns a ReviewID committing the package, configured paths and policies,
storage migration, executor position, every authority position and journal head.
Execute repeats the same arguments with `--mode execute --expected-review-id
<ReviewID>`. It reopens the original owners, verifies the exact review, reads all
current original lineages and replays every full target archive. The final
storage authorization rejects stale receipts, insufficient remaining retention,
backwards time, cancellation and substituted owners. Original authority and
journal guards remain held until the durable result is retained. All owners
close before CLI output.

Before deletion, the executor durably retains a start bound to this inventory.
Storage atomically commits the deletion, floor, byte accounting and exact v2
effect. A crash after that commit can be resolved with a new review and
`--mode recover --expected-review-id <new-ReviewID>`. Recovery reads the existing
effect and never runs deletion again. A start without a proven effect remains
held; absence is not a no-effect certificate. Pending independent executor or
storage confirmations require their own explicit recovery, not implicit startup
repair. Lost stdout does not roll back a retained effect.

Cleanup completes no tickets. `CompleteScheduledArchiveReplica` accepts a separate
consumer-signed, authority-co-signed v2 Complete for each original replica after
the exact effect is durably retained. It verifies the actual admitted operation,
resynchronizes the immutable inventory and holds the original owner through
acceptance. Exact retries retain the same evidence; all other pending and spent
work remains unchanged. Reviewed CLI preparation for these completions remains
open.

These are trusted local owner APIs. Keep owner roots, pins and immutable archive
copies under exclusive administration during each operation. A location ID does
not prove physical independence, and copied keys plus all owner/pin roots are
not fenced by this local workflow. The implementation does not establish an
independently operated remote quorum.

## Remaining gates

Scheduled pruning preparation/signing/admission and per-replica completion need
an end-to-end reviewed CLI workflow. Reconciliation and unknown-start resolution
need their own evidence paths; they must not clear outstanding work or manufacture
a response. Legacy fixed-width transports still reject v2.

Remote assignment v1 and profile-5 require a versioned scope transition covering
witnesses, guards, execution plans and source acceptance. They remain refused by
this migration. New native post-activation archive custody, independent operator
deployment and larger streaming migrations also remain open. No mainnet readiness
gate is closed by this bounded local implementation.

## Canonical reference values

The deterministic fixtures in `schedule_test.go` and `custody_schedule_test.go`
fix these IDs. They are format references, not live network identities.

| Artifact | ID |
| --- | --- |
| Version 2 migration entry | `600d67ae84ee481323e5f07d409a5ff6eb0b97bef120df6ed1d5bf2034ed1732` |
| Schedule proof | `439e603f95f1d9ecff0372ef0a4150c3848e0a8a366901b85582c85451cdc290` |
| Scheduled receipt | `0e1a776acaf1e74056c05024bfbdcc04272ad003751237308523d7e0b76be31d` |
| Version 2 reviewed completion entry | `a2140ed64a446e75bc486a57bd795f1897bd66aacf6fbc615e8571fa91bc6f9b` |
| Version 1 scheduled terminal | `ab32d8670864c297614117b67a7f2ee749b1d231abfc96939833d26c301461fa` |
| Scheduled availability bundle | `a6d73873151636c75628811875244828d0d523aa818797378d3ed7294135e33e` |

The frozen scheduled-pruning fixture uses disposable test keys and is stored in
`node/custodyauthority/store/testdata/scheduled_prune_v0.json`. It fixes:

| Artifact | ID |
| --- | --- |
| Scheduled prune inventory v0 | `0d2a41131debe84ee9c8555fa03fbd0ebca9fc6f8a9299702668998e8ee5c49e` |
| Scheduled prune request v2 | `4f783c20cdf453dfbcd8b954963f3d39b05ca585f2cb80797d6eb6bc3f75e5e3` |
| Scheduled prune effect v2 | `5d6ec18c4926f6268593539b560a24534d44918385aa20bd75c98b2f61297351` |
