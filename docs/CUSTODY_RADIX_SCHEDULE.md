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

## Remaining gates

The version 2 state machine supports draining existing tickets, but the existing
reviewed terminal, offline admission/completion and reconciliation services have
not yet acquired schedule-bound source/evidence formats. Their legacy commands
are refused after migration. Until those adapters are integrated, keep the
original pending obligations; do not manufacture completion or bootstrap a
replacement assignment. Plan this maintenance transition accordingly.

Remote assignment v1 and profile-5 require their own versioned scope transition,
including witnesses, guards, execution plans and source acceptance. They are
explicitly refused by this migration. Scheduled receipts are not accepted by
legacy replica quorum/availability or pruning formats. New canonical pruning
remains gated until that full path verifies schedule-bound retention evidence.
No mainnet readiness gate is closed by this implementation.

## Canonical reference values

The deterministic fixtures in `schedule_test.go` and `custody_schedule_test.go`
fix these IDs. They are format references, not live network identities.

| Artifact | ID |
| --- | --- |
| Version 2 migration entry | `600d67ae84ee481323e5f07d409a5ff6eb0b97bef120df6ed1d5bf2034ed1732` |
| Schedule proof | `439e603f95f1d9ecff0372ef0a4150c3848e0a8a366901b85582c85451cdc290` |
| Scheduled receipt | `0e1a776acaf1e74056c05024bfbdcc04272ad003751237308523d7e0b76be31d` |
