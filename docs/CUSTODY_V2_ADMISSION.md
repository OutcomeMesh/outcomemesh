# Assignment-wide V2 admission coordinator

Status: experimental accounting coordinator with independently enrolled witness
histories. This stage implements a shared budget chain and its reviewed operator
CLI. The separate [required profile](CUSTODY_V2_REQUIRED.md) now enforces its
proof in new signed policy-3 owners. The coordinator alone does not activate
legacy policy-2 owners, migrate old tickets, grant an effect or change consensus.
Every CLI review/output explicitly reports `coordinator_only=true` and
`execution_granted=false`.

The [profile-5 accounting import](CUSTODY_IMPORTED_ACCOUNTING.md) additionally
seeds this same machine with verified old spending/source/retention and requires
full registry selection in durable imported witnesses. Native genesis behavior
and historical bytes remain unchanged. Imported execution is disabled.

## One assignment, one budget history

Separate job Claim and Serve slots cannot impose an aggregate budget: every new
Plan creates another job scope. The admission coordinator instead uses one
permanent, sequential witness history for the outer V2 Assignment ID. The roster
and threshold come from the assignment: 4–16 unique, independently selected
witness keys and strictly more than two thirds for each transition.

`AdmissionGenesis` contains the V2 assignment, manifest, initial receipt and
custody policy. Its validation reconstructs the embedded public Base and checks
all archive/role/source bindings. Bootstrap requires a signed Context with source
sequence zero, zero prior head and the exact initial receipt.

Two pins serve different purposes:

- `Genesis.ID()` derives only from the outer Assignment ID in the separate
  admission domain. Another descriptor or Plan cannot choose a fresh budget
  namespace for that assignment.
- `Genesis.DescriptorID()` commits the complete canonical descriptor. Operators
  independently pin it too, so alternate encodings or source/policy descriptors
  cannot silently replace the original enrollment.

Each witness must have one independently protected original history for this
assignment/key. The SDK cannot establish that an operator has not enrolled a
second empty root, lost every external pin or copied raw signing keys. A fresh
constructor is not recovery of any preexisting raw V2 assignment or unresolved
V1 operation. Enrollment/activation must prove eligibility separately.

## Budget units and transitions

Base limits count operation units. A V2 job contains Audit and Serve, so admission
permanently spends **two** `MaximumOperations` units and reserves **two**
`MaximumPending` units. The initial implementation admits one active job per
source/assignment, even if the declared pending limit is larger. A limit below
two permits no job. Unclaimed cancellation does not refund permanent spending.

| Transition | Preconditions | Result |
| --- | --- | --- |
| Admit | Exact current ledger sequence/head; authority signature; complete signed Context for this genesis; no active job; two available permanent and pending units; never-used Context ID and Plan ID; Context predecessor equals the ledger source cursor | Spend two permanent units, hold two pending units, retain exact active job IDs |
| Close fulfilled | Exact active Context; full Serve certificate; A's applied receipt and B's applied receipt with exact A parent; valid original execution/result/accepted-source proof contained in Serve evidence | Clear pending units; keep lifetime spending/deduplication; advance cursor to exact result entry and renewed receipt; preserve minimum retention |
| Close unclaimed | Same complete closure packet, including original execution no-claim QC and both applied receipts | Clear pending units; keep lifetime spending/deduplication; leave source cursor and retention unchanged |
| Unknown, missing response, B-only expired result, missing or unrelated receipt | No valid Close packet exists | Keep active job and both pending units; no refund or source advance |

Admit and Close entries bind the semantic genesis ID, exact expected sequence and
head, complete Context and (for Close) complete closure packet. The authority
signs the whole entry in a separate admission domain. Existing three Context
role signatures remain required. Entries, votes and QCs have new bounded codecs
and domains; old execution/witness packets cannot serve as admission votes.

All witnesses replay the same typed reference machine before voting or committing.
A quorum cannot substitute an opaque result hash for Serve verification. Reusing
an already completed/cancelled Context or Plan is refused. A different job while
one is active is refused. Closing work never restores permanent allowance.
`SourceSequence/SourceHeadID/SourceReceiptID` describe the coordinator's expected
lineage, not a fresh independent reading of A or B.

A complete Close packet is **historical accounting evidence**. This stage verifies
its typed signatures and cursor, and may record accounting closure. It does not
hold an original A/B source lock or establish live current source ownership.
The [required execution adapter](CUSTODY_V2_REQUIRED.md) binds certified admission
to original owners, checks their current source and consumes admission durably
before current archive-object reads/signing/appending. Existing raw policy-2
APIs remain separate;
a coordinator QC or diagnostic snapshot cannot enable them or certify that an
old effect happened after this admission.

## Durable witness ownership and recovery

An `AdmissionWitness` retains:

- canonical genesis, exact original path/root/lock placement and ready identity;
- one immutable full vote proposal per sequence, before returning its signature;
- full selected quorum certificates, before exposing the committed state.

A different proposal at the same position cannot replace the vote, including
after a crash. A valid majority QC may override a minority local proposal; both
records stay retained and cold replay validates the original mixed history.
Split votes can block progress. There is no timeout unlock, view change, roster
replacement, counter reset, compaction or lost-root reinitialization API.

Open requires an exact external `(sequence, head, pending ID)` pin. It validates
and flushes retained files before exposing an owner. A pending vote never becomes
a QC on open. Complete retained QC bytes may prove the exact one-transition
extension after lost output; `RecoverAdmissionCommit` accepts only that exact
before/after relationship and retained packet. `RecoverAdmissionVote` accepts
only the attempted full proposal at the retained before position. A different
valid QC subset does not silently replace the committed packet.

Any uncertain write poisons the live owner. The operator must close and explicitly
recover the exact attempt. Source data is not read or modified by these witness
operations. Path/inode/device/uid/mode checks reject ordinary moved/copied roots;
they do not protect hostile implementations, raw keys or rollback of every pin.

There is also a fixed 512 MiB local journal byte cap, separate from signed budget
units and bounded record count. A witness reserves worst-case local room for
remaining Admit/Close records before voting or committing Admit. New admissions
may stop on local capacity; retained operations are never refunded or discarded.
This reserve is not proof against physical device exhaustion, lost evidence or
quorum liveness failures. Original sources/archives are never deleted here.

## Reviewed operator CLI

Command: `omd work-archive-custody-v2-admission`.

Default mode is keyless `review`, with no owner acquisition or private seed load.
Execute the same pinned action using `--mode run --expected-review-id <id>`.
The review binds action, genesis semantic/descriptor IDs, input file contents,
original root/key paths, all external witness pins and output placement.
Outputs are immutable and must be outside original witness roots. After lost
output, retain the same attempt and use a fresh output path.

1. Derive `NewAdmissionGenesis(context)`, its `ID()` and `DescriptorID()` from the
   independently pinned public Context. `genesis` verifies these pins and exports
   canonical bytes using `--context` / `--context-id`.
2. All other actions require `--genesis`, `--genesis-id` and
   `--genesis-descriptor-id`.
3. `admit-entry` takes the Context/pin, exact `--sequence` / `--head-id` and
   authority `--sign-key`. It signs a candidate, not an execution grant or a
   unilateral budget change.
4. `witness-create` explicitly enrolls a fresh root for a pinned `--witness`
   signing key. `witness-vote` validates the complete `--in` entry. Every witness
   action requires all three external fields: `--sequence`, `--head-id`,
   `--pending-id` (explicit zero if absent), original `--root` and signing key.
5. `certificate` takes entry and distinct sorted votes, provided as comma-separated
   `--votes` and matching `--vote-ids`. Input pins use the existing V2 artifact ID
   domain. Two of four or repeated copies of one signature cannot form a quorum.
6. `witness-commit` takes the full certificate and exact before pin. Cold exact
   retries permit only that selected extension. `witness-status` exports the
   checked local snapshot and observed pin; it is diagnostic, not signed live
   permission. Hash fields in JSON use Go's 32-byte array representation.
7. `close-entry` takes the exact active Context, `--in` Serve certificate,
   `--a-receipt`, `--b-receipt` with their artifact pins and the current ledger
   sequence/head. The authority signs the complete candidate. It must pass the
   same witness vote/quorum/commit cycle before pending accounting clears.

There is no admission RPC service or automatic retry/activation. Remote witness
operators can run these standalone commands through their authenticated operator
channel. Neither historical QCs nor local status output should be presented as
current execution rights.

## Compatibility and remaining integration

V0/V1 authority ledgers, V2 assignments/jobs, execution/Serve formats and original
source owners remain unchanged. The new coordinator has its own journal markers,
IDs, signature domains and roots. It cannot open old roots as empty budget state.
The separate [V1 cutover specification](CUSTODY_V2_MIGRATION.md) requires complete
retirement/source/accounting and independently enforced exclusion of old grants;
its separate [disabled review preparation](CUSTODY_CUTOVER_REVIEW.md) now retains
full eligible histories, original-source observations and no-refund arithmetic.
It implements no source/spending import or activation command. Pending old Serve
stays pending.

The signed policy-3 profile and original-owner runtime binding now implement
one-use consumption before effects and original source-currentness checks.
[Retained proof delivery](CUSTODY_V2_DELIVERY.md) now supplies bounded typed
network distribution and exact inbox/outbox recovery without creating execution
owners. Activation registry integration and protected
independent enrollment, safe split-vote progress, migration/activation, physical
storage acceptance, external review and the sustained adversarial public-testnet
conditions remain launch gates. This coordinator does not waive them.

## Recorded acceptance

The 2026-10-28 [acceptance index](evidence/custody-v2-admission-20261028.json)
records 13 joint campaign checks. Four logical witnesses split 2/2 across two
observed Linux kernels choose one Admit, recover lost vote/commit output in new
CLI processes and agree on spent=2/pending=2 at position one. A second Admit and
stale pins are refused, with no position-two vote retained. Original A/B/copy
sources and identities remain unchanged at sequence zero. No effect is started;
the active job is deliberately retained. This campaign does not claim remote
budget exhaustion or closure; local/reference/native tests cover those paths.

The [public manifest](evidence/custody-v2-admission-public-20261028.json) pins 38
artifacts in a 10,838-byte archive. Production Go APIs reverify descriptor and
Context bindings, authority entries, four signed witness votes, selected quorum,
16 diagnostic checkpoints and rejection of the second signed candidate against
that history. Snapshots remain unsigned diagnostic metadata; the QC is signed
historical evidence. Neither grants execution.

Validation also passes all five race groups, fresh CLI process integration,
integration vet, 46 Python helper tests, five canonical vectors and bounded
five-seed decoder fuzz smoke. Local tests include operation exhaustion, closure
without refunds, exact fulfilled cursor advancement, competing jobs, four sync
fault boundaries and original-root refusal/recovery. Both hosts finish without
selected listeners or task processes; all Go sources match the native build pin.
