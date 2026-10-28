# V2 Serve disposition

This is an opt-in, per-job disposition adapter for witness-mandatory custody V2.
It is not a consensus upgrade, an archive retirement operation, or a migration of
legacy V0/V1 authority tickets. An execution-fence `ResultRecorded` observation
by itself still does not close Serve.

## Accepted outcomes

| Outcome | Required evidence | Original A/B source | Archive obligation |
| --- | --- | --- | --- |
| Fulfilled | Complete V2 result bundle and execution quorum chain; A's original accepted-source receipt; authority and Serve-consumer signatures; independent Serve decision quorum | Both contain the exact result entry; A also retains the exact original accepted receipt and bundle, B retains the exact session result | Retain at least through the renewed receipt's deadline |
| Unclaimed | Original execution scope's initial `CloseUnclaimed` quorum; authority and Serve-consumer signatures; independent Serve decision quorum | Both remain at the exact predecessor, without acceptance/consumption markers | Retain at least through the previous receipt's deadline |
| Claimed/unknown without a verifiable accepted result | No closing proposal exists | Any existing source/consumed/result history remains authoritative | Serve remains pending and archive remains held |
| Result retained only at B and expired before A accepts | No fulfilled proposal exists | B's append/renewal remains; A stays at its predecessor | Serve remains pending, including B's renewed retention deadline |

A timeout, an empty source snapshot, or a participant saying “no work happened”
cannot replace the original no-claim quorum. A pending original witness vote for
a claim already excludes that witness from voting cancellation, even before the
claim QC is committed. There is no witness-roster reset, unlock, or view change.
Split votes may therefore block progress indefinitely.

## Typed witness decision

`ServeProposal` binds the complete signed Context ID and exactly one typed proof.
The authority and the Context's Serve consumer sign separate domains over the
whole proposal. Drafts may carry zero or one signature; they are never votes or
settlement rights. Fulfilled evidence is verified at A's original `AcceptedAt`,
including proof freshness at that time. Settlement does not refresh that time.

The decision scope is derived only from the original execution scope ID, using
`OMESH/custody/v2/serve/decision-slot`. Its roster/threshold come from the signed
V2 assignment. The scope is independent of the chosen outcome and proof, so an
alternative proposal cannot select another slot for the same execution job.

The adapter reuses the existing V0 permanent single-writer witness journal and
its initial `CloseUnclaimed` transition as a one-shot **decision-slot** closure.
The decision command commits the full signed Proposal ID in `EvidenceID` and is
signed by the original authority. It is not a cancellation certificate for the
execution scope. `ServeCertificate` checks the typed proposal and its exact
command binding before verifying the quorum. No new execution grant is created;
V0/V1 execution formats, domains and historical golden vectors are unchanged.

The typed `VoteServe`/`CommitServe` adapters verify evidence and both role
signatures before calling the durable witness methods. The new CLI uses those
adapters directly on the witness host. It does **not** expose the generic
hash-only witness RPC as a Serve voting service. There is no dedicated Serve RPC
in this stage; remote orchestration runs reviewed standalone CLI processes over
an authenticated operator channel. Use separate original decision roots, retain
external sequence/head/pending pins, and do not enroll replacement roots for the
same witness key. A lost vote reply permits only the exact retained proposal.

## Original-owner application

A verifies the complete certificate under its retained original source decision
lock. Fulfillment additionally requires the exact cached accepted-source receipt,
bundle and current original source entry. A historical signed receipt presented
to an unused source cannot make that source settle. Cancellation requires the
predecessor and absence of pending/accepted markers.

A retains `serve.pending` (certificate and original checked time), flushes the
file and directory, then retains `serve.settled` with its signed applied receipt.
Only afterward can the CLI publish an output artifact and write its response.

B requires A's applied receipt, the same certificate, and its own exact retained
result/source. Cancellation also requires absence of consumed/result markers.
B retains A's receipt in its own pending record before publishing its own applied
receipt. Source journals are not appended by either settlement step.

Pending or settled Serve blocks Target Prepare/Execute and new A acceptance.
Existing accepted receipts and retained results remain recoverable. An unused
volatile B session is erased when cancellation is applied. Archive objects and
all evidence remain retained; `ServeStatus.ArchiveHeld` stays true even when
`Pending` becomes false. This module provides no deletion permission.

A cold open validates retained bytes against the original source and flushes
already verified files before exposing an owner. It creates no decision or
signature. A pending attempt needs explicit `resume-a`/`resume-b` with the exact
certificate and, for B, the exact A receipt. A complete cached receipt is returned
unchanged, including its original time. A different valid quorum subset is a
different certificate ID and cannot silently replace the pinned attempt.

## CLI workflow

Command: `omd work-archive-custody-v2-serve`.

Every action requires `--context`, `--context-id`, `--scope-id` (execution scope),
`--serve-scope-id` (independently retained decision scope) and an immutable `--out`
outside all original roots/sources. Default mode is keyless `review`. To run the
same reviewed action, add `--mode run --expected-review-id <review_id>`. The review
binds action, context/scope pins, public artifact contents, role/key paths,
original owner/source placement, witness pins and output. It never loads seeds
or acquires an owner. Outputs must be absent before dispatch; recover to a fresh
output path after lost output. There is no external clock override.

1. `scope` exports the derived decision descriptor. Its independent ID is available
   through `Context.ServeScope().ID()`; fresh WAN fixture metadata includes it.
2. Build `proposal-fulfilled` from `--in` bundle and `--proof` accepted-source
   receipt, or `proposal-unclaimed` from the original execution no-claim QC.
   Each file requires its `--in-id` / `--proof-id` artifact pin. The auxiliary
   `unclaimed-command` action signs only an initial execution cancellation command,
   with a nonzero `--evidence-id`; original execution witnesses must certify it.
3. Run `sign-proposal` once per `--sign-role authority|consumer` with the matching
   `--sign-key`. Each output becomes the next pinned input. `decision` signs the
   complete proposal's exact decision command with the authority key.
4. On each original witness host, `witness-create` enrolls a fresh decision root
   with `--witness` public key and `--sign-key`. `witness-vote` takes the complete
   proposal in `--in` and command in `--proof`. Supply all three independent
   fields: `--sequence`, `--head-id`, `--pending-id` (explicit zero when absent).
   A cold exact retry returns the same signed vote without a competing lock.
5. `certificate` takes proposal, command, comma-separated `--votes` paths and
   matching `--vote-ids`. It sorts distinct witnesses and verifies the full
   threshold; duplicates and two of four are rejected. `witness-commit` takes
   the resulting complete certificate and exact before pin. Cold commit retry
   permits only that one-transition extension. Observations are request-bound
   signed historical metadata, not live execution rights.
6. `apply-a` requires original `--root`, `--journal`, authority `--sign-key`, and
   pinned `--in` certificate. Recover pending/lost output with `resume-a`.
7. `apply-b` / `resume-b` additionally require original `--objects`,
   `--replica-key`, control `--sign-key`, and A's applied receipt as `--proof`.
8. `status-a` / `status-b` inspect the original local owner and export Serve
   pending/receipt IDs and minimum retention. They require the same owner keys;
   their preceding review remains keyless. Unknown B states derive minimum
   retention from the original current receipt, including a renewal already
   appended before a lost result publication.

Artifact pins use the existing V2 artifact domain, not plain file SHA-256.
Public proof verification is historical. Applying it always rechecks the original
local source; no detached proof is a replacement owner.

## Validation and remaining gates

Unit tests cover fulfilled and no-claim paths, missing A application, unaccepted
historical receipts, B copies without original results, unknown/expired work,
retained renewal deadlines, competing certificates, strict codecs, typed witness
refusals and permanent vote locks. Eight A/B persistence boundaries are injected
before/after pending and settled sync. Cold open never completes a pending
attempt. The CLI lifecycle also runs in separate native processes.

The two-host campaign in `scripts/remote_acceptance/serve.py` repeats the V2
network fault matrix, then closes fulfilled/unclaimed jobs and holds unknown/
expired jobs. Serve voting/application use original standalone CLI processes,
including broken stdout and exact cold retry. It does not test a Serve RPC,
physical power loss or independently protected witness enrollment. Four logical
witnesses on two kernels remain two observed hosts. Public deterministic fixture
keys are not deployment key protection.

Assignment-wide V2 admission/budgets, explicit V1 ticket migration/activation,
protected independent witness/root enrollment, split-vote progress, real device
faults, external review and the required sustained adversarial public testnet
remain open. Legacy pending Serve tickets are unchanged by this adapter.

The 2026-10-28 [acceptance index](evidence/custody-v2-serve-20261028.json)
records four completed disposition cases and 26 scenario checks: two jobs close,
two remain pending, zero archives release. The original execution matrix is a
snapshot taken before Serve disposition. The
[public manifest](evidence/custody-v2-serve-public-20261028.json) pins 267 artifacts
in a 52,848-byte archive. Production Go APIs reverify the execution quorums,
typed decisions, 44 Serve witness artifacts and both pairs of applied receipts.
This proves historical packet validity; original-source/current-owner checks
were additionally exercised during the campaign. Both hosts finish with no
selected listener or task process. Validation includes all five race groups,
fresh CLI process tests, integration vet, 41 Python helper tests and a bounded
Serve-decoder fuzz smoke run. The index also records a corrected controller
hash-array parsing error and its full fresh rerun; Go runtime sources did not
change for that correction.
