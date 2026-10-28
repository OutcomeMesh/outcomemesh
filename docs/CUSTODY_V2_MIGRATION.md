# Legacy V1 to V2 cutover rules

Status: activation requirements plus an implemented
[imported accounting stage](CUSTODY_IMPORTED_ACCOUNTING.md). The
[review preparation](CUSTODY_CUTOVER_REVIEW.md) supplies bounded legacy replay,
original-source observations, no-refund arithmetic and the signed proposal.
Profile5 now enforces historical spending/source carry-over in the existing
admission ledger, with one shared registry selection slot. Active source handoff,
protected old-grant exclusion and execution activation remain unimplemented.
The [V2 job](CUSTODY_V2.md) and [Serve disposition](CUSTODY_V2_SERVE.md) continue to
operate in their supported native scopes; they cannot settle unresolved old tickets.

The rules below use MUST/MUST NOT as requirements for that future implementation.
They do not grant present permission to move, reinitialize or discard an owner.
V0/V1 canonical bytes, signature domains and successful completion semantics
remain unchanged.

## Legacy state is authoritative

The existing V1 authority machine has `Accepting`, `Stopping` and `Retired`
phases. `Stop` forbids new admissions; it does not settle pending work. `Retire`
requires `Stopping`, zero ordinary pending operations and no active remote hold.
A `RemoteDrained` record closes only the exact remote hold. It does not complete
its ordinary Audit or Serve ticket. Replay must reach the independently retained
exact sequence/head, including every completed operation.

The [negative workflow](REMOTE_CUSTODY_NEGATIVE.md) may explicitly complete only
the administrative Audit ticket. Serve remains pending for Unseen, NoResult,
unverified result and historically verified but unaccepted B result. This is an
accounted obligation, not a diagnostic file that a new ledger can omit.

| Observed legacy branch | Cutover treatment |
| --- | --- |
| Active Begin, pending authority mutation, missing confirmed Drain, or unavailable original owner | Blocked; preserve all histories and exact recovery pins. |
| Drained Unseen | Blocked while Serve is pending. It cannot be relabelled V2 Unclaimed. |
| Drained NoResult | Blocked as unknown; elapsed time or restart cannot establish absence of an effect. |
| B-only result, including an expired result | Blocked until existing V1 rules independently resolve every obligation. Do not import it as A acceptance or sign a fresh proof time. |
| Accepted successful terminal but one ordinary ticket remains pending | Blocked until the existing exact, typed completion path closes that ticket. |
| Stopping with any pending ticket | Stopped for admission, still blocked for cutover and retirement. |
| Retired, exactly replayed, no pending mutation or remote/ordinary hold | Eligible for cutover **review** only; original-source, accounting and independent fencing gates below still apply. |

V1 Unseen has no original mandatory witness exclusion. A new V2 no-claim quorum
for another scope cannot retroactively exclude an old V1 execution or copied
signer. A V2 Serve certificate MUST NOT be supplied as arbitrary EvidenceID to
V1 generic Complete, or used to bypass the typed V1 managed terminal checks.
No migration may invent a missing old completion, receipt, Drain or witness vote.

## Required eligibility evidence

A future cutover implementation MUST retain and verify all of the following
under the original owners and their serialization/source guards:

1. Exact legacy assignment, original authority root and external sequence/head
   pin; complete replay to its immutable retirement entry; every admission and
   completion; zero ordinary pending operations, no remote hold and no unresolved
   local publication/delivery attempt. A detached Snapshot is not an import proof.
2. Original A and B source-journal identities and exact sequence/head/receipt
   observations. For a shared successor lineage their current accepted predecessor must
   agree. Successful closure evidence must match the corresponding records in
   the original accepted history; the selected predecessor must match the current
   head. Historical signatures alone do not establish this original-owner
   condition. A source discrepancy blocks the cutover.
3. The exact retained archive/manifest, current receipt, custody policy and all
   outstanding retention deadlines. The successor starts from those verified
   source records. Cutover creates no custody response, source append, renewal,
   reward or fresh proof timestamp. Archive retention survives authority retirement.
4. A complete accounting bridge: old lifetime admissions/consumed allowance and
   the explicitly authorized remaining V2 allowance. Historical spending MUST
   NOT be refunded by resetting counters to zero. A larger allowance requires
   its own explicit policy authorization. Until a verifiable bridge exists,
   a fresh V2 budget is not a continuation of the retired V1 budget.
5. The successor's outer V2 assignment ID, immutable witness roster/threshold,
   participant roles, source lineage and initial admission position. Its embedded
   V1 Base is public preparation, not a reusable old execution grant. Old tickets,
   Begin offers, seals, proof formats and private-root files cannot become V2
   permissions through reinterpretation.
6. Independent enrollment and retained monotone pins for the original admission
   authority and every witness. Four keys on two hosts do not establish four
   protected failure domains. Replacing roots, losing all copies of an external
   pin or changing a roster cannot be described as recovery of an old slot.

Local [placement checks](REMOTE_CUSTODY_PLACEMENT.md) detect ordinary path/inode
substitution; they do not revoke copied raw keys or exclude a full clone that
preserves identities. A retired original V1 branch therefore is not proof that
all old copies stopped. Activation over the same protected resources MUST remain
blocked until independently enforced version/issuer/execution fencing excludes
old grants on every relevant effectful and acceptance path. Both participants'
signatures alone do not supply that fencing. No such protected global cutover is
claimed by the current prototype.

## One-way cutover contract

A future canonical cutover artifact MUST bind the exact old retirement and
source/accounting evidence to exactly one successor assignment and its initial
admission/witness pins. It needs a separate bounded format and signature/ID
domains, strict decoding, compatibility decision and canonical vectors before
implementation. The implemented accounting-only bytes and signature domains are specified in
[CUSTODY_IMPORTED_ACCOUNTING.md](CUSTODY_IMPORTED_ACCOUNTING.md). They provide no
activation certificate.
A second successor cannot be selected merely by signing another artifact.
Uniqueness must be enforced by the independently retained monotone cutover state.

The future lifecycle is:

| Specification state | Permitted transition |
| --- | --- |
| `blocked-legacy` | Read original state and use only existing exact recovery/settlement operations; no V2 continuation is activated. |
| `eligible-for-review` | Build and independently review the complete evidence above; no effect permission is released. |
| `successor-prepared` | Explicitly prepare a disabled successor and enroll the reviewed original roots/pins; preparation does not consume an execution slot. |
| `cutover-pending` | Durably retain the exact selected cutover before publication; missing output requires exact recovery, never another successor or reset budget. |
| `activated` | Only after independently confirmed irreversible cutover and all protected-path checks may the successor admit fresh V2 jobs. Legacy remains retired. |

These are activation specification labels, not current Go enums or CLI modes. The
implemented accounting selection must not be labelled `activated`. A future
implementation MUST make each interrupted transition explicit and reviewable.
Opening, inspection, a timeout or an unreachable signer must not advance it.
Failure after durable selection retains the chosen successor and budget bridge;
recovery cannot start `NewState` on an empty root or enroll replacement witnesses.
A lost file, conflicting pin or source replacement fails closed without deleting
old evidence. A rollback to V1 accepting state is forbidden. A successor's later
retirement requires a new explicit successor protocol, not reversal of this one.

Old sources, authority entries, seals, terminals and retention evidence remain
retained after activation. An archive's deletion still requires its separate
retention/prune rules; neither V1 Retire nor a V2 Serve-applied receipt supplies
that permission. Public artifacts stay historical after release and do not
replace current original-owner checks.

## Acceptance required before enabling cutover

- Refuse every blocked legacy branch above, including an Audit-completed negative
  branch with its exact Serve ticket still pending, a stale source observation,
  a shortened replay, an omitted completed admission and an opaque digest in
  place of typed closure evidence.
- Prove that a second successor, reset budget, stale admission/witness pin,
  changed roster, copied/replaced root and legacy-format grant cannot authorize
  another accepted effect or obligation release.
- Cover before/after durable-selection failure, lost output, process death,
  explicit exact resume, mismatching A/B sources and a partition during cutover.
  Neither side may proceed independently from an uncertain cutover.
- Re-run V0/V1 compatibility, V2 admission/execution/disposition checks and native
  multi-host acceptance against independently operated protected domains. Device
  failures, external review and the sustained adversarial public-testnet gates
  remain required by [PLAN.md](PLAN.md).

Creating an isolated experimental V2 assignment is not a migration certificate
for existing V1 resources or obligations. None of these design states activates
consensus, mainnet, a production signer, or any legacy-ticket exception.
