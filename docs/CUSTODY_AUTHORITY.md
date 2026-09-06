# Custody acceptance and cross-host cutover boundary

Status: acceptance inventory and implementation requirements; no distributed
revocation authority or active rebaseline is installed.

Local retirement serializes upgraded participants using the named journal
roots. It does not invalidate a previously extracted Ed25519 key, a copied
unretired journal, an old binary, or a receipt already delivered elsewhere.
A verifier supplied the old trusted keys can still verify those signatures.
This is why another signed retirement file, by itself, is not a global fence.

## Acceptance paths

| Path | Current enforcement | Required before active cross-host cutover |
| --- | --- | --- |
| Auditor challenge creation, result publication, journal append and artifact recovery | CLI holds artifact lock then active journal decision scope for the whole cycle | Bind the whole live operation to the current assignment; recovery must not promote historical validity to current acceptance |
| Replica fresh, cached and restart-recovered responses | Journal-backed sessions hold their current decision scope through response and stream retirement | Reject retired assignments even with copied keys/journals; drain operations admitted before retirement |
| Raw/record-backed sessions and signing helpers | Signature, binding and timing checks; no journal retirement guard | Remain ineligible for managed cutover or require the same authority protocol; no silent fallback |
| `CustodySession.Audit` live result acceptance | Rechecks returned renewal at current time under static keys | Hold a current assignment decision through durable acceptance, not just transport identity |
| `workarchive.PruneCanonicalPrefix` destructive maintenance | Full replica replay, static trusted keys, immutable evidence and final in-batch time/cancellation check | Hold current assignment authorization through storage transition; reject retired receipt keys regardless of their signatures |
| `workchain.Store.PruneCanonicalPrefix` low-level primitive | Chain ancestry, retained-depth policy and atomic persistence | Remain a trusted internal primitive; never expose it as a command bypassing archive/authority policy |
| Codecs, journal replay, pinned backups, historical application | Canonical signatures and exact historical links; explicit observation times where applicable | Keep historical verification independent of live authority so retirement does not destroy auditability |

`PruneCanonicalPrefixAuthorized` provides the final bounded callback inside the
prepared WorkChain batch. It is used for live freshness and cancellation, not
distributed revocation: the caller still supplies static replica policy, and
no policy-generation identifier has entered receipts. Reading mutable authority
once before the method, or inside its callback without a guard held through
completion, cannot establish ordering against a concurrent retirement.

## Required ordering, not a deployed protocol

1. Establish independently trusted assignment authority and enumerate every
   accepting consumer. Bind network/archive scope, generation, allowed evidence
   roles and policy, and exact predecessor. Do not infer the latest generation
   from candidate receipts or proposals.
2. Serialize the stop decision against admission of old-generation operations.
   Once stopping, admit no new old-generation decision. Preserve the original
   stop identity across crash/retry instead of issuing a new one.
3. Drain every admitted decision through its last observable effect: response
   delivery, artifact/journal publication, or storage commit. A disconnected
   consumer is not presumed stopped merely because it is silent.
4. Commit retirement only when the drain condition is established. A lease
   design must specify bounded clocks/skew, expiry enforcement, restart behavior
   and the point after which a stalled client cannot act. Short-lived signatures
   alone do not establish that condition.
5. Link exactly one activation to the reviewed full-replay proposal, historical
   reconstruction and retired predecessor. Persist the activation choice before
   new-generation effects. Partial activation may reduce availability but must
   not reopen the old generation or admit a second successor.

An online implementation must fail closed when it cannot establish current
authority. A cached signed snapshot proves what was signed, not that a later
retirement has not occurred. Partition-time availability must not be claimed
until the authority and drain protocol explicitly supports it.

This authority is operational custody policy, not a committee able to override
hard-PoW fork choice. No new hosted coordinator, external service, consensus
rule, keys, or deployment is selected by this document. The independent failure
domain, durability/rollback guarantees, authorization and distribution remain
architecture and deployment decisions to implement and review.

## Required negative tests

- Valid old/copy/restarted signatures fail at live acceptance once retired.
- A stale, rolled-back or partitioned consumer cannot resume or silently switch
  to an unguarded session when current authority is unavailable.
- Retirement racing a response or prepared database batch produces one ordered
  outcome: the operation drains first, or is denied before its live effect.
  A query/commit gap is not an accepted result.
- Death before/after admission, stop, drain, retirement and activation preserves
  one durable ordering and never selects two active successors.
- Keys, archive binding, policy generation, predecessor and proposal ID cannot
  be substituted; replaying the old generation fails live acceptance.
- Historical records remain replayable without re-dating proofs, resetting
  retention or reopening retired participants.

Existing local lock, retirement, freshness and process-kill tests are necessary
building blocks, not closure of these cross-host gates. Rebaseline proposals
remain inactive; command output continues to report
`global_participants_fenced=false` and `active_cutover=false`.
