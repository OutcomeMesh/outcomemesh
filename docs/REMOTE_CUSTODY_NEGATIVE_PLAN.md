# Remote custody negative-disposition work plan

Status: next implementation gate, not an implemented terminal format or a
permission to complete tickets. The [WAN campaign](REMOTE_CUSTODY_WAN.md) checks
that these branches retain their ordinary Audit/Serve tickets and refuse a
successful terminal. No readiness credit is assigned to this design note.

## Existing behavior that must be preserved

`remoteworker.Seal` distinguishes three historical observations:

| B disposition | Meaning | What it does not establish |
| --- | --- | --- |
| `Unseen` | This retained worker branch has no local Start. | No execution by an independent copy of its keys/root. |
| `NoResult` | A local Start exists, but no retained result is selected. | Cancellation, absence of an effect, or absence of an earlier response. |
| `RetainedResult` | The sealed branch commits an immutable result ID. | Acceptance in A's original journal or present proof freshness. |

The distinction is defined in `remoteworker/model.go`. Do not rename NoResult
to failure or pre-start cancellation. A timeout or an unreachable B cannot
produce any of these sealed observations.

`RemoteDrained` clears the active remote hold only after an authenticated sealed
branch. Ordinary tickets remain pending. The current successful terminal in
`store/remote_custody_terminal.go` additionally requires the exact response
already accepted in A's original source. Its canonical bytes, ID domain and
successful Complete checks must remain compatible.

The authority state machine treats Complete's EvidenceID as a commitment; it
does not interpret that evidence as successful custody. Therefore a new managed
negative workflow needs its own evidence validation. Feeding an arbitrary digest
to the existing generic state machine is not a safe implementation shortcut.

## Required order

1. **Specify disposition and retention rules before adding a completion path.**
   For each branch, state which obligation is resolved and which retention or
   uncertainty obligation remains. A negative administrative outcome cannot earn
   custody rewards, advance an accepted source, extend a receipt, or authorize
   deletion in conflict with existing retention. In particular, decide how a
   NoResult uncertainty hold survives ordinary-ticket settlement; if there is no
   independently justified rule, that branch must keep its tickets pending.
   Do not treat elapsed time as evidence of no effect.

2. **Add a separately versioned, bounded negative evidence type.** Bind the exact
   assignment, intent, Audit/Serve admissions, plan, Begin, B seal and confirmed
   Drain. Include the original A source observation needed by the classification.
   When a B-only retained result is supplied, verify its complete signed journal
   entry and historical proof at its original RespondedAt; never import it into
   A or refresh it. Define a separate ID/signature domain and fixed vectors.
   Reject unknown versions, trailing bytes, mixed branches and a successful
   terminal supplied as negative evidence. Final field layout and domain names
   are part of this implementation slice, not defined by this note.

3. **Implement owned capture and default read-only review first.** Hold the
   original A authority, artifact lock and source decision through classification
   and no-replace publication. Require confirmed Drain, no active Begin and no
   unrelated pending authority mutation. Compare original source/root/lock
   identities before and after. A later source advance or a conflicting accepted
   result invalidates an old absence/unaccepted-result observation. Lost output
   may recover only the same immutable artifact. This slice publishes evidence;
   it does not complete tickets or grant a new execution attempt.

4. **Add reviewed signing and explicit per-ticket application only for eligible
   dispositions.** Derive the actor and purpose from the independently pinned
   admission/evidence, then obtain the consumer signature and authority
   co-signature. Apply each Complete under the same original guards, rechecking
   the retained classification and all remaining uncertainty/retention holds.
   Keep Audit and Serve independent. Resume may settle only the exact retained
   pending entry; opening, reviewing, sealing and reading metadata never resume
   or complete implicitly. An ineligible unknown branch must still refuse this
   path even if both parties supply signatures.

5. **Repeat native process and two-host acceptance.** Cover publication before/
   after durable confirmation, lost output, kill/reopen, changed scope/source,
   stale reviewed commands, duplicate completion and interrupted Resume. Extend
   the same-assignment WAN cases for Unseen, Started/NoResult and expired B-only
   cache. Verify every remaining hold explicitly. Reuse the original roots for a
   later valid cycle only where the defined disposition permits it; otherwise
   prove that a new attempt/deletion remains blocked. Re-run positive V0/V1
   compatibility and the repository gates before crediting the lifecycle point.

## Minimum rejection matrix

- No authenticated durable seal, or a seal for another Begin/plan/assignment.
- NoResult presented as Unseen, cancellation, or successful custody.
- A result accepted locally presented as absent; a B-only result presented as
  accepted; a stale result presented with a newly signed proof time.
- A source/root/lock replacement, later source advance or unrelated pending
  authority command between review, capture and application.
- Wrong consumer, wrong purpose/ticket, mismatched authority position, reused
  review token or negative evidence supplied to the successful-terminal path.
- Partial publication, lost stdout, process death and exact historical retries
  that would append another entry, release an unresolved hold or rewrite evidence.

This work remains within the original-owner trusted-key boundary. Independent
key/root copy fencing, physical-device failures, external audits and sustained
public-testnet acceptance remain separate launch gates.
