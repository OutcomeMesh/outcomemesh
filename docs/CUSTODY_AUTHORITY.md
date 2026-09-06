# Custody acceptance and cross-host cutover boundary

Status: bounded reference admission/drain machine implemented in
`node/custodyauthority`; durable authority, network enforcement and active
rebaseline are not installed.

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

## Implemented reference kernel

The version-0 kernel operates on one independently pinned immutable assignment.
It binds network/genesis/activation/base, manifest, statement, initial receipt,
custody policy, a separately selected incarnation ID, evidence roles and the
closed consumer-control-key list. `CreateCustodyAuthorityAssignment` checks the
archive/receipt/policy binding without claiming current availability. Changing
any binding, membership or limit changes the assignment ID. This bootstrap
format has no successor activation or membership-update operation.

Consumer control keys must be distinct from the authority key, replica evidence
key, every auditor key and each other. Each consumer has explicit `Audit`,
`Serve` and/or `Prune` purposes. Declared coverage must include all three, but
this does not prove the operator enumerated every real accepting deployment.
Unknown consumers and evidence keys cannot request admissions or close tickets.

Commands carry the exact assignment, expected sequence and expected head.
Consumers sign admission/completion commands; the assignment authority signs
stop/retire commands. Every accepted history entry also requires that pinned
authority's co-signature, in a separate domain. The first predecessor is the
assignment ID. Compare-and-append rejects stale or forked entries; neither
validation nor rejection changes state. This is one logical ordered authority,
not a replicated/BFT implementation or protection against a signing authority
that equivocates across independently forked stores.

| Command | Allowed effect in the reference machine |
| --- | --- |
| `Admit` | Only in `Accepting`; allocate one ticket for a permitted consumer/purpose and a never-before-admitted consumer operation ID |
| `Complete` | Only the admitted consumer can close its still-pending ticket, in `Accepting` or `Stopping`, with a nonzero terminal-effect/disposition commitment |
| `Stop` | Move `Accepting` to `Stopping`, preserving one signed stop-intent reference; reject every new admission from then on |
| `Retire` | Move `Stopping` to terminal `Retired` only with the exact stop entry ID and zero pending tickets |

No timer, cancellation, disconnect, missing response or replay closes a ticket.
There is no force-complete, resume, key-replacement or activation transition.
An unresolvable consumer can therefore block retirement indefinitely. The next
runtime layer must define safe evidence-backed recovery of that consumer; it
must not invent an expiry to restore availability. A completion commitment is
an assertion by the trusted consumer, not proof that its code has actually
finished every effect. The runtime adapter must enforce that ordering before
signing it and must prevent duplicate execution after a lost response/restart.

Limits are part of the assignment: up to 65,536 total admissions and 1,024
pending tickets, with 1–64 auditors and consumers. Completed operation IDs remain
retained, preventing reuse and keeping memory bounded. Admission exhaustion
does not consume completion/stop/retire capacity: the maximum accepted history
has `2 * MaximumOperations + 2` entries. It is not automatically compacted or
reset. `LookupOperation` distinguishes unknown, pending and completed work but
returns only a detached observation, never a reusable permission.

`Replay` requires independently retained assignment and exact sequence/head
pins. It rejects even a valid shorter prefix, or an extension beyond the selected
pin. Replaying an outstanding ticket leaves it outstanding; no snapshot import
exists. A historical pin still cannot prove there is no later remote stop.
`NewState` is bootstrap only, never a fallback when history is missing.

The kernel is deliberately in-memory. `ValidateNext` followed by `Apply` is not
an external transaction, and a signed `Entry` is not a live grant. The durable
adapter must serialize validation, history publication and state application,
fsync accepted history before any grant can escape, and recover only by full
pinned replay. Then a current-authority transport and per-consumer durable
operation protocol must hold admission through the last acceptance effect.
No existing custody session, journal, pruning command or receipt parser consumes
these entries yet. Reference tests exercise local state/replay and concurrency;
they are not cross-host partition, durable-store or process-crash certification.

### Canonical reference vectors

`TestAuthorityCanonicalGoldenHistory` freezes a 451-byte assignment, two
admissions, stop, two completions and retirement. Commands are exactly 276 bytes;
co-signed entries are exactly 382 bytes. Assignment bytes are bounded at 8 KiB.
Unused command fields, trailing bytes and unknown versions/kinds are rejected.
These are operational fixtures, not a consensus or peer-wire upgrade.

```text
assignment = 0a971f736838505235eef8d8f342e3370e574681f71cc3c3f033b459e40b9931
ticket_1   = a9054c2e49821a3dbe12bee0fced4616c2b7c211ef71ef52c99477643998cb6d
stop       = d8fb8af2bce85728f50eae473d9f1889927bfbd0742d61336b6ab4041d681779
retirement = 4ef0bac9e865e9b107fca609ed9c0134dcce41db3e094d4890ccac97347b9586
```

The signature domains are `OMESH/custody-authority/command/signature/v0` and
`OMESH/custody-authority/entry/signature/v0`; assignment and entry IDs have
separate `/id/v0` domains. Existing receipt, challenge and proposal signatures
and formats are unchanged.

## Required deployment ordering

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
hard-PoW fork choice. The reference format uses one explicit authority signing
key; no hosted coordinator, replication architecture, external service,
consensus rule, real keys, or deployment is installed. The independent failure
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

Existing local lock, retirement, freshness, reference-machine and process-kill
tests are building blocks, not closure of these cross-host gates. Rebaseline proposals
remain inactive; command output continues to report
`global_participants_fenced=false` and `active_cutover=false`.
