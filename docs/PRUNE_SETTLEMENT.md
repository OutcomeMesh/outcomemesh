# Observed-effect Prune settlement

A request-v3 execution can commit its storage effect and stop before the volatile
session signs a result. The original executor then remains Started. This
procedure settles only the case where the exact effect is still present in the
original confirmed protected storage pair. It does not reconstruct a session key
or signature, repeat deletion, declare that missing work never happened, or close
an authority ticket automatically.

The consumer and primary authority sign one proposal containing the exact retained
claim and effect ID. The original witness policy selects that proposal in a
separate request-wide decision slot. The original owners then check the actual
storage record again and retain the complete decision. Each replica completes
its own ticket in a later, separately signed action.

## Preconditions

Keep the original plan, inventory, request, executor and independent pins, primary
authority and its pins, storage pair and migration ID. All IDs must be separately
retained and checked. The executor must have a confirmed start and no terminal
record or pending transition. The storage pair must have a confirmed position and
the exact matching effect. Absence, timeout, expiry, a different database or a
copied unconfirmed journal cannot replace that evidence.

Use `resume-executor` first for an already retained transition, following the
[scheduled outcome procedure](PRUNE_SCHEDULED_OUTCOMES.md). Do not create fresh
pins, delete records, choose a new policy or reset witness enrollment.

## Prepare the proposal

The review opens the original owners and reads the effect without changing them:

```sh
omd work-prune-scheduled-outcome --mode review-settlement \
  --plan plan.bin --plan-id PLAN_ID \
  --inventory inventory.bin --inventory-id INVENTORY_ID \
  --assignment-id PRIMARY_ASSIGNMENT_ID \
  --authority /srv/om-authority --authority-pins /srv/om-authority-pins \
  --executor /srv/om-prune --executor-pins /srv/om-prune-pins \
  --data /srv/om-node --chain /srv/om-chain --chain-pins /srv/om-chain-pins \
  --storage-migration-id MIGRATION_ID
```

Pass the original storage policy flags if they differ from the defaults. Check
the proposal's claim, effect ID, inventory, executor binding and storage pair,
along with the displayed owner and storage positions. Repeat the same inputs
with `--mode prepare-settlement --expected-review-id REVIEW_ID --out proposal.bin`.
Keep `proposal_id` separately. A changed owner or storage position invalidates
the prior review. Preparation signs nothing and grants no execution permission.

## Obtain both signatures

Review the original consumer's signature over the exact proposal:

```sh
omd work-prune-settlement --mode review --role owner \
  --plan plan.bin --plan-id PLAN_ID \
  --inventory inventory.bin --inventory-id INVENTORY_ID \
  --proposal proposal.bin --proposal-id PROPOSAL_ID
```

Repeat with `--mode sign --key consumer.seed --expected-review-id REVIEW_ID
--out owner-signed.bin`. Then review and sign `owner-signed.bin` with its newly
reported proposal ID, `--role controller` and the original primary authority
seed. Write `both-signed.bin` and retain its new proposal ID. Every signature
changes the proposal artifact ID. Each signature uses a separate role domain;
one role's signature cannot substitute for the other.

These commands read public artifacts and an explicitly selected signing seed.
They do not open owners or discover newer positions. A static signature review
is not a live storage inspection.

## Select the proposal with the original witnesses

Export the separate settlement scope from the original plan:

```sh
omd work-prune-settlement-scope --input plan.bin --plan-id PLAN_ID
omd work-prune-settlement-scope --input plan.bin --plan-id PLAN_ID \
  --mode publish --expected-id SETTLEMENT_SCOPE_ID --out settlement-scope.bin
```

Explicitly enroll this scope on the same independently selected witness roster
using the [witness CLI](CUSTODY_WITNESS_NETWORK.md#explicit-cli-workflow). Keep its
own original roots and pins. The initial sequence is zero and head is
`SETTLEMENT_SCOPE_ID`. Do not repoint or replace the execution scope's history.
The policy's original guard, keys and threshold are preserved. The settlement
scope depends on the original request-wide execution scope, not on an inventory,
candidate, effect or current storage head.

```sh
omd work-prune-settlement --mode collect \
  --plan plan.bin --plan-id PLAN_ID \
  --inventory inventory.bin --inventory-id INVENTORY_ID \
  --proposal both-signed.bin --proposal-id SIGNED_PROPOSAL_ID \
  --fence-network settlement-witnesses.json --controller-key authority.seed \
  --fence-transport-key client-transport.seed --fence-timeout 5s \
  --out settlement-certificate.bin
```

The network configuration has the same shape as the
[Prune execution configuration](PRUNE_FENCE.md). Endpoints serve the settlement
scope. A minority, lost response or split vote leaves the original obligations
held. Exact collection retry preserves an existing matching output offline.
Otherwise repeat the same proposal against the original witness history; never
adopt an unreviewed remote head or reset a vote.

Verify without private keys or network access:

```sh
omd work-prune-settlement --mode verify \
  --plan plan.bin --plan-id PLAN_ID \
  --inventory inventory.bin --inventory-id INVENTORY_ID \
  --proposal both-signed.bin --proposal-id SIGNED_PROPOSAL_ID \
  --certificate settlement-certificate.bin --certificate-id CERTIFICATE_ID
```

## Apply and complete

Repeat the original owned review inputs from preparation with `--mode review`,
adding `--settlement-certificate settlement-certificate.bin --certificate-id
CERTIFICATE_ID`. Check its new review ID, then repeat with `--mode settle-effect
--expected-review-id REVIEW_ID`. The executor and primary operation guard remain
held while the actual storage effect is checked and the certificate is retained
through intent, executor record and independent confirmation. No storage deletion
or authority entry is submitted.

A pending terminal record resumes through `resume-executor`, using the original
plan, inventory and owner paths without storage, preparation or certificate
flags. Recovery uses the complete certificate already inside the retained
intent. A confirmed retry accepts only the exact certificate bytes, including
its original vote subset.

Review and publish through `work-prune-scheduled-outcome` without settlement or
storage flags. The exported `outcome_kind` is `settlement`; its ID commits the
actual effect and complete decision. Follow the existing per-replica completion
workflow, passing `--settlement outcome.bin --settlement-id SETTLEMENT_ID` to
both scheduled command signing commands. The original owners reject completion
against the bare effect ID. Other work, lifetime spending, retained operation
identities and archive deadlines remain unchanged.

## Compatibility and trust boundary

The new proposal, decision and terminal record have distinct version-0 magic
values and ID/signature domains. Existing request, start, signed result,
cancellation and authority entry encodings are unchanged. Older binaries cannot
read the new terminal record and must not reopen an executor after settlement.
The existing Succeeded stage denotes a retained actual effect; `FenceSettlement`
and exported outcome kind distinguish this path from `FenceResult`.

The witness decision selects one fully signed proposal. Generic witnesses vote
on its committed ID; they do not inspect storage or attest physical deletion.
A controller can obstruct the decision slot but cannot apply a settlement without
the other signature and the original effect. Application trusts the original
storage API and protected histories. It does not provide hardware isolation from
a malicious process, copied live memory or rollback of all protected domains.
Independent deployment, remote profile-5 integration and external review remain
open. If the exact effect is unavailable, the operation remains held.
