# Revoked custody key replacement

Status: opt-in experimental recovery; no consensus or mainnet activation.

A replacement changes the signer, not the participant. The original subject
remains the owner of guard slots, witness membership, service descriptors,
assignment accounting and source obligations. There is one successor per subject
in this bounded version. Revocation remains permanent for both generations.

## Authorization and retained state

The original guard configuration must include nonzero `Revoker` and `Replacer`
public keys. `Replacer` is an offline authority; it may equal `Revoker`, but neither
may equal a protected subject or the guard itself. Omitted fields preserve the
legacy configuration bytes. An existing configuration cannot acquire these
powers in place.

The replacement command binds:

- the original guard identity and revoked subject;
- a fresh successor key and the configured replacement authority;
- the exact retained revocation ID;
- a nonzero `EvidenceID` committing to the operator's recovery inventory;
- the independently retained current guard sequence and head;
- separate successor-possession and offline-authorization signatures.

The guard verifies its own retained revocation and roster, serializes the command
with ordinary choices and revocations, and publishes it durably before returning
a signed receipt. A concurrent event makes an uncommitted replacement stale.
Retain the signed attempt before delivery; do not silently update its cursor.
An exact committed retry returns the original receipt, including after successor
revocation. Another successor, reused subject key or second generation is refused.

The inventory should identify original roots, exact external cursors, pending
proposals/requests, admission prefixes, source heads and retention obligations.
`EvidenceID` commits to that inventory; it does not validate its contents or settle
unknown work. Each original owner still replays its own history and checks the
independently supplied cursor before reopening.

A successor inherits every `(kind, namespace, slot)` of the original subject.
An identical inherited choice can be sealed for the successor without another
journal event. A conflicting choice is refused. Ordinary choices keep the same
lifetime budget. Replacement-capable guards reserve three records per original
subject: original revocation, replacement and successor revocation. At the limits,
there are 4,096 choices and 96 reserved records for 32 subjects.

## Witnesses and quorum membership

Votes and status observations carry the guard-signed replacement receipt and
use the successor's actual signature. Verifiers resolve the receipt against the
guard key in the signed scope or deployment, then count the original member.
Old and new keys cannot count as two witnesses. Canonical ordering remains by
the actual signing public key; mixed historical and successor votes have bounded,
length-prefixed encodings.

Existing job witnesses reopen their original scope/root and exact committed and
pending pin. Admission witnesses reopen their original genesis, enrollment,
placement and complete journal. Replacement has no admission-create operation.
A fresh job scope can enroll the successor only with the same original logical
member and its signed receipt. A pending command stays locked. Spent and pending
operations, source progress, retention and permanent deduplication are unchanged.
The signed job's guard is checked before recording a new admission proposal.
A successor cannot reuse another signed assignment, witness or service role.

## Service signer installation

Service replacement additionally requires `Descriptor.Guard` to have been pinned
before the issuer signed the original descriptor. Prepare it with
`work-archive-custody-gateway --action descriptor-prepare --guard-key <public-key>`.
Its guard must match the execution deployment. Legacy descriptors, including
older profile-5 deployments with guarded effects but unguarded outer responses,
cannot activate service replacement in place.

Every new response under this descriptor requires a guard seal over the complete
signed response, with descriptor ID as namespace and the original service
sequence as slot. The successor's receipt is part of its response signature.
Protected result, acceptance and Serve effects also carry the receipt and retain
their full original deployment/admission/source bindings.

Stop the owner and install the successor using the original private root and an
exact external position. Activation validates the existing source and execution
configuration, takes the original exclusive lock and publishes one private
`signer-replacement` file containing the successor key and public receipt. The
original identity/key files remain part of the immutable placement identity;
new signatures use only the successor. Existing descriptors, source paths,
execution journals and accounting are not rewritten. Each subsequent action
checks the installed file's bytes, permissions and placement. Exact activation
retry confirms durability; partial or changed files block reopening and are not
repaired automatically. A locally decommissioned service cannot be revived.

## Reviewed CLI sequence

Public paths and key paths must be outside private roots. Private signing seeds
for these recovery commands are 32 raw bytes. Each command defaults to `review`,
which reads public inputs only. Apply the same arguments with `--mode run
--expected-review-id <reported-id>`. A change to a public input, endpoint or output
requires a new review. Use a fresh output path for each publication.

1. Revoke the original subject with `work-archive-custody-guard-revoke`. Retain
   the complete signed receipt and independently record the guard's current
   position. Preserve original participant/service histories and pins.
2. On the successor signing machine, use `work-archive-custody-guard-replace
   --action propose --identity <identity.json> --config <config.json>
   --revocation <revoked.bin> --position <guard-position.json>
   --successor <public-key> --evidence-id <inventory-hash>
   --key <successor.seed> --out <proposal.bin>`.
3. On the offline authority machine, use the same command with `--action authorize
   --identity <identity.json> --config <config.json> --proposal <proposal.bin>
   --key <replacement-authority.seed> --out <replacement.bin>`.
4. Deliver with `--action send --identity <identity.json> --config <config.json>
   --request <replacement.bin> --guard-url <endpoint> --out <receipt.bin>`.
   Inspect offline with `--action inspect`, the same identity/config/request,
   `--receipt <receipt.bin>` and a fresh `--out <report.json>`.
5. For an existing job witness, retain `--witness-public-key` as the original
   member. Add `--replacement <receipt.bin>` to its server/open/recovery command
   and supply the successor seed through `--sign-key`. Keep its original root,
   scope ID, exact sequence/head/pending pin and distinct transport identity.
6. For assignment admission `witness-vote`, `witness-commit` or `witness-status`,
   add `--replacement <receipt.bin> --replacement-id <V2-artifact-id>`.
   Keep `--witness` as the original member and use the successor `--sign-key`.
   `witness-create` rejects replacement selectors. Voting still requires the
   endpoint through `--guard-url`; the signed job supplies its verification key.
7. For a configured service, use `work-archive-custody-gateway-replace
   --root <original-root> --descriptor <original-descriptor.bin>
   --descriptor-id <original-id> --position <service-position.json>
   --replacement <receipt.bin> --key <successor.seed> --out <activation.json>`.
   Include `--request <exact-unresolved-request.bin>` only for a retained unknown
   outer request. Start the existing service with its original descriptor and
   `--guard-url` after activation. Activation does not execute that request.

If a replacement reply is lost and the guard restarts, its `serve` action accepts
`--replace-attempt <replacement.bin>` alongside the retained pre-attempt position.
It admits only that position or its one exact replacement extension. Choice,
revocation and replacement recovery selectors are mutually exclusive. A different
or later unknown event is not adopted. Successor revocation uses the ordinary
revocation CLI with `--subject <successor>` and `--replacement <receipt.bin>` for
its public membership proof; it does not permit another replacement generation.

## Unknown outcomes and trust limits

Replacement never reconstructs a volatile session, re-executes consumed work,
refunds a lifetime allowance or releases pending accounting. An executed source
without a valid retained result stays held. A lost or partial original history
cannot be replaced with a fresh journal. Already signed old results and quorums
remain historical evidence, including responses delivered after revocation.
An old effect cannot be re-signed into a different successor effect at an occupied
slot. Recovery of a missing result or further rotations needs a separate protocol.

The original guard key and monotone history must remain outside subject backups
and control domains. This feature does not protect a copied guard key/store, add
independent operators, supply hardware custody, rotate registry/assignment/transport
keys or provide automated incident settlement. The offline replacement authority
and successor delivery are additional trusted operational roles. Separately
operated deployment, long-retention incident procedures and independent review
remain launch gates. Overall production readiness remains **44/100**.
