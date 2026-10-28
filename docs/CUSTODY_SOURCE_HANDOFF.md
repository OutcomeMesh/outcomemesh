# Sealed original-source handoff

Status: implemented local version exclusion and sealed handoff to a selected
profile-5 successor. Imported execution remains disabled. Protected deployment,
revocation of copied raw keys/whole-machine backups, and active successor access
remain activation requirements. This change does not establish those requirements.

## Original source, exact successor

`ReviewSourceHandoff` consumes the complete imported genesis and Selection3
binding, with independent genesis ID, full descriptor ID, enrollment **object** ID
and original SourceLocation ID. The placement must match the old signed A or B
observation's nonce/commitment. Copying a source to another directory, replacing
its permanent lock, or choosing a different original owner changes that pin.
The reviewed record fixes registry identities, full successor identities, exact
selected proof, old source sequence/head/receipt, retention floor and spent count.

`TransferSourceHandoff` reacquires the original guards used by source observation:
A's confirmed retired coordinator and complete authority history, or every exact
sealed B worker with no pending mutation. It then acquires the original journal
lock, checks the location again, replays the full current source, and requires the
reviewed predecessor and exact terminal entry. Missing, busy, divergent, replaced
or unresolved original state blocks transfer. Retained pending publication files
and undecided orphan bodies block sealing even when ordinary replay still reports
the expected committed head. Nothing deletes or promotes that evidence. An empty prepared root or supplied
Snapshot is insufficient. The selected proof and all caller-owned slices are
frozen before publication.

Transfer modifies the original source root, without copying or renaming it. Its
header, accepted entries, receipts and archive chunks remain retained. There is
no append, renewal, reward, new proof time, spending refund or new admission.
The successor is named as the sole destination, but receives no live source API.

## Ordered publication and recovery

Under the whole source decision and original owner guards:

1. Replay and compare the exact source predecessor and retention floor, and
   reserve the complete seal/proof additions under the hard byte/path bounds.
2. Publish and synchronize `source-handoff.omcsh`, the permanent version seal.
3. Publish and synchronize `source-handoff-proof.omcsh`, the full selected binding.
4. Recheck the original identities and complete retained pair before returning.

The seal is the first decision. Once its name exists, all ordinary source use is
blocked, including if the file is malformed, incomplete, a symlink or directory.
A missing proof after the seal is an unresolved handoff. The same explicit
transfer may finish it only with the exact original record, complete proof and
independent pins. A proof-only root is invalid. Different genesis, enrollment,
source position or placement cannot replace the committed attempt, even if another
certificate would also be a valid quorum for that selection.

The preflight reserves logical replay capacity, not physical disk space. A real
disk-full or device failure after the seal can still leave a partial handoff;
that source stays sealed until exact recovery can finish.

Publication uses synchronized sibling temporary files and exclusive hard links.
A failure retains its evidence. Published files are never overwritten or removed.
Retry synchronizes already identical records. Partial/corrupt committed bytes
refuse; recovery does not invent or repair them. A failed live decision is poisoned
and requires cold recovery. Cancellation or missing stdout cannot reopen legacy
access. There is no unseal, reset, fallback, or automatic discovery of a new tip.

One side may be sealed before the other during a failure or partition. Its seal
stays retained. A `SourceHandoffPair` requires A and B in fixed role order, distinct
original placements, and identical successor/proof/source/accounting fields.
`Verify` compares both records with the complete selected import and both pins.
This pair is historical evidence. Activation must independently inspect both
original sources and the protected version authority; a pair alone grants no action.

## Version checks on current access paths

The permanent source lock covers each complete managed action, including signing,
publication and transport. A compliant handoff therefore waits for existing
source-owning actions to drain; it cannot commit between their checks and effects.
The updated code also rechecks version and root/lock identity on every held
`CustodyJournalDecision` State, Head, Usage, Append and Rotate call. A detected
substitution permanently poisons that handle, including if the named file is later
removed. A handoff decision itself cannot append or rotate, even before sealing.

| Current path | Enforcement |
| --- | --- |
| Ordinary source create/open and decision acquisition | Any handoff seal/proof name refuses. No missing file or lock is recreated by explicit existing-open recovery. |
| Ordinary source State/Head/Usage | Handed-off sources refuse; existing pre-handoff historical retirement inspection keeps its behavior. |
| V2 Target actions, result reads/signing, Serve and recovery | Common owner check rechecks the retained source decision. |
| Target archive effects | Additional check after durable consumption and the final pre-effect boundary, before the first object-store open/read. |
| Acceptor acceptance and recovery | Source decision checks before source operations and immediately before signing the accepted receipt. |
| Runtime record publication | Recheck before publication and existing full owner check afterward. |
| Incoming admission proof delivery, including cached receipt reads | Retained source check at entry and again after proof persistence, before signing its acknowledgement. |

Direct offline proof functions and a program with arbitrary access to raw keys,
source files or a whole cloned machine remain outside this local boundary. Older
binaries do not know this seal. Source storage and signing authority must be
isolated behind an independently protected, monotone authority that all accepted
effects consult; deployment must remove participant access that bypasses it.
No protected backend has been substituted with a boolean or operator callback.
Profile5 execution constructors continue to refuse it until that boundary exists.
These checks are not a global old-key revocation certificate.

## CLI

`work-archive-custody-source-handoff` supports `--action transfer` and `inspect`.
Both default to public review, which reads proof/placement metadata, opens no
owner and loads no key. `--mode run --expected-review-id <id>` executes the exact
reviewed action. It needs:

- `--genesis`, `--genesis-id`, `--genesis-descriptor-id`;
- `--enrollment`, `--enrollment-id` (the canonical EnrollmentBinding object ID);
- `--source` (complete SourceLocation JSON), `--placement-id`;
- `--out` (fresh public record outside all source/owner/input paths).

The enrollment flag here names the object ID, as retained in the source record;
it is distinct from the artifact hash used by the admission CLI. Review output
includes the exact record and all input hashes. Inspect requires the complete
committed record/proof under original guards; it cannot inspect an absent or
incomplete handoff as successful. Repeat a lost transfer with the same pins and
a fresh output path. Retain the first output and both original roots. No private
seed, witness enrollment reset or activation flag is accepted by this command.

## Bytes and compatibility

Source record: `OMCSHOF1`, u16 version 1, u16 target profile 5, u8 role (A=1/B=2),
then RegistryID, RegistryDescriptorID, GenesisID, GenesisDescriptorID,
EnrollmentID, ProposalID, PlacementID, ProofID, SourceHeadID and ReceiptID
(each 32 bytes), u64 source sequence, u64 retention floor and u32 spent operations.
Integers use the existing codec. Exact length is **353 bytes**. SourceHeadID alone
may be zero when sequence is zero; the other identities are mandatory.
ID domain: `OMESH/custody-source-handoff/v1/id`.
The complete proof is bounded at **9 MiB**, above the existing Selection3 binding
bound. Proof commitment: `OMESH/custody-source-handoff/v1/selected-proof`.

Pair: `OMCSHPR1`, u16 version 1, fixed full A record then fixed full B record;
exact length **716 bytes**. ID domain: `OMESH/custody-source-handoff/v1/pair/id`.
Decoders require exact length, version, roles and canonical round trip. Two fixed
vectors and separate fuzz targets pin the new formats.

Existing V0/V1 journal and authority bytes, policy2/3/4/5, registry1/2 descriptors,
selections, imported accounting and wire packets retain their encodings. There is
no consensus rule change. The explicit behavior change is that handed-off source
roots can only be opened through the exact sealed-handoff API, which cannot
execute work. Historical replay recognizes the two new retained file names;
malformed named files never authorize ordinary use.

## Acceptance

Tests cover full original A/B transfer after a real managed V1 exchange with
spent=2/source=1, fixed source/retention, original guards, signed placement,
conflicting/missing proofs, copied roots, source discrepancies, first-seal/proof
publication faults, exact cold recovery, cancellation while locked, poisoned
handles, lock/root replacement, mutation of caller-owned proof bytes, partial A/B
pairs, wrong role order and noncanonical packets. Runtime tests inject a version
change before object reads, after source acceptance but before receipt signing,
and before/cached delivery acknowledgements. The process campaign loses stdout
after transfer publication and recovers through the same public CLI.

[Acceptance evidence](evidence/custody-source-handoff-20261029.json) records the
frozen sources, required checks and limits of the controlled campaign. Production
readiness remains **44/100**; this local exclusion layer closes no independent
protected-deployment, external-audit or sustained public-testnet gate.


## Isolated source access after handoff

The separate [source/version gateway](CUSTODY_GATEWAY.md) can now inspect this
exact seal and read original B objects while the original A/B and journal guards
are held. Its fresh key/private storage live under a different Linux UID from
participants. Exact per-action pins, retained replies and irreversible revocation
provide the first protected service component. It grants no imported job
execution and does not claim root/VM-clone resistance; active runtime integration
and independent deployment remain required.
