# Imported custody accounting and one-choice selection

Status: experimental accounting import, with execution disabled. The existing
admission state machine and durable witnesses now carry verified V1 spending,
source position and retention forward. Selection shares the original resource
registry slot with native candidates. This is not protected global exclusion of
old keys, active successor execution, or a mainnet cutover. The subsequent
[sealed source handoff](CUSTODY_SOURCE_HANDOFF.md) now closes legacy access on
original A/B sources; protected activation remains required.

## Import rule

`NewImportedAdmissionGenesis` requires the complete signed review Proposal and
independent resource ID, full descriptor ID, legacy assignment ID, exact retirement
position and Proposal ID. The complete historical verifier remains authoritative:
all admissions, typed terminal closures, source entries, A/B observations and three
review signatures must verify. Unknown results, pending obligations, incomplete
histories and unsupported old operations remain blocked.

The final assignment is derived deterministically. It preserves the original
manifest, initial receipt, custody policy, auditors, replica identity and consumer
permissions. The reviewed Blueprint fixes the new incarnation, authority, control,
transport, witness roster, threshold and pending bound. Policy 5 additionally
commits the semantic registry ID, full registry descriptor ID and entire signed
Proposal ID. Changing any of those changes the outer assignment.

For verified old spending `S` and explicitly authorized allowance `A`:

```text
successor lifetime limit = S + A
initial spent           = S
initial pending         = 0
remaining               = A
maximum complete jobs   = floor(A / 2)
```

The Proposal verifier already requires `S + A <= min(old limit, resource limit)`.
Any unallocated remainder stays unavailable. There is no budget expansion path.
Admission consumes two more units; closing a job releases pending units only.
A timeout, restart, cancellation or source migration never refunds lifetime spending.

The initial source sequence/head, full current receipt and receipt ID are the
last accepted old source entry. The retention floor is the maximum across the
complete old lineage. Original initial receipt and current receipt remain separate
values. No new receipt, proof time, renewal, archive append or reward is created.

Admission sequence starts at zero under the new outer assignment's genesis ID;
its *spent counter and source sequence do not start over*. Every later Admit must
name the carried predecessor exactly. Admission entries and full closure evidence
use the existing accounting rules. The imported history bound is `A + 2` entries,
reserving the normal closure capacity. Old entry signatures cannot become entries
for the new assignment/genesis.

`AdmissionGenesis.Version=5` retains the entire Proposal. All exposed fields are
compared against their deterministic derivation before encoding/verification.
Native Genesis2 rejects a policy-5 assignment or a nonnil import. A missing import,
changed cap, substituted initial receipt or zero-source continuation cannot turn
into a fresh native budget for the same outer assignment.

## One slot across native and imported candidates

Registry descriptor versions remain **1 and 2**. There is no descriptor version 3,
new semantic resource namespace, changed witness roster or reset existing root.

- Descriptor1 accepts Selection1/profile3 only.
- Descriptor2 accepts Selection2/profile4 or the new **Selection3/profile5**.
- Both choices occupy the same original durable slot and pending-vote record.

Selection3 contains the complete imported genesis, including all old proofs.
The resource issuer and **new** authority/control sign that exact candidate.
The old authority/control consent remains inside the signed Proposal. The original
registry quorum then selects the candidate. The existing threshold, sorted votes,
permanent vote, minority retention and exact commit-recovery rules apply unchanged.
A pending native choice blocks a different import vote, and vice versa. A final
selection blocks all different successors, regardless of their format. A valid
quorum may be learned by a minority voter without rewriting its original vote.

Old binaries reject Selection3. Upgrade original registry witness software in
place with its retained independent pins; do not recreate roots to obtain support.
A registry already selected for a different assignment remains selected. An
unavailable quorum or split vote is not permission to reset it.

This provides one-choice safety under the existing honest-quorum and protected
history assumptions. Four logical keys do not establish four independent failure
domains. Historical selection cannot prove that all old raw-key copies stopped.

## Durable imported witnesses

An imported admission witness requires the complete `EnrollmentBinding` format 5
when created, opened or explicitly recovered. It verifies the Selection3 quorum,
resource descriptor, all role signatures and byte-exact imported candidate before
creating a root. A bare genesis or hash-only selection is insufficient. Native
witness APIs retain their existing behavior and reject an unsolicited binding.

The original root retains genesis, placement, complete enrollment and a format-5
ready marker. The marker also commits the retained enrollment bytes. Creation is
exclusive, synchronized and publishes ready last. Interrupted creation stays
retained; it is not repaired by creating a fresh history. Every operation checks
the immutable files. Cold open replays the original nonzero spending/source seed
and all subsequent votes/certificates before comparing the independent pin.

Imported placement records include permanent lock change time, in addition to
path/device/inode/owner/mode. Ordinary root copies, moves, lock replacement and
immediate inode reuse are rejected. Directory change time is excluded because
normal journal writes change it. Local identity checks do not fence a full VM
rollback or revoke an extracted private key.

A failed vote or commit publication makes the live witness uncertain. Recovery
requires the original root, exact genesis, full enrollment, external before-pin
and exact attempted entry/certificate. It cannot choose another proposal, discard
an acknowledged expense or adopt a stale diagnostic Snapshot as a recovery pin.

## CLI workflow

All commands default to public review, with no seed or owner opened. Run unchanged
arguments with `--mode run --expected-review-id <review-id>`. Outputs must be fresh
immutable files outside owners and key paths.

1. `work-archive-custody-cutover-review --action import-genesis` uses `--proposal`,
   `--proposal-id`, `--anchor-id`, `--descriptor-id`, `--legacy-id`,
   `--retired-sequence`, `--retired-head` and `--out`.
2. Existing `work-archive-custody-registry` actions `selection`, `sign-selection`,
   `witness-vote`, `certificate` and `witness-commit` operate on the original
   Descriptor2 slot and exact pins. `selection` derives Selection3 from Genesis5;
   it does not change the descriptor. `witness-create` is only for an independently
   enrolled absent test/deployment root, never recovery of an existing slot.
3. `work-archive-custody-registry --action import-enrollment` verifies a complete
   Selection3 certificate (`--in`, `--in-id`) against the separately pinned
   `--registry`, `--registry-id` and `--registry-descriptor-id`, then writes the
   format-5 binding.
4. `work-archive-custody-v2-admission` requires `--enrollment` and its independent
   `--enrollment-id` for all imported-genesis actions. Existing witness creation,
   vote, commit, status and exact cold recovery use that full binding. No action
   silently discovers enrollment in a private root.
5. `inspect-genesis` reports the verified historical starting counters/source.
   `inspect-history` additionally replays a complete `AdmissionBinding` supplied
   by `--in`/`--in-id`, including every certificate, from that exact genesis.
   These commands need no seed or owner and never claim the result is a live tip.

## Compatibility and bytes

Public legacy review code now lives in `node/custodycutover/review`; the original
package retains public aliases and original-owner operations. Existing review,
V0/V1, native Genesis2, policy2/3/4 and registry1/2 artifact bytes remain unchanged.
The new imported artifacts use:

| Object | Format | Commitment |
| --- | --- | --- |
| Policy5 | `OMCVPOL2`, u16 5; ordinary roster followed by registry ID, descriptor ID and Proposal ID | `OMESH/custody/v5/witness-policy/id` |
| Imported genesis | `OMCVAGN5`, u16 5, one bounded full Proposal field | Existing assignment-derived admission ID and full descriptor ID; outer assignment commits Policy5 |
| Registry choice/vote/quorum | `OMCRSEL3` / `OMCRVOT3` / `OMCRGCT3`, u16 3 | Existing registry suffixes under `OMESH/custody-registry/v3/` |
| Imported enrollment | `OMCVENR5`, u16 5, full Descriptor2 and Selection3 certificate | `OMESH/custody/v5/enrollment-binding/id` |
| Local ready | `OMCVAWR5`, genesis ID, witness key, retained enrollment hash | Enrollment hash domain `OMESH/custody/v5/retained-enrollment` |

Imported genesis is bounded by the 32 MiB review Proposal bound plus its envelope.
Native genesis keeps its original bound. Registry selection still has its existing
8 MiB limit: a larger otherwise valid review cannot be selected by truncating it
or replacing it with a digest. Existing proof-delivery profiles do not accept
policy5. Three fixed imported vectors and the original compatibility vectors pin
these choices; decoder fuzzing covers the new envelopes.

## Activation boundary and verification

All original execution owner constructors reject policy5. Mandatory admission
proof alone does not enable it; the raw constructor rejects it before opening
sources or creating files. No imported Target/Acceptor, active source clone,
legacy signer revocation, witness deployment upgrade or consensus activation is
performed by this slice. Actual execution remains blocked even after accounting
selection/admission. Unexecuted admitted obligations remain pending until supported
settlement rules supply complete evidence.

The next gate is protected, monotone version enforcement on every effectful and
acceptance path, with original-source handoff and independently enrolled witness
roots/pins. Otherwise an old program with copied keys/data can bypass a gate it
never consulted. The selected accounting history must be preserved while that
work proceeds. Replacing it is not recovery.

Tests cover a real retained legacy success corpus, nonzero imported accounting,
exact source predecessor, no-refund closure arithmetic, incompatible native
initialization, disabled execution, shared registry choices, minority votes,
interrupted writes before/after synchronization, stale pins, original cold recovery,
root/lock/enrollment substitution and separate CLI processes with lost output.
Synthetic closure receipts in the reference arithmetic test are explicitly marked;
they are not evidence that the disabled imported runtime executed.

```sh
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-all
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 go test -tags=integration ./cmd/omd -run '^TestProcessRemoteImportedAccountingColdRecovery$' -count=1 -timeout=2m
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 go test ./node/custodyv2 -run '^$' -fuzz '^FuzzImportedAdmissionCodecs$' -fuzztime=5s
```

The [public manifest](evidence/custody-import-public-20261028.json) and
[archive](evidence/custody-import-public-20261028.tar.gz) contain only historical
public proofs and reports. Extract into an empty directory and verify against a
separately trusted manifest with a current local binary:

```sh
python3 scripts/verify_imported_public.py --omd ./bin/omd --corpus /absolute/path/to/extracted-corpus --manifest docs/evidence/custody-import-public-20261028.json
```

The verifier independently invokes the reviewed production commands to derive the
same genesis/enrollment and replay initial/final accounting. It opens no owner and
loads no key. [Acceptance evidence](evidence/custody-import-20261028.json) records
exact source hashes, commands, native binaries and results.

The first Linux acceptance run exposed repeated complete historical signature
verification within one action. Registry/CLI cases exceeded their existing
two-minute limit. Validation now shares a verified assessment within the same
call; all signatures and field comparisons remain required. No global cache,
timeout increase or weaker assertion was introduced. The same final native
binaries pass accounting, registry, CLI and lost-output process cases on both
servers, and both production binaries replay the public corpus. These are
per-host tests, not a new joint WAN migration or independent protected deployment.
Internal controlled checks are not an independent audit. Readiness remains
**44/100**.
