# One-choice resource enrollment foundation

Format 2 now selects fresh profile-4 owners under the
[mandatory enrollment runtime](CUSTODY_V2_ENROLLED.md). The format-1 behavior below
remains selection-only and cannot be upgraded in place.

Status: experimental selection-only library, original witness journals and
reviewed operator CLI. It records one profile-3 assignment under an independently
provisioned resource anchor. It grants no execution, migration, profile upgrade
or mainnet activation permission.

The issuer here is an operational custody-enrollment role. It has no authority
over other holders' funds, trade prices, coin emission or global consensus rules.

## Identity must precede a candidate

The assignment-wide admission coordinator accounts within an assignment. A new
IncarnationID, assignment, receipt, participant key or witness roster can produce
another assignment ID. Treating that ID as a protected resource's identity would
allow another enrollment namespace and an apparent fresh allowance.

The registry therefore starts from three independently selected fields:

| Anchor field | Meaning |
| --- | --- |
| NetworkID | Intended chain network |
| ChainGenesisID | Exact chain genesis |
| ResourceID | Stable resource identity assigned by the protected enrollment issuer |

The semantic RegistryID hashes only those fields under
`OMESH/custody-registry/v1/id`. The complete descriptor separately fixes issuer,
witness roster/threshold and maximum operation/pending allowances. Changing any
of these policy fields changes DescriptorID, while preserving the RegistryID.
Every signature and witness journal also binds that full DescriptorID.

ResourceID is not derived from a received candidate or its nonce. An independent
issuer must enforce which physical sources and obligations belong to it. Pure
hashes cannot establish that two differently declared ResourceIDs refer to the
same disks, VM, copied key or legacy obligation. Creating a new anchor for the
same resource is not recovery. Local placement checks cannot supply this missing
deployment guarantee.

## One immutable selection

Genesis version 1 requires 4–16 sorted unique witness keys and a threshold
strictly greater than two thirds. Issuer and registry witness keys must be
separate; candidate validation also excludes every assignment/replica/control/
transport/consumer/auditor and custody-job witness key from those registry roles.
Distinct keys alone do not establish distinct protected failure domains.

A Selection binds RegistryID, full registry DescriptorID and the exact complete
V2 admission Genesis. It requires three independent role signatures in separate
domains: enrollment issuer, assignment authority A and target control B. All
three sign the same unsigned body. Replacing assignment, source descriptor,
budget or roster invalidates that agreement.

Candidates are limited to the existing policy-3 descriptor format and a full
replay version-0 initial receipt. Network/chain identity must match the anchor,
and selected operation/pending limits cannot exceed its fixed caps. This is a
new-origin preparation rule. A receipt's shape does not prove that the original
journals are at zero, that no old grants exist, or that all prior spending was
accounted. Protected issuer eligibility and the later original-source checks
remain required. There is no legacy import or accounting bridge in this format.

Registry votes bind exact registry/descriptor/selection IDs and a member key.
A certificate requires unique sorted members and a full valid selection. Weak,
duplicate, foreign-descriptor, foreign-network, shared-role or over-budget
candidates are refused.

The reference state has one transition:

`sequence 0 / head RegistryID` → `sequence 1 / head SelectionID`.

The selected assignment and admission Genesis/descriptor remain permanent.
There is no release, replacement, expiry, counter refund, roster change or
second slot. Unused capacity is not permission to select another assignment.
Snapshots expose diagnostic caps and chosen IDs, not newly granted spending.
State freezes inputs and serializes concurrent Apply/Snapshot calls.

## Original durable witnesses

Each witness retains an original private root and permanent kernel lock. Ready
binds registry ID, full descriptor and member. The origin bytes, absolute UTF-8
path, device/inode/user/mode stamps, bounded file set and immutable records are
checked on every operation. Ordinary copy, move, same-path replacement, missing
ready/lock, malformed key, unknown file and truncated evidence fail closed.
Initialization never recreates an existing or interrupted root.

Before signing a vote, the witness retains the full canonical selection with
file and directory durability. Before applying a quorum, it retains the full
certificate. A valid majority may override a different local minority vote;
both complete records remain retained. This is not permission to discard a
conflicting majority or reset a selected slot.

Any uncertain write poisons the open handle. Cold Open validates and synchronizes
existing bytes without issuing a new vote or selecting another candidate.
Explicit recovery accepts the exact attempted selection or certificate and its
original external sequence/head/pending pin. A different sufficient QC subset
cannot replace the pinned attempted certificate after lost output.

The root has a 20 MiB retained-byte cap. Public descriptors are at most 2 KiB,
selections at most 8 MiB, and certificates add at most 16 fixed 202-byte votes.
Counts and lengths are bounded before allocation. Every format has its own
version-1 magic, ID and signature domains; V0/V1 and custody V2 bytes are unchanged.

## Reviewed CLI

Command: `omd work-archive-custody-registry`.

Every action defaults to public review without loading a seed or opening a
witness. Run the unchanged arguments with
`--mode run --expected-review-id <id>`. Review binds complete public input bytes,
semantic pins, role/key paths, original placement metadata, before-position and
fresh immutable output. Unused or duplicate selectors are errors. Inputs, keys
and outputs must stay outside the original root.

1. `genesis --draft <JSON> --out <file>` prepares the public canonical descriptor.
   Its review exposes both IDs for independent inspection. It creates no owner.
2. Every subsequent action requires `--registry`, `--registry-id` and
   `--registry-descriptor-id`. `selection` additionally takes `--candidate`,
   `--candidate-id` and `--candidate-descriptor-id` for a complete canonical
   profile-3 admission Genesis.
3. `sign-selection` takes `--in`, its registry-domain `--in-id`,
   `--sign-role issuer|authority|control`, `--sign-key` and a fresh `--out`.
   Partial signatures remain preparation; all three are needed before voting.
4. `witness-create`, `witness-vote`, `witness-commit` and `witness-status` take
   `--root`, `--witness`, `--sign-key` and explicit `--sequence`, `--head-id`,
   `--pending-id`, including explicit zero. Vote/commit also pin their full
   typed input and artifact ID. They never discover/adopt a different head.
5. `certificate` takes a fully signed selection plus comma-separated `--votes`
   and matching `--vote-ids` in sorted member order. It opens no owner.
6. Recover lost vote or commit output to a fresh output using the same exact
   input and original before-pin. Status requires the exact committed current
   pin. All outputs advertise `selection_only=true`, `execution_granted=false`
   and `legacy_cutover=false`.

This is an operator channel, not an automatic enrollment RPC. Creation of
runtime owners, admission delivery and custody work remain separate operations.

## Integration and version boundaries

Profile-3 runtime and delivery are unchanged and do not yet mandate this
registry certificate. A registry certificate cannot be decoded as an admission
binding or used as a job Claim, Serve decision or legacy completion. This stage
closes a selection foundation, not the protected activation gate.

The selected profile-3 assignment is immutable. A future required profile would
have another AssignmentID; this selection cannot automatically authorize it.
Before any mandatory integration, a version contract must explicitly bind
old/new assignment IDs, source/accounting continuity, archive obligations and
independently enforced exclusion of old execution paths. Existing selection
cannot be reset as an upgrade. A genuinely new protected origin may use a future
format, but a new ResourceID for the same source is not a substitute bridge.

Likewise, a later registry-format version must preserve this protected anchor
identity or carry an explicit monotone bridge. Merely changing the ID domain to
`v2` would create another namespace. No such upgrade mapping, profile-4 encoding,
physical key fence or legacy migration is invented by this prototype.

The [legacy cutover requirements](CUSTODY_V2_MIGRATION.md), protected independent
issuer/witness enrollment, original-source/current-owner checks, mandatory
runtime integration, split-vote progress, physical device acceptance, external
review and public-testnet gates remain open. A quorum is historical agreement
under those assumptions; it cannot prove raw keys or running memory were never
copied, revoke an offline old signer or establish physical uniqueness.

## Recorded acceptance

The 2026-10-28 [acceptance index](evidence/custody-registry-20261028.json)
records 17 checks through the reviewed operator CLI on two observed Linux
kernels. Issuer and authority sign on A, control signs on B, and four original
registry witness roots are created independently, split 2/2. Three witnesses
vote for one assignment while the fourth retains another candidate. A real
majority certificate selects the same assignment at every root without deleting
that minority proposal.

One vote and one commit lose stdout after retained output. Exact cold retries
recover the same bytes. Weak/duplicate quorums, another assignment after
selection, stale position, an external wrong descriptor and a changed descriptor
under the same RegistryID are refused. Original proposal/QC hashes remain
unchanged after refusals. No custody source, execution owner or service is created.
These observations establish the controlled operator selection slice, not
physical issuer protection or runtime activation.

The [public manifest](evidence/custody-registry-public-20261028.json) pins 59
artifacts in an 8,789-byte archive. Production Go APIs verify both three-role
selections, four signed votes, the three-vote majority, four retained proposals
and certificates, exact vote/commit recovery and every initial/final diagnostic
against reference-state replay. Native Go 1.26.7 builds use readonly/offline
modules with CGO disabled; both hosts use the same three pinned binaries.
All 719 packed Go/module/public-fixture files remain at the native source pin.

Validation passes all seven race groups, fresh CLI process integration,
integration vet, 56 Python helper tests, five golden vectors and bounded decoder
fuzz smoke. Nineteen new Go tests include four persistence barriers, root/descriptor
replacement, malformed key/path and incomplete-file refusal, minority retention
and concurrent one-winner selection. No task process remains on either server.
