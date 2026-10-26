# Explicit offline prune preparation

Status: opt-in pre-alpha tooling. Six primary commands prepare the inputs for the
[command-only transport](PRUNE_COMMANDS.md). They do not open WorkChain, validate
live archive availability, execute or cancel pruning, stop/retire assignments,
or enforce all-required-assignment policy. Review is the default, not creation
or signing. Nothing here is a service-startup or recovery fallback.

Two additional offline secondary signing commands bind an original primary
request to a selected secondary assignment, as described below. Their outputs
can enter a prepared inventory or typed outbox. The current command server still
accepts only its original primary assignment; secondary remote delivery and
supervised multi-owner CLI ownership remain separate gates.

The assignment, storage-bound request and independent IDs must already exist.
Request construction and validation against the actual protected database remain
separate guarded library workflows. A structurally valid request file is not
evidence that a database exists, is current or may be pruned.

## Inputs and trust

Every command needs `--assignment` and `--assignment-id`. The assignment is a
bounded canonical binary artifact, not JSON; the ID must come from the separately
reviewed assignment. Bootstrap/signing of an executor command also requires
`--request` and its independent `--request-id`. The request must match the
assignment's archive scope and declared prune consumer, and have a nonzero
storage-incarnation ID. Do not invent a replacement ID for lost storage.

Inputs use a bounded regular-artifact reader and canonical decoders. Together
they reject final-path symlinks, oversized/truncated/noncanonical files and a
changed opened-file identity. They do not establish ownership/ACL policy,
trusted parent directories, physical independence or secure memory erasure.
Keep keys and trust material protected;
do not place seed bytes in command arguments or logs.

All IDs are nonzero 32-byte hashes encoded as hex. Unknown, positional and
duplicate flags are rejected. Modes are explicit single values, not composable
switches. Review rejects write/sign-only flags even when their values are empty.
No command accepts a network address or automatic retry flag.

An independently reviewed ID is a decision checkpoint, not another value to
blindly copy from untrusted input. Review the displayed scope, keys, sequence,
head and evidence against your retained records; retain the reviewed ID outside
the candidate artifact before invoking a write mode. Do not pipe review output
directly into signing or creation as a substitute for that review.

## 1. Initialize new journal pairs

Authority placement review (substitute the placeholders before running):

```sh
omd work-prune-authority-bootstrap \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --authority /srv/om-authority \
  --authority-pins /srv/om-authority-pins
```

Executor placement and request review:

```sh
omd work-prune-executor-prepare \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --request /srv/om-trust/request.omcpr \
  --request-id <independently-retained-request-id> \
  --executor /srv/om-prune-executor \
  --executor-pins /srv/om-prune-pins
```

Each command accepts `--mode review|create|verify`, default `review`:

- `review` checks input and root placement. Both parents must exist; roots must
  be disjoint and cannot be final-path symlinks. It does not open journal
  contents, acquire their locks, sync or create anything. An existing empty,
  corrupt or busy root can pass placement review; this is not initialization
  verification or a guarantee that creation will succeed.
- `create` uses the same arguments with `--mode create`. Both targets of that
  pair must be absent. It locks the independent pin journal before creating and
  locking the writer, verifies the resulting snapshot and closes both before
  printing success. An old authority cannot receive fresh pins through this
  command. A used, empty or partially initialized root is never reset.
- `verify` uses `--mode verify` and opens only the two existing roots against
  the same independent IDs. It reports observed/confirmed state and retained
  attempts, then closes both. Executor verification also compares the complete
  retained canonical request with the supplied artifact. Opening may re-sync
  existing evidence; it never appends, confirms, resumes or starts an attempt.

These are two separate pair operations, not an atomic four-root transaction.
Their individual path checks do not prove that the four-root layout will pass
the command runtime's combined checks. A failure can leave partial trees.
Preserve them and their independent pins; do not delete/recreate them, attach
fresh pins or switch paths as automatic recovery. Explicit verify can accept
only a fully valid retained initialization. A missing final initialization
record is an error, not an invitation to repair it in place.

Different paths are not different failure domains. Root creation does not fence
copied storage or keys. Independent pin protection and ownership handoff remain
operator prerequisites. Creating a second copy of the same logical assignment
is not a way to recover its lost history.

## 2. Review and consumer-sign one command

Example initial Admit review:

```sh
omd work-prune-command-sign \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --request /srv/om-trust/request.omcpr \
  --request-id <independently-retained-request-id> \
  --kind admit \
  --expected-sequence 0 \
  --expected-head <independently-retained-assignment-id>
```

Sequence must be supplied, including zero, as a canonical decimal integer.
The initial head must be the assignment ID; a later head must not reuse that
ID. The consumer comes from the pinned request and must have Prune permission.
Static sequence limits reject impossible operations. No journal is opened to
learn, refresh or validate the current head; a stale reviewed command can still
be signed and later rejected by the live service.

The output includes `command_review_id` and `review_id`, the exact existing
command-signature message hash. After independent review, repeat the same
arguments with these additional flags:

```text
--mode sign
--consumer-key /srv/om-keys/prune-consumer.key
--expected-review-id <independently-reviewed-command-message-id>
--out /srv/om-artifacts/admit.command
```

`--consumer-key` contains exactly 32 raw Ed25519 seed bytes. All artifact,
scope and review-ID checks precede the key read; the key must match the named
consumer. The command never generates keys or uses the transport identity as
the signer. Review forbids `--consumer-key`, `--expected-review-id` and `--out`.

Only `admit` and `complete` are supported. A Complete review/sign uses
`--kind complete`, an independently reviewed sequence/head, and additionally:

```text
--admission /srv/om-artifacts/admit.entry
--admission-id <independently-retained-admission-entry-id>
--terminal /srv/om-artifacts/terminal.bin
--terminal-id <independently-confirmed-terminal-evidence-id>
```

The original co-signed admission must match the assignment, consumer and exact
request. Completion must follow that admission; an immediately following
completion's head is that admission ID. Terminal bytes must be the canonical
cancellation or canonical prune effect for the same request/ticket and archive
boundary; successful effects must also match the storage ID. Admit rejects all
four completion-only flags, including empty values.

[Reviewed local maintenance](PRUNE_MAINTENANCE.md) can now supply the canonical
cancellation bytes through its `canonical_hex` output. Decode that exact field
into a protected terminal artifact and independently retain/check its terminal
ID before this signing workflow. Maintenance does not sign or submit Complete.

These checks bind supplied historical bytes, not physical state. A cancellation's
binding ID is committed by the independent terminal ID but cannot prove the
executor durably cancelled without its retained journals. An effect file alone
does not prove a deletion occurred in a particular database. Output therefore
always states `historical_only=true terminal_durability_proven=false
execution_authorized=false`. The original command service independently checks
its own retained terminal state before it accepts Complete.

## 3. Independently review and authority-co-sign

Use `work-prune-command-cosign` with the same assignment/request/kind/position
and, for Complete, the same four evidence flags. Add:

```text
--command /srv/om-artifacts/admit.command
```

Default review verifies the consumer signature and requires every unsigned
field to equal the explicitly reviewed draft. Its `review_id` is now the
existing **entry-signature** message hash, binding the consumer signature and
the assignment's authority key. It is not the consumer review ID. After a
separate review, repeat with:

```text
--mode sign
--authority-key /srv/om-keys/authority.key
--expected-review-id <independently-reviewed-entry-message-id>
--out /srv/om-artifacts/admit.entry
```

The authority seed must match the assignment. Review forbids the key/output/
expected-review flags. Co-signing neither admits a ticket nor verifies a live
head. Existing command/entry encodings, signature domains and network formats
are unchanged. Signing output includes the new co-signed `entry_id`.

Both signers publish canonical binary artifacts without replacing existing
files. A retry accepts only byte-identical output, syncs that existing inode,
checks its identity and closes it before syncing the directory. Parent
directories may be created by the existing artifact publisher; configure a
trusted output location.
A conflicting output is an error. A stdout failure may happen after durable
publication: preserve the artifact and repeat only the exact reviewed signing
attempt to recover its output, not a new head or replacement signature.

## 4. Prepare a typed client outbox

Review an already co-signed admission and both transport pins:

```sh
omd work-prune-admission-prepare \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --entry /srv/om-artifacts/admit.entry \
  --entry-id <independently-retained-entry-id> \
  --client-peer-id <pinned-client-transport-id> \
  --server-peer-id <pinned-server-transport-id>
```

Completion uses `work-prune-completion-prepare` and its own Complete entry.
The two peers must be nonzero, distinct and separate from assignment authority,
consumer, replica and auditor identities. The typed entry's signatures,
assignment/role/purpose and static sequence bounds are checked before creation.
This does not inspect server journals, pending tickets, current head or terminal
durability. There is no key input, network or automatic send.

Review prints the full scope and derived `intent_id` and forbids `--outbox` and
`--intent-id`. After review, retain that ID independently and repeat with:

```text
--mode create
--outbox /srv/om-admission-outbox
--intent-id <independently-reviewed-intent-id>
```

Creation exclusively initializes one new typed root. Verify uses the same full
arguments with `--mode verify`, opens only the existing root and compares its
entire intent to the supplied entry and pins. It can report a locally retained
historical receipt and exchange nonce with the server offline. It cannot send,
reset the receipt, repair a partial root or assert present execution authority.
Owners close before output; a failed stdout write leaves the root for explicit
verify, not another create. Review and creation both report `sent=false`.

Finally use the [transport runbook](PRUNE_COMMANDS.md) to start the explicitly
configured service and deliver a retained outbox. Preparation does not select
or perform a live effect, even after an admission receipt has arrived.

## 5. Review and sign secondary commands

Use `work-prune-secondary-command-sign` for the consumer signature and
`work-prune-secondary-command-cosign` for the authority co-signature. They share
the review/sign modes, role-specific seed inputs, independent review ID and
immutable publication behavior above. They read no owner journal or database.

Each command requires `--assignment` / `--assignment-id` for the selected
secondary and additionally `--primary-assignment` / `--primary-assignment-id`
for the original primary. Both assignments must be independently reviewed,
have different IDs and replica public keys, share network/genesis/activation/
base/manifest/statement, and allow the original request consumer to Prune.
Initial receipts, custody policies, generations and auditor sets may differ
between these independently selected replicas. These checks do not establish
the complete required set or current live permission.

`--request` and `--request-id` always name the **unchanged primary request**.
Changing its AssignmentID to the secondary would create a different operation.
The Admit draft uses the secondary AssignmentID and the original primary
request ID as OperationID. The sequence/head refer to the secondary's explicitly
reviewed history. Initial admission review, for example:

```sh
omd work-prune-secondary-command-sign \
  --primary-assignment /srv/om-trust/primary.omcaa \
  --primary-assignment-id <reviewed-primary-assignment-id> \
  --assignment /srv/om-trust/secondary.omcaa \
  --assignment-id <reviewed-secondary-assignment-id> \
  --request /srv/om-trust/primary-request.omcpr \
  --request-id <reviewed-original-primary-request-id> \
  --kind admit \
  --expected-sequence 0 \
  --expected-head <reviewed-secondary-assignment-id>
```

After independent review, add the same consumer-key / expected-review-id / out
flags from section 2. Authority review uses the secondary co-signing command,
the same scope/position flags and the consumer `--command`; after independent
review add authority-key / expected-review-id / out as in section 3. Keys are
read only after all scope, artifact and review-ID checks succeed.

No inventory is required at signing time: inventory already contains the
co-signed admissions, so requiring it to create their first signatures would
be circular. Assemble and independently pin the complete inventory afterwards
using the existing library preparation. A signature or typed outbox alone
cannot substitute for the live primary guard used by secondary admission.

For secondary Complete, set `--kind complete` and supply six evidence flags:

```text
--admission /srv/om-artifacts/secondary-admit.entry
--admission-id <reviewed-secondary-admission-id>
--primary-admission /srv/om-artifacts/primary-admit.entry
--primary-admission-id <reviewed-primary-admission-id>
--terminal /srv/om-artifacts/primary-terminal.bin
--terminal-id <reviewed-primary-terminal-evidence-id>
```

Each admission must match its own pinned assignment/authority and the same
original request ID/consumer. Sequence/head checks use the **secondary admission**;
the Complete draft closes that secondary ticket. Terminal validation uses the
**primary admission**: effect/cancellation bytes must match the original primary
request and primary ticket, and successful effects also match its storage ID
and exact boundary. A secondary ticket cannot be substituted into those bytes.
Admit forbids all six completion evidence flags, even with empty values.

Secondary output adds `secondary=true`, `primary_assignment_id` and
`primary_admission_id` (zero for Admit) to the existing scope report. The existing
command/entry signature-message review hashes, canonical encodings and signature
domains are reused. Offline terminal validation remains historical:
`terminal_durability_proven=false execution_authorized=false`. Supplied effect
bytes do not prove an inventory-bound start. The live secondary completion
adapter must still require its own confirmed executor outcome and exact actual
secondary admission before submitting Complete.

The generic admission/completion preparation commands accept these canonical
secondary entries with the secondary assignment and its independent ID. They
can review/create/verify the corresponding typed outbox using separately pinned
transport peers. This retains a delivery intent without opening a socket or
checking a server. **The current primary command server cannot receive secondary
operations.** No new secondary server/delivery endpoint is installed by signing
or outbox preparation; retain these artifacts for the later reviewed handoff.
The original primary signing commands continue to reject secondary-only flags.
Developers can explicitly install the caller-owned fixed-secondary library
sessions described in [PRUNE_ACCEPTANCE.md](PRUNE_ACCEPTANCE.md); the installed
primary command CLI is not a multi-owner or secondary service.

## Verification boundary

Tests cover separate review/sign domains, exact artifact pins, immutable
publication, both new-root pairs, partial initialization, ownership exclusion,
stdout failure and both typed historical receipts. A separate-process scenario
uses all six commands, delivers Admit, explicitly cancels offline through the
existing guarded library API, then signs/prepares/delivers Complete. Real broken
stdout tests preserve new roots and signed artifacts for exact recovery.
The fixture has no WorkChain database. These tests establish neither a live
prune pipeline nor physical fencing, power-loss behavior or testnet readiness.

Secondary tests additionally cover the original primary request across both
signers, target vs primary admission/terminal separation, re-pinned archive/role
substitutions and immutable typed outboxes. Three separate-process phases cover
Admit and success/cancellation Complete. Nine closed-stdout cases retain their
consumer command, authority entry or outbox and recover through exact retry or
explicit verify. No secondary network delivery or live terminal acceptance is
claimed by this offline process coverage.
