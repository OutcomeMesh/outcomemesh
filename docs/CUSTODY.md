# Custody renewal journals

The experimental custody commands support repeated renewal cycles for one
archive manifest and replica. Both participants keep their own journal. Each
startup verifies the original receipt, fixed auditor policy, and every completed
renewal before selecting the next predecessor.

This is operator tooling for the WorkGraph archive path. It does not enable
canonical pruning, activate consensus rules, or certify independent storage.

## Journal layout and publication

`header.omcj` fixes the manifest ID, initial signed receipt, and a domain-separated
digest of the sorted auditor keys and all custody policy limits. An entry carries
its sequence, previous entry ID, previous receipt, and the complete canonical
challenge/batch/proof/renewal record. Its ID hashes those canonical bytes.

```
journal/
  header.omcj
  journal.lock
  slots/bucket-0000000000000000/slot-00000000000000000001.omcs
  objects/active/<entry-id>.omce
  objects/segments/segment-<random-id>/<entry-id>.omce
  pending/.outcomemesh-custody-journal-<temporary-id>
```

Slots are grouped in buckets of 1,024 sequence numbers. The permanent
`journal.lock` inode serializes open, replay, append, and rotation across handles
and processes. A process death releases its kernel lock; contention longer than
30 seconds returns a retryable busy error. Never remove this file while any
participant might be using the journal.

Append fsyncs a mode-0600 entry body and publishes it with a no-replace hard link
before publishing the fixed sequence slot and fsyncing its directory. The slot
commits the decision. An identical challenge retry returns the committed head;
a different challenge for the same predecessor fails. Unreferenced bodies from
an interrupted append are allowed but must retain valid canonical bytes and IDs.
Temporary files are never interpreted as decisions.

Rotation renames the entire active body directory into a segment, fsyncs the
segment and both parents, and recreates the active directory. Slots stay in
place. Reopen recovers the missing active directory if the process died between
rename and recreation. Segmentation deletes no evidence, including abandoned
temporary files. Disk usage continues to grow; there is no garbage collector or
retention compactor in this version. Local growth limits stop further admission
before the journal reaches its configured budget.

Replay checks canonical names, regular files, content IDs, gapless slot order,
entry links, exact predecessor receipts, signatures, manifest samples, returned
chunks, and retention extensions. It loads body payloads one at a time; path and
slot metadata grow with history, subject to a hard path ceiling checked by a
streaming inventory before replay allocates these indexes. Golden vectors cover
header, policy, and entry encoding; all three new decoders have fuzz targets.

## Storage limits

Both journal commands accept `--journal-max-bytes` (default 4 GiB, maximum
1 TiB) and `--journal-max-paths` (default 262,144, maximum 1,048,576). These are
local, per-handle limits; supply the intended values on every invocation and
to every process using that journal. They are independent of the immutable
signed custody policy, so adjusting them does not change existing evidence or
wire encodings. The library exposes `OpenOrCreateCustodyJournalWithLimits`;
the original opener applies the defaults.

Accounting includes the header, lock, all active and sealed bodies, immutable
slots, unreferenced bodies, and abandoned temporary files. Every directory entry
counts as a path, including the root, directories, and empty files. File lengths
are charged once per path: duplicate hard links are deliberately counted twice.
Directory allocation, filesystem metadata, compression, and sparse-file block
allocation are not represented by the byte counter.

Under the same cross-process lock used for publication, append inventories
current usage and reserves the body and slot together before writing either.
Both published and temporary links are charged, plus a slot bucket if needed.
An exact already-present body only needs a slot reserve. This leaves room for
an exact-record retry after an interrupted append, including a leftover body
temporary link, provided the limits and other usage have not changed. Repeated
crashes can accumulate additional temporary files and eventually exhaust this
reserve. A regenerated response with different signed bytes is a new body; it
cannot reuse the original body's allowance. Rotation requires one additional
directory path and never reduces the byte count.

A budget refusal returns `ErrCustodyJournalBudget` with current usage, limits,
and required reserve. It does not publish a new body, slot, or segment. Reopen,
full replay, and exact committed-head retries still work after lowering local
limits below existing usage. Reopening an existing header does not allocate a
temporary file. Recovery may recreate the fixed active directory after an
interrupted rotation. The hard 1,048,576-path replay ceiling still applies even
when local growth is disabled; exceeding it fails closed before building the
history indexes.

Each journal command prints `work_archive_custody_journal_usage` on stderr at
startup, including logical bytes, paths, pending bytes/files, and `over_budget`.
The public `Usage` method inventories storage; only `State` and `Head` establish
replay-verified custody state. A full journal remains usable for recovering
committed responses and missing auditor outputs. A fresh cycle or nonempty
rotation can fail until the operator increases the allowance. If an auditor
has already persisted a verified record, the next invocation can finish its
journal append locally under the increased limit. Preserve all pending cycle
artifacts; do not replace the signed challenge or remove evidence to make room.
Threshold rotation can report a budget error after a renewal is already
committed. For recovery-only work, `--rotate-every 0` defers that maintenance;
it does not change the committed head or waive append limits.

These limits cover one journal, not the replica object store, the separate
auditor artifact directory, other journals, logs, or other programs. They are
logical admission checks, not a filesystem quota or a physical space
reservation. Operators still need volume free-space/inode monitoring and room
for those other consumers. Write/fsync failures remain errors; process-kill
and budget-boundary tests are not an ENOSPC or power-loss certification.

## Running a cycle

Start from a manifest and initial receipt obtained through the existing full
archive replay and replica-receipt flow. Keep the same initial receipt file on
every invocation. Use four distinct keys: replica transport, auditor transport,
replica evidence, and auditor evidence. Both journals must receive exactly the
same custody policy on every reopen; changing that policy needs a separately
reviewed baseline and a new journal.

On the replica, use `--journal` instead of `--record`:

```sh
omd work-archive-custody-serve-quic \
  --key replica-transport.key \
  --listen /ip4/127.0.0.1/udp/9007/quic-v1 \
  --auditor-peer-id "$AUDITOR_PEER_ID" \
  --replica-key replica-evidence.key \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
  --manifest manifest.omwm --receipt initial.omrr \
  --object-store replica-objects \
  --journal replica-journal --rotate-every 24
```

The readiness line prints the authenticated peer ID and direct QUIC address.
The process serves one completed exchange, then exits. A supervisor can restart
it on the same key, endpoint, store, initial receipt, and journal. The last
journaled response remains available to an auditor that lost its response;
a new challenge can extend the current journal head.

On the auditor, use a separate artifact directory and a retention duration:

```sh
omd work-archive-custody-challenge-quic \
  --key auditor-transport.key \
  --peer "$REPLICA_QUIC_ADDRESS" --peer-id "$REPLICA_PEER_ID" \
  --auditor-key auditor-evidence.key \
  --manifest manifest.omwm --receipt initial.omrr \
  --journal auditor-journal --artifacts auditor-cycles \
  --renewal-seconds 86400 --minimum-interval-seconds 3600 \
  --lifetime-seconds 60 --samples 2 --rotate-every 24
```

`REPLICA_QUIC_ADDRESS` includes the `/p2p/<id>` suffix printed by the replica.
The artifact directory must be outside the journal, including through symlink
aliases. Journal mode replaces the explicit `--challenge`, `--record`,
`--out-receipt`, and `--renew-until` flags with deterministic cycle directories.
An external timer may invoke this command periodically; it performs at most one
cycle per invocation. No timer or background service is installed by the command.

For a fresh cycle, due time is the current receipt's `StoredAt` plus
`minimum-interval-seconds`. Before that time the command prints
`work_archive_custody_not_due` and exits successfully without dialing. An
unfinished durable challenge bypasses the interval gate and retries the same
signed request. Its lifetime, sample count, and renewal duration must match the
requested settings. Choose an interval and term that leave enough time before
the previous receipt expires; a renewal must strictly extend its retention.

The auditor persists the challenge before dialing, then the verified record,
journal entry, and renewed receipt. If a record exists without its journal slot,
the next invocation completes the append locally. If the head is already
committed but its challenge, record, or output receipt is missing, the next
invocation restores the exact head artifacts and returns `recovered=true`.
Existing conflicting artifacts fail rather than being overwritten. An incomplete
rotation at the head threshold is retried during startup recovery.

The permanent `custody.lock` in the artifact root now serializes the whole
journal-mode auditor invocation, including pre-dial challenge publication and
offline recovery. The lock order is artifacts first, journal second; journal
operations still release their own lock before network I/O. Contention returns
the same bounded, retryable busy error as journal locking. Keep one stable
artifact root paired with each auditor journal, and use this version for every
writer. Older binaries, a different artifact root for the same journal, and
out-of-band file edits do not participate in that serialization. Never delete
either lock file to clear contention.

## Evidence retention and cold-copy checkpoints

For this experimental version the retention rule is **retain all evidence**.
Receipt expiry is not a deletion deadline. Keep the initial header, all slots,
active and sealed bodies, unreferenced bodies, pending files, and the entire
auditor artifact directory, including unfinished and partially written files.
Do not discard an old segment, challenge, or checkpoint to satisfy a disk cap.
Increase storage capacity or stop admitting new cycles. A future deletion or
compaction policy needs its own review and recovery tests; none is enabled here.

`work-archive-custody-checkpoint` produces a small canonical `.omccp` inventory,
not a backup of the evidence. It replays the complete existing journal against
the supplied manifest, initial receipt, and fixed auditor policy, then hashes
both directory trees under the artifact/journal locks. It binds the header,
sequence, head entry, current receipt, every relative file name and byte, and
every directory, including empty ones. The auditor tree is required unless the
operator explicitly selects `--replica-only`. A pending signed challenge can
change this checkpoint even when the journal head has not advanced.

Tree hashing streams file contents and bounds directory metadata before sorting.
Each tree is limited to 1 TiB logical file bytes, 1,048,576 paths, and directory
depth three below its root. Hard links count once per path. These are checkpoint
inspection ceilings, not new growth limits for the auditor. Symlinks and special
files fail closed. Root names, inodes, timestamps, ownership, and permissions
are not part of the digest, so a byte-preserving cold copy can be checked on a
different volume. Protect copy permissions and private material separately.
The journal is semantically replayed; arbitrary artifact/temporary bytes are
preserved and hashed, not promoted to valid decisions. The auditor still checks
their canonical evidence and challenge settings when it resumes.

Capture on the auditor, using the same policy flags as the running command:

```sh
omd work-archive-custody-checkpoint \
  --journal auditor-journal --artifacts auditor-cycles \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
  --checkpoint checkpoints/custody-000001.omccp
```

The checkpoint output must be outside both trees, including symlink and existing
case-insensitive directory aliases. Publication is mode 0600,
fsynced, and no-replace; an identical retry is allowed, a changed inventory
requires a new output name. Capture can create an absent artifact lock for a
stopped older installation, but never initializes a journal or repairs a missing
active directory. Finish any interrupted rotation on the authoritative instance
before checkpointing; preserve the original failure evidence for diagnosis.

Cold-backup procedure:

1. Stop the local writer and its timer/supervisor. For coordinated participant
   backups, stop both sides before taking their separate checkpoints. Keep them
   stopped through copying and verification; capture releases its locks on
   return and does not create a filesystem snapshot.
2. Capture a new checkpoint. Retain the printed `id`, checkpoint bytes, trusted
   manifest, initial receipt, and policy configuration in an independent,
   access-controlled failure domain. A checkpoint stored only beside its backup
   cannot detect replacement of both with an older valid pair. Keep the history
   and identify which pin is current; never derive `--expected-id` from the copy
   being tested. This tool does not provide an external pin service.
3. Copy the **entire** journal and auditor trees to a fresh, non-serving location,
   including dotfiles, empty directories, and permanent lock files. Use a
   byte-preserving cold-copy or filesystem-snapshot facility, then durably flush
   it using that platform's supported backup procedure. Do not copy over an
   existing authoritative journal. No copying, uploading, deletion, or service
   cutover is performed by the checkpoint commands.
4. Check the copy before starting any recovery command, using the independently
   retained checkpoint and ID:

   ```sh
   omd work-archive-custody-verify-checkpoint \
     --journal restored/auditor-journal --artifacts restored/auditor-cycles \
     --manifest manifest.omwm --receipt initial.omrr \
     --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
     --checkpoint checkpoints/custody-000001.omccp \
     --expected-id "$INDEPENDENT_CHECKPOINT_ID"
   ```

   Verification checks the pin first, replays the journal, and requires an exact
   inventory match. It requires existing lock files and never creates, repairs,
   overwrites, or deletes evidence. The local lock files need read/write access
   for kernel locking. Missing pending artifacts, an older valid prefix, a
   same-head copy missing a later challenge, and even a newer valid head fail.
   This is exact-copy verification, not ancestry or freshness reconciliation.
5. Before a real cutover, confirm that no later local or remote decisions are
   known and that the old authority cannot restart. Resume only one instance
   with the same identities, trust configuration, and challenge settings. A
   pending verified record can finish locally without changing its challenge.
   If later evidence exists, the independently retained pin is missing or stale,
   or the outage exceeds the freshness bounds, preserve both copies and stop:
   do not regenerate a challenge or silently rebaseline. The reconciliation
   workflow remains a separate gate.

For a replica checkpoint, replace `--artifacts ...` with `--replica-only` in both
commands. Back up the replica object store separately and use the existing full
archive materialization/replay checks; this checkpoint does not inventory it.
Transport/evidence private seeds also need a separate secure recovery policy;
these two commands need only the auditor public key and do not package seeds.

A successful check establishes integrity at the checkpoint, not that it contains
the latest possible decision or that a physical backup survived power loss.
Renewals or artifact writes after capture need a new independent checkpoint and
backup. The restore drill tests an exact pending-record continuation in a new
directory without a live replica. The managed local-copy command below removes
the manual copy window. The pin journal below adds explicit local maintenance;
independent storage deployment, pin freshness, cross-host cutover, and
long-duration filesystem-fault campaigns remain deployment work.

## Managed local backups

`work-archive-custody-backup` holds the source artifact lock and then its journal
lock through copying, destination verification, and publication. This keeps the
evidence pair stable without a separate checkpoint/copy gap. All source locks
must already exist; backup creation never initializes or repairs source state.
Pause timers for large copies: competing invocations may hit the normal
30-second lock-wait limit, and the replica's journal is also unavailable to new
renewals while its own backup is copied. A local backup does not coordinate the
other participant or guarantee that no remote decision is newer.

```sh
omd work-archive-custody-backup \
  --journal auditor-journal --artifacts auditor-cycles \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
  --backup backups/custody-000001
```

Use `--replica-only` instead of `--artifacts` for a replica. The destination must
be outside both source trees, including aliases. Its parent may be created, but
the destination itself is reserved by a no-replace directory creation. Even an
existing empty directory is not adopted. The bundle layout is:

```text
custody-000001/
  backup.lock
  journal/             # full journal, including journal.lock and pending files
  artifacts/           # full auditor tree; omitted for replica-only backups
  checkpoint.omccp     # published last; commits the complete bundle
```

Files are streamed into new mode-0600 inodes and directories are created with
mode 0700. Source hard links are copied independently; the backup does not
share mutable files or lock inodes with the source. Each file is fsynced,
directories are synced bottom-up, and the destination is fully replayed and
checked against the inventory of the bytes copied. Only then is the canonical
checkpoint published by a no-replace hard link and its parent fsynced. A
permanent `backup.lock` serializes bundle verification with this final step.
Never remove this lock to force a retry.
The checkpoint/tree encodings and IDs are unchanged from standalone capture.

A directory without its final checkpoint is incomplete, even if most or all
payload files are present. Errors, cancellation, or process death do not clean
up the attempt or resume copying into it. Preserve it and choose a new target.
A completed destination is accepted on retry only if its full inventory still
matches the locked source. If the source advanced, use a new backup name; the
old backup remains verifiable with its original independent ID. A crash after
publication but before the success output can therefore be retried without
overwriting evidence. At most one small abandoned checkpoint temporary file is
allowed beside the bundle metadata; it is not a completion marker and is not
deleted by verification.

The same per-tree checkpoint ceilings apply: 1 TiB logical bytes, 1,048,576
paths, and directory depth three, with an additional small bundle root. There
is no physical space reservation or volume quota. A pair can need up to twice
the single-tree allowance plus metadata, and copying sparse files can allocate
more blocks than their sources used. Provision destination bytes and inodes
and monitor free space. Copy reads observe cancellation between bounded reads
and before commit; replay and bounded lock waits can delay cancellation.
No scheduler, upload, pin service, garbage collector, or retention deletion is
installed by the command.

Save the printed `id` outside the backup's failure/rollback domain and retain the
trusted manifest, initial receipt, and policy separately. Verification needs
that independent ID, not the original source directories:

```sh
omd work-archive-custody-verify-backup \
  --backup backups/custody-000001 \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
  --expected-id "$INDEPENDENT_CHECKPOINT_ID"
```

The verifier derives auditor/replica scope from the pinned checkpoint, checks
the bounded bundle layout, and replays both evidence inventories without
initialization or repair. A checkpoint merely read from the bundle is not an
independent pin. The command does not separately collect private seeds, replica
object-store data, or external trust configuration. It copies every file placed
under the evidence roots, so keep keys and unrelated data outside those roots.

Keep the published bundle as a retained backup, not a live journal. For a
restore drill, verify it, copy its `journal/` and optional `artifacts/` to fresh
non-serving locations, and use `work-archive-custody-verify-checkpoint` with the
same independently pinned checkpoint before resuming. Apply all cold-copy
cutover requirements above, including retiring the old authority and checking
for later decisions. Process tests kill creation after the journal copy, before
commit, and after commit; the CLI drill restores a pending record into a separate
directory, finishes it offline, and verifies that the retained bundle has not
changed. These tests do not certify power-loss durability, remote filesystems,
scheduled pin freshness, or a cross-host cutover procedure.

## Maintaining the current backup pin

The optional pin journal remembers which completed bundle was explicitly
designated current. Put it on independently managed, access-controlled storage,
outside **all** live evidence and backup trees. The commands reject path/alias
overlap with the supplied bundles, but cannot establish physical independence
or check paths to live trees they were not given. No remote service, storage
account, timer, or upload is provisioned. Keep the trusted manifest, immutable
initial receipt, and exact policy configuration available separately.

There are two publication steps: create a verified backup, then pin its printed
checkpoint `id`. A backup that exists but has not been pinned is not current in
this journal. Never obtain `--checkpoint-id` by simply reading whichever backup
you want to restore: it must come from the authoritative backup operation.
Initial pinning is an explicit operator decision:

```sh
omd work-archive-custody-pin-backup \
  --pins /independent/custody-pins --initial \
  --backup backups/custody-000001 \
  --checkpoint-id "$AUTHORITATIVE_CHECKPOINT_ID" \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY"
```

Retain the printed `pin_id` and `checkpoint_id`. Pin sequence counts backup
updates, not custody cycles: a new signed challenge changes the checkpoint even
before a receipt commits. To inspect the current journal head:

```sh
omd work-archive-custody-pin-head --pins /independent/custody-pins
```

This replays the pin log only; `verified=false` means the bundle was not checked.
For a new update, supply the pin ID observed before the operation and the
previous pinned bundle, both independently known:

```sh
omd work-archive-custody-pin-backup \
  --pins /independent/custody-pins \
  --expected-pin "$PREVIOUS_PIN_ID" \
  --previous-backup backups/custody-000001 \
  --backup backups/custody-000002 \
  --checkpoint-id "$NEW_AUTHORITATIVE_CHECKPOINT_ID" \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY"
```

Both bundles are fully replayed against their checkpoint IDs and the supplied
trust policy before promotion. The new bundle must extend the same journal,
retain the earlier committed head and receipt, and keep the same auditor/replica
scope. Every old body content ID, including orphans, must remain; rotation may
move bodies between active and sealed directories. Every old journal-pending
and auditor relative path and file byte, including empty/partial files, must
remain unchanged. New paths are allowed. Comparing body IDs does not certify
physical duplicate counts or authorize removing old files: the retain-all rule
still applies. Even a valid later chain is rejected if previously pinned
evidence disappeared. If the prior bundle is lost or cannot be verified, stop
and preserve the remaining evidence; there is no force/rebaseline flag.

A competing update produces a conflict instead of replacing its result.
An exact retry of the latest checkpoint re-verifies the bundle and returns
`created=false`; it accepts either the current pin ID or that pin's immediate
predecessor, so a lost success output is recoverable. The prior bundle is not
needed for this exact retry. Repeating the initial command is allowed only
while that first exact pin is still current. Never respond to a conflict by
blindly taking the newest ID and retrying an older candidate.

Check a candidate against the latest pin before copying it into a new recovery
directory:

```sh
omd work-archive-custody-verify-pinned-backup \
  --pins /independent/custody-pins \
  --backup backups/custody-000002 \
  --expected-pin "$LATEST_INDEPENDENT_PIN_ID" \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY"
```

Verification holds the pin lock through full bundle verification. A valid older
backup fails even if its custody sequence is identical. `--expected-pin` is
optional for this command only: without it, the current independent pin store
is the authority. With an exact head ID retained in another trusted domain, it
also detects rollback of that store. A hash-linked log cannot detect replacement
of the entire store and its backups by an older valid set on its own. The pins
are not signed, and neither the log nor a separately retained ID proves that no
newer unpinned decision exists. Continue to apply all cutover and reconciliation
requirements above; pin verification does not start a recovered authority.

The journal has a permanent `pins.lock`, `entries/pin-%020d.omcpin` immutable
sequence files, and a `pending/` directory. Each v0 pin is 260 bytes and binds
its sequence, previous pin ID, and complete checkpoint. Publication uses a
mode-0600 temporary file, fsync, no-replace hard link, and directory fsync;
directories are mode 0700. Replay requires a gapless linked history and bounds
it to 65,536 pins plus 1,024 pending files of at most 260 bytes each. At capacity
new updates stop, but exact committed retries and verification remain available
within those ceilings. Abandoned pending files are retained, not treated as
commits or garbage-collected. There is no compaction or mutable head file.

Missing, empty, malformed, or partially initialized stores cannot select a
restore checkpoint. Only explicit initialization can populate a new, absent
store or finish a fully initialized empty one; an incomplete directory is not
automatically repaired. Preserve it for diagnosis. A crash after backup
completion but before pin publication leaves the prior pin current; repeat the
intended pin operation with its original expectation. Process-kill tests bracket
pin publication and verify exact retries with released locks. They do not prove
power-loss durability or independently deployed storage/freshness operations.

## Read-only outage reconciliation

`work-archive-custody-reconcile` compares two **retained, immutable** bundles:
an auditor backup containing its artifact tree and a replica-only backup. Both
must share the same manifest, immutable initial receipt, and custody policy.
Select each checkpoint ID from its independently maintained pin authority, not
from metadata found inside an arbitrary candidate. If currentness matters,
first verify each candidate with its own `work-archive-custody-verify-pinned-backup`
command and a separately retained current head ID. Reconciliation accepts the
explicit checkpoint IDs; it does not itself lock or refresh the pin authorities.

```sh
omd work-archive-custody-reconcile \
  --auditor-backup backups/auditor-000007 \
  --auditor-checkpoint-id "$AUDITOR_CHECKPOINT_ID" \
  --replica-backup backups/replica-000008 \
  --replica-checkpoint-id "$REPLICA_CHECKPOINT_ID" \
  --manifest manifest.omwm --receipt initial.omrr \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY"
```

Supply the same policy flags used by both journals. The assessment uses the
local Unix clock by default. `--at SECONDS` permits a repeatable historical
assessment; it must be nonzero. The printed time is an input, not a trusted time
attestation. Never backdate this flag to present stale evidence as current.

The command verifies both exact inventories, replays both chains, and holds
their existing bundle locks throughout inspection. It neither initializes nor
repairs evidence and never opens a network session or loads private keys. Like
backup verification, it needs writable access to the existing permanent lock
files and uses fsync. Do not use retained bundles as live journals or modify
their contents out of band.

Four output lines describe the result:

- `work_archive_custody_reconciliation` binds the two checkpoint IDs and the
  assessment time. `relation` is `aligned`, `auditor-ahead`, `replica-ahead`, or
  `diverged`; `common_sequence` and `first_divergence` compare exact committed
  entry IDs. A longer divergent history is not a winner. This is a custody
  evidence comparison, not blockchain fork choice.
- `work_archive_custody_reconciliation_freshness` reports each committed head's
  response time, proof-age bound, and receipt expiry separately. Sequence-zero
  journals have no custody proof, so their response time is zero and
  `proof_within_age` is false even if the initial receipt is unexpired.
- `work_archive_custody_reconciliation_pending` describes only the auditor's
  next cycle. It checks the signed request against its actual predecessor and
  compares full response bytes if both sides retain a response. A matching
  response may come from an auditor artifact, the replica's committed next slot,
  or both. Unreferenced bodies are never treated as committed responses. Without
  local intent or a local response record, a peer's later slot is not silently
  adopted as the auditor's pending request.
- `work_archive_custody_reconciliation_review` gives an advisory `next_step`
  and counts missing/conflicting committed artifacts, unclassified artifact
  entries, orphan body IDs, and journal pending files. Unclassified entries
  include unknown names, future-cycle directories, and artifact temporaries;
  an unknown directory counts as one entry, not all its descendants. Its full
  contents remain bound by the previously verified checkpoint.

Historical signature/batch/renewal validity does not expire, but live proof
acceptance still obeys `max-proof-age-seconds`, and retention has its own end.
Thus `state=historical-response` can coexist with `proof_within_age=false` and
`receipt_unexpired=false`. These time fields alone are never permission to use
a response: conflicts and all review blockers remain relevant. Malformed pending
requests/records or wrong pins/trust fail the command; structurally valid
conflicting evidence is reported without selecting or rewriting either side.

`review-historical-response` means an exact historical candidate was identified
for review, **not imported**. `review-rebaseline` means the selected snapshots
cannot support an ordinary fresh cycle as assessed, **not permission to create
a new baseline**. A reply absent from a snapshot may exist in newer remote
evidence. Collect that evidence and establish that old authorities cannot run
before deciding how to recover. Missing/unknown/partial artifacts and orphan
bodies must be preserved and investigated, not deleted to clear a review flag.

Every report prints `automatic_resume=false` and `availability_attested=false`.
Exit zero means inspection completed, including when it found a conflict; it is
not a successful restore or approval to start a service. There is no `--apply`,
import, challenge replacement, signature generation, pin update, or rebaseline
operation. Two matching snapshots are still only historical snapshots and may
both predate later decisions. The offline handoff stage below packages selected
evidence; explicit application below reconstructs a separate historical-only
journal. Linked rebaseline, participant fencing, and crash-safe active cutover
remain separate plan items. Process tests verify
repeatable offline assessment with stale evidence
while leaving both bundles, the pending challenge, and the auditor head intact.

## Reviewed historical-response handoff

Use `work-archive-custody-transfer` to prepare a portable **historical-only
package**, not a working journal. The first format handles one narrowly defined
case: the replica is exactly one committed cycle ahead, the entire auditor
prefix matches, and its next retained signed intent identifies that response.
A matching local response may already exist, including a record from which a
missing standalone challenge can be recovered without changing any file.
Missing committed artifacts, conflicting or unknown files, future-cycle
artifacts, orphan bodies, journal temporaries, and abandoned backup checkpoint
links block preparation. Keep those files and investigate; do not delete them
to make this command pass. Larger gaps, unanswered requests, and divergent
histories need a different recovery decision.

First verify the source choices with their independent pin authorities when
latest-known state matters. Then prepare without creating a package (Bash/Zsh):

```sh
handoff_args=(
  --auditor-backup /cold/auditor-backup
  --replica-backup /cold/replica-backup
  --auditor-checkpoint-id "$AUDITOR_CHECKPOINT_ID"
  --replica-checkpoint-id "$REPLICA_CHECKPOINT_ID"
  --manifest archive/manifest.omwm
  --receipt evidence/initial.omrr
  --auditor-public-key "$AUDITOR_PUBLIC_KEY"
)
omd work-archive-custody-transfer --mode plan "${handoff_args[@]}"
```

Use the same policy flags as the original journals if they differ from the
defaults. The result identifies the exact two checkpoints, sequence, entry,
challenge, original response time, and envelope `id`. Review this selection and
retain its ID independently as `REVIEWED_TRANSFER_ID`; do not automatically pipe
the plan output into export and treat that as approval. An explicit ID selects
bytes, but does not cryptographically attest that a human reviewed them.

```sh
omd work-archive-custody-transfer --mode export "${handoff_args[@]}" \
  --package /cold/handoff-001 --expected-id "$REVIEWED_TRANSFER_ID"

omd work-archive-custody-transfer --mode verify "${handoff_args[@]}" \
  --package /cold/handoff-001 --expected-id "$REVIEWED_TRANSFER_ID"
```

Export rechecks the sources under ordered existing bundle locks before creating
the destination. It writes `historical.omcht`, a versioned envelope containing
both complete checkpoints and the original replica journal entry, and an empty
`transfer.lock`. The envelope has its own magic and domain-separated ID; it is
neither a standalone custody response nor an appendable journal entry.
No signatures or timestamps are generated or rewritten. Historical validity
does not imply present-day availability, and no current clock enters the ID.

The destination must be outside both backups and must not exist, except for an
exact completed retry. Files are independently written, synced, and published
with a no-replace link. Failed attempts retain their directory and temporary
bytes; preserve them and choose another destination. If the process dies after
commit, verification may accept one byte-identical abandoned temporary link.
It does not delete that link. Extra or changed files fail verification. Process
kills test both sides of this commit boundary, not physical power-loss behavior.
The decoder bounds one envelope by `MaximumCustodyHistoricalTransferBytes`;
publication may temporarily store two links to those bytes. This is not a global
quota across handoff directories or a retention cleanup policy.

Verification requires both complete source bundles and all three independently
retained IDs, even after moving the package to another machine. It recomputes
the exact selection from source evidence: a valid envelope hash alone cannot
prove the auditor's pending intent or full prefix. The package does not contain
the source bundles and is not a replacement for retaining them. Source IDs
select historical copies, not necessarily the latest authority decisions.

Every successful mode prints `historical_only=true`, `automatic_resume=false`,
and `availability_attested=false`. No mode appends a journal, changes pins,
imports artifacts, rebaselines, or starts/stops a service; `--apply` is unsupported.
Do not extract the entry into a live decision directory. The explicit command
below can reconstruct a historical-only copy, but linked rebaseline and
enforceable participant fencing remain required before any resumed authority.
A local handoff file cannot establish that an old participant on another host
has stopped.

## Apply history to a quarantined reconstruction

`work-archive-custody-apply-history` applies the selected response to a **new
auditor reconstruction**, not to either original journal. The same independently
pinned source bundles and reviewed handoff must still be available. All four
directories (both backups, handoff, and reconstruction) must be disjoint;
symlink/case aliases are checked as for backup creation. Creation accepts only a
new destination or an exact completed retry. It needs no private key or network.

Using the trusted `handoff_args` and reviewed transfer ID from the previous
section:

```sh
omd work-archive-custody-apply-history --mode create "${handoff_args[@]}" \
  --package /cold/handoff-001 --transfer-id "$REVIEWED_TRANSFER_ID" \
  --recovery /cold/auditor-recovery-001

# Retain the returned application id independently as APPLICATION_ID.
omd work-archive-custody-apply-history --mode verify "${handoff_args[@]}" \
  --package /cold/handoff-001 --transfer-id "$REVIEWED_TRANSFER_ID" \
  --recovery /cold/auditor-recovery-001 --expected-id "$APPLICATION_ID"
```

The result contains `journal/`, `artifacts/`, the exact `historical.omcht`
handoff envelope, an empty `recovery.lock`, and the final `application.omcap`
marker. That marker binds the transfer ID and a complete result checkpoint;
its own domain-separated application ID is the value to retain independently.
Verification requires all four IDs: both source checkpoints, transfer, and
application. It does not trust an application checkpoint read from the candidate
alone. Do not discard the sources or handoff after creating this directory.

The new journal preserves the original manifest, policy, immutable initial
receipt, committed prefix, and segmented body locations. Its first published
header is version 1, defined exclusively as historical-only, with the reviewed
transfer ID appended. No live v0 header is copied. Live open rejects this header
before initializing or repairing child directories; append, rotation, and
journal-backed replica-session construction reject it too. v0 canonical bytes
and policy IDs are unchanged, and older v0-only decoders reject the new version.
Only checkpoint/evidence replay is supported for this historical journal.

Under the ordinary artifact-then-journal locks, the private constructor adds
exactly the reviewed next body and slot, then completes that cycle's canonical
challenge, record, and receipt files. Existing matching files are retained
byte-for-byte. The original response time, signatures, and renewed receipt are
not regenerated. A stale proof remains stale; the old initial receipt is not
replaced with a new baseline. The original auditor and replica are never changed.

Before final publication, the destination is independently replayed and checked
as the exact original auditor trees plus these named changes. Matching a head
or containing the old files is insufficient: extra paths, relocated/duplicated
bodies, and altered earlier artifacts fail, even if a candidate supplies a newly
computed checkpoint. This exact comparison also makes a completed lost-result
retry deterministic without deriving authority from candidate metadata.

Creation streams copies under the existing hard byte/path ceilings. Admission
of the added journal entry uses `--journal-max-bytes` and `--journal-max-paths`
with the existing defaults. These are journal growth limits, not a filesystem
quota for all copies or artifacts. A budget/copy/write failure preserves the
incomplete destination. Raising the budget does not resume it in place: retain
it and choose another destination. An already complete exact retry may still
succeed under reduced growth limits, without adding files. Verification accepts
no growth-limit overrides because it performs no admission.

The final marker is published with fsync and a no-replace link only after the
full reconstruction verifies. An incomplete directory is never treated as ready
or repaired by retry. Process-kill tests cover header publication, copied prefix,
body publication, slot publication, completed artifacts, and both sides of the
final marker. A killed attempt with a historical header remains forbidden to
run, even if it lacks the rest of the journal. These tests do not certify power
loss, disk exhaustion, every filesystem, or another host's state.

Successful output always includes `historical_only=true`,
`automatic_resume=false`, `participant_fenced=false`, and
`availability_attested=false`. There is no activate, resume, rebaseline, header
downgrade, or pin-promotion operation. The format guard prevents accidental live
use under the existing exclusive-operator filesystem assumptions; it is not an
access-control boundary against someone who rewrites files or ignores pins.
Do not downgrade the header or extract its receipt into an unjournaled service.
The separately running original participant has not been stopped. A fresh
linked proposal can now be prepared as described below; enforceable
cross-host fencing and crash-safe active cutover remain unimplemented. The
separate local-retirement mode below can disable managed old journal roots.

## Propose a linked rebaseline after full replay

The `create` and `verify` modes of `work-archive-custody-rebaseline` prepare or
verify an **inactive proposal**. They do not restore service. Creation revalidates the complete historical
application against the original backups and handoff, then replays every chunk
and block of a complete archive through consensus execution. A retained sampled
batch, signed manifest, old receipt, or application marker alone is insufficient.
The archive must match the original manifest and checkpoint statement exactly.
Keep the archive and recovery evidence trees immutable throughout verification;
this command does not lock an externally writable archive or certify continued
possession afterward. Supply a separate offline verified node for `--data`: the
existing activation-base loader opens its ledger normally and may update database
housekeeping files. It is not a read-only database snapshot interface.

The fixed 322-byte v0 proposal binds the independently retained application ID,
last historical receipt ID, manifest and statement IDs, proposed custody policy
ID, replica key, opaque location commitment, and three timestamps. The new
replica signs in `custody-rebaseline-proposal/signature/v0`, not a receipt domain.
No valid live receipt can be extracted by copying that signature. Neither old
nor current live parsers accept proposal bytes as a receipt, challenge, or journal
header. No auditor acceptance, availability bundle, live journal, challenge,
pin promotion, or service configuration is produced.

All next auditor keys and the next replica key must be disjoint from both old
evidence roles and from each other. Callers must independently supply the intended
new public assignment and location; verification never trusts these values just
because the candidate signed them. Different keys do not prove different owners,
failure domains, key erasure, or retirement of copied old services. The Go API
can bind a complete new custody policy; this CLI deliberately keeps the existing
timing limits and changes only the single trusted auditor identity.

Time is sampled after successful replay. The signed review lifetime is 1–600
seconds (default 300); the review window is half-open. Review checks local time
before and after replay, so expiry or clock rollback during expensive work fails.
The proposed retention deadline must exceed both the review window and previous
receipt deadline, and fit the new policy's maximum renewal term. Expired proposals
remain valid historical signed artifacts but fail current review. Clock trust is
an operator assumption; the signature alone proves neither wall-clock accuracy
nor that its signer honestly performed replay. Independent verification performs
the replay itself. There is no `--at` override or automatic timestamp renewal.

Using the trusted `handoff_args` from above (including the exact original custody
policy), add the archive's independently configured activation base and checkpoint
trust. Public keys and IDs below must come from operator review, not from values
extracted from the candidate. The proposal's parent directory must already exist
and be outside all input and node-data trees.

```sh
rebaseline_args=(
  "${handoff_args[@]}"
  --data /review/verified-node
  --archive /cold/complete-archive
  --checkpoint /review/archive-checkpoint.omwc
  --attestor-public-key "$ARCHIVE_ATTESTOR_A"
  --attestor-public-key "$ARCHIVE_ATTESTOR_B"
  --package /cold/handoff-001 --transfer-id "$REVIEWED_TRANSFER_ID"
  --recovery /cold/auditor-recovery-001 --application-id "$APPLICATION_ID"
  --next-auditor-public-key "$NEXT_AUDITOR_PUBLIC_KEY"
  --next-replica-public-key "$NEXT_REPLICA_PUBLIC_KEY"
  --location-id "$NEXT_LOCATION_ID"
  --proposal /review/proposals/rebaseline-001.omcrb
)

omd work-archive-custody-rebaseline --mode create "${rebaseline_args[@]}" \
  --next-replica-key /keys/next-replica.key \
  --retain-until "$PROPOSED_RETENTION_UNIX_SECONDS"

# Independently retain/review the returned proposal ID. Verify needs no key.
omd work-archive-custody-rebaseline "${rebaseline_args[@]}" \
  --expected-id "$REVIEWED_PROPOSAL_ID"
```

The default mode is `verify`; a missing independent proposal ID is an error.
Verification requires all four original evidence IDs, the proposal ID, intended
assignment, full source trees, and complete replay inputs. It does not infer
missing trust from a nearby file. Creation publishes one fsynced file through a
no-replace hard link. Repeating create, even after a lost response, refuses the
existing path rather than issuing a new timestamp or overwriting evidence.
Inspect and independently review the retained artifact; use a new explicit path
for a later proposal. A killed pre-publication temporary file is not a committed
proposal. This single-file publication creates no durable activation decision.

Successful output includes `proposal_only=true`, `archive_replayed=true`,
`automatic_resume=false`, `participant_fenced=false`, and
`availability_attested=false`. The old participants are untouched, and the
reconstructed journal remains historical-only. Active cutover still needs an
independently enforced retirement decision covering old/copy/restarted authority
paths, followed by one durable activation linked to the reviewed proposal.
Crashes before, between, and after those decisions must not permit two active
authorities or revive retired keys. No local flag or proposal signature supplies
that deployment mechanism; activation, resume, and cross-host fencing are not
implemented. The local-only operation below is deliberately a separate mode.

## Retire the managed local participants

`--mode retire-local` permanently disables the **two named local journal roots**.
This is an administrative state change, not proposal verification or activation.
Use it only on the actual old auditor/replica roots after all processes using
those roots have been upgraded to the guarded journal-backed implementation (or
quiesced). An already loaded legacy binary, an unjournaled service, a copied
directory or an extracted key does not participate in this local lock protocol.
The command cannot discover or stop those authorities. Do not deploy a mixed
old/new runtime and interpret its output as a global fence.

The auditor holds its artifact lock and a `CustodyJournalDecision` for the entire
cycle: checking/recovering artifacts, issuing the challenge, network exchange,
record publication, journal append, and rotation. The replica acquires the same
permanent journal lock after decoding the bounded request and holds it through
head revalidation, signing, append, response writes and stream completion. Cached
and restart-loaded responses take the same guard. A session whose journal head
has changed fails without sending an older cached result. Library users must
hold a decision scope around their whole authority operation and use its methods
until `Close`; calling methods on the original journal while holding its scope
would try to acquire that lock again. Raw cryptographic helpers are not fenced.

Retirement takes the auditor artifact lock first, then both journal locks in
canonical resolved-path order. It waits for active guarded operations to drain;
the existing bounded lock wait returns busy instead of claiming successful
retirement if it cannot acquire them. Both current inventories must exactly
match the reviewed source checkpoints, including the auditor's pending intent.
An advanced head, changed artifact, relocated body or unknown retained file
blocks the operation before the first marker. The three target directories must
be distinct and outside the source backups, handoff, reconstruction, archive,
proposal, trust files and verification node. Missing roots or lock files are not
initialized or repaired.

Using the previously reviewed `rebaseline_args` and proposal ID:

```sh
local_retirement_args=(
  "${rebaseline_args[@]}" --expected-id "$REVIEWED_PROPOSAL_ID"
  --auditor-journal /live/old-auditor/journal
  --auditor-artifacts /live/old-auditor/artifacts
  --replica-journal /live/old-replica/journal
)

# Irreversible through supported APIs; does not start any replacement.
omd work-archive-custody-rebaseline --mode retire-local \
  "${local_retirement_args[@]}"

# Retain the returned pair ID independently. Verification has no time override.
omd work-archive-custody-rebaseline --mode verify-local-retirement \
  "${local_retirement_args[@]}" --retirement-id "$LOCAL_RETIREMENT_ID"
```

Each root receives a fixed 260-byte `retirement.omcrt`, published by fsync and a
no-replace hard link. It binds the reviewed proposal ID, that participant's full
pre-retirement checkpoint, and the original pair-decision timestamp. The returned
pair ID commits the ordered auditor/replica marker IDs. These are local integrity
commitments, not operator signatures or noncopyable remote revocation proofs.
The immutable initial receipt, header, slots, bodies and artifacts are unchanged.
Scratch files are siblings outside the pinned trees: failed/uncommitted attempts
are retained, never rediscovered as authority or automatically promoted. Only
the successfully committed temporary link is removed. The 260-byte/one-path
administrative addition can exceed a reduced local growth limit but not the hard
replay ceilings. Filesystem exhaustion and power-loss certification remain open.

The pair is **not an atomic two-directory transaction**. The first marker
durably commits intent to retire both exact participants. A crash before that
marker leaves both active; after it, the auditor stays retired even if the replica
has not yet been disabled. No success is reported until both markers and full
inventories verify. Retry replays all original evidence and may finish the same
already committed intent after proposal expiry, preserving the first timestamp.
It does not claim fresh review or re-enable anything. Without a committed marker,
an expired proposal cannot begin retirement. If the remaining live participant
advances after a partial crash, retry fails; retain the partial retirement and
review the additional evidence rather than deleting a marker or rolling back.
A replica-only marker is also rejected: ordered publication cannot produce it,
so the missing first decision must not be silently reconstructed from the second.

Any retirement path, even corrupt, truncated, a directory or a symlink, blocks
live initialization before child-directory repair, plus stale-handle append,
rotation and new decision scopes. There is no unretire, overwrite or header-
downgrade API. Well-formed retired journals remain readable: replay validates the
exact journal tree with only the separately checked marker excluded from its
pre-retirement digest. Normal checkpoints and backups include the marker; copying
a retired journal therefore preserves the live-use prohibition. Dedicated pair
verification also checks the exact original artifact tree and both independent
source pins, so a candidate cannot bless altered history by rehashing its marker.

An idle upgraded service may still have a listening socket; its next request
fails the guard and the CLI exits without sending its cached response. Retirement
does not send OS signals, erase keys, revoke transport identities, undo bytes
already delivered to another machine or change remote trust policies. A complete
rollback to an unretired snapshot still needs an independent authority to detect.
Successful output says `local_pair_retired=true`,
`global_participants_fenced=false`, `active_cutover=false`, and
`availability_attested=false`. Do not use a local retirement ID as permission to
start a replacement. Cross-host acceptance enforcement and one durable activation
decision remain required; no live receipt or active journal is produced here.

The acceptance-path inventory and required cross-host ordering are tracked in
[`CUSTODY_AUTHORITY.md`](CUSTODY_AUTHORITY.md). The live deletion path now checks
freshness again inside its prepared storage batch and retains no-replace
availability evidence on a failed attempt. That closes a time-of-authorization
gap; it does not turn these local retirement markers into remote revocations.

## Recovery limits and deployment gates

An expired challenge can retrieve only an already committed response whose
proof is still within `max-proof-age-seconds`. An unanswered expired challenge
cannot mint a fresh proof. A stale committed proof also fails. Preserve the
journals and artifacts on these errors; do not delete a challenge to generate a
sibling. Read-only reconciliation above can identify historical candidates and
blockers, the handoff stage can package one exact response, and explicit
application can reconstruct a historical-only auditor copy. Full replay can then
produce an inactive linked rebaseline proposal, followed by explicit retirement
of guarded local roots. Cross-host acceptance enforcement and crash-safe active
cutover remain separate work.

Use a local filesystem with working file locks, no-replace hard links, atomic
directory rename, and fsync semantics. The implementation has lock adapters for
Unix and Windows; unsupported lock platforms fail closed. The current runtime
tests exercise the host filesystem, not every supported OS or remote filesystem.
Process-kill tests cover body publication, slot publication, and segment rename;
they are not power-loss or disk-exhaustion certification.

The journal assumes exclusive operator control over its files. It detects
corruption and gaps, but a complete rollback to an earlier valid prefix requires
an independently retained checkpoint to detect. The paired inventory also covers
signed intentions that have not reached the head. Two separately copied journals
are separate decision authorities. Policy migration, evidence deletion,
scheduled backup/pin maintenance, cross-host reconciliation, and long
filesystem-fault campaigns remain activation gates.
