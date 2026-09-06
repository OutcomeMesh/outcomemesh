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
both predate later decisions. Reviewed historical transfer, explicitly linked
rebaseline, participant fencing, and crash-safe cutover remain separate plan
items. Process tests verify repeatable offline assessment with stale evidence
while leaving both bundles, the pending challenge, and the auditor head intact.

## Recovery limits and deployment gates

An expired challenge can retrieve only an already committed response whose
proof is still within `max-proof-age-seconds`. An unanswered expired challenge
cannot mint a fresh proof. A stale committed proof also fails. Preserve the
journals and artifacts on these errors; do not delete a challenge to generate a
sibling. Read-only reconciliation above can identify historical candidates and
blockers, but historical transfer and an explicit rebaseline workflow remain
separate work.

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
