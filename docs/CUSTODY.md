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

## Recovery limits and deployment gates

An expired challenge can retrieve only an already committed response whose
proof is still within `max-proof-age-seconds`. An unanswered expired challenge
cannot mint a fresh proof. A stale committed proof also fails. Preserve the
journals and artifacts on these errors; do not delete a challenge to generate a
sibling. Long-outage reconciliation and an explicit rebaseline workflow remain
separate work.

Use a local filesystem with working file locks, no-replace hard links, atomic
directory rename, and fsync semantics. The implementation has lock adapters for
Unix and Windows; unsupported lock platforms fail closed. The current runtime
tests exercise the host filesystem, not every supported OS or remote filesystem.
Process-kill tests cover body publication, slot publication, and segment rename;
they are not power-loss or disk-exhaustion certification.

The journal assumes exclusive operator control over its files. It detects
corruption and gaps, but a complete rollback to an earlier valid prefix requires
an independently retained head to detect. Two separately copied journals are
also separate decision authorities. Policy migration, evidence deletion,
artifact retention, cross-host reconciliation, and long filesystem-fault
campaigns remain activation gates.
