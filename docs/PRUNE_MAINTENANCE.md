# Reviewed local prune maintenance

Status: opt-in pre-alpha operator boundary for one original, colocated pinned
executor/coordinator. It can review retained state and cancel admitted work
before start. It cannot Execute, Complete, sign, resume, repair, retire, discover
owners, stop another process or authorize live archive pruning. Do not use these
commands with production data or real value.

The [library boundary](CUSTODY_AUTHORITY.md#one-way-library-maintenance-boundary)
defines the exact review digest and same-guard cancellation check. The
[transport runbook](PRUNE_COMMANDS.md) defines the four existing roots and
independently retained assignment, request and transport identity pins.

## Two explicit entry points

| Entry point | Ownership and lifetime |
| --- | --- |
| Existing command server with `--maintenance-control stdin` | First `review` parks transport and drains accepted handlers without releasing any of the four original locks. The local pipe supervises the same owners until shutdown. |
| `work-prune-maintenance` | Opens the four existing roots without starting transport, performs one review or explicitly pinned cancellation, then closes. Another owner must already have stopped. Separate invocations do not keep locks between them. |

Neither entry point creates missing roots. They reject unresolved authority or
executor confirmations and never fill a partial admission-binding gap. A review
may describe Prepared, Started or Succeeded state, but none can be cancelled.
Stopping may still drain an already admitted ticket. Started means cancellation
is forbidden even when the effect's outcome is unknown.

## Offline review and cancellation

Default mode is `review`; no key or network address is accepted:

```sh
omd work-prune-maintenance \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --authority /srv/om-authority \
  --authority-pins /srv/om-authority-pins \
  --executor /srv/om-prune-executor \
  --executor-pins /srv/om-prune-pins \
  --request-id <independently-retained-request-id> \
  --server-peer-id <retained-server-transport-id> \
  --client-peer-id <retained-client-transport-id>
```

Replace placeholders before execution. The peer IDs validate the existing
runtime configuration; no transport key is read and no socket is created.
Open validates/re-syncs retained evidence, but review appends and resumes nothing.
Busy roots are an error, never a reason to kill a process or remove a lock file.

`work_prune_maintenance_review` reports the combined `review_id`, assignment,
request, storage and binding IDs, authority sequence/head/phase, independently
confirmed executor stage/head, admission ticket and terminal ID. Stages are
Prepared=1, Admitted=2, Started=3, Succeeded=4, Cancelled=5; authority phases are
Accepting=1, Stopping=2, Retired=3. Zero ticket/terminal IDs mean those executor
fields are absent; they do not prove that no authority admission occurred.
`network_stopped=true` describes this owner only.

Independently inspect these fields and the original retained intent. To cancel,
repeat the same explicit flags with:

```text
--mode cancel --expected-review-id <independently-reviewed-maintenance-id>
```

The exact digest is recomputed under the lifecycle, executor and coordinator
guards held through the live pending-ticket check and durable cancellation.
A head, phase, admission or terminal change makes an old review unusable. The
command does not query a replacement ID, choose a new head or retry for you.
Review mode rejects `--expected-review-id`, even when empty. All repeated flags,
unknown flags and positional arguments are rejected.

## Local control of a running service

On macOS/Linux, add `--maintenance-control stdin` to the existing explicit
`work-prune-command-serve-quic` invocation. Default is `none`, which does not read,
adopt or close stdin. Readiness includes `maintenance_control=stdin` or `none`.

The supervisor must supply a dedicated inherited OS pipe as stdin and consume
stdout. Do not share its read endpoint with another reader. Terminal input and
regular files are rejected; use the offline command for standalone operations.
Only inherited anonymous pipes are covered by the process tests; named-FIFO
reconnect/EOF semantics are not an operator guarantee. Native pipe adoption on
other platforms, including Windows, is refused before roots open. Offline
maintenance and the default network-only service remain available there.

The server adopts a close-on-exec duplicate in nonblocking mode and verifies Go
poller support before opening journal owners. Nonblocking status is shared with
the original read endpoint; this is why the pipe must be exclusively dedicated
to this opt-in session. No remote control socket or protocol is installed.

The pipe accepts exactly these LF-terminated lines:

```text
review
cancel-before-start <64-lowercase-hex-review-id>
close
```

The placeholder is explanatory, not valid input. First send `review`, read its
response and independently inspect it before supplying the exact ID in a second
command. The first review enters maintenance; repeated review only observes the
same parked owners. Sending cancel before review is rejected without an implicit
handoff. There is no command to restart transport in this process.

Input is bounded to 96 bytes per line, including LF. Empty lines, CRLF, extra
whitespace/arguments, uppercase IDs, unknown commands, oversized lines and partial
commands at EOF are errors. Each command is handled in order; the stream is not
an atomic batch, so a later error does not roll back an earlier cancellation.
`close` ends the session; remaining input is not processed.

EOF at a command boundary, `close`, SIGTERM or interrupt ends the session and
closes the service. The supervisor interrupts blocked pipe reads both before and
after handoff, joins its watcher, and returns retained input/storage/close errors.
A malformed command, stale review, storage failure or stdout error also stops
the session. This local error behavior is distinct from an ordinary rejected
remote Admit/Complete request, which need not stop a healthy service.

Shutdown waits for an active owner action; it does not force-unlock through fsync.
The transport's `--timeout` is neither a maintenance lease nor a filesystem or
stdout deadline. A supervisor must drain stdout; a blocked output consumer is not
an authorization to release owners while an action is active. Process death
releases OS locks, but does not itself cancel or recover work.

## Cancellation evidence and the next step

Successful cancellation emits `work_prune_maintenance_cancelled`, including the
supplied review ID, assignment/request/binding/ticket IDs, `terminal_id` and
`canonical_hex`. The latter is the exact 138-byte canonical cancellation encoded
as 276 hex characters. Decoding that field produces the terminal artifact accepted
by the existing [reviewed Complete signing workflow](PRUNE_PREPARATION.md).
This command writes no external artifact path; the supervisor must preserve the
decoded bytes and independently checked terminal ID in protected storage outside
the four journal roots. An output file is not independently confirmed merely
because these bytes were printed.

The output is historical evidence, not a signed portable durability certificate,
a current execution grant or proof that every storage copy is fenced. The
authority ticket remains pending: Complete still requires separate consumer
review/signing, authority review/co-signing, typed outbox preparation and delivery.

Cancellation changes the review ID. If output is lost, do not resend the old ID
or infer that nothing committed. SIGPIPE/EPIPE and short writes return an error
without erasing the journals. Close/reopen the same roots when necessary, obtain
a new review, and inspect its terminal state. An explicit cancel call pinned to
a fresh confirmed Cancelled review returns the original historical bytes. It
does not cancel another operation or submit Complete. Unconfirmed transitions
still require existing exact recovery APIs outside these CLI entry points.

## Remaining gates

This closes local review/cancellation control and its supervised lifetime, not
the full archive lifecycle. Explicit operator recovery of incomplete transitions,
actual audit/serve/prune acceptance under live policy, all-required-assignment
enforcement, protected physical storage checks, copied-owner fencing and active
cross-host cutover remain open. There is no operator Execute path.
