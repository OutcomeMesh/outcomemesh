# Reviewed local prune maintenance

Status: opt-in pre-alpha operator boundary for one original, colocated pinned
executor/coordinator. It can review retained state, cancel admitted work
before start and explicitly recover one eligible retained transition offline.
It cannot Execute, create a new Complete, sign, repair, retire, discover
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
| `work-prune-maintenance` | Opens the four existing roots without starting transport, performs one review, explicitly pinned cancellation or exact single-transition recovery, then closes. Another owner must already have stopped. Separate invocations do not keep locks between them. |

Neither entry point creates missing roots. Ordinary review/cancel rejects unresolved
authority or executor confirmations. Neither fills a partial admission-binding gap. A review
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

## Offline recovery of one retained intent

After uncertainty, close the original owner and reopen the **same** four retained
roots. Never delete a confirmation, intent or lock, replace a journal, or derive
missing evidence from an old backup. A sticky storage error is not cleared by a
recovery call on that handle. Corrupt, missing or mismatched roots still fail.

Using the same required identity/root flags shown above, obtain a separate review:

```text
--mode recovery-review
```

`work_prune_recovery_review` distinguishes the independently confirmed authority
and executor prefixes from the actually observed prefixes and exact pending
intents. It includes the assignment/request/storage/binding IDs, authority phase,
pending entry ID/kind, pending executor stage/head, retained admission/terminal
IDs and `recovery_action`. Retained terminal bytes are not called confirmed while
their pin is pending. All these fields enter a separate local hash domain:
`OMESH/custody-prune/maintenance/recovery-review/v0`. A cancellation review ID
cannot substitute for a recovery review ID. Review never promotes evidence.

Independently inspect the retained intent and select exactly the reported action:

| Action | The only allowed change |
| --- | --- |
| `authority-admission` | Finish an existing co-signed Admit for this exact request while the executor is Prepared. Do not bind the executor. |
| `authority-completion` | Finish an existing co-signed Complete matching this executor's already confirmed terminal evidence. Do not create or sign another entry. |
| `executor-admission` | Retain/confirm the already journaled admission binding; do not start work. |
| `executor-start` | Retain/confirm the already journaled start. It remains Started/unknown; no effect, retry or cancellation is allowed. |
| `executor-result` | Retain/confirm the already journaled result, without invoking WorkChain or submitting Complete. |
| `executor-cancellation` | Retain/confirm the already journaled cancellation, without submitting Complete. |
| `none` | No incomplete transition exists; there is no recover action. |
| `blocked` | Unrelated authority intent, mismatched terminal or pending intents on both layers. No automatic choice or repair is permitted. |

For one of the six eligible actions, submit a separate invocation:

```text
--mode recover --expected-review-id <independently-reviewed-recovery-id> --recovery-action <independently-chosen-action>
```

Both ID and action are compared under the same lifecycle → executor → coordinator
guards held through recovery and rereview. Only that already retained transition
may finish. No follow-on binding, execution, new completion, Stop or Retire is
inferred. `--recovery-action` is forbidden outside recover mode, even when empty.
Both review modes forbid `--expected-review-id`, even when empty.

Success emits `work_prune_recovered`, the supplied ID, recovered action, a new
`after_review_id` and resulting prefixes. `single_transition=true`,
`effect_execution=false`, `execution_authorized=false`, `historical_only=true`
and `automatic_retry=false` describe this narrow result. It is not portable
durability evidence or authorization for another operation. Lost/short stdout
does not undo the transition; a new recovery-review is required. The old review
is stale even if only the observed prefix advanced before confirmation failed.
A fresh `none` is an observation, not another successful recovery.

Recovery is not part of the live stdin grammar. Stop that local session normally
before using offline recovery. No remote recovery endpoint has been added.

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
require the separate offline recovery-review/recover procedure above.

## Remaining gates

This closes local review/cancellation control, its supervised lifetime and exact
single-intent operator recovery, not the full archive lifecycle.
Actual audit/serve/prune acceptance under live policy, all-required-assignment
enforcement, protected physical storage checks, copied-owner fencing and active
cross-host cutover remain open. There is no operator Execute path.
A separate [local archive acceptance library](PRUNE_ACCEPTANCE.md) now covers
initial receipts or separately pinned renewal prefixes, replica replay and all
selected guards through deletion/result.
It does not expose owners through this maintenance capability or extend stdin.
