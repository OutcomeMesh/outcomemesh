# Command-only prune transport

Status: opt-in pre-alpha operator commands for the original colocated pinned
executor/coordinator and their existing client outboxes. These commands deliver
already signed Admit/Complete entries. They do not validate archive availability,
open WorkChain, sign entries, prepare requests, execute pruning, remotely cancel work,
stop/retire an assignment or implement all-assignment authorization.

The lifecycle and trust boundaries are specified in
[CUSTODY_AUTHORITY.md](CUSTODY_AUTHORITY.md). This runbook does not make the
system suitable for real value or production data.

Separate opt-in [local maintenance](PRUNE_MAINTENANCE.md) now exposes reviewed
pre-start cancellation through a dedicated stdin control pipe or a standalone
offline command. No cancellation method is added to either QUIC protocol.

## Required preparation

Prepare and independently review these inputs before using the commands:

- The canonical binary assignment and its independently retained 32-byte ID.
- Four existing, disjoint roots: authority, its intent/pin journal, executor,
  and its stage-pin journal. The executor must already contain the exact request
  named by the independently retained request ID.
- Distinct server/client transport keys and their independently pinned
  OutcomeMesh transport peer IDs. Neither key may reuse an assignment authority,
  consumer, replica or auditor identity. A libp2p `/p2p/…` route component is not
  the 32-byte OutcomeMesh peer pin accepted by these flags.
- A separately prepared admission or completion outbox with its independently
  retained intent ID. Its immutable entry is already consumer-signed and
  authority-co-signed; its transport pins select the two endpoints. Completion
  must name the original executor's independently confirmed terminal evidence.

Six separate [offline preparation commands](PRUNE_PREPARATION.md) now expose
explicit new-root bootstrap, reviewed consumer signing/authority co-signing and
typed outbox creation/verification. Request construction remains a guarded
library workflow. None of those steps is inferred by these transport commands:
there is no `--init`, `--sign`, `--resume`, `--execute`, missing-root fallback,
head refresh or automatic signature renewal in the transport entry points.

The separate offline secondary signing commands can prepare canonical entries
and typed outboxes for selected secondary assignments. This server still owns
only its original primary executor/coordinator pair. It does not accept those
secondary operations; the reviewed secondary server/delivery handoff remains a
separate implementation gate. See the secondary section of
[PRUNE_PREPARATION.md](PRUNE_PREPARATION.md) for the preparation boundary.

An assignment file is bounded to 8 KiB and canonically decoded. A `--key` file
contains exactly 32 raw Ed25519 seed bytes, not hex or a 64-byte private key.
Both use the existing bounded regular-artifact reader, which rejects final-path
symlinks and checks the opened file identity. Keys are read only from the
explicit path, never generated or persisted by these commands. Use protected
files and directories (normally mode 0600 for seed files); this reader does not
establish OS owner/ACL policy or guarantee memory erasure. Do not put seed bytes
in flags, logs or a shared journal.

The paths below are illustrative. Different names are not evidence of separate
physical failure domains. Independently protect all pin/outbox roots and keep
the original writers fenced before handing their ownership to this service.

## Start the command service

```sh
omd work-prune-command-serve-quic \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --key /srv/om-keys/command-server.key \
  --server-peer-id <pinned-server-transport-id> \
  --client-peer-id <pinned-client-transport-id> \
  --authority /srv/om-authority \
  --authority-pins /srv/om-authority-pins \
  --executor /srv/om-prune-executor \
  --executor-pins /srv/om-prune-pins \
  --request-id <independently-retained-request-id> \
  --listen /ip4/127.0.0.1/udp/0/quic-v1 \
  --timeout 10s
```

Replace the angle-bracket placeholders before running. The default listen
address is loopback with a dynamically allocated UDP port. There is no default
data directory or key path. The existing transport resource, concurrency and
rate limits apply; this CLI does not offer flags to remove them.

After both handlers are installed, stdout emits one
`serving_work_prune_commands` line with the server/client pins, assignment ID,
request ID and actual `listen` route. It also reports `command_only=true`,
`execution_enabled=false` and `automatic_resume=false`. Readiness describes this
local startup, not a continuing availability or execution authorization proof.
If readiness output fails, the service closes and drains its acquired owners.
During these commands, Unix SIGPIPE notifications are handled so a broken stdout
returns EPIPE through that cleanup path instead of terminating before deferred
shutdown. This signal handling is removed when the command returns.

Ctrl-C/SIGTERM cancels the transport, prevents new handler admission and waits
for accepted handlers before releasing the four roots. Ordinary shutdown exits
successfully; retained storage/shutdown failures return an error. Do not force
unlock a live owner. A filesystem sync is not force-aborted by the network
timeout. Storage uncertainty stops the service without reopening or submitting
anything automatically. Malformed or stale commands do not stop a healthy
service merely because their delivery failed.

## Deliver one retained command

Admission:

```sh
omd work-prune-admission-deliver-quic \
  --assignment /srv/om-trust/assignment.omcaa \
  --assignment-id <independently-retained-assignment-id> \
  --key /srv/om-keys/command-client.key \
  --outbox /srv/om-admission-outbox \
  --intent-id <independently-retained-admission-intent-id> \
  --peer <explicit-server-route> \
  --timeout 10s
```

Completion uses `work-prune-completion-deliver-quic` with a separately prepared
completion outbox and its own intent ID; the remaining flags are the same.
The two outbox types cannot substitute for one another. The route is not a
source of trust: authentication must match the server pin retained in the
outbox. All IDs must be nonzero. Positional arguments, unknown flags and repeated
flags are rejected, including repetitions with the same value.

Each invocation owns the existing outbox and performs at most one exact
exchange. The default timeout is 10 seconds; accepted values are 100ms through
2m. This is an exchange limit, not a deadline for opening/fsyncing files or
creating/closing transport. No command mutates global daemon settings.

After a checked receipt is durably retained and the owned transport/journal have
closed successfully, stdout emits `work_prune_delivery` with the command name,
assignment ID, intent ID, entry ID and exchange nonce. Its flags are
`delivery_confirmed=true historical_only=true execution_authorized=false
automatic_retry=false`. It does not attest that a new network exchange occurred:
a retained receipt returns without opening a socket, even with an offline
route, after the supplied key still matches the retained client pin.

## Failed delivery and recovery

An error or missing output does not prove the server failed to commit. Keep the
same outbox and independently retained intent ID. Do not replace the entry,
choose a newer authority head or infer that work was cancelled. After a stdout
failure, the receipt may already be present: rerunning the exact command can
print that original receipt without contacting the server.

If no receipt is retained, only an explicit invocation retries the exact entry
with a fresh exchange nonce. Historical retry after completion/retirement does
not reopen an admission or repeat a chain effect. A cached ACK is a local
historical channel observation, not a signed portable certificate or current
authorization. Changing a route does not change either peer pin.

An explicitly configured local stdin pipe can now enter the
[one-way maintenance boundary](PRUNE_MAINTENANCE.md) without releasing the
original locks. It permits only review and exact reviewed pre-start cancellation,
not Execute. The default service still ignores stdin. A separate offline command
opens only stopped owners, without listening, signing or automatic recovery.
Its separate recovery-review/recover modes require an exact confirmed/observed
state digest and explicit action, and can settle only one eligible retained
transition. They never fill an admission-binding gap or create a new Complete.
Any local chain effect still requires a separate guarded ownership handoff; there is no
CLI effect API. Live archive-policy checks, all-required-assignment
enforcement, reviewed ownership handoff, protected physical storage/pins,
copied-owner fencing and active cross-host cutover remain separate open gates.
The separate [local archive acceptance library](PRUNE_ACCEPTANCE.md)
does not add an effect command or transfer ownership out of this service.

## Verification scope

Unit/race tests cover required/external pins, bounded input files, repeated
flags, key separation, failed startup cleanup, typed outboxes, cached receipts,
and stdout failure after durable delivery. Two real CLI-process campaigns use
SIGTERM and forced termination across prepared, admitted, cancelled/completed
and retired states. Both endpoints survive restart and explicit exact retry;
two successive reopen checks leave the expected histories unchanged. The
command-only fixture deliberately has no WorkChain database. Earlier runtime
and executor tests cover publication boundaries and actual local chain effects.
Process termination is not power-loss or physical-independence evidence.
Additional regressions require a storage-triggered service stop to return its
retained error and exercise genuinely closed stdout pipes for readiness and both
delivery commands. Delivery receipts survive the failed output and can be read
offline without another exchange.
