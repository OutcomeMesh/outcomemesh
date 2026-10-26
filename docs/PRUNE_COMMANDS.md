# Command-only prune transport

Status: opt-in pre-alpha operator commands for the original colocated pinned
executor/coordinator, one explicitly selected secondary and existing client
outboxes. These commands deliver already signed Admit/Complete entries. They do
not validate live archive availability, open WorkChain, sign entries, prepare
requests, execute pruning, remotely cancel work, stop/retire an assignment or
implement all-assignment authorization.

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

The separate offline secondary signing commands prepare canonical entries and
typed outboxes for selected secondary assignments. The original primary server
continues to accept only its own assignment. The separate fixed-secondary
service below owns the original executor and the selected secondary, plus the
primary coordinator when admission is enabled. See the secondary section of
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

## Start the primary command service

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

## Start one fixed-secondary command service

The secondary service requires an existing canonical prepared inventory, its
independently retained inventory and policy IDs, and the independently selected
secondary assignment ID. It derives both assignments and the unchanged primary
request from that pinned package. It accepts no `--assignment`,
`--primary-assignment` or `--request-id` substitute. Creating or reviewing the
inventory remains a separate guarded library workflow; startup does not assemble
it, discover its trusted IDs or renew the packaged admissions.

Admission example:

```sh
omd work-prune-secondary-command-serve-quic \
  --mode admit \
  --inventory /srv/om-inventory/prepared.ompi \
  --inventory-id <independently-retained-inventory-id> \
  --policy-id <independently-retained-policy-id> \
  --assignment-id <independently-selected-secondary-assignment-id> \
  --key /srv/om-keys/secondary-command-server.key \
  --server-peer-id <pinned-secondary-server-transport-id> \
  --client-peer-id <pinned-client-transport-id> \
  --executor /srv/om-prune-executor \
  --executor-pins /srv/om-prune-pins \
  --authority /srv/om-secondary-authority \
  --authority-pins /srv/om-secondary-authority-pins \
  --primary-authority /srv/om-primary-authority \
  --primary-authority-pins /srv/om-primary-authority-pins \
  --listen /ip4/127.0.0.1/udp/0/quic-v1 \
  --timeout 10s
```

`--mode` is required and accepts exactly `admit`, `complete` or `both`:

- `admit` installs only the admission receiver and requires all six existing
  owner roots shown above. Each command must equal the selected packaged
  admission; a first target intent also requires the original primary's confirmed
  live guard. Exact retained retries keep the existing recovery/history rules.
- `complete` installs only the completion receiver. Supply the four original
  executor/target roots and omit both primary authority flags. Supplying either
  primary flag is an error, including an empty value. This mode does not open
  the primary coordinator and can receive completion while a separate owner
  retains that primary. It still requires the original executor's independently
  confirmed terminal state and the exact actual secondary admission.
- `both` installs both receivers and requires the same six roots as `admit`.
  It does not create a terminal outcome or execute any work between the two
  command types.

All selected owner roots and the inventory's dedicated parent directory must
be pairwise disjoint, including aliases and containment. All must already
exist; startup initializes or repairs none of them. The two package pins, target
selection, executor binding, retained owner states and peer separation are
checked before the transport seed is read. Server/client transport identities
must differ from every assignment's authority, consumer, replica and auditor
keys and from all trusted checkpoint attestor and replica keys in the package,
including trusted keys outside the selected target. Start then checks the
actual host identity against the explicit server pin. The same protected
32-byte seed format, loopback listener default and timeout bounds apply.

Readiness is a `serving_work_prune_secondary_commands` line containing `mode`,
server/client pins, selected assignment ID, both inventory pins and the actual
`listen` route. It also reports `command_only=true execution_enabled=false
automatic_resume=false`. Failed readiness output, Ctrl-C/SIGTERM and retained
storage failure use the owned drain path before releasing any owner. A second
service cannot share these live roots. The service owns no signer or WorkChain
handle and accepts no stdin maintenance, initialization, execution or recovery
flags.

Use an explicit ownership handoff between admission and the local outcome:

1. Deliver the selected secondary Admit through its existing typed outbox.
2. Stop the command service and wait for successful shutdown/drain before any
   offline owner opens the same roots. For library callers, finish `Close` and
   observe `Done`; preserve any returned storage/shutdown error for review.
3. Use the separate guarded local workflow for an effect or reviewed pre-start
   cancellation. Complete signing/outbox preparation remains separate as well.
4. Close those offline owners, then reopen the fixed-secondary service with
   `--mode complete`, the same inventory/pins/target and the four original
   executor/target roots. Deliver the retained secondary Complete outbox.

Keeping `both` running cannot perform step 3: it retains the executor owner and
exposes no effect/cancellation API. Reopening in either mode advances nothing
by itself and is not recovery of a retained attempt. The library wrapper exposes
only `Start`, `Addresses`, `Done` and `Close`; it does not export the owned
coordinators, executor or the primary service's stdin maintenance boundary.

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

These same two delivery commands carry secondary entries unchanged. Supply the
selected secondary's canonical assignment and independent ID, its typed outbox,
and the fixed-secondary service route. The server derives its trusted scope
from the pinned inventory; the client's assignment file does not select or
replace that scope. There is no separate secondary delivery format or automatic
multi-target routing.

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

For the original primary server, an explicitly configured local stdin pipe can enter the
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

Fixed-secondary tests additionally cover all explicit modes, external package
pins, target selection, peer/key separation, disjoint paths, scope validation
before key reads, failed startup cleanup and refusal of primary flags in
completion mode. Real CLI processes deliver the secondary Admit, stop/drain,
perform a separate offline pre-start cancellation, then reopen completion-only
and deliver Complete while the primary remains separately owned. SIGTERM,
forced termination and broken readiness/delivery stdout preserve owner history
and exact offline receipts. These command tests open no WorkChain database and
do not establish live all-assignment authorization, an archive effect,
cross-host ownership transfer or production readiness.
