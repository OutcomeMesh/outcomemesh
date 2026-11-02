# Scheduled Prune command delivery

Status: experimental explicit CLI and library adapter. The default daemon does
not register this endpoint. Independently protected remote execution remains open.

The [two-host acceptance workflow](PRUNE_DELIVERY_ACCEPTANCE.md) covers original
command accounting across process cuts, explicit recovery and cold retries.

Scheduled admission and completion use `/outcomemesh/scheduled-prune-command/0`.
Legacy admission and completion protocols continue to accept only their original
version-0 entries. There is no negotiation or fallback between these families.

## Prepared inputs

The operator first prepares and signs a scheduled command through the existing
[local workflow](PRUNE_SCHEDULED_OUTCOMES.md). A delivery intent fixes:

- the sending and receiving transport identities;
- the original plan ID, request ID and executor binding;
- the exact co-signed ScheduleVersion2 entry and selected assignment;
- the inventory ID for completion, or zero for admission;
- the receiving operator's independently obtained local review ID.

The receiver configures the original paths separately. Paths, keys, archive
contents and replacement owner positions cannot be supplied over the stream.
Both sides retain the intent ID independently. Intent creation and server
construction do not create authority, executor or storage roots.

## Receiver behavior

`NewScheduledPruneCommandServer` accepts one fixed intent and local configuration.
`Register` checks the receiving transport identity before installing its pinned
peer handler. Each complete request must be followed by write-side EOF before
the server opens any original owner. Frames are bounded before decoding.

The server uses the local scheduled-command validation while holding the original
executor, its independent pins, the selected authority and its confirmation
journal. Fresh admission also holds the original custody journal. It verifies
the full plan and, for completion, the original inventory and retained terminal
outcome. A settlement completion must name the full settlement artifact; a bare
effect ID cannot substitute for it.

Within that owned call, completion reuses the already validated inventory bytes
and terminal evidence ID. Public validation still checks every supplied value,
and each new request checks the original owners again. Verification results are
not cached across requests. Internal validation reads executor state only while
holding its mutex; public snapshots remain detached.

A fresh command requires the configured local review. A confirmed exact
historical command can be acknowledged without adopting a newer review or
appending another entry. Primary admission additionally requires its confirmed
executor binding. The reply follows successful owner confirmation and close.

An unconfirmed authority attempt, an executor pin intent, or an authority admission
without its executor binding receives no acknowledgement. The operator inspects
the original owners and uses the existing local `apply` or `resume` workflow with
a new explicit review. Once that exact command is fully confirmed, the original
delivery intent can be retried. The network endpoint cannot perform this recovery.

The adapter holds no owner locks while idle. Concurrent local ownership makes a
delivery fail closed. It cannot sign, execute deletion, cancel, settle, retire,
create an owner, clear a pending attempt or select a new head.

`PrepareScheduledPruneCommandService` checks the complete original-owner command
path before opening a listener, then releases those owners. Preparation returns
before application and does not publish command artifacts. The transport keys
must be separate from every authority, replica, consumer and auditor in the full
plan. Every request repeats the owned validation; preparation grants no cached
permission. Shutdown stops admission, cancels transport I/O and drains accepted
handlers before reporting completion. An uncertain durable write stops the
service and retains its error. A stream deadline cannot interrupt filesystem I/O.

## Sender persistence and recovery

`CreateScheduledPruneOutbox` creates one new root and durably retains the exact
intent and selected assignment. `OpenScheduledPruneOutbox` requires the original
external intent ID. It verifies and re-syncs existing evidence without sending.
A missing, partial or mismatched root must not be recreated as recovery.

`DeliverScheduledPrune` owns that existing outbox and a fresh pinned transport
for one explicit attempt. A random nonce binds the response to that exchange.
The full reply and EOF must match before the outbox publishes its checksummed
receipt through file sync, exclusive publication and directory sync. No public
API accepts a supplied acknowledgement as proof of delivery.

An interrupted or missing response leaves the intent unresolved. Only the exact
intent may be retried. A killed server can also leave a stale connection in a
long-lived client; that failed exchange remains unresolved. The wrapper closes
the transport before releasing the outbox, and the next explicit call creates a
new one. It never retries automatically.

Cold open does not promote an unpublished temporary receipt. A visible published
receipt is checked and re-synced before it is returned. A confirmed receipt permits
an offline historical response, with the same nonce, after checking the original
client identity. It grants no current execution or storage permission.

## CLI workflow

The commands below require existing, independently pinned artifacts from the
[scheduled operator workflow](PRUNE_SCHEDULED_OUTCOMES.md). Variables are operator
inputs, not values to discover from an untrusted sender. In particular,
`RECEIVER_REVIEW_ID` comes from local `work-prune-scheduled-command` review with the
exact receiver paths, policy and journal limits that will be used for serving.
The review also supplies the original executor binding. Changing those paths or
limits requires a new review for a fresh command. Neither side refreshes it over
the network.

Use distinct transport-only keys. `--key` reads an existing private, regular
32-byte Ed25519 seed file after validating the intent and original stores. It
does not generate a key or accept a role signing key. Keep seeds outside all
owner roots, outboxes and input artifacts, with private permissions. This is an
operator transport credential, not an encrypted user wallet.

### Review and publish

The following is an Admit example. The entry must already carry both required
signatures. Offline review checks the plan, request, entry and transport roles;
it cannot attest the receiver's current position or terminal state.

```sh
omd work-prune-scheduled-delivery-prepare \
  --plan "$PLAN" --plan-id "$PLAN_ID" \
  --assignment-id "$ASSIGNMENT_ID" --entry "$ENTRY" --entry-id "$ENTRY_ID" \
  --request-id "$REQUEST_ID" --executor-binding-id "$EXECUTOR_BINDING_ID" \
  --receiver-review-id "$RECEIVER_REVIEW_ID" \
  --client-peer-id "$CLIENT_PEER_ID" --server-peer-id "$SERVER_PEER_ID"
```

Review the JSON, retain `intent_id` independently, then repeat the same command
with `--mode publish --intent-id "$INTENT_ID" --out "$INTENT"`. Publication is
exclusive. After lost output, repeating those exact inputs preserves the same
artifact; a different existing file is refused. Review rejects output flags.

For Complete, both review and publication also require
`--inventory "$INVENTORY" --inventory-id "$INVENTORY_ID"`. The inventory must
bind the original plan and executor. Admit forbids these flags. An evidence ID
in the signed completion does not itself prove the outcome exists; the receiver
checks the actual retained outcome under original ownership.

### Retain and inspect the sender outbox

```sh
omd work-prune-scheduled-delivery-outbox --mode create \
  --assignment "$ASSIGNMENT" --assignment-id "$ASSIGNMENT_ID" \
  --intent "$INTENT" --intent-id "$INTENT_ID" --outbox "$OUTBOX"

omd work-prune-scheduled-delivery-outbox \
  --assignment "$ASSIGNMENT" --assignment-id "$ASSIGNMENT_ID" \
  --intent-id "$INTENT_ID" --outbox "$OUTBOX"
```

Creation sends nothing and refuses any existing or partial root. If its output
is lost, inspect that original root. Inspection requires the external intent pin,
opens no network connection and rejects `--intent`; it cannot substitute a new
intent or import a receipt. Preserve the original outbox across retries.

### Serve one reviewed command

Run this on the receiver with its original selected authority and primary
executor. All four owner paths must be available locally to that process.
For a fresh Admit, provide the original custody journal and the same policy and
limits used in local command review:

```sh
omd work-prune-scheduled-serve-quic \
  --intent "$INTENT" --intent-id "$INTENT_ID" \
  --plan "$PLAN" --plan-id "$PLAN_ID" \
  --assignment-id "$ASSIGNMENT_ID" --entry "$ENTRY" --entry-id "$ENTRY_ID" \
  --authority "$AUTHORITY" --authority-pins "$AUTHORITY_PINS" \
  --executor "$EXECUTOR" --executor-pins "$EXECUTOR_PINS" \
  --journal "$JOURNAL" \
  --max-challenge-lifetime-seconds "$CHALLENGE_LIFETIME" \
  --max-proof-age-seconds "$PROOF_AGE" --max-renewal-term-seconds "$RENEWAL_TERM" \
  --key "$SERVER_KEY" \
  --client-peer-id "$CLIENT_PEER_ID" --server-peer-id "$SERVER_PEER_ID" \
  --listen /ip4/127.0.0.1/udp/0/quic-v1
```

For Complete, replace the journal and custody policy flags with the pinned
inventory pair. Complete forbids `--journal`. Explicit journal limits require a
journal. Historical Admit can use its retained original evidence after the
journal is offline; this does not permit a fresh admission without its journal.

The default listener is loopback with an allocated UDP port. Select a reachable
QUIC-v1 listener explicitly for deployment. Readiness is one JSON line containing
the actual `listen` routes and exact intent pins. It confirms successful local
preflight and transport setup, not delivery or execution permission. The service
has no mode for signing, resuming, settling or deleting. On SIGINT/SIGTERM it
drains accepted calls before exit; failed readiness output also closes the service.

### Deliver once

```sh
omd work-prune-scheduled-deliver-quic \
  --assignment "$ASSIGNMENT" --assignment-id "$ASSIGNMENT_ID" \
  --intent-id "$INTENT_ID" --outbox "$OUTBOX" \
  --key "$CLIENT_KEY" --peer "$SERVER_ADDRESS"
```

The route does not replace the pinned server identity. Both runtime commands
accept `--timeout` from `100ms` through `2m`, default `10s`. There is one explicit
attempt, with no automatic retry. An error, broken stdout or missing reply does
not establish that the authority rejected the command. Inspect the original
outbox, and if necessary review the original receiver owners before retrying.
Pending writes require local recovery as described above.

With a retained receipt, the same delivery command checks the client key and
returns that historical receipt without dialing; `--peer` remains a required
explicit argument. Reports always distinguish historical delivery from current
head, terminal-state verification and execution authorization. Never use the
receipt as a live storage or deletion grant.

Duplicate flags, positionals, unsupported modes and irrelevant inputs are errors.
These commands retain the existing POSIX owner-lock requirement. Native Windows
binaries remain distributed, but this protected original-store workflow is not
enabled there; use a supported Linux or macOS operator host.

## Bounds and trust

An intent is 648 bytes, a request 690 bytes and an acknowledgement 74 bytes.
The local receipt is 148 bytes. Scheduled streams have their own resource-manager
scope and peer/global rate budgets; unauthorized peers cannot consume the rate
budget. Defaults allow two streams globally, one per peer, eight requests per
peer per minute and 32 globally. Session timeouts range from 100 ms to two minutes.

This is authenticated command delivery to existing locally available owners.
It is not cross-host deletion authorization, profile-5 execution integration or
protection against copied keys, rolled-back hosts or a compromised administrator.
The receiver must already have the original required roots. No new independence
or public activation claim follows from the adapter or its transport tests.

Coverage includes fixed layouts and hashes, malformed frames and incompatible
versions, wrong peers and owner pins, retained settlement downgrade attempts,
lost replies, failed receipt publication, cold reopen and actual process kills
around authority/executor confirmation and client receipt publication. CLI
coverage adds complete admission/completion lifecycles, full settlement evidence,
private-key permissions, lost publication/readiness/delivery output, SIGTERM,
process termination and restart, offline receipts and shutdown while owners are
busy. The original protocol's publication crash tests remain separate.
