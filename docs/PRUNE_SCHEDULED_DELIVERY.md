# Scheduled Prune command delivery

Status: experimental library adapter. The default daemon does not register this
endpoint. CLI service configuration and protected remote execution remain open.

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
around authority/executor confirmation and client receipt publication.
