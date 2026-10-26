# Managed custody audit and serving

The managed custody path binds each live action to a pending operation in the
original local authority coordinator. Audit preparation, acceptance and exact
recovery are explicit library calls. A separate operator CLI owns a serving host
for one already admitted challenge. Neither path completes tickets automatically.

These are local enforcement boundaries. They do not establish distributed
revocation, cross-host authority freshness, copied-key fencing, physical storage
independence or mainnet readiness. The wider gate remains in
[PLAN.md](PLAN.md) and [CUSTODY_AUTHORITY.md](CUSTODY_AUTHORITY.md).

## Prepare one audit before signing its challenge

Use the following order. IDs must come from reviewed, independently retained
inputs, never from a queried peer or an untrusted latest-head response.

1. Select the existing original assignment, active version-0 auditor journal and
   artifact root. The artifact root and its permanent zero-length `custody.lock`
   must already exist. Initialization/import is a separate offline bootstrap
   action. Constructors do not create missing journals, locks or object stores.
2. Build an unsigned `workarchive.CustodyAuditIntent` with the assignment ID,
   consumer control key, auditor evidence key, pinned replica transport ID,
   predecessor sequence/head/receipt IDs, exact issue/expiry/renewal times,
   requested sample count and a nonzero nonce. Retain that nonce and those times
   before any challenge signature is produced. Generate a fresh nonce with a
   cryptographic random source and protect the intent until the challenge is
   published; an externally predictable sample is not an independent storage test.
3. Review its canonical bytes and `intent.ID()`. Publish it explicitly with
   `PublishCustodyAuditIntent(ctx, path, intent)` into an existing protected
   directory separate from both journals and the legacy artifact tree. Exact
   retry compares retained bytes; it does not generate a replacement intent.
4. Obtain and confirm an externally co-signed `Admit` for purpose `Audit`, with
   `OperationID == IntentID`, under the original coordinator. Signing and
   admission are separate operator actions; the managed constructor does neither.
5. Construct `store.NewManagedCustodyAuditSession` with the original coordinator,
   `ManagedCustodyAuditConfig`, independent intent ID, canonical admission,
   manifest, initial receipt, exact custody policy and auditor evidence key.
   The constructor rederives the assignment scope and opens only existing
   active evidence. It signs nothing and repairs no missing outputs.
6. Call `PrepareChallenge(ctx)`. Under the current Audit ticket, artifact lock
   and journal decision, this signs/publishes the exact selected challenge using
   the retained nonce and times. Retain the returned canonical challenge ID.
7. Independently admit purpose `Serve` with `OperationID == ChallengeID`.
   A Serve admission binds this signed challenge, while the Audit admission
   continues to bind the earlier unsigned intent.

The intent's directory, artifact root, journal, original authority root and
authority pin root must be pairwise disjoint. Transport identities remain
separate from authority, consumer and auditor/replica evidence keys. The intent
is unsigned preparation; retaining it grants no permission to sign or accept.

The new intent has its own bounded canonical encoding and hash domain. Existing
challenge, response, receipt and custody-journal encodings remain unchanged.
Do not put an intent file in the legacy artifact tree: that tree still recognizes
its existing per-cycle challenge/record/receipt layout.
Back up the independently pinned intent and its protected directory separately:
the existing journal/artifact backup format does not include this external root.
Missing intent after a restore is an error, not permission to generate another.

### Intent encoding

Version 0 is exactly 268 bytes with fixed fields in this order. Integers use
the existing codec's big-endian encoding; there are no variable-length fields.

| Field | Bytes |
| --- | ---: |
| ASCII magic `OMCAINT0`, then version `u16 = 0` | 10 |
| Assignment ID, consumer public key, auditor public key, replica peer ID | 128 |
| Predecessor sequence `u64` | 8 |
| Predecessor head ID, predecessor receipt ID | 64 |
| Issue time, expiry time, renewal deadline, each `u64` | 24 |
| Requested samples `u16` | 2 |
| Retained nonce | 32 |

Its ID uses `types.DomainHash` with
`OMESH/workgraph/archive/custody-audit-intent/id/v0` and those canonical bytes.
Unknown versions, trailing bytes, invalid field bounds and envelopes above the
512-byte input ceiling fail closed. The deterministic golden fixture in
`custody_audit_intent_test.go` has ID
`4916f1d3fdb11272b9f4c1a826975f946b1519569f70281844e86ba7ab314113`.

## Audit acceptance and exact recovery

`ManagedCustodyAuditSession.Audit(ctx, authenticatedReplicaID, stream)` requires
the actual identity authenticated by the caller's transport. The caller owns
that transport and the original coordinator; passing a hash does not authenticate
a connection. Construction creates no host, listener or audit client CLI.

Every effect rechecks the pending Audit ticket, the original retained intent and
root placement under that same coordinator. The guard covers challenge
publication, network validation, actual stream closure, journal acceptance,
durable artifact publication and cancellation cleanup. Stopping allows previously
admitted pending work to drain; completed tickets, retired assignments and
uncertain authority attempts reject live entry. No diagnostic snapshot replaces
the guard.

A fresh response is verified at the current trusted clock. The complete record
is committed to the auditor journal before its record/renewed-receipt outputs
are published. An output failure can therefore leave committed evidence even
when the method returns an error. Keep the ticket pending and inspect/recover
that exact operation; an error does not prove no effect.

`Audit` always performs the network exchange, including an exact retry after its
record has committed. It compares the returned canonical record with that head
without another append or refreshed timestamps. Use the separate `Recover`
method when no network exchange is intended.

`Recover(ctx)` requires the exact `PriorSequence + 1` journal entry, matching
predecessor head and receipt pins, and the challenge selected by this intent.
It restores only the exact retained challenge/record/receipt bytes. It does not
search an arbitrary newer head, promote a record-only file into a journal commit,
replace a nonce, move issue/expiry time or refresh proof age. Live recovery still
requires current authority and the configured proof freshness checks. Historical
verification remains a separate evidence workflow.

Raw `CustodyAuditCycle` methods are trusted effect primitives. They do not prove
admission by themselves. Do not substitute them or a legacy CLI path when the
managed adapter refuses a ticket or its retained evidence.

## Server CLI

`work-archive-custody-managed-serve-quic` selects one signed Serve admission and
one exact challenge ID. It privately opens the original coordinator, existing
object store and existing active journal before any listener starts. It has no
Admit, Complete, Retire, object import, journal initialization or automatic
recovery mode.

Review is the default. It validates retained scope, closes every original owner
and then prints `owners_retained=false` and `listener_started=false`, followed by
readable paths, content pins and effective limits. A successful review is a local
observation, not a reusable execution token. The serving invocation reopens and
checks the original authority again.

Replace the uppercase ID placeholders below with the independently retained
canonical lowercase hexadecimal IDs. Every named input file/root already exists.
The three custody limits must reconstruct the policy committed by the assignment.

```sh
omd work-archive-custody-managed-serve-quic \
  --assignment /srv/outcomemesh/metadata/assignment.omcaa \
  --assignment-id ASSIGNMENT_ID \
  --admission /srv/outcomemesh/metadata/serve-admission.omcae \
  --ticket-id SERVE_TICKET_ID \
  --challenge-id SIGNED_CHALLENGE_ID \
  --manifest /srv/outcomemesh/metadata/manifest.omwm \
  --receipt /srv/outcomemesh/metadata/initial-receipt.omrr \
  --authority /srv/outcomemesh/authority \
  --authority-pins /srv/outcomemesh/authority-pins \
  --journal /srv/outcomemesh/replica-journal \
  --objects /srv/outcomemesh/objects \
  --key /run/keys/replica-transport.seed \
  --replica-key /run/keys/replica-proof.seed \
  --server-peer-id SERVER_TRANSPORT_ID \
  --auditor-peer-id AUDITOR_TRANSPORT_ID \
  --max-challenge-lifetime-seconds 60 \
  --max-proof-age-seconds 100 \
  --max-renewal-term-seconds 20000 \
  --timeout 10s \
  --listen /ip4/127.0.0.1/udp/0/quic-v1
```

`--ticket-id` is the canonical ID of the co-signed Serve admission, not the
challenge ID or an outbox delivery ID. The receipt is the journal's immutable
initial receipt, including after a successful renewal; do not substitute the
latest output receipt when reopening this same journal.

The transport and proof seed files contain exactly 32 bytes each. Their derived
public identities must match the externally pinned server peer and initial
receipt. The allowed auditor transport identity must differ from the server and
all assignment control/evidence identities. No default key path or generated
fallback is used. Public pins, custody policy and root placement are checked
before seed reads. Required path text must be valid UTF-8 so the rendered review
describes the actual configured paths.

Additional local budgets are `--journal-max-bytes`, `--journal-max-paths`,
`--max-objects` and `--max-object-bytes`. The exchange timeout is bounded to
100ms..10m. Existing objects are checked against their content-addressed filenames
and local budgets; starting the server does not establish independent physical
storage or availability of every possible requested object.

### Supervised serving

Add `--mode serve` to the reviewed flags and run the command under a supervisor
that supplies dedicated readable stdin and writable stdout pipes. Native serving
uses interruptible pipes on macOS/Linux; terminals and regular files are rejected
before original owners open. An embedded caller must provide interruptible
closers or a nonblocking output writer with the same contract.

Keep stdin open while serving and consume the bounded readiness line beginning
`work_archive_custody_managed_serve_ready`. It includes the exact assignment,
ticket, challenge, both peer pins, actual listener address and
`owners_retained=true`. Treat a missing/partial readiness line as startup failure;
do not infer that no process or retained response existed.

The control input accepts only `close` followed by LF, or EOF. A partial command,
unknown command or oversized line fails closed. EOF, SIGINT/SIGTERM, cancellation
and readiness-output failure stop handler admission and interrupt network/output
I/O. Shutdown waits for every accepted handler and actual stream cleanup before
releasing the original coordinator. `Done` means that drain and owner closure
finished; `Close` returns any retained shutdown/storage error.

Closing the service is a local lifetime operation. It does not append authority
Stop/Complete/Retire, erase an admission, renew a receipt, or release an uncertain
operation for a different request. Stop/drain/close this owner before a separate
offline authority command reopens the same roots. A competing process is refused
while the server owns them.

Fresh, cached and restart-recovered responses remain bound to the same ticket
and challenge. A replica response is committed before its first network byte.
Exact retry can return only that retained response while its proof is fresh and
the journal head still matches; it cannot sign a sibling response or refresh its
time. See [CUSTODY_SERVE_ACCEPTANCE.md](CUSTODY_SERVE_ACCEPTANCE.md).

## Pair both local participants without recursive ownership

A standalone managed Audit holds its original coordinator while waiting for its
peer. Calling public managed Serve against that same coordinator at the same
time would wait on the same non-reentrant lock. Different consumer keys do not
create different original owners. Copying roots or opening a second coordinator
does not solve that ordering.

Use `NewManagedCustodyAuditServePair(auditSession, serveSession)` for explicit
local composition. Both sessions must use the same original coordinator and
independently retained pending Audit/Serve tickets. The caller keeps that owner
alive and supplies authenticated opposite stream ends to `Exchange`. The pair
requires different auditor/replica transport identities. It
acquires the original coordinator once, validates both exact operations and
challenge binding, then runs the private participants concurrently under that
single guard. It does not call either public guarded adapter recursively.

Auditor journal, replica journal, artifacts, intent directory, object root and
the authority/pin roots must be distinct real placements. Both streams,
cancellation callbacks and private effects drain before the shared guard exits.
A partial failure can leave one or both journals committed; neither ticket is
completed. Inspect each exact retained side and use its explicit recovery path.

This pair is a local library executor. It owns no transport host and grants no
permission to remote copies. It is not a distributed broker, cross-host fence,
automatic owner transfer or authority policy-generation protocol. Keep those
larger acceptance gates open even after local paired execution succeeds.
