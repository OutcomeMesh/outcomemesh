# Local managed custody Serve acceptance

`store.ManagedCustodyServeSession` is an opt-in library adapter for one already
admitted Serve operation. It binds a private journal-backed replica session to
the original local `Coordinator`, an exact signed admission, an independently
selected challenge ID and an authenticated transport peer. It creates no host,
listener, CLI mode, admission, completion or retirement command.

This adapter closes a bounded local Serve path. Separate managed Audit, local
paired execution and owned Serve host/CLI adapters are documented in
[CUSTODY_MANAGED_RUNTIME.md](CUSTODY_MANAGED_RUNTIME.md). This library session
alone owns no host and does not activate cross-host cutover. Broader boundaries remain in
[CUSTODY_AUTHORITY.md](CUSTODY_AUTHORITY.md).

## Construction and immutable scope

Construct with
`store.NewManagedCustodyServeSession(ctx, originalCoordinator, config)`.
`ManagedCustodyServeConfig` supplies the following exact bindings:

| Input | Required binding |
| --- | --- |
| `AssignmentID` | The independently pinned assignment ID of the original coordinator |
| `Admission` | An already retained, actor-signed and authority-signed `Admit` entry with purpose `Serve` |
| `ChallengeID` | The selected signed challenge's canonical ID, equal to the admission's `OperationID` |
| `AuditorPeerID` | One independently pinned transport identity, supplied again as the authenticated peer on every exchange |
| `Manifest`, `InitialReceipt`, `CustodyPolicy` | The exact static custody scope committed by that assignment and the existing journal header |
| `ReplicaPrivateKey` | A canonical Ed25519 private key matching the initial receipt's replica public key |
| `JournalPath`, `JournalLimits` | An existing active version-0 custody journal and explicit valid local growth limits |
| `Objects` | The original object-store owner containing the manifest's sampled objects |
| `SessionConfig` | A valid bounded request timeout and trusted clock |

The constructor verifies both admission signatures and its exact ticket ID.
Under the original coordinator's operation guard it checks that this ticket is
still pending, reconstructs the assignment from the supplied archive scope and
the owner's retained control scope, and requires the same assignment ID. A
detached snapshot or caller-supplied assignment cannot replace that owner.

The transport identity must be separate from the authority, replica, auditor
evidence and consumer control keys. The adapter compares the transport peer IDs
derived from every one of those keys against `AuditorPeerID`. Transport
authentication alone does not grant execution permission: `Serve` also requires
the original pending admission on every call.

Manifest, auditor-key slices and replica key are copied into private
configuration. The adapter constructs its own journal-backed `CustodySession`;
it accepts no externally supplied raw or record-backed session. The caller
retains the original coordinator and object-store owners for the adapter's
entire lifetime. The adapter does not close either owner.

The authority root, independent intent/pin root, custody journal and object
store must be pairwise disjoint. Construction checks configured and opened
placement; each `Serve` checks placement again under the original coordinator.
Existing ancestor aliases and directory identities participate in overlap
checks. These checks establish placement, not independent physical failure
domains or fencing against later uncooperative root replacement.

## Existing-only journal opening

`workarchive.OpenExistingCustodyJournalWithLimits` never initializes, repairs,
creates or republishes a journal root, permanent lock, header, child directory
or evidence file. It requires an existing nonsymlink root and its existing
zero-length regular `journal.lock`, resolves ancestor aliases, and acquires that
original permanent lock without a create fallback.

While holding the lock, it requires an active version-0 header with exact
canonical bytes for the expected manifest, custody policy and initial receipt,
then fully replays the bounded journal. Any named retirement marker blocks live
opening, even when that marker is malformed. Historical-only version-1 headers,
missing or damaged layout, mismatched pins and changed root/lock identities are
rejected. Root and lock identity are checked across replay. The manifest and
policy retained by the returned handle are detached from caller-owned slices.

The returned state is an observation made under that local lock. It is neither
a reusable authority grant nor a globally current head proof. Local growth
limits retain the existing journal semantics: evidence above a lowered growth
limit may still be replayed up to the fixed hard replay ceiling; that does not
authorize further growth beyond the configured budget.

Opening releases its temporary lock before returning. A lock-close error
suppresses the returned journal and state. Creating the private replica session
uses a separate journal decision to derive its current receipt and exact head
response; a decision-close error similarly suppresses the returned session.

## One guarded exchange

Call `session.Serve(ctx, authenticatedPeerID, stream)` only with the peer identity
established by the transport. This method does not authenticate an arbitrary
caller-supplied hash. The caller supplies and owns the authenticated transport
integration and must provide a stream whose concurrent `Close` interrupts
blocked I/O.

The adapter validates the peer and calls the original coordinator's
`WithOperation` for the exact assignment, ticket, consumer, challenge ID and
Serve purpose. Completed tickets, retired assignments, uncertain retained
authority attempts and closed owners are rejected before challenge input is
read. A rejection closes the supplied stream.

Inside that guard, `CustodySession.ServeExpected` reads one bounded canonical
challenge and compares its ID with the selected nonzero challenge ID. A mismatch
is rejected before the session mutex, journal access, cached delivery, fresh
signing or publication. `ServeExpected` by itself is only an exact-input API; it
does not establish live authority outside this adapter.

For an accepted request the same coordinator guard spans:

1. Active journal decision acquisition and current receipt/head checks.
2. Fresh proof and linked receipt signing, or exact cached/recovered response
   selection.
3. Durable journal append before the first response byte for a fresh response.
4. All response writes, the auditor's final EOF and actual synchronous stream
   closure.
5. Journal decision cleanup and the drain of any cancellation callback before
   the coordinator can admit another guarded transition.

The stream wrapper performs its underlying `Close` once and preserves that
result across normal cleanup and cancellation. Cancellation requests closure
through `context.AfterFunc`; the guard does not return while that callback is
still running. Stream-close, journal-decision-close and cancellation errors
remain errors; a journal decision cleanup failure suppresses the successful
Serve report. A transport or cleanup error does not mean that no journal entry
was committed.

The journal's lock covers signing, response publication and stream retirement.
Its sequence/head checks reject an old session after another operation has
advanced the journal. An exact retry can deliver the same retained response;
cached and restart-recovered responses must still satisfy `MaximumProofAge`
at the current trusted clock. An expired request may recover its already
committed fresh-enough proof, but cannot obtain a newly signed response after
its challenge window. Retry does not refresh proof time or create a sibling
renewal.

Stopping allows an already admitted pending ticket to drain. It does not permit
new admissions. An exchange never implicitly completes its ticket, including
after success, cancellation, disconnect, timeout or process death. Finding a
retained response is not permission to complete or retire the authority.

## Lock and transport lifecycle

The local order is:

`original coordinator guard -> session serve mutex -> custody journal decision`.

The journal decision retains its journal mutex and original permanent kernel
lock. Stream closure occurs before releasing that decision. Cancellation cleanup
is drained before releasing the coordinator guard. Callbacks must not re-enter
the coordinator or start work that outlives the guarded call. A caller's host
must drain active handlers before closing the original owners; the adapter owns
no handler registry, host shutdown or supervision loop.

The custody exchange still uses one challenge and three response frames, with
no new wire encoding or extra acknowledgement frame. After validating all
response frames, `CustodySession.Audit` uses `CloseWrite` when the duplex stream
supports it. The write-side FIN supplies the auditor EOF; Audit then waits for
the replica's EOF before its deferred full close. This prevents a full QUIC
close from cancelling the replica's graceful close while it is still draining.
Simple finite streams without `CloseWrite`, including `net.Pipe`, retain the
full-close/EOF path. Waiting for either final EOF uses the already installed
bounded deadline, without resetting it after the last frame.

This transport cleanup change does not make Audit authority-managed. Static
receipt verification and successful EOF do not authorize durable auditor result
acceptance, artifact recovery or challenge creation.

The existing-only opener uses its supplied context when waiting for the journal
lock. Private-session construction and live Serve inherit the existing journal
decision's bounded lock acquisition, which can wait up to 30 seconds. Closing a
stream interrupts network I/O, not that journal lock wait or synchronous replay.
Cancellation therefore drains within the existing local bounded operations;
it is not a promise of instantaneous return. Owner-controlled clock callbacks,
filesystem operations and transport cleanup must also remain bounded.

## Operator integration and recovery

1. Retain the exact signed challenge and its canonical ID independently. Prepare
   the exact assignment, active journal and object-store owners through their
   explicit bootstrap procedures before using this adapter.
2. Obtain and retain the externally signed Serve admission with
   `OperationID == ChallengeID`; confirm it through the original coordinator.
   The adapter neither signs nor submits that admission.
3. Construct the adapter with those original owners, exact scope and independent
   transport peer pin. Treat any constructor error as absence of a usable
   adapter; do not initialize missing journal evidence as recovery.
4. Route only authenticated matching-peer streams to `Serve`, retain errors and
   drain each call fully. Keep the ticket pending after either success or
   failure. Do not infer a no-effect result from a failed network exchange.
5. After process death, reopen the original coordinator and intact journal with
   the same independent pins and admission. Reconstruct the adapter and retry
   only the exact selected challenge. A committed journal head recovers the
   original response; a missing response does not supply new authority.
6. Stop and drain the caller's transport handlers before closing its coordinator
   and object-store owners. Completion and retirement require their separate
   authorized lifecycle; this adapter provides neither operation.

Never fall back to raw `Serve`, a record-only session, a recreated journal,
detached authority snapshot or a new coordinator when this path refuses entry.
Those alternatives do not preserve this acceptance boundary.

## Test map and remaining boundary

The following named tests describe the intended acceptance evidence. This
document does not record a test run or certify that a release passed them.

| Test | Boundary exercised |
| --- | --- |
| `TestManagedCustodyServeFreshCachedAndRestarted` | Exact fresh, cached and reopened delivery without authority completion |
| `TestManagedCustodyServeRejectsDifferentChallengeBeforeEffect` | Admission-to-challenge binding before effects |
| `TestManagedCustodyServeAuthorityCheckedBeforeStreamInput` | Peer, pending authority, phase, cancellation and closed-owner rejection |
| `TestManagedCustodyServeGuardDrainsEOFAndClose` | Guard retention through EOF and actual cleanup |
| `TestManagedCustodyServeCancellationDrainsCloseAndPreservesErrors` | Once-only close, cancellation interruption and cleanup drain |
| `TestManagedCustodyServeLostWriteRecoversExactRecord` | Durable response surviving a failed first write |
| `TestManagedCustodyServeRejectsAdvancedJournalHead` | Stale cached-session rejection after journal advancement |
| `TestManagedCustodyServeRejectsMissingRetiredHistoricalAndAliasedRoots` | No bootstrap fallback and placement rejection |
| `TestManagedCustodyServeRejectsWrongSignedBindingsAndDetachesConfig` | Exact signed scope, role-key separation and detached configuration |
| `TestManagedCustodyServePinnedQUIC` | Authenticated QUIC fresh/cache/reopen and completed-ticket refusal |
| `TestManagedCustodyServeProcessRecovery` | Process death at construction, first write, EOF, close and return boundaries |
| `TestCustodySessionServeExpectedRejectsBeforeFreshCachedAndRecoveredEffects` | Expected-ID rejection before held session/journal locks |
| `TestCustodySessionServeExpectedRejectsZeroBeforeReading` | Nonzero expected challenge pin before input |
| `TestOpenExistingCustodyJournalReplaysWithoutMutationAndDetachesConfiguration` | Existing replay and immutable configuration |
| `TestOpenExistingCustodyJournalRejectsMissingDamagedRetiredAndHistoricalWithoutMutation` | Existing-only failures without evidence mutation |
| `TestOpenExistingCustodyJournalCancellationWhileWaitingForOriginalLock` | Context-aware original-lock wait |
| `TestCustodyAuditHalfCloseAcknowledgesVerifiedResponseBeforeReplicaEOF` | Verified response, write-side FIN, bounded replica EOF and full-close ordering |
| `TestCustodyAuditHalfCloseRejectsFinishFailures` | Half-close, extra-data and EOF failures cannot become successful delivery |
| `TestCustodyAuditInvalidProofDoesNotHalfCloseAsAcknowledgment` | Verification failure sends no success FIN |

The adapter relies on intact owner-controlled local roots and the original
coordinator and object-store owners. It does not fence later uncooperative inode
replacement, copied roots, copied signing keys, legacy binaries or remote
participants that retain old authority. It adds no distributed current-authority
protocol, cross-host retirement fence, managed Audit lifecycle, default daemon
handler, owned host, CLI acceptance command or automatic ticket completion.

The separate managed Audit adapter now binds a reviewed unsigned intent before
challenge signing. The old `challenge.omcc` is already signed and cannot serve
as that pre-admission intent. Audit binds the new intent through publication and
exact recovery; Serve binds the resulting signed challenge ID. This Serve
session does not itself prepare intents, sign audit challenges or recover audit
artifacts.

`Coordinator.WithOperation` remains non-reentrant: an Audit that holds that
guard while waiting on a Serve that needs the same original coordinator would
deadlock. Different consumers do not create independent authority owners, and
copying roots or opening another coordinator cannot resolve this ordering.
The explicit local pair acquires that owner once, validates both pending tickets
and runs the private participants against separate journals. Its caller retains
the transport lifetime; the separate owned paired runtime and operator CLI now
provide that lifetime. Distributed authority and physical/copy fencing remain open.
