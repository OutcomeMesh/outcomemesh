# Managed remote custody execution

This opt-in library connects the [V1 authority foundation](REMOTE_AUTHORITY_FOUNDATION.md)
to an owned remote custody exchange. A retains the only authority coordinator
and its original Audit journal. B retains its separate worker journal, original
Serve journal, archive objects and replica proof key. No authority root or proof
key is transferred between them. Existing V0 workflows retain their original
contract; no default daemon endpoint or automatic upgrade is installed.

## Fixed scope and roles

`store.RemoteCustodyScope` pins the complete worker configuration, archive,
initial and predecessor receipts, custody policy and already signed challenge.
The challenge must match the exact admitted Serve operation before either
runtime opens. The unsigned Audit intent, its signed admission and selected
predecessor must also match before A can prepare any artifact.

The assignment commits B's separate control and transport keys. The immutable
plan additionally commits distinct A control and Audit transport keys. All are
separate from authority, consumer, auditor evidence and replica proof roles.
Transport peers are derived from these independently configured public keys;
incoming messages cannot choose another owner, plan, predecessor or peer.

The two owned entry points are `OpenRemoteCustodyAuditRuntime` and
`OpenRemoteCustodyServeService`. They open existing roots only. A owns its
original coordinator until all actions and transport cleanup finish. B keeps
the worker's permanent process lock until all data and control handlers drain.
Journal directories and permanent lock identities are rechecked so a live
runtime cannot follow a replacement directory containing the other host's data.
Privileged rollback, complete copied deployments and extracted keys still need
independent physical/access-control fencing.

## Execution order

1. Independently bootstrap one fresh V1 assignment on A, admit the exact Audit
   intent and Serve challenge, and retain B's separate worker plan/Begin proposal.
   B holds no authority coordinator. Prepare the existing A challenge artifact
   explicitly with `PrepareChallenge`; the result must match the pinned body.
2. `Begin` retains, applies and independently confirms the configured Begin in
   A's original coordinator. A pending attempt requires explicit `ResumeBegin`.
   Opening a runtime or retrying a different action does not confirm it.
3. `ExecuteQUIC` holds the original A coordinator and checks both pending
   tickets, the exact active hold and original source position. Only then may
   A's pinned control host send Start. B first confirms Started in its protected
   worker journal, then allows one fresh data attempt in that same runtime.
4. A uses its different pinned Audit transport to exchange the fixed challenge
   on the existing archive-custody protocol. B commits before response delivery.
   A verifies the response at current time, closes/drains the stream, verifies
   freshness again and commits its own original journal before publishing local
   result artifacts. A delivery error leaves the authority hold unresolved.
5. Explicit `SealQUIC` asks B to retain Sealing before stopping data admission,
   cancelling streams and waiting for every accepted data callback. B then
   selects the exact original journal result or an immutable unknown/unseen
   disposition, commits the seal and only afterward signs RemoteDrained.
6. A verifies that signed metadata, closes/drains its control host, co-signs the
   exact Drain and independently confirms its local append. This releases the
   remote hold while both ordinary tickets remain separate obligations.
7. `CaptureTerminal` uses this same runtime's private original A journal. It
   requires the accepted entry ID to equal B's sealed ResultID and the exact
   Drain to be settled in the original authority history. `ApplyComplete` can
   then close Audit and Serve independently using externally signed V1 Complete
   entries whose evidence commits the full typed terminal.

The generic local operation guards remain blocked during the remote hold; the
new Audit exception is private and bound to this exact plan and both tickets.
After draining, the consumed Serve ticket can never enter a generic live Serve
callback again. Reopening the owned A runtime for capture/completion does not
reopen remote execution or sign a new challenge.

## B restart and shutdown

Started is a durable attempt boundary, not a reusable grant. A duplicate Start
cannot replenish the same runtime's fresh allowance. A reopened Started journal
can serve only an already committed exact predecessor+1 cached response. If
that record is absent, it refuses fresh signing and can only be explicitly
sealed with an unknown outcome. Cached recovery preserves the original body,
response time and proof-age checks.

Sealing, including an unconfirmed complete Sealing record, permanently blocks
Start. An unseen seal also rejects delayed Start requests that arrive after
closure. B's owned Close follows the same admission stop and handler drain,
retaining a closed or uncertain journal before releasing its owner. Close does
not sign a successful drain or clear A's durable obligation.

## Metadata protocol

The separate QUIC protocol is `/outcomemesh/custody-remote-control/0`.
Its independently pinned control peer has separate stream, rate and memory
budgets from archive data and admission/completion traffic. A length prefix is
bounded to 4 KiB before body allocation. Canonical requests contain a version,
Start/Seal/Reconcile verb, fresh exchange nonce, full plan and exact Begin.
Replies echo the nonce and both IDs. A Started reply is advisory; a Drained
reply carries the canonical seal and B-signed V1 Drain command. Each exchange
requires exact framing, half-close, complete EOF and a bounded deadline.

The current request is 1,023 bytes, Started reply 107 bytes and retained-result
reply 526 bytes, before the four-byte frame prefix. The control channel never
carries a journal body. ResultID is the canonical `CustodyJournalEntry.ID`;
the original proof body already travels on the separately pinned Audit stream.
Reconcile only observes confirmed Started or replays a confirmed sealed result;
it neither starts data nor implicitly seals or repairs an unresolved marker.

## Acceptance and explicit recovery

| Observation | Required action |
| --- | --- |
| A retained Begin without confirmation | Explicit ResumeBegin; no Start before confirmation |
| B Started without a committed selected result after restart | Reject fresh work; explicit Seal records NoResult |
| B committed but A did not accept before proof expiry | Drain may settle the hold; no successful terminal or completion |
| Lost Seal reply | Retry explicit Seal or query the same retained sealed metadata |
| A retained Drain without confirmation | ResumeDrainQUIC retrieves B's sealed metadata and confirms only the identical pending entry |
| A retained Complete without confirmation | ResumeComplete revalidates the exact terminal and original source before settling that command |
| Exact confirmed Complete retried after the other ticket closes | Historical lookup with the original entry ID and current state, without another effect |

`RemoteCustodyTerminal` commits the plan/Begin IDs, signed Audit admission and
intent, B's seal, the co-signed Drain and the full locally accepted journal entry.
Its codec is a separate bounded version-0 envelope with ID domain
`OMESH/custody-authority/remote-terminal/id/v0`. Historical proof validation uses
the original RespondedAt. No metadata reply, retained digest or expired proof
can create an Audit acceptance that is absent from A's original journal.
Unknown/unseen drains leave both tickets pending; a negative-disposition operator
workflow is a separate remaining task, not successful custody completion.

## Verification and remaining scope

Use Go 1.27.3. Focused normal/race tests cover the wire, explicit peer/rate
isolation, owned execution, immutable source identity, proof expiry and exact
Begin/Drain/Complete recovery. Integration process tests kill B before data and
after its journal commit before response delivery, reopen A's original owner,
and exercise exact cached recovery without fresh signing.

```sh
GOTOOLCHAIN=go1.27.3 go test -race -tags=integration \
  ./node/custodyauthority/store ./node/custodyauthority/remotewire \
  ./node/transport/libp2p -run '^(TestRemote|TestControl|TestQUICRemoteCustody)' \
  -count=1 -timeout=2m
GOTOOLCHAIN=go1.27.3 make -j1 test-all
```

The separate [operator/server CLI](REMOTE_CUSTODY_OPERATOR.md) now supervises
these APIs and durably retains sealed metadata and original-source terminals.
It opens existing roots only and does not automatically bootstrap a deployment.
The subsequent [offline preparation](REMOTE_CUSTODY_OFFLINE.md) and
[position-zero workflow](REMOTE_CUSTODY_BOOTSTRAP.md) provide explicit bootstrap
and reviewed signing. See the separate [V1 WAN campaign](REMOTE_CUSTODY_WAN.md)
for same-assignment cross-host procedure and acceptance records. Independently
enforced key/root copy fencing, negative-disposition closure and the wider
mainnet gates remain open. Local/process success does not supply independent
audit or long-duration public-testnet evidence.

The frozen implementation passed the focused integration/race suite on macOS
(store 76.302 seconds, wire 4.313, transport 3.996). The same suite passed
natively on one Linux/amd64 host with Go 1.26.7, CGO_ENABLED=0, offline dependencies
and `-mod=readonly -p=2` (store 23.051 seconds, wire 0.374, transport 0.663).
Both actual B kill/restart cases and the Begin/Drain/Complete recovery checks
passed. Only helper-only environment guards skipped; the parent tests executed
those helpers explicitly. All 39 recorded native task processes were gone at
cleanup, and the temporary SSH master was closed. Earlier evidence was retained.

The Go-only source manifest matched before and after native testing: 597 tracked
`.go`/`go.mod`/`go.sum` files, sorted by path, with lines containing SHA256(file
bytes), two spaces, relative path and LF. Its SHA256 is:

```text
251e16fdb8d0179aa04eb0509d3949beb5b8ae6ec3315157d87df0883f9e93df
```

Native logs and provenance remain private. This is process acceptance on one
Linux host, with no same-assignment WAN or independent fencing credit.

The final full Go 1.26.7 make test-all also passed formatting, vet and the three
disjoint race groups (store 221.172, 493.024 and 151.868 seconds). Integration-tag
vet and both new parser fuzz smoke targets passed without extending timeouts.
