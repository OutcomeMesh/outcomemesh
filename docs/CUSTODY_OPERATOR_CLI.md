# Managed custody operator commands

Three opt-in commands expose retained intent preparation, the owned auditor and
the owned local Audit/Serve pair:

| Command | Default | Explicit work |
| --- | --- | --- |
| `work-archive-custody-audit-intent` | Review unsigned preparation | Publish exact reviewed bytes, or verify a retained file |
| `work-archive-custody-managed-audit-quic` | Review existing auditor scope, then release the owner | Supervised prepare, exact recovery or one pinned network audit |
| `work-archive-custody-managed-pair-quic` | Review both existing participants, then release their shared owner | Supervised paired exchange through two privately owned QUIC hosts |

These commands use the existing intent and acceptance contracts in
[CUSTODY_MANAGED_RUNTIME.md](CUSTODY_MANAGED_RUNTIME.md). Bootstrap, externally
co-signed admissions and authority completion remain separate operations.
The commands do not create authority tickets or append Stop/Complete/Retire.
They do not initialize missing authority roots, journals, artifact locks or
object stores. A successful exchange leaves both tickets pending.

The separate [ticket workflow](CUSTODY_TICKET_WORKFLOW.md) now provides reviewed
consumer signing, authority co-signing, terminal capture and explicit local
application of Audit/Serve Admit/Complete. It uses the exact existing owner and
source journal; it does not make completion part of a network exchange.

This is a local operator boundary. Distributed current-authority enforcement,
remote partitions, copied-key fencing and independent physical storage remain
separate deployment gates.

## Retain an unsigned audit intent

Prepare all exact values before invoking the command. The dedicated nonce file
contains exactly 32 bytes from a cryptographic random source and must not be the
all-zero value. Use fresh
random material for this purpose; a transport or evidence-key seed is not a nonce
source. Protect it until the corresponding challenge is published.

Review and publish require every construction field explicitly, including
`--prior-sequence 0` for the initial cycle. The command does not infer a head,
receipt, nonce, issue time or expiry from a peer or the current clock. For the
initial cycle the predecessor receipt is the assignment's immutable initial
receipt and the predecessor head is exactly 64 zero hexadecimal digits.

Replace uppercase placeholders with independently retained values. IDs and
public keys use canonical lowercase 32-byte hexadecimal; times are fixed Unix
seconds and sample count is an unsigned integer.

```sh
omd work-archive-custody-audit-intent \
  --assignment /srv/outcomemesh/metadata/assignment.omcaa \
  --assignment-id ASSIGNMENT_ID \
  --intent /srv/outcomemesh/audit-intent/intent.omcai \
  --consumer-public-key AUDIT_CONSUMER_PUBLIC_KEY \
  --auditor-public-key AUDITOR_EVIDENCE_PUBLIC_KEY \
  --replica-peer-id REPLICA_TRANSPORT_ID \
  --prior-sequence 0 \
  --prior-head-id 0000000000000000000000000000000000000000000000000000000000000000 \
  --prior-receipt-id INITIAL_RECEIPT_ID \
  --issued-at ISSUED_AT \
  --expires-at EXPIRES_AT \
  --renew-until RENEW_UNTIL \
  --samples SAMPLE_COUNT \
  --nonce-file /run/outcomemesh/audit-nonce.bin
```

The intent parent already exists and is separate from assignment metadata and
the nonce source. Review prints its `intent_id` and readable scope with
`published=false`, `signed=false`, `admitted=false`. Neither nonce bytes nor
private-key bytes enter the report.

After independently retaining that ID, repeat the same construction invocation
with `--mode publish --intent-id INTENT_ID`. Publication requires that exact ID
and uses immutable no-replace installation. An identical retry reuses the same
bytes; a conflicting destination is an error. Changing a nonce or a timestamp
creates different preparation and cannot replace this intent.

Verification needs only the assignment and intent pins:

```sh
omd work-archive-custody-audit-intent --mode verify \
  --assignment /srv/outcomemesh/metadata/assignment.omcaa \
  --assignment-id ASSIGNMENT_ID \
  --intent /srv/outcomemesh/audit-intent/intent.omcai \
  --intent-id INTENT_ID
```

`verify` is read-only and rejects construction flags. If publication output is
lost, verify the exact retained file before any explicit retry. Keep the external
intent and its ID in the operator's backup set; the existing journal/artifact
backup does not include its separate parent.

## Owned auditor

The Audit admission must already be confirmed in the original coordinator, with
purpose `Audit` and `OperationID == IntentID`. `--ticket-id` pins the canonical ID
of the complete co-signed admission, rather than the unsigned intent itself.

The following invocation only reviews existing scope:

```sh
omd work-archive-custody-managed-audit-quic \
  --assignment /srv/outcomemesh/metadata/assignment.omcaa \
  --assignment-id ASSIGNMENT_ID \
  --admission /srv/outcomemesh/metadata/audit-admission.omcae \
  --ticket-id AUDIT_TICKET_ID \
  --intent /srv/outcomemesh/audit-intent/intent.omcai \
  --intent-id INTENT_ID \
  --manifest /srv/outcomemesh/metadata/manifest.omwm \
  --receipt /srv/outcomemesh/metadata/initial-receipt.omrr \
  --authority /srv/outcomemesh/authority \
  --authority-pins /srv/outcomemesh/authority-pins \
  --journal /srv/outcomemesh/auditor-journal \
  --artifacts /srv/outcomemesh/audit-artifacts \
  --auditor-key /run/keys/auditor-evidence.seed \
  --auditor-peer-id AUDITOR_TRANSPORT_ID \
  --max-challenge-lifetime-seconds 60 \
  --max-proof-age-seconds 100 \
  --max-renewal-term-seconds 20000 \
  --timeout 10s
```

Use the custody-policy values actually committed by the assignment; the numbers
above are an example. The receipt remains the journal's initial receipt after
renewal. The artifact root and its permanent `custody.lock` already exist. All
authority/pin, journal, artifact and intent-parent placements are disjoint.

For a network audit add `--transport-key /run/keys/auditor-transport.seed` and
`--peer /ip4/127.0.0.1/udp/PORT/quic-v1/p2p/ROUTE_LIBP2P_ID` together. The route's
libp2p suffix is distinct in format from the OutcomeMesh hexadecimal transport
pin. The authenticated replica must match the transport ID retained in the
intent; the route supplies no replacement identity. `--listen` controls the
client's direct IP/UDP/QUIC-v1 address and defaults to loopback with port zero.

The evidence seed and optional transport seed contain exactly 32 bytes each.
Their public identities must match their separate pinned roles. Public content,
policy and placement checks precede seed reads. Local journal budgets are
`--journal-max-bytes` and `--journal-max-paths`; timeout is bounded to 100ms..10m
and is not a synchronous filesystem deadline.

Add `--mode control` for the supervised protocol below. The auditor exposes:

| Input line | Effect |
| --- | --- |
| `review` | Report current scope and its local review ID |
| `prepare REVIEW_ID` | Sign/publish the exact intent-selected challenge |
| `recover REVIEW_ID` | Restore the exact committed `prior+1` outputs without networking |
| `audit REVIEW_ID` | Perform one exchange against the pinned replica and accept its exact result |
| `close` | Drain the runtime and release its original owner |

Preparation returns the signed challenge ID. Obtain the separate confirmed
Serve admission for that ID before opening a paired runtime. Stop/drain/close
the auditor before any offline workflow reopens its original authority roots.
The new commands provide no admission signing, delivery or append workflow.
That operator lifecycle remains an explicit integration gate.

`audit` always performs networking, including an exact retry of an already
committed response. `recover` is the separate offline action. Both preserve the
original nonce, times and record; recovery cannot promote a standalone record or
an unrelated newer head into current acceptance.

## Owned local pair

Use `work-archive-custody-managed-pair-quic` when both local participants need
enforcement by the same original coordinator. Running the public managed Audit
and Serve runtimes separately against copied roots does not establish that
ownership, and two live owners cannot open the same roots.

Build paired flags from the auditor invocation as follows:

| Auditor flag | Paired equivalent or addition |
| --- | --- |
| `--assignment`, `--assignment-id`, `--manifest`, `--receipt` | Same pinned inputs |
| `--authority`, `--authority-pins`, `--intent`, `--intent-id`, `--artifacts` | Same original roots and retained intent |
| `--admission`, `--ticket-id` | Rename to `--audit-admission`, `--audit-ticket-id` |
| `--journal` | Rename to `--audit-journal` |
| — | Add `--serve-admission`, `--serve-ticket-id`, `--challenge-id` |
| — | Add the separate existing `--replica-journal` and `--objects` |
| `--auditor-key`, `--auditor-peer-id` | Same evidence seed and auditor transport pin |
| `--transport-key` | Rename to `--auditor-transport-key` |
| — | Add `--replica-key` for the proof seed and `--replica-transport-key` for its transport seed |
| — | Add `--replica-peer-id`, matching the intent |
| `--peer` | Omit: the pair privately connects its own two authenticated hosts |
| Custody-policy limits, `--timeout`, journal budgets | Same effective values, applied to both participants |
| — | Optional `--max-objects` and `--max-object-bytes` for existing object validation |

The paired command defaults to review. Add `--mode control` to retain one
original coordinator and enable `review`, `exchange REVIEW_ID`, and `close`.
Each explicit exchange creates two private QUIC hosts, admits only the selected
opposite transport identity, and drains both streams, callbacks and hosts before
returning. Review and control startup create no listener and exchange nothing.

Auditor and replica transport identities must differ from each other and every
assignment control/evidence key. Auditor/replica journals, artifact root, intent
parent, object root and authority/pin roots are pairwise disjoint. Existing
objects are validated and all required manifest chunks must already be present;
the command does not import missing data.

The same `--listen` configuration is used for both local hosts. Prefer the
default `/ip4/127.0.0.1/udp/0/quic-v1`, allowing separate ephemeral bindings.
A fixed nonzero port can fail the second bind; the runtime reports the failure
and drains the first host. It does not silently rewrite the reviewed address.

## Control channels, review tokens and failure handling

Native control on macOS/Linux needs dedicated readable stdin and writable stdout
pipes, adopted before original owners open. Terminals and regular control files
are rejected. An embedded caller provides interruptible closers or nonblocking
output with the same lifetime contract.

1. Keep stdin open and consume the complete `..._ready` line.
2. Send `review` followed by LF.
3. Consume the review header, readable `scope` and matching `..._scope_end` line.
4. Send an action and the exact lowercase review ID reported by that process.
5. Consume its result, then request a new review before another action.

A header digest alone is insufficient: the complete readable scope must have
been successfully written. A one-shot review is not a reusable control token.
The local comparison ID includes the runtime observation plus the displayed
configuration, including network route/listen where applicable. The runtime
rechecks current state under the original coordinator immediately before the
effect. The token itself grants no authority, and is consumed before the action.

Input consists of bounded complete LF-terminated commands, with at most one
queued line. Wait for each response before pipelining more input. A partial line
followed by EOF is an error; a clean EOF cancels in-flight work. `close` is ordered
after a preceding accepted action. SIGINT/SIGTERM and parent-context cancellation
also interrupt networking/output and drain the runtime. Cancellation may produce
a nonzero exit status; cleanup errors remain available rather than being hidden
as a successful shutdown.

A lost readiness or action result stops the command through its normal cleanup.
An action may already have committed one or both journals before output fails.
Inspect the exact retained intent, authority and journal positions; then perform
a new review and explicit exact recovery/retry. Do not replace a nonce, timestamp,
ticket or journal as a response to missing stdout. The separate signed authority
completion workflow decides when those pending operations may be closed.

These commands add neither a distributed authority broker nor a cross-host
revocation/fencing protocol. The complete launch gate remains in [PLAN.md](PLAN.md).
