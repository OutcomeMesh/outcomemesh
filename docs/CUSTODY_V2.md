# Witness-mandatory custody jobs (V2)

Status: experimental, explicit node-side custody protocol. This does not change
ledger consensus, activate a fork, migrate V1 owners, close existing Serve
obligations or authorize mainnet. The website is unrelated to this work.

## Public assignment and job

`node/custodyv2.Assignment` embeds the V1 archive/participant description as public
preparation, together with a mandatory immutable `Policy`. The outer V2 ID is
new. Policy exists before the assignment: 4–16 sorted unique witness signing
keys, with a threshold strictly greater than two thirds. None may reuse the
replica, authority, remote control, transport, auditor or consumer keys.

A V2 `Plan` names the outer assignment, one audit intent, the exact original
source predecessor and signed challenge, a Serve consumer and one independently
selected client transport key. Audit consumer, Serve consumer and authority sign
the same plan in three different domains. The source, manifest, receipts,
challenge, policy and peer bindings are checked together in `Context`.

The runtime derives its fence scope from that signed context. The scope fixes
outer assignment/intent/plan IDs, a derived Begin commitment, owner/controller
and the assignment's witness policy. A caller cannot substitute a convenient
roster, lower the quorum or supply an unrelated scope. Old assignment, command,
result and root formats cannot authorize this V2 job. The embedded Base ID and
V1 signatures have no V2 execution authority.

This is a distinct experimental custody format, not a new format for every
transaction, PoW block or arbitrary solver task. Other job families and network
activation rules still require their own specified integration.

## Session-bound fence version 1

Fence V0 bytes/domains remain unchanged. Fence V1 uses separate scope, command,
vote, observation and request domains. Its Claim requires a nonzero execution
session commitment in `EvidenceID`. Snapshot/observation retain `SessionID`
through Claim, Unknown and Result; a V1 observation is 340 bytes (V0: 308).
An old zero-evidence Claim does not authorize a V1 scope.

The original target's `Prepare` generates a fresh random Ed25519 session key in
memory. Only its public key and owner-signed Claim leave the process. The private
session key has no import option, file format, seed flag or persisted copy.
Repeated preparation in that live process returns the same candidate.

The witnesses still vote once at each position and retain the full proposal
before signing. A quorum chooses one exact session Claim. Two copies with the
same persistent keys produce different session keys; neither can execute the
other's permission. Witness roots must be explicitly enrolled for this exact
scope by their independent operators. Participants cannot automatically create
new witness histories or discard split votes.

## The actual effect boundary

`Target` retains the original B source-journal decision and object store for its
whole lifetime. It validates the selected claim quorum, its own live session,
original source predecessor and current challenge time before consumption.
It then fsyncs `consumed`, including the candidate and claim certificate, before:

1. reading the challenged archive chunks;
2. signing the custody proof and linked renewed receipt;
3. appending the complete custody record to original B;
4. signing a V2 Result with the winning session key and retaining that result.

There is no arbitrary execution callback. Both signed entry and session signature
are required. The session secret is cleared after the consumed attempt returns.
Every repeated Execute is refused, including after a process kill, key-file copy
or reopen. A new process cannot reconstruct a prepared but unconsumed session;
its old quorum therefore cannot activate another session either.

If consumption exists but no result was retained, the outcome remains unknown.
Neither cancellation nor a missing reply resets consumption. `ReadResult` and
`ResultCommand` can recover only the exact retained result, without new chunk
work, proof time, receipt or session key. A controller may certify Unknown and
then the same result can follow that exact claim/unknown history. There is no
operation to manufacture a result for an unfinished attempt.

## Original A acceptance

A `Bundle` includes the complete V2 Result and Claim/[Unknown]/Result quorum
history. The final certificate must name the exact full result ID, same scope,
claim and session. Quorum evidence cannot be an opaque stand-in for custody
verification: A verifies the chunks, signatures, renewal and predecessor too.

`Acceptor` retains original A's source decision. On first acceptance it verifies
current proof freshness and source position, fsyncs the exact pending bundle and
checked time, then appends the record. A signed, immutable Receipt binds outer
assignment, plan, scope, result, bundle and the accepted source entry/sequence.
The receipt is retained before it can be published to the operator.

Opening an interrupted owner never appends. It validates and fsyncs existing
retained files and their directory before exposing the owner: a complete file
left by a failed sync is not durable merely because it can be read. This creates
no file, signature or grant. `Resume` requires the exact retained
bundle ID. If A still has the predecessor, freshness is checked again before
append; expiration cannot be bypassed with the old checked time. If the exact
entry is already in original A, recovery only publishes its historical receipt,
with the original checked time. A cached receipt is historical evidence, never a
fresh execution permit. Pending, consumed and accepted roots are not deleted or
reinitialized after uncertainty.

Owner roots currently require Darwin or Linux; other platforms fail closed.
Roots have distinct V2 markers and allowed files. Original root/source/lock
placements, metadata, canonical context and ready pins are checked. Kernel locks
serialize each original owner; plain moved/copied roots and source substitutions
fail. Filesystem checks supplement the witness/session protocol; they do not
establish hardware identity.

## Transport and CLI

Only an explicit `Service.Start` registers `/outcomemesh/custody/v2`. It pins the
plan's client peer and assignment's server transport identity. It does not
register a V1 custody execution or control handler. There are at most 8 active
streams and 256 authenticated openings per minute; requests are bounded to
8192 bytes and replies to the existing bounded custody-entry size plus framing.
Complete EOF is required before mutation and before accepting a reply. The
service retains its target until handlers have drained. Requests are Prepare,
Execute(claim), and RecoverResult(claim/[unknown]); none selects roots or keys.
Transport failure never causes an automatic Execute retry.

`omd work-archive-custody-v2` uses `--action ACTION` and defaults to `--mode review`.
Every operation uses a separate action-bound review digest; execution additionally
requires `--mode run --expected-review-id REVIEW`. Reviews read public metadata,
load no seed bytes and open no owner. They are not execution grants.

| Action | Inputs / result |
| --- | --- |
| `draft-sign` | Strict public Context JSON in `--draft`; `--sign-role audit\|serve\|authority`, one private `--sign-key`; publishes a new JSON draft preserving other signatures. |
| `context` | Fully signed public draft; validates and publishes canonical V2 Context. |
| `scope` | Derives and publishes the mandatory witness scope from Context. |
| `create-target` | Explicit fresh root and existing original B journal/objects; performs no custody work. |
| `create-acceptor` | Explicit fresh root and existing original A journal; performs no acceptance. |
| `serve-target` | Retains target and B's separate control/replica/transport seeds; supervises dedicated pipes until `close`, EOF or cancellation. |
| `request` | Publishes a Prepare/Execute/RecoverResult request with an explicit nonce and pinned claim/[unknown] certificates. |
| `call` | Pins one request and peer; makes exactly one authenticated call, retaining the validated reply before stdout. |
| `extract` | Checks response against original pinned request; publishes its claim command, result or result command. |
| `bundle` | Verifies and publishes complete result plus mandatory quorum chain. |
| `sign-unknown` | Validates the exact claim quorum and signs a controller proposal bound to `--evidence-id`; never executes or releases an obligation. |
| `accept` | Checks a pinned bundle under original A and publishes its source receipt. |
| `resume` | Explicit exact pending bundle recovery under original A. |
| `receipt` | Publishes an already retained historical source receipt. |

Except draft preparation, every action selects `--context FILE --context-id ID
--scope-id ID`. Context uses its semantic ID; `--in-id` and certificate input pins
use the reported V2 `artifact_id`. Request extraction additionally uses the
request's semantic `--request-id`. Witness commands use their existing separate
certificate artifact IDs; the same canonical certificate consequently has a
witness-CLI artifact ID and a V2-CLI artifact ID in their respective domains.
Never interchange these pins. V2 ID helpers are documented in the Go API.

Public/seed paths and outputs must be outside the original owner/source/object
roots. All paths and public content pins enter the review digest. Outputs cannot
alias inputs. Call/Accept/Resume require an absent output before dispatch; recover
lost output to a fresh path using the corresponding recovery/read action. Other
immutable publications permit an exact same-byte retry. Irrelevant action flags
are errors. No action creates missing sources or silently enrolls witnesses.

Use the existing witness request/call/quorum commands on the derived V1 scope to
collect and commit each certificate. `TestProcessCustodyV2EntireJobThroughCLI`
is an executable reference for public draft signing, root creation, target RPCs,
normal witness RPCs/quorum assembly and original-source acceptance. Only initial
archive data, unstarted source fixtures and public draft data come from helpers.

The [joint two-host fault campaign](CUSTODY_V2_WAN.md) now exercises the normal
CLI path under reply loss, process kills, quorum outages and expired results.

## Typed per-job Serve disposition

[Serve disposition](CUSTODY_V2_SERVE.md) adds complete typed proposals, a separate
outcome-independent witness decision slot and original-owner A-then-B apply.
Fulfilled and certified-unclaimed jobs can close their V2 execution obligation;
unknown outcomes and ordinary expired B-only outcomes stay held. Guarded profile
5 now has a separate [signed retained-result path](CUSTODY_RETAINED_ACCEPTANCE.md)
for delayed complete proofs. Archive retention is separate and
remains held in every case. Original execution witness history is unchanged.
This is a standalone reviewed operator CLI, not a new Serve voting RPC or V1
ledger migration. Historical acceptance receipts alone never close an unused
original local source.

## Assignment-wide accounting coordinator

The [admission coordinator](CUSTODY_V2_ADMISSION.md) adds a shared witness history
for the outer assignment, two-unit lifetime/pending job accounting, exact source
cursor, never-reused contexts/plans and typed Serve A/B accounting closure.
It is a separate reviewed CLI and journal. Its certificates alone do not
establish current original source ownership or grant execution. The
[required profile](CUSTODY_V2_REQUIRED.md) now binds them to signed policy-3
Target/Acceptor owners and consumes them before archive work. Legacy policy-2
raw owners are unchanged. [Retained proof delivery](CUSTODY_V2_DELIVERY.md)
now adds a bounded authenticated inbox/outbox channel with exact cold recovery;
its acknowledgements do not create an owner or grant execution. Protected
enrollment and activation remain gates.
[Legacy migration rules](CUSTODY_V2_MIGRATION.md) are a specification, with no
import/activation implementation and no release of old pending tickets.

## Trust limits and remaining gates

The safety claim assumes original monotone witness histories and fewer than one
third faulty or copied witnesses. Four logical journals on one/two kernels are
not four independent protected failure domains. Full witness rollback can defeat
that assumption. Split votes can stall permanently; there is no view change,
expiry reset, timeout winner or roster replacement for the same job.

The honest target's volatile session prevents persistent-file copies from using
its old grant. A copied running address space/session secret, compromised target
code, a malicious implementation persisting a supposedly ephemeral secret, or
arbitrary physical work performed outside this adapter is not excluded by a
signature. Remote peers cannot prove that a private key is volatile without an
independently trusted execution/attestation boundary. The quorum fixes one
accepted session/result history; it is not a physical exactly-once theorem for
hostile raw-key programs. Protected independent execution/keys remain a launch
gate. Session public keys must also differ from every persistent participant and
witness role, but that check cannot prove their generation history.

The accepted-source receipt does not advance a V1 authority journal or close its
Serve ticket. Assignment-wide admission/budget integration, global enablement/migration,
independently certified negative Serve
resolution, protected witnesses, safe split-vote progress, external audit and
sustained adversarial public-testnet evidence remain open. The current V1 negative
owners and obligations must be retained unchanged.
