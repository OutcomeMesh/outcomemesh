# Service-bound scheduled Prune admission

This experimental local path binds the execution service before authority
admission. It extends the [owned scheduled runtime](PRUNE_SCHEDULED_RUNTIME.md).
The separate [isolated owner](PRUNE_ISOLATED_SERVICE.md) exposes an explicit Linux
Unix exchange. There is no default daemon registration or public activation.

## Enrollment and compatibility

An issuer signs a `prunefence.ServiceEnrollment` containing the original primary
assignment, migrated schedule, storage incarnation and Prune storage pair, plus
distinct service, issuer and guard public keys. These are the actual deletion
identities, not an Audit/Serve deployment pair. The approved issuer and guard
must be pinned by the operator; a self-signed enrollment does not establish trust.

`ScheduledPrunePlan.WithFence` accepts this enrollment inside a new fence policy.
Plan validation rejects service roles reused from the original authority,
replica, consumer, transport, audit, attestation or witness roster. It checks
every storage and schedule binding before any signed admission. The request
commits both the policy ID and enrollment ID. Original authority admissions
still sign that exact request ID as their operation ID.

| Artifact | Existing versions | Service-bound version |
| --- | --- | --- |
| Retained request | 0–3 | 4 |
| Scheduled plan and inventory | 0–1 | 2 |
| Fence policy and candidate | 0 | 1 |
| Signed fence result | 0 | 1 |
| Canonical storage effect | 0–2 | 3 |

Each new artifact uses a distinct ID or signing domain where the artifact has
one. Nested claim, executor and settlement envelopes retain their existing
versions and bind the complete new artifacts. Existing canonical vectors and
their domains remain unchanged. There is no automatic upgrade of an admitted
request, witness slot, executor, authority journal or storage history. Older
binaries cannot consume the new artifact versions and must not open a placement
that has accepted them. Keep every original store and pin when upgrading.

## Live execution

The trusted storage owner supplies a `prunefence.ServiceIdentity` through local
`ScheduledPruneRuntimeConfig.ServiceIdentity`. This field is excluded from JSON.
It contains the enrolled service key and independently configured bounded guard
client. The key and raw owner handles must never become request payloads.
The one-shot scheduled CLI has no option to supply this capability; it refuses
execution of a service-bound request and can still inspect or recover its
retained result. `work-prune-service` configures the isolated owner, which creates
the live capability internally without receiving a consumer seed.

The service signs a fresh volatile session over the full fence policy, original
request, assignment, operation, inventory, executor binding and storage pair.
The original request-wide witness quorum selects that exact signed candidate.
It cannot move to another witness slot by changing a local inventory or session.
The session private key is never serialized.

Immediately before deletion, under the original WorkChain lock, the permit
checks the enrollment committed in the storage operation. It then spends the
local attempt and generates a new random challenge. The independent guard signs
one choice over that challenge and the entire candidate. Its namespace commits
the original storage incarnation, storage pair and admitted request, using the
guard's service-choice kind and slot zero. Repeated sessions for that request
collide in the same namespace. The call has a ten-second upper deadline, further
limited by the caller's context. The configured client must honor that deadline.

The guard applies its retained revocation rules before returning a choice. A
cached seal cannot answer a new challenge. Revocation is effective at this
choice boundary; it cannot retroactively undo a choice already granted. A
matching historical certificate alone never creates a live session or permit.
Legacy session creation and storage consumption reject the service requirement.

The storage effect retains the enrollment ID. The signed result additionally
retains the consumption challenge and guard seal. Verification binds them to
the exact candidate, witness claim and effect. Deletion preserves original
pending tickets, spent accounting, custody receipts and retention history.

## Interrupted and held outcomes

A lost guard reply, cancellation or revocation refusal cannot make the local
attempt reusable. Once Started is retained, missing storage evidence remains
unknown; it is not a reason to retry deletion or discharge the tickets.

After a confirmed signed result, cold recovery returns that exact evidence
without the service key or another guard call. If the process dies after the
storage effect but before its signed result is confirmed, use the existing full
[observed-effect settlement](PRUNE_SETTLEMENT.md). The original witness decision
and each separate replica completion remain necessary. A bare effect does not
replace them. Service key replacement for an already admitted request is not
implemented; do not rewrite its enrollment to make a recovery path pass.

## Deployment boundary

This implementation verifies the mandatory admission and actual effect boundary
inside a trusted local process. The guard has to remain outside participant and
service backups. Local tests include original guard revocation and cold restart,
copied service attempts, cached seals, process termination and full settlement.
They do not prove isolation against an administrator who can read both keys,
change the program, access raw storage or roll back the guard machine.

The isolated owner retains signed requests and service positions and configures
guard and witness clients internally. Its local authenticated Unix exchange is
specified separately. A remote relay, ownership transfer for existing stores,
independent operators and protected monotone storage remain launch gates.
