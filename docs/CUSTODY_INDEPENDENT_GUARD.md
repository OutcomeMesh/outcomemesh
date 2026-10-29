# Independent custody choice guard

Status: experimental, opt-in extension of protected Plan5. No consensus or
mainnet activation. Existing unguarded profiles do not gain clone protection.

The signed deployment can now require a fresh external guard key. Both gateway
services and the original admission, execution and Serve witnesses need a guard
seal in addition to their own signatures. Verifiers derive the guard requirement
from the five-party deployment and its derived scope. A caller cannot remove the
seal, substitute a guard key or provide an old-format quorum to disable it.

## What is protected

An external, non-rolled-back guard retains one choice for each tuple:

| Operation | Namespace | Slot | Choice |
| --- | --- | --- | --- |
| Admission witness | Original admission genesis ID | Expected admission sequence | Complete signed entry ID |
| Execution / Serve witness | Full derived scope ID | Expected command sequence | Complete signed command ID |
| Gateway effect | Job scope ID | Execute, Accept, ServeA or ServeB | Hash of the complete signed legacy effect |

The tuple also contains the subject public key and operation family. Expected
head, proposed choice and caller-selected nonce are **not** slot components:
competing branches at the same position must collide. The effect choice binds
its deployment, full admission binding, artifact, original source position,
service signer and checked time. Admission prefixes in guarded jobs must use the
same exact deployment for every certificate, starting at sequence zero of that
imported genesis. There is no implicit upgrade of an already used unguarded
admission history. The prior imported/retired source remains the separately
reviewed initial trust anchor; registry votes are not retroactively guarded.

A copied subject key and a reset or copied local journal can still submit a
request. Until explicit subject revocation, the external guard returns the previously
selected seal only for the identical request, and refuses another choice. A copied service signature alone
is insufficient for Result5, Receipt5 or either Serve receipt. A copied witness
quorum alone is insufficient for a guarded admission, execution or Serve scope.

This is acceptance safety, not identity discovery. A malicious copy can win the
first valid choice, consume the finite guard budget, or deny availability. The
guard does not validate arbitrary execution semantics itself; complete artifact
verification remains mandatory. It cannot stop someone reading archive bytes
already copied to their own machine, or prevent a malicious host performing an
unaccepted physical action outside this runtime. Status observations, candidate
replies and outer gateway cursors are not independently sealed by this adapter.
The guard does not mirror the gateway's global revocation state. A local Revoke
alone is not independent revocation of a leaked service key. Use the external
subject revocation below first, retaining its signed receipt. Legacy guard roots
without a revocation authority require freezing the entire external guard. Safe
key replacement remains separate work; never rely on a restored local revocation
flag to exclude a malicious copy.

## External trust boundary

The guard's private key, original journal and independently retained startup
cursor must remain outside all protected subjects' backups and control domains.
The software store is not an HSM. Copying its own private key and state together
can defeat this construction. Ordinary placement replacement, live journal
rollback and stale startup cursors are detected; a privileged clone of the entire
trusted environment is not. A new guard key cannot replace the pinned old key
without a new explicitly authorized deployment; that is not a recovery action.

This first adapter uses one external guard key per deployment. It is a shared
safety and availability dependency, not four independently operated guard
services or a decentralized monotone-signing quorum. Separate operators,
non-exportable keys, monotone storage and independent review remain production
gates. Two servers managed by one operator do not satisfy those gates.

## Durable service and transport

`node/custodyguard` generates a fresh Ed25519 key and fixes a sorted roster of at
most 32 subject keys and a lifetime limit of at most 4,096 choices. Private roots
are exclusive and permission checked. Each complete authenticated request is
published without overwrite, fsynced and its directory synced before any seal is
returned. Partial records, duplicate slots, gaps and changed files block opening;
there is no repair, truncate, delete, reset, eviction or automatic re-enrollment.
Exact choice retries remain available after capacity is exhausted unless that
subject has been revoked. A configured revoker adds one reserved permanent
revocation record per subject; ordinary choices cannot consume these slots.

Open requires the exact retained identity and sequence/head. Recovery permits
only the supplied position itself or one additional, identical retained request.
A stale cursor without that request does not adopt the current tip. A failed
write poisons the live store. Cancellation or a lost response does not undo a
durable choice. Observer output contains the public request and current cursor;
retain it outside the guard root, and retain exact attempts before sending them.
Do not infer a new startup cursor by scanning a suspect backup.

The HTTP endpoint is `/outcomemesh/custody-guard/1`. Requests are fixed 177-byte
subject-signed objects; replies are 64-byte guard seals. Clients verify the pinned
key and reconstruct the tuple; they do not follow redirects, use environment
proxies or automatically repeat attempts. The daemon bounds connections (16),
active requests (8), headers, bodies and deadlines. Request EOF precedes choice
selection. The native listener is HTTP; use a private network or an independently
configured TLS terminator for confidentiality and network abuse resistance.
Signatures authenticate the public protocol, not the transport address.

## Reviewed CLI workflow

All commands below default to review. Execution requires the displayed exact
`--expected-review-id` and `--mode run`; changed inputs or endpoints change the
review. Reviews neither open owner roots, load signing keys nor contact services.

1. Create the independent guard with `omd work-archive-custody-guard --action
   create --root <private-root> --config <roster.json> --out <identity.json>`.
   Config contains `Subjects` (strictly sorted 32-byte public keys), `Limit`, and
   optionally `Revoker`, a separate offline public key. JSON public keys are
   arrays of 32 byte values. The revoker must differ from all subjects and the
   guard. Keep its private seed outside the guard and participant machines.
   Retain the public identity and initial `Position` (`Sequence: 0`, zero `Head`)
   outside that root. Never ship the generated private key to a participant.
2. Prepare a fresh profile-5 deployment with the existing profile-5 CLI and
   `--guard-key <hex-public-key>`. All five endorsements bind this selection.
   Configure both original gateways through the existing execution setup.
3. Start the guard with `--action serve --identity <identity.json> --position
   <retained-position.json> --root <original-root> --listen <explicit-IP:port>`.
   A lost response may additionally select `--attempt <exact-signed-request>`
   or `--revoke-attempt <exact-signed-revocation>`, never both.
   Preserve the public cursor/request log on a separate machine.
4. Add `--guard-url <http(s)://IP:port>` to gateway `--action serve`, original
   admission `--action witness-vote`, and witness server/vote actions. The URL
   chooses delivery; the signed deployment/scope chooses the guard key. Reopening
   a process requires configuring the client again. Missing configuration refuses
   guarded operations. Raw callers cannot bypass mandatory proof verification.

The library equivalents are `Store.Create/Open`, `guardwire.Obtain` and the
`SetGuard` adapters. Original local intent, session, source and witness locks
remain mandatory. An external outage after an irreversible action may leave an
unknown outcome. Exact existing recovery may obtain the same seal; it must never
repeat execution, synthesize a missing session result or refund pending work.

## Permanent subject revocation

New guard roots can pin a separate offline `Revoker`. Its signed command names
one listed subject, the exact guard identity (public key, original RootID and
immutable ConfigID), and a nonzero incident evidence ID. It does not trust a
caller clock or require the current global sequence: a busy compromised signer
cannot invalidate the command by advancing unrelated choices.

The guard serializes revocation with choice selection, persists the command in
the original journal, then returns a signed receipt. From that point it refuses
all new seals for the subject across admission, execution, Serve and service
effects, including exact retries and newly created local roots/scopes. Another
subject can continue. A second, different revocation command for the same key is
refused; exact retransmission returns the byte-identical original receipt even
after other events or a cold restart. There is no un-revoke operation.

Already issued seals and quorum certificates remain valid historical evidence.
A choice serialized before revocation can finish its network delivery afterwards.
This mechanism prevents new guard signatures after durable revocation; it does
not recall previously signed artifacts or prove that an underlying action never
ran. In the real profile-5 test, execution consumes the session and records source
evidence, then the revoked service cannot obtain its result seal. The job remains
spent=2, pending=2 across restart; no result is fabricated, source record changed,
execution repeated or allowance refunded. Operator settlement/key replacement is
not automated by this mechanism.

The revocation request is 200 bytes; its separate HTTP endpoint is
`/outcomemesh/custody-guard/revoke/1`, with a 340-byte signed receipt. Both require
complete EOF and use the same connection/request/deadline bounds as choices.
The receipt includes the exact signed command and the original preceding cursor.
Its derived `After` cursor is historical, **not** the latest daemon cursor after
other choices. Retain the independently observed current cursor separately. A
lost reply or failed output publication is unresolved until exact retransmission
or inspection; do not create a replacement command with a different reason.

Use `omd work-archive-custody-guard-revoke` with these public inputs on every action:
`--identity <identity.json> --config <roster.json>`. Review first, then repeat the
same invocation with `--mode run --expected-review-id <displayed-ID>`:

1. On the offline authority machine: `--action sign --subject <hex-public-key>
   --reason-id <incident-hash> --key <private-32-raw-byte-seed> --out <revoke.bin>`.
   The reviewed public authority must match the loaded private seed. Review does
   not open that seed; it may be absent during review.
2. On the delivery machine: `--action send --request <revoke.bin> --guard-url
   <http(s)://IP:port> --out <receipt.bin>`. Retain the exact command before sending.
   The response must bind the independently retained identity, key and command.
3. Offline inspection: `--action inspect --request <revoke.bin> --receipt
   <receipt.bin> --out <report.json>`. This verifies both signatures and records
   the original before/after cursors and incident ID; it contacts no service.

Outputs must be fresh and cannot alias inputs or the private seed. Review binds
all public file contents, paths, destination and endpoint; it opens no private
root, loads no seed and contacts no service. The serve command logs a public
`Revocation` plus current `Position` after durable application. Cold recovery
requires the retained original identity/cursor and at most one exact signed
`--revoke-attempt`; partial records or additional unknown events stay blocked.

Config remains immutable. An omitted/zero revoker preserves legacy ConfigID
bytes and does not enable revocation on an old root. Do not edit its config,
recreate it, move the subject to an unguarded policy, or substitute a new guard
to regain availability. Old binaries reject revocation-enabled config and new
records; mixed-version failover must not reset a root.

## Compatibility and validation

Guarded encodings use new magic tags inside the existing experimental profile:
`OMCGDG01` (deployment), `OMCGEFG1` (effect), `OMCFSG01` (scope),
`OMCFVG01` / `OMCFQG01` (vote/quorum), `OMCVAVG1` / `OMCVAQG1`
(admission vote/quorum), and `OMCGREQ1` (guard request). Unguarded canonical
bytes and vectors remain unchanged. Old binaries reject the new encodings;
upgrading binaries alone does not enroll an existing deployment.

The tests cover a killed/restarted standalone guard process, cloned signing keys with empty witness stores, concurrent
competing requests, cold exact recovery, dropped replies, partial evidence,
capacity, foreign keys, invalid framing, stripped/substituted seals, deployment
downgrade, guarded canonical vectors and decoder fuzzing. The real archive
lifecycle test requires 19 retained choices: six admission votes, nine execution/
Serve votes and four service effects, closing at spent=2, pending=0, source=1.
[The validation record](evidence/custody-independent-guard-20261029.json) lists
commands, results and explicit exclusions. These are controlled tests, not independent-operator or physical-failure
acceptance. Readiness remains approximately 44/100.

The [revocation validation record](evidence/custody-guard-revocation-20261029.json)
adds offline CLI review/sign/send/inspect, reserved capacity, unrelated-subject
progress, concurrent revoke/choose, framing/lost replies, partial/tampered history,
process kill after fsync, cold exact receipts, cloned witness/admission keys and
a real profile-5 unsealed-effect hold. No new WAN or independent operator campaign
is claimed by these local tests.
