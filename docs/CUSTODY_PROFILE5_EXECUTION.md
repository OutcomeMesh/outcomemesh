# Protected profile-5 execution

Status: experimental execution inside an explicitly configured isolated gateway.
This extends the [source/version service](CUSTODY_GATEWAY.md), not consensus or
mainnet activation. Ordinary profile-5 Target/Acceptor constructors still refuse.
An accounting-only imported Plan2 remains historical/accounting preparation and
cannot execute through this adapter. A protected job uses a separately signed
Plan5 and the original imported admission history.

## One selected deployment, two original sources

A Deployment5 contains both complete issuer-signed gateway descriptors, exact
imported genesis/full descriptor/enrollment IDs, import proposal ID, original
source-pair ID, old retention floor, successor authority and control public keys.
Its choice ID hashes the unsigned body. Complete activation requires five
separate endorsements: issuer, successor authority, successor control, gateway A
and gateway B. Partial drafts are canonical preparation only and never pass the
complete verification required by Plan5 or execution configuration.

Each gateway checks its exact original selected source under the retired
coordinator or sealed worker/source guards before endorsing. It permanently
retains one deployment choice before emitting that endorsement. A different
peer, source, enrollment, floor or role changes that choice; no replace/reset API
exists. Installation requires the complete five endorsements and the exact
retained choice. The complete selection and original-source evidence remain in
the private base configuration. Original admission witnesses additionally compare
Plan5's enrollment ID with their own retained selection proof during vote,
commit and cold replay. Source/assignment/accounting namespaces are not replaced.

Plan5 signs the entire complete deployment in a separate magic and signature/ID
domain. Its ordinary audit/Serve consumers and successor authority still sign the
job. Scope derivation commits the Plan5 ID, thus both gateway identities. A
historical descriptor or endorsement alone grants no execution. Every operation
also checks its local gateway's current exact cursor, private configuration/key
files, revocation state, complete admitted prefix and private job state.

## Actual archive execution and protected continuation

The original A/B journals remain sealed and unchanged. A private append-only
continuation under `execution/jobs/<scope>/entry` starts from the verified import's
sequence/head/current receipt and retention floor. It does not copy the old
journal, initialize another ordinary journal, rewrite an accepted entry or
refresh a receipt during installation. Replay verifies the original predecessor
and each continuation record in sequence. Different, duplicate, missing or
incompatible predecessors refuse. The current protected source is this retained
prefix plus its continuation, not an unsigned snapshot file.

For one admitted job:

1. B validates the complete admission/enrollment/deployment and exact source
   predecessor. Prepare generates a fresh volatile session private key inside B;
   only its public candidate and control-signed Claim leave the service. The
   session key is never stored or imported from a caller.
2. The original mandatory witness scope must select that exact Claim. B checks
   the full quorum against its own live candidate and full retained admission.
3. B durably retains the exact gateway intent and consumes the session **before**
   opening or reading current archive objects. It then answers the real challenge
   under the original retired/worker/source guards, signs the custody proof and
   renewed receipt, and stores the exact continuation entry.
4. A completed core result needs both the winning session signature and a fresh
   B service Effect5. The effect binds deployment, scope, exact admission entry
   and complete binding IDs, completed core artifact, resulting source position
   and checked time. Result5 cannot be reduced to a bare replica/control proof.
5. B's result-command operation signs only the exact retained completed result
   against the supplied original Claim/Unknown prefix. It reads no objects and
   creates no session. The original job witnesses select the Result5 ID.
6. A verifies that complete result quorum, fresh B service effect and the same
   complete admission binding, checks current freshness, and retains acceptance
   pending before changing its continuation. It verifies the original A source
   before source acceptance and again before signing. Receipt5 includes the
   successor authority signature and a separate fresh A service effect.

The service's own wall clock governs freshness/proof time. A request timestamp
is reviewed request data, not permission to rewind the service's clock. Exact
historical retries retain the original proof/acceptance time.

## Serve and original admission closure

Fulfilled and original-quorum Unclaimed Serve outcomes use Plan5-specific
proposals. Fulfilled evidence contains the full protected result bundle and
Receipt5. Unclaimed requires the original execution-scope quorum excluding Claim;
it cannot relabel an unknown, consumed or executed session as absent work.

A applies the complete Serve certificate under its current service gate. B
requires that exact protected A application as parent before applying its own.
Both ServeReceipt5 artifacts contain ordinary role signatures plus fresh service
effects bound to the same job/deployment/admission. The retention deadline is at
least the deployment's inherited floor as well as the verified proposal deadline.
Archive deletion is never authorized by these receipts.

AdmissionClosure5 retains the complete Serve certificate and both protected
applications. The original imported witnesses close the same active context:
pending can fall from two to zero, spent never falls, and the accepted source
position/receipt/maximum retention carry forward. Bare role-only results,
acceptances, parents or closure receipts cannot close a protected Plan5 job.
Historical accounting-only Plan2 encodings remain unchanged and are not promoted.

## Failure, retry and revocation

Every runtime request is a typed `OMCGCMD5` payload committed by the authenticated
gateway request. `OMCGXRQ5` carries that request and its full payload; the ordinary
241-byte request body remains unchanged. A bare Runtime-kind request without its
bound payload fails. No arbitrary path, caller-chosen source state, imported
session private key or unrestricted signing callback is exposed.

An immutable sequence-named runtime intent precedes each attempted operation.
The regular gateway response is synchronized before output, with the same exact
cursor/nonce and tip-only retry rules as the base service. An interrupted intent
cannot be replaced by another request or fresh nonce at that slot. Cold open
requires the exact attempted signed request when a pending intent exists. A
committed response is replayed byte for byte without redoing the effect.

- If consumption exists without a completed result, losing the volatile key
  prevents reexecution. Old copied keys, journals, a timeout or an empty new root
  cannot regenerate it. The unknown job retains its two pending units and spent
  allowance. No synthetic successful result or Unclaimed closure is produced.
- If A source acceptance is retained but its receipt is absent, the exact attempt
  may finish from its complete retained pending bundle and original checked time.
  Current proof freshness is checked again before new acceptance. It does not
  append another source entry or mint a later proof time.
- Completed results survive process death. Result-command production and exact
  reply recovery do not require recreating the volatile private session.
- Partial/corrupt named evidence remains blocking. No force, reset, file deletion,
  automatic tip adoption or rollback-to-legacy path is added.

Issuer revocation is local and permanent for the named gateway. It also blocks
new runtime operations and old result retries there. A pending intent may be
superseded only by that explicit irreversible revocation; its evidence and job
obligation remain retained. Stopping both sides requires revoking both named
services. A completed B result remains historical evidence; A can accept it only
under A's own current gate and original freshness rules. Revoking B does not erase
a completed effect or release its admission/retention obligation. This is not an
instantaneous atomic revocation protocol across machines.

## Keys, bounds and trust

Execution installation places the selected role keys inside the same private UID
boundary as the fresh service key: replica/control at B and successor authority
at A. External setup seed files must be canonical private files owned by that
service UID; participant processes receive only public signed requests/artifacts.
The fresh service signatures are mandatory even if old role-key copies exist.
The Linux peer-UID and descriptor/key checks are unchanged.

The first adapter accepts at most 8 MiB total manifest object bytes before
consumption, at most 16 MiB per complete runtime payload and at most 256 MiB of
retained runtime configuration/jobs/intents, in addition to the existing bounded
gateway response journal. It conservatively reserves work/recovery space before
acting. Larger workloads refuse, rather than silently falling back to raw V2.
Eight connections and the existing ten-second IPC deadline remain. Large managed
legacy integration cases remain under the existing two-minute process limit;
individual short CLI children retain their fifteen-second limit.

These are logical bounds and tested software behavior. Physical torn writes,
disk exhaustion, long retention, host-root/service-UID compromise or a complete
service-host VM/key clone require further protected deployment and acceptance.
The two-server campaign is controlled by one operator; it is not independent
operators, a new joint WAN cutover, hardware attestation or an external audit.

## Wire and compatibility contract

All integers and byte fields use the existing canonical codec. Trailing bytes,
noncanonical lengths, invalid embedded signatures and nested protected-core
wrappers refuse. The fixed core artifact inside a protected wrapper must have its
ordinary v2 magic/version before decoding begins.

| Record | Encoding / domain |
| --- | --- |
| Deployment5 | `OMCGDEP5`, two length-prefixed complete descriptors, five import/source IDs, retention floor, authority/control keys, then five 64-byte signatures in issuer/authority/control/A/B order; maximum 4096 bytes. Choice ID hashes the unsigned body under `OMESH/custody-gateway/v1/deployment/id`; signatures use `deployment/<role>/sign` under that same gateway prefix. |
| Effect5 | `OMCGEFF5`, kind (1 Execute, 2 Accept, 3 ServeA, 4 ServeB), deployment/scope/admission/binding/artifact IDs, source sequence/head, checked time, signer, signature; exactly 313 bytes. Signature domain is `OMESH/custody-gateway/v1/effect/sign`. |
| Plan5 | `OMCVPLN5`, version 5, existing assignment/consumer/transport/intent/challenge fields, length-prefixed complete Deployment5, ordinary three-role signatures. Maximum 8192 bytes. ID/signature prefix is `OMESH/custody/v5/plan`. |
| Runtime envelope | `OMCGXRQ5`, fixed signed 241-byte request, length-prefixed typed payload. Kind 4 commits `OMESH/custody-gateway/v1/runtime-payload/id`; the other request/signature/cursor rules stay unchanged. |
| Typed command | `OMCGCMD5`, one-byte kind, reviewed timestamp, length-prefixed full admission binding (empty only for Endorse), length-prefixed operation data. Kind order: Endorse, Prepare, Execute, ResultCommand, Accept, ResumeAccept, Serve, ReadResult. Maximum 16 MiB. |
| Protected result / acceptance / Serve application | `OMCVRES5` / `OMCVACK5` / `OMCVSAC5`, one length-prefixed ordinary core artifact and fixed Effect5. Their complete-artifact ID domains are distinct v5 domains; ordinary inner session/role signatures keep their v2 domains. |
| Serve proposal / admission closure | `OMCVSPR5` / `OMCVACL5`; complete protected evidence is retained. The outer witness certificates, context, admission entry and admission certificate formats remain v2 containers committing these new bytes. |

Fixed deterministic aggregate vectors (the order of the component encodings is
retained in the corresponding tests):

- Gateway wire, `OMESH/test/profile5/wire-vector`:
  `0a3f1f6ea4f104151e2699053f6c666fb6c1cee7f3f6ec84e068be3bb364256d`.
- Full job artifacts, `OMESH/test/profile5/artifact-vector`:
  `3afabe12f01ece7a0a8d81eda9ea916fc0635a68a70d9be0f56a6c18e1232f67`.

This is an explicit versioned opt-in for imported jobs, not an in-place rewrite
of existing native or accounting-only profiles. Original byte/signature golden
vectors remain required by the full compatibility suite.

## Reviewed CLI

`omd work-archive-custody-profile5` uses the same review-first procedure: repeat
exactly the reviewed action with `--mode run --expected-review-id <id>`.
Public input hashes, canonical paths, signer path/role, output and public operation
summary are bound to review. `--key` takes a path to a file containing a hex-encoded
32-byte seed, never seed text on the command line. No private seed or exclusive
owner is loaded by review. Fresh output and private-root separation remain required.

| Action | Public input and output |
| --- | --- |
| `deployment` | JSON DeploymentPreparation with canonical Genesis/Enrollment/Pair/A/B byte fields → partial Deployment5. |
| `sign-deployment` | Partial deployment, offline `--key`, `--role issuer/authority/control` → signed partial deployment. Service endorsements are obtained through Runtime Endorse. |
| `command` | JSON Kind/Admission/Data/Now, or Deployment/Pair for Endorse, or Certificate/Parent for Serve → typed command. Byte fields are base64 in JSON. |
| `sign-request` | JSON DescriptorID/Before/Nonce/Payload plus offline proxy seed → signed Runtime envelope. |
| `configure` | Original `--root` and JSON ExecutionSetup containing complete Deployment/Pair plus canonical private role-key **paths** → private ready execution installation. Stop the original daemon first. |
| `extract` | Signed gateway response plus complete `--descriptor` and independent `--descriptor-id` → verified response data. Extraction supplies no future permission. |

Run the existing gateway's `serve` with the original descriptor and independent
position; use its `call --request <runtime-envelope>` from ParticipantUID. The
public review includes the runtime operation and scope/binding/deployment IDs.
After unknown output, retain that exact envelope and use `serve --request
<exact-attempt>` with its original before-position. Stale sockets still require
explicit exact cleanup. Descriptor/roster/key/root replacement is not recovery.

## Verification

Run the heavy suites sequentially on a development machine:

```sh
GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-process
GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-all
```

The full race suite now has eleven disjoint name groups. The custody CLI families
have separate bounded groups; the old eight-case crash-atomicity batch is separated
into three process invocations. Each previous named test remains selected exactly
once. The published record retains the inventory and selector counts, earlier
cumulative-timeout attempts and successful final checks. Per-invocation
caps and the ten-second IPC / fifteen-second short-child limits are unchanged.

Native Linux checks use identical prebuilt binaries on both hosts and require a
root launcher for the distinct UID process scenario; that scenario explicitly
skips on other platforms. The final post-native source change is only the test
schedule in Makefile. Both source inventories are retained, and every Go/module
build input is identical. No native execution result is attributed to different
Go code. Dedicated ten-second fuzz smoke checks cover wire, protected artifacts
and runtime commands; smoke coverage is not an audit or long-duration campaign.

[Evidence](evidence/custody-profile5-20261029.json) records the frozen code, vectors,
parser fuzzing, original-witness accounting, controlled crash/clock/key/cursor
checks, and native Linux process campaigns. Production readiness remains
approximately 44/100 until the weighted launch gates actually close.
