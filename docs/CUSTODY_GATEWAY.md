# Isolated custody source gateway

Status: experimental source/version service with a Linux user boundary. The
service owns a newly generated key and performs original sealed-source inspection
and manifest-bound archive reads. The separate [explicit Plan5
adapter](CUSTODY_PROFILE5_EXECUTION.md) now adds real protected execution and
closure after complete deployment endorsement and private role-key installation.
Base-only gateways and raw profile-5 constructors remain non-executing. A generic
gateway response is historical operation evidence, never a future execution grant.

## Boundary and deployment

An old participant process may retain its old keys, requests and participant
backup. It must have a different, unprivileged Linux UID, without service/root
credentials, supplementary access, host administration, capabilities or access to
the service machine's backup, memory or private directories. Its current ACL key
can request an operation through the Unix socket. It cannot obtain the fresh
service signing key or open the live source/object directories directly.

The service UID owns the original sealed source, retired A authority or sealed B
workers, original object directory, and the new 0700 gateway root. Keys and
retained files are 0600. Canonical ancestors must resist participant replacement;
root-owned sticky temporary directories are permitted. Private files reject
symlinks and extra hard links. The root identity pins canonical paths, device,
inode, UID, mode and permanent key/lock change time. These metadata checks detect
ordinary replacement; they are **not** hardware attestation or an uncloneable key.

Do not change ownership or move an already observed source: its signed original
SourceLocation commits those properties. A production deployment should establish
the dedicated owner UID before source enrollment. The native tests launch a root
service and UID 65534 participant on fresh fixtures to test the kernel boundary;
they do not certify root as an untrusted or independently protected service host.

The socket belongs outside private roots, in an owner/root-controlled traversable
directory. Its 0666 mode permits connection attempts. Linux `SO_PEERCRED` must
match the descriptor's distinct, nonzero ParticipantUID **before** the server reads
a frame. A valid signed ACL request is additionally required. The client checks
the kernel server UID and the pinned gateway public key. At most eight connections
are served, with bounded frames and ten-second connection/operation deadlines.
macOS supports offline artifacts and owner tests; live service/client operations
fail closed because this implementation requires Linux peer credentials.

A trusted service administrator or a full service-host disk/VM/memory clone can
cross this boundary. Independently protected key storage, external monotone state,
independent deployment, backup policy and audit remain required against that
threat. Existing bytes already copied by a participant cannot be erased remotely.
Old offline signatures and arbitrary old verifiers are not retroactively revoked.

## Signed descriptor and requests

The complete selected profile-5 genesis, enrollment certificate and original source
pins are retained in the private configuration. Issuer consent signs a descriptor
fixing the new root/key, source handoff ID, genesis ID/full descriptor ID,
enrollment object ID, original object-directory identity, service/participant UIDs,
sorted ACL of one to eight keys and a lifetime event limit of 2–256. The issuer
must be the selected resource issuer. Clients independently retain the exact signed
descriptor ID; accepting any descriptor offered by a peer would lose that pin.
The service key is generated locally with the cryptographic random source and
has no import, export, arbitrary-sign, key-replacement or reset RPC.

Every request includes that descriptor ID, a fresh nonzero nonce and an exact
externally retained before-position `(Sequence, Head)`. All three request kinds
have separate typed semantics under the gateway domain:

| Request | Authorized signer | Effect |
| --- | --- | --- |
| Inspect | An explicit ACL key | Inspect the original sealed source; return its exact handoff bytes. |
| ReadChunk | An explicit ACL key | B only: return one original chunk named in the imported manifest. |
| Revoke | Resource issuer | Irreversibly revoke all subsequent source reads/inspections. |

No arbitrary file path, supplied data to sign, wall-clock renewal, source append,
new admission, spending refund, source reset or roster replacement is accepted.
ReadChunk holds the original retirement/worker and source decision guards across
manifest lookup and actual object validation/read. The owner mutex excludes
revocation across the entire operation, signing and durable response publication.
Source/object placement is checked again before signing. Revoke skips source
replay, so a broken source proof does not prevent disabling access. Original
owner, key, configuration and object-directory placement checks remain mandatory;
a missing/replaced object root blocks the service, including revocation, until
those original prerequisites are available. It cannot authorize reads meanwhile.

## Durable positions, retry and unknown outcomes

A response contains the complete signed request, selected source ID, bounded data
and gateway signature. Its next sequence is `Before.Sequence + 1`; its head is a
domain-separated hash of the unsigned response, including the request's previous
head and nonce. Canonical encodings, signatures and authorization are checked on
complete cold replay. Response data is at most 64 MiB. The journal is at most
256 MiB and the signed event limit. Non-revocation operations reserve a final
revocation event/byte allowance before accessing the object store.

Each response is written exclusively to its sequence-named file, synchronized and
its parent synchronized **before** it can leave the service. A failed publication
poisons the live owner. Named partial/corrupt evidence is retained and blocks
reopen; no truncation, deletion, automatic reconstruction or forced repair exists.
A pre-publication refusal consumes no event. Disk exhaustion or torn writes may
therefore require operator investigation; these tests do not certify physical
power-loss recovery or storage lifetime.

While active, only an exact duplicate of the current tip request returns its
identical retained response without rereading the object, signing again or spending
another event. A different nonce/request at the old slot refuses. Clients sharing
one descriptor must coordinate this single cursor and retain verified replies
externally; the service does not solve concurrent-client cursor discovery by
automatically trusting the latest local file. After Revoke,
even old exact read retries refuse; only the exact retained Revoke retry succeeds.
An old signed report still verifies as historical evidence. It cannot answer a new
nonce or grant a future action.

Startup requires the exact independent descriptor ID and position. To resolve a
lost response, the caller may additionally supply the **exact signed attempted
request** at that before-position. Open accepts either no new event or exactly
that one committed event, never another request, a longer suffix or arbitrary
latest state. Public response inspection can produce a candidate position for
explicit external review/retention; it never silently changes startup pins.

Socket names are retained after stop/crash. Startup never unlinks an existing
socket. Explicit cleanup requires its reviewed exact identity, the original
exclusive owner lock, connection refusal and a second identity check. Cleanup
removes only that socket; it cannot remove/reset any owner, key, journal or lock.

## Reviewed CLI workflow

`omd work-archive-custody-gateway` defaults to `--mode review`. Every run repeats
the same inputs with `--mode run --expected-review-id <review_id>`. Public input
hashes, canonical selectors, output and offline key **path** are bound to that
review. Review loads no private signing key and opens no exclusive source owner.
Outputs must be fresh, outside all supplied owner/source roots, and distinct from
input/key files. Signing keys are offline hexadecimal Ed25519 seeds; the daemon
never takes those issuer/client seeds.

JSON preparation uses the exported Go field names. Config contains `Genesis` and
`Enrollment` as base64 canonical bytes, the four `Pins` hashes, original
`SourceLocation`, canonical `Objects` path (empty for A) and, at configure time,
the base64 signed `Descriptor`. Hashes and fixed-size public keys in these JSON
plans use arrays of bytes, as in the existing custody preparation files. Binary
public artifacts use the bounded canonical wire encodings, not JSON.

1. `identity-create --root <fresh-private-root> --out <public-identity.json>`
   creates the key in place, publishes identity readiness last, and returns only
   the public identity. `identity-public` can reread its metadata. Existing or
   partially created roots are never recreated.
2. Prepare a Config JSON with the complete selected evidence, original source
   pins/paths and original object root. Run `descriptor-prepare --root <root>
   --input <config.json> --participant-uid <separate-uid> --clients <hex-key,...>
   --event-limit <2..256> --out <unsigned-descriptor.json>`. This derives public
   IDs without source-owner acquisition or service-key loading.
3. `descriptor-sign --input <unsigned-descriptor.json> --key <issuer.seed>
   --out <descriptor>` produces the issuer consent. Distribute its exact ID and
   complete bytes through an independently authenticated channel.
4. Put those descriptor bytes in Config. `configure --root <root>
   --input <config.json> --out <configured.json>` validates the complete selection,
   original sealed source and existing objects, then publishes configured
   readiness last. It never creates or copies a source/object store.
5. Retain an independent initial Position JSON `{ "Sequence": 0, "Head":
   [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] }`.
   `serve --root <root> --descriptor <descriptor> --descriptor-id <pin>
   --position <position.json> --socket <public-socket>` starts the Linux daemon.
   It reports the socket identity and current position; SIGTERM stops and drains
   operations. Keep it running as the service UID.
6. Prepare Request JSON with descriptor ID, exact before-position, fresh nonce,
   kind (1/2/3), chunk ID (only kind 2). `request-sign --input <request.json>
   --key <client.seed> --out <request>` signs offline. Actor is derived from the
   seed; issuer seed is required for kind 3. The participant gets only the signed
   request, public descriptor, socket and separate output directory.
7. As ParticipantUID: `call --descriptor <descriptor> --descriptor-id <pin>
   --request <request> --socket <socket> --out <response>`. Verify/retain the exact
   response before advancing the external client position. A disconnect means
   unknown outcome: retry the same request; do not create a fresh nonce at its slot.
8. `response-inspect --descriptor <descriptor> --descriptor-id <pin>
   --response <response> --out <candidate-position.json>` verifies all signatures
   and emits position, request, source ID, data length and revocation status, with
   `ExecutionGranted=false`. This is an explicit inspection, not an automatic
   independent-pin update. For a lost response after restart, add
   `--request <exact-attempt>` to serve with the original before-position.
9. After stopping the owner, `cleanup-socket --root <root> --socket <socket>
   --socket-id <reviewed-id>` removes only the exact stale socket. Reopening still
   requires the original key/root/configuration and independent state pins.

## Compatibility and next gate

Gateway v1 has separate descriptor/request/response magic and signing/hash domains.
It changes no consensus, block, coin, old custody proof or existing V2 packet
encoding. Existing profile-5 Target/Acceptor constructors still reject execution.
No historical source pair or gateway response enables them implicitly.

Next bind actual imported job execution, witness admission, target reads,
acceptance signatures and closure to this protected service, with explicit
unknown-outcome handling and original accounting/source continuity. Both A/B
protected domains, independently operated deployment, external review, HSM/VM
rollback defenses and end-to-end faults remain activation work. This component
alone does not close the production copy-fencing criterion.

[Acceptance evidence](evidence/custody-gateway-20261029.json) records frozen source
inventory, local/race/process/fuzz checks and the same native binaries tested on
two Linux kernels. Test helpers' faults and UID-dropping probes are not exposed
through the production CLI or RPC.


## Runtime extension

The original descriptor and 241-byte signed request body remain compatible.
Runtime kind 4 commits a complete typed payload; `OMCGXRQ5` frames it with that
request. A runtime payload is at most 16 MiB. The same UID, local revocation,
exact cursor, bounded connection and durable response checks apply. An immutable
runtime intent additionally blocks replacement of an unknown operation. Public
call review reports the typed operation and scope/binding/deployment IDs.
Protected result/acceptance/Serve artifacts have their own verification rules;
reading an outer historical response alone is never live permission.
See the [complete contract](CUSTODY_PROFILE5_EXECUTION.md) for explicit setup,
source continuation, keys, limits and failure behavior. The original base-only
workflow above remains usable without configuring execution.


## Optional profile-5 network relay

[Gateway relay v5](CUSTODY_PROFILE5_WAN.md) is a separate ParticipantUID process
with an allowlisted, independently peer-pinned QUIC endpoint. It forwards only
complete signed Runtime envelopes over the original Unix socket. The owner stays
local and retains all current source/version, key, cursor and recovery checks.
Raw reads, local inspection and permanent revocation are not exposed by this
network endpoint. Transport authentication never replaces gateway signatures.
