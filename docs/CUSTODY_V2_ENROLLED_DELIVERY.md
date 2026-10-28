# Delivery of complete registry-bound custody proofs

Status: experimental profile-4 proof transport. Receiving a packet retains
historical evidence; execution remains a separate explicit enrolled-owner action.
There is no consensus activation, legacy cutover or protected physical issuer.

## Exact proof identity

The format-4 receiver descriptor fixes the exact ContextID, ScopeID,
AdmissionBinding ID, Registry EnrollmentBinding ID, sender and recipient peer
identities, salted placement commitment, random nonce, receipt role and public
key. The registry proof ID is independently selected before receiving anything.
An incoming packet cannot choose or replace the receiver's descriptor.

A format-4 delivery contains the complete descriptor, signed Context, complete
admission prefix and complete registry EnrollmentBinding. Both proofs are checked
with production validators against the same assignment/job. Hashes alone, weak
quorums, corrupt signatures, a different registry descriptor and a different valid
sufficient subset under the old proof pin are refused.

Registry selection fixes assignment-level keys before jobs exist. The actual
EnrollmentBinding verifier additionally rejects a later job's client transport
key if it equals the registry issuer or any registry witness. This check applies
to both the enrolled execution owners and complete proof delivery.

| Object | Magic/version | Encoded size | ID domain |
| --- | --- | --- | --- |
| Receiver descriptor | `OMCVDEN4`, u16 4 | 299 bytes | `OMESH/custody/v4/enrolled/proof-delivery/enrollment/id` |
| Complete delivery | `OMCVDLV4`, u16 4 | at most 8 MiB total | `OMESH/custody/v4/enrolled/proof-delivery/id` |
| Retention receipt | `OMCVDAR4`, u16 4 | 267 bytes | `OMESH/custody/v4/enrolled/proof-delivery/receipt/id` |

The receipt signs its body under
`OMESH/custody/v4/enrolled/proof-delivery/receipt/signature`. It fixes DeliveryID,
receiver descriptor ID, ContextID, ScopeID, AdmissionBinding ID, registry proof ID
and role. DeliveryID also commits both authenticated peers and full proof bytes.
There is no timestamp, refreshed expiry, latest-head claim or execution grant.

The combined bound includes both proofs and the Context. Admission certificates
are preflighted before constructing a large operator-channel prefix. A proof
that does not fit the 8 MiB envelope stays on the explicit file channel; there
is no implicit truncation, hash-only fallback or chunked delivery protocol.

## Original inbox and outbox

Explicit `Create/OpenEnrolledAdmissionInbox` and
`Create/OpenEnrolledAdmissionOutbox` APIs select the new format. The corresponding
legacy APIs continue to require delivery 2 / policy 3 and refuse profile 4.

Inbox creation pins public IDs against the original source and local placement.
It does not receive a proof, open archive chunks, create an execution owner or
prepare a volatile session. The original source decision remains held while
intake is open. Intake must close before explicitly opening its execution owner.

An inbox retains the complete exact packet before signing, and the exact receipt
before returning success. Its ready marker is `OMCVIDY4` plus descriptor ID. An
outbox retains the complete exact packet and route before dispatch; its ready
marker is `OMCVODY4` plus DeliveryID. Both retain permanent locks, original path/
inode/source checks and bounded immutable files. Local copies, moves and changed
placement are refused by those checks; they do not supply VM/key rollback fencing.

An uncertain write poisons the live handle. Cold open validates and synchronizes
existing evidence without sending, signing missing acknowledgements or appending
a source. Explicit retry accepts the exact packet. A retained receipt remains
historical after source advancement; proof without a receipt still requires the
original predecessor before Receive may finish. A missing sender receipt means
unresolved even when the peer may already have retained the proof.

## Separate authenticated protocol

The negotiated protocol is
`/outcomemesh/custody/v4/enrollment-delivery`. The existing profile-3 protocol is
unchanged. Explicit new service/sender APIs select format 4; neither negotiates a
fallback to the old protocol. Proof intake exposes no execution/control protocol.

The pinned sender is authenticated before bounded packet parsing. Per-host
admission permits at most two active handlers and 32 accepted requests per minute.
A complete request frame and EOF precede Receive. The sender requires a complete
role-signed matching receipt, reply EOF and successful stream close before its
outbox confirms. Partial/trailing replies, wrong peers and uncertain close leave
that exact intent unresolved. A cached confirmed receipt needs no network or
sender key load.

## Reviewed CLI

Command: `omd work-archive-custody-v2-enrolled-delivery`. Every action defaults to
public review without loading seeds or opening stores. Run unchanged arguments
with `--mode run --expected-review-id <id>`.

All actions take exact context/scope, `--binding-id` and the independent
`--registry-enrollment-id`. The latter refers to the registry proof; ordinary
`--enrollment-id` refers to the separately pinned receiver descriptor.

1. `inbox-create` chooses an absent private root, authority/target role, original
   source paths and concrete recipient peer. It emits the random descriptor.
   `inbox-enrollment` exports a lost descriptor as a candidate for independent
   review; it never automatically adopts a replacement pin.
2. `delivery` takes both full proof files through `--binding` and
   `--registry-enrollment`, plus the pinned receiver descriptor. It prepares an
   immutable public packet without opening stores.
3. `outbox-create` persists that packet and exact reviewed direct QUIC route.
   `outbox-send` performs one bounded attempt; `outbox-receipt` reads the retained
   confirmation. Retries use the same packet, route and original store.
4. `inbox-serve` owns intake until its handlers drain. `inbox-receipt` reads the
   retained acknowledgement. `inbox-binding` and `inbox-registry-enrollment`
   export their respective complete retained proof only after receipt retention.
5. Close intake, independently verify both exported proof IDs, and use those
   actual files with `work-archive-custody-v2-enrolled` to create/open the target
   or acceptor. Execution, original-session consumption, Serve and lifetime
   accounting still enforce their own gates.

All outputs are fresh immutable files outside original roots/sources; duplicate
or unused selectors fail. Review binds full public bytes, proof IDs, paths,
placement metadata and route. No receive/send retry resets an unknown slot,
refunds work or replaces a registry/admission history.

## Compatibility and launch limits

Format-2 descriptor/packet/receipt bytes and domains remain unchanged. New
fields are forbidden on old packets. Existing inbox/outbox histories cannot be
adopted through a new format. The new client-role separation is an explicit
profile-4 restriction; it does not alter policies 2/3 or their consensus bytes.
A previously prepared profile-4 context that reuses a registry signing key as
its client transport is now refused. Its old evidence must remain retained;
there is no automatic root replacement or new allowance.

Full proof delivery does not establish physical resource uniqueness, exclusion
of old grants, independent protected signing domains or the legacy accounting
bridge. A copied raw key outside the protected execution model remains outside
the honest-owner guarantee. Mainnet, external review and sustained adversarial
public-testnet gates remain open; production readiness stays **44/100**.

## Reproduction and evidence

[Joint acceptance](evidence/custody-v2-enrolled-delivery-20261028.json) records
both host kernels, original witness positions, exact proofs/receipts, source
counters, held accounting and process cleanup. Its
[public corpus](evidence/custody-v2-enrolled-delivery-public-20261028.json) contains
27 files, including both complete packets and 12 original/cold receipts. These
are historical fixture proofs, not live permissions or real-value endorsements.

```sh
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-all
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 go test -tags=integration ./cmd/omd -run '^TestProcessCustodyV2EnrolledDeliveryColdStoresAndLostOutput$' -count=1 -timeout=2m
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 go test ./node/custodyv2 -run '^$' -fuzz '^FuzzEnrolledDeliveryPublicPackets$' -fuzztime=5s
```

Extract the public archive into a separate directory and set
`OUTCOMEMESH_ENROLLED_PUBLIC_CORPUS` to its absolute path. Then run
`go test -tags=integration ./cmd/omd -run '^TestVerifyCustodyV2EnrolledDeliveryPublicEvidence$' -count=1 -v`
with Go 1.26.7 to check the complete proofs and all 12 receipt copies without
opening original execution owners.

The full CLI pipeline performs many signatures under the race detector. Its
fresh fixture chooses the existing protocol maximum of 600 seconds before any
assignment, Plan or proof is signed; the 60-second default fixtures are unchanged.
An expired request remains refused. Native/WAN production code is identical to
the final production sources; the later test-only fixture change is identified
separately in the report instead of claiming identical full source snapshots.

The new profile-4 synthetic stream test uses the existing 10-second protocol
budget for verifying both complete proofs under the race detector. The older
profile-3 synthetic stream test retains its one-second budget. Existing
production network bounds and Go test process timeouts are unchanged.

Final validation passes: seven race groups, 14 new Go tests including the public
verifier, fresh process integration, integration vet, 60 helper tests and six
decoder fuzz runs totaling 459,167 executions. Three deterministic vectors pin
the new receiver, packet and receipt IDs. Both host binaries match; task native
processes and Python supervisors are zero, with both task connections closed.
