# Retained admission proof delivery

Status: experimental required-profile delivery, durable inbox/outbox, reviewed
CLI and an explicitly enabled authenticated protocol. Delivery moves the exact
public admission binding. Required-owner creation and actual custody execution
remain separate actions.

## What the acknowledgement means

An admission delivery receipt attests that the selected receiver retained the
exact public Context and complete Admit-ending binding in its original enrolled
inbox. It is historical proof-retention evidence. It does not attest the latest
admission head, a live execution session, consumed Claim, completed archive work,
source acceptance, Serve settlement or mainnet activation.

The existing signed policy 3, binding verification, original source predecessor,
volatile winning session, durable consumption and typed result/Serve/accounting
gates remain necessary. Lost delivery output cannot release any pending operation
or archive hold. Delivery does not issue another admission certificate.

## Public formats and independent pins

All three formats have explicit version 2 and distinct domains under
`OMESH/custody/v2/required/admission-delivery/`.

| Artifact | Canonical contents | Bound |
| --- | --- | --- |
| Enrollment, `OMCVDEN2` | Context, job scope, complete binding ID, sender/receiver peer IDs, role, receipt key, opaque placement commitment and random nonce | 267 bytes |
| Delivery, `OMCVDLV2` | Exact enrollment, signed Context and complete admission binding | 8 MiB total |
| Receipt, `OMCVDAR2` | Delivery, enrollment, Context, scope and binding IDs, role and signature | 235 bytes |

The sender is the signed Plan's client transport identity. The target receiver
uses the assignment's signed B transport and control receipt key. The authority
uses its signed authority receipt key and an independently selected transport
peer, because the assignment does not contain an A transport key. The enrollment
ID must be independently reviewed and retained before constructing the delivery
or opening a receiver. Incoming packets cannot select or replace it.

The full binding is replayed from genesis and must end in this exact job's Admit.
Binding identity fixes all canonical bytes, including the chosen valid quorum
subset. A different sufficient subset cannot replace an existing delivery.
The 8 MiB cap is checked before constructing the complete delivery packet.
Larger histories retain the existing bounded operator channel; pagination or
chunking is not implemented by silently weakening proof validation.

The binding decoder also grows its certificate list only from fully decoded
evidence. A declared count alone cannot reserve Context-bearing slots. A
66,874-byte malformed packet declaring 65,538 certificates previously reserved
about 165 MiB before its first invalid certificate; the regression test now
requires refusal with less than 16 MiB allocated. Existing canonical bytes and
IDs remain unchanged.

Receipt signatures are deterministic and domain separated. They contain no
timestamp or refreshed proof age. Exact recovery therefore returns the original
bytes without inventing a new observation time.

## Original inbox

`CreateAdmissionInbox` enrolls against an independently chosen Context, scope,
binding ID, role, receiver peer and original source placement. It generates a
fresh random enrollment nonce and commits the private absolute paths and
device/inode/user/mode stamps with that nonce. Public descriptors expose the
opaque commitment, not those filesystem paths.

The source must exist at the Context's exact predecessor during enrollment.
An inbox retains a lifetime source decision lock while open. Its placement also
pins the journal lock, source directories, inbox directory and inbox lock inode.
Copies, moves, source replacement, extra files, partial records and a missing
ready marker fail closed. Creation does not repair an incomplete enrollment.

First `Receive` checks the complete delivery and original current predecessor,
then saves `delivery` followed by its signed `receipt`. Both file and directory
durability precede reply. It never opens the chunk store, hashes current archive
objects, prepares a session, creates a required owner or appends a source.

An uncertain write poisons that open handle. Cold Open validates every retained
record and resynchronizes only existing valid bytes. It never fabricates an
absent receipt. Explicit exact Receive can finish a retained delivery without a
receipt only while the original source remains at the predecessor. A truncated
record remains blocked; no reset/delete/replace path is supplied.

An already retained receipt is historical and remains readable after the source
advances. Repeating the exact delivery returns that receipt. A retained proof
without a receipt cannot gain this exception. Later required-owner creation
still independently verifies the original source and full binding.

Stop and close intake before explicitly creating or opening the required owner;
the source decision lock deliberately excludes simultaneous intake and execution.

## Original outbox and unknown outcomes

`CreateAdmissionOutbox` saves the full immutable delivery and exact reviewed
recipient route before any send. The route must be a canonical direct QUIC-v1
multiaddress with the enrollment's matching authenticated `/p2p` identity.
The outbox's original directory and lock placement are retained too.

Open requires the independently selected full delivery and route. It does not
discover an alternate intent, send a packet or adopt a replacement root.
`Confirm` verifies the complete receipt against that delivery and durably saves
it before successful return. A missing receipt is unresolved, even if a prior
attempt timed out or the receiver has the proof. There is no timeout unlock,
implicit retry, destination substitution or automatic outbox deletion.

After loss, the operator explicitly resends that same retained intent to the
same route, or reads its original receipt. A completed outbox returns the exact
cached acknowledgement without opening a network channel or loading a transport
seed. A new proof-only outbox may repeat the same intent, but cannot create a
second admission, execution session or custody effect.

## Authenticated network boundary

Protocol: `/outcomemesh/custody/v2/admission-delivery`. It is opt-in and separate
from raw custody execution, generic hash-only witnesses and typed Serve.

The receiver authenticates the one enrolled sender before consuming its own
limit of two active streams and 32 requests per minute. Frame lengths are
bounded before payload allocation. The receiver requires complete request EOF
and checks cancellation before durable Receive. Trailing bytes, incomplete
half-close, foreign enrollment/peer and malformed or oversized frames cannot
produce a receipt.

The client fixes the authenticated recipient independently of the route, verifies
the complete receipt, requires reply EOF and successful stream close, then
confirms the original outbox. A cut reply, invalid receipt or close failure
leaves it unresolved. Service shutdown stops networking and drains handlers
before releasing the original inbox/source and role key.

## Reviewed CLI workflow

Command: `omd work-archive-custody-v2-delivery`.

Every action defaults to keyless review. Run the unchanged selectors with
`--mode run --expected-review-id <id>`. Reviews bind public input contents,
semantic IDs, exact paths, source filesystem metadata, role, route, timeout,
listen address, seed paths and output. Reviews open neither a source decision
nor a store, read no chunk and load no private seed. Unused/duplicate selectors
are refused. Outputs must be fresh and outside original stores and sources.

1. Obtain a signed policy-3 Context and full witnessed admission binding using
   the existing required/admission commands. Retain their independent IDs.
2. On the receiver, `inbox-create` takes common Context/scope/binding pins,
   `--role authority|target`, `--root`, `--journal`, target-only `--objects`,
   `--recipient-peer-id` and `--out`. Independently review/pin the resulting
   enrollment descriptor and ID. No full binding is discovered during creation.
3. `delivery` takes those common pins, `--enrollment`, `--enrollment-id`,
   `--binding` and `--out`, producing the immutable full public delivery.
4. `inbox-serve` takes common pins, original paths, exact enrollment, role
   `--sign-key`, `--transport-key`, `--listen` and `--timeout`. A dedicated
   control pipe accepts `close` or EOF. Startup performs no delivery or work.
5. On the sender, `outbox-create` takes common pins, `--root`, `--delivery`,
   `--delivery-id` and exact `--address`. `outbox-send` adds the Plan client's
   `--transport-key`, optional local `--listen`/`--timeout` and `--out` receipt.
   Lost output is recovered to a fresh output through `outbox-receipt`, or an
   explicitly reviewed exact send. No retry runs automatically.
6. After stopping intake, `inbox-receipt` exports the original acknowledgement.
   `inbox-binding` requires that retained receipt before exporting the canonical
   binding. Both require the same original paths/enrollment and role key.
7. Explicitly create required A/B owners with that exact binding using
   `work-archive-custody-v2-required`. The normal execution, acceptance, Serve
   and global accounting rules still apply.

If enrollment output is lost after creation, `inbox-enrollment` uses the same
explicit creation selectors and exports a **candidate** descriptor after
read-only physical/retained-record validation. It does not adopt the candidate
as an external pin, sign, recreate, flush or resume anything. Operator review
and independently protected enrollment IDs remain essential. An incomplete
enrollment or loss/rollback of all independent pins cannot be repaired by
treating local files as authoritative identity.

## Validation and limits

Tests cover canonical/golden identities, role and peer separation, alternate QC
subsets, size/truncation/trailing refusal, deterministic historical receipts,
inbox/outbox sync failure boundaries, exact cold retry, simultaneous access,
copies/moves/source replacement, cancellation, stale source with and without a
retained receipt, and delivery with a missing archive chunk. Authenticated QUIC
tests cut a reply after receiver durability and then cold-recover the same ACK.
CLI process tests use real admission witness roots, deliver to A and B, lose
sender output, recover without a server/key, export the exact binding and only
then explicitly create owners and perform one custody effect and acceptance.

This stage does not solve hostile implementations, raw-key or RAM compromise,
all-pin rollback, duplicate deliberate enrollment, independent failure-domain
deployment, migration/cutover, safe split-vote progress, physical disk failure or
sustained public-testnet acceptance. Local placement checks and public delivery
receipts cannot replace those launch gates. Legacy V1/policy-2 histories remain
untouched and no mainnet switch is activated.

## Recorded acceptance

The 2026-10-28 [acceptance index](evidence/custody-v2-delivery-20261028.json)
records two fresh required-profile jobs on two observed Linux kernels. Each
obtains real global witness admission, delivers the full binding from A to B,
loses sender stdout after confirmation, kills/reopens the receiver, refuses an
unresolved offline send, and repeats the exact intent after restart. Four signed
acknowledgement exports remain byte-identical. Original B explicitly uses the
binding exported from its delivered inbox before the existing execution matrix.

The fulfilled case ends with A/B/copy source positions 1/1/0, lifetime spent=2,
pending=0 and accounting source cursor1 after Serve A/B and global Close. The
lost-session case stays 0/0/0, spent=2/pending=2/cursor0. Archive holds remain in
both. Delivery itself advances no source and creates no execution owner. The
WAN cut is sender stdout loss; actual reply loss after receiver durability is
covered by the separate real-QUIC test hook, not overstated as a WAN observation.

The [public manifest](evidence/custody-v2-delivery-public-20261028.json) pins 272
artifacts in a 61,490-byte archive. Production APIs reverify complete delivery,
enrollment, four identical acknowledgements per case, received binding, original
execution quorums, binding-aware consumed/pending records, exact acceptance
receipt, Serve A/B and final accounting. The final 707 Go/module/fixture files
match the native source manifest; both hosts use the same pinned native binaries. Four logical witnesses split 2/2
and public fixture keys remain controlled test conditions, not four protected
independent operators.

An initial complete campaign also passed. Final review then found the malformed
certificate-count allocation gap described above; its histories were retained.
The published final campaign uses a fresh source pin and jobs after that decoder
hardening, with unchanged controller sources and valid canonical formats/IDs.
Both campaigns finish without task processes or selected listeners. No V1 owner,
website or mainnet activation was used or changed.

All seven disjoint race groups, fresh CLI process integration, integration vet,
52 Python helper tests, both bounded decoder fuzz smokes and the forged-count
memory regression pass. The native Linux build uses Go 1.26.7, readonly/offline
modules and CGO disabled. This acceptance does not close the protected enrollment,
legacy cutover/accounting bridge or independent audit/public-testnet gates.
