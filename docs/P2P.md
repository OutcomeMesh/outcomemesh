# Development peer protocol

Status: transport-independent protocol with QUIC-v1 and TLS/TCP adapters

The peer stack is split so no transport library enters consensus code:

```text
QUIC-v1 primary; TLS/TCP fallback
              |
        deadline session
              |
 bounded OutcomeMesh wire frames
              |
 locator sync / mempool policy / Chain.Submit
              |
 deterministic consensus kernel
```

## Wire framing

Each frame is:

```text
uint32_be(body_length) || uint8(message_type) || payload
```

`body_length` is rejected before allocation when zero or greater than 8 MiB plus
the type byte. Payloads use the same strict integer/length primitives as the
consensus codec, but network messages have an independent version and are not
part of a block hash.

Version 0 messages:

- `Status`: network ID, genesis ID, tip ID/state root/height/work, frame
  capability;
- `GetBlocks`: 1–32 unique block locators and a 1–128 block limit;
- `GetHeaders`: the same locator form and a 1–128 header limit;
- `Headers`: zero to 128 contiguous fixed-size canonical headers plus the
  responder tip used to assemble the batch;
- `Block`: one canonical block, independently replayed on receipt;
- `Transaction`: one canonical signed transaction, admitted through mempool;
- `BatchDone`: responder tip marking the end of a bounded block batch;
- `Result`: accepted/rejected plus the transaction or block ID;
- `GetPeers`: request for 1–64 signed peer advertisements;
- `Peers`: zero to 64 opaque advertisements, each at most 2,048 bytes;
- `GetSnapshot`: request for the exact tip advertised during the handshake;
- `SnapshotManifest`, `SnapshotChunk`, `SnapshotDone`: bounded chunked state
  transfer tied to that tip and state root.

Unknown types/versions, duplicate locators, trailing bytes, truncated fields,
and oversize frames fail closed. The frame-body parser has a native Go fuzz
target.

The two header message type IDs were appended to the pre-alpha version-0 wire
table. Active chain sessions still have no in-band version upgrade: an older
peer rejects an unknown type and disconnects. This is an explicit development
compatibility decision, not a silent reinterpretation of an old message.

Two further inactive message IDs, 20 and 21, encode `VersionedBlock` and
`VersionedHeaders`. Both require wire version 1. The block envelope contains
one length-delimited v0 or v1 canonical block. The header envelope contains up
to 128 individually length-delimited v0/v1 headers, requires contiguous parent
IDs and heights, and permits only the forward v0-to-v1 transition. Activation
height validation is intentionally outside the framing layer.

`ReadMessage` still rejects a body above the original 8 MiB block ceiling from
its length prefix. Only an explicit `ReadMessageLimit` opt-in can admit the
larger maximum required by a WorkGraph block, and per-message payload ceilings
are rechecked after the type byte is available. No active `Status`, locator
request, sync loop, or session handler advertises or consumes these new chain
messages yet.

Message IDs 22–25 complete the inactive control grammar: `ChainHello`,
`GetVersionedBlocks`, `GetVersionedHeaders`, and `VersionedBatchDone`.
`ChainHello` commits the network, genesis, activation height, capability bits,
tip metadata, cumulative hard work, and allocation ceiling. Both peers must
match the first three values exactly and advertise `versioned_sync_v1`; the
usable frame limit is the smaller advertisement. Locator requests retain the
32-locator/128-object bounds and duplicate rejection of v0 under distinct
message IDs, so an active handler cannot reinterpret them accidentally. The
isolated router-backed state machine now serves and downloads those messages,
and the QUIC adapter can register it explicitly as `/outcomemesh/chain/1`.
Default hosts and ordinary v0 CLI paths leave that protocol unhandled;
`work-serve-quic` is the explicit experimental registration point.

The isolated versioned chain session uses the negotiated maximum for both reads
and writes. It admits at most 64 header/body batches by default, with separate
64-request responder budgets and the existing 4,096-message ceiling. Headers
are validated before bodies across both versions: requested parent, height,
activation boundary, network, MTP, future time, lagged target, PoW, and
contiguous IDs all fail closed. Bodies must reproduce the exact header bytes
and pass full activation-router execution. The responder pins one emitted
header batch and accepts only the matching locator/count body request next;
body-first, repeated-header, or substituted-locator requests close the stream.
Blocks are not fragmented: if one valid block exceeds the negotiated ceiling,
that synchronization attempt closes with a frame-size error.

A continuation locator records the last downloaded remote block even while a
long divergent branch has not yet beaten the local selected tip. This avoids
requesting the same prefix forever; once the branch wins, ordinary global
hard-work fork choice takes over. The completed tip must match the hello's ID,
height, state root, and cumulative work. A deterministic test uses two-block
batches, keeps the first remote prefix as a losing side branch, then crosses
v0→v1 and reorganizes through a different activation base. The session remains
an opt-in prototype behind `work-enable`, `work-serve-quic`, and
`work-sync-quic`; its router recovers every activation-base tree from the
optional persistent forest.

## Handshake and synchronization

The initiator sends `Status`; the responder validates network and genesis before
returning its own `Status`. A mismatch closes the stream before block or
transaction processing.

If the remote tip has better cumulative work (using the same smaller-ID tie
break), the requester sends exponentially spaced locators ending at genesis.
For every batch it first requests at most 128 headers. Before asking for the
corresponding bodies, it checks the selected locator, contiguous ancestry,
network ID, height, ASERT target, median-time-past, future-time bound, PoW, and
the handshake tip binding. It then requests exactly that number of blocks and
requires byte-identical headers and the same responder tip. Each body still
goes through normal transaction, receipt, reward, state-root, fork, and commit
validation. Thus header sync reduces exposure to large invalid bodies but does
not replace full execution. Batches repeat until the local tip equals
`BatchDone.tip_id`, with hard message, header-request, block-request, and batch
caps plus a no-progress disconnect.

This works across divergent branches: the receiver stores the remote branch and
atomically reorganizes only when its cumulative work wins.

## Isolated WorkGraph relay

The inactive WorkGraph prototype uses a separate finite stream and wire version
1. Types 15–17 are `ShareInventory`, `GetShares`, and `Shares`; types 18–19 are
`WorkHello` and `ShareResult`. They are never accepted by the active version-0
session handler.

Both endpoints first send `WorkHello` with one exact
network/height/anchor/target/payload context, a `share_relay_v1` capability, and
bounded frame, inventory, and body counts. Context mismatch or absence of the
capability closes the stream. Limits are intersected and reduced against the
worst-case encoded share size; the negotiated frame ceiling is enforced from
the four-byte prefix before allocation.

The sender announces at most 1,024 sorted IDs. The receiver requests only
unknown IDs, at most once and at most the negotiated body count per batch. Each
response remains ID-sorted and is passed through the local pool's full PoW and
DAG admission. A final accepted/rejected receipt accounts for returned invalid
bodies and advertised bodies the peer withheld. One stream cannot become an
unbounded request loop. The libp2p QUIC adapter exposes the separate
`/outcomemesh/workgraph/1` protocol only after an explicit handler is installed;
without that call negotiation fails. Ordinary CLI nodes do not install it; the
experimental `work-serve-quic` command installs both this handler and the
separate activation chain handler. On each incoming share stream it resolves
the current best-parent round, performs full pool admission, and reports the
bounded pool totals. The pool is replaced rather than migrated when the parent
changes. A real process fixture chain-syncs three WorkGraph-enabled Pebble
nodes, relays fresh weak shares, then proves that two compatible peers converge
after the miner wins while a third authenticated v0-only peer fails
independently. Activation-aware peer exchange and topology-aware selection are
available only on the explicit WorkGraph mining path; production activation
remains a separate gate.

`work-mine-quic` is the first explicit outbound fanout path. Up to eight direct
QUIC peers are identity-derived from their `/p2p` multiaddresses; optional
OutcomeMesh pins must match those identities and duplicate identities fail
before mining. Every peer receives sorted unpublished subsets from an
independent round-bounded queue. `RelayInventory` proves every selected ID
belongs to the local pool before opening the application exchange. If a peer
advertises a smaller inventory limit, only that prefix is counted as announced
and its tail remains queued. The mining callback performs no network I/O, so a
slow peer cannot block another worker or hard-PoW progress. Relay is attempted
when 128 fresh IDs accumulate or an eight-second partial-batch timer expires,
whichever happens first. A newly admitted inbound share is forwarded to the
other explicit peers, never directly back to its authenticated source. Since
only the first successful pool admission invokes forwarding, cycles terminate
at the existing per-round deduplication boundary. Shares arriving just before
publisher attachment wait in a bounded 8,192-entry lifecycle buffer. Failures
keep the suffix for a later attempt. The command uses the same peer byte
accounting, fixed-window WorkGraph stream limits, exact-context handshake, and
separate chain-v1 handler as the server. It does not yet discover or select
peers automatically unless the operator explicitly enables the bounded
peerbook selector described below.

`work-mine-quic --auto-peers` first refreshes `peers.bin` from explicit and
eligible signed bootstraps over activation-bound chain-v1, then reuses the
ordinary routing score, latency, dial backoff, and ASN-diversity policy.
Automatic selection requires an operator-owned, age-checked ASN map. It
excludes self and any explicit peer, accepts only signed version-1 records
claiming WorkGraph at the exact local activation height, considers only direct
QUIC-v1 addresses whose embedded libp2p identity matches the record, and spends
at most `--auto-attempts`. A handshake-only `Probe` remains authoritative: it
verifies the live WorkGraph protocol and byte-identical mining context without
announcing share IDs. Selection fails closed if it cannot reach the requested
count; failed capability probes update persisted dial backoff.

After startup, selected peers become the bootstrap tier for another bounded
refresh every 30 minutes. Selected bootstrap entries stay ahead of other learned
entries, while ordering inside each tier is the hash of local identity, refresh epoch, and
candidate identity. That removes permanent fixed-prefix starvation under a
small attempt budget without pretending to solve Sybil or eclipse attacks.
An in-process QUIC adversarial fixture makes one authenticated bootstrap return
a mixed exact/foreign-activation batch. The receiver admits none of that batch,
continues to the next independent bootstrap, persists its compatible WorkGraph
record, and recovers the same one-record book after reopen.

`/outcomemesh/chain-notify/1` reuses the complete chain-v1 wire and validation
state machine with inverted connection roles. The winning dialer serves; the
inbound handler synchronizes. Thus a notification grants no block authority and
cannot bypass cumulative-work comparison, header-first validation, body/header
identity, replay, or activation routing. It has its own libp2p protocol scope
and shares the versioned-chain fixed-window admission counter. Default hosts do
not register it. A notified cooperative miner cancels its current round only
after the selected tip actually changes. Outbound notifications run in one
worker per explicit peer and coalesce repeated wins to one pending prompt. The
responder pins the canonical chain path advertised in its hello, preventing a
concurrent next-round win from changing an in-flight header/body response.

## Signed peer advertisements

`node/discovery` defines an OutcomeMesh-native discovery record rather than
making peer routing part of consensus. A version-0 record contains the network
ID, a non-zero monotonic sequence, expiry, Ed25519 public key, one to eight
canonical endpoints, and a signature. Endpoints may be literal IP:port for the
TLS/TCP fallback or an exact `/ip{4,6}/.../udp/.../quic-v1/p2p/...`
multiaddress. DNS names are deliberately not accepted in version 0. A QUIC
multiaddress is rejected unless its embedded libp2p ID resolves to the same
Ed25519 public key carried by the signed record. The signature covers the
domain-separated hash of every unsigned field, and the OutcomeMesh peer ID is
derived from that public key.

Version 1 preserves those fields and adds a signed feature mask plus one exact
activation height under the separate `OMESH/p2p/advertisement/v1` domain.
Unknown feature bits, zero capabilities, and zero activation height fail
closed. Chain-v1 negotiates `peer_discovery_v1` independently from versioned
sync. Only after network, genesis, activation, and that feature agree may a
peer request up to 64 records. The responder serves only exact-activation v1
records, shortens the deterministic response prefix to the negotiated frame
budget, and accepts at most eight requests per session. The receiver validates
the entire batch before one atomic merge. WorkGraph servers and long-lived
miners publish a one-hour self-record and replace it every 30 minutes with a
monotonic sequence. Peerbook file replacement is serialized with refresh so a
concurrent renewal cannot overwrite a newer learned batch. These capability
assertions optimize routing; only a live protocol handshake proves current
support.

Records live for at most 24 hours. The address book has a hard record cap,
prunes expiry, rejects stale sequence numbers, returns detached deterministic
lists, caps each IPv4 /16 or IPv6 /32 diversity bucket, and admits each received
batch atomically. Thus one bad record cannot partially mutate the book. The
book has a bounded canonical local-file encoding; replacement is temp-file,
file-fsync, rename, and directory-fsync, so anti-replay sequence survives
restart. A persisted self sequence is incremented even if the wall clock moves
backwards. `omd serve` publishes a one-hour self-record;
`omd peers` and `omd peers-quic` fetch records through a
network/genesis-checked, mutually authenticated session and can pin the
contacted peer ID.

A signature proves who asserted an address, not that the address is reachable
or that one entity has only one key. Continuous dialing is disabled by default.
The opt-in scheduler requires an operator-supplied ASN table and never overlaps
passes; public bootstrapping still needs a maintained source for that table,
active reachability history, and stronger Sybil-aware admission.

The local `node/routing` layer ranks live signed records by bounded local score,
skips self, reserves only one concurrent dial per identity, and applies capped
exponential backoff after failure. The score is clamped at both the positive
cap and ban threshold. Active dial reservations survive retention pruning, and
a process-local monotonic clamp prevents a wall-clock rollback from shortening
backoff. Authenticated success clears the dial penalty; useful chain progress,
valid traffic, stale data, invalid objects, protocol violations, and timeouts
have distinct bounded counters/weights. Scores decay one point per hour toward
neutral, so old behavior is not permanent reputation. `auto-sync-quic`
measures authenticated QUIC stream establishment with Go's monotonic clock and
stores a capped integer-millisecond EWMA. Equal-score peers with measurements
are ordered by lower EWMA before the stable peer-ID tie-break; ASN caps still
apply. This is local route quality, not a signed claim or consensus input.
`auto-sync-quic` atomically persists the bounded, canonical
score/backoff/counter/latency set in `reputation.bin` after every pass;
sessions, in-flight dials, and byte windows are intentionally reset. The file
is capped at 2 MiB, mode `0600`, restored with retention pruning and offline
score decay, and has its own fuzzed decoder. Reputation format version 1 reads
version-0 files with latency initialized as unknown.
`omd auto-sync-quic` performs one bounded pass over the persisted book, opens
records through full signature/network/expiry/identity checks, and runs the
normal fork sync. A real three-process check discovered a peer, restarted from
the saved peerbook, synchronized height 0→3 without an explicit address, and
then passed full replay verification.

An optional immutable longest-prefix-match table maps literal IP CIDRs to
32-bit ASNs. Its local format is one `CIDR,ASN` pair per line, with `#` comments;
it is capped at 16 MiB and 65,536 unique prefixes. `--max-per-asn` limits all
attempted identities sharing any resolved ASN in one pass. The table is local
policy and is never signed, gossiped, or consulted by consensus. Without
`--asn-map`, one-shot behavior remains score/prefix based. With an ASN map,
`--watch-interval 5s..1h` enables an immediate then periodic non-overlapping
schedule. Every successful established session performs both header-first/full
sync and idempotent signed-record refresh; QUIC servers republish their own
one-hour record every 30 minutes. Failed peers retain capped exponential
backoff. Continuous mode reloads the bounded regular-file table before every
pass, swaps it only after a complete successful parse, and stops before dialing
when it is malformed, too far in the future, or older than `--asn-max-age`
(24-hour default, 30-day hard maximum). A stale or malicious ASN dataset can
still reduce diversity, so no dataset is bundled or implicitly trusted.

## Snapshot verification boundary

The snapshot protocol transfers at most 262,144 resources in chunks of 256
(protocol maximum 512). The manifest commits to network, block ID, height,
state root, exact resource count, chunk size, and chunk count. The receiver
requires consecutive chunk indexes, exact chunk cardinality, globally
increasing resource IDs, valid canonical resources, the configured total cap,
and an exact recomputation of the state Merkle root. A malformed chunk cannot
finalize a partial snapshot.

`omd snapshot-check` exercises this verifier and prints `imported=false`.
Deliberately, there is no canonical database import API yet: a TLS-authenticated
peer can still lie consistently in both its status and snapshot. Safe fast sync
must bind the manifest anchor to independently validated header/history data
(or a separately specified validity proof). Until that exists, full block
download and replay is the trustless synchronization path.

## Mempool policy

The development mempool has independent caps for transaction count, total
bytes, and per-transaction bytes. Admission performs full signature, state,
maturity, conservation, and GuardVM validation at the next height, then reserves
all inputs. Local double spends are rejected.

Selection and eviction use exact integer fee-rate comparison, absolute fee, and
smaller transaction ID as deterministic tie breakers. A full pool evicts only
strictly lower-priority entries. Template selection replays candidates against
the evolving state, and every canonical tip change triggers revalidation so
reorgs release or invalidate reservations safely. These are local policy rules,
never consensus rules.

## Authenticated transports

`node/transport` provides a standard-library local-devnet fallback:

- TCP with TLS 1.3 only;
- mutual Ed25519 certificates;
- self-signature, key type, validity, and ALPN verification;
- stable peer ID `SHA256("OMESH/p2p/ed25519/v0" || public_key)`;
- optional expected-peer pinning;
- session deadlines over every handshake/request.

An end-to-end loopback test authenticates both peers and performs a full fork
sync over the encrypted socket. `omd serve` uses a persistent seed-derived peer
identity and a hard global connection cap; `omd sync` optionally pins the
expected peer ID. The server also enforces a bounded peer table, per-peer
concurrent-session and plaintext-byte windows, capped local reputation, and
temporary bans for repeated malformed traffic. Both inbound and attempted
outbound plaintext bytes have per-identity rolling windows, preventing a small
request stream from eliciting unlimited responses. This adapter is
provisional.

`node/transport/libp2p` uses official go-libp2p v0.48.0 and is deliberately
outside consensus packages. It enables only QUIC-v1 listen/dial addresses,
derives the same OutcomeMesh peer ID from the authenticated remote Ed25519 key,
accepts only exact IP/UDP/QUIC-v1 address stacks, supports independent peer-ID
pinning, disables relay, and configures hard
connection, stream, file-descriptor, and memory scopes plus connection-manager
watermarks. The chain session runs unchanged over a multiplexed stream. The
optional WorkGraph protocol has its own protocol/peer scope (one concurrent
stream per peer by default, hard implementation maximum four), so enabling it
does not silently expand the chain-session allowance. A fixed-window gate also
defaults to eight accepted WorkGraph streams per peer and 512 globally per
minute (hard configurable maxima 60 and 4,096). With the exact 630,258-byte
worst-case application relay, the defaults cap admitted WorkGraph framing at
about 82.1 KiB/s per peer and 5.13 MiB/s globally averaged over the window.
Window-boundary bursts, QUIC/IP overhead, and retransmissions are separate
capacity concerns.

The activation-aware chain session is a third protocol scope under
`/outcomemesh/chain/1`; it never falls back to `/outcomemesh/session/0`. Its
defaults allow one concurrent stream per peer and four across the host, with
hard implementation maxima of two and 64. An independent fixed-window gate
admits four new streams per peer and 128 globally per minute by default (hard
maxima 30 and 1,024). These controls bound concurrent frame allocation and
sequential reconnect churn; the session's own frame, message, request, and
batch ceilings provide the application-level bounds. The handler is opt-in and
is installed only by `omd work-serve-quic`; ordinary `serve-quic` remains v0.

QUIC-v1 authentication is performed by libp2p's built-in TLS 1.3 identity
handshake. Noise is registered in the libp2p security configuration but is not
layered over QUIC; describing QUIC as “QUIC over Noise” would be technically
incorrect. A future TCP fallback inside libp2p may negotiate Noise explicitly.

An integration test and real two-Pebble-node CLI run prove authenticated QUIC
fork synchronization followed by complete replay verification. The test
harness also covers five-node partition/heal and a fixed-seed seven-node
run with short writes, delay, whole-session duplication, loss, connection
churn, and asymmetric reachability. An opt-in process harness additionally runs
three by default (up to 100) mine/server-start/sync/replay/SIGTERM/restart cycles
against two real Pebble directories.

A separate two-host QUIC integration fixture explicitly enables WorkGraph v1,
pins the authenticated OutcomeMesh peer ID, negotiates a 512-byte receiver
frame, relays an out-of-order parent/child DAG in two body batches, and verifies
full pool admission. Negative fixtures reject a different payload context,
refuse negotiation when no WorkGraph handler is installed, and enforce its
independent one-stream-per-peer scope.

Another two-host fixture explicitly enables `/outcomemesh/chain/1`, pins the
authenticated peer ID, negotiates a 1 KiB frame ceiling, and synchronizes a
divergent branch across v0→v1 in two-block batches. It verifies final hard work
and state equality after the remote branch reorganizes the receiver. Negative
fixtures prove that an unhandled host cannot negotiate the protocol, a held
chain-v1 stream does not consume a v0 session slot, and the dedicated per-peer,
global, concurrent, and fixed-window limits fail closed.

A separate process fixture initializes three activated Pebble nodes with the
same genesis, writes independently validated activation profiles, mines through
v0→v1, synchronizes over the versioned QUIC protocol, performs mixed-chain
replay verification, stops both compatible servers, and reopens the receivers
with the same tip, state root, cumulative work, and forest inventory. A fourth
authenticated v0-only process proves optional-protocol incompatibility is
isolated. The fixture also proves ordinary v0 mining is rejected after
activation is marked.

Milestone 4's written devnet gates are closed: convergence, fail-closed resource
bounds, and trustless full-history bootstrap are reproducibly tested. A public
network still requires an independently maintained production ASN-data source,
a validity-backed fast snapshot activation path, physical disk-reserve/pruning
policy, and longer randomized process soak/resource-fault runs. Per-block
fork-state amplification is limited by schema-3 resource deltas rather than
full state copies, and immutable logical history has a fail-closed local budget.
