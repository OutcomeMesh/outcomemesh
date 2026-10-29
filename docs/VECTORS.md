# Protocol version 0 vectors

These vectors are consensus fixtures. Any intentional change requires a new
protocol version or an explicit compatibility decision.

## Signed transaction

The transaction is constructed by `testSignedTransaction` in
`core/outcome/transaction_test.go`. Its canonical bytes are:

```text
00000000000701000000000000000000000000000000000000000000000000000000000000000100000000000000000200000000000000000000000000000000000000000000000000000000000000022f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb30000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2cd65f2baa9c0377a94c8399de6abdba8e3ee561e96d3b4d83a0f9d508f27e42f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb3000000000000037f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000504010000000000000005090e0f00000000000000050000000000000064000000000000000000000000000000000000000000000000000000000000000903a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b86b79f3f7da7eac02d758c2b6b3e57e866b2de3721ae3bb5ba17ede517f6d5164eda26b343d96ba8de2ff0bbdfacdb763b3eaf9b144980e87913b81e6ddcbad0a
```

Expected unsigned transaction identifier:

```text
ba52e389b007e9d38cb3313aceb215d8a3c9d3671b5825567dcf1dc7b6bf4fcd
```

## Reference state root

For the three resources constructed in `TestRootIsIndependentOfInsertionOrder`,
the expected root is:

```text
69790007c85c9e268e4abeeebfe44a8ff80824ce4bae80e4646d57adf57a4f4b
```

## Genesis document

The document constructed by `testDocument` in `core/genesis/genesis_test.go`
has canonical bytes:

```text
00000000000b000000006553f10000ffffff00000000000000000000000000000000000000000000000000000000000000000000003201acd69fcdbfcac6605db8407602e6df47c6fdfaa7425d54528584a75ec8d52ccd0000000000000000223208fdaecf845f6173f99e779d5a3c7d6639e9d719b54febec14ff5693d9f62f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb300000000000003e8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Expected identifiers:

```text
genesis_id = 9bbaa98da32d9a9f1e0cc744a44b2d44fcd0c50fdd9dfa517c985b73fead5e96
state_root = bd9d2b89a375c129542bd83d4fd852203c966dedb3f12bff8a174e2abc27a755
```

## Empty development block

The mined empty block constructed by `TestPrepareMineValidateEmptyBlock` has
canonical bytes:

```text
0000000000090000000000000001243fc993547ba2a9ffab93a9e926f91977e2b8fcfc15bd6b4e7a822e0ba77770000000006553f101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a838f137f4680f1bb8da88e859511438286cbdda3b926c08907d158a6a6b2154a6ed7b941fc24bf386993c2db1dd82afaa552bfc358c1230d7d0bec36edf1769f7000000000000000000
```

Expected commitments:

```text
block_id    = 8c63485ab8a8a8fcf43d69b0fbd938133112185fe47a0cc93a52366f9d225874
tx_root     = c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da8
receipt_root= 6672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8
state_root  = 38f137f4680f1bb8da88e859511438286cbdda3b926c08907d158a6a6b2154a6
```

## ASERT fractional vectors

Inputs shared by these vectors:

```text
anchor_target    = 0001000000000000000000000000000000000000000000000000000000000000
anchor_timestamp = 1700000000
height           = 100
target_spacing   = 60
half_life        = 7200
scheduled_time   = 1700006000
```

Expected targets by `timestamp - scheduled_time`:

```text
-3600 = 0000b50100000000000000000000000000000000000000000000000000000000
  -61 = 0000fe8100000000000000000000000000000000000000000000000000000000
   -1 = 0000fff900000000000000000000000000000000000000000000000000000000
    1 = 0001000000000000000000000000000000000000000000000000000000000000
   61 = 0001000000000000000000000000000000000000000000000000000000000000
 3600 = 0001000000000000000000000000000000000000000000000000000000000000
```

Positive offsets clamp because the anchor target is also the version-0 proof-of-
work limit.

## WorkGraph draft share

These Milestone-5 fixtures are implemented by `TestGoldenShareVectors`. They do
not alter a version-0 block until the WorkGraph activation decision is made.

Canonical share bytes:

```text
00000000004d00000000000000096cbf201defd160bae5a8f83d09a0ab1b5d96dae4a67be8d6048a51dd4b2447a9000000006553f101007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff30437bb9bcd7a8f9e102e80d36db384da29954bf43eb12ee33b9b537f6789e5faddd6d5ae0229cd6dc8308ca52b8973246ecf2e27b2224af2d28a75f7857f621052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c000000000000000007
```

Expected commitments:

```text
work_id             = d602d67c610d3f45e3db5a19c5899aaab8a6c9b792dde021c097749338d061fe
empty_inclusion_root = 052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c
one_share_batch_root = 468ddfa28a83db3d8dcd144bb2b95a22fa2083fc7820cb85f8dd85b4b0f91e7a
```

For anchor target value `1`, the exact ratio formula produces share target
value `1023`, encoded as:

```text
00000000000000000000000000000000000000000000000000000000000003ff
```

The easiest WorkGraph-valid hard target is `2^247-1`; it derives the exact
maximum 256-bit weak target without saturation:

```text
007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

For test subsidy `10,220` and `E=511`, the fixed omission-neutral rates are:

```text
anchor_subsidy = 5,110
share_reward   = 10
```

## Signed activation peer advertisement version 1

`TestActivationRecordBindsCapabilitiesAndHeight` fixes a short-lived signed
record for network 91, sequence 9, expiry 1,800,000,600, activation height 25,
and feature mask `0x0b` (`versioned-chain`, `WorkGraph`, and `peer-exchange`).
Its one canonical address is `127.0.0.1:9845`:

```text
00010000005b0000000000000009000000006b49d458000000000000000b000000000000001940b696ecad98757501f34b85ca2447eb10fb123aec8f75d96989d83df6ec3f62010e3132372e302e302e313a393834352147c8af64e13359d2a0bde5b1d45e074e5066bd9837201e2c72f29e1badcb68f67aef7b4295bf631ad44c6987d02c420ae9f54434ec352db27479c800e4d403
```

The Ed25519 signature domain is `OMESH/p2p/advertisement/v1`. Changing the
feature mask or activation height invalidates the signature. Version-0 peer
records keep their original encoding and signature domain.

## WorkGraph relay hello version 1

`TestWorkHelloGoldenFrame` fixes the complete length-prefixed frame for message
type `0x12` (`WorkHello`). It advertises wire version 1, the test mining
context, `share_relay_v1`, a 98,304-byte frame ceiling, 1,024 inventory IDs,
and 256 share bodies:

```text
frame_bytes = 131
frame = 0000007f1200010000005b0000000000000005f2ee6638d996e281afb71491418b5da2c148422e715b2b872dfb2008025f719c007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe3803b3afdc3629f6673d43cf2c0b630edf7dee3afbb6286dc29bf7eb52596e400000000000000010001800004000100
```

The four-byte prefix `0000007f` is the 127-byte frame body length and is
checked against the negotiated WorkGraph ceiling before allocation.

## Versioned chain hello

`TestChainHelloGoldenFrame` fixes the complete message-type `0x16`
(`ChainHello`) frame. It advertises wire version 1, network 91, activation at
height 5, `versioned_sync_v1`, the test tip at height 4 with cumulative work 7,
and the 11,535,373-byte maximum versioned frame body:

```text
frame_bytes = 137
frame = 000000851600010000005bf4114ac064ae0a0c51c0698b6489f637b748ad5e62772c6352097f5abf2b57e3000000000000000500000000000000014f798cff34d9eba2f1ffbbf96323acc5bd35594dd89d45279437685dcc47f9f030384bfb981b28a7f8d40049408d54ab1c93bf78da83be0b081b2533b0a97c910000000000000004010700b0040d
```

The body-length prefix is `00000085` (133 bytes). Peers must agree on the
network, genesis, and activation height before any locator request; the usable
allocation ceiling is the smaller valid advertisement.

## Delayed fee queue

`TestFeeQueueEncodingRoundTripAndDetachedSlots` fixes a three-slot queue after
deposits `10, 20, 0`. Its cursor is back at zero, its conserved balance is 30,
and its slots are `[10, 20, 0]`:

```text
canonical = 000000030000000000000000001e000000000000000a00000000000000140000000000000000
root      = 9edb244b34d9734c6d82e6bfa3acbc24fd2c175d57d9da64c162fe43a9507539
bytes     = 38
```

## Experimental WorkGraph block version 1

`TestGoldenVersion1BlockVector` fixes the isolated activation-block codec. The
fixture has no transactions or shares; the final two `00` bytes are its two
empty canonical list lengths. It is not accepted by active version-0 storage.

```text
header_bytes = 361
block_bytes  = 363
block_id     = 002fd4201ce8009bee8176585ab086affdb1a5b5e3b5ad77c7a29f76af3f0619
```

Canonical header bytes:

```text
000100000000004d0000000000000001c03ea83b20b7f068ecf378fe3dde1662213fb410c87757e466b0314b05a0c14a000000006553f100007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffde688a7e3502cfc2ce9c832eee98e4cd3d107e0aafd1c5253a273e74f217f650ace6904f805047b8675a3129f84d0916fa60cfc9516bfca85033202e1a3852a7052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c0000000000000000e4c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a84a725e151beb9dd0fba579c14cc511895301f6a632142e7294f88f783891222531199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020d44be30322640c368aff4cf516cd220bf70227f9f1558f65166116387cdd61ae0000000000000000
```

## Local custody terminal version 0

`TestCustodyTerminalCanonicalGoldenAndBounds` retains the full canonical wire
vector in `node/custodyauthority/store/custody_terminal_test.go`. It commits the
signed admission, unsigned intent and complete journal result. The ID domain is
`OMESH/custody-authority/custody-terminal/id/v0`; this local envelope changes no
consensus, receipt, journal or network encoding. Historical signatures do not
make this value a current execution grant.

```text
magic         = 4f4d434154524d30
version       = 0
terminal_bytes = 3252
terminal_id   = 7e2c187517a864f52745f742671eea0ecd87df89fe0289c012e7cae8fd8cd9cc
```

## Remote custody authority version 1

`TestRemoteAuthorityV1GoldenHistory` fixes the opt-in assignment and complete
eight-entry reference history in `node/custodyauthority/remote_signing_test.go`.
Assignment, command-signature, entry-signature and entry-ID domains select
`OMESH/custody-authority/<purpose>/v1`. Existing V0 domains and bytes stay fixed.
Command/entry lengths remain 276/382 bytes. These are operational records, not
consensus encodings, execution permission or validated remote terminal evidence.

```text
assignment_bytes = 515
assignment_id    = 4f7596ad0e318749d6d1d47c55c50b1637315870470c41ec0367d9abb9248006
Audit Admit      = 73dfbd89e799b2d8e77e351a748a3451780a2aae6c8ab5c6538c87c91f04a1fc
Serve Admit      = e87dcfc03c9762c032b917d18940387c3e5a1ebc8f01fa3543e2f34786549d72
RemoteBegin      = e1b8c76157010fbcf155233b519e5497b3d71f7fc18b3fd67dc487f517735a92
RemoteDrained    = 1b07c6a6fcdd1efc534e12217b1ada9c6eb201ab6c1f372af048dd2451faa94e
Audit Complete   = 3fb4218736ac4b9d243bf610e91d6efdf936405f5d7775e33e9377325cbc8418
Serve Complete   = 34b036323e5004282a0a8960081cc2a369813b7eb5808188a651e70547dae277
Stop             = 2156f53c31663b68f2416c2d33a78f006dced8369579731756f5215799ef56b8
Retire           = 9ae890d3829b6932c491882d749e0cd1f1addb330ad966ed7b8544854beb6764
```

The separate worker-envelope format starts at version 0; its plan requires an
authority V1 Serve admission. `TestPlanAndSealGoldenAndBounds` retains full
vectors in `node/custodyauthority/remoteworker/model_test.go`. The ID domains are
`OMESH/custody-remote-worker/plan/id/v0` and
`OMESH/custody-remote-worker/seal/id/v0`. The seal commits one immutable sealing
branch and disposition, without attesting physical runtime drain or proof validity.

```text
plan_bytes = 594
plan_id    = 29e1f46f85cf0d4a6b9b883c0c0e227659961e46eef1bd473b326770f0779929
seal_bytes = 139
seal_id    = 7070477c5923dbd0a7c28cb445b81b1b66129b9d456f8627d0b75e86fe67c52c
```

## Managed remote metadata and typed terminal

`TestControlCanonicalGoldenAndFrames` fixes full request/response codecs in
`node/custodyauthority/remotewire/wire_test.go`. The separate protocol is
`/outcomemesh/custody-remote-control/0`; its four-byte big-endian frame prefix
counts only the canonical body and rejects bodies over 4 KiB before allocation.
The fixed fixture has a 1,023-byte request, 107-byte Started reply and 526-byte
retained-result Drain reply. It carries no journal/proof body.

`TestRemoteCustodyTerminalCodecVectorAndSubstitution` retains a fixed canonical
envelope built from the existing historical custody vector, V1 signatures and
sealing commitments. This codec fixture alone supplies no current owner or
acceptance proof; real owned network tests separately establish that binding.
The separate ID domain is `OMESH/custody-authority/remote-terminal/id/v0`.

```text
magic          = 4f4d43525445524d
version        = 0
terminal_bytes = 3809
terminal_id    = 65bdc27adc12bbb246f043845034d5f43ffdba2a64f31a6325332d00dc580eab
```

## Separate protocol 2 / radix commitment 1

The complete canonical resources, membership/absence proofs, genesis and first
block are in [`radix-v1.json`](../core/state/testdata/radix-v1.json).
Original protocol 0 vectors above remain unchanged. Expected identifiers:

| Value | Hex |
| --- | --- |
| Empty radix root | `eda3c66a2a850ff6a9f70fe1d238e12563b3e6bfde86db03f2dfab1c890802e5` |
| Three-resource radix root | `ce66a5c56a00da5d070906ba5e3ffa337782c295c72f4f68a43087ec7efadd8b` |
| Protocol 2 genesis ID | `79f0789eb503f702395b925d51001f5992cb28ba1d740f73c4a99ccfe34b2a19` |
| Protocol 2 first block ID | `c0e0d2da278978c32c12eecd67fe697db48f9832f9eed6e98db262d87572dae8` |

## WorkGraph block version 3

The deterministic empty-state activation fixture in
`TestGoldenVersion3BlockVector` retains the v1 fixture's network, height, parent,
timestamp, target and miner. It schedules radix at height 1. Header size is 361
bytes and full block size is 363 bytes. The payload domain is
`OMESH/workgraph/payload/v3` and the first valid nonce is 9.

Canonical block bytes:

```text
000300000000004d0000000000000001c03ea83b20b7f068ecf378fe3dde1662213fb410c87757e466b0314b05a0c14a000000006553f100007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff407d668ae524a7f74b0e9eba82c12562eb03e8bb158927abd0bdf6cd10a69d78ace6904f805047b8675a3129f84d0916fa60cfc9516bfca85033202e1a3852a7052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c000000000000000904c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8eda3c66a2a850ff6a9f70fe1d238e12563b3e6bfde86db03f2dfab1c890802e531199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020d44be30322640c368aff4cf516cd220bf70227f9f1558f65166116387cdd61ae00000000000000000000
```

Block ID: `0041e1b81fcf70c9e90d09111fb3faf5077c1f570d2c74732028ff0ce64e330c`.
State root: `eda3c66a2a850ff6a9f70fe1d238e12563b3e6bfde86db03f2dfab1c890802e5`.
The original version-1 vector remains unchanged.

## WorkGraph radix activation profile

`TestGoldenRadixActivationProfile` fixes a local profile with network 1, genesis
ID `01` followed by 31 zero bytes, WorkGraph activation 2, radix activation 5,
fee delay 3, four trees and a 67,108,864-byte forest budget. The 72 bytes are:

```text
4f4d574f524b000200000001010000000000000000000000000000000000000000000000000000000000000000000000000000020003000400000000040000000000000000000005
```
