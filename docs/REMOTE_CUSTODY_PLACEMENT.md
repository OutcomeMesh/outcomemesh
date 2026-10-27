# Remote operator local placement profile

This opt-in profile binds the remote Audit/Serve operator to independently pinned
original local roots, permanent locks and private-key FILES across process restart.
It detects ordinary file/directory copies, path substitution, key-file replacement
and changed access modes. It does not make an Ed25519 seed uncopyable, fence a raw
key holder on the wire, provide a distributed lease, or detect a full VM/filesystem
clone that preserves identities. The independent key/root fencing gate remains open.

The [2026-10-27 acceptance index](evidence/remote-custody-negative-placement-20261027.json)
records native CLI/process checks, 33 copy refusals on retained original WAN
branches, and six normal-CLI WAN scenarios with required placement. The latter
complete 13 successful cycles and 26 independent ticket completions, including
eight sequential cycles retaining A's original pin and source/authority roots.
B explicitly enrolls each new worker. These are controlled local-profile tests.

## Selected bindings

| Operator | Existing roots | Existing seed files |
| --- | --- | --- |
| A / audit | authority, authority-pins, journal, artifacts | authority-key, auditor-key, control-key, key |
| B / serve | worker, journal, objects | replica-key, control-key, key |

The profile also derives and binds `authority.lock`, `intent.lock`, `journal.lock`,
`custody.lock` or `worker.lock` inside the corresponding roots. It records canonical
paths, native device/inode identities, owning UID, access modes and fixed file
sizes. Directory contents may grow without changing their identity. Seed bytes
and seed hashes are never included in the manifest.

Existing roots must be disjoint directories; key directories must be outside
them. Selected files/directories must belong to the current user and deny group/
other access. Seed files must be regular 32-byte files, and locks empty regular
files. Symlinks and path aliases are not enrolled as alternative installations.

The placement manifest's parent is another existing private directory outside
ALL selected owner roots and key directories. Its own native identity is bound
as well. The manifest contains local deployment paths and should remain private.
Two filesystem paths do not establish separate devices or failure domains.

## Explicit enrollment and startup

Use the complete independently pinned session flags from the
[operator guide](REMOTE_CUSTODY_OPERATOR.md). Append one of these modes to the
selected `work-archive-custody-remote-audit` or `...-serve` command:

```text
--mode placement-review --placement /ABS/CONTROL/placement
```

This reads metadata only. It loads no seed, opens no owner, starts no listener,
creates no directory and writes no file. Keep the reported placement ID in an
independently trusted deployment configuration. Then explicitly publish:

```text
--mode placement-create --placement /ABS/CONTROL/placement --placement-id REVIEWED_ID
```

Creation compares the full current metadata to that reviewed ID and publishes
no-replace bytes with file/parent sync. Existing matching private bytes can be
recovered exactly; different bytes, identities or insecure existing output fail.
No bootstrap/open path automatically enrolls, repairs or replaces a placement.

Normal review/control then selects:

```text
--placement /ABS/CONTROL/placement --placement-id INDEPENDENT_ID --require-placement=true
```

The explicit boolean value is intentional: the existing strict once-only flag
parser requires a value. A missing path/pin fails before seed loading. The CLI
checks the complete binding set before loading private material; the SDK checks
the selected owner roots again and retains a frozen guard. Runtime actions and
B's control/data responses recheck it. A copied key with identical bytes at a
different path or inode does not pass that pinned profile.

Reports include the placement ID/path so an operator can distinguish a selected
profile from legacy unbound operation. Source compatibility is retained: callers
without a placement still use the earlier trusted-original-root contract. Do
not describe an unbound caller as copy-protected. Offline consumer signing,
wallet storage and generic legacy SDK entry points are not upgraded by this flag.

A keeps its placement while reusing the same assignment and original roots.
Each new B worker has a different path/identity, so a new fixed-session worker
requires explicit reviewed enrollment and a new independently retained pin.
Recovery of that worker uses its SAME pin; restart never enrolls it afresh.

## Refusal and recovery

If a selected path, native identity, UID, mode/fixed size, placement bytes or
anchor directory identity changes, the configured runtime refuses the next
guarded action. A's active remote obligation
and ordinary tickets are not cleared. B may retain an unresolved Sealing branch
when it cannot finish cleanup against the original source; that is uncertainty,
not an acknowledgement or successful result.

This is a metadata profile. It does not monitor same-inode/same-size edits to
seed bytes after a process has loaded its key, or rollback preserving all bound
identities. Normal startup still checks loaded keys against the pinned public
roles. These limitations are another reason this is not protected signing.

Retain all files and inspect the original owner. Replacing the pin automatically
would defeat the protection. Restoring an original retained inode is different
from installing a new backup copy; the latter needs a separately designed,
explicit recovery/fencing procedure. This feature supplies no in-place owner
transfer, timeout-based lease takeover or permission to ignore a pending attempt.

The bounded `OMCRPLC0` metadata envelope has its own local ID domain:

```text
OMESH/local/remote-custody-placement/id/v0
```

Its complete field set, order and path forms are canonical; IDs are local
deployment commitments, not network certificates. Native enforcement is available
on Linux and macOS. On unsupported platforms a selected profile fails closed;
it does not silently switch to unbound operation.

## What is still required for independent fencing

The next protocol gate needs an independently protected signing/authority service
whose durable state is outside the copied owners. A protected assignment must
REQUIRE its evidence in validators, not merely recommend a CLI flag. A V1 raw
key holder can bypass local software, so this requires a separately versioned
scope and rejection of downgrade for protected assignments.

Before that gate can be credited, specify and implement:

1. A pinned external issuer and monotone owner generation/position checked on
   every effectful path, including remote data/proof signing and cached replies.
2. One durable attempt claim before effects and an immutable result/unknown seal
   afterward. Historical ACKs and cached metadata are not live permits.
3. Proof/terminal commitments that include the required issuer evidence, so
   copied raw role keys cannot manufacture accepted unstamped results.
4. Explicit recovery of uncertain claims. Lease expiry, a partition or a missing
   reply cannot authorize a competing owner while an old effect may still run.
5. Protection against cloning/rollback of the issuer itself: a reviewed external
   consensus/monotone anchor or suitable protected signer, plus actual cross-host
   partition, replay, copy, rollback and device-failure acceptance.

No wire layout or signature domain for that future version is defined by this
local-profile implementation. Full-VM clones, in-place rollback of all original
history, compromised root users and copied raw keys remain outside its guarantees.
