# Disabled review of a legacy custody transition

Status: implemented historical review and durable preparation. This is not a
V1-to-V2 importer, registry selection, runtime assignment, admission genesis or
activation certificate. The separate [imported accounting stage](CUSTODY_IMPORTED_ACCOUNTING.md) now
consumes this review with an enforced spending/source seed and exact registry
selection. The [cutover contract](CUSTODY_V2_MIGRATION.md) still requires protected
exclusion of old grants and active original-source handoff.

## Complete legacy evidence

`node/custodycutover` accepts a complete original V1 assignment, archive manifest,
initial receipt, custody policy, every authority entry through an independently
pinned retirement, and every successful remote cycle. A cycle includes its full
Plan, Begin and typed `RemoteCustodyTerminal`, including the accepted source entry.

Verification derives the old assignment again and replays all authority entries
to the exact external sequence/head. The result must be Retired, with zero pending
tickets and no remote hold. A detached Snapshot or an arbitrary completion hash
is insufficient. Every ordinary admission, including completed admissions, must
match exactly one Audit/Serve pair. Both completions must contain the same typed
terminal ID and match the existing typed completion builder. The Serve's exact
Plan/Begin/Drain/seal and the Audit's intent/admission must be in that history.

The archive entries must form the complete source sequence starting at the
original initial receipt. Each previous head and full predecessor receipt must
match. The selected head is the last accepted entry, never a convenient older
prefix. The retention floor is the maximum deadline in that complete lineage.
Historical proofs are checked at their original response times; review produces
no new challenge, response, receipt, source append or renewed deadline.

The supported subset is an unused retired assignment, or up to 64 fully completed
remote Audit/Serve cycles. At most 642 authority entries and 32 MiB of complete
canonical evidence are accepted. An omitted cycle, unsupported operation,
negative settlement, unknown result or remaining ticket blocks review. There is
no partial-success path that discards unsupported obligations. A zero remaining
allowance can be assessed, but cannot prepare another two-operation job.

## Original-owner export and source observations

`history-export` obtains entries from the original coordinator under its intent
and authority guards. It requires an exact externally retained retirement pin,
no pending local attempt, complete replay and a caller-supplied finite history
bound. A supplied template cannot bring its own authority history or End position.
The immutable public evidence is published before those guards are released.

A source observation requires separately retained local placement metadata and
an explicit nonzero nonce. The metadata candidate binds canonical paths, root
and permanent lock inodes, device, user, mode and role. Permanent lock change
time is also retained to distinguish immediate ordinary inode reuse on Linux.
Directory change time is excluded because legitimate file creation changes it. It is a diagnostic value
for independent review; it is not automatically trusted enrollment.

- A opens its original coordinator, verifies the entire same retired history,
  then holds the original source decision through signing and publication.
- B opens every original cycle worker in source order. All must already be
  sealed, have no pending mutation and retain the exact corresponding seal.
  It then holds the original source decision through signing and publication.

Both source states must match the full evidence's exact current sequence, head,
initial receipt and current receipt. An independent placement pin rejects an
ordinary copy or move. Capture does not start, seal, drain, retire or import a
source. It opens no archive objects. A source cannot advance while its observation
is published under the source guard. After release the observation is historical,
with no freshness or future exclusion claim. A missing output is recovered only
from the same sources/pins and explicit nonce, or by reading the exact already
published immutable artifact; changing the nonce is a different observation.

The signed public observation contains a salted placement commitment, not local
paths/inodes. Its signature binds evidence, original assignment/retirement,
source sequence/head/receipt, retention floor, resource anchor, role and nonce.
Different A/B commitments do not prove independent physical failure domains.

## No-refund review arithmetic

For old lifetime limit `L`, admitted operations `S` and stable resource cap `R`:

```text
available = min(L, R) - S
0 <= authorized <= available
unallocated = available - authorized
whole successor jobs = floor(authorized / 2)
```

Completed operations remain spent. Lower resource caps cannot make past spending
disappear; spending above the effective cap refuses preparation. The proposed
pending bound cannot exceed the old bound, resource bound or authorized allowance.
At least two pending units are required for the supported Audit/Serve job model.
This format supplies no budget-expansion authorization.

The successor Blueprint has a fresh incarnation, distinct participant keys and a
sorted, strict >2/3 job-witness roster of 4–16 keys. Job witnesses cannot reuse
participant/legacy consumer/auditor keys. The separate resource issuer and registry
witnesses cannot reuse any legacy or proposed participant/job-witness role.

A proposal contains the complete evidence, both original-source observations,
full stable resource descriptor, Blueprint and explicit allowance. Three separate
signatures cover that complete unsigned body: resource issuer, old A authority
and old B control. The semantic anchor ID and full descriptor ID are independently
pinned. The resource Genesis2 is public metadata here: no existing registry slot
is selected, reset or upgraded by this package.

The Blueprint alone is not an outer V2 assignment. The separate profile-5 importer
now deterministically derives the full assignment and initial source/spending
position from the signed Proposal. Its full registry selection commits those
bytes. Future activation must also check actual job and protected execution roles.

This review arithmetic becomes enforced accounting only through the separate
profile-5 importer and its selected admission witnesses. Native V2 histories
continue to start from their own genesis. An ordinary fresh native budget is not
a continuation of old spending; neither path activates imported execution.

## Reviewed CLI

`omd work-archive-custody-cutover-review` defaults to public review. It loads no
seeds and opens no owners. Review may read public artifacts and local placement
metadata; it does not establish live eligibility. Every execution uses unchanged
arguments plus `--mode run --expected-review-id <reported-id>`.

| Action | Required material / output |
| --- | --- |
| `import-genesis` | Full signed proposal and all independent pins including `--proposal-id`; derive the inactive profile-5 accounting genesis. See the separate imported accounting rules. |
| `history-export` | Complete Evidence JSON template with empty History and zero End; original `--authority` / `--authority-pins`; canonical full evidence output. |
| `assess` | Full `--evidence`; historical source, spending and retention assessment. |
| `source-location` | Complete `--source` SourceLocation JSON; metadata candidate output for independent review. |
| `observe` | Full evidence, SourceLocation, external `--placement-id`, `--anchor-id`, explicit `--nonce`, original role `--sign-key`; full signed observation output. |
| `proposal` | Evidence, canonical `--anchor`, A/B observations, complete `--blueprint` JSON and explicit `--allowance`; unsigned non-runtime proposal. |
| `sign-proposal` | Complete proposal, `--role issuer\|authority\|control` and matching seed; a fresh artifact retaining the accumulated signatures. |
| `verify-proposal` | Fully signed proposal; verified historical bridge report with ActivationAllowed=false. |
| `prepare` | Fully signed proposal, external `--proposal-id`, absent `--root`; original disabled preparation, with no `--out` selector. |
| `read-preparation` | Original root and exact independent pins; exact retained signed proposal to a fresh output. |
| `recover-preparation` | Same original root/pins; explicitly finish only the missing ready publication when the entire exact proposal already exists. |

Except `source-location`, all actions require `--legacy-id`, `--retired-sequence`
and `--retired-head`. Proposal actions also require `--anchor-id` and
`--descriptor-id`; all preparation actions require `--proposal-id`. Outputs are
fresh immutable files outside all selected owners, sources and key paths. Duplicate
flags, unused selectors, extra JSON fields/objects, duplicate JSON keys, ambiguous
fixed key arrays and implicit pin/nonce choices refuse. JSON uses the complete
public Go struct shape; arrays of public-key bytes have exactly 32 elements.

Review binds public artifact hashes, semantic pins, paths, source metadata, role,
nonce, allowance, seed path and output. Changing any reviewed input invalidates
execution review. A blocked native output pipe observes cancellation and releases
original guards; a broken output cannot discard an already retained artifact.

## Disabled preparation and recovery

The preparation retains exactly four private files: permanent `owner.lock`,
original root/lock placement, full signed proposal, and a ready marker committing
the proposal/resource/descriptor IDs. Creation is exclusive, with file and directory
synchronization. A partial creation is uncertain and its original root stays
retained. Cold open validates exact pins, canonical bytes, signatures, original
placement and the complete bounded file set.

Explicit recovery may finish a missing ready marker only after the full original
proposal and placement are present and verified. It never reconstructs a missing
proposal, replaces a candidate, chooses a new successor or resets an authority.
Ordinary copy/move, lock replacement, changed payload/marker/placement, unknown
files, wrong pins and concurrent opening refuse. A failed live read poisons its
handle; reopening is an explicit exact validation step. The journal enforces one
local preparation only; it does not provide globally unique resource enrollment.

## Canonical compatibility and launch boundary

All new objects use the separate `OMESH/custody-cutover-review/v1/` namespace:

| Object | Magic + version | Bound | ID suffix |
| --- | --- | --- | --- |
| Evidence | `OMCXEVD1`, u16 1 | 32 MiB | `evidence/id` |
| Source observation | `OMCXOBS1`, u16 1 | 347 bytes | `observation/id` |
| Blueprint | `OMCXBLP1`, u16 1 | 1,024 bytes | `blueprint/id` |
| Proposal | `OMCXPRP1`, u16 1 | 32 MiB + 4,278 bytes | `proposal/id` |

Observation signatures use `observation/signature`. Proposal signatures use
`proposal/signature/{issuer,authority,control}`. Old custody/fence/registry formats,
domains, completion rules and source files are unchanged. Existing execution and
registry decoders reject this review format; no consensus or network switch is
introduced. The four pinned codec vectors are in `node/custodycutover/codec_test.go`.

Local inode checks do not revoke raw keys, fence a full VM clone, prove no extra
resource descriptor was issued or establish protected independent witnesses. The
new observations/signatures are historical consent, not exclusion of old grants.
Protected monotone enrollment, runtime version fencing, active source handoff,
actual device failures, independent review and sustained
public-testnet evidence remain launch gates. Readiness remains **44/100**.

## Checks

```sh
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-all
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 go test -tags=integration ./cmd/omd -run '^TestProcessRemoteCutoverColdPreparationAndLostOutput$' -count=1 -timeout=2m
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 go test ./node/custodycutover -run '^$' -fuzz '^FuzzCutoverPublicArtifacts$' -fuzztime=5s
```

Coverage includes complete one- and two-cycle histories, opaque/unmatched
completions, source ordering, wrong pins and roles, budget/retention substitution,
original guard retention, six preparation write-fault boundaries, exact cold
recovery, copy/move/lock/marker/file substitution, concurrent detached reads,
strict JSON/CLI review, interrupted output, native process restarts and codec fuzzing.
A separate adversarial probe attaches a valid complete signed retirement/terminal
to an A source that accepted no result; no observation or output is published.

[Acceptance evidence](evidence/custody-cutover-review-20261028.json) records the
macOS race/process checks and the same native Linux binaries on two observed
kernels. Each native campaign uses local A/B sources and loopback transport;
this stage is not a new joint WAN migration or protected multi-domain deployment.

The [public manifest](evidence/custody-cutover-review-public-20261028.json) and
[seven-file archive](evidence/custody-cutover-review-public-20261028.tar.gz) retain
the complete signed proposal and its full evidence/observations, plus the review
reports. They contain historical test proofs, not private seeds or owner roots.
After extracting into an empty directory, verify against the separately trusted
manifest with a locally built current `omd`:

```sh
python3 scripts/verify_cutover_public.py --omd ./bin/omd --corpus /absolute/path/to/extracted-corpus --manifest docs/evidence/custody-cutover-review-public-20261028.json
```

The helper checks all file hashes, then invokes the production CLI with the
manifest's independently supplied resource/descriptor/legacy/retirement pins.
It confirms spent=2, authorized=2 and one whole possible job, with activation
disabled. A positive verification certifies historical fixture consistency only.
