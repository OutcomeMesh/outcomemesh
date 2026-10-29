# Custody V2: joint two-host fault acceptance

Status: controlled experimental acceptance, 2026-10-28. This extends the
[V2 job/target protocol](CUSTODY_V2.md); it neither activates consensus nor closes
Serve obligations. Four logical witnesses run on two observed Linux kernels,
two witnesses per host. This is not four protected independent failure domains.

## What runs on each host

A holds its original source, authority/audit consumer/client keys, and witnesses
0–1. B holds its own original source/objects, Serve consumer/control/replica and
transport keys, and witnesses 2–3. Audit, authority and Serve signatures are
produced by normal CLI processes on their respective hosts. The canonical Context
must equal the independently pinned fixture job before any owner is created.

The integration-test exporter supplies immutable real archive data, never-started
empty source headers, fresh nonces/incarnations, unsigned public draft data and
**public deterministic test seeds**. No live owner, session key, admitted witness
slot or accepted source is transferred. A's private role files are excluded from
B's fixture. An additional never-started B fixture supplies the deliberately
copied persistent participant used by the negative test. These fixtures must not
be used for funds or deployed trusted witnesses.

All effects, witness votes/commits, result extraction, bundle assembly, original-A
acceptance and receipt recovery use normal `omd` CLI commands. Test-only helpers
export fresh inputs, inspect original sources without signing, and send bounded
authenticated hostile packets that the ordinary client would reject locally.
Those helpers are absent from the normal executable.

## Fault matrix and observed source positions

Each row uses a fresh assignment/job/scope and retains its original roots.
Failed attempts are never recovered by deleting a slot or reusing a scope.

| Scenario | A / B / cold copy source positions | Final witness state |
| --- | --- | --- |
| Result reply lost after B's source commit | 1 / 1 / 0 | All four at position 3, ResultRecorded, same session, obligation held. |
| B killed after Claim, before execution | 0 / 0 / 0 | All four at position 2, Unknown, same original session, obligation held. |
| B result exceeds A's proof-age limit | 0 / 1 / 0 | All four at position 2, ResultRecorded, same session, obligation held. |

Every row stops the two A-side witnesses: the remaining two votes fail quorum
assembly. Repeating one member also fails. Returning one original member permits
the 3/4 claim. A witness is then SIGKILLed with its pending vote retained; stale
cold pins fail, while exact restart/replay returns the same signed response.
Minority catch-up uses the actual certificate, never an adopted local snapshot.

In the lost-result row an opaque UDP relay initially delays delivery. Once the
B result marker is observable (which follows B's durable source append), the
controller drops the reverse path and clears queued reverse packets. The client
must fail without retaining a response. The campaign records queue/partition
drop counters and verifies the full retained B result after SIGKILL. This is a
process-failure/delivery test, not a power-loss or storage-device durability test.
The resumed target refuses another Execute and recovers the original signed
result through Claim/Unknown/Result. Original A accepts exactly that entry.
Breaking the accepting process's stdout loses its output but preserves its
source receipt; a new normal CLI process returns the identical receipt bytes.

In the lost-session row the prepared private session disappears when B is killed
before execution. The old quorum cannot activate a newly prepared session.
Witnesses reject its stale new Claim; Unknown preserves the original obligation.
RecoverResult cannot manufacture a result from the empty original source.

In the expired-result row, the full typed result quorum remains valid historical
evidence. A still refuses acceptance after the actual proof-age limit. A retains
neither a source append nor pending acceptance. Reopening B returns the same
proof time/bytes, and another Execute is refused. A freshly opened cold copy of
the persistent B participant likewise cannot import the original live session or
consume its old grant; its source remains zero. The campaign does not copy RAM.

Actual authenticated weak-quorum, wrong-scope, legacy-protocol and late-execution
probes are also refused. Inspectors compare complete custody/receipt signatures,
original source heads and root/lock identities, not only file existence or an
opaque result digest. All test processes and selected UDP listeners are checked
absent after cleanup; existing V1 roots are not used.

## Unknown proposals through the operator CLI

`work-archive-custody-v2 --action sign-unknown` takes the normal independently
pinned Context/scope, `--claim FILE --claim-id V2_ARTIFACT_ID`, a nonzero
`--evidence-id` observation commitment, `--sign-key` for the selected authority,
and an immutable `--out` outside owner/source roots. Review is keyless and opens
no owner. `--mode run --expected-review-id REVIEW` signs only after validating the
full claim quorum. The review binds the evidence commitment too.

The output is a controller-signed proposal, not a certificate or a disposition.
Collect and commit its quorum through the existing witness commands. It cannot
execute, prove absence of physical work, release retention, close Serve or select
a timeout winner. Partial, old-version or unrelated claim quorums fail before
signing. The WAN controller commits the actual signed missing-response observation
before requesting this proposal.

## Reproduction

Use Go 1.27.3, pure Go native Linux builds, the pinned module cache and the
integration-tagged `omd.test`. The built-in test helpers are opt-in:

- `TestExportCustodyV2WANFixture`: private `OUTCOMEMESH_REMOTE_FIXTURE_OUT` and
  `OMESH_V2_SCENARIO=lost-result|lost-session|expired-result`.
- `TestInspectCustodyV2WANFixture`: original `OUTCOMEMESH_REMOTE_ROLE_ROOT`.
- `TestCustodyV2WANProbe`: the same private role root and a fixed bounded probe
  selection; it cannot sign custody evidence or advance A's source.

`scripts/remote_acceptance/v2.py --config PRIVATE_CONFIG --out PRIVATE_REPORT`
runs the matrix. Config contains existing local SSH control argv, independently
pinned binary/support hashes and dedicated paths/ports, **never passwords**.
Each host entry uses the existing `Host` schema (`kind`, `root`, `binary`,
`test_binary`, `support`, `ssh`, `public_ip`). Top-level fields are
`expected_binaries`, `source_manifest`, `support_sha256`, `export_parent`,
`target_port`, `relay_port`, `client_port`, and `witness_port` (four consecutive
ports). The relay front and exact client endpoint stay loopback-only on A;
upstream is the selected B target. Firewall, host clocks, SSH settings and
unrelated services are not modified.

The report validator rejects missing scenarios, reused scopes, incomplete witness
transcripts, changed pins, duplicate-member quorum claims, divergent final
sessions/heads, released obligations and incorrect original-source counts.
Python unit tests cover the V1 response layout and corrupted reports. The normal
repository race groups, focused CLI/process/integration checks and integration
vet accompany the network campaign. The
[sanitized acceptance index](evidence/custody-v2-wan-20261028.json) pins their
source/binary/script provenance and reports the exact checks performed.

## Public signed evidence and limits

The [public artifact manifest](evidence/custody-v2-wan-public-20261028.json) pins a
[small archive of canonical signed artifacts](evidence/custody-v2-wan-public-20261028.tar.gz):
Contexts, scopes, commands, actual quorum certificates, request/response
transcripts, full custody results/bundles and the successful accepted-source
receipt. It excludes seeds, private roots, journal files and host addresses.
Archive hashes/paths are checked and the full public certificate histories,
result/bundle signatures and receipt are verified again with the production Go
APIs (`Context.Scope`, `State.Apply`, `Bundle.Verify`, `Receipt.Verify`). This is
historical verification; it cannot replace inspection of the original live source.
The expired row intentionally has a valid historical bundle and no A receipt.

Still open: protected execution/session keys and four independently protected
witness domains; an adversarial implementation can persist/copy its own session
secret. Also open are assignment-wide admission/budgets and activation/migration,
independently certified Serve resolution, safe split-vote progress, external audit
and sustained adversarial testnet/calibration gates. A successful two-host
campaign does not waive these requirements or raise the weighted launch score.
