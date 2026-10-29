# Same-assignment V1 WAN acceptance

This procedure runs one V1 assignment with A's original authority/pin/source
roots and B's separate original worker/source. It uses the
[position-zero CLI workflow](REMOTE_CUSTODY_BOOTSTRAP.md). Unlike the earlier
[V0 transport campaign](REMOTE_ACCEPTANCE.md), A and B do not have separate
assignment IDs or copies of an authority. Keys and original local roots remain
owner-controlled trusted inputs. This is not independent key/root copy fencing,
external security review or mainnet acceptance.

The standard-library controller is
[`v1_matrix.py`](../scripts/remote_acceptance/v1_matrix.py), with the individual
runner in [`v1.py`](../scripts/remote_acceptance/v1.py). The existing private
stdio supervisor/fault relay in `support.py` supplies bounded dedicated pipes
and opaque UDP loss/delay. No runner changes firewall rules, routing or clocks.
The relay has an exact loopback client and fixed B endpoint; application traffic
still verifies B's independently pinned transport identity.

## Artifacts and fixture boundary

Select and record a frozen source revision/manifest. Build with Go 1.27.3 for
the actual target architecture, using the same module inputs and build flags:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.3 go build -mod=readonly -p=2 -trimpath -buildvcs=false -o omd ./cmd/omd
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.3 go test -c -mod=readonly -p=2 -tags=integration -trimpath -o omd.test ./cmd/omd
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.3 go test -c -mod=readonly -p=2 -tags=integration -trimpath -o store.test ./node/custodyauthority/store
make test-remote-support
```

Deploy the same three executables to both explicitly selected hosts and compare
their SHA256 with the recorded build. `omd` is the normal binary. The CLI test
binary contains the opt-in exporter, seed-free inspector, B-only pause-config
builder and adversarial delayed-Start probe. `store.test` contains the private
B effect-boundary helper. No exporter, probe, pause environment or fault command
is reachable from the normal `omd` dispatcher. Its private sealed-response hook
is unset in ordinary operation.

For every independent scenario, the exporter generates new test keys and a new
incarnation. It exports only immutable archive/initial-receipt/object data and
never-started keys/nonces. It exports no assignment or initialized authority,
source journal, artifact root or worker. All those objects are created at their
destination through CLI. A's authority key is never installed on B. Audit and
Serve use different consumer keys; B also has separate control, transport and
replica evidence keys. Only immutable public signed artifacts cross between
the running roles.

The controller preserves private directories/files at 0700/0600, including after
Python's archive data filter drops directory modes. An initial rehearsal exposed
that filter behavior: the supervisor correctly refused a role root with public
permissions before applying its first admission. Private extraction is now
explicitly restored and covered by a regression test; root checks were not relaxed.

## Configuration and execution

Keep credentials and real configuration outside Git. Configure SSH authentication
and strict host-key verification beforehand; `ssh` is an argv array with an
already established agent/control socket, not a password or shell fragment.
Each host entry uses the existing fields documented in REMOTE_ACCEPTANCE.md,
plus `gate_binary` pointing at the pinned `store.test`. Additional top-level
fields are:

```json
{
  "export_parent": "/ABS/PRIVATE/exports",
  "expected_binaries": {
    "omd": "LOWERCASE_SHA256",
    "omd.test": "LOWERCASE_SHA256",
    "store.test": "LOWERCASE_SHA256"
  },
  "provenance": {
    "go": "go version go1.26.7 linux/amd64",
    "source_manifest": "LOWERCASE_SOURCE_MANIFEST_SHA256"
  }
}
```

The real configuration also supplies both `hosts` entries. Their `root` paths
are fresh role-root prefixes; the matrix adds a new scenario/UUID suffix.
Executable and supervisor paths live outside those role roots. Report/export
parents must be private. The runner checks both host clocks without adjusting
them, and records different observed kernel-boot hashes for two SSH hosts. These
observations identify the tested endpoints; they do not prove independent
hardware or failure domains.

The task's endpoints are A `127.0.0.1:43971` for the current control/data client,
A `127.0.0.1:43972` for the fault relay, and B public UDP `43980` for its pinned
QUIC host. Provision only their required reachability through the existing host
configuration. There is no public administrative relay endpoint.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/remote_acceptance/v1_matrix.py \
  --config /ABS/PRIVATE/hosts.json \
  --out-dir /ABS/PRIVATE/reports \
  --soak-cycles 32
```

Use `--scenarios healthy,partition-before,...` to select a smaller explicit set.
An optional configuration field `"require_placement": true` enables the
[local placement profile](REMOTE_CUSTODY_PLACEMENT.md) on the normal A/B CLI
runtimes. The controller explicitly enrolls A once and each fresh B worker,
retains their pins in checkpoints, and requires them on reopen. Its supported
scenarios are healthy, partition-before, loss-delay, both A restart cases and
soak. Private B pause helpers do not enforce this profile, so other scenarios
are refused before initialization. This option is local copy detection, not
independent protected-key fencing; its campaign is recorded separately.
The complete matrix is the default. Every scenario has a new fixture/assignment;
the soak instead retains one assignment and the SAME original A/B source roots
through all sequential cycles. No existing role root is reinitialized. New
cycles select the previously accepted predecessor/receipt and a new nonce/intent;
an interrupted cycle never obtains refreshed nonce, signed time or proof.
Each new intent/plan gets its own fresh B worker. Fault recovery within that
session reopens the same worker. The reuse check compares A's original authority,
pins/artifacts and both original source roots/locks; it does not reuse one worker
across different plans.

Every completed cycle is published as a separate exclusive, synced checkpoint
before the next cycle begins. Full private reports, config and logs remain in
the private output directory, including failed runs. Failure preserves original
root files and any uncertain obligation; it is not repaired by deletion or
automatic ticket completion. A cleanup failure cannot hide the original error.

## Scenarios and required observations

| Scenario | Required result |
| --- | --- |
| `healthy` | Both original source heads agree; independently complete Audit/Serve at A position six. |
| `partition-before` | A retains Begin and both tickets during loss; restoring the route admits one result without replacing scope. |
| `loss-delay` | Deterministic packet drops and delay still yield one matching result and explicit independent completions. |
| `a-restart-before-data` | Kill A after confirmed Begin; reopened original owner retains the hold before B can execute. |
| `a-restart-after-data` | Kill A after original acceptance; recover the same source/result and explicitly seal/complete. |
| `b-restart-before-result` | Kill B after data admission but before signing; reopened Started refuses fresh work, NoResult drain retains both ordinary tickets. |
| `b-restart-after-result` | Kill B after journal commit before response; recover only the exact cached result, preserving proof ID and RespondedAt. |
| `seal-reply-loss` | Kill B after durable seal/drain before its control reply; A still holds Begin. Metadata-only Reconcile does not confirm A's Drain; explicit Seal retains the same artifact. |
| `expired-cache` | After the original proof ages out, retry cannot sign a replacement or accept it at A. Drain may retain B's historical result; successful capture is refused and ordinary tickets remain. |
| `unseen-seal` | Failed Start followed by explicit Seal records Unseen, never a successful result or ticket completion. |
| `soak` | Sequential cycles reuse one assignment and original roots/locks; every fourth cycle includes loss/delay. Each closes two tickets and advances both sources once. |

All cycles also send the old Start directly through an authenticated live B
control connection after sealing. A transport timeout is not accepted as proof
of refusal. B must provide no Started confirmation, and retained inspection
must show the same sealed branch. This probe exists only in the integration
binary; the normal A operator already refuses execution without its original
active hold.

Private pause helpers run only at explicit effect boundaries, with B-only scope,
paths and keys. They use real host clocks. The process is actually killed, then
the normal server resumes the retained original worker. A marker triggers the
kill; it is not substituted for SDK replay/inspection of the durable branch.

The fixture policy's 20-second proof-age bound keeps the expiry scenario bounded;
it is a test policy, not a production-default change. Expiry waits use the tested
host clock. Every request lifetime remains fixed once its intent is published.

## Verify and publish evidence

The reporter revalidates the retained records rather than trusting `passed=true`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/remote_acceptance/v1_report.py \
  --input /ABS/PRIVATE/healthy/report.json \
  --input /ABS/PRIVATE/partition-before/report.json \
  --input /ABS/PRIVATE/OTHER_SCENARIOS/report.json \
  --require-matrix --out /ABS/NEW/sanitized.json
```

Supply all eleven reports with repeated `--input`. `--require-matrix` requires
the full scenario set and at least 32 cycles in one soak assignment. The reporter
checks common build/source pins, distinct original scenario assignments, exact
per-cycle result agreement, independent ticket completion, monotone source and
authority positions, stable original root/lock identities, actual relay counters,
delayed-Start refusal and negative-branch retention. Its public index contains
no real host address, SSH config, seed, private root path or raw log; hashes bind
it to the corresponding private reports. Outputs never replace existing bytes.

## Recorded 2026-10-27 campaign

The [sanitized index](evidence/remote-custody-wan-20261027.json) records all eleven
scenarios passing on two selected Linux/amd64 hosts with different observed
kernel boots. Ten scenarios each used a fresh assignment; the separate soak
completed 32 cycles on one assignment and the original source/authority roots.
It finished at A authority position 192, both source positions 32, zero ordinary
pending operations and no active remote hold. Loss/delay ran every fourth cycle.
Across the full campaign, 42 cycles completed: 39 successful cycles independently
completed 78 tickets, while three negative scenarios retained their ordinary
tickets. Every sealed session refused the direct authenticated delayed Start.

Native artifacts were built with Go 1.26.7, CGO_ENABLED=0, offline/read-only
module inputs, trimpath and two build workers (92.161 seconds). Artifact hashes
matched on both hosts and remained unchanged. The 620-file Go/module source manifest
was unchanged locally and on the build host:

```text
f9b0d488f2bce40e8ecb439126dadb7df81e9efd95557129ec75d4490ec56190
```

The manifest format is sorted relative paths with SHA256(file bytes), two spaces,
path and LF for every tracked/new `.go`, `go.mod` and `go.sum` file. The public
index also binds the operating controller and each retained private report.

Go 1.26.7 make test-all passed formatting, full vet and all five disjoint race
groups (store 239.156, 293.799, 151.987, 151.863 and 80.388 seconds), without a
timeout increase. Integration-tag vet passed. The focused sealed-reply race
test passed (store 5.494 seconds); existing process recovery checks passed
(store 9.794 seconds). The opt-in fixture/probe helpers executed in the native
WAN campaign; without their environment they intentionally skip. All 25 Python
supervisor/controller/reporter tests passed.

After acceptance, all three deployment hashes and the private supervisor were
checked again on both hosts. No task process or socket bound to the test UDP
ports remained, and both temporary SSH masters were closed. Original scenario
workspaces, including the earlier extraction-permission refusals, remain retained.
No raw deployment configuration, role seed, root path, real host address or log
is published in the index.

This is controlled fault/reuse acceptance with owner-controlled keys. It does
not implement negative ticket closure, fence independent key/root copies, prove
physical-device durability, satisfy sustained public-testnet duration, provide
an external audit, or authorize real-value mainnet operation.

The next [negative-disposition work plan](REMOTE_CUSTODY_NEGATIVE_PLAN.md)
separates evidence capture, uncertainty/retention rules and independently
reviewed ticket settlement. In particular, NoResult remains an unknown outcome;
this campaign does not turn it into cancellation.
