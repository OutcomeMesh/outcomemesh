# Remote acceptance procedure

This runbook exercises custody exchange and ordinary devnet synchronization on
two explicitly configured hosts. The controller runs
[`run.py`](../scripts/remote_acceptance/run.py) or
[`chain.py`](../scripts/remote_acceptance/chain.py); each host runs the private
stdio supervisor in [`support.py`](../scripts/remote_acceptance/support.py).
Python uses the standard library. SSH authentication and host verification are
configured outside these scripts.

This document describes the procedure and expected assertions. A scenario is
evidence only after its actual run finishes successfully and its report is
retained. Record completed runs separately in [STATUS.md](STATUS.md).

The [2026-10-27 sanitized record](evidence/remote-acceptance-20261027.json)
contains five completed custody scenarios and the ordinary chain run on two
provided Linux VPS instances. It includes source/artifact commitments, observed
states and scenario assertions. Private raw reports retain the corresponding
deployment details; their digests bind the public summary to those records.

## Scope and ownership

Custody role A owns an Audit assignment and role B owns a different Serve
assignment. They have distinct authority keys, consumer keys, assignment IDs,
local coordinators and pin roots. They exchange one identity-pinned challenge
and response over QUIC. This does **not** distribute one assignment's authority
across two servers.

The separate [V1 WAN procedure](REMOTE_CUSTODY_WAN.md) uses one assignment,
A's original authority and a separately bootstrapped B worker/source. Keep its
scenario records distinct from this earlier two-assignment transport campaign.

The exporter declares `AllPurposes` for each fresh test consumer because the
reference assignment requires complete purpose coverage. The procedure admits
only A's Audit operation and B's Serve operation. It creates no Prune ticket.
Capture, recovery and successful delivery do not complete a ticket; the driver
separately reviews, signs, co-signs and applies each completion.

Use dedicated test hosts or dedicated owner-controlled workspaces. Create a new
export and new destination roots for every custody scenario. The installer
rejects an export containing `authority` or `authority-pins`, then bootstraps
those roots once at their destination. Never copy an initialized authority/pin
root, a running participant journal, or an old scenario into a replacement run.
Retain failed workspaces for inspection; do not repair them by deleting locks,
pending attempts, journal entries or evidence.

The ordinary chain procedure creates separate new ledgers and new miner and
transport keys on each host. It does not copy a ledger, wallet seed or transport
seed from an existing node.

## Prepare builds, hosts and transport first

1. Select and record the source revision. Build with the repository's pinned
   `go1.27.3` toolchain. For a manual toolchain installation, select the matching
   version/OS/architecture archive and verify its SHA256 against the
   [official Go download metadata](https://go.dev/dl/?mode=json&include=all)
   before unpacking it. Retain the archive name and digest in the run's private
   provenance record.
2. Use two Linux hosts of the same target architecture for a run that compares
   identical executables. Deploy the same normal `omd` artifact and the same
   integration-test artifact to A and B. Compare each installed SHA256 with the
   corresponding local artifact and with the other host before exporting the
   time-bounded fixture. Record Go version, target, source revision and both
   artifact digests. The supervisor rechecks the pinned executable digest on
   each child start.
3. Install the current `support.py` on both hosts. Prepare Python 3, Linux `tar`,
   free task ports and private storage. Prepare and verify SSH keys/agent,
   known-host entries and ControlMaster connections before starting the fixture
   clock. No password, private key, real host configuration or raw report belongs
   in Git.
4. Keep workspace/export/report parents at mode `0700` and private config, seed,
   export metadata and report files at mode `0600`. Each remote `root` must be a
   fresh path, not an existing deployment. Keep executables and `support.py`
   outside that fresh role root so installation can create the role exclusively.
5. Check the two host clocks before the run. Do not change clocks or edit signed
   times to rescue an expired fixture.

Example builds from the selected source revision, for Linux amd64 targets:

```sh
mkdir -p bin
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -o bin/omd-native ./cmd/omd
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go test -c -tags=integration -trimpath -o bin/omd-native.test ./cmd/omd
GOTOOLCHAIN=go1.27.3 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/omd-linux-amd64 ./cmd/omd
GOTOOLCHAIN=go1.27.3 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags=integration -trimpath -o bin/omd-linux-amd64.test ./cmd/omd
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/remote_acceptance -p 'test_*.py'
```

On a macOS controller, `omd-native.test` is the native executable used for the
local fixture export. Linux executables are separate deployment artifacts;
cross-compiling them does not execute or validate them on macOS. A local
rehearsal uses native executables and `kind: "local"` for both hosts, with
disjoint roots and B's `public_ip` set to a reachable local address. Such a
rehearsal does not establish two-host WAN transport.

Only the integration-test binary contains the fixture exporter, inspector and
response gate. They are absent from the normal `omd` dispatcher. Deploying a
test binary for this procedure does not add a production fault-control switch.

## Private controller configuration

Write the real configuration outside the checkout with mode `0600`. The values
below are placeholders. SSH aliases resolve through separately maintained host
and authentication configuration; `ssh` is an argv array, not a shell fragment.
Use a private existing directory for ControlMaster sockets.

```json
{
  "hosts": {
    "a": {
      "kind": "ssh",
      "root": "/srv/outcomemesh-acceptance/roles/UNIQUE-RUN-a",
      "binary": "/srv/outcomemesh-acceptance/bin/omd-linux-amd64",
      "test_binary": "/srv/outcomemesh-acceptance/bin/omd-linux-amd64.test",
      "support": "/srv/outcomemesh-acceptance/support.py",
      "ssh": ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ControlMaster=auto", "-o", "ControlPersist=600", "-o", "ControlPath=/ABS/PRIVATE/ssh-%C", "HOST_A_ALIAS"],
      "public_ip": "HOST_A_PUBLIC_IP"
    },
    "b": {
      "kind": "ssh",
      "root": "/srv/outcomemesh-acceptance/roles/UNIQUE-RUN-b",
      "binary": "/srv/outcomemesh-acceptance/bin/omd-linux-amd64",
      "test_binary": "/srv/outcomemesh-acceptance/bin/omd-linux-amd64.test",
      "support": "/srv/outcomemesh-acceptance/support.py",
      "ssh": ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ControlMaster=auto", "-o", "ControlPersist=600", "-o", "ControlPath=/ABS/PRIVATE/ssh-%C", "HOST_B_ALIAS"],
      "public_ip": "HOST_B_PUBLIC_IP"
    }
  },
  "chain_roots": {
    "a": "/srv/outcomemesh-acceptance/chains/UNIQUE-CHAIN-a",
    "b": "/srv/outcomemesh-acceptance/chains/UNIQUE-CHAIN-b"
  }
}
```

`root`, `binary`, `test_binary` and `support` are absolute paths on their
respective host. `public_ip` is a numeric reachable IP, not a DNS name. The
custody driver uses IPv4 routes. `chain_roots` is optional and overrides only
the root paths used by `chain.py`; it accepts only `a` and `b`.

The task uses these UDP endpoints:

| Host | Endpoint | Purpose |
| --- | --- | --- |
| A | `127.0.0.1:43871` | Fixed auditor QUIC listen endpoint |
| A | `127.0.0.1:43872` | Fault relay front; accepts only `127.0.0.1:43871` |
| B | public IP, port `43880` | Custody Serve endpoint reached by the relay's connected back socket |
| B | public IP, port `43884` | Ordinary devnet QUIC server used by `chain.py` |

Provision reachability only for the task's required endpoints using the
operator's existing network configuration. The runners do not change firewall
rules, routing tables or `tc`. The relay has no public front or administration
socket. It forwards opaque datagrams between its exact configured endpoints;
the application still verifies the pinned B transport identity.

## Export last, then run one custody scenario

Finish builds, deployment, configuration and SSH preparation before export.
The exporter fixes the original intent's issue time, nonce and expiry once.
The intent lifetime is **600 seconds** and the proof-age policy is **120
seconds**. Neither the exporter nor the driver refreshes those times on retry.

Create an existing private local parent, then run the **native** integration-test
binary:

```sh
acceptance_workspace=/ABS/PRIVATE/acceptance
install -d -m 700 "$acceptance_workspace" "$acceptance_workspace/exports" "$acceptance_workspace/reports"
OUTCOMEMESH_REMOTE_FIXTURE_OUT="$acceptance_workspace/exports" bin/omd-native.test -test.run='^TestExportRemoteCustodyFixture$' -test.count=1
```

The `remote_custody_fixture` record reports a new `root=.../fixture-...`, both
assignment IDs and `intent_expires_at`. Its child contains `role-a`, `role-b`
and `summary.json`. The generated role metadata and `commands.json` retain
exact pins and fixed command templates; the export contains fresh test seeds.
Keep the whole export private. Do not hand-edit its scope, keys or timestamps.

Immediately run the controller, substituting the reported fixture root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/remote_acceptance/run.py \
  --config /ABS/PRIVATE/acceptance/hosts-UNIQUE-RUN.json \
  --fixture /ABS/PRIVATE/acceptance/exports/fixture-REPORTED \
  --scenario healthy \
  --out /ABS/PRIVATE/acceptance/reports/healthy-UNIQUE-RUN.json
```

The output parent must exist and `--out` must be a new path. Preserve controller
stdout/stderr privately too. The driver transfers only the never-started role
export using a Python-generated archive, avoiding macOS AppleDouble metadata
that would correctly invalidate an existing-only journal layout. It then
bootstraps each original local authority, reviews/signs/applies the selected
admission, prepares A's exact challenge and transfers that immutable challenge
to B.

Repeat export and choose new A/B destination roots and a new report path for
each scenario below. Do not reuse one expiring export for the whole matrix.

| `--scenario` | Injected condition | Expected assertions |
| --- | --- | --- |
| `healthy` | Normal two-host QUIC exchange | Both journals reach sequence 1 with the same proof, receipt, head and original `RespondedAt`; explicit completions follow. |
| `partition-before` | Relay drops all packets before the request | Failed exchange leaves both journals at 0 and both admitted operations incomplete; restoring the route permits the exact selected exchange. |
| `partition-after-replica` | B commits its journal before the first custody application response write; relay is partitioned and B is killed | A remains at 0 while B is at 1; restart/retry returns B's original proof and receipt without refreshing `RespondedAt`. |
| `loss-delay` | Drop every seventh received datagram per direction and delay forwarding by 40 ms per direction | QUIC completes the selected exchange despite deterministic loss/delay; both committed results agree. |
| `expired-proof` | Same post-B-commit partition/kill, then wait past the original 120-second proof age | A remains at 0 and B at 1; the retry is rejected and both retained states remain unchanged. Both operations deliberately remain incomplete. |

The last row treats rejection as its expected successful assertion. It does not
force a completion or mint a replacement proof. A pending admitted operation
here is distinct from an uncertain authority append (`pending_attempt`); a
failed custody exchange must not create an uncertain authority attempt.

The post-commit gate is `TestRemoteCustodyGatedServeHelper`, enabled only in the
integration-test binary with a private `OMESH_REMOTE_GATE_ARGS` file. It retains
B's original owner and pauses the first custody application `Write` after the
durable journal commit. QUIC handshake traffic may already have flowed. The
driver observes `journal_committed=true`, enables the partition, explicitly
releases the gate and kills the selected helper after the failed exchange. A
packet counter or elapsed sleep alone does not establish that commit boundary.

For non-expiry scenarios, the driver stops B and calls `relay.stop` **before**
the reviewed offline `recover` action. It checks the original proof ID, then
captures separate terminal envelopes and explicitly completes A and B. The
final exact completion retry must report `Appended=false`. Recovery must not be
credited as offline merely because teardown packets stopped arriving.

## Review framing, cancellation and retained evidence

The supervisor exposes JSONL over dedicated SSH stdin/stdout only. Each process
name selects a fixed spec argv whose executable is SHA256-pinned. Role path
environment is fixed in the spec, confined to the private task root and allowed
only for the declared test binary. It is not a remote shell service.

The driver sends `review`, then uses one `until` RPC to consume the exact full
scope through its LF-terminated `*_scope_end` marker. The RPC is bounded by
8,192 lines, 1 MiB of UTF-8 data and a 45-second overall deadline; the driver's
review call uses 40 seconds. This avoids one WAN round trip per scope line.
EOF, partial frames, overflow or a deadline failure cancel that child and return
no partial review. Only after the full report does the driver explicitly send
an action with the same-session review ID. Neither the supervisor nor a
reconnection automatically replays controls.

Controller EOF closes the dedicated child inputs and cleans up only children
started by that supervisor. Failure or lost output can follow a durable commit:
retain the exact canonical files and original journals, drain the selected
owners, inspect them, and use a separately reviewed explicit retry/resume when
appropriate. Do not infer an absent effect from missing stdout.

Reports contain executable digests, scenario, assignment/challenge commitments,
inspected before/after states, relay counters and the applicable recovery or
expiry assertions. Keep raw reports, routes, workspace paths, configurations
and seeds private. A public evidence summary should retain the source/build
provenance and relevant committed IDs/assertions while removing deployment and
authentication details.

## Ordinary devnet restart, outage and fork procedure

`chain.py` uses the same host configuration and installed executables. It does
not need a custody fixture. Set fresh `chain_roots` or use completely fresh
`hosts.*.root` values; create their private parent directories beforehand.
The script creates each leaf root exclusively and does not recursively create
its parent, delete an old root, or resume an existing ledger.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/remote_acceptance/chain.py \
  --config /ABS/PRIVATE/acceptance/hosts-UNIQUE-CHAIN.json \
  --out /ABS/PRIVATE/acceptance/reports/ordinary-chain-UNIQUE-CHAIN.json
```

The expected sequence uses isolated development network `20261027`, genesis
timestamp `1700000000`, difficulty bits `0` and a 64 MiB history limit:

1. Initialize the same development genesis independently and generate distinct
   miner/transport keys on each host. B mines three blocks; A synchronizes over
   direct identity-pinned QUIC on B's port `43884`.
2. Drain serving before independent full replay/status checks. Crash B's server,
   require disconnected synchronization to fail without changing A's retained
   history, then restart B and verify healing.
3. With the route unavailable because the owned server is stopped, mine two
   additional blocks on A and four on B. Retain different first fork blocks,
   heights 5/7 and B's greater cumulative work. Restore serving and require both
   nodes to select B's height-7 tip/state/work/resources, verified by full replay.
4. Crash/restart B again and require exact repeat synchronization to leave both
   retained ledgers unchanged. Record the server identity across restarts and
   both owned process crash outcomes.

This partition model is a controlled server-process outage, not a firewall or
physical-link failure. Distinct WAN host attribution comes from operator
configuration. The development genesis and easy mining establish no monetary
value, production performance or mainnet difficulty behavior.

## Evidence boundary

A completed run can establish the reported process, storage, authenticated
transport and replay assertions for its exact source, binaries, endpoints and
time window. Two configured VPS endpoints do not establish independent physical
operators, disks, power or failure domains. These procedures do not provide
copied-owner fencing, distributed authority freshness, an independent security
audit, physical power-loss testing or sustained adversarial testnet duration.
Keep those launch gates separate from individual scenario results.
