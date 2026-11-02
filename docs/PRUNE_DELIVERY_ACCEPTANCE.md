# Scheduled Prune delivery acceptance

This campaign exercises the [scheduled delivery CLI](PRUNE_SCHEDULED_DELIVERY.md)
across two hosts. The receiver holds the original primary executor, selected
authority and their independent journals. The sender holds its original outbox.
Only the canonical plan, assignment, entry, inventory and intent cross hosts.

The [2026-11-02 evidence record](evidence/prune-delivery-wan-20261102.json)
contains four successful campaigns on two Linux amd64 hosts: both outcomes in
both transport directions, with sixteen original command stages in total.
All supervised children exited; no task process remained on either host. The
record retains source and binary hashes and the checked accounting assertions.

The campaign is test infrastructure. It uses public fixture keys and creates a
small original history with old pending work on the receiver. It does not open
production roots. Both transport directions can be tested with separate fresh
fixtures; within each fixture, every retry uses the same owners and outboxes.

## Execution and crash boundaries

The production `omd` binary performs intent review/publication, outbox creation
and inspection, service startup, delivery, local review and explicit recovery.
Separate integration-test binaries provide deterministic kill barriers. They
pause the existing store adapter at a named write boundary. No test fault flag,
network administration endpoint or recovery shortcut is added to `omd`.

The fixture driver pauses before each of four commands:

| Command | Controlled interruption | Required result |
| --- | --- | --- |
| Primary Admit | Kill the receiver before executor-pin confirmation | CLI startup refuses the pending write. Reviewed local `resume` confirms the original attempt; the same network intent can then be acknowledged. |
| Secondary Admit | Kill the receiver after original-owner confirmation, before its reply | The sender remains unresolved. A cold CLI retry confirms the exact historical entry without another append. |
| Primary Complete | Kill the sender after verifying the reply, before publishing its receipt | The original completion remains confirmed. The same outbox retries the same command and retains its receipt. |
| Secondary Complete | Kill the sender after receipt publication | Cold inspection verifies and re-syncs the visible receipt. Offline delivery returns that historical receipt without dialing. |

The first stage also checks an unreachable QUIC route and receiver SIGTERM and
SIGKILL while idle. Route discovery preserves the `/p2p/` transport identity from
readiness; the peer hash in the intent remains an independent pin. Removing that
route component would test invalid input, not a network outage.

The two outcome scenarios are cancellation before execution and a full retained
observed-effect settlement. The settlement scenario must reach both completion
commands and retain the full settlement ID. Other obligations, spent operation
history and executor outcomes are compared before and after recovery and retry.
Every complete run must contain two admissions and two completions.

The settlement setup uses the existing CLI fixture to seed a confirmed Started
record, obtain a real witness claim and commit an actual protected storage effect
without a session signature. Settlement and subsequent command delivery then use
that retained outcome. This setup does not test publication of the original
Started record; the separate store process tests cover that boundary.

These are process cuts and an unreachable route. Random packet-loss distributions,
long partitions, power loss and storage-device failure remain separate campaigns.

## Build and configuration

Use the repository's Go version. Build for the hosts' operating system and
architecture, including the two separate test executables:

```sh
go build -trimpath -o build/omd ./cmd/omd
go test -c -tags=integration -o build/omd.test ./cmd/omd
go test -c -tags=integration -o build/store.test ./node/custodyauthority/store
```

Install those files and `scripts/remote_acceptance/support.py` in a private build
directory on each host. Verify SHA256 after transfer. The runner independently
pins each executable before starting a supervised child and refuses different
binary hashes between the hosts. It does not transfer an initialized owner.

Provide a local JSON configuration. Replace the example addresses, host aliases
and build paths with the intended test placements. Each root must be a new
absolute directory beneath an existing canonical parent. Creation refuses an
existing root, including a partial prior campaign.

```json
{
  "version": 1,
  "scenario": "settlement",
  "server_ip": "192.0.2.10",
  "port": 46371,
  "a": {
    "kind": "ssh",
    "root": "/var/tmp/prune-acceptance-receiver",
    "binary": "/var/tmp/prune-build/omd",
    "test_binary": "/var/tmp/prune-build/omd.test",
    "store_test_binary": "/var/tmp/prune-build/store.test",
    "support": "/var/tmp/prune-build/support.py",
    "ssh": ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=30", "receiver"]
  },
  "b": {
    "kind": "ssh",
    "root": "/var/tmp/prune-acceptance-sender",
    "binary": "/var/tmp/prune-build/omd",
    "test_binary": "/var/tmp/prune-build/omd.test",
    "store_test_binary": "/var/tmp/prune-build/store.test",
    "support": "/var/tmp/prune-build/support.py",
    "ssh": ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=30", "sender"]
  }
}
```

The other scenario name is `cancellation`. Reverse `a` and `b`, choose new roots
and the new receiver's address to exercise the other transport direction. SSH
requires existing keys, an agent or a pinned control connection; configurations
must not contain passwords. The runner modifies no firewall or existing service.
It listens on the explicit dedicated test UDP port only during each server step.

```sh
python3 scripts/remote_acceptance/prune_delivery.py \
  --config acceptance.json --report acceptance-report.json
```

The report contains executable hashes, public intent/assignment/evidence IDs,
command phases, pending counts and the checked fault boundaries. It contains no
SSH configuration, seed, private owner path or raw command output. A successful
report requires all four stages and drained supervised children. An exception
leaves `completed` false; a partial report is not acceptance evidence.

Original fixture roots are retained on their originating hosts after the driver
exits, including failed cases. Inspect them before explicit task cleanup. Never
recreate an outbox or reset an owner as recovery. Starting a new campaign uses
new test data and does not resolve the failed campaign's original obligations.

## Local regression coverage

The same Python campaign runs against separate local processes for both outcomes
in `TestProcessPruneWANAcceptance`. It builds the production CLI and store test
binary, uses the current integration-test binary as fixture driver, and requires
four completed stages per scenario. CI and `make test-process` run this check.
The runner's input and accounting checks are also covered by
`make test-remote-support`.

The full-settlement CLI regression explicitly counts both admissions and both
completions. This closes an earlier fixture-selection gap where the delivery test
selected a closure-only branch and returned before completion. The implementation's
existing library settlement checks remain unchanged.

## Trust boundary

The receiver still needs the original primary executor and selected authority
locally. This campaign does not distribute owner capabilities, execute deletion
remotely or grant profile-5 Prune permission. Public fixture keys and two hosts
under shared administration do not establish independent copy fencing. Historical
receipts grant no current storage or execution permission. Public activation and
the production-readiness gates remain separate.
