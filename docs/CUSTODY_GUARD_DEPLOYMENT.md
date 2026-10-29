# Guard deployment with separated access

Use a dedicated guard UID, a private original store, and a separately retained
identity and monotone cursor. Participant UIDs must not read or write the guard's
key, store, parent directories, executable or configuration. The guard must not
share participant backup/restore jobs. The current two servers share an operator;
UID separation and an authenticated route do not create an independent operator,
protect against root compromise, or make the guard itself uncloneable.

The built-in guard HTTP listener now accepts only literal loopback addresses.
Clients reject non-loopback plain HTTP, including DNS names that might resolve
differently later. Remote deployments need an authenticated SSH tunnel or HTTPS
terminated by a separately configured authenticated service. Signed subjects and
pinned guard seals remain mandatory inside the transport. HTTP redirects and
proxy environment variables remain disabled. HTTPS uses the normal trusted
certificate roots and hostname verification.

A direct server-to-server tunnel can forward a participant-local loopback port to
the guard's loopback port. Provision a dedicated SSH identity limited to that
forward, pin the server host key, disable shell access for the tunnel identity,
and keep its key outside participant snapshots. Do not expose the guard's HTTP
port on 0.0.0.0. Local users that can reach the forwarded port still need an
allowlisted subject's signature to request a choice.

The unit template in `deploy/custody-guard/omesh-custody-guard.service` runs under
`omesh-guard` with no capabilities, a restricted filesystem and no automatic
restart. Provision the private original store before installing it; it is never
created from an empty directory as a recovery shortcut. Root owns the binary,
unit, `/etc/outcomemesh` and the independently reviewed public pins. The guard UID
owns `/var/lib/outcomemesh-guard/original` and its private files. Keep the store's
canonical path and native identities unchanged.

Run the exact command from ExecStart in review mode first. Put only the resulting
`GUARD_REVIEW_ID=...` in root-owned `/etc/outcomemesh/guard.env`. Every restart needs
the independently retained Position and a matching review. Lost-response recovery
uses the existing exact request/revocation/replacement artifact. Do not read a
possibly restored guard store and call its self-reported tip an external pin.
Observer events must be retained outside the participant/guard backup set;
journald alone is not an independent monotone authority. A cursor older than the
store is refused unless the exact permitted recovery artifact explains it.

## Bounded two-host deployment

`scripts/guard_acceptance` generates fresh disposable signed public requests and
verifies returned seals. `scripts/remote_acceptance/guard.py` creates a new dedicated
`/var/tmp/omesh-guard-*` directory on each authorized SSH host, runs the guard as
an unused non-root UID on A, and sends requests as UID 65534 on B. It uses existing
SSH control connections; configuration contains no passwords. The campaign route
passes through the operator workstation, so that workstation is an availability
dependency. It is not a long-running direct production route.

Configuration fields are `ssh_a`, `ssh_b` (complete SSH argv including the host),
`binary` (Linux amd64 omd), `fixtures` (fresh generator output including the Linux
amd64 verification helper), `root`, `uid`, `guard_port`, `local_port`, and
`client_port`. An optional `binary_cache` names a previous campaign binary on A;
its SHA-256 must equal the local binary before reuse. Use distinct unused high ports and a fresh root for every run.
Original evidence remains on both hosts. The runner stops only its guard process
and removes only its own forwards on completion or error; it does not change the
firewall or shared node services.

The sequence covers a valid choice, a signed conflicting choice, external cursor
retention on B, tunnel loss, process death, rejection of a stale restart pin,
restart at the exact retained position, byte-identical retry and a subsequent
choice. Its report records access refusal under the participant UID. It does not
establish independent administration, hardware monotonicity, power-loss durability
or long-retention availability. Those gates remain open.


The 2026-10-29 two-host run completed with two accepted choices, two refused
conflicts (before and after restart), a refused stale restart cursor, a retained
byte-identical reply and a refused request during tunnel loss. Guard UID 65531
and participant UID 65534 were separate; the participant could not read the
original guard key. B retained cursor sequences 1 and 2. The campaign stopped its
guard and removed its forwards afterward. The deployed binary SHA-256 was
`2d1ca4a26bdb496666de55e00f37840e3fea8bcb6e4fa95ac3ad034baae6fc00`.
The public result is retained in `docs/evidence/guard-deployment-20261029.json`.
