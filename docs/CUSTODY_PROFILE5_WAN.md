# Protected profile-5 across two hosts

The profile-5 network adapter carries the existing signed gateway envelope over
an explicitly enabled authenticated QUIC protocol. It does not create another
execution owner or make raw imported V2 constructors executable. See the
[execution contract](CUSTODY_PROFILE5_EXECUTION.md) for admission, source,
consumption, result, Serve and recovery rules.

## Transport and privilege boundary

`/outcomemesh/custody-gateway/5` is separate from legacy custody, witness and
archive protocols. A relay runs as the descriptor's unprivileged ParticipantUID.
It owns only a network transport key and the public descriptor/socket path. It
cannot open a service root, read archive objects, import a session key, sign an
execution result or select a different source. The local owner still checks the
kernel peer UID, exact signed request, current cursor and all profile-5 evidence.

The network side independently pins the relay's transport peer and the complete
issuer-signed gateway descriptor. Transport admission is an explicit allowlist of
at most 16 peers, with eight active streams and 256 admitted streams per minute.
Each stream has one bounded request, complete request EOF, one signed response
and complete response EOF. Both sides retain the existing ten-second upper
bound. A wrong peer, descriptor, actor, payload hash, frame length or trailing
request is refused before local forwarding. A local signed reply is verified
again before the relay returns it; the caller verifies the same response against
its exact original request. There is no automatic retry or fallback protocol.

The endpoint forwards Runtime envelopes only. Local inspection, raw chunk reads
and permanent issuer revocation are not exposed through this relay. The endpoint
is a delivery channel, not a new authority or an atomic cross-host lock. A relay
can withhold a response; that is an unknown outcome, never a refund or permission
to choose a different attempt.

## Reviewed operator CLI

`omd work-archive-custody-relay` defaults to review. Run the exact reviewed
arguments with `--mode run --expected-review-id <id>`. The review commits the
complete public input hashes, descriptor/peer IDs, key path, endpoints, request,
output and timeout. Review loads no private key, opens no owner and makes no
network connection. Missing `/p2p/<peer>` identity or a mismatch between that
address and the independent `--peer` pin fails during review.

- `--action serve`: `--descriptor`, `--descriptor-id`, `--key` (transport seed
  file), `--socket`, `--listen` (QUIC multiaddress), `--clients` (allowlisted
  OutcomeMesh transport peer IDs). Run as ParticipantUID; OwnerUID is refused.
- `--action call`: `--descriptor`, `--descriptor-id`, `--key` (client transport
  seed file), `--address` (complete QUIC address including `/p2p/...`), `--peer`,
  `--request` (exact signed Runtime envelope), and a fresh `--out` response path.
  Optional `--client-listen` selects the local QUIC binding. `--timeout` defaults
  to ten seconds and cannot exceed it.

A call makes exactly one attempt and publishes only a verified complete response.
After an unconfirmed send, retain that exact envelope and its independently kept
before-position. Restart the original gateway with the base CLI's exact recovery
request, explicitly clean its pinned stale socket, and retry the original bytes.
Changing a nonce, using a fresh root or adopting an observed tip is not recovery.
A completed reply is historical evidence; current downstream freshness checks
remain mandatory.

## Reproducing the controlled campaign

The acceptance driver is `scripts/remote_acceptance/profile5.py`; the task-private
stdio supervisor is `profile5_host.py`, using the existing bounded opaque UDP
fault relay from `support.py`. It requires Linux root launchers, two already
pinned SSH connections, identical prebuilt binaries, public test fixtures, a fresh
placement on each host and unused UDP ports. It does not modify users, firewall
rules or system services. EOF/exit terminates only its own tracked processes.
Old task roots are retained, never reset to make another run pass.

The JSON configuration supplies `ssh_a`, `ssh_b` argument arrays with strict
host-key checks, `build`, a fresh `root` prefix, `ip_a`, `ip_b`, `port`, and
independently computed fixture transport `peers` for A, B and the client. The
build directory contains `omd`, `omd.test`, `relay.test`, `binaries.json`,
`fixture/public-fixture`, the supervisor and `support.py`. It must be traversable
by ParticipantUID; private source/service roots remain mode 0700. No password is
stored in the configuration or repository.

Each host creates only its own original source and service identity. Public
observations, the selected import, source pair and five-endorsed deployment are
exchanged. The campaign never copies or relocates a live owner, journal, session
or service key. Four original admission/job/Serve witnesses are split two per
host, with threshold three. Their public voting/commit artifacts use the pinned
SSH control channel; this is not a new witness-QUIC acceptance claim.

The `fulfilled` scenario exercises real B execution and renewal, an established
QUIC stream with all reverse packets dropped, loss of B and relay processes,
exact cold reply recovery without any retained-file change, stale request refusal,
original witness Unknown then Result selection, complete bidirectional packet
loss before another request, A restarts, A acceptance, A/B protected Serve and
closure of all four original admission histories. The `lost-session` scenario
kills B after Claim but before Execute: original and cold-recovered attempts
cannot recreate the volatile key, invent a result or clear the pending budget.
Both scenarios compare final original handoff bytes with their initial values.

A complete successful job carries source sequence 0→1, spent 0→2→2 and pending
0→2→0. An unresolved lost session holds spent 2 and pending 2 with source sequence
0. Two votes alone cannot form an admission or job quorum.

## Evidence and limits

The dated [campaign record](evidence/custody-profile5-wan-20261029.json) identifies
final source and native binary hashes, successful scenarios, packet counters,
original-witness state, cleanup and earlier unsuccessful attempts. Unit/race
checks separately cover malformed/trailing frames, peer and descriptor mismatch,
response binding, write/close failure, bounded concurrency and shutdown. Fuzzing
is a bounded smoke test, not an audit.

Two servers operated by one person with published test keys are not independent
operators or four protected failure domains. Packet drops and killed processes
are not disk exhaustion, physical power loss, rollback of an entire service VM,
external monotone storage or trusted time. Those acceptance gates, independent
security review and the sustained public testnet remain open. Readiness stays
approximately **44/100**; this network adapter does not activate mainnet.
