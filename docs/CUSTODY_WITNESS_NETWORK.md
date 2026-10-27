# Witness network, operator CLI and historical result verification

Status: experimental witness transport/CLI and typed historical-result binding.
The [witness state machine](CUSTODY_FENCE.md) now has an owned network adapter.
This is not mandatory V0/V1 custody fencing, a protected effect executor, live
source acceptance, Serve completion or mainnet activation.

## Protocol and authority boundary

The explicitly enabled libp2p QUIC protocol is
`/outcomemesh/custody-witness/0`. Default hosts do not register its handler.
It has no fallback to the V1 remote-control or custody-data protocols. Endpoint
transport identity and witness signing identity are independently pinned and
different; the server transport key cannot reuse any key in the witness scope.
Only the selected client transport peer IDs reach the handler.

Request/response frames have a four-byte length and at most 4096 payload bytes.
The endpoint allows 1–16 distinct client peers, eight concurrent handlers and
256 admitted streams per fixed minute. Rejected transport peers do not consume
that rate budget. Time affects transport deadlines/budgets only, never witness
positions, lease expiry, owner replacement or uncertainty release.

Each canonical request binds its scope ID, kind, fresh 32-byte channel nonce,
independently retained before position/pending ID, and exact signed command or
quorum certificate. Its ID has a separate signature-context domain. A signature
over another scope, role, command, request kind or nonce cannot substitute.
The entire request and EOF are required before a mutation. Extra bytes, malformed
frames, stale pins and unlisted peers refuse without producing a success reply.

| Request | Required facts | Effect |
| --- | --- | --- |
| Review | Exact original committed and pending pin | Signed historical observation; no mutation. |
| Vote | Owner/controller-signed exact next command and original before position | Persist one proposal, sync, then return its vote and observation. |
| Commit | Quorum-valid exact transition and original before position | Persist the certificate before returning the resulting observation. |

Observations use `OMCFOB00` and the domain
`OMESH/custody-fence/observation/signature/v0`. They authenticate the full request
ID, witness key, scope, committed position, pending proposal, phase, claim,
evidence and remaining-obligation flag. They are historical when returned and
are not current execution permission. Individual observations are not a quorum.
Request/response magic is `OMCFWR00` / `OMCFWS00`.

The deterministic wire fixture's vote request ID is
`36a17d1b540789fb9bd70c44d6c470f50e3bad20cc01fe739f2f37e2a82f656b`.
Its request/response/observation lengths are 360/458/308 bytes. The response SHA-256
is `cf016899511878467e2f50686bfe2f326eccacaa6b71a160d227e5f9871ab65f`;
the observation SHA-256 is
`cebc4c27a3c68977c7bb49bb47ad3518c60e2a16c9afcaf2fecf1f3bb4d700e0`.
Fixed signature/domain vectors accompany rejection, frame-bound and fuzz tests.

The client pins both server transport and witness signing keys, verifies the
complete reply and EOF, and owns complete transport cleanup. Its deadline covers
dial plus exchange. It never retries automatically, adopts a pin from an error,
opens a replacement root or creates another attempt. A timeout, missing EOF,
reset or lost output is uncertainty; retain the full exact attempted request.

Exact Vote retry may recover that same pending proposal. Exact Commit retry may
recover that same one-transition extension. A nonzero retained pending pin must
also match the historical proposal after the commit: an already confirmed head
does not excuse a contradictory earlier pending pin. The same check applies to
cold `RecoverCommit`. No path discards a competing lock to restore progress.

`witnessnet.Service` retains the original owner for its whole lifetime, serializes
decisions through response validation and cancels/drains active handlers before
closing that owner. EOF, explicit close or process death does not close a slot
as unclaimed, release an unknown outcome or complete an ordinary ticket.

## Explicit CLI workflow

All paths below represent already selected private local placements. Keep seed
files and public input/output artifacts outside the witness root. A new root's
parent must be private. Scope IDs, member keys, positions and pending IDs come
from separately retained enrollment/attempt records, not an incoming reply.

The `work-archive-custody-witness` command provides:

| Mode | Behavior |
| --- | --- |
| `review` (default) | Open existing original root under its kernel lock and exact pin; load no seed and start no listener. |
| `create-review` | Review a fresh absent root at position zero without opening an owner or reading a seed. |
| `create` | Explicit fresh bootstrap after comparing the create review ID; refuses partial/existing roots. |
| `serve` | Compare the exact serve review, open the original pinned owner and serve the authenticated witness protocol. |
| `vote`, `commit` | Explicit local operations over the pinned input, with an action-specific review ID. |
| `recover-vote-review`, `recover-commit-review` | Review the separately retained before pin and full exact attempted artifact; no recovery or signing. |
| `recover-vote`, `recover-commit` | Explicit bounded recovery only; no implicit vote/commit or network start. |

Supply `--scope FILE --scope-id ID --root ROOT --witness-public-key KEY`, explicit
`--expected-sequence N --expected-head ID`, and `--pending-id ID` whenever a vote
is pending. Creation starts at sequence zero with head equal to the scope ID and
no pending proposal. Signing actions require an existing private 32-byte
`--sign-key` seed matching the selected member. Review never reads that seed.
The review hash binds the command family, intended action and full public
context; it cannot approve a different action with the same artifacts.

For serving, include `--transport-public-key KEY --clients PEER_ID[,PEER_ID]`,
the selected `--listen` and `--timeout` in the review. Repeat the same public
configuration with `--mode serve --expected-review-id REVIEW_ID` and the matching
`--transport-key` seed. Native serving requires dedicated stdin/stdout pipes.
It reports `custody_witness_serving` and accepts only `close` or EOF on stdin.
Collect and retain each RPC's exact before request and verified result before
changing an independently retained restart pin. Restart never adopts disk state
from a stale pin or automatically repairs a partial journal.

The remaining commands are:

- `work-archive-custody-witness-request`: review/publish a canonical `review`,
  `vote` or `commit` RPC with explicit `--nonce` (64 lowercase nonzero hex digits),
  before pin and signed `--command`/`--command-id` or pinned certificate.
- `work-archive-custody-witness-call`: review, then explicitly `--mode exchange`
  against the independent `--server-transport-public-key`, member key and route.
  It needs a pinned `--request-id`, distinct local transport public key/seed and
  immutable `--out`. A verified response artifact is retained before stdout.
- `work-archive-custody-witness-quorum`: review/publish a certificate from a
  bounded `--pairs` JSON list of `request`/`response` file paths. It authenticates
  every complete pair, requires the independent expected `--command-id`, rejects
  duplicate members and sorts the unique votes. Two copies of one member count
  once. Insufficient votes cannot produce a certificate.

Artifact publication requires `--mode publish --expected-review-id REVIEW_ID`.
Existing exact bytes may be recovered, never overwritten. Output paths/aliases
are checked before the corresponding vote or RPC; outputs inside an original
local witness root are refused. Request IDs and certificate artifact IDs use
different domains; use the explicitly reported `request_id` for RPC inputs.

## Quorum-bound historical custody result

`custodyfence/custodyproof.Bundle` has separate magic `OMCFRS00`, version zero and
its own ID domain. It requires exactly Claim/Result or Claim/Unknown/Result quorum
certificates and a complete typed positive historical terminal. There is no
legacy-terminal fallback, digest-only success or optional certificate path in
this verifier. All positions, claims, signatures, scopes and quorum memberships
must replay as one history. Its final evidence ID must equal the exact complete
custody journal entry ID.

`ValidateBinding` checks the externally pinned witness scope against the full
selected V1 assignment, intent, Audit admission, plan and Begin. The owner is B's
control key and controller A's authority key. Witness members cannot reuse any
participant's control, consumer, evidence, auditor or transport key. A quorum
over an unrelated digest is insufficient, even with valid signatures.

`work-archive-custody-witness-result` exposes read-only review/verify and explicit
immutable publication. It consumes the ordinary public V1 scope flags plus the
independent `--witness-scope`/ID and either a pinned `--bundle`/ID or the pinned
terminal and a bounded JSON `--chain` list of certificate `file`/`id` pairs.
It opens no original owners and loads no seeds. Verification preserves the
original RespondedAt, receipt and proof bytes. Output explicitly reports
`historical_result_verified=true`, `current_source_acceptance_checked=false`,
`proof_refreshed=false` and `completion_submitted=false`.

This proves a historical evidence binding, not current original-A source
acceptance, live proof freshness, physical at-most-once execution or eligibility
to close Serve. Do not attach a newly selected scope to old V1 uncertainty to
claim that an earlier execution never occurred.

## Acceptance and remaining integration

The controlled campaign in `scripts/remote_acceptance/witness.py` uses normal CLI
bootstrap, request publication, authenticated calls and quorum assembly. Four
logical members run on two kernels, two per host. It refuses two-member and
duplicate-member quorums, proceeds with three members, recovers exact commits,
retains Unknown across a verified SIGKILL, refuses stale cold pins/late claims,
and ends with all four members holding the same immutable result commitment.
The result is explicitly opaque; it is not custody proof or source acceptance.
Fixtures use public deterministic test keys and fresh per-campaign test scopes.

This is not four independent failure domains or protected-key deployment. Losing
one of these hosts loses two members, which cannot preserve 3/4 availability.
Independent key/rollback protection, physical-device campaigns and external
review remain gates. The [production ledger](PRODUCTION_READINESS.md) assigns no
additional point to this partial integration.

Next, a new custody assignment/proof version must mandate a preselected witness
policy, derive each exact slot, enforce consumption at the actual effect target,
and require the full result binding under the original A source decision before
acceptance or completion. Avoid a circular commitment: a scope already contains
assignment/plan/Begin IDs, so its full ID cannot simply be embedded back into that
same assignment. Pin a prior witness policy and deterministic derivation rules
in the new assignment. Split-vote progress also needs a safe protocol; this
version deliberately stalls instead of forgetting votes or selecting a timeout
winner. Existing V0/V1 paths are not silently upgraded by these commands.
