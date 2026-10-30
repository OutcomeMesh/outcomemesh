# Recovering completed custody evidence

Profile-5 owners can return already durable evidence after a reply is lost,
a process restarts, or Serve closes. This continues the
[retained-result settlement path](CUSTODY_RETAINED_ACCEPTANCE.md): recovery supplies
missing artifacts to the original result, Serve and admission flow. It cannot
execute work, create an acceptance receipt, decide Serve or close accounting.

| Command kind | Owner | Returned artifact |
| --- | --- | --- |
| 8, `ProtectedReadResult` | Original B/target | Existing signed execution result |
| 11, `ProtectedReadAcceptance` | Original A/authority | Existing acceptance receipt, including retained consent when present |
| 12, `ProtectedReadServe` | Original A or B | That owner's existing applied Serve receipt |

All three commands carry the exact original admission binding and empty Data.
The service requires its configured deployment and original stored binding. It
verifies the retained artifact against the original result/claim, acceptance
intent or Serve certificate and A-parent receipt. Missing, partial or inconsistent
records fail; recovery never substitutes a new signature or current approval time.
The original bytes, timestamps, retention and independently sealed effects remain
unchanged. Expiry of an approval window does not invalidate a completed historical
receipt.

A successful read consumes an ordinary bounded service response position and,
for guarded deployments, a fresh outer response seal. It does not consume or
refund execution allowance, advance the source, shorten retention or reopen Serve.
The request still requires the current independently retained service cursor.
Copies with stale cursors, revoked keys, a missing guard or a pending unresolved
runtime request gain no alternate access path. Resolve the exact pending runtime
request through its existing recovery procedure first.

Historical reads do not require the current source to remain at the old job's
head. Later jobs may have advanced it. The returned receipt is evidence of that
original completed action, not a statement about today's source position. Retain
original protected stores and public artifacts; this is not reconstruction from
an arbitrary copied directory.

## Interrupted result sealing

A guarded target may retain the completed session-signed `core-result` before
its independently sealed `result` or outer response is durable. The original
pending `ProtectedExecute` request can now finish this specific interrupted
publication after a restart. It does not use any of the evidence-read commands
above and is not a new execution attempt.

Reopen the original service with its pinned descriptor, retained before-position
and exact signed attempted request. Deliver that same request and payload through
the existing gateway recovery path. Do not change its nonce, admission binding or
claim certificate, create a new owner, or edit the retained files. The service
requires all of the following under its original owner lock:

1. The configured guarded deployment, current service identity and exact pending
   runtime intent.
2. The original admission, candidate and consumed quorum certificate, matching
   the completed core's scope, claim and session signature.
3. The original verified source entry, including its predecessor, challenge and
   renewed receipt, at the target's current retained source head.
4. The independent guard's original effect choice or permission to select that
   same effect at its still-empty slot.

The service rechecks retained evidence after contacting the guard and before
publishing the result. It preserves the session signature, source entry and
original `RespondedAt`; it cannot generate a new session key, reread archive
objects as execution, append a source entry or refresh proof age. Lost guard
replies reuse the same choice. Exact completed request retries return the original
outer response without another choice. Accounting remains held until the normal
result quorum, A acceptance, Serve A/B receipts and admission closure complete.
An expired result still requires the explicit retained-acceptance consent.

After authorized [key replacement](CUSTODY_KEY_REPLACEMENT.md), the successor
can finish a complete signed core only if the original logical effect slot is
still free. If the old signer already occupied that slot but its sealed result
was lost, a different successor effect is refused. Revocation blocks new seals
from the old signer, including exact requests. Neither condition resets the slot.

Missing or corrupt core evidence, a crash before the session signature was
durable, a conflicting guard choice, an unavailable guard or an unguarded
deployment still blocks this recovery. The complete result verifier continues
to reject a bare core without its protected effect. Existing wire and stored
artifact formats are unchanged; this adds no new command or acceptance rule.
It does not resolve Prune starts or add independent fencing to that workflow.

## Reviewed CLI

Use `omd work-archive-custody-profile5 --action command --input <json> --out <fresh-path>`.
The complete strict JSON object contains `Kind`, `Admission` (base64 canonical
binding), `Now`, and `Data`, `Deployment`, `Pair`, `Certificate`, `Parent` set to
`null`. Select kind 8, 11 or 12. Review output marks `EvidenceReadOnly: true`.
Use the exact review ID for run mode, then the existing `sign-request`, original
gateway delivery and pinned-descriptor `extract` flow. Preparation neither opens
the service store nor contacts the service.

For a delayed completed result, recover B's result and obtain the original result
quorum. If A has not accepted it, follow ordinary acceptance or explicit dual
consent for retained acceptance. If A already accepted it, recover that exact
receipt. Complete the original Serve decision, recover or apply A's receipt,
then B's matching receipt. Admission closure still needs the full matching
certificate and both receipts; reading them does not submit closure automatically.

An unknown outcome without a complete verifiable result remains held. A partial
acceptance intent is not an acceptance receipt; a pending Serve intent is not an
applied receipt. Unavailable or damaged evidence creates no timeout, cancellation,
refund, source replacement or new execution permission. Shared administrative
control of the two current servers remains a separate deployment limitation.

Existing command bytes are unchanged. New kinds 11/12 are rejected by older
readers. Kind 8 additionally permits historical reads after Serve closure.
No consensus or mainnet activation is implied.
