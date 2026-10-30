# Independent authorization before Prune

This experimental path protects newly prepared scheduled Prune tasks against
participant key and disk copies when the original witness quorum remains
independent. It preserves every original admission, pending obligation and spent
operation ID. It does not retrofit protection onto an already admitted request.

## Policy and execution

The consumer and primary authority commit the witness policy before admission.
The policy selects 4 to 16 sorted witness keys and a threshold greater than two
thirds of the roster. Witness and optional guard keys must differ from all
participating authorities, replicas, consumers, auditors and trusted attestors.
Different keys alone do not establish independent administration or backups.

The witness scope derives from the original assignment, request and policy.
Changing an inventory, executor directory or storage pair cannot create another
slot for that request. The candidate additionally binds the exact admitted
storage operation, inventory, original executor binding, protected storage pair
and a new session public key. Its private key exists only in the live process.

Execution holds the original owners and journals, validates the complete archive
quorum and retains the candidate before contacting witnesses. Each witness locks
one proposal durably before voting. A complete matching quorum is retained in
the start record and confirmed by the original executor pin journal. Retention
and ownership are checked again after the network exchange.

The actual storage target consumes the live permit under its lock, before any
deletion. It checks the exact operation and protected storage pair. A serialized
claim cannot construct that permit. The permit can be consumed once; the session
can sign one exact effect and then erases its private key. The retained result
contains both the original effect and its session signature. Completing each
replica's original ticket still requires the existing reviewed, co-signed command
and original owner. Deletion itself releases no accounting obligation.

## Prepare and run

Use the existing [scheduled preparation and outcome procedure](PRUNE_SCHEDULED_OUTCOMES.md)
with these additional steps. All `ID` values below come from separately checked
outputs. Paths and keys are operator inputs, not values supplied by remote peers.

1. Prepare a JSON policy with `owner`, `controller`, optional `guard`, `threshold`
   and `witnesses`. Keys are 64 lowercase hexadecimal characters. `owner` is the
   request consumer; `controller` is its primary authority. Publish the canonical
   policy after reviewing its ID:

   ```sh
   omd work-prune-fence-policy --input policy.json
   omd work-prune-fence-policy --input policy.json --mode publish \
     --expected-id POLICY_ID --out policy.bin
   ```

2. Add `--fence-policy policy.bin --fence-policy-id POLICY_ID` to
   `work-prune-scheduled-plan` during both review and publication. These flags
   must be selected before signing admissions. Keep the original request and
   plan bytes. The normal executor preparation, consumer signature, authority
   countersignature and per-replica admission steps remain required.

3. Export the scope from that exact plan:

   ```sh
   omd work-prune-fence-scope --input plan.bin --plan-id PLAN_ID
   omd work-prune-fence-scope --input plan.bin --plan-id PLAN_ID \
     --mode publish --expected-id SCOPE_ID --out scope.bin
   ```

   Enroll this scope explicitly on the original independent witness services
   using the [witness CLI](CUSTODY_WITNESS_NETWORK.md#explicit-cli-workflow).
   Initial sequence is zero and initial head is `SCOPE_ID`. Give every service
   its own signing key, transport key and retained root. Its client allowlist uses
   the OutcomeMesh peer ID derived from the client's transport public key, not
   the raw public key. Never recreate a used scope to clear a pending vote.

4. Package the admitted inventory through `work-prune-scheduled-inventory` and
   review `work-archive-prune-scheduled` normally. Review loads no private seeds
   and makes no witness calls. For execution add:

   ```text
   --mode execute --expected-review-id REVIEW_ID
   --fence-network witnesses.json
   --fence-owner-key consumer.seed
   --fence-transport-key client-transport.seed
   --fence-timeout 5s
   ```

   `witnesses.json` contains `client_transport` and `witnesses`, an array with one
   `{ "witness": "PUBLIC_KEY", "transport": "PUBLIC_KEY", "address": "MULTIADDRESS" }`
   entry for every enrolled member. The client pins both witness and transport
   identities. Seeds are existing private regular 32-byte files with mode 0600.
   Transport keys must be distinct from policy roles and each other. The timeout
   bounds each dial and exchange. The collector makes one attempt per witness;
   it neither creates roots nor adopts newer pins from replies.

5. Inspect the retained executor result, then export the original effect and
   complete tickets through the existing scheduled outcome commands. The live
   owner verifies the matching claim, session signature and original pins before
   accepting completion. The exported effect alone grants no execution rights.

## Interruption and recovery

| Retained state | Permitted continuation |
| --- | --- |
| No candidate and no start | Review and execute against the original enrollment. |
| Candidate without quorum/start | Retain the candidate and all tickets. Do not create a new session or cancel locally. |
| Confirmed start without signed result | Hold the outcome, even if the local storage effect exists. Do not repeat deletion or reconstruct a signature. |
| Complete signed result with pending pin confirmation | Continue the exact original retained transition through the existing pin recovery path. |
| Confirmed signed result | Read historical evidence and complete each original ticket separately. |

Local pre-start cancellation is deliberately unavailable for this request version.
A minority vote, lost response, timeout or process death does not prove that the
slot is unclaimed. Independent CloseUnclaimed settlement and resolution without
a retained session-signed result are later work. No new adapter changes old
request or cancellation semantics.

The witness quorum prevents conflicting claims; it does not execute storage or
attest that an administrator physically deleted data. The storage API and process
remain trusted. A malicious process with raw database access can bypass local
APIs, and a copied live memory image can copy secrets. Witness keys and histories
must remain outside participant backups and rollback authority. Two hosts under
one administrator do not meet the independent deployment requirement. Hardware
isolation, independent operators and external review remain launch gates.

## Compatibility and verification

Request v3, plan/inventory v1 and start v2 are explicit opt-in formats. Old request,
plan, inventory, effect and cancellation encodings retain their existing rules.
The executor's new `fence/candidate` file is immutable. No chain database, storage
position journal or authority history is replaced. Codecs and signature domains
are specified in [PROTOCOL.md](PROTOCOL.md#independent-scheduled-prune-claims).

Coverage includes four real witness services, one/two-member outages, competing
participant copies, concurrent permit consumption, crossed storage identities,
full CLI completion, malformed and downgraded artifacts, fault injection and
five process-kill boundaries. Fixed vectors and decoder fuzz targets accompany
the new formats. These checks establish local behavior, not deployment readiness.
