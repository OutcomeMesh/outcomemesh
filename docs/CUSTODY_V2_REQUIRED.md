# Mandatory admission for new V2 jobs

Status: experimental signed required profile, original-owner runtime and reviewed
CLI. A new assignment can now require admission before its real custody effect.
This is opt-in profile enforcement, not mainnet activation, old-ticket migration,
a public admission RPC or protection against hostile implementations/raw keys.

## Immutable signed profile

`PolicyVersionAdmission = 3` is a version of the witness-policy descriptor.
Assignment, Plan, Context and portable custody evidence remain their explicit
V2 formats. Policy 3 keeps the policy-family framing with an explicit version 3
and its own `OMESH/custody/v3/witness-policy/id` domain. Legacy policy 2 bytes,
IDs and domains remain unchanged.

The outer assignment commits the policy, and the three role signatures commit
that assignment through the Plan. Removing required mode changes assignment,
Plan, Context and job scope IDs and invalidates existing signatures. An existing
policy-2 assignment is not promoted or reset. Creating an unrelated assignment
is separate enrollment, not permission to reuse this assignment's budget.

| Layer | Required behavior |
| --- | --- |
| Assignment policy | Signed mandatory mode 3; same immutable roster/threshold constraints |
| Admission accounting | Existing shared genesis and contiguous QC chain, for this exact profile-3 assignment |
| Owner root | Exact admission binding retained and flushed before `ready`; ordinary raw factories refuse policy 3 |
| Execution scope | Existing session-bound fence version 1, derived from the signed profile-3 Context |
| Target consumption | One durable record commits binding ID, admission entry ID, exact candidate and Claim QC before current archive-object reads, proof signing or append |
| A acceptance | Pending record commits the same local binding/admission IDs and exact bundle/time before original source append |
| Recovery and Serve | Explicit required-owner opens retain the original binding; cached evidence/time and all archive holds remain intact |

## Admission binding is a complete prefix

`AdmissionBinding` carries the canonical genesis and an ordered, bounded list of
complete admission certificates from its initial position. It is not a detached
Admit QC or an unsigned Snapshot. Validation:

1. verifies the signed profile-3 Context, genesis and all descriptor bindings;
2. replays every typed QC, quorum, position, budget, deduplication and source
   transition from genesis;
3. requires the final entry to be Admit for this exact Context and Plan;
4. requires that replayed active job/pending=2 and source sequence/head/receipt
   match this Context's exact predecessor.

A missing prefix, gap, weak or repeated quorum, foreign descriptor/context,
wrong active job, prefix ending Close or extra bytes is refused. Total proof
bytes are capped at 512 MiB and certificate count is bounded by the assignment's
entry limit. The CLI pins genesis semantic and full descriptor IDs during
construction, then independently pins the complete binding's semantic ID.

Creation/Open freezes caller-provided values through canonical decode and retains
exact public proof bytes in the private `admission` file. Every root check compares
those original bytes. No ordinary Open discovers/adopts this file implicitly.
Profile-2 roots reject an extra admission file; profile-3 raw Create/Open refuse
without the explicit verified proof. Replacing a stored binding with another
valid QC subset also fails the exact-byte root pin.

## Historical proof, safe one-use execution

A valid Admit-ending prefix is historical: it does not claim to read the latest
accounting head online. Its safe use also depends on the original source, live
execution session and permanent job-fence gates:

- A later fulfilled accounting Close requires the exact original result, accepted
  source evidence and both applied Serve receipts. The honest original B has
  already persisted consumed/result. It cannot Execute again.
- A later unclaimed Close requires the original execution no-claim QC. Under
  witness non-equivocation and fewer than one-third faulty witnesses, that QC
  excludes any Claim QC for the same job. A fresh prepared session cannot gain
  permission by replaying an old Admit prefix.
- A persistent key/journal copy does not possess the winning volatile session.
  A replacement session cannot execute the old Claim. The original source
  predecessor and physical placement checks remain enforced too.

The binding is consequently a necessary admission proof, not sufficient physical
execution permission. Existing no-reset/no-expiry witness locks, original-source
checks and session ownership must not be removed. Split votes can still stall.
Protected enrollment, raw-key/RAM protection and external pins remain explicit
assumptions; an online snapshot alone would not solve those problems.

## Original B effect boundary

`CreateRequiredTarget` / `OpenRequiredTarget` require signed mode 3, the complete
binding, independent job scope pin, original journal and original object directory.
The old `CreateTarget` / `OpenTarget` cannot open the same signed job as raw work.
The existing authenticated V2 transport starts only with an already bound Target;
its normal handler reaches the same mandatory checks.

Unlike legacy policy-2 inspection, required Open/Prepare do not open, scan or hash
the current archive object files. They validate public proof, original source
history and directory placement. Historical source-journal/proof verification and
directory metadata are not a new custody response. Current object-store opening
and chunk verification are deferred until after durable consumption.

Execute, under the retained original root/source decision, verifies exact binding,
current predecessor, its own live session, the winning Claim QC, current challenge
freshness and cancellation. It then retains the **single** binding-aware `consumed`
record with family magic `OMCVUSE3`, version 3, binding ID, admission entry ID and
the original complete candidate/Claim packet. File and directory durability
precede object-store reads, proof signing, receipt renewal and source append.
There is no separate admission-used marker with a crash gap before consumption.

An object-store failure after this boundary is unknown. Missing/corrupt chunks
can therefore allow Open/Prepare but fail Execute after consumption. Repairing
files does not permit another Execute. A pre-sync or post-sync failure poisons
that owner; cold recovery validates/resyncs retained evidence, never reconstructs
an old private session or resumes work. Retained result recovery does no new
archive work and preserves the original proof time.

## Original A acceptance and Serve

`CreateRequiredAcceptor` / `OpenRequiredAcceptor` require the same signed mode,
complete proof and exact original source. The normal acceptance checks still
verify all chunks/proof/signatures, selected job/session and current proof age.
The binding-aware pending record (`OMCVPEN3`, version 3) retains binding/admission
IDs, full bundle and original checked time before append. Cold open validates
its exact IDs; a detached or substituted record cannot authorize Resume.

Explicit Resume appends only if the source is still the predecessor and the proof
is fresh now. If the exact entry already exists, it recovers only the historical
receipt with the original time. Serve application/status uses required owners,
so it cannot bypass admission or become inaccessible through a raw-owner CLI.
Complete Serve evidence and A/B applied receipts can then close shared accounting
through its ordinary witnessed Close transition. Lifetime spending remains two;
fulfilled source cursor advances, while archive retention stays held.

Legacy receipt/result/Serve portable bytes remain V2 and bind the profile-3 job
scope and outer assignment. The private consumed/pending wrappers are explicit
new retained formats. Required owners refuse old unbound private records; old
owners are not migrated by interpreting those wrappers.

## Reviewed operator workflow

Command: `omd work-archive-custody-v2-required`.

Default `review` loads no private seed and opens no owner. It verifies the full
public proof and binds action, Context/scope/binding IDs, all file contents,
original placement, key paths, output and network route. Run the same action
using `--mode run --expected-review-id <id>`. Files are immutable and remain
outside all owner/source roots. Recover lost output to a fresh path.

1. Create/sign a new Context whose assignment policy version is 3. Use the
   ordinary public V2 draft/context helpers; old policy-2 signatures cannot be
   reused after changing mode.
2. Obtain the exact Admit through the existing reviewed admission coordinator
   CLI and independently enrolled global witnesses. Its full prior history is
   required for later jobs.
3. `binding` takes Context/scope pins, `--genesis`, `--genesis-id`,
   `--genesis-descriptor-id`, comma-separated `--certificates` and matching
   `--certificate-ids` in the V2 artifact domain. It verifies/replays the proof
   and publishes the canonical binding and semantic `binding_id`.
4. `create-target`, `create-acceptor` and all later owner actions require
   `--context`, `--context-id`, `--scope-id`, `--binding`, `--binding-id` plus the
   original root/source paths. Distribute/pin the same exact public binding.
5. `serve-target` retains original source/root, control/replica keys and the
   pinned authenticated transport. Existing V2 request/client helpers perform
   Prepare/Execute/Recover with the normal job Claim/Result quorum chain. The
   service advertises `admission_required=true` and its binding ID; startup does
   not prepare a session or start work.
6. `accept`, `resume`, `receipt` use the required A owner. `serve-apply-a/b`,
   `serve-resume-a/b` and `serve-status-a/b` use required owners with the same
   binding. B application additionally pins A's applied receipt as `--proof`.
7. Close global accounting with the ordinary admission CLI only after full Serve
   and A/B applied evidence. An unknown/expired/unaccepted result cannot close
   it; nothing in this command waives that hold.

Admission distribution currently uses the explicit operator channel. There is no
new autonomous delivery outbox/RPC, forced adoption, clock override, private
session import or automatic legacy transition in this stage.

## Validation and remaining gates

Tests cover immutable mode/downgrade refusal, legacy policy vectors, complete
prefix/gap/descriptor/context/quorum checks, genuine Claim/no-claim exclusion,
fulfilled source advancement, old bindings and fresh key copies, original-root
replacement, corrupted binding/consumption/pending IDs, four B and two A crash
boundaries, missing/corrupt object failures after consumption, and exact cached
recovery. Native process CLI runs admission through real retained witness roots,
actual required QUIC execution/acceptance, Serve A/B and global accounting Close.

The two-host campaign uses newly signed profile-3 fixtures, actual admission,
execution and Serve witness decisions, controlled reply loss/process restart and
a pre-effect lost session. It separately records physical source positions,
immutable binding/consumption IDs and final accounting. Four logical witnesses
on two kernels remain two observed hosts, with public fixture keys.

Mainnet/old-owner activation remains gated by protected independent enrollment,
one-successor exclusion of legacy grants, implemented accounting/migration bridge,
durable admission delivery, safe split-vote progress, physical-storage acceptance,
external review and the sustained adversarial public testnet. Raw policy-2/V1
histories and their pending obligations remain unchanged. This signed profile
implements required execution for new jobs; it does not waive those launch gates.

The 2026-10-28 [acceptance index](evidence/custody-v2-required-20261028.json)
records two fresh jointly operated profile-3 jobs. The reply-loss job ends with
original A/B/copy source counts 1/1/0 and global spent=2/pending=0/source cursor1.
The lost-session job ends 0/0/0 and spent=2/pending=2/cursor0. Both retain archive
obligations. The final controller sources were pinned before that campaign; an
initial attempt was interrupted to harden the dedicated-pipe raw CLI probe, with
its histories retained and no runtime source change for the rerun.

The [public manifest](evidence/custody-v2-required-public-20261028.json) pins 256
artifacts in a 59,615-byte archive. Production Go APIs reverify profile and full
admission binding, original execution quorums, binding-aware consumed/A-pending
IDs, exact result/acceptance time, Serve A/B receipts and final global accounting
snapshots. Local records and snapshots remain historical diagnostic evidence;
original physical sources were additionally inspected during the campaign.
All five race groups, fresh CLI process integration, integration vet, 49 Python
helper tests and bounded profile/binding decoder fuzz smoke pass. Both hosts end
without selected listeners or task processes. All 695 packed Go/module/fixture
sources still match the native build pin; the website and old V1 owners are
unchanged.
