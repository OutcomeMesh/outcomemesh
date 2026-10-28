# Registry-bound custody execution

Status: experimental signed policy 4 for fresh assignments. No consensus fork,
mainnet activation, physical-resource enrollment service or legacy migration.

The [one-choice registry](CUSTODY_REGISTRY.md) previously recorded a profile-3
candidate without gating execution. A new registry format 2 selects profile 4,
whose actual target and acceptor require its complete certificate. Old registry
format 1 remains selection-only; an existing selection cannot be promoted.

## Construction order and identity

1. An independently protected issuer provisions the stable resource identity.
   Registry Genesis 2 fixes chain/network, issuer, sorted witness roster,
   threshold and lifetime/pending caps before an assignment exists.
2. Policy 4 fixes the registry's semantic ID and full descriptor ID alongside
   the job witness roster/threshold. Both enter AssignmentID and the signed Plan.
3. Registry Selection 2 carries the complete exact admission Genesis, including
   assignment, original manifest/initial receipt, custody policy and budget.
   Issuer, A authority and B control sign the same body in separate domains.
4. A separate >2/3 registry quorum permanently selects that candidate. Ordinary
   assignment admission still needs its own complete valid Admit prefix.
5. EnrollmentBinding 4 retains the full Genesis 2 and selection certificate.
   Runtime verifies its signatures, caps, disjoint roles and exact candidate
   bytes against the admitted assignment before opening original sources.

RegistryID keeps `OMESH/custody-registry/v1/id` across formats: changing format,
policy, keys or allowance must not manufacture another identity for the same
resource. Format 2 descriptor/selection/vote/certificate domains use
`OMESH/custody-registry/v2/`. The issuer still must prevent a second independently
declared ResourceID for the same physical sources and old obligations.

## Effect and persistence rules

Only explicit `Create/OpenEnrolledTarget` and `Create/OpenEnrolledAcceptor`
constructors accept profile 4. Raw and required-profile-3 constructors refuse it.
A missing, weak, foreign or malformed enrollment is rejected before owner
creation or opening source journals. Public admission alone grants no execution.

Each owner retains exact complete `admission` and `enrollment` files before ready.
Cold open requires byte-identical evidence, including the selected quorum subset;
a different valid sufficient subset cannot replace the retained certificate.
Placement, permanent locks and original journal identity checks still apply.

Before opening/hashing current archive chunks, B durably consumes the original
live candidate/Claim under `OMCVUSE4`, version 4, admission-binding ID, Admit ID,
enrollment-binding ID and the original length-prefixed consumption record.
A similarly retains `OMCVPEN4` with those three IDs before its original append.
A failed or unknown consumed attempt cannot execute again. A cold open alone
never appends; explicit exact A resume recovers the retained pending attempt.

The original volatile session, per-job witness quorums, typed Result/Receipt,
Serve A/B disposition, retention deadlines and assignment-wide two-unit accounting
remain required. Result, Receipt, Serve and job network formats remain version 2;
the signed assignment/scope IDs distinguish profile 4. Registry selection does
not refund operations, prove freshness or resolve an unknown effect.

## Reviewed CLI

Command: `omd work-archive-custody-v2-enrolled`. All actions default to public
review with no seed load or owner open. Run the exact reviewed arguments with
`--mode run --expected-review-id <id>`. Immutable outputs must be absent and
outside original roots and sources.

- `binding` uses the existing complete genesis/certificate-prefix inputs and
  independently pinned context/scope to prepare the admission proof for policy 4.
- `enrollment` takes context/scope, `--binding`, `--binding-id`, canonical
  `--registry`, full `--registry-certificate`, its registry-domain artifact pin
  `--registry-certificate-id`, and a fresh `--out`. Registry IDs are already fixed
  by the signed policy. This action verifies/prepares public evidence only.
- Every owner action additionally requires `--enrollment` and its semantic
  `--enrollment-id`: target/acceptor creation, target service, acceptance,
  receipt/resume and A/B Serve application, recovery and status. Source, key,
  before-proof and output selectors retain the required-profile CLI rules.
- The registry CLI uses format 2 from its Genesis for selections/certificates.
  Four original witness histories, exact vote/commit recovery and immutable
  sequence/head/pending pins retain their existing behavior.

The profile-3 inbox/outbox protocol remains explicitly profile 3. The separate
[enrolled proof delivery](CUSTODY_V2_ENROLLED_DELIVERY.md) now carries both complete
profile-4 proofs under an independently pinned receiver descriptor. Intake
retains proof only; owners still require their separate explicit action.

## Compatibility and remaining gates

Policy 2/3, registry 1 and old private record bytes/IDs are preserved. Hidden
registry fields on old policies are refused rather than ignored. Reframing an
old witness history as registry 2 is refused even though semantic RegistryID is
stable. There is no upgrade, reset, import or second selection API.

This is a mandatory check for newly signed profile-4 owners, not exclusion of
all old raw grants on the same disks. Independently protected anchor issuance,
key/VM rollback resistance, legacy-grant exclusion, a real accounting bridge,
joint WAN fault acceptance and independent review
remain open. Four keys on two operator-controlled hosts do not establish four
independent protected failure domains. Production readiness remains **44/100**.

## Verification

Deterministic vectors pin policy, assignment, registry, descriptor, selection,
certificate and enrollment IDs in `TestEnrolledCanonicalVectors`. Tests cover
valid-but-foreign selected assignments, insufficient quorums, signature and marker
corruption, profile downgrade, alternate sufficient subsets, consumption and
acceptance write boundaries, old-history preservation and minority vote retention.

The CLI lifecycle creates actual registry/admission witness histories, executes
and recovers a result over authenticated QUIC, accepts on original A, applies
Serve on A/B and closes accounting through original admission witnesses. Native
process variants exercise the same reviewed commands. Per-job Claim/Result/Serve
endorsements in this lifecycle are explicitly deterministic fixture signatures;
registry and admission votes come from the real original witness CLI.

Reproduce the local gates with Go 1.26.7:

```sh
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 GOFLAGS=-p=1 make -j1 test-all
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 go test -tags=integration ./cmd/omd -run '^TestProcessCustodyV2(Enrolled|Required)AdmissionAndExecution$' -count=1 -timeout=2m
GOTOOLCHAIN=go1.26.7 GOMAXPROCS=2 go test ./node/custodyv2 -run '^$' -fuzz '^FuzzEnrolledBindingDecoder$' -fuzztime=5s
```

[Acceptance report](evidence/custody-v2-enrolled-20261028.json) records 13 new
top-level Go tests, all seven race groups, process CLI, integration vet, 56 helper
tests and six fuzz runs totaling 539,124 executions. One offline, read-only,
CGO-free Go 1.26.7 build passed native tests on both Linux hosts with identical
binary hashes. Each host ran the authenticated QUIC lifecycle on loopback;
this does not claim profile-4 cross-host fault acceptance. Task processes are
zero and both task SSH connections are closed.
