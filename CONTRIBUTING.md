# Contributing to OutcomeMesh Core

OutcomeMesh Core is an independent Go implementation of the OutcomeMesh
protocol. It is pre-alpha. Passing a local test or merging a contribution does
not establish that it is safe to operate a network with assets of real value.
The [development plan](docs/PLAN.md) and
[production readiness gates](docs/PRODUCTION_READINESS.md) track that distinction.

## Before changing code

Check the current plan and the runbook for the component you are changing.
For a new protocol rule, storage format, economic rule or dependency, open an
issue describing the problem, proposed behavior and compatibility implications
before investing in a large implementation. Small fixes can go straight to a
pull request against `main`.

Keep a change focused enough to review. Explain the concrete trigger and
resulting behavior; include reproduction steps for a bug. Commit messages
should describe what changed and why. Do not include credentials, private keys,
private server paths, unpublished vulnerability details or raw operator reports
in commits, issue bodies or test fixtures.

## Development environment

Use Go 1.26.7, the toolchain recorded in `go.mod`. From the repository root:

```sh
GOTOOLCHAIN=go1.26.7 make build
GOTOOLCHAIN=go1.26.7 go test ./path/to/changed/package -run '^TestRelevantBehavior$' -count=1
GOTOOLCHAIN=go1.26.7 make -j1 test-all
```

`test-all` formats the code, runs vet and covers the test suite in five disjoint
race-enabled groups. Run the focused checks while developing, then the required
repository gates before submitting a core change. Do not raise timeouts or
weaken assertions to hide a regression. Document a failure and its cause.

For changes to codecs, run their fuzz targets (`make test-fuzz-smoke` runs the
smoke suite). For process recovery, run the relevant tests with
`-tags=integration`; see `make test-process` for the existing selections. Changes
to remote acceptance helpers also need `make test-remote-support` (Python 3).
Describe the operating system, toolchain, commands and results in the pull
request. A permission test skipped under root is not a passing permission test.

## Protocol and storage rules

- Consensus decisions belong in the deterministic core. Do not introduce clocks,
  network calls, filesystem state, randomness or floating point into consensus.
- Validate bounds and canonical encodings before allocating or accepting data.
  Use explicit versions and distinct signature/ID domains. A format or semantic
  change needs compatibility decisions and fixed vectors, including rejection
  of malformed or substituted inputs.
- Validate a full transition before mutation. A durable adapter must serialize
  the decision, persist it and confirm durability before releasing a grant.
  Preserve incomplete writes for explicit recovery; never silently replace a
  history with a fresh one after restart.
- An unknown outcome remains unknown. Timeouts, lost acknowledgements and
  expired leases do not prove that an effect never happened. Test interrupted
  writes, lost output, exact retries, stale positions and conflicting attempts.
- State the trust boundary precisely. A local file identity check does not
  establish protection against a copied signing key or a rolled-back machine.
  Historical signatures do not establish current execution permission.
- Do not bypass retention, pending obligations or reviewed command pins to make
  a recovery path pass. No administrative outcome may manufacture custody proof,
  refresh a receipt or earn rewards.

Use meaningful tests for the changed behavior, particularly safety failures.
Include independent expected values where appropriate; a test that computes its
expected value with the function under test does not validate that function.
Update affected operator documentation alongside externally visible behavior.
Keep experimental adapters separate from deployed protocol claims.

## Review and security reports

A pull request should identify the problem, behavior change, compatibility and
trust assumptions, validation performed, and remaining limitations. Maintainers
may request a smaller change or independent review for consensus, cryptography,
economic rules and durable recovery. Merge does not waive launch gates.

For a suspected exploitable vulnerability, use the repository's private
vulnerability reporting route if it is enabled. Otherwise ask a maintainer for
a private reporting channel without posting exploit details or secrets publicly.
Do not test an exploit against other people's nodes or funds.

## Copyright and licensing

Project-owned code is offered under the [MIT License](LICENSE). By submitting
your contribution for inclusion, you offer that contribution under the same
license and confirm that you have the right to do so. You retain your copyright;
no copyright assignment or additional contributor agreement is required by this
document. The collective project notice does not transfer ownership from authors.

Preserve existing third-party copyright and license notices. Dependencies and
separately licensed material keep their own terms; the repository license does
not relicense them. Explain the provenance and license of imported material in
the pull request. The software license does not grant rights to present a fork
as an official OutcomeMesh release or to use project branding as an endorsement.
