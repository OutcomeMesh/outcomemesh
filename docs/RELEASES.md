# Building and releasing OutcomeMesh Core

OutcomeMesh Core supports Go **1.27.3**. The minimum version in `go.mod`, the
`.go-version` pin and official binaries use this version. Support for Go 1.26.7
has ended. Historical records retain the compiler version that produced them;
they are not current build instructions.

Install Go 1.27.3 from [the official Go downloads](https://go.dev/dl/).
With Go's automatic toolchain selection enabled, the module requests the required
version. `make` also selects the repository pin. No compatibility build tag is
needed for the storage dependency.

## Local build

```sh
make build
./bin/omd version --json
```

A source build reports `dev` unless release metadata is supplied. Official
archives are built from a clean Git checkout:

```sh
make release VERSION=v0.1.0-alpha.1 OUT=dist/v0.1.0-alpha.1
```

The output directory must not already exist. Packaging fixes Go 1.27.3, disables
CGO, trims machine-specific paths and records the exact commit. Archive times
come from that commit; file ownership, modes and ordering are normalized.
No existing archive is overwritten. Outputs cover Linux/amd64, Linux/arm64,
macOS/amd64 and macOS/arm64. Windows binaries are not currently distributed.

Each archive includes the executable, `BUILDINFO.json`, project license,
dependency metadata and third-party notices. The release also includes a source
manifest, aggregate build information and `SHA256SUMS`. For downloaded files:

```sh
sha256sum --check SHA256SUMS
# macOS: shasum -a 256 --check SHA256SUMS
```

Checksums establish file consistency. Official GitHub Actions builds also attach
GitHub provenance attestations, which bind artifacts to this repository and its
release workflow:

```sh
gh attestation verify outcomemesh-v0.1.0-alpha.1-linux-amd64.tar.gz --repo OutcomeMesh/outcomemesh
```

## GitHub release workflow

1. Merge the intended release commit into `main`. The repository CI must finish
   successfully for that exact commit, along with Go, Python and Actions CodeQL.
2. Add the release notes at `docs/releases/<tag>.md` before tagging. State concrete
   changes and compatibility requirements; keep execution logs out of the notes.
3. Create and push an annotated version tag, for example `v0.1.0-alpha.1`.
4. The Release workflow requires an annotated tag, its ancestry on `main` and
   the latest successful CI and CodeQL runs for that exact commit. It checks every
   required job in the current run attempt; an older success cannot hide a newer
   failure, cancellation or pending rerun. It builds all archives twice with
   separate caches, compares every output file, rechecks the gates, attaches provenance and
   creates a **draft prerelease**. It never marks a release as stable or latest.
5. Review the draft, assets and notes in GitHub before publishing it.

The workflow can also be started manually for an existing tag. It refuses to
replace an existing release or its assets; inspect a partial draft before any
recovery. Rebuilding is not permission to move a published tag. Until the
production gates are complete, releases remain pre-alpha and do not activate
mainnet.

## Repository policy

`main` requires every CI job, all three CodeQL analysis jobs and the aggregate `required` check, up-to-date
branches, one reviewed pull request and code-owner review. Requiring each job
also prevents a skipped aggregate after cancellation from admitting a change.
Stale approvals are dismissed. Force pushes
and branch deletion are disabled. Repository administrators retain GitHub's
explicit bypass for exceptional maintenance; ordinary contribution flow uses
pull requests. Squash merges and automatic deletion of merged branches keep the
history readable. Version tags cannot be force-updated or deleted.

GitHub Actions defaults to read-only permissions. Only the release job requests
write access to releases and attestations. External actions are pinned to full
commit IDs. Dependabot proposes weekly Go dependency and Actions updates; private
vulnerability reporting, dependency security alerts and CodeQL analysis for
Go, Python and Actions are enabled. Issues and
Discussions serve different purposes, with templates for bugs and proposals.

## Audit and maintenance

With an authenticated GitHub CLI and repository administration read access:

```sh
python3 scripts/repository.py --repo OutcomeMesh/outcomemesh
```

The audit checks merge policy, required reviews, pinned CI/CodeQL check providers,
default Actions permissions, secret scanning and immutable version tags. It exits
unsuccessfully when these settings drift and reports the existing administrator
bypass explicitly. It does not change anything by default. To add missing
required checks with administration write access:

```sh
python3 scripts/repository.py --repo OutcomeMesh/outcomemesh --apply-checks
```

This operation preserves additional checks and all other protection settings.
It does not remove review requirements or change administrator access. Keep
administration credentials out of workflows and repository files. The normal
Actions token is sufficient for building and creating release drafts, but is
not granted repository administration access.

For a local reproducibility check from clean committed source:

```sh
python3 scripts/release.py --version v0.1.0-alpha.2 \
  --out dist/v0.1.0-alpha.2 --verify-reproducible
```

Two matching builds establish determinism on that builder. Independent builder
verification and release review remain separate requirements. A failed build
leaves partial output for inspection and creates no draft; use a fresh output
directory on retry. The workflow never overwrites an existing draft or its assets.
After a failed gate, rerun the Release workflow for the same unchanged tag once
the current required checks succeed.
