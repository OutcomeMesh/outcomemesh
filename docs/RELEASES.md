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
   successfully for that exact commit.
2. Add the release notes at `docs/releases/<tag>.md` before tagging. State concrete
   changes and compatibility requirements; keep execution logs out of the notes.
3. Create and push an annotated version tag, for example `v0.1.0-alpha.1`.
4. The Release workflow verifies the tag, its ancestry on `main` and the successful
   CI run, builds all archives with the pinned compiler, attaches provenance and
   creates a **draft prerelease**. It never marks a release as stable or latest.
5. Review the draft, assets and notes in GitHub before publishing it.

The workflow can also be started manually for an existing tag. It refuses to
replace an existing release or its assets; inspect a partial draft before any
recovery. Rebuilding is not permission to move a published tag. Until the
production gates are complete, releases remain pre-alpha and do not activate
mainnet.

## Repository policy

`main` uses the required `required` CI check, up-to-date branches, one reviewed
pull request and code-owner review. Stale approvals are dismissed. Force pushes
and branch deletion are disabled. Repository administrators retain GitHub's
explicit bypass for exceptional maintenance; ordinary contribution flow uses
pull requests. Squash merges and automatic deletion of merged branches keep the
history readable. Version tags cannot be force-updated or deleted.

GitHub Actions defaults to read-only permissions. Only the release job requests
write access to releases and attestations. External actions are pinned to full
commit IDs. Dependabot proposes weekly Go dependency and Actions updates; private
vulnerability reporting and dependency security alerts are enabled. Issues and
Discussions serve different purposes, with templates for bugs and proposals.
