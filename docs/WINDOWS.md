# Windows operation

The `windows-amd64.zip` download is for x64 Windows; `windows-arm64.zip` is for
Windows on ARM. Extract the whole archive into a new directory. In PowerShell:

```powershell
.\omd.exe version --json
Get-FileHash .\outcomemesh-v0.2.0-windows-amd64.zip -Algorithm SHA256
```

Run the checksum command from the directory containing the downloaded ZIP and
compare its digest with that filename in the release's `SHA256SUMS`. Provenance
can also be verified with `gh attestation verify <archive> --repo OutcomeMesh/outcomemesh`.

## Command coverage

The native Windows amd64 gate covers core validation, ledger persistence,
wallet creation and encryption, protocol 0 and protocol 2 chain initialization,
transfers, mining, status and replay after reopening. This is development network
coverage. Protocol 2 still requires a separate explicit network identifier.
ARM64 archives are cross-compiled; native ARM64 execution is not yet qualified.

Protected custody owner services use Unix file identity and process isolation.
The `work-archive-custody-guard`, `-guard-revoke`, `-guard-replace`, `-gateway`,
`-gateway-replace` and `-profile5` commands refuse on Windows before touching
operator files. Deploy those services on supported Linux hosts. Other protected
journal and WorkGraph operator procedures have not received Windows runtime
acceptance; use their documented Linux environment. Downloading a Windows
executable does not establish support for those procedures.

## Private keys

`keygen` writes an encrypted wallet by default and requires a private passphrase
file. Its encoding and encryption are the same on all platforms. Windows key
files are created atomically with a protected ACL granting access only to the
current user and SYSTEM. File data is flushed before creation reports success;
this is not a claim of directory durability across sudden power loss.

A passphrase file must likewise be owned by the current user, with explicit
(non-inherited) allow entries only for that user and SYSTEM. Keep its parent
directory private before entering any secret, disable inheritance on the file,
and remove other entries through Windows security properties. The exact file
bytes are the passphrase; a newline or encoding marker changes it. The CLI
rejects permissive files instead of silently changing permissions. Use a local
NTFS volume; network shares, device namespaces and alternate streams are refused.

An explicit `keygen --plaintext` is available for development daemon identities.
It still creates a restricted file, but the seed is unencrypted. Do not treat
that option as an encrypted wallet. Administrators and SYSTEM remain part of
the operating-system trust boundary; ACLs do not protect against a compromised
machine, copied backups or a malicious administrator.

## Building from source

Install the Go version recorded in `.go-version`, then run from the repository:

```powershell
go build -mod=readonly -trimpath -o omd.exe ./cmd/omd
.\omd.exe version --json
```

A source build reports `dev`. Official release packaging runs on the release
builder, records the exact source commit and verifies repeatable archive bytes.
