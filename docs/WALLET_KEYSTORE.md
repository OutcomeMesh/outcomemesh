# Encrypted local wallet keys

`omd keygen` now creates an encrypted wallet. It requires `--passphrase-file`:
a regular file with mode 0600 or stricter containing 12–1024 exact bytes. Newlines
are significant. There is no passphrase argument or environment-variable fallback.
Keep this file outside the wallet's backup and access domain; storing both together
would defeat protection against a stolen wallet backup. The current interface is
an operator CLI; a no-echo interactive unlock and a reviewed user wallet remain
separate work.

```sh
omd keygen --out alice.key --passphrase-file /private/location/alice.pass
omd transfer --data ./data/dev --key alice.key \
  --passphrase-file /private/location/alice.pass --to ADDRESS --amount 100 --fee 1
omd key-encrypt --in old-alice.seed --out encrypted-alice.key \
  --passphrase-file /private/location/alice.pass
```

Migration preserves the raw source. Confirm access and backup of the encrypted
copy before deciding how to retire the old seed. Existing backups containing a
raw seed remain sensitive. Creation never overwrites any path; writes synchronize
the file and parent directory. Partial files after an error are retained for
inspection, not silently replaced. Reads reject symlinks, non-regular files,
public permissions and oversized inputs. Parent directories must remain trusted.

Version 1 has exactly 116 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `OMKEY001` |
| 8 | 16 | random Argon2 salt |
| 24 | 32 | Ed25519 public key |
| 56 | 12 | random GCM nonce |
| 68 | 48 | encrypted 32-byte seed and 16-byte authentication tag |

Argon2id uses 64 MiB, three passes, four lanes, and a 32-byte output, following
the memory-constrained profile in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
AES-256-GCM authenticates the full 56-byte header as associated data. Go's
`NewGCMWithRandomNonce` generates the nonce. Parameters are fixed by the version;
an untrusted file cannot request arbitrary KDF work. Unsupported versions fail
closed. The public key is visible and is unauthenticated until decryption succeeds.

Raw 32-byte seeds remain readable for existing development workflows. New raw
seeds require `keygen --plaintext`; daemon transport/miner identities continue to
use that explicit format. This option is not an encrypted user wallet. Temporary
seed, derived-key and password buffers are cleared where available, but Go and
the operating system do not guarantee complete removal of all memory copies.
Encryption protects the stored seed, not a compromised running machine. Lost
passphrases cannot be recovered by the project.
