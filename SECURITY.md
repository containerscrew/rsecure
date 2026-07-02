# Security Policy

`rsecure` is a file encryption CLI built on top of [AES-256-GCM][aes-gcm]. Because it handles
sensitive data, the following document describes what it does and does not protect against,
and how to responsibly report a vulnerability.

## Supported Versions

Only the latest released version receives security fixes. Older versions are unsupported.
Check the latest release at https://github.com/containerscrew/rsecure/releases.

## Cryptographic Design

### File format v3 (current)

| Element             | Value |
|---------------------|-------|
| Cipher              | AES-256-GCM (256-bit key, 128-bit tag) |
| Construction        | STREAM (chunked AEAD) via `aes_gcm::aead::stream::EncryptorBE32` |
| Chunk size          | 131072 bytes (128 KiB), declared per-file in the header |
| Key derivation      | HKDF-SHA256(ikm=master_key, salt=random 32 B per file, info=`"rsecure-v3-aes256gcm-stream"`) → 32-byte AES-256 subkey |
| STREAM nonce        | Fixed all-zero 7-byte salt; uniqueness is provided by the per-file HKDF subkey, with STREAM's 4-byte BE32 counter ensuring uniqueness across chunks within the file |
| File header         | `RSEC` (4 B) + version `0x03` (1 B) + flags (1 B) + chunk_size (u32 LE, 4 B) + HKDF salt (32 B) = **42 bytes**; passphrase mode appends Argon2 params (9 B) + Argon2 salt (16 B) for **67 bytes** total |
| Header authenticity | The entire on-disk header is passed as AAD on every chunk; any tampering invalidates the first GCM tag and decryption fails before any plaintext is recovered |
| Master key source   | Either a 32-byte keyfile (default) or derived once-per-invocation from a passphrase via Argon2id, see below |

#### Master key sources

`flags & 0x01 == 0` (**keyfile**): the master key is the 32-byte keyfile passed
via `-p`. This is the strongest default — the master key has 256 bits of OS-RNG
entropy.

`flags & 0x01 == 1` (**passphrase**): the master key is derived via
Argon2id(passphrase, argon2_salt, params) where the salt and parameters live in
the file header. Default parameters: `m_cost = 19456 KiB (~19 MiB)`,
`t_cost = 2`, `p_cost = 1`, output length 32 bytes. These defaults can be
overridden per-invocation via `--argon2-memory`, `--argon2-time`, and
`--argon2-parallelism`; the chosen values are recorded in each file's header so
decryption picks them up automatically. **Raising the parameters (more memory,
more iterations) strengthens the KDF; lowering them below the defaults weakens
it and is discouraged.** The salt is generated once per invocation, so an entire
`encrypt` batch shares one Argon2 derivation; the decrypter caches by salt to
avoid re-running the KDF on subsequent files of the same batch.

**Security in passphrase mode is bounded by the entropy of your passphrase.**
Argon2id raises the cost-per-attempt enough to make weak passphrases
significantly harder to brute-force, but a 6-character dictionary word remains
weak regardless of the KDF.

Because the AES-256 subkey is unique per file (derived from a fresh 256-bit
random salt), the `(key, nonce)` pair is globally unique across all files even
with a fixed STREAM nonce. This eliminates the birthday-bound nonce-collision
concern that would otherwise apply to AES-GCM's 96-bit nonce when many files
are encrypted under the same master key.

On decrypt, a sanity bound (`chunk_size ≤ 16 MiB`) rejects pathological headers
before any buffer is allocated, so a hostile `.enc` cannot trigger an unbounded
allocation.

### File formats v1 and v2 (legacy, decrypt-only)

- **v1** (rsecure ≤ 0.5.0): AES-256-GCM STREAM with a 7-byte random nonce
  derived directly from the master key, no HKDF, no magic header.
- **v2** (interim, brief release window before v3): `RSEC` `0x02` header,
  HKDF-derived subkey, AAD-bound — same scheme as v3 keyfile mode but without
  the flags byte.

`rsecure decrypt` reads both transparently; the dispatcher picks the right
code path from the magic + version. New encryptions always use v3.

The cryptographic primitives are provided by the [`aes-gcm`][aes-gcm-crate],
[`hkdf`][hkdf-crate], and [`argon2`][argon2-crate] crates from [RustCrypto],
widely-used, audited, pure-Rust implementations.

## Threat Model

### What rsecure guarantees

- **Confidentiality** of file contents under a chosen-plaintext attacker that does not
  possess the master key.
- **Integrity & authenticity** of each chunk — any tampering will be detected on decrypt
  (GCM authentication tag).
- **Resistance to chunk reordering or truncation** — STREAM binds chunks via a counter
  and a final-chunk marker.
- **No catastrophic nonce reuse across files** — the per-file HKDF subkey makes the
  `(key, nonce)` pair globally unique even with a fixed STREAM nonce.
- **Best-effort memory hygiene** for secrets. Passphrases, master keys, and
  derived subkeys are wrapped in [`zeroize`](https://crates.io/crates/zeroize)
  guards and cleared on drop. This is best-effort — Rust does not guarantee
  freedom from compiler-introduced copies or spilled stack slots, and swap /
  hibernation / core dumps can still leak secrets outside the process — but it
  narrows the residual-memory attack surface.
- **Header authenticity (v2 only).** Modifying any byte of the on-disk header
  (magic, version, chunk_size, salt) causes decryption to fail with an auth error
  on the first chunk, before any plaintext is written. There is no downgrade,
  rebinding, or wrong-key-via-salt-swap path that produces valid plaintext.

### What rsecure does NOT guarantee

- **Filename and directory structure are not protected.** Only the file contents are
  encrypted; metadata (paths, sizes, timestamps) remain visible.
- **Key storage is the user's responsibility.** A master key file left on disk in
  plaintext offers no protection against an attacker with filesystem access. Use
  full-disk encryption, a hardware token, or a password manager for key custody.
- **No forward secrecy / no post-compromise security.** If the master key (or
  passphrase) is compromised, all past and future ciphertext under it is
  exposed (HKDF subkeys are derived deterministically from the master key and
  the per-file salt).
- **No authenticated key exchange.** Distributing the master key to another party is
  out of scope; use an out-of-band secure channel (Signal, age, GPG, in person).
- **No plausible deniability.** Encrypted files are clearly identifiable as such (`.enc`
  extension and structured header).
- **Side-channel resistance** is best-effort, inherited from `aes-gcm`. The crate uses
  constant-time arithmetic but does not formally guarantee freedom from cache or timing
  side channels on every target architecture. On CPUs without AES-NI (or equivalent
  hardware-accelerated AES), software AES is more exposed to cache-timing side channels.
- **Legacy v1 nonce collisions.** Files encrypted by rsecure ≤ 0.5.0 used a 7-byte
  random nonce (56 bits), which approaches the birthday bound around 2²⁸ files
  (~268M) and crosses NIST's 2⁻³² safety margin around ~6k files. Re-encrypt
  long-lived v1 archives with the current version to migrate them to v3.
- **Passphrase strength.** In passphrase mode, the master key's effective
  security is bounded by your passphrase's entropy. Argon2id raises the
  per-attempt cost but cannot rescue a weak passphrase from an offline
  brute-force attacker who obtains a `.enc` file. Use a key file for the
  strongest guarantee, or a long, high-entropy passphrase (e.g., a diceware
  phrase of 6+ words).

## Reporting a Vulnerability

**Do not file public issues for security vulnerabilities.**

Please report security issues via one of these channels:

1. **GitHub Security Advisories (preferred):** open a private advisory at
   https://github.com/containerscrew/rsecure/security/advisories/new
2. **Email:** `info@containerscrew.com` with the subject prefixed by `[rsecure-sec]`.

Please include:

- A description of the issue and its impact.
- A minimal reproduction (file, command, expected vs. actual behavior).
- Your suggested fix, if any.

You can expect an acknowledgement within 7 days and a status update within 30 days.
Coordinated disclosure is preferred; please give us a reasonable window to ship a fix
before public disclosure.

[aes-gcm]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[aes-gcm-crate]: https://crates.io/crates/aes-gcm
[hkdf-crate]: https://crates.io/crates/hkdf
[argon2-crate]: https://crates.io/crates/argon2
[RustCrypto]: https://github.com/RustCrypto
