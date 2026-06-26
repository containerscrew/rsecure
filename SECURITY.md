# Security Policy

`rsecure` is a file encryption CLI built on top of [AES-256-GCM][aes-gcm]. Because it handles
sensitive data, the following document describes what it does and does not protect against,
and how to responsibly report a vulnerability.

## Supported Versions

Only the latest released version receives security fixes. Older versions are unsupported.
Check the latest release at https://github.com/containerscrew/rsecure/releases.

## Cryptographic Design

### File format v2 (current)

| Element            | Value |
|--------------------|-------|
| Cipher             | AES-256-GCM (256-bit key, 128-bit tag) |
| Construction       | STREAM (chunked AEAD) via `aes_gcm::aead::stream::EncryptorBE32` |
| Chunk size         | 131072 bytes (128 KiB), declared per-file in the header |
| Key derivation     | HKDF-SHA256(ikm=master_key, salt=random 32 B per file, info=`"rsecure-v2-aes256gcm-stream"`) → 32-byte AES-256 subkey |
| STREAM nonce       | Fixed all-zero 7-byte salt; uniqueness is provided by the per-file HKDF subkey, with STREAM's 4-byte BE32 counter ensuring uniqueness across chunks within the file |
| File header        | `RSEC` magic (4 B) + version byte (`0x02`) + chunk_size (u32 LE, 4 B) + HKDF salt (32 B) = **41 bytes** |
| Header authenticity | The full 41-byte header is passed as AAD on every chunk; any tampering with magic, version, chunk_size, or salt invalidates the first chunk's GCM tag and decryption fails before any plaintext is recovered |
| Master key storage | 32 random bytes from the OS RNG, written as plain bytes on disk at a location chosen by the user |

Because the AES-256 subkey is unique per file (derived from a fresh 256-bit random salt),
the `(key, nonce)` pair is globally unique across all files even with a fixed STREAM nonce.
This eliminates the birthday-bound nonce-collision concern that would otherwise apply to
AES-GCM's 96-bit nonce when many files are encrypted under the same master key.

On decrypt, a sanity bound (`chunk_size ≤ 16 MiB`) rejects pathological headers before
any buffer is allocated, so a hostile `.enc` cannot trigger an unbounded allocation.

### File format v1 (legacy, decrypt-only)

Files produced by rsecure ≤ 0.5.0 use AES-256-GCM STREAM with a 7-byte random nonce derived
directly from the master key, no HKDF, no magic header. `rsecure decrypt` still reads these
— the absence of the `RSEC` magic switches the decryptor to the legacy path. New
encryptions always use v2.

The cryptographic primitives are provided by the [`aes-gcm`][aes-gcm-crate] and
[`hkdf`][hkdf-crate] crates from [RustCrypto], widely-used, audited, pure-Rust
implementations.

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
- **No forward secrecy / no post-compromise security.** If the master key is
  compromised, all past and future ciphertext under that key is exposed (HKDF subkeys
  are derived deterministically from the master key and the per-file salt).
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
  long-lived v1 archives with the current version to migrate them to v2.

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
[RustCrypto]: https://github.com/RustCrypto
