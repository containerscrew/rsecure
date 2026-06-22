# Security Policy

`rsecure` is a file encryption CLI built on top of [AES-256-GCM][aes-gcm]. Because it handles
sensitive data, the following document describes what it does and does not protect against,
and how to responsibly report a vulnerability.

## Supported Versions

Only the latest released version receives security fixes. Older versions are unsupported.
Check the latest release at https://github.com/containerscrew/rsecure/releases.

## Cryptographic Design

| Element       | Value |
|---------------|-------|
| Cipher        | AES-256-GCM (256-bit key, 96-bit tag) |
| Construction  | STREAM (chunked AEAD) via `aes_gcm::stream::EncryptorBE32` |
| Chunk size    | 131072 bytes (128 KiB) |
| Nonce         | 7 random bytes per file from the OS RNG (`OsRng`), 4-byte BE32 counter appended per chunk by STREAM |
| Key generation| `Aes256Gcm::generate_key(OsRng)` (32 bytes from the OS RNG) |
| Key storage   | Plain bytes on disk, location chosen by the user |

The cryptographic primitives are provided by the [`aes-gcm`][aes-gcm-crate] crate from
[RustCrypto], which is a widely-used, audited, pure-Rust implementation.

## Threat Model

### What rsecure guarantees

- **Confidentiality** of file contents under a chosen-plaintext attacker that does not
  possess the key.
- **Integrity & authenticity** of each chunk — any tampering will be detected on decrypt
  (GCM authentication tag).
- **Resistance to chunk reordering or truncation** — STREAM binds chunks via a counter
  and a final-chunk marker.

### What rsecure does NOT guarantee

- **Filename and directory structure are not protected.** Only the file contents are
  encrypted; metadata (paths, sizes, timestamps) remain visible.
- **Key storage is the user's responsibility.** A key file left on disk in plaintext
  offers no protection against an attacker with filesystem access. Use full-disk
  encryption, a hardware token, or a password manager for key custody.
- **No forward secrecy / no post-compromise security.** If the long-term key is
  compromised, all past and future ciphertext under that key is exposed.
- **No authenticated key exchange.** Distributing the key to another party is out of
  scope; use an out-of-band secure channel (Signal, age, GPG, in person).
- **No plausible deniability.** Encrypted files are clearly identifiable as such (`.enc`
  extension and structured header).
- **Side-channel resistance** is best-effort, inherited from `aes-gcm`. The crate uses
  constant-time arithmetic but does not formally guarantee freedom from cache or timing
  side channels on every target architecture.
- **Nonce collisions** are not impossible. With 7 random nonce bytes (56 bits), encrypting
  many files under the same key approaches the birthday bound around 2^28 files (~268M).
  This is acceptable for personal use but **rsecure should not be used to encrypt
  unbounded numbers of files under a single static key without periodic key rotation**.

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
[RustCrypto]: https://github.com/RustCrypto
