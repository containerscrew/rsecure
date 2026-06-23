# rsecure

`rsecure` is a simple and secure command-line tool for AES-256-GCM file encryption and decryption, built in pure Rust. Ideal for protecting sensitive files, backups, and personal data.

`rsecure` uses `stream` encryption and `rayon` parallelism. The speed of the encryption also depends of your hardware specs (disk speed, CPU speed and number of cores).

<p align="center" >
    <a href="https://github.com/containerscrew/rsecure/actions/workflows/ci-cd.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/containerscrew/rsecure/ci-cd.yml?branch=main&label=CI"></a>
    <a href="./CHANGELOG.md"><img alt="Changelog" src="https://img.shields.io/badge/changelog-md-blue"></a>
    <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/containerscrew/rsecure">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/containerscrew/rsecure">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/containerscrew/rsecure">
    <img alt="GitHub pull requests" src="https://img.shields.io/github/issues-pr/containerscrew/rsecure">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/containerscrew/rsecure?style=social">
    <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/containerscrew/rsecure?style=social">
    <img alt="License" src="https://img.shields.io/badge/License-GPLv3-blue.svg">
    <img alt="Crates.io" src="https://img.shields.io/crates/v/rsecure">
    <img alt="AUR Version" src="https://img.shields.io/aur/version/rsecure">
    <img alt="Crates.io Total Downloads"
     src="https://img.shields.io/crates/d/rsecure?label=crates.io%20downloads">
    <img alt="GitHub Releases Downloads"
        src="https://img.shields.io/github/downloads/containerscrew/rsecure/total?label=github%20downloads">
</p>

---

![rsecure CLI screenshot showing an encrypt run with progress bar](./example.png)

---

## Quickstart

```bash
# 1. Install
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh

# 2. Generate a key (store it somewhere safe!)
rsecure create-key -o ~/rsecure.key

# 3. Encrypt a file (produces secret.txt.enc next to it)
rsecure encrypt -p ~/rsecure.key -s ./secret.txt

# 4. Decrypt it back
rsecure decrypt -p ~/rsecure.key -s ./secret.txt.enc
```

> [!WARNING]
> If you lose the key, the encrypted data is unrecoverable. Read the [Security](#security) section before storing real data.

## Installation

### Universal install script

```shell
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh
```

Pin a specific release by appending `-s -- -v <version>`:

```shell
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh -s -- -v <version>
```

> [!NOTE]
> The installation script automatically detects your `OS` and `ARCH` and installs the correct binary (rpm, deb, apk, or just a binary in `/usr/local/bin`). On Alpine, install `apk add gcompat` since the binary is built with `glibc` and Alpine uses `musl`.

### AUR (Arch Linux)

```bash
paru -S rsecure # or yay -S rsecure
```

### Homebrew

```bash
brew tap containerscrew/tap
brew install --cask rsecure
```

> [!WARNING]
> The binary is not signed by Apple. After installing, remove the quarantine attribute:

```bash
xattr -d com.apple.quarantine /opt/homebrew/bin/rsecure
```

> If you still have issues, install via `cargo` or download the binary from the [releases page](https://github.com/containerscrew/rsecure/releases).

### Using [`cargo`](https://rustup.rs/)

```bash
cargo install rsecure
cargo install rsecure --version <version>   # pin a specific release
```

### Local build

```bash
git clone https://github.com/containerscrew/rsecure.git
cd rsecure
cargo build --release
sudo cp ./target/release/rsecure /usr/local/bin/
```

## Usage

### Commands

| Command                                                                                  | Description                                                          |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `rsecure create-key -o /mnt/myusb/rsecure.key`                                           | Generate a new AES-256 key and save it to a file                     |
| `openssl rand -out /mnt/myusb/rsecure.key 32`                                            | Alternative: generate a random 256-bit key using OpenSSL             |
| `rsecure encrypt -p /mnt/myusb/rsecure.key -s /home/mydirectory/text_to_encrypt.txt`     | Encrypt a single file (`.enc` file is created in the same directory) |
| `rsecure encrypt -p /mnt/myusb/rsecure.key -s /home/mydirectory/files/`                  | Encrypt all files in a directory                                     |
| `rsecure decrypt -p /mnt/myusb/rsecure.key -s /home/mydirectory/text_to_encrypt.txt.enc` | Decrypt a single encrypted file                                      |
| `rsecure decrypt -p /mnt/myusb/rsecure.key -s /home/mydirectory/files/`                  | Decrypt all files in a directory                                     |
| `rsecure encrypt -r -p /mnt/myusb/rsecure.key -s /home/rsecure/dirtoencrypt/`            | Encrypt and **remove** original files (plain text)                   |
| `rsecure encrypt -p /mnt/myusb/rsecure.key -s /home/rsecure/dirtoencrypt -e '.git'`      | Encrypt all files in a directory excluding `.git/` files             |

> [!WARNING]
> Saving the key in the same local filesystem where you save the encrypted files is not a good idea.
> Save the key in a secure location, like a `USB drive` or a password manager.
> Or just save it in a `root owned directory` with strict permissions (will require sudo to use it).

Something like:

```bash
sudo rsecure encrypt -p /root/rsecure.key -s /home/dcr/Documents/PrivateDocuments -r
```

> `rsecure` must be in a PATH directory where `root` user can execute it. Which means, if you installed it using `cargo`, you need to add `~/.cargo/bin` to the `PATH` variable in the `root` user environment. Or just copy the binary to `/usr/local/bin/` or any other directory in the `PATH`.

> [!IMPORTANT]
> By default, `rsecure` will not delete the source plain files after encryption to avoid data loss.
> If you want to delete the source files after encryption, use `-r` flag.

## Security

`rsecure` encrypts file contents with **AES-256-GCM** via the audited [`aes-gcm`](https://crates.io/crates/aes-gcm) crate from [RustCrypto](https://github.com/RustCrypto), using the STREAM construction (`EncryptorBE32`) over 128 KiB chunks. The crate forbids `unsafe` code at the root (`#![forbid(unsafe_code)]`), and the dependency tree is continuously checked against the [RustSec Advisory Database](https://rustsec.org/) by `cargo-audit` and `cargo-deny` in CI.

Read [`SECURITY.md`](./SECURITY.md) for the full threat model — what `rsecure` does and does not protect against, the exact cryptographic parameters, and key custody guidance.

To report a vulnerability, please use [GitHub Security Advisories](https://github.com/containerscrew/rsecure/security/advisories/new) — do **not** open a public issue.

## Local dev

Testing encryption and decryption:

```bash
git clone https://github.com/containerscrew/rsecure.git
cd rsecure
sh scripts/fake_data.sh # will generate 17gb of fake data in /var/tmp/dummy_files/
rsecure encrypt -p /var/tmp/rsecure.key -s /var/tmp/dummy_files/
rsecure decrypt -p /var/tmp/rsecure.key -s /var/tmp/dummy_files/
```

> Edit the `fake_data.sh` script to create different types of files and directories for testing.

### Benchmark (hyperfine)

```bash
cargo install hyperfine
hyperfine --runs 5 'rsecure encrypt -p /var/tmp/rsecure.key -s /var/tmp/dummy_files/'
hyperfine --runs 5 'rsecure decrypt -p /var/tmp/rsecure.key -s /var/tmp/dummy_files/'
```

## License

`rsecure` is distributed under the terms of the [GPLv3](./LICENSE) license.
