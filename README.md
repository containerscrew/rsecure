# rsecure

Secure file encryption using pure Rust and AES 🔒.

> _Keep It Simple Stupid_

<p align="center" >
    <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/containerscrew/rsecure">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/containerscrew/rsecure">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/containerscrew/rsecure">
    <img alt="GitHub pull requests" src="https://img.shields.io/github/issues-pr/containerscrew/rsecure">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/containerscrew/rsecure?style=social">
    <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/containerscrew/rsecure?style=social">
    <img alt="License" src="https://img.shields.io/badge/License-GPLv3-blue.svg">
    <img alt="Crates.io" src="https://img.shields.io/crates/v/rsecure">
    <img alt="Crates.io downloads" src="https://img.shields.io/crates/dr/rsecure?style=flat&label=crates.io%20Downloads">
</p>

---

# Installation

```bash
cargo install rsecure
```

Without cargo:

```bash
git clone https://github.com/containerscrew/rsecure.git
cd rsecure
cargo build --release
sudo cp ./target/release/rsecure /usr/local/bin/
```

# Usage

Generate a new AES 256 key and save it to a file if you don't have one already:

```bash
rsecure create-key -o /mnt/myusb/rsecure.key
# Or using openssl
openssl rand -out /mnt/myusb/rsecure.key 32
```

> [!WARNING]
> Saving the key in the same local filesystem were you save the encrypted files is not a good idea.
> Save the key in a secure location, like a `USB drive` or a password manager.
> Or just save it in a `root owned directory` with strict permissions (will require sudo to use it).

```bash
rsecure encrypt -p /mnt/myusb/rsecure.key -s /tmp/mydirectory/text_to_encrypt.txt 
```

> This will create a file named `text_to_encrypt.txt.enc` in the same directory as the source file.

```bash
rsecure encrypt -p /mnt/myusb/rsecure.key -s /tmp/mydirectory/files/
```

> This will encrypt all the files inside the directory `/tmp/mydirectory/files/`

```bash
rsecure decrypt -p /mnt/myusb/rsecure.key -s /tmp/mydirectory/text_to_encrypt.txt.enc
```

> This will decrypt the file named `text_to_encrypt.txt.enc` in the same directory as the source file.

```bash
rsecure decrypt -p /mnt/myusb/rsecure.key -s /tmp/mydirectory/files/
```

> This will decrypt all the files inside the directory `/tmp/mydirectory/files/`

# Local dev

Testing encryption and decryption:

```bash
mkdir -p /tmp/rsecure/dirtoencrypt
touch /tmp/rsecure/filetoencrypt.txt
echo 'please, hack me!' > /tmp/rsecure/filetoencrypt.txt
for i in {1..10}; do
    head -c 100 /dev/urandom | base64 > /tmp/rsecure/dirtoencrypt/file_$i.txt
done
```

```bash
rsecure create-key -o ~/.keys/rsecure.key
rsecure encrypt -p ~/.keys/rsecure.key -s /tmp/rsecure/filetoencrypt.txt
rsecure decrypt -p ~/.keys/rsecure.key -s /tmp/rsecure/filetoencrypt.txt.enc
#
rsecure encrypt -p ~/.keys/rsecure.key -s /tmp/rsecure/dirtoencrypt/
rsecure decrypt -p ~/.keys/rsecure.key -s /tmp/rsecure/dirtoencrypt/
```

# License

**`rsecure`** is distributed under the terms of the [GPL3](./LICENSE-GPL3) license.