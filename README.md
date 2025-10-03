# rsecure

Secure file encryption using pure Rust and AES 🔒.

> _Keep It Simple Stupid_

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
rsecure create-key -o ~/.keys/rsecure.key
# Or using openssl
openssl rand -out ~/.keys/rsecure.key 32
```

> [!WARNING]
> Saving the key in the same local filesystem were you save the encrypted files is not a good idea.
> Save the key in a secure location, like a USB drive or a password manager.
> Or just save it in a root owned directory with strict permissions

```bash
rsecure encrypt -p ~/.keys/rsecure.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p ~/.keys/rsecure.key -s encrypted.enc -d decrypted.txt
```

> Thats all, KISS (Keep It Simple Stupid)

```bash
rsecure encrypt -p ~/.keys/rsecure.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p ~/.keys/rsecure.key -s encrypted.enc -d decrypted.txt
```

# License

**`rsecure`** is distributed under the terms of the [GPL3](./LICENSE-GPL3) license.