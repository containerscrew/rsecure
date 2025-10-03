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
rsecure create-key -o /mnt/myusb/rsecure.key
# Or using openssl
openssl rand -out /mnt/myusb/rsecure.key 32
```

> [!WARNING]
> Saving the key in the same local filesystem were you save the encrypted files is not a good idea.
> Save the key in a secure location, like a USB drive or a password manager.
> Or just save it in a root owned directory with strict permissions.

```bash
rsecure encrypt -p /mnt/myusb/rsecure.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p /mnt/myusb/rsecure.key -s encrypted.enc -d decrypted.txt
```

> Thats all, KISS (Keep It Simple Stupid)

```bash
rsecure encrypt -p /mnt/myusb/rsecure.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p /mnt/myusb/rsecure.key -s encrypted.enc -d decrypted.txt
```

# Local dev

```bash
mkdir -p /tmp/rsecure/dirtoencrypt
touch /tmp/rsecure/filetoencrypt.txt
echo 'please, hack me!' > /tmp/rsecure/filetoencrypt.txt
for i in {1..10}; do
    head -c 100 /dev/urandom | base64 > /tmp/rsecure/dirtoencrypt/file_$i.txt
done
```

# License

**`rsecure`** is distributed under the terms of the [GPL3](./LICENSE-GPL3) license.