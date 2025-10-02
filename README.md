# rsecure

Secure file encryption using pure Rust and AES 🔒

# Usage

Generate a new AES 256 key and save it to a file if you don't have one already:

```bash
rsecure create-key -o ~/.keys/enigma.key
# Or using openssl
openssl rand -out ~/.keys/enigma.key 32
```

```bash
rsecure encrypt -p ~/.keys/enigma.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p ~/.keys/enigma.key -s encrypted.enc -d decrypted.txt
```

> Thats all, KISS (Keep It Simple Stupid)

```bash
rsecure encrypt -p ~/.keys/enigma.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p ~/.keys/enigma.key -s encrypted.enc -d decrypted.txt
```

> Thats all, KISS (Keep It Simple Stupid)

# License

**`rsecure`** is distributed under the terms of the [GPL3](./LICENSE-GPL3) license.