# rsecure

Secure file encryption using pure Rust and AES 

# Usage

Generate a new AES 256 key and save it to a file.

```bash
rsecure create-key -o ~/.keys/enigma.key
```

```bash
rsecure encrypt -p ~/.keys/enigma.key -s text_to_encrypt.txt -d encrypted.enc
```

```bash
rsecure decrypt -p ~/.keys/enigma.key -s encrypted.enc -d decrypted.txt
```

> Thats all, KISS (Keep It Simple Stupid)

# License

**`rsecure`** is distributed under the terms of the [GPL3](./LICENSE-GPL3) license.