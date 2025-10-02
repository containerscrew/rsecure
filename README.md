# rsecure

```bash
openssl rand -out ~/Keys/aes-256.key 32 # Generate a random 256-bit AES key (32 bytes)
```

> [!NOTE]  
> Replace `~/Keys/rsecure.pem` with your desired path.

## Usage

```bash
cargo run --release -- encrypt -r /Users/dcr/Keys/rsecure.pem -s text_to_encrypt.txt
```

```bash
cargo run --release -- decrypt -r /Users/dcr/Keys/rsecure.pem -s text_to_decrypt.txt
```
