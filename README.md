# rsecure

```bash
openssl genpkey -algorithm RSA -out ~/Keys/rsecure.pem -pkeyopt rsa_keygen_bits:4096
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
