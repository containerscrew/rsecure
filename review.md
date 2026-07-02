# Review de `rsecure`

## Lo Bueno

- **Diseño criptográfico sólido**: AES-256-GCM con HKDF-SHA256 por archivo, AAD binding del header, formatos versionados (v1/v2/v3 legacy). La `SECURITY.md` es honesta sobre el threat model — de lo mejor que he visto en proyectos pequeños.
- **Código limpio y bien estructurado**: Separación clara entre `cli/`, `commands/`, `crypto.rs`, `format.rs`, `file_ops.rs`. Sin `unsafe`, con `anyhow` para errores.
- **Buenos tests de integración**: Roundtrip, multi-chunk, legacy v1, passphrase, tampering de header, exclusión de directorios, fallo con contraseña incorrecta. Bien cubierto.
- **CI y tooling sólidos**: `cargo-deny`, `cargo-audit`, pre-commit hooks, conventional commits con cocogitto.
- **Operaciones atómicas**: Patrón write-to-tmp + rename, cleanup en error.

## Cosas a Mejorar

### 1. `DecryptionArgs` definido pero nunca usado (dead code)

En `src/cli/args.rs:49-53` defines un struct `DecryptionArgs` que solo tiene un campo `common`, pero en la línea 21 el comando `Decrypt` usa `EncryptionArgs`:

```rust
Decrypt(EncryptionArgs),   // args.rs:21
```

Esto implica que `decrypt` hereda flags irrelevantes como `--passphrase` y `--exclude-dir`. La función `decrypt_file.rs:run` acepta `EncryptionArgs` e ignora esos campos. Sugiero: o eliminar `DecryptionArgs` y renombrar `EncryptionArgs` a algo genérico, o usar `DecryptionArgs` para el comando decrypt.

### 2. Flag `-r/--remove-file` ignorado en decrypt

En `src/commands/decrypt_file.rs:108`, el source `.enc` se borra **siempre** tras un descifrado exitoso, sin consultar el flag `enc_args.common.remove_file`:

```rust
fs::remove_file(source)?;  // línea 108 — incondicional
```

El CLI documenta `-r` como "remove file after encryption or decryption", pero decrypt lo ignora. O bien hazlo respetar el flag, o elimina `-r` del help de decrypt.

### 3. Material sensible no se zeroiza

Passphrase y key material se almacenan en `Vec<u8>` y arrays en stack, sin zeroización explícita tras su uso. Para una herramienta criptográfica, sería buena práctica usar el crate `zeroize` (o al menos `vec.fill(0)` + `drop`) para las passphrases y claves derivadas. En Rust no hay garantía de que el compilador no optimice un `.fill(0)` a no-op, así que `zeroize` es lo recomendado.

### 4. Sin barra de progreso para archivos individuales

Solo se muestra progress bar en modo directorio. Para un archivo de 5 GB encriptándose con chunks de 128 KiB, el usuario no ve nada hasta que termina. Sería útil añadir una barra de progreso también en `encrypt_file_stream` y `decrypt_file_stream`.

### 5. Clonaciones innecesarias

`src/commands/decrypt_file.rs:236`: `enc_args.common.source.clone()` es innecesario porque el `else` branch toma ownership y `is_dir`/`is_file` aceptan `&str`. Podrías reestructurar con un `if let` o `match` que evite el clone.

### 6. Parámetros Argon2 no configurables desde CLI

Los costos de Argon2 (m_cost, t_cost, p_cost) están hardcodeados en `format.rs:37-39`. Sería útil permitir `--argon2-memory`, `--argon2-time`, `--argon2-parallelism` para dar flexibilidad.

### 7. `open_private_key` no valida que el archivo sea exactamente 32 bytes

`src/file_ops.rs:16-21`: solo lee 32 bytes, ignorando silenciosamente bytes extra si el archivo es más largo. Convendría verificar que no queden bytes sin leer (`file.bytes().next().is_none()`).

## Veredicto

El proyecto está **muy bien** para ser una herramienta CLI de cifrado de archivos. Las decisiones criptográficas son correctas y están bien documentadas. Los problemas encontrados son de pulido (dead code, zeroización, UX consistency), no de seguridad. Con los ajustes sugeridos quedaría redondo.
