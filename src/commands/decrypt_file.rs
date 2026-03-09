use std::fs::{self, File};
use std::io::{Read, Write};

use crate::cli::EncryptionArgs;
use crate::file_ops::open_private_key;
use crate::utils::{is_dir, is_file};
use aes_gcm::aead::stream;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::Result;
use walkdir::WalkDir;

// TODO: Add tests for decryption

/// Decrypts file in chunks and deletes encrypted source
fn decrypt_file_stream(key_bytes: &[u8], source: &str) -> Result<()> {
    // Init cipher from key bytes
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Gen destination filename
    let dest = if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", source)
    };

    // Open source and dest files
    let mut source_file = File::open(source)?;
    let mut dest_file = File::create(&dest)?;

    // Read 7-byte nonce
    let mut nonce = [0u8; 7];
    source_file.read_exact(&mut nonce)?;

    // Init stream decryptor
    let mut decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

    // Set 4KB + 16B buffer for auth tag
    let mut buffer = [0u8; 4096 + 16];

    // Read, decrypt and write loop
    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == buffer.len() {
            let plaintext = decryptor
                .decrypt_next(buffer[..].as_ref())
                .map_err(|_| anyhow::anyhow!("Decryption error or file corrupted"))?;
            dest_file.write_all(&plaintext)?;
        } else if read_count > 0 {
            let plaintext = decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|_| anyhow::anyhow!("Decryption error on final chunk"))?;
            dest_file.write_all(&plaintext)?;
            break;
        } else {
            break;
        }
    }

    // Always delete encrypted file after decryption
    fs::remove_file(source)?;

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read AES key from file
    let key_bytes = open_private_key(&enc_args.common.private_key_path)?;

    if is_dir(&enc_args.common.source) {
        // Iterate and decrypt .enc files recursively
        for entry in WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().map_or(false, |ext| ext == "enc")
            })
        {
            let file_path = entry.path().to_string_lossy().to_string();
            decrypt_file_stream(&key_bytes, &file_path)?;
        }
    } else if is_file(&enc_args.common.source) {
        decrypt_file_stream(&key_bytes, &enc_args.common.source)?;
    } else {
        eprintln!(
            "Path '{}' is neither a file nor directory.",
            enc_args.common.source
        );
    }

    Ok(())
}
