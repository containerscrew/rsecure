use std::fs::{self, File};
use std::io::{Read, Write};

use crate::cli::EncryptionArgs;
use crate::file_ops::open_private_key;
use crate::utils::{is_dir, is_file};
use aes_gcm::aead::stream;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;

// TODO: Add tests for decryption

// Decrypt file in chunks
fn decrypt_file_stream(key_bytes: &[u8], source: &str) -> Result<()> {
    // Init cipher
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Gen dest filename
    let dest = if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", source)
    };

    // Open files
    let mut source_file = File::open(source)?;
    let mut dest_file = File::create(&dest)?;

    // Read 7-byte nonce
    let mut nonce = [0u8; 7];
    source_file.read_exact(&mut nonce)?;

    // Init stream decryptor
    let mut decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

    // Set 128KB + 16B buffer
    let mut buffer = vec![0u8; 131072 + 16];

    // Read, decrypt, write loop
    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == buffer.len() {
            // Decrypt full chunk
            let plaintext = decryptor
                .decrypt_next(buffer[..].as_ref())
                .map_err(|_| anyhow::anyhow!("Decryption error or file corrupted"))?;
            dest_file.write_all(&plaintext)?;
        } else if read_count > 0 {
            // Decrypt final chunk
            let plaintext = decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|_| anyhow::anyhow!("Decryption error on final chunk"))?;
            dest_file.write_all(&plaintext)?;
            break;
        } else {
            break;
        }
    }

    // Always remove encrypted file
    fs::remove_file(source)?;

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read AES key
    let key_bytes = open_private_key(&enc_args.common.private_key_path)?;

    if is_dir(&enc_args.common.source) {
        // Collect files into Vec
        let files_to_process: Vec<_> = WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().map_or(false, |ext| ext == "enc")
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .collect();

        // Setup progress bar
        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        // Process files in parallel
        files_to_process.into_par_iter().for_each(|file_path| {
            if let Err(e) = decrypt_file_stream(&key_bytes, &file_path) {
                eprintln!("Failed to decrypt {}: {}", file_path, e);
            }
            // Update progress bar
            pb.inc(1);
        });

        // Finish progress bar
        pb.finish_with_message("Decryption complete");
    } else if is_file(&enc_args.common.source) {
        decrypt_file_stream(&key_bytes, &enc_args.common.source)?;
    } else {
        eprintln!("Path '{}' is not valid.", enc_args.common.source);
    }

    Ok(())
}
