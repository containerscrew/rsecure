use std::fs::{self, File};
use std::io::{Read, Write};

use crate::cli::EncryptionArgs;
use crate::file_ops::open_private_key;
use crate::utils::{is_dir, is_file};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::stream;
use aes_gcm::{Aes256Gcm, KeyInit, aead::OsRng};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;

fn is_excluded_dir(path: &str, exclude_list: &[String]) -> bool {
    exclude_list.iter().any(|ex| path.contains(ex))
}

// Encrypt file in chunks
fn encrypt_file_stream(key_bytes: &[u8], source: &str, should_remove: bool) -> Result<()> {
    // Init cipher
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Gen 7-byte nonce
    let mut nonce = [0u8; 7];
    OsRng.fill_bytes(&mut nonce);

    // Init stream encryptor
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce.into());

    // Set dest filename
    let dest = format!("{}.enc", source);

    // Open files
    let mut source_file = File::open(source)?;
    let mut dest_file = File::create(&dest)?;

    // Write nonce
    dest_file.write_all(&nonce)?;

    // Set 128KB buffer
    let mut buffer = vec![0u8; 131072];

    // Read, encrypt, write loop
    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == buffer.len() {
            // Encrypt full chunk
            let ciphertext = encryptor
                .encrypt_next(buffer[..].as_ref())
                .map_err(|_| anyhow::anyhow!("Encryption error on chunk"))?;
            dest_file.write_all(&ciphertext)?;
        } else {
            // Encrypt final chunk
            let ciphertext = encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|_| anyhow::anyhow!("Encryption error on final chunk"))?;
            dest_file.write_all(&ciphertext)?;
            break;
        }
    }

    // Remove original file
    if should_remove {
        fs::remove_file(source)?;
    }

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
            .filter(|e| e.path().is_file())
            .filter(|e| {
                !is_excluded_dir(
                    &e.path().to_string_lossy(),
                    enc_args.exclude_dir.as_deref().unwrap_or(&[]),
                )
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .filter(|path| !path.ends_with(".enc"))
            .collect();

        // Setup progress bar
        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        // Process files in parallel
        files_to_process.into_par_iter().for_each(|file_path| {
            if let Err(e) = encrypt_file_stream(&key_bytes, &file_path, enc_args.common.remove_file)
            {
                eprintln!("Failed to encrypt {}: {}", file_path, e);
            }
            // Update progress bar
            pb.inc(1);
        });

        // Finish progress bar
        pb.finish_with_message("Encryption complete");
    } else if is_file(&enc_args.common.source) {
        if !enc_args.common.source.ends_with(".enc") {
            encrypt_file_stream(
                &key_bytes,
                &enc_args.common.source,
                enc_args.common.remove_file,
            )?;
        }
    } else {
        eprintln!("Path '{}' is not valid.", enc_args.common.source);
    }

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use aes_gcm::{Aes256Gcm, Key, KeyInit};
//     use std::fs;
//     use tempfile::tempdir;

//     #[test]
//     fn test_is_excluded_dir_matches() {
//         let excludes = vec![".git".to_string(), "target".to_string()];
//         assert!(is_excluded_dir("/home/user/project/.git/config", &excludes));
//     }

//     #[test]
//     fn test_is_excluded_dir_not_matches() {
//         let excludes = vec![".git".to_string()];
//         assert!(!is_excluded_dir(
//             "/home/user/project/src/main.rs",
//             &excludes
//         ));
//     }

//     #[test]
//     fn encrypt_file_creates_enc_file() {
//         let dir = tempdir().unwrap();
//         let file_path = dir.path().join("test.txt");
//         fs::write(&file_path, b"hola mundo").unwrap();

//         let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
//         let cipher = Aes256Gcm::new(key);

//         encrypt_file(&cipher, file_path.to_str().unwrap(), false).unwrap();

//         let enc_path = dir.path().join("test.txt.enc");
//         assert!(enc_path.exists());
//     }

//     #[test]
//     fn encrypt_file_removes_original_if_requested() {
//         let dir = tempdir().unwrap();
//         let file_path = dir.path().join("remove_me.txt");
//         fs::write(&file_path, b"secret").unwrap();

//         let key = Key::<Aes256Gcm>::from_slice(&[1u8; 32]);
//         let cipher = Aes256Gcm::new(key);

//         encrypt_file(&cipher, file_path.to_str().unwrap(), true).unwrap();

//         assert!(!file_path.exists());
//         assert!(dir.path().join("remove_me.txt.enc").exists());
//     }
// }
