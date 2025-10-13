use crate::cli::EncryptionArgs;
use crate::utils::{is_dir, is_file};
use crate::{open_private_key, print_message, read_file, remove_file, write_to_file};
use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, AeadCore, OsRng},
};
use anyhow::Result;
use colored::Colorize;
use walkdir::WalkDir;

// Check if a directory should be excluded
fn is_excluded_dir(entry: &walkdir::DirEntry, exclude_dirs: &[String]) -> bool {
    let path = entry.path(); // Get the full path of the directory
    exclude_dirs
        .iter()
        .any(|exclude| path.to_string_lossy().contains(exclude))
}

/// Encrypts a single file.
fn encrypt_file(cipher: &Aes256Gcm, source: &str, should_remove_file: bool) -> Result<()> {
    // Read plaintext from source file
    let plaintext = read_file(source)?;

    // Generate a random nonce for this encryption
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("encryption failure!");

    // Determine destination filename
    let destination_file = format!("{}.enc", source);

    // Write nonce and ciphertext to destination file
    write_to_file(&destination_file, &[&nonce, &ciphertext])?;

    // Optionally remove the original file
    if should_remove_file {
        remove_file(source)?;
    }

    print_message!("File encrypted and saved as {}", destination_file);
    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read AES key from file
    let key_bytes = open_private_key(&enc_args.common.private_key_path)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // && !is_excluded_dir(&enc_args.common.source, &enc_args.exclude_dir)

    if is_dir(&enc_args.common.source) {
        // Iterate all files in the directory recursively
        for entry in WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            let file_path = entry.path().to_string_lossy().to_string();

            // If the file is already encrypted, skip it
            if file_path.ends_with(".enc") {
                continue;
            }

            // Encrypt each file with a new nonce
            encrypt_file(&cipher, &file_path, enc_args.common.remove_file)?;
        }
    } else if is_file(&enc_args.common.source) {
        // If the file is already encrypted, skip it
        if enc_args.common.source.ends_with(".enc") {
            return Ok(());
        }

        // Encrypt only the source file
        encrypt_file(
            &cipher,
            &enc_args.common.source,
            enc_args.common.remove_file,
        )?;
    } else {
        eprintln!(
            "The path '{}' is neither a regular file nor a directory.",
            enc_args.common.source
        );
    }

    Ok(())
}
