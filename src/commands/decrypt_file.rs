use colored::Colorize;
use crate::cli::EncryptionArgs;
use aes_gcm::{Aes256Gcm, Key, aead::Aead, KeyInit, Nonce};
use anyhow::Result;
use walkdir::WalkDir;
use crate::{open_private_key, read_file, write_to_file, remove_file, print_message};
use crate::utils::{is_dir, is_file};

/// Decrypts a single file
fn decrypt_file(
    cipher: &Aes256Gcm,
    source: &str,
) -> Result<()> {
    // Read the encrypted file (contains nonce + ciphertext)
    let file_content = read_file(source)?;

    // Split nonce and ciphertext; nonce is 12 bytes for AES-GCM
    let (nonce_bytes, ciphertext) = file_content.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure!");

    // Determine destination file name
    let destination_file = if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", source)
    };

    // Write decrypted data to destination file
    write_to_file(&destination_file, &[&decrypted_data])?;

    // By the moment, always delete encrypted file after decryption
    remove_file(source)?;
    print_message!("File decrypted and saved as {}", destination_file);

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read AES key from the specified private key file
    let key_bytes = open_private_key(&enc_args.private_key_path)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    if is_dir(&enc_args.source) {
        // Iterate all encrypted files (.enc) in the directory recursively
        for entry in WalkDir::new(&enc_args.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().map_or(false, |ext| ext == "enc")
            })
        {
            let file_path = entry.path().to_string_lossy().to_string();
            decrypt_file(
                &cipher,
                &file_path,
            )?;
        }
    } else if is_file(&enc_args.source) {
        // Decrypt only the source file
        decrypt_file(
            &cipher,
            &enc_args.source,
        )?;
    } else {
        eprintln!("The path '{}' is neither a regular file nor a directory.", enc_args.source);
    }

    Ok(())
}