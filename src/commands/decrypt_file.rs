use crate::cli::{EncryptionArgs};
use aes_gcm::{Aes256Gcm, Key, aead::{Aead}, KeyInit, Nonce};
use anyhow::Result;

use crate::{open_private_key, read_file, write_to_file, remove_file};

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read the AES key from file
    let key_bytes = open_private_key(&enc_args.private_key_path)?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Read the encrypted file (nonce + ciphertext)
    let file_content = read_file(&enc_args.source_file)?;

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // Nonce is 12 bytes for AES-GCM
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure!");

    let destination_file = &enc_args.destination_file.unwrap_or_else(|| {
        if enc_args.source_file.ends_with(".enc") {
            enc_args.source_file.trim_end_matches(".enc").to_string()
        } else {
            format!("{}.dec", &enc_args.source_file)
        }
    });

    // Save decrypted file
    write_to_file(destination_file, &[&decrypted_data])?;

    // Always remove the source encrypted file after decryption
    remove_file(&enc_args.source_file)?;
    println!("Removed source file {}", enc_args.source_file);
    println!("File decrypted and saved as {}", destination_file);

    Ok(())
}