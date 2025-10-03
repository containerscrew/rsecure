use crate::cli::{EncryptionArgs};
use aes_gcm::{Aes256Gcm, Key, aead::{Aead, OsRng, AeadCore}, KeyInit};
use anyhow::Result;

use crate::{open_private_key, read_file, write_to_file, remove_file};

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Read the AES key from file
    let key_bytes = open_private_key(&enc_args.private_key_path)?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Read source file (plaintext)
    let plaintext = read_file(&enc_args.source_file)?;

    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // Encrypt the plaintext data
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("encryption failure!");

    let destination_file = enc_args
        .destination_file
        .clone()
        .unwrap_or_else(|| format!("{}.enc", &enc_args.source_file));

    write_to_file(&destination_file, &[&nonce, &ciphertext])?;

    if enc_args.remove_file {
        remove_file(&enc_args.source_file)?;
        println!("Removed source file {}", enc_args.source_file);
    }

    println!("File encrypted and saved as {}", destination_file);

    Ok(())
}