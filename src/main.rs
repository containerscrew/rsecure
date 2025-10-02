use std::fs::File;
use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use clap::Parser;

mod cli;
use crate::cli::{Commands, RsecureCliArgs};

// Encrypts or decrypts a file using AES-256-GCM
fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = RsecureCliArgs::parse();

    match args.command {
        Commands::CreateKey(create_key_args) => {
            let key = Aes256Gcm::generate_key(OsRng);

            // Save the key to the specified output file
            let mut keyfile =
                File::create(&create_key_args.output).expect("Could not create AES key file");

            keyfile
                .write_all(&key.as_slice())
                .expect("Could not write AES key");

            println!("AES key generated and saved to {}", create_key_args.output);
        }
        Commands::Encrypt(enc_args) => {
            // Read the source file to encrypt
            let mut data = File::open(&enc_args.source_file).expect("Could not open source file");
            let mut data_content = Vec::new();
            data.read_to_end(&mut data_content)
                .expect("Could not read source file");

            // Generate a random 256-bit AES key
            let key = Key::<Aes256Gcm>::from_slice(&&data_content.as_slice());
            let cipher = Aes256Gcm::new(key);
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

            // Encrypt data
            let encrypt = cipher
                .encrypt(&nonce, b"plaintext message".as_ref())
                .expect("encryption failure!");

            // Save ciphertext to file
            // let mut out = File::create("encrypted.bin").expect("Could not create output file");
            // out.write_all(&encrypted)
            //     .expect("Could not write encrypted data");

            // // Save key + nonce so we can decrypt later
            // let mut keyfile = File::create("aes_key.bin").expect("Could not create AES key file");
            // keyfile
            //     .write_all(&key_bytes)
            //     .expect("Could not write AES key");
            // keyfile
            //     .write_all(&nonce_bytes)
            //     .expect("Could not write nonce");

            println!("File encrypted and saved as {}", "encrypted.bin");
        }
        Commands::Decrypt(enc_args) => {
            // Read ciphertext
            let mut f = File::open(&enc_args.source_file).expect("Could not open encrypted file");
            let mut encrypted_content = Vec::new();
            f.read_to_end(&mut encrypted_content)
                .expect("Could not read encrypted file");

            // Read key + nonce from file
            let mut keyfile =
                File::open(&enc_args.aes_file_path).expect("Could not open AES key file");
            let mut key_nonce_content = Vec::new();
            keyfile
                .read_to_end(&mut key_nonce_content)
                .expect("Could not read AES key file");

            let (key_bytes, nonce_bytes) = key_nonce_content.split_at(32);
            let key = Key::<Aes256Gcm>::from_slice(key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(nonce_bytes);

            // Decrypt data
            let decrypted = cipher
                .decrypt(nonce, encrypted_content.as_ref())
                .expect("decryption failure!");

            // Save decrypted file
            let mut out = File::create("decrypted.txt").expect("Could not create output file");
            out.write_all(&decrypted)
                .expect("Could not write decrypted data");

            println!("File decrypted and saved as {}", "decrypted.txt");
        }
    }
    Ok(())
}
