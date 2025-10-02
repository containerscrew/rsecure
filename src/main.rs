use std::env::home_dir;
use std::fs::File;
use std::io::{self, Read};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use clap::{CommandFactory, Parser};
use clap_complete::generate;

mod cli;
mod utils;
use crate::cli::{Commands, RsecureCliArgs};

fn write_to_file(file_path: &str, contents: &[&[u8]]) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(file_path)?;
    for content in contents {
        file.write_all(content)?;
    }
    Ok(())
}

fn open_private_key(file_path: &str) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut key_bytes = vec![0u8; 32]; // AES-256 key size
    file.read_exact(&mut key_bytes)?;
    Ok(key_bytes)
}

fn read_file(file_path: &str) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

fn remove_file(file_path: &str) -> anyhow::Result<()> {
    std::fs::remove_file(file_path)?;
    Ok(())
}

// Encrypts or decrypts a file using AES-256-GCM
fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = RsecureCliArgs::parse();

    match args.command {
        Commands::Completions { shell } => {
            let mut cmd = cli::RsecureCliArgs::command();
            generate(shell, &mut cmd, "rsecure", &mut io::stdout());
        }
        Commands::CreateKey(create_key_args) => {
            let key = Aes256Gcm::generate_key(OsRng);

            // Save the key to the specified output file
            write_to_file(&create_key_args.output, &[&key.as_slice()])?;

            println!("AES key generated and saved to {}", create_key_args.output);
            println!(
                "Please, save this key securely, if you lose it, you won't be able to decrypt your files!"
            );
        }
        Commands::Encrypt(enc_args) => {
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

            let destination_file = &enc_args
                .destination_file
                .unwrap_or_else(|| format!("{}.enc", &enc_args.source_file));

            write_to_file(&destination_file, &[&nonce, &ciphertext])?;

            if enc_args.remove_file {
                remove_file(&enc_args.source_file)?;
                println!("Removed source file {}", enc_args.source_file);
            }

            println!("File encrypted and saved as {}", destination_file);
        }
        Commands::Decrypt(enc_args) => {
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

            if enc_args.remove_file {
                remove_file(&enc_args.source_file)?;
                println!("Removed source file {}", enc_args.source_file);
            }

            println!("File decrypted and saved as {}", destination_file);
        }
    }
    Ok(())
}
