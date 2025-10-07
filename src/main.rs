mod cli;
mod commands;
pub mod macros;
mod utils;

use clap::Parser;
use cli::{Commands, RsecureCliArgs};
use colored::Colorize;
use std::fs::File;
use std::io::{Read, Write};

fn write_to_file(file_path: &str, contents: &[&[u8]]) -> anyhow::Result<()> {
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
        Commands::CreateKey(create_key_args) => commands::create_key::run(create_key_args)?,
        Commands::Encrypt(enc_args) => {
            // Tell the user if the original file will be deleted after encryption
            if enc_args.remove_file {
                print_message!("Warning: The original file(s) will be deleted after encryption");
            }
            commands::encrypt_file::run(enc_args)?
        }
        Commands::Decrypt(enc_args) => commands::decrypt_file::run(enc_args)?,
    }
    Ok(())
}
