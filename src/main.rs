use std::fs::File;
use std::io::{Read, Write};

use clap::Parser;
use rand::thread_rng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey};

mod cli;
use crate::cli::{Commands, RsecureCliArgs};

// Encrypts or decrypts a file using RSA
fn main() -> rsa::errors::Result<()> {
    // Parse command line arguments
    let args = RsecureCliArgs::parse();

    let mut rng = thread_rng();

    match args.command {
        Commands::Encrypt(enc_args) => {
            // Open the private RSA key file and read its content
            let mut rsa_file =
                File::open(&enc_args.rsa_file_path).expect("Could not open RSA key file");
            let mut rsa_content = String::new();
            rsa_file
                .read_to_string(&mut rsa_content)
                .expect("Could not read RSA key file");

            // Parse the private key from PEM format
            let private = RsaPrivateKey::from_pkcs8_pem(&rsa_content)
                .expect("Could not parse private key from PEM");
            let public = RsaPublicKey::from(&private);

            // Read the source file to encrypt
            let mut data = File::open(&enc_args.source_file).expect("Could not open source file");
            let mut data_content = Vec::new();
            data.read_to_end(&mut data_content)
                .expect("Could not read source file");

            let encrypted = public.encrypt(&mut rng, Pkcs1v15Encrypt, &data_content)?;
            let mut out = File::create("encrypted.txt").expect("Could not create output file");
            out.write_all(&encrypted)
                .expect("Could not write encrypted data");
            println!("File encrypted and saved as {}", "encrypted.txt");
        }
        Commands::Decrypt(enc_args) => {
            // Open the private RSA key file and read its content
            let mut rsa_file =
                File::open(&enc_args.rsa_file_path).expect("Could not open RSA key file");
            let mut rsa_content = String::new();
            rsa_file
                .read_to_string(&mut rsa_content)
                .expect("Could not read RSA key file");

            // Parse the private key from PEM format
            let private = RsaPrivateKey::from_pkcs8_pem(&rsa_content)
                .expect("Could not parse private key from PEM");

            // Read the encrypted file
            let mut f = File::open(&enc_args.source_file).expect("Could not open encrypted file");
            let mut encrypted_content = Vec::new();
            f.read_to_end(&mut encrypted_content)
                .expect("Could not read encrypted file");

            let decrypted = private.decrypt(Pkcs1v15Encrypt, &encrypted_content)?;
            let mut out = File::create("decrypted.txt").expect("Could not create output file");
            out.write_all(&decrypted)
                .expect("Could not write decrypted data");
            println!("File decrypted and saved as {}", "decrypted.txt");
        }
    }
    Ok(())
}
