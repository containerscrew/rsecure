use std::fs::File;
use std::io::prelude::*;

use rand::thread_rng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey};

fn create_file(file_name: &str) -> File {
    File::create(file_name).expect("Could not create file")
}

// Encrypts selected file and saves to encrypted.txt
fn main() -> rsa::errors::Result<()> {
    // Open the private RSA key file
    let mut rsa_file =
        File::open("/Users/dcr/Keys/rsecure.pem").expect("Could not open RSA key file");
    let mut rsa_content = String::new();
    rsa_file
        .read_to_string(&mut rsa_content)
        .expect("Could not read RSA key file");

    // let mut file = create_file("encrypted.txt");
    let private =
        RsaPrivateKey::from_pkcs8_pem(&rsa_content).expect("Could not parse private key from PEM");
    let public = RsaPublicKey::from(&private);

    let mut rng = thread_rng();

    let data = b"Hola mundo";
    let encrypted = public.encrypt(&mut rng, Pkcs1v15Encrypt, data.as_ref())?;
    println!("Encrypted: {:?}", encrypted);

    let decrypted = private.decrypt(Pkcs1v15Encrypt, &encrypted)?;

    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    Ok(())
}
