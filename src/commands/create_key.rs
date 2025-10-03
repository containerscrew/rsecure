use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use crate::cli::{CreateKeyArgs};
use crate::write_to_file;

pub fn run(crt_args: CreateKeyArgs) -> anyhow::Result<()> {
    let key = Aes256Gcm::generate_key(OsRng);

    // Save the key to the specified output file
    write_to_file(&crt_args.output, &[&key.as_slice()])?;

    println!("AES key generated and saved to {}", crt_args.output);
    println!(
        "Please, save this key securely, if you lose it, you won't be able to decrypt your files!"
    );
    Ok(())
}