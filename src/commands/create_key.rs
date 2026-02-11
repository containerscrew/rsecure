use crate::cli::CreateKeyArgs;
use crate::file_ops::write_to_file;
use crate::print_message;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use colored::Colorize;

pub fn run(crt_args: CreateKeyArgs) -> anyhow::Result<()> {
    let key = Aes256Gcm::generate_key(OsRng);

    // Save the key to the specified output file
    write_to_file(&crt_args.output, &[&key.as_slice()])?;

    print_message!("AES key generated and saved to {}", crt_args.output);
    print_message!(
        "Please, save this key securely, if you lose it, you won't be able to decrypt your files!"
    );
    Ok(())
}
