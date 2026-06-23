use crate::cli::CreateKeyArgs;
use crate::file_ops::write_to_file;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use console::style;

pub fn run(crt_args: CreateKeyArgs) -> anyhow::Result<()> {
    let key = Aes256Gcm::generate_key(OsRng);

    write_to_file(&crt_args.output, &[key.as_slice()])?;

    println!(
        "{} AES key generated and saved to {}",
        style("✓").green().bold(),
        style(&crt_args.output).bold(),
    );
    eprintln!(
        "{}",
        style(
            "⚠  Save this key securely — if you lose it, you won't be able to decrypt your files!"
        )
        .red()
        .bold(),
    );
    Ok(())
}
