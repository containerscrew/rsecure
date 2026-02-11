mod cli;
mod commands;
mod file_ops;

#[macro_use]
mod macros;
mod utils;

use clap::Parser;
use cli::{Commands, RsecureCliArgs};

fn main() -> anyhow::Result<()> {
    let args = RsecureCliArgs::parse();

    match args.command {
        Commands::CreateKey(create_key_args) => commands::create_key::run(create_key_args)?,
        Commands::Encrypt(enc_args) => commands::encrypt_file::run(enc_args)?,
        Commands::Decrypt(enc_args) => commands::decrypt_file::run(enc_args)?,
    }
    Ok(())
}
