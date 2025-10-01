use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    about = "Secure file encryption using pure Rust and RSA 🔒",
    version = env!("CARGO_PKG_VERSION"),
    author = "Containerscrew info@containerscrew.com",
    arg_required_else_help = true,
)]
pub struct RsecureCliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[clap(about = "Encrypt a file using your RSA private key.")]
    Encrypt(EncryptionArgs),
    #[clap(about = "Decrypt an encrypted file using your RSA private key.")]
    Decrypt(EncryptionArgs),
}

#[derive(Debug, Args)]
pub struct EncryptionArgs {
    #[arg(
        short = 'r',
        long = "rsa-file-path",
        help = "Path to the RSA private key file"
    )]
    pub rsa_file_path: String,

    #[arg(
        short = 's',
        long = "source-file",
        help = "Path to the source file to encrypt (plain text)"
    )]
    pub source_file: String,
}
