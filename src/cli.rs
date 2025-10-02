use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    about = "Secure file encryption using pure Rust and AES 🔒",
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
    #[clap(about = "Encrypt a file using your AES key.")]
    Encrypt(EncryptionArgs),
    #[clap(about = "Decrypt an encrypted file using your AES private key.")]
    Decrypt(EncryptionArgs),
    #[clap(about = "Create a new AES key pair.")]
    CreateKey(CreateKeyArgs),
}

#[derive(Debug, Args)]
pub struct EncryptionArgs {
    #[arg(short = 'r', long = "aes-file-path", help = "Path to the AES key file")]
    pub aes_file_path: String,

    #[arg(
        short = 's',
        long = "source-file",
        help = "Path to the source file to encrypt (plain text)"
    )]
    pub source_file: String,
}

#[derive(Debug, Args)]
pub struct CreateKeyArgs {
    #[arg(
        short = 'o',
        long = "output",
        help = "Output path for the generated AES key"
    )]
    pub output: String,
}
