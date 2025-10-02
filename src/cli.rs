use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[clap(
    about = "Secure file encryption using pure Rust and AES 🔒",
    version = env!("CARGO_PKG_VERSION"),
    author = "Containerscrew info@containerscrew.com",
    arg_required_else_help = true,
    after_help = print_after_help_message(),
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
    #[clap(about = "Generate shell completions")]
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Args)]
pub struct EncryptionArgs {
    #[arg(
        short = 'p',
        long = "private-key-path",
        help = "Path to the AES key file"
    )]
    pub private_key_path: String,

    #[arg(
        short = 's',
        long = "source-file",
        help = "Path to the source file to encrypt or decrypt"
    )]
    pub source_file: String,

    #[arg(
        short = 'd',
        long = "destination-file",
        help = "Path to the destination file for the encrypted or decrypted content"
    )]
    pub destination_file: String,
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

fn print_after_help_message() -> String {
    String::from(
        "Author: containerscrew \nLicense: GPL3\nWebsite: github.com/containerscrew/rsecure\nIssues: github.com/containerscrew/rsecure/issues\nUsage: github.com/containerscrew/rsecure/tree/main/README.md",
    )
}
