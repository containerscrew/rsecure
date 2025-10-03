use clap::{Args, Parser, Subcommand};

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
    #[clap(about = "Encrypt a file in plain text  using your AES key.")]
    Encrypt(EncryptionArgs),
    #[clap(about = "Decrypt an encrypted file using your AES private key.")]
    Decrypt(EncryptionArgs),
    #[clap(about = "Create a new AES key pair.")]
    CreateKey(CreateKeyArgs),
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct EncryptionArgs {
    #[arg(
        short = 'p',
        long = "private-key-path",
        help = "Path to the AES key file"
    )]
    pub private_key_path: String,

    #[arg(
        short = 's',
        long = "source",
        help = "Path to the source file or folder with files to encrypt or decrypt"
    )]
    pub source: String,
    
    #[arg(
        short = 'r',
        long = "remove-file",
        default_value_t = false,
        required = false,
        help = "Path to the file to remove after encryption or decryption"
    )]
    pub remove_file: bool,
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
