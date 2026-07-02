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
    Decrypt(DecryptionArgs),
    #[clap(about = "Create a new AES key pair.")]
    CreateKey(CreateKeyArgs),
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct EncryptionArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    #[arg(
        short = 'e',
        long = "exclude-dir",
        help = "Exclude directories to encrypt",
        value_delimiter = ' ',
        num_args = 1..,
        required = false
    )]
    pub exclude_dir: Option<Vec<String>>,

    #[arg(
        long = "passphrase",
        default_value_t = false,
        help = "Use a passphrase (Argon2id) instead of a key file. Prompts on stdin (no echo)."
    )]
    pub passphrase: bool,

    #[arg(
        long = "argon2-memory",
        help = "Argon2id memory cost in KiB (default: 19456 ~ 19 MiB)",
        value_parser = clap::value_parser!(u32).range(8..),
        default_value = "19456"
    )]
    pub argon2_m_cost: u32,

    #[arg(
        long = "argon2-time",
        help = "Argon2id time cost / iterations (default: 2)",
        value_parser = clap::value_parser!(u32).range(1..),
        default_value = "2"
    )]
    pub argon2_t_cost: u32,

    #[arg(
        long = "argon2-parallelism",
        help = "Argon2id parallelism / lanes (default: 1)",
        value_parser = clap::value_parser!(u8).range(1..),
        default_value = "1"
    )]
    pub argon2_p_cost: u8,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct DecryptionArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct CommonArgs {
    #[arg(
        short = 'p',
        long = "private-key-path",
        help = "Path to the AES key file (omit when using --passphrase)"
    )]
    pub private_key_path: Option<String>,

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
        "Author: containerscrew \nLicense: GPL3\nWebsite: github.com/containerscrew/rsecure",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_after_help_message() {
        let expected =
            "Author: containerscrew \nLicense: GPL3\nWebsite: github.com/containerscrew/rsecure";
        assert_eq!(print_after_help_message(), expected);
    }
}
