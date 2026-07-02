use std::{
    fs::File,
    io::{IsTerminal, Read, Write},
};

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

pub fn write_to_file(file_path: &str, contents: &[&[u8]]) -> Result<()> {
    let mut file = File::create(file_path)?;
    for content in contents {
        file.write_all(content)?;
    }
    Ok(())
}

pub fn open_private_key(file_path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = File::open(file_path)?;
    let file_len = file.metadata()?.len();
    let mut key_bytes = vec![0u8; 32];
    file.read_exact(&mut key_bytes)?;
    if file_len > 32 {
        return Err(anyhow!(
            "Key file '{}' is {} bytes — expected exactly 32 bytes (256 bits)",
            file_path,
            file_len
        ));
    }
    Ok(Zeroizing::new(key_bytes))
}

/// Prompt the user for a passphrase without echoing it. If `confirm`, prompts
/// twice and verifies they match. On a TTY this uses `rpassword::prompt_password`
/// (writes the prompt to /dev/tty, reads from /dev/tty with echo disabled);
/// when stdin is piped (tests, shell pipelines), it reads a line from stdin
/// directly — no echo manipulation needed since there's no terminal to echo
/// to anyway.
pub fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let interactive = std::io::stdin().is_terminal();

    let read = |label: &str| -> Result<String> {
        if interactive {
            Ok(rpassword::prompt_password(format!("{label}: "))?)
        } else {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            // Trim only a trailing newline pair; preserve any other whitespace
            // the user might genuinely want in their passphrase.
            if let Some(stripped) = line.strip_suffix('\n') {
                line.truncate(stripped.len());
            }
            if let Some(stripped) = line.strip_suffix('\r') {
                line.truncate(stripped.len());
            }
            Ok(line)
        }
    };

    let p1 = read("Passphrase")?;
    if confirm {
        let p2 = read("Confirm passphrase")?;
        if p1 != p2 {
            return Err(anyhow!("Passphrases do not match"));
        }
    }
    if p1.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty"));
    }
    Ok(Zeroizing::new(p1.into_bytes()))
}
