use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};

use crate::cli::EncryptionArgs;
use crate::crypto::{derive_master_key_argon2, derive_subkey_v3};
use crate::file_ops::{open_private_key, prompt_passphrase};
use crate::format::{
    self, ARGON2_SALT_LEN, Argon2Params, CHUNK_SIZE, HKDF_SALT_LEN, MAX_ENCRYPTED_NAME_LEN,
    NAME_LEN_PREFIX, STREAM_SALT_LEN,
};
use crate::utils::{fill_buffer, is_dir, is_file};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{KeyInit, OsRng, Payload, stream};
use anyhow::{Result, anyhow};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;
use zeroize::Zeroizing;

// Returns true if any path component matches an entry of `exclude_list`.
// Trailing path separators on the patterns are stripped, so `-e .git` and
// `-e .git/` behave the same. Component-based matching prevents the obvious
// substring trap, e.g. `-e .git` no longer matches `forgit.txt` or `.github/`.
fn is_excluded(path: &Path, exclude_list: &[String]) -> bool {
    if exclude_list.is_empty() {
        return false;
    }
    path.components().any(|c| match c {
        Component::Normal(name) => name.to_str().is_some_and(|name| {
            exclude_list
                .iter()
                .any(|ex| name == ex.trim_end_matches('/').trim_end_matches('\\'))
        }),
        _ => false,
    })
}

/// What the encrypter needs in order to write a single file's header and
/// derive its subkey. The master key was either read from a keyfile or
/// derived once via Argon2id from the passphrase entered at invocation time.
/// The master key is held in a `Zeroizing` wrapper so its memory is scrubbed
/// when the context is dropped.
struct EncryptContext {
    master_key: Zeroizing<Vec<u8>>,
    /// `Some` for passphrase mode: every file embeds these Argon2 params and
    /// salt in its header so decrypt can re-derive without prompting again.
    passphrase_meta: Option<(Argon2Params, [u8; ARGON2_SALT_LEN])>,
    /// When true, the original filename is embedded in the encrypted stream and
    /// the `.enc` is written under an opaque random name (see `opaque_enc_path`).
    hide_name: bool,
}

/// Build an opaque `<32 hex>.enc` path in the same directory as `source`, so a
/// hidden-name ciphertext leaks nothing about the original filename through its
/// own name.
fn opaque_enc_path(source: &str) -> String {
    let mut rand = [0u8; 16];
    OsRng.fill_bytes(&mut rand);
    let hex: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    let name = format!("{hex}.enc");
    match Path::new(source).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(name).to_string_lossy().into_owned()
        }
        _ => name,
    }
}

fn encrypt_file_stream(
    ctx: &EncryptContext,
    source: &str,
    should_remove: bool,
    show_progress: bool,
) -> Result<()> {
    let final_dest = if ctx.hide_name {
        opaque_enc_path(source)
    } else {
        format!("{source}.enc")
    };
    let tmp_dest = format!("{final_dest}.tmp");

    match encrypt_to_path(ctx, source, &tmp_dest, show_progress) {
        Ok(()) => {
            fs::rename(&tmp_dest, &final_dest)?;
            if should_remove {
                fs::remove_file(source)?;
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_dest);
            Err(e)
        }
    }
}

fn encrypt_to_path(
    ctx: &EncryptContext,
    source: &str,
    tmp_dest: &str,
    show_progress: bool,
) -> Result<()> {
    let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
    OsRng.fill_bytes(&mut hkdf_salt);

    let subkey = derive_subkey_v3(&ctx.master_key, &hkdf_salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
    let cipher = Aes256Gcm::new(key);

    let stream_salt = [0u8; STREAM_SALT_LEN];
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &stream_salt.into());

    // When hiding the name, prepend `[u32 LE name_len][name]` to the plaintext
    // stream so the filename is encrypted and authenticated alongside the file
    // contents, and flag the header so decrypt knows to peel it back off.
    let (extra_flags, name_prefix) = if ctx.hide_name {
        let name = Path::new(source)
            .file_name()
            .ok_or_else(|| anyhow!("Cannot hide name: '{source}' has no final path component"))?
            .to_string_lossy();
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_ENCRYPTED_NAME_LEN {
            return Err(anyhow!(
                "Filename length {} is out of range (1..={})",
                name_bytes.len(),
                MAX_ENCRYPTED_NAME_LEN
            ));
        }
        let mut prefix = Vec::with_capacity(NAME_LEN_PREFIX + name_bytes.len());
        prefix.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        prefix.extend_from_slice(name_bytes);
        (format::FLAG_ENCRYPTED_NAME, prefix)
    } else {
        (0u8, Vec::new())
    };

    let header: Vec<u8> = match ctx.passphrase_meta {
        None => format::build_v3_keyfile_header(CHUNK_SIZE, &hkdf_salt, extra_flags).to_vec(),
        Some((params, salt)) => {
            format::build_v3_passphrase_header(CHUNK_SIZE, &hkdf_salt, &params, &salt, extra_flags)
                .to_vec()
        }
    };

    let source_file = File::open(source)?;
    let file_size = source_file.metadata()?.len();
    let total_plaintext = file_size + name_prefix.len() as u64;
    // Read the name prefix first, then the file contents, as one logical stream.
    let mut reader = Cursor::new(name_prefix).chain(source_file);
    let mut dest_file = File::create(tmp_dest)?;
    dest_file.write_all(&header)?;

    let pb = if show_progress {
        let pb = ProgressBar::new(total_plaintext);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"));
        Some(pb)
    } else {
        None
    };

    let mut buffer = vec![0u8; CHUNK_SIZE as usize];

    loop {
        let read_count = fill_buffer(&mut reader, &mut buffer)?;
        if let Some(ref pb) = pb {
            pb.inc(read_count as u64);
        }

        if read_count == buffer.len() {
            let payload = Payload {
                msg: buffer[..].as_ref(),
                aad: &header,
            };
            let ciphertext = encryptor
                .encrypt_next(payload)
                .map_err(|_| anyhow!("Encryption error on chunk"))?;
            dest_file.write_all(&ciphertext)?;
        } else {
            let payload = Payload {
                msg: &buffer[..read_count],
                aad: &header,
            };
            let ciphertext = encryptor
                .encrypt_last(payload)
                .map_err(|_| anyhow!("Encryption error on final chunk"))?;
            dest_file.write_all(&ciphertext)?;
            break;
        }
    }

    if let Some(pb) = pb {
        pb.finish_with_message("Encrypted");
    }

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // CLI guardrails: exactly one of {-p, --passphrase} on encrypt.
    let key_path = enc_args.common.key_path.clone();
    let use_passphrase = enc_args.passphrase;
    match (&key_path, use_passphrase) {
        (Some(_), true) => {
            return Err(anyhow!(
                "Pass either -p <key file> or --passphrase, not both"
            ));
        }
        (None, false) => {
            return Err(anyhow!(
                "Encrypt needs either -p <key file> or --passphrase"
            ));
        }
        _ => {}
    }

    // Resolve master key once.
    let master_key: Zeroizing<Vec<u8>>;
    let passphrase_meta;

    if use_passphrase {
        let passphrase = prompt_passphrase(true)?;
        let params = Argon2Params {
            m_cost: enc_args.argon2_m_cost,
            t_cost: enc_args.argon2_t_cost,
            p_cost: enc_args.argon2_p_cost,
        };
        let mut argon2_salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut argon2_salt);
        let mk = derive_master_key_argon2(&passphrase, &argon2_salt, &params)?;
        master_key = Zeroizing::new(mk.to_vec());
        passphrase_meta = Some((params, argon2_salt));
    } else {
        master_key = open_private_key(key_path.as_deref().expect("checked above"))?;
        passphrase_meta = None;
    }

    if enc_args.hide_name && !enc_args.common.remove_file {
        eprintln!(
            "{} --hide-name was set but -r/--remove-file was not: the original file (and its name) will remain on disk next to the opaque .enc. Add -r to remove it.",
            style("!").yellow().bold(),
        );
    }

    let ctx = EncryptContext {
        master_key,
        passphrase_meta,
        hide_name: enc_args.hide_name,
    };

    if is_dir(&enc_args.common.source) {
        let files_to_process: Vec<_> = WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| !is_excluded(e.path(), enc_args.exclude_dir.as_deref().unwrap_or(&[])))
            .map(|e| e.path().to_string_lossy().to_string())
            .filter(|path| !path.ends_with(".enc"))
            .collect();

        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        files_to_process.into_par_iter().for_each(|file_path| {
            if let Err(e) =
                encrypt_file_stream(&ctx, &file_path, enc_args.common.remove_file, false)
            {
                eprintln!(
                    "{} Failed to encrypt {}: {}",
                    style("✗").red().bold(),
                    style(&file_path).bold(),
                    e,
                );
            }
            pb.inc(1);
        });

        pb.finish_with_message("Encryption complete");
    } else if is_file(&enc_args.common.source) {
        if enc_args.common.source.ends_with(".enc") {
            eprintln!(
                "{} '{}' already has a .enc extension; refusing to re-encrypt.",
                style("!").yellow().bold(),
                style(&enc_args.common.source).bold(),
            );
        } else {
            encrypt_file_stream(
                &ctx,
                &enc_args.common.source,
                enc_args.common.remove_file,
                true,
            )?;
        }
    } else {
        eprintln!(
            "{} Path '{}' is not valid.",
            style("✗").red().bold(),
            style(&enc_args.common.source).bold(),
        );
    }

    Ok(())
}
