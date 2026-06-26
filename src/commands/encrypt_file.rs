use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path};

use crate::cli::EncryptionArgs;
use crate::crypto::{derive_master_key_argon2, derive_subkey_v3};
use crate::file_ops::{open_private_key, prompt_passphrase};
use crate::format::{
    self, ARGON2_SALT_LEN, Argon2Params, CHUNK_SIZE, HKDF_SALT_LEN, STREAM_SALT_LEN,
};
use crate::utils::{is_dir, is_file};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{KeyInit, OsRng, Payload, stream};
use anyhow::{Result, anyhow};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;

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
struct EncryptContext<'a> {
    master_key: &'a [u8],
    /// `Some` for passphrase mode: every file embeds these Argon2 params and
    /// salt in its header so decrypt can re-derive without prompting again.
    passphrase_meta: Option<(Argon2Params, [u8; ARGON2_SALT_LEN])>,
}

fn encrypt_file_stream(ctx: &EncryptContext, source: &str, should_remove: bool) -> Result<()> {
    let final_dest = format!("{}.enc", source);
    let tmp_dest = format!("{}.enc.tmp", source);

    match encrypt_to_path(ctx, source, &tmp_dest) {
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

fn encrypt_to_path(ctx: &EncryptContext, source: &str, tmp_dest: &str) -> Result<()> {
    let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
    OsRng.fill_bytes(&mut hkdf_salt);

    let subkey = derive_subkey_v3(ctx.master_key, &hkdf_salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
    let cipher = Aes256Gcm::new(key);

    let stream_salt = [0u8; STREAM_SALT_LEN];
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &stream_salt.into());

    let header: Vec<u8> = match ctx.passphrase_meta {
        None => format::build_v3_keyfile_header(CHUNK_SIZE, &hkdf_salt).to_vec(),
        Some((params, salt)) => {
            format::build_v3_passphrase_header(CHUNK_SIZE, &hkdf_salt, &params, &salt).to_vec()
        }
    };

    let mut source_file = File::open(source)?;
    let mut dest_file = File::create(tmp_dest)?;
    dest_file.write_all(&header)?;

    let mut buffer = vec![0u8; CHUNK_SIZE as usize];

    loop {
        let read_count = source_file.read(&mut buffer)?;

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

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // CLI guardrails: exactly one of {-p, --passphrase} on encrypt.
    let key_path = enc_args.common.private_key_path.clone();
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
    let (master_key, passphrase_meta) = if use_passphrase {
        let passphrase = prompt_passphrase(true)?;
        let params = Argon2Params::defaults();
        let mut argon2_salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut argon2_salt);
        let mk = derive_master_key_argon2(&passphrase, &argon2_salt, &params)?;
        (mk.to_vec(), Some((params, argon2_salt)))
    } else {
        let bytes = open_private_key(key_path.as_deref().expect("checked above"))?;
        (bytes, None)
    };

    let ctx = EncryptContext {
        master_key: &master_key,
        passphrase_meta,
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
            if let Err(e) = encrypt_file_stream(&ctx, &file_path, enc_args.common.remove_file) {
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
            encrypt_file_stream(&ctx, &enc_args.common.source, enc_args.common.remove_file)?;
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
