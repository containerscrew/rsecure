use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path};

use crate::cli::EncryptionArgs;
use crate::file_ops::open_private_key;
use crate::utils::{is_dir, is_file};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{KeyInit, OsRng, Payload, stream};
use aes_gcm::Aes256Gcm;
use anyhow::Result;
use console::style;
use hkdf::Hkdf;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::Sha256;
use walkdir::WalkDir;

// File format v2:
//   [magic "RSEC" 4B][version 1B][chunk_size_le u32 4B][hkdf_salt 32B]
//   [AES-256-GCM STREAM ciphertext (each chunk authenticated with the header as AAD)]
//
// For each file we derive an AES-256 subkey via HKDF-SHA256(ikm=master_key,
// salt=random 32 B, info=HKDF_INFO). Because the subkey is unique per file, the
// STREAM nonce stays fixed (all zeros). The entire header is passed as AAD to
// every chunk, so any tampering with the header bytes — version, chunk_size,
// salt — invalidates the very first GCM tag and decryption fails immediately.
const MAGIC: &[u8; 4] = b"RSEC";
const FORMAT_VERSION_V2: u8 = 0x02;
const HKDF_SALT_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"rsecure-v2-aes256gcm-stream";
const STREAM_SALT_LEN: usize = 7;
const CHUNK_SIZE: u32 = 131072;
const HEADER_LEN: usize = 4 + 1 + 4 + HKDF_SALT_LEN; // 41

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

fn derive_subkey(master_key: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut subkey = [0u8; 32];
    hk.expand(HKDF_INFO, &mut subkey)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(subkey)
}

fn build_header(version: u8, chunk_size: u32, hkdf_salt: &[u8; HKDF_SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = version;
    header[5..9].copy_from_slice(&chunk_size.to_le_bytes());
    header[9..41].copy_from_slice(hkdf_salt);
    header
}

fn encrypt_file_stream(key_bytes: &[u8], source: &str, should_remove: bool) -> Result<()> {
    let final_dest = format!("{}.enc", source);
    let tmp_dest = format!("{}.enc.tmp", source);

    // Write into a .tmp sibling so a mid-write crash never leaves a half-baked
    // .enc file alongside its plaintext. fs::rename is atomic within the same
    // filesystem; either the consumer sees the old absence or the fully-written
    // ciphertext, never an in-between truncated file.
    let result = encrypt_to_path(key_bytes, source, &tmp_dest);
    match result {
        Ok(()) => {
            fs::rename(&tmp_dest, &final_dest)?;
            if should_remove {
                fs::remove_file(source)?;
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_dest); // best-effort
            Err(e)
        }
    }
}

fn encrypt_to_path(key_bytes: &[u8], source: &str, tmp_dest: &str) -> Result<()> {
    let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
    OsRng.fill_bytes(&mut hkdf_salt);

    let subkey = derive_subkey(key_bytes, &hkdf_salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
    let cipher = Aes256Gcm::new(key);

    let stream_salt = [0u8; STREAM_SALT_LEN];
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, &stream_salt.into());

    let header = build_header(FORMAT_VERSION_V2, CHUNK_SIZE, &hkdf_salt);

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
                .map_err(|_| anyhow::anyhow!("Encryption error on chunk"))?;
            dest_file.write_all(&ciphertext)?;
        } else {
            let payload = Payload {
                msg: &buffer[..read_count],
                aad: &header,
            };
            let ciphertext = encryptor
                .encrypt_last(payload)
                .map_err(|_| anyhow::anyhow!("Encryption error on final chunk"))?;
            dest_file.write_all(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    let key_bytes = open_private_key(&enc_args.common.private_key_path)?;

    if is_dir(&enc_args.common.source) {
        let files_to_process: Vec<_> = WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| {
                !is_excluded(e.path(), enc_args.exclude_dir.as_deref().unwrap_or(&[]))
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .filter(|path| !path.ends_with(".enc"))
            .collect();

        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        files_to_process.into_par_iter().for_each(|file_path| {
            if let Err(e) = encrypt_file_stream(&key_bytes, &file_path, enc_args.common.remove_file)
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
                &key_bytes,
                &enc_args.common.source,
                enc_args.common.remove_file,
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
