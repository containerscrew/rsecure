use std::fs::{self, File};
use std::io::{Read, Write};

use crate::cli::EncryptionArgs;
use crate::file_ops::open_private_key;
use crate::utils::{is_dir, is_file};
use aes_gcm::aead::{KeyInit, Payload, stream};
use aes_gcm::Aes256Gcm;
use anyhow::Result;
use console::style;
use hkdf::Hkdf;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::Sha256;
use walkdir::WalkDir;

// See `encrypt_file.rs` for the v2 format. Decrypt also accepts v1 (legacy)
// files produced by rsecure <= 0.5.0: those used AES-256-GCM with a 7-byte
// random nonce derived directly from the master key, no magic header, no
// HKDF, no AAD binding.
const MAGIC: &[u8; 4] = b"RSEC";
const FORMAT_VERSION_V2: u8 = 0x02;
const HKDF_SALT_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"rsecure-v2-aes256gcm-stream";
const LEGACY_NONCE_LEN: usize = 7;
const STREAM_SALT_LEN: usize = 7;
const AEAD_TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 4 + HKDF_SALT_LEN; // 41

// Sanity bound to prevent a malicious header from triggering huge allocations.
// 16 MiB is well above the 128 KiB default and any plausible future tuning.
const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

fn derive_subkey(master_key: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut subkey = [0u8; 32];
    hk.expand(HKDF_INFO, &mut subkey)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(subkey)
}

fn decrypt_file_stream(key_bytes: &[u8], source: &str) -> Result<()> {
    let final_dest = if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", source)
    };
    let tmp_dest = format!("{}.dec.tmp", source);

    // Write into a .tmp sibling and rename only on full success, so a failed
    // auth check or mid-stream crash never produces a half-decrypted plaintext
    // that looks valid to a naive consumer.
    match decrypt_to_path(key_bytes, source, &tmp_dest) {
        Ok(()) => {
            fs::rename(&tmp_dest, &final_dest)?;
            fs::remove_file(source)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_dest);
            Err(e)
        }
    }
}

fn decrypt_to_path(key_bytes: &[u8], source: &str, tmp_dest: &str) -> Result<()> {
    let mut source_file = File::open(source)?;

    let mut magic_buf = [0u8; 4];
    source_file.read_exact(&mut magic_buf)?;

    let mut dest_file = File::create(tmp_dest)?;

    if &magic_buf == MAGIC {
        // v2: full header, AAD-bound chunks
        let mut version = [0u8; 1];
        source_file.read_exact(&mut version)?;
        if version[0] != FORMAT_VERSION_V2 {
            return Err(anyhow::anyhow!(
                "Unsupported rsecure file format version: 0x{:02x}",
                version[0]
            ));
        }

        let mut chunk_size_bytes = [0u8; 4];
        source_file.read_exact(&mut chunk_size_bytes)?;
        let chunk_size = u32::from_le_bytes(chunk_size_bytes);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(anyhow::anyhow!(
                "Refusing to decrypt: header reports chunk_size={} (must be 1..={})",
                chunk_size,
                MAX_CHUNK_SIZE
            ));
        }

        let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
        source_file.read_exact(&mut hkdf_salt)?;

        // Rebuild the on-disk header bytes verbatim for use as AAD.
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&magic_buf);
        header[4] = version[0];
        header[5..9].copy_from_slice(&chunk_size_bytes);
        header[9..41].copy_from_slice(&hkdf_salt);

        let subkey = derive_subkey(key_bytes, &hkdf_salt)?;
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
        let cipher = Aes256Gcm::new(key);

        let stream_salt = [0u8; STREAM_SALT_LEN];
        let decryptor = stream::DecryptorBE32::from_aead(cipher, &stream_salt.into());

        let buffer_size = chunk_size as usize + AEAD_TAG_LEN;
        let mut buffer = vec![0u8; buffer_size];

        drive_decrypt_loop(&mut source_file, &mut dest_file, decryptor, &mut buffer, &header)?;
    } else {
        // v1 legacy: 7-byte STREAM nonce in the header (first 4 bytes already read),
        // ciphertext encrypted directly under the master key, no AAD.
        let mut nonce = [0u8; LEGACY_NONCE_LEN];
        nonce[..4].copy_from_slice(&magic_buf);
        source_file.read_exact(&mut nonce[4..])?;

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

        let buffer_size = 131072 + AEAD_TAG_LEN;
        let mut buffer = vec![0u8; buffer_size];

        drive_decrypt_loop(&mut source_file, &mut dest_file, decryptor, &mut buffer, &[])?;
    }

    Ok(())
}

fn drive_decrypt_loop(
    source_file: &mut File,
    dest_file: &mut File,
    mut decryptor: stream::DecryptorBE32<Aes256Gcm>,
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<()> {
    loop {
        let read_count = source_file.read(buffer)?;
        if read_count == buffer.len() {
            let payload = Payload {
                msg: buffer[..].as_ref(),
                aad,
            };
            let plaintext = decryptor
                .decrypt_next(payload)
                .map_err(|_| anyhow::anyhow!("Decryption error or file corrupted"))?;
            dest_file.write_all(&plaintext)?;
        } else if read_count > 0 {
            let payload = Payload {
                msg: &buffer[..read_count],
                aad,
            };
            let plaintext = decryptor
                .decrypt_last(payload)
                .map_err(|_| anyhow::anyhow!("Decryption error on final chunk"))?;
            dest_file.write_all(&plaintext)?;
            break;
        } else {
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
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().is_some_and(|ext| ext == "enc")
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .collect();

        let pb = ProgressBar::new(files_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        files_to_process.into_par_iter().for_each(|file_path| {
            if let Err(e) = decrypt_file_stream(&key_bytes, &file_path) {
                eprintln!(
                    "{} Failed to decrypt {}: {}",
                    style("✗").red().bold(),
                    style(&file_path).bold(),
                    e,
                );
            }
            pb.inc(1);
        });

        pb.finish_with_message("Decryption complete");
    } else if is_file(&enc_args.common.source) {
        decrypt_file_stream(&key_bytes, &enc_args.common.source)?;
    } else {
        eprintln!(
            "{} Path '{}' is not valid.",
            style("✗").red().bold(),
            style(&enc_args.common.source).bold(),
        );
    }

    Ok(())
}
