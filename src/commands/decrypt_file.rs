use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::sync::Mutex;

use crate::cli::EncryptionArgs;
use crate::crypto::{derive_master_key_argon2, derive_subkey_v2, derive_subkey_v3};
use crate::file_ops::{open_private_key, prompt_passphrase};
use crate::format::{
    self, AEAD_TAG_LEN, ARGON2_SALT_LEN, CHUNK_SIZE, Header, STREAM_SALT_LEN,
};
use crate::utils::{is_dir, is_file};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{KeyInit, Payload, stream};
use anyhow::{Result, anyhow};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;

/// What the decrypter has at hand while processing a batch. The keyfile (if
/// any) is loaded once. Passphrase + Argon2 cache live across files so a
/// directory of files encrypted in the same invocation only pays the KDF
/// cost once.
struct DecryptContext {
    keyfile_master_key: Option<Vec<u8>>,
    passphrase: Option<Vec<u8>>,
    // Cache of Argon2 derivations keyed by (params, salt). Re-running Argon2id
    // is expensive (~0.5s by default), so cache across all files in the batch.
    argon2_cache: Mutex<HashMap<Argon2CacheKey, [u8; 32]>>,
}

#[derive(Hash, Eq, PartialEq)]
struct Argon2CacheKey {
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    salt: [u8; ARGON2_SALT_LEN],
}

impl DecryptContext {
    fn resolve_master_key_for(&self, header: &Header) -> Result<MasterKey<'_>> {
        match header {
            Header::V1Legacy { .. } | Header::V2 { .. } | Header::V3Keyfile { .. } => {
                let bytes = self.keyfile_master_key.as_deref().ok_or_else(|| {
                    anyhow!(
                        "This file is encrypted with a key file; pass -p <key file> to decrypt it"
                    )
                })?;
                Ok(MasterKey::Borrowed(bytes))
            }
            Header::V3Passphrase {
                argon2_params,
                argon2_salt,
                ..
            } => {
                let passphrase = self.passphrase.as_deref().ok_or_else(|| {
                    anyhow!(
                        "This file is encrypted with a passphrase; rerun rsecure decrypt without -p"
                    )
                })?;
                let cache_key = Argon2CacheKey {
                    m_cost: argon2_params.m_cost,
                    t_cost: argon2_params.t_cost,
                    p_cost: argon2_params.p_cost,
                    salt: *argon2_salt,
                };
                {
                    let cache = self.argon2_cache.lock().unwrap();
                    if let Some(k) = cache.get(&cache_key) {
                        return Ok(MasterKey::Owned(*k));
                    }
                }
                let derived =
                    derive_master_key_argon2(passphrase, argon2_salt, argon2_params)?;
                {
                    let mut cache = self.argon2_cache.lock().unwrap();
                    cache.insert(cache_key, derived);
                }
                Ok(MasterKey::Owned(derived))
            }
        }
    }
}

enum MasterKey<'a> {
    Borrowed(&'a [u8]),
    Owned([u8; 32]),
}

impl MasterKey<'_> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            MasterKey::Borrowed(b) => b,
            MasterKey::Owned(a) => a,
        }
    }
}

fn decrypt_file_stream(ctx: &DecryptContext, source: &str) -> Result<()> {
    let final_dest = if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", source)
    };
    let tmp_dest = format!("{}.dec.tmp", source);

    match decrypt_to_path(ctx, source, &tmp_dest) {
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

fn decrypt_to_path(ctx: &DecryptContext, source: &str, tmp_dest: &str) -> Result<()> {
    let mut source_file = File::open(source)?;
    let header = format::parse_header(&mut source_file)?;
    let master_key = ctx.resolve_master_key_for(&header)?;

    let cipher = match &header {
        Header::V1Legacy { nonce } => {
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(master_key.as_bytes());
            let cipher = Aes256Gcm::new(key);
            let decryptor = stream::DecryptorBE32::from_aead(cipher, &(*nonce).into());
            let mut dest_file = File::create(tmp_dest)?;
            let mut buffer = vec![0u8; CHUNK_SIZE as usize + AEAD_TAG_LEN];
            return drive_decrypt_loop(&mut source_file, &mut dest_file, decryptor, &mut buffer, &[]);
        }
        Header::V2 { hkdf_salt, .. } => {
            let subkey = derive_subkey_v2(master_key.as_bytes(), hkdf_salt)?;
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
            Aes256Gcm::new(key)
        }
        Header::V3Keyfile { hkdf_salt, .. } | Header::V3Passphrase { hkdf_salt, .. } => {
            let subkey = derive_subkey_v3(master_key.as_bytes(), hkdf_salt)?;
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&subkey);
            Aes256Gcm::new(key)
        }
    };

    let stream_salt = [0u8; STREAM_SALT_LEN];
    let decryptor = stream::DecryptorBE32::from_aead(cipher, &stream_salt.into());

    let chunk_size = header.chunk_size();
    let aad = header.aad();
    let mut buffer = vec![0u8; chunk_size as usize + AEAD_TAG_LEN];
    let mut dest_file = File::create(tmp_dest)?;

    drive_decrypt_loop(&mut source_file, &mut dest_file, decryptor, &mut buffer, aad)
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
                .map_err(|_| anyhow!("Decryption error or file corrupted"))?;
            dest_file.write_all(&plaintext)?;
        } else if read_count > 0 {
            let payload = Payload {
                msg: &buffer[..read_count],
                aad,
            };
            let plaintext = decryptor
                .decrypt_last(payload)
                .map_err(|_| anyhow!("Decryption error on final chunk"))?;
            dest_file.write_all(&plaintext)?;
            break;
        } else {
            break;
        }
    }
    Ok(())
}

/// First-pass probe: peek at one file's header to learn whether the batch
/// needs a passphrase. Lets us prompt exactly once up front instead of
/// surprising the user mid-batch. Returns None if the file is unreadable —
/// the actual decrypt loop will surface the error properly.
fn batch_needs_passphrase(source: &str) -> bool {
    let Ok(mut f) = File::open(source) else {
        return false;
    };
    let mut probe = [0u8; 6];
    if f.read_exact(&mut probe).is_err() {
        return false;
    }
    if &probe[..4] != format::MAGIC {
        return false;
    }
    if probe[4] != format::VERSION_V3 {
        return false;
    }
    probe[5] & format::FLAG_PASSPHRASE != 0
}

pub fn run(enc_args: EncryptionArgs) -> Result<()> {
    // Collect targets first so we can probe before any decrypting.
    let sources: Vec<String> = if is_dir(&enc_args.common.source) {
        WalkDir::new(&enc_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().is_some_and(|ext| ext == "enc")
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .collect()
    } else if is_file(&enc_args.common.source) {
        vec![enc_args.common.source.clone()]
    } else {
        eprintln!(
            "{} Path '{}' is not valid.",
            style("✗").red().bold(),
            style(&enc_args.common.source).bold(),
        );
        return Ok(());
    };

    // Resolve credentials up front based on what the batch actually needs.
    let keyfile_master_key = match &enc_args.common.private_key_path {
        Some(path) => Some(open_private_key(path)?),
        None => None,
    };

    let needs_passphrase = sources.iter().any(|s| batch_needs_passphrase(s));
    let passphrase = if needs_passphrase {
        Some(prompt_passphrase(false)?)
    } else {
        None
    };

    let ctx = DecryptContext {
        keyfile_master_key,
        passphrase,
        argon2_cache: Mutex::new(HashMap::new()),
    };

    if is_dir(&enc_args.common.source) {
        let pb = ProgressBar::new(sources.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        sources.into_par_iter().for_each(|file_path| {
            if let Err(e) = decrypt_file_stream(&ctx, &file_path) {
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
    } else {
        decrypt_file_stream(&ctx, &enc_args.common.source)?;
    }

    Ok(())
}
