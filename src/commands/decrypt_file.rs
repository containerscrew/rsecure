use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::cli::DecryptionArgs;
use crate::crypto::{derive_master_key_argon2, derive_subkey_v2, derive_subkey_v3};
use crate::file_ops::{open_private_key, prompt_passphrase};
use crate::format::{
    self, AEAD_TAG_LEN, ARGON2_SALT_LEN, CHUNK_SIZE, Header, MAX_ENCRYPTED_NAME_LEN,
    NAME_LEN_PREFIX, STREAM_SALT_LEN,
};
use crate::utils::{fill_buffer, is_dir, is_file};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{KeyInit, Payload, stream};
use anyhow::{Result, anyhow};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

/// What the decrypter has at hand while processing a batch. The keyfile (if
/// any) is loaded once. Passphrase + Argon2 cache live across files so a
/// directory of files encrypted in the same invocation only pays the KDF
/// cost once.
struct DecryptContext {
    keyfile_master_key: Option<Zeroizing<Vec<u8>>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
    // Cache of Argon2 derivations keyed by (params, salt). Re-running Argon2id
    // is expensive (~0.5s by default), so cache across all files in the batch.
    argon2_cache: Mutex<HashMap<Argon2CacheKey, [u8; 32]>>,
}

impl Drop for DecryptContext {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.argon2_cache.lock() {
            for (_, v) in cache.iter_mut() {
                v.zeroize();
            }
        }
    }
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
                let derived = derive_master_key_argon2(passphrase, argon2_salt, argon2_params)?;
                {
                    let mut cache = self.argon2_cache.lock().unwrap();
                    cache.insert(cache_key, *derived);
                }
                Ok(MasterKey::Owned(*derived))
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

/// Destination path for a decrypt when the ciphertext does not carry an
/// embedded filename: strip `.enc`, or append `.dec` if it was renamed away.
fn default_decrypt_dest(source: &str) -> String {
    if source.ends_with(".enc") {
        source.trim_end_matches(".enc").to_string()
    } else {
        format!("{source}.dec")
    }
}

/// Place a recovered embedded filename in the same directory as the `.enc` it
/// came from. The name was validated (no separators, not `.`/`..`) in
/// `decrypt_to_path`, so it can only land inside that directory.
fn recovered_dest(source: &str, name: &str) -> String {
    match Path::new(source).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(name).to_string_lossy().into_owned()
        }
        _ => name.to_string(),
    }
}

fn decrypt_file_stream(
    ctx: &DecryptContext,
    source: &str,
    should_remove: bool,
    show_progress: bool,
) -> Result<()> {
    let tmp_dest = format!("{source}.dec.tmp");

    match decrypt_to_path(ctx, source, &tmp_dest, show_progress) {
        Ok(recovered_name) => {
            let final_dest = match recovered_name {
                Some(name) => recovered_dest(source, &name),
                None => default_decrypt_dest(source),
            };
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

/// Decrypt `source` into `tmp_dest`. Returns the recovered original filename
/// when the ciphertext carried one (v3 `FLAG_ENCRYPTED_NAME`), else `None`.
fn decrypt_to_path(
    ctx: &DecryptContext,
    source: &str,
    tmp_dest: &str,
    show_progress: bool,
) -> Result<Option<String>> {
    let mut source_file = File::open(source)?;
    let header = format::parse_header(&mut source_file)?;
    let master_key = ctx.resolve_master_key_for(&header)?;

    let file_size = source_file.metadata()?.len();
    let header_offset = source_file.stream_position()?;

    let cipher = match &header {
        Header::V1Legacy { nonce } => {
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(master_key.as_bytes());
            let cipher = Aes256Gcm::new(key);
            let decryptor = stream::DecryptorBE32::from_aead(cipher, &(*nonce).into());
            let mut dest_file = File::create(tmp_dest)?;
            let mut buffer = vec![0u8; CHUNK_SIZE as usize + AEAD_TAG_LEN];
            let pb = build_decrypt_progress(file_size, header_offset, show_progress);
            // v1 never carries an embedded name.
            return drive_decrypt_loop(
                &mut source_file,
                &mut dest_file,
                decryptor,
                &mut buffer,
                &[],
                pb,
            )
            .map(|()| None);
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
    let pb = build_decrypt_progress(file_size, header_offset, show_progress);

    if header.has_encrypted_name() {
        // The plaintext starts with `[u32 LE name_len][name]`; strip it back
        // off through the writer adaptor and recover the original filename.
        let mut writer = NameStrippingWriter::new(File::create(tmp_dest)?);
        drive_decrypt_loop(
            &mut source_file,
            &mut writer,
            decryptor,
            &mut buffer,
            aad,
            pb,
        )?;
        let name_bytes = writer.into_name().ok_or_else(|| {
            anyhow!("Decryption error: ciphertext ended before the embedded filename was complete")
        })?;
        let name = String::from_utf8(name_bytes)
            .map_err(|_| anyhow!("Embedded filename is not valid UTF-8"))?;
        validate_embedded_name(&name)?;
        Ok(Some(name))
    } else {
        let mut dest_file = File::create(tmp_dest)?;
        drive_decrypt_loop(
            &mut source_file,
            &mut dest_file,
            decryptor,
            &mut buffer,
            aad,
            pb,
        )?;
        Ok(None)
    }
}

/// Reject an embedded filename that could escape the target directory. The name
/// must be a bare filename: non-empty, not `.`/`..`, and free of path
/// separators. A well-formed rsecure file only ever stores a basename, so this
/// only fires on a maliciously crafted or corrupted ciphertext.
fn validate_embedded_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(anyhow!(
            "Refusing to use unsafe embedded filename: {name:?}"
        ));
    }
    Ok(())
}

fn build_decrypt_progress(
    file_size: u64,
    header_offset: u64,
    show_progress: bool,
) -> Option<ProgressBar> {
    if !show_progress {
        return None;
    }
    let pb = ProgressBar::new(file_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));
    pb.inc(header_offset);
    Some(pb)
}

/// A `Write` adaptor that peels the `[u32 LE name_len][name]` prefix off the
/// front of the decrypted plaintext stream (v3 `FLAG_ENCRYPTED_NAME`) and
/// forwards the remaining file contents to `inner`, capturing the recovered
/// filename. The prefix is small and always lands inside the first plaintext
/// chunk, but the adaptor tolerates the name being split across `write` calls.
struct NameStrippingWriter<W: Write> {
    inner: W,
    phase: NamePhase,
    name: Option<Vec<u8>>,
}

enum NamePhase {
    /// Still collecting the 4-byte little-endian length prefix.
    Len(Vec<u8>),
    /// Collecting `need` filename bytes.
    Name { need: usize, buf: Vec<u8> },
    /// Prefix fully consumed; everything after is file content.
    Done,
}

impl<W: Write> NameStrippingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            phase: NamePhase::Len(Vec::with_capacity(NAME_LEN_PREFIX)),
            name: None,
        }
    }

    /// The recovered filename bytes, or `None` if the stream ended before the
    /// declared name was fully read (a truncated or malformed ciphertext).
    fn into_name(self) -> Option<Vec<u8>> {
        match self.phase {
            NamePhase::Done => self.name,
            _ => None,
        }
    }
}

impl<W: Write> Write for NameStrippingWriter<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let total = data.len();
        let mut rest = data;
        loop {
            match &mut self.phase {
                NamePhase::Len(buf) => {
                    while buf.len() < NAME_LEN_PREFIX && !rest.is_empty() {
                        buf.push(rest[0]);
                        rest = &rest[1..];
                    }
                    if buf.len() < NAME_LEN_PREFIX {
                        return Ok(total);
                    }
                    let len =
                        u32::from_le_bytes(buf[..NAME_LEN_PREFIX].try_into().unwrap()) as usize;
                    if len == 0 || len > MAX_ENCRYPTED_NAME_LEN {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "embedded filename length out of range",
                        ));
                    }
                    self.phase = NamePhase::Name {
                        need: len,
                        buf: Vec::with_capacity(len),
                    };
                }
                NamePhase::Name { need, buf } => {
                    let take = (*need - buf.len()).min(rest.len());
                    buf.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    if buf.len() < *need {
                        return Ok(total);
                    }
                    self.name = Some(std::mem::take(buf));
                    self.phase = NamePhase::Done;
                }
                NamePhase::Done => {
                    if !rest.is_empty() {
                        self.inner.write_all(rest)?;
                    }
                    return Ok(total);
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn drive_decrypt_loop<W: Write>(
    source_file: &mut File,
    dest_file: &mut W,
    mut decryptor: stream::DecryptorBE32<Aes256Gcm>,
    buffer: &mut [u8],
    aad: &[u8],
    pb: Option<ProgressBar>,
) -> Result<()> {
    loop {
        let read_count = fill_buffer(source_file, buffer)?;
        if let Some(ref pb) = pb {
            pb.inc(read_count as u64);
        }
        if read_count == buffer.len() {
            // A full buffer is always an intermediate `encrypt_next` chunk: the
            // encrypter never seals a full-size chunk with `encrypt_last`, and
            // it always emits a trailing `encrypt_last` segment (a partial
            // chunk, or a bare 16-byte tag when the plaintext is a whole number
            // of chunks). So more ciphertext must follow.
            let payload = Payload {
                msg: buffer[..].as_ref(),
                aad,
            };
            let plaintext = decryptor
                .decrypt_next(payload)
                .map_err(|_| anyhow!("Decryption error or file corrupted"))?;
            dest_file.write_all(&plaintext)?;
        } else if read_count >= AEAD_TAG_LEN {
            // A partial buffer means genuine EOF (fill_buffer drained short
            // reads), so this is the terminal segment sealed with
            // `encrypt_last`. Requiring every stream to end here is what makes
            // truncation detectable: a file cut at a chunk boundary ends right
            // after a `decrypt_next` and falls into the `else` branch below.
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
            // Fewer bytes remain than a GCM tag (including zero): the
            // `encrypt_last` segment that every well-formed file ends with is
            // missing, i.e. the ciphertext was truncated.
            return Err(anyhow!(
                "Decryption error: ciphertext is truncated (missing final chunk)"
            ));
        }
    }
    if let Some(pb) = pb {
        pb.finish_with_message("Decrypted");
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

pub fn run(dec_args: DecryptionArgs) -> Result<()> {
    let keyfile_master_key = match &dec_args.common.key_path {
        Some(path) => Some(open_private_key(path)?),
        None => None,
    };

    if is_dir(&dec_args.common.source) {
        let sources: Vec<String> = WalkDir::new(&dec_args.common.source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                path.is_file() && path.extension().is_some_and(|ext| ext == "enc")
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .collect();

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

        let pb = ProgressBar::new(sources.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        let should_remove = dec_args.common.remove_file;
        sources.into_par_iter().for_each(|file_path| {
            if let Err(e) = decrypt_file_stream(&ctx, &file_path, should_remove, false) {
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
    } else if is_file(&dec_args.common.source) {
        let needs_passphrase = batch_needs_passphrase(&dec_args.common.source);
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

        decrypt_file_stream(
            &ctx,
            &dec_args.common.source,
            dec_args.common.remove_file,
            true,
        )?;
    } else {
        eprintln!(
            "{} Path '{}' is not valid.",
            style("✗").red().bold(),
            style(&dec_args.common.source).bold(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_embedded_name;

    #[test]
    fn validate_embedded_name_accepts_plain_basenames() {
        for name in ["foo.txt", "carta_despido.pdf", "a", "file.tar.gz"] {
            assert!(validate_embedded_name(name).is_ok(), "should accept {name}");
        }
    }

    #[test]
    fn validate_embedded_name_rejects_traversal_and_separators() {
        for name in ["", ".", "..", "../etc/passwd", "a/b", "a\\b", "/abs"] {
            assert!(
                validate_embedded_name(name).is_err(),
                "should reject {name:?}"
            );
        }
    }
}
