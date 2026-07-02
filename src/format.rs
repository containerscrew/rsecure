//! On-disk file format.
//!
//! Layouts (each followed by AES-256-GCM STREAM ciphertext over fixed 128 KiB
//! plaintext chunks):
//!
//!   v1 (rsecure ≤ 0.5.0, legacy decrypt-only):
//!     [7-byte random nonce]
//!     Plain master_key as AES-GCM key. No AAD.
//!
//!   v2 (rsecure 0.5.x interim, HKDF, no flags):
//!     [magic "RSEC" 4 B][0x02][chunk_size u32 LE 4 B][hkdf_salt 32 B] = 41 B
//!     AES-256-GCM key derived as HKDF(master_key, hkdf_salt). Header is AAD.
//!
//!   v3 (current):
//!     [magic "RSEC" 4 B][0x03][flags 1 B][chunk_size u32 LE 4 B][hkdf_salt 32 B] = 42 B
//!     + if flags & FLAG_PASSPHRASE:
//!       [argon2_m_cost u32 LE 4 B][argon2_t_cost u32 LE 4 B]
//!       [argon2_p_cost 1 B][argon2_salt 16 B] = +25 B
//!     Header (whatever its actual length) is AAD on every chunk.

use std::fs::File;
use std::io::Read;

use anyhow::{Result, anyhow};

pub const MAGIC: &[u8; 4] = b"RSEC";
pub const VERSION_V2: u8 = 0x02;
pub const VERSION_V3: u8 = 0x03;

pub const FLAG_PASSPHRASE: u8 = 0x01;

pub const HKDF_SALT_LEN: usize = 32;
pub const HKDF_INFO_V2: &[u8] = b"rsecure-v2-aes256gcm-stream";
pub const HKDF_INFO_V3: &[u8] = b"rsecure-v3-aes256gcm-stream";

pub const ARGON2_SALT_LEN: usize = 16;
#[allow(dead_code)]
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 19_456; // ~19 MiB
#[allow(dead_code)]
pub const ARGON2_DEFAULT_T_COST: u32 = 2;
#[allow(dead_code)]
pub const ARGON2_DEFAULT_P_COST: u8 = 1;

pub const LEGACY_NONCE_LEN: usize = 7;
pub const STREAM_SALT_LEN: usize = 7;
pub const AEAD_TAG_LEN: usize = 16;
pub const CHUNK_SIZE: u32 = 131_072;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

pub const HEADER_LEN_V2: usize = 4 + 1 + 4 + HKDF_SALT_LEN; // 41
pub const HEADER_LEN_V3_KEYFILE: usize = HEADER_LEN_V2 + 1; // 42
pub const HEADER_LEN_V3_PASSPHRASE: usize = HEADER_LEN_V3_KEYFILE + 4 + 4 + 1 + ARGON2_SALT_LEN; // 67

#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u8,
}

impl Argon2Params {
    #[allow(dead_code)]
    pub fn defaults() -> Self {
        Self {
            m_cost: ARGON2_DEFAULT_M_COST_KIB,
            t_cost: ARGON2_DEFAULT_T_COST,
            p_cost: ARGON2_DEFAULT_P_COST,
        }
    }
}

#[derive(Debug)]
pub enum Header {
    V1Legacy {
        nonce: [u8; LEGACY_NONCE_LEN],
    },
    V2 {
        chunk_size: u32,
        hkdf_salt: [u8; HKDF_SALT_LEN],
        bytes: [u8; HEADER_LEN_V2],
    },
    V3Keyfile {
        chunk_size: u32,
        hkdf_salt: [u8; HKDF_SALT_LEN],
        bytes: [u8; HEADER_LEN_V3_KEYFILE],
    },
    V3Passphrase {
        chunk_size: u32,
        hkdf_salt: [u8; HKDF_SALT_LEN],
        argon2_params: Argon2Params,
        argon2_salt: [u8; ARGON2_SALT_LEN],
        bytes: [u8; HEADER_LEN_V3_PASSPHRASE],
    },
}

impl Header {
    pub fn chunk_size(&self) -> u32 {
        match self {
            Header::V1Legacy { .. } => CHUNK_SIZE,
            Header::V2 { chunk_size, .. }
            | Header::V3Keyfile { chunk_size, .. }
            | Header::V3Passphrase { chunk_size, .. } => *chunk_size,
        }
    }

    /// Bytes to feed as AAD on every chunk. Empty slice for v1 (no AAD bound).
    pub fn aad(&self) -> &[u8] {
        match self {
            Header::V1Legacy { .. } => &[],
            Header::V2 { bytes, .. } => bytes,
            Header::V3Keyfile { bytes, .. } => bytes,
            Header::V3Passphrase { bytes, .. } => bytes,
        }
    }
}

fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(anyhow!(
            "Refusing to decrypt: header reports chunk_size={} (must be 1..={})",
            chunk_size,
            MAX_CHUNK_SIZE
        ));
    }
    Ok(())
}

/// Read enough bytes from `file` to fully describe the header, then return it.
/// The file cursor will be positioned at the start of the ciphertext on return.
pub fn parse_header(file: &mut File) -> Result<Header> {
    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf)?;

    if &magic_buf != MAGIC {
        // v1 legacy: the 4 bytes we just read are the first 4 bytes of a
        // 7-byte AES-GCM nonce. Read the remaining 3.
        let mut nonce = [0u8; LEGACY_NONCE_LEN];
        nonce[..4].copy_from_slice(&magic_buf);
        file.read_exact(&mut nonce[4..])?;
        return Ok(Header::V1Legacy { nonce });
    }

    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;

    match version[0] {
        VERSION_V2 => {
            let mut chunk_size_bytes = [0u8; 4];
            file.read_exact(&mut chunk_size_bytes)?;
            let chunk_size = u32::from_le_bytes(chunk_size_bytes);
            validate_chunk_size(chunk_size)?;

            let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
            file.read_exact(&mut hkdf_salt)?;

            let mut bytes = [0u8; HEADER_LEN_V2];
            bytes[0..4].copy_from_slice(&magic_buf);
            bytes[4] = version[0];
            bytes[5..9].copy_from_slice(&chunk_size_bytes);
            bytes[9..41].copy_from_slice(&hkdf_salt);
            Ok(Header::V2 {
                chunk_size,
                hkdf_salt,
                bytes,
            })
        }
        VERSION_V3 => {
            let mut flags = [0u8; 1];
            file.read_exact(&mut flags)?;

            let mut chunk_size_bytes = [0u8; 4];
            file.read_exact(&mut chunk_size_bytes)?;
            let chunk_size = u32::from_le_bytes(chunk_size_bytes);
            validate_chunk_size(chunk_size)?;

            let mut hkdf_salt = [0u8; HKDF_SALT_LEN];
            file.read_exact(&mut hkdf_salt)?;

            if flags[0] & FLAG_PASSPHRASE == 0 {
                let mut bytes = [0u8; HEADER_LEN_V3_KEYFILE];
                bytes[0..4].copy_from_slice(&magic_buf);
                bytes[4] = version[0];
                bytes[5] = flags[0];
                bytes[6..10].copy_from_slice(&chunk_size_bytes);
                bytes[10..42].copy_from_slice(&hkdf_salt);
                Ok(Header::V3Keyfile {
                    chunk_size,
                    hkdf_salt,
                    bytes,
                })
            } else {
                let mut m_cost_bytes = [0u8; 4];
                let mut t_cost_bytes = [0u8; 4];
                let mut p_cost_byte = [0u8; 1];
                let mut argon2_salt = [0u8; ARGON2_SALT_LEN];
                file.read_exact(&mut m_cost_bytes)?;
                file.read_exact(&mut t_cost_bytes)?;
                file.read_exact(&mut p_cost_byte)?;
                file.read_exact(&mut argon2_salt)?;

                let argon2_params = Argon2Params {
                    m_cost: u32::from_le_bytes(m_cost_bytes),
                    t_cost: u32::from_le_bytes(t_cost_bytes),
                    p_cost: p_cost_byte[0],
                };

                let mut bytes = [0u8; HEADER_LEN_V3_PASSPHRASE];
                bytes[0..4].copy_from_slice(&magic_buf);
                bytes[4] = version[0];
                bytes[5] = flags[0];
                bytes[6..10].copy_from_slice(&chunk_size_bytes);
                bytes[10..42].copy_from_slice(&hkdf_salt);
                bytes[42..46].copy_from_slice(&m_cost_bytes);
                bytes[46..50].copy_from_slice(&t_cost_bytes);
                bytes[50] = p_cost_byte[0];
                bytes[51..67].copy_from_slice(&argon2_salt);

                Ok(Header::V3Passphrase {
                    chunk_size,
                    hkdf_salt,
                    argon2_params,
                    argon2_salt,
                    bytes,
                })
            }
        }
        other => Err(anyhow!(
            "Unsupported rsecure file format version: 0x{:02x}",
            other
        )),
    }
}

pub fn build_v3_keyfile_header(
    chunk_size: u32,
    hkdf_salt: &[u8; HKDF_SALT_LEN],
) -> [u8; HEADER_LEN_V3_KEYFILE] {
    let mut bytes = [0u8; HEADER_LEN_V3_KEYFILE];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION_V3;
    bytes[5] = 0;
    bytes[6..10].copy_from_slice(&chunk_size.to_le_bytes());
    bytes[10..42].copy_from_slice(hkdf_salt);
    bytes
}

pub fn build_v3_passphrase_header(
    chunk_size: u32,
    hkdf_salt: &[u8; HKDF_SALT_LEN],
    argon2_params: &Argon2Params,
    argon2_salt: &[u8; ARGON2_SALT_LEN],
) -> [u8; HEADER_LEN_V3_PASSPHRASE] {
    let mut bytes = [0u8; HEADER_LEN_V3_PASSPHRASE];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION_V3;
    bytes[5] = FLAG_PASSPHRASE;
    bytes[6..10].copy_from_slice(&chunk_size.to_le_bytes());
    bytes[10..42].copy_from_slice(hkdf_salt);
    bytes[42..46].copy_from_slice(&argon2_params.m_cost.to_le_bytes());
    bytes[46..50].copy_from_slice(&argon2_params.t_cost.to_le_bytes());
    bytes[50] = argon2_params.p_cost;
    bytes[51..67].copy_from_slice(argon2_salt);
    bytes
}
