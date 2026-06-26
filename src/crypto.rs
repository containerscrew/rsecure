//! Key-derivation helpers shared by encrypt and decrypt.

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::format;

/// Derive a per-file AES-256 subkey from a master key and HKDF salt, using a
/// versioned info string so v2 and v3 subkeys are domain-separated.
fn derive_subkey(master_key: &[u8], hkdf_salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), master_key);
    let mut subkey = [0u8; 32];
    hk.expand(info, &mut subkey)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(subkey)
}

pub fn derive_subkey_v2(master_key: &[u8], hkdf_salt: &[u8]) -> Result<[u8; 32]> {
    derive_subkey(master_key, hkdf_salt, format::HKDF_INFO_V2)
}

pub fn derive_subkey_v3(master_key: &[u8], hkdf_salt: &[u8]) -> Result<[u8; 32]> {
    derive_subkey(master_key, hkdf_salt, format::HKDF_INFO_V3)
}

/// Argon2id derivation from a passphrase and salt to a 32-byte master key.
/// The salt and parameters live in each v3-passphrase file's header.
pub fn derive_master_key_argon2(
    passphrase: &[u8],
    salt: &[u8],
    params: &format::Argon2Params,
) -> Result<[u8; 32]> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost as u32, Some(32))
        .map_err(|e| {
        anyhow!(
            "Invalid Argon2 params (m={}, t={}, p={}): {}",
            params.m_cost,
            params.t_cost,
            params.p_cost,
            e
        )
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| anyhow!("Argon2 derivation failed: {}", e))?;
    Ok(output)
}
