use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use crate::error::QSafeError;
use crate::crypto::memory::SecureKey;

/// Default Argon2id parameters optimized for interactive yet quantum/ASIC-resistant security
pub const DEFAULT_ARGON2_M_COST: u32 = 64 * 1024; // 64 MB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;         // 3 iterations
pub const DEFAULT_ARGON2_P_COST: u32 = 4;         // 4 parallel lanes
pub const SALT_LEN: usize = 32;

pub struct KdfEngine;

impl KdfEngine {
    /// Derives a 256-bit Master Key Encryption Key (KEK) from a passphrase using Argon2id
    pub fn derive_kek_from_passphrase(
        passphrase: &[u8],
        salt: &[u8; SALT_LEN],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<SecureKey<32>, QSafeError> {
        let params = Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| QSafeError::KdfError(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output_key = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut output_key)
            .map_err(|e| QSafeError::KdfError(format!("Argon2id derivation failed: {}", e)))?;

        Ok(SecureKey::new(output_key))
    }

    /// Derives subkeys using HKDF-SHA256 with domain separation
    pub fn hkdf_expand(
        prk: &[u8],
        info: &[u8],
    ) -> Result<SecureKey<32>, QSafeError> {
        let hk = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|e| QSafeError::Crypto(format!("Invalid PRK length: {}", e)))?;

        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| QSafeError::Crypto(format!("HKDF expansion failed: {}", e)))?;

        Ok(SecureKey::new(okm))
    }

    /// Combines multiple secrets using HKDF-SHA256 Extract-and-Expand
    pub fn hkdf_combine_secrets(
        salt: Option<&[u8]>,
        secrets: &[&[u8]],
        info: &[u8],
    ) -> Result<SecureKey<32>, QSafeError> {
        let mut total_len = 0;
        for s in secrets {
            total_len += s.len();
        }

        let mut ikm = Vec::with_capacity(total_len);
        for s in secrets {
            ikm.extend_from_slice(s);
        }

        let hk = Hkdf::<Sha256>::new(salt, &ikm);
        ikm.zeroize();

        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| QSafeError::Crypto(format!("HKDF expansion failed: {}", e)))?;

        Ok(SecureKey::new(okm))
    }
}
