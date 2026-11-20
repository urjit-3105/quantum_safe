use std::io::{Read, Write};
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::error::QSafeError;
use crate::crypto::{CipherSuite, ML_KEM_768_CIPHERTEXT_SIZE, X25519_KEY_SIZE};

pub const MAGIC_BYTES: &[u8; 5] = b"QSAFE";
pub const CURRENT_VERSION: u8 = 0x01;
pub const HEADER_AUTH_TAG_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub version: u8,
    pub cipher_suite: CipherSuite,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 32],
    pub base_nonce: [u8; 16],
    pub ephemeral_x25519_public: [u8; X25519_KEY_SIZE],
    pub ml_kem_ciphertext: Vec<u8>,
    pub encrypted_dek: [u8; 48], // 32-byte DEK + 16-byte AEAD tag
}

impl VaultHeader {
    /// Serializes header and calculates HMAC-SHA256 integrity tag using derived auth key
    pub fn write_to<W: Write>(&self, writer: &mut W, auth_key: &[u8; 32]) -> Result<(), QSafeError> {
        let mut buffer = Vec::with_capacity(1280);

        // 1. Magic + Version + Cipher
        buffer.extend_from_slice(MAGIC_BYTES);
        buffer.push(self.version);
        buffer.push(self.cipher_suite as u8);

        // 2. KDF Parameters
        buffer.extend_from_slice(&self.m_cost.to_be_bytes());
        buffer.extend_from_slice(&self.t_cost.to_be_bytes());
        buffer.extend_from_slice(&self.p_cost.to_be_bytes());
        buffer.extend_from_slice(&self.salt);

        // 3. Streaming Base Nonce
        buffer.extend_from_slice(&self.base_nonce);

        // 4. Hybrid Asymmetric Envelope
        buffer.extend_from_slice(&self.ephemeral_x25519_public);
        buffer.extend_from_slice(&self.ml_kem_ciphertext);
        buffer.extend_from_slice(&self.encrypted_dek);

        // 5. Header MAC computation
        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|e| QSafeError::Crypto(format!("HMAC init failed: {}", e)))?;
        mac.update(&buffer);
        let header_tag = mac.finalize().into_bytes();

        buffer.extend_from_slice(&header_tag);

        writer.write_all(&buffer)?;
        Ok(())
    }

    /// Reads and authenticates header from stream
    pub fn read_from<R: Read>(reader: &mut R, auth_key: &[u8; 32]) -> Result<Self, QSafeError> {
        let mut magic = [0u8; 5];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC_BYTES {
            return Err(QSafeError::InvalidMagic);
        }

        let mut ver_cipher = [0u8; 2];
        reader.read_exact(&mut ver_cipher)?;
        let version = ver_cipher[0];
        if version != CURRENT_VERSION {
            return Err(QSafeError::UnsupportedVersion(version));
        }
        let cipher_suite = CipherSuite::try_from(ver_cipher[1])?;

        let mut kdf_params = [0u8; 12];
        reader.read_exact(&mut kdf_params)?;
        let m_cost = u32::from_be_bytes(kdf_params[0..4].try_into().unwrap());
        let t_cost = u32::from_be_bytes(kdf_params[4..8].try_into().unwrap());
        let p_cost = u32::from_be_bytes(kdf_params[8..12].try_into().unwrap());

        let mut salt = [0u8; 32];
        reader.read_exact(&mut salt)?;

        let mut base_nonce = [0u8; 16];
        reader.read_exact(&mut base_nonce)?;

        let mut ephemeral_x25519_public = [0u8; 32];
        reader.read_exact(&mut ephemeral_x25519_public)?;

        let mut ml_kem_ciphertext = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        reader.read_exact(&mut ml_kem_ciphertext)?;

        let mut encrypted_dek = [0u8; 48];
        reader.read_exact(&mut encrypted_dek)?;

        let mut expected_tag = [0u8; HEADER_AUTH_TAG_SIZE];
        reader.read_exact(&mut expected_tag)?;

        // Reconstruct authenticated buffer to verify tag
        let mut buffer = Vec::with_capacity(1280);
        buffer.extend_from_slice(MAGIC_BYTES);
        buffer.push(version);
        buffer.push(cipher_suite as u8);
        buffer.extend_from_slice(&kdf_params);
        buffer.extend_from_slice(&salt);
        buffer.extend_from_slice(&base_nonce);
        buffer.extend_from_slice(&ephemeral_x25519_public);
        buffer.extend_from_slice(&ml_kem_ciphertext);
        buffer.extend_from_slice(&encrypted_dek);

        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|e| QSafeError::Crypto(format!("HMAC init failed: {}", e)))?;
        mac.update(&buffer);

        if mac.verify_slice(&expected_tag).is_err() {
            return Err(QSafeError::HeaderIntegrityFailed);
        }

        Ok(Self {
            version,
            cipher_suite,
            m_cost,
            t_cost,
            p_cost,
            salt,
            base_nonce,
            ephemeral_x25519_public,
            ml_kem_ciphertext,
            encrypted_dek,
        })
    }

    /// Reads raw unauthenticated header without checking MAC (for extracting salt and KDF params before key derivation)
    pub fn read_metadata<R: Read>(reader: &mut R) -> Result<(Self, [u8; HEADER_AUTH_TAG_SIZE], Vec<u8>), QSafeError> {
        let mut buffer = Vec::with_capacity(1280);

        let mut magic = [0u8; 5];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC_BYTES {
            return Err(QSafeError::InvalidMagic);
        }
        buffer.extend_from_slice(&magic);

        let mut ver_cipher = [0u8; 2];
        reader.read_exact(&mut ver_cipher)?;
        let version = ver_cipher[0];
        if version != CURRENT_VERSION {
            return Err(QSafeError::UnsupportedVersion(version));
        }
        let cipher_suite = CipherSuite::try_from(ver_cipher[1])?;
        buffer.extend_from_slice(&ver_cipher);

        let mut kdf_params = [0u8; 12];
        reader.read_exact(&mut kdf_params)?;
        let m_cost = u32::from_be_bytes(kdf_params[0..4].try_into().unwrap());
        let t_cost = u32::from_be_bytes(kdf_params[4..8].try_into().unwrap());
        let p_cost = u32::from_be_bytes(kdf_params[8..12].try_into().unwrap());
        buffer.extend_from_slice(&kdf_params);

        let mut salt = [0u8; 32];
        reader.read_exact(&mut salt)?;
        buffer.extend_from_slice(&salt);

        let mut base_nonce = [0u8; 16];
        reader.read_exact(&mut base_nonce)?;
        buffer.extend_from_slice(&base_nonce);

        let mut ephemeral_x25519_public = [0u8; 32];
        reader.read_exact(&mut ephemeral_x25519_public)?;
        buffer.extend_from_slice(&ephemeral_x25519_public);

        let mut ml_kem_ciphertext = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        reader.read_exact(&mut ml_kem_ciphertext)?;
        buffer.extend_from_slice(&ml_kem_ciphertext);

        let mut encrypted_dek = [0u8; 48];
        reader.read_exact(&mut encrypted_dek)?;
        buffer.extend_from_slice(&encrypted_dek);

        let mut tag = [0u8; HEADER_AUTH_TAG_SIZE];
        reader.read_exact(&mut tag)?;

        let header = Self {
            version,
            cipher_suite,
            m_cost,
            t_cost,
            p_cost,
            salt,
            base_nonce,
            ephemeral_x25519_public,
            ml_kem_ciphertext,
            encrypted_dek,
        };

        Ok((header, tag, buffer))
    }

    pub fn verify_tag(buffer: &[u8], expected_tag: &[u8; 32], auth_key: &[u8; 32]) -> Result<(), QSafeError> {
        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|e| QSafeError::Crypto(format!("HMAC init failed: {}", e)))?;
        mac.update(buffer);

        if mac.verify_slice(expected_tag).is_err() {
            return Err(QSafeError::HeaderIntegrityFailed);
        }
        Ok(())
    }
}
