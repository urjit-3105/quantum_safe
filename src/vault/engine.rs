use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::Rng;
use zeroize::Zeroize;

use crate::error::QSafeError;
use crate::crypto::{
    CipherSuite, HybridKeyPair, HybridPublicKey, HybridKemEngine,
    KdfEngine, SecureKey, StreamEngine, get_secure_rng,
    DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_T_COST, DEFAULT_ARGON2_P_COST,
};
use crate::vault::header::{VaultHeader, CURRENT_VERSION};

pub struct VaultEngine;

impl VaultEngine {
    pub const INFO_DEK_WRAP: &'static [u8] = b"qsafe-v1-dek-wrap-key";
    pub const INFO_HEADER_AUTH: &'static [u8] = b"qsafe-v1-header-auth-key";

    /// Encrypts an arbitrary file into a quantum-safe `.qsafe` container
    pub fn encrypt_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        input_path: P1,
        output_path: P2,
        recipient_pub: &HybridPublicKey,
        passphrase: Option<&[u8]>,
        cipher_suite: CipherSuite,
    ) -> Result<u64, QSafeError> {
        let mut rng = get_secure_rng();

        // 1. Generate Ephemeral Data Encryption Key (DEK) and Base Nonce
        let mut raw_dek = [0u8; 32];
        rng.fill_bytes(&mut raw_dek);
        let dek = SecureKey::new(raw_dek);
        raw_dek.zeroize();

        let mut base_nonce = [0u8; 16];
        rng.fill_bytes(&mut base_nonce);

        // 2. Generate Salt and derive Password KEK
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        let pw_kek = match passphrase {
            Some(pw) if !pw.is_empty() => {
                KdfEngine::derive_kek_from_passphrase(
                    pw,
                    &salt,
                    DEFAULT_ARGON2_M_COST,
                    DEFAULT_ARGON2_T_COST,
                    DEFAULT_ARGON2_P_COST,
                )?
            }
            _ => {
                let dummy = [0u8; 32];
                SecureKey::new(dummy)
            }
        };

        // 3. Post-Quantum Hybrid KEM Encapsulation
        let (hybrid_ct, asym_kek) = HybridKemEngine::encapsulate(recipient_pub)?;

        // 4. Combine Passphrase KEK & Asymmetric KEK into Master KEK
        let master_kek = KdfEngine::hkdf_combine_secrets(
            Some(&salt),
            &[pw_kek.as_bytes(), asym_kek.as_bytes()],
            b"qsafe-v1-master-kek-combiner",
        )?;

        // 5. Derive Subkeys for DEK Wrapping and Header Authentication
        let dek_wrap_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_DEK_WRAP)?;
        let header_auth_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_HEADER_AUTH)?;

        // 6. Encrypt DEK with XChaCha20-Poly1305 using zero-nonce (key is single-use ephemeral)
        let cipher = XChaCha20Poly1305::new_from_slice(dek_wrap_key.as_bytes())
            .map_err(|e| QSafeError::Crypto(format!("Cipher init failed: {}", e)))?;

        let mut encrypted_dek_vec = Vec::with_capacity(48);
        encrypted_dek_vec.extend_from_slice(dek.as_bytes());
        let zero_nonce = XNonce::try_from([0u8; 24].as_slice()).unwrap();
        cipher
            .encrypt_in_place(&zero_nonce, &[], &mut encrypted_dek_vec)
            .map_err(|e| QSafeError::Crypto(format!("DEK wrap failed: {}", e)))?;

        let mut encrypted_dek = [0u8; 48];
        encrypted_dek.copy_from_slice(&encrypted_dek_vec);

        // 7. Assemble and write Header
        let header = VaultHeader {
            version: CURRENT_VERSION,
            cipher_suite,
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST,
            salt,
            base_nonce,
            ephemeral_x25519_public: hybrid_ct.ephemeral_x25519_public,
            ml_kem_ciphertext: hybrid_ct.ml_kem_ciphertext,
            encrypted_dek,
        };

        let out_file = File::create(output_path)?;
        let mut writer = BufWriter::new(out_file);
        header.write_to(&mut writer, header_auth_key.as_bytes())?;

        // 8. Stream Encrypt Input File Chunks
        let in_file = File::open(input_path)?;
        let mut reader = BufReader::new(in_file);

        let total_payload = StreamEngine::encrypt_stream(
            &mut reader,
            &mut writer,
            dek.as_bytes(),
            &base_nonce,
            cipher_suite,
        )?;

        Ok(total_payload)
    }

    /// Decrypts a `.qsafe` container back to its original plaintext
    pub fn decrypt_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        input_path: P1,
        output_path: P2,
        keypair: &HybridKeyPair,
        passphrase: Option<&[u8]>,
    ) -> Result<u64, QSafeError> {
        let in_file = File::open(input_path)?;
        let mut reader = BufReader::new(in_file);

        // 1. Read unauthenticated metadata to extract parameters
        let (header, tag, buffer) = VaultHeader::read_metadata(&mut reader)?;

        // 2. Re-derive Password KEK
        let pw_kek = match passphrase {
            Some(pw) if !pw.is_empty() => {
                KdfEngine::derive_kek_from_passphrase(
                    pw,
                    &header.salt,
                    header.m_cost,
                    header.t_cost,
                    header.p_cost,
                )?
            }
            _ => {
                let dummy = [0u8; 32];
                SecureKey::new(dummy)
            }
        };

        // 3. Decapsulate Asymmetric KEK
        let hybrid_ct = crate::crypto::HybridCiphertext {
            ephemeral_x25519_public: header.ephemeral_x25519_public,
            ml_kem_ciphertext: header.ml_kem_ciphertext,
        };
        let asym_kek = HybridKemEngine::decapsulate(keypair, &hybrid_ct)?;

        // 4. Derive Master KEK
        let master_kek = KdfEngine::hkdf_combine_secrets(
            Some(&header.salt),
            &[pw_kek.as_bytes(), asym_kek.as_bytes()],
            b"qsafe-v1-master-kek-combiner",
        )?;

        // 5. Derive Subkeys
        let dek_wrap_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_DEK_WRAP)?;
        let header_auth_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_HEADER_AUTH)?;

        // 6. Authenticate Header (abort immediately if wrong password, wrong key, or tampering)
        VaultHeader::verify_tag(&buffer, &tag, header_auth_key.as_bytes())
            .map_err(|_| QSafeError::AuthenticationFailed)?;

        // 7. Unwrap DEK
        let cipher = XChaCha20Poly1305::new_from_slice(dek_wrap_key.as_bytes())
            .map_err(|e| QSafeError::Crypto(format!("Cipher init failed: {}", e)))?;

        let mut dek_buf = header.encrypted_dek.to_vec();
        let zero_nonce = XNonce::try_from([0u8; 24].as_slice()).unwrap();
        cipher
            .decrypt_in_place(&zero_nonce, &[], &mut dek_buf)
            .map_err(|_| QSafeError::AuthenticationFailed)?;

        let mut dek_bytes = [0u8; 32];
        dek_bytes.copy_from_slice(&dek_buf);
        let dek = SecureKey::new(dek_bytes);
        dek_buf.zeroize();
        dek_bytes.zeroize();

        // 8. Stream Decrypt Chunks to Output File
        let out_file = File::create(output_path)?;
        let mut writer = BufWriter::new(out_file);

        let total_bytes = StreamEngine::decrypt_stream(
            &mut reader,
            &mut writer,
            dek.as_bytes(),
            &header.base_nonce,
            header.cipher_suite,
        )?;

        Ok(total_bytes)
    }

    /// Verifies container integrity without decrypting plaintext to disk
    pub fn verify_file<P: AsRef<Path>>(
        input_path: P,
        keypair: &HybridKeyPair,
        passphrase: Option<&[u8]>,
    ) -> Result<u64, QSafeError> {
        let in_file = File::open(input_path)?;
        let mut reader = BufReader::new(in_file);

        // 1. Read metadata
        let (header, tag, buffer) = VaultHeader::read_metadata(&mut reader)?;

        // 2. Derive Password KEK
        let pw_kek = match passphrase {
            Some(pw) if !pw.is_empty() => {
                KdfEngine::derive_kek_from_passphrase(
                    pw,
                    &header.salt,
                    header.m_cost,
                    header.t_cost,
                    header.p_cost,
                )?
            }
            _ => {
                let dummy = [0u8; 32];
                SecureKey::new(dummy)
            }
        };

        // 3. Decapsulate Asymmetric KEK
        let hybrid_ct = crate::crypto::HybridCiphertext {
            ephemeral_x25519_public: header.ephemeral_x25519_public,
            ml_kem_ciphertext: header.ml_kem_ciphertext,
        };
        let asym_kek = HybridKemEngine::decapsulate(keypair, &hybrid_ct)?;

        // 4. Derive Master KEK & Subkeys
        let master_kek = KdfEngine::hkdf_combine_secrets(
            Some(&header.salt),
            &[pw_kek.as_bytes(), asym_kek.as_bytes()],
            b"qsafe-v1-master-kek-combiner",
        )?;

        let dek_wrap_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_DEK_WRAP)?;
        let header_auth_key = KdfEngine::hkdf_expand(master_kek.as_bytes(), Self::INFO_HEADER_AUTH)?;

        // 5. Verify Header Authentication Tag
        VaultHeader::verify_tag(&buffer, &tag, header_auth_key.as_bytes())
            .map_err(|_| QSafeError::AuthenticationFailed)?;

        // 6. Unwrap DEK
        let cipher = XChaCha20Poly1305::new_from_slice(dek_wrap_key.as_bytes())
            .map_err(|e| QSafeError::Crypto(format!("Cipher init failed: {}", e)))?;

        let mut dek_buf = header.encrypted_dek.to_vec();
        let zero_nonce = XNonce::try_from([0u8; 24].as_slice()).unwrap();
        cipher
            .decrypt_in_place(&zero_nonce, &[], &mut dek_buf)
            .map_err(|_| QSafeError::AuthenticationFailed)?;

        let mut dek_bytes = [0u8; 32];
        dek_bytes.copy_from_slice(&dek_buf);
        let dek = SecureKey::new(dek_bytes);
        dek_buf.zeroize();
        dek_bytes.zeroize();

        // 7. Verify all chunks using a sink writer
        let mut sink = std::io::sink();
        let total_bytes = StreamEngine::decrypt_stream(
            &mut reader,
            &mut sink,
            dek.as_bytes(),
            &header.base_nonce,
            header.cipher_suite,
        )?;

        Ok(total_bytes)
    }
}
