use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey, MlKem768};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Kem};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use crate::error::QSafeError;
use crate::crypto::kdf::KdfEngine;
use crate::crypto::memory::SecureKey;
use crate::crypto::rng::get_secure_rng;

pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_SEED_SIZE: usize = 64;
pub const X25519_KEY_SIZE: usize = 32;

/// Post-Quantum Hybrid Identity Keypair
pub struct HybridKeyPair {
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
    pub ml_kem_decapsulation_key: DecapsulationKey,
    pub ml_kem_encapsulation_key: EncapsulationKey,
}

impl HybridKeyPair {
    /// Generates a new fresh hybrid keypair using OS entropy
    pub fn generate() -> Self {
        let mut rng = get_secure_rng();

        // 1. Classical X25519
        let x25519_secret = StaticSecret::random_from_rng(&mut rng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // 2. Post-Quantum FIPS 203 ML-KEM-768
        let (ml_kem_dk, ml_kem_ek) = MlKem768::generate_keypair_from_rng(&mut rng);

        Self {
            x25519_secret,
            x25519_public,
            ml_kem_decapsulation_key: ml_kem_dk,
            ml_kem_encapsulation_key: ml_kem_ek,
        }
    }

    /// Reconstructs keypair from raw secrets: x25519 secret (32B) + ml_kem seed (64B)
    pub fn from_secrets(x25519_secret_bytes: &[u8; 32], ml_kem_seed_bytes: &[u8; 64]) -> Self {
        let x25519_secret = StaticSecret::from(*x25519_secret_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let ml_kem_seed: ml_kem::Seed = ml_kem::array::Array::from(*ml_kem_seed_bytes);
        let ml_kem_dk = DecapsulationKey::from_seed(ml_kem_seed);
        let ml_kem_ek = ml_kem_dk.encapsulation_key().clone();

        Self {
            x25519_secret,
            x25519_public,
            ml_kem_decapsulation_key: ml_kem_dk,
            ml_kem_encapsulation_key: ml_kem_ek,
        }
    }

    pub fn public_keys(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519: self.x25519_public,
            ml_kem: self.ml_kem_encapsulation_key.clone(),
        }
    }

    /// Serializes private key components: 32B (x25519) + 64B (ml_kem seed) = 96B
    pub fn to_private_bytes(&self) -> SecureKey<96> {
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&self.x25519_secret.to_bytes());
        let seed = self.ml_kem_decapsulation_key.to_bytes();
        out[32..96].copy_from_slice(seed.as_slice());
        SecureKey::new(out)
    }
}

/// Hybrid Public Key containing classical X25519 and PQC ML-KEM-768 keys
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519: X25519PublicKey,
    pub ml_kem: EncapsulationKey,
}

impl HybridPublicKey {
    pub fn from_bytes(x25519_bytes: &[u8; 32], ml_kem_bytes: &[u8]) -> Result<Self, QSafeError> {
        let x25519 = X25519PublicKey::from(*x25519_bytes);
        if ml_kem_bytes.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(QSafeError::InvalidKey(format!(
                "Invalid ML-KEM-768 key size: expected {}, got {}",
                ML_KEM_768_PUBLIC_KEY_SIZE,
                ml_kem_bytes.len()
            )));
        }

        let ml_kem_array = ml_kem::array::Array::try_from(ml_kem_bytes)
            .map_err(|_| QSafeError::InvalidKey("Failed to convert ML-KEM key array".into()))?;

        let ml_kem = EncapsulationKey::new(&ml_kem_array)
            .map_err(|_| QSafeError::InvalidKey("Invalid ML-KEM-768 public key data".into()))?;

        Ok(Self { x25519, ml_kem })
    }

    pub fn ml_kem_bytes(&self) -> Vec<u8> {
        self.ml_kem.to_bytes().as_slice().to_vec()
    }
}

/// Dual ciphertext produced by hybrid encapsulation
pub struct HybridCiphertext {
    pub ephemeral_x25519_public: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
}

pub struct HybridKemEngine;

impl HybridKemEngine {
    pub const HYBRID_KEM_INFO: &'static [u8] = b"qsafe-v1-hybrid-kem-x25519-mlkem768";

    /// Encapsulates against recipient's hybrid public key
    /// Returns (HybridCiphertext, 256-bit Combined Shared Secret)
    pub fn encapsulate(
        recipient: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, SecureKey<32>), QSafeError> {
        let mut rng = get_secure_rng();

        // 1. Classical Ephemeral X25519 Diffie-Hellman
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        let ss_classical = ephemeral_secret.diffie_hellman(&recipient.x25519);

        // 2. Post-Quantum FIPS 203 ML-KEM-768 Encapsulation
        let (ml_kem_ct, ss_pqc) = recipient
            .ml_kem
            .encapsulate_with_rng(&mut rng);

        // 3. Robust Dual Combiner: HKDF-SHA256(SS_classical || SS_pqc, info)
        let combined_key = KdfEngine::hkdf_combine_secrets(
            None,
            &[ss_classical.as_bytes(), ss_pqc.as_slice()],
            Self::HYBRID_KEM_INFO,
        )?;

        let ciphertext = HybridCiphertext {
            ephemeral_x25519_public: *ephemeral_pub.as_bytes(),
            ml_kem_ciphertext: ml_kem_ct.as_slice().to_vec(),
        };

        Ok((ciphertext, combined_key))
    }

    /// Decapsulates ciphertext using private keypair
    pub fn decapsulate(
        keypair: &HybridKeyPair,
        ciphertext: &HybridCiphertext,
    ) -> Result<SecureKey<32>, QSafeError> {
        // 1. Recover classical shared secret
        let sender_pub = X25519PublicKey::from(ciphertext.ephemeral_x25519_public);
        let ss_classical = keypair.x25519_secret.diffie_hellman(&sender_pub);

        // 2. Recover post-quantum ML-KEM shared secret
        if ciphertext.ml_kem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(QSafeError::Crypto("Invalid ML-KEM ciphertext length".into()));
        }

        let ct_array = ml_kem::array::Array::try_from(ciphertext.ml_kem_ciphertext.as_slice())
            .map_err(|_| QSafeError::Crypto("Malformed ML-KEM ciphertext bytes".into()))?;

        let ss_pqc = keypair.ml_kem_decapsulation_key.decapsulate(&ct_array);

        // 3. Run identical combiner
        let combined_key = KdfEngine::hkdf_combine_secrets(
            None,
            &[ss_classical.as_bytes(), ss_pqc.as_slice()],
            Self::HYBRID_KEM_INFO,
        )?;

        Ok(combined_key)
    }
}
