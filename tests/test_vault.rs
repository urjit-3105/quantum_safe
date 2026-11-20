use std::io::Cursor;
use tempfile::NamedTempFile;
use qsafe::crypto::{
    CipherSuite, HybridKeyPair, HybridKemEngine, KdfEngine, StreamEngine,
};
use qsafe::vault::{VaultEngine, VaultHeader};
use qsafe::error::QSafeError;

#[test]
fn test_hybrid_kem_roundtrip() {
    let alice = HybridKeyPair::generate();
    let bob = HybridKeyPair::generate();

    // Alice encapsulates to Bob
    let (ct, ss_alice) = HybridKemEngine::encapsulate(&bob.public_keys()).unwrap();

    // Bob decapsulates
    let ss_bob = HybridKemEngine::decapsulate(&bob, &ct).unwrap();

    assert_eq!(ss_alice.as_bytes(), ss_bob.as_bytes());

    // Alice trying to decapsulate Bob's ciphertext fails to yield matching secret
    let ss_wrong = HybridKemEngine::decapsulate(&alice, &ct).unwrap();
    assert_ne!(ss_alice.as_bytes(), ss_wrong.as_bytes());
}

#[test]
fn test_stream_xchacha20_roundtrip() {
    let key = [0x42u8; 32];
    let base_nonce = [0x11u8; 16];
    let plaintext = b"Hello Quantum World! STREAM authenticated encryption with 64KB chunking.";

    let mut ciphertext = Vec::new();
    let mut reader = Cursor::new(plaintext);
    StreamEngine::encrypt_stream(
        &mut reader,
        &mut ciphertext,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();

    let mut decrypted = Vec::new();
    let mut ct_reader = Cursor::new(&ciphertext);
    StreamEngine::decrypt_stream(
        &mut ct_reader,
        &mut decrypted,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_stream_aes256_roundtrip() {
    let key = [0x99u8; 32];
    let base_nonce = [0x33u8; 16];
    let plaintext = vec![0xABu8; 150 * 1024]; // 150 KB spans 3 chunks

    let mut ciphertext = Vec::new();
    let mut reader = Cursor::new(&plaintext);
    StreamEngine::encrypt_stream(
        &mut reader,
        &mut ciphertext,
        &key,
        &base_nonce,
        CipherSuite::Aes256Gcm,
    ).unwrap();

    let mut decrypted = Vec::new();
    let mut ct_reader = Cursor::new(&ciphertext);
    StreamEngine::decrypt_stream(
        &mut ct_reader,
        &mut decrypted,
        &key,
        &base_nonce,
        CipherSuite::Aes256Gcm,
    ).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_tamper_detection_chunk_bitflip() {
    let key = [0x77u8; 32];
    let base_nonce = [0x88u8; 16];
    let plaintext = vec![0x42u8; 100 * 1024]; // 2 chunks

    let mut ciphertext = Vec::new();
    let mut reader = Cursor::new(&plaintext);
    StreamEngine::encrypt_stream(
        &mut reader,
        &mut ciphertext,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();

    // Flip 1 byte in the middle of chunk 0 ciphertext
    ciphertext[50] ^= 0x01;

    let mut decrypted = Vec::new();
    let mut ct_reader = Cursor::new(&ciphertext);
    let result = StreamEngine::decrypt_stream(
        &mut ct_reader,
        &mut decrypted,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        QSafeError::PayloadTampered(chunk_idx) => assert_eq!(chunk_idx, 0),
        other => panic!("Expected PayloadTampered, got {:?}", other),
    }
}

#[test]
fn test_tamper_detection_truncation() {
    let key = [0x55u8; 32];
    let base_nonce = [0x66u8; 16];
    let plaintext = vec![0x12u8; 150 * 1024]; // 3 chunks

    let mut ciphertext = Vec::new();
    let mut reader = Cursor::new(&plaintext);
    StreamEngine::encrypt_stream(
        &mut reader,
        &mut ciphertext,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();

    // Truncate the last 50 bytes of the file (cutting the final tag)
    let truncated_len = ciphertext.len() - 50;
    let mut ct_reader = Cursor::new(&ciphertext[..truncated_len]);
    let mut decrypted = Vec::new();
    let result = StreamEngine::decrypt_stream(
        &mut ct_reader,
        &mut decrypted,
        &key,
        &base_nonce,
        CipherSuite::XChaCha20Poly1305,
    );

    assert!(result.is_err());
}

#[test]
fn test_vault_e2e_encryption_decryption() {
    let bob = HybridKeyPair::generate();
    let passphrase = b"SuperQuantumSafeMasterPassphrase2026!";

    // Create temporary source file with 200 KB test payload
    let source_data = vec![0xFEu8; 200 * 1024];
    let source_file = NamedTempFile::new().unwrap();
    std::fs::write(source_file.path(), &source_data).unwrap();

    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    // Encrypt
    let total_encrypted = VaultEngine::encrypt_file(
        source_file.path(),
        encrypted_file.path(),
        &bob.public_keys(),
        Some(passphrase),
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();
    assert!(total_encrypted > 0);

    // Verify integrity without decrypting to disk
    let verified_bytes = VaultEngine::verify_file(
        encrypted_file.path(),
        &bob,
        Some(passphrase),
    ).unwrap();
    assert_eq!(verified_bytes, source_data.len() as u64);

    // Decrypt
    let total_decrypted = VaultEngine::decrypt_file(
        encrypted_file.path(),
        decrypted_file.path(),
        &bob,
        Some(passphrase),
    ).unwrap();
    assert_eq!(total_decrypted, source_data.len() as u64);

    // Compare original and decrypted
    let decrypted_bytes = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(source_data, decrypted_bytes);

    // Attempting decrypt with WRONG passphrase must fail
    let wrong_passphrase = b"WrongPasswordAttempts!";
    let fail_result = VaultEngine::decrypt_file(
        encrypted_file.path(),
        decrypted_file.path(),
        &bob,
        Some(wrong_passphrase),
    );
    assert!(fail_result.is_err());
}

#[test]
fn test_vault_e2e_header_tamper_detected() {
    let bob = HybridKeyPair::generate();
    let passphrase = b"SafePass123";

    let source_data = b"Sensitive Quantum Safe Data";
    let source_file = NamedTempFile::new().unwrap();
    std::fs::write(source_file.path(), source_data).unwrap();

    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    VaultEngine::encrypt_file(
        source_file.path(),
        encrypted_file.path(),
        &bob.public_keys(),
        Some(passphrase),
        CipherSuite::XChaCha20Poly1305,
    ).unwrap();

    // Tamper with header in the encrypted file (e.g. byte 20)
    let mut ct_bytes = std::fs::read(encrypted_file.path()).unwrap();
    ct_bytes[20] ^= 0xFF;
    std::fs::write(encrypted_file.path(), &ct_bytes).unwrap();

    // Decryption must fail header authentication
    let result = VaultEngine::decrypt_file(
        encrypted_file.path(),
        decrypted_file.path(),
        &bob,
        Some(passphrase),
    );
    assert!(result.is_err());
}
