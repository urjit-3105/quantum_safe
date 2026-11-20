use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use zeroize::Zeroize;
use std::io::{Read, Write};
use crate::error::QSafeError;

pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB plaintext chunk
pub const TAG_SIZE: usize = 16;          // 16 bytes AEAD auth tag

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    XChaCha20Poly1305 = 0x01,
    Aes256Gcm = 0x02,
}

impl TryFrom<u8> for CipherSuite {
    type Error = QSafeError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(CipherSuite::XChaCha20Poly1305),
            0x02 => Ok(CipherSuite::Aes256Gcm),
            other => Err(QSafeError::UnsupportedCipherSuite(other)),
        }
    }
}

pub struct StreamEngine;

impl StreamEngine {
    /// Encrypts an input stream into chunked authenticated ciphertext stream
    /// Returns total ciphertext bytes written
    pub fn encrypt_stream<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        key: &[u8; 32],
        base_nonce: &[u8; 16],
        cipher_suite: CipherSuite,
    ) -> Result<u64, QSafeError> {
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut chunk_index: u64 = 0;
        let mut total_written: u64 = 0;
        let mut leftover: Option<u8> = None;

        loop {
            let mut bytes_read = 0;
            if let Some(b) = leftover.take() {
                buffer[0] = b;
                bytes_read = 1;
            }

            while bytes_read < CHUNK_SIZE {
                let n = reader.read(&mut buffer[bytes_read..])?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            let is_last = if bytes_read < CHUNK_SIZE {
                true
            } else {
                let mut peek = [0u8; 1];
                let n = reader.read(&mut peek)?;
                if n == 0 {
                    true
                } else {
                    leftover = Some(peek[0]);
                    false
                }
            };

            let mut chunk_data = Vec::with_capacity(bytes_read + TAG_SIZE);
            chunk_data.extend_from_slice(&buffer[..bytes_read]);

            match cipher_suite {
                CipherSuite::XChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new_from_slice(key)
                        .map_err(|e| QSafeError::Crypto(format!("Invalid key: {}", e)))?;

                    // Nonce: 16 bytes base || 7 bytes chunk_index || 1 byte is_last = 24 bytes
                    let mut nonce_bytes = [0u8; 24];
                    nonce_bytes[..16].copy_from_slice(base_nonce);
                    nonce_bytes[16..23].copy_from_slice(&chunk_index.to_be_bytes()[1..8]);
                    nonce_bytes[23] = if is_last { 0x01 } else { 0x00 };

                    let nonce = XNonce::try_from(nonce_bytes.as_slice()).unwrap();
                    cipher
                        .encrypt_in_place(&nonce, &[], &mut chunk_data)
                        .map_err(|e| QSafeError::Crypto(format!("Encryption failed: {}", e)))?;
                }
                CipherSuite::Aes256Gcm => {
                    let cipher = Aes256Gcm::new_from_slice(key)
                        .map_err(|e| QSafeError::Crypto(format!("Invalid key: {}", e)))?;

                    // Nonce: 4 bytes base || 7 bytes chunk_index || 1 byte is_last = 12 bytes
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes[..4].copy_from_slice(&base_nonce[..4]);
                    nonce_bytes[4..11].copy_from_slice(&chunk_index.to_be_bytes()[1..8]);
                    nonce_bytes[11] = if is_last { 0x01 } else { 0x00 };

                    let nonce = AesNonce::try_from(nonce_bytes.as_slice()).unwrap();
                    cipher
                        .encrypt_in_place(&nonce, &[], &mut chunk_data)
                        .map_err(|e| QSafeError::Crypto(format!("Encryption failed: {}", e)))?;
                }
            }

            // Write 4-byte big endian chunk length + chunk data (ciphertext + tag)
            let chunk_len = chunk_data.len() as u32;
            writer.write_all(&chunk_len.to_be_bytes())?;
            writer.write_all(&chunk_data)?;
            total_written += 4 + chunk_data.len() as u64;

            if is_last {
                break;
            }

            chunk_index += 1;
        }

        buffer.zeroize();
        Ok(total_written)
    }

    /// Decrypts a chunked authenticated stream and writes plaintext to writer
    pub fn decrypt_stream<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        key: &[u8; 32],
        base_nonce: &[u8; 16],
        cipher_suite: CipherSuite,
    ) -> Result<u64, QSafeError> {
        let mut chunk_index: u64 = 0;
        let mut total_plaintext_bytes: u64 = 0;
        let mut last_chunk_seen = false;

        loop {
            // Read 4-byte length prefix
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    if last_chunk_seen {
                        break;
                    } else {
                        return Err(QSafeError::PayloadTampered(chunk_index));
                    }
                }
                Err(e) => return Err(QSafeError::Io(e)),
            }

            let chunk_len = u32::from_be_bytes(len_buf) as usize;
            if chunk_len < TAG_SIZE || chunk_len > CHUNK_SIZE + TAG_SIZE {
                return Err(QSafeError::PayloadTampered(chunk_index));
            }

            let mut chunk_buf = vec![0u8; chunk_len];
            reader.read_exact(&mut chunk_buf)?;

            // Try decrypting with is_last = false first, if fails try is_last = true
            let mut is_last = false;
            let mut decrypted = false;

            for test_is_last in [false, true] {
                let mut trial_buf = chunk_buf.clone();
                match cipher_suite {
                    CipherSuite::XChaCha20Poly1305 => {
                        let cipher = XChaCha20Poly1305::new_from_slice(key)
                            .map_err(|e| QSafeError::Crypto(format!("Invalid key: {}", e)))?;

                        let mut nonce_bytes = [0u8; 24];
                        nonce_bytes[..16].copy_from_slice(base_nonce);
                        nonce_bytes[16..23].copy_from_slice(&chunk_index.to_be_bytes()[1..8]);
                        nonce_bytes[23] = if test_is_last { 0x01 } else { 0x00 };

                        let nonce = XNonce::try_from(nonce_bytes.as_slice()).unwrap();
                        if cipher.decrypt_in_place(&nonce, &[], &mut trial_buf).is_ok() {
                            is_last = test_is_last;
                            decrypted = true;
                            writer.write_all(&trial_buf)?;
                            total_plaintext_bytes += trial_buf.len() as u64;
                            trial_buf.zeroize();
                            break;
                        }
                    }
                    CipherSuite::Aes256Gcm => {
                        let cipher = Aes256Gcm::new_from_slice(key)
                            .map_err(|e| QSafeError::Crypto(format!("Invalid key: {}", e)))?;

                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[..4].copy_from_slice(&base_nonce[..4]);
                        nonce_bytes[4..11].copy_from_slice(&chunk_index.to_be_bytes()[1..8]);
                        nonce_bytes[11] = if test_is_last { 0x01 } else { 0x00 };

                        let nonce = AesNonce::try_from(nonce_bytes.as_slice()).unwrap();
                        if cipher.decrypt_in_place(&nonce, &[], &mut trial_buf).is_ok() {
                            is_last = test_is_last;
                            decrypted = true;
                            writer.write_all(&trial_buf)?;
                            total_plaintext_bytes += trial_buf.len() as u64;
                            trial_buf.zeroize();
                            break;
                        }
                    }
                }
                trial_buf.zeroize();
            }

            if !decrypted {
                return Err(QSafeError::PayloadTampered(chunk_index));
            }

            if is_last {
                last_chunk_seen = true;
                break;
            }

            chunk_index += 1;
        }

        if !last_chunk_seen {
            return Err(QSafeError::PayloadTampered(chunk_index));
        }

        Ok(total_plaintext_bytes)
    }
}
