use thiserror::Error;

#[derive(Error, Debug)]
pub enum QSafeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Invalid vault magic bytes: expected 'QSAFE'")]
    InvalidMagic,

    #[error("Unsupported vault format version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(u8),

    #[error("Header authentication tag mismatch: vault header is corrupted or tampered")]
    HeaderIntegrityFailed,

    #[error("Payload authentication tag mismatch on chunk {0}: data corrupted or tampered")]
    PayloadTampered(u64),

    #[error("Key derivation failed: {0}")]
    KdfError(String),

    #[error("Invalid passphrase or corrupted key envelope")]
    AuthenticationFailed,

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Memory security error: {0}")]
    MemorySecurity(String),
}
