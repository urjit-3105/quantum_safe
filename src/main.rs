use std::path::PathBuf;
use std::time::Instant;
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};

use qsafe::crypto::{
    CipherSuite, HybridKeyPair, HybridPublicKey, KdfEngine,
    ML_KEM_768_PUBLIC_KEY_SIZE,
};
use qsafe::vault::{VaultEngine, VaultHeader};
use qsafe::QSafeError;

#[derive(Parser)]
#[command(
    name = "qsafe",
    about = "Quantum-Safe Local Storage Engine (FIPS 203 ML-KEM-768 + X25519 Hybrid AEAD)",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum CliCipher {
    Xchacha20,
    Aes256,
}

impl From<CliCipher> for CipherSuite {
    fn from(c: CliCipher) -> Self {
        match c {
            CliCipher::Xchacha20 => CipherSuite::XChaCha20Poly1305,
            CliCipher::Aes256 => CipherSuite::Aes256Gcm,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a post-quantum hybrid keypair (ML-KEM-768 + X25519)
    Keygen {
        /// Output path for keypair (creates <name>.pub and <name>.key)
        #[arg(short, long, default_value = "id_qsafe")]
        out: String,

        /// Encrypt the private key with a passphrase
        #[arg(short, long)]
        password: bool,
    },

    /// Encrypt a file into a quantum-safe (.qsafe) envelope
    Encrypt {
        /// Path of plaintext input file
        #[arg(short, long)]
        input: PathBuf,

        /// Path of encrypted output container
        #[arg(short, long)]
        output: PathBuf,

        /// Path to recipient's hybrid public key (.pub file)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Protect with a user master passphrase
        #[arg(short, long)]
        password: bool,

        /// Symmetric cipher suite (xchacha20 or aes256)
        #[arg(short, long, value_enum, default_value = "xchacha20")]
        cipher: CliCipher,
    },

    /// Decrypt a quantum-safe (.qsafe) container back to plaintext
    Decrypt {
        /// Path of encrypted input file (.qsafe)
        #[arg(short, long)]
        input: PathBuf,

        /// Path of decrypted output file
        #[arg(short, long)]
        output: PathBuf,

        /// Path to private key (.key file)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Prompt for passphrase
        #[arg(short, long)]
        password: bool,
    },

    /// Verify integrity and authenticity of a .qsafe container without writing plaintext
    Verify {
        /// Path of encrypted container
        #[arg(short, long)]
        input: PathBuf,

        /// Path to private key (.key file)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Prompt for passphrase
        #[arg(short, long)]
        password: bool,
    },

    /// Inspect header and cryptographic parameters of a .qsafe container
    Info {
        /// Path of encrypted container
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Benchmark quantum-safe cryptographic primitives on this machine
    Bench,
}

fn prompt_password(prompt: &str) -> Result<String, QSafeError> {
    rpassword::prompt_password(prompt)
        .map_err(|e| QSafeError::Crypto(format!("Failed to read password: {}", e)))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out, password } => {
            println!("[*] Generating Post-Quantum Hybrid Keypair (FIPS 203 ML-KEM-768 + X25519)...");
            let start = Instant::now();
            let keypair = HybridKeyPair::generate();
            let elapsed = start.elapsed();

            let pub_path = format!("{}.pub", out);
            let key_path = format!("{}.key", out);

            // Serialize public key: 32B (x25519) + 1184B (ml_kem) = 1216B
            let pub_keys = keypair.public_keys();
            let mut pub_bytes = Vec::with_capacity(32 + ML_KEM_768_PUBLIC_KEY_SIZE);
            pub_bytes.extend_from_slice(pub_keys.x25519.as_bytes());
            pub_bytes.extend_from_slice(&pub_keys.ml_kem_bytes());
            std::fs::write(&pub_path, &pub_bytes)?;

            // Serialize private key: 32B (x25519 secret) + 64B (ml_kem seed) = 96B
            let priv_key_material = keypair.to_private_bytes();

            if password {
                let pw = prompt_password("Enter passphrase to protect private key: ")?;
                let confirm = prompt_password("Confirm passphrase: ")?;
                if pw != confirm {
                    eprintln!("[-] Error: Passphrases do not match.");
                    std::process::exit(1);
                }

                // Derive key using Argon2id
                let mut salt = [0u8; 32];
                getrandom::fill(&mut salt)?;
                let kek = KdfEngine::derive_kek_from_passphrase(
                    pw.as_bytes(),
                    &salt,
                    64 * 1024,
                    3,
                    4,
                )?;

                // Encrypt private key with XChaCha20Poly1305
                use chacha20poly1305::{aead::{AeadInPlace, KeyInit}, XChaCha20Poly1305, XNonce};
                let cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
                    .map_err(|e| QSafeError::Crypto(e.to_string()))?;

                let mut nonce = [0u8; 24];
                getrandom::fill(&mut nonce)?;
                let mut encrypted_priv = priv_key_material.as_bytes().to_vec();
                let xnonce = XNonce::try_from(nonce.as_slice()).unwrap();
                cipher.encrypt_in_place(&xnonce, &[], &mut encrypted_priv)
                    .map_err(|e| QSafeError::Crypto(e.to_string()))?;

                // Format: MAGIC(4B) "QKEY" || Salt(32B) || Nonce(24B) || EncryptedKey(96B + 16B tag = 112B)
                let mut out_file_bytes = Vec::with_capacity(4 + 32 + 24 + 112);
                out_file_bytes.extend_from_slice(b"QKEY");
                out_file_bytes.extend_from_slice(&salt);
                out_file_bytes.extend_from_slice(&nonce);
                out_file_bytes.extend_from_slice(&encrypted_priv);
                std::fs::write(&key_path, out_file_bytes)?;
            } else {
                // Unencrypted private key format: MAGIC "QRAW" || 96 bytes
                let mut out_file_bytes = Vec::with_capacity(4 + 96);
                out_file_bytes.extend_from_slice(b"QRAW");
                out_file_bytes.extend_from_slice(priv_key_material.as_bytes());
                std::fs::write(&key_path, out_file_bytes)?;
            }

            println!("[+] Keypair generated successfully in {:.2?}:", elapsed);
            println!("    Public Key:  {}", pub_path);
            println!("    Private Key: {}", key_path);
        }

        Commands::Encrypt {
            input,
            output,
            key,
            password,
            cipher,
        } => {
            if !input.exists() {
                eprintln!("[-] Error: Input file {:?} does not exist.", input);
                std::process::exit(1);
            }

            // 1. Resolve Recipient Public Key
            let (pubkey, temp_keypair) = if let Some(key_path) = key {
                let bytes = std::fs::read(&key_path)?;
                if bytes.len() != 32 + ML_KEM_768_PUBLIC_KEY_SIZE {
                    eprintln!("[-] Error: Invalid public key file size.");
                    std::process::exit(1);
                }
                let mut x25519_bytes = [0u8; 32];
                x25519_bytes.copy_from_slice(&bytes[..32]);
                let pk = HybridPublicKey::from_bytes(&x25519_bytes, &bytes[32..])?;
                (pk, None)
            } else {
                // Ephemeral keypair for passphrase-only mode
                let kp = HybridKeyPair::generate();
                let pk = kp.public_keys();
                (pk, Some(kp))
            };

            // 2. Resolve Passphrase
            let passphrase = if password || temp_keypair.is_some() {
                let pw = prompt_password("Enter master passphrase for vault: ")?;
                let confirm = prompt_password("Confirm master passphrase: ")?;
                if pw != confirm {
                    eprintln!("[-] Error: Passphrases do not match.");
                    std::process::exit(1);
                }
                Some(pw)
            } else {
                None
            };

            // If we generated an ephemeral keypair for passphrase mode, save it alongside or bundle it
            if let Some(kp) = temp_keypair {
                let key_path = output.with_extension("key");
                let priv_bytes = kp.to_private_bytes();
                let mut raw = Vec::with_capacity(4 + 96);
                raw.extend_from_slice(b"QRAW");
                raw.extend_from_slice(priv_bytes.as_bytes());
                std::fs::write(&key_path, raw)?;
                println!("[*] Generated recovery private key: {:?}", key_path);
            }

            println!("[*] Encrypting {:?} -> {:?} ...", input, output);
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Encrypting STREAM chunks with post-quantum envelope...");

            let start = Instant::now();
            let total_bytes = VaultEngine::encrypt_file(
                &input,
                &output,
                &pubkey,
                passphrase.as_deref().map(|s| s.as_bytes()),
                cipher.into(),
            )?;
            pb.finish_and_clear();

            println!("[+] Successfully encrypted {:?} ({:.2} MB) in {:.2?}",
                output,
                total_bytes as f64 / (1024.0 * 1024.0),
                start.elapsed()
            );
        }

        Commands::Decrypt {
            input,
            output,
            key,
            password,
        } => {
            if !input.exists() {
                eprintln!("[-] Error: Input file {:?} does not exist.", input);
                std::process::exit(1);
            }

            // Find key file if not specified (default to input.with_extension("key") or id_qsafe.key)
            let key_path = if let Some(k) = key {
                k
            } else {
                let candidate1 = input.with_extension("key");
                let candidate2 = PathBuf::from("id_qsafe.key");
                if candidate1.exists() {
                    candidate1
                } else if candidate2.exists() {
                    candidate2
                } else {
                    eprintln!("[-] Error: Private key file not specified and none found.");
                    std::process::exit(1);
                }
            };

            // Load and parse private key
            let key_data = std::fs::read(&key_path)?;
            if key_data.len() < 4 {
                eprintln!("[-] Error: Corrupted private key file.");
                std::process::exit(1);
            }

            let keypair = match &key_data[..4] {
                b"QRAW" => {
                    if key_data.len() != 4 + 96 {
                        eprintln!("[-] Error: Invalid raw private key size.");
                        std::process::exit(1);
                    }
                    let mut x25519_bytes = [0u8; 32];
                    x25519_bytes.copy_from_slice(&key_data[4..36]);
                    let mut ml_kem_seed = [0u8; 64];
                    ml_kem_seed.copy_from_slice(&key_data[36..100]);
                    HybridKeyPair::from_secrets(&x25519_bytes, &ml_kem_seed)
                }
                b"QKEY" => {
                    // Encrypted private key: QKEY(4B) || Salt(32B) || Nonce(24B) || EncryptedKey(112B)
                    if key_data.len() != 4 + 32 + 24 + 112 {
                        eprintln!("[-] Error: Invalid encrypted private key size.");
                        std::process::exit(1);
                    }
                    let pw = prompt_password("Enter passphrase to unlock private key: ")?;
                    let salt: [u8; 32] = key_data[4..36].try_into().unwrap();
                    let nonce: [u8; 24] = key_data[36..60].try_into().unwrap();
                    let kek = KdfEngine::derive_kek_from_passphrase(
                        pw.as_bytes(),
                        &salt,
                        64 * 1024,
                        3,
                        4,
                    )?;

                    use chacha20poly1305::{aead::{AeadInPlace, KeyInit}, XChaCha20Poly1305, XNonce};
                    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
                        .map_err(|e| QSafeError::Crypto(e.to_string()))?;

                    let mut priv_buf = key_data[60..].to_vec();
                    let xnonce = XNonce::try_from(nonce.as_slice()).unwrap();
                    cipher.decrypt_in_place(&xnonce, &[], &mut priv_buf)
                        .map_err(|_| QSafeError::AuthenticationFailed)?;

                    let mut x25519_bytes = [0u8; 32];
                    x25519_bytes.copy_from_slice(&priv_buf[..32]);
                    let mut ml_kem_seed = [0u8; 64];
                    ml_kem_seed.copy_from_slice(&priv_buf[32..96]);
                    HybridKeyPair::from_secrets(&x25519_bytes, &ml_kem_seed)
                }
                _ => {
                    eprintln!("[-] Error: Unknown key file format.");
                    std::process::exit(1);
                }
            };

            let passphrase = if password {
                Some(prompt_password("Enter vault master passphrase: ")?)
            } else {
                None
            };

            println!("[*] Decrypting {:?} -> {:?} ...", input, output);
            let start = Instant::now();
            let total_bytes = VaultEngine::decrypt_file(
                &input,
                &output,
                &keypair,
                passphrase.as_deref().map(|s| s.as_bytes()),
            )?;

            println!("[+] Successfully decrypted {:?} ({:.2} MB) in {:.2?}",
                output,
                total_bytes as f64 / (1024.0 * 1024.0),
                start.elapsed()
            );
        }

        Commands::Verify {
            input,
            key,
            password,
        } => {
            if !input.exists() {
                eprintln!("[-] Error: Input file {:?} does not exist.", input);
                std::process::exit(1);
            }

            let key_path = if let Some(k) = key {
                k
            } else {
                let candidate1 = input.with_extension("key");
                let candidate2 = PathBuf::from("id_qsafe.key");
                if candidate1.exists() {
                    candidate1
                } else if candidate2.exists() {
                    candidate2
                } else {
                    eprintln!("[-] Error: Private key file not found.");
                    std::process::exit(1);
                }
            };

            let key_data = std::fs::read(&key_path)?;
            let keypair = match &key_data[..4] {
                b"QRAW" => {
                    let mut x25519_bytes = [0u8; 32];
                    x25519_bytes.copy_from_slice(&key_data[4..36]);
                    let mut ml_kem_seed = [0u8; 64];
                    ml_kem_seed.copy_from_slice(&key_data[36..100]);
                    HybridKeyPair::from_secrets(&x25519_bytes, &ml_kem_seed)
                }
                b"QKEY" => {
                    let pw = prompt_password("Enter passphrase to unlock private key: ")?;
                    let salt: [u8; 32] = key_data[4..36].try_into().unwrap();
                    let nonce: [u8; 24] = key_data[36..60].try_into().unwrap();
                    let kek = KdfEngine::derive_kek_from_passphrase(
                        pw.as_bytes(),
                        &salt,
                        64 * 1024,
                        3,
                        4,
                    )?;
                    use chacha20poly1305::{aead::{AeadInPlace, KeyInit}, XChaCha20Poly1305, XNonce};
                    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
                        .map_err(|e| QSafeError::Crypto(e.to_string()))?;
                    let mut priv_buf = key_data[60..].to_vec();
                    let xnonce = XNonce::try_from(nonce.as_slice()).unwrap();
                    cipher.decrypt_in_place(&xnonce, &[], &mut priv_buf)
                        .map_err(|_| QSafeError::AuthenticationFailed)?;

                    let mut x25519_bytes = [0u8; 32];
                    x25519_bytes.copy_from_slice(&priv_buf[..32]);
                    let mut ml_kem_seed = [0u8; 64];
                    ml_kem_seed.copy_from_slice(&priv_buf[32..96]);
                    HybridKeyPair::from_secrets(&x25519_bytes, &ml_kem_seed)
                }
                _ => {
                    eprintln!("[-] Error: Unknown key file format.");
                    std::process::exit(1);
                }
            };

            let passphrase = if password {
                Some(prompt_password("Enter vault master passphrase: ")?)
            } else {
                None
            };

            println!("[*] Verifying cryptographic integrity of {:?} ...", input);
            let start = Instant::now();
            let total_bytes = VaultEngine::verify_file(
                &input,
                &keypair,
                passphrase.as_deref().map(|s| s.as_bytes()),
            )?;

            println!("[+] INTEGRITY VERIFIED: All STREAM chunks and header HMAC tags matched!");
            println!("    Plaintext Payload: {:.2} MB", total_bytes as f64 / (1024.0 * 1024.0));
            println!("    Verification Time: {:.2?}", start.elapsed());
        }

        Commands::Info { input } => {
            let in_file = std::fs::File::open(&input)?;
            let mut reader = std::io::BufReader::new(in_file);
            let (header, tag, _) = VaultHeader::read_metadata(&mut reader)?;

            println!("=======================================================");
            println!("        QSafe Container Cryptographic Metadata        ");
            println!("=======================================================");
            println!("Version:               0x{:02x}", header.version);
            println!("Cipher Suite:          {:?}", header.cipher_suite);
            println!("Argon2id Memory Cost:  {} KB ({} MB)", header.m_cost, header.m_cost / 1024);
            println!("Argon2id Time Cost:    {} iterations", header.t_cost);
            println!("Argon2id Parallelism:  {} lanes", header.p_cost);
            println!("KDF Salt (32B):        {}", hex_encode(&header.salt));
            println!("Base Nonce (16B):      {}", hex_encode(&header.base_nonce));
            println!("Ephemeral X25519:      {}", hex_encode(&header.ephemeral_x25519_public));
            println!("ML-KEM Ciphertext:     {} bytes (FIPS 203)", header.ml_kem_ciphertext.len());
            println!("Encrypted DEK:         48 bytes (32B Key + 16B Poly1305 Tag)");
            println!("Header Auth Tag:       {}", hex_encode(&tag));
            println!("=======================================================");
        }

        Commands::Bench => {
            println!("=======================================================");
            println!("         QSafe Post-Quantum Cryptographic Benchmark     ");
            println!("=======================================================");

            // 1. ML-KEM-768 Benchmark
            print!("[*] Benchmarking FIPS 203 ML-KEM-768 key generation... ");
            let iters = 200;
            let start = Instant::now();
            for _ in 0..iters {
                let _ = HybridKeyPair::generate();
            }
            let total_time = start.elapsed();
            let per_op = total_time / iters;
            println!("{:.2?} / op ({:.0} ops/sec)", per_op, iters as f64 / total_time.as_secs_f64());

            // 2. Encapsulation / Decapsulation Benchmark
            let kp = HybridKeyPair::generate();
            let pk = kp.public_keys();
            print!("[*] Benchmarking Hybrid Encapsulation (ML-KEM + X25519)... ");
            let start = Instant::now();
            for _ in 0..iters {
                let _ = qsafe::crypto::HybridKemEngine::encapsulate(&pk).unwrap();
            }
            let total_time = start.elapsed();
            println!("{:.2?} / op", total_time / iters);

            // 3. Argon2id Benchmark
            print!("[*] Benchmarking Argon2id (64MB, t=3, p=4)... ");
            let salt = [0x42u8; 32];
            let start = Instant::now();
            let _ = KdfEngine::derive_kek_from_passphrase(b"benchmark_password", &salt, 64 * 1024, 3, 4).unwrap();
            println!("{:.2?}", start.elapsed());

            // 4. STREAM AEAD Throughput Benchmark
            print!("[*] Benchmarking STREAM XChaCha20-Poly1305 throughput (16 MB)... ");
            let data_16mb = vec![0x33u8; 16 * 1024 * 1024];
            let key = [0x55u8; 32];
            let nonce = [0x77u8; 16];
            let mut out = Vec::new();
            let mut reader = std::io::Cursor::new(&data_16mb);
            let start = Instant::now();
            let _ = qsafe::crypto::StreamEngine::encrypt_stream(
                &mut reader,
                &mut out,
                &key,
                &nonce,
                CipherSuite::XChaCha20Poly1305,
            ).unwrap();
            let elapsed = start.elapsed();
            let mb_per_sec = 16.0 / elapsed.as_secs_f64();
            println!("{:.2?} ({:.2} MB/s)", elapsed, mb_per_sec);

            println!("=======================================================");
            println!("[+] Benchmark completed successfully.");
        }
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}
