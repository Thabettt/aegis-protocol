# Implementation Plan

## Zero-Trust Secure File Sharing Protocol

**Project Codename:** Aegis  
**Author:** Abdulaziz  
**Version:** 1.1  
**Date:** July 26, 2026
**Revision:** v1.1 — Scope refined to desktop and web clients only (mobile platforms removed)  

---

## Overview

This implementation plan provides a detailed roadmap for building the zero-trust secure file sharing system. It is organized into eight phases, each with specific deliverables, technologies, and acceptance criteria.

### Guiding Principles

1. **Cryptography before features**: Crypto layer must be correct before anything else
2. **Security before convenience**: Never compromise invariants for UX
3. **Test everything**: Every crypto operation must be test-covered
4. **Audit-ready code**: Write as if a security auditor reads every line
5. **Minimal complexity**: Each added component must justify its existence
6. **Minimal attack surface**: Every platform target increases the surface area an attacker can probe; only ship what can be fully audited and hardened

---

## Technology Stack Summary

### Core Technologies

| Component             | Technology         | Version               |
| --------------------- | ------------------ | --------------------- |
| **Core Language**     | Rust               | Latest stable (1.75+) |
| **Desktop Framework** | Tauri              | 2.0+                  |
| **Server Runtime**    | Rust (Tokio async) | Latest stable         |
| **Build System**      | Cargo, npm         | Latest                |

### Why No Native Mobile Clients

Native mobile applications (Android via Kotlin + Rust JNI, iOS via Swift + Rust FFI) have been deliberately excluded from scope. This is a security-driven decision:

| Concern                                | Impact                                                                                                                                                                                                                                                                                                   |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FFI bridge attack surface**          | Every JNI/FFI boundary is a potential source of use-after-free, double-free, or type confusion — the exact vulnerability class Rust is chosen to eliminate. Two additional FFI layers (Android JNI, iOS C-interop) roughly triple the number of unsafe boundary crossings that must be audited.          |
| **Platform-controlled key storage**    | Android Keystore and iOS Secure Enclave are opaque, vendor-controlled subsystems. Documented vulnerabilities in hardware TEEs (Samsung TrustZone CVEs, Qualcomm TEE escapes) mean relying on them for root-of-trust moves security guarantees outside our auditable codebase.                            |
| **OS-level data leakage**              | Mobile OSes routinely snapshot app state for task switchers, back up app data to cloud services (iCloud, Google Backup), index file contents for system search (Spotlight), and log IPC calls. Preventing these leaks requires per-OS workarounds that are fragile, version-dependent, and unverifiable. |
| **App store as a trusted third party** | Distribution through Apple App Store and Google Play introduces gatekeepers who can inject code (cf. XcodeGhost), demand metadata disclosure, and remotely revoke or modify applications — all of which conflict with zero-trust principles.                                                             |
| **Audit cost**                         | A security audit of the Rust core + Tauri desktop app is a tractable, well-bounded problem. Adding two native mobile codebases with platform-specific secure storage, biometric APIs, and push notification integrations roughly triples the audit surface without proportional security benefit.        |
| **Engineering overhead**               | Maintaining native mobile apps requires dedicated platform expertise, separate CI/CD pipelines, platform-specific testing matrices, and ongoing compliance with frequently changing app store policies. This effort is better invested in hardening the cryptographic core.                              |

Desktop users are the primary audience for a tool built around secure file sharing with cryptographic identity management. The Tauri desktop app delivers full functionality across Windows, macOS, and Linux from a single auditable codebase. A deliberately limited web client may serve as a companion for receiving shared files.

### Cryptographic Libraries

| Purpose            | Library          | Crate                |
| ------------------ | ---------------- | -------------------- |
| AEAD Encryption    | chacha20poly1305 | `chacha20poly1305`   |
| Key Exchange       | x25519-dalek     | `x25519-dalek`       |
| Digital Signatures | ed25519-dalek    | `ed25519-dalek`      |
| Hashing            | blake3           | `blake3`             |
| KDF                | hkdf             | `hkdf`               |
| Secure Random      | rand             | `rand` + `getrandom` |
| Noise Protocol     | snow             | `snow`               |
| Password Hashing   | argon2           | `argon2`             |

### Server Technologies

| Component      | Technology                             |
| -------------- | -------------------------------------- |
| HTTP Framework | Axum                                   |
| Async Runtime  | Tokio                                  |
| Object Storage | S3-compatible (MinIO dev, AWS S3 prod) |
| Rate Limiting  | In-memory (tower-governor)             |
| Deployment     | Docker, Kubernetes                     |

### Client Technologies

| Platform | Core                | UI               |
| -------- | ------------------- | ---------------- |
| Desktop  | Rust (Tauri)        | TypeScript/React |
| Web      | Rust/WASM (limited) | TypeScript/React |

---

## Phase 0: Foundation

### Objective

Establish project structure, development environment, and documentation framework.

### 0.1 Repository Setup

```bash
# Create monorepo structure
vault/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── security-audit.yml
│   │   └── release.yml
│   ├── CODEOWNERS
│   └── SECURITY.md
├── crates/
│   ├── vault-crypto/           # Core cryptography
│   ├── vault-protocol/         # Wire protocol
│   ├── vault-client/           # Shared client logic
│   └── vault-server/           # Server binary
├── apps/
│   ├── desktop/                # Tauri app
│   └── web/                    # Web app (limited)
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   ├── api/
│   └── audit/
├── tests/
│   ├── integration/
│   ├── e2e/
│   └── fuzz/
├── Cargo.toml                  # Workspace manifest
├── README.md
├── LICENSE
└── CHANGELOG.md
```

### 0.2 Development Environment

```bash
# Required tools
rustup default stable
rustup component add clippy rustfmt
cargo install cargo-audit cargo-deny cargo-expand cargo-fuzz

# Tauri requirements
cargo install tauri-cli

# Node.js for frontend
nvm install 20
npm install -g pnpm
```

### 0.3 Documentation Framework

Create initial documents:

| Document            | Location                      | Purpose                   |
| ------------------- | ----------------------------- | ------------------------- |
| Threat Model        | `docs/threat-model/`          | Formal threat analysis    |
| Security Invariants | `docs/security/INVARIANTS.md` | Non-negotiable rules      |
| API Specification   | `docs/api/`                   | Protocol documentation    |
| Audit Log           | `docs/audit/`                 | Security decision history |

### 0.4 Threat Model Document

```markdown
# docs/threat-model/THREAT_MODEL.md

## Protected Against

1. Server-side data breaches
2. Insider/administrator attacks
3. Government data requests
4. Man-in-the-middle attacks
5. Mass surveillance

## NOT Protected Against (Explicit Non-Goals)

1. Compromised endpoints (malware on user device)
2. Malicious recipients (intentional disclosure)
3. Physical coercion of users
4. Global passive adversary with timing analysis

## Security Invariants

1. Server NEVER possesses decryption keys
2. All encryption happens client-side
3. Every file has unique encryption key
4. Metadata must be encrypted or meaningless
5. Identity = public key only
```

### 0.5 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - run: cargo clippy -- -D warnings

  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cd crates/vault-crypto && cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=60
```

### Phase 0 Deliverables

- [ ] Repository structure created
- [ ] Development environment documented
- [ ] CI/CD pipeline operational
- [ ] Threat model document complete
- [ ] Security invariants documented
- [ ] Code of conduct and security policy

---

## Phase 1: Cryptographic Core

### Objective

Implement the core cryptography module with comprehensive testing.

### 1.1 Crate Structure

```rust
// crates/vault-crypto/Cargo.toml
[package]
name = "vault-crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
# AEAD
chacha20poly1305 = { version = "0.10", features = ["std"] }

# Key exchange
x25519-dalek = { version = "2", features = ["static_secrets"] }

# Signatures
ed25519-dalek = { version = "2", features = ["rand_core"] }

# Hashing
blake3 = "1.5"

# KDF
hkdf = "0.12"
sha2 = "0.10"  # For HKDF-SHA256 compatibility

# Random
rand = "0.8"
getrandom = { version = "0.2", features = ["js"] }  # For WASM

# Serialization
serde = { version = "1", features = ["derive"] }

# Secure memory
zeroize = { version = "1", features = ["derive"] }

[dev-dependencies]
criterion = "0.5"
proptest = "1"
```

### 1.2 Core Types

```rust
// crates/vault-crypto/src/types.rs

use zeroize::Zeroize;

/// 256-bit symmetric key for file encryption
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct FileKey([u8; 32]);

impl FileKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 identity keypair
pub struct Identity {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// X25519 ephemeral keypair for key exchange
pub struct EphemeralKeypair {
    pub secret: x25519_dalek::StaticSecret,
    pub public: x25519_dalek::PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }
}
```

### 1.3 AEAD Operations

```rust
// crates/vault-crypto/src/aead.rs

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use crate::types::FileKey;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed - authentication tag mismatch")]
    DecryptionFailed,
    #[error("Invalid nonce length")]
    InvalidNonce,
}

/// Encrypt data with XChaCha20-Poly1305
pub fn encrypt(
    key: &FileKey,
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| AeadError::EncryptionFailed)
}

/// Decrypt data with XChaCha20-Poly1305
pub fn decrypt(
    key: &FileKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| AeadError::DecryptionFailed)
}

/// Generate a random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
    nonce
}
```

### 1.4 Key Exchange

```rust
// crates/vault-crypto/src/kex.rs

use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::types::{EphemeralKeypair, FileKey};

pub const SHARED_SECRET_SIZE: usize = 32;

/// Perform X25519 key exchange and derive file key
pub fn derive_file_key(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    salt: &[u8],
    context: &[u8],
) -> FileKey {
    // X25519 shared secret
    let shared_secret = our_secret.diffie_hellman(their_public);

    // HKDF-SHA256 extract and expand
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());

    let mut file_key = [0u8; 32];
    hk.expand(context, &mut file_key)
        .expect("HKDF expand failed");

    FileKey::from_bytes(file_key)
}

/// Complete key exchange: generate ephemeral keypair and derive shared key
pub fn key_exchange_sender(
    recipient_public: &PublicKey,
    file_id: &[u8],
) -> (EphemeralKeypair, FileKey, [u8; 32]) {
    let ephemeral = EphemeralKeypair::generate();
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).expect("Failed to generate salt");

    let context = [b"vault-file-encryption-v1", file_id].concat();
    let file_key = derive_file_key(&ephemeral.secret, recipient_public, &salt, &context);

    (ephemeral, file_key, salt)
}
```

### 1.5 Digital Signatures

```rust
// crates/vault-crypto/src/sign.rs

use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};
use crate::types::Identity;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid signature format")]
    InvalidFormat,
}

/// Sign a message with Ed25519
pub fn sign(identity: &Identity, message: &[u8]) -> Signature {
    identity.signing_key.sign(message)
}

/// Verify an Ed25519 signature
pub fn verify(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    public_key
        .verify(message, signature)
        .map_err(|_| SignatureError::VerificationFailed)
}
```

### 1.6 File Encryption Package

```rust
// crates/vault-crypto/src/file.rs

use serde::{Serialize, Deserialize};
use crate::{aead, kex, sign, types::*};

/// Complete encrypted file package
#[derive(Serialize, Deserialize)]
pub struct EncryptedPackage {
    /// Version for forward compatibility
    pub version: u8,
    /// Sender's ephemeral public key (32 bytes)
    pub ephemeral_public: [u8; 32],
    /// Salt for key derivation (32 bytes)
    pub salt: [u8; 32],
    /// Nonce for AEAD (24 bytes)
    pub nonce: [u8; 24],
    /// Encrypted file content
    pub ciphertext: Vec<u8>,
    /// Sender's signature over the package
    pub signature: [u8; 64],
}

impl EncryptedPackage {
    /// Encrypt a file for a recipient
    pub fn create(
        sender: &Identity,
        recipient_public: &x25519_dalek::PublicKey,
        file_id: &[u8],
        plaintext: &[u8],
        metadata: &[u8], // AAD: encrypted separately but authenticated
    ) -> Result<Self, CryptoError> {
        // Generate ephemeral keypair and derive file key
        let (ephemeral, file_key, salt) = kex::key_exchange_sender(recipient_public, file_id);

        // Generate nonce
        let nonce = aead::generate_nonce();

        // Encrypt
        let ciphertext = aead::encrypt(&file_key, &nonce, plaintext, metadata)?;

        // Create unsigned package
        let unsigned = UnsignedPackage {
            version: 1,
            ephemeral_public: ephemeral.public.to_bytes(),
            salt,
            nonce,
            ciphertext,
        };

        // Sign the package
        let to_sign = unsigned.to_bytes();
        let signature = sign::sign(sender, &to_sign);

        Ok(Self {
            version: unsigned.version,
            ephemeral_public: unsigned.ephemeral_public,
            salt: unsigned.salt,
            nonce: unsigned.nonce,
            ciphertext: unsigned.ciphertext,
            signature: signature.to_bytes(),
        })
    }

    /// Decrypt a package
    pub fn decrypt(
        &self,
        recipient_secret: &x25519_dalek::StaticSecret,
        sender_public: &ed25519_dalek::VerifyingKey,
        file_id: &[u8],
        expected_aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Verify signature first
        let unsigned = UnsignedPackage {
            version: self.version,
            ephemeral_public: self.ephemeral_public,
            salt: self.salt,
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        };
        let to_verify = unsigned.to_bytes();
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        sign::verify(sender_public, &to_verify, &signature)?;

        // Derive key
        let sender_ephemeral = x25519_dalek::PublicKey::from(self.ephemeral_public);
        let context = [b"vault-file-encryption-v1", file_id].concat();
        let file_key = kex::derive_file_key(recipient_secret, &sender_ephemeral, &self.salt, &context);

        // Decrypt
        aead::decrypt(&file_key, &self.nonce, &self.ciphertext, expected_aad)
    }
}
```

### 1.7 Comprehensive Tests

```rust
// crates/vault-crypto/src/tests.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = Identity::generate();
        let recipient = EphemeralKeypair::generate();
        let file_id = b"test-file-001";
        let plaintext = b"Hello, secure world!";
        let metadata = b"filename: test.txt";

        let package = EncryptedPackage::create(
            &sender,
            &recipient.public,
            file_id,
            plaintext,
            metadata,
        ).unwrap();

        let decrypted = package.decrypt(
            &recipient.secret,
            &sender.verifying_key,
            file_id,
            metadata,
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let sender = Identity::generate();
        let recipient = EphemeralKeypair::generate();
        let file_id = b"test-file-002";
        let plaintext = b"Secret data";
        let metadata = b"";

        let mut package = EncryptedPackage::create(
            &sender,
            &recipient.public,
            file_id,
            plaintext,
            metadata,
        ).unwrap();

        // Tamper with ciphertext
        package.ciphertext[0] ^= 0xFF;

        let result = package.decrypt(
            &recipient.secret,
            &sender.verifying_key,
            file_id,
            metadata,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_sender_signature_fails() {
        let sender = Identity::generate();
        let imposter = Identity::generate();
        let recipient = EphemeralKeypair::generate();
        let file_id = b"test-file-003";
        let plaintext = b"Authenticated data";
        let metadata = b"";

        let package = EncryptedPackage::create(
            &sender,
            &recipient.public,
            file_id,
            plaintext,
            metadata,
        ).unwrap();

        // Try to verify with wrong public key
        let result = package.decrypt(
            &recipient.secret,
            &imposter.verifying_key, // Wrong key
            file_id,
            metadata,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unique_keys_per_file() {
        let sender = Identity::generate();
        let recipient = EphemeralKeypair::generate();

        let file1 = b"file-001";
        let file2 = b"file-002";
        let plaintext = b"Same content";

        let package1 = EncryptedPackage::create(
            &sender, &recipient.public, file1, plaintext, b"",
        ).unwrap();

        let package2 = EncryptedPackage::create(
            &sender, &recipient.public, file2, plaintext, b"",
        ).unwrap();

        // Different ephemeral keys
        assert_ne!(package1.ephemeral_public, package2.ephemeral_public);
        // Different salts
        assert_ne!(package1.salt, package2.salt);
        // Different nonces
        assert_ne!(package1.nonce, package2.nonce);
        // Different ciphertext (even for same plaintext)
        assert_ne!(package1.ciphertext, package2.ciphertext);
    }
}
```

### 1.8 Fuzzing

```rust
// crates/vault-crypto/fuzz/fuzz_targets/fuzz_decrypt.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_crypto::*;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse and decrypt arbitrary data
    // Should never panic, only return errors
    if let Ok(package) = EncryptedPackage::deserialize(data) {
        let recipient = EphemeralKeypair::generate();
        let sender = Identity::generate();
        let _ = package.decrypt(
            &recipient.secret,
            &sender.verifying_key,
            b"fuzz-test",
            b"",
        );
    }
});
```

### Phase 1 Deliverables

- [ ] `vault-crypto` crate with all primitives
- [ ] XChaCha20-Poly1305 AEAD implementation
- [ ] X25519 key exchange
- [ ] Ed25519 signatures
- [ ] BLAKE3 hashing
- [ ] HKDF key derivation
- [ ] EncryptedPackage structure
- [ ] 100% test coverage for crypto operations
- [ ] Fuzz testing setup
- [ ] Performance benchmarks

---

## Phase 2: Identity System

### Objective

Implement the cryptographic identity system without personal identifiable information.

### 2.1 Identity Storage

```rust
// crates/vault-client/src/identity.rs

use argon2::{Argon2, password_hash::PasswordHasher};
use vault_crypto::types::Identity;

/// Encrypted identity storage
pub struct IdentityStore {
    /// Path to encrypted identity file
    path: PathBuf,
}

impl IdentityStore {
    /// Create or load identity with passphrase protection
    pub fn unlock(&self, passphrase: &str) -> Result<Identity, IdentityError> {
        let encrypted = std::fs::read(&self.path)?;

        // Derive key from passphrase using Argon2id
        let salt = &encrypted[0..32];
        let argon2 = Argon2::default();
        let key = argon2.hash_password(
            passphrase.as_bytes(),
            salt,
        )?;

        // Decrypt identity
        let nonce = &encrypted[32..56];
        let ciphertext = &encrypted[56..];

        let identity_bytes = aead::decrypt(
            &FileKey::from_slice(&key.hash.unwrap().as_bytes()[0..32]),
            nonce.try_into()?,
            ciphertext,
            b"identity-encryption",
        )?;

        Identity::from_bytes(&identity_bytes)
    }

    /// Save identity encrypted with passphrase
    pub fn save(&self, identity: &Identity, passphrase: &str) -> Result<(), IdentityError> {
        // Generate salt
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)?;

        // Derive key from passphrase
        let argon2 = Argon2::default();
        let key = argon2.hash_password(passphrase.as_bytes(), &salt)?;

        // Encrypt identity
        let nonce = aead::generate_nonce();
        let ciphertext = aead::encrypt(
            &FileKey::from_slice(&key.hash.unwrap().as_bytes()[0..32]),
            &nonce,
            &identity.to_bytes(),
            b"identity-encryption",
        )?;

        // Write: salt || nonce || ciphertext
        let mut output = Vec::with_capacity(32 + 24 + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        std::fs::write(&self.path, output)?;
        Ok(())
    }
}
```

### 2.2 Recovery Phrase (BIP-39 Compatible)

```rust
// crates/vault-client/src/recovery.rs

use bip39::{Mnemonic, Language};

/// Generate recovery phrase from identity seed
pub fn generate_recovery_phrase(identity: &Identity) -> String {
    let entropy = identity.signing_key.to_bytes();
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Valid entropy length");
    mnemonic.into_phrase()
}

/// Recover identity from recovery phrase
pub fn recover_from_phrase(phrase: &str) -> Result<Identity, RecoveryError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)?;
    let entropy = mnemonic.to_entropy();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        entropy.try_into().map_err(|_| RecoveryError::InvalidPhrase)?
    );

    Ok(Identity {
        signing_key,
        verifying_key: signing_key.verifying_key(),
    })
}
```

### Phase 2 Deliverables

- [ ] Identity generation and storage
- [ ] Passphrase-based encryption with Argon2
- [ ] Recovery phrase generation/recovery
- [ ] Key export/import

---

## Phase 3: Server Infrastructure

### Objective

Build the deliberately "dumb" server that stores only encrypted blobs.

### 3.1 Server Structure

```rust
// crates/vault-server/src/main.rs

use axum::{
    routing::{get, post, delete},
    Router,
};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    // Configure server
    let config = Config::from_env();

    // Initialize storage
    let storage = S3Storage::new(&config.s3_endpoint, &config.s3_bucket).await;

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/upload", post(upload_blob))
        .route("/download/:blob_id", get(download_blob))
        .route("/delete/:blob_id", delete(delete_blob))
        .layer(CorsLayer::permissive())
        .with_state(AppState { storage });

    // Run server
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 3.2 Blob Storage

```rust
// crates/vault-server/src/storage.rs

use aws_sdk_s3::Client;
use uuid::Uuid;

pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    /// Store an encrypted blob
    /// Returns randomly generated blob ID
    pub async fn store(&self, data: &[u8], ttl_hours: u32) -> Result<String, StorageError> {
        let blob_id = Uuid::new_v4().to_string();

        // Calculate expiration
        let expires = chrono::Utc::now() + chrono::Duration::hours(ttl_hours as i64);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&blob_id)
            .body(data.to_vec().into())
            .expires(expires.into())
            .send()
            .await?;

        Ok(blob_id)
    }

    /// Retrieve a blob
    pub async fn get(&self, blob_id: &str) -> Result<Vec<u8>, StorageError> {
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(blob_id)
            .send()
            .await?;

        let data = response.body.collect().await?.into_bytes().to_vec();
        Ok(data)
    }

    /// Delete a blob
    pub async fn delete(&self, blob_id: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(blob_id)
            .send()
            .await?;

        Ok(())
    }
}
```

### 3.3 Rate Limiting

```rust
// crates/vault-server/src/rate_limit.rs

use tower_governor::{GovernorLayer, GovernorConfigBuilder};

pub fn rate_limit_layer() -> GovernorLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(50)
        .finish()
        .unwrap();

    GovernorLayer::new(config)
}
```

### 3.4 Minimal Logging

```rust
// crates/vault-server/src/logging.rs

/// Server logs ONLY operational data
/// NO user identifiers, NO file content, NO metadata
pub fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .json()
        .init();
}

/// What we log (operational)
/// - Request type (upload/download)
/// - Blob ID (opaque identifier)
/// - Response time
/// - Error types

/// What we DO NOT log
/// - IP addresses (privacy)
/// - User tokens (security)
/// - File sizes (metadata)
/// - Timestamps with user precision
```

### Phase 3 Deliverables

- [ ] Axum server with minimal endpoints
- [ ] S3-compatible blob storage integration
- [ ] Rate limiting
- [ ] TTL-based blob expiration
- [ ] Minimal operational logging
- [ ] Docker container
- [ ] Kubernetes deployment manifests

---

## Phase 4: Desktop Client Application

### Objective

Build the Tauri desktop client with the crypto core.

### 4.1 Desktop (Tauri)

```bash
# Initialize Tauri project
cd apps/desktop
pnpm create tauri-app
```

```rust
// apps/desktop/src-tauri/src/main.rs

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use vault_client::VaultClient;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Initialize vault client
            let client = VaultClient::new()?;
            app.manage(client);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            upload_file,
            download_file,
            generate_share_link,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn encrypt_file(
    client: tauri::State<'_, VaultClient>,
    path: String,
    recipient_public_key: String,
) -> Result<EncryptedPackage, String> {
    client.encrypt_file(&path, &recipient_public_key)
        .await
        .map_err(|e| e.to_string())
}
```

### 4.2 Frontend (React/TypeScript)

```typescript
// apps/desktop/src/lib/crypto.ts

import { invoke } from "@tauri-apps/api/tauri";

interface EncryptedPackage {
  version: number;
  ephemeralPublic: string; // base64
  salt: string;
  nonce: string;
  ciphertext: string;
  signature: string;
}

export async function encryptFile(
  filePath: string,
  recipientPublicKey: string,
): Promise<EncryptedPackage> {
  return await invoke("encrypt_file", {
    path: filePath,
    recipientPublicKey,
  });
}

export async function decryptFile(
  package: EncryptedPackage,
  outputPath: string,
): Promise<void> {
  return await invoke("decrypt_file", {
    package,
    outputPath,
  });
}
```

### Phase 4 Deliverables

- [ ] Tauri desktop app structure
- [ ] React frontend with TypeScript
- [ ] Cross-platform file picker
- [ ] Secure storage integration (OS Keychain / Credential Manager)

---

## Phase 5: Sharing Mechanisms

### Objective

Implement split-key sharing and link generation.

### 5.1 Share Link Protocol

```rust
// crates/vault-protocol/src/share.rs

/// Share link contains ONLY the blob location
/// Key is delivered separately
#[derive(Serialize, Deserialize)]
pub struct ShareLink {
    /// Version for forward compatibility
    pub version: u8,
    /// Server URL
    pub server: String,
    /// Blob identifier
    pub blob_id: String,
    /// Optional: encrypted metadata (filename, type)
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl ShareLink {
    pub fn to_url(&self) -> String {
        let encoded = base64url::encode(&serde_json::to_vec(self).unwrap());
        format!("vault://share/{}", encoded)
    }

    pub fn from_url(url: &str) -> Result<Self, ParseError> {
        let encoded = url.strip_prefix("vault://share/")?;
        let bytes = base64url::decode(encoded)?;
        serde_json::from_slice(&bytes).map_err(Into::into)
    }
}

/// Decryption key delivered via separate channel
#[derive(Serialize, Deserialize)]
pub struct ShareKey {
    /// Ephemeral public key from encryption
    pub ephemeral_public: [u8; 32],
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// File ID for AAD
    pub file_id: Vec<u8>,
}

impl ShareKey {
    pub fn to_string(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap();
        format!("vault:key:{}", base64url::encode(&bytes))
    }
}
```

### 5.2 Key Delivery Options

```typescript
// apps/desktop/src/components/ShareDialog.tsx

import QRCode from 'qrcode.react';

interface ShareDialogProps {
  shareLink: string;
  shareKey: string;
}

export function ShareDialog({ shareLink, shareKey }: ShareDialogProps) {
  const [deliveryMethod, setDeliveryMethod] = useState<'qr' | 'copy'>('qr');

  return (
    <div className="share-dialog">
      <h2>Share File</h2>

      <section className="share-link">
        <h3>Step 1: Send Link</h3>
        <p>Share this link via any channel:</p>
        <CopyableText value={shareLink} />
      </section>

      <section className="share-key">
        <h3>Step 2: Deliver Key Separately</h3>
        <p className="warning">
          ⚠️ Do NOT send the key through the same channel as the link
        </p>

        <Tabs value={deliveryMethod} onChange={setDeliveryMethod}>
          <Tab value="qr">QR Code</Tab>
          <Tab value="copy">Copy</Tab>
        </Tabs>

        {deliveryMethod === 'qr' && (
          <QRCode value={shareKey} size={256} />
        )}

        {deliveryMethod === 'copy' && (
          <CopyableText value={shareKey} />
        )}
      </section>
    </div>
  );
}
```

### Phase 5 Deliverables

- [ ] Share link generation
- [ ] Split-key architecture
- [ ] QR code key delivery
- [ ] Link expiration
- [ ] Download tracking

---

## Phase 6: P2P System

### Objective

Implement optional peer-to-peer transfers using Noise Protocol.

### 6.1 Noise Protocol Integration

```rust
// crates/vault-protocol/src/p2p.rs

use snow::{Builder, HandshakeState, TransportState};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

pub struct P2PSession {
    transport: TransportState,
}

impl P2PSession {
    /// Initiate P2P connection (as initiator)
    pub async fn connect(
        their_static_public: &[u8; 32],
        stream: &mut TcpStream,
    ) -> Result<Self, P2PError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;

        let mut handshake = builder
            .local_private_key(&keypair.private)
            .remote_public_key(their_static_public)
            .build_initiator()?;

        // Perform XX handshake
        let transport = perform_handshake(&mut handshake, stream).await?;

        Ok(Self { transport })
    }

    /// Accept P2P connection (as responder)
    pub async fn accept(
        our_static: &Keypair,
        stream: &mut TcpStream,
    ) -> Result<Self, P2PError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);

        let mut handshake = builder
            .local_private_key(&our_static.private)
            .build_responder()?;

        let transport = perform_handshake(&mut handshake, stream).await?;

        Ok(Self { transport })
    }

    /// Send encrypted data
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, P2PError> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // Room for auth tag
        let len = self.transport.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Receive and decrypt data
    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, P2PError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}
```

### Phase 6 Deliverables

- [ ] Noise Protocol XX pattern implementation
- [ ] NAT traversal assistance
- [ ] P2P file transfer
- [ ] Session key ratcheting
- [ ] Fallback to server if P2P fails

---

## Phase 7: Vault and Hardening

### Objective

Implement secure local vault and system hardening.

### 7.1 Secure Vault

```rust
// crates/vault-client/src/vault.rs

use std::io::{Read, Write};
use std::path::PathBuf;

/// Secure local storage for decrypted files
pub struct SecureVault {
    /// Path to vault directory
    path: PathBuf,
    /// Vault encryption key (derived from passphrase)
    key: VaultKey,
    /// Auto-lock timeout
    lock_timeout: Duration,
    /// Last activity timestamp
    last_activity: Instant,
}

impl SecureVault {
    /// Store a file in the vault (encrypted at rest)
    pub fn store(&self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        let nonce = aead::generate_nonce();
        let ciphertext = aead::encrypt(&self.key.file_key(), &nonce, data, name.as_bytes())?;

        let path = self.path.join(blake3::hash(name.as_bytes()).to_hex());
        let mut file = std::fs::File::create(path)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;

        Ok(())
    }

    /// Retrieve a file from the vault
    pub fn retrieve(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let path = self.path.join(blake3::hash(name.as_bytes()).to_hex());
        let mut file = std::fs::File::open(path)?;

        let mut nonce = [0u8; 24];
        file.read_exact(&mut nonce)?;

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        aead::decrypt(&self.key.file_key(), &nonce, &ciphertext, name.as_bytes())
    }

    /// Auto-wipe after inactivity
    pub fn check_timeout(&mut self) -> bool {
        if self.last_activity.elapsed() > self.lock_timeout {
            self.lock();
            return true;
        }
        false
    }

    /// Securely wipe vault contents
    pub fn wipe(&self) -> Result<(), VaultError> {
        for entry in std::fs::read_dir(&self.path)? {
            let path = entry?.path();
            // Overwrite with random data before deletion
            if path.is_file() {
                let len = std::fs::metadata(&path)?.len() as usize;
                let random = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
                std::fs::write(&path, random)?;
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}
```

### 7.2 Memory Hygiene

```rust
// crates/vault-crypto/src/secure_mem.rs

use zeroize::Zeroize;

/// Secure buffer that zeros on drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self { data: slice.to_vec() }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

// Lock memory pages to prevent swapping to disk
#[cfg(unix)]
pub fn lock_memory(addr: *const u8, len: usize) -> Result<(), std::io::Error> {
    unsafe {
        if libc::mlock(addr as *const libc::c_void, len) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
```

### Phase 7 Deliverables

- [ ] Encrypted local vault
- [ ] Auto-lock after inactivity
- [ ] Auto-wipe option
- [ ] Secure memory allocation
- [ ] Memory locking to prevent swap

---

## Phase 8: Launch Preparation

### Objective

Security audit, documentation, and launch.

### 8.1 Security Audit Preparation

```markdown
# Audit Scope

## In Scope

- vault-crypto crate (all cryptographic operations)
- vault-protocol crate (wire protocol, P2P)
- vault-client core logic
- Server blob handling

## Critical Focus Areas

1. Key derivation correctness
2. Nonce generation uniqueness
3. Signature verification completeness
4. Memory hygiene (zeroization)
5. Side-channel resistance

## Deliverables for Auditors

- Complete source code
- Threat model document
- Architecture diagrams
- Test suite results
- Fuzzing coverage
```

### 8.2 Documentation

| Document            | Purpose                    |
| ------------------- | -------------------------- |
| User Guide          | End-user documentation     |
| Security Whitepaper | Technical security details |
| API Documentation   | Developer reference        |
| Deployment Guide    | Server operators           |
| Threat Model        | Security researchers       |

### 8.3 Launch Checklist

- [ ] Security audit complete
- [ ] All critical issues resolved
- [ ] Documentation complete
- [ ] Beta testing complete
- [ ] Performance benchmarks acceptable
- [ ] Legal review complete
- [ ] Privacy policy published
- [ ] Incident response plan ready

### Phase 8 Deliverables

- [ ] Security audit report
- [ ] All documentation
- [ ] Beta test results
- [ ] Performance benchmarks
- [ ] Launch announcement
- [ ] Bug bounty program setup

---

## Summary Timeline

| Phase   | Focus                 |
| ------- | --------------------- |
| Phase 0 | Foundation            |
| Phase 1 | Cryptographic Core    |
| Phase 2 | Identity System       |
| Phase 3 | Server Infrastructure |
| Phase 4 | Desktop Client        |
| Phase 5 | Sharing Mechanisms    |
| Phase 6 | P2P System            |
| Phase 7 | Vault and Hardening   |
| Phase 8 | Launch Preparation    |

> **Note:** Compared to v1.0, the overall effort has been significantly reduced. The removal of Android and iOS native clients eliminates Phase 4's mobile workstreams (Kotlin + JNI, Swift + FFI, platform-specific Keychain/Keystore integration, and mobile CI/CD pipelines). This effort savings also reduces security audit scope in Phase 8, since auditors no longer need to review two additional FFI boundaries and platform-specific secure storage implementations.

---

## Technology Dependencies Summary

### Rust Crates

```toml
# Cryptography
chacha20poly1305 = "0.10"
x25519-dalek = "2"
ed25519-dalek = "2"
blake3 = "1.5"
hkdf = "0.12"
argon2 = "0.5"
snow = "0.9"  # Noise Protocol

# Security
zeroize = { version = "1", features = ["derive"] }
rand = "0.8"
getrandom = "0.2"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.21"

# Async
tokio = { version = "1", features = ["full"] }

# Server
axum = "0.7"
tower = "0.4"
tower-http = "0.5"

# Storage
aws-sdk-s3 = "1"

# Error handling
thiserror = "1"
anyhow = "1"

# Testing
criterion = "0.5"
proptest = "1"
```

### Node.js Packages

```json
{
  "dependencies": {
    "@tauri-apps/api": "^2.0.0",
    "react": "^18.2.0",
    "typescript": "^5.3.0",
    "qrcode.react": "^3.1.0"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2.0.0",
    "vite": "^5.0.0"
  }
}
```

---

## Success Criteria

### Security

- [ ] Zero critical vulnerabilities in audit
- [ ] All invariants verified by testing
- [ ] Fuzzing finds no crashes
- [ ] Side-channel analysis passes

### Performance

- [ ] Encryption: >100 MB/s on desktop
- [ ] Decryption: >100 MB/s on desktop
- [ ] Server: >1000 requests/second

### Usability

- [ ] <3 clicks to share a file
- [ ] <5 seconds to decrypt typical file
- [ ] Recovery phrase backup flow intuitive
- [ ] Split-key sharing clear and guided

---

**End of Implementation Plan**
