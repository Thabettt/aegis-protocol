# Implementation Plan

## Aegis Protocol & Reference Implementation

**Project:** Aegis
**Author:** Abdulaziz
**Version:** 2.1
**Date:** June 29, 2026
**Revision:** v2.1 -- Structural polish. Track separation clarified. No engineering changes.

---

## Overview

This implementation plan provides a detailed roadmap for building the Aegis protocol library and its reference implementation. It is organized into two tracks: **Track A** covers the protocol library (cryptographic core, wire formats, identity, P2P protocol, specification review, and protocol verification), while **Track B** covers the reference application (server, desktop client, vault hardening, and release). Each track contains phases with specific deliverables and acceptance criteria.

### Guiding Principles

1. **Cryptography before features**: Crypto layer must be correct before anything else
2. **Security before convenience**: Never compromise invariants for UX
3. **Test everything**: Every crypto operation must be test-covered
4. **Audit-ready code**: Write as if a security auditor reads every line
5. **Minimal complexity**: Each added component must justify its existence
6. **Minimal attack surface**: Every platform target increases the surface area an attacker can probe; only ship what can be fully audited and hardened

---

## Technology Stack

### Track A: Protocol Library Stack

| Component     | Technology | Version               |
| ------------- | ---------- | --------------------- |
| Core Language | Rust       | Latest stable (1.75+) |
| Async Runtime | Tokio      | Latest stable         |
| Build System  | Cargo      | Latest                |

#### Cryptographic Libraries

| Purpose            | Crate                | Version |
| ------------------ | -------------------- | ------- |
| AEAD Encryption    | `chacha20poly1305`   | 0.10    |
| Key Exchange       | `x25519-dalek`       | 2       |
| Digital Signatures | `ed25519-dalek`      | 2       |
| Hashing            | `blake3`             | 1.5     |
| KDF                | `hkdf`               | 0.12    |
| Secure Random      | `rand` + `getrandom` | 0.8     |
| Noise Protocol     | `snow`               | 0.9     |
| Secure Memory      | `zeroize`            | 1       |

### Track B: Reference Application Stack

The following technologies are used only by the reference application and are not required for protocol library development.

| Component         | Technology                             |
| ----------------- | -------------------------------------- |
| Desktop Framework | Tauri 2.0+                             |
| Server Framework  | Axum 0.7                               |
| Object Storage    | S3-compatible (MinIO dev, AWS S3 prod) |
| Rate Limiting     | tower-governor (in-memory)             |
| Password Hashing  | Argon2 0.5                             |
| Deployment        | Docker, Kubernetes                     |

---

## Track A: Protocol & Reference Library

## Phase 0: Foundation

### Objective

Establish project structure, development environment, and documentation framework.

### 0.1 Repository Setup

```bash
# Create monorepo structure
aegis/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── security-audit.yml
│   │   └── release.yml
│   ├── CODEOWNERS
│   └── SECURITY.md
├── crates/
│   ├── aegis-crypto/           # Core cryptography (Track A)
│   └── aegis-protocol/         # Wire protocol, P2P (Track A)
├── reference/
│   ├── aegis-server/           # Reference server implementation (Track B)
│   ├── aegis-client/           # Reference client logic (Track B)
│   └── desktop/                # Tauri desktop app (Track B)
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

> **Note:** `crates/` contains only protocol-level libraries. All application-level code -- including the reference server, client, and desktop app -- lives under `reference/`. A developer building only the protocol library never needs to touch `reference/`.

### 0.2 Development Environment

**Track A Setup (Protocol Library):**

```bash
# Required for all protocol development
rustup default stable
rustup component add clippy rustfmt
cargo install cargo-audit cargo-deny cargo-expand cargo-fuzz
```

**Track B Setup (Reference Application):**

Only required if building the reference server, desktop client, or web app.

```bash
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
      - run: cd crates/aegis-crypto && cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=60
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
// crates/aegis-crypto/Cargo.toml
[package]
name = "aegis-crypto"
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
// crates/aegis-crypto/src/types.rs

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
// crates/aegis-crypto/src/aead.rs

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
// crates/aegis-crypto/src/kex.rs

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

    let context = [b"aegis-file-encryption-v1", file_id].concat();
    let file_key = derive_file_key(&ephemeral.secret, recipient_public, &salt, &context);

    (ephemeral, file_key, salt)
}
```

### 1.5 Digital Signatures

```rust
// crates/aegis-crypto/src/sign.rs

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
// crates/aegis-crypto/src/file.rs

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
        let context = [b"aegis-file-encryption-v1", file_id].concat();
        let file_key = kex::derive_file_key(recipient_secret, &sender_ephemeral, &self.salt, &context);

        // Decrypt
        aead::decrypt(&file_key, &self.nonce, &self.ciphertext, expected_aad)
    }
}
```

### 1.7 Comprehensive Tests

```rust
// crates/aegis-crypto/src/tests.rs

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
// crates/aegis-crypto/fuzz/fuzz_targets/fuzz_decrypt.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use aegis_crypto::*;

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

- [ ] `aegis-crypto` crate with all primitives
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
// reference/aegis-client/src/identity.rs

use argon2::{Argon2, password_hash::PasswordHasher};
use aegis_crypto::types::Identity;

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
// reference/aegis-client/src/recovery.rs

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

## Phase 3: Wire Protocol & Message Formats

### Objective

Formalize message formats and share link structures.

### 3.1 Share Link Wire Format

```rust
// crates/aegis-protocol/src/share.rs

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
        format!("aegis://share/{}", encoded)
    }

    pub fn from_url(url: &str) -> Result<Self, ParseError> {
        let encoded = url.strip_prefix("aegis://share/")?;
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
        format!("aegis:key:{}", base64url::encode(&bytes))
    }
}
```

---

## Phase 4: P2P Protocol

### Objective

Implement optional peer-to-peer transfers using Noise Protocol.

### 4.1 Noise Protocol Integration

```rust
// crates/aegis-protocol/src/p2p.rs

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

### Phase 4 Deliverables

- [ ] Noise Protocol XX pattern implementation
- [ ] NAT traversal assistance
- [ ] P2P file transfer
- [ ] Session key ratcheting
- [ ] Fallback to server if P2P fails

---

## Phase 5: Protocol Specification Review and Lock

### Objective

Validate the existing protocol specification (`Aegis_project_specification.md`) against the implemented crates, resolve any discrepancies between the specification and the code, and formally freeze the wire format before audit.

### 5.1 Specification-to-Implementation Audit

Systematically compare every section of the protocol specification against the corresponding implementation in `aegis-crypto` and `aegis-protocol`. Document any case where the implementation diverges from the spec -- whether in field ordering, key derivation context strings, error handling behavior, or state machine transitions. Each discrepancy must be resolved by updating either the spec or the code, with a written justification for the choice.

### 5.2 Wire Format Freeze

Once the specification and implementation are aligned, formally freeze the wire format. After this point, any change to the EncryptedPackage binary layout, ShareLink JSON schema, ShareKey JSON schema, or error code taxonomy requires a major version increment and a full re-audit.

### 5.3 Test Vector Generation

Generate a canonical set of test vectors from the reference implementation: known inputs, keys, salts, nonces, and expected outputs for every cryptographic operation. Publish these vectors alongside the specification so that third-party implementations can verify conformance without access to the reference code.

### Phase 5 Deliverables

- [ ] Specification-to-implementation discrepancy report (all items resolved)
- [ ] Wire format formally frozen (version 1.0)
- [ ] Canonical test vectors published
- [ ] Specification updated to match final implementation where necessary
- [ ] Version negotiation mechanism validated against spec §7.3

---

## Phase 6: Protocol Verification & Audit

### Objective

Verify all protocol invariants and prepare for security audit.

### 6.1 Security Audit Preparation

```markdown
# Audit Scope

## In Scope

- aegis-crypto crate (all cryptographic operations)
- aegis-protocol crate (wire protocol, P2P)
- aegis-client core logic
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

### Phase 6 Deliverables

- [ ] Security audit report
- [ ] Test suite results
- [ ] Fuzzing coverage

---

## Track B: Reference Application

Track B covers all application-level code that consumes the protocol library. It lives entirely under the `reference/` directory and has no effect on the protocol crates in `crates/`. Track B development may proceed in parallel with Track A after Phase 1 is complete, but Track B may not ship before Track A Phase 6 (audit) is finished.

### App Phase 1: Server Reference Implementation

**Objective:** Build a minimal, conforming Aegis server that implements the blob storage interface defined in the protocol specification.

**Key decisions:** The server is built on Axum with Tokio for async I/O. Blob storage uses an S3-compatible backend (MinIO for development, AWS S3 for production). Rate limiting is handled in-memory via `tower-governor`. The server stores only encrypted blobs with random IDs and TTL metadata -- it never inspects, indexes, or logs blob contents.

**Deliverables:**

- [ ] `POST /upload` endpoint accepting encrypted blobs
- [ ] `GET /download/:id` endpoint serving blobs
- [ ] `DELETE /:id` endpoint for blob removal
- [ ] TTL enforcement with automatic expiry
- [ ] Rate limiting per IP / per token
- [ ] NAT traversal coordination for P2P handshakes
- [ ] Docker image and Kubernetes deployment manifests
- [ ] Integration tests against `aegis-protocol` crate

### App Phase 2: Desktop Client

**Objective:** Build a Tauri-based desktop client for Windows, macOS, and Linux that demonstrates all protocol operations via a native desktop interface.

**Key decisions:** The client interfaces with the Rust backend through Tauri's IPC mechanism. All cryptographic operations are performed by the `aegis-crypto` and `aegis-protocol` crates via `aegis-client` -- the frontend handles only presentation. The IPC surface uses Tauri's explicit permission model; no broad IPC access is granted.

**Deliverables:**

- [ ] Tauri project structure under `reference/desktop/`
- [ ] IPC commands wrapping `aegis-client` operations
- [ ] File selection, encryption, and upload flow
- [ ] Share link generation with split-key delivery
- [ ] File download and decryption flow
- [ ] Identity creation, backup, and recovery UI
- [ ] P2P transfer initiation and acceptance
- [ ] Builds for Windows, macOS, and Linux

### App Phase 3: Secure Vault & Hardening

**Objective:** Implement endpoint protection features that go beyond the protocol's scope to harden the reference client against local threats.

**Key decisions:** The vault encrypts all local state at rest. Memory containing sensitive material (keys, plaintext) is zeroized immediately after use and allocated in non-swappable pages where the OS permits. The vault auto-locks after a configurable inactivity timeout. OS keychain integration (Windows Credential Store, macOS Keychain, Linux Secret Service) is used for passphrase-derived key caching.

**Deliverables:**

- [ ] Encrypted local vault for file and key storage
- [ ] Memory hygiene: zeroization, mlock where available
- [ ] Auto-lock on inactivity timeout
- [ ] OS keychain integration for key caching
- [ ] Hardening audit checklist completed

### App Phase 4: Release Preparation

**Objective:** Prepare the reference application for public release.

**Key decisions:** End-user documentation is written for the desktop client, not the protocol library (which has its own specification). Beta testing focuses on the encryption/decryption roundtrip, split-key sharing flow, and P2P transfers. A bug bounty program is established covering both the protocol crates and the reference application.

**Deliverables:**

- [ ] End-user documentation (installation, usage, recovery)
- [ ] Beta testing complete with issue resolution
- [ ] Privacy policy published
- [ ] Bug bounty program established
- [ ] Release binaries signed and published

---

## Phase Overview

### Track A: Protocol Library

Phases are sequential. Each phase depends on the completion of the previous one.

| Phase   | Focus                         | Depends On |
| ------- | ----------------------------- | ---------- |
| Phase 0 | Foundation                    | --         |
| Phase 1 | Cryptographic Core            | Phase 0    |
| Phase 2 | Identity System               | Phase 1    |
| Phase 3 | Wire Protocol Format          | Phase 1    |
| Phase 4 | P2P Protocol                  | Phase 3    |
| Phase 5 | Protocol Specification Review | Phase 1-4  |
| Phase 6 | Verification & Audit          | Phase 5    |

### Track B: Reference Application

Track B may begin after Track A Phase 1 is complete. Track B may not ship before Track A Phase 6 is finished.

| Phase | Focus                 | Depends On      |
| ----- | --------------------- | --------------- |
| App 1 | Server Implementation | Track A Phase 1 |
| App 2 | Desktop Client        | Track A Phase 3 |
| App 3 | Vault & Hardening     | App 2           |
| App 4 | Release Preparation   | App 3, Phase 6  |

---

## Technology Dependencies Summary

### Protocol Crates (Track A)

```toml
# Cryptography
chacha20poly1305 = "0.10"
x25519-dalek = "2"
ed25519-dalek = "2"
blake3 = "1.5"
hkdf = "0.12"
snow = "0.9"

# Security
zeroize = { version = "1", features = ["derive"] }
rand = "0.8"
getrandom = "0.2"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.21"

# Error handling
thiserror = "1"

# Testing
criterion = "0.5"
proptest = "1"
```

### Reference Application Crates (Track B)

```toml
# Async runtime
tokio = { version = "1", features = ["full"] }

# Server
axum = "0.7"
tower = "0.4"
tower-http = "0.5"

# Storage
aws-sdk-s3 = "1"

# Password hashing
argon2 = "0.5"

# Error handling
anyhow = "1"
```

> **Note:** All frontend dependencies are managed separately in the reference desktop application and will be documented in `Aegis_reference_implementation_plan.md` (when written). They are not listed here as they are not required for protocol library development.

---

## Success Criteria

### Protocol Library (Track A)

- [ ] Zero critical vulnerabilities in protocol audit
- [ ] Protocol invariants mathematically and empirically verified
- [ ] Fuzzing finds no crashes in cryptographic implementations
- [ ] Cryptographic primitives resist side-channel analysis
- [ ] Formal specification document reviewed and frozen

### Reference Application (Track B)

- [ ] Desktop Encryption/Decryption: >100 MB/s
- [ ] Server handling: >1000 requests/second
- [ ] UX: <3 clicks to share a file
- [ ] UX: Recovery phrase backup flow intuitive
- [ ] UX: Split-key sharing clear and guided
- [ ] Local Vault auto-locks and memory hygiene passes testing

---

**End of Implementation Plan**
