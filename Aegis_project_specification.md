# Zero-Trust Secure File Sharing Protocol

## Complete Project Specification

**Project Codename:** Aegis  
**Author:** Abdulaziz  
**Version:** 1.1  
**Date:** July 26, 2026
**Revision:** v1.1 — Scope refined to desktop and web clients only (mobile platforms removed; see §4.5 for rationale)

---

## Executive Summary

This document specifies a secure file sharing system designed from first principles around a revolutionary concept: **the server knows nothing**. Unlike existing solutions that compromise between security and convenience, this system achieves both by placing cryptographic operations entirely on client devices, treating the server as an untrusted storage medium, and implementing defense-in-depth through split-key delivery, ephemeral cryptographic keys, and optional peer-to-peer transfers.

The system targets desktop platforms (Windows, macOS, Linux) via a Tauri-based application with a Rust cryptographic core, and a deliberately limited web companion for file reception. Native mobile clients are excluded by design to minimize attack surface and maintain a tractable security audit scope (see §4.5).

This specification details every aspect of the system: the vision, architecture, security model, threat analysis, data flows, technology choices, and comparison with existing solutions. A security expert reading this document should find answers to questions before they ask them.

---

## Table of Contents

1. [Vision and Philosophy](#1-vision-and-philosophy)
2. [Problem Statement](#2-problem-statement)
3. [Security Fundamentals](#3-security-fundamentals)
4. [System Architecture](#4-system-architecture)
5. [Cryptographic Design](#5-cryptographic-design)
6. [Data Flows](#6-data-flows)
7. [Threat Model and Attacker Analysis](#7-threat-model-and-attacker-analysis)
8. [Attack Vector Analysis](#8-attack-vector-analysis)
9. [CIA Triad Alignment](#9-cia-triad-alignment)
10. [Technology Justification](#10-technology-justification)
11. [Comparison with Existing Solutions](#11-comparison-with-existing-solutions)
12. [Limitations and Known Weaknesses](#12-limitations-and-known-weaknesses)
13. [Legal and Compliance Considerations](#13-legal-and-compliance-considerations)
14. [Conclusion](#14-conclusion)

---

## 1. Vision and Philosophy

### 1.1 The Dream

> _"A system so solid that even you, the creator, can't breach it without the user's key."_

This system represents the convergence of three historically separate ideals:

1. **Apple-level simplicity**: Premium UX that feels natural and intuitive
2. **Signal-level security**: End-to-end encryption with forward secrecy
3. **ProtonMail-level privacy**: Zero-knowledge architecture under Swiss-style principles

The result is a file sharing platform where:

- **Privacy feels natural**: Users don't need to think about security
- **Security feels invisible**: Protection is automatic and comprehensive
- **Power users feel like gods**: Full control over every cryptographic decision
- **Normal users feel safe**: Sensible defaults protect without complexity

### 1.2 Core Principles

#### Principle 1: Zero Trust Everything

```
Server knows nothing.
Server stores nothing readable.
Server can't identify users except via anonymous tokens.
Files are encrypted before they touch the backend.
Metadata is encrypted. Even filenames are blobs.
The server becomes an expensive USB stick — blind, dumb, fast.
```

#### Principle 2: Cryptographic Invariants

These must NEVER be violated, regardless of feature pressure:

| Invariant                   | Meaning                              |
| --------------------------- | ------------------------------------ |
| Server never sees plaintext | All encryption on client             |
| Server never possesses keys | Keys never leave client devices      |
| Every file has unique key   | No key reuse across files            |
| Metadata is meaningless     | Encrypted or randomized              |
| Identity = public key       | No personal identifiable information |

#### Principle 3: Defense in Depth

No single point of failure should compromise security:

```
Layer 1: End-to-end encryption (content protection)
Layer 2: Split-key delivery (link theft protection)
Layer 3: Ephemeral keys (forward secrecy)
Layer 4: Zero-knowledge server (breach protection)
Layer 5: P2P fallback (server bypass)
Layer 6: Secure vault (endpoint protection)
```

### 1.3 Why This Matters

This is not overengineering for the sake of complexity. Every feature addresses a real threat:

| Feature                 | Threat Addressed                                   |
| ----------------------- | -------------------------------------------------- |
| Per-file ephemeral keys | Limits blast radius of any key compromise          |
| Zero-trust server       | Prevents insider attacks and government data grabs |
| No metadata             | Protects against correlation attacks               |
| P2P fallback            | Saves server cost and increases privacy            |
| Split-key delivery      | Protects links from theft                          |
| Secure local vault      | Prevents OS-level leaks                            |

---

## 2. Problem Statement

### 2.1 The Current Landscape

Existing file sharing solutions fall into categories:

**Category 1: Convenient but Insecure**

- Google Drive, Dropbox, OneDrive
- Server has full access to all files
- Single breach exposes millions of users
- Comply with any government request

**Category 2: Secure but Inconvenient**

- PGP file encryption, GPG
- Excellent security, terrible UX
- Key management is a nightmare
- Regular users cannot adopt

**Category 3: Partially Secure**

- Proton Drive, Tresorit
- E2EE but account-based identity
- Some metadata still exposed
- No P2P option

**Category 4: Anonymous but Limited**

- OnionShare
- Highest anonymity but requires both parties online
- No persistent storage
- Tor latency makes files slow

### 2.2 The Gap

No existing solution provides ALL of:

| Requirement                    | Gap in Current Solutions         |
| ------------------------------ | -------------------------------- |
| True anonymity                 | All require email/phone identity |
| Zero metadata                  | All leak some metadata           |
| Split-key security             | None implement this              |
| Per-file forward secrecy       | None implement this              |
| P2P option with cloud fallback | None combine both                |
| Encrypted search               | None support this                |
| Offline both parties           | OnionShare lacks this            |

### 2.3 Our Solution

A system that combines:

- **Cloud reliability** of Proton/Tresorit
- **Anonymity** of OnionShare
- **Forward secrecy** of Signal
- **Split-key** security as a default
- **P2P fallback** for high-value transfers
- **Local vault** for endpoint protection

---

## 3. Security Fundamentals

### 3.1 Security Invariants (Non-Negotiable)

These properties MUST be maintained at all times:

```markdown
1. Server NEVER sees plaintext files
2. Server NEVER possesses decryption keys
3. Losing the server reveals NOTHING
4. Every file has an INDEPENDENT key
5. Metadata MUST be encrypted or meaningless
6. Users are identified ONLY by public keys
```

Any feature that violates these invariants is rejected, regardless of its value.

### 3.2 Security Non-Goals

The system explicitly does NOT protect against:

| Non-Goal                             | Reason                                                      |
| ------------------------------------ | ----------------------------------------------------------- |
| Compromised endpoints                | Malware on user device can always capture decrypted content |
| Malicious recipients                 | Users who receive files can always leak them                |
| Physical coercion                    | Users cannot be protected from physical threats             |
| Traffic analysis by global adversary | No practical system defeats nation-state timing correlation |

These are fundamental limitations of any cryptographic system, not design flaws.

### 3.3 The Trust Model

```
           Trust Level Diagram

FULLY TRUSTED
├── Client Crypto Layer (key generation, encryption, signing)
├── Client Vault Layer (secure storage, memory hygiene)
│
PARTIALLY TRUSTED
├── Network (TLS protects content, but timing may leak)
│
NOT TRUSTED
├── Server (stores encrypted blobs, handles routing)
├── Storage (dumb blob storage)
│
CONDITIONALLY TRUSTED
└── P2P (trusted locally, ephemeral keys)
```

---

## 4. System Architecture

### 4.1 High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     USER DEVICES                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                   Application Layer                    │ │
│  │  ┌──────────────────────────┐  ┌──────────────────┐   │ │
│  │  │       Desktop            │  │      Web         │   │ │
│  │  │       (Tauri)            │  │   (Limited)      │   │ │
│  │  └──────────────────────────┘  └──────────────────┘   │ │
│  ├───────────────────────────────────────────────────────┤ │
│  │                    Vault Layer                         │ │
│  │  ┌────────────────────────────────────────────────┐   │ │
│  │  │  Secure Sandbox │ Memory Hygiene │ Auto-Lock   │   │ │
│  │  └────────────────────────────────────────────────┘   │ │
│  ├───────────────────────────────────────────────────────┤ │
│  │                   Crypto Layer                         │ │
│  │  ┌────────────────────────────────────────────────┐   │ │
│  │  │  XChaCha20-Poly1305 │ Curve25519 │ Ed25519     │   │ │
│  │  │  BLAKE3             │ HKDF       │ Noise       │   │ │
│  │  └────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                             │
                    Transport Layer
                    TLS 1.3 / QUIC
                             │
┌────────────────────────────────────────────────────────────┐
│                      SERVER LAYER                           │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                   API Gateway                          │ │
│  │  ┌────────────────────────────────────────────────┐   │ │
│  │  │  Rate Limiting │ Request Routing │ Auth Tokens │   │ │
│  │  └────────────────────────────────────────────────┘   │ │
│  ├───────────────────────────────────────────────────────┤ │
│  │                   Blob Handler                         │ │
│  │  ┌────────────────────────────────────────────────┐   │ │
│  │  │  Upload │ Download │ Expiry Enforcement        │   │ │
│  │  └────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                             │
                     Storage Layer
                             │
┌────────────────────────────────────────────────────────────┐
│                    BLOB STORAGE                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  Encrypted Blobs │ Random IDs │ TTL Metadata          │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

                    Optional P2P Path
                           ↓
┌────────────────────────────────────────────────────────────┐
│                    P2P TRANSFER                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  Noise Protocol │ Direct Tunnel │ Server Bypass       │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

### 4.2 Trust Boundaries

| Zone                | Trust Level       | Responsibilities                              |
| ------------------- | ----------------- | --------------------------------------------- |
| Client Crypto Layer | Fully Trusted     | Key generation, encryption, signing, ratchets |
| Client Vault Layer  | Trusted           | Secure storage, memory hygiene, sandbox       |
| Network             | Partially Trusted | TLS protects against MITM                     |
| Server              | NOT Trusted       | Encrypted blob storage, routing               |
| Storage             | NOT Trusted       | Dumb blob persistence                         |
| P2P                 | Trusted locally   | Direct encrypted transfer                     |

### 4.3 Server Responsibilities

The server is deliberately "stupid":

**Server DOES:**

- Accept encrypted blob uploads
- Store blobs with random IDs
- Serve blobs on request
- Enforce time-to-live (TTL)
- Rate limit requests
- Coordinate P2P handshakes (NAT traversal)

**Server DOES NOT:**

- Know file contents
- Know file names
- Know user identities (beyond tokens)
- Know who shares with whom
- Decrypt anything
- Log meaningful metadata

If the server code grows beyond these responsibilities, something is wrong.

### 4.4 Component Details

#### 4.4.1 Client Crypto Layer

```rust
// Core operations (all in Rust)
pub struct CryptoLayer {
    // Key management
    fn generate_identity() -> (SecretKey, PublicKey);
    fn generate_ephemeral_keypair() -> (SecretKey, PublicKey);

    // File encryption
    fn encrypt_file(plaintext: &[u8], recipient: &PublicKey) -> EncryptedPackage;
    fn decrypt_file(package: &EncryptedPackage, key: &SecretKey) -> Vec<u8>;

    // Key exchange
    fn derive_shared_secret(our_private: &SecretKey, their_public: &PublicKey) -> SharedSecret;
    fn derive_file_key(shared: &SharedSecret, file_id: &[u8]) -> FileKey;

    // Signing
    fn sign(message: &[u8], key: &SecretKey) -> Signature;
    fn verify(message: &[u8], signature: &Signature, key: &PublicKey) -> bool;
}
```

#### 4.4.2 Vault Layer

```rust
pub struct SecureVault {
    // Storage
    fn store_file(encrypted: &[u8], id: &FileId) -> Result<()>;
    fn retrieve_file(id: &FileId) -> Result<Vec<u8>>;

    // Memory management
    fn secure_allocate(size: usize) -> SecureBuffer;
    fn secure_zero(buffer: &mut [u8]);

    // Auto-management
    fn set_auto_lock(timeout: Duration);
    fn set_auto_wipe(inactivity: Duration);

    // Access control
    fn unlock(passphrase: &str) -> Result<VaultHandle>;
    fn lock() -> Result<()>;
}
```

### 4.5 Scope Decision: No Native Mobile Clients

This system deliberately excludes native mobile applications (Android/iOS) from scope. This is a principled security and engineering decision:

#### 4.5.1 Security Rationale

| Concern                                | Explanation                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FFI bridge attack surface**          | Each native mobile platform (Android via JNI, iOS via Swift FFI) introduces platform-specific bindings that create new categories of memory safety bugs at the FFI boundary — use-after-free, double-free, and type confusion. These are precisely the vulnerability classes Rust was chosen to eliminate. Adding two FFI layers roughly triples the number of unsafe boundary crossings that must be audited. |
| **Platform-controlled key storage**    | Android Keystore and iOS Secure Enclave are opaque, vendor-controlled subsystems. Documented vulnerabilities in hardware TEEs (Samsung TrustZone CVEs, Qualcomm TEE escapes) mean relying on them for root-of-trust moves security guarantees outside our auditable codebase.                                                                                                                                  |
| **OS-level data leakage**              | Mobile operating systems routinely snapshot app state for task switchers, back up app data to cloud services (iCloud, Google Backup), index file contents for system search (Spotlight), and log IPC calls. Preventing these leaks requires per-OS workarounds that are fragile, version-dependent, and unverifiable by auditors.                                                                              |
| **App store as a trusted third party** | Distribution through Apple App Store and Google Play introduces gatekeepers who can inject code (cf. XcodeGhost), demand metadata disclosure (privacy nutrition labels), and remotely revoke or modify applications. This conflicts with zero-trust principles — it inserts a trusted third party into the software delivery chain.                                                                            |
| **Audit cost**                         | A security audit of the Rust core + Tauri desktop app is a tractable, well-bounded problem. Adding two native mobile codebases with platform-specific secure storage, biometric APIs, and push notification integrations roughly triples the audit surface without proportional security benefit.                                                                                                              |

#### 4.5.2 Engineering Rationale

Maintaining native mobile apps requires dedicated platform expertise (Kotlin/Android, Swift/iOS), separate CI/CD pipelines, platform-specific testing matrices, and ongoing compliance with frequently changing app store policies. For a security-first project, this engineering effort is better invested in hardening the cryptographic core and the desktop client.

#### 4.5.3 What Users Get Instead

The Tauri-based desktop application provides full access to all system features — encryption, decryption, split-key sharing, P2P transfers, and the secure local vault — across Windows, macOS, and Linux from a single auditable Rust codebase. A future web client with deliberately limited functionality (constrained by browser sandbox limitations on filesystem access, memory locking, and secure key storage) may serve as a lightweight companion for receiving shared files, but the desktop application remains the primary trusted client.

---

## 5. Cryptographic Design

### 5.1 Primitive Selection

| Purpose              | Primitive           | Justification                           |
| -------------------- | ------------------- | --------------------------------------- |
| Symmetric Encryption | XChaCha20-Poly1305  | 192-bit nonce (random-safe), fast, AEAD |
| Key Exchange         | X25519 (Curve25519) | Side-channel resistant, constant-time   |
| Digital Signatures   | Ed25519             | Deterministic, no RNG dependency        |
| Hashing              | BLAKE3              | Fastest secure hash, parallelizable     |
| Key Derivation       | HKDF-BLAKE3         | Standard, domain separation             |

### 5.2 Why These Choices

#### Why XChaCha20-Poly1305 (Not AES-GCM)?

| Factor                    | XChaCha20-Poly1305         | AES-GCM                       |
| ------------------------- | -------------------------- | ----------------------------- |
| Nonce size                | 192 bits (random-safe)     | 96 bits (collision risk)      |
| Hardware acceleration     | Not required               | Required for speed            |
| Timing attacks            | Immune by design           | Vulnerable without AES-NI     |
| Implementation complexity | Simple                     | Complex (requires care)       |
| Software performance      | Excellent on all platforms | Slow without hardware support |

For a system where random nonce generation is preferred and consistent cross-platform performance matters, XChaCha20-Poly1305 is superior.

#### Why Curve25519 (Not NIST curves)?

| Factor                  | Curve25519        | NIST P-256                 |
| ----------------------- | ----------------- | -------------------------- |
| Parameter transparency  | Fully documented  | Unexplained seeds          |
| Implementation safety   | Montgomery ladder | Requires care              |
| Side-channel resistance | Built-in          | Must be added              |
| Patents                 | None              | Complex history            |
| Community trust         | High              | Suspicion of NSA influence |

#### Why Ed25519 (Not ECDSA)?

| Factor                | Ed25519  | ECDSA             |
| --------------------- | -------- | ----------------- |
| Signature determinism | Yes      | No (RNG required) |
| RNG failure impact    | None     | Catastrophic      |
| Speed                 | Faster   | Slower            |
| Signature size        | 64 bytes | 64 bytes          |

ECDSA failures have caused real-world disasters (Sony PS3, Bitcoin thefts). Ed25519 eliminates this risk.

#### Why BLAKE3 (Not SHA-256)?

| Factor           | BLAKE3               | SHA-256     |
| ---------------- | -------------------- | ----------- |
| Speed            | 12× faster           | Baseline    |
| Parallelization  | Native (Merkle tree) | None        |
| Length extension | Immune               | Vulnerable  |
| Future-proof     | Modern design        | 2001 design |

For a system handling large files, BLAKE3's parallelism provides significant advantages.

### 5.3 File Encryption Flow

```
ENCRYPTION:

1. Sender generates ephemeral key pair (e_priv, e_pub)

2. Sender performs ECDH:
   shared_secret = X25519(e_priv, recipient_public_key)

3. Sender derives file key using HKDF:
   PRK = HKDF-Extract(random_salt, shared_secret)
   file_key = HKDF-Expand(PRK, "file-encryption" || file_id, 32)
   nonce_key = HKDF-Expand(PRK, "nonce-generation" || file_id, 32)

4. Sender generates random nonce:
   nonce = BLAKE3(nonce_key || random_bytes(16))[0:24]

5. Sender encrypts file:
   ciphertext = XChaCha20-Poly1305.Encrypt(file_key, nonce, plaintext, aad)

6. Sender signs package:
   package = e_pub || salt || nonce || ciphertext
   signature = Ed25519.Sign(sender_private_key, package)

7. Final upload:
   encrypted_package = package || signature
```

```
DECRYPTION:

1. Recipient verifies signature:
   valid = Ed25519.Verify(sender_public_key, package, signature)
   if !valid: REJECT

2. Recipient extracts ephemeral public key:
   e_pub = package[0:32]

3. Recipient performs ECDH:
   shared_secret = X25519(recipient_private_key, e_pub)

4. Recipient derives file key (same as sender):
   PRK = HKDF-Extract(salt, shared_secret)
   file_key = HKDF-Expand(PRK, "file-encryption" || file_id, 32)

5. Recipient decrypts:
   plaintext = XChaCha20-Poly1305.Decrypt(file_key, nonce, ciphertext, aad)

6. Recipient verifies integrity:
   if decryption_failed: REJECT (authentication tag mismatch)
```

### 5.4 Split-Key Architecture

```
TRADITIONAL SHARING:
┌─────────────────────────────────────────────────────────────┐
│  link = https://vault.app/file/abc123?key=decryption_key   │
│                                                             │
│  PROBLEM: Link theft = complete access                      │
└─────────────────────────────────────────────────────────────┘

SPLIT-KEY SHARING:
┌─────────────────────────────────────────────────────────────┐
│  Artifact A: https://vault.app/file/abc123                  │
│              (encrypted blob location)                      │
│                                                             │
│  Artifact B: vault:key:xyzABC123...                         │
│              (decryption key via separate channel)          │
│                                                             │
│  PROTECTION: Must obtain BOTH for access                    │
└─────────────────────────────────────────────────────────────┘

DELIVERY CHANNELS:
┌─────────────────────────────────────────────────────────────┐
│  Blob link: via app, email, message                         │
│  Key: via QR code, verbal, separate message                 │
│                                                             │
│  Attacker needs to compromise BOTH channels                 │
└─────────────────────────────────────────────────────────────┘
```

### 5.5 Per-File Ephemeral Keys

Every file uses a unique ephemeral key pair:

```
File 1: (e1_priv, e1_pub) → shared_secret_1 → file_key_1
File 2: (e2_priv, e2_pub) → shared_secret_2 → file_key_2
File 3: (e3_priv, e3_pub) → shared_secret_3 → file_key_3

Benefits:
- Compromising file_key_1 reveals NOTHING about file_key_2
- Forward secrecy: ephemeral keys discarded after encryption
- No key reuse across files ever
```

### 5.6 Identity Architecture

```
TRADITIONAL IDENTITY:
┌─────────────────────────────────────────────────────────────┐
│  user@email.com + password = identity                       │
│  Phone number required for 2FA                              │
│  Personal information tied to account                       │
└─────────────────────────────────────────────────────────────┘

CRYPTOGRAPHIC IDENTITY:
┌─────────────────────────────────────────────────────────────┐
│  Ed25519 public key = identity                              │
│  Short display name: aziz#3281 (optional, self-assigned)    │
│  No email, no phone, no personal information                │
│                                                             │
│  Identity Generation:                                        │
│  1. Generate Ed25519 keypair locally                        │
│  2. Store private key in OS keychain / credential manager   │
│  3. Public key IS the identity                              │
│  4. Optional: Add display name (stored encrypted)           │
└─────────────────────────────────────────────────────────────┘

ACCOUNT RECOVERY:
┌─────────────────────────────────────────────────────────────┐
│  There is no server-side recovery.                          │
│  User exports encrypted key backup.                         │
│  User guards recovery phrase.                               │
│  Losing keys = permanent loss (security feature, not bug)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Data Flows

### 6.1 File Upload Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        USER DEVICE                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User selects file                                        │
│                     ↓                                        │
│  2. Generate ephemeral keypair: (e_priv, e_pub)             │
│                     ↓                                        │
│  3. ECDH with recipient public key → shared_secret          │
│                     ↓                                        │
│  4. HKDF → file_key                                         │
│                     ↓                                        │
│  5. XChaCha20-Poly1305.Encrypt(file_key, nonce, file)       │
│                     ↓                                        │
│  6. Encrypt metadata (filename, size, type)                 │
│                     ↓                                        │
│  7. Ed25519.Sign(sender_key, package)                       │
│                     ↓                                        │
│  8. POST /upload (encrypted_blob)                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         SERVER                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  9. Receive encrypted blob (opaque bytes)                   │
│                     ↓                                        │
│  10. Generate random blob_id (unrelated to content)         │
│                     ↓                                        │
│  11. Store blob with TTL                                    │
│                     ↓                                        │
│  12. Return blob_id to client                               │
│                                                              │
│  Server knows: blob_id, size, TTL                           │
│  Server does NOT know: content, filename, sender, recipient │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      USER DEVICE                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  13. Construct share link: vault.app/file/{blob_id}         │
│                     ↓                                        │
│  14. Separately store/share decryption key                  │
│      - Key stored locally in vault                          │
│      - Key shared via separate channel (QR, message)        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 File Download Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    RECIPIENT DEVICE                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Receive share link: vault.app/file/{blob_id}            │
│                     ↓                                        │
│  2. Receive decryption key via separate channel             │
│                     ↓                                        │
│  3. GET /download/{blob_id}                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         SERVER                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  4. Retrieve encrypted blob from storage                    │
│                     ↓                                        │
│  5. Return encrypted blob (opaque bytes)                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    RECIPIENT DEVICE                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  6. Verify Ed25519 signature (authenticity)                 │
│                     ↓                                        │
│  7. Extract e_pub from package                              │
│                     ↓                                        │
│  8. ECDH with own private key → shared_secret               │
│                     ↓                                        │
│  9. HKDF → file_key                                         │
│                     ↓                                        │
│  10. XChaCha20-Poly1305.Decrypt(file_key, nonce, blob)      │
│                     ↓                                        │
│  11. Verify authentication tag (integrity)                  │
│                     ↓                                        │
│  12. Decrypt metadata (filename, size, type)                │
│                     ↓                                        │
│  13. Store decrypted file in secure vault                   │
│                     ↓                                        │
│  14. Wipe decryption key from memory                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 P2P Transfer Flow (High-Security Mode)

```
┌─────────────────────────────────────────────────────────────┐
│                        SENDER                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User enables P2P mode                                   │
│                     ↓                                        │
│  2. Request P2P handshake info from server                  │
│     (NAT traversal assistance only)                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         SERVER                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  3. Exchange connection info (STUN/TURN-like)               │
│     Server learns: IP addresses (already knows)             │
│     Server does NOT learn: file content, keys               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  DIRECT CONNECTION                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  4. Establish Noise Protocol tunnel (XX pattern)            │
│     - Mutual authentication                                 │
│     - Forward secrecy                                       │
│     - Identity hiding                                       │
│                                                              │
│  5. Generate ephemeral session keys                         │
│                                                              │
│  6. Transfer encrypted file directly                        │
│     - Server NEVER sees the data                            │
│     - Connection fully encrypted end-to-end                 │
│                                                              │
│  7. Verify integrity, destroy session keys                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Threat Model and Attacker Analysis

### 7.1 Attacker Classification

#### 7.1.1 Top 5 Most Significant Attacker Models Protected Against

**Rank 1: Compromised Cloud Provider / Data Center Intruder**

```
THREAT:
- Attacker gains full access to servers
- Cloud provider inspects stored data
- Insider copies entire disk contents
- Datacenter physically breached

WHY SIGNIFICANT:
- Most common real-world breach
- Affects millions of users at once
- Big companies regularly compromised
- Employees can be bribed

PROTECTION:
├── Server stores ONLY encrypted blobs
├── No decryption keys on server
├── No metadata in plaintext
├── Blobs look like random noise
└── Result: COMPLETE IMMUNITY

Even total server compromise reveals NOTHING useful.
```

**Rank 2: Malicious Server Administrator (Insider Threat)**

```
THREAT:
- Rogue admin with internal access
- Compromised credentials
- Social engineering target
- Coerced employee

WHY SIGNIFICANT:
- Insiders are MORE dangerous than external hackers
- Have legitimate access
- Know system architecture
- Can exfiltrate over time

PROTECTION:
├── Zero-trust architecture
├── Server holds no decryptable data
├── Admin sees only random bytes
├── No user identities beyond tokens
└── Result: COMPLETE IMMUNITY

This is a MAJOR advantage over Dropbox, Google Drive, Mega.
```

**Rank 3: Government Data Requests / Mass Surveillance**

```
THREAT:
- Government forces data handover
- Mass metadata collection (NSA/GCHQ)
- ISP deep packet inspection
- Multi-nation surveillance cooperation

WHY SIGNIFICANT:
- Governments prefer metadata over content
- Metadata reveals:
  - Who talks to whom
  - When and how often
  - Behavioral patterns
- Legal compulsion difficult to resist

PROTECTION:
├── No metadata stored
├── No user identity
├── Encrypted traffic
├── P2P fallback
├── Ephemeral accounts
└── Result: STRONG PROTECTION

Legal response: "We cannot comply because we have no data."
(Exactly what Signal and Proton do)
```

**Rank 4: Link Interception / Network Attackers (MITM)**

```
THREAT:
- Intercepted share links
- WiFi sniffing
- ISP monitoring
- Man-in-the-middle attacks

WHY SIGNIFICANT:
- Extremely common and easy
- Public WiFi is hostile
- ISPs have full traffic visibility
- Corporate networks monitor traffic

PROTECTION:
├── Split-key architecture (link alone useless)
├── TLS 1.3 / QUIC transport
├── E2EE for all content
├── Ephemeral keys prevent reuse
└── Result: COMPLETE IMMUNITY

Stealing only the URL accomplishes nothing.
```

**Rank 5: Mass-Scale Platform Hackers**

```
THREAT:
- Database dump attacks
- Large-scale data harvesting
- Correlation attacks across users
- Systematic exploitation

WHY SIGNIFICANT:
- How billion-dollar breaches happen
- Single attack affects all users
- Valuable data = attractive target

PROTECTION:
├── No usable data to steal
├── No metadata to correlate
├── Each file has unique keys
├── Files are random noise
└── Result: COMPLETE IMMUNITY

Removes #1 reason attackers target cloud platforms.
```

### 7.2 Additional Attacker Models

**Rank 6: Surveillance Capitalism**

- Data mining for advertising
- Behavioral profiling
- Protection: No data to mine

**Rank 7: Competitive Intelligence**

- Corporate espionage
- Protection: Files are encrypted, metadata hidden

**Rank 8: Script Kiddies / Opportunistic Hackers**

- Automated scanning and exploitation
- Protection: Standard security + no valuable targets

### 7.3 Threat Summary Table

| Attacker Model          | Protection Level | Notes               |
| ----------------------- | ---------------- | ------------------- |
| Server breach           | **IMMUNE**       | No useful data      |
| Insider threat          | **IMMUNE**       | Zero-trust design   |
| Government surveillance | **STRONG**       | No data to compel   |
| Network attackers       | **IMMUNE**       | Split-key + E2EE    |
| Mass-scale hackers      | **IMMUNE**       | No valuable targets |
| Endpoint malware        | EXPOSED          | Out of scope        |
| Social engineering      | EXPOSED          | Human weakness      |
| Physical coercion       | EXPOSED          | Out of scope        |

---

## 8. Attack Vector Analysis

### 8.1 Immune Attack Vectors

| Attack Vector           | Status     | Explanation                   |
| ----------------------- | ---------- | ----------------------------- |
| Server-side data breach | **IMMUNE** | Only encrypted blobs stored   |
| Insider/admin abuse     | **IMMUNE** | No keys on server             |
| Link hijacking          | **IMMUNE** | Split-key requires both parts |
| Metadata correlation    | **IMMUNE** | All metadata encrypted        |
| Mass surveillance       | **IMMUNE** | No logs, no identities        |
| Man-in-the-middle       | **IMMUNE** | ECDH + TLS + signatures       |
| Plaintext on disk       | **IMMUNE** | Secure vault sandbox          |
| Cloud provider access   | **IMMUNE** | Blobs are meaningless         |
| ISP surveillance        | **IMMUNE** | E2EE + TLS                    |

### 8.2 Strongly Protected Attack Vectors

| Attack Vector            | Status    | Mitigation                                                     |
| ------------------------ | --------- | -------------------------------------------------------------- |
| Targeted device malware  | PROTECTED | Vault prevents filesystem leaks, but in-memory access possible |
| Social engineering       | PROTECTED | Warnings, but humans are weak                                  |
| Traffic correlation      | PROTECTED | Padding and P2P help, but timing leaks                         |
| Zero-day vulnerabilities | PROTECTED | Regular updates, but unknown bugs exist                        |

### 8.3 Partially Covered Attack Vectors

| Attack Vector        | Status    | Notes                                             |
| -------------------- | --------- | ------------------------------------------------- |
| Replay attacks       | PARTIALLY | Nonces prevent, but need careful implementation   |
| Denial of service    | PARTIALLY | Rate limiting helps, but flooding possible        |
| Side-channel attacks | PARTIALLY | Constant-time crypto, but hardware channels exist |
| Fingerprinting       | PARTIALLY | Can detect device/OS characteristics              |

### 8.4 Exposed Attack Vectors (Fundamental Limitations)

| Attack Vector               | Status      | Why Unsolvable                             |
| --------------------------- | ----------- | ------------------------------------------ |
| Compromised recipient       | **EXPOSED** | Recipients can always screenshot, re-share |
| Physical access             | **EXPOSED** | Unlocked devices accessible                |
| Human error                 | **EXPOSED** | Users leak keys, use weak passphrases      |
| Legal compulsion of user    | **EXPOSED** | Users can be forced to reveal keys         |
| Nation-state level attacker | **EXPOSED** | Unlimited resources, unknown capabilities  |

### 8.5 Detailed Attack Analysis

#### 8.5.1 Server Breach Scenario

```
ATTACK SCENARIO:
Attacker gains root access to all servers and storage.

ATTACKER OBTAINS:
├── Encrypted blobs (random bytes)
├── Blob IDs (random strings)
├── TTL metadata (expiry times)
└── Rate limiting counters

ATTACKER DOES NOT OBTAIN:
├── Decryption keys (never on server)
├── File contents (encrypted)
├── File names (encrypted)
├── User identities (just tokens)
├── Who shares with whom (no logs)
└── Communication patterns (ephemeral)

ATTACK OUTCOME: COMPLETE FAILURE
Attacker has terabytes of random-looking data.
Zero actionable intelligence.
```

#### 8.5.2 Link Theft Scenario

```
ATTACK SCENARIO:
Attacker intercepts share link from email/message.

WITH TRADITIONAL SYSTEM:
├── Link contains: URL + decryption key
├── Attacker has: everything
└── Outcome: COMPLETE COMPROMISE

WITH SPLIT-KEY SYSTEM:
├── Link contains: URL only
├── Key delivered: separately (QR, voice)
├── Attacker has: encrypted blob location
└── Outcome: ATTACK FAILURE

Both link AND key required.
Compromising one channel is insufficient.
```

#### 8.5.3 Malicious Insider Scenario

```
ATTACK SCENARIO:
System administrator attempts to access user files.

ADMIN CAN:
├── View encrypted blobs
├── Access rate limiting data
├── See TTL expiry times
├── Read server logs (minimal)

ADMIN CANNOT:
├── Decrypt any file
├── Identify any user
├── See file names
├── Correlate activity
└── Recover any keys

ATTACK OUTCOME: COMPLETE FAILURE
Admin's privileged access provides zero advantage.
```

---

## 9. CIA Triad Alignment

### 9.1 Confidentiality

| Mechanism               | Contribution                       |
| ----------------------- | ---------------------------------- |
| XChaCha20-Poly1305      | Content encrypted with 256-bit key |
| Per-file ephemeral keys | Each file independently secured    |
| Zero-knowledge server   | Server cannot read content         |
| Split-key delivery      | Link alone reveals nothing         |
| Encrypted metadata      | Filenames, sizes hidden            |

**Result**: Maximum confidentiality at all layers.

### 9.2 Integrity

| Mechanism               | Contribution                        |
| ----------------------- | ----------------------------------- |
| Poly1305 authentication | Detects any ciphertext modification |
| Ed25519 signatures      | Verifies sender authenticity        |
| BLAKE3 hashing          | Content integrity verification      |
| Per-chunk MACs          | Large file corruption detected      |

**Result**: Any tampering immediately detected.

### 9.3 Availability

| Mechanism            | Contribution                 |
| -------------------- | ---------------------------- |
| Multi-region storage | Survives datacenter failures |
| Stateless servers    | Horizontal scaling           |
| P2P fallback         | Server bypass if needed      |
| TTL expiration       | Automatic cleanup            |

**Result**: High availability with graceful degradation.

### 9.4 Extended CIA Properties

#### 9.4.1 Non-Repudiation

- Ed25519 signatures prove sender identity
- Recipients can verify authenticity
- Sender cannot deny creating signed content

#### 9.4.2 Forward Secrecy

- Ephemeral keys discarded after use
- Past files protected even if long-term keys compromised
- Key ratcheting for P2P sessions

#### 9.4.3 Anonymity

- No personal identifiers required
- Key-based identity
- No meaningful logs

---

## 10. Technology Justification

### 10.1 Why Rust

| Requirement            | How Rust Achieves It                           |
| ---------------------- | ---------------------------------------------- |
| Memory safety          | Ownership system prevents UAF, buffer overflow |
| Performance            | Zero-cost abstractions, no GC                  |
| Concurrency            | Compile-time race prevention                   |
| Cryptographic security | No memory bugs in crypto code                  |
| Cross-platform         | Compiles to all targets                        |

**Alternative considered**: C/C++
**Rejection reason**: 70% of CVEs are memory safety bugs. Rust eliminates this class.

### 10.2 Why Tauri (Not Electron)

| Requirement      | Tauri                | Electron            |
| ---------------- | -------------------- | ------------------- |
| Binary size      | 3-10 MB              | 150+ MB             |
| Memory usage     | Low                  | High                |
| Security updates | OS WebView           | Manual Chromium     |
| Attack surface   | Minimal              | Large (full Chrome) |
| IPC security     | Explicit permissions | Broad by default    |

**Alternative considered**: Electron
**Rejection reason**: Electron bundles 150+ MB Chrome, has larger attack surface, requires manual security updates.

### 10.3 Why These Specific Algorithms

#### XChaCha20-Poly1305 vs AES-GCM

```
REQUIREMENT: Random nonce safety
├── XChaCha20: 192-bit nonce → 2^96 birthday bound
├── AES-GCM: 96-bit nonce → 2^48 birthday bound
└── WINNER: XChaCha20 (no nonce tracking needed)

REQUIREMENT: Software performance
├── XChaCha20: Fast without hardware
├── AES-GCM: Slow without AES-NI
└── WINNER: XChaCha20 (consistent cross-platform performance)

REQUIREMENT: Side-channel resistance
├── XChaCha20: Inherently constant-time
├── AES-GCM: Requires careful implementation
└── WINNER: XChaCha20 (simpler correctness)
```

#### Ed25519 vs ECDSA

```
REQUIREMENT: RNG safety
├── Ed25519: Deterministic (no RNG needed)
├── ECDSA: Requires perfect RNG
└── WINNER: Ed25519 (RNG failures are catastrophic)

REQUIREMENT: Implementation safety
├── Ed25519: Simple, well-defined
├── ECDSA: Complex, easy to get wrong
└── WINNER: Ed25519
```

#### BLAKE3 vs SHA-256

```
REQUIREMENT: Large file hashing
├── BLAKE3: Parallelizable (Merkle tree)
├── SHA-256: Sequential only
└── WINNER: BLAKE3 (10x faster on large files)

REQUIREMENT: Length extension immunity
├── BLAKE3: Immune by design
├── SHA-256: Vulnerable
└── WINNER: BLAKE3
```

### 10.4 Server Technology

| Option    | Choice                     | Reason                     |
| --------- | -------------------------- | -------------------------- |
| Language  | Rust or Go                 | Memory safety, performance |
| Framework | Minimal custom             | Reduce attack surface      |
| Database  | None (blob storage)        | Minimal state              |
| Storage   | S3-compatible              | Commodity, replaceable     |
| Caching   | Redis (rate limiting only) | Ephemeral data             |

### 10.5 What NOT to Use

| Technology          | Reject Reason                |
| ------------------- | ---------------------------- |
| Blockchain          | Adds nothing, leaks metadata |
| Smart contracts     | Unnecessary complexity       |
| AI in crypto path   | Unverifiable, risky          |
| Electron            | Huge attack surface          |
| Node.js for crypto  | Memory + dependency issues   |
| Custom cryptography | Career-ending mistake        |

---

## 11. Comparison with Existing Solutions

### 11.1 Feature Matrix

| Feature                 | Our System | Proton Drive | Tresorit     | OnionShare | Dropbox |
| ----------------------- | ---------- | ------------ | ------------ | ---------- | ------- |
| E2E Encryption          | ✅         | ✅           | ✅           | ✅         | ❌      |
| Zero-knowledge server   | ✅         | ✅           | ✅           | ✅         | ❌      |
| Anonymous identity      | ✅         | ❌ (email)   | ❌ (email)   | ✅         | ❌      |
| Zero metadata           | ✅         | ⚠️ (partial) | ⚠️ (partial) | ✅         | ❌      |
| Split-key delivery      | ✅         | ❌           | ❌           | ❌         | ❌      |
| Per-file ephemeral keys | ✅         | ❌           | ❌           | ❌         | ❌      |
| P2P option              | ✅         | ❌           | ❌           | ✅ (only)  | ❌      |
| Offline recipient       | ✅         | ✅           | ✅           | ❌         | ✅      |
| Secure local vault      | ✅         | ⚠️           | ⚠️           | ❌         | ❌      |
| Forward secrecy         | ✅         | ❌           | ❌           | ❌         | ❌      |
| Encrypted search        | 🔜         | ❌           | ❌           | ❌         | ❌      |
| Open source             | ✅         | ✅ (partial) | ❌           | ✅         | ❌      |

### 11.2 Where Competitors Fail

**Proton Drive**:

- ✘ Requires email account (identity leak)
- ✘ No split-key architecture
- ✘ No P2P fallback
- ✘ No per-file forward secrecy

**Tresorit**:

- ✘ Requires account registration
- ✘ Closed source
- ✘ Business-focused (less privacy-centric)
- ✘ No P2P, no split-key

**OnionShare**:

- ✘ Requires both parties online
- ✘ No persistent storage
- ✘ Tor latency (slow)
- ✘ No cloud option

**Sync/Mega/Others**:

- ✘ Account-based identity
- ✘ Some metadata exposed
- ✘ Varying trust models

### 11.3 Our Unique Value Proposition

```
"The world's first truly anonymous, zero-trust file exchange vault."

Combining:
├── Cloud convenience (like Proton)
├── Anonymity (like OnionShare)
├── Forward secrecy (like Signal)
├── Split-key (unique)
├── Ephemeral per-file keys (unique)
└── P2P + Cloud hybrid (unique)
```

---

## 12. Limitations and Known Weaknesses

### 12.1 Fundamental Limitations

These cannot be solved by any cryptographic system:

| Limitation             | Explanation                                  |
| ---------------------- | -------------------------------------------- |
| Compromised recipient  | If recipient leaks file, crypto cannot help  |
| Physical coercion      | User can be forced to reveal keys            |
| Endpoint malware       | Keyloggers, screen capture bypass all crypto |
| Nation-state adversary | Unlimited resources may find unknown attacks |
| User error             | Weak passwords, key mismanagement            |

### 12.2 Design Trade-offs

| Trade-off                | Choice Made               | Cost                        |
| ------------------------ | ------------------------- | --------------------------- |
| No account recovery      | Security over convenience | Lost keys = lost access     |
| Split-key sharing        | Security over simplicity  | Extra step for users        |
| No server-side search    | Privacy over features     | Client-only search          |
| Random nonces            | Security over determinism | Slightly larger ciphertext  |
| No native mobile clients | Auditability over reach   | Desktop-only primary client |

### 12.3 Potential Attack Scenarios

**Scenario: Advanced Persistent Threat (APT) targeting specific user**

```
Attack path:
1. Identify target user
2. Install malware on user's device
3. Capture encryption keys in memory
4. Exfiltrate decrypted files

Defense: Some vault protections, but fundamentally out of scope.
```

**Scenario: Traffic correlation attack**

```
Attack path:
1. Global adversary monitors network
2. Correlates upload/download timing
3. Infers who communicates with whom

Defense: P2P helps, padding helps, but not perfect.
```

### 12.4 UX Challenges

| Challenge             | Mitigation                         |
| --------------------- | ---------------------------------- |
| Key backup complexity | Clear UX, recovery phrase          |
| Split-key friction    | Optional for low-security shares   |
| No password recovery  | Extensive warnings, backup prompts |

---

## 13. Legal and Compliance Considerations

### 13.1 Legal Status of Strong Encryption

**In most jurisdictions (US, EU, etc.):**

- Writing encryption software: **LEGAL**
- Selling encryption software: **LEGAL**
- Open-source crypto: **LEGAL**
- Running privacy services: **LEGAL**

Signal exists. Proton exists. Tor exists. This is not illegal.

### 13.2 Handling Legal Requests

**Server response to data requests:**

```
"We are unable to comply with requests for user data or content
because we do not possess:
- Decryption keys
- Unencrypted content
- User identity information
- Communication logs or metadata

By design, our servers store only encrypted blobs that we cannot decrypt."
```

This is exactly how Signal and Proton respond to legal requests.

### 13.3 What Could Attract Attention

| Trigger                    | Response                                     |
| -------------------------- | -------------------------------------------- |
| Heavy criminal usage       | Cooperate with "no data" response            |
| Marketing as "untraceable" | Avoid this language                          |
| Hosting illegal content    | Blobs are encrypted - no moderation possible |

### 13.4 Jurisdictional Considerations

Prefer hosting in privacy-friendly jurisdictions:

- Switzerland
- Iceland
- Netherlands

### 13.5 Export Control

Cryptographic software may be subject to export controls:

- Avoid distribution to sanctioned countries
- Standard open-source exemptions usually apply

---

## 14. Conclusion

### 14.1 Summary

This specification defines a file sharing system that:

1. **Achieves true zero-trust**: Server compromise reveals nothing
2. **Provides anonymous identity**: No personal information required
3. **Implements defense-in-depth**: Six layers of protection
4. **Uses proven cryptography**: XChaCha20, Curve25519, Ed25519, BLAKE3
5. **Targets real threats**: Server breaches, insider attacks, surveillance
6. **Acknowledges limitations**: Endpoints, coercion, human error
7. **Maintains a minimal attack surface**: Desktop-first design with no native mobile clients, keeping the auditable codebase focused and tractable

### 14.2 Why This Matters

This is not overengineering. Every feature addresses a real threat:

- Signal proved messaging could be secure AND usable
- Proton proved email could be encrypted AND functional
- WireGuard proved VPNs could be both fast AND secure

This system aims to prove that file sharing can be:

- Maximally secure (zero-trust, forward secrecy)
- Maximally private (anonymous identity, no metadata)
- Maximally usable (premium UX, sensible defaults)

### 14.3 The Vision Realized

> _"A system where privacy feels natural, security feels invisible, UX feels premium, power users feel like gods, normal users feel safe."_

This specification provides the blueprint. The implementation plan follows.

---

**End of Project Specification**
