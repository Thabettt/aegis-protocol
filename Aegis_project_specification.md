# The Aegis Protocol

## Protocol Specification

**Project:** Aegis
**Author:** Abdulaziz
**Version:** 2.1
**Date:** June 29, 2026
**Revision:** v2.1 -- Prose rewrite. Consolidated security analysis. Diagrams redrawn. No architectural changes.

---

## Executive Summary

This document specifies the Aegis protocol -- a zero-trust secure file sharing protocol designed from first principles around a core concept: **the server knows nothing**. The protocol places all cryptographic operations on the client side, treats any server as an untrusted storage medium, and implements defense-in-depth through split-key delivery, ephemeral cryptographic keys, and optional peer-to-peer transfers.

The Aegis protocol is implementation-agnostic: any conforming client or server that adheres to the message formats, cryptographic operations, and security invariants defined herein is a valid participant in the protocol. A reference implementation in Rust accompanies this specification separately.

This specification details the protocol's design philosophy, architecture, cryptographic design, message flows, threat model, and security analysis. A security expert reading this document should find answers to questions before they ask them.

---

## Table of Contents

1. [Vision and Philosophy](#1-vision-and-philosophy)
2. [Problem Statement](#2-problem-statement)
3. [Security Fundamentals](#3-security-fundamentals)
4. [Protocol Architecture](#4-protocol-architecture)
5. [Cryptographic Design](#5-cryptographic-design)
6. [Protocol Flows](#6-protocol-flows)
7. [Protocol Wire Formats and State Machine](#7-protocol-wire-formats-and-state-machine)
8. [Security Analysis](#8-security-analysis)
9. [Algorithm Justification](#9-algorithm-justification)
10. [Protocol Differentiation](#10-protocol-differentiation)
11. [Limitations and Known Weaknesses](#11-limitations-and-known-weaknesses)
12. [Regulatory and Compliance Context](#12-regulatory-and-compliance-context)
13. [Conclusion](#13-conclusion)
14. [Appendix A: Reference Implementation Decisions](#appendix-a-reference-implementation-decisions)

---

## 1. Vision and Philosophy

### 1.1 Protocol Design Vision

> _"A protocol so solid that even the operator can't breach it without the user's key."_

The Aegis protocol represents the convergence of three design goals: Signal-level security through end-to-end encryption with forward secrecy, a zero-knowledge architecture in which the server acts as a blind and untrusted relay, and implementation agnosticism so that any conforming client or server can participate in the protocol regardless of language, platform, or interface.

The protocol defines the cryptographic operations, message formats, and security invariants that any implementation must uphold. How an implementation presents these capabilities to users -- its visual design, platform support, or interaction patterns -- is outside the protocol's scope.

### 1.2 Core Principles

**Principle 1: Zero Trust Everything.** The server knows nothing. It stores nothing readable. It cannot identify users except via anonymous tokens. Files are encrypted before they touch any backend. Metadata is encrypted. Even filenames are opaque blobs. The server is, by design, a blind and dumb storage medium.

**Principle 2: Cryptographic Invariants.** The following properties must never be violated, regardless of feature pressure or convenience trade-offs:

| Invariant                   | Meaning                              |
| --------------------------- | ------------------------------------ |
| Server never sees plaintext | All encryption on client             |
| Server never possesses keys | Keys never leave client devices      |
| Every file has unique key   | No key reuse across files            |
| Metadata is meaningless     | Encrypted or randomized              |
| Identity = public key       | No personal identifiable information |

**Principle 3: Defense in Depth.** No single point of failure should compromise security. The protocol defines five layers of defense, each independent of the others: end-to-end encryption protects content, split-key delivery guards against link theft, ephemeral keys provide forward secrecy, the zero-knowledge server design protects against breaches, and the P2P fallback path allows the server to be bypassed entirely.

> **Note:** Endpoint protection (e.g., secure local vaults, memory hygiene) is a recommended implementation practice but is outside the protocol's scope. See Appendix A for reference implementation guidance.

### 1.3 Why This Matters

None of the protocol's features exist for their own sake. Per-file ephemeral keys limit the blast radius of any key compromise. The zero-trust server design prevents insider attacks and government data grabs. Encrypted metadata protects against correlation attacks. The P2P fallback increases privacy by removing the server from the data path entirely. Split-key delivery ensures that intercepting a share link alone accomplishes nothing.

---

## 2. Problem Statement

### 2.1 The Current Landscape

Existing file sharing solutions cluster into four categories, each with a defining weakness.

Convenient services like Google Drive, Dropbox, and OneDrive give the server full access to all files. A single breach exposes millions of users, and the provider will comply with any government request because it can.

Secure-but-inconvenient tools like PGP and GPG offer excellent cryptographic properties but impose key management complexity that ordinary users cannot adopt.

Partially secure services like Proton Drive and Tresorit provide end-to-end encryption but require account-based identity (leaking email addresses), still expose some metadata, and offer no peer-to-peer transfer option.

Anonymous-but-limited tools like OnionShare achieve high anonymity but require both parties to be online simultaneously, offer no persistent storage, and impose Tor latency on every transfer.

### 2.2 The Gap

No existing solution simultaneously provides true anonymity without email or phone identity, zero metadata leakage, split-key delivery, per-file forward secrecy, a P2P option with cloud fallback, and support for offline recipients. Each of these properties exists somewhere in the landscape, but no protocol combines all of them.

### 2.3 The Aegis Protocol

The Aegis protocol fills this gap by defining a standard that combines persistent encrypted blob storage with TTL (enabling offline recipients), cryptographic anonymity through key-based identity with no PII requirement, per-file forward secrecy through ephemeral keypairs, split-key delivery where the blob location and decryption key travel through separate channels, and a P2P transfer mode for direct peer-to-peer file transfer via Noise Protocol tunnels.

---

## 3. Security Fundamentals

### 3.1 Security Invariants

The following six properties are non-negotiable. Any feature, optimization, or extension that would violate any of them is rejected regardless of its value:

1. The server never sees plaintext files.
2. The server never possesses decryption keys.
3. A complete server compromise reveals nothing.
4. Every file is encrypted with an independent key.
5. All metadata is encrypted or meaningless.
6. Users are identified only by public keys.

### 3.2 Security Non-Goals

The protocol explicitly does not protect against four classes of threat, because no cryptographic protocol can. Endpoint compromise by malware allows an attacker to capture decrypted content directly from the user's device. Malicious recipients who receive files can always leak them. Physical coercion against users is outside the reach of mathematics. Traffic analysis by a global adversary with nation-state timing correlation capabilities is a limitation shared by every practical protocol. These are fundamental boundaries of cryptography, not design flaws.

### 3.3 The Trust Model

The protocol assigns trust in four tiers. The client's cryptographic operations layer -- key generation, encryption, signing, and ratcheting -- is fully trusted and represents the protocol's security foundation. The network is partially trusted: TLS protects content in transit, but timing information may leak. The server and its storage are not trusted at all; they handle only encrypted blobs and routing. P2P channels are conditionally trusted: they are encrypted end-to-end with ephemeral session keys, but trust extends only for the duration of the session.

```
            Trust Level Diagram

  FULLY TRUSTED
  +-- Client Crypto Layer (key generation, encryption, signing)
  |
  PARTIALLY TRUSTED
  +-- Network (TLS protects content, but timing may leak)
  |
  NOT TRUSTED
  +-- Server (stores encrypted blobs, handles routing)
  +-- Storage (dumb blob persistence)
  |
  CONDITIONALLY TRUSTED
  +-- P2P (trusted locally, ephemeral keys)
```

---

## 4. Protocol Architecture

### 4.1 Protocol Layer Model

The protocol is organized into three principal layers, each with a well-defined boundary.

The **Cryptographic Operations Layer** contains the primitive algorithms that perform all security-critical work: XChaCha20-Poly1305 for authenticated encryption, Curve25519 for key exchange, Ed25519 for digital signatures, BLAKE3 for hashing, HKDF for key derivation, and the Noise Framework for P2P tunnels.

The **Wire Protocol Layer** defines the message formats that cross trust boundaries: the EncryptedPackage binary format, ShareLink and ShareKey JSON structures, the identity format, error codes, and protocol versioning.

The **Identity Layer** establishes that an Ed25519 keypair constitutes a complete identity. No personally identifiable information is required. An optional self-assigned display name may be stored in encrypted form. Recovery is handled through passphrase-protected key backups.

```
+--------------------------------------------------------------+
|                       PROTOCOL LAYERS                        |
|                                                              |
|  +--------------------------------------------------------+  |
|  |            Cryptographic Operations Layer               |  |
|  |  +--------------------------------------------------+   |  |
|  |  | XChaCha20-Poly1305 | Curve25519    | Ed25519     |   |  |
|  |  | BLAKE3             | HKDF          | Noise       |   |  |
|  |  +--------------------------------------------------+   |  |
|  +--------------------------------------------------------+  |
|  |            Wire Protocol Layer                          |  |
|  |  +--------------------------------------------------+   |  |
|  |  | EncryptedPackage | ShareLink  | ShareKey          |   |  |
|  |  | Identity Format  | Error Codes | Versioning       |   |  |
|  |  +--------------------------------------------------+   |  |
|  +--------------------------------------------------------+  |
|  |            Identity Layer                               |  |
|  |  +--------------------------------------------------+   |  |
|  |  | Ed25519 Keypair = Identity | Recovery Phrase      |   |  |
|  |  | No PII | Passphrase-Protected Storage              |   |  |
|  |  +--------------------------------------------------+   |  |
|  +--------------------------------------------------------+  |
+--------------------------------------------------------------+
                             |
                   Transport Requirements
                   TLS 1.3 / QUIC minimum
                             |
+--------------------------------------------------------------+
|             SERVER INTERFACE (Protocol-Defined)               |
|  +--------------------------------------------------------+  |
|  |                   API Contract                          |  |
|  |  +--------------------------------------------------+   |  |
|  |  | POST /upload | GET /download/:id                  |   |  |
|  |  | DELETE /:id  | Rate Limiting | TTL Enforcement    |   |  |
|  |  +--------------------------------------------------+   |  |
|  +--------------------------------------------------------+  |
|  |                   Storage Interface                     |  |
|  |  +--------------------------------------------------+   |  |
|  |  | Encrypted Blobs | Random IDs | TTL Metadata       |   |  |
|  |  +--------------------------------------------------+   |  |
|  +--------------------------------------------------------+  |
+--------------------------------------------------------------+

                    Optional P2P Path
                           |
                           v
+--------------------------------------------------------------+
|              P2P PROTOCOL (Noise Framework)                   |
|  +--------------------------------------------------------+  |
|  | Noise_XX_25519_ChaChaPoly_BLAKE2b                       |  |
|  | Direct Tunnel | Server Bypass | Session Ratcheting       |  |
|  +--------------------------------------------------------+  |
+--------------------------------------------------------------+
```

> **Note:** The diagram above shows only protocol-defined layers. How a conforming implementation handles local storage, UI, platform integration, or endpoint security is outside the protocol's scope.

### 4.2 Trust Boundaries

| Zone                        | Trust Level       | Responsibilities                              |
| --------------------------- | ----------------- | --------------------------------------------- |
| Client Crypto Operations    | Fully Trusted     | Key generation, encryption, signing, ratchets |
| Network                     | Partially Trusted | TLS protects against MITM                     |
| Server                      | NOT Trusted       | Encrypted blob storage, routing               |
| Storage                     | NOT Trusted       | Dumb blob persistence                         |
| P2P Channel                 | Trusted locally   | Direct encrypted transfer                     |

### 4.3 Server Role within the Protocol

The protocol defines the server as a deliberately minimal participant. A conforming server accepts encrypted blob uploads via `POST /upload`, stores blobs with random IDs, serves blobs on request via `GET /download/:id`, enforces time-to-live (TTL), rate limits requests, and coordinates P2P handshakes for NAT traversal.

A conforming server does not know file contents, file names, user identities beyond opaque tokens, or who shares with whom. It never decrypts anything and never logs meaningful metadata. If a server implementation grows beyond these responsibilities, it is no longer a conforming Aegis server.

### 4.4 Required Protocol Operations

A conforming Aegis client implementation must support the following logical operations. These are specified as abstract functions, not as an API surface -- implementations may organize them however they choose.

```
Protocol Operations:

  Identity Management:
    generate_identity()        -> (SigningKey, VerifyingKey)
    generate_ephemeral_pair()  -> (SecretKey, PublicKey)

  File Encryption:
    encrypt_file(plaintext, recipient_public_key) -> EncryptedPackage
    decrypt_file(package, recipient_secret_key)   -> plaintext

  Key Exchange:
    derive_shared_secret(our_private, their_public) -> SharedSecret
    derive_file_key(shared_secret, salt, context)   -> FileKey

  Signing:
    sign(message, signing_key)                    -> Signature
    verify(message, signature, verifying_key)      -> bool

  Share Protocol:
    create_share_link(blob_id, server, metadata)  -> ShareLink
    create_share_key(ephemeral_public, salt, id)  -> ShareKey
```

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

**XChaCha20-Poly1305 over AES-GCM.** The decisive factor is nonce safety. XChaCha20-Poly1305 uses a 192-bit nonce, giving a birthday bound of 2^96 -- large enough that random nonce generation is safe without any coordination or counter management. AES-GCM's 96-bit nonce provides only a 2^48 birthday bound, which is dangerously low for a protocol where many independent clients may encrypt without coordination. Beyond nonces, XChaCha20 is inherently constant-time and performs well in software on all platforms, while AES-GCM requires hardware AES-NI instructions for both speed and side-channel resistance.

| Factor                    | XChaCha20-Poly1305         | AES-GCM                       |
| ------------------------- | -------------------------- | ----------------------------- |
| Nonce size                | 192 bits (random-safe)     | 96 bits (collision risk)      |
| Hardware acceleration     | Not required               | Required for speed            |
| Timing attacks            | Immune by design           | Vulnerable without AES-NI     |
| Implementation complexity | Simple                     | Complex (requires care)       |
| Software performance      | Excellent on all platforms | Slow without hardware support |

**Curve25519 over NIST curves.** Curve25519's parameters are fully transparent and documented, eliminating the trust concerns surrounding NIST P-256's unexplained seed values. The Montgomery ladder implementation is inherently side-channel resistant, whereas NIST curves require careful implementation to avoid timing leaks. Curve25519 carries no patent encumbrances and enjoys high community trust. NIST P-256 remains under suspicion of NSA influence due to its opaque parameter generation.

**Ed25519 over ECDSA.** Ed25519 produces deterministic signatures that do not depend on a random number generator. This is not merely a convenience property -- it is a safety property. ECDSA requires a perfect RNG for every signature; a single weak or reused nonce leaks the private key entirely. This failure mode has caused real-world disasters, including the Sony PS3 private key extraction and multiple Bitcoin wallet thefts. Ed25519 eliminates this entire class of catastrophic failure.

**BLAKE3 over SHA-256.** BLAKE3 is approximately 12 times faster than SHA-256 in software and natively parallelizable through its Merkle tree construction, which matters for a protocol that handles large files. BLAKE3 is immune to length extension attacks by design, while SHA-256 is vulnerable to them. For a modern protocol with no legacy compatibility requirements, BLAKE3 is the strictly superior choice.

### 5.3 File Encryption Flow

The encryption flow proceeds in seven steps. First, the sender generates an ephemeral key pair (e_priv, e_pub). Second, the sender performs an ECDH key exchange: shared_secret = X25519(e_priv, recipient_public_key). Third, the sender derives a file key using HKDF: the pseudorandom key PRK is extracted from the shared secret using a random salt, and then expanded with the context string "file-encryption" concatenated with the file ID to produce a 32-byte file key. A nonce key is derived separately with the context "nonce-generation." Fourth, a random nonce is generated by hashing the nonce key with 16 random bytes through BLAKE3 and taking the first 24 bytes. Fifth, the file is encrypted: ciphertext = XChaCha20-Poly1305.Encrypt(file_key, nonce, plaintext, aad). Sixth, the sender signs the complete package (ephemeral public key, salt, nonce, and ciphertext) with their Ed25519 private key. Seventh, the signature is appended and the encrypted package is uploaded.

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

Decryption reverses this process. The recipient first verifies the Ed25519 signature to confirm authenticity, rejecting the package if verification fails. The ephemeral public key is extracted from the first 32 bytes of the package, and the recipient performs ECDH with their own private key to recover the shared secret. The same HKDF derivation produces the file key. Decryption with XChaCha20-Poly1305 simultaneously verifies the authentication tag; any modification to the ciphertext causes an immediate rejection.

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

In a traditional sharing protocol, a single link contains both the blob location and the decryption key. Stealing that link grants complete access. The Aegis protocol splits this into two independent artifacts: the **ShareLink** carries the blob location and encrypted metadata, while the **ShareKey** carries the ephemeral public key and salt needed for decryption. These two artifacts are designed to travel through separate channels -- the link might be sent by email while the key is delivered by QR code, voice, or a separate messaging service.

```
TRADITIONAL SHARING:
+-------------------------------------------------------------+
|  link = https://server.example.com/file/abc123?key=SECRET   |
|                                                             |
|  PROBLEM: Link theft = complete access                      |
+-------------------------------------------------------------+

SPLIT-KEY SHARING:
+-------------------------------------------------------------+
|  Artifact A: https://server.example.com/file/abc123         |
|              (encrypted blob location)                      |
|                                                             |
|  Artifact B: aegis:key:xyzABC123...                         |
|              (decryption key via separate channel)           |
|                                                             |
|  Both artifacts required for access                         |
+-------------------------------------------------------------+
```

An attacker who compromises only one channel -- intercepting the share link from an email, for instance -- obtains nothing more than the location of an encrypted blob they cannot decrypt. Compromising both channels simultaneously is a materially harder attack.

### 5.5 Per-File Ephemeral Keys

Every file encrypted under the Aegis protocol uses a unique, freshly generated ephemeral key pair. File 1 produces (e1_priv, e1_pub), which derives shared_secret_1 and file_key_1. File 2 produces an entirely independent (e2_priv, e2_pub), shared_secret_2, and file_key_2. The ephemeral private keys are discarded immediately after encryption.

This design provides forward secrecy at the file level: compromising one file's key reveals nothing about any other file. There is no master key whose compromise would unlock everything, and no key is ever reused across files.

### 5.6 Identity Architecture

The Aegis protocol replaces account-based identity with pure cryptographic identity. An Ed25519 public key is a complete identity. No email address, phone number, or personal information is required or accepted. Users may optionally assign themselves a display name (e.g., "aziz#3281"), which is stored in encrypted form and has no protocol significance.

Identity generation is entirely local: the client generates an Ed25519 keypair, stores the private key in whatever secure storage the implementation provides, and uses the public key as its identity. There is no registration server, no account creation endpoint, and no identity provider.

There is no server-side account recovery. If a user loses their private key, they lose access to everything encrypted to it. This is a security feature, not a limitation: it means there is no recovery mechanism that an attacker could exploit. Users are expected to maintain encrypted key backups and guard their recovery phrases.

---

## 6. Protocol Flows

### 6.1 File Upload Flow

The upload flow begins on the user's device and involves a single round-trip to the server. The client selects a file, generates an ephemeral keypair, performs ECDH with the recipient's public key to derive a shared secret, runs HKDF to produce a file key, encrypts the file with XChaCha20-Poly1305, encrypts the metadata (filename, size, type) separately, signs the entire package with Ed25519, and uploads the encrypted blob via `POST /upload`.

The server receives the blob as opaque bytes, generates a random blob_id unrelated to the content, stores the blob with its TTL, and returns the blob_id to the client. The server knows only the blob_id, the blob's size, and its TTL. It does not know the content, filename, sender, or intended recipient.

The client then constructs a ShareLink containing the blob_id and server location, and separately stores or shares the ShareKey through an independent channel.

```
+-------------------------------------------------------------+
|                        USER DEVICE                          |
+-------------------------------------------------------------+
|                                                             |
|  1. User selects file                                       |
|                     |                                       |
|                     v                                       |
|  2. Generate ephemeral keypair: (e_priv, e_pub)             |
|                     |                                       |
|                     v                                       |
|  3. ECDH with recipient public key -> shared_secret         |
|                     |                                       |
|                     v                                       |
|  4. HKDF -> file_key                                        |
|                     |                                       |
|                     v                                       |
|  5. XChaCha20-Poly1305.Encrypt(file_key, nonce, file)       |
|                     |                                       |
|                     v                                       |
|  6. Encrypt metadata (filename, size, type)                 |
|                     |                                       |
|                     v                                       |
|  7. Ed25519.Sign(sender_key, package)                       |
|                     |                                       |
|                     v                                       |
|  8. POST /upload (encrypted_blob)                           |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                         SERVER                              |
+-------------------------------------------------------------+
|                                                             |
|  9. Receive encrypted blob (opaque bytes)                   |
|                     |                                       |
|                     v                                       |
|  10. Generate random blob_id (unrelated to content)         |
|                     |                                       |
|                     v                                       |
|  11. Store blob with TTL                                    |
|                     |                                       |
|                     v                                       |
|  12. Return blob_id to client                               |
|                                                             |
|  Server knows: blob_id, size, TTL                           |
|  Server does NOT know: content, filename, sender, recipient |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                      USER DEVICE                            |
+-------------------------------------------------------------+
|                                                             |
|  13. Construct share link: server.example.com/file/{id}     |
|                     |                                       |
|                     v                                       |
|  14. Separately store/share decryption key                  |
|      - Key stored locally                                   |
|      - Key shared via separate channel (QR, message)        |
|                                                             |
+-------------------------------------------------------------+
```

### 6.2 File Download Flow

The download flow is the inverse. The recipient receives the ShareLink through one channel and the ShareKey through another. The recipient's client fetches the encrypted blob from the server via `GET /download/{blob_id}`. The server retrieves the blob from storage and returns it as opaque bytes.

Back on the recipient's device, the client verifies the Ed25519 signature for authenticity, extracts the ephemeral public key from the package, performs ECDH with the recipient's private key to recover the shared secret, derives the file key through HKDF, decrypts the file with XChaCha20-Poly1305 (which simultaneously verifies the authentication tag), decrypts the metadata, and wipes the decryption key from memory.

```
+-------------------------------------------------------------+
|                    RECIPIENT DEVICE                         |
+-------------------------------------------------------------+
|                                                             |
|  1. Receive share link: server.example.com/file/{blob_id}   |
|                     |                                       |
|                     v                                       |
|  2. Receive decryption key via separate channel             |
|                     |                                       |
|                     v                                       |
|  3. GET /download/{blob_id}                                 |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                         SERVER                              |
+-------------------------------------------------------------+
|                                                             |
|  4. Retrieve encrypted blob from storage                    |
|                     |                                       |
|                     v                                       |
|  5. Return encrypted blob (opaque bytes)                    |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                    RECIPIENT DEVICE                         |
+-------------------------------------------------------------+
|                                                             |
|  6. Verify Ed25519 signature (authenticity)                 |
|                     |                                       |
|                     v                                       |
|  7. Extract e_pub from package                              |
|                     |                                       |
|                     v                                       |
|  8. ECDH with own private key -> shared_secret              |
|                     |                                       |
|                     v                                       |
|  9. HKDF -> file_key                                        |
|                     |                                       |
|                     v                                       |
|  10. XChaCha20-Poly1305.Decrypt(file_key, nonce, blob)      |
|                     |                                       |
|                     v                                       |
|  11. Verify authentication tag (integrity)                  |
|                     |                                       |
|                     v                                       |
|  12. Decrypt metadata (filename, size, type)                |
|                     |                                       |
|                     v                                       |
|  13. Wipe decryption key from memory                        |
|                                                             |
+-------------------------------------------------------------+
```

### 6.3 P2P Transfer Flow (High-Security Mode)

When both parties are online simultaneously, the protocol supports a direct peer-to-peer transfer path that bypasses the server entirely for data transfer. The server's only role is NAT traversal assistance: it exchanges connection information (STUN/TURN-like) between peers without learning anything about the file content or keys.

Once connectivity is established, the peers negotiate a Noise Protocol tunnel using the XX handshake pattern, which provides mutual authentication, forward secrecy, and identity hiding. Ephemeral session keys are generated for the tunnel. The encrypted file is transferred directly through this tunnel -- the server never sees the data. After transfer, both sides verify integrity and destroy all session keys.

```
+-------------------------------------------------------------+
|                        SENDER                               |
+-------------------------------------------------------------+
|                                                             |
|  1. Request P2P mode                                        |
|                     |                                       |
|                     v                                       |
|  2. Request P2P handshake info from server                  |
|     (NAT traversal assistance only)                         |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                         SERVER                              |
+-------------------------------------------------------------+
|                                                             |
|  3. Exchange connection info (STUN/TURN-like)               |
|     Server learns: IP addresses (already knows)             |
|     Server does NOT learn: file content, keys               |
|                                                             |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                  DIRECT CONNECTION                          |
+-------------------------------------------------------------+
|                                                             |
|  4. Establish Noise Protocol tunnel (XX pattern)            |
|     - Mutual authentication                                 |
|     - Forward secrecy                                       |
|     - Identity hiding                                       |
|                                                             |
|  5. Generate ephemeral session keys                         |
|                                                             |
|  6. Transfer encrypted file directly                        |
|     - Server never sees the data                            |
|     - Connection fully encrypted end-to-end                 |
|                                                             |
|  7. Verify integrity, destroy session keys                  |
|                                                             |
+-------------------------------------------------------------+
```

---

## 7. Protocol Wire Formats and State Machine

### 7.1 Formal Message Format Specification

All Aegis Protocol messages are serialized as JSON (UTF-8) for control plane messages and raw binary for data plane blobs.

**ShareLink Format:**
```json
{
  "v": 1,
  "s": "https://server.example.com",
  "b": "base64url(blob_id)",
  "m": "base64url(encrypted_metadata)"
}
```

**ShareKey Format:**
```json
{
  "v": 1,
  "ep": "base64url(ephemeral_public_key)",
  "sl": "base64url(salt)",
  "id": "base64url(file_id)"
}
```

**EncryptedPackage Format (Binary Blob):**
- `[0..1]` Version (0x01)
- `[1..33]` Ephemeral Public Key
- `[33..65]` Salt
- `[65..89]` XChaCha20 Nonce
- `[89..end-64]` Ciphertext
- `[end-64..end]` Ed25519 Signature

### 7.2 Protocol State Machine

The protocol defines strict, one-way state transitions for a client encryption session. A conforming implementation must not permit backward transitions, as reuse of ephemeral material would violate forward secrecy.

1. `INIT` -> `KEY_GEN` (Client generates ephemeral keys)
2. `KEY_GEN` -> `ENCRYPTING` (File chunks processed)
3. `ENCRYPTING` -> `UPLOADING` (Pushed to server)
4. `UPLOADING` -> `SHARE_GEN` (Links generated)
5. `SHARE_GEN` -> `DONE` (Secure wipe of memory)

### 7.3 Versioning and Negotiation Mechanism

The protocol uses a strict major.minor versioning schema. Major version changes indicate incompatible cryptographic modifications -- a change in cipher suite, key derivation parameters, or wire format structure. Minor version changes add optional metadata fields while retaining full wire-compatibility with the same major version.

During a P2P Noise handshake, peers must negotiate the highest mutually supported protocol version or fail closed. Servers do not participate in version negotiation because they handle only opaque blobs and are version-unaware by design.

### 7.4 Standardized Error Code Taxonomy

| Code             | Category       | Meaning                       | Required Action                    |
| ---------------- | -------------- | ----------------------------- | ---------------------------------- |
| `AEG-CRYPTO-01`  | Cryptography   | MAC verification failed       | Terminate immediately, wipe memory |
| `AEG-NET-01`     | Network        | Server unreachable            | Retry with exponential backoff     |
| `AEG-STATE-01`   | State          | Invalid transition attempted  | Halt execution                     |
| `AEG-AUTH-01`    | Authentication | Invalid signature             | Reject payload                     |

### 7.5 Interoperability Requirements

A conforming implementation must support Ed25519, X25519, XChaCha20-Poly1305, and BLAKE3 exactly as specified in their respective standards. It must accept and emit the precise JSON keys defined in §7.1 for control plane messages, and produce binary EncryptedPackage blobs that conform to the byte layout specified above. Any payload containing unknown or malformed fields in the cryptographic headers must be rejected.

### 7.6 Compliance Test Suite

To verify conformance with the Aegis Protocol, an implementation must pass a standardized test suite covering three areas: **test vectors**, which verify correct decryption of static known-good EncryptedPackage blobs using known keys; **negative tests**, which verify rejection of blobs with bit-flips in the MAC, invalid nonces, or malformed JSON fields; and **state machine tests**, which verify that invalid state transitions (e.g., `INIT` directly to `UPLOADING`) are rejected.

---

## 8. Security Analysis

This section presents the protocol's threat model, analyzes specific attack vectors, and maps the protocol's defenses to the CIA triad. Rather than enumerating protections in isolation, each threat is analyzed as a scenario with a specific argument for why the protocol's design defeats it.

### 8.1 Threat Landscape and Attacker Models

The protocol is designed to resist five primary attacker models, listed in order of real-world significance.

**Server Compromise.** The most common and consequential attack on file sharing services is a breach of the server infrastructure -- whether through a hacked cloud provider, a physically breached datacenter, or an insider who copies disk contents. The Aegis protocol renders this attack meaningless by ensuring the server never possesses decryption keys and stores only encrypted blobs. An attacker who gains root access to every server obtains terabytes of data that is computationally indistinguishable from random noise. There are no keys to steal, no metadata to correlate, and no plaintext to read. The attack succeeds at the infrastructure level but fails completely at the data level.

**Malicious Insiders.** A rogue administrator poses a more dangerous threat than an external hacker because they have legitimate access and knowledge of the architecture. Against most services, this is a devastating position. Against the Aegis protocol, it is worthless. The zero-trust design means an administrator can view encrypted blobs, access rate limiting counters, and read TTL expiry times -- but cannot decrypt any file, identify any user, correlate any activity, or recover any key. Privileged server access provides zero advantage over an anonymous external observer.

**Government Data Requests and Surveillance.** Governments prefer metadata over content because metadata reveals behavioral patterns -- who communicates with whom, when, and how often. Legal compulsion is difficult to resist. The Aegis protocol's defense is architectural: no metadata is stored, no user identities exist on the server, and the server operator's truthful response to any data request is "we have no data to provide." This is exactly the approach that Signal and Proton have validated in practice.

**Network Attackers (MITM and Link Interception).** Intercepting share links over WiFi, through ISP monitoring, or via man-in-the-middle attacks is common and easy. The split-key architecture defeats this by ensuring that a captured ShareLink alone is useless -- the attacker obtains only the location of an encrypted blob they cannot decrypt. The decryption key travels through a separate channel. Even if the network layer is completely compromised, the attacker must independently compromise the second channel to gain access. Additionally, all transport is protected by TLS 1.3 or QUIC, and all content is end-to-end encrypted with per-file ephemeral keys.

**Mass-Scale Platform Attacks.** Large-scale database dumps and data harvesting attacks target platforms precisely because they store valuable, readable data. The Aegis protocol removes this incentive entirely. A complete database dump yields only encrypted blobs with random IDs. There is no user table to exfiltrate, no password hashes to crack, and no metadata to correlate across users. Each file's key is unique, so even a theoretical break of one file's encryption reveals nothing about any other file.

### 8.2 Detailed Attack Scenarios

**Server Breach Scenario.** An attacker gains root access to all servers and storage. They obtain encrypted blobs (random bytes), blob IDs (random strings), TTL metadata (expiry times), and rate limiting counters. They do not obtain decryption keys (which were never on the server), file contents, file names, user identities (only anonymous tokens), communication patterns, or any correlation between users. The attacker has terabytes of data and zero actionable intelligence.

**Link Theft Scenario.** An attacker intercepts a share link from an email or messaging conversation. In a traditional protocol where the link contains both the URL and the decryption key, this is a complete compromise. Under the Aegis split-key design, the link contains only the blob location. The decryption key was delivered separately -- via QR code, voice call, or a different messaging channel. The attacker has the location of an encrypted blob and no means to decrypt it. Compromising one channel is insufficient; both the link and the key are required.

**Malicious Insider Scenario.** A server administrator attempts to access user files. The administrator can view encrypted blobs, access rate limiting data, see TTL expiry times, and read server logs (which contain minimal information). The administrator cannot decrypt any file, identify any user, see file names, correlate activity across users, or recover any key. Their privileged access provides no advantage.

### 8.3 Security Properties Summary

The following table summarizes the protocol's protection level against each attacker model. The distinction between "immune" and "protected" is precise: "immune" means the protocol's design makes the attack mathematically futile regardless of the attacker's resources. "Protected" means the protocol significantly raises the cost of attack but cannot eliminate the threat entirely. "Exposed" means the threat is fundamentally outside the reach of any cryptographic protocol.

| Attacker Model             | Protection Level | Reasoning                                                       |
| -------------------------- | ---------------- | --------------------------------------------------------------- |
| Server breach              | Immune           | No useful data exists on the server                             |
| Insider threat             | Immune           | Zero-trust: privileged access provides no advantage             |
| Network attacker / MITM    | Immune           | Split-key + E2EE + TLS: no single interception point suffices   |
| Mass-scale data harvesting | Immune           | No readable data, no metadata to correlate                      |
| Government data requests   | Strong           | No data to compel; validated by Signal/Proton precedent         |
| Traffic correlation        | Protected        | Padding and P2P help, but timing analysis remains possible      |
| Targeted device malware    | Protected        | Out of protocol scope; implementation-level vault defenses help |
| Endpoint compromise        | Exposed          | Malware on user device can always capture decrypted content     |
| Social engineering         | Exposed          | Humans are vulnerable regardless of protocol design             |
| Physical coercion          | Exposed          | Users can be forced to reveal keys                              |

### 8.4 CIA Triad Alignment

**Confidentiality.** The protocol achieves confidentiality through four reinforcing mechanisms. XChaCha20-Poly1305 encrypts all content with 256-bit keys. Per-file ephemeral keys ensure each file is independently secured, so compromising one key reveals nothing about others. The zero-knowledge server design means the server cannot read content even if compromised. Split-key delivery ensures that intercepting the share link alone reveals nothing. All metadata -- including filenames and file sizes -- is encrypted.

**Integrity.** Every encrypted package carries three layers of integrity protection. The Poly1305 authentication tag detects any modification to the ciphertext. The Ed25519 signature verifies sender authenticity and prevents forgery. BLAKE3 hashing provides content integrity verification for large files processed in chunks. Any tampering at any layer is immediately detected.

**Availability.** The protocol supports availability through stateless server design (enabling horizontal scaling), P2P fallback (allowing transfers to proceed even if the server is unreachable), and TTL-based automatic cleanup (preventing unbounded storage growth). Multi-region storage is a deployment concern outside the protocol's scope but is compatible with the protocol's design since servers handle only opaque blobs.

**Forward Secrecy.** Ephemeral keys are discarded after use. Even if a user's long-term identity key is later compromised, files encrypted with past ephemeral keys remain protected. P2P sessions use key ratcheting for additional forward secrecy.

**Non-Repudiation.** Ed25519 signatures on every encrypted package prove sender identity. Recipients can verify authenticity, and senders cannot deny having created signed content.

**Anonymity.** No personal identifiers are required at any point in the protocol. Identity is purely key-based. The server maintains no meaningful logs. Users are anonymous by default.

---

## 9. Algorithm Justification

This section provides detailed technical justification for each algorithm choice. The comparative tables in §5.2 summarize the selection criteria; this section provides the deeper reasoning.

### 9.1 XChaCha20-Poly1305 vs AES-GCM

The protocol requires an AEAD cipher that is safe under random nonce generation, because independent clients will encrypt files without any coordination or shared counter. XChaCha20-Poly1305's 192-bit nonce provides a birthday bound of 2^96, making random nonce collisions negligible even at enormous scale. AES-GCM's 96-bit nonce limits the birthday bound to 2^48, which is dangerously low for an uncoordinated protocol.

Beyond nonces, XChaCha20 is inherently constant-time: its operations are additions, XORs, and rotations, with no data-dependent memory accesses or branching. AES without hardware AES-NI is vulnerable to cache-timing attacks that leak key material. XChaCha20 achieves excellent software performance on all platforms, while AES-GCM is slow and insecure without hardware acceleration.

### 9.2 Ed25519 vs ECDSA

The protocol requires deterministic signatures. Ed25519 derives its nonce from the message and private key using a hash function, eliminating any dependency on a random number generator. ECDSA requires a cryptographically strong random nonce for every signature. If that nonce is weak, reused, or predictable, the private key is immediately recoverable. This is not a theoretical risk -- the Sony PS3 ECDSA key was extracted because Sony reused a nonce, and multiple Bitcoin wallets have been drained due to weak ECDSA nonces.

### 9.3 BLAKE3 vs SHA-256

The protocol handles files that may be large. BLAKE3's Merkle tree construction enables native parallelism, achieving roughly 10x the throughput of SHA-256 on multi-core systems. SHA-256 processes data strictly sequentially. BLAKE3 is also immune to length extension attacks by design, while SHA-256 requires HMAC or similar constructions to avoid this vulnerability class.

### 9.4 Rejected Technologies

Certain technologies are explicitly excluded from any conforming implementation. Blockchain adds nothing to the security model and leaks metadata through its public ledger. Smart contracts introduce unnecessary complexity. AI in the cryptographic path is unverifiable and introduces non-determinism. Node.js for cryptographic operations suffers from memory management limitations and supply-chain risk through its dependency ecosystem. Custom cryptography -- designing novel ciphers or protocols rather than using established, audited primitives -- is categorically rejected.

---

## 10. Protocol Differentiation

### 10.1 Comparison with Existing File Sharing Protocols

Unlike existing file-sharing mechanisms -- standard HTTPS uploads, WebRTC transfers, or application-layer encryption in consumer applications -- the Aegis Protocol provides strict zero-trust (the protocol does not permit the server to access plaintext or keys), key-based identity (no accounts or emails required at the protocol level), split-key distribution (separate channels for the encrypted blob location and the decryption key), and hybrid transport (seamless fallback between P2P Noise tunnels and server-relayed blob retrieval).

### 10.2 What the Protocol Rejects

The Aegis protocol explicitly rejects account-based identity systems (emails, phone numbers), server-side metadata logging (filenames, file types, user activity), and any reliance on server-side access control lists for security. Security in the Aegis protocol is enforced by cryptography, not by access controls that depend on server integrity.

---

## 11. Limitations and Known Weaknesses

### 11.1 Fundamental Limitations

Five classes of threat cannot be solved by any cryptographic protocol. A compromised recipient can always screenshot, re-share, or otherwise leak a decrypted file -- cryptography protects data in transit and at rest, not after intentional disclosure. Physical coercion can force a user to reveal keys. Endpoint malware such as keyloggers and screen capture tools bypasses all cryptography by operating on decrypted content. A nation-state adversary with unlimited resources may discover unknown attack vectors. User error -- weak passphrases, careless key management, or social engineering susceptibility -- remains outside the reach of protocol design.

### 11.2 Design Trade-offs

Every protocol makes trade-offs. The following table documents the Aegis protocol's deliberate choices and their consequences for conforming implementations.

| Trade-off             | Choice Made               | Consequence for Implementations                                           |
| --------------------- | ------------------------- | ------------------------------------------------------------------------- |
| No account recovery   | Security over convenience | Implementations must not provide server-side key recovery mechanisms      |
| Split-key sharing     | Security over simplicity  | Implementations must support at least two independent delivery channels   |
| No server-side search | Privacy over features     | Search must be performed entirely on the client against local state       |
| Random nonces         | Security over determinism | Implementations must include a CSPRNG; ciphertext is slightly larger      |

### 11.3 Residual Attack Scenarios

**Advanced Persistent Threat (APT) targeting a specific user.** An attacker who can install malware on a user's device can capture encryption keys in memory and exfiltrate decrypted files. The protocol's cryptographic protections are irrelevant once the endpoint is compromised. Implementation-level defenses (secure memory allocation, vault locking) can raise the difficulty but cannot eliminate this threat.

**Traffic correlation attack.** A global adversary who monitors network traffic can correlate the timing of uploads and downloads to infer communication patterns between users. P2P transfers reduce exposure by removing the server from the data path, and padding can obscure transfer sizes, but timing analysis by a sufficiently resourced adversary remains possible. This is a fundamental limitation shared with every practical network protocol.

---

## 12. Regulatory and Compliance Context

The Aegis Protocol is a mathematical specification. As such, it cannot itself be regulated. However, implementations of the protocol -- particularly server deployments -- may face regulatory scrutiny in certain jurisdictions.

### 12.1 Export Control

Cryptographic software implementing this protocol may be subject to export controls in some jurisdictions. Implementers should avoid distribution to sanctioned countries and should note that standard open-source exemptions for published cryptographic software usually apply.

### 12.2 Server Operator Considerations

The protocol's design creates a specific regulatory posture for server operators. The server possesses no decryption keys or plaintext content. It cannot comply with requests for user data beyond delivering encrypted blobs. Operators should structure their terms of service to reflect their technical inability to access the data they store. This is the same posture adopted by Signal and Proton Mail.

---

## 13. Conclusion

### 13.1 Summary

This specification defines a cryptographic protocol that achieves true zero-trust (server compromise reveals nothing by cryptographic necessity), provides anonymous identity (the protocol relies exclusively on key-pairs), implements defense-in-depth through five independent protection layers, uses only proven, audited cryptographic primitives (XChaCha20-Poly1305, Curve25519, Ed25519, BLAKE3), and maintains a clean separation between protocol layers and implementation layers to minimize attack surface.

### 13.2 The Protocol Vision

> _"A protocol where privacy is mathematically guaranteed, security is verifiable, and developers can build zero-trust applications without cryptographic expertise."_

This specification provides the blueprint. The implementation plan follows.

---

## Appendix A: Reference Implementation Decisions

While the Aegis Protocol is designed to be implementation-agnostic, the official reference application makes specific architectural and scope decisions to maximize security and minimize attack surface.

### A.1 The Vault Layer

The reference implementation employs a "Vault Layer" on the client device to ensure secure operation within the untrusted host environment (the user's OS).

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

The Vault Layer is responsible for memory hygiene, secure allocation (preventing sensitive data from being swapped to disk), and automatic locking upon inactivity.

### A.2 Scope Decision: No Native Mobile Clients

The reference implementation deliberately excludes native mobile applications (Android/iOS) from its scope. This is a principled security and engineering decision.

Each native mobile platform (Android via JNI, iOS via Swift FFI) introduces platform-specific bindings that create new categories of memory safety bugs at the FFI boundary -- use-after-free, double-free, and type confusion. These are precisely the vulnerability classes Rust was chosen to eliminate. Adding two FFI layers roughly triples the number of unsafe boundary crossings that must be audited.

Android Keystore and iOS Secure Enclave are opaque, vendor-controlled subsystems. Documented vulnerabilities in hardware TEEs mean that relying on them for root-of-trust moves security guarantees outside the auditable codebase.

Mobile operating systems routinely snapshot app state for task switchers, back up app data to cloud services, index file contents for search, and log IPC calls. Preventing these leaks requires per-OS workarounds that are fragile, version-dependent, and unverifiable. Distribution through app stores introduces gatekeepers who can inject code, demand metadata disclosure, and remotely revoke applications, conflicting with zero-trust principles.

A security audit of the Rust core plus a Tauri desktop client is a tractable, well-bounded problem. Adding two native mobile codebases with platform-specific secure storage roughly triples the audit surface without proportional security benefit. The engineering effort is better invested in hardening the cryptographic core.

### A.3 Why Tauri (Not Electron)

The reference implementation's desktop client uses Tauri rather than Electron. Tauri produces binaries of 3-10 MB versus Electron's 150+ MB, uses significantly less memory, delegates security updates to the OS WebView rather than requiring manual Chromium updates, presents a minimal attack surface compared to Electron's full Chromium engine, and enforces explicit IPC permissions rather than Electron's broad-by-default model.

### A.4 UX Challenges in the Reference Implementation

| Challenge             | Mitigation                         |
| --------------------- | ---------------------------------- |
| Key backup complexity | Clear UX, recovery phrase          |
| Split-key friction    | Optional for low-security shares   |
| No password recovery  | Extensive warnings, backup prompts |

---

**End of Protocol Specification**
