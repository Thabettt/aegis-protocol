# The Aegis Protocol

## Protocol Specification

**Project:** Aegis
**Author:** Abdulaziz
**Version:** 3.0 (draft)
**Date:** November 16, 2026
**Revision:** v3.0 — Complete redesign following the v2.1 audit (`Aegis_audit_report.md`). Replaces v2.1 in full. Not wire-compatible with any earlier draft.

---

## 0. Status of this document

This is a draft for review. It has not been independently audited and has no machine-checked proof. The wire format is not frozen; it freezes at milestone M4 of `Aegis_implementation_plan.md`, after an independent implementation reproduces the test vectors.

Do not use this protocol to protect anyone at real risk until that work is complete.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

Companion documents:

| Document | Purpose |
|----------|---------|
| `Aegis_audit_report.md` | Why v2.1 was withdrawn; finding IDs (AEG-nn) referenced below |
| `Aegis_research.md` | Design rationale, security analysis, prior art |
| `Aegis_implementation_plan.md` | Build, verification and audit plan |
| `Aegis_engineering_standard.md` | Binding architecture and assurance rules for implementers |
| `model/aegis_v3_model.py` | Executable model of §3–§11; generates the test vectors |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Security Model](#2-security-model)
3. [Cryptographic Suite](#3-cryptographic-suite)
4. [Artifacts](#4-artifacts)
5. [Share Modes](#5-share-modes)
6. [Key Schedule](#6-key-schedule)
7. [Blob Format](#7-blob-format)
8. [Procedures](#8-procedures)
9. [Identity](#9-identity)
10. [Storage Service](#10-storage-service)
11. [Live Transfer](#11-live-transfer)
12. [Errors](#12-errors)
13. [Versioning and Extensibility](#13-versioning-and-extensibility)
14. [Conformance](#14-conformance)
15. [Security Considerations](#15-security-considerations)
16. [Changes from v2.1](#16-changes-from-v21)

Appendices: [A Constants](#appendix-a-constants) · [B Padmé](#appendix-b-padmé-reference) · [C Reference implementation notes](#appendix-c-reference-implementation-notes) · [D Test vectors](#appendix-d-test-vectors) · [E Deferred features](#appendix-e-deferred-features)

---

## 1. Introduction

### 1.1 What Aegis is

> _"A protocol so solid that even the operator can't breach it without the user's key."_

Aegis is a protocol for handing a file to another person through a server that is assumed to be hostile.

A sender **seals** a file into an encrypted **blob** and two short **artifacts**: a **ShareLink** and a **ShareKey**. The blob goes to a storage server, or directly to the recipient through a relayed live tunnel. The artifacts travel to the recipient over two different channels chosen by the sender. The recipient combines them to locate, authenticate and decrypt the blob.

The server stores bytes it cannot distinguish from random noise, under an address it cannot connect to anyone. It has no accounts, sees no public keys, and has no say in whether a decryption succeeds.

Optionally, a share can also be **addressed** to a recipient's public key, protected by a **passphrase**, and **signed** by the sender. These options combine freely.

### 1.2 Design principles

1. **The server is the adversary.** Not honest-but-curious: actively malicious, colluding with others, and keeping everything forever.
2. **Invariants are not negotiable.** §2.3 lists sixteen. A feature that breaks one is rejected.
3. **Every claim is checkable.** Each security property names the adversary it holds against and the assumption it rests on. Each byte on the wire is specified once and covered by a test vector.
4. **One way to do each thing.** One suite, no negotiation, no optional algorithms, fixed-size headers, strict parsing.
5. **Standard parts only.** Every primitive has a published specification and independent implementations. Aegis composes them; it invents none.
6. **Honest labels.** Anything the server merely promises (expiry, deletion, download limits) is called advisory, in the specification and in the user interface.

### 1.3 Conventions and notation

| Notation | Meaning |
|----------|---------|
| `a ‖ b` | Concatenation of byte strings |
| `\|x\|` | Length of `x` in bytes |
| `x[a:b]` | Bytes `a` (inclusive) to `b` (exclusive) |
| `u8(n)`, `u16(n)`, `u32(n)`, `u64(n)`, `u88(n)` | Unsigned big-endian integer of 1, 2, 4, 8, 11 bytes |
| `0^n` | `n` zero bytes |
| `random(n)` | `n` bytes from the operating system's CSPRNG |
| `"text"` | ASCII bytes of the string, no terminator |
| `ct_eq(a, b)` | Constant-time equality |
| `b32(x)` | RFC 4648 base32, lowercase, no padding (§4.3) |
| `hex(x)` | Lowercase hexadecimal |

All integers are big-endian. All lengths are in bytes unless stated.

---

## 2. Security Model

### 2.1 Parties

| Party | Role |
|-------|------|
| **Sender** | Seals a file; chooses the mode and the channels |
| **Recipient** | Holds the artifacts (and, for addressed shares, a KEM private key) |
| **Storage service** | Stores blobs by address; relays live sessions |
| **Channel A** | Whatever carries the ShareLink |
| **Channel B** | Whatever carries the ShareKey |

Channels A and B are outside the protocol. Aegis assumes nothing about them except that the sender chose them.

### 2.2 Adversaries

| Name | Capability |
|------|------------|
| **SRV** | Full control of the storage service and its storage: reads, modifies, withholds, replays, retains forever, and lies. Also observes all network traffic to and from it. |
| **NET** | Full control of the network between any two parties. |
| **A** | Has obtained the ShareLink. |
| **B** | Has obtained the ShareKey. |
| **RK** | Has obtained the recipient's KEM private keys that exist at the time of compromise. |
| **PW** | Knows the passphrase. |
| **Q** | Records everything now and has a cryptographically relevant quantum computer later. |
| **Malicious sender** | Follows no rules when constructing blobs and artifacts. |
| **Malicious recipient** | Holds everything a recipient legitimately holds. |

Adversaries collude freely. `SRV + A` means the server working together with someone who stole the link.

### 2.3 Invariants

These sixteen properties MUST hold in every conforming implementation, in every mode. I1–I6 are the six invariants of v2.1, restated so that each can be tested. I7–I16 are new.

| # | Invariant | Tested by |
|---|-----------|-----------|
| **I1** | The server never sees plaintext. | Construction (§7); server receives only blob bytes |
| **I2** | The server never possesses a decryption key, nor any value from which one can be computed. | §6: every server-visible value is a one-way output |
| **I3** | A complete server compromise reveals nothing — precisely, nothing outside the leakage set of §2.6. | §2.6; model lemma `server_view_pseudorandom` |
| **I4** | Every file is encrypted under an independent key. | §8.1 step 2: fresh `LS` per seal |
| **I5** | All metadata is encrypted or meaningless. Names, types, exact sizes, the share mode and all identities are inside the encryption. | §7.3, §7.4, §6.2 |
| **I6** | Users are identified only by public keys, and no user's public key is ever visible to the server. | §7.5, §9; no account concept in §10 |
| **I7** | The split is cryptographic. In SPLIT mode, one artifact — even combined with SRV's entire state — yields no information about the plaintext, the names, or the parties. | §6.1; model lemma `split_2of2` |
| **I8** | Every symmetric key encrypts exactly one message sequence, exactly once. Ciphertext, once produced, is immutable; retries and resumptions replay stored bytes. | §8.1, §8.4 |
| **I9** | No unauthenticated plaintext is released, and no transfer is reported complete before its final chunk has verified. | §8.3 |
| **I10** | Every derived key is bound to the complete public context: version, mode, blob address, header, and recipient. | §6.4 |
| **I11** | One blob, one plaintext. No blob can be opened to two different plaintexts under two different sets of keys. | §6.6 |
| **I12** | Sender identity never appears outside the encryption. | §7.5 |
| **I13** | The server has no authority. Whatever it asserts is either verified cryptographically or presented as advisory. | §10.6, §14 |
| **I14** | No secret is ever sent to a server: not in a URL, a header, or a body. The only share-derived values a server ever receives are the capabilities of §10.3: one-way outputs that decrypt nothing, each sent only to the share's own origin. | §4.4, §10.3, §10.8 |
| **I15** | Fail closed. There is no negotiation, no fallback and no downgrade path. | §13 |
| **I16** | Long-term keys do not decrypt beyond their epoch. KEM private keys are destroyed on schedule and are never derivable from the recovery seed. | §9.3, §9.6 |

### 2.4 What each mode guarantees

**Confidentiality.** The content, name and type of a shared file remain secret unless the adversary holds *every* factor in the row below. Adding SRV or NET to any coalition never shrinks the set.

| Mode | Factors the adversary needs | Unaffected by Q? |
|------|-----------------------------|------------------|
| sealed | A | Yes — symmetric only |
| sealed + split *(default)* | A and B | Yes — symmetric only |
| addressed | A and RK | Yes, while ML-KEM-768 holds |
| addressed + split | A and B and RK | Yes — needs A and B regardless |
| any of the above + passphrase | the above, and PW | As above |

A passphrase is worth only its entropy. An adversary holding all other factors can test guesses offline at the cost of one Argon2id evaluation each (§15.5).

**Integrity.** In every mode, any change to a blob by SRV or NET — modification, truncation, extension, reordering, substitution — is detected (I9, I11).

**Origin.**

| Share is | The recipient learns |
|----------|----------------------|
| unsigned | The blob was made by someone who held the artifacts. Nothing more. |
| signed | The blob was made by the holder of the named identity key, for this exact share and (if addressed) this exact recipient. Meaningful only if the recipient has verified that key (§9.5). |

Encrypting to a public key authenticates nobody: anyone can do it.

**Forward secrecy** is stated per mode in §15.2.

### 2.5 Non-goals

Aegis does not and cannot protect against:

1. **Endpoint compromise.** Malware on either device sees plaintext.
2. **A malicious recipient.** Anyone who can read a file can leak it.
3. **Coercion.**
4. **Traffic analysis by an adversary who sees both ends.** Padding hides exact size, not timing or volume class.
5. **Denial of service by the server.** It can always refuse to store or serve.
6. **Loss of both artifacts through the sender's chosen channels.** If one party reads both channels, the split protects nothing against that party.

### 2.6 What the server learns

This is the complete leakage set **L**. I3 is the claim that SRV learns nothing else.

| Item | Detail |
|------|--------|
| Blob length | One of the Padmé size classes of §7.4; never below 66,752 bytes |
| Blob address | 32 pseudorandom bytes, unlinkable to any party or to any other blob |
| Two delete verifiers | 32 pseudorandom bytes each |
| Requested lifetime | `Aegis-Ttl`, and `Aegis-Max-Fetches` if set |
| Timing | Time of upload, of every fetch and byte range, of deletion. §10.8 rule 6 keeps the fetch pattern independent of the share's mode. |
| Which delete capability was used | Owner or burn |
| Network metadata | Client addresses and transport fingerprints, unless the client uses an anonymising transport (§15.4) |
| Admission stamp | Proof-of-work bound to the blob address; carries no identity |
| Live sessions | Rendezvous address, both peers' network metadata, timing, byte counts |

The server does **not** learn: content, name, type, exact size, the share mode, whether a passphrase or signature is used, any public key, the sender, the recipient, or whether two blobs are related.

---

## 3. Cryptographic Suite

### 3.1 Primitives

Aegis v3 has exactly one suite.

| Function | Primitive | Reference |
|----------|-----------|-----------|
| Hash | SHA-512 | FIPS 180-4 |
| Key derivation | HKDF-SHA-512 | RFC 5869 |
| AEAD | ChaCha20-Poly1305, 96-bit nonce, 128-bit tag | RFC 8439 |
| KEM | X-Wing (X25519 + ML-KEM-768) | draft-connolly-cfrg-xwing-kem; FIPS 203; RFC 7748 |
| Signature | Ed25519 (pure) | RFC 8032 |
| Passphrase hashing | Argon2id v1.3 | RFC 9106 |
| Live handshake | `Noise_NNpsk0_25519_ChaChaPoly_SHA512` | Noise Protocol Framework, revision 34 |

Sizes:

| Object | Bytes |
|--------|-------|
| Symmetric key, secret, blob address, token, commitment | 32 |
| HKDF pseudorandom key, SHA-512 output, transcript hash | 64 |
| AEAD nonce / tag | 12 / 16 |
| X-Wing public key / ciphertext / shared secret / private seed | 1216 / 1120 / 32 / 32 |
| Ed25519 public key / signature / seed | 32 / 64 / 32 |

X-Wing is specified in an Internet-Draft. Implementations MUST reproduce that draft's test vectors. If the published RFC differs from it in any output byte, adopting the RFC is a new Aegis version (§13).

### 3.2 Labelled derivation

Every hash, derivation and signature in Aegis is domain-separated by a label.

```
PROTO           = "AEGIS-v3"                                   (8 bytes)
Ctx(label)      = PROTO ‖ u8(|label|) ‖ label

LExtract(salt, label, ikm)   = HKDF-Extract(salt, Ctx(label) ‖ ikm)             → 64 bytes
LExpand(prk, label, info, L) = HKDF-Expand(prk, u16(L) ‖ Ctx(label) ‖ info, L)  → L bytes
LHash(label, data)           = SHA-512(Ctx(label) ‖ data)                       → 64 bytes
LSign(sk, label, data)       = Ed25519.Sign(sk, Ctx(label) ‖ data)              → 64 bytes
```

An empty salt is the zero-length string; per RFC 5869 it is treated as 64 zero bytes.

The complete label registry. A label MUST NOT be used for any purpose other than the one listed.

| Label | Used in | Section |
|-------|---------|---------|
| `artifact` | LExtract — Stage A | §6.1 |
| `blob id`, `header key`, `burn token`, `live id`, `live psk`, `chain` | LExpand from Stage A | §6.1 |
| `header` | AEAD associated data | §6.2 |
| `recipient` | LHash — recipient binding | §6.3 |
| `transcript` | LHash — transcript | §6.4 |
| `root` | LExtract — Stage B | §6.5 |
| `commit`, `payload key` | LExpand from Stage B | §6.5 |
| `stream digest` | LHash — content digest under a sender signature | §7.5 |
| `sender signature` | LSign | §7.5 |
| `link check`, `key check`, `card check` | LHash — checksums | §4, §9.4 |
| `identity root` | LExtract | §9.2 |
| `identity key` | LExpand | §9.2 |
| `card` | LSign | §9.4 |
| `fingerprint` | LHash | §9.5 |
| `delete verifier` | LHash | §10.3 |
| `pow` | LHash | §10.4 |
| `live` | Noise prologue | §11.3 |
| `direct`, `direct psk` | LExtract / LExpand | §11.5 |
| `vault passphrase`, `vault wrap`, `vault record`, `record key` | Reference vault | App. C.1 |

### 3.3 Requirements on implementations of primitives

1. **Randomness.** `random(n)` MUST come from the operating system's CSPRNG. If it fails, the implementation MUST abort the process (`AEG-RNG-01`). There is no fallback source.
2. **Ed25519 signing** MUST follow RFC 8032 §5.1.6.
3. **Ed25519 verification** MUST be strict. A signature `(R, S)` under public key `A` is valid only if all of the following hold:
   - `S` is canonical: `S < L`, the group order;
   - `A` and `R` are canonical encodings: decoding and re-encoding yields the same 32 bytes;
   - neither `A` nor `R` is a small-order point;
   - the cofactorless equation `[S]B = R + [k]A` holds.
4. **ML-KEM.** An encapsulation key MUST pass the FIPS 203 §7.2 input checks before use.
5. **AEAD.** Tag comparison MUST be constant-time. Plaintext MUST NOT be returned when the tag fails.
6. **Comparisons** of commitments, tokens, verifiers and checksums MUST use `ct_eq`.
7. **Erasure.** Secret values MUST be overwritten as soon as they are no longer needed. §8.4 marks the points.
8. **No compression.** Implementations MUST NOT compress plaintext before sealing.

### 3.4 No algorithm agility

There are no algorithm identifiers on the wire and nothing is negotiated. The version number selects the entire suite. Replacing any primitive, any label, or any byte layout is a new version with a new `PROTO` string (§13).

---

## 4. Artifacts

An artifact is a short byte string with a text form. Artifacts are the only things a sender gives a recipient.

### 4.1 ShareLink

Carried on channel A.

```
offset  size  field
0       1     version      = 0x03
1       1     lflags       bit 0 SPLIT, bit 1 LIVE; bits 2–7 MUST be 0
2       32    LS           link secret
34      1     origin_len   n, 1..255
35      n     origin       ASCII
35+n    4     check        = LHash("link check", bytes[0 : 35+n])[0:4]
```

- **SPLIT** — a ShareKey exists and is required.
- **LIVE** — the sender is offering a live transfer (§11). A hint only; it is not bound into any key.
- **origin** — the storage service, as a lowercase ASCII web origin: `https://host[:port]`, or `http://host[:port]` only when `host` ends in `.onion`. No path, query, fragment or user information. Internationalised names MUST be in A-label form.

### 4.2 ShareKey

Carried on channel B. Present only when SPLIT is set.

```
offset  size  field
0       1     version = 0x03
1       32    KS      key secret
33      4     check   = LHash("key check", bytes[0:33])[0:4]
```

### 4.3 Text encoding

```
ShareLink   "aegis:link:" ‖ b32(link bytes)
ShareKey    "aegis:key:"  ‖ b32(key bytes)
```

`b32` is the RFC 4648 §6 alphabet in lowercase, without padding.

Decoders:

- MUST accept upper or lower case and MUST ignore ASCII spaces and hyphens, so that a key can be read aloud or typed in groups;
- MUST reject any other character, any `=` padding, and any encoding whose unused trailing bits are not zero;
- MUST read the version byte first and report anything other than `0x03` as `AEG-FMT-02`;
- MUST then verify `check` before using any other field, and report a mismatch as `AEG-FMT-01`.

A ShareKey is 60 characters. That is long but speakable, and it is a full 256-bit secret. Aegis does not define a shorter form: a short key is one the server can guess offline (AEG-20). Short spoken codes require a PAKE and are deferred (Appendix E).

The checksum exists to catch typing errors. It has no security function.

### 4.4 Handling rules

1. `LS` and `KS` MUST be produced by the seal operation from `random(32)`. An interface that lets a caller supply them MUST NOT exist.
2. `LS` and `KS` MUST NOT be sent to any server in any form (I14).
3. Artifacts MUST NOT be released to the user until the blob is durably stored, or a live session is ready (§8.4).
4. When SPLIT is set, a client MUST present the two artifacts as separate objects and MUST NOT offer an action that copies or sends both together.
5. A client MUST NOT register a handler that causes a ShareLink to be opened by a web page.
6. After a share is delivered, the sender SHOULD erase `LS` and `KS`, keeping only `blob_id` and the owner token (§10.3). After a successful open, the recipient SHOULD erase both artifacts.

---

## 5. Share Modes

### 5.1 Factors

A share's keys are derived from between one and four independent factors.

| Factor | Where it lives | Flag | Present |
|--------|----------------|------|---------|
| Link secret `LS` | ShareLink | — | Always |
| Key secret `KS` | ShareKey | `lflags` SPLIT | When split |
| KEM secret `ss_kem` | Recipient's KEM private key | `hflags` ADDRESSED | When addressed |
| Passphrase key `pw_key` | A human | `hflags` PASSPHRASE | When passphrase-protected |

SPLIT is carried in the link because the recipient must know to ask for the ShareKey before anything can be fetched. The other flags are inside the encrypted header, where neither the server nor anyone holding fewer than all artifacts can see them (I5).

### 5.2 Modes

| Name | Flags | Typical use |
|------|-------|-------------|
| **sealed + split** | SPLIT | The default. Recipient has no Aegis identity. Two channels. |
| **sealed** | — | Single-channel bearer share. Whoever has the link has the file. |
| **addressed** | ADDRESSED | Recipient has published a card. Link plus their private key. |
| **addressed + split** | SPLIT, ADDRESSED | Strongest. Two channels and the recipient's key. |

PASSPHRASE and SIGNED can be added to any mode.

### 5.3 Defaults and labelling

1. A client MUST default to SPLIT.
2. A client MAY create a share without SPLIT only by explicit user choice, and MUST label a share that has neither SPLIT nor ADDRESSED as **single-channel**: anyone who obtains the link can read the file.
3. A client MUST NOT describe an unsigned share as coming from any particular person.
4. A client MUST show the signer of a signed share as *verified*, or as *unverified* together with the full fingerprint (§9.5).

---

## 6. Key Schedule

```
   ShareLink            ShareKey
      LS                   KS (if SPLIT)
       └────────┬───────────┘
                ▼
        ┌───────────────┐
        │    Stage A    │  PRK_A = LExtract("", "artifact", mode ‖ LS [‖ KS])
        └───────┬───────┘
     ┌──────────┼──────────┬───────────┬───────────┬──────────┐
     ▼          ▼          ▼           ▼           ▼          ▼
  blob_id     K_hdr     T_burn      live_id    live_psk     chain
 (address)  (header)   (delete)   (rendezvous)  (Noise)       │
     │          │                                             │
     │          ▼                                             │
     │   OH = Seal(K_hdr, HP)   HP = flags, pw_salt, kem_ct   │
     │          │                                             │
     ▼          ▼                                             │
   TH = LHash("transcript", mode ‖ blob_id ‖ OH ‖ rcpt)       │
                │                                             │
                │        ss_kem (X-Wing)    pw_key (Argon2id) │
                │             └──────┬──────────┘             │
                │                    ▼                        │
                │            ┌───────────────┐                │
                │            │    Stage B    │◄───────────────┘
                │            └───────┬───────┘  PRK_B = LExtract("", "root",
                │                    │                  chain ‖ ss_kem ‖ pw_key)
                └──────► info ───────┤
                              ┌──────┴──────┐
                              ▼             ▼
                           commit       K_payload
```

### 6.1 Stage A: artifact keys

```
mode  = 0x01 if SPLIT else 0x00
ikm_A = u8(mode) ‖ LS             if mode = 0x00      (33 bytes)
ikm_A = u8(mode) ‖ LS ‖ KS        if mode = 0x01      (65 bytes)

PRK_A    = LExtract("", "artifact", ikm_A)

blob_id  = LExpand(PRK_A, "blob id",    "", 32)
K_hdr    = LExpand(PRK_A, "header key", "", 32)
T_burn   = LExpand(PRK_A, "burn token", "", 32)
live_id  = LExpand(PRK_A, "live id",    "", 32)
live_psk = LExpand(PRK_A, "live psk",   "", 32)
chain    = LExpand(PRK_A, "chain",      "", 64)
```

`blob_id` is the blob's address on the storage service. It is derived from every artifact secret, so in SPLIT mode someone holding only the link cannot even locate the ciphertext.

`blob_id` also commits to the artifact secrets: two different artifact sets yielding the same `blob_id` would be a collision in HMAC-SHA-512.

### 6.2 Sealed header

The header plaintext `HP` is exactly 1152 bytes.

```
offset  size  field
0       1     hflags       bit 0 ADDRESSED, bit 1 PASSPHRASE, bit 2 SIGNED; bits 3–7 MUST be 0
1       1     pw_profile   0x00 if not PASSPHRASE; otherwise 0x01 or 0x02 (§6.5)
2       14    reserved     MUST be 0^14
16      16    pw_salt      random(16) if PASSPHRASE; otherwise 0^16
32      1120  kem_ct       X-Wing ciphertext if ADDRESSED; otherwise 0^1120
```

```
OH = AEAD.Seal(key   = K_hdr,
               nonce = 0^12,
               aad   = Ctx("header") ‖ blob_id,
               pt    = HP)                                    (1168 bytes)
```

`K_hdr` is used for this one encryption only (I8), so a fixed nonce is safe.

The header has the same size in every mode. Unused fields are zero and, being encrypted, are indistinguishable from used ones.

An opener MUST reject (`AEG-FMT-03`) a header in which any reserved bit or byte is non-zero, `pw_profile` is inconsistent with PASSPHRASE or is not a defined profile, `pw_salt` is non-zero without PASSPHRASE, or `kem_ct` is non-zero without ADDRESSED.

### 6.3 Recipient binding

```
rcpt = LHash("recipient", ik_pub_R ‖ kem_pub_R)      if ADDRESSED     (64 bytes)
rcpt = 0^64                                           otherwise
```

`ik_pub_R` and `kem_pub_R` are the recipient's identity key and the KEM public key encapsulated to, both taken from the recipient's card (§9.4).

### 6.4 Transcript hash

```
TH = LHash("transcript", u8(mode) ‖ blob_id ‖ OH ‖ rcpt)                (64 bytes)
```

All four inputs have fixed length, so the encoding is injective. `TH` covers the version (through `PROTO`), the split mode, the artifact secrets (through `blob_id`), every header field including the KEM ciphertext (through `OH`), and the recipient's identity and KEM keys.

### 6.5 Stage B: root keys

```
ss_kem = X-Wing shared secret            if ADDRESSED,   else 0^32
pw_key = Argon2id(passphrase, pw_salt)   if PASSPHRASE,  else 0^32

PRK_B     = LExtract("", "root", chain ‖ ss_kem ‖ pw_key)             (ikm is 128 bytes)

commit    = LExpand(PRK_B, "commit",      TH, 32)
K_payload = LExpand(PRK_B, "payload key", TH, 32)
```

**Argon2id.** Version 0x13, output length 32, no secret key, no associated data, salt `pw_salt`.

| `pw_profile` | Memory | Passes | Lanes | Source |
|--------------|--------|--------|-------|--------|
| `0x01` | 64 MiB (2^16 KiB) | 3 | 4 | RFC 9106, second recommended option |
| `0x02` | 2 GiB (2^21 KiB) | 1 | 4 | RFC 9106, first recommended option |

Openers MUST support both. Sealers SHOULD use `0x02` wherever the recipient is expected to have the memory.

The passphrase is the UTF-8 encoding of the user's input after applying the OpaqueString profile of RFC 8265. It MUST NOT be trimmed, truncated or case-folded.

### 6.6 Key commitment

`commit` is stored in the clear immediately after the sealed header.

An opener MUST recompute `commit` from its candidate factors and compare with `ct_eq` **before** decrypting any payload chunk. A mismatch is `AEG-CRYPTO-02`.

This is what makes I11 hold. For a blob to open under two different key sets, both would have to produce the same `commit`, which requires a collision in HMAC-SHA-512 truncated to 256 bits. It also gives a correct way to test candidate KEM keys and passphrases without touching the payload cipher, which closes partitioning-oracle attacks.

---

## 7. Blob Format

### 7.1 Layout

```
offset   size        field
0        1168        OH        sealed header                     (§6.2)
1168     32          commit    key commitment                    (§6.6)
1200     …           C_0 ‖ C_1 ‖ … ‖ C_(N-1)                     (§7.2)
```

There is no magic number, no version field and no length field. A blob is, in its entirety, indistinguishable from random bytes to anyone who does not hold all the artifacts. Its version is the version of the ShareLink that points to it.

### 7.2 Payload stream

The plaintext stream `P` (§7.3–§7.5) is split into chunks of `CHUNK = 65536` bytes. Every chunk is full except possibly the last, which holds between 1 and 65,536 bytes. `P` is never empty.

```
N       = ceil(|P| / 65536)
P_i     = P[i·65536 : min((i+1)·65536, |P|)]
last_i  = 0x01 if i = N−1 else 0x00

C_i     = AEAD.Seal(key   = K_payload,
                    nonce = u88(i) ‖ u8(last_i),
                    aad   = "",
                    pt    = P_i)                              (|P_i| + 16 bytes)
```

This is the STREAM construction. The counter prevents reordering and duplication. The final flag prevents truncation and extension. `K_payload` is unique to the blob, so nonces never repeat across blobs.

```
blob length = 1200 + |P| + 16·N
```

An opener that knows the blob length `B` MUST check its structure before decrypting:

```
body = B − 1200                    require body ≥ 17
N    = ceil(body / 65552)
tail = body − (N−1)·65552          require 17 ≤ tail ≤ 65552
|P|  = body − 16·N
```

An opener that does not know `B` in advance MUST treat a chunk as final if and only if no byte follows it.

Random access: chunk `i` occupies blob bytes `[1200 + i·65552, 1200 + (i+1)·65552)` and decrypts independently.

### 7.3 Manifest

`P` begins with a manifest describing the content.

```
P = manifest ‖ content ‖ pad ‖ [ signature ]

manifest = u32(mlen) ‖ body                 43 ≤ mlen ≤ 16384

body:
  size  field
  8     content_len    u64, exact length of content
  32    sender_ik      sender's Ed25519 identity key if SIGNED; otherwise 0^32
  2     name_len       u16, 0..1024
  n     name           UTF-8
  1     type_len       u8, 0..127
  t     media_type     ASCII, bytes 0x21–0x7E only
  …     extensions     zero or more, to the end of body

extension = u16(type) ‖ u16(len) ‖ value
```

Rules, all enforced by the opener (`AEG-FMT-04` on violation):

- The manifest always fits in the first chunk, so it can be read after decrypting `C_0` alone.
- `sender_ik` MUST be non-zero if and only if SIGNED is set.
- `name` MUST be valid UTF-8 and MUST NOT contain U+0000. Sealers SHOULD normalise it to NFC; openers MUST NOT accept or reject on normalisation, because Unicode versions differ.
- Every byte of `media_type` MUST be in the range 0x21–0x7E.
- Every length MUST fit within `mlen`, and `4 + mlen + content_len + siglen` MUST NOT exceed `|P|`.
- Extensions MUST appear in strictly ascending order of `type`. No type may repeat.
- An extension whose `type` has its high bit set (`type ≥ 0x8000`) is **critical**: an opener that does not understand it MUST reject the blob. Unknown non-critical extensions MUST be ignored.

Extensions defined in v3.0:

| Type | Name | Value | Meaning |
|------|------|-------|---------|
| `0x0001` | `note` | UTF-8, ≤ 4096 bytes | A message from the sender, shown to the recipient |
| `0x0002` | `burn` | empty | The recipient's client SHOULD delete the blob after a successful open (§10.6) |

`name` and `media_type` are untrusted input from the sender. Appendix C gives the handling rules.

A share carries exactly one byte stream. Multi-file shares are an application convention (an archive as content) and are outside this specification.

### 7.4 Padding

```
siglen = 64 if SIGNED else 0
n      = 4 + mlen + content_len + siglen
|P|    = Padme(max(n, 65536))
pad    = 0^(|P| − n)
```

`Padme` is defined in Appendix B. It rounds a length up so that only O(log log) bits of the true size leak. For the lengths Aegis uses (65,536 and above) it adds less than 1/32 of the length, about 3.1%, and permits 32 sizes per doubling.

The opener MUST verify, after the final chunk, that every pad byte is zero and that `|P| = Padme(max(n, 65536))` for the `n` implied by the manifest. Either failure is `AEG-FMT-04`.

The smallest possible blob is 1200 + 65,536 + 16 = **66,752 bytes**. A one-line note and a 60 KB document are indistinguishable.

### 7.5 Sender signature

When SIGNED is set, the last 64 bytes of `P` are a signature.

```
digest    = LHash("stream digest", P[0 : |P| − 64])
signature = LSign(ik_sk_S, "sender signature", TH ‖ commit ‖ digest)
```

The signature covers:

- through `TH`: the version, the share's address and so its secrets, the header, and — for addressed shares — the recipient's identity and KEM keys;
- through `commit`: the actual keys;
- through `digest`: the manifest (which names the signer), the content, and the padding.

It therefore cannot be lifted to another share, another recipient, or other content. It is inside the encryption, so the server and anyone without the keys can neither see who signed nor test a guess (I12).

Verification uses `sender_ik` from the manifest and the strict rules of §3.3. Failure is `AEG-AUTH-01`, and the whole open fails.

A signature is transferable evidence. A recipient who reveals the artifacts can prove to a third party that the holder of `sender_ik` signed this content. Clients MUST say so where the option is offered. Unsigned shares carry no such evidence.

### 7.6 Limits

| Quantity | Limit |
|----------|-------|
| `content_len` | `2^62` bytes; in practice the service's `max_blob_bytes` |
| `mlen` | 16,384 |
| `name_len` | 1,024 |
| `type_len` | 127 |
| Chunks per blob | `2^88` by construction |

---

## 8. Procedures

### 8.1 Sealing

Inputs: the content with its exact length; a name and media type; the options SPLIT, ADDRESSED (with a validated recipient card, §9.4), PASSPHRASE, SIGNED (with the sender's identity key), LIVE, `note`, `burn`.

1. `LS ← random(32)`. If SPLIT, `KS ← random(32)`.
2. Run Stage A (§6.1).
3. If ADDRESSED: `(ss_kem, kem_ct) ← XWing.Encaps(kem_pub_R)`.
4. If PASSPHRASE: `pw_salt ← random(16)`; compute `pw_key`.
5. Build `HP`; compute `OH` (§6.2).
6. Compute `rcpt`, `TH`, `PRK_B`, `commit`, `K_payload` (§6.3–§6.5).
7. Build the manifest; compute `n`, `|P|` and the padding (§7.3, §7.4).
8. Encrypt `P` chunk by chunk (§7.2). If SIGNED, hash `P` as it is produced and append the signature (§7.5).
9. `T_owner ← random(32)`.
10. Erase `PRK_A`, `PRK_B`, `K_hdr`, `K_payload`, `chain`, `ss_kem`, `pw_key` and the passphrase.

Outputs: the blob; the ShareLink and, if SPLIT, the ShareKey; `blob_id`; `T_owner`; `T_burn`.

The content length must be known before step 7. Input of unknown length (a pipe) MUST be spooled first.

**The blob is immutable (I8).** It is produced once. Upload retries, resumed uploads, live transfers and fallbacks from live to stored all send these same bytes. An implementation MUST NOT run step 8 again under the same `K_payload`; sealing again means starting again from step 1.

### 8.2 Opening

Inputs: a ShareLink; a ShareKey if SPLIT; local KEM private keys; a passphrase if asked for.

1. Decode and check the artifacts (§4.3). If SPLIT is set and no ShareKey is available, stop and ask for it.
2. Run Stage A.
3. Obtain blob bytes `[0, 1200)` from the storage service at `blob_id`, or from a live session. As soon as the blob length is known, check its structure (§7.2); an impossible length is `AEG-FMT-03`.
4. Open `OH` with `K_hdr`. Failure is `AEG-CRYPTO-01`: the artifacts do not match this blob, or it is corrupt.
5. Parse `HP` strictly (§6.2).
6. If PASSPHRASE, obtain the passphrase and compute `pw_key`.
7. Form the candidate list. If ADDRESSED, one candidate per local KEM private key, newest first, each with `ss_kem = XWing.Decaps(sk, kem_ct)` and the `rcpt` for that key. Otherwise a single candidate with `ss_kem = 0^32`, `rcpt = 0^64`.
8. For each candidate compute `TH`, `PRK_B` and `commit′`. The first with `ct_eq(commit′, commit)` is selected. If none matches: `AEG-CRYPTO-02`. With PASSPHRASE, the client MAY let the user try again from step 6.
9. Derive `K_payload`. Decrypt chunks under the release rule (§8.3).
10. After the final chunk, check padding and length (§7.4) and, if SIGNED, the signature (§7.5).
11. Release the output. If the manifest carries `burn`, request deletion with `T_burn` (§10.3).
12. Erase all keys and, by default, the artifacts.

A client SHOULD keep no more than 8 KEM private keys, which bounds step 7.

### 8.3 Plaintext release rule

1. A byte of plaintext MUST NOT leave the decryption routine unless the chunk containing it has passed AEAD verification.
2. Output MUST be written under a temporary name or held in memory, and MUST NOT appear under its final name or be reported as received until every check in step 10 has passed.
3. A client MAY show the name, type, size and note from the manifest once `C_0` has verified. It MUST NOT show the signer as authenticated until step 10 has passed.
4. A client MAY offer preview of verified chunks before the transfer completes, and MUST mark it incomplete.
5. On any failure, partial output MUST be deleted.

### 8.4 State machines

Transitions not listed are invalid and raise `AEG-STATE-01`. `FAILED` is reachable from every state and is terminal; entering it erases all secret state for the operation.

**Sender**

| State | Entered when | Holds | Next |
|-------|--------------|-------|------|
| `S_INIT` | Operation requested | Inputs | `S_KEYED` |
| `S_KEYED` | Steps 1–6 done | All keys | `S_SEALING` |
| `S_SEALING` | Encrypting | `K_payload` | `S_SEALED` |
| `S_SEALED` | Blob complete; keys erased (step 10) | Blob, artifacts, tokens | `S_PUBLISHING` |
| `S_PUBLISHING` | Uploading, or waiting for a live peer | Same | `S_PUBLISHING` (retry, same bytes), `S_PUBLISHED` |
| `S_PUBLISHED` | Server confirmed, or peer acknowledged | Artifacts, tokens | `S_DONE` |
| `S_DONE` | Artifacts handed to the user | `blob_id`, `T_owner` | — |

There is no transition back to `S_KEYED` or `S_SEALING`. Artifacts are released only on entering `S_DONE`. For a live offer, artifacts are released on entering `S_PUBLISHING`, since the recipient needs them to connect.

**Recipient**

| State | Entered when | Next |
|-------|--------------|------|
| `R_INIT` | Artifact received | `R_ARTIFACTS` |
| `R_ARTIFACTS` | All required artifacts decoded and checked | `R_HEADER` |
| `R_HEADER` | `OH` opened and parsed | `R_HEADER` (passphrase retry), `R_KEYED` |
| `R_KEYED` | Commitment matched | `R_STREAMING` |
| `R_STREAMING` | Decrypting chunks | `R_VERIFIED` |
| `R_VERIFIED` | Final chunk, padding, length and signature all checked | `R_DONE` |
| `R_DONE` | Output released; secrets erased | — |

---

## 9. Identity

Sealed shares need no identity at all. This section applies to addressed shares and to signing.

### 9.1 Recovery seed

An identity is generated from `seed ← random(32)`.

The seed's human-readable form is the 24-word BIP-39 English mnemonic that encodes these 32 bytes as entropy. Only BIP-39's wordlist and checksum are used; its PBKDF2 seed derivation is not.

### 9.2 Identity key

```
PRK_id  = LExtract("", "identity root", seed)
ik_seed = LExpand(PRK_id, "identity key", "", 32)
(ik_sk, ik_pub) = Ed25519 key pair from ik_seed          (RFC 8032 §5.1.5)
```

`ik_pub` **is** the identity. It signs identity cards (§9.4) and, when the user opts in, sender signatures (§7.5). It is used for nothing else.

### 9.3 KEM epoch keys

Encryption to a recipient uses a separate X-Wing key pair.

1. A KEM key pair MUST be generated from fresh `random(32)`. It MUST NOT be derived from `seed`, from `ik_sk`, or from any other long-term secret (I16).
2. Each KEM key has a validity window of at most 90 days.
3. A recipient MAY hold several KEM keys with overlapping windows.

### 9.4 Identity cards

A card binds a KEM public key to an identity for a limited time.

```
offset  size  field
0       1     version     = 0x03
1       32    ik_pub
33      1216  kem_pub     X-Wing public key
1249    8     not_before  u64, Unix seconds
1257    8     not_after   u64, Unix seconds
1265    64    sig         = LSign(ik_sk, "card", bytes[0:1265])
1329    4     check       = LHash("card check", bytes[0:1329])[0:4]
```

Text form: `"aegis:card:" ‖ b32(card bytes)`. A card is 1,333 bytes. It is public; it may be sent over any channel, shown as a QR code, or itself shared as an Aegis blob.

Before sealing to a card, a sender MUST check, and reject with `AEG-AUTH-02` on any failure:

1. `version` and `check`;
2. `sig`, under `ik_pub`, with strict verification (§3.3);
3. `not_before < not_after` and `not_after − not_before ≤ 7,776,000` (90 days);
4. the sender's clock is before `not_after`;
5. `kem_pub` passes the ML-KEM encapsulation-key check (§3.3);
6. `ik_pub` belongs to a contact the user has accepted (§9.5).

When a sender holds several valid cards for one identity, it MUST use the one with the latest `not_after`.

There is no key directory. The storage service never stores, serves or sees cards as such.

### 9.5 Fingerprints and verification

```
fingerprint = b32( LHash("fingerprint", ik_pub)[0:20] )       32 characters, shown as 8 groups of 4
```

A client keeps, per contact: `ik_pub`, a local name chosen by the user, a state (`unverified` or `verified`), and the current card.

1. A contact becomes `verified` only when the user confirms that the fingerprint matches one obtained from the contact through a channel the user trusts.
2. A client MUST NOT replace a contact's `ik_pub`. A different identity key is a different contact, shown as new and unverified.
3. A new card for an existing `ik_pub`, correctly signed, MAY replace the old one without user action.
4. Sealing an addressed share to an `unverified` contact MUST show a warning.

### 9.6 Rotation and destruction

1. A recipient SHOULD publish a new card when two thirds of the current window has elapsed.
2. A KEM private key MUST be destroyed no later than 37 days after its `not_after`: the 30-day maximum blob lifetime plus 7 days' grace.
3. Destruction means overwriting every stored copy, including backups under the implementation's control.
4. Rotating the identity key creates a new identity. Carrying verification across is deferred (Appendix E).

### 9.7 Storage and recovery

1. The recovery seed restores `ik_sk`, and with it the identity and every contact's ability to recognise it.
2. The recovery seed restores **no** KEM private key. Addressed shares not yet opened when a device is lost are unrecoverable; the sender must seal again to a new card. This is what I16 means in practice, and clients MUST tell users at the time of backup.
3. There is no server-side recovery of anything.
4. Appendix C specifies the reference vault that stores `seed`, KEM private keys, contacts and share records at rest.

---

## 10. Storage Service

### 10.1 Role

A storage service stores opaque blobs under addresses chosen by clients, serves them to anyone who knows the address, deletes them on request or on expiry, and relays live sessions. It does nothing else.

It has no accounts, no sessions, no cookies, and no knowledge of the protocol version of the blobs it stores.

### 10.2 API

HTTPS, under the ShareLink's `origin`. Addresses and tokens are lowercase hex.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v3/info` | Service limits and options |
| `POST` | `/v3/admission` | Obtain an admission challenge |
| `PUT` | `/v3/blobs/{blob_id}` | Store a blob |
| `HEAD` | `/v3/blobs/{blob_id}` | Length of a stored blob |
| `GET` | `/v3/blobs/{blob_id}` | Fetch a blob or a byte range |
| `DELETE` | `/v3/blobs/{blob_id}` | Delete a blob |
| `GET` | `/v3/live/{live_id}` | WebSocket upgrade for a live session (§11) |

**`GET /v3/info`** returns JSON:

```json
{ "max_blob_bytes": 5368709120, "max_ttl": 2592000,
  "admission": ["pow-sha512"], "resumable": true, "live": true }
```

Clients MUST treat every value as untrusted and range-check it.

**`PUT /v3/blobs/{blob_id}`** — request headers:

| Header | Required | Value |
|--------|----------|-------|
| `Content-Length` | Yes | Blob length |
| `Aegis-Ttl` | Yes | Seconds, 1 … 2,592,000 |
| `Aegis-Owner-Verifier` | Yes | `hex(Verifier(T_owner))` |
| `Aegis-Burn-Verifier` | Yes | `hex(Verifier(T_burn))` |
| `Aegis-Admission` | Yes | Admission stamp (§10.4) |
| `Aegis-Max-Fetches` | No | Positive integer |

Responses: `201` stored; `409` address in use; `413` too large; `403` admission refused; `429` rate limited.

Clients MUST always send both verifiers, whether or not `burn` is requested, so that the request reveals nothing about the option.

If the service advertises `resumable`, a `PUT` carrying `Content-Range: bytes a-b/total` appends to an incomplete blob with the same address and owner verifier, and `HEAD` with `Aegis-Owner-Verifier` returns `Aegis-Upload-Offset` for it. Incomplete blobs MUST NOT be served and MUST be discarded after 24 hours.

**`GET /v3/blobs/{blob_id}`** — `Range` MUST be supported. `200` or `206` with the bytes; `404` otherwise.

**`DELETE /v3/blobs/{blob_id}`** — header `Aegis-Delete-Token: hex(token)`. `204` if the token matches either verifier; `404` otherwise.

### 10.3 Capabilities

Authorisation is by possession of a value. There are no identities.

| Capability | Value | Who holds it | Grants |
|------------|-------|--------------|--------|
| Read | `blob_id` | Anyone with all artifacts | Fetch ciphertext |
| Burn | `T_burn` (§6.1) | Anyone with all artifacts | Delete |
| Owner | `T_owner = random(32)` | The sender only | Delete |
| Rendezvous | `live_id` | Anyone with all artifacts | Join the live session |

```
Verifier(token) = LHash("delete verifier", token)[0:32]
```

The service stores verifiers, never tokens. `T_owner` is independent of the share secrets, so a sender can erase `LS` and `KS` and still revoke the blob later.

None of these values is a decryption key, and none can be turned into one (I2, I14).

### 10.4 Admission control

A service needs to limit abuse without identifying anyone. Every `PUT` and every live connection carries an admission stamp.

**`pow-sha512`** — REQUIRED for clients and services.

```
POST /v3/admission  →  { "scheme": "pow-sha512", "challenge": hex(32 bytes),
                         "bits": d, "expires": unix_seconds }

stamp = "pow-sha512." ‖ hex(challenge) ‖ "." ‖ hex(u64(counter))

valid  ⇔  the first d bits of LHash("pow", challenge ‖ id ‖ u64(counter)) are zero
```

`id` is the `blob_id` or `live_id` the stamp is for. Because blob addresses are write-once, a stamp cannot be replayed and the service needs no replay cache. Challenges SHOULD be self-authenticating (a MAC under a service key over the challenge and its expiry) so that issuing them is stateless.

A client SHOULD refuse a difficulty above a locally configured ceiling.

Proof-of-work is weak against a determined abuser. A service MAY additionally or instead accept Privacy Pass tokens (RFC 9576–9578). It MUST NOT require an account, an e-mail address or a telephone number.

### 10.5 Server requirements

A conforming service:

1. MUST serve only over TLS 1.3 or later, except on `.onion` origins.
2. MUST treat blob addresses as write-once. A `PUT` to an existing or incomplete-and-foreign address returns `409`.
3. MUST NOT serve a blob until it has been completely received.
4. MUST return the same `404` response, with indistinguishable timing as far as practical, for addresses that never existed, expired, were deleted, or are incomplete — and for a `DELETE` with a wrong token.
5. MUST delete a blob and all its records when its lifetime ends, when its fetch limit is reached, or on a valid `DELETE`.
6. MUST store, per blob, only: the bytes, the address, the two verifiers, the expiry time, and the remaining fetch count if one was set. Expiry SHOULD be stored rounded up to the hour.
7. MUST NOT write any persistent record that associates a network address or transport fingerprint with a blob address, a live address or a time. Rate-limiting state MUST be held in memory only and discarded within one hour.
8. MUST NOT set cookies, MUST send `Cache-Control: no-store`, and MUST NOT load third-party resources on any page it serves.
9. MUST NOT inspect, transform, deduplicate or index blob contents.
10. MUST compare delete tokens in constant time.

A client cannot verify requirements 5–9. That is the point of I13: the protocol's security does not depend on them.

### 10.6 Advisory features

Expiry (`Aegis-Ttl`), fetch limits (`Aegis-Max-Fetches`), deletion by the owner, and burn-after-reading are **requests to the server**. An honest service honours them. A malicious one keeps every byte.

Clients MUST present them accordingly — for example "the server is asked to delete this after one download" — and MUST NOT present any of them as a guarantee that the data is gone.

The `burn` extension makes the recipient's client send `DELETE` with `T_burn` after a successful open, which removes the blob from an honest server promptly instead of at expiry.

### 10.7 Abuse handling

1. A service MUST accept takedown requests that identify a blob by its address, and MAY delete any blob at its own discretion.
2. A service SHOULD accept abuse reports in which the reporter voluntarily discloses the artifacts. The operator can then derive the address and decrypt. Because of I11, what the operator sees is necessarily what every recipient saw.
3. A service cannot scan content, and MUST NOT require the means to.
4. There is no web client. A ShareLink is not an `https` URL and does nothing in a browser, which removes the drive-by delivery path that ended earlier services of this kind.

### 10.8 Client requirements toward the service

The service is the adversary (I13). A client therefore:

1. MUST NOT follow HTTP redirects. A redirect would carry a capability to another origin (I14).
2. MUST send capabilities only to the `origin` named in the ShareLink, only over TLS 1.3 with full certificate validation (or to a `.onion` origin), and only in the request each one authorises.
3. MUST send `Accept-Encoding: identity`, MUST reject compressed responses, and MUST ignore cookies.
4. MUST bound every response: a size limit on `/v3/info` and on error bodies, and exactly the expected length for blob data.
5. MUST use a proxy only when the user has configured one explicitly, never one taken silently from the environment.
6. **MUST fetch uniformly.** The timing and pattern of a client's requests MUST NOT depend on anything inside the sealed header. In particular a client MUST NOT pause, slow or reorder a download while it derives a passphrase key, tries KEM keys, or waits for the user to type a passphrase; it continues fetching ciphertext to temporary storage. Otherwise the fetch pattern tells the server which mode a share uses, which I5 says it must not learn.
7. MUST NOT fetch anything when a ShareLink arrives through an operating-system link handler until the user has seen the origin and confirmed. An unconfirmed fetch discloses the user's network address to a server of the link author's choosing.

---

## 11. Live Transfer

### 11.1 Overview

When both parties are online, the blob can be streamed from sender to recipient through the service's relay instead of being stored.

What travels is the ordinary blob of §7, byte for byte. Live transfer is a transport. All content protection, recipient binding and sender authentication come from the blob, exactly as in stored mode. The tunnel adds three things: the ciphertext is never at rest on the service; a relay that records the session cannot decrypt the recording even if it later obtains the artifacts; and the sender gets a delivery acknowledgement.

### 11.2 Rendezvous

Each peer opens a WebSocket to `wss://origin/v3/live/{hex(live_id)}`, presenting an admission stamp for `live_id`.

The service pairs the first two connections for an address and rejects any further one. It then forwards binary messages verbatim, in order, in both directions, and keeps nothing. Each WebSocket binary message carries exactly one Noise message.

### 11.3 Handshake

```
Protocol   Noise_NNpsk0_25519_ChaChaPoly_SHA512
Prologue   Ctx("live") ‖ live_id
PSK        live_psk
Initiator  the recipient
Responder  the sender

  -> psk, e
  <- e, ee
```

Both handshake payloads are empty; each handshake message is 48 bytes.

Either side MUST abort (`AEG-LIVE-01`) on any handshake failure. A peer without the artifacts cannot produce a valid first message or read anything that follows.

There is no version negotiation. A peer speaking a different version has a different `PROTO`, hence a different prologue and PSK, and the handshake fails (I15).

### 11.4 Frames

After the handshake, every Noise transport message carries one frame: `u8(type) ‖ body`. A transport message is at most 65,535 bytes, so a `DATA` body is at most 65,518 bytes.

| Type | Name | Direction | Body |
|------|------|-----------|------|
| `0x01` | `HELLO` | Sender → Recipient | `u64(blob_length)` |
| `0x02` | `READY` | Recipient → Sender | `u64(offset)`, the number of blob bytes already held |
| `0x03` | `DATA` | Sender → Recipient | Blob bytes, in order from `offset` |
| `0x04` | `END` | Sender → Recipient | empty |
| `0x05` | `ACK` | Recipient → Sender | empty |
| `0x06` | `ABORT` | Either | `u8(reason)` |

Sequence: `HELLO`, `READY`, `DATA`…, `END`, `ACK`.

1. The sender MUST NOT send `DATA` before it has received and authenticated `READY`. A replayed first handshake message therefore earns an attacker nothing: it cannot produce `READY`.
2. `offset` MUST NOT exceed `blob_length`. A non-zero offset resumes an interrupted transfer; the bytes come from the same immutable blob (I8).
3. The recipient MUST send `ACK` only on entering `R_VERIFIED` (§8.4).
4. The sender enters `S_PUBLISHED` only on receiving `ACK`.
5. Any frame out of sequence, of unknown type, or of wrong length is `AEG-LIVE-02`; the peer sends `ABORT` and closes.

`ABORT` reasons: `0x01` protocol violation, `0x02` verification failed, `0x03` cancelled by user, `0x04` resource limit.

If no peer arrives, the sender MAY, with the user's consent, fall back to storing the same blob.

### 11.5 Direct path (OPTIONAL)

By default all live traffic passes through the relay, so neither peer learns the other's network address.

Peers MAY upgrade to a direct connection if both users opt in. A client MUST warn that this discloses its network address to the other party.

1. Candidate addresses are exchanged in frames of type `0x10` **inside** the established tunnel. The relay never sees them.
2. On the direct connection the peers run a new handshake of the same pattern with

   ```
   Prologue  Ctx("direct") ‖ live_id
   PSK       LExpand(LExtract("", "direct", h ‖ live_psk), "direct psk", "", 32)
   ```

   where `h` is the handshake hash of the relayed session. This binds the direct session to the relayed one.
3. The transfer continues on the direct path with a fresh `READY`.

How candidates are gathered and which transport is used are outside v3.0.

### 11.6 Properties

| Property | Holds against | Basis |
|----------|---------------|-------|
| Only artifact holders can complete a session | SRV, NET | PSK |
| Recorded sessions stay unreadable if the artifacts leak later | SRV, NET, without Q | Ephemeral X25519 |
| Recorded sessions stay unreadable against Q | SRV, NET — unless Q also obtains the artifacts | PSK is a 256-bit symmetric secret |
| Everything of §2.4 | As in stored mode | The inner blob |

A live session authenticates possession of the artifacts. It does not authenticate an identity; that is the job of ADDRESSED and SIGNED in the blob.

---

## 12. Errors

| Code | Condition | Required action |
|------|-----------|-----------------|
| `AEG-FMT-01` | Malformed or missing artifact: encoding, length, flags, checksum | Reject; ask the user to re-enter |
| `AEG-FMT-02` | Unsupported version | Reject; do not attempt another version |
| `AEG-FMT-03` | Impossible blob length; non-canonical header | Fail |
| `AEG-FMT-04` | Malformed manifest; unknown critical extension; padding or length rule violated | Fail; delete partial output |
| `AEG-CRYPTO-01` | Sealed header failed authentication | Fail |
| `AEG-CRYPTO-02` | No candidate matched the commitment | Fail; passphrase retry permitted |
| `AEG-CRYPTO-03` | A chunk failed authentication. This is how truncation, extension, reordering and duplication appear when the blob length is known, because each changes a chunk's counter or final flag. | Fail; delete partial output |
| `AEG-CRYPTO-04` | When the length is not known in advance: the stream ended without a final chunk, bytes followed the final chunk, or the length disagreed with `HELLO` | Fail; delete partial output |
| `AEG-AUTH-01` | Sender signature invalid | Fail; delete partial output |
| `AEG-AUTH-02` | Identity card invalid or expired | Refuse to seal |
| `AEG-NET-01` | Service unreachable | Retry with backoff, sending identical bytes |
| `AEG-NET-02` | Not found | Report as "not available"; do not guess why |
| `AEG-NET-03` | Admission refused or rate limited | Obtain a new challenge; back off |
| `AEG-NET-04` | Address already in use | Fail; seal again from the start |
| `AEG-LIVE-01` | Live handshake failed | Fail |
| `AEG-LIVE-02` | Live protocol violation or peer abort | Fail; delete partial output |
| `AEG-STATE-01` | Invalid state transition | Halt the operation |
| `AEG-RNG-01` | CSPRNG failure | Abort the process |

Rules:

1. Every `FMT`, `CRYPTO` and `AUTH` failure is terminal for the operation. The implementation enters `FAILED`, erases keys, and deletes partial output.
2. Detailed codes are for local logs and the local user. Nothing more specific than an `ABORT` reason is ever sent to a peer, and nothing at all to the service.
3. To the user, `AEG-CRYPTO-01` and `AEG-CRYPTO-02` SHOULD be reported together as: the link, key or passphrase is wrong, the share is addressed to someone else, or the data is damaged.
4. Local logs MUST NOT contain artifacts, keys, tokens, blob addresses, names or passphrases.

---

## 13. Versioning and Extensibility

1. The version is a single integer, `3`. It appears as the first byte of every artifact and card, in `PROTO`, and in the API path.
2. Any change to a byte produced or accepted under §3–§9 or §11 is a new version, with a new `PROTO` string and therefore no key in common with this one.
3. The version of a share is the version of its ShareLink. It is never negotiated and never inferred from a blob. A client that supports several versions selects by the artifact and MUST NOT retry under another version on failure (I15).
4. Within a version, the only extension points are manifest extensions (§7.3), frame types `0x10`–`0x1F` reserved for §11.5, and additional members of `/v3/info`. Non-critical manifest extensions are ignored when unknown; critical ones cause rejection.
5. A service is version-unaware with respect to blobs. The `/v3/` in its paths versions the HTTP interface only.

---

## 14. Conformance

An implementation claims conformance in one or more roles.

| Role | MUST implement |
|------|----------------|
| **Sealer** | §3–§8.1, §8.4 (sender); every mode and flag combination; §9.4 card validation |
| **Opener** | §3–§7, §8.2–§8.4 (recipient); every mode; both Argon2id profiles; both defined extensions |
| **Storage service** | §10 |
| **Live peer** | §11.1–§11.4 in the role of sender, recipient, or both |

Any Sealer, Opener or Live peer that talks to a storage service MUST also implement §10.8.

A conforming implementation MUST pass the published test suite for its roles:

1. **Known-answer vectors** for every derivation and every mode, generated by `model/aegis_v3_model.py` and reproduced by the reference implementation.
2. **Negative vectors**, each of which MUST be rejected with the stated error: a flipped bit in each field of each artifact and of the blob; a truncated blob; an extended blob; two chunks swapped; a non-final chunk presented as final and the reverse; each reserved bit or byte set; non-zero padding; a padded length that is not a Padmé value; extensions out of order or repeated; an unknown critical extension; a non-canonical base32 string; a signature with non-canonical `S`, with a small-order `R`, and under a small-order key; a signed manifest with `sender_ik` zero.
3. **State-machine tests**: every invalid transition is refused.
4. **Release-rule tests**: no plaintext byte is observable from a blob that fails at any later point.
5. **Service tests**: write-once behaviour, uniform `404`, token handling, incomplete uploads not served.

Appendix D describes the vector files.

---

## 15. Security Considerations

`Aegis_research.md` gives the full analysis. This section states the results and their limits.

### 15.1 Assumptions

| # | Assumption |
|---|------------|
| S1 | HKDF-SHA-512 is a secure KDF: HMAC-SHA-512 is a PRF, and extraction is modelled as a random oracle. |
| S2 | HMAC-SHA-512 truncated to 256 bits is collision-resistant in key and message. |
| S3 | ChaCha20-Poly1305 is a secure AEAD with pseudorandom ciphertexts. |
| S4 | X-Wing is IND-CCA2 secure if either X25519 or ML-KEM-768 is, and its ciphertexts do not identify the public key. |
| S5 | Ed25519 with strict verification is strongly unforgeable and binds the key and the message. |
| S6 | Argon2id is memory-hard. |
| S7 | The operating system's CSPRNG is sound. |
| S8 | The Noise NNpsk0 handshake is secure under Gap-DH for X25519 and S1, S3. |

Which results rest on which assumptions:

| Result | Invariants | Assumptions |
|--------|------------|-------------|
| The server's view is pseudorandom apart from **L** | I1, I2, I3, I5, I6, I12 | S1, S3, S7 |
| One artifact plus SRV learns nothing | I7 | S1, S3, S7 |
| Tampering is detected | I9 | S3 |
| A blob opens to one plaintext only | I11 | S2 |
| Addressed shares need the recipient's key | §2.4 | S1, S4 |
| Signatures cannot be lifted or forged | §7.5 | S2, S5 |

### 15.2 Forward secrecy

Forward secrecy means different things in different modes, and each is stated exactly.

| Mode | Property |
|------|----------|
| **Sealed** | No long-term key is involved. Once both parties have erased the artifacts, nothing that remains on any device can decrypt the blob. Exposure is governed entirely by where copies of the artifacts persist — typically the message histories of channels A and B. |
| **Addressed** | Compromise of a recipient's device reveals only shares addressed to KEM keys not yet destroyed: at most a 90-day window plus 37 days. The recovery seed reveals none (I16). With SPLIT, an adversary also needs both artifacts. |
| **Live** | Session keys come from an ephemeral exchange and are erased at the end. A recording cannot be decrypted later even with the artifacts, short of a quantum computer. |

Aegis does not provide per-message forward secrecy for addressed shares. That needs one-time prekeys, and therefore a key directory, which conflicts with I6 (Appendix E).

### 15.3 Post-quantum security

1. Sealed shares use only symmetric primitives with 256-bit keys. They are not affected by known quantum algorithms beyond Grover's square-root speed-up.
2. Addressed shares stay confidential against Q while ML-KEM-768 holds, and against today's adversaries while either component holds. An adversary without the link faces the symmetric secret `LS` in addition.
3. Signatures are Ed25519 and can be forged by a quantum adversary. This affects authenticity from the day such a machine exists, not the confidentiality of anything sealed earlier.
4. Live sessions use X25519. Against Q, their confidentiality rests on the PSK, and so on the artifacts not leaking.

### 15.4 Metadata

Aegis hides what is shared and between whom. It does not hide that a network address used an Aegis service at a certain time for a blob in a certain size class.

Clients SHOULD support connecting through a SOCKS5 proxy, and services SHOULD be reachable as onion services. Users who need network-level anonymity MUST be told that Aegis alone does not provide it.

A service can be compelled to begin recording whatever it is technically able to observe. Everything in **L** should be assumed available to such an order.

### 15.5 Known limitations

1. **Co-holders can substitute content in unsigned shares.** Anyone holding all artifacts holds the keys and can build a different valid blob. With write-once addresses this requires the server's help. Signed shares are not affected.
2. **Passphrases are guessable offline** by anyone who holds every other factor and the first 1,200 bytes of the blob. The passphrase factor is as strong as the passphrase.
3. **One recipient per addressed share.** Sending to several people means sealing several times (Appendix E).
4. **No deniable sender authentication.** A share is either unsigned or carries transferable evidence (Appendix E).
5. **Artifacts outlive the protocol.** An e-mail archive containing a ShareLink is a standing copy of factor A.
6. **Clocks.** Card validity uses the sender's clock. A wrong clock can cause sealing to an expired key whose private half no longer exists.
7. **Names are attacker-controlled text.** See Appendix C.
8. **The service can deny service**, and can selectively deny it.
9. **Size classes leak.** Above the 64 KiB floor, padding hides a file's size only to within about 3%. It does not hide its order of magnitude.

---

## 16. Changes from v2.1

| Area | v2.1 | v3.0 |
|------|------|------|
| Split-key | ShareKey held public values | True 2-of-2 secret split; blob address derived from both |
| Recipient | Required, type undefined | Optional; X-Wing KEM key bound to identity by a signed card |
| Post-quantum | None | Symmetric by default; hybrid KEM when addressed |
| KDF | "HKDF-BLAKE3" / HKDF-SHA-256 | HKDF-SHA-512, labelled, transcript-bound |
| AEAD | XChaCha20-Poly1305, one message per file, derived random nonce | ChaCha20-Poly1305 STREAM, 64 KiB chunks, counter nonces, single-use keys |
| Key commitment | None | 32-byte commitment checked before decryption |
| Sender signature | Mandatory, outside encryption, over ciphertext only | Optional, inside encryption, over transcript, commitment and content |
| Metadata | Unspecified | Encrypted manifest; Padmé padding; mode hidden from server |
| Blob | Version byte, cleartext header and signature | No cleartext structure; pseudorandom throughout |
| Blob address | Server-assigned | Derived from the secrets; write-once |
| Deletion | Unauthenticated | Owner and burn capability tokens |
| Abuse control | Undefined "anonymous tokens" | Proof-of-work stamps; optional Privacy Pass |
| P2P | Noise XX, unauthenticated in practice, direct | Noise NNpsk0 keyed by the artifacts, relayed; direct path opt-in |
| Identity | Ed25519 key used ambiguously | Seed → identity key; separate rotating KEM keys; cards; fingerprints |
| Forward secrecy | Claimed | Defined per mode; epoch-bounded for addressed shares |
| Artifacts | JSON, base64url | Fixed binary, base32, checksummed |
| Hash functions | BLAKE3, SHA-256, SHA-512, BLAKE2b | SHA-512 (SHA-3 only inside X-Wing) |
| Invariants | 6 | 16 |

---

## Appendix A: Constants

| Name | Value |
|------|-------|
| `PROTO` | `"AEGIS-v3"` |
| Version byte | `0x03` |
| `CHUNK` | 65,536 |
| Header length | 1,200 (`OH` 1,168 + `commit` 32) |
| Encrypted chunk length | 65,552 |
| Minimum `\|P\|` | 65,536 |
| Minimum blob length | 66,752 |
| Maximum `mlen` | 16,384 |
| Maximum lifetime | 2,592,000 s (30 days) |
| Maximum card window | 7,776,000 s (90 days) |
| KEM key destruction deadline | `not_after` + 3,196,800 s (37 days) |
| Card length | 1,333 |
| ShareKey length | 37 bytes; 60 characters |
| Fingerprint | 20 bytes; 32 characters |

## Appendix B: Padmé reference

From Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (PoPETs 2019). Defined for `L ≥ 2`; Aegis only calls it with `L ≥ 65536`.

```
Padme(L):
    E    = floor(log2(L))
    S    = floor(log2(E)) + 1
    z    = E − S
    mask = 2^z − 1
    return (L + mask) AND NOT mask
```

Examples: `Padme(65536) = 65536`; `Padme(65537) = 67584`; `Padme(1000000) = 1015808`; `Padme(1073741825) = 1107296256`.

## Appendix C: Reference implementation notes

Non-normative for the protocol; binding on the reference implementation.

### C.1 Vault

All local secrets are stored in one file.

```
header  = "AEGISVLT" ‖ u8(0x03) ‖ u8(pw_profile) ‖ salt(16)                       (26 bytes)
K_wrap  = LExpand(LExtract(salt, "vault passphrase", Argon2id(passphrase, salt)),
                  "vault wrap", "", 32)
wrapped = AEAD.Seal(K_wrap, 0^12, aad = header, pt = VMK)                         (48 bytes)

record  = rec_salt(32) ‖ AEAD.Seal(K_rec, 0^12, aad = Ctx("vault record") ‖ u8(type), pt)
K_rec   = LExpand(LExtract(rec_salt, "vault record", VMK), "record key", u8(type), 32)
```

- `VMK ← random(32)` is the vault master key. `salt` is regenerated whenever the passphrase changes, so `K_wrap` is single-use.
- Each record gets a fresh `rec_salt ← random(32)` every time it is written, so `K_rec` is single-use (I8) without any random nonce.
- Record types: recovery seed; KEM private key with its window; contact; share record (`blob_id`, `T_owner`, expiry).
- Writes go to a temporary file, are flushed to disk, and replace the vault by atomic rename. The previous generation is kept.
- The derived key is never cached outside process memory. The passphrase is asked for at each unlock.

### C.2 Memory

Secrets are held in types that erase on drop, are not `Copy` or `Clone`, do not implement `Debug`, and are locked in memory where the platform allows. Erasure in a language with move semantics is best-effort; this is stated in the threat model rather than hidden.

### C.3 Names and types

- A received `name` is a display string only. To save a file, the client strips path separators, control characters and bidirectional-override characters, refuses reserved device names, and never writes outside the directory the user chose.
- The client never opens or executes a received file automatically, and never chooses an application based on `media_type` alone.
- The client never overwrites an existing file, and marks received files with the operating system's "came from elsewhere" attribute where one exists.
- The process that holds vault keys never interprets received content: no previews, no thumbnails, no archive extraction.

### C.4 Interface obligations

The reference client MUST implement the labelling rules of §4.4, §5.3, §7.5, §9.5 and §10.6. They are part of the security design, not decoration.

In addition:

- Artifacts, passphrases and recovery phrases are never accepted as command-line arguments or environment variables, where the process list and shell history would expose them. They are read from a prompt, standard input, or a file the user names.
- A fingerprint is always shown in full. No interface shows a shortened one.
- A sender's `note` is rendered as plain text, visibly attributed to the sender, with nothing in it made clickable.

### C.5 Time

The vault records the latest time it has been given and rejects an earlier one for card validity, key destruction and expiry. Setting the clock back cannot revive an expired card or postpone the destruction of a key.

## Appendix D: Test vectors

`model/aegis_v3_model.py` is a dependency-free executable model of §3–§11. Running it:

1. self-tests its primitives against the published vectors of RFC 5869, RFC 7748, RFC 8032 and RFC 8439;
2. seals and opens six shares covering every mode and flag, and checks each round trip;
3. runs 45 negative cases — tampered artifacts and blobs, and blobs crafted by a malicious sender — and checks that each is rejected with the error this specification assigns;
4. exercises identity derivation, card validation, delete verifiers, proof-of-work stamps and the live handshake;
5. writes `model/vectors_v3_provisional.json`.

The vectors are **provisional** until the reference implementation reproduces them independently (plan milestone M4). The live-handshake vectors additionally need confirming against an independent Noise implementation (milestone M7).

X-Wing and Argon2id are not reimplemented in the model; where a vector needs `ss_kem`, `kem_ct` or `pw_key`, the value is given as an input and marked `injected`. Those primitives are tested against their own official vectors in the reference implementation.

The model is not constant-time and must never handle real secrets.

## Appendix E: Deferred features

Considered, judged worthwhile, and left out of v3.0 so that the core can be analysed first.

| Feature | Why deferred |
|---------|--------------|
| **Short spoken codes** for live transfer | Needs a PAKE (CPace). Sound only for live sessions, never for stored blobs. |
| **Multiple recipients per addressed share** | Needs per-recipient key wrapping in a variable-length header while keeping the recipient count hidden. |
| **One-time prekeys** | Per-share forward secrecy for addressed mode. Needs a key directory, which conflicts with I6 unless fetched anonymously. |
| **Deniable sender authentication** | Static Diffie–Hellman between identities. Classical only, and open to key-compromise impersonation. |
| **Identity succession** | An old identity key vouching for a new one, so verification carries over. |
| **Post-quantum signatures** | Hybrid Ed25519 + ML-DSA cards and sender signatures. |
| **Post-quantum live handshake** | An ephemeral KEM exchange in place of X25519. |
| **Mirrors** | The same derived address on several services, for availability. |

---

**End of Protocol Specification**
