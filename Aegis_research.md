# Cryptographic Foundations and Design Rationale for the Aegis Protocol

**Author:** Abdulaziz
**Project:** Aegis — Secure File Sharing Through a Hostile Server
**Version:** 3.0 (draft)
**Date:** November 16, 2026
**Revision:** v3.0 — Rewritten after the v2.1 audit. The earlier document explained how standard primitives work; this one argues why Aegis v3.0 is built the way it is, and what can and cannot be claimed for it.

---

## Abstract

Aegis lets one person hand a file to another through a storage server that is assumed to be actively malicious. This document gives the reasoning behind the v3.0 design: the security model, the choice of each primitive and the alternatives rejected, the constructions that combine them, the argument that each stated invariant holds, and the limits of that argument.

It is a companion to `Aegis_project_specification.md`, which is normative. Section numbers written "spec §n" refer to it. Finding numbers written AEG-nn refer to `Aegis_audit_report.md`.

Nothing here is a proof. §7 lists what a machine-checked model must establish before the design is relied on.

---

## Table of Contents

1. [The Problem and the Model](#1-the-problem-and-the-model)
2. [Prior Art](#2-prior-art)
3. [Primitives](#3-primitives)
4. [Constructions](#4-constructions)
5. [Security Analysis](#5-security-analysis)
6. [Metadata](#6-metadata)
7. [What a Formal Model Must Show](#7-what-a-formal-model-must-show)
8. [Open Problems](#8-open-problems)
9. [Implementation Technology](#9-implementation-technology)
10. [References](#10-references)

---

## 1. The Problem and the Model

### 1.1 What is being protected, from whom

A sender wants a recipient to obtain a file. The recipient may be offline, so something must hold the file in between. That something — the storage service — is the adversary.

v2.1 described this as "Zero Trust" and cited NIST SP 800-207. That standard describes an enterprise architecture in which every access request is checked against the identity, device and location of the requester. It is about verifying users more, which is the opposite of what an anonymous file-sharing protocol does (AEG-27). The model Aegis needs is the older and simpler cryptographic one:

> **End-to-end security against a malicious intermediary.** The intermediary sees every byte it handles, may alter, drop, replay or keep any of them, may collude with other attackers, and is assumed to do so.

Two consequences follow immediately, and v2.1 missed both.

1. **A passive model is not enough.** v2.1 analysed a thief who copies the database. A malicious server also chooses what to serve and to whom. Every integrity property has to hold against it (spec I9, I11, I13).
2. **Retention is forever.** A time-to-live is something the server says it will do. If the server is the adversary, every ciphertext it ever received is still there on the day any key leaks, and on the day a large quantum computer exists (AEG-07).

### 1.2 The second channel

The sender must give the recipient something secret, or the server could decrypt. The channel that carries it is outside the protocol, and it is where real attacks happen: forwarded e-mail, synced chat histories, shoulder-surfed screens.

Aegis's answer is to use two channels and require both. That only means something if it is true against the strongest relevant adversary: someone who reads one channel *and* controls the server. v2.1's construction failed this completely (AEG-01). The v3.0 requirement is spec invariant I7, and §4.1 below shows how it is met.

### 1.3 Goals, stated so they can be tested

| Goal | Statement | Spec |
|------|-----------|------|
| Confidentiality | An adversary lacking any one required factor cannot distinguish the sealed content from random data of the same padded length. | §2.4 |
| Server blindness | Everything the server holds is indistinguishable from random bytes, apart from an enumerated leakage set. | I3, §2.6 |
| Split | One artifact plus the server's whole state gives no advantage. | I7 |
| Integrity | Any change to a blob is detected before the affected plaintext is released. | I9 |
| Uniqueness | A blob has at most one valid opening. | I11 |
| Origin (optional) | A signed share proves who made it, for which share and recipient, and cannot be re-targeted. | §7.5 |
| Sender privacy | No one without the keys can tell who sealed a blob, or test a guess. | I12 |
| Bounded damage | A stolen long-term key opens only a bounded window of past shares. | I16 |

### 1.4 What is out of reach

Endpoint compromise, a recipient who leaks, coercion, a network observer who sees both ends, and a server that refuses service. These are stated in spec §2.5 and not argued further here.

---

## 2. Prior Art

v2.1 claimed that split-key delivery and per-file keys existed nowhere else. Neither claim was true (AEG-29). The accurate picture is more useful, because several existing systems solved pieces of this problem well and one of them shows how such a service ends.

| System | What it does | What Aegis takes from it | Where Aegis differs |
|--------|--------------|--------------------------|---------------------|
| **OpenPGP** (1991–) | Hybrid encryption: a fresh session key per message, wrapped to recipient keys. | Per-file keys are a thirty-year-old idea. | No long-term-key-only mode; no cleartext recipient key IDs. |
| **Signal attachments** | Ciphertext on an untrusted CDN; a fresh key and a digest travel inside the end-to-end encrypted message. | This *is* split delivery: location and key by different paths. | Aegis makes the split two-of-two and independent of any one messenger. |
| **Firefox Send** (2017–2020) | Client-side encryption; the secret in the URL fragment; optional password; expiry and download limits; an owner token for deletion. | The capability model; honest framing of expiry. | No web client, so no server-delivered code holding the key; padding; split secrets. |
| **Magic Wormhole** | A short spoken code, turned into a strong key by a PAKE; relayed peer-to-peer transfer. | Relayed live transfer; the right way to do spoken codes (deferred, spec App. E). | Aegis also supports offline recipients. |
| **age** | A small, strict file-encryption format: HKDF, ChaCha20-Poly1305 in 64 KiB STREAM chunks, a header MAC. | The payload construction, nearly unchanged. | Aegis hides the header and adds a server protocol. |
| **Tahoe-LAFS** | Storage on untrusted servers, with access expressed as unforgeable capability strings. | Authorisation by possession instead of identity. | Aegis is transfer, not a filesystem. |
| **OnionShare** | The sender hosts the file as a Tor onion service. | Onion origins are first-class in Aegis. | Offline recipients; no requirement that the sender run a server. |
| **Proton Drive, Tresorit** | End-to-end encrypted cloud storage tied to accounts. | — | No accounts; the server sees no identities. |

**The lesson of Firefox Send.** Mozilla withdrew the service in 2020 because it was being used to deliver malware. An anonymous host of opaque files attracts that use, and the operator cannot scan what it cannot read. This is the most relevant precedent for Aegis, and v2.1 did not mention it. v3.0's response is in spec §10.4 and §10.7: admission control that costs something without identifying anyone, takedown by address, a reporting path made unambiguous by key commitment, and the absence of any web page that a link could open.

**What is actually new.** A two-of-two split that survives server collusion; a blob with no cleartext structure at all, so that even the share's mode is hidden; a symmetric-only default that is post-quantum for free; and a single specification covering both stored and live transfer with the same content format. That is a modest and honest claim: a careful combination, analysed.

---

## 3. Primitives

One rule governs the selection: **the smallest set of standard primitives that does the job.** Each one added is more code to audit, more ways to misuse, and more assumptions for the proof.

v2.1 used four hash functions (BLAKE3, SHA-256, SHA-512 inside Ed25519, BLAKE2b inside Noise), two of them in documents that disagreed about which. v3.0 calls exactly one, SHA-512, and it is one that Ed25519 makes mandatory anyway.

### 3.1 ChaCha20-Poly1305

**Role.** All symmetric encryption: the sealed header, every payload chunk, live transport, the local vault.

**Definition.** RFC 8439. 256-bit key, 96-bit nonce, 128-bit tag.

**Security.** Proven a secure AEAD if ChaCha20 is a pseudorandom function (Procter 2014), with tight multi-user bounds (Degabriele et al. 2021). Ciphertexts and tags are pseudorandom, which the server-blindness argument uses. The probability that a single forged chunk of length `l` bytes is accepted is at most `8·⌈l/16⌉ / 2^106`; for a full 64 KiB chunk that is about `2^-91`.

**Known pitfalls, and how v3.0 avoids them.**

- *Nonce reuse is catastrophic.* It reveals the XOR of plaintexts and the authentication key. v3.0 has no random nonces and no long-lived keys: each key encrypts one sequence under counter nonces, once (I8).
- *It does not commit to its key* (Grubbs et al. 2017; Dodis et al. 2018; Albertini et al. 2022). See §4.4.

**Why not XChaCha20-Poly1305.** v2.1 chose the extended-nonce variant so that nonces could be random. That reasoning is sound for a long-lived key. Aegis has none, so the extended nonce would protect against a hazard that the design has already removed. Meanwhile XChaCha20 exists only as an expired Internet-Draft, and Noise requires plain ChaCha20-Poly1305 regardless, so keeping it would mean two AEADs. Where a long-lived key does need to encrypt many records — the local vault — v3.0 derives a fresh single-use key per record from a 256-bit random salt (spec App. C), which achieves what the extended nonce achieves, from standard parts.

**Why not AES-256-GCM.** With single-use keys and counter nonces it would also be secure; v2.1's objection about random-nonce limits no longer applies. ChaCha20-Poly1305 wins on two points: it is constant-time in portable software on every platform, and Noise already brings it in.

**Why not the AEGIS ciphers.** Fast and well regarded, but still in standardisation, with fewer independent implementations, and equally non-committing. (And unrelated to this project despite the name; AEG-31.)

### 3.2 SHA-512 and HKDF

**Role.** Every derivation, the transcript hash, checksums, fingerprints, and the content digest under a sender signature.

**Definition.** FIPS 180-4; RFC 5869.

**Why SHA-512.** Ed25519 requires it. Using it everywhere means one hash function in the trusted base. Its 512-bit output gives 256-bit collision resistance, and commitments truncated to 256 bits keep 128.

**Why not BLAKE3.** BLAKE3 is a sound, very fast hash, and v2.1 made it central. In v3.0 it has no work to do. Key derivation hashes a few hundred bytes, where speed is irrelevant. Whole-file integrity comes from per-chunk AEAD tags, not from a file hash. The one place a long input is hashed is the content digest for signed shares, and there SHA-512's throughput is several times what the stated performance target needs. BLAKE3 also has no published standard, and "HKDF-BLAKE3", which v2.1 called standard, does not exist (AEG-05). It could return in a later suite as an optimisation for signed shares; nothing in the design forbids it.

**What HKDF is and is not.** HKDF turns a secret with enough entropy into independent keys. It does not add entropy. v2.1's research text said it could "stretch limited-entropy input"; feeding it a password gives an attacker a fast offline guessing oracle. Low-entropy inputs go through Argon2id first (§3.5), and only then into HKDF.

All of Aegis's HKDF inputs are either uniformly random 32-byte strings or outputs of a KEM or of Argon2id. Extraction is therefore not strictly needed for uniformity; it is used so that every derivation has the same shape and the same proof.

**Labels.** Every call is prefixed with `"AEGIS-v3"`, a one-byte length, and a label unique to its purpose (spec §3.2). Length-prefixing makes the encoding injective, so no two purposes can ever hash the same input. v2.1 concatenated a label and a variable-length identifier with no delimiter (AEG-13).

### 3.3 X-Wing

**Role.** Encrypting to a recipient's public key in addressed shares.

**Definition.** X-Wing (Barbosa et al. 2024): X25519 and ML-KEM-768 run side by side, their outputs combined with SHA3-256 together with the X25519 ciphertext and public key.

**Why a hybrid.** A share addressed today sits on a hostile server indefinitely. If confidentiality rested on X25519 alone, it would end the day a large quantum computer exists. If it rested on ML-KEM alone, it would depend on a scheme with only a few years of deployment. X-Wing is secure if *either* holds. It is a specific, analysed combiner — not a hand-rolled concatenation — and that is why it is used instead of composing the two parts inside Aegis.

**Security level.** ML-KEM-768 targets NIST category 3. Deployments bound by policies that demand category 5 need a different KEM and therefore a different Aegis suite. Two things soften this: an adversary without the ShareLink faces the 256-bit symmetric secret `LS` in addition, and sealed shares use no KEM at all.

**Properties relied on.**

- IND-CCA2 security, giving confidentiality.
- Ciphertexts that do not reveal which public key they were made for (Grubbs et al. 2022; Maram and Xagawa 2023, for ML-KEM), so that someone holding only a link cannot identify the recipient from the header.
- Implicit rejection: decapsulating with the wrong key yields a pseudorandom value, not an error. Trial decryption across a recipient's keys is therefore decided by the commitment check and leaks nothing through an error path.

**Binding.** X-Wing binds the X25519 public key and ciphertext itself. Aegis additionally hashes the recipient's identity key and full KEM public key into the transcript (spec §6.3). The extra binding is cheap, and it ties the share to the recipient's *identity*, which the KEM alone does not know about.

**Status.** X-Wing is an Internet-Draft. The construction has been stable, but the specification pins it by test vectors, and any change to an output byte in a final RFC is a new Aegis version.

### 3.4 Ed25519

**Role.** Signing identity cards, and — only when the sender opts in — signing shares.

**Definition.** RFC 8032, pure Ed25519.

**Verification must be pinned.** Ed25519 is defined over a curve with cofactor 8, and implementations have historically disagreed about signatures involving small-order points, non-canonical encodings, and whether to multiply by the cofactor when checking (Chalkias et al. 2020). Two libraries can disagree on whether the same signature is valid. With a small-order public key, a signature can be made that verifies for every message. v2.1 did not specify verification at all (AEG-14), and its research text described Ed25519 as "immune by design" to small-subgroup issues, which is the reverse of the truth.

v3.0 fixes the strictest common rule set (spec §3.3): canonical `S`, canonical encodings of `A` and `R`, neither of small order, cofactorless equation. Under these rules Ed25519 is strongly unforgeable and binds both the key and the message (Brendel et al. 2021). The executable model tests each rejection.

**Determinism.** RFC 8032 signing needs no randomness, which removes the classic ECDSA failure of a repeated nonce. It is not free of risk: deterministic signing is more exposed to fault injection. For a desktop file-sharing tool that trade is acceptable; the document notes it instead of presenting determinism as a pure benefit, as v2.1 did.

**Scope.** The identity key signs two kinds of message, cards and sender signatures, under different labels. It is never used for key agreement. v2.1 left open whether the same key did both (AEG-04).

### 3.5 Argon2id

**Role.** Turning a passphrase into a key: for the optional passphrase factor on a share, and for unlocking the local vault.

**Definition.** RFC 9106, version 1.3, the `id` variant.

**Parameters.** Two profiles, both taken from the RFC's own recommendations so that nothing is invented: 2 GiB with one pass, and 64 MiB with three passes, each with four lanes. v2.1's plan used the library default of about 19 MiB, which is a floor for web logins (AEG-16).

**What it buys.** Each guess costs one evaluation. That multiplies an attacker's cost by a large constant; it does not rescue a weak passphrase. A passphrase of six random words from a 7,776-word list has about 77 bits of entropy and is out of reach at any plausible per-guess cost. A memorable phrase of the user's own invention may have 30. The specification says the passphrase factor is as strong as the passphrase (spec §15.5) and the client should say the same.

### 3.6 Noise NNpsk0

**Role.** The live-transfer tunnel.

**Definition.** `Noise_NNpsk0_25519_ChaChaPoly_SHA512` (Perrin 2018): both sides send an ephemeral X25519 key; a pre-shared key is mixed in before anything else.

**Why this pattern.** By the time two parties attempt a live transfer they already share a strong secret: the artifacts. A pattern keyed by that secret is the direct expression of "only the people I gave these to". v2.1 used the XX pattern, which authenticates by long-term identity keys — keys of the wrong type that the specification never bound to an identity and that the reference code never checked (AEG-12). Identity assurance has not been lost by the change: where a sender wants it, it comes from the blob itself, through addressing and signing, in live and stored mode alike.

**What it provides.** Mutual proof of the pre-shared key; forward secrecy from the ephemeral exchange; and, because the pre-shared key is a 256-bit symmetric secret, confidentiality against a quantum adversary who does not also learn the artifacts. Noise patterns of this family have machine-checked analyses (Kobeissi et al. 2019; Dowling et al. 2020; Girol et al. 2020).

**What it does not provide.** A ratchet. v2.1 claimed "session ratcheting"; Noise has none, and a single short-lived session does not need one.

---

## 4. Constructions

### 4.1 The split

**Requirement.** With two artifacts, either one alone — together with everything the server has — must be useless.

**Construction.** The ShareLink carries a random 256-bit `LS`. The ShareKey carries an independent random 256-bit `KS`. Everything is derived from both:

```
PRK_A = HKDF-Extract("", label ‖ mode ‖ LS ‖ KS)
```

This is two-of-two secret sharing with a KDF as the combiner. An adversary holding `LS` faces a 256-bit unknown, `KS`, in the extraction input, so `PRK_A` and everything derived from it is pseudorandom to it; the same holds with the roles reversed.

**The address is derived too.** The blob's location on the server, `blob_id`, is one of the outputs. This is the step that makes the claim hold against server collusion, and the step v2.1 lacked.

| Adversary | v2.1 | v3.0 |
|-----------|------|------|
| Link only | Fetches the ciphertext; blocked only by the recipient's private key | Cannot compute the address; holds nothing |
| Key only | Holds public values | Cannot compute the address; holds nothing |
| Link + server | As link only | Server can supply every blob; without `KS` none can be recognised or opened |
| Key + server | Server scans all blobs for the matching header: found | Without `LS`, none can be recognised or opened |

**Why a server-assigned address would be weaker.** If the server chose the address and the link carried it, then the link alone would locate the ciphertext, and a link thief could at least fetch it, see its size, and exhaust a download limit. Deriving the address removes all three.

**A commitment for free.** `blob_id` is a one-way function of the artifact secrets and is bound into the header's associated data and into the transcript. Two different sets of artifacts leading to the same blob would be a collision in HMAC-SHA-512. So a blob cannot be ambiguous about which artifacts it belongs to.

### 4.2 The two-stage schedule

Stage A uses only what the artifacts carry. Stage B adds whatever else the mode requires.

The stages are separate because of an ordering constraint. A recipient must be able to locate the blob and read its header before it can know whether a KEM key or a passphrase is needed — and the KEM ciphertext it would need is itself inside the blob. So the address and the header key cannot depend on those factors. Everything that protects *content* does.

**Absent factors are zero.** `PRK_B` is extracted from `chain ‖ ss_kem ‖ pw_key` with a fixed layout, unused factors being 32 zero bytes. This is the same device TLS 1.3 uses for an absent pre-shared key. It is unambiguous because the header flags that say which factors are present are bound into the transcript hash, which is the `info` input of every Stage B expansion. A blob sealed without a passphrase cannot be confused with one sealed under a passphrase whose derived key happened to be zero: their transcripts differ.

**Any one unknown factor suffices.** With extraction modelled as a random oracle, `PRK_B` is pseudorandom to anyone who lacks any one of the high-entropy inputs. That is exactly what the mode table in spec §2.4 states: the adversary needs all of them.

### 4.3 The sealed header and mode hiding

The header carries the flags, the passphrase salt and the KEM ciphertext, encrypted under a key from Stage A.

Three decisions make the server's view uniform:

1. **Fixed size.** The header is 1,152 bytes in every mode, with unused fields zeroed. An addressed share and a sealed one differ in no observable length.
2. **Encrypted.** Zero-filled fields are indistinguishable from real ones.
3. **No cleartext at all.** There is no magic number and no version byte. The version travels in the ShareLink.

The result is that a blob is pseudorandom from its first byte to its last. The server cannot tell which mode a share uses, whether it has a passphrase, or whether it is signed — metadata that v2.1 would have exposed had it specified the modes at all. It also means an Aegis blob at rest in third-party object storage has no signature to match.

Someone holding all the artifacts can open the header. In an addressed share without SPLIT, that includes a link thief. What they learn is that the share is addressed, and a KEM ciphertext that does not identify the recipient (§3.3). They do not learn the sender: the manifest and signature are under the Stage B key.

### 4.4 Key commitment

**The problem.** Given two keys, it is easy to build one ChaCha20-Poly1305 ciphertext that both accept, decrypting to two different plaintexts. In a protocol with several key inputs this lets a malicious sender show different files to different openers of "the same" blob, and it makes any abuse report disputable. Where a key can be guessed from a small set, it also enables partitioning-oracle attacks, which test many candidate keys per query.

**The construction.** A 32-byte value `commit`, derived from the Stage B key and the transcript, is stored in the blob and checked before any payload is decrypted.

**Why it works.** For a blob to be accepted under two different key sets, both would have to derive the same `commit`. `commit` is HMAC-SHA-512 output truncated to 256 bits; a collision across different keys implies a collision in SHA-512 truncated to 256 bits, which costs about `2^128` work. The payload key is derived from the same pseudorandom key and transcript, so fixing `commit` fixes it.

This is the approach of age's header MAC and of the commitment key in several vendor encryption SDKs, expressed as one more labelled expansion. It adds no primitive.

**A second use.** The commitment is also the *correct* way to answer "is this the right key?". Trying a recipient's several KEM keys, or a re-entered passphrase, is decided by comparing 32 bytes, never by attempting an AEAD decryption and observing whether it fails.

### 4.5 The payload stream

v2.1 encrypted a file as one AEAD message. That forces a choice between holding the whole file in memory and releasing plaintext before its tag is checked (AEG-08).

v3.0 uses STREAM (Hoang et al. 2015), in the parameterisation age made familiar: 64 KiB chunks, each sealed separately under the same single-use key, with a nonce made of an 11-byte chunk counter and a one-byte final flag.

| Attack | Why it fails |
|--------|--------------|
| Modify a chunk | Tag fails. |
| Reorder or duplicate chunks | The counter is in the nonce; a chunk verifies only at its own position. |
| Truncate | The new last chunk was sealed with the final flag clear, and fails when opened with it set. |
| Append | The old last chunk was sealed with the flag set, and fails when opened as a middle chunk. |
| Splice chunks from another blob | Different key. |

The executable model exercises each of these.

Because chunks are independent given the key, any chunk can be fetched and verified alone. That gives resumable transfers and bounded memory for free, and it is what makes the release rule of spec §8.3 enforceable: plaintext leaves the decryption routine one verified chunk at a time, and the whole is not presented as received until the final chunk has verified.

### 4.6 Padding

Exact file size identifies content surprisingly well: a specific document, a specific software release, a specific photograph. v2.1 mentioned padding in one table cell and never defined it (AEG-06).

v3.0 pads the plaintext stream with Padmé (Nikitin et al. 2019), which rounds a length up to a value with a limited number of significant bits. Two properties matter:

- **Overhead is small.** Padmé's general bound is about 12%, reached only for inputs of a few bytes. Aegis never pads below 64 KiB, and from there upward the padding is always less than 1/32 of the length, about 3.1%, falling to 1.6% above 4 GiB.
- **Leakage is O(log log)** of the size instead of O(log). Between 64 KiB and 1 GiB there are 14 doublings, each with 32 permitted sizes: 448 size classes in total, or under 9 bits, against roughly 30 bits for an exact length.

A floor of one full chunk means everything up to about 64 KiB — notes, keys, short documents — looks identical.

Padding sits inside the encryption, between the content and any signature, and must be all zero and exactly the canonical amount. The strictness is not for secrecy; it is so that every implementation agrees on what a valid blob is.

### 4.7 Sender signatures

v2.1 appended an Ed25519 signature to the blob, in the clear, over the ciphertext. That exposed the sender to anyone who could test candidate public keys, let anyone strip and replace the signature, and bound neither the content nor the recipient (AEG-03).

**Design decisions in v3.0.**

1. **Optional, and off by default.** A signature is permanent, transferable evidence of authorship. For an anonymity tool that must be a choice. v2.1 listed non-repudiation as a goal without noting that it is the opposite of deniability.
2. **Inside the encryption.** The signer's key is in the manifest and the signature is the last 64 bytes of the plaintext stream. Without the keys, nobody can see or test who signed.
3. **Over the content, not just the keys.** In a sealed share every recipient holds the symmetric keys. If the signature covered only the transcript, a recipient could re-encrypt different content under the same keys and keep the genuine signature. So the signature covers a labelled SHA-512 digest of the entire plaintext stream.
4. **Over the transcript and commitment.** This ties the signature to one share and, when addressed, to one recipient. The classic attack on combining signatures with encryption — decrypt, then re-encrypt the signed message to someone else so that it appears to have been sent to them (Davis 2001) — fails because the new share has a different transcript.

**Why at the end.** The digest covers the whole stream, so the signature can only be produced after the last byte. Placing it in a trailer keeps sealing a single pass. The recipient learns that the signature is valid only on completion, which is why the release rule forbids showing a signer as authenticated before then.

**What an unsigned share proves.** Only that its maker held the artifacts. The specification requires clients to say so, and forbids presenting an unsigned share as being "from" anyone (spec §5.3).

### 4.8 Capabilities

The server needs to decide who may fetch and who may delete, without knowing who anyone is. v2.1 left this undefined, so deletion was open to anyone with a link (AEG-11).

v3.0 uses capabilities: authority is a value that cannot be guessed.

- **Read** is knowledge of `blob_id`.
- **Burn** is a token derived from the artifacts, so any legitimate recipient holds it. It lets a recipient's client remove the blob once it has been read.
- **Owner** is a token the sender draws at random. It is deliberately *not* derived from the share secrets, so the sender can erase those — which is what gives sealed shares their forward secrecy — and still revoke the blob later.

The server stores a hash of each delete token, so a leaked server database cannot be used to delete blobs. None of these values helps decrypt anything.

### 4.9 Live transfer

**Layering.** The live tunnel carries the same blob that would have been stored. One content format means one thing to analyse; the tunnel is a transport.

What the tunnel adds is real but specific. The ciphertext is not at rest on the server. A relay that records the session cannot later decrypt its recording by obtaining the artifacts, because the session key also depended on ephemeral keys that are gone. And the sender learns that the recipient verified the whole file.

**Replay.** The first handshake message can be replayed by anyone who recorded it. In response a sender would compute keys the replayer cannot derive, so nothing leaks — but a careless sender would then stream the whole blob to nobody and consider it delivered. The specification therefore requires the recipient's first transport message, `READY`, before any data flows. Producing it needs the ephemeral private key.

**Relay by default.** A direct connection reveals each party's network address to the other. For a protocol whose identity model is "no personal information", that is a disclosure users must choose, so it is opt-in. v2.1 presented peer-to-peer as a privacy improvement and as resilience against server outage; it is neither, since the server still brokers the connection (AEG-21).

### 4.10 Identity

**The seed restores the identity and nothing else.** The Ed25519 identity key is derived from a 32-byte seed that the user writes down. KEM keys are *not* derived from it. If they were, the recovery phrase would decrypt every addressed share the user had ever received, and rotation would be theatre. Because they are random and destroyed on schedule, a stolen device or a stolen phrase exposes at most a bounded window (I16).

The cost is that addressed shares not yet opened are lost with the device. For a transfer protocol with a 30-day maximum lifetime, where the sender can simply seal again, that is the right trade. The client must say so when the user makes a backup.

**Cards.** A card is the identity key's signature over a KEM public key and a validity window of at most 90 days. The window bounds how long a stolen KEM key is useful and how long a replayed old card is accepted.

**No directory.** Publishing cards through the storage service would make it a key server: it would learn who looks up whom, and could serve false keys. Cards travel out of band, and authenticity rests on comparing fingerprints. This is less convenient and it is the only arrangement consistent with I6.

---

## 5. Security Analysis

These are arguments, not proofs. Each names what it assumes.

### 5.1 Assumptions

Spec §15.1 lists them as S1–S8: HKDF as a KDF with random-oracle extraction; collision resistance of truncated HMAC-SHA-512; ChaCha20-Poly1305 as an AEAD with pseudorandom ciphertexts; X-Wing as an anonymous IND-CCA2 KEM; strict Ed25519 as a strongly unforgeable, binding signature; Argon2id as memory-hard; a sound system random number generator; and the security of Noise NNpsk0.

### 5.2 Server blindness (I1–I3, I5, I6, I12)

*Claim.* The server's view of a share — the address, the blob, the two verifiers — is indistinguishable from random strings of the same lengths.

*Argument.* `LS` is uniform and unknown to the server, so `PRK_A` is pseudorandom (S1), and so are its labelled outputs: the address, the header key, the burn token and `chain`. The sealed header is an AEAD ciphertext under a pseudorandom single-use key (S3). `PRK_B` is extracted from an input containing the pseudorandom `chain`, so `commit` and the payload key are pseudorandom (S1). Each chunk is an AEAD ciphertext under that key with distinct nonces (S3). The verifiers are hashes of a pseudorandom token and of a uniform one. What remains observable is length, timing and network metadata: the set **L** of spec §2.6.

Nothing a user's identity key touched is outside the AEAD, so the server sees no public key and can test no guess about who sealed the blob.

### 5.3 The split (I7)

*Claim.* An adversary with the server's state and one artifact does no better than the server alone.

*Argument.* Holding `LS` but not `KS`, the adversary knows 32 bytes of the extraction input and faces 256 bits of entropy in the rest. `PRK_A` remains pseudorandom to it (S1), and the argument of §5.2 goes through unchanged. The other case is symmetric. In particular the adversary cannot compute `blob_id`, so with the server's help it can obtain every blob and still cannot tell which one is its target.

### 5.4 Integrity and uniqueness (I9, I11)

Any alteration of the header changes the transcript, hence the keys, hence the commitment — or fails the header's own tag. Any alteration of a chunk fails that chunk's tag; reordering, truncation and extension fail as tabulated in §4.5 (S3). Uniqueness follows from §4.4 (S2).

The release rule turns these detections into a guarantee about behaviour: an implementation that follows it never hands unverified bytes to the user.

### 5.5 Addressed shares

*Claim.* An adversary holding every artifact, but not the recipient's KEM private key, learns nothing about the content.

*Argument.* It can compute Stage A and open the header. `ss_kem` is indistinguishable from random given the ciphertext and public key (S4), so `PRK_B` is pseudorandom (S1), and the payload is protected as before.

*And the converse:* an adversary holding the recipient's private key but lacking an artifact is in the position of §5.3.

### 5.6 Signatures

*Claim.* If a signed share opens and names identity key `K`, then the holder of `K` signed exactly this content for exactly this share and recipient.

*Argument.* The signed message contains the transcript hash, the commitment, and a SHA-512 digest of the stream. Producing a valid signature on a different triple is a forgery (S5) or a hash collision (S2). The transcript hash fixes the address, the header and the recipient binding; the digest fixes the manifest, content and padding. Strict verification excludes the degenerate keys for which signatures are not binding.

### 5.7 Forward secrecy

"Forward secrecy" was used loosely in v2.1 and is defined per mode here.

| Mode | What is compromised later | What stays secret | Why |
|------|---------------------------|-------------------|-----|
| Sealed | Any device, any long-term key | Everything, provided the artifacts were erased | No long-term key was ever involved. |
| Sealed | A channel history containing an artifact | Everything, unless *both* histories are obtained (with SPLIT) | §5.3 |
| Addressed | Recipient's device, including KEM keys | Shares to KEM keys already destroyed | I16; random, scheduled keys |
| Addressed | Recovery seed | All shares | KEM keys are not derived from it |
| Live | The artifacts, after the session | The recorded session | Ephemeral exchange (S8) |

v2.1's claim — that deleting the sender's ephemeral key protects past files against compromise of the recipient's long-term key — described none of these and was false (AEG-02).

Stronger forward secrecy for addressed shares would need one-time prekeys (Marlinspike and Perrin 2016) and with them a directory that hands them out, which is in tension with I6. It is deferred, not dismissed.

### 5.8 Post-quantum analysis

Take an adversary who records everything now and has a large quantum computer later.

| Mode | Adversary additionally holds | Outcome |
|------|------------------------------|---------|
| Sealed, any | Nothing | Safe: only symmetric primitives with 256-bit keys are involved. |
| Addressed | Nothing | Safe: `LS` is unknown, so the KEM is not even reached. |
| Addressed | The ShareLink | Safe while ML-KEM-768 holds. |
| Addressed + split | The ShareLink | Safe: `KS` is unknown. |
| Live | Nothing | Safe: the pre-shared key is symmetric. |
| Live | The artifacts, obtained later | Session key recoverable by breaking X25519. The inner blob is then protected as in the rows above. |

The default mode needs no post-quantum assumption at all. That is a consequence of choosing a symmetric split as the foundation, and it is the strongest argument for that choice.

Signatures are a separate matter. Ed25519 can be forged by a quantum adversary, but only from the day such a machine exists; it does not undo the confidentiality of anything already sealed. Hybrid signatures are deferred.

### 5.9 Numbers

| Event | Bound |
|-------|-------|
| Guess a 256-bit secret | `2^-256` per attempt; about `2^128` quantum work |
| Two of `2^64` blobs share an address | `≈ 2^-129` |
| Find two key sets opening one blob (I11) | `≈ 2^128` work |
| Forge one full payload chunk | `≈ 2^-91` per attempt |
| Forge a ShareLink or ShareKey checksum | `2^-32`, deliberately: it detects typing errors and has no security role |
| Find a second identity key with a given fingerprint | `≈ 2^160` work |

---

## 6. Metadata

Content is the easy part. Who communicates with whom, and when, is what an adversary with legal power usually wants, and it is where "the server knows nothing" has to be most careful.

**What Aegis removes.** Names, types and exact sizes are encrypted. The share's mode is hidden. No public key reaches the server. There are no accounts, so nothing links two uploads by the same person at the protocol level.

**What Aegis cannot remove.** A network address connected at a certain time and moved a certain number of bytes. If one address uploads a 3 MB blob and another fetches it a minute later, the server knows those two addresses share a file.

**What follows.**

- The specification enumerates this residue (spec §2.6) instead of claiming there is none.
- Clients should work through a SOCKS proxy, and services should be reachable as onion services. With both, the server sees neither party's address.
- An operator can be legally compelled to start recording what it is able to observe. The Proton case of 2021 is the standard example: a provider that kept no address logs was ordered to collect them for one account, and did. "We keep no logs" is a policy; "we cannot see it" is a property. Only the second survives an order, and Aegis's guarantees are written in terms of the second.
- Padding reduces what size reveals, but not to zero. Timing is not hidden at all. Hiding it needs cover traffic or mixing, which is a different system.

---

## 7. What a Formal Model Must Show

The executable model shows that the specification can be implemented and that it rejects what it should. It says nothing about whether an attack exists that nobody thought to test. That needs a symbolic model — Tamarin or ProVerif — in which the tool searches for attacks.

**Lemmas to prove.**

| # | Lemma | Invariant |
|---|-------|-----------|
| 1 | Content secrecy against the server together with the ShareLink (SPLIT set) | I7 |
| 2 | Content secrecy against the server together with the ShareKey | I7 |
| 3 | Content secrecy against the server and all artifacts, without the recipient's KEM key (ADDRESSED) | §2.4 |
| 4 | Content secrecy against a later reveal of a KEM key whose epoch had been destroyed | I16 |
| 5 | If an opener accepts content `m` for a share, some party holding that share's factors sealed `m` | I9 |
| 6 | If an opener accepts a signature by `K` on `m` for share `s` and recipient `r`, then `K`'s holder signed `m` for `s` and `r` | §7.5 |
| 7 | A signature accepted in share `s` is never accepted in a share `s′ ≠ s` | §7.5 |
| 8 | No public key of any user is derivable from the server's view | I6, I12 |
| 9 | Live: a session completes only between holders of the artifacts | §11 |
| 10 | Live: session keys stay secret after the artifacts are revealed post-session | §11.6 |
| 11 | Live: the sender sends data only after the recipient has proved possession of its ephemeral key | §11.4 |
| 12 | No secret-bearing term is ever sent to the server | I14 |

**Outside a symbolic model.** Pseudorandomness of the server's view, the collision argument for I11, and the padding leakage are computational statements. They rest on the reductions sketched in §5, and a tool such as CryptoVerif could mechanise the key schedule. That is a stretch goal; the twelve lemmas above are the minimum.

**Outside any model.** The release rule, erasure of secrets, constant-time comparison and the user-interface obligations are properties of an implementation. They are covered by tests and review (plan M3, M5, M9).

---

## 8. Open Problems

1. **Short codes.** People want to read a few words over the phone. Done naively, a short code is something the server can guess offline. Done with a PAKE it is sound, but only when both parties are online. Whether it can be offered without users mistaking it for the stored mode is as much a design question as a cryptographic one.
2. **Several recipients.** Wrapping one content key to several KEM keys is routine. Doing it while hiding how many recipients there are, in a fixed-size or padded header, needs care.
3. **Forward secrecy without a directory.** One-time prekeys need distribution. Fetching them through an anonymising transport, or having each contact hold a small batch, are both possible and both awkward.
4. **Deniable authentication.** A static Diffie–Hellman between identities would authenticate the sender to the recipient without creating evidence for third parties. It is classical-only and is open to impersonation if the recipient's key leaks. Whether it is worth a third origin mode is undecided.
5. **Timing.** Nothing in Aegis hides when a transfer happens.
6. **Abuse.** Proof-of-work is a weak deterrent. Privacy Pass tokens are stronger but need an issuer who must itself not learn identities. There is no settled answer for an anonymous storage service.
7. **The human channel.** The split is only as good as the user's choice of two channels. How a client can encourage a good choice without lecturing is unsolved.

---

## 9. Implementation Technology

Short, because the implementation plan covers it.

**Language.** Rust, for memory safety without a garbage collector, and because every primitive Aegis needs has a maintained pure-Rust implementation. This removes the memory-corruption class from safe code. It does not remove logic errors, and `unsafe` blocks and FFI boundaries need the same scrutiny as C. v2.1's "eliminates this class entirely" overstated it (AEG-27).

**Erasing secrets** in a language that moves values freely is best-effort: a moved value may leave a copy behind that no destructor will ever see. The plan requires heap-pinned secret types, and the threat model states the limit plainly.

**Library selection criteria**, in order:

1. Implements the pinned specification exactly, and passes its official test vectors.
2. Has been independently audited, or formally verified, in a version close to the one used.
3. Constant-time by construction for secret-dependent operations.
4. Maintained, with a history of prompt security fixes.
5. Small dependency tree.
6. An API that makes misuse hard — for instance, an ephemeral-secret type that is consumed by use.

Specific crates and versions are chosen and recorded at plan milestone M0, with the audit status of each verified at that time, not taken from this document.

---

## 10. References

**Standards**

1. FIPS 180-4. *Secure Hash Standard.* NIST, 2015.
2. FIPS 203. *Module-Lattice-Based Key-Encapsulation Mechanism Standard.* NIST, 2024.
3. RFC 2119 / RFC 8174. *Key words for use in RFCs to Indicate Requirement Levels.*
4. RFC 4648. S. Josefsson. *The Base16, Base32, and Base64 Data Encodings.* 2006.
5. RFC 5869. H. Krawczyk, P. Eronen. *HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* 2010.
6. RFC 7748. A. Langley, M. Hamburg, S. Turner. *Elliptic Curves for Security.* 2016.
7. RFC 8032. S. Josefsson, I. Liusvaara. *Edwards-Curve Digital Signature Algorithm (EdDSA).* 2017.
8. RFC 8265. P. Saint-Andre, A. Melnikov. *Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords.* 2017.
9. RFC 8439. Y. Nir, A. Langley. *ChaCha20 and Poly1305 for IETF Protocols.* 2018.
10. RFC 9106. A. Biryukov, D. Dinu, D. Khovratovich, S. Josefsson. *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.* 2021.
11. RFC 9576, 9577, 9578. *Privacy Pass* architecture, authentication scheme, and issuance protocols. 2024.
12. T. Perrin. *The Noise Protocol Framework*, revision 34. 2018.
13. D. Connolly, P. Schwabe, B. Westerbaan. *X-Wing: general-purpose hybrid post-quantum KEM.* Internet-Draft `draft-connolly-cfrg-xwing-kem`.
14. *Bitcoin Improvement Proposal 39: Mnemonic code for generating deterministic keys.* 2013. (Wordlist and checksum only.)

**Papers**

15. A. Albertini, T. Duong, S. Gueron, S. Kölbl, A. Luykx, S. Schmieg. *How to Abuse and Fix Authenticated Encryption Without Key Commitment.* USENIX Security 2022.
16. J. H. An, Y. Dodis, T. Rabin. *On the Security of Joint Signature and Encryption.* EUROCRYPT 2002.
17. M. Barbosa, D. Connolly, J. D. Duarte, A. Kaiser, P. Schwabe, K. Varner, B. Westerbaan. *X-Wing: The Hybrid KEM You've Been Looking For.* IACR Communications in Cryptology, 2024.
18. D. J. Bernstein. *The Poly1305-AES Message-Authentication Code.* FSE 2005.
19. D. J. Bernstein. *Curve25519: New Diffie-Hellman Speed Records.* PKC 2006.
20. D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang. *High-Speed High-Security Signatures.* Journal of Cryptographic Engineering, 2012.
21. J. Brendel, C. Cremers, D. Jackson, M. Zhao. *The Provable Security of Ed25519: Theory and Practice.* IEEE S&P 2021.
22. K. Chalkias, F. Garillot, V. Nikolaenko. *Taming the Many EdDSAs.* SSR 2020.
23. D. Davis. *Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML.* USENIX Annual Technical Conference 2001.
24. J. P. Degabriele, J. Govinden, F. Günther, K. G. Paterson. *The Security of ChaCha20-Poly1305 in the Multi-User Setting.* ACM CCS 2021.
25. Y. Dodis, P. Grubbs, T. Ristenpart, J. Woodage. *Fast Message Franking: From Invisible Salamanders to Encryptment.* CRYPTO 2018.
26. B. Dowling, P. Rösler, J. Schwenk. *Flexible Authenticated and Confidential Channel Establishment (fACCE): Analyzing the Noise Protocol Framework.* PKC 2020.
27. G. Girol, L. Hirschi, R. Sasse, D. Jackson, C. Cremers, D. Basin. *A Spectral Analysis of Noise: A Comprehensive, Automated, Formal Analysis of Diffie-Hellman Protocols.* USENIX Security 2020.
28. P. Grubbs, J. Lu, T. Ristenpart. *Message Franking via Committing Authenticated Encryption.* CRYPTO 2017.
29. P. Grubbs, V. Maram, K. G. Paterson. *Anonymous, Robust Post-Quantum Public Key Encryption.* EUROCRYPT 2022.
30. V. T. Hoang, R. Reyhanitabar, P. Rogaway, D. Vizár. *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance.* CRYPTO 2015.
31. N. Kobeissi, G. Nicolas, K. Bhargavan. *Noise Explorer: Fully Automated Modeling and Verification for Arbitrary Noise Protocols.* IEEE EuroS&P 2019.
32. H. Krawczyk. *Cryptographic Extraction and Key Derivation: The HKDF Scheme.* CRYPTO 2010.
33. J. Len, P. Grubbs, T. Ristenpart. *Partitioning Oracle Attacks.* USENIX Security 2021.
34. V. Maram, K. Xagawa. *Post-Quantum Anonymity of Kyber.* PKC 2023.
35. K. Nikitin, L. Barman, W. Lueks, M. Underwood, J.-P. Hubaux, B. Ford. *Reducing Metadata Leakage from Encrypted Files and Communication with PURBs.* PoPETs 2019.
36. G. Procter. *A Security Analysis of the Composition of ChaCha20 and Poly1305.* IACR ePrint 2014/613.

**Systems and specifications**

37. F. Valsorda, B. Cartwright-Cox. *The age file encryption format*, `age-encryption.org/v1`.
38. M. Marlinspike, T. Perrin. *The X3DH Key Agreement Protocol.* Signal, 2016.
39. E. Kret, R. Schmidt. *The PQXDH Key Agreement Protocol.* Signal, 2023.
40. B. Warner. *Magic Wormhole.*
41. Z. Wilcox-O'Hearn, B. Warner. *Tahoe – The Least-Authority Filesystem.* ACM StorageSS 2008.
42. Mozilla. *Firefox Send* (2017–2020).

---

**End of Research Document**
