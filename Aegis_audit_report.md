# Aegis v2.1 — Cryptographic Audit

**Subject:** `Aegis_project_specification.md`, `Aegis_research.md`, `Aegis_implementation_plan.md` at commit `a531356` (v2.1, 2026-06-29)
**Audit date:** 2026-11-16
**Outcome:** v2.1 is withdrawn. It is replaced by the v3.0 documents in this repository.

---

## 0. Verdict

The instincts behind Aegis are right. The protocol as written does not deliver them.

Seven of the properties v2.1 advertises are not provided by the construction it specifies, and one of them — split-key delivery, the feature the documents call unique — is a no-op: the "key" artifact contains no secret. Forward secrecy is claimed and absent. Sender anonymity is claimed and defeated by a signature the server can test. The three documents describe three mutually incompatible protocols, so no two implementations could interoperate, and the code in the plan does not compile.

None of this needs exotic cryptanalysis. Every critical finding below follows from reading §5.3 and §7.1 of the specification side by side.

This is fixable, and nothing has shipped, so the cost of fixing it is zero. The v3.0 rewrite keeps every invariant you declared, makes each of them a statement that can be tested, and adds ten more.

---

## 1. Scope, method, and what this audit is not

**Covered:** protocol design, key schedule, wire formats, threat model, claims, the reference code in the plan, engineering process.

**Method:** for each claimed property, find the adversary the claim is about, give that adversary exactly what the specification gives it, and work out what it can compute. Then check the three documents against each other.

**Not covered, and not replaceable by this document:**

- No machine-checked proof exists for v2.1 or v3.0. v3.0 comes with an executable model and provisional test vectors (`model/`), which show the specification is implementable and self-consistent. They do not show it is secure.
- This audit was produced by an AI model. Your own specification (§9.4) says AI in the cryptographic path is unverifiable, and that rule is correct. Treat this report and the v3.0 documents as a draft written to be attacked: a symbolic model, independent human review, and time in public are still owed before anyone relies on it. The implementation plan schedules all three.

Severity scale: **Critical** — a stated security goal or invariant does not hold. **High** — exploitable weakness or a gap that makes secure implementation impossible. **Medium** — weakens the design or will cause implementation divergence. **Low/Info** — errors of fact, overclaims, hygiene.

---

## 2. What I approve

These are sound and survive into v3.0 unchanged in spirit.

| # | Decision | Why it is right |
|---|----------|-----------------|
| 1 | "The server knows nothing" as the organising principle | Designing against your own operator is the only server threat model that survives contact with breaches, insiders and subpoenas. |
| 2 | A short list of non-negotiable invariants | Most projects never write these down. Having them is what made this audit possible: each one is a claim that can be checked. |
| 3 | All cryptography on the client; server as dumb blob store | Correct trust placement. Kept and tightened. |
| 4 | An explicit non-goals section | Endpoint compromise, malicious recipients and coercion are honestly out of reach. Saying so is a strength. |
| 5 | The idea of split delivery across two channels | Two-channel secret sharing is a real defence. The idea is right; only the construction was empty. v3.0 makes it a true 2-of-2 split. |
| 6 | Fresh key material per file | Correct. Kept and made structural (every key is single-use). |
| 7 | Identity is a key, no accounts, no PII, no server-side recovery | Correct, and consistently held. |
| 8 | The Curve25519 / Ed25519 / ChaCha20-Poly1305 family | Conservative, widely analysed, misuse-resistant implementations exist. |
| 9 | Noise for live channels | Right tool. Wrong pattern and wrong usage, but right tool. |
| 10 | Argon2id for passphrases; Rust; RustCrypto and dalek crates | All defensible. |
| 11 | Rejecting custom ciphers, blockchain, accounts | Correct. |
| 12 | Separating the protocol library from the reference application; no shipping before audit; declining mobile scope | Good engineering discipline. Scope restraint is rare and valuable. |
| 13 | Wanting a state machine, an error taxonomy, test vectors, and a conformance suite | The right deliverables. v2.1 only sketched them; v3.0 fills them in. |

---

## 3. Findings

### Critical

#### AEG-01 — The ShareKey contains no secret. Split-key delivery is a no-op.

*Evidence: spec §5.4, §7.1.*

The ShareKey is `{v, ep, sl, id}`: the ephemeral **public** key, the salt, and a file ID. The EncryptedPackage stores the ephemeral public key at bytes `[1..33]` and the salt at `[33..65]`. So two of the three fields are copies of data in the blob that the ShareLink already points to.

The third field, `file_id`, is an HKDF `info` input. The specification gives it no length, no entropy requirement and no generation rule; the plan's own tests use `b"test-file-001"`.

Meanwhile the value that actually gates decryption — the recipient's X25519 private key — is in neither artifact.

Consequences:

- An attacker with the link is stopped by the recipient's private key, not by channel B. Channel B contributes nothing the design can rely on.
- Wherever `file_id` is guessable, "both artifacts required for access" is simply false.
- The diagram labelling Artifact B "decryption key via separate channel" describes a different protocol from the one specified.
- The design cannot serve the use case that motivates share links at all: sending a file to someone who has not published a key in advance.

*v3.0 fix:* the link carries a 256-bit secret `LS`, the key carries a 256-bit secret `KS`, and every key — including the blob's address on the server — is derived from both (spec §4, §6.1). Either artifact alone, even combined with the server's entire state, yields nothing. This is now invariant I7.

#### AEG-02 — There is no forward secrecy. The claim is false.

*Evidence: spec §1.1, §5.5, §8.4; research §6.2.*

> "Even if a user's long-term identity key is later compromised, files encrypted with past ephemeral keys remain protected."

The blob stores `e_pub` and `salt`. Anyone who later obtains the recipient's static private key computes `X25519(sk_R, e_pub)`, runs the KDF, and decrypts every file ever sent to that recipient. Deleting `e_priv` protects against later compromise of the *sender* only.

This construction is ECIES (equivalently HPKE base mode), which is defined as not forward secret against recipient compromise. The worked example in research §6.2 makes the same mistake.

"Signal-level security" is therefore wrong on its central point: Signal's forward secrecy comes from one-time prekeys and ratcheting, and v2.1 has neither.

*v3.0 fix:* three honest levels, each stated precisely (spec §15.2). Sealed shares involve no long-term key at all, so secrecy depends only on the artifacts being erased. Addressed shares use KEM keys that rotate and are destroyed on a schedule, and are never derivable from the recovery seed (I16). Live transfers get ephemeral-DH forward secrecy.

#### AEG-03 — The sender signature sits outside the encryption and binds nothing that matters.

*Evidence: spec §5.3 steps 6–7, §7.1, §8.4.*

Four separate failures:

1. **It deanonymises the sender.** The signature is the last 64 bytes of the blob, in the clear. Ed25519 verification is a public operation. Anyone holding the blob and a list of candidate public keys can test which one signed it. Identity keys are meant to be handed out, so "the server does NOT know: sender" is false against anyone the sender has ever dealt with. This breaks invariants 3 and 5.
2. **It can be stripped and replaced.** The signed bytes are `e_pub ‖ salt ‖ nonce ‖ ciphertext`. Nothing inside the AEAD names the sender. Whoever can touch the blob removes the signature and appends their own; the recipient decrypts genuine content and attributes it to the attacker. This is the textbook failure of encrypt-then-sign without identity binding (Davis 2001; An, Dodis, Rabin 2002).
3. **It does not cover** the version byte (the specification signs without it, the plan signs with it), the `file_id`, the metadata, or the recipient.
4. **The recipient has no specified way to learn** `sender_public_key` in the first place.

Separately: v2.1 lists non-repudiation as a goal. For an anonymity tool that is a liability — every upload becomes a permanent, transferable proof of authorship. It should be opt-in, never the default.

*v3.0 fix:* sender signatures are optional, live inside the encrypted stream, and cover the full transcript, the key commitment, the recipient binding and a hash of the content (spec §7.5). The server never sees any public key of any user (I12).

#### AEG-04 — The recipient key is the wrong type and comes from nowhere.

*Evidence: spec §5.3 step 2, §5.6; plan §1.7.*

Identity is an Ed25519 key. Encryption uses `X25519(e_priv, recipient_public_key)`. No conversion and no subordinate key is defined; the plan's tests use an unrelated X25519 keypair as "the recipient".

Worse, nothing authenticates a recipient key: no fingerprint, no verification ceremony, no signed encryption key. Whoever controls the channel a public key first arrives on owns every file sent afterwards. The table entry "Network attacker / MITM: Immune" has no support.

*v3.0 fix:* a signed identity card binds a rotating KEM key to the Ed25519 identity key; fingerprints and a verification state are part of the protocol (spec §9).

#### AEG-05 — The three documents specify three different protocols.

| Item | Specification | Research | Plan |
|------|---------------|----------|------|
| KDF | "HKDF-BLAKE3" | HKDF over an unnamed hash | HKDF-SHA-256 |
| KDF label | `"file-encryption" ‖ file_id` | `"file-encryption"` | `"aegis-file-encryption-v1" ‖ file_id` |
| Nonce | `BLAKE3(nonce_key ‖ rand16)[0:24]` | random | 24 random bytes |
| Signature covers version byte | no | — | yes |
| ShareLink | JSON `{v,s,b,m}` | — | `aegis://share/` + base64url of JSON with different field names |
| ShareKey | JSON with version, base64url fields | — | JSON without version, byte arrays as JSON number arrays |
| Metadata | "encrypted separately" | separate `metadata_key` | passed in plaintext as AAD |
| Package encoding | fixed byte layout | — | `serde` derive, format unspecified |

"HKDF-BLAKE3 — Standard" names something that does not exist: HKDF is defined over HMAC (RFC 5869), and BLAKE3 has its own key-derivation mode. §7.5 requires primitives "exactly as specified in their respective standards", but neither XChaCha20-Poly1305 nor BLAKE3 has one — both exist only as Internet-Drafts.

*v3.0 fix:* one suite, every primitive pinned to a published reference, every byte specified once, and an executable model that generates the test vectors (spec §3, §14; `model/`).

#### AEG-06 — "A complete server compromise reveals nothing" is false as written.

*Evidence: spec §3.1, §4.3, §6.1, §6.3, §8.*

What the v2.1 server observes, none of it enumerated anywhere:

- exact file size (padding is mentioned once in a table and never specified);
- upload time, every download time, download counts;
- client IP addresses — the specification's own P2P diagram says "Server learns: IP addresses (already knows)";
- "anonymous tokens", which are never defined and are therefore linkable identifiers;
- the cleartext signature (AEG-03);
- in P2P mode, exactly who is talking to whom.

The threat model also considers only a thief who copies the database. A server that is *actively* malicious — withholding, truncating, replaying, keeping blobs past their TTL, serving different bytes to different people — is never analysed.

*v3.0 fix:* the invariant is kept and made falsifiable. The specification enumerates the complete leakage set (spec §2.6); everything else, including the share mode, is pseudorandom to the server. Sizes are padded. The active server is the default adversary (I13).

#### AEG-07 — No defence against harvest-now-decrypt-later.

An untrusted server holding ciphertext whose only key agreement is X25519 is the canonical target for recording today and decrypting with a future quantum computer. A design whose premise is "assume the server is the adversary" must also assume that adversary keeps every blob forever; the TTL is a promise, not a mechanism.

v2.1 contains no post-quantum component and no discussion of the threat. By 2026 that is not a defensible omission: ML-KEM is a final standard (FIPS 203), and Signal, iMessage and TLS deployments have all moved to hybrid key agreement.

*v3.0 fix:* sealed shares are symmetric-only, so they are post-quantum by construction. Addressed shares use the X-Wing hybrid KEM (X25519 + ML-KEM-768), and still mix in the link secret (spec §3, §6).

### High

#### AEG-08 — The whole file is one AEAD message.

The wire format has one nonce and one tag. The plan's API is `&[u8] → Vec<u8>`. An implementation must either hold the entire file in memory, or decrypt as a stream and hand out plaintext before the tag is checked. The state machine mentions "chunks", §8.4 mentions BLAKE3 over chunks, the research document mentions per-chunk keys; none of it is in the format. Nothing defends against truncation or reordering.

*v3.0 fix:* STREAM construction, 64 KiB chunks, counter nonces with a final-chunk flag, random access, and an explicit rule on when plaintext may be released (spec §7.2, §8.3, I9).

#### AEG-09 — No key commitment.

ChaCha20-Poly1305 does not commit to its key. A malicious sender can build one ciphertext that decrypts correctly under two different keys to two different files. In a protocol with several key inputs that means different holders can be shown different content, and if any key is ever derived from a low-entropy secret — the specification suggests reading keys over a phone call — partitioning-oracle attacks apply (Len, Grubbs, Ristenpart 2021).

*v3.0 fix:* a 32-byte commitment derived from the full key schedule is checked before any payload decryption (spec §6.6, I11).

#### AEG-10 — Metadata encryption and AAD are undefined.

"Encrypt metadata (filename, size, type)" — with what key, what nonce, stored where? `aad` appears in the encryption call and is never defined. The plan passes the plaintext filename as AAD and requires the receiver to already know it.

*v3.0 fix:* metadata is a manifest at the start of the encrypted stream (spec §7.3).

#### AEG-11 — The server API has no authorisation model.

`DELETE /:id` is unauthenticated: anyone holding a link can destroy the file, which contradicts "link theft accomplishes nothing". Uploads are unauthenticated, so storage can be exhausted at will. Rate limiting "per IP" requires holding IPs. Nothing says whether a blob can be overwritten.

*v3.0 fix:* capability tokens — a secret-derived blob address, an owner delete token independent of the share secrets, an optional recipient burn token — plus write-once blobs and anonymous admission control (spec §10).

#### AEG-12 — Noise XX is misused.

1. XX transmits static keys; authentication exists only if each side checks the key it received against one it expected. Neither the specification nor the plan does. The plan generates a fresh random static key for the initiator, hands `remote_public_key` to a pattern in which that key is transmitted and not known in advance, and never compares the key it receives with the one it expected. The result is an encrypted channel to whoever answered.
2. Identities are Ed25519; Noise statics are X25519. The binding is undefined.
3. "Session ratcheting" and "key ratcheting" are claimed. Noise has no ratchet.
4. Peers "must negotiate the highest mutually supported version or fail closed", with no negotiation mechanism and nothing binding the outcome to the handshake.
5. Noise messages are capped at 65,535 bytes; the plan's `send` fails beyond that.
6. In XX the responder's identity is disclosed to any active prober, so "identity hiding" is one-sided.

*v3.0 fix:* `Noise_NNpsk0_25519_ChaChaPoly_SHA512` keyed by a secret derived from the artifacts, a prologue that binds the session, and no claims the pattern does not support (spec §11).

#### AEG-13 — The key schedule binds nothing.

The KDF input excludes the ephemeral public key, the recipient's public key, the sender, the version and the suite. X25519 public keys have several encodings that produce the same shared secret, so the header is malleable. Concatenations are not length-delimited. There is no check for the all-zero shared secret, so a low-order "recipient key" makes the file key a public function of the public salt.

*v3.0 fix:* labelled, length-prefixed derivations with a transcript hash over every public value (spec §3.2, §6.4, I10).

#### AEG-14 — Signature verification rules are not pinned.

Ed25519 implementations disagree on non-canonical encodings, small-order points, and cofactored versus cofactorless checks (Chalkias, Garillot, Nikolaenko 2020). Two conforming clients can disagree about whether the same signature is valid.

*v3.0 fix:* strict verification is mandatory and defined (spec §3.3).

#### AEG-15 — The nonce derivation is custom cryptography that makes things worse.

`nonce = BLAKE3(nonce_key ‖ random_bytes(16))[0:24]` fills a 192-bit nonce from 128 bits of entropy, after the specification justified XChaCha20 specifically by its 192-bit random nonces. And because the key is already unique per file, the nonce could have been a constant. §9.4 of the same document "categorically rejects" custom cryptography.

*v3.0 fix:* no random nonces anywhere. Keys are single-use; nonces are counters.

#### AEG-16 — Identity storage and recovery are unsafe.

*Evidence: plan §2.1, §2.2, App Phase 3.*

- `Argon2::default()` is roughly 19 MiB and two passes — a floor for web logins, not a setting for wrapping an unrecoverable identity.
- `hash_password` is the password-verification API; key derivation needs `hash_password_into`.
- The file stores no parameters and no version, so the settings can never be raised.
- `std::fs::write` is not atomic. A crash during save destroys the only copy of a key the protocol promises cannot be recovered.
- The recovery phrase encodes the raw signing key. There is no derivation hierarchy, and the unrelated X25519 key is not recoverable at all.
- App Phase 3 caches the passphrase-derived key in the OS keychain, where any process running as the user can request it. This contradicts Appendix A.2, which rejects platform keystores as unauditable.

*v3.0 fix:* spec §9.7 and Appendix C; plan Milestone 5.

#### AEG-17 — Wire format rules contradict each other.

§7.5 says unknown fields must be rejected; §7.3 says minor versions add optional fields. Versioning is "major.minor", but the formats carry a single integer or a single byte. The JSON has no canonical form, base64url padding is unspecified, and encrypted metadata is placed in the link, where it cannot be bound to the blob.

*v3.0 fix:* fixed binary layouts, one version number, extensions only inside the authenticated manifest with a critical bit (spec §4, §7.3, §13).

### Medium

| ID | Finding | v3.0 |
|----|---------|------|
| AEG-18 | The state machine covers only the sender, has no failure states and no receiver, and its "no backward transitions" rule collides with the "retry with backoff" error action. | §8.4 |
| AEG-19 | Four error codes. Nothing for truncation, version mismatch, expiry or malformed input, and no rule on what a remote party may learn from a failure. | §12 |
| AEG-20 | Keys "delivered by voice" would be well over 100 base64 characters. If shortened, the server — which holds the ciphertext — brute-forces them offline. | §4.3, App. E |
| AEG-21 | P2P discloses each peer's IP to the other and the pairing to the server. "Transfers proceed even if the server is unreachable" is false: the server does the signalling. | §11 |
| AEG-22 | Appendix A.4 makes split-key "optional for low-security shares"; §11.2 says implementations must support two channels. | §5 |
| AEG-23 | TTL is presented as a security property. It is a courtesy the server may ignore. | §10.6 |
| AEG-24 | The reference code does not compile and embeds unsafe patterns: `StaticSecret` used for ephemerals (the crate offers `EphemeralSecret` precisely so reuse is a compile error); public fields on secret types; use after move in `recover_from_phrase`; `serde` derive on a 64-byte array; more than ten functions and types that are used and never defined; `thiserror` used but absent from the crate manifest; `getrandom`'s `js` feature enabled in a library crate for a web target that does not exist. | Plan |
| AEG-25 | Process: the specification is "locked" after the code is written; the audit is last; success criteria are unfalsifiable ("mathematically verified", "resist side-channel analysis", "100% coverage"); the fuzz target generates fresh random keys per run, so every input fails signature verification and the decrypt path is never reached; CI fuzzes for 60 seconds; no known-answer tests, no Wycheproof, no formal model. | Plan |
| AEG-26 | Supply chain: Node and pnpm build the binary that holds keys while the specification bans Node from the crypto path; WebView patching is delegated to the OS; CI actions are pinned by tag; no `cargo-vet` or `cargo-deny` policy; no reproducible builds; Kubernetes and S3 for what is one static binary and a directory. | Plan |

### Low / Informational

#### AEG-27 — Errors of fact in the research document

| Where | Statement | Correction |
|-------|-----------|------------|
| §3.3 | Ed25519 signs ~50k/s and verifies ~200k/s | Inverted. Verification is slower. The original paper reports about 109k signatures/s and 71k verifications/s on a 2010 quad-core. |
| §3.3.3 | Security "relies on SHA-512's collision resistance" | Pure Ed25519 is collision-resilient by design. |
| §3.3.3, §3.2.4 | Ed25519 "immune by design" to small-subgroup attacks; Curve25519 has "no cofactor complications" | The cofactor is 8. It is the source of nearly every Ed25519 edge case (see AEG-14). |
| §3.3 | "512-bit private keys" | The private key is a 32-byte seed. |
| §2.1 | XChaCha20-Poly1305 is "the same class of algorithm used in TLS 1.3, WireGuard and Signal Protocol" | TLS 1.3 and WireGuard use ChaCha20-Poly1305 with 96-bit nonces. Signal's Double Ratchet uses AES-256-CBC with HMAC-SHA-256. |
| §7.1 | Noise is used by "Signal Protocol" and "Zcash" | Signal Protocol is X3DH/PQXDH plus Double Ratchet. WhatsApp uses Noise for client–server transport only. The well-known cryptocurrency use is Lightning (BOLT 8). |
| §7.2 | "specified by three choices", then lists four | — |
| §4.5 | BLAKE3 preimage resistance 256 bits | The designers claim 128-bit security for every goal, preimage included. |
| §4.6 | BLAKE3 for "content addressing" | Contradicts the specification's random blob IDs, and plaintext-derived identifiers enable confirmation-of-file attacks. |
| §5.1, §5.3 | HKDF can "stretch limited-entropy input"; "Forward secrecy: PRK not recoverable from OKM" | HKDF adds no entropy; feeding it passwords is unsafe. The second property is one-wayness, not forward secrecy. |
| §8 | NIST SP 800-207 "Zero Trust" as the security model | SP 800-207 is an enterprise access-control architecture built on continuously verifying users, devices and location — the opposite of anonymity. The model Aegis needs is the cryptographic one: end-to-end security against a malicious intermediary. |
| §10.1 | "70% of CVEs are memory safety issues. Rust eliminates this class entirely." | The figure is Microsoft's and Chromium's for their own C/C++ code. Safe Rust removes the class; `unsafe`, FFI and logic errors remain. |
| §14 ref. 10 | "Langley, A. (2020). ChaCha20-Poly1305 Cipher Suites for TLS. RFC 8439" | RFC 8439 is Nir and Langley, "ChaCha20 and Poly1305 for IETF Protocols", 2018. The TLS cipher suites are RFC 7905 (2016). |

#### AEG-28 — Overclaims in the specification

- "Computationally indistinguishable from random noise": the blob starts with `0x01`, has a fixed structure, and ends with a publicly verifiable signature.
- "Immune … mathematically futile regardless of the attacker's resources": computational security is resource-bounded by definition. Reserve "immune" for things that are information-theoretically impossible.
- "ECDSA requires a perfect RNG": deterministic ECDSA exists (RFC 6979). The PlayStation 3 failure was a constant nonce. Deterministic signing also has its own fault-attack exposure.
- "BLAKE3 is the strictly superior choice" over SHA-256: SHA-2 has far more cryptanalysis, standardisation and hardware support. Length extension is irrelevant wherever HMAC or HKDF is used.
- "AES-GCM … 2^48 birthday bound": the operational limit NIST sets for random 96-bit nonces is 2^32 messages per key.
- "Validated by Signal/Proton precedent": in 2021 Proton was compelled by a Swiss order to log and disclose an activist's IP address. The precedent shows a server can be ordered to *start* collecting whatever it is able to observe. Only what the server cannot observe is safe.
- §12, "a mathematical specification … cannot itself be regulated", and the export-control advice: legal conclusions without a basis. Take advice from counsel before operating a server.

#### AEG-29 — The prior-art analysis is wrong, and omits the closest relatives.

The gap table says split delivery and per-file keys exist in no other system. Per-message session keys are in every hybrid encryption scheme since PGP. Split delivery is how Signal attachments work: ciphertext on an untrusted CDN, key inside the end-to-end channel.

The comparison never mentions the systems Aegis most resembles:

- **Firefox Send** (2017–2020): client-side encryption, the secret in the URL fragment, an optional password as a second factor, expiry and download limits. Mozilla shut it down because it was used to deliver malware. That is the single most relevant precedent for this project and it is absent.
- **Magic Wormhole**: short spoken codes done correctly, with a PAKE, plus relayed peer-to-peer transfer.
- **age**: the file format v3.0 borrows its stream construction from.
- **Tahoe-LAFS**: capability-based storage on untrusted servers.

"Encrypted search" appears in the gap table and nowhere in the protocol.

The honest contribution is a careful, analysed combination. That is worth building. It is not a category of one.

#### AEG-30 — There is no abuse model.

An anonymous host of opaque blobs will be used to stage malware and illegal content; see Firefox Send. The operator needs takedown by blob ID, an abuse-report path in which a reporter can voluntarily disclose keys, and admission control that does not identify users. v2.1 has none of these.

*v3.0:* spec §10.4, §10.7. Key commitment (AEG-09) is what makes a disclosed-key report unambiguous.

#### AEG-31 — The name collides with a cipher.

AEGIS is a family of authenticated ciphers (AEGIS-128L, AEGIS-256): a CAESAR competition winner with an active CFRG specification. A document titled "Aegis protocol" that then specifies ChaCha20-Poly1305 will confuse every cryptographer who opens it, and searches for one return the other. Rename before publishing, or always write "Aegis Share Protocol". This is your call; v3.0 keeps the name.

---

## 4. What I dismiss

| Dismissed | Reason | Replaced by |
|-----------|--------|-------------|
| **XChaCha20** (the extended-nonce variant) | Its only advantage is safety with random nonces. v3.0 has no random nonces: every key is single-use and every nonce is a counter. That leaves a non-standard primitive doing a job that does not exist, and a second AEAD alongside the one Noise already requires. Your instinct — avoid AES-GCM's random-nonce hazard — was right; removing random nonces is the stronger fix. XChaCha20-Poly1305 is not broken, and a v3.0 built on it would also be secure. | ChaCha20-Poly1305, RFC 8439 |
| **BLAKE3** | A good hash with nothing left to do. Key derivation hashes a few hundred bytes, where speed is irrelevant. Per-chunk AEAD tags replace whole-file hashing. SHA-512 is already mandatory because Ed25519 uses it. Every extra primitive is audit surface. It can return in a later suite as an optimisation. | SHA-512 |
| **"HKDF-BLAKE3"** | Does not exist. | HKDF-SHA-512, RFC 5869 |
| **The `nonce_key` derivation** | AEG-15. | Counter nonces |
| **The outer Ed25519 signature** | AEG-03. | Optional signature inside the encryption |
| **Non-repudiation as a default property** | Contradicts anonymity. | Opt-in signed mode, labelled |
| **`file_id`** | An unspecified value doing a secret's job by accident. | Secret-derived `blob_id` |
| **Noise XX with identity keys** | AEG-12. Identity assurance belongs to the blob, which carries it in every mode. | NNpsk0 |
| **"Session ratcheting"** | Never existed. | Nothing; the claim is removed |
| **P2P as an availability feature** | AEG-21. Direct connections also break anonymity between peers. | Relayed live transfer; direct path is opt-in |
| **JSON artifacts** | Non-canonical, and a parser in the trust path for 70 bytes of data. | Fixed binary layout, base32 text form |
| **Caching the vault key in the OS keychain** | AEG-16. | Passphrase each unlock |
| **"Immune"** as a protection level | AEG-28. | A per-adversary table of what holds and under which assumption |
| **Kubernetes, S3, Tokio in the crypto crate** | The server is one binary and a directory. The crypto core should be synchronous and I/O-free. | Plan Milestones 1 and 6 |
| **"Zero Trust" / SP 800-207 framing** | AEG-27. | "Malicious server" in the cryptographic sense |
| **The protocol-differentiation and regulatory sections** | Marketing and unsupported legal claims do not belong in a protocol specification. | An accurate prior-art section in the research document |
| **Textbook exposition in the research document** | More than half restates how ChaCha20, Poly1305 and elliptic curves work, with errors. A design-rationale document should argue for *this* design. | Rewritten as rationale and security analysis |

---

## 5. Things you did not ask about

**The effort has been going into prose.** The git history shows about 4,100 lines of documents written by the end of May, then a single commit a month later that added 2,100 lines and removed 3,200. The specification's revision note for that version reads "Prose rewrite. Diagrams redrawn. No architectural changes" — while the central mechanism was empty and no line of code or test vector existed. A protocol cannot be checked by rereading it. The single most valuable habit to adopt is: no claim enters the specification without a test vector or a model lemma behind it. v3.0 starts that way.

**Usability is the security perimeter.** Two-channel delivery only protects users who actually use two channels. If the client makes it tedious, people will paste both artifacts into one chat and the property is gone. Design the split flow first; it matters more than any primitive choice.

**Anonymity is a network property.** "No PII in the protocol" does not make users anonymous while their IP addresses reach the server. v3.0 says so and supports onion-service origins; the reference client should support a SOCKS proxy from the first release.

**The server's TTL, burn-after-read and download limits are promises.** A malicious server keeps everything. v3.0 labels them advisory and requires clients to present them that way.

**Running a server has legal consequences this document cannot assess.** Get advice before operating one publicly.

**Do not protect anyone at real risk with this until it has been independently audited.** That includes v3.0.

---

## 6. Invariant ledger

No v2.1 invariant is dropped or weakened. Each is restated so that it can be tested, and ten are added. Full text is in spec §2.3.

| v2.1 | v3.0 | Change |
|------|------|--------|
| 1. Server never sees plaintext | I1 | Unchanged. |
| 2. Server never possesses keys | I2 | Extended: nor any value from which a key can be computed. |
| 3. Complete server compromise reveals nothing | I3 | Made falsifiable: nothing outside the enumerated leakage set of §2.6. v2.1's version was untrue as written. |
| 4. Every file has an independent key | I4 | Unchanged; I8 adds that every key is used exactly once. |
| 5. Metadata encrypted or meaningless | I5 | Now covers size (padded), share mode, and sender identity. |
| 6. Users identified only by public keys | I6 | Strengthened: the server never sees any user's public key. |
| — | I7 | The split is cryptographic: one artifact plus the entire server yields nothing. |
| — | I8 | Single-use keys; ciphertext is immutable once produced. |
| — | I9 | No unauthenticated plaintext is released. |
| — | I10 | Every key is bound to the complete public context. |
| — | I11 | One blob, one plaintext (key commitment). |
| — | I12 | Sender identity never appears outside the encryption. |
| — | I13 | The server has no authority. |
| — | I14 | No secret is ever sent to a server. |
| — | I15 | Fail closed; no negotiation. |
| — | I16 | Long-term keys do not decrypt beyond their epoch. |

---

## 7. Traceability

| Finding | Severity | Resolved in v3.0 |
|---------|----------|------------------|
| AEG-01 Split-key empty | Critical | Spec §4, §6.1; I7 |
| AEG-02 No forward secrecy | Critical | Spec §9.3, §9.6, §15.2; I16 |
| AEG-03 Signature outside encryption | Critical | Spec §7.5; I12 |
| AEG-04 Recipient key undefined | Critical | Spec §9 |
| AEG-05 Three protocols | Critical | Spec §3, §14; `model/` |
| AEG-06 Server leakage | Critical | Spec §2.6, §7.4; I3, I5, I13 |
| AEG-07 Harvest-now-decrypt-later | Critical | Spec §3, §6, §15.3 |
| AEG-08 Single-shot AEAD | High | Spec §7.2, §8.3; I9 |
| AEG-09 Key commitment | High | Spec §6.6; I11 |
| AEG-10 Metadata undefined | High | Spec §7.3 |
| AEG-11 Server authorisation | High | Spec §10 |
| AEG-12 Noise misuse | High | Spec §11 |
| AEG-13 Unbound key schedule | High | Spec §3.2, §6.4; I10 |
| AEG-14 Signature verification | High | Spec §3.3 |
| AEG-15 Nonce derivation | High | Spec §7.2; I8 |
| AEG-16 Identity storage | High | Spec §9.7, App. C; Plan M5 |
| AEG-17 Wire format rules | High | Spec §4, §7, §13 |
| AEG-18 – AEG-23 | Medium | Spec §5, §8.4, §10.6, §11, §12 |
| AEG-24 – AEG-26 | Medium | Implementation plan |
| AEG-27 – AEG-29 | Low | Research document, rewritten |
| AEG-30 Abuse model | Low | Spec §10.4, §10.7 |
| AEG-31 Name | Info | Open; your decision |

---

**End of audit**
