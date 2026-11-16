# Implementation Plan

## Aegis Protocol v3 & Reference Implementation

**Project:** Aegis
**Author:** Abdulaziz
**Version:** 3.0
**Date:** November 16, 2026
**Revision:** v3.0 — Rewritten for the v3.0 protocol. Replaces the v2.1 plan in full.

---

## Overview

This plan takes Aegis from a specification with an executable model to an audited, released reference implementation. It has twelve milestones, M0 to M11.

The order matters more than anything else in this document:

1. **M0–M4 make the protocol real.** Core library, conformance suite, formal model, and a frozen wire format. Nothing user-facing is built before this.
2. **M5–M8 make it usable.** Client library, storage service, live transfer, command-line client.
3. **M9 is the external audit.** Nothing ships to users before it.
4. **M10–M11 are the desktop application and release.**

v2.1's plan built applications in parallel with an unfinished protocol, "locked" the specification after writing the code, and put the audit last. This plan fixes the specification's behaviour with test vectors first, proves what can be proved, and only then spends effort on things users see.

**This plan says what is built and in what order. `Aegis_engineering_standard.md` says how every piece must be structured, attacked and evidenced, and it is binding.** Where the two differ, the standard wins. Each milestone below carries the additional gates listed in §7 of the standard.

### What exists today

| Artefact | State |
|----------|-------|
| `Aegis_project_specification.md` v3.0 | Draft; complete; not frozen |
| `Aegis_research.md` v3.0 | Rationale and analysis |
| `Aegis_audit_report.md` | Findings against v2.1 |
| `Aegis_engineering_standard.md` v1.0 | Architecture rules, the eight gates, the five test rings, the attack catalogue, the sabotage suite |
| `model/aegis_v3_model.py` | Executable model; all checks pass |
| `model/vectors_v3_provisional.json` | 6 positive and 45 negative vectors, plus identity, service and live-handshake vectors |
| Rust code | None |

### Guiding principles

1. **No claim without a test.** Every invariant in spec §2.3 maps to a test, a model lemma, or a compile-time guarantee (see [Invariant coverage](#invariant-coverage)).
2. **Specification first.** Code that disagrees with the specification is wrong until the specification is changed by a recorded decision.
3. **Misuse must not compile.** Where the type system can enforce a rule — single-use keys, state order, plaintext release — it does.
4. **Small trusted core.** The crates that touch secrets do no networking, no async, no file-system access and no logging.
5. **Fewer dependencies beat nicer ones.**
6. **Nothing ships before the audit.**

### Sizing

Milestones carry a relative size — S, M, L — and no dates. For one developer, M0–M4 is the bulk of the cryptographic work and should not be compressed. Sizes are comparisons between milestones, not calendar estimates.

---

## Architecture

### Workspace

```
aegis/
├── Aegis_project_specification.md      normative
├── Aegis_research.md
├── Aegis_implementation_plan.md
├── Aegis_audit_report.md
├── model/                              executable model and vectors (exists)
├── formal/                             symbolic model (M4)
├── crates/
│   ├── aegis-label/                    spec §3.2 only: Ctx and LHash. No keys.
│   ├── aegis-core/                     spec §3–§8
│   ├── aegis-identity/                 spec §9
│   ├── aegis-live/                     spec §11, transport-agnostic
│   ├── aegis-vault/                    spec Appendix C.1
│   ├── aegis-client/                   orchestration: HTTP, contacts, share records
│   └── aegis-testkit/                  vector loader, mutators, differential harness (dev only)
├── apps/
│   ├── aegis-cli/                      reference client (M8)
│   ├── aegis-server/                   reference storage service (M6)
│   └── aegis-desktop/                  desktop application (M10)
├── fuzz/
├── docs/
│   ├── THREAT_MODEL.md
│   ├── INVARIANTS.md                   one entry per invariant: statement, test, owner
│   ├── decisions/                      one short record per design or dependency decision
│   └── audit/
├── deny.toml   supply-chain/   Cargo.toml   Cargo.lock
└── .github/workflows/
```

### Dependency direction

```
            aegis-core  ◄── aegis-identity
                ▲   ▲            ▲
                │   └── aegis-live
                │                ▲
            aegis-vault          │
                ▲                │
                └──── aegis-client ────► apps/aegis-cli, apps/aegis-desktop

            aegis-label is a leaf used by aegis-core and by apps/aegis-server.

            apps/aegis-server depends on aegis-label alone, for delete verifiers and
            proof-of-work. It never links key-schedule code.
```

### Trust tiers

| Tier | Crates | Rules |
|------|--------|-------|
| **1 — handles keys** | `aegis-core`, `aegis-identity`, `aegis-live`, `aegis-vault` | `#![forbid(unsafe_code)]`. Synchronous. No network, no file system, no clock, no logging, no global state. Input and output through `Read`/`Write`-style traits and byte slices only. Every public function is fuzzed or property-tested. |
| **2 — orchestrates** | `aegis-client` | May do I/O. Holds secrets only inside Tier 1 types. Implements the state machines of spec §8.4. |
| **3 — presents** | `aegis-cli`, `aegis-desktop` | Never sees key material except the artifacts it must show the user. Implements the labelling obligations (spec App. C.4). |
| **Untrusted** | `aegis-server` | Assumed hostile by every other component. Still held to spec §10.5. |

The server shares no secret-handling code with the client. A bug in the server cannot become a bug in key handling.

### Dependencies

Candidates only. Each is confirmed at M0 by a written decision in `docs/decisions/` that records the version, the audit or verification status *as checked that day*, and the official test vectors it passes.

| Need | Candidate | Note |
|------|-----------|------|
| ChaCha20-Poly1305 | RustCrypto `chacha20poly1305` | |
| SHA-512, HMAC, HKDF | RustCrypto `sha2`, `hmac`, `hkdf` | |
| Ed25519 | `ed25519-dalek` | `verify_strict`, plus an explicit canonical-encoding check on the public key (spec §3.3) |
| X-Wing | RustCrypto `x-wing`, or `libcrux` ML-KEM with `x25519-dalek` | Decision at M0. Must reproduce the X-Wing draft's vectors. Prefer a formally verified ML-KEM. |
| Argon2id | RustCrypto `argon2` | Raw-output API, never the password-hash string API |
| Noise | `snow` | Confirm NNpsk0, SHA512, ChaChaPoly against the model's handshake vectors |
| Constant time, erasure | `subtle`, `zeroize` | |
| OS randomness | `getrandom` | Called directly. No `rand` in Tier 1. |
| HTTP client | A blocking client over `rustls` with SOCKS5 support | Tier 2 only |
| Server | `axum` on `tokio` | Server only |

**No version numbers appear in this document.** v2.1's plan pinned versions in prose and was stale within months. Versions live in `Cargo.lock`, and the reasons for them in `docs/decisions/`.

---

## Engineering rules

These bind every milestone. Each is checked by CI or by review. They are a summary; the full, numbered rules are in `Aegis_engineering_standard.md` §2 and §3, including the `no_std` requirement for Tier 1, the five data classes, ports and deterministic simulation, and the size budgets.

### Secrets

1. A secret lives in a dedicated type that erases on drop, is heap-allocated so that moves do not copy it, and implements none of `Copy`, `Clone`, `Debug`, `Display`, `Serialize`, `PartialEq`.
2. Comparison of secrets and of anything derived from them uses `subtle`.
3. Secret types have private fields and no accessor that returns owned bytes.
4. Ephemeral key-agreement secrets use types that are consumed by use.
5. No secret, artifact, token, blob address, name or passphrase is ever passed to a logging or formatting macro. A CI check greps for `Debug` derives on types in Tier 1.

### Interfaces

1. **Sealing draws its own randomness.** No public function accepts `LS`, `KS`, a nonce, a salt or a random number generator (spec §4.4 rule 1, I8). Vector tests use a hook compiled only under a `test-vectors` feature; a CI job fails if that feature is reachable from any application crate.
2. **Sealing happens once.** `seal` consumes its options and returns an immutable blob handle. There is no "re-seal" and no "resume encryption".
3. **Opening is a typestate chain.** Each recipient state of spec §8.4 is a distinct type; each transition consumes the previous one. Skipping the commitment check or reading plaintext before `R_KEYED` does not compile. Compile-fail tests assert this.
4. **Plaintext release is enforced by a sink.** Decrypted bytes go to a `PendingOutput` that can be finalised only by presenting a `Verified` value, which only the final-chunk check constructs. Dropping it without finalising deletes what was written (spec §8.3, I9).

### Parsing

1. Parsers of untrusted input never panic, never allocate based on an unchecked length field, and never index without a bounds check. `clippy::indexing_slicing`, `clippy::unwrap_used`, `clippy::expect_used` and `clippy::arithmetic_side_effects` are denied in Tier 1.
2. Every parser has a fuzz target and a round-trip property test.
3. Every reserved field is checked to be zero. Every length is checked against its limit. This is specified, tested by negative vectors, and not optional.

### Errors

1. One error enum per crate, mapping one-to-one onto the codes of spec §12.
2. Randomness failure aborts the process. It is not an error value.
3. Errors carry no secret-dependent data.

### Interface sketch

Shapes only; these are not final signatures.

```rust
// aegis-core

pub struct SealOptions<'a> {
    pub split: bool,                              // defaults to true
    pub recipient: Option<&'a ValidatedCard>,     // ADDRESSED
    pub passphrase: Option<Passphrase>,           // PASSPHRASE
    pub signer: Option<&'a IdentityKey>,          // SIGNED
    pub offer_live: bool,
    pub note: Option<&'a str>,
    pub burn: bool,
}

pub struct Sealed {
    pub link: ShareLink,
    pub key: Option<ShareKey>,
    pub blob_id: BlobId,
    pub owner_token: OwnerToken,
    pub owner_verifier: Verifier,
    pub burn_verifier: Verifier,
    pub blob_len: u64,
}

/// Reads exactly `content_len` bytes; writes the complete blob to `out`.
pub fn seal<R: Read, W: Write>(
    content: R, content_len: u64, meta: &Metadata, origin: &Origin,
    options: SealOptions<'_>, out: W,
) -> Result<Sealed, Error>;

// Opening: one type per state of spec §8.4.
impl Opener<Artifacts> {
    pub fn new(link: &str, key: Option<&str>) -> Result<Self, Error>;
    pub fn blob_id(&self) -> &BlobId;
    pub fn header(self, first_1200: &[u8], blob_len: u64) -> Result<Opener<Header>, Error>;
}
impl Opener<Header> {
    pub fn needs(&self) -> Needs;                 // passphrase? recipient key?
    pub fn unlock(self, keys: &dyn KemKeyring, passphrase: Option<Passphrase>)
        -> Result<Opener<Keyed>, (Self, Error)>;  // returns self on AEG-CRYPTO-02 so a passphrase can be retried
}
impl Opener<Keyed> {
    pub fn stream<W: PendingOutput>(self, out: W) -> Opener<Streaming<W>>;
}
impl<W: PendingOutput> Opener<Streaming<W>> {
    pub fn manifest(&self) -> Option<&ManifestPreview>;   // available after chunk 0
    pub fn push(&mut self, encrypted: &[u8]) -> Result<(), Error>;
    pub fn finish(self) -> Result<(Verified, Manifest, SignerStatus), Error>;
}
```

---

## Milestones

### M0 — Foundations · size S

**Objective.** A repository in which a wrong change cannot be merged quietly.

**Work**

- Install the Rust toolchain. (The development machine currently has Python 3.12 and no Rust.) Pin the toolchain in `rust-toolchain.toml`.
- Create the workspace layout above, with empty crates.
- Make dependency decisions; write one record per dependency in `docs/decisions/`, including which official vectors were run and passed.
- Write `docs/THREAT_MODEL.md` from spec §2 and `docs/INVARIANTS.md` from the [coverage table](#invariant-coverage).
- Put the Python model in CI: it must run clean, and regenerating the vectors must produce no diff.
- Set up CI (see [CI gates](#ci-gates)).
- Write `SECURITY.md` with a private reporting address.
- Decide the open questions listed under [Decisions for the author](#decisions-for-the-author) that block M1: the KEM crate, and the project name.

**Exit criteria**

- [ ] `cargo build --workspace --locked` succeeds on Windows, macOS and Linux.
- [ ] CI runs every gate and fails on a deliberately introduced `unsafe` block, a `Debug` derive on a secret type, and a dependency with a disallowed licence.
- [ ] Every dependency has a decision record.
- [ ] Each chosen primitive crate passes its official test vectors in CI.
- [ ] The model job passes and the vectors file is byte-identical when regenerated.

---

### M1 — Cryptographic core · size L

**Objective.** `aegis-core` implements spec §3–§8 completely.

**Work, in this order.** Each step ends with its vectors reproduced.

1. **Labelled derivation** (§3.2): `Ctx`, `LExtract`, `LExpand`, `LHash`, `LSign`, strict `LVerify`. A single module owns the label registry; labels are an enum, not strings at call sites.
2. **Text encoding and artifacts** (§4): base32 with canonical decoding; ShareLink and ShareKey encode and decode; origin validation.
3. **Stage A** (§6.1).
4. **Sealed header** (§6.2): build, seal, open, strict parse.
5. **Transcript and Stage B** (§6.3–§6.6), with X-Wing and Argon2id.
6. **Padmé** (App. B).
7. **Manifest** (§7.3): build and strict parse.
8. **Stream** (§7.2): chunked encryption and decryption, length-structure check, lookahead for unknown length.
9. **Sender signature** (§7.5): incremental digest during sealing and opening.
10. **`seal`** (§8.1) and the **`Opener` typestate chain** (§8.2–§8.4).
11. **Secret types** and erasure at the points §8.1 step 10 and §8.2 step 12 name.

**Deliverables**

- [ ] `aegis-core` with the public surface sketched above.
- [ ] Every positive vector in `model/vectors_v3_provisional.json` reproduced byte for byte.
- [ ] Every negative vector rejected with the stated code.
- [ ] Additional vectors generated by the Rust implementation for the paths the model does not cover — real X-Wing and real Argon2id — and committed.
- [ ] Benchmarks for sealing and opening at 1 MiB, 100 MiB and 4 GiB.

**Exit criteria**

- [ ] 100% of model vectors pass.
- [ ] No `unsafe`, no panic path reachable from untrusted input (checked by fuzzing in M3 and by the denied lints now).
- [ ] Peak memory while sealing or opening is independent of file size, excluding the Argon2id profile.
- [ ] Throughput on the reference machine: at least 200 MB/s unsigned and 100 MB/s signed. If missed, record why; do not change the protocol to hit a number.

**Invariants addressed.** I1, I2, I4, I5, I7–I12.

---

### M2 — Identity · size M

**Objective.** `aegis-identity` implements spec §9.

**Work**

- Recovery seed generation; BIP-39 English encoding and decoding with checksum. The wordlist is embedded and its hash asserted in a test.
- Identity key derivation (§9.2).
- KEM epoch keys: generation from fresh randomness only; a type that records the validity window and refuses use after it.
- Cards: build, sign, encode, decode, and the six checks of §9.4. The result of validation is a `ValidatedCard`; `seal` accepts nothing else.
- Fingerprints (§9.5) and the contact state model.
- Destruction schedule (§9.6) as a pure function of the clock value passed in. Tier 1 reads no clock.
- `KemKeyring` implementation for trial decapsulation, newest key first, bounded at 8.

**Deliverables**

- [ ] `aegis-identity`.
- [ ] Identity and card vectors from the model reproduced.
- [ ] Negative tests: expired card, over-long window, substituted KEM key, small-order identity key, malformed ML-KEM key.

**Exit criteria**

- [ ] A test proves no code path derives a KEM key from the seed (I16): KEM key generation takes no argument but the validity window.
- [ ] A contact's identity key cannot be replaced through any public function.

**Invariants addressed.** I6, I16.

---

### M3 — Conformance and adversarial testing · size L

**Objective.** Find the bugs before anyone else does.

**Work**

*Differential testing against the model.* A harness seals 100,000 random cases in Rust and opens them in the model, and the reverse, across all flag combinations and with sizes concentrated on boundaries: 0, 1, the largest content that fits one chunk, one byte more, exact multiples of the chunk size, Padmé boundaries.

*Property tests.*

- Any single-bit flip anywhere in a blob or artifact causes rejection, and no plaintext byte reaches the finalised output.
- Any truncation or extension causes rejection.
- `open(seal(x)) = x` for all modes.
- Padmé is monotonic, idempotent, and for every length from 65,536 upward adds less than 1/32 of it.
- Two seals of the same input share no byte of key material, address or token.

*Fuzzing.* The v2.1 fuzz target could never get past signature verification (AEG-25). The same trap exists here: random bytes never pass an AEAD tag. So the targets are placed *behind* authentication:

| Target | Input | Asserts |
|--------|-------|---------|
| `artifact_decode` | Arbitrary text | No panic; accept implies canonical re-encoding matches |
| `header_parse` | 1,152 arbitrary bytes as header plaintext | No panic; accept implies canonical |
| `manifest_parse` | Arbitrary bytes as stream prefix | No panic; no over-read |
| `crafted_blob` | Arbitrary header plaintext and stream, **encrypted by the harness under fixed keys**, then opened | No panic; accept if and only if an independent validity predicate accepts |
| `card_decode` | Arbitrary bytes | No panic |
| `live_frames` | Arbitrary frame sequences into an established session | No panic; state machine never accepts out-of-order frames |

`crafted_blob` plays the malicious sender and is the most important target.

*Third-party vectors.* Run Project Wycheproof vectors for ChaCha20-Poly1305, Ed25519, X25519, HKDF and ML-KEM through the wrappers in `aegis-core`. Record any vector where strict verification deliberately differs.

*Release-rule tests.* An instrumented sink records every byte handed to it. For every negative vector, assert that nothing was finalised.

*Compile-fail tests.* Assert that out-of-order use of `Opener` does not compile.

*Constant-time checks.* A statistical timing test on commitment and token comparison. This shows the absence of gross leaks in Aegis's own code; it is not a claim about the primitives.

*Miri.* Run the Tier 1 test suites under Miri with software backends.

**Exit criteria**

- [ ] 100,000 differential cases in each direction with zero disagreements.
- [ ] 100 CPU-hours per fuzz target with no findings. Fuzzing continues indefinitely afterwards; corpora are committed.
- [ ] Line and branch coverage of Tier 1 reported. Coverage is a diagnostic here, not a target: uncovered branches are either tested or justified in writing.
- [ ] Every finding has a regression test and, where it reflects an ambiguity, a specification change.

**Invariants addressed.** I9, I11, I15.

---

### M4 — Formal model and format freeze · size L

**Objective.** Machine-checked evidence for the properties a symbolic model can express, an independent implementation, and a frozen wire format.

**Work**

*Symbolic model.* Write the protocol in Tamarin or ProVerif under `formal/`. Model: both stages of the key schedule, all four modes, the sender signature, cards with epochs and key destruction, the storage service as the adversary, and the live handshake with frames. Prove the twelve lemmas of research §7.

For each lemma, also write a deliberately broken variant of the protocol — for example, an address that does not depend on `KS`, or a signature that omits the transcript — and confirm the tool finds the attack. A model that cannot find a known attack proves nothing.

*Independent implementation.* A second opener, in a different language, by a different person if at all possible, written from the specification alone. It must open every Rust-generated vector, including real X-Wing and Argon2id cases. Ambiguities it exposes are specification defects and are fixed in the text.

*Public review.* Publish the specification, research document, model and vectors. Ask for review on at least one cryptography forum. Keep the comment period open for no less than 30 days.

*Freeze.* Fold in errata. Mark the specification v3.0 final. Rename the vectors file to drop "provisional". From here any change to a byte on the wire is version 4.

**Exit criteria**

- [ ] All twelve lemmas proved; every broken variant yields an attack trace.
- [ ] The independent opener passes every vector.
- [ ] Review period complete; every comment answered in `docs/audit/review-log.md`.
- [ ] Specification marked final; tag `spec-v3.0`.

**Invariants addressed.** I3, I6, I7, I10, I12, I14, I16.

---

### M5 — Vault and client library · size L

**Objective.** `aegis-vault` and `aegis-client`: everything an application needs, with no user interface.

**Work**

*Vault* (spec App. C.1; resolves AEG-16).

- File format with header, wrapped master key, and typed records under single-use keys.
- Atomic replace: write to a temporary file, flush, rename, flush the directory. The previous generation is kept. A crash at any point leaves a readable vault; a test kills the process at each step and checks.
- Passphrase change re-wraps the master key under a new salt.
- Memory locking where the platform allows (`VirtualLock`, `mlock`), with failure reported, not ignored.
- No caching of the derived key outside process memory. Auto-lock on inactivity.

*Client.*

- Share records: `blob_id`, `T_owner`, expiry. `LS` and `KS` are erased once the artifacts have been handed over (spec §4.4 rule 6).
- Contacts with verification state.
- The sender and recipient state machines of §8.4, including the rule that artifacts are released only on `S_DONE`.
- HTTP client for spec §10.2: admission, upload with retry and resumption from the staged immutable blob, ranged download, delete.
- The staged blob: sealing writes ciphertext to a file; every upload attempt and any live transfer reads from it (I8).
- SOCKS5 proxy support from the first version (spec §15.4), used only when configured explicitly.
- The client rules of spec §10.8: no redirects, identity encoding only, bounded responses, and uniform fetching — the download never pauses for key derivation or a passphrase prompt.
- Range-checking of everything the server says (I13).
- Burn: `DELETE` with `T_burn` after a verified open when the manifest asks for it.
- KEM key rotation and scheduled destruction, driven by a clock value supplied by the caller.

**Exit criteria**

- [ ] Crash-injection test on vault writes: no corruption in 10,000 runs.
- [ ] End-to-end tests against an in-process fake server for all four modes, with passphrase and signing.
- [ ] A malicious fake server that truncates, substitutes, replays, serves stale blobs and lies in `/v3/info` never causes plaintext release or a wrong success report.
- [ ] A test captures all network output of a full session and asserts that neither `LS`, `KS`, nor any Stage B value appears in it (I14).

**Invariants addressed.** I8, I9, I13, I14, I16.

---

### M6 — Storage service · size M

**Objective.** `aegis-server`: a conforming service as one static binary.

**Work**

- The seven endpoints of spec §10.2.
- Storage: a directory of blob files plus a small embedded store for address, verifiers, expiry and fetch count. No object store, no orchestration layer, no external database.
- Write-once addresses; incomplete uploads invisible; resumable upload bound to the owner verifier.
- Uniform `404` for every not-available case and for failed deletes.
- Proof-of-work admission with stateless, authenticated challenges; adjustable difficulty.
- Expiry reaper; fetch-count enforcement.
- Rate limiting held in memory only.
- **Logging.** The default configuration writes aggregate counters only. No request line, address or blob identifier is written anywhere. A test runs the whole conformance suite with all output captured and asserts that no blob address, live address or client address appears.
- Live relay (spec §11.2): pair two, forward frames, keep nothing.
- Operator documentation: running behind a reverse proxy with access logs disabled; running as an onion service; takedown and abuse-report procedure (spec §10.7).

**Exit criteria**

- [ ] The service conformance suite passes, including timing-similarity checks on the `404` paths.
- [ ] The log-content test passes.
- [ ] Sustains 1,000 concurrent transfers on the reference machine without unbounded memory growth.
- [ ] A fuzz target on the HTTP request surface runs 100 CPU-hours clean.

**Invariants addressed.** I13 from the other side: the service is built to be honest, and the client is built not to care.

---

### M7 — Live transfer · size M

**Objective.** `aegis-live` and its integration: spec §11.1–§11.4. The direct path of §11.5 is not in this milestone.

**Work**

- A transport-agnostic session state machine: bytes in, bytes out, events. No sockets inside the crate.
- Noise NNpsk0 through `snow`, with the prologue and PSK of §11.3.
- **Confirm the model's handshake vectors.** This is the independent check the vectors are waiting for. If `snow` and the model disagree, find out which is wrong before proceeding.
- Frames and sequencing of §11.4, including the rule that no `DATA` is sent before an authenticated `READY`.
- Resume from an offset, reading from the staged blob.
- Client integration: offer live, wait, fall back to stored upload with the user's consent, using the same blob.
- WebSocket transport in `aegis-client`.

**Exit criteria**

- [ ] Handshake vectors match between `snow` and the model.
- [ ] Tests: wrong PSK fails on the first message; a replayed first message causes no data to be sent; frames out of order abort; interrupted transfers resume and verify.
- [ ] A malicious relay that drops, reorders, duplicates or injects frames causes failure, never acceptance.

---

### M8 — Command-line client · size M

**Objective.** `aegis-cli`: the reference client, and the first thing a user can run.

A command-line client comes before any graphical one because it is small, scriptable, testable end to end, and has no web view or JavaScript toolchain in its build.

**Commands**

```
aegis id new | show | backup | restore | rotate
aegis card export | import
aegis contact list | verify <name> | remove <name>
aegis send <file> [--to <contact>] [--no-split] [--passphrase] [--sign]
                  [--ttl <duration>] [--burn] [--live] [--note-file <path>]
aegis receive [--out <dir>]
aegis revoke <share>
aegis shares
```

No command takes an artifact, a passphrase or a recovery phrase as an argument or from the environment: both are visible in the process list and saved in shell history. `receive` prompts for the link and then the key, or reads them from standard input.

**Interface obligations** (spec App. C.4). Each is a test.

- `send` prints the link and the key as two separate, clearly labelled outputs, and never both on one line or in one clipboard operation.
- `--no-split` without `--to` requires confirmation and prints the single-channel warning.
- `--sign` states that the signature is transferable evidence.
- Expiry, burn and fetch limits are worded as requests to the server.
- `receive` shows an unsigned share as having no known sender, and a signed one with "verified" or the full fingerprint.
- `id backup` states that the recovery phrase does not restore undelivered addressed shares.
- A received name is sanitised before it touches the file system (spec App. C.3).

**Exit criteria**

- [ ] End-to-end tests of every command against a real `aegis-server` in every mode.
- [ ] Every interface obligation covered by a test on the actual output text.
- [ ] A usability pass with at least five people who have not seen the project: can they send a split share over two channels unaided? Record what confused them and fix it before M9.

---

### M9 — External audit · size M, plus the auditors' time

**Objective.** An independent professional review, and every finding resolved.

**Scope.** `aegis-core`, `aegis-identity`, `aegis-live`, `aegis-vault`, `aegis-client`, `aegis-server`, `aegis-cli`; the specification; the symbolic model.

**Hand-over package**

- The four documents, the model and vectors, the symbolic model and proofs.
- `docs/THREAT_MODEL.md`, `docs/INVARIANTS.md`, every decision record.
- Test, fuzz and coverage reports; the M4 review log.
- A list of what the author is least sure about. Auditors' time is best spent where the designer has doubts.

**Questions to put to the auditors explicitly**

1. Does the key schedule bind everything it should? Is anything bound twice in a way that creates a cycle or an ordering hazard?
2. Is the commitment argument (spec §6.6) correct as stated?
3. Is the sender-signature construction (§7.5) free of lifting and substitution attacks?
4. Is strict Ed25519 verification implemented as specified?
5. Can any sequence of server behaviours cause plaintext release or a false success?
6. Is anything secret-dependent observable through timing, errors or memory?
7. Does the vault survive crashes and resist offline attack as claimed?

**Exit criteria**

- [ ] Report received.
- [ ] Every finding of medium severity or above fixed and re-tested by the auditors.
- [ ] Lower-severity findings fixed or accepted in writing.
- [ ] Report published in full, alongside the responses.

Budget for this early. An audit of a protocol library and service of this size is a significant cost, and it is the one item on this plan that cannot be substituted.

---

### M10 — Desktop application and release engineering · size L

**Objective.** A graphical client for people who will not use a terminal, and a release process users can verify.

**Desktop application.** A decision is required at the start of this milestone (see [Decisions for the author](#decisions-for-the-author)): a web-view shell or a native Rust toolkit. Whichever is chosen:

- All protocol logic stays in `aegis-client`. The interface layer calls a narrow, explicitly enumerated set of commands.
- The interface layer receives artifacts only to display them, and never receives vault keys, identity keys or KEM keys.
- Copying an artifact to the clipboard is done by the Rust side, with an automatic clear after a short interval.
- No remote content is ever loaded. If a web view is used: a strict content security policy, no network access from the view, and front-end dependencies vendored and built offline.
- Every interface obligation tested in M8 is implemented again and tested again.

**Release engineering**

- Reproducible builds, verified by building twice on separate machines and comparing hashes.
- Releases signed with a key kept offline. Signature verification documented and tested.
- A software bill of materials for every release.
- Updates are never applied without verifying a signature. No silent automatic update.
- `cargo vet` records for every dependency.

**Exit criteria**

- [ ] Two independent builds of the release produce identical binaries.
- [ ] A fresh usability pass on the graphical client.
- [ ] A focused review of the interface layer and its command surface by the M9 auditors or an equivalent second reviewer.

---

### M11 — Public beta and maintenance · size M

**Objective.** Real use, with eyes open.

**Work**

- Publish binaries, source, and the audit report.
- State prominently what Aegis does not do: spec §2.5 and §15.5 in plain language.
- User documentation written around tasks, starting with "send a file to someone using two channels".
- Operator documentation for running a service.
- A vulnerability disclosure policy with a response-time commitment, and a bounty if funds allow.
- A documented process for security releases.
- Continuous fuzzing kept running. Dependency advisories watched.
- Begin work on the deferred features (spec App. E) only after the beta has been stable for a full release cycle, and each as a new protocol version with its own analysis.

**Exit criteria**

- [ ] Beta running with external users.
- [ ] No open finding of high severity.
- [ ] A written decision on whether, and under what conditions, the author operates a public service.

---

## Sequencing

| Milestone | Depends on | May overlap with |
|-----------|------------|------------------|
| M0 Foundations | — | — |
| M1 Core | M0 | M2 once step 1 of M1 is done |
| M2 Identity | M1 step 1 | M1 |
| M3 Conformance | M1, M2 | Starts as soon as M1 has anything to test |
| M4 Formal model and freeze | M3 | The symbolic model can begin during M1 |
| M5 Vault and client | M4 for release; work may begin after M3 | M6 |
| M6 Server | M0 | M1–M5; it shares almost no code |
| M7 Live | M5, M6 | — |
| M8 CLI | M5, M6, M7 | — |
| M9 Audit | M8 | M10 design work |
| M10 Desktop and release | M9 | — |
| M11 Beta | M10 | — |

Two things can safely run early and in parallel with the core: the storage service (M6), and the symbolic model (M4). Everything else is sequential for a reason.

---

## Testing strategy

| Layer | What it catches | Where |
|-------|-----------------|-------|
| Official primitive vectors | A wrong or misconfigured library | M0 |
| Model vectors, positive | Any deviation from the specification | M1, M2 |
| Model vectors, negative | Acceptance of invalid input | M1, M2 |
| Differential against the model | Disagreement on inputs nobody wrote by hand | M3 |
| Property tests | Violations of stated algebraic properties | M3 |
| Fuzzing behind authentication | Parser bugs reachable by a malicious sender | M3 onward |
| Wycheproof | Edge cases in primitives | M3 |
| Compile-fail tests | Misuse that should be unrepresentable | M3 |
| Release-rule instrumentation | Unverified plaintext escaping | M3, M5 |
| Malicious fake server | Trust in server statements | M5 |
| Crash injection | Vault corruption | M5 |
| Service conformance | Server deviations | M6 |
| Malicious relay | Live-transfer acceptance of tampering | M7 |
| End-to-end | Integration failures | M8 |
| Interface-text tests | Missing or misleading warnings | M8, M10 |
| Symbolic model | Attacks nobody thought to test | M4 |
| Independent implementation | Ambiguity in the specification | M4 |
| External audit | Everything else | M9 |

### CI gates

Every pull request must pass all of these. GitHub Actions are pinned by commit hash, not by tag.

| Gate | Command or check |
|------|------------------|
| Format | `cargo fmt --check` |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings`, with the denied set in [Parsing](#parsing) |
| Tests | `cargo test --workspace --locked` on Windows, macOS, Linux |
| Model | Run `model/aegis_v3_model.py`; regenerate vectors; fail on any diff |
| Vectors | Rust reproduces every model vector |
| Supply chain | `cargo deny check` (licences, bans, sources, advisories); `cargo vet` |
| Minimum toolchain | Build on the pinned minimum supported version |
| No `unsafe` | `#![forbid(unsafe_code)]` present in every Tier 1 crate |
| Secret hygiene | Script: no `Debug`, `Clone` or `Serialize` on secret types; `test-vectors` feature unreachable from `apps/` |
| Miri | Tier 1 unit tests |
| Fuzz smoke | Each target for five minutes on the committed corpus |
| Compile-fail | `trybuild` suite |
| Tier graph | Test over `cargo metadata`: no dependency edge the standard forbids (A-1) |
| Routes | Every route in `docs/surface/routes.toml` has a tagged adversarial test (M-2) |
| Sabotage | Each patch in `sabotage/` applied to a scratch tree must turn the suite red (T-10) |
| Mutation | No untriaged surviving mutant in Tier 1 (T-9); run on changed crates per pull request, in full nightly |

Long fuzzing runs, the 100,000-case differential run, and the one-million-seed deterministic simulation (T-17) are scheduled nightly, not per pull request.

---

## Invariant coverage

Every invariant of spec §2.3, and how it is established. This table becomes `docs/INVARIANTS.md` at M0 and is updated when any row changes.

| # | Invariant | Established by | Milestone |
|---|-----------|----------------|-----------|
| I1 | Server never sees plaintext | Construction; captured-traffic test | M1, M5 |
| I2 | Server never holds a key or key-equivalent | Symbolic lemma 12; captured-traffic test | M4, M5 |
| I3 | Server learns only **L** | Argument in research §5.2; statistical test that blobs, addresses and verifiers pass randomness checks; log-content test | M3, M6 |
| I4 | Independent key per file | Property test: two seals share nothing | M3 |
| I5 | Metadata encrypted or meaningless | Fixed header size test; padding tests; mode-indistinguishability test on blob lengths | M1, M3 |
| I6 | Identified only by public keys; none visible to server | Symbolic lemma 8; server has no code path that parses a key | M4, M6 |
| I7 | Split is cryptographic | Symbolic lemmas 1 and 2, with broken-variant check | M4 |
| I8 | Single-use keys; immutable ciphertext | API shape (no re-seal, no injected randomness); staged-blob design; `test-vectors` feature gate | M1, M5 |
| I9 | No unauthenticated plaintext released | `PendingOutput`/`Verified` types; release-rule instrumentation over all negative vectors | M1, M3 |
| I10 | Keys bound to full context | Negative vectors that alter each bound field; symbolic lemmas 6 and 7 | M1, M4 |
| I11 | One blob, one plaintext | Argument in research §4.4; audit question 2 | M9 |
| I12 | Sender identity never outside encryption | Symbolic lemma 8; test that a signed and an unsigned blob of equal content length have equal size | M3, M4 |
| I13 | Server has no authority | Malicious fake server suite; range checks on `/v3/info` | M5 |
| I14 | No secret sent to a server | Symbolic lemma 12; captured-traffic test | M4, M5 |
| I15 | Fail closed; no negotiation | No version-retry code path exists; negative vector for unknown version; live handshake fails across versions | M1, M7 |
| I16 | Long-term keys bounded to their epoch | KEM generation takes no seed (type-level); destruction schedule tests; symbolic lemma 4 | M2, M4 |

---

## Risk register

| Risk | Likelihood | Impact | Response |
|------|------------|--------|----------|
| The X-Wing draft changes before publication as an RFC | Medium | Wire format change | Pin by test vectors. If it changes before the M4 freeze, adopt it. After the freeze, it is version 4. |
| The chosen ML-KEM implementation is found to have a flaw | Low–medium | High | Prefer a formally verified implementation. Wrap it behind one module so it can be replaced without touching the key schedule. Sealed shares are unaffected. |
| `snow` and the model disagree on the handshake | Medium | Delay to M7 | Resolve by reference to the Noise specification before any other M7 work. |
| A flaw is found in the v3.0 design itself | Medium | High | This is what M3, M4 and M9 are for. Nothing is frozen before M4 and nothing ships before M9. |
| One developer, no second reviewer for cryptographic code | High | High | Recruit a reviewer before M1 ends, even informally. The independent implementation in M4 doubles as review. Do not waive M9. |
| Scope creep from the deferred-features list | High | Medium | Nothing from spec App. E is started before M11. |
| Users defeat the split by sending both artifacts together | High | Defeats I7 in practice | Interface design in M8 and M10; usability passes; plain documentation. |
| A public service is abused | High if run publicly | Legal and operational | Decide deliberately in M11 whether to run one. Admission control, takedown process, legal advice first. |
| Secret erasure is incomplete | Certain, to some degree | Low–medium | Heap-pinned secret types; memory locking; stated honestly in the threat model. |
| Audit cost exceeds budget | Medium | Blocks release | Seek funding during M1–M4. The CLI and core can be audited first, the desktop application later. |
| The name collides with the AEGIS cipher | Certain | Confusion | Decide at M0 (AEG-31). |

---

## Decisions for the author

These are yours to make. Each has a recommendation.

| # | Decision | Needed by | Recommendation |
|---|----------|-----------|----------------|
| 1 | Keep the name "Aegis", or rename? | M0 | Rename, or use "Aegis Share Protocol" consistently. A rename costs nothing now and a great deal after publication. |
| 2 | Which ML-KEM / X-Wing implementation? | M0 | A formally verified ML-KEM, combined per the X-Wing draft, if its API and platform support are adequate; otherwise the RustCrypto crate. Decide by running both against the draft's vectors. |
| 3 | Tamarin or ProVerif? | M4 | Tamarin, for its handling of state and key-compromise events. ProVerif if you find it quicker to learn. |
| 4 | Who writes the independent implementation? | M4 | Someone else. If nobody can be found, write it yourself in a different language after a gap of some weeks, from the specification only. |
| 5 | Web-view shell or native toolkit for the desktop client? | M10 | A native Rust toolkit, which removes the JavaScript build chain and the web view from the trusted base. v2.1 banned Node from the cryptographic path while requiring it to build the application; a native toolkit resolves that. If the web-view route is kept, apply every constraint in M10. |
| 6 | Run a public storage service? | M11 | Not before taking legal advice, and not as a side effect of releasing the software. |

---

## Definition of done

The project is ready for general use when all of the following are true. Each is a fact that can be checked.

- [ ] The specification is marked final and tagged.
- [ ] Every model vector is reproduced by the Rust implementation and by one independent implementation.
- [ ] All twelve symbolic lemmas are proved, and every broken variant yields an attack.
- [ ] Every row of the invariant coverage table has a passing test, a proof, or a recorded audit conclusion.
- [ ] Every fuzz target has run at least 1,000 CPU-hours in total without an open finding.
- [ ] The external audit report is published and every finding of medium severity or above is closed.
- [ ] Release binaries are reproducible and signed.
- [ ] The interface obligations are tested in every client.
- [ ] User documentation states the limits of spec §2.5 and §15.5 in plain language.

---

## First three steps

1. Install Rust, create the workspace, and get the model running in CI (M0).
2. Run the candidate KEM crates against the X-Wing draft vectors and record the decision (M0).
3. Implement labelled derivation and Stage A, and reproduce the first vector's `blob_id` (M1 steps 1–3). The moment a Rust test prints the same 32 bytes as the model, the protocol exists in two implementations.

---

**End of Implementation Plan**
