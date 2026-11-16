# Aegis Engineering Standard

## Architecture and Assurance Methodology for Implementers

**Project:** Aegis
**Author:** Abdulaziz
**Version:** 1.0 (for protocol v3.0)
**Date:** November 16, 2026

---

## 0. Status and precedence

This document is binding on everyone who writes, reviews or releases Aegis code.

| Document | Says | Wins against |
|----------|------|--------------|
| `Aegis_project_specification.md` | What the protocol does, byte for byte | Everything |
| **This standard** | How code must be structured, and what evidence it must come with | The plan |
| `Aegis_implementation_plan.md` | What is built, in what order | — |

Rules are numbered so that a review can cite them: **P** principles, **A** architecture, **M** method, **T** testing, **X** attack catalogue, **R** review and release. "MUST" and "MUST NOT" are requirements. Deviating from one needs a written decision in `docs/decisions/`, approved by someone other than the person who wants to deviate.

### What "bulletproof" and "air-gapped" mean here

Neither word describes a property a networked program can have. This standard uses them for two things that are real and checkable:

- **Bulletproof** means: every way we know to attack the system has been tried against it, automatically, on every change, and the attempt is on record. It does not mean no attack exists. §8 states the limits.
- **Air-gapped** means three specific separations: the code that handles keys cannot reach the network, the file system or the clock (A-3); builds run without network access (A-20); and release signing keys live on a machine that has never been online (R-9).

---

## 1. First principles

**P-1. The specification is the only source of behaviour.** Code never decides what the protocol does. If the specification is silent or ambiguous, stop and fix the specification first.

**P-2. Everything outside the piece you are writing is hostile or broken.** The server, the network, the disk, the clock, the caller, the callee, the other implementer, and the input you produced yourself a moment ago. Each piece defends itself.

**P-3. Unrepresentable beats tested; tested beats reviewed; reviewed beats remembered.** Push every rule as far up that ladder as it will go. A rule that depends on implementers remembering it is not a control.

**P-4. Every piece has a stated attack surface, and tests follow the surface.** When the surface changes, the old tests are no longer sufficient by definition. New ones are derived from the new surface, at every level the change touches (M-6).

**P-5. A test that has never failed proves nothing.** Every check must be shown to catch the fault it exists for: by mutation, by a seeded defect, or by a deliberately broken variant (T-9, T-10).

**P-6. Attacks are written before code.** For each piece, the list of ways to break it exists before the first line of implementation (M-3).

**P-7. Data is classified by type, and only named functions change its class.** Secret, capability, untrusted, validated, public. No conversion happens by accident (A-8).

**P-8. Same inputs, same bytes.** The trusted core has no hidden inputs: no clock, no environment, no global state, no thread timing. Randomness enters at exactly one point.

**P-9. Fail closed, fail the same way, and say nothing useful to an attacker.**

**P-10. Complexity is attack surface.** Size and dependency budgets are security controls, enforced like any other (A-22).

**P-11. Evidence over confidence.** A claim about the code is true when an artefact in the repository demonstrates it. "I checked" is not an artefact.

**P-12. Nobody approves their own work in the trusted core.**

---

## 2. Strict architecture

### 2.1 Tiers

| Tier | Contents | May hold key material | May do I/O |
|------|----------|-----------------------|------------|
| **0** | Third-party primitives: AEAD, hash, KDF, signature, KEM, password hash, Noise | Transiently | No |
| **1** | `aegis-label`, `aegis-core`, `aegis-identity`, `aegis-live`, `aegis-vault` (format and crypto only) | Yes | **No** |
| **2** | `aegis-client` | Only inside Tier 1 types | Yes, through ports (A-11) |
| **3** | `aegis-cli`, `aegis-desktop` | Artifacts for display only | Yes |
| **U** | `aegis-server` | Never; it is the adversary | Yes |
| **B** | Build, CI, release tooling | Signing keys, offline only | — |

**A-1.** Dependencies point from higher tier number to lower only. Tier 1 never depends on Tier 2 or 3. Tier U depends on `aegis-label` and nothing else from the workspace. A test over `cargo metadata` fails the build on any other edge.

**A-2.** Tier 0 is used only through thin wrappers in Tier 1, one module per primitive. No other code names a primitive crate. Replacing a primitive implementation touches one module.

### 2.2 The code-level air gap

**A-3.** Tier 1 crates are `#![no_std]` with `alloc`, and `#![forbid(unsafe_code)]`. Under `no_std` there is no file system, socket, clock, environment or thread to call; the separation is enforced by the compiler, not by convention. Where a dependency forces `std`, the exception is recorded and the crate instead denies, by lint configuration, every item in A-4.

**A-4.** Forbidden in Tier 1, with no exceptions: networking; file-system access; reading the clock; reading the environment; spawning threads or tasks; async runtimes; logging, tracing and metrics of any kind; global mutable state; `build.rs`; procedural macros defined in this workspace; feature flags that change behaviour (the single exception is `test-vectors`, A-7).

**A-5.** Tier 1 functions take bytes and values and return bytes and values. Time is a parameter. Streams are caller-provided `Read`/`Write`-shaped traits defined in Tier 1.

**A-6.** One function in the entire workspace calls the operating system's random generator. It lives in `aegis-core`, returns at least 32 bytes per call, aborts the process on failure, and aborts if a draw is all zero or equals the previous draw. That last check catches only a stuck generator; it is not an entropy estimate. A lint forbids every other path to randomness.

**A-7.** Deterministic test hooks exist only behind the `test-vectors` feature. CI proves that feature is not enabled in any build of `apps/`, and that release binaries contain none of the hook symbols.

### 2.3 Data classes

**A-8.** Every value belongs to exactly one class, expressed as a type.

| Class | Examples | Rules |
|-------|----------|-------|
| **S — secret** | `LS`, `KS`, every `PRK` and `K_*`, `chain`, `live_psk`, `ss_kem`, `pw_key`, passphrases, the recovery seed, private keys, the vault master key | Heap-pinned; erased on drop; not `Copy`, `Clone`, `Debug`, `Display`, `Serialize`, `PartialEq`, `Hash`; compared only in constant time; never leaves the process except as an artifact shown to the user or inside the vault |
| **C — capability** | `blob_id`, `live_id`, `T_burn`, `T_owner` | As class S in memory. May be sent to the share's own origin, over TLS, in the one request it authorises, and nowhere else. Never logged, never in an error, never in a crash report |
| **U — untrusted** | Any byte from the network, disk, clipboard, command line, or another process | Opaque. Cannot be indexed, compared or formatted. Only a parser can consume it |
| **V — validated** | `ValidatedCard`, a parsed header, a verified chunk, `Verified` | Constructed only by the function that performed the check. Private constructor |
| **P — public** | Blob bytes, verifiers, cards, fingerprints | No restriction |

**A-9.** Conversions between classes happen only in functions listed in `docs/surface/declassification.md`. Each entry names the function, the classes, and the specification section that permits it. CI fails if a class-S or class-C type gains a new public method that returns plain bytes and is not on the list.

**A-10.** Parse, don't validate. A parser consumes class U and returns class V or an error. No function accepts raw bytes and a separate promise that they were checked.

### 2.4 Ports and simulation

**A-11.** In Tier 2 and Tier U, every interaction with the outside world goes through a port: `Network`, `Disk`, `Clock`, `Entropy` (Tier U only, for challenge keys), `Terminal`. Production adapters are thin and contain no logic.

**A-12.** Because of A-3 and A-11, the complete system — clients, service, relay — MUST be runnable in one process against simulated ports driven by a single seed. Every network delay, drop, reorder, disk error, crash point and clock step comes from that seed. Any failure reproduces from its seed alone. This is the main system-level test instrument (T-17).

### 2.5 State

**A-13.** Protocol state machines are typestates: one type per state of spec §8.4 and §11.4, each transition consuming the previous state. An invalid order is a compile error.

**A-14.** Decrypted bytes flow only into a `PendingOutput`. Finalising it requires a `Verified` value that only the final-chunk check constructs. Dropping it deletes what was written.

**A-15.** Encryption under a payload key happens in one function that consumes the key. The blob it produces is immutable. Upload retries, resumption, live transfer and fallback all read the stored blob (spec I8).

**A-16.** The vault records the latest time it has ever been given. A clock value earlier than that is rejected for every decision that depends on time: card validity, key destruction, expiry. Setting the clock back cannot resurrect a key or extend a window.

### 2.6 Process and platform

**A-17.** The process that holds vault keys never interprets received content. No previews, no thumbnails, no archive extraction, no opening of files. It writes verified bytes to disk and stops.

**A-18.** On start, every Aegis process: disables core dumps and crash-reporter uploads; locks secret allocations into memory where the platform allows and reports when it cannot; refuses to run if it cannot set owner-only permissions on its own files.

**A-19.** The service runs unprivileged, with a read-only file system apart from its blob directory, with system-call and file-system sandboxing where the platform offers it, and with no shell or interpreter in its image.

### 2.7 Build

**A-20.** Builds are hermetic. Dependencies are vendored. The build runs with network access disabled, a pinned toolchain, and `--locked --offline`. A build that tries to reach the network fails.

**A-21.** Every dependency that runs code at build time — build scripts and procedural macros — is listed in `supply-chain/build-time-code.md` with a reason. A new one needs a decision record.

### 2.8 Budgets

**A-22.** These are ceilings. Raising one needs a decision record.

| Budget | Ceiling |
|--------|---------|
| `aegis-core`, non-test lines | 3,000 |
| Any other Tier 1 crate, non-test lines | 1,500 |
| Any Tier 1 function | 60 lines; no more than 10 branches |
| Direct dependencies of any Tier 1 crate | 8 |
| Generic parameters over cryptographic primitives | 0 — there is one suite |
| Production implementations of any cryptographic trait | 1 |

The point of the first two is that one person can read the whole trusted core in a day. If the code does not fit, the design is too large.

---

## 3. Method: the life of one piece

A **piece** is the smallest unit that has its own inputs and outputs: a parser, a derivation stage, an endpoint, a command, a port adapter. Every piece passes eight gates, in order. A gate that is skipped is a failed gate.

### G0 — Anchor

**M-1.** Name the specification sections the piece implements. If a behaviour is needed that the specification does not define, the work stops and the specification is changed first, by a decision record. The model is updated in the same change.

### G1 — Surface statement

**M-2.** Before any code, write the piece's surface statement into `docs/surface/<piece>.md`:

1. **Inputs**: each one, its data class, and who controls it.
2. **Outputs**: each one, its data class, and who can observe it — including errors, timing, sizes and resource use.
3. **Secrets touched**, and where each is erased.
4. **State** held, and its lifetime.
5. **Neighbours**: every piece it calls or is called by.
6. **Routes**: every new path this piece creates from an untrusted input to a sensitive sink, each with an identifier (`R-nnn`).
7. **Assumptions** about callers, and what happens when each is false.
8. **Invariants** (spec §2.3) it can affect.

Routes are recorded in `docs/surface/routes.toml`. CI fails if any route has no adversarial test tagged with its identifier.

### G2 — Attack plan

**M-3.** Walk every class of the attack catalogue (§5) against the surface statement. Each class yields either named tests or a written "not applicable, because…". Then spend a fixed period — at least thirty minutes — on attacks the catalogue does not list, and write those down too.

### G3 — Tests first

**M-4.** Write the tests from G2, the known-answer vectors from the model, and the properties. They must compile and fail before the implementation exists. A test first seen passing has not been shown to detect anything.

### G4 — Implementation

**M-5.** Implement under §2. If the implementation needs something G1 did not predict — a new input, a new neighbour, a new secret — return to G1.

### G5 — The rings

**M-6. The regeneration rule.** Adding or changing a piece triggers new tests at every ring, not only for the piece itself:

- **Ring 1** for the piece.
- **Ring 2** for every edge between the piece and a neighbour — and for every *neighbour's other edges* if the neighbour's surface statement changed as a result.
- **Ring 3**: the system matrix is generated from a declarative description of modes, options and transports, so a new option enlarges it automatically; and every new route gets a system-level attack.
- **Ring 4** wherever the piece touches memory, disk, the network or the build.

Re-running existing tests is necessary and is not sufficient. §4 defines the rings.

### G6 — Break-it session

**M-7.** Someone who did not write the piece spends a fixed period trying to break it, with the surface statement and the code in front of them and the attack plan hidden until afterwards. Every attempt is recorded in `docs/attack-log/`, including those that failed: what was tried, how, and why it did not work. An attack that fails for a reason nobody can state is treated as an open finding.

**M-8.** Where there is only one developer: the session happens after at least 48 hours away from the piece, following the catalogue line by line, and the piece is flagged `single-reviewer` until a second person has done it. No release ships with a `single-reviewer` flag in Tier 1.

### G7 — Evidence and merge

**M-9.** The change merges only with: the surface statement; the attack plan with every class answered; the attack-log entry; all rings green; the mutation and coverage reports (T-9); the fuzz corpus; and updates to `docs/INVARIANTS.md`, the routes file and the threat model where affected.

### When a defect is found

**M-10.** Every defect, however found, gets five things: a test that reproduces it; a statement of its class; a search of the whole codebase for the same class; an addition to the attack catalogue if the class was missing; and a written answer to "which gate should have caught this, and why did it not?" The last one changes the process, not just the code.

---

## 4. The rings

### Ring 1 — the piece alone

| # | Requirement |
|---|-------------|
| **T-1** | **Known answers.** Every vector the model has for the piece, byte for byte. |
| **T-2** | **Rejections.** Every negative vector, with the exact error code. |
| **T-3** | **Boundaries.** For every length and count: 0, 1, limit − 1, limit, limit + 1, and the largest representable value. For streams: content that ends exactly at a chunk boundary, one byte before, one byte after; exactly at a padding boundary. |
| **T-4** | **Exhaustion where the domain is small.** All 65,536 combinations of the two header flag bytes. Every single-bit flip of a minimum-size blob (534,016 cases). Every truncation length of a minimum-size blob. Every single-character substitution of a ShareLink and a ShareKey. If it can be enumerated, enumerate it. |
| **T-5** | **Properties.** Round trip; rejection of any modification; independence of two seals; idempotence and monotonicity of padding; canonical re-encoding of anything accepted. |
| **T-6** | **Fuzzing, behind authentication.** Random bytes never pass an AEAD tag, so fuzz targets feed the parsers that sit after it, and the `crafted_blob` target has the harness encrypt arbitrary structure under fixed keys before opening it. Each accept/reject is checked against an independent validity predicate, not merely for absence of panics. |
| **T-7** | **Bounded proof.** For pure arithmetic and parsers — padding, length structure, base32, manifest bounds — a bounded model checker proves absence of panic and overflow for all inputs up to a stated size. |
| **T-8** | **Undefined behaviour and overflow.** Tier 1 tests run under Miri. Arithmetic overflow checks stay enabled in release builds of Tier 1. |
| **T-9** | **Mutation.** Every mutant of Tier 1 code is either killed by a test or triaged in writing as equivalent. Floors: no untriaged survivor in Tier 1; line coverage 95% and branch coverage 90% in Tier 1. Coverage is a floor that reveals untested code, never a target that certifies tested code. |
| **T-10** | **Sabotage suite.** See §6. |
| **T-11** | **Timing.** A statistical test shows that comparison of commitments, tokens and checksums does not depend on where the first difference lies, and that a wrong passphrase, a wrong key and a wrong recipient are indistinguishable by duration. |

### Ring 2 — the piece with each neighbour

| # | Requirement |
|---|-------------|
| **T-12** | **Contract, both directions.** For each edge: the caller's assumptions tested against the real callee, and the callee's against the real caller. |
| **T-13** | **Hostile neighbour.** Each neighbour is replaced in turn by a double that violates its contract: wrong lengths, short reads and writes, data after end, repeated and reordered calls, values at every boundary, and results that are valid in form and wrong in substance. The piece under test must fail closed and release nothing. |
| **T-14** | **Fault sweep.** For every sequence of port calls the edge can make, the N-th call fails, for every N. Then the N-th call is cancelled, for every N. Then the process is killed after the N-th call, for every N, and restarted. No sequence may release plaintext, lose the vault, re-encrypt under a used key, or leave a secret on disk. |
| **T-15** | **Differential at the seam.** Where the model implements both sides of an edge, random inputs cross the edge in both implementations and the outputs are compared. |
| **T-16** | **Class discipline at the seam.** Compile-fail tests show that a class-U value cannot cross the edge unparsed and a class-S value cannot cross it unwrapped. |

### Ring 3 — the whole system

| # | Requirement |
|---|-------------|
| **T-17** | **Deterministic simulation.** Clients, service and relay run in one process on simulated ports (A-12). Each seed chooses a scenario, a fault schedule, and adversary behaviour. At least one million seeds per night; every failing seed becomes a permanent regression case. Checked on every seed: no plaintext released from a transfer that did not verify; no success reported without verification; no secret-class bytes in any simulated network or disk write outside the vault; no key used twice. |
| **T-18** | **The full matrix.** SPLIT × ADDRESSED × PASSPHRASE × SIGNED × {stored, live} × {fresh, resumed}: all 64 combinations, generated, not hand-written. A new option doubles the matrix automatically. |
| **T-19** | **Adversary suites**, each a library of behaviours run against the real stack: malicious server; malicious relay; malicious sender (crafted blobs and cards through the real client); malicious recipient; network attacker (drop, delay, reorder, duplicate, truncate, inject, reset, half-open, slow). |
| **T-20** | **Pressure.** Maximum blob size; thousands of concurrent transfers; disk full at every point; memory capped below need; file descriptors exhausted; 72-hour soak with leak detection; clock jumps of ± 10 years mid-operation. Under every one: fail closed, recover cleanly, corrupt nothing. |
| **T-21** | **Wire capture.** All bytes a client emits during a full session are captured and searched for every class-S value of that session, and for every class-C value outside the one request that carries it. Zero hits (spec I14). |
| **T-22** | **Server view.** Blobs, addresses and verifiers from 10,000 shares across all modes pass a statistical randomness battery, and a classifier trained to tell modes apart from the server's view performs at chance. This shows the absence of gross structure; the argument for I3 is in the research document. |
| **T-23** | **Interoperability.** Reference implementation, model and independent implementation open each other's output in every mode. |

### Ring 4 — the hostile environment

| # | Requirement |
|---|-------------|
| **T-24** | **Memory forensics.** A test process runs an operation with known secrets and stops after the specified erasure point. Its entire memory is dumped and searched for each secret, each derived key, the passphrase and a plaintext marker. Every hit is fixed or explained in writing. The same search runs over temporary files, the vault file, logs, and a forced crash dump. |
| **T-25** | **File-system attacks.** Output directory containing symlinks, junctions and pre-existing files of the target name; received names with path separators, device names, trailing dots and spaces, alternate-data-stream syntax, bidirectional overrides, and names that differ only by case. Nothing is overwritten, nothing is written outside the chosen directory, and every file Aegis creates is owner-only. |
| **T-26** | **Local observer.** Process list, environment, shell history and clipboard are inspected during and after use. No artifact, passphrase or token appears in any of them, and the clipboard is cleared on schedule. |
| **T-27** | **Build.** Two independent machines produce identical release binaries. A build with network access enabled and a build without produce the same output. Removing any vendored dependency breaks the build loudly. |

### Ring 5 — independent people

| # | Requirement |
|---|-------------|
| **T-28** | Independent implementation from the specification alone (plan M4). |
| **T-29** | Red-team exercise before the format freeze and before the audit: people who did not build the system, given the source, a running service and a planted target, for a fixed period. |
| **T-30** | External audit (plan M9), then public review and a bounty. |

No ring substitutes for another. A piece that passes Ring 3 without Ring 1 has been tested only on the paths the system happened to take.

---

## 5. The attack catalogue

For every piece, at gate G2, each class below is answered. The catalogue grows by M-10 and never shrinks.

### X-1 Malformed input

Truncation at every byte. Extension. Every bit flipped. Length fields that lie: zero, maximum, one more than remains, values that overflow when added or multiplied, values above 2^32 on a 32-bit target. Fields duplicated, missing, out of order. Reserved bits set. Non-canonical encodings: base32 with stray trailing bits, mixed case, padding characters; overlong or invalid UTF-8; embedded NUL; Unicode that normalises to something else. One kind of artifact presented as another. An artifact of another version.

### X-2 Cryptographic misuse

A key used twice: seal twice with the test hook frozen and confirm the system refuses or the test detects it. A stuck or zero random source. A commitment check skipped or made non-constant-time. One blob that opens under two key sets. Signatures with non-canonical `S`, small-order `R`, small-order or mixed-order public key, non-canonical point encodings. ML-KEM keys with out-of-range coefficients; ciphertexts of wrong length. Low-order and all-zero X25519 points in a KEM key and in a live handshake. A value derived under one label accepted under another. A card signature presented as a sender signature and the reverse.

### X-3 Binding and substitution

A signed stream moved into another share. An addressed share re-targeted to another recipient. The SPLIT bit cleared in a link. A header from one blob in front of the chunks of another. Chunks reordered, duplicated, dropped, or spliced. A blob replayed under another address. An old card replayed. An identity key swapped under an existing contact name. A valid first handshake message replayed. A party's own messages reflected back to it.

### X-4 Oracles and side channels

Any difference an outsider can observe between two failures: error code, response size, timing, connection behaviour, `ABORT` reason. Comparison that exits early. Work whose duration depends on a secret, on the number of keys held, or on which candidate matched. **Network behaviour that depends on what a header contained**: a client that pauses its download while Argon2id runs, or while the user types a passphrase, has told the server which mode the share uses. Request sizes or header sets that vary with an option. Compression anywhere on a path that carries secrets or blobs.

### X-5 State and concurrency

Calls out of order. Finalising twice. Re-entry. Cancellation at every suspension point. Process death at every step. Two uploads to one address. A fetch racing a delete. A vault write racing a read. An old vault file restored over a new one. The clock set back to revive an expired card or postpone a key's destruction. Partial writes and torn renames.

### X-6 Exhaustion

Lengths that cause large allocations before validation. Many extensions; many candidates. A sender choosing the 2 GiB passphrase profile for a recipient with less memory. Proof-of-work difficulty set absurdly high by a server. Slow senders and slow readers. Disk and descriptor exhaustion. Maps keyed by attacker-chosen addresses with an unkeyed hash. The relay used as free bandwidth: sessions without byte or time limits.

### X-7 The service under attack by clients

Address enumeration. Timing that distinguishes "exists" from "does not". Addresses that are not exactly 64 lowercase hex characters, used as path components. Request smuggling through a reverse proxy. Header injection. Many, overlapping or multipart ranges. A declared length that disagrees with the body. Delete-token guessing. Stamps replayed or precomputed. An incomplete upload appended to by someone else. Storage filled at maximum lifetime. A third connection to a paired live address.

### X-8 The client under attack by the service

Redirects — following one sends a capability to another origin. `/v3/info` with huge, negative, wrongly typed or deeply nested values, or an unbounded body. A response body longer or shorter than declared, or endless. Compressed responses. Cookies. Certificates that do not validate; plaintext downgrade. Proxy settings picked up from the environment without the user choosing them. A blob served to one client and a different one to another.

### X-9 The local machine

Secrets in command-line arguments, environment variables, shell history, terminal titles. Secrets in swap, hibernation files, core dumps, crash reports, logs, temporary files. World-readable files. Predictable temporary names. Clipboard contents left behind. Another process of the same user reading memory or the vault. The `aegis:` link handler invoked by a web page: a fetch made without the user confirming the origin discloses the user's address and exposes the client to a chosen server. Received files without the operating system's "downloaded from elsewhere" marking.

### X-10 The human

A ShareKey pasted where a ShareLink was expected, and sent somewhere. An origin that resembles a trusted one. A fingerprint that matches in its first and last groups only; any interface that shows less than the whole fingerprint. A note crafted to look like an instruction from the application. Both artifacts requested "in one message, for convenience". A warning that can be dismissed without reading.

### X-11 Supply chain and build

A dependency update that changes behaviour. A new transitive dependency. A typo-squatted or confused package name. Build-time code. A compromised CI runner. A release artefact replaced after signing. A signing key exposed to a networked machine. An update delivered without a verified signature. A commit or tag that is not signed.

---

## 6. Proving the tests work: the sabotage suite

**T-10.** `sabotage/` holds a set of small patches, each of which breaks exactly one security control. A CI job applies each patch to a scratch copy of the tree, runs the test suite, and requires at least one test to fail. A patch that leaves the suite green is a hole in the tests, and blocks merging until closed.

Sabotage exists only as patch files. It MUST NOT exist as a compile-time flag, a feature or a configuration switch: a control that can be turned off in shipped code is itself a vulnerability.

The initial set. Every new control adds its own patch at gate G3.

| # | Sabotage |
|---|----------|
| 1 | Skip the commitment check |
| 2 | Compare the commitment with a non-constant-time equality |
| 3 | Ignore the final-chunk flag |
| 4 | Do not advance the chunk counter |
| 5 | Accept non-zero padding |
| 6 | Skip the canonical padded-length check |
| 7 | Skip reserved-field checks in the header |
| 8 | Use permissive signature verification |
| 9 | Leave the transcript hash out of the sender signature |
| 10 | Leave the stream digest out of the sender signature |
| 11 | Leave the recipient binding out of the transcript |
| 12 | Derive the blob address without `KS` |
| 13 | Use the header key as the payload key |
| 14 | Finalise output before the last chunk verifies |
| 15 | Do not erase the payload key |
| 16 | Derive a KEM key from the recovery seed |
| 17 | Return a constant from the random source |
| 18 | Accept `=` padding and stray bits in base32 |
| 19 | Skip artifact checksums |
| 20 | Accept a card with an over-long window, or an expired one |
| 21 | Accept an artifact of another version |
| 22 | Follow an HTTP redirect |
| 23 | Pause the download until the header has been processed |
| 24 | Write a blob address to the log |
| 25 | Service: serve an incomplete upload |
| 26 | Service: return a distinguishable response for a wrong delete token |
| 27 | Service: allow a second write to an address |
| 28 | Live: send data before `READY` |
| 29 | Live: omit the prologue |
| 30 | Accept the clock moving backwards |

Sabotage 2 and 15 cannot be caught by an ordinary functional test. They are caught by the timing test (T-11) and the memory-forensics test (T-24). That is the reason those tests are mandatory and not optional extras.

---

## 7. Review and release

**R-1.** Every change to Tier 1 has an author, a reviewer who did not write it, and a break-it session (M-7). Nobody merges their own Tier 1 change.

**R-2.** Review is against the surface statement and the attack plan, not only the diff. The reviewer's first question is: what does this change let an attacker reach that they could not reach before?

**R-3.** A flaky test is a defect. It is fixed or its cause understood within 48 hours. It is never retried into passing.

**R-4.** No warning is suppressed without a comment naming the rule and the reason. No `TODO` survives in Tier 1 at a release.

**R-5.** A dependency is updated only with a recorded review of the differences. Outside security fixes, no version younger than 14 days is adopted.

**R-6.** Commits and tags are signed. The default branch is protected. CI holds no secrets that matter: no signing keys, no deployment credentials.

**R-7.** A release is cut only from a commit for which every gate in the plan's CI table, every ring, the sabotage suite and the nightly simulation have been green for seven consecutive days.

**R-8.** Releases are reproducible, built by two machines that share no administrator, and published with a bill of materials.

**R-9.** Release signing keys are generated and used on a machine that has never been connected to a network, held in hardware, and never present in CI. What crosses the gap is a hash to sign and a signature back.

**R-10.** A defect in the design — as opposed to the code — found after the format freeze is fixed by a new protocol version with its own analysis. It is never patched silently into v3.

### Gates added to the plan's milestones

| Milestone | This standard additionally requires |
|-----------|-------------------------------------|
| M0 | Tier graph test (A-1); `no_std` Tier 1 skeletons (A-3); class types (A-8); sabotage job running with at least one patch; surface, routes and attack-log directories in place |
| M1, M2 | G0–G7 for every piece; Ring 1 complete; sabotage 1–21 |
| M3 | T-4 exhaustion, T-7 bounded proofs, T-9 mutation floors, T-11 timing, T-24 memory forensics |
| M4 | First red-team exercise (T-29) before the freeze |
| M5 | Ports and the simulator (A-11, A-12); T-13, T-14; T-17 at one million seeds nightly; T-21; sabotage 22–24, 30 |
| M6 | X-7 in full; sabotage 25–27; A-19 |
| M7 | Malicious-relay suite; sabotage 28–29 |
| M8 | X-9 and X-10 in full; T-25, T-26 |
| M9 | Second red-team exercise; the attack log handed to the auditors |
| M10 | A-20, R-8, R-9; T-27 |

---

## 8. What this does not give you

1. **It does not prove the design.** That is the job of the symbolic model and the audit. Tests show that known attacks fail against this code.
2. **It does not cover what nobody imagined.** The catalogue holds the attacks we know. The thirty unscripted minutes of M-3, the red team and the bounty exist because the catalogue is incomplete, and will stay incomplete.
3. **It does not protect a compromised endpoint.** Memory forensics shows that secrets are erased after use, not that malware running during use cannot take them.
4. **It does not make erasure perfect.** T-24 finds copies; the language and the operating system may make more than a test can see.
5. **It does not replace judgement.** Passing every gate is the minimum. A reviewer who believes something is wrong and cannot yet say why has the right to stop a merge until they can.

The discipline is worth exactly as much as the willingness to stop a release because of it.

---

**End of Engineering Standard**
