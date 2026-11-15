# DIGITAL MINERAL CIVILIZATION
## M2 — Cryptographic Agent Identity and Key Lifecycle

- **Specification ID:** `DMC-M2-SPEC-001`
- **Version:** `1.0` (Incorporating Amendment `DMC-M2-DEC-002`)
- **Authorization IDs:** `DMC-M2-AUTH-001`, `DMC-M2-DEC-002`
- **Status:** Finalized Specification — All Founder Decisions & Keystore Architecture Incorporated
- **Classification:** Foundational Security Architecture
- **Implementation Status:** **NOT AUTHORIZED** (Specification Only; Requires Separate Founder Authorization)
- **Predecessor:** `M1.1` — Provisional Identity, Delegation, and Provenance Foundation (Frozen)

---

## Specification Change History

| Version | Directive / Authority | Date (UTC) | Summary of Changes |
|---|---|---|---|
| `0.2` | `DMC-M2-SPEC-001` | 2026-11-14 | Baseline M2 specification with 6 initial Founder decisions and 10 open design review items. |
| `1.0` | `DMC-M2-AUTH-001` | 2026-11-14 | Incorporated Founder Decisions 1–10 and Additional Security Requirements A–C; documented `BLOCKER-M2-001` for keystore KDF/AEAD selection. |
| `1.0 (Rev A)` | `DMC-M2-DEC-002` | 2026-11-14 | Resolved `BLOCKER-M2-001`: Founder selected Option 2 (`scrypt` + `ChaCha20-Poly1305` + `zeroize`) for `DMC-DEV-KEYSTORE-V1`; prohibited custom Encrypt-then-HMAC constructions; defined KDF resource caps, AAD layout, and dependency cache provisioning status (`PROV-M2-001`). |
| `1.0 (Rev B)` | `DMC-M2-AUDIT-004` | 2026-11-14 | Reconciled `scrypt` parameter bounds (`log_n: 15..=16`, `r: 8..=15`, `p: 1..=2`), exact `scrypt-0.10.0` heap memory formula (`128 * r * (2^log_n + p + 1) <= 128 MiB`), CPU work-factor bound (`2^log_n * r * p <= 1,966,080`), and `MIN_KEYSTORE_FILE_BYTES = 183`. |

---

## 1. Purpose and Constitutional Subordination

### 1.1 Purpose
Milestone 2 (`M2`) establishes cryptographically verifiable identities for Digital Mineral Civilization (`DMC`) agents and defines the authoritative lifecycle for their cryptographic keys. `M2` introduces Ed25519 cryptographic authentication while preserving strict separation between **identity**, **authentication**, **authorization**, **delegation**, **process provenance**, and **execution permission**.

`M2` establishes:
1. **Identity:** Which stable `AgentId` is presenting an identity claim.
2. **Authentication:** Whether the presenter controls a registered, active Ed25519 private key (`KeyId`) bound to that `AgentId`.
3. **Credential Validity:** Whether the presented `KeyId` and owning `AgentId` are currently active, unrevoked, and unexpired in the authoritative live registry.
4. **Key Lifecycle Governance:** How keys are generated, enrolled under the Founder Root Trust Anchor, rotated with immediate cutover, revoked, and recovered.
5. **M1.1 Integration:** How cryptographically verified identity evidence integrates with the frozen `M1.1` delegation, process-provenance, policy-evaluation, and audit-sequencing interfaces without breaking existing `M1` or `M1.1` functionality.

> [!IMPORTANT]
> **Authentication Does Not Equal Authorization:** A valid Ed25519 signature over a canonical challenge proves key possession and authenticates the presenting `AgentId` at a specific registry sequence. It **never** independently grants execution permission, elevates autonomy tier, widens resource scope, or bypasses `ProvenanceTracker` lineage checks.

### 1.2 Authority and Subordination
This specification is subordinate to the DMC Constitution (`DM-FOUNDATION-001`) and Engineering Charter. It incorporates all ten Founder-approved design decisions (`DMC-M2-AUTH-001`), the keystore cryptographic directive (`DMC-M2-DEC-002`), and all three additional mandatory security requirements. No implementation, dependency modification, or source-code change is authorized by this specification.

---

## 2. Incorporated Founder Architectural and Design Decisions (10/10)

### 2.1 Decision 1 — Canonical Encoding (`DMC-CANON-V1`)
All signed messages and canonical challenges in `M2` use **DMC-CANON-V1**, a deterministic, big-endian, length-prefixed binary wire format implemented in `dmc-types` with **zero external crate dependencies**.
- **Magic Prefix:** Exact 11-byte ASCII prefix `b"DMC-SIG-V1\0"` (`44 4D 43 2D 53 49 47 2D 56 31 00`).
- **Header Fields:** `protocol_version: u16` (`0x0001`, big-endian), `schema_version: u16` (`0x0001`, big-endian), `message_type: u8` (`0x01`..`0x06`), and `algorithm_id: u8` (`0x01` = Ed25519).
- **Deterministic Layout:** Fixed field ordering; no optional untagged fields; strings and variable-length byte slices are encoded as `<u32 big-endian byte length><exact bytes>`.
- **Strict Rejection:** Decoders reject unknown `message_type`, unknown `algorithm_id`, unsupported `(protocol_version, schema_version)`, trailing bytes, truncated frames, oversized messages (`> 4096` bytes), oversized fields, or noncanonical string/identifier encodings. Ordinary JSON, YAML, or non-canonical CBOR is prohibited for signing.
- **Exact Signing Boundaries:** Normatively defined per message type in [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md).

### 2.2 Decision 2 — Founder-Controlled Root Trust Anchor
DMC maintains a separate Founder-controlled trust anchor (`RootTrustAnchorSet`) logically and physically separated from routine agent credentials:
- **Runtime Public-Key Pinning Only:** Runtime services (`CryptographicIdentityRegistry`) receive only pinned `RootPublicKeyEntry` records (`RootAnchorId`, `Ed25519PublicKeyBytes`, `RootRole`, activation/status metadata). Runtime services never load or hold Founder Root Private Keys.
- **Role Separation:** Root anchors are partitioned into:
  - `ActiveEnrollmentAndRecovery` (`active_root_key_id`): Authorizes agent enrollment (`IdentityRegistration`) and credential recovery (`RecoveryRecord`).
  - `EmergencyRecoveryOnly` (`emergency_recovery_root_key_id`): Offline cold root anchor reserved for root-anchor rotation, compromise remediation, or emergency recovery.
- **Zero Autonomous Access:** No RDA process, agent, or automated service may access Founder Root Private Keys.
- **Lifecycle Procedures:**
  - *Generation:* Performed manually offline or in a dedicated operator ceremony using OS CSPRNG (`getrandom`) into an isolated root keystore directory (`0700` dir, `0600` file) separate from agent keystores.
  - *Backup:* Offline encrypted backup split across operator-controlled storage media outside the Termux workspace.
  - *Rotation & Compromise:* If `active_root_key_id` is rotated or compromised, the Founder signs a root transition/revocation directive using `emergency_recovery_root_key_id`, updates the pinned `RootTrustAnchorSet`, and re-verifies active registrations against the monotonic registry sequence.
  - *Restoration:* Restored only via explicit operator ceremony verified against offline digests.

### 2.3 Decision 3 — Local Development Keystore (`DMC-DEV-KEYSTORE-V1`, Amended by `DMC-M2-DEC-002`)
Initial key custody targets the Termux-first local development environment under strict filesystem, memory, KDF, and AEAD controls. Custom Encrypt-then-HMAC constructions and plaintext storage fallbacks are strictly prohibited.

1. **Approved Cryptographic Architecture (`DMC-M2-DEC-002`):**
   - **Password-Based Key Derivation (KDF):** `scrypt` (RFC 7914, `kdf_id = 0x01`) deriving a 32-byte (`256-bit`) symmetric keyEncryptionKey (`KEK`).
   - **Authenticated Encryption (AEAD):** IETF `ChaCha20-Poly1305` (RFC 8439, `aead_id = 0x01`) with a 256-bit key, 96-bit (`12-byte`) nonce, and 128-bit (`16-byte`) Poly1305 authentication tag.
   - **Memory Protection:** `zeroize` (`Zeroize` and `ZeroizeOnDrop`) on all passphrases, derived KEKs, and Ed25519 private seeds.
   - **Strict Key Separation:** The agent's 32-byte Ed25519 secret seed is generated independently from the OS CSPRNG (`getrandom`). The `scrypt`-derived 32-byte key is used **exclusively** as the `ChaCha20-Poly1305` wrapping key (`KEK`) and is never used as or mixed into Ed25519 signing key material.
2. **Exact `scrypt` Parameterization, Resource Model, and Calibration Methodology (`DMC-M2-AUDIT-004`):**
   - **Selected Rust `scrypt = "=0.10.0"` Resource Behavior:**
     In `scrypt-0.10.0/src/lib.rs` (lines 104–117), `scrypt::scrypt` allocates three simultaneous `Vec<u8>` buffers on the heap:
     1. Primary ROMix scratchpad `v`: $|V| = 128 \cdot r \cdot 2^{\text{log\_n}}$ bytes (`vec![0u8; nr128]`).
     2. PBKDF2/ROMix parallelization buffer `b`: $|B| = 128 \cdot r \cdot p$ bytes (`vec![0u8; pr128]`).
     3. Temporary block-XOR buffer `t`: $|T| = 128 \cdot r$ bytes (`vec![0u8; r128]`).
     The `p` chunks of `b` are processed **sequentially** in a single thread (`for chunk in &mut b.chunks_mut(r128) { romix::scrypt_ro_mix(chunk, &mut v, &mut t, n); }`), reusing `v` and `t`. Consequently, **`p` affects both memory and CPU cost**:
     - *Memory effect of `p`:* `p` does not multiply the primary ROMix buffer `v` ($|V|$), but linearly increases the `b` buffer allocation by $128 \cdot r \cdot p$ bytes.
     - *CPU effect of `p`:* `p` scales single-threaded CPU execution time linearly ($\mathcal{O}(2^{\text{log\_n}} \cdot r \cdot p)$), performing $2 \cdot 2^{\text{log\_n}} \cdot p$ `BlockMix` calls ($4 \cdot 2^{\text{log\_n}} \cdot r \cdot p$ `Salsa20/8` 64-byte block transformations).
   - **Default Production/Development Baseline (`ScryptParamsConfig::baseline()` — Retained):**
     - `log_n: u8 = 15` ($N = 2^{15} = 32,768$ CPU/memory cost iterations)
     - `r: u32 = 8` (block size factor; $128 \times r = 1,024$ bytes)
     - `p: u32 = 1` (parallelization factor)
     - `derived_key_len = 32` bytes
   - **Calibration Rationale:** At baseline (`log_n = 15, r = 8, p = 1`), $|V| = 33,554,432$ bytes (`32 MiB`), $|B| = 1,024$ bytes (`1 KiB`), and $|T| = 1,024$ bytes (`1 KiB`), for an exact total heap allocation of `33,556,480` bytes ($\approx 32.002\text{ MiB}$) and CPU work factor $2^{15} \times 8 \times 1 = 262,144$. On ARM64 Termux mobile/edge processors, this completes in ~120–300 ms per key unlock while staying safely below Android low-memory-killer (`LMK`) thresholds.
3. **Maximum Permitted Resource Consumption During KDF Processing (DoS Defense — Amended by `DMC-M2-AUDIT-004`):**
   - Because a keystore file's header is parsed prior to Poly1305 tag verification, an attacker with local file write access could tamper with `log_n`, `r`, or `p` to trigger an out-of-memory panic or CPU hang.
   - Before allocating buffers or invoking `scrypt::scrypt`, the loader enforces hard pre-KDF bounds derived from the `128 MiB` (`134,217,728`-byte) total heap ceiling:
     - **File Size Cap:** Inspect `std::fs::metadata(path)?.len()` before reading; reject any file `< 183` bytes (`MIN_KEYSTORE_FILE_BYTES`) or `> MAX_KEYSTORE_FILE_BYTES` (`1024` bytes) with `KeystoreError::FileSizeOutOfBounds`.
     - **Derived Parameter Bounds (`DMC-M2-AUDIT-004`):**
       - `MIN_SCRYPT_LOG_N (15) <= log_n <= MAX_SCRYPT_LOG_N (16)` ($32,768 \le N \le 65,536$; reduced from `17` because at `log_n = 17, r >= 8, p >= 1`, $|V|$ alone is $\ge 134,217,728$ bytes and $|V| + |B| + |T| \ge 134,219,776$ bytes $> 128\text{ MiB}$, and `(log_n = 17, r = 16)` required `256 MiB`).
       - `MIN_SCRYPT_R (8) <= r <= MAX_SCRYPT_R (15)` (reduced from `16` because at `log_n = 16, p >= 1`, $\lfloor 1,048,576 / (65,536 + p + 1) \rfloor = 15$, whereas `r = 16` requires $|V| + |B| + |T| \ge 134,221,824$ bytes $> 128\text{ MiB}$).
       - `MIN_SCRYPT_P (1) <= p <= MAX_SCRYPT_P (2)` (reduced from `4` to bound single-thread sequential CPU multiplication).
     - **Explicit Checked Total Heap Memory Cap:** Compute the exact simultaneous heap allocation of `scrypt::scrypt` (`|V| + |B| + |T|`) using checked arithmetic (`checked_shl`, `checked_mul`, `checked_add`) before any KDF allocation:
       $$\text{total\_heap\_bytes} = 128 \times 2^{\text{log\_n}} \times r + 128 \times p \times r + 128 \times r = 128 \times r \times \left(2^{\text{log\_n}} + p + 1\right)$$
       Reject if arithmetic overflow occurs or if $\text{total\_heap\_bytes} > \text{MAX\_KDF\_MEMORY\_BYTES}$ (`134,217,728` bytes = `128 MiB`) with `KeystoreError::KdfParametersOutOfBounds`.
     - **Explicit Checked CPU Work-Factor Cap:** Compute the sequential CPU work factor using checked arithmetic:
       $$\text{work\_factor} = 2^{\text{log\_n}} \times r \times p$$
       Reject if overflow occurs or if $\text{work\_factor} > \text{MAX\_KDF\_WORK\_FACTOR}$ (`1,966,080` $= 2^{16} \times 15 \times 2 = 7.5\times$ baseline) with `KeystoreError::KdfParametersOutOfBounds`.
     - **Maximum Accepted vs. First Rejected Configurations:**
       - *Maximum Accepted Configuration:* `(log_n = 16, r = 15, p = 2)` $\implies |V| = 125,829,120\text{ B}$ (`120 MiB`), $|B| = 3,840\text{ B}$, $|T| = 1,920\text{ B}$, `total_heap_bytes` $= 125,834,880\text{ B}$ ($\le 134,217,728\text{ B}$), `work_factor` $= 1,966,080$ ($\le 1,966,080$). *(At standard `r = 8`: `(log_n = 16, r = 8, p = 2)` $\implies$ `total_heap_bytes` $= 67,111,936\text{ B} \approx 64.003\text{ MiB}$, `work_factor` $= 1,048,576$.)*
       - *First Rejected Configurations Above `128 MiB` Ceiling:* `(log_n = 16, r = 16, p = 1)` (`total_heap_bytes` $= 134,221,824\text{ B} = 128\text{ MiB} + 4,096\text{ B}$) and `(log_n = 17, r = 8, p = 1)` (`total_heap_bytes` $= 134,219,776\text{ B} = 128\text{ MiB} + 2,048\text{ B}$).
     - **Concurrency Cap:** A process-wide mutex/semaphore limits active in-flight `scrypt` derivations to `1` (`MAX_CONCURRENT_KDF_JOBS = 1`) so parallel calls cannot multiply peak memory above `128 MiB`.
4. **Unique CSPRNG Salt Generation:**
   - Every keystore write operation generates a fresh **32-byte (`256-bit`) salt** (`kdf_salt: [u8; 32]`) via `getrandom::getrandom(&mut kdf_salt)`.
   - An all-zero salt `[0u8; 32]` is rejected as `KeystoreError::CsprngFailure`. Salts are never reused across files or across re-saves of the same key.
5. **ChaCha20-Poly1305 Nonce Generation and Uniqueness Requirements:**
   - Every keystore write operation generates a fresh **12-byte (`96-bit`) nonce** (`aead_nonce: [u8; 12]`) via `getrandom::getrandom(&mut aead_nonce)`.
   - An all-zero nonce `[0u8; 12]` is rejected as `KeystoreError::CsprngFailure`.
   - **Double Uniqueness Invariant:** Because every write generates both a fresh 32-byte `kdf_salt` (producing a fresh 256-bit `ChaCha20-Poly1305` key) and a fresh 12-byte `aead_nonce`, a `(KEK, nonce)` pair is never reused under any circumstance.
6. **Associated Authenticated Data (AAD) Fields:**
   - All header and identity binding fields preceding the ciphertext (`envelope_bytes[0..aad_end]`) are passed as the `aad` slice to `ChaCha20Poly1305`:
     `ks_magic` (`10B`), `ks_version` (`2B`), `custody_tag` (`1B`), `custody_ascii` (`24B`), `kdf_id` (`1B`), `aead_id` (`1B`), `scrypt_log_n` (`1B`), `scrypt_r` (`4B`), `scrypt_p` (`4B`), `kdf_salt` (`32B`), `aead_nonce` (`12B`), `agent_id` (`LP-UTF8`), `key_id` (`LP-UTF8`), `algorithm_id` (`1B`), and `public_key` (`32B`).
7. **Authentication-Tag Verification, Wrong-Password, and Corrupted-Envelope Behavior:**
   - Structural corruption (bad magic, unsupported version/KDF/AEAD tag, out-of-bounds KDF params, malformed IDs, or trailing bytes) is rejected **before** KDF execution (`KeystoreError::InvalidKeystoreEnvelope` / `KdfParametersOutOfBounds`).
   - `ChaCha20Poly1305::decrypt_in_place_detached` verifies the 16-byte Poly1305 tag in constant time over `(aad, encrypted_seed)`.
   - If the password is wrong or any byte of `aad`, `encrypted_seed`, or `poly1305_tag` was modified, tag verification fails, the temporary buffer is zeroized immediately, and a single uniform error `KeystoreError::AuthenticationFailed` is returned (without distinguishing wrong password from tampered ciphertext).
   - After successful tag verification, the loader computes `ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key()` and verifies that its 32-byte public key matches the AAD-authenticated `public_key` field; any mismatch zeroizes the seed and returns `KeystoreError::DecodedPublicKeyMismatch`.
8. **Password Handling and Memory Zeroization:**
   - Passphrases are encapsulated in `SecretPassphrase(Zeroizing<Vec<u8>>)` with `Debug`/`Display` redacted to `"<REDACTED-PASSPHRASE>"`.
   - Passphrases with length `< MIN_PASSPHRASE_BYTES (12)` or `> MAX_PASSPHRASE_BYTES (256)`, or consisting solely of whitespace, are rejected before KDF execution (`KeystoreError::InvalidPassphraseLength`).
   - Intermediate buffers (`derived_kek: Zeroizing<[u8; 32]>`, `seed_buf: Zeroizing<[u8; 32]>`) are automatically zeroized on scope exit.
9. **Filesystem Permissions, Versioning, Migration, and No-Plaintext-Fallback:**
   - Keystore directories must reside outside the Git workspace with mode `0700`; key files must have mode `0600` and must not be symlinks.
   - `ks_version = 0x0001`, `kdf_id = 0x01`, and `aead_id = 0x01` enable future migration to `ks_version = 2` or hardware-backed `M3+` custody by decrypting v1 and re-wrapping without altering `AgentId` or `KeyId`.
   - Plaintext fallback is unconditionally prohibited (`KeystoreError::PlaintextFallbackProhibited`).

### 2.4 Decision 4 — Challenges and Replay Protection
Authentication requires signing a fresh verifier-issued challenge bound to a specific agent and verifier instance:
- **Challenge Structure:**
  - `challenge_id: ChallengeId` (unique validated identifier)
  - `nonce: [u8; 32]` (32 bytes generated from OS CSPRNG via `getrandom`)
  - `target_agent_id: AgentId`
  - `verifier_instance_id: u64` (unique per `CryptographicIdentityRegistry` instance)
  - `registry_sequence_at_issue: u64`
  - `issued_at_epoch_ms: u64` and `expires_at_epoch_ms: u64`
  - In-memory monotonic `issued_instant: std::time::Instant` and `max_ttl_ms: u64`
- **Lifetime & Clock Enforcement:** Maximum challenge lifetime is `300_000 ms` (5 minutes). Verification rejects challenges where:
  - `expires_at_epoch_ms <= issued_at_epoch_ms` or `expires_at_epoch_ms - issued_at_epoch_ms > 300_000`
  - `eval_epoch_ms < issued_at_epoch_ms` (future-dated challenge / clock rollback)
  - `eval_epoch_ms >= expires_at_epoch_ms` (expired wall-clock window)
  - `eval_instant.saturating_duration_since(issued_instant).as_millis() > u128::from(max_ttl_ms)` (monotonic elapsed-time enforcement)
- **Bounded Replay Cache & Saturation:** `ReplayTracker` holds at most `MAX_ACTIVE_CHALLENGES = 10_000` entries. Expired entries are pruned deterministically before issuance. If `10_000` unexpired challenges are already active, issuance fails closed with `ChallengeError::ReplayCacheSaturated` without evicting unexpired challenges.
- **Atomic Consumption:** Upon verifying a challenge during authentication, its state transitions atomically from `Pending` to `Consumed { consumed_at_epoch_ms }`. Re-presenting a `Consumed` challenge fails closed with `ChallengeError::ChallengeReplayed`.
- **Verifier Restart Safety:** Each `CryptographicIdentityRegistry` / `ReplayTracker` instance draws a fresh non-zero `verifier_instance_id` and starts with an empty active-challenge table. Any challenge issued prior to a restart has either a foreign `verifier_instance_id` or is absent from the active table (`ChallengeError::UnknownOrRestartInvalidatedChallenge`), ensuring restarts never reactivate pre-restart challenges.

### 2.5 Decision 5 — Registry Rollback Protection (Option 5B)
`M2` adopts an authoritative in-memory `CryptographicIdentityRegistry` with monotonic sequence tracking:
- **Monotonic Sequence:** Every state-mutating operation (`enroll_agent`, `rotate_key`, `revoke_key`, `revoke_agent`, `recover_agent_keys`) increments `registry_sequence: u64` via `checked_add(1)`. Overflow at `u64::MAX` fails closed with `CryptoIdentityError::RegistrySequenceOverflow` without mutating state.
- **Instance Binding:** Each registry instance has a unique non-zero `instance_id: u64` (`AtomicU64`) and does not implement `Clone`.
- **High-Water-Mark Enforcement:** The registry and verification layer track `min_acceptable_sequence: u64`. Any operation or identity token presenting a foreign `instance_id` or a registry state where `registry_sequence < min_acceptable_sequence` is rejected with `CryptoIdentityError::RegistryRollbackDetected`.
- **Explicit M2 Limitation:** Durable registry snapshots and protection against disk or OS-process-restart rollback are **not** claimed in `M2` and are explicitly deferred to `M3` (see [DMC-M2-M3-BOUNDARY.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-M3-BOUNDARY.md)).

### 2.6 Decision 6 — Key Rotation (Immediate Cutover, Zero Overlap)
Key rotation preserves the stable `AgentId` while replacing the active `KeyId` with zero overlap:
- **Dual Cryptographic Authorization:** A `KeyRotationRecord` contains a canonical `KeyRotationPayload` (binding `agent_id`, `old_key_id`, `new_key_id`, `new_public_key`, `custody_assurance`, `expected_registry_sequence`, `rotated_at_epoch_secs`) signed by **both**:
  1. `old_key_signature`: Ed25519 signature by the currently `Active` `old_key_id`.
  2. `new_key_pop_signature`: Ed25519 proof-of-possession signature by `new_key_id` over the identical canonical payload bytes.
- **Atomic Cutover:** Upon verification, `old_key_id` transitions immediately to `KeyLifecycleStatus::Retired { superseded_by: new_key_id, retired_at_sequence, retired_at_epoch_secs }`, `new_key_id` becomes the sole `Active` key for `agent_id`, and `registry_sequence` increments by 1.
- **Zero Grace Period:** Once retired, `old_key_id` cannot authenticate new claims, sign rotations, or authorize any operation.

### 2.7 Decision 7 — Revocation (Strict Fail-Closed)
- **Live Registry Requirement:** Every authentication and strict policy evaluation (`policy_evaluate_strict_cryptographic_provenance`) queries live `CryptographicIdentityRegistry` state.
- **Immediate Invalidation:**
  - Revoking a `KeyId` transitions that key to `KeyLifecycleStatus::Revoked` and immediately invalidates any `ResolvedAgentIdentity` bound to that `KeyId`.
  - Revoking an `AgentId` marks the agent revoked and transitions all of its `Active` keys to `KeyLifecycleStatus::Revoked`, invalidating the agent and any dependent delegation chains where the agent is issuer or recipient.
- **No Self-Restoration:** A revoked key or revoked agent cannot authenticate, rotate keys, or authorize recovery.
- **Unavailability / Poisoning:** If the registry reference is missing, from a foreign `instance_id`, or at a stale sequence, evaluation fails closed (`Decision::Deny`, `execution_authorized() == false`).

### 2.8 Decision 8 — Credential Recovery (Founder Root Authorization)
When an agent loses access to its active private key or suspects key compromise, recovery is performed via `RecoveryRecord`:
- **Authority Separation:** Routine agent keys (whether `Active`, `Retired`, or `Revoked`) cannot authorize a `RecoveryRecord`. Recovery requires authorization from the pinned **Founder Root Trust Anchor**.
- **Initial `1-of-1` Mode with `M-of-N` Schema Support:**
  - `RecoveryRecord` carries `root_approvals: Vec<RootSignatureApproval>` and `required_threshold: u8`.
  - In `M2`, operational verification enforces `required_threshold == 1` against a pinned active or emergency Founder Root key. If a caller submits `required_threshold > 1` or configures a threshold > 1 before threshold verification is authorized, verification fails closed with `CryptoIdentityError::ThresholdRecoveryNotYetOperational`.
  - **Truthfulness Constraint:** `M2` does **not** claim operational multi-party (`M > 1`) threshold recovery.
- **Proof of Possession & Atomic Quarantine:** `RecoveryRecord` also requires `new_key_pop_signature` from `new_key_id`. Execution atomically marks all previously `Active` keys of `agent_id` as `KeyLifecycleStatus::Revoked { reason_code: RevocationReasonCode::SupersededByRecovery, ... }`, registers `new_key_id` as `Active`, preserves all historical key records, increments `registry_sequence`, and emits a `CredentialRecovery` audit event.

### 2.9 Decision 9 — Cryptographic Dependencies (Amended by `DMC-M2-DEC-002`)
Cryptographic dependencies are confined strictly to `core/titan-identity`:
- `core/dmc-types` has **zero** external dependencies (`[dependencies]` remains empty).
- Approved dependency set for `core/titan-identity`:
  - `ed25519-dalek = { version = "=2.2.0", default-features = false, features = ["rand_core", "zeroize"] }` *(cached locally)*
  - `getrandom = { version = "=0.2.17", default-features = false }` *(cached locally)*
  - `rand_core = { version = "=0.6.4", default-features = false, features = ["getrandom"] }` *(cached locally)*
  - `zeroize = { version = "=1.8.2", default-features = false, features = ["alloc", "derive"] }` *(cached locally)*
  - `sha2 = { version = "=0.10.9", default-features = false }` *(cached locally)*
  - `scrypt = { version = "=0.10.0", default-features = false }` *(cached locally with all transitive dependencies: `hmac 0.12.1`, `pbkdf2 0.11.0`, `salsa20 0.10.2`, `sha2 0.10.9`, `cipher 0.4.4`, `digest 0.10.7`, `inout 0.1.4`, `crypto-common 0.1.6`, `block-buffer 0.10.4`, `generic-array 0.14.7`, `typenum 1.20.0`)*
  - `chacha20poly1305 = { version = "=0.10.1", default-features = false, features = ["alloc", "zeroize"] }` *(approved by `DMC-M2-DEC-002`; requires cache provisioning prior to `M2.1` build — see Section 5.2)*
- **Strict Verification Mandate:** All Ed25519 signature checks must invoke `ed25519_dalek::VerifyingKey::verify_strict(&message_bytes, &signature)` (coupled with rejecting small-order public keys via `VerifyingKey::is_weak()`) to prevent small-subgroup and non-canonical $S \ge L$ signature malleability.

### 2.10 Decision 10 — M1.1 Migration and Compatibility
`M2` is additive and non-breaking with respect to `M1` and `M1.1`:
- `ProvisionalIdentityRegistry`, `policy_evaluate`, `policy_evaluate_authorized`, `policy_evaluate_strict_provenance`, and all 20 existing `M1.1` unit tests remain preserved.
- New variants and entrypoints introduced in `M2`:
  - `dmc_types::IdentityTrustStatus::CryptographicallyVerified`
  - `titan_policy_core::PolicyTrustLevel::CryptographicLiveProvenanceVerified`
  - `titan_identity::CryptographicIdentityRegistry`
  - `titan_policy_core::policy_evaluate_strict_cryptographic_provenance`
- **Exhaustive Match Compatibility:** Adding variants to `IdentityTrustStatus`, `PolicyTrustLevel`, `AuditEventKind`, and `AuditError` affects exhaustive `match` expressions across workspace crates; exact call sites are documented in [DMC-M2-CHANGE-CONTROL-REPORT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CHANGE-CONTROL-REPORT.md).

---

## 3. Additional Mandatory Security Requirements (3/3)

### 3.1 Requirement A — No Implicit Privilege Escalation
Cryptographic verification establishes **only** that `AgentId` authenticated using an active `KeyId` at a verified `registry_sequence`.
- It **never** increases `AutonomyLevel` above the agent's registered `max_autonomy` or the process's `effective_autonomy`.
- It **never** permits `AutonomyLevel::E5ReservedAuthority`.
- It **never** permits actions outside `Action::is_allowed_for_autonomy` or outside the process/delegation `permitted_actions`.
- It **never** widens `ResourceScope` or bypasses `validate_canonical_resource_uri`.
- It **never** bypasses `ProvenanceTracker` registration, acyclic process lineage, or multi-hop delegation ancestry checks.

### 3.2 Requirement B — Security Failure Observability
Every security-sensitive rejection or lifecycle transition produces a structured `SecurityAuditRecord` (consumable by `titan_audit::InMemoryAuditSequencer::record_security_event`) covering all eight mandated failure categories:
1. `InvalidSignature` (bad Ed25519 signature, weak public key, wrong domain/message type, malformed canonical wire frame)
2. `ReplayAttempt` (replayed, expired, unknown, future-dated, or saturated challenge)
3. `RevokedCredential` (authentication, rotation, or policy evaluation using a revoked `KeyId`, retired `KeyId`, or revoked `AgentId`)
4. `UnauthorizedRecovery` (recovery signed by non-root key, revoked root key, invalid PoP, or unsupported threshold)
5. `RegistryRollbackDetected` (stale `registry_sequence < min_acceptable_sequence`, foreign `registry_instance_id`, or sequence overflow)
6. `InvalidRotation` (rotation signed by non-active key, mismatched `AgentId`, invalid new-key PoP, or duplicate `KeyId`)
7. `RootTrustFailure` (enrollment or recovery signed by unknown, retired, or role-mismatched root anchor)
8. `KeystorePermissionViolation` (directory mode $\ne 0700$, file mode $\ne 0600$, path inside Git workspace, out-of-bounds KDF parameters, or `ChaCha20-Poly1305` authentication failure)

> [!CAUTION]
> **Fail-Closed Audit Invariant:** Audit recording failure (such as `AuditError::SequenceOverflow` or `AuditError::DuplicateEventId`) **must never** convert a rejected authentication, lifecycle transition, or policy evaluation into an accepted result. Conversely, if a caller's strict execution gate requires an audit record before execution, an audit failure must abort execution permission (`fail closed`).

### 3.3 Requirement C — Explicit Change Control
No source code, Cargo manifest, or dependency lockfile may be modified, and no phase of `M2` (`M2.0` through `M2.6`) may be implemented, without a separate, explicit Founder implementation authorization directive.

---

## 4. Security-Sensitive Operations Specification

### 4.1 Operation 1 — Root Trust Anchor Initialization (`RootTrustAnchorSet::new`)
- **Preconditions:** Caller supplies pinned active and emergency recovery Founder Root public keys.
- **Inputs:** `active_entry: RootPublicKeyEntry`, `emergency_entry: RootPublicKeyEntry`.
- **Validation Sequence:**
  1. Validate `active_entry.anchor_id` and `emergency_entry.anchor_id` via `RootAnchorId::new`; reject if identical (`DuplicateRootAnchorId`).
  2. Verify `active_entry.role == RootRole::ActiveEnrollmentAndRecovery` and `emergency_entry.role == RootRole::EmergencyRecoveryOnly`.
  3. Parse both 32-byte Ed25519 public keys via `ed25519_dalek::VerifyingKey::from_bytes`; reject invalid curve points or weak/small-order keys (`VerifyingKey::is_weak()`) with `CryptoIdentityError::WeakOrInvalidPublicKey`.
  4. Reject if both entries share identical 32-byte public key material (`DuplicateRootPublicKeyBytes`).
- **Authorization Requirements:** Pinned at registry construction time by the host initialization boundary.
- **State Transitions:** Initializes immutable `RootTrustAnchorSet` inside `CryptographicIdentityRegistry`.
- **Failure Behavior:** Fails closed; returns `Err(CryptoIdentityError)` and prevents registry creation.
- **Audit Behavior:** Emits `SecurityFailureCode::RootTrustFailure` if initialization fails.
- **Atomicity Requirements:** Pure constructor; no partial registry instance can be created on error.
- **Relevant Tests:** `T-ROOT-001` through `T-ROOT-004` in [DMC-M2-SECURITY-TEST-PLAN.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SECURITY-TEST-PLAN.md).

### 4.2 Operation 2 — Development Keypair Generation & Keystore Save/Load (`DevKeystore`)
- **Preconditions:** Target keystore directory lies outside any Git repository and has POSIX mode `0700`.
- **Inputs:** `keystore_dir: &Path`, `key_id: &KeyId`, `agent_id: &AgentId`, `passphrase: &SecretPassphrase`, `kdf_config: ScryptParamsConfig`.
- **Validation Sequence (Save & Load):**
  1. Validate `passphrase`: length must be `12..=256` bytes and not all-whitespace (`KeystoreError::InvalidPassphraseLength`).
  2. Canonicalize `keystore_dir`; verify no ancestor directory contains `.git` (`KeystoreError::PathInsideGitWorkspace`).
  3. Inspect `std::fs::metadata(keystore_dir)` permissions via `PermissionsExt::mode()`; reject if `(mode & 0o777) != 0o700` (`KeystoreError::InsecurePermissions`).
  4. On **Load**:
     - Inspect `std::fs::symlink_metadata(file_path)`; reject if symlink (`SymlinkNotAllowed`) or `(file_mode & 0o777) != 0o600` (`InsecurePermissions`).
     - Verify `MIN_KEYSTORE_FILE_BYTES (183) <= file_len <= MAX_KEYSTORE_FILE_BYTES (1024)` **before** reading bytes into memory (`FileSizeOutOfBounds`).
     - Parse `DMC-DEV-KEYSTORE-V1` header: verify `ks_magic == b"DMC-KS-V1\0"`, `ks_version == 1`, `custody_tag == 0x01`, `custody_ascii == b"local_development_only\0\0"`, `kdf_id == 0x01` (`scrypt`), and `aead_id == 0x01` (`ChaCha20-Poly1305`).
     - Validate `scrypt` parameters **before** running KDF or allocating KDF buffers: `15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, checked total heap memory `128 * r * ((1 << log_n) + p + 1) <= 134_217_728` (`128 MiB`), and checked CPU work factor `(1 << log_n) * r * p <= 1_966_080` (`KdfParametersOutOfBounds`).
     - Validate `agent_id`, `key_id`, `algorithm_id == 0x01`, `public_key` (non-weak Ed25519 point), and verify exact remaining byte count is `32` (`encrypted_seed`) + `16` (`poly1305_tag`) = `48` bytes (no trailing bytes).
     - Acquire single-flight KDF guard, derive `Zeroizing<[u8; 32]>` `KEK` via `scrypt::scrypt`, and run `ChaCha20Poly1305::decrypt_in_place_detached(&aead_nonce, &aad_bytes, &mut seed_buf, &poly1305_tag)`.
     - If Poly1305 tag verification fails, immediately zeroize `seed_buf` and `KEK` and return `KeystoreError::AuthenticationFailed`.
     - Construct `SigningKey::from_bytes(&seed_buf)`, verify `signing_key.verifying_key().to_bytes() == public_key.0` (`DecodedPublicKeyMismatch`), zeroize `seed_buf` and `KEK`, and return `DevSigningKey`.
  5. On **Save**:
     - Generate 32-byte Ed25519 `seed` (on key generation), 32-byte `kdf_salt`, and 12-byte `aead_nonce` from OS CSPRNG (`getrandom`), rejecting any all-zero output (`CsprngFailure`).
     - Assemble AAD header bytes `0..aad_end`, derive `Zeroizing<[u8; 32]>` `KEK` via `scrypt::scrypt` (`log_n = 15, r = 8, p = 1`), encrypt `seed` in-place via `ChaCha20Poly1305::encrypt_in_place_detached(&aead_nonce, &aad_bytes, &mut seed_buf)`, and append the 16-byte `poly1305_tag`.
- **Authorization Requirements:** Local operator `SecretPassphrase` and OS user ownership (`0700` dir / `0600` file).
- **State Transitions:** Writes encrypted `<key_id>.dmcks` file with mode `0600` or loads `DevSigningKey` into zeroizable memory.
- **Failure Behavior:** Zeroizes all intermediate secret buffers, removes any `.tmp` file if created during save, and returns `Err((KeystoreError, SecurityAuditRecord))`. Never writes or loads plaintext keys.
- **Audit Behavior:** Emits `SecurityFailureCode::KeystorePermissionViolation` on any permission, path, KDF-bound, or AEAD tag failure.
- **Atomicity Requirements:** Writes to `<key_id>.tmp` via `OpenOptionsExt::mode(0o600)`, calls `sync_all()`, and atomically renames to `<key_id>.dmcks`.
- **Relevant Tests:** `T-KS-001` through `T-KS-017`.

### 4.3 Operation 3 — Agent Enrollment (`CryptographicIdentityRegistry::enroll_agent`)
- **Preconditions:** `CryptographicIdentityRegistry` initialized with valid `RootTrustAnchorSet`.
- **Inputs:** `registration: &IdentityRegistration`, `now_epoch_secs: u64`.
- **Validation Sequence:**
  1. Check `self.registry_sequence.checked_add(1)` does not overflow (`RegistrySequenceOverflow`).
  2. Verify `registration.payload.expected_registry_sequence == self.registry_sequence + 1` (`RegistrySequenceMismatch`).
  3. Reject if `registration.payload.max_autonomy == AutonomyLevel::E5ReservedAuthority` (`ReservedAuthorityNotEnrollable`).
  4. Reject if `registration.payload.department` is empty or contains control characters.
  5. Reject if `registration.payload.custody_assurance != CustodyAssuranceLevel::LocalDevelopmentOnly` (in M2 dev mode) or if production mode is requested with dev custody.
  6. Reject if `registration.payload.expires_at_epoch_secs <= registration.payload.issued_at_epoch_secs` or `now_epoch_secs >= registration.payload.expires_at_epoch_secs`.
  7. Reject if `agent_id` is already registered (`DuplicateAgentRegistration`) or `key_id` is already registered (`DuplicateKeyId`).
  8. Parse `registration.payload.public_key` as Ed25519 `VerifyingKey` and verify `!verifying_key.is_weak()`.
  9. Look up `registration.root_anchor_id` in `self.root_anchors`; verify it is active and has role `ActiveEnrollmentAndRecovery`.
  10. Encode `registration.payload` using `DMC-CANON-V1` (`message_type = 0x01`) and verify `registration.root_signature` using `root_verifying_key.verify_strict`.
- **Authorization Requirements:** Valid `verify_strict` Ed25519 signature by the pinned active Founder Root Trust Anchor over the canonical `IdentityRegistrationPayload`.
- **State Transitions:** Increments `self.registry_sequence` to `next_seq`, updates `self.min_acceptable_sequence = next_seq`, inserts `CryptographicAgentEntry` with `key_id` in `KeyLifecycleStatus::Active`.
- **Failure Behavior:** Returns `Err((CryptoIdentityError, SecurityAuditRecord))`; registry state and `registry_sequence` remain completely unchanged.
- **Audit Behavior:** Emits `AuditEventKind::CryptographicEnrollment` on success or `SecurityFailureObserved` (`RootTrustFailure` / `InvalidSignature` / `RegistryRollbackDetected`) on failure.
- **Atomicity Requirements:** All checks complete before mutating `entries`, `key_to_agent`, or `registry_sequence`.
- **Relevant Tests:** `T-ENROLL-001` through `T-ENROLL-006`.

### 4.4 Operation 4 — Challenge Issuance & Cryptographic Authentication (`issue_challenge` & `authenticate_claim`)
- **Preconditions:** Target `agent_id` is enrolled and active in `CryptographicIdentityRegistry`.
- **Inputs (`authenticate_claim`):** `claim: &SignedIdentityClaim`, `now_epoch_ms: u64`, `now_instant: Instant`.
- **Validation Sequence:**
  1. Verify `claim.payload.verifier_instance_id == self.instance_id` (`ForeignRegistryInstance`).
  2. Verify `claim.payload.registry_sequence_bound <= self.registry_sequence` and `self.registry_sequence >= self.min_acceptable_sequence`.
  3. Look up `claim.payload.challenge_id` in `self.replay_tracker`:
     - Reject if unknown (`UnknownOrRestartInvalidatedChallenge`), already `Consumed` (`ChallengeReplayed`), target `agent_id` mismatch, or `nonce != challenge.nonce`.
     - Reject if `now_epoch_ms < challenge.issued_at_epoch_ms` (`FutureDatedChallenge`), `now_epoch_ms >= challenge.expires_at_epoch_ms` (`ChallengeExpired`), or `now_instant.duration_since(challenge.issued_instant) > challenge.max_ttl` (`ChallengeMonotonicTtlElapsed`).
     - Reject if `claim.payload.expires_at_epoch_ms > challenge.expires_at_epoch_ms` or `now_epoch_ms >= claim.payload.expires_at_epoch_ms`.
  4. Look up `claim.payload.agent_id` in `self.entries`; reject if unknown (`UnknownAgent`) or revoked (`RevokedIdentity`).
  5. Look up `claim.payload.key_id` in agent's key records; reject if unknown (`UnknownKey`), `Retired` (`RetiredKeyUsed`), `Revoked` (`RevokedKeyUsed`), or expired (`KeyExpired`).
  6. Verify `claim.payload.claimed_department == agent_entry.department` and `claim.payload.claimed_autonomy <= agent_entry.max_autonomy` and `!= E5ReservedAuthority`.
  7. Encode `claim.payload` via `DMC-CANON-V1` (`message_type = 0x03`) and verify `claim.signature` via `active_verifying_key.verify_strict`.
  8. Atomically mark `challenge_id` as `Consumed` in `self.replay_tracker`.
  9. Mint sealed `ResolvedAgentIdentity` with `trust_status = IdentityTrustStatus::CryptographicallyVerified`, `authenticated_key_id = Some(key_id)`, `registry_instance_id = self.instance_id`, and `registry_sequence_at_resolution = Some(self.registry_sequence)`.
- **Authorization Requirements:** Valid Ed25519 signature by the agent's currently `Active` private key over the canonical `SignedIdentityClaimPayload` containing an unconsumed, unexpired challenge.
- **State Transitions:** Marks `challenge_id` as `Consumed`. Does **not** grant execution permission.
- **Failure Behavior:** Fails closed; returns `Err((CryptoIdentityError, SecurityAuditRecord))`.
- **Audit Behavior:** Emits `CryptographicAuthentication` on success; emits `SecurityFailureObserved` (`InvalidSignature`, `ReplayAttempt`, `RevokedCredential`, or `RegistryRollbackDetected`) on failure.
- **Atomicity Requirements:** Challenge consumption occurs only after all cryptographic and registry state checks succeed.
- **Relevant Tests:** `T-AUTH-001` through `T-AUTH-010`.

### 4.5 Operation 5 — Immediate-Cutover Key Rotation (`CryptographicIdentityRegistry::rotate_key`)
- **Preconditions:** `agent_id` is enrolled and unrevoked; `old_key_id` is currently `Active`.
- **Inputs:** `rotation: &KeyRotationRecord`, `now_epoch_secs: u64`.
- **Validation Sequence:**
  1. Check `self.registry_sequence.checked_add(1)` (`RegistrySequenceOverflow`) and verify `rotation.payload.expected_registry_sequence == self.registry_sequence + 1`.
  2. Verify `agent_id` is active and not revoked.
  3. Verify `old_key_id != new_key_id` and `new_key_id` is globally unused in `self.key_to_agent`.
  4. Verify `old_key_id` belongs to `agent_id`, has status `KeyLifecycleStatus::Active`, and is not expired at `now_epoch_secs`.
  5. Parse `rotation.payload.new_public_key`, verify `!new_verifying_key.is_weak()`, and verify `new_public_key != old_public_key` (`IdenticalRotationKeyMaterial`).
  6. Encode `rotation.payload` via `DMC-CANON-V1` (`message_type = 0x04`).
  7. Verify `rotation.old_key_signature` using `old_verifying_key.verify_strict(&canonical_bytes)`.
  8. Verify `rotation.new_key_pop_signature` using `new_verifying_key.verify_strict(&canonical_bytes)`.
- **Authorization Requirements:** Dual `verify_strict` signatures over the identical `KeyRotationPayload` (`old_key_id` + `new_key_id`).
- **State Transitions:** Atomically sets `old_key_id` status to `KeyLifecycleStatus::Retired { superseded_by: new_key_id, retired_at_sequence: next_seq, retired_at_epoch_secs: now_epoch_secs }`, inserts `new_key_id` as `KeyLifecycleStatus::Active`, updates `active_key_id = Some(new_key_id)`, appends `rotation` to rotation history, and increments `registry_sequence`.
- **Failure Behavior:** Fails closed without mutating key status or `registry_sequence`.
- **Audit Behavior:** Emits `KeyRotation` on success; emits `SecurityFailureObserved` (`InvalidRotation`, `RevokedCredential`, `InvalidSignature`) on failure.
- **Atomicity Requirements:** Old-key retirement, new-key activation, and sequence increment occur in a single infallible in-memory commit step after all validations succeed.
- **Relevant Tests:** `T-ROT-001` through `T-ROT-004`.

### 4.6 Operation 6 — Key and Agent Revocation (`revoke_key` & `revoke_agent_cryptographic`)
- **Preconditions:** Target `agent_id` and `key_id` exist in `CryptographicIdentityRegistry`.
- **Inputs:** `revocation: &KeyRevocationRecord`, `now_epoch_secs: u64`.
- **Validation Sequence:**
  1. Check `self.registry_sequence.checked_add(1)` and verify `revocation.payload.expected_registry_sequence == self.registry_sequence + 1`.
  2. Verify `agent_id` and `key_id` exist and `key_id` belongs to `agent_id`.
  3. Reject if `key_id` is already `Revoked` (`AlreadyRevoked`).
  4. Verify authorization signature on `revocation` (`DMC-CANON-V1`, `message_type = 0x05`):
     - Either signed by the pinned `ActiveEnrollmentAndRecovery` / `EmergencyRecoveryOnly` Founder Root Anchor, **or** self-revoked by the currently `Active` key being revoked (an already-revoked or retired key can never sign a revocation).
- **Authorization Requirements:** Valid `verify_strict` signature by Founder Root Anchor or by the currently `Active` `key_id` being revoked.
- **State Transitions:** Marks `key_id` as `KeyLifecycleStatus::Revoked`, clears `active_key_id` if `key_id` was active (or marks entire `agent_id` revoked if `revoke_entire_agent == true`), records `KeyRevocationRecord`, and increments `registry_sequence`.
- **Failure Behavior:** Fails closed without mutating state.
- **Audit Behavior:** Emits `KeyRevocation` on success; emits `SecurityFailureObserved` on failure.
- **Atomicity Requirements:** Single atomic state mutation after signature verification.
- **Relevant Tests:** `T-REV-001` through `T-REV-005`.

### 4.7 Operation 7 — Founder-Authorized Credential Recovery (`recover_agent_keys`)
- **Preconditions:** `agent_id` is enrolled and not permanently terminated; replacement keypair generated.
- **Inputs:** `recovery: &RecoveryRecord`, `now_epoch_secs: u64`.
- **Validation Sequence:**
  1. Check `self.registry_sequence.checked_add(1)` and verify `recovery.payload.expected_registry_sequence == self.registry_sequence + 1`.
  2. Verify `agent_id` exists and is not permanently revoked.
  3. Verify `recovery.payload.new_key_id` is globally unused and `new_public_key` is a valid, non-weak Ed25519 key distinct from all historical keys of `agent_id`.
  4. Enforce `M2` threshold rule: if `recovery.payload.required_threshold != 1` or `recovery.root_approvals.len() != 1`, reject with `CryptoIdentityError::ThresholdRecoveryNotYetOperational`.
  5. Look up `recovery.root_approvals[0].root_anchor_id` in `self.root_anchors`; verify it is pinned and active (`ActiveEnrollmentAndRecovery` or `EmergencyRecoveryOnly`).
  6. Encode `recovery.payload` via `DMC-CANON-V1` (`message_type = 0x06`).
  7. Verify `recovery.root_approvals[0].signature` using `root_verifying_key.verify_strict(&canonical_bytes)`.
  8. Verify `recovery.new_key_pop_signature` using `new_verifying_key.verify_strict(&canonical_bytes)`.
- **Authorization Requirements:** Founder Root Trust Anchor signature (`1-of-1` in M2) **plus** replacement key proof-of-possession signature. Routine agent keys are strictly rejected.
- **State Transitions:** Atomically transitions all previously `Active` keys of `agent_id` to `KeyLifecycleStatus::Revoked { reason_code: SupersededByRecovery, ... }`, inserts `new_key_id` as `Active`, preserves all prior key records in `historical_keys`, appends `RecoveryRecord`, and increments `registry_sequence`.
- **Failure Behavior:** Fails closed; no keys are modified and `registry_sequence` is unchanged.
- **Audit Behavior:** Emits `CredentialRecovery` on success; emits `SecurityFailureObserved` (`UnauthorizedRecovery`, `RootTrustFailure`, `InvalidSignature`) on failure.
- **Atomicity Requirements:** Quarantine of old keys, activation of `new_key_id`, and sequence increment happen atomically.
- **Relevant Tests:** `T-REC-001` through `T-REC-004`.

### 4.8 Operation 8 — Strict Cryptographic Live-Provenance Policy Evaluation (`policy_evaluate_strict_cryptographic_provenance`)
- **Preconditions:** Caller holds an `AuthorizedPolicyRequest` whose `identity` was minted by `CryptographicIdentityRegistry::authenticate_claim`, plus live references to `CryptographicIdentityRegistry` and `ProvenanceTracker`.
- **Inputs:** `request: &AuthorizedPolicyRequest`, `registry: &CryptographicIdentityRegistry`, `tracker: &ProvenanceTracker`.
- **Validation Sequence:**
  1. Validate `request.policy_version` is non-empty and `validate_canonical_resource_uri(&request.resource)` succeeds.
  2. Require `identity = request.identity.as_ref()` and `process = request.process.as_ref()`.
  3. Re-validate `identity` live against `registry` (`registry.verify_live_cryptographic_identity(identity, request.evaluation_epoch_secs)`):
     - Verify `identity.registry_instance_id() == registry.instance_id()`.
     - Verify `identity.trust_status() == IdentityTrustStatus::CryptographicallyVerified`.
     - Verify `identity.registry_sequence_at_resolution() <= Some(registry.registry_sequence())` and `registry.registry_sequence() >= registry.min_acceptable_sequence()`.
     - Verify `identity.authenticated_key_id()` is still the currently `Active`, unrevoked, unexpired key for `identity.agent_id()` in `registry`.
  4. Verify complete process lineage and multi-hop delegation ancestry in `tracker` (`tracker.verify_live_cryptographic_process_and_delegation_lineage`), verifying that **every** ancestor process's `parent_agent_id` and **every** delegation's `issuer` and `recipient` in the chain is registered, active, unrevoked, and has an active cryptographic key in `registry`.
  5. Verify action and resource scope constraints against agent autonomy, process effective autonomy, process permitted actions, process resource scope, and (if delegated) delegation permitted actions and resource scope.
  6. Mint private `CryptographicLiveProvenanceSeal` and return `PolicyResult` with `Decision::Allow`, `trust_level = PolicyTrustLevel::CryptographicLiveProvenanceVerified`, and `execution_authorized() == true`.
- **Authorization Requirements:** Live cryptographic identity + live unrevoked key + live acyclic process provenance + live multi-hop delegation ancestry + policy rule satisfaction.
- **State Transitions:** Pure evaluation; mutates no registry or tracker state.
- **Failure Behavior:** Fails closed on any error, returning `PolicyResult` with `Decision::Deny` and `execution_authorized() == false`.
- **Audit Behavior:** `audit_required` is always `true`; caller records decision via `InMemoryAuditSequencer::record_authorized_decision`.
- **Atomicity Requirements:** Stateless deterministic evaluation.
- **Relevant Tests:** `T-REV-004`, `T-REV-005`, `T-ADV-001` through `T-ADV-003`.

---

## 5. Specification Blockers and Pre-Implementation Provisioning Status

### 5.1 `BLOCKER-M2-001` — **RESOLVED** (by Founder Directive `DMC-M2-DEC-002`)
- **Resolution:** Founder Directive `DMC-M2-DEC-002` selected **Option 2**: dedicated `scrypt` (`kdf_id = 0x01`, baseline `log_n = 15, r = 8, p = 1`) + `ChaCha20-Poly1305` (`aead_id = 0x01`, 256-bit key, 96-bit nonce, 128-bit Poly1305 tag) + `zeroize` for `DMC-DEV-KEYSTORE-V1`, and prohibited custom Encrypt-then-HMAC constructions. All technical requirements are normatively specified in Sections 2.3 and 4.2 and in [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md#L165-L240).
- **Remaining Specification Blockers:** **NONE (`0`).** The `M2` specification is 100% architecturally complete.

### 5.2 `PROV-M2-001` — Pre-Implementation Cargo Cache Provisioning Requirement (`chacha20poly1305`)
While the specification is complete and unblocked, read-only inspection of the local Termux Cargo cache (`/data/data/com.termux/files/home/.cargo/registry/`) establishes the following distinction between **specification resolution** and **offline implementation readiness**:
- **Present in Local Termux Cargo Cache:**
  - `scrypt-0.10.0` (with `default-features = false`) and **100% of its transitive dependencies**: `hmac-0.12.1`, `pbkdf2-0.11.0`, `salsa20-0.10.2`, `sha2-0.10.9`, `cipher-0.4.4`, `digest-0.10.7`, `inout-0.1.4`, `crypto-common-0.1.6`, `block-buffer-0.10.4`, `generic-array-0.14.7`, `typenum-1.20.0`, `cpufeatures-0.2.17`, `cfg-if-1.0.4`.
  - `zeroize-1.8.2` / `zeroize-1.9.1` and `zeroize_derive-1.5.0`.
  - `ed25519-dalek-2.2.0`, `curve25519-dalek-4.1.3`, `ed25519-2.2.3`, `signature-2.2.0`, `subtle-2.6.1`, `getrandom-0.2.17`, `rand_core-0.6.4`.
- **Not Present in Local Termux Cargo Cache (Requires Provisioning When Phase `M2.1` Is Authorized):**
  - `chacha20poly1305 = "=0.10.1"` and its transitive RustCrypto AEAD dependencies (`aead = "=0.5.2"`, `chacha20 = "=0.9.1"`, `poly1305 = "=0.8.0"`, `universal-hash = "=0.5.1"`, `opaque-debug = "=0.3.1"`). *(Note: `chacha20-0.10.2` in the cache targets the newer `cipher 0.5` interface rather than `chacha20poly1305 0.10.1`.)*
- **Required Provisioning Action (Only When Implementation Is Authorized):** Run `cargo fetch` with network access enabled (or vendor the 6 crates above into `~/.cargo/registry/`) during Phase `M2.0`/`M2.1` setup. Per `DMC-M2-DEC-002`, no alternative cipher construction may be substituted without Founder approval.

---

## 6. M2 Implementation Sequence (Unauthorized Pending Separate Directive)

| Phase | Scope | Prerequisite |
|---|---|---|
| **M2.0** | Threat model lock and Cargo cache provisioning of `chacha20poly1305 =0.10.1` (`PROV-M2-001`) | Separate Founder implementation authorization |
| **M2.1** | `DMC-CANON-V1` codec in `dmc-types`; `DevSigningKey`, `PublicKeyRecord`, and `DMC-DEV-KEYSTORE-V1` (`scrypt` + `ChaCha20-Poly1305`) in `titan-identity` | `M2.0` review approval |
| **M2.2** | `RootTrustAnchorSet` and Founder-authorized `IdentityRegistration` enrollment | `M2.1` review approval |
| **M2.3** | `ReplayTracker`, `AuthChallengePayload`, and `SignedIdentityClaim` verification | `M2.2` review approval |
| **M2.4** | Immediate-cutover `KeyRotationRecord` and fail-closed `KeyRevocationRecord` | `M2.3` review approval |
| **M2.5** | `1-of-1` Founder-authorized `RecoveryRecord` and monotonic `registry_sequence` rollback guards | `M2.4` review approval |
| **M2.6** | `policy_evaluate_strict_cryptographic_provenance`, `titan-audit` observability integration, and full adversarial test suite | `M2.5` review approval |
