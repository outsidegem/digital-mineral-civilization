# DMC M2 — Final Independent Security & Architecture Specification Audit (`DMC-M2-FINAL-SECURITY-AUDIT`)

- **Audit Authorization IDs:** `DMC-M2-AUDIT-003`, `DMC-M2-AUDIT-004` (Final Audit Correction & `scrypt` Resource-Limit Reconciliation)
- **Audited Specification Package:** `DMC-M2-SPEC-001 v1.0 (Rev B)` and 6 companion specification documents in [docs/m2/](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2)
- **Preceding Directives:** `DMC-M2-AUTH-001`, `DMC-M2-DEC-002` (Resolution of `BLOCKER-M2-001`)
- **Audit Scope:** Independent read-only security and architectural audit against the frozen M1.1 source code and cached `scrypt-0.10.0` implementation
- **Implementation Authorization Status:** **NOT GRANTED** (Specification Audit Only)

---

## 1. Executive Verdict

**Verdict:** **`APPROVED FOR FOUNDER IMPLEMENTATION AUTHORIZATION`** *(Following in-audit resolution of `FINDING-M2-AUD-001`, `FINDING-M2-AUD-002`, and `FINDING-M2-AUD-004`; subject to `PROV-M2-001` Cargo cache provisioning during Phase `M2.0` and runtime test execution once implementation is authorized).*

### Executive Summary
An independent line-by-line security and architectural audit was conducted across all seven M2 specification documents in [docs/m2/](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2), cross-verified against the four frozen M1.1 Rust crates ([core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs), [core/titan-identity/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/src/lib.rs), [core/titan-policy-core/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/src/lib.rs), and [core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs)) and the locally cached `scrypt-0.10.0` crate source ([scrypt-0.10.0/src/lib.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/lib.rs)).

- **Critical Findings:** `0`
- **High-Severity Findings:** `1` (`FINDING-M2-AUD-004` — Inconsistent `scrypt` upper parameter bounds `log_n: 15..=17, r: 8..=16, p: 1..=4` permitting `256 MiB` primary memory against a declared `128 MiB` ceiling and omitting buffer `T` (`128 * r`); **resolved across all 6 documents under `DMC-M2-AUDIT-004`**).
- **Medium-Severity Findings:** `1` (`FINDING-M2-AUD-001` — Stale minimum keystore byte constant `143` vs. canonical `183` bytes; **resolved across all documents**).
- **Low-Severity Findings:** `2` (`FINDING-M2-AUD-002` — Omitted explicit struct/method declarations in interface reference; **resolved**; `FINDING-M2-AUD-003` / `PROV-M2-001` — Offline Cargo cache provisioning required for `chacha20poly1305 = "=0.10.1"` when Phase `M2.0` is authorized).

---

## 2. Critical Findings

**None (`0`).** No critical architectural or cryptographic vulnerabilities were identified.

---

## 3. High-Severity Findings

### `FINDING-M2-AUD-004` — `scrypt` Parameter-Bound & `128 MiB` Heap-Ceiling Inconsistency (`DMC-M2-AUDIT-004`)
- **Severity:** High (Resource-limit / DoS specification consistency)
- **Status:** **RESOLVED IN THIS AUDIT (`DMC-M2-AUDIT-004`)**
- **Affected Documents (Reconciled):**
  - [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L76-L115) (Section 2.3.2–2.3.3, Section 4.2)
  - [DMC-M2-INTERFACE-REFERENCE.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-INTERFACE-REFERENCE.md#L519-L579) (Section 3.3)
  - [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md#L199-L221) (Section 4, Section 4.1)
  - [DMC-M2-SECURITY-TEST-PLAN.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SECURITY-TEST-PLAN.md#L58-L70) (`T-KS-005`, `T-KS-013`..`017`)
  - [DMC-M2-ACCEPTANCE-CRITERIA.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-ACCEPTANCE-CRITERIA.md#L26-L38) (`AC-11`, Invariant 3)
- **Root Cause Analysis:**
  1. **Joint `(log_n = 17, r = 16)` Exceeded `128 MiB` by $2\times$:** The prior draft declared `log_n: 15..=17`, `r: 8..=16`, `p: 1..=4` alongside `MAX_KDF_MEMORY_BYTES = 134,217,728` (`128 MiB`). At `(log_n = 17, r = 16)`, primary ROMix memory $|V| = 128 \times 16 \times 2^{17} = 268,435,456\text{ B}$ (`256 MiB`), double the `128 MiB` ceiling.
  2. **Omission of Buffer `T` (`128 * r`) & Unreachability of `log_n = 17` and `(log_n = 16, r = 16)`:** Direct inspection of [scrypt-0.10.0/src/lib.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/lib.rs#L104-L114) proves that `scrypt::scrypt` simultaneously allocates `b` ($128 \cdot r \cdot p$), `v` ($128 \cdot r \cdot 2^{\text{log\_n}}$), and `t` ($128 \cdot r$), for an exact heap total of $128 \cdot r \cdot (2^{\text{log\_n}} + p + 1)$. At `log_n = 17, r = 8, p = 1`, $|V|$ alone is `134,217,728` bytes (`128 MiB`), so adding $|B| + |T| = 2,048$ bytes produces `134,219,776` bytes ($> 128\text{ MiB}$). Similarly, `(log_n = 16, r = 16, p = 1)` requires `134,221,824` bytes ($> 128\text{ MiB}$).
  3. **Unbounded CPU Multiplication via `p = 4`:** Allowing `p = 4` at elevated `log_n` and `r` permitted up to $32\times$ baseline single-threaded CPU execution time.
- **Resolution Applied:** Preserved the `128 MiB` (`134,217,728`-byte) hard ceiling on exact total heap memory $128 \cdot r \cdot (2^{\text{log\_n}} + p + 1)$, derived tight parameter bounds (`15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`), added an explicit CPU work-factor cap (`2^log_n * r * p <= 1,966,080`), retained the baseline `(15, 8, 1)`, and added security tests `T-KS-013` through `T-KS-017` (see Section 7.2 for full mathematical proof).

---

## 4. Medium-Severity Findings

### `FINDING-M2-AUD-001` — Minimum Keystore File Size Constant Discrepancy (`143` vs. `183` Bytes)
- **Severity:** Medium (Pre-KDF file-size boundary check accuracy)
- **Status:** **RESOLVED IN THIS AUDIT**
- **Location:** [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md#L191-L216), [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L97), and [DMC-M2-INTERFACE-REFERENCE.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-INTERFACE-REFERENCE.md#L513)
- **Technical Analysis & Resolution:** Fixed AAD fields (`133` bytes) + minimum identifier bytes ($L_1 = 1, L_2 = 1$) + `encrypted_seed` (`32` bytes) + `poly1305_tag` (`16` bytes) $= 183$ bytes (`MIN_KEYSTORE_FILE_BYTES`). Reconciled `143` $\to$ `183` across all specification files.

---

## 5. Low-Severity Findings

### `FINDING-M2-AUD-002` — Omitted Explicit Struct and Lineage Method Signatures in Interface Reference
- **Severity:** Low (Interface reference completeness)
- **Status:** **RESOLVED IN THIS AUDIT**
- **Location:** [DMC-M2-INTERFACE-REFERENCE.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-INTERFACE-REFERENCE.md#L444-L458) (`L444-L458` and `L725-L742`)
- **Resolution:** Added explicit Rust signatures for `ProvenanceTracker::verify_live_cryptographic_process_and_delegation_lineage` and `pub struct CryptographicAgentEntry`.

### `FINDING-M2-AUD-003` (`PROV-M2-001`) — Offline Cargo Cache Provisioning Required for `chacha20poly1305`
- **Severity:** Low (Pre-implementation build environment readiness)
- **Status:** **DOCUMENTED & GATED AT PHASE `M2.0` (`CONDITIONAL PASS` / `NOT VERIFIED` OFFLINE)**
- **Location:** [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L407-L416) and [DMC-M2-CHANGE-CONTROL-REPORT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CHANGE-CONTROL-REPORT.md#L48-L61)
- **Technical Analysis:** 6 of the 7 approved crates (`ed25519-dalek`, `getrandom`, `rand_core`, `zeroize`, `sha2`, `scrypt`) and 100% of their transitive dependencies are cached in `/data/data/com.termux/files/home/.cargo/registry/`. `chacha20poly1305 = "=0.10.1"` (`aead-0.5.2`, `chacha20-0.9.1`, `poly1305-0.8.0`, `universal-hash-0.5.1`, `opaque-debug-0.3.1`) must be provisioned via `cargo fetch` during Phase `M2.0` once implementation is authorized.

---

## 6. Cryptographic Correctness Review (Audit Area A)

| Check ID | Audit Area & Requirement | Classification | Independent Technical Verification & Evidence |
|---|---|---|---|
| **A-01** | **`DMC-CANON-V1` Deterministic Framing** | **`PASS`** | [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md#L12-L162) defines an injective binary framing (`b"DMC-SIG-V1\0"` + `protocol_version = 1` + `schema_version = 1` + `message_type` `0x01..=0x06` + `algorithm_id = 0x01`), explicit big-endian lengths, and trailing-byte rejection. |
| **A-02** | **Ed25519 Strict Verification & Weak-Key Rejection** | **`PASS`** | Mandates `ed25519_dalek::VerifyingKey::verify_strict` and `!verifying_key.is_weak()` across all 6 signed message types and keystore load ([DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L194)). |
| **A-03** | **Key Generation & Custody Separation** | **`PASS`** | 32-byte Ed25519 seeds are generated from OS CSPRNG (`getrandom`) with all-zero rejection and labeled `LocalDevelopmentOnly` ([DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L74)). |
| **A-04** | **Founder Root Trust Anchor Separation** | **`PASS`** | Enforces distinct `ActiveEnrollmentAndRecovery` and `EmergencyRecoveryOnly` Founder Root public keys with offline root private key custody ([DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L48-L65)). |
| **A-05** | **`scrypt` Configuration & Reconciled Bounds (`DMC-M2-AUDIT-004`)** | **`PASS`** | Baseline `log_n = 15, r = 8, p = 1` (`33,556,480` B total heap) and reconciled bounds `15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, `total_heap_bytes <= 134,217,728` (`128 MiB`), and `work_factor <= 1,966,080` are verified against [scrypt-0.10.0/src/lib.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/lib.rs#L104-L117). |
| **A-06** | **`ChaCha20-Poly1305` Envelope Construction** | **`PASS`** | RFC 8439 IETF `ChaCha20-Poly1305` with 256-bit `scrypt`-derived `KEK`, 96-bit CSPRNG nonce, 15-field AAD, 32-byte encrypted seed, and 16-byte Poly1305 tag ([DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md#L187-L225)). |
| **A-07** | **Cryptographic Key Separation (`KEK` vs. Signing Seed)** | **`PASS`** | The `scrypt`-derived 32-byte `KEK` is used exclusively as the `ChaCha20-Poly1305` key and is never mixed into Ed25519 signing material. |
| **A-08** | **Memory Zeroization & Redaction** | **`PASS`** | `SecretPassphrase(Zeroizing<Vec<u8>>)`, `Zeroizing<[u8; 32]>` `KEK`/seed buffers, and `DevSigningKey` (`Drop` zeroization + redacted `Debug`/`Display`) prevent secret leakage. |
| **A-09** | **Password Handling & Validation** | **`PASS`** | Passphrases must be `12..=256` bytes and non-whitespace (`InvalidPassphraseLength`), checked before KDF execution. |
| **A-10** | **Runtime Execution of M2 Cryptographic Test Vectors** | **`NOT VERIFIED`** | M2 implementation is not yet authorized; runtime execution of `T-VEC-001`..`004` and `T-KS-001`..`017` is an explicit implementation-time verification requirement. |

---

## 7. Keystore Architecture & `scrypt-0.10.0` Resource Model Review (Audit Area B)

### 7.1 Summary Matrix

| Check ID | Keystore Security Requirement | Classification | Verification Detail |
|---|---|---|---|
| **B-01** | **Exact `scrypt-0.10.0` Memory & CPU Calculations (`DMC-M2-AUDIT-004`)** | **`PASS`** | Verified directly against [scrypt-0.10.0/src/lib.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/lib.rs#L104-L117) (see Section 7.2). |
| **B-02** | **Pre-KDF Resource Limits & Malicious Parameter Rejection** | **`PASS`** | Enforces `183 <= file_len <= 1024`, `15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, checked `128 * r * ((1 << log_n) + p + 1) <= 134,217,728` (`128 MiB`), checked `(1 << log_n) * r * p <= 1,966,080`, and `MAX_CONCURRENT_KDF_JOBS = 1` **before** allocating any KDF buffers (`T-KS-005`, `T-KS-013`..`017`). |
| **B-03** | **96-Bit `ChaCha20-Poly1305` AEAD Nonce Uniqueness Strategy** | **`PASS`** | Verified safe under per-write CSPRNG salt + nonce generation (see Section 7.3). |
| **B-04** | **Envelope Field Offsets, Lengths & Total Size Bounds** | **`PASS`** | Verified byte-for-byte (`MIN_KEYSTORE_FILE_BYTES = 183`, maximum valid envelope $= 437\text{ B} \le 1024\text{ B}$). |
| **B-05** | **AAD Construction & Tamper Detection** | **`PASS`** | All 15 header/identity fields (`envelope_bytes[0..N]`) are authenticated by the 128-bit Poly1305 tag (`T-KS-004`), plus post-decryption public-key correspondence check (`T-KS-009`). |
| **B-06** | **Uniform Error Behavior & No Plaintext Fallback** | **`PASS`** | Wrong passphrase and tampered ciphertext/AAD return uniform `KeystoreError::AuthenticationFailed` after constant-time tag check and zeroization (`T-KS-003`, `T-KS-012`). |

### 7.2 Independent Verification of Rust `scrypt = "=0.10.0"` Resource Model (`DMC-M2-AUDIT-004`)

1. **Evidence from Locally Cached `scrypt-0.10.0` Source Code:**
   Inspection of [scrypt-0.10.0/src/lib.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/lib.rs#L104-L117) (lines 104–117) and [scrypt-0.10.0/src/romix.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/romix.rs#L7-L31) (lines 7–31) confirms the exact allocations performed by `scrypt::scrypt`:
   - `let n = 1 << params.log_n;` ($N = 2^{\text{log\_n}}$)
   - `let r128 = (params.r as usize) * 128;`
   - `let mut b = vec![0u8; (params.p as usize) * r128];` $\implies |B| = 128 \cdot r \cdot p\text{ bytes}$
   - `let mut v = vec![0u8; n * r128];` $\implies |V| = 128 \cdot r \cdot 2^{\text{log\_n}}\text{ bytes}$
   - `let mut t = vec![0u8; r128];` $\implies |T| = 128 \cdot r\text{ bytes}$
   - `for chunk in &mut b.chunks_mut(r128) { romix::scrypt_ro_mix(chunk, &mut v, &mut t, n); }` (plus `192` bytes of fixed stack arrays in `scrypt_block_mix`).

2. **Exact Simultaneous Heap Memory Formula:**
   $$\text{total\_heap\_bytes}(\text{log\_n}, r, p) = |V| + |B| + |T| = 128 \cdot r \cdot 2^{\text{log\_n}} + 128 \cdot r \cdot p + 128 \cdot r = 128 \cdot r \cdot \left(2^{\text{log\_n}} + p + 1\right)$$

3. **How `p` Affects Memory and CPU Cost:**
   - **Memory Effect of `p`:** Because `scrypt-0.10.0` runs the `p` ROMix chunks **sequentially** in a single thread reusing `v` and `t`, `p` does **not** multiply the primary $128 \cdot r \cdot 2^{\text{log\_n}}$ ROMix vector `v`, **but `p` linearly increases the `b` buffer heap allocation by $128 \cdot r \cdot p$ bytes**.
   - **CPU Cost Effect of `p`:** Each of the `p` loop iterations calls `scrypt_ro_mix`, which executes $2N$ `scrypt_block_mix` calls ($4 \cdot 2^{\text{log\_n}} \cdot r$ `Salsa20/8` 64-byte core rounds). Thus **`p` scales single-threaded CPU cost linearly**:
     $$\text{work\_factor}(\text{log\_n}, r, p) = 2^{\text{log\_n}} \cdot r \cdot p$$

4. **Derivation of Corrected Parameter Bounds from the `128 MiB` (`134,217,728` Bytes) Ceiling:**
   Enforcing $\text{total\_heap\_bytes}(\text{log\_n}, r, p) \le 134,217,728$ ($2^{27}$) is equivalent to:
   $$r \cdot \left(2^{\text{log\_n}} + p + 1\right) \le 1,048,576 \quad (2^{20})$$
   - **Why `MAX_SCRYPT_LOG_N` is Reduced from `17` to `16`:** For $\text{log\_n} = 17$ ($2^{17} = 131,072$) and $r \ge 8, p \ge 1$, $r \cdot (131,072 + p + 1) \ge 8 \times 131,074 = 1,048,592 > 1,048,576$ (`134,219,776` bytes $> 128\text{ MiB}$). Thus `log_n = 17` always exceeds the `128 MiB` total heap ceiling for all $r \ge 8, p \ge 1$. Setting `MAX_SCRYPT_LOG_N = 16` ($N = 65,536$) eliminates this contradiction.
   - **Why `MAX_SCRYPT_R` is Reduced from `16` to `15`:** At $\text{log\_n} = 16$ ($2^{16} = 65,536$) and $p \ge 1$, $\lfloor 1,048,576 / (65,536 + p + 1) \rfloor = 15$. At $r = 16$, $|V|$ alone is $134,217,728$ bytes (`128 MiB`), so adding $|B| + |T| = 2,048(p + 1) \ge 4,096$ bytes yields $134,221,824\text{ bytes} > 128\text{ MiB}$. Setting `MAX_SCRYPT_R = 15` ensures every `(log_n, r, p)` tuple within the allowed bounds satisfies $\text{total\_heap\_bytes} \le 128\text{ MiB}$. *(Note: In RFC 7914 and [scrypt-0.10.0/src/params.rs](file:///data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scrypt-0.10.0/src/params.rs#L34-L70), `r` is any positive integer; only $N = 2^{\text{log\_n}}$ is required to be a power of 2.)*
   - **Why `MAX_SCRYPT_P` is Reduced from `4` to `2` with `MAX_KDF_WORK_FACTOR = 1,966,080`:** Caps worst-case sequential CPU cost at $2^{16} \times 15 \times 2 = 1,966,080$ ($7.5\times$ baseline) instead of $32\times$ baseline.

5. **Summary of Key Configurations & Exact Resource Consumption:**

| Configuration Role | `(log_n, r, p)` | Primary `|V|` (Bytes) | Aux `|B| + |T|` (Bytes) | Total Heap `|V| + |B| + |T|` (Bytes) | CPU `work_factor` ($2^{\text{log\_n}} \cdot r \cdot p$) | Policy Outcome |
|---|---|---|---|---|---|---|
| **Selected Baseline (Retained)** | `(15, 8, 1)` | `33,554,432` (`32 MiB`) | `1,024 + 1,024 = 2,048` | **`33,556,480`** ($\approx 32.002\text{ MiB}$) | `262,144` ($1.0\times$) | **ACCEPTED** (`T-KS-001`) |
| **Max Accepted (Standard `r = 8`)** | `(16, 8, 2)` | `67,108,864` (`64 MiB`) | `2,048 + 1,024 = 3,072` | **`67,111,936`** ($\approx 64.003\text{ MiB}$) | `1,048,576` ($4.0\times$) | **ACCEPTED** (`T-KS-013`) |
| **Maximum Accepted Configuration** | `(16, 15, 2)` | `125,829,120` (`120 MiB`) | `3,840 + 1,920 = 5,760` | **`125,834,880`** ($\approx 120.005\text{ MiB}$) | `1,966,080` ($7.5\times$) | **ACCEPTED** (`T-KS-013`) |
| **First Rejected Above `128 MiB` (`log_n`)** | `(17, 8, 1)` | `134,217,728` (`128 MiB`) | `1,024 + 1,024 = 2,048` | **`134,219,776`** (`128 MiB + 2 KiB`) | `1,048,576` | **REJECTED PRE-KDF** (`T-KS-014`) |
| **First Rejected Above `128 MiB` (`r`)** | `(16, 16, 1)` | `134,217,728` (`128 MiB`) | `2,048 + 2,048 = 4,096` | **`134,221,824`** (`128 MiB + 4 KiB`) | `1,048,576` | **REJECTED PRE-KDF** (`T-KS-014`) |
| **Excessive CPU Cost (Memory `< 128 MiB`)** | `(16, 8, 16)` | `67,108,864` (`64 MiB`) | `16,384 + 1,024 = 17,408` | **`67,126,272`** ($\approx 64.017\text{ MiB}$) | `8,388,608` ($32.0\times$) | **REJECTED PRE-KDF** (`T-KS-017`) |
| **Prior Inconsistent Corner (`256 MiB`)** | `(17, 16, 4)` | `268,435,456` (`256 MiB`) | `8,192 + 2,048 = 10,240` | **`268,445,696`** ($\approx 256.010\text{ MiB}$) | `8,388,608` ($32.0\times$) | **REJECTED PRE-KDF** (`T-KS-016`) |

### 7.3 Dedicated Analysis of the 96-Bit `ChaCha20-Poly1305` Nonce Strategy
Every `DevKeystore::save_key` operation generates both a fresh 256-bit CSPRNG `kdf_salt` (deriving an independent `KEK` via `scrypt` so each `KEK` encrypts $q = 1$ seed) and a fresh 96-bit CSPRNG `aead_nonce`, bounding `(KEK, nonce)` collision probability across $k$ saves under the same passphrase by $\le k(k-1)/2^{353}$ (and $< 10^{-18}$ across $2^{18}$ saves even under hypothetical salt reuse).

---

## 8. Interface, Lifecycle, and Frozen M1.1 Compatibility Review (Audit Areas C, D, E, F)

| Frozen M1.1 Source File / Area | Verification Summary | Classification |
|---|---|---|
| [core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs#L1-L598) | Zero external dependencies preserved (`[dependencies]` empty); `IdentityTrustStatus::CryptographicallyVerified` is additive; all 3 unit tests preserved. | **`PASS`** |
| [core/titan-identity/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/src/lib.rs#L1-L781) | Private fields on `ResolvedAgentIdentity`, `LiveProvenanceVerificationSeal`, and `CryptographicLiveProvenanceSeal` prevent external forgery; all 5 unit tests preserved. | **`PASS`** |
| [core/titan-policy-core/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/src/lib.rs#L1-L484) | `policy_evaluate_strict_cryptographic_provenance` enforces live identity, key non-revocation, acyclic process lineage, and multi-hop delegation ancestry (`T-REV-004`, `T-REV-005`, `T-ADV-001`..`003`); all 8 unit tests preserved. | **`PASS`** |
| [core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs#L1-L364) | Checked monotonic sequencing (`checked_add(1)`), canonical URI validation, and fail-closed audit observability across all 8 `SecurityFailureCode` categories (`T-ADV-004`); all 4 unit tests preserved. | **`PASS`** |
| **Lifecycle & Boundary Truthfulness (`C-01`..`C-06`, `E-01`, `F-01`)** | Enrollment, 5-minute monotonic/epoch challenge replay protection (`10,000` cap), zero-overlap rotation, fail-closed revocation, `1-of-1` root recovery (`required_threshold > 1` rejected), and M2/M3 boundary truthfulness verified. | **`PASS`** (`F-01`: **`CONDITIONAL PASS`** on `PROV-M2-001`) |

---

## 9. Required Specification Corrections (Completed During Audit)

1. **`FINDING-M2-AUD-004` (`DMC-M2-AUDIT-004` — `scrypt` Resource Limits & Parameter Bounds):** Reconciled `15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, exact `scrypt-0.10.0` heap formula `128 * r * ((1 << log_n) + p + 1) <= 134,217,728` (`128 MiB`), CPU work-factor cap `(1 << log_n) * r * p <= 1,966,080`, and tests `T-KS-013`..`017` across [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md), [DMC-M2-INTERFACE-REFERENCE.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-INTERFACE-REFERENCE.md), [DMC-M2-CANONICAL-WIRE-FORMAT.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-CANONICAL-WIRE-FORMAT.md), [DMC-M2-SECURITY-TEST-PLAN.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SECURITY-TEST-PLAN.md), and [DMC-M2-ACCEPTANCE-CRITERIA.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-ACCEPTANCE-CRITERIA.md).
2. **`FINDING-M2-AUD-001` (`MIN_KEYSTORE_FILE_BYTES = 183`):** Reconciled `143` $\to$ `183` across all specification documents.
3. **`FINDING-M2-AUD-002` (Interface Completeness):** Added `CryptographicAgentEntry` and `ProvenanceTracker::verify_live_cryptographic_process_and_delegation_lineage` declarations to [DMC-M2-INTERFACE-REFERENCE.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-INTERFACE-REFERENCE.md).

**Remaining Open Specification Corrections:** **NONE (`0`).**

---

## 10. Final Implementation-Readiness Determination & Implementation-Time Verification Requirements

1. **Specification Readiness:** **READY (`100%`).** All specification documents are mathematically and architecturally consistent.
2. **Mandatory Implementation-Time Verification Requirements (When Authorized):**
   - **Phase `M2.0` (`PROV-M2-001`):** Provision `chacha20poly1305 = "=0.10.1"` and its 5 transitive RustCrypto AEAD dependencies into the local Termux Cargo cache.
   - **Phase `M2.1` (`T-VEC-001`..`004`, `T-KS-001`..`017`):** Execute runtime unit tests verifying `ScryptParamsConfig::new_checked` on the maximum accepted configuration `(16, 15, 2)` (`125,834,880` B), first rejected configurations `(16, 16, 1)` (`134,221,824` B) and `(17, 8, 1)` (`134,219,776` B), integer overflow inputs (`T-KS-015`), pre-KDF rejection timing/zero-allocation (`T-KS-016`), and excessive CPU-cost rejection (`T-KS-017`).

**Final Audit Verdict:** **`APPROVED FOR FOUNDER IMPLEMENTATION AUTHORIZATION`**
