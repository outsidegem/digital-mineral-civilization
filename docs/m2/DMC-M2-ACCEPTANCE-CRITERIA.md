# DMC M2 — Acceptance Criteria (`DMC-M2-ACCEPTANCE-CRITERIA`)

- **Parent Specification:** [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md)
- **Test Plan Reference:** [DMC-M2-SECURITY-TEST-PLAN.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SECURITY-TEST-PLAN.md)
- **Authorization IDs:** `DMC-M2-AUTH-001`, `DMC-M2-DEC-002`, `DMC-M2-AUDIT-004`
- **Implementation Status:** **NOT AUTHORIZED** (Acceptance Gate Definition Only)

---

## 1. Mandatory Measurable Completion Criteria

Milestone 2 (`M2`) **cannot** be accepted for completion or freeze unless every criterion below is demonstrably satisfied by automated tests and independent read-only review:

| # | Criterion | Verification Method & Required Test IDs |
|---|---|---|
| **AC-01** | **Valid Registered Credentials Authenticate:** Enrolled agents signing fresh `DMC-CANON-V1` challenges with their active Ed25519 key authenticate and produce a sealed `ResolvedAgentIdentity` (`IdentityTrustStatus::CryptographicallyVerified`). | `T-VEC-001`, `T-ENROLL-001`, `T-AUTH-001` |
| **AC-02** | **Unknown Credentials Rejected:** Unknown `AgentId`, unknown `KeyId`, or unpinned `RootAnchorId` fail closed before or during signature verification. | `T-SIG-002`, `T-ENROLL-002` |
| **AC-03** | **Modified & Non-Canonical Claims Rejected:** Single-bit flips in headers/payloads/signatures, non-canonical $S \ge L$ scalars, weak/small-order public keys, trailing bytes, and non-`DMC-CANON-V1` frames fail verification via `verify_strict`. | `T-SIG-001`, `T-SIG-003`, `T-SIG-004`, `T-SIG-005`, `T-WIRE-001`..`007` |
| **AC-04** | **Expired Claims & Challenges Rejected:** Claims or challenges exceeding the 5-minute (`300,000 ms`) wall-clock or monotonic elapsed-time window, or future-dated claims, fail verification. | `T-AUTH-004`, `T-AUTH-005`, `T-AUTH-006`, `T-AUTH-007` |
| **AC-05** | **Replayed & Restart-Stale Challenges Rejected:** Consumed challenges, saturated replay caches (`> 10,000` active), and challenges issued prior to a verifier restart fail closed. | `T-AUTH-002`, `T-AUTH-003`, `T-AUTH-008`, `T-AUTH-009` |
| **AC-06** | **Revoked Keys & Agents Fail Verification:** Revoked keys and revoked agents fail authentication, rotation, recovery, and live policy re-validation even when signatures are mathematically valid. | `T-REV-001`..`005` |
| **AC-07** | **Immediate-Cutover Key Rotation Preserves `AgentId`:** Key rotation requires dual signatures (`old_key_id` + `new_key_id` PoP), preserves `AgentId`, activates `new_key_id`, and immediately retires `old_key_id` with zero grace period. | `T-ROT-001`..`004` |
| **AC-08** | **Unauthorized Rotation & Recovery Rejected:** Compromised/revoked agent keys cannot self-recover; recovery requires `1-of-1` Founder Root Trust Anchor signature + `new_key_id` PoP and atomically revokes all prior keys of that `AgentId`. Requests with `required_threshold > 1` fail closed in `M2`. | `T-REC-001`..`004` |
| **AC-09** | **No Implicit Privilege Escalation:** Valid cryptographic authentication never independently grants execution authority (`execution_authorized() == false` without live process/delegation provenance and policy approval). | `T-ADV-001`, `T-ADV-002`, `T-ADV-003` |
| **AC-10** | **M1 and M1.1 Backward Compatibility:** All 20 existing `M1` and `M1.1` unit tests pass without modification or deletion. | `cargo test --workspace` (`>= 20` baseline + all M2 tests) |
| **AC-11** | **Secret Hygiene & `DMC-DEV-KEYSTORE-V1` (`scrypt` + `ChaCha20-Poly1305`):** Keystore enforces `0700`/`0600` permissions outside Git workspace, derives 256-bit wrapping keys via `scrypt` (`log_n = 15, r = 8, p = 1`) with fresh 32-byte CSPRNG salts, encrypts seeds via `ChaCha20-Poly1305` with fresh 12-byte CSPRNG nonces and 15-field AAD, enforces pre-KDF resource caps (`15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, `128 * r * ((1 << log_n) + p + 1) <= 128 MiB`, `(1 << log_n) * r * p <= 1,966,080`, `183 <= file_len <= 1024` bytes), zeroizes secret buffers, redacts `Debug`/`Display`, and never falls back to plaintext. | `T-VEC-004`, `T-KS-001`..`017` |
| **AC-12** | **Registry Instance, Overflow & Rollback Protection:** Foreign `registry_instance_id`, stale `registry_sequence < min_acceptable_sequence`, and `u64::MAX` sequence overflow fail closed without mutating state. | `T-REG-001`..`004` |
| **AC-13** | **Security Failure Observability:** All eight required failure categories emit structured `SecurityAuditRecord` entries sequenceable by `InMemoryAuditSequencer`, and audit failures never turn a rejected operation into an accepted one. | `T-ADV-004` + audit assertions across `T-SIG-*`, `T-AUTH-*`, `T-KS-*`, `T-REV-*`, `T-REC-*`, `T-REG-*` |
| **AC-14** | **Zero Warnings & Clean Workspace Quality Gates:** Formatting, Clippy (`-D warnings`), workspace unit/doc tests, and diff whitespace checks pass with zero errors or warnings. | Verification commands in Section 3 |

---

## 2. Non-Negotiable Security Invariants

1. **Zero Dependencies in `dmc-types`:** `[dependencies]` in [core/dmc-types/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/Cargo.toml) must remain empty.
2. **Dedicated AEAD + KDF Only (`DMC-M2-DEC-002`):** `DMC-DEV-KEYSTORE-V1` must use `scrypt` + `ChaCha20-Poly1305` + `zeroize`. Custom Encrypt-then-HMAC constructions and plaintext storage fallbacks are strictly prohibited.
3. **Pre-KDF Resource Protection (`DMC-M2-AUDIT-004`):** Keystore files outside `183..=1024` bytes or specifying `scrypt` parameters outside `15 <= log_n <= 16`, `8 <= r <= 15`, `1 <= p <= 2`, total heap memory `128 * r * ((1 << log_n) + p + 1) > 134,217,728` bytes (`128 MiB`), or CPU work factor `(1 << log_n) * r * p > 1,966,080` must be rejected using checked arithmetic **before** allocating KDF buffers or invoking `scrypt`.
4. **Sealed Capability Tokens:** Neither `ResolvedAgentIdentity`, `LiveProvenanceVerificationSeal`, `CryptographicLiveProvenanceSeal`, nor `PolicyResult` may expose public struct fields or public constructors that allow external callers to manufacture `CryptographicallyVerified` or `execution_authorized() == true`.
5. **Strict Ed25519 Verification Only:** Standard malleable verification (`VerifyingKey::verify`) must not be used; only `VerifyingKey::verify_strict` coupled with `!VerifyingKey::is_weak()` is permitted.
6. **Checked Monotonic Arithmetic:** All sequence counters (`registry_sequence` and `InMemoryAuditSequencer::last_sequence`) must use `checked_add(1)` and fail closed at `u64::MAX` without mutating state.
7. **Truthfulness of Security Claims:** Code comments, docs, and API names must not claim protection against disk/restart rollback (deferred to `M3`) or operational multi-party threshold recovery (`M > 1` deferred until separately authorized).

---

## 3. Mandatory Verification Commands (When Implementation Is Authorized)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```
