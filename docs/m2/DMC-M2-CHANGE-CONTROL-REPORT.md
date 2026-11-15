# DMC M2 — Change-Control and Compatibility Report (`DMC-M2-CHANGE-CONTROL-REPORT`)

- **Parent Specification:** [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md)
- **Authorization IDs:** `DMC-M2-AUTH-001`, `DMC-M2-DEC-002`
- **Implementation Status:** **NOT AUTHORIZED** (Change-Control Report Only)

---

## 1. Confirmation of Zero Implementation Changes in This Assignment

In strict compliance with Section 2 and Section 9 of `DMC-M2-AUTH-001` and Section 5 of `DMC-M2-DEC-002`:
- **Zero M1.1 source files were modified:**
  - [core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs) — **UNTOUCHED**
  - [core/titan-identity/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/src/lib.rs) — **UNTOUCHED**
  - [core/titan-policy-core/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/src/lib.rs) — **UNTOUCHED**
  - [core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs) — **UNTOUCHED**
- **Zero Cargo manifests or lockfiles were modified:**
  - [Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/Cargo.toml), [Cargo.lock](file:///data/data/com.termux/files/home/digital-mineral-civilization/Cargo.lock), [core/dmc-types/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/Cargo.toml), [core/titan-identity/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/Cargo.toml), [core/titan-policy-core/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/Cargo.toml), [core/titan-audit/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/Cargo.toml) — **UNTOUCHED**
- **Zero dependencies were installed or downloaded.**
- **Zero Git commits or branches were created.**
- **Zero cryptographic keys were generated.**

---

## 2. Proposed Future Source-Code Changes (When Authorized)

| Existing File | Proposed Future Modification (Phase) | M1.1 Preservation Guarantee |
|---|---|---|
| [core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs) | Add `KeyId`, `ChallengeId`, `RootAnchorId`, `KeyRotationId`, `KeyRevocationId`, `RecoveryId`; add `IdentityTrustStatus::CryptographicallyVerified`; re-export `canon_wire` and `crypto_records` submodules (`M2.1`). | All M1/M1.1 types, methods, and 3 unit tests remain unchanged. Zero external dependencies added. |
| [core/titan-identity/Cargo.toml](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/Cargo.toml) | Add pinned RustCrypto dependencies (`ed25519-dalek`, `getrandom`, `rand_core`, `zeroize`, `sha2`, `scrypt`, `chacha20poly1305`) (`M2.1`). | Confined strictly to `titan-identity`. |
| [core/titan-identity/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-identity/src/lib.rs) | Extend `ResolvedAgentIdentity` with private `authenticated_key_id: Option<KeyId>` and `registry_sequence_at_resolution: Option<u64>` (`None` in `mint_provisional`); add `CryptographicLiveProvenanceSeal`; add `ProvenanceTracker::verify_live_cryptographic_process_and_delegation_lineage`; re-export M2 submodules (`M2.1`–`M2.6`). | `ProvisionalIdentityRegistry`, `ProvenanceTracker`, `LiveProvenanceVerificationSeal`, and all 5 existing M1.1 tests remain intact. |
| [core/titan-policy-core/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/src/lib.rs) | Add `PolicyTrustLevel::CryptographicLiveProvenanceVerified`; add `PolicyResult::new_cryptographic_live_provenance_denied`, private `new_cryptographic_live_provenance_allowed`, and `is_cryptographically_execution_authorized()`; add `policy_evaluate_strict_cryptographic_provenance` (`M2.6`). | `policy_evaluate`, `policy_evaluate_authorized`, `policy_evaluate_strict_provenance`, and all 8 existing M1/M1.1 tests remain intact. |
| [core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs) | Add 6 M2 variants to `AuditEventKind`; add optional `key_id`, `registry_sequence`, and `security_failure_code` fields to `AuditEvent` (populated as `None` in existing constructors); add `InMemoryAuditSequencer::record_security_event` (`M2.6`). | `from_legacy_request_sequenced`, `from_authorized_request`, `record_legacy_decision`, `record_authorized_decision`, and all 4 existing M1.1 tests remain intact. |

---

## 3. Proposed Future New Source Modules (When Authorized)

1. `core/dmc-types/src/canon_wire.rs` — `DMC-CANON-V1` encoder/decoder, `CanonMessageType`, `CanonWireError`, `CanonicalPayload` trait, and wire unit tests (`M2.1`).
2. `core/dmc-types/src/crypto_records.rs` — `PublicKeyRecord`, `IdentityRegistration`, `AuthChallengePayload`, `SignedIdentityClaim`, `KeyRotationRecord`, `KeyRevocationRecord`, `RecoveryRecord`, and `SecurityAuditRecord` (`M2.1`–`M2.5`).
3. `core/titan-identity/src/root_anchor.rs` — `RootTrustAnchorSet`, `RootPublicKeyEntry`, `RootRole` (`M2.2`).
4. `core/titan-identity/src/keystore.rs` — `DevSigningKey`, `DevKeystore`, `ScryptParamsConfig`, `SecretPassphrase`, and `DMC-DEV-KEYSTORE-V1` (`scrypt` + `ChaCha20-Poly1305`) handling (`M2.1`).
5. `core/titan-identity/src/replay.rs` — `ReplayTracker`, monotonic/epoch TTL validation, saturation handling (`M2.3`).
6. `core/titan-identity/src/crypto_registry.rs` — `CryptographicIdentityRegistry` enrollment, authentication, rotation, revocation, recovery, and sequence rollback enforcement (`M2.2`–`M2.5`).

---

## 4. Proposed Dependency Changes & Local Termux Cache Inspection (`DMC-M2-DEC-002`)

Read-only inspection of `/data/data/com.termux/files/home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f` established the exact availability and transitive dependency status for the approved `DMC-M2-DEC-002` architecture:

| Approved Crate | Target Crate | Version & Features | Local Termux Cargo Cache Status | Transitive Dependency Cache Verification |
|---|---|---|---|---|
| `ed25519-dalek` | `titan-identity` | `=2.2.0` (`["rand_core", "zeroize"]`, `default-features = false`) | **CACHED** | `curve25519-dalek-4.1.3`, `ed25519-2.2.3`, `signature-2.2.0`, `subtle-2.6.1` **CACHED** |
| `getrandom` | `titan-identity` | `=0.2.17` (`default-features = false`) | **CACHED** | `cfg-if-1.0.4`, `libc-0.2.*` **CACHED** |
| `rand_core` | `titan-identity` | `=0.6.4` (`["getrandom"]`, `default-features = false`) | **CACHED** | `getrandom-0.2.17` **CACHED** |
| `zeroize` | `titan-identity` | `=1.8.2` (`["alloc", "derive"]`, `default-features = false`) | **CACHED** (`1.8.2` & `1.9.1`) | `zeroize_derive-1.5.0` **CACHED** |
| `sha2` | `titan-identity` | `=0.10.9` (`default-features = false`) | **CACHED** | `digest-0.10.7`, `block-buffer-0.10.4`, `crypto-common-0.1.6`, `generic-array-0.14.7`, `typenum-1.20.0`, `cpufeatures-0.2.17` **CACHED** |
| `scrypt` | `titan-identity` | `=0.10.0` (`default-features = false`) | **CACHED** | `hmac-0.12.1`, `pbkdf2-0.11.0`, `salsa20-0.10.2`, `sha2-0.10.9`, `cipher-0.4.4`, `inout-0.1.4` **100% CACHED** |
| `chacha20poly1305` | `titan-identity` | `=0.10.1` (`["alloc", "zeroize"]`, `default-features = false`) | **NOT CACHED (`PROV-M2-001`)** | Requires provisioning `chacha20poly1305-0.10.1`, `aead-0.5.2`, `chacha20-0.9.1`, `poly1305-0.8.0`, `universal-hash-0.5.1`, `opaque-debug-0.3.1` via `cargo fetch` when Phase `M2.0`/`M2.1` is authorized. |

---

## 5. Rust Enum Exhaustive-Match Compatibility Assessment (Decision 10)

1. **`dmc_types::IdentityTrustStatus`** ([core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs#L92-L114)):
   - *Internal match site:* `IdentityTrustStatus::stable_name` ([core/dmc-types/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/dmc-types/src/lib.rs#L106-L113)) — will add `Self::CryptographicallyVerified => "cryptographically_verified"`.
2. **`titan_policy_core::PolicyTrustLevel`** ([core/titan-policy-core/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-policy-core/src/lib.rs#L24-L34)):
   - Updating `execution_authorized()` to accept `LiveProvenanceVerified | CryptographicLiveProvenanceVerified` and adding `is_cryptographically_execution_authorized()` preserves all 8 existing `titan-policy-core` tests.
3. **`titan_audit::AuditEventKind`** ([core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs#L21-L38)):
   - *Internal match site:* `AuditEventKind::stable_name` ([core/titan-audit/src/lib.rs](file:///data/data/com.termux/files/home/digital-mineral-civilization/core/titan-audit/src/lib.rs#L30-L37)) — will map each of the 6 new M2 variants to its canonical dot-separated name.
