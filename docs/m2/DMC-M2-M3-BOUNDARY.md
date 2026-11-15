# DMC M2 / M3 Responsibility and Security Boundary (`DMC-M2-M3-BOUNDARY`)

- **Parent Specification:** [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md)
- **Authorization ID:** `DMC-M2-AUTH-001`
- **Implementation Status:** **NOT AUTHORIZED** (Architectural Boundary Definition Only)

---

## 1. Milestone Responsibility Matrix

| Capability / Security Control | M1.1 (Frozen) | M2 (Specified in `DMC-M2-SPEC-001 v1.0`) | M3+ (Explicitly Deferred) |
|---|---|---|---|
| **Agent Identity Model** | `AgentIdentityClaim` + in-memory `LocalProvisional` resolution | Stable `AgentId` + Ed25519 `KeyId` (`CryptographicallyVerified`) | Cross-node / distributed identity federation |
| **Root Trust Anchor** | None | Offline Founder Root keypair; pinned `RootTrustAnchorSet` public keys in runtime | Hardware Security Module (HSM) / hardware token root custody |
| **Agent Key Custody** | None | `DMC-DEV-KEYSTORE-V1` (`0700`/`0600`, encrypted at rest, `local_development_only`) | Production hardware-backed / TEE / HSM key custody |
| **Signed Wire Format** | None | `DMC-CANON-V1` deterministic binary framing (`0x01`..`0x06`) | Extended schemas (`protocol_version >= 2` if required) |
| **Challenge & Replay Protection** | None | 32-byte CSPRNG nonce, $\le 5\text{ min}$ TTL, bounded in-memory `ReplayTracker` (`10,000`), restart invalidation | Persistent cross-restart distributed replay ledger |
| **Key Rotation & Revocation** | Agent-level & delegation-level revocation in memory | Immediate-cutover dual-signed rotation (`Zero Overlap`); live key & agent revocation | Automated revocation distribution / CRL / OCSP-equivalent push |
| **Credential Recovery** | None | `1-of-1` Founder Root-authorized `RecoveryRecord` + new-key PoP (`M-of-N` wire schema ready) | Operational `M-of-N` ($M > 1$) multi-party threshold recovery verification |
| **Registry Rollback Protection** | Instance-bound `ProvisionalIdentityRegistry` (`instance_id`) | In-memory `registry_sequence: u64` (`checked_add(1)`) + `min_acceptable_sequence` high-water mark (Option 5B) | Durable signed registry snapshots + independently protected persistent rollback checkpoints |
| **Process & Artifact Provenance** | In-memory `ProvenanceTracker` + `ContentDigest` correspondence | Live cryptographic agent/key verification integrated with `ProvenanceTracker` lineage | Cryptographically signed execution & artifact provenance attestations; OS-boundary RDA process identity |
| **Audit Infrastructure** | `InMemoryAuditSequencer` (`checked_add(1)`, canonical URI validation) | Structured `SecurityAuditRecord` & 6 new `AuditEventKind` variants in `InMemoryAuditSequencer` | Durable append-only audit storage + cryptographic hash chaining |
| **Blockchain / EVM / Treasury** | Prohibited (`TransferTreasuryFunds` denied) | Prohibited (Ed25519 identity keys strictly separated from EVM/wallets) | Requires separate constitutional & Founder specification |

---

## 2. Explicit Deferrals to Milestone 3 (`M3`) and Beyond

### 2.1 Durable Registry Persistence (Deferred to `M3`)
- **M2 Scope (Decision 5B):** `CryptographicIdentityRegistry` is an authoritative **in-memory** state machine for the lifetime of a runtime process.
- **Deferred to M3:** Serializing registry state to durable storage, atomic journal replay, and signed persistent state snapshots (`RegistrySnapshot`).

### 2.2 Independently Protected Persistent Rollback Checkpoints (Deferred to `M3`)
- **M2 Scope:** `CryptographicIdentityRegistry` enforces monotonic `registry_sequence: u64` transitions in memory and rejects any in-process state or token whose sequence is older than `min_acceptable_sequence`.
- **Mandatory Truthfulness Constraint:** `M2` **does not** protect against an attacker with host filesystem access rolling back an on-disk image across a full OS process restart, because `M2` has no external hardware monotonic counter, TPM/TEE nvram index, or remote witness. Disk-rollback and process-restart rollback resistance are explicitly deferred to `M3`.

### 2.3 Durable Append-Only Audit Storage and Hash Chaining (Deferred to `M3`)
- **M2 Scope:** `titan-audit` sequences `AuditEvent` and `SecurityAuditRecord` entries in memory using `InMemoryAuditSequencer` with unique `AuditEventId` and checked monotonic `u64` sequence numbers.
- **Deferred to M3:** Write-ahead append-only file/database storage, cryptographic hash chaining (`prev_event_digest -> current_event_digest`), and signed audit checkpoints.

### 2.4 Operational Multi-Party (`M-of-N`, $M > 1$) Threshold Recovery (Deferred Until Separately Authorized)
- **M2 Scope (Decision 8):** The `RecoveryRecord` data model and `DMC-CANON-V1` message type `0x06` include `required_threshold: u8` and `root_approvals: Vec<RootSignatureApproval>` so the binary wire format will not require a breaking change when multi-party recovery is introduced. However, in `M2`, `CryptographicIdentityRegistry::recover_agent_keys` enforces `required_threshold == 1` and `root_approvals.len() == 1`, rejecting any `required_threshold > 1` with `CryptoIdentityError::ThresholdRecoveryNotYetOperational`.
- **Mandatory Truthfulness Constraint:** Operational threshold recovery is **not** claimed in `M2` and remains disabled until a separate Founder specification authorizes multi-anchor quorum rules, duplicate-signer deduplication, and ceremony tooling.

### 2.5 OS-Boundary RDA Process Identity and Signed Provenance (Deferred to `M3+`)
- **M2 Scope:** `ProcessProvenance`, `ExecutionIdentity`, `ToolInvocationIdentity`, and `ArtifactProvenance` remain governed by `ProvenanceTracker` linked to live `CryptographicIdentityRegistry` agent and key status.
- **Deferred:** Cross-OS-process attestation, kernel/container sandboxing credentials, and per-artifact Ed25519 authorship signatures.
