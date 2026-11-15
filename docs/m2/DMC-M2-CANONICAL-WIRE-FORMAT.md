# DMC M2 — Canonical Wire Format Specification (`DMC-M2-CANONICAL-WIRE-FORMAT`)

- **Parent Specification:** [DMC-M2-SPEC-001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md)
- **Standard Identifiers:** `DMC-CANON-V1` (Decision 1) & `DMC-DEV-KEYSTORE-V1` (Decision 3, Amended by `DMC-M2-DEC-002`)
- **Authorization IDs:** `DMC-M2-AUTH-001`, `DMC-M2-DEC-002`
- **Implementation Status:** **NOT AUTHORIZED** (Specification Only)

---

## 1. General Wire Rules (`DMC-CANON-V1`)

1. **Endianness:** All multi-byte integer fields (`u16`, `u32`, `u64`) are encoded in **big-endian (network byte order)**.
2. **Length-Prefixed Variable Fields (`LP-UTF8`):** Every variable-length UTF-8 string (`AgentId`, `KeyId`, `department`, `reason`, etc.) is encoded as:
   - `length: u32` (big-endian byte length, `1 <= length <= MAX_FIELD_BYTES`)
   - `bytes: [u8; length]` (exact UTF-8 bytes, no NUL terminator, no BOM, no leading/trailing whitespace, no control characters `0x00..=0x1F` or `0x7F`).
3. **Fixed-Size Byte Arrays:** Fixed-size cryptographic fields (`nonce: [u8; 32]`, `Ed25519PublicKeyBytes: [u8; 32]`, `Ed25519SignatureBytes: [u8; 64]`) are written as raw contiguous bytes **without** a length prefix because their sizes are fixed by protocol version `(1, 1)` and `algorithm_id = 0x01`.
4. **Explicit Enum Tags:**
   - `AutonomyLevel` (`u8`): `E0Observe = 0x00`, `E1Plan = 0x01`, `E2Sandbox = 0x02`, `E3InternalOperations = 0x03`, `E4BoundedProduction = 0x04`, `E5ReservedAuthority = 0x05`. (Any tag `> 0x05` is rejected; `0x05` is rejected at enrollment/authentication).
   - `CustodyAssuranceLevel` (`u8`): `LocalDevelopmentOnly = 0x01`. (Any tag `!= 0x01` is rejected in `M2`).
   - `RevocationReasonCode` (`u8`): `KeyCompromise = 0x01`, `KeyLost = 0x02`, `AdministrativeTermination = 0x03`, `SupersededByRecovery = 0x04`.
   - `RevocationAuthority` (`u8` tag + `LP-UTF8` ID): `0x01` = `SelfActiveKey(KeyId)`, `0x02` = `FounderRootAnchor(RootAnchorId)`.
   - `Boolean Flag` (`u8`): `0x00 = false`, `0x01 = true`. Any byte `>= 0x02` fails closed with `CanonWireError::InvalidEnumTag`.
5. **Global & Per-Field Size Bounds:**
   - `MAX_CANON_MESSAGE_BYTES = 4096` bytes (any buffer `< 17` bytes or `> 4096` bytes is rejected immediately before field parsing).
   - `MAX_CANON_IDENTIFIER_BYTES = 128` bytes (`AgentId`, `KeyId`, `ChallengeId`, `RootAnchorId`, `KeyRotationId`, `KeyRevocationId`, `RecoveryId`).
   - `MAX_CANON_DEPARTMENT_BYTES = 128` bytes.
   - `MAX_CANON_REASON_BYTES = 512` bytes.
   - `MAX_THRESHOLD_APPROVALS = 16` entries (`1` required in `M2`).

---

## 2. Common 17-Byte Header Layout

Every `DMC-CANON-V1` signable frame starts with an identical 17-byte header:

| Byte Offset | Size (Bytes) | Field Name | Type | Required Value (`M2`) |
|---|---|---|---|---|
| `0..11` | `11` | `magic` | `[u8; 11]` | `b"DMC-SIG-V1\0"` (`44 4D 43 2D 53 49 47 2D 56 31 00`) |
| `11..13` | `2` | `protocol_version` | `u16` (BE) | `0x0001` (`1`) |
| `13..15` | `2` | `schema_version` | `u16` (BE) | `0x0001` (`1`) |
| `15..16` | `1` | `message_type` | `u8` | `0x01`..`0x06` (Domain Separator Tag) |
| `16..17` | `1` | `algorithm_id` | `u8` | `0x01` (`SignatureAlgorithmId::Ed25519`) |

> [!IMPORTANT]
> **Domain Separation Guarantee:** Because bytes `0..17` (including `message_type` at byte offset `15`) are **inside** the signed byte range for every message type, an Ed25519 signature over a message of type `0x03` (`AuthClaim`) is cryptographically impossible to reuse as a valid signature for type `0x01` (`Enrollment`), `0x04` (`KeyRotation`), `0x05` (`KeyRevocation`), or `0x06` (`CredentialRecovery`), even if payload bytes were otherwise identical.

---

## 3. Binary Layouts and Signing Boundaries by Message Type

### 3.1 Message Type `0x01` — `Enrollment` (`IdentityRegistration`)

#### Signable Frame (`IdentityRegistrationPayload`, `message_type = 0x01`)
| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x01` \| `0x01` | Fixed `17` bytes |
| `1` | `agent_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `AgentId` |
| `2` | `department` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, trimmed UTF-8, no control chars |
| `3` | `max_autonomy` | `u8` | `0x00..=0x04` (`0x05` rejected) |
| `4` | `key_id` | `u32` (BE len $L_3$) + `[u8; L_3]` | $1 \le L_3 \le 128$, valid `KeyId` |
| `5` | `public_key` | `[u8; 32]` | Fixed `32` bytes (valid non-weak Ed25519 point) |
| `6` | `custody_assurance` | `u8` | `0x01` (`LocalDevelopmentOnly`) |
| `7` | `expected_registry_sequence` | `u64` (BE) | Fixed `8` bytes ($\ge 1$) |
| `8` | `issued_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes |
| `9` | `expires_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes (`> issued_at_epoch_secs`) |

- **Signing Boundary:** Exact byte slice `signable_bytes[0..N]` comprising `H` through Field `9`.
- **Full Wire Envelope Trailer (appended after `signable_bytes[0..N]`):**
  - `root_anchor_id`: `u32` (BE len $L_R$) + `[u8; L_R]` ($1 \le L_R \le 128$)
  - `root_signature`: `[u8; 64]` (verified via `root_verifying_key.verify_strict(&signable_bytes[0..N], &root_signature)`).

---

### 3.2 Message Type `0x02` — `AuthChallenge` (`AuthChallengePayload`)

Used for deterministic canonical representation and digest/commitment of verifier-issued challenges:

| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x02` \| `0x01` | Fixed `17` bytes |
| `1` | `challenge_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `ChallengeId` |
| `2` | `nonce` | `[u8; 32]` | Fixed `32` bytes (OS CSPRNG) |
| `3` | `target_agent_id` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, valid `AgentId` |
| `4` | `verifier_instance_id` | `u64` (BE) | Fixed `8` bytes ($\ge 1$) |
| `5` | `registry_sequence_at_issue` | `u64` (BE) | Fixed `8` bytes |
| `6` | `issued_at_epoch_ms` | `u64` (BE) | Fixed `8` bytes |
| `7` | `expires_at_epoch_ms` | `u64` (BE) | Fixed `8` bytes (`issued < expires <= issued + 300_000`) |

---

### 3.3 Message Type `0x03` — `AuthClaim` (`SignedIdentityClaim`)

#### Signable Frame (`SignedIdentityClaimPayload`, `message_type = 0x03`)
| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x03` \| `0x01` | Fixed `17` bytes |
| `1` | `challenge_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `ChallengeId` |
| `2` | `nonce` | `[u8; 32]` | Fixed `32` bytes (must match issued challenge) |
| `3` | `agent_id` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, valid `AgentId` |
| `4` | `key_id` | `u32` (BE len $L_3$) + `[u8; L_3]` | $1 \le L_3 \le 128$, valid `KeyId` |
| `5` | `claimed_department` | `u32` (BE len $L_4$) + `[u8; L_4]` | $1 \le L_4 \le 128$, trimmed UTF-8 |
| `6` | `claimed_autonomy` | `u8` | `0x00..=0x04` (`0x05` rejected) |
| `7` | `verifier_instance_id` | `u64` (BE) | Fixed `8` bytes ($\ge 1$) |
| `8` | `registry_sequence_bound` | `u64` (BE) | Fixed `8` bytes ($\ge 1$) |
| `9` | `signed_at_epoch_ms` | `u64` (BE) | Fixed `8` bytes |
| `10` | `expires_at_epoch_ms` | `u64` (BE) | Fixed `8` bytes (`signed_at < expires_at <= challenge.expires_at`) |

- **Signing Boundary:** Exact byte slice `signable_bytes[0..N]` comprising `H` through Field `10`.
- **Full Wire Envelope Trailer:**
  - `signature`: `[u8; 64]` (verified via the registered active `KeyId`'s `VerifyingKey::verify_strict(&signable_bytes[0..N], &signature)`).

---

### 3.4 Message Type `0x04` — `KeyRotation` (`KeyRotationRecord`)

#### Signable Frame (`KeyRotationPayload`, `message_type = 0x04`)
| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x04` \| `0x01` | Fixed `17` bytes |
| `1` | `rotation_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `KeyRotationId` |
| `2` | `agent_id` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, valid `AgentId` |
| `3` | `old_key_id` | `u32` (BE len $L_3$) + `[u8; L_3]` | $1 \le L_3 \le 128$, valid `KeyId` |
| `4` | `new_key_id` | `u32` (BE len $L_4$) + `[u8; L_4]` | $1 \le L_4 \le 128$, valid `KeyId` (`!= old_key_id`) |
| `5` | `new_public_key` | `[u8; 32]` | Fixed `32` bytes (valid non-weak Ed25519 point) |
| `6` | `custody_assurance` | `u8` | `0x01` (`LocalDevelopmentOnly`) |
| `7` | `expected_registry_sequence` | `u64` (BE) | Fixed `8` bytes ($\ge 2$) |
| `8` | `rotated_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes |
| `9` | `new_key_expires_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes (`> rotated_at_epoch_secs`) |

- **Dual-Signature Boundary (Decision 6):** Both keys sign the **exact same** byte slice `signable_bytes[0..N]` (`H` through Field `9`):
  1. `old_key_signature`: `[u8; 64]` verified against `old_key_id`'s currently `Active` `VerifyingKey` via `verify_strict(&signable_bytes[0..N], &old_key_signature)`.
  2. `new_key_pop_signature`: `[u8; 64]` verified against `new_public_key` via `verify_strict(&signable_bytes[0..N], &new_key_pop_signature)`.
- **Full Wire Envelope Trailer:** `old_key_signature` (`64` bytes) followed immediately by `new_key_pop_signature` (`64` bytes).

---

### 3.5 Message Type `0x05` — `KeyRevocation` (`KeyRevocationRecord`)

#### Signable Frame (`KeyRevocationPayload`, `message_type = 0x05`)
| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x05` \| `0x01` | Fixed `17` bytes |
| `1` | `revocation_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `KeyRevocationId` |
| `2` | `agent_id` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, valid `AgentId` |
| `3` | `target_key_id` | `u32` (BE len $L_3$) + `[u8; L_3]` | $1 \le L_3 \le 128$, valid `KeyId` |
| `4` | `revoke_entire_agent` | `u8` | `0x00` (`false`) or `0x01` (`true`) |
| `5` | `reason_code` | `u8` | `0x01..=0x04` (`RevocationReasonCode`) |
| `6` | `reason` | `u32` (BE len $L_4$) + `[u8; L_4]` | $1 \le L_4 \le 512$, trimmed UTF-8 |
| `7` | `authorizing_authority_tag` | `u8` | `0x01` (`SelfActiveKey`) or `0x02` (`FounderRootAnchor`) |
| `8` | `authorizing_authority_id` | `u32` (BE len $L_5$) + `[u8; L_5]` | $1 \le L_5 \le 128$ (`KeyId` if `0x01`; `RootAnchorId` if `0x02`) |
| `9` | `expected_registry_sequence` | `u64` (BE) | Fixed `8` bytes ($\ge 2$) |
| `10` | `revoked_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes |

- **Signing Boundary:** Exact byte slice `signable_bytes[0..N]` comprising `H` through Field `10`.
- **Full Wire Envelope Trailer:**
  - `authorizing_signature`: `[u8; 64]` (verified via `verify_strict` against either the target `Active` key if `tag == 0x01` and `authorizing_authority_id == target_key_id`, or the pinned Founder Root key if `tag == 0x02`).

---

### 3.6 Message Type `0x06` — `CredentialRecovery` (`RecoveryRecord`)

#### Signable Frame (`RecoveryPayload`, `message_type = 0x06`)
| Order | Field | Wire Representation | Size Constraints |
|---|---|---|---|
| `H` | Common Header | `DMC-SIG-V1\0` \| `0x0001` \| `0x0001` \| `0x06` \| `0x01` | Fixed `17` bytes |
| `1` | `recovery_id` | `u32` (BE len $L_1$) + `[u8; L_1]` | $1 \le L_1 \le 128$, valid `RecoveryId` |
| `2` | `agent_id` | `u32` (BE len $L_2$) + `[u8; L_2]` | $1 \le L_2 \le 128$, valid `AgentId` |
| `3` | `new_key_id` | `u32` (BE len $L_3$) + `[u8; L_3]` | $1 \le L_3 \le 128$, valid `KeyId` |
| `4` | `new_public_key` | `[u8; 32]` | Fixed `32` bytes (valid non-weak Ed25519 point) |
| `5` | `custody_assurance` | `u8` | `0x01` (`LocalDevelopmentOnly`) |
| `6` | `reason` | `u32` (BE len $L_4$) + `[u8; L_4]` | $1 \le L_4 \le 512$, trimmed UTF-8 |
| `7` | `required_threshold` | `u8` | `1..=16` (must be `0x01` in operational `M2`) |
| `8` | `expected_registry_sequence` | `u64` (BE) | Fixed `8` bytes ($\ge 2$) |
| `9` | `recovered_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes |
| `10` | `new_key_expires_at_epoch_secs` | `u64` (BE) | Fixed `8` bytes (`> recovered_at_epoch_secs`) |

- **Signing Boundary (Decision 8):** Both the Founder Root Trust Anchor(s) and the replacement key (`new_key_id`) sign the **exact same** byte slice `signable_bytes[0..N]` (`H` through Field `10`).
- **Full Wire Envelope Trailer:**
  1. `approvals_count: u8` ($1 \le \text{approvals\_count} \le 16$; must equal `0x01` in `M2`)
  2. Repeated `approvals_count` times:
     - `root_anchor_id`: `u32` (BE len $L_R$) + `[u8; L_R]` ($1 \le L_R \le 128$)
     - `root_signature`: `[u8; 64]` (verified via `root_verifying_key.verify_strict(&signable_bytes[0..N], &root_signature)`)
  3. `new_key_pop_signature`: `[u8; 64]` (verified via `new_verifying_key.verify_strict(&signable_bytes[0..N], &new_key_pop_signature)`).

---

## 4. Development Keystore Envelope Format (`DMC-DEV-KEYSTORE-V1` — Amended by `DMC-M2-DEC-002`)

Per Founder Directive `DMC-M2-DEC-002`, each encrypted local development key file (`<key_id>.dmcks`, POSIX mode `0600` inside a `0700` directory outside the Git workspace) uses **scrypt** (`kdf_id = 0x01`) and **ChaCha20-Poly1305** (`aead_id = 0x01`) in the following exact binary layout:

| Offset / Order | Size (Bytes) | Field Name | Wire Type & Value (`DMC-DEV-KEYSTORE-V1`) |
|---|---|---|---|
| `0..10` | `10` | `ks_magic` | `b"DMC-KS-V1\0"` (`44 4D 43 2D 4B 53 2D 56 31 00`) |
| `10..12` | `2` | `ks_version` | `u16` BE = `0x0001` |
| `12..13` | `1` | `custody_tag` | `u8` = `0x01` (`CustodyAssuranceLevel::LocalDevelopmentOnly`) |
| `13..37` | `24` | `custody_ascii` | Fixed ASCII `b"local_development_only\0\0"` |
| `37..38` | `1` | `kdf_id` | `u8` = `0x01` (`KdfAlgorithmId::Scrypt`) |
| `38..39` | `1` | `aead_id` | `u8` = `0x01` (`AeadAlgorithmId::ChaCha20Poly1305`) |
| `39..40` | `1` | `scrypt_log_n` | `u8` (`15 <= scrypt_log_n <= 16`; baseline `15`) |
| `40..44` | `4` | `scrypt_r` | `u32` BE (`8 <= scrypt_r <= 15`; baseline `8`) |
| `44..48` | `4` | `scrypt_p` | `u32` BE (`1 <= scrypt_p <= 2`; baseline `1`) |
| `48..80` | `32` | `kdf_salt` | `[u8; 32]` (fresh OS CSPRNG salt per write, non-zero) |
| `80..92` | `12` | `aead_nonce` | `[u8; 12]` (fresh 96-bit OS CSPRNG nonce per write, non-zero) |
| `92..96+L1` | `4 + L1` | `agent_id` | `u32` BE length $L_1$ ($1 \le L_1 \le 128$) + UTF-8 `AgentId` bytes |
| `96+L1..100+L1+L2` | `4 + L2` | `key_id` | `u32` BE length $L_2$ ($1 \le L_2 \le 128$) + UTF-8 `KeyId` bytes |
| `100+L1+L2..101+L1+L2` | `1` | `algorithm_id` | `u8` = `0x01` (`SignatureAlgorithmId::Ed25519`) |
| `101+L1+L2..133+L1+L2` | `32` | `public_key` | `[u8; 32]` (uncompressed Ed25519 verifying key bytes) |
| `N..N+32` | `32` | `encrypted_seed` | `[u8; 32]` (`ChaCha20` ciphertext of the 32-byte Ed25519 secret seed) |
| `N+32..N+48` | `16` | `poly1305_tag` | `[u8; 16]` (128-bit `Poly1305` MAC over AAD `bytes[0..N]` and `encrypted_seed`) |

*(Where $N = 133 + L_1 + L_2$. Minimum valid file size with $L_1 = 1, L_2 = 1$ is $135 + 48 = 183$ bytes; maximum valid file size with $L_1 = 128, L_2 = 128$ is $389 + 48 = 437$ bytes, well within `MAX_KEYSTORE_FILE_BYTES = 1024`.)*

### 4.1 Keystore AAD and Cryptographic Processing Rules
1. **Exact AAD Boundary:** The entire slice `envelope_bytes[0..N]` (from byte `0` of `ks_magic` through the last byte of `public_key` at offset $N - 1$) is passed as the Associated Authenticated Data (`aad`) to `ChaCha20Poly1305`.
2. **Pre-KDF Validation Order:** Before calling `scrypt::scrypt` or allocating KDF buffers, the loader **must** validate:
   - File size `183 <= file_len <= 1024`
   - `ks_magic`, `ks_version == 1`, `custody_tag == 0x01`, `custody_ascii`, `kdf_id == 0x01`, `aead_id == 0x01`
   - `15 <= scrypt_log_n <= 16`, `8 <= scrypt_r <= 15`, `1 <= scrypt_p <= 2`, checked total heap memory `128 * scrypt_r * ((1 << scrypt_log_n) + scrypt_p + 1) <= 134_217_728` (`128 MiB`), and checked CPU work factor `(1 << scrypt_log_n) * scrypt_r * scrypt_p <= 1_966_080` (`KdfParametersOutOfBounds`)
   - `kdf_salt != [0u8; 32]` and `aead_nonce != [0u8; 12]`
   - Valid `agent_id`, `key_id`, `algorithm_id == 0x01`, non-weak `public_key`, and exact remaining trailer length `== 48` bytes (`bytes.len() == N + 48`).
3. **Key Derivation & Decryption:**
   - Derive `kek: Zeroizing<[u8; 32]>` via `scrypt::scrypt(passphrase.as_bytes(), &kdf_salt, &params, &mut *kek)`.
   - Decrypt and verify tag via `ChaCha20Poly1305::new(&kek).decrypt_in_place_detached(&aead_nonce, &envelope_bytes[0..N], &mut seed_buf, &poly1305_tag)`.
   - If tag verification fails, zeroize `seed_buf` and `kek` immediately and return `KeystoreError::AuthenticationFailed`.

---

## 5. Version Compatibility and Rejection Rules

1. **Protocol/Schema Version Mismatch:** Any `DMC-CANON-V1` message with `protocol_version != 1` or `schema_version != 1`, or any `DMC-DEV-KEYSTORE-V1` file with `ks_version != 1`, is rejected before cryptographic processing.
2. **Trailing Bytes:** After decoding the last defined field of a signable payload, full record envelope, or keystore file, if `cursor != bytes.len()`, decoding fails closed (`TrailingBytes` / `InvalidKeystoreEnvelope`).
3. **Integer Overflow & Bounds:** When reading a `u32` length prefix `L`, the decoder converts `L` to `usize`, checks `1 <= L <= field_max`, and checks `cursor.checked_add(L) <= Some(bytes.len())` before slicing.
4. **Canonical Re-encoding Check:** Verifiers decode incoming wire bytes and verify that `decoded.encode_canonical_signable()? == incoming_signable_bytes`, guaranteeing zero representation ambiguity.
