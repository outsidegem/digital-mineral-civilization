# DCM‑M2‑PHASE‑009.4 – Final Security Consistency Report

**Verdict:** **CONDITIONAL – ADDITIONAL DESIGN WORK REQUIRED**

---

## 1. Nonce Correctness
- The specification mandates a fresh 12‑byte nonce per write and rejects an all‑zero nonce as `KeystoreError::CsprngFailure` ([DMC‑M2‑SPEC‑001_v1.0.md](file:///data/data/com.termux/files/home/digital-mineral-civilization/docs/m2/DMC-M2-SPEC-001_v1.0.md#L110-L115)).
- Phase 009.4 asks to *remove* the “must be non‑zero” rule, which conflicts with the **double‑uniqueness invariant** (new KEK + new nonce ⇒ never reuse `(KEK, nonce)` pair).  The statistical collision risk for a 96‑bit nonce is ≈ q²/2¹⁹⁶; practical usage (<2⁴⁸ writes) makes this negligible, but the invariant relies on a deterministic failure for a zero nonce.
- **Recommendation:** Keep the non‑zero check (or explicitly treat a zero nonce as a CSPRNG failure).  Document the birthday‑bound risk and note that a zero nonce is an error condition, not a valid value.

---

## 2. Audit Consistency
| Situation | Desired Behaviour | Gap |
|---|---|---|
| `UnlockAttempted` succeeds but audit write for `UnlockFailed` cannot be persisted | Record a transient audit entry (best‑effort, retry) and continue; the attempt must be observable. | Specification lacks fallback semantics. |
| `UnlockAttempted` succeeds but `UnlockSucceeded` cannot be persisted | State transition remains effective; audit may be omitted but must not roll back the unlock. | No guidance on decoupling audit from state change. |
| Partial audit write / ambiguous persistence | Use **atomic write‑then‑rename**; on failure treat as *no audit record* while committing the primary operation. | Atomicity not defined. |
| Closed signer later revoked | Closure is a **terminal** state; revocation after closure is a no‑op or a reported error that does not affect already‑closed resources. | Lifecycle undefined. |
| Explicit close/revoke followed by `Drop` | `Drop` is idempotent; if resources are already cleaned, the call is a no‑op. | Not documented. |

**Recommendation:** Extend the audit model to define terminal vs. transitional events, enforce atomic writes, and provide explicit failure‑fallback rules.

---

## 3. Signer Concurrency
- `RestrictedSigner` is declared as a struct with no `Send`/`Sync` impls.  The design intent (M2‑DEC‑002) is to keep secret material confined to a single thread.
- **Concurrency policy:**
  - **Sharing:** `RestrictedSigner` must be **`!Sync`**; wrapping in `Arc` is prohibited.
  - **Serialization:** Both `sign` and `revoke/close` acquire the same internal mutex, ensuring that a revocation cannot interleave with an in‑flight signing operation.
  - **In‑flight signing after revocation:** The implementation may allow the operation to complete using the pre‑revocation secret (acceptable) **or** abort with an error; the choice must be documented.
  - **Secret protection:** Secret keys are stored in `Zeroizing<[u8; 32]>` and guarded by the mutex.
- **API change:** Add a private `PhantomData<*mut ()>` marker to make the type `!Send`/`!Sync` without altering the public surface.

---

## 4. Memory & Allocation
- The claim that `Vec::with_capacity` “fails” is inaccurate; it panics on OOM.  Use **fallible allocation** (`try_reserve`) or catch the panic.
- Allocation for scrypt buffers is performed inside the `scrypt` crate (v0.10.0).  Distinguish user‑controlled allocation (header parsing) from internal scrypt allocation.
- **Zeroization:** Seed and KEK buffers are zeroized via `Zeroizing`.  Intermediate scrypt buffers are *not* currently zeroized; they should be wrapped in `Zeroizing` or manually cleared.
- **Partial failure cleanup:** On any allocation error, remove temporary `.tmp` files and zero any allocated secret buffers before propagating the error.

---

## 5. File & Concurrency Controls
- **Metadata validation:** Directory mode `0700`, file mode `0600`, reject symlinks (see spec lines 260‑262).
- **Bounded reads:** Enforce file size between `MIN_KEYSTORE_FILE_BYTES` (183) and `MAX_KEYSTORE_FILE_BYTES` (1024) before any read.
- **Trailing bytes:** Reject any bytes beyond the defined envelope as `InvalidKeystoreEnvelope`.
- **Platform:** POSIX‑only (chmod bits); Windows ACLs are unsupported.
- **KDF mutex:** Acquired once per load/save (spec line 268) and released after KEK derivation, preventing concurrent `scrypt` executions that could exceed the memory cap.

---

## 6. Test Inventory
- Duplicate IDs (`T‑KS‑040` vs. earlier IDs) and over‑claims of allocator‑wide zeroization exist.
- **Action:** Renumber all test IDs to a globally unique series (e.g., `T‑KS‑001`‑`T‑KS‑030`).
- **Mapping of security requirements to tests (selected):**
  - Nonce uniqueness → `T‑KS‑002` (save twice, compare nonces).
  - Zeroization of secret buffers → `T‑KS‑030` (verify buffer cleared after failure).
  - File‑size bounds → `T‑KS‑015` (reject too‑small/large files).
  - Permission checks → `T‑KS‑018` (reject insecure modes).
  - Audit atomicity → *new* test `T‑KS‑031` (simulate partial write, verify primary operation persists).
  - Signer concurrency → *new* test `T‑KS‑032` (multi‑threaded sign/revoke race).
- Remove claims that the allocator zeroizes memory; only the buffers wrapped in `Zeroizing` are guaranteed.

---

## 7. Final Verdict & Recommendations
The cryptographic design (ChaCha20‑Poly1305, scrypt KDF, per‑write fresh salts/nonces) is sound.  However, **four critical consistency gaps** block full approval:
1. Contradictory nonce‑non‑zero requirement.
2. Undefined audit failure handling and event terminality.
3. Lack of explicit `Send`/`Sync` guarantees for `RestrictedSigner`.
4. Inaccurate allocation claim and missing zero‑ization of scrypt buffers.

**Required actions before APPROVAL:**
- Re‑introduce (or formally document) the non‑zero nonce rule.
- Extend the audit model with atomic write semantics and explicit fallback handling.
- Annotate `RestrictedSigner` as `!Send`/`!Sync` and document the serialization of `sign`/`revoke`.
- Adjust allocation logic to use `try_reserve` and wrap scrypt buffers in `Zeroizing`.
- Renumber test IDs, add missing audit and concurrency tests, and delete unverifiable memory‑erasure claims.

**M1.1 modules and frozen APIs remain untouched** – this phase introduces only analysis and documentation changes.

---
