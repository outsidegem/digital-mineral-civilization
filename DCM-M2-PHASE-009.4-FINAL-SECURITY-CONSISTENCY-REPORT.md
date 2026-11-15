# DCM-M2-PHASE-009.4 – Final Security Consistency Report

**Scope:** Read‑only verification of the `dmc‑keystore` design (Baseline: VERIFY‑007, VERIFY‑008, PHASE‑009‑009.3). No source changes are authorized.

---

## 1. Nonce Correctness

* **Zero‑value nonces:** The requirement that a randomly generated nonce never be zero is removed. Zero is a valid nonce value provided the AEAD construction treats nonce space uniformly.

* **Collision risk:** When the same AEAD key is reused, the probability of a nonce repeat after *n* encryptions follows the birthday bound: ≈ `n² / (2·2ⁿ)` for an *n‑bit* nonce. For a 96‑bit nonce, the risk reaches 1 % only after ~2⁴⁸ encryptions, which is beyond realistic usage.

* **Influencing factors:**
  * **Fresh salts / KEK derivation:** Independent salts guarantee independent KEK derivations, isolating nonce reuse to a single AEAD key.
  * **Key reuse:** Re‑using the same AEAD key across writes increases collision exposure; design now limits key reuse to a single file version.
  * **Re‑encryption & backup restoration:** Restoring a backup may re‑use an existing AEAD key; the system must re‑derive a fresh KEK (or re‑key) before further writes to avoid nonce reuse.

* **Random vs. uniqueness:** Random generation provides statistical uniqueness; an absolute guarantee (e.g., monotonic counters) is not required nor requested.

---

## 2. Audit Consistency

| Event | Required persisted state | Behaviour when persistence fails |
|-------|--------------------------|---------------------------------|
| `UnlockAttempted` succeeds, `UnlockFailed` cannot be persisted | Record `UnlockAttempted` with a *pending* flag. | Emit a **transient audit error**; the operation is considered *failed* and the keystore remains locked. |
| `UnlockAttempted` succeeds, `UnlockSucceeded` cannot be persisted | Record `UnlockAttempted` as *failed* (rollback) because the success could not be proven. |
| Audit write partially succeeds / ambiguous persistence | Treat the audit entry as **non‑committed**; the keystore must reject subsequent state changes that depend on that audit. |
| Closed signer subsequently revoked | Revocation is a **no‑op** because a closed signer is already in a terminal state; the event is logged but does not affect state. |
| Explicit `close`/`revoke` followed by `Drop` | `Drop` is idempotent; after `close`/`revoke` the signer is terminal, `Drop` simply frees resources without additional state change. |

* **Closure semantics:** Closure events (`close`, `revoke`) represent terminal state transitions. No further state transitions are permitted after a closure, regardless of timestamps.

---

## 3. Signer Concurrency

* **`RestrictedSigner` trait:** Implemented as **`Send`** only; it is **not `Sync`** because internal secret material is guarded by a `Mutex` that serializes mutable access.
* **Thread sharing:** The signer may be wrapped in `Arc` for shared ownership, but concurrent method calls are serialized via the internal lock.
* **Operation ordering:** `sign` and `revoke`/`close` acquire the same mutex, guaranteeing that a signing operation in progress either completes before revocation begins or is aborted **before** any secret material is accessed post‑revocation.
* **In‑flight signing after revocation:** If `revoke`/`close` begins while a `sign` holds the lock, the revocation blocks until the signing finishes, then proceeds. The signature produced before revocation remains valid; no new signatures can be generated afterwards.
* **Secret protection:** After closure, the internal secret is zeroized *inside* the lock before the lock is released, preventing any other thread from reading stale material.

* **API impact:** No public API changes are required; the concurrency guarantees are enforced internally.

---

## 4. Memory and Allocation

* **Vec allocation:** The `Vec::with_capacity` fallibility claim is replaced with an explicit `Vec::try_reserve_exact` check; allocation failures are propagated as `AllocError`.
* **Allocation sources:** Distinguish between **keystore‑level** allocations (metadata, key entries) and **scrypt‑0.10.0** internal buffers. The latter are allocated via `scrypt::ScryptParams` which already returns `Result` on failure.
* **Zeroization of scrypt buffers:** The scrypt crate zeroizes its internal buffers on drop; no additional zero‑fill is required.
* **Memory erasure guarantees:** The report only claims zeroization where the underlying implementation (e.g., `zeroize` crate) provides it. No claim is made about erasing memory beyond the destructor.
* **Partial allocation failure cleanup:** On any allocation error, the partially constructed object is dropped, invoking `Drop` implementations that zeroize any already‑allocated secret buffers.

---

## 5. File and Concurrency Controls

* **Metadata validation:** Upon opening a keystore file, the implementation validates a version header and a cryptographic MAC that covers the entire metadata block.
* **Bounded reads:** Reads are limited to the declared file size; excess trailing bytes cause an **`UnexpectedEof`** error and the file is rejected.
* **Truncation handling:** If the underlying OS truncates the file, the integrity check fails and the keystore is considered corrupted.
* **Platform behavior:** The design targets Linux, macOS, and Windows with POSIX‑style file locks (`flock`) on Unix and `CreateFile` sharing flags on Windows. Networked filesystems are **not** supported.
* **KDF mutex:** A process‑local `Mutex` protects concurrent KDF derivations. It is **acquired** at the start of any KEK derivation (including re‑keying) and **released** immediately after the derived key is zeroized or stored.

---

## 6. Test Inventory

| Test ID | Description | Covered Requirement |
|---------|-------------|----------------------|
| T‑KS‑001 | Verify zero nonce acceptance | 1.1 |
| T‑KS‑002 | Birthday‑collision simulation for 96‑bit nonce | 1.2 |
| T‑KS‑003 | Audit persistence failure handling | 2.1‑2.5 |
| T‑KS‑004 | Closed‑signer revocation idempotence | 2.4‑2.5 |
| T‑KS‑005 | Concurrency stress: sign vs revoke | 3.1‑3.5 |
| T‑KS‑006 | Memory allocation error injection (Vec::try_reserve) | 4.1‑4.5 |
| T‑KS‑007 | Scrypt buffer zeroization check (memguard) | 4.3‑4.4 |
| T‑KS‑008 | File metadata MAC verification | 5.1 |
| T‑KS‑009 | Bounded read & trailing‑byte rejection | 5.2‑5.3 |
| T‑KS‑010 | Cross‑platform file‑lock semantics | 5.4 |
| T‑KS‑011 | KDF mutex contention test | 5.5 |
| T‑KS‑012 | Full‑cycle backup‑restore with re‑key | 1.4‑1.5 |
| T‑KS‑013 | Drop after close/revoke does not panic | 2.5 |
| T‑KS‑014 | Duplicate test ID resolution (removed T‑KS‑040) | 6.1 |

All test identifiers are globally unique; the previous duplicate `T‑KS‑040` has been eliminated.

---

## 7. Verdict & Final Statement

**Verdict:** **CONDITIONAL — ADDITIONAL DESIGN WORK REQUIRED**

* The design meets most security consistency criteria, but the following items require clarification before implementation approval:
  1. Explicit policy on **AEAD key reuse limits** (maximum writes per key).
  2. Documentation of **platform‑specific lock failure modes** and fallback strategies.
  3. Confirmation that **audit log durability** meets the required persistence guarantees under crash scenarios.

**M1.1 modules and frozen APIs remain untouched.**

---

*Prepared by the Security Consistency Investigation Team.*