# DMC Simulation Architecture Report

## Overview
This document records the **actual public API surface** of the four foundational crates in the repository and describes the **intended integration sequence** required to run a deterministic Engineering Department simulation (the *foundation scenario*).

---

## 1. Core Domain Types – `core/dmc-types`

| Module / Item | Purpose | Public API (selected) |
|---|---|---|
| `AutonomyLevel` | Ordered autonomy tiers `E0…E5`. | `stable_name(&self) -> &'static str` |
| `AgentIdentity` / `AgentIdentityClaim` | Untrusted caller‑supplied identity claim. | fields `agent_id`, `department`, `autonomy`; `to_claim()` converts to `AgentIdentityClaim` |
| Typed IDs (`AgentId`, `RdaProcessId`, `ExecutionId`, …) | Strongly typed, validated identifier strings. | `new(value) -> Result<Self, IdValidationError>`; `as_str(&self) -> &str` |
| `Action` | Enumerates permitted actions. | `stable_name(&self) -> String`; `is_allowed_for_autonomy(&self, AutonomyLevel) -> bool`; `is_delegable_in_m1_1(&self) -> bool` |
| `ResourceScope` & validator | Bounded set of canonical URI prefixes. | `validate_canonical_resource_uri(&str) -> Result<String, ResourceScopeError>` |
| `Decision` (from `dmc-types`) | `Allow` / `Deny` used by policy results. |
| `PolicyRequest` | Legacy M1 request used by the simple evaluator. |

**Key security notes** (comments in the source):
* `AgentIdentity` and `AgentIdentityClaim` are *unverified*; only a `ResolvedAgentIdentity` from `titan-identity` is trusted.
* Typed IDs guarantee syntactic validation (no whitespace, control chars, etc.).

---

## 2. Identity & Provenance – `core/titan-identity`

### Principal structs
* **`ResolvedAgentIdentity`** – Trusted identity minted only by `ProvisionalIdentityRegistry::resolve_claim`. Contains:
  * `agent_id: AgentId`
  * `department: String`
  * `autonomy: AutonomyLevel`
  * `trust_status: IdentityTrustStatus`
  * `registry_instance_id` & `resolution_source`
* **`ProvisionalIdentityRegistry`** – In‑memory provisional registry.
  * `new(registry_id: impl Into<String>) -> Self`
  * `register_agent(entry: ProvisionalAgentEntry) -> Result<(), IdentityError>`
  * `revoke_agent(&AgentId, reason) -> Result<(), IdentityError>`
  * `resolve_claim(&self, &AgentIdentityClaim) -> Result<ResolvedAgentIdentity, IdentityError>` – validates claim against registry entries.
  * `verify_live_identity(&self, &ResolvedAgentIdentity) -> Result<(), IdentityError>` – ensures token came from this instance and is still valid.
* **`LiveProvenanceVerificationSeal`** – Private token created when live provenance verification succeeds; carries `registry_instance_id`, `agent_id`, `process_id`.
* **`AuthorizedPolicyRequest`** – The request type accepted by the strict policy evaluator. Fields include optional `identity`, `process`, `parent_process`, `delegation`, `parent_delegation`, `action`, `resource`, `policy_version`, and `evaluation_epoch_secs`.

### Important enums / errors
* `IdentityTrustStatus` – `UnverifiedClaim`, `LocalProvisional`, `Revoked`, `Rejected`.
* `IdentityError` – Covers validation, revocation, mismatched department, autonomy overflow, foreign registry instance, etc.

### Provenance (not fully shown)
The registry also provides `validate_process_provenance` and a `ProvenanceTracker` (omitted for brevity) that can issue the `LiveProvenanceVerificationSeal` after verifying the full delegation lineage.

---

## 3. Policy Evaluation – `core/titan-policy-core`

### Public API
* **`policy_evaluate(request: &PolicyRequest) -> PolicyResult`** – Legacy M1 simulation; always returns `execution_authorized() == false` and `trust_level == LegacyUnverifiedSimulationOnly`.
* **`policy_evaluate_authorized(request: &AuthorizedPolicyRequest) -> PolicyResult`** – Structural checks only; never authorizes execution (`ProvisionalIdentityOnly`).
* **`policy_evaluate_strict_provenance(request: &AuthorizedPolicyRequest, registry: &ProvisionalIdentityRegistry, tracker: &ProvenanceTracker) -> PolicyResult`** – (implementation hidden) the only path that can yield `PolicyTrustLevel::LiveProvenanceVerified` and `execution_authorized() == true`. It requires:
  1. `registry.verify_live_identity(&identity)`
  2. `tracker.verify_live_process_and_delegation_lineage(... )`
  3. A successful `LiveProvenanceVerificationSeal`.

### Result type
* **`PolicyResult`** – fields `decision: Decision`, `reason: String`, `audit_required: bool`, `policy_version: String`, plus private `execution_authorized` and `trust_level`. Constructors:
  * `new_legacy_unverified`
  * `new_provisional_identity_only`
  * `new_live_provenance_denied`
  * **private** `new_live_provenance_allowed(seal, ...)` – only callable from the strict evaluator.
* Accessors `execution_authorized()`, `trust_level()`.

---

## 4. Auditing – `core/titan-audit`

### Core types
* **`AuditEventKind`** – Stable names for event kinds (`policy.authorization_decision`, `identity.resolution`, …).
* **`AuditEvent`** – Private `event_id` (`AuditEventId`) and `sequence` (monotonic `u64`). Public fields include `event_kind`, `agent_id`, `resolved_agent_id`, `process_id`, `execution_id`, `delegation_id`, `action`, `resource`, `decision`, `reason`, `policy_version`, `artifact_ids`.
* **Construction helpers**
  * `from_legacy_request_sequenced(event_id, sequence, &PolicyRequest, &PolicyResult) -> Result<Self, AuditError>`
  * `from_authorized_request(event_id, sequence, &AuthorizedPolicyRequest, &PolicyResult, Option<ExecutionId>, Vec<ArtifactId>) -> Result<Self, AuditError>`
* **`AuditError`** – validation errors (zero sequence, duplicate artifact, malformed fields, etc.).
* **`InMemoryAuditSequencer`** (not displayed) – maintains `next_sequence: u64` with checked increment; on overflow returns `AuditError::SequenceOverflow`.

### Guarantees
* All events must be sequenced (`sequence != 0`).
* Event IDs are validated via the same typed‑ID validator as other identifiers.
* The sequencer is fail‑closed – overflow aborts before mutating state.

---

## 5. Intended Simulation Integration Sequence
The **foundation scenario** must orchestrate the crates in the exact order below so that policy evaluation is *fail‑closed* unless every check succeeds.

1. **Simulation Run Setup**
   * Generate a unique `ExecutionId` (typed ID).
   * Create a fresh `ProvisionalIdentityRegistry` (`registry = ProvisionalIdentityRegistry::new("simulation-registry")`).
   * Register the Engineering Department agent with `registry.register_agent(ProvisionalAgentEntry { agent_id: AgentId::new("eng_dept")?, department: "Engineering".into(), max_autonomy: AutonomyLevel::E3InternalOperations, revocation_reason: None })`.
2. **Identity Claim & Resolution**
   * Build an `AgentIdentity` (or directly a claim) for the simulated agent.
   * Call `registry.resolve_claim(&claim)` → `ResolvedAgentIdentity`.
   * Immediately call `registry.verify_live_identity(&resolved)` to ensure the token matches the registry instance and is not revoked.
3. **Process / Delegation Provenance**
   * Construct a `ProcessProvenance` (or reuse an existing one) describing the RDA process.
   * Use the `ProvenanceTracker` (instantiated once per simulation) to `verify_live_process_and_delegation_lineage(...)`. On success it returns a `LiveProvenanceVerificationSeal`.
4. **Policy Request Construction**
   * Populate an `AuthorizedPolicyRequest` with:
     * `identity: Some(resolved)`
     * `process: Some(process_provenance)`
     * `delegation: Some(delegation_record)` (if any; must be delegable via `Action::is_delegable_in_m1_1`)
     * `action: Action::CreateSandboxReport` (or another allowed action)
     * `resource: "dmc://engineering/sandbox/report"` (canonical URI)
     * `policy_version` and `evaluation_epoch_secs`.
5. **Policy Evaluation (strict path)**
   * Call `policy_evaluate_strict_provenance(&request, &registry, &tracker)`.
   * The function internally:
     * Re‑validates the identity via `registry.verify_live_identity`.
     * Checks provenance via the tracker, obtaining a `LiveProvenanceVerificationSeal`.
     * If both succeed and the action is permitted, returns `PolicyResult::new_live_provenance_allowed(seal, …)` which yields `execution_authorized() == true`.
6. **Execution Guard**
   * The simulation **must not** proceed to the harmless operation unless `policy_result.execution_authorized()` is true.
   * If false, abort and record a denial.
7. **Audit Event Creation**
   * Obtain a new `AuditEventId` (typed ID).
   * Increment the `InMemoryAuditSequencer` to get the next monotonic sequence.
   * Call `AuditEvent::from_authorized_request(event_id, sequence, &request, &policy_result, Some(execution_id), vec![])`.
   * Store the event (in‑memory vector or test harness) – no external I/O.
8. **Result Reporting**
   * Assemble a JSON report containing all fields listed in the task specification (scenario ID, run ID, agent identity, action, decision, audit refs, etc.).
   * Emit the JSON to `stdout` and also print a human‑readable summary.

---

## 6. Security Invariants Enforced by the Sequence
| Invariant | Enforced by | Failure Mode |
|---|---|---|
| **Policy denial prevents execution** | `PolicyResult::execution_authorized()` is private and only true for `LiveProvenanceVerified` results. | Simulation code checks the flag before any operation; compile‑time guarantee that the flag cannot be fabricated.
| **Identity cannot be forged** | `ResolvedAgentIdentity` can only be minted by `ProvisionalIdentityRegistry::resolve_claim` and verified by `verify_live_identity`. | Any mismatch results in `IdentityError` → policy evaluation returns denied.
| **Provenance must be live‑verified** | `LiveProvenanceVerificationSeal` is private; only `policy_evaluate_strict_provenance` can obtain it after successful tracker verification. | Without a seal, the strict evaluator falls back to `new_live_provenance_denied`.
| **Audit sequencing is monotonic and non‑zero** | `InMemoryAuditSequencer` uses checked arithmetic; `AuditEvent::validate` rejects zero sequence. | Overflow returns `AuditError::SequenceOverflow`; simulation aborts.
| **No external side‑effects** | The simulation crate performs *only* in‑memory operations; any shell or network call is disallowed by design. | Compile‑time lint (no `std::process::Command` usage) and code review.

---

## 7. Next Steps for Implementation
* Scaffold `simulation/dmc-simulator` crate and register it in the workspace.
* Implement the steps above in a deterministic CLI (`run foundation` and `run all`).
* Add unit tests covering each security regression scenario.
* Create the GitHub Actions workflow that builds the simulator, runs the foundation scenario, and archives the generated report.

---

*Generated on $(date -u) by Antigravity.*
