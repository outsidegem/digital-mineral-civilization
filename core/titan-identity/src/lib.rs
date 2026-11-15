//! M1.1 identity resolution, delegation validation, and provenance verification boundaries.
//!
//! # Security Assumptions and Limitations (M1.1)
//! - Cryptographic key generation, signing, and verification are **not** implemented in M1.1.
//! - [`ResolvedAgentIdentity`] has no public constructor; only [`ProvisionalIdentityRegistry::resolve_claim`]
//!   can mint a `LocalProvisional` identity, binding it to the issuing registry's unique `instance_id`.
//! - Live verification ([`ProvisionalIdentityRegistry::verify_live_identity`] and
//!   [`ProvenanceTracker::verify_live_process_and_delegation_lineage`]) detects subsequent agent
//!   or issuer revocation, multi-hop delegation ancestry violations, and unregistered or forged
//!   process provenance.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use dmc_types::{
    Action, AgentId, AgentIdentity, AgentIdentityClaim, ArtifactId, ArtifactProvenance,
    ArtifactProvenanceError, AutonomyLevel, DelegationId, DelegationRecord, ExecutionId,
    ExecutionIdentity, IdValidationError, IdentityTrustStatus, ProcessAuthorityBinding,
    ProcessProvenance, RdaProcessId, RevocationStatus, ToolInvocationId, ToolInvocationIdentity,
};

/// Sealed proof token attesting that live registry identity and provenance lineage verification
/// succeeded. Fields and constructor are private to `titan-identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProvenanceVerificationSeal {
    registry_instance_id: u64,
    agent_id: AgentId,
    process_id: RdaProcessId,
}

impl LiveProvenanceVerificationSeal {
    fn mint_after_live_verification(
        registry_instance_id: u64,
        agent_id: AgentId,
        process_id: RdaProcessId,
    ) -> Option<Self> {
        if registry_instance_id == 0 {
            return None;
        }
        Some(Self {
            registry_instance_id,
            agent_id,
            process_id,
        })
    }

    pub fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn process_id(&self) -> &RdaProcessId {
        &self.process_id
    }
}

static NEXT_REGISTRY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    EmptyAgentId,
    EmptyDepartment,
    InvalidAgentId(IdValidationError),
    InvalidDepartmentCharacters,
    UnverifiedIdentity,
    DuplicateAgentRegistration(String),
    UnknownAgent(String),
    RevokedIdentity {
        agent_id: String,
        reason: String,
    },
    DepartmentMismatch {
        expected: String,
        claimed: String,
    },
    AutonomyClaimExceedsRegistered {
        registered: AutonomyLevel,
        claimed: AutonomyLevel,
    },
    ReservedAuthorityNotResolvable,
    ForeignRegistryInstance {
        expected_instance_id: u64,
        actual_instance_id: u64,
    },
    UntrustedIdentityStatus(IdentityTrustStatus),
}

/// Representation of an agent identity after explicit resolution by a [`ProvisionalIdentityRegistry`].
///
/// There is **no public constructor** for `ResolvedAgentIdentity`. Only
/// [`ProvisionalIdentityRegistry::resolve_claim`] may mint an instance, binding it to the issuing
/// registry's unique `registry_instance_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgentIdentity {
    agent_id: AgentId,
    department: String,
    autonomy: AutonomyLevel,
    trust_status: IdentityTrustStatus,
    resolution_source: String,
    registry_instance_id: u64,
}

impl ResolvedAgentIdentity {
    fn mint_provisional(
        agent_id: AgentId,
        department: String,
        autonomy: AutonomyLevel,
        resolution_source: String,
        registry_instance_id: u64,
    ) -> Self {
        Self {
            agent_id,
            department,
            autonomy,
            trust_status: IdentityTrustStatus::LocalProvisional,
            resolution_source,
            registry_instance_id,
        }
    }

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn department(&self) -> &str {
        &self.department
    }

    pub fn autonomy(&self) -> AutonomyLevel {
        self.autonomy
    }

    pub fn trust_status(&self) -> IdentityTrustStatus {
        self.trust_status
    }

    pub fn resolution_source(&self) -> &str {
        &self.resolution_source
    }

    pub fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    /// Returns `true` if this identity holds a provisional status token (must still be verified
    /// against live registry state via [`ProvisionalIdentityRegistry::verify_live_identity`] for
    /// strict execution authorization).
    pub fn is_trusted_for_policy(&self) -> bool {
        self.trust_status == IdentityTrustStatus::LocalProvisional
            && self.registry_instance_id != 0
            && self.autonomy != AutonomyLevel::E5ReservedAuthority
    }
}

/// M1.1 policy evaluation request requiring an explicitly resolved [`ResolvedAgentIdentity`]
/// and supporting bounded process provenance and delegation verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPolicyRequest {
    pub identity: Option<ResolvedAgentIdentity>,
    pub process: Option<ProcessProvenance>,
    pub parent_process: Option<ProcessProvenance>,
    pub delegation: Option<DelegationRecord>,
    pub parent_delegation: Option<DelegationRecord>,
    pub action: Action,
    pub resource: String,
    pub policy_version: String,
    pub evaluation_epoch_secs: u64,
}

/// Validates required fields only; this is NOT proof of identity.
pub fn validate_claims(identity: &AgentIdentity) -> Result<(), IdentityError> {
    if identity.agent_id.trim().is_empty() {
        return Err(IdentityError::EmptyAgentId);
    }
    if identity.department.trim().is_empty() {
        return Err(IdentityError::EmptyDepartment);
    }
    let _ = AgentId::new(&identity.agent_id).map_err(IdentityError::InvalidAgentId)?;
    if identity.department.trim().chars().any(|c| c.is_control()) {
        return Err(IdentityError::InvalidDepartmentCharacters);
    }
    Err(IdentityError::UnverifiedIdentity)
}

/// Validates an [`AgentIdentityClaim`] structurally; never returns `Ok(())` because a claim
/// alone cannot establish identity without explicit resolution.
pub fn validate_identity_claim(claim: &AgentIdentityClaim) -> Result<(), IdentityError> {
    if claim.agent_id.trim().is_empty() {
        return Err(IdentityError::EmptyAgentId);
    }
    if claim.department.trim().is_empty() {
        return Err(IdentityError::EmptyDepartment);
    }
    let _ = AgentId::new(&claim.agent_id).map_err(IdentityError::InvalidAgentId)?;
    if claim.department.trim().chars().any(|c| c.is_control()) {
        return Err(IdentityError::InvalidDepartmentCharacters);
    }
    Err(IdentityError::UnverifiedIdentity)
}

/// Authoritative local registration entry in a [`ProvisionalIdentityRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalAgentEntry {
    pub agent_id: AgentId,
    pub department: String,
    pub max_autonomy: AutonomyLevel,
    pub revocation_reason: Option<String>,
}

/// In-memory provisional identity registry for M1.1.
///
/// Each registry instance receives a unique `instance_id` and is intentionally not `Clone`,
/// ensuring that [`ResolvedAgentIdentity`] tokens are verifiably bound to the exact registry
/// instance that issued them.
#[derive(Debug)]
pub struct ProvisionalIdentityRegistry {
    instance_id: u64,
    registry_id: String,
    entries: BTreeMap<AgentId, ProvisionalAgentEntry>,
}

impl Default for ProvisionalIdentityRegistry {
    fn default() -> Self {
        Self::new("m1.1-local-provisional-registry")
    }
}

impl ProvisionalIdentityRegistry {
    /// Creates a new provisional registry with a unique `instance_id`.
    pub fn new(registry_id: impl Into<String>) -> Self {
        let id = registry_id.into();
        let clean = if id.trim().is_empty() {
            "m1.1-local-provisional-registry".to_owned()
        } else {
            id.trim().to_owned()
        };
        let instance_id = NEXT_REGISTRY_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            instance_id,
            registry_id: clean,
            entries: BTreeMap::new(),
        }
    }

    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }

    /// Registers an agent in the local provisional registry.
    pub fn register_agent(&mut self, entry: ProvisionalAgentEntry) -> Result<(), IdentityError> {
        let dept = entry.department.trim();
        if dept.is_empty() {
            return Err(IdentityError::EmptyDepartment);
        }
        if dept.chars().any(|c| c.is_control()) {
            return Err(IdentityError::InvalidDepartmentCharacters);
        }
        if entry.max_autonomy == AutonomyLevel::E5ReservedAuthority {
            return Err(IdentityError::ReservedAuthorityNotResolvable);
        }
        if self.entries.contains_key(&entry.agent_id) {
            return Err(IdentityError::DuplicateAgentRegistration(
                entry.agent_id.as_str().to_owned(),
            ));
        }
        self.entries.insert(
            entry.agent_id.clone(),
            ProvisionalAgentEntry {
                agent_id: entry.agent_id,
                department: dept.to_owned(),
                max_autonomy: entry.max_autonomy,
                revocation_reason: entry.revocation_reason,
            },
        );
        Ok(())
    }

    /// Marks a registered agent identity as revoked.
    pub fn revoke_agent(
        &mut self,
        agent_id: &AgentId,
        reason: impl Into<String>,
    ) -> Result<(), IdentityError> {
        let Some(entry) = self.entries.get_mut(agent_id) else {
            return Err(IdentityError::UnknownAgent(agent_id.as_str().to_owned()));
        };
        let r = reason.into();
        entry.revocation_reason = Some(if r.trim().is_empty() {
            "revoked by local registry".to_owned()
        } else {
            r.trim().to_owned()
        });
        Ok(())
    }

    /// Explicitly resolves an untrusted [`AgentIdentityClaim`] against this provisional registry.
    pub fn resolve_claim(
        &self,
        claim: &AgentIdentityClaim,
    ) -> Result<ResolvedAgentIdentity, IdentityError> {
        if claim.agent_id.trim().is_empty() {
            return Err(IdentityError::EmptyAgentId);
        }
        if claim.department.trim().is_empty() {
            return Err(IdentityError::EmptyDepartment);
        }
        let agent_id = AgentId::new(&claim.agent_id).map_err(IdentityError::InvalidAgentId)?;
        let claimed_dept = claim.department.trim();
        if claimed_dept.chars().any(|c| c.is_control()) {
            return Err(IdentityError::InvalidDepartmentCharacters);
        }
        if claim.claimed_autonomy == AutonomyLevel::E5ReservedAuthority {
            return Err(IdentityError::ReservedAuthorityNotResolvable);
        }

        let Some(entry) = self.entries.get(&agent_id) else {
            return Err(IdentityError::UnknownAgent(agent_id.as_str().to_owned()));
        };

        if let Some(reason) = &entry.revocation_reason {
            return Err(IdentityError::RevokedIdentity {
                agent_id: agent_id.as_str().to_owned(),
                reason: reason.clone(),
            });
        }

        if entry.department != claimed_dept {
            return Err(IdentityError::DepartmentMismatch {
                expected: entry.department.clone(),
                claimed: claimed_dept.to_owned(),
            });
        }

        if claim.claimed_autonomy > entry.max_autonomy {
            return Err(IdentityError::AutonomyClaimExceedsRegistered {
                registered: entry.max_autonomy,
                claimed: claim.claimed_autonomy,
            });
        }

        Ok(ResolvedAgentIdentity::mint_provisional(
            agent_id,
            entry.department.clone(),
            claim.claimed_autonomy,
            self.registry_id.clone(),
            self.instance_id,
        ))
    }

    /// Verifies that a [`ResolvedAgentIdentity`] was issued by this exact registry instance and
    /// that its underlying agent registration has not been revoked or downgraded.
    pub fn verify_live_identity(
        &self,
        identity: &ResolvedAgentIdentity,
    ) -> Result<(), IdentityError> {
        if identity.registry_instance_id != self.instance_id
            || identity.resolution_source != self.registry_id
        {
            return Err(IdentityError::ForeignRegistryInstance {
                expected_instance_id: self.instance_id,
                actual_instance_id: identity.registry_instance_id,
            });
        }
        if identity.trust_status != IdentityTrustStatus::LocalProvisional {
            return Err(IdentityError::UntrustedIdentityStatus(
                identity.trust_status,
            ));
        }
        if identity.autonomy == AutonomyLevel::E5ReservedAuthority {
            return Err(IdentityError::ReservedAuthorityNotResolvable);
        }

        let entry = self.verify_live_agent_id(&identity.agent_id)?;
        if entry.department != identity.department {
            return Err(IdentityError::DepartmentMismatch {
                expected: entry.department.clone(),
                claimed: identity.department.clone(),
            });
        }
        if identity.autonomy > entry.max_autonomy {
            return Err(IdentityError::AutonomyClaimExceedsRegistered {
                registered: entry.max_autonomy,
                claimed: identity.autonomy,
            });
        }
        Ok(())
    }

    /// Verifies that `agent_id` is currently registered and active (not revoked) in this registry.
    pub fn verify_live_agent_id(
        &self,
        agent_id: &AgentId,
    ) -> Result<&ProvisionalAgentEntry, IdentityError> {
        let Some(entry) = self.entries.get(agent_id) else {
            return Err(IdentityError::UnknownAgent(agent_id.as_str().to_owned()));
        };
        if let Some(reason) = &entry.revocation_reason {
            return Err(IdentityError::RevokedIdentity {
                agent_id: agent_id.as_str().to_owned(),
                reason: reason.clone(),
            });
        }
        if entry.max_autonomy == AutonomyLevel::E5ReservedAuthority {
            return Err(IdentityError::ReservedAuthorityNotResolvable);
        }
        Ok(entry)
    }
}

/// Validation errors for [`DelegationRecord`] invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationValidationError {
    UntrustedIssuerIdentity,
    IssuerMismatch {
        expected: AgentId,
        actual: AgentId,
    },
    SelfDelegationCycle(DelegationId),
    ReservedAuthorityNotDelegable,
    AutonomyExceedsIssuer {
        issuer_autonomy: AutonomyLevel,
        delegated_autonomy: AutonomyLevel,
    },
    EmptyPermittedActions,
    NonDelegableAction(Action),
    ActionExceedsDelegatedAutonomy {
        action: Action,
        max_autonomy: AutonomyLevel,
    },
    InvalidExpirationWindow {
        issued_at: u64,
        expires_at: u64,
    },
    Expired {
        expires_at: u64,
        evaluation_time: u64,
    },
    Revoked {
        delegation_id: DelegationId,
        reason: String,
    },
    MissingParentDelegation(DelegationId),
    ParentDelegationIdMismatch {
        expected: DelegationId,
        actual: DelegationId,
    },
    ParentDelegationIssuerChainBroken {
        parent_recipient: AgentId,
        child_issuer: AgentId,
    },
    AuthorityExceedsParentDelegation {
        parent_max: AutonomyLevel,
        child_max: AutonomyLevel,
    },
    ActionOutsideParentDelegation(Action),
    ResourceScopeExceedsParentDelegation,
    ExpirationExceedsParentDelegation {
        parent_expires_at: u64,
        child_expires_at: u64,
    },
}

/// Validates a [`DelegationRecord`] against its issuer's resolved identity, optional parent
/// delegation, and current evaluation timestamp (`now_epoch_secs`).
pub fn validate_delegation(
    delegation: &DelegationRecord,
    issuer_identity: &ResolvedAgentIdentity,
    parent_delegation: Option<&DelegationRecord>,
    now_epoch_secs: u64,
) -> Result<(), DelegationValidationError> {
    if !issuer_identity.is_trusted_for_policy() {
        return Err(DelegationValidationError::UntrustedIssuerIdentity);
    }
    if issuer_identity.agent_id() != &delegation.issuer {
        return Err(DelegationValidationError::IssuerMismatch {
            expected: issuer_identity.agent_id().clone(),
            actual: delegation.issuer.clone(),
        });
    }
    validate_delegation_hop(delegation, parent_delegation, now_epoch_secs)?;

    if delegation.max_autonomy > issuer_identity.autonomy() {
        return Err(DelegationValidationError::AutonomyExceedsIssuer {
            issuer_autonomy: issuer_identity.autonomy(),
            delegated_autonomy: delegation.max_autonomy,
        });
    }

    Ok(())
}

/// Validates a single [`DelegationRecord`] and its immediate parent link (if present).
/// Multi-hop delegation chains are validated across all ancestors by [`ProvenanceTracker`].
pub fn validate_delegation_rules(
    delegation: &DelegationRecord,
    parent_delegation: Option<&DelegationRecord>,
    now_epoch_secs: u64,
) -> Result<(), DelegationValidationError> {
    validate_delegation_hop(delegation, parent_delegation, now_epoch_secs)
}

fn validate_delegation_single(
    delegation: &DelegationRecord,
    now_epoch_secs: u64,
) -> Result<(), DelegationValidationError> {
    if let RevocationStatus::Revoked { reason, .. } = &delegation.revocation_status {
        return Err(DelegationValidationError::Revoked {
            delegation_id: delegation.delegation_id.clone(),
            reason: reason.clone(),
        });
    }
    if delegation.expires_at_epoch_secs <= delegation.issued_at_epoch_secs {
        return Err(DelegationValidationError::InvalidExpirationWindow {
            issued_at: delegation.issued_at_epoch_secs,
            expires_at: delegation.expires_at_epoch_secs,
        });
    }
    if now_epoch_secs >= delegation.expires_at_epoch_secs {
        return Err(DelegationValidationError::Expired {
            expires_at: delegation.expires_at_epoch_secs,
            evaluation_time: now_epoch_secs,
        });
    }
    if delegation.max_autonomy == AutonomyLevel::E5ReservedAuthority {
        return Err(DelegationValidationError::ReservedAuthorityNotDelegable);
    }
    if delegation.permitted_actions.is_empty() {
        return Err(DelegationValidationError::EmptyPermittedActions);
    }
    for action in &delegation.permitted_actions {
        if !action.is_delegable_in_m1_1() {
            return Err(DelegationValidationError::NonDelegableAction(
                action.clone(),
            ));
        }
        if !action.is_allowed_for_autonomy(delegation.max_autonomy) {
            return Err(DelegationValidationError::ActionExceedsDelegatedAutonomy {
                action: action.clone(),
                max_autonomy: delegation.max_autonomy,
            });
        }
    }
    Ok(())
}

fn validate_delegation_hop(
    delegation: &DelegationRecord,
    parent_delegation: Option<&DelegationRecord>,
    now_epoch_secs: u64,
) -> Result<(), DelegationValidationError> {
    validate_delegation_single(delegation, now_epoch_secs)?;

    if let Some(expected_parent_id) = &delegation.parent_delegation_id {
        if expected_parent_id == &delegation.delegation_id {
            return Err(DelegationValidationError::SelfDelegationCycle(
                delegation.delegation_id.clone(),
            ));
        }
        let Some(parent) = parent_delegation else {
            return Err(DelegationValidationError::MissingParentDelegation(
                expected_parent_id.clone(),
            ));
        };
        if &parent.delegation_id != expected_parent_id {
            return Err(DelegationValidationError::ParentDelegationIdMismatch {
                expected: expected_parent_id.clone(),
                actual: parent.delegation_id.clone(),
            });
        }
        validate_delegation_single(parent, now_epoch_secs)?;

        if delegation.issuer != parent.recipient {
            return Err(
                DelegationValidationError::ParentDelegationIssuerChainBroken {
                    parent_recipient: parent.recipient.clone(),
                    child_issuer: delegation.issuer.clone(),
                },
            );
        }
        if delegation.max_autonomy > parent.max_autonomy {
            return Err(
                DelegationValidationError::AuthorityExceedsParentDelegation {
                    parent_max: parent.max_autonomy,
                    child_max: delegation.max_autonomy,
                },
            );
        }
        for action in &delegation.permitted_actions {
            if !parent.permitted_actions.contains(action) {
                return Err(DelegationValidationError::ActionOutsideParentDelegation(
                    action.clone(),
                ));
            }
        }
        if !delegation
            .resource_scope
            .is_subset_of(&parent.resource_scope)
        {
            return Err(DelegationValidationError::ResourceScopeExceedsParentDelegation);
        }
        if delegation.expires_at_epoch_secs > parent.expires_at_epoch_secs {
            return Err(
                DelegationValidationError::ExpirationExceedsParentDelegation {
                    parent_expires_at: parent.expires_at_epoch_secs,
                    child_expires_at: delegation.expires_at_epoch_secs,
                },
            );
        }
    }

    Ok(())
}

/// Validation errors for process, execution, tool invocation, and artifact provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceValidationError {
    EmptyEnvironment,
    EmptyPurpose,
    EmptyPermittedActions,
    EmptyToolName,
    ReservedAuthorityNotAllowed,
    ProcessActionExceedsProcessAutonomy {
        action: Action,
        effective_autonomy: AutonomyLevel,
    },
    SelfParentingProcess(RdaProcessId),
    ProcessLineageCycleDetected(RdaProcessId),
    DelegationCycleDetected(DelegationId),
    ChildProcessRequiresExplicitDelegation(RdaProcessId),
    MissingParentProcess(RdaProcessId),
    ParentProcessMismatch {
        expected: RdaProcessId,
        actual: RdaProcessId,
    },
    MissingDelegationForProcess(DelegationId),
    DelegationIdMismatch {
        expected: DelegationId,
        actual: DelegationId,
    },
    DelegationRecipientMismatch {
        delegation_recipient: AgentId,
        process_agent: AgentId,
    },
    DelegationRecipientProcessMismatch {
        expected_process: RdaProcessId,
        actual_process: RdaProcessId,
    },
    DelegationIssuerDoesNotMatchParentProcessAgent {
        delegation_issuer: AgentId,
        parent_process_agent: AgentId,
    },
    ChildDelegationMissingParentLink {
        expected_parent_delegation: DelegationId,
    },
    ChildProcessAutonomyExceedsDelegation {
        delegated_max: AutonomyLevel,
        process_autonomy: AutonomyLevel,
    },
    ChildProcessAutonomyExceedsParentProcess {
        parent_autonomy: AutonomyLevel,
        child_autonomy: AutonomyLevel,
    },
    ProcessActionNotInDelegation(Action),
    ProcessActionNotInParentProcess(Action),
    ProcessResourceScopeExceedsDelegation,
    ProcessResourceScopeExceedsParentProcess,
    DelegationInvalid(DelegationValidationError),
    ArtifactInvalid(ArtifactProvenanceError),
    IdentityInvalid(IdentityError),
    UnregisteredOrForgedProcess(RdaProcessId),
    UnregisteredOrForgedDelegation(DelegationId),
    DuplicateProcessId(RdaProcessId),
    DuplicateExecutionId(ExecutionId),
    DuplicateToolInvocationId(ToolInvocationId),
    DuplicateDelegationId(DelegationId),
    DuplicateArtifactId(ArtifactId),
    CrossKindIdentifierCollision(String),
    MissingProducingProcess(RdaProcessId),
    MissingProducingExecution(ExecutionId),
    ExecutionAgentMismatch {
        process_agent: AgentId,
        execution_agent: AgentId,
    },
    ToolInvocationProcessMismatch {
        execution_process: RdaProcessId,
        invocation_process: RdaProcessId,
    },
    ArtifactProcessMismatch {
        execution_process: RdaProcessId,
        artifact_process: RdaProcessId,
    },
    MissingParentArtifact(ArtifactId),
}

/// Validates a [`ProcessProvenance`] record against its optional parent process and delegation.
pub fn validate_process_provenance(
    process: &ProcessProvenance,
    parent_process: Option<&ProcessProvenance>,
    delegation: Option<&DelegationRecord>,
    parent_delegation: Option<&DelegationRecord>,
    now_epoch_secs: u64,
) -> Result<(), ProvenanceValidationError> {
    if process.creation_context.environment.trim().is_empty() {
        return Err(ProvenanceValidationError::EmptyEnvironment);
    }
    if process.creation_context.purpose.trim().is_empty() {
        return Err(ProvenanceValidationError::EmptyPurpose);
    }
    if process.effective_autonomy() == AutonomyLevel::E5ReservedAuthority {
        return Err(ProvenanceValidationError::ReservedAuthorityNotAllowed);
    }
    if process.permitted_actions().is_empty() {
        return Err(ProvenanceValidationError::EmptyPermittedActions);
    }
    for action in process.permitted_actions() {
        if !action.is_allowed_for_autonomy(process.effective_autonomy()) {
            return Err(
                ProvenanceValidationError::ProcessActionExceedsProcessAutonomy {
                    action: action.clone(),
                    effective_autonomy: process.effective_autonomy(),
                },
            );
        }
    }
    if process.parent_process_id.as_ref() == Some(&process.process_id) {
        return Err(ProvenanceValidationError::SelfParentingProcess(
            process.process_id.clone(),
        ));
    }

    // If this is a child process, it MUST have a parent process and an explicit DelegationRecord.
    if let Some(expected_parent_pid) = &process.parent_process_id {
        let Some(parent_proc) = parent_process else {
            return Err(ProvenanceValidationError::MissingParentProcess(
                expected_parent_pid.clone(),
            ));
        };
        if &parent_proc.process_id != expected_parent_pid {
            return Err(ProvenanceValidationError::ParentProcessMismatch {
                expected: expected_parent_pid.clone(),
                actual: parent_proc.process_id.clone(),
            });
        }
        if parent_proc.parent_process_id.as_ref() == Some(&process.process_id) {
            return Err(ProvenanceValidationError::ProcessLineageCycleDetected(
                process.process_id.clone(),
            ));
        }
        if process.delegation_id().is_none() {
            return Err(
                ProvenanceValidationError::ChildProcessRequiresExplicitDelegation(
                    process.process_id.clone(),
                ),
            );
        }

        if process.effective_autonomy() > parent_proc.effective_autonomy() {
            return Err(
                ProvenanceValidationError::ChildProcessAutonomyExceedsParentProcess {
                    parent_autonomy: parent_proc.effective_autonomy(),
                    child_autonomy: process.effective_autonomy(),
                },
            );
        }
        for action in process.permitted_actions() {
            if !parent_proc.permitted_actions().contains(action) {
                return Err(ProvenanceValidationError::ProcessActionNotInParentProcess(
                    action.clone(),
                ));
            }
        }
        if !process
            .resource_scope()
            .is_subset_of(parent_proc.resource_scope())
        {
            return Err(ProvenanceValidationError::ProcessResourceScopeExceedsParentProcess);
        }
    }

    match (&process.authority, delegation) {
        (ProcessAuthorityBinding::DirectAgentAuthority { .. }, Some(del)) => {
            return Err(ProvenanceValidationError::MissingDelegationForProcess(
                del.delegation_id.clone(),
            ));
        }
        (ProcessAuthorityBinding::DelegatedAuthority { delegation_id, .. }, None) => {
            return Err(ProvenanceValidationError::MissingDelegationForProcess(
                delegation_id.clone(),
            ));
        }
        (ProcessAuthorityBinding::DelegatedAuthority { delegation_id, .. }, Some(del)) => {
            if delegation_id != &del.delegation_id {
                return Err(ProvenanceValidationError::DelegationIdMismatch {
                    expected: delegation_id.clone(),
                    actual: del.delegation_id.clone(),
                });
            }
            validate_delegation_hop(del, parent_delegation, now_epoch_secs)
                .map_err(ProvenanceValidationError::DelegationInvalid)?;

            if del.recipient != process.parent_agent_id {
                return Err(ProvenanceValidationError::DelegationRecipientMismatch {
                    delegation_recipient: del.recipient.clone(),
                    process_agent: process.parent_agent_id.clone(),
                });
            }
            if let Some(target_proc) = &del.recipient_process {
                if target_proc != &process.process_id {
                    return Err(
                        ProvenanceValidationError::DelegationRecipientProcessMismatch {
                            expected_process: target_proc.clone(),
                            actual_process: process.process_id.clone(),
                        },
                    );
                }
            }
            if let Some(parent_proc) = parent_process {
                if del.issuer != parent_proc.parent_agent_id {
                    return Err(
                        ProvenanceValidationError::DelegationIssuerDoesNotMatchParentProcessAgent {
                            delegation_issuer: del.issuer.clone(),
                            parent_process_agent: parent_proc.parent_agent_id.clone(),
                        },
                    );
                }
                if let Some(parent_del_id) = parent_proc.delegation_id() {
                    if del.parent_delegation_id.as_ref() != Some(parent_del_id) {
                        return Err(
                            ProvenanceValidationError::ChildDelegationMissingParentLink {
                                expected_parent_delegation: parent_del_id.clone(),
                            },
                        );
                    }
                }
            }
            if process.effective_autonomy() > del.max_autonomy {
                return Err(
                    ProvenanceValidationError::ChildProcessAutonomyExceedsDelegation {
                        delegated_max: del.max_autonomy,
                        process_autonomy: process.effective_autonomy(),
                    },
                );
            }
            for action in process.permitted_actions() {
                if !del.permitted_actions.contains(action) {
                    return Err(ProvenanceValidationError::ProcessActionNotInDelegation(
                        action.clone(),
                    ));
                }
            }
            if !process.resource_scope().is_subset_of(&del.resource_scope) {
                return Err(ProvenanceValidationError::ProcessResourceScopeExceedsDelegation);
            }
        }
        (ProcessAuthorityBinding::DirectAgentAuthority { .. }, None) => {}
    }

    Ok(())
}

/// In-memory tracker that enforces unique process, execution, tool invocation, delegation,
/// and artifact identities and verifies complete acyclic provenance and delegation ancestry.
#[derive(Debug, Clone, Default)]
pub struct ProvenanceTracker {
    processes: BTreeMap<RdaProcessId, ProcessProvenance>,
    executions: BTreeMap<ExecutionId, ExecutionIdentity>,
    tool_invocations: BTreeMap<ToolInvocationId, ToolInvocationIdentity>,
    delegations: BTreeMap<DelegationId, DelegationRecord>,
    artifacts: BTreeMap<ArtifactId, ArtifactProvenance>,
    all_issued_ids: BTreeSet<String>,
}

impl ProvenanceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn claim_unique_id(&mut self, raw: &str) -> Result<(), ProvenanceValidationError> {
        if self.all_issued_ids.contains(raw) {
            return Err(ProvenanceValidationError::CrossKindIdentifierCollision(
                raw.to_owned(),
            ));
        }
        self.all_issued_ids.insert(raw.to_owned());
        Ok(())
    }

    pub fn register_delegation(
        &mut self,
        delegation: DelegationRecord,
        issuer_identity: &ResolvedAgentIdentity,
        now_epoch_secs: u64,
    ) -> Result<(), ProvenanceValidationError> {
        if self.delegations.contains_key(&delegation.delegation_id) {
            return Err(ProvenanceValidationError::DuplicateDelegationId(
                delegation.delegation_id,
            ));
        }
        let parent_del = delegation
            .parent_delegation_id
            .as_ref()
            .and_then(|pid| self.delegations.get(pid));
        validate_delegation(&delegation, issuer_identity, parent_del, now_epoch_secs)
            .map_err(ProvenanceValidationError::DelegationInvalid)?;

        // Also walk any deeper delegation ancestry to ensure multi-hop chain integrity and acyclicity.
        let mut visited = BTreeSet::new();
        visited.insert(delegation.delegation_id.clone());
        let mut cursor_parent_id = delegation.parent_delegation_id.clone();
        while let Some(pid) = cursor_parent_id {
            if !visited.insert(pid.clone()) {
                return Err(ProvenanceValidationError::DelegationCycleDetected(pid));
            }
            let Some(curr_parent) = self.delegations.get(&pid) else {
                return Err(ProvenanceValidationError::DelegationInvalid(
                    DelegationValidationError::MissingParentDelegation(pid),
                ));
            };
            let next_parent = curr_parent
                .parent_delegation_id
                .as_ref()
                .and_then(|gpid| self.delegations.get(gpid));
            validate_delegation_hop(curr_parent, next_parent, now_epoch_secs)
                .map_err(ProvenanceValidationError::DelegationInvalid)?;
            cursor_parent_id = curr_parent.parent_delegation_id.clone();
        }

        self.claim_unique_id(delegation.delegation_id.as_str())?;
        self.delegations
            .insert(delegation.delegation_id.clone(), delegation);
        Ok(())
    }

    pub fn register_process(
        &mut self,
        process: ProcessProvenance,
        now_epoch_secs: u64,
    ) -> Result<(), ProvenanceValidationError> {
        if self.processes.contains_key(&process.process_id) {
            return Err(ProvenanceValidationError::DuplicateProcessId(
                process.process_id,
            ));
        }
        let parent_proc = process
            .parent_process_id
            .as_ref()
            .and_then(|pid| self.processes.get(pid));
        let delegation = process
            .delegation_id()
            .and_then(|did| self.delegations.get(did));
        let parent_delegation = delegation
            .and_then(|d| d.parent_delegation_id.as_ref())
            .and_then(|pdid| self.delegations.get(pdid));

        validate_process_provenance(
            &process,
            parent_proc,
            delegation,
            parent_delegation,
            now_epoch_secs,
        )?;

        // Ensure complete ancestor process lineage is acyclic and exists in the tracker.
        let mut visited = BTreeSet::new();
        visited.insert(process.process_id.clone());
        let mut cursor_parent_pid = process.parent_process_id.clone();
        while let Some(pid) = cursor_parent_pid {
            if !visited.insert(pid.clone()) {
                return Err(ProvenanceValidationError::ProcessLineageCycleDetected(pid));
            }
            let Some(ancestor) = self.processes.get(&pid) else {
                return Err(ProvenanceValidationError::MissingParentProcess(pid));
            };
            cursor_parent_pid = ancestor.parent_process_id.clone();
        }

        self.claim_unique_id(process.process_id.as_str())?;
        self.processes.insert(process.process_id.clone(), process);
        Ok(())
    }

    pub fn register_execution(
        &mut self,
        execution: ExecutionIdentity,
    ) -> Result<(), ProvenanceValidationError> {
        if self.executions.contains_key(&execution.execution_id) {
            return Err(ProvenanceValidationError::DuplicateExecutionId(
                execution.execution_id,
            ));
        }
        let Some(process) = self.processes.get(&execution.process_id) else {
            return Err(ProvenanceValidationError::MissingProducingProcess(
                execution.process_id,
            ));
        };
        if process.parent_agent_id != execution.agent_id {
            return Err(ProvenanceValidationError::ExecutionAgentMismatch {
                process_agent: process.parent_agent_id.clone(),
                execution_agent: execution.agent_id,
            });
        }
        self.claim_unique_id(execution.execution_id.as_str())?;
        self.executions
            .insert(execution.execution_id.clone(), execution);
        Ok(())
    }

    pub fn register_tool_invocation(
        &mut self,
        invocation: ToolInvocationIdentity,
    ) -> Result<(), ProvenanceValidationError> {
        if invocation.tool_name.trim().is_empty() {
            return Err(ProvenanceValidationError::EmptyToolName);
        }
        if self
            .tool_invocations
            .contains_key(&invocation.invocation_id)
        {
            return Err(ProvenanceValidationError::DuplicateToolInvocationId(
                invocation.invocation_id,
            ));
        }
        let Some(execution) = self.executions.get(&invocation.execution_id) else {
            return Err(ProvenanceValidationError::MissingProducingExecution(
                invocation.execution_id,
            ));
        };
        if execution.process_id != invocation.process_id {
            return Err(ProvenanceValidationError::ToolInvocationProcessMismatch {
                execution_process: execution.process_id.clone(),
                invocation_process: invocation.process_id,
            });
        }
        self.claim_unique_id(invocation.invocation_id.as_str())?;
        self.tool_invocations
            .insert(invocation.invocation_id.clone(), invocation);
        Ok(())
    }

    pub fn register_artifact(
        &mut self,
        artifact: ArtifactProvenance,
    ) -> Result<(), ProvenanceValidationError> {
        artifact
            .validate()
            .map_err(ProvenanceValidationError::ArtifactInvalid)?;
        if self.artifacts.contains_key(&artifact.artifact_id) {
            return Err(ProvenanceValidationError::DuplicateArtifactId(
                artifact.artifact_id,
            ));
        }
        if !self.processes.contains_key(&artifact.producing_process_id) {
            return Err(ProvenanceValidationError::MissingProducingProcess(
                artifact.producing_process_id,
            ));
        }
        let Some(execution) = self.executions.get(&artifact.producing_execution_id) else {
            return Err(ProvenanceValidationError::MissingProducingExecution(
                artifact.producing_execution_id,
            ));
        };
        if execution.process_id != artifact.producing_process_id {
            return Err(ProvenanceValidationError::ArtifactProcessMismatch {
                execution_process: execution.process_id.clone(),
                artifact_process: artifact.producing_process_id,
            });
        }
        for parent_id in &artifact.parent_artifact_ids {
            if !self.artifacts.contains_key(parent_id) {
                return Err(ProvenanceValidationError::MissingParentArtifact(
                    parent_id.clone(),
                ));
            }
        }
        self.claim_unique_id(artifact.artifact_id.as_str())?;
        self.artifacts
            .insert(artifact.artifact_id.clone(), artifact);
        Ok(())
    }

    /// Verifies complete live identity, delegation ancestry, and acyclic process lineage against
    /// `registry` and `self`, returning a sealed [`LiveProvenanceVerificationSeal`] on success.
    pub fn verify_live_process_and_delegation_lineage(
        &self,
        registry: &ProvisionalIdentityRegistry,
        identity: &ResolvedAgentIdentity,
        process: &ProcessProvenance,
        supplied_delegation: Option<&DelegationRecord>,
        now_epoch_secs: u64,
    ) -> Result<LiveProvenanceVerificationSeal, ProvenanceValidationError> {
        registry
            .verify_live_identity(identity)
            .map_err(ProvenanceValidationError::IdentityInvalid)?;

        if &process.parent_agent_id != identity.agent_id() {
            return Err(ProvenanceValidationError::ExecutionAgentMismatch {
                process_agent: process.parent_agent_id.clone(),
                execution_agent: identity.agent_id().clone(),
            });
        }
        if process.effective_autonomy() > identity.autonomy() {
            return Err(
                ProvenanceValidationError::ChildProcessAutonomyExceedsParentProcess {
                    parent_autonomy: identity.autonomy(),
                    child_autonomy: process.effective_autonomy(),
                },
            );
        }

        // Verify the supplied process is registered in this tracker and has not been tampered with.
        let Some(registered_process) = self.processes.get(&process.process_id) else {
            return Err(ProvenanceValidationError::UnregisteredOrForgedProcess(
                process.process_id.clone(),
            ));
        };
        if registered_process != process {
            return Err(ProvenanceValidationError::UnregisteredOrForgedProcess(
                process.process_id.clone(),
            ));
        }

        // If a delegation was supplied in the request, verify it matches the process and tracker.
        if let Some(supplied_del) = supplied_delegation {
            if process.delegation_id() != Some(&supplied_del.delegation_id) {
                return Err(ProvenanceValidationError::MissingDelegationForProcess(
                    supplied_del.delegation_id.clone(),
                ));
            }
            let Some(registered_del) = self.delegations.get(&supplied_del.delegation_id) else {
                return Err(ProvenanceValidationError::UnregisteredOrForgedDelegation(
                    supplied_del.delegation_id.clone(),
                ));
            };
            if registered_del != supplied_del {
                return Err(ProvenanceValidationError::UnregisteredOrForgedDelegation(
                    supplied_del.delegation_id.clone(),
                ));
            }
        }

        // Walk the full process lineage up to the root process, verifying every ancestor process,
        // every ancestor agent's live revocation status, and every delegation chain along the way.
        let mut visited_procs = BTreeSet::new();
        let mut cursor_proc = registered_process;
        loop {
            if !visited_procs.insert(cursor_proc.process_id.clone()) {
                return Err(ProvenanceValidationError::ProcessLineageCycleDetected(
                    cursor_proc.process_id.clone(),
                ));
            }

            let agent_entry = registry
                .verify_live_agent_id(&cursor_proc.parent_agent_id)
                .map_err(ProvenanceValidationError::IdentityInvalid)?;
            if cursor_proc.effective_autonomy() > agent_entry.max_autonomy {
                return Err(ProvenanceValidationError::IdentityInvalid(
                    IdentityError::AutonomyClaimExceedsRegistered {
                        registered: agent_entry.max_autonomy,
                        claimed: cursor_proc.effective_autonomy(),
                    },
                ));
            }

            let parent_proc = match &cursor_proc.parent_process_id {
                Some(parent_pid) => {
                    let Some(pp) = self.processes.get(parent_pid) else {
                        return Err(ProvenanceValidationError::MissingParentProcess(
                            parent_pid.clone(),
                        ));
                    };
                    Some(pp)
                }
                None => None,
            };

            let delegation = match cursor_proc.delegation_id() {
                Some(del_id) => {
                    let Some(del) = self.delegations.get(del_id) else {
                        return Err(ProvenanceValidationError::UnregisteredOrForgedDelegation(
                            del_id.clone(),
                        ));
                    };
                    self.verify_complete_delegation_ancestry(del, registry, now_epoch_secs)?;
                    Some(del)
                }
                None => None,
            };

            let parent_delegation = delegation
                .and_then(|d| d.parent_delegation_id.as_ref())
                .and_then(|pdid| self.delegations.get(pdid));

            validate_process_provenance(
                cursor_proc,
                parent_proc,
                delegation,
                parent_delegation,
                now_epoch_secs,
            )?;

            match parent_proc {
                Some(pp) => cursor_proc = pp,
                None => break,
            }
        }

        LiveProvenanceVerificationSeal::mint_after_live_verification(
            registry.instance_id(),
            identity.agent_id().clone(),
            process.process_id.clone(),
        )
        .ok_or_else(|| {
            ProvenanceValidationError::UnregisteredOrForgedProcess(process.process_id.clone())
        })
    }

    fn verify_complete_delegation_ancestry(
        &self,
        leaf_delegation: &DelegationRecord,
        registry: &ProvisionalIdentityRegistry,
        now_epoch_secs: u64,
    ) -> Result<(), ProvenanceValidationError> {
        let mut visited_dels = BTreeSet::new();
        let mut curr = leaf_delegation;
        loop {
            if !visited_dels.insert(curr.delegation_id.clone()) {
                return Err(ProvenanceValidationError::DelegationCycleDetected(
                    curr.delegation_id.clone(),
                ));
            }

            // Both issuer and recipient of every delegation in the ancestry must be active/unrevoked.
            let issuer_entry = registry
                .verify_live_agent_id(&curr.issuer)
                .map_err(ProvenanceValidationError::IdentityInvalid)?;
            let _recipient_entry = registry
                .verify_live_agent_id(&curr.recipient)
                .map_err(ProvenanceValidationError::IdentityInvalid)?;

            if curr.max_autonomy > issuer_entry.max_autonomy {
                return Err(ProvenanceValidationError::DelegationInvalid(
                    DelegationValidationError::AutonomyExceedsIssuer {
                        issuer_autonomy: issuer_entry.max_autonomy,
                        delegated_autonomy: curr.max_autonomy,
                    },
                ));
            }

            let parent = match &curr.parent_delegation_id {
                Some(parent_id) => {
                    let Some(p) = self.delegations.get(parent_id) else {
                        return Err(ProvenanceValidationError::DelegationInvalid(
                            DelegationValidationError::MissingParentDelegation(parent_id.clone()),
                        ));
                    };
                    Some(p)
                }
                None => None,
            };

            validate_delegation_hop(curr, parent, now_epoch_secs)
                .map_err(ProvenanceValidationError::DelegationInvalid)?;

            match parent {
                Some(p) => curr = p,
                None => break,
            }
        }
        Ok(())
    }

    pub fn get_process(&self, id: &RdaProcessId) -> Option<&ProcessProvenance> {
        self.processes.get(id)
    }

    pub fn get_delegation(&self, id: &DelegationId) -> Option<&DelegationRecord> {
        self.delegations.get(id)
    }

    pub fn get_execution(&self, id: &ExecutionId) -> Option<&ExecutionIdentity> {
        self.executions.get(id)
    }

    pub fn get_artifact(&self, id: &ArtifactId) -> Option<&ArtifactProvenance> {
        self.artifacts.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_types::{
        ArtifactType, ContentDigest, DigestAlgorithm, ProcessCreationContext, ResourceScope, TaskId,
    };

    #[test]
    fn claims_are_not_mistaken_for_cryptographic_identity() {
        let id = AgentIdentity {
            agent_id: "agent-1".into(),
            department: "Research".into(),
            autonomy: AutonomyLevel::E2Sandbox,
        };
        assert_eq!(validate_claims(&id), Err(IdentityError::UnverifiedIdentity));
    }

    #[test]
    fn empty_and_malformed_identity_claims_fail_validation() {
        let empty_id = AgentIdentity {
            agent_id: "   ".into(),
            department: "Research".into(),
            autonomy: AutonomyLevel::E2Sandbox,
        };
        assert_eq!(validate_claims(&empty_id), Err(IdentityError::EmptyAgentId));

        let empty_dept = AgentIdentity {
            agent_id: "agent-1".into(),
            department: "".into(),
            autonomy: AutonomyLevel::E2Sandbox,
        };
        assert_eq!(
            validate_claims(&empty_dept),
            Err(IdentityError::EmptyDepartment)
        );

        let whitespace_in_id = AgentIdentityClaim {
            agent_id: "agent 1".into(),
            department: "Research".into(),
            claimed_autonomy: AutonomyLevel::E2Sandbox,
        };
        assert!(matches!(
            validate_identity_claim(&whitespace_in_id),
            Err(IdentityError::InvalidAgentId(_))
        ));
    }

    #[test]
    fn resolved_identity_bound_to_issuing_registry_and_detects_post_resolution_revocation() {
        let mut registry_a = ProvisionalIdentityRegistry::new("registry-a");
        let mut registry_b = ProvisionalIdentityRegistry::new("registry-a"); // same name, distinct instance_id
        assert_ne!(registry_a.instance_id(), registry_b.instance_id());

        let agent_id = AgentId::new("agent-research-001").unwrap();
        for reg in [&mut registry_a, &mut registry_b] {
            reg.register_agent(ProvisionalAgentEntry {
                agent_id: agent_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E2Sandbox,
                revocation_reason: None,
            })
            .unwrap();
        }

        let claim = AgentIdentityClaim {
            agent_id: "agent-research-001".into(),
            department: "Research".into(),
            claimed_autonomy: AutonomyLevel::E2Sandbox,
        };
        let resolved_from_a = registry_a.resolve_claim(&claim).unwrap();
        assert_eq!(registry_a.verify_live_identity(&resolved_from_a), Ok(()));

        // Passing identity resolved by registry_a into registry_b is rejected
        assert_eq!(
            registry_b.verify_live_identity(&resolved_from_a),
            Err(IdentityError::ForeignRegistryInstance {
                expected_instance_id: registry_b.instance_id(),
                actual_instance_id: registry_a.instance_id(),
            })
        );

        // Revoking the agent in registry_a invalidates previously resolved identity
        registry_a
            .revoke_agent(&agent_id, "compromised session")
            .unwrap();
        assert_eq!(
            registry_a.verify_live_identity(&resolved_from_a),
            Err(IdentityError::RevokedIdentity {
                agent_id: "agent-research-001".into(),
                reason: "compromised session".into(),
            })
        );
    }

    #[test]
    fn unique_process_execution_and_artifact_identities_and_parent_child_delegation() {
        let mut registry = ProvisionalIdentityRegistry::new("test-registry");
        let parent_agent_id = AgentId::new("agent-parent").unwrap();
        let child_agent_id = AgentId::new("agent-child").unwrap();
        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: parent_agent_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E3InternalOperations,
                revocation_reason: None,
            })
            .unwrap();
        let parent_resolved = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-parent".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E3InternalOperations,
            })
            .unwrap();

        let mut tracker = ProvenanceTracker::new();
        let parent_scope = ResourceScope::new(vec!["sandbox://research".into()]).unwrap();
        let child_scope = ResourceScope::new(vec!["sandbox://research/subtask".into()]).unwrap();

        let root_proc = ProcessProvenance {
            process_id: RdaProcessId::new("proc-root-1").unwrap(),
            parent_agent_id: parent_agent_id.clone(),
            parent_process_id: None,
            originating_task_id: TaskId::new("task-100").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_000,
                environment: "termux-sandbox".into(),
                purpose: "root research coordination".into(),
            },
            authority: ProcessAuthorityBinding::DirectAgentAuthority {
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::ReadKnowledge, Action::CreateSandboxReport],
                resource_scope: parent_scope,
            },
        };
        tracker.register_process(root_proc.clone(), 1_005).unwrap();

        assert_eq!(
            tracker.register_process(root_proc, 1_005),
            Err(ProvenanceValidationError::DuplicateProcessId(
                RdaProcessId::new("proc-root-1").unwrap()
            ))
        );

        let unbacked_child = ProcessProvenance {
            process_id: RdaProcessId::new("proc-child-unbacked").unwrap(),
            parent_agent_id: child_agent_id.clone(),
            parent_process_id: Some(RdaProcessId::new("proc-root-1").unwrap()),
            originating_task_id: TaskId::new("task-101").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_010,
                environment: "termux-sandbox".into(),
                purpose: "unbacked child".into(),
            },
            authority: ProcessAuthorityBinding::DirectAgentAuthority {
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::ReadKnowledge],
                resource_scope: child_scope.clone(),
            },
        };
        assert_eq!(
            tracker.register_process(unbacked_child, 1_010),
            Err(
                ProvenanceValidationError::ChildProcessRequiresExplicitDelegation(
                    RdaProcessId::new("proc-child-unbacked").unwrap()
                )
            )
        );

        let del_id = DelegationId::new("del-1").unwrap();
        let delegation = DelegationRecord {
            delegation_id: del_id.clone(),
            issuer: parent_agent_id,
            recipient: child_agent_id.clone(),
            recipient_process: Some(RdaProcessId::new("proc-child-1").unwrap()),
            max_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::ReadKnowledge],
            resource_scope: child_scope.clone(),
            issued_at_epoch_secs: 1_000,
            expires_at_epoch_secs: 2_000,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: None,
        };
        tracker
            .register_delegation(delegation, &parent_resolved, 1_010)
            .unwrap();

        let valid_child = ProcessProvenance {
            process_id: RdaProcessId::new("proc-child-1").unwrap(),
            parent_agent_id: child_agent_id.clone(),
            parent_process_id: Some(RdaProcessId::new("proc-root-1").unwrap()),
            originating_task_id: TaskId::new("task-101").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_010,
                environment: "termux-sandbox".into(),
                purpose: "valid delegated child".into(),
            },
            authority: ProcessAuthorityBinding::DelegatedAuthority {
                delegation_id: del_id,
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::ReadKnowledge],
                resource_scope: child_scope,
            },
        };
        tracker.register_process(valid_child, 1_010).unwrap();

        let exec = ExecutionIdentity {
            execution_id: ExecutionId::new("exec-1").unwrap(),
            process_id: RdaProcessId::new("proc-child-1").unwrap(),
            agent_id: child_agent_id,
        };
        tracker.register_execution(exec).unwrap();

        let digest = ContentDigest::new(DigestAlgorithm::Sha256, "b".repeat(64)).unwrap();
        let root_artifact = ArtifactProvenance {
            artifact_id: ArtifactId::new("art-root").unwrap(),
            content_digest: digest,
            artifact_type: ArtifactType::KnowledgeSnapshot,
            producing_execution_id: ExecutionId::new("exec-1").unwrap(),
            producing_process_id: RdaProcessId::new("proc-child-1").unwrap(),
            parent_artifact_ids: vec![],
        };
        tracker.register_artifact(root_artifact).unwrap();
    }

    #[test]
    fn multi_hop_delegation_chain_and_action_tier_bounds() {
        let mut registry = ProvisionalIdentityRegistry::new("delegation-test-registry");
        let root_id = AgentId::new("agent-root").unwrap();
        let mid_id = AgentId::new("agent-mid").unwrap();
        let leaf_id = AgentId::new("agent-leaf").unwrap();
        let subleaf_id = AgentId::new("agent-subleaf").unwrap();

        for (id, level) in [
            (root_id.clone(), AutonomyLevel::E3InternalOperations),
            (mid_id.clone(), AutonomyLevel::E2Sandbox),
            (leaf_id.clone(), AutonomyLevel::E2Sandbox),
            (subleaf_id.clone(), AutonomyLevel::E0Observe),
        ] {
            registry
                .register_agent(ProvisionalAgentEntry {
                    agent_id: id,
                    department: "Research".into(),
                    max_autonomy: level,
                    revocation_reason: None,
                })
                .unwrap();
        }

        let root_res = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-root".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E3InternalOperations,
            })
            .unwrap();
        let mid_res = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-mid".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();
        let leaf_res = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-leaf".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();

        // Delegation with E0Observe cannot permit CreateSandboxReport
        let bad_tier_del = DelegationRecord {
            delegation_id: DelegationId::new("del-bad-tier").unwrap(),
            issuer: root_id.clone(),
            recipient: subleaf_id.clone(),
            recipient_process: None,
            max_autonomy: AutonomyLevel::E0Observe,
            permitted_actions: vec![Action::CreateSandboxReport],
            resource_scope: ResourceScope::new(vec!["sandbox://research".into()]).unwrap(),
            issued_at_epoch_secs: 1_000,
            expires_at_epoch_secs: 2_000,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: None,
        };
        assert_eq!(
            validate_delegation(&bad_tier_del, &root_res, None, 1_500),
            Err(DelegationValidationError::ActionExceedsDelegatedAutonomy {
                action: Action::CreateSandboxReport,
                max_autonomy: AutonomyLevel::E0Observe,
            })
        );

        // 3-hop delegation chain in ProvenanceTracker (del-1 -> del-2 -> del-3)
        let mut tracker = ProvenanceTracker::new();
        let del1 = DelegationRecord {
            delegation_id: DelegationId::new("del-1").unwrap(),
            issuer: root_id,
            recipient: mid_id.clone(),
            recipient_process: None,
            max_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::ReadKnowledge, Action::CreateSandboxReport],
            resource_scope: ResourceScope::new(vec!["sandbox://research".into()]).unwrap(),
            issued_at_epoch_secs: 1_000,
            expires_at_epoch_secs: 2_000,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: None,
        };
        tracker
            .register_delegation(del1.clone(), &root_res, 1_100)
            .unwrap();

        let del2 = DelegationRecord {
            delegation_id: DelegationId::new("del-2").unwrap(),
            issuer: mid_id,
            recipient: leaf_id.clone(),
            recipient_process: None,
            max_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::ReadKnowledge],
            resource_scope: ResourceScope::new(vec!["sandbox://research/sub".into()]).unwrap(),
            issued_at_epoch_secs: 1_100,
            expires_at_epoch_secs: 1_900,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: Some(del1.delegation_id),
        };
        tracker
            .register_delegation(del2.clone(), &mid_res, 1_200)
            .unwrap();

        let del3 = DelegationRecord {
            delegation_id: DelegationId::new("del-3").unwrap(),
            issuer: leaf_id,
            recipient: subleaf_id,
            recipient_process: None,
            max_autonomy: AutonomyLevel::E0Observe,
            permitted_actions: vec![Action::ReadKnowledge],
            resource_scope: ResourceScope::new(vec!["sandbox://research/sub/notes".into()])
                .unwrap(),
            issued_at_epoch_secs: 1_200,
            expires_at_epoch_secs: 1_800,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: Some(del2.delegation_id),
        };
        tracker.register_delegation(del3, &leaf_res, 1_300).unwrap();
    }
}
