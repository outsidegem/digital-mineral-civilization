//! Shared, dependency-free domain types for the DMC constitutional runtime.
//!
//! # M1.1 Security Note
//! - [`AgentIdentity`] and [`AgentIdentityClaim`] represent **unverified caller claims**.
//! - Resolved identities (`titan_identity::ResolvedAgentIdentity`) can only be minted by
//!   `titan_identity::ProvisionalIdentityRegistry::resolve_claim`; in M1.1 this represents
//!   local provisional resolution, **not** cryptographic authentication.
//! - [`ContentDigest`] proves content correspondence only, **not** authorship or origin.

use std::fmt;

/// Constitutional autonomy tiers ordered from lowest (`E0Observe`) to highest (`E5ReservedAuthority`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AutonomyLevel {
    E0Observe,
    E1Plan,
    E2Sandbox,
    E3InternalOperations,
    E4BoundedProduction,
    E5ReservedAuthority,
}

impl AutonomyLevel {
    /// Stable, serialization-safe identifier for this autonomy level.
    pub fn stable_name(&self) -> &'static str {
        match self {
            Self::E0Observe => "e0_observe",
            Self::E1Plan => "e1_plan",
            Self::E2Sandbox => "e2_sandbox",
            Self::E3InternalOperations => "e3_internal_operations",
            Self::E4BoundedProduction => "e4_bounded_production",
            Self::E5ReservedAuthority => "e5_reserved_authority",
        }
    }
}

/// M1 legacy agent identity claim structure.
///
/// # Security Warning
/// This struct contains caller-supplied fields including a self-asserted [`AutonomyLevel`].
/// It is **not** a cryptographically verified or registry-resolved identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub department: String,
    pub autonomy: AutonomyLevel,
}

impl AgentIdentity {
    /// Converts this M1 structure into an explicit [`AgentIdentityClaim`].
    pub fn to_claim(&self) -> AgentIdentityClaim {
        AgentIdentityClaim {
            agent_id: self.agent_id.clone(),
            department: self.department.clone(),
            claimed_autonomy: self.autonomy,
        }
    }
}

/// Explicit representation of an untrusted, caller-supplied agent identity claim.
///
/// Untrusted claims must never be treated as verified identities or converted directly
/// into `ResolvedAgentIdentity` without explicit registry resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentityClaim {
    pub agent_id: String,
    pub department: String,
    pub claimed_autonomy: AutonomyLevel,
}

impl From<&AgentIdentity> for AgentIdentityClaim {
    fn from(identity: &AgentIdentity) -> Self {
        identity.to_claim()
    }
}

impl From<AgentIdentity> for AgentIdentityClaim {
    fn from(identity: AgentIdentity) -> Self {
        Self {
            agent_id: identity.agent_id,
            department: identity.department,
            claimed_autonomy: identity.autonomy,
        }
    }
}

/// Resolution and trust status of an identity within the M1.1 runtime.
///
/// Note: No `CryptographicallyVerified` variant exists in M1.1 because cryptographic
/// key management and signature verification are intentionally deferred to M3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityTrustStatus {
    /// Raw caller-supplied claim; never valid for authorized policy execution.
    UnverifiedClaim,
    /// Resolved against a local in-memory provisional registry (M1.1 only).
    /// Does NOT provide cryptographic authenticity, non-repudiation, or tamper resistance.
    LocalProvisional,
    /// Identity registration has been explicitly revoked.
    Revoked,
    /// Claim resolution was rejected due to unknown identity or attribute mismatch.
    Rejected,
}

impl IdentityTrustStatus {
    /// Stable name for audit and diagnostic records.
    pub fn stable_name(&self) -> &'static str {
        match self {
            Self::UnverifiedClaim => "unverified_claim",
            Self::LocalProvisional => "local_provisional",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }
}

/// Validation error for typed domain identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdValidationError {
    Empty { kind: &'static str },
    InvalidCharacters { kind: &'static str },
}

impl fmt::Display for IdValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(f, "{kind} identifier must not be empty"),
            Self::InvalidCharacters { kind } => {
                write!(
                    f,
                    "{kind} identifier must not contain whitespace or control characters"
                )
            }
        }
    }
}

fn validate_identifier(raw: &str, kind: &'static str) -> Result<String, IdValidationError> {
    if raw.is_empty() || raw.trim().is_empty() {
        return Err(IdValidationError::Empty { kind });
    }
    if raw != raw.trim() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(IdValidationError::InvalidCharacters { kind });
    }
    Ok(raw.to_owned())
}

macro_rules! define_typed_id {
    ($(#[$meta:meta])* $name:ident, $kind_label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs a new typed identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, IdValidationError> {
                let raw = value.into();
                validate_identifier(&raw, $kind_label).map(Self)
            }

            /// Returns the validated identifier string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_typed_id!(
    /// Distinct identifier for a DMC agent.
    AgentId,
    "agent"
);

define_typed_id!(
    /// Distinct identifier for an RDA process instance.
    RdaProcessId,
    "rda_process"
);

define_typed_id!(
    /// Distinct identifier for an execution run.
    ExecutionId,
    "execution"
);

define_typed_id!(
    /// Distinct identifier for a tool invocation record.
    ToolInvocationId,
    "tool_invocation"
);

define_typed_id!(
    /// Distinct identifier for a produced or referenced artifact.
    ArtifactId,
    "artifact"
);

define_typed_id!(
    /// Distinct identifier for an explicit authority delegation record.
    DelegationId,
    "delegation"
);

define_typed_id!(
    /// Distinct identifier for an originating task.
    TaskId,
    "task"
);

define_typed_id!(
    /// Distinct stable identifier for an audit event.
    AuditEventId,
    "audit_event"
);

/// Execution identity binding an [`ExecutionId`] to its owning process and agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub execution_id: ExecutionId,
    pub process_id: RdaProcessId,
    pub agent_id: AgentId,
}

/// Tool invocation identity record binding a [`ToolInvocationId`] to its execution and process.
///
/// Note: External tool execution and shell execution are not enabled in M1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocationIdentity {
    pub invocation_id: ToolInvocationId,
    pub execution_id: ExecutionId,
    pub process_id: RdaProcessId,
    pub tool_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    CreateSandboxReport,
    ReadKnowledge,
    RunUnitTests,
    TransferTreasuryFunds,
    DeployProduction,
    Unknown(String),
}

impl Action {
    /// Returns an explicit, stable action name suitable for audit records and policy serialization.
    /// Does not rely on `fmt::Debug`.
    pub fn stable_name(&self) -> String {
        match self {
            Self::CreateSandboxReport => "create_sandbox_report".to_owned(),
            Self::ReadKnowledge => "read_knowledge".to_owned(),
            Self::RunUnitTests => "run_unit_tests".to_owned(),
            Self::TransferTreasuryFunds => "transfer_treasury_funds".to_owned(),
            Self::DeployProduction => "deploy_production".to_owned(),
            Self::Unknown(raw) => {
                let sanitized = raw.trim();
                if sanitized.is_empty() {
                    "unknown:unspecified".to_owned()
                } else {
                    format!("unknown:{sanitized}")
                }
            }
        }
    }

    /// Returns `true` if this action is permitted at `autonomy` under the M1/M1.1 baseline rules.
    pub fn is_allowed_for_autonomy(&self, autonomy: AutonomyLevel) -> bool {
        if autonomy == AutonomyLevel::E5ReservedAuthority {
            return false;
        }
        match (self, autonomy) {
            (
                Self::ReadKnowledge,
                AutonomyLevel::E0Observe
                | AutonomyLevel::E1Plan
                | AutonomyLevel::E2Sandbox
                | AutonomyLevel::E3InternalOperations
                | AutonomyLevel::E4BoundedProduction,
            ) => true,
            (
                Self::CreateSandboxReport | Self::RunUnitTests,
                AutonomyLevel::E2Sandbox
                | AutonomyLevel::E3InternalOperations
                | AutonomyLevel::E4BoundedProduction,
            ) => true,
            (Self::TransferTreasuryFunds | Self::DeployProduction | Self::Unknown(_), _) => false,
            _ => false,
        }
    }

    /// Returns `true` if this action is eligible for delegation in M1.1.
    /// Treasury transfers, production deployments, and unknown actions cannot be delegated.
    pub fn is_delegable_in_m1_1(&self) -> bool {
        matches!(
            self,
            Self::CreateSandboxReport | Self::ReadKnowledge | Self::RunUnitTests
        )
    }
}

/// Validation error for [`ResourceScope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceScopeError {
    EmptyScopeList,
    EmptyResourcePattern,
    UnboundedWildcardNotAllowed,
    InvalidResourceCharacters,
    MissingOrInvalidScheme,
    EmptyPathSegment,
    TraversalSegmentNotAllowed,
    ForbiddenUriCharacters,
}

/// Validates and canonicalizes a resource URI (`<scheme>://<segment>(/<segment>)*`).
///
/// Rejects:
/// - Leading/trailing whitespace or control characters
/// - Wildcards (`*`), backslashes (`\`), percent-encoding (`%`), query (`?`), fragment (`#`)
/// - Missing or repeated `"://"` scheme separators or invalid scheme characters
/// - Leading/trailing slashes on the authority/path or empty segments (`//`)
/// - Dot segments (`.` or `..`) or any segment containing `..`
pub fn validate_canonical_resource_uri(raw: &str) -> Result<String, ResourceScopeError> {
    if raw.is_empty() {
        return Err(ResourceScopeError::EmptyResourcePattern);
    }
    if raw != raw.trim() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ResourceScopeError::InvalidResourceCharacters);
    }
    if raw.contains('*') {
        return Err(ResourceScopeError::UnboundedWildcardNotAllowed);
    }
    if raw
        .chars()
        .any(|c| matches!(c, '\\' | '%' | '?' | '#' | '@' | ':') && c != ':')
        || raw.contains('\\')
        || raw.contains('%')
        || raw.contains('?')
        || raw.contains('#')
    {
        return Err(ResourceScopeError::ForbiddenUriCharacters);
    }

    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err(ResourceScopeError::MissingOrInvalidScheme);
    };
    if scheme.is_empty() || rest.contains("://") || rest.contains(':') {
        return Err(ResourceScopeError::MissingOrInvalidScheme);
    }
    let mut scheme_chars = scheme.chars();
    let Some(first_scheme) = scheme_chars.next() else {
        return Err(ResourceScopeError::MissingOrInvalidScheme);
    };
    if !first_scheme.is_ascii_lowercase()
        || !scheme_chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
    {
        return Err(ResourceScopeError::MissingOrInvalidScheme);
    }

    if rest.is_empty() || rest.starts_with('/') || rest.ends_with('/') {
        return Err(ResourceScopeError::EmptyPathSegment);
    }

    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(ResourceScopeError::EmptyPathSegment);
        }
        if segment == "." || segment == ".." || segment.contains("..") {
            return Err(ResourceScopeError::TraversalSegmentNotAllowed);
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(ResourceScopeError::ForbiddenUriCharacters);
        }
    }

    Ok(raw.to_owned())
}

/// Bounded resource scope represented as a non-empty set of canonical URI prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceScope {
    allowed_prefixes: Vec<String>,
}

impl ResourceScope {
    /// Constructs a bounded [`ResourceScope`] from one or more strict canonical resource prefixes.
    pub fn new(prefixes: Vec<String>) -> Result<Self, ResourceScopeError> {
        if prefixes.is_empty() {
            return Err(ResourceScopeError::EmptyScopeList);
        }
        let mut normalized = Vec::with_capacity(prefixes.len());
        for raw in prefixes {
            let clean = validate_canonical_resource_uri(&raw)?;
            if !normalized.contains(&clean) {
                normalized.push(clean);
            }
        }
        Ok(Self {
            allowed_prefixes: normalized,
        })
    }

    pub fn allowed_prefixes(&self) -> &[String] {
        &self.allowed_prefixes
    }

    /// Checks whether `resource` is a valid canonical URI and falls within any allowed prefix
    /// on a strict path-segment boundary.
    pub fn matches_resource(&self, resource: &str) -> bool {
        let Ok(candidate) = validate_canonical_resource_uri(resource) else {
            return false;
        };
        self.allowed_prefixes
            .iter()
            .any(|prefix| prefix_contains(prefix, &candidate))
    }

    /// Returns `true` if every allowed prefix in `self` is contained within `parent`.
    pub fn is_subset_of(&self, parent: &ResourceScope) -> bool {
        !self.allowed_prefixes.is_empty()
            && self
                .allowed_prefixes
                .iter()
                .all(|prefix| parent.matches_resource(prefix))
    }
}

fn prefix_contains(prefix: &str, candidate: &str) -> bool {
    if candidate == prefix {
        return true;
    }
    if let Some(rest) = candidate.strip_prefix(prefix) {
        return rest.starts_with('/');
    }
    false
}

/// Revocation status of a [`DelegationRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Active,
    Revoked {
        revocation_id: String,
        revoked_at_epoch_secs: u64,
        reason: String,
    },
}

/// Explicit, bounded authority delegation between an issuing agent and a recipient agent/process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRecord {
    pub delegation_id: DelegationId,
    pub issuer: AgentId,
    pub recipient: AgentId,
    pub recipient_process: Option<RdaProcessId>,
    pub max_autonomy: AutonomyLevel,
    pub permitted_actions: Vec<Action>,
    pub resource_scope: ResourceScope,
    pub issued_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
    pub revocation_status: RevocationStatus,
    pub parent_delegation_id: Option<DelegationId>,
}

/// Context recorded when an RDA process is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCreationContext {
    pub created_at_epoch_secs: u64,
    pub environment: String,
    pub purpose: String,
}

/// Authority assigned to an RDA process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAuthorityBinding {
    /// Root process operating directly under its parent agent's resolved authority.
    DirectAgentAuthority {
        effective_autonomy: AutonomyLevel,
        permitted_actions: Vec<Action>,
        resource_scope: ResourceScope,
    },
    /// Process operating under an explicit, bounded [`DelegationRecord`].
    DelegatedAuthority {
        delegation_id: DelegationId,
        effective_autonomy: AutonomyLevel,
        permitted_actions: Vec<Action>,
        resource_scope: ResourceScope,
    },
}

/// Provenance and authority record for an RDA process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessProvenance {
    pub process_id: RdaProcessId,
    pub parent_agent_id: AgentId,
    pub parent_process_id: Option<RdaProcessId>,
    pub originating_task_id: TaskId,
    pub creation_context: ProcessCreationContext,
    pub authority: ProcessAuthorityBinding,
}

impl ProcessProvenance {
    pub fn effective_autonomy(&self) -> AutonomyLevel {
        match &self.authority {
            ProcessAuthorityBinding::DirectAgentAuthority {
                effective_autonomy, ..
            }
            | ProcessAuthorityBinding::DelegatedAuthority {
                effective_autonomy, ..
            } => *effective_autonomy,
        }
    }

    pub fn permitted_actions(&self) -> &[Action] {
        match &self.authority {
            ProcessAuthorityBinding::DirectAgentAuthority {
                permitted_actions, ..
            }
            | ProcessAuthorityBinding::DelegatedAuthority {
                permitted_actions, ..
            } => permitted_actions,
        }
    }

    pub fn resource_scope(&self) -> &ResourceScope {
        match &self.authority {
            ProcessAuthorityBinding::DirectAgentAuthority { resource_scope, .. }
            | ProcessAuthorityBinding::DelegatedAuthority { resource_scope, .. } => resource_scope,
        }
    }

    pub fn delegation_id(&self) -> Option<&DelegationId> {
        match &self.authority {
            ProcessAuthorityBinding::DirectAgentAuthority { .. } => None,
            ProcessAuthorityBinding::DelegatedAuthority { delegation_id, .. } => {
                Some(delegation_id)
            }
        }
    }
}

/// Digest algorithm identifier for artifact content digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Blake3,
}

impl DigestAlgorithm {
    pub fn stable_name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }

    pub fn expected_hex_len(&self) -> usize {
        match self {
            Self::Sha256 | Self::Blake3 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
        }
    }
}

/// Validation errors for artifact provenance and content digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactProvenanceError {
    EmptyDigest,
    InvalidHexCharacters,
    DigestLengthMismatch {
        algorithm: DigestAlgorithm,
        expected: usize,
        actual: usize,
    },
    EmptyCustomArtifactType,
    SelfReferentialParentArtifact(ArtifactId),
    DuplicateParentArtifact(ArtifactId),
}

/// Content digest and algorithm identifier for an artifact.
///
/// # Security Note
/// A content digest establishes **content correspondence** only. It does **not** prove authorship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    pub digest_hex: String,
}

impl ContentDigest {
    /// Validates and constructs a [`ContentDigest`].
    pub fn new(
        algorithm: DigestAlgorithm,
        digest_hex: impl Into<String>,
    ) -> Result<Self, ArtifactProvenanceError> {
        let raw = digest_hex.into();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ArtifactProvenanceError::EmptyDigest);
        }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ArtifactProvenanceError::InvalidHexCharacters);
        }
        let expected = algorithm.expected_hex_len();
        if trimmed.len() != expected {
            return Err(ArtifactProvenanceError::DigestLengthMismatch {
                algorithm,
                expected,
                actual: trimmed.len(),
            });
        }
        Ok(Self {
            algorithm,
            digest_hex: trimmed.to_ascii_lowercase(),
        })
    }
}

/// Classification of an artifact produced within the DMC runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactType {
    SandboxReport,
    UnitTestReport,
    KnowledgeSnapshot,
    AuditBundle,
    Custom(String),
}

impl ArtifactType {
    pub fn stable_name(&self) -> String {
        match self {
            Self::SandboxReport => "sandbox_report".to_owned(),
            Self::UnitTestReport => "unit_test_report".to_owned(),
            Self::KnowledgeSnapshot => "knowledge_snapshot".to_owned(),
            Self::AuditBundle => "audit_bundle".to_owned(),
            Self::Custom(name) => format!("custom:{}", name.trim()),
        }
    }
}

/// Provenance record for an artifact linking content digest to producing execution,
/// producing process, and optional parent/source artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProvenance {
    pub artifact_id: ArtifactId,
    pub content_digest: ContentDigest,
    pub artifact_type: ArtifactType,
    pub producing_execution_id: ExecutionId,
    pub producing_process_id: RdaProcessId,
    pub parent_artifact_ids: Vec<ArtifactId>,
}

impl ArtifactProvenance {
    /// Validates structural invariants on the artifact provenance record.
    pub fn validate(&self) -> Result<(), ArtifactProvenanceError> {
        let _ = ContentDigest::new(
            self.content_digest.algorithm,
            self.content_digest.digest_hex.clone(),
        )?;
        if let ArtifactType::Custom(name) = &self.artifact_type {
            if name.trim().is_empty() {
                return Err(ArtifactProvenanceError::EmptyCustomArtifactType);
            }
        }
        let mut seen = Vec::with_capacity(self.parent_artifact_ids.len());
        for parent_id in &self.parent_artifact_ids {
            if parent_id == &self.artifact_id {
                return Err(ArtifactProvenanceError::SelfReferentialParentArtifact(
                    parent_id.clone(),
                ));
            }
            if seen.contains(parent_id) {
                return Err(ArtifactProvenanceError::DuplicateParentArtifact(
                    parent_id.clone(),
                ));
            }
            seen.push(parent_id.clone());
        }
        Ok(())
    }
}

/// M1 baseline policy request structure (operates over unverified [`AgentIdentity`] claims).
///
/// Retained for M1 test compatibility only. Cannot produce execution-authorized policy results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub agent: Option<AgentIdentity>,
    pub action: Action,
    pub resource: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    /// Stable lowercase identifier (`"allow"` or `"deny"`) for audit records.
    pub fn stable_name(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_identifiers_reject_empty_and_whitespace() {
        assert!(AgentId::new("").is_err());
        assert!(AgentId::new("   ").is_err());
        assert!(AgentId::new(" padded ").is_err());
        assert!(RdaProcessId::new("proc with spaces").is_err());
        assert!(ExecutionId::new("exec\n1").is_err());
        assert!(ToolInvocationId::new("\t").is_err());
        assert!(ArtifactId::new("").is_err());
        assert!(DelegationId::new("").is_err());
        assert!(TaskId::new("").is_err());
        assert!(AuditEventId::new("").is_err());

        assert_eq!(AgentId::new("agent-01").unwrap().as_str(), "agent-01");
    }

    #[test]
    fn resource_scope_rejects_traversal_backslashes_percent_encoding_and_ambiguous_separators() {
        assert_eq!(
            ResourceScope::new(vec![]),
            Err(ResourceScopeError::EmptyScopeList)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://*".into()]),
            Err(ResourceScopeError::UnboundedWildcardNotAllowed)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/../treasury".into()]),
            Err(ResourceScopeError::TraversalSegmentNotAllowed)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/./reports".into()]),
            Err(ResourceScopeError::TraversalSegmentNotAllowed)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/reports/..".into()]),
            Err(ResourceScopeError::TraversalSegmentNotAllowed)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research//reports".into()]),
            Err(ResourceScopeError::EmptyPathSegment)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/".into()]),
            Err(ResourceScopeError::EmptyPathSegment)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research\\..\\treasury".into()]),
            Err(ResourceScopeError::ForbiddenUriCharacters)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/%2e%2e/treasury".into()]),
            Err(ResourceScopeError::ForbiddenUriCharacters)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/report?admin=1".into()]),
            Err(ResourceScopeError::ForbiddenUriCharacters)
        );
        assert_eq!(
            ResourceScope::new(vec!["sandbox://research/report#frag".into()]),
            Err(ResourceScopeError::ForbiddenUriCharacters)
        );
        assert_eq!(
            ResourceScope::new(vec!["/relative/path".into()]),
            Err(ResourceScopeError::MissingOrInvalidScheme)
        );

        let scope = ResourceScope::new(vec!["sandbox://research/reports".into()]).unwrap();
        assert!(scope.matches_resource("sandbox://research/reports"));
        assert!(scope.matches_resource("sandbox://research/reports/q1"));

        // Adversarial candidate strings must all return false
        assert!(!scope.matches_resource("sandbox://research/reports/../../treasury"));
        assert!(!scope.matches_resource("sandbox://research/reports/../other"));
        assert!(!scope.matches_resource("sandbox://research/reports/./q1"));
        assert!(!scope.matches_resource("sandbox://research/reports//q1"));
        assert!(!scope.matches_resource("sandbox://research/reports/"));
        assert!(!scope.matches_resource("sandbox://research/reports\\..\\treasury"));
        assert!(!scope.matches_resource("sandbox://research/reports/%2e%2e/treasury"));
        assert!(!scope.matches_resource("sandbox://research/reports_evil"));
    }

    #[test]
    fn content_digest_and_artifact_provenance_validation() {
        let valid_hex = "a".repeat(64);
        let digest = ContentDigest::new(DigestAlgorithm::Sha256, &valid_hex).unwrap();
        assert_eq!(digest.digest_hex, valid_hex);

        assert!(ContentDigest::new(DigestAlgorithm::Sha256, "short").is_err());
        assert!(ContentDigest::new(DigestAlgorithm::Sha256, "z".repeat(64)).is_err());

        let art_id = ArtifactId::new("art-1").unwrap();
        let self_ref = ArtifactProvenance {
            artifact_id: art_id.clone(),
            content_digest: digest,
            artifact_type: ArtifactType::SandboxReport,
            producing_execution_id: ExecutionId::new("exec-1").unwrap(),
            producing_process_id: RdaProcessId::new("proc-1").unwrap(),
            parent_artifact_ids: vec![art_id.clone()],
        };
        assert_eq!(
            self_ref.validate(),
            Err(ArtifactProvenanceError::SelfReferentialParentArtifact(
                art_id
            ))
        );
    }
}
