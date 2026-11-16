//! DMC Simulation Foundation runtime crate.

pub mod crypto;
pub mod report;
pub mod runner;
pub mod scenarios;
pub mod types;

pub use runner::{execute_all, execute_foundation};
pub use scenarios::foundation::run_foundation_scenario;
pub use scenarios::security::run_all_security_scenarios;
pub use types::{AcceptanceCriterion, AuditEventSummary, SimulationReport};
