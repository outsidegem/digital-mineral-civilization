use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct SupervisorEnvelope {
    pub suite_id: String,
    pub suite_timestamp: String,
    pub supervisor_version: &'static str,
    pub report_json: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<&'static str>,
}
