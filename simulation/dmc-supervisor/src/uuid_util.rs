use uuid::Uuid;

/// Generate a new suite UUID (v4) as a string.
pub fn new_suite_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a new scenario UUID (v4) as a string.
pub fn new_scenario_uuid() -> String {
    Uuid::new_v4().to_string()
}
