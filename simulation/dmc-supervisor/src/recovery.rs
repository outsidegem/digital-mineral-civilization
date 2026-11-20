// Recovery module placeholder – future implementation will parse the JSONL log
use crate::log::Event;
use std::path::Path;

#[allow(dead_code)]
pub fn recover(_log_path: &Path) -> Vec<Event> {
    // For now return an empty vector.
    Vec::new()
}
