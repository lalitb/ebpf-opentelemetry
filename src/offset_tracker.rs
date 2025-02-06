use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct StructOffsets {
    pub offsets: HashMap<String, u64>,
}

impl StructOffsets {
    pub fn new() -> Self {
        StructOffsets {
            offsets: HashMap::new(),
        }
    }

    pub fn load_from_file(path: &str) -> Self {
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(offsets) = serde_json::from_str(&data) {
                return offsets;
            }
        }
        StructOffsets::new()
    }

    pub fn save_to_file(&self, path: &str) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, data);
        }
    }

    pub fn get_offset(&self, struct_name: &str, field: &str) -> Option<u64> {
        self.offsets
            .get(&format!("{}.{}", struct_name, field))
            .copied()
    }
}
