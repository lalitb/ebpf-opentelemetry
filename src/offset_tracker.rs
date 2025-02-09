use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct OffsetTracker {
    pub offsets: HashMap<String, u64>,
}

impl OffsetTracker {
    pub fn new() -> Self {
        OffsetTracker {
            offsets: HashMap::new(),
        }
    }

    /// Loads an ELF binary and extracts function offsets
    pub fn find_function_offset(
        &mut self,
        binary_path: &str,
        function_name: &str,
    ) -> Result<Option<u64>> {
        let mut file = File::open(binary_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer).expect("Failed to parse ELF file");

        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == function_name {
                    self.offsets.insert(name.to_string(), sym.st_value);
                    return Ok(Some(sym.st_value)); // Offset in binary
                }
            }
        }

        Ok(None) // Function not found
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;

    /// Creates a small test ELF binary with a known function
    fn create_test_binary() -> String {
        let source_code = r#"
            #include <stdio.h>
            void test_function() { printf("Hello, World!"); }
            int main() { test_function(); return 0; }
        "#;

        let c_file = "/tmp/test_program.c";
        let bin_file = "/tmp/test_program";

        // Write C source code to a file
        let mut file = File::create(c_file).unwrap();
        file.write_all(source_code.as_bytes()).unwrap();

        // Compile the C source file to an ELF binary
        let output = Command::new("gcc")
            .arg("-o")
            .arg(bin_file)
            .arg(c_file)
            .output()
            .expect("Failed to compile test binary");

        assert!(output.status.success(), "Compilation failed!");

        bin_file.to_string()
    }

    #[test]
    fn test_function_offset_extraction() {
        let test_binary = create_test_binary();
        let mut tracker = OffsetTracker::new();

        // Try to find the function offset in the ELF binary
        let offset = tracker
            .find_function_offset(&test_binary, "test_function")
            .unwrap();
        assert!(offset.is_some(), "Function offset should be found");

        println!("Found function offset: {:?}", offset);
    }

    #[test]
    fn test_missing_function() {
        let test_binary = create_test_binary();
        let mut tracker = OffsetTracker::new();

        // Try to find a non-existent function
        let offset = tracker
            .find_function_offset(&test_binary, "non_existent_function")
            .unwrap();
        assert!(offset.is_none(), "Non-existent function should return None");
    }
}
