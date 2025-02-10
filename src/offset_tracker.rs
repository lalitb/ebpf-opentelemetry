use goblin::elf::Elf;
use rustc_demangle::demangle;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryConfig {
    pub path: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstrumentationConfig {
    pub binaries: Vec<BinaryConfig>,
}

#[derive(Debug, Default)]
pub struct OffsetTracker {
    pub offsets: HashMap<String, HashMap<String, u64>>, // {binary: {function: offset}}
}

impl OffsetTracker {
    pub fn from_config_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        println!("offset_traker::from_config_file");
        let file = File::open(path)?;
        let config: InstrumentationConfig = serde_json::from_reader(file)?;
        println!("Parsed config: {:?}", config);
        let mut tracker = Self::default();

        for binary in &config.binaries {
            println!("Processing binary: {}", binary.path);
            let mut file = File::open(&binary.path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            let elf = Elf::parse(&buffer).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            println!("Parsed ELF file:");
            let hex_suffix_regex = Regex::new(r"::h[0-9a-f]+$").unwrap(); // Regex to remove hash suffixes

            // Store function offsets after demangling Rust symbols
            let function_offsets = elf
                .syms
                .iter()
                .filter_map(|sym| {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        let demangled = demangle(name).to_string(); // Demangle Rust symbol
                                                                    // Match exactly with config.json
                        if binary.functions.contains(&cleaned_name) {
                            println!(
                                "✅ Matched function: {} at offset {:#x}",
                                cleaned_name, sym.st_value
                            );
                            Some((cleaned_name, sym.st_value))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<HashMap<String, u64>>();

            tracker
                .offsets
                .insert(binary.path.clone(), function_offsets);
        }

        Ok(tracker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::{self, File};
    use std::io::{Result, Write};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Creates a small test ELF binary with a known function
    fn create_test_binary() -> Result<PathBuf> {
        let temp_dir = env::temp_dir();
        let c_file = temp_dir.join("test_program.c");
        let bin_file = temp_dir.join("test_program");

        let source_code = r#"
            #include <stdio.h>
            void test_function() { printf("Hello, World!"); }
            void another_function() { printf("Another function"); }
            int main() { test_function(); another_function(); return 0; }
        "#;

        // Write C source code to a temporary file
        let mut file = File::create(&c_file)?;
        file.write_all(source_code.as_bytes())?;

        // Compile the C source file into an ELF binary
        let output = Command::new("gcc")
            .arg("-o")
            .arg(&bin_file)
            .arg(&c_file)
            .output()?;

        assert!(
            output.status.success(),
            "Compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(bin_file)
    }

    /// Removes test files after test execution
    fn cleanup_test_files(binary_path: &Path) {
        let _ = fs::remove_file(binary_path);
        let _ = fs::remove_file(binary_path.with_extension("c"));
    }

    #[test]
    fn test_function_offset_extraction() -> Result<()> {
        let test_binary = create_test_binary()?;
        let mut tracker = OffsetTracker::default();

        let mut function_offsets = HashMap::new();
        function_offsets.insert("test_function".to_string(), 0);
        function_offsets.insert("another_function".to_string(), 0);

        let mut config = InstrumentationConfig {
            binaries: vec![BinaryConfig {
                path: test_binary.to_str().unwrap().to_string(),
                functions: function_offsets.keys().cloned().collect(),
            }],
        };

        // Save config to a temporary file
        let config_path = test_binary.with_extension("json");
        let config_file = File::create(&config_path)?;
        serde_json::to_writer_pretty(config_file, &config)?;

        // Load offsets from the binary
        tracker.from_config_file(&config_path)?;

        for func in function_offsets.keys() {
            let offset = tracker
                .offsets
                .get(test_binary.to_str().unwrap())
                .and_then(|f| f.get(func));

            assert!(
                offset.is_some(),
                "Function '{}' should have an offset",
                func
            );
            println!(
                "✅ Found function '{}' at offset: {:#x}",
                func,
                offset.unwrap()
            );
        }

        // Cleanup test files
        cleanup_test_files(&test_binary);
        let _ = fs::remove_file(&config_path);

        Ok(())
    }

    #[test]
    fn test_missing_function() -> Result<()> {
        let test_binary = create_test_binary()?;
        let mut tracker = OffsetTracker::default();

        let mut config = InstrumentationConfig {
            binaries: vec![BinaryConfig {
                path: test_binary.to_str().unwrap().to_string(),
                functions: vec!["non_existent_function".to_string()],
            }],
        };

        // Save config to a temporary file
        let config_path = test_binary.with_extension("json");
        let config_file = File::create(&config_path)?;
        serde_json::to_writer_pretty(config_file, &config)?;

        tracker.from_config_file(&config_path)?;

        let offset = tracker
            .offsets
            .get(test_binary.to_str().unwrap())
            .and_then(|f| f.get("non_existent_function"));

        assert!(offset.is_none(), "Non-existent function should return None");

        // Cleanup test files
        cleanup_test_files(&test_binary);
        let _ = fs::remove_file(&config_path);

        Ok(())
    }
}
