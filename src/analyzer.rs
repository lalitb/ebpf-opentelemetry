use crate::offset_tracker::StructOffsets;
use goblin::elf::Elf;
use std::fs;

pub struct Analyzer {
    pid: i32,
    binary_path: String,
    offsets: StructOffsets,
}

impl Analyzer {
    pub fn new(target_exe: &str) -> anyhow::Result<Self> {
        let pid = Self::discover_process_id(target_exe)?;
        let offsets = StructOffsets::load_from_file("offsets.json");

        Ok(Self {
            pid,
            binary_path: target_exe.to_string(),
            offsets,
        })
    }

    fn discover_process_id(target_exe: &str) -> anyhow::Result<i32> {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    let exe_path = format!("/proc/{}/exe", pid);
                    if let Ok(path) = fs::read_link(&exe_path) {
                        if path.to_string_lossy().contains(target_exe) {
                            return Ok(pid);
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Process not found"))
    }

    pub fn analyze(&self) -> anyhow::Result<()> {
        let binary_data = fs::read(&self.binary_path)?;
        let elf = Elf::parse(&binary_data)?;

        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                println!("Found function: {} at 0x{:x}", name, sym.st_value);
            }
        }

        Ok(())
    }
}
