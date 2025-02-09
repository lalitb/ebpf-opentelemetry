use libbpf_rs::MapCore;
use libbpf_rs::ObjectBuilder; // PerfBuffer};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

pub struct Probe {
    pub(crate) bpf_object: Arc<Mutex<libbpf_rs::Object>>,
    event_channel: Sender<BPFEvent>,
    links: Vec<Link>,
    name: String,
}

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)] // Ensure correct memory layout
pub struct BPFEvent {
    pub timestamp_start: u64,
    pub timestamp_end: u64,
    pub pid: u32,
    pub comm: [u8; 16], // Fixed-size array to match `char comm[16]` in C
}

impl BPFEvent {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid event data size"));
        }

        let timestamp_start = u64::from_ne_bytes(data[0..8].try_into()?);
        let timestamp_end = u64::from_ne_bytes(data[8..16].try_into()?);
        let pid = u32::from_ne_bytes(data[16..20].try_into()?);

        let mut comm = [0u8; 16]; // Fixed-size array
        comm.copy_from_slice(&data[20..36]); // Copy only 16 bytes

        Ok(Self {
            timestamp_start,
            timestamp_end,
            pid,
            comm,
        })
    }
}

impl Probe {
    pub fn new(name: &str, event_channel: Sender<BPFEvent>) -> Result<Self> {
        let out_dir = env::var("OUT_DIR").unwrap_or_else(|_| "target/debug".to_string());

        let bpf_path = PathBuf::from(out_dir).join("probe.bpf.o");
        println!("Loading eBPF program from: {:?}", bpf_path);

        let open_obj = ObjectBuilder::default().open_file(bpf_path.to_str().unwrap())?;
        let obj = open_obj.load()?;
        println!("Loaded eBPF program for probe: {}", name);

        Ok(Self {
            bpf_object: Arc::new(Mutex::new(obj)),
            event_channel,
            links: Vec::new(),
            name: name.to_string(),
        })
    }

    fn find_function_offset(function_name: &str) -> Result<u64> {
        let binary_path = std::env::current_exe()?;
        let binary_data = fs::read(&binary_path)?;
        let obj_file = object::File::parse(&*binary_data)?;

        for sym in obj_file.dynamic_symbols() {
            if let Ok(name) = sym.name() {
                if name == function_name {
                    println!("Found function {} at address {:#x}", name, sym.address());
                    return Ok(sym.address());
                } else {
                    println!("Skipping symbol: {}", name);
                }
            }
        }
        Err(anyhow::anyhow!("Function {} not found", function_name))
    }

    pub async fn attach(&mut self) -> Result<()> {
        if self.name == "target_function" {
            self.attach_target_function().await?;
        }
        // Add other probe attachments here if needed
        Ok(())
    }

    async fn attach_target_function(&mut self) -> Result<()> {
        let bpf_object = self.bpf_object.lock().await;
        let binary_path = std::env::current_exe()?;

        let offset = Self::find_function_offset("target_function")?;
        println!("Found target_function at offset: {:#x}", offset);

        // Attach uprobe
        if let Some(prog) = bpf_object.prog("trace_enter") {
            let link = prog.attach_uprobe(-1, binary_path.to_str().unwrap(), offset)?;
            self.links.push(link);
            println!("Attached uprobe successfully");
        }

        // Attach uretprobe
        if let Some(prog) = bpf_object.prog("trace_exit") {
            let link = prog.attach_uretprobe(-1, binary_path.to_str().unwrap(), offset)?;
            self.links.push(link);
            println!("Attached uretprobe successfully");
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        println!("Running probe...");
        let mut ringbuf_builder = RingBufferBuilder::new();
        let bpf_object = self.bpf_object.lock().await;
        let events_map = bpf_object
            .maps() // ✅ Already an iterator, so use `.find()` directly
            .find(|m| m.name().to_string_lossy().as_ref() == "events")
            .expect("events map not found");

        ringbuf_builder.add(&events_map as &dyn MapCore, |data: &[u8]| {
            match BPFEvent::parse(data) {
                Ok(event) => {
                    // Use a blocking send here since we're in a non-async context
                    if let Err(err) = self.event_channel.blocking_send(event) {
                        eprintln!("Failed to send event: {}", err);
                    }
                }
                Err(err) => eprintln!("Failed to parse BPF event: {}", err),
            }
            // Return 0 to indicate success
            0
        })?;

        let ringbuf = ringbuf_builder.build()?;

        loop {
            ringbuf.poll(std::time::Duration::from_millis(100))?;
        }
    }

    fn process_event(&self, data: &[u8]) -> anyhow::Result<BPFEvent> {
        BPFEvent::parse(data)
    }
}
