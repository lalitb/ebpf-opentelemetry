use anyhow::Result;
use libbpf_rs::MapCore;
//use libbpf_rs::{ObjectBuilder, UprobeAttachType};
use libbpf_rs::ObjectBuilder;
use libbpf_rs::RingBufferBuilder;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

pub struct Probe {
    pub(crate) bpf_object: Arc<Mutex<libbpf_rs::Object>>,
    event_channel: Sender<BPFEvent>,
}

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
    pub fn new(
        binary_path: &str,
        function_name: &str,
        event_channel: Sender<BPFEvent>,
        function_offset: u64,
    ) -> Result<Self> {
        let bpf_path = "target/debug/probe.bpf.o";
        println!("Loading eBPF program from: {:?}", bpf_path);

        let open_obj = ObjectBuilder::default().open_file(bpf_path)?.load()?;
        println!("Loaded eBPF program for probe: {}", function_name);

        //let program = open_obj
        //    .prog("uprobe_handler")
        //    .ok_or_else(|| anyhow::anyhow!("Failed to find uprobe handler"))?;
        let program = open_obj
            .programs()
            .find(|p| p.name() == "uprobe_handler")
            .ok_or_else(|| anyhow::anyhow!("Failed to find uprobe handler"))?;

        program.attach_uprobe(
            true,
            -1,
            binary_path,
            function_offset as i64,
            //UprobeAttachType::Attach,
        )?;

        println!(
            "✅ Attached eBPF probe for '{}' at offset: {:#x}",
            function_name, function_offset
        );

        Ok(Self {
            bpf_object: Arc::new(Mutex::new(open_obj)),
            event_channel,
        })
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
