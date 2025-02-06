use libbpf_rs::MapCore;
use libbpf_rs::ObjectBuilder; // PerfBuffer};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

pub struct Probe {
    pub(crate) bpf_object: Arc<Mutex<libbpf_rs::Object>>,
    event_channel: Sender<BPFEvent>,
}

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BPFEvent {
    pub name: String,
    pub pid: u32,
    pub timestamp: u64,
    pub additional_data: String, // Extend as needed for more fields
}

impl BPFEvent {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        // Example deserialization logic
        let name = String::from_utf8(data[0..16].to_vec())?
            .trim_end_matches('\0')
            .to_string();
        let pid = u32::from_ne_bytes(data[16..20].try_into()?);
        let timestamp = u64::from_ne_bytes(data[20..28].try_into()?);

        Ok(Self {
            name,
            pid,
            timestamp,
            additional_data: "Example".to_string(),
        })
    }
}

const BPF_OBJECT: &[u8] = include_bytes!(env!("BPF_OBJECT"));

impl Probe {
    pub fn new(name: &str, event_channel: Sender<BPFEvent>) -> Result<Self> {
        let obj = ObjectBuilder::default().open_memory(BPF_OBJECT)?.load()?;
        println!("Loaded eBPF program for probe: {}", name);
        Ok(Self {
            bpf_object: Arc::new(Mutex::new(obj)),
            event_channel,
        })
    }

    pub async fn run(&self) -> Result<()> {
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
