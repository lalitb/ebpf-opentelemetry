use crate::controller::Controller;
use crate::probe::Probe;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;

pub struct Manager {
    probes: Vec<Arc<Probe>>,
    controller: Arc<Mutex<Controller>>,
}
use tokio::task::spawn_local;

impl Manager {
    pub fn new(controller: Arc<Mutex<Controller>>) -> Result<Self> {
        Ok(Self {
            probes: Vec::new(),
            controller,
        })
    }

    pub fn register_probe(&mut self, probe: Probe) {
        self.probes.push(Arc::new(probe));
    }

    pub async fn run(&self) -> Result<()> {
        for probe in &self.probes {
            let probe = Arc::clone(probe);
            spawn_local(async move {
                let probe_guard = probe.bpf_object.lock().await; // ✅ Lock bpf_object inside async block

                if let Err(e) = probe.run().await {
                    eprintln!("Probe run failed: {}", e);
                }
            });
        }
        Ok(())
    }
}
