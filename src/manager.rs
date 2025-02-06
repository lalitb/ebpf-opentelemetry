use crate::controller::Controller;
use crate::probe::Probe;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::{spawn_local, LocalSet};

pub struct Manager {
    probes: Vec<Arc<Probe>>,
    controller: Arc<Mutex<Controller>>,
}
use tokio::task;

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
        println!("Running manager...");
        let local_set = LocalSet::new(); // ✅ Create a `LocalSet`

        for probe in &self.probes {
            println!("Running probe: {:?}", probe);
            let probe = Arc::clone(probe);
            local_set.spawn_local(async move {
                let probe_guard = probe.bpf_object.lock().await; // ✅ Lock bpf_object inside async block

                if let Err(e) = probe.run().await {
                    eprintln!("Probe run failed: {}", e);
                }
            });
        }
        Ok(())
    }
}
