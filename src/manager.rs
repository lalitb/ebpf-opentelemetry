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
            println!("Iterating over probes...");
            let probe = Arc::clone(probe);
            local_set.spawn_local(async move {
                let mut probe_guard = probe.lock().await;
                if let Err(e) = probe_guard.attach().await {
                    eprintln!("Failed to attach probe {}: {}", probe_guard.name, e);
                    return;
                }
                println!("Attached probe: {}", probe_guard.name);

                if let Err(e) = probe_guard.run().await {
                    eprintln!("Probe run failed: {}", e);
                } else {
                    println!("Probe run initiated.");
                }
            });
        }
        local_set.await; // ✅ Ensure `spawn_local()` tasks are executed
        Ok(())
    }
}
