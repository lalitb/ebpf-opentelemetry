use crate::{controller::Controller, manager::Manager, probe::Probe};
use anyhow::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, Mutex};

pub struct Instrumentation {
    manager: Manager,
    controller: Arc<Mutex<Controller>>,
}

impl Instrumentation {
    pub fn new(offsets: HashMap<String, HashMap<String, u64>>) -> Result<Self> {
        println!("Initializing instrumentation...");
        let (event_sender, event_receiver) = mpsc::channel(100);
        let controller = Arc::new(Mutex::new(Controller::new(event_receiver)?));
        let mut manager = Manager::new(controller.clone())?;

        for (binary, functions) in &offsets {
            for (function, &offset) in functions.iter() {
                println!(
                    "🔍 Attaching probe to {} in {} at {:#x}",
                    function, binary, offset
                );
                let probe = Probe::new(binary, function, event_sender.clone(), offset)?;
                manager.register_probe(probe);
            }
        }

        Ok(Self {
            manager,
            controller,
        })
    }

    pub async fn run(&self) -> Result<()> {
        println!("Running instrumentation...");
        let controller = self.controller.clone();
        tokio::spawn(async move {
            let mut controller_guard = controller.lock().await;
            if let Err(err) = controller_guard.run().await {
                eprintln!("Controller error: {}", err);
            }
        });

        self.manager.run().await
    }
}
