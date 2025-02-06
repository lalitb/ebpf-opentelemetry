use crate::{controller::Controller, manager::Manager, probe::Probe};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub struct Instrumentation {
    manager: Manager,
    controller: Arc<Mutex<Controller>>,
}

impl Instrumentation {
    pub fn new() -> Result<Self> {
        println!("Initializing instrumentation...");
        let (event_sender, event_receiver) = mpsc::channel(100);
        let controller = Arc::new(Mutex::new(Controller::new(event_receiver)?)); // ✅ Wrap Controller in Arc<Mutex<>>
        let mut manager = Manager::new(controller.clone())?;

        let http_probe = Probe::new("http_request", event_sender.clone())?;
        let db_probe = Probe::new("db_query", event_sender.clone())?;

        manager.register_probe(http_probe);
        manager.register_probe(db_probe);

        Ok(Self {
            manager,
            controller,
        })
    }

    pub async fn run(&self) -> Result<()> {
        println!("Running instrumentation...");
        let controller = self.controller.clone();
        tokio::spawn(async move {
            let mut controller_guard = controller.lock().await; // ✅ Lock controller for mutability
            controller_guard.run().await.unwrap();
        });
        self.manager.run().await
    }
}
