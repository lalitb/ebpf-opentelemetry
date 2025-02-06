use opentelemetry::global;
use opentelemetry::trace::{TraceResult, Tracer};

use crate::probe::BPFEvent;
use anyhow::Result;
use opentelemetry::global::BoxedTracer;
use opentelemetry::trace::Span;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use tokio::sync::mpsc::Receiver;
use tracing::info;

pub struct Controller {
    tracer: BoxedTracer,
    event_receiver: Receiver<BPFEvent>,
}

impl Controller {
    pub fn new(event_receiver: Receiver<BPFEvent>) -> Result<Self> {
        let tracer = global::tracer_provider().tracer("ebpf_tracer");

        Ok(Self {
            tracer,
            event_receiver,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(event) = self.event_receiver.recv().await {
            self.trace(event)?;
        }
        Ok(())
    }

    fn trace(&self, event: BPFEvent) -> TraceResult<()> {
        let span_name = format!("bpf_event: {}", String::from_utf8_lossy(&event.comm));
        //let span_name = event.name.clone();
        let mut span = self
            .tracer
            .span_builder(span_name)
            .with_start_time(
                std::time::UNIX_EPOCH + std::time::Duration::from_nanos(event.timestamp_start),
            )
            .with_attributes(vec![
                KeyValue::new("pid", event.pid as i64),
                KeyValue::new("timestamp_start", event.timestamp_start as i64),
                KeyValue::new("timestamp_end", event.timestamp_end as i64),
            ])
            .start(&self.tracer);

        info!("Captured event: {:?}", event);
        span.end();
        Ok(())
    }
}
