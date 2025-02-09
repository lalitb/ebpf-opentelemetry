mod analyzer;
mod controller;
mod instrumentation;
mod manager;
mod offset_tracker;
mod probe;

use anyhow::Result;
use instrumentation::Instrumentation;
use offset_tracker::OffsetTracker;
use opentelemetry::global;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use std::{thread::sleep, time::Duration};
use tracing::info;

#[tokio::main(flavor = "multi_thread")] // ✅ Multi-threaded runtime
async fn main() -> Result<()> {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    global::set_tracer_provider(provider);
    info!("OpenTelemetry tracing initialized with stdout exporter");
    sleep(Duration::from_secs(5));

    let config_path = "config.json";
    let offset_tracker = OffsetTracker::from_config_file(config_path)?;

    for (binary, functions) in &offset_tracker.offsets {
        for (function, offset) in functions {
            println!(
                "✅ Found function offset for '{}' in '{}': {:#x}",
                function, binary, offset
            );
        }
    }

    let instrumentation = Instrumentation::new(offset_tracker.offsets.clone())?;
    instrumentation.run().await?;
    Ok(())
}
