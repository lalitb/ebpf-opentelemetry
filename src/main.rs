mod analyzer;
mod controller;
mod instrumentation;
mod manager;
mod offset_tracker;
mod probe;

use anyhow::Result;
use instrumentation::Instrumentation;
use opentelemetry::global;
use tracing::info;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
#[tokio::main(flavor = "current_thread")] // ✅ Single-threaded Tokio runtime
async fn main() -> Result<()> {

    let exporter = opentelemetry_stdout::SpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    global::set_tracer_provider(provider);    
    info!("OpenTelemetry tracing initialized with stdout exporter");

    let instrumentation = Instrumentation::new()?;
    instrumentation.run().await?;
    Ok(())
}