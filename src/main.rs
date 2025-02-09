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
use std::{env, fs, thread::sleep, time::Duration};
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

    let args: Vec<String> = env::args().collect();
    let config_path = args
        .get(1)
        .cloned()
        .or_else(|| env::var("CONFIG_PATH").ok())
        .unwrap_or_else(|| {
            eprintln!(
                "❌ Error: Configuration file path not provided via argument or CONFIG_PATH."
            );
            std::process::exit(1);
        });

    // Check if the file exists and is readable
    if !fs::metadata(&config_path).is_ok() {
        eprintln!(
            "❌ Error: Configuration file '{}' does not exist or is not readable.",
            config_path
        );
        std::process::exit(1);
    }

    println!("Using config file: {}", config_path);
    let offset_tracker = OffsetTracker::from_config_file(config_path)?;
    println!("offset traceker initialized");

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
