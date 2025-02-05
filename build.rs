use std::process::Command;
use std::env;
use std::path::PathBuf;

fn main() {
    // Get the output directory for compiled artifacts
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");

    // Define the path to the eBPF source file
    let bpf_source = "probe.bpf.c";
    let bpf_output = PathBuf::from(&out_dir).join("probe.bpf.o");

    // Compile the eBPF program
    let status = Command::new("clang")
        .args(&[
            "-O2",
            "-target",
            "bpf",
            "-c",
            bpf_source,
            "-o",
            bpf_output.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to compile eBPF program");

    if !status.success() {
        panic!("eBPF compilation failed");
    }

    // Inform Cargo to watch the eBPF source file for changes
    println!("cargo:rerun-if-changed={}", bpf_source);
}
