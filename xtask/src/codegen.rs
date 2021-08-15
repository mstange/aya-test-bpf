use aya_gen::btf_types;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("aya-test-bpf-ebpf/src");
    let names: Vec<&str> = vec!["trace_event_raw_sched_switch", "bpf_perf_event_data", "task_struct"];
    let bindings = btf_types::generate(Path::new("/sys/kernel/btf/vmlinux"), &names, false)?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings).expect("unable to write bindings to file");
    Ok(())
}
