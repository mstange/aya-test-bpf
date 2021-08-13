# aya-test-bpf

I'm trying to access `prev->pid` in my `sched_switch` tracepoint handler, but `bpf_probe_read` is returning error code -34.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
sudo ./target/debug/aya-test-bpf ./target/bpfel-unknown-none/debug/aya-test-bpf
```