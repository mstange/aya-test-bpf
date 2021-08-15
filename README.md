# aya-test-bpf

Just playing around with aya.

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
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release && cargo xtask build-ebpf --release && sudo ./target/release/aya-test-bpf ./target/bpfel-unknown-none/release/aya-test-bpf
```