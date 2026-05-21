# citadel-core

A high-performance eBPF XDP program written in Rust using the [Aya](https://aya-rs.dev/) framework. 
Designed for line-rate packet inspection and real-time infrastructure security.

## Technical Specifications:
- **Language:** Rust (no_std)
- **Framework:** Aya eBPF
- **Hook Point:** XDP (eXpress Data Path)
- **Primary Function:** Metadata extraction and packet filtering at the NIC driver level.

## Key Features:
- **Zero-copy packet inspection:** Directly reads from `ctx.data()`.
- **High-throughput logging:** Outputs packet metadata via `PerfEventArray`.
- **Low overhead:** Built with `no_std` for minimal footprint in the kernel.

## Getting Started:
1. Ensure you have the `aya-tool` installed.
2. Compile with `cargo build --release`.
3. Load the program using the associated User Space controller.
