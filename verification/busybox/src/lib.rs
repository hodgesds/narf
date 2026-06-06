//! BusyBox demo binary, baked at build time.
//!
//! `build.rs` downloads the upstream busybox source, builds it
//! static-against-musl at NARF's PML4[1] user vaddr
//! (`-Wl,-Ttext-segment=0x8000001000`), and exports the resulting
//! ELF path via `NARF_BUSYBOX_*` env vars. `include_bytes!`
//! materialises those into `pub const` slices.
//!
//! When `musl-gcc` is absent on the host (so the build can't run)
//! the env vars fall back to `/dev/null` — the resulting slice is
//! empty and the kernel-side consumer
//! (`frame/src/bare_main.rs::MemFs::with_seeds`) skips seeding
//! `/bin/busybox`.

#![no_std]

#[cfg(target_arch = "x86_64")]
pub const NARF_BUSYBOX: &[u8] = include_bytes!(env!("NARF_BUSYBOX_X86_64"));

#[cfg(target_arch = "aarch64")]
pub const NARF_BUSYBOX: &[u8] = include_bytes!(env!("NARF_BUSYBOX_AARCH64"));
