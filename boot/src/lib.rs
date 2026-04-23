//! narf-boot — bootloader handoff.
//!
//! Spec: `boot/specification/spec.md`. Stage 1 ships the BootInfo types and
//! a Wave-1 handoff minimum: parse enough of the bootloader's payload to
//! expose the UART physical base and a usable RAM window, then hand to
//! `frame/`. Full `validate_boot_info` (all 6 checks) lands as consumers
//! appear — Wave 1's single check is "pointer is non-null and inside an
//! identity-mapped region."
//!
//! **Deviation from spec §5 noted:** the spec pins Limine as the sole
//! Stage-1 bootloader on x86_64, but `cargo xtask run` targets QEMU's
//! `-kernel` path which supports multiboot2 natively. Stage 1 uses
//! multiboot2; Limine integration is a future-Limine-CI task that has no
//! visible behaviour difference at the `frame::init_bsp` hand-off.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod info;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub use info::{BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo};
