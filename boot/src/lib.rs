//! narf-boot — bootloader handoff.
//!
//! Spec: `boot/specification/spec.md`. Stage 1 ships the BootInfo types and
//! a bounded handoff parser: reject malformed or oversized memory maps,
//! validate non-overlap and address arithmetic, preserve protocol-owned
//! firmware pointers, and hand normalized data to `frame/`.
//!
//! **Deviation from spec §5 noted:** the spec pins Limine as the sole
//! Stage-1 bootloader on x86_64, but `cargo xtask run` targets QEMU's
//! `-kernel` path which supports multiboot2 natively. Stage 1 uses
//! multiboot2; Limine's UEFI application converts its firmware handoff to
//! that same protocol, and the OVMF path is exercised by `xtask iso-boot`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod info;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub use info::{validate_memory_map, BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo};

/// Bootloader-supplied kernel command-line as a `&'static str`.
/// Empty before the per-arch `parse_raw` runs, or when the loader
/// passed no cmdline. See `boot/specification/cmdline.md` (TBD)
/// for the recognized flag set; today the kernel parses:
///
/// - `safe_mode` / `safe_mode=N` — equivalent to `stop_at=subsys`.
/// - `stop_at=<stage>` — halt initcall execution after the named
///   stage. Valid: early, core, postcore, arch, subsys, fs,
///   device, late.
///
/// Anything else is ignored. Unknown flags do not abort boot.
#[cfg(target_arch = "x86_64")]
pub fn cmdline() -> &'static str {
    x86_64::cmdline()
}

#[cfg(target_arch = "aarch64")]
pub fn cmdline() -> &'static str {
    aarch64::cmdline()
}

/// Architectures with no cmdline source yet.
///
/// aarch64 got a real one above: it always parsed `/chosen/bootargs` into a
/// static buffer for `BootInfo::cmdline`, but this dispatcher had no aarch64 arm
/// and returned `""`, so every cmdline flag was inert there. `stop_at=` and
/// `safe_mode` silently did nothing, and `cargo xtask test --subsystem <name>`
/// appeared to filter nothing — the harness passes the filter through
/// `-append`, the kernel read an empty string, and `run_all_and_exit()` ran the
/// whole suite while still reporting success.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn cmdline() -> &'static str {
    ""
}
