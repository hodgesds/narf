//! Stand-ins for the arch hooks `narf-lib` references.
//!
//! `narf-lib`'s `mod tests` is compiled unconditionally, and its test
//! functions call the `#[no_mangle]` `narf_arch_cpu_id` /
//! `narf_arch_current_domain` hooks (the per-arch CPU-id read and the
//! current-domain byte) through the `extern "Rust"` declarations in
//! `lib/src/percpu.rs` and `lib/src/assert.rs`. Those test entries are
//! `#[used]` statics, so the linker keeps them — and their hook
//! references — in every binary that links `narf-lib`, test or not.
//! The kernel satisfies them from `narf-arch`; the loader links no
//! `narf-arch`, so without these definitions both the host test binary
//! and the `aarch64-unknown-uefi` binary fail to link with undefined
//! `narf_arch_cpu_id` / `narf_arch_current_domain` (verified on this
//! branch for both targets).
//!
//! Values mirror the single-CPU behavior `arch` reports: CPU id 0
//! (BSP; `arch/src/lib.rs::narf_arch_cpu_id`) and domain 0
//! (`DomainId::FRAME`, the initial `CURRENT_DOMAIN` value
//! `arch/src/lib.rs::narf_arch_current_domain` returns). The loader
//! runs single-threaded at boot before any domain exists, so both are
//! truthful here, not just link fodder. No live loader code calls
//! these hooks — only `narf-lib` test functions that never run in this
//! binary — so they change no production behavior.
//!
//! This mirrors `firmware/fdt/src/host_test_shims.rs` (#2151), except
//! that crate's copy is test-only: the loader needs the definitions in
//! the production binary too, so this module is compiled always.

#![allow(dead_code)]

/// ID of the CPU currently executing this code. Single-CPU loader:
/// 0 (the BSP), as `arch` reports before AP bring-up populates
/// per-CPU ids.
#[no_mangle]
extern "Rust" fn narf_arch_cpu_id() -> usize {
    0
}

/// The domain byte this CPU is currently reporting. No domain scopes
/// in the loader: 0 (`DomainId::FRAME`), as `arch` reports from its
/// zero-initialised `CURRENT_DOMAIN` table.
#[no_mangle]
extern "Rust" fn narf_arch_current_domain() -> u8 {
    0
}
