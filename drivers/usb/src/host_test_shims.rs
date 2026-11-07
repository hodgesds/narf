//! Host-only definitions for the kernel-provided symbols the USB lib-test
//! binary links against (#1579).
//!
//! On a kernel target the linker scripts (`build/linker/*.ld`) define the
//! `__text_start` / `__build_id_note_*` / `__narf_probes_*` /
//! `__kernel_phys_bounds` anchors, and `frame/src/bare_main.rs` defines
//! the `#[no_mangle]` NUMA topology hooks. The host `cargo test` binary
//! has neither, but the lib-test link still pulls in the referencing
//! code: `narf-memory`'s `text_poke`/KASLR paths, `narf-filesystem`'s
//! sysfs/procfs NUMA and build-ID readers, `narf-tracing`'s `probes()`,
//! and `narf-userspace`'s `sys_move_pages` / `sys_get_mempolicy` /
//! `sys_getcpu` handlers (plus the unconditionally-compiled `mod tests`
//! of those crates, whose `#[test]` fns reference the same symbols).
//!
//! This module supplies inert stand-ins so the link succeeds. It is
//! test-only (`#[cfg(test)]` in `lib.rs`): it is never compiled into
//! the kernel driver, so it cannot collide with `frame`'s definitions
//! at kernel link time, and it changes no production behavior. Values
//! mirror the no-topology / no-SRAT behavior `frame` reports — one
//! node, local distance 10 / remote 20, unknown CPU node
//! (`u32::MAX`, which `filesystem::sysfs` maps to `None`), and empty
//! build-ID / probe ranges — the same technique as
//! `block/src/luks2.rs`'s `host_tests` module, `fuzz/src/lib.rs`'s
//! `host` module, and `verification/btrfs-host/src/host.rs`.
//!
//! None of the USB unit tests execute the referencing paths (they are
//! sysfs / mempolicy / tracing-note readers the USB tests never call);
//! the definitions exist only to satisfy the linker.

#![allow(dead_code)]

/// Physical bounds of the kernel image, as the linker script emits
/// them. Zeroed: the KASLR/text-poke paths that read them never run
/// under the host test harness.
#[no_mangle]
static __kernel_phys_bounds: [u64; 2] = [0; 2];

/// Start of the kernel `.text` section, as the linker script emits
/// it. Zeroed: the host test binary has no kernel image layout.
#[no_mangle]
static __text_start: u8 = 0;

/// Bounds of the GNU build-ID note, as the linker script emits them.
/// Equal addresses give `kernel_notes_read` an empty note, matching a
/// binary with no build-ID note.
#[no_mangle]
static __build_id_note_start: u8 = 0;
#[no_mangle]
static __build_id_note_end: u8 = 0;

/// Bounds of the `.note.narf.probes` section, as the linker script
/// emits them. Equal addresses give `tracing::probes()` an empty
/// slice (the two `u8` statics sit < `size_of::<ProbeSite>()` apart).
#[no_mangle]
static __narf_probes_start: u8 = 0;
#[no_mangle]
static __narf_probes_end: u8 = 0;

/// NUMA node of a physical address. No SRAT on host → node 0, as
/// `frame` reports for an address outside every SRAT range.
#[no_mangle]
extern "Rust" fn narf_phys_to_node(_addr: u64) -> u32 {
    0
}

/// NUMA node hosting a logical CPU. No SRAT on host → node 0, as
/// `frame` reports for a CPU with no proximity entry.
#[no_mangle]
extern "Rust" fn narf_cpu_to_node(_cpu: u32) -> u32 {
    0
}

/// CPU → NUMA node, or `u32::MAX` when the CPU has no SRAT proximity
/// entry (so sysfs can distinguish "node 0" from "unknown"). No SRAT
/// on host → unknown, exactly as `frame/src/bare_main.rs` reports.
#[no_mangle]
extern "Rust" fn narf_cpu_node_opt(_cpu: u32) -> u32 {
    u32::MAX
}

/// NUMA distance between two nodes (Linux `node_distance`, scaled so
/// local == 10). Single-node host: 10 same-node, 20 cross-node, as
/// `frame` reports with no SLIT matrix.
#[no_mangle]
extern "Rust" fn narf_node_distance(from: u32, to: u32) -> u32 {
    if from == to {
        10
    } else {
        20
    }
}

/// Number of NUMA nodes in the firmware-described topology. No SRAT
/// on host → single node, as `frame` reports (floored at 1).
#[no_mangle]
extern "Rust" fn narf_numa_node_count() -> u32 {
    1
}
