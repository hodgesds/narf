//! Fuzz target: the Flattened Device Tree (FDT / DTB v17) parser.
//!
//! Surface: `narf_firmware_fdt::parse_header` plus the walkers
//! and decoders that run over a parsed blob — `walk_with_cells`
//! (struct-block walk with `#address-cells` / `#size-cells`
//! inheritance), the `reg` decoder, `chosen_bootargs`,
//! `copy_reservations`, `copy_memory_ranges`,
//! `copy_reserved_memory_ranges`, and the `compatible` matchers.
//! The blob arrives from the bootloader (aarch64 boot path,
//! fw_cfg on x86_64-virt-with-FDT) and carries its own offsets
//! into its struct / strings / reserve-map blocks — the classic
//! shape for offset-arithmetic bugs. The walker is iterative
//! with a fixed path-depth cap (`MAX_PATH_DEPTH`), so a hostile
//! blob cannot recurse or loop without bound; the property
//! iterator advances at least 12 bytes per entry and returns
//! `None` on any out-of-range offset.
//!
//! Invariant: never panic, never read out of bounds, for any byte
//! string. `None` / `0` from the header and decoders is the
//! correct outcome for a malformed blob.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Cap the blob size: real DTBs are tens of KiB; parsing risk
/// lives in offset arithmetic, not in bulk data.
const MAX_BLOB: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_BLOB {
        return;
    }
    // Pull `narf_arch`'s definitions of the `narf_arch_cpu_id` /
    // `narf_arch_current_domain` hooks into the link:
    // `narf-lib`'s unconditionally-compiled tests reference them,
    // and this target's closure has no other crate that defines
    // them (`firmware/fdt/src/host_test_shims.rs` supplies them
    // only under `#[cfg(test)]`). Both read host-safe state (CPU
    // id 0 / domain FRAME before AP bring-up).
    let _ = (
        narf_arch::narf_arch_cpu_id(),
        narf_arch::narf_arch_current_domain(),
    );

    let Some(_hdr) = narf_firmware_fdt::parse_header(data) else {
        return;
    };

    // Walk every node the way the boot path does, iterating each
    // node's properties and decoding any `reg` through the
    // inherited cells. Counts are bounded by the blob itself.
    let mut nodes = 0u32;
    let mut props = 0u32;
    narf_firmware_fdt::walk_with_cells(data, |_path, prop_iter, cells| {
        nodes += 1;
        for (name, value) in prop_iter {
            props += 1;
            if name == "reg" {
                let _ = cells.read_one_reg(value, 0);
                let _ = cells.entry_bytes();
            }
        }
    });
    let _ = (nodes, props);

    // The remaining decoders over the same blob.
    let _ = narf_firmware_fdt::chosen_bootargs(data);
    let _ = narf_firmware_fdt::chosen_initrd_range(data);
    let mut reservations = [narf_firmware_fdt::Reservation::default(); 8];
    let _ = narf_firmware_fdt::copy_reservations(data, &mut reservations);
    let mut ranges = [narf_firmware_fdt::Reservation::default(); 8];
    let _ = narf_firmware_fdt::copy_memory_ranges(data, &mut ranges);
    let mut reserved = [narf_firmware_fdt::ReservedRegion::default(); 8];
    let _ = narf_firmware_fdt::copy_reserved_memory_ranges(data, &mut reserved);
    let mut matches = 0u32;
    narf_firmware_fdt::for_each_compatible(data, "narf,fuzz", |_path, _props, _cells| {
        matches += 1;
    });
    let _ = matches;
});
