//! aarch64 bus enumeration entry points.
//!
//! Spec: `bus/` §5 aarch64. Enumeration proper lives in
//! `crate::dt` on top of `narf_firmware_fdt` — the tree's one FDT
//! parser. This module keeps the arch entry points: `enumerate`
//! (DT first, QEMU-`virt` slot-scan fallback for the no-DTB case)
//! and `discover_pmu_ppi`.
//!
//! History: this file carried its own hand-rolled FDT walker (a
//! second parser, virtio-mmio + PCIe node names only). It was
//! deleted in the DT programme's step 3 (issue #1048); the
//! audit's "one walker" rule (embedded audit R1,
//! boot-enumeration.md §5.1) is now structural, not aspirational.

use alloc::vec::Vec;

use narf_memory::PhysAddr;

use crate::device::BusDevice;

/// Enumerate the aarch64 platform: devicetree-described devices
/// (platform records, populated virtio-mmio slots, PCIe behind
/// the DT host bridge) when a DTB is available, falling back to
/// the QEMU `virt` virtio-mmio slot scan when there is none (or
/// the blob yields nothing — a bogus pointer degrades to the
/// fallback, never to UB: `discover` validates the header before
/// any offset is trusted).
///
/// # Safety
/// `dtb` — when `Some` — must point at a DTB blob in
/// identity/direct-mapped memory describing this machine.
pub unsafe fn enumerate(dtb: Option<PhysAddr>) -> Vec<BusDevice> {
    if let Some(dtb_phys) = dtb {
        // SAFETY: caller promise — the DTB is live mapped memory;
        // `discover` validates magic + totalsize before slicing.
        if let Some(blob) = unsafe {
            narf_firmware_fdt::discover(dtb_phys.raw() as usize, crate::dt::MAX_DTB_BYTES)
        } {
            // SAFETY: the blob describes this machine (the boot
            // handoff supplied it); enumerate_dt's probes run
            // under that contract.
            let out = unsafe { crate::dt::enumerate_dt(blob) };
            if !out.is_empty() {
                return out;
            }
        }
    }

    // Fallback: QEMU `virt` layout is well known. 32 virtio-mmio
    // slots starting at 0x0a00_0000, stride 0x200 each. This
    // mirrors the same "trust QEMU defaults when FDT parsing isn't
    // wired" fallback `boot/src/aarch64/mod.rs` uses for the
    // memory map, and is the path the DTB-less `-kernel` boots
    // (and `init(None)` smokes) exercise.
    let mut out = Vec::new();
    const VIRT_MMIO_BASE: u64 = 0x0a00_0000;
    const VIRT_MMIO_STRIDE: u64 = 0x200;
    const VIRT_MMIO_COUNT: u64 = 32;
    for slot in 0..VIRT_MMIO_COUNT {
        let base_addr = VIRT_MMIO_BASE + slot * VIRT_MMIO_STRIDE;
        // SAFETY: probe_virtio_mmio maps the window it reads; the
        // QEMU virt slot range is machine-fixed.
        if let Some(dev) = unsafe { crate::dt::probe_virtio_mmio(base_addr, VIRT_MMIO_STRIDE) } {
            out.push(dev);
        }
    }
    out
}

/// Discover the firmware-described Arm PMUv3 private interrupt.
///
/// The GIC binding encodes a PPI as `<1, ppi-number, flags>` and
/// the architectural INTID is `16 + ppi-number`. There is
/// deliberately no QEMU fallback: the PMU PPI is
/// implementation-defined and sampling must remain unavailable
/// when firmware does not describe it.
///
/// # Safety
/// `dtb` must point at a live, identity-mapped flattened
/// Devicetree blob.
pub unsafe fn discover_pmu_ppi(dtb: PhysAddr) -> Option<u32> {
    // SAFETY: caller promises a readable, live blob; `discover`
    // validates the header before slicing.
    let blob =
        unsafe { narf_firmware_fdt::discover(dtb.raw() as usize, crate::dt::MAX_DTB_BYTES) }?;
    // The PMU node carries no `interrupt-parent` of its own on
    // QEMU virt; the root's is the inherited one.
    let inherited = narf_firmware_fdt::root_prop_u32(blob, "interrupt-parent");
    let mut ppi = None;
    narf_firmware_fdt::for_each_compatible(blob, "arm,armv8-pmuv3", |_path, props, _cells| {
        narf_firmware_fdt::for_each_interrupt(blob, props, inherited, |_parent, cells| {
            // Spec §3.2: only a three-cell GIC PPI specifier
            // (type 1) with a PPI number in range resolves.
            if cells.len() == 3 && cells[0] == 1 && cells[1] < 16 {
                ppi = Some(16 + cells[1]);
            }
        });
    });
    ppi
}
