//! Arch-neutral PCIe ECAM walker.
//!
//! Both x86_64 (q35 ECAM at `0xb000_0000`) and aarch64 (QEMU virt
//! ECAM at `0x3F00_0000`) use the standard ECAM layout described in
//! PCIe spec §6.2: 256 buses × 32 devices × 8 functions × 4 KiB =
//! 256 MiB. Per-arch backends supply the base; this module owns the
//! walk + per-function header decode.

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_memory::PhysAddr;

use crate::addr::{BusAddr, PcieAddr};
use crate::device::{BusDevice, BusKind, DeviceId};

/// Number of PCIe buses in a fully-populated ECAM region.
pub const MAX_BUSES: u16 = 256;

/// Walk an ECAM region and return every function whose vendor ID is
/// valid (i.e. not `0xFFFF` — PCIe's "no device here" sentinel).
/// Walks up to `MAX_BUSES` (256) — full PCIe topology.
///
/// # Safety
/// The caller promises `ecam_base` names a real ECAM region of at
/// least `MAX_BUSES * 0x10_0000` bytes (256 MiB) and that the
/// kernel's identity map covers it (low 4 GiB on x86_64 q35 ECAM).
pub unsafe fn enumerate(ecam_base: PhysAddr) -> Vec<BusDevice> {
    // SAFETY: forwarded.
    unsafe { enumerate_n(ecam_base, MAX_BUSES) }
}

/// Same as `enumerate` but caps the walk at `n_buses`. Useful on
/// platforms whose ECAM region is smaller than the full 256-bus
/// PCIe range — e.g. QEMU virt's `pcie@10000000` exposes 16 MiB =
/// 16 buses; reading past that aborts on Device memory.
///
/// # Safety
/// `ecam_base + n_buses * 0x10_0000` must lie inside the kernel's
/// identity map of MMIO-tolerant memory.
pub unsafe fn enumerate_n(ecam_base: PhysAddr, n_buses: u16) -> Vec<BusDevice> {
    // SAFETY: forwarded to enumerate_segment.
    unsafe { enumerate_segment(ecam_base, n_buses, 0) }
}

/// Walk an ECAM-shaped config window and return every discovered
/// function tagged with the caller-supplied `segment`. Used by the
/// Intel VMD bridge to surface children behind its BAR0 config window
/// — the layout is identical to platform ECAM (4 KiB per function,
/// `(bus<<20)|(dev<<15)|(fn<<12)` offset), but the children live in
/// a private PCI domain that must not collide with the host's
/// `segment=0` keys. VMD allocates a non-zero segment per bridge.
///
/// # Safety
/// `ecam_base + n_buses * 0x10_0000` must lie inside the kernel's
/// identity map of MMIO-tolerant memory.
pub unsafe fn enumerate_segment(ecam_base: PhysAddr, n_buses: u16, segment: u16) -> Vec<BusDevice> {
    // Config space is MMIO and must be ioremap'd before any access — the low
    // identity map that used to make `phys as *const u32` work is gone.
    // SAFETY: caller's contract that this names a real ECAM window.
    if !unsafe { crate::ecam::map_segment(ecam_base, (n_buses as u64) * 0x10_0000) } {
        return Vec::new();
    }
    let mut devices = Vec::new();

    for bus in 0..n_buses {
        for dev in 0..32u8 {
            // Probe function 0 first. If vendor is invalid, slot is empty.
            // If valid, the header-type bit 7 says "multi-function" —
            // if clear, fn 0 is the only function on the device.
            let addr0 = PcieAddr::new(segment, bus as u8, dev, 0);
            let cfg0 = phys_for(ecam_base, addr0);
            // SAFETY: ecam_base + offset is inside the ECAM region per
            // the MAX_BUSES bound; reads are 4-byte aligned.
            // SAFETY: Valid memory or trusted environment
            let vendor_device = unsafe { ecam_read32(cfg0) };
            let v0 = vendor_device & 0xFFFF;
            // PCI Local Bus 3.0: vendor ID `0xFFFF` means "no
            // device responded" (cfg cycle aborted). Vendor ID
            // `0x0000` is reserved + has been observed coming back
            // from unmapped ECAM regions on UEFI platforms whose
            // firmware-as-ROM mapping returns zeros instead of
            // forwarding the cfg cycle. Treat both as empty.
            if v0 == 0xFFFF || v0 == 0x0000 {
                continue;
            }

            // SAFETY: same as above; offset 0x0C holds header/class.
            let hdr_word = unsafe { ecam_read32(PhysAddr::new(cfg0.raw() + 0x0C)) };
            let header_type = ((hdr_word >> 16) & 0xFF) as u8;
            let multifn = (header_type & 0x80) != 0;
            let max_fn: u8 = if multifn { 8 } else { 1 };

            for fn_ in 0..max_fn {
                let addr = PcieAddr::new(segment, bus as u8, dev, fn_);
                let cfg = phys_for(ecam_base, addr);
                // SAFETY: in-range ECAM read.
                let vd = unsafe { ecam_read32(cfg) };
                let vendor = (vd & 0xFFFF) as u16;
                let device = ((vd >> 16) & 0xFFFF) as u16;
                // Same empty-slot test as the function-0 probe above.
                if vendor == 0xFFFF || vendor == 0x0000 {
                    continue;
                }

                // Offset 0x08: rev (0..=7), class_prog_if (8..=15),
                // subclass (16..=23), class (24..=31). The upper 24
                // bits give the (class, subclass, prog_if) triple.
                // SAFETY: in-range.
                let class_word = unsafe { ecam_read32(PhysAddr::new(cfg.raw() + 0x08)) };
                let class = (class_word >> 8) & 0x00FF_FFFF;

                // Offsets 0x2C/0x2E: Subsystem Vendor ID + Subsystem ID.
                // PCI 3.0 §6.2.4 — present in every type-0 header.
                // Linux ref: drivers/pci/probe.c::pci_read_bases (called
                // by pci_setup_device) populates dev->subsystem_vendor /
                // dev->subsystem_device. Packed in one 32-bit read:
                // bits [15:0] = subsystem_vendor, [31:16] = subsystem_id.
                // SAFETY: 0x2C is 4-byte aligned; in-range type-0 header.
                let subsys_word = unsafe { ecam_read32(PhysAddr::new(cfg.raw() + 0x2C)) };
                let subsystem_vendor = (subsys_word & 0xFFFF) as u16;
                let subsystem_id = ((subsys_word >> 16) & 0xFFFF) as u16;

                devices.push(BusDevice {
                    addr: BusAddr::Pcie(addr),
                    id: DeviceId {
                        vendor,
                        device,
                        class,
                        subsystem_vendor,
                        subsystem_id,
                    },
                    kind: BusKind::Pcie {
                        addr,
                        cfg_phys: cfg,
                    },
                });
            }
        }
    }

    devices
}

#[inline]
unsafe fn ecam_read32(addr: PhysAddr) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts `addr` is a readable 4-byte MMIO slot inside a
    // mapped ECAM segment. An unmapped address reads as all-ones, which is
    // exactly how config space reports "no device" — far better than the
    // wild dereference a raw physical cast would produce.
    let Some(p) = crate::ecam::ptr_for(addr, 0) else {
        return u32::MAX;
    };
    // SAFETY: `p` is inside the mapped ECAM window resolved above, and the
    // caller asserts the slot is a 4-byte-aligned config register.
    let v = unsafe { core::ptr::read_volatile(p as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
fn phys_for(ecam_base: PhysAddr, addr: PcieAddr) -> PhysAddr {
    PhysAddr::new(ecam_base.raw() + addr.ecam_offset())
}
