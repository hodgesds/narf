//! x86_64 PCIe ECAM enumeration.
//!
//! Spec: `bus/` §5 x86_64. QEMU `q35` exposes a PCIe host bridge with
//! ECAM at `0xb000_0000` (the `pcie.0` memory region, 256 MiB =
//! 256 buses × 32 devices × 8 functions × 4 KiB). The MCFG ACPI table
//! would tell us this authoritatively; Stage 2 doesn't yet parse it
//! (boot/ exposes PVH memmap, not ACPI), so we fall back to the
//! QEMU default. The moment `boot/` surfaces an MCFG pointer this
//! file picks it up (see `ECAM_DEFAULT_BASE` + `init` signature).
//!
//! Enumeration strategy: scan the root bus (bus 0), and any bus we
//! see behind a PCI-to-PCI bridge (header type 1). Multi-function
//! devices are detected via bit 7 of the header-type field. We do
//! not do BAR sizing — that's a Wave-2 follow-up; each driver will
//! size its own BARs through the bus-provided cfg-space cap.

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_memory::PhysAddr;

use crate::addr::{BusAddr, PcieAddr};
use crate::device::{BusDevice, BusKind, DeviceId};

/// QEMU `q35` default PCIe ECAM base. The `pcie-mmcfg` region sits at
/// 0xb000_0000 and is 256 MiB wide (`0x1000_0000`). This lives in the
/// low-4-GiB identity map the MMU brings up, so raw reads are safe
/// without a separate translation.
pub const ECAM_DEFAULT_BASE: PhysAddr = PhysAddr::new(0xb000_0000);

/// Number of buses to scan in the default ECAM. Full PCIe is 256;
/// QEMU only ever populates a handful (bus 0 + any nested behind the
/// `pcie.0` root port) so scanning all of them is cheap.
pub const MAX_BUSES: u16 = 256;

/// A single cfg-space `u32` read. ECAM access is naturally aligned
/// 4-byte MMIO; the `mfence`-equivalent `compiler_fence` pair defeats
/// LTO reorders per `build/` §4.
///
/// # Safety
/// `addr` must point into an ECAM-mapped 4-KiB function window. The
/// low-4-GiB identity map covers the QEMU default ECAM, so Stage 2
/// callers don't need a separate mapping step.
#[inline]
unsafe fn ecam_read32(addr: PhysAddr) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts `addr` is a readable 4-byte MMIO slot.
    let v = unsafe { core::ptr::read_volatile(addr.raw() as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Walk the ECAM and return every function whose vendor ID is valid
/// (i.e. not `0xFFFF` — PCIe's "no device here" sentinel).
///
/// # Safety
/// The caller promises `ecam_base` names a real ECAM region of at
/// least `MAX_BUSES * 0x10_0000` bytes and that the low-4-GiB identity
/// map covers it (true for QEMU q35 by construction).
pub unsafe fn enumerate(ecam_base: PhysAddr) -> Vec<BusDevice> {
    let mut devices = Vec::new();

    for bus in 0..MAX_BUSES {
        for dev in 0..32u8 {
            // Probe function 0 first. If vendor is invalid, this slot
            // is empty; skip. If it's valid, check the header-type
            // field for multi-function (bit 7) — if clear, only fn 0
            // exists.
            let addr0 = PcieAddr::new(0, bus as u8, dev, 0);
            let cfg0  = phys_for(ecam_base, addr0);
            // SAFETY: ecam_base + offset is inside the ECAM region per
            // MAX_BUSES bound; reads are 4-byte aligned.
            let vendor_device = unsafe { ecam_read32(cfg0) };
            if (vendor_device & 0xFFFF) == 0xFFFF {
                continue; // slot empty
            }

            // SAFETY: same as above; offset 0x0C holds header/class.
            let hdr_word = unsafe {
                ecam_read32(PhysAddr::new(cfg0.raw() + 0x0C))
            };
            let header_type = ((hdr_word >> 16) & 0xFF) as u8;
            let multifn     = (header_type & 0x80) != 0;
            let max_fn: u8  = if multifn { 8 } else { 1 };

            for fn_ in 0..max_fn {
                let addr = PcieAddr::new(0, bus as u8, dev, fn_);
                let cfg  = phys_for(ecam_base, addr);
                // SAFETY: in-range ECAM read.
                let vd   = unsafe { ecam_read32(cfg) };
                let vendor = (vd & 0xFFFF) as u16;
                let device = ((vd >> 16) & 0xFFFF) as u16;
                if vendor == 0xFFFF { continue; }

                // Offset 0x08 holds: rev (0..=7), class_prog_if (8..=15),
                // subclass (16..=23), class (24..=31). We pack the upper
                // 24 bits as the "class" triple.
                // SAFETY: in-range.
                let class_word = unsafe {
                    ecam_read32(PhysAddr::new(cfg.raw() + 0x08))
                };
                let class = (class_word >> 8) & 0x00FF_FFFF;

                devices.push(BusDevice {
                    addr: BusAddr::Pcie(addr),
                    id:   DeviceId { vendor, device, class },
                    kind: BusKind::Pcie { addr, cfg_phys: cfg },
                });
            }
        }
    }

    devices
}

#[inline]
fn phys_for(ecam_base: PhysAddr, addr: PcieAddr) -> PhysAddr {
    PhysAddr::new(ecam_base.raw() + addr.ecam_offset())
}
