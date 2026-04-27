//! x86_64 PCIe ECAM enumeration.
//!
//! Spec: `bus/` §5 x86_64. QEMU `q35` exposes a PCIe host bridge with
//! ECAM at `0xb000_0000` (the `pcie.0` memory region, 256 MiB =
//! 256 buses × 32 devices × 8 functions × 4 KiB). The MCFG ACPI table
//! would tell us this authoritatively; Stage 2 doesn't yet parse it
//! (boot/ exposes PVH memmap, not ACPI), so we fall back to the
//! QEMU default. The moment `boot/` surfaces an MCFG pointer this
//! file picks it up (see `ECAM_DEFAULT_BASE`).
//!
//! Walker body lives in `crate::pcie` so the aarch64 backend (QEMU
//! virt PCIe at `0x3F00_0000`) can share the implementation.

use alloc::vec::Vec;

use narf_memory::PhysAddr;

use crate::device::BusDevice;

/// QEMU `q35` default PCIe ECAM base. The `pcie-mmcfg` region sits at
/// 0xb000_0000 and is 256 MiB wide (`0x1000_0000`). This lives in the
/// low-4-GiB identity map the MMU brings up, so raw reads are safe
/// without a separate translation.
pub const ECAM_DEFAULT_BASE: PhysAddr = PhysAddr::new(0xb000_0000);

/// Re-export the architecturally-shared bus count so existing callers
/// keep working without an import shuffle.
pub use crate::pcie::MAX_BUSES;

/// Walk the ECAM and return every function whose vendor ID is valid.
///
/// # Safety
/// Forwarded to `crate::pcie::enumerate`.
pub unsafe fn enumerate(ecam_base: PhysAddr) -> Vec<BusDevice> {
    // SAFETY: caller-checked ECAM range.
    unsafe { crate::pcie::enumerate(ecam_base) }
}
