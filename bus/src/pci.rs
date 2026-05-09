//! PCIe configuration-space helpers shared across drivers.
//!
//! Beyond the BAR / MSI-X paths in `bus::bar` / `bus::msix`, every
//! Stage-4 driver eventually flips a bit in the **command register**
//! (cfg offset 0x04). Without `Bus Master Enable` (bit 2) the device
//! can't DMA — its MSI writes and queue-buffer accesses get blocked
//! at the host bridge. QEMU's emulated devices are permissive and
//! work without BME being set, but real silicon refuses; keeping the
//! helper here means drivers don't each hand-roll the cfg-space
//! write.
//!
//! Cap-gated: `set_command` requires a live `Cap<BusDeviceCap, Write>`
//! the caller obtained from `claim_device_cap`. That's the same
//! authority MSI-X programming uses, since both touch cfg-space.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, Write};
use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};
use crate::registry::BusDeviceCap;

/// Cfg-space offset of the type-0 / type-1 Command register (PCIe spec
/// §7.5.1.1.3).
pub const COMMAND_OFFSET: u64 = 0x04;

/// Bits in the Command register we care about today.
pub mod cmd {
    /// I/O Space Enable. Required before reads/writes to I/O-space
    /// BARs are routed to the device.
    pub const IO_SPACE: u16 = 1 << 0;
    /// Memory Space Enable. Required before reads/writes to MMIO BARs
    /// are routed to the device. Most drivers want this on.
    pub const MEM_SPACE: u16 = 1 << 1;
    /// Bus Master Enable. Required for the device to issue any DMA
    /// (write its completion queue, fetch from a submission queue,
    /// or write an MSI message). All drivers that touch DMA need
    /// this set.
    pub const BUS_MASTER: u16 = 1 << 2;
    /// Disable INTx legacy interrupt assertion. Recommended on when
    /// using MSI / MSI-X exclusively.
    pub const INTX_DISABLE: u16 = 1 << 10;
}

/// Errors from `set_command` / `read_command`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciError {
    /// Caller's cap epoch was revoked.
    AuthorityRevoked,
    /// Device isn't a PCIe transport (e.g. virtio-mmio).
    NotPcie,
}

impl From<narf_capabilities::CapError> for PciError {
    fn from(_: narf_capabilities::CapError) -> Self {
        PciError::AuthorityRevoked
    }
}

/// Read the device's current Command-register value.
///
/// Cap-gated; the cap's epoch is checked.
pub fn read_command(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<u16, PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: cfg-space is identity-mapped for the lifetime of the
    // BusDevice, and offset 0x04 is well inside the type-0 header.
    Ok(unsafe { cfg_read16(cfg, COMMAND_OFFSET) })
}

/// OR `bits` into the device's Command register, leaving every other
/// bit unchanged. Used to flip on `MEM_SPACE | BUS_MASTER` before a
/// driver starts DMA, or to set `INTX_DISABLE` once MSI/MSI-X is up.
///
/// Cap-gated. The read-modify-write is *not* atomic against a parallel
/// writer — the Stage-3 single-threaded contract holds (only one
/// driver claims a given device).
pub fn set_command(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    bits: u16,
) -> Result<u16, PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: same window.
    let old = unsafe { cfg_read16(cfg, COMMAND_OFFSET) };
    let new = old | bits;
    // SAFETY: same window; caller owns the device exclusively.
    unsafe {
        cfg_write16(cfg, COMMAND_OFFSET, new);
    }
    Ok(new)
}

/// Mask `bits` out of the device's Command register, leaving every
/// other bit unchanged.
pub fn clear_command(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    bits: u16,
) -> Result<u16, PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: same window.
    let old = unsafe { cfg_read16(cfg, COMMAND_OFFSET) };
    let new = old & !bits;
    // SAFETY: same window; caller owns the device.
    unsafe {
        cfg_write16(cfg, COMMAND_OFFSET, new);
    }
    Ok(new)
}

#[inline]
fn pcie_cfg_phys(device: &BusDevice) -> Result<PhysAddr, PciError> {
    match device.kind {
        BusKind::Pcie { cfg_phys, .. } => Ok(cfg_phys),
        BusKind::VirtioMmio { .. } => Err(PciError::NotPcie),
    }
}

#[inline]
unsafe fn cfg_read16(cfg: PhysAddr, off: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 2-byte aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u16) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write16(cfg: PhysAddr, off: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 2-byte aligned.
    unsafe {
        core::ptr::write_volatile((cfg.raw() + off) as *mut u16, value);
    }
    compiler_fence(Ordering::SeqCst);
}

/// PCI config-space offset for the INTx pin field (PCI Local Bus
/// Specification §6.2.4: byte 0x3D, values 0=no INTx, 1=INTA,
/// 2=INTB, 3=INTC, 4=INTD).
const INTERRUPT_PIN_OFFSET: u64 = 0x3D;

/// Read the device's INTx interrupt-pin selector. Returns `0` for
/// devices that don't drive a legacy INTx line, `1..=4` for
/// INTA..INTD. Used by the INTx fallback in drivers (e.g. xHCI)
/// when MSI-X cap walking fails — combined with the device's
/// slot via the AML `_PRT` lookup it resolves to the GSI to
/// route through the IOAPIC.
///
/// Cap-gated; the cap's epoch is checked.
pub fn read_intx_pin(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<u8, PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: cfg-space is identity-mapped for the lifetime of
    // the BusDevice; offset 0x3D is well inside the type-0
    // header.
    Ok(unsafe { core::ptr::read_volatile((cfg.raw() + INTERRUPT_PIN_OFFSET) as *const u8) })
}

/// Compute the GIC ITS DeviceID for a PCIe function. ITS uses the
/// bus master's RequesterID — for PCIe that's just the BDF packed
/// into a 16-bit value: `(bus << 8) | (dev << 3) | fn`. Same shape
/// QEMU virt's gpex-host-msi-irqfd uses for `requester_id_to_devid`.
///
/// Returns `None` for non-PCIe devices.
#[inline]
pub fn requester_id(device: &BusDevice) -> Option<u16> {
    match device.kind {
        BusKind::Pcie { addr, .. } => {
            Some(((addr.bus as u16) << 8) | ((addr.device as u16) << 3) | (addr.function as u16))
        }
        BusKind::VirtioMmio { .. } => None,
    }
}
