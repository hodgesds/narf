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

/// Errors from `set_command` / `read_command` / `pm_d3hot_cycle`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciError {
    /// Caller's cap epoch was revoked.
    AuthorityRevoked,
    /// Device isn't a PCIe transport (e.g. virtio-mmio).
    NotPcie,
    /// Device does not advertise the requested capability (e.g. PM).
    CapNotPresent,
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

/// PCI capability ID for Power Management (PCI Bus PM Interface
/// Spec rev 1.2 §3.2.1).
const PM_CAP_ID: u8 = 0x01;
/// Offset from the PM cap header to the PMCSR (Power Management
/// Control / Status) register. PMCSR is 16 bits; bits [1:0] are the
/// PowerState field (00=D0, 01=D1, 10=D2, 11=D3hot).
const PM_PMCSR_OFFSET: u64 = 0x04;
const PM_PMCSR_STATE_MASK: u16 = 0x3;
const PM_STATE_D0: u16 = 0;
const PM_STATE_D3HOT: u16 = 3;

/// Drive the device through a D3hot → D0 power-state cycle via its
/// PCI Power-Management capability. Used to clear sticky / latched
/// state on controllers whose soft-reset path doesn't recover from
/// every error mode — notably AMD FCH SDHCI, where SRST_ALL won't
/// self-clear from a DATA-line-stuck state without first cycling the
/// PM state (see Linux `drivers/mmc/host/sdhci-pci-core.c:
/// amd_sdhci_reset`).
///
/// This is D3hot, not D3cold — the link stays up, no _PS3/_PS0
/// ACPI methods are invoked, and config-space state survives. The
/// PCI PM spec §5.4 requires a 10 ms settle after each PMCSR write
/// before next config access.
///
/// Returns `Err(CapNotPresent)` if the device has no PM cap (very
/// unusual on PCIe — every endpoint must advertise it per PCIe
/// §7.5.2).
pub fn pm_d3hot_cycle(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<(), PciError> {
    cap.check_live()?;
    // SAFETY: walking the cap-list on identity-mapped PCIe ECAM.
    let pm_off = match unsafe { crate::pci_cap::find_cap(device, PM_CAP_ID) } {
        Ok(Some(off)) => off,
        _ => return Err(PciError::CapNotPresent),
    };
    let pmcsr_off = pm_off + PM_PMCSR_OFFSET;
    let cfg = pcie_cfg_phys(device)?;

    // SAFETY: caller owns the device; PMCSR is a 2-byte aligned
    // register inside the PM capability block.
    let cur = unsafe { cfg_read16(cfg, pmcsr_off) };
    // Enter D3hot.
    // SAFETY: same.
    unsafe {
        cfg_write16(
            cfg,
            pmcsr_off,
            (cur & !PM_PMCSR_STATE_MASK) | PM_STATE_D3HOT,
        );
    }
    // PCI PM Spec §5.4: 10 ms minimum before next config access.
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(10));
    // Return to D0. The PowerState field is RW; bits 15..2 are
    // preserved so we don't clobber PME enable / data / status.
    // SAFETY: same.
    unsafe {
        cfg_write16(cfg, pmcsr_off, cur & !PM_PMCSR_STATE_MASK);
    }
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(10));
    Ok(())
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

/// Saved PCI config-space context for suspend/resume.
///
/// On D3hot (and S3 for the host) most PCIe endpoints lose their
/// configured BAR addresses, Command register, cache-line size,
/// interrupt-line, and MSI/MSI-X enable state. The PM registry
/// driver snapshots a `SavedPciConfig` on suspend and reapplies
/// it on resume.
///
/// Only the 64-byte type-0 header is captured. Capability blocks
/// (MSI, MSI-X, PCIe extended) live at vendor-specific offsets and
/// are restored by per-cap helpers (see `bus::msi`, `bus::msix`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SavedPciConfig {
    /// Command register (cfg+0x04). Low bit = I/O space, bit 1 =
    /// Memory space, bit 2 = Bus Master, bit 10 = INTx disable.
    pub command: u16,
    /// Cache-line size (cfg+0x0C) in 32-bit words.
    pub cache_line_size: u8,
    /// Master latency timer (cfg+0x0D). PCI-only; ignored on PCIe
    /// but we save+restore for completeness.
    pub latency_timer: u8,
    /// BIST (cfg+0x0F) — typically 0; restored as-is.
    pub bist: u8,
    /// BARs 0..=5 (cfg+0x10..0x28). Each is a 32-bit register; for
    /// 64-bit BARs the high half lives in the next slot.
    pub bars: [u32; 6],
    /// Cardbus CIS pointer (cfg+0x28).
    pub cardbus_cis_ptr: u32,
    /// Subsystem vendor/device (cfg+0x2C..0x2E, 0x2E..0x30). Most
    /// hardware exposes these as RO; saving for diagnostic parity.
    pub subsys_vendor: u16,
    pub subsys_device: u16,
    /// Expansion ROM base address (cfg+0x30).
    pub expansion_rom_bar: u32,
    /// Interrupt line / pin (cfg+0x3C..0x3E). INTx routing — even
    /// MSI-X devices have these populated by firmware.
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    /// Min_Gnt / Max_Lat (cfg+0x3E..0x40) — ignored on PCIe but
    /// captured for parity.
    pub min_gnt: u8,
    pub max_lat: u8,
}

/// Snapshot the type-0 header of `device`'s config space. Caller
/// holds a `Cap<BusDeviceCap, Write>` to prove device authority.
pub fn save_config(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<SavedPciConfig, PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: cfg-space is identity-mapped; offsets stay inside
    // the 64-byte type-0 header.
    let saved = unsafe {
        SavedPciConfig {
            command: cfg_read16(cfg, 0x04),
            cache_line_size: cfg_read8(cfg, 0x0C),
            latency_timer: cfg_read8(cfg, 0x0D),
            bist: cfg_read8(cfg, 0x0F),
            bars: [
                cfg_read32(cfg, 0x10),
                cfg_read32(cfg, 0x14),
                cfg_read32(cfg, 0x18),
                cfg_read32(cfg, 0x1C),
                cfg_read32(cfg, 0x20),
                cfg_read32(cfg, 0x24),
            ],
            cardbus_cis_ptr: cfg_read32(cfg, 0x28),
            subsys_vendor: cfg_read16(cfg, 0x2C),
            subsys_device: cfg_read16(cfg, 0x2E),
            expansion_rom_bar: cfg_read32(cfg, 0x30),
            interrupt_line: cfg_read8(cfg, 0x3C),
            interrupt_pin: cfg_read8(cfg, 0x3D),
            min_gnt: cfg_read8(cfg, 0x3E),
            max_lat: cfg_read8(cfg, 0x3F),
        }
    };
    Ok(saved)
}

/// Restore a previously-captured config snapshot. Writes BARs +
/// auxiliary fields *first*, then the Command register *last* —
/// the order matters because the device starts decoding MMIO /
/// honouring Bus Master access the moment the Command register
/// has those bits set, and we need the BAR base addresses in
/// place before that happens.
pub fn restore_config(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    saved: &SavedPciConfig,
) -> Result<(), PciError> {
    cap.check_live()?;
    let cfg = pcie_cfg_phys(device)?;
    // SAFETY: cfg-space writes within the type-0 header; the device
    // is in D0 (woken by the platform) but not yet command-enabled.
    unsafe {
        // BARs first.
        cfg_write32(cfg, 0x10, saved.bars[0]);
        cfg_write32(cfg, 0x14, saved.bars[1]);
        cfg_write32(cfg, 0x18, saved.bars[2]);
        cfg_write32(cfg, 0x1C, saved.bars[3]);
        cfg_write32(cfg, 0x20, saved.bars[4]);
        cfg_write32(cfg, 0x24, saved.bars[5]);
        cfg_write32(cfg, 0x30, saved.expansion_rom_bar);
        // Aux fields.
        cfg_write8(cfg, 0x0C, saved.cache_line_size);
        cfg_write8(cfg, 0x0D, saved.latency_timer);
        cfg_write8(cfg, 0x0F, saved.bist);
        cfg_write8(cfg, 0x3C, saved.interrupt_line);
        // INTx pin / Min_Gnt / Max_Lat are RO on real silicon —
        // skip writes to avoid spurious config aborts on devices
        // that aren't tolerant.
        // Command register LAST — re-enables MEM / BUS_MASTER /
        // INTx-disable in a single atomic-ish write, matching the
        // state the driver was running in before suspend.
        cfg_write16(cfg, 0x04, saved.command);
    }
    Ok(())
}

#[inline]
unsafe fn cfg_read8(cfg: PhysAddr, off: u64) -> u8 {
    compiler_fence(Ordering::SeqCst);
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u8) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write8(cfg: PhysAddr, off: u64, value: u8) {
    compiler_fence(Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile((cfg.raw() + off) as *mut u8, value);
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile((cfg.raw() + off) as *mut u32, value);
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
pub fn read_intx_pin(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<u8, PciError> {
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
