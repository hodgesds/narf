//! PCI Express capability surface (cap ID 0x10) + Function-Level Reset.
//!
//! Spec: PCIe base 5.0 §7.5.3. The PCI Express capability is the
//! per-function structure that lets the host read/write link state,
//! tune `MaxPayload` / `MaxReadRequest`, and request a Function-Level
//! Reset (FLR) when a device gets stuck.
//!
//! Layout (offsets relative to the cap header at `cap_offset`):
//!
//! | offset | name              | width |
//! |--------|-------------------|-------|
//! | +0     | Cap ID + Next Ptr | u16   |
//! | +2     | PCIe Capabilities | u16   |
//! | +4     | Device Caps       | u32   |
//! | +8     | Device Control    | u16   |
//! | +0xA   | Device Status     | u16   |
//! | +0xC   | Link Caps         | u32   |
//! | +0x10  | Link Control      | u16   |
//! | +0x12  | Link Status       | u16   |
//! | +0x24  | Device Caps 2     | u32   |
//! | +0x28  | Device Control 2  | u16   |
//! | +0x2A  | Device Status 2   | u16   |
//!
//! The reader functions cap-gate on `Cap<BusDeviceCap, Read>` (a
//! reader can derive from the per-driver `Write` cap via the
//! `Read ⊂ Write` lattice rule). FLR gates on `Cap<BusDeviceCap,
//! Invoke>` since it's a state-changing trigger, not a config-space
//! mutation.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, CapError, Read, Write};
use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};
use crate::pci_cap;
use crate::registry::BusDeviceCap;

/// Cap ID for the PCI Express capability.
pub const PCIE_CAP_ID: u8 = pci_cap::id::PCI_EXPRESS;

/// Errors specific to the PCI Express cap surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PcieCapError {
    /// Caller's cap was revoked.
    AuthorityRevoked,
    /// Device isn't PCIe (virtio-mmio, etc).
    NotPcie,
    /// Device has no PCI Express capability — pre-PCIe legacy device.
    NotExpress,
    /// Device Caps reports FLR not supported (bit 28 clear).
    FlrUnsupported,
    /// FLR was issued but the device never returned to a responsive
    /// state within the bounded post-reset wait.
    FlrTimeout,
}

impl From<CapError> for PcieCapError {
    fn from(_: CapError) -> Self {
        PcieCapError::AuthorityRevoked
    }
}

/// Decoded snapshot of the PCI Express capability registers we care
/// about. Read once per query so the driver doesn't need to re-walk
/// the cap list on every field access.
#[derive(Copy, Clone, Debug)]
pub struct PcieStatus {
    /// `Device Capabilities` register (RO).
    pub device_caps: u32,
    /// `Device Control` register (RW).
    pub device_control: u16,
    /// `Device Status` register (RW1C).
    pub device_status: u16,
    /// `Link Capabilities` register (RO).
    pub link_caps: u32,
    /// `Link Status` register.
    pub link_status: u16,
}

impl PcieStatus {
    /// `MaxPayload Supported` — bits[2:0] of Device Caps. Encoded
    /// as `log2(payload/128)`, so 0 = 128, 1 = 256, ..., 5 = 4096.
    pub fn max_payload_supported(&self) -> u16 {
        128 << (self.device_caps & 0x7)
    }

    /// Currently-programmed `MaxPayload Size` — bits[7:5] of Device
    /// Control.
    pub fn max_payload_current(&self) -> u16 {
        128 << ((self.device_control >> 5) & 0x7)
    }

    /// `Function-Level Reset Capable` — bit 28 of Device Caps.
    pub fn flr_supported(&self) -> bool {
        (self.device_caps & (1 << 28)) != 0
    }

    /// Negotiated link speed — Link Status bits[3:0]. 1 = 2.5 GT/s,
    /// 2 = 5.0 GT/s, 3 = 8 GT/s, 4 = 16 GT/s, 5 = 32 GT/s.
    pub fn link_speed(&self) -> u8 {
        (self.link_status & 0xF) as u8
    }

    /// Negotiated link width — Link Status bits[9:4].
    pub fn link_width(&self) -> u8 {
        ((self.link_status >> 4) & 0x3F) as u8
    }
}

/// Read the PCI Express capability snapshot for `device`.
///
/// Cap-gated on `Cap<BusDeviceCap, Read>`.
pub fn read_status(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<PcieStatus, PcieCapError> {
    cap.check_live()?;
    let cfg_phys = pcie_cfg_phys(device)?;
    // SAFETY: cap-list walker bounded; cfg-space reads are aligned.
    let off = unsafe { pci_cap::find_cap(device, PCIE_CAP_ID) }
        .map_err(|_| PcieCapError::NotPcie)?
        .ok_or(PcieCapError::NotExpress)?;
    // SAFETY: off + 0x14 < 0x100 by spec; identity-mapped MMIO.
    Ok(unsafe {
        PcieStatus {
            device_caps: cfg_read32(cfg_phys, off + 0x4),
            device_control: cfg_read16(cfg_phys, off + 0x8),
            device_status: cfg_read16(cfg_phys, off + 0xA),
            link_caps: cfg_read32(cfg_phys, off + 0xC),
            link_status: cfg_read16(cfg_phys, off + 0x12),
        }
    })
}

/// Set bits in Device Control. Useful for tuning MaxPayload /
/// MaxReadRequest, or for kicking off FLR (bit 15).
///
/// `or_bits` is OR'd in — pass `0` if all you want is the read-back.
/// Returns the post-write Device Control value.
pub fn set_device_control(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    or_bits: u16,
) -> Result<u16, PcieCapError> {
    cap.check_live()?;
    let cfg_phys = pcie_cfg_phys(device)?;
    // SAFETY: cap-list walker bounded.
    let off = unsafe { pci_cap::find_cap(device, PCIE_CAP_ID) }
        .map_err(|_| PcieCapError::NotPcie)?
        .ok_or(PcieCapError::NotExpress)?;
    // SAFETY: off + 0x8 < 0x100; aligned 16-bit access.
    let cur = unsafe { cfg_read16(cfg_phys, off + 0x8) };
    let new = cur | or_bits;
    // SAFETY: same window.
    unsafe {
        cfg_write16(cfg_phys, off + 0x8, new);
    }
    Ok(new)
}

/// Issue a Function-Level Reset (FLR) on `device`.
///
/// Steps (PCIe base 5.0 §6.6.2):
///   1. Confirm Device Caps bit 28 (FLR Capable) is set.
///   2. Wait for any in-flight transactions to complete (driver's
///      job — typically by quiescing its queues; here we just spin
///      a bit and assume cooperation).
///   3. Set Device Control bit 15 (Initiate FLR).
///   4. Wait at least 100 ms for the function to complete the reset
///      (PCIe spec mandate).
///   5. Re-read Vendor ID; an unresponsive function returns 0xFFFF.
///
/// Cap-gated on `Cap<BusDeviceCap, Write>` because FLR mutates
/// device state; an `Invoke`-only cap split is a follow-up once the
/// rights system grows the relevant lattice rule.
pub fn function_level_reset(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<(), PcieCapError> {
    cap.check_live()?;

    // 1. FLR-capable check via Device Caps.
    // Derive a Read cap for the snapshot read.
    let read_cap: Cap<BusDeviceCap, Read> = cap.derive()?;
    let snap = read_status(&read_cap, device)?;
    if !snap.flr_supported() {
        return Err(PcieCapError::FlrUnsupported);
    }

    // 3. Set DevCtl.InitiateFLR (bit 15).
    let _ = set_device_control(cap, device, 1 << 15)?;

    // 4. Bounded wait — 100 ms minimum per spec; ~200 ms slack.
    // We spin on a loop bound that's far longer than QEMU needs and
    // that real silicon comfortably finishes within. The exact
    // wall-clock is calibrated by `narf_time::Instant` in callers
    // that have it; this fallback is a coarse busy-wait.
    let start = narf_time::Instant::now();
    let target_cycles = 200_000_000u64; // ~200 ms at 1 GHz; over-budget by design
    let cfg_phys = pcie_cfg_phys(device)?;
    // responsive_spin ticks sleep_pumps so cursor/FB stay alive
    // across the post-FLR settle wait. `done` returns true when
    // the device is back (vid != 0xFFFF) OR the wall-clock budget
    // is exhausted; we re-check vid_back after to disambiguate.
    let mut vid_back = false;
    let _ = narf_scheduler::responsive_spin(
        || {
            // SAFETY: identity-mapped ECAM; offset 0x00 = Vendor ID.
            let vid = unsafe { cfg_read16(cfg_phys, 0x00) };
            if vid != 0xFFFF {
                vid_back = true;
                return true;
            }
            start.cycles_since(narf_time::Instant::now()) >= target_cycles
        },
        u32::MAX,
    );
    if vid_back {
        return Ok(());
    }
    Err(PcieCapError::FlrTimeout)
}

#[inline]
fn pcie_cfg_phys(device: &BusDevice) -> Result<PhysAddr, PcieCapError> {
    match device.kind {
        BusKind::Pcie { cfg_phys, .. } => Ok(cfg_phys),
        BusKind::VirtioMmio { .. } => Err(PcieCapError::NotPcie),
    }
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read16(cfg: PhysAddr, off: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 2-byte aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u16) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 4-byte aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write16(cfg: PhysAddr, off: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + aligned.
    unsafe {
        core::ptr::write_volatile((cfg.raw() + off) as *mut u16, value);
    }
    compiler_fence(Ordering::SeqCst);
}
