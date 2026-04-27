//! Legacy MSI (Message-Signaled Interrupt) capability — cap ID 0x05.
//!
//! Spec: PCIe base 5.0 §7.7.1. MSI predates MSI-X and is what most
//! pre-2010 PCIe devices and many embedded controllers implement.
//! Differences from MSI-X (`bus::msix`):
//!
//! - **Up to 32 vectors** instead of 2048.
//! - **Single message-address / message-data pair in cfg-space**
//!   instead of a BAR-mapped table. The device fires
//!   `msg_data + i` for vector `i` (0..N-1) rather than per-entry
//!   programming.
//! - **No per-vector mask** in basic MSI; PCIe added optional
//!   per-vector masking later (cap structure variant). Stage-3 cuts
//!   only support the basic 64-bit-address form.
//!
//! Cap structure (Multi-Message Capable = how many vectors device
//! wants; Multi-Message Enable = how many host actually grants):
//!
//! | offset | name           | width |
//! |--------|----------------|-------|
//! | +0     | Cap ID + Next  | u16   |
//! | +2     | Message Ctrl   | u16   |
//! | +4     | Message Addr   | u32   |
//! | +8     | Message Addr Hi| u32 (only if 64-bit cap) |
//! | +0xC   | Message Data   | u16   |
//!
//! For 32-bit MSI (no 64-bit address), `Message Data` is at +8.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, CapError, Write};
use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};
use crate::pci_cap;
use crate::registry::BusDeviceCap;

/// MSI cap ID per PCIe spec §7.7.1.
pub const MSI_CAP_ID: u8 = pci_cap::id::MSI;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsiError {
    AuthorityRevoked,
    NotPcie,
    /// Device exposes neither MSI nor MSI-X.
    CapabilityNotFound,
    /// Caller asked for more vectors than the device's
    /// Multi-Message-Capable field permits.
    TooManyVectors,
    /// MSI not supported on this arch (placeholder for future
    /// arch-specific gating).
    Unsupported,
}

impl From<CapError> for MsiError {
    fn from(_: CapError) -> Self { MsiError::AuthorityRevoked }
}

/// MSI configuration after `enable_msi`. Holding this is the type-
/// level proof that the device's MSI cap was discovered + enabled.
#[derive(Debug)]
pub struct MsiConfig {
    /// Cfg-space offset of the cap header.
    cap_offset:    u64,
    /// `true` if the cap supports a 64-bit Message Address (most
    /// modern devices do).
    is_64bit:      bool,
    /// `true` if the cap supports per-vector masking.
    per_vec_mask:  bool,
    /// Multi-Message Capable — `log2(N)` vectors device wants.
    /// Actual N = 1 << mmc, range 1..=32.
    mmc_log2:      u8,
    /// Multi-Message Enable — what we asked for. Mirrors what's in
    /// the device's Message Control register.
    mme_log2:      u8,
    /// Cfg-space window for the device.
    cfg_phys:      PhysAddr,
}

impl MsiConfig {
    pub fn vectors_supported(&self) -> u16 { 1 << self.mmc_log2 }
    pub fn vectors_enabled(&self)   -> u16 { 1 << self.mme_log2 }
    pub fn is_64bit(&self)          -> bool { self.is_64bit }
    pub fn per_vector_mask(&self)   -> bool { self.per_vec_mask }
}

/// Discover the MSI cap on `device` and reserve up to `n_vectors`
/// (rounded down to the largest power of 2 the device supports).
/// Does not yet enable delivery — the caller writes the message
/// address/data via `program_msi` then flips the enable bit with
/// `enable`.
///
/// Cap-gated.
pub fn enable_msi(
    cap:    &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    n_requested: u16,
) -> Result<MsiConfig, MsiError> {
    cap.check_live()?;
    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. }     => return Err(MsiError::NotPcie),
    };
    // SAFETY: bounded cap-list walk.
    let cap_off = unsafe { pci_cap::find_cap(device, MSI_CAP_ID) }
        .map_err(|_| MsiError::NotPcie)?
        .ok_or(MsiError::CapabilityNotFound)?;

    // SAFETY: cap_off + 2 < 0x100 by spec.
    let msg_ctrl = unsafe { cfg_read16(cfg_phys, cap_off + 2) };
    let mmc      = ((msg_ctrl >> 1) & 0x7) as u8;          // bits 3:1
    let is_64bit = (msg_ctrl & (1 << 7))  != 0;
    let per_vec  = (msg_ctrl & (1 << 8))  != 0;

    if n_requested == 0 || n_requested > (1u16 << mmc) {
        return Err(MsiError::TooManyVectors);
    }
    // Round down to the largest power of 2 ≤ n_requested ≤ MMC.
    let mme_log2 = (15 - n_requested.leading_zeros() as u8).min(mmc);

    Ok(MsiConfig {
        cap_offset: cap_off,
        is_64bit,
        per_vec_mask: per_vec,
        mmc_log2: mmc,
        mme_log2,
        cfg_phys,
    })
}

/// Program the MSI message-address + message-data pair, then enable.
///
/// On x86_64: addr = `0xFEE0_0000 | (apic<<12)`, data = base IDT
/// vector. Multi-message MSI fires `data + i` for vector `i`.
///
/// On aarch64: addr = `GITS_TRANSLATER`, data = base EventID. The
/// caller is responsible for issuing ITS `MAPD` + `MAPTI` for every
/// `(DeviceID, EventID..EventID+N-1)` pair before enabling.
///
/// # Safety
/// Caller owns the device's cfg-space exclusively for the call.
pub unsafe fn program_msi(
    cfg: &mut MsiConfig,
    target_apic_id: u32,
    base_irq:        u8,
) -> Result<u64, MsiError> {
    let (addr, data) = msi_message(target_apic_id, base_irq);

    let addr_lo = addr as u32;
    let addr_hi = (addr >> 32) as u32;

    // SAFETY: cap_offset is < 0x100 by construction; offsets +4 ..
    // +0xC inclusive stay in the type-0 header.
    unsafe {
        cfg_write32(cfg.cfg_phys, cfg.cap_offset + 4, addr_lo);
        if cfg.is_64bit {
            cfg_write32(cfg.cfg_phys, cfg.cap_offset + 8, addr_hi);
            cfg_write16(cfg.cfg_phys, cfg.cap_offset + 0xC, data as u16);
        } else {
            // 32-bit MSI: data sits at +8. The high address word
            // doesn't exist on this cap.
            if addr_hi != 0 { return Err(MsiError::Unsupported); }
            cfg_write16(cfg.cfg_phys, cfg.cap_offset + 8, data as u16);
        }
    }
    Ok(addr)
}

/// Flip the MSI Enable bit (Message Control bit 0). Also writes the
/// negotiated Multi-Message Enable field (bits 6:4) so the device
/// knows how many vectors we actually granted.
///
/// # Safety
/// Caller owns the device's cfg-space exclusively.
pub unsafe fn enable(cfg: &MsiConfig) -> Result<(), MsiError> {
    // SAFETY: cap window.
    let mc = unsafe { cfg_read16(cfg.cfg_phys, cfg.cap_offset + 2) };
    let new = (mc & !(0x7 << 4))
        | ((cfg.mme_log2 as u16) << 4)
        | 1; // Enable
    // SAFETY: same.
    unsafe { cfg_write16(cfg.cfg_phys, cfg.cap_offset + 2, new); }
    Ok(())
}

/// Compute (msi_addr, msg_data) for the configured arch. Mirrors the
/// helper in `msix.rs` so MSI / MSI-X share the same MSI message
/// math; the only divergence is whether the message lives in
/// cfg-space (MSI) or a BAR-mapped table (MSI-X).
#[inline]
fn msi_message(target: u32, base_irq: u8) -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    {
        let addr = 0xFEE0_0000u64 | ((target as u64 & 0xFF) << 12);
        (addr, base_irq as u32)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = target;
        (
            narf_interrupts::aarch64::its::doorbell_pa(),
            base_irq as u32,
        )
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (target, base_irq); (0, 0) }
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
unsafe fn cfg_write16(cfg: PhysAddr, off: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 2-byte aligned.
    unsafe { core::ptr::write_volatile((cfg.raw() + off) as *mut u16, value); }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 4-byte aligned.
    unsafe { core::ptr::write_volatile((cfg.raw() + off) as *mut u32, value); }
    compiler_fence(Ordering::SeqCst);
}
