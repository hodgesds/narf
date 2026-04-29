//! BAR decode + size detection + MMIO mapping.
//!
//! Spec: `bus/specification/spec.md` §5 — Stage-3 lands the read-side of
//! BAR sizing so a driver can ask "where in physical memory does BAR N
//! live and how big is it" without owning a config-space accessor of
//! its own. The MSI-X table programmer (msix.rs) uses this to find the
//! BAR named by `MsixTable::bir()`.
//!
//! Today the kernel's identity map covers the q35 ECAM + low 4 GiB,
//! so the "map" step is a value-by-value (PhysAddr, len) pair that the
//! caller dereferences as MMIO. Once the kernel grows a separate ioremap
//! for above-4-GiB BARs, `map_bar` becomes the place that allocates a
//! VMA and updates the page tables; callers don't need to change.
//!
//! BAR sizing is the standard PCI ritual:
//!   1. Read original BAR value (preserve type/prefetch bits).
//!   2. Write 0xFFFF_FFFF.
//!   3. Read back. Mask off the type/prefetch bits.
//!   4. Invert + add 1 → size.
//!   5. Restore original value.
//!
//! Naked u32 BARs span 4 GiB. 64-bit MMIO BARs use two adjacent BAR
//! slots (low + high u32); we sniff bit 2 of the type field to detect
//! that case and read the upper word too.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};

/// Type-decode of a single BAR slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BarKind {
    /// 32-bit MMIO BAR. `phys` < 4 GiB by construction.
    Mmio32 { prefetchable: bool },
    /// 64-bit MMIO BAR. `phys` may be above 4 GiB. Consumes two
    /// adjacent BAR slots in the type-0 header.
    Mmio64 { prefetchable: bool },
    /// I/O-port BAR. x86_64 only; aarch64 has no I/O-port space, so
    /// drivers must ignore these (or platform code must trap them).
    Io,
}

/// One decoded BAR.
#[derive(Copy, Clone, Debug)]
pub struct Bar {
    /// Slot index in the type-0 header (0..6). For a 64-bit BAR this
    /// names the *low* slot — the high slot is `idx + 1`.
    pub idx:   u8,
    pub kind:  BarKind,
    /// Physical base. Zero means the BAR is unprogrammed (e.g. firmware
    /// hasn't assigned a window) — drivers should treat that as "absent."
    pub phys:  PhysAddr,
    /// Size in bytes, derived from the size-detection write-read-restore
    /// cycle. Zero means the BAR is unimplemented (write of 0xFFFF_FFFF
    /// reads back as zero).
    pub size:  u64,
}

/// BAR-decode error surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BarError {
    /// Caller asked for a BAR index >= 6, or for the high half of a
    /// 64-bit BAR (slot 1 / 3 / 5 of a pair).
    OutOfRange,
    /// Caller asked for a BAR on a non-PCIe device (virtio-mmio
    /// transports use their own fixed register layout, not BARs).
    NotPcie,
    /// BAR is unimplemented or unprogrammed (size == 0).
    Unimplemented,
}

/// Type-0 PCIe configuration-space layout, BAR window.
const BAR0_OFFSET: u64 = 0x10;
/// Six BAR slots (0x10..0x28).
pub const NUM_BARS: u8 = 6;

/// Bit 0 of a BAR: 0 = MMIO, 1 = I/O.
const BAR_TYPE_IO: u32 = 1 << 0;
/// Bits 1..2 of an MMIO BAR: 00 = 32-bit, 10 = 64-bit.
const BAR_MMIO_64BIT: u32 = 0b10 << 1;
/// Bit 3: prefetchable.
const BAR_MMIO_PREFETCH: u32 = 1 << 3;

/// MMIO BAR address mask (clears the low 4 type/prefetch bits).
const BAR_MMIO_ADDR_MASK_32: u32 = 0xFFFF_FFF0;
/// I/O BAR address mask (clears the low 2 reserved bits).
const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC;

/// Read BAR `idx` of `device` and return the decoded slot.
///
/// # Safety
/// `device.kind` must be PCIe and the function must own its cfg window
/// exclusively for the duration of this call (size detection writes to
/// the BAR briefly and restores it). Concurrent BAR access is UB.
pub unsafe fn read_bar(device: &BusDevice, idx: u8) -> Result<Bar, BarError> {
    if idx >= NUM_BARS { return Err(BarError::OutOfRange); }
    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. }     => return Err(BarError::NotPcie),
    };

    let off = BAR0_OFFSET + (idx as u64) * 4;
    // SAFETY: cfg_phys + off lives inside the function's 4-KiB cfg
    // window (off < 0x28 < 0x100); identity-mapped.
    let original = unsafe { cfg_read32(cfg_phys, off) };

    // I/O-port BAR? Bit 0 set.
    if original & BAR_TYPE_IO != 0 {
        // Size: write all-1s, read back, mask, invert, +1.
        // SAFETY: same window; we restore below.
        let size_low = unsafe {
            cfg_write32(cfg_phys, off, 0xFFFF_FFFF);
            let v = cfg_read32(cfg_phys, off);
            cfg_write32(cfg_phys, off, original);
            v
        };
        let masked = size_low & BAR_IO_ADDR_MASK;
        let size = if masked == 0 { 0 } else { ((!masked) as u64).wrapping_add(1) & 0xFFFF };
        if size == 0 { return Err(BarError::Unimplemented); }
        return Ok(Bar {
            idx,
            kind: BarKind::Io,
            phys: PhysAddr::new((original & BAR_IO_ADDR_MASK) as u64),
            size,
        });
    }

    // MMIO BAR. Bits 1..2 = 10 ⇒ 64-bit (consumes the next slot too).
    let is_64 = (original & 0b110) == BAR_MMIO_64BIT;
    let prefetchable = (original & BAR_MMIO_PREFETCH) != 0;

    // Size detection on the low slot.
    // SAFETY: cfg-space writes restored below; same window.
    let size_low = unsafe {
        cfg_write32(cfg_phys, off, 0xFFFF_FFFF);
        let v = cfg_read32(cfg_phys, off);
        cfg_write32(cfg_phys, off, original);
        v
    };

    if is_64 {
        if idx + 1 >= NUM_BARS { return Err(BarError::OutOfRange); }
        let off_hi = off + 4;
        // SAFETY: high slot is in the same 4-KiB cfg window.
        let original_hi = unsafe { cfg_read32(cfg_phys, off_hi) };
        // SAFETY: cfg-space writes restored below; same window.
        let size_hi = unsafe {
            cfg_write32(cfg_phys, off_hi, 0xFFFF_FFFF);
            let v = cfg_read32(cfg_phys, off_hi);
            cfg_write32(cfg_phys, off_hi, original_hi);
            v
        };
        let phys = ((original_hi as u64) << 32)
            | ((original & BAR_MMIO_ADDR_MASK_32) as u64);
        let size_combined = ((size_hi as u64) << 32)
            | ((size_low & BAR_MMIO_ADDR_MASK_32) as u64);
        if size_combined == 0 { return Err(BarError::Unimplemented); }
        let size = (!size_combined).wrapping_add(1);
        return Ok(Bar {
            idx,
            kind: BarKind::Mmio64 { prefetchable },
            phys: PhysAddr::new(phys),
            size,
        });
    }

    // 32-bit MMIO.
    let masked = size_low & BAR_MMIO_ADDR_MASK_32;
    if masked == 0 { return Err(BarError::Unimplemented); }
    let size = ((!masked) as u64).wrapping_add(1) & 0xFFFF_FFFF;
    Ok(Bar {
        idx,
        kind: BarKind::Mmio32 { prefetchable },
        phys: PhysAddr::new((original & BAR_MMIO_ADDR_MASK_32) as u64),
        size,
    })
}

/// Map a device's BAR for MMIO access.
///
/// Stage-3 implementation: the kernel's identity map covers the low
/// 4 GiB and the q35 ECAM, so for every BAR a Stage-3 driver can
/// possibly hold, the returned `(phys, size)` pair is directly
/// dereferenceable. When kernel-side ioremap arrives this function
/// becomes the place that allocates a VMA + updates page tables — the
/// returned shape stays the same.
///
/// # Safety
/// See `read_bar`: `device` must be PCIe and the caller must hold
/// exclusive access to the function's cfg window.
pub unsafe fn map_bar(device: &BusDevice, idx: u8) -> Result<MmioRegion, BarError> {
    // SAFETY: forwarded.
    let bar = unsafe { read_bar(device, idx)? };
    if matches!(bar.kind, BarKind::Io) {
        // I/O-port BARs aren't MMIO; callers wanting them go through
        // `read_bar` and use `outb/inb` directly.
        return Err(BarError::NotPcie);
    }
    Ok(MmioRegion { phys: bar.phys, len: bar.size, kind: bar.kind })
}

/// A mapped MMIO region. Stage-3 representation: the physical base is
/// directly dereferenceable through the kernel's identity map, so MMIO
/// reads/writes go through this handle's `read32` / `write32` helpers
/// which do the volatile + barrier dance.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub phys: PhysAddr,
    pub len:  u64,
    pub kind: BarKind,
}

impl MmioRegion {
    /// Read a naturally-aligned 16-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 2 <= self.len`, `offset` 2-byte aligned, and the
    /// device behind the BAR must tolerate the read at this offset.
    #[inline]
    pub unsafe fn read16(&self, offset: u64) -> u16 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller-asserted in-range, naturally-aligned.
        let v = unsafe {
            core::ptr::read_volatile((self.phys.raw() + offset) as *const u16)
        };
        compiler_fence(Ordering::SeqCst);
        v
    }

    /// Write a naturally-aligned 16-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 2 <= self.len`, `offset` 2-byte aligned; caller owns
    /// the device exclusively.
    #[inline]
    pub unsafe fn write16(&self, offset: u64, value: u16) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller-asserted in-range, naturally-aligned.
        unsafe {
            core::ptr::write_volatile((self.phys.raw() + offset) as *mut u16, value);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Read a naturally-aligned 32-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 4 <= self.len` and the device behind the BAR must
    /// tolerate a register read at this offset (no read-side effect
    /// the caller doesn't want).
    #[inline]
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller-asserted in-range, naturally-aligned.
        let v = unsafe {
            core::ptr::read_volatile((self.phys.raw() + offset) as *const u32)
        };
        compiler_fence(Ordering::SeqCst);
        v
    }

    /// Write a naturally-aligned 32-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 4 <= self.len`; caller owns the device exclusively.
    #[inline]
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller-asserted in-range, naturally-aligned.
        unsafe {
            core::ptr::write_volatile((self.phys.raw() + offset) as *mut u32, value);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable.
    unsafe { core::ptr::write_volatile((cfg.raw() + off) as *mut u32, value); }
    compiler_fence(Ordering::SeqCst);
}
