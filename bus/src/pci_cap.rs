//! Generic PCI / PCIe capability-list walker.
//!
//! The PCI base spec § 6.7 defines a singly-linked list of "extended
//! features" rooted at config offset 0x34 (Capabilities Pointer) when
//! `Status[CAP_LIST]` (bit 4) is set. Each cap header is a u16 layout
//! `(id: u8, next: u8)` at the cap's offset, followed by cap-specific
//! data.
//!
//! PCIe spec § 7.7 adds a *second* list — the **extended** capability
//! list — rooted at offset 0x100, with 16-bit IDs. That walker lives
//! in `pci_cap_ext` so the standard cap-list walker stays simple and
//! both can be tested independently.
//!
//! Standard capability IDs we care about (full list in PCIe § 7):
//!
//! | id    | name                      |
//! |-------|---------------------------|
//! | 0x01  | Power Management          |
//! | 0x05  | Message-Signalled IRQs    |
//! | 0x09  | Vendor-Specific           |
//! | 0x10  | PCI Express               |
//! | 0x11  | MSI-X                     |
//! | 0x13  | Conventional PCI Hot-Plug |

use core::sync::atomic::{compiler_fence, Ordering};

use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};

/// Standard cap IDs. Drivers can extend with their own constants;
/// re-exported by `bus::pci_cap` for ergonomic match patterns.
pub mod id {
    pub const POWER_MGMT:    u8 = 0x01;
    pub const MSI:           u8 = 0x05;
    pub const VENDOR_SPEC:   u8 = 0x09;
    pub const PCI_EXPRESS:   u8 = 0x10;
    pub const MSI_X:         u8 = 0x11;
}

/// Cfg-space offset of the Status register (16-bit).
const STATUS_OFFSET: u64 = 0x06;
/// Status bit 4: capabilities list present.
const STATUS_CAP_LIST_BIT: u16 = 1 << 4;
/// Cfg-space offset of the Capabilities Pointer (8-bit, type-0/type-1).
const CAP_POINTER_OFFSET: u64 = 0x34;
/// Maximum hops in the cap list. Bounded so a malformed device
/// doesn't loop the kernel — 48 caps is far more than any real
/// device.
const MAX_HOPS: u32 = 48;

/// Errors specific to the cap-list walker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapError {
    /// Caller passed a non-PCIe `BusDevice`.
    NotPcie,
    /// Status register's CAP_LIST bit is clear — device has no list.
    NoCapList,
}

/// Find the first capability with the given ID. Returns the cfg-space
/// offset of the cap header, or `None` if the cap isn't present.
///
/// # Safety
/// `device` must be PCIe and live (registry-discovered). The walker
/// only does aligned cfg-space reads.
pub unsafe fn find_cap(device: &BusDevice, id: u8) -> Result<Option<u64>, CapError> {
    // SAFETY: caller-asserted; iter checks PCIe + status.
    for cap in unsafe { iter(device)? } {
        if cap.id == id { return Ok(Some(cap.offset)); }
    }
    Ok(None)
}

/// One discovered cap header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapHeader {
    /// Cap ID — see `id::*` for known values.
    pub id:     u8,
    /// Cfg-space offset of the cap header itself. Cap-specific data
    /// follows at `offset + 2`.
    pub offset: u64,
}

/// Walk the cap list and return every header. Cheaper than calling
/// `find_cap` repeatedly when a driver wants to discover several caps
/// at once.
///
/// # Safety
/// Same as `find_cap`.
pub unsafe fn iter(device: &BusDevice) -> Result<CapIter, CapError> {
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. }     => return Err(CapError::NotPcie),
    };
    // SAFETY: cfg-space is identity-mapped MMIO; offset 0x06 is in
    // every type-0 / type-1 header.
    let status = unsafe { cfg_read16(cfg, STATUS_OFFSET) };
    if (status & STATUS_CAP_LIST_BIT) == 0 {
        return Err(CapError::NoCapList);
    }
    // SAFETY: same window; offset 0x34 is the Capabilities Pointer.
    let head = unsafe { cfg_read8(cfg, CAP_POINTER_OFFSET) };
    Ok(CapIter { cfg, next: (head as u64) & 0xFC, hops: 0 })
}

/// Iterator over cap-list entries — produced by `iter`.
#[derive(Debug)]
pub struct CapIter {
    cfg:  PhysAddr,
    next: u64,
    hops: u32,
}

impl Iterator for CapIter {
    type Item = CapHeader;
    fn next(&mut self) -> Option<CapHeader> {
        if self.next == 0 || self.hops >= MAX_HOPS { return None; }
        // SAFETY: cfg-space is identity-mapped; `next` is < 0x100 by
        // mask + bound.
        let id   = unsafe { cfg_read8(self.cfg, self.next)     };
        let nxt  = unsafe { cfg_read8(self.cfg, self.next + 1) };
        let here = self.next;
        self.next = (nxt as u64) & 0xFC;
        self.hops += 1;
        Some(CapHeader { id, offset: here })
    }
}

// ── helpers — duplicated from msix.rs for module isolation ──────────

#[inline]
unsafe fn cfg_read8(cfg: PhysAddr, off: u64) -> u8 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the byte is readable.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u8) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_read16(cfg: PhysAddr, off: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the word is readable + 2-byte aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u16) };
    compiler_fence(Ordering::SeqCst);
    v
}
