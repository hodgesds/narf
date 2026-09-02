//! aarch64 ioremap — map device-MMIO phys ranges into kernel
//! virtual address space (TTBR1 territory).
//!
//! Pairs with `arch/x86_64/ioremap.rs` — same surface (`ioremap`,
//! `iounmap`, `MmioAttrs`), arch-specific in the page-walk and
//! TLB-invalidation primitives.
//!
//! Memory attribute: `ATTR_DEVICE` indexes MAIR_EL1[2] which the
//! boot stub configures as `Device-nGnRnE` (strongly-ordered,
//! non-gathered, non-reordered, non-early-write-acknowledge) —
//! the safest default for MMIO BARs that need predictable
//! ordering with respect to driver writes.
//!
//! TLB invalidation uses `tlbi vaae1is`, which broadcasts the VA invalidation
//! for every ASID across the inner-shareable domain. This covers shared TTBR1
//! mappings even while peers execute under distinct process ASIDs.

#![cfg(target_arch = "aarch64")]

extern crate alloc;

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::aarch64::paging::{
    self, map_4kb, read_ttbr1_el1, tlb_invalidate_va_all_asids_inner_shareable, MapError, PtFlags,
};
use crate::vmalloc::{self, VmRange, VmallocError};
use crate::{PhysAddr, VirtAddr};

/// Cache of (phys, len) → IoMapping. Same rationale as x86_64:
/// repeated probes / map_cap calls on the same BAR return the
/// cached VA so we don't leak vmalloc + PTE frames.
static CACHE: IrqSafeSpinLock<Vec<IoMapping>> = IrqSafeSpinLock::new(Vec::new());

fn cache_lookup(phys: u64, len: u64) -> Option<IoMapping> {
    CACHE
        .lock()
        .iter()
        .copied()
        .find(|m| m.phys == phys && m.len == len)
}

fn cache_insert(m: IoMapping) {
    CACHE.lock().push(m);
}

fn cache_remove(virt: u64) {
    CACHE.lock().retain(|m| m.virt != virt);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmioAttrs {
    Device,
    WriteBack,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoremapError {
    BadLen,
    BadAlign,
    Exhausted,
    Map(MapError),
}

impl From<VmallocError> for IoremapError {
    fn from(e: VmallocError) -> Self {
        match e {
            VmallocError::BadLen => IoremapError::BadLen,
            VmallocError::Exhausted => IoremapError::Exhausted,
        }
    }
}

impl From<MapError> for IoremapError {
    fn from(e: MapError) -> Self {
        IoremapError::Map(e)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct IoMapping {
    /// Page-aligned physical base actually mapped.
    pub phys: u64,
    /// Page-aligned virtual base of the mapping. Use [`IoMapping::va`] to
    /// reach the byte the caller asked for.
    pub virt: u64,
    /// Page-multiple length actually mapped.
    pub len: u64,
    /// Distance from `phys`/`virt` to the address the caller requested.
    /// Zero unless the request was not page-aligned.
    pub offset: u64,
}

impl IoMapping {
    /// Virtual address of the byte the caller asked `ioremap` for — this is
    /// what Linux's `ioremap()` hands back. `virt` is the page-aligned base
    /// that the mapping, and `iounmap`, are built on.
    #[inline]
    pub fn va(&self) -> u64 {
        self.virt + self.offset
    }
}

/// Map a phys range into kernel virtual space via TTBR1.
///
/// # Safety
/// Mirrors x86_64 ioremap's contract: phys must be a real device
/// MMIO address held exclusively by the caller; len must cover the
/// driver-relevant window; the active TTBR1 root must be writable.
pub unsafe fn ioremap(phys: u64, len: u64, attrs: MmioAttrs) -> Result<IoMapping, IoremapError> {
    if len == 0 {
        return Err(IoremapError::BadLen);
    }
    // Linux's `ioremap()` takes an unaligned address and size, maps whole
    // pages, and returns a pointer carrying the sub-page offset. Match that.
    // Rejecting sub-page requests only pushed the rounding into callers, and
    // four had grown their own copy of it — one of which (virtio-mmio, whose
    // register window is 0x200 bytes) just failed instead, unnoticed because
    // no test flavour populated a virtio-mmio slot to exercise its probe.
    let offset = phys & 0xFFF;
    let base = phys - offset;
    let map_len = len
        .checked_add(offset)
        .and_then(|v| v.checked_add(0xFFF))
        .ok_or(IoremapError::BadLen)?
        & !0xFFF;

    if let Some(m) = cache_lookup(base, map_len) {
        // The cached entry carries whichever offset first created it; this
        // caller wants its own.
        return Ok(IoMapping { offset, ..m });
    }

    let range = vmalloc::alloc(map_len)?;
    // SAFETY: `read_ttbr1_el1` only issues `MRS .., TTBR1_EL1`, which
    // is defined at EL1 with no precondition; we run at EL1 in the
    // kernel and use the returned root solely as the page-table base
    // for the mapping below.
    // SAFETY: Valid memory or trusted environment
    let root = unsafe { read_ttbr1_el1() };

    let attr_flag = match attrs {
        MmioAttrs::Device => PtFlags::ATTR_DEVICE,
        MmioAttrs::WriteBack => PtFlags::ATTR_NORMAL,
    };
    // map_4kb already ORs in VALID | TYPE_PAGE | AF | SH_INNER |
    // ATTR_NORMAL — passing ATTR_DEVICE here OR's into the same
    // bit field and the higher index wins for non-zero values.
    // We also UXN+PXN device memory to be safe (no-execute).
    let flags = attr_flag | PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;

    let pages = (map_len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(range.base + off);
        let p = PhysAddr::new(base + off);
        // SAFETY: vmalloc-fresh VA; phys+off per caller's
        // exclusivity contract; root is the active TTBR1.
        // SAFETY: Valid memory or trusted environment
        if let Err(e) = unsafe { map_4kb(root, v, p, flags) } {
            // Roll back.
            for j in 0..i {
                let off_j = (j as u64) * 4096;
                let v_j = VirtAddr::new(range.base + off_j);
                // SAFETY: tlbi is always legal at EL1.
                unsafe {
                    tlb_invalidate_va_all_asids_inner_shareable(v_j);
                }
                // No unmap_4kb on aarch64 yet — leave the L3
                // entry; the caller's vmalloc::free is enough
                // for now since the bump-pointer never reuses
                // freed VA.
            }
            vmalloc::free(range);
            return Err(IoremapError::Map(e));
        }
        // Local TLB invalidate so subsequent loads see the new
        // mapping. dsb-ish makes it broadcast on a multi-core
        // system — same as the x86_64 INVLPG broadcast.
        // SAFETY: tlbi at EL1 always legal.
        unsafe {
            tlb_invalidate_va_all_asids_inner_shareable(v);
        }
    }

    let m = IoMapping {
        phys: base,
        virt: range.base,
        len: map_len,
        offset,
    };
    cache_insert(m);
    Ok(m)
}

/// Tear down a mapping. Today: clears the TLB locally + calls
/// vmalloc::free; a real PTE-clearing path lands when
/// aarch64 paging gets an `unmap_4kb` to mirror x86_64's.
///
/// # Safety
/// `m` must originate from `ioremap`.
pub unsafe fn iounmap(m: IoMapping) {
    cache_remove(m.virt);
    let pages = (m.len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(m.virt + off);
        // SAFETY: TLB invalidation is always safe.
        unsafe {
            tlb_invalidate_va_all_asids_inner_shareable(v);
        }
    }
    let _ = paging::translate; // silence unused
    vmalloc::free(VmRange {
        base: m.virt,
        len: m.len,
    });
}
