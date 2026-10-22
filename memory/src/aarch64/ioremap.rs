//! aarch64 ioremap — map device-MMIO phys ranges into kernel
//! virtual address space (TTBR1 territory).
//!
//! Pairs with `arch/x86_64/ioremap.rs` — same surface (`ioremap`,
//! `iounmap`, `MmioAttrs`), arch-specific in the page-walk and
//! TLB-invalidation primitives.
//!
//! Register mappings use Device-nGnRE (MAIR index 1). Prefetchable
//! framebuffer windows use Normal-NC (index 3), matching Linux's
//! `ioremap_wc` and the user leaves returned by `pgprot_writecombine`.
//!
//! TLB invalidation uses `tlbi vaae1is`, which broadcasts the VA invalidation
//! for every ASID across the inner-shareable domain. This covers shared TTBR1
//! mappings even while peers execute under distinct process ASIDs.

#![cfg(target_arch = "aarch64")]

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

use crate::aarch64::paging::{
    self, map_4kb, read_ttbr1_el1, tlb_invalidate_va_all_asids_inner_shareable, unmap_4kb,
    MapError, PtFlags,
};
use crate::vmalloc::{self, VmRange, VmallocError};
use crate::{PhysAddr, VirtAddr};

/// Typed claims include pending installs and teardowns. No cache lock is
/// held across page-table allocation, mapping, rollback or TLB shootdown.
static CACHE: IrqSafeSpinLock<crate::ioremap_cache::Cache<MmioAttrs, IoMapping>> =
    IrqSafeSpinLock::new(crate::ioremap_cache::Cache::new());

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmioAttrs {
    Device,
    WriteBack,
    /// Normal, inner/outer non-cacheable: Linux `ioremap_wc`.
    WriteCombining,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoremapError {
    BadLen,
    BadAlign,
    /// An overlapping mapping requests different memory attributes.
    AttributeConflict,
    /// An identical mapping is currently installing or tearing down.
    Busy,
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
/// MMIO address or owned firmware/RAM window held exclusively by the caller;
/// len must cover the driver-relevant window; the active TTBR1 root must be
/// writable. Known System RAM retains write-back leaves like its direct map.
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

    let reservation =
        match crate::ioremap_cache::claim(&CACHE, base, map_len, attrs).map_err(|e| match e {
            crate::ioremap_cache::Error::BadRange => IoremapError::BadLen,
            crate::ioremap_cache::Error::Conflict => IoremapError::AttributeConflict,
            crate::ioremap_cache::Error::Busy => IoremapError::Busy,
            crate::ioremap_cache::Error::Exhausted => IoremapError::Exhausted,
        })? {
            crate::ioremap_cache::Claim::Ready(m) => return Ok(IoMapping { offset, ..m }),
            crate::ioremap_cache::Claim::Pending(reservation) => reservation,
        };

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
        MmioAttrs::WriteCombining => PtFlags::ATTR_NORMAL_NC,
    };
    // ATTR_NORMAL is zero. Nonzero AttrIndx values select the requested
    // device/Normal-NC type. All kernel I/O windows are execute-never.
    let flags = attr_flag | PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;

    let pages = (map_len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(range.base + off);
        let p = PhysAddr::new(base + off);
        let flags = if attrs != MmioAttrs::WriteBack && crate::frame::is_system_ram(p) {
            PtFlags::ATTR_NORMAL | PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN
        } else {
            flags
        };
        // SAFETY: vmalloc-fresh VA; phys+off per caller's
        // exclusivity contract; root is the active TTBR1.
        // SAFETY: Valid memory or trusted environment
        if let Err(e) = unsafe { map_4kb(root, v, p, flags) } {
            // Roll back.
            for j in 0..i {
                let off_j = (j as u64) * 4096;
                let v_j = VirtAddr::new(range.base + off_j);
                // SAFETY: this exact leaf was installed above; unmap
                // clears it and broadcasts the required TLB invalidation.
                if unsafe { unmap_4kb(root, v_j) }.is_err() {
                    // Keep the interval reserved if rollback cannot prove
                    // every old leaf gone; never admit a conflicting alias.
                    core::mem::forget(reservation);
                    return Err(IoremapError::Map(e));
                }
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
    reservation.publish(m);
    Ok(m)
}

/// Tear down a mapping, keeping its typed claim until every PTE is
/// cleared and its TLB invalidation completes.
///
/// # Safety
/// `m` must originate from `ioremap`; all users of reused handles must have
/// stopped accessing it before teardown. Teardown is exclusive and may run
/// once per installed mapping.
pub unsafe fn iounmap(m: IoMapping) {
    let reservation = crate::ioremap_cache::retire(&CACHE, |ready| ready.virt == m.virt);
    // SAFETY: the active kernel TTBR1 owns this mapping.
    let root = unsafe { read_ttbr1_el1() };
    let pages = (m.len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(m.virt + off);
        // SAFETY: this exact leaf belongs to the caller's mapping;
        // unmap broadcasts the required invalidation before returning.
        if unsafe { unmap_4kb(root, v) }.is_err() {
            // A retained pending claim quarantines any uncertain leaf.
            core::mem::forget(reservation);
            return;
        }
    }
    let _ = paging::translate; // silence unused
    vmalloc::free(VmRange {
        base: m.virt,
        len: m.len,
    });
    drop(reservation);
}
