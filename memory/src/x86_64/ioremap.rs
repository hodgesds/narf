//! x86_64 ioremap — map device-MMIO phys ranges into a fresh
//! kernel virtual address that's not in the boot identity map.
//!
//! Use case: a PCIe BAR allocated above the boot identity map's
//! 4 GiB ceiling (or in some configurations, even within it but
//! outside its actual page coverage). Drivers call
//! `ioremap(phys, len, MmioAttrs::Device)`; the returned virtual
//! address can be dereferenced for MMIO reads/writes for the
//! lifetime of the mapping.
//!
//! The mapping uses `NO_CACHE | WRITABLE | PRESENT` flags. The
//! NO_CACHE bit (PTE bit 4) is the closest x86 PTE attribute
//! produces to "device-uncached" without using PAT — sufficient
//! for MMIO BARs which the device guarantees are coherent through
//! its own protocol.
//!
//! `iounmap` walks the same range and clears each PTE; the local
//! INVLPG + the existing shootdown-broadcast hook handle TLB
//! consistency.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::paging::{self, invlpg_global, map_4kb, read_cr3, unmap_4kb, MapError, PtFlags};
use crate::vmalloc::{self, VmRange, VmallocError};
use crate::{PhysAddr, VirtAddr};

/// Cache of (phys, len) → IoMapping. Repeated `ioremap` calls on
/// the same range return the same kernel VA — avoids leaking
/// vmalloc ranges + PTE frames when test smokes re-probe the
/// same hardware.
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
    /// Strongly-uncached. The default for PCIe BARs.
    Device,
    /// Cacheable + write-back. For prefetchable BARs (framebuffers,
    /// ROMs) where ordering doesn't matter and read-prefetching
    /// helps. Today's drivers all want Device.
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

/// Returned mapping handle. `virt` is dereferenceable for MMIO;
/// `phys` is the original phys; `len` is the page-rounded length.
/// Hold by-value through the lifetime of the mapping; pass to
/// `iounmap` to tear it down.
#[derive(Copy, Clone, Debug)]
pub struct IoMapping {
    pub phys: u64,
    pub virt: u64,
    pub len: u64,
}

/// Map a phys range into kernel virtual space. The phys + len
/// must be page-aligned + page-multiple; sub-page granularity is
/// not supported.
///
/// # Safety
/// - `phys` must be a real device MMIO address the caller has
///   exclusive access to (or the cap-system has authorised).
/// - `len` must cover the full device-window the caller wants
///   to dereference. Reads past `phys + len` may hit unmapped or
///   neighbour-device addresses.
/// - The active page table must be writable (i.e. we're at CPL=0
///   on the BSP boot path or holding the appropriate cap to
///   mutate kernel mappings).
pub unsafe fn ioremap(phys: u64, len: u64, _attrs: MmioAttrs) -> Result<IoMapping, IoremapError> {
    if phys & 0xFFF != 0 {
        return Err(IoremapError::BadAlign);
    }
    if len & 0xFFF != 0 || len == 0 {
        return Err(IoremapError::BadLen);
    }

    // Cache hit? Return the prior mapping. Avoids the per-test-
    // re-probe leak that otherwise eats vmalloc + PT frames.
    if let Some(m) = cache_lookup(phys, len) {
        return Ok(m);
    }

    let range = vmalloc::alloc(len)?;
    let pml4_phys = unsafe { read_cr3() };
    let flags = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_CACHE;

    // Map page by page. On failure, walk back and unmap the
    // pages we did install so the address space stays clean.
    let pages = (len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(range.base + off);
        let p = PhysAddr::new(phys + off);
        // SAFETY: range.base + off is freshly-allocated VA (no
        // existing mapping); phys + off is per the caller's
        // exclusivity contract.
        if let Err(e) = unsafe { map_4kb(pml4_phys, v, p, flags) } {
            // Roll back successful pages.
            for j in 0..i {
                let off_j = (j as u64) * 4096;
                let v_j = VirtAddr::new(range.base + off_j);
                // SAFETY: we just installed this PTE.
                let _ = unsafe { unmap_4kb(pml4_phys, v_j) };
            }
            vmalloc::free(range);
            return Err(IoremapError::Map(e));
        }
        // Local INVLPG — the new mapping doesn't need a TLB
        // shootdown broadcast on install (no peer CPU could
        // have a cached translation for an address that wasn't
        // mapped yet), so we use the cheaper local form.
        // SAFETY: INVLPG always legal at CPL=0.
        unsafe {
            paging::invlpg(v);
        }
    }

    let m = IoMapping {
        phys,
        virt: range.base,
        len,
    };
    cache_insert(m);
    Ok(m)
}

/// Tear down a mapping. Each unmapped page broadcasts a TLB
/// shootdown via the shared hook so peer CPUs invalidate any
/// cached translations.
///
/// # Safety
/// `m` must originate from `ioremap`; the caller must have
/// drained any in-flight MMIO accesses through the mapping
/// before calling iounmap.
pub unsafe fn iounmap(m: IoMapping) {
    // Pull from cache first so a future ioremap of the same range
    // gets a fresh mapping rather than the now-torn-down one.
    cache_remove(m.virt);
    // SAFETY: caller-provided mapping handle.
    let pml4_phys = unsafe { read_cr3() };
    let pages = (m.len >> 12) as usize;
    for i in 0..pages {
        let off = (i as u64) * 4096;
        let v = VirtAddr::new(m.virt + off);
        // SAFETY: paired with ioremap's map_4kb.
        let _ = unsafe { unmap_4kb(pml4_phys, v) };
        // SAFETY: invlpg_global broadcasts via the installed
        // shootdown hook.
        unsafe {
            invlpg_global(v);
        }
    }
    vmalloc::free(VmRange {
        base: m.virt,
        len: m.len,
    });
}
