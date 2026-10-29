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

use narf_lib::sync::IrqSafeSpinLock;

use crate::paging::{
    self, invlpg_global, map_2mb, map_4kb, read_cr3, unmap_2mb, unmap_4kb, MapError, PtFlags,
};
use crate::vmalloc::{self, VmRange, VmallocError};
use crate::{PhysAddr, VirtAddr};

/// Typed claims include pending installs and teardowns. No cache lock is
/// held across page-table allocation, mapping, rollback or TLB shootdown.
static CACHE: IrqSafeSpinLock<crate::ioremap_cache::Cache<MmioAttrs, IoMapping>> =
    IrqSafeSpinLock::new(crate::ioremap_cache::Cache::new());

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmioAttrs {
    /// Strongly-uncached. The default for PCIe BARs.
    Device,
    /// Cacheable + write-back. For prefetchable BARs (framebuffers,
    /// ROMs) where ordering doesn't matter and read-prefetching
    /// helps. Today's drivers all want Device.
    WriteBack,
    /// Write-combining for device framebuffer and command windows.
    /// Known System RAM retains write-back leaves to match its direct map.
    /// Requires PAT support + `narf_arch::x86_64::pat::bp_init` /
    /// `cpu_init` to have set PA1 = WC on every CPU. PWT (bit 3) in the
    /// PTE selects PA1.
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

/// Returned mapping handle. `virt` is dereferenceable for MMIO;
/// `phys` is the original phys; `len` is the page-rounded length.
/// Hold by-value through the lifetime of the mapping; pass to
/// `iounmap` to tear it down.
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

/// Map a phys range into kernel virtual space.
///
/// `phys` and `len` may be unaligned: whole pages are mapped and
/// [`IoMapping::va`] gives back the requested byte, carrying the sub-page
/// offset, exactly as Linux's `ioremap()` does. `virt`/`len` describe the
/// page-aligned mapping that `iounmap` tears down.
///
/// # Safety
/// - `phys` must be a real device MMIO address or owned firmware/RAM
///   window the caller has exclusive access to (or cap authorization).
///   Known System RAM always retains its write-back memory type.
/// - `len` must cover the full device-window the caller wants
///   to dereference. Reads past `phys + len` may hit unmapped or
///   neighbour-device addresses.
/// - The active page table must be writable (i.e. we're at CPL=0
///   on the BSP boot path or holding the appropriate cap to
///   mutate kernel mappings).
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

    // Cache hit? Return the prior mapping. Avoids the per-test-
    // re-probe leak that otherwise eats vmalloc + PT frames.
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

    const HUGE: u64 = 2 * 1024 * 1024;
    let range = if map_len >= HUGE {
        vmalloc::alloc_aligned(map_len, HUGE)?
    } else {
        vmalloc::alloc(map_len)?
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let pml4_phys = unsafe { read_cr3() };
    // Per-attr PTE flags:
    //   Device          → NO_CACHE (PCD=1)              → PA2 = UC-
    //   WriteBack       → no extra bits                 → PA0 = WB
    //   WriteCombining  → PAT cache-mode table (normally PWT / PA1 = WC).
    // The table also supplies the conservative fallback when PAT is disabled;
    // an unexpected programming/readback failure stops CPU bring-up.
    let flags = match attrs {
        MmioAttrs::Device => PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_CACHE,
        MmioAttrs::WriteBack => PtFlags::PRESENT | PtFlags::WRITABLE,
        MmioAttrs::WriteCombining => {
            PtFlags::PRESENT
                | PtFlags::WRITABLE
                | PtFlags::from_bits(narf_arch::x86_64::pat::cachemode2pte(
                    narf_arch::x86_64::pat::CacheMode::Wc,
                ))
        }
    };

    // Map page by page. On failure, walk back and unmap the
    // pages we did install so the address space stays clean.
    let mut off = 0;
    while off < map_len {
        let v = VirtAddr::new(range.base + off);
        let p = PhysAddr::new(base + off);
        let huge = should_map_huge(v.raw(), p.raw(), map_len - off);
        let flags = if attrs != MmioAttrs::WriteBack && crate::frame::is_system_ram(p) {
            PtFlags::PRESENT | PtFlags::WRITABLE
        } else {
            flags
        };
        // SAFETY: range.base + off is freshly-allocated VA (no
        // existing mapping); phys + off is per the caller's
        // exclusivity contract.
        // SAFETY: Valid memory or trusted environment
        let result = if huge {
            // Large leaves use PAT bit 12 rather than bit 7, which is PS.
            // SAFETY: this is a fresh, aligned VA and caller-owned MMIO range.
            unsafe { map_2mb(pml4_phys, v, p, flags.protval_4k_2_large()) }
        } else {
            // SAFETY: this is a fresh VA and caller-owned MMIO page.
            unsafe { map_4kb(pml4_phys, v, p, flags) }
        };
        if let Err(e) = result {
            // Roll back successful pages.
            let mut off_j = 0;
            while off_j < off {
                let v_j = VirtAddr::new(range.base + off_j);
                let large_j = mapped_leaf_is_huge(pml4_phys, v_j);
                let unmapped = if large_j {
                    // SAFETY: this 2 MiB leaf was installed above.
                    unsafe { unmap_2mb(pml4_phys, v_j) }
                } else {
                    // SAFETY: this 4 KiB leaf was installed above.
                    unsafe { unmap_4kb(pml4_phys, v_j) }
                };
                if unmapped.is_err() {
                    // Keep the interval reserved if rollback cannot prove
                    // every old leaf gone; never admit a conflicting alias.
                    core::mem::forget(reservation);
                    return Err(IoremapError::Map(e));
                }
                off_j += if large_j { HUGE } else { 4096 };
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
        off += if huge { HUGE } else { 4096 };
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

/// Tear down a mapping. Each unmapped page broadcasts a TLB
/// shootdown via the shared hook so peer CPUs invalidate any
/// cached translations.
///
/// # Safety
/// `m` must originate from `ioremap`; the caller must have
/// stopped every user of reused handles and drained all in-flight MMIO
/// accesses. Teardown is exclusive and may run once per installed mapping.
pub unsafe fn iounmap(m: IoMapping) {
    // Mark the entry pending before teardown. Its physical type remains
    // reserved until all leaves and cached translations have gone.
    let reservation = crate::ioremap_cache::retire(&CACHE, |ready| ready.virt == m.virt);
    // SAFETY: caller-provided mapping handle.
    let pml4_phys = unsafe { read_cr3() };
    let mut off = 0;
    while off < m.len {
        let v = VirtAddr::new(m.virt + off);
        let huge = mapped_leaf_is_huge(pml4_phys, v);
        let unmapped = if huge {
            // SAFETY: paired with ioremap's map_2mb.
            unsafe { unmap_2mb(pml4_phys, v) }
        } else {
            // SAFETY: paired with ioremap's map_4kb.
            unsafe { unmap_4kb(pml4_phys, v) }
        };
        if unmapped.is_err() {
            // A retained pending claim quarantines any uncertain leaf.
            core::mem::forget(reservation);
            return;
        }
        // SAFETY: invlpg_global broadcasts via the installed
        // shootdown hook.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            invlpg_global(v);
        }
        off += if huge { 2 * 1024 * 1024 } else { 4096 };
    }
    vmalloc::free(VmRange {
        base: m.virt,
        len: m.len,
    });
    drop(reservation);
}

const fn can_map_huge(virt: u64, phys: u64, remaining: u64) -> bool {
    const HUGE: u64 = 2 * 1024 * 1024;
    virt & (HUGE - 1) == 0 && phys & (HUGE - 1) == 0 && remaining >= HUGE
}

fn should_map_huge(virt: u64, phys: u64, remaining: u64) -> bool {
    can_map_huge(virt, phys, remaining)
        && !crate::frame::system_ram_intersects(phys, 2 * 1024 * 1024)
}

fn mapped_leaf_is_huge(root: PhysAddr, virt: VirtAddr) -> bool {
    // SAFETY: the address belongs to an ioremap leaf installed in this root.
    unsafe { paging::leaf_flags_at(root, virt).is_some_and(|(_, size)| size == 2 * 1024 * 1024) }
}
