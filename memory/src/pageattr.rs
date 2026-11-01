//! Kernel page attributes of System RAM: write-combining pages that a device
//! reads without snooping and a user maps write-combining.
//!
//! Spec: `memory/specification/spec.md` §3 ("Kernel page attributes") and §4
//! ("User memory types never alias System RAM").
//!
//! Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: `arch/x86/mm/pat/set_memory.c`
//! (`_set_pages_array`, `cpa_flush`, `__split_large_page`),
//! `arch/x86/mm/pat/memtype.c` (`reserve_ram_pages_type`,
//! `free_ram_pages_type`, `lookup_memtype`) and
//! `drivers/gpu/drm/ttm/ttm_pool.c` (`ttm_pool_apply_caching`,
//! `ttm_pool_free_page`).
//!
//! The kernel maps every RAM page write-back in the direct map (and, for the
//! kernel image, in the higher-half window). A user write-combining alias of
//! such a page would be an architectural mixed-attribute alias, so
//! [`crate::memtype`] refuses it. A display engine or GPU that fetches
//! without snooping needs exactly that alias, though: the CPU must write
//! around its caches. Linux's answer, which TTM applies to every
//! `ttm_write_combined` page, is to retype the *kernel's* aliases first
//! (`set_pages_array_wc`) and record the page's memtype, after which a user
//! PFN insert takes the recorded type (`lookup_memtype`). This module is that
//! answer:
//!
//! * [`set_pages_wc`] reserves each page's type ([`ram_memory_type`] answers
//!   `WriteCombining` from then on), rewrites every kernel alias to UC-,
//!   flushes all CPUs' TLBs and the pages' cache lines, then rewrites them
//!   to WC and flushes again — Linux's "If WC, set to UC- first and then WC".
//!   A huge alias leaf is split first (identical translation, all-CPU
//!   flush, then the attribute change) by `text_poke`'s `__split_large_page`.
//! * [`set_pages_wb`] restores write-back before a page may be freed (TTM
//!   frees `set_pages_wb` pages only).
//! * [`WcPages`] owns zeroed pages for that lifetime: it allocates, zeroes,
//!   retypes, and on drop restores write-back before freeing. A page whose
//!   restore fails is leaked, never returned to the allocator retyped.
//!
//! Only x86_64 retypes. aarch64 Linux never changes the linear map's
//! attributes for a write-combining buffer; NARF's aarch64 kernel window is
//! built with 2 MiB blocks that cannot be split without break-before-make on
//! live memory (see `text_poke`), so every operation there is
//! [`PageAttrError::Unsupported`].
//!
//! [`CPA_LOCK`] serialises every rewrite of the shared kernel windows, here
//! and in `text_poke` (Linux `cpa_lock`). It is an `IrqSafeSpinLock` held
//! across all-CPU flushes; a peer spinning on it with interrupts masked
//! drains pending shootdowns (`narf_lib::sync`), so the flush cannot strand.
//! Lock order: callers' locks (`bpf_text::PACKS`) → `CPA_LOCK` → frame
//! allocator → `RAM_TYPES`. A user leaf build may take `RAM_TYPES` under a
//! page-table root lock; nothing here takes a root lock.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::frame::PhysFrame;
use crate::memtype::MemoryType;
use crate::PhysAddr;

/// Why a retype was refused. Every refusal leaves every page unchanged.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageAttrError {
    /// A page is not System RAM. Device memory is typed by its mapping.
    NotRam,
    /// A page already has a recorded type (Linux `reserve_ram_pages_type`
    /// -EBUSY), appears twice in one request, or — when restoring — was never
    /// retyped.
    Busy,
    /// Not available here: aarch64, no live direct map, or no recorded kernel
    /// root yet.
    Unsupported,
    /// A page-table split could not allocate a table, or no page was left to
    /// allocate.
    NoFrame,
}

/// Serialises rewrites of the kernel's shared RAM windows (Linux `cpa_lock`).
pub(crate) static CPA_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Page frame number → recorded type of every retyped RAM page (Linux
/// `set_page_memtype`). Absent means write-back.
static RAM_TYPES: IrqSafeSpinLock<BTreeMap<u64, MemoryType>> =
    IrqSafeSpinLock::new(BTreeMap::new());
/// Entries in [`RAM_TYPES`]; zero keeps [`ram_memory_type`] lock-free on
/// machines with no retyped page.
static RETYPED: AtomicUsize = AtomicUsize::new(0);
/// Pages [`WcPages`] could not restore and therefore never freed.
static LEAKED: AtomicU64 = AtomicU64::new(0);

/// Pages per `CPA_LOCK` hold. Each chunk costs two all-CPU TLB flushes and
/// `CHUNK * 4 KiB` of cache-line flushes with interrupts masked.
#[cfg(target_arch = "x86_64")]
const CHUNK: usize = 256;

/// The recorded type of RAM page `phys`, if [`set_pages_wc`] retyped it
/// (Linux `lookup_memtype` for a RAM pfn). Every kernel alias of such a page
/// has this type, so a user leaf must use it too.
pub fn ram_memory_type(phys: PhysAddr) -> Option<MemoryType> {
    if RETYPED.load(Ordering::Acquire) == 0 {
        return None;
    }
    RAM_TYPES.lock().get(&(phys.raw() >> 12)).copied()
}

/// Pages currently retyped.
pub fn retyped_pages() -> usize {
    RETYPED.load(Ordering::Acquire)
}

/// Pages a [`WcPages`] drop could not restore to write-back and leaked.
pub fn leaked_pages() -> u64 {
    LEAKED.load(Ordering::Relaxed)
}

/// Whether this kernel can retype RAM now.
pub fn supported() -> bool {
    kernel_root().is_ok()
}

#[cfg(target_arch = "x86_64")]
fn kernel_root() -> Result<PhysAddr, PageAttrError> {
    if !crate::addr::direct_map_live() {
        return Err(PageAttrError::Unsupported);
    }
    crate::bpf_text::kernel_root_for_mapping().ok_or(PageAttrError::Unsupported)
}

#[cfg(not(target_arch = "x86_64"))]
fn kernel_root() -> Result<PhysAddr, PageAttrError> {
    Err(PageAttrError::Unsupported)
}

/// Page frame numbers of `pages`, or `Busy` if one repeats.
fn distinct_pfns(pages: &[PhysFrame]) -> Result<Vec<u64>, PageAttrError> {
    let mut pfns: Vec<u64> = pages
        .iter()
        .map(|page| page.start_address().raw() >> 12)
        .collect();
    pfns.sort_unstable();
    if pfns.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PageAttrError::Busy);
    }
    Ok(pfns)
}

/// Record `memory_type` for every page, all or nothing.
fn reserve(pages: &[PhysFrame], memory_type: MemoryType) -> Result<(), PageAttrError> {
    // The RAM registry takes its own locks; consult it before RAM_TYPES.
    if pages
        .iter()
        .any(|page| !crate::frame::is_system_ram(page.start_address()))
    {
        return Err(PageAttrError::NotRam);
    }
    let pfns = distinct_pfns(pages)?;
    let mut types = RAM_TYPES.lock();
    if pfns.iter().any(|pfn| types.contains_key(pfn)) {
        return Err(PageAttrError::Busy);
    }
    for pfn in pfns {
        types.insert(pfn, memory_type);
    }
    RETYPED.fetch_add(pages.len(), Ordering::AcqRel);
    Ok(())
}

/// Forget the records of `pages`, which must all be recorded.
fn unreserve(pages: &[PhysFrame]) {
    let mut types = RAM_TYPES.lock();
    for page in pages {
        types.remove(&(page.start_address().raw() >> 12));
    }
    RETYPED.fetch_sub(pages.len(), Ordering::AcqRel);
}

/// Make every kernel alias of `pages` write-combining (Linux
/// `set_pages_array_wc`). Each page must be System RAM with no recorded type.
/// On error nothing changes — except if undoing a partial rewrite itself
/// fails, when every page stays recorded and must never be freed.
///
/// # Safety
/// The caller owns every page exclusively: no other kernel pointer, user
/// mapping or device access reaches them until this returns, and
/// [`set_pages_wb`] runs before they are freed. Bytes the caller wrote before
/// the call reach memory (the cache lines are written back).
pub unsafe fn set_pages_wc(pages: &[PhysFrame]) -> Result<(), PageAttrError> {
    let root = kernel_root()?;
    if pages.is_empty() {
        return Ok(());
    }
    reserve(pages, MemoryType::WriteCombining)?;
    #[cfg(target_arch = "x86_64")]
    for (index, chunk) in pages.chunks(CHUNK).enumerate() {
        // SAFETY: forwarded contract; `root` is the recorded kernel root.
        let done = unsafe { x86::retype(root, chunk, MemoryType::Uncached) }
            .and_then(|()| unsafe { x86::retype(root, chunk, MemoryType::WriteCombining) });
        if let Err(error) = done {
            let touched = ((index + 1) * CHUNK).min(pages.len());
            // SAFETY: the same pages, still exclusively owned. Restoring never
            // splits, so it does not fail where the walk above succeeded.
            if unsafe { x86::restore(root, &pages[..touched]) }.is_ok() {
                unreserve(pages);
            }
            return Err(error);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = root;
    Ok(())
}

/// Restore write-back on every kernel alias of `pages` (Linux
/// `set_pages_array_wb`). Each page must have been retyped by
/// [`set_pages_wc`]; otherwise nothing changes and the result is
/// [`PageAttrError::Busy`]. If an alias cannot be rewritten the pages stay
/// recorded and must not be freed.
///
/// # Safety
/// The caller owns every page exclusively and no user mapping or device
/// access to them remains.
pub unsafe fn set_pages_wb(pages: &[PhysFrame]) -> Result<(), PageAttrError> {
    let root = kernel_root()?;
    let pfns = distinct_pfns(pages)?;
    if !{
        let types = RAM_TYPES.lock();
        pfns.iter().all(|pfn| types.contains_key(pfn))
    } {
        return Err(PageAttrError::Busy);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: forwarded contract.
    unsafe {
        x86::restore(root, pages)?
    };
    #[cfg(not(target_arch = "x86_64"))]
    let _ = root;
    unreserve(pages);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::{PageAttrError, CHUNK, CPA_LOCK};
    use crate::frame::PhysFrame;
    use crate::memtype::MemoryType;
    use crate::x86_64::paging::{PageTable, PageTableEntry, PtFlags, WalkIndices};
    use crate::{PhysAddr, VirtAddr};
    use core::sync::atomic::{compiler_fence, fence, Ordering};

    fn from_poke(error: crate::text_poke::PokeError) -> PageAttrError {
        match error {
            crate::text_poke::PokeError::NoFrame => PageAttrError::NoFrame,
            _ => PageAttrError::Unsupported,
        }
    }

    /// The 4 KiB leaf mapping `va`. Huge leaves are split on the way down when
    /// `split`; otherwise a huge leaf answers `None` (this module never
    /// retypes one, so it is still write-back).
    ///
    /// # Safety
    /// `root` is the live kernel root and the caller holds `CPA_LOCK`.
    unsafe fn leaf(
        root: PhysAddr,
        va: u64,
        split: bool,
    ) -> Result<Option<*mut PageTableEntry>, PageAttrError> {
        // At most two splits (1 GiB → 2 MiB → 4 KiB).
        loop {
            let idx = WalkIndices::from_virt(VirtAddr::new(va));
            // SAFETY: page tables are reached through the direct map; the
            // windows walked here are built by `init_mmu` or by a split.
            unsafe {
                let pml4 = &mut *root.kernel_mut_ptr::<PageTable>();
                let e = pml4.entries[idx.pml4];
                if !e.is_present() {
                    return Err(PageAttrError::Unsupported);
                }
                let pdpt = &mut *e.addr().kernel_mut_ptr::<PageTable>();
                let pe = pdpt.entries[idx.pdpt];
                if !pe.is_present() {
                    return Err(PageAttrError::Unsupported);
                }
                if pe.flags().contains(PtFlags::HUGE_PAGE) {
                    if !split {
                        return Ok(None);
                    }
                    crate::text_poke::split_leaf(&mut pdpt.entries[idx.pdpt], true)
                        .map_err(from_poke)?;
                    continue;
                }
                let pd = &mut *pe.addr().kernel_mut_ptr::<PageTable>();
                let de = pd.entries[idx.pd];
                if !de.is_present() {
                    return Err(PageAttrError::Unsupported);
                }
                if de.flags().contains(PtFlags::HUGE_PAGE) {
                    if !split {
                        return Ok(None);
                    }
                    crate::text_poke::split_leaf(&mut pd.entries[idx.pd], false)
                        .map_err(from_poke)?;
                    continue;
                }
                let pt = &mut *de.addr().kernel_mut_ptr::<PageTable>();
                if !pt.entries[idx.pt].is_present() {
                    return Err(PageAttrError::Unsupported);
                }
                return Ok(Some(&mut pt.entries[idx.pt] as *mut PageTableEntry));
            }
        }
    }

    /// Rewrite every kernel alias of `pages` to `memory_type` (splitting as
    /// needed), then invalidate every CPU's TLB and, for a non-write-back
    /// target, write back and invalidate the pages' cache lines (`cpa_flush`).
    /// The flush runs even after a partial failure so no CPU keeps a stale
    /// translation of what was rewritten.
    ///
    /// # Safety
    /// `root` is the live kernel root; the caller owns `pages` exclusively.
    pub(super) unsafe fn retype(
        root: PhysAddr,
        pages: &[PhysFrame],
        memory_type: MemoryType,
    ) -> Result<(), PageAttrError> {
        debug_assert!(pages.len() <= CHUNK);
        let bits = crate::memtype::x86_leaf_bits_4k(memory_type).bits();
        let split = memory_type != MemoryType::WriteBack;
        let _cpa = CPA_LOCK.lock();
        let mut global = false;
        let mut result = Ok(());
        'pages: for page in pages {
            let (vas, n) = crate::text_poke::alias_vas(page.start_address().raw());
            for &va in vas.iter().take(n) {
                // SAFETY: CPA_LOCK held; forwarded root contract.
                match unsafe { leaf(root, va, split) } {
                    Ok(Some(entry)) => {
                        // SAFETY: a present leaf of a live kernel table. One
                        // aligned 8-byte store; the CPA lock excludes other
                        // writers of these windows.
                        unsafe {
                            let raw = core::ptr::read_volatile(entry).raw();
                            global |= raw & PtFlags::GLOBAL.bits() != 0;
                            let next = (raw & !PtFlags::CACHE_MASK_4K.bits()) | bits;
                            core::ptr::write_volatile(entry, PageTableEntry::from_raw(next));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        result = Err(error);
                        break 'pages;
                    }
                }
            }
        }
        // SAFETY: CPL=0; every VA is a mapped kernel alias.
        unsafe { flush(pages, global, split) };
        result
    }

    /// Write-back on every alias, without splitting. Does not fail on a range
    /// [`retype`] walked: split leaves stay split and an unsplit huge leaf is
    /// already write-back. Every chunk is attempted; the first error returns.
    ///
    /// # Safety
    /// As [`retype`].
    pub(super) unsafe fn restore(root: PhysAddr, pages: &[PhysFrame]) -> Result<(), PageAttrError> {
        // Retire this CPU's write-combining buffers before the pages become
        // cacheable; peers' buffers drain with the shootdown interrupt.
        // SAFETY: SFENCE has no preconditions.
        unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
        let mut result = Ok(());
        for chunk in pages.chunks(CHUNK) {
            // SAFETY: forwarded. Without splitting the walk only fails on a
            // non-present window, which `retype` would have refused first.
            let done = unsafe { retype(root, chunk, MemoryType::WriteBack) };
            result = result.and(done);
        }
        result
    }

    /// `cpa_flush`: TLBs first, then (for a non-cacheable target) every cache
    /// line of every page, bracketed by full fences.
    unsafe fn flush(pages: &[PhysFrame], global: bool, cache: bool) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: CPL=0.
        unsafe {
            if global {
                // Kernel RAM aliases are not GLOBAL today; if one is, a full
                // non-global flush would not retire it.
                for page in pages {
                    let (vas, n) = crate::text_poke::alias_vas(page.start_address().raw());
                    for &va in vas.iter().take(n) {
                        crate::x86_64::paging::invlpg_global_range(VirtAddr::new(va), 1);
                    }
                }
            }
            crate::x86_64::paging::flush_user_tlb_all_cpus();
        }
        compiler_fence(Ordering::SeqCst);
        if !cache {
            return;
        }
        let caps = narf_arch::x86_64::cache::caps();
        let line = match caps.line_bytes {
            0 => 64,
            bytes => usize::from(bytes),
        };
        fence(Ordering::SeqCst);
        for page in pages {
            let base = page.start_address().kernel_ptr::<u8>();
            for offset in (0..4096).step_by(line) {
                // SAFETY: a mapped kernel alias of an owned page; CLFLUSH is
                // architectural on x86_64, CLFLUSHOPT used only when present.
                unsafe {
                    if caps.clflushopt {
                        narf_arch::x86_64::cache::clflushopt(base.add(offset));
                    } else {
                        narf_arch::x86_64::cache::clflush(base.add(offset));
                    }
                }
            }
        }
        fence(Ordering::SeqCst);
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroed System RAM pages that every kernel alias maps write-combining, for
/// write-combining user mappings and non-snooped device access (a TTM
/// `ttm_write_combined` allocation). Drop restores write-back, then frees.
#[derive(Debug)]
pub struct WcPages {
    frames: Vec<PhysFrame>,
}

impl WcPages {
    /// Allocate, zero and retype `count` pages. The zeroes are in memory when
    /// this returns, so a non-snooping reader sees them.
    pub fn allocate(count: usize) -> Result<Self, PageAttrError> {
        kernel_root()?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(count)
            .map_err(|_| PageAttrError::NoFrame)?;
        for _ in 0..count {
            let Ok(frame) = crate::frame::alloc_frame() else {
                crate::frame::free_frame_batch(&frames);
                return Err(PageAttrError::NoFrame);
            };
            // SAFETY: a fresh, exclusively owned frame, still write-back.
            unsafe {
                core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, 4096)
            };
            frames.push(frame);
        }
        // SAFETY: every frame is freshly allocated and unpublished; the drop
        // below restores write-back before freeing.
        if let Err(error) = unsafe { set_pages_wc(&frames) } {
            if frames
                .first()
                .is_some_and(|frame| ram_memory_type(frame.start_address()).is_some())
            {
                // The rollback could not restore: never free retyped pages.
                LEAKED.fetch_add(frames.len() as u64, Ordering::Relaxed);
            } else {
                crate::frame::free_frame_batch(&frames);
            }
            return Err(error);
        }
        Ok(Self { frames })
    }

    pub fn frames(&self) -> &[PhysFrame] {
        &self.frames
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl Drop for WcPages {
    fn drop(&mut self) {
        // SAFETY: the holder drops this only after every user mapping and
        // device access through the pages has ended.
        match unsafe { set_pages_wb(&self.frames) } {
            Ok(()) => crate::frame::free_frame_batch(&self.frames),
            Err(_) => {
                LEAKED.fetch_add(self.frames.len() as u64, Ordering::Relaxed);
            }
        }
        self.frames.clear();
    }
}
