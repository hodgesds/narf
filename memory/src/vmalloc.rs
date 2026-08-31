//! Kernel-VA allocator — hands out unbacked virtual address
//! ranges from a high-half cursor.
//!
//! Use case: mapping device BARs that fall outside the boot
//! identity map. ioremap (per-arch) calls `alloc(len)` here to
//! get a fresh kernel virtual range, then walks the active page
//! tables to install PTEs pointing at the device phys with the
//! appropriate device-memory attributes.
//!
//! Layout:
//!   * x86_64 — kernel VA space lives in the upper half. The
//!     vmalloc cursor starts at 0xFFFF_8800_0000_0000 (PML4
//!     slot 272 — bits 47:39 of that address are 0b1_0001_0000),
//!     well clear of:
//!       - the higher-half kernel image at PML4[511] (Stage 1 boot).
//!       - the per-driver-domain private slots 256..=271 we
//!         carved out for the PCID enforcer.
//!       - the upper user-mappable cursor at slot 256 (KPTI-style
//!         shared lower half, in case ASIDs ever come into play).
//!   * aarch64 — TTBR1 covers 0xFFFF_0000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF
//!     by convention; we pick a mid-TTBR1 range starting at
//!     0xFFFF_C000_0000_0000.
//!
//! No fragmentation handling yet. `alloc(len)` advances the
//! cursor monotonically; `free(range)` is a no-op for the bump
//! pointer. A real free list can land later when long-running
//! drivers actually exercise iounmap.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, PhysFrame, VirtAddr};

#[cfg(target_arch = "x86_64")]
const VMALLOC_BASE: u64 = 0xFFFF_8800_0000_0000;
#[cfg(target_arch = "aarch64")]
const VMALLOC_BASE: u64 = 0xFFFF_C000_0000_0000;

/// 4 GiB of vmalloc space, split in two halves that share one kernel PML4
/// slot (so one boot-time `reserve_kernel_slot` covers both):
///   * lower 2 GiB — `ioremap`'s unbacked bump allocator (device BARs;
///     long-lived, so its no-op free is acceptable).
///   * upper 2 GiB — the frame-backed [`valloc`] heap fallback, with a
///     bitmap allocator that actually reclaims VA on `vfree`.
const IOREMAP_LIMIT: u64 = VMALLOC_BASE + (2u64 << 30);
const VALLOC_BASE: u64 = IOREMAP_LIMIT;
const VALLOC_LIMIT: u64 = VMALLOC_BASE + (4u64 << 30);
/// Pages in the `valloc` half; one bit each in `VALLOC_MAP`.
const VALLOC_PAGES: usize = (2usize << 30) / 4096;
const VALLOC_WORDS: usize = VALLOC_PAGES / 64;

/// Kernel PML4 (x86) / L0 (aarch64) slot the whole vmalloc window lives in.
/// The entire 4 GiB fits in one 512 GiB slot. Boot pre-populates this slot's
/// top-level entry BEFORE any user address space is created, so the by-value
/// kernel-half copy in `new_user_pml4` shares the same lower page tables and
/// vmalloc/ioremap mappings are visible in every address space (otherwise a
/// kernel access from another AS's CPU would hit an empty slot — a cross-AS
/// page fault). Decodes from `VMALLOC_BASE`; asserted in `reserve_kernel_slot`.
#[cfg(target_arch = "x86_64")]
pub const KERNEL_PML4_SLOT: usize = 272;
#[cfg(target_arch = "aarch64")]
pub const KERNEL_PML4_SLOT: usize = 384;

static CURSOR: AtomicU64 = AtomicU64::new(VMALLOC_BASE);

/// A reserved kernel-VA range. Holders should keep it alive for
/// the lifetime of the mapping it backs (device BAR, etc.).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmRange {
    pub base: u64,
    pub len: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmallocError {
    /// Requested zero or non-page-aligned length.
    BadLen,
    /// Address space exhausted.
    Exhausted,
}

/// Allocate `len` bytes (rounded up to a page) of fresh kernel
/// VA. The returned range is unbacked — callers (ioremap,
/// vmap-style mappers) install PTEs themselves before
/// dereferencing.
pub fn alloc(len: u64) -> Result<VmRange, VmallocError> {
    let len_pg = (len + 0xFFF) & !0xFFFu64;
    if len_pg == 0 {
        return Err(VmallocError::BadLen);
    }
    // Bump-pointer atomic CAS so concurrent callers don't
    // overlap.
    loop {
        let cur = CURSOR.load(Ordering::Relaxed);
        let end = cur.checked_add(len_pg).ok_or(VmallocError::Exhausted)?;
        if end > IOREMAP_LIMIT {
            return Err(VmallocError::Exhausted);
        }
        match CURSOR.compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => {
                return Ok(VmRange {
                    base: cur,
                    len: len_pg,
                })
            }
            Err(_) => continue,
        }
    }
}

/// Free a previously-allocated range. Today's bump-pointer
/// allocator just drops the range on the floor — the cursor only
/// moves forward. iounmap callers still call this so the API
/// stays right when a real free list lands.
pub fn free(range: VmRange) {
    let _ = range;
}

/// Total bytes claimed since boot — diagnostic only.
pub fn claimed_bytes() -> u64 {
    CURSOR.load(Ordering::Relaxed) - VMALLOC_BASE
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    CURSOR.store(VMALLOC_BASE, Ordering::Relaxed);
}

// ── Frame-backed vmalloc (kernel-heap large-allocation fallback) ───────
//
// The kernel heap's large-object path (`slab::alloc_large`) uses a
// physically-CONTIGUOUS buddy block, which fails under fragmentation even when
// plenty of scattered pages are free (a 64 KiB `Vec` needs 16 adjacent frames).
// `valloc` backs a virtually-contiguous range with SCATTERED order-0 frames, so
// a large kernel allocation — e.g. `clone_for_fork`'s region-sized `Vec` — only
// needs enough free pages, not a contiguous run. NARF's analogue of Linux
// `vmalloc` behind `kvmalloc`.

/// Bitmap allocator over the `valloc` half of the window: one bit per page,
/// set = in use. Fixed-size (allocation-free), so `valloc` never re-enters the
/// heap allocator it backs. `free_run` reclaims VA — unlike the ioremap bump.
struct VaMap {
    words: [u64; VALLOC_WORDS],
}

impl VaMap {
    const fn new() -> Self {
        Self {
            words: [0; VALLOC_WORDS],
        }
    }
    #[inline]
    fn used(&self, page: usize) -> bool {
        self.words[page / 64] & (1u64 << (page % 64)) != 0
    }
    /// First-fit run of `n` contiguous free pages; marks them used. Skips
    /// fully-allocated words to keep the scan short under churn.
    fn alloc_run(&mut self, n: usize) -> Option<usize> {
        if n == 0 || n > VALLOC_PAGES {
            return None;
        }
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut page = 0usize;
        while page < VALLOC_PAGES {
            if run_len == 0 && page % 64 == 0 && self.words[page / 64] == u64::MAX {
                page += 64;
                run_start = page;
                continue;
            }
            if self.used(page) {
                run_len = 0;
                run_start = page + 1;
            } else {
                run_len += 1;
                if run_len == n {
                    for p in run_start..run_start + n {
                        self.words[p / 64] |= 1u64 << (p % 64);
                    }
                    return Some(run_start);
                }
            }
            page += 1;
        }
        None
    }
    fn free_run(&mut self, base: usize, n: usize) {
        for p in base..base + n {
            self.words[p / 64] &= !(1u64 << (p % 64));
        }
    }
}

static VALLOC_MAP: IrqSafeSpinLock<VaMap> = IrqSafeSpinLock::new(VaMap::new());

/// Kernel leaf-mapping flags for a frame-backed vmalloc page: writable,
/// non-executable, and **NON-global**.
///
/// vmalloc pages are mapped and UNMAPPED at runtime, so they must never be
/// GLOBAL: several TLB-flush paths (the idle-CPU deferred `flush_user_tlb_local`
/// via `apply_lazy_local_full`, `invpcid_all_without_globals`, and the
/// no-PCID MOV-CR3 self-flush) deliberately RETAIN global entries. A global
/// vmalloc mapping would therefore leave a stale translation on an idle peer
/// after `vfree`, and it would access the reused frame — an intermittent SMP
/// #PF / corruption. Global is reserved for PERMANENT kernel mappings (kernel
/// text, the direct map, the per-CPU BPF stack) that are never shot down;
/// `unmap_4kb` `debug_assert`s this invariant. Cross-AS visibility comes from
/// the shared kernel page tables, not the global bit, so dropping it is free.
#[inline]
fn kernel_leaf_flags() -> crate::paging::PtFlags {
    use crate::paging::PtFlags;
    #[cfg(target_arch = "x86_64")]
    {
        PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_EXEC
    }
    #[cfg(target_arch = "aarch64")]
    {
        PtFlags::AP_RW_EL1 | PtFlags::ATTR_NORMAL | PtFlags::UXN | PtFlags::PXN
    }
}

/// Map one kernel page at `va` to `phys` in the shared kernel tables.
///
/// # Safety
/// `va` must lie in the pre-reserved vmalloc slot and `phys` be an owned frame.
unsafe fn map_kernel_page(va: VirtAddr, phys: PhysAddr) -> Result<(), ()> {
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(())?;
    // SAFETY: `root` is the live kernel PML4/L0; `va` is in the pre-reserved
    // kernel-shared vmalloc slot; `phys` is a fresh, exclusively-owned frame.
    unsafe { crate::paging::map_4kb(root, va, phys, kernel_leaf_flags()) }.map_err(|_| ())
}

/// Unmap one kernel page at `va`, returning the physical frame it backed. The
/// underlying `unmap_4kb` performs the global TLB invalidation.
///
/// # Safety
/// `va` must be a page currently mapped by `map_kernel_page`.
unsafe fn unmap_kernel_page(va: VirtAddr) -> Result<PhysAddr, ()> {
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(())?;
    // SAFETY: `root` is the live kernel root; `va` was mapped here by us.
    unsafe { crate::paging::unmap_4kb(root, va) }.map_err(|_| ())
}

/// Unmap + free the first `count` pages of the range at VA `base`.
///
/// # Safety
/// `[base, base + count*4096)` must be pages this module mapped.
unsafe fn unmap_and_free(base: u64, count: usize) {
    for i in 0..count {
        let va = VirtAddr::new(base + (i as u64) * 4096);
        // SAFETY: mapped by `map_kernel_page` for this allocation.
        if let Ok(phys) = unsafe { unmap_kernel_page(va) } {
            if phys.raw() != 0 {
                crate::frame::free_frame(PhysFrame::new(phys));
            }
        }
    }
    // Fully reclaim page tables: free any last-level table the freed range
    // leaves empty (checked once per 2 MiB granule; a table still holding a
    // live allocation's leaves is kept). Every leaf above was unmapped with a
    // global TLB/PWC invalidation, so freeing the now-empty table is safe.
    if count != 0 {
        if let Some(root) = crate::bpf_text::kernel_root_for_mapping() {
            let end = base + (count as u64) * 4096;
            let mut granule = base & !0x1F_FFFFu64;
            while granule < end {
                // SAFETY: the range's leaves were just unmapped+flushed above.
                let _ = unsafe { crate::paging::free_empty_pt(root, VirtAddr::new(granule)) };
                granule += 0x20_0000;
            }
        }
    }
}

/// `true` when `ptr` lies in the frame-backed `valloc` half of the window.
/// The kernel-heap large-free path uses this to route a pointer back to
/// `vfree` vs the contiguous buddy free.
#[inline]
pub fn is_valloc_ptr(ptr: *const u8) -> bool {
    (VALLOC_BASE..VALLOC_LIMIT).contains(&(ptr as u64))
}

/// Allocate `size` bytes of virtually-contiguous, physically-SCATTERED kernel
/// memory. Returns `None` if VA or frames are exhausted. Bookkeeping is
/// allocation-free, so it is safe to call from the heap allocator's large-object
/// path. Every backing frame uses `Kernel` context (may draw the `min` reserve).
pub fn valloc(size: usize) -> Option<NonNull<u8>> {
    let n = size.div_ceil(4096);
    if n == 0 {
        return None;
    }
    let base_page = VALLOC_MAP.lock().alloc_run(n)?;
    let base = VALLOC_BASE + (base_page as u64) * 4096;

    let mut done = 0usize;
    while done < n {
        let va = VirtAddr::new(base + (done as u64) * 4096);
        let frame = match crate::frame::alloc_frame() {
            Ok(f) => f,
            Err(_) => {
                // SAFETY: `done` pages were mapped above.
                unsafe { unmap_and_free(base, done) };
                VALLOC_MAP.lock().free_run(base_page, n);
                return None;
            }
        };
        // SAFETY: kernel VA in the reserved vmalloc slot; frame is ours.
        if unsafe { map_kernel_page(va, frame.start_address()) }.is_err() {
            crate::frame::free_frame(frame);
            // SAFETY: `done` pages were mapped above (this one is not).
            unsafe { unmap_and_free(base, done) };
            VALLOC_MAP.lock().free_run(base_page, n);
            return None;
        }
        done += 1;
    }
    NonNull::new(base as *mut u8)
}

/// Free a `valloc` allocation: unmap + free every backing DATA frame, free any
/// page tables the range leaves empty (`unmap_and_free` → `free_empty_pt`
/// cascade, keeping only the shared reserved top-level slot), then reclaim the
/// VA. Fully reclaiming — no residual page-table retention. Each leaf is
/// unmapped with a global (broadcast) invalidation, so peers cannot hold a
/// stale entry for a freed table.
///
/// # Safety
/// `ptr` must have come from `valloc` and `size` be the same size passed there.
pub unsafe fn vfree(ptr: NonNull<u8>, size: usize) {
    let n = size.div_ceil(4096);
    let base = ptr.as_ptr() as u64;
    // SAFETY: forwarded from the caller's contract; these are our pages.
    unsafe { unmap_and_free(base, n) };
    let base_page = ((base - VALLOC_BASE) / 4096) as usize;
    VALLOC_MAP.lock().free_run(base_page, n);
}

/// Pre-populate the vmalloc window's kernel PML4/L0 slot in the live kernel
/// root, so the by-value kernel-half copy in `new_user_pml4` shares the same
/// lower tables and vmalloc/ioremap mappings are visible in EVERY address
/// space. MUST run at boot, after `init_mmu` installs the final kernel root and
/// BEFORE the first user address space is created. Idempotent.
pub fn reserve_kernel_slot() -> Result<(), VmallocError> {
    debug_assert_eq!(
        ((VMALLOC_BASE >> 39) & 0x1FF) as usize,
        KERNEL_PML4_SLOT,
        "VMALLOC_BASE does not decode to KERNEL_PML4_SLOT"
    );
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(VmallocError::Exhausted)?;
    // SAFETY: `root` is the live kernel root; single-threaded boot context.
    unsafe { reserve_slot(root, KERNEL_PML4_SLOT) }
}

/// Install an empty next-level table under `root[slot]` if absent, so the slot
/// is shared by every address space that later copies the kernel half.
///
/// # Safety
/// `root` must be the live, identity-reachable kernel root and the caller
/// single-threaded (boot).
#[cfg(target_arch = "x86_64")]
unsafe fn reserve_slot(root: PhysAddr, slot: usize) -> Result<(), VmallocError> {
    use crate::x86_64::paging::{PageTable, PageTableEntry, PtFlags};
    // SAFETY: caller's contract — live kernel PML4.
    let pml4 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    if pml4.entries[slot].is_present() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| VmallocError::Exhausted)?;
    let phys = frame.start_address();
    crate::frame::__pagetable_register(phys.raw());
    // SAFETY: fresh frame, exclusively ours until published below.
    unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
    pml4.entries[slot] = PageTableEntry::new(phys, PtFlags::PRESENT | PtFlags::WRITABLE);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
unsafe fn reserve_slot(root: PhysAddr, slot: usize) -> Result<(), VmallocError> {
    use crate::aarch64::paging::{PageTable, PageTableEntry};
    // SAFETY: caller's contract — live TTBR1 L0.
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    if l0.entries[slot].is_valid() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| VmallocError::Exhausted)?;
    let phys = frame.start_address();
    // SAFETY: fresh frame, exclusively ours until published below.
    unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
    // Table descriptor: bits[1:0] = 0b11 (valid + table); leaf entries carry
    // the real permissions.
    l0.entries[slot] = PageTableEntry::from_raw(phys.raw() | 0b11);
    Ok(())
}
