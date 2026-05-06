//! x86_64 page-table types and helpers (Stage 1 subset).
//!
//! Spec: `memory/specification/spec.md` §3 + §5. Stage-1 lands the
//! 4-level PML4 structure, 1-GiB huge-page mapping (enough to build our
//! own identity map), and a CR3-swap primitive. 4 KiB and 2 MiB page
//! mapping, unmap, page-fault recovery, and the Folio wrapper land in
//! Wave 2b / 2c as consumers arrive.
//!
//! The page-table types here are x86_64-specific. aarch64 has a
//! structurally similar but bit-field-different layout; we'll gate by
//! `#[cfg(target_arch)]` when aarch64 MMU bring-up lands.

#![cfg(target_arch = "x86_64")]

use core::fmt;
use core::ptr;

use crate::PhysAddr;

/// A single 64-bit page-table entry (all levels share the same width).
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

/// Bits in a page-table entry, per Intel SDM Vol 3 §4.5. We name only
/// the subset we use today; the rest stay as literal bit masks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PtFlags(u64);

impl PtFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const NO_CACHE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    /// On a PDPT / PD entry: "this is a huge page, not a pointer to the
    /// next-level table." On x86_64 a PS=1 PDPT entry maps 1 GiB; a
    /// PS=1 PD entry maps 2 MiB. Never set in a PML4 entry.
    pub const HUGE_PAGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    /// Execute-disable bit (IA32_EFER.NXE must be set for this to be
    /// interpreted; without NXE the bit is reserved-zero).
    pub const NO_EXEC: Self = Self(1 << 63);

    /// Protection-key mask. Bits 59..=62 in a PTE hold the PK field
    /// (4 bits, 16 possible domains). See SDM Vol 3 §4.6.2.
    pub const PK_MASK: Self = Self(0xF << 59);

    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Flag mask that tags a PTE with protection-key `domain`. Only the
    /// low 4 bits of `domain` are used; higher bits are silently masked.
    #[inline]
    pub const fn pk(domain: u8) -> Self {
        Self(((domain as u64) & 0xF) << 59)
    }

    /// Extract the protection-key domain from a flag value. Returns a
    /// value in 0..=15.
    #[inline]
    pub const fn pk_of(self) -> u8 {
        ((self.0 >> 59) & 0xF) as u8
    }
}

impl core::ops::BitOr for PtFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for PtFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn new(addr: PhysAddr, flags: PtFlags) -> Self {
        // Physical address must be 4 KiB-aligned: low 12 bits are flag
        // bits, not address bits.
        Self((addr.raw() & 0x000f_ffff_ffff_f000) | flags.bits())
    }

    #[inline]
    pub const fn is_present(self) -> bool {
        self.0 & 1 == 1
    }
    #[inline]
    pub const fn flags(self) -> PtFlags {
        PtFlags(self.0 & 0xfff0_0000_0000_0fff)
    }

    /// Physical address of the mapped page / next-level table.
    #[inline]
    pub const fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000f_ffff_ffff_f000)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PTE({:#018x})", self.0)
    }
}

/// 4 KiB / 512 entries. Alignment matters — MMU expects this at a
/// 4 KiB boundary.
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    /// A freshly-zeroed page table. Not `const` because it's large;
    /// call this on freshly-allocated page-table storage.
    pub fn zero_at(ptr: *mut PageTable) {
        // SAFETY: caller guarantees `ptr` references at least
        // `size_of::<PageTable>()` writable, properly-aligned bytes.
        unsafe {
            ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<PageTable>());
        }
    }
}

impl fmt::Debug for PageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self.entries.iter().filter(|e| e.is_present()).count();
        f.debug_struct("PageTable")
            .field("present_entries", &present)
            .finish_non_exhaustive()
    }
}

/// Errors from `new_user_pml4` / address-space construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageTableAllocError {
    NoFrame,
}

/// Allocate a fresh PML4 for an address-space handle. Full-copy of
/// the currently-active PML4 so activation is safe under the current
/// kernel layout (which keeps the low 4 GiB identity-mapped for
/// frame-allocator access and the high half for kernel code/stack).
///
/// This is a Stage-4 **structural** constructor — the AS returned
/// can be installed via `AddressSpace::activate()` without
/// triple-faulting, but every user-space access goes through the
/// same mappings as the kernel. A genuinely isolating user AS
/// needs either a higher-half direct map in `memory/` or a
/// migration of the frame allocator off the identity map so the
/// low half can be cleared. That work is tracked separately.
///
/// # Safety
/// - Caller must run with paging enabled and the low 4 GiB still
///   identity-mapped (standard NARF boot state).
/// - The returned PhysAddr must be dropped through the frame
///   allocator when the address space retires — leaks are live
///   pages until reboot.
pub unsafe fn new_user_pml4() -> Result<PhysAddr, PageTableAllocError> {
    // SAFETY: delegated; node 0 is always present.
    unsafe { new_user_pml4_on(0) }
}

/// Same as `new_user_pml4` but allocates the fresh frame on a
/// specific NUMA node. Used by the per-domain PML4 boot loop on
/// AMD silicon to spread PML4 storage across the topology.
///
/// # Safety
/// Same as `new_user_pml4`.
pub unsafe fn new_user_pml4_on(node: usize) -> Result<PhysAddr, PageTableAllocError> {
    let frame = crate::frame::alloc_frame_on(node).map_err(|_| PageTableAllocError::NoFrame)?;
    let phys = frame.start_address();

    // Read the currently-active PML4.
    // SAFETY: `read_cr3` is a single privileged read — legal at CPL=0.
    let cur_pml4 = unsafe { read_cr3() };

    // Full-copy the 4 KiB of PML4 entries into the fresh frame.
    // SAFETY: both `cur_pml4` and `phys` point at properly-aligned
    // `PageTable`-sized identity-mapped regions.
    unsafe {
        ptr::copy_nonoverlapping(
            cur_pml4.raw() as *const u8,
            phys.raw() as *mut u8,
            core::mem::size_of::<PageTable>(),
        );
    }

    Ok(phys)
}

/// Write a value to physical memory while we're still in an
/// identity-mapped phase of boot. Used to prime a fresh PML4 before
/// `write_cr3` swaps to it.
///
/// # Safety
/// - `phys` must be identity-mapped in the *current* page tables.
/// - The write must respect the target's alignment.
pub unsafe fn write_identity<T>(phys: PhysAddr, value: T) {
    // SAFETY: per caller contract.
    unsafe {
        ptr::write_volatile(phys.raw() as *mut T, value);
    }
}

/// Read the currently-active PML4 physical address from CR3.
///
/// # Safety
/// `MOV from CR3` is always legal at CPL=0; the `unsafe` marker is for
/// the inline-asm boundary only.
pub unsafe fn read_cr3() -> PhysAddr {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: CR3 read at CPL=0 is always defined.
    unsafe {
        asm!(
            "mov {v}, cr3",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    // Low 12 bits are PCID (when CR4.PCIDE=1); mask them off.
    PhysAddr::new(v & 0x000f_ffff_ffff_f000)
}

/// Load a fresh PML4 physical address into CR3. The full pre/post
/// `compiler_fence(SeqCst)` pair follows `arch/` §4 discipline.
///
/// # Safety
/// - `pml4_phys` must point at a valid PML4 that maps enough memory
///   for the code path continuing after this call. Getting this wrong
///   triple-faults the kernel immediately.
/// - Interrupts should be disabled across the swap; the caller's
///   boot sequence already holds this invariant.
pub unsafe fn write_cr3(pml4_phys: PhysAddr) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    compiler_fence(Ordering::SeqCst);
    // SAFETY: `mov cr3, rax` is legal at CPL=0 and is the defined way
    // to switch the address-space root on x86_64.
    unsafe {
        asm!(
            "mov cr3, {addr}",
            addr = in(reg) pml4_phys.raw(),
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Optional cross-CPU TLB-shootdown hook, installed at boot by
/// `frame/` once the IPI handler is live. When `None`, mapping
/// mutations only INVLPG locally — fine for single-CPU bring-up
/// and for fresh mappings (no stale TLB entries on other CPUs).
/// When `Some`, every `invlpg_global` call broadcasts to peers.
///
/// Stored as `AtomicUsize` rather than `Option<fn>` so it can be
/// initialised in a `static` and updated atomically without a lock.
static SHOOTDOWN_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Hook signature: takes the VA whose mapping just changed and
/// arranges for every other CPU's TLB to invalidate it.
pub type TlbShootdownHook = fn(u64);

/// Install the shootdown hook. Frame's boot path calls this after
/// IPI handlers are installed and APs are online.
pub fn set_shootdown_hook(hook: TlbShootdownHook) {
    SHOOTDOWN_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

/// Local INVLPG followed by a cross-CPU broadcast when the hook is
/// installed. Use this from any path that *mutates* an existing
/// mapping (remap or unmap) where stale TLB entries on peer CPUs
/// would matter. Fresh mappings can use `invlpg` directly — no peer
/// has the entry cached.
///
/// # Safety
/// Same as `invlpg`.
pub unsafe fn invlpg_global(virt: VirtAddr) {
    // SAFETY: caller upholds invlpg's contract.
    unsafe {
        invlpg(virt);
    }
    let h = SHOOTDOWN_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if h != 0 {
        // SAFETY: stored as `TlbShootdownHook as usize`.
        let f: TlbShootdownHook = unsafe { core::mem::transmute(h) };
        f(virt.raw());
    }
}

/// Optional cross-CPU TLB-shootdown range hook, paired with
/// `set_range_shootdown_hook`. Same shape as the single-page hook
/// but broadcasts an inclusive run of pages — one IPI for N pages.
static RANGE_SHOOTDOWN_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Hook signature for range broadcasts: `(va_base, page_count)`.
pub type TlbShootdownRangeHook = fn(u64, u64);

pub fn set_range_shootdown_hook(hook: TlbShootdownRangeHook) {
    RANGE_SHOOTDOWN_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

/// Local INVLPG over a contiguous range followed by a single-IPI
/// cross-CPU broadcast when the range hook is installed. Falls back
/// to per-page `invlpg_global` calls if the range hook is absent.
///
/// # Safety
/// Each page in `[va_base, va_base + pages*4096)` must have
/// satisfied `invlpg`'s safety contract.
pub unsafe fn invlpg_global_range(va_base: VirtAddr, pages: u64) {
    if pages == 0 {
        return;
    }
    // Local INVLPG over each page.
    for k in 0..pages {
        let v = VirtAddr::new(va_base.raw() + k * 4096);
        // SAFETY: per the function contract.
        unsafe {
            invlpg(v);
        }
    }
    // Prefer the range hook for one-IPI broadcast; fall back to per-page.
    let rh = RANGE_SHOOTDOWN_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if rh != 0 {
        // SAFETY: stored as `TlbShootdownRangeHook as usize`.
        let f: TlbShootdownRangeHook = unsafe { core::mem::transmute(rh) };
        f(va_base.raw(), pages);
        return;
    }
    let h = SHOOTDOWN_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if h != 0 {
        // SAFETY: stored as `TlbShootdownHook as usize`.
        let f: TlbShootdownHook = unsafe { core::mem::transmute(h) };
        for k in 0..pages {
            f(va_base.raw() + k * 4096);
        }
    }
}

/// Invalidate the TLB for a single virtual address via `INVLPG`.
///
/// # Safety
/// Single-page TLB invalidation is always safe at CPL=0; the
/// `compiler_fence` pair keeps the post-invalidation load ordering
/// correct under fat LTO.
pub unsafe fn invlpg(virt: VirtAddr) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    compiler_fence(Ordering::SeqCst);
    // SAFETY: INVLPG [mem] at CPL=0 is always legal.
    unsafe {
        asm!(
            "invlpg [{addr}]",
            addr = in(reg) virt.raw(),
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Errors from `map_4kb` / `unmap_4kb`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The target virtual address isn't 4 KiB-aligned.
    UnalignedVirt,
    /// The target physical address isn't 4 KiB-aligned.
    UnalignedPhys,
    /// Frame allocator couldn't provide a new intermediate page table.
    FrameExhausted,
    /// A higher-level entry on the walk is marked HUGE_PAGE — the caller
    /// asked to overlay a 4 KiB mapping on top of a 1 GiB or 2 MiB
    /// page. Callers must explicitly demote before remapping; Stage-2
    /// work.
    EncounteredHugePage,
    /// The target virtual address already has a 4 KiB mapping. Caller
    /// should `unmap_4kb` first if replacement is intended.
    AlreadyMapped,
    /// The address isn't in canonical 48-bit form (bits 47–63 must be
    /// uniformly 0 or all-1).
    NonCanonical,
}

/// Indices into each level of the 4-level page-table walk.
///
/// Bits [47:39]=PML4, [38:30]=PDPT, [29:21]=PD, [20:12]=PT.
#[derive(Copy, Clone, Debug)]
pub struct WalkIndices {
    pub pml4: usize,
    pub pdpt: usize,
    pub pd: usize,
    pub pt: usize,
}

impl WalkIndices {
    pub const fn from_virt(v: VirtAddr) -> Self {
        let raw = v.raw();
        Self {
            pml4: ((raw >> 39) & 0x1FF) as usize,
            pdpt: ((raw >> 30) & 0x1FF) as usize,
            pd: ((raw >> 21) & 0x1FF) as usize,
            pt: ((raw >> 12) & 0x1FF) as usize,
        }
    }
}

/// Check canonical-form constraint: bits 47–63 must all equal bit 47.
#[inline]
const fn is_canonical(v: VirtAddr) -> bool {
    let hi = v.raw() >> 47;
    hi == 0 || hi == 0x1FFFF
}

use crate::VirtAddr;

/// Map a 4 KiB virtual page to a 4 KiB physical frame.
///
/// Walks the PML4 starting at `pml4_phys`, allocating fresh PDPT / PD /
/// PT frames along the way if they don't exist. Sets the final PT entry
/// to point at `phys` with `flags | PRESENT`. `INVLPG`s the target
/// address so subsequent accesses see the new mapping immediately.
///
/// # Safety
/// - The current address space must identity-map the physical addresses
///   of every page-table level touched. Stage 1's low-4-GiB identity
///   mapping covers this because page tables are in low RAM.
/// - `pml4_phys` must point at a valid PML4 owned by the caller —
///   concurrently modifying it from another CPU is UB.
pub unsafe fn map_4kb(
    pml4_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.raw() & 0xFFF != 0 {
        return Err(MapError::UnalignedVirt);
    }
    if phys.raw() & 0xFFF != 0 {
        return Err(MapError::UnalignedPhys);
    }

    let idx = WalkIndices::from_virt(virt);
    // Intermediate tables need `USER` whenever the leaf does — the
    // CPU AND's the USER bits across every level of the walk, so a
    // `USER` leaf under a supervisor-only PML4 entry is unreachable
    // from CPL=3. Kernel pages are still protected by their own
    // leaf-PTE USER=0.
    let mut base_flags = PtFlags::PRESENT | PtFlags::WRITABLE;
    if flags.contains(PtFlags::USER) {
        base_flags = base_flags | PtFlags::USER;
    }

    // SAFETY: caller guarantees pml4_phys is identity-reachable.
    let pml4 = unsafe { &mut *pml4_phys.as_mut_ptr::<PageTable>() };
    let pdpt_phys = unsafe { ensure_next_table(&mut pml4.entries[idx.pml4], base_flags)? };

    // SAFETY: pdpt_phys came either from an existing mapping we
    // validated, or from a freshly-allocated frame (identity-mapped).
    let pdpt = unsafe { &mut *pdpt_phys.as_mut_ptr::<PageTable>() };
    if pdpt.entries[idx.pdpt].flags().contains(PtFlags::HUGE_PAGE) {
        return Err(MapError::EncounteredHugePage);
    }
    let pd_phys = unsafe { ensure_next_table(&mut pdpt.entries[idx.pdpt], base_flags)? };

    let pd = unsafe { &mut *pd_phys.as_mut_ptr::<PageTable>() };
    if pd.entries[idx.pd].flags().contains(PtFlags::HUGE_PAGE) {
        return Err(MapError::EncounteredHugePage);
    }
    let pt_phys = unsafe { ensure_next_table(&mut pd.entries[idx.pd], base_flags)? };

    let pt = unsafe { &mut *pt_phys.as_mut_ptr::<PageTable>() };
    if pt.entries[idx.pt].is_present() {
        return Err(MapError::AlreadyMapped);
    }
    pt.entries[idx.pt] = PageTableEntry::new(phys, flags | PtFlags::PRESENT);

    // Local INVLPG is sufficient for a fresh mapping — peer CPUs have
    // no entry to invalidate. Remap/unmap call sites broadcast via
    // `invlpg_global`.
    // SAFETY: INVLPG is always safe.
    unsafe {
        invlpg(virt);
    }

    Ok(())
}

/// Tear down a 4 KiB mapping. Intermediate tables are left intact —
/// Wave 2+'s refcounted-table work adds the "delete if empty" sweep.
///
/// # Safety
/// Same identity-mapping precondition as `map_4kb`.
pub unsafe fn unmap_4kb(pml4_phys: PhysAddr, virt: VirtAddr) -> Result<PhysAddr, MapError> {
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.raw() & 0xFFF != 0 {
        return Err(MapError::UnalignedVirt);
    }

    let idx = WalkIndices::from_virt(virt);
    // SAFETY: caller promises identity reachability.
    let pml4 = unsafe { &mut *pml4_phys.as_mut_ptr::<PageTable>() };
    let e = pml4.entries[idx.pml4];
    if !e.is_present() {
        return Err(MapError::AlreadyMapped);
    }
    let pdpt = unsafe { &mut *e.addr().as_mut_ptr::<PageTable>() };

    let e = pdpt.entries[idx.pdpt];
    if !e.is_present() {
        return Err(MapError::AlreadyMapped);
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return Err(MapError::EncounteredHugePage);
    }
    let pd = unsafe { &mut *e.addr().as_mut_ptr::<PageTable>() };

    let e = pd.entries[idx.pd];
    if !e.is_present() {
        return Err(MapError::AlreadyMapped);
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return Err(MapError::EncounteredHugePage);
    }
    let pt = unsafe { &mut *e.addr().as_mut_ptr::<PageTable>() };

    let removed = pt.entries[idx.pt];
    if !removed.is_present() {
        return Err(MapError::AlreadyMapped);
    }
    pt.entries[idx.pt] = PageTableEntry::EMPTY;

    // Unmap is the canonical "stale-TLB" case: peer CPUs may have
    // cached the prior PA. Use the cross-CPU invalidator so any
    // installed shootdown hook fires.
    // SAFETY: INVLPG always safe; hook call is gated by atomic load.
    unsafe {
        invlpg_global(virt);
    }

    Ok(removed.addr())
}

/// Return the PT-level flags currently set for `virt`, or `None` if
/// unmapped / resolved at a huge-page level. Useful for verifying that
/// a `map_4kb` call preserved the flags the caller requested (especially
/// the PK field, which won't show in a plain `translate` call).
///
/// # Safety
/// `pml4_phys` must be identity-reachable (same as `map_4kb`).
pub unsafe fn flags_at(pml4_phys: PhysAddr, virt: VirtAddr) -> Option<PtFlags> {
    if !is_canonical(virt) {
        return None;
    }
    let idx = WalkIndices::from_virt(virt);
    let pml4 = unsafe { &*pml4_phys.as_ptr::<PageTable>() };
    let e = pml4.entries[idx.pml4];
    if !e.is_present() {
        return None;
    }
    let pdpt = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pdpt.entries[idx.pdpt];
    if !e.is_present() {
        return None;
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return None;
    }
    let pd = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pd.entries[idx.pd];
    if !e.is_present() {
        return None;
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return None;
    }
    let pt = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pt.entries[idx.pt];
    if !e.is_present() {
        return None;
    }
    Some(e.flags())
}

/// Resolve the physical address currently mapped at `virt`, if any.
/// Returns `None` when the walk hits a not-present entry. Treats huge
/// pages (1 GiB at PDPT level, 2 MiB at PD level) as first-class —
/// the returned address is the *base* of the huge page, with no
/// offset rollup; callers that need the byte-level phys can add
/// `virt.raw() & (page_size - 1)`.
///
/// # Safety
/// `pml4_phys` must be identity-reachable (same as `map_4kb`).
pub unsafe fn translate(pml4_phys: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
    if !is_canonical(virt) {
        return None;
    }
    let idx = WalkIndices::from_virt(virt);
    let pml4 = unsafe { &*pml4_phys.as_ptr::<PageTable>() };
    let e = pml4.entries[idx.pml4];
    if !e.is_present() {
        return None;
    }
    let pdpt = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pdpt.entries[idx.pdpt];
    if !e.is_present() {
        return None;
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return Some(e.addr());
    } // 1 GiB
    let pd = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pd.entries[idx.pd];
    if !e.is_present() {
        return None;
    }
    if e.flags().contains(PtFlags::HUGE_PAGE) {
        return Some(e.addr());
    } // 2 MiB
    let pt = unsafe { &*e.addr().as_ptr::<PageTable>() };
    let e = pt.entries[idx.pt];
    if !e.is_present() {
        return None;
    }
    Some(e.addr()) // 4 KiB
}

/// Ensure the entry at `slot` references a present, non-huge
/// intermediate table. Allocates a zeroed frame if the slot is empty.
/// Returns the physical address of the next-level table.
///
/// # Safety
/// - `slot` must be a mutable reference to a real PTE slot reachable
///   under the current identity map.
/// - The caller owns the logical mutation window (no other CPU /
///   interrupt path can be walking this subtree).
unsafe fn ensure_next_table(
    slot: &mut PageTableEntry,
    flags: PtFlags,
) -> Result<PhysAddr, MapError> {
    if slot.is_present() {
        if slot.flags().contains(PtFlags::HUGE_PAGE) {
            return Err(MapError::EncounteredHugePage);
        }
        return Ok(slot.addr());
    }
    let frame = crate::alloc_frame().map_err(|_| MapError::FrameExhausted)?;
    let phys = frame.start_address();
    // Caller promises identity-mapped reachability; the unsafe lives
    // inside PageTable::zero_at.
    PageTable::zero_at(phys.as_mut_ptr::<PageTable>());
    *slot = PageTableEntry::new(phys, flags);
    Ok(phys)
}
