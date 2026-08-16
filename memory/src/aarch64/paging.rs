//! aarch64 VMSAv8-64 page-table types and helpers.
//!
//! Spec: `memory/specification/spec.md`. aarch64 uses 64-bit descriptors
//! in a 4-level walk (L0-L3) for 4 KiB pages.

use core::ptr;

use crate::PhysAddr;

#[cfg(feature = "kernel-test")]
static PUBLISH_BARRIER_SEQUENCES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static TLBI_BARRIER_SEQUENCES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Test-only counters for proving multi-leaf helpers amortise architecture
/// barrier sequences. Production builds contain neither counter nor update.
#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __batch_barrier_counts_for_test() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    (
        PUBLISH_BARRIER_SEQUENCES.load(Ordering::Relaxed),
        TLBI_BARRIER_SEQUENCES.load(Ordering::Relaxed),
    )
}

/// A single 64-bit descriptor.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PTE({:#018x})", self.0)
    }
}

/// Bits in a descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PtFlags(u64);

impl PtFlags {
    pub const VALID: Self = Self(1 << 0);
    /// Bit 1 is 1 for Table (L0-L2) or Page (L3), 0 for Block (L1-L2).
    pub const TYPE_TABLE: Self = Self(1 << 1);
    pub const TYPE_PAGE: Self = Self(1 << 1);

    /// Access Permissions: 00=RW EL1, 01=RW EL1/EL0, 10=RO EL1, 11=RO EL1/EL0.
    pub const AP_RW_EL1: Self = Self(0b00 << 6);
    pub const AP_RW_EL0: Self = Self(0b01 << 6);
    pub const AP_RO_EL1: Self = Self(0b10 << 6);
    pub const AP_RO_EL0: Self = Self(0b11 << 6);

    /// Shareability: 10=Outer, 11=Inner.
    pub const SH_INNER: Self = Self(0b11 << 8);

    /// Access Flag: must be 1 to avoid Access Flag faults.
    pub const AF: Self = Self(1 << 10);

    /// MAIR attribute index (bits 4:2).
    pub const ATTR_NORMAL: Self = Self(0 << 2); // Index 0 in MAIR
    pub const ATTR_TAGGED: Self = Self(1 << 2); // Index 1 in MAIR
    pub const ATTR_DEVICE: Self = Self(2 << 2); // Index 2 in MAIR

    /// Execute-never bits.
    pub const UXN: Self = Self(1 << 54);
    pub const PXN: Self = Self(1 << 53);

    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl core::ops::BitOr for PtFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn new(addr: PhysAddr, flags: PtFlags) -> Self {
        // [47:12] is the physical address.
        Self((addr.raw() & 0x0000_FFFF_FFFF_F000) | flags.bits())
    }

    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 & 1 == 1
    }
    #[inline]
    pub const fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x0000_FFFF_FFFF_F000)
    }

    /// Raw 64-bit descriptor.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Rebuild a descriptor from a raw 64-bit value.
    ///
    /// The counterpart of [`PageTableEntry::raw`], for callers that
    /// read-modify-write a live leaf in place — permission flips (`bpf_text`'s
    /// RW→RX seal clears `PXN` and rewrites `AP`) rather than fresh mappings,
    /// where the address bits and descriptor type must survive untouched.
    #[inline]
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }
}

/// 4 KiB / 512 entries.
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl core::fmt::Debug for PageTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let present = self.entries.iter().filter(|e| e.is_valid()).count();
        f.debug_struct("PageTable")
            .field("present_entries", &present)
            .finish_non_exhaustive()
    }
}

impl PageTable {
    pub fn zero_at(ptr: *mut PageTable) {
        // SAFETY: `ptr` is a `*mut PageTable` the caller guarantees points
        // at owned, writable storage for a full `PageTable`; the byte count
        // equals `size_of::<PageTable>()` so the write stays in bounds, and
        // `PageTable` (all-zero `PageTableEntry`s) is valid when zeroed.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<PageTable>());
        }
    }
}

/// Write a value to physical memory using identity-mapped access.
///
/// # Safety
/// `phys` must be the start of writable storage of at least
/// `size_of::<T>()` bytes that is identity-mapped (kernel-window
/// reachable) and aligned for `T`; no other CPU may be reading or
/// writing it concurrently.
pub unsafe fn write_identity<T>(phys: PhysAddr, value: T) {
    // SAFETY: per the fn contract `phys` is identity-mapped writable
    // storage aligned for `T`, so `kernel_mut_ptr::<T>()` is a valid,
    // aligned destination for a single `T` volatile write.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        ptr::write_volatile(phys.kernel_mut_ptr::<T>(), value);
    }
}

use crate::VirtAddr;

/// Read the current TTBR0_EL1 (low-half / user) translation base.
///
/// # Safety
/// `MRS` to a system register at EL1 is always legal.
pub unsafe fn read_ttbr0_el1() -> PhysAddr {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: register read at EL1 is defined.
    unsafe {
        asm!(
            "mrs {v}, ttbr0_el1",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    // Low bits (ASID / CnP) are not part of the base; the BADDR
    // field lives in [47:1] — mask to page boundary.
    PhysAddr::new(v & 0x0000_FFFF_FFFF_F000)
}

/// Read TTBR1_EL1 (high-half / kernel).
///
/// # Safety
/// `MRS` from a system register at EL1 is always legal; this fn only
/// reads `TTBR1_EL1` and has no other precondition.
pub unsafe fn read_ttbr1_el1() -> PhysAddr {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: register read at EL1 is defined.
    unsafe {
        asm!(
            "mrs {v}, ttbr1_el1",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    PhysAddr::new(v & 0x0000_FFFF_FFFF_F000)
}

/// Install a fresh TTBR0_EL1. A `DSB ISH; ISB` pair ensures the
/// translation change is observable to later instructions.
///
/// # Safety
/// `root` must point at a valid root table for the low half
/// (user space). Installing garbage kills the low-half mappings
/// immediately, which takes down anything the kernel accesses
/// through identity/user virt — today the NARF kernel runs in the
/// high half (TTBR1) so swapping TTBR0 is safe from the kernel's
/// perspective.
pub unsafe fn write_ttbr0_el1(root: PhysAddr) {
    // SAFETY: forwarded contract; ASID 0 selects the flushing fallback.
    unsafe { write_ttbr0_el1_asid(root, 0) };
}

/// Install `root` in TTBR0_EL1 under a lifetime-scoped process ASID.
///
/// A nonzero ASID preserves cached translations belonging to other address
/// spaces. ASID 0 is the exhaustion/bootstrap fallback and performs a local
/// full EL1 invalidation whenever the root changes. Reinstalling the exact
/// `(root, ASID)` pair is a no-op, which avoids duplicate work when both the
/// scheduler and the user-task wrapper activate the same address space.
///
/// # Safety
/// `root` must remain a valid low-half root for every CPU that can execute
/// with `asid`. A nonzero `asid` must be owned exclusively by this root until
/// a system-wide tag invalidation completes.
pub(crate) unsafe fn write_ttbr0_el1_asid(root: PhysAddr, asid: u16) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    let next = (root.raw() & 0x0000_FFFF_FFFF_F000) | ((asid as u64) << 48);
    let current: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TTBR0_EL1 is readable at EL1 and has no memory side effects.
    unsafe {
        asm!(
            "mrs {current}, ttbr0_el1",
            current = out(reg) current,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    if current == next {
        return;
    }

    compiler_fence(Ordering::SeqCst);
    if asid == 0 {
        // SAFETY: ASID 0 may have described a different root on this CPU, so
        // switching it requires invalidating every local EL1 translation.
        unsafe {
            asm!(
                "dsb nsh",
                "msr ttbr0_el1, {next}",
                "isb",
                "tlbi vmalle1",
                "dsb nsh",
                "isb",
                next = in(reg) next,
                options(nostack, preserves_flags),
            );
        }
    } else {
        // SAFETY: the caller guarantees that this ASID is exclusive to `root`.
        // The pre-write DSB completes prior translation-table writes and the
        // ISB makes the new translation context effective before later access.
        unsafe {
            asm!(
                "dsb ish",
                "msr ttbr0_el1, {next}",
                "isb",
                next = in(reg) next,
                options(nostack, preserves_flags),
            );
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Make a freshly-written translation-table descriptor visible to the table
/// walker before the caller touches the VA it describes.
///
/// The architecture does not guarantee that a normal store to a page-table
/// entry is observed by the walker in program order: the walk is a separate
/// observer, so the descriptor write needs a `DSB ISHST` to be ordered ahead of
/// any subsequent access, and an `ISB` before an instruction fetch through the
/// new mapping can be relied on.
///
/// **This was missing from every `map_*` path** while `unmap_4kb` twelve lines
/// below correctly issued `dsb ishst; tlbi vaale1is; dsb ish; isb`. Callers
/// routinely map a page and write through the returned VA immediately —
/// `bpf_arena`'s populate does exactly that — so on real silicon the access
/// could be reordered ahead of the descriptor becoming visible and take a
/// spurious translation fault. QEMU's TCG walker re-reads the tables on every
/// access and so never reproduces it, which is why the boot smokes stayed green;
/// the justification here is the architecture, not the emulator.
///
/// No TLB maintenance: these paths install a mapping where the leaf was
/// **invalid**, and there is no stale valid entry to evict. Changing a live
/// valid entry is break-before-make and belongs with the caller that does it
/// (see `unmap_4kb`, and `bpf_text::seal`'s permission flip).
///
/// # Safety
/// `DSB`/`ISB` at EL1 are unconditional; the caller must have completed the
/// descriptor write before calling.
#[inline]
unsafe fn publish_table_write() {
    use core::sync::atomic::{compiler_fence, Ordering};
    compiler_fence(Ordering::SeqCst);
    #[cfg(feature = "kernel-test")]
    PUBLISH_BARRIER_SEQUENCES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: barriers at EL1 are always legal and have no operands.
    unsafe {
        core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate a single virtual address for every ASID via
/// `TLBI VAAE1IS, xN` with the required barrier dance.
///
/// # The `IS` is load-bearing
///
/// This used to issue `tlbi vae1` — the **non-shareable** form, which
/// invalidates on the issuing PE only. Every caller is mutating a *kernel-half*
/// (TTBR1) mapping, which every CPU shares, so a local-only invalidation leaves
/// peer CPUs holding the stale translation. That is a plain SMP correctness bug,
/// and it was reachable in several shapes:
///
///   * `bpf_text::seal` flips JIT text from `AP_RW | PXN` to `AP_RO`, PXN
///     clear. A peer CPU keeping the pre-flip leaf sees **PXN still set** (so an
///     instruction fetch at the program entry faults at a PC with no extable
///     entry — fatal by design) and **AP=RW** (so the W^X flip bought nothing
///     on that CPU).
///   * `unmap_2mb` / `unmap_1gb` / `bpf_text::unmap_pack` return the frame to
///     the hugepage pool while a peer CPU can still hold an **executable**
///     translation onto it — a stale RX window onto recycled memory. The
///     reclaim path's note that "its VA is never reissued, so a stale TLB entry
///     cannot alias a later mapping" was wrong in the direction that matters:
///     the *frame* is reissued, not the VA.
///
/// The tree already knew the difference — `unmap_4kb` uses an
/// inner-shareable invalidation, and `ioremap`'s module doc explicitly noted
/// that the old `vae1`
/// "covers the local CPU" while assuming a separate IPI paired with it. Nothing
/// issued that IPI for these paths.
///
/// `vaae1is` broadcasts to the whole inner-shareable domain and covers every
/// ASID. The all-ASID form is required because callers mutate both shared
/// TTBR1 mappings and arbitrary process TTBR0 roots while another ASID may be
/// active; encoding ASID 0 would leave nonzero process translations stale.
///
/// # Safety
/// `TLBI`/`DSB`/`ISB` at EL1 are unconditional, but dropping a stale
/// TLB entry only yields a coherent address space when `virt`'s
/// page-table entry has already been updated; the caller must order
/// the descriptor write before this call.
pub unsafe fn tlb_invalidate_va_all_asids_inner_shareable(virt: VirtAddr) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI at EL1 is always legal; the VA field is
    // bits [43:0] of the operand (shifted-down by 12).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {a}",
            "dsb ish",
            "isb",
            a = in(reg) (virt.as_u64() >> 12),
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate a contiguous 4 KiB run for every ASID with one barrier pair.
///
/// The architecture still receives one last-level TLBI operand per page, but
/// the expensive `DSB ISHST` / `DSB ISH` / `ISB` sequence brackets the whole
/// transaction instead of every leaf. The caller must have cleared all leaves
/// before invoking this helper.
unsafe fn tlb_invalidate_4kb_range_all_asids_inner_shareable(base: VirtAddr, pages: u64) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    if pages == 0 {
        return;
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(feature = "kernel-test")]
    TLBI_BARRIER_SEQUENCES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: EL1 barrier and TLBI operations are unconditional. VAs are
    // page-aligned by the caller and encoded shifted down by 12.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
    for page in 0..pages {
        let va_page = (base.as_u64() >> 12) + page;
        unsafe {
            asm!(
                "tlbi vaale1is, {va}",
                va = in(reg) va_page,
                options(nostack, preserves_flags),
            );
        }
    }
    unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    compiler_fence(Ordering::SeqCst);
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors from `new_user_ttbr0` and related primitives.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageTableAllocError {
    NoFrame,
}

/// Errors from `map_4kb`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    NonCanonical,
    UnalignedVirt,
    UnalignedPhys,
    AlreadyMapped,
    EncounteredBlock,
    NoFrame,
}

// ── Allocation ──────────────────────────────────────────────────────

/// Allocate a fresh zeroed root for a user-mode address space.
/// aarch64's split translation (TTBR0 low, TTBR1 high) means the
/// low-half root starts empty — the kernel lives in TTBR1 and is
/// unaffected by whatever we install in TTBR0.
///
/// # Safety
/// Caller must run with the MMU up and the frame allocator's
/// output identity-mapped (standard NARF boot state).
pub unsafe fn new_user_ttbr0() -> Result<PhysAddr, PageTableAllocError> {
    let frame = crate::frame::alloc_frame().map_err(|_| PageTableAllocError::NoFrame)?;
    let phys = frame.start_address();
    // SAFETY: frame is identity-mapped per the allocator's
    // contract; 4 KiB write is aligned.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        ptr::write_bytes(
            phys.kernel_mut_ptr::<u8>(),
            0,
            core::mem::size_of::<PageTable>(),
        );
    }
    Ok(phys)
}

// ── 4 KiB mapping walk ──────────────────────────────────────────────

/// Indices into the 4-level walk for a 4 KiB page.
struct WalkIndices {
    l0: usize,
    l1: usize,
    l2: usize,
    l3: usize,
}

impl WalkIndices {
    fn from_virt(v: VirtAddr) -> Self {
        let a = v.as_u64();
        Self {
            l0: ((a >> 39) & 0x1FF) as usize,
            l1: ((a >> 30) & 0x1FF) as usize,
            l2: ((a >> 21) & 0x1FF) as usize,
            l3: ((a >> 12) & 0x1FF) as usize,
        }
    }
}

// ── Per-page-table-root mutation lock ──────────────────────────────
//
// Threads sharing one TTBR0 may fault, mprotect, and unmap concurrently on
// different CPUs. In particular, two `ensure_next_table` calls racing on the
// same empty descriptor can otherwise publish different child tables, leaking
// one and orphaning any leaves installed through it. Shard by root page so
// unrelated address spaces still mutate in parallel, matching x86_64.
const PT_LOCK_SHARDS: usize = 64;

#[repr(align(64))]
struct PtLock(narf_lib::sync::IrqSafeSpinLock<()>);

impl PtLock {
    const fn new() -> Self {
        Self(narf_lib::sync::IrqSafeSpinLock::new(()))
    }
}

static PT_LOCKS: [PtLock; PT_LOCK_SHARDS] = [const { PtLock::new() }; PT_LOCK_SHARDS];

#[inline]
pub(crate) fn pt_lock_for(root: PhysAddr) -> &'static narf_lib::sync::IrqSafeSpinLock<()> {
    &PT_LOCKS[((root.raw() >> 12) as usize) & (PT_LOCK_SHARDS - 1)].0
}

/// Tear down every subtree of a user-mode TTBR0 root and return
/// the root frame itself to the allocator.
///
/// AArch64 user TTBR0 starts empty (the kernel lives in TTBR1 per
/// `new_user_ttbr0`'s comment) so every present entry in the root
/// is user-private — no kernel-half to skip. Walks all four levels
/// (L0 → L1 → L2 → L3), freeing intermediate page-table frames on
/// the way back up. Leaf L3 entries (data pages) are NOT freed
/// here; the `AddressSpace::Drop` path arranges for
/// `unmap_region_pages` to release every region's data frames first
/// so this routine only reclaims the page-table pages themselves.
///
/// Reference: ARM ARM (DDI 0487 §D8) translation-table descriptor
/// formats — bit 0 = VALID, bit 1 = TYPE (1 = table at L0/L1/L2,
/// page at L3; 0 = block stop). Block entries at L1/L2 (1 GiB /
/// 2 MiB pages) are skipped.
///
/// # Safety
/// - `root` must be identity-reachable (allocator contract).
/// - All data-page leaves must already have been released.
/// - No CPU may be using `root` as its active TTBR0.
pub unsafe fn free_user_ttbr0_tree(root: PhysAddr) {
    use crate::frame::{free_frame, PhysFrame};
    if root.raw() == 0 {
        return;
    }
    let _guard = pt_lock_for(root).lock();
    /// True if this entry is present AND a TABLE (not a block).
    /// At L0 every present entry is a table per ARM ARM. At L1/L2
    /// a block entry stops the walk and must be skipped.
    fn is_table_descriptor(e: PageTableEntry) -> bool {
        e.is_valid() && (e.0 & 0b10) != 0
    }
    // SAFETY: identity-reachable per caller contract.
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    for l0_idx in 0..512usize {
        let l0e = l0.entries[l0_idx];
        if !is_table_descriptor(l0e) {
            continue;
        }
        let l1_pa = l0e.addr();
        // SAFETY: same.
        let l1 = unsafe { &mut *l1_pa.kernel_mut_ptr::<PageTable>() };
        for l1_idx in 0..512usize {
            let l1e = l1.entries[l1_idx];
            if !is_table_descriptor(l1e) {
                continue;
            }
            let l2_pa = l1e.addr();
            // SAFETY: same.
            let l2 = unsafe { &mut *l2_pa.kernel_mut_ptr::<PageTable>() };
            for l2_idx in 0..512usize {
                let l2e = l2.entries[l2_idx];
                if !is_table_descriptor(l2e) {
                    continue;
                }
                // L3 — leaf-level table; data frames already
                // released by `unmap_region_pages`. Reclaim the
                // table page itself.
                free_frame(PhysFrame::new(l2e.addr()));
            }
            free_frame(PhysFrame::new(l2_pa));
        }
        free_frame(PhysFrame::new(l1_pa));
        l0.entries[l0_idx] = PageTableEntry::EMPTY;
    }
    free_frame(PhysFrame::new(root));
}

/// aarch64 "canonical": top 16 bits are either all-0 (low half /
/// user) or all-1 (high half / kernel).
fn is_canonical(v: VirtAddr) -> bool {
    let top = v.as_u64() >> 48;
    top == 0x0000 || top == 0xFFFF
}

/// Install a next-level table descriptor at `entry`, allocating a
/// fresh frame if the entry is currently empty. Returns the phys
/// address of the next-level table.
unsafe fn ensure_next_table(entry: &mut PageTableEntry) -> Result<PhysAddr, MapError> {
    if entry.is_valid() {
        // Must be a TABLE (bit 1 = 1) — BLOCK entries stop the walk.
        if (entry.0 & 0b11) != 0b11 {
            return Err(MapError::EncounteredBlock);
        }
        return Ok(entry.addr());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| MapError::NoFrame)?;
    let next = frame.start_address();
    // Zero the new table.
    // SAFETY: identity-mapped frame.
    unsafe {
        ptr::write_bytes(
            next.kernel_mut_ptr::<u8>(),
            0,
            core::mem::size_of::<PageTable>(),
        );
    }
    // Table descriptor: low bits 0b11 = valid + table.
    *entry = PageTableEntry(next.raw() | 0b11);
    Ok(next)
}

/// Map one naturally aligned 2 MiB L2 block.
///
/// # Safety
/// Same root/identity-map contract as [`map_4kb`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub unsafe fn map_2mb(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    let _guard = pt_lock_for(root).lock();
    unsafe { map_2mb_locked(root, virt, phys, flags) }
}

/// [`map_2mb`] with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`map_2mb`]'s contract and hold [`pt_lock_for`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) unsafe fn map_2mb_locked(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    const SIZE: u64 = 2 * 1024 * 1024;
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedVirt);
    }
    if phys.raw() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedPhys);
    }
    let idx = WalkIndices::from_virt(virt);
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    let l1_phys = unsafe { ensure_next_table(&mut l0.entries[idx.l0])? };
    let l1 = unsafe { &mut *l1_phys.kernel_mut_ptr::<PageTable>() };
    let l2_phys = unsafe { ensure_next_table(&mut l1.entries[idx.l1])? };
    let l2 = unsafe { &mut *l2_phys.kernel_mut_ptr::<PageTable>() };
    if l2.entries[idx.l2].is_valid() {
        return Err(MapError::AlreadyMapped);
    }
    let base = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_NORMAL;
    l2.entries[idx.l2] = PageTableEntry::new(phys, base | flags);
    // SAFETY: publish the descriptor before returning — see `publish_table_write`.
    unsafe { publish_table_write() };
    unsafe { tlb_invalidate_va_all_asids_inner_shareable(virt) };
    Ok(())
}

/// Map one naturally aligned 1 GiB L1 block.
///
/// # Safety
/// Same root/identity-map contract as [`map_4kb`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub unsafe fn map_1gb(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    let _guard = pt_lock_for(root).lock();
    unsafe { map_1gb_locked(root, virt, phys, flags) }
}

/// [`map_1gb`] with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`map_1gb`]'s contract and hold [`pt_lock_for`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) unsafe fn map_1gb_locked(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    const SIZE: u64 = 1024 * 1024 * 1024;
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedVirt);
    }
    if phys.raw() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedPhys);
    }
    let idx = WalkIndices::from_virt(virt);
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    let l1_phys = unsafe { ensure_next_table(&mut l0.entries[idx.l0])? };
    let l1 = unsafe { &mut *l1_phys.kernel_mut_ptr::<PageTable>() };
    if l1.entries[idx.l1].is_valid() {
        return Err(MapError::AlreadyMapped);
    }
    let base = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_NORMAL;
    l1.entries[idx.l1] = PageTableEntry::new(phys, base | flags);
    // SAFETY: publish the descriptor before returning — see `publish_table_write`.
    unsafe { publish_table_write() };
    unsafe { tlb_invalidate_va_all_asids_inner_shareable(virt) };
    Ok(())
}

/// Remove a 2 MiB L2 block and return its physical base.
///
/// # Safety
/// Same root/identity-map contract as [`unmap_4kb`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub unsafe fn unmap_2mb(root: PhysAddr, virt: VirtAddr) -> Result<PhysAddr, MapError> {
    let _guard = pt_lock_for(root).lock();
    unsafe { unmap_2mb_locked(root, virt) }
}

/// [`unmap_2mb`] with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`unmap_2mb`]'s contract and hold [`pt_lock_for`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) unsafe fn unmap_2mb_locked(
    root: PhysAddr,
    virt: VirtAddr,
) -> Result<PhysAddr, MapError> {
    const SIZE: u64 = 2 * 1024 * 1024;
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedVirt);
    }
    let idx = WalkIndices::from_virt(virt);
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    let l0e = l0.entries[idx.l0];
    if !l0e.is_valid() || (l0e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    let l1 = unsafe { &mut *l0e.addr().kernel_mut_ptr::<PageTable>() };
    let l1e = l1.entries[idx.l1];
    if !l1e.is_valid() || (l1e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    let l2 = unsafe { &mut *l1e.addr().kernel_mut_ptr::<PageTable>() };
    let leaf = l2.entries[idx.l2];
    if !leaf.is_valid() || (leaf.0 & 0b10) != 0 {
        return Err(MapError::AlreadyMapped);
    }
    l2.entries[idx.l2] = PageTableEntry::EMPTY;
    unsafe { tlb_invalidate_va_all_asids_inner_shareable(virt) };
    Ok(leaf.addr())
}

/// Remove a 1 GiB L1 block and return its physical base.
///
/// # Safety
/// Same root/identity-map contract as [`unmap_4kb`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub unsafe fn unmap_1gb(root: PhysAddr, virt: VirtAddr) -> Result<PhysAddr, MapError> {
    let _guard = pt_lock_for(root).lock();
    unsafe { unmap_1gb_locked(root, virt) }
}

/// [`unmap_1gb`] with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`unmap_1gb`]'s contract and hold [`pt_lock_for`].
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) unsafe fn unmap_1gb_locked(
    root: PhysAddr,
    virt: VirtAddr,
) -> Result<PhysAddr, MapError> {
    const SIZE: u64 = 1024 * 1024 * 1024;
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & (SIZE - 1) != 0 {
        return Err(MapError::UnalignedVirt);
    }
    let idx = WalkIndices::from_virt(virt);
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    let l0e = l0.entries[idx.l0];
    if !l0e.is_valid() || (l0e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    let l1 = unsafe { &mut *l0e.addr().kernel_mut_ptr::<PageTable>() };
    let leaf = l1.entries[idx.l1];
    if !leaf.is_valid() || (leaf.0 & 0b10) != 0 {
        return Err(MapError::AlreadyMapped);
    }
    l1.entries[idx.l1] = PageTableEntry::EMPTY;
    unsafe { tlb_invalidate_va_all_asids_inner_shareable(virt) };
    Ok(leaf.addr())
}

/// Map `virt` to `phys` at 4 KiB granularity under `root`.
///
/// # Safety
/// - `root` must point at a valid aarch64 root translation table
///   whose storage is identity-mapped in the currently-active
///   mappings.
/// - The root must remain live; concurrent mutation is serialized by a
///   root-sharded IRQ-safe lock.
pub unsafe fn map_4kb(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
) -> Result<(), MapError> {
    let _guard = pt_lock_for(root).lock();
    // SAFETY: the public contract is forwarded while the root lock is held.
    unsafe { map_4kb_locked(root, virt, phys, flags, true) }
}

/// Install one leaf with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`map_4kb`]'s contract and hold [`pt_lock_for`].
unsafe fn map_4kb_locked(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
    publish: bool,
) -> Result<(), MapError> {
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & 0xFFF != 0 {
        return Err(MapError::UnalignedVirt);
    }
    if phys.raw() & 0xFFF != 0 {
        return Err(MapError::UnalignedPhys);
    }

    let idx = WalkIndices::from_virt(virt);

    // SAFETY: `root` is identity-mapped per caller contract.
    let l0 = unsafe { &mut *(root.kernel_mut_ptr::<PageTable>()) };
    // SAFETY: `&mut l0.entries[idx.l0]` borrows a live L0 entry of the
    // table just dereferenced; `ensure_next_table` only allocates an
    // identity-mapped frame and writes a table descriptor through it.
    // SAFETY: Valid memory or trusted environment
    let l1_phys = unsafe { ensure_next_table(&mut l0.entries[idx.l0])? };

    // SAFETY: `l1_phys` is the L1 table phys addr `ensure_next_table`
    // just returned — an identity-mapped, page-aligned `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l1 = unsafe { &mut *(l1_phys.kernel_mut_ptr::<PageTable>()) };
    // SAFETY: as above; borrows a live entry of the L1 table.
    let l2_phys = unsafe { ensure_next_table(&mut l1.entries[idx.l1])? };

    // SAFETY: `l2_phys` is the identity-mapped L2 table phys addr
    // returned by `ensure_next_table`.
    // SAFETY: Valid memory or trusted environment
    let l2 = unsafe { &mut *(l2_phys.kernel_mut_ptr::<PageTable>()) };
    // SAFETY: as above; borrows a live entry of the L2 table.
    let l3_phys = unsafe { ensure_next_table(&mut l2.entries[idx.l2])? };

    // SAFETY: `l3_phys` is the identity-mapped L3 table phys addr
    // returned by `ensure_next_table`.
    // SAFETY: Valid memory or trusted environment
    let l3 = unsafe { &mut *(l3_phys.kernel_mut_ptr::<PageTable>()) };
    if l3.entries[idx.l3].is_valid() {
        return Err(MapError::AlreadyMapped);
    }
    // L3 entry for a 4 KiB page: valid + page (low bits = 0b11),
    // AF must be set to avoid Access Flag faults on first touch,
    // inner-shareable + normal memory attr.
    let base = PtFlags::VALID
        | PtFlags::TYPE_PAGE
        | PtFlags::AF
        | PtFlags::SH_INNER
        | PtFlags::ATTR_NORMAL;
    l3.entries[idx.l3] = PageTableEntry::new(phys, base | flags);
    if publish {
        // SAFETY: publish the descriptor before returning — see
        // `publish_table_write`.
        unsafe { publish_table_write() };
    }
    Ok(())
}

/// Map scatter backing while taking the root mutation lock and descriptor
/// publication barrier once. Zero physical entries are lazy holes.
///
/// On failure, earlier leaves remain installed; transactional callers must
/// tear them down, matching the x86_64 helper's contract.
///
/// # Safety
/// Same live-root and identity-map contract as [`map_4kb`] for the complete
/// range and every non-zero physical entry.
pub unsafe fn map_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    mut flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError> {
    if !is_canonical(base) || base.as_u64() & 0xFFF != 0 {
        return Err(if is_canonical(base) {
            MapError::UnalignedVirt
        } else {
            MapError::NonCanonical
        });
    }
    let span = (backing.len() as u64)
        .checked_mul(4096)
        .ok_or(MapError::NonCanonical)?;
    let end = base
        .as_u64()
        .checked_add(span)
        .ok_or(MapError::NonCanonical)?;
    if !backing.is_empty() {
        let last = VirtAddr::new(end - 1);
        if !is_canonical(last) || ((base.as_u64() ^ last.as_u64()) & (1 << 47)) != 0 {
            return Err(MapError::NonCanonical);
        }
    }
    if backing
        .iter()
        .any(|phys| phys.raw() != 0 && phys.raw() & 0xFFF != 0)
    {
        return Err(MapError::UnalignedPhys);
    }

    let _guard = pt_lock_for(root).lock();
    let mut result = Ok(());
    let mut attempted = false;
    for (index, phys) in backing.iter().copied().enumerate() {
        if phys.raw() == 0 {
            continue;
        }
        attempted = true;
        let virt = VirtAddr::new(base.as_u64() + index as u64 * 4096);
        // SAFETY: complete input validation and the root lock are above.
        if let Err(error) =
            unsafe { map_4kb_locked(root, virt, phys, flags_for(index, phys), false) }
        {
            result = Err(error);
            break;
        }
    }
    if attempted {
        // SAFETY: every descriptor write (including an intermediate table
        // created before a later error) precedes this batch publication.
        unsafe { publish_table_write() };
    }
    result
}

/// Rewrite a scatter-backed 4 KiB run with one break-before-make transaction.
///
/// Every old leaf in the virtual span is cleared first, then one inner-
/// shareable TLBI sequence invalidates the complete run before any replacement
/// descriptor is installed. Non-zero backing entries are subsequently mapped
/// under the same root lock and published with one descriptor barrier. Zero
/// entries remain lazy holes.
///
/// This is the batched permission-rewrite primitive used by `mprotect` and the
/// parent-side COW write-protect pass after `fork`. On failure, descriptors
/// already installed during the make phase remain present, matching
/// [`map_4kb_scatter_range`]'s partial-progress contract.
///
/// # Safety
/// Same live-root and identity-map contract as [`map_4kb_scatter_range`]. The
/// caller must keep every non-zero backing frame live through the complete
/// break-before-make transaction.
pub unsafe fn rewrite_4kb_scatter_range(
    root: PhysAddr,
    base: VirtAddr,
    backing: &[PhysAddr],
    mut flags_for: impl FnMut(usize, PhysAddr) -> PtFlags,
) -> Result<(), MapError> {
    if !is_canonical(base) || base.as_u64() & 0xFFF != 0 {
        return Err(if is_canonical(base) {
            MapError::UnalignedVirt
        } else {
            MapError::NonCanonical
        });
    }
    let pages = backing.len() as u64;
    let span = pages.checked_mul(4096).ok_or(MapError::NonCanonical)?;
    let end = base
        .as_u64()
        .checked_add(span)
        .ok_or(MapError::NonCanonical)?;
    if pages != 0 {
        let last = VirtAddr::new(end - 1);
        if !is_canonical(last) || ((base.as_u64() ^ last.as_u64()) & (1 << 47)) != 0 {
            return Err(MapError::NonCanonical);
        }
    }
    if backing
        .iter()
        .any(|phys| phys.raw() != 0 && phys.raw() & 0xFFF != 0)
    {
        return Err(MapError::UnalignedPhys);
    }

    let _guard = pt_lock_for(root).lock();
    let mut removed = 0;
    for page in 0..pages {
        let virt = VirtAddr::new(base.as_u64() + page * 4096);
        // SAFETY: the complete range was validated and the root lock remains
        // held for both halves of break-before-make.
        match unsafe { unmap_4kb_locked(root, virt, false) } {
            Ok(_) => removed += 1,
            Err(MapError::AlreadyMapped) => {}
            Err(error) => {
                if removed != 0 {
                    // SAFETY: all descriptors cleared so far precede this
                    // invalidation; covering untouched suffix pages is benign.
                    unsafe { tlb_invalidate_4kb_range_all_asids_inner_shareable(base, pages) };
                }
                return Err(error);
            }
        }
    }
    if removed != 0 {
        // SAFETY: all old valid leaves are now clear. This is the break half;
        // the helper's trailing DSB/ISB completes it before any make store.
        unsafe { tlb_invalidate_4kb_range_all_asids_inner_shareable(base, pages) };
    }

    let mut attempted = false;
    let mut result = Ok(());
    for (index, phys) in backing.iter().copied().enumerate() {
        if phys.raw() == 0 {
            continue;
        }
        attempted = true;
        let virt = VirtAddr::new(base.as_u64() + index as u64 * 4096);
        // SAFETY: validated backing stays live and the root lock is held.
        if let Err(error) =
            unsafe { map_4kb_locked(root, virt, phys, flags_for(index, phys), false) }
        {
            result = Err(error);
            break;
        }
    }
    if attempted {
        // SAFETY: publish every replacement descriptor (and any intermediate
        // table created before an error) as the make half of the transaction.
        unsafe { publish_table_write() };
    }
    result
}

/// Tear down a 4 KiB mapping at `virt` under `root`. Returns the
/// physical address that was mapped, or `MapError::AlreadyMapped`
/// if no leaf entry was present (overloaded for symmetry with
/// the x86_64 path; the meaning is "nothing was mapped here").
/// Intermediate tables are left intact — the eventual
/// refcounted-table sweep will reap them.
///
/// # Safety
/// Same identity-mapping precondition as `map_4kb`.
pub unsafe fn unmap_4kb(root: PhysAddr, virt: VirtAddr) -> Result<PhysAddr, MapError> {
    let _guard = pt_lock_for(root).lock();
    // SAFETY: the public contract is forwarded while the root lock is held.
    unsafe { unmap_4kb_locked(root, virt, true) }
}

/// Remove one leaf with this root's mutation lock already held.
///
/// # Safety
/// The caller must uphold [`unmap_4kb`]'s contract and hold [`pt_lock_for`].
unsafe fn unmap_4kb_locked(
    root: PhysAddr,
    virt: VirtAddr,
    invalidate: bool,
) -> Result<PhysAddr, MapError> {
    if !is_canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if virt.as_u64() & 0xFFF != 0 {
        return Err(MapError::UnalignedVirt);
    }
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: `root` is identity-mapped per caller contract.
    let l0 = unsafe { &mut *(root.kernel_mut_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    // SAFETY: `e` was just checked to be a valid TABLE descriptor
    // (low bits `0b11`), so `e.addr()` is the identity-mapped phys
    // addr of the next-level `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l1 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    // SAFETY: `e` is a verified L1 TABLE descriptor; `e.addr()` is the
    // identity-mapped L2 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l2 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    // SAFETY: `e` is a verified L2 TABLE descriptor; `e.addr()` is the
    // identity-mapped L3 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l3 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let leaf = l3.entries[idx.l3];
    if !leaf.is_valid() {
        return Err(MapError::AlreadyMapped);
    }
    let prev_phys = leaf.addr();
    l3.entries[idx.l3] = PageTableEntry::EMPTY;
    if invalidate {
        // SAFETY: the leaf is already clear and `virt` is page aligned.
        unsafe { tlb_invalidate_4kb_range_all_asids_inner_shareable(virt, 1) };
    }
    Ok(prev_phys)
}

/// Tear down a contiguous run under one root lock and one TLBI barrier pair.
/// Missing leaves are benign; the returned count includes only leaves that
/// were present and cleared.
///
/// # Safety
/// Same live-root and identity-map contract as [`unmap_4kb`] for every page in
/// the range. The root must not be destroyed during the transaction.
pub unsafe fn unmap_4kb_range(root: PhysAddr, base: VirtAddr, pages: u64) -> Result<u64, MapError> {
    if !is_canonical(base) {
        return Err(MapError::NonCanonical);
    }
    if base.as_u64() & 0xFFF != 0 {
        return Err(MapError::UnalignedVirt);
    }
    let span = pages.checked_mul(4096).ok_or(MapError::NonCanonical)?;
    let end = base
        .as_u64()
        .checked_add(span)
        .ok_or(MapError::NonCanonical)?;
    if pages != 0 {
        let last = VirtAddr::new(end - 1);
        if !is_canonical(last) || ((base.as_u64() ^ last.as_u64()) & (1 << 47)) != 0 {
            return Err(MapError::NonCanonical);
        }
    }

    let _guard = pt_lock_for(root).lock();
    let mut removed = 0;
    let mut result = Ok(());
    for page in 0..pages {
        let virt = VirtAddr::new(base.as_u64() + page * 4096);
        // SAFETY: the complete range was validated and the root lock remains
        // held for this walk.
        match unsafe { unmap_4kb_locked(root, virt, false) } {
            Ok(_) => removed += 1,
            Err(MapError::AlreadyMapped) => {}
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    if removed != 0 {
        // SAFETY: every present leaf in the range is already clear.
        unsafe { tlb_invalidate_4kb_range_all_asids_inner_shareable(base, pages) };
    }
    result.map(|()| removed)
}

/// Walk the table at `root` and return the physical address mapped
/// at `virt`, or `None` if unmapped.
///
/// # Safety
/// `root` must point at a valid aarch64 root translation table whose
/// storage (and that of every table it transitively references) is
/// identity-mapped in the currently-active mappings; no other CPU may
/// concurrently mutate the walked tables.
pub unsafe fn translate(root: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: root must be identity-mapped per caller contract;
    // callers hold this invariant.
    // SAFETY: Valid memory or trusted environment
    let l0 = unsafe { &*(root.kernel_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    // SAFETY: the L0 `e` was just checked to be a valid TABLE
    // descriptor (`0b11`), so `e.addr()` is the identity-mapped L1
    // `PageTable`; we only read through the shared reference.
    // SAFETY: Valid memory or trusted environment
    let l1 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        /* block at L1 — 1 GiB */
        return Some(PhysAddr::new(
            e.addr().raw() + (virt.as_u64() & ((1 << 30) - 1)),
        ));
    }

    // SAFETY: `e` is a valid, non-block (`0b11`) L1 TABLE descriptor,
    // so `e.addr()` is the identity-mapped L2 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l2 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        /* block at L2 — 2 MiB */
        return Some(PhysAddr::new(
            e.addr().raw() + (virt.as_u64() & ((1 << 21) - 1)),
        ));
    }

    // SAFETY: `e` is a valid, non-block (`0b11`) L2 TABLE descriptor,
    // so `e.addr()` is the identity-mapped L3 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l3 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l3.entries[idx.l3];
    if !e.is_valid() {
        return None;
    }
    Some(e.addr())
}

/// Flags of whichever descriptor actually maps `virt` — 1 GiB or 2 MiB block,
/// or 4 KiB page — together with that leaf's size in bytes.
///
/// [`flags_at`] returns `None` at a block descriptor, which makes it useless
/// for asking whether an address is executable: the kernel's own mappings are
/// blocks, so a `PXN` check built on `flags_at` silently passes on every
/// address it cannot see. The x86_64 twin is `x86_64::paging::leaf_flags_at`.
///
/// # Safety
/// Same contract as [`flags_at`].
pub unsafe fn leaf_flags_at(root: PhysAddr, virt: VirtAddr) -> Option<(PtFlags, u64)> {
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: `root` is the identity-mapped root `PageTable` per the contract.
    let l0 = unsafe { &*(root.kernel_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }
    // SAFETY: verified L0 TABLE descriptor.
    let l1 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        return Some((PtFlags(e.0 & !ADDR_MASK), 1 << 30));
    }
    // SAFETY: verified L1 TABLE descriptor.
    let l2 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        return Some((PtFlags(e.0 & !ADDR_MASK), 1 << 21));
    }
    // SAFETY: verified L2 TABLE descriptor.
    let l3 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l3.entries[idx.l3];
    if !e.is_valid() {
        return None;
    }
    Some((PtFlags(e.0 & !ADDR_MASK), 1 << 12))
}

/// Walk the table at `root` and return the flags for `virt`, or
/// `None` if unmapped.
///
/// # Safety
/// `root` must point at a valid aarch64 root translation table whose
/// storage (and that of every table it transitively references) is
/// identity-mapped in the currently-active mappings; no other CPU may
/// concurrently mutate the walked tables.
pub unsafe fn flags_at(root: PhysAddr, virt: VirtAddr) -> Option<PtFlags> {
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: `root` is the identity-mapped root `PageTable` per the
    // fn contract; we only read through the shared reference.
    // SAFETY: Valid memory or trusted environment
    let l0 = unsafe { &*(root.kernel_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    // SAFETY: the L0 `e` was just checked to be a valid TABLE
    // descriptor (`0b11`), so `e.addr()` is the identity-mapped L1
    // `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l1 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    // SAFETY: `e` is a verified L1 TABLE descriptor; `e.addr()` is the
    // identity-mapped L2 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l2 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    // SAFETY: `e` is a verified L2 TABLE descriptor; `e.addr()` is the
    // identity-mapped L3 `PageTable`.
    // SAFETY: Valid memory or trusted environment
    let l3 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l3.entries[idx.l3];
    if !e.is_valid() {
        return None;
    }
    // Strip the phys-addr bits; keep the flag bits.
    Some(PtFlags(e.0 & !0x0000_FFFF_FFFF_F000))
}
