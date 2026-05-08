//! aarch64 VMSAv8-64 page-table types and helpers.
//!
//! Spec: `memory/specification/spec.md`. aarch64 uses 64-bit descriptors
//! in a 4-level walk (L0-L3) for 4 KiB pages.

use core::ptr;

use crate::PhysAddr;

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
    pub const AP_RO_EL1: Self = Self(0b10 << 6);

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
        unsafe {
            ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<PageTable>());
        }
    }
}

/// Write a value to physical memory using identity-mapped access.
pub unsafe fn write_identity<T>(phys: PhysAddr, value: T) {
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
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    compiler_fence(Ordering::SeqCst);
    // SAFETY: `MSR TTBR0_EL1, xN` at EL1 is the architected way to
    // swap the low-half translation root; the ASID field in bits
    // [63:48] stays zero (single-ASID mode for Stage-4 structural).
    // Use the cheaper local `tlbi vmalle1` (current EL, NOT
    // inner-shareable broadcast) — every CPU executes its own
    // activate() before polling, so per-CPU TLB scoping suffices
    // and avoids the cross-core synchronisation cost.
    unsafe {
        asm!(
            "msr ttbr0_el1, {addr}",
            "dsb nsh",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            addr = in(reg) root.raw(),
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate a single virtual address from the TLB via
/// `TLBI VAE1, xN` with the required barrier dance.
pub unsafe fn tlb_invalidate_vae1(virt: VirtAddr) {
    use core::arch::asm;
    use core::sync::atomic::{compiler_fence, Ordering};

    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI at EL1 is always legal; the VA field is
    // bits [43:0] of the operand (shifted-down by 12).
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vae1, {a}",
            "dsb ish",
            "isb",
            a = in(reg) (virt.as_u64() >> 12),
            options(nostack, preserves_flags),
        );
    }
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
    unsafe {
        ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, core::mem::size_of::<PageTable>());
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
        ptr::write_bytes(next.kernel_mut_ptr::<u8>(), 0, core::mem::size_of::<PageTable>());
    }
    // Table descriptor: low bits 0b11 = valid + table.
    *entry = PageTableEntry(next.raw() | 0b11);
    Ok(next)
}

/// Map `virt` to `phys` at 4 KiB granularity under `root`.
///
/// # Safety
/// - `root` must point at a valid aarch64 root translation table
///   whose storage is identity-mapped in the currently-active
///   mappings.
/// - Concurrent modification from another CPU is UB.
pub unsafe fn map_4kb(
    root: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PtFlags,
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
    let l1_phys = unsafe { ensure_next_table(&mut l0.entries[idx.l0])? };

    let l1 = unsafe { &mut *(l1_phys.kernel_mut_ptr::<PageTable>()) };
    let l2_phys = unsafe { ensure_next_table(&mut l1.entries[idx.l1])? };

    let l2 = unsafe { &mut *(l2_phys.kernel_mut_ptr::<PageTable>()) };
    let l3_phys = unsafe { ensure_next_table(&mut l2.entries[idx.l2])? };

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
    Ok(())
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
    let l1 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    let l2 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return Err(MapError::AlreadyMapped);
    }
    let l3 = unsafe { &mut *(e.addr().kernel_mut_ptr::<PageTable>()) };
    let leaf = l3.entries[idx.l3];
    if !leaf.is_valid() {
        return Err(MapError::AlreadyMapped);
    }
    let prev_phys = leaf.addr();
    l3.entries[idx.l3] = PageTableEntry(0);
    // TLB invalidation for the page (VAE1IS — by VA at EL1
    // inner-shareable). Wrap in DSB to order the table mutation
    // before the TLB op, and ISB after to drain.
    let va_page = virt.as_u64() >> 12;
    // SAFETY: TLBI/DSB/ISB at EL1 are unconditional.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vale1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va_page,
            options(nostack, preserves_flags),
        );
    }
    Ok(prev_phys)
}

/// Walk the table at `root` and return the physical address mapped
/// at `virt`, or `None` if unmapped.
pub unsafe fn translate(root: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: root must be identity-mapped per caller contract;
    // callers hold this invariant.
    let l0 = unsafe { &*(root.kernel_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    let l1 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        /* block at L1 — 1 GiB */
        return None;
    }

    let l2 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() {
        return None;
    }
    if (e.0 & 0b11) != 0b11 {
        /* block at L2 — 2 MiB */
        return None;
    }

    let l3 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l3.entries[idx.l3];
    if !e.is_valid() {
        return None;
    }
    Some(e.addr())
}

/// Walk the table at `root` and return the flags for `virt`, or
/// `None` if unmapped.
pub unsafe fn flags_at(root: PhysAddr, virt: VirtAddr) -> Option<PtFlags> {
    let idx = WalkIndices::from_virt(virt);
    let l0 = unsafe { &*(root.kernel_ptr::<PageTable>()) };
    let e = l0.entries[idx.l0];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    let l1 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l1.entries[idx.l1];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    let l2 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l2.entries[idx.l2];
    if !e.is_valid() || (e.0 & 0b11) != 0b11 {
        return None;
    }

    let l3 = unsafe { &*(e.addr().kernel_ptr::<PageTable>()) };
    let e = l3.entries[idx.l3];
    if !e.is_valid() {
        return None;
    }
    // Strip the phys-addr bits; keep the flag bits.
    Some(PtFlags(e.0 & !0x0000_FFFF_FFFF_F000))
}
