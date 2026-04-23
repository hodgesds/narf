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
    pub const PRESENT:   Self = Self(1 <<  0);
    pub const WRITABLE:  Self = Self(1 <<  1);
    pub const USER:      Self = Self(1 <<  2);
    pub const WRITE_THROUGH: Self = Self(1 <<  3);
    pub const NO_CACHE:  Self = Self(1 <<  4);
    pub const ACCESSED:  Self = Self(1 <<  5);
    pub const DIRTY:     Self = Self(1 <<  6);
    /// On a PDPT / PD entry: "this is a huge page, not a pointer to the
    /// next-level table." On x86_64 a PS=1 PDPT entry maps 1 GiB; a
    /// PS=1 PD entry maps 2 MiB. Never set in a PML4 entry.
    pub const HUGE_PAGE: Self = Self(1 <<  7);
    pub const GLOBAL:    Self = Self(1 <<  8);
    /// Execute-disable bit (IA32_EFER.NXE must be set for this to be
    /// interpreted; without NXE the bit is reserved-zero).
    pub const NO_EXEC:   Self = Self(1 << 63);

    pub const EMPTY: Self = Self(0);

    #[inline] pub const fn bits(self) -> u64 { self.0 }
    #[inline] pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for PtFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for PtFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0 }
}

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn new(addr: PhysAddr, flags: PtFlags) -> Self {
        // Physical address must be 4 KiB-aligned: low 12 bits are flag
        // bits, not address bits.
        Self((addr.raw() & 0x000f_ffff_ffff_f000) | flags.bits())
    }

    #[inline] pub const fn is_present(self) -> bool { self.0 & 1 == 1 }
    #[inline] pub const fn flags(self) -> PtFlags { PtFlags(self.0 & 0xfff0_0000_0000_0fff) }

    /// Physical address of the mapped page / next-level table.
    #[inline] pub const fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000f_ffff_ffff_f000)
    }

    #[inline] pub const fn raw(self) -> u64 { self.0 }
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
        unsafe { ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<PageTable>()); }
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

/// Write a value to physical memory while we're still in an
/// identity-mapped phase of boot. Used to prime a fresh PML4 before
/// `write_cr3` swaps to it.
///
/// # Safety
/// - `phys` must be identity-mapped in the *current* page tables.
/// - The write must respect the target's alignment.
pub unsafe fn write_identity<T>(phys: PhysAddr, value: T) {
    // SAFETY: per caller contract.
    unsafe { ptr::write_volatile(phys.raw() as *mut T, value); }
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
