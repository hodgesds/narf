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
    pub const VALID:        Self = Self(1 << 0);
    /// Bit 1 is 1 for Table (L0-L2) or Page (L3), 0 for Block (L1-L2).
    pub const TYPE_TABLE:   Self = Self(1 << 1);
    pub const TYPE_PAGE:    Self = Self(1 << 1);

    /// Access Permissions: 00=RW EL1, 01=RW EL1/EL0, 10=RO EL1, 11=RO EL1/EL0.
    pub const AP_RW_EL1:    Self = Self(0b00 << 6);
    pub const AP_RO_EL1:    Self = Self(0b10 << 6);

    /// Shareability: 10=Outer, 11=Inner.
    pub const SH_INNER:     Self = Self(0b11 << 8);

    /// Access Flag: must be 1 to avoid Access Flag faults.
    pub const AF:           Self = Self(1 << 10);

    /// MAIR attribute index (bits 4:2).
    pub const ATTR_NORMAL:  Self = Self(0 << 2);  // Index 0 in MAIR
    pub const ATTR_TAGGED:  Self = Self(1 << 2);  // Index 1 in MAIR
    pub const ATTR_DEVICE:  Self = Self(2 << 2);  // Index 2 in MAIR

    /// Execute-never bits.
    pub const UXN:          Self = Self(1 << 54);
    pub const PXN:          Self = Self(1 << 53);

    pub const EMPTY:        Self = Self(0);

    #[inline] pub const fn bits(self) -> u64 { self.0 }
}

impl core::ops::BitOr for PtFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn new(addr: PhysAddr, flags: PtFlags) -> Self {
        // [47:12] is the physical address.
        Self((addr.raw() & 0x0000_FFFF_FFFF_F000) | flags.bits())
    }

    #[inline] pub const fn is_valid(self) -> bool { self.0 & 1 == 1 }
    #[inline] pub const fn addr(self) -> PhysAddr {
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
        unsafe { ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<PageTable>()); }
    }
}

/// Write a value to physical memory using identity-mapped access.
pub unsafe fn write_identity<T>(phys: PhysAddr, value: T) {
    unsafe { ptr::write_volatile(phys.raw() as *mut T, value); }
}
