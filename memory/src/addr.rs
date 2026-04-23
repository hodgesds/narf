//! Physical and virtual address newtypes.
//!
//! Keeping these distinct at the type level is load-bearing: a raw `usize`
//! that holds a `PhysAddr` and one that holds a `VirtAddr` are not
//! interchangeable, and conflating them is the classic "why doesn't the
//! UART work after MMU enable" bug. See `console/` §3.1.

use core::fmt;

/// Physical address.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

/// Virtual address.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl PhysAddr {
    #[inline] pub const fn new(v: u64) -> Self { Self(v) }
    #[inline] pub const fn raw(self)  -> u64  { self.0 }
    #[inline] pub const fn as_u64(self) -> u64 { self.0 }

    /// Cast to a raw pointer for MMIO access. Caller is responsible for
    /// ensuring the address is reachable (identity-mapped, or already
    /// translated via `remap_to_virtual`).
    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T { self.0 as *mut T }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T { self.0 as *const T }
}

impl VirtAddr {
    #[inline] pub const fn new(v: u64) -> Self { Self(v) }
    #[inline] pub const fn raw(self)  -> u64  { self.0 }
    #[inline] pub const fn as_u64(self) -> u64 { self.0 }

    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T { self.0 as *mut T }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T { self.0 as *const T }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#018x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#018x})", self.0)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}
