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
    #[inline]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Cast to a raw pointer for MMIO access. Caller is responsible for
    /// ensuring the address is reachable (identity-mapped, or already
    /// translated via `remap_to_virtual`).
    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Cast to a raw pointer reachable from the **kernel** address
    /// space — i.e. via TTBR1 on aarch64, the boot identity map on
    /// x86_64. Use this (not [`Self::as_mut_ptr`]) for kernel-side
    /// access to physical RAM (page-table walks, frame allocator
    /// output, COW memcpys) so the access stays valid even after a
    /// user task swaps TTBR0 to its private root.
    ///
    /// On x86_64 this is the same as `as_mut_ptr` — the kernel is
    /// linked high-half but the boot CR3 carries a low-4-GiB
    /// identity map and every per-domain PML4 clones it.
    ///
    /// On aarch64 this offsets by `KERNEL_PHYS_OFFSET` so the
    /// pointer lands in TTBR1's high-half RAM window
    /// (`KERNEL_VIRT_BASE` from `build/linker/aarch64.ld`,
    /// `0xFFFF_FF80_0000_0000`). The boot.S TTBR1 setup maps the
    /// 1 GiB block at PA `0x4000_0000` into VA
    /// `0xFFFF_FF80_4000_0000` — the same VA you'd get by OR'ing
    /// the offset into the PA.
    #[inline]
    pub fn kernel_mut_ptr<T>(self) -> *mut T {
        #[cfg(target_arch = "x86_64")]
        {
            self.0 as *mut T
        }
        #[cfg(target_arch = "aarch64")]
        {
            (self.0 | crate::KERNEL_PHYS_OFFSET) as *mut T
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.0 as *mut T
        }
    }

    /// Const-pointer counterpart to [`Self::kernel_mut_ptr`].
    #[inline]
    pub fn kernel_ptr<T>(self) -> *const T {
        #[cfg(target_arch = "x86_64")]
        {
            self.0 as *const T
        }
        #[cfg(target_arch = "aarch64")]
        {
            (self.0 | crate::KERNEL_PHYS_OFFSET) as *const T
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.0 as *const T
        }
    }
}

impl VirtAddr {
    #[inline]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
