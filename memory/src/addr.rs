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
    ///
    /// On x86_64 this OR's in [`KERNEL_DIRECT_MAP_BASE`] once
    /// [`direct_map_activate`] has run — the high-half kernel direct
    /// map `init_mmu` installs, which reaches RAM above 512 GiB that
    /// cannot be identity-mapped (PML4[2..255] belongs to user address
    /// space). Before activation (early boot, only < 4 GiB frames
    /// exist) it falls back to the boot identity map. OR (not ADD,
    /// mirroring aarch64's `KERNEL_PHYS_OFFSET`) is deliberate: for a
    /// true physical address (bits 46-47 clear, i.e. < 64 TiB) it
    /// equals `base + phys` and lands in the direct map, but for a
    /// value already inside the kernel window (a kernel VA some callers
    /// wrap in a `PhysAddr` and relied on the old x86_64 identity no-op
    /// for) it is idempotent instead of overflowing.
    #[inline]
    pub fn kernel_mut_ptr<T>(self) -> *mut T {
        #[cfg(target_arch = "x86_64")]
        {
            // EVERY frame takes the direct-map offset once the map is
            // live -- not just those above LOW_IDENTITY_LIMIT.
            //
            // This used to be gated on `self.0 >= LOW_IDENTITY_LIMIT` so
            // that `ptr == phys` held on any machine under 512 GiB, which
            // let identity-assuming code stay correct. That gate is what
            // kept PML4[0] pinned to an identity map, and PML4[0] is the
            // slot an ordinary Linux `ET_EXEC` binary wants to load into
            // (PT_LOAD at 0x400000). Routing all kernel physical access
            // through the high-half direct map frees the entire low half
            // for user space.
            //
            // The `direct_map_live()` fallback still yields identity
            // before `init_mmu` installs the map, which is what early
            // boot (running on boot.S's identity CR3) needs.
            if direct_map_live() {
                (self.0 | KERNEL_DIRECT_MAP_BASE) as *mut T
            } else {
                self.0 as *mut T
            }
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
            // See `kernel_mut_ptr`: all frames take the offset once live.
            if direct_map_live() {
                (self.0 | KERNEL_DIRECT_MAP_BASE) as *const T
            } else {
                self.0 as *const T
            }
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

    /// Inverse of [`Self::kernel_mut_ptr`] / [`Self::kernel_ptr`]:
    /// recover the physical address from a pointer those returned. Use
    /// this — never `PhysAddr::new(ptr as u64)` — whenever code that got
    /// a kernel-RAM pointer needs the underlying frame again (e.g. to
    /// free it). Treating the pointer as a physical address is only
    /// correct while the kernel accessor is the identity map; once the
    /// high-half direct map is live the pointer carries the offset and
    /// the naive cast frees the wrong frame (buddy double-alloc).
    #[inline]
    pub fn from_kernel_ptr<T>(ptr: *const T) -> Self {
        let v = ptr as u64;
        #[cfg(target_arch = "x86_64")]
        {
            // A direct-map pointer is >= KERNEL_DIRECT_MAP_BASE; anything
            // below that is a low identity pointer (ptr == phys). This
            // mirrors `kernel_mut_ptr`'s LOW_IDENTITY_LIMIT gate.
            if v >= KERNEL_DIRECT_MAP_BASE {
                PhysAddr::new(v & !KERNEL_DIRECT_MAP_BASE)
            } else {
                PhysAddr::new(v)
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            PhysAddr::new(v & !crate::KERNEL_PHYS_OFFSET)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            PhysAddr::new(v)
        }
    }
}

/// Base of the x86_64 high-half kernel direct map — PML4[384]. Kernel
/// access to a physical frame is `KERNEL_DIRECT_MAP_BASE | phys` once
/// the map is live; mirrors aarch64's `KERNEL_PHYS_OFFSET`. This is a
/// separate window from the low identity map (0..512 GiB) precisely so
/// RAM above 512 GiB — which the identity map can't reach because
/// PML4[2..255] is user address space — is still reachable by the
/// kernel.
///
/// Slot choice: PML4[256..271] is the PCID per-domain private VA range
/// (`x86_64/domain.rs`, which *overwrites* those slots per domain), and
/// PML4[511] is the kernel image higher-half — both off-limits.
/// PML4[384..510] is free. PML4[384] specifically is `0b11 << 46`
/// (bits 46-47 set, bits 0..46 clear), so `base | phys == base + phys`
/// for any `phys < 64 TiB` (the OR trick) while remaining idempotent
/// for a kernel VA a caller might wrap in a `PhysAddr`. The map spans
/// PML4[384..510] (127 slots = 63.5 TiB), sized at boot to installed
/// RAM. `init_mmu` builds it and calls [`direct_map_activate`] after
/// the CR3 swap.
#[cfg(target_arch = "x86_64")]
pub const KERNEL_DIRECT_MAP_BASE: u64 = 0xFFFF_C000_0000_0000;

/// Physical addresses below this are covered by the low identity map
/// (PML4[0], built by `init_mmu` as 512 × 1-GiB huge pages) and are
/// reached at `phys == virt`; `kernel_mut_ptr` only applies the
/// direct-map offset to frames at or above it. 512 GiB = the identity
/// map's full reach before PML4[1] (user + high-MMIO) begins.
#[cfg(target_arch = "x86_64")]
pub const LOW_IDENTITY_LIMIT: u64 = 512u64 << 30;

/// First PML4 slot of the direct map (`KERNEL_DIRECT_MAP_BASE >> 39`).
#[cfg(target_arch = "x86_64")]
pub const KERNEL_DIRECT_MAP_PML4_BASE: usize = 384;

/// Number of PML4 slots available to the direct map: PML4[384..=510]
/// (511 is the kernel image). 127 × 512 GiB = 63.5 TiB of RAM.
#[cfg(target_arch = "x86_64")]
pub const KERNEL_DIRECT_MAP_PML4_SLOTS: usize = 127;

/// False until `init_mmu` has installed the high-half direct map and
/// swapped CR3. While false, [`PhysAddr::kernel_mut_ptr`] uses the boot
/// identity map — correct because every frame that exists before the
/// handoff is < 4 GiB (the early phys ceiling) and thus inside boot.S's
/// identity window. Flipping to offset addressing only after the map is
/// live keeps the accessor valid across the whole boot, without a
/// separate early/late code path at each of its ~50 call sites.
#[cfg(target_arch = "x86_64")]
static DIRECT_MAP_LIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Publish that the high-half direct map is installed. Called once by
/// `init_mmu` immediately after the CR3 swap.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn direct_map_activate() {
    DIRECT_MAP_LIVE.store(true, core::sync::atomic::Ordering::Release);
}

/// Whether the high-half direct map is live. Used by the kernel RAM
/// accessors to pick the offset vs. identity window.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn direct_map_live() -> bool {
    DIRECT_MAP_LIVE.load(core::sync::atomic::Ordering::Acquire)
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
