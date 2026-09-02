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
            (self.0 | direct_map_base()) as *mut T
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

    /// Invertibility bound: this is `phys | base`, and the base owns PML4
    /// slot bits (39 and up), so [`PhysAddr::from_kernel_ptr`] recovers
    /// `phys` only while the two are disjoint — i.e. `phys` below the
    /// alignment `init_mmu` chose for the slot (512 GiB for a single-chunk
    /// map). Beyond that the map does not cover the address anyway; a fixed
    /// base merely made the arithmetic look right.
    ///
    /// Const-pointer counterpart to [`Self::kernel_mut_ptr`].
    #[inline]
    pub fn kernel_ptr<T>(self) -> *const T {
        #[cfg(target_arch = "x86_64")]
        {
            // See `kernel_mut_ptr`: all frames take the offset once live.
            (self.0 | direct_map_base()) as *const T
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
            // Mirror `kernel_mut_ptr` exactly: once the direct map is live it
            // applies the offset to *every* frame, so the inverse strips it
            // from every pointer. Before activation the accessor is the
            // identity, and so is this.
            //
            // The old form discriminated on `v >= KERNEL_DIRECT_MAP_BASE` and
            // treated anything lower as an identity pointer, which was a
            // faithful mirror only while `kernel_mut_ptr` had a
            // LOW_IDENTITY_LIMIT gate. That gate is gone and the kernel no
            // longer identity-maps RAM, so a lower pointer is not an identity
            // pointer — it is a vmalloc/ioremap VA (x86_64 vmalloc starts at
            // 0xFFFF_8800_0000_0000, *below* the direct map) and there is no
            // physical address to recover from it. Returning one anyway hands
            // the caller a frame it does not own; `slab::dealloc_large` is
            // safe only because it checks `is_valloc_ptr` first, i.e. the
            // invariant lived in the callers rather than here.
            //
            // `assert!`, not `debug_assert!`: the builds where a wrong frame
            // reaches the buddy are release builds. Linux makes the same
            // call — `virt_to_phys` on a vmalloc address is a classic bug,
            // which CONFIG_DEBUG_VIRTUAL turns into a BUG() rather than a
            // plausible-looking wrong answer.
            let base = crate::addr::direct_map_base();
            if base != 0 {
                assert!(
                    v >= base,
                    "from_kernel_ptr on a pointer outside the direct map                      ({v:#x}) — a vmalloc/ioremap VA has no physical address                      to recover; the caller must resolve it through its own                      mapping (e.g. vmalloc::vfree) instead"
                );
                PhysAddr::new(v & !base)
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
/// The map is built at a slot chosen at boot (see `init_mmu`), so this is
/// the *lowest* legal base rather than the live one — read
/// [`direct_map_base`] for that.
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
/// Live base of the direct map, or 0 before `init_mmu` installs it.
///
/// Zero is load-bearing rather than a sentinel: `phys | 0 == phys`, so the
/// early-boot identity behaviour falls out of the same OR the live path uses.
/// That removes the `direct_map_live()` test — an atomic load *and* a branch —
/// from the hottest accessor in the kernel, leaving one load and an OR.
#[cfg(target_arch = "x86_64")]
static DIRECT_MAP_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Publish the direct map's base. Called once by `init_mmu` immediately
/// after the CR3 swap, with the (possibly randomized) base the map was
/// actually built at.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn direct_map_activate_at(base: u64) {
    DIRECT_MAP_BASE.store(base, core::sync::atomic::Ordering::Release);
}

/// Base the direct map is live at, or 0 while it is not.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn direct_map_base() -> u64 {
    DIRECT_MAP_BASE.load(core::sync::atomic::Ordering::Acquire)
}

/// Whether the high-half direct map is live.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn direct_map_live() -> bool {
    direct_map_base() != 0
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
