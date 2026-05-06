//! narf-driver-runtime — kernel-vs-userspace driver runtime split.
//!
//! Hardware-driver crates (`narf-drivers-net`, `narf-drivers-usb`,
//! `narf-drivers-nvme`, …) reach a small set of primitives:
//!
//! - **MMIO**: read/write at a BAR's identity-mapped phys range.
//! - **DMA**: allocate coherent host memory the device can read/write.
//! - **IRQ**: subscribe to an MSI-X vector and `await` delivery.
//! - **Bus**: PCIe cfg-space write (PCI command, MSI-X enable).
//! - **Sync**: an IRQ-disable spinlock the driver holds across
//!   shared-state mutation.
//!
//! All of those have a kernel implementation today and CAN have a
//! userspace implementation tomorrow:
//!
//! | primitive       | kernel                               | userspace                                   |
//! |-----------------|--------------------------------------|---------------------------------------------|
//! | `map_bar`       | walks PCI BAR + identity-maps phys   | syscall: kernel grants `Cap<MmioRegion,Write>` mapped into user AS via IOMMU + EPT |
//! | `alloc_coherent`| kernel buddy allocator + IOMMU pin   | syscall: kernel-minted shared coherent page |
//! | `wait_for_irq`  | per-vector waker queue               | IPC endpoint cap; kernel signals on IRQ     |
//! | `set_command`   | direct PCIe cfg MMIO write           | cap-gated `pci_cfg_write` syscall           |
//! | `IrqSafeSpinLock` | toggles RFLAGS.IF (ring 0 only)    | plain `Mutex<T>` (user can't toggle IF)     |
//!
//! Drivers depend on this crate (with one of the two features
//! enabled) instead of reaching into `narf_bus` / `narf_io` /
//! `narf_interrupts` / `narf_lib` directly. The same driver
//! source compiles either way; only the runtime impl differs.
//!
//! This first cut wires up the `kernel` feature — which is just a
//! re-export of the existing kernel crates. The `userspace`
//! feature surfaces the same identifiers but as types whose
//! constructors are unimplemented, so a userspace runtime crate
//! (`narf-user-driver-runtime`, future) can fill them in without
//! touching driver source.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![cfg_attr(
    not(feature = "kernel"),
    allow(dead_code, missing_debug_implementations)
)]

#[cfg(all(feature = "kernel", feature = "userspace"))]
compile_error!(
    "narf-driver-runtime: features `kernel` and `userspace` are mutually exclusive — \
     pick one (`kernel` is the default)."
);

#[cfg(not(any(feature = "kernel", feature = "userspace")))]
compile_error!("narf-driver-runtime: enable one of `kernel` (default) or `userspace`.");

// ── Kernel runtime ─────────────────────────────────────────────────

#[cfg(feature = "kernel")]
mod kernel_rt {
    pub use narf_bus::pci;
    pub use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
    pub use narf_capabilities::{Cap, Write};
    pub use narf_interrupts::wait_for_irq;
    pub use narf_io::{alloc_coherent, DmaBuffer};
    pub use narf_lib::id::DomainId;
    pub use narf_lib::sync::IrqSafeSpinLock as Lock;
}

#[cfg(feature = "kernel")]
pub use kernel_rt::*;

// ── Userspace runtime — type surface only, impls land later ────────
//
// These shapes mirror the kernel surface so a driver built against
// `narf-driver-runtime` compiles either way. The actual syscall
// plumbing (cap-gated BAR mapping, shared coherent pages, IPC IRQ
// delivery) lives in `narf-user-driver-runtime` (future companion
// crate). Constructors here panic with a clear message so a
// driver accidentally linked under `userspace` without that
// companion crate fails loudly at link-time / runtime instead of
// silently doing nothing.

#[cfg(feature = "userspace")]
mod user_rt {
    use core::marker::PhantomData;

    /// Phys-address-backed MMIO region. Userspace impl maps this
    /// into the process AS via an IOMMU-backed cap window.
    #[derive(Debug, Clone, Copy)]
    pub struct MmioRegion {
        _va: *mut u8,
        _len: usize,
    }
    // SAFETY: the userspace impl will own the cap exclusively while
    // the region is borrowed; no concurrent threads can race the
    // pointer until the cap-mediated layer hands it out elsewhere.
    unsafe impl Send for MmioRegion {}
    unsafe impl Sync for MmioRegion {}

    impl MmioRegion {
        /// Stub. The userspace runtime crate will mint these from a
        /// `Cap<BusDeviceCap, Write>` via a `map_bar` syscall.
        pub fn from_user_va(va: *mut u8, len: usize) -> Self {
            Self { _va: va, _len: len }
        }
        /// # Safety
        /// `offset + 1 <= len`. Wraps a volatile read against the
        /// userspace VA.
        pub unsafe fn read8(&self, offset: u64) -> u8 {
            unsafe { core::ptr::read_volatile(self._va.add(offset as usize)) }
        }
        /// # Safety
        /// `offset + 1 <= len`.
        pub unsafe fn write8(&self, offset: u64, value: u8) {
            unsafe {
                core::ptr::write_volatile(self._va.add(offset as usize), value);
            }
        }
        /// # Safety
        /// `offset + 2 <= len`, naturally aligned.
        pub unsafe fn read16(&self, offset: u64) -> u16 {
            unsafe { core::ptr::read_volatile(self._va.add(offset as usize) as *const u16) }
        }
        /// # Safety
        /// `offset + 2 <= len`, naturally aligned.
        pub unsafe fn write16(&self, offset: u64, value: u16) {
            unsafe {
                core::ptr::write_volatile(self._va.add(offset as usize) as *mut u16, value);
            }
        }
        /// # Safety
        /// `offset + 4 <= len`, naturally aligned.
        pub unsafe fn read32(&self, offset: u64) -> u32 {
            unsafe { core::ptr::read_volatile(self._va.add(offset as usize) as *const u32) }
        }
        /// # Safety
        /// `offset + 4 <= len`, naturally aligned.
        pub unsafe fn write32(&self, offset: u64, value: u32) {
            unsafe {
                core::ptr::write_volatile(self._va.add(offset as usize) as *mut u32, value);
            }
        }
    }

    /// DMA-coherent buffer. Userspace impl gets these from a
    /// kernel-minted shared page (mapped writable in the user AS,
    /// IOMMU-mapped on the device side).
    #[derive(Debug)]
    pub struct DmaBuffer {
        _va: *mut u8,
        _phys: u64,
        _len: usize,
    }
    // SAFETY: same single-owner discipline as MmioRegion.
    unsafe impl Send for DmaBuffer {}
    unsafe impl Sync for DmaBuffer {}

    /// Phys-address handle returned by `DmaBuffer::phys_addr`.
    #[derive(Debug, Clone, Copy)]
    pub struct PhysAddr(pub u64);
    impl PhysAddr {
        pub fn raw(self) -> u64 {
            self.0
        }
    }

    impl DmaBuffer {
        pub fn phys_addr(&self) -> PhysAddr {
            PhysAddr(self._phys)
        }
        pub fn len(&self) -> usize {
            self._len
        }
        pub fn is_empty(&self) -> bool {
            self._len == 0
        }
    }

    /// Errors from `alloc_coherent`. Userspace impl returns these
    /// when the kernel cap-mint syscall fails.
    #[derive(Debug)]
    pub enum DmaError {
        OutOfMemory,
        NoCap,
    }

    /// Allocate a DMA-coherent buffer. Stub — the userspace impl
    /// crates a `narf_user_driver_runtime::dma_alloc` syscall.
    pub fn alloc_coherent(_size: usize, _domain: DomainId) -> Result<DmaBuffer, DmaError> {
        // TODO: cap-mediated syscall in narf-user-driver-runtime.
        Err(DmaError::NoCap)
    }

    /// Cap-gated BAR mapping. Stub.
    pub fn map_bar(_device: &BusDevice, _idx: u8) -> Result<MmioRegion, MapBarError> {
        Err(MapBarError::NoCap)
    }

    #[derive(Debug)]
    pub enum MapBarError {
        NoCap,
        OutOfRange,
    }

    /// PCIe cfg-space writes — cap-gated. Stub for userspace; the
    /// kernel runtime forwards to `narf_bus::pci::*` directly.
    pub mod pci {
        use super::super::{Cap, Write};
        use super::BusDeviceCap;
        pub mod cmd {
            pub const MEM_SPACE: u16 = 1 << 1;
            pub const BUS_MASTER: u16 = 1 << 2;
            pub const INTX_DISABLE: u16 = 1 << 10;
        }
        #[derive(Debug)]
        pub enum CfgError {
            NoCap,
        }
        pub fn set_command(
            _cap: &Cap<BusDeviceCap, Write>,
            _device: &super::BusDevice,
            _bits: u16,
        ) -> Result<(), CfgError> {
            Err(CfgError::NoCap)
        }
    }

    /// IRQ-vector subscription. Userspace impl: each vector maps to
    /// an IPC endpoint cap; the kernel signals it on IRQ delivery.
    /// Returned future resolves on the next signal.
    #[derive(Debug)]
    pub struct IrqWaiter {
        _vec: u8,
    }
    impl core::future::Future for IrqWaiter {
        type Output = ();
        fn poll(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            // TODO: poll the IPC endpoint via the user-side runtime.
            core::task::Poll::Pending
        }
    }
    pub fn wait_for_irq(vec: u8) -> IrqWaiter {
        IrqWaiter { _vec: vec }
    }

    /// Domain id — same shape as the kernel-side type, just
    /// re-exported here so driver source can name it without a
    /// conditional `use`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DomainId(u8);
    impl DomainId {
        pub const DRIVER_0: DomainId = DomainId(8);
        pub fn raw(self) -> u8 {
            self.0
        }
    }

    /// Userspace doesn't run with IRQs disabled — a plain spin-
    /// based mutex suffices. Single-owner-by-cap-discipline means
    /// contention is rare.
    #[derive(Debug)]
    pub struct Lock<T> {
        _data: core::cell::UnsafeCell<T>,
        _busy: core::sync::atomic::AtomicBool,
    }
    unsafe impl<T: Send> Send for Lock<T> {}
    unsafe impl<T: Send> Sync for Lock<T> {}

    impl<T> Lock<T> {
        pub const fn new(v: T) -> Self {
            Self {
                _data: core::cell::UnsafeCell::new(v),
                _busy: core::sync::atomic::AtomicBool::new(false),
            }
        }
        pub fn lock(&self) -> LockGuard<'_, T> {
            use core::sync::atomic::Ordering;
            while self
                ._busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            LockGuard {
                _data: unsafe { &mut *self._data.get() },
                _busy: &self._busy,
                _phantom: PhantomData,
            }
        }
    }
    #[derive(Debug)]
    pub struct LockGuard<'a, T> {
        _data: &'a mut T,
        _busy: &'a core::sync::atomic::AtomicBool,
        _phantom: PhantomData<&'a mut T>,
    }
    impl<'a, T> core::ops::Deref for LockGuard<'a, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self._data
        }
    }
    impl<'a, T> core::ops::DerefMut for LockGuard<'a, T> {
        fn deref_mut(&mut self) -> &mut T {
            self._data
        }
    }
    impl<'a, T> Drop for LockGuard<'a, T> {
        fn drop(&mut self) {
            use core::sync::atomic::Ordering;
            self._busy.store(false, Ordering::Release);
        }
    }

    /// Cap + cap-type stubs so driver source can name them
    /// without a conditional `use`. Userspace impl puts a real
    /// cap handle here (kernel-issued reference into the user
    /// process's cap table).
    #[derive(Debug, Clone, Copy)]
    pub struct Cap<T, R> {
        _t: PhantomData<T>,
        _r: PhantomData<R>,
    }
    #[derive(Debug, Clone, Copy)]
    pub struct Write;
    #[derive(Debug, Clone, Copy)]
    pub struct BusDeviceCap;
    #[derive(Debug, Clone, Copy)]
    pub struct BusDevice {
        pub id: BusDeviceId,
    }
    #[derive(Debug, Clone, Copy)]
    pub struct BusDeviceId {
        pub vendor: u16,
        pub device: u16,
        pub class: u32,
    }
}

#[cfg(feature = "userspace")]
pub use user_rt::*;
