//! The kernel crates' names, for the module build.
//!
//! Built in, the driver names kernel services by their crates
//! (`narf_time::Deadline`, `narf_io::alloc_coherent`, `narf_lib::sync::*`).
//! A `.ko` can link none of those crates, so this module defines modules of
//! the same names holding the subset of each API the module-built files
//! use, implemented over `narf-module-rt` and the KABI. Each such file
//! carries
//!
//! ```ignore
//! #[cfg(feature = "module")]
//! use crate::iwlwifi::module::kernel::*;
//! ```
//!
//! which shadows the (absent) extern crates, so the driver source is the same
//! text in both builds and the built-in build is untouched.
//!
//! The semantics that differ from the kernel's are stated per item. The
//! biggest: a [`narf_capabilities::Cap`] here is the probe's device token,
//! not a revocable capability — the kernel enforces the module's authority
//! at every KABI call instead, and device teardown revokes the token.

#![allow(non_camel_case_types)]

use alloc::vec::Vec;

use super::device;

/// KABI exports the shim calls. Private, like every non-`narf_*` item here,
/// so the glob import brings in only the kernel-crate names.
mod ffi {
    unsafe extern "C" {
        pub fn narf_dma_alloc_mapped(
            dev: u64,
            len: usize,
            addr_bits: u32,
            out_cpu: *mut usize,
            out_bus: *mut u64,
            out_len: *mut usize,
        ) -> u64;
        pub fn narf_dma_free(dev: u64, dma: u64) -> i32;
        pub fn narf_udelay(ns: u64) -> i32;
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
    }
}

/// `narf_lib`: locks and ids.
pub mod narf_lib {
    pub mod sync {
        /// The module's spinlock. It never masks interrupts: module code runs
        /// only in task context (probe, the poller, vector callbacks).
        pub use narf_module_rt::sync::{SpinLock as IrqSafeSpinLock, SpinLockGuard};
    }
    pub mod mutex {
        pub use narf_module_rt::sync::{Mutex, MutexGuard};
    }
    pub mod id {
        /// Allocation domain. A module allocates in its own effective domain
        /// whatever the driver names; the type keeps the built-in signature.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct DomainId;
        impl DomainId {
            pub const DRIVER_0: DomainId = DomainId;
        }
    }
}

/// `narf_net`: the frame metadata the station code produces. The module's
/// frames go through the netif bridge (`narf_netif_rx`), which takes bytes
/// only, so RX verdicts are computed and then dropped at the bridge — the
/// stack verifies checksums in software, as for any non-offloading netdev.
pub mod narf_net {
    /// Per-frame receive metadata (the kernel type's fields).
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct RxMeta {
        pub timestamp_ns: Option<u64>,
        pub csum_l3: bool,
        pub csum_l4: bool,
        pub vlan_tag: Option<u16>,
        pub gro_segs: u16,
        pub rx_hash: u32,
    }

    /// The L4 checksum a transmit asks the hardware for.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum L4CsumKind {
        Tcp,
        Udp,
        Sctp,
    }

    pub mod native_emission {
        /// A native emitting role's lifetime (P2P/AP). The module carries no
        /// such role, so no value exists (see `module/absent.rs`).
        #[derive(Debug)]
        pub enum Lifetime {}
    }
}

/// `narf_console`: the boot console.
pub mod narf_console {
    pub use narf_module_rt::console::Console as Writer;
}

/// `narf_time`: the monotonic clock. A module has no cycle counter export,
/// so "cycles" are nanoseconds: every driver use pairs `now_cycles` /
/// `sleep_cycles` with `ns_to_cycles`, which is the identity here. Sleeps
/// complete on the executor's heartbeat (the 1 ms device poller).
pub mod narf_time {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// An absolute timeout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Deadline(narf_module_rt::time::Deadline);

    impl Deadline {
        pub fn after_ms(ms: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ms(ms))
        }
        pub fn after_ns(ns: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ns(ns))
        }
        pub fn expired(&self) -> bool {
            self.0.expired()
        }
    }

    /// Completes once its deadline has passed.
    #[derive(Debug)]
    #[must_use = "futures do nothing unless polled"]
    pub struct SleepUntil(narf_module_rt::time::SleepUntil);

    impl Future for SleepUntil {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.0).poll(cx)
        }
    }

    /// Sleep for `cycles` (nanoseconds, see the module docs).
    pub fn sleep_cycles(cycles: u64) -> SleepUntil {
        SleepUntil(narf_module_rt::time::sleep_until(
            narf_module_rt::time::Deadline::after_ns(cycles),
        ))
    }

    /// The monotonic clock in "cycles" (nanoseconds).
    pub fn now_cycles() -> u64 {
        narf_module_rt::time::now_ns()
    }

    pub mod wall {
        /// Nanoseconds on the monotonic clock.
        pub fn monotonic_ns() -> u64 {
            narf_module_rt::time::now_ns()
        }
        /// Nanoseconds to "cycles": the identity (see the module docs).
        pub fn ns_to_cycles(ns: u64) -> u64 {
            ns
        }
        /// "Cycles" to nanoseconds: the identity.
        pub fn cycles_to_ns(cycles: u64) -> u64 {
            cycles
        }
    }
}

/// `narf_scheduler`: the module's executor.
pub mod narf_scheduler {
    use core::future::Future;

    /// Spawn a driver task on the module's executor. Refused only after
    /// module exit stopped the executor, when nothing may run any more.
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) -> Result<(), ()> {
        super::super::EXEC.spawn(future).map_err(|_| ())
    }

    /// Yield to the executor once.
    pub fn yield_now() -> narf_module_rt::time::YieldNow {
        narf_module_rt::time::yield_now()
    }

    /// Spin until `done` or `deadline`, keeping the kernel's sleep pumps
    /// ticking between samples (`narf_udelay`). `true` when `done` held.
    pub fn responsive_spin_until(
        mut done: impl FnMut() -> bool,
        deadline: super::narf_time::Deadline,
    ) -> bool {
        loop {
            if done() {
                return true;
            }
            if deadline.expired() {
                return false;
            }
            // SAFETY: argument-only call, 10 us.
            let _ = unsafe { super::ffi::narf_udelay(10_000) };
        }
    }
}

/// `narf_capabilities`: the probe's device authority.
///
/// The kernel's `Cap<T, R>` is a revocable capability that every register
/// and DMA operation invokes. A module cannot hold one: its authority is the
/// probe token, which the kernel checks on every KABI call and revokes at
/// device teardown (a revoked token makes every export fail). So `Cap` here
/// is a unit authority whose `invoke` always runs the operation; the
/// enforcement that matters happens one level down, in the KABI.
pub mod narf_capabilities {
    use core::marker::PhantomData;

    /// The write right.
    #[derive(Clone, Copy, Debug)]
    pub struct Write;
    /// The read right.
    #[derive(Clone, Copy, Debug)]
    pub struct Read;
    /// The grant right.
    #[derive(Clone, Copy, Debug)]
    pub struct Grant;

    /// Why an invocation failed (never, here).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CapError {
        Revoked,
    }

    /// An operation run under a capability.
    pub trait CapOp<T, R> {
        type Output;
        fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
    }

    /// The empty operation (`authorized()` probes).
    #[derive(Clone, Copy, Debug)]
    pub struct NoopOp;
    impl<T, R> CapOp<T, R> for NoopOp {
        type Output = ();
        fn execute(self, _: &Cap<T, R>) -> Result<(), CapError> {
            Ok(())
        }
    }

    /// The module's authority over the probed device (see the module docs).
    pub struct Cap<T, R>(PhantomData<fn() -> (T, R)>);

    impl<T, R> Clone for Cap<T, R> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T, R> Copy for Cap<T, R> {}
    impl<T, R> core::fmt::Debug for Cap<T, R> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Cap(module device token)")
        }
    }

    impl<T, R> Cap<T, R> {
        /// The probed device's authority.
        pub const fn device() -> Self {
            Self(PhantomData)
        }
        /// Run `op` (the KABI enforces the token underneath).
        pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
            op.execute(self)
        }
    }
}

/// `narf_bus`: the probed function.
pub mod narf_bus {
    /// Marker for device-scoped authority.
    #[derive(Clone, Copy, Debug)]
    pub struct BusDeviceCap;

    /// `(segment, bus, slot, function)` of the probed function.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BusAddr {
        pub segment: u16,
        pub bus: u8,
        pub slot: u8,
        pub function: u8,
    }

    /// The function's identity (`narf_pci_identity`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceId {
        pub vendor: u16,
        pub device: u16,
        pub class: u32,
        pub subsystem_vendor: u16,
        pub subsystem_id: u16,
    }

    /// PCI command register access over `narf_pci_command`: clear, then set,
    /// then the register read back, on the probe token.
    pub mod pci {
        use super::super::narf_capabilities::{Cap, Write};
        use super::{BusDevice, BusDeviceCap};

        mod ffi {
            unsafe extern "C" {
                pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32;
            }
        }

        /// `PCI_COMMAND` bits.
        pub mod cmd {
            pub const MEM_SPACE: u16 = 1 << 1;
            pub const BUS_MASTER: u16 = 1 << 2;
            pub const INTX_DISABLE: u16 = 1 << 10;
        }

        /// A refused or failed command-register access (the KABI errno).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PciError(pub i32);

        fn command(clear: u16, set: u16) -> Result<u16, PciError> {
            let mut value = 0u16;
            // SAFETY: `value` is a live local.
            match unsafe {
                ffi::narf_pci_command(super::super::super::device(), clear, set, &mut value)
            } {
                0 => Ok(value),
                errno => Err(PciError(errno)),
            }
        }

        pub fn read_command(
            _cap: &Cap<BusDeviceCap, Write>,
            _device: &BusDevice,
        ) -> Result<u16, PciError> {
            command(0, 0)
        }

        pub fn set_command(
            _cap: &Cap<BusDeviceCap, Write>,
            _device: &BusDevice,
            bits: u16,
        ) -> Result<u16, PciError> {
            command(0, bits)
        }

        pub fn clear_command(
            _cap: &Cap<BusDeviceCap, Write>,
            _device: &BusDevice,
            bits: u16,
        ) -> Result<u16, PciError> {
            command(bits, 0)
        }
    }

    /// The probed function, as the driver's owners carry it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BusDevice {
        pub addr: BusAddr,
        pub id: DeviceId,
    }

    /// BAR0 as the driver sees it: a length and 32-bit accessors. The
    /// mapping stays in the kernel; every access is a bounds-checked KABI
    /// call on the probe token.
    #[derive(Clone, Copy, Debug)]
    pub struct MmioRegion {
        pub len: u64,
        pub(crate) bar: u64,
    }

    impl MmioRegion {
        /// # Safety
        /// `off` names a readable register inside the BAR (the kernel
        /// bounds-checks it as well; a refused read yields all-ones).
        pub unsafe fn read32(&self, off: u64) -> u32 {
            let mut value = u32::MAX;
            // SAFETY: `value` is a live local.
            let _ =
                unsafe { super::ffi::narf_mmio_read32(super::device(), self.bar, off, &mut value) };
            value
        }

        /// # Safety
        /// `off` names a writable register inside the BAR.
        pub unsafe fn write32(&self, off: u64, value: u32) {
            // SAFETY: argument-only call; the kernel bounds-checks `off`.
            let _ = unsafe { super::ffi::narf_mmio_write32(super::device(), self.bar, off, value) };
        }
    }
}

/// `narf_io`: coherent DMA the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// The transport allocates its RX buffers, rings and per-frame command
/// buffers in many small pieces and frees them again. KABI DMA handles are
/// never reused, so small buffers come from size-class pools carved out of
/// 1 MiB mapped chunks and return to their pool on drop; large ones
/// (firmware sections, PNVM) are allocated and freed directly.
pub mod narf_io {
    use super::narf_lib::id::DomainId;
    use super::narf_lib::sync::IrqSafeSpinLock;
    use super::*;

    /// Device-visible address.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DmaAddr(u64);
    impl DmaAddr {
        pub const fn raw(self) -> u64 {
            self.0
        }
    }

    /// Allocation failure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IoError;

    const PAGE: usize = 4096;
    /// Largest pooled block; bigger requests go straight to the kernel.
    const MAX_POOLED: usize = 64 * 1024;
    /// Pool refill unit.
    const CHUNK: usize = 1 << 20;
    /// Size classes: 4 KiB, 8 KiB, ..., 64 KiB.
    const CLASSES: usize = 5;

    #[derive(Clone, Copy)]
    struct Block {
        cpu: usize,
        bus: u64,
    }

    /// Free blocks per (address limit, class). Index 0: the 32-bit pool;
    /// index 1: unrestricted. Other limits are allocated directly.
    static POOLS: IrqSafeSpinLock<[[Vec<Block>; CLASSES]; 2]> = IrqSafeSpinLock::new([
        [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()],
    ]);

    enum Origin {
        Pooled { pool: usize, class: usize },
        Direct { handle: u64 },
    }

    /// A coherent buffer: `len` bytes at `cpu` (CPU) / `bus` (device).
    pub struct DmaBuffer {
        cpu: usize,
        bus: u64,
        len: usize,
        origin: Origin,
    }

    // SAFETY: the buffer is plain memory owned by this value; sharing it
    // across CPUs is what the driver's ring protocol already arbitrates.
    unsafe impl Send for DmaBuffer {}
    // SAFETY: as above.
    unsafe impl Sync for DmaBuffer {}

    impl core::fmt::Debug for DmaBuffer {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("DmaBuffer")
                .field("bus", &self.bus)
                .field("len", &self.len)
                .finish_non_exhaustive()
        }
    }

    fn mapped(len: usize, addr_bits: u32) -> Result<(u64, usize, u64, usize), IoError> {
        let (mut cpu, mut bus, mut got) = (0usize, 0u64, 0usize);
        // SAFETY: the three outputs are live locals.
        let handle = unsafe {
            ffi::narf_dma_alloc_mapped(device(), len, addr_bits, &mut cpu, &mut bus, &mut got)
        };
        if handle == 0 || cpu == 0 {
            return Err(IoError);
        }
        Ok((handle, cpu, bus, got))
    }

    fn addr_bits(mask: u64) -> u32 {
        64 - mask.leading_zeros()
    }

    /// `narf_io::alloc_coherent_masked`: zeroed, wholly below `mask`. The
    /// buffer is exactly `len` bytes long to the driver, as built in.
    pub fn alloc_coherent_masked(
        len: usize,
        _domain: DomainId,
        mask: u64,
    ) -> Result<DmaBuffer, IoError> {
        let bits = addr_bits(mask).clamp(32, 64);
        let size = len.max(1).next_power_of_two().max(PAGE);
        // A pool holds blocks of one address limit: a block carved under a
        // 64-bit limit must never satisfy a narrower request.
        if size > MAX_POOLED || !matches!(bits, 32 | 64) {
            let (handle, cpu, bus, _got) = mapped(len.max(1), bits)?;
            return Ok(DmaBuffer {
                cpu,
                bus,
                len,
                origin: Origin::Direct { handle },
            });
        }
        let pool = usize::from(bits == 64);
        let class = (size / PAGE).trailing_zeros() as usize;
        let block = {
            let mut pools = POOLS.lock();
            pools[pool][class].pop()
        };
        let block = match block {
            Some(block) => block,
            None => {
                // Carve a fresh chunk into blocks of this class. The chunk's
                // handle is kept for the device's lifetime: device teardown
                // releases it with every other module DMA allocation.
                let (_handle, cpu, bus, got) = mapped(CHUNK, bits)?;
                let mut pools = POOLS.lock();
                let free = &mut pools[pool][class];
                for i in 1..got / size {
                    free.push(Block {
                        cpu: cpu + i * size,
                        bus: bus + (i * size) as u64,
                    });
                }
                Block { cpu, bus }
            }
        };
        // SAFETY: `block` names `size` bytes of this module's mapped DMA
        // memory, owned by no one else until it returns to the pool.
        unsafe { core::ptr::write_bytes(block.cpu as *mut u8, 0, size) };
        Ok(DmaBuffer {
            cpu: block.cpu,
            bus: block.bus,
            len,
            origin: Origin::Pooled { pool, class },
        })
    }

    /// `narf_io::alloc_coherent`: no address limit.
    pub fn alloc_coherent(len: usize, domain: DomainId) -> Result<DmaBuffer, IoError> {
        alloc_coherent_masked(len, domain, u64::MAX)
    }

    impl DmaBuffer {
        pub fn dma_addr(&self) -> DmaAddr {
            DmaAddr(self.bus)
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn as_ptr(&self) -> *const u8 {
            self.cpu as *const u8
        }
        pub fn as_mut_ptr(&self) -> *mut u8 {
            self.cpu as *mut u8
        }
        pub fn cpu_ptr<T>(&self) -> *const T {
            self.cpu as *const T
        }
        pub fn cpu_mut_ptr<T>(&self) -> *mut T {
            self.cpu as *mut T
        }
        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: `cpu` names `len` bytes of mapped DMA memory owned by
            // this buffer.
            unsafe { core::slice::from_raw_parts(self.cpu as *const u8, self.len) }
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: as above; `&mut self` makes the borrow unique.
            unsafe { core::slice::from_raw_parts_mut(self.cpu as *mut u8, self.len) }
        }
    }

    impl Drop for DmaBuffer {
        fn drop(&mut self) {
            match self.origin {
                Origin::Pooled { pool, class } => POOLS.lock()[pool][class].push(Block {
                    cpu: self.cpu,
                    bus: self.bus,
                }),
                Origin::Direct { handle } => {
                    // SAFETY: `handle` came from this module's allocation on
                    // this device and is freed exactly once, here.
                    let _ = unsafe { ffi::narf_dma_free(device(), handle) };
                }
            }
        }
    }
}
