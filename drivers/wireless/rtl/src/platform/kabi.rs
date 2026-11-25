//! Module platform: the built-in platform's names over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! The built-in platform re-exports kernel crates (`narf_time` as `time`,
//! `narf_lib` as `lib`, ...); this file provides the subset of those paths
//! the drivers use, with the same names and signatures, so one driver source
//! builds both ways. Everything here runs in task context on whichever upcall
//! (init, probe, the 1 ms device poller, an MSI vector callback, a netif or
//! wireless-host callback) is driving the module's [`EXEC`]utor. The device
//! token is recorded once by probe; every device export takes it.

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use narf_module_rt::exec::Executor;

pub use narf_module_rt::console::Console;
pub use narf_module_rt::sync::SpinLock as IrqSafeSpinLock;

/// KABI exports the platform itself calls.
pub(crate) mod ffi {
    unsafe extern "C" {
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
        pub fn narf_mmio_read16(dev: u64, bar: u64, off: u64, out: *mut u16) -> i32;
        pub fn narf_mmio_write16(dev: u64, bar: u64, off: u64, val: u16) -> i32;
        pub fn narf_mmio_read8(dev: u64, bar: u64, off: u64, out: *mut u8) -> i32;
        pub fn narf_mmio_write8(dev: u64, bar: u64, off: u64, val: u8) -> i32;
        pub fn narf_udelay(ns: u64) -> i32;
        pub fn narf_random_bytes(buf: *mut u8, len: usize) -> i32;
        pub fn narf_dma_alloc_mapped(
            dev: u64,
            len: usize,
            addr_bits: u32,
            out_cpu: *mut usize,
            out_bus: *mut u64,
            out_len: *mut usize,
        ) -> u64;
        pub fn narf_dma_free(dev: u64, dma: u64) -> i32;
        pub fn narf_firmware_open(
            name: *const u8,
            name_len: usize,
            out_handle: *mut u64,
            out_size: *mut usize,
        ) -> i32;
        pub fn narf_firmware_read(
            handle: u64,
            offset: u64,
            buf: *mut u8,
            len: usize,
            out_read: *mut usize,
        ) -> i32;
        pub fn narf_firmware_signed(handle: u64) -> i32;
        pub fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    }
}

/// The probed device's token; 0 until probe.
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// Record the probed device (the token every device export takes).
pub fn set_device(dev: u64) {
    DEVICE.store(dev, Ordering::Release);
}

/// The probed device's token.
pub fn device() -> u64 {
    DEVICE.load(Ordering::Acquire)
}

/// The module's executor: every driver future runs here.
pub static EXEC: Executor = Executor::new();

/// Run the executor once from an upcall (poller, vector, host callback).
pub fn run_executor() {
    let _ = EXEC.run();
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (SAE/ANonce/SNonce, `try_fill_random_bytes`).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// A mapped BAR as the register code sees it: a length and 8/16/32-bit
/// accessors (the `narf_bus::MmioRegion` methods the driver calls). The
/// mapping stays in the kernel; every access is a bounds-checked export on
/// the bound device, so an out-of-range read returns all-ones and an
/// out-of-range write is dropped.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub len: u64,
    bar: u64,
}

impl MmioRegion {
    /// The BAR handle `narf_bar_map_control` returned, `len` bytes long.
    pub(crate) fn new(bar: u64, len: u64) -> Self {
        Self { len, bar }
    }

    /// # Safety
    /// `off` names a readable register of the BAR.
    pub unsafe fn read8(&self, off: u64) -> u8 {
        let mut value = u8::MAX;
        // SAFETY: `value` is a live local; the kernel bounds-checks `off`.
        let _ = unsafe { ffi::narf_mmio_read8(device(), self.bar, off, &mut value) };
        value
    }

    /// # Safety
    /// `off` names a readable, 2-byte-aligned register of the BAR.
    pub unsafe fn read16(&self, off: u64) -> u16 {
        let mut value = u16::MAX;
        // SAFETY: as `read8`.
        let _ = unsafe { ffi::narf_mmio_read16(device(), self.bar, off, &mut value) };
        value
    }

    /// # Safety
    /// `off` names a readable, 4-byte-aligned register of the BAR.
    pub unsafe fn read32(&self, off: u64) -> u32 {
        let mut value = u32::MAX;
        // SAFETY: as `read8`.
        let _ = unsafe { ffi::narf_mmio_read32(device(), self.bar, off, &mut value) };
        value
    }

    /// # Safety
    /// `off` names a writable register of the BAR.
    pub unsafe fn write8(&self, off: u64, value: u8) {
        // SAFETY: argument-only call; the kernel bounds-checks `off`.
        let _ = unsafe { ffi::narf_mmio_write8(device(), self.bar, off, value) };
    }

    /// # Safety
    /// `off` names a writable, 2-byte-aligned register of the BAR.
    pub unsafe fn write16(&self, off: u64, value: u16) {
        // SAFETY: as `write8`.
        let _ = unsafe { ffi::narf_mmio_write16(device(), self.bar, off, value) };
    }

    /// # Safety
    /// `off` names a writable, 4-byte-aligned register of the BAR.
    pub unsafe fn write32(&self, off: u64, value: u32) {
        // SAFETY: as `write8`.
        let _ = unsafe { ffi::narf_mmio_write32(device(), self.bar, off, value) };
    }
}

pub use time::Deadline;

/// Granularity of the module's responsive spin: one `narf_udelay` between
/// polls, during which the kernel's sleep pumps keep ticking.
const SPIN_STEP_NS: u64 = 1_000;

/// `narf_scheduler::responsive_spin_until`: poll `done` until it holds or
/// `deadline` passes, rechecking once at expiry. Between polls the module
/// waits in `narf_udelay`, so the console and framebuffer keep moving.
pub fn responsive_spin_until<F: FnMut() -> bool>(mut done: F, deadline: Deadline) -> bool {
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        // SAFETY: argument-only call, 1 µs.
        let _ = unsafe { ffi::narf_udelay(SPIN_STEP_NS) };
    }
}

/// `narf_bus` names: the bus address of the bound function and the BAR.
pub mod bus {
    pub use super::MmioRegion;

    /// `narf_bus::PcieAddr`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PcieAddr {
        pub segment: u16,
        pub bus: u8,
        pub device: u8,
        pub function: u8,
    }

    impl PcieAddr {
        pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
            Self {
                segment,
                bus,
                device,
                function,
            }
        }
    }

    /// `narf_bus::BusAddr` (PCIe is the only bus the module binds).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum BusAddr {
        Pcie(PcieAddr),
    }
}

/// `narf_time` names. Cycles are nanoseconds in the module: the module's
/// only clock is the kernel's monotonic nanosecond counter.
pub mod time {
    use super::*;

    /// A point on the monotonic clock.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Instant(narf_module_rt::time::Deadline);

    /// An absolute timeout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Deadline(narf_module_rt::time::Deadline);

    impl Deadline {
        pub fn after_ns(ns: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ns(ns))
        }
        pub fn after_us(us: u64) -> Self {
            Self::after_ns(us.saturating_mul(1_000))
        }
        pub fn after_ms(ms: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ms(ms))
        }
        pub fn expired(&self) -> bool {
            self.0.expired()
        }
        pub fn as_instant(&self) -> Instant {
            Instant(self.0)
        }
    }

    /// Completes once its instant has passed. Resolution is the executor's
    /// heartbeat (the 1 ms device poller).
    #[derive(Debug)]
    #[must_use = "futures do nothing unless polled"]
    pub struct SleepUntil(narf_module_rt::time::SleepUntil);

    impl SleepUntil {
        pub fn new(at: Instant) -> Self {
            Self(narf_module_rt::time::sleep_until(at.0))
        }
    }

    impl Future for SleepUntil {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.0).poll(cx)
        }
    }

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_module_rt::time::now_ns()
    }

    /// Nanoseconds to "cycles" (the identity: see the module doc).
    pub fn ns_to_cycles(ns: u64) -> u64 {
        ns
    }

    /// Sleep for `cycles` (nanoseconds).
    pub fn sleep_cycles(cycles: u64) -> SleepUntil {
        SleepUntil::new(Deadline::after_ns(cycles).as_instant())
    }

    /// Synchronous delay of `cycles` (nanoseconds) in `narf_udelay`, which
    /// keeps the kernel's sleep pumps ticking.
    pub fn busy_wait_cycles(cycles: u64) {
        let mut left = cycles;
        while left > 0 {
            let step = left.min(1_000_000_000);
            // SAFETY: argument-only call, 1 ns ..= 1 s.
            let _ = unsafe { ffi::narf_udelay(step) };
            left -= step;
        }
    }

    /// `narf_time::timeout`'s error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Elapsed;

    /// `fut`, or `Err(Elapsed)` once `deadline` passes first.
    pub fn timeout<F: Future>(deadline: Deadline, fut: F) -> Timeout<F> {
        Timeout {
            fut: alloc::boxed::Box::pin(fut),
            deadline,
        }
    }

    /// Future returned by [`timeout`].
    #[must_use = "futures do nothing unless polled"]
    pub struct Timeout<F> {
        fut: Pin<alloc::boxed::Box<F>>,
        deadline: Deadline,
    }

    impl<F> core::fmt::Debug for Timeout<F> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Timeout").finish_non_exhaustive()
        }
    }

    impl<F: Future> Future for Timeout<F> {
        type Output = Result<F::Output, Elapsed>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Poll::Ready(value) = self.fut.as_mut().poll(cx) {
                return Poll::Ready(Ok(value));
            }
            if self.deadline.expired() {
                return Poll::Ready(Err(Elapsed));
            }
            // The executor's heartbeat re-polls; ask for the next pass too.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// `narf_time::wall`.
    pub mod wall {
        pub use super::{monotonic_ns, ns_to_cycles};
    }
}

/// `narf_scheduler` names.
pub mod scheduler {
    use super::*;

    pub use super::responsive_spin_until;

    /// Spawn a driver task on the module's executor. Refused only after
    /// module exit stopped the executor, when nothing may run any more.
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
        let _ = EXEC.spawn(future);
    }

    /// Drive a self-advancing future to completion on the calling upcall.
    pub fn block_on<F: Future>(future: F) -> F::Output {
        narf_module_rt::exec::block_on(future)
    }

    /// As [`block_on`]: a module never holds an IRQ-masking lock.
    pub fn block_on_spin<F: Future>(future: F) -> F::Output {
        narf_module_rt::exec::block_on(future)
    }

    /// Yield once to the executor.
    pub fn yield_now() -> narf_module_rt::time::YieldNow {
        narf_module_rt::time::yield_now()
    }
}

/// `narf_lib` names.
pub mod lib {
    /// `narf_lib::sync`.
    pub mod sync {
        use core::cell::UnsafeCell;
        use core::sync::atomic::{AtomicU8, Ordering};
        pub use narf_module_rt::sync::{
            SpinLock as IrqSafeSpinLock, SpinLockGuard as IrqSafeSpinLockGuard,
        };

        /// `narf_lib::sync::OnceLock`: set once, then read freely.
        pub struct OnceLock<T> {
            state: AtomicU8,
            value: UnsafeCell<Option<T>>,
        }

        const EMPTY: u8 = 0;
        const WRITING: u8 = 1;
        const READY: u8 = 2;

        // SAFETY: the value is written once under the WRITING state and only
        // read after READY is published.
        unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
        // SAFETY: as above.
        unsafe impl<T: Send> Send for OnceLock<T> {}

        impl<T> Default for OnceLock<T> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<T: core::fmt::Debug> core::fmt::Debug for OnceLock<T> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple("OnceLock").field(&self.get()).finish()
            }
        }

        impl<T> OnceLock<T> {
            pub const fn new() -> Self {
                Self {
                    state: AtomicU8::new(EMPTY),
                    value: UnsafeCell::new(None),
                }
            }

            /// Install `value` once; the second set returns it back.
            pub fn set(&self, value: T) -> Result<(), T> {
                if self
                    .state
                    .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Err(value);
                }
                // SAFETY: the WRITING state makes this the only access.
                unsafe { *self.value.get() = Some(value) };
                self.state.store(READY, Ordering::Release);
                Ok(())
            }

            pub fn get(&self) -> Option<&T> {
                if self.state.load(Ordering::Acquire) != READY {
                    return None;
                }
                // SAFETY: READY: written once, never again.
                unsafe { (*self.value.get()).as_ref() }
            }

            pub fn get_or_init<F: FnOnce() -> T>(&self, init: F) -> &T {
                if let Some(value) = self.get() {
                    return value;
                }
                let _ = self.set(init());
                loop {
                    if let Some(value) = self.get() {
                        return value;
                    }
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// `narf_lib::mutex`: the async mutex.
    pub mod mutex {
        pub use narf_module_rt::sync::{Mutex, MutexGuard};
    }

    /// `narf_lib::id`.
    pub mod id {
        /// Allocation domain. The module allocates in its own effective
        /// domain whatever the driver names; the type keeps the signature.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct DomainId;
        impl DomainId {
            pub const DRIVER_0: DomainId = DomainId;
        }
    }
}

/// `narf_capabilities` names. A module holds no kernel capability; the
/// one kind whose current validity it can observe is a retained firmware
/// blob (an open `narf_firmware_*` handle, whose kernel binding keeps the
/// blob's own `Cap<FirmwareBlob, Read>`): `invoke` on it re-checks that
/// binding through `narf_firmware_signed` before the operation runs.
pub mod capabilities {
    use core::marker::PhantomData;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Read;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Write;

    /// The capability no longer proves current validity.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CapError {
        Revoked,
    }

    /// How a kind's current validity is observed.
    pub trait Kind {
        fn live(_handle: u64) -> bool {
            true
        }
    }

    pub struct Cap<T, R> {
        handle: u64,
        _kind: PhantomData<fn() -> (T, R)>,
    }

    impl<T, R> Clone for Cap<T, R> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T, R> Copy for Cap<T, R> {}
    impl<T, R> core::fmt::Debug for Cap<T, R> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Cap").field("handle", &self.handle).finish()
        }
    }
    impl<T, R> PartialEq for Cap<T, R> {
        fn eq(&self, other: &Self) -> bool {
            self.handle == other.handle
        }
    }
    impl<T, R> Eq for Cap<T, R> {}

    impl<T: Kind, R> Cap<T, R> {
        pub(crate) const fn from_handle(handle: u64) -> Self {
            Self {
                handle,
                _kind: PhantomData,
            }
        }
        pub(crate) fn handle(&self) -> u64 {
            self.handle
        }
        pub fn check_live(&self) -> Result<(), CapError> {
            if T::live(self.handle) {
                Ok(())
            } else {
                Err(CapError::Revoked)
            }
        }
        /// Run `op` only while this capability is current.
        pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
            self.check_live()?;
            op.execute(self)
        }
        pub fn derive<R2>(&self) -> Result<Cap<T, R2>, CapError> {
            self.check_live()?;
            Ok(Cap::from_handle(self.handle))
        }
    }

    pub trait CapOp<T, R> {
        type Output;
        fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
    }

    /// The operation that only proves current validity.
    #[derive(Clone, Copy, Debug)]
    pub struct NoopOp;
    impl<T, R> CapOp<T, R> for NoopOp {
        type Output = ();
        fn execute(self, _: &Cap<T, R>) -> Result<(), CapError> {
            Ok(())
        }
    }
}

/// `narf_firmware` names over `narf_firmware_open` / `_read` / `_signed`.
pub mod firmware {
    use super::capabilities::{Cap, Kind, Write};

    /// A retained, opened blob (`Cap<FirmwareBlob, _>` holds its handle).
    #[derive(Clone, Copy, Debug)]
    pub struct FirmwareBlob;
    impl Kind for FirmwareBlob {
        fn live(handle: u64) -> bool {
            // SAFETY: argument-only call on this module's own handle.
            handle != 0 && unsafe { super::ffi::narf_firmware_signed(handle) } >= 0
        }
    }

    /// The firmware registry; the module's `Firmware` manifest grant is its
    /// authority, which stays current while the module is loaded.
    #[derive(Clone, Copy, Debug)]
    pub struct FirmwareRegistry;
    impl Kind for FirmwareRegistry {}

    /// `narf_firmware::FirmwareError`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FirmwareError {
        NotFound,
        SignatureInvalid,
        BadFormat,
        OutOfMemory,
        AuthorityRevoked,
        UnsignedRejected,
        InvalidName,
        BufferTooSmall,
    }

    /// The module's registry authority (the `Firmware` manifest cap).
    pub fn trusted_loader_authority() -> Option<Cap<FirmwareRegistry, Write>> {
        Some(Cap::from_handle(0))
    }
}

/// `narf-drivers-wireless-core::firmware_asset` over the KABI.
pub mod firmware_asset {
    use super::capabilities::{Cap, Read};
    use super::firmware::{FirmwareBlob, FirmwareError, FirmwareRegistry};
    use super::*;

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;

    /// An owned copy of a firmware asset, with the retained blob that proves
    /// its current validity. The KABI reports only whether a verified signer
    /// exists, not which: `signer` is `Some([0; 32])` for a signed blob.
    #[derive(Debug)]
    pub struct Asset {
        pub bytes: Vec<u8>,
        pub cap: Cap<FirmwareBlob, Read>,
        pub signer: Option<[u8; 32]>,
        pub digest: [u8; 32],
    }

    impl Asset {
        pub fn current(&self) -> bool {
            self.cap.check_live().is_ok()
        }
    }

    fn open(name: &str) -> Result<(u64, usize), FirmwareError> {
        let (mut handle, mut size) = (0u64, 0usize);
        // SAFETY: `name` is a live `&str`; both outputs are live locals.
        let rc =
            unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
        if rc != 0 {
            return Err(FirmwareError::NotFound);
        }
        Ok((handle, size))
    }

    /// `firmware_asset::load`: open `name`, then [`copy`] it.
    pub fn load(
        authority: &Cap<FirmwareRegistry, Read>,
        name: &str,
        maximum: usize,
        signer: bool,
    ) -> Result<Asset, FirmwareError> {
        authority
            .check_live()
            .map_err(|_| FirmwareError::AuthorityRevoked)?;
        let (handle, _) = open(name)?;
        copy(&Cap::from_handle(handle), name, maximum, signer)
    }

    /// `firmware_asset::copy`: the whole retained blob, at most `maximum`
    /// bytes, refused unsigned when `signer` is required. The handle stays
    /// open (it is the asset's current-validity proof) until unload.
    pub fn copy(
        cap: &Cap<FirmwareBlob, Read>,
        _name: &str,
        maximum: usize,
        signer: bool,
    ) -> Result<Asset, FirmwareError> {
        let handle = cap.handle();
        // SAFETY: argument-only call on our open handle.
        let signed = match unsafe { ffi::narf_firmware_signed(handle) } {
            1 => true,
            0 => false,
            _ => return Err(FirmwareError::AuthorityRevoked),
        };
        if signer && !signed {
            return Err(FirmwareError::UnsignedRejected);
        }
        let mut bytes = Vec::new();
        let mut at = 0usize;
        loop {
            if bytes.len() > maximum {
                return Err(FirmwareError::BadFormat);
            }
            bytes
                .try_reserve(CHUNK)
                .map_err(|_| FirmwareError::OutOfMemory)?;
            let start = bytes.len();
            bytes.resize(start + CHUNK, 0);
            let mut got = 0usize;
            // SAFETY: `bytes[start..]` names CHUNK writable bytes.
            let rc = unsafe {
                ffi::narf_firmware_read(
                    handle,
                    at as u64,
                    bytes[start..].as_mut_ptr(),
                    CHUNK,
                    &mut got,
                )
            };
            if rc != 0 {
                return Err(FirmwareError::AuthorityRevoked);
            }
            bytes.truncate(start + got);
            at += got;
            if got == 0 {
                break;
            }
        }
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(FirmwareError::BadFormat);
        }
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(&bytes);
        Ok(Asset {
            digest: digest.finalize(),
            bytes,
            cap: *cap,
            signer: signed.then_some([0; 32]),
        })
    }
}

/// `narf-drivers-wireless-core::future_heap`.
pub mod future_heap {
    use alloc::boxed::Box;
    use core::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    /// Construct without polling, then retain the future in pinned heap
    /// storage (the separate frame keeps a parent from reserving it).
    #[inline(never)]
    pub fn build<F: Future>(make: impl FnOnce() -> F) -> HeapFuture<F> {
        HeapFuture {
            inner: Box::pin(make()),
        }
    }

    pub struct HeapFuture<F> {
        inner: Pin<Box<F>>,
    }

    impl<F> core::fmt::Debug for HeapFuture<F> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("HeapFuture").finish_non_exhaustive()
        }
    }

    impl<F: Future> Future for HeapFuture<F> {
        type Output = F::Output;
        #[inline(never)]
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }
}

/// `narf-drivers-wireless-core::watchdog_work`: the periodic step as a task
/// on the module's executor, holding the device weakly.
pub mod watchdog_work {
    use alloc::{boxed::Box, sync::Arc};
    use core::{future::Future, pin::Pin};

    /// A device whose watchdog step runs periodically.
    pub trait Watchdog: Send + Sync + 'static {
        fn watchdog_stopped(&self) -> bool;
        fn watchdog_step(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
    }

    /// Run `device`'s step every `period_ms`, the first one period from now,
    /// until the device is gone or reports itself withdrawn.
    pub fn start<D: Watchdog>(device: &Arc<D>, period_ms: u64) {
        let device = Arc::downgrade(device);
        super::scheduler::spawn(async move {
            loop {
                super::time::sleep_cycles(period_ms.saturating_mul(1_000_000)).await;
                match device.upgrade() {
                    Some(device) if !device.watchdog_stopped() => device.watchdog_step().await,
                    _ => return,
                }
            }
        });
    }
}

/// `narf_io` names: coherent DMA over `narf_dma_alloc_mapped`.
///
/// rtlwifi allocates a buffer per RX/TX frame and per descriptor ring. KABI
/// DMA handles are never reused, so small buffers come from size-class
/// pools carved out of 1 MiB mapped chunks (the `ath11k.ko` scheme) and go
/// back to their pool on drop; large ones are allocated and freed directly.
pub mod io {
    use super::lib::id::DomainId;
    use super::*;

    /// `narf_io::IoError`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IoError {
        OutOfMemory,
    }

    /// Device-visible address.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DmaAddr(u64);
    impl DmaAddr {
        pub fn raw(self) -> u64 {
            self.0
        }
    }

    /// `narf_io::iommu`: KABI mapped DMA already returns the device's bus
    /// address, so per-domain translation is the kernel's concern.
    pub mod iommu {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum IommuMode {
            Off,
            PerDomain,
        }
        pub fn mode() -> IommuMode {
            IommuMode::Off
        }
    }

    const PAGE: usize = 4096;
    const MAX_POOLED: usize = 64 * 1024;
    const CHUNK: usize = 1 << 20;
    const CLASSES: usize = 5;

    #[derive(Clone, Copy)]
    struct Block {
        cpu: usize,
        bus: u64,
    }

    /// Free blocks per (address limit, class): index 0 the 32-bit pool,
    /// index 1 unrestricted. Other limits are allocated directly.
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

    // SAFETY: plain memory owned by this value; cross-CPU sharing is what
    // the driver's ring protocol already arbitrates.
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
            return Err(IoError::OutOfMemory);
        }
        Ok((handle, cpu, bus, got))
    }

    /// `narf_io::alloc_coherent_masked`: zeroed, wholly below `mask`.
    pub fn alloc_coherent_masked(
        len: usize,
        _domain: DomainId,
        mask: u64,
    ) -> Result<DmaBuffer, IoError> {
        let bits = (64 - mask.leading_zeros()).clamp(32, 64);
        let size = len.max(1).next_power_of_two().max(PAGE);
        if size > MAX_POOLED || !matches!(bits, 32 | 64) {
            let (handle, cpu, bus, got) = mapped(size, bits)?;
            return Ok(DmaBuffer {
                cpu,
                bus,
                len: len.min(got),
                origin: Origin::Direct { handle },
            });
        }
        let pool = usize::from(bits == 64);
        let class = (size / PAGE).trailing_zeros() as usize;
        let block = POOLS.lock()[pool][class].pop();
        let block = match block {
            Some(block) => block,
            None => {
                // The chunk's handle lives as long as the device: teardown
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
        pub fn cpu_ptr_at<T>(&self, offset: u64) -> *const T {
            (self.cpu + offset as usize) as *const T
        }
        pub fn cpu_mut_ptr_at<T>(&self, offset: u64) -> *mut T {
            (self.cpu + offset as usize) as *mut T
        }
        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: `cpu` names at least `len` bytes owned by this buffer.
            unsafe { core::slice::from_raw_parts(self.cpu as *const u8, self.len) }
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: as above; `&mut self` makes the borrow unique.
            unsafe { core::slice::from_raw_parts_mut(self.cpu as *mut u8, self.len) }
        }
        pub fn as_ptr(&self) -> *const u8 {
            self.cpu as *const u8
        }
        pub fn as_mut_ptr(&self) -> *mut u8 {
            self.cpu as *mut u8
        }
        /// `narf_io::DmaBuffer::sync`. KABI mapped DMA is cache-coherent
        /// (`narf_pci_prepare_probe` clears No Snoop), so only the ordering
        /// of the CPU's accesses against the device's is needed.
        pub fn sync(&self, _offset: usize, _len: usize) {
            core::sync::atomic::fence(Ordering::SeqCst);
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
                    // SAFETY: our own allocation, freed exactly once, here.
                    let _ = unsafe { ffi::narf_dma_free(device(), handle) };
                }
            }
        }
    }
}

/// `narf_ipc` names: a bounded single-producer/single-consumer channel.
pub mod ipc {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;

    struct Ring<T> {
        queue: IrqSafeSpinLock<VecDeque<T>>,
        capacity: usize,
        closed: core::sync::atomic::AtomicBool,
    }

    /// `narf_ipc::TrySendError`.
    #[derive(Debug)]
    pub enum TrySendError<T> {
        Full(T),
        Closed(T),
    }

    /// `narf_ipc::RecvError`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RecvError {
        Closed,
    }

    pub struct Producer<T, const N: usize>(Arc<Ring<T>>);
    pub struct Consumer<T, const N: usize>(Arc<Ring<T>>);

    impl<T, const N: usize> core::fmt::Debug for Producer<T, N> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Producer").finish_non_exhaustive()
        }
    }
    impl<T, const N: usize> core::fmt::Debug for Consumer<T, N> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Consumer").finish_non_exhaustive()
        }
    }

    /// A channel of capacity `N`.
    pub fn channel<T, const N: usize>() -> (Producer<T, N>, Consumer<T, N>) {
        let ring = Arc::new(Ring {
            queue: IrqSafeSpinLock::new(VecDeque::new()),
            capacity: N,
            closed: core::sync::atomic::AtomicBool::new(false),
        });
        (Producer(ring.clone()), Consumer(ring))
    }

    impl<T, const N: usize> Producer<T, N> {
        pub fn try_send(&mut self, msg: T) -> Result<(), TrySendError<T>> {
            if self.0.closed.load(Ordering::Acquire) {
                return Err(TrySendError::Closed(msg));
            }
            let mut queue = self.0.queue.lock();
            if queue.len() >= self.0.capacity {
                return Err(TrySendError::Full(msg));
            }
            queue.push_back(msg);
            Ok(())
        }
        pub fn len(&self) -> usize {
            self.0.queue.lock().len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl<T, const N: usize> Consumer<T, N> {
        pub fn try_recv(&mut self) -> Result<Option<T>, RecvError> {
            let next = self.0.queue.lock().pop_front();
            match next {
                Some(msg) => Ok(Some(msg)),
                None if Arc::strong_count(&self.0) == 1 => Err(RecvError::Closed),
                None => Ok(None),
            }
        }
        pub fn len(&self) -> usize {
            self.0.queue.lock().len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl<T, const N: usize> Drop for Consumer<T, N> {
        fn drop(&mut self) {
            self.0.closed.store(true, Ordering::Release);
        }
    }
}

/// `narf_net` names: frames, TX metadata, and the interface calls the
/// driver makes, served by the module's netdev (`iface_module`).
pub mod net {
    use super::io::DmaBuffer;

    pub const RX_RING_N: usize = 1024;
    pub const TX_RING_N: usize = 1024;

    /// `narf_net::L4CsumKind`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum L4CsumKind {
        Tcp,
        Udp,
    }

    /// `narf_net::TxMeta`. The netif bridge hands the module plain frames,
    /// so every field stays at its default.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct TxMeta {
        pub csum_l4: Option<L4CsumKind>,
        pub tso_mss: Option<u16>,
        pub vlan_tag: Option<u16>,
        pub more: bool,
    }

    /// `narf_net::Frame`: `len` bytes in an owned buffer.
    #[derive(Debug)]
    pub struct Frame {
        buf: DmaBuffer,
        len: u32,
        tx_meta: TxMeta,
    }

    impl Frame {
        pub fn new(buf: DmaBuffer, len: u32) -> Self {
            Self {
                buf,
                len,
                tx_meta: TxMeta::default(),
            }
        }
        pub fn len(&self) -> u32 {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[..self.len as usize]
        }
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let len = self.len as usize;
            &mut self.buf.as_mut_slice()[..len]
        }
        pub fn tx_meta(&self) -> TxMeta {
            self.tx_meta
        }
        pub fn set_tx_meta(&mut self, meta: TxMeta) {
            self.tx_meta = meta;
        }
    }

    /// `narf_net::Interface`: what a netdev exposes. The module's netdev is
    /// the bridge's; the driver's implementation stays the same.
    pub trait Interface: Send + Sync {
        fn name(&self) -> &str;
        fn mac(&self) -> [u8; 6];
        fn mtu(&self) -> u32;
        fn link_up(&self) -> bool;
        fn rx_ring(
            &self,
        ) -> &super::IrqSafeSpinLock<Option<super::ipc::Consumer<Frame, RX_RING_N>>>;
        fn tx_ring(
            &self,
        ) -> &super::IrqSafeSpinLock<Option<super::ipc::Producer<Frame, TX_RING_N>>>;
    }

    /// `narf_net::trusted_net_authority`: the module's `NetIface` manifest
    /// grant is its net authority, current while the module is loaded.
    pub fn trusted_net_authority() -> Option<()> {
        Some(())
    }

    /// `narf_net::iface`: the calls a published device makes on its netdev.
    pub mod iface {
        /// The netif bridge names the module's netdev (`wlan%d`) when it
        /// registers; the driver's own name only labels its logs.
        pub fn reserve_name(_pattern: &str) -> &'static str {
            "wlan"
        }
        /// Deliver one received Ethernet frame (`narf_netif_rx`).
        pub fn on_rx_frame_from(name: &str, bytes: &mut [u8]) {
            crate::module_netdev::rx(name, bytes);
        }
        /// Carrier follows the association (`CONNECT_RESULT`/`DISCONNECTED`
        /// reports are the module netdev's).
        pub fn set_link_metadata(
            name: &str,
            up: bool,
            _speed: Option<u32>,
            _duplex: Option<bool>,
        ) -> bool {
            crate::module_netdev::link(name, up);
            true
        }

        /// `narf_net::iface::NetIfaceSnapshot`. The bridge owns the module's
        /// netdev, so no administrative binding exists: [`lookup`] finds
        /// none, and a device without a binding is administratively open
        /// (the module has no IFF_UP event; the station opens at publish).
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct NetIfaceSnapshot {
            pub name: alloc::string::String,
            pub mac: [u8; 6],
            pub link_up: bool,
        }

        /// `narf_net::iface::OpenStopEvent` (never delivered to a module).
        #[derive(Clone, Debug)]
        pub struct OpenStopEvent {
            name: alloc::string::String,
            up: bool,
        }
        impl OpenStopEvent {
            pub fn name(&self) -> &str {
                &self.name
            }
            pub fn up(&self) -> bool {
                self.up
            }
            pub fn current(&self) -> bool {
                false
            }
        }

        /// `narf_net::iface::OpenStopTarget`.
        pub trait OpenStopTarget: Send + Sync {
            fn transition(&self, event: OpenStopEvent);
        }

        pub fn lookup(_name: &str) -> Option<NetIfaceSnapshot> {
            None
        }
        pub fn set_link_metadata_for(
            binding: &NetIfaceSnapshot,
            up: bool,
            _speed: Option<u32>,
            _duplex: Option<bool>,
        ) -> bool {
            crate::module_netdev::link(&binding.name, up);
            true
        }
        pub fn withdraw_link_metadata_for(binding: &NetIfaceSnapshot) -> bool {
            crate::module_netdev::link(&binding.name, false);
            true
        }
        pub fn set_open_stop_target(
            _binding: &NetIfaceSnapshot,
            _target: alloc::sync::Arc<dyn OpenStopTarget>,
        ) -> bool {
            false
        }
    }
}

/// `narf_wireless` kernel-side names (the station trait, nl80211 events and
/// rfkill), served by the module's wiphy.
pub mod wireless {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use narf_wireless::{
        iface::PhyCapabilities, AssociateRequest, BssInfo, ScanRequest, WirelessConfig,
        WirelessError, WirelessIfaceInfo, WowlanConfig, WowlanSupport,
    };

    /// `narf_wireless::WirelessNetIface`, the methods the driver implements.
    /// Built in, nl80211 calls them; in the module the `WIFI` family host's
    /// events do (`rtlwifi::iface_module`).
    /// The defaults are the kernel trait's.
    #[async_trait::async_trait]
    pub trait WirelessNetIface: super::net::Interface {
        fn rts_threshold(&self) -> Option<u32> {
            None
        }
        fn set_rts_threshold(&self, _threshold: u32) -> Result<(), i32> {
            Err(narf_wireless::EOPNOTSUPP)
        }
        fn supports_handshake_offload(&self) -> bool {
            false
        }
        fn reports_disconnect_events(&self) -> bool {
            false
        }
        fn supports_scan_dwell(&self) -> bool {
            false
        }
        fn max_scan_ssids(&self) -> u8 {
            0
        }
        fn max_scan_ie_len(&self) -> u16 {
            512
        }
        fn wowlan_support(&self) -> Option<WowlanSupport> {
            None
        }
        fn set_wowlan(&self, _config: Option<WowlanConfig>) -> Result<(), i32> {
            Err(narf_wireless::EOPNOTSUPP)
        }
        fn wowlan_config(&self) -> Option<WowlanConfig> {
            None
        }
        fn connected_bssid(&self) -> Option<[u8; 6]> {
            None
        }
        fn cipher_suites(&self) -> &'static [u32] {
            &[]
        }
        fn scan_information_elements(&self, _bssid: [u8; 6]) -> Option<Vec<u8>> {
            None
        }
        fn get_wireless_info(&self) -> WirelessIfaceInfo;
        fn phy_capabilities(&self, _band: u32) -> Option<PhyCapabilities> {
            None
        }
        async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;
        async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError>;
        async fn disassociate(&self) -> Result<(), WirelessError>;
        async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError>;
    }

    /// `narf_wireless::nl80211`.
    pub mod nl80211 {
        /// An unsolicited disconnect (`DISCONNECTED` to the family host).
        pub fn notify_disconnect(name: &str, reason: u16, local: bool) {
            crate::module_netdev::disconnected(name, reason, local);
        }
    }
    /// `narf_wireless::rfkill`: no rfkill switch reaches a module.
    pub mod rfkill {
        pub fn blocked(_wiphy: u64) -> bool {
            false
        }
    }
}

/// The kernel's active regulatory domain (`narf_wireless::reg::db`), read
/// through `narf_wireless_regdomain` as an NRGD record.
pub mod regdb {
    use alloc::sync::Arc;
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

    use super::*;

    /// Why no domain could be had (`reg::policy::Error`'s role).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Authority,
        Format(&'static str),
    }

    /// The largest NRGD record: 12-byte header, 64 rules of 16 bytes.
    const MAX: usize = 12 + 64 * 16;

    fn decode(bytes: &[u8]) -> Result<RegulatoryDomain, Error> {
        if bytes.len() < 12 || &bytes[..4] != b"NRGD" || bytes[4..6] != [1, 0] {
            return Err(Error::Format("invalid regulatory record header"));
        }
        let count = usize::from(u16::from_le_bytes([bytes[8], bytes[9]]));
        if bytes.len() != 12 + count * 16 {
            return Err(Error::Format("invalid regulatory rule count"));
        }
        let mut rules = Vec::with_capacity(count);
        for raw in bytes[12..].chunks_exact(16) {
            let word = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
            rules.push(RegRule {
                freq_start_mhz: word(0),
                freq_end_mhz: word(4),
                max_bandwidth_mhz: word(8),
                max_power_dbm: raw[12] as i8,
                flags: RegFlags::from_bits(u32::from(raw[13]) | u32::from(raw[14]) << 8)
                    .ok_or(Error::Format("unknown regulatory flags"))?,
            });
        }
        Ok(RegulatoryDomain {
            country_code: [bytes[6], bytes[7]],
            rules,
        })
    }

    /// The kernel's current installation, if one exists.
    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        let mut buf = alloc::vec![0u8; MAX];
        let mut len = 0usize;
        // SAFETY: `buf` names MAX writable bytes; `len` is a live local.
        let rc = unsafe { ffi::narf_wireless_regdomain(buf.as_mut_ptr(), buf.len(), &mut len) };
        if rc != 0 || len > buf.len() {
            return None;
        }
        decode(&buf[..len]).ok().map(Arc::new)
    }

    pub fn get_domain() -> Option<RegulatoryDomain> {
        snapshot().map(|domain| domain.as_ref().clone())
    }

    /// The kernel bootstraps its signed (or Linux-database) policy when no
    /// domain is installed yet; the export reports the result.
    pub fn ensure_domain() -> Result<RegulatoryDomain, Error> {
        get_domain().ok_or(Error::Authority)
    }

    pub fn ensure_snapshot() -> Result<Arc<RegulatoryDomain>, Error> {
        snapshot().ok_or(Error::Authority)
    }

    /// `reg::db::Database` (a private installation, for fixtures).
    #[derive(Debug, Default)]
    pub struct Database {
        domain: IrqSafeSpinLock<Option<Arc<RegulatoryDomain>>>,
    }

    impl Database {
        pub const fn new() -> Self {
            Self {
                domain: IrqSafeSpinLock::new(None),
            }
        }
        pub fn install(&self, domain: RegulatoryDomain) {
            *self.domain.lock() = Some(Arc::new(domain));
        }
        pub fn clear(&self) {
            *self.domain.lock() = None;
        }
        pub fn snapshot(&self) -> Option<Arc<RegulatoryDomain>> {
            self.domain.lock().clone()
        }
    }
}

/// The shared Realtek USB transport over the `narf_usb_*` KABI.
#[path = "usb_kabi.rs"]
pub mod rtl_usb;

/// `narf_drivers_usb` names rtl8xxxu uses.
pub mod usb {
    pub use super::rtl_usb::{USBDevice, UsbError};
}

/// `narf_wireless::reg::policy`: the signed deployment policy rtl8xxxu's
/// admission reads. A module sees the kernel's installation, which the
/// kernel bootstraps from that same policy (`narf_wireless_regdomain`); no
/// installation reads as the policy asset not being staged yet.
pub mod regpolicy {
    use super::firmware::FirmwareError;
    use narf_wireless::reg::RegulatoryDomain;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Authority,
        Firmware(FirmwareError),
        Unsigned,
        Format(&'static str),
    }

    pub fn load() -> Result<RegulatoryDomain, Error> {
        super::regdb::get_domain().ok_or(Error::Firmware(FirmwareError::NotFound))
    }
}

/// `narf_console` names.
pub mod console {
    pub use super::Console as Writer;
}
