//! Module platform: the built-in platform's names over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! Everything here runs in task context on whichever CPU's upcall (probe,
//! the 1 ms device poller, an MSI vector callback) is driving the module's
//! [`EXEC`]utor. The device token is set once by probe; the DMA pool needs it
//! to allocate.

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll};

use narf_module_rt::exec::Executor;

pub use narf_module_rt::console::Console;
pub use narf_module_rt::sync::{Mutex, MutexGuard, SpinLock as IrqSafeSpinLock};

/// KABI exports the platform itself calls.
pub(crate) mod ffi {
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
        pub fn narf_random_bytes(buf: *mut u8, len: usize) -> i32;
        pub fn narf_udelay(ns: u64) -> i32;
        pub fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
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
        pub fn narf_firmware_close(handle: u64) -> i32;
        pub fn narf_smbios_read(off: usize, buf: *mut u8, len: usize, out_total: *mut usize)
            -> i32;
    }
}

/// Synchronous hardware delay (`narf_udelay`, ≤ 1 s per call), during which
/// the kernel's sleep pumps keep ticking.
pub fn delay_ms(ms: u32) {
    let mut left = u64::from(ms);
    while left > 0 {
        let step = left.min(1000);
        // SAFETY: argument-only call, 1 ms ..= 1 s.
        let _ = unsafe { ffi::narf_udelay(step * 1_000_000) };
        left -= step;
    }
}

/// The firmware's raw SMBIOS structure table (empty when it has none).
pub fn smbios_table() -> Vec<u8> {
    let mut total = 0usize;
    // SAFETY: sizing call — null buffer, zero length, live `total`.
    if unsafe { ffi::narf_smbios_read(0, core::ptr::null_mut(), 0, &mut total) } != 0 || total == 0
    {
        return Vec::new();
    }
    let mut table = alloc::vec![0u8; total];
    // SAFETY: `table` names `total` writable bytes.
    if unsafe { ffi::narf_smbios_read(0, table.as_mut_ptr(), total, &mut total) } != 0 {
        return Vec::new();
    }
    table.truncate(total);
    table
}

/// The CPU running the caller, for spreading TX rings. A module has no CPU
/// id export; every flow uses ring 0's CPU slot, which is correct, only
/// less spread.
pub fn current_cpu() -> u32 {
    0
}

/// The module's executor: every driver future runs here.
pub static EXEC: Executor = Executor::new();

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

/// Spawn a driver task on the module's executor. Refused only after
/// module exit has stopped the executor, when nothing may run any more.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    let _ = EXEC.spawn(future);
}

/// Drive one self-advancing future to completion on the calling upcall
/// (the kernel's `block_on_spin` contract: it must not need another task).
pub fn block_on_spin<F: Future>(future: F) -> F::Output {
    narf_module_rt::exec::block_on(future)
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (SAE commit scalars, nonces).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// Wi-Fi status counters. Built in these feed the framebuffer status panel;
/// a module has no panel export, so stage changes and the first latched
/// error go to the console instead — the same facts, in the boot log.
pub mod diag {
    use super::*;

    /// Same stages, same order, as `narf_memory::diag::WifiStage`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum WifiStage {
        None = 0,
        Probe = 1,
        PowerUp = 2,
        Transport = 3,
        FwBoot = 4,
        Control = 5,
        Commands = 6,
        DataPath = 7,
        Scan = 8,
        Connected = 9,
        Recovery = 10,
    }

    static STAGE: AtomicU8 = AtomicU8::new(0);
    static ERROR: AtomicU64 = AtomicU64::new(0);

    pub fn set_wifi_stage(stage: WifiStage) {
        if STAGE.swap(stage as u8, Ordering::AcqRel) != stage as u8 {
            narf_module_rt::printkln!("  ath11k.ko: wifi stage {:?}", stage);
        }
    }

    pub fn latch_wifi_error(err: u32, detail: u32) {
        if err != 0
            && ERROR
                .compare_exchange(0, u64::from(err), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            narf_module_rt::printkln!(
                "  ath11k.ko: wifi FAILED step={} detail={:#x} (stage {})",
                err,
                detail,
                STAGE.load(Ordering::Acquire)
            );
        }
    }

    pub fn note_wifi_crash() {
        narf_module_rt::printkln!("  ath11k.ko: firmware crash");
        set_wifi_stage(WifiStage::Recovery);
    }

    pub fn note_wifi_recovered() {
        narf_module_rt::printkln!("  ath11k.ko: firmware recovered");
    }
}

/// Monotonic clock, deadlines and sleeps with the kernel's names. Sleeps
/// complete on the executor's heartbeat (the 1 ms device poller).
pub mod time {
    use super::*;

    /// A point on the monotonic clock.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Instant(narf_module_rt::time::Deadline);

    /// An absolute timeout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Deadline(narf_module_rt::time::Deadline);

    impl Deadline {
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

    /// Completes once its instant has passed.
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
}

/// Coherent DMA memory the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// ath11k allocates a fresh buffer for every RX refill and every TX frame.
/// KABI DMA handles are never reused, so per-packet KABI allocations would
/// grow the device context without bound; small buffers therefore come from
/// size-class pools carved out of 1 MiB mapped chunks and go back to their
/// pool on drop. Large ones (firmware segments, link-descriptor banks) are
/// allocated and freed directly.
pub mod dma {
    use super::*;

    /// Allocation domain. The module allocates in its own effective domain
    /// whatever the driver asks for; the type keeps the built-in signature.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DomainId;
    impl DomainId {
        pub const DRIVER_0: DomainId = DomainId;
    }

    /// Device-visible address.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DmaAddr(u64);
    impl DmaAddr {
        pub fn raw(self) -> u64 {
            self.0
        }
    }

    /// Allocation failure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NoMemory;

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

    fn mapped(len: usize, addr_bits: u32) -> Result<(u64, usize, u64, usize), NoMemory> {
        let (mut cpu, mut bus, mut got) = (0usize, 0u64, 0usize);
        // SAFETY: the three outputs are live locals.
        let handle = unsafe {
            ffi::narf_dma_alloc_mapped(device(), len, addr_bits, &mut cpu, &mut bus, &mut got)
        };
        if handle == 0 || cpu == 0 {
            return Err(NoMemory);
        }
        Ok((handle, cpu, bus, got))
    }

    fn addr_bits(mask: u64) -> u32 {
        64 - mask.leading_zeros()
    }

    /// `narf_io::alloc_coherent_masked`: zeroed, wholly below `mask`.
    pub fn alloc_coherent_masked(
        len: usize,
        _domain: DomainId,
        mask: u64,
    ) -> Result<DmaBuffer, NoMemory> {
        let bits = addr_bits(mask).clamp(32, 64);
        let size = len.max(1).next_power_of_two().max(PAGE);
        // A pool holds blocks of one address limit: a block carved under a
        // 64-bit limit must never satisfy a narrower request.
        if size > MAX_POOLED || !matches!(bits, 32 | 64) {
            let (handle, cpu, bus, got) = mapped(size, bits)?;
            return Ok(DmaBuffer {
                cpu,
                bus,
                len: got,
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
            len: size,
            origin: Origin::Pooled { pool, class },
        })
    }

    /// `narf_io::alloc_coherent`: no address limit.
    pub fn alloc_coherent(len: usize, domain: DomainId) -> Result<DmaBuffer, NoMemory> {
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

/// Interrupt handlers. Built in these run in hard-IRQ context and several
/// may share a vector; a module gets one task-context callback per vector
/// (`narf_irq_set_handler`). So the module keeps its own per-vector handler
/// table behind one [`trampoline`] per vector, which runs every handler on
/// the vector and then the executor — the handlers only set pending bits and
/// wake, exactly as they do built in.
pub mod irq {
    use super::*;

    /// A handler's verdict (the built-in type's variants).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IrqStatus {
        Handled,
        None,
    }

    /// A vector handler, called with its install cookie.
    pub type Handler = fn(u64) -> IrqStatus;

    #[derive(Clone, Copy)]
    struct Entry {
        vector: u8,
        name: &'static str,
        cookie: u64,
        handler: Handler,
    }

    static HANDLERS: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

    /// Add `handler` to `vector`'s chain (the built-in signature).
    pub fn install_handler_named(vector: u8, name: &'static str, cookie: u64, handler: Handler) {
        HANDLERS.lock().push(Entry {
            vector,
            name,
            cookie,
            handler,
        });
    }

    /// Remove the matching handler; `true` if one was installed.
    pub fn remove_handler(vector: u8, name: &str, cookie: u64) -> bool {
        let mut handlers = HANDLERS.lock();
        let before = handlers.len();
        handlers.retain(|e| !(e.vector == vector && e.name == name && e.cookie == cookie));
        handlers.len() != before
    }

    /// Bind `vector`'s KABI callback to the trampoline. Called once per
    /// granted MSI vector, after the kernel programmed the block.
    pub fn bind_vector(vector: u16) -> i32 {
        // SAFETY: `trampoline` is a valid `extern "C" fn(u64) -> i32` in this
        // module's text, which the kernel unbinds before unmapping it.
        unsafe {
            ffi::narf_irq_set_handler(device(), vector, trampoline as usize, u64::from(vector))
        }
    }

    /// Task-context upcall for one vector: run its handlers, then the
    /// executor so the woken tasks make progress on this CPU now.
    pub extern "C" fn trampoline(vector: u64) -> i32 {
        let entries: Vec<Entry> = HANDLERS
            .lock()
            .iter()
            .filter(|e| u64::from(e.vector) == vector)
            .copied()
            .collect();
        for entry in entries {
            let _ = (entry.handler)(entry.cookie);
        }
        let _ = EXEC.run();
        0
    }
}

/// Firmware lookup through `narf_firmware_open` / `_read` / `_signed`.
pub mod firmware {
    use super::*;

    /// Why a firmware file could not be had (the built-in variants).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FwError {
        NotFound,
        NoMemory,
        Invalid,
        NoAuthority,
        Revoked,
    }

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;

    /// `request_firmware` for a module. The module's `Firmware` manifest cap
    /// is its authority, so construction cannot fail.
    #[derive(Debug, Default)]
    pub struct Loader;

    impl Loader {
        pub fn new() -> Result<Self, FwError> {
            Ok(Self)
        }

        /// The whole file, at most `max` bytes; `signed` requires a verified
        /// signer (board, regulatory and calibration data), as built in.
        pub fn load(&self, name: &str, max: usize, signed: bool) -> Result<Vec<u8>, FwError> {
            let (mut handle, mut size) = (0u64, 0usize);
            // SAFETY: `name` is a live `&str`; both outputs are live locals.
            let rc = unsafe {
                ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size)
            };
            if rc != 0 {
                return Err(FwError::NotFound);
            }
            let result = (|| {
                if size == 0 || size > max {
                    return Err(FwError::Invalid);
                }
                // SAFETY: argument-only call on our open handle.
                if signed && unsafe { ffi::narf_firmware_signed(handle) } != 1 {
                    return Err(FwError::Invalid);
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(size)
                    .map_err(|_| FwError::NoMemory)?;
                bytes.resize(size, 0);
                let mut at = 0usize;
                while at < size {
                    let want = (size - at).min(CHUNK);
                    let mut got = 0usize;
                    // SAFETY: `bytes[at..at + want]` is writable and in bounds.
                    let rc = unsafe {
                        ffi::narf_firmware_read(
                            handle,
                            at as u64,
                            bytes[at..].as_mut_ptr(),
                            want,
                            &mut got,
                        )
                    };
                    if rc != 0 || got == 0 {
                        return Err(FwError::Invalid);
                    }
                    at += got;
                }
                Ok(bytes)
            })();
            // SAFETY: closing our own open handle once.
            let _ = unsafe { ffi::narf_firmware_close(handle) };
            result
        }
    }
}
