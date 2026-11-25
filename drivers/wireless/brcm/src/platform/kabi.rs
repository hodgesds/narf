//! Module platform: the built-in platform's names over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! Everything here runs in task context on whichever CPU's upcall (probe,
//! the 1 ms device poller, the MSI vector callback) is driving the module's
//! [`EXEC`]utor. The device token is set once by probe; the DMA pool and the
//! PCI accessors need it.

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
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
        pub fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    }
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

/// Spawn a driver task on the module's executor. Refused only after module
/// exit has stopped the executor, when nothing may run any more.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    let _ = EXEC.spawn(future);
}

/// Drive one self-advancing future to completion on the calling upcall
/// (the kernel's `block_on_spin` contract: it must not need another task).
pub fn block_on_spin<F: Future>(future: F) -> F::Output {
    narf_module_rt::exec::block_on(future)
}

/// The kernel's `block_on`: a module upcall cannot halt for an interrupt,
/// so this is [`block_on_spin`].
pub fn block_on<F: Future>(future: F) -> F::Output {
    narf_module_rt::exec::block_on(future)
}

/// `narf_scheduler::responsive_spin_until`: poll `done` until it holds or
/// `deadline` passes, delaying through `narf_udelay` (which keeps the
/// kernel's sleep pumps ticking) between polls. Returns the last verdict.
pub fn responsive_spin_until<F: FnMut() -> bool>(mut done: F, deadline: time::Deadline) -> bool {
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        let step = deadline.remaining_ns().clamp(1_000, 1_000_000);
        // SAFETY: argument-only call, 1 µs ..= 1 ms.
        let _ = unsafe { ffi::narf_udelay(step) };
    }
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (SAE scalars, the boot-time random seed).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// `narf_io::iommu::DmaBlock`. A module cannot block its function at the
/// IOMMU; its backplane always reports `Untranslated`, leaving the
/// device-side stop proof as the only quiescence evidence (and the device
/// context retains the DMA on teardown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaBlock {
    Blocked,
    Untranslated,
}

/// Monotonic clock, deadlines and sleeps with the kernel's names. A module
/// has no cycle counter export: one "cycle" is one nanosecond, so
/// `sleep_cycles(ns_to_cycles(n))` sleeps `n` ns. Sleeps complete on the
/// executor's heartbeat (the 1 ms device poller).
pub mod time {
    use super::*;

    /// An absolute timeout (`narf_time::Deadline`).
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
        pub fn remaining_ns(&self) -> u64 {
            self.0.remaining_ns()
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

    /// Sleep `cycles` (nanoseconds, see the module docs).
    pub fn sleep_cycles(cycles: u64) -> SleepUntil {
        SleepUntil(narf_module_rt::time::sleep_until(
            narf_module_rt::time::Deadline::after_ns(cycles),
        ))
    }

    /// Cycle/nanosecond conversion and the monotonic clock.
    pub mod wall {
        /// One module "cycle" is one nanosecond.
        pub fn ns_to_cycles(ns: u64) -> u64 {
            ns
        }
        /// Nanoseconds on the monotonic clock.
        pub fn monotonic_ns() -> u64 {
            narf_module_rt::time::now_ns()
        }
    }
}

/// Bus identity types the provisioning records bind to: the fields of
/// `narf_bus::{BusAddr, PcieAddr, DeviceId}` and
/// `narf_drivers_sdio::pio::HostIdentity`, rebuilt from
/// `narf_pci_identity` in the module.
pub mod bus {
    /// PCIe segment/bus/device/function.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// A physical MMIO address (an SDHCI platform host's record key).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhysAddr(u64);
    impl PhysAddr {
        pub const fn new(address: u64) -> Self {
            Self(address)
        }
    }
    /// Where a function sits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BusAddr {
        Pcie(PcieAddr),
        Mmio(PhysAddr),
    }
    /// The function's PCI identity.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceId {
        pub vendor: u16,
        pub device: u16,
        pub class: u32,
        pub subsystem_vendor: u16,
        pub subsystem_id: u16,
    }
    /// Immutable host facts a board-selection record binds to.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HostIdentity {
        pub address: BusAddr,
        pub id: DeviceId,
    }
}

/// Coherent DMA memory the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// The msgbuf runtime allocates a fresh buffer for every TX frame. KABI DMA
/// handles are never reused, so per-packet KABI allocations would grow the
/// device context without bound; small buffers therefore come from
/// size-class pools carved out of 1 MiB mapped chunks and go back to their
/// pool on drop (the `ath11k.ko` design). Large ones (rings, the flow-ring
/// table) are allocated and freed directly. Every buffer is below 4 GiB:
/// brcmfmac keeps the PCI default 32-bit coherent mask.
pub mod dma {
    use super::*;

    const PAGE: usize = 4096;
    /// Largest pooled block; bigger requests go straight to the kernel.
    const MAX_POOLED: usize = 64 * 1024;
    /// Pool refill unit.
    const CHUNK: usize = 1 << 20;
    /// Size classes: 4 KiB, 8 KiB, ..., 64 KiB.
    const CLASSES: usize = 5;
    /// brcmfmac never widens the PCI default coherent mask.
    const ADDR_BITS: u32 = 32;

    #[derive(Clone, Copy)]
    struct Block {
        cpu: usize,
        bus: u64,
    }

    static POOLS: IrqSafeSpinLock<[Vec<Block>; CLASSES]> =
        IrqSafeSpinLock::new([Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()]);

    enum Origin {
        Pooled { class: usize },
        Direct { handle: u64 },
    }

    /// Allocation failure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NoMemory;

    /// A coherent buffer: `len` bytes at `cpu` (CPU) / `bus` (device).
    pub struct DmaBuffer {
        cpu: usize,
        bus: u64,
        len: usize,
        origin: Origin,
    }

    // SAFETY: the buffer is plain memory owned by this value; the ring
    // protocol arbitrates device and CPU access.
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

    fn mapped(len: usize) -> Result<(u64, usize, u64, usize), NoMemory> {
        let (mut cpu, mut bus, mut got) = (0usize, 0u64, 0usize);
        // SAFETY: the three outputs are live locals.
        let handle = unsafe {
            ffi::narf_dma_alloc_mapped(device(), len, ADDR_BITS, &mut cpu, &mut bus, &mut got)
        };
        if handle == 0 || cpu == 0 || got < len {
            return Err(NoMemory);
        }
        Ok((handle, cpu, bus, got))
    }

    /// Zeroed coherent memory of at least `len` bytes, wholly below 4 GiB.
    pub fn alloc(len: usize) -> Result<DmaBuffer, NoMemory> {
        let size = len.max(1).next_power_of_two().max(PAGE);
        if size > MAX_POOLED {
            let (handle, cpu, bus, got) = mapped(len)?;
            // SAFETY: `cpu` names `got` bytes of this module's mapped memory.
            unsafe { core::ptr::write_bytes(cpu as *mut u8, 0, got) };
            return Ok(DmaBuffer {
                cpu,
                bus,
                len,
                origin: Origin::Direct { handle },
            });
        }
        let class = (size / PAGE).trailing_zeros() as usize;
        let block = POOLS.lock()[class].pop();
        let block = match block {
            Some(block) => block,
            None => {
                // Carve a fresh chunk into blocks of this class. The chunk's
                // handle is kept for the device's lifetime: device teardown
                // releases it with every other module DMA allocation.
                let (_handle, cpu, bus, got) = mapped(CHUNK)?;
                let mut pools = POOLS.lock();
                for i in 1..got / size {
                    pools[class].push(Block {
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
            origin: Origin::Pooled { class },
        })
    }

    impl DmaBuffer {
        /// Device-visible address.
        pub fn bus(&self) -> u64 {
            self.bus
        }
        /// Usable length (the requested length).
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        /// CPU pointer to byte 0.
        pub fn cpu_ptr(&self) -> *mut u8 {
            self.cpu as *mut u8
        }
    }

    impl Drop for DmaBuffer {
        fn drop(&mut self) {
            match self.origin {
                Origin::Pooled { class } => POOLS.lock()[class].push(Block {
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

/// Firmware reads through `narf_firmware_open` / `_read` / `_signed`.
pub mod firmware {
    use super::*;

    /// Why a firmware file could not be had.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FwError {
        NotFound,
        NoMemory,
        Invalid,
    }

    /// One whole file and whether a verified signer stands behind it.
    #[derive(Debug)]
    pub struct Blob {
        pub bytes: Vec<u8>,
        pub signed: bool,
    }

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;

    /// `(size, signed)` of the file `name` as the registry holds it now,
    /// without reading it; `None` when it cannot be opened.
    pub fn stat(name: &str) -> Option<(usize, bool)> {
        let (mut handle, mut size) = (0u64, 0usize);
        // SAFETY: `name` is a live `&str`; both outputs are live locals.
        let rc =
            unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
        if rc != 0 {
            return None;
        }
        // SAFETY: argument-only calls on our open handle, closed once.
        let signed = unsafe { ffi::narf_firmware_signed(handle) } == 1;
        // SAFETY: as above.
        let _ = unsafe { ffi::narf_firmware_close(handle) };
        Some((size, signed))
    }

    /// The whole file `name`, at most `max` bytes. The module's `Firmware`
    /// manifest cap is the authority.
    pub fn load(name: &str, max: usize) -> Result<Blob, FwError> {
        let (mut handle, mut size) = (0u64, 0usize);
        // SAFETY: `name` is a live `&str`; both outputs are live locals.
        let rc =
            unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
        if rc != 0 {
            return Err(FwError::NotFound);
        }
        let result = (|| {
            if size == 0 || size > max {
                return Err(FwError::Invalid);
            }
            // SAFETY: argument-only call on our open handle.
            let signed = unsafe { ffi::narf_firmware_signed(handle) } == 1;
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
                if rc != 0 || got == 0 || got > want {
                    return Err(FwError::Invalid);
                }
                at += got;
            }
            Ok(Blob { bytes, signed })
        })();
        // SAFETY: closing our own open handle once.
        let _ = unsafe { ffi::narf_firmware_close(handle) };
        result
    }
}

/// The kernel's regulatory domain: the one the built-in driver reads.
///
/// Built in, `narf_wireless::reg::db` holds it: a signed deployment policy
/// (`wireless-regulatory.bin`) when one is staged, else world `00` from the
/// Linux database authenticated at image build, with the user's and the
/// Country IE's changes on top. The module reads that same installed domain
/// through `narf_wireless_regdomain` (one NRGD v1 record, decoded by
/// `narf_wireless::reg::parse_domain_record`, which accepts world `00`),
/// again on every read, as built in each check reads the live database. An
/// unchanged record keeps the previous snapshot's `Arc`, so the station's
/// identity check still sees an unchanged domain as unchanged.
///
/// No domain (`-ENODATA`: nothing installed and nothing to bootstrap) or a
/// record that does not decode is `None`: the caller fails closed, as built
/// in on an empty database.
pub mod reg {
    use super::*;
    use alloc::sync::Arc;
    use narf_wireless::reg::RegulatoryDomain;

    /// Largest NRGD v1 record: 12-byte header, at most 64 16-byte rules
    /// (the export refuses a larger domain).
    const MAX_RECORD: usize = 12 + 64 * 16;

    /// The last record and its decoded domain.
    static CACHE: IrqSafeSpinLock<Option<(Vec<u8>, Arc<RegulatoryDomain>)>> =
        IrqSafeSpinLock::new(None);

    /// The kernel's installed domain, or `None` (fail closed).
    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        let mut record = [0u8; MAX_RECORD];
        let mut len = 0usize;
        // SAFETY: `record` names `MAX_RECORD` writable bytes; `len` is a
        // live local.
        let rc =
            unsafe { ffi::narf_wireless_regdomain(record.as_mut_ptr(), record.len(), &mut len) };
        let mut cache = CACHE.lock();
        if rc != 0 || len > record.len() {
            *cache = None;
            return None;
        }
        let record = &record[..len];
        if let Some((cached, domain)) = cache.as_ref() {
            if cached.as_slice() == record {
                return Some(domain.clone());
            }
        }
        let Ok(domain) = narf_wireless::reg::parse_domain_record(record) else {
            *cache = None;
            return None;
        };
        let domain = Arc::new(domain);
        *cache = Some((record.to_vec(), domain.clone()));
        Some(domain)
    }
}
