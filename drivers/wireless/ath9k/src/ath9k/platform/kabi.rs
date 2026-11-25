//! Module platform: the kernel names ath9k uses, over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! Everything here runs in task context on whichever upcall (probe, the
//! 1 ms device poller, the MSI vector callback, a `WIFI` host event) is
//! driving the module's [`EXEC`]utor. Probe sets the device token once
//! ([`set_device`]); every device export takes it, and the device
//! capability shim ([`compat::narf_capabilities`]) is live only while it is
//! the bound token.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_module_rt::exec::Executor;
use narf_module_rt::sync::SpinLock;

pub use narf_module_rt::console::Console;

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
        pub fn narf_msi_enable(
            dev: u64,
            want: u16,
            out_count: *mut u16,
            out_base_vector: *mut u16,
            out_addr: *mut u64,
            out_data: *mut u32,
        ) -> i32;
        pub fn narf_msi_set_enabled(dev: u64, enabled: u32) -> i32;
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_prev: *mut u16) -> i32;
        pub fn narf_pcie_state(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_pci_config_read32(dev: u64, offset: u16, out: *mut u32) -> i32;
        pub fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
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
    }
}

/// The module's executor: every driver future runs here.
pub static EXEC: Executor = Executor::new();

/// The probed device's token; 0 until probe and after removal.
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// Record the probed device (the token every device export takes); 0
/// revokes the device capability shim.
pub fn set_device(dev: u64) {
    DEVICE.store(dev, Ordering::Release);
}

/// The probed device's token.
pub fn device() -> u64 {
    DEVICE.load(Ordering::Acquire)
}

/// Spawn a driver task on the module's executor. Refused only after the
/// executor was stopped, when nothing may run any more.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    let _ = EXEC.spawn(future);
}

/// Synchronous delay of `ns` nanoseconds (`narf_udelay`, ≤ 1 s per call)
/// during which the kernel's sleep pumps keep ticking.
pub fn delay_ns(ns: u64) {
    let mut left = ns;
    while left > 0 {
        let step = left.min(1_000_000_000);
        // SAFETY: argument-only call, 1 ns ..= 1 s.
        let _ = unsafe { ffi::narf_udelay(step) };
        left -= step;
    }
}

/// The kernel DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (EAPOL nonces).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// The host regulatory domain (`narf_wireless_regdomain`), with the names of
/// `narf_wireless::reg::db`. A softMAC driver enforces it itself: every
/// calibration, channel and transmit-power admission reads a current
/// snapshot, and admission closes when the host has no domain.
///
/// The export returns one NRGD v1 record (decoded by
/// `narf_wireless::reg::parse_domain_record`) and always bootstraps the staged signed policy when no domain is
/// installed, so `snapshot` and `ensure_domain` read the same thing here
/// (built in, only `ensure_domain` bootstraps). There is no revision: every
/// read refetches the record, and an unchanged record reuses its last parse.
pub mod regdb {
    use super::*;
    use narf_wireless::reg::RegulatoryDomain;

    /// No regulatory domain is installed (and none could be bootstrapped).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NoDomain;

    /// NRGD v1: a 12-byte header and at most 64 rules of 16 bytes.
    const MAX_RECORD: usize = 12 + 64 * 16;

    /// The last record and its parse.
    static CACHE: SpinLock<Option<(Vec<u8>, Arc<RegulatoryDomain>)>> = SpinLock::new(None);

    /// The export's record (`parse_domain_record`: `parse_policy`'s layout
    /// and rule checks, also accepting the world domain's `"00"`).
    fn decode(record: &[u8]) -> Option<RegulatoryDomain> {
        narf_wireless::reg::parse_domain_record(record).ok()
    }

    fn fetch() -> Option<Arc<RegulatoryDomain>> {
        let mut record = [0u8; MAX_RECORD];
        let mut len = 0usize;
        // SAFETY: `record` names `MAX_RECORD` writable bytes; `len` is live.
        let rc = unsafe { ffi::narf_wireless_regdomain(record.as_mut_ptr(), MAX_RECORD, &mut len) };
        if rc != 0 || len == 0 || len > MAX_RECORD {
            // -ENODATA: no domain; anything else: nothing trustworthy.
            *CACHE.lock() = None;
            return None;
        }
        let record = &record[..len];
        if let Some((bytes, domain)) = CACHE.lock().as_ref() {
            if bytes.as_slice() == record {
                return Some(domain.clone());
            }
        }
        let Some(domain) = decode(record).map(Arc::new) else {
            *CACHE.lock() = None;
            return None;
        };
        *CACHE.lock() = Some((record.to_vec(), domain.clone()));
        Some(domain)
    }

    /// The installed domain, if any (`db::snapshot`).
    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        fetch()
    }

    /// The installed domain, bootstrapping the staged signed policy when
    /// there is none (`db::ensure_domain`).
    pub fn ensure_domain() -> Result<RegulatoryDomain, NoDomain> {
        fetch()
            .map(|domain| domain.as_ref().clone())
            .ok_or(NoDomain)
    }

    /// `db::get_domain`.
    pub fn get_domain() -> Option<RegulatoryDomain> {
        snapshot().map(|domain| domain.as_ref().clone())
    }
}

/// The netdev control surface the built-in nl80211 drives
/// (`narf_wireless::WirelessNetIface`, kernel-resident), restated with the
/// methods ath9k's netdev implements. In the module the `WIFI` family host
/// events call it (`iface_module.rs`).
#[async_trait::async_trait]
pub trait WirelessNetIface: compat::narf_net::Interface {
    fn power_save_default(&self) -> Option<bool> {
        None
    }
    fn set_power_save(&self, _enabled: bool) -> Result<(), i32> {
        Err(-95)
    }
    fn max_scan_ssids(&self) -> u8 {
        4
    }
    fn max_scan_ie_len(&self) -> u16 {
        512
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
    fn cipher_suites(&self) -> &'static [u32] {
        &[]
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        None
    }
    fn scan_information_elements(&self, _bssid: [u8; 6]) -> Option<Vec<u8>> {
        None
    }
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        None
    }
    fn set_wowlan(&self, _config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        Err(-95)
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        None
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo;
    async fn scan(
        &self,
        req: narf_wireless::ScanRequest,
    ) -> Result<Vec<narf_wireless::BssInfo>, narf_wireless::WirelessError>;
    async fn associate(
        &self,
        req: narf_wireless::AssociateRequest,
    ) -> Result<(), narf_wireless::WirelessError>;
    async fn disassociate(&self) -> Result<(), narf_wireless::WirelessError>;
    async fn set_config(
        &self,
        cfg: narf_wireless::WirelessConfig,
    ) -> Result<(), narf_wireless::WirelessError>;
}

/// Coherent DMA memory the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// ath9k allocates RX buffers, TX frames and descriptor rings per
/// generation, and the netdev copies every frame through a buffer. KABI DMA
/// handles are never reused, so small buffers come from size-class pools
/// carved out of 1 MiB mapped chunks and go back to their pool on drop;
/// large ones are allocated and freed directly. (The same scheme as
/// `ath11k.ko`.)
pub mod dma {
    use super::*;

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

    /// Direction of a cache sync (the mapping is coherent: syncs are
    /// ordering fences only).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DmaDirection {
        ToDevice,
        FromDevice,
        Bidirectional,
    }

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
    static POOLS: SpinLock<[[Vec<Block>; CLASSES]; 2]> = SpinLock::new([
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
    pub fn alloc_coherent_masked(len: usize, mask: u64) -> Result<DmaBuffer, NoMemory> {
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

    impl DmaBuffer {
        pub fn dma_addr(&self) -> DmaAddr {
            DmaAddr(self.bus)
        }
        pub fn dma_addr_at(&self, offset: u64) -> DmaAddr {
            DmaAddr(self.bus + offset)
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn cpu_ptr<T>(&self) -> *const T {
            self.cpu as *const T
        }
        pub fn cpu_mut_ptr<T>(&self) -> *mut T {
            self.cpu as *mut T
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
        /// The mapping is coherent (`narf_dma_alloc_mapped`); this only
        /// orders the CPU's accesses against the device's.
        pub fn sync(&self, _offset: usize, _len: usize) {
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        /// The mapping is coherent; this orders the CPU's view after the
        /// device's writes.
        pub fn sync_for_cpu(&self, _offset: usize, _len: usize, _direction: DmaDirection) {
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        /// The mapping is coherent; this orders the CPU's writes before the
        /// device's next access.
        pub fn sync_for_device(&self, _offset: usize, _len: usize, _direction: DmaDirection) {
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
                    // SAFETY: `handle` came from this module's allocation on
                    // this device and is freed exactly once, here.
                    let _ = unsafe { ffi::narf_dma_free(device(), handle) };
                }
            }
        }
    }
}

/// The device's single plain-MSI vector. Built in, ath9k discovers and
/// programs MSI itself and installs a hard-IRQ handler that only raises its
/// signal. A module asks the kernel for one programmed vector
/// (`narf_msi_enable`, delivery off) and gets one task-context callback for
/// it (`narf_irq_set_handler`); the [`trampoline`] runs the installed
/// handler, then the executor so the woken station task makes progress now.
pub mod irq {
    use super::*;

    /// A handler, called with its install cookie.
    pub type Handler = fn(u64);

    /// The granted vector (0 = none yet). MSI is set up once per device
    /// context: a later generation reuses the same block.
    static VECTOR: AtomicU64 = AtomicU64::new(0);
    static HANDLER: SpinLock<Option<(u64, Handler)>> = SpinLock::new(None);

    /// The device's MSI vector, setting it up (one vector, delivery off,
    /// callback bound) on first use. `None` keeps the driver polled.
    pub fn msi_vector() -> Option<u8> {
        let granted = VECTOR.load(Ordering::Acquire);
        if granted != 0 {
            return u8::try_from(granted - 1).ok();
        }
        let (mut count, mut base, mut addr, mut data) = (0u16, 0u16, 0u64, 0u32);
        // SAFETY: the four outputs are live locals.
        let rc = unsafe {
            ffi::narf_msi_enable(device(), 1, &mut count, &mut base, &mut addr, &mut data)
        };
        // The driver keys its vector as `u8`; a vector past 255 (possible on
        // aarch64 GICs) is refused rather than truncated.
        let vector = u8::try_from(base).ok().filter(|_| rc == 0 && count == 1)?;
        // SAFETY: `trampoline` is a valid `extern "C" fn(u64) -> i32` in this
        // module's text, which the kernel unbinds before unmapping it.
        if unsafe { ffi::narf_irq_set_handler(device(), base, trampoline as usize, 0) } != 0 {
            return None;
        }
        VECTOR.store(u64::from(vector) + 1, Ordering::Release);
        Some(vector)
    }

    /// Install (or with `None`, remove) the vector's handler.
    pub fn set_handler(handler: Option<(u64, Handler)>) {
        *HANDLER.lock() = handler;
    }

    /// Turn MSI delivery on or off for the device's block.
    pub fn set_delivery(enabled: bool) -> bool {
        // SAFETY: argument-only call on the probed device.
        unsafe { ffi::narf_msi_set_enabled(device(), u32::from(enabled)) == 0 }
    }

    /// Task-context upcall for the vector.
    pub extern "C" fn trampoline(_cookie: u64) -> i32 {
        let handler = *HANDLER.lock();
        if let Some((cookie, handler)) = handler {
            handler(cookie);
        }
        let _ = EXEC.run();
        0
    }
}

/// Signed qualification records through `narf_firmware_open` / `_read` /
/// `_signed`. Each opened record stays readable for the module's lifetime
/// (the grants that decode it keep its capability); re-opening identical
/// bytes reuses the entry.
pub mod firmware {
    use super::*;

    /// One opened record.
    pub(super) struct Blob {
        pub(super) name: alloc::string::String,
        pub(super) bytes: &'static [u8],
        pub(super) signed: bool,
    }

    pub(super) static BLOBS: SpinLock<Vec<Blob>> = SpinLock::new(Vec::new());

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;
    /// Qualification records are small; refuse anything absurd.
    const MAX: usize = 1 << 20;

    /// Read the whole file. `Err(true)` = not found, `Err(false)` = invalid.
    fn read(name: &str) -> Result<(Vec<u8>, bool), bool> {
        let (mut handle, mut size) = (0u64, 0usize);
        // SAFETY: `name` is a live `&str`; both outputs are live locals.
        let rc =
            unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
        if rc != 0 {
            return Err(true);
        }
        let result = (|| {
            if size == 0 || size > MAX {
                return Err(false);
            }
            // SAFETY: argument-only call on our open handle.
            let signed = unsafe { ffi::narf_firmware_signed(handle) } == 1;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(size).map_err(|_| false)?;
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
                    return Err(false);
                }
                at += got;
            }
            Ok((bytes, signed))
        })();
        // SAFETY: closing our own open handle once.
        let _ = unsafe { ffi::narf_firmware_close(handle) };
        result
    }

    /// Open `name`; the returned token (1-based) names its entry.
    pub(super) fn open(name: &str) -> Result<u64, bool> {
        let (bytes, signed) = read(name)?;
        let mut blobs = BLOBS.lock();
        if let Some(at) = blobs
            .iter()
            .position(|b| b.name == name && b.signed == signed && b.bytes == bytes.as_slice())
        {
            return Ok(at as u64 + 1);
        }
        blobs.push(Blob {
            name: alloc::string::String::from(name),
            bytes: Box::leak(bytes.into_boxed_slice()),
            signed,
        });
        Ok(blobs.len() as u64)
    }
}

/// The kernel crates ath9k names, restated over the KABI: exactly the subset
/// of each API the driver uses, with the same paths, types and semantics. A
/// driver file brings the ones it names into scope under
/// `#[cfg(feature = "module")]`; built in, the same paths are the real
/// crates.
pub mod compat {
    /// `narf_console`: console output.
    pub mod narf_console {
        pub use narf_module_rt::console::Console as Writer;
    }

    /// `narf_lib`: locks, a one-shot cell and domain ids.
    pub mod narf_lib {
        pub mod sync {
            use core::cell::UnsafeCell;
            use core::mem::MaybeUninit;
            use core::sync::atomic::{AtomicU8, Ordering};

            /// Module code always runs in task context, so the module's
            /// spin lock never needs to mask interrupts.
            pub use narf_module_rt::sync::SpinLock as IrqSafeSpinLock;

            /// One-shot cell that stores a value after its first `set`.
            pub struct OnceLock<T> {
                state: AtomicU8,
                data: UnsafeCell<MaybeUninit<T>>,
            }

            const EMPTY: u8 = 0;
            const WRITING: u8 = 1;
            const DONE: u8 = 2;

            // SAFETY: the value is published only through Release/Acquire on
            // `state`; shared readers see it fully written.
            unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
            // SAFETY: moving the cell moves the owned `T`.
            unsafe impl<T: Send> Send for OnceLock<T> {}

            impl<T> OnceLock<T> {
                pub const fn new() -> Self {
                    Self {
                        state: AtomicU8::new(EMPTY),
                        data: UnsafeCell::new(MaybeUninit::uninit()),
                    }
                }
                /// Set the value; `Err(value)` if already set.
                pub fn set(&self, value: T) -> Result<(), T> {
                    if self
                        .state
                        .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Acquire)
                        .is_err()
                    {
                        return Err(value);
                    }
                    // SAFETY: the EMPTY→WRITING winner is the sole writer, and
                    // no reader looks at the cell before DONE.
                    unsafe { (*self.data.get()).write(value) };
                    self.state.store(DONE, Ordering::Release);
                    Ok(())
                }
                /// The value, if set.
                pub fn get(&self) -> Option<&T> {
                    (self.state.load(Ordering::Acquire) == DONE)
                        // SAFETY: DONE is stored only after the value was
                        // written, and it is never written again.
                        .then(|| unsafe { (*self.data.get()).assume_init_ref() })
                }
            }

            impl<T> Default for OnceLock<T> {
                fn default() -> Self {
                    Self::new()
                }
            }

            impl<T> Drop for OnceLock<T> {
                fn drop(&mut self) {
                    if *self.state.get_mut() == DONE {
                        // SAFETY: DONE means initialised; dropped once here.
                        unsafe { self.data.get_mut().assume_init_drop() };
                    }
                }
            }
        }

        pub mod mutex {
            pub use narf_module_rt::sync::Mutex;
        }

        pub mod id {
            /// Allocation domain. A module allocates in its own effective
            /// domain whatever the driver names; the type keeps the
            /// built-in signatures.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct DomainId(u8);
            impl DomainId {
                pub const DRIVER_0: DomainId = DomainId(9);
            }
        }
    }

    /// `narf_time`: the monotonic clock, deadlines and sleeps. A "cycle" is
    /// a nanosecond here: the driver only ever converts with
    /// [`wall::ns_to_cycles`] before sleeping.
    pub mod narf_time {
        /// Nanoseconds on the monotonic clock.
        pub fn monotonic_ns() -> u64 {
            narf_module_rt::time::now_ns()
        }

        pub mod wall {
            pub fn monotonic_ns() -> u64 {
                narf_module_rt::time::now_ns()
            }
            pub fn ns_to_cycles(ns: u64) -> u64 {
                ns
            }
        }

        /// Sleep for `cycles` (nanoseconds); completes on the executor's
        /// next heartbeat after the deadline.
        pub fn sleep_cycles(cycles: u64) -> narf_module_rt::time::SleepUntil {
            narf_module_rt::time::sleep_until(narf_module_rt::time::Deadline::after_ns(cycles))
        }

        /// An absolute timeout.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Deadline(narf_module_rt::time::Deadline);
        impl Deadline {
            pub fn after_us(us: u64) -> Self {
                Self(narf_module_rt::time::Deadline::after_ns(
                    us.saturating_mul(1000),
                ))
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
    }

    /// `narf_scheduler`: task spawning and the responsive spin.
    pub mod narf_scheduler {
        use core::future::Future;

        /// Spawn on the module's executor.
        pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
            super::super::spawn(future);
        }

        /// Spin until `done` or the deadline, in `narf_udelay` steps of at
        /// most 10 µs (Linux ath9k's `AH_TIME_QUANTUM` poll interval) so the
        /// kernel's sleep pumps keep ticking. `true` if `done` held.
        pub fn responsive_spin_until(
            mut done: impl FnMut() -> bool,
            deadline: super::narf_time::Deadline,
        ) -> bool {
            loop {
                if done() {
                    return true;
                }
                let left = deadline.remaining_ns();
                if left == 0 || deadline.expired() {
                    return false;
                }
                super::super::delay_ns(left.min(10_000));
            }
        }

        pub fn yield_now() -> narf_module_rt::time::YieldNow {
            narf_module_rt::time::yield_now()
        }
    }

    /// `narf_io`: coherent DMA memory.
    pub mod narf_io {
        pub use super::super::dma::{DmaBuffer, DmaDirection, NoMemory};
        use super::narf_lib::id::DomainId;

        pub fn alloc_coherent(len: usize, _domain: DomainId) -> Result<DmaBuffer, NoMemory> {
            super::super::dma::alloc_coherent_masked(len, u64::MAX)
        }

        pub fn alloc_coherent_masked(
            len: usize,
            _domain: DomainId,
            mask: u64,
        ) -> Result<DmaBuffer, NoMemory> {
            super::super::dma::alloc_coherent_masked(len, mask)
        }

        pub mod iommu {
            /// Translation the device sees. The KABI hands the driver the
            /// device-visible address of every mapping, so the driver's
            /// per-domain refusal (built-in buffers it cannot rebase) does
            /// not apply.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum IommuMode {
                Translated,
                PerDomain,
            }
            pub fn mode() -> IommuMode {
                IommuMode::Translated
            }
        }
    }

    /// `narf_capabilities`: the typed capability handles the driver threads
    /// through every device access. A module holds no kernel capability;
    /// the kernel checks its own device cap on every export. These handles
    /// keep the driver's revocation structure: a device handle is live only
    /// while its token is the bound device ([`super::super::device`]), and a
    /// firmware handle only while its record is open.
    pub mod narf_capabilities {
        use core::marker::PhantomData;

        #[derive(Clone, Copy, Debug)]
        pub struct Read;
        #[derive(Clone, Copy, Debug)]
        pub struct Write;
        #[derive(Clone, Copy, Debug)]
        pub struct Grant;

        pub trait Rights: 'static {}
        impl Rights for Read {}
        impl Rights for Write {}
        impl Rights for Grant {}

        /// What a handle names, and whether it is still live.
        pub trait CapType {
            fn live(token: u64) -> bool;
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum CapError {
            Revoked,
        }

        pub struct Cap<T, R: Rights> {
            token: u64,
            _tag: PhantomData<(T, R)>,
        }

        impl<T, R: Rights> Clone for Cap<T, R> {
            fn clone(&self) -> Self {
                *self
            }
        }
        impl<T, R: Rights> Copy for Cap<T, R> {}
        impl<T, R: Rights> core::fmt::Debug for Cap<T, R> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("Cap").field("token", &self.token).finish()
            }
        }
        // SAFETY: a token is a plain integer.
        unsafe impl<T, R: Rights> Send for Cap<T, R> {}
        // SAFETY: as above.
        unsafe impl<T, R: Rights> Sync for Cap<T, R> {}

        impl<T, R: Rights> Cap<T, R> {
            pub(crate) const fn new(token: u64) -> Self {
                Self {
                    token,
                    _tag: PhantomData,
                }
            }
            pub(crate) fn token(&self) -> u64 {
                self.token
            }
        }

        impl<T: CapType, R: Rights> Cap<T, R> {
            pub fn check_live(&self) -> Result<(), CapError> {
                if T::live(self.token) {
                    Ok(())
                } else {
                    Err(CapError::Revoked)
                }
            }
            pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
                self.check_live()?;
                op.execute(self)
            }
            pub fn derive<R2: Rights>(&self) -> Result<Cap<T, R2>, CapError> {
                self.check_live()?;
                Ok(Cap::new(self.token))
            }
        }

        pub trait CapOp<T, R: Rights>: Sized {
            type Output;
            fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub struct NoopOp;
        impl<T, R: Rights> CapOp<T, R> for NoopOp {
            type Output = ();
            fn execute(self, _cap: &Cap<T, R>) -> Result<(), CapError> {
                Ok(())
            }
        }
    }

    /// `narf_bus`: the bound PCI function, its BAR, the Command register,
    /// PCI Express state and MSI.
    pub mod narf_bus {
        use super::super::ffi;
        use super::narf_capabilities::{Cap, CapType, Read, Write};

        /// The bound function's device capability type.
        #[derive(Debug)]
        pub struct BusDeviceCap;
        impl CapType for BusDeviceCap {
            fn live(token: u64) -> bool {
                token != 0 && token == super::super::device()
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PcieAddr {
            pub segment: u16,
            pub bus: u8,
            pub device: u8,
            pub function: u8,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum BusAddr {
            Pcie(PcieAddr),
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct DeviceId {
            pub vendor: u16,
            pub device: u16,
            pub class: u32,
            pub subsystem_vendor: u16,
            pub subsystem_id: u16,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct BusDevice {
            pub addr: BusAddr,
            pub id: DeviceId,
        }

        /// A mapped BAR as the driver sees it: a length and 32-bit
        /// accessors. The mapping stays in the kernel; every access is a
        /// bounds-checked export.
        #[derive(Clone, Copy, Debug)]
        pub struct MmioRegion {
            pub len: u64,
            bar: u64,
        }

        impl MmioRegion {
            pub(crate) fn new(bar: u64, len: u64) -> Self {
                Self { len, bar }
            }

            /// # Safety
            /// `off` names a readable register inside the BAR (the kernel
            /// bounds-checks it too; a refused read returns all-ones).
            pub unsafe fn read32(&self, off: u64) -> u32 {
                let mut value = u32::MAX;
                // SAFETY: `value` is a live local.
                let _ = unsafe {
                    ffi::narf_mmio_read32(super::super::device(), self.bar, off, &mut value)
                };
                value
            }

            /// # Safety
            /// `off` names a writable register inside the BAR.
            pub unsafe fn write32(&self, off: u64, value: u32) {
                // SAFETY: argument-only call; the kernel bounds-checks `off`.
                let _ =
                    unsafe { ffi::narf_mmio_write32(super::super::device(), self.bar, off, value) };
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProbeError {
            NotForThisDriver,
            BadDevice,
            Other(&'static str),
        }

        pub mod pci {
            use super::*;

            /// Why a config access failed.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum PciError {
                AuthorityRevoked,
                NotReady,
                /// No such access in a module (general config space).
                Unsupported,
            }

            pub mod cmd {
                pub const MEM_SPACE: u16 = 1 << 1;
                pub const BUS_MASTER: u16 = 1 << 2;
                pub const INTX_DISABLE: u16 = 1 << 10;
            }

            /// `narf_pci_command`: clear, then set, then the register read
            /// back.
            fn command(
                cap: &Cap<BusDeviceCap, Write>,
                clear: u16,
                set: u16,
            ) -> Result<u16, PciError> {
                cap.check_live().map_err(|_| PciError::AuthorityRevoked)?;
                let mut readback = 0u16;
                // SAFETY: `readback` is a live local.
                match unsafe { ffi::narf_pci_command(cap.token(), clear, set, &mut readback) } {
                    0 => Ok(readback),
                    _ => Err(PciError::NotReady),
                }
            }

            /// The Command register.
            pub fn read_command(
                cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
            ) -> Result<u16, PciError> {
                command(cap, 0, 0)
            }

            /// Set Command bits (Memory Space, Bus Master, INTx Disable);
            /// the register read back.
            pub fn set_command(
                cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
                bits: u16,
            ) -> Result<u16, PciError> {
                command(cap, 0, bits)
            }

            /// Clear Command bits; the register read back.
            pub fn clear_command(
                cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
                bits: u16,
            ) -> Result<u16, PciError> {
                command(cap, bits, 0)
            }

            /// One config dword past the standard header
            /// (`narf_pci_config_read32`, read only).
            pub fn read_config32(
                cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
                offset: u16,
            ) -> Result<u32, PciError> {
                cap.check_live().map_err(|_| PciError::AuthorityRevoked)?;
                let mut value = 0u32;
                // SAFETY: `value` is a live local.
                match unsafe { ffi::narf_pci_config_read32(cap.token(), offset, &mut value) } {
                    0 => Ok(value),
                    -22 => Err(PciError::Unsupported),
                    _ => Err(PciError::NotReady),
                }
            }

            /// Config writes are not exported to modules: the only ones ath9k
            /// makes (the PCI retry-timeout clear) are in its system-PM path,
            /// which the module does not carry.
            pub fn write_config32(
                _cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
                _offset: u16,
                _value: u32,
            ) -> Result<(), PciError> {
                Err(PciError::Unsupported)
            }
        }

        pub mod pci_express {
            use super::*;

            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum PcieCapError {
                AuthorityRevoked,
                NotExpress,
            }

            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct PcieStatus {
                pub device_caps: u32,
                pub device_control: u16,
                pub device_status: u16,
                pub link_caps: u32,
                pub link_status: u16,
            }

            fn state(cap: &Cap<BusDeviceCap, Read>) -> Result<[u8; 20], PcieCapError> {
                cap.check_live()
                    .map_err(|_| PcieCapError::AuthorityRevoked)?;
                let mut record = [0u8; 20];
                // SAFETY: `record` names 20 writable bytes.
                match unsafe { ffi::narf_pcie_state(cap.token(), record.as_mut_ptr(), 20) } {
                    0 => Ok(record),
                    _ => Err(PcieCapError::NotExpress),
                }
            }

            /// Device/Link Capabilities, Control and Status.
            pub fn read_status(
                cap: &Cap<BusDeviceCap, Read>,
                _device: &BusDevice,
            ) -> Result<PcieStatus, PcieCapError> {
                let r = state(cap)?;
                let half = |at: usize| u16::from_le_bytes([r[at], r[at + 1]]);
                let word = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
                Ok(PcieStatus {
                    device_caps: word(0),
                    device_control: half(4),
                    device_status: half(6),
                    link_caps: word(8),
                    link_status: half(12),
                })
            }

            /// The upstream bridge's Link Control, when there is one.
            pub fn parent_link_control(
                cap: &Cap<BusDeviceCap, Read>,
                _child: &BusDevice,
            ) -> Result<Option<u16>, PcieCapError> {
                let r = state(cap)?;
                Ok((r[16] & 1 != 0).then(|| u16::from_le_bytes([r[14], r[15]])))
            }
        }

        /// Plain MSI over `narf_msi_enable`. The kernel programs the message
        /// for the one vector it grants; "program" here only confirms the
        /// vector the driver allocated is that one.
        pub mod msi {
            use super::*;

            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum MsiError {
                Unavailable,
            }

            /// The device's MSI block (one vector).
            #[derive(Clone, Copy, Debug)]
            pub struct MsiConfig {
                vector: u8,
            }

            /// Discover and set up MSI for `count` (= 1) vector.
            pub fn enable_msi(
                cap: &Cap<BusDeviceCap, Write>,
                _device: &BusDevice,
                count: u16,
            ) -> Result<MsiConfig, MsiError> {
                if count != 1 || cap.check_live().is_err() {
                    return Err(MsiError::Unavailable);
                }
                super::super::super::irq::msi_vector()
                    .map(|vector| MsiConfig { vector })
                    .ok_or(MsiError::Unavailable)
            }

            /// # Safety
            /// The caller owns the function's MSI capability.
            pub unsafe fn program_msi(
                config: &mut MsiConfig,
                entry: u16,
                vector: u8,
            ) -> Result<(), MsiError> {
                (entry == 0 && vector == config.vector)
                    .then_some(())
                    .ok_or(MsiError::Unavailable)
            }

            /// # Safety
            /// The caller owns the function's MSI capability.
            pub unsafe fn enable(_config: &MsiConfig) -> Result<(), MsiError> {
                super::super::super::irq::set_delivery(true)
                    .then_some(())
                    .ok_or(MsiError::Unavailable)
            }

            /// # Safety
            /// The caller owns the function's MSI capability.
            pub unsafe fn disable(_config: &MsiConfig) -> Result<(), MsiError> {
                super::super::super::irq::set_delivery(false)
                    .then_some(())
                    .ok_or(MsiError::Unavailable)
            }
        }
    }

    /// `narf_interrupts`: the vector the MSI block granted and its handler.
    /// Delivery gating is MSI Enable (`narf_bus::msi::enable`/`disable`);
    /// the handler runs in task context from the trampoline.
    pub mod narf_interrupts {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum IrqStatus {
            Handled,
            None,
        }

        pub mod vector {
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct NoVector;
            /// The device's granted vector (MSI must be set up first).
            pub fn alloc() -> Result<u8, NoVector> {
                super::super::super::irq::msi_vector().ok_or(NoVector)
            }
            /// The block is released with the device context.
            pub fn free(_vector: u8) -> Result<(), NoVector> {
                Ok(())
            }
        }

        pub mod dispatch {
            /// No kernel wakers are registered on a module vector.
            pub fn clear_all_wakers(_vector: u8) {}
        }

        static NAME: narf_module_rt::sync::SpinLock<Option<&'static str>> =
            narf_module_rt::sync::SpinLock::new(None);
        /// A vector handler (the built-in signature).
        type Handler = fn(u64) -> IrqStatus;
        static HANDLER: narf_module_rt::sync::SpinLock<Option<Handler>> =
            narf_module_rt::sync::SpinLock::new(None);

        fn call(cookie: u64) {
            let handler = *HANDLER.lock();
            if let Some(handler) = handler {
                let _ = handler(cookie);
            }
        }

        pub fn install_handler_named(
            _vector: u8,
            name: &'static str,
            cookie: u64,
            handler: fn(u64) -> IrqStatus,
        ) {
            *NAME.lock() = Some(name);
            *HANDLER.lock() = Some(handler);
            super::super::irq::set_handler(Some((cookie, call)));
        }

        pub fn remove_handler(_vector: u8, name: &str, _cookie: u64) -> bool {
            let mut current = NAME.lock();
            if *current != Some(name) {
                return false;
            }
            *current = None;
            *HANDLER.lock() = None;
            super::super::irq::set_handler(None);
            true
        }

        pub fn enable_irq(_vector: u8) {}
        pub fn disable_irq(_vector: u8) {}
        /// The trampoline holds no lock across the handler, so a removed
        /// handler is not called again once `remove_handler` returned.
        pub fn synchronize_irq(_vector: u8) {}
    }

    /// `narf_firmware`: signed records the qualification grants decode.
    pub mod narf_firmware {
        use super::narf_capabilities::{Cap, CapType, Read, Write};

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum FirmwareError {
            NotFound,
            BadFormat,
            AuthorityRevoked,
        }

        /// The registry the module's `Firmware` manifest cap opens.
        #[derive(Debug)]
        pub struct FirmwareRegistry;
        impl CapType for FirmwareRegistry {
            fn live(_token: u64) -> bool {
                true
            }
        }

        /// One opened record.
        #[derive(Debug)]
        pub struct FirmwareBlob;
        impl CapType for FirmwareBlob {
            fn live(token: u64) -> bool {
                token != 0 && (token as usize) <= super::super::firmware::BLOBS.lock().len()
            }
        }

        /// What a record holds. `signer` is present when the kernel verified
        /// a signer (`narf_firmware_signed`); the module learns that fact,
        /// not the key.
        #[derive(Debug)]
        pub struct BlobView<'a> {
            pub bytes: &'a [u8],
            pub signer: Option<[u8; 32]>,
        }

        /// The module's firmware authority (its manifest cap).
        pub fn trusted_loader_authority() -> Option<Cap<FirmwareRegistry, Write>> {
            Some(Cap::new(1))
        }

        pub fn open(
            name: &str,
            _auth: &Cap<FirmwareRegistry, Read>,
        ) -> Result<Cap<FirmwareBlob, Read>, FirmwareError> {
            super::super::firmware::open(name)
                .map(Cap::new)
                .map_err(|missing| {
                    if missing {
                        FirmwareError::NotFound
                    } else {
                        FirmwareError::BadFormat
                    }
                })
        }

        pub fn view_of(cap: &Cap<FirmwareBlob, Read>) -> Result<BlobView<'_>, FirmwareError> {
            cap.check_live()
                .map_err(|_| FirmwareError::AuthorityRevoked)?;
            let blobs = super::super::firmware::BLOBS.lock();
            let blob = blobs
                .get(cap.token() as usize - 1)
                .ok_or(FirmwareError::AuthorityRevoked)?;
            Ok(BlobView {
                bytes: blob.bytes,
                signer: blob.signed.then_some([0; 32]),
            })
        }
    }

    /// `narf_net`: the frame and netdev types the station netdev shares
    /// with the stack, and the stack hooks it calls. In the module those
    /// hooks are the netif bridge (`iface_module.rs`).
    pub mod narf_net {
        use super::narf_io::DmaBuffer;
        use super::narf_ipc::{Consumer, Producer};
        use super::narf_lib::sync::IrqSafeSpinLock;

        /// RX copies nothing consumes in a module (delivery is
        /// `narf_netif_rx`): a short ring bounds what it can hold.
        pub const RX_RING_N: usize = 16;
        /// Stack → driver frames queued between netif TX and the station.
        pub const TX_RING_N: usize = 256;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum L4CsumKind {
            Tcp,
            Udp,
            Sctp,
        }

        /// Per-frame TX metadata. The netif bridge requests no offloads.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct TxMeta {
            pub csum_l4: Option<L4CsumKind>,
            pub tso_mss: Option<u16>,
            pub vlan_tag: Option<u16>,
            pub more: bool,
        }
        impl TxMeta {
            pub const fn plain() -> Self {
                Self {
                    csum_l4: None,
                    tso_mss: None,
                    vlan_tag: None,
                    more: false,
                }
            }
        }

        /// One frame in a DMA buffer.
        #[derive(Debug)]
        pub struct Frame {
            buf: DmaBuffer,
            len: u32,
            meta: TxMeta,
        }
        impl Frame {
            pub fn new(buf: DmaBuffer, len: u32) -> Self {
                let len = len.min(buf.len() as u32);
                Self {
                    buf,
                    len,
                    meta: TxMeta::plain(),
                }
            }
            pub fn payload(&self) -> &[u8] {
                &self.buf.as_slice()[..self.len as usize]
            }
            pub fn payload_mut(&mut self) -> &mut [u8] {
                let len = self.len as usize;
                &mut self.buf.as_mut_slice()[..len]
            }
            pub fn tx_meta(&self) -> TxMeta {
                self.meta
            }
            pub fn set_tx_meta(&mut self, meta: TxMeta) {
                self.meta = meta;
            }
        }

        /// A netdev (the built-in `narf_net::Interface`).
        pub trait Interface: Send + Sync {
            fn name(&self) -> &str;
            fn mac(&self) -> [u8; 6];
            fn mtu(&self) -> u32;
            fn link_up(&self) -> bool;
            fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>;
            fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>;
        }

        /// The module's `NetIface` manifest cap is its network authority.
        pub fn trusted_net_authority() -> Option<()> {
            Some(())
        }

        pub mod iface {
            /// Carrier is the `WIFI` host's (`CONNECT_RESULT` /
            /// `DISCONNECTED`); the bridge keeps no separate metadata.
            pub fn set_link_metadata(
                _name: &str,
                _carrier: bool,
                _speed_mbps: Option<u32>,
                _duplex: Option<()>,
            ) -> bool {
                true
            }

            /// Deliver one received Ethernet frame to the stack.
            pub fn on_rx_frame_from(_name: &str, frame: &mut [u8]) {
                crate::ath9k::iface_module::deliver(frame);
            }
        }
    }

    /// `narf_ipc`: the netdev's bounded frame queues.
    pub mod narf_ipc {
        use alloc::collections::VecDeque;
        use alloc::sync::Arc;
        use narf_module_rt::sync::SpinLock;

        #[derive(Debug)]
        pub enum TrySendError<T> {
            Full(T),
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum RecvError {
            Closed,
        }

        pub struct Producer<T, const N: usize>(Arc<SpinLock<VecDeque<T>>>);
        pub struct Consumer<T, const N: usize>(Arc<SpinLock<VecDeque<T>>>);

        pub fn channel<T, const N: usize>() -> (Producer<T, N>, Consumer<T, N>) {
            let ring = Arc::new(SpinLock::new(VecDeque::new()));
            (Producer(ring.clone()), Consumer(ring))
        }

        impl<T, const N: usize> Producer<T, N> {
            pub fn try_send(&mut self, msg: T) -> Result<(), TrySendError<T>> {
                let mut ring = self.0.lock();
                if ring.len() >= N {
                    return Err(TrySendError::Full(msg));
                }
                ring.push_back(msg);
                Ok(())
            }
        }

        impl<T, const N: usize> Consumer<T, N> {
            pub fn try_recv(&mut self) -> Result<Option<T>, RecvError> {
                Ok(self.0.lock().pop_front())
            }
        }
    }

    /// `narf_power`: the suspend callback's error type (system PM is not
    /// carried by the module; the callbacks are never registered).
    pub mod narf_power {
        pub mod device_pm {
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum DeviceSuspendError {
                DriverError,
                Busy,
                NotImplemented,
            }
        }
    }
}
