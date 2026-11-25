//! Module platform: the built-in platform's names over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! Everything here runs in task context on whichever CPU's upcall (probe,
//! the 1 ms device poller, the MSI vector callback) is driving the module's
//! [`EXEC`]utor. The device token is set once by probe; every device export
//! (BAR access, DMA, the command register) takes it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_module_rt::exec::Executor;

pub use narf_module_rt::console::Console;
pub use narf_module_rt::sync::{LockFuture, Mutex, MutexGuard, SpinLock as IrqSafeSpinLock};
pub use narf_module_rt::time::yield_now;

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
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32;
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
        pub fn narf_firmware_close(handle: u64) -> i32;
    }
}

/// The console at a `printk` level. A module has one console line sink, so
/// every level is the same writer (the level is kept for the built-in name).
#[derive(Clone, Copy, Debug, Default)]
pub struct PriorityConsole<const LEVEL: u32>;

impl<const LEVEL: u32> core::fmt::Write for PriorityConsole<LEVEL> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        Console.write_str(s)
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

/// Spawn a driver task on the module's executor. Refused only after
/// module exit has stopped the executor, when nothing may run any more.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    let _ = EXEC.spawn(future);
}

/// Synchronous hardware wait (the kernel's `responsive_spin_until`): sample
/// `done` until it holds or `deadline` passes, in `narf_udelay` steps during
/// which the kernel's sleep pumps keep ticking. Returns the final sample.
pub fn responsive_spin_until<F: FnMut() -> bool>(mut done: F, deadline: time::Deadline) -> bool {
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        // SAFETY: argument-only call, 20 µs.
        let _ = unsafe { ffi::narf_udelay(20_000) };
    }
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (SAE commit scalars, EAPOL nonces).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// Monotonic clock, deadlines and sleeps with the kernel's names. Sleeps
/// complete on the executor's heartbeat (the 1 ms device poller).
pub mod time {
    pub use narf_module_rt::time::{sleep_until, Deadline, SleepUntil};

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_module_rt::time::now_ns()
    }

    /// Sleep `ns` nanoseconds.
    pub fn sleep_ns(ns: u64) -> SleepUntil {
        sleep_until(Deadline::after_ns(ns))
    }
}

/// Coherent DMA memory the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// The driver allocates one frame buffer per ring slot (about 2000 of them
/// for the default ring layout) and a fresh buffer for some commands. KABI
/// DMA handles are never reused, so per-buffer KABI allocations would grow
/// the device context without bound; small buffers therefore come from
/// size-class pools carved out of 1 MiB mapped chunks and go back to their
/// pool on drop. Large ones are allocated and freed directly.
pub mod dma {
    use super::*;

    /// Allocation domain. The module allocates in its own effective domain
    /// whatever the driver asks for; the type keeps the built-in signature.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DomainId;
    impl DomainId {
        pub const DRIVER_0: DomainId = DomainId;
    }

    /// The function's DMA facts. A module's mapped DMA is always coherent
    /// kernel memory (`narf_dma_alloc_mapped`); there is nothing to choose.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct DmaDevice;
    impl DmaDevice {
        pub const fn coherent() -> Self {
            Self
        }
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
        if handle == 0 || cpu == 0 || got < len {
            return Err(NoMemory);
        }
        Ok((handle, cpu, bus, got))
    }

    fn addr_bits(mask: u64) -> u32 {
        64 - mask.leading_zeros()
    }

    /// `narf_io::alloc_coherent_for`: zeroed, wholly below `mask`.
    pub fn alloc_coherent_for(
        _dev: &DmaDevice,
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
                // releases (or, with retained DMA, keeps) it with every other
                // module DMA allocation.
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
        alloc_coherent_for(&DmaDevice, len, domain, u64::MAX)
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
        pub fn cpu_ptr<T>(&self) -> *const T {
            self.cpu as *const T
        }
        pub fn cpu_mut_ptr<T>(&self) -> *mut T {
            self.cpu as *mut T
        }
        pub fn as_ptr(&self) -> *const u8 {
            self.cpu as *const u8
        }
        pub fn as_mut_ptr(&self) -> *mut u8 {
            self.cpu as *mut u8
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

/// The bound PCI function, as the probe token the KABI hands the module.
pub mod bus {
    use super::*;

    /// `PCI_COMMAND` bits.
    pub mod cmd {
        pub const MEM_SPACE: u16 = 1 << 1;
        pub const BUS_MASTER: u16 = 1 << 2;
        pub const INTX_DISABLE: u16 = 1 << 10;
    }

    /// PCI PM: the D3hot -> D0 recovery time (PCI PM 1.2 §5.6.1).
    pub const PM_D3HOT_DELAY_MS: u64 = 10;

    /// The function's PCI id.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PciId {
        pub vendor: u16,
        pub device: u16,
    }

    /// The probed function: its KABI token and identity.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BusDevice {
        pub token: u64,
        pub id: PciId,
    }

    /// Marker for the probe capability's object type.
    #[derive(Clone, Copy, Debug)]
    pub struct BusDeviceCap;

    /// A revoked or foreign probe token.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CapError;

    /// The probe grant. The kernel re-validates the module's device context
    /// on every export call; this is the module-side check that the token is
    /// still the bound one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceCap {
        token: u64,
    }

    impl DeviceCap {
        pub fn for_token(token: u64) -> Self {
            Self { token }
        }
        pub fn check_live(&self) -> Result<(), CapError> {
            if self.token != 0 && self.token == device() {
                Ok(())
            } else {
                Err(CapError)
            }
        }
    }

    /// Run `operation` while the grant is the bound device's.
    pub fn invoke<T>(cap: &DeviceCap, operation: impl FnOnce() -> T) -> Result<T, CapError> {
        cap.check_live()?;
        Ok(operation())
    }

    /// Clear, then set, PCI command bits and read the register back
    /// (`narf_pci_command`; `clear = set = 0` only reads it).
    pub fn command(_cap: &DeviceCap, device: &BusDevice, clear: u16, set: u16) -> Result<u16, ()> {
        let mut value = 0u16;
        // SAFETY: `value` is a live local.
        match unsafe { ffi::narf_pci_command(device.token, clear, set, &mut value) } {
            0 => Ok(value),
            _ => Err(()),
        }
    }

    /// The function's DMA facts (always coherent mapped memory here).
    pub fn dma_device(_device: &BusDevice) -> Result<dma::DmaDevice, ()> {
        Ok(dma::DmaDevice)
    }

    /// BAR0 as the register helpers see it: a length and 32-bit accessors.
    /// The mapping stays in the kernel; every access is a bounds-checked
    /// export.
    #[derive(Copy, Clone, Debug)]
    pub struct MmioRegion {
        pub len: u64,
        bar: u64,
    }

    impl MmioRegion {
        pub fn new(bar: u64, len: u64) -> Self {
            Self { len, bar }
        }

        /// # Safety
        /// `off` names a readable register inside the BAR (the kernel
        /// bounds-checks it as well; an out-of-range read returns all-ones).
        pub unsafe fn read32(&self, off: u64) -> u32 {
            let mut value = u32::MAX;
            // SAFETY: `value` is a live local.
            let _ = unsafe { ffi::narf_mmio_read32(device(), self.bar, off, &mut value) };
            value
        }

        /// # Safety
        /// `off` names a writable register inside the BAR.
        pub unsafe fn write32(&self, off: u64, value: u32) {
            // SAFETY: argument-only call; the kernel bounds-checks `off`.
            let _ = unsafe { ffi::narf_mmio_write32(device(), self.bar, off, value) };
        }
    }
}

/// The function's IOMMU stop proof. A module's mapped DMA is untranslated
/// kernel memory (`narf_dma_alloc_mapped` does not attach an IOMMU domain),
/// so there is nothing to block or restore: the device-side evidence
/// (DMA idle, bus mastering off) is the only proof, as built in outside
/// `IommuMode::PerDomain`.
pub mod iommu {
    use super::bus::BusDevice;

    /// What a block achieved.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DmaBlock {
        /// No translation: nothing was blocked.
        Untranslated,
        /// The function's DMA is blocked at its IOMMU.
        Blocked,
    }

    pub fn block(_device: &BusDevice) -> Result<DmaBlock, bool> {
        Ok(DmaBlock::Untranslated)
    }

    pub fn restore(_device: &BusDevice) -> Result<(), bool> {
        Ok(())
    }

    pub fn blocked(_device: &BusDevice) -> bool {
        false
    }
}

/// System sleep states (the built-in variants). A module takes part in no
/// system PM transition; the type keeps the shared signatures.
pub mod power {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum SystemSleepState {
        S0Idle,
        S3,
        S4,
    }
}

/// The regulatory policy the radio is programmed from.
///
/// Built in, this is the kernel's regulatory database (a signed deployment
/// policy, else world `00` from the Linux database authenticated at image
/// build). A module cannot reach either, so it uses cfg80211's own built-in
/// world domain (`world_regdom`, net/wireless/reg.c) — what Linux falls back
/// to before any country is known. Channel 14 (NO-OFDM) and 60 GHz are left
/// out, so nothing outside the world rules can be enabled. Every 5 GHz rule
/// is NO_IR: the station may only join an AP it heard beacon there.
pub mod reg_db {
    use super::*;
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

    static WORLD: IrqSafeSpinLock<Option<Arc<RegulatoryDomain>>> = IrqSafeSpinLock::new(None);

    fn rule(start: u32, end: u32, bandwidth: u32, flags: RegFlags) -> RegRule {
        RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: 20,
            flags,
        }
    }

    fn world() -> RegulatoryDomain {
        let no_ir = RegFlags::NO_IR;
        RegulatoryDomain {
            country_code: *b"00",
            rules: alloc::vec![
                // IEEE 802.11b/g, channels 1..11.
                rule(2402, 2472, 40, RegFlags::empty()),
                // Channels 12..13.
                rule(2457, 2482, 20, no_ir | RegFlags::AUTO_BW),
                // Channels 36..48.
                rule(5170, 5250, 80, no_ir | RegFlags::AUTO_BW),
                // Channels 52..64, DFS.
                rule(5250, 5330, 80, no_ir | RegFlags::AUTO_BW | RegFlags::DFS),
                // Channels 100..144, DFS.
                rule(5490, 5730, 160, no_ir | RegFlags::DFS),
                // Channels 149..165.
                rule(5735, 5835, 80, no_ir),
            ],
        }
    }

    /// The installed domain snapshot (installed on first use).
    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        let mut slot = WORLD.lock();
        Some(slot.get_or_insert_with(|| Arc::new(world())).clone())
    }

    /// The domain, installing the world domain on first use.
    pub fn ensure_domain() -> Result<RegulatoryDomain, ()> {
        snapshot().map(|d| (*d).clone()).ok_or(())
    }

    /// The installed domain.
    pub fn get_domain() -> Option<RegulatoryDomain> {
        snapshot().map(|d| (*d).clone())
    }
}

/// Firmware files through `narf_firmware_open` / `_read`.
pub mod firmware {
    use super::*;

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;

    /// Why a firmware file could not be had.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FwError {
        NotFound,
        NoMemory,
        Invalid,
    }

    /// The whole file `name`, at most `max` bytes (the built-in copies the
    /// registry view under the same bound).
    pub fn load(name: &str, max: usize) -> Result<Vec<u8>, FwError> {
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

/// Native AP / radio control authorities.
///
/// Built in, nl80211 mints these for an AP, P2P or monitor request on the
/// live interface. The module build publishes a station netdev only (the
/// `WIFI` host version 2 carries no AP/P2P role), so no authority is ever
/// created: each type has a private field and no constructor, and the AP/P2P
/// owner paths that take one are compiled but cannot be reached. Every check
/// refuses (`NotSupported`, not current) should one ever be reached anyway.
pub mod ap_control {
    use narf_wireless::WirelessError;

    macro_rules! unconstructible {
        ($($name:ident),* $(,)?) => {$(
            #[derive(Clone, Debug)]
            pub struct $name {
                _private: (),
            }
        )*};
    }
    unconstructible!(
        ApControlAuthority,
        RadioControlAuthority,
        RadioControlRetirement,
        RadioEventAuthority,
        RadioInterfaceIdentity,
        ApInterfaceIdentity,
    );

    const REFUSED: Result<(), WirelessError> = Err(WirelessError::NotSupported);

    impl ApControlAuthority {
        pub fn current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn mode(&self) -> u32 {
            0
        }
        pub fn has_reservation(&self) -> bool {
            false
        }
        pub fn identity(&self) -> Result<ApInterfaceIdentity, WirelessError> {
            Err(WirelessError::NotSupported)
        }
    }

    impl ApInterfaceIdentity {
        pub fn mac(&self) -> [u8; 6] {
            [0; 6]
        }
        pub fn current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
    }

    impl RadioControlAuthority {
        pub fn current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn require_mode(&self, _mode: u32) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn mode(&self) -> u32 {
            0
        }
        pub fn has_reservation(&self) -> bool {
            false
        }
        pub fn identity(&self) -> Result<RadioInterfaceIdentity, WirelessError> {
            Err(WirelessError::NotSupported)
        }
        pub fn event_authority(&self) -> Result<RadioEventAuthority, WirelessError> {
            Err(WirelessError::NotSupported)
        }
        pub fn check_identity(
            &self,
            _identity: &RadioInterfaceIdentity,
        ) -> Result<(), WirelessError> {
            REFUSED
        }
    }

    impl RadioInterfaceIdentity {
        pub fn mac(&self) -> [u8; 6] {
            [0; 6]
        }
        pub fn current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
    }

    impl RadioEventAuthority {
        pub fn registration_current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn current(&self) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn roc_ready(
            &self,
            _cookie: u64,
            _frequency_mhz: u32,
            _duration_ms: u32,
        ) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn roc_expired(
            &self,
            _cookie: u64,
            _frequency_mhz: u32,
            _duration_ms: u32,
        ) -> Result<(), WirelessError> {
            REFUSED
        }
        pub fn management_received(
            &self,
            _frequency_mhz: u32,
            _signal_dbm: Option<i8>,
            _frame: &[u8],
        ) -> Result<(), WirelessError> {
            REFUSED
        }
    }

    impl RadioControlRetirement {
        pub fn current(&self) -> bool {
            false
        }
    }
}
