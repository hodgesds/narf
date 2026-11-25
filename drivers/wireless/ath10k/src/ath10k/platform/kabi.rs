//! Module platform: the built-in platform's names over `narf-module-rt` and
//! the KABI (`modules/src/kabi.rs`).
//!
//! Everything here runs in task context on whichever CPU's upcall (probe,
//! the 1 ms device poller, the MSI vector callback) is driving the module's
//! [`EXEC`]utor. The device token is set once by probe; every device export
//! takes it, and the kernel invokes the probe's real device capability on
//! each of those calls — a revoked grant fails the export, whatever the
//! module believes.

use alloc::sync::Arc;
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
        pub fn narf_smbios_read(off: usize, buf: *mut u8, len: usize, out_total: *mut usize)
            -> i32;
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
        pub fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32;
        pub fn narf_pci_config_read32(dev: u64, offset: u16, out: *mut u32) -> i32;
        pub fn narf_pci_config_write32(dev: u64, offset: u16, value: u32) -> i32;
        pub fn narf_pcie_state(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
        pub fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32;
        pub fn narf_msi_enable(
            dev: u64,
            want: u16,
            out_count: *mut u16,
            out_base_vector: *mut u16,
            out_addr: *mut u64,
            out_data: *mut u32,
        ) -> i32;
        pub fn narf_msi_set_enabled(dev: u64, enabled: u32) -> i32;
        pub fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
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

/// Yield to the module's executor once.
pub fn yield_now() -> narf_module_rt::time::YieldNow {
    narf_module_rt::time::yield_now()
}

/// Drive one self-advancing future to completion on the calling upcall
/// (the kernel's `block_on_spin` contract: it must not need another task).
pub fn block_on_spin<F: Future>(future: F) -> F::Output {
    narf_module_rt::exec::block_on(future)
}

/// The scheduler's `responsive_spin_until`: poll `done` until it holds or
/// `deadline` passes, in 10 µs `narf_udelay` steps (the kernel's sleep pumps
/// keep ticking during each).
pub fn responsive_spin_until<F: FnMut() -> bool>(mut done: F, deadline: time::Deadline) -> bool {
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        // SAFETY: argument-only call, 10 µs.
        let _ = unsafe { ffi::narf_udelay(10_000) };
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

/// `ath10k_core_check_smbios` in the module build: the firmware's SMBIOS
/// table through `narf_smbios_read`, walked the way `dmi_walk` walks it
/// (formatted area, then its string set up to the double NUL), each
/// structure handed to the shared ath-core parser. Empty without a table.
pub fn check_smbios() -> narf_drivers_wireless_ath_core::board::SmbiosBdf {
    use narf_drivers_wireless_ath_core::board::{smbios_bdf_ext, SmbiosBdf};
    /// SMBIOS type 127: end of table.
    const END_OF_TABLE: u8 = 127;
    let table = smbios_table();
    let mut state = SmbiosBdf::default();
    let mut at = 0usize;
    while at + 4 <= table.len() {
        let len = usize::from(table[at + 1]);
        if len < 4 || at + len > table.len() {
            break;
        }
        let mut end = at + len;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        let end = (end + 2).min(table.len());
        smbios_bdf_ext(&table[at..end], &mut state);
        if table[at] == END_OF_TABLE {
            break;
        }
        at = end;
    }
    state
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (EAPOL nonces, SAE commit scalars).
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
    use super::*;

    /// An absolute timeout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Deadline(narf_module_rt::time::Deadline);

    impl Deadline {
        pub fn after_ms(ms: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ms(ms))
        }
        pub fn after_us(us: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ns(
                us.saturating_mul(1000),
            ))
        }
        /// The kernel's TSC-cycle deadline. The module has no cycle clock;
        /// the driver only ever asks for `after_cycles(0)` ("already due"),
        /// which this is exactly. Other counts are taken as nanoseconds.
        pub fn after_cycles(cycles: u64) -> Self {
            Self(narf_module_rt::time::Deadline::after_ns(cycles))
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

    /// Sleep `ns` nanoseconds (rounded up to the executor's heartbeat).
    pub fn sleep_ns(ns: u64) -> SleepUntil {
        SleepUntil(narf_module_rt::time::sleep_until(
            narf_module_rt::time::Deadline::after_ns(ns),
        ))
    }

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_module_rt::time::now_ns()
    }
}

/// Coherent DMA memory the CPU walks directly (`narf_dma_alloc_mapped`).
///
/// ath10k allocates every ring, bounce buffer and host-memory chunk once
/// per generation and frees them only after proving the engines quiescent,
/// so these are direct KABI allocations (no per-packet churn to pool).
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

    /// A coherent buffer: `len` bytes at `cpu` (CPU) / `bus` (device).
    pub struct DmaBuffer {
        cpu: usize,
        bus: u64,
        len: usize,
        handle: u64,
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

    /// `narf_io::alloc_coherent_masked`: zeroed, wholly below `mask`.
    pub fn alloc_coherent_masked(
        len: usize,
        _domain: DomainId,
        mask: u64,
    ) -> Result<DmaBuffer, NoMemory> {
        let bits = (64 - mask.leading_zeros()).clamp(32, 64);
        let (mut cpu, mut bus, mut got) = (0usize, 0u64, 0usize);
        // SAFETY: the three outputs are live locals.
        let handle = unsafe {
            ffi::narf_dma_alloc_mapped(device(), len.max(1), bits, &mut cpu, &mut bus, &mut got)
        };
        if handle == 0 || cpu == 0 || got < len {
            return Err(NoMemory);
        }
        Ok(DmaBuffer {
            cpu,
            bus,
            len,
            handle,
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
        pub fn cpu_ptr<T>(&self) -> *const T {
            self.cpu as *const T
        }
        pub fn cpu_mut_ptr<T>(&self) -> *mut T {
            self.cpu as *mut T
        }
    }

    impl Drop for DmaBuffer {
        fn drop(&mut self) {
            // SAFETY: `handle` came from this module's allocation on this
            // device and is freed exactly once, here. The driver drops a
            // buffer only after proving its engine stopped (`PciBoot::drop`).
            let _ = unsafe { ffi::narf_dma_free(device(), self.handle) };
        }
    }
}

/// The bound PCI function as the transport sees it.
///
/// Built in, the transport holds the bus's `BusDevice` and the probe's
/// `Cap<BusDeviceCap, Write>` and performs config-space operations through
/// them. A module never holds either: the kernel keeps both in the device
/// context and invokes the cap on every export. So `Cap` here is the
/// module's handle on that probe grant (its `invoke` runs the operation;
/// the export inside it is what the kernel actually checks), and the
/// config-space operations are the KABI's: the command register
/// (`narf_pci_command`), the ASPM field (`narf_pcie_aspm`), the PCI Express
/// state (`narf_pcie_state`), device-specific config dwords
/// (`narf_pci_config_read32`/`_write32`, 0x40 and up) and BAR access. The
/// standard header and the kernel-owned capabilities stay out of reach.
pub mod pci {
    use super::*;
    use core::marker::PhantomData;

    /// `narf_bus::PcieAddr`: segment, bus, device, function.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PcieAddr {
        pub segment: u16,
        pub bus: u8,
        pub device: u8,
        pub function: u8,
    }

    /// `narf_bus::BusAddr`, the arms a module device can have.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BusAddr {
        Pcie(PcieAddr),
        /// No PCI address was reported (`narf_pci_identity` failed).
        Unknown,
    }

    /// `narf_bus::DeviceId`, the fields the driver reads.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceId {
        pub vendor: u16,
        pub device: u16,
        pub subsystem_vendor: u16,
        pub subsystem_id: u16,
    }

    /// The probed function: identity from `narf_pci_identity`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BusDevice {
        pub id: DeviceId,
        pub addr: BusAddr,
    }

    /// Cap-type marker of a PCI function.
    #[derive(Debug)]
    pub struct BusDeviceCap;
    /// Rights markers.
    #[derive(Debug)]
    pub struct Read;
    #[derive(Debug)]
    pub struct Write;

    /// Why an operation was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CapError;

    /// The module's handle on its probe grant (see the module docs).
    pub struct Cap<T, R>(PhantomData<fn() -> (T, R)>);

    impl<T, R> Clone for Cap<T, R> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T, R> Copy for Cap<T, R> {}
    impl<T, R> core::fmt::Debug for Cap<T, R> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("ModuleProbeGrant")
        }
    }

    /// An operation run under the grant (`narf_capabilities::CapOp`).
    pub trait CapOp<T, R> {
        type Output;
        fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
    }

    /// The liveness probe (`narf_capabilities::NoopOp`).
    #[derive(Clone, Copy, Debug)]
    pub struct NoopOp;
    impl<T, R> CapOp<T, R> for NoopOp {
        type Output = ();
        fn execute(self, _: &Cap<T, R>) -> Result<(), CapError> {
            Ok(())
        }
    }

    impl<T, R> Cap<T, R> {
        /// The grant probe handed this module (one device per module).
        pub(crate) const fn probe_grant() -> Self {
            Self(PhantomData)
        }
        /// Run `op` while a device is bound; the KABI calls inside it are
        /// what the kernel checks against the real cap.
        pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
            if device() == 0 {
                return Err(CapError);
            }
            op.execute(self)
        }
        /// A handle with other rights on the same grant.
        pub fn derive<R2>(&self) -> Result<Cap<T, R2>, CapError> {
            if device() == 0 {
                return Err(CapError);
            }
            Ok(Cap(PhantomData))
        }
    }

    /// `qualcomm_pci::invoke`: run `operation` inside one invocation.
    pub fn invoke<T>(
        cap: &Cap<BusDeviceCap, Write>,
        operation: impl FnOnce() -> T,
    ) -> Result<T, CapError> {
        struct Access<F>(F);
        impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Access<F> {
            type Output = T;
            fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
                Ok(self.0())
            }
        }
        cap.invoke(Access(operation))
    }

    /// PCI command register bits.
    pub mod cmd {
        pub const MEM_SPACE: u16 = 1 << 1;
        pub const BUS_MASTER: u16 = 1 << 2;
    }

    /// A refused config-space operation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PciError(pub i32);

    fn rc(code: i32) -> Result<(), PciError> {
        if code == 0 {
            Ok(())
        } else {
            Err(PciError(code))
        }
    }

    /// Clear, then set, command bits and return the register read back
    /// (`narf_pci_command`; `clear = set = 0` only reads).
    fn command(clear: u16, set: u16) -> Result<u16, PciError> {
        let mut command = 0u16;
        // SAFETY: `command` is a live local.
        rc(unsafe { ffi::narf_pci_command(super::device(), clear, set, &mut command) })?;
        Ok(command)
    }

    /// The command register.
    pub fn read_command(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
    ) -> Result<u16, PciError> {
        command(0, 0)
    }

    /// Set command bits (`narf_pci_enable`, which verifies they read back).
    pub fn set_command(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        bits: u16,
    ) -> Result<(), PciError> {
        // SAFETY: argument-only call on the bound token.
        rc(unsafe { ffi::narf_pci_enable(super::device(), bits) })
    }

    /// Clear command bits. Callers that must prove them clear read the
    /// register back (`read_command`), as built in.
    pub fn clear_command(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        bits: u16,
    ) -> Result<u16, PciError> {
        command(bits, 0)
    }

    /// One device-specific config dword (`narf_pci_config_read32`).
    pub fn read_config32(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        offset: u16,
    ) -> Result<u32, PciError> {
        let mut value = 0u32;
        // SAFETY: `value` is a live local.
        rc(unsafe { ffi::narf_pci_config_read32(super::device(), offset, &mut value) })?;
        Ok(value)
    }

    /// One device-specific config dword (`narf_pci_config_write32`).
    pub fn write_config32(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        offset: u16,
        value: u32,
    ) -> Result<(), PciError> {
        // SAFETY: argument-only call on the bound token.
        rc(unsafe { ffi::narf_pci_config_write32(super::device(), offset, value) })
    }

    /// `PCI_EXP_LNKCTL_ASPMC`.
    pub const LNKCTL_ASPMC: u16 = 0x0003;

    /// The ASPM field the last write through [`clear_and_set_link_control`]
    /// left (bit 15 = valid), for the zero-update read-back.
    static ASPM_WRITTEN: AtomicU64 = AtomicU64::new(0);

    /// `pcie_capability_clear_and_set_word(LNKCTL)` restricted to the ASPM
    /// field (`narf_pcie_aspm`); returns the field before the write.
    ///
    /// The built-in transport also calls it with a zero update to read the
    /// field back. `narf_pcie_aspm` always writes, so that read rewrites the
    /// field this function last wrote (a no-op on a correct link) and
    /// returns what the hardware held: a real read-back, not a remembered
    /// value. Before any write it is refused.
    pub fn clear_and_set_link_control(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        clear: u16,
        set: u16,
    ) -> Result<u16, PciError> {
        let field = if clear == 0 && set == 0 {
            let written = ASPM_WRITTEN.load(Ordering::Acquire);
            if written & (1 << 15) == 0 {
                return Err(PciError(-95));
            }
            (written as u16) & LNKCTL_ASPMC
        } else if clear == LNKCTL_ASPMC && set & !LNKCTL_ASPMC == 0 {
            set
        } else {
            return Err(PciError(-95));
        };
        let mut previous = 0u16;
        // SAFETY: `previous` is a live local.
        rc(unsafe { ffi::narf_pcie_aspm(super::device(), field, &mut previous) })?;
        ASPM_WRITTEN.store(u64::from(field) | (1 << 15), Ordering::Release);
        Ok(previous)
    }

    /// `narf_bus::pci_express::PcieStatus`, the field the driver reads.
    #[derive(Clone, Copy, Debug)]
    pub struct PcieStatus {
        pub device_control: u16,
    }

    /// The function's PCI Express Device Control (`narf_pcie_state`), for
    /// the Relaxed Ordering check behind DMA reclamation.
    pub fn read_status(
        _cap: &Cap<BusDeviceCap, Read>,
        _device: &BusDevice,
    ) -> Result<PcieStatus, PciError> {
        let mut record = [0u8; 20];
        // SAFETY: `record` names 20 writable bytes.
        rc(unsafe { ffi::narf_pcie_state(super::device(), record.as_mut_ptr(), record.len()) })?;
        Ok(PcieStatus {
            device_control: u16::from_le_bytes([record[4], record[5]]),
        })
    }

    /// BAR0 as the transport sees it: a length and 32-bit accessors. The
    /// mapping stays in the kernel; every access is a bounds-checked export.
    #[derive(Copy, Clone, Debug)]
    pub struct MmioRegion {
        pub len: u64,
        bar: u64,
    }

    impl MmioRegion {
        pub(crate) const fn new(bar: u64, len: u64) -> Self {
            Self { len, bar }
        }

        /// # Safety
        /// `off` names a readable register inside the BAR (the kernel
        /// bounds-checks it as well; a refused read returns all-ones).
        pub unsafe fn read32(&self, off: u64) -> u32 {
            let mut value = u32::MAX;
            // SAFETY: `value` is a live local.
            let _ = unsafe { ffi::narf_mmio_read32(super::device(), self.bar, off, &mut value) };
            value
        }

        /// # Safety
        /// `off` names a writable register inside the BAR.
        pub unsafe fn write32(&self, off: u64, value: u32) {
            // SAFETY: argument-only call; the kernel bounds-checks `off`.
            let _ = unsafe { ffi::narf_mmio_write32(super::device(), self.bar, off, value) };
        }
    }
}

/// The function's one plain-MSI vector (`narf_msi_enable(want = 1)`) and
/// its task-context callback.
///
/// Built in, the vector handler runs in hard-IRQ context and only raises
/// the transport's signal. A module's vector callback runs from an executor
/// task (`narf_irq_set_handler`); it raises the same signal and then runs
/// the module's executor, so the woken service makes progress on this CPU
/// now. The KABI programs MSI once per device context, so the grant is kept
/// for the device's lifetime and later generations re-arm the same vector.
pub mod msi {
    use super::*;

    type Handler = fn();

    static GRANT: IrqSafeSpinLock<Option<u16>> = IrqSafeSpinLock::new(None);
    static HANDLER: IrqSafeSpinLock<Option<Handler>> = IrqSafeSpinLock::new(None);

    extern "C" fn trampoline(_cookie: u64) -> i32 {
        let handler = *HANDLER.lock();
        if let Some(handler) = handler {
            handler();
        }
        let _ = EXEC.run();
        0
    }

    /// Allocate (once) and bind the vector to `handler`, delivery still
    /// off. `None` leaves the transport polled.
    pub fn arm(handler: Handler) -> Option<u16> {
        let mut grant = GRANT.lock();
        let vector = match *grant {
            Some(vector) => vector,
            None => {
                let (mut count, mut base, mut addr, mut data) = (0u16, 0u16, 0u64, 0u32);
                // SAFETY: the four outputs are live locals.
                let rc = unsafe {
                    ffi::narf_msi_enable(device(), 1, &mut count, &mut base, &mut addr, &mut data)
                };
                if rc != 0 || count != 1 {
                    return None;
                }
                // SAFETY: `trampoline` is a valid `extern "C" fn(u64) -> i32`
                // in this module's text, which the kernel unbinds before
                // unmapping it.
                if unsafe { ffi::narf_irq_set_handler(device(), base, trampoline as usize, 0) } != 0
                {
                    return None;
                }
                *grant = Some(base);
                base
            }
        };
        *HANDLER.lock() = Some(handler);
        Some(vector)
    }

    /// MSI Enable at the function.
    pub fn set_enabled(enabled: bool) -> bool {
        // SAFETY: argument-only call on the bound token.
        unsafe { ffi::narf_msi_set_enabled(device(), u32::from(enabled)) == 0 }
    }

    /// Detach the handler (the vector stays granted, delivery off).
    pub fn disarm() {
        *HANDLER.lock() = None;
    }
}

/// Firmware lookup through `narf_firmware_open` / `_read` / `_signed`.
pub mod firmware {
    use super::*;

    /// Why a firmware file could not be had.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FwError {
        NotFound,
        NoMemory,
        /// Unsigned where a signer is required, or failed validation.
        Invalid,
    }

    /// The KABI reads at most this much per call.
    const CHUNK: usize = 64 * 1024;

    /// The whole file, at most `max` bytes; `signed` requires a verified
    /// signer (board and calibration data, regulatory policy), as built in.
    /// The module's `Firmware` manifest cap is the authority.
    pub fn load(name: &str, max: usize, signed: bool) -> Result<Vec<u8>, FwError> {
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

/// The regulatory domain the module's station checks against: the kernel's
/// installed domain (`narf_wireless::reg::db`, the one the built-in driver
/// reads, with its user and Country-IE changes), copied through
/// `narf_wireless_regdomain` as an NRGD v1 record on every read, as built
/// in each check reads the live database. An unchanged record keeps the
/// previous snapshot's `Arc`, so snapshot identity still tracks a change of
/// the installed domain.
pub mod reg {
    use super::*;
    use narf_wireless::reg::{parse_domain_record, RegulatoryDomain};

    /// Why no domain could be had.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        /// The export's errno (`-ENODATA`: none installed or bootstrapped).
        Kernel(i32),
        Format(&'static str),
    }

    /// The last record and its decoded domain.
    static CACHE: IrqSafeSpinLock<Option<(Vec<u8>, Arc<RegulatoryDomain>)>> =
        IrqSafeSpinLock::new(None);

    fn record() -> Result<Vec<u8>, Error> {
        let mut needed = 0usize;
        // SAFETY: sizing call — null buffer, zero length, live `needed`.
        let rc = unsafe { ffi::narf_wireless_regdomain(core::ptr::null_mut(), 0, &mut needed) };
        if rc != 0 && rc != -105 {
            return Err(Error::Kernel(rc));
        }
        let mut bytes = alloc::vec![0u8; needed];
        let mut got = 0usize;
        // SAFETY: `bytes` names `needed` writable bytes; `got` is live.
        let rc = unsafe { ffi::narf_wireless_regdomain(bytes.as_mut_ptr(), bytes.len(), &mut got) };
        if rc != 0 {
            return Err(Error::Kernel(rc));
        }
        bytes.truncate(got);
        Ok(bytes)
    }

    /// The record as `narf_wireless::reg::parse_domain_record` decodes it:
    /// `parse_policy`'s layout and rule checks, with the world domain "00"
    /// accepted.
    fn decode(bytes: &[u8]) -> Result<RegulatoryDomain, Error> {
        parse_domain_record(bytes).map_err(Error::Format)
    }

    /// The kernel's current domain.
    pub fn ensure_snapshot() -> Result<Arc<RegulatoryDomain>, Error> {
        let bytes = record()?;
        if let Some((cached, domain)) = CACHE.lock().as_ref() {
            if *cached == bytes {
                return Ok(domain.clone());
            }
        }
        let domain = Arc::new(decode(&bytes)?);
        *CACHE.lock() = Some((bytes, domain.clone()));
        Ok(domain)
    }

    /// `narf_wireless::reg::db::ensure_domain`.
    pub fn ensure_domain() -> Result<RegulatoryDomain, Error> {
        ensure_snapshot().map(|domain| domain.as_ref().clone())
    }

    /// `narf_wireless::reg::db::snapshot`.
    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        ensure_snapshot().ok()
    }

    /// `narf_wireless::reg::db::get_domain`.
    pub fn get_domain() -> Option<RegulatoryDomain> {
        snapshot().map(|domain| domain.as_ref().clone())
    }
}

/// The AP and off-channel (ROC) owners' kernel authorities.
///
/// Built in these come from `narf_wireless::ap_control`, minted by the
/// nl80211 AP and radio-control paths. The module has no such path (the
/// `WIFI` host v2 is station-only), so here no value of them can exist:
/// each wraps the uninhabited [`Never`](ap_control::Never) in a private
/// field. The radio's AP/ROC code still compiles unchanged; nothing in the
/// `.ko` can construct the authority that would start it.
pub mod ap_control {
    use core::sync::atomic::AtomicU64;

    /// No AP/ROC authority can exist in the module.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Never {}

    macro_rules! unconstructible {
        ($($name:ident),*) => {$(
            #[derive(Clone, Debug)]
            pub struct $name {
                never: Never,
            }
            impl $name {
                pub fn current(&self) -> bool {
                    match self.never {}
                }
            }
        )*};
    }
    unconstructible!(
        ApEmissionAuthority,
        RadioEmissionAuthority,
        RadioInterfaceIdentity,
        PreparedRadioManagementEvent
    );

    /// `narf_wireless::ap_control::RadioEventAuthority`.
    #[derive(Clone, Debug)]
    pub struct RadioEventAuthority {
        never: Never,
    }

    impl RadioEventAuthority {
        pub fn current(&self) -> Result<(), Never> {
            match self.never {}
        }
        pub fn registration_current(&self) -> Result<(), Never> {
            match self.never {}
        }
        pub fn check_for<I: super::WirelessNetIface + ?Sized>(
            &self,
            _iface: &I,
        ) -> Result<(), Never> {
            match self.never {}
        }
        pub fn prepare_management_received(
            &self,
            _frequency: u32,
            _signal_dbm: Option<i8>,
            _frame: &[u8],
        ) -> Result<PreparedRadioManagementEvent, Never> {
            match self.never {}
        }
    }

    /// `narf_wireless::ap_control::RadioReceiveFence`.
    #[derive(Debug)]
    pub struct RadioReceiveFence<'a> {
        pub epoch: &'a AtomicU64,
        pub generation: u64,
        pub receiver: &'a RadioEmissionAuthority,
        pub origin: &'a RadioEmissionAuthority,
    }

    impl PreparedRadioManagementEvent {
        pub fn deliver(self, _fence: RadioReceiveFence<'_>) -> Result<(), Never> {
            match self.never {}
        }
    }
}

/// The nl80211 netdev trait the ROC receive path is generic over; the
/// module implements it for nothing.
pub trait WirelessNetIface {}
