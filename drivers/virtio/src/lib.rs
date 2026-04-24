//! narf-drivers-virtio — virtio-mmio transport probe + skeleton driver.
//!
//! Spec: `drivers/virtio/specification/spec.md`. Stage 3 Wave 3b
//! side-track scope: just enough of virtio-mmio to validate the
//! transport (magic + version + device-id) and hand the driver
//! framework a `Driver` impl that records a probe sweep at boot.
//! Concrete virtio device subdrivers (virtio-blk, virtio-net,
//! virtio-console) and the virtqueue descriptor-ring setup are
//! deferred to Wave 4.
//!
//! What exists in Wave 3b:
//! - Register-offset constants for the full modern (version 2)
//!   virtio-mmio transport layout, per the virtio 1.2 spec §4.2.2.
//! - `VirtioMmioDevice` — a probed transport: base pointer + cached
//!   identification (`device_id`, `vendor_id`, `version`). The type is
//!   constructed only via `probe`, which validates magic + version and
//!   rejects empty slots.
//! - `ProbeError` — enumerates the ways a probe can decline: wrong
//!   `BusKind`, wrong magic, unsupported version, empty slot.
//! - `VirtioSkeletonDriver` — no-op `narf_drivers::Driver` impl whose
//!   `start` hook walks the bus registry, probes every
//!   `BusKind::VirtioMmio` device it finds, and records the success
//!   count in an atomic so tests can assert. Intentionally passive: it
//!   does not negotiate features, set `QUEUE_READY`, or touch any
//!   driver-status bits.
//!
//! Non-goals for Wave 3b (Wave 4 picks up):
//! - Feature negotiation (`DEVICE_FEATURES` / `DRIVER_FEATURES`
//!   handshake + `FEATURES_OK` bit in `STATUS`).
//! - Virtqueue descriptor-ring construction (`QUEUE_DESC_*` /
//!   `QUEUE_DRIVER_*` / `QUEUE_DEVICE_*` programming + `QUEUE_READY`).
//! - Buffer submission through the available ring and completion
//!   consumption from the used ring.
//! - Interrupt binding (virtio-mmio uses a single shared IRQ with a
//!   status register at 0x60 / 0x64; needs `interrupts/` Stage-3
//!   routing).
//! - Device-specific subdrivers: virtio-blk (DeviceID 2), virtio-net
//!   (DeviceID 1), virtio-console (DeviceID 3), virtio-gpu, etc.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

use narf_bus::{BusDevice, BusKind};
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_memory::PhysAddr;

// ── virtio-mmio register offsets ────────────────────────────────────
//
// All offsets are in bytes from the MMIO window's base. Values come
// from the virtio 1.2 specification §4.2.2 "MMIO Device Register
// Layout". Only the registers we actually touch in Wave 3b are
// consumed by this crate; the rest are exported for Wave 4 consumers
// (virtqueue setup, feature negotiation, device-specific config).

/// Magic at offset 0x00. Identifies the window as a virtio-mmio
/// transport. Must read back as `VIRTIO_MAGIC`.
pub const MAGIC_VALUE: u64 = 0x000;
/// Transport version. `2` = modern (1.0+); `1` = legacy (not supported).
pub const VERSION: u64 = 0x004;
/// Device identification. `0` means the slot is unpopulated.
pub const DEVICE_ID: u64 = 0x008;
/// Vendor identification (informational).
pub const VENDOR_ID: u64 = 0x00C;
/// Device-offered feature bits (banked by `DEVICE_FEATURES_SEL`).
pub const DEVICE_FEATURES: u64 = 0x010;
/// Selects which queue subsequent queue-related registers address.
pub const QUEUE_SEL: u64 = 0x030;
/// Maximum queue depth the device supports for the selected queue.
pub const QUEUE_NUM_MAX: u64 = 0x034;
/// Driver-chosen queue depth for the selected queue.
pub const QUEUE_NUM: u64 = 0x038;
/// `1` = queue ready for use, `0` = quiesced.
pub const QUEUE_READY: u64 = 0x044;
/// Doorbell — write a queue index here to notify the device.
pub const QUEUE_NOTIFY: u64 = 0x050;
/// Device-status bits (ACK / DRIVER / FEATURES_OK / DRIVER_OK / FAILED).
pub const STATUS: u64 = 0x070;
/// Low 32 bits of the physical address of the selected queue's
/// descriptor table.
pub const QUEUE_DESC_LOW: u64 = 0x080;
/// High 32 bits of the physical address of the selected queue's
/// descriptor table.
pub const QUEUE_DESC_HIGH: u64 = 0x084;
/// Low 32 bits of the physical address of the selected queue's
/// driver-area (available ring).
pub const QUEUE_DRIVER_LOW: u64 = 0x090;
/// High 32 bits of the physical address of the selected queue's
/// driver-area.
pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
/// Low 32 bits of the physical address of the selected queue's
/// device-area (used ring).
pub const QUEUE_DEVICE_LOW: u64 = 0x0A0;
/// High 32 bits of the physical address of the selected queue's
/// device-area.
pub const QUEUE_DEVICE_HIGH: u64 = 0x0A4;
/// Monotonic counter that ticks whenever the device-specific config
/// changes; read twice and retry if it differs.
pub const CONFIG_GENERATION: u64 = 0x0FC;
/// Base of the device-specific configuration area.
pub const CONFIG: u64 = 0x100;

/// Magic cookie expected at `MAGIC_VALUE`. ASCII "virt" in
/// little-endian byte order: 'v' (0x76), 'i' (0x69), 'r' (0x72),
/// 't' (0x74) → 0x7472_6976.
pub const VIRTIO_MAGIC: u32 = 0x7472_6976;

/// Modern virtio-mmio transport version. Legacy (`1`) used a different
/// queue programming model and is intentionally unsupported here;
/// QEMU defaults to version 2 on every transport it exposes.
pub const VIRTIO_VERSION_MODERN: u32 = 2;

// ── Probe surface ───────────────────────────────────────────────────

/// Reasons `VirtioMmioDevice::probe` can decline.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The `BusDevice` handed in wasn't a `BusKind::VirtioMmio`.
    NotVirtioMmio,
    /// Magic register did not read back as `VIRTIO_MAGIC`.
    WrongMagic,
    /// Version register was neither the modern value nor any version
    /// this crate understands. Legacy `1` lives here; QEMU never
    /// emits it on `virt` / `q35`.
    UnsupportedVersion,
    /// The slot is structurally sound (magic ok, version ok) but
    /// `DEVICE_ID` read back as zero — per virtio-mmio spec §4.2.2,
    /// that means "no device present at this slot". The bus-registry
    /// walker filters most of these out; this variant exists for
    /// direct callers (and the synthesised-window test).
    NoDevice,
}

/// A probed virtio-mmio transport. Constructed via `probe`; every
/// field is filled from a volatile read at probe time and cached
/// thereafter. Drivers that actually want to *drive* the transport
/// will, in Wave 4, take `mmio_base()` and start writing to the
/// programming registers — but for now this type is strictly
/// read-only.
#[derive(Copy, Clone)]
pub struct VirtioMmioDevice {
    base: PhysAddr,
    device_id: u32,
    vendor_id: u32,
    version: u32,
}

impl core::fmt::Debug for VirtioMmioDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioMmioDevice")
            .field("base", &self.base)
            .field("device_id", &self.device_id)
            .field("vendor_id", &self.vendor_id)
            .field("version", &self.version)
            .finish()
    }
}

impl VirtioMmioDevice {
    /// Probe the transport named by `dev`. Validates transport magic
    /// and version, reads device + vendor ID. Returns
    /// `ProbeError::NoDevice` iff magic and version are fine but the
    /// slot is unpopulated.
    ///
    /// Callers typically iterate `narf_bus::devices()` and ignore
    /// `NotVirtioMmio` / `NoDevice` — those are expected for non-matching
    /// entries. `WrongMagic` / `UnsupportedVersion` signal a genuine
    /// configuration error worth surfacing.
    pub fn probe(dev: &BusDevice) -> Result<Self, ProbeError> {
        let base = match dev.kind {
            BusKind::VirtioMmio { base, .. } => base,
            _ => return Err(ProbeError::NotVirtioMmio),
        };
        // SAFETY: `BusKind::VirtioMmio::base` is populated by
        // `narf_bus`'s arch-specific enumerator only for regions it
        // has already identity-mapped and already volatile-read the
        // magic register of. We repeat the reads here so the
        // `VirtioMmioDevice` fields reflect the transport state at
        // probe time rather than enumeration time.
        unsafe { Self::probe_raw(base.raw()) }
    }

    /// Probe a raw MMIO address. Exposed for synthetic-pointer tests
    /// (the `smoke_virtio_mmio_wrong_magic` harness) and for callers
    /// that have already resolved the address via some other path.
    ///
    /// # Safety
    /// `addr` must point at a readable region covering at least
    /// `CONFIG` bytes (0x100), aligned to `u32`. A region that
    /// happens to read back a non-magic value simply surfaces as
    /// `ProbeError::WrongMagic`; the safety burden is strictly on
    /// "is this address dereferenceable".
    pub unsafe fn probe_raw(addr: u64) -> Result<Self, ProbeError> {
        // SAFETY: caller asserts the region is readable.
        let magic = unsafe { read_reg(addr, MAGIC_VALUE) };
        if magic != VIRTIO_MAGIC {
            return Err(ProbeError::WrongMagic);
        }

        // SAFETY: same region, offset within the 0x100-byte transport
        // window per virtio 1.2 §4.2.2.
        let version = unsafe { read_reg(addr, VERSION) };
        if version != VIRTIO_VERSION_MODERN {
            return Err(ProbeError::UnsupportedVersion);
        }

        // SAFETY: same region.
        let device_id = unsafe { read_reg(addr, DEVICE_ID) };
        if device_id == 0 {
            return Err(ProbeError::NoDevice);
        }

        // SAFETY: same region.
        let vendor_id = unsafe { read_reg(addr, VENDOR_ID) };

        Ok(Self {
            base: PhysAddr::new(addr),
            device_id,
            vendor_id,
            version,
        })
    }

    /// virtio-mmio DeviceID, see virtio 1.2 §5 for the per-device
    /// mapping (1 = net, 2 = block, 3 = console, ...).
    #[inline]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }
    /// Vendor identification register.
    #[inline]
    pub fn vendor_id(&self) -> u32 {
        self.vendor_id
    }
    /// Transport version — always `VIRTIO_VERSION_MODERN` for a
    /// successfully-probed device in Wave 3b.
    #[inline]
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Physical base of the MMIO window. Callers that need to write
    /// to programming registers (Wave 4) take this address and build
    /// their own accessor.
    #[inline]
    pub fn mmio_base(&self) -> PhysAddr {
        self.base
    }
}

/// Volatile 4-byte read of a virtio-mmio register. The
/// compiler-fence pair is the standard NARF MMIO idiom (see
/// `arch/` §4 and `bus/src/aarch64/mod.rs::probe_virtio_mmio`): fat
/// LTO will otherwise reorder loads and stores around volatile MMIO
/// accesses.
///
/// # Safety
/// `base + offset` must be readable and `u32`-aligned.
#[inline]
unsafe fn read_reg(base: u64, offset: u64) -> u32 {
    let p = (base + offset) as *const u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted MMIO window.
    let v = unsafe { core::ptr::read_volatile(p) };
    compiler_fence(Ordering::SeqCst);
    v
}

// ── Skeleton driver ─────────────────────────────────────────────────

/// No-op `narf_drivers::Driver`. On `start` it walks the bus registry
/// once, attempts to probe every `BusKind::VirtioMmio` device, and
/// records three counters the test can observe:
/// - `probed_ok`: probes that returned `Ok(_)`.
/// - `probed_no_device`: probes that returned `NoDevice` (empty slot
///   — benign).
/// - `probed_error`: probes that returned some other error (a genuine
///   misconfiguration).
///
/// Wave 4 replaces this with a real dispatcher that, per device-id,
/// spawns a subdriver (virtio-blk / virtio-net / …) against the
/// `DriverRegistry`.
#[derive(Debug, Default)]
pub struct VirtioSkeletonDriver {
    pub probed_ok: AtomicU32,
    pub probed_no_device: AtomicU32,
    pub probed_error: AtomicU32,
}

impl VirtioSkeletonDriver {
    pub const fn new() -> Self {
        Self {
            probed_ok: AtomicU32::new(0),
            probed_no_device: AtomicU32::new(0),
            probed_error: AtomicU32::new(0),
        }
    }

    /// Run the probe sweep synchronously. Exposed so a test can
    /// drive it without the async lifecycle. Returns the number of
    /// successful probes (matches the increment to `probed_ok`).
    pub fn probe_registry(&self) -> u32 {
        let mut ok = 0u32;
        for dev in narf_bus::devices() {
            if !matches!(dev.kind, BusKind::VirtioMmio { .. }) {
                continue;
            }
            match VirtioMmioDevice::probe(&dev) {
                Ok(_) => {
                    self.probed_ok.fetch_add(1, Ordering::Relaxed);
                    ok += 1;
                }
                Err(ProbeError::NoDevice) => {
                    self.probed_no_device.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.probed_error.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        ok
    }
}

impl Driver for VirtioSkeletonDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            self.probe_registry();
        })
    }
    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move { /* no resources to release yet */ })
    }
}
