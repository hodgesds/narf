//! The module build's PCI binding (`mt76.ko`), mounted as `mt7921::pci`: the
//! names the firmware transport uses (`claim_firmware_transport`,
//! `generation`, `release_transport_claim`) and the probe, over the KABI
//! instead of `narf-bus`.
//!
//! The probe is the built-in `bring_up_current` step for step (Linux
//! `mt7921_pci_probe` up to `mt7921_register_device`):
//!
//! 1. identity (`narf_pci_identity`) against the CONNAC2 id table; firmware-
//!    owned DMA is retained on teardown from the start;
//! 2. `narf_pci_prepare_probe` parks inherited decode and mastering, which
//!    is verified (`narf_pci_command`);
//! 3. BAR0 is mapped and every identity/power register is checked to lie
//!    inside it;
//! 4. memory decode with INTx disabled — no bus mastering: the function may
//!    still carry WFDMA ring bases inherited from firmware or a previous OS;
//! 5. ASPM off (`narf_pcie_aspm`);
//! 6. chip id / revision / bond, and the MT7961 -> MT7920 retag;
//! 7. driver ownership and the WFSYS reset (`mac::initialize_probe`);
//! 8. the 1 ms poller becomes the executor's heartbeat, and the same
//!    `firmware_transport::boot_radio` task the built-in initcall spawns
//!    downloads the patch and RAM code, initializes the radio and publishes
//!    the station netdev (`iface_module`).
//!
//! Bus mastering is granted only by the firmware transport, after it has
//! programmed its own rings, exactly as built in.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::firmware_transport::{Error, Firmware, Transport};
use super::mac;
pub(super) use super::pci_common::validate_probe_window;
use super::pci_common::{chip_id_read, hw_bound_read, hw_rev_read};
pub use super::pci_common::{firmware_blobs_for, l1_remap, name_for, ProbeError};
use super::regs::*;
use crate::platform::bus::{cmd, BusDevice, DeviceCap, MmioRegion, PciId};
use crate::platform::{self, IrqSafeSpinLock};

/// KABI exports the PCI binding calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_register_pci_driver(
            name: *const u8,
            len: usize,
            vendor: u16,
            device: u16,
            probe: usize,
        ) -> i32;
        pub fn narf_pci_prepare_probe(dev: u64) -> i32;
        pub fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32;
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
        pub fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;

/// The command bits the identity/driver-own probe runs with (the built-in
/// `PROBE_COMMAND`): decode on, INTx off, bus mastering deliberately off.
const PROBE_COMMAND: u16 = cmd::MEM_SPACE | cmd::INTX_DISABLE;

/// The PCI ids the module claims: the built-in table (`ALL_DEV_IDS` under the
/// MediaTek vendor id, plus the ITTIM-vendor MT7922 SKU).
pub const MODULE_IDS: &[(u16, u16)] = &[
    (MTK_VENDOR, MTK_DEV_MT7961),
    (MTK_VENDOR, MTK_DEV_MT7922),
    (MTK_VENDOR, MTK_DEV_MT7921),
    (MTK_VENDOR, MTK_DEV_MT7921_ALT),
    (MTK_VENDOR, MTK_DEV_MT7920),
    (ITTIM_VENDOR, MTK_DEV_MT7922),
];

/// What the binding retains after probe (the built-in `Mt7921Device`).
#[derive(Clone, Copy, Debug)]
struct Controller {
    mmio: MmioRegion,
    device: BusDevice,
    /// Device id after the MT7961 -> MT7920 retag.
    effective_did: u16,
    chip_id: u32,
    chip_rev: u8,
}

/// One bound function per module image (laptops carry one MT7921/MT7922).
static CONTROLLER: IrqSafeSpinLock<Option<Controller>> = IrqSafeSpinLock::new(None);
static TRANSPORT_CLAIMED: AtomicBool = AtomicBool::new(false);
/// Binding generation, as built in: odd while a function is bound; a
/// transport carries the generation it was claimed under.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static CLAIM_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Current binding generation; odd while a function is bound.
pub(super) fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// A retired transport of `generation` returns its claim.
pub(super) fn release_transport_claim(generation: u64) {
    let _controller = CONTROLLER.lock();
    if CLAIM_GENERATION.load(Ordering::Acquire) == generation {
        TRANSPORT_CLAIMED.store(false, Ordering::Release);
    }
}

/// Whether probe bound a function.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Hand the bound function to the firmware transport (the built-in
/// `claim_firmware_transport`): the firmware files are read and validated
/// first, then the transport allocates its unpublished rings.
pub(super) fn claim_firmware_transport() -> Result<Option<Transport>, Error> {
    let Some(controller) = *CONTROLLER.lock() else {
        return Ok(None);
    };
    if TRANSPORT_CLAIMED.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    let generation = self::generation();
    let firmware = Firmware::open(controller.effective_did)?;
    {
        let guard = CONTROLLER.lock();
        if guard.is_none() || self::generation() != generation {
            return Err(Error::DeviceGone);
        }
        TRANSPORT_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Busy)?;
        CLAIM_GENERATION.store(generation, Ordering::Release);
    }
    // SAFETY: the provisioning mutex and owner/work locks serialize this
    // handoff. Probe parked bus mastering; no transport has been claimed and
    // no MT76 rings have been published for this binding.
    let transport = unsafe {
        Transport::new(
            controller.mmio,
            controller.device,
            DeviceCap::for_token(controller.device.token),
            firmware,
            generation,
        )
    };
    if transport.is_err() {
        release_transport_claim(generation);
    }
    transport.map(Some)
}

/// Register the CONNAC2 PCI ids; the kernel calls [`probe_c`] for a match.
pub fn register() {
    const NAME: &[u8] = b"mt76";
    platform::install_entropy();
    for &(vendor, device) in MODULE_IDS {
        // SAFETY: `NAME` is 'static and `probe_c` is a valid extern "C" fn;
        // the loader unregisters every match before this image is unmapped.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                vendor,
                device,
                probe_c as usize,
            )
        };
        if rc != 0 {
            let _ = writeln!(
                platform::Console,
                "  mt76.ko: PCI registration of {vendor:04x}:{device:04x} failed ({rc})"
            );
        }
    }
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    let _ = platform::EXEC.run();
    0
}

/// `(vendor, device)` from the function's identity record.
fn identity(dev: u64) -> Option<PciId> {
    let mut record = [0u8; 16];
    // SAFETY: `record` names 16 writable bytes.
    if unsafe { ffi::narf_pci_identity(dev, record.as_mut_ptr(), record.len()) } != 0 {
        return None;
    }
    Some(PciId {
        vendor: u16::from_le_bytes([record[0], record[1]]),
        device: u16::from_le_bytes([record[2], record[3]]),
    })
}

fn command(dev: u64, clear: u16, set: u16) -> Result<u16, ProbeError> {
    let mut value = 0u16;
    // SAFETY: `value` is a live local.
    match unsafe { ffi::narf_pci_command(dev, clear, set, &mut value) } {
        0 if value != u16::MAX => Ok(value),
        0 => Err(ProbeError::DeviceGone),
        _ => Err(ProbeError::Authority),
    }
}

/// The built-in `bring_up_current` over the KABI.
fn bring_up(dev: u64, id: PciId) -> Result<Controller, ProbeError> {
    const PARKED: u16 = cmd::BUS_MASTER | cmd::MEM_SPACE | cmd::INTX_DISABLE;
    // SAFETY: argument-only call on our fresh probe token.
    if unsafe { ffi::narf_pci_prepare_probe(dev) } != 0 {
        return Err(ProbeError::Authority);
    }
    if command(dev, 0, 0)? & PARKED != cmd::INTX_DISABLE {
        return Err(ProbeError::Authority);
    }
    // ── Stage 0: BAR0 mapping ──
    // SAFETY: argument-only call on our probe token.
    let bar = unsafe { ffi::narf_bar_map(dev, 0) };
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if bar == 0 || unsafe { ffi::narf_bar_len(dev, bar, &mut len) } != 0 {
        return Err(ProbeError::Bar0MapFailed);
    }
    let mmio = MmioRegion::new(bar, len);
    validate_probe_window(mmio.len)?;
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_enable(dev, PROBE_COMMAND) } != 0
        || command(dev, 0, 0)? & PARKED != PROBE_COMMAND
    {
        return Err(ProbeError::Authority);
    }
    let mut previous = 0u16;
    // SAFETY: `previous` is a live local.
    if unsafe { ffi::narf_pcie_aspm(dev, 0, &mut previous) } != 0 {
        return Err(ProbeError::Authority);
    }
    let _ = writeln!(
        platform::Console,
        "  mt76.ko: BAR0 mapped ({} bytes); reading identity",
        mmio.len
    );
    // SAFETY: probe owns BAR0 and its L1 selector; the checked access
    // validates every word.
    let (chip_id, hw_rev, bound) = unsafe {
        (
            chip_id_read(&mmio)?,
            hw_rev_read(&mmio)?,
            hw_bound_read(&mmio)?,
        )
    };
    if [chip_id, hw_rev, bound].contains(&u32::MAX) {
        return Err(ProbeError::DeviceGone);
    }
    let raw_chip = (chip_id & 0xffff) as u16;
    if !matches!(raw_chip, MTK_DEV_MT7961 | MTK_DEV_MT7922 | MTK_DEV_MT7920) {
        return Err(ProbeError::UnsupportedChip);
    }
    let effective_did = if raw_chip == MTK_DEV_MT7961 && (bound & MT_HW_BOUND_DBDC) != 0 {
        MTK_DEV_MT7920
    } else {
        raw_chip
    };
    let _ = writeln!(
        platform::Console,
        "  mt76.ko: chip={raw_chip:04x} rev={hw_rev:#x}; taking driver ownership"
    );
    // Ownership before any WFSYS access, with bus mastering verified off.
    if command(dev, 0, 0)? & PARKED != PROBE_COMMAND {
        return Err(ProbeError::Authority);
    }
    // SAFETY: probe owns BAR0, bus mastering is verified off and no host DMA
    // allocation or transport exists.
    match unsafe { mac::initialize_probe(&mmio) } {
        Ok(()) => {}
        Err(mac::PowerError::Timeout) => return Err(ProbeError::DriverOwnTimeout),
        Err(mac::PowerError::DeviceGone) => return Err(ProbeError::DeviceGone),
        Err(mac::PowerError::InvalidWindow) => return Err(ProbeError::UnsupportedRegisterWindow),
        Err(mac::PowerError::ResetRejected | mac::PowerError::ResetTimeout) => {
            return Err(ProbeError::ResetFailed);
        }
    }
    Ok(Controller {
        mmio,
        device: BusDevice { token: dev, id },
        effective_did,
        chip_id,
        chip_rev: (hw_rev & 0xff) as u8,
    })
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, reserved: u64) -> i32 {
    // Every device export after this point takes the bound token: a second
    // function must not replace it.
    if reserved != 0 || CONTROLLER.lock().is_some() {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 {
        platform::set_device(0);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    platform::set_device(dev);
    let Some(id) = identity(dev) else {
        return ENODEV;
    };
    if !MODULE_IDS.contains(&(id.vendor, id.device)) {
        return ENODEV;
    }
    // Firmware owns the rings from the first DMA enable; a teardown that
    // cannot prove the device stopped must not free them.
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    let controller = match bring_up(dev, id) {
        Ok(controller) => controller,
        Err(error) => {
            // No controller was published: leave the function inert.
            let _ = command(dev, cmd::MEM_SPACE | cmd::BUS_MASTER, 0);
            let _ = writeln!(
                platform::Console,
                "  mt76.ko: bring-up failed ({:04x}:{:04x}): {error:?}",
                id.vendor,
                id.device
            );
            return EIO;
        }
    };
    let _ = writeln!(
        platform::Console,
        "  mt76.ko: probed {} ({:04x}:{:04x}) chip={:04x} rev={:#04x}; ownership and WFSYS ready",
        name_for(controller.effective_did),
        id.vendor,
        id.device,
        (controller.chip_id & 0xffff) as u16,
        controller.chip_rev,
    );
    {
        let mut guard = CONTROLLER.lock();
        *guard = Some(controller);
        GENERATION.fetch_add(1, Ordering::AcqRel);
    }
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller before unmapping it.
    if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
        return EIO;
    }
    // The built-in initcall's bring-up task: firmware download, radio
    // initialization, netdev publication, then retry/recovery on failure.
    platform::spawn(super::firmware_transport::boot_radio());
    let _ = platform::EXEC.run();
    0
}

/// Module exit (the built-in `remove`, Linux `mt7921_pci_remove`): end the
/// binding generation, withdraw the netdev, retire the transport with its
/// DMA stop proven where possible, then stop the executor. Without a proof
/// the rings stay retained (`narf_dma_retain_on_teardown`) and only bus
/// mastering is cleared, exactly as built in.
pub fn exit() {
    let dev = platform::device();
    let retired_generation = {
        let mut guard = CONTROLLER.lock();
        if guard.take().is_none() {
            platform::EXEC.stop();
            return;
        }
        GENERATION.fetch_add(1, Ordering::AcqRel)
    };
    crate::iface_module::withdraw();
    let retired = super::firmware_transport::retire_for_removal(retired_generation);
    platform::EXEC.stop();
    let bits = if retired {
        cmd::BUS_MASTER | cmd::MEM_SPACE
    } else {
        cmd::BUS_MASTER
    };
    let _ = command(dev, bits, 0);
    if retired {
        release_transport_claim(retired_generation);
        // SAFETY: argument-only call on our probe token; the rings' DMA
        // retirement is proven.
        let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 0) };
    }
    let _ = writeln!(
        platform::Console,
        "  mt76.ko: removed (generation {retired_generation}, transport {})",
        if retired { "retired" } else { "retained" },
    );
}
