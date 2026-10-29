//! MT7921 PCI probe.
//!
//! Stage-0: register the PCI match table, map BAR0, read
//! `MT_HW_CHIPID` / `MT_HW_REV`, and apply the MT7920 re-tagging that
//! Linux's `mt7921/pci.c` does at probe time (line ~358 in v6.6).
//!
//! Stage-1 power-on (driver-own latch, EFUSE MCU stub) lives in
//! `mac.rs`. The probe entry orchestrates both stages and degrades
//! gracefully when firmware blobs aren't installed — the chip will
//! be recorded as bound + the MAC field will be the EFUSE-derived
//! value if available, else the all-zero sentinel.
//!
//! References (all GPL-2.0; NARF is GPL-2.0-or-later since 2026-05-20):
//!
//! - `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` —
//!   `mt7921_pci_probe`, `mt7921_pci_device_table`,
//!   the `chipid == 0x7961 && BIT(7)` re-tag at ~L358.
//! - `drivers/net/wireless/mediatek/mt76/mt792x_regs.h` —
//!   `MT_HW_CHIPID`, `MT_HW_REV`, `MT_HW_BOUND`.

#![allow(dead_code)]

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::mac;
use super::regs::*;

pub(super) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct Registers<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Registers<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Registers(operation))
}

/// One bound MT7921 controller — what the driver retains after probe.
///
/// Single-instance per the baseline: laptops ship at most one PCIe
/// MT7921/MT7922 radio. Multi-radio support is a non-goal here.
pub struct Mt7921Device {
    pub mmio_bar0: MmioRegion,
    /// PCI device id we matched on (post-re-tagging — 0x7961 may have
    /// been folded to 0x7920 if MT_HW_BOUND[7] was set).
    pub effective_did: u16,
    /// Raw chip-id read from `MT_HW_CHIPID`.
    pub chip_id: u32,
    /// Chip revision byte (low 8 bits of `MT_HW_REV`).
    pub chip_rev: u8,
    /// True once `mac::take_driver_own` succeeded.
    pub driver_owned: bool,
    /// EFUSE-derived MAC. All-zero if EFUSE read hasn't run / failed
    /// (firmware not loaded or MCU not alive).
    pub mac: [u8; MAC_ADDR_LEN],
}

impl core::fmt::Debug for Mt7921Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mt7921Device")
            .field(
                "effective_did",
                &format_args!("{:#06x}", self.effective_did),
            )
            .field("chip_id", &format_args!("{:#010x}", self.chip_id))
            .field("chip_rev", &format_args!("{:#04x}", self.chip_rev))
            .field("driver_owned", &self.driver_owned)
            .field("mac", &self.mac)
            .finish()
    }
}

/// Errors raised by the Stage-0/Stage-1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Current PCI invocation or command-policy validation failed.
    Authority,
    /// The register window cannot contain all required probe accesses.
    UnsupportedRegisterWindow,
    /// The hardware did not latch the requested indirect register page.
    RemapRejected,
    /// Chip identity is not supported by this CONNAC2 implementation.
    UnsupportedChip,
    /// `map_bar_control(device, 0)` failed. Most likely the BAR isn't
    /// implemented (wrong PCI ID matched) or another driver claimed it.
    Bar0MapFailed,
    /// BAR0 reads returned the all-FF sentinel that means "device
    /// gone" — link down or surprise-remove.
    DeviceGone,
    /// Driver-own handshake timed out after `DRV_OWN_RETRY_COUNT`
    /// retries. Either the firmware never released ownership (cold
    /// power-up with no PCIE_BUS_PWR), or the chip is wedged.
    DriverOwnTimeout,
    /// Legacy EFUSE probe error. Discovery leaves MAC unset; the retained
    /// post-firmware path requires a valid firmware-reported MAC.
    EfuseRead,
    /// MCU patch / RAM-code firmware load hit `NotImplemented`. The
    /// firmware-loader path needs the blob to be registered via the
    /// initramfs scan path; absent that, probe still records the
    /// device as bound.
    NotImplemented,
}

/// Single-instance live device. Probe drops a new entry into this
/// slot. The kernel-test smokes reset it via `__reset_for_test`.
static CONTROLLER: IrqSafeSpinLock<Option<Mt7921Device>> = IrqSafeSpinLock::new(None);
static FIRMWARE_BINDING: IrqSafeSpinLock<Option<(BusDevice, Cap<BusDeviceCap, Write>)>> =
    IrqSafeSpinLock::new(None);
static TRANSPORT_CLAIMED: AtomicBool = AtomicBool::new(false);
/// Binding generation (Linux: one `mt792x_dev` per `pci_dev` probe). Every
/// probe and removal advances it; a transport carries the generation it was
/// claimed under, and a stale one can never be republished as the owner.
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// Generation whose transport still holds `TRANSPORT_CLAIMED`.
static CLAIM_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Current binding generation; odd while a function is bound.
pub(super) fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// A retired transport of `generation` returns its claim. A claim already
/// held by a newer generation is untouched.
pub(super) fn release_transport_claim(generation: u64) {
    let _controller = CONTROLLER.lock();
    if CLAIM_GENERATION.load(Ordering::Acquire) == generation {
        TRANSPORT_CLAIMED.store(false, Ordering::Release);
    }
}

/// Register the PCI match table. One entry per supported device id —
/// names must be unique (the bus match registry is keyed by `name`)
/// so we use the `mt7921-<did>` shape. Sync with `name_for`.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MTK_VENDOR,
                device: did,
            },
            probe,
        });
        narf_bus::register_pci_remove(name_for(did), remove);
    }
    // Also register the ITTIM-vendor MT7922 SKU. Linux's table
    // includes `{ PCI_DEVICE(PCI_VENDOR_ID_ITTIM, 0x7922), ... }` at
    // line 21 of `mt7921_pci_device_table`.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "mt7921-ittim-7922",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ITTIM_VENDOR,
            device: MTK_DEV_MT7922,
        },
        probe,
    });
    narf_bus::register_pci_remove("mt7921-ittim-7922", remove);
}

/// Bus detach hook (Linux `mt7921_pci_remove` → `mt7921e_unregister_device`):
/// withdraw the interface, stop and retire the retained transport (or keep
/// its uncertain DMA forever), end the binding generation and stop PCI
/// decoding. Synchronous and never awaits: the caller context is unknown.
fn remove(device: BusDevice, cap: Cap<BusDeviceCap, Write>) {
    let bound = FIRMWARE_BINDING
        .lock()
        .as_ref()
        .is_some_and(|(bound, _)| bound.addr == device.addr);
    if !bound {
        return;
    }
    // Close discovery first: no claim or probe of this generation may race
    // the teardown, and every stale owner now fails its generation check.
    let retired_generation = {
        let mut controller = CONTROLLER.lock();
        *FIRMWARE_BINDING.lock() = None;
        *controller = None;
        GENERATION.fetch_add(1, Ordering::AcqRel)
    };
    crate::iface::remove_scan_iface();
    let retired = super::firmware_transport::retire_for_removal(retired_generation);
    let _ = invoke(&cap, || {
        use narf_bus::pci::cmd;
        // Bus mastering always stops; memory decoding only after the
        // transport proved its DMA retired (or never existed).
        let bits = if retired {
            cmd::BUS_MASTER | cmd::MEM_SPACE
        } else {
            cmd::BUS_MASTER
        };
        narf_bus::pci::clear_command(&cap, &device, bits)
    });
    if retired {
        release_transport_claim(retired_generation);
    }
    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: removed {:04x}:{:04x} (generation {retired_generation}, transport {})",
        device.id.vendor,
        device.id.device,
        if retired { "retired" } else { "retained" },
    );
}

/// PCI probe entry. Called by the bus dispatch layer when one of our
/// registered (vendor, device) pairs is enumerated.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    cap.check_live()
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    if FIRMWARE_BINDING
        .lock()
        .as_ref()
        .is_some_and(|(bound, authority)| {
            bound.addr == device.addr && authority.check_live().is_ok()
        })
    {
        // Rediscovery must not park a function whose retained owner is active.
        return Ok(());
    }
    // No BAR sizing with decode enabled, and no probe-time access outside
    // current invocation. Skipped singleton functions remain parked.
    let result = invoke(&cap, || {
        use narf_bus::pci::{self, cmd};
        pci::clear_command(&cap, &device, cmd::BUS_MASTER | cmd::MEM_SPACE)
            .map_err(|_| ProbeError::Authority)?;
        pci::set_command(&cap, &device, cmd::INTX_DISABLE).map_err(|_| ProbeError::Authority)?;
        if pci::read_command(&cap, &device).map_err(|_| ProbeError::Authority)?
            & (cmd::BUS_MASTER | cmd::MEM_SPACE | cmd::INTX_DISABLE)
            != cmd::INTX_DISABLE
        {
            return Err(ProbeError::Authority);
        }
        if CONTROLLER.lock().is_some() {
            return Ok(None);
        }
        // SAFETY: exact exclusive PCI invocation; inherited DMA/decode parked.
        unsafe { bring_up(&device, &cap) }.map(Some)
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let result = match result {
        Ok(Some(device)) => Ok(device),
        Ok(None) => return Ok(()),
        Err(error) => Err(error),
    };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            // No controller was published, so no later lifecycle path will
            // revoke the command bits. Leave the rejected function inert:
            // bus mastering must remain off, and a failed probe does not need
            // memory decoding left enabled either.
            let _ = invoke(&cap, || {
                narf_bus::pci::clear_command(
                    &cap,
                    &device,
                    narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
                )
            });
            let _ = writeln!(
                narf_console::Writer,
                "  mt7921: bring-up failed ({:04x}:{:04x}): {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: probed {} ({:04x}:{:04x}) chip={:04x} rev={:#04x} owned={} mac={:02x?}",
        name_for(dev.effective_did),
        device.id.vendor,
        device.id.device,
        (dev.chip_id & 0xffff) as u16,
        dev.chip_rev,
        dev.driver_owned,
        dev.mac,
    );

    let did = dev.effective_did;
    {
        let mut controller = CONTROLLER.lock();
        *FIRMWARE_BINDING.lock() = Some((device, cap));
        *controller = Some(dev);
        GENERATION.fetch_add(1, Ordering::AcqRel);
    }
    // A reprobe after the boot-time firmware initcall starts provisioning
    // itself (Linux queues mt7921_init_work from every probe).
    super::firmware_transport::provision_after_reprobe();

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Hardware discovery is not radio readiness. Firmware/EFUSE and DMA
    // transport are not live yet; do not publish a zero-MAC netdev/wiphy.
    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: discovery complete; firmware startup deferred until firmware scan"
    );
    Ok(())
}

/// Stage-0 + Stage-1: BAR0 map, chip-ID read, driver-own latch,
/// firmware-load stub, EFUSE read.
///
/// # Safety
/// Caller owns the device's BARs exclusively for the duration of the
/// call.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Mt7921Device, ProbeError> {
    invoke(cap, || bring_up_current(device, cap)).map_err(|_| ProbeError::Authority)?
}

fn bring_up_current(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Mt7921Device, ProbeError> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    let parked = narf_bus::pci::read_command(cap, device).map_err(|_| ProbeError::Authority)?;
    if parked == u16::MAX || parked & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != INTX_DISABLE {
        return Err(ProbeError::Authority);
    }
    // ── Stage 0: BAR0 mapping ───────────────────────────────────
    //
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar_control(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    validate_probe_window(mmio_bar0.len)?;
    use narf_bus::pci::{self, cmd};
    pci::set_command(cap, device, cmd::MEM_SPACE).map_err(|_| ProbeError::Authority)?;
    let command = pci::read_command(cap, device).map_err(|_| ProbeError::Authority)?;
    if command == u16::MAX
        || command & (cmd::BUS_MASTER | cmd::MEM_SPACE | cmd::INTX_DISABLE)
            != cmd::MEM_SPACE | cmd::INTX_DISABLE
    {
        return Err(ProbeError::Authority);
    }

    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: BAR0 mapped ({} bytes); reading identity",
        mmio_bar0.len
    );
    // SAFETY: caller owns BAR0/latch; checked access validates every word.
    let chip_id = unsafe { chip_id_read(&mmio_bar0)? };
    // SAFETY: same ownership and checked transaction.
    let hw_rev = unsafe { hw_rev_read(&mmio_bar0)? };
    // SAFETY: same ownership and checked transaction.
    let bound = unsafe { hw_bound_read(&mmio_bar0)? };
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
        narf_console::Writer,
        "  mt7921: chip={raw_chip:04x} rev={hw_rev:#x}; taking driver ownership"
    );

    // ── Stage 1: driver-own + firmware-load stub + EFUSE ─────────
    //
    // SAFETY: BAR0 mapped + owned.
    let driver_owned = match unsafe { mac::take_driver_own(&mmio_bar0) } {
        Ok(()) => true,
        Err(mac::PowerError::Timeout) => return Err(ProbeError::DriverOwnTimeout),
        Err(mac::PowerError::DeviceGone) => return Err(ProbeError::DeviceGone),
        Err(mac::PowerError::InvalidWindow) => return Err(ProbeError::UnsupportedRegisterWindow),
    };

    // Firmware payloads are not registered until Late init. The retained
    // MCU/DMA owner is prepared there, outside this controller spinlock.
    let mac_bytes = [0u8; MAC_ADDR_LEN];

    Ok(Mt7921Device {
        mmio_bar0,
        effective_did,
        chip_id,
        chip_rev: (hw_rev & 0xff) as u8,
        driver_owned,
        mac: mac_bytes,
    })
}

/// Validate all identity/power accesses, including the indirect selector.
pub(super) fn validate_probe_window(len: u64) -> Result<(), ProbeError> {
    for addr in [
        MT_PCIE_MAC_INT_ENABLE,
        MT_HW_CHIPID,
        MT_HW_REV,
        MT_HW_BOUND,
        MT_CONN_ON_LPCTL,
    ] {
        super::registers::plan(addr, len).map_err(|_| ProbeError::UnsupportedRegisterWindow)?;
    }
    Ok(())
}

/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
unsafe fn chip_id_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_CHIPID) }.map_err(register_error)
}
/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
unsafe fn hw_rev_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_REV) }.map_err(register_error)
}
/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
unsafe fn hw_bound_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_BOUND) }.map_err(register_error)
}

fn register_error(error: super::registers::Error) -> ProbeError {
    match error {
        super::registers::Error::DeviceGone => ProbeError::DeviceGone,
        super::registers::Error::RemapRejected => ProbeError::RemapRejected,
        _ => ProbeError::UnsupportedRegisterWindow,
    }
}

/// Return the checked PCI register offset, or `u32::MAX` if unsupported.
/// An indirect offset alone is not sufficient for I/O: use the checked
/// register transaction, which programs and flushes the L1 selector first.
pub fn l1_remap(abs: u32) -> u32 {
    super::registers::plan(abs, 0x100000).map_or(u32::MAX, |plan| plan.offset)
}

/// SendFn registered with `narf_net::iface` at probe. Stage-2 lights
/// up real TX once the DMA ring path lands; until then we return Err
/// so the kernel-side TCP stack surfaces the unimplemented-ness
/// without crashing.
pub fn send_frame_unimpl(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        MTK_DEV_MT7961 => "mt7921-7961",
        MTK_DEV_MT7922 => "mt7921-7922",
        MTK_DEV_MT7921 => "mt7921-0608",
        // 0616 is a PCI alias for MT7922, not an MT7921 variant. Keep the
        // bound-driver/log label aligned with the firmware and raw chip ID.
        MTK_DEV_MT7921_ALT => "mt7922-0616",
        MTK_DEV_MT7920 => "mt7921-7920",
        _ => "mt7921",
    }
}

/// Resolve the firmware-blob names this chip wants. Returns
/// `(patch_name, ram_code_name)`. Used by the firmware-load stub.
pub fn firmware_blobs_for(did: u16) -> (&'static str, &'static str) {
    match did {
        MTK_DEV_MT7922 | MTK_DEV_MT7921_ALT => (MT7922_ROM_PATCH, MT7922_FIRMWARE_WM),
        MTK_DEV_MT7920 => (MT7920_ROM_PATCH, MT7920_FIRMWARE_WM),
        // MT7921 + MT7961 share the 7961 patch and RAM code.
        _ => (MT7961_ROM_PATCH, MT7961_FIRMWARE_WM),
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow discovery state before the exclusive firmware transport handoff.
/// Returns `None` if probe hasn't run or the transport owns the device.
pub fn with_controller<R>(f: impl FnOnce(&Mt7921Device) -> R) -> Option<R> {
    let controller = CONTROLLER.lock();
    if TRANSPORT_CLAIMED.load(Ordering::Acquire) {
        return None;
    }
    controller.as_ref().map(f)
}

pub(super) fn claim_firmware_transport(
) -> Result<Option<super::firmware_transport::Transport>, super::firmware_transport::Error> {
    use super::firmware_transport::{Error, Firmware, Transport};
    let Some((device, authority)) = *FIRMWARE_BINDING.lock() else {
        return Ok(None);
    };
    if TRANSPORT_CLAIMED.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    let (mmio, did, generation) = {
        let guard = CONTROLLER.lock();
        let controller = guard.as_ref().ok_or(Error::Busy)?;
        (
            controller.mmio_bar0,
            controller.effective_did,
            self::generation(),
        )
    };
    let registry = narf_firmware::trusted_loader_authority()
        .ok_or(Error::Authority)?
        .derive()
        .map_err(|_| Error::Authority)?;
    let firmware = Firmware::open(did, &registry)?;
    {
        // Match with_controller's lock so a reader which observed an earlier
        // unclaimed value cannot enter after the runtime handoff.
        let controller = CONTROLLER.lock();
        // The binding may have been removed (and reprobed) since the
        // snapshot: never claim a transport for a retired generation.
        if controller.is_none() || self::generation() != generation {
            return Err(Error::DeviceGone);
        }
        TRANSPORT_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Busy)?;
        CLAIM_GENERATION.store(generation, Ordering::Release);
    }
    // SAFETY: the boot provisioning mutex and owner/work locks serialize this
    // handoff with later provisioning callers. Discovery has parked BME; no
    // transport has been claimed and no MT76 rings have been published.
    let transport = unsafe { Transport::new(mmio, device, authority, firmware, generation) };
    if transport.is_err() {
        // Construction only validates/read-checks and allocates unpublished
        // rings. No hardware references exist, so discovery may be retried.
        release_transport_claim(generation);
    }
    transport.map(Some)
}

/// Test-only reset of the bound slot. Available in the built-in build (which
/// carries the co-located smokes); dropped from the `.ko` build.
#[cfg(any(test, feature = "builtin"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
    {
        *FIRMWARE_BINDING.lock() = None;
    }
    TRANSPORT_CLAIMED.store(false, Ordering::Release);
    CLAIM_GENERATION.store(0, Ordering::Release);
}

/// Test-only swap of the claim/generation state; returns the previous
/// `(claimed, claim_generation, generation)` so a smoke can restore it.
#[cfg(any(test, feature = "builtin"))]
pub(super) fn __swap_claim_for_test(state: (bool, u64, u64)) -> (bool, u64, u64) {
    let _controller = CONTROLLER.lock();
    (
        TRANSPORT_CLAIMED.swap(state.0, Ordering::AcqRel),
        CLAIM_GENERATION.swap(state.1, Ordering::AcqRel),
        GENERATION.swap(state.2, Ordering::AcqRel),
    )
}

#[cfg(any(test, feature = "builtin"))]
pub(super) fn __claimed_for_test() -> bool {
    TRANSPORT_CLAIMED.load(Ordering::Acquire)
}
