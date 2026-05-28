//! RTW88 PCI probe.
//!
//! Driver-match registration + BAR0 / BAR2 mapping. Mirrors the layout
//! Linux uses in `drivers/net/wireless/realtek/rtw88/pci.c`
//! (`rtw_pci_probe`, ~L1620..L1750 in v6.6): the chip exposes
//!   - BAR0 (32-bit, 64 KiB) — register window,
//!   - BAR2 (32-bit, 16 KiB) — secondary data window for the
//!     8822C-class parts (used for TX/RX bookkeeping; baseline maps
//!     it so the follow-up commit doesn't have to re-probe).
//!
//! What this file does *not* do, intentionally:
//!   - MSI/MSI-X vector setup. The baseline is "chip detected + MAC
//!     readable"; IRQ delivery lands with the TX/RX ring follow-up.
//!   - Firmware load. Deferred — there's no `narf-firmware` blob
//!     registered for RTW88 yet.

#![allow(dead_code)]

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::efuse;
use super::power;
use super::regs::*;

/// One bound RTW88 device. Holds the BAR0/BAR2 mappings + the EFUSE-
/// derived MAC. Single-instance for the baseline (every laptop ships
/// at most one of these); multi-radio comes with the follow-up.
pub struct Rtw88Device {
    pub mmio_bar0: MmioRegion,
    pub mmio_bar2: Option<MmioRegion>,
    pub mac: [u8; MAC_ADDR_LEN],
    /// PCI device id we matched on — controls per-chip quirks in
    /// follow-up commits. Today it just feeds `name_for`.
    pub device_id: u16,
}

impl core::fmt::Debug for Rtw88Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Device")
            .field("mac", &self.mac)
            .field("device_id", &self.device_id)
            .field("bar2_present", &self.mmio_bar2.is_some())
            .finish_non_exhaustive()
    }
}

/// Errors raised by the baseline probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed. Most likely the BAR isn't
    /// implemented at all (wrong device) or the cap-list claim raced
    /// another driver.
    Bar0MapFailed,
    /// Power-on / chip-reset prologue failed. See [`power::PowerError`].
    PowerOn(power::PowerError),
    /// EFUSE read failed. See [`efuse::EfuseError`].
    Efuse(efuse::EfuseError),
}

/// Single-instance live device. The baseline only supports one bound
/// RTW88; the follow-up will switch to a `Vec` keyed by domain id.
static CONTROLLER: IrqSafeSpinLock<Option<Rtw88Device>> = IrqSafeSpinLock::new(None);

/// PCI driver match registration. One entry per supported device id —
/// mirrors the `rtw88/pci.c::rtw_pci_id_table` shape.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: REALTEK_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Probe entry called by `narf-bus::driver_match` when a Realtek
/// vendor/device pair we registered for surfaces.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Skip if a device is already bound. Real laptops only ship one
    // RTW88; a second probe is a re-enumeration race.
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    // Enable MEM_SPACE + BUS_MASTER so BAR reads land + the device
    // can DMA later. Match the `e1000` shape so the test harness's
    // mocked-cfg writes go through the same path.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller (the bus dispatch layer) hands us exclusive
    // BusDeviceCap authority for this device's cfg + BARs.
    let result = unsafe { bring_up(&device) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let mac = dev.mac;
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Register the iface with `narf-net` so the kernel-side TCP
    // stack sees the MAC. send_frame returns Err for now — this
    // commit only delivers "chip detected + MAC readable."
    narf_net::iface::register("wlan0", mac, send_frame_unimpl);
    Ok(())
}

/// Bring the chip up: map BAR0, run baseline power-on, map BAR2, read
/// MAC from EFUSE. Pure-IO; no TX/RX ring setup.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice) -> Result<Rtw88Device, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // Power-on prologue. Some parts (notably 8821CE on certain BIOSes)
    // arrive in a fully-powered state and the prologue is a no-op;
    // others arrive in D3cold and need the PWR-state walk. Baseline
    // does the minimum cross-part prologue — full per-chip table
    // lands in the follow-up.
    // SAFETY: BAR0 mapped + owned.
    unsafe {
        power::baseline_power_on(&mmio_bar0).map_err(ProbeError::PowerOn)?;
    }

    // Map BAR2 *after* power-on. The 8821C / 8822B / 8822C parts
    // gate BAR2 visibility on the SYS clock being live (which the
    // prologue ensures). Failure here is non-fatal — the baseline
    // doesn't actually touch BAR2 yet.
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar2 = unsafe { map_bar(device, 2) }.ok();

    // Read MAC from logical EFUSE offset 0.
    // SAFETY: BAR0 mapped, power-on done.
    let mac = unsafe { efuse::read_mac(&mmio_bar0) }.map_err(ProbeError::Efuse)?;

    // ── Stage 2: Firmware load ──
    let auth = match narf_firmware::trusted_loader_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        match unsafe {
            super::fw::download_firmware(&mmio_bar0, mmio_bar2.as_ref(), device.id.device, &auth)
        } {
            Ok(()) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "  rtw88: firmware loaded successfully");
            }
            Err(e) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "  rtw88: firmware load failed: {:?}", e);
            }
        }
    }

    Ok(Rtw88Device {
        mmio_bar0,
        mmio_bar2,
        mac,
        device_id: device.id.device,
    })
}

/// SendFn registered with `narf_net::iface` at probe time. The
/// baseline only delivers "chip detected + MAC readable" — there's
/// no TX ring yet. Returning Err lets the kernel-side TCP stack
/// surface the unimplemented-ness without crashing.
pub fn send_frame_unimpl(_frame: &[u8]) -> Result<(), ()> {
    Err(())
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8821CE => "rtw88-8821ce",
        RTL_DEV_8822CE => "rtw88-8822ce",
        RTL_DEV_8822BE => "rtw88-8822be",
        _ => "rtw88",
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Rtw88Device) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
