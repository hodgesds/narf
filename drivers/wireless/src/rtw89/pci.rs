//! RTW89 PCI probe.
//!
//! Driver-match registration + **BAR2** mapping. Notable difference
//! from the sibling rtw88: the AX-generation 8852/8851/8922 parts
//! expose only BAR2 as a single 64 KiB window — the register block
//! Linux walks during init lives entirely inside BAR2, not BAR0.
//!
//! Linux's `rtw89/pci.c::rtw89_pci_claim_device` (~L3340..L3420) hard-
//! codes `u8 bar_id = 2;` before the `pci_iomap` call. We mirror that
//! exactly.
//!
//! ## What this file does *not* do at Stage 0/1 (deferred)
//!
//! - MSI/MSI-X vector setup. Lands with Stage-2 TX/RX rings.
//! - Firmware load. Stubbed in `fw.rs`; needs `narf-firmware` blobs
//!   for `rtw89/8852a_*.bin` / `rtw89/8852b_*.bin` etc.
//! - PHY parameter table load. Stubbed in `phy.rs`.
//! - DMA channel ring setup. The Linux code in `pci.c` allocates 13
//!   TX + 2 RX rings; that's a non-trivial pile (~600 LOC of ring
//!   bookkeeping) that lands with Stage 2.

#![allow(dead_code)]

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::efuse;
use super::mac::{self, ChipId};
use super::*;

/// One bound RTW89 device. Holds the BAR2 mapping + the EFUSE-derived
/// MAC. Single-instance for the baseline (every laptop ships at most
/// one of these); multi-radio comes with the follow-up.
pub struct Rtw89Device {
    /// BAR2 MMIO mapping — the only BAR rtw89 silicon exposes.
    pub mmio_bar2: MmioRegion,
    /// Factory MAC read from logical EFUSE offset 0.
    pub mac: [u8; efuse::MAC_ADDR_LEN],
    /// PCI device id we matched on.
    pub device_id: u16,
    /// Chip family decoded from the PCI device id. `None` for ids we
    /// match on but don't yet branch on per-chip.
    pub chip_id: Option<ChipId>,
    /// Chip-version field from `R_AX_SYS_CFG1`. Stored so a follow-up
    /// per-chip PWR-seq table can dispatch on cut.
    pub chip_version: u8,
}

impl core::fmt::Debug for Rtw89Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89Device")
            .field("mac", &self.mac)
            .field("device_id", &self.device_id)
            .field("chip_id", &self.chip_id)
            .field("chip_version", &self.chip_version)
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage-0/1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 2)` failed. Most likely the BAR isn't
    /// implemented at all (wrong device) or the cap-list claim raced
    /// another driver.
    Bar2MapFailed,
    /// Power-on prologue failed. See [`mac::MacError`].
    PowerOn(mac::MacError),
    /// EFUSE read failed. See [`efuse::EfuseError`].
    Efuse(efuse::EfuseError),
}

/// Single-instance live device. The baseline only supports one bound
/// RTW89; the follow-up will switch to a `Vec` keyed by domain id.
static CONTROLLER: IrqSafeSpinLock<Option<Rtw89Device>> = IrqSafeSpinLock::new(None);

/// PCI driver match registration. One entry per supported device id —
/// mirrors the per-chip-file `rtw89_pci_id_table` shape Linux uses
/// (e.g. `rtw8852be.c::rtw89_8852be_id_table`).
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
    // RTW89 radio; a second probe is a re-enumeration race.
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    // Enable MEM_SPACE + BUS_MASTER so BAR2 reads land + the device
    // can DMA later. Match the `rtw88` shape.
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

    // Register the iface with `narf-net` so the kernel-side TCP stack
    // sees the MAC. send_frame returns Err for now — Stage 0/1 only
    // delivers "chip detected + MAC readable."
    narf_net::iface::register("wlan0", mac, send_frame_unimpl);
    Ok(())
}

/// Bring the chip up: map BAR2, run baseline power-on, detect chip
/// version, read MAC from EFUSE. Pure-IO; no TX/RX ring setup.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice) -> Result<Rtw89Device, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity. rtw89 maps BAR2 only;
    // Linux `pci.c:rtw89_pci_claim_device` sets `bar_id = 2` before
    // its single `pci_iomap` call.
    let mmio_bar2 = unsafe { map_bar(device, 2) }.map_err(|_| ProbeError::Bar2MapFailed)?;

    // SAFETY: BAR2 mapped + owned.
    unsafe {
        mac::baseline_power_on(&mmio_bar2).map_err(ProbeError::PowerOn)?;
    }

    // Chip-version detection. Linux reads R_AX_SYS_CFG1 immediately
    // after PWR-seq completes; the value flows into per-chip cut
    // dispatch in `rtw89_chip_setup`.
    // SAFETY: BAR2 mapped, power-on done.
    let chip_version = unsafe { mac::read_chip_version(&mmio_bar2) };

    // Read MAC from logical EFUSE offset 0.
    // SAFETY: same.
    let mac = unsafe { efuse::read_mac(&mmio_bar2) }.map_err(ProbeError::Efuse)?;

    // Firmware download path — stub at Stage 1. Linux runs
    // `rtw89_fw_download` here after the chip is up and EFUSE is
    // read; we keep the call so the Stage-2 wire-in is a one-line
    // replacement.
    // SAFETY: BAR2 mapped, power-on done — same invariants the
    // future real downloader will require.
    let _ = unsafe { super::fw::download_stub(&mmio_bar2) };

    // PHY parameter table — stub at Stage 1. Linux pulls these from
    // `rtw89/rtw8852a_phy_table.c` etc. once firmware is alive.
    // SAFETY: same.
    let _ = unsafe { super::phy::load_param_tables_stub(&mmio_bar2) };

    Ok(Rtw89Device {
        mmio_bar2,
        mac,
        device_id: device.id.device,
        chip_id: ChipId::from_pci_did(device.id.device),
        chip_version,
    })
}

/// SendFn registered with `narf_net::iface` at probe time. Stage 0/1
/// has no TX ring yet — returning Err lets the kernel-side TCP stack
/// surface the unimplemented-ness without crashing.
pub fn send_frame_unimpl(_frame: &[u8]) -> Result<(), ()> {
    Err(())
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
///
/// **Must be 1:1 per device id.** The bus's `register_pci_driver`
/// registry is keyed on `name` and a later entry with the same name
/// overwrites the earlier one — collapsing two device ids onto one
/// name silently drops the first from the match table. Variant
/// suffixes (`-vt`, `-alt`) keep the chip-family prefix readable
/// while preserving uniqueness.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8852AE => "rtw89-8852ae",
        RTL_DEV_8852AE_VT => "rtw89-8852ae-vt",
        RTL_DEV_8852BE => "rtw89-8852be",
        RTL_DEV_8852BE_ALT => "rtw89-8852be-alt",
        RTL_DEV_8852CE => "rtw89-8852ce",
        RTL_DEV_8851BE => "rtw89-8851be",
        RTL_DEV_8922AE => "rtw89-8922ae",
        RTL_DEV_8922AE_ALT => "rtw89-8922ae-alt",
        _ => "rtw89",
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Rtw89Device) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
