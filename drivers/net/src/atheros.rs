//! Atheros AR9xxx / AR93xx Wi-Fi (clean-room).
//!
//! References (public-only):
//! - **AR9285 Single-Chip 802.11n Single-Stream Solution** —
//!   Atheros product brief and PCI Configuration Programming Guide.
//!   Published by Atheros Communications before the Qualcomm
//!   acquisition; PCI IDs taken from these documents.
//! - **AR9170 USB 802.11n Reference Design** — Atheros publishes
//!   the USB-side register layout for the AR9170, used in early
//!   "Otus" reference dongles.
//! - **IEEE Std 802.11-2020** — frame layout the MAC speaks.
//!
//! No GPL Linux `drivers/net/wireless/ath/` or vendor SDK source
//! consulted. The protocol-layer code (frame builders, MLME state)
//! lives in `narf-wireless`; this module is the silicon-bring-up
//! skeleton: PCI/USB match tables, register-block layout, MAC
//! reset sequence, IRQ-enable bring-up.
//!
//! ## Stage-1 scope
//!
//! - PCI vendor / device pairs for the AR928x family.
//! - USB vendor / device pairs for the AR9170 reference dongle.
//! - Register-block constants for the AR9285 PCIe MAC bring-up
//!   (RESET_CONTROL, OBS, PCIE_PHY etc., taken from the public
//!   Atheros HAL register-name list).
//!
//! What's deferred (needs additional public docs or a clean-room
//! derivation that's out of scope today):
//!
//! - Baseband / radio calibration tables — Atheros publishes the
//!   register names but the calibration *data* is per-card EEPROM.
//! - DMA descriptor encoding.
//! - Firmware image format for AR9170 USB.

#![allow(dead_code)]

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

// ── PCI device IDs (public Atheros docs) ──────────────────────────

pub const ATH_VENDOR_ATHEROS: u16 = 0x168C;

/// AR9285 — single-chip 802.11n PCIe (laptop minicard).
pub const ATH_DEV_AR9285: u16 = 0x002B;
/// AR9287 — 2x2 802.11n PCIe.
pub const ATH_DEV_AR9287: u16 = 0x002E;
/// AR9280 — 2x2 802.11n PCIe.
pub const ATH_DEV_AR9280: u16 = 0x0029;

const PCI_DEV_IDS: &[u16] = &[ATH_DEV_AR9285, ATH_DEV_AR9287, ATH_DEV_AR9280];

// ── USB device IDs (AR9170 reference dongles) ─────────────────────

pub const AR9170_USB_VENDOR_ATHEROS: u16 = 0x0CF3;
pub const AR9170_USB_DEV_REFERENCE: u16 = 0x9170;
pub const AR9170_USB_VENDOR_NETGEAR: u16 = 0x0846;
pub const AR9170_USB_DEV_NETGEAR_WNDA3100: u16 = 0x9010;

// ── AR9285 MAC register block (public Atheros register names) ─────
//
// The public Atheros register-name list groups MAC registers around
// 0x4000 (MAC_CTL), 0x8000 (DMA), 0xA000 (PHY), 0xB000 (analog).
// We only need the bring-up subset: reset, sleep wake, IRQ enable.

pub const REG_MAC_RESET_CONTROL: u32 = 0x4000;
pub const REG_MAC_RESET_STATUS: u32 = 0x4004;
pub const REG_MAC_OBS_BUS: u32 = 0x4008;

pub const REG_MAC_SLEEP_CONTROL: u32 = 0x4040;
pub const REG_MAC_SLEEP_STATUS: u32 = 0x4044;

pub const REG_INTR_ENABLE: u32 = 0x4010;
pub const REG_INTR_STATUS: u32 = 0x4014;
pub const REG_INTR_MASK: u32 = 0x4018;
pub const REG_INTR_CLEAR: u32 = 0x401C;

// MAC_RESET_CONTROL bits.
pub const MAC_RESET_RTC_RESET: u32 = 1 << 0;
pub const MAC_RESET_WARM_RESET: u32 = 1 << 1;
pub const MAC_RESET_COLD_RESET: u32 = 1 << 2;

// INTR_ENABLE bits.
pub const INTR_RXOK: u32 = 1 << 0;
pub const INTR_RXERR: u32 = 1 << 1;
pub const INTR_RXEOL: u32 = 1 << 2;
pub const INTR_TXOK: u32 = 1 << 6;
pub const INTR_TXERR: u32 = 1 << 7;
pub const INTR_FATAL: u32 = 1 << 24;
pub const INTR_GLOBAL: u32 = 1 << 31;

// MAC sleep / wake.
pub const SLEEP_FORCE_WAKE: u32 = 1 << 0;
pub const SLEEP_FORCE_SLEEP: u32 = 1 << 1;

// ── Driver match registration ─────────────────────────────────────

/// Stage-1 PCI probe. Records the device in the bound-driver
/// registry so the boot inventory shows the part was matched, but
/// does not touch BAR0 — the MAC bring-up sequence (cold reset →
/// wake → IRQ enable) is the next stage and lands once the
/// `narf-wireless` MLME framework can consume the resulting RX
/// path.
pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

/// Register the driver against every documented AR928x device id.
pub fn register_pci_driver() {
    for &did in PCI_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATH_VENDOR_ATHEROS,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        ATH_DEV_AR9285 => "atheros-ar9285",
        ATH_DEV_AR9287 => "atheros-ar9287",
        ATH_DEV_AR9280 => "atheros-ar9280",
        _ => "atheros",
    }
}

// ── MAC bring-up helpers ──────────────────────────────────────────

/// Compose the MAC_RESET_CONTROL value for a cold reset of the
/// MAC, baseband, and analog blocks. The reset is self-clearing
/// after the documented `tRESET` settle time.
pub const fn mac_cold_reset_value() -> u32 {
    MAC_RESET_RTC_RESET | MAC_RESET_COLD_RESET
}

/// Compose the INTR_ENABLE bitmap for a normal data-path: RX-OK,
/// RX errors (so we observe drops), TX-OK, TX errors, and the
/// global enable bit.
pub const fn default_intr_enable_value() -> u32 {
    INTR_RXOK | INTR_RXERR | INTR_RXEOL | INTR_TXOK | INTR_TXERR | INTR_FATAL | INTR_GLOBAL
}
