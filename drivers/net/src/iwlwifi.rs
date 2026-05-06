//! Intel iwlwifi — Wi-Fi 6 / 6E PCIe host-controller driver.
//!
//! Spec: `drivers/net/specification/iwlwifi.md`.
//!
//! Clean-room: PCI vendor/device pairs sourced from the public
//! Intel "Wi-Fi 6 (Gig+) / Wi-Fi 6E AX210 product brief" PDFs. No
//! GPL Linux `drivers/net/wireless/intel/iwlwifi/` source consulted.
//!
//! ## Stage 1 scope
//!
//! Structural-only: PCI match table for the four supported parts.
//! No BAR access, no register decode, no firmware load. The Intel
//! product briefs publish PCI IDs + PCIe capability shape, but the
//! operational register map (CSR/PRPH offsets, command queue layout,
//! TFD descriptors) is not in any public document — that surface
//! lives only inside the GPL Linux driver. We stop here. See the
//! spec doc for the full wall.

#![allow(dead_code)]

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

mod tests;

// ── PCI device IDs ─────────────────────────────────────────────────
//
// Vendor: Intel Corporation (`0x8086`). Device IDs per the public
// Intel product briefs / ARK SKU pages:
//
//   AX200 — Wi-Fi 6 (Gig+) — `0x2723`
//   AX201 — Wi-Fi 6 (Gig+) CRF/CNVio — `0x02F0`
//   AX210 — Wi-Fi 6E       — `0x2725`
//   AX211 — Wi-Fi 6E       CRF/CNVio — `0x51F0`

pub const IWL_VENDOR: u16 = 0x8086;

pub const IWL_DEV_AX200: u16 = 0x2723;
pub const IWL_DEV_AX201: u16 = 0x02F0;
pub const IWL_DEV_AX210: u16 = 0x2725;
pub const IWL_DEV_AX211: u16 = 0x51F0;

const ALL_DEV_IDS: &[u16] = &[IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210, IWL_DEV_AX211];

// ── Probe ──────────────────────────────────────────────────────────

/// Stage 1 probe stub. Records the device in `narf-drivers` so the
/// boot inventory shows the part was seen, but does not touch BAR0
/// or attempt firmware load — the operational register map is not
/// publicly documented (see `iwlwifi.md`). Future stages need either
/// firmware blobs we don't ship or a clean-room derivation we cannot
/// do without public docs.
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
    // TODO(iwlwifi-public-docs): BAR0 map + CSR reset + firmware
    // image load are blocked on register-map docs that Intel does
    // not publish. Stage progression resumes when public docs (or a
    // clean-room derivation) are available.
    Ok(())
}

/// Register the driver against every documented AX2xx device id.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IWL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        IWL_DEV_AX200 => "iwlwifi-ax200",
        IWL_DEV_AX201 => "iwlwifi-ax201",
        IWL_DEV_AX210 => "iwlwifi-ax210",
        IWL_DEV_AX211 => "iwlwifi-ax211",
        _ => "iwlwifi",
    }
}
