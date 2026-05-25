//! Intel iwlwifi — Wi-Fi 6 / 6E PCIe host-controller driver.
//!
//! Spec: `drivers/net/specification/iwlwifi.md`.
//!
//! ## Stage 1 (history)
//!
//! Structural-only — PCI match table. Couldn't progress past that
//! because the operational register map was only documented inside
//! the GPL Linux iwlwifi tree and NARF was MIT-licensed.
//!
//! ## Stage 2 (this stage)
//!
//! NARF relicensed to GPL-2.0-or-later on 2026-05-20, so direct
//! adaptation of upstream is allowed. This stage lands:
//!
//! - `csr` — CSR (control / status register) offset map adapted
//!   from Linux `iwl-csr.h`.
//! - `prph` — PRPH (peripheral) indirect-access wrapper for
//!   registers reached via the HBUS_TARG window. Adapted from
//!   `pcie/gen1_2/trans.c::iwl_trans_pcie_{read,write}_prph`.
//! - `apm` — the "wake up the NIC" preamble: SW reset → APM init →
//!   activate_nic poll → APMG clock enable. Adapted from
//!   `pcie/gen1_2/trans.c::iwl_pcie_apm_init`.
//! - `ucode` — TLV-format ucode header decoder. Adapted from
//!   `fw/file.h`.
//! - Probe — claims BAR0, maps MMIO, reads `CSR_HW_REV`, logs a
//!   detection line. Does NOT run APM init from probe yet (that's
//!   Stage 3 territory — actual firmware load).
//!
//! ## Stage 3 (planned)
//!
//! - Run `apm::sw_reset` + `apm::apm_init` from probe.
//! - Resolve the ucode blob via `narf-firmware` and DMA-upload the
//!   sections to device SRAM.
//! - Wait on the alive-notification handshake.
//!
//! ## Stage 4 (planned)
//!
//! - mac80211-equivalent integration: scan, associate, key install.
//!
//! ## Reference
//!
//! All upstream citations are GPL-2.0 OR BSD-3-Clause — pickable
//! freely now that NARF is GPL-2.0-or-later:
//! - `drivers/net/wireless/intel/iwlwifi/iwl-csr.h`
//! - `drivers/net/wireless/intel/iwlwifi/iwl-prph.h`
//! - `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c`
//! - `drivers/net/wireless/intel/iwlwifi/fw/file.h`

#![allow(dead_code)]

use core::fmt::Write as _;

use narf_bus::{map_bar, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

pub mod apm;
pub mod csr;
pub mod prph;
pub mod ucode;

mod tests;

// ── PCI device IDs ─────────────────────────────────────────────────
//
// Vendor: Intel Corporation (`0x8086`). Device IDs adapted from
// Linux `pcie/drv.c` (kernel ≥ 6.10). Aliased SKUs share a family.

pub const IWL_VENDOR: u16 = 0x8086;

/// AX200 — Cyclone Peak, Wi-Fi 6 Gig+, Family-1 firmware.
pub const IWL_DEV_AX200: u16 = 0x2723;

/// AX201 — Comet Lake / Tiger Lake CRF/CNVio, primary DID.
pub const IWL_DEV_AX201: u16 = 0x02F0;
/// AX201 — Killer Wi-Fi 6 AX1650i alias DID (same family).
pub const IWL_DEV_AX201_2: u16 = 0x4DF0;

/// AX210 — Typhoon Peak, Wi-Fi 6E, Family-2 firmware. Primary DID.
pub const IWL_DEV_AX210: u16 = 0x2725;
/// AX210 — SnowField alias DID (Family-2 firmware).
pub const IWL_DEV_AX210_2: u16 = 0x7AF0;

/// AX211 — long-latency-SO CRF, primary DID.
pub const IWL_DEV_AX211: u16 = 0x51F0;
/// AX211 — SO-LL with IMR.
pub const IWL_DEV_AX211_2: u16 = 0x51F1;
/// AX211 — Ma (Meteor Lake host).
pub const IWL_DEV_AX211_3: u16 = 0x7E40;

/// AX411 — long-latency-SO alias DID.
pub const IWL_DEV_AX411: u16 = 0x54F0;
/// Killer 1690 / AX411-family alias DID.
pub const IWL_DEV_KILLER_1690: u16 = 0x5417;

const ALL_DEV_IDS: &[u16] = &[
    IWL_DEV_AX200,
    IWL_DEV_AX201,
    IWL_DEV_AX201_2,
    IWL_DEV_AX210,
    IWL_DEV_AX210_2,
    IWL_DEV_AX211,
    IWL_DEV_AX211_2,
    IWL_DEV_AX211_3,
    IWL_DEV_AX411,
    IWL_DEV_KILLER_1690,
];

/// Family classification per device id — chooses the PRPH mask
/// width, ucode loader path, and whether APMG-clock-enable applies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceFamily {
    /// AX200 / AX201 / AX201_2. Family-1 firmware ("Qu"/"AX200"
    /// generation). PRPH window is 20 bits; APMG clock-enable is
    /// required by `apm_init`.
    Family1,
    /// AX210 / AX211 / AX411. Family-2 firmware ("Typhoon Peak").
    /// PRPH window is 24 bits; APMG is not present (skipped in APM
    /// init).
    Family2,
}

impl DeviceFamily {
    pub const fn for_device(did: u16) -> Self {
        match did {
            IWL_DEV_AX200 | IWL_DEV_AX201 | IWL_DEV_AX201_2 => Self::Family1,
            // Everything else from our table is Typhoon Peak (AX210/
            // AX211/AX411/Killer 1690). When a real BE-class part
            // shows up it'll need its own family variant.
            _ => Self::Family2,
        }
    }

    /// PRPH-address mask used by `prph::pack_addr` for this family.
    pub const fn prph_mask(self) -> prph::PrphMask {
        match self {
            Self::Family1 => prph::PrphMask::Mask20,
            Self::Family2 => prph::PrphMask::Mask24,
        }
    }

    /// Whether APMG (Active Power Management Gateway) is present on
    /// this family. AX210+ deliberately skips the APMG clock-enable
    /// step in `apm_init`.
    pub const fn apmg_supported(self) -> bool {
        matches!(self, Self::Family1)
    }
}

// ── Probe ──────────────────────────────────────────────────────────

/// Stage 2 probe: claim BAR0, map MMIO, read `CSR_HW_REV` to confirm
/// the device is live, log a detection line. APM init + firmware
/// load are Stage 3.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Enable Memory + Bus Master + INTx-disable per the PCI spec.
    // We need Memory enabled to read BAR0, Bus Master for any future
    // DMA, and INTx off because we'll use MSI-X (Stage 3+).
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let name = name_for(device.id.device);
    let family = DeviceFamily::for_device(device.id.device);

    // SAFETY: bus-registry handed us this device with exclusive
    // claim; map_bar consumes the BAR0 reservation accordingly.
    let mmio = unsafe { map_bar(&device, 0) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: BAR0 is mapped; offset is in-range (CSR_HW_REV at
    // 0x028 is well under any AX-class BAR0 size, which is 4–64
    // KiB depending on family).
    let hw_rev = unsafe { mmio.read32(csr::CSR_HW_REV as u64) };

    // If HW_REV reads as all-ones the device isn't really there —
    // typical signature for a phantom function or a missing card.
    // Don't fail probe; record + log + return so the bus layer
    // doesn't keep trying.
    if hw_rev == u32::MAX {
        let _ = writeln!(
            narf_console::Writer,
            "  iwlwifi: {} BAR0={:#018x} hw_rev=0xFFFFFFFF — not-present",
            name,
            mmio.phys.raw()
        );
        narf_drivers::record_bound(narf_drivers::BoundDriver {
            name: alloc::string::String::from(name),
            kind: narf_drivers::BoundKind::Net,
            pci_vid: Some(device.id.vendor),
            pci_did: Some(device.id.device),
            domain: narf_drivers::BoundKind::Net.default_domain(),
        });
        return Ok(());
    }

    let hw_type = csr::csr_hw_rev_type(hw_rev);
    let hw_step = csr::csr_hw_rev_step_dash(hw_rev);

    let _ = writeln!(
        narf_console::Writer,
        "  iwlwifi: detected {} rev={:#010x} (type={:#05x} step+dash={:#x}) family={:?} BAR0={:#018x}+{:#x}",
        name,
        hw_rev,
        hw_type,
        hw_step,
        family,
        mmio.phys.raw(),
        mmio.len,
    );

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Stage 3: from here we'd call `apm::sw_reset` → `apm::apm_init`
    // → load ucode → wait on alive notification. None of that fires
    // yet — the next stage commit lands that path.
    Ok(())
}

/// Register the driver against every documented AX-class device id.
/// Each `PciMatch` gets a DID-unique name so the registry's
/// name-keyed deduplication doesn't collapse aliased entries.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: match_name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IWL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Human-facing display name (what we log + record_bound with).
/// Several DIDs share a display name because they're the same
/// silicon under different OEM SKUs.
fn name_for(did: u16) -> &'static str {
    match did {
        IWL_DEV_AX200 => "iwlwifi-ax200",
        IWL_DEV_AX201 | IWL_DEV_AX201_2 => "iwlwifi-ax201",
        IWL_DEV_AX210 | IWL_DEV_AX210_2 => "iwlwifi-ax210",
        IWL_DEV_AX211 | IWL_DEV_AX211_2 | IWL_DEV_AX211_3 => "iwlwifi-ax211",
        IWL_DEV_AX411 => "iwlwifi-ax411",
        IWL_DEV_KILLER_1690 => "iwlwifi-killer1690",
        _ => "iwlwifi",
    }
}

/// Unique per-DID match name used at registration. The bus registry
/// is keyed by `PciMatch::name` and refuses duplicates (last-write-
/// wins) — using the display name alone would collapse aliased DIDs
/// down to one match entry.
fn match_name_for(did: u16) -> &'static str {
    match did {
        IWL_DEV_AX200 => "iwlwifi-2723",
        IWL_DEV_AX201 => "iwlwifi-02f0",
        IWL_DEV_AX201_2 => "iwlwifi-4df0",
        IWL_DEV_AX210 => "iwlwifi-2725",
        IWL_DEV_AX210_2 => "iwlwifi-7af0",
        IWL_DEV_AX211 => "iwlwifi-51f0",
        IWL_DEV_AX211_2 => "iwlwifi-51f1",
        IWL_DEV_AX211_3 => "iwlwifi-7e40",
        IWL_DEV_AX411 => "iwlwifi-54f0",
        IWL_DEV_KILLER_1690 => "iwlwifi-5417",
        _ => "iwlwifi-unknown",
    }
}
