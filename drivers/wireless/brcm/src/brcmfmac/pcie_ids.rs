//! Broadcom FullMAC PCIe identification: the device-id table, per-id names
//! and firmware filenames. Shared by the built-in binding (`pcie.rs`) and
//! the module binding (`pcie_kabi.rs`).
//! Reference: Linux `include/brcm_hw_ids.h` and `brcmfmac/pcie.c`.

// ── Hardware identification ────────────────────────────────────────
//
// Per Linux `include/brcm_hw_ids.h`. All entries on the PCIe bus share
// the Broadcom vendor id `0x14E4` (`PCI_VENDOR_ID_BROADCOM`).

/// Broadcom Inc. PCI vendor id.
pub const BROADCOM_VENDOR: u16 = 0x14E4;

// Per Linux `include/brcm_hw_ids.h` (lines ~75..101) — copied verbatim.
pub const BRCM_PCIE_4350_DEVICE_ID: u16 = 0x43A3;
pub const BRCM_PCIE_4354_DEVICE_ID: u16 = 0x43DF;
pub const BRCM_PCIE_4354_RAW_DEVICE_ID: u16 = 0x4354;
pub const BRCM_PCIE_4355_DEVICE_ID: u16 = 0x43DC;
pub const BRCM_PCIE_4356_DEVICE_ID: u16 = 0x43EC;
pub const BRCM_PCIE_43567_DEVICE_ID: u16 = 0x43D3;
pub const BRCM_PCIE_43570_DEVICE_ID: u16 = 0x43D9;
pub const BRCM_PCIE_43570_RAW_DEVICE_ID: u16 = 0xAA31;
pub const BRCM_PCIE_4358_DEVICE_ID: u16 = 0x43E9;
pub const BRCM_PCIE_4359_DEVICE_ID: u16 = 0x43EF;
pub const BRCM_PCIE_43602_DEVICE_ID: u16 = 0x43BA;
pub const BRCM_PCIE_43602_2G_DEVICE_ID: u16 = 0x43BB;
pub const BRCM_PCIE_43602_5G_DEVICE_ID: u16 = 0x43BC;
pub const BRCM_PCIE_4364_DEVICE_ID: u16 = 0x4464;
pub const BRCM_PCIE_4365_DEVICE_ID: u16 = 0x43CA;
pub const BRCM_PCIE_4365_2G_DEVICE_ID: u16 = 0x43CB;
pub const BRCM_PCIE_4365_5G_DEVICE_ID: u16 = 0x43CC;
pub const BRCM_PCIE_4366_DEVICE_ID: u16 = 0x43C3;
pub const BRCM_PCIE_4366_2G_DEVICE_ID: u16 = 0x43C4;
pub const BRCM_PCIE_4366_5G_DEVICE_ID: u16 = 0x43C5;
pub const BRCM_PCIE_4371_DEVICE_ID: u16 = 0x440D;
pub const BRCM_PCIE_43596_DEVICE_ID: u16 = 0x4415;
pub const BRCM_PCIE_43752_DEVICE_ID: u16 = 0x449D;
pub const BRCM_PCIE_4377_DEVICE_ID: u16 = 0x4488;
pub const BRCM_PCIE_4378_DEVICE_ID: u16 = 0x4425;
pub const BRCM_PCIE_4387_DEVICE_ID: u16 = 0x4433;

/// All PCI device ids in the match table. Order matches the Linux
/// `brcmf_pcie_devices` array in `pcie.c` (~L2724..L2754) and is purely
/// cosmetic — the dispatcher matches by `(vendor, device)` pair.
pub const ALL_DEV_IDS: &[u16] = &[
    BRCM_PCIE_4350_DEVICE_ID,
    BRCM_PCIE_4354_DEVICE_ID,
    BRCM_PCIE_4354_RAW_DEVICE_ID,
    BRCM_PCIE_4355_DEVICE_ID,
    BRCM_PCIE_4356_DEVICE_ID,
    BRCM_PCIE_43567_DEVICE_ID,
    BRCM_PCIE_43570_DEVICE_ID,
    BRCM_PCIE_43570_RAW_DEVICE_ID,
    BRCM_PCIE_4358_DEVICE_ID,
    BRCM_PCIE_4359_DEVICE_ID,
    BRCM_PCIE_43602_DEVICE_ID,
    BRCM_PCIE_43602_2G_DEVICE_ID,
    BRCM_PCIE_43602_5G_DEVICE_ID,
    BRCM_PCIE_4364_DEVICE_ID,
    BRCM_PCIE_4365_DEVICE_ID,
    BRCM_PCIE_4365_2G_DEVICE_ID,
    BRCM_PCIE_4365_5G_DEVICE_ID,
    BRCM_PCIE_4366_DEVICE_ID,
    BRCM_PCIE_4366_2G_DEVICE_ID,
    BRCM_PCIE_4366_5G_DEVICE_ID,
    BRCM_PCIE_4371_DEVICE_ID,
    BRCM_PCIE_43596_DEVICE_ID,
    BRCM_PCIE_43752_DEVICE_ID,
    BRCM_PCIE_4377_DEVICE_ID,
    BRCM_PCIE_4378_DEVICE_ID,
    BRCM_PCIE_4387_DEVICE_ID,
];

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value. Each entry is
/// unique per device id — the bus's match-table registration is
/// idempotent on `name`, so collapsing variants (e.g. the
/// 43602/43602_2G/43602_5G triplet) to a single name would
/// silently overwrite all but the last entry. Sub-chip variants are
/// disambiguated via a per-id suffix instead.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        BRCM_PCIE_4350_DEVICE_ID => "brcmfmac-4350",
        BRCM_PCIE_4354_DEVICE_ID => "brcmfmac-4354",
        BRCM_PCIE_4354_RAW_DEVICE_ID => "brcmfmac-4354-raw",
        BRCM_PCIE_4355_DEVICE_ID => "brcmfmac-4355",
        BRCM_PCIE_4356_DEVICE_ID => "brcmfmac-4356",
        BRCM_PCIE_43567_DEVICE_ID => "brcmfmac-43567",
        BRCM_PCIE_43570_DEVICE_ID => "brcmfmac-43570",
        BRCM_PCIE_43570_RAW_DEVICE_ID => "brcmfmac-43570-raw",
        BRCM_PCIE_4358_DEVICE_ID => "brcmfmac-4358",
        BRCM_PCIE_4359_DEVICE_ID => "brcmfmac-4359",
        BRCM_PCIE_43602_DEVICE_ID => "brcmfmac-43602",
        BRCM_PCIE_43602_2G_DEVICE_ID => "brcmfmac-43602-2g",
        BRCM_PCIE_43602_5G_DEVICE_ID => "brcmfmac-43602-5g",
        BRCM_PCIE_4364_DEVICE_ID => "brcmfmac-4364",
        BRCM_PCIE_4365_DEVICE_ID => "brcmfmac-4365",
        BRCM_PCIE_4365_2G_DEVICE_ID => "brcmfmac-4365-2g",
        BRCM_PCIE_4365_5G_DEVICE_ID => "brcmfmac-4365-5g",
        BRCM_PCIE_4366_DEVICE_ID => "brcmfmac-4366",
        BRCM_PCIE_4366_2G_DEVICE_ID => "brcmfmac-4366-2g",
        BRCM_PCIE_4366_5G_DEVICE_ID => "brcmfmac-4366-5g",
        BRCM_PCIE_4371_DEVICE_ID => "brcmfmac-4371",
        BRCM_PCIE_43596_DEVICE_ID => "brcmfmac-43596",
        BRCM_PCIE_43752_DEVICE_ID => "brcmfmac-43752",
        BRCM_PCIE_4377_DEVICE_ID => "brcmfmac-4377",
        BRCM_PCIE_4378_DEVICE_ID => "brcmfmac-4378",
        BRCM_PCIE_4387_DEVICE_ID => "brcmfmac-4387",
        _ => "brcmfmac",
    }
}

/// Best-guess firmware-blob filename for a known device id. Format
/// matches the Linux `linux-firmware` tree's `brcm/brcmfmacXXXX-pcie.bin`
/// naming. Returns `None` for ids we don't have a registered candidate
/// for — the firmware-load path can still try the generic
/// `brcmfmac-pcie.bin` fallback.
pub const fn firmware_filename(did: u16) -> Option<&'static str> {
    match did {
        BRCM_PCIE_4350_DEVICE_ID => Some("/firmware/brcm/brcmfmac4350-pcie.bin"),
        BRCM_PCIE_4356_DEVICE_ID => Some("/firmware/brcm/brcmfmac4356-pcie.bin"),
        BRCM_PCIE_4358_DEVICE_ID => Some("/firmware/brcm/brcmfmac4358-pcie.bin"),
        BRCM_PCIE_43602_DEVICE_ID | BRCM_PCIE_43602_2G_DEVICE_ID | BRCM_PCIE_43602_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac43602-pcie.bin")
        }
        BRCM_PCIE_4365_DEVICE_ID | BRCM_PCIE_4365_2G_DEVICE_ID | BRCM_PCIE_4365_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac4366c-pcie.bin")
        }
        BRCM_PCIE_4366_DEVICE_ID | BRCM_PCIE_4366_2G_DEVICE_ID | BRCM_PCIE_4366_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac4366c-pcie.bin")
        }
        BRCM_PCIE_4371_DEVICE_ID => Some("/firmware/brcm/brcmfmac4371-pcie.bin"),
        BRCM_PCIE_4378_DEVICE_ID => Some("/firmware/brcm/brcmfmac4378b1-pcie.bin"),
        BRCM_PCIE_4377_DEVICE_ID => Some("/firmware/brcm/brcmfmac4377b3-pcie.bin"),
        BRCM_PCIE_4387_DEVICE_ID => Some("/firmware/brcm/brcmfmac4387c2-pcie.bin"),
        _ => None,
    }
}
