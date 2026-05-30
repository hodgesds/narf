//! btusb vendor quirks — chip-specific firmware paths and behavioural
//! hacks per inbound USB VID:PID.
//!
//! References (clean-room — Linux GPL source consulted per NARF
//! 2026-05-20 relicense to GPL-2.0-or-later):
//! - `drivers/bluetooth/btusb.c` — Linux btusb chip table with
//!   `USB_DEVICE_AND_INTERFACE_INFO()` entries and
//!   `BTUSB_*` quirk flags (`BTUSB_INTEL`, `BTUSB_REALTEK`,
//!   `BTUSB_QCA_WCN6855`, `BTUSB_MEDIATEK`, `BTUSB_BCM_PATCHRAM`,
//!   `BTUSB_CSR`, `BTUSB_AMP`).
//! - `drivers/bluetooth/btintel.c` — Intel firmware-load sequence
//!   (HCI_Reset → vendor command 0xFC09 read boot params → load
//!   .sfi/.bseq into boot ROM → vendor command 0xFC01 boot → wait
//!   for vendor event 0xFF/0x02). NARF defers blob load but records
//!   the path so a userspace firmware service can stage it.
//! - `drivers/bluetooth/btrtl.c` — Realtek firmware-load sequence
//!   (read ROM version via H4 vendor pkt, fetch `rtl_bt/rtl8761*.bin`
//!   + `rtl_bt/rtl8761*_config.bin`, send via vendor command 0xFC20).
//! - `drivers/bluetooth/btqca.c` — Qualcomm WCN6855 NVM/firmware load.
//! - `drivers/bluetooth/btmtk.{c,h}` — MediaTek 7921/7922 firmware
//!   load via WMT command sequence.
//!
//! ## Surface
//!
//! - [`Quirk`] enum — the chip family.
//! - [`identify`] — VID:PID → `Option<Quirk>` from a static table.
//! - [`firmware_paths`] — the (firmware, config) blob basenames the
//!   Linux upstream looks up. Per-vendor format documented inline.

extern crate alloc;

use alloc::vec::Vec;

/// Chip-family quirk classification. One per upstream `BTUSB_*` flag
/// that affects the host-side bring-up path. CSR is included for the
/// "fake CSR" clones whose USB descriptor lies about the chip ID —
/// distinguished by `bcdDevice == 0x0867` (Linux btusb commit
/// e51eaa7a51b2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Quirk {
    /// Intel AX2xx series — vendor command 0xFC09 / 0xFC01.
    Intel,
    /// Realtek RTL8761/RTL8852 — vendor command 0xFC20 / 0xFC6D.
    Realtek,
    /// Qualcomm WCN6855 — NVM + RAM patch via vendor cmd 0xFC00.
    QualcommWcn6855,
    /// MediaTek MT7921 / MT7922 — WMT command 0xFC6F.
    MediaTek,
    /// Broadcom BCM4329/BCM4377 — `.hcd` patch RAM upload.
    Broadcom,
    /// Cambridge Silicon Radio (CSR8510). Some clones spoof the VID
    /// (0x0a12:0x0001) but report bcdDevice 0x0867 — "fake CSR".
    Csr,
    /// Marvell SD8897 USB.
    Marvell,
}

/// Match record for a single (vendor, product) combination.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QuirkMatch {
    pub vendor: u16,
    pub product: u16,
    pub quirk: Quirk,
}

/// Static quirk table. The list is far from exhaustive; the entries
/// here are the ones every recent Linux release matches plus the two
/// NARF bring-up targets (Zen2 Renoir = Intel AX200, Phoenix
/// HawkPoint1 = MT7922).
///
/// Linux reference: `drivers/bluetooth/btusb.c`, `btusb_table[]`.
pub const QUIRK_TABLE: &[QuirkMatch] = &[
    // Intel AX2xx (BTUSB_INTEL_COMBINED).
    QuirkMatch { vendor: 0x8087, product: 0x0026, quirk: Quirk::Intel },
    QuirkMatch { vendor: 0x8087, product: 0x0029, quirk: Quirk::Intel },
    QuirkMatch { vendor: 0x8087, product: 0x0032, quirk: Quirk::Intel }, // AX210
    QuirkMatch { vendor: 0x8087, product: 0x0033, quirk: Quirk::Intel }, // AX211
    QuirkMatch { vendor: 0x8087, product: 0x0036, quirk: Quirk::Intel }, // BE200
    // Realtek RTL8761/RTL8821/RTL8852.
    QuirkMatch { vendor: 0x0bda, product: 0x8771, quirk: Quirk::Realtek }, // RTL8761B
    QuirkMatch { vendor: 0x0bda, product: 0xb852, quirk: Quirk::Realtek }, // RTL8852A
    QuirkMatch { vendor: 0x0bda, product: 0xc852, quirk: Quirk::Realtek }, // RTL8852C
    QuirkMatch { vendor: 0x0bda, product: 0xc123, quirk: Quirk::Realtek }, // RTL8761
    QuirkMatch { vendor: 0x13d3, product: 0x3548, quirk: Quirk::Realtek },
    // Qualcomm WCN6855.
    QuirkMatch { vendor: 0x0489, product: 0xe0cd, quirk: Quirk::QualcommWcn6855 },
    QuirkMatch { vendor: 0x0489, product: 0xe0e0, quirk: Quirk::QualcommWcn6855 },
    // MediaTek MT7921 / MT7922 (Phoenix HawkPoint1 default).
    QuirkMatch { vendor: 0x0e8d, product: 0x7961, quirk: Quirk::MediaTek }, // MT7921
    QuirkMatch { vendor: 0x0e8d, product: 0x7922, quirk: Quirk::MediaTek }, // MT7922
    QuirkMatch { vendor: 0x13d3, product: 0x3563, quirk: Quirk::MediaTek }, // MT7922 Lite-On
    // Broadcom BCM4377/4378 (Apple Silicon — uncommon on x86 NARF).
    QuirkMatch { vendor: 0x0a5c, product: 0x6410, quirk: Quirk::Broadcom },
    // CSR8510 official + clones.
    QuirkMatch { vendor: 0x0a12, product: 0x0001, quirk: Quirk::Csr },
    // Marvell SD8897 USB.
    QuirkMatch { vendor: 0x1286, product: 0x2044, quirk: Quirk::Marvell },
];

/// Match a USB VID:PID against the quirk table.
#[inline]
pub fn identify(vendor: u16, product: u16) -> Option<Quirk> {
    QUIRK_TABLE
        .iter()
        .find(|q| q.vendor == vendor && q.product == product)
        .map(|q| q.quirk)
}

/// Identify a "fake CSR" clone — VID/PID match a real CSR8510 but the
/// device descriptor reports an out-of-band `bcdDevice`. Linux btusb
/// `btusb_check_bdaddr()` rejects these because their BD_ADDR is a
/// fixed string. Returning true here tells the controller-supervisor
/// to skip the BD_ADDR check and mint a random address.
#[inline]
pub fn is_fake_csr(vendor: u16, product: u16, bcd_device: u16) -> bool {
    vendor == 0x0a12
        && product == 0x0001
        && (bcd_device == 0x0867 || bcd_device == 0x1915 || bcd_device == 0x2520)
}

/// Per-quirk firmware blob basenames. `(firmware, config)` — the
/// config slot is `None` when the vendor only ships one file. Names
/// match the Linux blobs in `/lib/firmware/` so userspace can share
/// the cache.
///
/// Caller must concatenate the vendor's prefix (`intel/`, `rtl_bt/`,
/// `qca/`, `mediatek/`, `brcm/`, …) when actually hitting the FS.
pub fn firmware_paths(quirk: Quirk) -> Vec<(&'static str, Option<&'static str>)> {
    let mut out = Vec::new();
    match quirk {
        Quirk::Intel => {
            // .sfi + .ddc per upstream btintel naming. AX210 / AX211
            // both stage from these same families.
            out.push(("ibt-0040-1050.sfi", Some("ibt-0040-1050.ddc")));
            out.push(("ibt-0041-0041.sfi", Some("ibt-0041-0041.ddc")));
        }
        Quirk::Realtek => {
            out.push(("rtl8761b_fw.bin", Some("rtl8761b_config.bin")));
            out.push(("rtl8852au_fw.bin", Some("rtl8852au_config.bin")));
            out.push(("rtl8852bu_fw.bin", Some("rtl8852bu_config.bin")));
            out.push(("rtl8761bu_fw.bin", Some("rtl8761bu_config.bin")));
        }
        Quirk::QualcommWcn6855 => {
            // NVM+RAM patch pair, per btqca.
            out.push(("hpnv21.bin", None));
            out.push(("hpbtfw21.tlv", None));
        }
        Quirk::MediaTek => {
            // BT_RAM_CODE_MT*.bin per btmtk WMT load.
            out.push(("BT_RAM_CODE_MT7961_1_2_hdr.bin", None));
            out.push(("BT_RAM_CODE_MT7922_1_1_hdr.bin", None));
        }
        Quirk::Broadcom => {
            // .hcd patch file.
            out.push(("BCM4377C5.hcd", None));
            out.push(("BCM-0a5c-6410.hcd", None));
        }
        Quirk::Csr => {
            // CSR8510 has on-chip firmware; no host blob.
        }
        Quirk::Marvell => {
            out.push(("mrvl/sd8897_uapsta.bin", None));
        }
    }
    out
}

/// Result of an early-boot vendor probe. The controller supervisor
/// fills `bd_addr` once it has issued `HCI_Read_BD_ADDR`; quirks
/// that need a vendor command to retrieve the BD_ADDR (Intel post-
/// firmware) set this from the vendor event payload instead.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VendorIdentity {
    pub quirk: Option<Quirk>,
    pub bd_addr: Option<[u8; 6]>,
    pub bcd_device: u16,
    pub vendor: u16,
    pub product: u16,
}

impl VendorIdentity {
    /// Build from a USB device descriptor's idVendor/idProduct/bcdDevice
    /// (USB 2.0 §9.6.1).
    pub fn from_descriptor(vendor: u16, product: u16, bcd_device: u16) -> Self {
        Self {
            quirk: identify(vendor, product),
            bd_addr: None,
            bcd_device,
            vendor,
            product,
        }
    }

    /// Whether the controller should skip the post-boot BD_ADDR sanity
    /// check (used for fake CSR clones that hardcode 00:00:00:00:5A:AD).
    pub fn skip_bdaddr_check(&self) -> bool {
        is_fake_csr(self.vendor, self.product, self.bcd_device)
    }
}

#[cfg(test)]
mod selftest {
    use super::*;
    const _: () = assert!(QUIRK_TABLE.len() > 10);
    // Compile-time sanity: VID 0x8087 is Intel.
    const _: () = {
        let mut i = 0;
        let mut found = false;
        while i < QUIRK_TABLE.len() {
            if QUIRK_TABLE[i].vendor == 0x8087 {
                found = true;
                break;
            }
            i += 1;
        }
        assert!(found);
    };
}
