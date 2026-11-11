//! NVIDIA chip family table — Maxwell through Ada Lovelace.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/device/`**
//!   — Nouveau's per-ASIC dispatch tree, one file per ASIC. Family
//!   tags map to `NVxx` macros: Fermi=NVC0, Kepler=NVE0,
//!   Maxwell=NV110, Pascal=NV130, Volta=NV140, Turing=NV160,
//!   Ampere=NV170, Ada=NV190 (cited
//!   `drivers/gpu/drm/nouveau/include/nvkm/core/device.h`).
//! - **`PMC_BOOT_0`** layout — universal NVIDIA chip-id register at
//!   BAR0 offset 0x000000 (stable since Fermi). The architecture
//!   is a 6-bit field split across the register: low 5 bits at
//!   bits[28:24] plus the MSB at bit 8 —
//!   `arch = ((raw >> 8) & 1) << 5 | ((raw >> 24) & 0x1F)`.
//!   Grounded against the upstream Linux Nova driver
//!   (`drivers/gpu/nova-core/regs.rs`, commit
//!   1b155edcab0832a887387dd77e209e37beb7b49c:
//!   `NV_PMC_BOOT_0` = minor 3:0, major 7:4, architecture_1 bit 8,
//!   implementation 23:20, architecture_0 bits 28:24), whose
//!   `Architecture` enum pins GF100 = 0x0c, Turing = 0x16,
//!   Ampere = 0x17, Ada = 0x19. The remaining values follow the
//!   same rule from the NVxx codes above (arch = NV-code >> 4:
//!   NVE0 → 0x0e, NV110 → 0x11, NV130 → 0x13, NV140 → 0x14).
//! - **Public `pci.ids` database (version 2026.10.27)** for every
//!   device-id entry below. Two attributions were adjudicated
//!   against it in the crate-split step 3: 0x2786 is AD104
//!   [GeForce RTX 4070] (not AD103) and 0x2882 is AD107
//!   [GeForce RTX 4060] (not AD106); 0x2820 is AD106M
//!   [GeForce RTX 4070 Max-Q / Mobile].
//!
//! NARF licence: GPL-2.0-or-later (see top-of-repo `LICENSE`). The
//! Nouveau adaptations here are legitimate cross-references.

#![allow(dead_code)]

/// NVIDIA Corporation PCI vendor id.
pub const NVIDIA_VENDOR: u16 = 0x10DE;

/// PCI class code (display controller). Used as a backstop match
/// to catch unenumerated parts; the probe still filters by vendor.
pub const PCI_CLASS_DISPLAY: u8 = 0x03;

/// Chip-family generations the driver knows about.
///
/// `PMC_BOOT_0` carries the **architecture version** the chip
/// reports — a 6-bit value split across the register (low 5 bits
/// at bits[28:24], MSB at bit 8; see the module header for the
/// Nova grounding). Maxwell is the earliest family this driver
/// targets; pre-Maxwell parts use a substantially different
/// display block (`dispnv04`) that we don't intend to support here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipFamily {
    /// Fermi (NVC0). Architecture value 0x0c.
    Fermi,
    /// Kepler (NVE0). Architecture value 0x0e.
    Kepler,
    /// Maxwell (NV110, GM10x/GM20x). Architecture value 0x11.
    Maxwell,
    /// Pascal (NV130, GP10x). Architecture value 0x13.
    Pascal,
    /// Volta (NV140, GV10x). Architecture value 0x14.
    Volta,
    /// Turing (NV160, TU10x). Architecture value 0x16.
    Turing,
    /// Ampere (NV170, GA10x). Architecture value 0x17.
    Ampere,
    /// Ada Lovelace (NV190, AD10x). Architecture value 0x19.
    Ada,
    /// Architecture the driver doesn't recognise. Carries the raw
    /// 6-bit value from PMC_BOOT_0 so a future maintainer doesn't
    /// lose data.
    Unknown(u8),
}

impl ChipFamily {
    /// Decode the architecture version from `PMC_BOOT_0`.
    pub const fn from_arch_version(arch: u8) -> Self {
        match arch {
            0x0c => ChipFamily::Fermi,
            0x0e => ChipFamily::Kepler,
            0x11 => ChipFamily::Maxwell,
            0x13 => ChipFamily::Pascal,
            0x14 => ChipFamily::Volta,
            0x16 => ChipFamily::Turing,
            0x17 => ChipFamily::Ampere,
            0x19 => ChipFamily::Ada,
            n => ChipFamily::Unknown(n),
        }
    }

    /// The architecture version this family reports in
    /// `PMC_BOOT_0`.
    pub const fn arch_version(self) -> u8 {
        match self {
            ChipFamily::Fermi => 0x0c,
            ChipFamily::Kepler => 0x0e,
            ChipFamily::Maxwell => 0x11,
            ChipFamily::Pascal => 0x13,
            ChipFamily::Volta => 0x14,
            ChipFamily::Turing => 0x16,
            ChipFamily::Ampere => 0x17,
            ChipFamily::Ada => 0x19,
            ChipFamily::Unknown(n) => n,
        }
    }

    /// Short ASCII tag for diagnostics ("maxwell", "ada", …).
    pub const fn tag(self) -> &'static str {
        match self {
            ChipFamily::Fermi => "fermi",
            ChipFamily::Kepler => "kepler",
            ChipFamily::Maxwell => "maxwell",
            ChipFamily::Pascal => "pascal",
            ChipFamily::Volta => "volta",
            ChipFamily::Turing => "turing",
            ChipFamily::Ampere => "ampere",
            ChipFamily::Ada => "ada",
            ChipFamily::Unknown(_) => "unknown",
        }
    }

    /// True when this family uses the NV50/NVD0/NV9x dispclass
    /// register layout (Maxwell and later). Pre-Maxwell parts use
    /// `dispnv04` which has a different shape.
    pub const fn has_disp_nv50(self) -> bool {
        matches!(
            self,
            ChipFamily::Maxwell
                | ChipFamily::Pascal
                | ChipFamily::Volta
                | ChipFamily::Turing
                | ChipFamily::Ampere
                | ChipFamily::Ada
        )
    }

    /// True if this family has a GPU System Processor (GSP). Turing
    /// introduced GSP-RM offload; Ampere/Ada lean on it heavily.
    pub const fn has_gsp(self) -> bool {
        matches!(
            self,
            ChipFamily::Turing | ChipFamily::Ampere | ChipFamily::Ada
        )
    }
}

/// Static per-chip identification record. The probe walks a table
/// of these, matches on `(vid, did)`, and lifts the family + ASIC
/// tag straight out.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub family: ChipFamily,
    /// Short ASIC name ("gm204", "ga102", …).
    pub asic: &'static str,
}

// ── PCI device IDs ───────────────────────────────────────────────
//
// vendor 0x10DE; device ids drawn from upstream `pci.ids` and
// Nouveau's per-ASIC files (e.g. `nvkm/device/gm200.c`).

// Maxwell (GM10x/GM20x) — GTX 900-series.
pub const GM107_GTX_750_TI: u16 = 0x1380;
pub const GM107_GTX_750: u16 = 0x1381;
pub const GM204_GTX_970: u16 = 0x13C2;
pub const GM204_GTX_980: u16 = 0x13C0;
pub const GM206_GTX_960: u16 = 0x1401;
pub const GM200_GTX_TITAN_X: u16 = 0x17C2;

// Pascal (GP10x) — GTX 1000-series.
pub const GP104_GTX_1080: u16 = 0x1B80;
pub const GP104_GTX_1070: u16 = 0x1B81;
pub const GP106_GTX_1060_6G: u16 = 0x1C03;
pub const GP106_GTX_1060_3G: u16 = 0x1C02;
pub const GP102_GTX_1080_TI: u16 = 0x1B06;
pub const GP107_GTX_1050_TI: u16 = 0x1C82;
// GP107 family, pci.ids 2026.10.27 (vendor 0x10DE section).
// 0x1C81 is the plain desktop GTX 1050 (G1: Daniel's card).
// 0x1C8E is a bare "GP107M" with no product name — left out.
// `_R2` suffixes mark the two product names pci.ids repeats for
// two DIDs (GTX 1050 Mobile: 0x1C8D/0x1C92; MX350: 0x1C94/0x1C96).
pub const GP107_GTX_1050: u16 = 0x1C81;
pub const GP107_GTX_1050_3G: u16 = 0x1C83;
pub const GP107M_GTX_1050_TI_MOBILE: u16 = 0x1C8C;
pub const GP107M_GTX_1050_MOBILE: u16 = 0x1C8D;
pub const GP107M_GTX_1050_TI_MAXQ: u16 = 0x1C8F;
pub const GP107M_MX150: u16 = 0x1C90;
pub const GP107M_GTX_1050_3G_MAXQ: u16 = 0x1C91;
pub const GP107M_GTX_1050_MOBILE_R2: u16 = 0x1C92;
pub const GP107M_MX350: u16 = 0x1C94;
pub const GP107M_MX350_R2: u16 = 0x1C96;

// Volta (GV10x) — Titan V only; Quadro GV100 etc.
pub const GV100_TITAN_V: u16 = 0x1D81;

// Turing (TU10x) — GTX 16-series + RTX 20-series.
pub const TU116_GTX_1660: u16 = 0x2184;
pub const TU117_GTX_1650: u16 = 0x1F82;
pub const TU106_RTX_2060: u16 = 0x1F08;
pub const TU106_RTX_2070: u16 = 0x1F02;
pub const TU104_RTX_2080: u16 = 0x1E82;
pub const TU104_RTX_2080_SUPER: u16 = 0x1E81;
pub const TU102_RTX_2080_TI: u16 = 0x1E04;
pub const TU102_RTX_2080_TI_REFRESH: u16 = 0x1E07;

// Ampere (GA10x) — RTX 30-series.
pub const GA106_RTX_3060: u16 = 0x2503;
pub const GA104_RTX_3070: u16 = 0x2484;
pub const GA102_RTX_3080: u16 = 0x2206;
pub const GA102_RTX_3090: u16 = 0x2204;

// Ada Lovelace (AD10x) — RTX 40-series.
pub const AD106_RTX_4060_TI: u16 = 0x2803;
pub const AD106_RTX_4060_TI_16G: u16 = 0x2805;
pub const AD106_RTX_4060: u16 = 0x2808;
pub const AD106M_RTX_4070_MOBILE: u16 = 0x2820;
pub const AD107_RTX_4060: u16 = 0x2882;
pub const AD104_RTX_4070: u16 = 0x2786;
pub const AD103_RTX_4080: u16 = 0x2704;
pub const AD102_RTX_4090: u16 = 0x2684;

/// Look up a chip's `ChipInfo` by `(vid, did)`. Returns `None` if
/// the vendor isn't NVIDIA or the device id isn't in our table.
pub fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != NVIDIA_VENDOR {
        return None;
    }
    let (family, asic) = match did {
        // Maxwell.
        GM107_GTX_750_TI | GM107_GTX_750 => (ChipFamily::Maxwell, "gm107"),
        GM200_GTX_TITAN_X => (ChipFamily::Maxwell, "gm200"),
        GM204_GTX_970 | GM204_GTX_980 => (ChipFamily::Maxwell, "gm204"),
        GM206_GTX_960 => (ChipFamily::Maxwell, "gm206"),
        // Pascal.
        GP102_GTX_1080_TI => (ChipFamily::Pascal, "gp102"),
        GP104_GTX_1080 | GP104_GTX_1070 => (ChipFamily::Pascal, "gp104"),
        GP106_GTX_1060_6G | GP106_GTX_1060_3G => (ChipFamily::Pascal, "gp106"),
        GP107_GTX_1050_TI | GP107_GTX_1050 | GP107_GTX_1050_3G => (ChipFamily::Pascal, "gp107"),
        GP107M_GTX_1050_TI_MOBILE
        | GP107M_GTX_1050_MOBILE
        | GP107M_GTX_1050_TI_MAXQ
        | GP107M_MX150
        | GP107M_GTX_1050_3G_MAXQ
        | GP107M_GTX_1050_MOBILE_R2
        | GP107M_MX350
        | GP107M_MX350_R2 => (ChipFamily::Pascal, "gp107m"),
        // Volta.
        GV100_TITAN_V => (ChipFamily::Volta, "gv100"),
        // Turing.
        TU102_RTX_2080_TI | TU102_RTX_2080_TI_REFRESH => (ChipFamily::Turing, "tu102"),
        TU104_RTX_2080 | TU104_RTX_2080_SUPER => (ChipFamily::Turing, "tu104"),
        TU106_RTX_2060 | TU106_RTX_2070 => (ChipFamily::Turing, "tu106"),
        TU116_GTX_1660 => (ChipFamily::Turing, "tu116"),
        TU117_GTX_1650 => (ChipFamily::Turing, "tu117"),
        // Ampere.
        GA102_RTX_3080 | GA102_RTX_3090 => (ChipFamily::Ampere, "ga102"),
        GA104_RTX_3070 => (ChipFamily::Ampere, "ga104"),
        GA106_RTX_3060 => (ChipFamily::Ampere, "ga106"),
        // Ada.
        AD102_RTX_4090 => (ChipFamily::Ada, "ad102"),
        AD103_RTX_4080 => (ChipFamily::Ada, "ad103"),
        AD104_RTX_4070 => (ChipFamily::Ada, "ad104"),
        AD106_RTX_4060_TI | AD106_RTX_4060_TI_16G | AD106_RTX_4060 => (ChipFamily::Ada, "ad106"),
        AD106M_RTX_4070_MOBILE => (ChipFamily::Ada, "ad106m"),
        AD107_RTX_4060 => (ChipFamily::Ada, "ad107"),
        _ => return None,
    };
    Some(ChipInfo {
        vid,
        did,
        family,
        asic,
    })
}

/// Static table of all known PCI ids, in registration order. Used
/// by the PCI driver-match registration and by smoke tests for
/// coverage.
///
/// Every entry is grounded against the public `pci.ids` database,
/// version 2026.10.27 (vendor 0x10DE section). Step-3 corrections
/// against that snapshot: 0x2786 is AD104 [GeForce RTX 4070];
/// 0x2882 is AD107 [GeForce RTX 4060]; 0x2820 is AD106M
/// [GeForce RTX 4070 Max-Q / Mobile]; AD106 desktop parts are
/// 0x2803 (4060 Ti), 0x2805 (4060 Ti 16GB), 0x2808 (4060).
/// G1 GP107 additions against the same snapshot: 0x1C81 is GP107
/// [GeForce GTX 1050]; 0x1C83 GP107 [GeForce GTX 1050 3GB];
/// mobile GP107M: 0x1C8C (1050 Ti Mobile), 0x1C8D (1050 Mobile),
/// 0x1C8F (1050 Ti Max-Q), 0x1C90 (MX150), 0x1C91 (1050 3 GB
/// Max-Q), 0x1C92 (1050 Mobile), 0x1C94/0x1C96 (MX350).
/// 0x1C8E is a bare "GP107M" with no product name — not registered.
pub const KNOWN_DEVICES: &[(&str, u16)] = &[
    // Maxwell.
    ("nvidia-gm107-gtx750ti", GM107_GTX_750_TI),
    ("nvidia-gm107-gtx750", GM107_GTX_750),
    ("nvidia-gm200-titanx", GM200_GTX_TITAN_X),
    ("nvidia-gm204-gtx970", GM204_GTX_970),
    ("nvidia-gm204-gtx980", GM204_GTX_980),
    ("nvidia-gm206-gtx960", GM206_GTX_960),
    // Pascal.
    ("nvidia-gp102-1080ti", GP102_GTX_1080_TI),
    ("nvidia-gp104-gtx1080", GP104_GTX_1080),
    ("nvidia-gp104-gtx1070", GP104_GTX_1070),
    ("nvidia-gp106-gtx1060-6g", GP106_GTX_1060_6G),
    ("nvidia-gp106-gtx1060-3g", GP106_GTX_1060_3G),
    ("nvidia-gp107-gtx1050ti", GP107_GTX_1050_TI),
    ("nvidia-gp107-gtx1050", GP107_GTX_1050),
    ("nvidia-gp107-gtx1050-3g", GP107_GTX_1050_3G),
    ("nvidia-gp107m-gtx1050ti-mobile", GP107M_GTX_1050_TI_MOBILE),
    ("nvidia-gp107m-gtx1050-mobile", GP107M_GTX_1050_MOBILE),
    ("nvidia-gp107m-gtx1050ti-maxq", GP107M_GTX_1050_TI_MAXQ),
    ("nvidia-gp107m-mx150", GP107M_MX150),
    ("nvidia-gp107m-gtx1050-3g-maxq", GP107M_GTX_1050_3G_MAXQ),
    ("nvidia-gp107m-gtx1050-mobile-r2", GP107M_GTX_1050_MOBILE_R2),
    ("nvidia-gp107m-mx350", GP107M_MX350),
    ("nvidia-gp107m-mx350-r2", GP107M_MX350_R2),
    // Volta.
    ("nvidia-gv100-titanv", GV100_TITAN_V),
    // Turing.
    ("nvidia-tu102-2080ti", TU102_RTX_2080_TI),
    ("nvidia-tu102-2080ti-r", TU102_RTX_2080_TI_REFRESH),
    ("nvidia-tu104-2080", TU104_RTX_2080),
    ("nvidia-tu104-2080s", TU104_RTX_2080_SUPER),
    ("nvidia-tu106-2060", TU106_RTX_2060),
    ("nvidia-tu106-2070", TU106_RTX_2070),
    ("nvidia-tu116-1660", TU116_GTX_1660),
    ("nvidia-tu117-1650", TU117_GTX_1650),
    // Ampere.
    ("nvidia-ga102-3080", GA102_RTX_3080),
    ("nvidia-ga102-3090", GA102_RTX_3090),
    ("nvidia-ga104-3070", GA104_RTX_3070),
    ("nvidia-ga106-3060", GA106_RTX_3060),
    // Ada.
    ("nvidia-ad102-4090", AD102_RTX_4090),
    ("nvidia-ad103-4080", AD103_RTX_4080),
    ("nvidia-ad104-4070", AD104_RTX_4070),
    ("nvidia-ad106-4060ti", AD106_RTX_4060_TI),
    ("nvidia-ad106-4060ti-16g", AD106_RTX_4060_TI_16G),
    ("nvidia-ad106-4060", AD106_RTX_4060),
    ("nvidia-ad106m-4070-mobile", AD106M_RTX_4070_MOBILE),
    ("nvidia-ad107-4060", AD107_RTX_4060),
];
