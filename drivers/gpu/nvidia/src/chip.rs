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
//!   BAR0 offset 0x000000 (stable since Fermi). Bits[24:20] hold
//!   ARCHITECTURE_VERSION, the value the chip reports about
//!   itself. Cited per
//!   `drivers/gpu/drm/nouveau/nvkm/subdev/mc/g84.c` & friends
//!   which read `0x000000` to detect the silicon.
//! - **Public `pci.ids` database** for every device-id entry.
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
/// `PMC_BOOT_0[24:20]` is the **architecture version** the chip
/// reports — a small integer that increments per generation.
/// Maxwell is the earliest family this driver targets; pre-Maxwell
/// parts use a substantially different display block (`dispnv04`)
/// that we don't intend to support here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipFamily {
    /// Fermi (NVC0). Architecture tag 0x20.
    Fermi,
    /// Kepler (NVE0). Architecture tag 0x30.
    Kepler,
    /// Maxwell (NV110, GM10x/GM20x). Architecture tag 0x40.
    Maxwell,
    /// Pascal (NV130, GP10x). Architecture tag 0x50.
    Pascal,
    /// Volta (NV140, GV10x). Architecture tag 0x60.
    Volta,
    /// Turing (NV160, TU10x). Architecture tag 0x70.
    Turing,
    /// Ampere (NV170, GA10x). Architecture tag 0x80.
    Ampere,
    /// Ada Lovelace (NV190, AD10x). Architecture tag 0x90.
    Ada,
    /// Architecture the driver doesn't recognise. Carries the raw
    /// 5-bit value from PMC_BOOT_0 so a future maintainer doesn't
    /// lose data.
    Unknown(u8),
}

impl ChipFamily {
    /// Decode the architecture version from `PMC_BOOT_0[24:20]`.
    pub const fn from_arch_version(arch: u8) -> Self {
        match arch {
            0x20 => ChipFamily::Fermi,
            0x30 => ChipFamily::Kepler,
            0x40 => ChipFamily::Maxwell,
            0x50 => ChipFamily::Pascal,
            0x60 => ChipFamily::Volta,
            0x70 => ChipFamily::Turing,
            0x80 => ChipFamily::Ampere,
            0x90 => ChipFamily::Ada,
            n => ChipFamily::Unknown(n),
        }
    }

    /// The architecture version this family reports in
    /// `PMC_BOOT_0[24:20]`.
    pub const fn arch_version(self) -> u8 {
        match self {
            ChipFamily::Fermi => 0x20,
            ChipFamily::Kepler => 0x30,
            ChipFamily::Maxwell => 0x40,
            ChipFamily::Pascal => 0x50,
            ChipFamily::Volta => 0x60,
            ChipFamily::Turing => 0x70,
            ChipFamily::Ampere => 0x80,
            ChipFamily::Ada => 0x90,
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
pub const AD106_RTX_4060: u16 = 0x2882;
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
        GP107_GTX_1050_TI => (ChipFamily::Pascal, "gp107"),
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
        AD106_RTX_4060 => (ChipFamily::Ada, "ad106"),
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
    ("nvidia-ad106-4060", AD106_RTX_4060),
];
