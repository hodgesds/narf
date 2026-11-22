//! HDA controller PCI ids.
//!
//! Compiled in both the built-in and the module build, so the `.ko`'s
//! registration-only probe and the real driver match exactly the same
//! devices. Pure data: no kernel crates.

// ── PCI device ids ─────────────────────────────────────────────────

/// AMD platform (FCH / SoC) HD-Audio controllers: the board's analog codec.
pub const HDA_AMD_VENDOR: u16 = 0x1022;
/// The Family 17h/19h HD-Audio controller. Linux lists it as "AMD Raven",
/// the first part it shipped on, but the same function carries the analog
/// codec on Renoir, Cezanne, Rembrandt and Phoenix APUs and on the Ryzen 7000
/// (Raphael / Granite Ridge, AM5) desktop, such as a Ryzen 5 7600X board.
pub const HDA_AMD_ZEN_DEVICE: u16 = 0x15e3;
/// Linux "AMD, X370 & co": the Zen 1/Zen+ desktop chipset's HD-Audio.
pub const HDA_AMD_X370_DEVICE: u16 = 0x1457;
/// Linux "AMD, X570 & co": the Zen 2/Zen 3 desktop HD-Audio.
pub const HDA_AMD_X570_DEVICE: u16 = 0x1487;

/// Whether `vendor:device` is one Linux binds with `AZX_DCAPS_PRESET_AMD_SB`
/// (sound/hda/controllers/intel.c): ATI snoop (PCI 0x42), no TCSEL, the
/// FIFO position fix (LPIB, 32-frame delay) and, in particular
/// `AZX_DCAPS_RETRY_PROBE`: Linux retries the codec probe every second, up
/// to 60 times, because "a few recent AMD systems show the codec
/// configuration errors at the early boot, while loading the driver at a
/// later stage works magically" (commit c0f1886de7e1).
pub const fn amd_sb_preset(vendor: u16, device: u16) -> bool {
    vendor == HDA_AMD_VENDOR
        && matches!(
            device,
            HDA_AMD_X370_DEVICE | HDA_AMD_X570_DEVICE | HDA_AMD_ZEN_DEVICE
        )
}

/// The ATI HDMI no-snoop functions whose Linux `azx_ids[]` entry adds
/// `AZX_DCAPS_PM_RUNTIME` to `AZX_DCAPS_PRESET_ATI_HDMI_NS`.
const ATI_HDMI_NS_RUNTIME_PM: &[u16] = &[
    0x0002, 0xaac0, 0xaac8, 0xaad8, 0xaae0, 0xaae8, 0xaaf0, 0xaaf8, 0xab00, 0xab08, 0xab10, 0xab18,
    0xab20, 0xab28, 0xab30, 0xab38, 0xab40,
];

/// Whether Linux runtime-suspends the controller (`azx_has_pm_runtime`:
/// `AZX_DCAPS_PM_RUNTIME` in its `azx_ids[]` entry), so that
/// `azx_runtime_idle` lets it power down once its codecs have. The AMD SB
/// preset has it, as do the ATI HDMI functions listed above and every Intel
/// PCH from Skylake on; the ICH parts, the other ATI HDMI functions and the
/// ATI/AMD class match (1002:1640, 1002:1637) do not, and there only the
/// codecs suspend.
pub fn runtime_pm(vendor: u16, device: u16) -> bool {
    match vendor {
        HDA_AMD_VENDOR => amd_sb_preset(vendor, device),
        HDA_AMD_RADEON_VENDOR => ATI_HDMI_NS_RUNTIME_PM.contains(&device),
        HDA_INTEL_ICH9_VENDOR => !matches!(
            device,
            HDA_INTEL_ICH6_DEVICE | HDA_INTEL_ICH7_DEVICE | HDA_INTEL_ICH9_DEVICE
        ),
        _ => false,
    }
}

/// The card's short name (Linux `card->shortname`): `driver_short_names[]`
/// for the driver type `azx_ids[]` gives the controller. The ATI HDMI NS
/// functions are `AZX_DRIVER_ATIHDMI_NS`; the AMD platform controllers and
/// the ATI/AMD class match (1002:1640 among them) are `AZX_DRIVER_GENERIC`;
/// the ICH parts are `AZX_DRIVER_ICH` and every later Intel PCH is
/// `AZX_DRIVER_PCH` / `AZX_DRIVER_SKL` ("HDA Intel PCH" for both).
pub fn card_short_name(vendor: u16, device: u16) -> &'static str {
    if vendor == HDA_AMD_RADEON_VENDOR && HDA_ATI_HDMI_NS_DEVICES.contains(&device) {
        "HDA ATI HDMI"
    } else if vendor == HDA_INTEL_ICH9_VENDOR {
        match device {
            HDA_INTEL_ICH6_DEVICE | HDA_INTEL_ICH7_DEVICE | HDA_INTEL_ICH9_DEVICE => "HDA Intel",
            _ => "HDA Intel PCH",
        }
    } else {
        "HD-Audio Generic"
    }
}

/// The card id Linux `snd_card_register` derives when the driver sets none:
/// the short name's last word (`retrieve_id_from_card_name`), so "HDMI",
/// "Generic", "Intel" or "PCH". The sound registry makes it unique.
pub fn card_id(short_name: &'static str) -> &'static str {
    short_name.rsplit(' ').next().unwrap_or(short_name)
}

/// AMD Radeon HD Audio Controller — found on integrated Radeon GPUs.
pub const HDA_AMD_RADEON_VENDOR: u16 = 0x1002;
pub const HDA_AMD_RADEON_DEVICE: u16 = 0x1640;

/// Intel ICH6 HD Audio.
pub const HDA_INTEL_ICH6_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH6_DEVICE: u16 = 0x2668;

/// Intel ICH7 HD Audio.
pub const HDA_INTEL_ICH7_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH7_DEVICE: u16 = 0x27D8;

/// Intel ICH9 HD Audio (QEMU default).
pub const HDA_INTEL_ICH9_VENDOR: u16 = 0x8086;
pub const HDA_INTEL_ICH9_DEVICE: u16 = 0x293E;

// ── Intel PCH HDA controller PCI device ids ───────────────────────
//
// Every Intel PCH HDA controller speaks the standard Intel HDA
// programming model (same BAR0 layout, CORB/RIRB, stream descriptors,
// codec verbs) — only the PCI ID changes. The IDs below cover the
// modern PCH era (Skylake → Meteor Lake). All share the Intel vendor
// ID 0x8086 and the same `probe` entry as the legacy ICH path.
//
// Reference: Linux `sound/pci/hda/hda_intel.c` `azx_ids[]` and
// `pci.ids`. We deliberately keep each ID in its own named constant
// so it is grep-able and the registration site is a flat enumeration.

/// Sunrise Point-LP HD Audio (Skylake / Kaby Lake PCH-LP).
pub const HDA_INTEL_SUNRISE_POINT_LP_DEVICE: u16 = 0x9D70;
/// Sunrise Point-LP HD Audio — variant.
pub const HDA_INTEL_SUNRISE_POINT_LP_DEVICE_B: u16 = 0x9D71;

/// Cannon Lake PCH HD Audio.
pub const HDA_INTEL_CANNON_LAKE_DEVICE: u16 = 0xA348;

/// Comet Lake HD Audio — variant A.
pub const HDA_INTEL_COMET_LAKE_DEVICE: u16 = 0xA171;
/// Comet Lake HD Audio — variant B.
pub const HDA_INTEL_COMET_LAKE_DEVICE_B: u16 = 0x43C8;

/// Tiger Lake PCH-LP HD Audio — variant A.
pub const HDA_INTEL_TIGER_LAKE_LP_DEVICE: u16 = 0xA0C8;
/// Tiger Lake PCH-LP HD Audio — variant B.
pub const HDA_INTEL_TIGER_LAKE_LP_DEVICE_B: u16 = 0xA0C9;

/// Alder Lake-P / Alder Lake-S HD Audio — variant A.
pub const HDA_INTEL_ALDER_LAKE_DEVICE: u16 = 0x7AD0;
/// Alder Lake-P / Alder Lake-S HD Audio — variant B.
pub const HDA_INTEL_ALDER_LAKE_DEVICE_B: u16 = 0x51C8;
/// Alder Lake-P / Alder Lake-S HD Audio — variant C.
pub const HDA_INTEL_ALDER_LAKE_DEVICE_C: u16 = 0x51CD;

/// Meteor Lake HD Audio.
pub const HDA_INTEL_METEOR_LAKE_DEVICE: u16 = 0x7E28;
// Names below track Linux's `PCI_DEVICE_ID_INTEL_HDA_*` in
// `include/linux/pci_ids.h` so the two tables can be diffed directly.

/// Arrow Lake HD Audio (`PCI_DEVICE_ID_INTEL_HDA_ARL`).
pub const HDA_INTEL_ARROW_LAKE_DEVICE: u16 = 0x7728;
/// Arrow Lake-S HD Audio (`PCI_DEVICE_ID_INTEL_HDA_ARL_S`).
pub const HDA_INTEL_ARROW_LAKE_S_DEVICE: u16 = 0x7F50;
/// Lunar Lake-P HD Audio (`PCI_DEVICE_ID_INTEL_HDA_LNL_P`).
pub const HDA_INTEL_LUNAR_LAKE_P_DEVICE: u16 = 0xA828;
/// Panther Lake-H HD Audio (`PCI_DEVICE_ID_INTEL_HDA_PTL_H`) — the
/// controller on the Minisforum MS-03 at `00:1f.3`.
pub const HDA_INTEL_PANTHER_LAKE_H_DEVICE: u16 = 0xE328;
/// Panther Lake HD Audio (`PCI_DEVICE_ID_INTEL_HDA_PTL`).
pub const HDA_INTEL_PANTHER_LAKE_DEVICE: u16 = 0xE428;

// ── Intel iGPU display-audio PCI device ids ───────────────────────
//
// On Intel platforms a second HDA-class controller lives on the
// graphics PCI function and carries HDMI / DisplayPort audio. The
// programming model is identical to the PCH HDA controller — same
// CORB/RIRB, same codec verbs — only the BAR layout and bus
// location differ. We register the same `probe` entry so both lines
// bind out of the same code path.

/// Tiger Lake-H iGPU HD Audio.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE: u16 = 0x4F90;
/// Tiger Lake-H iGPU HD Audio — variant B.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_B: u16 = 0x4F92;
/// Tiger Lake-LP iGPU HD Audio.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_C: u16 = 0x9A09;
/// Tiger Lake-LP iGPU HD Audio — variant.
pub const HDA_INTEL_TIGER_LAKE_GFX_DEVICE_D: u16 = 0x9A0C;

/// Every named HDA controller `(match name, vendor, device)`; each binds
/// the same vendor-agnostic probe.
pub const HDA_PCI_IDS: &[(&str, u16, u16)] = &[
    // AMD platform HD-Audio (the board codec) + Radeon HD Audio iGPU.
    ("hda-amd-zen", HDA_AMD_VENDOR, HDA_AMD_ZEN_DEVICE),
    ("hda-amd-x370", HDA_AMD_VENDOR, HDA_AMD_X370_DEVICE),
    ("hda-amd-x570", HDA_AMD_VENDOR, HDA_AMD_X570_DEVICE),
    (
        "hda-amd-radeon",
        HDA_AMD_RADEON_VENDOR,
        HDA_AMD_RADEON_DEVICE,
    ),
    // Intel legacy ICH HD Audio.
    (
        "hda-intel-ich6",
        HDA_INTEL_ICH6_VENDOR,
        HDA_INTEL_ICH6_DEVICE,
    ),
    (
        "hda-intel-ich7",
        HDA_INTEL_ICH7_VENDOR,
        HDA_INTEL_ICH7_DEVICE,
    ),
    (
        "hda-intel-ich9",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ICH9_DEVICE,
    ),
    // Intel PCH HDA (Skylake → Meteor Lake).
    (
        "hda-intel-sunrise-point-lp",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_SUNRISE_POINT_LP_DEVICE,
    ),
    (
        "hda-intel-sunrise-point-lp-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_SUNRISE_POINT_LP_DEVICE_B,
    ),
    (
        "hda-intel-cannon-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_CANNON_LAKE_DEVICE,
    ),
    (
        "hda-intel-comet-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_COMET_LAKE_DEVICE,
    ),
    (
        "hda-intel-comet-lake-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_COMET_LAKE_DEVICE_B,
    ),
    (
        "hda-intel-tiger-lake-lp",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_LP_DEVICE,
    ),
    (
        "hda-intel-tiger-lake-lp-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_LP_DEVICE_B,
    ),
    (
        "hda-intel-alder-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE,
    ),
    (
        "hda-intel-alder-lake-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE_B,
    ),
    (
        "hda-intel-alder-lake-c",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ALDER_LAKE_DEVICE_C,
    ),
    (
        "hda-intel-meteor-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_METEOR_LAKE_DEVICE,
    ),
    (
        "hda-intel-arrow-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ARROW_LAKE_DEVICE,
    ),
    (
        "hda-intel-arrow-lake-s",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_ARROW_LAKE_S_DEVICE,
    ),
    (
        "hda-intel-lunar-lake-p",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_LUNAR_LAKE_P_DEVICE,
    ),
    (
        "hda-intel-panther-lake-h",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_PANTHER_LAKE_H_DEVICE,
    ),
    (
        "hda-intel-panther-lake",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_PANTHER_LAKE_DEVICE,
    ),
    // Intel iGPU display-audio (TGL / TGL-LP graphics function).
    (
        "hda-intel-tgl-gfx",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE,
    ),
    (
        "hda-intel-tgl-gfx-b",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_B,
    ),
    (
        "hda-intel-tgl-gfx-c",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_C,
    ),
    (
        "hda-intel-tgl-gfx-d",
        HDA_INTEL_ICH9_VENDOR,
        HDA_INTEL_TIGER_LAKE_GFX_DEVICE_D,
    ),
];

/// The Renoir / Lucienne / Cezanne APU's display-audio function
/// (1002:1637). Unlike the Phoenix function (1002:1640, a named
/// `HDA_PCI_IDS` entry), Linux binds this one through the ATI HDMI
/// no-snoop preset, so it belongs in `HDA_ATI_HDMI_NS_DEVICES`: the
/// registration gets the bind and `ati_hdmi_noncoherent` gives the
/// probe the same explicit cache maintenance the other ATI HDMI
/// functions receive. Without the entry the APU's only HDA function
/// matched nothing and the target laptops had no HDA audio at all.
pub const HDA_AMD_RENOIR_HDMI_DEVICE: u16 = 0x1637;

/// ATI/AMD GPU HD-Audio functions Linux binds with
/// `AZX_DRIVER_ATIHDMI_NS | AZX_DCAPS_PRESET_ATI_HDMI_NS`
/// (sound/hda/controllers/intel.c): HDMI/DP audio beside a Radeon GPU, with
/// snooping off and LPIB positions. 0xab40 is the newest (RDNA4-era) entry.
pub const HDA_ATI_HDMI_NS_DEVICES: &[u16] = &[
    0x0002,
    0x1308,
    0x157a,
    0x15b3,
    HDA_AMD_RENOIR_HDMI_DEVICE,
    0x9840,
    0x9902,
    0xaaa0,
    0xaaa8,
    0xaab0,
    0xaac0,
    0xaac8,
    0xaad8,
    0xaae0,
    0xaae8,
    0xaaf0,
    0xaaf8,
    0xab00,
    0xab08,
    0xab10,
    0xab18,
    0xab20,
    0xab28,
    0xab30,
    0xab38,
    0xab40,
];
