//! Realtek codec fixup data — per-chip init coef tables and
//! per-laptop pin-override quirks.
//!
//! ## Provenance (#783 rescue)
//!
//! This module is the data rescued from the retired legacy audio
//! stack in `narf-drivers-sound` (`codec/quirks.rs` +
//! `codec/realtek.rs`), excised in #783. The legacy stack's
//! transport/walker code was deliberately *not* ported — the live
//! equivalents live in [`crate::hda_codec`] and this crate's
//! `hda::runtime` — but its tables are the only copies in the tree,
//! distilled from Linux `sound/pci/hda/patch_realtek.c`
//! (`alc269_fixup_models[]`, per-chip `alc*_init` sequences), and
//! they are an asset, not garbage.
//!
//! ## Status: staged data, not yet consumed
//!
//! The live HDA path ([`super::routing`]) currently routes from BIOS
//! pin defaults only and applies no vendor fixups — that is #776.
//! Nothing in the running system reads these tables yet; they are
//! preserved here, in the live crate that will consume them, so the
//! #776 lane wires fixups into `routing.rs` against data that
//! already has a home and a content test. The kernel tests under
//! `audio/hda-quirks` pin the table contents (counts + spot
//! entries) so an accidental edit of the data fails loudly.

// ── Chip identity ───────────────────────────────────────────────────

/// Realtek vendor ID (high half of the VENDOR_ID parameter response).
pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

/// Realtek ALC-family codec SKUs known to the fixup tables. The
/// discriminants are the codec device IDs (low half of VENDOR_ID).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RealtekChip {
    Alc233 = 0x0233,
    Alc235 = 0x0235,
    Alc236 = 0x0236,
    Alc255 = 0x0255,
    Alc256 = 0x0256,
    Alc257 = 0x0257,
    Alc270 = 0x0270,
    Alc280 = 0x0280,
    Alc282 = 0x0282,
    Alc283 = 0x0283,
    Alc285 = 0x0285,
    Alc286 = 0x0286,
    Alc287 = 0x0287,
    Alc289 = 0x0289,
    Alc290 = 0x0290,
    Alc292 = 0x0292,
    Alc293 = 0x0293,
    Alc294 = 0x0294,
    Alc295 = 0x0295,
    Alc298 = 0x0298,
    /// "ALC3204" / "ALC3225" / ... are vendor-rebrands of ALC families
    /// for OEM SKUs. They share the underlying core register map but
    /// carry a distinct PCI subsystem ID.
    Alc3204 = 0x3204,
    Alc3225 = 0x3225,
    Alc3236 = 0x3236,
    Alc3254 = 0x3254,
    Alc3266 = 0x3266,
    Alc3268 = 0x3268,
    Alc3286 = 0x3286,
    Alc3287 = 0x3287,
}

impl RealtekChip {
    /// Decode a 32-bit VENDOR_ID response. High 16 bits = vendor,
    /// low 16 bits = device. Returns None if the vendor isn't
    /// Realtek or the device ID isn't one of the SKUs we know.
    pub const fn from_vendor_id(v: u32) -> Option<RealtekChip> {
        let vendor = ((v >> 16) & 0xFFFF) as u16;
        let device = (v & 0xFFFF) as u16;
        if vendor != REALTEK_VENDOR_ID {
            return None;
        }
        match device {
            0x0233 => Some(RealtekChip::Alc233),
            0x0235 => Some(RealtekChip::Alc235),
            0x0236 => Some(RealtekChip::Alc236),
            0x0255 => Some(RealtekChip::Alc255),
            0x0256 => Some(RealtekChip::Alc256),
            0x0257 => Some(RealtekChip::Alc257),
            0x0270 => Some(RealtekChip::Alc270),
            0x0280 => Some(RealtekChip::Alc280),
            0x0282 => Some(RealtekChip::Alc282),
            0x0283 => Some(RealtekChip::Alc283),
            0x0285 => Some(RealtekChip::Alc285),
            0x0286 => Some(RealtekChip::Alc286),
            0x0287 => Some(RealtekChip::Alc287),
            0x0289 => Some(RealtekChip::Alc289),
            0x0290 => Some(RealtekChip::Alc290),
            0x0292 => Some(RealtekChip::Alc292),
            0x0293 => Some(RealtekChip::Alc293),
            0x0294 => Some(RealtekChip::Alc294),
            0x0295 => Some(RealtekChip::Alc295),
            0x0298 => Some(RealtekChip::Alc298),
            0x3204 => Some(RealtekChip::Alc3204),
            0x3225 => Some(RealtekChip::Alc3225),
            0x3236 => Some(RealtekChip::Alc3236),
            0x3254 => Some(RealtekChip::Alc3254),
            0x3266 => Some(RealtekChip::Alc3266),
            0x3268 => Some(RealtekChip::Alc3268),
            0x3286 => Some(RealtekChip::Alc3286),
            0x3287 => Some(RealtekChip::Alc3287),
            _ => None,
        }
    }

    /// Human-readable codec name, used by diagnostics and the
    /// `CardInfo::name` field at probe time.
    pub const fn name(self) -> &'static str {
        match self {
            RealtekChip::Alc233 => "ALC233",
            RealtekChip::Alc235 => "ALC235",
            RealtekChip::Alc236 => "ALC236",
            RealtekChip::Alc255 => "ALC255",
            RealtekChip::Alc256 => "ALC256",
            RealtekChip::Alc257 => "ALC257",
            RealtekChip::Alc270 => "ALC270",
            RealtekChip::Alc280 => "ALC280",
            RealtekChip::Alc282 => "ALC282",
            RealtekChip::Alc283 => "ALC283",
            RealtekChip::Alc285 => "ALC285",
            RealtekChip::Alc286 => "ALC286",
            RealtekChip::Alc287 => "ALC287",
            RealtekChip::Alc289 => "ALC289",
            RealtekChip::Alc290 => "ALC290",
            RealtekChip::Alc292 => "ALC292",
            RealtekChip::Alc293 => "ALC293",
            RealtekChip::Alc294 => "ALC294",
            RealtekChip::Alc295 => "ALC295",
            RealtekChip::Alc298 => "ALC298",
            RealtekChip::Alc3204 => "ALC3204",
            RealtekChip::Alc3225 => "ALC3225",
            RealtekChip::Alc3236 => "ALC3236",
            RealtekChip::Alc3254 => "ALC3254",
            RealtekChip::Alc3266 => "ALC3266",
            RealtekChip::Alc3268 => "ALC3268",
            RealtekChip::Alc3286 => "ALC3286",
            RealtekChip::Alc3287 => "ALC3287",
        }
    }
}

// ── Per-chip init coef tables ───────────────────────────────────────
//
// Realtek codecs expose an internal Processing Coefficient table
// that is the entire chip configuration surface, written through
// VERB_SET_COEF_INDEX (0x500) + VERB_SET_PROC_COEF (0x400). Most
// Realtek init sequences are an `(idx, value)` table. These are
// the universal "speaker comes up at boot" baselines; they are NOT
// the full per-OEM fixup tables — those are the pin quirks below,
// picked by codec subsystem ID. Without these baseline pokes, the
// chip won't produce sound even with a correctly-routed graph.

/// One (index, value) row in a Realtek init table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CoefRow {
    pub idx: u16,
    pub value: u16,
}

impl CoefRow {
    pub const fn new(idx: u16, value: u16) -> Self {
        CoefRow { idx, value }
    }
}

/// Pin Widget Control — "Output Enable" (HDA §7.3.3.13, bit 6).
pub const PIN_WIDGET_OUT: u8 = 0x40;
/// "Headphone Enable" (HDA §7.3.3.13, bit 7).
pub const PIN_WIDGET_HP: u8 = 0x80;
/// Both — common for headphone-jack pins that also drive the speaker.
pub const PIN_WIDGET_OUT_HP: u8 = 0xC0;
/// "Input Enable" (HDA §7.3.3.13, bit 5).
pub const PIN_WIDGET_IN: u8 = 0x20;

/// EAPD = External Amplifier Power Down. Setting bit 1 of the
/// EAPD/BTL verb (0x70C) powers the external speaker amp.
pub const EAPD_ENABLE: u8 = 0x02;
/// Setting bit 0 of EAPD/BTL puts the codec amp into BTL (bridge-tied
/// load) mode — used by some laptop speakers.
pub const BTL_ENABLE: u8 = 0x01;

/// ALC256 init verb sequence (Linux `alc269.c::alc256_init` distilled).
pub const ALC256_INIT: &[CoefRow] = &[
    // PC-Beep noise gate workaround: expose headphone mic on NID 0x1A
    // instead of PC Beep, and disable 1Ah loopback. Linux:
    // alc_write_coef_idx(codec, 0x36, 0x5757)
    CoefRow::new(0x36, 0x5757),
    // Clear high-power "ultra-low-power" bit.
    CoefRow::new(0x46, 0x0000),
];

/// ALC255 init — virtually identical to ALC256.
pub const ALC255_INIT: &[CoefRow] = ALC256_INIT;

/// ALC233 init (Linux `alc269.c::alc233_init`).
pub const ALC233_INIT: &[CoefRow] = &[
    CoefRow::new(0x35, 0x0000), // clear class-D digital pattern
];

/// ALC235 init — same shape as ALC233.
pub const ALC235_INIT: &[CoefRow] = &[CoefRow::new(0x36, 0x5757)];

/// ALC236 init — same shape as ALC235 with one extra POP-noise fix.
pub const ALC236_INIT: &[CoefRow] = &[
    CoefRow::new(0x36, 0x5757),
    CoefRow::new(0x1B, 0x0c0b), // pop-noise reduction.
];

/// ALC270 init.
pub const ALC270_INIT: &[CoefRow] = &[CoefRow::new(0x14, 0x0080)];

/// ALC280 init.
pub const ALC280_INIT: &[CoefRow] = &[CoefRow::new(0x35, 0x1080)];

/// ALC282 init (Linux `alc269.c::alc282_init`).
pub const ALC282_INIT: &[CoefRow] = &[CoefRow::new(0x35, 0x0000), CoefRow::new(0x36, 0x0000)];

/// ALC283 init.
pub const ALC283_INIT: &[CoefRow] = &[CoefRow::new(0x1A, 0x2c11), CoefRow::new(0x06, 0x2104)];

/// ALC285 init (Linux `alc269.c::alc285_init`).
pub const ALC285_INIT: &[CoefRow] = &[
    // Enable the standard speaker path (typical HP / Lenovo bring-up).
    CoefRow::new(0x36, 0x5757),
    // Bottom-end speaker boost.
    CoefRow::new(0x6F, 0x0007),
];

/// ALC286 init.
pub const ALC286_INIT: &[CoefRow] = &[CoefRow::new(0x10, 0xFA34), CoefRow::new(0x11, 0x6810)];

/// ALC287 init — same baseline as ALC285 with one HP-amp-fix bit.
pub const ALC287_INIT: &[CoefRow] = &[
    CoefRow::new(0x36, 0x5757),
    CoefRow::new(0x6F, 0x0007),
    CoefRow::new(0x38, 0x4901), // HP amp routing.
];

/// ALC289 init.
pub const ALC289_INIT: &[CoefRow] = &[CoefRow::new(0x36, 0x5757)];

/// ALC290 init.
pub const ALC290_INIT: &[CoefRow] = &[CoefRow::new(0x10, 0x0E40)];

/// ALC292 init.
pub const ALC292_INIT: &[CoefRow] = &[CoefRow::new(0x6, 0x2104)];

/// ALC293 init.
pub const ALC293_INIT: &[CoefRow] = &[CoefRow::new(0x35, 0x0000)];

/// ALC294 init.
pub const ALC294_INIT: &[CoefRow] = &[
    CoefRow::new(0x36, 0x5757),
    CoefRow::new(0x67, 0x4060), // speaker amp gain.
];

/// ALC295 init (Linux `alc269.c::alc295_init`).
pub const ALC295_INIT: &[CoefRow] = &[
    CoefRow::new(0x36, 0x5757),
    // Speaker boost (Linux Asus / HP fixup).
    CoefRow::new(0x4A, 0xA050),
];

/// ALC298 init.
pub const ALC298_INIT: &[CoefRow] = &[CoefRow::new(0x36, 0x5757), CoefRow::new(0x6F, 0x0007)];

// "ALC32xx" rebrands share their core silicon with one of the above —
// reuse the matching base table.
pub const ALC3204_INIT: &[CoefRow] = ALC287_INIT;
pub const ALC3225_INIT: &[CoefRow] = ALC295_INIT;
pub const ALC3236_INIT: &[CoefRow] = ALC236_INIT;
pub const ALC3254_INIT: &[CoefRow] = ALC287_INIT;
pub const ALC3266_INIT: &[CoefRow] = ALC256_INIT;
pub const ALC3268_INIT: &[CoefRow] = ALC256_INIT;
pub const ALC3286_INIT: &[CoefRow] = ALC287_INIT;
pub const ALC3287_INIT: &[CoefRow] = ALC287_INIT;

/// Pick the init table for a known chip.
pub fn init_table_for(chip: RealtekChip) -> &'static [CoefRow] {
    match chip {
        RealtekChip::Alc233 => ALC233_INIT,
        RealtekChip::Alc235 => ALC235_INIT,
        RealtekChip::Alc236 => ALC236_INIT,
        RealtekChip::Alc255 => ALC255_INIT,
        RealtekChip::Alc256 => ALC256_INIT,
        RealtekChip::Alc257 => ALC256_INIT,
        RealtekChip::Alc270 => ALC270_INIT,
        RealtekChip::Alc280 => ALC280_INIT,
        RealtekChip::Alc282 => ALC282_INIT,
        RealtekChip::Alc283 => ALC283_INIT,
        RealtekChip::Alc285 => ALC285_INIT,
        RealtekChip::Alc286 => ALC286_INIT,
        RealtekChip::Alc287 => ALC287_INIT,
        RealtekChip::Alc289 => ALC289_INIT,
        RealtekChip::Alc290 => ALC290_INIT,
        RealtekChip::Alc292 => ALC292_INIT,
        RealtekChip::Alc293 => ALC293_INIT,
        RealtekChip::Alc294 => ALC294_INIT,
        RealtekChip::Alc295 => ALC295_INIT,
        RealtekChip::Alc298 => ALC298_INIT,
        RealtekChip::Alc3204 => ALC3204_INIT,
        RealtekChip::Alc3225 => ALC3225_INIT,
        RealtekChip::Alc3236 => ALC3236_INIT,
        RealtekChip::Alc3254 => ALC3254_INIT,
        RealtekChip::Alc3266 => ALC3266_INIT,
        RealtekChip::Alc3268 => ALC3268_INIT,
        RealtekChip::Alc3286 => ALC3286_INIT,
        RealtekChip::Alc3287 => ALC3287_INIT,
    }
}

// ── Per-laptop pin-override quirks ──────────────────────────────────
//
// HDA codecs ship with a vendor-default pin / connection layout that
// is correct on the chip's reference board. Every laptop OEM
// re-routes pins to fit their physical jack layout, but the codec's
// Get-Config-Default response is the OEM's value — so a stock
// `alc_init` only produces sound on the literal Realtek reference
// board. Linux solves this with a giant `alc269_fixup_models[]`
// table; we ship a smaller distilled version for the codecs +
// laptop families the user actually runs.
//
// Each entry is `(codec_subsystem_id, override_table)`. The
// `subsystem_id` comes from `VERB_GET_SUBSYSTEM_ID` (codec response,
// formatted as `subvendor << 16 | subdevice`); a match swaps in a
// per-laptop override of the chip's pin defaults.

/// One pin override — `(nid, config_default)`. We re-issue the pin's
/// SET_CONFIG_DEFAULT_* verb chain with this value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PinOverride {
    pub nid: u8,
    pub cfg: u32,
}

/// One quirk entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Quirk {
    /// Codec subsystem ID = `(subvendor << 16) | subdevice`.
    pub subsystem_id: u32,
    /// Matching codec.
    pub chip: RealtekChip,
    /// Pin overrides to apply.
    pub pins: &'static [PinOverride],
    /// Friendly identifier (e.g. `"Lenovo X1 Carbon Gen 7"`).
    pub name: &'static str,
}

// ── Lenovo ThinkPad bring-up tables ─────────────────────────────────
//
// Source: Linux `alc269_fixup_models[]` entries
// ALC285_FIXUP_THINKPAD_X1_GEN7,
// ALC285_FIXUP_LENOVO_HEADPHONE_NOISE,
// ALC287_FIXUP_LENOVO_THINKPAD_T14_GEN3.

pub const QUIRK_X1_CARBON_GEN7: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    }, // speaker @ "Internal mid"
    PinOverride {
        nid: 0x17,
        cfg: 0x90170150,
    }, // boost amp speaker
    PinOverride {
        nid: 0x19,
        cfg: 0x03A11030,
    }, // mic @ jack
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    }, // headphone @ jack
];

pub const QUIRK_THINKPAD_T14_GEN3: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x17,
        cfg: 0x90170150,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x04A11040,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x04211020,
    },
];

// ── HP EliteBook / Pavilion bring-up tables ─────────────────────────

pub const QUIRK_HP_ELITEBOOK_845_G8: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x03a11020,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211030,
    },
];

// ── Dell Latitude / XPS bring-up tables ─────────────────────────────

pub const QUIRK_DELL_LATITUDE_5430: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x90a60140,
    }, // internal mic.
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── ASUS ROG / Zephyrus bring-up tables ─────────────────────────────

pub const QUIRK_ASUS_ROG: &[PinOverride] = &[
    PinOverride {
        nid: 0x12,
        cfg: 0x90A60130,
    },
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x17,
        cfg: 0x90170120,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── MSI bring-up tables ─────────────────────────────────────────────

pub const QUIRK_MSI: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x03A11040,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── Quirk table ─────────────────────────────────────────────────────

/// Static quirk table. Indexed by subsystem ID through `find_quirk`.
pub const QUIRK_TABLE: &[Quirk] = &[
    Quirk {
        subsystem_id: 0x17AA_22BE, // Lenovo X1 Carbon Gen 7
        chip: RealtekChip::Alc285,
        pins: QUIRK_X1_CARBON_GEN7,
        name: "Lenovo ThinkPad X1 Carbon Gen 7",
    },
    Quirk {
        subsystem_id: 0x17AA_22F0,
        chip: RealtekChip::Alc287,
        pins: QUIRK_THINKPAD_T14_GEN3,
        name: "Lenovo ThinkPad T14 Gen 3",
    },
    Quirk {
        subsystem_id: 0x103C_8716, // HP EliteBook 845 G8 (AMD Renoir)
        chip: RealtekChip::Alc285,
        pins: QUIRK_HP_ELITEBOOK_845_G8,
        name: "HP EliteBook 845 G8",
    },
    Quirk {
        subsystem_id: 0x1028_0AB9, // Dell Latitude 5430
        chip: RealtekChip::Alc256,
        pins: QUIRK_DELL_LATITUDE_5430,
        name: "Dell Latitude 5430",
    },
    Quirk {
        subsystem_id: 0x1043_1A30, // ASUS ROG Strix
        chip: RealtekChip::Alc295,
        pins: QUIRK_ASUS_ROG,
        name: "ASUS ROG Strix",
    },
    Quirk {
        subsystem_id: 0x1462_1234, // MSI generic
        chip: RealtekChip::Alc256,
        pins: QUIRK_MSI,
        name: "MSI laptop",
    },
];

/// Look up a quirk by codec subsystem ID. Returns the first matching
/// entry — the table is short enough that a linear scan is fine.
pub fn find_quirk(subsystem_id: u32) -> Option<&'static Quirk> {
    QUIRK_TABLE.iter().find(|q| q.subsystem_id == subsystem_id)
}

/// Find a quirk for a known chip ignoring subsystem ID. Used by the
/// bring-up path as a fallback when no exact match exists.
pub fn first_for_chip(chip: RealtekChip) -> Option<&'static Quirk> {
    QUIRK_TABLE.iter().find(|q| q.chip == chip)
}

/// Number of registered quirks.
pub const fn quirk_count() -> usize {
    QUIRK_TABLE.len()
}
