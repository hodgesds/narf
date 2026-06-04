//! Per-laptop-model widget connection quirks.
//!
//! HDA codecs ship with a vendor-default pin / connection layout that
//! is correct on the chip's reference board. Every laptop OEM
//! re-routes pins to fit their physical jack layout, but the codec's
//! Get-Config-Default response is the OEM's value — so a stock
//! `alc_init` only produces sound on the literal Realtek reference
//! board. Linux solves this with a giant `alc269_fixup_models[]`
//! table; we ship a smaller distilled version for the codecs +
//! laptop families the user actually runs.
//!
//! Each entry is `(codec_subsystem_id, override_table)`. The
//! `subsystem_id` comes from `VERB_GET_SUBSYSTEM_ID` (codec response,
//! formatted as `subvendor << 16 | subdevice`); a match swaps in a
//! per-laptop override of the chip's pin defaults.

use crate::codec::realtek::RealtekChip;

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
