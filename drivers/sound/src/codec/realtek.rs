//! Realtek ALC-family codec bring-up.
//!
//! Tables for ALC233 / ALC235 / ALC236 / ALC255 / ALC256 / ALC270 /
//! ALC280 / ALC282 / ALC283 / ALC285 / ALC286 / ALC287 / ALC289 /
//! ALC290 / ALC292 / ALC293 / ALC294 / ALC295 / ALC298 / ALC3204 /
//! ALC3225 / ALC3236 / ALC3254 / ALC3266 / ALC3268 / ALC3286 /
//! ALC3287 — the codec family that ships on essentially every modern
//! AMD and Intel laptop motherboard.
//!
//! ## Sources
//!
//! - Linux `sound/hda/codecs/realtek/realtek.c` + per-`alc<N>.c` files
//!   (post-2026-05-20 GPL-link allowance). Each chip's init verb
//!   sequence is the distilled form of its `alc<N>_init` /
//!   `alc<N>_shutup` plus the "standard" fixups every laptop OEM
//!   applies (HP, Dell, Lenovo).
//! - Realtek ALC* datasheets — vendor-specific COEF index map (the
//!   set of `(idx, value)` pokes that the chip needs at boot before
//!   any analog output is audible).
//! - HDA Spec §7.3.3 — verb opcodes the COEF pokes layer on top of.

use alloc::vec::Vec;

use crate::codec::generic::{
    encode_verb, set_amp_gain_mute_verb, AmpGainMute, CodecVerbBus, VerbError, PARAM_VENDOR_ID,
    VERB_GET_PARAMETER, VERB_SET_EAPD_BTL, VERB_SET_PIN_WIDGET_CONTROL, VERB_SET_POWER_STATE,
    VERB_SET_UNSOLICITED_RESPONSE,
};

/// Realtek vendor ID (HDA `VENDOR_ID` response high 16 bits).
pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

/// Concrete ALC chip variants this module knows how to bring up.
/// One enum entry per ALC* SKU; the discriminant value matches the
/// low 16 bits of the Realtek `VENDOR_ID` parameter.
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

// ── COEF helpers ────────────────────────────────────────────────────
//
// Realtek codecs expose an internal Processing Coefficient table that
// is the entire chip configuration surface. The HDA spec exposes the
// table through two verbs:
//   - VERB_SET_COEF_INDEX (0x500) — write the 16-bit index register.
//   - VERB_SET_PROC_COEF  (0x400) — write the 16-bit data register.
//
// Most Realtek init sequences are an `(idx, value)` table that this
// helper walks. Some entries are `(coef_addr, idx, value)` triples
// for the "extended" COEF range — those land via the GET_COEF_INDEX
// alias 0xD00 + an extra byte, but we don't need that for the
// universal bring-up tables here.

/// Write a COEF register: drive SET_COEF_INDEX, then SET_PROC_COEF.
pub fn write_coef(
    bus: &mut dyn CodecVerbBus,
    cad: u8,
    nid: u8,
    idx: u16,
    value: u16,
) -> Result<(), VerbError> {
    // SET_COEF_INDEX is a 4-byte verb whose payload is the low byte
    // of the COEF index. The high byte rides in the verb_id low
    // nibble per HDA §7.3.3.13.
    let coef_idx_verb_id = (0x5 << 8) | ((idx >> 8) & 0xFF);
    bus.send_verb(encode_verb(cad, nid, coef_idx_verb_id, (idx & 0xFF) as u8))?;
    let coef_data_verb_id = (0x4 << 8) | ((value >> 8) & 0xFF);
    bus.send_verb(encode_verb(
        cad,
        nid,
        coef_data_verb_id,
        (value & 0xFF) as u8,
    ))?;
    Ok(())
}

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

/// Apply a sequence of COEF writes against the codec's AFG node.
pub fn apply_coef_table(
    bus: &mut dyn CodecVerbBus,
    cad: u8,
    afg_nid: u8,
    rows: &[CoefRow],
) -> Result<(), VerbError> {
    for row in rows {
        write_coef(bus, cad, afg_nid, row.idx, row.value)?;
    }
    Ok(())
}

// ── Default pin widget control values ───────────────────────────────

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

// ── Per-chip init sequences ─────────────────────────────────────────
//
// These are the universal "speaker comes up at boot" baselines.
// They are NOT the full per-OEM fixup tables — those live in
// `quirks` and are picked by PCI subsystem ID. Without these baseline
// pokes, the chip won't produce sound even with a correctly-routed
// graph.

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

/// Apply the per-chip init table plus the universal "speaker comes up"
/// path: full power → unmute → drive pin to OUT → enable EAPD on
/// speaker pins.
///
/// `dac_nid` / `speaker_pin_nid` / `headphone_pin_nid` come from the
/// graph walker; on a fresh codec they are typically `0x02`, `0x14`,
/// and `0x21` respectively (the same NIDs Linux's
/// `auto_parse_config` discovers for ALC256/285/295/298).
pub fn bring_up(
    bus: &mut dyn CodecVerbBus,
    cad: u8,
    afg_nid: u8,
    chip: RealtekChip,
    dac_nid: u8,
    speaker_pin_nid: u8,
    headphone_pin_nid: u8,
) -> Result<(), VerbError> {
    // 1) Vendor-specific COEF table.
    apply_coef_table(bus, cad, afg_nid, init_table_for(chip))?;
    // 2) Power-state D0 on AFG, DAC, both pins.
    for nid in [afg_nid, dac_nid, speaker_pin_nid, headphone_pin_nid] {
        bus.send_verb(encode_verb(cad, nid, VERB_SET_POWER_STATE, 0x00))?;
    }
    // 3) Unmute the DAC output amp.
    let unmute = set_amp_gain_mute_verb(
        cad,
        dac_nid,
        AmpGainMute {
            set_output: true,
            set_input: false,
            left: true,
            right: true,
            index: 0,
            mute: false,
            gain: 0,
        },
    );
    bus.send_verb(unmute)?;
    // 4) Drive speaker pin OUT enabled.
    bus.send_verb(encode_verb(
        cad,
        speaker_pin_nid,
        VERB_SET_PIN_WIDGET_CONTROL,
        PIN_WIDGET_OUT,
    ))?;
    // 5) Drive headphone pin OUT + HP enabled (so jack-detect mux
    //    routes correctly when nothing's plugged in).
    bus.send_verb(encode_verb(
        cad,
        headphone_pin_nid,
        VERB_SET_PIN_WIDGET_CONTROL,
        PIN_WIDGET_OUT_HP,
    ))?;
    // 6) Enable EAPD on the speaker pin so the external amp powers up.
    bus.send_verb(encode_verb(
        cad,
        speaker_pin_nid,
        VERB_SET_EAPD_BTL,
        EAPD_ENABLE,
    ))?;
    // 7) Enable unsolicited-response on the headphone pin so a jack
    //    plug event arrives via the RIRB unsolicited path.
    bus.send_verb(encode_verb(
        cad,
        headphone_pin_nid,
        VERB_SET_UNSOLICITED_RESPONSE,
        /*enable=*/ 0x80 | /*tag=*/ 0x01,
    ))?;
    Ok(())
}

/// Vendor-ID detection — read VENDOR_ID (Get Parameter 0x00) and
/// match against the known SKU table.
pub fn detect(bus: &mut dyn CodecVerbBus, cad: u8) -> Result<Option<RealtekChip>, VerbError> {
    // Root NID is always 0x00 for the Get-Parameter VENDOR_ID query.
    let v = bus.send_verb(encode_verb(cad, 0x00, VERB_GET_PARAMETER, PARAM_VENDOR_ID))?;
    Ok(RealtekChip::from_vendor_id(v))
}

/// EAPD verb encoder used by tests.
pub const fn eapd_verb(cad: u8, pin_nid: u8, enable: bool) -> u32 {
    encode_verb(
        cad,
        pin_nid,
        VERB_SET_EAPD_BTL,
        if enable { EAPD_ENABLE } else { 0 },
    )
}

// ── Test-only FakeCorb ──────────────────────────────────────────────

/// Records every verb sent — round-trip tests rebind the bus to this
/// and read out the verb history.
#[derive(Debug, Default)]
pub struct VerbRecorder {
    pub history: Vec<u32>,
    /// Static responses returned by `send_verb`. Indexed by verb-history
    /// position; missing entries default to 0.
    pub responses: Vec<u32>,
}

impl VerbRecorder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_response(&mut self, at: usize, value: u32) {
        if self.responses.len() <= at {
            self.responses.resize(at + 1, 0);
        }
        self.responses[at] = value;
    }
    pub fn with_initial_responses(responses: Vec<u32>) -> Self {
        VerbRecorder {
            history: Vec::new(),
            responses,
        }
    }
}

impl CodecVerbBus for VerbRecorder {
    fn send_verb(&mut self, verb: u32) -> Result<u32, VerbError> {
        let idx = self.history.len();
        self.history.push(verb);
        Ok(self.responses.get(idx).copied().unwrap_or(0))
    }
}
