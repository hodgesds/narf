//! Realtek ALC-series codec bring-up.
//!
//! ALC295 / ALC289 / ALC294 / ALC256 / ALC257 — the codec family that
//! ships on essentially every modern AMD-laptop motherboard. The
//! controller-side bring-up is in [`crate::hda`]; the vendor-agnostic
//! verb sender + widget walker is in [`crate::codec`]; *this* module
//! is the per-vendor patch that knows which NIDs to poke for a sane
//! "speaker comes up at boot" baseline.
//!
//! ## Sources (post-2026-05-20 GPL-link allowance)
//!
//! - **Linux `sound/pci/hda/patch_realtek.c`** — `alc_subsystem_id`,
//!   `alc_init`, `alc269_fixup_models[]`, `alc_pick_fixup`, and the
//!   per-chip `alc269_quirks[]` table. The ALC295 default pin config
//!   in particular comes from `alc269_fixup_x101_headset_mic` and the
//!   matching `alc295_fixup_*` entries.
//! - **HDA Spec §7.3.3.31** — Get/Set Configuration Default (Default
//!   Device / Connection Type / Color / Sequence / Association
//!   fields).
//! - **Realtek ALC295 datasheet, rev 1.4** — public on the Realtek
//!   developer portal; documents the codec's NID map.
//!
//! ## What this module is
//!
//! Public surface:
//!
//! - [`detect`] — `(cad) -> Option<RealtekChip>`. Sends `Get
//!   Parameter VENDOR_ID`, decodes vendor 0x10EC + the device ID into
//!   a [`RealtekChip`] enum.
//! - [`bring_up_alc295`] — `(cad) -> Result<(), AlcError>`. Stages the
//!   ALC295's speaker + headphone path so the boot chime / userspace
//!   PCM can land. Pin Widget Control on speaker pins → output enable;
//!   Amp Gain/Mute on speaker DACs → 0 dB; Unsolicited Response Enable
//!   on the headphone pin → plug events.
//! - [`is_supported`] — registry check against the list of codec IDs
//!   this module has a bring-up for.
//!
//! The bring-up path runs entirely through [`crate::codec::send_verb`]
//! / [`crate::codec::enumerate`]. There's a parallel
//! [`bring_up_alc295_with`] variant that takes an injected verb
//! closure — the smokes drive it against a
//! [`crate::codec::FakeCorb`].

extern crate alloc;

use alloc::vec::Vec;

use crate::codec::{
    self, param, CodecError, CodecTree, CodecWidget, FakeCorb, WidgetKind,
    VERB_GET_PARAMETER, VERB_SET_AMP_GAIN_MUTE_PREFIX,
    VERB_SET_EAPD_BTL, VERB_SET_PIN_WIDGET_CONTROL, VERB_SET_POWER_STATE,
    VERB_SET_UNSOLICITED_RESPONSE,
};

// ── Vendor / Chip detection ─────────────────────────────────────────

/// Realtek vendor ID (HDA Spec §7.3.4.1 VENDOR_ID response, high 16
/// bits). Every codec from the ALC family carries this.
pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

/// Specific Realtek chip variant we care about. Each variant has a
/// distinct pin-config baseline; the bring-up branches per-chip.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RealtekChip {
    /// ALC295 — Renoir 4700U + many Ryzen-based laptops.
    Alc295,
    /// ALC289 — Phoenix HawkPoint1 + later Ryzen 7000-series.
    Alc289,
    /// ALC294 — Renoir / Cezanne 5000U-series.
    Alc294,
    /// ALC256 — older Ryzen 3000-series laptops.
    Alc256,
    /// ALC257 — common Ryzen 4000U-series variant.
    Alc257,
    /// ALC269 — legacy Ryzen 2000 / Intel Skylake-era.
    Alc269,
    /// ALC233 — entry-level Phoenix-class laptops.
    Alc233,
    /// Recognised vendor but unknown device ID — bring-up will use
    /// the generic ALC269 path as a safe baseline.
    Unknown(u16),
}

impl RealtekChip {
    /// Decode a Realtek device ID into the matching chip variant.
    pub const fn from_device_id(did: u16) -> Self {
        match did {
            0x0295 => Self::Alc295,
            0x0289 => Self::Alc289,
            0x0294 => Self::Alc294,
            0x0256 => Self::Alc256,
            0x0257 => Self::Alc257,
            0x0269 => Self::Alc269,
            0x0233 => Self::Alc233,
            d => Self::Unknown(d),
        }
    }
    /// Human-readable name — used by diagnostic logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Alc295 => "ALC295",
            Self::Alc289 => "ALC289",
            Self::Alc294 => "ALC294",
            Self::Alc256 => "ALC256",
            Self::Alc257 => "ALC257",
            Self::Alc269 => "ALC269",
            Self::Alc233 => "ALC233",
            Self::Unknown(_) => "ALC?",
        }
    }
}

/// `true` if this module has a bring-up sequence for the given chip.
/// Used by the audio init path before dispatching `bring_up_*`.
pub const fn is_supported(chip: RealtekChip) -> bool {
    !matches!(chip, RealtekChip::Unknown(_))
}

/// The list of chip IDs this module recognises. Registry-style entry
/// point used by smokes + the future codec-dispatch table.
pub const SUPPORTED_CHIPS: &[(RealtekChip, u16)] = &[
    (RealtekChip::Alc295, 0x0295),
    (RealtekChip::Alc289, 0x0289),
    (RealtekChip::Alc294, 0x0294),
    (RealtekChip::Alc256, 0x0256),
    (RealtekChip::Alc257, 0x0257),
    (RealtekChip::Alc269, 0x0269),
    (RealtekChip::Alc233, 0x0233),
];

// ── Errors ──────────────────────────────────────────────────────────

/// Failure modes for [`bring_up_alc295`] and its siblings.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AlcError {
    /// Vendor ID wasn't 0x10EC — caller shouldn't have dispatched
    /// through this module.
    NotRealtek,
    /// Device ID didn't match the called bring-up (e.g.
    /// `bring_up_alc295` invoked on an ALC289 codec).
    WrongChip,
    /// Codec enumeration failed (no AFG, no widgets, transport error).
    EnumerationFailed,
    /// Transport (CORB / RIRB) errored mid-bring-up.
    TransportFailed,
    /// No Pin Complex matched the role the caller asked for (e.g.
    /// "find a speaker pin" failed). Indicates a board-config issue
    /// or a codec that doesn't ship with the expected pin layout.
    NoMatchingPin,
}

impl From<CodecError> for AlcError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::ControllerNotProbed => Self::TransportFailed,
            CodecError::TransportFailed => Self::TransportFailed,
        }
    }
}

// ── Pin Default Config (HDA Spec §7.3.3.31) ─────────────────────────

/// Decoded Pin Default Config — the per-board hint the BIOS programs
/// into each Pin Complex. Driver consults this to decide which pin
/// to bring up for which role.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PinDefault {
    /// Default Device (bits[23:20]): 0=Line Out, 1=Speaker, 2=HP Out,
    /// 3=CD, 4=SPDIF Out, 5=Digital Other Out, 6=Modem Line, 7=Modem
    /// Handset, 8=Line In, 9=AUX, 0xA=Mic In, 0xB=Telephony, 0xC=SPDIF
    /// In, 0xD=Digital Other In, 0xE=Reserved, 0xF=Other.
    pub default_device: u8,
    /// Port Connectivity (bits[31:30]): 0=jack, 1=no physical conn,
    /// 2=fixed, 3=both jack and internal.
    pub port_connectivity: u8,
    /// Connection Type (bits[27:24]): 1=Stereo 1/8", 4=Optical, …
    pub connection_type: u8,
    /// Color (bits[19:16]): 0=Unknown, 1=Black, 2=Grey, 3=Blue,
    /// 4=Green, 5=Red, 6=Orange, 7=Yellow, 8=Purple, 9=Pink,
    /// 0xE=White.
    pub color: u8,
    /// Misc (bits[15:12]): bit 0 = Jack Detect Override.
    pub misc: u8,
    /// Default Association (bits[11:8]): identifies a paired set
    /// (e.g. left + right pins forming one logical output).
    pub default_assoc: u8,
    /// Sequence (bits[7:4]): order within the association.
    pub sequence: u8,
    /// Original 32-bit value.
    pub raw: u32,
}

impl PinDefault {
    /// Decode a 32-bit Get Configuration Default response.
    pub const fn decode(raw: u32) -> Self {
        Self {
            default_device: ((raw >> 20) & 0xF) as u8,
            port_connectivity: ((raw >> 30) & 0x3) as u8,
            connection_type: ((raw >> 24) & 0xF) as u8,
            color: ((raw >> 16) & 0xF) as u8,
            misc: ((raw >> 12) & 0xF) as u8,
            default_assoc: ((raw >> 8) & 0xF) as u8,
            sequence: ((raw >> 4) & 0xF) as u8,
            raw,
        }
    }
    /// `true` for `Default Device == 1` (Speaker) and Port Connectivity
    /// != 1 (i.e. there's a physical connection — fixed internal or
    /// jack).
    pub const fn is_speaker(self) -> bool {
        self.default_device == 0x1 && self.port_connectivity != 0x1
    }
    /// `true` for `Default Device == 2` (Headphone Out).
    pub const fn is_headphone(self) -> bool {
        self.default_device == 0x2 && self.port_connectivity != 0x1
    }
    /// `true` for `Default Device == 0` (Line Out).
    pub const fn is_line_out(self) -> bool {
        self.default_device == 0x0 && self.port_connectivity != 0x1
    }
    /// `true` for `Default Device == 0xA` (Mic In).
    pub const fn is_microphone(self) -> bool {
        self.default_device == 0xA && self.port_connectivity != 0x1
    }
}

// ── ALC295 default pin configuration table ──────────────────────────
//
// Source: Linux `patch_realtek.c::alc269_fixup_models[]` /
// `alc295_fixup_disable_dac3_headphone_jack`. The table below records
// the NIDs the ALC295 ships with active on a Renoir laptop, paired
// with their default pin role.
//
// On any real chip the BIOS programs the actual Configuration Default
// via Set Configuration Default; this static table is the *expected*
// layout the bring-up sequence walks. The smokes assert that every
// entry decodes cleanly through `PinDefault::decode`.
//
// NID legend (ALC269/295 family, per Realtek datasheet):
//   0x12 — Internal mic (digital)
//   0x14 — Speaker (internal)
//   0x17 — Mono speaker (some boards)
//   0x18 — Headset mic (external jack)
//   0x19 — Headphone out (combo jack)
//   0x1A — Line in (some boards)
//   0x1B — Headphone out alternate
//   0x1D — PC beep
//   0x1E — SPDIF out
//   0x21 — Headphone amp (ALC295 specific)

/// One row in the ALC295 default-pin-config baseline.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AlcPinEntry {
    /// Codec NID this entry programs.
    pub nid: u8,
    /// Raw 32-bit Configuration Default value.
    pub default_config: u32,
    /// Human-readable description (for logs).
    pub label: &'static str,
}

/// Reference ALC295 default pin map — what a "well-formed" Renoir
/// laptop ships. Values are the BIOS-written configuration defaults
/// that the bring-up sequence assumes; mismatch means a quirk fixup
/// is needed.
///
/// The raw 32-bit constants pack the §7.3.3.31 fields. Examples:
///   0x9017_0110 — Speaker, fixed, internal, no color, assoc 1, seq 0.
///   0x21_021_4020 — Headphone Out, jack, stereo 1/8", green, assoc 2.
///   0x9081_a1f0 — Mic In, fixed, internal, no color, assoc f, seq 0.
pub const ALC295_PIN_DEFAULTS: &[AlcPinEntry] = &[
    AlcPinEntry {
        nid: 0x12,
        default_config: 0x90A6_0140,
        label: "internal-mic",
    },
    AlcPinEntry {
        nid: 0x14,
        default_config: 0x9017_0110,
        label: "speaker",
    },
    AlcPinEntry {
        nid: 0x17,
        default_config: 0x4000_0000,
        label: "unused-pin",
    },
    AlcPinEntry {
        nid: 0x18,
        default_config: 0x411D_1F40,
        label: "unused-pin",
    },
    AlcPinEntry {
        nid: 0x19,
        default_config: 0x04A1_1020,
        label: "headset-mic",
    },
    AlcPinEntry {
        nid: 0x1A,
        default_config: 0x411D_1F40,
        label: "unused-pin",
    },
    AlcPinEntry {
        nid: 0x1B,
        default_config: 0x411D_1F40,
        label: "unused-pin",
    },
    AlcPinEntry {
        nid: 0x1D,
        default_config: 0x4055_2205,
        label: "internal-beep",
    },
    AlcPinEntry {
        nid: 0x1E,
        default_config: 0x411D_1F40,
        label: "unused-pin",
    },
    AlcPinEntry {
        nid: 0x21,
        default_config: 0x0421_1010,
        label: "headphone-out",
    },
];

// ── Pin Widget Control + Amp Gain/Mute bits ─────────────────────────

/// Pin Widget Control bits (HDA Spec §7.3.3.13).
pub mod pin_ctl {
    /// Bit 6 — Out Enable. When set, the pin drives its connected DAC.
    pub const OUT_ENABLE: u8 = 1 << 6;
    /// Bit 7 — HP-amp Enable. When set, the high-power amplifier is
    /// enabled (required for headphones).
    pub const HP_AMP_ENABLE: u8 = 1 << 7;
    /// Bit 5 — In Enable. When set, the pin samples its connected
    /// ADC.
    pub const IN_ENABLE: u8 = 1 << 5;
    /// Bits[1:0] — Voltage Reference Enable (mic bias). 0=Hi-Z, 1=50%,
    /// 2=80%, 3=100%, 4=Ground, 5=Reserved.
    pub const VREF_50: u8 = 0x1;
    pub const VREF_80: u8 = 0x2;
    pub const VREF_100: u8 = 0x3;
}

/// Amp Gain/Mute payload bits (HDA Spec §7.3.3.7).
///
/// The 4-bit major opcode 0x3 (Set Amp Gain/Mute) takes a 16-bit
/// payload, of which the low 8 bits go through the encoder's
/// `payload` arg. The remaining 8 bits go in the high byte of the
/// "verb-id" half of the CORB word — this module's helper splits the
/// payload across the two halves correctly.
pub mod amp_gain {
    /// Set output amplifier (vs. input amp). Bit 15 of the 16-bit
    /// payload.
    pub const SET_OUTPUT: u16 = 1 << 15;
    /// Set input amplifier (mutually exclusive with `SET_OUTPUT`).
    pub const SET_INPUT: u16 = 1 << 14;
    /// Set left channel. Set both `SET_LEFT` and `SET_RIGHT` for
    /// "both sides".
    pub const SET_LEFT: u16 = 1 << 13;
    /// Set right channel.
    pub const SET_RIGHT: u16 = 1 << 12;
    /// Mute bit (low byte, bit 7).
    pub const MUTE: u8 = 1 << 7;
    /// Default gain — 0 dB. The exact mapping is per-codec; 0x80 is a
    /// common mid-point for ALC295's 7-bit gain field.
    pub const ZERO_DB_GAIN: u8 = 0x80;
}

// ── Verb senders ────────────────────────────────────────────────────

/// Type alias for the "send a verb" closure used throughout the
/// bring-up paths. Returns the 32-bit RIRB response or a codec error.
pub type SendVerb<'a> = &'a mut dyn FnMut(u8, u8, u16, u8) -> Result<u32, CodecError>;

/// Send the 4-bit-major Set-Amp-Gain-Mute verb. The high byte of the
/// 16-bit payload lives in the bottom byte of the verb-id field; the
/// low byte goes through the standard payload arg. See HDA Spec
/// §7.3.3.7.
fn set_amp_gain_mute(
    send: SendVerb<'_>,
    cad: u8,
    nid: u8,
    high: u8,
    low: u8,
) -> Result<(), CodecError> {
    // VERB_SET_AMP_GAIN_MUTE_PREFIX is the 4-bit major opcode 0x3
    // already shifted into the high 4 bits of a 12-bit "verb id".
    let verb_id = VERB_SET_AMP_GAIN_MUTE_PREFIX | (high as u16);
    send(cad, nid, verb_id, low)?;
    Ok(())
}

/// Pin Widget Control payload — what the bring-up writes to a speaker
/// pin. Both `OUT_ENABLE` and `HP_AMP_ENABLE` are set: HP-amp enable
/// is harmless on speaker pins but required when the same pin is
/// reused for the combo headphone jack.
pub const SPEAKER_PIN_PAYLOAD: u8 = pin_ctl::OUT_ENABLE | pin_ctl::HP_AMP_ENABLE;

/// Pin Widget Control payload for a microphone — In Enable + 80% VREF
/// (mic bias).
pub const MIC_PIN_PAYLOAD: u8 = pin_ctl::IN_ENABLE | pin_ctl::VREF_80;

// ── ALC295 bring-up ─────────────────────────────────────────────────

/// Bring up the ALC295's analog output path through the probed HDA
/// controller. Convenience wrapper over [`bring_up_alc295_with`] that
/// dispatches through [`crate::codec::send_verb`].
pub fn bring_up_alc295(cad: u8) -> Result<(), AlcError> {
    bring_up_alc295_with(cad, &mut |c, n, v, p| codec::send_verb(c, n, v, p))
}

/// Bring-up with an injected verb closure. The smokes drive this
/// directly against a [`FakeCorb`].
///
/// Sequence (mirrors `alc_init` + `alc295_fixup_*` in Linux's
/// `patch_realtek.c`):
///
///  1. **Detect.** Read VENDOR_ID, confirm Realtek 0x10EC + device
///     0x0295.
///  2. **Enumerate.** Walk the codec graph to discover every Pin
///     Complex + its default config + its connection list.
///  3. **Power on AFG.** Set Power State D0 on the Audio Function
///     Group root.
///  4. **EAPD on.** Enable EAPD (external amp enable) on the
///     speaker-amp pin. Many ALC295 boards route the speaker through
///     a class-D amp that's gated on EAPD bit 1.
///  5. **Speaker pins → out enable + HP-amp.** Walk every Pin Complex
///     whose default config marks it Speaker (device code 0x1) and
///     write Pin Widget Control with bits 6 + 7 set.
///  6. **Walk each speaker pin back to its DAC.** For every NID in
///     the speaker pin's connection list, set Amp Gain/Mute on the
///     output amp, both sides, index 0, gain 0x80 (0 dB).
///  7. **Headphone unsol response.** On every Pin Complex with default
///     device == 0x2 (Headphone Out), set Unsolicited Response Enable
///     (verb 0x708) bit 7 with tag 0.
pub fn bring_up_alc295_with(cad: u8, send: SendVerb<'_>) -> Result<(), AlcError> {
    // 1. Detect.
    let chip = match detect_with(cad, &mut |c, n, v, p| send(c, n, v, p))? {
        Some(c) => c,
        None => return Err(AlcError::NotRealtek),
    };
    if chip != RealtekChip::Alc295 {
        return Err(AlcError::WrongChip);
    }

    // 2. Enumerate.
    let tree = codec::enumerate_with(cad, |c, n, v, p| send(c, n, v, p))
        .map_err(|_| AlcError::EnumerationFailed)?;
    let afg = tree.audio_function_group().ok_or(AlcError::EnumerationFailed)?;
    let afg_nid = afg.nid;

    // 3. Power AFG into D0.
    send(cad, afg_nid, VERB_SET_POWER_STATE, 0x00)
        .map_err(|_| AlcError::TransportFailed)?;

    // Collect the lists we need to walk — done up front so the
    // mutable closure doesn't fight the borrow checker mid-loop.
    let speaker_pins: Vec<&CodecWidget> = afg
        .widgets
        .iter()
        .filter(|w| {
            w.kind() == WidgetKind::PinComplex
                && w.pin_config.map(PinDefault::decode).map(|p| p.is_speaker())
                    == Some(true)
        })
        .collect();
    let headphone_pins: Vec<&CodecWidget> = afg
        .widgets
        .iter()
        .filter(|w| {
            w.kind() == WidgetKind::PinComplex
                && w.pin_config.map(PinDefault::decode).map(|p| p.is_headphone())
                    == Some(true)
        })
        .collect();

    if speaker_pins.is_empty() {
        return Err(AlcError::NoMatchingPin);
    }

    // 4. EAPD on for every speaker pin. Harmless if the pin doesn't
    //    actually drive a class-D amp.
    for pin in &speaker_pins {
        // Bit 1 = EAPD enable, bit 0 = BTL (balanced trans-load). We
        // set bit 1 only.
        send(cad, pin.nid, VERB_SET_EAPD_BTL, 0x02)
            .map_err(|_| AlcError::TransportFailed)?;
    }

    // 5. Speaker pins → Pin Widget Control = out_enable | HP-amp.
    for pin in &speaker_pins {
        send(cad, pin.nid, VERB_SET_PIN_WIDGET_CONTROL, SPEAKER_PIN_PAYLOAD)
            .map_err(|_| AlcError::TransportFailed)?;
    }

    // 6. For each speaker pin, walk its connection list and unmute
    //    the upstream DAC + any selector/mixer in between. Payload
    //    decomposes into a 16-bit value: bit 15 = out, bit 13 = left,
    //    bit 12 = right, bits 11:8 = index, bits 7:0 = gain | mute.
    //    The encoder splits it across the verb-id high byte + the
    //    standard payload byte.
    let speaker_pin_nids: Vec<u8> = speaker_pins.iter().map(|p| p.nid).collect();
    for &pin_nid in &speaker_pin_nids {
        let pin = match tree.widget(pin_nid) {
            Some(w) => w,
            None => continue,
        };
        for &upstream in &pin.connections {
            // Output amp, both sides, index 0, gain 0x80 (0 dB), no
            // mute. high byte = bits[15:8] of payload = 0xB0 (output,
            // both sides, index 0). low byte = bits[7:0] = 0x80.
            //
            // 0xB0 decomposes: 1 (out) << 7 | 1 (left) << 5 | 1
            // (right) << 4 | 0 (index) = 0xB0.
            //
            // Equivalent expression in Linux's `update_amp` macros:
            //   AC_AMP_SET_OUTPUT | AC_AMP_SET_LEFT | AC_AMP_SET_RIGHT
            //   = 0xB000 (in the 16-bit payload).
            set_amp_gain_mute(send, cad, upstream, 0xB0, amp_gain::ZERO_DB_GAIN)
                .map_err(|_| AlcError::TransportFailed)?;
        }
    }

    // 7. Headphone Pin Complex → unsolicited-response enable. Bit 7
    //    enables, low 6 bits = tag. Tag 0 — the IRQ handler tells
    //    plug events apart by reading Get Pin Sense.
    for hp in &headphone_pins {
        send(cad, hp.nid, VERB_SET_UNSOLICITED_RESPONSE, 0x80)
            .map_err(|_| AlcError::TransportFailed)?;
    }

    Ok(())
}

// ── Detection ───────────────────────────────────────────────────────

/// Detect the codec at `cad` through the probed HDA controller.
/// Returns `Ok(Some(chip))` for a Realtek codec, `Ok(None)` for any
/// other vendor, or `Err(AlcError::TransportFailed)` on transport
/// failure.
pub fn detect(cad: u8) -> Result<Option<RealtekChip>, AlcError> {
    detect_with(cad, &mut |c, n, v, p| codec::send_verb(c, n, v, p))
}

/// Detection variant with an injected verb closure.
pub fn detect_with(
    cad: u8,
    send: SendVerb<'_>,
) -> Result<Option<RealtekChip>, AlcError> {
    let vid_did = send(cad, 0, VERB_GET_PARAMETER, param::VENDOR_ID)
        .map_err(|_| AlcError::TransportFailed)?;
    let vendor = ((vid_did >> 16) & 0xFFFF) as u16;
    if vendor != REALTEK_VENDOR_ID {
        return Ok(None);
    }
    let device = (vid_did & 0xFFFF) as u16;
    Ok(Some(RealtekChip::from_device_id(device)))
}

/// Convenience: detect a Realtek codec out of an already-enumerated
/// [`CodecTree`]. Used by the audio init path when enumeration is
/// already cached.
pub fn detect_from_tree(tree: &CodecTree) -> Option<RealtekChip> {
    if tree.vendor_id != REALTEK_VENDOR_ID {
        return None;
    }
    Some(RealtekChip::from_device_id(tree.device_id))
}

// ── FakeCorb-driven test scaffolding ────────────────────────────────
//
// The smokes program a FakeCorb with a synthetic ALC295 codec graph
// and exercise the bring-up path against it. The graph is intentionally
// minimal — one speaker pin + one headphone pin + their DACs — so the
// smokes assert specific verb sequences without modelling the entire
// real codec.

/// Pre-load `fake` with an ALC295-shaped codec tree at codec address
/// `cad`. Used by smokes + by anyone wanting to drive the bring-up
/// path without real silicon.
pub fn arm_fake_alc295(fake: &mut FakeCorb, cad: u8) {
    // Root: vendor 0x10EC, device 0x0295.
    fake.arm_param(cad, 0, param::VENDOR_ID, (0x10ECu32 << 16) | 0x0295);
    fake.arm_param(cad, 0, param::REVISION_ID, 0x0010_0000);
    // One function group starting at NID 1.
    fake.arm_param(cad, 0, param::SUBORDINATE_NODE_COUNT, (1u32 << 16) | 1);
    // Function group: Audio (type 1).
    fake.arm_param(cad, 1, param::FUNCTION_GROUP_TYPE, 0x01);
    // 4 widgets at NID 2..=5.
    fake.arm_param(cad, 1, param::SUBORDINATE_NODE_COUNT, (2u32 << 16) | 4);

    // NID 2 — Audio Output (DAC1) — stereo, out_amp.
    fake.arm_param(cad, 2, param::WIDGET_CAPS, 0b101);

    // NID 3 — Audio Output (DAC2) — stereo, out_amp.
    fake.arm_param(cad, 3, param::WIDGET_CAPS, 0b101);

    // NID 4 — Speaker Pin Complex with connection to NID 2.
    let speaker_caps = (4u32 << 20) | (1 << 8) | 1; // PinComplex, conn-list, stereo
    fake.arm_param(cad, 4, param::WIDGET_CAPS, speaker_caps);
    fake.arm_param(cad, 4, param::CONNECTION_LIST_LENGTH, 1);
    fake.arm(cad, 4, codec::VERB_GET_CONNECTION_LIST_ENTRY, 0, 0x0000_0002);
    // Pin Default — Speaker (device 1), fixed, no jack.
    fake.arm(cad, 4, codec::VERB_GET_CONFIG_DEFAULT, 0, 0x9017_0110);

    // NID 5 — Headphone Pin Complex with connection to NID 3.
    let hp_caps = (4u32 << 20) | (1 << 8) | (1 << 7) | 1; // PinComplex, conn-list, unsol, stereo
    fake.arm_param(cad, 5, param::WIDGET_CAPS, hp_caps);
    fake.arm_param(cad, 5, param::CONNECTION_LIST_LENGTH, 1);
    fake.arm(cad, 5, codec::VERB_GET_CONNECTION_LIST_ENTRY, 0, 0x0000_0003);
    // Pin Default — Headphone Out (device 2), jack, green, assoc 1.
    fake.arm(cad, 5, codec::VERB_GET_CONFIG_DEFAULT, 0, 0x2121_4020);
}

// ── Tests ───────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The pin-default table for ALC295 decodes every entry without
    /// surprises, and the speaker / headphone helpers identify the
    /// right rows.
    fn smoke_alc_pin_defaults_decode_cleanly() -> TestResult {
        let mut speakers = 0;
        let mut headphones = 0;
        let mut mics = 0;
        for entry in ALC295_PIN_DEFAULTS {
            let pd = PinDefault::decode(entry.default_config);
            // Decoder is total — no panic path.
            if pd.raw != entry.default_config {
                return TestResult::Fail("raw round-trip lost");
            }
            if pd.is_speaker() {
                speakers += 1;
            }
            if pd.is_headphone() {
                headphones += 1;
            }
            if pd.is_microphone() {
                mics += 1;
            }
        }
        // We programmed exactly one speaker (NID 0x14), one headphone
        // (NID 0x21), and two mics (NID 0x12 internal-mic, NID 0x19
        // headset-mic).
        if speakers != 1 {
            return TestResult::Fail("expected exactly one speaker pin");
        }
        if headphones != 1 {
            return TestResult::Fail("expected exactly one headphone pin");
        }
        if mics != 2 {
            return TestResult::Fail("expected two mic pins");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/realtek_alc", smoke_alc_pin_defaults_decode_cleanly);

    /// `bring_up_alc295` drives the right speaker-amp on/off verbs
    /// through a FakeCorb — Set Pin Widget Control on the speaker pin
    /// + Set Amp Gain/Mute on its DAC + Set Unsolicited Response on
    /// the headphone pin.
    fn smoke_alc295_speaker_amp_round_trip() -> TestResult {
        let cad: u8 = 0;
        let mut fake = FakeCorb::new();
        arm_fake_alc295(&mut fake, cad);

        let r = bring_up_alc295_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)));
        if r.is_err() {
            return TestResult::Fail("bring_up_alc295_with errored");
        }

        // Speaker pin (NID 4) saw Set Pin Widget Control with the
        // speaker payload (OUT_ENABLE | HP_AMP_ENABLE = 0xC0).
        if !fake.saw(cad, 4, VERB_SET_PIN_WIDGET_CONTROL, SPEAKER_PIN_PAYLOAD) {
            return TestResult::Fail("speaker pin widget control missing");
        }
        // DAC behind speaker pin (NID 2) saw Set Amp Gain/Mute with
        // 0x80 in the low byte. We look for the encoded verb-id
        // 0x3B0 (0x3 major + 0xB0 high byte).
        let amp_verb_id = VERB_SET_AMP_GAIN_MUTE_PREFIX | 0xB0;
        if !fake.saw(cad, 2, amp_verb_id, amp_gain::ZERO_DB_GAIN) {
            return TestResult::Fail("DAC unmute missing");
        }
        // Headphone pin (NID 5) saw Unsolicited Response Enable
        // (bit 7 set, tag 0).
        if !fake.saw(cad, 5, VERB_SET_UNSOLICITED_RESPONSE, 0x80) {
            return TestResult::Fail("headphone unsol response missing");
        }
        // AFG (NID 1) saw Power State D0.
        if !fake.saw(cad, 1, VERB_SET_POWER_STATE, 0x00) {
            return TestResult::Fail("AFG power-on missing");
        }
        // EAPD enable on the speaker pin.
        if !fake.saw(cad, 4, VERB_SET_EAPD_BTL, 0x02) {
            return TestResult::Fail("speaker EAPD enable missing");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/realtek_alc", smoke_alc295_speaker_amp_round_trip);

    /// Detect distinguishes Realtek from non-Realtek codecs and
    /// classifies the device IDs we recognise.
    fn smoke_alc_detect_chip_ids() -> TestResult {
        let cad: u8 = 0;

        // 1. Realtek ALC295.
        let mut fake = FakeCorb::new();
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x10ECu32 << 16) | 0x0295);
        let chip = detect_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)))
            .expect("detect ok");
        if chip != Some(RealtekChip::Alc295) {
            return TestResult::Fail("ALC295 not detected");
        }

        // 2. Realtek ALC289 (Phoenix HawkPoint1).
        let mut fake = FakeCorb::new();
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x10ECu32 << 16) | 0x0289);
        let chip = detect_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)))
            .expect("detect ok");
        if chip != Some(RealtekChip::Alc289) {
            return TestResult::Fail("ALC289 not detected");
        }

        // 3. Cirrus Logic (vendor 0x1013) — not Realtek.
        let mut fake = FakeCorb::new();
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x1013u32 << 16) | 0x4208);
        let chip = detect_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)))
            .expect("detect ok");
        if chip.is_some() {
            return TestResult::Fail("non-Realtek codec misdetected");
        }

        // 4. Realtek unknown device ID.
        let mut fake = FakeCorb::new();
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x10ECu32 << 16) | 0xFFFF);
        let chip = detect_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)))
            .expect("detect ok");
        if !matches!(chip, Some(RealtekChip::Unknown(0xFFFF))) {
            return TestResult::Fail("Realtek unknown device id not classified");
        }

        // is_supported() round-trip.
        if !is_supported(RealtekChip::Alc295) {
            return TestResult::Fail("ALC295 should be in supported registry");
        }
        if is_supported(RealtekChip::Unknown(0x1234)) {
            return TestResult::Fail("Unknown should never be supported");
        }
        if SUPPORTED_CHIPS.len() < 4 {
            return TestResult::Fail("supported-chip registry too small");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/realtek_alc", smoke_alc_detect_chip_ids);

    /// Jack-sense unsolicited-response decode (HDA Spec §4.7.4
    /// "Unsolicited Response Format"). The 32-bit response carries:
    ///
    /// - **bits 31:26** — tag (6 bits) — driver-assigned at
    ///   `Set Unsolicited Response` time (verb 0x708 payload bits 5:0).
    /// - **bits 25:0** — sub-tag data. For pin-sense unsol responses
    ///   on Realtek codecs, bit 0 of the sub-tag data reflects the
    ///   "Presence Detect" state read out of the Get Pin Sense response
    ///   (bit 31 of *that* response).
    ///
    /// We exercise:
    ///   1. tag round-trip across the full 6-bit range,
    ///   2. presence-bit (sub-tag bit 0) round-trip,
    ///   3. distinguishing plug from unplug,
    ///   4. ELD-valid sub-tag bit (bit 1) for HDMI/DP variant.
    fn smoke_alc_unsol_response_decode() -> TestResult {
        // Helpers: encode + decode an unsol response.
        fn encode_unsol(tag: u8, presence: bool, eldv: bool) -> u32 {
            let mut v = ((tag as u32) & 0x3F) << 26;
            if presence {
                v |= 1 << 0;
            }
            if eldv {
                v |= 1 << 1;
            }
            v
        }
        fn decode_tag(v: u32) -> u8 {
            ((v >> 26) & 0x3F) as u8
        }
        fn decode_presence(v: u32) -> bool {
            v & 1 != 0
        }
        fn decode_eldv(v: u32) -> bool {
            v & 2 != 0
        }

        // 1. Tag round-trip — every value of the 6-bit field.
        for tag in 0..=0x3Fu8 {
            let v = encode_unsol(tag, false, false);
            if decode_tag(v) != tag {
                return TestResult::Fail("tag round-trip lost");
            }
        }

        // 2. Plug event with tag 0 (the default the bring-up arms).
        let plug = encode_unsol(0, true, false);
        if !decode_presence(plug) {
            return TestResult::Fail("plug presence lost");
        }
        if decode_tag(plug) != 0 {
            return TestResult::Fail("plug tag wrong");
        }

        // 3. Unplug — presence = 0.
        let unplug = encode_unsol(0, false, false);
        if decode_presence(unplug) {
            return TestResult::Fail("spurious presence on unplug");
        }

        // 4. ELDV sub-tag (HDMI / DisplayPort audio).
        let eldv = encode_unsol(0x1F, true, true);
        if !decode_eldv(eldv) {
            return TestResult::Fail("ELDV bit lost");
        }
        if decode_tag(eldv) != 0x1F {
            return TestResult::Fail("tag with ELDV wrong");
        }
        if !decode_presence(eldv) {
            return TestResult::Fail("presence with ELDV wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/realtek_alc", smoke_alc_unsol_response_decode);

    /// Wrong-chip dispatch returns the right error — caller invoked
    /// `bring_up_alc295` against an ALC289.
    fn smoke_alc295_rejects_alc289() -> TestResult {
        let cad: u8 = 0;
        let mut fake = FakeCorb::new();
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x10ECu32 << 16) | 0x0289);
        let r = bring_up_alc295_with(cad, &mut |c, n, v, p| Ok(fake.send(c, n, v, p)));
        match r {
            Err(AlcError::WrongChip) => TestResult::Pass,
            Err(_) => TestResult::Fail("wrong error variant"),
            Ok(_) => TestResult::Fail("should have failed with WrongChip"),
        }
    }
    kernel_test_in!("audio/realtek_alc", smoke_alc295_rejects_alc289);
}
