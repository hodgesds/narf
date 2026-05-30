//! Vendor-agnostic codec layer.
//!
//! Knows how to:
//! - Pack 32-bit CORB verbs (HDA §7.3.1).
//! - Issue Get-Parameter / Get-Connection-List / Get-Pin-Cfg.
//! - Walk the AFG subnode tree and classify widgets by kind.
//! - Run the minimum bring-up that gives an output path a chance to
//!   produce sound on any AFG-compliant codec (power → unmute →
//!   pin-widget-control out).
//!
//! Per-vendor patch modules (`crate::codec::realtek`) layer on top.
//!
//! Linux references:
//! - `sound/hda/core/regmap.c` — verb encoding helpers.
//! - `sound/hda/codecs/generic.c::generic_init` — default bring-up.
//! - `sound/hda/codecs/generic.c::snd_hda_gen_parse_auto_config` —
//!   widget enumeration.

use alloc::vec::Vec;

// ── Verb opcodes (HDA §7.3.3) ───────────────────────────────────────

pub const VERB_GET_PARAMETER: u16 = 0xF00;
pub const VERB_GET_CONNECTION_SELECT: u16 = 0xF01;
pub const VERB_GET_CONNECTION_LIST: u16 = 0xF02;
pub const VERB_GET_PROC_STATE: u16 = 0xF03;
pub const VERB_GET_AMP_GAIN_MUTE: u16 = 0xB00;
pub const VERB_GET_PIN_WIDGET_CONTROL: u16 = 0xF07;
pub const VERB_GET_UNSOLICITED_RESPONSE: u16 = 0xF08;
pub const VERB_GET_PIN_SENSE: u16 = 0xF09;
pub const VERB_GET_EAPD_BTL: u16 = 0xF0C;
pub const VERB_GET_GPIO_DATA: u16 = 0xF15;
pub const VERB_GET_CONFIG_DEFAULT: u16 = 0xF1C;
pub const VERB_GET_VENDOR_ID: u16 = 0xF00; // alias of Get-Parameter w/ PARAM_VENDOR_ID
pub const VERB_GET_POWER_STATE: u16 = 0xF05;

pub const VERB_SET_CONVERTER_FORMAT: u16 = 0x200;
pub const VERB_SET_AMP_GAIN_MUTE: u16 = 0x300;
pub const VERB_SET_PROC_COEF: u16 = 0x400;
pub const VERB_SET_COEF_INDEX: u16 = 0x500;
pub const VERB_SET_POWER_STATE: u16 = 0x705;
pub const VERB_SET_CONVERTER_STREAM_CHANNEL: u16 = 0x706;
pub const VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x707;
pub const VERB_SET_UNSOLICITED_RESPONSE: u16 = 0x708;
pub const VERB_SET_PIN_SENSE: u16 = 0x709;
pub const VERB_SET_EAPD_BTL: u16 = 0x70C;
pub const VERB_SET_GPIO_DATA: u16 = 0x715;
pub const VERB_SET_RESET: u16 = 0x7FF;

// ── Get-Parameter parameter IDs (HDA §7.3.4) ────────────────────────

pub const PARAM_VENDOR_ID: u8 = 0x00;
pub const PARAM_REVISION_ID: u8 = 0x02;
pub const PARAM_SUB_NODE_COUNT: u8 = 0x04;
pub const PARAM_FUNCTION_GROUP: u8 = 0x05;
pub const PARAM_AUDIO_GROUP_CAPS: u8 = 0x08;
pub const PARAM_AUDIO_WIDGET_CAPS: u8 = 0x09;
pub const PARAM_SUPP_PCM_SIZE_RATES: u8 = 0x0A;
pub const PARAM_SUPP_STREAM_FORMATS: u8 = 0x0B;
pub const PARAM_PIN_CAPS: u8 = 0x0C;
pub const PARAM_INPUT_AMP_CAPS: u8 = 0x0D;
pub const PARAM_CONN_LIST_LEN: u8 = 0x0E;
pub const PARAM_POWER_STATES: u8 = 0x0F;
pub const PARAM_PROCESSING_CAPS: u8 = 0x10;
pub const PARAM_GPIO_COUNT: u8 = 0x11;
pub const PARAM_OUTPUT_AMP_CAPS: u8 = 0x12;
pub const PARAM_VOLUME_KNOB_CAPS: u8 = 0x13;

// ── Function group types ────────────────────────────────────────────

pub const FUNC_GROUP_AFG: u8 = 0x01; // Audio Function Group
pub const FUNC_GROUP_MFG: u8 = 0x02; // Modem Function Group

// ── Widget types ────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WidgetKind {
    AudioOutput,
    AudioInput,
    Mixer,
    Selector,
    PinComplex,
    Power,
    VolumeKnob,
    BeepGen,
    Vendor,
    Other,
}

impl WidgetKind {
    /// Decode bits 20..23 of the Audio Widget Capabilities parameter.
    pub const fn from_caps(caps: u32) -> Self {
        match ((caps >> 20) & 0xF) as u8 {
            0x0 => WidgetKind::AudioOutput,
            0x1 => WidgetKind::AudioInput,
            0x2 => WidgetKind::Mixer,
            0x3 => WidgetKind::Selector,
            0x4 => WidgetKind::PinComplex,
            0x5 => WidgetKind::Power,
            0x6 => WidgetKind::VolumeKnob,
            0x7 => WidgetKind::BeepGen,
            0xF => WidgetKind::Vendor,
            _ => WidgetKind::Other,
        }
    }
}

// ── Pin device types (HDA §7.3.3.31 Config Default) ────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PinDevice {
    LineOut,
    Speaker,
    HpOut,
    Cd,
    Spdif,
    DigitalOther,
    ModemLineSide,
    ModemHandset,
    LineIn,
    AuxIn,
    MicIn,
    Telephony,
    SpdifIn,
    DigitalOtherIn,
    Unknown,
}

impl PinDevice {
    /// Decode bits 20..23 of the Config Default response.
    pub const fn from_cfg(cfg: u32) -> Self {
        match ((cfg >> 20) & 0xF) as u8 {
            0x0 => PinDevice::LineOut,
            0x1 => PinDevice::Speaker,
            0x2 => PinDevice::HpOut,
            0x3 => PinDevice::Cd,
            0x4 => PinDevice::Spdif,
            0x5 => PinDevice::DigitalOther,
            0x6 => PinDevice::ModemLineSide,
            0x7 => PinDevice::ModemHandset,
            0x8 => PinDevice::LineIn,
            0x9 => PinDevice::AuxIn,
            0xA => PinDevice::MicIn,
            0xB => PinDevice::Telephony,
            0xC => PinDevice::SpdifIn,
            0xD => PinDevice::DigitalOtherIn,
            _ => PinDevice::Unknown,
        }
    }
}

// ── Verb encoder ────────────────────────────────────────────────────

/// Encode a (cad, nid, verb_id, payload) tuple into the 32-bit CORB
/// command word — same shape as `corb::Verb::new` but exposed as a
/// loose function for codec patches that don't need the wrapper type.
pub const fn encode_verb(cad: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
    ((cad as u32 & 0xF) << 28)
        | ((nid as u32) << 20)
        | (((verb_id as u32) & 0x0FFF) << 8)
        | (payload as u32)
}

/// Codec address — index into the controller's codec link.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CodecAddr(pub u8);

// ── Widget ──────────────────────────────────────────────────────────

/// One widget on a codec.
#[derive(Clone, Debug)]
pub struct Widget {
    pub nid: u8,
    pub kind: WidgetKind,
    pub caps: u32,
    /// Connection list (NIDs of widgets feeding this node).
    pub connections: Vec<u8>,
    /// Pin Capabilities (only meaningful for `PinComplex`).
    pub pin_caps: u32,
    /// Config Default (only meaningful for `PinComplex`).
    pub config_default: u32,
    /// Decoded pin device, valid when `kind == PinComplex`.
    pub pin_device: PinDevice,
}

impl Widget {
    pub fn new(nid: u8, caps: u32) -> Self {
        Widget {
            nid,
            kind: WidgetKind::from_caps(caps),
            caps,
            connections: Vec::new(),
            pin_caps: 0,
            config_default: 0,
            pin_device: PinDevice::Unknown,
        }
    }
}

// ── Codec ───────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecKind {
    Realtek,
    Conexant,
    Cirrus,
    SigmaTel,
    Analog,
    Generic,
    Unknown,
}

impl CodecKind {
    pub fn from_vendor_id(v: u32) -> Self {
        let vendor = ((v >> 16) & 0xFFFF) as u16;
        match vendor {
            0x10EC => CodecKind::Realtek,
            0x14F1 => CodecKind::Conexant,
            0x1013 => CodecKind::Cirrus,
            0x8384 => CodecKind::SigmaTel,
            0x11D4 => CodecKind::Analog,
            0x0000 => CodecKind::Unknown,
            _ => CodecKind::Generic,
        }
    }
}

/// One probed codec. Owned by the controller's codec list.
#[derive(Clone, Debug)]
pub struct Codec {
    pub addr: u8,
    pub vendor_id: u32,
    pub revision_id: u32,
    pub kind: CodecKind,
    /// Root AFG NID — typically 0x01 but the codec reports it.
    pub afg_nid: u8,
    pub widgets: Vec<Widget>,
}

// ── Verb transport trait ────────────────────────────────────────────

/// What the controller layer provides to the codec layer:
/// a single round-trip verb send.
pub trait CodecVerbBus {
    fn send_verb(&mut self, verb: u32) -> Result<u32, VerbError>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerbError {
    /// CORB ring is full; software hasn't drained RIRB yet.
    CorbFull,
    /// Hardware timed out waiting for RIRB response.
    NoResponse,
    /// Controller isn't ready (not brought out of reset).
    NotReady,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Get-Parameter helper.
pub fn get_param(bus: &mut dyn CodecVerbBus, cad: u8, nid: u8, param: u8)
                 -> Result<u32, VerbError> {
    bus.send_verb(encode_verb(cad, nid, VERB_GET_PARAMETER, param))
}

/// Build the SET_AMP_GAIN_MUTE payload (HDA §7.3.3.8).
///
/// `set_output`, `set_input` choose which amp; `left`, `right`
/// choose which channel; `index` is the connection-list index
/// (output amps use 0); `mute` is the mute bit; `gain` is the
/// 7-bit attenuator (0 = max).
///
/// Returns a 16-bit value: high byte is the payload's high byte
/// (containing the channel + amp-type bits), low byte is the
/// payload's low byte (containing mute + gain). The 0x300 verb is a
/// 4-bit-major verb so callers pack the high byte into the verb_id.
pub const fn amp_gain_mute_payload(set_output: bool, set_input: bool,
                                    left: bool, right: bool,
                                    index: u8, mute: bool, gain: u8)
                                    -> u16 {
    let mut hi: u8 = 0;
    if set_output { hi |= 0x80; }
    if set_input  { hi |= 0x40; }
    if left       { hi |= 0x20; }
    if right      { hi |= 0x10; }
    hi |= index & 0x0F;
    let mut lo: u8 = gain & 0x7F;
    if mute { lo |= 0x80; }
    ((hi as u16) << 8) | (lo as u16)
}

/// Pack a Set Amp Gain/Mute verb (HDA §7.3.3.8). Returns the full
/// 32-bit CORB word — major opcode 0x3 + payload.
pub const fn set_amp_gain_mute_verb(cad: u8, nid: u8,
                                     set_output: bool, set_input: bool,
                                     left: bool, right: bool,
                                     index: u8, mute: bool, gain: u8) -> u32 {
    let payload = amp_gain_mute_payload(set_output, set_input,
                                         left, right, index, mute, gain);
    // major opcode 0x3 lives in bits 19..16 of the CORB word —
    // i.e. the high nibble of the 12-bit verb_id.
    let verb_id = (0x3 << 8) | ((payload >> 8) & 0xFF);
    let payload_lo = (payload & 0xFF) as u8;
    encode_verb(cad, nid, verb_id, payload_lo)
}

/// Default bring-up: power node up, unmute output, drive
/// pin-widget-control with `OUT_ENABLE | HP_ENABLE` (0x40 for
/// headphone amps, 0x40 for speaker EAPD-controlled paths,
/// 0xC0 = headphone + output).
pub fn generic_bring_up_output(bus: &mut dyn CodecVerbBus,
                               cad: u8,
                               dac_nid: u8,
                               pin_nid: u8) -> Result<(), VerbError> {
    // Set power state D0 (full power) on both the DAC and the pin.
    bus.send_verb(encode_verb(cad, dac_nid, VERB_SET_POWER_STATE, 0x00))?;
    bus.send_verb(encode_verb(cad, pin_nid, VERB_SET_POWER_STATE, 0x00))?;
    // Unmute the DAC output amp (output, both channels, index 0,
    // gain 0 = max).
    let unmute = set_amp_gain_mute_verb(cad, dac_nid,
        /*set_output=*/ true, /*set_input=*/ false,
        /*left=*/ true, /*right=*/ true,
        /*index=*/ 0, /*mute=*/ false, /*gain=*/ 0);
    bus.send_verb(unmute)?;
    // Drive pin widget control to "out enable" (bit 6 = 0x40).
    bus.send_verb(encode_verb(cad, pin_nid, VERB_SET_PIN_WIDGET_CONTROL, 0x40))?;
    Ok(())
}
