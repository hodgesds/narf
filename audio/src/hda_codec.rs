//! HDA codec / widget enumeration — transport-neutral.
//!
//! ## Sources (public only)
//!
//! - **"High Definition Audio Specification"**, Revision 1.0a, June
//!   17 2010 — Intel. Public document.
//!   <https://www.intel.com/content/dam/www/public/us/en/documents/product-specifications/high-definition-audio-specification.pdf>
//!   - §7.3.3 — Codec Verbs (Get Parameter, Get/Set Connection List
//!     Entry, Get Configuration Default, Get/Set Pin Widget Control,
//!     Get/Set Amplifier Gain/Mute, Get/Set Power State).
//!   - §7.3.4 — Get Parameter responses (Vendor ID, Revision ID,
//!     Subordinate Node Count, Function Group Type, Audio Widget
//!     Capabilities, Pin Capabilities, Input/Output Amp Capabilities,
//!     Connection List Length).
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! The bulk of `audio/src/hda.rs` is the controller-side bring-up
//! that pumps verbs through CORB / RIRB MMIO. This module is its
//! *transport-neutral* sibling: given any closure that resolves a
//! 32-bit verb to a 32-bit response, [`enumerate`] returns a fully
//! decoded [`Codec`] with the widget graph, pin defaults, and amp
//! capabilities.
//!
//! Why split it out:
//!
//! - **Testability**: the decoder can be exercised against a static
//!   `(verb → response)` table, no MMIO needed.
//! - **Reuse**: a future Bluetooth-A2DP / virtio-snd / cloud-emulator
//!   path can drive the same enumerator without dragging in the
//!   Intel HDA controller.
//! - **Separation of policy**: `find_output_path` /
//!   `find_input_path` are pure functions over the parsed graph,
//!   making them straightforward to fuzz.

extern crate alloc;
use alloc::vec::Vec;

// ── Verb encoding (§7.3.1) ────────────────────────────────────────

/// Encode the 32-bit verb word: CAd[31:28] | NID[27:20] | Verb+Payload[19:0].
pub const fn make_verb(cad: u8, nid: u8, verb: u32) -> u32 {
    ((cad as u32) << 28) | ((nid as u32) << 20) | (verb & 0x000F_FFFF)
}

/// Verb opcodes (§7.3.3). Each constant is already shifted into the
/// 20-bit payload position, ready to be OR'd with payload bits.
pub mod verb {
    pub const GET_PARAMETER: u32 = 0xF00 << 8;
    pub const GET_CONNECTION_LIST_ENTRY: u32 = 0xF02 << 8;
    pub const GET_PROCESSING_STATE: u32 = 0xF03 << 8;
    pub const GET_AMP_GAIN_MUTE: u32 = 0xB << 16;
    pub const SET_AMP_GAIN_MUTE: u32 = 0x3 << 16;
    pub const SET_CONVERTER_FORMAT: u32 = 0x2 << 16;
    pub const GET_CONVERTER_FORMAT: u32 = 0xA << 16;
    pub const GET_CONFIG_DEFAULT: u32 = 0xF1C << 8;
    pub const GET_PIN_WIDGET_CONTROL: u32 = 0xF07 << 8;
    pub const SET_PIN_WIDGET_CONTROL: u32 = 0x707 << 8;
    pub const GET_POWER_STATE: u32 = 0xF05 << 8;
    pub const SET_POWER_STATE: u32 = 0x705 << 8;
    pub const GET_PIN_SENSE: u32 = 0xF09 << 8;
    pub const EXECUTE_PIN_SENSE: u32 = 0x709 << 8;
    pub const GET_CONVERTER_STREAM_CHANNEL: u32 = 0xF06 << 8;
    pub const SET_CONVERTER_STREAM_CHANNEL: u32 = 0x706 << 8;
}

/// Get-Parameter sub-codes (§7.3.4). OR with `verb::GET_PARAMETER`.
pub mod param {
    pub const VENDOR_ID: u32 = 0x00;
    pub const REVISION_ID: u32 = 0x02;
    pub const SUBORDINATE_NODE_COUNT: u32 = 0x04;
    pub const FUNCTION_GROUP_TYPE: u32 = 0x05;
    pub const AUDIO_FUNC_GROUP_CAPS: u32 = 0x08;
    pub const AUDIO_WIDGET_CAPS: u32 = 0x09;
    pub const PCM_RATES_FORMATS: u32 = 0x0A;
    pub const STREAM_FORMATS: u32 = 0x0B;
    pub const PIN_CAPS: u32 = 0x0C;
    pub const INPUT_AMP_CAPS: u32 = 0x0D;
    pub const CONNECTION_LIST_LENGTH: u32 = 0x0E;
    pub const SUPPORTED_POWER_STATES: u32 = 0x0F;
    pub const PROCESSING_CAPS: u32 = 0x10;
    pub const GPIO_COUNT: u32 = 0x11;
    pub const OUTPUT_AMP_CAPS: u32 = 0x12;
    pub const VOLUME_KNOB_CAPS: u32 = 0x13;
}

// ── Decoded widget graph ─────────────────────────────────────────

/// Widget type code (§7.3.4.6 Audio Widget Capabilities, bits[23:20]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WidgetType {
    AudioOutput = 0x0,
    AudioInput = 0x1,
    AudioMixer = 0x2,
    AudioSelector = 0x3,
    PinComplex = 0x4,
    PowerWidget = 0x5,
    VolumeKnob = 0x6,
    BeepGenerator = 0x7,
    /// Vendor-defined (0xF) or any other reserved value.
    Vendor = 0xF,
    Reserved = 0xFE,
}

impl WidgetType {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x0 => Self::AudioOutput,
            0x1 => Self::AudioInput,
            0x2 => Self::AudioMixer,
            0x3 => Self::AudioSelector,
            0x4 => Self::PinComplex,
            0x5 => Self::PowerWidget,
            0x6 => Self::VolumeKnob,
            0x7 => Self::BeepGenerator,
            0xF => Self::Vendor,
            _ => Self::Reserved,
        }
    }
}

/// Audio Widget Capabilities (§7.3.4.6) — decoded into the bits the
/// path builder needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WidgetCaps(pub u32);

impl WidgetCaps {
    pub fn ty(self) -> WidgetType {
        WidgetType::from_byte(((self.0 >> 20) & 0xF) as u8)
    }
    pub fn channels(self) -> u8 {
        // bits[15:13] is "Channel Count Ext", bit 0 is "Stereo".
        // Channel count = (bits[15:13] << 1) | (Stereo bit) + 1.
        let cce = ((self.0 >> 13) & 0x7) as u8;
        let stereo = (self.0 & 1) as u8;
        ((cce << 1) | stereo) + 1
    }
    pub fn in_amp_present(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    pub fn out_amp_present(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    pub fn amp_param_override(self) -> bool {
        self.0 & (1 << 3) != 0
    }
    pub fn format_override(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    pub fn stripe(self) -> bool {
        self.0 & (1 << 5) != 0
    }
    pub fn proc_widget(self) -> bool {
        self.0 & (1 << 6) != 0
    }
    pub fn unsol_capable(self) -> bool {
        self.0 & (1 << 7) != 0
    }
    pub fn conn_list_present(self) -> bool {
        self.0 & (1 << 8) != 0
    }
    pub fn digital(self) -> bool {
        self.0 & (1 << 9) != 0
    }
    pub fn power_ctrl(self) -> bool {
        self.0 & (1 << 10) != 0
    }
    pub fn lr_swap(self) -> bool {
        self.0 & (1 << 11) != 0
    }
    pub fn cp_caps(self) -> bool {
        self.0 & (1 << 12) != 0
    }
}

/// Configuration Default (§7.3.3.31) decoded into device class +
/// connectivity. The runtime driver consults this to pick the
/// "right" pin for a given audio role.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PinConfigDefault {
    /// Bits[23:20] — see [`default_device`].
    pub default_device: u8,
    /// Bits[31:30] — 0=jack, 1=no physical conn, 2=fixed, 3=both.
    pub port_connectivity: u8,
    /// Bits[27:24] — Connection Type (3.5mm jack, optical, ...).
    pub connection_type: u8,
    /// Bits[19:16] — Color (HID 1.4 / HDA color codes).
    pub color: u8,
    /// Bits[15:12] — Misc (Jack-detect override, etc.).
    pub misc: u8,
    /// Bits[11:8] — Default Association (identifies a paired set,
    /// e.g. a stereo pair of pins forming one logical output).
    pub default_assoc: u8,
    /// Bits[7:4] — Sequence within the association (unique per
    /// association).
    pub sequence: u8,
    pub raw: u32,
}

impl PinConfigDefault {
    pub fn decode(raw: u32) -> Self {
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
    pub fn is_output_role(self) -> bool {
        // Default Device codes (§7.3.3.31): 0=Line Out, 1=Speaker,
        // 2=HP Out, 3=CD, 4=SPDIF Out, 5=Digital Other Out.
        matches!(self.default_device, 0x0..=0x5)
    }
    pub fn is_input_role(self) -> bool {
        // 6=Modem Line Side, 7=Modem Handset, 8=Line In,
        // 9=AUX, 0xA=Mic In, 0xB=Telephony, 0xC=SPDIF In, 0xD=Dig In.
        matches!(self.default_device, 0x8..=0xD)
    }
    /// `true` if this pin can plausibly be picked for normal speaker
    /// playback (laptop boot path).
    pub fn is_speaker(self) -> bool {
        self.default_device == 0x1 && self.port_connectivity != 0x1
    }
    /// `true` if this is a microphone input.
    pub fn is_microphone(self) -> bool {
        self.default_device == 0xA && self.port_connectivity != 0x1
    }
}

/// Amplifier Capabilities (§7.3.4.10/§7.3.4.11). Same shape for both
/// input and output amps; the driver decides which it's reading.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AmpCaps {
    pub offset: u8,    // bits[6:0]
    pub num_steps: u8, // bits[14:8]
    pub step_size: u8, // bits[22:16] in 0.25 dB units
    pub mute_capable: bool,
    pub raw: u32,
}

impl AmpCaps {
    pub fn decode(raw: u32) -> Self {
        Self {
            offset: (raw & 0x7F) as u8,
            num_steps: ((raw >> 8) & 0x7F) as u8,
            step_size: ((raw >> 16) & 0x7F) as u8,
            mute_capable: raw & (1 << 31) != 0,
            raw,
        }
    }
}

/// One node in the codec graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Widget {
    pub nid: u8,
    pub caps: WidgetCaps,
    /// Connection-list entries — only populated when
    /// [`WidgetCaps::conn_list_present`] is set. Encoded NIDs (8-bit
    /// short form). The codec graph reachable via these is what the
    /// path builder walks.
    pub connections: Vec<u8>,
    /// Set on Pin Complex widgets only.
    pub pin_caps: Option<u32>,
    /// Set on Pin Complex widgets only.
    pub pin_config: Option<PinConfigDefault>,
    /// Set if [`WidgetCaps::in_amp_present`] (or amp_param_override
    /// and reading from the AFG default).
    pub in_amp: Option<AmpCaps>,
    pub out_amp: Option<AmpCaps>,
}

impl Widget {
    pub fn ty(&self) -> WidgetType {
        self.caps.ty()
    }
}

/// Decoded codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Codec {
    pub addr: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u32,
    pub afg_nid: u8,
    pub widgets: Vec<Widget>,
}

impl Codec {
    pub fn widget(&self, nid: u8) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.nid == nid)
    }
}

// ── Enumerator ───────────────────────────────────────────────────

/// Walk the entire codec graph using the supplied verb-execution
/// closure. `verb` takes the encoded 32-bit verb and returns the
/// 32-bit response from RIRB. The walker issues exactly the verbs
/// needed to populate every field of the returned [`Codec`].
pub fn enumerate<F>(addr: u8, mut verb: F) -> Codec
where
    F: FnMut(u32) -> u32,
{
    // Vendor / Device id.
    let vid_did = verb(make_verb(addr, 0, verb::GET_PARAMETER | param::VENDOR_ID));
    let device_id = (vid_did >> 16) as u16;
    let vendor_id = (vid_did & 0xFFFF) as u16;
    let revision = verb(make_verb(addr, 0, verb::GET_PARAMETER | param::REVISION_ID));
    let sub_root = verb(make_verb(
        addr,
        0,
        verb::GET_PARAMETER | param::SUBORDINATE_NODE_COUNT,
    ));
    let first_fg = (sub_root & 0xFF) as u8;
    let n_fg = ((sub_root >> 16) & 0xFF) as u8;

    // Find the first Audio Function Group (Function Group Type = 1).
    let mut afg_nid = 0u8;
    for i in 0..n_fg {
        let nid = first_fg + i;
        let fgt = verb(make_verb(
            addr,
            nid,
            verb::GET_PARAMETER | param::FUNCTION_GROUP_TYPE,
        ));
        if (fgt & 0x7F) == 0x01 {
            afg_nid = nid;
            break;
        }
    }

    // Walk every widget under the AFG.
    let mut widgets: Vec<Widget> = Vec::new();
    if afg_nid != 0 {
        let sub_afg = verb(make_verb(
            addr,
            afg_nid,
            verb::GET_PARAMETER | param::SUBORDINATE_NODE_COUNT,
        ));
        let first_w = (sub_afg & 0xFF) as u8;
        let n_w = ((sub_afg >> 16) & 0xFF) as u8;
        for i in 0..n_w {
            let nid = first_w + i;
            let caps_raw = verb(make_verb(
                addr,
                nid,
                verb::GET_PARAMETER | param::AUDIO_WIDGET_CAPS,
            ));
            let caps = WidgetCaps(caps_raw);

            // Connection list.
            let mut connections = Vec::new();
            if caps.conn_list_present() {
                let cll = verb(make_verb(
                    addr,
                    nid,
                    verb::GET_PARAMETER | param::CONNECTION_LIST_LENGTH,
                ));
                let n = (cll & 0x7F) as u8;
                let long_form = cll & (1 << 7) != 0;
                let mut idx = 0u8;
                while idx < n {
                    let resp =
                        verb(make_verb(addr, nid, verb::GET_CONNECTION_LIST_ENTRY | idx as u32));
                    if long_form {
                        // Two 16-bit entries per response (§7.3.3.3).
                        connections.push((resp & 0xFFFF) as u8);
                        if idx + 1 < n {
                            connections.push(((resp >> 16) & 0xFFFF) as u8);
                        }
                        idx += 2;
                    } else {
                        // Four 8-bit entries.
                        connections.push((resp & 0xFF) as u8);
                        if idx + 1 < n {
                            connections.push(((resp >> 8) & 0xFF) as u8);
                        }
                        if idx + 2 < n {
                            connections.push(((resp >> 16) & 0xFF) as u8);
                        }
                        if idx + 3 < n {
                            connections.push(((resp >> 24) & 0xFF) as u8);
                        }
                        idx += 4;
                    }
                }
            }

            let pin_caps = if matches!(caps.ty(), WidgetType::PinComplex) {
                Some(verb(make_verb(
                    addr,
                    nid,
                    verb::GET_PARAMETER | param::PIN_CAPS,
                )))
            } else {
                None
            };
            let pin_config = if matches!(caps.ty(), WidgetType::PinComplex) {
                Some(PinConfigDefault::decode(verb(make_verb(
                    addr,
                    nid,
                    verb::GET_CONFIG_DEFAULT,
                ))))
            } else {
                None
            };

            let in_amp = if caps.in_amp_present() {
                Some(AmpCaps::decode(verb(make_verb(
                    addr,
                    nid,
                    verb::GET_PARAMETER | param::INPUT_AMP_CAPS,
                ))))
            } else {
                None
            };
            let out_amp = if caps.out_amp_present() {
                Some(AmpCaps::decode(verb(make_verb(
                    addr,
                    nid,
                    verb::GET_PARAMETER | param::OUTPUT_AMP_CAPS,
                ))))
            } else {
                None
            };

            widgets.push(Widget {
                nid,
                caps,
                connections,
                pin_caps,
                pin_config,
                in_amp,
                out_amp,
            });
        }
    }

    Codec {
        addr,
        vendor_id,
        device_id,
        revision,
        afg_nid,
        widgets,
    }
}

// ── Audio path builder ───────────────────────────────────────────

/// A resolved audio path: pin → (mixer/selector chain) → converter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioPath {
    pub pin_nid: u8,
    /// In-order chain of mixer / selector NIDs between the pin and
    /// the converter (may be empty for direct pin-to-converter
    /// paths).
    pub chain: Vec<u8>,
    /// Audio Output (for output paths) or Audio Input (for input
    /// paths) NID.
    pub converter_nid: u8,
}

/// Walk every output Pin Complex (Speaker > Line Out > Headphone),
/// pick the highest-preference one whose connection list reaches an
/// Audio-Output converter, and return the resolved path.
pub fn find_output_path(c: &Codec) -> Option<AudioPath> {
    // Preference: Speaker (1) > Line Out (0) > HP Out (2).
    const PREF: &[u8] = &[0x1, 0x0, 0x2];
    for &want in PREF {
        for w in c.widgets.iter().filter(|w| matches!(w.ty(), WidgetType::PinComplex)) {
            let cfg = match w.pin_config {
                Some(c) => c,
                None => continue,
            };
            if cfg.default_device != want {
                continue;
            }
            if cfg.port_connectivity == 0x1 {
                continue;
            }
            if let Some(p) = trace_to_converter(c, w.nid, WidgetType::AudioOutput, 4) {
                return Some(p);
            }
        }
    }
    None
}

/// Walk every input Pin Complex (Mic In, Line In, AUX), pick the
/// first one whose connection list reaches an Audio-Input converter.
pub fn find_input_path(c: &Codec) -> Option<AudioPath> {
    // Preference: Mic In (0xA) > Line In (0x8) > AUX (0x9).
    const PREF: &[u8] = &[0xA, 0x8, 0x9];
    for &want in PREF {
        for w in c.widgets.iter().filter(|w| matches!(w.ty(), WidgetType::PinComplex)) {
            let cfg = match w.pin_config {
                Some(c) => c,
                None => continue,
            };
            if cfg.default_device != want {
                continue;
            }
            if cfg.port_connectivity == 0x1 {
                continue;
            }
            if let Some(p) = trace_to_converter(c, w.nid, WidgetType::AudioInput, 4) {
                return Some(p);
            }
        }
    }
    None
}

/// Depth-limited DFS through connection lists to find a converter of
/// the requested type. `chain` accumulates the mixer/selector path.
fn trace_to_converter(c: &Codec, start: u8, want: WidgetType, depth: usize) -> Option<AudioPath> {
    let mut chain = Vec::new();
    let cur = trace_step(c, start, want, depth, &mut chain)?;
    Some(AudioPath {
        pin_nid: start,
        chain,
        converter_nid: cur,
    })
}

fn trace_step(
    c: &Codec,
    nid: u8,
    want: WidgetType,
    depth: usize,
    chain: &mut Vec<u8>,
) -> Option<u8> {
    if depth == 0 {
        return None;
    }
    let w = c.widget(nid)?;
    for &child in &w.connections {
        if let Some(cw) = c.widget(child) {
            if cw.ty() == want {
                return Some(child);
            }
            // Only walk through Mixers / Selectors / Pins.
            match cw.ty() {
                WidgetType::AudioMixer | WidgetType::AudioSelector | WidgetType::PinComplex => {
                    chain.push(child);
                    if let Some(found) = trace_step(c, child, want, depth - 1, chain) {
                        return Some(found);
                    }
                    chain.pop();
                }
                _ => {}
            }
        }
    }
    None
}

