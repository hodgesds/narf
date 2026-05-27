//! HDA codec verb sender + widget walker — vendor-agnostic.
//!
//! Sits between the HDA *controller* in [`crate::hda`] (which owns
//! CORB/RIRB MMIO and per-link DMA) and the per-vendor *codec patch*
//! modules ([`crate::realtek_alc`], future Cirrus / Conexant / IDT
//! variants). The split mirrors Linux `sound/hda/`: the controller
//! pumps verbs through a fixed transport; this module knows how to
//! encode them and how to walk the codec graph; the patch modules
//! know which NIDs to poke for a given silicon part.
//!
//! ## Sources (cited per the GPL-link allowance, post-2026-05-20
//! relicense)
//!
//! - **HDA Spec §7.3** — Verb format (CAd[31:28] | NID[27:20] |
//!   Verb+Payload[19:0]) and the Get-Parameter parameter table.
//! - **Linux `sound/hda/hdac_regmap.c`** — verb-ID / payload split
//!   conventions, especially the 12-bit-verb vs 4-bit-verb encoding.
//! - **Linux `sound/pci/hda/hda_codec.c::snd_hdac_get_sub_nodes`** —
//!   widget enumeration pattern (Get Sub Node Count → walk
//!   first-node…first-node+n-1).
//! - **Linux `sound/pci/hda/hda_codec.c::snd_hda_get_connections`** —
//!   connection-list 4-byte / 2-byte short/long encoding.
//!
//! ## Shape
//!
//! Public entry points:
//!
//! - [`verb`] — pack a `(cad, nid, verb_id, payload)` tuple into the
//!   32-bit CORB command word. Pure / `const fn`.
//! - [`send_verb`] — push a verb through the *probed* HDA controller's
//!   CORB ring and pop the response from RIRB. Returns
//!   [`CodecError::ControllerNotProbed`] when the controller isn't
//!   bound. The transport is the existing
//!   [`crate::hda::IntelHda::send_verb`].
//! - [`enumerate`] — walk the codec graph (root → function groups →
//!   widgets) and return a fully populated [`CodecTree`].
//!
//! [`codec::CodecTree`] is a *parallel* graph type to
//! [`crate::hda_codec::Codec`]: the older type lives next to the
//! controller and is consumed by the path builder; this type is the
//! shape that the new per-vendor patch modules want. A future cutover
//! collapses the two — for now we keep both wired through the same
//! transport.

extern crate alloc;

use alloc::vec::Vec;

use crate::hda;

// ── Verb encoding (HDA Spec §7.3) ───────────────────────────────────

/// Pack a codec verb into the 32-bit CORB command word.
///
/// Layout (per HDA Spec §7.3.1):
///
/// ```text
///   bits 31:28  Codec Address (CAd)
///   bits 27:20  Node ID (NID)
///   bits 19:8   12-bit verb ID  (e.g. 0xF00 = Get Parameter,
///                                0x707 = Set Pin Widget Control)
///   bits  7:0   8-bit payload
/// ```
///
/// Some "set" verbs use a 4-bit major opcode + 16-bit payload — those
/// are encoded by callers passing a 12-bit `verb_id` whose high 4 bits
/// hold the major opcode and whose low 8 bits hold the high byte of
/// the payload, with the low byte of the payload going through this
/// function's `payload` argument. The classic example is `Set Amp Gain
/// Mute` (major 0x3); see [`crate::realtek_alc::set_amp_gain_mute`]
/// for the helper that does the split.
pub const fn verb(cad: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
    ((cad as u32) << 28)
        | ((nid as u32) << 20)
        | (((verb_id as u32) & 0x0FFF) << 8)
        | (payload as u32)
}

/// Decode the 12-bit verb ID out of a packed CORB command word. Used
/// by the round-trip smoke test and by debug logs.
pub const fn verb_id_of(packed: u32) -> u16 {
    ((packed >> 8) & 0x0FFF) as u16
}

/// Decode the codec address out of a packed CORB command word.
pub const fn cad_of(packed: u32) -> u8 {
    ((packed >> 28) & 0xF) as u8
}

/// Decode the node ID out of a packed CORB command word.
pub const fn nid_of(packed: u32) -> u8 {
    ((packed >> 20) & 0xFF) as u8
}

/// Decode the 8-bit payload out of a packed CORB command word.
pub const fn payload_of(packed: u32) -> u8 {
    (packed & 0xFF) as u8
}

// ── Verb opcodes (HDA Spec §7.3.3) ──────────────────────────────────

/// Get Parameter. Sub-parameters are in [`param`].
pub const VERB_GET_PARAMETER: u16 = 0xF00;
/// Get Connection List Entry. Payload = list index.
pub const VERB_GET_CONNECTION_LIST_ENTRY: u16 = 0xF02;
/// Get Pin Widget Control.
pub const VERB_GET_PIN_WIDGET_CONTROL: u16 = 0xF07;
/// Set Pin Widget Control. Payload bit 6 = output enable, bit 7 =
/// HP-amp enable.
pub const VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x707;
/// Get Configuration Default (returns 32-bit pin config).
pub const VERB_GET_CONFIG_DEFAULT: u16 = 0xF1C;
/// Get Pin Sense (returns 32-bit; bit 31 = presence).
pub const VERB_GET_PIN_SENSE: u16 = 0xF09;
/// Execute Pin Sense.
pub const VERB_EXECUTE_PIN_SENSE: u16 = 0x709;
/// Get Unsolicited Response (returns enable bit + tag).
pub const VERB_GET_UNSOLICITED_RESPONSE: u16 = 0xF08;
/// Set Unsolicited Response Enable. Payload bit 7 = enable, bits 5:0
/// = tag.
pub const VERB_SET_UNSOLICITED_RESPONSE: u16 = 0x708;
/// Get Power State.
pub const VERB_GET_POWER_STATE: u16 = 0xF05;
/// Set Power State. Payload bits 3:0 = state (0=D0, 3=D3).
pub const VERB_SET_POWER_STATE: u16 = 0x705;
/// Get EAPD / BTL Enable.
pub const VERB_GET_EAPD_BTL: u16 = 0xF0C;
/// Set EAPD / BTL Enable. Payload bit 1 = EAPD enable.
pub const VERB_SET_EAPD_BTL: u16 = 0x70C;

/// Get-Parameter sub-codes (HDA Spec §7.3.4). OR with
/// [`VERB_GET_PARAMETER`] is *not* how this is used: the codec
/// hardware decodes the 8-bit payload directly. Callers do:
/// `verb(cad, nid, VERB_GET_PARAMETER, param::WIDGET_CAPS as u8)`.
pub mod param {
    /// 0x00 — Vendor / Device ID. Response: (vendor << 16) | device.
    pub const VENDOR_ID: u8 = 0x00;
    /// 0x02 — Revision ID.
    pub const REVISION_ID: u8 = 0x02;
    /// 0x04 — Subordinate Node Count. Response:
    /// (first_node << 16) | (total_nodes).
    pub const SUBORDINATE_NODE_COUNT: u8 = 0x04;
    /// 0x05 — Function Group Type. Bit 8 = Unsol Capable, low 7 bits
    /// = type code (1 = Audio Function Group, 2 = Modem).
    pub const FUNCTION_GROUP_TYPE: u8 = 0x05;
    /// 0x08 — Audio Function Group Capabilities.
    pub const AUDIO_FUNC_GROUP_CAPS: u8 = 0x08;
    /// 0x09 — Audio Widget Capabilities.
    pub const WIDGET_CAPS: u8 = 0x09;
    /// 0x0A — Supported PCM Sample Sizes / Rates.
    pub const PCM_SIZES_RATES: u8 = 0x0A;
    /// 0x0B — Supported Stream Formats.
    pub const STREAM_FORMATS: u8 = 0x0B;
    /// 0x0C — Pin Capabilities.
    pub const PIN_CAPS: u8 = 0x0C;
    /// 0x0D — Input Amplifier Capabilities.
    pub const INPUT_AMP_CAPS: u8 = 0x0D;
    /// 0x0E — Connection List Length. Bit 7 = long form (16-bit
    /// entries), low 7 bits = entry count.
    pub const CONNECTION_LIST_LENGTH: u8 = 0x0E;
    /// 0x0F — Supported Power States.
    pub const POWER_STATES: u8 = 0x0F;
    /// 0x10 — Processing Capabilities.
    pub const PROCESSING_CAPS: u8 = 0x10;
    /// 0x11 — GPIO Count.
    pub const GPIO_COUNT: u8 = 0x11;
    /// 0x12 — Output Amplifier Capabilities.
    pub const OUTPUT_AMP_CAPS: u8 = 0x12;
    /// 0x13 — Volume Knob Capabilities.
    pub const VOLUME_KNOB_CAPS: u8 = 0x13;
}

// ── Widget type code (§7.3.4.6) ─────────────────────────────────────

/// Widget type — decoded out of [`WidgetCaps::ty`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WidgetKind {
    /// 0 — Audio Output (DAC).
    AudioOutput = 0,
    /// 1 — Audio Input (ADC).
    AudioInput = 1,
    /// 2 — Audio Mixer (sums multiple inputs).
    AudioMixer = 2,
    /// 3 — Audio Selector (picks one of multiple inputs).
    AudioSelector = 3,
    /// 4 — Pin Complex (analog/digital physical pin).
    PinComplex = 4,
    /// 5 — Power Widget.
    PowerWidget = 5,
    /// 6 — Volume Knob.
    VolumeKnob = 6,
    /// 7 — Beep Generator.
    BeepGenerator = 7,
    /// 0xF — Vendor-defined. Mapped here for any code 0x8..=0xF that
    /// isn't otherwise recognised.
    Vendor = 0xF,
}

impl WidgetKind {
    /// Decode the 4-bit type field. Unknown / reserved values
    /// collapse to [`WidgetKind::Vendor`].
    pub const fn from_nibble(n: u8) -> Self {
        match n & 0xF {
            0 => Self::AudioOutput,
            1 => Self::AudioInput,
            2 => Self::AudioMixer,
            3 => Self::AudioSelector,
            4 => Self::PinComplex,
            5 => Self::PowerWidget,
            6 => Self::VolumeKnob,
            7 => Self::BeepGenerator,
            _ => Self::Vendor,
        }
    }
}

// ── Widget Capabilities (§7.3.4.6) ──────────────────────────────────

/// 32-bit Audio Widget Capabilities response, decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WidgetCaps(pub u32);

impl WidgetCaps {
    /// Widget kind from bits[23:20].
    pub const fn ty(self) -> WidgetKind {
        WidgetKind::from_nibble(((self.0 >> 20) & 0xF) as u8)
    }
    /// Stereo bit (bit 0).
    pub const fn stereo(self) -> bool {
        self.0 & 1 != 0
    }
    /// Input amp present (bit 1).
    pub const fn has_in_amp(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    /// Output amp present (bit 2).
    pub const fn has_out_amp(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    /// Amplifier parameter override (bit 3).
    pub const fn amp_param_override(self) -> bool {
        self.0 & (1 << 3) != 0
    }
    /// Stream format override (bit 4).
    pub const fn format_override(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    /// Stripe-capable (bit 5).
    pub const fn stripe(self) -> bool {
        self.0 & (1 << 5) != 0
    }
    /// Processing widget (bit 6).
    pub const fn proc_widget(self) -> bool {
        self.0 & (1 << 6) != 0
    }
    /// Unsolicited Response Capable (bit 7).
    pub const fn unsol_capable(self) -> bool {
        self.0 & (1 << 7) != 0
    }
    /// Connection list present (bit 8).
    pub const fn has_conn_list(self) -> bool {
        self.0 & (1 << 8) != 0
    }
    /// Digital widget (bit 9).
    pub const fn digital(self) -> bool {
        self.0 & (1 << 9) != 0
    }
    /// Power-control capable (bit 10).
    pub const fn power_ctrl(self) -> bool {
        self.0 & (1 << 10) != 0
    }
    /// L/R swap support (bit 11).
    pub const fn lr_swap(self) -> bool {
        self.0 & (1 << 11) != 0
    }
    /// Content-protection capable (bit 12).
    pub const fn cp_caps(self) -> bool {
        self.0 & (1 << 12) != 0
    }
    /// Channel count = ((bits[15:13] << 1) | stereo) + 1.
    pub const fn channels(self) -> u8 {
        let cce = ((self.0 >> 13) & 0x7) as u8;
        let stereo = (self.0 & 1) as u8;
        ((cce << 1) | stereo) + 1
    }
}

// ── Codec graph ─────────────────────────────────────────────────────

/// One node in the codec widget graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecWidget {
    /// NID — addressable inside this codec.
    pub nid: u8,
    /// Raw Audio Widget Capabilities word.
    pub caps: WidgetCaps,
    /// Connection list (encoded NIDs of upstream-feeding widgets).
    /// Empty when `caps.has_conn_list()` is false.
    pub connections: Vec<u8>,
    /// Pin Configuration Default — `Some` only for Pin Complex
    /// widgets. Raw 32-bit value, decoded by per-vendor patch modules.
    pub pin_config: Option<u32>,
}

impl CodecWidget {
    /// Convenience for `caps.ty()`.
    pub fn kind(&self) -> WidgetKind {
        self.caps.ty()
    }
}

/// One function group beneath a codec root. We only care about Audio
/// Function Groups (type code 0x01); modem function groups are
/// recorded for completeness but never walked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionGroup {
    /// NID of the function-group node.
    pub nid: u8,
    /// Function Group Type (1 = Audio, 2 = Modem).
    pub group_type: u8,
    /// Widgets enumerated under this function group. Empty for non-
    /// audio groups.
    pub widgets: Vec<CodecWidget>,
}

/// Tree of widgets returned by [`enumerate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecTree {
    /// Codec Address (CAd) bus position.
    pub cad: u8,
    /// Vendor ID (high 16 bits of Get-Parameter VENDOR_ID).
    pub vendor_id: u16,
    /// Device ID (low 16 bits of Get-Parameter VENDOR_ID).
    pub device_id: u16,
    /// Revision ID (raw 32-bit Get-Parameter REVISION_ID response).
    pub revision_id: u32,
    /// Function groups discovered below the root node.
    pub function_groups: Vec<FunctionGroup>,
}

impl CodecTree {
    /// Combined 32-bit vendor/device ID: `(vendor << 16) | device`.
    /// Matches the wire format that
    /// [`crate::hda::CodecInfo::vendor_id`] carries.
    pub fn vendor_device(&self) -> u32 {
        ((self.vendor_id as u32) << 16) | (self.device_id as u32)
    }

    /// First Audio Function Group (type = 1), if any.
    pub fn audio_function_group(&self) -> Option<&FunctionGroup> {
        self.function_groups.iter().find(|g| g.group_type == 0x01)
    }

    /// Look up a widget by NID across every function group.
    pub fn widget(&self, nid: u8) -> Option<&CodecWidget> {
        self.function_groups
            .iter()
            .flat_map(|g| g.widgets.iter())
            .find(|w| w.nid == nid)
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Failure modes for verb sends + enumeration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// `hda::with_controller` returned `None` — no probed controller
    /// to dispatch through.
    ControllerNotProbed,
    /// Controller's transport returned an error (CORB / RIRB timeout
    /// or hardware-level error). Reflects [`crate::hda::HdaError`].
    TransportFailed,
}

// ── Transport ───────────────────────────────────────────────────────

/// Send `verb_id` + `payload` to `(cad, nid)` through the probed HDA
/// controller's CORB ring and return the 32-bit RIRB response.
///
/// Returns [`CodecError::ControllerNotProbed`] when the singleton
/// hasn't been bound yet (the bus probe walker hasn't run or the
/// match table didn't fire). On QEMU + bare metal this is the
/// "no audio" path.
///
/// # Safety boundary
///
/// The unsafety lives inside [`crate::hda::IntelHda::send_verb`] —
/// it asserts BAR0 ownership. The controller singleton holds that
/// ownership for its lifetime, so callers of `codec::send_verb` are
/// safe.
pub fn send_verb(cad: u8, nid: u8, verb_id: u16, payload: u8) -> Result<u32, CodecError> {
    let packed = verb(cad, nid, verb_id, payload);
    let result = hda::with_controller(|c|
        // SAFETY: controller singleton owns BAR0 for its lifetime; verb
        // dispatch is the documented use of the public `send_verb` API.
        unsafe { c.send_verb(packed) })
    .ok_or(CodecError::ControllerNotProbed)?;
    result.map_err(|_| CodecError::TransportFailed)
}

// ── Enumeration walker ─────────────────────────────────────────────

/// Read the full codec graph for `cad` through the probed HDA
/// controller. See [`enumerate_with`] for a transport-injected
/// variant that the test stand drives.
pub fn enumerate(cad: u8) -> Result<CodecTree, CodecError> {
    enumerate_with(cad, |c, n, v, p| send_verb(c, n, v, p))
}

/// Enumeration with an injected verb closure. Used by the codec
/// fixture tests against a [`FakeCorb`] and by future paths that
/// drive enumeration over a non-HDA transport (Bluetooth A2DP CTKE,
/// virtio-sound, …).
///
/// The closure receives `(cad, nid, verb_id, payload)` and must return
/// the 32-bit RIRB response. Errors short-circuit the walk.
pub fn enumerate_with<F>(cad: u8, mut send: F) -> Result<CodecTree, CodecError>
where
    F: FnMut(u8, u8, u16, u8) -> Result<u32, CodecError>,
{
    // Root — NID 0. Vendor / device id is a single response with
    // vendor in the high 16 bits, device in the low 16 (HDA §7.3.4.1).
    let vid_did = send(cad, 0, VERB_GET_PARAMETER, param::VENDOR_ID)?;
    let vendor_id = ((vid_did >> 16) & 0xFFFF) as u16;
    let device_id = (vid_did & 0xFFFF) as u16;
    let revision_id = send(cad, 0, VERB_GET_PARAMETER, param::REVISION_ID)?;

    let sub_root = send(cad, 0, VERB_GET_PARAMETER, param::SUBORDINATE_NODE_COUNT)?;
    let first_fg = (sub_root >> 16) as u8;
    let n_fg = (sub_root & 0xFF) as u8;

    let mut function_groups = Vec::new();
    for i in 0..n_fg {
        let fg_nid = first_fg.wrapping_add(i);
        let fgt = send(cad, fg_nid, VERB_GET_PARAMETER, param::FUNCTION_GROUP_TYPE)?;
        let group_type = (fgt & 0x7F) as u8;
        let mut widgets = Vec::new();
        if group_type == 0x01 {
            // Audio Function Group — walk its widgets.
            let sub_afg = send(cad, fg_nid, VERB_GET_PARAMETER, param::SUBORDINATE_NODE_COUNT)?;
            let first_w = (sub_afg >> 16) as u8;
            let n_w = (sub_afg & 0xFF) as u8;
            for j in 0..n_w {
                let nid = first_w.wrapping_add(j);
                let caps_raw = send(cad, nid, VERB_GET_PARAMETER, param::WIDGET_CAPS)?;
                let caps = WidgetCaps(caps_raw);

                let mut connections = Vec::new();
                if caps.has_conn_list() {
                    let cll = send(cad, nid, VERB_GET_PARAMETER, param::CONNECTION_LIST_LENGTH)?;
                    let n = (cll & 0x7F) as u8;
                    let long_form = cll & (1 << 7) != 0;
                    let mut idx: u8 = 0;
                    while idx < n {
                        let resp = send(
                            cad,
                            nid,
                            VERB_GET_CONNECTION_LIST_ENTRY,
                            idx,
                        )?;
                        if long_form {
                            // Two 16-bit entries per response.
                            connections.push((resp & 0xFF) as u8);
                            if idx + 1 < n {
                                connections.push(((resp >> 16) & 0xFF) as u8);
                            }
                            idx = idx.saturating_add(2);
                        } else {
                            // Four 8-bit entries per response.
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
                            idx = idx.saturating_add(4);
                        }
                    }
                }

                let pin_config = if matches!(caps.ty(), WidgetKind::PinComplex) {
                    Some(send(cad, nid, VERB_GET_CONFIG_DEFAULT, 0)?)
                } else {
                    None
                };

                widgets.push(CodecWidget {
                    nid,
                    caps,
                    connections,
                    pin_config,
                });
            }
        }
        function_groups.push(FunctionGroup {
            nid: fg_nid,
            group_type,
            widgets,
        });
    }

    Ok(CodecTree {
        cad,
        vendor_id,
        device_id,
        revision_id,
        function_groups,
    })
}

// ── Test stand: FakeCorb ────────────────────────────────────────────
//
// Records every verb a caller sends + replays canned responses. Used
// by codec.rs's own smokes and by realtek_alc.rs to verify the speaker
// bring-up sequence without a real HDA controller.

/// Recorded `(cad, nid, verb_id, payload)` tuple.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FakeVerb {
    pub cad: u8,
    pub nid: u8,
    pub verb_id: u16,
    pub payload: u8,
}

/// Test stand that records every verb a caller sends + replays canned
/// responses keyed off `(cad, nid, verb_id, payload)`. Sends with no
/// canned response default to 0.
#[derive(Default, Debug)]
pub struct FakeCorb {
    sent: alloc::vec::Vec<FakeVerb>,
    canned: alloc::vec::Vec<(u8, u8, u16, u8, u32)>,
}

impl FakeCorb {
    /// New empty test stand.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-program a canned response for `(cad, nid, verb_id,
    /// payload)`. If the same key is re-armed, the latest value wins.
    pub fn arm(&mut self, cad: u8, nid: u8, verb_id: u16, payload: u8, resp: u32) {
        // Overwrite any prior entry for the same key.
        for slot in self.canned.iter_mut() {
            if slot.0 == cad && slot.1 == nid && slot.2 == verb_id && slot.3 == payload {
                slot.4 = resp;
                return;
            }
        }
        self.canned.push((cad, nid, verb_id, payload, resp));
    }

    /// Convenience: arm a `Get Parameter <p>` response on `(cad, nid)`.
    pub fn arm_param(&mut self, cad: u8, nid: u8, p: u8, resp: u32) {
        self.arm(cad, nid, VERB_GET_PARAMETER, p, resp);
    }

    /// Send one verb. Records the request, returns the canned response
    /// (or 0 if none was armed).
    pub fn send(&mut self, cad: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
        self.sent.push(FakeVerb {
            cad,
            nid,
            verb_id,
            payload,
        });
        for slot in self.canned.iter() {
            if slot.0 == cad && slot.1 == nid && slot.2 == verb_id && slot.3 == payload {
                return slot.4;
            }
        }
        0
    }

    /// Recorded verbs in send order.
    pub fn log(&self) -> &[FakeVerb] {
        &self.sent
    }

    /// `true` if a verb with `(cad, nid, verb_id, payload)` was sent
    /// at any point.
    pub fn saw(&self, cad: u8, nid: u8, verb_id: u16, payload: u8) -> bool {
        self.sent.iter().any(|v| {
            v.cad == cad && v.nid == nid && v.verb_id == verb_id && v.payload == payload
        })
    }

    /// Clear the recorded log + canned responses.
    pub fn reset(&mut self) {
        self.sent.clear();
        self.canned.clear();
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[allow(clippy::module_inception)]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Verb encoder packs each field into the correct bit range, and
    /// the decoders pull each field back out unchanged.
    fn smoke_codec_verb_round_trip() -> TestResult {
        let packed = verb(0x3, 0x07, 0xF00, 0x09);
        // Expected layout: CAd in bits 31:28 = 0x3 → 0x3000_0000.
        // NID in bits 27:20 = 0x07 → 0x0070_0000. Verb 0xF00 in bits
        // 19:8 → 0x000F_F000 wait: actual placement (0xF00 << 8) =
        // 0xF_0000 = 0x000F_0000. Payload 0x09 → 0x09.
        let want = 0x3000_0000u32 | 0x0070_0000 | (0xF00u32 << 8) | 0x09;
        if packed != want {
            return TestResult::Fail("verb pack mismatch");
        }
        if cad_of(packed) != 0x3 {
            return TestResult::Fail("cad_of mismatch");
        }
        if nid_of(packed) != 0x07 {
            return TestResult::Fail("nid_of mismatch");
        }
        if verb_id_of(packed) != 0xF00 {
            return TestResult::Fail("verb_id_of mismatch");
        }
        if payload_of(packed) != 0x09 {
            return TestResult::Fail("payload_of mismatch");
        }
        // Maximum-value round trip — exercises the high bits.
        let max = verb(0xF, 0xFF, 0xFFF, 0xFF);
        if cad_of(max) != 0xF {
            return TestResult::Fail("cad_of max");
        }
        if nid_of(max) != 0xFF {
            return TestResult::Fail("nid_of max");
        }
        if verb_id_of(max) != 0xFFF {
            return TestResult::Fail("verb_id_of max");
        }
        if payload_of(max) != 0xFF {
            return TestResult::Fail("payload_of max");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/codec", smoke_codec_verb_round_trip);

    /// Widget Capabilities decoder reports the right type + flags from
    /// a canned 32-bit value. Captures the bits the path builder
    /// actually consults.
    fn smoke_codec_widget_caps_decode() -> TestResult {
        // Construct an Audio Output (type 0), stereo, with output amp:
        //   bit 0 = stereo  → 1
        //   bit 2 = out_amp → 1
        //   bits 23:20 = 0 (AudioOutput)
        let raw = 0b101u32; // stereo + out_amp; no other flags
        let caps = WidgetCaps(raw);
        if caps.ty() != WidgetKind::AudioOutput {
            return TestResult::Fail("AudioOutput type wrong");
        }
        if !caps.stereo() {
            return TestResult::Fail("stereo bit lost");
        }
        if !caps.has_out_amp() {
            return TestResult::Fail("out_amp bit lost");
        }
        if caps.has_in_amp() {
            return TestResult::Fail("spurious in_amp");
        }
        // Pin Complex with conn-list + unsol-capable (typical jack).
        let pin_raw = (4u32 << 20) | (1 << 8) | (1 << 7) | 1;
        let pin = WidgetCaps(pin_raw);
        if pin.ty() != WidgetKind::PinComplex {
            return TestResult::Fail("PinComplex type wrong");
        }
        if !pin.has_conn_list() {
            return TestResult::Fail("conn_list bit lost");
        }
        if !pin.unsol_capable() {
            return TestResult::Fail("unsol_capable bit lost");
        }
        // Channel count: stereo bit set (1) + CCE 0 → channels = 2.
        if pin.channels() != 2 {
            return TestResult::Fail("stereo channel count wrong");
        }
        // 6-channel widget: stereo=1, CCE=2 → channels = (2<<1|1)+1 = 6.
        let six = WidgetCaps((2u32 << 13) | 1);
        if six.channels() != 6 {
            return TestResult::Fail("6-channel widget count wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/codec", smoke_codec_widget_caps_decode);

    /// FakeCorb-driven enumeration walks the canned widget graph and
    /// produces the expected CodecTree.
    fn smoke_codec_enumerate_fakecorb() -> TestResult {
        let mut fake = FakeCorb::new();
        let cad = 0;
        // Root: vendor 0x10EC (Realtek), device 0x0295 (ALC295).
        fake.arm_param(cad, 0, param::VENDOR_ID, (0x10EC << 16) | 0x0295);
        fake.arm_param(cad, 0, param::REVISION_ID, 0x0010_0000);
        // One function group at NID 1.
        fake.arm_param(cad, 0, param::SUBORDINATE_NODE_COUNT, (1u32 << 16) | 1);
        // Function group: type = 1 (Audio).
        fake.arm_param(cad, 1, param::FUNCTION_GROUP_TYPE, 0x01);
        // Two widgets at NID 2..3.
        fake.arm_param(cad, 1, param::SUBORDINATE_NODE_COUNT, (2u32 << 16) | 2);
        // NID 2: Audio Output, stereo, out_amp, no conn list.
        fake.arm_param(cad, 2, param::WIDGET_CAPS, 0b101);
        // NID 3: Pin Complex, conn_list len 1 short form, points to NID 2.
        let pin_caps = (4u32 << 20) | (1 << 8) | 1;
        fake.arm_param(cad, 3, param::WIDGET_CAPS, pin_caps);
        fake.arm_param(cad, 3, param::CONNECTION_LIST_LENGTH, 1);
        fake.arm(cad, 3, VERB_GET_CONNECTION_LIST_ENTRY, 0, 0x0000_0002);
        // Pin Default Config — speaker, jack present, default association 1.
        fake.arm(cad, 3, VERB_GET_CONFIG_DEFAULT, 0, 0x9017_0110);

        let tree = enumerate_with(cad, |c, n, v, p| Ok(fake.send(c, n, v, p)))
            .expect("enumerate_with ok");
        if tree.vendor_id != 0x10EC {
            return TestResult::Fail("vendor_id wrong");
        }
        if tree.device_id != 0x0295 {
            return TestResult::Fail("device_id wrong");
        }
        if tree.function_groups.len() != 1 {
            return TestResult::Fail("function group count wrong");
        }
        let afg = match tree.audio_function_group() {
            Some(a) => a,
            None => return TestResult::Fail("no AFG present"),
        };
        if afg.widgets.len() != 2 {
            return TestResult::Fail("widget count wrong");
        }
        if afg.widgets[0].kind() != WidgetKind::AudioOutput {
            return TestResult::Fail("widget0 should be AudioOutput");
        }
        if afg.widgets[1].kind() != WidgetKind::PinComplex {
            return TestResult::Fail("widget1 should be PinComplex");
        }
        if afg.widgets[1].connections != [2] {
            return TestResult::Fail("connection list wrong");
        }
        if afg.widgets[1].pin_config != Some(0x9017_0110) {
            return TestResult::Fail("pin_config wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/codec", smoke_codec_enumerate_fakecorb);

    /// `send_verb` is well-typed against the unprobed controller — it
    /// returns `ControllerNotProbed` without panicking. This is the
    /// only path we can exercise without a real HDA backend; the
    /// `Ok` branch is covered by realtek_alc's bring-up smoke against
    /// a FakeCorb.
    fn smoke_codec_send_verb_unprobed_clean_error() -> TestResult {
        crate::hda::__reset_for_test();
        match send_verb(0, 0, VERB_GET_PARAMETER, param::VENDOR_ID) {
            Err(CodecError::ControllerNotProbed) => TestResult::Pass,
            Err(_) => TestResult::Fail("wrong error variant"),
            Ok(_) => TestResult::Fail("send_verb should have errored"),
        }
    }
    kernel_test_in!("audio/codec", smoke_codec_send_verb_unprobed_clean_error);
}
