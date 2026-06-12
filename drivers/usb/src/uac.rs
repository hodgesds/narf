//! USB Audio Class 1.0 — descriptor parsing (clean-room).
//!
//! References (public-only):
//! - "Universal Serial Bus Device Class Definition for Audio Devices"
//!   Release 1.0, March 18, 1998. Public document, usb.org.
//!   <https://www.usb.org/document-library/audio-class-document-10>
//! - "Universal Serial Bus Device Class Definition for Audio Data
//!   Formats" Release 1.0, March 18, 1998. Public, usb.org.
//!   <https://www.usb.org/document-library/audio-class-document-10>
//! - "Universal Serial Bus Specification" 2.0, §9 (standard
//!   descriptors). Public, usb.org.
//!
//! No GPL Linux source consulted.
//!
//! ## Class triple (§A.1)
//!
//! All audio interfaces share class code 0x01 (AUDIO). The
//! subclass distinguishes:
//!   - 0x01 AUDIOCONTROL (AC) — control surface (mute, volume, etc.)
//!   - 0x02 AUDIOSTREAMING (AS) — isochronous PCM/MIDI data path
//!   - 0x03 MIDISTREAMING (MS) — MIDI data path
//!
//! Protocol byte is 0x00 for UAC1; UAC2 is 0x20 (we don't decode
//! UAC2 here).
//!
//! ## Class-specific AC interface descriptor layout (§4.3.2)
//!
//! AC interfaces carry a tree of class-specific descriptors that
//! describe the device's audio topology:
//!
//! ```text
//!   bLength bDescriptorType=0x24 (CS_INTERFACE) bDescriptorSubtype ...
//! ```
//!
//! Subtype values (§A.5):
//!   - 0x01 HEADER          — bcdADC + total topology length + N collection
//!   - 0x02 INPUT_TERMINAL  — 12 bytes, defines a source
//!   - 0x03 OUTPUT_TERMINAL — 9 bytes, defines a sink
//!   - 0x04 MIXER_UNIT
//!   - 0x05 SELECTOR_UNIT
//!   - 0x06 FEATURE_UNIT    — per-channel volume/mute/etc. controls
//!
//! AS interfaces carry:
//!   - 0x01 AS_GENERAL      — terminal link + format tag (FORMAT_TYPE_I etc.)
//!   - 0x02 FORMAT_TYPE     — Type-I PCM: channels + subframe + bit-resolution
//!     + sampling-frequency table

use alloc::vec::Vec;

// ── Class triple ───────────────────────────────────────────────────

pub const USB_CLASS_AUDIO: u8 = 0x01;
pub const USB_AUDIO_SUBCLASS_AUDIOCONTROL: u8 = 0x01;
pub const USB_AUDIO_SUBCLASS_AUDIOSTREAMING: u8 = 0x02;
pub const USB_AUDIO_SUBCLASS_MIDISTREAMING: u8 = 0x03;
pub const USB_AUDIO_PROTOCOL_UAC1: u8 = 0x00;

// ── Descriptor types ───────────────────────────────────────────────

/// Class-specific interface descriptor type (§A.4).
pub const CS_INTERFACE: u8 = 0x24;
/// Class-specific endpoint descriptor type (§A.4).
pub const CS_ENDPOINT: u8 = 0x25;

// AC subtypes (§A.5).
pub const AC_SUBTYPE_HEADER: u8 = 0x01;
pub const AC_SUBTYPE_INPUT_TERMINAL: u8 = 0x02;
pub const AC_SUBTYPE_OUTPUT_TERMINAL: u8 = 0x03;
pub const AC_SUBTYPE_MIXER_UNIT: u8 = 0x04;
pub const AC_SUBTYPE_SELECTOR_UNIT: u8 = 0x05;
pub const AC_SUBTYPE_FEATURE_UNIT: u8 = 0x06;

// AS subtypes (§A.6).
pub const AS_SUBTYPE_GENERAL: u8 = 0x01;
pub const AS_SUBTYPE_FORMAT_TYPE: u8 = 0x02;

// Format tags (Audio Data Formats §A.1.1).
pub const FORMAT_TAG_PCM: u16 = 0x0001;
pub const FORMAT_TAG_PCM8: u16 = 0x0002;
pub const FORMAT_TAG_IEEE_FLOAT: u16 = 0x0003;
pub const FORMAT_TAG_ALAW: u16 = 0x0004;
pub const FORMAT_TAG_MULAW: u16 = 0x0005;

// Format type codes (Audio Data Formats §A.2).
pub const FORMAT_TYPE_I: u8 = 0x01;
pub const FORMAT_TYPE_II: u8 = 0x02;
pub const FORMAT_TYPE_III: u8 = 0x03;

// Terminal types (§A.7) — selected.
pub const TERMINAL_USB_STREAMING: u16 = 0x0101;
pub const TERMINAL_MICROPHONE: u16 = 0x0201;
pub const TERMINAL_HEADPHONES: u16 = 0x0302;
pub const TERMINAL_SPEAKER: u16 = 0x0301;
pub const TERMINAL_HEADSET: u16 = 0x0402;

// Feature-Unit control bits (§4.3.2.5, table 4-7) — per logical channel.
pub const FEATURE_MUTE: u16 = 1 << 0;
pub const FEATURE_VOLUME: u16 = 1 << 1;
pub const FEATURE_BASS: u16 = 1 << 2;
pub const FEATURE_MID: u16 = 1 << 3;
pub const FEATURE_TREBLE: u16 = 1 << 4;
pub const FEATURE_GRAPHIC_EQ: u16 = 1 << 5;
pub const FEATURE_AUTOMATIC_GAIN: u16 = 1 << 6;
pub const FEATURE_DELAY: u16 = 1 << 7;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UacError {
    /// Descriptor smaller than its mandatory header.
    Short,
    /// `bLength` claimed past the buffer end.
    Truncated,
    /// `bDescriptorType` is not `CS_INTERFACE`.
    NotClassSpecific,
    /// Unknown / unsupported subtype.
    BadSubtype(u8),
    /// Device's interface descriptors didn't include an Audio Class
    /// AudioControl interface — not a UAC device.
    NotAudio,
    /// SET_CONFIGURATION control transfer failed during bind.
    SetConfigFailed,
}

// ── Descriptor types ───────────────────────────────────────────────

/// AC HEADER descriptor (§4.3.2, table 4-2). Length = 8 + N where
/// `N = bInCollection` (number of streaming interfaces in the topology).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcHeader {
    /// bcd Audio Class spec, e.g. 0x0100 for UAC1.
    pub bcd_adc: u16,
    /// Total length of the AC interface descriptor block (header +
    /// all class-specific units that follow it).
    pub total_length: u16,
    /// Streaming interface numbers that this AC controls.
    pub in_collection: Vec<u8>,
}

impl AcHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 8 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_HEADER)?;
        let bcd_adc = u16::from_le_bytes([buf[3], buf[4]]);
        let total_length = u16::from_le_bytes([buf[5], buf[6]]);
        let n = buf[7] as usize;
        if buf.len() < 8 + n {
            return Err(UacError::Truncated);
        }
        let in_collection = buf[8..8 + n].to_vec();
        Ok(Self {
            bcd_adc,
            total_length,
            in_collection,
        })
    }
}

/// AC INPUT_TERMINAL descriptor (§4.3.2.1, table 4-3, fixed 12 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub nr_channels: u8,
    pub channel_config: u16,
    pub channel_names_idx: u8,
    pub terminal_idx: u8,
}

impl InputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 12 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_INPUT_TERMINAL)?;
        Ok(Self {
            terminal_id: buf[3],
            terminal_type: u16::from_le_bytes([buf[4], buf[5]]),
            assoc_terminal: buf[6],
            nr_channels: buf[7],
            channel_config: u16::from_le_bytes([buf[8], buf[9]]),
            channel_names_idx: buf[10],
            terminal_idx: buf[11],
        })
    }
}

/// AC OUTPUT_TERMINAL descriptor (§4.3.2.2, table 4-4, fixed 9 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub source_id: u8,
    pub terminal_idx: u8,
}

impl OutputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 9 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_OUTPUT_TERMINAL)?;
        Ok(Self {
            terminal_id: buf[3],
            terminal_type: u16::from_le_bytes([buf[4], buf[5]]),
            assoc_terminal: buf[6],
            source_id: buf[7],
            terminal_idx: buf[8],
        })
    }
}

/// AC FEATURE_UNIT descriptor (§4.3.2.5, table 4-7).
/// Length = 7 + (ch+1) * controlSize, where ch is `bNrChannels` of
/// the source (channel 0 is the master). This decoder surfaces the
/// raw control bitmaps; the caller knows the channel count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureUnit {
    pub unit_id: u8,
    pub source_id: u8,
    /// Number of bytes per control bitmap (commonly 1 or 2).
    pub control_size: u8,
    /// Per-logical-channel control bitmaps (logical 0 = master).
    /// Each entry's least-significant byte is `control_size` wide;
    /// callers OR `FEATURE_MUTE` / `FEATURE_VOLUME` etc.
    pub controls: Vec<u16>,
    pub feature_idx: u8,
}

impl FeatureUnit {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 7 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_FEATURE_UNIT)?;
        let unit_id = buf[3];
        let source_id = buf[4];
        let control_size = buf[5];
        if control_size == 0 || control_size > 2 {
            // UAC1 leaves it open; we cap at 2 bytes to keep the
            // decoder bounded.
            return Err(UacError::BadSubtype(buf[2]));
        }
        let body = &buf[6..buf.len() - 1]; // exclude iFeature trailing byte
        if body.len() % (control_size as usize) != 0 {
            return Err(UacError::Truncated);
        }
        let mut controls = Vec::new();
        for chunk in body.chunks_exact(control_size as usize) {
            let v = if control_size == 1 {
                chunk[0] as u16
            } else {
                u16::from_le_bytes([chunk[0], chunk[1]])
            };
            controls.push(v);
        }
        let feature_idx = buf[buf.len() - 1];
        Ok(Self {
            unit_id,
            source_id,
            control_size,
            controls,
            feature_idx,
        })
    }
}

/// AS_GENERAL descriptor (§4.5.2, fixed 7 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AsGeneral {
    pub terminal_link: u8,
    pub delay: u8,
    pub format_tag: u16,
}

impl AsGeneral {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 7 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AS_SUBTYPE_GENERAL)?;
        Ok(Self {
            terminal_link: buf[3],
            delay: buf[4],
            format_tag: u16::from_le_bytes([buf[5], buf[6]]),
        })
    }
}

/// AS Type-I FORMAT_TYPE descriptor (Audio Data Formats §2.2.5,
/// table 2-1). Length 8 + 3 * `nr_freqs`, with discrete frequencies
/// listed as 3-byte LE 24-bit Hz values; if `nr_freqs == 0` the
/// payload is two 3-byte values: lower + upper Hz of a continuous
/// range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatTypeI {
    pub nr_channels: u8,
    pub subframe_size: u8,
    pub bit_resolution: u8,
    /// Discrete sample rates in Hz. Empty if the device declared a
    /// continuous range; in that case `range_lower_hz` and
    /// `range_upper_hz` are set instead.
    pub sample_rates: Vec<u32>,
    pub range_lower_hz: Option<u32>,
    pub range_upper_hz: Option<u32>,
}

impl FormatTypeI {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 8 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AS_SUBTYPE_FORMAT_TYPE)?;
        if buf[3] != FORMAT_TYPE_I {
            return Err(UacError::BadSubtype(buf[3]));
        }
        let nr_channels = buf[4];
        let subframe_size = buf[5];
        let bit_resolution = buf[6];
        let nr_freqs = buf[7];

        let body = &buf[8..];
        if nr_freqs == 0 {
            if body.len() < 6 {
                return Err(UacError::Truncated);
            }
            let lo = decode_24le(&body[0..3]);
            let hi = decode_24le(&body[3..6]);
            Ok(Self {
                nr_channels,
                subframe_size,
                bit_resolution,
                sample_rates: Vec::new(),
                range_lower_hz: Some(lo),
                range_upper_hz: Some(hi),
            })
        } else {
            let need = (nr_freqs as usize) * 3;
            if body.len() < need {
                return Err(UacError::Truncated);
            }
            let mut sample_rates = Vec::with_capacity(nr_freqs as usize);
            for chunk in body[..need].chunks_exact(3) {
                sample_rates.push(decode_24le(chunk));
            }
            Ok(Self {
                nr_channels,
                subframe_size,
                bit_resolution,
                sample_rates,
                range_lower_hz: None,
                range_upper_hz: None,
            })
        }
    }
}

fn decode_24le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn check_class_specific(buf: &[u8], expect_subtype: u8) -> Result<(), UacError> {
    if buf.len() < 3 {
        return Err(UacError::Short);
    }
    let length = buf[0] as usize;
    if length > buf.len() {
        return Err(UacError::Truncated);
    }
    if buf[1] != CS_INTERFACE {
        return Err(UacError::NotClassSpecific);
    }
    if buf[2] != expect_subtype {
        return Err(UacError::BadSubtype(buf[2]));
    }
    Ok(())
}

// ── Class enumeration + bind ───────────────────────────────────────
//
// Minimal "is this a UAC device, and if so claim it" path. The
// full streaming surface (iso playback / capture rings) is a
// follow-up — this commit makes the device visible in the
// registry so it stops being logged as UnknownClass.

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

/// One bound UAC device — slot id + AudioControl interface number.
/// The streaming-interface enumeration + iso endpoint open lives
/// behind this once the iso path lands.
#[derive(Copy, Clone, Debug)]
pub struct UacDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the AudioControl interface.
    pub ac_iface: u8,
    /// DCI of the iso-OUT endpoint (playback). 0 = no playback EP
    /// found in the descriptor.
    pub iso_out_dci: u8,
    /// DCI of the iso-IN endpoint (capture / microphone). 0 = none.
    pub iso_in_dci: u8,
}

/// System-wide registry of bound UAC devices.
pub static UAC_DEVICES: IrqSafeSpinLock<Vec<UacDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Walk a configuration descriptor blob looking for the first
/// interface whose `bInterfaceClass:SubClass` matches Audio /
/// AudioControl (UAC's required "control" interface). Returns
/// `bInterfaceNumber` on a match.
pub fn find_audio_control_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        // bDescriptorType 0x04 = INTERFACE; length 9.
        if cfg[i + 1] == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            if cls == USB_CLASS_AUDIO && sub == USB_AUDIO_SUBCLASS_AUDIOCONTROL {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}

/// Bind to an already-addressed UAC device. Issues SET_CONFIGURATION
/// so the device exits Default state, then records the slot/interface
/// pair in UAC_DEVICES. Returns the new index on success.
pub async fn try_bind_audio_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, UacError> {
    let ac_iface = find_audio_control_interface(cfg).ok_or(UacError::NotAudio)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    let mut nothing = [0u8; 0];
    if xhci_dev
        .control_in(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &mut nothing,
        )
        .await
        .is_err()
    {
        return Err(UacError::SetConfigFailed);
    }
    // Find iso endpoints in any AudioStreaming alt setting. May be
    // absent (UAC AudioControl-only devices like USB volume knobs);
    // in that case the iso DCIs stay 0.
    let (iso_out_dci, iso_in_dci) = find_audio_streaming_iso_eps(cfg);
    let mut g = UAC_DEVICES.lock();
    let idx = g.len();
    g.push(UacDevice {
        slot_id,
        ac_iface,
        iso_out_dci,
        iso_in_dci,
    });
    Ok(idx)
}

/// Scan the config blob for the first AudioStreaming interface's
/// iso endpoints. Returns (iso_out_dci, iso_in_dci) — either may
/// be 0 if not present. Note this picks the *first* AS interface
/// alt setting it sees — real bind would walk all alt settings
/// + pick one matching the desired sample rate / channel count.
pub fn find_audio_streaming_iso_eps(cfg: &[u8]) -> (u8, u8) {
    let mut i = 0;
    let mut in_as_iface = false;
    let mut iso_out: u8 = 0;
    let mut iso_in: u8 = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE: check AS class triple.
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            in_as_iface = cls == USB_CLASS_AUDIO && sub == USB_AUDIO_SUBCLASS_AUDIOSTREAMING;
        } else if desc_type == 0x05 && in_as_iface && len >= 7 {
            // ENDPOINT under an AS interface — check iso (xfer type 1).
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            if attrs & 0x03 == 1 {
                let ep_num = ep_addr & 0x0F;
                let is_in = ep_addr & 0x80 != 0;
                let dci = (ep_num * 2) + (if is_in { 1 } else { 0 });
                if is_in && iso_in == 0 {
                    iso_in = dci;
                } else if !is_in && iso_out == 0 {
                    iso_out = dci;
                }
            }
        }
        i += len;
    }
    (iso_out, iso_in)
}

/// Submit one PCM packet to the bound UAC device's iso-OUT endpoint
/// (playback). Caller's `data` must be audio-frame-aligned per the
/// device's PcmFormat. Returns the number of bytes actually written
/// (may be short on an oversubscribed iso frame).
pub fn playback_one_packet(idx: usize, data: &[u8]) -> Result<usize, UacError> {
    let (slot_id, dci) = {
        let g = UAC_DEVICES.lock();
        let dev = g.get(idx).ok_or(UacError::NotAudio)?;
        if dev.iso_out_dci == 0 {
            return Err(UacError::NotAudio);
        }
        (dev.slot_id, dev.iso_out_dci)
    };
    // Sync entry-point on the UAC playback path; bridge to async
    // isoch_out via block_on. Called from non-executor contexts.
    let c = match crate::xhci::controller() {
        Some(c) => c,
        None => return Err(UacError::SetConfigFailed),
    };
    let outcome = narf_scheduler::block_on(async { c.isoch_out(slot_id, dci, data).await });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(UacError::SetConfigFailed),
    }
}

/// Pull one PCM capture packet from the bound UAC device's iso-IN
/// endpoint (microphone). Returns the byte count actually read.
pub fn capture_one_packet(idx: usize, out: &mut [u8]) -> Result<usize, UacError> {
    let (slot_id, dci) = {
        let g = UAC_DEVICES.lock();
        let dev = g.get(idx).ok_or(UacError::NotAudio)?;
        if dev.iso_in_dci == 0 {
            return Err(UacError::NotAudio);
        }
        (dev.slot_id, dev.iso_in_dci)
    };
    // Sync entry-point on the UAC capture path; bridge to async
    // isoch_in via block_on.
    let c = match crate::xhci::controller() {
        Some(c) => c,
        None => return Err(UacError::SetConfigFailed),
    };
    let outcome = narf_scheduler::block_on(async { c.isoch_in(slot_id, dci, out).await });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(UacError::SetConfigFailed),
    }
}

/// Number of bound UAC devices.
pub fn attached_uac_count() -> usize {
    UAC_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_uac_for_test() {
    UAC_DEVICES.lock().clear();
}

// ── Sample-rate class request (§5.2.2.1.2) ─────────────────────────
//
// UAC1 endpoints expose a SAMPLING_FREQUENCY_CONTROL the host
// programs via class-specific SET_CUR on the endpoint:
//
//   bmRequestType = 0x22 (host→device, class, endpoint)
//   bRequest = SET_CUR (0x01) or GET_CUR (0x81)
//   wValue = (SAMPLING_FREQUENCY_CONTROL << 8) | 0
//   wIndex = endpoint address
//   wLength = 3
//   data = sample rate in Hz, little-endian, 24-bit
//
// 48 kHz = 0x00BB80, 44.1 kHz = 0x00AC44, 96 kHz = 0x017700.

/// `SET_CUR` class request code.
pub const REQ_SET_CUR: u8 = 0x01;
/// `GET_CUR` class request code.
pub const REQ_GET_CUR: u8 = 0x81;
/// Control selector for sampling-frequency endpoint control.
pub const SAMPLING_FREQUENCY_CONTROL: u8 = 0x01;

/// Encode a sampling frequency for SET_CUR data payload. UAC1
/// uses a 24-bit little-endian integer (3 bytes).
pub fn encode_sampling_freq(hz: u32) -> [u8; 3] {
    [
        (hz & 0xFF) as u8,
        ((hz >> 8) & 0xFF) as u8,
        ((hz >> 16) & 0xFF) as u8,
    ]
}

/// Decode a 24-bit LE sampling frequency from a GET_CUR response.
pub fn decode_sampling_freq(buf: &[u8]) -> Option<u32> {
    if buf.len() < 3 {
        return None;
    }
    Some((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16))
}

// ── Feature Unit control requests (§5.2.2.4) ───────────────────────
//
// The host programs Feature Unit controls (volume, mute, bass, …)
// via class-specific requests on the AC interface:
//
//   bmRequestType = 0x21 (host→device, class, interface)
//   bRequest = SET_CUR (0x01) / GET_CUR (0x81) / GET_MIN (0x82) / GET_MAX (0x83)
//   wValue = (ControlSelector << 8) | LogicalChannelNumber
//   wIndex = (FeatureUnitID << 8) | InterfaceNumber
//   wLength = 1 (mute) or 2 (volume / bass / treble)
//
// Volume is a signed 16-bit fixed-point value in 1/256 dB units
// (UAC1 §5.2.2.4.3). Mute is a single byte: 0 = unmuted, 1 = muted.

/// Feature Unit control selector codes (§A.10.2).
pub const FU_CS_MUTE: u8 = 0x01;
pub const FU_CS_VOLUME: u8 = 0x02;
pub const FU_CS_BASS: u8 = 0x03;
pub const FU_CS_MID: u8 = 0x04;
pub const FU_CS_TREBLE: u8 = 0x05;

/// Logical channel number 0 = master; 1..=N = per-channel.
pub const CHANNEL_MASTER: u8 = 0x00;

/// Encode the `wValue` field for a Feature Unit control request:
/// `(control_selector << 8) | channel`.
pub const fn fu_wvalue(cs: u8, channel: u8) -> u16 {
    ((cs as u16) << 8) | (channel as u16)
}

/// Encode the `wIndex` field: `(feature_unit_id << 8) | iface_number`.
pub const fn fu_windex(unit_id: u8, iface: u8) -> u16 {
    ((unit_id as u16) << 8) | (iface as u16)
}

/// Encode a volume SET_CUR data payload (2-byte signed LE).
///
/// `db_256` is the desired volume in 1/256 dB units (UAC1 §5.2.2.4.3).
/// For example −6 dB = −1536 (i.e. −6 × 256). The silent minimum
/// reported by GET_MIN is typically 0x8000 (= −128 dB) and 0x0000 is
/// 0 dB (unity gain); headsets often top out at 0x0000.
pub fn encode_volume(db_256: i16) -> [u8; 2] {
    (db_256 as u16).to_le_bytes()
}

/// Decode a volume GET_CUR / GET_MIN / GET_MAX response (2-byte LE).
pub fn decode_volume(buf: &[u8]) -> Option<i16> {
    if buf.len() < 2 {
        return None;
    }
    Some(i16::from_le_bytes([buf[0], buf[1]]))
}

/// Encode a mute SET_CUR payload. `mute = true` silences the channel.
pub fn encode_mute(mute: bool) -> [u8; 1] {
    [mute as u8]
}

/// Decode a mute GET_CUR response. Returns `None` if buf is empty.
pub fn decode_mute(buf: &[u8]) -> Option<bool> {
    buf.first().map(|&b| b != 0)
}

// ── PCM frame ring ─────────────────────────────────────────────────
//
// Holds enqueued PCM samples for playback or just-captured samples
// for record. The xHCI iso ring submits/consumes one "iso packet" of
// N samples per service interval; this buffer queues whole packets'
// worth of samples behind the ring.

/// Format of one PCM sample as carried over the iso endpoint.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcmFormat {
    /// Number of channels per frame (1 = mono, 2 = stereo, 6 = 5.1).
    pub channels: u8,
    /// Bytes per sample per channel (2 = 16-bit, 3 = 24-bit packed,
    /// 4 = 32-bit). UAC1 calls this `bSubframeSize`.
    pub bytes_per_sample: u8,
    /// Bit depth (16, 24, 32). UAC1 calls this `bBitResolution` and
    /// it can be less than `bytes_per_sample * 8` — e.g. 24-bit
    /// data packed into 4-byte subframes.
    pub bit_depth: u8,
}

impl PcmFormat {
    /// Bytes per PCM "audio frame" (= one sample on every channel).
    pub fn audio_frame_bytes(&self) -> usize {
        self.channels as usize * self.bytes_per_sample as usize
    }

    /// Iso-packet size in bytes for `audio_frames_per_packet` frames.
    pub fn iso_packet_bytes(&self, audio_frames_per_packet: usize) -> usize {
        self.audio_frame_bytes() * audio_frames_per_packet
    }
}

/// Errors from the PCM ring layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PcmError {
    /// Caller asked to enqueue an audio-frame-boundary-misaligned
    /// byte count (would split a frame across iso packets).
    Misaligned,
    /// Ring is full — caller should wait + retry.
    Full,
    /// Ring is empty.
    Empty,
}

/// Lock-free-ish PCM byte ring. Producer writes audio-frame-
/// aligned chunks via `push`; consumer reads same-aligned chunks
/// via `pop`. Wrapping is by byte index, not audio-frame count.
#[derive(Debug)]
pub struct PcmRing {
    pub format: PcmFormat,
    /// Backing storage (Vec to side-step boot-time MEM init order).
    storage: Vec<u8>,
    head: usize, // next byte to read
    tail: usize, // next byte to write
    /// Filled byte count — `head + filled == tail (mod len)`.
    filled: usize,
}

impl PcmRing {
    /// Allocate a ring with `capacity_bytes` of storage. Capacity
    /// is rounded UP to a multiple of `format.audio_frame_bytes()`
    /// so push/pop are always frame-aligned.
    pub fn new(format: PcmFormat, capacity_bytes: usize) -> Self {
        let frame = format.audio_frame_bytes().max(1);
        let rounded = capacity_bytes.div_ceil(frame) * frame;
        Self {
            format,
            storage: alloc::vec![0u8; rounded],
            head: 0,
            tail: 0,
            filled: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    pub fn filled(&self) -> usize {
        self.filled
    }

    pub fn free(&self) -> usize {
        self.storage.len() - self.filled
    }

    /// Push audio-frame-aligned bytes. Returns Misaligned on a
    /// fractional-frame `data.len()`, Full when there isn't room.
    pub fn push(&mut self, data: &[u8]) -> Result<(), PcmError> {
        let frame = self.format.audio_frame_bytes();
        if frame == 0 || data.len() % frame != 0 {
            return Err(PcmError::Misaligned);
        }
        if data.len() > self.free() {
            return Err(PcmError::Full);
        }
        let cap = self.storage.len();
        for &b in data {
            self.storage[self.tail] = b;
            self.tail = (self.tail + 1) % cap;
        }
        self.filled += data.len();
        Ok(())
    }

    /// Pop up to `out.len()` bytes (must be a multiple of audio-frame
    /// bytes). Returns the number actually moved.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<usize, PcmError> {
        let frame = self.format.audio_frame_bytes();
        if frame == 0 || out.len() % frame != 0 {
            return Err(PcmError::Misaligned);
        }
        if self.filled == 0 {
            return Err(PcmError::Empty);
        }
        let n = out.len().min(self.filled);
        let cap = self.storage.len();
        for slot in out.iter_mut().take(n) {
            *slot = self.storage[self.head];
            self.head = (self.head + 1) % cap;
        }
        self.filled -= n;
        Ok(n)
    }
}

pub static UAC_MATCH: [crate::class_registry::UsbClassMatch; 1] =
    [crate::class_registry::UsbClassMatch::class_only(
        USB_CLASS_AUDIO,
    )];

pub fn probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "  usb: USB Audio Class (UAC) device bound!"
    );
    Ok(())
}

pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver("snd-usb-audio", &UAC_MATCH, probe);
}
