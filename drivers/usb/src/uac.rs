//! USB Audio Class 1.0 / 2.0 — descriptor parsing, topology walk,
//! bind conversation, and sound-card publication (clean-room).
//!
//! References (public-only):
//! - "Universal Serial Bus Device Class Definition for Audio Devices"
//!   Release 1.0, March 18, 1998. Public document, usb.org.
//!   <https://www.usb.org/document-library/audio-class-document-10>
//! - "Universal Serial Bus Device Class Definition for Audio Devices"
//!   Release 2.0, May 31, 2006. Public document, usb.org.
//!   <https://www.usb.org/document-library/audio-class-document-20>
//! - "Universal Serial Bus Device Class Definition for Audio Data
//!   Formats" Release 1.0 / 2.0. Public, usb.org.
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
//! Protocol byte is 0x00 for UAC1 and 0x20 for UAC2; both are
//! decoded here (the v2 AC/AS descriptor layouts and the v2 clock
//! entity model live below the v1 decoders).
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
pub const USB_AUDIO_PROTOCOL_UAC2: u8 = 0x20;

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

// ── UAC2 class-specific descriptors (Release 2.0) ──────────────────
//
// The v2 AC block reuses the v1 subtype numbering for HEADER /
// INPUT_TERMINAL / OUTPUT_TERMINAL / FEATURE_UNIT with wider
// layouts, and adds the clock entity family that replaces the v1
// endpoint sampling-frequency control:
//   - 0x0A CLOCK_SOURCE    — the programmable (or fixed) clock
//   - 0x0B CLOCK_SELECTOR  — picks one of N source pins
//   - 0x0C CLOCK_MULTIPLIER — derives a rate from another clock

/// AC subtype: CLOCK_SOURCE (UAC2 §4.7.2.10).
pub const AC_SUBTYPE_CLOCK_SOURCE: u8 = 0x0A;
/// AC subtype: CLOCK_SELECTOR (UAC2 §4.7.2.11).
pub const AC_SUBTYPE_CLOCK_SELECTOR: u8 = 0x0B;
/// AC subtype: CLOCK_MULTIPLIER (UAC2 §4.7.2.12).
pub const AC_SUBTYPE_CLOCK_MULTIPLIER: u8 = 0x0C;

/// Sampling-frequency control selector for clock entities (UAC2
/// §5.2.2): SET_CUR / GET_CUR / GET_RANGE address it on the AC
/// interface with `wIndex = (clock_id << 8) | interface`.
pub const CLOCK_CS_SAMPLING_FREQUENCY: u8 = 0x01;
/// UAC2 class request: RANGE (returns subranges for a control).
pub const REQ_RANGE: u8 = 0x02;
/// UAC2 class request: CUR.
pub const REQ_CUR: u8 = 0x01;

/// UAC2 AC HEADER descriptor (§4.7.2). Unlike v1 there is no
/// interface collection list — every AS interface in the
/// configuration belongs to the single AC interface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AcHeader2 {
    /// bcd Audio Class spec — 0x0200 for UAC2.
    pub bcd_adc: u16,
    /// Device category (function code, e.g. 0x05 = headset).
    pub category: u8,
    /// Total length of the AC descriptor block.
    pub total_length: u16,
    /// Latency / sync control bitmap.
    pub controls: u8,
}

impl AcHeader2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 9 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_HEADER)?;
        Ok(Self {
            bcd_adc: u16::from_le_bytes([buf[3], buf[4]]),
            category: buf[5],
            total_length: u16::from_le_bytes([buf[6], buf[7]]),
            controls: buf[8],
        })
    }
}

/// UAC2 INPUT_TERMINAL descriptor (§4.7.2.4). The fields this
/// driver consumes (id, type, association, source, channel count)
/// sit at the same leading offsets the v2 layout shares with the
/// walker's expectations; trailing clock-control fields are
/// informational here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InputTerminal2 {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub nr_channels: u8,
    pub channel_config: u32,
    /// `bmControls` — copy-protect / connector / overload bits.
    pub controls: u16,
}

impl InputTerminal2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 16 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_INPUT_TERMINAL)?;
        Ok(Self {
            terminal_id: buf[3],
            terminal_type: u16::from_le_bytes([buf[4], buf[5]]),
            assoc_terminal: buf[6],
            nr_channels: buf[7],
            channel_config: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            controls: u16::from_le_bytes([buf[13], buf[14]]),
        })
    }
}

/// UAC2 OUTPUT_TERMINAL descriptor (§4.7.2.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutputTerminal2 {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub source_id: u8,
    pub controls: u16,
}

impl OutputTerminal2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 10 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_OUTPUT_TERMINAL)?;
        Ok(Self {
            terminal_id: buf[3],
            terminal_type: u16::from_le_bytes([buf[4], buf[5]]),
            assoc_terminal: buf[6],
            source_id: buf[7],
            controls: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }
}

/// UAC2 FEATURE_UNIT descriptor (§4.7.2.8). Control bitmaps are
/// 4 bytes per logical channel (channel 0 = master), in the same
/// bit positions as v1 (bit 0 mute, bit 1 volume, …).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureUnit2 {
    pub unit_id: u8,
    pub source_id: u8,
    /// Per-logical-channel control bitmaps (u32 each).
    pub controls: Vec<u32>,
}

impl FeatureUnit2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 6 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_FEATURE_UNIT)?;
        let body = &buf[5..buf.len() - 1]; // exclude trailing iFeature
        if body.len() % 4 != 0 {
            return Err(UacError::Truncated);
        }
        let mut controls = Vec::new();
        for chunk in body.chunks_exact(4) {
            controls.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        Ok(Self {
            unit_id: buf[3],
            source_id: buf[4],
            controls,
        })
    }

    /// Master-channel (logical channel 0) control bitmap, widened
    /// to the v1 `u16` shape the shared bind/card code consumes.
    pub fn master_controls(&self) -> u16 {
        self.controls.first().map(|c| *c as u16).unwrap_or(0)
    }
}

/// UAC2 CLOCK_SOURCE descriptor (§4.7.2.10, fixed 8 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClockSource {
    pub clock_id: u8,
    /// `bmAttributes`: clock type (0 internal fixed, 1 internal
    /// variable, 2 internal programmable, 3 external).
    pub attributes: u8,
    /// `bmControls` — see `CLOCK_CTRL_*` (2 bits per control).
    pub controls: u8,
    pub assoc_terminal: u8,
}

impl ClockSource {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 8 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_CLOCK_SOURCE)?;
        Ok(Self {
            clock_id: buf[3],
            attributes: buf[4],
            controls: buf[5],
            assoc_terminal: buf[6],
        })
    }

    /// True when the host may program the sampling frequency
    /// (bmControls field for control 1 (frequency) == 0b10 read/
    /// write in its low two bits, per table 4-36 encoding where
    /// each control occupies 2 bits: bits [1:0] = frequency).
    pub fn freq_programmable(&self) -> bool {
        self.controls & 0x03 == 0x03 || self.controls & 0x02 != 0
    }
}

/// UAC2 CLOCK_SELECTOR descriptor (§4.7.2.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockSelector {
    pub clock_id: u8,
    /// Source clock IDs, one per input pin.
    pub pins: Vec<u8>,
    pub controls: u8,
}

impl ClockSelector {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 5 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_CLOCK_SELECTOR)?;
        let n = buf[4] as usize;
        if buf.len() < 5 + n + 2 {
            return Err(UacError::Truncated);
        }
        Ok(Self {
            clock_id: buf[3],
            pins: buf[5..5 + n].to_vec(),
            controls: buf[5 + n],
        })
    }
}

/// UAC2 CLOCK_MULTIPLIER descriptor (§4.7.2.12). Only the graph
/// edge (which clock it derives from) is consumed here; the
/// numerator/denominator controls are programmed by the device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClockMultiplier {
    pub clock_id: u8,
    pub source_clock_id: u8,
}

impl ClockMultiplier {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 5 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AC_SUBTYPE_CLOCK_MULTIPLIER)?;
        Ok(Self {
            clock_id: buf[3],
            source_clock_id: buf[4],
        })
    }
}

/// UAC2 AS_GENERAL descriptor (§4.8.2.1, fixed 16 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AsGeneral2 {
    pub terminal_link: u8,
    pub controls: u8,
    pub format_type: u8,
    /// `bmFormats` bitmask (bit 0 = PCM, 1 = PCM8, 2 = IEEE_FLOAT,
    /// 3 = ALAW, 4 = MULAW).
    pub formats: u32,
    pub nr_channels: u8,
    pub channel_config: u32,
}

impl AsGeneral2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 16 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AS_SUBTYPE_GENERAL)?;
        Ok(Self {
            terminal_link: buf[3],
            controls: buf[4],
            format_type: buf[5],
            formats: u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]),
            nr_channels: buf[10],
            channel_config: u32::from_le_bytes([buf[11], buf[12], buf[13], buf[14]]),
        })
    }
}

/// UAC2 Type-I FORMAT_TYPE descriptor (§3.6.1 of the Formats
/// document, fixed 6 bytes): subslot size + bit resolution; the
/// sampling frequency lives on the clock entity, not here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FormatTypeI2 {
    pub subslot_size: u8,
    pub bit_resolution: u8,
}

impl FormatTypeI2 {
    pub fn parse(buf: &[u8]) -> Result<Self, UacError> {
        if buf.len() < 6 {
            return Err(UacError::Short);
        }
        check_class_specific(buf, AS_SUBTYPE_FORMAT_TYPE)?;
        if buf[3] != FORMAT_TYPE_I {
            return Err(UacError::BadSubtype(buf[3]));
        }
        Ok(Self {
            subslot_size: buf[4],
            bit_resolution: buf[5],
        })
    }
}

/// One sampling-frequency subrange from a UAC2 RANGE response:
/// the clock accepts `min + k * res` up to `max`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClockSubrange {
    pub min_hz: u32,
    pub max_hz: u32,
    pub res_hz: u32,
}

/// Parse a UAC2 RANGE response for the sampling-frequency
/// control: `wNumSubRanges` (u16) followed by that many
/// `{dMIN, dMAX, dRES}` u32 triplets.
pub fn parse_clock_ranges(buf: &[u8]) -> Vec<ClockSubrange> {
    let mut out = Vec::new();
    if buf.len() < 2 {
        return out;
    }
    let n = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let mut off = 2;
    for _ in 0..n {
        if off + 12 > buf.len() {
            break;
        }
        let rd = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        out.push(ClockSubrange {
            min_hz: rd(off),
            max_hz: rd(off + 4),
            res_hz: rd(off + 8),
        });
        off += 12;
    }
    out
}

/// Choose the rate to program from the advertised subranges:
/// prefer exactly 48 kHz when a subrange admits it (respecting
/// the resolution grid), else 44.1 kHz, else the lowest admitted
/// rate. `None` when the clock admits nothing.
pub fn choose_clock_rate(ranges: &[ClockSubrange]) -> Option<u32> {
    let admits = |hz: u32| -> bool {
        ranges.iter().any(|r| {
            hz >= r.min_hz && hz <= r.max_hz && (r.res_hz == 0 || (hz - r.min_hz) % r.res_hz == 0)
        })
    };
    if admits(48_000) {
        return Some(48_000);
    }
    if admits(44_100) {
        return Some(44_100);
    }
    ranges.iter().map(|r| r.min_hz).min()
}

// ── Unified topology ───────────────────────────────────────────────
//
// One version-tagged model the bind plan and the sound card are
// both built from. The walker composes the per-descriptor parsers
// above over a whole configuration blob.

/// Which Audio Class revision a device speaks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UacVersion {
    V1,
    V2,
}

/// A terminal in the AC topology (either revision, unified).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UacTerminal {
    pub id: u8,
    pub terminal_type: u16,
    /// For output terminals: the unit/terminal feeding this one.
    /// Zero for input terminals.
    pub source_id: u8,
    pub is_input: bool,
    pub nr_channels: u8,
}

/// A Feature Unit in the AC topology (either revision).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacFeatureUnit {
    pub id: u8,
    pub source_id: u8,
    /// Master-channel control bitmap (FEATURE_MUTE / FEATURE_VOLUME
    /// bits), widened from either revision's layout.
    pub master_controls: u16,
    /// Number of logical channels with control bitmaps (including
    /// the master channel at index 0).
    pub channels: u8,
}

/// A clock entity (UAC2 only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacClock {
    pub id: u8,
    pub kind: UacClockKind,
    /// For a source: whether SET_CUR frequency is accepted.
    pub freq_programmable: bool,
    /// Terminal this clock is associated with (source only).
    pub assoc_terminal: u8,
    /// For selectors: candidate source clock IDs.
    pub pins: Vec<u8>,
    /// For multipliers: the clock it derives from.
    pub derives_from: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UacClockKind {
    Source,
    Selector,
    Multiplier,
}

/// The PCM shape of one alternate setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacAltFormat {
    pub channels: u8,
    pub subframe_size: u8,
    pub bit_resolution: u8,
    /// UAC1: discrete rates from FORMAT_TYPE (empty = continuous,
    /// see `range`). UAC2: always empty — rates live on the clock.
    pub rates: Vec<u32>,
    /// UAC1 continuous range (lower, upper).
    pub range: Option<(u32, u32)>,
}

/// One alternate setting of a streaming interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacAlt {
    pub alt_setting: u8,
    pub format: Option<UacAltFormat>,
    /// Iso endpoint address (0 = this alt has no endpoint, the
    /// zero-bandwidth alt 0 shape).
    pub ep_addr: u8,
    pub ep_max_packet: u16,
    pub ep_interval: u8,
    /// Sampling-frequency control present on the endpoint
    /// (CS_ENDPOINT bmAttributes bit 0; assumed true when the
    /// device carries no CS_ENDPOINT descriptor).
    pub ep_freq_control: bool,
}

impl UacAlt {
    /// Endpoint Control Sequence ID on the xHCI — `(ep * 2) + dir`.
    pub fn dci(&self) -> u8 {
        let ep = self.ep_addr & 0x0F;
        let is_in = self.ep_addr & 0x80 != 0;
        (ep * 2) + (if is_in { 1 } else { 0 })
    }
    pub fn is_capture_ep(&self) -> bool {
        self.ep_addr & 0x80 != 0
    }
}

/// One AudioStreaming interface with all of its alt settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacStream {
    pub iface: u8,
    /// Terminal (in the AC topology) this stream connects to.
    pub terminal_link: u8,
    pub alts: Vec<UacAlt>,
}

impl UacStream {
    /// Direction from the first endpoint-bearing alt: an IN
    /// endpoint means the device sends audio (capture).
    pub fn is_capture(&self) -> Option<bool> {
        self.alts
            .iter()
            .find(|a| a.ep_addr != 0)
            .map(|a| a.is_capture_ep())
    }
}

/// A whole device's parsed audio topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacTopology {
    pub version: UacVersion,
    pub ac_iface: u8,
    pub terminals: Vec<UacTerminal>,
    pub feature_units: Vec<UacFeatureUnit>,
    pub clocks: Vec<UacClock>,
    pub streams: Vec<UacStream>,
}

impl UacTopology {
    /// Walk a configuration descriptor blob and build the
    /// topology. Finds the AC interface first (its protocol byte
    /// selects the v1/v2 layouts), then decodes the AC block and
    /// every AS interface's alt settings.
    pub fn parse(cfg: &[u8]) -> Result<Self, UacError> {
        // First pass: locate the AC interface + its protocol.
        let mut version = UacVersion::V1;
        let mut ac_iface = None;
        let mut i = 0;
        while i + 2 <= cfg.len() {
            let len = cfg[i] as usize;
            if len < 2 || i + len > cfg.len() {
                break;
            }
            if cfg[i + 1] == 0x04 && len >= 9 {
                let (num, _alt, cls, sub, proto) =
                    (cfg[i + 2], cfg[i + 3], cfg[i + 5], cfg[i + 6], cfg[i + 7]);
                if cls == USB_CLASS_AUDIO && sub == USB_AUDIO_SUBCLASS_AUDIOCONTROL {
                    ac_iface = Some(num);
                    version = if proto == USB_AUDIO_PROTOCOL_UAC2 {
                        UacVersion::V2
                    } else {
                        UacVersion::V1
                    };
                    break;
                }
            }
            i += len;
        }
        let ac_iface = ac_iface.ok_or(UacError::NotAudio)?;

        let mut topo = UacTopology {
            version,
            ac_iface,
            terminals: Vec::new(),
            feature_units: Vec::new(),
            clocks: Vec::new(),
            streams: Vec::new(),
        };

        // Second pass: decode everything, tracking the current
        // interface / alt setting.
        #[derive(PartialEq)]
        enum Ctx {
            None,
            Ac,
            As,
            Other,
        }
        let mut ctx = Ctx::None;
        let mut cur_stream: Option<usize> = None; // index into topo.streams
        let mut i = 0;
        while i + 2 <= cfg.len() {
            let len = cfg[i] as usize;
            if len < 2 || i + len > cfg.len() {
                break;
            }
            let desc = &cfg[i..i + len];
            let dtype = desc[1];
            match dtype {
                0x04 if len >= 9 => {
                    // INTERFACE
                    let (num, alt, cls, sub) = (desc[2], desc[3], desc[5], desc[6]);
                    if cls == USB_CLASS_AUDIO && sub == USB_AUDIO_SUBCLASS_AUDIOCONTROL {
                        ctx = Ctx::Ac;
                        cur_stream = None;
                    } else if cls == USB_CLASS_AUDIO && sub == USB_AUDIO_SUBCLASS_AUDIOSTREAMING {
                        ctx = Ctx::As;
                        // One UacStream per interface number; alt
                        // settings append to it.
                        let idx = match topo.streams.iter().position(|s| s.iface == num) {
                            Some(p) => p,
                            None => {
                                topo.streams.push(UacStream {
                                    iface: num,
                                    terminal_link: 0,
                                    alts: Vec::new(),
                                });
                                topo.streams.len() - 1
                            }
                        };
                        topo.streams[idx].alts.push(UacAlt {
                            alt_setting: alt,
                            format: None,
                            ep_addr: 0,
                            ep_max_packet: 0,
                            ep_interval: 0,
                            ep_freq_control: true,
                        });
                        cur_stream = Some(idx);
                    } else {
                        ctx = Ctx::Other;
                        cur_stream = None;
                    }
                }
                0x24 if ctx == Ctx::Ac => {
                    topo.parse_ac_descriptor(desc);
                }
                0x24 if ctx == Ctx::As => {
                    if let Some(si) = cur_stream {
                        topo.parse_as_descriptor(si, desc);
                    }
                }
                0x05 if ctx == Ctx::As && len >= 7 => {
                    // ENDPOINT under the current alt.
                    if let Some(si) = cur_stream {
                        let attrs = desc[3];
                        if attrs & 0x03 == 0x01 {
                            // Isochronous.
                            let alt = topo.streams[si].alts.last_mut().unwrap();
                            alt.ep_addr = desc[2];
                            alt.ep_max_packet = u16::from_le_bytes([desc[4], desc[5]]);
                            alt.ep_interval = desc[6];
                        }
                    }
                }
                0x25 if ctx == Ctx::As && len >= 3 => {
                    // CS_ENDPOINT (EP_GENERAL): bmAttributes bit 0
                    // = sampling-frequency control.
                    if let Some(si) = cur_stream {
                        if desc[2] == 0x01 {
                            let alt = topo.streams[si].alts.last_mut().unwrap();
                            alt.ep_freq_control = desc[3] & 0x01 != 0;
                        }
                    }
                }
                _ => {}
            }
            i += len;
        }
        Ok(topo)
    }

    fn parse_ac_descriptor(&mut self, desc: &[u8]) {
        if desc.len() < 3 {
            return;
        }
        match (self.version, desc[2]) {
            (UacVersion::V1, AC_SUBTYPE_INPUT_TERMINAL) => {
                if let Ok(t) = InputTerminal::parse(desc) {
                    self.terminals.push(UacTerminal {
                        id: t.terminal_id,
                        terminal_type: t.terminal_type,
                        source_id: 0,
                        is_input: true,
                        nr_channels: t.nr_channels,
                    });
                }
            }
            (UacVersion::V1, AC_SUBTYPE_OUTPUT_TERMINAL) => {
                if let Ok(t) = OutputTerminal::parse(desc) {
                    self.terminals.push(UacTerminal {
                        id: t.terminal_id,
                        terminal_type: t.terminal_type,
                        source_id: t.source_id,
                        is_input: false,
                        nr_channels: 0,
                    });
                }
            }
            (UacVersion::V1, AC_SUBTYPE_FEATURE_UNIT) => {
                if let Ok(f) = FeatureUnit::parse(desc) {
                    self.feature_units.push(UacFeatureUnit {
                        id: f.unit_id,
                        source_id: f.source_id,
                        master_controls: f.controls.first().copied().unwrap_or(0),
                        channels: f.controls.len() as u8,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_INPUT_TERMINAL) => {
                if let Ok(t) = InputTerminal2::parse(desc) {
                    self.terminals.push(UacTerminal {
                        id: t.terminal_id,
                        terminal_type: t.terminal_type,
                        source_id: 0,
                        is_input: true,
                        nr_channels: t.nr_channels,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_OUTPUT_TERMINAL) => {
                if let Ok(t) = OutputTerminal2::parse(desc) {
                    self.terminals.push(UacTerminal {
                        id: t.terminal_id,
                        terminal_type: t.terminal_type,
                        source_id: t.source_id,
                        is_input: false,
                        nr_channels: 0,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_FEATURE_UNIT) => {
                if let Ok(f) = FeatureUnit2::parse(desc) {
                    self.feature_units.push(UacFeatureUnit {
                        id: f.unit_id,
                        source_id: f.source_id,
                        master_controls: f.master_controls(),
                        channels: f.controls.len() as u8,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_CLOCK_SOURCE) => {
                if let Ok(c) = ClockSource::parse(desc) {
                    self.clocks.push(UacClock {
                        id: c.clock_id,
                        kind: UacClockKind::Source,
                        freq_programmable: c.freq_programmable(),
                        assoc_terminal: c.assoc_terminal,
                        pins: Vec::new(),
                        derives_from: 0,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_CLOCK_SELECTOR) => {
                if let Ok(c) = ClockSelector::parse(desc) {
                    self.clocks.push(UacClock {
                        id: c.clock_id,
                        kind: UacClockKind::Selector,
                        freq_programmable: false,
                        assoc_terminal: 0,
                        pins: c.pins,
                        derives_from: 0,
                    });
                }
            }
            (UacVersion::V2, AC_SUBTYPE_CLOCK_MULTIPLIER) => {
                if let Ok(c) = ClockMultiplier::parse(desc) {
                    self.clocks.push(UacClock {
                        id: c.clock_id,
                        kind: UacClockKind::Multiplier,
                        freq_programmable: false,
                        assoc_terminal: 0,
                        pins: Vec::new(),
                        derives_from: c.source_clock_id,
                    });
                }
            }
            _ => {}
        }
    }

    fn parse_as_descriptor(&mut self, stream_idx: usize, desc: &[u8]) {
        if desc.len() < 3 {
            return;
        }
        match desc[2] {
            AS_SUBTYPE_GENERAL => match self.version {
                UacVersion::V1 => {
                    if let Ok(g) = AsGeneral::parse(desc) {
                        let s = &mut self.streams[stream_idx];
                        s.terminal_link = g.terminal_link;
                        // PCM alts get a placeholder format the
                        // FORMAT_TYPE descriptor that follows fills
                        // in; non-PCM alts stay format-less (and
                        // therefore unusable to the sound layer).
                        if g.format_tag == FORMAT_TAG_PCM {
                            if let Some(a) = s.alts.last_mut() {
                                if a.format.is_none() {
                                    a.format = Some(UacAltFormat {
                                        channels: 0,
                                        subframe_size: 0,
                                        bit_resolution: 0,
                                        rates: Vec::new(),
                                        range: None,
                                    });
                                }
                            }
                        }
                    }
                }
                UacVersion::V2 => {
                    if let Ok(g) = AsGeneral2::parse(desc) {
                        let s = &mut self.streams[stream_idx];
                        s.terminal_link = g.terminal_link;
                        if g.formats & 0x01 != 0 {
                            // PCM present.
                            if let Some(a) = s.alts.last_mut() {
                                a.format = Some(UacAltFormat {
                                    channels: g.nr_channels,
                                    subframe_size: 2,
                                    bit_resolution: 16,
                                    rates: Vec::new(),
                                    range: None,
                                });
                            }
                        }
                    }
                }
            },
            AS_SUBTYPE_FORMAT_TYPE => match self.version {
                UacVersion::V1 => {
                    if let Ok(f) = FormatTypeI::parse(desc) {
                        let s = &mut self.streams[stream_idx];
                        if let Some(a) = s.alts.last_mut() {
                            if let Some(fmt) = a.format.as_mut() {
                                fmt.channels = f.nr_channels;
                                fmt.subframe_size = f.subframe_size;
                                fmt.bit_resolution = f.bit_resolution;
                                fmt.rates = f.sample_rates.clone();
                                if let (Some(lo), Some(hi)) = (f.range_lower_hz, f.range_upper_hz) {
                                    fmt.range = Some((lo, hi));
                                }
                            }
                        }
                    }
                }
                UacVersion::V2 => {
                    if let Ok(f) = FormatTypeI2::parse(desc) {
                        let s = &mut self.streams[stream_idx];
                        if let Some(a) = s.alts.last_mut() {
                            if let Some(fmt) = a.format.as_mut() {
                                fmt.subframe_size = f.subslot_size;
                                fmt.bit_resolution = f.bit_resolution;
                            }
                        }
                    }
                }
            },
            _ => {}
        }
    }

    /// The Feature Unit on the path feeding `terminal_id`:
    /// follows `source_id` edges (FU → its source) until a unit
    /// whose source is the terminal itself, or the FU whose own
    /// source chain reaches it. Headset topologies are a direct
    /// IT → FU → OT chain; selector/mixer units are traversed
    /// through their recorded source edges where present.
    pub fn feature_unit_for(&self, terminal_id: u8) -> Option<&UacFeatureUnit> {
        // Direct: an FU whose source is the terminal.
        if let Some(f) = self
            .feature_units
            .iter()
            .find(|f| f.source_id == terminal_id)
        {
            return Some(f);
        }
        // One hop: FU feeding the terminal that feeds this one.
        let feeder = self.terminals.iter().find(|t| t.id == terminal_id)?;
        if feeder.source_id != 0 {
            return self
                .feature_units
                .iter()
                .find(|f| f.source_id == feeder.source_id || f.id == feeder.source_id);
        }
        None
    }

    /// Resolve the clock entity that drives the stream linked to
    /// `terminal_id` (UAC2): a source associated with the
    /// terminal, else the selector/multiplier chain pointing at
    /// one, else the device's only clock source.
    pub fn clock_for_terminal(&self, terminal_id: u8) -> Option<&UacClock> {
        if let Some(c) = self
            .clocks
            .iter()
            .find(|c| c.kind == UacClockKind::Source && c.assoc_terminal == terminal_id)
        {
            return Some(c);
        }
        if self.clocks.len() == 1 {
            return self.clocks.first();
        }
        // A selector whose (single) pin set includes a source
        // associated with the terminal.
        for c in self
            .clocks
            .iter()
            .filter(|c| c.kind == UacClockKind::Selector)
        {
            for pin in &c.pins {
                if let Some(src) = self.clocks.iter().find(|s| {
                    s.id == *pin
                        && s.kind == UacClockKind::Source
                        && s.assoc_terminal == terminal_id
                }) {
                    return Some(src);
                }
            }
        }
        None
    }
}

// ── Class enumeration + bind ───────────────────────────────────────
//
// "Is this a UAC device, and if so claim it": topology walk →
// bind conversation → sound-card publication → registry entry.

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

/// One bound UAC device — slot id + AudioControl interface number.
#[derive(Clone, Debug)]
pub struct UacDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the AudioControl interface.
    pub ac_iface: u8,
    /// DCI of the iso-OUT endpoint (playback). 0 = no playback EP
    /// found in the descriptor.
    pub iso_out_dci: u8,
    /// DCI of the iso-IN endpoint (capture / microphone). 0 = none.
    pub iso_in_dci: u8,
    /// Sound-card state when the bind published a card (`None`
    /// for AudioControl-only devices with no usable stream).
    pub card: Option<alloc::sync::Arc<crate::uac_card::UacCardState>>,
}

/// System-wide registry of bound UAC devices.
pub static UAC_DEVICES: IrqSafeSpinLock<Vec<UacDevice>> = IrqSafeSpinLock::new(Vec::new());

/// The negotiated shape of one direction, chosen at bind time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StreamChoice {
    pub iface: u8,
    pub alt_setting: u8,
    pub ep_addr: u8,
    pub dci: u8,
    pub channels: u8,
    pub subframe_size: u8,
    pub bit_resolution: u8,
    /// Sampling rate to program at bind (Hz). For UAC2 this is
    /// the preferred rate; the RANGE response may adjust it (see
    /// `BindOutcome::clock_rate_hz`).
    pub rate_hz: u32,
    /// Terminal the stream links to (FU lookup + clock lookup).
    pub terminal_link: u8,
    pub capture: bool,
}

/// Rates (Hz) one alt can serve through the sound layer: UAC1
/// from its FORMAT_TYPE discrete list / continuous range,
/// intersected with the sound layer's rate set; UAC2 the full
/// standard set (the clock RANGE response narrows it at bind).
/// Empty when the alt's shape is not sound-representable.
pub fn alt_sound_rates(alt: &UacAlt, version: UacVersion) -> Vec<u32> {
    let Some(fmt) = &alt.format else {
        return Vec::new();
    };
    if !matches!(fmt.channels, 1 | 2 | 4 | 6 | 8) {
        return Vec::new();
    }
    if !matches!(
        (fmt.subframe_size, fmt.bit_resolution),
        (2, 1..=16) | (3, 20) | (3, 24) | (4, 1..=32)
    ) {
        return Vec::new();
    }
    const STD: [u32; 6] = [44_100, 48_000, 88_200, 96_000, 176_400, 192_000];
    match version {
        UacVersion::V1 => {
            if !fmt.rates.is_empty() {
                return STD.into_iter().filter(|r| fmt.rates.contains(r)).collect();
            }
            match fmt.range {
                Some((lo, hi)) => STD.into_iter().filter(|r| *r >= lo && *r <= hi).collect(),
                None => Vec::new(),
            }
        }
        UacVersion::V2 => STD.to_vec(),
    }
}

/// Pick the default (alt, rate) for one stream: prefer 48 kHz,
/// then 44.1 kHz, then the highest representable rate; among alts
/// serving the chosen rate pick the smallest max-packet that
/// still fits one millisecond of audio (bandwidth economy).
pub fn choose_stream_default(stream: &UacStream, version: UacVersion) -> Option<StreamChoice> {
    let capture = stream.is_capture()?;
    let mut best: Option<(u32, &UacAlt)> = None;
    for alt in &stream.alts {
        if alt.ep_addr == 0 {
            continue;
        }
        let Some(fmt) = &alt.format else {
            continue;
        };
        for rate in alt_sound_rates(alt, version) {
            let frame_bytes = fmt.channels as u32 * fmt.subframe_size as u32;
            let need = (rate * frame_bytes).div_ceil(1000);
            if (alt.ep_max_packet as u32) < need {
                continue;
            }
            let better = match best {
                None => true,
                Some((br, ba)) => {
                    rate_pref(rate) < rate_pref(br)
                        || (rate == br && alt.ep_max_packet < ba.ep_max_packet)
                }
            };
            if better {
                best = Some((rate, alt));
            }
        }
    }
    let (rate, alt) = best?;
    let fmt = alt.format.as_ref()?;
    Some(StreamChoice {
        iface: stream.iface,
        alt_setting: alt.alt_setting,
        ep_addr: alt.ep_addr,
        dci: alt.dci(),
        channels: fmt.channels,
        subframe_size: fmt.subframe_size,
        bit_resolution: fmt.bit_resolution,
        rate_hz: rate,
        terminal_link: stream.terminal_link,
        capture,
    })
}

fn rate_pref(hz: u32) -> u32 {
    match hz {
        48_000 => 0,
        44_100 => 1,
        r => 100 + (192_000 - r.min(192_000)),
    }
}

// ── Bind conversation (plan + executor) ────────────────────────────
//
// The bind is a pure, ordered plan of control transfers built
// from the topology; the executor is a trivial loop over it.
// Fatal steps abort the bind (no half-configured card is ever
// registered); informational GETs are non-fatal and fall back to
// spec defaults.

/// One control transfer in a bind plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlStep {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub data: StepData,
    /// A failed fatal step aborts the bind.
    pub fatal: bool,
    /// What an IN response means, for the outcome record.
    pub slot: ResponseSlot,
    /// For a UAC2 clock SET_CUR: resolve the OUT payload against
    /// this direction's stored RANGE response at execution time.
    pub resolve_rate_from_range: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepData {
    /// No data stage, or an OUT stage with these bytes.
    Out(Vec<u8>),
    /// IN stage of up to this many bytes.
    In(usize),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseSlot {
    None,
    /// Sampling-frequency RANGE response of the stream's clock.
    ClockRange {
        capture: bool,
    },
    /// Current sampling frequency of a fixed (non-programmable)
    /// clock.
    ClockCur {
        capture: bool,
    },
    FuVolumeMin {
        capture: bool,
    },
    FuVolumeMax {
        capture: bool,
    },
    FuVolumeRes {
        capture: bool,
    },
}

/// Facts gathered while executing a bind plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindOutcome {
    /// Per direction [playback, capture]: (min, max, res) in
    /// dB×256 as read from the Feature Unit.
    pub volume_range: [Option<(i32, i32, i32)>; 2],
    /// Rate actually programmed (or read back) on a UAC2 clock,
    /// per direction [playback, capture].
    pub clock_rate_hz: [Option<u32>; 2],
    /// Clock subranges seen (UAC2), per direction.
    pub clock_ranges: [Vec<ClockSubrange>; 2],
    /// Steps completed (attempted non-fatal failures included).
    pub steps_executed: usize,
}

impl BindOutcome {
    pub fn dir_idx(capture: bool) -> usize {
        if capture {
            1
        } else {
            0
        }
    }
}

/// Build the full ordered bind conversation for a device:
/// SET_CONFIGURATION, then per direction (in `choices` order)
/// SET_INTERFACE → sampling frequency → FeatureUnit range + set.
pub fn build_bind_plan(
    topo: &UacTopology,
    cfg_value: u8,
    choices: &[StreamChoice],
) -> Vec<ControlStep> {
    let plain =
        |request_type: u8, request: u8, value: u16, index: u16, data: StepData, fatal: bool| {
            ControlStep {
                request_type,
                request,
                value,
                index,
                data,
                fatal,
                slot: ResponseSlot::None,
                resolve_rate_from_range: None,
            }
        };
    let mut steps = alloc::vec![plain(
        0x00,
        crate::hid::STD_REQ_SET_CONFIGURATION,
        cfg_value as u16,
        0,
        StepData::Out(Vec::new()),
        true,
    )];
    for choice in choices {
        steps.push(plain(
            0x01,
            crate::control::REQ_SET_INTERFACE,
            choice.alt_setting as u16,
            choice.iface as u16,
            StepData::Out(Vec::new()),
            true,
        ));
        // Sampling frequency.
        match topo.version {
            UacVersion::V1 => {
                steps.push(plain(
                    0x22,
                    REQ_SET_CUR,
                    (SAMPLING_FREQUENCY_CONTROL as u16) << 8,
                    choice.ep_addr as u16,
                    StepData::Out(encode_sampling_freq(choice.rate_hz).to_vec()),
                    true,
                ));
            }
            UacVersion::V2 => {
                if let Some(clock) = topo.clock_for_terminal(choice.terminal_link) {
                    let idx = ((clock.id as u16) << 8) | topo.ac_iface as u16;
                    let val = (CLOCK_CS_SAMPLING_FREQUENCY as u16) << 8;
                    if clock.freq_programmable {
                        let mut get_range =
                            plain(0xA1, REQ_RANGE, val, idx, StepData::In(2 + 12 * 8), false);
                        get_range.slot = ResponseSlot::ClockRange {
                            capture: choice.capture,
                        };
                        steps.push(get_range);
                        let mut set_cur = plain(
                            0x21,
                            REQ_CUR,
                            val,
                            idx,
                            StepData::Out(choice.rate_hz.to_le_bytes().to_vec()),
                            true,
                        );
                        set_cur.resolve_rate_from_range = Some(choice.capture);
                        steps.push(set_cur);
                    } else {
                        // Fixed clock: read the rate the card must
                        // advertise. GET_CUR on a UAC2 clock uses
                        // bRequest CUR (0x01) with an IN stage.
                        let mut get_cur = plain(0xA1, REQ_CUR, val, idx, StepData::In(4), false);
                        get_cur.slot = ResponseSlot::ClockCur {
                            capture: choice.capture,
                        };
                        steps.push(get_cur);
                    }
                }
            }
        }
        // Feature Unit on this direction's path: learn the volume
        // range, then program 0 dB (the card clamps against the
        // learned range) and unmute.
        if let Some(fu) = topo.feature_unit_for(choice.terminal_link) {
            let idx = fu_windex(fu.id, topo.ac_iface);
            let mc = fu.master_controls;
            if mc & FEATURE_VOLUME != 0 {
                for (req, slot) in [
                    (
                        REQ_GET_MIN,
                        ResponseSlot::FuVolumeMin {
                            capture: choice.capture,
                        },
                    ),
                    (
                        REQ_GET_MAX,
                        ResponseSlot::FuVolumeMax {
                            capture: choice.capture,
                        },
                    ),
                    (
                        REQ_GET_RES,
                        ResponseSlot::FuVolumeRes {
                            capture: choice.capture,
                        },
                    ),
                ] {
                    let mut s = plain(
                        0xA1,
                        req,
                        fu_wvalue(FU_CS_VOLUME, CHANNEL_MASTER),
                        idx,
                        StepData::In(2),
                        false,
                    );
                    s.slot = slot;
                    steps.push(s);
                }
                steps.push(plain(
                    0x21,
                    REQ_SET_CUR,
                    fu_wvalue(FU_CS_VOLUME, CHANNEL_MASTER),
                    idx,
                    StepData::Out(encode_volume(0).to_vec()),
                    true,
                ));
            }
            if mc & FEATURE_MUTE != 0 {
                steps.push(plain(
                    0x21,
                    REQ_SET_CUR,
                    fu_wvalue(FU_CS_MUTE, CHANNEL_MASTER),
                    idx,
                    StepData::Out(encode_mute(false).to_vec()),
                    true,
                ));
            }
        }
    }
    steps
}

/// Execute a bind plan against the xHCI. RANGE-aware rate
/// resolution happens when a flagged clock SET_CUR step runs:
/// its coded payload is the preferred rate, re-resolved via
/// `choose_clock_rate` against the stored RANGE response.
pub async fn execute_bind_plan(
    ctrl: &crate::xhci::Xhci,
    slot_id: u8,
    steps: &[ControlStep],
) -> Result<BindOutcome, UacError> {
    let mut outcome = BindOutcome::default();
    for step in steps {
        let res: Result<Vec<u8>, UacError> = match &step.data {
            StepData::Out(bytes) => {
                let mut payload = bytes.clone();
                if let Some(capture) = step.resolve_rate_from_range {
                    let i = BindOutcome::dir_idx(capture);
                    if !outcome.clock_ranges[i].is_empty() {
                        if let Some(hz) = choose_clock_rate(&outcome.clock_ranges[i]) {
                            payload = hz.to_le_bytes().to_vec();
                            outcome.clock_rate_hz[i] = Some(hz);
                        }
                    }
                }
                ctrl.control_out(
                    slot_id,
                    step.request_type,
                    step.request,
                    step.value,
                    step.index,
                    &payload,
                )
                .await
                .map(|_| Vec::new())
                .map_err(|_| UacError::SetConfigFailed)
            }
            StepData::In(len) => {
                let mut buf = alloc::vec![0u8; *len];
                match ctrl
                    .control_in(
                        slot_id,
                        step.request_type,
                        step.request,
                        step.value,
                        step.index,
                        &mut buf,
                    )
                    .await
                {
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(buf)
                    }
                    Err(_) => Err(UacError::SetConfigFailed),
                }
            }
        };
        match res {
            Ok(data) => {
                outcome.steps_executed += 1;
                record_response(&mut outcome, step.slot, &data);
            }
            Err(e) => {
                if step.fatal {
                    return Err(e);
                }
                outcome.steps_executed += 1; // attempted; defaults apply
            }
        }
    }
    Ok(outcome)
}

fn record_response(outcome: &mut BindOutcome, slot: ResponseSlot, data: &[u8]) {
    let rd_i16 = |d: &[u8]| -> Option<i32> {
        if d.len() >= 2 {
            Some(i16::from_le_bytes([d[0], d[1]]) as i32)
        } else {
            None
        }
    };
    // Default FU range until a read lands: −128 dB .. 0 dB, 1 dB steps.
    const DEFAULT_RANGE: (i32, i32, i32) = (i16::MIN as i32, 0, 256);
    match slot {
        ResponseSlot::None => {}
        ResponseSlot::ClockRange { capture } => {
            let i = BindOutcome::dir_idx(capture);
            outcome.clock_ranges[i] = parse_clock_ranges(data);
        }
        ResponseSlot::ClockCur { capture } => {
            let i = BindOutcome::dir_idx(capture);
            if data.len() >= 4 {
                outcome.clock_rate_hz[i] =
                    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
            }
        }
        ResponseSlot::FuVolumeMin { capture } => {
            let i = BindOutcome::dir_idx(capture);
            let cur = outcome.volume_range[i].unwrap_or(DEFAULT_RANGE);
            if let Some(v) = rd_i16(data) {
                outcome.volume_range[i] = Some((v, cur.1, cur.2));
            }
        }
        ResponseSlot::FuVolumeMax { capture } => {
            let i = BindOutcome::dir_idx(capture);
            let cur = outcome.volume_range[i].unwrap_or(DEFAULT_RANGE);
            if let Some(v) = rd_i16(data) {
                outcome.volume_range[i] = Some((cur.0, v, cur.2));
            }
        }
        ResponseSlot::FuVolumeRes { capture } => {
            let i = BindOutcome::dir_idx(capture);
            let cur = outcome.volume_range[i].unwrap_or(DEFAULT_RANGE);
            if let Some(v) = rd_i16(data) {
                outcome.volume_range[i] = Some((cur.0, cur.1, v));
            }
        }
    }
}

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

/// Bind to an already-addressed UAC device: walk the topology,
/// run the full bind conversation (SET_CONFIGURATION → per-stream
/// SET_INTERFACE alt selection → sampling-frequency SET_CUR →
/// FeatureUnit range read + SET_CUR program), register the sound
/// card, then record the slot in UAC_DEVICES. Returns the new
/// registry index on success.
///
/// AudioControl-only devices (USB volume knobs and friends, no
/// usable stream) still bind registry-only after
/// SET_CONFIGURATION, exactly as before.
pub async fn try_bind_audio_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, UacError> {
    let topo = UacTopology::parse(cfg)?;
    let ac_iface = topo.ac_iface;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };

    let mut choices: Vec<StreamChoice> = Vec::new();
    for stream in &topo.streams {
        if let Some(c) = choose_stream_default(stream, topo.version) {
            choices.push(c);
        }
    }
    // Playback streams first, matching the plan's documented order.
    choices.sort_by_key(|c| c.capture);

    let plan = build_bind_plan(&topo, cfg_value, &choices);
    let outcome = execute_bind_plan(xhci_dev, slot_id, &plan).await?;

    // Find iso endpoints in any AudioStreaming alt setting. May be
    // absent (UAC AudioControl-only devices like USB volume knobs);
    // in that case the iso DCIs stay 0.
    let (iso_out_dci, iso_in_dci) = find_audio_streaming_iso_eps(cfg);

    let card = if choices.is_empty() {
        None
    } else {
        let state = crate::uac_card::UacCardState::from_bind(slot_id, &topo, &choices, &outcome);
        match crate::uac_card::register_card(&state) {
            Ok(_) => Some(state),
            Err(e) => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "uac: card registration failed slot={} err={:?}",
                    slot_id,
                    e
                );
                None
            }
        }
    };

    let mut g = UAC_DEVICES.lock();
    let idx = g.len();
    g.push(UacDevice {
        slot_id,
        ac_iface,
        iso_out_dci,
        iso_in_dci,
        card,
    });
    Ok(idx)
}

/// Unbind every UAC device on `slot_id`: unregister its sound
/// card (outstanding leases keep the hardware alive until they
/// stop, per the sound layer's contract) and drop the registry
/// entries. Returns how many entries were removed.
///
/// There is no supervisor caller on main yet — the USB detach
/// passes (PRs #846/#847) call this from their per-slot teardown
/// once they land.
pub fn unbind_audio(slot_id: u8) -> usize {
    let removed: Vec<UacDevice> = {
        let mut reg = UAC_DEVICES.lock();
        let mut taken = Vec::new();
        let mut i = 0;
        while i < reg.len() {
            if reg[i].slot_id == slot_id {
                taken.push(reg.remove(i));
            } else {
                i += 1;
            }
        }
        taken
    };
    for dev in &removed {
        if let Some(state) = &dev.card {
            state.detach();
        }
    }
    removed.len()
}

/// Unbind every bound UAC device (all slots). See `unbind_audio`.
pub fn unbind_all_uac() -> usize {
    let removed: Vec<UacDevice> = {
        let mut reg = UAC_DEVICES.lock();
        reg.drain(..).collect()
    };
    for dev in &removed {
        if let Some(state) = &dev.card {
            state.detach();
        }
    }
    removed.len()
}

/// Test-only: push a pre-built registry entry without running a
/// bind conversation (fixture companion to
/// `__reset_uac_for_test`).
#[doc(hidden)]
pub fn __push_uac_for_test(dev: UacDevice) {
    UAC_DEVICES.lock().push(dev);
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
/// `GET_MIN` class request code (Feature Unit range query).
pub const REQ_GET_MIN: u8 = 0x82;
/// `GET_MAX` class request code.
pub const REQ_GET_MAX: u8 = 0x83;
/// `GET_RES` class request code.
pub const REQ_GET_RES: u8 = 0x84;
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
