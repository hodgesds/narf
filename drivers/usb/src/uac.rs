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
//!                            + sampling-frequency table

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
