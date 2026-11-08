//! USB Video Class — descriptor parsing (clean-room).
//!
//! References (public-only):
//! - "USB Device Class Definition for Video Devices, Revision 1.5"
//!   (March 16, 2012) — USB-IF. Public document.
//!   <https://www.usb.org/document-library/video-class-v15-document-set>
//! - "USB Device Class Definition for Video Devices: Frame-based
//!   Payload, Revision 1.5" — USB-IF. Public.
//!   <https://www.usb.org/document-library/video-class-v15-document-set>
//! - "USB Device Class Definition for Video Devices: Uncompressed
//!   Payload, Revision 1.5" — USB-IF. Public. §3.1.1 declares the
//!   Format-GUID layout for YUV2 / NV12.
//!   <https://www.usb.org/document-library/video-class-v15-document-set>
//!
//! No GPL Linux source consulted.
//!
//! ## Class triple (§3.1)
//!
//! Video interfaces share class code 0x0E (CC_VIDEO):
//!   - subclass 0x01 SC_VIDEOCONTROL    — control surface
//!   - subclass 0x02 SC_VIDEOSTREAMING  — isoch / bulk video data path
//!   - subclass 0x03 SC_VIDEO_INTERFACE_COLLECTION — composite IAD
//!
//! Protocol byte: 0x00 (UVC 1.0/1.1) or 0x01 (UVC 1.5).
//!
//! ## VC class-specific interface descriptor (§3.7)
//!
//! ```text
//!   bLength bDescriptorType=0x24 (CS_INTERFACE) bDescriptorSubtype ...
//! ```
//!
//! Subtype values (table 3-1):
//!   0x01 VC_HEADER          — bcdUVC + total length + N interfaces
//!   0x02 VC_INPUT_TERMINAL  — camera / external composite input
//!   0x03 VC_OUTPUT_TERMINAL
//!   0x04 VC_SELECTOR_UNIT
//!   0x05 VC_PROCESSING_UNIT — brightness/contrast/gain/etc.
//!   0x06 VC_EXTENSION_UNIT  — vendor-specific
//!
//! VS subtype values (table 3-7):
//!   0x01 VS_INPUT_HEADER         — declares N FORMAT descriptors
//!   0x04 VS_FORMAT_UNCOMPRESSED  — YUV2/NV12 (GUID-tagged)
//!   0x05 VS_FRAME_UNCOMPRESSED   — width/height/frame-interval list
//!   0x06 VS_FORMAT_MJPEG
//!   0x07 VS_FRAME_MJPEG
//!   0x10 VS_FORMAT_FRAME_BASED   — H.264 etc.
//!   0x11 VS_FRAME_FRAME_BASED
//!   0x12 VS_FORMAT_STREAM_BASED   — MPEG-2 TS etc. (Table A-6)

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

// ── Class triple ───────────────────────────────────────────────────

pub const USB_CLASS_VIDEO: u8 = 0x0E;
pub const USB_VIDEO_SUBCLASS_VIDEOCONTROL: u8 = 0x01;
pub const USB_VIDEO_SUBCLASS_VIDEOSTREAMING: u8 = 0x02;
pub const USB_VIDEO_SUBCLASS_INTERFACE_COLLECTION: u8 = 0x03;
pub const USB_VIDEO_PROTOCOL_UVC10: u8 = 0x00;
pub const USB_VIDEO_PROTOCOL_UVC15: u8 = 0x01;

pub const CS_INTERFACE: u8 = 0x24;

// VC subtypes (table 3-1).
pub const VC_HEADER: u8 = 0x01;
pub const VC_INPUT_TERMINAL: u8 = 0x02;
pub const VC_OUTPUT_TERMINAL: u8 = 0x03;
pub const VC_SELECTOR_UNIT: u8 = 0x04;
pub const VC_PROCESSING_UNIT: u8 = 0x05;
pub const VC_EXTENSION_UNIT: u8 = 0x06;

// VS subtypes (table 3-7).
pub const VS_INPUT_HEADER: u8 = 0x01;
pub const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
pub const VS_FRAME_UNCOMPRESSED: u8 = 0x05;
pub const VS_FORMAT_MJPEG: u8 = 0x06;
pub const VS_FRAME_MJPEG: u8 = 0x07;
pub const VS_FORMAT_FRAME_BASED: u8 = 0x10;
pub const VS_FRAME_FRAME_BASED: u8 = 0x11;
pub const VS_FORMAT_STREAM_BASED: u8 = 0x12;

// Terminal types (table A-1) — selected.
pub const TT_VENDOR_SPECIFIC: u16 = 0x0100;
pub const TT_STREAMING: u16 = 0x0101;
pub const ITT_VENDOR_SPECIFIC: u16 = 0x0200;
pub const ITT_CAMERA: u16 = 0x0201;
pub const ITT_MEDIA_TRANSPORT_INPUT: u16 = 0x0202;
pub const OTT_VENDOR_SPECIFIC: u16 = 0x0300;
pub const OTT_DISPLAY: u16 = 0x0301;
pub const OTT_MEDIA_TRANSPORT_OUTPUT: u16 = 0x0302;

// Format GUIDs (Uncompressed Payload spec §3.1.1).
//
// All UVC GUIDs are stored little-endian on the wire (§3.1.1 footnote).
// We surface them as the 16 raw bytes the descriptor carries.
pub const GUID_FORMAT_YUY2: [u8; 16] = [
    0x59, 0x55, 0x59, 0x32, // "YUY2"
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];
pub const GUID_FORMAT_NV12: [u8; 16] = [
    0x4E, 0x56, 0x31, 0x32, // "NV12"
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UvcError {
    Short,
    Truncated,
    NotClassSpecific,
    BadSubtype(u8),
    /// Device's interface descriptors didn't include a Video Class
    /// VideoControl interface — not a UVC device.
    NotVideo,
    /// SET_CONFIGURATION control transfer failed during bind.
    SetConfigFailed,
    /// No isochronous IN alternate setting can carry the negotiated
    /// UVC `dwMaxPayloadTransferSize`.
    NoStreamingEndpoint,
    /// xHCI rejected the selected VideoStreaming endpoint context.
    ConfigureEndpointFailed,
    /// SET_INTERFACE failed while switching from the zero-bandwidth
    /// alternate setting to the selected streaming alternate.
    SetInterfaceFailed,
    /// The device already has a different streaming alternate active.
    AlreadyStreaming,
    /// SET_CUR/GET_CUR(PROBE) failed, returned a truncated payload,
    /// or returned a malformed 1.1+ version triple.
    ProbeFailed,
    /// SET_CUR(COMMIT) failed for the device-accepted stream parameters.
    CommitFailed,
    /// The xHCI data path failed while capturing an isochronous packet.
    CaptureFailed,
}

fn check_cs(buf: &[u8], expect: u8) -> Result<(), UvcError> {
    if buf.len() < 3 {
        return Err(UvcError::Short);
    }
    if (buf[0] as usize) > buf.len() {
        return Err(UvcError::Truncated);
    }
    if buf[1] != CS_INTERFACE {
        return Err(UvcError::NotClassSpecific);
    }
    if buf[2] != expect {
        return Err(UvcError::BadSubtype(buf[2]));
    }
    Ok(())
}

// ── VC descriptors ─────────────────────────────────────────────────

/// VC HEADER (§3.7.2, table 3-3). Length = 12 + bInCollection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcHeader {
    pub bcd_uvc: u16,
    pub total_length: u16,
    /// Device-clock frequency in Hz.
    pub clock_frequency: u32,
    /// Streaming interface numbers controlled by this VC.
    pub in_collection: Vec<u8>,
}

impl VcHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VC_HEADER)?;
        if buf.len() < 12 {
            return Err(UvcError::Short);
        }
        let bcd_uvc = u16::from_le_bytes([buf[3], buf[4]]);
        let total_length = u16::from_le_bytes([buf[5], buf[6]]);
        let clock_frequency = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
        let n = buf[11] as usize;
        if buf.len() < 12 + n {
            return Err(UvcError::Truncated);
        }
        Ok(Self {
            bcd_uvc,
            total_length,
            clock_frequency,
            in_collection: buf[12..12 + n].to_vec(),
        })
    }
}

/// Camera / Input Terminal (§3.7.2.3, table 3-5). Camera adds 7
/// extra bytes (objective focal length range + controls bitmap)
/// after the generic INPUT_TERMINAL fields, gated on `terminal_type
/// == ITT_CAMERA`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub terminal_idx: u8,
    /// Camera-specific (None when terminal_type ≠ ITT_CAMERA):
    pub camera: Option<CameraSpecific>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct CameraSpecific {
    pub objective_focal_length_min: u16,
    pub objective_focal_length_max: u16,
    pub ocular_focal_length: u16,
    /// `bControlSize` bytes of `bmControls`, MSB first per spec; we
    /// surface the raw u32 of the first 4 bytes.
    pub controls: u32,
}

impl InputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VC_INPUT_TERMINAL)?;
        if buf.len() < 8 {
            return Err(UvcError::Short);
        }
        let terminal_id = buf[3];
        let terminal_type = u16::from_le_bytes([buf[4], buf[5]]);
        let assoc_terminal = buf[6];
        let terminal_idx = buf[7];

        let camera = if terminal_type == ITT_CAMERA {
            if buf.len() < 15 {
                return Err(UvcError::Short);
            }
            let objective_focal_length_min = u16::from_le_bytes([buf[8], buf[9]]);
            let objective_focal_length_max = u16::from_le_bytes([buf[10], buf[11]]);
            let ocular_focal_length = u16::from_le_bytes([buf[12], buf[13]]);
            let control_size = buf[14] as usize;
            if buf.len() < 15 + control_size {
                return Err(UvcError::Truncated);
            }
            let mut ctl = [0u8; 4];
            for (i, b) in buf[15..15 + control_size.min(4)].iter().enumerate() {
                ctl[i] = *b;
            }
            Some(CameraSpecific {
                objective_focal_length_min,
                objective_focal_length_max,
                ocular_focal_length,
                controls: u32::from_le_bytes(ctl),
            })
        } else {
            None
        };

        Ok(Self {
            terminal_id,
            terminal_type,
            assoc_terminal,
            terminal_idx,
            camera,
        })
    }
}

/// Output Terminal (§3.7.2.2, table 3-4, fixed 9 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub source_id: u8,
    pub terminal_idx: u8,
}

impl OutputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VC_OUTPUT_TERMINAL)?;
        if buf.len() < 9 {
            return Err(UvcError::Short);
        }
        Ok(Self {
            terminal_id: buf[3],
            terminal_type: u16::from_le_bytes([buf[4], buf[5]]),
            assoc_terminal: buf[6],
            source_id: buf[7],
            terminal_idx: buf[8],
        })
    }
}

/// Processing Unit (§3.7.2.5, table 3-8). Length = 10 + bControlSize
/// (+1 for iProcessing on UVC 1.0; +1 for bmVideoStandards on 1.1+).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessingUnit {
    pub unit_id: u8,
    pub source_id: u8,
    pub max_multiplier: u16,
    /// Raw control bitmap (1..3 bytes per spec; we surface as u32).
    pub controls: u32,
    pub processing_idx: u8,
}

impl ProcessingUnit {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VC_PROCESSING_UNIT)?;
        if buf.len() < 10 {
            return Err(UvcError::Short);
        }
        let unit_id = buf[3];
        let source_id = buf[4];
        let max_multiplier = u16::from_le_bytes([buf[5], buf[6]]);
        let control_size = buf[7] as usize;
        if buf.len() < 8 + control_size + 1 {
            return Err(UvcError::Truncated);
        }
        let mut ctl = [0u8; 4];
        for (i, b) in buf[8..8 + control_size.min(4)].iter().enumerate() {
            ctl[i] = *b;
        }
        let processing_idx = buf[8 + control_size];
        Ok(Self {
            unit_id,
            source_id,
            max_multiplier,
            controls: u32::from_le_bytes(ctl),
            processing_idx,
        })
    }
}

// ── VS descriptors ─────────────────────────────────────────────────

/// VS INPUT_HEADER (§3.9.2.1, table 3-13). Length = 13 + N×bControlSize
/// where N is the number of FORMAT descriptors that follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputHeader {
    pub num_formats: u8,
    pub total_length: u16,
    /// Bulk/Iso endpoint address that carries the video stream.
    pub endpoint_address: u8,
    pub still_capture_method: u8,
    pub trigger_support: bool,
    pub trigger_usage: u8,
    /// Raw control bitmaps, one per FORMAT.
    pub format_controls: Vec<u8>,
}

impl InputHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VS_INPUT_HEADER)?;
        if buf.len() < 13 {
            return Err(UvcError::Short);
        }
        let num_formats = buf[3];
        let total_length = u16::from_le_bytes([buf[4], buf[5]]);
        let endpoint_address = buf[6];
        // bmInfo at buf[7] — bit 0 = "supports dynamic format change"
        let _info = buf[7];
        // bTerminalLink at buf[8] — id of the OT this VS feeds.
        let _terminal_link = buf[8];
        let still_capture_method = buf[9];
        let trigger_support = buf[10] != 0;
        let trigger_usage = buf[11];
        let control_size = buf[12] as usize;
        let need = 13 + (num_formats as usize) * control_size;
        if buf.len() < need {
            return Err(UvcError::Truncated);
        }
        let format_controls = buf[13..need].to_vec();
        Ok(Self {
            num_formats,
            total_length,
            endpoint_address,
            still_capture_method,
            trigger_support,
            trigger_usage,
            format_controls,
        })
    }
}

/// VS_FORMAT_UNCOMPRESSED (§3.1.1 of Uncompressed Payload spec, 27 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatUncompressed {
    pub format_index: u8,
    pub num_frame_descriptors: u8,
    /// 16-byte Format GUID (compare against `GUID_FORMAT_YUY2` etc.).
    pub guid: [u8; 16],
    /// Bits per pixel (16 for YUY2, 12 for NV12).
    pub bits_per_pixel: u8,
    pub default_frame_index: u8,
    /// Aspect ratio numerator / denominator (zero = "non-interlaced
    /// or N/A").
    pub aspect_ratio_x: u8,
    pub aspect_ratio_y: u8,
    pub interlace_flags: u8,
    pub copy_protect: bool,
}

impl FormatUncompressed {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VS_FORMAT_UNCOMPRESSED)?;
        if buf.len() < 27 {
            return Err(UvcError::Short);
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&buf[5..21]);
        Ok(Self {
            format_index: buf[3],
            num_frame_descriptors: buf[4],
            guid,
            bits_per_pixel: buf[21],
            default_frame_index: buf[22],
            aspect_ratio_x: buf[23],
            aspect_ratio_y: buf[24],
            interlace_flags: buf[25],
            copy_protect: buf[26] != 0,
        })
    }
}

/// VS_FRAME_UNCOMPRESSED (§3.1.2 Uncompressed Payload). Variable
/// length: fixed 26 bytes + 4 × bFrameIntervalType (LE 32-bit Hz⁻¹
/// in 100 ns units), or 4 × 3 = 12 bytes when type=0 (continuous).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameUncompressed {
    pub frame_index: u8,
    pub capabilities: u8,
    pub width: u16,
    pub height: u16,
    pub min_bitrate: u32,
    pub max_bitrate: u32,
    pub max_video_frame_buffer_size: u32,
    pub default_frame_interval: u32,
    /// Discrete frame intervals, in 100 ns units. Empty when
    /// `continuous_min/max/step` is set.
    pub frame_intervals: Vec<u32>,
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
}

impl FrameUncompressed {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VS_FRAME_UNCOMPRESSED)?;
        if buf.len() < 26 {
            return Err(UvcError::Short);
        }
        let frame_index = buf[3];
        let capabilities = buf[4];
        let width = u16::from_le_bytes([buf[5], buf[6]]);
        let height = u16::from_le_bytes([buf[7], buf[8]]);
        let min_bitrate = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]);
        let max_bitrate = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        let max_video_frame_buffer_size = u32::from_le_bytes([buf[17], buf[18], buf[19], buf[20]]);
        let default_frame_interval = u32::from_le_bytes([buf[21], buf[22], buf[23], buf[24]]);
        let interval_type = buf[25];
        let body = &buf[26..];
        if interval_type == 0 {
            if body.len() < 12 {
                return Err(UvcError::Truncated);
            }
            let cmin = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let cmax = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let cstep = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
            Ok(Self {
                frame_index,
                capabilities,
                width,
                height,
                min_bitrate,
                max_bitrate,
                max_video_frame_buffer_size,
                default_frame_interval,
                frame_intervals: Vec::new(),
                continuous_min: Some(cmin),
                continuous_max: Some(cmax),
                continuous_step: Some(cstep),
            })
        } else {
            let need = (interval_type as usize) * 4;
            if body.len() < need {
                return Err(UvcError::Truncated);
            }
            let mut intervals = Vec::with_capacity(interval_type as usize);
            for chunk in body[..need].chunks_exact(4) {
                intervals.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
            Ok(Self {
                frame_index,
                capabilities,
                width,
                height,
                min_bitrate,
                max_bitrate,
                max_video_frame_buffer_size,
                default_frame_interval,
                frame_intervals: intervals,
                continuous_min: None,
                continuous_max: None,
                continuous_step: None,
            })
        }
    }

    /// Convenience: convert a 100 ns interval to frames per second.
    /// e.g. interval = 333_333 (33.33 ms) → 30 fps.
    pub fn fps_from_interval(interval_100ns: u32) -> u32 {
        if interval_100ns == 0 {
            return 0;
        }
        10_000_000 / interval_100ns
    }
}

/// VS_FORMAT_MJPEG (§3.1.1 of UVC 1.5 base, 11 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatMjpeg {
    pub format_index: u8,
    pub num_frame_descriptors: u8,
    pub flags: u8,
    pub default_frame_index: u8,
    pub aspect_ratio_x: u8,
    pub aspect_ratio_y: u8,
    pub interlace_flags: u8,
    pub copy_protect: bool,
}

impl FormatMjpeg {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VS_FORMAT_MJPEG)?;
        if buf.len() < 11 {
            return Err(UvcError::Short);
        }
        Ok(Self {
            format_index: buf[3],
            num_frame_descriptors: buf[4],
            flags: buf[5],
            default_frame_index: buf[6],
            aspect_ratio_x: buf[7],
            aspect_ratio_y: buf[8],
            interlace_flags: buf[9],
            copy_protect: buf[10] != 0,
        })
    }
}

/// VS_FRAME_MJPEG (§3.1.2 of UVC 1.5 MJPEG Payload companion spec).
///
/// Identical structure to VS_FRAME_UNCOMPRESSED but tagged with
/// subtype 0x07. Fixed 26 bytes + 4 × bFrameIntervalType (discrete)
/// or 12 bytes (continuous, type = 0).
///
/// Linux equivalent: `uvc_parse_format()` in drivers/media/usb/uvc/uvc_driver.c
/// handles both UNCOMPRESSED and MJPEG frame descriptors with the same
/// 26-byte fixed-header parse (uvc_frame_desc layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameMjpeg {
    pub frame_index: u8,
    pub capabilities: u8,
    pub width: u16,
    pub height: u16,
    pub min_bitrate: u32,
    pub max_bitrate: u32,
    pub max_video_frame_buffer_size: u32,
    pub default_frame_interval: u32,
    /// Discrete frame intervals in 100 ns units. Empty when
    /// `continuous_min/max/step` is set (interval_type = 0).
    pub frame_intervals: Vec<u32>,
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
}

impl FrameMjpeg {
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        check_cs(buf, VS_FRAME_MJPEG)?;
        if buf.len() < 26 {
            return Err(UvcError::Short);
        }
        let frame_index = buf[3];
        let capabilities = buf[4];
        let width = u16::from_le_bytes([buf[5], buf[6]]);
        let height = u16::from_le_bytes([buf[7], buf[8]]);
        let min_bitrate = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]);
        let max_bitrate = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        let max_video_frame_buffer_size = u32::from_le_bytes([buf[17], buf[18], buf[19], buf[20]]);
        let default_frame_interval = u32::from_le_bytes([buf[21], buf[22], buf[23], buf[24]]);
        let interval_type = buf[25];
        let body = &buf[26..];
        if interval_type == 0 {
            if body.len() < 12 {
                return Err(UvcError::Truncated);
            }
            let cmin = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let cmax = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let cstep = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
            Ok(Self {
                frame_index,
                capabilities,
                width,
                height,
                min_bitrate,
                max_bitrate,
                max_video_frame_buffer_size,
                default_frame_interval,
                frame_intervals: Vec::new(),
                continuous_min: Some(cmin),
                continuous_max: Some(cmax),
                continuous_step: Some(cstep),
            })
        } else {
            let need = (interval_type as usize) * 4;
            if body.len() < need {
                return Err(UvcError::Truncated);
            }
            let mut intervals = Vec::with_capacity(interval_type as usize);
            for chunk in body[..need].chunks_exact(4) {
                intervals.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
            Ok(Self {
                frame_index,
                capabilities,
                width,
                height,
                min_bitrate,
                max_bitrate,
                max_video_frame_buffer_size,
                default_frame_interval,
                frame_intervals: intervals,
                continuous_min: None,
                continuous_max: None,
                continuous_step: None,
            })
        }
    }

    /// Convenience: convert a 100 ns interval to frames per second.
    pub fn fps_from_interval(interval_100ns: u32) -> u32 {
        if interval_100ns == 0 {
            return 0;
        }
        10_000_000 / interval_100ns
    }
}

// ── Class enumeration + bind ───────────────────────────────────────
//
// Minimal "is this a UVC device, and if so claim it" path. The
// full streaming surface (iso video frame ring + MJPEG /
// uncompressed payload decode) is a follow-up.

extern crate alloc;

use alloc::boxed::Box;

use core::future::Future;

use narf_lib::sync::IrqSafeSpinLock;

/// Transport exposed by a VideoStreaming alternate setting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UvcStreamingTransport {
    Isochronous,
    Bulk,
}

/// One IN endpoint advertised by a VideoStreaming interface alternate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UvcStreamingEndpoint {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub endpoint_address: u8,
    pub dci: u8,
    pub transport: UvcStreamingTransport,
    /// Raw USB Endpoint Descriptor `wMaxPacketSize`, including the
    /// USB 2.0 high-bandwidth transaction bits in 12:11.
    pub raw_max_packet: u16,
    /// Bytes carried by one USB transaction (`wMaxPacketSize[10:0]`).
    pub max_packet_size: u16,
    /// Transactions available in one service interval. USB 2.0
    /// high-bandwidth isoch endpoints advertise 1–3 here.
    pub transactions_per_interval: u8,
    /// Total bytes available in one service interval.
    pub max_payload_size: u32,
    /// Raw USB Endpoint Descriptor `bInterval`.
    pub interval: u8,
}

/// One bound UVC control: the V4L2-facing id plus the wire length
/// the device reported for it via GET_LEN. The (unit, selector)
/// pair is not stored here — it is derived on every access through
/// [`narf_drivers_video::uvc::route_control`] from the device's
/// retained PU/CT unit ids, so there is exactly one routing
/// authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UvcControl {
    pub id: narf_drivers_video::uvc::ControlId,
    /// Payload length in bytes (1, 2, or 4) from GET_LEN.
    pub len: u8,
}

/// One bound UVC device — control interface plus its streaming alternates.
#[derive(Clone, Debug)]
pub struct UvcDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the VideoControl interface.
    pub vc_iface: u8,
    /// Primary `bInterfaceNumber` of the VideoStreaming interface.
    pub vs_iface: u8,
    /// Every bulk/isochronous IN endpoint found on a VideoStreaming
    /// alternate setting. Bind retains these until PROBE/COMMIT tells
    /// the driver how much payload bandwidth to request.
    pub streaming_endpoints: Vec<UvcStreamingEndpoint>,
    /// Parsed VideoStreaming format table retained from bind. The
    /// STREAMON composition maps the S_FMT-committed V4L2 format back
    /// to UVC (format index, frame index, frame interval) through this
    /// table; the V4L2 `FmtEntry` table alone has already dropped the
    /// UVC indices negotiation needs.
    pub formats: Vec<narf_drivers_video::uvc::StreamFormat>,
    /// Endpoint whose xHCI context has been configured and whose
    /// alternate setting has been selected, if streaming is active.
    pub active_stream: Option<UvcStreamingEndpoint>,
    /// Device-accepted Probe/Commit control from the last successful
    /// negotiation (set by
    /// [`negotiate_and_activate_video_stream_with`], cleared by
    /// [`deactivate_video_stream_with`]). The capture pump derives
    /// its reassembler configuration from it — the negotiated
    /// `dwMaxVideoFrameSize` bound and `bmFramingInfo` — so the
    /// pump never reassembles against stale stream parameters.
    pub negotiated: Option<VsProbeCommit>,
    /// `/dev/video<N>` minor registered for this camera.
    pub video_node: usize,
    /// Generation of the current stream: bumped by every successful
    /// activation (and only by activation). A capture pump captures
    /// the generation it was spawned for and exits as soon as the
    /// device's generation no longer matches — a STREAMOFF →
    /// STREAMON toggle therefore retires the old pump by construction,
    /// however long it stays parked in a transfer.
    pub stream_generation: u64,
    /// Generation of the capture pump currently marked as running, or
    /// 0 when none is. The mark is generation-scoped: a stale pump's
    /// exit clears it only when it still names that pump's own
    /// generation, never a successor's.
    pub capture_pump_generation: u64,
    /// Stop request for the *current* generation, set by STREAMOFF
    /// teardown. The current generation's pump observes it at its next
    /// wake (loop top, and again before delivering a completed frame)
    /// and exits, consuming it. A new activation supersedes it: it
    /// targeted the stream being replaced, so activation clears it.
    pub capture_stop_requested: bool,
    /// `bcdUVC` from the VC HEADER descriptor (0x0100 when the header
    /// could not be parsed). Drives the PROBE/COMMIT wire length:
    /// 34 bytes for UVC 1.1+, 26 bytes otherwise.
    pub uvc_version: u16,
    /// Device clock frequency in Hz from the VC HEADER descriptor
    /// (0 when unknown). Offered as `dwClockFrequency` on 1.1+ PROBE.
    pub clock_frequency: u32,
    /// Index of the xHCI controller the camera is on
    /// ([`UvcTransport::controller_id`]); `slot_id` is only unique within it.
    pub controller: u8,
    /// Unit id of the first Processing Unit found in the VC
    /// descriptors (0 when the device has none). PU controls route
    /// here via `route_control`.
    pub pu_unit_id: u8,
    /// Unit id of the first Camera Terminal found in the VC
    /// descriptors (0 when the device has none). CT controls route
    /// here via `route_control`.
    pub ct_unit_id: u8,
    /// Controls the device's PU/CT descriptors advertise, with the
    /// wire length each reported via GET_LEN. The V4L2 control list
    /// installed on the `/dev/video<N>` node mirrors this table;
    /// controls absent from it are never advertised.
    pub controls: Vec<UvcControl>,
    /// Hub context for hub idle-suspend accounting: `Some((parent hub
    /// slot id, downstream port))` when the camera sits behind a hub,
    /// `None` on a root port. Recorded at bind (MSC/NCM/CDC-ACM
    /// precedent); the capture pump feeds it to
    /// [`crate::attach::mark_port_activity`] on every completed
    /// transfer, and the class suspend hook + TX-demand resume filter
    /// on it (#807).
    pub hub_port: Option<(u8, u8)>,
    /// Device-accepted VS PROBE/COMMIT values from the last successful
    /// negotiation — the parameters a suspend/resume cycle
    /// re-negotiates from. Written by negotiation success only, so a
    /// stream activated without negotiation has none.
    pub last_stream: Option<VsProbeCommit>,
    /// Stream that was active when the system-PM prepare hook quiesced
    /// the device: the resume replay's work-list. Set by prepare (from
    /// `last_stream`, only for a device whose stream was live) and
    /// taken by the resume replay; `None` means "nothing to restore".
    pub suspended_stream: Option<VsProbeCommit>,
}

/// System-wide registry of bound UVC devices (records carry their
/// controller).
pub static UVC_DEVICES: IrqSafeSpinLock<Vec<UvcDevice>> = IrqSafeSpinLock::new(Vec::new());

impl UvcDevice {
    /// Reassembler configuration for the currently negotiated stream
    /// (#1334): the negotiated `dwMaxVideoFrameSize` bounds
    /// accumulation and completes stream-based segments on buffer
    /// fullness (UVC 1.5 §2.4.3.7); `stream_based` is true exactly
    /// when the negotiated format index names a
    /// `VS_FORMAT_STREAM_BASED` entry in the retained format table,
    /// in which case FID/EOF are honoured only per the negotiated
    /// `bmFramingInfo`. With no negotiation on record the legacy
    /// config is returned (FID/EOF machine, unbounded) — the pump
    /// then behaves exactly as before this lane.
    pub(crate) fn reassembly_config(&self) -> ReassemblyConfig {
        let Some(negotiated) = self.negotiated else {
            return ReassemblyConfig::default();
        };
        let stream_based = self.formats.iter().any(|f| {
            f.format_index == negotiated.format_index
                && f.pixel_fmt == narf_drivers_video::uvc::PixelFmt::StreamBased
        });
        ReassemblyConfig {
            max_frame_size: negotiated.max_video_frame_size,
            stream_based,
            framing_info: negotiated.framing_info,
        }
    }
}

/// The slice of the xHCI surface the UVC streaming composition needs.
///
/// Production code runs against the live [`crate::xhci::Xhci`]; the
/// end-to-end fixture (`smoke_uvc_streamon_composition_e2e` in
/// `crate::tests`) runs the *same* bind / negotiate / activate /
/// deactivate / pump code against a modelled device implementing this
/// trait, so the composition is validated without silicon. The seam is
/// deliberately narrow — six operations, no controller state — so a
/// modelled transport stays a faithful device conversation (control
/// transfers, endpoint configuration, isochronous packets, bulk
/// transfers), not a
/// re-implementation of the composition itself.
///
/// Transports are shared across pump tasks (the live controller
/// behind an `Arc`, the modelled device behind an `Arc` in the
/// fixture), so the trait requires `Sync`: the pipelined receive
/// keeps several transfers in flight at once, each borrowing the
/// transport, and the owned-buffer adapter below must be `Send`.
pub trait UvcTransport: Sync {
    /// Index of the controller this transport drives
    /// ([`crate::xhci::Xhci::id`]); fixtures are controller 0.
    fn controller_id(&self) -> u8 {
        0
    }
    /// Host-to-device control transfer with an OUT data stage.
    fn control_out<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &'a [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a;
    /// Device-to-host control transfer; returns the byte count read.
    fn control_in<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a;
    /// Configure the given endpoints on the slot.
    fn configure_endpoints<'a>(
        &'a self,
        slot_id: u8,
        endpoints: &'a [crate::xhci::EndpointConfig],
    ) -> impl Future<Output = Result<(), crate::xhci::XhciError>> + Send + 'a;
    /// Receive one isochronous IN packet into `out`; returns the byte
    /// count (0 = no packet this service interval).
    fn isoch_in<'a>(
        &'a self,
        slot_id: u8,
        dci: u8,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a;
    /// Maximum number of concurrent `isoch_in` transfers this
    /// transport can serve on one endpoint — the pipeline depth the
    /// capture pump may keep in flight (#808).
    ///
    /// A transport returning N > 1 promises that N concurrent
    /// `isoch_in` calls on the same endpoint run against
    /// independent buffers and complete in submission order, so the
    /// pump can refill slots as they complete without reordering
    /// packets. The default is 1 (single-shot): the real xHCI
    /// transport keeps it — one isochronous TRB per endpoint shares
    /// the endpoint's single 4096-byte DMA page, and Transfer Events
    /// carry slot + endpoint identity only, so concurrent calls
    /// would overwrite each other's payloads. True multi-TRB
    /// pipelining with per-transfer buffers and TRB identity is
    /// #885's work, not this method's.
    fn isoch_pipeline_depth(&self) -> usize {
        1
    }
    /// Owned-buffer form of [`UvcTransport::isoch_in`]: takes a
    /// packet buffer by value and returns it alongside the byte
    /// count, so the pipelined pump can own one buffer per
    /// in-flight transfer instead of borrowing a shared ring.
    /// Borrowing the ring fails borrowck: several simultaneous
    /// `&mut` borrows into one ring cannot be held across loop
    /// iterations (the container's destructor extends each borrow
    /// to the container's scope), while owned buffers move in and
    /// out of the ring freely and the futures borrow only the
    /// shared `&self`.
    ///
    /// The default adapts the single-shot call, so a transport
    /// whose `isoch_in` calls are already independent (the modelled
    /// device: each call parks on its own staged packet) pipelines
    /// with no extra code. A transport with shared per-endpoint
    /// state must keep [`UvcTransport::isoch_pipeline_depth`] at 1
    /// so the pump never calls this concurrently on one endpoint.
    fn isoch_in_owned<'a>(
        &'a self,
        slot_id: u8,
        dci: u8,
        mut out: Vec<u8>,
    ) -> impl Future<Output = (Vec<u8>, Result<usize, crate::xhci::XhciError>)> + Send + 'a {
        async move {
            let received = self.isoch_in(slot_id, dci, &mut out).await;
            (out, received)
        }
    }
    /// Receive one bulk IN transfer into `out`; returns the byte
    /// count (0 = empty transfer; a short transfer ends at the
    /// device's packet boundary). Bulk transfers carry the same UVC
    /// payload header framing as isochronous packets (UVC §2.4.3.3),
    /// so the capture pump feeds them into the same
    /// [`UvcFrameReassembler`] path.
    fn bulk_in<'a>(
        &'a self,
        slot_id: u8,
        dci: u8,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a;
}

impl UvcTransport for crate::xhci::Xhci {
    fn controller_id(&self) -> u8 {
        self.id()
    }

    fn control_out<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &'a [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a {
        // Fully-qualified inherent method (same name) — not this
        // trait method.
        crate::xhci::Xhci::control_out(
            self,
            slot_id,
            bm_request_type,
            b_request,
            w_value,
            w_index,
            data,
        )
    }

    fn control_in<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a {
        crate::xhci::Xhci::control_in(
            self,
            slot_id,
            bm_request_type,
            b_request,
            w_value,
            w_index,
            out,
        )
    }

    fn configure_endpoints<'a>(
        &'a self,
        slot_id: u8,
        endpoints: &'a [crate::xhci::EndpointConfig],
    ) -> impl Future<Output = Result<(), crate::xhci::XhciError>> + Send + 'a {
        crate::xhci::Xhci::configure_endpoints(self, slot_id, endpoints)
    }

    fn isoch_in<'a>(
        &'a self,
        slot_id: u8,
        dci: u8,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a {
        crate::xhci::Xhci::isoch_in(self, slot_id, dci, out)
    }

    fn isoch_pipeline_depth(&self) -> usize {
        // Single-shot only: `Xhci::isoch_in` stages every transfer
        // in the endpoint's single 4096-byte DMA page and matches
        // completions by slot + endpoint, so two concurrent calls
        // would DMA into the same page (see #885). The pump's
        // pipelined receive still runs for transports that advertise
        // depth > 1; this transport advertises 1 until #885 lands
        // per-transfer buffers and TRB identity.
        1
    }

    fn bulk_in<'a>(
        &'a self,
        slot_id: u8,
        dci: u8,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, crate::xhci::XhciError>> + Send + 'a {
        crate::xhci::Xhci::bulk_in(self, slot_id, dci, out)
    }
}

/// Find the first VideoControl interface in `cfg`.
pub fn find_video_control_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            if cls == USB_CLASS_VIDEO && sub == USB_VIDEO_SUBCLASS_VIDEOCONTROL {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}

/// Find the first VideoStreaming interface in `cfg`. Alternate setting
/// zero is sufficient: every alternate for one stream shares the same
/// `bInterfaceNumber`.
pub fn find_video_streaming_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04
            && len >= 9
            && cfg[i + 5] == USB_CLASS_VIDEO
            && cfg[i + 6] == USB_VIDEO_SUBCLASS_VIDEOSTREAMING
        {
            return Some(cfg[i + 2]);
        }
        i += len;
    }
    None
}

// ── VC control-unit discovery + GET/SET_CUR query (#809) ─────────────
//
// The VideoControl class-specific blob carries the entities that own
// the camera's controls: the Camera Terminal (bmControls per UVC 1.5
// §3.7.2.3 Table 3-6) and the Processing Unit (bmControls per §3.7.2.5
// Table 3-8). Bind walks the blob, builds the V4L2 control list from
// the bitmaps (`supported_controls`: bit N ↔ selector N+1), and reads
// each advertised control's range from the hardware (GET_LEN →
// GET_MIN/GET_MAX/GET_RES/GET_DEF/GET_CUR) so the V4L2 surface
// reports device values, never an invented table. A control whose
// query fails, whose length has no V4L2 integer mapping, or whose
// device-reported range is inverted is skipped, not advertised.

/// One VC control unit found in a class-specific blob:
/// `(unit_id, bmControls bitmap)`.
pub type VcControlUnit = (u8, u32);

/// First Camera Terminal / Processing Unit found in a VC
/// class-specific blob: one [`VcControlUnit`] each, or
/// `None` when the blob carries no such entity.
pub type VcControlUnits = (Option<VcControlUnit>, Option<VcControlUnit>);

/// First Camera Terminal / Processing Unit found in a VC
/// class-specific blob: `(unit_id, bmControls bitmap)` each, or
/// `None` when the blob carries no such entity. Only the first of
/// each kind is retained — multi-PU/multi-CT topologies are not
/// modelled (see the #809 remainder note in
/// [`try_bind_video_with_transport`]).
pub fn parse_vc_control_units(vc_cs_blob: &[u8]) -> VcControlUnits {
    let mut ct: Option<(u8, u32)> = None;
    let mut pu: Option<(u8, u32)> = None;
    let mut i = 0usize;
    while i + 3 <= vc_cs_blob.len() {
        let len = vc_cs_blob[i] as usize;
        if len < 3 || i + len > vc_cs_blob.len() {
            break;
        }
        if vc_cs_blob[i + 1] == CS_INTERFACE {
            match vc_cs_blob[i + 2] {
                VC_INPUT_TERMINAL if ct.is_none() => {
                    if let Ok(it) = InputTerminal::parse(&vc_cs_blob[i..i + len]) {
                        if let Some(camera) = it.camera {
                            ct = Some((it.terminal_id, camera.controls));
                        }
                    }
                }
                VC_PROCESSING_UNIT if pu.is_none() => {
                    if let Ok(unit) = ProcessingUnit::parse(&vc_cs_blob[i..i + len]) {
                        pu = Some((unit.unit_id, unit.controls));
                    }
                }
                _ => {}
            }
        }
        i += len;
    }
    (ct, pu)
}

/// One descriptor-advertised control with its hardware-reported
/// range, ready to install as a V4L2 [`ControlState`].
#[derive(Debug)]
pub struct BoundUvcControl {
    pub id: narf_drivers_video::uvc::ControlId,
    /// Payload length in bytes (1, 2, or 4) from GET_LEN.
    pub len: u8,
    pub state: narf_drivers_video::v4l2_ioctl::ControlState,
}

/// Issue one UVC GET_* control query and return the payload bytes.
/// `None` on transfer failure or a short read — the caller skips
/// that control rather than advertising a range it never read.
async fn query_control<T: UvcTransport>(
    transport: &T,
    slot_id: u8,
    vc_iface: u8,
    request: u8,
    selector: u8,
    unit_id: u8,
    len: usize,
) -> Option<Vec<u8>> {
    use narf_drivers_video::uvc::control::{bm_request_type, w_index, w_value};
    let mut buf = alloc::vec![0u8; len];
    let n = transport
        .control_in(
            slot_id,
            bm_request_type(request),
            request,
            w_value(selector),
            w_index(unit_id, vc_iface),
            &mut buf,
        )
        .await
        .ok()?;
    if n < len {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// Query the hardware ranges for every control the PU/CT bitmaps
/// advertise and build the V4L2 control list from them.
///
/// Per control, in order: GET_LEN (the 2-byte length answer, UVC 1.5
/// §A.8 — the device itself reports the payload size, so no size is
/// ever assumed), then GET_MIN / GET_MAX / GET_DEF / GET_CUR at that
/// length, and GET_RES for the step (a failed GET_RES falls back to
/// step 1, the V4L2 default step). Any failure, an unsupported
/// length, or an inverted `[min, max]` range skips that control.
/// Returns `(bound_controls, pu_unit_id, ct_unit_id)`.
pub async fn query_uvc_controls<T: UvcTransport>(
    transport: &T,
    slot_id: u8,
    vc_iface: u8,
    vc_cs_blob: &[u8],
) -> (Vec<BoundUvcControl>, u8, u8) {
    use narf_drivers_video::uvc::control::{
        decode_control_value, supported_controls, GET_CUR, GET_DEF, GET_LEN, GET_MAX, GET_MIN,
        GET_RES,
    };
    let (ct, pu) = parse_vc_control_units(vc_cs_blob);
    let (ct_unit_id, ct_bitmap) = ct.unwrap_or((0, 0));
    let (pu_unit_id, pu_bitmap) = pu.unwrap_or((0, 0));
    let mut out = Vec::new();
    for id in supported_controls(pu_bitmap, ct_bitmap) {
        let Some((unit_id, selector)) =
            narf_drivers_video::uvc::route_control(id, pu_unit_id, ct_unit_id)
        else {
            continue;
        };
        // GET_LEN answers a 2-byte little-endian length.
        let len_bytes = match query_control(
            transport, slot_id, vc_iface, GET_LEN, selector, unit_id, 2,
        )
        .await
        {
            Some(b) => b,
            None => continue,
        };
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if !matches!(len, 1 | 2 | 4) {
            continue;
        }
        let (Some(min_b), Some(max_b), Some(def_b), Some(cur_b)) = (
            query_control(
                transport, slot_id, vc_iface, GET_MIN, selector, unit_id, len,
            )
            .await,
            query_control(
                transport, slot_id, vc_iface, GET_MAX, selector, unit_id, len,
            )
            .await,
            query_control(
                transport, slot_id, vc_iface, GET_DEF, selector, unit_id, len,
            )
            .await,
            query_control(
                transport, slot_id, vc_iface, GET_CUR, selector, unit_id, len,
            )
            .await,
        ) else {
            continue;
        };
        let (Some(min), Some(max), Some(def), Some(cur)) = (
            decode_control_value(&min_b),
            decode_control_value(&max_b),
            decode_control_value(&def_b),
            decode_control_value(&cur_b),
        ) else {
            continue;
        };
        if min > max {
            continue;
        }
        // GET_RES (step); a device that cannot answer it gets step 1.
        let step = query_control(
            transport, slot_id, vc_iface, GET_RES, selector, unit_id, len,
        )
        .await
        .and_then(|b| decode_control_value(&b))
        .filter(|&s| s > 0)
        .unwrap_or(1);
        let value = cur.clamp(min, max);
        out.push(BoundUvcControl {
            id,
            len: len as u8,
            state: narf_drivers_video::v4l2_ioctl::ControlState {
                id: id.v4l2_id(),
                name: id.name(),
                min,
                max,
                step,
                default: def,
                value,
            },
        });
    }
    (out, pu_unit_id, ct_unit_id)
}

/// Transport-generic GET_CUR for one V4L2 control id on `/dev/video<node>`.
/// Resolves the node to its bound device, routes the id through
/// `route_control` to the owning unit/selector, and issues the
/// hardware GET_CUR. Returns the device-reported value, or the
/// positive Linux errno on failure.
pub async fn control_get_with<T: UvcTransport>(
    transport: &T,
    node: usize,
    id: u32,
) -> Result<i32, i64> {
    use narf_drivers_video::uvc::control::{decode_control_value, route_control, GET_CUR};
    let control_id = narf_drivers_video::uvc::ControlId::from_v4l2_id(id).ok_or(ERRNO_ENODEV)?;
    let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
    let (slot_id, vc_iface, pu_unit_id, ct_unit_id, len) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(ERRNO_ENODEV)?;
        let entry = device
            .controls
            .iter()
            .find(|c| c.id == control_id)
            .ok_or(ERRNO_ENODEV)?;
        (
            device.slot_id,
            device.vc_iface,
            device.pu_unit_id,
            device.ct_unit_id,
            entry.len,
        )
    };
    let (unit_id, selector) =
        route_control(control_id, pu_unit_id, ct_unit_id).ok_or(ERRNO_ENODEV)?;
    let buf = query_control(
        transport,
        slot_id,
        vc_iface,
        GET_CUR,
        selector,
        unit_id,
        len as usize,
    )
    .await
    .ok_or(ERRNO_EIO)?;
    decode_control_value(&buf).ok_or(ERRNO_EIO)
}

/// Transport-generic SET_CUR for one V4L2 control id on `/dev/video<node>`.
/// Same resolution as [`control_get_with`]; encodes the clamped
/// value at the GET_LEN-reported length and returns the value the
/// transfer carried (the device echoes nothing on SET_CUR, so the
/// clamped value is the confirmed one).
pub async fn control_set_with<T: UvcTransport>(
    transport: &T,
    node: usize,
    id: u32,
    value: i32,
) -> Result<i32, i64> {
    use narf_drivers_video::uvc::control::{encode_control_value, route_control, SET_CUR};
    let control_id = narf_drivers_video::uvc::ControlId::from_v4l2_id(id).ok_or(ERRNO_ENODEV)?;
    let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
    let (slot_id, vc_iface, pu_unit_id, ct_unit_id, len) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(ERRNO_ENODEV)?;
        let entry = device
            .controls
            .iter()
            .find(|c| c.id == control_id)
            .ok_or(ERRNO_ENODEV)?;
        (
            device.slot_id,
            device.vc_iface,
            device.pu_unit_id,
            device.ct_unit_id,
            entry.len,
        )
    };
    let (unit_id, selector) =
        route_control(control_id, pu_unit_id, ct_unit_id).ok_or(ERRNO_ENODEV)?;
    let mut payload = [0u8; 4];
    if !encode_control_value(value, len, &mut payload) {
        return Err(ERRNO_EIO);
    }
    transport
        .control_out(
            slot_id,
            narf_drivers_video::uvc::control::bm_request_type(SET_CUR),
            SET_CUR,
            narf_drivers_video::uvc::control::w_value(selector),
            narf_drivers_video::uvc::control::w_index(unit_id, vc_iface),
            &payload[..len as usize],
        )
        .await
        .map_err(|_| ERRNO_EIO)?;
    Ok(value)
}

/// Transport-generic core of [`try_bind_video_already_addressed`]:
/// SET_CONFIGURATION, then record the slot/interface pair, the parsed
/// streaming format table, and register the `/dev/video<N>` node.
/// `hub_port` is the attach cascade's hub context (parent hub slot +
/// downstream port, `None` on a root port); it is recorded for the
/// hub idle-suspend accounting in #807.
pub async fn try_bind_video_with_transport<T: UvcTransport>(
    transport: &T,
    slot_id: u8,
    cfg: &[u8],
    hub_port: Option<(u8, u8)>,
) -> Result<usize, UvcError> {
    let vc_iface = find_video_control_interface(cfg).ok_or(UvcError::NotVideo)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    let nothing = [0u8; 0];
    if transport
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &nothing,
        )
        .await
        .is_err()
    {
        return Err(UvcError::SetConfigFailed);
    }
    let streaming_endpoints = find_video_streaming_endpoints(cfg);
    let vs_iface = find_video_streaming_interface(cfg).ok_or(UvcError::NoStreamingEndpoint)?;
    // Advertise the camera's real formats/resolutions by parsing its
    // VideoStreaming class-specific descriptors; fall back to the default table
    // (inside register_video_with_formats) if the probe or parse yields nothing.
    // The parsed table itself is retained on the device: STREAMON maps the
    // S_FMT-committed format back to UVC indices through it.
    let probe = narf_drivers_video::uvc::probe_uvc(cfg).ok();
    let stream_formats = probe
        .as_ref()
        .map(|p| {
            narf_drivers_video::uvc::parse_streaming_descriptors(&p.vs_cs_blob).unwrap_or_default()
        })
        .unwrap_or_default();
    // The VC HEADER is the first class-specific VC descriptor; its bcdUVC
    // selects the PROBE/COMMIT wire length and its clock feeds
    // dwClockFrequency on 1.1+ PROBE. Unparseable → 1.0 behaviour.
    let (uvc_version, clock_frequency) = probe
        .as_ref()
        .and_then(|p| VcHeader::parse(&p.vc_cs_blob).ok())
        .map(|h| (h.bcd_uvc, h.clock_frequency))
        .unwrap_or((0x0100, 0));
    let formats = narf_drivers_video::v4l2_ioctl::uvc_to_v4l2_formats(&stream_formats);
    // Build the V4L2 control list from the device's real PU/CT
    // descriptors, with ranges read from the hardware (#809). The
    // query runs against the live transport before the node is
    // registered, so the node never advertises the synthetic
    // default table: a camera whose descriptors advertise no
    // controls gets an empty list. Only the first Camera Terminal
    // and first Processing Unit are retained — multi-PU/multi-CT
    // topologies are a known remainder, not modelled here.
    let (bound_controls, pu_unit_id, ct_unit_id) = match &probe {
        Some(p) => query_uvc_controls(transport, slot_id, vc_iface, &p.vc_cs_blob).await,
        None => (Vec::new(), 0, 0),
    };
    let video_node =
        narf_drivers_video::devfs_bridge::register_video_with_formats("USB Video Device", formats);
    narf_drivers_video::devfs_bridge::set_controls(
        video_node,
        bound_controls.iter().map(|b| b.state).collect(),
    );
    let mut g = UVC_DEVICES.lock();
    let idx = g.len();
    g.push(UvcDevice {
        slot_id,
        vc_iface,
        vs_iface,
        streaming_endpoints,
        formats: stream_formats,
        active_stream: None,
        negotiated: None,
        video_node,
        stream_generation: 0,
        capture_pump_generation: 0,
        capture_stop_requested: false,
        uvc_version,
        clock_frequency,
        controller: transport.controller_id(),
        pu_unit_id,
        ct_unit_id,
        controls: bound_controls
            .iter()
            .map(|b| UvcControl {
                id: b.id,
                len: b.len,
            })
            .collect(),
        hub_port,
        last_stream: None,
        suspended_stream: None,
    });
    Ok(idx)
}

/// Bind to an already-addressed UVC device. SET_CONFIGURATION,
/// then record the slot/interface pair. Also installs the V4L2
/// streaming hooks on the registered node, so `VIDIOC_STREAMON` /
/// `VIDIOC_STREAMOFF` drive this device's negotiation and teardown.
pub async fn try_bind_video_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
    hub_port: Option<(u8, u8)>,
) -> Result<usize, UvcError> {
    let idx = try_bind_video_with_transport(xhci_dev, slot_id, cfg, hub_port).await?;
    let video_node = {
        let devices = UVC_DEVICES.lock();
        devices.get(idx).map(|device| device.video_node)
    };
    if let Some(video_node) = video_node {
        narf_drivers_video::devfs_bridge::set_stream_ops(video_node, video_stream_ops());
        narf_drivers_video::devfs_bridge::set_control_ops(video_node, video_control_ops());
    }
    Ok(idx)
}

/// Canonical public entry-point for UVC device bind (alias for
/// [`try_bind_video_already_addressed`]). Spec-name per UVC §4.2:
/// "already addressed" = slot is assigned, SET_CONFIGURATION not yet
/// issued. Returns the device index into [`UVC_DEVICES`].
///
/// Bind records all streaming alternates without opening one; call
/// [`activate_video_stream`] after UVC PROBE/COMMIT returns the accepted
/// maximum payload size.
pub async fn try_bind_uvc_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, UvcError> {
    try_bind_video_already_addressed(xhci_dev, slot_id, cfg, None).await
}

/// Retain every bulk/isochronous IN endpoint together with the
/// VideoStreaming interface alternate that owns it.
pub fn find_video_streaming_endpoints(cfg: &[u8]) -> Vec<UvcStreamingEndpoint> {
    let mut endpoints = Vec::new();
    let mut i = 0;
    let mut vs_iface = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            vs_iface = (cls == USB_CLASS_VIDEO && sub == USB_VIDEO_SUBCLASS_VIDEOSTREAMING)
                .then_some((cfg[i + 2], cfg[i + 3]));
        } else if desc_type == 0x05 && len >= 7 {
            let Some((interface_number, alternate_setting)) = vs_iface else {
                i += len;
                continue;
            };
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let transfer_type = attrs & 0x03;
            let transport = match transfer_type {
                1 => UvcStreamingTransport::Isochronous,
                2 => UvcStreamingTransport::Bulk,
                _ => {
                    i += len;
                    continue;
                }
            };
            let ep_num = ep_addr & 0x0f;
            if ep_addr & 0x80 != 0 && ep_num != 0 {
                let raw_max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let max_packet_size = raw_max_packet & 0x07ff;
                let transactions_per_interval = if transport == UvcStreamingTransport::Isochronous {
                    (((raw_max_packet >> 11) & 0x03) + 1) as u8
                } else {
                    1
                };
                // 0b11 in wMaxPacketSize[12:11] is reserved by USB 2.0.
                if max_packet_size != 0 && transactions_per_interval <= 3 {
                    endpoints.push(UvcStreamingEndpoint {
                        interface_number,
                        alternate_setting,
                        endpoint_address: ep_addr,
                        dci: (ep_num * 2) + 1,
                        transport,
                        raw_max_packet,
                        max_packet_size,
                        transactions_per_interval,
                        max_payload_size: u32::from(max_packet_size)
                            * u32::from(transactions_per_interval),
                        interval: cfg[i + 6],
                    });
                }
            }
        }
        i += len;
    }
    endpoints
}

/// Scan the config blob for the first VideoStreaming isoch-IN DCI.
/// Compatibility helper for descriptor-only callers; activation must
/// use [`activate_video_stream`] so the owning alternate is selected.
pub fn find_video_streaming_iso_in_ep(cfg: &[u8]) -> u8 {
    find_video_streaming_endpoints(cfg)
        .into_iter()
        .find(|endpoint| endpoint.transport == UvcStreamingTransport::Isochronous)
        .map_or(0, |endpoint| endpoint.dci)
}

/// Choose the least-bandwidth isoch alternate that can carry the
/// device-accepted `dwMaxPayloadTransferSize` from UVC PROBE.
pub fn select_video_streaming_iso_endpoint(
    endpoints: &[UvcStreamingEndpoint],
    required_payload: u32,
) -> Option<UvcStreamingEndpoint> {
    select_video_streaming_iso_endpoint_for_interface(endpoints, None, required_payload)
}

fn select_video_streaming_iso_endpoint_for_interface(
    endpoints: &[UvcStreamingEndpoint],
    interface_number: Option<u8>,
    required_payload: u32,
) -> Option<UvcStreamingEndpoint> {
    endpoints
        .iter()
        .copied()
        .filter(|endpoint| endpoint.transport == UvcStreamingTransport::Isochronous)
        .filter(|endpoint| {
            interface_number.is_none_or(|number| endpoint.interface_number == number)
        })
        .filter(|endpoint| endpoint.max_payload_size >= required_payload)
        .min_by_key(|endpoint| {
            (
                endpoint.max_payload_size,
                endpoint.alternate_setting,
                endpoint.endpoint_address,
            )
        })
}

/// Choose the least-bandwidth bulk alternate, with no payload gate.
///
/// Bulk transfers reserve no interval bandwidth: the transfer length
/// is host-chosen (the pump's buffer), and the device returns up to
/// that many bytes, so the PROBE-accepted `dwMaxPayloadTransferSize`
/// — an isochronous bandwidth figure — is not a per-transfer cap
/// for bulk. Gating bulk alternates on it would reject every bulk
/// endpoint whose `wMaxPacketSize` is smaller than the PROBE figure
/// even though the transfer would succeed. Activation therefore
/// tries the isochronous selector first and falls back here.
pub fn select_video_streaming_bulk_endpoint(
    endpoints: &[UvcStreamingEndpoint],
) -> Option<UvcStreamingEndpoint> {
    select_video_streaming_bulk_endpoint_for_interface(endpoints, None)
}

fn select_video_streaming_bulk_endpoint_for_interface(
    endpoints: &[UvcStreamingEndpoint],
    interface_number: Option<u8>,
) -> Option<UvcStreamingEndpoint> {
    endpoints
        .iter()
        .copied()
        .filter(|endpoint| endpoint.transport == UvcStreamingTransport::Bulk)
        .filter(|endpoint| {
            interface_number.is_none_or(|number| endpoint.interface_number == number)
        })
        .min_by_key(|endpoint| {
            (
                endpoint.max_payload_size,
                endpoint.alternate_setting,
                endpoint.endpoint_address,
            )
        })
}

/// Isochronous-first streaming endpoint selection for activation:
/// the least-bandwidth isochronous alternate satisfying PROBE, or —
/// when no isochronous endpoint qualifies (bulk-only cameras) — the
/// least-bandwidth bulk alternate. `None` only when the interface
/// has no usable streaming endpoint of either kind.
fn select_video_streaming_endpoint_for_activation(
    endpoints: &[UvcStreamingEndpoint],
    interface_number: u8,
    required_payload: u32,
) -> Option<UvcStreamingEndpoint> {
    select_video_streaming_iso_endpoint_for_interface(
        endpoints,
        Some(interface_number),
        required_payload,
    )
    .or_else(|| {
        select_video_streaming_bulk_endpoint_for_interface(endpoints, Some(interface_number))
    })
}

/// Configure and select the VideoStreaming alternate chosen for the
/// payload size accepted by UVC PROBE/COMMIT — the least-bandwidth
/// isochronous alternate satisfying it, or, when no isochronous
/// endpoint qualifies, the least-bandwidth bulk alternate (bulk
/// transfers reserve no interval bandwidth, so no payload gate
/// applies there).
pub async fn activate_video_stream(
    xhci_dev: &crate::xhci::Xhci,
    idx: usize,
    required_payload: u32,
) -> Result<UvcStreamingEndpoint, UvcError> {
    activate_video_stream_with(xhci_dev, idx, required_payload).await
}

/// Transport-generic core of [`activate_video_stream`].
pub async fn activate_video_stream_with<T: UvcTransport>(
    transport: &T,
    idx: usize,
    required_payload: u32,
) -> Result<UvcStreamingEndpoint, UvcError> {
    let (slot_id, endpoint) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(UvcError::NotVideo)?;
        let vs_iface = device.vs_iface;
        if let Some(active) = device.active_stream {
            let selected = select_video_streaming_endpoint_for_activation(
                &device.streaming_endpoints,
                vs_iface,
                required_payload,
            )
            .ok_or(UvcError::NoStreamingEndpoint)?;
            if active == selected {
                return Ok(active);
            }
            return Err(UvcError::AlreadyStreaming);
        }
        let selected = select_video_streaming_endpoint_for_activation(
            &device.streaming_endpoints,
            vs_iface,
            required_payload,
        )
        .ok_or(UvcError::NoStreamingEndpoint)?;
        (device.slot_id, selected)
    };

    let endpoint_config = crate::xhci::EndpointConfig {
        ep_addr: endpoint.endpoint_address,
        max_packet: endpoint.raw_max_packet,
        kind: match endpoint.transport {
            UvcStreamingTransport::Isochronous => crate::xhci::EndpointKind::IsochIn,
            UvcStreamingTransport::Bulk => crate::xhci::EndpointKind::BulkIn,
        },
        interval: endpoint.interval,
    };
    transport
        .configure_endpoints(slot_id, &[endpoint_config])
        .await
        .map_err(|_| UvcError::ConfigureEndpointFailed)?;
    transport
        .control_out(
            slot_id,
            crate::control::RT_DIR_OUT
                | crate::control::RT_TYPE_STANDARD
                | crate::control::RT_RECIP_INTERFACE,
            crate::control::REQ_SET_INTERFACE,
            u16::from(endpoint.alternate_setting),
            u16::from(endpoint.interface_number),
            &[],
        )
        .await
        .map_err(|_| UvcError::SetInterfaceFailed)?;

    let mut devices = UVC_DEVICES.lock();
    let device = devices.get_mut(idx).ok_or(UvcError::NotVideo)?;
    device.active_stream = Some(endpoint);
    // A successful activation starts a new stream generation: pumps
    // of older generations are now stale (they exit at their next
    // wake without delivering), and a stop request still standing
    // from the superseded stream's teardown is void — it must not
    // kill the pump this activation is about to spawn.
    device.stream_generation = device.stream_generation.wrapping_add(1);
    device.capture_stop_requested = false;
    Ok(endpoint)
}

/// Reverse [`activate_video_stream`]: stop the capture pump and
/// release the streaming alternate setting (STREAMOFF teardown).
pub async fn deactivate_video_stream(
    xhci_dev: &crate::xhci::Xhci,
    idx: usize,
) -> Result<(), UvcError> {
    deactivate_video_stream_with(xhci_dev, idx).await
}

/// Transport-generic core of [`deactivate_video_stream`].
///
/// Requests the current generation's capture pump to stop first (it
/// observes `capture_stop_requested` at its next wake — a pump parked
/// in a transfer on the now-silent interface may not wake until the
/// next stream sources packets, which is safe: the generation
/// protocol in [`pump_video_frames_with`] keeps a late-waking pump
/// from delivering into, or consuming the lifecycle state of, any
/// successor stream), then
/// selects the zero-bandwidth alternate setting 0 on the
/// VideoStreaming interface — the exact reverse of activation's
/// `configure_endpoints` → `SET_INTERFACE(alt)` order, minus endpoint
/// deconfiguration (xHCI has no drop-endpoint path in-tree; alt 0
/// already stops the device sourcing packets). The software
/// `active_stream` record is cleared before the control transfer: if
/// SET_INTERFACE fails the stream is unusable either way, and a stale
/// record would wedge every later STREAMON with `AlreadyStreaming`.
pub async fn deactivate_video_stream_with<T: UvcTransport>(
    transport: &T,
    idx: usize,
) -> Result<(), UvcError> {
    let (slot_id, active) = {
        let mut devices = UVC_DEVICES.lock();
        let device = devices.get_mut(idx).ok_or(UvcError::NotVideo)?;
        device.capture_stop_requested = true;
        // The negotiated control goes with the stream: a later pump
        // must never reassemble against superseded parameters.
        device.negotiated = None;
        (device.slot_id, device.active_stream.take())
    };
    if let Some(endpoint) = active {
        transport
            .control_out(
                slot_id,
                crate::control::RT_DIR_OUT
                    | crate::control::RT_TYPE_STANDARD
                    | crate::control::RT_RECIP_INTERFACE,
                crate::control::REQ_SET_INTERFACE,
                0,
                u16::from(endpoint.interface_number),
                &[],
            )
            .await
            .map_err(|_| UvcError::SetInterfaceFailed)?;
    }
    Ok(())
}

/// Result of a complete UVC streaming negotiation and alternate activation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UvcNegotiatedStream {
    pub control: VsProbeCommit,
    pub endpoint: UvcStreamingEndpoint,
}

/// Store the device-accepted Probe/Commit control on the device
/// record (see [`UvcDevice::negotiated`]) after a successful
/// negotiation + activation, so the capture pump can derive its
/// reassembler configuration from the negotiated stream parameters.
fn retain_negotiated_stream(idx: usize, accepted: VsProbeCommit) {
    if let Some(device) = UVC_DEVICES.lock().get_mut(idx) {
        device.negotiated = Some(accepted);
    }
}

/// Run the version-aware negotiation sequence (26-byte UVC 1.0,
/// 34-byte UVC 1.1+ per the device's VC HEADER `bcdUVC`), then configure
/// and select the least-bandwidth isochronous alternate that satisfies the
/// device-accepted maximum payload size (bulk fallback when none
/// qualifies), and start the capture pump.
pub async fn negotiate_and_activate_video_stream(
    xhci_dev: &crate::xhci::Xhci,
    idx: usize,
    desired: VsProbeCommit,
) -> Result<UvcNegotiatedStream, UvcError> {
    // A port the hub idle-suspend pass gated while the camera was
    // idle must come back before the negotiation transfers (#807).
    ensure_uvc_port_awake(xhci_dev, idx).await;
    let negotiated = negotiate_and_activate_video_stream_with(xhci_dev, idx, desired).await?;
    start_video_capture_pump(idx);
    Ok(negotiated)
}

/// Transport-generic core of [`negotiate_and_activate_video_stream`] —
/// everything except the capture-pump spawn, so fixtures can drive the
/// pump themselves. If activation fails after COMMIT succeeded, the
/// VideoStreaming interface is returned to its zero-bandwidth
/// alternate setting (best effort) before the error propagates: the
/// device must not be left committed to a stream nobody opened.
pub async fn negotiate_and_activate_video_stream_with<T: UvcTransport>(
    transport: &T,
    idx: usize,
    desired: VsProbeCommit,
) -> Result<UvcNegotiatedStream, UvcError> {
    let (slot_id, vs_iface, uvc_version) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(UvcError::NotVideo)?;
        (device.slot_id, device.vs_iface, device.uvc_version)
    };
    // The wire length follows the device's VC HEADER bcdUVC, not the
    // caller's struct: a 1.1+ device must never receive a truncated
    // 26-byte PROBE, and a 1.0 device must never receive 34 bytes.
    let probe_len = VsProbeCommit::len_for(uvc_version);
    let request_type_out = crate::control::RT_DIR_OUT
        | crate::control::RT_TYPE_CLASS
        | crate::control::RT_RECIP_INTERFACE;
    let request_type_in = crate::control::RT_DIR_IN
        | crate::control::RT_TYPE_CLASS
        | crate::control::RT_RECIP_INTERFACE;
    let desired_bytes = desired.encode_for(uvc_version);
    transport
        .control_out(
            slot_id,
            request_type_out,
            VS_REQ_SET_CUR,
            VS_PROBE_CONTROL,
            u16::from(vs_iface),
            &desired_bytes,
        )
        .await
        .map_err(|_| UvcError::ProbeFailed)?;

    let mut accepted_bytes = [0u8; VsProbeCommit::LEN_V15];
    let accepted_len = transport
        .control_in(
            slot_id,
            request_type_in,
            VS_REQ_GET_CUR,
            VS_PROBE_CONTROL,
            u16::from(vs_iface),
            &mut accepted_bytes,
        )
        .await
        .map_err(|_| UvcError::ProbeFailed)?;
    if accepted_len < probe_len {
        return Err(UvcError::ProbeFailed);
    }
    let accepted = VsProbeCommit::decode(&accepted_bytes[..accepted_len])
        .map_err(|_| UvcError::ProbeFailed)?;
    // GET_CUR version validation (#1244, UVC 1.5 §4.3.1.1): a 34-byte
    // response carries version fields, and the device's preferred
    // version must lie inside its own declared [min, max] range. A
    // malformed triple is a negotiation failure, not a COMMIT:
    // committing it verbatim would lock in a payload version the
    // device never offered. 26-byte (1.0) responses carry no version
    // fields and skip this check.
    if accepted_len >= VsProbeCommit::LEN_V15 && !accepted.accepted_versions_valid() {
        return Err(UvcError::ProbeFailed);
    }
    // COMMIT carries the device-accepted values at the same version
    // length — including the device's 1.1+ clock and version fields.
    let accepted_encoded = accepted.encode_for(uvc_version);
    transport
        .control_out(
            slot_id,
            request_type_out,
            VS_REQ_SET_CUR,
            VS_COMMIT_CONTROL,
            u16::from(vs_iface),
            &accepted_encoded,
        )
        .await
        .map_err(|_| UvcError::CommitFailed)?;

    let endpoint = match activate_video_stream_with(
        transport,
        idx,
        accepted.max_payload_transfer_size,
    )
    .await
    {
        Ok(endpoint) => endpoint,
        Err(e) => {
            // Unwind the commit: best-effort SET_INTERFACE to the
            // zero-bandwidth alternate before reporting the failure.
            let _ = transport
                .control_out(
                    slot_id,
                    crate::control::RT_DIR_OUT
                        | crate::control::RT_TYPE_STANDARD
                        | crate::control::RT_RECIP_INTERFACE,
                    crate::control::REQ_SET_INTERFACE,
                    0,
                    u16::from(vs_iface),
                    &[],
                )
                .await;
            return Err(e);
        }
    };
    // Retain the device-accepted control before returning: the
    // capture pump derives its reassembler configuration from it.
    // `VsProbeCommit` is `Copy`, so `accepted` is still available
    // for the return value below.
    retain_negotiated_stream(idx, accepted);
    // Record the device-accepted parameters: a later suspend/resume
    // cycle re-negotiates from exactly these values (#807). Only a
    // successful negotiation writes the record.
    {
        let mut devices = UVC_DEVICES.lock();
        if let Some(device) = devices.get_mut(idx) {
            device.last_stream = Some(accepted);
        }
    }
    Ok(UvcNegotiatedStream {
        control: accepted,
        endpoint,
    })
}

/// Claim the capture-pump slot for the device's current stream
/// generation. Returns the generation a new pump must run (and later
/// release) under, or `None` when a pump for *this* generation is
/// already marked or no stream has ever been activated.
///
/// The claim is generation-scoped, not a boolean: a pump of an older
/// generation still marked — e.g. parked in a transfer that only the
/// new stream's packets will resolve — never blocks the claim. The
/// stale pump retires itself at its next wake (see
/// [`pump_video_frames_with`]); until then two pumps may briefly
/// coexist, which the generation checks in the pump make harmless.
pub fn claim_capture_pump(idx: usize) -> Option<u64> {
    let mut devices = UVC_DEVICES.lock();
    let device = devices.get_mut(idx)?;
    let generation = device.stream_generation;
    if generation == 0 || device.capture_pump_generation == generation {
        return None;
    }
    device.capture_pump_generation = generation;
    Some(generation)
}

/// Release a capture-pump claim taken under `generation`. The mark
/// is cleared only when it still names `generation`: a stale pump's
/// exit must never clear the mark of the successor pump that
/// superseded it.
pub fn release_capture_pump(idx: usize, generation: u64) {
    if let Some(device) = UVC_DEVICES.lock().get_mut(idx) {
        if device.capture_pump_generation == generation {
            device.capture_pump_generation = 0;
        }
    }
}

/// Spawn the packet-to-frame pump for the activated camera's current
/// stream generation. Completed frames are delivered to the camera's
/// registered `/dev/video<N>` queue.
fn start_video_capture_pump(idx: usize) {
    let Some(generation) = claim_capture_pump(idx) else {
        return;
    };
    narf_scheduler::spawn(async move {
        let result = pump_video_frames(idx, generation).await;
        if result.is_err() {
            let _ = core::fmt::write(
                &mut narf_console::Writer,
                format_args!("  usb-uvc: capture pump stopped for device {idx}\n"),
            );
        }
        release_capture_pump(idx, generation);
    });
}

/// Continuously receive UVC payloads, reassemble frames, and enqueue them on
/// the corresponding V4L2-style devfs node. The task sleeps in xHCI's event
/// future between packets; it does not poll the controller in a spin loop.
async fn pump_video_frames(idx: usize, generation: u64) -> Result<(), UvcError> {
    let controller = controller_of(idx).ok_or(UvcError::CaptureFailed)?;
    pump_video_frames_with(idx, &*controller, generation).await
}

/// Lifecycle check for a capture pump running under `generation`:
/// true when the pump must exit without delivering anything further.
///
/// Two retirement causes, one check: the pump's generation has been
/// superseded by a newer activation (STREAMOFF → STREAMON while this
/// pump was parked in a transfer), or STREAMOFF requested a stop for
/// the pump's own, still-current generation. A stop request is
/// consumed only by the pump it targets — a stale pump leaves it
/// standing for the current generation's pump — and a stale pump
/// touches no lifecycle state at all.
fn take_pump_exit_request(idx: usize, generation: u64) -> bool {
    let mut devices = UVC_DEVICES.lock();
    let Some(device) = devices.get_mut(idx) else {
        return true;
    };
    if device.stream_generation != generation {
        return true;
    }
    if device.capture_stop_requested {
        device.capture_stop_requested = false;
        return true;
    }
    false
}

/// Transport-generic core of the capture pump, running under the
/// stream `generation` it was spawned for.
///
/// #808 seam: the receive call site in this loop — one transfer outstanding
/// at a time, dispatching on the active endpoint's transport
/// (`isoch_in` for isochronous streams, `bulk_in` for bulk
/// streams). Isochronous streams whose transport advertises
/// `isoch_pipeline_depth() > 1` leave this loop for the pipelined
/// receive ([`pump_video_frames_pipelined`], which adopts the
/// video crate's depth-4 `IsocScheduler`); bulk streams and
/// depth-1 transports (the real xHCI path, until #885) stay on
/// the single-shot receive below. Negotiation, activation, the
/// stop protocol, and frame delivery are unchanged by the split;
/// nothing here bakes in a single-shot assumption beyond that one
/// call.
///
/// Lifecycle: the loop exits cleanly with `Ok(())` when
/// [`take_pump_exit_request`] fires — checked at every loop top, and
/// again after a frame completes, before it is delivered. The second
/// check is load-bearing: the pump parks inside the receive call with no
/// timeout, so STREAMOFF (and a whole STREAMOFF → STREAMON toggle)
/// can run while a transfer is in flight; a frame that completes from
/// such a transfer belongs to a stream whose buffers were already
/// reset, and delivering it would plant a stale frame in the fresh
/// stream's queue.
pub async fn pump_video_frames_with<T: UvcTransport>(
    idx: usize,
    transport: &T,
    generation: u64,
) -> Result<(), UvcError> {
    let (slot_id, endpoint, video_node, reassembly, controller, hub_port) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(UvcError::NotVideo)?;
        (
            device.slot_id,
            device.active_stream.ok_or(UvcError::NoStreamingEndpoint)?,
            device.video_node,
            // Snapshot the negotiated stream parameters with the
            // endpoint: the reassembler completes stream-based
            // segments on buffer fullness at the negotiated
            // dwMaxVideoFrameSize and caps accumulation there (#1334).
            // A stream negotiated before this lane (or a fixture pump
            // with no negotiation on record) yields the legacy
            // config, so the pump behaves exactly as before.
            device.reassembly_config(),
            device.controller,
            device.hub_port,
        )
    };
    let packet_size = usize::try_from(endpoint.max_payload_size)
        .unwrap_or(4096)
        .clamp(1, 4096);
    // #808: isochronous streams run pipelined when the transport can
    // serve concurrent transfers; bulk streams and depth-1 transports
    // (the real xHCI path, until #885) stay on the single-shot loop
    // below.
    if endpoint.transport == UvcStreamingTransport::Isochronous
        && transport.isoch_pipeline_depth() > 1
    {
        return pump_video_frames_pipelined(
            idx,
            transport,
            generation,
            slot_id,
            endpoint,
            video_node,
            reassembly,
            controller,
            hub_port,
            packet_size,
        )
        .await;
    }
    let mut packet = alloc::vec![0u8; packet_size];
    let mut reassembler = UvcFrameReassembler::with_config(reassembly);
    let mut consecutive_errors = 0u8;

    loop {
        if take_pump_exit_request(idx, generation) {
            return Ok(());
        }
        // Bulk transfers carry the same UVC payload header framing
        // as isochronous packets, so both feed the same reassembler
        // below; only the receive call differs.
        let transfer = match endpoint.transport {
            UvcStreamingTransport::Isochronous => {
                transport.isoch_in(slot_id, endpoint.dci, &mut packet).await
            }
            UvcStreamingTransport::Bulk => {
                transport.bulk_in(slot_id, endpoint.dci, &mut packet).await
            }
        };
        match transfer {
            Ok(received) if received != 0 => {
                consecutive_errors = 0;
                // Hub idle-suspend accounting (#807): every completed
                // transfer resets the port's idle timer, so a
                // streaming camera never idles into a port suspend.
                // No-op for root-port cameras (`hub_port` is `None`)
                // and when the hub is gone.
                if let Some((hub_slot, port)) = hub_port {
                    crate::attach::mark_port_activity(controller, hub_slot, port);
                }
                if reassembler.push(&packet[..received]) == ReassemblerOutcome::FrameComplete {
                    let frame = reassembler.take_frame();
                    // The transfer that completed this frame may
                    // have straddled STREAMOFF (or a whole stream
                    // toggle): re-check before delivering, and drop
                    // the frame rather than deliver it into the
                    // successor stream's reset queues.
                    if take_pump_exit_request(idx, generation) {
                        return Ok(());
                    }
                    let device = narf_drivers_video::devfs_bridge::get_device(video_node)
                        .ok_or(UvcError::CaptureFailed)?;
                    device.lock().deliver_frame(frame);
                }
            }
            Ok(_) => narf_scheduler::yield_now().await,
            Err(_) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                if consecutive_errors >= 8 {
                    return Err(UvcError::CaptureFailed);
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
}

/// Pipelined isochronous receive for the capture pump (#808).
///
/// The single-shot loop awaits one `isoch_in` at a time, so a slow
/// service interval stalls the whole stream. This loop keeps up to
/// `IsocScheduler::depth` transfers in flight against a transport
/// that advertises `isoch_pipeline_depth() > 1`, polling them
/// round-robin with a no-op waker (the btrfs `noop_waker` idiom:
/// the futures here are IRQ/self-waking, and the loop re-polls
/// after every `yield_now`, so no wake is ever lost) and feeding
/// completed packets to the reassembler strictly in submission
/// order. Only the ring head is ever consumed, so a late packet
/// can never overtake an earlier one and frames complete in order.
///
/// Polling starts at the head each round, so the head slot always
/// gets first claim on the next completion — the modelled
/// transport serves concurrent calls from one FIFO queue, and
/// head-first polling is what makes its completions land in ring
/// order the way a controller's Transfer Events do. A non-head
/// completion is buffered until its turn, never fed early.
///
/// The scheduler is the depth counter: a slot launches only while
/// `should_submit()`, each launch calls `on_submit()`, each
/// completion calls `on_complete()`. Depth is capped at
/// `ISOC_DEPTH` (4, the video crate's scheduler depth) and at the
/// transport's advertised depth. Each slot owns its packet buffer
/// (`Vec` moved into the owned-buffer receive and returned with
/// the result), so no slot ever aliases another's buffer.
///
/// Lifecycle mirrors the single-shot loop: exit is checked after
/// each poll round — after a transfer completes, before its packet
/// is fed, and when no transfer completed, before yielding — so a
/// stale pump consumes its in-flight completion (never leaving it
/// queued for the successor stream) and still exits promptly with
/// no traffic. Errors count in consumption order;
/// eight consecutive errors end the pump with `CaptureFailed`,
/// same as the single-shot loop.
#[allow(clippy::too_many_arguments)] // pump context: identity + negotiated config + hub accounting.
async fn pump_video_frames_pipelined<T: UvcTransport>(
    idx: usize,
    transport: &T,
    generation: u64,
    slot_id: u8,
    endpoint: UvcStreamingEndpoint,
    video_node: usize,
    reassembly: ReassemblyConfig,
    controller: u8,
    hub_port: Option<(u8, u8)>,
    packet_size: usize,
) -> Result<(), UvcError> {
    use core::task::{Context, Poll};
    use narf_drivers_video::uvc::{IsocScheduler, ISOC_DEPTH};

    let depth = transport.isoch_pipeline_depth().clamp(1, ISOC_DEPTH);
    let mut scheduler = IsocScheduler::new();
    scheduler.depth = depth;

    // One owned packet buffer per ring slot, handed to the
    // owned-buffer receive on launch and returned with the result.
    let mut bufs: [Option<Vec<u8>>; ISOC_DEPTH] =
        core::array::from_fn(|_| Some(alloc::vec![0u8; packet_size]));
    /// One isochronous completion: the buffer back with its transfer result.
    type IsochResult = (Vec<u8>, Result<usize, crate::xhci::XhciError>);
    type IsochFut<'a> =
        core::pin::Pin<alloc::boxed::Box<dyn Future<Output = IsochResult> + Send + 'a>>;
    let mut in_flight: [Option<IsochFut<'_>>; ISOC_DEPTH] = [None, None, None, None];
    let mut completed: [Option<IsochResult>; ISOC_DEPTH] = [None, None, None, None];
    let mut head = 0usize;
    // Same negotiated completion/cap config as the single-shot
    // loop: a stream-based stream completes on buffer fullness at
    // the negotiated dwMaxVideoFrameSize (#1334), and a bounded
    // frame-based stream caps accumulation there. The legacy
    // default config never completes a stream-based segment that
    // signals neither FID nor EOF.
    let mut reassembler = UvcFrameReassembler::with_config(reassembly);
    let mut consecutive_errors = 0u8;

    loop {
        // Refill: launch into every free slot while the scheduler
        // has room. A free slot always holds its buffer: the buffer
        // returns to the slot with its completed result.
        for (i, slot) in in_flight.iter_mut().enumerate().take(depth) {
            if slot.is_none() && completed[i].is_none() && scheduler.should_submit() {
                if let Some(buf) = bufs[i].take() {
                    *slot = Some(Box::pin(transport.isoch_in_owned(
                        slot_id,
                        endpoint.dci,
                        buf,
                    )));
                    scheduler.on_submit();
                }
            }
        }
        // Poll every in-flight transfer once, head first. The poll
        // context lives only in this block: `core::task::Context`
        // is unconditionally `!Send` on this toolchain (it carries
        // a `LocalWaker` and a `&mut dyn Any` extension), so holding
        // it across the `yield_now().await` below would make the
        // whole pump future `!Send` and unspawnable via
        // `narf_scheduler::spawn`. The waker is a stateless no-op
        // and the loop re-polls after every yield, so rebuilding it
        // each round loses no wake.
        {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            for k in 0..depth {
                let i = (head + k) % depth;
                if let Some(fut) = in_flight[i].as_mut() {
                    if let Poll::Ready((buf, result)) = fut.as_mut().poll(&mut cx) {
                        completed[i] = Some((buf, result));
                        in_flight[i] = None;
                        scheduler.on_complete();
                    }
                }
            }
        }
        // Consume the ring head — and only the head — so packets
        // feed the reassembler in submission order.
        let Some((buf, result)) = completed[head].take() else {
            // No completion yet: the exit check lives here, after
            // the poll, rather than at the loop top. A stale pump
            // must consume its in-flight completions before
            // exiting — the single-shot loop consumes the transfer
            // it was parked in, and exiting here first would leave
            // a completed packet queued for the successor stream
            // (an errored wake packet would poison its first
            // frame). With no completion the check still exits
            // promptly, without waiting for traffic.
            if take_pump_exit_request(idx, generation) {
                return Ok(());
            }
            narf_scheduler::yield_now().await;
            continue;
        };
        // The transfer that completed this packet may have straddled
        // STREAMOFF: re-check before feeding, and drop the packet
        // rather than deliver a stale frame into the successor
        // stream. This check subsumes the single-shot loop's
        // pre-delivery check — delivery follows the feed with no
        // await between, so nothing can interleave a stop there.
        // Consuming the packet before exiting is what keeps it out
        // of the successor stream's queue.
        if take_pump_exit_request(idx, generation) {
            return Ok(());
        }
        match result {
            Ok(received) if received != 0 => {
                consecutive_errors = 0;
                // Hub idle-suspend accounting (#807), as in the
                // single-shot loop: every completed transfer resets
                // the port's idle timer, so a streaming camera never
                // idles into a port suspend.
                if let Some((hub_slot, port)) = hub_port {
                    crate::attach::mark_port_activity(controller, hub_slot, port);
                }
                // Clamp, don't trust: a transport reporting more
                // bytes than its buffer held must not panic the pump.
                let n = received.min(buf.len());
                if reassembler.push(&buf[..n]) == ReassemblerOutcome::FrameComplete {
                    let frame = reassembler.take_frame();
                    let device = narf_drivers_video::devfs_bridge::get_device(video_node)
                        .ok_or(UvcError::CaptureFailed)?;
                    device.lock().deliver_frame(frame);
                }
            }
            Ok(_) => {}
            Err(_) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                if consecutive_errors >= 8 {
                    return Err(UvcError::CaptureFailed);
                }
            }
        }
        bufs[head] = Some(buf);
        head = (head + 1) % depth;
    }
}

/// A waker that does nothing, for the single in-place polls in
/// [`pump_video_frames_pipelined`] (same idiom as btrfs'
/// `noop_waker`: the polled futures are IRQ/self-waking and the
/// loop re-polls after every `yield_now`, so the wake itself is
/// never load-bearing).
fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw()
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable never dereferences the (null) data pointer.
    unsafe { Waker::from_raw(raw()) }
}

/// Pull one video transfer from the bound UVC device: one iso-IN
/// packet on an isochronous stream, one bulk-IN transfer on a bulk
/// stream. Caller feeds it into a [`UvcFrameReassembler`] to
/// stitch payloads back into whole frames. Returns the byte count.
pub fn capture_one_packet(idx: usize, out: &mut [u8]) -> Result<usize, UvcError> {
    let (slot_id, endpoint) = {
        let g = UVC_DEVICES.lock();
        let dev = g.get(idx).ok_or(UvcError::NotVideo)?;
        let endpoint = dev.active_stream.ok_or(UvcError::NoStreamingEndpoint)?;
        (dev.slot_id, endpoint)
    };
    // Sync entry-point on the UVC capture path; bridge to the async
    // receive via block_on. Called from non-executor contexts.
    let c = match controller_of(idx) {
        Some(c) => c,
        None => return Err(UvcError::SetConfigFailed),
    };
    let outcome = narf_scheduler::block_on(async {
        match endpoint.transport {
            UvcStreamingTransport::Isochronous => c.isoch_in(slot_id, endpoint.dci, out).await,
            UvcStreamingTransport::Bulk => c.bulk_in(slot_id, endpoint.dci, out).await,
        }
    });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(UvcError::SetConfigFailed),
    }
}

pub fn attached_uvc_count() -> usize {
    UVC_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_uvc_for_test() {
    UVC_DEVICES.lock().clear();
    // A previous smoke that quiesced for suspend without resuming
    // must not wedge the next smoke's STREAMON.
    UVC_PM_SUSPENDED.store(false, Ordering::SeqCst);
}

/// Detach half of UVC bind for one slot: drop every `UVC_DEVICES`
/// entry bound to `slot_id` and unregister each entry's
/// `/dev/video<N>` node, so a replug re-binds from scratch and a
/// stale node can never STREAMON against a slot id the dispatcher
/// has since handed to another device.
///
/// Panic-free and idempotent by the #893 hook contract: no indexing
/// and no fallible unwraps on any path, and detaching a slot with no
/// UVC binding (or detaching twice) is a silent no-op. The capture
/// pump needs no explicit kill: the stop flag is set before removal,
/// and a pump that wakes after removal exits on its own — its
/// `take_pump_exit_request` sees the entry gone (or a different
/// device's generation at the reused index), its next
/// `get_device(video_node)` finds the unregistered node, and its
/// `isoch_in`/`bulk_in` on the disabled slot errors out. Registered as the
/// class-registry unbind hook, so the supervisor's hub-detach path
/// (`attach::detach_slot` → `dispatch_unbind`) reaches it; see also
/// [`detach_all_uvc`] for the controller-recovery path.
pub fn detach_uvc(controller: u8, slot_id: u8) {
    let ours = |device: &UvcDevice| device.controller == controller && device.slot_id == slot_id;
    let video_nodes: Vec<usize> = {
        let mut devices = UVC_DEVICES.lock();
        for device in devices.iter_mut() {
            if ours(device) {
                device.capture_stop_requested = true;
            }
        }
        // Collect-then-retain: the node unregister below takes the
        // video registry lock, which must never be taken while the
        // UVC registry lock is held.
        let nodes: Vec<usize> = devices
            .iter()
            .filter(|device| ours(device))
            .map(|device| device.video_node)
            .collect();
        devices.retain(|device| !ours(device));
        nodes
    };
    for node in video_nodes {
        let _ = narf_drivers_video::devfs_bridge::unregister_video(node);
    }
}

/// Wholesale variant of [`detach_uvc`] for controller recovery
/// (`attach::detach_all_bindings`): drop every UVC binding on
/// `controller` and unregister its video node, regardless of slot. Infallible and
/// idempotent, same pump-exit reasoning as [`detach_uvc`].
pub fn detach_all_uvc(controller: u8) {
    let video_nodes: Vec<usize> = {
        let mut devices = UVC_DEVICES.lock();
        for device in devices.iter_mut().filter(|d| d.controller == controller) {
            device.capture_stop_requested = true;
        }
        let nodes: Vec<usize> = devices
            .iter()
            .filter(|d| d.controller == controller)
            .map(|device| device.video_node)
            .collect();
        devices.retain(|d| d.controller != controller);
        nodes
    };
    for node in video_nodes {
        let _ = narf_drivers_video::devfs_bridge::unregister_video(node);
    }
}

// ── V4L2 streaming hooks (VIDIOC_STREAMON / STREAMOFF composition) ────
//
// Installed on the bound device's /dev/video<N> node at bind time (see
// `try_bind_video_already_addressed`). The V4L2 layer awaits `start`
// before marking the device streaming, so a negotiation failure fails
// the ioctl instead of silently black-streaming; it awaits `stop`
// before resetting local buffer state on STREAMOFF.

/// Linux errno values (asm-generic) returned through the stream hooks.
const ERRNO_EIO: i64 = 5;
const ERRNO_EBUSY: i64 = 16;
const ERRNO_ENODEV: i64 = 19;

fn uvc_errno(error: UvcError) -> i64 {
    match error {
        UvcError::NotVideo => ERRNO_ENODEV,
        UvcError::AlreadyStreaming => ERRNO_EBUSY,
        _ => ERRNO_EIO,
    }
}

/// The live controller of the UVC device at registry index `idx`.
fn controller_of(idx: usize) -> Option<alloc::sync::Arc<crate::xhci::Xhci>> {
    let controller = UVC_DEVICES.lock().get(idx)?.controller;
    crate::xhci::controller_by_id(controller)
}

/// Registry index of the bound device owning `/dev/video<node>`.
pub fn uvc_index_for_video_node(node: usize) -> Option<usize> {
    UVC_DEVICES
        .lock()
        .iter()
        .position(|device| device.video_node == node)
}

/// Build the desired VS PROBE payload for the S_FMT-committed format.
///
/// The V4L2 format is mapped back through the format table retained at
/// bind (the advertised `FmtEntry` table has no UVC indices). No
/// frame-rate surface reaches STREAMON — `VIDIOC_S_PARM` is
/// report-only in the V4L2 layer — so the frame's interval nearest
/// 30 fps is requested, with the hint bit set for `dwFrameInterval`.
/// On UVC 1.1+ devices the 1.1+ fields are filled from the device
/// record (VC-header clock; 1.0 payload-version declaration, retained
/// as a #1225 design choice — see `VsProbeCommit::preferred_version`
/// for the spec-correct encoding note); on 1.0 devices they stay zero
/// and are never sent. The reassembler decodes the shared §2.4.3.3
/// header for every format class, including frame-based
/// (temporally-encoded) streams, so the declaration no longer gates
/// which streams the driver can reassemble.
/// `pub(crate)` so the negotiation fixture drives the production
/// desired-construction path instead of hand-building a payload.
pub(crate) fn desired_probe_commit(
    device: &UvcDevice,
    format: narf_drivers_video::v4l2_ioctl::PixFormat,
) -> Option<VsProbeCommit> {
    use narf_drivers_video::uvc::PixelFmt;
    let pixel = if format.fourcc == u32::from_le_bytes(*b"YUYV") {
        PixelFmt::Yuyv
    } else if format.fourcc == u32::from_le_bytes(*b"NV12") {
        PixelFmt::Nv12
    } else if format.fourcc == u32::from_le_bytes(*b"MJPG") {
        PixelFmt::Mjpeg
    } else if format.fourcc == u32::from_le_bytes(*b"H264") {
        PixelFmt::FrameBased
    } else {
        return None;
    };
    let stream_format = device
        .formats
        .iter()
        .find(|candidate| candidate.pixel_fmt == pixel)?;
    let (frame_index, frame_interval) =
        stream_format.find_frame(format.width as u16, format.height as u16, 30)?;
    let v15 = device.uvc_version >= 0x0110;
    Some(VsProbeCommit {
        hint: 1,
        format_index: stream_format.format_index,
        frame_index,
        frame_interval,
        clock_frequency: if v15 { device.clock_frequency } else { 0 },
        framing_info: 0,
        preferred_version: if v15 { 0x10 } else { 0 },
        min_version: if v15 { 0x10 } else { 0 },
        max_version: if v15 { 0x10 } else { 0 },
        ..Default::default()
    })
}

/// Negotiation half of the STREAMON composition over an arbitrary
/// transport: resolve the device + desired stream parameters, then run
/// PROBE/COMMIT + activation. The production hook additionally spawns
/// the capture pump on success; fixtures drive
/// [`pump_video_frames_with`] themselves instead.
pub async fn stream_start_with<T: UvcTransport>(
    transport: &T,
    node: usize,
    format: narf_drivers_video::v4l2_ioctl::PixFormat,
) -> Result<(), i64> {
    // Quiesced for system suspend (#807): the PM prepare hook latched
    // this before the controller fan-out, and the resume replay clears
    // it when the camera is streaming again. A STREAMON racing the
    // transition fails busy instead of negotiating against a device
    // whose power is about to be cut; the caller retries after resume.
    if pm_quiesced() {
        return Err(ERRNO_EBUSY);
    }
    let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
    let desired = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(ERRNO_ENODEV)?;
        desired_probe_commit(device, format).ok_or(ERRNO_EIO)?
    };
    negotiate_and_activate_video_stream_with(transport, idx, desired)
        .await
        .map_err(uvc_errno)?;
    Ok(())
}

/// Teardown half of the STREAMON composition over an arbitrary
/// transport (STREAMOFF): stop the pump + release the alternate
/// setting via [`deactivate_video_stream_with`].
pub async fn stream_stop_with<T: UvcTransport>(transport: &T, node: usize) -> Result<(), i64> {
    let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
    deactivate_video_stream_with(transport, idx)
        .await
        .map_err(uvc_errno)
}

fn video_stream_start(
    node: usize,
    format: narf_drivers_video::v4l2_ioctl::PixFormat,
) -> narf_drivers_video::v4l2_ioctl::StreamHookFuture {
    Box::pin(async move {
        let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
        let controller = controller_of(idx).ok_or(ERRNO_ENODEV)?;
        // A port the hub idle-suspend pass gated while the camera was
        // idle must come back before the negotiation transfers (#807).
        ensure_uvc_port_awake(&controller, idx).await;
        stream_start_with(&*controller, node, format).await?;
        if let Some(idx) = uvc_index_for_video_node(node) {
            start_video_capture_pump(idx);
        }
        Ok(())
    })
}

fn video_stream_stop(node: usize) -> narf_drivers_video::v4l2_ioctl::StreamHookFuture {
    Box::pin(async move {
        match uvc_index_for_video_node(node).and_then(controller_of) {
            Some(controller) => stream_stop_with(&*controller, node).await,
            None => {
                // Controller is gone, so the device is too: only the
                // software teardown remains.
                if let Some(idx) = uvc_index_for_video_node(node) {
                    let mut devices = UVC_DEVICES.lock();
                    if let Some(device) = devices.get_mut(idx) {
                        device.capture_stop_requested = true;
                        device.active_stream = None;
                        device.negotiated = None;
                    }
                }
                Ok(())
            }
        }
    })
}

/// The [`narf_drivers_video::v4l2_ioctl::StreamOps`] installed on every
/// UVC-bound `/dev/video<N>` node.
pub fn video_stream_ops() -> narf_drivers_video::v4l2_ioctl::StreamOps {
    narf_drivers_video::v4l2_ioctl::StreamOps {
        start: video_stream_start,
        stop: video_stream_stop,
    }
}

// ── V4L2 control hooks (VIDIOC_G/S_CTRL composition, #809) ────────────
//
// Installed on the bound device's /dev/video<N> node at bind time
// (see `try_bind_video_already_addressed`). The V4L2 layer awaits
// `get`/`set` before reporting a value, so a failed transfer fails
// the ioctl instead of echoing a cached value the hardware never
// took.

fn video_control_get(node: usize, id: u32) -> narf_drivers_video::v4l2_ioctl::ControlHookFuture {
    Box::pin(async move {
        let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
        let controller = controller_of(idx).ok_or(ERRNO_ENODEV)?;
        control_get_with(&*controller, node, id).await
    })
}

fn video_control_set(
    node: usize,
    id: u32,
    value: i32,
) -> narf_drivers_video::v4l2_ioctl::ControlHookFuture {
    Box::pin(async move {
        let idx = uvc_index_for_video_node(node).ok_or(ERRNO_ENODEV)?;
        let controller = controller_of(idx).ok_or(ERRNO_ENODEV)?;
        control_set_with(&*controller, node, id, value).await
    })
}

/// The [`narf_drivers_video::v4l2_ioctl::ControlOps`] installed on every
/// UVC-bound `/dev/video<N>` node.
pub fn video_control_ops() -> narf_drivers_video::v4l2_ioctl::ControlOps {
    narf_drivers_video::v4l2_ioctl::ControlOps {
        get: video_control_get,
        set: video_control_set,
    }
}

// ── Suspend / resume (#807) ──────────────────────────────────────────
//
// Two registrations, mirroring the USB classes that already suspend:
//
// - The async system-PM hook (`narf_power::system_pm`, #763 pattern):
//   prepare runs while the scheduler and device interrupts still
//   service futures, so it can do the real quiesce — stop the pump +
//   select alternate setting 0, the STREAMOFF teardown — and record
//   the stream for the resume replay. Resume runs only after the
//   synchronous device fan-out restored xHCI, and re-negotiates +
//   re-activates each quiesced camera from its recorded parameters.
// - The synchronous device-PM hook (`narf_power::device_pm`, #820
//   pattern): a flag-only backstop for the interrupt-gated fan-out.
//   It latches the quiesce flag and stop-requests every streaming
//   pump — it can do no I/O, so alternate-setting selection stays
//   the async prepare's job.
//
// Hub idle-suspend participation rides on the same hub context:
// the pump feeds [`crate::attach::mark_port_activity`] on every
// completed transfer (a streaming camera never idles), the class
// suspend hook vetoes gating a live stream, and STREAMON resumes a
// gated port before negotiating.

/// Pump quiesce latch: set by the PM prepare hook (and by the
/// synchronous device-PM backstop), cleared when the resume replay
/// settles. While set, STREAMON refuses busy and no pump delivers.
static UVC_PM_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// True while the class is quiesced for system suspend.
pub fn pm_quiesced() -> bool {
    UVC_PM_SUSPENDED.load(Ordering::SeqCst)
}

fn pm_prepare() {
    UVC_PM_SUSPENDED.store(true, Ordering::SeqCst);
}

fn pm_finish_resume() {
    UVC_PM_SUSPENDED.store(false, Ordering::SeqCst);
}

/// TX-demand resume for UVC (#807): if the camera's hub port is
/// gated, resume it before the transfer that would otherwise NAK on
/// it (Linux `usb_autopm_get_interface` shape; the btusb
/// `ensure_port_awake` precedent). No-op for root-port cameras
/// (`hub_port` is `None`) and when the port is already awake.
async fn ensure_uvc_port_awake(xhci_dev: &crate::xhci::Xhci, idx: usize) {
    let Some((hub_slot, port)) = UVC_DEVICES.lock().get(idx).and_then(|d| d.hub_port) else {
        return;
    };
    if !crate::attach::hub_port_is_suspended(xhci_dev.id(), hub_slot, port) {
        return;
    }
    crate::attach::resume_port(xhci_dev, hub_slot, port).await;
    if !crate::attach::hub_port_is_suspended(xhci_dev.id(), hub_slot, port) {
        crate::attach::mark_port_activity(xhci_dev.id(), hub_slot, port);
    }
}

/// Register the UVC class suspend hook (#807). Called from the USB
/// crate's Stage::Subsys initcalls; registration tolerates
/// duplicates (see [`crate::class_registry::register_suspend_hook`]).
pub fn register() {
    let _ = crate::class_registry::register_suspend_hook("uvcvideo", |slot, port| {
        alloc::boxed::Box::pin(suspend_uvc_port(slot, port))
    });
}

/// Class suspend hook for one hub port (see
/// [`crate::class_registry::dispatch_suspend`]). Runs inside the
/// supervisor's idle-suspend pass, before the pass gates the port.
///
/// A streaming camera vetoes gating (`ParkFailed`): the pump's
/// activity marks keep a streaming camera from ever going
/// idle-expired, so a veto only fires for a stalled stream — and
/// gating mid-stream would break the pump's in-flight transfer with
/// no resume path (it exits after 8 consecutive errors, leaving the
/// V4L2 node streaming into a dead pump). An idle bound camera parks
/// (`Parked`: nothing to do; the next STREAMON resumes the port
/// first). Idempotent and panic-free.
pub(crate) async fn suspend_uvc_port(
    hub_slot: u8,
    port: u8,
) -> crate::class_registry::SuspendOutcome {
    use crate::class_registry::SuspendOutcome;
    let devices = UVC_DEVICES.lock();
    let Some(device) = devices
        .iter()
        .find(|d| d.hub_port == Some((hub_slot, port)))
    else {
        return SuspendOutcome::NotMine;
    };
    if device.active_stream.is_some() {
        SuspendOutcome::ParkFailed
    } else {
        SuspendOutcome::Parked
    }
}

/// Quiesce every streaming UVC camera on `controller` for system
/// suspend (#807): latch the class quiesce flag, then for each live
/// stream record the device-accepted parameters for the resume
/// replay and run the STREAMOFF teardown (stop pump + select
/// alternate setting 0) over `transport`.
///
/// Best-effort per device: a failed alt-0 selection still leaves the
/// software state quiesced (pump stopping, `active_stream` cleared),
/// and STREAMON can restart the camera afterwards — so a single sick
/// camera never aborts the whole system suspend (a failing prepare
/// makes the coordinator unwind every earlier hook). A streaming
/// device whose negotiation record is missing (`last_stream` is
/// `None` — activated without negotiation) is still quiesced, but
/// has nothing for resume to replay.
pub async fn prepare_suspend_with<T: UvcTransport>(transport: &T, controller: u8) {
    pm_prepare();
    let streaming: Vec<(usize, Option<VsProbeCommit>)> = {
        let devices = UVC_DEVICES.lock();
        devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.controller == controller && d.active_stream.is_some())
            .map(|(idx, d)| (idx, d.last_stream))
            .collect()
    };
    for (idx, last) in streaming {
        {
            let mut devices = UVC_DEVICES.lock();
            if let Some(device) = devices.get_mut(idx) {
                device.suspended_stream = last;
            }
        }
        let _ = deactivate_video_stream_with(transport, idx).await;
    }
}

/// Re-negotiate + re-activate every camera
/// [`prepare_suspend_with`] quiesced on `controller` (#807):
/// PROBE/COMMIT with the device-accepted parameters the prepare
/// recorded, then activation (alternate setting + endpoint
/// configuration). Returns the registry indices re-activated — the
/// caller spawns each one's capture pump — and `DriverError` when
/// any replay failed (best-effort: one sick camera never blocks the
/// rest). A device whose stream restarted already (a STREAMON raced
/// the resume through the window between the synchronous resume
/// clearing the latch and this replay reaching the device) is
/// skipped, not re-negotiated. Clears the class quiesce latch when
/// the replay settles, even on failure, so STREAMON is usable again.
pub async fn resume_replay_with<T: UvcTransport>(
    transport: &T,
    controller: u8,
) -> (
    Vec<usize>,
    Result<(), narf_power::device_pm::DeviceSuspendError>,
) {
    let pending: Vec<(usize, VsProbeCommit)> = {
        let mut devices = UVC_DEVICES.lock();
        let mut out = Vec::new();
        for (idx, device) in devices.iter_mut().enumerate() {
            if device.controller != controller {
                continue;
            }
            if let Some(desired) = device.suspended_stream.take() {
                out.push((idx, desired));
            }
        }
        out
    };
    let mut reactivated = Vec::new();
    let mut failed = false;
    for (idx, desired) in pending {
        if UVC_DEVICES
            .lock()
            .get(idx)
            .is_some_and(|d| d.active_stream.is_some())
        {
            continue;
        }
        match negotiate_and_activate_video_stream_with(transport, idx, desired).await {
            Ok(_) => reactivated.push(idx),
            Err(_) => failed = true,
        }
    }
    pm_finish_resume();
    let result = if failed {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    } else {
        Ok(())
    };
    (reactivated, result)
}

/// Flag-only system-suspend backstop for UVC (#807).
///
/// Runs on the boot CPU with interrupts gated (the synchronous
/// device-PM fan-out), so it must not schedule, sleep, or do I/O:
/// it latches the quiesce flag and stop-requests every streaming
/// pump so no frame is delivered across suspend. Alternate-setting-0
/// selection stays the async prepare hook's job — this hook never
/// selects alt 0, because it cannot issue a control transfer.
///
/// A suspend that bypassed the async prepare (no caller in-tree
/// does; the coordinator always prepares first) leaves the stream
/// record standing with a dead pump: STREAMON then fails busy until
/// STREAMOFF tears the record down. That degraded path is accepted
/// rather than wedging the machine: the backstop's job is only to
/// stop delivery, never to own the hardware state.
pub(crate) struct UvcPm;

impl narf_power::device_pm::DevicePmOps for UvcPm {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        pm_prepare();
        let mut devices = UVC_DEVICES.lock();
        for device in devices.iter_mut() {
            if device.active_stream.is_some() {
                device.capture_stop_requested = true;
            }
        }
        Ok(())
    }

    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        pm_finish_resume();
        Ok(())
    }
}

struct UvcSystemPm;

impl narf_power::system_pm::AsyncSystemPm for UvcSystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async {
            for xhci in crate::xhci::controllers() {
                prepare_suspend_with(xhci.as_ref(), xhci.id()).await;
            }
            Ok(())
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async {
            // Every controller replays its own bindings; a binding whose
            // controller is gone cannot be replayed.
            let mut result = Ok(());
            let controllers = crate::xhci::controllers();
            for xhci in &controllers {
                // The port may have idled into a gate while the machine
                // slept; wake each pending camera's port before its
                // replay transfers.
                let pending: Vec<usize> = {
                    let devices = UVC_DEVICES.lock();
                    devices
                        .iter()
                        .enumerate()
                        .filter(|(_, d)| d.controller == xhci.id() && d.suspended_stream.is_some())
                        .map(|(idx, _)| idx)
                        .collect()
                };
                for idx in pending {
                    ensure_uvc_port_awake(xhci.as_ref(), idx).await;
                }
                let (reactivated, replay) = resume_replay_with(xhci.as_ref(), xhci.id()).await;
                if replay.is_err() {
                    result = Err(narf_power::device_pm::DeviceSuspendError::DriverError);
                }
                for idx in reactivated {
                    start_video_capture_pump(idx);
                }
            }
            let orphaned = UVC_DEVICES.lock().iter().any(|d| {
                d.suspended_stream.is_some() && !controllers.iter().any(|c| c.id() == d.controller)
            });
            if orphaned {
                result = Err(narf_power::device_pm::DeviceSuspendError::DriverError);
            }
            pm_finish_resume();
            result
        })
    }
}

/// Register the UVC power-management hooks (#807): the async
/// system-PM hook (prepare quiesces, resume re-negotiates) and the
/// synchronous device-PM backstop. Called once from the USB crate's
/// Stage::Subsys initcalls; both registrations are idempotent on
/// the hook name.
pub fn register_pm() {
    narf_power::system_pm::register_async_system_pm("uvcvideo", alloc::sync::Arc::new(UvcSystemPm));
    narf_power::device_pm::register_device_pm_ops("uvcvideo", alloc::sync::Arc::new(UvcPm));
}

// ── UVC payload header (§2.4.3.3) ──────────────────────────────────
//
// Every iso packet (and every bulk transfer in bulk-streaming mode)
// starts with a UVC payload header. The first byte is the header
// length; the second is a bit-field of frame flags. Then optionally
// 4 bytes of Presentation Time Stamp (PTS) and 6 bytes of Source
// Clock Reference (SCR) if their flag bits are set.

/// BFH (Bit Field Header) flag bits at offset 1.
pub mod bfh {
    /// `FID` — Frame ID. Toggles between adjacent frames so the host
    /// detects frame boundaries even when EOF/SOF events are missed.
    pub const FID: u8 = 1 << 0;
    /// `EOF` — End Of Frame on this payload.
    pub const EOF: u8 = 1 << 1;
    /// `PTS` — bytes 2..6 carry a 32-bit Presentation Time Stamp.
    pub const PTS: u8 = 1 << 2;
    /// `SCR` — 6-byte Source Clock Reference present.
    pub const SCR: u8 = 1 << 3;
    /// `PAYLOAD_SPECIFIC` — payload-specific bit (UVC 1.5 §2.4.3.3
    /// Table 2-5, D4). Its meaning is assigned by the individual
    /// payload specification, not by the core spec; for
    /// temporally-encoded (frame-based) formats the header carries
    /// the EOS slice marker here. It is NOT reserved: a device may
    /// legitimately set it, and the reassembler must not treat it
    /// as an error or a framing signal.
    pub const PAYLOAD_SPECIFIC: u8 = 1 << 4;
    /// `STI` — Still Image marker.
    pub const STI: u8 = 1 << 5;
    /// `ERR` — payload contains an error (driver should drop the
    /// current frame).
    pub const ERR: u8 = 1 << 6;
    /// `EOH` — End Of Header (must be set on every payload).
    pub const EOH: u8 = 1 << 7;
}

/// Decoded UVC payload header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UvcPayloadHeader {
    /// Total header length in bytes (typically 2 or 12).
    pub length: u8,
    /// Raw BFH byte — caller masks against [`bfh`] constants.
    pub bfh: u8,
    /// Presentation Time Stamp if BFH.PTS set; None otherwise.
    pub pts: Option<u32>,
    /// Source Clock Reference if BFH.SCR set. Two values: bus-clock
    /// at sampling (32 bits) + SOF token at sampling (16 bits).
    pub scr: Option<(u32, u16)>,
}

impl UvcPayloadHeader {
    /// Decode the header from a payload's prefix. Returns Err if
    /// the buffer is too short or the header length is invalid.
    pub fn parse(buf: &[u8]) -> Result<Self, UvcError> {
        if buf.len() < 2 {
            return Err(UvcError::Short);
        }
        let length = buf[0];
        if length < 2 || length as usize > buf.len() {
            return Err(UvcError::Truncated);
        }
        let bfh = buf[1];
        let mut off = 2usize;
        let pts = if bfh & bfh::PTS != 0 {
            if length as usize - off < 4 {
                return Err(UvcError::Truncated);
            }
            let v = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            off += 4;
            Some(v)
        } else {
            None
        };
        let scr = if bfh & bfh::SCR != 0 {
            if length as usize - off < 6 {
                return Err(UvcError::Truncated);
            }
            let bus = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let sof = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
            Some((bus, sof))
        } else {
            None
        };
        Ok(Self {
            length,
            bfh,
            pts,
            scr,
        })
    }
    /// True iff the End-Of-Frame marker is set.
    pub fn is_eof(&self) -> bool {
        self.bfh & bfh::EOF != 0
    }
    /// True iff the payload reports an error and the driver should
    /// drop the in-flight frame.
    pub fn is_error(&self) -> bool {
        self.bfh & bfh::ERR != 0
    }
    /// D4 payload-specific bit (UVC 1.5 §2.4.3.3 Table 2-5).
    /// Surfaced, not acted on: frame completion is driven by
    /// FID/EOF, and the bit's meaning belongs to the payload spec.
    pub fn is_payload_specific(&self) -> bool {
        self.bfh & bfh::PAYLOAD_SPECIFIC != 0
    }
    /// STI bit read as the temporally-encoded meaning: for
    /// frame-based (H.264/VP8) streams D5 marks an intra-coded frame
    /// (UVC 1.5 §2.4.3.3 Table 2-5, D5).
    pub fn is_intra_coded(&self) -> bool {
        self.bfh & bfh::STI != 0
    }
    /// FID bit — toggles between frames.
    pub fn fid(&self) -> bool {
        self.bfh & bfh::FID != 0
    }
}

// ── VS Probe/Commit Control (§4.3.1.1) ─────────────────────────────
//
// Before opening the iso stream, the host issues SET_CUR(PROBE)
// with its desired (FormatIndex, FrameIndex, FrameInterval), reads
// back GET_CUR(PROBE) to learn what the device accepted, then
// SET_CUR(COMMIT) to lock in. UVC 1.0/1.1 use a 26-byte payload;
// UVC 1.5 extends to 34 bytes.

/// UVC class-specific request codes (§A.8).
pub const VS_REQ_SET_CUR: u8 = 0x01;
pub const VS_REQ_GET_CUR: u8 = 0x81;
pub const VS_REQ_GET_MIN: u8 = 0x82;
pub const VS_REQ_GET_MAX: u8 = 0x83;
pub const VS_REQ_GET_DEF: u8 = 0x87;

/// wValue for the Probe control. High byte = control selector;
/// low byte = 0.
pub const VS_PROBE_CONTROL: u16 = 0x0100;
pub const VS_COMMIT_CONTROL: u16 = 0x0200;

/// VS Probe/Commit Control payload: 26 bytes for UVC 1.0, 34 bytes for
/// UVC 1.1+.
///
/// Wire layout (little-endian) per UVC 1.5 §4.3.1.1 table 4-47 and
/// Linux `struct uvc_streaming_control`
/// (`include/uapi/linux/usb/video.h`): bytes 0..26 are the 1.0 block;
/// bytes 26..34 are the extension block. The extension block arrived
/// with UVC 1.1, not 1.5 — the original Linux driver sizes the transfer
/// `uvc_version >= 0x0110 ? 34 : 26` (`uvc_video.c`, 2008), and UVC 1.5
/// devices are covered by the same rule. (An earlier in-tree codec
/// comment claimed a 0x0150 gate; that claim was single-sourced and
/// unverifiable, and the 0x0110 gate covers the 1.5 case identically.)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct VsProbeCommit {
    /// Bit-field — bit 0 = hint dwFrameInterval, etc. Caller usually
    /// sets this to 1 to advertise "frame_interval is the one we want".
    pub hint: u16,
    /// `bFormatIndex` — 1-based index into the format descriptors.
    pub format_index: u8,
    /// `bFrameIndex` — 1-based index into the frame descriptors of
    /// the chosen format.
    pub frame_index: u8,
    /// Desired interval in 100 ns units. 333_333 = 30 fps.
    pub frame_interval: u32,
    pub key_frame_rate: u16,
    pub p_frame_rate: u16,
    pub comp_quality: u16,
    pub comp_window_size: u16,
    pub delay: u16,
    pub max_video_frame_size: u32,
    pub max_payload_transfer_size: u32,
    // ── UVC 1.1+ extension fields (bytes 26..34) ────────────────────
    /// Device clock frequency in Hz, from the VC HEADER descriptor.
    /// The host offers the device's own clock on PROBE; the device's
    /// GET_CUR value is what gets committed.
    pub clock_frequency: u32,
    /// Framing-information bitmap. The host declares no framing
    /// requirement (0); the device's GET_CUR value is committed.
    pub framing_info: u8,
    /// Preferred payload-format version. This driver declares 1.0
    /// (0x10) for preferred, min, and max — a #1225 design choice
    /// that is NOT re-litigated here, so the declared values are
    /// unchanged by this lane. Note the spec-correct encoding for
    /// future work: UVC 1.5 §4.3.1.1 Table 4-47 defines these fields
    /// as the PAYLOAD-FORMAT-spec minor version (1–255), not a BCD
    /// UVC version, and requires the host to initialise them to zero
    /// on the first Probe SET, after which the device returns its
    /// preferred version plus its supported [min, max] range and the
    /// host may only pick a preferred value inside that range (the
    /// host must not alter min/max). What this lane enforces is the
    /// GET_CUR side of that rule: see
    /// [`accepted_versions_valid`](Self::accepted_versions_valid).
    pub preferred_version: u8,
    pub min_version: u8,
    pub max_version: u8,
}

impl VsProbeCommit {
    pub const LEN_V10: usize = 26;
    pub const LEN_V15: usize = 34;

    /// Wire length for a device advertising `bcd_uvc`: 34 bytes for
    /// UVC 1.1+, 26 bytes otherwise.
    pub fn len_for(bcd_uvc: u16) -> usize {
        if bcd_uvc >= 0x0110 {
            Self::LEN_V15
        } else {
            Self::LEN_V10
        }
    }

    /// Serialise the 26-byte (UVC 1.0) form for SET_CUR(PROBE/COMMIT).
    pub fn encode_v10(&self) -> [u8; Self::LEN_V10] {
        let mut b = [0u8; Self::LEN_V10];
        b[0..2].copy_from_slice(&self.hint.to_le_bytes());
        b[2] = self.format_index;
        b[3] = self.frame_index;
        b[4..8].copy_from_slice(&self.frame_interval.to_le_bytes());
        b[8..10].copy_from_slice(&self.key_frame_rate.to_le_bytes());
        b[10..12].copy_from_slice(&self.p_frame_rate.to_le_bytes());
        b[12..14].copy_from_slice(&self.comp_quality.to_le_bytes());
        b[14..16].copy_from_slice(&self.comp_window_size.to_le_bytes());
        b[16..18].copy_from_slice(&self.delay.to_le_bytes());
        b[18..22].copy_from_slice(&self.max_video_frame_size.to_le_bytes());
        b[22..26].copy_from_slice(&self.max_payload_transfer_size.to_le_bytes());
        b
    }

    /// Serialise the 34-byte (UVC 1.1+) form: the 26-byte block plus
    /// the extension fields.
    pub fn encode_v15(&self) -> [u8; Self::LEN_V15] {
        let mut b = [0u8; Self::LEN_V15];
        b[..26].copy_from_slice(&self.encode_v10());
        b[26..30].copy_from_slice(&self.clock_frequency.to_le_bytes());
        b[30] = self.framing_info;
        b[31] = self.preferred_version;
        b[32] = self.min_version;
        b[33] = self.max_version;
        b
    }

    /// Serialise at the length a device advertising `bcd_uvc` expects.
    /// There is deliberately no bare `encode()`: a length-blind encode
    /// silently truncates the 1.1+ fields (the defect this lane fixes).
    pub fn encode_for(&self, bcd_uvc: u16) -> Vec<u8> {
        if bcd_uvc >= 0x0110 {
            self.encode_v15().to_vec()
        } else {
            self.encode_v10().to_vec()
        }
    }

    /// Parse a GET_CUR/MIN/MAX/DEF response of either length. A 26-byte
    /// response zeroes the extension fields — a 1.0 device's reply must
    /// never carry stale 1.1+ values into COMMIT.
    pub fn decode(buf: &[u8]) -> Result<Self, UvcError> {
        if buf.len() < Self::LEN_V10 {
            return Err(UvcError::Short);
        }
        let mut s = Self {
            hint: u16::from_le_bytes([buf[0], buf[1]]),
            format_index: buf[2],
            frame_index: buf[3],
            frame_interval: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            key_frame_rate: u16::from_le_bytes([buf[8], buf[9]]),
            p_frame_rate: u16::from_le_bytes([buf[10], buf[11]]),
            comp_quality: u16::from_le_bytes([buf[12], buf[13]]),
            comp_window_size: u16::from_le_bytes([buf[14], buf[15]]),
            delay: u16::from_le_bytes([buf[16], buf[17]]),
            max_video_frame_size: u32::from_le_bytes(buf[18..22].try_into().unwrap()),
            max_payload_transfer_size: u32::from_le_bytes(buf[22..26].try_into().unwrap()),
            ..Self::default()
        };
        if buf.len() >= Self::LEN_V15 {
            s.clock_frequency = u32::from_le_bytes(buf[26..30].try_into().unwrap());
            s.framing_info = buf[30];
            s.preferred_version = buf[31];
            s.min_version = buf[32];
            s.max_version = buf[33];
        }
        Ok(s)
    }

    /// Validate a device's GET_CUR(PROBE) version triple (UVC 1.5
    /// §4.3.1.1 Table 4-47): the device must reset min/max to the
    /// 1–255 range it supports, and its preferred version must lie
    /// inside its own declared [min, max] range. A triple violating
    /// that — preferred outside [min, max], min zero, or min > max —
    /// is malformed: committing it would lock in a payload version
    /// the device never offered, so negotiation must fail instead
    /// of committing verbatim.
    ///
    /// Applies only to 34-byte (1.1+) responses, which are the only
    /// ones carrying version fields; callers must not apply it to a
    /// 26-byte decode (whose version fields are zero by
    /// construction, not by device answer).
    pub fn accepted_versions_valid(&self) -> bool {
        self.min_version >= 1
            && self.min_version <= self.preferred_version
            && self.preferred_version <= self.max_version
    }
}

/// `bmFramingInfo` D0 (UVC 1.5 §4.3.1.1 Table 4-47): the FID field is
/// required in the payload header; the sender must toggle FID at
/// least every `dwMaxVideoFrameSize` bytes.
pub const FRAMING_FID: u8 = 0x01;
/// `bmFramingInfo` D1: the EOF field may be present in the payload
/// header. It is a device error to specify D1 without D0; the
/// reassembler tolerates it (EOF is still honoured) rather than
/// failing the stream.
pub const FRAMING_EOF: u8 = 0x02;

/// How a reassembler completes frames and bounds its buffer.
///
/// Mirror of `narf_drivers_video::uvc::payload::ReassemblyConfig`:
/// the default is the legacy frame-based machine (FID/EOF completion,
/// no bound). A stream-based stream configures the negotiated
/// `dwMaxVideoFrameSize` bound plus `bmFramingInfo`, so segments
/// complete on buffer fullness (UVC 1.5 §2.4.3.7) when the device
/// sends no usable FID/EOF. A frame-based stream may also configure
/// a bound: the FID/EOF machine is unchanged and the bound acts as a
/// safety net (length completion + cap) if EOF is lost.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReassemblyConfig {
    /// Negotiated `dwMaxVideoFrameSize` in bytes: the maximum frame
    /// (frame-based) or codec-specific segment (stream-based) size.
    /// 0 = unbounded (legacy behaviour: no length completion, no cap).
    pub max_frame_size: u32,
    /// True for `VS_FORMAT_STREAM_BASED` streams.
    pub stream_based: bool,
    /// Negotiated `bmFramingInfo` (D0 = FID required, D1 = EOF may be
    /// present). Consulted only when `stream_based` is true — for
    /// known frame-based formats the field is ignored (§4.3.1.1).
    pub framing_info: u8,
}

impl ReassemblyConfig {
    /// Stream-based configuration: complete on buffer fullness at
    /// `max_frame_size`, honour FID/EOF only per `framing_info`.
    pub fn stream_based(max_frame_size: u32, framing_info: u8) -> Self {
        Self {
            max_frame_size,
            stream_based: true,
            framing_info,
        }
    }

    /// Frame-based configuration with a bound: the FID/EOF machine
    /// plus length completion and the cap at `max_frame_size`.
    pub fn bounded(max_frame_size: u32) -> Self {
        Self {
            max_frame_size,
            stream_based: false,
            framing_info: 0,
        }
    }
}

// ── Frame reassembler ──────────────────────────────────────────────
//
// Drives a sequence of iso payloads through the FID/EOF state
// machine to reassemble whole frames. The xHCI iso ring delivers
// one payload per packet; this reassembler accumulates them into
// a single buffer and yields a complete frame on EOF.
//
// Frame-based formats (uncompressed, MJPEG, DV) and
// temporally-encoded formats (H.264, VP8 — `VS_FORMAT_FRAME_BASED`)
// share this machine: the §2.4.3.3 header is identical and frame
// boundaries come from the FID toggle with EOF completion
// (§2.4.3.7). The payload-specific D4 bit and the STI/intra-coded
// bit are decoded on the header but do not drive completion.
//
// Stream-based formats (`VS_FORMAT_STREAM_BASED`) use the same
// machine with a [`ReassemblyConfig`]: FID/EOF are honoured only
// when the negotiated `bmFramingInfo` says they are meaningful, and
// a segment completes when the accumulated payload reaches the
// negotiated `dwMaxVideoFrameSize` (buffer-fullness completion,
// §2.4.3.7) — so a stream that signals neither bit still completes
// frames instead of growing the buffer without bound. The bound
// also caps accumulation in every mode (see [`push`](UvcFrameReassembler::push)).

#[derive(Debug)]
pub struct UvcFrameReassembler {
    /// In-flight frame buffer.
    pub buffer: Vec<u8>,
    /// Current frame's FID bit. New frames flip this.
    pub current_fid: bool,
    /// True if any payload in the current frame had BFH.ERR set —
    /// drop on EOF.
    pub frame_errored: bool,
    /// Sequence number incremented on each completed frame.
    pub frames_completed: u64,
    /// Total frames dropped due to error since creation.
    pub frames_dropped: u64,
    /// Completion / cap configuration (default: legacy FID/EOF
    /// machine, unbounded).
    pub config: ReassemblyConfig,
    /// Payload bytes dropped because a push would have grown the
    /// buffer past `config.max_frame_size` (0 when unbounded).
    pub bytes_dropped_overflow: u64,
}

impl UvcFrameReassembler {
    pub fn new() -> Self {
        Self::with_config(ReassemblyConfig::default())
    }

    /// Build a reassembler with an explicit completion/cap config.
    pub fn with_config(config: ReassemblyConfig) -> Self {
        Self {
            buffer: Vec::new(),
            current_fid: false,
            frame_errored: false,
            frames_completed: 0,
            frames_dropped: 0,
            config,
            bytes_dropped_overflow: 0,
        }
    }

    /// What the reassembler did with the just-pushed packet.
    ///
    /// Completion, in order: a meaningful EOF; the accumulation
    /// reaching `config.max_frame_size` (buffer-fullness completion,
    /// the stream-based rule when the device signals no boundary);
    /// a meaningful FID flip, which drops any partial frame and
    /// starts a new one. When a bound is configured the append is
    /// clamped to the remaining room: the buffer never exceeds
    /// `max_frame_size`, the frame completes at the bound, and the
    /// excess bytes of that packet are dropped (counted in
    /// `bytes_dropped_overflow`).
    pub fn push(&mut self, packet: &[u8]) -> ReassemblerOutcome {
        let hdr = match UvcPayloadHeader::parse(packet) {
            Ok(h) => h,
            Err(_) => return ReassemblerOutcome::Skipped,
        };
        let payload = &packet[hdr.length as usize..];
        // In stream-based mode FID/EOF are meaningful only when the
        // negotiated bmFramingInfo says so (Stream Based Payload 1.5
        // §2.1; core §4.3.1.1). For known frame-based formats the
        // field is ignored, so both bits are always meaningful there.
        let fid_meaningful =
            !self.config.stream_based || self.config.framing_info & FRAMING_FID != 0;
        let eof_meaningful =
            !self.config.stream_based || self.config.framing_info & FRAMING_EOF != 0;
        // FID flip means we're entering a new frame — drop the
        // in-flight buffer (it never saw EOF).
        if fid_meaningful && hdr.fid() != self.current_fid {
            self.buffer.clear();
            self.frame_errored = false;
            self.current_fid = hdr.fid();
        }
        if hdr.is_error() {
            self.frame_errored = true;
        }
        let room = if self.config.max_frame_size == 0 {
            payload.len()
        } else {
            (self.config.max_frame_size as usize).saturating_sub(self.buffer.len())
        };
        let take = payload.len().min(room);
        self.buffer.extend_from_slice(&payload[..take]);
        self.bytes_dropped_overflow += (payload.len() - take) as u64;

        let eof = eof_meaningful && hdr.is_eof();
        let full = self.config.max_frame_size != 0
            && self.buffer.len() >= self.config.max_frame_size as usize;
        if eof || full {
            if self.frame_errored {
                self.buffer.clear();
                self.frame_errored = false;
                self.frames_dropped += 1;
                ReassemblerOutcome::Errored
            } else {
                self.frames_completed += 1;
                ReassemblerOutcome::FrameComplete
            }
        } else {
            ReassemblerOutcome::Appended
        }
    }

    /// Take ownership of the just-completed frame buffer, leaving
    /// the reassembler ready for the next one.
    pub fn take_frame(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        core::mem::swap(&mut out, &mut self.buffer);
        out
    }
}

impl Default for UvcFrameReassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// What [`UvcFrameReassembler::push`] did with a packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReassemblerOutcome {
    /// Packet bytes appended to the in-flight buffer; frame not done yet.
    Appended,
    /// EOF saw a clean frame — buffer has a full frame ready.
    FrameComplete,
    /// EOF saw an error somewhere — buffer was dropped.
    Errored,
    /// Packet header didn't parse — skipped (logged + dropped).
    Skipped,
}

pub static UVC_MATCH: [crate::class_registry::UsbClassMatch; 1] =
    [crate::class_registry::UsbClassMatch::class_only(
        USB_CLASS_VIDEO,
    )];

pub fn probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
    _hub_port: Option<(u8, u8)>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "  usb: USB Video Class (UVC) device bound!"
    );
    Ok(())
}

pub fn register_initcalls() {
    // Mirror MSC's hook registration: the probe always declines (UVC
    // binding stays in the attach cascade), and the unbind hook adapts
    // infallible `detach_uvc` to the fallible `UsbUnbindFn` contract
    // with an unconditional `Ok(())` (#893: a hook reports failure
    // with `Err(())`, never by panicking).
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "uvcvideo",
        &UVC_MATCH,
        probe,
        |controller, slot| {
            detach_uvc(controller, slot);
            Ok(())
        },
    );
}
