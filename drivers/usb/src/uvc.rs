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

use alloc::vec::Vec;

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
    /// SET_CUR/GET_CUR(PROBE) failed or returned a truncated payload.
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
}

/// System-wide registry of bound UVC devices.
pub static UVC_DEVICES: IrqSafeSpinLock<Vec<UvcDevice>> = IrqSafeSpinLock::new(Vec::new());

/// The slice of the xHCI surface the UVC streaming composition needs.
///
/// Production code runs against the live [`crate::xhci::Xhci`]; the
/// end-to-end fixture (`smoke_uvc_streamon_composition_e2e` in
/// `crate::tests`) runs the *same* bind / negotiate / activate /
/// deactivate / pump code against a modelled device implementing this
/// trait, so the composition is validated without silicon. The seam is
/// deliberately narrow — four operations, no controller state — so a
/// modelled transport stays a faithful device conversation (control
/// transfers, endpoint configuration, isochronous packets), not a
/// re-implementation of the composition itself.
pub trait UvcTransport {
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
}

impl UvcTransport for crate::xhci::Xhci {
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

/// Transport-generic core of [`try_bind_video_already_addressed`]:
/// SET_CONFIGURATION, then record the slot/interface pair, the parsed
/// streaming format table, and register the `/dev/video<N>` node.
pub async fn try_bind_video_with_transport<T: UvcTransport>(
    transport: &T,
    slot_id: u8,
    cfg: &[u8],
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
    let video_node =
        narf_drivers_video::devfs_bridge::register_video_with_formats("USB Video Device", formats);
    let mut g = UVC_DEVICES.lock();
    let idx = g.len();
    g.push(UvcDevice {
        slot_id,
        vc_iface,
        vs_iface,
        streaming_endpoints,
        formats: stream_formats,
        active_stream: None,
        video_node,
        stream_generation: 0,
        capture_pump_generation: 0,
        capture_stop_requested: false,
        uvc_version,
        clock_frequency,
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
) -> Result<usize, UvcError> {
    let idx = try_bind_video_with_transport(xhci_dev, slot_id, cfg).await?;
    let video_node = {
        let devices = UVC_DEVICES.lock();
        devices.get(idx).map(|device| device.video_node)
    };
    if let Some(video_node) = video_node {
        narf_drivers_video::devfs_bridge::set_stream_ops(video_node, video_stream_ops());
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
    try_bind_video_already_addressed(xhci_dev, slot_id, cfg).await
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

/// Configure and select the isochronous VideoStreaming alternate chosen
/// for the payload size accepted by UVC PROBE/COMMIT.
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
            let selected = select_video_streaming_iso_endpoint_for_interface(
                &device.streaming_endpoints,
                Some(vs_iface),
                required_payload,
            )
            .ok_or(UvcError::NoStreamingEndpoint)?;
            if active == selected {
                return Ok(active);
            }
            return Err(UvcError::AlreadyStreaming);
        }
        let selected = select_video_streaming_iso_endpoint_for_interface(
            &device.streaming_endpoints,
            Some(vs_iface),
            required_payload,
        )
        .ok_or(UvcError::NoStreamingEndpoint)?;
        (device.slot_id, selected)
    };

    let endpoint_config = crate::xhci::EndpointConfig {
        ep_addr: endpoint.endpoint_address,
        max_packet: endpoint.raw_max_packet,
        kind: crate::xhci::EndpointKind::IsochIn,
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

/// Run the version-aware negotiation sequence (26-byte UVC 1.0,
/// 34-byte UVC 1.1+ per the device's VC HEADER `bcdUVC`), then configure
/// and select the least-bandwidth isochronous alternate that satisfies the
/// device-accepted maximum payload size, and start the capture pump.
pub async fn negotiate_and_activate_video_stream(
    xhci_dev: &crate::xhci::Xhci,
    idx: usize,
    desired: VsProbeCommit,
) -> Result<UvcNegotiatedStream, UvcError> {
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
    let controller = crate::xhci::controller().ok_or(UvcError::CaptureFailed)?;
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
/// #808 seam: packet reception goes through the single
/// [`UvcTransport::isoch_in`] call site in this loop — one packet
/// outstanding at a time. The depth-4 `IsocScheduler` pipelining work
/// slots in behind this seam (a pipelined transport receive) without
/// changing negotiation, activation, the stop protocol, or frame
/// delivery; nothing here bakes in a single-shot assumption beyond
/// that one call.
///
/// Lifecycle: the loop exits cleanly with `Ok(())` when
/// [`take_pump_exit_request`] fires — checked at every loop top, and
/// again after a frame completes, before it is delivered. The second
/// check is load-bearing: the pump parks inside `isoch_in` with no
/// timeout, so STREAMOFF (and a whole STREAMOFF → STREAMON toggle)
/// can run while a packet is in flight; a frame that completes from
/// such a packet belongs to a stream whose buffers were already
/// reset, and delivering it would plant a stale frame in the fresh
/// stream's queue.
pub async fn pump_video_frames_with<T: UvcTransport>(
    idx: usize,
    transport: &T,
    generation: u64,
) -> Result<(), UvcError> {
    let (slot_id, endpoint, video_node) = {
        let devices = UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or(UvcError::NotVideo)?;
        (
            device.slot_id,
            device.active_stream.ok_or(UvcError::NoStreamingEndpoint)?,
            device.video_node,
        )
    };
    let packet_size = usize::try_from(endpoint.max_payload_size)
        .unwrap_or(4096)
        .clamp(1, 4096);
    let mut packet = alloc::vec![0u8; packet_size];
    let mut reassembler = UvcFrameReassembler::new();
    let mut consecutive_errors = 0u8;

    loop {
        if take_pump_exit_request(idx, generation) {
            return Ok(());
        }
        match transport.isoch_in(slot_id, endpoint.dci, &mut packet).await {
            Ok(received) if received != 0 => {
                consecutive_errors = 0;
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

/// Pull one iso-IN packet (video frame fragment) from the bound
/// UVC device. Caller feeds it into a [`UvcFrameReassembler`] to
/// stitch payloads back into whole frames. Returns the byte count.
pub fn capture_one_packet(idx: usize, out: &mut [u8]) -> Result<usize, UvcError> {
    let (slot_id, dci) = {
        let g = UVC_DEVICES.lock();
        let dev = g.get(idx).ok_or(UvcError::NotVideo)?;
        let endpoint = dev.active_stream.ok_or(UvcError::NoStreamingEndpoint)?;
        (dev.slot_id, endpoint.dci)
    };
    // Sync entry-point on the UVC capture path; bridge to async
    // isoch_in via block_on. Called from non-executor contexts.
    let c = match crate::xhci::controller() {
        Some(c) => c,
        None => return Err(UvcError::SetConfigFailed),
    };
    let outcome = narf_scheduler::block_on(async { c.isoch_in(slot_id, dci, out).await });
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
/// record (VC-header clock; 1.0 payload-version declaration — the only
/// payload format this driver's reassembler implements); on 1.0
/// devices they stay zero and are never sent.
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
        let controller = crate::xhci::controller().ok_or(ERRNO_ENODEV)?;
        stream_start_with(&*controller, node, format).await?;
        if let Some(idx) = uvc_index_for_video_node(node) {
            start_video_capture_pump(idx);
        }
        Ok(())
    })
}

fn video_stream_stop(node: usize) -> narf_drivers_video::v4l2_ioctl::StreamHookFuture {
    Box::pin(async move {
        match crate::xhci::controller() {
            Some(controller) => stream_stop_with(&*controller, node).await,
            None => {
                // Controller is gone, so the device is too: only the
                // software teardown remains.
                if let Some(idx) = uvc_index_for_video_node(node) {
                    let mut devices = UVC_DEVICES.lock();
                    if let Some(device) = devices.get_mut(idx) {
                        device.capture_stop_requested = true;
                        device.active_stream = None;
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
    /// `RES` — reserved.
    pub const RES: u8 = 1 << 4;
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
    /// Preferred payload-format version. This driver implements the
    /// 1.0 payload header only, so it declares 1.0 (0x10, BCD nibble
    /// encoding as in `bcdUVC`) for preferred, min, and max; the
    /// device's GET_CUR values are what get committed. A device
    /// requiring 1.5 payloads needs reassembler work first.
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
}

// ── Frame reassembler ──────────────────────────────────────────────
//
// Drives a sequence of iso payloads through the FID/EOF state
// machine to reassemble whole frames. The xHCI iso ring delivers
// one payload per packet; this reassembler accumulates them into
// a single buffer and yields a complete frame on EOF.

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
}

impl UvcFrameReassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_fid: false,
            frame_errored: false,
            frames_completed: 0,
        }
    }

    /// What the reassembler did with the just-pushed packet.
    pub fn push(&mut self, packet: &[u8]) -> ReassemblerOutcome {
        let hdr = match UvcPayloadHeader::parse(packet) {
            Ok(h) => h,
            Err(_) => return ReassemblerOutcome::Skipped,
        };
        let payload = &packet[hdr.length as usize..];
        // FID flip means we're entering a new frame — drop the
        // in-flight buffer (it never saw EOF).
        if hdr.fid() != self.current_fid {
            self.buffer.clear();
            self.frame_errored = false;
            self.current_fid = hdr.fid();
        }
        if hdr.is_error() {
            self.frame_errored = true;
        }
        self.buffer.extend_from_slice(payload);
        if hdr.is_eof() {
            if self.frame_errored {
                self.buffer.clear();
                self.frame_errored = false;
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
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "  usb: USB Video Class (UVC) device bound!"
    );
    Ok(())
}

pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver("uvcvideo", &UVC_MATCH, probe);
}
