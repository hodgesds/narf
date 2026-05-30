//! UVC class-specific descriptor parsing.
//!
//! Parses Video Control (VC) and Video Streaming (VS) interface
//! class-specific descriptors as specified in:
//!
//! - USB Device Class Definition for Video Devices, Revision 1.5
//!   (USB-IF, March 2012) — Tables 3-1 through 3-13.
//! - UVC Uncompressed Payload Specification, Revision 1.5 §3.1.1
//!   (GUID layout for YUY2 / NV12).
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_driver.c`
//! `uvc_parse_vendor_control()` (line ~622), `uvc_parse_standard_control()`
//! (line ~637), `uvc_parse_streaming()` (line ~900) — same descriptor-walk
//! strategy, slicing each descriptor by bLength before dispatching on
//! bDescriptorSubtype.

use alloc::vec::Vec;

// ── Class / subclass / protocol ─────────────────────────────────────

pub const USB_CLASS_VIDEO: u8 = 0x0E;
pub const USB_VIDEO_SUBCLASS_VIDEOCONTROL: u8 = 0x01;
pub const USB_VIDEO_SUBCLASS_VIDEOSTREAMING: u8 = 0x02;
pub const USB_VIDEO_SUBCLASS_INTERFACE_COLLECTION: u8 = 0x03;
pub const USB_VIDEO_PROTOCOL_UVC10: u8 = 0x00;
pub const USB_VIDEO_PROTOCOL_UVC15: u8 = 0x01;

// ── Descriptor type ─────────────────────────────────────────────────

/// CS_INTERFACE — class-specific interface descriptor (bDescriptorType).
pub const CS_INTERFACE: u8 = 0x24;

// ── VC subtype constants (UVC 1.5 §A.5, table 3-1) ─────────────────

pub const VC_HEADER: u8 = 0x01;
pub const VC_INPUT_TERMINAL: u8 = 0x02;
pub const VC_OUTPUT_TERMINAL: u8 = 0x03;
pub const VC_SELECTOR_UNIT: u8 = 0x04;
pub const VC_PROCESSING_UNIT: u8 = 0x05;
pub const VC_EXTENSION_UNIT: u8 = 0x06;

// ── VS subtype constants (UVC 1.5 §A.6, table 3-7) ─────────────────

pub const VS_INPUT_HEADER: u8 = 0x01;
pub const VS_OUTPUT_HEADER: u8 = 0x02;
pub const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
pub const VS_FRAME_UNCOMPRESSED: u8 = 0x05;
pub const VS_FORMAT_MJPEG: u8 = 0x06;
pub const VS_FRAME_MJPEG: u8 = 0x07;
pub const VS_FORMAT_FRAME_BASED: u8 = 0x10;
pub const VS_FRAME_FRAME_BASED: u8 = 0x11;

// ── Terminal type constants (UVC 1.5 §B) ────────────────────────────

pub const TT_VENDOR_SPECIFIC: u16 = 0x0100;
pub const TT_STREAMING: u16 = 0x0101;
pub const ITT_VENDOR_SPECIFIC: u16 = 0x0200;
pub const ITT_CAMERA: u16 = 0x0201;
pub const ITT_MEDIA_TRANSPORT_INPUT: u16 = 0x0202;
pub const OTT_VENDOR_SPECIFIC: u16 = 0x0300;
pub const OTT_DISPLAY: u16 = 0x0301;
pub const OTT_MEDIA_TRANSPORT_OUTPUT: u16 = 0x0302;

// ── Format GUIDs (Uncompressed Payload spec §3.1.1) ─────────────────

/// GUID for YUY2 / YUYV packed 4:2:2.
pub const GUID_FORMAT_YUY2: [u8; 16] = [
    0x59, 0x55, 0x59, 0x32, // "YUY2"
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// GUID for NV12 semi-planar 4:2:0.
pub const GUID_FORMAT_NV12: [u8; 16] = [
    0x4E, 0x56, 0x31, 0x32, // "NV12"
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DescError {
    /// Buffer too short to contain the descriptor.
    Short,
    /// `bLength` field claims more bytes than the buffer contains.
    Truncated,
    /// `bDescriptorType` is not CS_INTERFACE (0x24).
    NotClassSpecific,
    /// `bDescriptorSubtype` didn't match the expected value.
    BadSubtype(u8),
}

fn check_cs(buf: &[u8], expect: u8) -> Result<(), DescError> {
    if buf.len() < 3 {
        return Err(DescError::Short);
    }
    if (buf[0] as usize) > buf.len() {
        return Err(DescError::Truncated);
    }
    if buf[1] != CS_INTERFACE {
        return Err(DescError::NotClassSpecific);
    }
    if buf[2] != expect {
        return Err(DescError::BadSubtype(buf[2]));
    }
    Ok(())
}

// ── VC descriptors ───────────────────────────────────────────────────

/// VC HEADER (§3.7.2, table 3-3). Length = 12 + bInCollection.
///
/// Linux equivalent: `uvc_parse_standard_control()` around line 637 of
/// `uvc_driver.c` — case VC_HEADER reads bcdUVC, wTotalLength, dwClockFrequency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcHeader {
    /// UVC specification release in BCD, e.g. 0x0150 = UVC 1.5.
    pub bcd_uvc: u16,
    /// Total byte length of class-specific VC interface descriptors.
    pub total_length: u16,
    /// Device clock frequency in Hz (deprecated in UVC 1.5; still present).
    pub clock_frequency: u32,
    /// VideoStreaming interface numbers in this collection.
    pub in_collection: Vec<u8>,
}

impl VcHeader {
    /// Parse a VC_HEADER class-specific descriptor.
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_HEADER)?;
        if buf.len() < 12 {
            return Err(DescError::Short);
        }
        let bcd_uvc = u16::from_le_bytes([buf[3], buf[4]]);
        let total_length = u16::from_le_bytes([buf[5], buf[6]]);
        let clock_frequency = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
        let n = buf[11] as usize;
        if buf.len() < 12 + n {
            return Err(DescError::Truncated);
        }
        Ok(Self {
            bcd_uvc,
            total_length,
            clock_frequency,
            in_collection: buf[12..12 + n].to_vec(),
        })
    }
}

/// Camera-specific fields appended to INPUT_TERMINAL when type == ITT_CAMERA.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct CameraTerminalFields {
    pub objective_focal_length_min: u16,
    pub objective_focal_length_max: u16,
    pub ocular_focal_length: u16,
    /// Packed LE u32 of the first ≤4 bytes of bmControls.
    pub controls: u32,
}

/// VC INPUT_TERMINAL (§3.7.2.1, table 3-5).
///
/// Linux equivalent: `uvc_parse_standard_control()` case VC_INPUT_TERMINAL —
/// reads `wTerminalType`, then for ITT_CAMERA reads focal lengths +
/// `bControlSize` + `bmControls`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub terminal_idx: u8,
    /// Camera-specific fields; `None` when terminal_type ≠ ITT_CAMERA.
    pub camera: Option<CameraTerminalFields>,
}

impl InputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_INPUT_TERMINAL)?;
        if buf.len() < 8 {
            return Err(DescError::Short);
        }
        let terminal_id = buf[3];
        let terminal_type = u16::from_le_bytes([buf[4], buf[5]]);
        let assoc_terminal = buf[6];
        let terminal_idx = buf[7];

        let camera = if terminal_type == ITT_CAMERA {
            // §3.7.2.3, table 3-6: fixed-header through offset 14,
            // then bControlSize at 14, then bmControls.
            if buf.len() < 15 {
                return Err(DescError::Short);
            }
            let fl_min = u16::from_le_bytes([buf[8], buf[9]]);
            let fl_max = u16::from_le_bytes([buf[10], buf[11]]);
            let fl_ocular = u16::from_le_bytes([buf[12], buf[13]]);
            let ctrl_sz = buf[14] as usize;
            if buf.len() < 15 + ctrl_sz {
                return Err(DescError::Truncated);
            }
            let mut ctl = [0u8; 4];
            for (i, b) in buf[15..15 + ctrl_sz.min(4)].iter().enumerate() {
                ctl[i] = *b;
            }
            Some(CameraTerminalFields {
                objective_focal_length_min: fl_min,
                objective_focal_length_max: fl_max,
                ocular_focal_length: fl_ocular,
                controls: u32::from_le_bytes(ctl),
            })
        } else {
            None
        };

        Ok(Self { terminal_id, terminal_type, assoc_terminal, terminal_idx, camera })
    }
}

/// VC OUTPUT_TERMINAL (§3.7.2.2, table 3-4). Fixed 9 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutputTerminal {
    pub terminal_id: u8,
    pub terminal_type: u16,
    pub assoc_terminal: u8,
    pub source_id: u8,
    pub terminal_idx: u8,
}

impl OutputTerminal {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_OUTPUT_TERMINAL)?;
        if buf.len() < 9 {
            return Err(DescError::Short);
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

/// VC SELECTOR_UNIT (§3.7.2.4, table 3-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorUnit {
    pub unit_id: u8,
    /// Input pin IDs — one per input.
    pub sources: Vec<u8>,
    pub selector_idx: u8,
}

impl SelectorUnit {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_SELECTOR_UNIT)?;
        if buf.len() < 5 {
            return Err(DescError::Short);
        }
        let unit_id = buf[3];
        let n_in = buf[4] as usize;
        if buf.len() < 5 + n_in + 1 {
            return Err(DescError::Truncated);
        }
        let sources = buf[5..5 + n_in].to_vec();
        let selector_idx = buf[5 + n_in];
        Ok(Self { unit_id, sources, selector_idx })
    }
}

/// VC PROCESSING_UNIT (§3.7.2.5, table 3-8).
///
/// Linux equivalent: `uvc_parse_standard_control()` case VC_PROCESSING_UNIT —
/// reads unit_id, source_id, wMaxMultiplier, bControlSize + bmControls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessingUnit {
    pub unit_id: u8,
    pub source_id: u8,
    pub max_multiplier: u16,
    /// Raw control bitmap (1–3 bytes per spec), packed into LE u32.
    pub controls: u32,
    pub processing_idx: u8,
}

impl ProcessingUnit {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_PROCESSING_UNIT)?;
        if buf.len() < 10 {
            return Err(DescError::Short);
        }
        let unit_id = buf[3];
        let source_id = buf[4];
        let max_multiplier = u16::from_le_bytes([buf[5], buf[6]]);
        let ctrl_sz = buf[7] as usize;
        if buf.len() < 8 + ctrl_sz + 1 {
            return Err(DescError::Truncated);
        }
        let mut ctl = [0u8; 4];
        for (i, b) in buf[8..8 + ctrl_sz.min(4)].iter().enumerate() {
            ctl[i] = *b;
        }
        let processing_idx = buf[8 + ctrl_sz];
        Ok(Self {
            unit_id,
            source_id,
            max_multiplier,
            controls: u32::from_le_bytes(ctl),
            processing_idx,
        })
    }
}

/// VC EXTENSION_UNIT (§3.7.2.7, table 3-12).
///
/// Vendor-specific unit; we capture the GUID and control bitmap but do not
/// interpret the extension-specific fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionUnit {
    pub unit_id: u8,
    pub guid_extension_code: [u8; 16],
    pub num_controls: u8,
    pub sources: Vec<u8>,
    pub controls: u32,
    pub extension_idx: u8,
}

impl ExtensionUnit {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VC_EXTENSION_UNIT)?;
        // Fixed header through offset 22 (bLength + type + subtype + unit_id
        // + guidExtensionCode[16] + bNumControls).
        if buf.len() < 24 {
            return Err(DescError::Short);
        }
        let unit_id = buf[3];
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&buf[4..20]);
        let num_controls = buf[20];
        let n_in = buf[21] as usize;
        if buf.len() < 22 + n_in + 1 {
            return Err(DescError::Truncated);
        }
        let sources = buf[22..22 + n_in].to_vec();
        let ctrl_sz = buf[22 + n_in] as usize;
        if buf.len() < 23 + n_in + ctrl_sz + 1 {
            return Err(DescError::Truncated);
        }
        let ctl_off = 23 + n_in;
        let mut ctl = [0u8; 4];
        for (i, b) in buf[ctl_off..ctl_off + ctrl_sz.min(4)].iter().enumerate() {
            ctl[i] = *b;
        }
        let extension_idx = buf[ctl_off + ctrl_sz];
        Ok(Self {
            unit_id,
            guid_extension_code: guid,
            num_controls,
            sources,
            controls: u32::from_le_bytes(ctl),
            extension_idx,
        })
    }
}

// ── VS descriptors ───────────────────────────────────────────────────

/// VS INPUT_HEADER (§3.9.2.1, table 3-13).
///
/// Linux equivalent: `uvc_parse_streaming()` around line 900 of `uvc_driver.c`
/// — reads bNumFormats, wTotalLength, bEndpointAddress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VsInputHeader {
    pub num_formats: u8,
    pub total_length: u16,
    pub endpoint_address: u8,
    pub still_capture_method: u8,
    pub trigger_support: bool,
    pub trigger_usage: u8,
    /// One control byte per format (bControlSize × bNumFormats).
    pub format_controls: Vec<u8>,
}

impl VsInputHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_INPUT_HEADER)?;
        if buf.len() < 13 {
            return Err(DescError::Short);
        }
        let num_formats = buf[3];
        let total_length = u16::from_le_bytes([buf[4], buf[5]]);
        let endpoint_address = buf[6];
        let still_capture_method = buf[9];
        let trigger_support = buf[10] != 0;
        let trigger_usage = buf[11];
        let ctrl_sz = buf[12] as usize;
        let need = 13 + (num_formats as usize) * ctrl_sz;
        if buf.len() < need {
            return Err(DescError::Truncated);
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

/// VS_FORMAT_UNCOMPRESSED (Uncompressed Payload spec §3.1.1, 27 bytes).
///
/// Linux equivalent: `uvc_parse_format()` in `uvc_driver.c` around line 750 —
/// case `VS_FORMAT_UNCOMPRESSED` reads guidFormat, bBitsPerPixel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatUncompressed {
    pub format_index: u8,
    pub num_frame_descriptors: u8,
    pub guid: [u8; 16],
    pub bits_per_pixel: u8,
    pub default_frame_index: u8,
    pub aspect_ratio_x: u8,
    pub aspect_ratio_y: u8,
    pub interlace_flags: u8,
    pub copy_protect: bool,
}

impl FormatUncompressed {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FORMAT_UNCOMPRESSED)?;
        if buf.len() < 27 {
            return Err(DescError::Short);
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

    /// True iff this format is YUY2 / YUYV.
    pub fn is_yuyv(&self) -> bool {
        self.guid == GUID_FORMAT_YUY2
    }

    /// True iff this format is NV12.
    pub fn is_nv12(&self) -> bool {
        self.guid == GUID_FORMAT_NV12
    }
}

/// VS_FRAME_UNCOMPRESSED (Uncompressed Payload spec §3.1.2).
///
/// Fixed 26 bytes + either 12 bytes (continuous, bFrameIntervalType=0) or
/// 4×N bytes (discrete).
///
/// Linux equivalent: `uvc_parse_frame()` in `uvc_driver.c` around line 800 —
/// same 26-byte fixed header, then dispatch on bFrameIntervalType.
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
    pub frame_intervals: Vec<u32>,
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
}

impl FrameUncompressed {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FRAME_UNCOMPRESSED)?;
        if buf.len() < 26 {
            return Err(DescError::Short);
        }
        parse_frame_body(buf)
    }

    /// Convert a 100 ns interval to fps.
    pub fn fps_from_interval(interval_100ns: u32) -> u32 {
        if interval_100ns == 0 { 0 } else { 10_000_000 / interval_100ns }
    }
}

/// VS_FORMAT_MJPEG (UVC 1.5 §3.1.1, 11 bytes).
///
/// Linux equivalent: `uvc_parse_format()` case `VS_FORMAT_MJPEG` in `uvc_driver.c`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatMjpeg {
    pub format_index: u8,
    pub num_frame_descriptors: u8,
    /// bmFlags — bit 0 = "fixed-size samples" hint.
    pub flags: u8,
    pub default_frame_index: u8,
    pub aspect_ratio_x: u8,
    pub aspect_ratio_y: u8,
    pub interlace_flags: u8,
    pub copy_protect: bool,
}

impl FormatMjpeg {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FORMAT_MJPEG)?;
        if buf.len() < 11 {
            return Err(DescError::Short);
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

/// VS_FRAME_MJPEG (MJPEG Payload companion spec §3.1.2).
///
/// Identical fixed-header layout to FrameUncompressed (26 bytes).
///
/// Linux equivalent: `uvc_parse_frame()` in `uvc_driver.c` — handles both
/// VS_FRAME_UNCOMPRESSED and VS_FRAME_MJPEG with the same 26-byte parse.
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
    pub frame_intervals: Vec<u32>,
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
}

impl FrameMjpeg {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FRAME_MJPEG)?;
        if buf.len() < 26 {
            return Err(DescError::Short);
        }
        parse_frame_body(buf)
    }

    pub fn fps_from_interval(interval_100ns: u32) -> u32 {
        if interval_100ns == 0 { 0 } else { 10_000_000 / interval_100ns }
    }
}

/// VS_FORMAT_FRAME_BASED (Frame-Based Payload spec §3.1.1, 28 bytes).
///
/// Used for H.264 and similar compressed formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatFrameBased {
    pub format_index: u8,
    pub num_frame_descriptors: u8,
    pub guid_format: [u8; 16],
    pub bits_per_pixel: u8,
    pub default_frame_index: u8,
    pub aspect_ratio_x: u8,
    pub aspect_ratio_y: u8,
    pub interlace_flags: u8,
    pub copy_protect: bool,
    pub variable_size: bool,
}

impl FormatFrameBased {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FORMAT_FRAME_BASED)?;
        if buf.len() < 28 {
            return Err(DescError::Short);
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&buf[5..21]);
        Ok(Self {
            format_index: buf[3],
            num_frame_descriptors: buf[4],
            guid_format: guid,
            bits_per_pixel: buf[21],
            default_frame_index: buf[22],
            aspect_ratio_x: buf[23],
            aspect_ratio_y: buf[24],
            interlace_flags: buf[25],
            copy_protect: buf[26] != 0,
            variable_size: buf[27] != 0,
        })
    }
}

/// VS_FRAME_FRAME_BASED (Frame-Based Payload spec §3.1.2).
///
/// Similar to FrameUncompressed but carries `dwBytesPerLine` instead of
/// `dwMaxVideoFrameBufferSize`. Fixed 26 bytes + intervals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameFrameBased {
    pub frame_index: u8,
    pub capabilities: u8,
    pub width: u16,
    pub height: u16,
    pub min_bitrate: u32,
    pub max_bitrate: u32,
    pub default_frame_interval: u32,
    pub bytes_per_line: u32,
    pub frame_intervals: Vec<u32>,
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
}

impl FrameFrameBased {
    pub fn parse(buf: &[u8]) -> Result<Self, DescError> {
        check_cs(buf, VS_FRAME_FRAME_BASED)?;
        if buf.len() < 26 {
            return Err(DescError::Short);
        }
        let frame_index = buf[3];
        let capabilities = buf[4];
        let width = u16::from_le_bytes([buf[5], buf[6]]);
        let height = u16::from_le_bytes([buf[7], buf[8]]);
        let min_bitrate = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]);
        let max_bitrate = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        let default_frame_interval = u32::from_le_bytes([buf[17], buf[18], buf[19], buf[20]]);
        let interval_type = buf[21];
        let bytes_per_line = u32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]);
        let body = &buf[26..];
        if interval_type == 0 {
            if body.len() < 12 {
                return Err(DescError::Truncated);
            }
            let cmin = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let cmax = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let cstep = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
            Ok(Self {
                frame_index, capabilities, width, height, min_bitrate, max_bitrate,
                default_frame_interval, bytes_per_line,
                frame_intervals: Vec::new(),
                continuous_min: Some(cmin), continuous_max: Some(cmax), continuous_step: Some(cstep),
            })
        } else {
            let need = interval_type as usize * 4;
            if body.len() < need {
                return Err(DescError::Truncated);
            }
            let mut intervals = Vec::with_capacity(interval_type as usize);
            for chunk in body[..need].chunks_exact(4) {
                intervals.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
            Ok(Self {
                frame_index, capabilities, width, height, min_bitrate, max_bitrate,
                default_frame_interval, bytes_per_line,
                frame_intervals: intervals,
                continuous_min: None, continuous_max: None, continuous_step: None,
            })
        }
    }
}

// ── Shared frame body parse helper ──────────────────────────────────

/// Parse the common 26-byte frame-descriptor body (used by both
/// FrameUncompressed and FrameMjpeg). `buf` must already have the
/// subtype byte at buf[2] — the caller checks it. Returns a populated
/// `FrameUncompressed` (FrameMjpeg has an identical layout so we
/// re-use this via `From` in streaming.rs).
fn parse_frame_body<T>(buf: &[u8]) -> Result<T, DescError>
where
    T: FromFrameBody,
{
    let frame_index = buf[3];
    let capabilities = buf[4];
    let width = u16::from_le_bytes([buf[5], buf[6]]);
    let height = u16::from_le_bytes([buf[7], buf[8]]);
    let min_bitrate = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]);
    let max_bitrate = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
    let max_frame_buf_size = u32::from_le_bytes([buf[17], buf[18], buf[19], buf[20]]);
    let default_frame_interval = u32::from_le_bytes([buf[21], buf[22], buf[23], buf[24]]);
    let interval_type = buf[25];
    let body = &buf[26..];

    if interval_type == 0 {
        if body.len() < 12 {
            return Err(DescError::Truncated);
        }
        let cmin = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let cmax = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let cstep = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        Ok(T::from_frame(FrameBodyData {
            frame_index, capabilities, width, height, min_bitrate, max_bitrate,
            max_frame_buf_size, default_frame_interval,
            frame_intervals: Vec::new(),
            continuous_min: Some(cmin), continuous_max: Some(cmax), continuous_step: Some(cstep),
        }))
    } else {
        let need = interval_type as usize * 4;
        if body.len() < need {
            return Err(DescError::Truncated);
        }
        let mut intervals = Vec::with_capacity(interval_type as usize);
        for chunk in body[..need].chunks_exact(4) {
            intervals.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        Ok(T::from_frame(FrameBodyData {
            frame_index, capabilities, width, height, min_bitrate, max_bitrate,
            max_frame_buf_size, default_frame_interval,
            frame_intervals: intervals,
            continuous_min: None, continuous_max: None, continuous_step: None,
        }))
    }
}

struct FrameBodyData {
    frame_index: u8,
    capabilities: u8,
    width: u16,
    height: u16,
    min_bitrate: u32,
    max_bitrate: u32,
    max_frame_buf_size: u32,
    default_frame_interval: u32,
    frame_intervals: Vec<u32>,
    continuous_min: Option<u32>,
    continuous_max: Option<u32>,
    continuous_step: Option<u32>,
}

trait FromFrameBody: Sized {
    fn from_frame(d: FrameBodyData) -> Self;
}

impl FromFrameBody for FrameUncompressed {
    fn from_frame(d: FrameBodyData) -> Self {
        Self {
            frame_index: d.frame_index,
            capabilities: d.capabilities,
            width: d.width,
            height: d.height,
            min_bitrate: d.min_bitrate,
            max_bitrate: d.max_bitrate,
            max_video_frame_buffer_size: d.max_frame_buf_size,
            default_frame_interval: d.default_frame_interval,
            frame_intervals: d.frame_intervals,
            continuous_min: d.continuous_min,
            continuous_max: d.continuous_max,
            continuous_step: d.continuous_step,
        }
    }
}

impl FromFrameBody for FrameMjpeg {
    fn from_frame(d: FrameBodyData) -> Self {
        Self {
            frame_index: d.frame_index,
            capabilities: d.capabilities,
            width: d.width,
            height: d.height,
            min_bitrate: d.min_bitrate,
            max_bitrate: d.max_bitrate,
            max_video_frame_buffer_size: d.max_frame_buf_size,
            default_frame_interval: d.default_frame_interval,
            frame_intervals: d.frame_intervals,
            continuous_min: d.continuous_min,
            continuous_max: d.continuous_max,
            continuous_step: d.continuous_step,
        }
    }
}
