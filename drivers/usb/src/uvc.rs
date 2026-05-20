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

// ── Class enumeration + bind ───────────────────────────────────────
//
// Minimal "is this a UVC device, and if so claim it" path. The
// full streaming surface (iso video frame ring + MJPEG /
// uncompressed payload decode) is a follow-up.

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

/// One bound UVC device — slot id + VideoControl interface number.
#[derive(Copy, Clone, Debug)]
pub struct UvcDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the VideoControl interface.
    pub vc_iface: u8,
}

/// System-wide registry of bound UVC devices.
pub static UVC_DEVICES: IrqSafeSpinLock<Vec<UvcDevice>> = IrqSafeSpinLock::new(Vec::new());

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

/// Bind to an already-addressed UVC device. SET_CONFIGURATION,
/// then record the slot/interface pair.
pub fn try_bind_video_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, UvcError> {
    let vc_iface = find_video_control_interface(cfg).ok_or(UvcError::NotVideo)?;
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
        .is_err()
    {
        return Err(UvcError::SetConfigFailed);
    }
    let mut g = UVC_DEVICES.lock();
    let idx = g.len();
    g.push(UvcDevice { slot_id, vc_iface });
    Ok(idx)
}

pub fn attached_uvc_count() -> usize {
    UVC_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_uvc_for_test() {
    UVC_DEVICES.lock().clear();
}
