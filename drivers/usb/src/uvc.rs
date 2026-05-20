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
    /// DCI of the iso-IN endpoint (video frames device→host).
    /// 0 = no iso IN endpoint found (bulk-streaming variant of UVC).
    pub iso_in_dci: u8,
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
    let iso_in_dci = find_video_streaming_iso_in_ep(cfg);
    let mut g = UVC_DEVICES.lock();
    let idx = g.len();
    g.push(UvcDevice {
        slot_id,
        vc_iface,
        iso_in_dci,
    });
    Ok(idx)
}

/// Scan the config blob for the first VideoStreaming interface's
/// iso-IN endpoint. Returns 0 if not present (UVC bulk-streaming
/// variant — used by some virtualised cameras).
pub fn find_video_streaming_iso_in_ep(cfg: &[u8]) -> u8 {
    let mut i = 0;
    let mut in_vs_iface = false;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            in_vs_iface = cls == USB_CLASS_VIDEO
                && sub == USB_VIDEO_SUBCLASS_VIDEOSTREAMING;
        } else if desc_type == 0x05 && in_vs_iface && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            if attrs & 0x03 == 1 && ep_addr & 0x80 != 0 {
                let ep_num = ep_addr & 0x0F;
                return (ep_num * 2) + 1; // IN endpoint DCI
            }
        }
        i += len;
    }
    0
}

/// Pull one iso-IN packet (video frame fragment) from the bound
/// UVC device. Caller feeds it into a [`UvcFrameReassembler`] to
/// stitch payloads back into whole frames. Returns the byte count.
pub fn capture_one_packet(idx: usize, out: &mut [u8]) -> Result<usize, UvcError> {
    let (slot_id, dci) = {
        let g = UVC_DEVICES.lock();
        let dev = g.get(idx).ok_or(UvcError::NotVideo)?;
        if dev.iso_in_dci == 0 {
            return Err(UvcError::NotVideo);
        }
        (dev.slot_id, dev.iso_in_dci)
    };
    let outcome = crate::xhci::with_controller(|c| c.isoch_in(slot_id, dci, out));
    match outcome {
        Some(Ok(n)) => Ok(n),
        Some(Err(_)) | None => Err(UvcError::SetConfigFailed),
    }
}

pub fn attached_uvc_count() -> usize {
    UVC_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_uvc_for_test() {
    UVC_DEVICES.lock().clear();
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

/// VS Probe/Commit Control payload (UVC 1.0/1.1 — 26 bytes).
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
}

impl VsProbeCommit {
    pub const LEN_V10: usize = 26;

    /// Serialise into a 26-byte buffer for SET_CUR(PROBE/COMMIT).
    pub fn encode(&self) -> [u8; Self::LEN_V10] {
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

    /// Parse a 26-byte GET_CUR/MIN/MAX/DEF response.
    pub fn decode(buf: &[u8]) -> Result<Self, UvcError> {
        if buf.len() < Self::LEN_V10 {
            return Err(UvcError::Short);
        }
        Ok(Self {
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
        })
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
