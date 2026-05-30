//! UVC class-specific control requests.
//!
//! Encodes the bmRequestType, bRequest, wValue, wIndex, and wLength
//! fields for UVC class requests as defined in:
//!
//! - UVC 1.5 §A.8 "Video Class-Specific Request Codes"
//! - UVC 1.5 §A.9.4 "Camera Terminal Control Selectors"
//! - UVC 1.5 §A.9.5 "Processing Unit Control Selectors"
//! - UVC 1.5 §A.9.7 "VideoStreaming Interface Control Selectors"
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_video.c`
//! `__uvc_query_ctrl()` lines 32-43 — bmRequestType encoding:
//!   `USB_TYPE_CLASS | USB_RECIP_INTERFACE | (query & 0x80 ? USB_DIR_IN : USB_DIR_OUT)`
//! and `uvc_video.c` `uvc_probe_video()` lines 440-480 — probe/commit loop.

// ── Request codes (UVC 1.5 §A.8) ────────────────────────────────────

/// SET_CUR — set current value of a control.
pub const SET_CUR: u8 = 0x01;
/// GET_CUR — get current value.
pub const GET_CUR: u8 = 0x81;
/// GET_MIN — get minimum value.
pub const GET_MIN: u8 = 0x82;
/// GET_MAX — get maximum value.
pub const GET_MAX: u8 = 0x83;
/// GET_RES — get resolution (step) for the control.
pub const GET_RES: u8 = 0x84;
/// GET_LEN — get payload length.
pub const GET_LEN: u8 = 0x85;
/// GET_INFO — get capability bits for the control.
pub const GET_INFO: u8 = 0x86;
/// GET_DEF — get default value.
pub const GET_DEF: u8 = 0x87;

// ── Processing Unit control selectors (UVC 1.5 §A.9.5) ──────────────

pub const PU_BACKLIGHT_COMPENSATION_CONTROL: u8 = 0x01;
pub const PU_BRIGHTNESS_CONTROL: u8 = 0x02;
pub const PU_CONTRAST_CONTROL: u8 = 0x03;
pub const PU_GAIN_CONTROL: u8 = 0x04;
pub const PU_POWER_LINE_FREQUENCY_CONTROL: u8 = 0x05;
pub const PU_HUE_CONTROL: u8 = 0x06;
pub const PU_SATURATION_CONTROL: u8 = 0x07;
pub const PU_SHARPNESS_CONTROL: u8 = 0x08;
pub const PU_GAMMA_CONTROL: u8 = 0x09;
pub const PU_WHITE_BALANCE_TEMPERATURE_CONTROL: u8 = 0x0A;
pub const PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL: u8 = 0x0B;
pub const PU_WHITE_BALANCE_COMPONENT_CONTROL: u8 = 0x0C;
pub const PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL: u8 = 0x0D;
pub const PU_DIGITAL_MULTIPLIER_CONTROL: u8 = 0x0E;
pub const PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL: u8 = 0x0F;
pub const PU_HUE_AUTO_CONTROL: u8 = 0x10;
pub const PU_ANALOG_VIDEO_STANDARD_CONTROL: u8 = 0x11;
pub const PU_ANALOG_LOCK_STATUS_CONTROL: u8 = 0x12;

// ── Camera Terminal control selectors (UVC 1.5 §A.9.4) ──────────────

pub const CT_SCANNING_MODE_CONTROL: u8 = 0x01;
pub const CT_AE_MODE_CONTROL: u8 = 0x02;
pub const CT_AE_PRIORITY_CONTROL: u8 = 0x03;
pub const CT_EXPOSURE_TIME_ABSOLUTE_CONTROL: u8 = 0x04;
pub const CT_EXPOSURE_TIME_RELATIVE_CONTROL: u8 = 0x05;
pub const CT_FOCUS_ABSOLUTE_CONTROL: u8 = 0x06;
pub const CT_FOCUS_RELATIVE_CONTROL: u8 = 0x07;
pub const CT_FOCUS_AUTO_CONTROL: u8 = 0x08;
pub const CT_IRIS_ABSOLUTE_CONTROL: u8 = 0x09;
pub const CT_IRIS_RELATIVE_CONTROL: u8 = 0x0A;
pub const CT_ZOOM_ABSOLUTE_CONTROL: u8 = 0x0B;
pub const CT_ZOOM_RELATIVE_CONTROL: u8 = 0x0C;
pub const CT_PANTILT_ABSOLUTE_CONTROL: u8 = 0x0D;
pub const CT_PANTILT_RELATIVE_CONTROL: u8 = 0x0E;
pub const CT_ROLL_ABSOLUTE_CONTROL: u8 = 0x0F;
pub const CT_ROLL_RELATIVE_CONTROL: u8 = 0x10;
pub const CT_PRIVACY_CONTROL: u8 = 0x11;

// ── VS interface control selectors (UVC 1.5 §A.9.7) ─────────────────

pub const VS_PROBE_CONTROL: u8 = 0x01;
pub const VS_COMMIT_CONTROL: u8 = 0x02;

// ── bmRequestType values ─────────────────────────────────────────────
//
// Linux uvc_video.c line 36:
//   u8 type = USB_TYPE_CLASS | USB_RECIP_INTERFACE;
//   type |= (query & 0x80) ? USB_DIR_IN : USB_DIR_OUT;
//
// USB_TYPE_CLASS = 0x20, USB_RECIP_INTERFACE = 0x01
// USB_DIR_IN = 0x80, USB_DIR_OUT = 0x00.

/// bmRequestType for a class-to-device (OUT) request on an interface.
pub const BM_REQUEST_TYPE_CLASS_OUT: u8 = 0x21;
/// bmRequestType for a class-from-device (IN) request on an interface.
pub const BM_REQUEST_TYPE_CLASS_IN: u8 = 0xA1;

/// Returns the correct bmRequestType for a given UVC request code.
/// GET_* requests have bit 7 set and map to IN; SET_* maps to OUT.
pub fn bm_request_type(request_code: u8) -> u8 {
    if request_code & 0x80 != 0 {
        BM_REQUEST_TYPE_CLASS_IN
    } else {
        BM_REQUEST_TYPE_CLASS_OUT
    }
}

/// Encode the `wValue` field for a control request.
///
/// Per Linux `uvc_video.c` line 31:
///   `usb_control_msg(..., cs << 8, unit << 8 | intfnum, ...)`.
/// So wValue = (control_selector << 8) | 0x00.
pub fn w_value(control_selector: u8) -> u16 {
    (control_selector as u16) << 8
}

/// Encode the `wIndex` field for a control request.
///
/// Per Linux `uvc_video.c` line 31:
///   `wIndex = unit_id << 8 | intfnum`.
pub fn w_index(unit_id: u8, interface_num: u8) -> u16 {
    ((unit_id as u16) << 8) | (interface_num as u16)
}

// ── VS Probe/Commit payload (UVC 1.5 §4.3.1.1) ──────────────────────
//
// The host negotiates format/frame/interval with the device through a
// pair of 26-byte (UVC 1.0/1.1) or 34-byte (UVC 1.5) payloads.
//
// Linux uvc_video.c lines 283-285:
//   if (uvc->uvc_version < 0x0150) return 26;
//   else return 34;
//
// We implement both variants; probe/commit always encodes at least 26
// bytes and extends to 34 when the device indicates UVC 1.5.

/// Probe/Commit control payload for UVC 1.0/1.1 (26 bytes).
pub const PROBE_COMMIT_LEN_V10: usize = 26;
/// Probe/Commit control payload extension for UVC 1.5 (34 bytes).
pub const PROBE_COMMIT_LEN_V15: usize = 34;

/// VS Probe/Commit control parameter block (§4.3.1.1, table 4-47).
///
/// Supports both 26-byte and 34-byte wire encoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProbeCommit {
    /// Hint bitmap — bit 0 = frame interval hint.
    pub hint: u16,
    /// 1-based format index from VS_FORMAT_* descriptors.
    pub format_index: u8,
    /// 1-based frame index from VS_FRAME_* descriptors of the chosen format.
    pub frame_index: u8,
    /// Desired frame interval in 100 ns units. 333_333 ≈ 30 fps.
    pub frame_interval: u32,
    pub key_frame_rate: u16,
    pub p_frame_rate: u16,
    pub comp_quality: u16,
    pub comp_window_size: u16,
    pub delay: u16,
    /// Maximum video frame size in bytes.
    pub max_video_frame_size: u32,
    /// Maximum payload transfer size in bytes.
    pub max_payload_transfer_size: u32,
    // ── UVC 1.5 extension fields (bytes 26-33) ────────────────────
    /// Device clock frequency. Valid when UVC ≥ 1.5.
    pub clock_frequency: u32,
    /// Framing information bitmask. Valid when UVC ≥ 1.5.
    pub framing_info: u8,
    /// Preferred payload format version. Valid when UVC ≥ 1.5.
    pub preferred_version: u8,
    /// Minimum payload format version. Valid when UVC ≥ 1.5.
    pub min_version: u8,
    /// Maximum payload format version. Valid when UVC ≥ 1.5.
    pub max_version: u8,
}

impl ProbeCommit {
    /// Encode to 26-byte (UVC 1.0/1.1) wire format.
    pub fn encode_v10(&self) -> [u8; PROBE_COMMIT_LEN_V10] {
        let mut b = [0u8; PROBE_COMMIT_LEN_V10];
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

    /// Encode to 34-byte (UVC 1.5) wire format.
    pub fn encode_v15(&self) -> [u8; PROBE_COMMIT_LEN_V15] {
        let mut b = [0u8; PROBE_COMMIT_LEN_V15];
        let v10 = self.encode_v10();
        b[..26].copy_from_slice(&v10);
        b[26..30].copy_from_slice(&self.clock_frequency.to_le_bytes());
        b[30] = self.framing_info;
        b[31] = self.preferred_version;
        b[32] = self.min_version;
        b[33] = self.max_version;
        b
    }

    /// Decode from a 26-byte buffer.
    pub fn decode_v10(buf: &[u8]) -> Option<Self> {
        if buf.len() < PROBE_COMMIT_LEN_V10 {
            return None;
        }
        Some(Self {
            hint: u16::from_le_bytes([buf[0], buf[1]]),
            format_index: buf[2],
            frame_index: buf[3],
            frame_interval: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            key_frame_rate: u16::from_le_bytes([buf[8], buf[9]]),
            p_frame_rate: u16::from_le_bytes([buf[10], buf[11]]),
            comp_quality: u16::from_le_bytes([buf[12], buf[13]]),
            comp_window_size: u16::from_le_bytes([buf[14], buf[15]]),
            delay: u16::from_le_bytes([buf[16], buf[17]]),
            max_video_frame_size: u32::from_le_bytes(buf[18..22].try_into().ok()?),
            max_payload_transfer_size: u32::from_le_bytes(buf[22..26].try_into().ok()?),
            ..Self::default()
        })
    }

    /// Decode from a 34-byte (UVC 1.5) buffer.
    pub fn decode_v15(buf: &[u8]) -> Option<Self> {
        let mut s = Self::decode_v10(buf)?;
        if buf.len() >= PROBE_COMMIT_LEN_V15 {
            s.clock_frequency = u32::from_le_bytes(buf[26..30].try_into().ok()?);
            s.framing_info = buf[30];
            s.preferred_version = buf[31];
            s.min_version = buf[32];
            s.max_version = buf[33];
        }
        Some(s)
    }

    /// Decode from a buffer of either 26 or 34 bytes.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() >= PROBE_COMMIT_LEN_V15 {
            Self::decode_v15(buf)
        } else {
            Self::decode_v10(buf)
        }
    }
}

// ── Control range descriptor ─────────────────────────────────────────

/// GET_MIN / GET_MAX / GET_RES / GET_CUR / GET_DEF response for a 2-byte
/// integer control (e.g. brightness, contrast, gain).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ControlRange {
    pub min: i16,
    pub max: i16,
    pub res: i16,
    pub cur: i16,
    pub def: i16,
}

impl ControlRange {
    /// Decode a 2-byte LE signed integer from a GET_* response.
    pub fn parse_i16(buf: &[u8]) -> Option<i16> {
        if buf.len() < 2 {
            return None;
        }
        Some(i16::from_le_bytes([buf[0], buf[1]]))
    }
}

/// High-level control IDs exposed to the V4L2-equivalent surface.
///
/// Maps to the UVC processing-unit or camera-terminal selector plus
/// the unit ID of the entity that owns the control.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ControlId {
    Brightness,
    Contrast,
    Saturation,
    Gain,
    WhiteBalanceTemperature,
    WhiteBalanceAuto,
    Hue,
    Sharpness,
    Gamma,
    Backlight,
    Zoom,
    Focus,
    AutoFocus,
    ExposureTimeAbsolute,
    AeMode,
}

impl ControlId {
    /// Returns `(unit_selector_byte, is_camera_terminal)`.
    ///
    /// Processing-unit controls use the PU selector and are sent to
    /// `unit_id = pu_unit_id`. Camera-terminal controls use the CT
    /// selector and are sent to `unit_id = ct_unit_id`.
    pub fn selector_and_is_ct(self) -> (u8, bool) {
        match self {
            ControlId::Brightness => (PU_BRIGHTNESS_CONTROL, false),
            ControlId::Contrast => (PU_CONTRAST_CONTROL, false),
            ControlId::Saturation => (PU_SATURATION_CONTROL, false),
            ControlId::Gain => (PU_GAIN_CONTROL, false),
            ControlId::WhiteBalanceTemperature => (PU_WHITE_BALANCE_TEMPERATURE_CONTROL, false),
            ControlId::WhiteBalanceAuto => (PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL, false),
            ControlId::Hue => (PU_HUE_CONTROL, false),
            ControlId::Sharpness => (PU_SHARPNESS_CONTROL, false),
            ControlId::Gamma => (PU_GAMMA_CONTROL, false),
            ControlId::Backlight => (PU_BACKLIGHT_COMPENSATION_CONTROL, false),
            ControlId::Zoom => (CT_ZOOM_ABSOLUTE_CONTROL, true),
            ControlId::Focus => (CT_FOCUS_ABSOLUTE_CONTROL, true),
            ControlId::AutoFocus => (CT_FOCUS_AUTO_CONTROL, true),
            ControlId::ExposureTimeAbsolute => (CT_EXPOSURE_TIME_ABSOLUTE_CONTROL, true),
            ControlId::AeMode => (CT_AE_MODE_CONTROL, true),
        }
    }
}
