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

use alloc::vec::Vec;

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
///
/// Only controls with a V4L2 integer/boolean/enum control ID are
/// represented here: every selector in UVC 1.5 §A.9.4/§A.9.5 that
/// maps to a `V4L2_CID_*` (see [`ControlId::v4l2_id`]). Selectors
/// with no V4L2 integer mapping are deliberately absent — the
/// white-balance *component* (one 4-byte control carrying two u16
/// fields), the digital multiplier/limit, the analog video
/// standard/lock status, the scanning mode, the *relative*
/// camera-terminal controls (no absolute V4L2 CID exists for them),
/// and pan/tilt/roll (multi-field payloads) are not single V4L2
/// integers; see [`supported_controls`].
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
    /// PU power-line frequency (V4L2 enum: 0 disabled, 1 50 Hz,
    /// 2 60 Hz, 3 auto).
    PowerLineFrequency,
    /// PU hue-auto (V4L2 boolean).
    HueAuto,
    Zoom,
    Focus,
    AutoFocus,
    ExposureTimeAbsolute,
    AeMode,
    /// CT auto-exposure priority (V4L2 boolean).
    AePriority,
    /// CT iris absolute.
    IrisAbsolute,
    /// CT privacy (V4L2 boolean).
    Privacy,
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
            ControlId::PowerLineFrequency => (PU_POWER_LINE_FREQUENCY_CONTROL, false),
            ControlId::HueAuto => (PU_HUE_AUTO_CONTROL, false),
            ControlId::Zoom => (CT_ZOOM_ABSOLUTE_CONTROL, true),
            ControlId::Focus => (CT_FOCUS_ABSOLUTE_CONTROL, true),
            ControlId::AutoFocus => (CT_FOCUS_AUTO_CONTROL, true),
            ControlId::ExposureTimeAbsolute => (CT_EXPOSURE_TIME_ABSOLUTE_CONTROL, true),
            ControlId::AeMode => (CT_AE_MODE_CONTROL, true),
            ControlId::AePriority => (CT_AE_PRIORITY_CONTROL, true),
            ControlId::IrisAbsolute => (CT_IRIS_ABSOLUTE_CONTROL, true),
            ControlId::Privacy => (CT_PRIVACY_CONTROL, true),
        }
    }

    /// Inverse of [`ControlId::selector_and_is_ct`]: the [`ControlId`]
    /// for a `(selector, is_camera_terminal)` pair, or `None` when
    /// the selector has no V4L2 integer mapping (see the enum docs).
    pub fn from_selector(selector: u8, is_ct: bool) -> Option<ControlId> {
        Some(match (selector, is_ct) {
            (PU_BACKLIGHT_COMPENSATION_CONTROL, false) => ControlId::Backlight,
            (PU_BRIGHTNESS_CONTROL, false) => ControlId::Brightness,
            (PU_CONTRAST_CONTROL, false) => ControlId::Contrast,
            (PU_GAIN_CONTROL, false) => ControlId::Gain,
            (PU_POWER_LINE_FREQUENCY_CONTROL, false) => ControlId::PowerLineFrequency,
            (PU_HUE_CONTROL, false) => ControlId::Hue,
            (PU_SATURATION_CONTROL, false) => ControlId::Saturation,
            (PU_SHARPNESS_CONTROL, false) => ControlId::Sharpness,
            (PU_GAMMA_CONTROL, false) => ControlId::Gamma,
            (PU_WHITE_BALANCE_TEMPERATURE_CONTROL, false) => ControlId::WhiteBalanceTemperature,
            (PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL, false) => ControlId::WhiteBalanceAuto,
            (PU_HUE_AUTO_CONTROL, false) => ControlId::HueAuto,
            (CT_AE_MODE_CONTROL, true) => ControlId::AeMode,
            (CT_AE_PRIORITY_CONTROL, true) => ControlId::AePriority,
            (CT_EXPOSURE_TIME_ABSOLUTE_CONTROL, true) => ControlId::ExposureTimeAbsolute,
            (CT_FOCUS_ABSOLUTE_CONTROL, true) => ControlId::Focus,
            (CT_FOCUS_AUTO_CONTROL, true) => ControlId::AutoFocus,
            (CT_IRIS_ABSOLUTE_CONTROL, true) => ControlId::IrisAbsolute,
            (CT_ZOOM_ABSOLUTE_CONTROL, true) => ControlId::Zoom,
            (CT_PRIVACY_CONTROL, true) => ControlId::Privacy,
            _ => return None,
        })
    }

    /// The V4L2 control ID for this control
    /// (`include/uapi/linux/v4l2-controls.h`, TI Linux 6.6 mirror):
    /// user class base `0x00980900` — brightness +0, contrast +1,
    /// saturation +2, hue +3, auto-white-balance +12, gamma +16,
    /// gain +19, power-line frequency +24, hue-auto +25, white-balance
    /// temperature +26, sharpness +27, backlight compensation +28;
    /// camera class base `0x009a0900` — exposure-auto +1,
    /// exposure-absolute +2, exposure-auto-priority +3, focus-absolute
    /// +10, focus-auto +12, zoom-absolute +13, privacy +16,
    /// iris-absolute +17.
    pub fn v4l2_id(self) -> u32 {
        const USER: u32 = 0x0098_0900;
        const CAMERA: u32 = 0x009a_0900;
        match self {
            ControlId::Brightness => USER,
            ControlId::Contrast => USER + 1,
            ControlId::Saturation => USER + 2,
            ControlId::Hue => USER + 3,
            ControlId::WhiteBalanceAuto => USER + 12,
            ControlId::Gamma => USER + 16,
            ControlId::Gain => USER + 19,
            ControlId::PowerLineFrequency => USER + 24,
            ControlId::HueAuto => USER + 25,
            ControlId::WhiteBalanceTemperature => USER + 26,
            ControlId::Sharpness => USER + 27,
            ControlId::Backlight => USER + 28,
            ControlId::AeMode => CAMERA + 1,
            ControlId::ExposureTimeAbsolute => CAMERA + 2,
            ControlId::AePriority => CAMERA + 3,
            ControlId::Focus => CAMERA + 10,
            ControlId::AutoFocus => CAMERA + 12,
            ControlId::Zoom => CAMERA + 13,
            ControlId::Privacy => CAMERA + 16,
            ControlId::IrisAbsolute => CAMERA + 17,
        }
    }

    /// Inverse of [`ControlId::v4l2_id`].
    pub fn from_v4l2_id(id: u32) -> Option<ControlId> {
        Some(match id {
            0x0098_0900 => ControlId::Brightness,
            0x0098_0901 => ControlId::Contrast,
            0x0098_0902 => ControlId::Saturation,
            0x0098_0903 => ControlId::Hue,
            0x0098_090c => ControlId::WhiteBalanceAuto,
            0x0098_0910 => ControlId::Gamma,
            0x0098_0913 => ControlId::Gain,
            0x0098_0918 => ControlId::PowerLineFrequency,
            0x0098_0919 => ControlId::HueAuto,
            0x0098_091a => ControlId::WhiteBalanceTemperature,
            0x0098_091b => ControlId::Sharpness,
            0x0098_091c => ControlId::Backlight,
            0x009a_0901 => ControlId::AeMode,
            0x009a_0902 => ControlId::ExposureTimeAbsolute,
            0x009a_0903 => ControlId::AePriority,
            0x009a_090a => ControlId::Focus,
            0x009a_090c => ControlId::AutoFocus,
            0x009a_090d => ControlId::Zoom,
            0x009a_0910 => ControlId::Privacy,
            0x009a_0911 => ControlId::IrisAbsolute,
            _ => return None,
        })
    }

    /// Display name used in `v4l2_queryctrl` (matches the V4L2
    /// control names in `v4l2-controls.h` / the V4L2 documentation).
    pub fn name(self) -> &'static str {
        match self {
            ControlId::Brightness => "Brightness",
            ControlId::Contrast => "Contrast",
            ControlId::Saturation => "Saturation",
            ControlId::Gain => "Gain",
            ControlId::WhiteBalanceTemperature => "White Balance Temperature",
            ControlId::WhiteBalanceAuto => "White Balance, Automatic",
            ControlId::Hue => "Hue",
            ControlId::Sharpness => "Sharpness",
            ControlId::Gamma => "Gamma",
            ControlId::Backlight => "Backlight Compensation",
            ControlId::PowerLineFrequency => "Power Line Frequency",
            ControlId::HueAuto => "Hue, Automatic",
            ControlId::Zoom => "Zoom, Absolute",
            ControlId::Focus => "Focus, Absolute",
            ControlId::AutoFocus => "Focus, Automatic",
            ControlId::ExposureTimeAbsolute => "Exposure, Absolute",
            ControlId::AeMode => "Exposure, Auto",
            ControlId::AePriority => "Exposure, Auto Priority",
            ControlId::IrisAbsolute => "Iris, Absolute",
            ControlId::Privacy => "Privacy",
        }
    }
}

/// Build the [`ControlId`] list a device actually supports from the
/// Processing Unit and Camera Terminal `bmControls` bitmaps.
///
/// UVC 1.5 §3.7.2.5 Table 3-9 (PU) and §3.7.2.3 Table 3-6 (CT)
/// number the bitmap `D0` first: bit *N* of the bitmap advertises
/// the control whose selector is *N+1* — D0 is the least-significant
/// bit of the first `bmControls` byte. The in-tree descriptor
/// parsers pack the bitmap bytes little-endian into a `u32`, so
/// `bitmap & (1 << (selector - 1))` is the support test. (The
/// existing `uvc_tests` PU/CT smokes pin this: a PU bitmap of
/// `0x5F` advertises brightness(bit 1)/contrast(bit 2)/gain(bit 3),
/// and a CT bitmap of `0x0E` advertises AE mode(bit 1)/AE
/// priority(bit 2)/exposure-absolute(bit 3).)
///
/// PU controls come first in selector order, then CT controls.
/// Bitmap bits with no [`ControlId`] mapping are skipped, never
/// advertised — a device that sets the white-balance-component,
/// scanning-mode, or pan/tilt-absolute bit does not gain a V4L2
/// control for it (see the [`ControlId`] docs).
pub fn supported_controls(pu_bitmap: u32, ct_bitmap: u32) -> Vec<ControlId> {
    let mut out = Vec::new();
    for selector in 1..=18u8 {
        if pu_bitmap & (1u32 << (selector - 1)) != 0 {
            if let Some(id) = ControlId::from_selector(selector, false) {
                out.push(id);
            }
        }
    }
    for selector in 1..=17u8 {
        if ct_bitmap & (1u32 << (selector - 1)) != 0 {
            if let Some(id) = ControlId::from_selector(selector, true) {
                out.push(id);
            }
        }
    }
    out
}

/// Decode a GET_CUR/GET_MIN/GET_MAX/GET_RES/GET_DEF response payload
/// into the V4L2 integer value.
///
/// The payload length comes from the device's own GET_LEN answer, so
/// this never assumes a size: 1 byte is an unsigned byte (booleans
/// and enums), 2 bytes are a little-endian `i16` (the in-tree
/// [`ControlRange::parse_i16`] encoding — brightness, contrast,
/// gain, focus, zoom, …), and 4 bytes are a little-endian `u32`
/// clamped into `i32` (exposure-time-absolute, UVC 1.5 §4.2.2.1.4).
/// Any other length (3-byte zoom-relative, 8-byte pan/tilt-absolute)
/// has no single-integer mapping and returns `None`.
pub fn decode_control_value(bytes: &[u8]) -> Option<i32> {
    match bytes.len() {
        1 => Some(bytes[0] as i32),
        2 => ControlRange::parse_i16(bytes).map(|v| v as i32),
        4 => {
            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Some(v.min(i32::MAX as u32) as i32)
        }
        _ => None,
    }
}

/// Encode a V4L2 integer value into a SET_CUR payload of `len` bytes
/// (the length the device reported via GET_LEN). Inverse of
/// [`decode_control_value`]; returns `false` for an unsupported
/// length instead of writing a truncated payload.
pub fn encode_control_value(value: i32, len: u8, out: &mut [u8]) -> bool {
    if (out.len() as u8) < len {
        return false;
    }
    match len {
        1 => {
            out[0] = value.clamp(0, u8::MAX as i32) as u8;
            true
        }
        2 => {
            out[..2].copy_from_slice(&(value as i16).to_le_bytes());
            true
        }
        4 => {
            out[..4].copy_from_slice(&(value.max(0) as u32).to_le_bytes());
            true
        }
        _ => false,
    }
}

// ── Control routing ──────────────────────────────────────────────────

/// Route a logical control to the `(unit_id, selector)` pair a UVC
/// class control transfer must address.
///
/// Processing-unit controls are sent to the Processing Unit
/// (`pu_unit_id`); camera-terminal controls to the Camera Terminal
/// (`ct_unit_id`). The selector byte comes from
/// [`ControlId::selector_and_is_ct`]; pair the result with
/// [`w_value`] / [`w_index`] to build the transfer.
///
/// Returns `None` when the addressed unit is absent (unit ID 0) —
/// the caller must not issue a transfer to unit 0.
///
/// This logic is the survivor of the excised `v4l2::Camera`
/// abstraction (#810): its `control_routing` was the only production
/// asset that layer held, and the V4L2 control path (#809) routes
/// through here.
pub fn route_control(id: ControlId, pu_unit_id: u8, ct_unit_id: u8) -> Option<(u8, u8)> {
    let (selector, is_ct) = id.selector_and_is_ct();
    let unit_id = if is_ct { ct_unit_id } else { pu_unit_id };
    if unit_id == 0 {
        return None;
    }
    Some((unit_id, selector))
}
