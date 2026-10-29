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
