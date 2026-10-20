//! Native-display entry points for the DRM bridges: the amdgpu card's KMS
//! state belongs to whichever native display owner published it. Navi22's
//! (`amdgpu_navi22_kms`) once it has published its card, else Navi48's.
use crate::drm::ioctl::DrmModeModeInfo;

fn navi22() -> bool {
    crate::amdgpu_navi22_kms::active()
}

pub fn crtc_display(crtc_id: u32) -> Option<u8> {
    if navi22() {
        crate::amdgpu_navi22_kms::crtc_display(crtc_id)
    } else {
        crate::amdgpu_navi48_kms::crtc_display(crtc_id)
    }
}
pub fn request_display_active(display: u8, active: bool) {
    if navi22() {
        crate::amdgpu_navi22_kms::request_display_active(display, active)
    } else {
        crate::amdgpu_navi48_platform::request_display_active(display, active)
    }
}
pub fn request_display_route(display: u8, connector: Option<u32>) -> bool {
    if navi22() {
        crate::amdgpu_navi22_kms::request_display_route(display, connector)
    } else {
        crate::amdgpu_navi48_platform::request_display_route(display, connector)
    }
}
pub fn request_connector_crtc(connector: u32, display: Option<u8>) -> bool {
    if navi22() {
        crate::amdgpu_navi22_kms::request_connector_crtc(connector, display)
    } else {
        crate::amdgpu_navi48_platform::request_connector_crtc(connector, display)
    }
}
pub fn display_offers(display: u8, connector: Option<u32>, mode: &DrmModeModeInfo) -> bool {
    if navi22() {
        crate::amdgpu_navi22_kms::display_offers(display, connector, mode)
    } else {
        crate::amdgpu_navi48_platform::display_offers(display, connector, mode)
    }
}
pub fn request_display_mode(display: u8, mode: Option<&DrmModeModeInfo>) -> bool {
    if navi22() {
        crate::amdgpu_navi22_kms::request_display_mode(display, mode)
    } else {
        crate::amdgpu_navi48_platform::request_display_mode(display, mode)
    }
}
/// CRTC "VRR_ENABLED". Only Navi48 attaches the property; Navi22 ignores it.
pub fn request_vrr_enabled(display: u8, enabled: bool) {
    if !navi22() {
        crate::amdgpu_navi48_platform::request_vrr_enabled(display, enabled)
    }
}
/// "Broadcast RGB" applies to the next modeset on either generation (both
/// select the AVI quantization through the same setting).
pub fn request_broadcast_rgb(value: u8) {
    crate::amdgpu_navi48_platform::request_broadcast_rgb(value);
}
pub fn restore_displays() {
    if navi22() {
        crate::amdgpu_navi22_kms::restore_displays()
    } else {
        crate::amdgpu_navi48_platform::restore_displays()
    }
}
pub fn native_present_ready(display: u8) -> bool {
    if navi22() {
        crate::amdgpu_navi22_platform::native_present_ready(display)
    } else {
        crate::amdgpu_navi48_platform::native_present_ready(display)
    }
}
/// The primary plane format (a DRM fourcc) DRM's framebuffer on display
/// `display`'s CRTC holds. Navi48 lights the display again in it when it
/// differs; Navi22's planes take only 32-bit 8888 frames, which its
/// presentation copies, and keep their scanout.
pub fn request_display_format(display: u8, format: u32) -> bool {
    if navi22() {
        true
    } else {
        crate::amdgpu_navi48_platform::request_display_format(display, format)
    }
}
/// Whether display `display` can scan out a `format` plane in `mode` (its
/// current one when None) on its routed connector, or `connector`.
/// Navi22 has nothing to admit beyond its plane formats.
pub fn display_admits_format(
    display: u8,
    connector: Option<u32>,
    mode: Option<&DrmModeModeInfo>,
    format: u32,
) -> bool {
    navi22()
        || crate::amdgpu_navi48_platform::display_admits_format(display, connector, mode, format)
}
/// Present a frame in the framebuffer format `format` (a DRM fourcc).
pub fn present_frame(
    display: u8,
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    ticket: Option<u64>,
    format: u32,
) -> bool {
    if navi22() {
        crate::amdgpu_navi22_platform::present_frame(display, phys, pitch, width, height, ticket)
    } else {
        crate::amdgpu_navi48_platform::present_frame(
            display, phys, pitch, width, height, ticket, format,
        )
    }
}
/// The display the console runs on.
pub fn console_pipe() -> u8 {
    if navi22() {
        0
    } else {
        crate::amdgpu_navi48_platform::console_pipe()
    }
}
