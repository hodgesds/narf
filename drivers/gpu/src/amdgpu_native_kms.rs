//! Native-display entry points for the DRM bridges: the amdgpu card's KMS
//! state belongs to whichever native display owner published it. Navi22's
//! (`amdgpu_navi22_kms`) once it has published its card, else Navi48's.
use crate::drm::ioctl::DrmModeModeInfo;

fn navi22() -> bool {
    crate::amdgpu_navi22_kms::active()
}

/// The DCN30 linear-primary card, whose GEM frames are copied rather than
/// scanned out with DCN401's modifier/plane machinery.
pub(crate) fn linear_gem_card(card: &crate::drm::card::Card) -> bool {
    card.driver_name == "amdgpu" && card.native_atomic && !card.gfx12_modifiers
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
/// DRM's planes on display `display`'s CRTC (Navi48 only: Navi22 exposes
/// no overlays or plane placement).
pub fn request_display_planes(display: u8, setup: crate::amdgpu_navi48_boot::PlaneSetup) -> bool {
    !navi22() && crate::amdgpu_navi48_platform::request_display_planes(display, setup)
}
/// Whether display `display` can light the planes `setup` with its
/// primary in `fourcc` (see `amdgpu_navi48_platform::display_admits_planes`).
pub fn display_admits_planes(
    display: u8,
    connector: Option<u32>,
    mode: Option<&DrmModeModeInfo>,
    fourcc: u32,
    setup: &crate::amdgpu_navi48_boot::PlaneSetup,
) -> bool {
    !navi22()
        && crate::amdgpu_navi48_platform::display_admits_planes(
            display, connector, mode, fourcc, setup,
        )
        .is_ok()
}
/// Present an atomic commit's planes on display `display` (Navi48).
pub fn present_planes(
    display: u8,
    primary: Option<crate::amdgpu_navi48_platform::PlaneFrame>,
    overlays: [Option<crate::amdgpu_navi48_platform::PlaneFrame>;
        crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
    ticket: Option<u64>,
) -> bool {
    if navi22() {
        if overlays.iter().any(Option::is_some) {
            return false;
        }
        crate::amdgpu_navi22_platform::present_plane(display, primary, ticket)
    } else {
        crate::amdgpu_navi48_platform::present_planes(display, primary, overlays, ticket)
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
/// A CRTC's committed CTM and GAMMA_LUT blob bytes (None: the property is
/// clear), as DRM hands amdgpu_dm a color_mgmt_changed CRTC state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrtcColorRequest {
    pub ctm: Option<alloc::vec::Vec<u8>>,
    pub gamma_lut: Option<alloc::vec::Vec<u8>>,
}
/// A connector's committed "Colorspace" and HDR_OUTPUT_METADATA bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorColorRequest {
    pub connector: u32,
    pub color_format: crate::amdgpu_hdr::ColorFormat,
    pub colorspace: u32,
    pub hdr_output_metadata: Option<alloc::vec::Vec<u8>>,
}
/// CRTC CTM / GAMMA_LUT. Only Navi48 attaches them.
pub fn request_crtc_color(display: u8, request: CrtcColorRequest) {
    if !navi22() {
        crate::amdgpu_navi48_platform::request_crtc_color(display, request)
    }
}
/// Connector Colorspace / HDR_OUTPUT_METADATA. Only Navi48 attaches them.
pub fn request_connector_color(request: ConnectorColorRequest) {
    if !navi22() {
        crate::amdgpu_navi48_platform::request_connector_color(request)
    }
}
/// Connector "max bpc" (max_requested_bpc). Only Navi48 attaches it.
pub fn request_connector_max_bpc(connector: u32, bpc: u8) {
    if !navi22() {
        crate::amdgpu_navi48_platform::request_connector_max_bpc(connector, bpc)
    }
}
/// Whether connector `connector`'s stream can signal `colorspace` and, with
/// `hdr`, HDR metadata (Navi48; Navi22 attaches neither property).
pub fn connector_color_supported(connector: u32, colorspace: u32, hdr: bool) -> bool {
    navi22() || crate::amdgpu_navi48_platform::connector_color_supported(connector, colorspace, hdr)
}
/// One prospective native HDMI output in an atomic check. The plane
/// setup and exact mode are carried by value; checking never stages state.
#[derive(Clone, Copy, Debug)]
pub struct OutputFormatRequest {
    pub display: u8,
    pub connector: u32,
    pub color_format: crate::amdgpu_hdr::ColorFormat,
    pub mode: Option<crate::drm::ioctl::DrmModeModeInfo>,
    pub max_bpc: Option<u8>,
    pub planes: Option<(u32, crate::amdgpu_navi48_boot::PlaneSetup)>,
}
/// Prospective connector routing (including unchanged native outputs) for
/// joint admission. DP/MST uses its observed link/DSC reservation; a new
/// unobserved link configuration is refused here.
#[derive(Clone, Copy, Debug)]
pub struct OutputRoute {
    pub display: u8,
    pub connector: u32,
    pub mode: Option<crate::drm::ioctl::DrmModeModeInfo>,
    pub planes: Option<(u32, crate::amdgpu_navi48_boot::PlaneSetup)>,
}
pub fn output_formats_supported(requests: &[OutputFormatRequest], routes: &[OutputRoute]) -> bool {
    requests.is_empty()
        || !navi22() && crate::amdgpu_navi48_platform::output_formats_supported(requests, routes)
}
/// Whether an HDR_OUTPUT_METADATA blob builds an HDR infoframe
/// (amdgpu_dm_fill_hdr_info_packet succeeds).
pub fn hdr_metadata_valid(blob: &[u8]) -> bool {
    crate::amdgpu_hdr::HdrOutputMetadata::from_blob(blob).is_ok()
}
/// A DRM cursor plane commit on display `display`: its image at CRTC_X/Y,
/// or off (Navi48 only: Navi22 exposes no cursor plane, its cursor ioctls
/// keep driving the console's pointer).
pub fn request_display_cursor(
    display: u8,
    image: Option<crate::amdgpu_navi48_platform::CursorContent>,
    position: (i32, i32),
) -> bool {
    !navi22()
        && crate::amdgpu_navi48_platform::request_display_cursor_content(display, image, position)
}
