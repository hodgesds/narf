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
/// CRTC "VRR_ENABLED" on native AMD display owners.
pub fn request_vrr_enabled(display: u8, enabled: bool) {
    if navi22() {
        crate::amdgpu_navi22_kms::request_vrr_enabled(display, enabled)
    } else {
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
        crate::amdgpu_navi22_platform::release_client_scanout_async();
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
/// Navi22 has nothing to admit beyond its plane formats (which
/// [`display_admits_planes`] checks for every CRTC a commit touches).
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
/// Present a linear 8888 dumb-buffer frame whose rows outside `damage`
/// are unchanged since that buffer's previous frame (DIRTYFB). False when
/// the display cannot present natively now.
pub fn present_damaged(
    display: u8,
    frame: crate::amdgpu_navi48_platform::PlaneFrame,
    damage: core::ops::Range<u32>,
) -> bool {
    if navi22() {
        crate::amdgpu_navi22_platform::present_damaged(display, Some(frame), None, Some(damage))
    } else {
        crate::amdgpu_navi48_platform::present_damaged(
            display,
            Some(frame),
            core::array::from_fn(|_| None),
            None,
            Some(damage),
        )
    }
}
/// DRM's planes on display `display`'s CRTC. Navi48 relights the display
/// with them (DC's full update); Navi22's presenter takes each plane's
/// placement with its frame, so there is nothing to stage and the request
/// is accepted as it is.
pub fn request_display_planes(display: u8, setup: crate::amdgpu_navi48_boot::PlaneSetup) -> bool {
    navi22() || crate::amdgpu_navi48_platform::request_display_planes(display, setup)
}
/// The refusal text for a plane configuration Navi48's DML refuses.
pub const PLANES_REFUSED: &str =
    "DC refuses the CRTC's primary and overlay planes together (dc_validate_global_state)";
/// Whether display `display` can light `planes` (its primary in
/// `planes.primary_format`, see
/// `amdgpu_navi48_platform::display_admits_planes` and
/// `amdgpu_navi22_plane::admit`): dc_validate_global_state for one CRTC.
/// The error is the refusal trace's `why=` text.
///
/// `mode` is the timing the request itself sets on the CRTC, if any
/// (Navi48 plans the planes on it); `active` is the CRTC's active size
/// after the request — that timing's, else the committed mode's — which
/// Navi22 compares with its lit stream: a plane placed for a mode the
/// display is not showing yet is validated by the modeset that lights it,
/// whether or not this request is the one carrying the MODE_ID.
pub fn display_admits_planes(
    display: u8,
    connector: Option<u32>,
    mode: Option<&DrmModeModeInfo>,
    active: Option<(u32, u32)>,
    planes: &crate::drm_native_planes::DisplayPlanes,
) -> Result<(), &'static str> {
    if navi22() {
        return crate::amdgpu_navi22_platform::planes_admitted(display, active, planes);
    }
    crate::amdgpu_navi48_platform::display_admits_planes(
        display,
        connector,
        mode,
        planes.primary_format,
        &planes.setup,
    )
    .map_err(|_| PLANES_REFUSED)
}
/// Whether the HDMI output format search ([`output_formats_supported`])
/// also admits the output's planes, so a CRTC driving HDMI needs no
/// separate [`display_admits_planes`]. Navi48's search plans the planes
/// with each candidate format; Navi22's validates the stream alone.
pub fn output_search_admits_planes() -> bool {
    !navi22()
}
/// DC's validation of a positioned or scaled primary of an `fb` (pitch in
/// bytes, width, height) on a CRTC of `mode` (Navi22's lit stream; other
/// cards validate their planes elsewhere).
pub fn primary_placement_admitted(
    fb: (u32, u32, u32),
    mode: (u32, u32),
    src: (u32, u32, u32, u32),
    dst: (i32, i32, u32, u32),
) -> bool {
    !navi22() || crate::amdgpu_navi22_platform::placement_admitted(fb, mode, src, dst)
}
/// Present an atomic commit's planes on display `display`. Navi22 shows
/// its primary (with the frame's placement); an overlay frame is never
/// admitted there ([`display_admits_planes`]), and one that arrives
/// anyway completes its event without being shown.
pub fn present_planes(
    display: u8,
    primary: Option<crate::amdgpu_navi48_platform::PlaneFrame>,
    overlays: [Option<crate::amdgpu_navi48_platform::PlaneFrame>;
        crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
    ticket: Option<u64>,
) -> bool {
    if navi22() {
        if overlays.iter().any(Option::is_some) {
            crate::drm::card::complete_flip_ticket(display, ticket);
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
/// A CRTC's committed CTM, GAMMA_LUT and DEGAMMA_LUT blob bytes (None: the
/// property is clear), as DRM hands amdgpu_dm a color_mgmt_changed CRTC
/// state. Navi48 leaves `degamma_lut` None: DCN 4.0.1 publishes no
/// DEGAMMA_LUT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrtcColorRequest {
    pub ctm: Option<alloc::vec::Vec<u8>>,
    pub gamma_lut: Option<alloc::vec::Vec<u8>>,
    pub degamma_lut: Option<alloc::vec::Vec<u8>>,
}
/// A connector's committed "Colorspace" and HDR_OUTPUT_METADATA bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorColorRequest {
    pub connector: u32,
    pub color_format: crate::amdgpu_hdr::ColorFormat,
    pub colorspace: u32,
    pub hdr_output_metadata: Option<alloc::vec::Vec<u8>>,
}
/// CRTC CTM / GAMMA_LUT / DEGAMMA_LUT: Navi48 attaches CTM and GAMMA_LUT,
/// Navi22 all three.
pub fn request_crtc_color(display: u8, request: CrtcColorRequest) {
    if navi22() {
        crate::amdgpu_navi22_kms::request_crtc_color(display, request)
    } else {
        crate::amdgpu_navi48_platform::request_crtc_color(display, request)
    }
}
/// Connector Colorspace / HDR_OUTPUT_METADATA on native HDMI outputs.
pub fn request_connector_color(request: ConnectorColorRequest) {
    if navi22() {
        crate::amdgpu_navi22_kms::request_connector_color(request)
    } else {
        crate::amdgpu_navi48_platform::request_connector_color(request)
    }
}
/// Connector "max bpc" (max_requested_bpc).
pub fn request_connector_max_bpc(connector: u32, bpc: u8) {
    if navi22() {
        crate::amdgpu_navi22_kms::request_connector_max_bpc(connector, bpc)
    } else {
        crate::amdgpu_navi48_platform::request_connector_max_bpc(connector, bpc)
    }
}
/// Whether connector `connector`'s stream can signal `colorspace` and, with
/// `hdr`, HDR metadata (including Navi22's native HDMI connectors).
pub fn connector_color_supported(connector: u32, colorspace: u32, hdr: bool) -> bool {
    if navi22() {
        crate::amdgpu_navi22_kms::connector_color_supported(connector, colorspace, hdr)
    } else {
        crate::amdgpu_navi48_platform::connector_color_supported(connector, colorspace, hdr)
    }
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
    if requests.is_empty() {
        return true;
    }
    if navi22() {
        crate::amdgpu_navi22_kms::output_formats_supported(requests, routes)
    } else {
        crate::amdgpu_navi48_platform::output_formats_supported(requests, routes)
    }
}
/// Whether an HDR_OUTPUT_METADATA blob builds an HDR infoframe
/// (amdgpu_dm_fill_hdr_info_packet succeeds).
pub fn hdr_metadata_valid(blob: &[u8]) -> bool {
    crate::amdgpu_hdr::HdrOutputMetadata::from_blob(blob).is_ok()
}
/// A DRM cursor plane commit on display `display`: its image at CRTC_X/Y,
/// or off, on the display's hardware cursor.
pub fn request_display_cursor(
    display: u8,
    image: Option<crate::amdgpu_navi48_platform::CursorContent>,
    position: (i32, i32),
) -> bool {
    if navi22() {
        crate::amdgpu_navi22_platform::request_display_cursor(display, image, position)
    } else {
        crate::amdgpu_navi48_platform::request_display_cursor_content(display, image, position)
    }
}
