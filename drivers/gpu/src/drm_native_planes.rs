//! The native Navi48 card's planes as amdgpu_dm exposes them on DCN 4.0.1
//! (amdgpu_dm_initialize_drm_device, amdgpu_dm_plane_init): one primary
//! per CRTC and DCN401's three overlay planes (max_slave_planes), each
//! with "pixel blend mode" (None, Pre-multiplied, Coverage), "zpos" (the
//! primary's immutable at 3, an overlay's 0..254 defaulting to
//! 3 + 1 + its DRM plane index) and "rotation" (rotate-0/90/180/270), the
//! overlays also with "alpha". The atomic checks are amdgpu_dm's:
//! drm_atomic_plane_check's CRTC switching and format rules,
//! amdgpu_dm_plane_helper_check_state (the 24x12 viewport minimum and
//! drm_atomic_helper_check_plane_state's scale limits from the DCN401
//! plane caps: 16x up, 6:1 down), amdgpu_dm_plane_fill_dc_scaling_info,
//! dm_crtc_helper_atomic_check's primary requirement, DML21's refusal of a
//! linear surface rotated 90/270 (tiled ones scan vertically), then
//! drm_atomic_normalize_zpos and DML21 admission of the whole configuration
//! (dc_validate_global_state) with a free pipe for every overlay. A plane
//! configuration change relights the display (DC's full update); a commit
//! that only changes framebuffers flips every changed plane at one VUPDATE.
//!
//! Each CRTC also has its DRM_PLANE_TYPE_CURSOR plane (amdgpu_dm_crtc_init:
//! possible on that CRTC only, ARGB8888 with LINEAR, "pixel blend mode"
//! Pre-multiplied alone, immutable "zpos" 255, no rotation). It never goes
//! to DC as a plane: amdgpu_dm_check_native_cursor_state (dm_check_cursor_fb)
//! and amdgpu_dm_atomic_check's DCN4 no-scaling rule check it, and a commit
//! programs the CRTC's hardware cursor on every pipe of its stream
//! (amdgpu_dm_commit_cursors, a FAST update: nothing relights).
use crate::amdgpu_dcn401_otg::{Blend, SurfaceFormat, Swizzle, MAX_OVERLAYS};
use crate::amdgpu_dcn401_spl::{Rect, Rotation};
use crate::amdgpu_navi48_boot::{OverlayPlane, PlaneGeometry, PlaneSetup};
use crate::drm::atomic::{AtomicState, PlaneState};
use crate::drm::card::{Card, NativePlane, PlaneProps};
use alloc::vec::Vec;
use narf_filesystem::FsError;

/// The primaries are planes 0x40 + n (the bridge's synthesized ids).
pub const PRIMARY_PLANE_ID_BASE: u32 = 0x40;
/// The overlays follow the four primaries amdgpu_dm registers.
pub const OVERLAY_PLANE_ID_BASE: u32 = 0x44;
/// The cursor planes follow the overlays, one per CRTC in index order (as
/// amdgpu_dm_crtc_init creates each CRTC's after every primary and overlay).
pub const CURSOR_PLANE_ID_BASE: u32 = OVERLAY_PLANE_ID_BASE + MAX_OVERLAYS as u32;
/// amdgpu_dm_plane.c's cursor_formats.
pub const CURSOR_FORMATS: [u32; 1] = [crate::amdgpu_dcn401_otg::SurfaceFormat::Argb8888.fourcc()];
/// dc caps' max_cursor_size on DCN 4.0.1 (dcn401_resource.c), amdgpu_crtc's
/// max_cursor_width and max_cursor_height.
pub const MAX_CURSOR_SIZE: u32 = crate::amdgpu_dcn401_otg::CURSOR_MAX;
/// The cursor plane's immutable zpos (drm_plane_create_zpos_immutable_property).
pub const CURSOR_ZPOS: u8 = 255;
/// The primary's immutable zpos: the number of overlay planes.
pub const PRIMARY_ZPOS: u8 = MAX_OVERLAYS as u8;
/// amdgpu_dm registers dc caps' max_streams (4) primaries first.
const PRIMARY_PLANES: u8 = 4;

/// Plane property ids (a separate id space from objects).
pub const ALPHA_PROP_ID: u32 = 0x69;
pub const BLEND_PROP_ID: u32 = 0x6a;
pub const PRIMARY_ZPOS_PROP_ID: u32 = 0x6b;
pub const ZPOS_PROP_ID: u32 = 0x6c;
pub const ROTATION_PROP_ID: u32 = 0x6d;
/// "IN_FORMATS" (drm_plane_create_format_property / create_in_format_blob):
/// an immutable blob of the plane's formats and modifiers.
pub const IN_FORMATS_PROP_ID: u32 = 0x6e;
/// "IN_FORMATS_ASYNC": the same blob for async flips (amdgpu_dm sets
/// format_mod_supported_async to the same check).
pub const IN_FORMATS_ASYNC_PROP_ID: u32 = 0x6f;
/// "COLOR_ENCODING" and "COLOR_RANGE" (drm_plane_create_color_properties),
/// on planes that scan NV12/P010.
pub const COLOR_ENCODING_PROP_ID: u32 = 0x70;
pub const COLOR_RANGE_PROP_ID: u32 = 0x71;
/// A cursor plane's "zpos" (immutable, 255) and "pixel blend mode"
/// (Pre-multiplied only): drm_plane_create_*_property make each plane its
/// own property, and these differ from the other planes'.
pub const CURSOR_ZPOS_PROP_ID: u32 = 0x72;
pub const CURSOR_BLEND_PROP_ID: u32 = 0x73;
/// Stable IN_FORMATS (and IN_FORMATS_ASYNC) blob ids, one per plane,
/// regenerated on GETPROPBLOB.
const IN_FORMATS_BLOB: u32 = 0x2000;
const IN_FORMATS_ASYNC_BLOB: u32 = 0x3000;
pub fn in_formats_blob_id(plane_id: u32) -> u32 {
    IN_FORMATS_BLOB | (plane_id & 0xfff)
}
pub fn in_formats_async_blob_id(plane_id: u32) -> u32 {
    IN_FORMATS_ASYNC_BLOB | (plane_id & 0xfff)
}
/// drm_color_mgmt.c's color_encoding_name / color_range_name for the
/// encodings and ranges amdgpu_dm supports.
pub const COLOR_ENCODING_ENUMS: [(u64, &[u8]); 3] = [
    (PlaneProps::BT601 as u64, b"ITU-R BT.601 YCbCr"),
    (PlaneProps::BT709 as u64, b"ITU-R BT.709 YCbCr"),
    (PlaneProps::BT2020 as u64, b"ITU-R BT.2020 YCbCr"),
];
pub const COLOR_RANGE_ENUMS: [(u64, &[u8]); 2] = [
    (PlaneProps::LIMITED as u64, b"YCbCr limited range"),
    (PlaneProps::FULL as u64, b"YCbCr full range"),
];
/// The formats plane `id` lists: a primary's `plane_formats`, an overlay's
/// `overlay_formats`, a cursor's `CURSOR_FORMATS`.
fn formats_of(card: &Card, id: u32) -> Option<&'static [u32]> {
    let p = card.native_plane(id)?;
    if p.is_cursor() {
        Some(&CURSOR_FORMATS)
    } else if p.primary_of.is_some() {
        card.plane_formats
    } else {
        card.overlay_formats
    }
}
/// Whether plane `id` lists a YCbCr format, so carries "COLOR_ENCODING" and
/// "COLOR_RANGE" (amdgpu_dm attaches them when the plane caps take NV12 or
/// P010).
fn has_yuv(card: &Card, id: u32) -> bool {
    use crate::amdgpu_dm_modifiers::{NV12, P010};
    formats_of(card, id).is_some_and(|f| f.contains(&NV12) || f.contains(&P010))
}
/// `drm_format_modifier_blob` for a native plane (its IN_FORMATS or
/// IN_FORMATS_ASYNC blob): every format the plane lists with each modifier
/// it lists and the formats that take it (create_in_format_blob). The
/// native amdgpu card lists `amdgpu_dm_modifiers::PLANE_MODIFIERS`; its
/// cursor planes (amdgpu_dm_plane_get_plane_modifiers for
/// DRM_PLANE_TYPE_CURSOR) and any other card with native planes only
/// DRM_FORMAT_MOD_LINEAR.
pub fn in_formats_blob(card: &Card, blob_id: u32) -> Option<Vec<u8>> {
    if blob_id & !0xfff != IN_FORMATS_BLOB && blob_id & !0xfff != IN_FORMATS_ASYNC_BLOB {
        return None;
    }
    let plane = blob_id & 0xfff;
    let formats = formats_of(card, plane)?;
    if card.gfx12_modifiers && !card.native_plane(plane).is_some_and(NativePlane::is_cursor) {
        return crate::amdgpu_dm_modifiers::in_formats_blob(formats);
    }
    let n = formats.len();
    if n == 0 || n > 64 {
        return None;
    }
    let formats_offset = 24u32;
    let modifiers_offset = (formats_offset + 4 * n as u32 + 7) & !7;
    let mut out = Vec::with_capacity(modifiers_offset as usize + 24);
    for word in [1, 0, n as u32, formats_offset, 1, modifiers_offset] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for &f in formats {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out.resize(modifiers_offset as usize, 0);
    // struct drm_format_modifier { u64 formats; u32 offset; u32 pad; u64 modifier }
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    out.extend_from_slice(&mask.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    Some(out)
}

/// drm_plane_create_blend_mode_property's entries.
pub const BLEND_ENUMS: [(u64, &[u8]); 3] = [
    (PlaneProps::PIXEL_NONE as u64, b"None"),
    (PlaneProps::PREMULTI as u64, b"Pre-multiplied"),
    (PlaneProps::COVERAGE as u64, b"Coverage"),
];
/// The cursor plane's blend mode property: amdgpu_dm_plane_init gives it
/// BIT(DRM_MODE_BLEND_PREMULTI) alone (DC blends the cursor
/// CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA).
pub const CURSOR_BLEND_ENUMS: [(u64, &[u8]); 1] =
    [(PlaneProps::PREMULTI as u64, b"Pre-multiplied")];
/// drm_plane_create_rotation_property's bits for ROTATE_0/90/180/270.
pub const ROTATION_ENUMS: [(u64, &[u8]); 4] = [
    (0, b"rotate-0"),
    (1, b"rotate-90"),
    (2, b"rotate-180"),
    (3, b"rotate-270"),
];

/// DCN401's plane caps (dcn401_resource.c): 16000 (16x) up, 167 (6:1)
/// down, the same for every format.
const MAX_UPSCALE: i64 = 16000;
const MIN_DOWNSCALE: i64 = 167;
/// MIN_VIEWPORT_SIZE.
const MIN_VIEWPORT: i64 = 12;

/// Overlay `k`'s default zpos: amdgpu_dm's primary_zpos + 1 +
/// drm_plane_index, the overlays indexed after the four primaries.
pub const fn overlay_zpos(k: usize) -> u8 {
    PRIMARY_ZPOS + 1 + PRIMARY_PLANES + k as u8
}

/// The card's planes for its CRTCs `crtcs` (in index order): each CRTC's
/// primary, the overlays and each CRTC's cursor plane, keeping the
/// committed state of every plane that remains.
pub fn planes_for(old: &[NativePlane], crtcs: &[u32]) -> Vec<NativePlane> {
    let keep =
        |id: u32, fresh: NativePlane| old.iter().copied().find(|p| p.id == id).unwrap_or(fresh);
    let blank = |id, primary_of, zpos| NativePlane {
        id,
        primary_of,
        cursor_of: None,
        crtc_id: None,
        fb_id: None,
        src: (0, 0, 0, 0),
        dst: (0, 0, 0, 0),
        placed: false,
        props: PlaneProps::new(zpos),
        internal_fb: false,
        legacy_position: (0, 0),
    };
    let mut out: Vec<NativePlane> = crtcs
        .iter()
        .enumerate()
        .map(|(k, &crtc)| {
            let id = PRIMARY_PLANE_ID_BASE + k as u32;
            let mut p = keep(id, blank(id, Some(crtc), PRIMARY_ZPOS));
            p.primary_of = Some(crtc);
            p
        })
        .collect();
    for k in 0..MAX_OVERLAYS {
        let id = OVERLAY_PLANE_ID_BASE + k as u32;
        let mut p = keep(id, blank(id, None, overlay_zpos(k)));
        // An overlay on a CRTC that is gone is disabled.
        if p.crtc_id.is_some_and(|c| !crtcs.contains(&c)) {
            p.crtc_id = None;
            p.fb_id = None;
        }
        out.push(p);
    }
    for (k, &crtc) in crtcs.iter().enumerate() {
        let id = CURSOR_PLANE_ID_BASE + k as u32;
        let mut p = keep(
            id,
            NativePlane {
                cursor_of: Some(crtc),
                ..blank(id, None, CURSOR_ZPOS)
            },
        );
        // A cursor left on another CRTC id at this index is disabled.
        if p.cursor_of != Some(crtc) || p.crtc_id.is_some_and(|c| c != crtc) {
            p.crtc_id = None;
            p.fb_id = None;
            p.internal_fb = false;
        }
        p.cursor_of = Some(crtc);
        out.push(p);
    }
    out
}

/// The overlay plane ids of `card`.
pub fn overlay_ids(card: &Card) -> Vec<u32> {
    card.native_planes
        .iter()
        .filter(|p| p.is_overlay())
        .map(|p| p.id)
        .collect()
}

/// The cursor plane ids of `card`, in CRTC index order.
pub fn cursor_ids(card: &Card) -> Vec<u32> {
    card.native_planes
        .iter()
        .filter(|p| p.is_cursor())
        .map(|p| p.id)
        .collect()
}

/// CRTC `crtc_id`'s cursor plane on `card` (drm_crtc's cursor).
pub fn cursor_of(card: &Card, crtc_id: u32) -> Option<&NativePlane> {
    card.native_planes
        .iter()
        .find(|p| p.cursor_of == Some(crtc_id))
}

/// Plane `id`'s current state as an atomic request starts from it
/// (drm_atomic_get_plane_state): a primary's CRTC and framebuffer are its
/// CRTC's, and an unplaced primary shows the framebuffer at the mode.
pub fn plane_state(card: &Card, id: u32) -> Option<PlaneState> {
    let p = card.native_plane(id)?;
    let (crtc_id, fb_id, src, dst) = match p.primary_of {
        Some(c) => {
            let crtc = card.crtc(c).ok()?;
            let fb = crtc.primary_fb;
            let (src, dst) = if p.placed {
                (p.src, p.dst)
            } else {
                // drm_atomic_helper_set_config: the mode's size, at the
                // CRTC's framebuffer offset.
                let f = fb.and_then(|id| card.framebuffer(id).ok());
                let w = crtc
                    .mode
                    .map(|m| m.width)
                    .or(f.map(|f| f.width))
                    .unwrap_or(0);
                let h = crtc
                    .mode
                    .map(|m| m.height)
                    .or(f.map(|f| f.height))
                    .unwrap_or(0);
                ((crtc.x, crtc.y, w, h), (0, 0, w, h))
            };
            (fb.map(|_| c), fb, src, dst)
        }
        None => (p.crtc_id, p.fb_id, p.src, p.dst),
    };
    Some(PlaneState {
        id,
        crtc_id,
        fb_id,
        crtc_x: dst.0,
        crtc_y: dst.1,
        crtc_w: dst.2,
        crtc_h: dst.3,
        src_x: src.0,
        src_y: src.1,
        src_w: src.2,
        src_h: src.3,
        in_fence_fd: None,
        props: Some(p.props),
    })
}

/// Apply one of the native properties to `plane`'s requested state, as
/// drm_atomic_plane_set_property with drm_property_change_valid_get's
/// range/enum/bitmask and immutability checks. Ok(false) for a property
/// that is not one of these.
pub fn set_property(
    card: &Card,
    plane: &mut PlaneState,
    prop: u32,
    value: u64,
) -> Result<bool, FsError> {
    let Some(p) = card.native_plane(plane.id) else {
        return Ok(false);
    };
    let props_of = p.props;
    if p.is_cursor() {
        // The cursor's own "pixel blend mode" and immutable "zpos".
        let props = plane.props.get_or_insert(props_of);
        match prop {
            CURSOR_BLEND_PROP_ID => {
                if !CURSOR_BLEND_ENUMS.iter().any(|&(v, _)| v == value) {
                    return Err(FsError::InvalidData);
                }
                props.blend = value as u8;
            }
            CURSOR_ZPOS_PROP_ID => return Err(FsError::InvalidData),
            _ => return Ok(false),
        }
        return Ok(true);
    }
    let overlay = p.primary_of.is_none();
    let yuv = has_yuv(card, plane.id);
    let props = plane.props.get_or_insert(props_of);
    match prop {
        ALPHA_PROP_ID if overlay => {
            props.alpha = u16::try_from(value).map_err(|_| FsError::InvalidData)?;
        }
        BLEND_PROP_ID => {
            if !BLEND_ENUMS.iter().any(|&(v, _)| v == value) {
                return Err(FsError::InvalidData);
            }
            props.blend = value as u8;
        }
        ZPOS_PROP_ID if overlay => {
            if value > 254 {
                return Err(FsError::InvalidData);
            }
            props.zpos = value as u8;
        }
        // The primary's zpos is immutable: never settable.
        PRIMARY_ZPOS_PROP_ID if !overlay => return Err(FsError::InvalidData),
        ROTATION_PROP_ID => {
            // The bitmask's valid bits, then exactly one rotation
            // (drm_atomic_plane_set_property).
            if value & !0xf != 0 || !(value & 0xf).is_power_of_two() {
                return Err(FsError::InvalidData);
            }
            props.rotation = value as u8;
        }
        COLOR_ENCODING_PROP_ID if yuv => {
            if !COLOR_ENCODING_ENUMS.iter().any(|&(v, _)| v == value) {
                return Err(FsError::InvalidData);
            }
            props.color_encoding = value as u8;
        }
        COLOR_RANGE_PROP_ID if yuv => {
            if !COLOR_RANGE_ENUMS.iter().any(|&(v, _)| v == value) {
                return Err(FsError::InvalidData);
            }
            props.color_range = value as u8;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Plane `id`'s properties and values as OBJ_GETPROPERTIES lists them
/// after the core plane properties.
pub fn object_properties(card: &Card, id: u32) -> Option<(Vec<u32>, Vec<u64>)> {
    let p = card.native_plane(id)?;
    let props = p.props;
    let mut ids = Vec::new();
    let mut values = Vec::new();
    if p.is_cursor() {
        // amdgpu_dm_plane_init for DRM_PLANE_TYPE_CURSOR: the blend mode and
        // immutable zpos only (no rotation, no color properties), then
        // IN_FORMATS (and, as the other planes, IN_FORMATS_ASYNC) of
        // ARGB8888 with LINEAR.
        ids.extend([
            CURSOR_BLEND_PROP_ID,
            CURSOR_ZPOS_PROP_ID,
            IN_FORMATS_PROP_ID,
        ]);
        values.extend([
            u64::from(props.blend),
            u64::from(CURSOR_ZPOS),
            u64::from(in_formats_blob_id(id)),
        ]);
        if card.gfx12_modifiers {
            ids.push(IN_FORMATS_ASYNC_PROP_ID);
            values.push(u64::from(in_formats_async_blob_id(id)));
        }
        return Some((ids, values));
    }
    if p.primary_of.is_none() {
        ids.push(ALPHA_PROP_ID);
        values.push(u64::from(props.alpha));
    }
    ids.extend([BLEND_PROP_ID]);
    values.push(u64::from(props.blend));
    if p.primary_of.is_none() {
        ids.push(ZPOS_PROP_ID);
    } else {
        ids.push(PRIMARY_ZPOS_PROP_ID);
    }
    values.push(u64::from(props.zpos));
    if has_yuv(card, id) {
        ids.extend([COLOR_ENCODING_PROP_ID, COLOR_RANGE_PROP_ID]);
        values.extend([
            u64::from(props.color_encoding),
            u64::from(props.color_range),
        ]);
    }
    ids.push(ROTATION_PROP_ID);
    values.push(u64::from(props.rotation));
    if formats_of(card, id).is_some() {
        ids.push(IN_FORMATS_PROP_ID);
        values.push(u64::from(in_formats_blob_id(id)));
        if card.gfx12_modifiers {
            ids.push(IN_FORMATS_ASYNC_PROP_ID);
            values.push(u64::from(in_formats_async_blob_id(id)));
        }
    }
    Some((ids, values))
}

/// What a native plane property's GETPROPERTY reports: its name, flags
/// and, for a range, its bounds.
pub fn range_property(prop: u32) -> Option<(&'static [u8], bool, [u64; 2])> {
    match prop {
        ALPHA_PROP_ID => Some((b"alpha", false, [0, 0xffff])),
        ZPOS_PROP_ID => Some((b"zpos", false, [0, 254])),
        PRIMARY_ZPOS_PROP_ID => Some((
            b"zpos",
            true,
            [u64::from(PRIMARY_ZPOS), u64::from(PRIMARY_ZPOS)],
        )),
        CURSOR_ZPOS_PROP_ID => Some((
            b"zpos",
            true,
            [u64::from(CURSOR_ZPOS), u64::from(CURSOR_ZPOS)],
        )),
        _ => None,
    }
}

/// amdgpu_dm_plane_fill_blending_from_plane_state for a plane in `format`.
pub fn blend(format: SurfaceFormat, props: PlaneProps, overlay: bool) -> Blend {
    let per_pixel = props.blend != PlaneProps::PIXEL_NONE && format.per_pixel_alpha();
    Blend {
        per_pixel_alpha: per_pixel,
        premultiplied: !(per_pixel && props.blend == PlaneProps::COVERAGE),
        // Only an overlay has "alpha"; a primary stays opaque.
        global_alpha: (overlay && props.alpha < 0xffff).then_some((props.alpha >> 8) as u8),
    }
}

/// A framebuffer's surface as DC programs it: the tiling and DCC of its
/// modifier (amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers) and, for a
/// YCbCr format, the color space of the plane's COLOR_ENCODING and
/// COLOR_RANGE (fill_plane_color_attributes).
pub fn plane_surface(
    fb: &crate::drm::card::Framebuffer,
    props: PlaneProps,
) -> Result<crate::amdgpu_dcn401_otg::PlaneSurface, FsError> {
    use crate::amdgpu_dcn401_otg::{PlaneSurface, Tiling, YuvColor};
    let yuv = matches!(
        fb.format,
        crate::drm::card::PixelFormat::Nv12 | crate::drm::card::PixelFormat::P010
    );
    Ok(PlaneSurface {
        tiling: Tiling::from_modifier(fb.modifier).ok_or(FsError::InvalidData)?,
        // The DRM color properties only affect YCbCr formats.
        color: if yuv {
            YuvColor::from_props(props.color_encoding, props.color_range)
                .ok_or(FsError::InvalidData)?
        } else {
            YuvColor::default()
        },
    })
}

/// The rotation of a DRM_MODE_ROTATE_* bit.
fn rotation(bits: u8) -> Rotation {
    match bits & 0xf {
        2 => Rotation::R90,
        4 => Rotation::R180,
        8 => Rotation::R270,
        _ => Rotation::R0,
    }
}

/// drm_calc_scale: src (16.16) over dst, rounded up when downscaling.
fn calc_scale(src: i64, dst: i64) -> i64 {
    if dst == 0 {
        0
    } else if src > dst << 16 {
        (src + dst - 1) / dst
    } else {
        src / dst
    }
}

/// amdgpu_dm_plane_helper_check_state, drm_atomic_helper_check_plane_state
/// (can_position, can_update_disabled) and
/// amdgpu_dm_plane_fill_dc_scaling_info for an enabled plane on a CRTC of
/// `mode` (width, height). A 90/270 rotation swaps the source's sides for
/// the helper's scale limits (drm_rect_rotate) but not for
/// fill_dc_scaling_info's, which takes SRC_W/SRC_H as they are.
pub fn check_plane(p: &PlaneState, mode: (u32, u32)) -> Result<(), FsError> {
    let (x, y, w, h) = (
        i64::from(p.crtc_x),
        i64::from(p.crtc_y),
        i64::from(p.crtc_w),
        i64::from(p.crtc_h),
    );
    let (mw, mh) = (i64::from(mode.0), i64::from(mode.1));
    let mut vw = w;
    let mut vh = h;
    if x < 0 {
        vw += x;
    } else if x + w > mw {
        vw = mw - x;
    }
    if y < 0 {
        vh += y;
    } else if y + h > mh {
        vh = mh - y;
    }
    if vw < 0 || vh < 0 || vw < MIN_VIEWPORT * 2 || vh < MIN_VIEWPORT {
        return Err(FsError::InvalidData);
    }
    // drm_rect_calc_hscale/vscale in DRM's 16.16 src/dst convention:
    // min_scale = 1.0 / max_upscale, max_scale = 1.0 / min_downscale.
    let min_scale = (1000 << 16) / MAX_UPSCALE;
    let max_scale = (1000 << 16) / MIN_DOWNSCALE;
    let (sw, sh) = if rotation(p.props.map_or(1, |r| r.rotation)).orthogonal() {
        (i64::from(p.src_h), i64::from(p.src_w))
    } else {
        (i64::from(p.src_w), i64::from(p.src_h))
    };
    // Linux's helper fails these with -ERANGE; FsError has no ERANGE, so
    // the refusal is EINVAL here as for every other plane check.
    for (src, dst) in [(sw << 16, w), (sh << 16, h)] {
        let scale = calc_scale(src, dst);
        if dst != 0 && !(min_scale..=max_scale).contains(&scale) {
            return Err(FsError::InvalidData);
        }
    }
    // amdgpu_dm_plane_fill_dc_scaling_info (DC's dst/src, 1000 == 1.0).
    if p.src_w == 0 || p.src_h == 0 || p.crtc_w == 0 || p.crtc_h == 0 {
        return Err(FsError::InvalidData);
    }
    let scale_w = w * 1000 / i64::from(p.src_w);
    let scale_h = h * 1000 / i64::from(p.src_h);
    if !(MIN_DOWNSCALE..=MAX_UPSCALE).contains(&scale_w)
        || !(MIN_DOWNSCALE..=MAX_UPSCALE).contains(&scale_h)
    {
        return Err(FsError::InvalidData);
    }
    Ok(())
}

/// One display's planes after a commit, as DC takes them: the plane
/// setup (`PlaneSetup::NONE` for the full-frame unscaled primary alone),
/// the primary's fourcc, and the overlay plane ids in the setup's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayPlanes {
    pub crtc_id: u32,
    pub setup: PlaneSetup,
    pub primary_format: u32,
    pub overlays: [Option<u32>; MAX_OVERLAYS],
}

/// Plane `id` as the request leaves it: its requested state, else its
/// committed one.
fn final_state(card: &Card, state: &AtomicState, id: u32) -> Option<PlaneState> {
    state
        .planes
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .or_else(|| plane_state(card, id))
}

/// amdgpu_dm's checks of every native plane in `state` and every CRTC the
/// request touches (the CRTCs of its planes, old and new, and its CRTCs),
/// with `mode_of` giving each CRTC's mode after the commit. Returns each
/// enabled touched CRTC's planes.
pub fn check(
    card: &Card,
    state: &AtomicState,
    mode_of: impl Fn(u32) -> Option<crate::Mode>,
) -> Result<Vec<DisplayPlanes>, FsError> {
    let mut crtcs: Vec<u32> = state.crtcs.iter().map(|c| c.id).collect();
    // The CRTCs only a cursor plane brings in.
    let mut cursor_crtcs: Vec<u32> = Vec::new();
    for p in &state.planes {
        let Some(native) = card.native_plane(p.id) else {
            continue;
        };
        let old = plane_state(card, p.id).and_then(|s| s.crtc_id);
        // drm_atomic_plane_check: no direct move between CRTCs, and a
        // primary only on its own CRTC.
        if old.is_some() && p.crtc_id.is_some() && old != p.crtc_id {
            return Err(FsError::InvalidData);
        }
        if native.primary_of.is_some() && p.crtc_id.is_some() && p.crtc_id != native.primary_of {
            return Err(FsError::InvalidData);
        }
        if native.is_cursor() {
            check_cursor_plane(card, native, p)?;
            cursor_crtcs.extend(old.into_iter().chain(p.crtc_id));
            continue;
        }
        if let Some(fb) = p.fb_id {
            let format = card.framebuffer(fb).map_err(|_| FsError::NotFound)?.format as u32;
            let formats: &[u32] = if native.primary_of.is_some() {
                card.plane_formats.unwrap_or(&[])
            } else {
                card.overlay_formats.unwrap_or(&[])
            };
            if !formats.contains(&format) {
                return Err(FsError::InvalidData);
            }
        }
        crtcs.extend(old.into_iter().chain(p.crtc_id));
    }
    crtcs.sort_unstable();
    crtcs.dedup();
    // A CRTC a cursor plane brings in gets dm_crtc_helper_atomic_check
    // (its primary whenever it is enabled), and DC no planes: a cursor
    // update is FAST.
    for crtc_id in cursor_crtcs {
        if crtcs.contains(&crtc_id) {
            continue;
        }
        let Ok(crtc) = card.crtc(crtc_id) else {
            continue;
        };
        let enabled = state
            .crtcs
            .iter()
            .find(|c| c.id == crtc_id)
            .map_or(crtc.enabled, |c| c.enable);
        let primary = card
            .native_planes
            .iter()
            .find(|p| p.primary_of == Some(crtc_id))
            .and_then(|p| final_state(card, state, p.id));
        if enabled && primary.is_none_or(|p| p.fb_id.is_none()) {
            return Err(FsError::InvalidData);
        }
    }
    let mut out = Vec::new();
    for crtc_id in crtcs {
        let Ok(crtc) = card.crtc(crtc_id) else {
            continue;
        };
        let enabled = state
            .crtcs
            .iter()
            .find(|c| c.id == crtc_id)
            .map_or(crtc.enabled, |c| c.enable);
        let primary_id = card
            .native_planes
            .iter()
            .find(|p| p.primary_of == Some(crtc_id))
            .map(|p| p.id);
        let primary = primary_id.and_then(|id| final_state(card, state, id));
        let overlays: Vec<PlaneState> = overlay_ids(card)
            .into_iter()
            .filter_map(|id| final_state(card, state, id))
            .filter(|p| p.crtc_id == Some(crtc_id) && p.fb_id.is_some())
            .collect();
        let primary = primary.filter(|p| p.fb_id.is_some());
        if !enabled {
            // amdgpu_dm leaves a disabled CRTC's planes out of DC (it adds
            // none for a CRTC that is not enabled); nothing to check.
            continue;
        }
        // dm_crtc_helper_atomic_check: an enabled CRTC needs its primary.
        let Some(primary) = primary else {
            return Err(FsError::InvalidData);
        };
        let mode = mode_of(crtc_id).ok_or(FsError::InvalidData)?;
        for p in core::iter::once(&primary).chain(&overlays) {
            check_plane(p, (mode.width, mode.height))?;
        }
        out.push(display_planes(
            card,
            crtc_id,
            &primary,
            &overlays,
            (mode.width, mode.height),
        )?);
    }
    Ok(out)
}

/// A cursor plane's framebuffer as dm_check_cursor_fb reads it: its size,
/// byte pitch and whether it is linear (its modifier LINEAR, or no
/// GFX12_SWIZZLE_MODE in the BO's tiling flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorFb {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub linear: bool,
}

/// amdgpu_dm_check_native_cursor_state with dm_check_cursor_fb for an
/// enabled cursor plane (`src` its SRC_X/Y/W/H in 16.16, `crtc` its
/// CRTC_W/H), then amdgpu_dm_atomic_check's DCN 4.x refusal of a scaled
/// cursor: no cropping (the source at 0,0 and the whole framebuffer), at
/// most max_cursor_size square, a pitch of exactly its width in 64, 128 or
/// 256 pixels, linear, and shown at its own size. All EINVAL.
pub fn check_cursor(
    fb: CursorFb,
    src: (u32, u32, u32, u32),
    crtc: (u32, u32),
) -> Result<(), FsError> {
    let (src_x, src_y, src_w, src_h) = src;
    if src_x != 0 || src_y != 0 {
        return Err(FsError::InvalidData);
    }
    if fb.width > MAX_CURSOR_SIZE || fb.height > MAX_CURSOR_SIZE {
        return Err(FsError::InvalidData);
    }
    if u64::from(src_w) != u64::from(fb.width) << 16
        || u64::from(src_h) != u64::from(fb.height) << 16
    {
        return Err(FsError::InvalidData);
    }
    // Pitch in pixels (ARGB8888's cpp is 4).
    let pitch = fb.pitch / 4;
    if fb.width != pitch || !matches!(pitch, 64 | 128 | 256) {
        return Err(FsError::InvalidData);
    }
    if !fb.linear {
        return Err(FsError::InvalidData);
    }
    if src_w >> 16 != crtc.0 || src_h >> 16 != crtc.1 {
        return Err(FsError::InvalidData);
    }
    Ok(())
}

/// drm_atomic_plane_check for a cursor plane `p` (its CRTC, the only one in
/// its possible_crtcs, and ARGB8888 with LINEAR), then `check_cursor` when
/// it is enabled. The source here is in whole pixels: the bridge refuses a
/// fractional SRC_* on an enabled cursor (`check_cursor` with the 16.16
/// values would).
fn check_cursor_plane(card: &Card, native: &NativePlane, p: &PlaneState) -> Result<(), FsError> {
    if p.crtc_id.is_some() && p.crtc_id != native.cursor_of {
        return Err(FsError::InvalidData);
    }
    let (Some(_), Some(fb_id)) = (p.crtc_id, p.fb_id) else {
        return Ok(());
    };
    let fb = card.framebuffer(fb_id).map_err(|_| FsError::NotFound)?;
    let linear = fb.modifier == crate::amdgpu_dm_modifiers::LINEAR;
    if !CURSOR_FORMATS.contains(&(fb.format as u32)) || !linear {
        return Err(FsError::InvalidData);
    }
    let fb = CursorFb {
        width: fb.width,
        height: fb.height,
        pitch: fb.pitch,
        linear,
    };
    let src = |v: u32| {
        v.checked_shl(16)
            .filter(|s| s >> 16 == v)
            .unwrap_or(u32::MAX)
    };
    check_cursor(
        fb,
        (src(p.src_x), src(p.src_y), src(p.src_w), src(p.src_h)),
        (p.crtc_w, p.crtc_h),
    )
}

/// What a commit does to one CRTC's hardware cursor, as
/// amdgpu_dm_plane_handle_cursor_update takes a cursor plane's old and new
/// state: the CRTC (the new one, else the one it leaves), the framebuffer
/// it shows (None: off), its CRTC_X/Y, and the legacy-wrapped framebuffer
/// the plane lets go of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorChange {
    pub plane: u32,
    pub crtc_id: u32,
    pub fb_id: Option<u32>,
    pub position: (i32, i32),
    pub released_fb: Option<u32>,
}

/// Each cursor plane `state` updates, against the committed planes (call
/// before `commit`). A cursor neither shown before nor after changes
/// nothing (handle_cursor_update returns early).
pub fn cursor_changes(card: &Card, state: &AtomicState) -> Vec<CursorChange> {
    state
        .planes
        .iter()
        .filter_map(|p| {
            let native = card.native_plane(p.id).filter(|n| n.is_cursor())?;
            if p.fb_id.is_none() && native.fb_id.is_none() {
                return None;
            }
            let crtc_id = if p.fb_id.is_some() {
                p.crtc_id
            } else {
                native.crtc_id
            }?;
            Some(CursorChange {
                plane: p.id,
                crtc_id,
                fb_id: p.fb_id,
                position: (p.crtc_x, p.crtc_y),
                released_fb: native
                    .fb_id
                    .filter(|&f| native.internal_fb && p.fb_id != Some(f)),
            })
        })
        .collect()
}

/// A cursor framebuffer's premultiplied ARGB8888 pixels, row by row, read
/// out of its dumb buffer, or out of its amdgpu GEM buffer pinned in VRAM
/// as amdgpu_dm_plane_helper_prepare_fb pins a cursor's (the hardware
/// cursor scans a copy). None when neither holds its rows.
pub fn cursor_image(card: &Card, fb_id: u32) -> Option<crate::amdgpu_navi48_platform::CursorImage> {
    let fb = card.framebuffer(fb_id).ok()?;
    let (w, h) = (fb.width, fb.height);
    if w == 0 || h == 0 || w > MAX_CURSOR_SIZE || h > MAX_CURSOR_SIZE {
        return None;
    }
    let row = u64::from(w) * 4;
    let end = u64::from(fb.offsets[0]) + u64::from(h - 1) * u64::from(fb.pitch) + row;
    let mut pixels = Vec::with_capacity((w * h) as usize);
    let mut line = [0u8; MAX_CURSOR_SIZE as usize * 4];
    if let Some(bo) = &fb.bo {
        let pin = bo.object.pin_scanout().ok()?;
        for y in 0..h {
            let at = u64::from(fb.offsets[0]) + u64::from(y) * u64::from(fb.pitch);
            pin.placement().read_bytes(at, &mut line[..row as usize])?;
            pixels.extend(
                line[..row as usize]
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            );
        }
        return Some(crate::amdgpu_navi48_platform::CursorImage {
            width: w,
            height: h,
            pixels,
        });
    }
    let backing = card.dumb_backing(fb.gem_handle)?;
    if end > backing.byte_len as u64 {
        return None;
    }
    for y in 0..h {
        let at = backing.phys + u64::from(fb.offsets[0]) + u64::from(y) * u64::from(fb.pitch);
        // SAFETY: the dumb buffer's frames are kernel-owned and mapped; the
        // row lies inside the backing (checked above) and in `line`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(at).kernel_ptr::<u8>(),
                line.as_mut_ptr(),
                row as usize,
            );
        }
        pixels.extend(
            line[..row as usize]
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        );
    }
    Some(crate::amdgpu_navi48_platform::CursorImage {
        width: w,
        height: h,
        pixels,
    })
}

/// drm_atomic_normalize_zpos on one CRTC's planes, then the plane setup
/// DC gets: the primary's placement unless it shows its framebuffer whole
/// and unscaled at the mode with its format's default blending, and the
/// overlays bottom first, those normalized below the primary underlays.
fn display_planes(
    card: &Card,
    crtc_id: u32,
    primary: &PlaneState,
    overlays: &[PlaneState],
    mode: (u32, u32),
) -> Result<DisplayPlanes, FsError> {
    let fourcc = |p: &PlaneState| -> Result<u32, FsError> {
        let fb = p.fb_id.ok_or(FsError::InvalidData)?;
        Ok(card.framebuffer(fb).map_err(|_| FsError::NotFound)?.format as u32)
    };
    let format_of = |p: &PlaneState| -> Result<SurfaceFormat, FsError> {
        SurfaceFormat::from_fourcc(fourcc(p)?).ok_or(FsError::InvalidData)
    };
    let geometry = |p: &PlaneState, format: SurfaceFormat, overlay: bool| {
        let fb = card
            .framebuffer(p.fb_id.ok_or(FsError::InvalidData)?)
            .map_err(|_| FsError::NotFound)?;
        let props = p.props.unwrap_or(PlaneProps::new(0));
        let surface = plane_surface(fb, props)?;
        let rotation = rotation(props.rotation);
        // DML21's SourceFormatPixelAndScanSupport: a linear surface cannot
        // be scanned vertically, so dc_validate_global_state refuses a
        // linear plane rotated 90 or 270 whatever the mode.
        if rotation.orthogonal() && surface.tiling.swizzle == Swizzle::Linear {
            return Err(FsError::InvalidData);
        }
        Ok::<_, FsError>(PlaneGeometry {
            src_x: p.src_x,
            src_y: p.src_y,
            width: p.src_w,
            height: p.src_h,
            dst: Rect::new(p.crtc_x, p.crtc_y, p.crtc_w as i32, p.crtc_h as i32),
            rotation,
            blend: blend(format, props, overlay),
            surface,
            fb_size: (fb.width, fb.height),
        })
    };
    let zpos = |p: &PlaneState| p.props.map_or(0, |r| r.zpos);
    // Normalized order: by zpos, then plane id.
    let mut order: Vec<&PlaneState> = core::iter::once(primary).chain(overlays).collect();
    order.sort_by_key(|p| (zpos(p), p.id));
    let primary_at = order
        .iter()
        .position(|p| p.id == primary.id)
        .ok_or(FsError::InvalidData)?;
    let format = format_of(primary)?;
    let g = geometry(primary, format, false)?;
    // A tiled or 4:2:0 primary always goes to DC as a placed plane (its
    // surface is its whole framebuffer).
    let full = !g.whole_framebuffer(format)
        && (g.src_x, g.src_y, g.width, g.height) == (0, 0, mode.0, mode.1)
        && g.dst == Rect::new(0, 0, mode.0 as i32, mode.1 as i32)
        && g.rotation == Rotation::R0
        && g.blend == Blend::default_for(format);
    let mut setup = PlaneSetup {
        primary: (!full).then_some(g),
        overlays: [None; MAX_OVERLAYS],
    };
    let mut ids = [None; MAX_OVERLAYS];
    for (k, p) in order.iter().filter(|p| p.id != primary.id).enumerate() {
        if k >= MAX_OVERLAYS {
            return Err(FsError::InvalidData);
        }
        let format = format_of(p)?;
        setup.overlays[k] = Some(OverlayPlane {
            geometry: geometry(p, format, true)?,
            format,
            underlay: order
                .iter()
                .position(|q| q.id == p.id)
                .is_some_and(|i| i < primary_at),
            plane: p.id,
        });
        ids[k] = Some(p.id);
    }
    Ok(DisplayPlanes {
        crtc_id,
        setup,
        primary_format: fourcc(primary)?,
        overlays: ids,
    })
}

/// Record a committed request's native plane states: each plane's CRTC,
/// framebuffer (an overlay's; a primary's is its CRTC's), rectangles and
/// properties.
pub fn commit(card: &mut Card, state: &AtomicState) {
    for p in &state.planes {
        let Some(native) = card.native_planes.iter_mut().find(|n| n.id == p.id) else {
            continue;
        };
        if native.is_cursor() && native.fb_id != p.fb_id {
            // A legacy-wrapped framebuffer goes with the plane's next one
            // (the bridge marks a new one again).
            native.internal_fb = false;
        }
        if native.primary_of.is_none() {
            native.crtc_id = p.crtc_id;
            native.fb_id = p.fb_id;
        } else {
            native.crtc_id = p.crtc_id;
            native.fb_id = p.fb_id;
            native.placed = true;
        }
        native.src = (p.src_x, p.src_y, p.src_w, p.src_h);
        native.dst = (p.crtc_x, p.crtc_y, p.crtc_w, p.crtc_h);
        if let Some(props) = p.props {
            native.props = props;
        }
    }
}

/// A legacy SETCRTC shows the framebuffer whole at the mode: its primary
/// is unplaced again (drm_atomic_helper_set_config), its properties kept.
pub fn reset_primary(card: &mut Card, crtc_id: u32) {
    if let Some(p) = card
        .native_planes
        .iter_mut()
        .find(|p| p.primary_of == Some(crtc_id))
    {
        p.placed = false;
    }
}

/// A PAGE_FLIP keeps the primary's placement: on a placed primary the new
/// framebuffer must hold its source rectangle (in the same format, checked
/// by the caller).
pub fn flip_fits(card: &Card, crtc_id: u32, fb_id: u32) -> Option<bool> {
    let p = card
        .native_planes
        .iter()
        .find(|p| p.primary_of == Some(crtc_id) && p.placed)?;
    let fb = card.framebuffer(fb_id).ok()?;
    let (x, y, w, h) = p.src;
    Some(
        u64::from(x) + u64::from(w) <= u64::from(fb.width)
            && u64::from(y) + u64::from(h) <= u64::from(fb.height),
    )
}

/// The planes a legacy SETCRTC of framebuffer `fb_id` at `(x, y)` on CRTC
/// `crtc_id` of `mode` would give the display (the primary unplaced, the
/// committed overlays kept), when its primary cannot be the full-frame
/// default: a tiled or 4:2:0 framebuffer is scanned as a placed plane.
/// None for a linear RGB framebuffer (its display takes the format check).
pub fn setcrtc_planes(
    card: &Card,
    crtc_id: u32,
    fb_id: u32,
    (x, y): (u32, u32),
    mode: (u32, u32),
) -> Option<Result<DisplayPlanes, FsError>> {
    let fb = card.framebuffer(fb_id).ok()?;
    let format = SurfaceFormat::from_fourcc(fb.format as u32)?;
    if !format.is_video() && fb.modifier == crate::amdgpu_dm_modifiers::LINEAR {
        return None;
    }
    let primary = card
        .native_planes
        .iter()
        .find(|p| p.primary_of == Some(crtc_id))?;
    let state = PlaneState {
        id: primary.id,
        crtc_id: Some(crtc_id),
        fb_id: Some(fb_id),
        crtc_x: 0,
        crtc_y: 0,
        crtc_w: mode.0,
        crtc_h: mode.1,
        src_x: x,
        src_y: y,
        src_w: mode.0,
        src_h: mode.1,
        in_fence_fd: None,
        props: Some(primary.props),
    };
    let overlays: Vec<PlaneState> = overlay_ids(card)
        .into_iter()
        .filter_map(|id| plane_state(card, id))
        .filter(|p| p.crtc_id == Some(crtc_id) && p.fb_id.is_some())
        .collect();
    Some(
        check_plane(&state, mode)
            .and_then(|()| display_planes(card, crtc_id, &state, &overlays, mode)),
    )
}

/// Each enabled CRTC's planes as the card now holds them (after a commit,
/// a framebuffer removal or a SETCRTC), for the displays to light with.
pub fn displays(card: &Card) -> Vec<DisplayPlanes> {
    let empty = AtomicState::default();
    card.crtcs
        .iter()
        .filter(|c| c.enabled)
        .filter_map(|c| {
            let mode = c.mode?;
            let primary_id = card
                .native_planes
                .iter()
                .find(|p| p.primary_of == Some(c.id))?
                .id;
            let primary = final_state(card, &empty, primary_id).filter(|p| p.fb_id.is_some())?;
            let overlays: Vec<PlaneState> = overlay_ids(card)
                .into_iter()
                .filter_map(|id| plane_state(card, id))
                .filter(|p| p.crtc_id == Some(c.id) && p.fb_id.is_some())
                .collect();
            display_planes(card, c.id, &primary, &overlays, (mode.width, mode.height)).ok()
        })
        .collect()
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::drm::card::Crtc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const XR24: u32 = 0x3432_5258;
    const AR24: u32 = 0x3432_5241;
    const XR30: u32 = 0x3033_5258;

    /// A native card with one 1920x1080 CRTC (id 1) showing a 1920x1080
    /// XRGB8888 framebuffer, and three more framebuffers to place.
    fn card() -> (Card, [u32; 4]) {
        let mut card = Card::new("amdgpu-test", "native planes", (3, 0, 0));
        card.crtcs.push(Crtc {
            id: 1,
            mode: Some(crate::Mode {
                width: 1920,
                height: 1080,
                refresh_hz: 60,
                bpp: 32,
            }),
            enabled: true,
            primary_fb: None,
            x: 0,
            y: 0,
        });
        card.plane_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.overlay_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.native_planes = planes_for(&[], &[1]);
        let mut fb = |w: u32, h: u32, format: u32| {
            let handle = card.gem.alloc(0x1000_0000, (w * h * 4) as usize).unwrap();
            card.addfb2(w, h, format, w * 4, handle).unwrap()
        };
        let fbs = [
            fb(1920, 1080, XR24),
            fb(1280, 720, AR24),
            fb(256, 256, XR24),
            fb(640, 480, XR30),
        ];
        card.crtcs[0].primary_fb = Some(fbs[0]);
        (card, fbs)
    }
    fn on(id: u32, fb: u32, src: (u32, u32), dst: (i32, i32, u32, u32)) -> PlaneState {
        PlaneState {
            id,
            crtc_id: Some(1),
            fb_id: Some(fb),
            crtc_x: dst.0,
            crtc_y: dst.1,
            crtc_w: dst.2,
            crtc_h: dst.3,
            src_x: 0,
            src_y: 0,
            src_w: src.0,
            src_h: src.1,
            in_fence_fd: None,
            props: None,
        }
    }

    /// amdgpu_dm_plane_helper_check_state and fill_dc_scaling_info with
    /// DCN401's caps: 16x up passes and 17x does not; 6:1 down is refused
    /// by the integer limits (scale 166 < 167), 5.9:1 passes; the viewport
    /// left on the CRTC must be 24x12. A 90/270 rotation swaps the source
    /// for the helper's limits: a 1920x200 source shown at 1920x200 is
    /// 9.6:1 down vertically once turned.
    fn drm_native_planes_scaling_and_viewport_limits() -> TestResult {
        let mode = (1920, 1080);
        let p = |src: (u32, u32), dst| on(OVERLAY_PLANE_ID_BASE, 0, src, dst);
        let ok = [
            p((1920, 1080), (0, 0, 1920, 1080)),
            p((120, 68), (0, 0, 1920, 1080)),
            p((1888, 1062), (0, 0, 320, 180)),
            p((64, 64), (-40, 10, 64, 64)),
        ];
        let bad = [
            p((112, 63), (0, 0, 1904, 1071)),
            p((1920, 1080), (0, 0, 320, 180)),
            p((64, 64), (0, 0, 23, 64)),
            p((64, 64), (0, 0, 64, 11)),
            p((64, 64), (-50, 0, 64, 64)),
            p((64, 64), (1900, 0, 64, 64)),
            p((64, 64), (2000, 0, 64, 64)),
            p((0, 64), (0, 0, 64, 64)),
        ];
        if ok.iter().any(|s| check_plane(s, mode).is_err()) {
            return TestResult::Fail("plane within the caps refused");
        }
        if bad
            .iter()
            .any(|s| check_plane(s, mode) != Err(FsError::InvalidData))
        {
            return TestResult::Fail("plane outside the caps accepted");
        }
        let mut turned = ok[0].clone();
        let mut strip = p((1920, 200), (0, 0, 1920, 200));
        for (rotation, fine) in [(1u8, true), (2, false), (4, true), (8, false)] {
            let props = Some(PlaneProps {
                rotation,
                ..PlaneProps::new(0)
            });
            turned.props = props;
            strip.props = props;
            if check_plane(&turned, mode).is_err() || check_plane(&strip, mode).is_ok() != fine {
                return TestResult::Fail("rotation");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_scaling_and_viewport_limits
    );

    /// amdgpu_dm's plane properties: each plane's defaults (the primary's
    /// immutable zpos 3, overlay k's 3 + 1 + 4 + k, the cursor's immutable
    /// 255), and the range, enum, bitmask and immutability checks of a set.
    fn drm_native_planes_properties_follow_amdgpu_dm() -> TestResult {
        let (card, _) = card();
        let primary = PRIMARY_PLANE_ID_BASE;
        let zpos: Vec<u8> = card.native_planes.iter().map(|p| p.props.zpos).collect();
        if zpos != [3, 8, 9, 10, 255]
            || overlay_ids(&card) != [0x44, 0x45, 0x46]
            || cursor_ids(&card) != [0x47]
        {
            return TestResult::Fail("default zpos and ids");
        }
        let Some((ids, values)) = object_properties(&card, OVERLAY_PLANE_ID_BASE) else {
            return TestResult::Fail("overlay properties");
        };
        // IN_FORMATS follows whenever the card lists plane formats.
        let tail = |mut v: alloc::vec::Vec<u32>| {
            if card.plane_formats.is_some() {
                v.push(IN_FORMATS_PROP_ID);
            }
            v
        };
        // The planes list NV12 and P010, so carry COLOR_ENCODING (BT.709)
        // and COLOR_RANGE (limited) before the rotation.
        if ids
            != tail(alloc::vec![
                ALPHA_PROP_ID,
                BLEND_PROP_ID,
                ZPOS_PROP_ID,
                COLOR_ENCODING_PROP_ID,
                COLOR_RANGE_PROP_ID,
                ROTATION_PROP_ID
            ])
            || values[..6] != [0xffff, 0, 8, 1, 0, 1]
            || object_properties(&card, primary).map(|(i, _)| i)
                != Some(tail(alloc::vec![
                    BLEND_PROP_ID,
                    PRIMARY_ZPOS_PROP_ID,
                    COLOR_ENCODING_PROP_ID,
                    COLOR_RANGE_PROP_ID,
                    ROTATION_PROP_ID
                ]))
        {
            return TestResult::Fail("property lists");
        }
        let set = |id: u32, prop: u32, value: u64| {
            let mut s = plane_state(&card, id).unwrap();
            set_property(&card, &mut s, prop, value).map(|known| (known, s.props.unwrap()))
        };
        let overlay = OVERLAY_PLANE_ID_BASE;
        let accepted = [
            (overlay, ALPHA_PROP_ID, 0x8000),
            (overlay, BLEND_PROP_ID, 1),
            (primary, BLEND_PROP_ID, 2),
            (overlay, ZPOS_PROP_ID, 0),
            (overlay, ZPOS_PROP_ID, 254),
            (primary, ROTATION_PROP_ID, 4),
            (overlay, ROTATION_PROP_ID, 8),
            (overlay, COLOR_ENCODING_PROP_ID, 0),
            (primary, COLOR_ENCODING_PROP_ID, 2),
            (overlay, COLOR_RANGE_PROP_ID, 1),
        ];
        for (id, prop, value) in accepted {
            if !matches!(set(id, prop, value), Ok((true, _))) {
                return TestResult::Fail("valid property refused");
            }
        }
        if set(overlay, ALPHA_PROP_ID, 0x4000).map(|(_, p)| p.alpha) != Ok(0x4000) {
            return TestResult::Fail("alpha value");
        }
        let refused = [
            (overlay, ALPHA_PROP_ID, 0x1_0000),
            (overlay, BLEND_PROP_ID, 3),
            (overlay, ZPOS_PROP_ID, 255),
            (primary, PRIMARY_ZPOS_PROP_ID, 3),
            (overlay, ROTATION_PROP_ID, 3),
            (overlay, ROTATION_PROP_ID, 0x10),
            (overlay, ROTATION_PROP_ID, 0),
            (overlay, COLOR_ENCODING_PROP_ID, 3),
            (primary, COLOR_RANGE_PROP_ID, 2),
        ];
        for (id, prop, value) in refused {
            if set(id, prop, value) != Err(FsError::InvalidData) {
                return TestResult::Fail("invalid property accepted");
            }
        }
        // The primary has no alpha: not one of its properties.
        if set(primary, ALPHA_PROP_ID, 0x8000).map(|(known, _)| known) != Ok(false) {
            return TestResult::Fail("primary alpha");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_properties_follow_amdgpu_dm
    );

    /// create_in_format_blob: version 1, the plane's formats at offset 24,
    /// one 8-byte-aligned modifier entry (LINEAR) covering every format;
    /// other blob ids and planes are not IN_FORMATS blobs.
    fn drm_native_planes_in_formats_blob_lists_linear_formats() -> TestResult {
        let (mut card, _) = card();
        static FORMATS: [u32; 3] = [0x3432_5258, 0x3432_5241, 0x3033_5258];
        card.overlay_formats = Some(&FORMATS);
        let id = in_formats_blob_id(OVERLAY_PLANE_ID_BASE);
        let blob = in_formats_blob(&card, id).unwrap();
        let word = |at: usize| u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        assert_eq!(
            [word(0), word(4), word(8), word(12), word(16), word(20)],
            [1, 0, 3, 24, 1, 40]
        );
        assert_eq!([word(24), word(28), word(32)], FORMATS);
        assert_eq!(blob.len(), 64);
        assert_eq!(u64::from_le_bytes(blob[40..48].try_into().unwrap()), 0b111);
        assert_eq!(&blob[48..64], &[0; 16]);
        let (ids, values) = object_properties(&card, OVERLAY_PLANE_ID_BASE).unwrap();
        assert_eq!(ids.last(), Some(&IN_FORMATS_PROP_ID));
        assert_eq!(values.last(), Some(&u64::from(id)));
        assert!(in_formats_blob(&card, 0x1000 | OVERLAY_PLANE_ID_BASE).is_none());
        assert!(in_formats_blob(&card, in_formats_blob_id(0x7ff)).is_none());
        card.overlay_formats = None;
        assert!(in_formats_blob(&card, id).is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_in_formats_blob_lists_linear_formats
    );

    /// The native amdgpu card's planes list the GFX12 modifiers: IN_FORMATS
    /// and IN_FORMATS_ASYNC carry every PLANE_FORMATS format under all 17
    /// (amdgpu_dm_plane_format_mod_supported takes each GFX12 modifier for
    /// every format), for primaries and overlays alike.
    fn drm_native_planes_in_formats_blob_lists_gfx12_modifiers() -> TestResult {
        use crate::amdgpu_dm_modifiers::PLANE_MODIFIERS;
        let (mut card, _) = card();
        card.gfx12_modifiers = true;
        let formats = crate::amdgpu_navi48_kms::PLANE_FORMATS;
        for plane in [PRIMARY_PLANE_ID_BASE, OVERLAY_PLANE_ID_BASE + 2] {
            for id in [in_formats_blob_id(plane), in_formats_async_blob_id(plane)] {
                let blob = in_formats_blob(&card, id).unwrap();
                let word = |at: usize| u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
                // 24 + 15 formats * 4 = 84, aligned to 88.
                assert_eq!(
                    [word(0), word(4), word(8), word(12), word(16), word(20)],
                    [1, 0, 15, 24, 17, 88]
                );
                assert_eq!(blob.len(), 88 + 17 * 24);
                for (i, m) in PLANE_MODIFIERS.iter().enumerate() {
                    let at = 88 + 24 * i;
                    let mask = u64::from_le_bytes(blob[at..at + 8].try_into().unwrap());
                    let modifier = u64::from_le_bytes(blob[at + 16..at + 24].try_into().unwrap());
                    assert_eq!((mask, modifier), ((1 << formats.len()) - 1, *m));
                }
            }
            let (ids, values) = object_properties(&card, plane).unwrap();
            assert_eq!(
                ids[ids.len() - 2..],
                [IN_FORMATS_PROP_ID, IN_FORMATS_ASYNC_PROP_ID]
            );
            assert_eq!(
                values[values.len() - 2..],
                [
                    u64::from(in_formats_blob_id(plane)),
                    u64::from(in_formats_async_blob_id(plane))
                ]
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_in_formats_blob_lists_gfx12_modifiers
    );

    /// A tiled or 4:2:0 framebuffer reaches DC as its whole surface: an
    /// NV12 overlay's geometry carries the framebuffer size, its modifier's
    /// tiling and COLOR_ENCODING / COLOR_RANGE's color space
    /// (fill_plane_color_attributes), and a tiled primary is never the
    /// full-frame default even shown whole and unscaled.
    fn drm_native_planes_carry_tiling_and_yuv_color() -> TestResult {
        use crate::amdgpu_dcn401_otg::{DccBlock, Swizzle, Tiling, YuvColor};
        use crate::amdgpu_dm_modifiers::{FbCmd, FB_MODIFIERS, NV12};
        let (mut card, fbs) = card();
        card.gfx12_modifiers = true;
        let tiled = Tiling {
            swizzle: Swizzle::S256K2D,
            dcc: Some(DccBlock::B256),
        };
        let mut fb = |w: u32, h: u32, format: u32, modifier: u64, chroma: bool| {
            let size = 64 << 20;
            let handle = card.gem.alloc(0x2000_0000, size).unwrap();
            let pitch = if format == NV12 { 2048 } else { 8192 };
            let mut cmd = FbCmd {
                width: w,
                height: h,
                pixel_format: format,
                flags: FB_MODIFIERS,
                ..FbCmd::default()
            };
            cmd.handles[0] = handle;
            cmd.pitches[0] = pitch;
            cmd.modifier[0] = modifier;
            if chroma {
                cmd.handles[1] = handle;
                cmd.pitches[1] = pitch;
                cmd.offsets[1] = 8 << 20;
                cmd.modifier[1] = modifier;
            }
            card.addfb2_cmd(&cmd)
        };
        let video = fb(1280, 720, NV12, 0, true).unwrap();
        let primary_tiled = fb(1920, 1080, XR24, tiled.modifier(), false).unwrap();
        // amdgpu_display_framebuffer_init: one BO for every plane.
        assert!(fb(1280, 720, NV12, 0, false).is_err());
        let mut state = AtomicState::default();
        let mut o = on(
            OVERLAY_PLANE_ID_BASE,
            video,
            (640, 360),
            (100, 50, 960, 540),
        );
        o.src_x = 320;
        o.src_y = 180;
        let mut props = PlaneProps::new(overlay_zpos(0));
        props.color_encoding = PlaneProps::BT601;
        props.color_range = PlaneProps::FULL;
        o.props = Some(props);
        state.planes.push(o);
        let mode = |_| {
            Some(crate::Mode {
                width: 1920,
                height: 1080,
                refresh_hz: 60,
                bpp: 32,
            })
        };
        let out = check(&card, &state, mode).unwrap();
        let g = out[0].setup.overlays[0].unwrap();
        assert_eq!(g.format, SurfaceFormat::Nv12);
        assert_eq!(g.geometry.fb_size, (1280, 720));
        assert_eq!((g.geometry.src_x, g.geometry.src_y), (320, 180));
        assert_eq!(g.geometry.surface.color, YuvColor::Bt601);
        assert_eq!(g.geometry.surface.tiling, Tiling::LINEAR);
        assert!(g.geometry.whole_framebuffer(g.format));
        // The tiled primary shown whole at the mode is still placed.
        let mut st = AtomicState::default();
        st.crtcs.push(crate::drm::atomic::CrtcState {
            id: 1,
            enable: true,
            ..Default::default()
        });
        card.crtcs[0].primary_fb = Some(primary_tiled);
        let out = check(&card, &st, mode).unwrap();
        let p = out[0].setup.primary.unwrap();
        assert_eq!(p.surface.tiling, tiled);
        // Its linear sibling stays the full-frame default.
        card.crtcs[0].primary_fb = Some(fbs[0]);
        assert!(check(&card, &st, mode).unwrap()[0].setup.primary.is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_carry_tiling_and_yuv_color
    );

    /// amdgpu_dm's "rotation" reaches DC on every plane (fill_dc_plane_info_
    /// and_addr's ROTATION_ANGLE): a tiled overlay or primary turned 90 or
    /// 270 is placed with its rotation, and a linear one is refused (DML21
    /// scans no linear surface vertically), as is a linear NV12 one; 180
    /// stays fine on linear.
    fn drm_native_planes_rotate_tiled_planes_90_and_270() -> TestResult {
        use crate::amdgpu_dcn401_otg::{DccBlock, Tiling};
        use crate::amdgpu_dm_modifiers::{FbCmd, FB_MODIFIERS, NV12};
        let (mut card, fbs) = card();
        card.gfx12_modifiers = true;
        let tiled = Tiling {
            swizzle: Swizzle::S64K2D,
            dcc: Some(DccBlock::B128),
        };
        let mut fb = |w: u32, h: u32, format: u32, modifier: u64| {
            let handle = card.gem.alloc(0x3000_0000, 64 << 20).unwrap();
            let mut cmd = FbCmd {
                width: w,
                height: h,
                pixel_format: format,
                flags: FB_MODIFIERS,
                ..FbCmd::default()
            };
            cmd.handles[0] = handle;
            cmd.pitches[0] = if format == NV12 { 2048 } else { 8192 };
            cmd.modifier[0] = modifier;
            if format == NV12 {
                cmd.handles[1] = handle;
                cmd.pitches[1] = 2048;
                cmd.offsets[1] = 8 << 20;
            }
            card.addfb2_cmd(&cmd).unwrap()
        };
        let portrait = fb(1080, 1920, XR24, tiled.modifier());
        let video = fb(720, 1280, NV12, 0);
        let mode = |_| {
            Some(crate::Mode {
                width: 1920,
                height: 1080,
                refresh_hz: 60,
                bpp: 32,
            })
        };
        let turned = |id: u32, fb: u32, src: (u32, u32), dst, rotation: u8| {
            let mut p = on(id, fb, src, dst);
            p.props = Some(PlaneProps {
                rotation,
                ..PlaneProps::new(if id == OVERLAY_PLANE_ID_BASE {
                    overlay_zpos(0)
                } else {
                    PRIMARY_ZPOS
                })
            });
            p
        };
        let with = |planes: &[PlaneState]| {
            let mut state = AtomicState::default();
            state.planes.extend_from_slice(planes);
            check(&card, &state, mode)
        };
        // A portrait overlay turned onto a landscape window.
        for (bits, rotation) in [(2u8, Rotation::R90), (8, Rotation::R270)] {
            let o = turned(
                OVERLAY_PLANE_ID_BASE,
                portrait,
                (1080, 1920),
                (100, 50, 960, 540),
                bits,
            );
            let Ok(out) = with(&[o]) else {
                return TestResult::Fail("tiled overlay turned 90/270 refused");
            };
            let Some(g) = out[0].setup.overlays[0] else {
                return TestResult::Fail("turned overlay lost");
            };
            if g.geometry.rotation != rotation
                || g.geometry.surface.tiling != tiled
                || (g.geometry.width, g.geometry.height) != (1080, 1920)
                || g.geometry.dst != Rect::new(100, 50, 960, 540)
            {
                return TestResult::Fail("turned overlay geometry");
            }
            // The primary turned too: placed, never the full-frame default.
            let primary = turned(
                PRIMARY_PLANE_ID_BASE,
                portrait,
                (1080, 1920),
                (0, 0, 1920, 1080),
                bits,
            );
            let Ok(out) = with(&[primary]) else {
                return TestResult::Fail("tiled primary turned 90/270 refused");
            };
            if out[0].setup.primary.map(|g| g.rotation) != Some(rotation) {
                return TestResult::Fail("turned primary geometry");
            }
        }
        // Linear surfaces: 90/270 refused, 180 placed.
        for (fb, src, bits, fine) in [
            (fbs[1], (1280, 720), 2u8, false),
            (fbs[1], (1280, 720), 8, false),
            (video, (720, 1280), 2, false),
            (fbs[1], (1280, 720), 4, true),
        ] {
            let o = turned(OVERLAY_PLANE_ID_BASE, fb, src, (0, 0, 640, 360), bits);
            match with(&[o]) {
                Ok(_) if fine => {}
                Err(FsError::InvalidData) if !fine => {}
                _ => return TestResult::Fail("linear rotation"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_rotate_tiled_planes_90_and_270
    );

    /// drm_atomic_normalize_zpos and the plane setup DC gets: an overlay
    /// with a lower zpos than the primary's 3 is an underlay, the others
    /// stack above in zpos (then id) order; each overlay's blending follows
    /// amdgpu_dm_plane_fill_blending_from_plane_state; the full-frame
    /// primary has no placement. Refused: an enabled CRTC without its
    /// primary, a plane moved straight to another CRTC, a format the
    /// overlay does not take.
    fn drm_native_planes_normalize_zpos_into_a_stack() -> TestResult {
        let (card, fbs) = card();
        let mut state = AtomicState::default();
        let mut under = on(0x45, fbs[2], (256, 256), (10, 10, 256, 256));
        under.props = Some(PlaneProps {
            zpos: 1,
            blend: PlaneProps::PIXEL_NONE,
            ..PlaneProps::new(1)
        });
        let mut video = on(0x44, fbs[1], (1280, 720), (100, 100, 640, 360));
        video.props = Some(PlaneProps {
            alpha: 0x8000,
            blend: PlaneProps::COVERAGE,
            ..PlaneProps::new(9)
        });
        state.planes.push(video);
        state.planes.push(under);
        let mode_of = |_| card.crtcs[0].mode;
        let Ok(displays) = check(&card, &state, mode_of) else {
            return TestResult::Fail("two overlays refused");
        };
        let [d] = displays.as_slice() else {
            return TestResult::Fail("one display");
        };
        let (Some(first), Some(second)) = (d.setup.overlays[0], d.setup.overlays[1]) else {
            return TestResult::Fail("two overlays in the stack");
        };
        if d.setup.primary.is_some()
            || d.overlays != [Some(0x45), Some(0x44), None]
            || !first.underlay
            || second.underlay
            || first.geometry.blend
                != (Blend {
                    per_pixel_alpha: false,
                    premultiplied: true,
                    global_alpha: None,
                })
            || second.geometry.blend
                != (Blend {
                    per_pixel_alpha: true,
                    premultiplied: false,
                    global_alpha: Some(0x80),
                })
            || second.geometry.dst != Rect::new(100, 100, 640, 360)
            || (second.geometry.width, second.geometry.height) != (1280, 720)
            || d.primary_format != XR24
        {
            return TestResult::Fail("normalized stack");
        }
        // A scaled primary gets its placement.
        let mut scaled = state.clone();
        scaled.planes.push(on(
            PRIMARY_PLANE_ID_BASE,
            fbs[1],
            (1280, 720),
            (0, 0, 1920, 1080),
        ));
        match check(&card, &scaled, mode_of).as_deref() {
            Ok([d]) if d.setup.primary.is_some_and(|g| g.width == 1280) => {}
            _ => return TestResult::Fail("scaled primary"),
        }
        let refused = |mutate: &dyn Fn(&mut AtomicState)| {
            let mut s = state.clone();
            mutate(&mut s);
            check(&card, &s, mode_of) == Err(FsError::InvalidData)
        };
        if !refused(&|s| {
            let mut off = plane_state(&card, PRIMARY_PLANE_ID_BASE).unwrap();
            off.crtc_id = None;
            off.fb_id = None;
            s.planes.push(off);
        }) || !refused(&|s| {
            let mut primary = plane_state(&card, PRIMARY_PLANE_ID_BASE).unwrap();
            primary.crtc_id = Some(7);
            s.planes.push(primary);
        }) {
            return TestResult::Fail("refusals");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_normalize_zpos_into_a_stack
    );

    /// A 64x64 ARGB8888 framebuffer with a 256-byte pitch: what a DCN 4.0.1
    /// cursor plane takes.
    fn cursor_fb(card: &mut Card, w: u32, h: u32, format: u32, pitch: u32) -> u32 {
        let handle = card.gem.alloc(0x1800_0000, (pitch * h) as usize).unwrap();
        card.addfb2(w, h, format, pitch, handle).unwrap()
    }
    fn cursor_on(fb: u32, (x, y): (i32, i32), size: (u32, u32)) -> PlaneState {
        PlaneState {
            id: CURSOR_PLANE_ID_BASE,
            crtc_id: Some(1),
            fb_id: Some(fb),
            crtc_x: x,
            crtc_y: y,
            crtc_w: size.0,
            crtc_h: size.1,
            src_x: 0,
            src_y: 0,
            src_w: size.0,
            src_h: size.1,
            in_fence_fd: None,
            props: None,
        }
    }
    fn mode_1080p(_: u32) -> Option<crate::Mode> {
        Some(crate::Mode {
            width: 1920,
            height: 1080,
            refresh_hz: 60,
            bpp: 32,
        })
    }

    /// amdgpu_dm_crtc_init's cursor plane per CRTC, after the primaries and
    /// overlays: on its own CRTC, its committed state kept across a
    /// republish and dropped when its CRTC goes; amdgpu_dm_plane_init's
    /// properties (Pre-multiplied alone, immutable zpos 255, no rotation,
    /// alpha or color properties) and ARGB8888 with LINEAR only in
    /// IN_FORMATS, even on the GFX12 card.
    fn drm_native_planes_cursor_plane_per_crtc() -> TestResult {
        let planes = planes_for(&[], &[1, 4, 7]);
        let cursors: Vec<(u32, Option<u32>)> = planes
            .iter()
            .filter(|p| p.is_cursor())
            .map(|p| (p.id, p.cursor_of))
            .collect();
        if cursors != [(0x47, Some(1)), (0x48, Some(4)), (0x49, Some(7))]
            || planes.iter().filter(|p| p.is_overlay()).count() != MAX_OVERLAYS
            || planes[planes.len() - 3..]
                .iter()
                .any(|p| p.props.zpos != CURSOR_ZPOS)
        {
            return TestResult::Fail("cursor planes");
        }
        // Kept on its CRTC, disabled when another CRTC takes its index.
        let mut shown = planes.clone();
        shown[MAX_OVERLAYS + 3].crtc_id = Some(1);
        shown[MAX_OVERLAYS + 3].fb_id = Some(5);
        shown[MAX_OVERLAYS + 3].internal_fb = true;
        let kept = planes_for(&shown, &[1, 4, 7]);
        let moved = planes_for(&shown, &[2]);
        if kept[MAX_OVERLAYS + 3].fb_id != Some(5)
            || moved[1 + MAX_OVERLAYS].cursor_of != Some(2)
            || moved[1 + MAX_OVERLAYS].fb_id.is_some()
            || moved[1 + MAX_OVERLAYS].internal_fb
        {
            return TestResult::Fail("republished cursor planes");
        }
        let (mut card, _) = card();
        card.gfx12_modifiers = true;
        let cursor = CURSOR_PLANE_ID_BASE;
        if cursor_ids(&card) != [cursor] || cursor_of(&card, 1).map(|p| p.id) != Some(cursor) {
            return TestResult::Fail("cursor of CRTC 1");
        }
        let Some((ids, values)) = object_properties(&card, cursor) else {
            return TestResult::Fail("cursor properties");
        };
        if ids
            != [
                CURSOR_BLEND_PROP_ID,
                CURSOR_ZPOS_PROP_ID,
                IN_FORMATS_PROP_ID,
                IN_FORMATS_ASYNC_PROP_ID,
            ]
            || values
                != [
                    u64::from(PlaneProps::PREMULTI),
                    255,
                    u64::from(in_formats_blob_id(cursor)),
                    u64::from(in_formats_async_blob_id(cursor)),
                ]
            || range_property(CURSOR_ZPOS_PROP_ID) != Some((b"zpos", true, [255, 255]))
        {
            return TestResult::Fail("cursor property list");
        }
        let set = |prop: u32, value: u64| {
            let mut s = plane_state(&card, cursor).unwrap();
            set_property(&card, &mut s, prop, value)
        };
        if set(CURSOR_BLEND_PROP_ID, 0) != Ok(true)
            || set(CURSOR_BLEND_PROP_ID, 1) != Err(FsError::InvalidData)
            || set(CURSOR_BLEND_PROP_ID, 2) != Err(FsError::InvalidData)
            || set(CURSOR_ZPOS_PROP_ID, 255) != Err(FsError::InvalidData)
            || [
                BLEND_PROP_ID,
                ALPHA_PROP_ID,
                ZPOS_PROP_ID,
                ROTATION_PROP_ID,
                COLOR_ENCODING_PROP_ID,
            ]
            .iter()
            .any(|&p| set(p, 0) != Ok(false))
        {
            return TestResult::Fail("cursor property sets");
        }
        // create_in_format_blob: ARGB8888 under DRM_FORMAT_MOD_LINEAR alone.
        for id in [in_formats_blob_id(cursor), in_formats_async_blob_id(cursor)] {
            let Some(blob) = in_formats_blob(&card, id) else {
                return TestResult::Fail("cursor IN_FORMATS");
            };
            let word = |at: usize| u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
            if [word(0), word(4), word(8), word(12), word(16), word(20)] != [1, 0, 1, 24, 1, 32]
                || word(24) != AR24
                || blob.len() != 56
                || u64::from_le_bytes(blob[32..40].try_into().unwrap()) != 1
                || blob[40..56] != [0; 16]
            {
                return TestResult::Fail("cursor IN_FORMATS blob");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/drm", drm_native_planes_cursor_plane_per_crtc);

    const CURSOR_VECTORS: &str = include_str!("../tests/dcn401_cursor_plane/vectors.txt");

    /// `check_cursor` against amdgpu_dm_check_native_cursor_state,
    /// dm_check_cursor_fb and the DCN 4.x scaling rule compiled from Linux
    /// (tests/dcn401_cursor_plane): the same answer for every framebuffer
    /// size, pitch, tiling, source and CRTC size there.
    fn drm_native_planes_check_cursor_matches_linux() -> TestResult {
        let mut n = 0;
        for line in CURSOR_VECTORS
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let Some((input, want)) = line.split_once(" = ") else {
                return TestResult::Fail("vector line");
            };
            let v: Vec<u64> = input.split(' ').filter_map(|w| w.parse().ok()).collect();
            let [w, h, pitch, mods, tiling, sx, sy, sw, sh, cw, ch] = v[..] else {
                return TestResult::Fail("vector fields");
            };
            // Without modifiers the BO's GFX12_SWIZZLE_MODE is the
            // framebuffer's modifier (amdgpu converts it); with them core
            // DRM took LINEAR only.
            let fb = CursorFb {
                width: w as u32,
                height: h as u32,
                pitch: pitch as u32,
                linear: mods != 0 || tiling & 7 == 0,
            };
            let got = check_cursor(
                fb,
                (sx as u32, sy as u32, sw as u32, sh as u32),
                (cw as u32, ch as u32),
            );
            let got = if got.is_ok() { "0" } else { "-22" };
            if got != want {
                return TestResult::Fail("cursor check differs from Linux");
            }
            n += 1;
        }
        if n < 2000 {
            return TestResult::Fail("cursor vectors missing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_check_cursor_matches_linux
    );

    /// The atomic checks of a cursor plane: drm_atomic_plane_check (its own
    /// CRTC only, ARGB8888 with LINEAR), amdgpu_dm's cursor rules, and
    /// dm_crtc_helper_atomic_check's primary; a cursor-only commit puts no
    /// plane in DC (FAST). Negative positions pass (they move into the
    /// hotspot). `cursor_changes` reads handle_cursor_update's input.
    fn drm_native_planes_cursor_atomic_checks() -> TestResult {
        let (mut card, fbs) = card();
        let cursor = cursor_fb(&mut card, 64, 64, AR24, 256);
        let short = cursor_fb(&mut card, 64, 20, AR24, 256);
        let narrow = cursor_fb(&mut card, 32, 32, AR24, 128);
        let packed = cursor_fb(&mut card, 32, 32, AR24, 256);
        let opaque = cursor_fb(&mut card, 64, 64, XR24, 256);
        let check1 = |card: &Card, p: PlaneState| {
            let mut state = AtomicState::default();
            state.planes.push(p);
            check(card, &state, mode_1080p)
        };
        for (fb, at, size) in [
            (cursor, (100, 100), (64, 64)),
            (cursor, (-63, -10), (64, 64)),
            (cursor, (-500, 2000), (64, 64)),
            (short, (1900, 1070), (64, 20)),
        ] {
            match check1(&card, cursor_on(fb, at, size)).as_deref() {
                Ok([]) => {}
                _ => return TestResult::Fail("cursor refused or put in DC"),
            }
        }
        let mut cropped = cursor_on(cursor, (0, 0), (32, 32));
        cropped.src_w = 32;
        let mut offset = cursor_on(cursor, (0, 0), (63, 64));
        offset.src_x = 1;
        offset.src_w = 63;
        let mut other_crtc = cursor_on(cursor, (0, 0), (64, 64));
        other_crtc.crtc_id = Some(2);
        let mut scaled = cursor_on(cursor, (0, 0), (64, 64));
        scaled.crtc_w = 128;
        scaled.crtc_h = 128;
        for refused in [
            cropped,
            offset,
            other_crtc,
            scaled,
            cursor_on(narrow, (0, 0), (32, 32)),
            cursor_on(packed, (0, 0), (32, 32)),
            cursor_on(opaque, (0, 0), (64, 64)),
            cursor_on(fbs[2], (0, 0), (256, 256)),
        ] {
            if check1(&card, refused) != Err(FsError::InvalidData) {
                return TestResult::Fail("cursor accepted");
            }
        }
        // A tiled framebuffer is not linear.
        card.framebuffers
            .iter_mut()
            .find(|f| f.id == cursor)
            .unwrap()
            .modifier = crate::amdgpu_dcn401_otg::Tiling {
            swizzle: Swizzle::S64K2D,
            dcc: None,
        }
        .modifier();
        if check1(&card, cursor_on(cursor, (0, 0), (64, 64))) != Err(FsError::InvalidData) {
            return TestResult::Fail("tiled cursor accepted");
        }
        card.framebuffers
            .iter_mut()
            .find(|f| f.id == cursor)
            .unwrap()
            .modifier = crate::amdgpu_dm_modifiers::LINEAR;
        // An enabled CRTC needs its primary, also for a cursor update.
        card.crtcs[0].primary_fb = None;
        if check1(&card, cursor_on(cursor, (0, 0), (64, 64))) != Err(FsError::InvalidData) {
            return TestResult::Fail("cursor on a CRTC without its primary");
        }
        card.crtcs[0].primary_fb = Some(fbs[0]);
        // handle_cursor_update's input: shown, moved, off, then nothing.
        let mut state = AtomicState::default();
        state.planes.push(cursor_on(cursor, (-5, 7), (64, 64)));
        let shown = cursor_changes(&card, &state);
        if shown
            != [CursorChange {
                plane: CURSOR_PLANE_ID_BASE,
                crtc_id: 1,
                fb_id: Some(cursor),
                position: (-5, 7),
                released_fb: None,
            }]
        {
            return TestResult::Fail("cursor shown");
        }
        commit(&mut card, &state);
        card.native_planes
            .iter_mut()
            .find(|p| p.id == CURSOR_PLANE_ID_BASE)
            .unwrap()
            .internal_fb = true;
        let mut off = plane_state(&card, CURSOR_PLANE_ID_BASE).unwrap();
        off.crtc_id = None;
        off.fb_id = None;
        let mut state = AtomicState::default();
        state.planes.push(off.clone());
        let changes = cursor_changes(&card, &state);
        if changes.len() != 1
            || changes[0].fb_id.is_some()
            || changes[0].crtc_id != 1
            || changes[0].released_fb != Some(cursor)
        {
            return TestResult::Fail("cursor off");
        }
        commit(&mut card, &state);
        let p = card.native_plane(CURSOR_PLANE_ID_BASE).unwrap();
        if p.internal_fb || p.fb_id.is_some() || !cursor_changes(&card, &state).is_empty() {
            return TestResult::Fail("cursor off twice");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/drm", drm_native_planes_cursor_atomic_checks);

    /// The hardware cursor's copy of a cursor framebuffer: its rows out of
    /// the dumb buffer (at its pitch), none without a dumb backing or past
    /// the 64x64 cursor.
    fn drm_native_planes_cursor_image_reads_the_bo() -> TestResult {
        use crate::drm::card::DumbBacking;
        let Ok(frame) = narf_memory::frame::alloc_pages_on(0, 3) else {
            return TestResult::Skip("no pages");
        };
        let phys = frame.start_address().raw();
        let size = 8 * 4096;
        // SAFETY: the freshly allocated, kernel-mapped 32 KiB.
        let words = unsafe {
            core::slice::from_raw_parts_mut(
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u32>(),
                size / 4,
            )
        };
        for (i, w) in words.iter_mut().enumerate() {
            *w = 0x8000_0000 | i as u32;
        }
        let (mut card, _) = card();
        let handle = card.gem.alloc(phys, size).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys,
            byte_len: size,
            order: 3,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        let fb = card.addfb2(64, 40, AR24, 256, handle).unwrap();
        let wide = card.addfb2(65, 8, AR24, 512, handle).unwrap();
        let bare = cursor_fb(&mut card, 64, 64, AR24, 256);
        let image = cursor_image(&card, fb);
        let result = match image {
            Some(i) if (i.width, i.height) == (64, 40) && i.pixels.len() == 64 * 40 => {
                if i.pixels[0] != 0x8000_0000
                    || i.pixels[64 * 39 + 63] != 0x8000_0000 | (64 * 39 + 63)
                    || cursor_image(&card, wide).is_some()
                    || cursor_image(&card, bare).is_some()
                {
                    TestResult::Fail("cursor image rows")
                } else {
                    TestResult::Pass
                }
            }
            _ => TestResult::Fail("cursor image"),
        };
        narf_memory::frame::free_pages(frame, 3);
        result
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_cursor_image_reads_the_bo
    );
}
