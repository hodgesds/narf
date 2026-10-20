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
//! dm_crtc_helper_atomic_check's primary requirement, then
//! drm_atomic_normalize_zpos and DML21 admission of the whole configuration
//! (dc_validate_global_state) with a free pipe for every overlay. A plane
//! configuration change relights the display (DC's full update); a commit
//! that only changes framebuffers flips every changed plane at one VUPDATE.
use crate::amdgpu_dcn401_otg::{Blend, SurfaceFormat, MAX_OVERLAYS};
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

/// drm_plane_create_blend_mode_property's entries.
pub const BLEND_ENUMS: [(u64, &[u8]); 3] = [
    (PlaneProps::PIXEL_NONE as u64, b"None"),
    (PlaneProps::PREMULTI as u64, b"Pre-multiplied"),
    (PlaneProps::COVERAGE as u64, b"Coverage"),
];
/// drm_plane_create_rotation_property's bits for ROTATE_0/90/180/270.
pub const ROTATION_ENUMS: [(u64, &[u8]); 4] = [
    (0, b"rotate-0"),
    (1, b"rotate-90"),
    (2, b"rotate-180"),
    (3, b"rotate-270"),
];

/// The overlay planes' formats: amdgpu_dm's overlay_formats less those
/// the native scanout does not program (RGBA8888, NV21, NV12, P010).
pub const OVERLAY_FORMATS: [u32; 5] = [
    SurfaceFormat::Xrgb8888.fourcc(),
    SurfaceFormat::Argb8888.fourcc(),
    SurfaceFormat::Xbgr8888.fourcc(),
    SurfaceFormat::Abgr8888.fourcc(),
    SurfaceFormat::Rgb565.fourcc(),
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
/// primary and the overlays, keeping the committed state of every plane
/// that remains.
pub fn planes_for(old: &[NativePlane], crtcs: &[u32]) -> Vec<NativePlane> {
    let keep =
        |id: u32, fresh: NativePlane| old.iter().copied().find(|p| p.id == id).unwrap_or(fresh);
    let blank = |id, primary_of, zpos| NativePlane {
        id,
        primary_of,
        crtc_id: None,
        fb_id: None,
        src: (0, 0, 0, 0),
        dst: (0, 0, 0, 0),
        placed: false,
        props: PlaneProps::new(zpos),
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
    out
}

/// The overlay plane ids of `card`.
pub fn overlay_ids(card: &Card) -> Vec<u32> {
    card.native_planes
        .iter()
        .filter(|p| p.primary_of.is_none())
        .map(|p| p.id)
        .collect()
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
    let overlay = p.primary_of.is_none();
    let props = plane.props.get_or_insert(p.props);
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
    ids.push(ROTATION_PROP_ID);
    values.push(u64::from(props.rotation));
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
/// `mode` (width, height). The rotation 90/270 refusal is DML21's: a
/// linear surface cannot be scanned vertically
/// (SourceFormatPixelAndScanSupport), so dc_validate_global_state fails.
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
    let (rot90, sw, sh) = match rotation(p.props.map_or(1, |r| r.rotation)) {
        Rotation::R90 | Rotation::R270 => (true, i64::from(p.src_h), i64::from(p.src_w)),
        _ => (false, i64::from(p.src_w), i64::from(p.src_h)),
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
    if rot90 {
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
    let geometry = |p: &PlaneState, format: SurfaceFormat, overlay: bool| PlaneGeometry {
        src_x: p.src_x,
        src_y: p.src_y,
        width: p.src_w,
        height: p.src_h,
        dst: Rect::new(p.crtc_x, p.crtc_y, p.crtc_w as i32, p.crtc_h as i32),
        rotation: rotation(p.props.map_or(1, |r| r.rotation)),
        blend: blend(format, p.props.unwrap_or(PlaneProps::new(0)), overlay),
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
    let g = geometry(primary, format, false);
    let full = (g.src_x, g.src_y, g.width, g.height) == (0, 0, mode.0, mode.1)
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
            geometry: geometry(p, format, true),
            format,
            underlay: order
                .iter()
                .position(|q| q.id == p.id)
                .is_some_and(|i| i < primary_at),
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
        card.overlay_formats = Some(&OVERLAY_FORMATS);
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
    /// left on the CRTC must be 24x12; 90/270 rotation is refused.
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
        for (rotation, fine) in [(1u8, true), (2, false), (4, true), (8, false)] {
            turned.props = Some(PlaneProps {
                rotation,
                ..PlaneProps::new(0)
            });
            if check_plane(&turned, mode).is_ok() != fine {
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
    /// immutable zpos 3, overlay k's 3 + 1 + 4 + k), and the range, enum,
    /// bitmask and immutability checks of a set.
    fn drm_native_planes_properties_follow_amdgpu_dm() -> TestResult {
        let (card, _) = card();
        let primary = PRIMARY_PLANE_ID_BASE;
        let zpos: Vec<u8> = card.native_planes.iter().map(|p| p.props.zpos).collect();
        if zpos != [3, 8, 9, 10] || overlay_ids(&card) != [0x44, 0x45, 0x46] {
            return TestResult::Fail("default zpos and ids");
        }
        let Some((ids, values)) = object_properties(&card, OVERLAY_PLANE_ID_BASE) else {
            return TestResult::Fail("overlay properties");
        };
        if ids != [ALPHA_PROP_ID, BLEND_PROP_ID, ZPOS_PROP_ID, ROTATION_PROP_ID]
            || values != [0xffff, 0, 8, 1]
            || object_properties(&card, primary).map(|(i, _)| i)
                != Some(alloc::vec![
                    BLEND_PROP_ID,
                    PRIMARY_ZPOS_PROP_ID,
                    ROTATION_PROP_ID
                ])
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
        }) || !refused(&|s| s.planes[0].fb_id = Some(fbs[3]))
            || !refused(&|s| {
                let mut primary = plane_state(&card, PRIMARY_PLANE_ID_BASE).unwrap();
                primary.crtc_id = Some(7);
                s.planes.push(primary);
            })
        {
            return TestResult::Fail("refusals");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm",
        drm_native_planes_normalize_zpos_into_a_stack
    );
}
