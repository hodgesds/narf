//! Intel KMS transactions: copy requests once, wait without IRQ-safe locks,
//! and publish software state/signalling only after witnessed display latch.
//! Fixed-mode primary presentation; Linux drm_atomic_uapi.c/drm_crtc.c and
//! intel_display_irq.c at b90c984d615e8ce2af96f5b1411a962d83fed2ad.
use super::*;
use crate::drm::card::{Card, Crtc, FlipEventReservation, FlipStamp, Framebuffer, PixelFormat};
use crate::intel_gpu_scanout::{Geometry, Viewport};
use alloc::boxed::Box;
use narf_filesystem::FsFuture;

type ModeState = Arc<narf_lib::sync::IrqSafeSpinLock<Card>>;
type Events = Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>;
type OutFences = narf_lib::sync::IrqSafeSpinLock<Vec<(u64, u64)>>;
const EVENT: u32 = 1;
const TEST_ONLY: u32 = 0x100;
const NONBLOCK: u32 = 0x200;
const ALLOW_MODESET: u32 = 0x400;

pub(super) fn mutates(cmd: u32) -> bool {
    matches!(
        drm_uapi::ioc_nr(cmd),
        0x1e | 0x1f | 0xa2 | 0xa3 | 0xab | 0xaf | 0xb0 | 0xb1 | 0xb7 | 0xba | 0xbb | 0xbc
    )
}

struct OwnedAtomic {
    flags: u32,
    cookie: u64,
    objects: Vec<u32>,
    counts: Vec<u32>,
    props: Vec<u32>,
    values: Vec<u64>,
}
enum Request {
    Atomic(OwnedAtomic),
    Property {
        object: u32,
        kind: u32,
        prop: u32,
        value: u64,
    },
    SetCrtc(DrmModeCrtcUapi, Option<u32>),
    PageFlip(DrmModePageFlipUapi),
    Remove(u32),
    DropMaster,
    SetMaster,
    Dirty(u32),
    Cursor(Vec<u8>, Option<Arc<crate::intel_gpu_gem::GemObject>>, bool),
}
fn read(context: &dyn IoctlContext, address: u64, size: usize) -> Result<Vec<u8>, FsError> {
    let mut bytes = vec![0; size];
    context.read(address, &mut bytes)?;
    Ok(bytes)
}
fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect()
}
fn u32_value(value: u64) -> Result<u32, FsError> {
    u32::try_from(value).map_err(|_| FsError::InvalidData)
}
impl Request {
    fn copy(cmd: u32, arg: u64, context: &dyn IoctlContext) -> Result<Self, FsError> {
        Ok(match drm_uapi::ioc_nr(cmd) {
            0x1e => Self::SetMaster,
            0x1f => Self::DropMaster,
            0xa2 => {
                let bytes = read(context, arg, core::mem::size_of::<DrmModeCrtcUapi>())?;
                // SAFETY: initialized repr(C) integer UAPI of exactly this size.
                let req =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<DrmModeCrtcUapi>()) };
                if req.count_connectors > 1
                    || (req.count_connectors == 1 && req.set_connectors_ptr == 0)
                {
                    return Err(FsError::InvalidData);
                }
                let connector = if req.count_connectors == 1 {
                    Some(words(&read(context, req.set_connectors_ptr, 4)?)[0])
                } else {
                    None
                };
                Self::SetCrtc(req, connector)
            }
            0xb0 => {
                let bytes = read(context, arg, core::mem::size_of::<DrmModePageFlipUapi>())?;
                // SAFETY: initialized repr(C) integer UAPI of exactly this size.
                Self::PageFlip(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) })
            }
            0xbc => {
                let bytes = read(context, arg, core::mem::size_of::<DrmModeAtomicUapi>())?;
                // SAFETY: initialized repr(C) integer UAPI of exactly this size.
                let req = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr().cast::<DrmModeAtomicUapi>())
                };
                // This synchronous-latch implementation deliberately refuses
                // ASYNC: the installed primary plane arms at vblank only.
                if req.reserved != 0
                    || req.flags & !(EVENT | TEST_ONLY | NONBLOCK | ALLOW_MODESET) != 0
                    || req.flags & (EVENT | TEST_ONLY) == EVENT | TEST_ONLY
                    || req.count_objs > 256
                {
                    return Err(FsError::InvalidData);
                }
                let count = req.count_objs as usize;
                if count != 0
                    && [
                        req.objs_ptr,
                        req.count_props_ptr,
                        req.props_ptr,
                        req.prop_values_ptr,
                    ]
                    .contains(&0)
                {
                    return Err(FsError::BadAddress);
                }
                let objects = if count == 0 {
                    Vec::new()
                } else {
                    words(&read(context, req.objs_ptr, count * 4)?)
                };
                let counts = if count == 0 {
                    Vec::new()
                } else {
                    words(&read(context, req.count_props_ptr, count * 4)?)
                };
                let total = counts
                    .iter()
                    .try_fold(0usize, |n, c| {
                        n.checked_add(*c as usize).filter(|n| *n <= 4096)
                    })
                    .ok_or(FsError::OutOfMemory)?;
                let props = if total == 0 {
                    Vec::new()
                } else {
                    words(&read(context, req.props_ptr, total * 4)?)
                };
                let values = if total == 0 {
                    Vec::new()
                } else {
                    read(context, req.prop_values_ptr, total * 8)?
                        .chunks_exact(8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        .collect()
                };
                Self::Atomic(OwnedAtomic {
                    flags: req.flags,
                    cookie: req.user_data,
                    objects,
                    counts,
                    props,
                    values,
                })
            }
            0xab | 0xba => {
                let obj = drm_uapi::ioc_nr(cmd) == 0xba;
                let b = read(context, arg, if obj { 20 } else { 16 })?;
                let w = words(&b);
                let kind = if obj { w[4] } else { DRM_MODE_OBJECT_CONNECTOR };
                if !matches!(
                    kind,
                    DRM_MODE_OBJECT_CRTC
                        | DRM_MODE_OBJECT_PLANE
                        | DRM_MODE_OBJECT_CONNECTOR
                        | DRM_MODE_OBJECT_ANY
                ) {
                    return Err(FsError::InvalidData);
                }
                Self::Property {
                    object: w[3],
                    kind,
                    prop: w[2],
                    value: u64::from_le_bytes(b[..8].try_into().unwrap()),
                }
            }
            0xb7 => {
                let w = words(&read(context, arg, 48)?);
                if w[3] != 0 {
                    return Err(FsError::InvalidData);
                }
                Self::Atomic(OwnedAtomic {
                    flags: ALLOW_MODESET,
                    cookie: 0,
                    objects: vec![w[0]],
                    counts: vec![10],
                    props: vec![
                        PLANE_CRTC_ID_PROP_ID,
                        PLANE_FB_ID_PROP_ID,
                        PLANE_CRTC_X_PROP_ID,
                        PLANE_CRTC_Y_PROP_ID,
                        PLANE_CRTC_W_PROP_ID,
                        PLANE_CRTC_H_PROP_ID,
                        PLANE_SRC_X_PROP_ID,
                        PLANE_SRC_Y_PROP_ID,
                        PLANE_SRC_H_PROP_ID,
                        PLANE_SRC_W_PROP_ID,
                    ],
                    values: vec![
                        w[1] as u64,
                        w[2] as u64,
                        w[4] as u64,
                        w[5] as u64,
                        w[6] as u64,
                        w[7] as u64,
                        w[8] as u64,
                        w[9] as u64,
                        w[10] as u64,
                        w[11] as u64,
                    ],
                })
            }
            0xaf => Self::Remove(words(&read(context, arg, 4)?)[0]),
            0xb1 => {
                let w = words(&read(context, arg, 24)?);
                if w[1] != 0 || w[3] > 256 {
                    return Err(FsError::InvalidData);
                }
                if w[3] != 0 {
                    let _ = read(
                        context,
                        u64::from(w[4]) | u64::from(w[5]) << 32,
                        w[3] as usize * 8,
                    )?;
                }
                Self::Dirty(w[0])
            }
            0xa3 | 0xbb => Self::Cursor(
                read(
                    context,
                    arg,
                    if drm_uapi::ioc_nr(cmd) == 0xbb {
                        36
                    } else {
                        28
                    },
                )?,
                None,
                false,
            ),
            _ => return Err(FsError::Unsupported),
        })
    }
}

struct Transaction(ModeState);
impl Drop for Transaction {
    fn drop(&mut self) {
        self.0.lock().intel_finish_transaction();
    }
}
enum Action {
    Present,
    Observe,
    Restore,
    Remove(u32),
    DropMaster,
    SetMaster,
    Color {
        primary: bool,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        dsb: Option<crate::intel_gpu_dsb::Timing>,
    },
    Cursor {
        bytes: Vec<u8>,
        object: Option<Arc<crate::intel_gpu_gem::GemObject>>,
        hardware: bool,
        timing: crate::intel_gpu_dsb::Timing,
    },
    Noop,
}
struct Plan {
    previous: Crtc,
    next: Crtc,
    framebuffer: Option<Framebuffer>,
    geometry: Geometry,
    action: Action,
    event: bool,
    cookie: u64,
    out: Option<u64>,
    fence: Option<i32>,
    test: bool,
    nonblock: bool,
    previous_ctm: u32,
    next_ctm: u32,
    previous_gamma: u32,
    next_gamma: u32,
}

fn same_timing(
    a: &crate::drm::ioctl::DrmModeModeInfo,
    b: &crate::drm::ioctl::DrmModeModeInfo,
) -> bool {
    (
        a.clock,
        a.hdisplay,
        a.hsync_start,
        a.hsync_end,
        a.htotal,
        a.hskew,
        a.vdisplay,
        a.vsync_start,
        a.vsync_end,
        a.vtotal,
        a.vscan,
        a.flags,
    ) == (
        b.clock,
        b.hdisplay,
        b.hsync_start,
        b.hsync_end,
        b.htotal,
        b.hskew,
        b.vdisplay,
        b.vsync_start,
        b.vsync_end,
        b.vtotal,
        b.vscan,
        b.flags,
    )
}
fn legacy_wire(m: crate::drm_uapi::DrmModeModeInfoUapi) -> crate::drm::ioctl::DrmModeModeInfo {
    crate::drm::ioctl::DrmModeModeInfo {
        clock: m.clock,
        hdisplay: m.hdisplay,
        hsync_start: m.hsync_start,
        hsync_end: m.hsync_end,
        htotal: m.htotal,
        hskew: m.hskew,
        vdisplay: m.vdisplay,
        vsync_start: m.vsync_start,
        vsync_end: m.vsync_end,
        vtotal: m.vtotal,
        vscan: m.vscan,
        vrefresh: m.vrefresh,
        flags: m.flags,
        r#type: m.r#type,
        name: m.name,
    }
}

impl Plan {
    #[cfg(any(test, feature = "kernel-test"))]
    fn stage(card: &Card, request: Request, geometry: Geometry) -> Result<Self, FsError> {
        Self::stage_from(card, request, geometry, None, None)
    }

    fn stage_from(
        card: &Card,
        request: Request,
        geometry: Geometry,
        previous: Option<Crtc>,
        previous_color: Option<(u32, u32)>,
    ) -> Result<Self, FsError> {
        let request = match request {
            Request::Property {
                object,
                kind,
                prop,
                value,
            } => {
                set_property_object(card, object, kind)?;
                Request::Atomic(OwnedAtomic {
                    flags: ALLOW_MODESET,
                    cookie: 0,
                    objects: vec![object],
                    counts: vec![1],
                    props: vec![prop],
                    values: vec![value],
                })
            }
            other => other,
        };
        let previous = previous
            .or_else(|| card.crtcs.first().cloned())
            .ok_or(FsError::NoDevice)?;
        let fixed = previous
            .mode
            .or_else(|| {
                card.connectors
                    .iter()
                    .flat_map(|c| &c.modes)
                    .copied()
                    .find(|m| (m.width, m.height) == (geometry.width, geometry.height))
            })
            .ok_or(FsError::NoDevice)?;
        let wire = card.mode_wire(&fixed);
        let (previous_ctm, previous_gamma) = previous_color.unwrap_or_else(|| {
            card.crtc_color(previous.id)
                .map_or((0, 0), |c| (c.ctm, c.gamma_lut))
        });
        let mut p = Self {
            previous_ctm,
            next_ctm: previous_ctm,
            previous_gamma,
            next_gamma: previous_gamma,
            next: previous.clone(),
            previous,
            framebuffer: None,
            geometry,
            action: Action::Present,
            event: false,
            cookie: 0,
            out: None,
            fence: None,
            test: false,
            nonblock: false,
        };
        let mut fb = p.next.primary_fb;
        let mut route = fb.map(|_| p.next.id);
        let mut primary_changed = false;
        let mut color = None;
        let mut gamma = None;
        let mut color_compatible = true;
        let mut color_primary = false;
        let mut rect = [
            p.next.x << 16,
            p.next.y << 16,
            geometry.width << 16,
            geometry.height << 16,
            0,
            0,
            geometry.width,
            geometry.height,
        ];
        match request {
            Request::Property { .. } => unreachable!("property request normalized before staging"),
            Request::SetMaster => {
                p.action = Action::SetMaster;
                return Ok(p);
            }
            Request::DropMaster => {
                p.next_ctm = 0;
                p.next_gamma = 0;
                p.action = Action::DropMaster;
                return Ok(p);
            }
            Request::Remove(id) => {
                card.framebuffer(id).map_err(|_| FsError::NotFound)?;
                p.action = Action::Remove(id);
                if p.next.primary_fb == Some(id) {
                    p.next_ctm = 0;
                    p.next_gamma = 0;
                    p.next.primary_fb = None;
                    p.next.enabled = false;
                    p.next.mode = None;
                }
                return Ok(p);
            }
            Request::Cursor(bytes, object, hardware) => {
                if !hardware && (p.next.x != 0 || p.next.y != 0) {
                    return Err(FsError::Unsupported);
                }
                let w = words(&bytes);
                if w[0] == 0 || w[0] & !3 != 0 || w[1] != p.next.id {
                    return Err(FsError::InvalidData);
                }
                if hardware
                    && w[0] & 1 != 0
                    && w[6] != 0
                    && (w[4] != 64
                        || w[5] != 64
                        || object
                            .as_ref()
                            .is_none_or(|o| o.size() < 16384 || o.is_userptr() || o.is_vram()))
                {
                    return Err(FsError::Unsupported);
                }
                if hardware
                    && w[0] & 2 != 0
                    && ((w[2] as i32).unsigned_abs() > 32767
                        || (w[3] as i32).unsigned_abs() > 32767)
                {
                    return Err(FsError::Unsupported);
                }
                p.action = Action::Cursor {
                    bytes,
                    object,
                    hardware,
                    timing: crate::intel_gpu_dsb::Timing {
                        clock: wire.clock,
                        width: wire.hdisplay,
                        height: wire.vdisplay,
                        htotal: wire.htotal,
                        vtotal: wire.vtotal,
                        flags: wire.flags,
                    },
                };
                if !hardware {
                    if let Some(id) = fb {
                        p.framebuffer =
                            Some(card.framebuffer(id).map_err(|_| FsError::NotFound)?.clone());
                    }
                }
                return Ok(p);
            }
            Request::Dirty(id) => {
                card.framebuffer(id).map_err(|_| FsError::NotFound)?;
                if p.next.primary_fb != Some(id) {
                    p.action = Action::Noop;
                    return Ok(p);
                }
            }
            Request::PageFlip(r) => {
                primary_changed = true;
                if r.flags & !EVENT != 0 || r.reserved != 0 {
                    return Err(FsError::InvalidData);
                }
                if r.crtc_id != p.next.id {
                    return Err(FsError::NotFound);
                }
                let old = card
                    .framebuffer(p.next.primary_fb.ok_or(FsError::Busy)?)
                    .map_err(|_| FsError::Busy)?;
                let target = card.framebuffer(r.fb_id).map_err(|_| FsError::NotFound)?;
                if target.format != old.format {
                    return Err(FsError::InvalidData);
                }
                if !p.next.enabled {
                    return Err(FsError::Busy);
                }
                fb = Some(r.fb_id);
                route = Some(p.next.id);
                p.event = r.flags & EVENT != 0;
                p.cookie = r.user_data;
            }
            Request::SetCrtc(r, connector) => {
                primary_changed = true;
                if r.crtc_id != p.next.id {
                    return Err(FsError::NotFound);
                }
                if r.x > 0xffff || r.y > 0xffff || r.mode_valid > 1 {
                    return Err(FsError::InvalidData);
                }
                if let Some(id) = connector {
                    card.connector(id).map_err(|_| FsError::NotFound)?;
                }
                if r.fb_id != 0 && r.mode_valid != 0 && !same_timing(&legacy_wire(r.mode), &wire) {
                    return Err(FsError::Unsupported);
                }
                fb = (r.fb_id != 0).then_some(r.fb_id);
                route = fb.map(|_| p.next.id);
                p.next.enabled = fb.is_some();
                p.next.mode = fb.map(|_| fixed);
                rect[0] = r.x << 16;
                rect[1] = r.y << 16;
            }
            Request::Atomic(a) => {
                if !atomic_card(card) {
                    return Err(FsError::Unsupported);
                }
                p.event = a.flags & EVENT != 0;
                p.cookie = a.cookie;
                p.test = a.flags & TEST_ONLY != 0;
                p.nonblock = a.flags & NONBLOCK != 0;
                if a.objects.len() != a.counts.len() {
                    return Err(FsError::InvalidData);
                }
                let mut at = 0usize;
                for (&object, &count) in a.objects.iter().zip(&a.counts) {
                    let end = at
                        .checked_add(count as usize)
                        .filter(|n| *n <= a.props.len() && *n <= a.values.len())
                        .ok_or(FsError::InvalidData)?;
                    for (&prop, &value) in a.props[at..end].iter().zip(&a.values[at..end]) {
                        if !((object == p.next.id
                            && matches!(
                                prop,
                                CRTC_CTM_PROP_ID
                                    | CRTC_GAMMA_LUT_PROP_ID
                                    | CRTC_OUT_FENCE_PTR_PROP_ID
                            ))
                            || (object == PLANE_ID_BASE
                                && matches!(
                                    prop,
                                    PLANE_IN_FENCE_FD_PROP_ID
                                        | PLANE_FB_ID_PROP_ID
                                        | PLANE_CRTC_ID_PROP_ID
                                        | PLANE_SRC_X_PROP_ID
                                        | PLANE_SRC_Y_PROP_ID
                                        | PLANE_SRC_W_PROP_ID
                                        | PLANE_SRC_H_PROP_ID
                                        | PLANE_CRTC_X_PROP_ID
                                        | PLANE_CRTC_Y_PROP_ID
                                        | PLANE_CRTC_W_PROP_ID
                                        | PLANE_CRTC_H_PROP_ID
                                )))
                        {
                            color_compatible = false;
                        }
                        if object == PLANE_ID_BASE {
                            color_primary |= prop != PLANE_IN_FENCE_FD_PROP_ID;
                            match prop {
                                PLANE_FB_ID_PROP_ID => {
                                    primary_changed = true;
                                    fb = (value != 0).then(|| u32_value(value)).transpose()?
                                }
                                PLANE_CRTC_ID_PROP_ID => {
                                    primary_changed = true;
                                    route = (value != 0).then(|| u32_value(value)).transpose()?
                                }
                                PLANE_SRC_X_PROP_ID | PLANE_SRC_Y_PROP_ID | PLANE_SRC_W_PROP_ID
                                | PLANE_SRC_H_PROP_ID => {
                                    let v = u32_value(value)?;
                                    if v & 0xffff != 0 {
                                        return Err(FsError::InvalidData);
                                    }
                                    let i = (prop - PLANE_SRC_X_PROP_ID) as usize;
                                    rect[i] = v;
                                }
                                PLANE_CRTC_X_PROP_ID | PLANE_CRTC_Y_PROP_ID
                                | PLANE_CRTC_W_PROP_ID | PLANE_CRTC_H_PROP_ID => {
                                    rect[4 + (prop - PLANE_CRTC_X_PROP_ID) as usize] =
                                        u32_value(value)?
                                }
                                PLANE_IN_FENCE_FD_PROP_ID => {
                                    let fd = value as i64;
                                    if fd < -1 || fd > i32::MAX as i64 {
                                        return Err(FsError::InvalidData);
                                    }
                                    p.fence = (fd >= 0).then_some(fd as i32);
                                }
                                _ => return Err(FsError::InvalidData),
                            }
                        } else if object == p.next.id {
                            match prop {
                                CRTC_CTM_PROP_ID => {
                                    if !card.intel_color(p.next.id) {
                                        return Err(FsError::Unsupported);
                                    }
                                    let blob = u32_value(value)?;
                                    if blob != 0
                                        && card.property_blob(blob).ok_or(FsError::NotFound)?.len()
                                            != 72
                                    {
                                        return Err(FsError::InvalidData);
                                    }
                                    color = Some(blob);
                                }
                                CRTC_GAMMA_LUT_PROP_ID => {
                                    if !card.intel_color(p.next.id) {
                                        return Err(FsError::Unsupported);
                                    }
                                    let id = u32_value(value)?;
                                    if id != 0 {
                                        let bytes =
                                            card.property_blob(id).ok_or(FsError::NotFound)?;
                                        if bytes.len() != crate::intel_gpu_color::LUT_SIZE * 8 {
                                            return Err(FsError::InvalidData);
                                        }
                                    }
                                    gamma = Some(id);
                                }
                                CRTC_ACTIVE_PROP_ID => {
                                    if value > 1 {
                                        return Err(FsError::InvalidData);
                                    }
                                    p.next.enabled = value != 0;
                                }
                                CRTC_MODE_ID_PROP_ID => {
                                    p.next.mode = if value == 0 {
                                        None
                                    } else {
                                        let bytes = card
                                            .property_blob(u32_value(value)?)
                                            .ok_or(FsError::NotFound)?;
                                        let m =
                                            crate::drm::ioctl::DrmModeModeInfo::from_bytes(bytes)
                                                .ok_or(FsError::InvalidData)?;
                                        if !same_timing(&m, &wire) {
                                            return Err(FsError::Unsupported);
                                        }
                                        Some(fixed)
                                    };
                                }
                                CRTC_OUT_FENCE_PTR_PROP_ID => p.out = (value != 0).then_some(value),
                                _ => return Err(FsError::InvalidData),
                            }
                        } else if card.connector(object).is_ok() {
                            if prop != CONNECTOR_CRTC_ID_PROP_ID || value != u64::from(p.next.id) {
                                return Err(FsError::Unsupported);
                            }
                        } else {
                            return Err(FsError::NotFound);
                        }
                    }
                    at = end;
                }
                if at != a.props.len() || at != a.values.len() {
                    return Err(FsError::InvalidData);
                }
                if a.objects.is_empty() {
                    if p.event {
                        return Err(FsError::InvalidData);
                    }
                    p.action = Action::Noop;
                    return Ok(p);
                }
                if (p.next.enabled != p.previous.enabled || p.next.mode != p.previous.mode)
                    && a.flags & ALLOW_MODESET == 0
                {
                    return Err(FsError::InvalidData);
                }
            }
        }
        if !p.next.enabled || fb.is_none() || route.is_none() {
            // Full restoration selects the retained origin-zero console;
            // an inherited panned rectangle must not prevent disabling it.
            rect[0] = 0;
            rect[1] = 0;
        }
        // Every panned primary arm uses the retained DSB owner, even if the
        // client changes no color properties. This also covers returning to
        // origin zero and PAGE_FLIP inheriting its queued source rectangle.
        let viewport = Viewport {
            x: rect[0] >> 16,
            y: rect[1] >> 16,
        };
        let panning = (primary_changed || color_primary || (color.is_none() && gamma.is_none()))
            && (viewport != Viewport::default() || p.previous.x != 0 || p.previous.y != 0)
            && p.next.enabled
            && fb.is_some()
            && route.is_some();
        color_primary |= panning;
        if color.is_some() || gamma.is_some() || panning {
            if !card.intel_color(p.next.id) {
                return Err(FsError::Unsupported);
            }
            if !color_compatible || !p.previous.enabled || p.previous.mode.is_none() {
                return Err(FsError::Unsupported);
            }
            if color_primary {
                if rect
                    != [
                        rect[0],
                        rect[1],
                        geometry.width << 16,
                        geometry.height << 16,
                        0,
                        0,
                        geometry.width,
                        geometry.height,
                    ]
                    || route != Some(p.next.id)
                {
                    return Err(FsError::Unsupported);
                }
                let id = fb.ok_or(FsError::Unsupported)?;
                let target = card.framebuffer(id).map_err(|_| FsError::NotFound)?;
                let object = target.intel.as_ref().ok_or(FsError::Unsupported)?;
                if target.pitch != geometry.pitch
                    || target.format != PixelFormat::Xrgb8888
                    || target.modifier != 0
                    || target.offsets != [0, 0]
                    || target.chroma_pitch != 0
                    || !object.object.is_wc()
                    || !object.object.scanout()
                    || object.object.is_vram()
                    || object.object.is_userptr()
                {
                    return Err(FsError::Unsupported);
                }
                if viewport
                    .x
                    .checked_add(geometry.width)
                    .is_none_or(|x| x > target.width)
                    || viewport
                        .y
                        .checked_add(geometry.height)
                        .is_none_or(|y| y > target.height)
                {
                    return Err(FsError::NoSpace);
                }
                let (_, _, extent) = viewport
                    .layout(geometry)
                    .map_err(|_| FsError::InvalidData)?;
                if extent > object.object.size() {
                    return Err(FsError::InvalidData);
                }
                p.framebuffer = Some(target.clone());
                p.next.primary_fb = Some(id);
                p.next.x = viewport.x;
                p.next.y = viewport.y;
            }
            if let Some(blob) = color {
                p.next_ctm = blob;
            }
            if let Some(id) = gamma {
                p.next_gamma = id;
            }
            // MTL's single-buffered LUT and independent color arms require
            // the owned DSB chain for active replacement/combined changes.
            let needs_dsb = color_primary
                || (p.next_ctm != p.previous_ctm && p.next_gamma != p.previous_gamma)
                || (p.previous_gamma != 0 && p.next_gamma != 0 && p.next_gamma != p.previous_gamma);
            let dsb = needs_dsb.then_some(crate::intel_gpu_dsb::Timing {
                clock: wire.clock,
                width: wire.hdisplay,
                height: wire.vdisplay,
                htotal: wire.htotal,
                vtotal: wire.vtotal,
                flags: wire.flags,
            });
            if dsb.is_some_and(|timing| !timing.valid()) {
                return Err(FsError::Unsupported);
            }
            let coefficients = if p.next_ctm == 0 {
                None
            } else {
                let bytes = card.property_blob(p.next_ctm).ok_or(FsError::NotFound)?;
                if bytes.len() != 72 {
                    return Err(FsError::InvalidData);
                }
                let mut coefficients = [0; 9];
                for (c, bytes) in coefficients.iter_mut().zip(bytes.chunks_exact(8)) {
                    *c = u64::from_le_bytes(bytes.try_into().unwrap());
                }
                Some(coefficients)
            };
            let lut = if p.next_gamma == 0 {
                None
            } else {
                Some(crate::intel_gpu_color::Lut::decode(
                    card.property_blob(p.next_gamma).ok_or(FsError::NotFound)?,
                )?)
            };
            p.action = Action::Color {
                primary: color_primary,
                coefficients,
                lut,
                dsb,
            };
            return Ok(p);
        }
        if rect
            != [
                0,
                0,
                geometry.width << 16,
                geometry.height << 16,
                0,
                0,
                geometry.width,
                geometry.height,
            ]
        {
            return Err(FsError::Unsupported);
        }
        if fb.is_none() && route.is_some() {
            route = None;
        }
        if route.is_some_and(|id| id != p.next.id) {
            return Err(FsError::InvalidData);
        }
        if !primary_changed && fb.is_none() && p.next.enabled && p.next.mode.is_some() {
            // Merely asking for a vblank/out-fence or repeating unchanged
            // CRTC/connector metadata does not disable the boot console.
            p.action = Action::Observe;
        } else if !p.next.enabled || fb.is_none() || route.is_none() {
            p.next_ctm = 0;
            p.next_gamma = 0;
            p.next.primary_fb = None;
            p.next.enabled = false;
            p.next.mode = None;
            p.next.x = 0;
            p.next.y = 0;
            p.action = Action::Restore;
        } else {
            if p.next.mode.is_none() {
                return Err(FsError::InvalidData);
            }
            let target = card
                .framebuffer(fb.unwrap())
                .map_err(|_| FsError::NotFound)?;
            if target.width < geometry.width || target.height < geometry.height {
                return Err(FsError::NoSpace);
            }
            if target.modifier != 0
                || target.offsets != [0, 0]
                || target.chroma_pitch != 0
                || !matches!(target.format, PixelFormat::Xrgb8888 | PixelFormat::Argb8888)
            {
                return Err(FsError::Unsupported);
            }
            if target.intel.is_none() && card.dumb_backing(target.gem_handle).is_none() {
                return Err(FsError::Unsupported);
            }
            let extent = u64::from(target.pitch) * u64::from(geometry.height);
            let size = if let Some(intel) = &target.intel {
                if intel.object.is_vram() || intel.object.is_userptr() {
                    return Err(FsError::Unsupported);
                }
                intel.object.size()
            } else {
                card.dumb_backing(target.gem_handle)
                    .ok_or(FsError::Unsupported)?
                    .byte_len as u64
            };
            if target.pitch < geometry.width * 4 || extent > size {
                return Err(FsError::InvalidData);
            }
            p.geometry.pitch = target.pitch;
            p.framebuffer = Some(target.clone());
            p.next.primary_fb = fb;
            p.next.x = 0;
            p.next.y = 0;
        }
        Ok(p)
    }
    fn still_valid(&self, card: &Card, open: u64) -> bool {
        if !card.is_master(open) {
            return false;
        }
        if card
            .crtc_color(self.previous.id)
            .map_or((0, 0), |c| (c.ctm, c.gamma_lut))
            != (self.previous_ctm, self.previous_gamma)
        {
            return false;
        }
        let Ok(current) = card.crtc(self.previous.id) else {
            return false;
        };
        if (
            current.enabled,
            current.mode,
            current.primary_fb,
            current.x,
            current.y,
        ) != (
            self.previous.enabled,
            self.previous.mode,
            self.previous.primary_fb,
            self.previous.x,
            self.previous.y,
        ) {
            return false;
        }
        if let Some(fb) = &self.framebuffer {
            if fb
                .gem_owner()
                .is_some_and(|owner| card.intel_owner_closed(owner))
            {
                return false;
            }
            let Ok(current) = card.framebuffer(fb.id) else {
                return false;
            };
            if current.gem_handle != fb.gem_handle
                || current.pitch != fb.pitch
                || current.format != fb.format
                || current.width != fb.width
                || current.height != fb.height
                || current.offsets != fb.offsets
                || current.chroma_pitch != fb.chroma_pitch
                || current.modifier != fb.modifier
                || current.gem_owner() != fb.gem_owner()
            {
                return false;
            }
            match (&current.intel, &fb.intel) {
                (Some(a), Some(b)) if Arc::ptr_eq(&a.object, &b.object) => {}
                (None, None) => {}
                _ => return false,
            }
        }
        true
    }
}

trait Backend {
    fn valid(&self) -> Result<(), FsError> {
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn geometry(&self) -> Geometry;
    fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb;
    fn check(&self, g: Geometry) -> Result<(), FsError>;
    fn present<'a>(
        &'a mut self,
        o: Arc<crate::intel_gpu_gem::GemObject>,
        g: Geometry,
    ) -> FsFuture<'a, FlipStamp>;
    fn restore(&mut self) -> FsFuture<'_, ()>;
    fn color_published(&mut self) {}
    fn surface(&mut self) -> FsFuture<'_, ()> {
        self.restore()
    }
    fn color(
        &mut self,
        _coefficients: Option<[u64; 9]>,
        _lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        _dsb: Option<crate::intel_gpu_dsb::Timing>,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn present_color(
        &mut self,
        _object: Arc<crate::intel_gpu_gem::GemObject>,
        _geometry: Geometry,
        _viewport: Viewport,
        _coefficients: Option<[u64; 9]>,
        _lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        _timing: crate::intel_gpu_dsb::Timing,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn cursor(
        &mut self,
        _object: Option<Arc<crate::intel_gpu_gem::GemObject>>,
        _replace: bool,
        _position: Option<(i32, i32)>,
        _timing: crate::intel_gpu_dsb::Timing,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp>;
    fn copy<'a>(&'a mut self, frame: &'a Framebuffer, mode: &'a ModeState) -> FsFuture<'a, ()> {
        alloc::boxed::Box::pin(copy_frame(frame, mode, self.console_fb()))
    }
}
impl<M: crate::intel_gpu_kms::Platform> Backend for crate::intel_gpu_kms::Guard<'_, M> {
    fn valid(&self) -> Result<(), FsError> {
        self.ownership_valid()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn geometry(&self) -> Geometry {
        self.console_geometry()
    }
    fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb {
        self.console_fb()
    }
    fn check(&self, g: Geometry) -> Result<(), FsError> {
        self.check(g)
    }
    fn present<'a>(
        &'a mut self,
        o: Arc<crate::intel_gpu_gem::GemObject>,
        g: Geometry,
    ) -> FsFuture<'a, FlipStamp> {
        alloc::boxed::Box::pin(self.present(o, g))
    }
    fn restore(&mut self) -> FsFuture<'_, ()> {
        alloc::boxed::Box::pin(self.restore_console())
    }
    fn color_published(&mut self) {
        self.confirm_ctm();
    }
    fn surface(&mut self) -> FsFuture<'_, ()> {
        Box::pin(self.restore_surface())
    }
    fn color(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        dsb: Option<crate::intel_gpu_dsb::Timing>,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(self.set_color_with_dsb(coefficients, lut, dsb))
    }
    fn present_color(
        &mut self,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        geometry: Geometry,
        viewport: Viewport,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        timing: crate::intel_gpu_dsb::Timing,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(self.present_color(object, geometry, viewport, coefficients, lut, timing))
    }
    fn cursor(
        &mut self,
        object: Option<Arc<crate::intel_gpu_gem::GemObject>>,
        replace: bool,
        position: Option<(i32, i32)>,
        timing: crate::intel_gpu_dsb::Timing,
    ) -> FsFuture<'_, FlipStamp> {
        Box::pin(self.cursor(object, replace, position, timing))
    }
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp> {
        alloc::boxed::Box::pin(self.wait_vblank())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
async fn wait_fences(fences: Vec<Arc<dyn narf_filesystem::DrmFence>>) -> Result<(), FsError> {
    let deadline = narf_time::monotonic_ns().saturating_add(15_000_000_000);
    while fences.iter().any(|f| !f.is_signalled()) {
        if narf_time::monotonic_ns() >= deadline {
            return Err(FsError::TimedOut);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ns(100_000).as_instant()).await;
    }
    Ok(())
}

async fn copy_frame(
    frame: &Framebuffer,
    mode: &ModeState,
    console: narf_graphics_driver::generic::GenericFb,
) -> Result<(), FsError> {
    copy_frame_to_query(
        frame,
        mode,
        console,
        crate::drm_fb_hook::query_scanout,
        narf_console::fb_take_for_user,
    )
    .await?;
    narf_console::bump_scanout_gen();
    crate::drm_fb_hook::flush_scanout();
    Ok(())
}

/// Production copy and native mapped-destination regression share this
/// source preparation, epoch and row loop. The claim callback runs only once
/// the current hook matches this card's restored physical console.
async fn copy_frame_to_query<Q, C>(
    frame: &Framebuffer,
    mode: &ModeState,
    console: narf_graphics_driver::generic::GenericFb,
    query: Q,
    claim: C,
) -> Result<(), FsError>
where
    Q: FnOnce() -> Option<crate::drm_fb_hook::ScanoutGeom> + Send,
    C: FnOnce() + Send,
{
    if !matches!(frame.format, PixelFormat::Xrgb8888 | PixelFormat::Argb8888)
        || frame.width < console.width
        || frame.height < console.height
        || console.bpp != 32
    {
        return Err(FsError::Unsupported);
    }
    let mut pages = None;
    let mut phys = None;
    let size = if let Some(intel) = &frame.intel {
        // The transaction owner resolves writer dependencies before obtaining
        // the display session, so reset recovery never waits behind a fence.

        if !intel.object.sync_for_cpu_read() {
            return Err(crate::intel_gpu_user::io_error());
        }
        pages = Some(intel.object.pages().collect::<Vec<_>>());
        intel.object.size()
    } else {
        let source = {
            mode.lock()
                .dumb_backing(frame.gem_handle)
                .map(|b| (b.phys, b.byte_len))
                .ok_or(FsError::Unsupported)?
        };
        phys = Some(source.0);
        source.1 as u64
    };
    if u64::from(frame.pitch) * u64::from(console.height) > size || frame.pitch < console.width * 4
    {
        return Err(FsError::InvalidData);
    }
    {
        // SAFETY: the driver restored this exact console mapping and holds
        // its session across the copy; this epoch excludes retirement while
        // these raw destination accesses run. There is no await in the view.
        let view = unsafe { crate::scanout_access::snapshot(query) };
        let info = (*view).ok_or(FsError::NoDevice)?;
        if (info.phys, info.width, info.height, info.stride_bytes)
            != (console.addr, console.width, console.height, console.pitch)
        {
            return Err(FsError::Busy);
        }
        claim();
        let len = console.width as usize * 4;
        for row in 0..console.height {
            let offset = u64::from(row) * u64::from(console.pitch);
            // Adopted GenericScanout hooks retain their actual kernel VA in
            // `virt`, even for this physical system-memory console surface.
            // The current hook/epoch owns that alias; phys still must match.
            let dst = if info.virt != 0 {
                (info.virt + offset) as *mut u8
            } else {
                narf_memory::PhysAddr::new(console.addr + offset).kernel_mut_ptr::<u8>()
            };
            if let Some(pages) = &pages {
                // SAFETY: retained source pages and validated pitch/extent;
                // the owned console has a full writable destination row.
                unsafe { copy_object_row(pages, size, frame.pitch, row, dst, len) };
            } else {
                let src = narf_memory::PhysAddr::new(
                    phys.expect("dumb source") + u64::from(row) * u64::from(frame.pitch),
                )
                .kernel_ptr::<u8>();
                // SAFETY: Card transaction excludes destruction of the
                // validated dumb source; console and source allocations differ.
                unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
            }
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[allow(clippy::too_many_arguments)]
async fn execute<B: Backend>(
    backend: &mut B,
    mode: &ModeState,
    open: u64,
    request: Request,
    context: &dyn IoctlContext,
    events: Option<&Events>,
    out: Option<&OutFences>,
) -> Result<u64, FsError> {
    let plan = {
        let card = mode.lock();
        if !card.is_master(open) {
            return Err(FsError::PermissionDenied);
        }
        Plan::stage(&card, request, backend.geometry())?
    };
    if plan.test {
        if let Some(fd) = plan.fence {
            context.sync_file_fences(fd).ok_or(FsError::InvalidData)?;
        }
        return Ok(0);
    }
    let reservation = if plan.event {
        Some(
            FlipEventReservation::reserve(events.ok_or(FsError::InvalidData)?)
                .map_err(|_| FsError::OutOfMemory)?,
        )
    } else {
        None
    };
    if let Some(ptr) = plan.out {
        if out.is_none() {
            return Err(FsError::Unsupported);
        }
        context.write(ptr, &(-1i32).to_le_bytes())?;
    }
    if let Some(fd) = plan.fence {
        wait_fences(context.sync_file_fences(fd).ok_or(FsError::InvalidData)?).await?;
    }
    wait_fences(plan_dependencies(&plan, mode)?).await?;
    let out_ptr = plan.out;
    let stamp = execute_plan(backend, mode, open, &plan, reservation).await?;
    if let (Some(ptr), Some(sink)) = (out_ptr, out) {
        sink.lock().push((ptr, stamp.ns));
    }
    Ok(0)
}

/// Both the close task and a replacement master's first transaction consume
/// the same marker under the display Session. Software master assignment alone
/// cannot skip restoration, and an old close task cannot restore newer state.
async fn finish_master_release<B: Backend>(
    backend: &mut B,
    mode: &ModeState,
) -> Result<(), FsError> {
    if !mode.lock().intel_master_restore_pending() {
        return Ok(());
    }
    backend.restore().await?;
    backend.valid()?;
    mode.lock().intel_master_restored();
    Ok(())
}
pub(crate) async fn restore_released_master<M: crate::intel_gpu_kms::Platform>(
    session: &mut crate::intel_gpu_kms::Guard<'_, M>,
    mode: &ModeState,
) -> Result<(), FsError> {
    finish_master_release(session, mode).await
}

async fn execute_plan<B: Backend>(
    backend: &mut B,
    mode: &ModeState,
    open: u64,
    plan: &Plan,
    reservation: Option<FlipEventReservation>,
) -> Result<FlipStamp, FsError> {
    finish_master_release(backend, mode).await?;
    if matches!(plan.action, Action::SetMaster) {
        mode.lock().set_master(open).map_err(|_| FsError::Busy)?;
        return Ok(FlipStamp {
            ns: narf_time::monotonic_ns(),
            sequence: 0,
        });
    }
    {
        let mut card = mode.lock();
        if !plan.still_valid(&card, open) {
            return Err(FsError::Busy);
        }
        card.intel_begin_transaction(open)?;
    }
    let _transaction = Transaction(mode.clone());
    let mut stamp = None;
    match &plan.action {
        Action::Noop => {}
        Action::SetMaster => unreachable!("handled before transaction"),
        Action::DropMaster => {
            backend.restore().await?;
        }
        Action::Remove(id) => {
            if plan.previous.primary_fb == Some(*id) {
                backend.restore().await?;
            }
        }
        Action::Restore => {
            backend.restore().await?;
            stamp = Some(backend.vblank().await?);
        }
        Action::Observe => {
            backend.surface().await?;
            stamp = Some(backend.vblank().await?);
        }
        Action::Color {
            primary,
            coefficients,
            lut,
            dsb,
        } => {
            stamp = Some(if *primary {
                let object = direct_object(plan.framebuffer.as_ref().ok_or(FsError::InvalidData)?)?;
                backend
                    .present_color(
                        object,
                        plan.geometry,
                        Viewport {
                            x: plan.next.x,
                            y: plan.next.y,
                        },
                        *coefficients,
                        lut.clone(),
                        dsb.ok_or(FsError::Unsupported)?,
                    )
                    .await?
            } else {
                backend.color(*coefficients, lut.clone(), *dsb).await?
            });
        }
        Action::Present => {
            let fb = plan.framebuffer.as_ref().ok_or(FsError::InvalidData)?;
            let direct = fb.intel.as_ref().filter(|i| {
                fb.format == PixelFormat::Xrgb8888
                    && i.object.is_wc()
                    && i.object.scanout()
                    && !i.object.is_vram()
                    && !i.object.is_userptr()
            });
            let direct = if direct.is_some() {
                match backend.check(plan.geometry) {
                    Ok(()) => true,
                    Err(FsError::Unsupported | FsError::InvalidData) => false,
                    Err(e) => return Err(e),
                }
            } else {
                false
            };
            if direct {
                let object = direct_object(fb)?;
                stamp = Some(match backend.present(object.clone(), plan.geometry).await {
                    Ok(stamp) => stamp,
                    // The display owner uses Unsupported only for admission
                    // before arm. A hard/lost/pending hardware error must keep
                    // its owners and cannot silently turn into CPU presentation.
                    Err(FsError::Unsupported) => {
                        backend.surface().await?;
                        backend.copy(fb, mode).await?;
                        backend.vblank().await?
                    }
                    Err(error) => return Err(error),
                });
            } else {
                backend.surface().await?;
                backend.copy(fb, mode).await?;
                stamp = Some(backend.vblank().await?);
            }
        }
        Action::Cursor {
            bytes,
            object,
            hardware,
            timing,
        } => {
            let w = words(bytes);
            if *hardware {
                stamp = Some(
                    backend
                        .cursor(
                            object.clone(),
                            w[0] & 1 != 0,
                            (w[0] & 2 != 0).then_some((w[2] as i32, w[3] as i32)),
                            *timing,
                        )
                        .await?,
                );
            } else {
                backend.surface().await?;
                if let Some(fb) = &plan.framebuffer {
                    backend.copy(fb, mode).await?;
                }
                let w = words(bytes);
                if w[0] & 1 != 0 {
                    if w[6] == 0 {
                        narf_console::user_cursor_hide();
                    } else {
                        narf_console::user_cursor_show();
                    }
                }
                if w[0] & 2 != 0 {
                    let (hx, hy) = if w.len() == 9 {
                        (w[7] as i32, w[8] as i32)
                    } else {
                        (0, 0)
                    };
                    let x =
                        (i64::from(w[2] as i32) + i64::from(hx)).clamp(0, u32::MAX as i64) as u32;
                    let y =
                        (i64::from(w[3] as i32) + i64::from(hy)).clamp(0, u32::MAX as i64) as u32;
                    narf_console::user_cursor_move(x, y);
                }
            }
        }
    }
    // This is the completion linearization witness. A reset/loss after the
    // final await must not turn an abandoned surface into a success event.
    backend.valid()?;
    let published = {
        let mut card = mode.lock();
        if !plan.still_valid(&card, open) {
            false
        } else {
            match &plan.action {
                Action::DropMaster => {
                    card.drop_master(open).map_err(|_| FsError::InvalidData)?;
                }
                Action::Remove(id) => {
                    if let Some((phys, order)) = card.rmfb(*id).map_err(|_| FsError::NotFound)? {
                        narf_memory::frame::free_pages(
                            narf_memory::frame::PhysFrame::new(narf_memory::PhysAddr::new(phys)),
                            order,
                        );
                    }
                }
                Action::Noop
                | Action::Observe
                | Action::Cursor { .. }
                | Action::SetMaster
                | Action::Color { primary: false, .. } => {}
                Action::Present | Action::Restore | Action::Color { primary: true, .. } => {
                    *card.crtc_mut(plan.next.id).map_err(|_| FsError::NotFound)? =
                        plan.next.clone();
                }
            }
            if let Some(color) = card.crtc_color.iter_mut().find(|c| c.crtc == plan.next.id) {
                color.ctm = plan.next_ctm;
                color.gamma_lut = plan.next_gamma;
            }
            card.collect_blobs();
            if matches!(plan.action, Action::Color { .. }) {
                backend.color_published();
            }
            if let Some(reservation) = reservation {
                reservation.complete(
                    plan.cookie,
                    plan.next.id,
                    stamp.ok_or(FsError::InvalidData)?,
                );
            }
            true
        }
    };
    if !published {
        backend.restore().await?;
        backend.valid()?;
        // The failed transaction restored the kernel console, including its
        // color. Keep subsequent admission consistent with that real image.
        mode.lock().intel_master_restored();
        return Err(FsError::Busy);
    }
    Ok(stamp.unwrap_or(FlipStamp {
        ns: narf_time::monotonic_ns(),
        sequence: 0,
    }))
}

fn plan_dependencies(
    plan: &Plan,
    mode: &ModeState,
) -> Result<Vec<Arc<dyn narf_filesystem::DrmFence>>, FsError> {
    if let Action::Cursor {
        object: Some(object),
        hardware: true,
        ..
    } = &plan.action
    {
        return Ok(object.dma_buf.resv.fences(DmaResvUsage::Write));
    }
    let Some(fb) = &plan.framebuffer else {
        return Ok(Vec::new());
    };
    if let Some(intel) = &fb.intel {
        Ok(intel.object.dma_buf.resv.fences(DmaResvUsage::Write))
    } else {
        Ok(mode
            .lock()
            .dumb_backing(fb.gem_handle)
            .ok_or(FsError::NotFound)?
            .dma_buf
            .resv
            .fences(DmaResvUsage::Write))
    }
}

fn direct_object(frame: &Framebuffer) -> Result<Arc<crate::intel_gpu_gem::GemObject>, FsError> {
    frame
        .intel
        .as_ref()
        .map(|i| i.object.clone())
        .ok_or(FsError::Unsupported)
}

/// Shared foreground boundary for the real dispatcher and native PCI models.
/// All user copies/FD lookups finish before the owned job can reach the worker.
#[allow(clippy::too_many_arguments)]
async fn admit_with_gem(
    queue: &queue::Queue,
    open: u64,
    cmd: u32,
    arg: u64,
    context: &dyn IoctlContext,
    events: Option<&Events>,
    geometry: Geometry,
    epoch: u64,
    gem: Option<&crate::intel_gpu_gem::GemState>,
) -> Result<queue::Submitted, queue::SubmitError> {
    if drm_uapi::ioc_nr(cmd) != 0x1e && !queue.is_master(open) {
        return Err(FsError::PermissionDenied.into());
    }
    let mut request = Request::copy(cmd, arg, context)?;
    if let (Request::Cursor(bytes, object, hardware), Some(gem)) = (&mut request, gem) {
        let w = words(bytes);
        if w[0] == 0 || w[0] & !3 != 0 {
            return Err(FsError::InvalidData.into());
        }
        if w[0] & 1 != 0 && w[6] != 0 {
            *object = Some(gem.object(w[6])?);
        }
        *hardware = true;
    }
    queue
        .submit(open, request, geometry, epoch, context, events)
        .await
}

#[cfg(any(test, feature = "kernel-test"))]
#[allow(clippy::too_many_arguments)]
async fn admit(
    queue: &queue::Queue,
    open: u64,
    cmd: u32,
    arg: u64,
    context: &dyn IoctlContext,
    events: Option<&Events>,
    geometry: Geometry,
    epoch: u64,
) -> Result<queue::Submitted, queue::SubmitError> {
    admit_with_gem(
        queue, open, cmd, arg, context, events, geometry, epoch, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    index: u32,
    open: u64,
    cmd: u32,
    arg: u64,
    context: &dyn IoctlContext,
    events: Option<&Events>,
    out: Option<&OutFences>,
    gem: &crate::intel_gpu_gem::GemState,
) -> Option<Result<u64, FsError>> {
    if !mutates(cmd) {
        return None;
    }
    let display = crate::intel_gpu_kms::display(index)?;
    Some(
        async {
            let mode = crate::drm_registry::mode_state(index).ok_or(FsError::Unsupported)?;
            let queue = queue::for_card(index, mode.clone());
            let geometry = display.console_geometry();
            let submitted = match admit_with_gem(
                &queue,
                open,
                cmd,
                arg,
                context,
                events,
                geometry,
                display.epoch(),
                (crate::drm_registry::mode_state(index).is_some_and(|card| card.lock().intel_ctm))
                    .then_some(gem),
            )
            .await
            {
                Ok(submitted) => submitted,
                Err(queue::SubmitError::Io(error)) => return Err(error),
                Err(queue::SubmitError::NoDescriptor) => return Ok((-24i64) as u64),
            };
            if let Some((completion, start, nonblock)) = submitted {
                if start {
                    let queue = queue.clone();
                    // Scheduler admission is infallible (TaskId, not Result);
                    // the independent task survives cancellation of this ioctl.
                    let _worker = narf_scheduler::spawn_stackful(async move {
                        let mut worker = queue::DisplayWorker { display, mode };
                        queue.run(&mut worker).await;
                    });
                }
                if !nonblock {
                    completion.result_async().await?;
                }
            }
            let _ = out; // Other vendors retain the legacy deadline export sink.
            Ok(0)
        }
        .await,
    )
}

#[path = "intel_gpu_kms_queue.rs"]
mod queue;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_kms_ioctl_tests.rs"]
mod tests;
