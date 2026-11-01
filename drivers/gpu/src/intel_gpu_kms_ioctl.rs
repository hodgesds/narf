//! Intel KMS transactions: copy requests once, wait without IRQ-safe locks,
//! and publish software state/signalling only after witnessed display latch.
//! Fixed-mode primary presentation; Linux drm_atomic_uapi.c/drm_crtc.c and
//! intel_display_irq.c at b90c984d615e8ce2af96f5b1411a962d83fed2ad.
use super::*;
use crate::drm::card::{Card, Crtc, FlipEventReservation, FlipStamp, Framebuffer, PixelFormat};
use crate::intel_gpu_scanout::Geometry;
use narf_filesystem::FsFuture;

type ModeState = Arc<narf_lib::sync::IrqSafeSpinLock<Card>>;
type Events = narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>;
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
    Cursor(Vec<u8>),
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
            0xa3 | 0xbb => Self::Cursor(read(
                context,
                arg,
                if drm_uapi::ioc_nr(cmd) == 0xbb {
                    36
                } else {
                    28
                },
            )?),
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
    Cursor(Vec<u8>),
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
    fn stage(card: &Card, request: Request, geometry: Geometry) -> Result<Self, FsError> {
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
        let previous = card.crtcs.first().ok_or(FsError::NoDevice)?.clone();
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
        let mut p = Self {
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
        };
        let mut fb = p.next.primary_fb;
        let mut route = fb.map(|_| p.next.id);
        let mut primary_changed = false;
        let mut rect = [
            0,
            0,
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
                p.action = Action::Noop;
                return Ok(p);
            }
            Request::DropMaster => {
                p.action = Action::DropMaster;
                return Ok(p);
            }
            Request::Remove(id) => {
                card.framebuffer(id).map_err(|_| FsError::NotFound)?;
                p.action = Action::Remove(id);
                if p.next.primary_fb == Some(id) {
                    p.next.primary_fb = None;
                    p.next.enabled = false;
                    p.next.mode = None;
                }
                return Ok(p);
            }
            Request::Cursor(bytes) => {
                let w = words(&bytes);
                if w[0] == 0 || w[0] & !3 != 0 || w[1] != p.next.id {
                    return Err(FsError::InvalidData);
                }
                p.action = Action::Cursor(bytes);
                if let Some(id) = fb {
                    p.framebuffer =
                        Some(card.framebuffer(id).map_err(|_| FsError::NotFound)?.clone());
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
                if r.x != 0 || r.y != 0 || r.mode_valid > 1 {
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
            }
            Request::Atomic(a) => {
                if !atomic_card(card) {
                    return Err(FsError::Unsupported);
                }
                p.event = a.flags & EVENT != 0;
                p.cookie = a.cookie;
                p.test = a.flags & TEST_ONLY != 0;
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
                        if object == PLANE_ID_BASE {
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
            p.next.primary_fb = None;
            p.next.enabled = false;
            p.next.mode = None;
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
    fn geometry(&self) -> Geometry;
    fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb;
    fn check(&self, g: Geometry) -> Result<(), FsError>;
    fn present<'a>(
        &'a mut self,
        o: Arc<crate::intel_gpu_gem::GemObject>,
        g: Geometry,
    ) -> FsFuture<'a, FlipStamp>;
    fn restore(&mut self) -> FsFuture<'_, ()>;
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp>;
    fn copy<'a>(&'a mut self, frame: &'a Framebuffer, mode: &'a ModeState) -> FsFuture<'a, ()> {
        alloc::boxed::Box::pin(copy_frame(frame, mode, self.console_fb()))
    }
}
impl Backend for crate::intel_gpu_kms::Session<'_> {
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
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp> {
        alloc::boxed::Box::pin(self.wait_vblank())
    }
}

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
        wait_fences(intel.object.dma_buf.resv.fences(DmaResvUsage::Write)).await?;
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
    let (plan, transaction) = {
        let mut card = mode.lock();
        if !card.is_master(open) {
            return Err(FsError::PermissionDenied);
        }
        let plan = Plan::stage(&card, request, backend.geometry())?;
        let transaction = if plan.test {
            None
        } else {
            card.intel_begin_transaction(open)?;
            Some(Transaction(mode.clone()))
        };
        (plan, transaction)
    };
    let _transaction = transaction;
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
    let mut stamp = None;
    match &plan.action {
        Action::Noop => {}
        Action::DropMaster => {
            backend.restore().await?;
        }
        Action::Remove(id) => {
            if plan.previous.primary_fb == Some(*id) {
                backend.restore().await?;
            }
        }
        Action::Restore | Action::Observe => {
            backend.restore().await?;
            stamp = Some(backend.vblank().await?);
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
                wait_fences(object.dma_buf.resv.fences(DmaResvUsage::Write)).await?;
                stamp = Some(match backend.present(object.clone(), plan.geometry).await {
                    Ok(stamp) => stamp,
                    // The display owner uses Unsupported only for admission
                    // before arm. A hard/lost/pending hardware error must keep
                    // its owners and cannot silently turn into CPU presentation.
                    Err(FsError::Unsupported) => {
                        backend.restore().await?;
                        backend.copy(fb, mode).await?;
                        backend.vblank().await?
                    }
                    Err(error) => return Err(error),
                });
            } else {
                backend.restore().await?;
                backend.copy(fb, mode).await?;
                stamp = Some(backend.vblank().await?);
            }
        }
        Action::Cursor(bytes) => {
            backend.restore().await?;
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
                let x = (i64::from(w[2] as i32) + i64::from(hx)).clamp(0, u32::MAX as i64) as u32;
                let y = (i64::from(w[3] as i32) + i64::from(hy)).clamp(0, u32::MAX as i64) as u32;
                narf_console::user_cursor_move(x, y);
            }
        }
    }
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
                Action::Noop | Action::Observe | Action::Cursor(_) => {}
                Action::Present | Action::Restore => {
                    *card.crtc_mut(plan.next.id).map_err(|_| FsError::NotFound)? =
                        plan.next.clone();
                }
            }
            if let Some(reservation) = reservation {
                reservation.complete(
                    plan.cookie,
                    plan.next.id,
                    stamp.ok_or(FsError::InvalidData)?,
                );
            }
            if let (Some(ptr), Some(sink)) = (plan.out, out) {
                sink.lock()
                    .push((ptr, stamp.ok_or(FsError::InvalidData)?.ns));
            }
            true
        }
    };
    if !published {
        backend.restore().await?;
        return Err(FsError::Busy);
    }
    Ok(0)
}
fn direct_object(frame: &Framebuffer) -> Result<Arc<crate::intel_gpu_gem::GemObject>, FsError> {
    frame
        .intel
        .as_ref()
        .map(|i| i.object.clone())
        .ok_or(FsError::Unsupported)
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
) -> Option<Result<u64, FsError>> {
    if !mutates(cmd) {
        return None;
    }
    let display = crate::intel_gpu_kms::display(index)?;
    Some(
        async {
            let mode = crate::drm_registry::mode_state(index).ok_or(FsError::Unsupported)?;
            // Preserve DRM_MASTER precedence before touching nested user pointers.
            if drm_uapi::ioc_nr(cmd) != 0x1e && !mode.lock().is_master(open) {
                return Err(FsError::PermissionDenied);
            }
            let request = Request::copy(cmd, arg, context)?;
            let mut session = display.session().await?;
            if matches!(request, Request::SetMaster) {
                return mode
                    .lock()
                    .set_master(open)
                    .map(|_| 0)
                    .map_err(|_| FsError::Busy);
            }
            execute(&mut session, &mode, open, request, context, events, out).await
        }
        .await,
    )
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_kms_ioctl_tests.rs"]
mod tests;
