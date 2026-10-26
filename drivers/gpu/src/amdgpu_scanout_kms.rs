//! Exact amdgpu prepare_fb targets, decoded once before any async work.
//! Placement admission spans target resolution, migration and the commit's
//! pin handoff; the KMS spinlock is held only for snapshots and commit.
use super::*;
#[cfg(feature = "amdgpu")]
use crate::amdgpu_gem::{GemObject, GemState};
/// Without the amdgpu driver there are no GEM objects to admit; the
/// admission types still name the object type, so it is uninhabited
/// and every target resolves to `None`.
#[cfg(not(feature = "amdgpu"))]
type GemObject = core::convert::Infallible;

type ModeState = Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>;
type Events = narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>;
type OutFences = narf_lib::sync::IrqSafeSpinLock<Vec<(u64, u64)>>;

#[derive(Debug)]
struct OwnedAtomic {
    flags: u32,
    user_data: u64,
    objects: Vec<u32>,
    counts: Vec<u32>,
    props: Vec<u32>,
    values: Vec<u64>,
}
impl OwnedAtomic {
    fn request(&self) -> AtomicRequest<'_> {
        AtomicRequest {
            flags: self.flags,
            user_data: self.user_data,
            objects: &self.objects,
            prop_counts: &self.counts,
            props: &self.props,
            values: &self.values,
        }
    }
}

// User pointers are copied only here, before acquiring placement admission.
// All later target selection and commit use these owned bytes, never arg.
enum Request {
    Atomic(OwnedAtomic),
    SetCrtc(DrmModeCrtcUapi, Option<u32>),
    PageFlip(DrmModePageFlipUapi),
    SetPlane(Vec<u8>),
    Cursor(LegacyCursor, Option<Arc<GemObject>>),
    Property {
        object: u32,
        kind: u32,
        prop: u32,
        value: u64,
    },
}

pub(super) fn copy_setcrtc(arg: usize) -> Result<(DrmModeCrtcUapi, Option<u32>), FsError> {
    // SAFETY: fixed integer/POD UAPI copied through bounded guarded access.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCrtcUapi>())? };
    // SAFETY: fully initialized bytes of exactly this repr(C) UAPI's size.
    let req = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<DrmModeCrtcUapi>()) };
    let connector = if req.count_connectors == 1 && req.set_connectors_ptr != 0 {
        // SAFETY: the same one-connector input the synchronous handler uses.
        let ids = unsafe { copy_in(req.set_connectors_ptr as usize, 4)? };
        Some(u32::from_le_bytes(ids[..4].try_into().unwrap()))
    } else {
        None
    };
    Ok((req, connector))
}
pub(super) fn copy_page_flip(arg: usize) -> Result<DrmModePageFlipUapi, FsError> {
    // SAFETY: integer/POD UAPI; guarded access rejects invalid user memory.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModePageFlipUapi>())? };
    // SAFETY: exactly one initialized repr(C) UAPI, byte alignment allowed.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<DrmModePageFlipUapi>()) })
}
#[cfg(feature = "amdgpu")]
fn copy_atomic(arg: usize) -> Result<OwnedAtomic, FsError> {
    // SAFETY: bounded guarded copy of one fixed integer/POD header.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeAtomicUapi>())? };
    // SAFETY: exactly one initialized repr(C) UAPI, byte alignment allowed.
    let req = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<DrmModeAtomicUapi>()) };
    const FLAGS: u32 = 0x0001 | 0x0002 | 0x0100 | 0x0200 | 0x0400;
    if req.reserved != 0
        || req.flags & !FLAGS != 0
        || req.count_objs > 256
        || req.flags & 0x0101 == 0x0101
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
    let (objects, counts) = if count == 0 {
        (Vec::new(), Vec::new())
    } else {
        // SAFETY: count <= 256, pointer ranges checked by copy_in.
        unsafe {
            (
                copy_in(req.objs_ptr as usize, count * 4)?,
                copy_in(req.count_props_ptr as usize, count * 4)?,
            )
        }
    };
    let words = |b: Vec<u8>| {
        b.chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect::<Vec<_>>()
    };
    let counts = words(counts);
    let total = counts
        .iter()
        .try_fold(0usize, |n, c| {
            n.checked_add(*c as usize).filter(|n| *n <= 4096)
        })
        .ok_or(FsError::OutOfMemory)?;
    let (props, values) = if total == 0 {
        (Vec::new(), Vec::new())
    } else {
        // SAFETY: total <= 4096; each guarded copy validates the full range.
        unsafe {
            (
                copy_in(req.props_ptr as usize, total * 4)?,
                copy_in(req.prop_values_ptr as usize, total * 8)?,
            )
        }
    };
    Ok(OwnedAtomic {
        flags: req.flags,
        user_data: req.user_data,
        objects: words(objects),
        counts,
        props: words(props),
        values: values
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect(),
    })
}
impl Request {
    #[cfg(feature = "amdgpu")]
    fn copy(nr: u32, arg: usize, gem: &GemState) -> Result<Self, FsError> {
        match nr {
            0xa2 => {
                let (r, c) = copy_setcrtc(arg)?;
                Ok(Self::SetCrtc(r, c))
            }
            0xb0 => copy_page_flip(arg).map(Self::PageFlip),
            0xbc => copy_atomic(arg).map(Self::Atomic),
            0xb7 => {
                // SAFETY: fixed 48-byte SETPLANE request, guarded copy.
                Ok(Self::SetPlane(unsafe { copy_in(arg, 48)? }))
            }
            0xa3 | 0xbb => {
                // SAFETY: cursor/cursor2 fixed layouts; copy both hotspots too.
                let b = unsafe { copy_in(arg, if nr == 0xbb { 36 } else { 28 })? };
                let word = |i| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                let r = LegacyCursor {
                    flags: word(0),
                    crtc_id: word(4),
                    position: (word(8) as i32, word(12) as i32),
                    size: (word(16), word(20)),
                    handle: word(24),
                };
                if r.flags == 0 || r.flags & !3 != 0 {
                    return Err(FsError::InvalidData);
                }
                let bo = (r.flags & 1 != 0 && r.handle != 0)
                    .then(|| gem.object_unvalidated(r.handle))
                    .flatten();
                // Native CREATE_DUMB aliases are in this same GemState.
                // An invalid own-open handle must not fall through to a
                // different open's global legacy dumb handle.
                if r.flags & 1 != 0 && r.handle != 0 && bo.is_none() {
                    return Err(FsError::NotFound);
                }
                Ok(Self::Cursor(r, bo))
            }
            0xab | 0xba => {
                // SAFETY: legacy property requests are 16 or 20 fixed bytes.
                let b = unsafe { copy_in(arg, if nr == 0xba { 20 } else { 16 })? };
                let word = |i| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                Ok(Self::Property {
                    value: u64::from_le_bytes(b[..8].try_into().unwrap()),
                    prop: word(8),
                    object: word(12),
                    kind: if nr == 0xba {
                        word(16)
                    } else {
                        DRM_MODE_OBJECT_CONNECTOR
                    },
                })
            }
            _ => Err(FsError::Unsupported),
        }
    }
    fn test_only(&self) -> bool {
        matches!(self,Self::Atomic(a) if a.flags & 0x0100 != 0)
    }
    fn framebuffer_ids(&self, card: &crate::drm::card::Card) -> Result<Vec<u32>, FsError> {
        let ids = match self {
            Self::SetCrtc(r, _) => vec![r.fb_id],
            Self::PageFlip(r) => vec![r.fb_id],
            Self::SetPlane(b) => vec![u32::from_le_bytes(b[8..12].try_into().unwrap())],
            Self::Atomic(a) => atomic_fbs(card, a.request())?,
            Self::Property {
                object,
                kind,
                prop,
                value,
            } => {
                let kind = set_property_object(card, *object, *kind)?;
                if kind == DRM_MODE_OBJECT_PLANE {
                    atomic_fbs(
                        card,
                        AtomicRequest {
                            flags: 0x0400,
                            user_data: 0,
                            objects: &[*object],
                            prop_counts: &[1],
                            props: &[*prop],
                            values: &[*value],
                        },
                    )?
                } else {
                    Vec::new()
                }
            }
            Self::Cursor(r, _) if r.flags & 1 == 0 => {
                // The cursor plane exists only on the native card.
                #[cfg(feature = "amdgpu")]
                {
                    crate::drm_native_planes::cursor_of(card, r.crtc_id)
                        .and_then(|p| p.fb_id)
                        .into_iter()
                        .collect()
                }
                #[cfg(not(feature = "amdgpu"))]
                {
                    let _ = (card, r);
                    Vec::new()
                }
            }
            Self::Cursor(_, _) => Vec::new(),
        };
        Ok(ids.into_iter().filter(|id| *id != 0).collect())
    }
    fn targets(&self, card: &crate::drm::card::Card) -> Result<Targets, FsError> {
        let mut fbs = Vec::new();
        for id in self.framebuffer_ids(card)? {
            if fbs.iter().any(|(other, _)| *other == id) {
                continue;
            }
            let fb = card.framebuffer(id).map_err(|_| FsError::NotFound)?;
            #[cfg(feature = "amdgpu")]
            fbs.push((id, fb.bo.as_ref().map(|bo| bo.object.clone())));
            #[cfg(not(feature = "amdgpu"))]
            fbs.push((id, { let _ = fb; None }));
        }
        let cursor = match self {
            Self::Cursor(_, bo) => bo.clone(),
            _ => None,
        };
        Ok(Targets { fbs, cursor })
    }
    #[cfg(feature = "amdgpu")]
    fn commit(
        &self,
        card: u32,
        mode: &ModeState,
        ctx: &DrmFileCtx,
        events: Option<&Events>,
        out: Option<&OutFences>,
        admission: Option<&CommitAdmission<'_>>,
    ) -> Result<u64, FsError> {
        match self {
            Self::Atomic(a) => atomic_commit(card, mode, a.request(), events, out, admission),
            Self::SetCrtc(r, c) => handle_setcrtc_decoded(card, mode, *r, *c, admission, false),
            Self::PageFlip(r) => handle_page_flip_decoded(card, mode, *r, events, admission, false),
            Self::SetPlane(b) => handle_setplane_decoded(card, mode, b, admission, false),
            Self::Cursor(r, bo) => cursor_universal(
                card,
                mode,
                ctx,
                LegacyCursor {
                    flags: r.flags,
                    crtc_id: r.crtc_id,
                    position: r.position,
                    size: r.size,
                    handle: r.handle,
                },
                bo.clone(),
                admission,
            ),
            Self::Property {
                object,
                kind,
                prop,
                value,
            } => {
                let kind = {
                    let c = mode.lock();
                    if let Some(a) = admission {
                        a.check(&c)?;
                    }
                    set_property_object(&c, *object, *kind)?
                };
                if kind == DRM_MODE_OBJECT_CRTC
                    && *prop == CRTC_OUT_FENCE_PTR_PROP_ID
                    && *value != 0
                {
                    // SAFETY: original checked UAPI output; guarded copy faults cleanly.
                    unsafe { copy_out(*value as usize, &(-1i32).to_le_bytes())? };
                }
                atomic_commit(
                    card,
                    mode,
                    AtomicRequest {
                        flags: 0x0400,
                        user_data: 0,
                        objects: &[*object],
                        prop_counts: &[1],
                        props: &[*prop],
                        values: &[*value],
                    },
                    None,
                    None,
                    admission,
                )
            }
        }
    }

    /// Reuse the commit's checks before any relocation. Atomic checks use
    /// a TEST_ONLY view of the same owned arrays; legacy paths stop at their
    /// own prepare_fb boundary. No pins, events or Card state are published.
    fn validate(
        &self,
        card: u32,
        mode: &ModeState,
        open: u64,
        events: Option<&Events>,
    ) -> Result<(), FsError> {
        let admission = CommitAdmission {
            open,
            request: self,
            targets: None,
        };
        {
            let c = mode.lock();
            admission.check(&c)?;
        }
        let test = |mut request: AtomicRequest<'_>| {
            request.flags = (request.flags | 0x100) & !1;
            atomic_commit(card, mode, request, None, None, Some(&admission)).map(|_| ())
        };
        match self {
            Self::Atomic(a) => test(a.request()),
            Self::SetCrtc(r, c) => {
                handle_setcrtc_decoded(card, mode, *r, *c, Some(&admission), true).map(|_| ())
            }
            Self::PageFlip(r) => {
                handle_page_flip_decoded(card, mode, *r, events, Some(&admission), true).map(|_| ())
            }
            Self::SetPlane(b) => {
                handle_setplane_decoded(card, mode, b, Some(&admission), true).map(|_| ())
            }
            Self::Property {
                object,
                kind,
                prop,
                value,
            } => {
                {
                    let c = mode.lock();
                    admission.check(&c)?;
                    set_property_object(&c, *object, *kind)?;
                }
                test(AtomicRequest {
                    flags: 0x400,
                    user_data: 0,
                    objects: &[*object],
                    prop_counts: &[1],
                    props: &[*prop],
                    values: &[*value],
                })
            }
            Self::Cursor(r, bo) => {
                let mut c = mode.lock();
                admission.check(&c)?;
                let crtc = c.crtc(r.crtc_id).map_err(|_| FsError::NotFound)?;
                let cursor = *crate::drm_native_planes::cursor_of(&c, r.crtc_id)
                    .ok_or(FsError::InvalidData)?;
                if r.flags == 0 || r.flags & !3 != 0 {
                    return Err(FsError::InvalidData);
                }
                if r.flags & 1 != 0 && r.handle != 0 {
                    let object = bo.as_ref().ok_or(FsError::NotFound)?;
                    let m = crate::amdgpu_dm_modifiers::FbCmd {
                        width: r.size.0,
                        height: r.size.1,
                        pixel_format: DRM_FORMAT_ARGB8888,
                        handles: [r.handle, 0, 0, 0],
                        pitches: [r.size.0.wrapping_mul(4), 0, 0, 0],
                        ..Default::default()
                    };
                    let info = crate::amdgpu_dm_modifiers::check_fb_cmd(&m)
                        .map_err(|_| FsError::InvalidData)?;
                    let modifier = crate::amdgpu_dm_modifiers::check_amdgpu_fb(
                        &m,
                        &info,
                        c.plane_formats.unwrap_or(&[]),
                        object.tiling_flags(),
                        object.flags & u64::from(crate::amdgpu_uapi::AMDGPU_GEM_CREATE_GFX12_DCC)
                            != 0,
                        object.byte_len,
                    )
                    .map_err(|_| FsError::InvalidData)?;
                    crate::drm_native_planes::check_cursor(
                        crate::drm_native_planes::CursorFb {
                            width: r.size.0,
                            height: r.size.1,
                            pitch: m.pitches[0],
                            linear: modifier == 0,
                        },
                        (0, 0, r.size.0 << 16, r.size.1 << 16),
                        r.size,
                    )?;
                    if crtc.enabled && crtc.primary_fb.is_none() {
                        return Err(FsError::InvalidData);
                    }
                    Ok(())
                } else {
                    let fb = if r.flags & 1 == 0 { cursor.fb_id } else { None };
                    let (w, h) = fb
                        .and_then(|id| c.framebuffer(id).ok())
                        .map_or((0, 0), |f| (f.width, f.height));
                    let position = if r.flags & 2 != 0 {
                        r.position
                    } else {
                        cursor.legacy_position
                    };
                    let plane = crate::drm::atomic::PlaneState {
                        id: cursor.id,
                        crtc_id: fb.map(|_| r.crtc_id),
                        fb_id: fb,
                        crtc_x: position.0,
                        crtc_y: position.1,
                        crtc_w: w,
                        crtc_h: h,
                        src_w: w,
                        src_h: h,
                        props: Some(cursor.props),
                        ..Default::default()
                    };
                    commit_cursor_plane(card, &mut c, plane, true).map(|_| ())
                }
            }
        }
    }
}
/// The same plane state inheritance atomic_commit uses. Only FB/CRTC ids
/// affect prepare_fb's targets; the commit still checks every property.
fn atomic_fbs(card: &crate::drm::card::Card, req: AtomicRequest<'_>) -> Result<Vec<u32>, FsError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    for (&object, &count) in req.objects.iter().zip(req.prop_counts) {
        let end = at
            .checked_add(count as usize)
            .filter(|n| *n <= req.props.len() && *n <= req.values.len())
            .ok_or(FsError::InvalidData)?;
        if let Some(mut p) = crate::drm_native_planes::plane_state(card, object) {
            for (&prop, &value) in req.props[at..end].iter().zip(&req.values[at..end]) {
                if prop == PLANE_FB_ID_PROP_ID {
                    p.fb_id = (value != 0).then_some(value as u32)
                }
                if prop == PLANE_CRTC_ID_PROP_ID {
                    p.crtc_id = (value != 0).then_some(value as u32)
                }
            }
            if let (Some(fb), Some(_)) = (p.fb_id, p.crtc_id) {
                out.push(fb)
            }
        }
        at = end;
    }
    Ok(out)
}
struct Targets {
    fbs: Vec<(u32, Option<Arc<GemObject>>)>,
    cursor: Option<Arc<GemObject>>,
}
impl Targets {
    fn objects(&self) -> Vec<Arc<GemObject>> {
        self.fbs
            .iter()
            .filter_map(|(_, o)| o.clone())
            .chain(self.cursor.clone())
            .collect()
    }
    fn same(&self, other: &Self) -> bool {
        let same = |a: &Option<Arc<GemObject>>, b: &Option<Arc<GemObject>>| match (a, b) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        self.fbs.len() == other.fbs.len()
            && self
                .fbs
                .iter()
                .zip(&other.fbs)
                .all(|((a, x), (b, y))| a == b && same(x, y))
            && same(&self.cursor, &other.cursor)
    }
}
/// Rechecked under the actual synchronous commit's card lock, before any
/// state/event mutation. Framebuffer ownership controls close cleanup, not
/// lookup permission for an authorized DRM master.
pub(super) struct CommitAdmission<'a> {
    open: u64,
    request: &'a Request,
    targets: Option<&'a Targets>,
}
impl CommitAdmission<'_> {
    pub(super) fn check(&self, card: &crate::drm::card::Card) -> Result<(), FsError> {
        if !card.is_master(self.open) {
            return Err(FsError::PermissionDenied);
        }
        if let Some(targets) = self.targets {
            let current = self.request.targets(card).map_err(|_| FsError::Busy)?;
            if !targets.same(&current) {
                return Err(FsError::Busy);
            }
        }
        Ok(())
    }
}
/// Native amdgpu KMS on a user open. Unsupported cards/commands retain
/// the synchronous dispatcher. No user input is reread after migration.
#[cfg(feature = "amdgpu")]
pub(crate) async fn dispatch(
    card: u32,
    open: u64,
    cmd: u32,
    arg: usize,
    gem: &GemState,
    events: Option<&Events>,
    out: Option<&OutFences>,
) -> Option<Result<u64, FsError>> {
    let nr = drm_uapi::ioc_nr(cmd);
    if (cmd >> 8) & 0xff != u32::from(b'd')
        || !matches!(nr, 0xa2 | 0xa3 | 0xab | 0xb0 | 0xb7 | 0xba | 0xbb | 0xbc)
    {
        return None;
    }
    let mode = crate::drm_registry::mode_state(card)?;
    {
        let c = mode.lock();
        if !c.gfx12_modifiers || c.native_planes.is_empty() || !atomic_card(&c) {
            return None;
        }
        // DRM_MASTER failure precedes user-pointer validation and relocation.
        if !c.is_master(open) {
            return Some(Err(FsError::PermissionDenied));
        }
    }
    let result = async {
        crate::amdgpu_gem::ensure_placement_live(card)?;
        let req = Request::copy(nr, arg, gem)?;
        let ctx = DrmFileCtx::primary(true);
        if req.test_only() {
            // No placement admission or migration for a probe, but retain
            // the same actual-commit master check as a real request.
            let admission = CommitAdmission {
                open,
                request: &req,
                targets: None,
            };
            return req.commit(card, &mode, &ctx, events, out, Some(&admission));
        }
        let gate = crate::amdgpu_gem::lock_placement_live(card).await?;
        req.validate(card, &mode, open, events)?;
        let targets = {
            let c = mode.lock();
            if !c.is_master(open) {
                return Err(FsError::PermissionDenied);
            }
            req.targets(&c)?
        };
        let _prepared = crate::amdgpu_gem::prepare_scanout_locked(gate, targets.objects()).await?;
        let admission = CommitAdmission {
            open,
            request: &req,
            targets: Some(&targets),
        };
        req.commit(card, &mode, &ctx, events, out, Some(&admission))
    }
    .await;
    Some(result)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_scanout_kms_tests.rs"]
mod tests;
