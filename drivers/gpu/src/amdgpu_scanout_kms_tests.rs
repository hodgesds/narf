//! Native KMS preparation tests use an owned BAR and no native presenter.
//! Successful pins are exercised directly; ioctl failure paths never reach
//! a real scanout or substitute a CPU blit for a GEM framebuffer.
#![cfg(target_arch = "x86_64")]

use super::*;
use crate::amdgpu_gem::{self as gem, ScanoutPin, VramHeap};
use crate::drm::card::{Card, Crtc};
use core::future::Future;
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

const MASTER: u64 = 0x5070;
const OTHER: u64 = 0x5060;
const CRTC: u32 = 0x4070;
const PRIMARY: u32 = crate::drm_native_planes::PRIMARY_PLANE_ID_BASE;
const CURSOR: u32 = crate::drm_native_planes::CURSOR_PLANE_ID_BASE;
const PAGE: u64 = 4096;

struct Fixture {
    index: u32,
    mode: ModeState,
    // Drop BO ownership before the BAR bytes they can still access.
    gem: GemState,
    objects: narf_lib::sync::IrqSafeSpinLock<Vec<Arc<GemObject>>>,
    _bar: Vec<u8>,
}
impl Fixture {
    fn new(pages: usize) -> Result<Self, FsError> {
        let mut card = Card::new("narf-drm", "scanout preparation fixture", (1, 0, 0));
        card.native_atomic = true;
        card.gfx12_modifiers = true;
        card.plane_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.overlay_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.crtcs.push(Crtc {
            id: CRTC,
            mode: Some(crate::Mode {
                width: 64,
                height: 12,
                refresh_hz: 60,
                bpp: 32,
            }),
            enabled: true,
            primary_fb: None,
            x: 0,
            y: 0,
        });
        card.native_planes = crate::drm_native_planes::planes_for(&[], &[CRTC]);
        card.master_open(MASTER);
        let iface = Arc::new(crate::drm_devfs_bridge::BochsCard::new(alloc::format!(
            "card{}",
            crate::drm_registry::count()
        )));
        let index = crate::drm_registry::register_drm_card_with_state(iface, card);
        let mode = crate::drm_registry::mode_state(index).ok_or(FsError::NoDevice)?;
        let mut bar = vec![0u8; pages * PAGE as usize];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xb800_0000),
            virt: bar.as_mut_ptr() as u64,
            len: bar.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: this fixture owns the whole range until every BO and heap
        // reference has been dropped; no hardware can reach these bytes.
        let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }
            .map_err(|_| FsError::InvalidData)?;
        gem::register_vram_heap(
            index,
            VramHeap {
                pool,
                fb_base: 0x8_0000_0000,
                fb_offset: 0x8_0000_0000,
                unmapped: None,
            },
        );
        gem::set_lru_eviction(index, true);
        Ok(Self {
            index,
            mode,
            gem: GemState::for_card(index),
            objects: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
            _bar: bar,
        })
    }
    fn object(&self) -> Result<Arc<GemObject>, FsError> {
        let mut req = [0u8; 32];
        req[..8].copy_from_slice(&PAGE.to_le_bytes());
        req[8..16].copy_from_slice(&PAGE.to_le_bytes());
        let domains = u64::from(
            crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM | crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_GTT,
        );
        req[16..24].copy_from_slice(&domains.to_le_bytes());
        // Preserve existing residents while creating the next BO, so a
        // full heap deliberately falls to GTT instead of evicting them.
        let _pins: Vec<_> = self
            .objects
            .lock()
            .iter()
            .filter(|o| !o.system())
            .filter_map(|o| o.pin_scanout().ok())
            .collect();
        gem::dispatch(0xc020_6440, req.as_mut_ptr() as usize, &self.gem)?;
        let handle = u32::from_le_bytes(req[..4].try_into().unwrap());
        let object = self.gem.object(handle).ok_or(FsError::NotFound)?;
        self.objects.lock().push(object.clone());
        Ok(object)
    }
    fn fb(&self, object: Arc<GemObject>, owner: u64, cursor: bool) -> Result<u32, FsError> {
        let cmd = crate::amdgpu_dm_modifiers::FbCmd {
            width: 64,
            height: 12,
            pixel_format: if cursor {
                DRM_FORMAT_ARGB8888
            } else {
                DRM_FORMAT_XRGB8888
            },
            handles: [1, 0, 0, 0],
            pitches: [256, 0, 0, 0],
            ..Default::default()
        };
        self.mode
            .lock()
            .addfb2_bo(&cmd, object, owner)
            .map_err(|_| FsError::InvalidData)
    }
    fn flip(&self, fb: u32) -> DrmModePageFlipUapi {
        DrmModePageFlipUapi {
            crtc_id: CRTC,
            fb_id: fb,
            flags: 1,
            user_data: 0xdead_9070,
            ..Default::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // The registry keeps the Card itself; it must retain no test BAR.
        self.mode.lock().framebuffers.clear();
        gem::set_lru_eviction(self.index, false);
        gem::unregister_vram_heap(self.index);
    }
}

fn atomic(objects: &[u32], counts: &[u32], props: &[u32], values: &[u64]) -> Request {
    Request::Atomic(OwnedAtomic {
        flags: 0x400,
        user_data: 0,
        objects: objects.to_vec(),
        counts: counts.to_vec(),
        props: props.to_vec(),
        values: values.to_vec(),
    })
}
fn one_target(request: &Request, card: &Card, object: &Arc<GemObject>) -> bool {
    request.targets(card).is_ok_and(|targets| {
        let objects = targets.objects();
        objects.len() == 1 && Arc::ptr_eq(&objects[0], object)
    })
}

fn kms_linear_primary_retains_gem_and_resolves_atomic_preparation() -> TestResult {
    let Ok(f) = Fixture::new(4) else {
        return TestResult::Fail("fixture");
    };
    {
        let mut c = f.mode.lock();
        c.driver_name = "amdgpu";
        c.gfx12_modifiers = false;
        c.native_planes.clear();
        c.overlay_formats = None;
        c.plane_formats = Some(&[DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888]);
    }
    let Ok(object) = f.object() else {
        return TestResult::Fail("linear BO");
    };
    let Ok(fb) = f.fb(object.clone(), MASTER, false) else {
        return TestResult::Fail("linear-primary ADDFB2 rejected a GEM handle");
    };
    let request = atomic(
        &[PRIMARY],
        &[2],
        &[PLANE_FB_ID_PROP_ID, PLANE_CRTC_ID_PROP_ID],
        &[u64::from(fb), u64::from(CRTC)],
    );
    if !one_target(&request, &f.mode.lock(), &object) {
        return TestResult::Fail("linear atomic FB bypassed placement preparation");
    }
    if request.validate(f.index, &f.mode, MASTER, None).is_err()
        || f.mode.lock().crtcs[0].primary_fb.is_some()
        || object.pinned()
    {
        return TestResult::Fail("linear atomic TEST_ONLY failed or changed live state");
    }
    let frame = {
        let c = f.mode.lock();
        crate::drm_ioctl_bridge::scanout_frame(&c, c.framebuffer(fb).unwrap())
    };
    let Some(frame) = frame else {
        return TestResult::Fail("linear GEM did not produce a pinned frame");
    };
    if frame.bo.is_none() || !object.pinned() || frame.modifier != 0 {
        return TestResult::Fail("linear GEM ownership lost at KMS handoff");
    }
    // Unsupported formats/modifiers fail before adding an FB, even
    // though the generic amdgpu validator understands them.
    let before = f.mode.lock().framebuffers.len();
    let mut cmd = crate::amdgpu_dm_modifiers::FbCmd {
        width: 64,
        height: 12,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [1, 0, 0, 0],
        pitches: [256, 0, 0, 0],
        ..Default::default()
    };
    cmd.pixel_format = crate::amdgpu_dm_modifiers::NV12;
    if f.mode
        .lock()
        .addfb2_bo(&cmd, object.clone(), MASTER)
        .is_ok()
        || f.mode.lock().framebuffers.len() != before
    {
        return TestResult::Fail("linear primary accepted a multi-plane framebuffer");
    }
    cmd.pixel_format = DRM_FORMAT_XRGB8888;
    cmd.flags = crate::amdgpu_dm_modifiers::FB_MODIFIERS;
    cmd.modifier[0] = crate::amdgpu_dm_modifiers::PLANE_MODIFIERS[1];
    if f.mode
        .lock()
        .addfb2_bo(&cmd, object.clone(), MASTER)
        .is_ok()
        || f.mode.lock().framebuffers.len() != before
    {
        return TestResult::Fail("linear primary accepted an AMD tiled modifier");
    }
    drop(frame);
    if object.pinned() {
        return TestResult::Fail("completed copy leaked its source pin");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_linear_primary_retains_gem_and_resolves_atomic_preparation
);

/// ADDFB2 on the linear card (Navi22) takes a two-plane NV12 GEM
/// framebuffer once an overlay plane takes the format
/// (drm_any_plane_has_format): the 19-format overlay list, not the
/// 2-format primary list, admits it — while a tiled modifier is still
/// refused on the linear card.
fn kms_linear_card_with_overlays_takes_gem_nv12() -> TestResult {
    let Ok(f) = Fixture::new(4) else {
        return TestResult::Fail("fixture");
    };
    {
        let mut c = f.mode.lock();
        c.driver_name = "amdgpu";
        c.gfx12_modifiers = false;
        c.native_planes.clear();
        c.overlay_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        c.plane_formats = Some(&[DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888]);
    }
    let Ok(object) = f.object() else {
        return TestResult::Fail("linear BO");
    };
    // One BO for both planes (amdgpu_dm's one-BO rule): 64x8 luma at
    // offset 0, 32x4 chroma at offset 2048. amdgpu_display_verify_sizes
    // gives a LINEAR plane 256-byte blocks (block_width = 256 / cpp,
    // block_size_log2 = 8), so amdgpu_display_verify_plane takes only a
    // pitch and an offset that are multiples of 256: 8 luma rows and 4
    // chroma rows of 256 bytes are 3072 bytes of the 4096-byte BO.
    let cmd = crate::amdgpu_dm_modifiers::FbCmd {
        width: 64,
        height: 8,
        pixel_format: crate::amdgpu_dm_modifiers::NV12,
        handles: [1, 1, 0, 0],
        pitches: [256, 256, 0, 0],
        offsets: [0, 2048, 0, 0],
        ..Default::default()
    };
    let before = f.mode.lock().framebuffers.len();
    let Ok(fb) = f.mode.lock().addfb2_bo(&cmd, object.clone(), MASTER) else {
        return TestResult::Fail("linear card with overlays refused GEM NV12");
    };
    if f.mode.lock().framebuffers.len() != before + 1 {
        return TestResult::Fail("GEM NV12 framebuffer not recorded");
    }
    let (offsets, chroma_pitch, modifier) = {
        let c = f.mode.lock();
        let record = c.framebuffer(fb).unwrap();
        (record.offsets, record.chroma_pitch, record.modifier)
    };
    if offsets != [0, 2048] || chroma_pitch != 256 || modifier != 0 {
        return TestResult::Fail("GEM NV12 planes not recorded");
    }
    // The pitch a 64-byte luma row would fit is no multiple of the block
    // pitch: Linux refuses it (amdgpu_display_verify_plane, -EINVAL).
    let mut narrow = cmd;
    narrow.pitches = [64, 64, 0, 0];
    narrow.offsets = [0, 768, 0, 0];
    if f.mode
        .lock()
        .addfb2_bo(&narrow, object.clone(), MASTER)
        .is_ok()
    {
        return TestResult::Fail("linear NV12 pitch below the 256-byte block accepted");
    }
    // A tiled modifier is still refused on the linear card.
    let mut tiled = cmd;
    tiled.pixel_format = DRM_FORMAT_XRGB8888;
    tiled.flags = crate::amdgpu_dm_modifiers::FB_MODIFIERS;
    tiled.modifier[0] = crate::amdgpu_dm_modifiers::PLANE_MODIFIERS[1];
    if f.mode
        .lock()
        .addfb2_bo(&tiled, object.clone(), MASTER)
        .is_ok()
        || f.mode.lock().framebuffers.len() != before + 1
    {
        return TestResult::Fail("linear card accepted an AMD tiled modifier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_linear_card_with_overlays_takes_gem_nv12
);

fn kms_prepare_exact_inherited_cross_open_and_cursor_targets() -> TestResult {
    let Ok(f) = Fixture::new(4) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(a), Ok(b), Ok(c)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("objects");
    };
    let (Ok(fa), Ok(fb), Ok(fc)) = (
        f.fb(a.clone(), MASTER, false),
        f.fb(b.clone(), OTHER, false),
        f.fb(c.clone(), crate::drm_devfs_bridge::NO_MASTER_OPEN_ID, true),
    ) else {
        return TestResult::Fail("framebuffers");
    };
    let mut card = f.mode.lock();
    card.crtcs[0].primary_fb = Some(fa);
    let cursor = card
        .native_planes
        .iter_mut()
        .find(|p| p.id == CURSOR)
        .unwrap();
    cursor.crtc_id = Some(CRTC);
    cursor.fb_id = Some(fc);
    cursor.internal_fb = true;
    let inherited = atomic(&[PRIMARY], &[1], &[PLANE_CRTC_X_PROP_ID], &[3]);
    let replaced = atomic(&[PRIMARY], &[1], &[PLANE_FB_ID_PROP_ID], &[u64::from(fb)]);
    let disabled = atomic(&[PRIMARY], &[1], &[PLANE_CRTC_ID_PROP_ID], &[0]);
    let removed = atomic(&[PRIMARY], &[1], &[PLANE_FB_ID_PROP_ID], &[0]);
    let last_wins = atomic(
        &[PRIMARY],
        &[2],
        &[PLANE_FB_ID_PROP_ID, PLANE_FB_ID_PROP_ID],
        &[u64::from(fb), u64::from(fa)],
    );
    let property = Request::Property {
        object: PRIMARY,
        kind: DRM_MODE_OBJECT_PLANE,
        prop: PLANE_CRTC_X_PROP_ID,
        value: 3,
    };
    let move_cursor = Request::Cursor(
        LegacyCursor {
            flags: 2,
            crtc_id: CRTC,
            position: (8, 9),
            size: (0, 0),
            handle: 0,
        },
        None,
    );
    let new_cursor = Request::Cursor(
        LegacyCursor {
            flags: 1,
            crtc_id: CRTC,
            position: (0, 0),
            size: (64, 12),
            handle: 7,
        },
        Some(b.clone()),
    );
    let disable_cursor = Request::Cursor(
        LegacyCursor {
            flags: 1,
            crtc_id: CRTC,
            position: (0, 0),
            size: (0, 0),
            handle: 0,
        },
        None,
    );
    let mut plane = vec![0u8; 48];
    plane[8..12].copy_from_slice(&fb.to_le_bytes());
    if !one_target(&inherited, &card, &a)
        || !one_target(&property, &card, &a)
        || !one_target(&last_wins, &card, &a)
        || !one_target(&replaced, &card, &b)
        || !one_target(&Request::PageFlip(f.flip(fb)), &card, &b)
        || !one_target(&Request::SetPlane(plane), &card, &b)
        || !one_target(
            &Request::SetCrtc(
                DrmModeCrtcUapi {
                    fb_id: fb,
                    ..Default::default()
                },
                None,
            ),
            &card,
            &b,
        )
        || !one_target(&move_cursor, &card, &c)
        || !one_target(&new_cursor, &card, &b)
        || [disabled, removed, disable_cursor]
            .iter()
            .any(|r| r.targets(&card).map_or(true, |t| !t.objects().is_empty()))
    {
        return TestResult::Fail("prepare targets differ from final/inherited plane state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_exact_inherited_cross_open_and_cursor_targets
);

fn kms_prepare_reclaims_idle_bos_excludes_all_targets_and_hands_off_pins() -> TestResult {
    let Ok(f) = Fixture::new(3) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(front), Ok(idle_a), Ok(idle_b)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("resident BOs");
    };
    let (Ok(a), Ok(b), Ok(unrelated)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("evicted targets");
    };
    let Ok(front_pin) = front.pin_scanout() else {
        return TestResult::Fail("front pin");
    };
    if !a.system() || !b.system() || !unrelated.system() {
        return TestResult::Fail("full heap did not fall back to system backing");
    }
    a.store_u64(8, 0x9070_000a);
    b.store_u64(8, 0x9060_000b);
    idle_a.store_u64(8, 0x000f_eeda);
    idle_b.store_u64(8, 0x000f_eedb);
    let Ok(prepared) = narf_scheduler::block_on_spin(gem::prepare_scanout(
        f.index,
        vec![a.clone(), b.clone(), a.clone()],
    )) else {
        return TestResult::Fail("prepare did not reclaim idle VRAM");
    };
    let pins: Result<Vec<ScanoutPin>, _> = [a.clone(), b.clone()]
        .iter()
        .map(GemObject::pin_scanout)
        .collect();
    if a.system()
        || b.system()
        || !idle_a.system()
        || !idle_b.system()
        || front.system()
        || !unrelated.system()
        || a.load_u64(8) != Some(0x9070_000a)
        || b.load_u64(8) != Some(0x9060_000b)
        || idle_a.load_u64(8) != Some(0x000f_eeda)
        || idle_b.load_u64(8) != Some(0x000f_eedb)
        || pins.is_err()
        || gem::try_placement(f.index).is_some()
    {
        return TestResult::Fail("reclaim moved a target/front or lost data/admission");
    }
    drop(prepared);
    if gem::try_placement(f.index).is_none() || !a.pinned() || !b.pinned() {
        return TestResult::Fail("placement did not hand off to scanout pins");
    }
    drop(pins);
    drop(front_pin);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_reclaims_idle_bos_excludes_all_targets_and_hands_off_pins
);

fn kms_prepare_failure_preserves_state_events_and_unrelated_bos() -> TestResult {
    let Ok(f) = Fixture::new(1) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(front), Ok(target), Ok(unrelated)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("objects");
    };
    let (Ok(fa), Ok(fb)) = (
        f.fb(front.clone(), MASTER, false),
        f.fb(target.clone(), OTHER, false),
    ) else {
        return TestResult::Fail("framebuffers");
    };
    f.mode.lock().crtcs[0].primary_fb = Some(fa);
    let Ok(_pin) = front.pin_scanout() else {
        return TestResult::Fail("front pin");
    };
    let mut req = f.flip(fb);
    let events = Events::new(crate::drm::card::DrmEventQueue::new());
    let result = narf_scheduler::block_on_spin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP,
        (&mut req as *mut DrmModePageFlipUapi) as usize,
        &f.gem,
        Some(&events),
        None,
    ));
    if result != Some(Err(FsError::OutOfMemory))
        || f.mode.lock().crtcs[0].primary_fb != Some(fa)
        || events.lock().next_event_deadline_ns(u64::MAX).is_some()
        || target.pinned()
        || !target.system()
        || !unrelated.system()
        || gem::try_placement(f.index).is_none()
    {
        return TestResult::Fail("failed preparation changed KMS state/events or kept admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_failure_preserves_state_events_and_unrelated_bos
);

fn kms_prepare_copies_once_and_rechecks_master_after_wait() -> TestResult {
    let Ok(f) = Fixture::new(1) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(idle), Ok(a), Ok(b)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("objects");
    };
    let (Ok(fa), Ok(fb)) = (
        f.fb(a.clone(), OTHER, false),
        f.fb(b.clone(), MASTER, false),
    ) else {
        return TestResult::Fail("framebuffers");
    };
    let Some(gate) = gem::try_placement(f.index) else {
        return TestResult::Fail("placement admission");
    };
    let mut req = f.flip(fa);
    // An absent CRTC ensures successful migration stops before presentation.
    req.crtc_id = u32::MAX;
    let mut pending = alloc::boxed::Box::pin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP,
        (&mut req as *mut DrmModePageFlipUapi) as usize,
        &f.gem,
        None,
        None,
    ));
    let mut context = Context::from_waker(Waker::noop());
    if pending.as_mut().poll(&mut context) != Poll::Pending {
        return TestResult::Fail("request did not wait for placement");
    }
    // The waiter has already copied the complete request. Rewriting it must
    // change neither which BO is promoted nor the CRTC used by commit.
    req.fb_id = fb;
    req.crtc_id = CRTC;
    drop(gate);
    if narf_scheduler::block_on_spin(pending) != Some(Err(FsError::NotFound))
        || !a.system()
        || !b.system()
        || idle.system()
    {
        return TestResult::Fail("post-wait ioctl reread or invalid request migrated a target");
    }
    let Some(gate) = gem::try_placement(f.index) else {
        return TestResult::Fail("second placement admission");
    };
    let mut pending = alloc::boxed::Box::pin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP,
        (&mut req as *mut DrmModePageFlipUapi) as usize,
        &f.gem,
        None,
        None,
    ));
    if pending.as_mut().poll(&mut context) != Poll::Pending {
        return TestResult::Fail("second request did not wait");
    }
    f.mode.lock().drop_master(MASTER).unwrap();
    drop(gate);
    if narf_scheduler::block_on_spin(pending) != Some(Err(FsError::PermissionDenied)) || !b.system()
    {
        return TestResult::Fail("revoked master migrated or committed after wait");
    }
    // Permission failure precedes even a null user pointer.
    if narf_scheduler::block_on_spin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        0,
        &f.gem,
        None,
        None,
    )) != Some(Err(FsError::PermissionDenied))
    {
        return TestResult::Fail("master precedence lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_copies_once_and_rechecks_master_after_wait
);

fn kms_prepare_commit_rechecks_target_identity_and_master() -> TestResult {
    let Ok(f) = Fixture::new(2) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(a), Ok(b)) = (f.object(), f.object()) else {
        return TestResult::Fail("objects");
    };
    let (Ok(fa), Ok(fb)) = (
        f.fb(a.clone(), MASTER, false),
        f.fb(b.clone(), OTHER, false),
    ) else {
        return TestResult::Fail("framebuffers");
    };
    f.mode.lock().crtcs[0].primary_fb = Some(fa);
    let req = atomic(&[PRIMARY], &[1], &[PLANE_CRTC_X_PROP_ID], &[0]);
    let targets = req.targets(&f.mode.lock()).unwrap();
    let admission = CommitAdmission {
        open: MASTER,
        request: &req,
        targets: Some(&targets),
    };
    let ctx = DrmFileCtx::primary(true);
    // The inherited framebuffer changed while an async migration was in
    // flight. This must fail before the atomic parser, pins, or core_commit.
    f.mode.lock().crtcs[0].primary_fb = Some(fb);
    if req.commit(f.index, &f.mode, &ctx, None, None, Some(&admission)) != Err(FsError::Busy) {
        return TestResult::Fail("actual commit accepted a changed inherited target");
    }
    f.mode.lock().crtcs[0].primary_fb = Some(fa);
    f.mode
        .lock()
        .framebuffers
        .iter_mut()
        .find(|fb| fb.id == fa)
        .unwrap()
        .bo
        .as_mut()
        .unwrap()
        .object = b;
    if req.commit(f.index, &f.mode, &ctx, None, None, Some(&admission)) != Err(FsError::Busy) {
        return TestResult::Fail("actual commit accepted another BO under the same framebuffer id");
    }
    f.mode
        .lock()
        .framebuffers
        .iter_mut()
        .find(|fb| fb.id == fa)
        .unwrap()
        .bo
        .as_mut()
        .unwrap()
        .object = a.clone();
    f.mode.lock().drop_master(MASTER).unwrap();
    // Exercise every decoded entry point's actual-lock permission check.
    let mut raw_plane = vec![0u8; 48];
    raw_plane[..4].copy_from_slice(&PRIMARY.to_le_bytes());
    let requests = [
        atomic(&[], &[], &[], &[]),
        Request::SetCrtc(DrmModeCrtcUapi::default(), None),
        Request::PageFlip(DrmModePageFlipUapi::default()),
        Request::SetPlane(raw_plane),
        Request::Cursor(
            LegacyCursor {
                flags: 2,
                crtc_id: CRTC,
                position: (0, 0),
                size: (0, 0),
                handle: 0,
            },
            None,
        ),
        Request::Property {
            object: PRIMARY,
            kind: DRM_MODE_OBJECT_PLANE,
            prop: PLANE_CRTC_X_PROP_ID,
            value: 0,
        },
    ];
    for request in &requests {
        let targets = request.targets(&f.mode.lock()).unwrap();
        let proof = CommitAdmission {
            open: MASTER,
            request,
            targets: Some(&targets),
        };
        if request.commit(f.index, &f.mode, &ctx, None, None, Some(&proof))
            != Err(FsError::PermissionDenied)
        {
            return TestResult::Fail("decoded commit bypassed current DRM master");
        }
    }
    if a.pinned() || f.mode.lock().crtcs[0].primary_fb != Some(fa) {
        return TestResult::Fail("refused commit mutated state or pinned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_commit_rechecks_target_identity_and_master
);

fn kms_prepare_owned_atomic_bounds_guarded_copy_and_test_only() -> TestResult {
    let Ok(f) = Fixture::new(1) else {
        return TestResult::Fail("fixture");
    };
    let mut objects = [PRIMARY];
    let mut counts = [1u32];
    let mut props = [PLANE_FB_ID_PROP_ID];
    let mut values = [17u64];
    let mut header = DrmModeAtomicUapi {
        count_objs: 1,
        objs_ptr: objects.as_mut_ptr() as u64,
        count_props_ptr: counts.as_mut_ptr() as u64,
        props_ptr: props.as_mut_ptr() as u64,
        prop_values_ptr: values.as_mut_ptr() as u64,
        ..Default::default()
    };
    let addr = (&mut header as *mut DrmModeAtomicUapi) as usize;
    let Ok(owned) = copy_atomic(addr) else {
        return TestResult::Fail("atomic copy");
    };
    objects[0] = 0;
    counts[0] = 0;
    props[0] = 0;
    values[0] = 99;
    if owned.objects != [PRIMARY]
        || owned.counts != [1]
        || owned.props != [PLANE_FB_ID_PROP_ID]
        || owned.values != [17]
    {
        return TestResult::Fail("atomic arrays were not owned snapshots");
    }
    header.count_objs = 257;
    if copy_atomic(addr).map(|_| ()) != Err(FsError::InvalidData) {
        return TestResult::Fail("atomic object limit");
    }
    header.count_objs = 1;
    counts[0] = 4097;
    if copy_atomic(addr).map(|_| ()) != Err(FsError::OutOfMemory) {
        return TestResult::Fail("atomic property limit");
    }
    counts[0] = 1;
    {
        use super::super::kernel_test_buffers::StrictUserCopies;
        let _strict = StrictUserCopies::allowing(addr, core::mem::size_of::<DrmModeAtomicUapi>());
        if copy_atomic(addr).map(|_| ()) != Err(FsError::BadAddress) {
            return TestResult::Fail("nested atomic array bypassed guarded copy");
        }
    }
    header = DrmModeAtomicUapi {
        flags: 0x100,
        ..Default::default()
    };
    let Some(_gate) = gem::try_placement(f.index) else {
        return TestResult::Fail("placement admission");
    };
    let mut probe = alloc::boxed::Box::pin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        (&mut header as *mut DrmModeAtomicUapi) as usize,
        &f.gem,
        None,
        None,
    ));
    let mut context = Context::from_waker(Waker::noop());
    if probe.as_mut().poll(&mut context) != Poll::Ready(Some(Ok(0))) {
        return TestResult::Fail("TEST_ONLY acquired placement admission or mutated state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_owned_atomic_bounds_guarded_copy_and_test_only
);

fn kms_prepare_terminal_loss_refuses_queued_and_new_ioctls() -> TestResult {
    let Ok(f) = Fixture::new(1) else {
        return TestResult::Fail("fixture");
    };
    let Some(held) = gem::try_placement(f.index) else {
        return TestResult::Fail("placement guard");
    };
    let mut header = DrmModeAtomicUapi::default();
    let mut request = alloc::boxed::Box::pin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        (&mut header as *mut DrmModeAtomicUapi) as usize,
        &f.gem,
        None,
        None,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if !request.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("KMS did not wait behind reset admission");
    }
    gem::mark_placement_lost(f.index);
    if request.as_mut().poll(&mut cx) != Poll::Ready(Some(Err(FsError::NoDevice)))
        || narf_scheduler::block_on_spin(dispatch(
            f.index,
            MASTER,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            0,
            &f.gem,
            None,
            None,
        )) != Some(Err(FsError::NoDevice))
    {
        return TestResult::Fail("lost device left a queued or new client waiting");
    }
    drop(held);
    if f.object().err() != Some(FsError::NoDevice)
        || f.gem.create_dumb(64, 12, 32).err() != Some(FsError::NoDevice)
        || !matches!(
            narf_scheduler::block_on_spin(gem::prepare_scanout(f.index, Vec::new())),
            Err(FsError::NoDevice)
        )
    {
        return TestResult::Fail("lost card permitted allocation or preparation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_terminal_loss_refuses_queued_and_new_ioctls
);

fn kms_prepare_invalid_requests_do_not_migrate_or_reclaim() -> TestResult {
    let Ok(f) = Fixture::new(2) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(front), Ok(idle), Ok(target)) = (f.object(), f.object(), f.object()) else {
        return TestResult::Fail("objects");
    };
    let (Ok(fa), Ok(fb)) = (
        f.fb(front.clone(), MASTER, false),
        f.fb(target.clone(), OTHER, false),
    ) else {
        return TestResult::Fail("framebuffers");
    };
    f.mode.lock().crtcs[0].primary_fb = Some(fa);
    let Ok(_pin) = front.pin_scanout() else {
        return TestResult::Fail("front pin");
    };
    let events = Events::new(crate::drm::card::DrmEventQueue::new());
    let mut cases = Vec::new();
    let mut flip_flags = vec![0u8; 24];
    flip_flags[..4].copy_from_slice(&CRTC.to_le_bytes());
    flip_flags[4..8].copy_from_slice(&fb.to_le_bytes());
    flip_flags[8..12].copy_from_slice(&2u32.to_le_bytes());
    cases.push((0xb0, flip_flags, FsError::InvalidData));
    let mut flip_crtc = vec![0u8; 24];
    flip_crtc[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    flip_crtc[4..8].copy_from_slice(&fb.to_le_bytes());
    cases.push((0xb0, flip_crtc, FsError::NotFound));
    let mut setcrtc = vec![0u8; 104];
    setcrtc[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    setcrtc[16..20].copy_from_slice(&fb.to_le_bytes());
    cases.push((0xa2, setcrtc, FsError::NotFound));
    let mut plane = vec![0u8; 48];
    plane[..4].copy_from_slice(&PRIMARY.to_le_bytes());
    plane[8..12].copy_from_slice(&fb.to_le_bytes());
    cases.push((0xb7, plane.clone(), FsError::NotFound));
    plane[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    plane[4..8].copy_from_slice(&CRTC.to_le_bytes());
    cases.push((0xb7, plane, FsError::NotFound));
    let mut cursor = vec![0u8; 28];
    cursor[..4].copy_from_slice(&4u32.to_le_bytes());
    cursor[4..8].copy_from_slice(&CRTC.to_le_bytes());
    cases.push((0xa3, cursor.clone(), FsError::InvalidData));
    cursor[..4].copy_from_slice(&1u32.to_le_bytes());
    cursor[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push((0xa3, cursor, FsError::NotFound));
    let mut property = vec![0u8; 20];
    property[..8].copy_from_slice(&u64::from(fb).to_le_bytes());
    property[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    property[12..16].copy_from_slice(&PRIMARY.to_le_bytes());
    property[16..20].copy_from_slice(&DRM_MODE_OBJECT_PLANE.to_le_bytes());
    cases.push((0xba, property, FsError::InvalidData));
    for (nr, mut bytes, expected) in cases {
        let cmd = drm_uapi::iowr(u32::from(b'd'), nr, bytes.len() as u32);
        if narf_scheduler::block_on_spin(dispatch(
            f.index,
            MASTER,
            cmd,
            bytes.as_mut_ptr() as usize,
            &f.gem,
            Some(&events),
            None,
        )) != Some(Err(expected))
        {
            return TestResult::Fail("invalid legacy request error precedence");
        }
        if idle.system()
            || !target.system()
            || f.mode.lock().crtcs[0].primary_fb != Some(fa)
            || events.lock().next_event_deadline_ns(u64::MAX).is_some()
        {
            return TestResult::Fail("invalid legacy request moved a BO or changed KMS state");
        }
    }
    let objects = [PRIMARY];
    let counts = [2u32];
    let props = [PLANE_FB_ID_PROP_ID, u32::MAX];
    let values = [u64::from(fb), 0];
    let mut header = DrmModeAtomicUapi {
        count_objs: 1,
        objs_ptr: objects.as_ptr() as u64,
        count_props_ptr: counts.as_ptr() as u64,
        props_ptr: props.as_ptr() as u64,
        prop_values_ptr: values.as_ptr() as u64,
        ..Default::default()
    };
    if narf_scheduler::block_on_spin(dispatch(
        f.index,
        MASTER,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        (&mut header as *mut DrmModeAtomicUapi) as usize,
        &f.gem,
        Some(&events),
        None,
    )) != Some(Err(FsError::InvalidData))
        || idle.system()
        || !target.system()
        || target.pinned()
    {
        return TestResult::Fail("invalid atomic property promoted target or reclaimed idle BO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_invalid_requests_do_not_migrate_or_reclaim
);

fn kms_prepare_cursor_uses_native_dumb_alias_in_own_open() -> TestResult {
    let Ok(f) = Fixture::new(2) else {
        return TestResult::Fail("fixture");
    };
    let (handle, _, _) = match f.gem.create_dumb(64, 12, 32) {
        Ok(result) => result,
        Err(error) => {
            let _ = core::fmt::Write::write_fmt(
                &mut narf_console::Writer,
                format_args!(
                    "  cursor CREATE_DUMB card{}: {error:?}; live {:?}; heap {:?}; layout {:?}\n",
                    f.index,
                    gem::ensure_placement_live(f.index),
                    gem::vram_heap_usage(f.index),
                    gem::dumb_layout(64, 12, 32)
                ),
            );
            return TestResult::Fail("native CREATE_DUMB");
        }
    };
    let Some(object) = f.gem.object(handle) else {
        return TestResult::Fail("dumb alias not in own GEM table");
    };
    let mut cursor = [0u8; 28];
    cursor[..4].copy_from_slice(&1u32.to_le_bytes());
    cursor[4..8].copy_from_slice(&CRTC.to_le_bytes());
    cursor[16..20].copy_from_slice(&64u32.to_le_bytes());
    cursor[20..24].copy_from_slice(&12u32.to_le_bytes());
    cursor[24..28].copy_from_slice(&handle.to_le_bytes());
    let (touched, moved) = narf_scheduler::block_on_spin(async {
        let gate = gem::lock_placement(f.index).await;
        gem::evict_all(&gate).await
    });
    gem::restore_domains(touched);
    if moved.is_err() || !object.system() {
        return TestResult::Fail("cursor fixture eviction");
    }
    let Ok(request) = Request::copy(0xa3, cursor.as_ptr() as usize, &f.gem) else {
        return TestResult::Fail("own native dumb cursor lookup");
    };
    if !one_target(&request, &f.mode.lock(), &object) || !object.system() {
        return TestResult::Fail("cursor prepared wrong own-open BO");
    }
    cursor[16..20].copy_from_slice(&32u32.to_le_bytes());
    if narf_scheduler::block_on_spin(dispatch(
        f.index,
        MASTER,
        drm_uapi::iowr(u32::from(b'd'), 0xa3, 28),
        cursor.as_ptr() as usize,
        &f.gem,
        None,
        None,
    )) != Some(Err(FsError::InvalidData))
        || !object.system()
    {
        return TestResult::Fail("invalid cursor shape promoted its copied own-open source");
    }
    cursor[16..20].copy_from_slice(&64u32.to_le_bytes());
    let other = GemState::for_card(f.index);
    if Request::copy(0xa3, cursor.as_ptr() as usize, &other)
        .err()
        .is_none()
    {
        return TestResult::Fail("cursor accepted another open's dumb alias");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_prepare_cursor_uses_native_dumb_alias_in_own_open
);

fn kms_allocation_and_lookup_observe_pm_placement_exclusion() -> TestResult {
    let Ok(f) = Fixture::new(2) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(a), Ok(b)) = (f.object(), f.object()) else {
        return TestResult::Fail("resident BOs");
    };
    let (held, touched, result) = narf_scheduler::block_on_spin(async {
        let held = gem::lock_placement(f.index).await;
        let (touched, result) = gem::evict_all(&held).await;
        (held, touched, result)
    });
    gem::restore_domains(touched);
    let usage = gem::vram_heap_usage(f.index);
    if result.is_err() || !a.system() || !b.system() || usage.map(|u| u.visible.1) != Some(0) {
        return TestResult::Fail("PM eviction snapshot");
    }
    // Lookup used to promote directly, bypassing PM's guard despite a
    // completely free heap. First native handle belongs to this BO.
    if f.gem.object(1).as_ref().is_none_or(|o| !Arc::ptr_eq(o, &a)) || !a.system() {
        return TestResult::Fail("lookup promoted after the PM eviction snapshot");
    }
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&PAGE.to_le_bytes());
    bytes[16..24]
        .copy_from_slice(&u64::from(crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    let before = bytes;
    if gem::dispatch(0xc020_6440, bytes.as_mut_ptr() as usize, &f.gem) != Err(FsError::Busy)
        || f.gem.create_dumb(64, 12, 32).err() != Some(FsError::Busy)
        || bytes != before
        || gem::vram_heap_usage(f.index) != usage
    {
        return TestResult::Fail("sync fast allocation bypassed PM admission");
    }
    let mut create = alloc::boxed::Box::pin(gem::dispatch_async(
        0xc020_6440,
        bytes.as_mut_ptr() as usize,
        &f.gem,
    ));
    let mut dumb = alloc::boxed::Box::pin(gem::create_dumb_async(&f.gem, 64, 12, 32));
    let mut cx = Context::from_waker(Waker::noop());
    if !create.as_mut().poll(&mut cx).is_pending()
        || !dumb.as_mut().poll(&mut cx).is_pending()
        || gem::vram_heap_usage(f.index) != usage
    {
        return TestResult::Fail("async fast allocation did not park before heap capture");
    }
    // Suspend withdraws the heap before releasing admission. Queued creates
    // must perform a fresh lookup: ordinary GEM retains its GTT fallback,
    // while dumb allocation requires a live VRAM heap.
    gem::unregister_vram_heap(f.index);
    drop(held);
    let created = narf_scheduler::block_on_spin(create);
    let handle = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    if created != Some(Ok(0))
        || narf_scheduler::block_on_spin(dumb).err() != Some(FsError::NoDevice)
        || !a.system()
        || !b.system()
        || f.gem.object_unvalidated(handle).is_none_or(|o| !o.system())
    {
        return TestResult::Fail("queued allocation published against a withdrawn heap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_allocation_and_lookup_observe_pm_placement_exclusion
);

fn kms_sync_allocation_reclaims_visible_vram_with_borrowed_admission() -> TestResult {
    let Ok(f) = Fixture::new(2) else {
        return TestResult::Fail("fixture");
    };
    let (Ok(a), Ok(b)) = (f.object(), f.object()) else {
        return TestResult::Fail("resident BOs");
    };
    // Both synchronous fast paths own the gate already. Their pressure
    // helper must borrow it, otherwise a recursive try-lock skips eviction.
    let Ok((dumb, _, _)) = f.gem.create_dumb(64, 12, 32) else {
        return TestResult::Fail("sync CREATE_DUMB skipped pressure eviction");
    };
    let Some(c) = f.gem.object_unvalidated(dumb) else {
        return TestResult::Fail("native dumb alias");
    };
    if !a.system() || b.system() || c.system() {
        return TestResult::Fail("CREATE_DUMB eviction placement");
    }
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&PAGE.to_le_bytes());
    bytes[16..24]
        .copy_from_slice(&u64::from(crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    if gem::dispatch(0xc020_6440, bytes.as_mut_ptr() as usize, &f.gem) != Ok(0) {
        return TestResult::Fail("sync GEM_CREATE skipped pressure eviction");
    }
    let handle = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let Some(d) = f.gem.object_unvalidated(handle) else {
        return TestResult::Fail("GEM_CREATE object");
    };
    if !b.system() || c.system() || d.system() || gem::try_placement(f.index).is_none() {
        return TestResult::Fail("GEM_CREATE eviction or admission release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_sync_allocation_reclaims_visible_vram_with_borrowed_admission
);

/// Navi22 as it publishes itself since the DCN30 overlays: synthesized
/// primaries (plane 0x40 + n, the CRTC's `primary_fb`) under two native
/// overlays and a cursor plane per CRTC. The primary is still the
/// synthesized one, so an atomic commit's primary framebuffer is still a
/// prepare_fb target (amdgpu_dm_plane_helper_prepare_fb pins every
/// plane's buffer), and a positioned primary keeps its SRC and CRTC
/// rectangles to the presenter (amdgpu_dm_plane_fill_dc_scaling_info).
/// The request is KWin's on a screen showing only the pointer: the pointer
/// image on the primary at the pointer position, overlays and cursor
/// plane off.
fn kms_synthesized_primary_under_overlays_keeps_target_and_placement() -> TestResult {
    let Ok(f) = Fixture::new(4) else {
        return TestResult::Fail("fixture");
    };
    {
        let mut c = f.mode.lock();
        c.driver_name = "amdgpu";
        c.gfx12_modifiers = false;
        c.native_planes = crate::drm_native_planes::overlay_cursor_planes_for(&[], &[CRTC]);
        c.overlay_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        c.plane_formats = Some(&[DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888]);
        if !c.has_native_kms_planes() {
            return TestResult::Fail("fixture publishes no native overlay");
        }
    }
    let Ok(object) = f.object() else {
        return TestResult::Fail("BO");
    };
    let Ok(fb) = f.fb(object.clone(), MASTER, false) else {
        return TestResult::Fail("ADDFB2");
    };
    let overlays = crate::drm_native_planes::overlay_ids(&f.mode.lock());
    let cursor = crate::drm_native_planes::cursor_ids(&f.mode.lock())[0];
    // obj69{IN_FENCE_FD=-1 FB_ID=0 CRTC_ID=0} obj68{..} obj70{..}
    // obj64{CRTC_H CRTC_W CRTC_Y CRTC_X SRC_H SRC_W SRC_Y SRC_X
    // IN_FENCE_FD FB_ID CRTC_ID}: a 32x12 view at CRTC (16, 0) of the
    // 64x12 mode.
    let off = [
        PLANE_IN_FENCE_FD_PROP_ID,
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
    ];
    let mut props: Vec<u32> = Vec::new();
    let mut values: Vec<u64> = Vec::new();
    for _ in 0..3 {
        props.extend_from_slice(&off);
        values.extend_from_slice(&[u64::MAX, 0, 0]);
    }
    props.extend_from_slice(&[
        PLANE_CRTC_H_PROP_ID,
        PLANE_CRTC_W_PROP_ID,
        PLANE_CRTC_Y_PROP_ID,
        PLANE_CRTC_X_PROP_ID,
        PLANE_SRC_H_PROP_ID,
        PLANE_SRC_W_PROP_ID,
        PLANE_SRC_Y_PROP_ID,
        PLANE_SRC_X_PROP_ID,
        PLANE_IN_FENCE_FD_PROP_ID,
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
    ]);
    values.extend_from_slice(&[
        12,
        32,
        0,
        16,
        12 << 16,
        32 << 16,
        0,
        0,
        u64::MAX,
        u64::from(fb),
        u64::from(CRTC),
    ]);
    let request = atomic(
        &[overlays[1], overlays[0], cursor, PRIMARY],
        &[3, 3, 3, 11],
        &props,
        &values,
    );
    if !one_target(&request, &f.mode.lock(), &object) {
        return TestResult::Fail("synthesized primary's framebuffer is no prepare_fb target");
    }
    if request.validate(f.index, &f.mode, MASTER, None).is_err() {
        return TestResult::Fail("positioned synthesized primary refused");
    }
    let mut state = crate::drm::atomic::AtomicState::default();
    state.planes.push(crate::drm::atomic::PlaneState {
        id: PRIMARY,
        crtc_id: Some(CRTC),
        fb_id: Some(fb),
        crtc_x: 16,
        crtc_y: 0,
        crtc_w: 32,
        crtc_h: 12,
        src_x: 0,
        src_y: 0,
        src_w: 32,
        src_h: 12,
        ..Default::default()
    });
    let placed = synthesized_primary_placement(&f.mode.lock(), &state, CRTC, fb);
    if placed
        != Some(crate::drm::card::Placement {
            src: (0, 0, 32, 12),
            dst: (16, 0, 32, 12),
        })
    {
        return TestResult::Fail("positioned synthesized primary lost its placement");
    }
    // The full screen unscaled is no placement.
    state.planes[0].crtc_x = 0;
    state.planes[0].crtc_w = 64;
    state.planes[0].src_w = 64;
    if synthesized_primary_placement(&f.mode.lock(), &state, CRTC, fb).is_some() {
        return TestResult::Fail("full-screen primary reported a placement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_synthesized_primary_under_overlays_keeps_target_and_placement
);

/// A commit the check accepts is one the presenter shows
/// (dc_validate_global_state admits what dc_commit_streams programs): an
/// overlay on a CRTC driving HDMI skips the display's own admission only
/// where the HDMI format search plans the planes itself (Navi48). Navi22's
/// search validates the stream alone and its presenter shows no overlay
/// yet, so its display is still asked and the overlay is refused, on HDMI
/// as on DisplayPort; the compositor then composites onto the primary.
fn kms_hdmi_planes_admitted_by_whoever_plans_them() -> TestResult {
    // Navi22 on HDMI: the display decides, and refuses.
    if planes_admitted(true, false, || false) {
        return TestResult::Fail("HDMI overlay admitted with no plane admission at all");
    }
    if !planes_admitted(true, false, || true) {
        return TestResult::Fail("HDMI overlay refused though its display admits it");
    }
    // Navi48 on HDMI: the format search decides; the display is not asked.
    let mut asked = false;
    if !planes_admitted(true, true, || {
        asked = true;
        false
    }) || asked
    {
        return TestResult::Fail("HDMI format search did not decide the planes");
    }
    // Any other output: the display decides.
    if planes_admitted(false, true, || false) || !planes_admitted(false, false, || true) {
        return TestResult::Fail("non-HDMI planes not decided by their display");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    kms_hdmi_planes_admitted_by_whoever_plans_them
);
