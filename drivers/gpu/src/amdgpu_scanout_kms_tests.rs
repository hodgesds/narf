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
    if f.gem.object(0x4000_0000).is_none() || !a.system() {
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
