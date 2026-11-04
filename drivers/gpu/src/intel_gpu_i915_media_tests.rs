// Raw registered compatibility dispatcher -> retained main-GuC media owners.
// Linux b90c984d i915_getparam.c, i915_gem_execbuffer.c:2439-2464,2625-2690.
use super::*;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_gt::Gen12Platform;

const SPARSE: u32 = 0x000f00ff & !0x00040042; // physical VCS1/6, VECS2
fn media(family: Gen12Platform, fuse: u32) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Gen12(family), 0x130044);
    w.0.borrow_mut().regs.insert(0x9140, fuse);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let fence = gt.begin_context_defaults(10_000_000).unwrap();
    let mut registered = BTreeMap::new();
    for now in 10_000_001..10_001_025 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
    (w, arena, gt)
}
fn parameter(file: &RenderFile, card: u32, user: &Cpu, key: u32) -> Result<u32, FsError> {
    let mut wire = [0; 16];
    put32(&mut wire, 0, key);
    put64(&mut wire, 8, 4096);
    user.wire.store(64, &wire);
    file.dispatch_card(card, abi::GETPARAM, 64, user).unwrap()?;
    Ok(u32_at(&user.wire.load(4096, 4), 0))
}
fn handles(file: &RenderFile, card: u32, user: &Cpu) -> [u32; 2] {
    make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, user), Some(Ok(0)))
    })
}
fn submit(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    now: u64,
) -> (Arc<UserContext>, Arc<CompletionFence>) {
    let mut call =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let accepted = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    accepted
}
fn poll_refusal(file: &RenderFile, card: u32, user: &Cpu, error: FsError) {
    let mut call =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, user));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Err(error)))
    );
}
fn close(file: &RenderFile, card: u32, user: &Cpu, command: u32, id: u32) {
    let mut wire = [0; 8];
    put32(&mut wire, 0, id);
    user.wire.store(64, &wire);
    assert_eq!(file.dispatch_card(card, command, 64, user), Some(Ok(0)));
}
fn smoke_i915_media_getparam_reports_only_current_published_dense_engines() -> TestResult {
    for fuse in [SPARSE, 0x000f00ff, 0x000f00ff & !0x40] {
        let (w, arena, mut gt) = media(Gen12Platform::TigerLake, fuse);
        let (mailbox, info, card) =
            registered(&mut gt, &w, GtPlatform::Gen12(Gen12Platform::TigerLake));
        let file = RenderFile::new();
        let user = Cpu::new();
        let mut version = [0; 64];
        put64(&mut version, 16, 8);
        put64(&mut version, 24, 4096);
        user.wire.store(64, &version);
        assert_eq!(
            file.dispatch_card(card, crate::drm_uapi::DRM_IOCTL_VERSION, 64, &user),
            Some(Ok(0))
        );
        assert_eq!(user.wire.load(4096, 2), b"xe");
        let expected = if fuse == SPARSE {
            [1, 1, 1, 1]
        } else if fuse == 0x000f00ff {
            [0, 1, 0, 0]
        } else {
            [1, 1, 0, 0]
        };
        for (key, value) in [10, 11, 22, 31].into_iter().zip(expected) {
            assert_eq!(parameter(&file, card, &user, key), Ok(value));
        }
        if expected[0] == 0 {
            let handles = handles(&file, card, &user);
            let before = arena.live_allocations();
            for ring in [2, 4] {
                legacy_exec(&user.wire, handles, 0);
                set_ring(&user.wire, ring);
                poll_refusal(&file, card, &user, FsError::InvalidData);
                assert!(mailbox.pending.lock().is_empty());
                assert_eq!(arena.live_allocations(), before);
            }
        }
        let mut status = (*mailbox.status.lock()).unwrap();
        status.engines = EngineSet::of(&[Engine::Rcs0]);
        *mailbox.status.lock() = Some(status);
        for key in [10, 11, 22, 31] {
            assert_eq!(parameter(&file, card, &user, key), Ok(0));
        }
        *mailbox.status.lock() = None;
        for key in [10, 11, 22, 31] {
            assert_eq!(parameter(&file, card, &user, key), Ok(0));
        }
        // Wrong-platform retained status cannot fabricate discovery either.
        status.platform = GtPlatform::Battlemage;
        *mailbox.status.lock() = Some(status);
        for key in [10, 11, 22, 31] {
            assert_eq!(parameter(&file, card, &user, key), Ok(0));
        }
        drop(info);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_media_getparam_reports_only_current_published_dense_engines
);

fn smoke_i915_media_raw_bsd_selectors_and_vebox_preserve_independent_context_state() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ] {
        let (w, arena, mut gt) = media(family, SPARSE);
        let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
        let file = RenderFile::new();
        let user = Cpu::new();
        let id = prototype(&file, card, &user);
        let handles = handles(&file, card, &user);
        let mut prior = Vec::new();
        for (slot, ring, expected) in [
            (0, 2 | 1 << 13, Engine::Vcs1),
            (1, 2 | 2 << 13, Engine::Vcs6),
            (2, 4, Engine::Vecs2),
        ] {
            for pass in 0..2 {
                legacy_exec(&user.wire, handles, id);
                set_ring(&user.wire, ring);
                let now = 20_000_000 + slot * 1000 + pass * 100;
                let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
                assert_eq!(context.engine(), expected);
                if pass == 0 {
                    prior.push(context.clone());
                } else {
                    assert!(Arc::ptr_eq(&context, &prior[slot as usize]));
                }
                let mut registered = BTreeMap::new();
                let mut seen = false;
                for tick in now + 1..now + 60 {
                    assert_eq!(gt.poll(tick), Poll::Ready(Ok(GtState::SchedulingReady)));
                    service_contexts(&w, &mut registered, true);
                    if !seen {
                        if let Some(base) = registered.values().next() {
                            let d = w.0.borrow();
                            let mut image = d.memory[base].borrow_mut();
                            assert_eq!(image[1026], expected.base() + 0x244);
                            if pass == 1 {
                                assert_eq!(image[0x1800 / 4], 0x7a130000 + slot as u32);
                            }
                            image[0x1800 / 4] = 0x7a130000 + slot as u32;
                            seen = true;
                        }
                    }
                    if fence.result().is_some() {
                        break;
                    }
                }
                assert!(seen);
                assert_eq!(fence.result(), Some(Ok(())));
                assert!(registered.is_empty());
                let mut value = [0; 4];
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .read(128, &mut value)
                    .unwrap();
                assert_eq!(u32::from_le_bytes(value), 0x4e415246);
            }
        }
        assert!(prior
            .iter()
            .enumerate()
            .all(|(i, a)| prior.iter().skip(i + 1).all(|b| !Arc::ptr_eq(a, b))));
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_media_raw_bsd_selectors_and_vebox_preserve_independent_context_state
);

fn smoke_i915_media_default_is_per_open_and_single_bsd_selectors_follow_source() -> TestResult {
    for fuse in [SPARSE, 0x000f00ff & !0x40] {
        let (w, arena, mut gt) = media(Gen12Platform::AlderLakeP, fuse);
        let (mailbox, _, card) =
            registered(&mut gt, &w, GtPlatform::Gen12(Gen12Platform::AlderLakeP));
        let file = RenderFile::new();
        let user = Cpu::new();
        let handles = handles(&file, card, &user);
        let ids = [prototype(&file, card, &user), prototype(&file, card, &user)];
        let mut default = None;
        for (index, selector) in if fuse == SPARSE {
            [0, 0, 0, 0]
        } else {
            [0, 1, 2, 3]
        }
        .into_iter()
        .enumerate()
        {
            legacy_exec(&user.wire, handles, ids[index % 2]);
            set_ring(&user.wire, 2 | selector << 13);
            let now = 30_000_000 + index as u64 * 100;
            let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
            if let Some(engine) = default {
                assert_eq!(context.engine(), engine);
            } else {
                default = Some(context.engine());
            }
            assert!(matches!(context.engine(), Engine::Vcs1 | Engine::Vcs6));
            if fuse != SPARSE {
                assert_eq!(context.engine(), Engine::Vcs6);
            }
            // i915 compatibility contexts retain the existing low3 policy;
            // Xe native CREATE alone configures its default normal2 policy.
            let mut registered = BTreeMap::new();
            finish_policy(&mut gt, &w, &fence, &mut registered, now + 1, 3);
        }
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_media_default_is_per_open_and_single_bsd_selectors_follow_source
);

fn smoke_i915_media_bad_legacy_selectors_refuse_before_dma_and_explicit_map_ignores_them(
) -> TestResult {
    let (w, arena, mut gt) = media(Gen12Platform::AlderLakeP, SPARSE);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(Gen12Platform::AlderLakeP));
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = handles(&file, card, &user);
    let id = prototype(&file, card, &user);
    let before = arena.live_allocations();
    for ring in [
        2 | 3 << 13,
        1 | 1 << 13,
        3 | 2 << 13,
        4 | 1 << 13,
        2 | 1 << 15,
        5,
        63,
    ] {
        legacy_exec(&user.wire, handles, id);
        set_ring(&user.wire, ring);
        poll_refusal(&file, card, &user, FsError::InvalidData);
        assert!(mailbox.pending.lock().is_empty());
        assert_eq!(arena.live_allocations(), before);
        assert_eq!(file.gem.object(handles[1]).unwrap().busy(), 0);
    }
    let mapped = prototype(&file, card, &user);
    let param = engines_param(&user.wire, mapped, &[(2, 1)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    legacy_exec(&user.wire, handles, mapped);
    set_ring(&user.wire, 3 << 13);
    let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, 40_000_000);
    assert_eq!(context.engine(), Engine::Vcs6);
    let mut registered = BTreeMap::new();
    finish_policy(&mut gt, &w, &fence, &mut registered, 40_000_001, 3);
    *mailbox.status.lock() = None;
    legacy_exec(&user.wire, handles, id);
    set_ring(&user.wire, 2);
    poll_refusal(&file, card, &user, FsError::NoDevice);
    assert_eq!(arena.live_allocations(), before);
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_media_bad_legacy_selectors_refuse_before_dma_and_explicit_map_ignores_them
);

fn smoke_i915_media_context_close_and_authority_loss_keep_vm_bo_and_state_until_reset() -> TestResult
{
    for ring in [2 | 2 << 13, 4] {
        let (w, arena, mut gt) = media(Gen12Platform::AlderLakeP, SPARSE);
        let (mailbox, _, card) =
            registered(&mut gt, &w, GtPlatform::Gen12(Gen12Platform::AlderLakeP));
        let file = RenderFile::new();
        let user = Cpu::new();
        let handles = handles(&file, card, &user);
        let id = prototype(&file, card, &user);
        let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
        legacy_exec(&user.wire, handles, id);
        set_ring(&user.wire, ring);
        let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, 50_000_000);
        let mut registered = BTreeMap::new();
        for now in 50_000_001..50_000_030 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        assert_eq!(registered.len(), 1);
        assert!(context.busy());
        assert!(fence.result().is_none());
        close(&file, card, &user, abi::GEM_CONTEXT_DESTROY, id);
        for handle in handles {
            close(&file, card, &user, abi::GEM_CLOSE, handle);
        }
        drop(file);
        let live = arena.live_allocations();
        assert!(gt.poll_with_access(50_000_031, || false).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        assert_eq!(arena.live_allocations(), live);
        assert!(weak.iter().all(|w| w.upgrade().is_some()));
        assert!(fence.result().is_none());
        hardware_stop(&mut gt, &w, 0x130044);
        assert_eq!(
            fence.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert!(!context.busy());
        assert!(weak.iter().all(|w| w.upgrade().is_none()));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_media_context_close_and_authority_loss_keep_vm_bo_and_state_until_reset
);

mod sseu {
    include!("intel_gpu_i915_media_sseu_tests.rs");
}
