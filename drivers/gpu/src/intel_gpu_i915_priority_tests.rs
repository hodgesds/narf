// i915 context priority -> GuC SCHEDULING_PRIORITY through registered node
// ioctls, the retained UserContexts and the real GuC scheduler. MIT Linux
// b90c984d: i915_gem_context.c validate_priority/set_priority/
// set_proto_ctx_param, i915_request.c::__i915_request_ensure_ordering,
// i915_scheduler.c::__i915_schedule and intel_guc_submission.c
// map_i915_prio_to_guc_prio/guc_context_set_prio/
// guc_bump_inflight_request_prio/guc_context_policy_init_v70.
use super::*;

static PRIORITY_NICE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
fn priority_capable(capability: u32) -> bool {
    capability == 23 && PRIORITY_NICE.load(core::sync::atomic::Ordering::Acquire)
}
/// Installs credentials holding CAP_SYS_NICE (23) or not; restores the
/// previous hook on drop.
struct PriorityCredentials(Option<fn(u32) -> bool>);
impl PriorityCredentials {
    fn install(nice: bool) -> Self {
        PRIORITY_NICE.store(nice, core::sync::atomic::Ordering::Release);
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            priority_capable,
        )))
    }
}
impl Drop for PriorityCredentials {
    fn drop(&mut self) {
        let _ = narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}

/// drm_i915_gem_context_param for I915_CONTEXT_PARAM_PRIORITY (6).
fn priority_param(id: u32, value: i64) -> [u8; 24] {
    let mut bytes = [0; 24];
    put32(&mut bytes, 0, id);
    put64(&mut bytes, 8, 6);
    put64(&mut bytes, 16, value as u64);
    bytes
}
fn set_priority(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    id: u32,
    value: i64,
) -> Result<u64, FsError> {
    user.wire.store(64, &priority_param(id, value));
    file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, user)
        .unwrap()
}
fn get_priority(file: &RenderFile, card: u32, user: &Cpu, id: u32) -> i64 {
    user.wire.store(64, &priority_param(id, 0x5a5a));
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_GETPARAM, 64, user),
        Some(Ok(0))
    );
    u64_at(&user.wire.load(64, 24), 16) as i64
}

/// UPDATE_CONTEXT_POLICIES pending in the host CT, before the model consumes
/// them: full registration policies and priority-only updates, each as
/// (GuC context id, SCHEDULING_PRIORITY).
#[allow(clippy::type_complexity)]
fn priority_policies(w: &Window) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) {
    let (mut full, mut updates) = (Vec::new(), Vec::new());
    for request in pending(w) {
        if request[0] as u16 != 0x100b {
            continue;
        }
        assert_eq!(request[2], 0x20030001);
        match request.len() {
            10 => full.push((request[1], request[3])),
            4 => updates.push((request[1], request[3])),
            n => panic!("{n}-word UPDATE_CONTEXT_POLICIES"),
        }
    }
    (full, updates)
}

/// Run one accepted job to retirement. Its registration names `band`, and
/// no priority-only update is sent.
fn run_band(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    start: u64,
    band: u32,
) {
    let mut registered = BTreeMap::new();
    let mut seen = Vec::new();
    for now in start..start + 100 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        let (full, updates) = priority_policies(w);
        assert!(updates.is_empty(), "priority update outside a raise");
        seen.extend(full.into_iter().map(|(_, priority)| priority));
        service_contexts(w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(seen, [band]);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}

/// Clear the batch's output word, select the ring and run one execbuffer at
/// `band`.
#[allow(clippy::too_many_arguments)]
fn exec_band(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    handles: [u32; 2],
    id: u32,
    ring: u64,
    now: u64,
    band: u32,
) -> Arc<UserContext> {
    file.gem
        .object(handles[1])
        .unwrap()
        .write(0x80, &[0; 4])
        .unwrap();
    raw(user, handles, id, ring);
    let (context, fence) = submit(file, card, user, mailbox, gt, now);
    run_band(gt, w, &fence, now + 1, band);
    assert_eq!(word(file, handles[1]), 0x4e415246);
    context
}

fn smoke_i915_priority_default_contexts_register_kmd_normal() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Gen12(Gen12Platform::TigerLake), 0x130044),
        (GtPlatform::Integrated(Generation::MeteorLake), 0xdfc),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (mailbox, _, card) = super::super::registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let handles = pair(&file, card, &user);
        // Context 0 from open, a plain CREATE, and a CREATE_EXT link that
        // sets the default I915_CONTEXT_DEFAULT_PRIORITY explicitly.
        let created = create(&file, card, &user, &[]).unwrap();
        let explicit = create(&file, card, &user, &[priority_param(0, 0)]).unwrap();
        let mut now = 20_000_000;
        for id in [0, created, explicit] {
            for (ring, engine) in [(1, Engine::Rcs0), (3, Engine::Bcs0)] {
                let context = exec_band(
                    &file, card, &user, &mailbox, &mut gt, &w, handles, id, ring, now, 2,
                );
                assert_eq!(context.engine(), engine);
                now += 200;
            }
            assert_eq!(get_priority(&file, card, &user, id), 0);
        }
        assert!(w.0.borrow().priority_updates.is_empty());
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_priority_default_contexts_register_kmd_normal
);

/// A PRIORITY set with no job in flight sends GuC nothing; each hardware
/// member, including ones created after the set, registers its next job in
/// the mapped band: NORMAL3 below 0, KMD_NORMAL2 at 0, HIGH1 above.
fn smoke_i915_priority_bands_apply_at_the_next_registration() -> TestResult {
    let _credentials = PriorityCredentials::install(true);
    let platform = GtPlatform::Integrated(Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, _, card) = super::super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    let mut now = 20_000_000;
    // ctx_setparam on a finalized context, between jobs.
    let id = create(&file, card, &user, &[]).unwrap();
    for (value, band) in [
        (-1023, 3),
        (-1, 3),
        (0, 2),
        (1, 1),
        (1023, 1),
        (-5, 3),
        (0, 2),
    ] {
        let writes = w.0.borrow().writes.len();
        assert_eq!(set_priority(&file, card, &user, id, value), Ok(0));
        assert_eq!(
            priority_policies(&w),
            (Vec::new(), Vec::new()),
            "set_priority queued a policy"
        );
        assert_eq!(w.0.borrow().writes.len(), writes);
        for ring in [1, 3] {
            exec_band(
                &file, card, &user, &mailbox, &mut gt, &w, handles, id, ring, now, band,
            );
            now += 200;
        }
        assert_eq!(get_priority(&file, card, &user, id), value);
    }
    // set_proto_ctx_param through CREATE_EXT.
    for (value, band) in [(-1, 3), (7, 1)] {
        let id = create(&file, card, &user, &[priority_param(0, value)]).unwrap();
        exec_band(
            &file, card, &user, &mailbox, &mut gt, &w, handles, id, 1, now, band,
        );
        now += 200;
    }
    // A late proto SET (graphics 12.70), then an engine map: the slots
    // created after the priority carry it.
    let id = prototype(&file, card, &user);
    assert_eq!(set_priority(&file, card, &user, id, 9), Ok(0));
    let map = engines_param(&user.wire, id, &[(0, 0), (1, 0)], 8192);
    user.wire.store(64, &map);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    for (slot, engine) in [(0, Engine::Rcs0), (1, Engine::Bcs0)] {
        let context = exec_band(
            &file, card, &user, &mailbox, &mut gt, &w, handles, id, slot, now, 1,
        );
        assert_eq!(context.engine(), engine);
        now += 200;
    }
    assert!(w.0.borrow().priority_updates.is_empty());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_priority_bands_apply_at_the_next_registration
);

/// Gen12 legacy BSD members are created at first use, after the set.
fn smoke_i915_priority_lazy_gen12_media_member_takes_the_context_band() -> TestResult {
    let _credentials = PriorityCredentials::install(true);
    let (w, arena, mut gt) = sparse_media(Gen12Platform::TigerLake);
    let (mailbox, _, card) =
        super::super::registered(&mut gt, &w, GtPlatform::Gen12(Gen12Platform::TigerLake));
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    let id = create(&file, card, &user, &[]).unwrap();
    assert_eq!(set_priority(&file, card, &user, id, 5), Ok(0));
    let mut now = 20_000_000;
    for (ring, engine, band) in [(2 | 1 << 13, Engine::Vcs1, 1), (4, Engine::Vecs2, 1)] {
        let context = exec_band(
            &file, card, &user, &mailbox, &mut gt, &w, handles, id, ring, now, band,
        );
        assert_eq!(context.engine(), engine);
        now += 1000;
    }
    // A later set reaches the existing media members' next registrations.
    assert_eq!(set_priority(&file, card, &user, id, -5), Ok(0));
    for ring in [2 | 1 << 13, 4] {
        exec_band(
            &file, card, &user, &mailbox, &mut gt, &w, handles, id, ring, now, 3,
        );
        now += 1000;
    }
    assert!(w.0.borrow().priority_updates.is_empty());
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_priority_lazy_gen12_media_member_takes_the_context_band
);

/// set_priority alone sends GuC nothing. The next execbuffer queues behind
/// the registered job and __i915_schedule bumps it, so GuC gets one
/// priority-only UPDATE_CONTEXT_POLICIES for that registration. A lower
/// request never demotes it. Each queued request registers with the
/// priority it was queued with, raised by the requests behind it.
fn smoke_i915_priority_raise_reaches_the_registered_job_through_the_next_request() -> TestResult {
    let _credentials = PriorityCredentials::install(true);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, _, card) = super::super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    let id = create(&file, card, &user, &[]).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut registered = BTreeMap::new();
    let step = |gt: &mut GuCGt<Window, Arena>,
                registered: &mut BTreeMap<u32, u32>,
                range: core::ops::Range<u64>| {
        let (mut full, mut updates) = (Vec::new(), Vec::new());
        for now in range {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            let (f, u) = priority_policies(&w);
            full.extend(f);
            updates.extend(u);
            service_contexts(&w, registered, false);
        }
        (full, updates)
    };

    // The first job registers at KMD_NORMAL2 and is enabled, not executed.
    raw(&user, handles, id, 1);
    let (context, first) = submit(&file, card, &user, &mailbox, &mut gt, 20_000_000);
    let (full, updates) = step(&mut gt, &mut registered, 20_000_001..20_000_040);
    assert_eq!(registered.len(), 1);
    let (&guc_id, &base) = registered.iter().next().unwrap();
    assert_eq!(full, [(guc_id, 2)]);
    assert!(updates.is_empty());
    assert!(first.is_submit_ready() && first.result().is_none());

    // ctx_setparam's set_priority stores 512 and sends GuC nothing.
    assert_eq!(set_priority(&file, card, &user, id, 512), Ok(0));
    let (full, updates) = step(&mut gt, &mut registered, 20_000_040..20_000_050);
    assert!(full.is_empty() && updates.is_empty());

    // The next request waits for the job, which it raises to HIGH1.
    raw(&user, handles, id, 1);
    let mut second =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert!(mailbox.pending.lock().is_empty());
    let (full, updates) = step(&mut gt, &mut registered, 20_000_050..20_000_060);
    assert!(full.is_empty());
    assert_eq!(updates, [(guc_id, 1)]);
    assert_eq!(w.0.borrow().priority_updates, [(guc_id, 1)]);

    // A lower request queued behind it demotes nothing.
    assert_eq!(set_priority(&file, card, &user, id, -5), Ok(0));
    raw(&user, handles, id, 1);
    let mut third =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
    assert!(third.as_mut().poll(&mut cx).is_pending());
    let (full, updates) = step(&mut gt, &mut registered, 20_000_060..20_000_070);
    assert!(full.is_empty() && updates.is_empty());

    // The first job retires; the second registers at the HIGH1 it was
    // queued with, not the later -5.
    complete_by_hand(&w, base);
    for now in 20_000_070..20_000_170 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert!(priority_policies(&w).1.is_empty());
        service_contexts(&w, &mut registered, false);
        if first.result().is_some() {
            break;
        }
    }
    assert_eq!(first.result(), Some(Ok(())));
    assert!(registered.is_empty() && !context.busy());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert_eq!(mailbox.pending.lock().len(), 1);
    let (same, fence) = mailbox.accept(&mut gt, 20_000_200);
    assert!(Arc::ptr_eq(&same, &context));
    assert_eq!(second.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
    run_band(&mut gt, &w, &fence, 20_000_201, 1);
    // The third registers at its own NORMAL3.
    assert!(third.as_mut().poll(&mut cx).is_pending());
    assert_eq!(mailbox.pending.lock().len(), 1);
    let (_, fence) = mailbox.accept(&mut gt, 20_000_400);
    assert_eq!(third.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
    run_band(&mut gt, &w, &fence, 20_000_401, 3);
    assert_eq!(word(&file, handles[1]), 0x4e415246);
    assert_eq!(get_priority(&file, card, &user, id), -5);
    assert_eq!(w.0.borrow().priority_updates, [(guc_id, 1)]);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_priority_raise_reaches_the_registered_job_through_the_next_request
);
