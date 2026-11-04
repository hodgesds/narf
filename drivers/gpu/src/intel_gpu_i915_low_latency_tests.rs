// Real registered i915 ioctls -> retained UserContext -> GuC policy/ENABLE,
// private PPGTT execution and terminal retirement. Linux b90c984d:
// i915_getparam.c161-166, set_proto_ctx_param907, create_ioctl2405,
// guc_context_policy_init_v70 and ABI key0x2005/strategy bit28.
use super::*;
use crate::intel_gpu::Generation;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_gt::Gen12Platform;

fn drop_reply(w: &Window) {
    let memory = ct_memory(w);
    let mut words = memory.borrow_mut();
    let head = words[512];
    assert_eq!(
        words[513].wrapping_sub(head) & 4095,
        4,
        "one unobserved mode reply"
    );
    // Omit firmware's reply before the host observes it. HEAD stays owned by
    // the host; moving it would inject transport loss rather than a lost ACK.
    words[513] = head;
}

fn hint_param(id: u32, size: u32, value: u64) -> [u8; 24] {
    let mut bytes = [0; 24];
    put32(&mut bytes, 0, id);
    put32(&mut bytes, 4, size);
    put64(&mut bytes, 8, 0xe); // independent source literal
    put64(&mut bytes, 16, value);
    bytes
}
fn set_hint(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    id: u32,
    size: u32,
    value: u64,
) -> Result<u64, FsError> {
    user.wire.store(64, &hint_param(id, size, value));
    file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, user)
        .unwrap()
}
fn create_wire(user: &Cpu, params: &[[u8; 24]]) {
    for (index, param) in params.iter().enumerate() {
        let mut ext = [0; 56];
        if index + 1 != params.len() {
            put64(&mut ext, 0, 12_000 + (index as u64 + 1) * 64);
        }
        ext[32..].copy_from_slice(param);
        user.wire.store(12_000 + index as u64 * 64, &ext);
    }
    let mut wire = [0; 16];
    if !params.is_empty() {
        put32(&mut wire, 4, 1);
        put64(&mut wire, 8, 12_000);
    }
    user.wire.store(64, &wire);
}
fn create(file: &RenderFile, card: u32, user: &Cpu, params: &[[u8; 24]]) -> Result<u32, FsError> {
    create_wire(user, params);
    file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, user)
        .unwrap()?;
    Ok(u32_at(&user.wire.load(64, 16), 0))
}
fn get_hint(file: &RenderFile, card: u32, user: &Cpu) -> i32 {
    let mut wire = [0; 16];
    put32(&mut wire, 0, 59);
    put64(&mut wire, 8, 4096);
    user.wire.store(64, &wire);
    assert_eq!(
        file.dispatch_card(card, abi::GETPARAM, 64, user),
        Some(Ok(0))
    );
    i32::from_le_bytes(user.wire.load(4096, 4).try_into().unwrap())
}
fn pair(file: &RenderFile, card: u32, user: &Cpu) -> [u32; 2] {
    make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, user), Some(Ok(0)))
    })
}
fn raw(user: &Cpu, handles: [u32; 2], id: u32, ring: u64) {
    legacy_exec(&user.wire, handles, id);
    set_ring(&user.wire, ring);
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
    assert_eq!(mailbox.pending.lock().len(), 1);
    let result = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    result
}
fn pending(w: &Window) -> Vec<Vec<u32>> {
    let memory = ct_memory(w);
    let words = memory.borrow();
    let (mut head, tail) = (words[0], words[1]);
    let mut requests = Vec::new();
    while head != tail {
        let count = words[1024 + head as usize] & 255;
        requests.push(
            (1..=count)
                .map(|n| words[1024 + ((head + n) & 1023) as usize])
                .collect(),
        );
        head = (head + count + 1) & 1023;
    }
    requests
}
/// Every default-priority i915 context registers at
/// GUC_CLIENT_PRIORITY_KMD_NORMAL (map_i915_prio_to_guc_prio(0)).
fn policy(w: &Window, hint: bool) -> bool {
    let mut seen = false;
    for request in pending(w) {
        if request[0] as u16 == 0x100b {
            assert_eq!(request.len(), 10);
            assert_eq!(
                &request[2..],
                &[
                    0x20030001,
                    2,
                    0x20010001,
                    1000,
                    0x20020001,
                    500000,
                    0x20050001,
                    if hint { 0x10000000 } else { 0 }
                ]
            );
            seen = true;
        }
    }
    seen
}
fn run(gt: &mut GuCGt<Window, Arena>, w: &Window, fence: &CompletionFence, start: u64, hint: bool) {
    let mut registered = BTreeMap::new();
    let (mut seen, mut enabled) = (false, false);
    for now in start..start + 100 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if policy(w, hint) {
            assert!(!enabled, "policy followed ENABLE");
            assert!(!fence.is_submit_ready());
            seen = true;
        }
        let enable = pending(w)
            .iter()
            .any(|r| r[0] as u16 == 0x1001 && r[2] == 1);
        if enable {
            assert!(seen, "ENABLE overtook retained policy");
            assert!(!fence.is_submit_ready());
            enabled = true;
        }
        service_contexts(w, &mut registered, true);
        if enable {
            assert!(!fence.is_submit_ready(), "enqueue fabricated firmware ACK");
        }
        if fence.result().is_some() {
            break;
        }
    }
    assert!(seen && enabled);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}
fn word(file: &RenderFile, handle: u32) -> u32 {
    let mut value = [0; 4];
    file.gem
        .object(handle)
        .unwrap()
        .read(0x80, &mut value)
        .unwrap();
    u32::from_le_bytes(value)
}
fn close_id(file: &RenderFile, card: u32, user: &Cpu, cmd: u32, id: u32) {
    let mut wire = [0; 8];
    put32(&mut wire, 0, id);
    user.wire.store(64, &wire);
    assert_eq!(file.dispatch_card(card, cmd, 64, user), Some(Ok(0)));
}
struct NoWrite<'a>(&'a Cpu);
impl IoctlContext for NoWrite<'_> {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.0.read(address, bytes)
    }
    fn write(&self, _: u64, _: &[u8]) -> Result<(), FsError> {
        Err(FsError::BadAddress)
    }
    fn nonblocking(&self) -> bool {
        false
    }
}

fn smoke_i915_context_freq_hint_live_discovery_and_no_wake_refusal() -> TestResult {
    assert_eq!(abi::CONTEXT_PARAM_LOW_LATENCY, 0xe);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, mut info, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let good = mailbox.status().unwrap();
    let writes = w.0.borrow().writes.len();
    let allocations = arena.live_allocations();
    assert_eq!(get_hint(&file, card, &user), 1);
    for name in [
        alloc::format!("card{card}"),
        alloc::format!("renderD{}", card + 128),
    ] {
        let node = crate::drm_devfs_bridge::DriDir.lookup(&name).unwrap();
        get_hint(&file, card, &user);
        let mut call = core::pin::pin!(node.ioctl_user(abi::GETPARAM, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
        assert_eq!(
            i32::from_le_bytes(user.wire.load(4096, 4).try_into().unwrap()),
            1
        );
    }
    *mailbox.status.lock() = Some(UserStatus {
        submission_version: (1, 7, 3),
        ..good
    });
    assert_eq!(get_hint(&file, card, &user), 1);
    for bad in [
        None,
        Some(UserStatus { epoch: 0, ..good }),
        Some(UserStatus {
            platform: GtPlatform::Alchemist,
            ..good
        }),
        Some(UserStatus {
            engines: EngineSet::default(),
            ..good
        }),
        Some(UserStatus {
            submission_version: (0, 255, 255),
            ..good
        }),
        Some(UserStatus {
            submission_version: (2, 0, 0),
            ..good
        }),
    ] {
        *mailbox.status.lock() = bad;
        assert_eq!(get_hint(&file, card, &user), -22);
        assert_eq!(
            create(&file, card, &user, &[hint_param(0, 0, 1)]),
            Err(FsError::InvalidData)
        );
    }
    *mailbox.status.lock() = Some(good);
    get_hint(&file, card, &user);
    user.wire.store(4096, &[0xa5; 8]);
    assert_eq!(
        file.dispatch_card(card, abi::GETPARAM, 64, &NoWrite(&user)),
        Some(Err(FsError::BadAddress))
    );
    assert_eq!(user.wire.load(4096, 8), [0xa5; 8]);
    // Even an internally retained backend cannot qualify an unlisted profile.
    info.platform = GtPlatform::Integrated(Generation::TigerLake);
    user.wire.store(64, &{
        let mut b = [0; 16];
        put32(&mut b, 0, 59);
        put64(&mut b, 8, 4096);
        b
    });
    assert_eq!(file.dispatch(&info, abi::GETPARAM, 64, &user), Some(Ok(0)));
    assert_eq!(
        i32::from_le_bytes(user.wire.load(4096, 4).try_into().unwrap()),
        -22
    );
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(arena.live_allocations(), allocations);
    assert!(mailbox.pending.lock().is_empty());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_live_discovery_and_no_wake_refusal
);

fn smoke_i915_context_freq_hint_raw_proto_phase_and_create_rollback() -> TestResult {
    for (platform, ack, late) in [
        (GtPlatform::Gen12(Gen12Platform::TigerLake), 0x130044, true),
        (GtPlatform::Alchemist, 0x130044, true),
        (GtPlatform::Integrated(Generation::MeteorLake), 0xdfc, true),
        (GtPlatform::Battlemage, 0xdfc, false),
        (GtPlatform::Integrated(Generation::LunarLake), 0xdfc, false),
        (
            GtPlatform::Integrated(Generation::PantherLake),
            0xdfc,
            false,
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (_, _, card) = super::registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let writes = w.0.borrow().writes.len();
        let allocations = arena.live_allocations();
        let id = prototype(&file, card, &user);
        // Pinned source ignores value and size. No pointer read at u64::MAX.
        let result = if late {
            Ok(0)
        } else {
            Err(FsError::InvalidData)
        };
        assert_eq!(set_hint(&file, card, &user, id, 4096, u64::MAX), result);
        assert_eq!(set_hint(&file, card, &user, id, 0, 0), result);
        assert_eq!(
            set_hint(&file, card, &user, 0, 0, 1),
            Err(FsError::InvalidData)
        );
        assert_eq!(
            set_hint(&file, card, &user, u32::MAX, 0, 1),
            Err(FsError::NotFound)
        );
        user.wire.store(64, &hint_param(id, 0, 1));
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_GETPARAM, 64, &user),
            Some(Err(FsError::InvalidData))
        );
        assert_eq!(
            set_hint(&file, card, &user, id, 0, 1),
            Err(FsError::InvalidData)
        );
        // An unrelated valid GET finalizes the proto as well.
        let other = prototype(&file, card, &user);
        let mut ordinary = hint_param(other, 0, 0);
        put64(&mut ordinary, 8, 3);
        user.wire.store(64, &ordinary);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_GETPARAM, 64, &user),
            Some(Ok(0))
        );
        assert_eq!(
            set_hint(&file, card, &user, other, 0, 1),
            Err(FsError::InvalidData)
        );
        let next = create(
            &file,
            card,
            &user,
            &[hint_param(0, 123, 0), hint_param(0, u32::MAX, u64::MAX)],
        )
        .unwrap();
        assert_eq!(next, 3);
        assert_eq!(set_hint(&file, card, &user, next, 0, 0), result);
        // Errors after the hint discard the entire unpublished record/name.
        let mut unknown = hint_param(0, 0, 0);
        put64(&mut unknown, 8, u64::MAX);
        assert_eq!(
            create(&file, card, &user, &[hint_param(0, 0, 1), unknown]),
            Err(FsError::InvalidData)
        );
        assert_eq!(
            create(&file, card, &user, &[hint_param(7, 0, 1)]),
            Err(FsError::InvalidData)
        );
        create_wire(&user, &[hint_param(0, 0, 1)]);
        user.wire.store(12_008, &99u32.to_le_bytes());
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &user),
            Some(Err(FsError::InvalidData))
        );
        // A self-referencing hint: create_setparam applies the one-way
        // enable at each of i915_user_extensions' 512 visits; the 513th is
        // -E2BIG.
        create_wire(&user, &[hint_param(0, 0, 1)]);
        user.wire.store(12_000, &12_000u64.to_le_bytes());
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &user),
            Some(Err(FsError::ArgumentListTooLong))
        );
        user.fail_report
            .store(true, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            create(&file, card, &user, &[hint_param(0, 0, 1)]),
            Err(FsError::BadAddress)
        );
        user.fail_report
            .store(false, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(create(&file, card, &user, &[hint_param(0, 0, 1)]), Ok(4));
        assert_eq!(w.0.borrow().writes.len(), writes);
        assert_eq!(arena.live_allocations(), allocations);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_raw_proto_phase_and_create_rollback
);

fn smoke_i915_context_freq_hint_all_profiles_actual_policy_and_repeated_retirement() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Gen12(Gen12Platform::TigerLake), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeP), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeS), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeN), 0x130044),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Integrated(Generation::MeteorLake), 0xdfc),
        (GtPlatform::Integrated(Generation::LunarLake), 0xdfc),
        (GtPlatform::Integrated(Generation::PantherLake), 0xdfc),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        assert_eq!(get_hint(&file, card, &user), 1);
        let handles = pair(&file, card, &user);
        for (iteration, hint) in [false, true].into_iter().enumerate() {
            let params = if hint {
                alloc::vec![hint_param(0, 0, 0)]
            } else {
                Vec::new()
            };
            let id = create(&file, card, &user, &params).unwrap();
            let mut previous: Option<Arc<UserContext>> = None;
            for pass in 0..2 {
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 4])
                    .unwrap();
                // Changing the copied extension cannot change the context.
                user.wire.store(12_048, &u64::MAX.to_le_bytes());
                raw(&user, handles, id, 1);
                let now = 20_000_000 + iteration as u64 * 400 + pass * 100;
                let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
                assert_eq!(context.engine(), Engine::Rcs0);
                if let Some(old) = &previous {
                    assert!(Arc::ptr_eq(old, &context));
                }
                assert_eq!(context.configure_low_latency(), Err(FsError::Busy));
                run(&mut gt, &w, &fence, now + 1, hint);
                assert_eq!(word(&file, handles[1]), 0x4e415246);
                assert!(!context.busy() && !context.banned());
                assert_eq!(
                    set_hint(&file, card, &user, id, 0, 1),
                    Err(FsError::InvalidData)
                );
                previous = Some(context);
            }
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_all_profiles_actual_policy_and_repeated_retirement
);

// Independent sparse literal: physical VCS1/VCS6 and VECS2. Capture real
// defaults before public readiness, using the same production owners as media.
fn sparse_media(family: Gen12Platform) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Gen12(family), 0x130044);
    w.0.borrow_mut()
        .regs
        .insert(0x9140, 0x000f00ff & !0x00040042);
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

fn smoke_i915_context_freq_hint_gen12_late_proto_and_lazy_sparse_media() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ] {
        let (w, arena, mut gt) = sparse_media(family);
        let (mailbox, _, card) = super::registered(&mut gt, &w, GtPlatform::Gen12(family));
        let file = RenderFile::new();
        let user = Cpu::new();
        let id = prototype(&file, card, &user);
        let handles = pair(&file, card, &user);
        assert_eq!(set_hint(&file, card, &user, id, 7, 0), Ok(0));
        let mut states = Vec::new();
        for (slot, ring, engine) in [
            (0, 1, Engine::Rcs0),
            (1, 3, Engine::Bcs0),
            (2, 2 | 1 << 13, Engine::Vcs1),
            (3, 2 | 2 << 13, Engine::Vcs6),
            (4, 4, Engine::Vecs2),
        ] {
            for pass in 0..2 {
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 4])
                    .unwrap();
                raw(&user, handles, id, ring);
                let now = 20_000_000 + slot * 1000 + pass * 100;
                let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
                assert_eq!(context.engine(), engine);
                if pass == 0 {
                    states.push(context.clone());
                } else {
                    assert!(Arc::ptr_eq(&states[slot as usize], &context));
                }
                run(&mut gt, &w, &fence, now + 1, true);
                assert_eq!(word(&file, handles[1]), 0x4e415246);
            }
        }
        assert!(states
            .iter()
            .enumerate()
            .all(|(i, a)| states.iter().skip(i + 1).all(|b| !Arc::ptr_eq(a, b))));
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_gen12_late_proto_and_lazy_sparse_media
);

fn smoke_i915_context_freq_hint_indexed_chain_order_holes_and_virtual_migration() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    for (order, hint_first) in [false, true].into_iter().enumerate() {
        let map = balanced_map(
            &user.wire,
            0,
            &[(0, 0), (1, 1), (0xffff, 0xffff), (0xffff, 0xffff)],
            3,
            &[(1, 0), (1, 1)],
        );
        let hint = hint_param(0, 0, 0);
        let params = if hint_first { [hint, map] } else { [map, hint] };
        let id = create(&file, card, &user, &params).unwrap();
        // Post-copy user bytes cannot change the retained placement or policy.
        user.wire.store(7168, &[0xa5; 64]);
        user.wire.store(8192, &[0xa5; 24]);
        raw(&user, handles, id, 2);
        let allocations = arena.live_allocations();
        {
            let mut call =
                core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Err(FsError::InvalidData)))
            );
        }
        assert!(mailbox.pending.lock().is_empty());
        assert_eq!(arena.live_allocations(), allocations);
        for (offset, slot, expected) in [(0, 0, Engine::Rcs0), (1, 1, Engine::Bcs8)] {
            raw(&user, handles, id, slot);
            let now = 500 + order as u64 * 2000 + offset * 100;
            let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
            assert_eq!(context.engine(), expected);
            run(&mut gt, &w, &fence, now + 1, true);
        }
        let mut prior: Option<Arc<UserContext>> = None;
        for chosen in [0, 1] {
            w.0.borrow_mut().virtual_pick = Some(chosen);
            raw(&user, handles, id, 3);
            let now = 900 + order as u64 * 2000 + u64::from(chosen) * 200;
            let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
            assert_eq!(
                context.placements(),
                EngineSet::of(&[Engine::Bcs0, Engine::Bcs8])
            );
            if let Some(old) = &prior {
                assert!(Arc::ptr_eq(old, &context));
            }
            run(&mut gt, &w, &fence, now + 1, true);
            assert_eq!(
                w.0.borrow().virtual_restores.last().unwrap().1,
                if chosen == 0 { 3 } else { 0x83 }
            );
            assert_eq!(word(&file, handles[1]), 0x4e415246);
            prior = Some(context);
        }
    }
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_indexed_chain_order_holes_and_virtual_migration
);

fn smoke_i915_context_freq_hint_proto_map_preflight_and_finalized_refusal_are_atomic() -> TestResult
{
    let platform = GtPlatform::Gen12(Gen12Platform::TigerLake);
    let (w, arena, mut gt) = hardware_model(platform, 0x130044);
    prime(&mut gt, &w, 0x130044);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    for scenario in 0..3 {
        let id = prototype(&file, card, &user);
        let hinted = scenario != 2;
        if scenario == 0 {
            assert_eq!(set_hint(&file, card, &user, id, 0, 0), Ok(0));
        }
        // No partial engine-map assignment: an unresolved final slot leaves
        // the proto free to install a complete valid map on the same name.
        let bad = engines_param(&user.wire, id, &[(0, 0), (1, 0), (5, 0)], 8192);
        user.wire.store(64, &bad);
        let allocations = arena.live_allocations();
        let writes = w.0.borrow().writes.len();
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(FsError::NotFound))
        );
        assert_eq!(arena.live_allocations(), allocations);
        assert_eq!(w.0.borrow().writes.len(), writes);
        let map = engines_param(&user.wire, id, &[(0, 0), (1, 0), (0xffff, 0xffff)], 8192);
        user.wire.store(64, &map);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Ok(0))
        );
        if hinted {
            // After-map enable reaches every slot, and repeated enable is
            // idempotent; before-map intent also survived the failed map.
            assert_eq!(set_hint(&file, card, &user, id, 0, 0), Ok(0));
            assert_eq!(set_hint(&file, card, &user, id, 123, u64::MAX), Ok(0));
        }
        for (slot, expected) in [(0, Engine::Rcs0), (1, Engine::Bcs0)] {
            raw(&user, handles, id, slot);
            let now = 20_000_000 + scenario * 1000 + slot * 100;
            let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, now);
            assert_eq!(context.engine(), expected);
            assert!(context.busy());
            // Failure is before mutation, even while one actual slot owns a
            // GPU job. The other slot must retain the same ordinary policy.
            assert_eq!(
                set_hint(&file, card, &user, id, 0, 1),
                Err(FsError::InvalidData)
            );
            run(&mut gt, &w, &fence, now + 1, hinted);
            assert_eq!(word(&file, handles[1]), 0x4e415246);
        }
    }
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_proto_map_preflight_and_finalized_refusal_are_atomic
);

fn smoke_i915_context_freq_hint_cancel_close_missing_ack_and_authority_loss_retain() -> TestResult {
    for lose_ack in [false, true] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        prime(&mut gt, &w, 0xdfc);
        let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let id = create(&file, card, &user, &[hint_param(0, 0, 0)]).unwrap();
        let handles = pair(&file, card, &user);
        let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
        raw(&user, handles, id, 1);
        let (context, fence) = {
            let mut call =
                Box::pin(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let accepted = mailbox.accept(&mut gt, 500);
            drop(call); // accepted work outlives caller cancellation
            accepted
        };
        let mut registered = BTreeMap::new();
        let (mut seen, mut enabled) = (false, false);
        for now in 501..540 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            seen |= policy(&w, true);
            if service_contexts(&w, &mut registered, false).contains(&0x1001) {
                assert!(seen && !fence.is_submit_ready());
                if lose_ack {
                    drop_reply(&w);
                }
                enabled = true;
                break;
            }
        }
        assert!(seen && enabled && registered.len() == 1);
        if lose_ack {
            assert_eq!(
                gt.poll(5_000_001_000),
                Poll::Ready(Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Timeout
                )))
            );
            assert!(!fence.is_submit_ready());
        } else {
            for now in 541..550 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
            }
            assert!(fence.is_submit_ready());
        }
        close_id(&file, card, &user, abi::GEM_CONTEXT_DESTROY, id);
        for handle in handles {
            close_id(&file, card, &user, abi::GEM_CLOSE, handle);
        }
        drop(file);
        let retained = arena.live_allocations();
        assert!(context.busy() && fence.result().is_none());
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        if !lose_ack {
            assert!(gt.poll_with_access(551, || false).is_ready());
            assert_eq!(gt.state(), GtState::Lost);
        }
        assert_eq!(arena.live_allocations(), retained);
        assert!(fence.result().is_none());
        hardware_stop(&mut gt, &w, 0xdfc);
        assert_eq!(
            fence.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert!(!context.busy());
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_cancel_close_missing_ack_and_authority_loss_retain
);

fn smoke_i915_context_freq_hint_reset_epoch_requires_fresh_context_and_policy() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = create(&file, card, &user, &[hint_param(0, 0, 1)]).unwrap();
    let handles = pair(&file, card, &user);
    raw(&user, handles, id, 1);
    let (old, fence) = submit(&file, card, &user, &mailbox, &mut gt, 500);
    run(&mut gt, &w, &fence, 501, true);
    let epoch = gt.user_epoch().unwrap();
    *mailbox.status.lock() = None;
    assert_eq!(get_hint(&file, card, &user), -22);
    assert_eq!(
        create(&file, card, &user, &[hint_param(0, 0, 1)]),
        Err(FsError::InvalidData)
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    // Fresh independent owner models resume/recovery, not a RuntimeOwner PCI/S3 test.
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    assert_ne!(gt.user_epoch(), Some(epoch));
    let baseline = arena.live_allocations();
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    assert!(gt
        .submit_user_batch(500, old.clone(), UserBatch(batch))
        .is_err());
    assert!(old.banned());
    assert_eq!(arena.live_allocations(), baseline);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let fresh = create(&file, card, &user, &[hint_param(0, 0, 0)]).unwrap();
    raw(&user, handles, fresh, 1);
    let (new, fence) = submit(&file, card, &user, &mailbox, &mut gt, 500);
    assert!(!Arc::ptr_eq(&old, &new));
    run(&mut gt, &w, &fence, 501, true);
    assert_eq!(word(&file, handles[1]), 0x4e415246);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_reset_epoch_requires_fresh_context_and_policy
);

fn smoke_i915_context_freq_hint_obeys_global_slpc_and_mixed_async_reservations() -> TestResult {
    use crate::intel_gpu_slpc::{FrequencyRange, PowerProfile, SlpcState};
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    let mut registered = BTreeMap::new();
    gt.begin_slpc(500).unwrap();
    for now in 501..541 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
    }
    assert_eq!(gt.slpc(), SlpcState::Running);
    gt.begin_slpc_frequency_range(
        FrequencyRange {
            min_mhz: 1250,
            max_mhz: 2000,
        },
        550,
    )
    .unwrap();
    for now in 551..591 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
    }
    gt.begin_slpc_power_profile(PowerProfile::PowerSaving, 600)
        .unwrap();
    for now in 601..641 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
    }
    let state = gt.slpc_status().unwrap();
    assert_eq!(
        state.range,
        FrequencyRange {
            min_mhz: 1250,
            max_mhz: 2000
        }
    );
    assert_eq!(state.profile, PowerProfile::PowerSaving);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = create(&file, card, &user, &[hint_param(0, 0, 0)]).unwrap();
    let handles = pair(&file, card, &user);
    let code = file.gem.object(handles[0]).unwrap();
    let data = file.gem.object(handles[1]).unwrap();
    // Deliberately foreign reservation fences; native completion below is real.
    let code_writer = Arc::new(CompletionFence::new());
    let data_writer = Arc::new(CompletionFence::new());
    code.import_fences(alloc::vec![code_writer.clone()], true);
    data.import_fences(alloc::vec![data_writer.clone()], true);
    raw(&user, handles, id, 1);
    let flags = u64_at(&user.wire.load(288, 8), 0) | 0x40;
    user.wire.store(288, &flags.to_le_bytes()); // code ASYNC, data synchronous
    let fence = {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            mailbox.pending.lock().is_empty(),
            "mixed request bypassed synchronous data writer"
        );
        assert_eq!(code.busy(), 0x10001);
        assert_eq!(data.busy(), 0x10001);
        data_writer.signal(Ok(()));
        let deadline = narf_time::monotonic_ns() + 10_000_000;
        while mailbox.pending.lock().is_empty() {
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert!(narf_time::monotonic_ns() < deadline);
            narf_scheduler::sleep_pumps::run();
        }
        assert!(
            code_writer.result().is_none(),
            "ASYNC silently waited on code writer"
        );
        let (_, fence) = mailbox.accept(&mut gt, 700);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let (mut seen, mut enabled) = (false, false);
    for now in 701..801 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        seen |= policy(&w, true);
        if pending(&w)
            .iter()
            .any(|r| r[0] as u16 == 0x1001 && r[2] == 1)
        {
            assert!(seen);
            enabled = true;
        }
        assert!(
            pending(&w).iter().all(|r| r[0] as u16 != 0x3003),
            "context bypassed global SLPC owner"
        );
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.slpc_status(), Some(state));
        if fence.result().is_some() {
            break;
        }
    }
    assert!(seen && enabled);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
    assert!(
        !code.idle(false),
        "newer ASYNC retirement erased older producer"
    );
    assert_eq!(data.busy(), 0);
    assert_eq!(word(&file, handles[1]), 0x4e415246);
    code_writer.signal(Ok(()));
    assert_eq!(code.busy(), 0);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_obeys_global_slpc_and_mixed_async_reservations
);

fn context_parameter(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    id: u32,
    parameter: u64,
    value: Option<u64>,
) -> Result<u64, FsError> {
    let mut bytes = [0; 24];
    put32(&mut bytes, 0, id);
    put64(&mut bytes, 8, parameter);
    put64(&mut bytes, 16, value.unwrap_or(0));
    user.wire.store(64, &bytes);
    file.dispatch_card(
        card,
        if value.is_some() {
            abi::GEM_CONTEXT_SETPARAM
        } else {
            abi::GEM_CONTEXT_GETPARAM
        },
        64,
        user,
    )
    .unwrap()?;
    Ok(u64_at(&user.wire.load(64, 24), 16))
}
fn legacy_vm(file: &RenderFile, card: u32, user: &Cpu) -> u32 {
    user.wire.store(64, &[0; 16]);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_VM_CREATE, 64, user),
        Some(Ok(0))
    );
    u32_at(&user.wire.load(64, 16), 12)
}

/// The callback runs at the actual outer CREATE copyout. Reentry would deadlock
/// if the real namespace IRQ guard were still held; no resolver/lock test seam.
struct ReentrantCreate<'a> {
    file: &'a RenderFile,
    card: u32,
    user: &'a Cpu,
    nested: Cpu,
    handles: [u32; 2],
    fail: bool,
    full: bool,
    existing: u32,
    remove_vm: Option<u32>,
    entered: core::sync::atomic::AtomicBool,
    outer: core::sync::atomic::AtomicU32,
    inner: core::sync::atomic::AtomicU32,
    new_vm: core::sync::atomic::AtomicU32,
}
impl<'a> ReentrantCreate<'a> {
    fn new(file: &'a RenderFile, card: u32, user: &'a Cpu, handles: [u32; 2]) -> Self {
        Self {
            file,
            card,
            user,
            handles,
            nested: Cpu::new(),
            fail: false,
            full: false,
            existing: 0,
            remove_vm: None,
            entered: core::sync::atomic::AtomicBool::new(false),
            outer: core::sync::atomic::AtomicU32::new(0),
            inner: core::sync::atomic::AtomicU32::new(0),
            new_vm: core::sync::atomic::AtomicU32::new(0),
        }
    }
}
impl IoctlContext for ReentrantCreate<'_> {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.user.read(address, bytes)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
        use core::sync::atomic::Ordering::Relaxed;
        if address != 64 || self.entered.swap(true, Relaxed) {
            return self.user.write(address, bytes);
        }
        let id = u32_at(bytes, 0);
        self.outer.store(id, Relaxed);
        // Neither observation, property mutation, destroy nor genuine EXEC
        // can access the reserved-but-unpublished context.
        assert_eq!(
            context_parameter(self.file, self.card, &self.nested, id, 4, None),
            Err(FsError::NotFound)
        );
        assert_eq!(
            context_parameter(self.file, self.card, &self.nested, id, 4, Some(1)),
            Err(FsError::NotFound)
        );
        let mut destroy = [0; 8];
        put32(&mut destroy, 0, id);
        self.nested.wire.store(64, &destroy);
        assert_eq!(
            self.file
                .dispatch_card(self.card, abi::GEM_CONTEXT_DESTROY, 64, &self.nested),
            Some(Err(FsError::NotFound))
        );
        raw(&self.nested, self.handles, id, 1);
        {
            let mut call = core::pin::pin!(self.file.dispatch_card_user(
                self.card,
                abi::GEM_EXECBUFFER2_WR,
                64,
                &self.nested
            ));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Err(FsError::NotFound)))
            );
        }
        let other = if self.full {
            assert_eq!(
                create(self.file, self.card, &self.nested, &[]),
                Err(FsError::OutOfMemory)
            );
            self.existing
        } else {
            let other = create(self.file, self.card, &self.nested, &[]).unwrap();
            assert_ne!(other, id, "pending ID was reused by an interleaved create");
            self.inner.store(other, Relaxed);
            other
        };
        assert_eq!(
            context_parameter(self.file, self.card, &self.nested, other, 4, Some(1)),
            Ok(1)
        );
        assert_eq!(
            context_parameter(self.file, self.card, &self.nested, other, 4, None),
            Ok(1)
        );
        if let Some(vm) = self.remove_vm {
            let mut destroy = [0; 16];
            put32(&mut destroy, 12, vm);
            self.nested.wire.store(64, &destroy);
            assert_eq!(
                self.file
                    .dispatch_card(self.card, abi::GEM_VM_DESTROY, 64, &self.nested),
                Some(Ok(0))
            );
            self.new_vm
                .store(legacy_vm(self.file, self.card, &self.nested), Relaxed);
        }
        if self.fail {
            // A real partial output followed by EFAULT still grants no live ID.
            self.user.write(address, &bytes[..4])?;
            return Err(FsError::BadAddress);
        }
        self.user.write(address, bytes)
    }
    fn nonblocking(&self) -> bool {
        false
    }
}

fn smoke_i915_context_freq_hint_reentrant_copyout_has_private_nonce_and_vm_snapshot() -> TestResult
{
    use core::sync::atomic::Ordering::Relaxed;
    for fail in [false, true] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        prime(&mut gt, &w, 0xdfc);
        let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let handles = pair(&file, card, &user);
        let vm = legacy_vm(&file, card, &user);
        let mut vm_parameter = [0; 24];
        put64(&mut vm_parameter, 8, 9);
        put64(&mut vm_parameter, 16, u64::from(vm));
        // A separate public context witnesses the exact selected VM identity.
        // After its original name is deleted, GET_VM re-exports the retained
        // Arc; the outer context must resolve to that same re-exported name.
        let witness = create(&file, card, &user, &[vm_parameter]).unwrap();
        assert_eq!(witness, 1);
        assert_eq!(
            context_parameter(&file, card, &user, witness, 9, None),
            Ok(u64::from(vm))
        );
        create_wire(&user, &[vm_parameter, hint_param(0, 0, 0)]);
        let mut reentrant = ReentrantCreate::new(&file, card, &user, handles);
        reentrant.fail = fail;
        reentrant.remove_vm = Some(vm);
        let allocations = arena.live_allocations();
        let writes = w.0.borrow().writes.len();
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &reentrant),
            Some(if fail {
                Err(FsError::BadAddress)
            } else {
                Ok(0)
            })
        );
        assert!(reentrant.entered.load(Relaxed));
        let outer = reentrant.outer.load(Relaxed);
        let inner = reentrant.inner.load(Relaxed);
        assert_eq!((outer, inner), (2, 3));
        assert_eq!(u32_at(&user.wire.load(64, 4), 0), outer);
        assert_eq!(
            context_parameter(&file, card, &user, inner, 4, None),
            Ok(1),
            "outer rollback changed the other context"
        );
        let created_vm = reentrant.new_vm.load(Relaxed);
        assert_ne!(created_vm, vm);
        let retained_vm = context_parameter(&file, card, &user, witness, 9, None).unwrap();
        assert_ne!(retained_vm, u64::from(created_vm));
        assert_eq!(
            context_parameter(&file, card, &user, witness, 9, None),
            Ok(retained_vm)
        );
        let target = if fail {
            assert_eq!(
                context_parameter(&file, card, &user, outer, 4, None),
                Err(FsError::NotFound)
            );
            let retry = create(&file, card, &user, &[]).unwrap();
            assert_eq!(retry, 4, "failed outer create rewound another creator's ID");
            retry
        } else {
            // Equality with the independent witness proves original shared
            // VM identity, rather than merely separation from the new VM.
            assert_eq!(
                context_parameter(&file, card, &user, outer, 9, None),
                Ok(retained_vm)
            );
            assert_eq!(create(&file, card, &user, &[]), Ok(4));
            outer
        };
        assert_eq!(w.0.borrow().writes.len(), writes);
        assert_eq!(arena.live_allocations(), allocations);
        assert!(mailbox.pending.lock().is_empty());
        // Publication transfers exactly the intended graph. The interleaved
        // context stays ordinary; a failed private hint cannot infect retry.
        for (step, id, hint) in [(0, target, !fail), (1, inner, false)] {
            raw(&user, handles, id, 1);
            let (_, fence) = submit(&file, card, &user, &mailbox, &mut gt, 500 + step * 200);
            run(&mut gt, &w, &fence, 501 + step * 200, hint);
            assert_eq!(word(&file, handles[1]), 0x4e415246);
        }
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_reentrant_copyout_has_private_nonce_and_vm_snapshot
);

fn smoke_i915_context_freq_hint_pending_capacity_and_failed_copyout_reclaim_slot() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, _, card) = super::registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user);
    // Independent public limit literal64 includes default0. 62 existing plus
    // one pending leaves no room for a callback's second unpublished create.
    for expected in 1..=62 {
        assert_eq!(create(&file, card, &user, &[]), Ok(expected));
    }
    create_wire(&user, &[hint_param(0, 0, 0)]);
    let mut reentrant = ReentrantCreate::new(&file, card, &user, handles);
    reentrant.fail = true;
    reentrant.full = true;
    reentrant.existing = 1;
    let writes = w.0.borrow().writes.len();
    let allocations = arena.live_allocations();
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &reentrant),
        Some(Err(FsError::BadAddress))
    );
    assert!(reentrant.entered.load(Relaxed));
    assert_eq!(reentrant.outer.load(Relaxed), 63);
    assert_eq!(reentrant.inner.load(Relaxed), 0);
    assert_eq!(
        context_parameter(&file, card, &user, 63, 4, None),
        Err(FsError::NotFound)
    );
    assert_eq!(context_parameter(&file, card, &user, 1, 4, None), Ok(1));
    assert_eq!(
        create(&file, card, &user, &[]),
        Ok(63),
        "failed pending reservation leaked capacity"
    );
    create_wire(&user, &[hint_param(0, 0, 1)]);
    let blocked = ReentrantCreate::new(&file, card, &user, handles);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &blocked),
        Some(Err(FsError::OutOfMemory))
    );
    assert!(
        !blocked.entered.load(Relaxed),
        "full namespace reached copyout"
    );
    close_id(&file, card, &user, abi::GEM_CONTEXT_DESTROY, 2);
    assert_eq!(create(&file, card, &user, &[]), Ok(64));
    assert_eq!(context_parameter(&file, card, &user, 1, 4, None), Ok(1));
    assert!(mailbox.pending.lock().is_empty());
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(arena.live_allocations(), allocations);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_context_freq_hint_pending_capacity_and_failed_copyout_reclaim_slot
);

mod priority {
    include!("intel_gpu_i915_priority_tests.rs");
}
