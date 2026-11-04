// Raw registered i915 ioctls -> actual retained GuC/PPGTT jobs -> native BO
// payload capture. Source literals deliberately do not reuse bit/query/param
// constants. ENABLE is executed on its first consumption; only its ACK is lost.
use super::*;
use crate::intel_gpu_error::{coredump, Reason};
use narf_filesystem::FileOps;

fn node(file: &dyn FileOps, user: &dyn IoctlContext, cmd: u32) -> Result<u64, FsError> {
    let mut call = core::pin::pin!(file.ioctl_user(cmd, 64, user));
    match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("synchronous raw control unexpectedly waited"),
    }
}
fn parameter(id: u32, size: u32, value: u64) -> [u8; 24] {
    let mut wire = [0; 24];
    put32(&mut wire, 0, id);
    put32(&mut wire, 4, size);
    put64(&mut wire, 8, 4);
    put64(&mut wire, 16, value);
    wire
}
fn set(file: &dyn FileOps, user: &User, id: u32, value: u64) {
    user.store(64, &parameter(id, 0, value));
    assert_eq!(node(file, user, abi::GEM_CONTEXT_SETPARAM), Ok(0));
}
fn get(file: &dyn FileOps, user: &User, id: u32) -> u64 {
    user.store(64, &parameter(id, 0xfeed, u64::MAX));
    assert_eq!(node(file, user, abi::GEM_CONTEXT_GETPARAM), Ok(0));
    let wire = user.load(64, 24);
    assert_eq!(u32_at(&wire, 4), 0);
    u64_at(&wire, 16)
}
fn create(file: &dyn FileOps, user: &User) -> u32 {
    user.store(64, &[0; 8]);
    assert_eq!(node(file, user, abi::GEM_CONTEXT_CREATE), Ok(0));
    u32_at(&user.load(64, 8), 0)
}
fn close(file: &dyn FileOps, user: &User, cmd: u32, id: u32) {
    let mut wire = [0; 8];
    put32(&mut wire, 0, id);
    user.store(64, &wire);
    assert_eq!(node(file, user, cmd), Ok(0));
}
fn selected(user: &User, selection: &[bool]) {
    for (i, select) in selection.iter().copied().enumerate() {
        let address = 256 + i as u64 * 56 + 32;
        let flags = u64_at(&user.load(address, 8), 0);
        user.store(
            address,
            &(flags | if select { 0x80 } else { 0 }).to_le_bytes(),
        );
    }
}
fn accept(
    file: &dyn FileOps,
    user: &User,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    now: u64,
) -> (Arc<UserContext>, Arc<CompletionFence>) {
    let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_EXECBUFFER2_WR, 64, user));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    assert_eq!(mailbox.pending.lock().len(), 1);
    // Every object/flag byte was copied before this first wait.
    user.store(256, &[0xa5; 112]);
    let result = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(0))
    );
    result
}
fn armed(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    start: u64,
) -> BTreeMap<u32, u32> {
    let mut registered = BTreeMap::new();
    let mut executed = false;
    for now in start..start + 100 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        let actions = service_contexts(w, &mut registered, true);
        if actions.contains(&0x1001) {
            // Actual ENABLE execution just performed the batch/store and
            // breadcrumb. Omit only its unobserved reply, never host HEAD.
            let memory = ct_memory(w);
            let mut words = memory.borrow_mut();
            let head = words[512];
            assert_eq!(words[513].wrapping_sub(head) & 4095, 4);
            words[513] = head;
            executed = true;
            break;
        }
    }
    assert!(executed && !registered.is_empty());
    assert_eq!(fence.result(), None);
    registered
}
fn report(gt: &GuCGt<Window, Arena>, w: &Window) -> crate::intel_gpu_error::Report {
    gt.error_report(
        Reason::Timeout,
        gt.user_epoch().unwrap_or(0),
        6_000_000_001,
        || true,
        |reg| Some(w.read32(reg)),
    )
}
fn capture(gt: &GuCGt<Window, Arena>, w: &Window, index: u32) -> Vec<u8> {
    let report = report(gt, w);
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    let writes = w.0.borrow().writes.len();
    gt.capture_coredump(armed, report, 6_000_000_002, [0; 32], || true);
    assert_eq!(w.0.borrow().writes.len(), writes);
    coredump::snapshot_bytes_for_test(index).expect("real raw job produced a bundle")
}
fn suppress(gt: &GuCGt<Window, Arena>, w: &Window, index: u32) {
    let report = report(gt, w);
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    let reads = w.0.borrow().mmio_reads.get();
    let writes = w.0.borrow().writes.len();
    // Every normal raw source copy is preceded by this current-access probe;
    // protection must return before even invoking it or any MMIO/backing read.
    gt.capture_coredump(armed, report, 6_000_000_002, [0; 32], || {
        panic!("protected diagnostic source access")
    });
    assert_eq!(w.0.borrow().mmio_reads.get(), reads);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert!(coredump::snapshot_bytes_for_test(index).is_none());
    // A skipped capture releases its preallocation permit, including repeated
    // skips; there is no leaked last permit or fake terminal fence.
    let a = coredump::Armed::reserve_for_test(index).unwrap();
    let b = coredump::Armed::reserve_for_test(index).unwrap();
    assert!(coredump::Armed::reserve_for_test(index).is_err());
    drop((a, b));
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32_at(bytes, at)
}
fn vm(bytes: &[u8]) -> &[u8] {
    let offset = word(bytes, 160) as usize;
    assert_eq!(offset, 0x1b4540);
    let section = &bytes[offset..];
    assert_eq!(&section[..8], b"NARFVMEM");
    assert_eq!((word(section, 24), word(section, 28)), (1, 1));
    assert_eq!(word(section, 32), u32::from(word(section, 36) == 0));
    &section[64..]
}
fn finish(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64, fence: &CompletionFence) {
    hardware_stop(gt, w, ack);
    assert_eq!(
        fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
}

fn smoke_i915_capture_registered_payload_live_policy_close_and_full_reset() -> TestResult {
    for render in [false, true] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, _, index) = registered(&mut gt, &w, GtPlatform::Battlemage);
        let name = if render {
            alloc::format!("renderD{}", index + 128)
        } else {
            alloc::format!("card{index}")
        };
        let file = crate::drm_devfs_bridge::DriDir.lookup(&name).unwrap();
        let user = User::new();
        let mut query = [0; 16];
        put32(&mut query, 0, 45);
        put64(&mut query, 8, 1024);
        user.store(64, &query);
        user.store(1024, &[0xa5; 8]);
        assert_eq!(node(&*file, &user, abi::GETPARAM), Ok(0));
        assert_eq!(user.load(1024, 8), [1, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
        let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
        let id = create(&*file, &user);
        assert_eq!(get(&*file, &user, id), 0);
        legacy_exec(&user, handles, id);
        selected(&user, &[true, true]);
        let (context, fence) = accept(&*file, &user, &mailbox, &mut gt, 500);
        let registered = armed(&mut gt, &w, &fence, 501);
        assert_eq!(registered.len(), 1);
        // Live finalized AND busy SET; submitted-job snapshots would fail this.
        set(&*file, &user, id, u64::MAX);
        assert_eq!(get(&*file, &user, id), 1);
        let allocations = arena.live_allocations();
        suppress(&gt, &w, 59);
        assert!(context.busy() && fence.result().is_none());
        assert_eq!(arena.live_allocations(), allocations);
        set(&*file, &user, id, 0);
        assert_eq!(get(&*file, &user, id), 0);
        close(&*file, &user, abi::GEM_CLOSE, handles[0]);
        close(&*file, &user, abi::GEM_CLOSE, handles[1]);
        assert!(gt.poll(6_000_000_000).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        let bytes = capture(&gt, &w, 59);
        let record = vm(&bytes);
        assert_eq!((word(record, 40), word(record, 44)), (2, 2));
        let code = &record[0x10180..];
        let data = &record[0x101c0..];
        assert_eq!(
            (u64_at(code, 0), u64_at(data, 0)),
            (0x1234_0000_0000, 0x2345_0000_0000)
        );
        assert_eq!((word(code, 32), word(data, 32)), (33, 32));
        assert_eq!((word(code, 44), word(data, 44)), (4096, 4096));
        assert_eq!(word(&bytes, word(code, 40) as usize), 0x10000002);
        assert_eq!(
            word(&bytes, word(data, 40) as usize + 0x80),
            0x4e415246,
            "actual GPU store, not seeded payload"
        );
        // Toggle cannot change already published immutable evidence.
        set(&*file, &user, id, 2);
        assert_eq!(coredump::snapshot_bytes_for_test(59).unwrap(), bytes);
        assert!(coredump::clear_for_test(59));
        close(&*file, &user, abi::GEM_CONTEXT_DESTROY, id);
        drop(file);
        suppress(&gt, &w, 59); // namespace/fd destruction retained the policy
        assert!(context.busy() && fence.result().is_none());
        finish(&mut gt, &w, ack, &fence);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_registered_payload_live_policy_close_and_full_reset
);

fn smoke_i915_capture_unselected_and_bounded_ranges_are_real_payload() -> TestResult {
    for count in [1usize, 9] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
        let file = crate::drm_devfs_bridge::DriDir
            .lookup(&alloc::format!("renderD{}", card + 128))
            .unwrap();
        let user = User::new();
        let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
        let id = create(&*file, &user);
        legacy_exec(&user, handles, id);
        if count == 1 {
            selected(&user, &[false, true]);
        } else {
            let mut objects = user.load(256, 112);
            selected(&user, &[true, true]);
            objects[..112].copy_from_slice(&user.load(256, 112));
            for i in 2..count {
                let mut create = [0; 16];
                put64(&mut create, 0, 32768);
                user.store(64, &create);
                assert_eq!(node(&*file, &user, abi::GEM_CREATE), Ok(0));
                let handle = u32_at(&user.load(64, 16), 8);
                user.store(16384, &[0xb7; 4096]);
                let mut upload = [0; 32];
                put32(&mut upload, 0, handle);
                put64(&mut upload, 16, 4096);
                put64(&mut upload, 24, 16384);
                user.store(64, &upload);
                assert_eq!(node(&*file, &user, abi::GEM_PWRITE), Ok(0));
                let mut entry = [0; 56];
                put32(&mut entry, 0, handle);
                put64(&mut entry, 24, 0x3000_0000_0000 + i as u64 * 0x10000);
                put64(&mut entry, 32, 0x10 | 0x8 | 0x80);
                objects.extend_from_slice(&entry);
            }
            legacy_exec(&user, handles, id);
            let mut wire = user.load(64, 64);
            put32(&mut wire, 8, count as u32);
            user.store(64, &wire);
            user.store(256, &objects);
        }
        let (_, fence) = accept(&*file, &user, &mailbox, &mut gt, 500);
        armed(&mut gt, &w, &fence, 501);
        let bytes = capture(&gt, &w, 59);
        let record = vm(&bytes);
        if count == 1 {
            assert_eq!((word(record, 40), word(record, 44)), (1, 1));
            let range = &record[0x10180..];
            assert_eq!(u64_at(range, 0), 0x2345_0000_0000);
            assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
        } else {
            assert_eq!((word(record, 40), word(record, 44)), (9, 8));
            assert_eq!(word(record, 52) & 8, 8);
            let range = &record[0x10200..];
            assert_eq!(word(range, 44), 16384);
            assert_eq!(word(range, 32) & 64, 64);
            assert!(
                bytes[word(range, 40) as usize..word(range, 40) as usize + 4096]
                    .iter()
                    .all(|b| *b == 0xb7)
            );
        }
        assert!(coredump::clear_for_test(59));
        finish(&mut gt, &w, ack, &fence);
        drop(file);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_unselected_and_bounded_ranges_are_real_payload
);

fn extensions(user: &User, params: &[[u8; 24]]) {
    for (i, param) in params.iter().enumerate() {
        let mut ext = [0; 56];
        if i + 1 != params.len() {
            put64(&mut ext, 0, 4096 + (i as u64 + 1) * 56);
        }
        ext[32..].copy_from_slice(param);
        user.store(4096 + i as u64 * 56, &ext);
    }
    let mut wire = [0; 16];
    put32(&mut wire, 4, 1);
    put64(&mut wire, 8, 4096);
    user.store(64, &wire);
}
fn smoke_i915_capture_query_source_parameter_sizes_values_and_faults() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("renderD{}", card + 128))
        .unwrap();
    let user = User::new();
    let original = mailbox.status.lock().unwrap();
    for kind in 0..5 {
        let mut status = original;
        match kind {
            0 => status.epoch = 0,
            1 => status.engines = EngineSet::of(&[]),
            2 => status.submission_version.0 = 2,
            3 => status.platform = GtPlatform::Alchemist,
            _ => {}
        }
        *mailbox.status.lock() = if kind == 4 { None } else { Some(status) };
        let mut query = [0; 16];
        put32(&mut query, 0, 45);
        put64(&mut query, 8, 1024);
        user.store(64, &query);
        user.store(1024, &[0xa5; 8]);
        assert_eq!(node(&*file, &user, abi::GETPARAM), Ok(0));
        assert_eq!(user.load(1024, 8), [0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
    }
    *mailbox.status.lock() = Some(original);
    let mut query = [0; 16];
    put32(&mut query, 0, 45);
    put64(&mut query, 8, 1024);
    user.store(64, &query);
    user.fault_write_at(Some(1024));
    assert_eq!(node(&*file, &user, abi::GETPARAM), Err(FsError::BadAddress));
    user.fault_write_at(None);
    assert_eq!(get(&*file, &user, 0), 0);
    for value in [2, u64::MAX, 0] {
        extensions(&user, &[parameter(0, 0, value)]);
        assert_eq!(node(&*file, &user, abi::GEM_CONTEXT_CREATE_EXT), Ok(0));
        let id = u32_at(&user.load(64, 16), 0);
        assert_eq!(get(&*file, &user, id), u64::from(value != 0));
        user.store(64, &parameter(id, 1, 0));
        assert_eq!(
            node(&*file, &user, abi::GEM_CONTEXT_SETPARAM),
            Err(FsError::InvalidData)
        );
        assert_eq!(get(&*file, &user, id), u64::from(value != 0));
        set(&*file, &user, id, 2);
        assert_eq!(get(&*file, &user, id), 1);
        set(&*file, &user, id, 0);
        close(&*file, &user, abi::GEM_CONTEXT_DESTROY, id);
        user.store(64, &parameter(id, 0, 0));
        assert_eq!(
            node(&*file, &user, abi::GEM_CONTEXT_GETPARAM),
            Err(FsError::NotFound)
        );
    }
    extensions(&user, &[parameter(0, 0, 2)]);
    user.fault_write_at(Some(64));
    assert_eq!(
        node(&*file, &user, abi::GEM_CONTEXT_CREATE_EXT),
        Err(FsError::BadAddress)
    );
    user.fault_write_at(None);
    assert_eq!(
        get(&*file, &user, 0),
        0,
        "private CREATE_EXT policy leaked into context0"
    );
    extensions(&user, &[parameter(0, 0, 2), parameter(0, 1, 0)]);
    assert_eq!(
        node(&*file, &user, abi::GEM_CONTEXT_CREATE_EXT),
        Err(FsError::InvalidData)
    );
    assert_eq!(get(&*file, &user, 0), 0);
    let mut other = parameter(0, 0, 2);
    put64(&mut other, 8, 8);
    user.store(64, &other);
    assert_eq!(
        node(&*file, &user, abi::GEM_CONTEXT_SETPARAM),
        Ok(0),
        "unrelated boolean accepts nonzero as true in Linux i915"
    );
    put32(&mut other, 4, 8);
    user.store(64, &other);
    assert_eq!(
        node(&*file, &user, abi::GEM_CONTEXT_SETPARAM),
        Err(FsError::InvalidData)
    );
    let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
    legacy_exec(&user, handles, 0);
    selected(&user, &[true, true]);
    let flags = u64_at(&user.load(288, 8), 0);
    user.store(288, &(flags | 0x100).to_le_bytes());
    assert_eq!(
        node(&*file, &user, abi::GEM_EXECBUFFER2_WR),
        Err(FsError::InvalidData)
    );
    assert!(mailbox.pending.lock().is_empty());
    // The same raw selected request then executes, so no negative-only flag
    // or discovery acceptance is offered as the feature's positive evidence.
    legacy_exec(&user, handles, 0);
    selected(&user, &[true, true]);
    let (_, fence) = accept(&*file, &user, &mailbox, &mut gt, 500);
    armed(&mut gt, &w, &fence, 501);
    let bytes = capture(&gt, &w, 59);
    let range = &vm(&bytes)[0x101c0..];
    assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
    assert!(coredump::clear_for_test(59));
    finish(&mut gt, &w, ack, &fence);
    drop(file);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_query_source_parameter_sizes_values_and_faults
);

fn media_gt() -> (Window, Arena, GuCGt<Window, Arena>, u64) {
    let (w, arena, mut gt) = hardware_model(
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
        0x130044,
    );
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
    (w, arena, gt, 0x130044)
}
fn mapped(file: &dyn FileOps, user: &User, virtual_slot: bool, protected_first: bool) -> u32 {
    let param = if virtual_slot {
        let param = engines_param(user, 0, &[(0xffff, 0xffff)], 8192);
        balance(user, 7168, 0, &[(1, 1), (1, 0)]);
        user.store(8192, &7168u64.to_le_bytes());
        param
    } else {
        engines_param(user, 0, &[(1, 1)], 8192)
    };
    let policy = parameter(0, 0, 2);
    extensions(
        user,
        &if protected_first {
            [policy, param]
        } else {
            [param, policy]
        },
    );
    assert_eq!(node(file, user, abi::GEM_CONTEXT_CREATE_EXT), Ok(0));
    u32_at(&user.load(64, 16), 0)
}
fn save_complete(gt: &mut GuCGt<Window, Arena>, w: &Window, fence: &CompletionFence, start: u64) {
    let mut registered = BTreeMap::new();
    let mut saved = false;
    for now in start..start + 80 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if !saved {
            if let Some(base) = registered.values().next() {
                let d = w.0.borrow();
                let mut image = d.memory[base].borrow_mut();
                // 0x1800 is inside the saved portion of every admitted LRC,
                // including two-page BCS/media images; RCS-only 0x2000 is not.
                image[0x1800 / 4] = 0x51a7ca23;
                saved = true;
            }
        }
        if fence.result().is_some() {
            break;
        }
    }
    assert!(saved && registered.is_empty());
    assert_eq!(fence.result(), Some(Ok(())));
}

fn smoke_i915_capture_shared_policy_all_engine_members_and_normal_state_save() -> TestResult {
    for kind in 0..7 {
        let (w, arena, mut gt, ack) = if kind >= 4 {
            media_gt()
        } else {
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
            prime_mode(&mut gt, &w, 2);
            (w, arena, gt, ack)
        };
        let platform = if kind >= 4 {
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake)
        } else {
            GtPlatform::Battlemage
        };
        let (mailbox, _, card) = registered(&mut gt, &w, platform);
        let file = crate::drm_devfs_bridge::DriDir
            .lookup(&alloc::format!("card{card}"))
            .unwrap();
        let user = User::new();
        let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
        let id = if kind == 0 {
            0
        } else if kind == 2 || kind == 3 {
            mapped(&*file, &user, kind == 3, kind == 2)
        } else {
            create(&*file, &user)
        };
        set(&*file, &user, id, 2);
        let ring = match kind {
            0 => 1,
            1 => 3,
            2 | 3 => 0,
            4 => 2 | 1 << 13,
            5 => 2 | 2 << 13,
            _ => 4,
        };
        let mut previous = None;
        for pass in 0..2 {
            legacy_exec(&user, handles, id);
            selected(&user, &[false, true]);
            set_ring(&user, ring);
            let now = 20_000_000 + pass * 1000;
            let (context, fence) = accept(&*file, &user, &mailbox, &mut gt, now);
            if pass == 0 {
                // Protection never disables normal terminal LRC state-save.
                save_complete(&mut gt, &w, &fence, now + 1);
                previous = Some(context);
                continue;
            }
            assert!(Arc::ptr_eq(previous.as_ref().unwrap(), &context));
            let registered = armed(&mut gt, &w, &fence, now + 1);
            let base = *registered.values().next().unwrap();
            assert_eq!(w.0.borrow().memory[&base].borrow()[0x1800 / 4], 0x51a7ca23);
            // Both existing lazy media and a newly materialized member retain
            // the same live logical-context policy, not a submission snapshot.
            set(&*file, &user, id, 0);
            set(&*file, &user, id, u64::MAX);
            suppress(&gt, &w, 59);
            set(&*file, &user, id, 0);
            let bytes = capture(&gt, &w, 59);
            let range = &vm(&bytes)[0x10180..];
            assert_eq!(u64_at(range, 0), 0x2345_0000_0000);
            assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
            assert!(coredump::clear_for_test(59));
            finish(&mut gt, &w, ack, &fence);
        }
        drop(previous);
        drop(file);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_shared_policy_all_engine_members_and_normal_state_save
);

fn smoke_i915_capture_prime_async_cancel_and_exact_terminal_ownership() -> TestResult {
    use crate::intel_gpu_gem::reserve_gpu;
    use narf_filesystem::dma_buf::DmaResvUsage;
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let source = RenderFile::new();
    let user = User::new();
    let original = make_buffers(&user, |cmd| {
        assert_eq!(source.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    let objects = original.map(|handle| source.gem.object(handle).unwrap());
    let weak = objects.each_ref().map(Arc::downgrade);
    let file = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("renderD{}", card + 128))
        .unwrap();
    let exported = objects
        .each_ref()
        .map(|object| crate::drm_devfs_bridge::intel_dma_buf_file(card, object.clone()));
    // Actual same-card PRIME import path, not a synthesized storage flag.
    let handles = exported
        .each_ref()
        .map(|export| file.drm_prime_import_file(export).unwrap());
    assert_eq!(file.drm_prime_import_file(&exported[1]), Ok(handles[1]));
    let prior_code = Arc::new(CompletionFence::new());
    let prior_data = Arc::new(CompletionFence::new());
    reserve_gpu(&[(objects[0].clone(), true)], &prior_code).unwrap();
    reserve_gpu(&[(objects[1].clone(), true)], &prior_data).unwrap();
    let id = create(&*file, &user);
    legacy_exec(&user, handles, id);
    selected(&user, &[true, true]);
    {
        let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert!(
            mailbox.pending.lock().is_empty(),
            "CAPTURE bypassed ordinary implicit dependencies"
        );
    }
    legacy_exec(&user, handles, id);
    selected(&user, &[true, true]);
    let flags = u64_at(&user.load(344, 8), 0);
    user.store(344, &(flags | 0x40).to_le_bytes());
    let (context, fence) = {
        let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert!(
            mailbox.pending.lock().is_empty(),
            "mixed normal code dependency disappeared"
        );
        // These are explicitly foreign dependency fences, never native job
        // completions. Only real GPU/retirement/reset signals the native fence.
        prior_code.signal(Ok(()));
        // wait_idle parks on its existing 100us timer, not this foreign
        // fence's waker. Resume to real admission with a bounded deadline;
        // an immediate poll need not have crossed that timer yet.
        let deadline = narf_time::monotonic_ns().saturating_add(10_000_000);
        while mailbox.pending.lock().is_empty() {
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            );
            assert_eq!(prior_data.result(), None);
            assert!(
                narf_time::monotonic_ns() < deadline,
                "normal code dependency did not resume after its timer"
            );
            narf_scheduler::sleep_pumps::run();
        }
        assert_eq!(mailbox.pending.lock().len(), 1);
        // Cancel/drop the ioctl waiter before observing its successful reply.
        mailbox.accept(&mut gt, 500)
    };
    assert_eq!(prior_data.result(), None);
    assert_eq!(
        objects[1].dma_buf.resv.fences(DmaResvUsage::Write).len(),
        2,
        "ASYNC lost mandatory terminal WRITE reservation"
    );
    assert_eq!(
        objects[0].dma_buf.resv.fences(DmaResvUsage::Read).len(),
        1,
        "normal code lost terminal READ reservation"
    );
    armed(&mut gt, &w, &fence, 501);
    for handle in original {
        source.gem.close(handle).unwrap();
    }
    for handle in handles {
        close(&*file, &user, abi::GEM_CLOSE, handle);
    }
    drop(source);
    drop(objects);
    drop(exported);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    set(&*file, &user, id, 2);
    suppress(&gt, &w, 59);
    set(&*file, &user, id, 0);
    let bytes = capture(&gt, &w, 59);
    let record = vm(&bytes);
    assert_eq!((word(record, 40), word(record, 44)), (2, 2));
    let range = &record[0x101c0..];
    assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
    assert_eq!(fence.result(), None);
    assert!(context.busy());
    assert_eq!(prior_data.result(), None);
    close(&*file, &user, abi::GEM_CONTEXT_DESTROY, id);
    drop(file);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    finish(&mut gt, &w, ack, &fence);
    assert!(!context.busy());
    assert!(
        weak.iter().all(|object| object.upgrade().is_none()),
        "capture leaked imported BO graph after proven reset"
    );
    assert_eq!(coredump::snapshot_bytes_for_test(59).unwrap(), bytes);
    assert!(coredump::clear_for_test(59));
    drop(context);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_prime_async_cancel_and_exact_terminal_ownership
);

fn smoke_i915_capture_protected_bundle_includes_real_native_parallel_sources() -> TestResult {
    use crate::intel_gpu_engine::Engine;
    use crate::intel_gpu_exec::ResidentBatch;
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("renderD{}", card + 128))
        .unwrap();
    let user = User::new();
    let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
    let id = create(&*file, &user);
    legacy_exec(&user, handles, id);
    selected(&user, &[true, true]);
    let (_, protected_fence) = accept(&*file, &user, &mailbox, &mut gt, 500);
    let mut registered = armed(&mut gt, &w, &protected_fence, 501);
    set(&*file, &user, id, 2);
    // A native two-lane submission has no i915 policy. Its actual multi-LRC
    // owner and scratch/child rings share the same raw bundle with i915 work.
    let native = UserContext::for_parallel(alloc::vec![
        EngineSet::of(&[Engine::Ccs1]),
        EngineSet::of(&[Engine::Ccs3])
    ])
    .unwrap();
    let batch =
        ResidentBatch::from_vm_parallel(GtPlatform::Battlemage, &[], None, 2, false, None).unwrap();
    let (native_id, native_fence) = gt
        .submit_user_batch(600, native.clone(), UserBatch(batch))
        .unwrap();
    let mut executed = false;
    for now in 601..680 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        let actions = service_contexts(&w, &mut registered, true);
        if actions.contains(&0x1000) {
            executed = true;
            break;
        }
    }
    assert!(executed && native_fence.result().is_none());
    let group = w.0.borrow().parallel_contexts[&u32::from(native_id)].clone();
    assert_eq!(group.images.len(), 2);
    for (i, base) in group.images.iter().enumerate() {
        let d = w.0.borrow();
        let mut image = d.memory[base].borrow_mut();
        image[0x1800 / 4] = 0x4c524300 + i as u32;
        let ring = image[1024 + 9];
        d.memory[&ring].borrow_mut()[0x7fc / 4] = 0x52494e00 + i as u32;
    }
    w.0.borrow().memory[&group.scratch].borrow_mut()[0xe00 / 4] = 0x47525023;
    suppress(&gt, &w, 59);
    assert!(native.busy() && native_fence.result().is_none() && protected_fence.result().is_none());
    set(&*file, &user, id, 0);
    let bytes = capture(&gt, &w, 59);
    assert_eq!(word(&bytes, 72) & 31, 31);
    let offset = word(&bytes, 144) as usize;
    let execution = &bytes[offset..];
    assert_eq!(&execution[..8], b"NARFEXEC");
    assert_eq!(
        (
            word(execution, 24),
            word(execution, 28),
            word(execution, 32)
        ),
        (3, 3, 3)
    );
    let mut lanes = 0;
    for record in execution[64..].chunks(0x13080).take(3) {
        if word(record, 4) == u32::from(native_id) {
            let lane = word(record, 8);
            assert_eq!(
                word(&bytes, word(record, 44) as usize + 0x1800),
                0x4c524300 + lane
            );
            assert_eq!(
                word(&bytes, word(record, 52) as usize + 0x7fc),
                0x52494e00 + lane
            );
            if lane == 0 {
                assert_eq!(word(&bytes, word(record, 60) as usize + 0xe00), 0x47525023);
            }
            lanes += 1;
        }
    }
    assert_eq!(lanes, 2);
    assert!(coredump::clear_for_test(59));
    hardware_stop(&mut gt, &w, ack);
    assert_eq!(
        native_fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert_eq!(
        protected_fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    drop(native);
    drop(file);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_protected_bundle_includes_real_native_parallel_sources
);

static RAW_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static RAW_READER: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static RAW_ADMIN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
fn raw_enabled() -> bool {
    RAW_ENABLED.load(core::sync::atomic::Ordering::Acquire)
}
fn raw_reader() -> bool {
    RAW_READER.load(core::sync::atomic::Ordering::Acquire)
}
fn raw_admin() -> bool {
    RAW_ADMIN.load(core::sync::atomic::Ordering::Acquire)
}
fn open_dump(write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
    coredump::open_for_test(59, raw_enabled, raw_reader, raw_admin, write)
}
fn dump_read(file: &dyn FileOps, offset: u64, out: &mut [u8]) -> Result<usize, FsError> {
    let mut call = core::pin::pin!(file.read(offset, out));
    match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("cached dump read waited"),
    }
}
fn dump_write(file: &dyn FileOps, offset: u64, input: &[u8]) -> Result<usize, FsError> {
    let mut call = core::pin::pin!(file.write(offset, input));
    match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("cached dump clear waited"),
    }
}
fn smoke_i915_capture_actual_bundle_current_reader_admin_and_generation_gates() -> TestResult {
    use core::sync::atomic::Ordering;
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("renderD{}", card + 128))
        .unwrap();
    let user = User::new();
    let handles = make_buffers(&user, |cmd| assert_eq!(node(&*file, &user, cmd), Ok(0)));
    let id = create(&*file, &user);
    legacy_exec(&user, handles, id);
    selected(&user, &[false, true]);
    let (_, fence) = accept(&*file, &user, &mailbox, &mut gt, 500);
    armed(&mut gt, &w, &fence, 501);
    let bytes = capture(&gt, &w, 59);
    let range = &vm(&bytes)[0x10180..];
    assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
    RAW_ENABLED.store(false, Ordering::Release);
    RAW_READER.store(true, Ordering::Release);
    RAW_ADMIN.store(true, Ordering::Release);
    assert!(matches!(
        open_dump(false),
        Err(FsError::OperationNotPermitted)
    ));
    RAW_ENABLED.store(true, Ordering::Release);
    RAW_READER.store(false, Ordering::Release);
    assert!(matches!(
        open_dump(false),
        Err(FsError::OperationNotPermitted)
    ));
    RAW_READER.store(true, Ordering::Release);
    let reader = open_dump(false).unwrap().unwrap();
    let writer = open_dump(true).unwrap().unwrap();
    assert_eq!(reader.stat().size as usize, bytes.len());
    let mut marker = [0; 4];
    let at = u64::from(word(range, 40)) + 0x80;
    assert_eq!(dump_read(&*reader, at, &mut marker), Ok(4));
    assert_eq!(u32_at(&marker, 0), 0x4e415246);
    let reads = w.0.borrow().mmio_reads.get();
    RAW_READER.store(false, Ordering::Release);
    for offset in [0, bytes.len() as u64, u64::MAX] {
        assert_eq!(
            dump_read(&*reader, offset, &mut []),
            Err(FsError::OperationNotPermitted)
        );
    }
    assert_eq!(reader.stat().size, 0);
    assert_eq!(
        dump_write(&*writer, 0, b"clear\n"),
        Err(FsError::OperationNotPermitted)
    );
    RAW_READER.store(true, Ordering::Release);
    RAW_ADMIN.store(false, Ordering::Release);
    assert_eq!(
        dump_write(&*writer, 0, b"clear\n"),
        Err(FsError::OperationNotPermitted)
    );
    assert!(matches!(
        open_dump(true),
        Err(FsError::OperationNotPermitted)
    ));
    RAW_ADMIN.store(true, Ordering::Release);
    assert_eq!(dump_write(&*reader, 0, b"clear\n"), Err(FsError::ReadOnly));
    assert_eq!(
        dump_write(&*writer, 1, b"clear\n"),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        w.0.borrow().mmio_reads.get(),
        reads,
        "cached permission checks touched hardware"
    );
    // Protection does not revoke an old immutable reader or splice new bytes.
    set(&*file, &user, id, 2);
    let armed = coredump::Armed::reserve_for_test(59).unwrap();
    gt.capture_coredump(armed, report(&gt, &w), 6_000_000_003, [0; 32], || {
        panic!("protected new generation read backing")
    });
    assert_eq!(coredump::snapshot_bytes_for_test(59).unwrap(), bytes);
    assert_eq!(dump_read(&*reader, at, &mut marker), Ok(4));
    assert_eq!(u32_at(&marker, 0), 0x4e415246);
    assert_eq!(dump_write(&*writer, 0, b"clear\n"), Ok(6));
    assert!(coredump::snapshot_bytes_for_test(59).is_none());
    set(&*file, &user, id, 0);
    let newer = capture(&gt, &w, 59);
    assert_eq!(
        dump_write(&*writer, 0, b"clear\n"),
        Err(FsError::Busy),
        "old generation cleared the newer bundle"
    );
    let current = open_dump(true).unwrap().unwrap();
    assert_eq!(dump_write(&*current, 0, b"clear\n"), Ok(6));
    assert!(coredump::snapshot_bytes_for_test(59).is_none());
    assert_eq!(dump_read(&*reader, at, &mut marker), Ok(4));
    assert_eq!(u32_at(&marker, 0), 0x4e415246);
    assert_eq!(&newer[..8], &bytes[..8]);
    drop((reader, writer, current));
    RAW_ENABLED.store(false, Ordering::Release);
    RAW_READER.store(false, Ordering::Release);
    RAW_ADMIN.store(false, Ordering::Release);
    assert_eq!(fence.result(), None);
    finish(&mut gt, &w, ack, &fence);
    drop(file);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_actual_bundle_current_reader_admin_and_generation_gates
);

fn smoke_i915_capture_storage_refusals_precede_context_and_dma_publication() -> TestResult {
    use crate::intel_gpu_gem::{GemObject, Placement};
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, mut info, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let source = RenderFile::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    let before = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    let refuse = |handle, asynchronous| {
        legacy_exec(&user.wire, [handles[0], handle], 0);
        selected(&user.wire, &[true, true]);
        if asynchronous {
            let flags = u64_at(&user.wire.load(344, 8), 0);
            user.wire.store(344, &(flags | 0x40).to_le_bytes());
        }
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
        assert!(mailbox.pending.lock().is_empty());
        assert_eq!(arena.live_allocations(), before);
        assert_eq!(w.0.borrow().writes.len(), writes);
    };
    let vm_id = create_vm(&source, &info, &user);
    let owned = create_bo(&source, &info, &user, 4096, vm_id);
    let object = source.gem.object(owned).unwrap();
    assert!(object.vm_owner().is_some());
    let imported = file.gem.import(&object).unwrap();
    assert!(Arc::ptr_eq(&object, &file.gem.object(imported).unwrap()));
    refuse(imported, false);
    match source
        .gem
        .create_placed(4096, None, Placement::SystemWc, |_, _| Ok(()))
    {
        Err(FsError::NotImplemented) => assert!(cfg!(target_arch = "aarch64")),
        result => {
            let wc = source.gem.object(result.unwrap()).unwrap();
            assert!(wc.is_wc());
            refuse(file.gem.import(&wc).unwrap(), false);
        }
    }
    *user.mapping.lock() = Some(
        file.gem
            .object(handles[1])
            .unwrap()
            .backing(0, 4096)
            .unwrap(),
    );
    let pinned =
        GemObject::from_user_pins(user.pin_user_pages(0x4000, 1, true).unwrap(), 0x18).unwrap();
    assert!(pinned.is_userptr());
    refuse(file.gem.import(&pinned).unwrap(), true); // existing ASYNC pin refusal
    let frame = narf_memory::frame::alloc_pages_on(0, 1).unwrap();
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_ptr::<u8>() as u64,
        len: 8192,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = crate::intel_gpu_vram::VramLayout {
        tile_size: 8192,
        tile_offset: 0,
        usable: 8192,
    };
    // SAFETY: this fixture owns the entire fake visible local aperture until
    // every source/import/pool reference is dropped below. No physical grant
    // or smallbar-CPU alias coverage is inferred from this refusal control.
    let pool = unsafe { crate::intel_gpu_vram::Vram::new(bar, layout) }.unwrap();
    info.vram = Some(pool.clone());
    let local = create_placed(&source, &info, &user, 4096, 2, 4, 2).unwrap();
    let local = source.gem.object(local).unwrap();
    assert!(local.is_vram());
    let imported = file.gem.import(&local).unwrap();
    legacy_exec(&user.wire, [handles[0], imported], 0);
    selected(&user.wire, &[true, true]);
    {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
    }
    assert!(mailbox.pending.lock().is_empty());
    assert_eq!(arena.live_allocations(), before);
    assert_eq!(w.0.borrow().writes.len(), writes);
    // Safe WB control uses this exact raw parser and the real native owner.
    legacy_exec(&user.wire, handles, 0);
    selected(&user.wire, &[true, true]);
    let (_, fence) = {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        let accepted = mailbox.accept(&mut gt, 500);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        accepted
    };
    armed(&mut gt, &w, &fence, 501);
    let bytes = capture(&gt, &w, 59);
    let range = &vm(&bytes)[0x101c0..];
    assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
    assert!(coredump::clear_for_test(59));
    finish(&mut gt, &w, ack, &fence);
    drop(local);
    drop(object);
    drop(pinned);
    *user.mapping.lock() = None;
    drop(source);
    drop(file);
    drop(info);
    assert_eq!(pool.used(), 0);
    drop(pool);
    narf_memory::frame::free_pages(frame, 1);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_storage_refusals_precede_context_and_dma_publication
);

struct Output {
    wire: User,
    fences: IrqSafeSpinLock<Vec<Arc<dyn DrmFence>>>,
    fail: core::sync::atomic::AtomicBool,
}
impl IoctlContext for Output {
    fn read(&self, at: u64, out: &mut [u8]) -> Result<(), FsError> {
        self.wire.read(at, out)
    }
    fn write(&self, at: u64, data: &[u8]) -> Result<(), FsError> {
        if at == 120 && self.fail.load(core::sync::atomic::Ordering::Acquire) {
            return Err(FsError::BadAddress);
        }
        self.wire.write(at, data)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        report(17).map_err(narf_filesystem::InstallFdError::Report)?;
        *self.fences.lock() = fences;
        Ok(17)
    }
}
fn smoke_i915_capture_faultable_output_rollback_and_exact_native_fence() -> TestResult {
    use crate::intel_gpu_exec::ExecRequest;
    use crate::intel_gpu_user::UserOutput;
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (_, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Output {
        wire: User::new(),
        fences: IrqSafeSpinLock::new(Vec::new()),
        fail: core::sync::atomic::AtomicBool::new(true),
    };
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    let context = UserContext::new();
    let before = arena.live_allocations();
    for cache_failure in [false, true] {
        legacy_exec(&user.wire, handles, 0);
        selected(&user.wire, &[true, true]);
        let batch = ExecRequest::read(&user, 64, &file.gem)
            .unwrap()
            .prepare_user(GtPlatform::Battlemage)
            .unwrap();
        user.fail
            .store(!cache_failure, core::sync::atomic::Ordering::Release);
        w.0.borrow_mut().fail_sync = cache_failure;
        assert!(gt
            .submit_user_batch_with_output(
                500,
                context.clone(),
                batch,
                &UserOutput {
                    user: &user,
                    address: 120,
                    input: 0x12345678
                }
            )
            .is_err());
        assert!(!context.busy() && context.last().is_none());
        assert!(user.fences.lock().is_empty());
        assert_eq!(file.gem.object(handles[0]).unwrap().busy(), 0);
        assert_eq!(file.gem.object(handles[1]).unwrap().busy(), 0);
        assert_eq!(arena.live_allocations(), before);
    }
    w.0.borrow_mut().fail_sync = false;
    user.fail
        .store(false, core::sync::atomic::Ordering::Release);
    legacy_exec(&user.wire, handles, 0);
    selected(&user.wire, &[true, true]);
    let batch = ExecRequest::read(&user, 64, &file.gem)
        .unwrap()
        .prepare_user(GtPlatform::Battlemage)
        .unwrap();
    let (_, fence) = gt
        .submit_user_batch_with_output(
            600,
            context.clone(),
            batch,
            &UserOutput {
                user: &user,
                address: 120,
                input: 0x12345678,
            },
        )
        .unwrap();
    assert_eq!(
        u64_at(&user.wire.load(120, 8), 0),
        (17u64 << 32) | 0x12345678
    );
    let exported = user.fences.lock().pop().unwrap();
    let exact: Arc<dyn DrmFence> = fence.clone();
    assert!(Arc::ptr_eq(&exported, &exact));
    armed(&mut gt, &w, &fence, 601);
    let bytes = capture(&gt, &w, 59);
    let range = &vm(&bytes)[0x101c0..];
    assert_eq!(word(&bytes, word(range, 40) as usize + 0x80), 0x4e415246);
    assert!(!exported.is_signalled());
    assert!(coredump::clear_for_test(59));
    finish(&mut gt, &w, ack, &fence);
    assert!(exported.is_signalled());
    drop(context);
    drop(file);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_capture",
    smoke_i915_capture_faultable_output_rollback_and_exact_native_fence
);
