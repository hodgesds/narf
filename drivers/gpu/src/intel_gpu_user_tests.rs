// Native userspace ioctl -> actual GT/CT/PPGTT ownership tests. The mailbox
// only transports calls to the !Send device model; all fences come from GuCGt.
use super::*;
use crate::{
    intel_gpu_exec::PpgttProbeResult,
    intel_gpu_fence::{CompletionFence, JobError},
    intel_gpu_render::{tests::User, DeviceInfo, RenderFile},
    intel_gpu_uapi::{self as abi, put32, put64, u32_at, u64_at},
    intel_gpu_user::{UserBackend, UserBatch, UserContext, UserStatus},
};
use alloc::boxed::Box;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_filesystem::{FsError, FsFuture};
use narf_lib::sync::IrqSafeSpinLock;

fn prime(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    hardware_discovery(gt, w, ack);
    hardware_scheduling(gt, w);
    let fence = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..95 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
    assert!(gt.user_epoch().is_some());
}

fn complete(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    start: u64,
    expected: u32,
    saved: u32,
) {
    let mut registered = BTreeMap::new();
    let mut saw = false;
    for now in start..start + 50 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        for base in registered.values() {
            let image = w.0.borrow().memory[base].clone();
            if !saw {
                assert_eq!(image.borrow()[0x2000 / 4], expected);
                image.borrow_mut()[0x2000 / 4] = saved;
                saw = true;
            }
        }
        if fence.result().is_some() {
            break;
        }
    }
    assert!(saw);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}

fn smoke_userspace_context_save_restore_and_isolation() -> TestResult {
    for (platform, ack, ip) in [
        (GtPlatform::Alchemist, 0x130044, 0),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (1 << 14)),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (2 << 14)),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (70 << 14),
        ),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (71 << 14),
        ),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (74 << 14),
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        if ip != 0 {
            w.0.borrow_mut().regs.insert(0xd8c, ip);
        }
        let context = UserContext::new();
        let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
        assert!(gt
            .submit_user_batch(0, context.clone(), UserBatch(batch))
            .is_err());
        assert!(!context.busy());
        prime(&mut gt, &w, ack);
        let baseline = arena.live_allocations();
        for (iteration, target, expected, saved) in [
            (0, context.clone(), 0xc01dcafe, 0x11112222),
            (1, context.clone(), 0x11112222, 0x33334444),
            (2, UserContext::new(), 0xc01dcafe, 0x55556666),
            (3, context.clone(), 0x33334444, 0x77778888),
        ] {
            let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
            let now = 100 + iteration * 100;
            let (_, fence) = gt
                .submit_user_batch(now, target.clone(), UserBatch(batch))
                .unwrap();
            assert!(target.busy());
            let (conflict, _) = PpgttProbeResult::prepare(platform).unwrap();
            assert!(matches!(
                gt.submit_user_batch(now, target.clone(), UserBatch(conflict)),
                Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Residency(FsError::WouldBlock)
                ))
            ));
            complete(&mut gt, &w, &fence, now + 1, expected, saved);
            assert_eq!(result.verify(), Ok(()));
            assert!(!target.busy());
            assert_eq!(arena.live_allocations(), baseline);
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_context_save_restore_and_isolation
);

fn smoke_userspace_cache_rollback_and_reset_ownership() -> TestResult {
    for cpu_failure in [false, true] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        prime(&mut gt, &w, 0xdfc);
        let context = UserContext::new();
        let weak_context = Arc::downgrade(&context);
        let baseline = arena.live_allocations();
        let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
        w.0.borrow_mut().fail_sync = true;
        assert!(gt
            .submit_user_batch(100, context.clone(), UserBatch(batch))
            .is_err());
        assert!(!context.busy());
        assert_eq!(arena.live_allocations(), baseline);
        w.0.borrow_mut().fail_sync = false;
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let weak_objects = result.weak_objects();
        let (_, fence) = gt
            .submit_user_batch(100, context.clone(), UserBatch(batch))
            .unwrap();
        drop(context);
        drop(result);
        let mut registered = BTreeMap::new();
        for now in 101..151 {
            if let Poll::Ready(Err(_)) = gt.poll(now) {
                break;
            }
            service_contexts(&w, &mut registered, cpu_failure);
            if cpu_failure {
                w.0.borrow_mut().fail_cpu_sync = true;
            }
            if !cpu_failure && !registered.is_empty() {
                break;
            }
        }
        assert!(fence.result().is_none());
        assert!(weak_context.upgrade().unwrap().busy());
        assert!(weak_objects.iter().all(|o| o.upgrade().is_some()));
        if cpu_failure {
            assert_eq!(gt.state(), GtState::Lost);
        }
        // Keep one observing Arc; ownership remains in the GT until reset.
        let context = weak_context.upgrade().unwrap();
        w.0.borrow_mut().fail_cpu_sync = false;
        hardware_stop(&mut gt, &w, 0xdfc);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert_eq!(context.reset_stats(), (0, 1));
        assert!(context.check_epoch(gt.user_epoch().unwrap_or(0)).is_err());
        assert!(!context.busy());
        assert!(weak_objects.iter().all(|o| o.upgrade().is_none()));
        drop(context);
        assert!(weak_context.upgrade().is_none());
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_cache_rollback_and_reset_ownership
);

#[derive(Debug)]
struct Reply {
    result: IrqSafeSpinLock<Option<Result<Arc<CompletionFence>, FsError>>>,
    waker: IrqSafeSpinLock<Option<Waker>>,
}
#[derive(Debug)]
struct Pending {
    context: Arc<UserContext>,
    batch: UserBatch,
    reply: Arc<Reply>,
}
#[derive(Debug)]
struct Mailbox {
    status: IrqSafeSpinLock<Option<UserStatus>>,
    pending: IrqSafeSpinLock<Vec<Pending>>,
}
impl UserBackend for Mailbox {
    fn status(&self) -> Option<UserStatus> {
        *self.status.lock()
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        Box::pin(async move {
            let reply = Arc::new(Reply {
                result: IrqSafeSpinLock::new(None),
                waker: IrqSafeSpinLock::new(None),
            });
            self.pending.lock().push(Pending {
                context,
                batch,
                reply: reply.clone(),
            });
            core::future::poll_fn(|cx| {
                *reply.waker.lock() = Some(cx.waker().clone());
                match reply.result.lock().take() {
                    Some(result) => Poll::Ready(result),
                    None => Poll::Pending,
                }
            })
            .await
        })
    }
}
impl Mailbox {
    fn accept(
        &self,
        gt: &mut GuCGt<Window, Arena>,
        now: u64,
    ) -> (Arc<UserContext>, Arc<CompletionFence>) {
        let pending = self
            .pending
            .lock()
            .pop()
            .expect("userspace queued a request");
        let (_, fence) = gt
            .submit_user_batch(now, pending.context.clone(), pending.batch)
            .unwrap();
        *pending.reply.result.lock() = Some(Ok(fence.clone()));
        if let Some(waker) = pending.reply.waker.lock().take() {
            waker.wake();
        }
        (pending.context, fence)
    }
}

fn invoke(file: &RenderFile, info: &DeviceInfo, user: &User, cmd: u32) {
    assert_eq!(file.dispatch(info, cmd, 64, user), Some(Ok(0)));
}

fn buffers(file: &RenderFile, info: &DeviceInfo, user: &User) -> [u32; 2] {
    make_buffers(user, |cmd| invoke(file, info, user, cmd))
}

fn make_buffers(user: &User, mut call: impl FnMut(u32)) -> [u32; 2] {
    let handles = core::array::from_fn(|_| {
        let mut request = [0; 16];
        put64(&mut request, 0, 4096);
        user.store(64, &request);
        call(abi::GEM_CREATE);
        u32_at(&user.load(64, 16), 8)
    });
    let mut code = Vec::new();
    for word in [0x10000002u32, 0x80, 0x2345, 0x4e415246, 0x05000000, 0] {
        code.extend_from_slice(&word.to_le_bytes());
    }
    user.store(512, &code);
    let mut upload = [0; 32];
    put32(&mut upload, 0, handles[0]);
    put64(&mut upload, 16, code.len() as u64);
    put64(&mut upload, 24, 512);
    user.store(64, &upload);
    call(abi::GEM_PWRITE);
    handles
}
fn exec(user: &User, handles: [u32; 2], context: u32) {
    let mut objects = [0; 112];
    for (i, (handle, va, write)) in [
        (handles[0], 0x1234_0000_0000, false),
        (handles[1], 0x2345_0000_0000, true),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = &mut objects[i * 56..(i + 1) * 56];
        put32(entry, 0, handle);
        put64(entry, 24, va);
        put64(
            entry,
            32,
            abi::OBJECT_PINNED
                | abi::OBJECT_SUPPORTS_48B
                | if write { abi::OBJECT_WRITE } else { 0 },
        );
    }
    user.store(256, &objects);
    let mut request = [0; 64];
    put64(&mut request, 0, 256);
    put32(&mut request, 8, 2);
    put32(&mut request, 16, 24);
    put64(
        &mut request,
        40,
        abi::EXEC_RENDER | abi::EXEC_NO_RELOC | abi::EXEC_BATCH_FIRST,
    );
    put64(&mut request, 48, u64::from(context));
    user.store(64, &request);
}

fn smoke_userspace_execbuffer_ioctl_order_close_and_completion() -> TestResult {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let backend = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x7d55,
        0,
        0,
    ));
    card.install_user_backend(backend.clone()).unwrap();
    let card_index = crate::drm_registry::register_drm_card(card);
    let info = DeviceInfo::for_card(card_index).unwrap();
    assert!(info.submission_ready());
    let file = RenderFile::new();
    let user = User::new();
    for (param, value) in [(8, 1), (11, 0)] {
        let mut request = [0; 24];
        put64(&mut request, 8, param);
        put64(&mut request, 16, value);
        user.store(64, &request);
        assert_eq!(
            file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(FsError::NotImplemented))
        );
    }
    // Live engine/version discovery uses Linux's exact sizes and field order.
    for (id, size) in [
        (abi::QUERY_ENGINES, 128),
        (abi::QUERY_GUC_SUBMISSION_VERSION, 16),
    ] {
        let mut query = [0; 16];
        put32(&mut query, 0, 1);
        put64(&mut query, 8, 1024);
        let mut item = [0; 24];
        put64(&mut item, 0, id);
        user.store(64, &query);
        user.store(1024, &item);
        invoke(&file, &info, &user, abi::QUERY);
        assert_eq!(u32_at(&user.load(1024, 24), 8), size);
        put32(&mut item, 8, size);
        put64(&mut item, 16, 2048);
        user.store(1024, &item);
        invoke(&file, &info, &user, abi::QUERY);
        let data = user.load(2048, size as usize);
        if id == abi::QUERY_ENGINES {
            // drm_i915_engine_info: RENDER/0 then COPY/0, HAS_LOGICAL_INSTANCE.
            assert_eq!(u32_at(&data, 0), 2);
            assert!(data[4..16].iter().all(|v| *v == 0));
            for (i, class) in [0u8, 1].into_iter().enumerate() {
                let entry = &data[16 + i * 56..16 + (i + 1) * 56];
                assert_eq!(&entry[..4], &[class, 0, 0, 0]);
                assert_eq!(u64_at(entry, 8), 1);
                assert!(entry[4..8].iter().chain(&entry[16..]).all(|v| *v == 0));
            }
            // Nonzero input num_engines/rsvd is EINVAL and leaves data untouched.
            user.store(2048, &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
            invoke(&file, &info, &user, abi::QUERY);
            assert_eq!(u32_at(&user.load(1024, 24), 8) as i32, -22);
            assert_eq!(u32_at(&user.load(2048, 16), 8), 1);
        } else {
            assert_eq!(&data, &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
    let mut version = [0; 64];
    put64(&mut version, 16, 16);
    put64(&mut version, 24, 2048);
    user.store(64, &version);
    invoke(&file, &info, &user, crate::drm_uapi::DRM_IOCTL_VERSION);
    assert_eq!(u64_at(&user.load(64, 64), 16), 4);
    assert_eq!(user.load(2048, 4), b"i915");
    let handles = buffers(&file, &info, &user);
    exec(&user, handles, 0);
    let mut cx = Context::from_waker(Waker::noop());
    // Secure dispatch is rejected before the backend sees any work.
    let mut hostile = user.load(64, 64);
    let flags = u64_at(&hostile, 40);
    put64(&mut hostile, 40, flags | (1 << 9));
    user.store(64, &hostile);
    {
        let mut call = core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut cx),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
        assert!(backend.pending.lock().is_empty());
    }
    exec(&user, handles, 0);
    let (context, fence) = {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card_index, abi::GEM_EXECBUFFER2, 64, &user));
        assert!(call.as_mut().poll(&mut cx).is_pending());
        let submitted = backend.accept(&mut gt, 100);
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        submitted
    };
    assert!(
        fence.result().is_none(),
        "ioctl acceptance is not GPU completion"
    );
    let mut rebind = [0; 24];
    put64(&mut rebind, 8, 9);
    user.store(64, &rebind);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::Busy))
    );
    exec(&user, handles, 0);
    // A second submission on the same context waits before backend publication;
    // cancellation of that waiter cannot cancel the first hardware job.
    {
        let mut waiting =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert!(backend.pending.lock().is_empty());
    }
    complete(&mut gt, &w, &fence, 101, 0xc01dcafe, 0xabcdef01);
    let mut readback = [0; 32];
    put32(&mut readback, 0, handles[1]);
    put64(&mut readback, 8, 0x80);
    put64(&mut readback, 16, 4);
    put64(&mut readback, 24, 512);
    user.store(64, &readback);
    invoke(&file, &info, &user, abi::GEM_PREAD);
    assert_eq!(u32_at(&user.load(512, 4), 0), 0x4e415246);
    exec(&user, handles, 0);
    let fence = {
        let mut call =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call.as_mut().poll(&mut cx).is_pending());
        let (_, fence) = backend.accept(&mut gt, 200);
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        fence
    };
    for handle in handles {
        let mut close = [0; 8];
        put32(&mut close, 0, handle);
        user.store(64, &close);
        invoke(&file, &info, &user, abi::GEM_CLOSE);
    }
    drop(file);
    assert!(context.busy());
    complete(&mut gt, &w, &fence, 201, 0xabcdef01, 0x12345678);
    assert!(!context.busy());
    *backend.status.lock() = None;
    assert!(!info.submission_ready());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_execbuffer_ioctl_order_close_and_completion
);

fn set_ring(user: &User, ring: u64) {
    let mut request = user.load(64, 64);
    let flags = u64_at(&request, 40) & !0x3f;
    put64(&mut request, 40, flags | ring);
    user.store(64, &request);
}

fn engines_param(user: &User, context: u32, entries: &[(u16, u16)], at: u64) -> [u8; 24] {
    let mut map = alloc::vec![0; 8];
    for (class, instance) in entries {
        map.extend_from_slice(&class.to_le_bytes());
        map.extend_from_slice(&instance.to_le_bytes());
    }
    user.store(at, &map);
    let mut param = [0; 24];
    put32(&mut param, 0, context);
    put32(&mut param, 4, map.len() as u32);
    put64(&mut param, 8, abi::CONTEXT_PARAM_ENGINES);
    put64(&mut param, 16, at);
    param
}

fn smoke_userspace_i915_copy_engine_legacy_ring_and_engine_map() -> TestResult {
    use crate::intel_gpu_engine::Engine;
    let platform = GtPlatform::Alchemist;
    let (w, arena, mut gt) = hardware_model(platform, 0x130044);
    prime(&mut gt, &w, 0x130044);
    let backend = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x56a0,
        0,
        0,
    ));
    card.install_user_backend(backend.clone()).unwrap();
    let info = DeviceInfo::for_card(crate::drm_registry::register_drm_card(card)).unwrap();
    let file = RenderFile::new();
    let user = User::new();
    // I915_PARAM_HAS_BLT.
    let mut getparam = [0; 16];
    put32(&mut getparam, 0, 11);
    put64(&mut getparam, 8, 4096);
    user.store(64, &getparam);
    invoke(&file, &info, &user, abi::GETPARAM);
    assert_eq!(u32_at(&user.load(4096, 4), 0), 1);
    let handles = buffers(&file, &info, &user);
    let submit = |ring: u64, context: u32, gt: &mut GuCGt<Window, Arena>, now| {
        exec(&user, handles, context);
        set_ring(&user, ring);
        let mut cx = Context::from_waker(Waker::noop());
        let mut call = core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call.as_mut().poll(&mut cx).is_pending());
        let submitted = backend.accept(gt, now);
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        submitted
    };
    let refuse = |ring: u64, context: u32| {
        exec(&user, handles, context);
        set_ring(&user, ring);
        let mut call = core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2, 64, &user));
        let result = call.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(backend.pending.lock().is_empty());
        result
    };
    let run = |gt: &mut GuCGt<Window, Arena>, fence: &CompletionFence, start| {
        let mut registered = BTreeMap::new();
        for now in start..start + 60 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Ok(())));
    };
    // eb_select_legacy_ring: BLT is BCS0; BSD/VEBOX/unknown rings are EINVAL.
    let (context, fence) = submit(abi::EXEC_BLT, 0, &mut gt, 100);
    assert_eq!(context.engine(), Engine::Bcs0);
    run(&mut gt, &fence, 101);
    let mut readback = [0; 32];
    put32(&mut readback, 0, handles[1]);
    put64(&mut readback, 8, 0x80);
    put64(&mut readback, 16, 4);
    put64(&mut readback, 24, 512);
    user.store(64, &readback);
    invoke(&file, &info, &user, abi::GEM_PREAD);
    assert_eq!(u32_at(&user.load(512, 4), 0), 0x4e415246);
    let (render, fence) = submit(abi::EXEC_RENDER, 0, &mut gt, 200);
    assert_eq!(render.engine(), Engine::Rcs0);
    assert!(!Arc::ptr_eq(&render, &context));
    run(&mut gt, &fence, 201);
    for ring in [2, 4, 5, 0x3f] {
        assert_eq!(refuse(ring, 0), Poll::Ready(Some(Err(FsError::InvalidData))));
    }
    // The default context is finalized at open: its map is immutable.
    let param = engines_param(&user, 0, &[(1, 0)], 8192);
    user.store(64, &param);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    // CREATE_EXT SETPARAM map: COPY, hole, RENDER.
    let param = engines_param(&user, 0, &[(1, 0), (0xffff, 0xffff), (0, 0)], 8192);
    let mut ext = [0; 56];
    ext[32..].copy_from_slice(&param);
    user.store(6144, &ext);
    let mut create = [0; 16];
    put32(&mut create, 4, 1);
    put64(&mut create, 8, 6144);
    user.store(64, &create);
    invoke(&file, &info, &user, abi::GEM_CONTEXT_CREATE_EXT);
    let mapped = u32_at(&user.load(64, 16), 0);
    let (slot0, fence) = submit(0, mapped, &mut gt, 300);
    assert_eq!(slot0.engine(), Engine::Bcs0);
    run(&mut gt, &fence, 301);
    let (slot2, fence) = submit(2, mapped, &mut gt, 400);
    assert_eq!(slot2.engine(), Engine::Rcs0);
    run(&mut gt, &fence, 401);
    for ring in [1, 3, abi::EXEC_BLT + 8] {
        assert_eq!(refuse(ring, mapped), Poll::Ready(Some(Err(FsError::InvalidData))));
    }
    // A duplicate ENGINES extension in one chain is EINVAL before its copy.
    let mut first = ext;
    put64(&mut first, 0, 6400);
    let mut second = ext;
    put64(&mut second, 48, 0x7fff_ffff_0000); // unreadable map
    user.store(6144, &first);
    user.store(6400, &second);
    user.store(64, &create);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_CREATE_EXT, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    // Proto-context setparam: errno classes follow set_proto_ctx_engines.
    user.store(64, &[0; 8]);
    invoke(&file, &info, &user, abi::GEM_CONTEXT_CREATE);
    let proto = u32_at(&user.load(64, 8), 0);
    for (entries, size, expected) in [
        (&[(2u16, 0u16)][..], None, FsError::NotFound), // no VCS0
        (&[(1, 1)][..], None, FsError::NotFound),
        (&[(0, 0)][..], Some(10), FsError::InvalidData),
        (&[(0, 0)][..], Some(4), FsError::InvalidData),
        (&[(0, 0)][..], Some(8 + 65 * 4), FsError::InvalidData),
    ] {
        let mut param = engines_param(&user, proto, entries, 8192);
        if let Some(size) = size {
            put32(&mut param, 4, size);
        }
        user.store(64, &param);
        assert_eq!(
            file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(expected))
        );
    }
    // An unknown entry is ENOENT before a later entry's copy can fault.
    let mut param = engines_param(&user, proto, &[(4, 0)], 32756);
    put32(&mut param, 4, 16);
    user.store(64, &param);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::NotFound))
    );
    // Load-balance extension (name 0) is not admitted; unknown names are EINVAL.
    for (name, expected) in [(0u32, FsError::NotImplemented), (3, FsError::InvalidData)] {
        let mut extension = [0; 32];
        put32(&mut extension, 8, name);
        user.store(7168, &extension);
        let param = engines_param(&user, proto, &[(1, 0)], 8192);
        user.store(8192, &7168u64.to_le_bytes());
        user.store(64, &param);
        assert_eq!(
            file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(expected))
        );
    }
    let param = engines_param(&user, proto, &[(1, 0)], 8192);
    user.store(64, &param);
    invoke(&file, &info, &user, abi::GEM_CONTEXT_SETPARAM);
    user.store(64, &param);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData)),
        "engines set twice"
    );
    let mut get = param;
    put32(&mut get, 4, 0);
    user.store(64, &get);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_GETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    let mut missing = param;
    put32(&mut missing, 0, 999);
    user.store(64, &missing);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::NotFound))
    );
    *backend.status.lock() = None;
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_i915_copy_engine_legacy_ring_and_engine_map
);

fn smoke_userspace_context_epoch_loss_refuses_replay() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let context = UserContext::new();
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let epoch = gt.user_epoch().unwrap();
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, fence) = gt
        .submit_user_batch(100, context.clone(), UserBatch(batch))
        .unwrap();
    complete(&mut gt, &w, &fence, 101, 0xc01dcafe, 0x11112222);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    assert_ne!(gt.user_epoch(), Some(epoch));
    let baseline = arena.live_allocations();
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    assert!(gt
        .submit_user_batch(100, context.clone(), UserBatch(batch))
        .is_err());
    assert_eq!(arena.live_allocations(), baseline);
    assert_eq!(context.reset_stats(), (0, 0));
    assert!(context.check_epoch(gt.user_epoch().unwrap()).is_err());
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, fence) = gt
        .submit_user_batch(100, UserContext::new(), UserBatch(batch))
        .unwrap();
    complete(&mut gt, &w, &fence, 101, 0xc01dcafe, 0x33334444);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_context_epoch_loss_refuses_replay
);

fn smoke_userspace_primary_render_nodes_and_context_namespaces() -> TestResult {
    use narf_filesystem::DirOps;
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let backend = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0xe20b,
        0,
        0,
    ));
    card.install_user_backend(backend.clone()).unwrap();
    let index = crate::drm_registry::register_drm_card(card);
    let mut contexts = Vec::new();
    for (iteration, name) in [
        alloc::format!("card{index}"),
        alloc::format!("renderD{}", index + 128),
    ]
    .into_iter()
    .enumerate()
    {
        let file = crate::drm_devfs_bridge::DriDir
            .lookup(&name)
            .expect("DRM device node");
        let user = User::new();
        let mut cx = Context::from_waker(Waker::noop());
        let handles = make_buffers(&user, |cmd| {
            let mut call = core::pin::pin!(file.ioctl_user(cmd, 64, &user));
            assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Ok(0)));
        });
        user.store(64, &[0; 8]);
        {
            let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_CONTEXT_CREATE, 64, &user));
            assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Ok(0)));
        }
        let id = u32_at(&user.load(64, 8), 0);
        assert_eq!(id, 1, "context handles are per-open");
        exec(&user, handles, id);
        let now = 100 + iteration as u64 * 100;
        let (context, fence) = {
            let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_EXECBUFFER2, 64, &user));
            assert!(call.as_mut().poll(&mut cx).is_pending());
            let submitted = backend.accept(&mut gt, now);
            assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Ok(0)));
            submitted
        };
        let weak = Arc::downgrade(&context);
        contexts.push(context);
        let mut destroy = [0; 8];
        put32(&mut destroy, 0, id);
        user.store(64, &destroy);
        {
            let mut call = core::pin::pin!(file.ioctl_user(abi::GEM_CONTEXT_DESTROY, 64, &user));
            assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Ok(0)));
        }
        drop(file);
        assert!(weak.upgrade().unwrap().busy());
        complete(
            &mut gt,
            &w,
            &fence,
            now + 1,
            0xc01dcafe,
            0x11110000 + iteration as u32,
        );
    }
    assert!(!Arc::ptr_eq(&contexts[0], &contexts[1]));
    *backend.status.lock() = None;
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_userspace_primary_render_nodes_and_context_namespaces
);

mod explicit {
    include!("intel_gpu_explicit_tests.rs");
}
mod xe {
    include!("intel_gpu_xe_tests.rs");
}
