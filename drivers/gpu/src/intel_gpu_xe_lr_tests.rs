// Long-running Xe VMs (`DRM_XE_VM_CREATE_FLAG_LR_MODE`):
// 1. Flag validation matrix on `VM_CREATE` (2, 3 valid; 4 invalid; 6 deferred to FAULT_MODE).
// 2. Forbid fence-export `SYNCOBJ`/`TIMELINE_SYNCOBJ` out-syncs on `VM_BIND` and `EXEC`.
// 3. Permit zero-operation barrier `VM_BIND` with out `USER_FENCE`.
// 4. Suppress the 5s watchdog / 15s stall timeout on LR jobs while cleanly aborting
//    active jobs on `EXEC_QUEUE_DESTROY` without hanging/failing the GT.
use super::*;

fn create_vm_flags(file: &RenderFile, info: &DeviceInfo, user: &Cpu, flags: u32) -> Result<u32, FsError> {
    let mut wire = [0; 32];
    put32(&mut wire, 8, flags);
    user.wire.store(64, &wire);
    invoke(file, info, user, xe::VM_CREATE)?;
    Ok(u32_at(&user.wire.load(64, 32), 12))
}

fn smoke_xe_lr_vm_flag_matrix_and_sync_contracts() -> TestResult {
    let platform = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake);
    let (w, arena, mut gt) = hardware_model(platform, 0x130044);
    prime(&mut gt, &w, 0x130044);
    let (_, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();

    // FAULT_MODE without LR_MODE is InvalidData; LR_MODE | FAULT_MODE (6) & +SCRATCH (7) are admitted.
    assert_eq!(create_vm_flags(&file, &info, &user, 4), Err(FsError::InvalidData));
    let fault_vm = create_vm_flags(&file, &info, &user, 6).unwrap();
    let fault_scratch_vm = create_vm_flags(&file, &info, &user, 7).unwrap();

    let lr_vm = create_vm_flags(&file, &info, &user, 2).unwrap();
    let lr_scratch_vm = create_vm_flags(&file, &info, &user, 3).unwrap();
    let lr_queue = create_queue(&file, &info, &user, lr_vm, 0);
    let syncobj = file.syncobjs.lock().create(0).unwrap();

    // Out-syncobj forbidden on LR VM_BIND and LR EXEC, including timeline syncobjs.
    for kind in [0u32, 1] {
        bind_wire(&user, lr_vm, &[], &[sync(kind, u64::from(syncobj), 0, true)]);
        assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));

        exec_wire(&user, lr_queue, false, &[sync(kind, u64::from(syncobj), 0, true)]);
        assert_eq!(
            narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::EXEC, 64, &user))
                .expect("LR exec"),
            Err(FsError::InvalidData)
        );
    }

    // Wait-in syncobj (signal == false) is permitted on LR VM_BIND; barrier zero-op with USER_FENCE out-sync succeeds.
    user.wire.store(0x7000, &0u64.to_le_bytes());
    bind_wire(&user, lr_vm, &[], &[sync(2, 0x7000, 0x11, true)]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert_eq!(user.read_u64_acquire(0x7000), Ok(0x11));

    // PREFETCH (op == 4) requires FAULT_MODE and a mapped VA range.
    let mut prefetch = [0; 80];
    put64(&mut prefetch, 24, 4096);
    put64(&mut prefetch, 32, 0x20000);
    put32(&mut prefetch, 40, 4);
    bind_wire(&user, lr_vm, &[prefetch], &[]);
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
    bind_wire(&user, fault_vm, &[prefetch], &[]);
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));

    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, lr_queue), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, lr_vm), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, lr_scratch_vm), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, fault_vm), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, fault_scratch_vm), Ok(0));
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_lr_vm_flag_matrix_and_sync_contracts
);

fn smoke_xe_lr_job_runs_past_watchdog_and_completes_or_cancels_on_destroy() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();

    let vm = create_vm_flags(&file, &info, &user, 2).unwrap();
    let queue = create_queue(&file, &info, &user, vm, 0);
    let _handles = buffers(&file, &info, &user, vm);

    // 1. Submit an LR job with a USER_FENCE output and run well past both the
    //    5s per-job watchdog and 15s (3 * TIMEOUT) global stall limit.
    user.wire.store(0x7020, &0u64.to_le_bytes());
    exec_wire(&user, queue, true, &[sync(2, 0x7020, 0x22, true)]);
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (_, fence1) = mailbox.accept(&mut gt, 100);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );

    let mut registered = BTreeMap::new();
    for step in 1..=25 {
        let now = 100 + step * 1_000_000_000;
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        assert_eq!(fence1.result(), None);
        assert!(gt.take_error_report().is_none());
    }
    assert_eq!(registered.len(), 1);
    let id1 = *registered.keys().next().unwrap();

    // Complete job1 normally at t = 25s + epsilon.
    {
        let base = registered[&id1];
        let d = w.0.borrow();
        let image = d.memory[&base].clone();
        let tail = image.borrow()[1024 + 7];
        let ring_base = image.borrow()[1024 + 9];
        let ring = d.memory[&ring_base].borrow();
        let stamp = ring[..tail as usize / 4]
            .windows(6)
            .find(|win| win[..4] == [0x7a000004, 0x01104080, base + 0x800, 0])
            .unwrap()[4];
        execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, stamp, base, false);
        let mut image = image.borrow_mut();
        image[0x800 / 4] = stamp;
        image[1024 + 5] = tail;
    }
    finish(&mut gt, &w, &fence1, &mut registered, 25_000_000_200);
    assert_eq!(user.read_u64_acquire(0x7020), Ok(0x22));
    assert!(registered.is_empty());

    // 2. Submit a second LR job, then destroy its exec queue while active:
    //    scheduler cleanly disables + retires it as aborted without hanging the GT.
    exec_wire(&user, queue, true, &[]);
    let mut call2 = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call2.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (_, fence2) = mailbox.accept(&mut gt, 26_000_000_000);
    assert_eq!(
        call2.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    for tick in 1..20 {
        assert_eq!(
            gt.poll(26_000_000_000 + tick),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&w, &mut registered, false);
        if registered.len() == 1 {
            break;
        }
    }
    assert_eq!(registered.len(), 1);
    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue), Ok(0));
    for tick in 20..120 {
        assert_eq!(
            gt.poll(26_000_000_000 + tick),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&w, &mut registered, true);
        if fence2.result().is_some() && registered.is_empty() {
            break;
        }
    }
    assert_eq!(fence2.result(), Some(Err(JobError::Hang)));
    assert!(registered.is_empty());
    assert!(gt.take_error_report().is_none());

    user.mapping.lock().take();
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_lr_job_runs_past_watchdog_and_completes_or_cancels_on_destroy
);

/// FAULT_MODE + PREFETCH (`op == 4`): sysmem prefetch (`region = 0`) evicts a
/// bound VRAM BO to system memory while retaining its VA mapping, and VRAM
/// prefetch (`region = 1`) migrates it back into VRAM cleanly.
fn smoke_xe_fault_mode_vm_and_prefetch_vram_residency() -> TestResult {
    let (frame, pool, backend, info) =
        super::vram_evict::evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();

    let vm = create_vm_flags(&file, &info, &user, 6).unwrap();
    let h = super::vram_evict::create_vram_bo(&file, &info, &user, 65536, 2).unwrap();
    let obj = file.gem.object(h).unwrap();
    assert!(obj.is_vram());
    let pattern: Vec<u8> = (0..65536).map(|i| ((i * 3 + 7) & 0xff) as u8).collect();
    obj.write(0, &pattern).unwrap();

    let mut map = [0; 80];
    put32(&mut map, 8, h);
    put32(&mut map, 12, 1); // PAT 1 coherent uncompressed on Xe2
    put64(&mut map, 24, 65536);
    put64(&mut map, 32, 0x20000);
    bind_wire(&user, vm, &[map], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));

    // Prefetch to region 0 (sysmem) evicts the VRAM object cleanly.
    let mut to_sys = [0; 80];
    put64(&mut to_sys, 16, 0);
    put64(&mut to_sys, 24, 65536);
    put64(&mut to_sys, 32, 0x20000);
    put32(&mut to_sys, 40, 4);
    bind_wire(&user, vm, &[to_sys], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(!obj.is_vram());
    assert_eq!(pool.used(), 0);

    // Prefetch to region 1 (VRAM) migrates it back to VRAM with data intact.
    let mut to_vram = [0; 80];
    put64(&mut to_vram, 16, 1);
    put64(&mut to_vram, 24, 65536);
    put64(&mut to_vram, 32, 0x20000);
    put32(&mut to_vram, 40, 4);
    bind_wire(&user, vm, &[to_vram], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(obj.is_vram());
    assert_eq!(pool.used(), 65536);
    let mut read_back = alloc::vec![0u8; 65536];
    obj.read(0, &mut read_back).unwrap();
    assert_eq!(read_back, pattern);

    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    drop(obj);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    crate::intel_gpu_exec::vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_fault_mode_vm_and_prefetch_vram_residency
);
