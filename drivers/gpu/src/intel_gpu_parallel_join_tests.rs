// Real Xe/GuC/PPGTT GPU joins. Literal semaphore encoding is from pinned
// MIT i915 intel_guc_submission.c; stores/flushes from xe_ring_ops.c.
use super::*;

const GPU_FENCE: u64 = 0x2345_0000_0100;
const CPU_FENCE: u64 = 0x4100;

fn stamp(w: &Window, group: &ParallelContext) -> u32 {
    let d = w.0.borrow();
    let image = d.memory[&group.images[0]].borrow();
    let ring = d.memory[&image[1033]].borrow();
    if matches!(image[1026], 0x22244 | 0x3ee244) {
        ring[9]
    } else {
        ring[7]
    }
}

fn assert_join_owner(w: &Window, group: &ParallelContext, owned: &[u32]) {
    let d = w.0.borrow();
    assert!(owned.iter().all(|base| d.memory.contains_key(base)));
    for (index, base) in group.images.iter().enumerate() {
        let image = d.memory[base].borrow();
        let ring = d.memory[&image[1033]].borrow();
        let words = &ring[..image[1031] as usize / 4];
        assert_eq!(
            words.iter().filter(|word| **word == 0x10200003).count(),
            usize::from(index == 0),
            "exactly one parent user-fence store"
        );
        assert_eq!(
            words.iter().filter(|word| **word == 0x0e40c002).count(),
            if index == 0 {
                group.images.len() - 1
            } else {
                0
            }
        );
    }
}

fn smoke_parallel_gpu_join_every_lane_orders_one_store_and_retirement() -> TestResult {
    for (platform, mask, mode, class, width) in [
        (GtPlatform::Battlemage, 15, 4, 1, 2),
        (GtPlatform::Alchemist, 10, 2, 4, 2),
        (GtPlatform::Alchemist, 13, 3, 4, 3),
        (GtPlatform::Alchemist, 15, 4, 4, 4),
        (GtPlatform::Battlemage, 13, 3, 4, 3),
        (GtPlatform::Battlemage, 15, 4, 4, 4),
    ] {
        let (w, arena, mut gt, ack) = discover(platform, mask);
        prime_mode(&mut gt, &w, mode);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = if class == 1 {
            create_parallel(&file, &info, &user, vm, class, 0)
        } else {
            create_width(&file, &info, &user, vm, 0, width)
        };
        let handles = buffers(&file, &info, &user, vm);
        let addresses = lane_batches(&file, handles[0], usize::from(width));
        let output = file.syncobjs.lock().create(0).unwrap();
        let core = file.syncobjs.lock().get(output).unwrap().core().clone();
        let baseline = arena.live_allocations();
        let mut point = 0u64;
        for barrier in [false, true] {
            for last in 0..usize::from(width) {
                point += 1;
                let now = 500 + point * 1000;
                let value = 0xfedc_ba98_0000_0000 | point;
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 136])
                    .unwrap();
                exec_width(
                    &user,
                    queue,
                    &addresses,
                    &[
                        sync(2, GPU_FENCE, value, true),
                        sync(1, u64::from(output), point, true),
                    ],
                    barrier,
                );
                let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
                let terminal = core.find_fence(point).unwrap();
                let mut registered = BTreeMap::new();
                let (id, group) = dispatch(&mut gt, &w, &mut registered, now + 1, false);
                let owned = owned_allocations(&w, &group);
                assert_join_owner(&w, &group, &owned);
                for (lane, base) in group.images.iter().copied().enumerate() {
                    if lane != last {
                        execute_parallel_lane(&w, id, base);
                        assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(0));
                    }
                }
                assert_eq!(gt.poll(now + 50), Poll::Ready(Ok(GtState::SchedulingReady)));
                assert!(service_contexts(&w, &mut registered, false).is_empty());
                assert!(context.busy() && fence.result().is_none() && !terminal.is_signalled());
                assert_eq!(w.0.borrow().parallel_join_stores.len(), point as usize - 1);
                assert_join_owner(&w, &group, &owned);
                execute_parallel_lane(&w, id, group.images[last]);
                assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(value));
                assert_eq!(w.0.borrow().parallel_join_stores.len(), point as usize);
                assert_eq!(
                    w.0.borrow().parallel_join_stores.last(),
                    Some(&(id, GPU_FENCE, value))
                );
                assert_eq!(
                    w.0.borrow().memory[&group.scratch].borrow()[32],
                    stamp(&w, &group)
                );
                assert!(fence.result().is_none() && !terminal.is_signalled());
                for lane in 0..usize::from(width) {
                    assert_eq!(
                        user.read_u64_acquire(0x4080 + lane as u64 * 8),
                        Ok(if barrier { 0 } else { 0xabc00000 + lane as u64 })
                    );
                }
                // Re-observing a completed hardware stream cannot replay its
                // user store, and the GPU signal never frees the owner.
                execute_parallel_join(&w, id);
                assert_eq!(w.0.borrow().parallel_join_stores.len(), point as usize);
                assert_join_owner(&w, &group, &owned);
                finish(&mut gt, &w, &fence, &mut registered, now + 60);
                assert!(terminal.is_signalled() && !context.busy() && !context.banned());
                assert_eq!(arena.live_allocations(), baseline);
                assert!(owned
                    .iter()
                    .all(|base| !w.0.borrow().memory.contains_key(base)));
            }
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_gpu_join_every_lane_orders_one_store_and_retirement
);

fn smoke_parallel_gpu_join_waiting_parent_and_final_phase_watchdogs() -> TestResult {
    for width in 2..=4u16 {
        for stalled_join in [false, true] {
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
            prime_mode(&mut gt, &w, 4);
            let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
            w.0.borrow_mut().regs.insert(0xd00, 0); //3MHz, five-second budget15M
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_width(&file, &info, &user, vm, 0, width);
            let _handles = buffers(&file, &info, &user, vm);
            let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
            exec_width(
                &user,
                queue,
                &addresses,
                &[sync(2, GPU_FENCE, 9, true)],
                false,
            );
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
            let owned = owned_allocations(&w, &group);
            w.0.borrow_mut().parallel_join_hold = stalled_join;
            execute_parallel_lane(&w, id, group.images[0]);
            // A parent polling a child semaphore must not become guilty
            // simply because its own CTX_TIMESTAMP keeps advancing.
            start_lane(
                &w,
                group.images[0],
                context.parallel().unwrap()[0],
                30_000_000,
            );
            if stalled_join {
                for base in group.images.iter().copied().skip(1) {
                    execute_parallel_lane(&w, id, base);
                }
                assert_eq!(gt.poll(540), Poll::Ready(Ok(GtState::SchedulingReady)));
                assert_eq!(
                    gt.poll(5_000_000_539),
                    Poll::Ready(Ok(GtState::SchedulingReady))
                );
                assert_eq!(
                    gt.poll(5_000_000_540),
                    Poll::Ready(Err(GtError::Scheduling(
                        crate::intel_gpu_guc_sched::SchedulingError::Timeout
                    )))
                );
                assert!(context.busy() && !context.banned() && fence.result().is_none());
                assert_eq!(context.reset_stats(), (0, 0));
                assert_join_owner(&w, &group, &owned);
            } else {
                for now in [5_000_001_000, 10_000_001_000] {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                    assert!(service_contexts(&w, &mut registered, false).is_empty());
                    assert!(gt.take_error_report().is_none());
                    assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(0));
                    assert!(context.busy() && !context.banned() && fence.result().is_none());
                }
                for base in group.images.iter().copied().skip(1) {
                    execute_parallel_lane(&w, id, base);
                }
                assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(9));
                finish(&mut gt, &w, &fence, &mut registered, 10_000_001_100);
            }
            if stalled_join {
                assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(0));
            }
            hardware_stop(&mut gt, &w, ack);
            assert_eq!(
                fence.result(),
                Some(if stalled_join {
                    Err(JobError::Reset)
                } else {
                    Ok(())
                })
            );
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_gpu_join_waiting_parent_and_final_phase_watchdogs
);

fn smoke_parallel_gpu_join_reset_close_and_corruption_retain_all_dma() -> TestResult {
    for width in 2..=4u16 {
        for failure in 0..4 {
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
            prime_mode(&mut gt, &w, 4);
            let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_width(&file, &info, &user, vm, 0, width);
            let handles = buffers(&file, &info, &user, vm);
            let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
            let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
            exec_width(
                &user,
                queue,
                &addresses,
                &[sync(2, GPU_FENCE, 13, true)],
                false,
            );
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
            let owned = owned_allocations(&w, &group);
            let retained = arena.live_allocations();
            for base in group.images.iter().copied().take(usize::from(width - 1)) {
                execute_parallel_lane(&w, id, base);
            }
            assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(0));
            assert_eq!(
                close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                Ok(0)
            );
            assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
            for handle in handles {
                assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
            }
            user.mapping.lock().take();
            drop(file);
            match failure {
                0 => {}
                1 => event(&ct_memory(&w), 0x1008, &[id + u32::from(width - 1)]),
                2 => {
                    let wrong = stamp(&w, &group) + 1;
                    w.0.borrow().memory[&group.scratch].borrow_mut()[32] = wrong;
                }
                _ => w.0.borrow_mut().fail_cpu_sync = true,
            }
            if failure == 1 {
                for now in 540..590 {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                    service_contexts(&w, &mut registered, false);
                    if fence.result().is_some() {
                        break;
                    }
                }
                assert_eq!(fence.result(), Some(Err(JobError::Hang)));
                assert_eq!(context.reset_stats(), (1, 0));
                assert!(weak.iter().all(|object| object.upgrade().is_none()));
            } else {
                if failure != 0 {
                    let expected = if failure == 2 {
                        crate::intel_gpu_guc_sched::SchedulingError::Protocol
                    } else {
                        crate::intel_gpu_guc_sched::SchedulingError::Cache
                    };
                    assert_eq!(
                        gt.poll(540),
                        Poll::Ready(Err(GtError::Scheduling(expected)))
                    );
                }
                assert!(context.busy() && fence.result().is_none());
                assert_eq!(arena.live_allocations(), retained);
                assert!(weak.iter().all(|object| object.upgrade().is_some()));
                assert_join_owner(&w, &group, &owned);
            }
            assert!(w.0.borrow().parallel_join_stores.is_empty());
            w.0.borrow_mut().fail_cpu_sync = false;
            hardware_stop(&mut gt, &w, ack);
            assert_eq!(
                fence.result(),
                Some(Err(if failure == 1 {
                    JobError::Hang
                } else {
                    JobError::Reset
                }))
            );
            assert!(!context.busy() && context.banned());
            assert!(weak.iter().all(|object| object.upgrade().is_none()));
            assert!(owned
                .iter()
                .all(|base| !w.0.borrow().memory.contains_key(base)));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_gpu_join_reset_close_and_corruption_retain_all_dma
);

fn smoke_parallel_gpu_join_admission_rollback_and_cancelled_submit_ownership() -> TestResult {
    for width in 2..=4u16 {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_width(&file, &info, &user, vm, 0, width);
        let _handles = buffers(&file, &info, &user, vm);
        let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
        let baseline = arena.live_allocations();
        for bad in [GPU_FENCE + 1, 0x1234_0000_0000, 0x2345_0000_1000] {
            exec_width(&user, queue, &addresses, &[sync(2, bad, 17, true)], false);
            assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::InvalidData));
            assert!(mailbox.pending.lock().is_empty());
            assert_eq!(arena.live_allocations(), baseline);
        }
        for failed in 1..=usize::from(width) * 2 + 2 {
            exec_width(
                &user,
                queue,
                &addresses,
                &[sync(2, GPU_FENCE, 17, true)],
                false,
            );
            let context = {
                let mut future = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
                assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
                let pending = mailbox.pending.lock().pop().unwrap();
                let context = pending.context.clone();
                if failed <= usize::from(width) * 2 + 1 {
                    let next = w.0.borrow().allocations + failed;
                    w.0.borrow_mut().fail_at = Some(next);
                } else {
                    w.0.borrow_mut().fail_sync = true;
                }
                assert!(gt
                    .submit_user_batch(500, context.clone(), pending.batch)
                    .is_err());
                w.0.borrow_mut().fail_at = None;
                w.0.borrow_mut().fail_sync = false;
                context
            };
            assert!(!context.busy() && !context.banned());
            assert_eq!(arena.live_allocations(), baseline);
            assert!(w.0.borrow().parallel_contexts.is_empty());
            assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(0));
        }
        let output = file.syncobjs.lock().create(0).unwrap();
        let core = file.syncobjs.lock().get(output).unwrap().core().clone();
        exec_width(
            &user,
            queue,
            &addresses,
            &[
                sync(2, GPU_FENCE, 19, true),
                sync(1, u64::from(output), 5, true),
            ],
            false,
        );
        let (context, fence) = {
            // Cancel the actual ioctl future after its backend accepted the
            // group, before returning to publish the caller's syncobj name.
            let mut future = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            mailbox.accept(&mut gt, 600)
        };
        assert!(context.busy() && fence.result().is_none());
        assert!(matches!(core.find_fence(5), Err(())));
        let mut registered = BTreeMap::new();
        let (id, group) = dispatch(&mut gt, &w, &mut registered, 601, false);
        let owned = owned_allocations(&w, &group);
        for base in group.images.iter().copied().rev() {
            execute_parallel_lane(&w, id, base);
        }
        assert_eq!(user.read_u64_acquire(CPU_FENCE), Ok(19));
        assert_eq!(w.0.borrow().parallel_join_stores.len(), 1);
        assert_join_owner(&w, &group, &owned);
        finish(&mut gt, &w, &fence, &mut registered, 640);
        assert!(!context.busy() && !context.banned());
        assert!(
            matches!(core.find_fence(5), Err(())),
            "cancellation fabricated syncobj publication"
        );
        assert_eq!(arena.live_allocations(), baseline);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_gpu_join_admission_rollback_and_cancelled_submit_ownership
);
