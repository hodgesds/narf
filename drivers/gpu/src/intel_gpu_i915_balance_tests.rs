// i915 client ABI on a production-profile Xe card, through actual registered
// node dispatch and the real GuC virtual-context/PPGTT retirement owner.
use super::super::super::{engines_param, exec as legacy_exec, make_buffers, set_ring};
use super::*;
use crate::intel_gpu_engine::EngineSet;
use narf_filesystem::{DirOps, DrmFence};

fn registered(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    platform: GtPlatform,
) -> (Arc<Mailbox>, DeviceInfo, u32) {
    let (mailbox, facts) = setup(gt, w, platform);
    let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        facts.device_id,
        0,
        0,
    ));
    card.install_user_backend(facts.backend.unwrap()).unwrap();
    card.publish_gt_topology(gt).unwrap();
    let index = crate::drm_registry::register_drm_card(card);
    let info = DeviceInfo::for_card(index).unwrap();
    assert!(info.native_xe() && info.submission_ready());
    (mailbox, info, index)
}

fn balance(user: &User, at: u64, index: u16, siblings: &[(u16, u16)]) {
    let mut ext = alloc::vec![0; 48];
    put32(&mut ext, 8, abi::CONTEXT_ENGINES_EXT_LOAD_BALANCE);
    ext[32..34].copy_from_slice(&index.to_le_bytes());
    ext[34..36].copy_from_slice(&(siblings.len() as u16).to_le_bytes());
    for (class, logical) in siblings {
        ext.extend_from_slice(&class.to_le_bytes());
        ext.extend_from_slice(&logical.to_le_bytes());
    }
    user.store(at, &ext);
}
fn balanced_map(
    user: &User,
    id: u32,
    entries: &[(u16, u16)],
    index: u16,
    siblings: &[(u16, u16)],
) -> [u8; 24] {
    let param = engines_param(user, id, entries, 8192);
    balance(user, 7168, index, siblings);
    user.store(8192, &7168u64.to_le_bytes());
    user.store(64, &param);
    param
}
fn prototype(file: &RenderFile, card: u32, user: &Cpu) -> u32 {
    user.wire.store(64, &[0; 8]);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_CREATE, 64, user),
        Some(Ok(0))
    );
    u32_at(&user.wire.load(64, 8), 0)
}

fn non_wb_cache_refusal(file: &RenderFile, card: u32, user: &Cpu, handle: u32) {
    use narf_filesystem::dma_buf::DmaResvUsage;
    let object = file.gem.object(handle).unwrap();
    assert!(object.is_wc() || object.is_vram());
    let offset = file.gem.mmap_offset(handle).unwrap();
    let mapping = object.backing(0, 4096).unwrap();
    assert_eq!(mapping.memory_type, narf_memory::MemoryType::WriteCombining);
    let reservations = object.dma_buf.resv.fences(DmaResvUsage::Write);
    for cmd in [abi::GEM_GET_CACHING, abi::GEM_SET_CACHING] {
        let mut wire = [0; 8];
        put32(&mut wire, 0, handle);
        put32(&mut wire, 4, 1);
        user.wire.store(64, &wire);
        assert_eq!(
            file.dispatch_card(card, cmd, 64, user),
            Some(Err(FsError::Unsupported))
        );
        assert_eq!(
            user.wire.load(64, 8),
            wire,
            "refusal fabricated a cache result"
        );
    }
    let mut wire = [0; 32];
    put32(&mut wire, 0, handle);
    put64(&mut wire, 8, 0xfeedface);
    put64(&mut wire, 16, 2);
    user.wire.store(64, &wire);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_MMAP_OFFSET, 64, user),
        Some(Err(FsError::InvalidData))
    );
    assert_eq!(user.wire.load(64, 32), wire, "refusal published a WB alias");
    // Native mmap keeps the original per-object memory type and offset.
    let mut wire = [0; 40];
    put32(&mut wire, 8, handle);
    user.wire.store(64, &wire);
    assert_eq!(
        file.dispatch_card(card, xe::GEM_MMAP_OFFSET, 64, user),
        Some(Ok(0))
    );
    assert_eq!(u64_at(&user.wire.load(64, 40), 16), offset);
    let after = object.backing(0, 4096).unwrap();
    assert_eq!(after.memory_type, mapping.memory_type);
    assert_eq!(after.frames, mapping.frames);
    let after = object.dma_buf.resv.fences(DmaResvUsage::Write);
    assert_eq!(reservations.len(), after.len());
    assert!(reservations
        .iter()
        .zip(&after)
        .all(|(a, b)| Arc::ptr_eq(a, b)));
    assert_eq!(object.busy(), 0);
}

fn smoke_i915_balanced_real_xe_nodes_dispatch_migrate_and_preserve_state() -> TestResult {
    for (platform, class) in [
        (GtPlatform::Alchemist, 4u16),
        (GtPlatform::Battlemage, 4),
        (GtPlatform::Battlemage, 1),
    ] {
        let (w, arena, mut gt, ack) = discover(platform, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, _, index) = registered(&mut gt, &w, platform);
        for (node, first) in [
            (alloc::format!("card{index}"), 0u64),
            (alloc::format!("renderD{}", index + 128), 1),
        ] {
            let file = crate::drm_devfs_bridge::DriDir.lookup(&node).unwrap();
            let user = User::new();
            let invoke = |cmd| {
                let mut call = core::pin::pin!(file.ioctl_user(cmd, 64, &user));
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(0))
                );
            };
            let mut version = [0; 64];
            put64(&mut version, 16, 8);
            put64(&mut version, 24, 4096);
            user.store(64, &version);
            invoke(crate::drm_uapi::DRM_IOCTL_VERSION);
            assert_eq!(user.load(4096, 2), b"xe");
            let handles = make_buffers(&user, invoke);
            // CREATE_EXT has an embedded SETPARAM with a virtual slot1;
            // the physical slot0 and unpopulated slot2 stay independent.
            let param = balanced_map(
                &user,
                0,
                &[(0, 0), (0xffff, 0xffff), (0xffff, 0xffff)],
                1,
                &[(class, 1), (class, 0)],
            );
            let mut ext = [0; 56];
            ext[32..].copy_from_slice(&param);
            user.store(6144, &ext);
            let mut create = [0; 16];
            put32(&mut create, 4, 1);
            put64(&mut create, 8, 6144);
            user.store(64, &create);
            invoke(abi::GEM_CONTEXT_CREATE_EXT);
            let id = u32_at(&user.load(64, 16), 0);
            let placements = if class == 4 {
                EngineSet::of(&[Engine::Ccs1, Engine::Ccs3])
            } else {
                EngineSet::of(&[Engine::Bcs0, Engine::Bcs8])
            };
            // All user extension/placement bytes may change after SETPARAM.
            user.store(7168, &[0xa5; 64]);
            user.store(8192, &[0xa5; 24]);
            let mut previous = None;
            for (iteration, logical) in [(0u64, 1u32), (1, 0)] {
                w.0.borrow_mut().virtual_pick = Some(logical);
                legacy_exec(&user, handles, id);
                set_ring(&user, 1);
                let start = 500 + first * 1000 + iteration * 100;
                let (context, fence) = {
                    let mut call =
                        core::pin::pin!(file.ioctl_user(abi::GEM_EXECBUFFER2_WR, 64, &user));
                    assert!(call
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending());
                    let result = mailbox.accept(&mut gt, start);
                    assert_eq!(
                        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Ready(Ok(0))
                    );
                    result
                };
                assert_eq!(context.placements(), placements);
                if let Some(old) = previous.as_ref() {
                    assert!(Arc::ptr_eq(old, &context));
                }
                previous = Some(context.clone());
                let mut registered = BTreeMap::new();
                let mut seen = false;
                for now in start + 1..start + 80 {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                    service_contexts(&w, &mut registered, true);
                    if !seen {
                        if let Some(base) = registered.values().next() {
                            let d = w.0.borrow();
                            assert_eq!(
                                d.virtual_contexts[base],
                                (if class == 4 { 4 } else { 3 }, 3)
                            );
                            let mut image = d.memory[base].borrow_mut();
                            assert_eq!(
                                image[0x1800 / 4],
                                if iteration == 0 { 0 } else { 0x51a7e001 }
                            );
                            image[0x1800 / 4] = 0x51a7e001 + iteration as u32;
                            seen = true;
                        }
                    }
                    if fence.result().is_some() {
                        break;
                    }
                }
                assert!(seen && registered.is_empty());
                assert_eq!(fence.result(), Some(Ok(())));
                let receipt = if class == 4 {
                    if logical == 1 {
                        0x35
                    } else {
                        0x15
                    }
                } else if logical == 1 {
                    0x83
                } else {
                    3
                };
                assert_eq!(w.0.borrow().virtual_restores.last().unwrap().1, receipt);
                let mut read = [0; 32];
                put32(&mut read, 0, handles[1]);
                put64(&mut read, 8, 0x80);
                put64(&mut read, 16, 4);
                put64(&mut read, 24, 512);
                user.store(64, &read);
                invoke(abi::GEM_PREAD);
                assert_eq!(u32_at(&user.load(512, 4), 0), 0x4e415246);
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
    smoke_i915_balanced_real_xe_nodes_dispatch_migrate_and_preserve_state
);

fn smoke_i915_balanced_extension_order_rollback_and_bounds() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (_, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = prototype(&file, card, &user);
    for (entries, index, siblings, expected) in [
        (
            alloc::vec![(0xffff, 0xffff)],
            1,
            alloc::vec![(4, 0), (4, 1)],
            FsError::InvalidData,
        ),
        (
            alloc::vec![(1, 0)],
            0,
            alloc::vec![(4, 0), (4, 1)],
            FsError::AlreadyExists,
        ),
        (
            alloc::vec![(0xffff, 0xffff)],
            0,
            alloc::vec![(4, 0), (1, 0)],
            FsError::InvalidData,
        ),
        (
            alloc::vec![(0xffff, 0xffff)],
            0,
            alloc::vec![(4, 0), (4, 0)],
            FsError::InvalidData,
        ),
        (
            alloc::vec![(0xffff, 0xffff)],
            0,
            alloc::vec![(4, 0), (4, 2)],
            FsError::InvalidData,
        ),
    ] {
        balanced_map(&user.wire, id, &entries, index, &siblings);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(expected))
        );
    }
    for (offset, value, expected) in [
        (8, 1, FsError::NotImplemented),
        (8, 2, FsError::NotImplemented),
        (8, 3, FsError::InvalidData),
        (12, 1, FsError::InvalidData),
        (36, 1, FsError::InvalidData),
        (40, 1, FsError::InvalidData),
    ] {
        balanced_map(&user.wire, id, &[(0xffff, 0xffff)], 0, &[(4, 0), (4, 1)]);
        user.wire
            .store(7168 + offset, &(value as u32).to_le_bytes());
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(expected))
        );
    }
    // A later bad extension cannot publish the first extension's valid slot.
    for later in [7168u64, 7296] {
        balanced_map(&user.wire, id, &[(0xffff, 0xffff)], 0, &[(4, 0), (4, 1)]);
        balance(&user.wire, 7296, 0, &[(4, 0)]);
        user.wire.store(7168, &later.to_le_bytes());
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(if later == 7168 {
                FsError::InvalidData
            } else {
                FsError::AlreadyExists
            }))
        );
    }
    // Destination errors precede an unreadable sibling count/body.
    for (entries, index, expected) in [
        (alloc::vec![(1, 0)], 0u16, FsError::AlreadyExists),
        (alloc::vec![(0xffff, 0xffff)], 1, FsError::InvalidData),
    ] {
        let param = engines_param(&user.wire, id, &entries, 8192);
        user.wire.store(8192, &32734u64.to_le_bytes());
        user.wire.store(32734, &[0; 32]);
        user.wire.store(32766, &index.to_le_bytes());
        user.wire.store(64, &param);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(Err(expected))
        );
    }
    // The first nonexistent sibling fails before a later sibling copy fault.
    let param = engines_param(&user.wire, id, &[(0xffff, 0xffff)], 8192);
    balance(&user.wire, 32716, 0, &[(4, 2)]);
    user.wire.store(32750, &2u16.to_le_bytes());
    user.wire.store(8192, &32716u64.to_le_bytes());
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    user.wire.store(32766, &0u16.to_le_bytes());
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::BadAddress))
    );
    // Sixteen no-op extensions are bounded; a seventeenth is refused.
    for count in [17u64, 16] {
        let param = engines_param(&user.wire, id, &[(0xffff, 0xffff)], 8192);
        for n in 0..count {
            let at = 10000 + n * 64;
            balance(&user.wire, at, 0, &[]);
            if n + 1 < count {
                user.wire.store(at, &(at + 64).to_le_bytes());
            }
        }
        user.wire.store(8192, &10000u64.to_le_bytes());
        user.wire.store(64, &param);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
            Some(if count == 17 {
                Err(FsError::InvalidData)
            } else {
                Ok(0)
            })
        );
    }
    // A failed CREATE_EXT reply removes its proto-context and keeps the ID.
    let param = balanced_map(&user.wire, 0, &[(0xffff, 0xffff)], 0, &[(1, 0), (1, 1)]);
    let mut ext = [0; 56];
    ext[32..].copy_from_slice(&param);
    user.wire.store(6144, &ext);
    let mut create = [0; 16];
    put32(&mut create, 4, 1);
    put64(&mut create, 8, 6144);
    user.wire.store(64, &create);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &user),
        Some(Err(FsError::BadAddress))
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_CREATE_EXT, 64, &user),
        Some(Ok(0))
    );
    assert_eq!(u32_at(&user.wire.load(64, 16), 0), id + 1);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_balanced_extension_order_rollback_and_bounds
);

fn smoke_i915_xe_shared_wb_reservations_syncobjs_and_private_vm_lifetimes() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, info, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 1);
    let handles = buffers(&file, &info, &user, vm);
    // A native VM-associated WB handle cannot be remapped into softpin's
    // independent PPGTT. Refusal leaves its native ownership and namespace.
    let associated = create_bo(&file, &info, &user, 4096, vm);
    let object = file.gem.object(associated).unwrap();
    let owner = object.vm_owner().expect("native associated owner");
    let writes = w.0.borrow().writes.len();
    let allocations = arena.live_allocations();
    legacy_exec(&user.wire, [handles[0], associated], 0);
    {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
    }
    assert!(mailbox.pending.lock().is_empty());
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(arena.live_allocations(), allocations);
    assert_eq!(object.vm_owner(), Some(owner));
    assert_eq!(object.busy(), 0);
    assert!(Arc::ptr_eq(&object, &file.gem.object(associated).unwrap()));
    assert!(object
        .dma_buf
        .resv
        .fences(narf_filesystem::dma_buf::DmaResvUsage::Write)
        .is_empty());
    let binding = mapping(associated, 0x3456_0000_0000, 0, 4096, 2, 0);
    bind_wire(&user, vm, &[binding], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(object.vm_bound());
    let other = create_vm(&file, &info, &user);
    bind_wire(&user, other, &[binding], &[]);
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
    assert_eq!(object.vm_owner(), Some(owner));
    assert!(object.vm_bound());
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, other), Ok(0));
    drop(object);
    // Native VM maps the second code page; compatibility maps the whole BO
    // at its own VA. Both pages contain the same actual private batch.
    let code: Vec<_> = [0x10000002u32, 0x80, 0x2345, 0x4e415246, 0x05000000, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    file.gem
        .object(handles[0])
        .unwrap()
        .write(0, &code)
        .unwrap();
    let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
    let id = prototype(&file, card, &user);
    balanced_map(&user.wire, id, &[(0xffff, 0xffff)], 0, &[(1, 0), (1, 1)]);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    exec_wire(&user, queue, true, &[]);
    let native = {
        let mut call = core::pin::pin!(file.dispatch_card_user(card, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 500);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let signal = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(signal).unwrap().core().clone();
    let (context, legacy) = {
        legacy_exec(&user.wire, handles, id);
        set_ring(&user.wire, 0);
        let mut request = user.wire.load(64, 64);
        let flags = u64_at(&request, 40);
        put64(&mut request, 40, flags | abi::EXEC_FENCE_ARRAY);
        put32(&mut request, 28, 1);
        put64(&mut request, 32, 1024);
        let mut output = [0; 8];
        put32(&mut output, 0, signal);
        put32(&mut output, 4, 2);
        user.wire.store(1024, &output);
        user.wire.store(64, &request);
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            mailbox.pending.lock().is_empty(),
            "i915 bypassed native writer reservation"
        );
        assert!(core.fence().is_none());
        let mut registered = BTreeMap::new();
        finish(&mut gt, &w, &native, &mut registered, 501);
        let deadline = narf_time::monotonic_ns() + 10_000_000;
        while mailbox.pending.lock().is_empty() {
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert!(
                narf_time::monotonic_ns() < deadline,
                "reservation waiter did not resume"
            );
            narf_scheduler::sleep_pumps::run();
        }
        let accepted = mailbox.accept(&mut gt, 600);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        accepted
    };
    let output = core.fence().unwrap();
    let exact: Arc<dyn DrmFence> = legacy.clone();
    assert!(crate::drm::syncobj::to_drm_leaves(&output)
        .iter()
        .any(|f| Arc::ptr_eq(f, &exact)));
    assert!(!output.is_signalled());
    // The Xe dependency path sees the same i915 out-fence. Cancelling its
    // waiter must not cancel the already admitted virtual job or its fence.
    exec_wire(&user, queue, false, &[sync(0, u64::from(signal), 0, false)]);
    {
        let mut wait = core::pin::pin!(file.dispatch_card_user(card, xe::EXEC, 64, &user));
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(mailbox.pending.lock().is_empty());
    }
    // Unbinding/destroying the native VM cannot alter the compatibility
    // job's independent immutable page tables, even for the same GEM pages.
    let mut unmaps = [
        mapping(0, 0x1234_0000_0000, 0, 4096, 0, 0),
        mapping(0, 0x2345_0000_0000, 0, 4096, 0, 0),
    ];
    for op in &mut unmaps {
        put32(op, 40, 1);
    }
    bind_wire(&user, vm, &unmaps, &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    let mut destroy = [0; 8];
    put32(&mut destroy, 0, id);
    user.wire.store(64, &destroy);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_DESTROY, 64, &user),
        Some(Ok(0))
    );
    for handle in handles {
        assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
    }
    user.mapping.lock().take();
    assert!(context.busy() && legacy.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    let mut registered = BTreeMap::new();
    finish_policy(&mut gt, &w, &legacy, &mut registered, 601, 3);
    assert!(output.is_signalled());
    assert!(!context.busy());
    assert_eq!(context.reset_stats(), (0, 0));
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_xe_shared_wb_reservations_syncobjs_and_private_vm_lifetimes
);

fn smoke_i915_balanced_close_full_reset_and_stale_epoch_never_reclaim_early() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Battlemage);
    let old_epoch = gt.user_epoch().unwrap();
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = prototype(&file, card, &user);
    balanced_map(&user.wire, id, &[(0xffff, 0xffff)], 0, &[(4, 0), (4, 1)]);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
    legacy_exec(&user.wire, handles, id);
    set_ring(&user.wire, 0);
    let (context, fence) = {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let accepted = mailbox.accept(&mut gt, 500);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        accepted
    };
    let mut registered = BTreeMap::new();
    for now in 501..530 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let mut destroy = [0; 8];
    put32(&mut destroy, 0, id);
    user.wire.store(64, &destroy);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_DESTROY, 64, &user),
        Some(Ok(0))
    );
    for handle in handles {
        let mut close = [0; 8];
        put32(&mut close, 0, handle);
        user.wire.store(64, &close);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CLOSE, 64, &user),
            Some(Ok(0))
        );
    }
    drop(file);
    let owned = arena.live_allocations();
    assert!(context.busy() && !context.banned());
    assert_eq!(fence.result(), None);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    // Stop begins but no GuC-idle/full-engine-reset proof exists yet.
    gt.begin_stop(1000).unwrap();
    assert_eq!(arena.live_allocations(), owned);
    assert_eq!(fence.result(), None);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    // Complete this already-started stop, rather than starting a second one.
    assert!(gt.poll(1001).is_pending());
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(1002).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(
        fence.result(),
        None,
        "GuC reset alone was treated as fetch stop"
    );
    assert_eq!(arena.live_allocations(), owned);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    assert!(gt.poll(1003).is_pending());
    reset_done(&w);
    assert!(gt.poll(1004).is_pending());
    assert_eq!(gt.state(), GtState::ReleasingRender);
    assert!(gt.poll(1005).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(1006).is_pending());
    w.0.borrow_mut().regs.insert(ack, 0);
    assert_eq!(gt.poll(1007), Poll::Ready(Ok(GtState::Stopped)));
    assert_eq!(fence.result(), Some(Err(JobError::Reset)));
    assert_eq!(context.reset_stats(), (0, 1));
    assert!(!context.busy());
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    let (batch, _) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    assert!(gt
        .submit_user_batch(2000, context.clone(), UserBatch(batch))
        .is_err());
    assert_eq!(fence.result(), Some(Err(JobError::Reset)));
    *mailbox.status.lock() = None;
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    // A genuinely rebuilt/probed scheduler has a fresh epoch. It must not
    // reuse the saved state of the closed context lost in the old reset.
    w.0.borrow_mut().next = 0x20000000;
    let mut boot = stage(w.clone(), arena.clone(), GtPlatform::Battlemage);
    boot.config.uncached_mocs = Some(3);
    let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
    hardware_discovery(&mut gt, &w, ack);
    prime_mode(&mut gt, &w, 2);
    assert_ne!(gt.user_epoch().unwrap(), old_epoch);
    let owned = arena.live_allocations();
    let (batch, _) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    assert!(matches!(
        gt.submit_user_batch(3000, context, UserBatch(batch)),
        Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Residency(_)
        ))
    ));
    assert_eq!(arena.live_allocations(), owned);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_balanced_close_full_reset_and_stale_epoch_never_reclaim_early
);

fn smoke_i915_xe_exact_dispatch_discovery_sseu_and_wc_refusal() -> TestResult {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt, ack) = discover(platform, 1);
    prime_mode(&mut gt, &w, 1);
    let (mailbox, info, card) = registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = prototype(&file, card, &user);
    let topology = info.topology.as_ref().unwrap();
    for live in [true, false] {
        if !live {
            *mailbox.status.lock() = None;
        }
        for (parameter, value) in [
            (4, u32::from(info.device_id)),
            (33, topology.dss_count()),
            (34, topology.eu_count()),
            (51, 25_000_000),
            (41, u32::from(live)),
        ] {
            let mut wire = [0; 16];
            put32(&mut wire, 0, parameter);
            put64(&mut wire, 8, 4096);
            user.wire.store(64, &wire);
            assert_eq!(
                file.dispatch_card(card, abi::GETPARAM, 64, &user),
                Some(Ok(0))
            );
            assert_eq!(u32_at(&user.wire.load(4096, 4), 0), value);
        }
        user.wire.store(2048, &[0; 32]);
        let mut get = [0; 24];
        put32(&mut get, 0, id);
        put32(&mut get, 4, 32);
        put64(&mut get, 8, 7);
        put64(&mut get, 16, 2048);
        user.wire.store(64, &get);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_GETPARAM, 64, &user),
            Some(Ok(0))
        );
        let sseu = user.wire.load(2048, 32);
        assert_eq!(u64_at(&sseu, 8), 1);
        assert_eq!(
            u64_at(&sseu, 16),
            u64::from((topology.geometry_dss() | topology.compute_dss()) & 255)
        );
        let mut version = [0; 64];
        put64(&mut version, 16, 8);
        put64(&mut version, 24, 4096);
        user.wire.store(64, &version);
        assert_eq!(
            file.dispatch_card(card, crate::drm_uapi::DRM_IOCTL_VERSION, 64, &user),
            Some(Ok(0))
        );
        assert_eq!(user.wire.load(4096, 2), b"xe");
        let mut query = [0; 40];
        put32(&mut query, 12, 256);
        put64(&mut query, 16, 4096);
        user.wire.store(64, &query);
        // Xe query requires its exact reply length, unlike GETPARAM.
        assert_eq!(
            file.dispatch_card(card, xe::DEVICE_QUERY, 64, &user),
            Some(Err(FsError::InvalidData))
        );
        put32(&mut query, 12, 0);
        user.wire.store(64, &query);
        assert_eq!(
            file.dispatch_card(card, xe::DEVICE_QUERY, 64, &user),
            Some(Ok(0))
        );
        assert_eq!(
            u32_at(&user.wire.load(64, 40), 12),
            if live { 8 + 3 * 32 } else { 8 }
        );
        assert_eq!(
            file.dispatch_card(
                card,
                crate::drm_uapi::iowr(b'd' as u32, 0x46, 24),
                64,
                &user
            ),
            Some(Err(FsError::InvalidData))
        );
    }
    // Reuse this fixture's actual ready epoch for the cache-policy negative.
    *mailbox.status.lock() = Some(UserStatus {
        epoch: gt.user_epoch().unwrap(),
        platform,
        submission_version: gt.submission_version(),
        engines: gt.engines().unwrap(),
    });
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    let mut create = [0; 56];
    put64(&mut create, 8, 4096);
    put32(&mut create, 16, 1);
    create[32] = 2;
    user.wire.store(64, &create);
    match file.dispatch_card(card, xe::GEM_CREATE, 64, &user) {
        Some(Err(FsError::NotImplemented)) => assert!(cfg!(target_arch = "aarch64")),
        result => {
            assert_eq!(result, Some(Ok(0)));
            let wc = u32_at(&user.wire.load(64, 56), 28);
            assert!(file.gem.object(wc).unwrap().is_wc());
            let writes = w.0.borrow().writes.len();
            non_wb_cache_refusal(&file, card, &user, wc);
            assert_eq!(w.0.borrow().writes.len(), writes);
            legacy_exec(&user.wire, [handles[0], wc], id);
            let mut call =
                core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Err(FsError::InvalidData)))
            );
            assert!(mailbox.pending.lock().is_empty());
            assert_eq!(file.gem.object(wc).unwrap().busy(), 0);
        }
    }
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_xe_exact_dispatch_discovery_sseu_and_wc_refusal
);

fn smoke_i915_native_vram_handle_keeps_placement_and_refuses_wb_compatibility() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (_, mut info, card) = registered(&mut gt, &w, platform);
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
    // SAFETY: this independent device model owns the entire fake LMEM BAR
    // until all pool, GEM and mapping references have been dropped below.
    let vram = unsafe { crate::intel_gpu_vram::Vram::new(bar, layout) }.unwrap();
    info.vram = Some(vram.clone());
    let file = RenderFile::new();
    let user = Cpu::new();
    let handle = create_placed(&file, &info, &user, 4096, 2, 4, 2).unwrap();
    assert!(file.gem.object(handle).unwrap().is_vram());
    assert_eq!(vram.used(), 4096);
    let writes = w.0.borrow().writes.len();
    non_wb_cache_refusal(&file, card, &user, handle);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(vram.used(), 4096);
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, &user), Some(Ok(0)))
    });
    legacy_exec(&user.wire, [handles[0], handle], 0);
    {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
    }
    drop(file);
    drop(info);
    assert_eq!(vram.used(), 0);
    drop(vram);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    narf_memory::frame::free_pages(frame, 1);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_balance",
    smoke_i915_native_vram_handle_keeps_placement_and_refuses_wb_compatibility
);
