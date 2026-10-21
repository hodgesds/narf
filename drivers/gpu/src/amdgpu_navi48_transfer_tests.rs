use super::*;
use core::sync::atomic::{AtomicU64, AtomicUsize};
use narf_kernel_test::{kernel_test_in, TestResult};

fn navi48_transfer_lost_generation_is_not_successful_completion() -> TestResult {
    let value = Arc::new(AtomicU64::new(0));
    let seen = value.clone();
    let fence = ClearFence::new(Arc::new(move || {
        let value = seen.load(Ordering::Acquire);
        (value != u64::MAX).then_some(value as u32)
    }));
    assert_eq!(completed(&fence, false), Ok(false));
    fence.seq.store(1, Ordering::Release);
    assert_eq!(completed(&fence, false), Ok(false));
    value.store(1, Ordering::Release);
    assert_eq!(completed(&fence, false), Ok(true));
    value.store(u64::MAX, Ordering::Release);
    assert_eq!(completed(&fence, false), Err(FsError::NoDevice));
    fence.seq.store(u64::MAX, Ordering::Release);
    assert_eq!(completed(&fence, false), Err(FsError::NoDevice));
    let blocked = ClearFence::new(Arc::new(|| panic!("blocked ring sampled")));
    assert_eq!(completed(&blocked, true), Ok(false));
    blocked.gone.store(true, Ordering::Release);
    assert_eq!(completed(&blocked, true), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_lost_generation_is_not_successful_completion
);

fn navi48_transfer_stale_generation_cannot_stage_or_read_progress() -> TestResult {
    let mut clearer = VramClearer::new(Arc::new(|| panic!("stale progress MMIO")));
    // Model a retained queue from an earlier owner without changing the
    // running system's generation or service interlock.
    Arc::get_mut(&mut clearer.0).unwrap().generation = (*READ_GENERATION.lock()).wrapping_sub(1);
    let writes = AtomicUsize::new(0);
    let result = clearer.with_live_progress(|| {
        writes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    });
    assert_eq!(result, Err(FsError::NoDevice));
    assert_eq!(writes.load(Ordering::Acquire), 0);
    // The final-upload check also refuses a current-generation transport
    // that disappeared after its final chunk signalled/yielded.
    let value = Arc::new(AtomicU64::new(1));
    let seen = value.clone();
    let current = VramClearer::new(Arc::new(move || {
        let value = seen.load(Ordering::Acquire);
        (value != u64::MAX).then_some(value as u32)
    }));
    assert_eq!(current.with_live_progress(|| Ok(())), Ok(()));
    value.store(u64::MAX, Ordering::Release);
    assert_eq!(
        current.with_live_progress(|| Ok(())),
        Err(FsError::NoDevice)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_stale_generation_cannot_stage_or_read_progress
);

fn navi48_transfer_stale_queue_retires_only_unsubmitted_resources() -> TestResult {
    #[derive(Debug)]
    struct Held(Arc<AtomicUsize>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let queued_drop = Arc::new(AtomicUsize::new(0));
    let inflight_drop = Arc::new(AtomicUsize::new(0));
    let request = |held: &Arc<AtomicUsize>| Clear {
        work: Work::Fill {
            address: 0x1000,
            bytes: 4096,
        },
        fence: Arc::new(ClearFence::new(Arc::new(|| Some(0)))),
        _held: Some(Arc::new(Held(held.clone()))),
    };
    let mut state = ClearState {
        draining: true,
        ..ClearState::default()
    };
    state.queued.push_back(request(&queued_drop));
    state.inflight.push_back(request(&inflight_drop));
    let queued_fence = state.queued[0].fence.clone();
    let inflight_fence = state.inflight[0].fence.clone();
    inflight_fence.seq.store(1, Ordering::Release);
    let refused = state.refuse_queued();
    assert!(state.queued.is_empty() && !state.draining);
    assert_eq!(state.inflight.len(), 1);
    assert!(queued_fence.gone.load(Ordering::Acquire));
    assert!(!inflight_fence.gone.load(Ordering::Acquire));
    assert_eq!(queued_drop.load(Ordering::Acquire), 0);
    drop(refused);
    assert_eq!(queued_drop.load(Ordering::Acquire), 1);
    assert_eq!(inflight_drop.load(Ordering::Acquire), 0);
    // Model a proven hardware reset: only now can the inflight lease go.
    state.inflight.clear();
    assert_eq!(inflight_drop.load(Ordering::Acquire), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_stale_queue_retires_only_unsubmitted_resources
);

fn navi48_transfer_quiesce_retains_inflight_until_reset_proof() -> TestResult {
    static QUARANTINE: narf_lib::sync::IrqSafeSpinLock<Option<VramClearer>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    struct Held(Arc<AtomicUsize>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let retain = || {
        let clearer = VramClearer::new(Arc::new(|| Some(0)));
        clearer.0.state.lock().inflight.push_back(Clear {
            work: Work::Fill {
                address: 0x1000,
                bytes: 4096,
            },
            fence: Arc::new(ClearFence::new(Arc::new(|| Some(0)))),
            _held: Some(Arc::new(Held(dropped.clone()))),
        });
        ResetClearer {
            clearer: Some(clearer),
            quarantine: |clearer| *QUARANTINE.lock() = Some(clearer),
        }
    };
    // Dropping a partially completed quiesce/reset must transfer its
    // inflight resources to quarantine, even when no registry retains it.
    drop(retain());
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    let mut saved = ResetClearer {
        clearer: QUARANTINE.lock().take(),
        quarantine: |_| panic!("proven queue quarantined twice"),
    };
    let stale = saved.clearer.as_ref().unwrap().clone();
    let skipped = stale.0.state.lock().inflight[0].fence.clone();
    // SAFETY: this model never submitted hardware work; represent the
    // successful full-reset proof before allowing the retained lease go.
    unsafe { saved.stopped() };
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    assert!(stale.0.state.lock().inflight.is_empty());
    assert!(skipped.gone.load(Ordering::Acquire));
    let mut successful = retain();
    // SAFETY: as above, a proven modeled reset.
    unsafe { successful.stopped() };
    drop(successful);
    assert!(QUARANTINE.lock().is_none());
    assert_eq!(dropped.load(Ordering::Acquire), 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_quiesce_retains_inflight_until_reset_proof
);

fn navi48_transfer_queued_copy_retains_stage_until_proven_retirement() -> TestResult {
    use crate::amdgpu_gem::GemState;
    use crate::amdgpu_uapi as u;
    let mut memory = alloc::vec![0u8; 4096];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb800_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: test RAM lives beyond every pool, stage and queued request.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    let mut window = pool.reserve(4096).unwrap();
    window.publish();
    let stage = Arc::new(Stage {
        address: window.address(),
        virt: map.virt as usize,
        len: 4096,
        _window: window,
        access: Mutex::new(()),
        last: narf_lib::sync::IrqSafeSpinLock::new(None),
    });
    let observed = Arc::downgrade(&stage);
    let clearer = VramClearer::new(Arc::new(|| Some(0)));
    // Drive the queue explicitly, without spawning hardware work.
    clearer.0.state.lock().draining = true;
    let mover = Mover {
        clearer: clearer.clone(),
        stage,
    };
    let gem = GemState::new();
    let mut args = [0u8; 32];
    args[0..8].copy_from_slice(&4096u64.to_le_bytes());
    args[16..24].copy_from_slice(&u64::from(u::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    let create = 0xc000_0000 | (0x64 << 8) | (0x40 + u::DRM_AMDGPU_GEM_CREATE);
    crate::amdgpu_gem::dispatch(create, args.as_mut_ptr() as usize, &gem).unwrap();
    let object = gem
        .object(u32::from_le_bytes(args[0..4].try_into().unwrap()))
        .unwrap();
    let done = mover
        .queue(
            &object,
            Work::Copy {
                src: mover.stage.address,
                dst: mover.stage.address + 8192,
                bytes: 4096,
                flags: 0,
                upload: None,
            },
            object.clone(),
        )
        .unwrap();
    drop(mover);
    assert!(observed.upgrade().is_some());
    assert_eq!(pool.retired(), 0);
    assert_eq!(pool.available(), 0);
    {
        let mut state = clearer.0.state.lock();
        let request = state.queued.pop_front().unwrap();
        request.fence.seq.store(1, Ordering::Release);
        state.inflight.push_back(request);
    }
    clearer.refuse_queued();
    assert!(observed.upgrade().is_some());
    assert!(!done.gone.load(Ordering::Acquire));
    assert_eq!(pool.retired(), 0);
    // No hardware exists in this model. Represent its proven reset before
    // disposing the inflight owner, then reclaim the published reservation.
    clearer.0.state.lock().inflight.clear();
    assert!(observed.upgrade().is_none());
    assert_eq!(pool.retired(), 4096);
    assert_eq!(pool.available(), 0);
    // SAFETY: the modeled request never reached hardware and has no owner.
    assert_eq!(unsafe { pool.reclaim_retired() }, 4096);
    assert_eq!(pool.available(), 4096);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_queued_copy_retains_stage_until_proven_retirement
);

fn navi48_reset_admission_wakes_terminal_waiters_and_retains_unknown_owner() -> TestResult {
    use alloc::task::Wake;
    use core::future::Future;
    use core::task::{Context, Waker};
    const CARD: u32 = 0xfeed_0401;
    static QUARANTINE: narf_lib::sync::IrqSafeSpinLock<Option<crate::amdgpu_gem::PlacementGuard>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let raw = narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement(CARD));
    let reset = ResetPlacement {
        guard: Some(raw),
        release_safe: false,
        restarted: false,
        quarantine: |guard| *QUARANTINE.lock() = Some(guard),
    };
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker: Waker = wakes.clone().into();
    let mut cx = Context::from_waker(&waker);
    let mut client = alloc::boxed::Box::pin(crate::amdgpu_gem::lock_placement_live(CARD));
    assert!(client.as_mut().poll(&mut cx).is_pending());
    // Cancellation/failure before hardware-stop proof preserves exclusion
    // while waking every client with a terminal errno.
    drop(reset);
    assert!(wakes.0.load(Ordering::Acquire) != 0);
    assert!(matches!(
        client.as_mut().poll(&mut cx),
        core::task::Poll::Ready(Err(FsError::NoDevice))
    ));
    assert!(crate::amdgpu_gem::try_placement(CARD).is_none());
    assert!(matches!(
        narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement_live(CARD)),
        Err(FsError::NoDevice)
    ));
    // This model never touched hardware: dispose the quarantined test
    // guard only after representing the missing stop proof.
    drop(QUARANTINE.lock().take());
    assert!(crate::amdgpu_gem::try_placement(CARD).is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_reset_admission_wakes_terminal_waiters_and_retains_unknown_owner
);

fn navi48_reset_proof_allows_release_but_failed_restart_stays_terminal() -> TestResult {
    const FAILED: u32 = 0xfeed_0402;
    const READY: u32 = 0xfeed_0403;
    let mut failed = ResetPlacement {
        guard: Some(narf_scheduler::block_on_spin(
            crate::amdgpu_gem::lock_placement(FAILED),
        )),
        release_safe: false,
        restarted: false,
        quarantine: |_| panic!("proven stop quarantined its mutex"),
    };
    // SAFETY: no hardware exists here; represent a completed full reset.
    unsafe { failed.stopped() };
    // A later new-owner failure may release the stopped old allocation
    // gate, but must keep clients terminal rather than resume admission.
    drop(failed);
    assert!(crate::amdgpu_gem::try_placement(FAILED).is_some());
    assert!(matches!(
        narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement_live(FAILED)),
        Err(FsError::NoDevice)
    ));
    let mut ready = ResetPlacement {
        guard: Some(narf_scheduler::block_on_spin(
            crate::amdgpu_gem::lock_placement(READY),
        )),
        release_safe: false,
        restarted: false,
        quarantine: |_| panic!("successful restart quarantined its mutex"),
    };
    // SAFETY: the same modeled full reset succeeded.
    unsafe { ready.stopped() };
    assert!(crate::amdgpu_gem::try_placement(READY).is_none());
    ready.restarted = true;
    drop(ready);
    assert!(narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement_live(READY)).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_reset_proof_allows_release_but_failed_restart_stays_terminal
);

fn navi48_lost_upload_keeps_actual_placement_and_gpu_ptes() -> TestResult {
    use crate::amdgpu_gem::{GemObject, GemPlacement, GemState, VramHeap, VramTransfer};
    use crate::amdgpu_uapi as u;
    use core::future::Future;
    use core::pin::Pin;
    const CARD: u32 = 0xfeed_0404;
    #[derive(Debug, Default)]
    struct Lost {
        calls: AtomicUsize,
        progress: Arc<AtomicU64>,
    }
    impl VramTransfer for Lost {
        fn read<'a>(
            &'a self,
            _: Arc<GemObject>,
            _: Arc<GemPlacement>,
            _: &'a mut GemPlacement,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async { Err(FsError::Unsupported) })
        }
        fn write<'a>(
            &'a self,
            _: Arc<GemObject>,
            _: Arc<GemPlacement>,
            _: Arc<GemPlacement>,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                self.calls.fetch_add(1, Ordering::AcqRel);
                self.progress.store(u64::MAX, Ordering::Release);
                // Model a submitted upload skipped by whole-device reset.
                // Exercise the production fence decision inside a real
                // relocation, before it may change placement or PTEs.
                let seen = self.progress.clone();
                let fence = ClearFence::new(Arc::new(move || {
                    let value = seen.load(Ordering::Acquire);
                    (value != u64::MAX).then_some(value as u32)
                }));
                fence.seq.store(1, Ordering::Release);
                let verdict = completed(&fence, false);
                // A later hardware sample can become readable without
                // proving the failed transfer completed.
                self.progress.store(0, Ordering::Release);
                verdict?;
                Ok(())
            })
        }
    }
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            crate::amdgpu_gem::unregister_vram_heap(CARD);
            crate::amdgpu_gem::register_vram_transfer(CARD, None);
            crate::amdgpu_gem::set_gfx12_dcc(CARD, None);
            crate::amdgpu_cs::retire(CARD, &|_| true);
            crate::amdgpu_cs::unregister_submitter(CARD);
        }
    }
    let mut memory = alloc::vec![0u8; 65536];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb900_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: private test RAM remains allocated until all heaps/BOs drop.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    let _registered = Registered;
    crate::amdgpu_gem::set_gfx12_dcc(CARD, Some(65536));
    let gem = GemState::for_card(CARD);
    let mut args = [0u64; 4];
    args[0] = 4096;
    args[2] = u64::from(u::AMDGPU_GEM_DOMAIN_VRAM | u::AMDGPU_GEM_DOMAIN_GTT);
    args[3] = u64::from(u::AMDGPU_GEM_CREATE_GFX12_DCC);
    let create = 0xc000_0000 | (0x64 << 8) | (0x40 + u::DRM_AMDGPU_GEM_CREATE);
    crate::amdgpu_gem::dispatch(create, args.as_mut_ptr() as usize, &gem).unwrap();
    let handle = args[0] as u32;
    let object = gem.object(handle).unwrap();
    assert!(object.system()); // no heap existed at CREATE
    let before = Arc::as_ptr(&object.placement()) as usize;
    crate::amdgpu_gem::register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base: 0x8_0000_0000,
            fb_offset: 0x9_0000_0000,
            unmapped: None,
        },
    );
    let engine = Arc::new(Lost::default());
    crate::amdgpu_gem::register_vram_transfer(CARD, Some(engine.clone()));
    let vm = crate::amdgpu_vm::VmState::for_card(CARD);
    let mut va = [0u8; 40];
    va[0..4].copy_from_slice(&handle.to_le_bytes());
    va[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
    va[12..16].copy_from_slice(&u::AMDGPU_VM_PAGE_READABLE.to_le_bytes());
    va[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    va[32..40].copy_from_slice(&4096u64.to_le_bytes());
    crate::amdgpu_vm::dispatch(
        crate::drm_uapi::DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA,
        va.as_ptr() as usize,
        &vm,
        &gem,
    )
    .unwrap();
    let pte = vm.leaf_entry(0x2_0000_0000);
    let tables = vm.table_count();
    let moved = narf_scheduler::block_on_spin(async {
        let gate = crate::amdgpu_gem::lock_placement_live(CARD).await?;
        crate::amdgpu_vm::relocate(&gate, &object, true).await
    });
    assert_eq!(moved, Err(FsError::NoDevice));
    assert_eq!(engine.calls.load(Ordering::Acquire), 1);
    assert!(object.system());
    assert_eq!(Arc::as_ptr(&object.placement()) as usize, before);
    assert_eq!(vm.leaf_entry(0x2_0000_0000), pte);
    assert_eq!(vm.table_count(), tables);
    assert_eq!(pool.available(), 65536);
    // Repeat through the actual native Mover, retaining its real published
    // stage while its old-generation progress reader refuses admission.
    let mut stage_memory = alloc::vec![0u8; 4096];
    let stage_map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xba00_0000),
        virt: stage_memory.as_mut_ptr() as u64,
        len: stage_memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: all stage owners drop before this private test RAM.
    let stage_pool =
        unsafe { crate::amdgpu_vram::Pool::from_owned_range(stage_map, 0xa_0000_0000) }.unwrap();
    let native = mover(
        VramClearer::new(Arc::new(|| None)),
        stage_pool.reserve(4096).unwrap(),
    );
    let _stage_registered = Registered;
    crate::amdgpu_gem::register_vram_transfer(CARD, Some(native.clone()));
    let moved = narf_scheduler::block_on_spin(async {
        let gate = crate::amdgpu_gem::lock_placement_live(CARD).await?;
        crate::amdgpu_vm::relocate(&gate, &object, true).await
    });
    assert_eq!(moved, Err(FsError::NoDevice));
    assert!(object.system());
    assert_eq!(Arc::as_ptr(&object.placement()) as usize, before);
    assert_eq!(vm.leaf_entry(0x2_0000_0000), pte);
    assert_eq!(vm.table_count(), tables);
    assert_eq!(pool.available(), 65536);
    crate::amdgpu_gem::register_vram_transfer(CARD, None);
    drop(native);
    assert_eq!(stage_pool.retired(), 4096);

    // Exercise actual CS parsing, validation and promotion: a later
    // readable sample must not turn the relocation's NoDevice into fallback.
    struct Submitted {
        count: AtomicUsize,
        lost: Arc<Lost>,
    }
    impl crate::amdgpu_cs::Submitter for Submitted {
        fn submit<'a>(
            &'a self,
            _: &'a crate::amdgpu_vm::VmState,
            _: &'a crate::amdgpu_cs::Submission,
            _: &'a Arc<crate::amdgpu_ctx::Health>,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                assert_ne!(self.lost.progress.load(Ordering::Acquire), u64::MAX);
                self.count.fetch_add(1, Ordering::AcqRel);
                Ok(1)
            })
        }
        fn signalled(&self, _: u64) -> bool {
            true
        }
        fn ring_for(&self, ip: u32, _: u32, _: u32) -> Option<u32> {
            (ip == u::AMDGPU_HW_IP_GFX).then_some(0)
        }
        fn wait(
            &self,
            _: u64,
            _: u64,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>>
        {
            alloc::boxed::Box::pin(async { Ok(true) })
        }
    }
    let submitted = Arc::new(Submitted {
        count: AtomicUsize::new(0),
        lost: engine.clone(),
    });
    crate::amdgpu_cs::register_submitter(CARD, submitted.clone());
    crate::amdgpu_gem::register_vram_transfer(CARD, Some(engine.clone()));
    let contexts = crate::amdgpu_ctx::CtxState::new();
    let mut context = [u::AMDGPU_CTX_OP_ALLOC_CTX, 0, 0, 0];
    crate::amdgpu_ctx::dispatch(
        create - u::DRM_AMDGPU_GEM_CREATE + u::DRM_AMDGPU_CTX,
        context.as_mut_ptr() as usize,
        &contexts,
        false,
    )
    .unwrap();
    let syncobjs = narf_lib::sync::IrqSafeSpinLock::new(crate::drm::syncobj::SyncObjTable::new());
    let bo_lists = crate::amdgpu_bo_list::BoListTable::new();
    let open = crate::amdgpu_cs::CsOpen {
        vm: &vm,
        gem: &gem,
        ctx: &contexts,
        syncobjs: &syncobjs,
        bo_lists: &bo_lists,
        files: None,
    };
    let mut entries = [handle, 0u32];
    let pointer = entries.as_ptr() as u64;
    let listed = [0, 0, 1, 8, pointer as u32, (pointer >> 32) as u32];
    let mut ib = [0u8; 32];
    ib[8..16].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    ib[16..20].copy_from_slice(&64u32.to_le_bytes());
    let mut chunks = [[0u64; 2]; 2];
    chunks[0] = [
        u64::from(u::AMDGPU_CHUNK_ID_IB) | 8 << 32,
        ib.as_ptr() as u64,
    ];
    chunks[1] = [
        u64::from(u::AMDGPU_CHUNK_ID_BO_HANDLES) | 6 << 32,
        listed.as_ptr() as u64,
    ];
    let pointers = [chunks[0].as_ptr() as u64, chunks[1].as_ptr() as u64];
    let mut cs = [u64::from(context[0]), 2, pointers.as_ptr() as u64];
    let cmd = create - u::DRM_AMDGPU_GEM_CREATE + u::DRM_AMDGPU_CS;
    let result = narf_scheduler::block_on_spin(crate::amdgpu_cs::dispatch_async(
        CARD,
        cmd,
        cs.as_mut_ptr() as usize,
        &open,
    ));
    assert_eq!(result, Err(FsError::NoDevice));
    assert_eq!(engine.calls.load(Ordering::Acquire), 2);
    assert_eq!(engine.progress.load(Ordering::Acquire), 0);
    assert_eq!(submitted.count.load(Ordering::Acquire), 0);
    assert!(object.system());
    assert_eq!(vm.leaf_entry(0x2_0000_0000), pte);

    // An already-VRAM BO bypasses promotion. Its generic initial-clear
    // fence must still block CS on None, then on readable/incomplete0.
    let mut plain = [4096u64, 0, u64::from(u::AMDGPU_GEM_DOMAIN_VRAM), 0];
    crate::amdgpu_gem::dispatch(create, plain.as_mut_ptr() as usize, &gem).unwrap();
    let plain_handle = plain[0] as u32;
    let plain = gem.object(plain_handle).unwrap();
    assert!(!plain.system());
    entries[0] = plain_handle;
    let initial = Arc::new(AtomicU64::new(u64::MAX));
    let seen = initial.clone();
    let fence = Arc::new(ClearFence::new(Arc::new(move || {
        let value = seen.load(Ordering::Acquire);
        (value != u64::MAX).then_some(value as u32)
    })));
    fence.seq.store(1, Ordering::Release);
    plain
        .dma_buf()
        .resv
        .add_fence(fence.clone(), DmaResvUsage::Kernel);
    {
        use core::task::{Context, Waker};
        let mut future = alloc::boxed::Box::pin(crate::amdgpu_cs::dispatch_async(
            CARD,
            cmd,
            cs.as_mut_ptr() as usize,
            &open,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(submitted.count.load(Ordering::Acquire), 0);
    }
    use narf_filesystem::DrmFence;
    initial.store(0, Ordering::Release);
    assert!(!fence.is_signalled());
    initial.store(1, Ordering::Release);
    assert!(fence.is_signalled());
    let result = narf_scheduler::block_on_spin(crate::amdgpu_cs::dispatch_async(
        CARD,
        cmd,
        cs.as_mut_ptr() as usize,
        &open,
    ));
    assert_eq!(result, Ok(0));
    assert_eq!(submitted.count.load(Ordering::Acquire), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_lost_upload_keeps_actual_placement_and_gpu_ptes
);

fn navi48_transfer_final_completion_releases_queue_source_before_commit() -> TestResult {
    use crate::amdgpu_gem::{GemState, VramHeap};
    use crate::amdgpu_uapi as u;
    use core::future::Future;
    const CARD: u32 = 0xfeed_0406;
    let mut memory = alloc::vec![0u8; 65536];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xbb00_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: all placement/pool leases drop before this private test RAM.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0xc_0000_0000) }.unwrap();
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            crate::amdgpu_gem::unregister_vram_heap(CARD);
            crate::amdgpu_gem::set_gfx12_dcc(CARD, None);
        }
    }
    let _registered = Registered;
    crate::amdgpu_gem::set_gfx12_dcc(CARD, Some(65536));
    let gem = GemState::for_card(CARD);
    let mut args = [
        4096u64,
        0,
        u64::from(u::AMDGPU_GEM_DOMAIN_VRAM | u::AMDGPU_GEM_DOMAIN_GTT),
        u64::from(u::AMDGPU_GEM_CREATE_GFX12_DCC),
    ];
    let cmd = 0xc000_0000 | (0x64 << 8) | (0x40 + u::DRM_AMDGPU_GEM_CREATE);
    crate::amdgpu_gem::dispatch(cmd, args.as_mut_ptr() as usize, &gem).unwrap();
    let object = gem.object(args[0] as u32).unwrap();
    let source = object.placement();
    crate::amdgpu_gem::register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base: 0xc_0000_0000,
            fb_offset: 0xc_0000_0000,
            unmapped: None,
        },
    );
    let destination = Arc::new(crate::amdgpu_gem::cpu_mapping::destination(&object, true).unwrap());
    let progress = Arc::new(AtomicU64::new(0));
    let seen = progress.clone();
    let clearer = VramClearer::new(Arc::new(move || Some(seen.load(Ordering::Acquire) as u32)));
    let fence = Arc::new(ClearFence::new(clearer.0.progress.clone()));
    fence.seq.store(1, Ordering::Release);
    object
        .dma_buf()
        .resv
        .add_fence(fence.clone(), DmaResvUsage::Kernel);
    clearer.0.state.lock().inflight.push_back(Clear {
        work: Work::Copy {
            src: 0xd_0000_0000,
            dst: destination.vram_address().unwrap(),
            bytes: 4096,
            flags: 0,
            upload: None,
        },
        fence: fence.clone(),
        _held: Some(Arc::new((
            object.clone(),
            source.clone(),
            destination.clone(),
        ))),
    });
    assert_eq!(Arc::strong_count(&source), 3);
    assert_eq!(
        object.commit_transfer(&source, destination.clone()),
        Err(FsError::Busy)
    );
    {
        use core::task::{Context, Waker};
        let mut waiter = alloc::boxed::Box::pin(await_done(&clearer, &fence));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        // Cancel the mover's completion waiter after hardware submission.
    }
    assert_eq!(Arc::strong_count(&source), 3);
    progress.store(1, Ordering::Release);
    assert_eq!(completed(&fence, false), Ok(true));
    // Run the queue collector's exact retirement step independently of
    // that cancelled waiter and without submitting any unrelated work.
    let _placement =
        narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement_live(CARD)).unwrap();
    {
        let _owner = narf_scheduler::block_on_spin(OWNER.lock());
        clearer.retire_completed(clearer.live_progress().unwrap());
    }
    assert!(clearer.0.state.lock().inflight.is_empty());
    assert_eq!(Arc::strong_count(&source), 2);
    assert_eq!(object.commit_transfer(&source, destination.clone()), Ok(()));
    assert!(!object.system());
    assert!(Arc::ptr_eq(&object.placement(), &destination));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    navi48_transfer_final_completion_releases_queue_source_before_commit
);
