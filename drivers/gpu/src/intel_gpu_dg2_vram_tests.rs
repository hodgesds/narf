// Actual Xe GEM_CREATE -> trusted BCS0 CCS copy -> hardware retirement ->
// handle publication. The independent sideband model starts metadata dirty.
use super::*;
use crate::intel_gpu_exec::vram_clear::{fixture_finish, fixture_seed, fixture_state};
use crate::intel_gpu_gem::GemObject;
use crate::intel_gpu_vram::{Dg2VramRegisters, Vram, VramLayout};
use core::sync::atomic::Ordering;

struct ClearPending {
    object: Arc<GemObject>,
    epoch: u64,
    reply: Arc<Reply>,
}
struct ClearBackend {
    ordinary: Arc<Mailbox>,
    facts: crate::intel_gpu_user::DeviceFacts,
    pool: Arc<Vram>,
    clears: IrqSafeSpinLock<Vec<ClearPending>>,
}
impl core::fmt::Debug for ClearBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClearBackend").finish_non_exhaustive()
    }
}
impl UserBackend for ClearBackend {
    fn status(&self) -> Option<UserStatus> {
        self.ordinary.status()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        Some(self.facts)
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.ordinary.submit(context, batch)
    }
    fn clear_vram(&self, object: Arc<GemObject>, epoch: u64) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            if !object.in_vram_pool(&self.pool) || self.status().is_none_or(|s| s.epoch != epoch) {
                return Err(FsError::NoDevice);
            }
            let reply = Arc::new(Reply {
                result: IrqSafeSpinLock::new(None),
                waker: IrqSafeSpinLock::new(None),
            });
            self.clears.lock().push(ClearPending {
                object,
                epoch,
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
impl ClearBackend {
    fn accept(
        &self,
        gt: &mut GuCGt<Window, Arena>,
        now: u64,
    ) -> (Arc<CompletionFence>, alloc::sync::Weak<GemObject>) {
        let request = self.clears.lock().pop().expect("private clear request");
        let weak = Arc::downgrade(&request.object);
        assert!(request.object.in_vram_pool(&self.pool));
        let fence = gt.clear_vram(now, request.object, request.epoch).unwrap();
        *request.reply.result.lock() = Some(Ok(fence.clone()));
        if let Some(waker) = request.reply.waker.lock().take() {
            waker.wake();
        }
        (fence, weak)
    }
}
struct Rig {
    w: Window,
    arena: Arena,
    gt: GuCGt<Window, Arena>,
    frame: narf_memory::frame::PhysFrame,
    pool: Arc<Vram>,
    backend: Arc<ClearBackend>,
    info: DeviceInfo,
}
impl Rig {
    fn new() -> Self {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        prime(&mut gt, &w, 0x130044);
        let (ordinary, mut info) = setup(&mut gt, &w, GtPlatform::Alchemist);
        let frame = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
        let bar = narf_bus::MmioRegion {
            phys: frame.start_address(),
            virt: frame.start_address().kernel_ptr::<u8>() as u64,
            len: 4 * 65536,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: the model's contiguous RAM frames are exclusively owned as
        // its fake WC LMEM BAR until end(), after every object/job is gone.
        unsafe {
            core::ptr::write_bytes(bar.virt as *mut u8, 0xa5, bar.len as usize);
        }
        let layout = VramLayout {
            tile_size: bar.len,
            tile_offset: 0,
            usable: bar.len,
        };
        // SAFETY: same exclusive fixture aperture, no inherited framebuffer.
        let pool = unsafe { Vram::new_dg2(bar, layout) }.unwrap();
        FIXTURE_VRAM.store(bar.phys.raw(), Ordering::Relaxed);
        fixture_seed(0, bar.len, bar.virt);
        let backend = Arc::new(ClearBackend {
            ordinary,
            facts: gt.device_facts().unwrap(),
            pool: pool.clone(),
            clears: IrqSafeSpinLock::new(Vec::new()),
        });
        info.backend = Some(backend.clone());
        info.vram = Some(pool.clone());
        Self {
            w,
            arena,
            gt,
            frame,
            pool,
            backend,
            info,
        }
    }
    fn finish(&mut self, fence: &CompletionFence, now: u64) {
        finish_policy(&mut self.gt, &self.w, fence, &mut BTreeMap::new(), now, 3);
    }
    fn end(mut self) {
        if self.gt.state() != GtState::Stopped {
            hardware_stop(&mut self.gt, &self.w, 0x130044);
        }
        drop(self.gt);
        assert_eq!(self.arena.live_allocations(), 0);
        assert_eq!(self.pool.used(), 0);
        drop(self.info);
        drop(self.backend);
        drop(self.pool);
        fixture_finish();
        FIXTURE_VRAM.store(0, Ordering::Relaxed);
        narf_memory::frame::free_pages(self.frame, 6);
    }
}
fn request(user: &Cpu, size: u64, placement: u32, vm: u32) {
    let mut wire = [0; 56];
    put64(&mut wire, 8, size);
    put32(&mut wire, 16, placement);
    put32(&mut wire, 20, if placement & 2 != 0 { 4 } else { 0 });
    put32(&mut wire, 24, vm);
    wire[32] = 2;
    user.wire.store(64, &wire);
}

fn smoke_dg2_vram_create_requires_actual_ccs_clear_before_handle_and_reuse() -> TestResult {
    let mut rig = Rig::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    let regions = xe_query(&file, &rig.info, &user, 1);
    assert_eq!(u32_at(&regions, 100), 65536);
    for iteration in 0..2 {
        fixture_seed(
            0,
            rig.pool.visible(),
            rig.frame.start_address().kernel_ptr::<u8>() as u64,
        );
        request(&user, 65536, 2, 0);
        let info = rig.info.clone();
        let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(u32_at(&user.wire.load(64, 56), 28), 0);
        assert!(fixture_state().0.iter().all(|b| *b == 0xa5));
        let (fence, weak) = rig.backend.accept(&mut rig.gt, 100 + iteration * 100);
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(rig.pool.used(), 65536);
        rig.finish(&fence, 101 + iteration * 100);
        assert_eq!(ready(call.as_mut()), Some(Ok(0)));
        drop(call);
        drop(info);
        let handle = u32_at(&user.wire.load(64, 56), 28);
        let object = file.gem.object(handle).unwrap();
        assert_eq!(object.pages().next(), Some(0));
        assert_eq!(object.vram_page_size(), 65536);
        let (metadata, clears) = fixture_state();
        assert_eq!(clears.len(), 1);
        assert_eq!(clears[0], 0..65536);
        assert!(metadata[..256].iter().all(|b| *b == 0));
        assert!(metadata[256..].iter().all(|b| *b == 0xa5));
        let mut data = [0xff; 65536];
        object.read(0, &mut data).unwrap();
        assert!(data.iter().all(|b| *b == 0));
        let view = object.backing(0, 65536).unwrap();
        assert_eq!(view.memory_type, narf_memory::MemoryType::WriteCombining);
        assert_eq!(view.frames.len(), 16);
        drop(view);
        assert!(rig
            .gt
            .clear_vram(
                180 + iteration * 100,
                object.clone(),
                rig.gt.user_epoch().unwrap()
            )
            .is_err());
        assert_eq!(
            file.gem.export_object(handle).err(),
            Some(FsError::NotImplemented)
        );
        object.write(0, &[0xa5; 16]).unwrap();
        drop(object);
        assert_eq!(
            close(&file, &rig.info, &user, abi::GEM_CLOSE, handle),
            Ok(0)
        );
        assert!(weak.upgrade().is_none());
        assert_eq!(rig.pool.used(), 0);
    }
    drop(file);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_create_requires_actual_ccs_clear_before_handle_and_reuse
);

fn smoke_dg2_vram_cancelled_create_retains_dma_until_clear_retirement() -> TestResult {
    let mut rig = Rig::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    request(&user, 65536, 2, 0);
    let mut call = Box::pin(file.dispatch_user(&rig.info, xe::GEM_CREATE, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (fence, weak) = rig.backend.accept(&mut rig.gt, 100);
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    drop(call);
    drop(file);
    assert!(weak.upgrade().is_some());
    assert_eq!(rig.pool.used(), 65536);
    rig.finish(&fence, 101);
    assert!(weak.upgrade().is_none());
    assert_eq!(rig.pool.used(), 0);
    assert_eq!(u32_at(&user.wire.load(64, 56), 28), 0);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_cancelled_create_retains_dma_until_clear_retirement
);

fn smoke_dg2_vram_reset_copyout_epoch_and_vm_loss_never_publish() -> TestResult {
    for failure in 0..4 {
        let mut rig = Rig::new();
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = if failure == 3 {
            create_vm(&file, &rig.info, &user)
        } else {
            0
        };
        request(&user, 65536, 2, vm);
        let info = rig.info.clone();
        let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (fence, weak) = rig.backend.accept(&mut rig.gt, 100);
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        if failure == 0 {
            hardware_stop(&mut rig.gt, &rig.w, 0x130044);
        } else {
            rig.finish(&fence, 101);
        }
        match failure {
            1 => user.fail_report.store(true, Ordering::Relaxed),
            2 => *rig.backend.ordinary.status.lock() = None,
            3 => {
                assert_eq!(close(&file, &rig.info, &user, xe::VM_DESTROY, vm), Ok(0));
            }
            _ => {}
        }
        assert!(matches!(ready(call.as_mut()), Some(Err(_))));
        drop(call);
        drop(info);
        assert!(file.gem.object(0x40000000).is_err());
        assert!(weak.upgrade().is_none());
        assert_eq!(rig.pool.used(), 0);
        drop(file);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_reset_copyout_epoch_and_vm_loss_never_publish
);

fn smoke_dg2_vram_alignment_flags_and_exhaustion_fallback() -> TestResult {
    let mut rig = Rig::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    for (size, placement, flags, cache) in [
        (4096u64, 2u32, 0u32, 2u16),
        (65536, 2, 8, 2),
        (65536, 2, 0, 1),
        (65536, 1, 4, 2),
        (65536, 4, 0, 2),
    ] {
        request(&user, size, placement, 0);
        user.wire.store(84, &flags.to_le_bytes());
        user.wire.store(96, &cache.to_le_bytes());
        let mut call = Box::pin(file.dispatch_user(&rig.info, xe::GEM_CREATE, 64, &user));
        assert_eq!(ready(call.as_mut()), Some(Err(FsError::InvalidData)));
        assert!(rig.backend.clears.lock().is_empty());
        assert_eq!(rig.pool.used(), 0);
    }
    request(&user, rig.pool.visible(), 2, 0);
    let info = rig.info.clone();
    let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (fence, _) = rig.backend.accept(&mut rig.gt, 100);
    rig.finish(&fence, 101);
    assert_eq!(ready(call.as_mut()), Some(Ok(0)));
    drop(call);
    drop(info);
    let first = u32_at(&user.wire.load(64, 56), 28);
    for placement in [2, 3] {
        request(&user, 65536, placement, 0);
        let mut call = Box::pin(file.dispatch_user(&rig.info, xe::GEM_CREATE, 64, &user));
        let result = ready(call.as_mut());
        drop(call);
        if placement == 2 {
            assert_eq!(result, Some(Err(FsError::OutOfMemory)));
        } else {
            assert_eq!(result, Some(Ok(0)));
            let handle = u32_at(&user.wire.load(64, 56), 28);
            assert!(!file.gem.object(handle).unwrap().is_vram());
            assert_eq!(
                close(&file, &rig.info, &user, abi::GEM_CLOSE, handle),
                Ok(0)
            );
        }
    }
    assert_eq!(close(&file, &rig.info, &user, abi::GEM_CLOSE, first), Ok(0));
    drop(file);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_alignment_flags_and_exhaustion_fallback
);

fn smoke_dg2_vram_64k_vm_bind_cpu_alias_and_real_copy_execution() -> TestResult {
    let mut rig = Rig::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    request(&user, 65536, 2, 0);
    let info = rig.info.clone();
    let mut create = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
    assert!(create
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (fence, _) = rig.backend.accept(&mut rig.gt, 100);
    rig.finish(&fence, 101);
    assert_eq!(ready(create.as_mut()), Some(Ok(0)));
    drop(create);
    drop(info);
    let handle = u32_at(&user.wire.load(64, 56), 28);
    let vm = create_vm(&file, &rig.info, &user);
    let queue = create_queue(&file, &rig.info, &user, vm, 1);
    let _system = buffers(&file, &rig.info, &user, vm);
    for (va, offset, size) in [
        (0x2345_0000_1000, 0, 65536),
        (0x2345_0000_0000, 4096, 65536),
        (0x2345_0000_0000, 0, 4096),
    ] {
        bind_wire(&user, vm, &[mapping(handle, va, offset, size, 0, 0)], &[]);
        assert_eq!(bind_now(&file, &rig.info, &user), Err(FsError::InvalidData));
    }
    bind_wire(
        &user,
        vm,
        &[mapping(handle, 0x2345_0000_0000, 0, 65536, 0, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &rig.info, &user), Ok(0));
    let mut partial = mapping(0, 0x2345_0000_1000, 0, 4096, 0, 0);
    put32(&mut partial, 40, 1);
    bind_wire(&user, vm, &[partial], &[]);
    assert_eq!(bind_now(&file, &rig.info, &user), Err(FsError::InvalidData));
    exec_wire(&user, queue, true, &[]);
    let mut exec = Box::pin(file.dispatch_user(&rig.info, xe::EXEC, 64, &user));
    assert!(exec
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (_, fence) = rig.backend.ordinary.accept(&mut rig.gt, 200);
    assert_eq!(ready(exec.as_mut()), Some(Ok(0)));
    drop(exec);
    finish(&mut rig.gt, &rig.w, &fence, &mut BTreeMap::new(), 201);
    let object = file.gem.object(handle).unwrap();
    let mut stored = [0; 4];
    object.read(0x80, &mut stored).unwrap();
    assert_eq!(u32_at(&stored, 0), 0x4e415246);
    let clears = fixture_state().1;
    assert_eq!(clears.len(), 1);
    assert_eq!(clears[0], 0..65536);
    assert_eq!(
        close(&file, &rig.info, &user, abi::GEM_CLOSE, handle),
        Ok(0)
    );
    assert_eq!(
        rig.pool.used(),
        65536,
        "VM and CPU owners retain allocation"
    );
    drop(object);
    assert_eq!(
        close(&file, &rig.info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &rig.info, &user, xe::VM_DESTROY, vm), Ok(0));
    user.mapping.lock().take();
    drop(file);
    assert_eq!(rig.pool.used(), 0);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_64k_vm_bind_cpu_alias_and_real_copy_execution
);

fn smoke_dg2_vram_layout_ps64_zero_dpa_and_partial_group_corruption() -> TestResult {
    let tile = 8u64 << 30;
    let gsm = tile - (64 << 20);
    let ccs = gsm - tile / 256;
    let words = Dg2VramRegisters {
        tile_range: 8 << 8,
        ccs_base: ((ccs / 65536) << 8) as u32,
        gsm_base: gsm,
    };
    let layout = VramLayout::dg2(words).unwrap();
    assert_eq!(
        (layout.tile_size, layout.tile_offset, layout.usable),
        (tile, 0, ccs)
    );
    for bad in [
        Dg2VramRegisters {
            ccs_base: 0,
            ..words
        },
        Dg2VramRegisters {
            ccs_base: u32::MAX,
            ..words
        },
        Dg2VramRegisters {
            tile_range: words.tile_range | 2,
            ..words
        },
        Dg2VramRegisters {
            gsm_base: ccs,
            ..words
        },
        Dg2VramRegisters {
            gsm_base: tile + 65536,
            ..words
        },
    ] {
        assert!(VramLayout::dg2(bad).is_err());
    }
    use crate::intel_gpu_ppgtt::{FramePtMemory, Ppgtt, PpgttError, PtMemory, WalkOutcome};
    let mut memory = FramePtMemory::new();
    let mut tables =
        Ppgtt::with_table_pat(&mut memory, crate::intel_gpu_gtt::PteFormat::Gen12, 0).unwrap();
    assert_eq!(
        tables.map_device_64k_with_pat(&mut memory, 0x11000, 0, 0, true),
        Err(PpgttError::Unaligned)
    );
    assert_eq!(
        tables.map_device_64k_with_pat(&mut memory, 0x10000, 4096, 0, true),
        Err(PpgttError::Unaligned)
    );
    tables
        .map_device_64k_with_pat(&mut memory, 0x10000, 0, 0, true)
        .unwrap();
    assert_eq!(tables.mapped_pages(), 16);
    assert_eq!(
        tables.translate(&memory, 0x10080),
        Ok(WalkOutcome::Mapped(128))
    );
    assert_eq!(
        tables.translate(&memory, 0x1ffff),
        Ok(WalkOutcome::Mapped(65535))
    );
    let mut page = tables.root_phys();
    for shift in [39, 30, 21] {
        page =
            memory.read_entry(page, ((0x10000u64 >> shift) & 511) as usize) & 0x0000_3fff_ffff_f000;
    }
    for i in 0..16 {
        assert_eq!(memory.read_entry(page, 16 + i), (i as u64 * 4096) | 0x903);
    }
    let saved = memory.read_entry(page, 17);
    memory.write_entry(page, 17, saved & !(1 << 8));
    assert_eq!(
        tables.translate(&memory, 0x10000),
        Ok(WalkOutcome::Corrupt { level: 3 })
    );
    assert_eq!(
        tables.translate(&memory, 0x11080),
        Ok(WalkOutcome::Corrupt { level: 3 })
    );
    memory.write_entry(page, 17, saved);
    assert_eq!(
        tables.translate(&memory, 0x10000),
        Ok(WalkOutcome::Mapped(0))
    );
    tables.teardown(&mut memory);
    assert_eq!(memory.live_tables(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_layout_ps64_zero_dpa_and_partial_group_corruption
);

#[derive(Debug)]
struct CpuOwner {
    ordinary: Arc<Mailbox>,
    facts: crate::intel_gpu_user::DeviceFacts,
    pool: Arc<Vram>,
    access: core::sync::atomic::AtomicBool,
    checks: core::sync::atomic::AtomicU32,
}
impl UserBackend for CpuOwner {
    fn status(&self) -> Option<UserStatus> {
        self.ordinary.status()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        Some(self.facts)
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.ordinary.submit(context, batch)
    }
    fn clear_vram(&self, object: Arc<GemObject>, epoch: u64) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            if !object.in_vram_pool(&self.pool) {
                return Err(FsError::NoDevice);
            }
            let mut token = object.begin_cpu_vram_clear()?;
            loop {
                self.checks.fetch_add(1, Ordering::Relaxed);
                if !self.access.load(Ordering::Acquire)
                    || self.status().is_none_or(|status| status.epoch != epoch)
                {
                    return Err(FsError::NoDevice);
                }
                // SAFETY: this actor owns the fake WC RAM aperture. The
                // modeled power/capability check precedes each bounded chunk.
                if let Some(fence) = unsafe { token.clear_next() } {
                    return Ok(fence);
                }
                narf_scheduler::yield_now().await;
            }
        })
    }
}

fn smoke_bmg_vram_private_cpu_owner_checks_each_chunk_and_cancellation() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (ordinary, mut info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let frame = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
    let pointer = frame.start_address().kernel_mut_ptr::<u8>();
    let bytes = 4 * 65536;
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: pointer as u64,
        len: bytes as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = VramLayout {
        tile_size: bar.len,
        tile_offset: 0,
        usable: bar.len,
    };
    // SAFETY: only this fixture owns these retained fake LMEM frames.
    let pool = unsafe { Vram::new(bar, layout) }.unwrap();
    let owner = Arc::new(CpuOwner {
        ordinary,
        facts: gt.device_facts().unwrap(),
        pool: pool.clone(),
        access: core::sync::atomic::AtomicBool::new(true),
        checks: core::sync::atomic::AtomicU32::new(0),
    });
    info.backend = Some(owner.clone());
    info.vram = Some(pool.clone());
    let file = RenderFile::new();
    let user = Cpu::new();
    for scenario in 0..4 {
        // SAFETY: the previous private operation/handle is gone; no GPU job
        // exists and this fixture owns the complete aperture.
        unsafe {
            core::ptr::write_bytes(pointer, 0xa5, bytes);
        }
        owner.access.store(scenario != 0, Ordering::Release);
        owner.checks.store(0, Ordering::Relaxed);
        request(&user, 3 * 65536, 2, 0);
        // The old sync entry cannot reserve or touch BAR bytes.
        assert_eq!(
            invoke(&file, &info, &user, xe::GEM_CREATE),
            Err(FsError::Unsupported)
        );
        assert_eq!(pool.used(), 0);
        let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
        if scenario == 0 {
            assert_eq!(ready(call.as_mut()), Some(Err(FsError::NoDevice)));
        } else {
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert_eq!(
                pool.used(),
                3 * 65536,
                "reservation blocks park before ownership release"
            );
            assert_eq!(u32_at(&user.wire.load(64, 56), 28), 0);
            // SAFETY: fake RAM stays live, and the yielded actor cannot write
            // again until this test polls it.
            let contents = unsafe { core::slice::from_raw_parts(pointer, bytes) };
            assert!(contents[..65536].iter().all(|b| *b == 0));
            assert!(contents[65536..].iter().all(|b| *b == 0xa5));
            match scenario {
                1 => {
                    owner.access.store(false, Ordering::Release);
                    assert_eq!(ready(call.as_mut()), Some(Err(FsError::NoDevice)));
                    assert_eq!(owner.checks.load(Ordering::Relaxed), 2);
                }
                2 => {} // Cancellation drops the private token between chunks.
                _ => {
                    assert!(call
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending());
                    assert_eq!(ready(call.as_mut()), Some(Ok(0)));
                    assert_eq!(owner.checks.load(Ordering::Relaxed), 3);
                }
            }
        }
        drop(call);
        if scenario == 3 {
            let handle = u32_at(&user.wire.load(64, 56), 28);
            let object = file.gem.object(handle).unwrap();
            let mut data = [0xff; 64];
            object.read(2 * 65536, &mut data).unwrap();
            assert_eq!(data, [0; 64]);
            drop(object);
            assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
        }
        assert_eq!(pool.used(), 0);
        // SAFETY: every operation is terminal or cancelled, with no remaining
        // reference capable of accessing this fixture's private allocation.
        let contents = unsafe { core::slice::from_raw_parts(pointer, bytes) };
        let initialized = match scenario {
            0 => 0,
            1 | 2 => 65536,
            _ => 3 * 65536,
        };
        assert!(contents[..initialized].iter().all(|b| *b == 0));
        assert!(contents[initialized..].iter().all(|b| *b == 0xa5));
    }
    drop(file);
    drop(info);
    drop(owner);
    drop(pool);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_bmg_vram_private_cpu_owner_checks_each_chunk_and_cancellation
);

fn smoke_dg2_vram_card_retains_pool_and_refuses_changed_or_missing_reset_layout() -> TestResult {
    fn fresh(ccs: Option<u64>) -> (Window, Arena, GuCGt<Window, Arena>) {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        if let Some(ccs) = ccs {
            let gsm = (8u64 << 30) - (64 << 20);
            w.0.borrow_mut().regs.extend([
                (0x1083a0, 8 << 8),
                (0x4910, ((ccs / 65536) << 8) as u32),
                (0x108104, (gsm >> 32) as u32),
                (0x108100, gsm as u32),
            ]);
        }
        prime(&mut gt, &w, 0x130044);
        (w, arena, gt)
    }
    let ccs = (8u64 << 30) - (96 << 20);
    let frame = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_ptr::<u8>() as u64,
        len: 4 * 65536,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let card = crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x56a0,
        0,
        0,
    );
    // SAFETY: only this card owns the retained fake LMEM RAM aperture; every
    // pool/reservation is released before these frames are freed.
    unsafe {
        card.install_lmem_bar(bar);
    }
    let (w, arena, mut gt) = fresh(Some(ccs));
    assert_eq!(card.publish_gt_vram(&gt), Ok(()));
    let pool = crate::drm_registry::DrmCard::intel_vram(&card).unwrap();
    assert_eq!(pool.layout.usable, ccs);
    assert_eq!(pool.visible(), bar.len);
    assert!(pool.requires_ccs_clear());
    let gem = crate::intel_gpu_gem::GemState::new();
    let pending = gem.prepare_vram(65536, None, &pool).unwrap();
    assert!(pending.object().in_vram_pool(&pool));
    assert_eq!(card.intel_vram_used(), Some(65536));
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    for source in [None, Some(ccs - 65536), Some(ccs)] {
        let (w, arena, mut gt) = fresh(source);
        assert_eq!(gt.vram_layout().map(|layout| layout.usable), source);
        let expected = if source == Some(ccs) {
            Ok(())
        } else {
            Err(FsError::NoDevice)
        };
        assert_eq!(card.publish_gt_vram(&gt), expected);
        let retained = crate::drm_registry::DrmCard::intel_vram(&card).unwrap();
        assert!(Arc::ptr_eq(&retained, &pool));
        assert!(pending.object().in_vram_pool(&retained));
        assert_eq!(retained.used(), 65536);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    drop(pending);
    assert_eq!(pool.used(), 0);
    drop(gem);
    drop(pool);
    drop(card);
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vram",
    smoke_dg2_vram_card_retains_pool_and_refuses_changed_or_missing_reset_layout
);
