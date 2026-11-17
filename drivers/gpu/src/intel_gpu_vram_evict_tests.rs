// dGPU VRAM eviction and migration:
// 1. Alchemist (DG2) bidirectional Flat-CCS metadata save on VRAM->sysmem eviction
//    and restore on sysmem->VRAM migration through real BCS0 commands & PPGTT.
// 2. Battlemage OOM eviction during DRM_XE_GEM_CREATE when VRAM is full,
//    excluding pinned scanout / CPU-mapped BOs, plus automatic re-migration
//    of preferred-VRAM objects back into VRAM on exec.
// 3. System suspend VRAM drain (`evict_vram_for(..., allow_scanout = true)`)
//    clearing idle VRAM BOs while refusing when active aliases or fences remain.
use super::*;
use crate::intel_gpu_exec::vram_clear;
use crate::intel_gpu_vram::{Vram, VramLayout};
use core::task::{Context, RawWaker, RawWakerVTable, Waker};

fn poll_now<F: core::future::Future>(future: F) -> F::Output {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: noop vtable functions have no preconditions.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(out) => out,
        core::task::Poll::Pending => panic!("eviction fixture stalled on synchronous completion"),
    }
}

pub(super) struct EvictBackend {
    platform: GtPlatform,
    mailbox: Arc<Mailbox>,
    facts: crate::intel_gpu_user::DeviceFacts,
    pool: Arc<Vram>,
    copies: core::sync::atomic::AtomicUsize,
}

impl core::fmt::Debug for EvictBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvictBackend")
            .field("platform", &self.platform)
            .field("copies", &self.copies.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl UserBackend for EvictBackend {
    fn status(&self) -> Option<UserStatus> {
        self.mailbox.status()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        Some(self.facts)
    }
    fn clear_vram(
        &self,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        epoch: u64,
    ) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            if self
                .status()
                .is_none_or(|s| s.epoch != epoch || s.platform != self.platform)
            {
                return Err(FsError::NoDevice);
            }
            if !self.pool.requires_ccs_clear() {
                let mut clear = object.begin_cpu_vram_clear()?;
                loop {
                    // SAFETY: this fixture exclusively owns its fake LMEM aperture.
                    if let Some(fence) = unsafe { clear.clear_next() } {
                        return Ok(fence);
                    }
                }
            }
            // prepare_vram_clear owns the CCS-clear claim (ccs 1 -> 2);
            // claiming it here first would make the factory call fail
            // with InvalidData (see #2157).
            let batch = crate::intel_gpu_exec::prepare_vram_clear(self.platform, object)?;
            let vm = batch.diagnostic_vm();
            assert!(vram_clear::execute_fixture(vm.root, vm.address));
            let fence = Arc::new(CompletionFence::new());
            fence.signal(Ok(()));
            Ok(fence)
        })
    }
    fn copy_objects(
        &self,
        request: crate::intel_gpu_exec::copy::CopyRequest,
        epoch: u64,
    ) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            if self
                .status()
                .is_none_or(|s| s.epoch != epoch || s.platform != self.platform)
            {
                return Err(FsError::NoDevice);
            }
            request.validate_pool(Some(&self.pool))?;
            let batch = request.prepare(self.platform)?;
            let vm = batch.diagnostic_vm();
            let root = vm.root
                | if self.platform == GtPlatform::Battlemage {
                    0x10
                } else {
                    0
                };
            assert!(vram_clear::execute_fixture(root, vm.address));
            self.copies.fetch_add(1, Ordering::AcqRel);
            let fence = Arc::new(CompletionFence::new());
            fence.signal(Ok(()));
            Ok(fence)
        })
    }
    fn submit<'a>(
        &'a self,
        _context: Arc<UserContext>,
        _batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        let fence = Arc::new(CompletionFence::new());
        fence.signal(Ok(()));
        Box::pin(async move { Ok(fence) })
    }
}

pub(super) fn evict_fixture(
    platform: GtPlatform,
    ack: u64,
) -> (
    narf_memory::frame::PhysFrame,
    Arc<Vram>,
    Arc<EvictBackend>,
    DeviceInfo,
) {
    let (w, _arena, mut gt) = hardware_model(platform, ack);
    prime(&mut gt, &w, ack);
    let (_, mut info) = setup(&mut gt, &w, platform);
    let frame = narf_memory::frame::alloc_pages_on(0, 6).expect("256 KiB test aperture");
    let len = 256 * 1024;
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_ptr::<u8>() as u64,
        len,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = VramLayout {
        tile_size: len,
        tile_offset: 0,
        usable: len,
    };
    // SAFETY: exclusively owned contiguous frames simulate LMEM for this fixture.
    let pool = unsafe {
        if platform == GtPlatform::Alchemist {
            Vram::new_dg2(bar, layout)
        } else {
            Vram::new(bar, layout)
        }
    }
    .unwrap();
    vram_clear::fixture_seed(0, len, bar.virt);
    let mailbox = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
            engines: gt.engines().unwrap(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let backend = Arc::new(EvictBackend {
        platform,
        mailbox,
        facts: gt.device_facts().unwrap(),
        pool: pool.clone(),
        copies: core::sync::atomic::AtomicUsize::new(0),
    });
    info.vram = Some(pool.clone());
    info.backend = Some(backend.clone());
    (frame, pool, backend, info)
}

pub(super) fn create_vram_bo(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    size: u64,
    placement: u32,
) -> Result<u32, FsError> {
    let mut wire = [0; 56];
    put64(&mut wire, 8, size);
    put32(&mut wire, 16, placement);
    wire[32] = 2; // DRM_XE_GEM_CPU_CACHING_WC
    user.wire.store(64, &wire);
    poll_now(file.dispatch_user(info, xe::GEM_CREATE, 64, user)).expect("native GEM_CREATE")?;
    Ok(u32_at(&user.wire.load(64, 56), 28))
}

fn smoke_dg2_vram_evict_saves_flat_ccs_and_migrates_back() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Alchemist, 0x130044);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;

    let h = create_vram_bo(&file, &info, &user, 65536, 2).unwrap();
    let obj = file.gem.object(h).unwrap();
    assert!(obj.is_vram());
    assert!(obj.preferred_vram());
    assert!(!obj.has_ccs_backup());
    assert_eq!(pool.used(), 65536);

    // Seed non-zero VRAM data and non-zero Flat-CCS sideband metadata.
    let pattern: Vec<u8> = (0..65536).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
    obj.write(0, &pattern).unwrap();
    let ccs_pattern: Vec<u8> = (0..256).map(|i| ((i * 11 + 5) & 0xff) as u8).collect();
    let dpa = obj.pages().next().unwrap();
    assert_eq!(dpa, 0);
    vram_clear::fixture_metadata(dpa, &ccs_pattern);

    // Evict to system memory: copies data + saves Flat-CCS into ccs_backup.
    let freed = poll_now(obj.evict_to_system(backend.as_ref(), epoch, false)).unwrap();
    assert_eq!(freed, 65536);
    assert!(!obj.is_vram());
    assert!(obj.preferred_vram());
    assert!(obj.has_ccs_backup());
    assert_eq!(pool.used(), 0);
    let mut sys_data = alloc::vec![0u8; 65536];
    obj.read(0, &mut sys_data).unwrap();
    assert_eq!(sys_data, pattern);

    // Poison freed Flat-CCS sideband, then migrate back to VRAM.
    vram_clear::fixture_metadata(0, &[0x5a; 256]);
    poll_now(obj.migrate_to_vram(backend.as_ref(), &pool, true, epoch)).unwrap();
    assert!(obj.is_vram());
    assert!(!obj.has_ccs_backup());
    assert_eq!(pool.used(), 65536);
    let mut restored_data = alloc::vec![0u8; 65536];
    obj.read(0, &mut restored_data).unwrap();
    assert_eq!(restored_data, pattern);
    let (metadata, _) = vram_clear::fixture_state();
    assert_eq!(&metadata[..256], &ccs_pattern[..]);

    drop(obj);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_dg2_vram_evict_saves_flat_ccs_and_migrates_back
);

fn smoke_bmg_vram_oom_eviction_exec_remigration_and_suspend_drain() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;

    // Aperture is 256 KiB. Fill it with two 128 KiB VRAM BOs.
    let h1 = create_vram_bo(&file, &info, &user, 128 * 1024, 2).unwrap();
    let h2 = create_vram_bo(&file, &info, &user, 128 * 1024, 2).unwrap();
    let obj1 = file.gem.object(h1).unwrap();
    let obj2 = file.gem.object(h2).unwrap();
    assert_eq!(pool.used(), 256 * 1024);

    let pattern1: Vec<u8> = (0..128 * 1024).map(|i| ((i + 1) & 0xff) as u8).collect();
    obj1.write(0, &pattern1).unwrap();
    // Mark obj2 scanout so OOM eviction skips obj2 and evicts idle obj1 instead.
    obj2.mark_scanout();
    assert!(!obj2.is_evictable(false));
    assert!(obj2.is_evictable(true));
    assert!(obj1.is_evictable(false));

    // Allocating a third 128 KiB VRAM BO (no sysmem fallback) triggers OOM eviction of obj1.
    let h3 = create_vram_bo(&file, &info, &user, 128 * 1024, 2).unwrap();
    let obj3 = file.gem.object(h3).unwrap();
    assert!(!obj1.is_vram(), "idle non-scanout obj1 must be evicted");
    assert!(obj2.is_vram(), "scanout obj2 must remain in VRAM");
    assert!(obj3.is_vram(), "new allocation succeeds after eviction");
    assert_eq!(pool.used(), 256 * 1024);
    let mut read1 = alloc::vec![0u8; 128 * 1024];
    obj1.read(0, &mut read1).unwrap();
    assert_eq!(read1, pattern1);

    // An active CPU mapping pins obj3 against eviction.
    let mapped = obj3.backing(0, 4096).unwrap();
    assert!(!obj3.is_evictable(false));
    // With obj2 scanout and obj3 CPU-mapped, another strict VRAM create must OOM cleanly.
    assert_eq!(
        create_vram_bo(&file, &info, &user, 128 * 1024, 2),
        Err(FsError::OutOfMemory)
    );
    drop(mapped);
    assert!(obj3.is_evictable(true));

    // Closing obj3 frees room; exec re-migrates evicted obj1 back into VRAM automatically.
    file.gem.close(h3).unwrap();
    drop(obj3);
    let vm = create_vm(&file, &info, &user);
    let q = create_queue(&file, &info, &user, vm, 0);
    bind_wire(&user, vm, &[mapping(h1, 0x1234_0000_0000, 0, 128 * 1024, 2, 0)], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    // Write MI_BATCH_BUFFER_END into obj1 before exec.
    obj1.write(0, &(0x0500_0000u32).to_le_bytes()).unwrap();
    exec_wire(&user, q, true, &[]);
    let exec_res = poll_now(file.dispatch_user(&info, xe::EXEC, 64, &user)).expect("native EXEC");
    assert_eq!(exec_res, Ok(0));
    assert!(obj1.is_vram(), "exec must re-migrate preferred-VRAM obj1 back to VRAM");

    // System suspend drain (`allow_scanout = true`) evicts both obj1 and scanout obj2 to 0 used.
    let drained = poll_now(crate::intel_gpu_xe::evict_vram_for(
        backend.as_ref(),
        &pool,
        false,
        0,
        epoch,
        true,
    ))
    .unwrap();
    assert_eq!(drained, 256 * 1024);
    assert_eq!(pool.used(), 0);
    assert!(!obj1.is_vram());
    assert!(!obj2.is_vram());

    drop(obj1);
    drop(obj2);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_bmg_vram_oom_eviction_exec_remigration_and_suspend_drain
);
