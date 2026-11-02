// Actual raw Xe ownership over the source BMG whole-device incarnation and
// the existing real MERT/GuC/CT/LRC/PPGTT device model. No fixture fence signal.
use super::super::super::mert::Rig as PowerRig;
use super::*;
use crate::amdgpu_vram::UnmappedReservation;
use crate::intel_gpu_exec::{copy::CopyRequest, vram_clear};
use crate::intel_gpu_gem::GemObject;
use crate::intel_gpu_gt::smallbar::{self, Authority, Takeover};
use crate::intel_gpu_vram::{Vram, VramLayout, Xe2VramRegisters};
use core::sync::atomic::Ordering;

const PAGE: u64 = 4096;
const BO: u64 = 65536;
const HIGH_PREFIX: u64 = 1 << 32;
const CODE_VA: u64 = 0x1234_0000_0000;
const DATA_VA: u64 = 0x2345_0000_0000;

fn source_device(id: u16) -> narf_bus::BusDevice {
    let addr = narf_bus::PcieAddr {
        segment: 0,
        bus: 0xf1,
        device: 2,
        function: 0,
    };
    narf_bus::BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0x100000),
        },
        id: narf_bus::DeviceId {
            vendor: 0x8086,
            device: id,
            class: 0x030000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
    }
}
fn source_bar() -> narf_bus::MmioRegion {
    narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x10000000),
        virt: 0x10000000,
        len: 16 * 1024 * 1024,
        kind: narf_bus::BarKind::Mmio64 {
            prefetchable: false,
        },
    }
}
fn source_layout(w: &Window, release: u32) {
    // Independent source literal: twelve GiB, four enabled L3 nodes,
    // GSM64MiB below end, flat CCS24MiB immediately before GSM.
    let tile = 12u64 << 30;
    let gsm = tile - (64 << 20);
    let ccs = gsm - tile / 512;
    assert_eq!(ccs, 0x2fa800000);
    let mut d = w.0.borrow_mut();
    d.smallbar = true;
    d.regs.extend([
        (0x1901f8, 0),
        (0x10100c, 0),
        (0x101010, 0),
        (0x101018, 0x80000000),
        (0xd8c, (20 << 22) | (release << 14)),
        (0x380d8c, (13 << 22) | (1 << 14)),
        (0x38a188, 0),
        (0x380dfc, 0),
        (0x38941c, 0),
        (0x38c000, 1),
        (0x38c314, 0),
        (0x1083a0, 0x0c00),
        (0x9118, 0x000f0000),
        (0x8800, (ccs / 4) as u32 | 1),
        (0x8804, 0),
        (0x108100, gsm as u32),
        (0x108104, (gsm >> 32) as u32),
        (0x1080c0, gsm as u32),
        (0x1080c4, (gsm >> 32) as u32),
    ]);
}
fn run_takeover(
    w: &Window,
    arena: &Arena,
    bar: narf_bus::MmioRegion,
    local: narf_bus::MmioRegion,
    id: u16,
) -> (Takeover, Arc<Authority>) {
    let mut owner = Takeover::new(source_device(id), bar, local, 0).unwrap();
    for now in 0..32 {
        assert_eq!(arena.live_allocations(), 0);
        assert_eq!(
            w.0.borrow().allocations,
            0,
            "pre-arena receipt cannot hide old DMA"
        );
        match owner.poll(w, now, || true) {
            Poll::Pending => {}
            Poll::Ready(Ok(authority)) => {
                let d = w.0.borrow();
                assert_eq!(d.smallbar_flrs, 1);
                assert!(d.smallbar_guc_retired && d.smallbar_engines_retired);
                assert!(!d.writes.iter().any(|(r, _)| *r == 0x130030));
                return (owner, authority);
            }
            other => panic!("source whole-device takeover failed: {other:?}"),
        }
    }
    panic!("bounded source takeover did not finish")
}
struct ClearPending {
    object: Arc<GemObject>,
    epoch: u64,
    reply: Arc<Reply>,
}
struct PublishReply {
    result: IrqSafeSpinLock<Option<Result<(), FsError>>>,
}
struct PublishPending {
    epoch: u64,
    pool: Arc<Vram>,
    object: Arc<GemObject>,
    fence: Arc<CompletionFence>,
    reply: Arc<PublishReply>,
}
struct Backend {
    ordinary: Arc<Mailbox>,
    facts: crate::intel_gpu_user::DeviceFacts,
    pool: Arc<Vram>,
    clears: IrqSafeSpinLock<Vec<ClearPending>>,
    publications: IrqSafeSpinLock<Vec<PublishPending>>,
}
impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SmallbarBackend").finish_non_exhaustive()
    }
}
impl UserBackend for Backend {
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
    fn publish_vram<'a>(
        &'a self,
        epoch: u64,
        pool: Arc<Vram>,
        object: Arc<GemObject>,
        fence: Arc<CompletionFence>,
        publish: crate::intel_gpu_user::VramPublish<'a>,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let reply = Arc::new(PublishReply {
                result: IrqSafeSpinLock::new(None),
            });
            self.publications.lock().push(PublishPending {
                epoch,
                pool,
                object,
                fence,
                reply: reply.clone(),
            });
            core::future::poll_fn(|_| match reply.result.lock().take() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            })
            .await?;
            // The !Send GT stays in the device-model executor. This mailbox
            // only carries its checked metadata permission; every hardware
            // proof is executed by accept_publication below, after copyout.
            let mut current = || {
                if self.status().is_some_and(|s| s.epoch == epoch) {
                    Ok(())
                } else {
                    Err(FsError::NoDevice)
                }
            };
            publish(&mut current)
        })
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
impl Backend {
    fn accept_publication(&self, core: &mut PowerRig) {
        let request = self
            .publications
            .lock()
            .pop()
            .expect("postcopyout owner transaction");
        let result = if !Arc::ptr_eq(&request.pool, &self.pool)
            || !request.object.in_vram_pool(&self.pool)
            || !request.object.initialization_complete(&request.fence)
            || request.epoch != core.epoch
            || self.status().is_none_or(|s| s.epoch != request.epoch)
        {
            Err(FsError::NoDevice)
        } else {
            core.gt.vram_access(request.epoch).map_err(|e| {
                if matches!(e, GtError::Busy) {
                    FsError::WouldBlock
                } else {
                    FsError::NoDevice
                }
            })
        };
        *request.reply.result.lock() = Some(result);
    }
    fn accept(&self, core: &mut PowerRig) -> (Arc<CompletionFence>, alloc::sync::Weak<GemObject>) {
        let request = self
            .clears
            .lock()
            .pop()
            .expect("actual raw create queued clear");
        let weak = Arc::downgrade(&request.object);
        let fence = if request.object.is_gpu_only() {
            core.gt
                .clear_vram(core.now, request.object, request.epoch)
                .unwrap()
        } else {
            // Drive the actual visible CPU-clear owner as production does:
            // current region before every chunk, retained MERT transaction
            // before stores, then a fresh completed invalidation before reply.
            let mut clear = request.object.begin_cpu_vram_clear().unwrap();
            let lease = core
                .gt
                .retain_cpu_vram_clear(request.object.clone(), request.epoch, core.now)
                .unwrap();
            let fence = loop {
                core.gt.vram_access(request.epoch).unwrap();
                // SAFETY: this fixture owns the actual pool, current source
                // region/epoch/cache/MERT owner and private visible target.
                if let Some(fence) = unsafe { clear.clear_next() } {
                    break fence;
                }
            };
            if let Some(lease) = lease {
                assert_eq!(lease.completion().result(), None);
                lease.ready();
                let mut done = false;
                for _ in 0..32 {
                    core.gt.vram_access(request.epoch).unwrap();
                    core.tick();
                    if core.gt.vram_flush_done(request.epoch, lease.id()).unwrap() {
                        done = true;
                        break;
                    }
                }
                assert!(done, "actual retained CPU-clear invalidation completed");
                assert_eq!(lease.completion().result(), Some(Ok(())));
            }
            fence
        };
        core.now += 100;
        *request.reply.result.lock() = Some(Ok(fence.clone()));
        if let Some(waker) = request.reply.waker.lock().take() {
            waker.wake();
        }
        (fence, weak)
    }
}
struct Rig {
    core: PowerRig,
    owner: Takeover,
    authority: Arc<Authority>,
    visible: narf_memory::frame::PhysFrame,
    shadow: narf_memory::frame::PhysFrame,
    local: narf_bus::MmioRegion,
    prefix: Option<UnmappedReservation>,
    pool: Arc<Vram>,
    backend: Arc<Backend>,
    info: DeviceInfo,
}
impl Rig {
    fn new(release: u32, high: bool) -> Self {
        let visible = narf_memory::frame::alloc_pages_on(0, 4).unwrap();
        let local = narf_bus::MmioRegion {
            phys: visible.start_address(),
            virt: visible.start_address().kernel_ptr::<u8>() as u64,
            len: BO,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        let shadow = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
        // SAFETY: independent model VRAM, never a production CPU alias.
        unsafe {
            core::ptr::write_bytes(local.virt as *mut u8, 0x6d, BO as usize);
            core::ptr::write_bytes(
                shadow.start_address().kernel_mut_ptr::<u8>(),
                0xa5,
                (4 * BO) as usize,
            );
        }
        let mut receipt = None;
        let mut core = PowerRig::with_before_stage(release, 0, |io, arena| {
            source_layout(&io.inner, release);
            receipt = Some(run_takeover(&io.inner, arena, source_bar(), local, 0xe20b));
        });
        let (owner, authority) = receipt.unwrap();
        if release == 1 {
            assert!(core.gt.smallbar_grant(&authority).is_err());
        }
        core.prepare();
        let grant = core.gt.smallbar_grant(&authority).unwrap();
        assert_eq!(
            grant.layout,
            VramLayout {
                tile_size: 12 << 30,
                tile_offset: 0,
                usable: 0x2fa800000
            }
        );
        // SAFETY: actual completed whole-device source receipt, fresh cache,
        // main/media/MERT owners and source layout supplied this exact grant.
        let pool = unsafe { Vram::new_smallbar(local, grant.layout, grant) }.unwrap();
        let prefix = high.then(|| pool.fixture_reserve_unmapped(HIGH_PREFIX).unwrap());
        let start = BO + if high { HIGH_PREFIX } else { 0 };
        vram_clear::fixture_seed(
            start,
            4 * BO,
            shadow.start_address().kernel_ptr::<u8>() as u64,
        );
        vram_clear::fixture_add_window(0, BO, local.virt);
        let inner = core.io.inner.clone();
        let (ordinary, mut info) = setup(&mut core.gt, &inner, GtPlatform::Battlemage);
        let backend = Arc::new(Backend {
            facts: core.gt.device_facts().unwrap(),
            ordinary,
            pool: pool.clone(),
            clears: IrqSafeSpinLock::new(Vec::new()),
            publications: IrqSafeSpinLock::new(Vec::new()),
        });
        info.vram = Some(pool.clone());
        info.backend = Some(backend.clone());
        Self {
            core,
            owner,
            authority,
            visible,
            shadow,
            local,
            prefix,
            pool,
            backend,
            info,
        }
    }
    fn base_used(&self) -> u64 {
        if self.prefix.is_some() {
            HIGH_PREFIX
        } else {
            0
        }
    }
    fn w(&self) -> Window {
        self.core.io.inner.clone()
    }
    fn finish(&mut self, fence: &CompletionFence) {
        let w = self.w();
        finish_policy(
            &mut self.core.gt,
            &w,
            fence,
            &mut self.core.registered,
            self.core.now,
            3,
        );
        self.core.now += 1000;
    }
    fn create(&mut self, file: &RenderFile, user: &Cpu, size: u64, vm: u32) -> u32 {
        self.create_class(file, user, size, vm, false)
    }
    fn create_class(
        &mut self,
        file: &RenderFile,
        user: &Cpu,
        size: u64,
        vm: u32,
        visible: bool,
    ) -> u32 {
        request(user, size, vm, visible);
        let info = self.info.clone();
        let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (fence, _) = self.backend.accept(&mut self.core);
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        if fence.result().is_none() {
            assert_eq!(u32_at(&user.wire.load(64, 56), 28), 0);
            self.finish(&fence);
        } else {
            // Visible initialization and its MERT invalidation completed in
            // accept(); its copyout may already report a still-private ID.
            assert_eq!(fence.result(), Some(Ok(())));
        }
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let reported = u32_at(&user.wire.load(64, 56), 28);
        assert_ne!(reported, 0);
        assert_eq!(file.gem.object(reported).err(), Some(FsError::NotFound));
        assert_eq!(file.gem.fixture_pending_usage(), (1, size));
        self.backend.accept_publication(&mut self.core);
        assert_eq!(ready(call.as_mut()), Some(Ok(0)));
        drop(call);
        u32_at(&user.wire.load(64, 56), 28)
    }
    fn copy(&mut self, source: Arc<GemObject>, destination: Arc<GemObject>, bytes: u64) {
        let request = CopyRequest::new(source, 0, destination, 0, bytes).unwrap();
        let fence = self
            .core
            .gt
            .copy_objects(self.core.now, request, self.core.epoch, Some(&self.pool))
            .unwrap();
        self.core.now += 100;
        self.finish(&fence);
    }
    fn end(mut self) {
        assert_eq!(self.pool.usage(), (self.base_used(), 0));
        assert_eq!(self.w().0.borrow().smallbar_flrs, 1);
        assert!(matches!(
            self.owner.poll(&self.core.io, 9_000_000_000, || true),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            self.w().0.borrow().smallbar_flrs,
            1,
            "restart cannot re-wipe"
        );
        drop(self.prefix.take());
        assert_eq!(self.pool.usage(), (0, 0));
        drop(self.info);
        drop(self.backend);
        drop(self.pool);
        self.core.stop();
        drop(self.authority);
        vram_clear::fixture_finish();
        narf_memory::frame::free_pages(self.shadow, 6);
        narf_memory::frame::free_pages(self.visible, 4);
    }
}
fn request(user: &Cpu, size: u64, vm: u32, visible: bool) {
    let mut wire = [0; 56];
    put64(&mut wire, 8, size);
    put32(&mut wire, 16, 2);
    put32(&mut wire, 20, if visible { 4 } else { 0 });
    put32(&mut wire, 24, vm);
    wire[32] = 2;
    user.wire.store(64, &wire);
}
fn smoke_bmg_smallbar_layout_and_dual_pool_literals() -> TestResult {
    let gsm = (12u64 << 30) - (64 << 20);
    let words = Xe2VramRegisters {
        tile_range: 0x0c00,
        ccs_lower: 0xbea00001,
        ccs_upper: 0,
        fuse3: 0x000f0000,
        gsm_base: gsm,
    };
    assert_eq!(VramLayout::xe2(words).unwrap().usable, 0x2fa800000);
    for bad in [
        Xe2VramRegisters { fuse3: 0, ..words },
        Xe2VramRegisters {
            ccs_upper: 1,
            ..words
        },
        Xe2VramRegisters {
            gsm_base: gsm - 4096,
            ..words
        },
        Xe2VramRegisters {
            tile_range: 0,
            ..words
        },
    ] {
        assert!(VramLayout::xe2(bad).is_err());
    }
    for release in [1, 2] {
        let rig = Rig::new(release, true);
        let hidden = rig.pool.allocate_class(BO, false).unwrap();
        let visible = rig.pool.allocate(BO).unwrap();
        assert_eq!(hidden.device_address(), 0x100010000);
        assert_eq!(hidden.cpu_address(), None);
        assert_eq!(visible.device_address(), 0);
        assert_eq!(visible.cpu_address(), Some(rig.local.phys.raw()));
        assert_eq!(rig.pool.usage(), (HIGH_PREFIX + 2 * BO, BO));
        assert!(rig.pool.allocate(4096).is_err());
        drop(hidden);
        drop(visible);
        let original = rig.w().0.borrow().regs[&0x1083a0];
        rig.w()
            .0
            .borrow_mut()
            .regs
            .insert(0x1083a0, original ^ 0x100);
        assert!(!rig.pool.smallbar_current(&rig.core.io));
        rig.w().0.borrow_mut().regs.insert(0x1083a0, original);
        assert!(rig.pool.smallbar_current(&rig.core.io));
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_layout_and_dual_pool_literals
);
fn smoke_bmg_smallbar_raw_create_runs_gpu_zero_before_publication() -> TestResult {
    for release in [1, 2] {
        let mut rig = Rig::new(release, true);
        let file = RenderFile::new();
        let user = Cpu::new();
        let handle = rig.create(&file, &user, BO, 0);
        let object = file.gem.object(handle).unwrap();
        assert!(object.is_gpu_only());
        assert_eq!(object.pages().next(), Some(0x100010000));
        let copies = vram_clear::fixture_copies();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].1, 0x100010000);
        assert_eq!(copies[0].2, BO);
        let output = GemObject::private_system(BO).unwrap();
        rig.copy(object.clone(), output.clone(), BO);
        let mut bytes = alloc::vec![0xff; BO as usize];
        output.read(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|v| *v == 0));
        // Independent hidden model guard and visible BAR remain untouched.
        let shadow = rig.shadow.start_address().kernel_ptr::<u8>();
        assert!((BO..4 * BO).all(|at| {
            // SAFETY: rig retains the complete four-BO shadow allocation;
            // this range reads only its in-bounds untouched guard bytes.
            unsafe { *shadow.add(at as usize) == 0xa5 }
        }));
        assert!((0..BO).all(|at| {
            // SAFETY: rig owns and retains this complete BO-sized RAM BAR
            // aperture; every byte offset is strictly within its extent.
            unsafe { *((rig.local.virt + at) as *const u8) == 0x6d }
        }));
        drop(output);
        drop(object);
        drop(file);

        // Exercise the new zero factory's second/remainder command at high
        // DPA, independently of ordinary system-copy chunking coverage.
        let bytes = 8 * 1024 * 1024 + BO;
        let large_shadow = narf_memory::frame::alloc_pages_on(0, 12).unwrap();
        let cpu = large_shadow.start_address().kernel_ptr::<u8>();
        // SAFETY: this independent device-side oracle owns sixteen MiB of
        // RAM, covering the complete hidden target plus an untouched guard.
        unsafe { core::ptr::write_bytes(cpu as *mut u8, 0xa5, (bytes + BO) as usize) };
        vram_clear::fixture_seed(0x100010000, bytes + BO, cpu as u64);
        vram_clear::fixture_add_window(0, BO, rig.local.virt);
        let file = RenderFile::new();
        let handle = rig.create(&file, &user, bytes, 0);
        let object = file.gem.object(handle).unwrap();
        assert!(object.is_gpu_only());
        assert_eq!(object.pages().next(), Some(0x100010000));
        let copies = vram_clear::fixture_copies();
        assert_eq!(copies.len(), 2);
        assert_eq!((copies[0].1, copies[0].2), (0x100010000, 0x800000));
        assert_eq!((copies[1].1, copies[1].2), (0x100810000, 0x10000));
        assert_eq!(
            copies[0].0, copies[1].0,
            "reuse the same owned RO zero source"
        );
        let output = GemObject::private_system(bytes).unwrap();
        rig.copy(object.clone(), output.clone(), bytes);
        let mut readback = alloc::vec![0xff; bytes as usize];
        output.read(0, &mut readback).unwrap();
        assert!(readback.iter().all(|byte| *byte == 0));
        // Only the private WB readback proves target zeroing. These direct
        // model reads inspect neighboring guards, never a production alias.
        assert!((bytes..bytes + BO).all(|at| {
            // SAFETY: large_shadow retains sixteen MiB; bytes + BO is less
            // than that allocation and these are the adjacent guard bytes.
            unsafe { *cpu.add(at as usize) == 0xa5 }
        }));
        assert!((0..BO).all(|at| {
            // SAFETY: rig owns and retains this complete BO-sized RAM BAR
            // aperture; every byte offset is strictly within its extent.
            unsafe { *((rig.local.virt + at) as *const u8) == 0x6d }
        }));
        drop(output);
        drop(object);
        drop(file);
        assert_eq!(rig.pool.usage(), (HIGH_PREFIX, 0));
        // Every job is terminal and the private target has no owner. Restore
        // the original oracle before freeing its temporary large RAM window.
        vram_clear::fixture_seed(
            0x100010000,
            4 * BO,
            rig.shadow.start_address().kernel_ptr::<u8>() as u64,
        );
        vram_clear::fixture_add_window(0, BO, rig.local.virt);
        narf_memory::frame::free_pages(large_shadow, 12);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_raw_create_runs_gpu_zero_before_publication
);
fn smoke_bmg_smallbar_cpu_export_alias_and_profile_refusals() -> TestResult {
    let mut rig = Rig::new(2, false);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handle = rig.create(&file, &user, BO, 0);
    let object = file.gem.object(handle).unwrap();
    assert_eq!(object.read(0, &mut [0]), Err(FsError::Unsupported));
    assert_eq!(object.write(0, &[1]), Err(FsError::Unsupported));
    assert_eq!(object.backing(0, 4096).err(), Some(FsError::Unsupported));
    assert_eq!(file.gem.mmap_offset(handle), Err(FsError::Unsupported));
    assert_eq!(
        file.gem.export_object(handle).err(),
        Some(FsError::NotImplemented)
    );
    let mut wire = [0; 40];
    put32(&mut wire, 8, handle);
    user.wire.store(64, &wire);
    assert_eq!(
        invoke(&file, &rig.info, &user, xe::GEM_MMAP_OFFSET),
        Err(FsError::Unsupported)
    );
    let staged = GemObject::private_system(BO).unwrap();
    assert_eq!(staged.backing(0, 4096).err(), Some(FsError::Unsupported));
    assert_eq!(file.gem.import(&staged), Err(FsError::Unsupported));
    let ordinary = file
        .gem
        .object(create_bo(&file, &rig.info, &user, BO, 0))
        .unwrap();
    assert_eq!(
        CopyRequest::new(ordinary, 0, object.clone(), 0, BO).err(),
        Some(FsError::Unsupported)
    );
    let mappings = [crate::intel_gpu_exec::VmMapping {
        object: Some(object.clone()),
        va: DATA_VA,
        offset: 0,
        length: BO,
        writable: true,
        pat: 2,
        dumpable: false,
    }];
    assert_eq!(
        crate::intel_gpu_exec::ResidentBatch::from_vm(
            GtPlatform::Battlemage,
            &mappings,
            None,
            false,
            Some((DATA_VA, 1))
        )
        .err(),
        Some(FsError::InvalidData)
    );
    drop(mappings);
    drop(staged);
    drop(object);
    drop(file);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_cpu_export_alias_and_profile_refusals
);
fn bind_hidden(file: &RenderFile, info: &DeviceInfo, user: &Cpu, vm: u32, hidden: u32) -> u32 {
    let code = create_bo(file, info, user, PAGE, 0);
    let words = [0x10000002u32, 0x80, 0x2345, 0x4e415246, 0x05000000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem.object(code).unwrap().write(0, &bytes).unwrap();
    bind_wire(
        user,
        vm,
        &[
            mapping(code, CODE_VA, 0, PAGE, 2, 1),
            mapping(hidden, DATA_VA, 0, BO, 2, 0),
        ],
        &[],
    );
    assert_eq!(bind_now(file, info, user), Ok(0));
    code
}
fn smoke_bmg_smallbar_raw_vm_exec_and_copy_roundtrip() -> TestResult {
    for release in [1, 2] {
        let mut rig = Rig::new(release, true);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &rig.info, &user);
        let hidden = rig.create(&file, &user, BO, vm);
        let object = file.gem.object(hidden).unwrap();
        let code = bind_hidden(&file, &rig.info, &user, vm, hidden);
        let engines = rig.core.gt.engines().unwrap();
        let exact: Vec<_> = engines.iter().collect();
        assert!(exact.contains(&crate::intel_gpu_engine::Engine::Rcs0));
        assert!(exact.contains(&crate::intel_gpu_engine::Engine::Bcs0));
        assert!(exact.contains(&crate::intel_gpu_engine::Engine::Bcs8));
        for (iteration, engine) in exact.into_iter().enumerate() {
            // Each engine must produce fresh payload evidence. A stale store
            // from the previous engine cannot satisfy this independent marker.
            let marker = 0x4e41_5200u32 + iteration as u32 + 1;
            file.gem
                .object(code)
                .unwrap()
                .write(12, &marker.to_le_bytes())
                .unwrap();
            let queue = create_queue_instance(
                &file,
                &rig.info,
                &user,
                vm,
                engine.xe_class(),
                engines.logical_instance(engine).unwrap(),
            );
            exec_wire(&user, queue, true, &[]);
            let info = rig.info.clone();
            let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let (_, fence) = rig.backend.ordinary.accept(&mut rig.core.gt, rig.core.now);
            assert_eq!(ready(call.as_mut()), Some(Ok(0)));
            drop(call);
            let w = rig.w();
            finish_policy(
                &mut rig.core.gt,
                &w,
                &fence,
                &mut rig.core.registered,
                rig.core.now + 1,
                2,
            );
            rig.core.now += 1000;
            let output = GemObject::private_system(BO).unwrap();
            rig.copy(object.clone(), output.clone(), BO);
            let mut bytes = alloc::vec![0; BO as usize];
            output.read(0, &mut bytes).unwrap();
            assert_eq!(&bytes[0x80..0x84], &marker.to_le_bytes());
            assert!(bytes[..0x80].iter().all(|v| *v == 0));
            assert!(bytes[0x84..].iter().all(|v| *v == 0));
            drop(output);
            assert_eq!(
                close(&file, &rig.info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                Ok(0)
            );
        }
        // Old VM snapshot owns the same immutable range until explicit unmap.
        let mut unmap = [0; 80];
        put64(&mut unmap, 24, BO);
        put64(&mut unmap, 32, DATA_VA);
        put32(&mut unmap, 40, 1); // DRM_XE_VM_BIND_OP_UNMAP
        bind_wire(&user, vm, &[unmap], &[]);
        assert_eq!(bind_now(&file, &rig.info, &user), Ok(0));
        assert_eq!(close(&file, &rig.info, &user, abi::GEM_CLOSE, code), Ok(0));
        drop(object);
        drop(file);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_raw_vm_exec_and_copy_roundtrip
);
fn smoke_bmg_smallbar_cancel_output_vm_close_and_exact_reuse() -> TestResult {
    for failure in 0..4 {
        let mut rig = Rig::new(2, false);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = if failure == 3 {
            create_vm(&file, &rig.info, &user)
        } else {
            0
        };
        request(&user, BO, vm, false);
        let info = rig.info.clone();
        type CreateCall<'a> =
            core::pin::Pin<Box<dyn Future<Output = Option<Result<u64, FsError>>> + 'a>>;
        let mut call: CreateCall<'_> =
            Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        if failure == 0 {
            drop(call);
            call = Box::pin(async { None });
        }
        let (fence, weak) = rig.backend.accept(&mut rig.core);
        if failure != 0 {
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(rig.pool.usage(), (BO, 0));
        if failure == 1 {
            drop(call);
            call = Box::pin(async { None });
        }
        assert!(weak.upgrade().is_some());
        rig.finish(&fence);
        match failure {
            2 => user.fail_report.store(true, Ordering::Relaxed),
            3 => assert_eq!(close(&file, &rig.info, &user, xe::VM_DESTROY, vm), Ok(0)),
            _ => {}
        }
        if failure >= 2 {
            match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(result) => assert!(matches!(result, Some(Err(_)))),
                Poll::Pending => {
                    rig.backend.accept_publication(&mut rig.core);
                    assert!(matches!(ready(call.as_mut()), Some(Err(_))));
                }
            }
        }
        drop(call);
        assert!(weak.upgrade().is_none());
        assert_eq!(rig.pool.used(), 0);
        user.fail_report.store(false, Ordering::Relaxed);
        let handle = rig.create(&file, &user, BO, 0);
        let object = file.gem.object(handle).unwrap();
        assert_eq!(object.pages().next(), Some(BO));
        let staged = GemObject::private_system(BO).unwrap();
        staged.write(0, &[0x5a; 4096]).unwrap();
        rig.copy(staged.clone(), object.clone(), BO);
        drop(object);
        assert_eq!(
            close(&file, &rig.info, &user, abi::GEM_CLOSE, handle),
            Ok(0)
        );
        let fresh = rig.create(&file, &user, BO, 0);
        let object = file.gem.object(fresh).unwrap();
        assert_eq!(object.pages().next(), Some(BO));
        rig.copy(object.clone(), staged.clone(), BO);
        let mut bytes = alloc::vec![0xff; BO as usize];
        staged.read(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|v| *v == 0));
        drop(object);
        drop(staged);
        drop(file);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_cancel_output_vm_close_and_exact_reuse
);
fn smoke_bmg_smallbar_current_cache_pm_and_mert_gates() -> TestResult {
    for release in [1, 2] {
        let mut rig = Rig::new(release, false);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &rig.info, &user);
        let hidden = rig.create(&file, &user, BO, vm);
        bind_hidden(&file, &rig.info, &user, vm, hidden);
        let queue = create_queue(&file, &rig.info, &user, vm, 0);
        let epoch = rig.core.epoch;
        assert!(rig.core.gt.vram_cpu_access(epoch));
        assert!(!rig.core.gt.vram_cpu_access(epoch + 1));
        for reg in [0x1080c0, 0x1083a0, 0x108100, 0x8800, 0x8804, 0x9118] {
            let saved = rig.w().0.borrow().regs[&reg];
            rig.w()
                .0
                .borrow_mut()
                .regs
                .insert(reg, saved ^ if reg == 0x1080c0 { 1 << 20 } else { 0x100 });
            assert!(!rig.pool.smallbar_current(&rig.core.io));
            assert!(
                !rig.core.gt.vram_cpu_access(epoch),
                "WC clear must also refuse geometry drift"
            );
            rig.w().0.borrow_mut().regs.insert(reg, saved);
            assert!(rig.core.gt.vram_cpu_access(epoch));
        }
        exec_wire(&user, queue, true, &[]);
        let info = rig.info.clone();
        let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let saved = rig.w().0.borrow().regs[&0x1080c0];
        rig.w()
            .0
            .borrow_mut()
            .regs
            .insert(0x1080c0, saved - (1 << 20));
        let request = rig.backend.ordinary.pending.lock().pop().unwrap();
        let before = rig.core.arena.live_allocations();
        let result = rig
            .core
            .gt
            .submit_user_batch(rig.core.now, request.context, request.batch);
        assert!(result.is_err());
        assert_eq!(rig.core.gt.state(), GtState::Lost);
        assert_eq!(rig.core.arena.live_allocations(), before);
        *request.reply.result.lock() = Some(Err(FsError::NoDevice));
        assert_eq!(ready(call.as_mut()), Some(Err(FsError::NoDevice)));
        drop(call);
        rig.w().0.borrow_mut().regs.insert(0x1080c0, saved);
        assert_eq!(rig.w().0.borrow().smallbar_flrs, 1);
        drop(file);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_current_cache_pm_and_mert_gates
);
fn smoke_bmg_smallbar_reset_quarantine_no_early_reuse() -> TestResult {
    let mut rig = Rig::new(1, false);
    let file = RenderFile::new();
    let user = Cpu::new();
    request(&user, BO, 0, false);
    let info = rig.info.clone();
    let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (fence, weak) = rig.backend.accept(&mut rig.core);
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    drop(call);
    drop(info);
    drop(file);
    assert!(weak.upgrade().is_some());
    assert_eq!(rig.pool.used(), BO);
    // No CT reply/retirement. A second reservation cannot overlap this range.
    let other = rig.pool.allocate_class(BO, false).unwrap();
    assert_eq!(other.device_address(), 2 * BO);
    rig.core.now = 3_000_000_000;
    rig.core.gt.begin_stop(rig.core.now).unwrap();
    for delta in 1..4 {
        assert!(rig.core.gt.poll(rig.core.now + delta).is_pending());
        assert!(weak.upgrade().is_some());
        assert_eq!(fence.result(), None);
    }
    assert_eq!(rig.w().0.borrow().smallbar_flrs, 1);
    rig.core.reset_to_mert(); // independent full GuC/DMA+engine reset ACKs
    assert!(matches!(fence.result(), Some(Err(_))));
    assert!(weak.upgrade().is_none());
    assert_eq!(rig.pool.used(), BO);
    let reused = rig.pool.allocate_class(BO, false).unwrap();
    assert_eq!(reused.device_address(), BO);
    assert_eq!(reused.cpu_address(), None);
    drop(reused);
    drop(other);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_reset_quarantine_no_early_reuse
);
fn smoke_bmg_smallbar_usage_and_power_exclusion() -> TestResult {
    let mut rig = Rig::new(1, false);
    let file = RenderFile::new();
    let user = Cpu::new();
    let hidden = rig.create(&file, &user, BO, 0);
    let before_flushes = rig.core.io.regs.borrow().flushes;
    let visible = rig.create_class(&file, &user, BO, 0, true);
    assert!(rig.core.io.regs.borrow().flushes > before_flushes);
    assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
    let visible_object = file.gem.object(visible).unwrap();
    assert!(!visible_object.is_gpu_only());
    assert!(visible_object.is_vram());
    assert_eq!(visible_object.pages().next(), Some(0));
    assert!((0..BO).all(|at| {
        // SAFETY: rig retains the complete BO-sized visible RAM aperture;
        // all initialization work is terminal before these in-bounds reads.
        unsafe { *((rig.local.virt + at) as *const u8) == 0 }
    }));
    drop(visible_object);
    let regions = xe_query(&file, &rig.info, &user, 1);
    assert_eq!(u64_at(&regions, 104), 0x2fa800000);
    assert_eq!(u64_at(&regions, 112), 2 * BO);
    assert_eq!(u64_at(&regions, 120), BO);
    assert_eq!(u64_at(&regions, 128), BO);
    let fill = rig
        .pool
        .fixture_reserve_unmapped(rig.pool.total() - 2 * BO)
        .unwrap();
    assert!(rig.pool.allocate_class(PAGE, false).is_err());
    let before = rig.pool.usage();
    request(&user, PAGE, 0, false);
    user.wire.store(80, &3u32.to_le_bytes());
    let info = rig.info.clone();
    let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
    assert_eq!(ready(call.as_mut()), Some(Ok(0)));
    drop(call);
    let fallback = u32_at(&user.wire.load(64, 56), 28);
    assert!(!file.gem.object(fallback).unwrap().is_vram());
    assert_eq!(rig.pool.usage(), before);
    drop(fill);
    assert_eq!(
        close(&file, &rig.info, &user, abi::GEM_CLOSE, visible),
        Ok(0)
    );
    assert_eq!(
        close(&file, &rig.info, &user, abi::GEM_CLOSE, hidden),
        Ok(0)
    );
    assert_eq!(rig.pool.usage(), (0, 0));
    drop(file);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_usage_and_power_exclusion
);
fn smoke_bmg_smallbar_option_separator_and_source_takeover_literals() -> TestResult {
    for line in [
        "",
        "narf.intel.bmg_smallbar",
        "narf.intel.bmg_smallbar=0",
        "narf.intel.bmg_smallbar=01",
        "-- narf.intel.bmg_smallbar=1",
        "narf.intel.bmg_smallbar=1 narf.intel.bmg_smallbar=1",
        "narf.intel.bmg_smallbar=1 narf.intel.bmg_smallbar",
    ] {
        assert!(!smallbar::requested(narf_boot::args::KernelCmdline::new(
            line
        )));
        // This is the exact physical install/cold-start option decision: no
        // requested transaction, no driver-FLR can be constructed/triggered.
        let (w, arena) = model();
        source_layout(&w, 2);
        if smallbar::requested(narf_boot::args::KernelCmdline::new(line)) {
            panic!("unexpected destructive startup admission");
        }
        assert!(w.0.borrow().writes.is_empty());
        assert_eq!(arena.live_allocations(), 0);
    }
    for line in [
        "narf.intel.bmg_smallbar=1",
        "quiet narf.intel.bmg_smallbar=1 -- narf.intel.bmg_smallbar",
        "narf.intel.bmg_smallbar=1 -- narf.intel.bmg_smallbar=0 narf.intel.bmg_smallbar=1",
    ] {
        assert!(smallbar::requested(narf_boot::args::KernelCmdline::new(
            line
        )));
    }
    for id in [
        0xe202, 0xe209, 0xe20b, 0xe20c, 0xe20d, 0xe210, 0xe211, 0xe212, 0xe216, 0xe220, 0xe221,
        0xe222, 0xe223,
    ] {
        for release in [1, 2] {
            let (w, arena) = model();
            source_layout(&w, release);
            let local = narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0x80000000),
                virt: 0x80000000,
                len: BO,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            };
            let (mut owner, authority) = run_takeover(&w, &arena, source_bar(), local, id);
            assert!(authority.current(&w).is_ok());
            assert!(matches!(
                owner.poll(&w, 10_000_000_000, || true),
                Poll::Ready(Ok(_))
            ));
            assert_eq!(w.0.borrow().smallbar_flrs, 1);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_option_separator_and_source_takeover_literals
);
fn smoke_bmg_smallbar_pending_quota_follows_actual_job_graph() -> TestResult {
    let mut rig = Rig::new(2, false);
    let file = RenderFile::new();
    let user = Cpu::new();
    // Byte quota is charged before any range/clear, including not-yet-queued
    // targets. No physical host pages back these two128MiB local reservations.
    let a = file
        .gem
        .prepare_vram_class(128 << 20, None, &rig.pool, false)
        .unwrap();
    let b = file
        .gem
        .prepare_vram_class(128 << 20, None, &rig.pool, false)
        .unwrap();
    assert_eq!(file.gem.fixture_pending_usage(), (2, 256 << 20));
    assert_eq!(
        file.gem
            .prepare_vram_class(PAGE, None, &rig.pool, false)
            .err(),
        Some(FsError::OutOfMemory)
    );
    assert_eq!(
        file.gem.create(PAGE, |_, _| Ok(())),
        Err(FsError::OutOfMemory)
    );
    let foreign = crate::intel_gpu_gem::GemState::new();
    let ordinary = foreign
        .object(foreign.create(PAGE, |_, _| Ok(())).unwrap())
        .unwrap();
    assert_eq!(file.gem.import(&ordinary), Err(FsError::OutOfMemory));
    drop(a);
    assert_eq!(file.gem.fixture_pending_usage(), (1, 128 << 20));
    drop(b);
    assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
    let mut pending = Vec::new();
    for _ in 0..4096 {
        pending.push(
            file.gem
                .prepare_vram_class(PAGE, None, &rig.pool, false)
                .unwrap(),
        );
    }
    assert_eq!(file.gem.fixture_pending_usage(), (4096, 16 << 20));
    assert_eq!(
        file.gem.create(PAGE, |_, _| Ok(())),
        Err(FsError::OutOfMemory)
    );
    assert_eq!(file.gem.import(&ordinary), Err(FsError::OutOfMemory));
    drop(pending);
    assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
    request(&user, BO, 0, false);
    let info = rig.info.clone();
    let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(file.gem.fixture_pending_usage(), (1, BO));
    let (fence, weak) = rig.backend.accept(&mut rig.core);
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    drop(call);
    assert_eq!(file.gem.fixture_pending_usage(), (1, BO));
    assert!(weak.upgrade().is_some());
    rig.finish(&fence);
    assert!(weak.upgrade().is_none());
    assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
    let handle = rig.create(&file, &user, BO, 0);
    assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
    assert_eq!(rig.pool.used(), BO);
    file.gem.close(handle).unwrap();
    drop(ordinary);
    drop(foreign);
    drop(file);
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_pending_quota_follows_actual_job_graph
);
struct Reentrant<'a> {
    base: &'a Cpu,
    file: &'a RenderFile,
    info: &'a DeviceInfo,
    backend: &'a Backend,
    vm: u32,
    mode: u8,
    entered: core::sync::atomic::AtomicBool,
    reported: core::sync::atomic::AtomicU32,
}
impl IoctlContext for Reentrant<'_> {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.base.read(address, bytes)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
        if address == 64 && bytes.len() == 56 && !self.entered.swap(true, Ordering::AcqRel) {
            let handle = u32_at(bytes, 28);
            self.reported.store(handle, Ordering::Release);
            assert_eq!(self.file.gem.object(handle).err(), Some(FsError::NotFound));
            assert_eq!(self.file.gem.mmap_offset(handle), Err(FsError::NotFound));
            assert_eq!(self.file.gem.close(handle), Err(FsError::NotFound));
            assert_eq!(self.file.gem.fixture_pending_usage(), (1, BO));
            // Real reentrant ordinary raw Xe create+close must find no Owner,
            // Xe-names or GEM IRQ guard held by the outer output operation.
            let ordinary = create_bo(self.file, self.info, self.base, PAGE, 0);
            assert_ne!(ordinary, handle);
            assert_eq!(
                close(self.file, self.info, self.base, abi::GEM_CLOSE, ordinary),
                Ok(0)
            );
            if self.mode == 1 {
                assert_eq!(
                    close(self.file, self.info, self.base, xe::VM_DESTROY, self.vm),
                    Ok(0)
                );
                assert_ne!(create_vm(self.file, self.info, self.base), self.vm);
            } else if self.mode == 2 {
                return Err(FsError::BadAddress);
            } else if self.mode == 3 {
                let mut status = self.backend.ordinary.status.lock();
                status.as_mut().unwrap().epoch += 1;
            }
        }
        self.base.write(address, bytes)
    }
    fn nonblocking(&self) -> bool {
        false
    }
}
fn smoke_bmg_smallbar_reentrant_copyout_and_postcopyout_owner_transaction() -> TestResult {
    for mode in 0..5 {
        let mut rig = Rig::new(2, false);
        let file = RenderFile::new();
        let base = Cpu::new();
        let vm = if mode == 1 {
            create_vm(&file, &rig.info, &base)
        } else {
            0
        };
        let info = rig.info.clone();
        let backend = rig.backend.clone();
        {
            let user = Reentrant {
                base: &base,
                file: &file,
                info: &info,
                backend: &backend,
                vm,
                mode,
                entered: core::sync::atomic::AtomicBool::new(false),
                reported: core::sync::atomic::AtomicU32::new(0),
            };
            request(&base, BO, vm, false);
            let mut call = Box::pin(file.dispatch_user(&info, xe::GEM_CREATE, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let (fence, weak) = rig.backend.accept(&mut rig.core);
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            rig.finish(&fence);
            let step = call.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert!(user.entered.load(Ordering::Acquire));
            let handle = user.reported.load(Ordering::Acquire);
            assert_eq!(file.gem.object(handle).err(), Some(FsError::NotFound));
            let saved = rig.w().0.borrow().regs[&0x1080c0];
            if mode == 4 {
                rig.w()
                    .0
                    .borrow_mut()
                    .regs
                    .insert(0x1080c0, saved - (1 << 20));
            }
            let result = match step {
                Poll::Ready(value) => value,
                Poll::Pending => {
                    rig.backend.accept_publication(&mut rig.core);
                    ready(call.as_mut())
                }
            };
            drop(call);
            if mode == 0 {
                assert_eq!(result, Some(Ok(0)));
                assert!(file.gem.object(handle).is_ok());
                file.gem.close(handle).unwrap();
            } else {
                assert!(matches!(result, Some(Err(_))));
                assert_eq!(file.gem.object(handle).err(), Some(FsError::NotFound));
                assert!(weak.upgrade().is_none());
            }
            if mode == 3 {
                // An old create cannot erase the newer epoch it observed after
                // copyout; production Backend checks this before loss cleanup.
                assert_eq!(rig.backend.status().unwrap().epoch, rig.core.epoch + 1);
                rig.backend.ordinary.status.lock().as_mut().unwrap().epoch = rig.core.epoch;
            }
            rig.w().0.borrow_mut().regs.insert(0x1080c0, saved);
            assert_eq!(file.gem.fixture_pending_usage(), (0, 0));
        }
        drop(backend);
        drop(info);
        drop(file);
        rig.end();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_reentrant_copyout_and_postcopyout_owner_transaction
);
fn smoke_bmg_smallbar_mcr_contention_and_selector_restore_are_distinct() -> TestResult {
    let mut rig = Rig::new(2, false);
    let epoch = rig.core.epoch;
    let selector = rig.core.io.regs.borrow().selector;
    rig.core.io.regs.borrow_mut().busy = true;
    assert_eq!(rig.core.gt.vram_access(epoch), Err(GtError::Busy));
    assert_eq!(rig.core.gt.state(), GtState::SchedulingReady);
    let before = rig.core.arena.live_allocations();
    let (batch, _) =
        crate::intel_gpu_exec::PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    assert!(matches!(
        rig.core
            .gt
            .submit_user_batch(rig.core.now, UserContext::new(), UserBatch(batch)),
        Err(GtError::Busy)
    ));
    assert_eq!(rig.core.arena.live_allocations(), before);
    let start = rig.core.now;
    assert!(rig.core.gt.poll_with_access(start, || true).is_pending());
    assert!(rig
        .core
        .gt
        .poll_with_access(start + 49_999_999, || true)
        .is_pending());
    assert_eq!(rig.core.gt.state(), GtState::SchedulingReady);
    assert_eq!(rig.core.io.regs.borrow().selector, selector);
    assert!(!rig.core.io.regs.borrow().held);
    rig.core.io.regs.borrow_mut().busy = false;
    assert_eq!(
        rig.core.gt.poll_with_access(start + 49_999_999, || true),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    assert_eq!(rig.core.gt.vram_access(epoch), Ok(()));
    assert_eq!(rig.core.io.regs.borrow().selector, selector);
    assert!(!rig.core.io.regs.borrow().held);
    // Loss after acquiring/steering still restores the prior selector and
    // releases the semaphore; no successful current proof is returned.
    rig.core.io.regs.borrow_mut().absent = Some(0x8804);
    assert_eq!(rig.core.gt.vram_access(epoch), Err(GtError::Unavailable));
    assert_eq!(rig.core.io.regs.borrow().selector, selector);
    assert!(!rig.core.io.regs.borrow().held);
    rig.core.io.regs.borrow_mut().absent = None;
    rig.core.now = start + 50_000_000;
    rig.end();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_mcr_contention_and_selector_restore_are_distinct
);
mod physical {
    include!("intel_gpu_bmg_takeover_hw_tests.rs");
}
