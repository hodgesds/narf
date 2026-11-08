// Native Xe ioctl -> actual GuC/CT/private PPGTT conversations. No fence is
// completed by the fixture: device stores and retirement/reset establish it.
use super::*;
use crate::{drm::syncobj as so, intel_gpu_xe_uapi as xe};
use narf_filesystem::{IoctlContext, MmapBacking};

struct Cpu {
    wire: User,
    mapping: IrqSafeSpinLock<Option<MmapBacking>>,
    fail_report: core::sync::atomic::AtomicBool,
    pin_calls: core::sync::atomic::AtomicU32,
    /// The process's VMAs: 0x4000 read/write and 0x6000 read-only. USERPTR
    /// intervals register here, so the real address-space operations on it
    /// (munmap, mprotect, MADV_DONTNEED) fire them.
    space: narf_memory::AddressSpace,
    /// Collections that fire an invalidation of 0x4000 before returning,
    /// modelling a racing munmap/remap during the pin.
    invalidate_on_pin: core::sync::atomic::AtomicU32,
}
fn cpu_vma(base: u64, perms: narf_memory::RegionPerms) -> narf_memory::Region {
    narf_memory::Region {
        base: narf_memory::VirtAddr::new(base),
        len: 4096,
        perms,
        phys: alloc::vec![narf_memory::PhysAddr::new(0)].into(),
    }
}
impl Cpu {
    fn new() -> Self {
        use narf_memory::RegionPerms;
        let space = narf_memory::AddressSpace::empty();
        space
            .map_region(cpu_vma(0x4000, RegionPerms::READ | RegionPerms::WRITE))
            .unwrap();
        space
            .map_region(cpu_vma(0x6000, RegionPerms::READ))
            .unwrap();
        Self {
            wire: User::new(),
            mapping: IrqSafeSpinLock::new(None),
            fail_report: core::sync::atomic::AtomicBool::new(false),
            pin_calls: core::sync::atomic::AtomicU32::new(0),
            space,
            invalidate_on_pin: core::sync::atomic::AtomicU32::new(0),
        }
    }
}
impl IoctlContext for Cpu {
    fn read(&self, address: u64, data: &mut [u8]) -> Result<(), FsError> {
        self.wire.read(address, data)
    }
    fn write(&self, address: u64, data: &[u8]) -> Result<(), FsError> {
        if address == 64 && self.fail_report.load(core::sync::atomic::Ordering::Relaxed) {
            return Err(FsError::BadAddress);
        }
        self.wire.write(address, data)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    // Modeled process: the VMAs in `space` (0x4000 writable, 0x6000 a
    // read-only alias of the same page), each backed by `mapping`'s frame.
    fn pin_user_pages(
        &self,
        address: u64,
        pages: u64,
        writable: bool,
    ) -> Result<Vec<narf_memory::address_space::UserPagePin>, FsError> {
        use narf_memory::RegionPerms;
        self.pin_calls
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let racing = self
            .invalidate_on_pin
            .fetch_update(
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
                |left| left.checked_sub(1),
            )
            .is_ok();
        if racing {
            self.space
                .madvise_dontneed(narf_memory::VirtAddr::new(0x4000), 4096)
                .unwrap();
        }
        let perms: Vec<_> = (0..pages)
            .map(|page| {
                self.space
                    .lookup(narf_memory::VirtAddr::new(address + page * 4096))
                    .map(|vma| vma.perms)
            })
            .collect();
        let mapping = self.mapping.lock();
        let frame = mapping.as_ref().ok_or(FsError::BadAddress)?.frames[0];
        perms
            .into_iter()
            .map(|perms| match perms {
                Some(perms) if writable && !perms.contains(RegionPerms::WRITE) => {
                    Err(FsError::OperationNotPermitted)
                }
                Some(perms) if perms.contains(RegionPerms::READ) => Ok(()),
                _ => Err(FsError::BadAddress),
            })
            .map(|page| {
                page.map(|()| {
                    // SAFETY: the mapping's BO frame is a live allocator frame
                    // retained by `mapping` across this call.
                    unsafe {
                        narf_memory::address_space::UserPagePin::retain_ram(
                            narf_memory::PhysAddr::new(frame),
                        )
                    }
                })
            })
            .collect()
    }
    fn mmu_interval_notifier(
        &self,
        address: u64,
        length: u64,
        ops: Arc<dyn narf_memory::mmu_notifier::MmuIntervalNotifierOps>,
    ) -> Result<narf_memory::mmu_notifier::MmuIntervalNotifier, FsError> {
        narf_memory::mmu_notifier::MmuIntervalNotifier::insert(&self.space, address, length, ops)
            .map_err(|_| FsError::BadAddress)
    }
    fn address_space_identity(&self) -> Option<u64> {
        Some(self.space.identity())
    }
    fn read_u64_acquire(&self, address: u64) -> Result<u64, FsError> {
        if address & 7 != 0 {
            return Err(FsError::InvalidData);
        }
        if (0x4000..0x5000).contains(&address) {
            let mapping = self.mapping.lock();
            let mapping = mapping.as_ref().ok_or(FsError::BadAddress)?;
            let pointer = narf_memory::PhysAddr::new(mapping.frames[0] + address - 0x4000)
                .kernel_ptr::<core::sync::atomic::AtomicU64>();
            // SAFETY: the fixture retains the aligned coherent BO mapping.
            return Ok(unsafe { &*pointer }.load(core::sync::atomic::Ordering::Acquire));
        }
        Ok(u64_at(&self.wire.load(address, 8), 0))
    }
    fn write_u64_release(&self, address: u64, value: u64) -> Result<(), FsError> {
        if address & 7 != 0 {
            return Err(FsError::InvalidData);
        }
        self.wire.write(address, &value.to_le_bytes())
    }
}
#[derive(Debug)]
struct Native {
    mailbox: Arc<Mailbox>,
    facts: crate::intel_gpu_user::DeviceFacts,
    /// A published standalone media GT (native Xe gt_id 1), if any.
    media: Option<crate::intel_gpu_user::MediaGtStatus>,
}
impl UserBackend for Native {
    fn status(&self) -> Option<UserStatus> {
        self.mailbox.status()
    }
    fn media_gt(&self) -> Option<crate::intel_gpu_user::MediaGtStatus> {
        self.media
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
            if self.status().is_none_or(|status| {
                status.epoch != epoch || status.platform != GtPlatform::Battlemage
            }) {
                return Err(FsError::NoDevice);
            }
            let mut clear = object.begin_cpu_vram_clear()?;
            loop {
                // SAFETY: this native fixture exclusively owns its fake
                // LMEM RAM aperture, without PCI power transitions.
                if let Some(fence) = unsafe { clear.clear_next() } {
                    return Ok(fence);
                }
            }
        })
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.mailbox.submit(context, batch)
    }
}
fn setup<M: MmioWindow, A: BootAllocator>(
    gt: &mut GuCGt<M, A>,
    w: &Window,
    platform: GtPlatform,
) -> (Arc<Mailbox>, DeviceInfo) {
    setup_media(gt, w, platform, None)
}
fn setup_media<M: MmioWindow, A: BootAllocator>(
    gt: &mut GuCGt<M, A>,
    w: &Window,
    platform: GtPlatform,
    media: Option<crate::intel_gpu_user::MediaGtStatus>,
) -> (Arc<Mailbox>, DeviceInfo) {
    w.0.borrow_mut().regs.insert(0xd00, 0x1e); // 25MHz crystal, timestamp /1
    let facts = gt.device_facts().unwrap();
    assert_eq!(facts.reference_clock, 25_000_000);
    let mailbox = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
            engines: gt.engines().unwrap(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let info = DeviceInfo {
        device_id: match platform {
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake) => 0x9a49,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP) => 0x46a6,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS) => 0x4680,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeN) => 0x46d1,
            GtPlatform::Battlemage => 0xe20b,
            _ if platform.is_ptl() => 0xb080,
            _ if platform.is_lnl() => 0x6420,
            GtPlatform::Alchemist => 0x56a0,
            _ => 0x7d55,
        },
        platform,
        memory_bytes: 0x80000000,
        hwconfig: gt.hwconfig().map(|c| {
            Arc::new(
                crate::intel_gpu_hwconfig::HardwareConfig::parse(c.as_bytes().to_vec()).unwrap(),
            )
        }),
        topology: gt.topology().cloned().map(Arc::new),
        vram: None,
        backend: Some(Arc::new(Native {
            mailbox: mailbox.clone(),
            facts,
            media,
        })),
    };
    assert!(info.native_xe());
    (mailbox, info)
}
fn invoke(file: &RenderFile, info: &DeviceInfo, user: &Cpu, cmd: u32) -> Result<u64, FsError> {
    file.dispatch(info, cmd, 64, user)
        .expect("native ioctl handled")
}
fn create_vm(file: &RenderFile, info: &DeviceInfo, user: &Cpu) -> u32 {
    let mut wire = [0; 32];
    put32(&mut wire, 8, 1);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::VM_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 32), 12)
}
fn create_bo(file: &RenderFile, info: &DeviceInfo, user: &Cpu, size: u64, vm: u32) -> u32 {
    let mut wire = [0; 56];
    put64(&mut wire, 8, size);
    put32(&mut wire, 16, 1);
    put32(&mut wire, 24, vm);
    wire[32] = 1;
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::GEM_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 56), 28)
}
fn create_queue(file: &RenderFile, info: &DeviceInfo, user: &Cpu, vm: u32, class: u16) -> u32 {
    create_queue_instance(file, info, user, vm, class, 0)
}
fn create_queue_instance(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    class: u16,
    instance: u16,
) -> u32 {
    user.wire
        .store(512, &[class as u8, 0, instance as u8, 0, 0, 0, 0, 0]);
    let mut wire = [0; 48];
    put32(&mut wire, 8, 0x00010001);
    put32(&mut wire, 12, vm);
    put64(&mut wire, 24, 512);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}

fn smoke_xe_copy1_query_and_instance_platform_refusal() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Battlemage, 0xdfc),
        (GtPlatform::Alchemist, 0x130044),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (_, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let mut wire = [0; 40];
        user.wire.store(64, &wire);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        let size = u32_at(&user.wire.load(64, 40), 12);
        put32(&mut wire, 12, size);
        put64(&mut wire, 16, 1024);
        user.wire.store(64, &wire);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        let reply = user.wire.load(1024, size as usize);
        let mut expected = alloc::vec![(0u16, 0u16), (1, 0)];
        if platform == GtPlatform::Battlemage {
            expected.push((1, 1));
        }
        if gt
            .engines()
            .unwrap()
            .contains(crate::intel_gpu_engine::Engine::Ccs0)
        {
            expected.push((4, 0));
        }
        assert_eq!(size as usize, 8 + 32 * expected.len());
        assert_eq!(u32_at(&reply, 0) as usize, expected.len());
        assert!(reply[4..8].iter().all(|byte| *byte == 0));
        for (entry, (class, instance)) in reply[8..].chunks_exact(32).zip(expected) {
            assert_eq!(&entry[..2], &class.to_le_bytes());
            assert_eq!(&entry[2..4], &instance.to_le_bytes());
            assert!(entry[4..].iter().all(|byte| *byte == 0));
        }
        let vm = create_vm(&file, &info, &user);
        for instance in [1u8, 2, 8] {
            if instance == 1 && platform == GtPlatform::Battlemage {
                continue;
            }
            user.wire.store(512, &[1, 0, instance, 0, 0, 0, 0, 0]);
            let mut queue = [0; 48];
            put32(&mut queue, 8, 0x00010001);
            put32(&mut queue, 12, vm);
            put64(&mut queue, 24, 512);
            user.wire.store(64, &queue);
            assert_eq!(
                invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
                Err(FsError::InvalidData)
            );
        }
        let before = arena.live_allocations();
        if platform != GtPlatform::Battlemage {
            assert!(gt
                .submit_ppgtt_probe_on(200, crate::intel_gpu_engine::Engine::Bcs8)
                .is_err());
            assert_eq!(arena.live_allocations(), before);
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_bcs8",
    smoke_xe_copy1_query_and_instance_platform_refusal
);
fn mapping(object: u32, va: u64, offset: u64, length: u64, pat: u16, flags: u32) -> [u8; 80] {
    let mut wire = [0; 80];
    put32(&mut wire, 8, object);
    wire[12..14].copy_from_slice(&pat.to_le_bytes());
    put64(&mut wire, 16, offset);
    put64(&mut wire, 24, length);
    put64(&mut wire, 32, va);
    put32(&mut wire, 44, flags);
    wire
}
fn bind_wire(user: &Cpu, vm: u32, operations: &[[u8; 80]], syncs: &[[u8; 48]]) {
    let mut wire = [0; 136];
    put32(&mut wire, 8, vm);
    put32(&mut wire, 20, operations.len() as u32);
    if operations.len() == 1 {
        wire[24..104].copy_from_slice(&operations[0]);
    } else if !operations.is_empty() {
        put64(&mut wire, 24, 1024);
        user.wire.store(1024, &operations.concat());
    }
    put32(&mut wire, 108, syncs.len() as u32);
    put64(&mut wire, 112, 2048);
    user.wire.store(2048, &syncs.concat());
    user.wire.store(64, &wire);
}
fn sync(kind: u32, handle: u64, point: u64, signal: bool) -> [u8; 48] {
    let mut wire = [0; 48];
    put32(&mut wire, 8, kind);
    put32(&mut wire, 12, u32::from(signal));
    put64(&mut wire, 16, handle);
    put64(&mut wire, 24, point);
    wire
}
fn exec_wire(user: &Cpu, queue: u32, batch: bool, syncs: &[[u8; 48]]) {
    let mut wire = [0; 56];
    put32(&mut wire, 8, queue);
    put32(&mut wire, 12, syncs.len() as u32);
    put64(&mut wire, 16, 2048);
    if batch {
        put64(&mut wire, 24, 0x1234_0000_0000);
        wire[32] = 1;
    }
    user.wire.store(2048, &syncs.concat());
    user.wire.store(64, &wire);
}
fn bind_now(file: &RenderFile, info: &DeviceInfo, user: &Cpu) -> Result<u64, FsError> {
    narf_scheduler::block_on_spin(file.dispatch_user(info, xe::VM_BIND, 64, user)).expect("VM bind")
}
fn close(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    cmd: u32,
    id: u32,
) -> Result<u64, FsError> {
    let mut wire = [0; 24];
    put32(&mut wire, 0, id);
    user.wire.store(64, &wire);
    invoke(file, info, user, cmd)
}
fn buffers(file: &RenderFile, info: &DeviceInfo, user: &Cpu, vm: u32) -> [u32; 2] {
    let code = create_bo(file, info, user, 8192, 0);
    let data = create_bo(file, info, user, 4096, 0);
    let words = [0x10000002u32, 0x80, 0x2345, 0x4e415246, 0x05000000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem.object(code).unwrap().write(4096, &bytes).unwrap();
    *user.mapping.lock() = Some(file.gem.object(data).unwrap().backing(0, 4096).unwrap());
    let pat = match info.platform {
        GtPlatform::Alchemist | GtPlatform::Gen12(_) => 0,
        _ if info.platform.is_headless_integrated() => 2,
        GtPlatform::Battlemage => 2,
        _ => 3,
    };
    bind_wire(
        user,
        vm,
        &[
            mapping(code, 0x1234_0000_0000, 4096, 4096, pat, 1),
            mapping(data, 0x2345_0000_0000, 0, 4096, pat, 0),
        ],
        &[],
    );
    assert_eq!(bind_now(file, info, user), Ok(0));
    [code, data]
}
fn finish(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
) {
    finish_policy(gt, w, fence, registered, start, 2);
}

fn finish_policy<M: MmioWindow, A: BootAllocator>(
    gt: &mut GuCGt<M, A>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
    priority: u32,
) {
    for now in start..start + 60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        // Native queues retain their selected high1/normal2/low3 policy;
        // trusted probes use low3. Keep the literal policy and KLV checks.
        {
            let memory = ct_memory(w);
            let words = memory.borrow();
            let mut head = words[0];
            let tail = words[1];
            while head != tail {
                let length = words[1024 + head as usize] & 255;
                if words[1024 + ((head + 1) & 1023) as usize] as u16 == 0x100b {
                    assert_eq!(words[1024 + ((head + 4) & 1023) as usize], priority);
                    assert_eq!(words[1024 + ((head + 6) & 1023) as usize], 1000);
                }
                head = (head + length + 1) & 1023;
            }
        }
        service_contexts(w, registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
}

fn ready<F: Future + ?Sized>(mut future: core::pin::Pin<&mut F>) -> F::Output {
    for _ in 0..1_000_000 {
        if let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
        narf_scheduler::sleep_pumps::run();
    }
    panic!("native Xe future did not resume within its poll budget");
}

fn smoke_xe_native_exec_user_fence_close_and_retirement() -> TestResult {
    // RENDER, then COPY: the same PPGTT batch and user fence on BCS0.
    for (platform, ack, class, logical) in [
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
            0x130044,
        ),
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP),
            0x130044,
        ),
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS),
            0x130044,
        ),
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeN),
            0x130044,
        ),
        (GtPlatform::Battlemage, 0xdfc),
        (GtPlatform::Alchemist, 0x130044),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
    ]
    .into_iter()
    .flat_map(|(platform, ack)| {
        [(0u16, 0u16), (1, 0), (1, 1), (4, 0)]
            .into_iter()
            .filter(move |(_, logical)| *logical == 0 || platform == GtPlatform::Battlemage)
            .map(move |(class, logical)| (platform, ack, class, logical))
    }) {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let ccs = gt
            .engines()
            .unwrap()
            .contains(crate::intel_gpu_engine::Engine::Ccs0);
        // Xe-LPG always has CCS0, so the compute path is exercised.
        assert!(ccs || !matches!(platform, GtPlatform::Integrated(_)));
        if class == 4 && !ccs {
            hardware_stop(&mut gt, &w, ack);
            continue;
        }
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        if platform.is_gen12() && !platform.has_hwconfig() {
            let mut query = [0; 40];
            put32(&mut query, 8, 4);
            put64(&mut query, 16, u64::MAX);
            user.wire.store(64, &query);
            assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
            assert_eq!(u32_at(&user.wire.load(64, 40), 12), 0);
            put32(&mut query, 12, 4);
            user.wire.store(64, &query);
            assert_eq!(
                invoke(&file, &info, &user, xe::DEVICE_QUERY),
                Err(FsError::InvalidData)
            );
        }
        let origin = if platform.is_gen12() { 20_000_000 } else { 0 };
        let vm = create_vm(&file, &info, &user);
        // VIDEO_DECODE, VIDEO_ENHANCE, unknown classes, and COMPUTE when
        // CCS0 is fused off are not admitted engines.
        for refused in [2u8, 3, 6].into_iter().chain((!ccs).then_some(4)) {
            user.wire.store(512, &[refused, 0, 0, 0, 0, 0, 0, 0]);
            let mut wire = [0; 48];
            put32(&mut wire, 8, 0x00010001);
            put32(&mut wire, 12, vm);
            put64(&mut wire, 24, 512);
            user.wire.store(64, &wire);
            assert_eq!(
                invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
                Err(FsError::InvalidData)
            );
        }
        let queue = create_queue_instance(&file, &info, &user, vm, class, logical);
        let handles = buffers(&file, &info, &user, vm);
        let objects = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
        let output = file.syncobjs.lock().create(0).unwrap();
        let core = file.syncobjs.lock().get(output).unwrap().core().clone();
        let value = 0x1122334455667788;
        exec_wire(
            &user,
            queue,
            true,
            &[
                sync(1, u64::from(output), 9, true),
                sync(2, 0x2345_0000_0090, value, true),
            ],
        );
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, origin + 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        let payload = core.find_fence(9).unwrap();
        let exact: Arc<dyn narf_filesystem::DrmFence> = fence.clone();
        assert!(so::to_drm_leaves(&payload)
            .iter()
            .any(|leaf| Arc::ptr_eq(leaf, &exact)));
        assert!(!payload.is_signalled());
        for handle in handles {
            assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
        }
        assert_eq!(
            close(&file, &info, &user, xe::VM_DESTROY, vm),
            Err(FsError::Busy)
        );
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
        assert!(objects.iter().all(|object| object.upgrade().is_some()));
        let mut registered = BTreeMap::new();
        for now in origin + 101..origin + 120 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if user.read_u64_acquire(0x4090).unwrap() == value {
                break;
            }
        }
        assert_eq!(user.read_u64_acquire(0x4090), Ok(value));
        // The batch's MI_STORE_DATA_IMM executed on the selected engine.
        assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
        let engine_base = match class {
            1 if logical == 1 => 0x3ee244,
            1 => 0x22244,
            4 => 0x1a244,
            _ => 0x2244,
        };
        assert!(registered
            .values()
            .all(|base| { w.0.borrow().memory[base].borrow()[1024 + 2] == engine_base }));
        assert_eq!(
            fence.result(),
            None,
            "user fence was fabricated from terminal completion"
        );
        let mut wait = [0; 72];
        put64(&mut wait, 8, 0x4090);
        put64(&mut wait, 24, value);
        put64(&mut wait, 32, u64::MAX);
        user.wire.store(64, &wait);
        assert_eq!(
            narf_scheduler::block_on_spin(file.dispatch_user(
                &info,
                xe::WAIT_USER_FENCE,
                64,
                &user
            )),
            Some(Ok(0))
        );
        finish(&mut gt, &w, &fence, &mut registered, origin + 120);
        assert!(registered.is_empty());
        assert!(payload.is_signalled());
        assert!(objects[0].upgrade().is_none());
        user.mapping.lock().take();
        assert!(objects[1].upgrade().is_none());
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_native_exec_user_fence_close_and_retirement
);

fn userptr_op(va: u64, address: u64, length: u64, pat: u16, flags: u32) -> [u8; 80] {
    let mut op = mapping(0, va, address, length, pat, flags);
    put32(&mut op, 40, 2); // DRM_XE_VM_BIND_OP_MAP_USERPTR
    op
}

fn smoke_xe_userptr_bind_exec_validation_and_retirement() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    for (platform, ack) in [
        (GtPlatform::Battlemage, 0xdfc),
        (GtPlatform::Alchemist, 0x130044),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_queue(&file, &info, &user, vm, 0);
        let handles = buffers(&file, &info, &user, vm);
        let pat = match platform {
            GtPlatform::Alchemist => 0,
            GtPlatform::Battlemage => 2,
            _ => 3,
        };
        // The process's own page: a separate allocation from the data BO.
        let host = create_bo(&file, &info, &user, 4096, 0);
        let host_object = file.gem.object(host).unwrap();
        *user.mapping.lock() = Some(host_object.backing(0, 4096).unwrap());
        let data = file.gem.object(handles[1]).unwrap();
        // vm_bind_ioctl_check_args refusals, before any page is faulted.
        for op in [
            {
                let mut op = userptr_op(0x2345_0000_0000, 0x4000, 4096, pat, 0);
                put32(&mut op, 8, handles[1]); // an object with MAP_USERPTR
                op
            },
            userptr_op(0x2345_0000_0000, 0x4000, 4096, pat, 4), // NULL
            userptr_op(0x2345_0000_0000, 0x4008, 4096, pat, 0), // unaligned
            userptr_op(0x2345_0000_0000, 0x4000, 4096, 15, 0),  // PAT
        ] {
            bind_wire(&user, vm, &[op], &[]);
            assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
        }
        // A later op's EINVAL wins over an earlier op's unmapped range.
        let mut bad = mapping(0, 0x3000_0000_0000, 0, 4096, pat, 0);
        put32(&mut bad, 40, 7);
        bind_wire(
            &user,
            vm,
            &[userptr_op(0x2345_0000_0000, 0x8000, 4096, pat, 0), bad],
            &[],
        );
        assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
        assert_eq!(user.pin_calls.load(Relaxed), 0);
        // Fault classes: unmapped is EFAULT, a write pin of a read-only page EPERM.
        for (address, flags, expected) in [
            (0x8000, 0, FsError::BadAddress),
            (0x4000, 0, FsError::BadAddress), // second page unmapped
            (0x6000, 0, FsError::OperationNotPermitted),
        ] {
            let length = if address == 0x4000 { 8192 } else { 4096 };
            bind_wire(
                &user,
                vm,
                &[userptr_op(0x2345_0000_0000, address, length, pat, flags)],
                &[],
            );
            assert_eq!(bind_now(&file, &info, &user), Err(expected));
        }
        // A READONLY pin of the read-only alias is admitted.
        bind_wire(
            &user,
            vm,
            &[userptr_op(0x3000_0000_0000, 0x6000, 4096, pat, 1)],
            &[],
        );
        assert_eq!(bind_now(&file, &info, &user), Ok(0));
        // Replace the data BO's VA with the process page and execute.
        bind_wire(
            &user,
            vm,
            &[userptr_op(0x2345_0000_0000, 0x4000, 4096, pat, 0)],
            &[],
        );
        assert_eq!(bind_now(&file, &info, &user), Ok(0));
        exec_wire(&user, queue, true, &[]);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        // Unbinding while the job is live keeps its pins until retirement.
        let mut unmap = mapping(0, 0x2345_0000_0000, 0, 4096, 0, 0);
        put32(&mut unmap, 40, 1);
        bind_wire(&user, vm, &[unmap], &[]);
        let mut unbind = core::pin::pin!(file.dispatch_user(&info, xe::VM_BIND, 64, &user));
        let _ = unbind
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let mut registered = BTreeMap::new();
        finish(&mut gt, &w, &fence, &mut registered, 101);
        assert_eq!(ready(unbind.as_mut()), Some(Ok(0)));
        assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
        let mut value = [0; 4];
        data.read(0x80, &mut value).unwrap();
        assert_eq!(value, [0; 4], "the store reached the replaced data BO");
        drop(data);
        drop(host_object);
        user.mapping.lock().take();
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_userptr_bind_exec_validation_and_retirement
);

/// One EXEC on `queue` from `user`: an immediate refusal is returned as is;
/// an admitted job is accepted, retired, and reported as `Ok(0)`.
#[allow(clippy::too_many_arguments)]
fn userptr_exec(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    queue: u32,
    batch: bool,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    registered: &mut BTreeMap<u32, u32>,
    now: u64,
) -> Result<u64, FsError> {
    exec_wire(user, queue, batch, &[]);
    let mut call = core::pin::pin!(file.dispatch_user(info, xe::EXEC, 64, user));
    if let Poll::Ready(result) = call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        return result.expect("native ioctl handled");
    }
    let (_, fence) = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    finish(gt, w, &fence, registered, now + 1);
    Ok(0)
}

/// MAP_USERPTR against CPU mapping changes (xe_userptr.c, xe_vm_userptr_pin):
/// an unchanged binding is not re-collected; munmap + remap makes the next
/// exec re-collect and the store reach only the new page; a writable binding
/// over memory made read-only fails the exec with EPERM and stays
/// invalidated; another process cannot re-collect it; a range that is gone
/// loses its GPU mapping while the exec proceeds; and a collection raced by
/// an invalidation is retried, ENOMEM once every round is raced.
fn smoke_xe_userptr_invalidation_repins_zaps_and_refuses() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    use narf_memory::{mmu_notifier::registered_intervals, RegionPerms, VirtAddr};
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let ack = 0xdfc;
    let pat = 3;
    let (w, arena, mut gt) = hardware_model(platform, ack);
    prime(&mut gt, &w, ack);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let baseline = registered_intervals();
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 0);
    let _ = buffers(&file, &info, &user, vm);
    let host = create_bo(&file, &info, &user, 4096, 0);
    let host_object = file.gem.object(host).unwrap();
    *user.mapping.lock() = Some(host_object.backing(0, 4096).unwrap());
    let mut registered = BTreeMap::new();
    let mut exec = |user: &Cpu, batch: bool, now: u64, gt: &mut GuCGt<Window, Arena>| {
        userptr_exec(
            &file,
            &info,
            user,
            queue,
            batch,
            &mailbox,
            gt,
            &w,
            &mut registered,
            now,
        )
    };

    // The batch's store targets 0x2345_0000_0080: bind the process page there.
    bind_wire(
        &user,
        vm,
        &[userptr_op(0x2345_0000_0000, 0x4000, 4096, pat, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert_eq!(registered_intervals(), baseline + 1);
    let pins = user.pin_calls.load(Relaxed);
    assert_eq!(exec(&user, true, 100, &mut gt), Ok(0));
    assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
    assert_eq!(
        user.pin_calls.load(Relaxed),
        pins,
        "an unchanged binding was re-collected"
    );

    // munmap + mmap of a new page at the bound CPU address.
    host_object.write(0x80, &[0; 8]).unwrap();
    let fresh = create_bo(&file, &info, &user, 4096, 0);
    let fresh_object = file.gem.object(fresh).unwrap();
    user.space.punch_fixed(VirtAddr::new(0x4000), 4096).unwrap();
    user.space
        .map_region(cpu_vma(0x4000, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    *user.mapping.lock() = Some(fresh_object.backing(0, 4096).unwrap());
    assert_eq!(exec(&user, true, 200, &mut gt), Ok(0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 1);
    let mut value = [0; 4];
    fresh_object.read(0x80, &mut value).unwrap();
    assert_eq!(u32::from_le_bytes(value), 0x4e415246);
    host_object.read(0x80, &mut value).unwrap();
    assert_eq!(value, [0; 4], "the GPU reached the unmapped page");
    assert_eq!(
        registered_intervals(),
        baseline + 1,
        "the re-collected binding kept its old interval"
    );

    // mprotect(PROT_READ) under a writable binding: EPERM, still invalidated.
    user.space
        .mprotect_range(VirtAddr::new(0x4000), 4096, RegionPerms::READ)
        .unwrap();
    assert_eq!(
        exec(&user, false, 300, &mut gt),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(user.pin_calls.load(Relaxed), pins + 2);
    user.space
        .mprotect_range(
            VirtAddr::new(0x4000),
            4096,
            RegionPerms::READ | RegionPerms::WRITE,
        )
        .unwrap();
    assert_eq!(exec(&user, false, 400, &mut gt), Ok(0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 3);

    // Another process executing on the shared VM cannot re-collect it.
    user.space
        .madvise_dontneed(VirtAddr::new(0x4000), 4096)
        .unwrap();
    let other = Cpu::new();
    assert_eq!(
        exec(&other, false, 500, &mut gt),
        Err(FsError::NotImplemented)
    );
    assert_eq!(other.pin_calls.load(Relaxed), 0);

    // munmap without a replacement: the binding loses its GPU mapping and
    // its interval, and the exec proceeds; later execs do not retry it.
    user.space.punch_fixed(VirtAddr::new(0x4000), 4096).unwrap();
    assert_eq!(exec(&user, false, 600, &mut gt), Ok(0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 4);
    assert_eq!(registered_intervals(), baseline);
    assert_eq!(exec(&user, false, 700, &mut gt), Ok(0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 4);

    // A collection raced by an invalidation is retried under a fresh
    // read_begin; one raced in every round is ENOMEM.
    user.space
        .map_region(cpu_vma(0x4000, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    user.invalidate_on_pin.store(1, Relaxed);
    bind_wire(
        &user,
        vm,
        &[userptr_op(0x3000_0000_0000, 0x4000, 4096, pat, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 6);
    user.invalidate_on_pin
        .store(crate::intel_gpu_xe_vm::USERPTR_PIN_ROUNDS as u32, Relaxed);
    bind_wire(
        &user,
        vm,
        &[userptr_op(0x3100_0000_0000, 0x4000, 4096, pat, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::OutOfMemory));
    assert_eq!(
        user.pin_calls.load(Relaxed),
        pins + 6 + crate::intel_gpu_xe_vm::USERPTR_PIN_ROUNDS as u32
    );
    assert_eq!(registered_intervals(), baseline + 1);

    drop(host_object);
    drop(fresh_object);
    user.mapping.lock().take();
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    assert_eq!(registered_intervals(), baseline);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_userptr_invalidation_repins_zaps_and_refuses
);

fn xe_query(file: &RenderFile, info: &DeviceInfo, user: &Cpu, id: u32) -> Vec<u8> {
    let mut wire = [0; 40];
    put32(&mut wire, 8, id);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::DEVICE_QUERY), Ok(0));
    let size = u32_at(&user.wire.load(64, 40), 12);
    put32(&mut wire, 12, size);
    put64(&mut wire, 16, 4096);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::DEVICE_QUERY), Ok(0));
    user.wire.load(4096, size as usize)
}

fn create_placed(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    size: u64,
    placement: u32,
    flags: u32,
    caching: u16,
) -> Result<u32, FsError> {
    let mut wire = [0; 56];
    put64(&mut wire, 8, size);
    put32(&mut wire, 16, placement);
    put32(&mut wire, 20, flags);
    wire[32..34].copy_from_slice(&caching.to_le_bytes());
    user.wire.store(64, &wire);
    let mut call = core::pin::pin!(file.dispatch_user(info, xe::GEM_CREATE, 64, user));
    ready(call.as_mut())
        .unwrap()
        .map(|_| u32_at(&user.wire.load(64, 56), 28))
}

fn smoke_xe_vram_placement_queries_mmap_execution_and_reuse() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, mut info) = setup(&mut gt, &w, platform);
    // Fake LMEM BAR: 16 contiguous RAM pages; device address 0 is its base.
    let frame = narf_memory::frame::alloc_pages_on(0, 4).unwrap();
    let base = frame.start_address().raw();
    let bytes = 16 * 4096;
    // SAFETY: the fixture owns these frames until after the pool is gone.
    unsafe { core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0xa5, bytes) };
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_ptr::<u8>() as u64,
        len: bytes as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = crate::intel_gpu_vram::VramLayout {
        tile_size: bytes as u64,
        tile_offset: 0,
        usable: bytes as u64,
    };
    // SAFETY: the frames are exclusively owned by this fixture pool.
    let vram = unsafe { crate::intel_gpu_vram::Vram::new(bar, layout) }.unwrap();
    info.vram = Some(vram.clone());
    FIXTURE_VRAM.store(base, core::sync::atomic::Ordering::Relaxed);
    let file = RenderFile::new();
    let user = Cpu::new();
    // MEM_REGIONS: SYSMEM/0 then VRAM/1; CONFIG HAS_VRAM; GT near=VRAM.
    let regions = xe_query(&file, &info, &user, 1);
    assert_eq!(regions.len(), 8 + 2 * 88);
    assert_eq!(u32_at(&regions, 0), 2);
    assert_eq!(&regions[96..100], &[1, 0, 1, 0]);
    assert_eq!(u32_at(&regions, 100), 4096);
    assert_eq!(
        [
            u64_at(&regions, 104),
            u64_at(&regions, 112),
            u64_at(&regions, 120)
        ],
        [bytes as u64, 0, bytes as u64]
    );
    assert_eq!(u64_at(&xe_query(&file, &info, &user, 2), 16), 11);
    let gt_list = xe_query(&file, &info, &user, 3);
    assert_eq!((u64_at(&gt_list, 24), u64_at(&gt_list, 32)), (2, 1));
    // xe_gem_create_ioctl EINVAL classes.
    for (placement, flags, caching) in [
        (4, 0, 2), // no such region
        (0, 0, 2),
        (2, 0, 1), // VRAM requires WC
        (2, 0, 0),
        (2, 0, 3),
        (1, 4, 2), // NEEDS_VISIBLE_VRAM without VRAM placement
    ] {
        assert_eq!(
            create_placed(&file, &info, &user, 8192, placement, flags, caching),
            Err(FsError::InvalidData)
        );
    }
    assert_eq!(vram.used(), 0);
    let handle = create_placed(&file, &info, &user, 8192, 2, 4, 2).unwrap();
    let object = file.gem.object(handle).unwrap();
    assert!(object.is_vram());
    assert_eq!(vram.used(), 8192);
    // Prior owner bytes never reach the new object.
    let mut prior = [0xffu8; 8192];
    object.read(0, &mut prior).unwrap();
    assert!(prior.iter().all(|b| *b == 0));
    let cpu_view = object.backing(0, 8192).unwrap();
    assert_eq!(
        cpu_view.memory_type,
        narf_memory::MemoryType::WriteCombining
    );
    let dpa = object.pages().next().unwrap();
    assert_eq!(cpu_view.frames, [base + dpa, base + dpa + 4096]);
    drop(cpu_view);
    assert_eq!(
        file.gem.export_object(handle).err(),
        Some(FsError::NotImplemented)
    );
    assert_eq!(u64_at(&xe_query(&file, &info, &user, 1), 112), 8192);
    // Execute: the batch's store lands in VRAM through a DM-bit PPGTT leaf.
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 1);
    buffers(&file, &info, &user, vm);
    bind_wire(
        &user,
        vm,
        &[mapping(handle, 0x2345_0000_0000, 0, 4096, 2, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    exec_wire(&user, queue, true, &[]);
    let fence = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &fence, &mut registered, 101);
    let mut stored = [0; 4];
    object.read(0x80, &mut stored).unwrap();
    assert_eq!(u32_at(&stored, 0), 0x4e415246);
    // Exhaustion: VRAM-only is ENOMEM; VRAM|SYSTEM falls back to system.
    let rest = bytes as u64 - 8192 + 4096;
    assert_eq!(
        create_placed(&file, &info, &user, rest, 2, 0, 2),
        Err(FsError::OutOfMemory)
    );
    let fallback = create_placed(&file, &info, &user, rest, 3, 0, 2).unwrap();
    assert!(!file.gem.object(fallback).unwrap().is_vram());
    // Release returns VRAM only after the VM, queue and handle drop it.
    drop(object);
    assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
    assert_eq!(vram.used(), 8192, "VM bindings still retain the object");
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    drop(file);
    assert_eq!(vram.used(), 0);
    FIXTURE_VRAM.store(0, core::sync::atomic::Ordering::Relaxed);
    drop(info);
    drop(vram);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    narf_memory::frame::free_pages(frame, 4);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_vram_placement_queries_mmap_execution_and_reuse
);

/// A hung EXEC is taken off the engine alone (GuC engine reset) and bans its
/// queue: GET_PROPERTY(BAN) reports it and the next EXEC is ECANCELED before
/// any sync is parsed (xe_exec_ioctl reset_status). A new queue on the same
/// VM still executes.
fn smoke_xe_hung_exec_bans_only_its_queue() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 0);
    buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let hung = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let mut registered = BTreeMap::new();
    let mut id = None;
    for now in 101..130 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        id = id.or(registered.keys().next().copied());
    }
    let id = id.expect("hung context registered");
    let ban = |user: &Cpu, queue: u32| {
        let mut wire = [0; 40];
        put32(&mut wire, 8, queue);
        user.wire.store(64, &wire);
        assert_eq!(
            invoke(&file, &info, user, xe::EXEC_QUEUE_GET_PROPERTY),
            Ok(0)
        );
        u64_at(&user.wire.load(64, 40), 16)
    };
    assert_eq!(ban(&user, queue), 0);
    // Refusals return from the first poll, before any await.
    let exec_now = |file: &RenderFile, info: &DeviceInfo, user: &Cpu| match core::pin::pin!(
        file.dispatch_user(info, xe::EXEC, 64, user)
    )
    .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Some(result)) => result,
        _ => panic!("EXEC refusal parked"),
    };
    let late = 5_000_000_130;
    assert_eq!(gt.poll(late), Poll::Ready(Ok(GtState::SchedulingReady)));
    event(&ct_memory(&w), 0x1008, &[id]);
    for now in late..late + 60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        if hung.result().is_some() {
            break;
        }
    }
    assert_eq!(
        hung.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Hang))
    );
    assert_eq!(ban(&user, queue), 1);
    // ECANCELED precedes sync parsing: a sync array at an unmapped address
    // would otherwise fault.
    exec_wire(&user, queue, true, &[]);
    let mut wire = user.wire.load(64, 56);
    put32(&mut wire, 12, 1);
    put64(&mut wire, 16, 0xdead_0000);
    user.wire.store(64, &wire);
    assert_eq!(exec_now(&file, &info, &user), Err(FsError::Canceled));
    // xe_exec_ioctl looks the queue up before checking the batch count.
    put32(&mut wire, 8, 0x7777);
    put32(&mut wire, 12, 0);
    wire[32] = 2;
    user.wire.store(64, &wire);
    assert_eq!(exec_now(&file, &info, &user), Err(FsError::NotFound));
    put32(&mut wire, 8, queue);
    user.wire.store(64, &wire);
    assert_eq!(exec_now(&file, &info, &user), Err(FsError::InvalidData));
    // Another queue on the same VM runs: the GT kept its epoch.
    let other = create_queue(&file, &info, &user, vm, 0);
    assert_eq!(ban(&user, other), 0);
    exec_wire(&user, other, true, &[]);
    let fence = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, late + 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    finish(&mut gt, &w, &fence, &mut registered, late + 101);
    assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
    user.mapping.lock().take();
    for queue in [queue, other] {
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
    }
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    drop(file);
    drop(info);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_hung_exec_bans_only_its_queue
);

/// DRM_XE_GEM_CPU_CACHING_WC on the iGPU: pages retyped write-combining for
/// the object's lifetime, a WC mmap, SCANOUT only with WC, XE_COH_NONE binds
/// only for WC objects, and a GPU store through a PAT1 leaf.
fn smoke_xe_igpu_wc_objects_scanout_noncoherent_binds_and_restore() -> TestResult {
    use narf_memory::pageattr::ram_memory_type;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let wc_type = Some(narf_memory::MemoryType::WriteCombining);
    // xe_gem_create_ioctl: scanout is never coherent with a WB CPU cache;
    // NEEDS_VISIBLE_VRAM is not an iGPU flag.
    assert_eq!(
        create_placed(&file, &info, &user, 8192, 1, 2, 1),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        create_placed(&file, &info, &user, 8192, 1, 4, 2),
        Err(FsError::InvalidData)
    );
    let wb = create_placed(&file, &info, &user, 4096, 1, 0, 1).unwrap();
    if !cfg!(target_arch = "x86_64") {
        // Only x86_64 retypes kernel RAM aliases.
        assert_eq!(
            create_placed(&file, &info, &user, 8192, 1, 2, 2),
            Err(FsError::NotImplemented)
        );
        drop(file);
        drop(info);
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        return TestResult::Pass;
    }
    let wc = create_placed(&file, &info, &user, 8192, 1, 2, 2).unwrap();
    let object = file.gem.object(wc).unwrap();
    assert!(object.is_wc() && !file.gem.object(wb).unwrap().is_wc());
    let pages: Vec<u64> = object.pages().collect();
    assert_eq!(pages.len(), 2);
    for page in &pages {
        assert_eq!(ram_memory_type(narf_memory::PhysAddr::new(*page)), wc_type);
    }
    let mut prior = [0xffu8; 8192];
    object.read(0, &mut prior).unwrap();
    assert!(prior.iter().all(|b| *b == 0));
    object.write(4000, b"narf").unwrap();
    let mut back = [0; 4];
    object.read(4000, &mut back).unwrap();
    assert_eq!(&back, b"narf");
    let view = object.backing(0, 8192).unwrap();
    assert_eq!(view.memory_type, narf_memory::MemoryType::WriteCombining);
    assert_eq!(view.frames, pages);
    drop(view);
    // xe_vm_bind_ioctl_validate_bo: XE_COH_NONE needs a non-WB object. PAT0 is
    // left to firmware and refused; a missing handle is ENOENT first.
    let vm = create_vm(&file, &info, &user);
    for (handle, pat, expected) in [
        (wb, 1, Err(FsError::InvalidData)),
        (wb, 2, Err(FsError::InvalidData)),
        (wc, 0, Err(FsError::InvalidData)),
        (wc, 5, Err(FsError::InvalidData)),
        (0x7fff_0000, 1, Err(FsError::NotFound)),
    ] {
        bind_wire(
            &user,
            vm,
            &[mapping(handle, 0x5000_0000, 0, 4096, pat, 0)],
            &[],
        );
        assert_eq!(bind_now(&file, &info, &user), expected, "pat {pat}");
    }
    for (va, pat) in [(0x6000_0000, 2), (0x7000_0000, 3)] {
        bind_wire(&user, vm, &[mapping(wc, va, 0, 8192, pat, 0)], &[]);
        assert_eq!(bind_now(&file, &info, &user), Ok(0));
    }
    // A GPU store lands in the WC object through a PAT1 leaf.
    let code = create_bo(&file, &info, &user, 8192, 0);
    let words = [0x10000002u32, 0x80, 0x2345, 0x4e415246, 0x05000000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem.object(code).unwrap().write(4096, &bytes).unwrap();
    *user.mapping.lock() = Some(object.backing(0, 4096).unwrap());
    bind_wire(
        &user,
        vm,
        &[
            mapping(code, 0x1234_0000_0000, 4096, 4096, 3, 1),
            mapping(wc, 0x2345_0000_0000, 0, 4096, 1, 0),
        ],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    let queue = create_queue(&file, &info, &user, vm, 1);
    exec_wire(&user, queue, true, &[]);
    let fence = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &fence, &mut registered, 101);
    let mut stored = [0; 4];
    object.read(0x80, &mut stored).unwrap();
    assert_eq!(u32_at(&stored, 0), 0x4e415246);
    // Pages return write-back only once mappings, binds and the handle go.
    *user.mapping.lock() = None;
    drop(object);
    assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, wc), Ok(0));
    assert_eq!(
        ram_memory_type(narf_memory::PhysAddr::new(pages[0])),
        wc_type
    );
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    drop(file);
    for page in &pages {
        assert_eq!(ram_memory_type(narf_memory::PhysAddr::new(*page)), None);
    }
    drop(info);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_igpu_wc_objects_scanout_noncoherent_binds_and_restore
);

fn smoke_xe_vm_slices_nulls_private_objects_and_transactions() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let other = create_vm(&file, &info, &user);
    let object = create_bo(&file, &info, &user, 16384, vm);
    assert!(matches!(
        file.gem.export_object(object),
        Err(FsError::InvalidData)
    ));
    bind_wire(
        &user,
        other,
        &[mapping(object, 0x10000, 0, 4096, 2, 0)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
    let output = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(output).unwrap().core().clone();
    bind_wire(
        &user,
        vm,
        &[mapping(object, 0x10000, 0, 16384, 2, 0)],
        &[
            sync(0, u64::from(output), 0, true),
            sync(2, 0x6000, 11, true),
        ],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(core.is_signalled());
    assert_eq!(user.read_u64_acquire(0x6000), Ok(11));
    let mut unmap = mapping(0, 0x11000, 0, 8192, 0, 0);
    put32(&mut unmap, 40, 1);
    bind_wire(
        &user,
        vm,
        &[unmap, mapping(0, 0x20000, 0, 1 << 30, 0, 4)],
        &[],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    // Copyout faults publish neither VM nor queue, and consume no local ID.
    // Mesa carries capture metadata on UNMAP_ALL and an ignored BO offset.
    let mut all = [0; 80];
    put32(&mut all, 8, object);
    put64(&mut all, 16, 4096);
    put32(&mut all, 40, 3);
    put32(&mut all, 44, 8);
    bind_wire(&user, vm, &[all], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    let mut create = [0; 32];
    user.wire.store(64, &create);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        invoke(&file, &info, &user, xe::VM_CREATE),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    put32(&mut create, 8, 1);
    user.wire.store(64, &create);
    assert_eq!(invoke(&file, &info, &user, xe::VM_CREATE), Ok(0));
    assert_eq!(u32_at(&user.wire.load(64, 32), 12), other + 1);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_vm_slices_nulls_private_objects_and_transactions
);

fn smoke_xe_queries_abi_identity_and_clock_facts() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    assert!(gt.device_facts().is_err());
    prime(&mut gt, &w, 0xdfc);
    for (rpm, frequency) in [
        (0, 3_000_000),
        (0x0e, 19_200_000),
        (0x14, 19_200_000),
        (0x1e, 25_000_000),
    ] {
        w.0.borrow_mut().regs.insert(0xd00, rpm);
        assert_eq!(gt.device_facts().unwrap().reference_clock, frequency);
    }
    w.0.borrow_mut().regs.insert(0xd00, 0x20);
    assert!(gt.device_facts().is_err());
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let mut version = [0; 64];
    put64(&mut version, 16, 8);
    put64(&mut version, 24, 4096);
    user.wire.store(64, &version);
    assert_eq!(
        invoke(&file, &info, &user, crate::drm_uapi::DRM_IOCTL_VERSION),
        Ok(0)
    );
    assert_eq!(user.wire.load(4096, 2), b"xe");
    assert_eq!(u64_at(&user.wire.load(64, 64), 16), 2);
    // GT_TOPOLOGY: geometry and compute (header8 + mask4 each), GT0's L3 bank
    // entry (header8 + mask8, always reported for a primary GT), then EU per
    // DSS (header8 + mask2).
    for (query, size) in [(0, 104), (1, 96), (2, 48), (3, 104), (5, 50)] {
        let mut wire = [0; 40];
        put32(&mut wire, 8, query);
        put64(&mut wire, 16, u64::MAX);
        user.wire.store(64, &wire);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        assert_eq!(u32_at(&user.wire.load(64, 40), 12), size);
        put32(&mut wire, 12, size - 1);
        user.wire.store(64, &wire);
        assert_eq!(
            invoke(&file, &info, &user, xe::DEVICE_QUERY),
            Err(FsError::InvalidData)
        );
        put32(&mut wire, 12, size);
        put64(&mut wire, 16, 1024);
        user.wire.store(64, &wire);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        let reply = user.wire.load(1024, size as usize);
        match query {
            0 => {
                // drm_xe_query_engines: header8 + three drm_xe_engine32.
                // BMG publishes RENDER0, COPY0 and logical COPY1 (BCS8).
                assert_eq!(u32_at(&reply, 0), 3);
                assert!(reply[4..8].iter().all(|byte| *byte == 0));
                for (entry, (class, instance)) in
                    reply[8..]
                        .chunks_exact(32)
                        .zip([(0u16, 0u16), (1, 0), (1, 1)])
                {
                    assert_eq!(&entry[..2], &class.to_le_bytes());
                    assert_eq!(&entry[2..4], &instance.to_le_bytes());
                    assert!(entry[4..].iter().all(|byte| *byte == 0));
                }
            }
            1 => {
                assert_eq!(u32_at(&reply, 12), 4096);
                assert_eq!(u64_at(&reply, 16), 0x80000000);
            }
            2 => {
                assert_eq!(u64_at(&reply, 8) & 65535, 0xe20b);
                assert_eq!(u64_at(&reply, 16), 10);
                assert_eq!(
                    u64_at(&reply, 40),
                    if narf_filesystem::caller_capable(23) {
                        2
                    } else {
                        1
                    }
                );
            }
            3 => {
                assert_eq!(u32_at(&reply, 20), 25_000_000);
                assert_eq!(u64_at(&reply, 32), 1);
                assert_eq!(&reply[40..44], &[20, 0, 1, 0]);
            }
            _ => {
                assert_eq!(&reply[..4], &[0, 0, 1, 0]);
                assert_eq!(u32_at(&reply, 4), 4);
                // load_l3_bank_mask's Xe2 branch: the model's MIRROR_FUSE3
                // (1) enables no XE2_NODE_ENABLE_MASK node, so the mask is
                // empty, and query_gt_topology still reports it.
                assert_eq!(&reply[24..28], &[0, 0, 3, 0]);
                assert_eq!(u32_at(&reply, 28), 8);
                assert_eq!(&reply[32..40], &[0; 8]);
                assert_eq!(&reply[40..44], &[0, 0, 5, 0]);
            }
        }
    }
    // Exact encodings distinguish i915 GETPARAM from Xe QUEUE_CREATE, both
    // numbered 0x46. Unknown sizes cannot fall through into compatibility.
    let mut getparam = [0; 16];
    put32(&mut getparam, 0, 11);
    put64(&mut getparam, 8, 1024);
    user.wire.store(64, &getparam);
    assert_eq!(invoke(&file, &info, &user, abi::GETPARAM), Ok(0));
    assert_eq!(u32_at(&user.wire.load(1024, 4), 0), 1);
    assert_eq!(
        invoke(
            &file,
            &info,
            &user,
            crate::drm_uapi::iowr(b'd' as u32, 0x46, 24)
        ),
        Err(FsError::InvalidData)
    );
    *mailbox.status.lock() = None;
    let mut wire = [0; 40];
    put32(&mut wire, 12, 8);
    put64(&mut wire, 16, 1024);
    user.wire.store(64, &wire);
    assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
    assert_eq!(user.wire.load(1024, 8), [0; 8]);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_queries_abi_identity_and_clock_facts
);

fn smoke_xe_zero_batch_user_fence_and_wait_timeout() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 0);
    let _ = buffers(&file, &info, &user, vm);
    exec_wire(
        &user,
        queue,
        false,
        &[sync(2, 0x2345_0000_0090, 0x1234_5678_0000_0001, true)],
    );
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (_, fence) = mailbox.accept(&mut gt, 100);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &fence, &mut registered, 101);
    assert_eq!(
        user.read_u64_acquire(0x4080),
        Ok(0),
        "zero-batch exec ran a user batch"
    );
    assert_eq!(user.read_u64_acquire(0x4090), Ok(0x1234_5678_0000_0001));
    for (op, value, expected) in [
        (0, 1, true),
        (1, 2, true),
        (2, 0, true),
        (3, 1, true),
        (4, 2, true),
        (5, 1, true),
        (0, 2, false),
    ] {
        let mut wire = [0; 72];
        put64(&mut wire, 8, 0x4090);
        wire[16] = op;
        put64(&mut wire, 24, value);
        put64(&mut wire, 32, u32::MAX as u64);
        user.wire.store(64, &wire);
        let result = narf_scheduler::block_on_spin(file.dispatch_user(
            &info,
            xe::WAIT_USER_FENCE,
            64,
            &user,
        ));
        assert_eq!(
            result,
            Some(if expected {
                Ok(0)
            } else {
                Err(FsError::TimedOut)
            })
        );
    }
    // A finite relative deadline is retained even if the caller rewrites it.
    let mut wire = [0; 72];
    put64(&mut wire, 8, 0x4090);
    put64(&mut wire, 24, 2);
    put64(&mut wire, 32, u32::MAX as u64);
    put64(&mut wire, 40, 100_000);
    user.wire.store(64, &wire);
    let clock = core::cell::Cell::new(0u64);
    let waits = crate::intel_gpu_xe::XeFile::new();
    let mut wait = core::pin::pin!(waits.wait_user_clock(64, &user, || clock.get()));
    assert!(wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    user.wire.store(104, &u64::MAX.to_le_bytes());
    clock.set(100_000);
    assert_eq!(ready(wait.as_mut()), Err(FsError::TimedOut));
    assert_eq!(u64_at(&user.wire.load(104, 8), 0), 0);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_zero_batch_user_fence_and_wait_timeout
);
mod queues {
    include!("intel_gpu_xe_queue_tests.rs");
}
mod timestamps {
    include!("intel_gpu_xe_timestamp_tests.rs");
}
mod waits {
    include!("intel_gpu_xe_wait_tests.rs");
}
mod pxp {
    include!("intel_gpu_xe_pxp_tests.rs");
}

mod multi_ccs {
    include!("intel_gpu_multi_ccs_tests.rs");
}
mod dg2_vram {
    include!("intel_gpu_dg2_vram_tests.rs");
}

// Read the actual pending host CT without consuming ENABLE or inventing its ACK.
// Preparatory invalidate/register/policy messages may still be serviced below.
fn pending_native_enable(
    w: &Window,
    registered: &BTreeMap<u32, u32>,
    engine: crate::intel_gpu_engine::Engine,
) -> bool {
    let memory = ct_memory(w);
    let words = memory.borrow();
    let mut head = words[0];
    let tail = words[1];
    let mut enabled = None;
    while head != tail {
        let count = words[1024 + head as usize] & 255;
        assert_ne!(count, 0);
        if words[1024 + ((head + 1) & 1023) as usize] as u16 == 0x1001 {
            assert_eq!(count, 3);
            assert_eq!(words[1024 + ((head + 3) & 1023) as usize], 1);
            let id = words[1024 + ((head + 2) & 1023) as usize];
            assert!(enabled.replace(id).is_none());
        }
        head = (head + count + 1) & 1023;
    }
    let Some(id) = enabled else {
        return false;
    };
    assert_eq!(registered.len(), 1);
    let base = registered[&id];
    let d = w.0.borrow();
    assert!(d.synced.contains(&base));
    let image = d.memory[&base].borrow();
    assert_eq!(image[1024 + 2], engine.base() + 0x244);
    assert_ne!(image[1024 + 0x33], 0); // retained private VM root
    assert_eq!(image[1024 + 5], 0); // no native head advance yet
    assert_eq!(image[0x800 / 4], 0); // no device breadcrumb yet
    true
}

fn smoke_lnl_native_xe_all_physical_engines_private_vm_cancel_and_completion() -> TestResult {
    use crate::intel_gpu_engine::Engine;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    for device in [0x6420, 0x64a0, 0x64b0] {
        let (w, arena, mut gt) = hardware_model_with_identity(platform, 0xdfc, 1, Some(device));
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling_reload_mode(&mut gt, &w, 4);
        hardware_enable_ct(&mut gt, &w);
        let defaults = gt.begin_context_defaults(26).unwrap();
        let mut registered = BTreeMap::new();
        for now in 27..500 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if defaults.result().is_some() {
                break;
            }
        }
        assert_eq!(defaults.result(), Some(Ok(())));
        assert_eq!(
            gt.engines().unwrap().iter().collect::<Vec<_>>(),
            [
                Engine::Rcs0,
                Engine::Bcs0,
                Engine::Bcs8,
                Engine::Ccs0,
                Engine::Ccs1,
                Engine::Ccs2,
                Engine::Ccs3
            ]
        );
        assert!(gt.vram_layout().is_none());
        {
            let d = w.0.borrow();
            for (reg, value) in [
                (0x4804, 0xe),
                (0x4808, 0xf),
                (0x480c, 0x3c),
                (0x4810, 0x32),
                (0x4814, 0x3e),
                (0x481c, 0x33),
            ] {
                assert_eq!(d.regs[&reg], value);
            }
            for index in 0..16 {
                assert_eq!(
                    d.regs[&(0x4000 + index * 4)],
                    *[0xc, 0x10c, 0x130, 0x13c, 0x100]
                        .get(index as usize)
                        .unwrap_or(&0x100)
                );
            }
            assert_eq!(d.regs[&0xc188], 0x00400000);
            assert_eq!(
                (d.regs[&0xc340] & 0xffffc000) + (d.regs[&0xc050] & 0xfffff000),
                0x1f7000
            ); //2MiB minus source reserve
            let ads = d.memory[&0x20001000].borrow();
            assert_eq!(
                &ads[0x3000 / 4..0x3000 / 4 + 6],
                &[0x90050000, 0x90070000, 0x90080001, 0xc40, 0x90090000, 0x900b0000]
            );
            assert_eq!(d.regs[&0xe48c] & 0x200, 0x200);
            assert_eq!(d.regs[&0xe4c4] & 0x1840, 0x840);
            assert_eq!(d.regs[&0x24d0], 0x23fc);
            for reg in [0x220c4, 0x3ee0c4, 0x1a0c4, 0x1c0c4, 0x1e0c4, 0x260c4] {
                assert_eq!(d.regs[&reg], 0x306);
            }
        }
        for engine in gt.engines().unwrap().iter() {
            assert_eq!(
                ads_registers(&w, engine).len(),
                if engine == Engine::Rcs0 { 28 } else { 18 }
            );
        }

        let (mailbox, mut info) = setup(&mut gt, &w, platform);
        info.device_id = device;
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let handles = buffers(&file, &info, &user, vm);
        let data = file.gem.object(handles[1]).unwrap();
        for (index, engine) in gt.engines().unwrap().iter().enumerate() {
            let logical = gt.engines().unwrap().logical_instance(engine).unwrap();
            let queue = create_queue_instance(&file, &info, &user, vm, engine.xe_class(), logical);
            data.write(0x80, &[0; 4]).unwrap();
            exec_wire(&user, queue, true, &[]);
            let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let start = 1_000_000 + index as u64 * 1000;
            let (context, fence) = mailbox.accept(&mut gt, start);
            assert_eq!(context.engine(), engine);
            // Dropping the syscall waiter cannot abandon the accepted VM.
            drop(call);
            let owned = arena.live_allocations();
            for now in start + 1..start + 10 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                // Withhold ENABLE and its ACK until finish executes the GPU.
                if !pending_native_enable(&w, &registered, engine) {
                    service_contexts(&w, &mut registered, false);
                }
            }
            assert!(pending_native_enable(&w, &registered, engine));
            assert!(context.busy());
            assert!(fence.result().is_none());
            assert!(arena.live_allocations() >= owned);
            finish(&mut gt, &w, &fence, &mut registered, start + 10);
            let mut value = [0; 4];
            data.read(0x80, &mut value).unwrap();
            assert_eq!(u32::from_le_bytes(value), 0x4e415246);
            assert_eq!(
                close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                Ok(0)
            );
        }
        // LNL exposes only programmed noncompressed coherent policies.
        for pat in [0, 3, 6, 8, 15, 16, 31] {
            assert!(!crate::intel_gpu_xe_vm::pat_allowed(platform, pat));
        }
        for pat in [1, 2, 4, 5, 7] {
            assert!(crate::intel_gpu_xe_vm::pat_allowed(platform, pat));
        }
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_lnl_native_xe_all_physical_engines_private_vm_cancel_and_completion
);

fn smoke_ptl_native_xe_all_skus_ips_engines_private_vm_cancel_and_completion() -> TestResult {
    use crate::intel_gpu_engine::Engine;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake);
    for device in [
        0xb080, 0xb081, 0xb082, 0xb083, 0xb084, 0xb085, 0xb086, 0xb087, 0xb08f, 0xb090, 0xb0a0,
        0xb0b0,
    ] {
        for (release, step) in [(0u32, 0u32), (0, 4), (1, 0)] {
            let (w, arena, mut gt) = hardware_model_with_identity(platform, 0xdfc, 1, Some(device));
            {
                let mut d = w.0.borrow_mut();
                d.regs.extend([
                    (0xd8c, 30 << 22 | release << 14 | step),
                    (0x913c, 0),
                    (0x9150, 0),
                    (0x9154, 0x80000000),
                    (0x9144, 0),
                    (0x9148, 0x80000000),
                    (0x914c, 0),
                    (0x380d8c, 30 << 22 | step),
                    // XE2_NODE_ENABLE_MASK nodes 0-1 over the harness's
                    // MEML3 nibble; MIRROR_L3BANK_ENABLE without bank 1.
                    (0x9118, 0x0003_0001),
                    (0x9130, 0xfd),
                ]);
            }
            hardware_discovery(&mut gt, &w, 0xdfc);
            hardware_scheduling_reload_mode(&mut gt, &w, 4);
            hardware_enable_ct(&mut gt, &w);
            let defaults = gt.begin_context_defaults(26).unwrap();
            let mut registered = BTreeMap::new();
            for now in 27..500 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, true);
                if defaults.result().is_some() {
                    break;
                }
            }
            assert_eq!(defaults.result(), Some(Ok(())));
            assert_eq!(
                gt.engines().unwrap().iter().collect::<Vec<_>>(),
                [
                    Engine::Rcs0,
                    Engine::Bcs0,
                    Engine::Bcs8,
                    Engine::Ccs0,
                    Engine::Ccs1,
                    Engine::Ccs2,
                    Engine::Ccs3
                ]
            );
            assert!(gt.vram_layout().is_none());
            {
                let d = w.0.borrow();
                for (reg, value) in [
                    (0x4804, 0xe),
                    (0x4808, 0xf),
                    (0x480c, 0x3c),
                    (0x4810, 0x32),
                    (0x4814, 0x3e),
                    (0x481c, 0x33),
                ] {
                    assert_eq!(d.regs[&reg], value);
                }
                for index in 0..16 {
                    assert_eq!(
                        d.regs[&(0x4000 + index * 4)],
                        *[0xc, 0x10c, 0x130, 0x13c, 0x100]
                            .get(index as usize)
                            .unwrap_or(&0x100)
                    );
                }
                assert_eq!(d.regs[&0xc188], 0x00400000);
                assert_eq!(
                    (d.regs[&0xc340] & 0xffffc000) + (d.regs[&0xc050] & 0xfffff000),
                    0x1f7000
                ); //2MiB minus source reserve
                let ads = d.memory[&0x20001000].borrow();
                let expected_klvs: &[u32] = if release == 0 && step < 4 {
                    &[0x900a0000, 0x90080001, 0xc40, 0x90090000, 0x900b0000]
                } else {
                    &[0x90080001, 0xc40, 0x90090000, 0x900b0000]
                };
                assert_eq!(
                    &ads[0x3000 / 4..0x3000 / 4 + expected_klvs.len()],
                    expected_klvs
                );
                assert_eq!(
                    d.regs.get(&0xe48c).copied().unwrap_or(0) & 0x200,
                    if release == 0 && step < 4 { 0x200 } else { 0 }
                );
                assert_eq!(d.regs[&0xe4c4] & 0x1840, 0x40);
                assert_eq!(
                    d.regs[&0xe5f4] & 0x1020,
                    if release == 0 { 0x1020 } else { 0x1000 }
                );
                assert_eq!(d.regs[&0xc50c] & 2, 2);
                assert_eq!(
                    d.regs.get(&0x9454).copied().unwrap_or(0) & 0x10,
                    if release == 0 && step < 4 { 0x10 } else { 0 }
                );
                assert_eq!(
                    (
                        d.regs[&0x24d0],
                        d.regs[&0x24d4],
                        d.regs[&0x24d8],
                        d.regs[&0x24dc],
                        d.regs[&0x24e0]
                    ),
                    (0x6210, 0x62a8, 0x1000dafc, 0x1000db01, 0xdb1c)
                );
                assert_eq!(d.regs[&0x20d4] & 0xc080, 0x80);
                assert!(!d.regs.contains_key(&0xb154)); // no LNL-only RW flush tuning
                for reg in [0x220c4, 0x3ee0c4, 0x1a0c4, 0x1c0c4, 0x1e0c4, 0x260c4] {
                    assert_eq!(d.regs[&reg], 0x306);
                }
            }
            for engine in gt.engines().unwrap().iter() {
                assert_eq!(
                    ads_registers(&w, engine).len(),
                    if engine == Engine::Rcs0 {
                        if release == 0 && step < 4 {
                            27
                        } else {
                            25
                        }
                    } else {
                        18
                    }
                );
            }

            let (mailbox, mut info) = setup(&mut gt, &w, platform);
            info.device_id = device;
            assert_eq!(info.topology.as_ref().unwrap().geometry_dss(), 1u128 << 95);
            assert_eq!(info.topology.as_ref().unwrap().compute_dss(), 1u128 << 63);
            let query_file = RenderFile::new();
            let query_user = Cpu::new();
            let config = xe_query(&query_file, &info, &query_user, 2);
            assert_eq!(u64_at(&config, 16), 2); // low latency only; no VRAM/USM/compression
            for flags in [2, 8] {
                assert_eq!(
                    create_placed(&query_file, &info, &query_user, 4096, 1, flags, 1),
                    Err(FsError::InvalidData)
                );
            }
            assert_eq!(
                create_placed(&query_file, &info, &query_user, 4096, 2, 0, 1),
                Err(FsError::InvalidData)
            );
            let topo = xe_query(&query_file, &info, &query_user, 5);
            // Independent Xe topology records: header8+mask12 twice, the
            // L3 bank header8+mask8, then EU header8+mask2. The L3 entry is
            // new: query_gt_topology always reports the primary GT's.
            assert_eq!(topo.len(), 66);
            assert_eq!(
                (&topo[..8], &topo[8..20]),
                (
                    &[0, 0, 1, 0, 12, 0, 0, 0][..],
                    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80][..]
                )
            );
            assert_eq!(
                (&topo[20..28], &topo[28..40]),
                (
                    &[0, 0, 2, 0, 12, 0, 0, 0][..],
                    &[0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0][..]
                )
            );
            // load_l3_bank_mask's Xe3 branch: banks 0xfd on nodes 0 and 1.
            assert_eq!(
                &topo[40..],
                &[
                    0, 0, 3, 0, 8, 0, 0, 0, 0xfd, 0, 0, 0, 0xfd, 0, 0, 0, // L3_BANK
                    0, 0, 5, 0, 2, 0, 0, 0, 5, 0, // SIMD16_EU_PER_DSS
                ][..]
            );
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let handles = buffers(&file, &info, &user, vm);
            let data = file.gem.object(handles[1]).unwrap();
            for (index, engine) in gt.engines().unwrap().iter().enumerate() {
                let logical = gt.engines().unwrap().logical_instance(engine).unwrap();
                let queue =
                    create_queue_instance(&file, &info, &user, vm, engine.xe_class(), logical);
                data.write(0x80, &[0; 4]).unwrap();
                exec_wire(&user, queue, true, &[]);
                let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
                assert!(call
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
                let start = 1_000_000 + index as u64 * 1000;
                let (context, fence) = mailbox.accept(&mut gt, start);
                assert_eq!(context.engine(), engine);
                // Dropping the syscall waiter cannot abandon the accepted VM.
                drop(call);
                let owned = arena.live_allocations();
                for now in start + 1..start + 10 {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                    // Withhold ENABLE and its ACK until finish executes the GPU.
                    if !pending_native_enable(&w, &registered, engine) {
                        service_contexts(&w, &mut registered, false);
                    }
                }
                assert!(pending_native_enable(&w, &registered, engine));
                assert!(context.busy());
                assert!(fence.result().is_none());
                assert!(arena.live_allocations() >= owned);
                finish(&mut gt, &w, &fence, &mut registered, start + 10);
                let mut value = [0; 4];
                data.read(0x80, &mut value).unwrap();
                assert_eq!(u32::from_le_bytes(value), 0x4e415246);
                assert_eq!(
                    close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                    Ok(0)
                );
            }
            // LNL exposes only programmed noncompressed coherent policies.
            for pat in [0, 3, 6, 8, 15, 16, 31] {
                assert!(!crate::intel_gpu_xe_vm::pat_allowed(platform, pat));
            }
            for pat in [1, 2, 4, 5, 7] {
                assert!(crate::intel_gpu_xe_vm::pat_allowed(platform, pat));
            }
            hardware_stop(&mut gt, &w, 0xdfc);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_ptl_native_xe_all_skus_ips_engines_private_vm_cancel_and_completion
);

/// Negative publication: without `narf.intel.media_gt=1` (or before its
/// engines executed) the backend publishes no media GT. The GT list and
/// engine query stay GT0-only, and every media or gt_id 1 placement refuses
/// with EINVAL before any queue, context or GGTT allocation (Linux
/// xe_device_get_gt/xe_hw_engine_lookup find no GT or engine for it).
fn smoke_xe_mtl_media_gt1_unpublished_and_placements_refuse_before_allocation() -> TestResult {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, platform);
    assert_eq!(info.backend.as_ref().unwrap().media_gt(), None);
    let file = RenderFile::new();
    let user = Cpu::new();
    let gts = xe_query(&file, &info, &user, 3);
    assert_eq!(gts.len(), 8 + 96);
    assert_eq!(u32_at(&gts, 0), 1, "only GT0 is published");
    assert_eq!(&gts[8..14], &[0u8; 6], "type MAIN, tile 0, gt_id 0");
    let engines = xe_query(&file, &info, &user, 0);
    let count = u32_at(&engines, 0) as usize;
    assert_eq!(engines.len(), 8 + count * 32);
    for entry in engines[8..].chunks_exact(32) {
        let class = u16::from_le_bytes([entry[0], entry[1]]);
        assert!(!matches!(class, 2 | 3), "no VCS/VECS engine is published");
        assert_eq!(&entry[4..6], &[0, 0], "every engine is on GT0");
    }
    let vm = create_vm(&file, &info, &user);
    let before = arena.live_allocations();
    for (class, gt_id) in [(2u8, 1u8), (3, 1), (2, 0), (3, 0), (0, 1), (1, 1), (4, 1), (5, 1)] {
        user.wire.store(512, &[class, 0, 0, 0, gt_id, 0, 0, 0]);
        let mut queue = [0; 48];
        put32(&mut queue, 8, 0x00010001);
        put32(&mut queue, 12, vm);
        put64(&mut queue, 24, 512);
        user.wire.store(64, &queue);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::InvalidData)
        );
        assert_eq!(u32_at(&user.wire.load(64, 48), 20), 0, "no queue id");
    }
    assert_eq!(arena.live_allocations(), before);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_mtl_media_gt1_unpublished_and_placements_refuse_before_allocation
);

/// Positive publication: once the media GuC scheduled GT1 and every engine
/// retired its private PPGTT job, native Xe reports a media GT (type MEDIA,
/// gt_id 1) with its own clock and GMD_ID, lists VCS/VECS with gt_id 1 and
/// dense GT1 logical instances after GT0's engines, and an exec queue on
/// gt_id 1 runs a real GuC submission in GT1's epoch. Unknown GT, wrong-GT
/// class, absent instance, mixed GT and VM refusals keep Linux's
/// xe_exec_queue_create_ioctl errnos and order, before any allocation. A
/// contiguous width-2 VCS row creates a parallel queue instead (a9fbb03fd;
/// spec §3 pins width > 1 for COPY/VCS/VECS/COMPUTE with contiguous rows).
fn smoke_xe_mtl_media_gt1_published_queries_queues_and_exec() -> TestResult {
    use super::super::media_gt_sched::{media_until, start_media, Hw};
    use crate::intel_gpu_engine::{Engine, EngineSet};
    use crate::intel_gpu_gt::media::MediaGucState;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    // GT1 on its own media GuC model: VCS0, VCS2 and VECS0 fused in.
    let (mw, marena) = media_model();
    let mut guc = start_media(&mw, &marena);
    let mut hw = Hw::default();
    let (mut now, polled) = media_until(&mut guc, &mw, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let publication = guc.publication().unwrap();
    let status = crate::intel_gpu_user::MediaGtStatus {
        epoch: publication.epoch,
        engines: publication.engines,
        gmd: publication.gmd,
        reference_clock: publication.reference_clock,
        topology: publication.topology,
    };
    assert_eq!(
        status.engines,
        EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs0])
    );
    let (mailbox, info) = setup_media(&mut gt, &w, platform, Some(status));
    let file = RenderFile::new();
    let user = Cpu::new();
    // query_gt_list: GT0 MAIN, then GT1 MEDIA with its clock and IP 13.00.
    let gts = xe_query(&file, &info, &user, 3);
    assert_eq!(gts.len(), 8 + 2 * 96);
    assert_eq!(u32_at(&gts, 0), 2);
    assert_eq!(&gts[8..14], &[0u8; 6], "type MAIN, tile 0, gt_id 0");
    assert_eq!(&gts[104..110], &[1, 0, 0, 0, 1, 0], "type MEDIA, tile 0, gt_id 1");
    assert_eq!(u32_at(&gts, 116), 19_200_000);
    assert_eq!(u64_at(&gts, 120), 1, "near: system memory");
    assert_eq!(u64_at(&gts, 128), 0, "far: none on the iGPU");
    assert_eq!(&gts[136..142], &[13, 0, 0, 0, 2, 0], "GMD_ID 13.00 revid 2");
    // query_engines: GT0 engines on gt_id 0, then VCS/VECS on gt_id 1.
    let engines = xe_query(&file, &info, &user, 0);
    let count = u32_at(&engines, 0) as usize;
    let gt0 = gt.engines().unwrap().iter().count();
    assert_eq!(count, gt0 + 3);
    for entry in engines[8..8 + gt0 * 32].chunks_exact(32) {
        assert!(!matches!(entry[0], 2 | 3));
        assert_eq!(&entry[4..6], &[0, 0]);
    }
    let media: Vec<_> = engines[8 + gt0 * 32..]
        .chunks_exact(32)
        .map(|entry| (entry[0], entry[2], entry[4]))
        .collect();
    assert_eq!(media, [(2, 0, 1), (2, 1, 1), (3, 0, 1)]);
    let vm = create_vm(&file, &info, &user);
    let before = (arena.live_allocations(), marena.live_allocations());
    let try_queue = |instances: &[[u8; 8]], width: u32, vm: u32| {
        user.wire.store(512, &instances.concat());
        let mut queue = [0; 48];
        put32(&mut queue, 8, width | (instances.len() as u32 / width) << 16);
        put32(&mut queue, 12, vm);
        put64(&mut queue, 24, 512);
        user.wire.store(64, &queue);
        let result = invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE);
        (result, u32_at(&user.wire.load(64, 48), 20))
    };
    let eci = |class: u8, instance: u8, gt_id: u8| [class, 0, instance, 0, gt_id, 0, 0, 0];
    for (instances, width, vm, errno) in [
        (alloc::vec![eci(2, 0, 0)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(3, 0, 0)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(0, 0, 1)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(1, 0, 1)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(4, 0, 1)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(2, 2, 1)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(3, 1, 1)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(2, 0, 2)], 1, vm, FsError::InvalidData),
        (alloc::vec![eci(5, 0, 2)], 1, vm, FsError::InvalidData),
        (
            alloc::vec![eci(2, 0, 1), eci(2, 1, 0)],
            1,
            vm,
            FsError::InvalidData,
        ),
        (
            alloc::vec![eci(2, 0, 1), eci(3, 0, 1)],
            1,
            vm,
            FsError::InvalidData,
        ),
        // Unknown GT precedes the VM lookup; a valid GT1 engine reaches it.
        (alloc::vec![eci(2, 0, 2)], 1, 999, FsError::InvalidData),
        (alloc::vec![eci(2, 0, 1)], 1, 999, FsError::NotFound),
    ] {
        assert_eq!(try_queue(&instances, width, vm), (Err(errno), 0));
    }
    assert_eq!(
        (arena.live_allocations(), marena.live_allocations()),
        before
    );
    // A VM_BIND queue may name the published GT1, as in Linux.
    let (bind, bind_id) = try_queue(&[eci(5, 0, 1)], 1, vm);
    assert_eq!(bind, Ok(0));
    assert_ne!(bind_id, 0);
    // A contiguous width-2 VCS row on GT1 is a parallel queue, not a
    // refusal (a9fbb03fd; spec §3): logical 0/1 are physical VCS0/VCS2.
    let (parallel, parallel_id) = try_queue(&[eci(2, 0, 1), eci(2, 1, 1)], 2, vm);
    assert_eq!(parallel, Ok(0));
    assert_ne!(parallel_id, 0);
    // VCS logical 1 on GT1 is physical VCS2; it runs a real media GuC job.
    let (result, queue) = try_queue(&[eci(2, 1, 1)], 1, vm);
    assert_eq!(result, Ok(0));
    assert_ne!(queue, 0);
    let _buffers = buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let pending = mailbox
        .pending
        .lock()
        .pop()
        .expect("userspace queued a media job");
    assert_eq!(pending.context.engine(), Engine::Vcs2);
    now += 1_000_000;
    let (_, fence) = guc
        .submit_user(now, pending.context.clone(), pending.batch, None)
        .unwrap();
    *pending.reply.result.lock() = Some(Ok(fence.clone()));
    if let Some(waker) = pending.reply.waker.lock().take() {
        waker.wake();
    }
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    let (now, _) = media_until(&mut guc, &mw, &mut hw, now + 1, |_| {
        fence.result().is_some()
    });
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(hw_ran_on(&hw, 0x1d0000));
    assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
    assert_eq!(pending.context.check_epoch(status.epoch), Ok(()));
    user.mapping.lock().take();
    for id in [queue, bind_id, parallel_id] {
        assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, id), Ok(0));
    }
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &mw, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    drop(guc);
    assert_eq!(marena.live_allocations(), 0);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_mtl_media_gt1_published_queries_queues_and_exec
);

fn hw_ran_on(hw: &super::super::media_gt_sched::Hw, base: u32) -> bool {
    hw.ppgtt_engines().contains(&base)
}

mod gen12_media {
    include!("intel_gpu_gen12_media_ioctl_tests.rs");
}

mod bmg_smallbar {
    include!("intel_gpu_bmg_smallbar_tests.rs");
}
