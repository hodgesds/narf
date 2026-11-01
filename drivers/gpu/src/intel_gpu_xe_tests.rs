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
}
impl Cpu {
    fn new() -> Self {
        Self {
            wire: User::new(),
            mapping: IrqSafeSpinLock::new(None),
            fail_report: core::sync::atomic::AtomicBool::new(false),
            pin_calls: core::sync::atomic::AtomicU32::new(0),
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
    // Modeled process: 0x4000 is the writable CPU mapping, 0x6000 a read-only
    // alias of the same page, everything else unmapped.
    fn pin_user_pages(
        &self,
        address: u64,
        pages: u64,
        writable: bool,
    ) -> Result<Vec<narf_memory::address_space::UserPagePin>, FsError> {
        self.pin_calls
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let mapping = self.mapping.lock();
        let frame = mapping.as_ref().ok_or(FsError::BadAddress)?.frames[0];
        (0..pages)
            .map(|page| match address + page * 4096 {
                0x4000 => Ok(()),
                0x6000 if writable => Err(FsError::OperationNotPermitted),
                0x6000 => Ok(()),
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
}
impl UserBackend for Native {
    fn status(&self) -> Option<UserStatus> {
        self.mailbox.status()
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
        self.mailbox.submit(context, batch)
    }
}
fn setup(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    platform: GtPlatform,
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
            GtPlatform::Battlemage => 0xe20b,
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
        GtPlatform::Alchemist => 0,
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

fn finish_policy(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
    priority: u32,
) {
    for now in start..start + 60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        // Native queues request normal2; trusted probes and direct contexts
        // use low3. Keep the exact caller-selected policy and KLV checks.
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
        let (_, fence) = mailbox.accept(&mut gt, 100);
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
        for now in 101..120 {
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
        finish(&mut gt, &w, &fence, &mut registered, 120);
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
    invoke(file, info, user, xe::GEM_CREATE).map(|_| u32_at(&user.wire.load(64, 56), 28))
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
    assert_eq!(u64_at(&xe_query(&file, &info, &user, 2), 16), 9);
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
    for (query, size) in [(0, 104), (1, 96), (2, 48), (3, 104), (5, 34)] {
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
                assert_eq!(u64_at(&reply, 16), 8);
                assert_eq!(u64_at(&reply, 40), 1);
            }
            3 => {
                assert_eq!(u32_at(&reply, 20), 25_000_000);
                assert_eq!(u64_at(&reply, 32), 1);
                assert_eq!(&reply[40..44], &[20, 0, 1, 0]);
            }
            _ => {
                assert_eq!(&reply[..4], &[0, 0, 1, 0]);
                assert_eq!(u32_at(&reply, 4), 4);
                assert_eq!(&reply[24..28], &[0, 0, 5, 0]);
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

mod multi_ccs {
    include!("intel_gpu_multi_ccs_tests.rs");
}
