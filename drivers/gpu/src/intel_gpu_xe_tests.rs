// Native Xe ioctl -> actual GuC/CT/private PPGTT conversations. No fence is
// completed by the fixture: device stores and retirement/reset establish it.
use super::*;
use crate::{drm::syncobj as so, intel_gpu_xe_uapi as xe};
use narf_filesystem::{IoctlContext, MmapBacking};

struct Cpu {
    wire: User,
    mapping: IrqSafeSpinLock<Option<MmapBacking>>,
    fail_report: core::sync::atomic::AtomicBool,
}
impl Cpu {
    fn new() -> Self {
        Self {
            wire: User::new(),
            mapping: IrqSafeSpinLock::new(None),
            fail_report: core::sync::atomic::AtomicBool::new(false),
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
    user.wire.store(512, &[class as u8, 0, 0, 0, 0, 0, 0, 0]);
    let mut wire = [0; 48];
    put32(&mut wire, 8, 0x00010001);
    put32(&mut wire, 12, vm);
    put64(&mut wire, 24, 512);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}
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
    for now in start..start + 60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        // Literal GuC policy KLVs for a normal native Xe queue. Inspect the
        // actual CT bytes before the independent firmware model consumes them.
        {
            let memory = ct_memory(w);
            let words = memory.borrow();
            let mut head = words[0];
            let tail = words[1];
            while head != tail {
                let length = words[1024 + head as usize] & 255;
                if words[1024 + ((head + 1) & 1023) as usize] as u16 == 0x100b {
                    assert_eq!(words[1024 + ((head + 4) & 1023) as usize], 2);
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
    let deadline = narf_time::monotonic_ns() + 10_000_000;
    loop {
        if let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
        assert!(
            narf_time::monotonic_ns() < deadline,
            "native Xe future did not resume"
        );
        narf_scheduler::sleep_pumps::run();
    }
}

fn smoke_xe_native_exec_user_fence_close_and_retirement() -> TestResult {
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
    for (query, size) in [(0, 40), (1, 96), (2, 48), (3, 104), (5, 34)] {
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
                assert_eq!(u32_at(&reply, 0), 1);
                assert!(reply[4..].iter().all(|b| *b == 0));
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
    // Full command encoding and stable Xe profile prevent i915/Xe number
    // collisions from decoding a malformed Xe request as legacy GETPARAM.
    assert_eq!(
        invoke(&file, &info, &user, abi::GETPARAM),
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
    let mut wait = core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
    assert!(wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    user.wire.store(104, &u64::MAX.to_le_bytes());
    assert_eq!(ready(wait.as_mut()), Some(Err(FsError::TimedOut)));
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
