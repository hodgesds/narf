// Actual registered i915 dispatch -> retained GuC/CT/private-VM owners.
// Model fences are signalled only for explicitly foreign dependencies. Native
// completions require the real store/breadcrumb/disable/deregister/TLB owner.
use super::*;
use crate::intel_gpu_exec::ExecRequest;
use crate::intel_gpu_gem::{reserve_gpu, reserve_gpu_mixed, GemObject, GemState};
use narf_filesystem::dma_buf::DmaResvUsage;

fn raw(user: &User, handles: [u32; 2], context: u32, asynchronous: u8) {
    legacy_exec(user, handles, context);
    // The literal bit is independent of the production constant.
    for entry in 0..2 {
        if asynchronous & (1 << entry) != 0 {
            let address = 256 + entry * 56 + 32;
            let flags = u64_at(&user.load(address, 8), 0) | 0x40;
            user.store(address, &flags.to_le_bytes());
        }
    }
    set_ring(user, 0); // explicit engine map's slot0
}
fn copy_context(file: &RenderFile, card: u32, user: &Cpu, logical: u16) -> u32 {
    let id = prototype(file, card, user);
    let param = engines_param(&user.wire, id, &[(1, logical)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, user),
        Some(Ok(0))
    );
    id
}
fn pair(file: &RenderFile, card: u32, user: &Cpu, offset: u32, value: u32) -> [u32; 2] {
    let handles = make_buffers(&user.wire, |cmd| {
        assert_eq!(file.dispatch_card(card, cmd, 64, user), Some(Ok(0)))
    });
    let words = [0x10000002u32, offset, 0x2345, value, 0x05000000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem
        .object(handles[0])
        .unwrap()
        .write(0, &bytes)
        .unwrap();
    handles
}
fn submit(
    file: &RenderFile,
    card: u32,
    user: &dyn IoctlContext,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    now: u64,
) -> (Arc<UserContext>, Arc<CompletionFence>) {
    let mut call =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, user));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    assert_eq!(mailbox.pending.lock().len(), 1);
    let accepted = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    accepted
}
fn held(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
) -> (u32, u32) {
    let mut enabled = false;
    for now in start..start + 12 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        // This is intentionally an accepted but not executed producer.
        // Later execute_copy consumes its actual retained LRC independently.
        enabled |= service_contexts(w, registered, false).contains(&0x1001);
        assert_eq!(fence.result(), None);
    }
    assert!(enabled);
    assert_eq!(registered.len(), 1);
    registered
        .iter()
        .next()
        .map(|(&id, &base)| (id, base))
        .unwrap()
}
fn device_word(object: &GemObject, offset: u64) -> u32 {
    let physical = object.pages().next().unwrap() + offset;
    // SAFETY: the model retains this WB BO and reads a valid aligned location
    // written by its emulated GPU, independently of the CPU admission API.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(physical).kernel_ptr::<u32>()) }
}
struct NoWrite<'a>(&'a dyn IoctlContext);
impl IoctlContext for NoWrite<'_> {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.0.read(address, bytes)
    }
    fn write(&self, _: u64, _: &[u8]) -> Result<(), FsError> {
        Err(FsError::BadAddress)
    }
    fn nonblocking(&self) -> bool {
        false
    }
}
fn get_async(file: &RenderFile, card: u32, user: &Cpu) -> u32 {
    let mut wire = [0; 16];
    put32(&mut wire, 0, 43);
    put64(&mut wire, 8, 4096);
    user.wire.store(64, &wire);
    assert_eq!(
        file.dispatch_card(card, abi::GETPARAM, 64, user),
        Some(Ok(0))
    );
    u32_at(&user.wire.load(4096, 4), 0)
}

fn smoke_i915_object_async_live_discovery_and_early_refusal() -> TestResult {
    assert_eq!(abi::OBJECT_ASYNC, 0x40);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, mut info, card) = registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let status = mailbox.status();
    let writes = w.0.borrow().writes.len();
    assert_eq!(get_async(&file, card, &user), 1);
    for name in [
        alloc::format!("card{card}"),
        alloc::format!("renderD{}", card + 128),
    ] {
        let node = crate::drm_devfs_bridge::DriDir.lookup(&name).unwrap();
        let mut wire = [0; 16];
        put32(&mut wire, 0, 43);
        put64(&mut wire, 8, 4096);
        user.wire.store(64, &wire);
        let mut query = core::pin::pin!(node.ioctl_user(abi::GETPARAM, 64, &user));
        assert_eq!(
            query.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
        assert_eq!(u32_at(&user.wire.load(4096, 4), 0), 1);
    }
    let mut wire = [0; 16];
    put32(&mut wire, 0, 43);
    put64(&mut wire, 8, 4096);
    user.wire.store(64, &wire);
    assert_eq!(
        file.dispatch_card(card, abi::GETPARAM, 64, &NoWrite(&user)),
        Some(Err(FsError::BadAddress))
    );

    let live = status.unwrap();
    for replacement in [
        None,
        Some(UserStatus { epoch: 0, ..live }),
        Some(UserStatus {
            platform: GtPlatform::Alchemist,
            ..live
        }),
        Some(UserStatus {
            engines: EngineSet::from_bits(0),
            ..live
        }),
    ] {
        *mailbox.status.lock() = replacement;
        assert_eq!(get_async(&file, card, &user), 0);
    }
    *mailbox.status.lock() = status;
    let handles = pair(&file, card, &user, 0x80, 0x18181818);
    let id = prototype(&file, card, &user);
    for platform in [
        GtPlatform::Alchemist,
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake),
        GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP),
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS),
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeN),
    ] {
        info.platform = platform;
        let mut get = [0; 16];
        put32(&mut get, 0, 43);
        put64(&mut get, 8, 4096);
        user.wire.store(64, &get);
        assert_eq!(file.dispatch(&info, abi::GETPARAM, 64, &user), Some(Ok(0)));
        assert_eq!(u32_at(&user.wire.load(4096, 4), 0), 0);
        raw(&user.wire, handles, id, 2);
        let mut call =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
        assert!(mailbox.pending.lock().is_empty());
    }
    // The refusals looked the context up, and an execbuffer lookup
    // finalizes a proto-context (spec: created contexts stay proto
    // until execbuffer, GETPARAM or reset-stats lookup), so the same
    // context no longer accepts its first engine map.
    let param = engines_param(&user.wire, id, &[(1, 1)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    // A fresh proto-context still accepts its first map.
    let fresh = prototype(&file, card, &user);
    let param = engines_param(&user.wire, fresh, &[(1, 1)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(file.gem.object(handles[1]).unwrap().busy(), 0);
    let baseline = arena.live_allocations();
    *mailbox.status.lock() = None;
    raw(&user.wire, handles, id, 2);
    {
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::NoDevice)))
        );
    }
    assert_eq!(arena.live_allocations(), baseline);
    assert!(mailbox.pending.lock().is_empty());
    *mailbox.status.lock() = status;
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_live_discovery_and_early_refusal
);

fn smoke_i915_object_async_real_overlap_prime_cpu_exclusion_and_retirement() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, platform);
    let first = RenderFile::new();
    let second = RenderFile::new();
    let user = Cpu::new();
    let a = pair(&first, card, &user, 0x80, 0x18180001);
    let mut b = pair(&second, card, &user, 0x84, 0x18180002);
    let object = first.gem.object(a[1]).unwrap();
    b[1] = second.gem.import(&object).unwrap();
    assert_eq!(second.gem.import(&object).unwrap(), b[1]);
    assert!(Arc::ptr_eq(&object, &second.gem.object(b[1]).unwrap()));
    let id_a = copy_context(&first, card, &user, 0);
    let id_b = copy_context(&second, card, &user, 1);
    raw(&user.wire, a, id_a, 0);
    let (context_a, fence_a) = submit(&first, card, &user, &mailbox, &mut gt, 500);
    let mut registered = BTreeMap::new();
    let (guc_a, base_a) = held(&mut gt, &w, &fence_a, &mut registered, 501);
    assert_eq!(context_a.engine(), Engine::Bcs0);
    assert_eq!(device_word(&object, 0x80), 0);
    // Without ASYNC the second raw request cannot reach the GT owner.
    raw(&user.wire, b, id_b, 0);
    {
        let mut call =
            core::pin::pin!(second.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(mailbox.pending.lock().is_empty());
    }
    raw(&user.wire, b, id_b, 2);
    let (context_b, fence_b) = submit(&second, card, &user, &mailbox, &mut gt, 520);
    assert_eq!(context_b.engine(), Engine::Bcs8);
    assert!(!Arc::ptr_eq(&context_a, &context_b));
    assert_eq!(object.dma_buf.resv.fences(DmaResvUsage::Write).len(), 2);
    finish_policy(&mut gt, &w, &fence_b, &mut registered, 521, 2);
    assert_eq!(registered.get(&guc_a), Some(&base_a));
    assert_eq!(device_word(&object, 0x80), 0);
    assert_eq!(device_word(&object, 0x84), 0x18180002);
    assert_eq!(fence_a.result(), None);
    assert_eq!(object.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    assert_eq!(object.busy(), 0x10001);
    assert_eq!(object.read(0x84, &mut [0; 4]), Err(FsError::WouldBlock));
    assert_eq!(object.write(0x84, &[0; 4]), Err(FsError::WouldBlock));
    let mut copy = [0; 32];
    put32(&mut copy, 0, b[1]);
    put64(&mut copy, 8, 0x84);
    put64(&mut copy, 16, 4);
    put64(&mut copy, 24, 512);
    for cmd in [abi::GEM_PREAD, abi::GEM_PWRITE] {
        user.wire.store(64, &copy);
        let mut cpu = core::pin::pin!(second.dispatch_card_user(card, cmd, 64, &user));
        assert!(cpu
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    let mut wait = [0; 16];
    put32(&mut wait, 0, b[1]);
    user.wire.store(64, &wait);
    {
        let mut cpu = core::pin::pin!(second.dispatch_card_user(card, abi::GEM_WAIT, 64, &user));
        assert_eq!(
            cpu.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::TimedOut)))
        );
    }
    let prime = crate::drm_devfs_bridge::intel_dma_buf_file(card, object.clone());
    user.wire.store(
        64,
        &narf_filesystem::dma_buf::DMA_BUF_SYNC_READ.to_le_bytes(),
    );
    {
        let mut cpu = prime.ioctl_user(narf_filesystem::dma_buf::DMA_BUF_IOCTL_SYNC, 64, &user);
        assert!(cpu
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    // A third synchronous EXEC still sees the older pending producer, even
    // after this identity's newer ASYNC fence has retired.
    raw(&user.wire, b, id_b, 0);
    {
        let mut call =
            core::pin::pin!(second.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(mailbox.pending.lock().is_empty());
    }
    execute_copy(&w, base_a);
    finish_policy(&mut gt, &w, &fence_a, &mut registered, 600, 2);
    assert!(registered.is_empty());
    assert_eq!(device_word(&object, 0x80), 0x18180001);
    assert_eq!(object.busy(), 0);
    let mut word = [0; 4];
    object.read(0x84, &mut word).unwrap();
    assert_eq!(u32::from_le_bytes(word), 0x18180002);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_real_overlap_prime_cpu_exclusion_and_retirement
);

// A foreign fence deliberately changes A while B's snapshot invokes it. This
// exercises the real generation recheck without a resolver/test-only hook.
struct MutateOther {
    target: Arc<GemObject>,
    fence: Arc<CompletionFence>,
    fired: core::sync::atomic::AtomicBool,
}
impl DrmFence for MutateOther {
    fn is_signalled(&self) -> bool {
        if !self.fired.swap(true, core::sync::atomic::Ordering::AcqRel) {
            self.target
                .import_fences(alloc::vec![self.fence.clone()], true);
        }
        true
    }
    fn wait(&self, _: u64) -> bool {
        self.is_signalled()
    }
}
fn smoke_i915_object_async_mixed_atomic_alias_and_read_write_matrix() -> TestResult {
    let gem = GemState::new();
    let a = gem
        .object(gem.create(4096, |_, _| Ok(())).unwrap())
        .unwrap();
    let b = gem
        .object(gem.create(4096, |_, _| Ok(())).unwrap())
        .unwrap();
    let invalid = Arc::new(CompletionFence::new());
    assert_eq!(
        reserve_gpu_mixed(&[(a.clone(), true)], &[], &invalid),
        Err(FsError::InvalidData)
    );
    assert_eq!(a.busy(), 0);

    for old_write in [false, true] {
        for new_write in [false, true] {
            for asynchronous in [false, true] {
                let old = Arc::new(CompletionFence::new());
                a.import_fences(alloc::vec![old.clone()], old_write);
                let new = Arc::new(CompletionFence::new());
                let expected = if !asynchronous && (old_write || new_write) {
                    Err(FsError::WouldBlock)
                } else {
                    Ok(())
                };
                assert_eq!(
                    reserve_gpu_mixed(&[(a.clone(), new_write)], &[asynchronous], &new),
                    expected
                );
                assert_eq!(
                    a.dma_buf.resv.fences(DmaResvUsage::Read).len(),
                    if expected.is_ok() { 2 } else { 1 }
                );
                // These are foreign reservation-only dependencies, not native jobs.
                new.signal(Ok(()));
                old.signal(Ok(()));
                assert_eq!(a.busy(), 0);
            }
        }
    }
    let old = Arc::new(CompletionFence::new());
    b.import_fences(alloc::vec![old.clone()], false);
    let new = Arc::new(CompletionFence::new());
    assert_eq!(
        reserve_gpu_mixed(
            &[(a.clone(), true), (b.clone(), true)],
            &[true, false],
            &new
        ),
        Err(FsError::WouldBlock)
    );
    assert_eq!(a.busy(), 0);
    assert_eq!(b.dma_buf.resv.fences(DmaResvUsage::Read).len(), 1);
    old.signal(Ok(()));
    let old = Arc::new(CompletionFence::new());
    a.import_fences(alloc::vec![old.clone()], false);
    assert_eq!(
        reserve_gpu_mixed(
            &[(a.clone(), true), (a.clone(), false)],
            &[true, false],
            &new
        ),
        Err(FsError::WouldBlock)
    );
    assert_eq!(a.dma_buf.resv.fences(DmaResvUsage::Read).len(), 1);
    // All-ASYNC aliases collapse to one strongest WRITE fence, preserving old READ.
    reserve_gpu_mixed(
        &[(a.clone(), false), (a.clone(), true)],
        &[true, true],
        &new,
    )
    .unwrap();
    assert_eq!(a.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    assert_eq!(a.dma_buf.resv.fences(DmaResvUsage::Read).len(), 2);
    old.signal(Ok(()));
    new.signal(Ok(()));
    let interfering = Arc::new(CompletionFence::new());
    let mutator = Arc::new(MutateOther {
        target: a.clone(),
        fence: interfering.clone(),
        fired: core::sync::atomic::AtomicBool::new(true),
    });
    b.import_fences(alloc::vec![mutator.clone()], true);
    mutator
        .fired
        .store(false, core::sync::atomic::Ordering::Release);
    let proposed = Arc::new(CompletionFence::new());
    assert_eq!(
        reserve_gpu_mixed(
            &[(a.clone(), true), (b.clone(), true)],
            &[false, false],
            &proposed
        ),
        Err(FsError::WouldBlock)
    );
    assert!(mutator.fired.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(proposed.result(), None);
    let live = a.dma_buf.resv.fences(DmaResvUsage::Read);
    let foreign: Arc<dyn DrmFence> = interfering.clone();
    assert_eq!(live.len(), 1);
    assert!(Arc::ptr_eq(&live[0], &foreign));
    assert_eq!(
        b.busy(),
        0,
        "failed final transaction partially published its fence"
    );
    interfering.signal(Ok(()));
    // Existing unflagged implicit helper remains unchanged and operational.
    reserve_gpu(&[(a.clone(), false)], &proposed).unwrap();
    proposed.signal(Ok(()));
    assert_eq!(a.busy(), 0);
    // The same interleaving is valid for ASYNC A. A stale snapshot must not
    // prune the new foreign fence inserted after it was sampled.
    let later = Arc::new(CompletionFence::new());
    let mutator = Arc::new(MutateOther {
        target: a.clone(),
        fence: later.clone(),
        fired: core::sync::atomic::AtomicBool::new(true),
    });
    b.import_fences(alloc::vec![mutator.clone()], true);
    mutator
        .fired
        .store(false, core::sync::atomic::Ordering::Release);
    let accepted = Arc::new(CompletionFence::new());
    reserve_gpu_mixed(
        &[(a.clone(), true), (b.clone(), true)],
        &[true, false],
        &accepted,
    )
    .unwrap();
    assert!(mutator.fired.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(a.dma_buf.resv.fences(DmaResvUsage::Write).len(), 2);
    assert_eq!(b.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    accepted.signal(Ok(()));
    assert_eq!(a.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    later.signal(Ok(()));
    assert_eq!(a.busy(), 0);
    assert_eq!(b.busy(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_mixed_atomic_alias_and_read_write_matrix
);

struct Fds {
    wire: User,
    files: IrqSafeSpinLock<BTreeMap<i32, Vec<Arc<dyn DrmFence>>>>,
    fail_report: core::sync::atomic::AtomicBool,
}
impl Fds {
    fn new() -> Self {
        Self {
            wire: User::new(),
            files: IrqSafeSpinLock::new(BTreeMap::new()),
            fail_report: core::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl IoctlContext for Fds {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.wire.read(address, bytes)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
        if address == 120 && self.fail_report.load(core::sync::atomic::Ordering::Acquire) {
            return Err(FsError::BadAddress);
        }
        self.wire.write(address, bytes)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn DrmFence>>> {
        self.files.lock().get(&fd).cloned()
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        report(17).map_err(narf_filesystem::InstallFdError::Report)?;
        self.files.lock().insert(17, fences);
        Ok(17)
    }
}
fn reach<F: Future>(mut call: core::pin::Pin<&mut F>, mailbox: &Mailbox) {
    let deadline = narf_time::monotonic_ns() + 10_000_000;
    while mailbox.pending.lock().is_empty() {
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            narf_time::monotonic_ns() < deadline,
            "copied ASYNC dependency did not resume"
        );
        narf_scheduler::sleep_pumps::run();
    }
}
fn smoke_i915_object_async_explicit_inputs_snapshot_and_same_context_order() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let fds = Fds::new();
    let handles = pair(&file, card, &user, 0x80, 0x18180003);
    let object = file.gem.object(handles[1]).unwrap();
    let id = copy_context(&file, card, &user, 1);
    let older = Arc::new(CompletionFence::new());
    object.import_fences(alloc::vec![older.clone()], true);
    for kind in 0..3 {
        let dependency = Arc::new(CompletionFence::new());
        raw(&fds.wire, handles, id, 3);
        let mut wire = fds.wire.load(64, 64);
        let flags = u64_at(&wire, 40);
        let mut core = None;
        let mut output = None;
        let mut handles_to_close = Vec::new();
        if kind == 0 {
            fds.files.lock().insert(9, alloc::vec![dependency.clone()]);
            put64(&mut wire, 40, flags | abi::EXEC_FENCE_IN);
            put64(&mut wire, 56, 9);
        } else {
            let (input, out) = {
                let mut table = file.syncobjs.lock();
                (table.create(0).unwrap(), table.create(0).unwrap())
            };
            let input_core = file.syncobjs.lock().get(input).unwrap().core().clone();
            let out_core = file.syncobjs.lock().get(out).unwrap().core().clone();
            let payload = so::from_drm_leaves(alloc::vec![dependency.clone()]);
            if kind == 1 {
                input_core.replace_fence(Some(payload));
            } else {
                input_core.add_point(payload, 7);
            }
            let mut entries = [0; 16];
            put32(&mut entries, 0, input);
            put32(&mut entries, 4, 1);
            put32(&mut entries, 8, out);
            put32(&mut entries, 12, 2);
            fds.wire.store(1024, &entries);
            if kind == 1 {
                put64(&mut wire, 40, flags | abi::EXEC_FENCE_ARRAY);
                put32(&mut wire, 28, 2);
                put64(&mut wire, 32, 1024);
            } else {
                let mut ext = [0; 56];
                put64(&mut ext, 32, 2);
                put64(&mut ext, 40, 1024);
                put64(&mut ext, 48, 2048);
                fds.wire.store(1536, &ext);
                let mut points = [0; 16];
                put64(&mut points, 0, 7);
                put64(&mut points, 8, 11);
                fds.wire.store(2048, &points);
                put64(&mut wire, 40, flags | abi::EXEC_USE_EXTENSIONS);
                put64(&mut wire, 32, 1536);
            }
            core = Some(input_core);
            output = Some(out_core);
            handles_to_close.extend([input, out]);
        }
        fds.wire.store(64, &wire);
        let mut call =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &fds));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(mailbox.pending.lock().is_empty());
        // Both per-object flags and explicit dependencies were copied already.
        fds.files.lock().clear();
        for handle in handles_to_close {
            file.syncobjs.lock().destroy(handle).unwrap();
        }
        drop(core);
        fds.wire.store(64, &[0; 64]);
        fds.wire.store(256, &[0; 112]);
        fds.wire.store(1024, &[0; 16]);
        dependency.signal(Ok(())); // foreign producer, independent of native job
        reach(call.as_mut(), &mailbox);
        let (_, fence) = mailbox.accept(&mut gt, 500 + kind * 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        assert_eq!(
            older.result(),
            None,
            "ASYNC silently waited for an implicit dependency"
        );
        let mut registered = BTreeMap::new();
        finish_policy(&mut gt, &w, &fence, &mut registered, 501 + kind * 100, 2);
        if let Some(output) = output {
            assert!(output
                .find_fence(if kind == 1 { 0 } else { 11 })
                .unwrap()
                .is_signalled());
        }
        assert_eq!(object.busy(), 0x10001);
    }
    older.signal(Ok(()));
    raw(&user.wire, handles, id, 3);
    let (_, producer) = submit(&file, card, &user, &mailbox, &mut gt, 900);
    let mut registered = BTreeMap::new();
    let (_, base) = held(&mut gt, &w, &producer, &mut registered, 901);
    raw(&user.wire, handles, id, 3);
    {
        let mut same =
            core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(same
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            mailbox.pending.lock().is_empty(),
            "ASYNC bypassed same-context ordering"
        );
    }
    execute_copy(&w, base);
    finish_policy(&mut gt, &w, &producer, &mut registered, 920, 2);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_explicit_inputs_snapshot_and_same_context_order
);

fn request(file: &RenderFile, user: &User) -> ExecRequest {
    ExecRequest::read_submission(user, 64, &file.gem, &file.syncobjs).unwrap().0
}
fn smoke_i915_object_async_publication_output_failure_and_exact_fence() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (_, _, card) = registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let fds = Fds::new();
    let handles = pair(&file, card, &user, 0x80, 0x18180004);
    let object = file.gem.object(handles[1]).unwrap();
    let context = UserContext::for_engine(Engine::Bcs8);
    let baseline = arena.live_allocations();
    // Same raw object parser and final retained production owner; no output
    // backend mock advertises a transaction it cannot implement.
    for fault in [0, 1] {
        raw(&fds.wire, handles, 0, 3);
        let batch = request(&file, &fds.wire).prepare_user(platform).unwrap();
        let output = crate::intel_gpu_user::UserOutput {
            user: &fds,
            address: 120,
            input: 0x12345678,
        };
        w.0.borrow_mut().fail_sync = fault == 0;
        fds.fail_report
            .store(fault == 1, core::sync::atomic::Ordering::Release);
        assert!(gt
            .submit_user_batch_with_output(500, context.clone(), batch, &output)
            .is_err());
        assert!(!context.busy());
        assert!(context.last().is_none());
        assert_eq!(object.busy(), 0);
        assert!(fds.files.lock().is_empty());
        assert_eq!(arena.live_allocations(), baseline);
    }
    w.0.borrow_mut().fail_sync = false;
    fds.fail_report
        .store(false, core::sync::atomic::Ordering::Release);
    raw(&fds.wire, handles, 0, 3);
    let batch = request(&file, &fds.wire).prepare_user(platform).unwrap();
    let (_, fence) = gt
        .submit_user_batch_with_output(
            600,
            context.clone(),
            batch,
            &crate::intel_gpu_user::UserOutput {
                user: &fds,
                address: 120,
                input: 0x12345678,
            },
        )
        .unwrap();
    let exact: Arc<dyn DrmFence> = fence.clone();
    let exported = fds.sync_file_fences(17).unwrap().pop().unwrap();
    assert!(Arc::ptr_eq(&exact, &exported));
    assert_eq!(
        u64_at(&fds.wire.load(120, 8), 0),
        (17u64 << 32) | 0x12345678
    );
    assert_eq!(object.busy(), 0x10001);
    assert!(!exported.is_signalled());
    fds.files.lock().clear();
    let mut registered = BTreeMap::new();
    finish_policy(&mut gt, &w, &fence, &mut registered, 601, 3);
    assert!(exported.is_signalled());
    assert_eq!(device_word(&object, 0x80), 0x18180004);
    assert_eq!(arena.live_allocations(), baseline);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_publication_output_failure_and_exact_fence
);

fn refused_storage(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    mailbox: &Mailbox,
    handles: [u32; 2],
    id: u32,
) {
    raw(&user.wire, handles, id, 3);
    let mut call =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, user));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Err(FsError::InvalidData)))
    );
    assert!(mailbox.pending.lock().is_empty());
    assert_eq!(file.gem.object(handles[0]).unwrap().busy(), 0);
    assert_eq!(file.gem.object(handles[1]).unwrap().busy(), 0);
}
fn smoke_i915_object_async_imported_storage_refuses_before_context_or_dma() -> TestResult {
    use crate::intel_gpu_gem::Placement;
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, mut info, card) = registered(&mut gt, &w, platform);
    let source = RenderFile::new();
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user, 0x80, 0x18180005);
    let id = prototype(&file, card, &user);
    let baseline = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    // VM-private storage is an actual native Xe object, imported with its
    // original immutable owner. No fake storage-kind flag is manufactured.
    let vm = create_vm(&source, &info, &user);
    let vm_bo = create_bo(&source, &info, &user, 4096, vm);
    let vm_object = source.gem.object(vm_bo).unwrap();
    assert!(vm_object.vm_owner().is_some());
    let imported = file.gem.import(&vm_object).unwrap();
    refused_storage(&file, card, &user, &mailbox, [handles[0], imported], id);
    // The driver's SystemWc placement is real retyped storage. A discrete
    // native creator currently uses WB instead; importing a real WC backing
    // through the shared same-card helper must still fail the EXEC boundary.
    match source
        .gem
        .create_placed(4096, None, Placement::SystemWc, |_, _| Ok(()))
    {
        Err(FsError::NotImplemented) => assert!(cfg!(target_arch = "aarch64")),
        result => {
            let wc = source.gem.object(result.unwrap()).unwrap();
            assert!(wc.is_wc());
            let imported = file.gem.import(&wc).unwrap();
            assert!(Arc::ptr_eq(&wc, &file.gem.object(imported).unwrap()));
            refused_storage(&file, card, &user, &mailbox, [handles[0], imported], id);
        }
    }
    // USERPTR retains an actual pin over an allocator-owned model page.
    *user.mapping.lock() = Some(
        file.gem
            .object(handles[1])
            .unwrap()
            .backing(0, 4096)
            .unwrap(),
    );
    let pinned =
        GemObject::from_user_pins(user.pin_user_pages(0x4000, 1, true).unwrap(), 0x18).unwrap();
    assert!(pinned.is_userptr());
    let imported = file.gem.import(&pinned).unwrap();
    refused_storage(&file, card, &user, &mailbox, [handles[0], imported], id);
    assert_eq!(arena.live_allocations(), baseline);
    assert_eq!(w.0.borrow().writes.len(), writes);
    // The refusals looked the context up, and an execbuffer lookup
    // finalizes a proto-context (spec: created contexts stay proto
    // until execbuffer, GETPARAM or reset-stats lookup), so the same
    // context no longer accepts its first engine map.
    let param = engines_param(&user.wire, id, &[(1, 1)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    // A fresh proto-context still accepts its first map.
    let fresh = prototype(&file, card, &user);
    let param = engines_param(&user.wire, fresh, &[(1, 1)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    // Real LMEM allocation/initialization uses the current native private
    // clear owner. Its object remains local after same-card import/refusal.
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
    // SAFETY: fixture owns this fake LMEM BAR until all backing references drop.
    let vram = unsafe { crate::intel_gpu_vram::Vram::new(bar, layout) }.unwrap();
    info.vram = Some(vram.clone());
    let handle = create_placed(&source, &info, &user, 4096, 2, 4, 2).unwrap();
    let object = source.gem.object(handle).unwrap();
    assert!(object.is_vram());
    let imported = file.gem.import(&object).unwrap();
    let writes = w.0.borrow().writes.len();
    refused_storage(&file, card, &user, &mailbox, [handles[0], imported], id);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(vram.used(), 4096);
    drop(object);
    drop(source);
    drop(file);
    drop(info);
    drop(pinned);
    *user.mapping.lock() = None;
    assert_eq!(vram.used(), 0);
    drop(vram);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    narf_memory::frame::free_pages(frame, 1);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_imported_storage_refuses_before_context_or_dma
);

fn smoke_i915_object_async_cancel_close_and_missing_retirement_keep_owners() -> TestResult {
    for (asynchronous, execute, cpu_failure) in
        [(3, false, false), (2, true, false), (3, true, true)]
    {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt, ack) = discover(platform, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, _, card) = registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let handles = pair(&file, card, &user, 0x80, 0x18180006);
        let weak: Vec<_> = handles
            .into_iter()
            .map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()))
            .collect();
        let id = copy_context(&file, card, &user, 1);
        let baseline = arena.live_allocations();
        raw(&user.wire, handles, id, asynchronous);
        let (context, fence) = {
            let mut call =
                core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            // Drop the caller before it receives its acceptance reply.
            mailbox.accept(&mut gt, 500)
        };
        let mut registered = BTreeMap::new();
        let (_, base) = held(&mut gt, &w, &fence, &mut registered, 501);
        if execute {
            execute_copy(&w, base);
            // The GPU store/breadcrumb is insufficient: withhold all firmware
            // retirement ACKs after the native owner sees this completion.
            w.0.borrow_mut().fail_cpu_sync = cpu_failure;
            for now in 520..529 {
                let result = gt.poll(now);
                assert_eq!(fence.result(), None);
                if cpu_failure {
                    assert!(matches!(result, Poll::Ready(Err(_))));
                    assert_eq!(gt.state(), GtState::Lost);
                    break;
                }
                assert_eq!(result, Poll::Ready(Ok(GtState::SchedulingReady)));
            }
        }
        assert!(arena.live_allocations() > baseline);
        assert!(context.busy());
        // Queue/context and GEM handles all close, but they do not own the
        // terminal proof. No arbitrary CPU mmap exclusion is claimed here.
        let mut close = [0; 8];
        put32(&mut close, 0, id);
        user.wire.store(64, &close);
        assert_eq!(
            file.dispatch_card(card, abi::GEM_CONTEXT_DESTROY, 64, &user),
            Some(Ok(0))
        );
        for handle in handles {
            file.gem.close(handle).unwrap();
        }
        drop(file);
        assert!(weak
            .iter()
            .all(|object| object.upgrade().is_some_and(|object| object.busy() != 0)));
        assert_eq!(fence.result(), None);
        assert!(context.busy());
        w.0.borrow_mut().fail_cpu_sync = false;
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert!(!context.busy());
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        assert!(context.check_epoch(gt.user_epoch().unwrap_or(0)).is_err());
        drop(context);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_cancel_close_and_missing_retirement_keep_owners
);

fn smoke_i915_object_async_raw_mixed_final_conflict_retries_without_partial_fences() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, _, card) = registered(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handles = pair(&file, card, &user, 0x80, 0x18180007);
    let id = copy_context(&file, card, &user, 1);
    let code = file.gem.object(handles[0]).unwrap();
    let object = file.gem.object(handles[1]).unwrap();
    // Only the code object is ASYNC. A later data-object reader must block
    // the synchronous WRITE at the final owner, despite an earlier idle wait.
    raw(&user.wire, handles, id, 1);
    let mut call =
        core::pin::pin!(file.dispatch_card_user(card, abi::GEM_EXECBUFFER2_WR, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(mailbox.pending.lock().len(), 1);
    let foreign = Arc::new(CompletionFence::new());
    object.import_fences(alloc::vec![foreign.clone()], false);
    let pending = mailbox.pending.lock().pop().unwrap();
    let context = pending.context;
    let baseline = arena.live_allocations();
    assert!(matches!(
        gt.submit_user_batch(500, context.clone(), pending.batch),
        Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Residency(FsError::WouldBlock)
        ))
    ));
    assert_eq!(
        code.busy(),
        0,
        "failed final admission published a partial ASYNC fence"
    );
    assert_eq!(object.dma_buf.resv.fences(DmaResvUsage::Read).len(), 1);
    assert!(!context.busy());
    assert!(context.last().is_none());
    assert_eq!(arena.live_allocations(), baseline);
    *pending.reply.result.lock() = Some(Err(FsError::WouldBlock));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(mailbox.pending.lock().is_empty());
    foreign.signal(Ok(())); // independent foreign CPU/GPU reservation producer
    reach(call.as_mut(), &mailbox);
    let (same_context, fence) = mailbox.accept(&mut gt, 600);
    assert!(Arc::ptr_eq(&context, &same_context));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    let mut registered = BTreeMap::new();
    finish_policy(&mut gt, &w, &fence, &mut registered, 601, 2);
    assert_eq!(device_word(&object, 0x80), 0x18180007);
    assert_eq!(code.busy(), 0);
    assert_eq!(object.busy(), 0);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_async",
    smoke_i915_object_async_raw_mixed_final_conflict_retries_without_partial_fences
);
