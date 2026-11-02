// Real boot/GT/scheduler owners and raw native Xe dispatcher. The mailbox only
// carries requests to the !Send device model, as existing userspace fixtures do.
use super::*;
use crate::{
    intel_gpu_huc as huc,
    intel_gpu_render::{tests::User, DeviceInfo, RenderFile},
    intel_gpu_uapi::{put32, put64, u32_at},
    intel_gpu_user::{UserBackend, UserBatch, UserContext, UserStatus},
};
use alloc::boxed::Box;
use core::{
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Waker},
};
use narf_filesystem::{FsError, FsFuture};
use narf_lib::sync::IrqSafeSpinLock;

// Kernel smokes run sequentially. Modes independently withhold ACK/status;
// production never sees these controls or a synthetic status register.
static MODE: AtomicU32 = AtomicU32::new(0);
static LAST_AUTH: AtomicU32 = AtomicU32::new(0);
static DMA_COMPLETIONS: AtomicU32 = AtomicU32::new(0);

fn css() -> Vec<u8> {
    let mut bytes = alloc::vec![0;400]; // CSS128 +code16 +RSA256
    for (at, v) in [
        (0, 6),
        (4, 161),
        (8, 0x10000),
        (16, 0x8086),
        (24, 165),
        (28, 64),
        (32, 64),
        (36, 1),
        (64, 0x00070903),
        (68, u32::MAX),
        (120, u32::MAX),
        (128, 0x12345678),
        (144, 0xabcdef01),
    ] {
        put32(&mut bytes, at, v);
    }
    bytes
}
fn model_boot(video: bool) -> (Window, Arena, GuCBoot<Window, Arena>) {
    let (w, arena) = model();
    {
        let mut d = w.0.borrow_mut();
        d.profile = Some(huc::PLATFORM);
        d.regs.extend([
            (0x130044, 0),
            (0xa188, 2),
            (0xa278, 2),
            (0xd84, 0),
            (0xfd0, 1),
            (0x913c, 5),
            (0x9144, 6),
            (0x9134, 5),
            (0x9114, 0x10),
            (0x9118, 1),
            (0x138000, (18 << 16) | 180),
            (0x13800c, 90),
            (0x145998, (6 << 16) | 60),
            (0x145ef0, 30 << 8),
            (0xd8c, u32::MAX),
            (0xc1dc, 0),
            (0x9140, if video { 0x000f00fd } else { 0x000f00ff }),
        ]); // only VCS1
    }
    let bytes = css();
    let boot = GuCBoot::stage_images(
        w.clone(),
        arena.clone(),
        huc::PLATFORM,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: 0x9a49,
            revision: 3,
            huc_upload_bytes: 144,
            uncached_mocs: None,
        },
        Some(huc::Image::parse(&bytes).unwrap()),
    )
    .unwrap();
    (w, arena, boot)
}
fn model_huc(video: bool) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (w, arena, boot) = model_boot(video);
    (w, arena, GuCGt::from_staged_hardware(boot).unwrap())
}

pub(super) fn complete_dma(d: &mut Device) {
    DMA_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
    assert_eq!(d.regs[&0xc300] & 4095, 0);
    assert_eq!(
        (d.regs[&0xc304], d.regs[&0xc308], d.regs[&0xc30c]),
        (0x80000, 0, 0x70000)
    );
    assert_eq!(d.regs[&0xc310], 144);
    let memory = d.memory[&d.regs[&0xc300]].clone();
    let words = memory.borrow();
    assert_eq!((words[0], words[1], words[6], words[7]), (6, 161, 165, 64));
    assert_eq!((words[32], words[36]), (0x12345678, 0xabcdef01));
    assert_eq!(
        d.regs[&0xc000], 1,
        "HuC must upload while GuC remains reset"
    );
    d.regs.insert(0xc314, 0x200); // START self-clear; HUC flag remains until host disable
}
fn response(memory: &Words, id: u16, hxg: u32) {
    response_payload(memory, id, hxg, &[]);
}
fn response_payload(memory: &Words, id: u16, hxg: u32, payload: &[u32]) {
    let mut words = memory.borrow_mut();
    let tail = words[513];
    words[2048 + (tail & 4095) as usize] = (1 + payload.len() as u32) | (u32::from(id) << 16);
    words[2048 + ((tail + 1) & 4095) as usize] = hxg;
    for (n, value) in payload.iter().enumerate() {
        words[2048 + ((tail + 2 + n as u32) & 4095) as usize] = *value;
    }
    words[513] = (tail + 2 + payload.len() as u32) & 4095;
}
pub(super) fn service_auth(w: &Window, memory: &Words, id: u16, request: &[u32]) {
    assert_eq!(request.len(), 2);
    assert_eq!(request[0], 0x4000); // normal REQUEST, not FAST
    assert!((0x4000..=0x7eff).contains(&id)); // excludes logs and SLPC
    let d = w.0.borrow();
    let (base, bytes) = d
        .memory
        .iter()
        .find(|(base, bytes)| {
            u64::from(**base) + 144 == u64::from(request[1]) && bytes.borrow()[7] == 64
        })
        .expect("auth points into retained HuC RSA");
    assert_eq!(request[1], *base + 144);
    assert_eq!(bytes.borrow()[36], 0xabcdef01);
    drop(d);
    LAST_AUTH.store(u32::from(id), Ordering::Relaxed);
    match MODE.load(Ordering::Relaxed) {
        0 => {
            response(memory, id, 0xf0000000);
            w.0.borrow_mut().regs.insert(0xc1dc, 1);
        }
        1 => response(memory, id, 0xf0000000), // ACK only
        2 => {
            w.0.borrow_mut().regs.insert(0xc1dc, 1);
        } // status only
        3 => response(memory, id, 0xe0000030),
        4 => response(memory, id, 0xf0000001), // positive DATA0 is not HuC success
        5 => response(memory, id, 0xb0000001), // BUSY
        6 => response(memory, id, 0xd0000000), // RETRY
        _ => panic!("invalid HuC fixture mode"),
    }
}
fn primed(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    hardware_discovery(gt, w, 0x130044);
    hardware_scheduling(gt, w);
    SLPC_FIXTURE_MODE.store(0, Ordering::Relaxed);
    gt.begin_slpc(4_000_000).unwrap();
    if gt
        .engines()
        .unwrap()
        .iter()
        .any(|engine| engine.is_decode())
    {
        assert!(
            !gt.prepare_huc(4_000_000).unwrap(),
            "pending PC must not authenticate HuC"
        );
    }
    let completion = gt.begin_context_defaults(4_000_001).unwrap();
    let mut contexts = BTreeMap::new();
    for now in (4_010_000..10_000_000).step_by(10_000) {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut contexts, true);
        if completion.result().is_some()
            && gt.slpc() == crate::intel_gpu_guc_sched::SlpcState::Running
        {
            break;
        }
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert_eq!(gt.slpc(), crate::intel_gpu_guc_sched::SlpcState::Running);
    assert!(gt.user_epoch().is_some());
}
fn authenticate(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    let mut contexts = BTreeMap::new();
    for now in (11_000_000..20_000_000).step_by(10_000) {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if gt.prepare_huc(now).unwrap() {
            return;
        }
        service_contexts(w, &mut contexts, true);
    }
    panic!("HuC authentication did not reach a bounded terminal state");
}
fn stop_gt(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    gt.begin_stop(2_000_000_000).unwrap();
    gen12_until(gt, w, 2_000_010_000, GtState::Stopped);
}

#[derive(Debug)]
struct QueryReply {
    requested: bool,
    result: Option<Result<(u8, u8, u8), FsError>>,
    waker: Option<Waker>,
}
#[derive(Debug)]
struct Backend {
    status: IrqSafeSpinLock<Option<UserStatus>>,
    query: IrqSafeSpinLock<QueryReply>,
}
impl UserBackend for Backend {
    fn status(&self) -> Option<UserStatus> {
        *self.status.lock()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn huc_version(&self) -> FsFuture<'_, (u8, u8, u8)> {
        Box::pin(core::future::poll_fn(|cx| {
            let mut q = self.query.lock();
            q.requested = true;
            q.waker = Some(cx.waker().clone());
            match q.result.take() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            }
        }))
    }
    fn submit<'a>(
        &'a self,
        _: Arc<UserContext>,
        _: UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
}
impl Backend {
    fn finish(&self, gt: &GuCGt<Window, Arena>, current: bool) {
        let epoch = self.status().map_or(0, |s| s.epoch);
        let mut q = self.query.lock();
        assert!(q.requested);
        q.result = Some(gt.huc_version(epoch, || current).ok_or(FsError::NoDevice));
        if let Some(w) = q.waker.take() {
            w.wake();
        }
    }
}
fn raw_info(gt: &GuCGt<Window, Arena>) -> (Arc<Backend>, DeviceInfo) {
    let backend = Arc::new(Backend {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform: huc::PLATFORM,
            submission_version: gt.submission_version(),
            engines: gt.engines().unwrap(),
        })),
        query: IrqSafeSpinLock::new(QueryReply {
            requested: false,
            result: None,
            waker: None,
        }),
    });
    let info = DeviceInfo {
        device_id: 0x9a49,
        platform: huc::PLATFORM,
        memory_bytes: 0x80000000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: Some(backend.clone()),
    };
    (backend, info)
}
fn query_wire(user: &User, size: u32, kind: u16) {
    let mut wire = [0; 40];
    put32(&mut wire, 8, 7);
    put32(&mut wire, 12, size);
    put64(&mut wire, 16, 1024);
    user.store(64, &wire);
    let mut data = [0; 32];
    data[..2].copy_from_slice(&kind.to_le_bytes());
    user.store(1024, &data);
}
fn raw_query(gt: &GuCGt<Window, Arena>, current: bool) -> Result<Vec<u8>, FsError> {
    let (backend, info) = raw_info(gt);
    let file = RenderFile::new();
    let user = User::new();
    query_wire(&user, 0, 1);
    let untouched = user.load(1024, 32);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut call = core::pin::pin!(file.dispatch_user(
            &info,
            crate::intel_gpu_xe_uapi::DEVICE_QUERY,
            64,
            &user
        ));
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
    }
    assert_eq!(u32_at(&user.load(64, 40), 12), 32);
    assert!(!backend.query.lock().requested);
    assert_eq!(user.load(1024, 32), untouched);
    query_wire(&user, 32, 1);
    let mut call = core::pin::pin!(file.dispatch_user(
        &info,
        crate::intel_gpu_xe_uapi::DEVICE_QUERY,
        64,
        &user
    ));
    assert!(call.as_mut().poll(&mut cx).is_pending());
    backend.finish(gt, current);
    match call.as_mut().poll(&mut cx) {
        Poll::Ready(Some(Ok(0))) => Ok(user.load(1024, 32)),
        Poll::Ready(Some(Err(e))) => Err(e),
        other => panic!("raw HuC query {other:?}"),
    }
}

fn smoke_tgl_huc_boot_upload_auth_and_raw_xe_version() -> TestResult {
    MODE.store(0, Ordering::Relaxed);
    DMA_COMPLETIONS.store(0, Ordering::Relaxed);
    let (w, arena, mut gt) = model_huc(true);
    primed(&mut gt, &w);
    let epoch = gt.user_epoch().unwrap();
    assert!(gt.huc_version(epoch, || true).is_none());
    assert_eq!(raw_query(&gt, true), Err(FsError::NoDevice));
    authenticate(&mut gt, &w);
    assert_eq!(gt.huc_version(epoch, || true), Some((7, 9, 3)));
    let reply = raw_query(&gt, true).unwrap();
    assert_eq!(
        (
            u32_at(&reply, 4),
            u32_at(&reply, 8),
            u32_at(&reply, 12),
            u32_at(&reply, 16)
        ),
        (0, 7, 9, 3)
    );
    {
        let d = w.0.borrow();
        let writes = &d.writes;
        let dma: Vec<_> = writes
            .iter()
            .filter(|(r, v)| *r == 0xc314 && v & 0x10001 == 0x10001)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(
            dma,
            alloc::vec![0x02010201, 0x00110011, 0x02010201, 0x00110011]
        );
        assert_eq!(
            writes
                .iter()
                .filter(|p| **p == (0xc314, 0x02000000))
                .count(),
            2
        );
        assert_eq!(w.read32(0xc340) & 3, 3);
    }
    assert_eq!(
        DMA_COMPLETIONS.load(Ordering::Relaxed),
        2,
        "both HuC DMAs independently retired"
    );
    assert_eq!(gt.submission_version(), (1, 0, 0));
    let (_backend, info) = raw_info(&gt);
    let file = RenderFile::new();
    let user = User::new();
    query_wire(&user, 32, 0);
    {
        let mut call = core::pin::pin!(file.dispatch_user(
            &info,
            crate::intel_gpu_xe_uapi::DEVICE_QUERY,
            64,
            &user
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
    }
    assert_eq!(
        (
            u32_at(&user.load(1024, 32), 8),
            u32_at(&user.load(1024, 32), 12)
        ),
        (1, 0)
    );
    w.0.borrow_mut().regs.insert(0xc1dc, u32::MAX);
    assert_eq!(raw_query(&gt, true), Err(FsError::NoDevice));
    w.0.borrow_mut().regs.insert(0xc1dc, 1);
    stop_gt(&mut gt, &w);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_boot_upload_auth_and_raw_xe_version
);

fn smoke_tgl_huc_auth_ack_and_status_are_independent() -> TestResult {
    for stale in [1, u32::MAX] {
        let (w, arena, mut gt) = model_huc(true);
        w.0.borrow_mut().regs.insert(0xc1dc, stale);
        gt.begin(0).unwrap();
        let mut failed = false;
        for now in (10_000..1_000_000).step_by(10_000) {
            gen12_progress(&w);
            if matches!(gt.poll(now), Poll::Ready(Err(_))) {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(!w.0.borrow().writes.contains(&(0xc314, 0x02010201)));
        assert_eq!(arena.live_allocations(), 4);
        stop_gt(&mut gt, &w);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }

    for mode in [1, 2, 3, 4] {
        MODE.store(mode, Ordering::Relaxed);
        let (w, arena, mut gt) = model_huc(true);
        primed(&mut gt, &w);
        let epoch = gt.user_epoch().unwrap();
        assert!(!gt.prepare_huc(11_000_000).unwrap());
        assert_eq!(
            gt.poll(11_000_001),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&w, &mut BTreeMap::new(), true);
        assert_eq!(
            gt.poll(11_000_002),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        if matches!(mode, 3 | 4) {
            w.0.borrow_mut().regs.insert(0xc1dc, 1);
        }
        assert!(gt.huc_version(epoch, || true).is_none());
        assert_eq!(raw_query(&gt, true), Err(FsError::NoDevice));
        if mode == 1 {
            assert_eq!(
                gt.poll(112_000_000),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
        }
        if mode == 2 {
            assert!(matches!(gt.poll(1_012_000_000), Poll::Ready(Err(_))));
        }
        let count = arena.live_allocations();
        assert!(count >= 4);
        stop_gt(&mut gt, &w);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    MODE.store(0, Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_auth_ack_and_status_are_independent
);

fn smoke_tgl_huc_wopcm_preflight_and_locked_agent() -> TestResult {
    for agent in [0, 2] {
        let (w, arena, mut gt) = model_huc(true);
        w.0.borrow_mut()
            .regs
            .extend([(0xc050, 0x1f0001), (0xc340, 0x8001 | agent)]);
        gt.begin(0).unwrap();
        let mut failed = false;
        for now in (10_000..1_000_000).step_by(10_000) {
            gen12_progress(&w);
            if matches!(gt.poll(now), Poll::Ready(Err(_))) {
                failed = true;
                break;
            }
            if gt.state() == GtState::Ready {
                break;
            }
        }
        assert_eq!(failed, agent == 0);
        assert!(!w
            .0
            .borrow()
            .writes
            .iter()
            .any(|(r, _)| matches!(r, 0xc050 | 0xc340)));
        if agent == 0 {
            assert!(!w.0.borrow().writes.contains(&(0xc314, 0x02010201)));
        }
        stop_gt(&mut gt, &w);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    let (w, arena) = model();
    let mut bytes = css();
    put32(&mut bytes, 24, 0x800000);
    assert!(huc::Image::parse(&bytes).is_err());
    assert_eq!(arena.live_allocations(), 0);
    assert!(w.0.borrow().writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_wopcm_preflight_and_locked_agent
);

// Exercise the production physical arena/cache adapter too. The main protocol
// model deliberately has no physical PTE window; do not infer PTE counts from it.
fn production_huc_ptes() {
    use crate::intel_gpu_gt_hw::HardwareInit;
    use crate::intel_gpu_rcs::{GgttArena, SharedArena};
    let (w, fake, staged) = model_boot(false);
    drop(staged);
    assert_eq!(fake.live_allocations(), 0);
    w.0.borrow_mut().regs.extend([(0xa188, 3), (0x130044, 1)]);
    let mut hardware = HardwareInit::new(huc::PLATFORM).unwrap();
    hardware.begin(&w, 0).unwrap();
    let mut policy = None;
    for now in (10_000..1_000_000).step_by(10_000) {
        gen12_progress(&w);
        if let Poll::Ready(result) = hardware.poll(&w, now) {
            policy = Some(result.unwrap());
            break;
        }
    }
    let policy = policy.expect("real hardware-owner cache proof");
    let mut memory = alloc::vec![0u32;4*1024*1024];
    let bar = narf_bus::bar::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xd7190000),
        virt: memory.as_mut_ptr() as u64,
        len: 16 * 1024 * 1024,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write> =
        narf_capabilities::Cap::bootstrap();
    let arena = SharedArena::new(GgttArena::for_gt(bar, cap, huc::PLATFORM));
    let bytes = css();
    let mut boot = GuCBoot::stage_images(
        w,
        arena.clone(),
        huc::PLATFORM,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: 0x9a49,
            revision: 3,
            huc_upload_bytes: 144,
            uncached_mocs: None,
        },
        Some(huc::Image::parse(&bytes).unwrap()),
    )
    .unwrap();
    let h = boot.resources.huc.as_ref().unwrap();
    let index = (0x800000 + u64::from(h.backing.ggtt_offset() / 4096) * 8) as usize / 4;
    let pages = h.backing.size_pages() as usize;
    assert_eq!((memory[index], memory[index + 1]), (0, 0));
    boot.configure_cache(policy).unwrap();
    for page in 0..pages {
        let lo = memory[index + page * 2];
        let hi = memory[index + page * 2 + 1];
        assert_eq!(lo & 0xfff, 1);
        assert!(hi < 128, "real HuC leaves obey DMA39");
        assert_ne!(u64::from(lo & !0xfff) | u64::from(hi) << 32, 0);
    }
    drop(boot);
    for page in 0..pages {
        assert_eq!(
            (memory[index + page * 2], memory[index + page * 2 + 1]),
            (0, 0)
        );
    }
    assert_eq!(arena.live_allocations(), 0);
}

fn smoke_tgl_huc_css_registry_bounds_and_real_layout() -> TestResult {
    production_huc_ptes();
    let (write, read) = narf_firmware::bootstrap_authority();
    write.revoke();
    assert!(matches!(
        huc::Firmware::open(huc::PLATFORM, &read),
        Err(crate::intel_gpu_guc_firmware::FirmwareError::Revoked)
    ));
    let mut bytes = css();
    assert_eq!(huc::Image::parse(&bytes).unwrap().signature.len(), 256);
    bytes.resize(660, 0);
    assert!(huc::Image::parse(&bytes).is_ok());
    bytes.pop();
    assert!(huc::Image::parse(&bytes).is_err());
    for (at, v) in [
        (0, 0x44504324),
        (4, 0),
        (24, 0),
        (28, 0),
        (28, u32::MAX),
        (36, u32::MAX),
    ] {
        let mut b = css();
        put32(&mut b, at, v);
        assert!(huc::Image::parse(&b).is_err());
    }
    let mut actual = alloc::vec![0;589888];
    for (at, v) in [
        (0, 6),
        (4, 161),
        (8, 0x10000),
        (16, 0x8086),
        (24, 147537),
        (28, 64),
        (32, 64),
        (36, 1),
        (64, 0x70903),
    ] {
        put32(&mut actual, at, v);
    }
    assert_eq!(huc::Image::parse(&actual).unwrap().upload.len(), 589632);
    for failure in 1..=4 {
        let (w, arena) = model();
        w.0.borrow_mut().fail_at = Some(failure);
        let bytes = css();
        let result = GuCBoot::stage_images(
            w.clone(),
            arena.clone(),
            huc::PLATFORM,
            CssImage::parse(&image(), 70).unwrap(),
            BootConfig {
                device_id: 0x9a49,
                revision: 3,
                huc_upload_bytes: 144,
                uncached_mocs: None,
            },
            Some(huc::Image::parse(&bytes).unwrap()),
        );
        assert!(matches!(result, Err(BootError::Allocation(_))));
        assert_eq!(arena.live_allocations(), 0);
        assert!(w.0.borrow().writes.is_empty());
    }
    let (w, arena, gt) = model_huc(true);
    assert_eq!(arena.live_allocations(), 4);
    assert!(w.0.borrow().writes.is_empty());
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_css_registry_bounds_and_real_layout
);

#[derive(Clone)]
struct RebeginFault {
    inner: Window,
    armed: Rc<core::cell::Cell<u8>>,
}
impl MmioWindow for RebeginFault {
    fn read32(&self, offset: u64) -> u32 {
        if offset == 0x941c && self.armed.get() != 0 {
            let n = self.armed.get();
            self.armed.set(n.saturating_add(1));
            if n >= 2 {
                return 1;
            }
        }
        self.inner.read32(offset)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.inner.write32(offset, value);
    }
}
fn lower_ready<M: MmioWindow>(boot: &mut GuCBoot<M, Arena>, w: &Window) {
    w.0.borrow_mut().regs.insert(0x130044, 1);
    boot.begin(0).unwrap();
    reset_done(w);
    assert!(boot.poll(1).is_pending());
    assert_eq!(boot.state(), BootState::HucDma);
    complete_dma(&mut w.0.borrow_mut());
    assert!(boot.poll(2).is_pending());
    w.0.borrow_mut()
        .regs
        .extend([(0xc314, 0x10), (0xc000, 0x8000f000)]);
    assert!(boot.poll(3).is_pending());
    assert_eq!(boot.poll(4), Poll::Ready(Ok(BootState::Ready)));
}

fn smoke_tgl_huc_shared_dma_stall_cancel_and_stop_retains_graph() -> TestResult {
    let (w, arena, mut gt) = model_huc(true);
    gt.begin(0).unwrap();
    for now in (10_000..1_000_000).step_by(10_000) {
        if w.read32(0xc314) & 0x201 == 0x201 {
            break;
        }
        gen12_progress(&w);
        assert!(!matches!(gt.poll(now), Poll::Ready(Err(_))));
    }
    assert_eq!(w.read32(0xc314) & 0x201, 0x201);
    let held = arena.live_allocations();
    assert_eq!(held, 4);
    {
        let mut waiter = core::pin::pin!(core::future::poll_fn(|_| gt.poll(1_000_000)));
        assert!(waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(arena.live_allocations(), held);
    assert!(!w.0.borrow().writes.contains(&(0xc314, 0x00110011)));
    gt.begin_stop(2_000_000).unwrap();
    // GuC reset/DMA idle is only the first owner phase. Retain through full reset/media ACK.
    reset_done(&w);
    let _ = gt.poll(2_010_000);
    assert_eq!(arena.live_allocations(), held);
    gen12_until(&mut gt, &w, 2_020_000, GtState::Stopped);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    // Lower boot Stopped is deliberately insufficient, including no scheduler/CT.
    let (w, arena, mut boot) = model_boot(true);
    lower_ready(&mut boot, &w);
    boot.begin_stop(100).unwrap();
    reset_done(&w);
    assert_eq!(boot.poll(101), Poll::Ready(Ok(BootState::Stopped)));
    let retained = arena.live_allocations();
    drop(boot);
    assert_eq!(arena.live_allocations(), retained);
    // Actual reload sets Staged before a fallible re-begin. Inject Busy at
    // that exact second GDRST read, after stop and complete ADS preflight.
    let (w, arena, staged) = model_boot(true);
    drop(staged);
    let fault = RebeginFault {
        inner: w.clone(),
        armed: Rc::new(core::cell::Cell::new(0)),
    };
    let bytes = css();
    let mut boot = GuCBoot::stage_images(
        fault.clone(),
        arena.clone(),
        huc::PLATFORM,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: 0x9a49,
            revision: 3,
            huc_upload_bytes: 144,
            uncached_mocs: None,
        },
        Some(huc::Image::parse(&bytes).unwrap()),
    )
    .unwrap();
    lower_ready(&mut boot, &w);
    use crate::intel_gpu_engine::{Engine, EngineSet};
    use crate::intel_gpu_guc_sched::{EngineAds, SchedulingAds};
    let engines = EngineSet::of(&[Engine::Rcs0]);
    let mut config = SchedulingAds {
        engines: [None; Engine::COUNT],
        reset_policy: crate::intel_gpu_reset_policy::ResetPolicy::new(
            huc::PLATFORM,
            0x9a49,
            1200,
            0,
            0x40000000,
            0,
            engines,
            false,
        ),
    };
    config.engines[Engine::Rcs0.index()] = Some(EngineAds {
        golden: 0x30000000,
        bytes: Engine::Rcs0.lrc_pages(huc::PLATFORM) * 4096,
        hwsp: 0x31000000,
    });
    boot.begin_scheduling(config, 100).unwrap();
    reset_done(&w);
    fault.armed.set(1);
    assert_eq!(boot.poll(101), Poll::Ready(Err(BootError::Busy)));
    assert_eq!(boot.state(), BootState::Staged);
    let retained = arena.live_allocations();
    assert_eq!(retained, 4);
    drop(boot);
    assert_eq!(
        arena.live_allocations(),
        retained,
        "failed re-begin cannot erase exposure"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_shared_dma_stall_cancel_and_stop_retains_graph
);

fn smoke_tgl_huc_ct_reply_dispatch_busy_retry_and_loss() -> TestResult {
    for mode in [5, 6] {
        MODE.store(mode, Ordering::Relaxed);
        let (w, arena, mut gt) = model_huc(true);
        primed(&mut gt, &w);
        let mut contexts = BTreeMap::new();
        assert!(!gt.prepare_huc(11_000_000).unwrap());
        let memory = ct_memory(&w);
        let old_head = memory.borrow()[0];
        {
            let mut words = memory.borrow_mut();
            words[0] = (words[1] + 1) & 1023;
        }
        let old_auth = LAST_AUTH.load(Ordering::Relaxed);
        assert_eq!(
            gt.poll(11_000_000),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        assert_eq!(LAST_AUTH.load(Ordering::Relaxed), old_auth);
        memory.borrow_mut()[0] = old_head;
        event(&memory, 0x8003, &[]); // real log sideband event must not reach HuC/context owners
        let _ = gt.poll(11_000_001);
        service_contexts(&w, &mut contexts, true);
        let old = LAST_AUTH.load(Ordering::Relaxed) as u16;
        // Both real owners now have work while the HuC reply remains pending.
        let probe = gt
            .submit_ppgtt_probe_on(11_000_002, crate::intel_gpu_engine::Engine::Rcs0)
            .unwrap();
        let range = gt.slpc_status().unwrap().range;
        gt.begin_slpc_frequency_range(range, 11_000_002).unwrap();
        assert!(probe.completion.result().is_none());
        assert_eq!(gt.slpc(), crate::intel_gpu_guc_sched::SlpcState::Updating);
        assert_eq!(
            gt.poll(11_000_002),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        assert!(gt.huc_version(gt.user_epoch().unwrap(), || true).is_none());
        MODE.store(5, Ordering::Relaxed); // keep the HuC request BUSY through both other lifetimes
        event(&memory, 0x8003, &[]);
        let mut actions = Vec::new();
        let mut completed_at = None;
        for now in 11_000_003..11_000_500 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            actions.extend(service_contexts(&w, &mut contexts, true));
            assert!(gt.huc_version(gt.user_epoch().unwrap(), || true).is_none());
            if probe.completion.result().is_some()
                && gt.slpc() == crate::intel_gpu_guc_sched::SlpcState::Running
            {
                completed_at = Some(now);
                break;
            }
        }
        assert!(
            completed_at.is_some(),
            "context and SLPC must complete independently of BUSY HuC"
        );
        assert_eq!(probe.completion.result(), Some(Ok(())));
        probe.result.verify().unwrap();
        assert_eq!(gt.slpc_status().unwrap().range, range);
        assert!(contexts.is_empty());
        for action in [0x3003, 0x4502, 0x1001, 0x4503, 0x7000] {
            assert!(
                actions.contains(&action),
                "missing real owner action {action:x}"
            );
        }
        let current = LAST_AUTH.load(Ordering::Relaxed) as u16;
        MODE.store(0, Ordering::Relaxed);
        response(&memory, current, 0xd0000000);
        for now in 11_001_000..11_001_030 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut contexts, true);
        }
        assert!(LAST_AUTH.load(Ordering::Relaxed) > u32::from(old));
        assert_eq!(
            gt.huc_version(gt.user_epoch().unwrap(), || true),
            Some((7, 9, 3))
        );
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert_eq!(gt.slpc_status().unwrap().range, range);
        response(&ct_memory(&w), old, 0xf0000000);
        assert_eq!(
            gt.poll(11_001_031),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        if mode == 6 {
            let held = arena.live_allocations();
            response(&ct_memory(&w), 0x7eaa, 0xf0000000);
            assert!(matches!(gt.poll(11_001_032), Poll::Ready(Err(_))));
            assert_eq!(arena.live_allocations(), held);
            assert!(gt
                .huc_version(gt.user_epoch().unwrap_or(0), || true)
                .is_none());
        }
        stop_gt(&mut gt, &w);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    for malformed in [true, false] {
        MODE.store(5, Ordering::Relaxed);
        let (w, arena, mut gt) = model_huc(true);
        primed(&mut gt, &w);
        assert!(!gt.prepare_huc(11_000_000).unwrap());
        assert_eq!(
            gt.poll(11_000_001),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&w, &mut BTreeMap::new(), true);
        let id = LAST_AUTH.load(Ordering::Relaxed) as u16;
        assert_eq!(
            gt.poll(11_000_002),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        let held = arena.live_allocations();
        if malformed {
            response_payload(&ct_memory(&w), id, 0xf0000000, &[0x4000]);
            assert!(matches!(gt.poll(11_000_003), Poll::Ready(Err(_))));
        } else {
            response(&ct_memory(&w), id, 0xb0000002);
            assert_eq!(
                gt.poll(1_010_999_999),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
            assert!(
                matches!(gt.poll(1_011_000_000), Poll::Ready(Err(_))),
                "BUSY must not move the original1s deadline"
            );
        }
        assert_eq!(arena.live_allocations(), held);
        assert!(gt
            .huc_version(gt.user_epoch().unwrap_or(0), || true)
            .is_none());
        stop_gt(&mut gt, &w);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    MODE.store(0, Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_ct_reply_dispatch_busy_retry_and_loss
);

fn smoke_tgl_huc_system_resume_reauth_and_query_cancel() -> TestResult {
    MODE.store(0, Ordering::Relaxed);
    let mut old_epoch = 0;
    for _ in 0..2 {
        let (w, arena, mut gt) = model_huc(true);
        primed(&mut gt, &w);
        let epoch = gt.user_epoch().unwrap();
        assert_ne!(epoch, old_epoch);
        old_epoch = epoch;
        assert_eq!(raw_query(&gt, true), Err(FsError::NoDevice));
        authenticate(&mut gt, &w);
        let (backend, info) = raw_info(&gt);
        let file = RenderFile::new();
        let user = User::new();
        query_wire(&user, 32, 1);
        {
            let mut call = core::pin::pin!(file.dispatch_user(
                &info,
                crate::intel_gpu_xe_uapi::DEVICE_QUERY,
                64,
                &user
            ));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        backend.finish(&gt, true);
        assert!(arena.live_allocations() > 4);
        assert_eq!(raw_query(&gt, false), Err(FsError::NoDevice));
        assert_eq!(raw_query(&gt, true).unwrap()[8], 7);
        gt.begin_stop(30_000_000).unwrap();
        assert!(gt.huc_version(epoch, || true).is_none());
        gen12_until(&mut gt, &w, 30_010_000, GtState::Stopped);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    assert!(!crate::intel_gpu_gt_runtime::autosuspend_profile_eligible(
        Some(huc::PLATFORM),
        false
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_system_resume_reauth_and_query_cancel
);

fn smoke_tgl_huc_disabled_unsupported_and_no_video_refuse() -> TestResult {
    for line in [
        "",
        "narf.intel.huc",
        "narf.intel.huc=0",
        "narf.intel.huc=01",
        "narf.intel.huc=1 narf.intel.huc=1",
        "narf.intel.huc=1 narf.intel.huc",
        "-- narf.intel.huc=1",
        "quiet -- narf.intel.huc=1 narf.intel.huc",
        "narf.intel.huc=0 -- narf.intel.huc=1",
    ] {
        assert!(!huc::opted_in(narf_boot::args::KernelCmdline::new(line)));
    }
    assert!(huc::opted_in(narf_boot::args::KernelCmdline::new(
        "quiet narf.intel.huc=1"
    )));

    for line in [
        "narf.intel.huc=1 -- narf.intel.huc",
        "narf.intel.huc=1 -- narf.intel.huc=1 narf.intel.huc=0",
    ] {
        assert!(huc::opted_in(narf_boot::args::KernelCmdline::new(line)));
    }

    let last = LAST_AUTH.load(Ordering::Relaxed);
    let (w, arena, mut gt) = model_huc(true);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    assert!(gt.prepare_huc(4_000_000).unwrap()); // PC Off: ordinary GuC owner, no HuC auth
    assert_eq!(LAST_AUTH.load(Ordering::Relaxed), last);
    stop_gt(&mut gt, &w);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    let (w, arena, mut gt) = model_huc(false);
    primed(&mut gt, &w);
    assert!(gt.prepare_huc(11_000_000).unwrap());
    assert!(gt.huc_version(gt.user_epoch().unwrap(), || true).is_none());
    assert_eq!(LAST_AUTH.load(Ordering::Relaxed), last);
    stop_gt(&mut gt, &w);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    let (w, arena, mut gt) = hardware_model(huc::PLATFORM, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    assert!(!w.0.borrow().writes.contains(&(0xc314, 0x02010201)));
    stop_gt(&mut gt, &w);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    for platform in [
        GtPlatform::Alchemist,
        GtPlatform::Battlemage,
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake),
        GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP),
    ] {
        let (w, arena) = model();
        let bytes = css();
        let result = GuCBoot::stage_images(
            w.clone(),
            arena.clone(),
            platform,
            CssImage::parse(&image(), 70).unwrap(),
            BootConfig {
                device_id: 0x9a49,
                revision: 3,
                huc_upload_bytes: 144,
                uncached_mocs: None,
            },
            Some(huc::Image::parse(&bytes).unwrap()),
        );
        assert!(matches!(result, Err(BootError::Unsupported)));
        assert_eq!(arena.live_allocations(), 0);
        assert!(w.0.borrow().writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_huc",
    smoke_tgl_huc_disabled_unsupported_and_no_video_refuse
);
