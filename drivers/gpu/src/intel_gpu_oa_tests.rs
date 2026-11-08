//! OA conversations against literal Linux b90c984d xe_oa.c register,
//! report and UAPI vectors: errno order, LRI emission, buffer landing,
//! wrap/clear/head, status loss, authority and reset/suspend teardown.
use super::*;
use crate::intel_gpu_guc_boot::BootError;
use crate::intel_gpu_rcs::{GpuAllocator, SubmitError};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const MTL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
const LNL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
const BASE: u32 = 0x0100_0000;
/// Host page addresses reported by [`Hw::with_host_pages`].
const HOST: u64 = 0x0000_0040_0000_0000;

struct Hw {
    regs: IrqSafeSpinLock<BTreeMap<u64, u32>>,
    writes: IrqSafeSpinLock<Vec<(u64, u32)>>,
    memory: IrqSafeSpinLock<BTreeMap<u32, u32>>,
    live: AtomicUsize,
    freed: AtomicUsize,
    coherent: AtomicBool,
    /// Nonzero: the next allocation reports host pages from this address.
    host: AtomicU64,
}
impl Hw {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            regs: IrqSafeSpinLock::new(BTreeMap::new()),
            writes: IrqSafeSpinLock::new(Vec::new()),
            memory: IrqSafeSpinLock::new(BTreeMap::new()),
            live: AtomicUsize::new(0),
            freed: AtomicUsize::new(0),
            coherent: AtomicBool::new(true),
            host: AtomicU64::new(0),
        })
    }
    /// A model whose reservation reports host page addresses. The OA
    /// fixtures never dereference them; sys_mmap's fixtures map real ones.
    fn with_host_pages() -> Arc<Self> {
        let hw = Self::new();
        hw.host.store(HOST, Ordering::Relaxed);
        hw
    }
    fn set(&self, reg: u64, value: u32) {
        self.regs.lock().insert(reg, value);
    }
    fn get(&self, reg: u64) -> u32 {
        *self.regs.lock().get(&reg).unwrap_or(&0)
    }
    fn take(&self) -> Vec<(u64, u32)> {
        core::mem::take(&mut *self.writes.lock())
    }
    fn word(&self, at: u32, value: u32) {
        let mut memory = self.memory.lock();
        if value == 0 {
            memory.remove(&at);
        } else {
            memory.insert(at, value);
        }
    }
    fn peek(&self, at: u32) -> u32 {
        *self.memory.lock().get(&at).unwrap_or(&0)
    }
    /// A report whose words are tag+i; word 0/1 carry the id/timestamp.
    fn report(&self, at: u32, size: u32, tag: u32, circ: u32) {
        for i in 0..size / 4 {
            self.word((at + i * 4) % circ, tag.wrapping_add(i) | 0x100);
        }
    }
}
#[derive(Clone)]
struct Window(Arc<Hw>);
impl MmioWindow for Window {
    fn read32(&self, offset: u64) -> u32 {
        self.0.get(offset)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.0.writes.lock().push((offset, value));
        // The OA TLB invalidation completes as soon as it is requested.
        let stored = if offset == OA_TLB_INV_CR { 0 } else { value };
        self.0.set(offset, stored);
    }
}
struct Memory {
    hw: Arc<Hw>,
    pages: u32,
    coherent: bool,
    host: u64,
}
impl GpuBacking for Arc<Memory> {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn host_frame(&self, page: u32) -> Option<u64> {
        (self.host != 0 && page < self.pages).then(|| self.host + u64::from(page) * 4096)
    }
    fn ggtt_offset(&self) -> u32 {
        BASE
    }
    fn size_pages(&self) -> u32 {
        self.pages
    }
    fn read32(&self, offset: u64) -> u32 {
        assert_eq!(offset & 3, 0);
        self.hw.peek(offset as u32)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.hw.word(offset as u32, value);
    }
}
#[derive(Clone)]
struct Allocator(Arc<Hw>);
impl GpuAllocator for Allocator {
    type Backing = Arc<Memory>;
    fn alloc(&mut self, pages: u32) -> Result<Self::Backing, SubmitError> {
        assert_eq!(self.0.live.swap(1, Ordering::Relaxed), 0);
        Ok(Arc::new(Memory {
            hw: self.0.clone(),
            pages,
            coherent: self.0.coherent.load(Ordering::Relaxed),
            host: self.0.host.load(Ordering::Relaxed),
        }))
    }
    fn free(&mut self, _: Self::Backing) {
        assert_eq!(self.0.live.swap(0, Ordering::Relaxed), 1);
        self.0.freed.fetch_add(1, Ordering::Relaxed);
    }
    fn live_allocations(&self) -> usize {
        self.0.live.load(Ordering::Relaxed)
    }
    fn live_pages(&self) -> u32 {
        0
    }
}
impl BootAllocator for Allocator {
    fn sync_for_device(&mut self, _: &Self::Backing) -> Result<(), BootError> {
        Ok(())
    }
}

struct Wire {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    installed: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
}
impl Wire {
    fn new() -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(vec![0; 0x20000]),
            installed: IrqSafeSpinLock::new(None),
        }
    }
    fn put(&self, at: u64, bytes: &[u8]) {
        self.write(at, bytes).unwrap();
    }
    /// A drm_xe_ext_set_property chain, one 48-byte record per 64 bytes.
    fn chain(&self, at: u64, properties: &[(u32, u64)]) -> u64 {
        for (i, &(property, value)) in properties.iter().enumerate() {
            let here = at + i as u64 * 64;
            let next = if i + 1 == properties.len() {
                0
            } else {
                here + 64
            };
            let mut record = [0u8; 48];
            record[..8].copy_from_slice(&next.to_le_bytes());
            record[16..20].copy_from_slice(&property.to_le_bytes());
            record[24..32].copy_from_slice(&value.to_le_bytes());
            self.put(here, &record);
        }
        at
    }
    fn file(&self) -> Arc<dyn FileOps> {
        self.installed.lock().take().expect("installed OA stream")
    }
}
impl IoctlContext for Wire {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        let at = usize::try_from(address).map_err(|_| FsError::BadAddress)?;
        let end = at
            .checked_add(destination.len())
            .ok_or(FsError::BadAddress)?;
        destination.copy_from_slice(self.bytes.lock().get(at..end).ok_or(FsError::BadAddress)?);
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        let at = usize::try_from(address).map_err(|_| FsError::BadAddress)?;
        let end = at.checked_add(source.len()).ok_or(FsError::BadAddress)?;
        self.bytes
            .lock()
            .get_mut(at..end)
            .ok_or(FsError::BadAddress)?
            .copy_from_slice(source);
        Ok(())
    }
    fn write_u64_release(&self, address: u64, value: u64) -> Result<(), FsError> {
        if address & 7 != 0 {
            return Err(FsError::InvalidData);
        }
        self.write(address, &value.to_le_bytes())
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn install_file(&self, file: Arc<dyn FileOps>, cloexec: bool) -> Result<i32, FsError> {
        assert!(!cloexec);
        assert!(self.installed.lock().replace(file).is_none());
        Ok(41)
    }
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("OA fixture transactions are synchronous"),
    }
}
fn allow() -> bool {
    true
}
fn deny() -> bool {
    false
}
const ALLOW: Gate = Gate { capable: allow };
const DENY: Gate = Gate { capable: deny };

fn device(card: u32, platform: GtPlatform, graphics: u16) -> Device {
    Device {
        card,
        platform,
        graphics,
        timestamp: 19_200_000,
        engines: EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs0]),
        reserve: DEFAULT_BUFFER,
        media_engines: None,
        media_timestamp: None,
    }
}

/// UserBackend over a real Unit; configuration jobs execute as the ring's
/// MI_LOAD_REGISTER_IMM writes against the same register model.
struct Backend {
    device: Device,
    hw: Arc<Hw>,
    unit: IrqSafeSpinLock<Option<Unit<Allocator>>>,
    jobs: IrqSafeSpinLock<Vec<Vec<u32>>>,
    now: AtomicU64,
}
impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OaFixtureBackend")
    }
}
impl Backend {
    fn new(device: Device) -> Arc<Self> {
        Self::over(device, Hw::new())
    }
    fn over(device: Device, hw: Arc<Hw>) -> Arc<Self> {
        let unit = Unit::new(
            Allocator(hw.clone()),
            device.platform,
            device.graphics,
            &Window(hw.clone()),
            || true,
        )
        .unwrap();
        hw.take();
        Arc::new(Self {
            device,
            hw,
            unit: IrqSafeSpinLock::new(Some(unit)),
            jobs: IrqSafeSpinLock::new(Vec::new()),
            now: AtomicU64::new(0),
        })
    }
    fn poll(&self, now: u64) {
        self.unit
            .lock()
            .as_mut()
            .unwrap()
            .poll(&Window(self.hw.clone()), now, || true);
    }
    fn execute(&self, words: &[u32]) {
        let mut at = 0;
        while at < words.len() {
            assert_eq!(words[at] & 0xffff_ff00, 0x1100_0000);
            let n = (words[at] & 0xff) as usize / 2 + 1;
            for pair in words[at + 1..at + 1 + 2 * n].chunks_exact(2) {
                Window(self.hw.clone()).write32(u64::from(pair[0]), pair[1]);
            }
            at += 1 + 2 * n;
        }
    }
}
impl UserBackend for Backend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn oa_device(&self) -> Option<Device> {
        Some(self.device)
    }
    fn oa_control(&self, session: Arc<Session>, request: Request) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let now = self.now.load(Ordering::Relaxed);
            let io = Window(self.hw.clone());
            let jobs =
                self.unit
                    .lock()
                    .as_mut()
                    .unwrap()
                    .begin(&io, &session, &request, now, || true)?;
            for job in &jobs {
                self.jobs.lock().push(job.words().to_vec());
                self.execute(job.words());
            }
            self.unit
                .lock()
                .as_mut()
                .unwrap()
                .finish(&io, &session, &request, now, || true)
        })
    }
    fn oa_read<'a>(
        &'a self,
        session: Arc<Session>,
        output: &'a mut [u8],
        blocking: bool,
    ) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.unit.lock().as_mut().unwrap().read(
                &Window(self.hw.clone()),
                &session,
                output,
                blocking,
                || true,
            )
        })
    }
    fn submit<'a>(
        &'a self,
        _: Arc<crate::intel_gpu_user::UserContext>,
        _: crate::intel_gpu_user::UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
}
fn none(_: u32) -> Option<(u16, usize, QueueBinding)> {
    None
}
fn render_queue(id: u32) -> Option<(u16, usize, QueueBinding)> {
    let (class, width, engine) = match id {
        3 => (0, 1, Engine::Rcs0),
        4 => (4, 2, Engine::Ccs0),
        // Width-1 compute queue, mirroring smoke_oa_exec_queue_oar_oac_streams'
        // id 11: the only queue OAC formats can bind (OAC on render is
        // rejected; a width-2 compute queue is rejected with EOPNOTSUPP).
        11 => (4, 1, Engine::Ccs0),
        _ => return None,
    };
    Some((
        class,
        width,
        QueueBinding::new(
            id,
            crate::intel_gpu_user::UserContext::for_engine(engine),
            Arc::new(|| true),
        ),
    ))
}
fn uuid(n: u8) -> [u8; 36] {
    let mut uuid = *b"01234567-89ab-cdef-0123-456789abcde0";
    uuid[35] = b"0123456789abcdef"[usize::from(n & 15)];
    uuid
}
/// drm_xe_oa_config at `at` with registers at `at + 64`.
fn config_wire(wire: &Wire, at: u64, uuid: [u8; 36], regs: &[(u32, u32)]) -> u64 {
    let mut head = [0u8; 56];
    head[8..44].copy_from_slice(&uuid);
    head[44..48].copy_from_slice(&(regs.len() as u32).to_le_bytes());
    head[48..56].copy_from_slice(&(at + 64).to_le_bytes());
    wire.put(at, &head);
    for (i, &(addr, value)) in regs.iter().enumerate() {
        wire.put(at + 64 + i as u64 * 8, &addr.to_le_bytes());
        wire.put(at + 68 + i as u64 * 8, &value.to_le_bytes());
    }
    at
}
fn add(backend: &Backend, wire: &Wire, n: u8, regs: &[(u32, u32)]) -> u64 {
    let at = config_wire(wire, 0x10000, uuid(n), regs);
    add_config(Some(backend), at, wire, ALLOW).unwrap()
}
const A24U40: u64 = 5 << 8;
const OAC192: u64 = 3 | 2 << 8;
const PEC64U64: u64 = 5 | 1 << 8 | 1 << 16;

fn smoke_oa_query_units_formats_and_timestamp() -> TestResult {
    let mtl = device(50, MTL, 1270);
    assert_eq!(query(None), vec![0; 16]);
    assert_eq!(query(Some(device(50, MTL, 1280))), vec![0; 16]);
    let reply = query(Some(mtl));
    assert_eq!(reply.len(), 16 + 72 + 2 * 8);
    assert_eq!(u32_at(&reply, 8), 1);
    assert_eq!((u32_at(&reply, 16 + 8), u32_at(&reply, 16 + 12)), (0, 0));
    assert_eq!(u64_at(&reply, 16 + 16), CAPS);
    assert_eq!(u64_at(&reply, 16 + 24), 19_200_000);
    assert_eq!(u64_at(&reply, 16 + 64), 2);
    // RENDER/0 then COMPUTE/0 on gt 0; BCS0 has no OA unit.
    assert_eq!(
        &reply[88..104],
        &[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    for (platform, graphics, profile) in [
        (GtPlatform::Alchemist, 1255, Some(Profile::Dg2)),
        (MTL, 1270, Some(Profile::Mtl)),
        (MTL, 1271, Some(Profile::Mtl)),
        (MTL, 1274, Some(Profile::Mtl)),
        (MTL, 1260, None),
        (GtPlatform::Battlemage, 2001, Some(Profile::Xe2)),
        (LNL, 2004, Some(Profile::Xe2)),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
            3000,
            None,
        ),
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
            1200,
            None,
        ),
    ] {
        assert_eq!(Profile::of(platform, graphics), profile);
    }
    // decode_oa_format: exact (type, select, counter size, BC) per platform.
    assert_eq!(Profile::Mtl.decode(1 | 5 << 8), Some(4));
    assert_eq!(Profile::Mtl.decode(A24U40), Some(5));
    assert_eq!(Profile::Mtl.decode(3 | 1 << 8), Some(6));
    assert_eq!(Profile::Mtl.decode(OAC192), Some(7));
    assert_eq!(Profile::Mtl.decode(4 | 2 << 8), Some(9));
    assert_eq!(Profile::Mtl.decode(PEC64U64), None);
    assert_eq!(Profile::Mtl.decode(0), None);
    assert_eq!(Profile::Dg2.decode(4 | 1 << 8), None);
    assert_eq!(Profile::Xe2.decode(PEC64U64), Some(10));
    assert_eq!(
        Profile::Xe2.decode(5 | 1 << 8 | 1 << 16 | 1 << 24),
        Some(11)
    );
    assert_eq!(Profile::Xe2.decode(A24U40), None);
    assert_eq!(FORMATS[11].wire(), 5 | 1 << 8 | 1 << 16 | 1 << 24);
    // xe_oa_timestamp_frequency: Wa_18013179988 scales by 3 - CTC shift.
    assert_eq!(timestamp_frequency(1255, 19_200_000, 1 << 1), 76_800_000);
    assert_eq!(timestamp_frequency(1255, 19_200_000, 3 << 1), 19_200_000);
    // The workaround's continuation covers MTL/Arrow 12.70..12.74.
    assert_eq!(timestamp_frequency(1270, 19_200_000, 1 << 1), 76_800_000);
    assert_eq!(timestamp_frequency(1274, 19_200_000, 2 << 1), 38_400_000);
    assert_eq!(timestamp_frequency(1260, 19_200_000, 1 << 1), 19_200_000);
    assert_eq!(timestamp_frequency(2001, 19_200_000, 1 << 1), 19_200_000);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_query_units_formats_and_timestamp
);

fn smoke_oa_open_property_privilege_and_errno_order() -> TestResult {
    let backend = Backend::new(device(51, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let open_at = |props: &[(u32, u64)], gate: Gate, queues: QueueLookup<'_>| {
        let at = wire.chain(0x1000, props);
        ready(open(Some(backend.clone()), at, &wire, queues, gate, None))
    };
    let invalid = Err(Error::Fs(FsError::InvalidData));
    assert_eq!(
        ready(open(None, 0x1000, &wire, &none, ALLOW, None)),
        Err(Error::Fs(FsError::NoDevice))
    );
    // Seventeen chained extensions are E2BIG; the walk reads before parsing.
    let many: Vec<_> = (0..17).map(|_| (2u32, 1u64)).collect();
    assert_eq!(open_at(&many, ALLOW, &none), Err(Error::Errno(E2BIG)));
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            0x7fff_0000,
            &wire,
            &none,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::BadAddress))
    );
    let at = wire.chain(0x1000, &[(2, 1)]);
    wire.put(at + 8, &1u32.to_le_bytes());
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &none, ALLOW, None)),
        invalid
    );
    let at = wire.chain(0x1000, &[(2, 1)]);
    wire.put(at + 20, &1u32.to_le_bytes());
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &none, ALLOW, None)),
        invalid
    );
    for props in [
        &[(0u32, 0u64)][..],
        &[(14, 0)],
        &[(1, 1)],
        &[(4, 1 << 8)],
        &[(5, 32)],
        &[(12, 3 << 17)],
        &[(12, 64 << 10)],
        &[(12, 256 << 20)],
        &[(13, 0)],
        &[(10, 1025)],
        // NO_PREEMPT without an exec queue precedes the privilege check.
        &[(9, 1)],
    ] {
        assert_eq!(open_at(props, DENY, &none), invalid);
    }
    assert_eq!(
        open_at(&[(7, 5)], DENY, &render_queue),
        Err(Error::Fs(FsError::NotFound))
    );
    assert_eq!(
        open_at(&[(7, 4)], DENY, &render_queue),
        Err(Error::Errno(EOPNOTSUPP))
    );
    assert_eq!(
        open_at(&[(2, 1)], DENY, &none),
        Err(Error::Fs(FsError::PermissionDenied))
    );
    // A global stream without sampling, then a missing format.
    assert_eq!(open_at(&[(4, A24U40)], ALLOW, &none), invalid);
    assert_eq!(open_at(&[(2, 1)], ALLOW, &none), invalid);
    // An exec queue without sampling is unprivileged until the exponent.
    assert_eq!(
        open_at(&[(7, 3), (4, A24U40), (5, 5)], DENY, &render_queue),
        invalid
    );
    // A non-OAG logical engine of the queue's class.
    assert_eq!(
        open_at(&[(7, 3), (8, 1), (4, A24U40)], DENY, &render_queue),
        invalid
    );
    let base = [(2u32, 1u64), (4, A24U40), (3, config), (12, 128 << 10)];
    let with = |extra: &[(u32, u64)]| {
        let mut props = base.to_vec();
        props.extend_from_slice(extra);
        props
    };
    assert_eq!(open_at(&with(&[(13, 513)]), ALLOW, &none), invalid);
    let busy = Permit::take(51, 0).unwrap();
    assert_eq!(
        open_at(&with(&[]), ALLOW, &none),
        Err(Error::Fs(FsError::Busy))
    );
    drop(busy);
    assert_eq!(open_at(&with(&[(10, 1)]), ALLOW, &none), invalid);
    assert_eq!(
        open_at(&with(&[(10, 1), (11, 0x4000)]), ALLOW, &none),
        invalid
    );
    assert_eq!(open_at(&with(&[(3, 99)]), ALLOW, &none), invalid);
    assert_eq!(
        open_at(&[(7, 4), (4, A24U40), (3, config)], DENY, &render_queue),
        Err(Error::Errno(EOPNOTSUPP))
    );
    assert!(
        backend.hw.take().is_empty(),
        "refusals never touch the unit"
    );
    // A 32 MiB buffer is inside the Linux range: the unit grows its
    // reservation past the 16 MiB default instead of returning ENOMEM.
    let _fd = open_at(&with(&[(12, 32 << 20)]), ALLOW, &none).unwrap();
    let file32 = wire.file();
    assert_eq!(ready(file32.ioctl_user(INFO, 0x5000, &wire)), Ok(0));
    let mut bytes = [0u8; 40];
    wire.read(0x5000, &mut bytes).unwrap();
    assert_eq!(u64_at(&bytes, 8), 32 << 20);
    assert!(oa_status_string(51).contains("oa_buffer_size: 33554432"));
    // buffer_field(32 MiB) == 5 in the programmed OABUFFER word.
    assert!(backend
        .hw
        .take()
        .iter()
        .any(|&(reg, value)| reg == OABUFFER && value == BASE | 1 | 5 << 3));
    drop(file32);
    backend.poll(1);
    let _ = backend.hw.take();
    // Valid exec queue stream open succeeds unprivileged when sample=false:
    let _fd = open_at(&[(7, 3), (4, A24U40), (3, config)], DENY, &render_queue).unwrap();
    let file = wire.file();
    drop(file);
    backend.poll(1);
    let _ = backend.hw.take();
    // C truncation: a 2^32 wait becomes 0 and then the default of one; the
    // unit id and metric set are u32 as in the source.
    assert_eq!(
        open_at(
            &with(&[(13, 1 << 32), (1, 1 << 32), (3, config | 1 << 32)]),
            ALLOW,
            &none
        ),
        Ok(41)
    );
    let file = wire.file();
    assert_eq!(
        open_at(&with(&[]), ALLOW, &none),
        Err(Error::Fs(FsError::Busy))
    );
    drop(file);
    backend.poll(1);
    assert_eq!(open_at(&with(&[]), ALLOW, &none), Ok(41));
    drop(wire.file());
    backend.poll(2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_open_property_privilege_and_errno_order
);

/// Configurable OA buffer size (issue #1777): the Linux 128 KiB..=128 MiB
/// range, 16 MiB default, out-of-range refusal, reservation growth past
/// the default, and growth refused while a user mapping aliases the old
/// pages. The session's INFO size, the programmed OABUFFER field and the
/// sysfs `oa_buffer_size` node all track the requested size.
fn smoke_oa_buffer_size_min_max_default_out_of_range() -> TestResult {
    use narf_filesystem::sysfs::Kobject;
    const READ: u32 = 1;
    const PRIVATE: u32 = 2;
    let backend = Backend::over(device(61, MTL, 1270), Hw::with_host_pages());
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let base = [(2u32, 1u64), (4, A24U40), (3, config)];
    let open_at = |props: &[(u32, u64)]| {
        let at = wire.chain(0x1000, props);
        ready(open(Some(backend.clone()), at, &wire, &none, ALLOW, None))
    };
    let with = |size: Option<u64>| {
        let mut props = base.to_vec();
        if let Some(size) = size {
            props.push((12, size));
        }
        props
    };
    let info = |file: &Arc<dyn FileOps>| {
        assert_eq!(ready(file.ioctl_user(INFO, 0x5000, &wire)), Ok(0));
        let mut bytes = [0u8; 40];
        wire.read(0x5000, &mut bytes).unwrap();
        u64_at(&bytes, 8)
    };
    let invalid = Err(Error::Fs(FsError::InvalidData));

    // Out of range on either side, non-power-of-two, and an explicit zero.
    for size in [64 << 10, 256 << 20, 3 << 17, 0] {
        assert_eq!(open_at(&with(Some(size))), invalid);
    }
    assert!(
        backend.hw.take().is_empty(),
        "refusals never touch the unit"
    );

    // Default: no property 12 keeps the 16 MiB reservation.
    let _fd = open_at(&with(None)).unwrap();
    let file = wire.file();
    assert_eq!(info(&file), 16 << 20);
    assert!(oa_status_string(61).contains("oa_buffer_size: 16777216"));
    drop(file);
    backend.poll(1);

    // Minimum: 128 KiB opens against the 16 MiB reservation, no growth,
    // and mmap still demands the whole session buffer.
    let _fd = open_at(&with(Some(128 << 10))).unwrap();
    let file = wire.file();
    assert_eq!(info(&file), 128 << 10);
    assert_eq!(file.validate_mmap(0, 128 << 10, READ, PRIVATE), Ok(READ));
    assert_eq!(
        file.validate_mmap(0, 16 << 20, READ, PRIVATE),
        Err(FsError::InvalidData)
    );
    assert!(oa_status_string(61).contains("oa_buffer_size: 16777216"));
    drop(file);
    backend.poll(1);

    // A live mapping pins the reservation: growth past it is ENOMEM, and
    // the refused open leaves the unit usable once the mapping drops.
    let _fd = open_at(&with(None)).unwrap();
    let file = wire.file();
    let mapping = file.mmap_backing(0, 16 << 20).unwrap();
    drop(file);
    assert_eq!(
        open_at(&with(Some(32 << 20))),
        Err(Error::Fs(FsError::OutOfMemory))
    );
    drop(mapping);
    backend.poll(1);
    let _fd = open_at(&with(Some(32 << 20))).unwrap();
    let file = wire.file();
    assert_eq!(info(&file), 32 << 20);
    assert!(oa_status_string(61).contains("oa_buffer_size: 33554432"));
    assert!(backend
        .hw
        .take()
        .iter()
        .any(|&(reg, value)| reg == OABUFFER && value == BASE | 1 | 5 << 3));
    drop(file);
    backend.poll(1);
    let _ = backend.hw.take();

    // Maximum: 128 MiB grows the reservation; the sysfs node follows it,
    // and the OABUFFER field is buffer_field(128 MiB) == 7.
    let _fd = open_at(&with(Some(128 << 20))).unwrap();
    let file = wire.file();
    assert_eq!(info(&file), 128 << 20);
    assert!(oa_status_string(61).contains("oa_buffer_size: 134217728"));
    assert!(backend
        .hw
        .take()
        .iter()
        .any(|&(reg, value)| reg == OABUFFER && value == BASE | 1 | 7 << 3));
    let card = Kobject::new_root("card61");
    install_metrics_for_test(61, &card);
    let oa = card.get_child("oa").expect("oa child exists");
    assert_eq!(
        oa.attr_show("oa_buffer_size").as_deref(),
        Some("134217728\n")
    );
    assert!(oa
        .attr_show("oa_status")
        .is_some_and(|status| status.contains("oa_buffer_size: 134217728")));
    drop(file);
    backend.poll(1);
    assert!(backend.unit.lock().as_ref().unwrap().idle());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_buffer_size_min_max_default_out_of_range
);

fn smoke_oa_config_registry_errno_order_ids_and_whitelists() -> TestResult {
    let backend = Backend::new(device(52, MTL, 1270));
    let wire = Wire::new();
    let invalid = Err(Error::Fs(FsError::InvalidData));
    let at = config_wire(&wire, 0x10000, uuid(1), &[(0x9888, 1)]);
    assert_eq!(
        add_config(None, at, &wire, ALLOW),
        Err(Error::Fs(FsError::NoDevice))
    );
    assert_eq!(
        add_config(Some(&*backend), 0x7fff_0000, &wire, DENY),
        Err(Error::Fs(FsError::PermissionDenied))
    );
    assert_eq!(
        add_config(Some(&*backend), 0x7fff_0000, &wire, ALLOW),
        Err(Error::Fs(FsError::BadAddress))
    );
    for (offset, value) in [(0u64, 1u64), (48, 0)] {
        config_wire(&wire, 0x10000, uuid(1), &[(0x9888, 1)]);
        wire.put(at + offset, &value.to_le_bytes());
        assert_eq!(add_config(Some(&*backend), at, &wire, ALLOW), invalid);
    }
    config_wire(&wire, 0x10000, uuid(1), &[]);
    assert_eq!(add_config(Some(&*backend), at, &wire, ALLOW), invalid);
    for (index, byte) in [(8usize, b'0'), (0, b'g')] {
        let mut bad = uuid(1);
        bad[index] = byte;
        config_wire(&wire, 0x10000, bad, &[(0x9888, 1)]);
        assert_eq!(add_config(Some(&*backend), at, &wire, ALLOW), invalid);
    }
    let mut head = [0u8; 4];
    config_wire(&wire, 0x10000, uuid(1), &[(0x9888, 1)]);
    head.copy_from_slice(&(MAX_CONFIG_REGS + 1).to_le_bytes());
    wire.put(at + 44, &head);
    assert_eq!(
        add_config(Some(&*backend), at, &wire, ALLOW),
        Err(Error::Fs(FsError::OutOfMemory))
    );
    // Per register: address fault, then address validity, then value fault.
    let edge: u64 = 0x20000 - 4;
    let mut config = [0u8; 56];
    config[8..44].copy_from_slice(&uuid(1));
    config[44..48].copy_from_slice(&1u32.to_le_bytes());
    config[48..56].copy_from_slice(&edge.to_le_bytes());
    wire.put(at, &config);
    wire.put(edge, &0x9888u32.to_le_bytes());
    assert_eq!(
        add_config(Some(&*backend), at, &wire, ALLOW),
        Err(Error::Fs(FsError::BadAddress))
    );
    wire.put(edge, &0x9890u32.to_le_bytes());
    assert_eq!(add_config(Some(&*backend), at, &wire, ALLOW), invalid);
    let first = add(&backend, &wire, 1, &[(0x9888, 1), (0xd04, 0x200)]);
    let second = add(&backend, &wire, 2, &[(0xe458, 3)]);
    assert_eq!((first, second), (1, 2));
    assert_eq!(
        add_config(
            Some(&*backend),
            config_wire(&wire, 0x10000, uuid(1), &[(0x9888, 1)]),
            &wire,
            ALLOW
        ),
        Err(Error::Errno(EADDRINUSE))
    );
    assert_eq!(
        lookup(52, 1).unwrap().regs(),
        &[(0x9888, 1), (0xd04, 0x200)]
    );
    let remove = |id: u64, gate| {
        wire.put(0x3000, &id.to_le_bytes());
        remove_config(Some(&*backend), 0x3000, &wire, gate)
    };
    assert_eq!(remove(1, DENY), Err(Error::Fs(FsError::PermissionDenied)));
    assert_eq!(
        remove_config(Some(&*backend), 0x7fff_0000, &wire, ALLOW),
        Err(Error::Fs(FsError::BadAddress))
    );
    assert_eq!(
        remove(1 << 32 | 1, ALLOW),
        Err(Error::Fs(FsError::NotFound))
    );
    assert_eq!(remove(1, ALLOW), Ok(0));
    assert_eq!(remove(1, ALLOW), Err(Error::Fs(FsError::NotFound)));
    // idr_alloc(.., 1, 0) reuses the lowest free id.
    assert_eq!(add(&backend, &wire, 3, &[(0x9884, 0)]), 1);
    assert_eq!(remove(1, ALLOW), Ok(0));
    assert_eq!(remove(2, ALLOW), Ok(0));
    // xe_oa_is_valid_config_reg_addr per graphics version.
    for (graphics, addr, valid) in [
        (1270, 0x38d100, true),
        (2004, 0x38d100, false),
        (2004, 0x13000, true),
        (1270, 0x13000, false),
        (1255, 0x20cc, true),
        (1270, 0x20cc, false),
        (1255, 0x394200, false),
        (2001, 0x394200, true),
        (1255, 0x393200, true),
        (1255, 0xe45c, true),
        (2004, 0xe758, true),
        (1270, 0xdd48, true),
        (1270, 0xdd4c, false),
        (1270, 0xd04, true),
        (2004, 0xd04, false),
    ] {
        assert_eq!(
            valid_register(graphics, addr),
            valid,
            "{graphics} {addr:#x}"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_config_registry_errno_order_ids_and_whitelists
);

fn smoke_oa_lri_groups_and_ordered_ring_jobs() -> TestResult {
    let regs: Vec<(u32, u32)> = (0..379u32).map(|i| (0x9888, i)).collect();
    assert_eq!(lri(&regs[..1]), vec![0x1100_0001, 0x9888, 0]);
    let one = lri(&regs[..126]);
    assert_eq!((one.len(), one[0]), (253, 0x1100_00fb));
    let two = lri(&regs[..127]);
    assert_eq!(
        (two[0], two[253], two.len()),
        (0x1100_00fb, 0x1100_0001, 256)
    );
    let jobs = config_jobs(&regs);
    assert_eq!(jobs.len(), 2);
    let words = jobs[0].words();
    assert_eq!(words.len(), 3 + 2 * 378);
    assert_eq!(
        (words[0], words[253], words[506]),
        (0x1100_00fb, 0x1100_00fb, 0x1100_00fb)
    );
    assert_eq!(&words[757..759], &[0x9888, 377]);
    assert_eq!(jobs[1].words(), &[0x1100_0001, 0x9888, 378]);
    // One job, its ARB word and completion fit the smallest ring budget.
    assert!(words.len() + 1 + 32 <= 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_lri_groups_and_ordered_ring_jobs
);

fn open_stream(backend: &Arc<Backend>, wire: &Wire, props: &[(u32, u64)]) -> Arc<dyn FileOps> {
    let at = wire.chain(0x1000, props);
    assert_eq!(
        ready(open(Some(backend.clone()), at, wire, &none, ALLOW, None)),
        Ok(41)
    );
    wire.file()
}
/// open_stream bound to an exec queue: OAR/OAC formats are per-context-only
/// since d9594ad0d1 and cannot open system-wide. The caller passes the queue
/// id as property 7 in `props` and the resolver that answers it.
fn open_stream_on_queue(
    backend: &Arc<Backend>,
    wire: &Wire,
    props: &[(u32, u64)],
    queues: QueueLookup<'_>,
) -> Arc<dyn FileOps> {
    let at = wire.chain(0x1000, props);
    assert_eq!(
        ready(open(Some(backend.clone()), at, wire, queues, ALLOW, None)),
        Ok(41)
    );
    wire.file()
}
fn session_of(backend: &Backend) -> Arc<Session> {
    backend
        .unit
        .lock()
        .as_ref()
        .unwrap()
        .session
        .clone()
        .unwrap()
}

fn smoke_oa_source_register_sequences_per_profile() -> TestResult {
    // MTL 12.70: metric set, LRI job, buffer, control, TLB invalidate, close.
    let backend = Backend::new(device(53, MTL, 1270));
    let wire = Wire::new();
    let config = add(
        &backend,
        &wire,
        1,
        &[(0x9888, 0x1234), (0xd04, GT_NOA_ENABLE)],
    );
    backend.hw.set(SQCNT1, 0x11);
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, config), (5, 5), (12, 128 << 10)],
    );
    let gtt = BASE;
    assert_eq!(
        backend.hw.take(),
        vec![
            (OA_DEBUG, 0x5062_0060),
            (OAGLBCTXCTRL, 0x17),
            (SQCNT1, 0x6000_0011),
            (0x9888, 0x1234),
            (RPM_CONFIG1, GT_NOA_ENABLE),
            (OASTATUS, 0),
            (OAHEADPTR, gtt),
            (OABUFFER, gtt | 1),
            (OATAILPTR, gtt),
            (OACONTROL, 0x15),
        ]
    );
    assert_eq!(
        *backend.jobs.lock(),
        vec![vec![0x1100_0003, 0x9888, 0x1234, 0xd04, GT_NOA_ENABLE]]
    );
    let info = |file: &Arc<dyn FileOps>| {
        assert_eq!(ready(file.ioctl_user(INFO, 0x5000, &wire)), Ok(0));
        let mut bytes = [0u8; 40];
        wire.read(0x5000, &mut bytes).unwrap();
        u64_at(&bytes, 8)
    };
    assert_eq!(info(&file), 128 << 10);
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert!(
        backend.hw.take().is_empty(),
        "ENABLE on an enabled stream is a no-op"
    );
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert_eq!(backend.hw.take(), vec![(OACONTROL, 0), (OA_TLB_INV_CR, 1)]);
    drop(file);
    backend.poll(10);
    assert_eq!(
        backend.hw.take(),
        vec![(OA_DEBUG, 0x4000_4000), (RPM_CONFIG1, 0), (SQCNT1, 0x11)]
    );
    assert!(backend.unit.lock().as_ref().unwrap().idle());

    // MTL 12.71 skips the OA TLB invalidation; 256 KiB encodes field 1.
    for (size, field) in [
        (128 << 10, 0),
        (256 << 10, 1),
        (16 << 20, 7),
        (32 << 20, 5),
        (128 << 20, 7),
    ] {
        assert_eq!(buffer_field(size), field);
    }
    let backend = Backend::new(device(54, MTL, 1271));
    let config = add(&backend, &wire, 1, &[(0x9888, 0)]);
    // This half used OAC192, which can no longer open system-wide
    // (d9594ad0d1). The format is incidental here — this half proves the
    // 12.71 TLB skip and the buffer field, both format-independent — so it
    // uses the OAG format, as the first half does; OAC192 coverage lives in
    // the read-wrap test (per-context) and the exec-queue tests.
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, config), (12, 256 << 10)],
    );
    let writes = backend.hw.take();
    assert!(writes.contains(&(OABUFFER, BASE | 1 | 1 << 3)));
    assert!(writes.contains(&(OACONTROL, (5 << 2) | 1)));
    assert!(writes.contains(&(OAGLBCTXCTRL, 1)));
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert_eq!(backend.hw.take(), vec![(OACONTROL, 0)]);
    drop(file);
    backend.poll(1);

    // Xe2 LNL: PEC counters need the three trigger bits, PES disaggregation
    // and a report-multiple circular size.
    let backend = Backend::new(device(55, LNL, 2004));
    let config = add(&backend, &wire, 1, &[(0x13000, 5)]);
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, PEC64U64), (3, config), (12, 128 << 10)],
    );
    let writes = backend.hw.take();
    assert_eq!(writes[0], (OA_DEBUG, 0x5062_0060 | 0x2180 << 16 | 0x2180));
    assert!(writes.contains(&(OACONTROL, PES_DISAG_EN | 0x104 | 1)));
    assert_eq!(session_of(&backend).circ, 131_072 - 131_072 % 576);
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert_eq!(backend.hw.take(), vec![(OACONTROL, 0)]);
    drop(file);
    backend.poll(1);

    // DG2 12.55: Wa_1508761755 DOP gating around the metric set.
    let backend = Backend::new(device(56, GtPlatform::Alchemist, 1255));
    let config = add(&backend, &wire, 1, &[(0x20cc, 5)]);
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, config), (6, 1), (12, 128 << 10)],
    );
    let writes = backend.hw.take();
    assert_eq!(
        &writes[..2],
        &[(ROW_CHICKEN, 0x0020_0020), (ROW_CHICKEN2, 0x0001_0001)]
    );
    assert!(
        !writes.iter().any(|(reg, _)| *reg == OACONTROL),
        "opened disabled"
    );
    drop(file);
    backend.poll(1);
    let writes = backend.hw.take();
    assert_eq!(
        &writes[..2],
        &[(ROW_CHICKEN, 0x0020_0000), (ROW_CHICKEN2, 0x0001_0000)]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_source_register_sequences_per_profile
);

fn smoke_oa_tail_landing_partial_reports_and_wait_threshold() -> TestResult {
    let backend = Backend::new(device(57, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 0)]);
    let file = open_stream(
        &backend,
        &wire,
        &[
            (2, 1),
            (4, A24U40),
            (3, config),
            (5, 5),
            (12, 128 << 10),
            (13, 2),
        ],
    );
    let session = session_of(&backend);
    let hw = &backend.hw;
    let circ = 128 << 10;
    hw.report(0, 256, 0x10, circ);
    hw.report(256, 256, 0x20, circ);
    hw.set(OATAILPTR, BASE + 512);
    // Not yet due: the 5 ms period starts at enable.
    backend.poll(POLL_NS - 1);
    assert_eq!(session.ready.mask(), 0);
    // The second report is held until the following header lands.
    backend.poll(POLL_NS);
    assert_eq!(backend.unit.lock().as_ref().unwrap().tail, 256);
    assert_eq!(
        session.ready.mask(),
        0,
        "one landed report < WAIT_NUM_REPORTS"
    );
    hw.word(512, 0x30);
    // 64 bytes of a fourth report are a partial report and are subtracted.
    hw.set(OATAILPTR, BASE + 768 + 64);
    backend.poll(2 * POLL_NS);
    assert_eq!(backend.unit.lock().as_ref().unwrap().tail, 512);
    assert_eq!(session.ready.mask(), POLL_IN);
    let mut out = vec![0u8; 4096];
    let read = |out: &mut [u8], nonblocking| {
        ready(file.read_with_options(0, out, ReadOptions { nonblocking }))
    };
    assert_eq!(read(&mut out, false), Ok(512));
    assert_eq!(u32_at(&out, 0), 0x110);
    assert_eq!(u32_at(&out, 256 + 4), 0x121);
    // Report id/timestamp words are cleared; the head follows the copy.
    assert_eq!((hw.peek(0), hw.peek(4), hw.peek(8)), (0, 0, 0x112));
    assert_eq!((hw.peek(256), hw.peek(260)), (0, 0));
    assert_eq!(hw.get(OAHEADPTR), BASE + 512);
    assert_eq!(session.ready.mask(), 0);
    // Below the threshold: blocking waits, nonblocking returns EAGAIN.
    assert_eq!(read(&mut out, false), Err(FsError::WouldBlock));
    assert_eq!(read(&mut out, true), Err(FsError::WouldBlock));
    assert_eq!(hw.get(OAHEADPTR), BASE + 512);
    drop(file);
    backend.poll(3 * POLL_NS);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_tail_landing_partial_reports_and_wait_threshold
);

fn smoke_oa_read_wrap_clear_enospc_status_eio_and_info() -> TestResult {
    let backend = Backend::new(device(58, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 0)]);
    // OAC192 is per-context-only since d9594ad0d1: a system-wide open is
    // rejected with InvalidData. The 192-byte report size is load-bearing
    // here (the straddle arithmetic below needs circ % 192 != 0, and no
    // 192-byte format decodes system-wide on MTL), so the test binds the
    // width-1 compute queue (id 11) instead of switching format.
    let file = open_stream_on_queue(
        &backend,
        &wire,
        &[(2, 1), (4, OAC192), (3, config), (7, 11), (12, 128 << 10)],
        &render_queue,
    );
    let session = session_of(&backend);
    let hw = &backend.hw;
    let circ: u32 = 128 << 10;
    assert_ne!(circ % 192, 0);
    // A 192-byte report straddles the ring end; the next header lands at 64.
    let start = circ - 128;
    {
        let mut unit = backend.unit.lock();
        let unit = unit.as_mut().unwrap();
        unit.head = start;
        unit.tail = start;
    }
    hw.report(start, 192, 0x40, circ);
    hw.report(64, 192, 0x80, circ);
    hw.set(OATAILPTR, BASE + 256);
    let mut small = vec![0u8; 100];
    let read =
        |out: &mut [u8]| ready(file.read_with_options(0, out, ReadOptions { nonblocking: true }));
    assert_eq!(read(&mut small), Err(FsError::NoSpace));
    assert_eq!(session.ready.mask(), POLL_IN, "ENOSPC keeps pollin");
    assert_eq!(hw.get(OAHEADPTR), BASE, "nothing was consumed");
    let mut out = vec![0u8; 4096];
    assert_eq!(read(&mut out), Ok(192));
    for i in 0..48u32 {
        assert_eq!(u32_at(&out, i as usize * 4), (0x40 + i) | 0x100);
    }
    // The whole straddling report is zeroed, both before and after the end.
    assert!((0..48).all(|i| hw.peek((start + i * 4) % circ) == 0));
    assert_ne!(hw.peek(64), 0, "the following report is untouched");
    assert_eq!(hw.get(OAHEADPTR), BASE + 64);
    // Relevant status bits are cleared, others kept; EIO keeps pollin.
    hw.set(OASTATUS, (1 << 2) | (1 << 6) | (1 << 8));
    hw.set(OATAILPTR, BASE + 256 + 192);
    hw.word(256, 0xc0);
    assert_eq!(read(&mut out), Err(crate::intel_gpu_user::io_error()));
    assert_eq!(hw.get(OASTATUS), 1 << 8);
    assert_eq!(session.ready.mask(), POLL_IN);
    assert_eq!(ready(file.ioctl_user(STATUS, 0x5000, &wire)), Ok(0));
    let mut status = [0u8; 40];
    wire.read(0x5000, &mut status).unwrap();
    assert_eq!(u64_at(&status, 8), (1 << 2) | (1 << 3));
    assert_eq!(
        ready(file.ioctl_user(STATUS, 0x7fff_0000, &wire)),
        Err(FsError::BadAddress)
    );
    assert_eq!(read(&mut out), Ok(192));
    assert_eq!(hw.get(OAHEADPTR), BASE + 256);
    drop(file);
    backend.poll(1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_read_wrap_clear_enospc_status_eio_and_info
);

static AUTHORITY: AtomicBool = AtomicBool::new(true);
fn authority() -> bool {
    AUTHORITY.load(Ordering::Acquire)
}

fn smoke_oa_descriptor_authority_blocking_config_and_reopen() -> TestResult {
    let backend = Backend::new(device(59, MTL, 1270));
    let wire = Wire::new();
    let first = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let second = add(&backend, &wire, 2, &[(0x9884, 2), (0x9888, 3)]);
    // Opened disabled and without a period: reads are EINVAL.
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, first), (6, 1), (12, 128 << 10)],
    );
    let read = |file: &Arc<dyn FileOps>, nonblocking| {
        let mut out = [0u8; 512];
        ready(file.read_with_options(0, &mut out, ReadOptions { nonblocking }))
    };
    assert_eq!(read(&file, true), Err(FsError::InvalidData));
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert_eq!(read(&file, false), Err(FsError::InvalidData), "no period");
    assert_eq!(read(&file, true), Err(FsError::WouldBlock));
    assert_eq!(ready(file.write(0, &[0])), Err(FsError::BadFd));
    assert_eq!(
        ready(file.ioctl_user(0x6905, 0, &wire)),
        Err(FsError::InvalidData)
    );
    // CONFIG: open-only properties are EINVAL, unknown sets ENODEV, success
    // returns the previous id after the new jobs retire.
    backend.jobs.lock().clear();
    let at = wire.chain(0x2000, &[(2, 1)]);
    assert_eq!(
        ready(file.ioctl_user(CONFIG, at, &wire)),
        Err(FsError::InvalidData)
    );
    let at = wire.chain(0x2000, &[(3, 77)]);
    assert_eq!(
        ready(file.ioctl_user(CONFIG, at, &wire)),
        Err(FsError::NoDevice)
    );
    let at = wire.chain(0x2000, &[(3, second), (10, 1)]);
    assert_eq!(
        ready(file.ioctl_user(CONFIG, at, &wire)),
        Err(FsError::InvalidData)
    );
    assert!(backend.jobs.lock().is_empty());
    let at = wire.chain(0x2000, &[(3, second)]);
    assert_eq!(ready(file.ioctl_user(CONFIG, at, &wire)), Ok(first));
    assert_eq!(
        *backend.jobs.lock(),
        vec![vec![0x1100_0003, 0x9884, 2, 0x9888, 3]]
    );
    assert_eq!(ready(file.ioctl_user(CONFIG, at, &wire)), Ok(second));
    drop(file);
    backend.poll(1);
    // Current authority is required at every read and control.
    AUTHORITY.store(true, Ordering::Release);
    let gate = Gate { capable: authority };
    let at = wire.chain(
        0x1000,
        &[(2, 1), (4, A24U40), (3, first), (5, 9), (12, 128 << 10)],
    );
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &none, gate, None)),
        Ok(41)
    );
    let installed = wire.file();
    drop(installed);
    backend.poll(2);
    // A fresh descriptor whose authority is revoked after installation.
    let session_file = {
        let at = wire.chain(
            0x1000,
            &[(2, 1), (4, A24U40), (3, first), (5, 9), (12, 128 << 10)],
        );
        ready(open(Some(backend.clone()), at, &wire, &none, gate, None)).unwrap();
        wire.file()
    };
    let session = session_of(&backend);
    AUTHORITY.store(false, Ordering::Release);
    let file = File {
        session: session.clone(),
        backend: backend.clone(),
        gate,
        syncobjs: None,
    };
    assert_eq!(file.poll_readiness(), POLL_ERR | POLL_HUP);
    let mut out = [0u8; 256];
    assert_eq!(
        ready(file.read_with_options(0, &mut out, ReadOptions { nonblocking: true })),
        Err(FsError::PermissionDenied)
    );
    assert_eq!(
        ready(file.ioctl_user(DISABLE, 0, &wire)),
        Err(FsError::PermissionDenied)
    );
    AUTHORITY.store(true, Ordering::Release);
    assert_eq!(session.ready.mask(), POLL_IN | POLL_ERR | POLL_HUP);
    assert_eq!(
        ready(file.read_with_options(0, &mut out, ReadOptions { nonblocking: true })),
        Err(FsError::PermissionDenied)
    );
    drop(file);
    drop(session_file);
    drop(session);
    backend.poll(3);
    assert!(backend.unit.lock().as_ref().unwrap().idle());
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, first), (12, 128 << 10)],
    );
    drop(file);
    backend.poll(4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_descriptor_authority_blocking_config_and_reopen
);

fn unit_with_stream(card: u32, hw: &Arc<Hw>) -> (Unit<Allocator>, Arc<Session>) {
    let mut unit = Unit::new(
        Allocator(hw.clone()),
        MTL,
        1270,
        &Window(hw.clone()),
        || true,
    )
    .unwrap();
    let config = Arc::new(Config::new(1, uuid(1), vec![(0x9888, 1)], 1, 0, 0));
    let session = Session::new(
        device(card, MTL, 1270),
        FORMATS[5],
        true,
        Some(5),
        1,
        128 << 10,
        Engine::Rcs0,
        Permit::take(card, 0).unwrap(),
        config,
        false,
        None,
        None,
        false,
        0,
        0,
        true,
    );
    let request = Request::Open { enable: true };
    let io = Window(hw.clone());
    assert_eq!(
        unit.begin(&io, &session, &request, 0, || true)
            .unwrap()
            .len(),
        1
    );
    unit.finish(&io, &session, &request, 0, || true).unwrap();
    (unit, session)
}

/// Like [`unit_with_stream`], but opened disabled: the stream attaches
/// (so the session holds the unit's pages and a mapping can alias them)
/// without enabling the unit, so it is never exposed.
fn unit_with_unexposed_stream(card: u32, hw: &Arc<Hw>) -> (Unit<Allocator>, Arc<Session>) {
    let mut unit = Unit::new(
        Allocator(hw.clone()),
        MTL,
        1270,
        &Window(hw.clone()),
        || true,
    )
    .unwrap();
    let config = Arc::new(Config::new(1, uuid(1), vec![(0x9888, 1)], 1, 0, 0));
    let session = Session::new(
        device(card, MTL, 1270),
        FORMATS[5],
        true,
        Some(5),
        1,
        128 << 10,
        Engine::Rcs0,
        Permit::take(card, 0).unwrap(),
        config,
        false,
        None,
        None,
        false,
        0,
        0,
        true,
    );
    let request = Request::Open { enable: false };
    let io = Window(hw.clone());
    assert_eq!(
        unit.begin(&io, &session, &request, 0, || true)
            .unwrap()
            .len(),
        1
    );
    unit.finish(&io, &session, &request, 0, || true).unwrap();
    (unit, session)
}

fn smoke_oa_reset_suspend_loss_and_buffer_retention() -> TestResult {
    // begin_stop (reset or system suspend): terminal stream, halt, release.
    let hw = Hw::new();
    let (mut unit, session) = unit_with_stream(60, &hw);
    assert!(!unit.idle(), "an open stream holds the GT awake");
    unit.invalidate();
    assert_eq!(session.precheck(false), Err(FsError::NoDevice));
    let mut out = [0u8; 512];
    assert_eq!(
        unit.read(&Window(hw.clone()), &session, &mut out, false, || true),
        Err(FsError::NoDevice)
    );
    hw.take();
    unit.halt(&Window(hw.clone()), || true);
    assert_eq!(
        hw.take(),
        vec![
            (OACONTROL, 0),
            (OA_DEBUG, 0x4000_4000),
            (RPM_CONFIG1, 0),
            (SQCNT1, 0)
        ]
    );
    assert!(unit.idle());
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (0, 1)
    );
    drop(session);

    // An exposed buffer without a reset proof is never returned.
    let hw = Hw::new();
    let (unit, session) = unit_with_stream(61, &hw);
    drop(unit);
    assert_eq!(session.precheck(false), Err(FsError::NoDevice));
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    drop(session);

    // An unexposed reservation is freed; incoherent storage is refused.
    let hw = Hw::new();
    drop(
        Unit::new(
            Allocator(hw.clone()),
            MTL,
            1270,
            &Window(hw.clone()),
            || true,
        )
        .unwrap(),
    );
    assert_eq!(hw.freed.load(Ordering::Relaxed), 1);
    hw.coherent.store(false, Ordering::Relaxed);
    assert!(matches!(
        Unit::new(
            Allocator(hw.clone()),
            MTL,
            1270,
            &Window(hw.clone()),
            || true
        ),
        Err(FsError::Unsupported)
    ));
    assert_eq!(hw.freed.load(Ordering::Relaxed), 2);
    assert!(matches!(
        Unit::new(Allocator(Hw::new()), MTL, 1260, &Window(Hw::new()), || true),
        Err(FsError::Unsupported)
    ));

    // Access loss during the tail check poisons the unit and the stream.
    let hw = Hw::new();
    let (mut unit, session) = unit_with_stream(62, &hw);
    unit.poll(&Window(hw.clone()), POLL_NS, || false);
    assert!(!unit.idle());
    assert_eq!(session.precheck(false), Err(FsError::NoDevice));
    assert_eq!(
        unit.begin(&Window(hw.clone()), &session, &Request::Enable, 0, || true)
            .map(|jobs| jobs.len()),
        Err(FsError::NoDevice)
    );
    unit.halt(&Window(hw.clone()), || true);
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    drop(session);

    // A tail outside the owned ring is malformed occupancy, not data.
    let hw = Hw::new();
    let (mut unit, session) = unit_with_stream(63, &hw);
    hw.set(OATAILPTR, BASE + (128 << 10));
    unit.poll(&Window(hw.clone()), POLL_NS, || true);
    assert_eq!(session.ready.mask(), POLL_IN | POLL_ERR | POLL_HUP);
    assert_eq!(
        unit.read(&Window(hw.clone()), &session, &mut out, false, || true),
        Err(FsError::NoDevice)
    );
    // An all-ones MMIO read is device loss.
    unit.halt(&Window(hw.clone()), || true);
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    drop(session);
    let hw = Hw::new();
    let (mut unit, session) = unit_with_stream(60, &hw);
    hw.set(OATAILPTR, u32::MAX);
    assert_eq!(
        unit.read(&Window(hw.clone()), &session, &mut out, false, || true),
        Err(FsError::NoDevice)
    );
    assert!(!unit.idle());
    unit.halt(&Window(hw.clone()), || true);
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_reset_suspend_loss_and_buffer_retention
);

/// xe_oa_mmap: EACCES, then whole-buffer length, then read-only
/// MAP_PRIVATE. A mapping passing all three becomes a private PFN mapping
/// (VM_DONTCOPY) of the buffer pages, never a read()-backed private copy
/// that would consume reports. A backing without host pages is ENODEV.
fn smoke_oa_mmap_source_checks_then_private_pfn_backing() -> TestResult {
    const READ: u32 = 1;
    const PRIVATE: u32 = 2;
    let backend = Backend::new(device(47, MTL, 1270));
    let wire = Wire::new();
    let first = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let size = 128 << 10;
    let file = open_stream(
        &backend,
        &wire,
        &[(2, 1), (4, A24U40), (3, first), (6, 1), (12, size as u64)],
    );
    assert_eq!(file.mmap_max_prot(0), READ);
    assert_eq!(
        file.mmap_private_pfn(0),
        Some(PrivatePfnMap { dont_copy: true })
    );
    assert_eq!(file.validate_mmap(0, size, READ, PRIVATE), Ok(READ));
    // The source never inspects vm_pgoff.
    assert_eq!(file.validate_mmap(1 << 20, size, READ, PRIVATE), Ok(READ));
    // A PROT_NONE private mapping passes the source checks too.
    assert_eq!(file.validate_mmap(0, size, 0, PRIVATE), Ok(0));
    // The model backing has no host pages to remap.
    assert!(matches!(file.mmap_backing(0, size), Err(FsError::NoDevice)));
    for len in [size - 4096, size + 4096, 16 << 20] {
        assert_eq!(
            file.validate_mmap(0, len, READ, PRIVATE),
            Err(FsError::InvalidData)
        );
    }
    // VM_WRITE, VM_EXEC, MAP_SHARED and MAP_SHARED_VALIDATE (VM_MAYSHARE).
    for (prot, flags) in [
        (READ | 2, PRIVATE),
        (READ | 4, PRIVATE),
        (READ, 1),
        (READ, 3),
        (0, 1),
    ] {
        assert_eq!(
            file.validate_mmap(0, size, prot, flags),
            Err(FsError::InvalidData)
        );
    }
    // Privilege precedes the size and VMA checks.
    let denied = File {
        session: session_of(&backend),
        backend: backend.clone(),
        gate: DENY,
        syncobjs: None,
    };
    assert_eq!(
        denied.validate_mmap(0, 4096, READ | 2, 1),
        Err(FsError::PermissionDenied)
    );
    drop(denied);
    drop(file);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_mmap_source_checks_then_private_pfn_backing
);

/// remap_pfn_range of the stream's buffer pages: the first buffer-size
/// pages of the reservation from the VMA start whatever vm_pgoff is, mapped
/// write-back. Each mapping holds the pages: a descriptor close while mapped
/// keeps the stream (the VMA holds the file), the last unmap ends it and the
/// unit admits the next stream, and a GT release while mapped defers the
/// reservation to the last munmap instead of leaking it.
fn smoke_oa_mmap_pages_hold_stream_and_survive_unit_release() -> TestResult {
    let size = 256usize << 10;
    let pages = size / 4096;
    let hw = Hw::with_host_pages();
    let backend = Backend::over(device(44, MTL, 1270), hw.clone());
    let wire = Wire::new();
    let first = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let props = [(2, 1), (4, A24U40), (3, first), (5, 5), (12, size as u64)];
    let file = open_stream(&backend, &wire, &props);
    let session = session_of(&backend);
    let expected: Vec<u64> = (0..pages as u64).map(|page| HOST + page * 4096).collect();
    let one = file.mmap_backing(0, size).unwrap();
    assert_eq!(one.frames, expected);
    assert_eq!(one.memory_type, narf_memory::MemoryType::WriteBack);
    assert!(one.lifetime.is_some());
    let two = file.mmap_backing(7 << 20, size).unwrap();
    assert_eq!(two.frames, expected);
    assert!(matches!(
        file.mmap_backing(0, size + 4096),
        Err(FsError::InvalidData)
    ));
    let held = session.pages.lock().clone().unwrap();
    assert_eq!(held.live_maps(), 2);
    drop(two);
    assert_eq!(held.live_maps(), 1);

    // close(fd) while mapped: the mapping's file reference keeps the stream.
    let mapping_file = file.clone();
    drop(file);
    assert!(!session.stop.load(Ordering::Acquire));
    assert!(session.enabled());
    assert!(matches!(
        ready(open(
            Some(backend.clone()),
            wire.chain(0x1000, &props),
            &wire,
            &none,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::Busy))
    ));
    // munmap: the token and the last file reference go; the next exclusive
    // open tears the old stream down and attaches to the same reservation.
    drop(one);
    drop(mapping_file);
    assert_eq!(held.live_maps(), 0);
    assert!(session.stop.load(Ordering::Acquire));
    drop(session);
    backend.poll(1);
    let file = open_stream(&backend, &wire, &props);
    let session = session_of(&backend);
    assert!(Arc::ptr_eq(&session.pages.lock().clone().unwrap(), &held));

    // A verified GT reset while mapped: the stream is terminal, new
    // mappings are ENODEV, the live ones keep their pages, and the
    // reservation is freed at the last munmap — never while mapped, and
    // exactly once (the fixture allocator panics on a second free).
    let mapping = file.mmap_backing(0, size).unwrap();
    let mapping_two = file.mmap_backing(0, size).unwrap();
    assert_eq!(held.live_maps(), 2);
    let mut unit = backend.unit.lock().take().unwrap();
    unit.invalidate();
    unit.halt(&Window(hw.clone()), || true);
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    assert!(matches!(file.mmap_backing(0, size), Err(FsError::NoDevice)));
    assert_eq!(held.live_maps(), 2);
    assert_eq!(mapping.frames, expected);
    drop(mapping);
    assert_eq!(held.live_maps(), 1);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    drop(mapping_two);
    assert_eq!(held.live_maps(), 0);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (0, 1)
    );
    drop(file);
    drop(session);

    // An exposed unit dropped without a reset proof while mapped keeps
    // the deliberate retention: the engine may still DMA into the
    // reservation, so even the last munmap must not free it.
    let hw = Hw::with_host_pages();
    let (unit, session) = unit_with_stream(40, &hw);
    let probe = session.pages.lock().clone().unwrap();
    let mapping = probe.map(64).unwrap();
    drop(unit);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    drop(mapping);
    assert_eq!(probe.live_maps(), 0);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    drop(session);

    // An unexposed unit dropped while mapped defers the same way: no
    // free while the mapping lives, free at the last munmap.
    let hw = Hw::with_host_pages();
    let (unit, session) = unit_with_unexposed_stream(41, &hw);
    let probe = session.pages.lock().clone().unwrap();
    let mapping = probe.map(64).unwrap();
    drop(unit);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (1, 0)
    );
    drop(mapping);
    assert_eq!(probe.live_maps(), 0);
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (0, 1)
    );
    drop(session);

    // Without a live mapping the same release frees the reservation.
    let hw = Hw::with_host_pages();
    let (mut unit, session) = unit_with_stream(43, &hw);
    let probe = session.pages.lock().clone().unwrap();
    assert_eq!(probe.live_maps(), 0);
    unit.invalidate();
    unit.halt(&Window(hw.clone()), || true);
    // SAFETY: the model's OA unit is stopped and no DMA remains.
    unsafe { unit.release_after_reset() };
    assert_eq!(
        (
            hw.live.load(Ordering::Relaxed),
            hw.freed.load(Ordering::Relaxed)
        ),
        (0, 1)
    );
    assert!(matches!(probe.map(32), Err(FsError::NoDevice)));
    drop(session);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_mmap_pages_hold_stream_and_survive_unit_release
);

/// create_dynamic_oa_sysfs_entry / sysfs_remove_group: metrics/<uuid>/id
/// follows the registry, including lowest-free id reuse.
fn smoke_oa_metrics_sysfs_uuid_id_follows_registry() -> TestResult {
    use narf_filesystem::sysfs::Kobject;
    let backend = Backend::new(device(46, MTL, 1270));
    let wire = Wire::new();
    let card = Kobject::new_root("card46");
    install_metrics_for_test(46, &card);
    install_metrics_for_test(46, &card);
    assert_eq!(card.child_names(), ["metrics"]);
    let metrics = card.get_child("metrics").unwrap();
    assert!(metrics.child_names().is_empty());
    let name = |n| alloc::string::String::from_utf8(uuid(n).to_vec()).unwrap();
    let id = |n| {
        metrics
            .get_child(&name(n))
            .and_then(|entry| entry.attr_show("id"))
    };
    assert_eq!(add(&backend, &wire, 1, &[(0x9888, 1)]), 1);
    assert_eq!(add(&backend, &wire, 2, &[(0x9888, 2)]), 2);
    assert_eq!(id(1).as_deref(), Some("1\n"));
    assert_eq!(id(2).as_deref(), Some("2\n"));
    assert_eq!(metrics.get_child(&name(1)).unwrap().attr_names(), ["id"]);
    // A refused duplicate publishes nothing.
    assert_eq!(
        add_config(
            Some(&*backend),
            config_wire(&wire, 0x10000, uuid(1), &[(0x9888, 1)]),
            &wire,
            ALLOW
        ),
        Err(Error::Errno(EADDRINUSE))
    );
    assert_eq!(metrics.child_names().len(), 2);
    let remove = |id: u64| {
        wire.put(0x3000, &id.to_le_bytes());
        remove_config(Some(&*backend), 0x3000, &wire, ALLOW)
    };
    assert_eq!(remove(1), Ok(0));
    assert_eq!(id(1), None);
    assert_eq!(remove(1), Err(Error::Fs(FsError::NotFound)));
    assert_eq!(metrics.child_names(), [name(2)]);
    // The lowest free id is reused under the new uuid's directory.
    assert_eq!(add(&backend, &wire, 3, &[(0x9888, 3)]), 1);
    assert_eq!(id(3).as_deref(), Some("1\n"));
    for n in [1, 2] {
        assert_eq!(remove(n), Ok(0));
    }
    assert!(metrics.child_names().is_empty());
    // A card without the published directory keeps the registry alone.
    let other = Backend::new(device(45, MTL, 1270));
    assert_eq!(add(&other, &wire, 4, &[(0x9888, 4)]), 1);
    assert!(metrics.child_names().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_metrics_sysfs_uuid_id_follows_registry
);

fn smoke_oa_query_units_with_oam() -> TestResult {
    let mut mtl = device(51, MTL, 1270);
    mtl.media_engines = Some(EngineSet::of(&[Engine::Vcs0, Engine::Vecs0]));
    mtl.media_timestamp = Some(19_200_000);

    let reply = query(Some(mtl));
    assert_eq!(reply.len(), 16 + 72 + 2 * 8 + 72 + 2 * 8);
    assert_eq!(u32_at(&reply, 8), 2);

    let u0 = 16;
    assert_eq!(u64_at(&reply, u0), 0);
    assert_eq!(u64_at(&reply, u0 + 8), 0);
    assert_eq!(u64_at(&reply, u0 + 16), CAPS);
    assert_eq!(u64_at(&reply, u0 + 24), 19_200_000);
    assert_eq!(u64_at(&reply, u0 + 64), 2);

    let u1 = u0 + 72 + 2 * 8;
    assert_eq!(u64_at(&reply, u1), 1);
    assert_eq!(u64_at(&reply, u1 + 8), 1);
    assert_eq!(u64_at(&reply, u1 + 16), CAPS_OAM);
    assert_eq!(u64_at(&reply, u1 + 24), 19_200_000);
    assert_eq!(u64_at(&reply, u1 + 64), 2);

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_oa", smoke_oa_query_units_with_oam);

fn smoke_oa_sysfs_telemetry_and_status() -> TestResult {
    use narf_filesystem::sysfs::Kobject;
    let card = Kobject::new_root("card47");
    install_metrics_for_test(47, &card);

    let oa = card.get_child("oa").expect("oa child exists");
    let status = oa.attr_show("oa_status").expect("oa_status attr");
    assert!(status.contains("oa_buffer_size: 16777216"));
    assert!(status.contains("oa_configs: 0"));

    assert_eq!(
        oa.attr_show("oa_buffer_size").as_deref(),
        Some("16777216\n")
    );
    assert_eq!(oa.attr_show("oa_active").as_deref(), Some("0\n"));
    assert_eq!(oa.attr_show("oa_configs_count").as_deref(), Some("0\n"));
    assert_eq!(oa.attr_show("oa_overflow_count").as_deref(), Some("0\n"));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_sysfs_telemetry_and_status
);

fn smoke_i915_perf_open_add_remove_config_and_stream() -> TestResult {
    let backend = Backend::new(device(60, MTL, 1270));
    let wire = Wire::new();

    // 1. i915_add_config:
    let u1 = uuid(1);
    let mut config_bytes = [0u8; 72];
    config_bytes[..36].copy_from_slice(&u1);
    put32(&mut config_bytes, 36, 1);
    put32(&mut config_bytes, 40, 1);
    put32(&mut config_bytes, 44, 0);
    put64(&mut config_bytes, 48, 0x2000);
    put64(&mut config_bytes, 56, 0x2010);
    put64(&mut config_bytes, 64, 0);
    wire.put(0x1000, &config_bytes);

    wire.put(0x2000, &0x9888u32.to_le_bytes());
    wire.put(0x2004, &0x1111u32.to_le_bytes());
    wire.put(0x2010, &0x9888u32.to_le_bytes());
    wire.put(0x2014, &0x2222u32.to_le_bytes());

    let id1 = i915_add_config(Some(&*backend), 0x1000, &wire, ALLOW).unwrap();
    assert!(id1 >= 1);

    // Duplicate uuid fails with EADDRINUSE
    assert_eq!(
        i915_add_config(Some(&*backend), 0x1000, &wire, ALLOW),
        Err(Error::Errno(EADDRINUSE))
    );

    // Add second config with uuid(2)
    let u2 = uuid(2);
    config_bytes[..36].copy_from_slice(&u2);
    wire.put(0x1100, &config_bytes);
    let id2 = i915_add_config(Some(&*backend), 0x1100, &wire, ALLOW).unwrap();
    assert_ne!(id1, id2);

    // Verify lookup helpers
    let ids = query_config_ids(60);
    assert!(ids.contains(&id1));
    assert!(ids.contains(&id2));
    assert_eq!(query_config_by_id(60, id1).unwrap().uuid, u1);
    assert_eq!(query_config_by_uuid(60, &u2).unwrap().id, id2 as u32);

    // 2. i915_open:
    let mut open_bytes = [0u8; 16];
    put32(&mut open_bytes, 0, 0);
    put32(&mut open_bytes, 4, 4);
    put64(&mut open_bytes, 8, 0x3100);
    wire.put(0x3000, &open_bytes);

    let props = [
        (crate::intel_gpu_uapi::PERF_PROP_SAMPLE_OA, 1u64),
        (crate::intel_gpu_uapi::PERF_PROP_OA_METRICS_SET, id1),
        (crate::intel_gpu_uapi::PERF_PROP_OA_FORMAT, 10), // A32u40 -> 256 bytes
        (crate::intel_gpu_uapi::PERF_PROP_OA_EXPONENT, 5),
    ];
    for (i, &(prop_id, val)) in props.iter().enumerate() {
        let at = 0x3100 + i as u64 * 16;
        let mut p = [0u8; 16];
        put64(&mut p, 0, prop_id);
        put64(&mut p, 8, val);
        wire.put(at, &p);
    }

    assert_eq!(
        ready(i915_open(Some(backend.clone()), 0x3000, &wire, ALLOW)),
        Ok(41)
    );
    let file = wire.file();

    // 3. Stream ioctls:
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert_eq!(ready(file.ioctl_user(CONFIG, id2, &wire)), Ok(id1));
    assert_eq!(
        ready(file.ioctl_user(CONFIG, 99999, &wire)),
        Err(FsError::InvalidData)
    );
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));

    // 4. Stream read: check i915 record header
    let hw = &backend.hw;
    let circ = DEFAULT_BUFFER;
    hw.report(0, 256, 0x42, circ);
    hw.set(OATAILPTR, BASE + 256);
    let mut out = vec![0u8; 512];
    let n = ready(file.read_with_options(0, &mut out, ReadOptions { nonblocking: true })).unwrap();
    assert_eq!(n, 8 + 256);
    assert_eq!(u32_at(&out, 0), 1); // DRM_I915_PERF_RECORD_SAMPLE
    assert_eq!(u16::from_le_bytes([out[4], out[5]]), 0); // pad
    assert_eq!(u16::from_le_bytes([out[6], out[7]]), 264); // size (8 + 256)

    // 5. remove_config:
    wire.put(0x4000, &id1.to_le_bytes());
    assert_eq!(remove_config(Some(&*backend), 0x4000, &wire, ALLOW), Ok(0));
    assert!(query_config_by_id(60, id1).is_none());

    drop(file);
    backend.poll(1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_i915_perf_open_add_remove_config_and_stream
);

fn smoke_oa_test_session_i915_header() -> TestResult {
    let dev = device(62, MTL, 1270);
    let session = test_session_i915(dev, 3, DEFAULT_BUFFER, Some(5), &[(0x9888, 1)]);
    assert!(session.is_i915);
    assert_eq!(session.format.size, 256);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_test_session_i915_header
);

fn smoke_oa_exec_queue_oar_oac_streams() -> TestResult {
    let backend = Backend::new(device(63, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);

    let queue_lookup = |id: u32| {
        let (class, width, engine) = match id {
            10 => (0, 1, Engine::Rcs0),
            11 => (4, 1, Engine::Ccs0),
            12 => (0, 2, Engine::Rcs0),
            13 => (4, 2, Engine::Ccs0),
            _ => return None,
        };
        Some((
            class,
            width,
            QueueBinding::new(
                id,
                crate::intel_gpu_user::UserContext::for_engine(engine),
                Arc::new(|| true),
            ),
        ))
    };

    const OAR256: u64 = 1 | 5 << 8;
    const OAC320: u64 = 3 | 1 << 8;
    const OAC192: u64 = 3 | 2 << 8;

    let open_at = |props: &[(u32, u64)], gate: Gate| {
        let at = wire.chain(0x1000, props);
        ready(open(
            Some(backend.clone()),
            at,
            &wire,
            &queue_lookup,
            gate,
            None,
        ))
    };

    // 1. Parallel queues are rejected with EOPNOTSUPP:
    assert_eq!(
        open_at(&[(7, 12), (4, OAR256), (3, config)], ALLOW),
        Err(Error::Errno(EOPNOTSUPP))
    );
    assert_eq!(
        open_at(&[(7, 13), (4, OAC320), (3, config)], ALLOW),
        Err(Error::Errno(EOPNOTSUPP))
    );

    // 2. Non-existent queue is rejected with NotFound:
    assert_eq!(
        open_at(&[(7, 99), (4, OAR256), (3, config)], ALLOW),
        Err(Error::Fs(FsError::NotFound))
    );

    // 3. Format mismatch:
    // OAC on Render queue -> InvalidData
    assert_eq!(
        open_at(&[(7, 10), (4, OAC320), (3, config)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );
    assert_eq!(
        open_at(&[(7, 10), (4, OAC192), (3, config)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );
    // OAR on Compute queue -> InvalidData
    assert_eq!(
        open_at(&[(7, 11), (4, OAR256), (3, config)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );

    // 4. OAR or OAC without exec_queue -> InvalidData
    assert_eq!(
        open_at(&[(4, OAR256), (3, config), (2, 1)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );
    assert_eq!(
        open_at(&[(4, OAC320), (3, config), (2, 1)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );

    // 5. Render queue with OAR:
    // 5a. Unprivileged open (sample=false) succeeds with DENY gate:
    let _fd = open_at(&[(7, 10), (4, OAR256), (3, config)], DENY).unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert_eq!(session.exec_queue(), Some(10));
    assert!(!session.no_preempt());
    assert!(!session.privileged());
    assert_eq!(session.format.kind, OAR);
    assert_eq!(session.engine(), Engine::Rcs0);
    // Unprivileged operations succeed:
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert_eq!(file.poll_readiness(), 0);
    drop(file);
    backend.poll(1);
    let _ = backend.hw.take();

    // 5b. Periodic timer sampling (sample=true) requires privilege:
    assert_eq!(
        open_at(&[(7, 10), (4, OAR256), (3, config), (2, 1), (5, 5)], DENY),
        Err(Error::Fs(FsError::PermissionDenied))
    );
    let _fd = open_at(&[(7, 10), (4, OAR256), (3, config), (2, 1), (5, 5)], ALLOW).unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert!(session.privileged());
    assert_eq!(session.exec_queue(), Some(10));
    drop(file);
    backend.poll(2);
    let _ = backend.hw.take();

    // 5c. no_preempt requires privilege:
    assert_eq!(
        open_at(&[(7, 10), (4, OAR256), (3, config), (9, 1)], DENY),
        Err(Error::Fs(FsError::PermissionDenied))
    );
    let _fd = open_at(&[(7, 10), (4, OAR256), (3, config), (9, 1)], ALLOW).unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert!(session.no_preempt());
    assert!(session.privileged());
    drop(file);
    backend.poll(3);
    let _ = backend.hw.take();

    // 6. Compute queue with OAC:
    // 6a. Unprivileged open (sample=false) succeeds with DENY gate:
    let _fd = open_at(&[(7, 11), (4, OAC320), (3, config)], DENY).unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert_eq!(session.exec_queue(), Some(11));
    assert!(!session.no_preempt());
    assert!(!session.privileged());
    assert_eq!(session.format.kind, OAC);
    assert_eq!(session.engine(), Engine::Ccs0);
    drop(file);
    backend.poll(4);
    let _ = backend.hw.take();

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_exec_queue_oar_oac_streams
);

fn smoke_oa_per_context_lri_batch_contents() -> TestResult {
    let dev = device(60, MTL, 1270);
    let alive: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| true);

    // OAR format 4: select 5, size 256, kind OAR. __format_to_oactrl with
    // the OAR counter-select mask (bits 3:1) is (5 << 1) & 0xe = 0xa.
    let session = test_session_exec(dev, 4, DEFAULT_BUFFER, Engine::Rcs0, 10, alive.clone());
    assert!(session.programs_per_context());
    assert_eq!(session.queue_binding().unwrap().id, 10);
    assert!(session.queue_binding().unwrap().alive());
    assert_eq!(
        session.queue_binding().unwrap().context.engine(),
        Engine::Rcs0
    );
    let enable = per_context_job(&session, true).unwrap();
    assert!(enable.per_context());
    assert_eq!(
        enable.words(),
        &[0x1100_0005, 0x2360, 1, 0x2960, 0xb, 0x2244, 0x0100_0100][..]
    );
    let disable = per_context_job(&session, false).unwrap();
    assert!(disable.per_context());
    assert_eq!(
        disable.words(),
        &[0x1100_0005, 0x2360, 0, 0x2960, 0xa, 0x2244, 0x0100_0000][..]
    );
    drop(session);

    // OAC format 6: select 1, size 320, kind OAC; control is (1 << 1) & 0xe = 2.
    // Compute adds CTX_CTRL_RUN_ALONE to the context-control mask.
    let session = test_session_exec(dev, 6, DEFAULT_BUFFER, Engine::Ccs0, 11, alive.clone());
    assert!(session.programs_per_context());
    let enable = per_context_job(&session, true).unwrap();
    assert!(enable.per_context());
    assert_eq!(
        enable.words(),
        &[0x1100_0005, 0x1a360, 1, 0x15114, 3, 0x1a244, 0x0180_0180][..]
    );
    let disable = per_context_job(&session, false).unwrap();
    assert!(disable.per_context());
    assert_eq!(
        disable.words(),
        &[0x1100_0005, 0x1a360, 0, 0x15114, 2, 0x1a244, 0x0180_0000][..]
    );
    drop(session);

    // Configuration jobs are not per-context: they retire on the kernel ring.
    assert!(!config_jobs(&[(0x9888, 1)])[0].per_context());

    // No exec queue, or a video engine, programs nothing.
    let session = test_session(dev, 4, DEFAULT_BUFFER, None, &[(0x9888, 1)]);
    assert!(!session.programs_per_context());
    assert!(per_context_job(&session, true).is_none());
    drop(session);
    let session = test_session_exec(dev, 4, DEFAULT_BUFFER, Engine::Vcs0, 20, alive);
    assert!(!session.programs_per_context());
    assert!(per_context_job(&session, true).is_none());
    drop(session);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_per_context_lri_batch_contents
);

fn smoke_oa_per_context_enable_disable_sequence() -> TestResult {
    let backend = Backend::new(device(61, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let alive = Arc::new(AtomicBool::new(true));
    let queues = |id: u32| {
        let probe = alive.clone();
        match id {
            10 => Some((
                0,
                1,
                QueueBinding::new(
                    10,
                    crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0),
                    Arc::new(move || probe.load(Ordering::Relaxed)),
                ),
            )),
            _ => None,
        }
    };
    const OAR256: u64 = 1 | 5 << 8;

    // Open enables: the per-context job retires first, then the config job.
    let at = wire.chain(0x1000, &[(7, 10), (4, OAR256), (3, config)]);
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &queues, DENY, None)),
        Ok(41)
    );
    let file = wire.file();
    let session = session_of(&backend);
    assert!(session.enabled());
    assert_eq!(backend.jobs.lock().len(), 2);
    assert_eq!(
        backend.jobs.lock()[0],
        vec![0x1100_0005, 0x2360, 1, 0x2960, 0xb, 0x2244, 0x0100_0100]
    );
    assert_eq!(backend.jobs.lock()[1], vec![0x1100_0001, 0x9888, 1]);
    assert_eq!(backend.hw.get(0x2360), 1);
    assert_eq!(backend.hw.get(0x2960), 0xb);
    assert_eq!(backend.hw.get(0x2244), 0x0100_0100);

    // Disable retires the per-context disable job before the global counter
    // is cleared; re-enable programs it again.
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert!(!session.enabled());
    assert_eq!(backend.hw.get(0x2360), 0);
    assert_eq!(backend.hw.get(0x2960), 0xa);
    assert_eq!(backend.hw.get(0x2244), 0x0100_0000);
    assert_eq!(backend.hw.get(OACONTROL) & COUNTER_ENABLE, 0);
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert!(session.enabled());
    assert_eq!(backend.hw.get(0x2360), 1);
    assert_eq!(backend.hw.get(0x2960), 0xb);
    assert_eq!(backend.hw.get(0x2244), 0x0100_0100);
    drop(file);
    backend.poll(1);
    assert!(!backend.unit.lock().as_ref().unwrap().per_context);

    // Compute: the CCS select is programmed before the OAC LRI retires.
    let dev = Device {
        card: 62,
        platform: MTL,
        graphics: 1270,
        timestamp: 19_200_000,
        engines: EngineSet::of(&[Engine::Rcs0, Engine::Ccs1]),
        reserve: DEFAULT_BUFFER,
        media_engines: None,
        media_timestamp: None,
    };
    let backend = Backend::new(dev);
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let queues = |id: u32| match id {
        11 => Some((
            4,
            1,
            QueueBinding::new(
                11,
                crate::intel_gpu_user::UserContext::for_engine(Engine::Ccs1),
                Arc::new(|| true),
            ),
        )),
        _ => None,
    };
    const OAC320: u64 = 3 | 1 << 8;
    // No engine-instance property: with engines [Rcs0, Ccs1], compute
    // logical instance 0 is Ccs1 (physical instance 1).
    let at = wire.chain(0x1000, &[(7, 11), (4, OAC320), (3, config)]);
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &queues, DENY, None)),
        Ok(41)
    );
    assert_eq!(backend.hw.get(0x1c360), 1);
    assert_eq!(backend.hw.get(0x15114), 3);
    assert_eq!(backend.hw.get(0x1c244), 0x0180_0180);
    assert_eq!(backend.hw.get(OACONTROL) & CCS_SELECT, 1u32 << 16);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_per_context_enable_disable_sequence
);

fn smoke_oa_no_preempt_enable_disable_restores_schedule() -> TestResult {
    let backend = Backend::new(device(61, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let alive = Arc::new(AtomicBool::new(true));
    // Retain the bound context so the fixture can read its schedule.
    let ctx = crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0);
    let queues = |id: u32| {
        let probe = alive.clone();
        let ctx = ctx.clone();
        match id {
            10 => Some((
                0,
                1,
                QueueBinding::new(10, ctx, Arc::new(move || probe.load(Ordering::Relaxed))),
            )),
            _ => None,
        }
    };
    const OAR256: u64 = 1 | 5 << 8;

    let open_at = |props: &[(u32, u64)], gate: Gate| {
        let at = wire.chain(0x1000, props);
        ready(open(Some(backend.clone()), at, &wire, &queues, gate, None))
    };

    // no_preempt needs privilege (Linux: no_preempt without an exec queue
    // is -EINVAL, and the open marks the stream privileged).
    assert_eq!(
        open_at(&[(7, 10), (4, OAR256), (3, config), (9, 1)], DENY),
        Err(Error::Fs(FsError::PermissionDenied))
    );
    let _fd = open_at(&[(7, 10), (4, OAR256), (3, config), (9, 1)], ALLOW).unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert!(session.enabled());
    assert!(session.no_preempt());
    assert!(session.privileged());
    // Enable holds the queue at timeslice 0 (default schedule is
    // (NORMAL, 1000): GuC priority 3, EXECUTION_QUANTUM 1000 us).
    assert_eq!(ctx.schedule_for_test(), (3, 0));
    assert!(ctx.oa_no_preempt());

    // Disable restores the saved schedule.
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert!(!session.enabled());
    assert_eq!(ctx.schedule_for_test(), (3, 1000));
    assert!(!ctx.oa_no_preempt());

    // Re-enable applies it again.
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert!(session.enabled());
    assert_eq!(ctx.schedule_for_test(), (3, 0));
    assert!(ctx.oa_no_preempt());

    // Close without disable: teardown restores the schedule too (Linux
    // xe_oa_destroy_locked disables the stream, which restores).
    drop(file);
    backend.poll(1);
    assert_eq!(ctx.schedule_for_test(), (3, 1000));
    assert!(!ctx.oa_no_preempt());
    assert!(!backend.unit.lock().as_ref().unwrap().per_context);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_no_preempt_enable_disable_restores_schedule
);

fn smoke_oa_query_sampler_report_ids_and_slots_rotate() -> TestResult {
    // OAR256 format: report size 256. A 1024-byte buffer holds 4 slots.
    let sampler = QuerySampler::new(0x1_0000, 1024, 256);
    // Gen8+ form: (0x28 << 23) | (4 - 2), address, report ID.
    assert_eq!(sampler.next_query(), [0x14000002, 0x1_0000, 0, 1]);
    assert_eq!(sampler.next_query(), [0x14000002, 0x1_0100, 0, 2]);
    assert_eq!(sampler.next_query(), [0x14000002, 0x1_0200, 0, 3]);
    assert_eq!(sampler.next_query(), [0x14000002, 0x1_0300, 0, 4]);
    // Fifth batch wraps to slot 0 with the next report ID.
    assert_eq!(sampler.next_query(), [0x14000002, 0x1_0000, 0, 5]);
    // A 64-bit address splits across the two address dwords.
    let high = QuerySampler::new(0x1_0000_0000, 256, 256);
    assert_eq!(high.next_query(), [0x14000002, 0, 1, 1]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_query_sampler_report_ids_and_slots_rotate
);

fn smoke_oa_query_splice_lands_before_breadcrumb() -> TestResult {
    // A resident-ring-shaped word stream: preparser + batch start, then
    // the owned breadcrumb (the exact marker + tail resident_ring
    // emits). The sampler targets slot 0 of a 512-byte buffer.
    let sampler = QuerySampler::new(0x2_0000, 512, 256);
    let mut words = vec![
        0x04000001, 0x02800101, 0x7a000404, 0x20344c1c, 0xd0, 0, 0, 0, 0x02800100, 0x18800101, 0,
        0, 0x04000000, 0x7a000004, 0x01104080, 0x1234, 0, 7, 0, 0x01000000, 0x04000001, 0x02800000,
    ];
    assert!(splice_query(&mut words, &sampler));
    // The 4 query dwords sit immediately before the breadcrumb marker.
    let at = words
        .windows(2)
        .position(|v| v == BREADCRUMB_MARKER)
        .unwrap();
    assert_eq!(&words[at - 4..at], &[0x14000002, 0x2_0000, 0, 1]);
    // A second batch advances to slot 1 with report ID 2.
    assert!(splice_query(&mut words, &sampler));
    let at = words
        .windows(2)
        .position(|v| v == BREADCRUMB_MARKER)
        .unwrap();
    assert_eq!(&words[at - 4..at], &[0x14000002, 0x2_0100, 0, 2]);
    // No breadcrumb marker: nothing is spliced.
    let mut bare = vec![0x04000001, 0x02800101];
    assert!(!splice_query(&mut bare, &sampler));
    assert_eq!(bare, vec![0x04000001, 0x02800101]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_query_splice_lands_before_breadcrumb
);

fn smoke_oa_query_open_validation_and_sampler_lifecycle() -> TestResult {
    let backend = Backend::new(device(64, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let alive = Arc::new(AtomicBool::new(true));
    let ctx = crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0);
    let queues = |id: u32| {
        let probe = alive.clone();
        let ctx = ctx.clone();
        match id {
            10 => Some((
                0,
                1,
                QueueBinding::new(10, ctx, Arc::new(move || probe.load(Ordering::Relaxed))),
            )),
            _ => None,
        }
    };
    const OAR256: u64 = 1 | 5 << 8;
    const OAG256: u64 = 5 << 8;

    let open_at = |props: &[(u32, u64)], gate: Gate| {
        let at = wire.chain(0x1000, props);
        ready(open(Some(backend.clone()), at, &wire, &queues, gate, None))
    };

    // Both query properties or neither.
    assert_eq!(
        open_at(&[(7, 10), (4, OAR256), (3, config), (14, 0x1_0000)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );
    assert_eq!(
        open_at(&[(7, 10), (4, OAR256), (3, config), (15, 1024)], ALLOW),
        Err(Error::Fs(FsError::InvalidData))
    );
    // Query sampling needs a bound queue (OAG is queue-less-legal, so
    // this isolates the bound-queue rule).
    assert_eq!(
        open_at(
            &[(4, OAG256), (3, config), (14, 0x1_0000), (15, 1024)],
            ALLOW
        ),
        Err(Error::Fs(FsError::InvalidData))
    );
    // Query sampling is the !sample mechanism: periodic sampling plus a
    // query buffer is rejected.
    assert_eq!(
        open_at(
            &[
                (7, 10),
                (4, OAR256),
                (3, config),
                (14, 0x1_0000),
                (15, 1024),
                (2, 1)
            ],
            ALLOW
        ),
        Err(Error::Fs(FsError::InvalidData))
    );
    // The buffer holds whole reports, at least one, base report-aligned.
    assert_eq!(
        open_at(
            &[(7, 10), (4, OAR256), (3, config), (14, 0x1_0000), (15, 100)],
            ALLOW
        ),
        Err(Error::Fs(FsError::InvalidData))
    );
    assert_eq!(
        open_at(
            &[
                (7, 10),
                (4, OAR256),
                (3, config),
                (14, 0x1_0001),
                (15, 1024)
            ],
            ALLOW
        ),
        Err(Error::Fs(FsError::InvalidData))
    );

    // A query-mode stream opens unprivileged (Linux: query sampling
    // with OAR/OAC, without global stream access, is unprivileged).
    let _fd = open_at(
        &[
            (7, 10),
            (4, OAR256),
            (3, config),
            (14, 0x1_0000),
            (15, 1024),
        ],
        DENY,
    )
    .unwrap();
    let file = wire.file();
    let session = session_of(&backend);
    assert!(session.enabled());
    assert!(!session.privileged());
    assert_eq!(session.query_address, 0x1_0000);
    assert_eq!(session.query_size, 1024);
    // Enable registered the sampler on the bound context.
    let sampler = ctx.query_sampler().expect("sampler registered at enable");
    assert_eq!(sampler.address(), 0x1_0000);
    assert_eq!(sampler.size(), 1024);

    // Disable clears it; re-enable registers a fresh one.
    assert_eq!(ready(file.ioctl_user(DISABLE, 0, &wire)), Ok(0));
    assert!(ctx.query_sampler().is_none());
    assert_eq!(ready(file.ioctl_user(ENABLE, 0, &wire)), Ok(0));
    assert!(ctx.query_sampler().is_some());

    // Close clears it too.
    drop(file);
    backend.poll(1);
    assert!(ctx.query_sampler().is_none());

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_query_open_validation_and_sampler_lifecycle
);

fn smoke_oa_per_context_stale_queue_fails_enable() -> TestResult {
    let backend = Backend::new(device(59, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let alive = Arc::new(AtomicBool::new(true));
    let queues = |id: u32| {
        let probe = alive.clone();
        match id {
            10 => Some((
                0,
                1,
                QueueBinding::new(
                    10,
                    crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0),
                    Arc::new(move || probe.load(Ordering::Relaxed)),
                ),
            )),
            _ => None,
        }
    };
    const OAR256: u64 = 1 | 5 << 8;

    // Open disabled so the enable path below is exercised on its own.
    let at = wire.chain(0x1000, &[(7, 10), (4, OAR256), (3, config), (6, 1)]);
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &queues, DENY, None)),
        Ok(41)
    );
    let session = session_of(&backend);
    assert!(!session.enabled());

    // The queue is gone: enable fails cleanly with NotFound and the stream
    // stays disabled with no per-context registers programmed.
    alive.store(false, Ordering::Relaxed);
    assert_eq!(
        ready(backend.oa_control(session.clone(), Request::Enable)),
        Err(FsError::NotFound)
    );
    assert!(!session.enabled());
    assert_eq!(backend.hw.get(0x2360), 0);

    // The queue is back: enable succeeds. A later disable still runs the
    // global disable even after the queue goes away again.
    alive.store(true, Ordering::Relaxed);
    assert_eq!(
        ready(backend.oa_control(session.clone(), Request::Enable)),
        Ok(())
    );
    assert!(session.enabled());
    assert_eq!(backend.hw.get(0x2360), 1);
    alive.store(false, Ordering::Relaxed);
    assert_eq!(
        ready(backend.oa_control(session.clone(), Request::Disable)),
        Ok(())
    );
    assert!(!session.enabled());
    assert_eq!(backend.hw.get(OACONTROL) & COUNTER_ENABLE, 0);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_per_context_stale_queue_fails_enable
);

fn smoke_oa_per_context_open_with_dead_queue_fails_clean() -> TestResult {
    let backend = Backend::new(device(58, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let _ = backend.hw.take();
    // The queue is already gone when open runs: the binding's probe is dead.
    let queues = |id: u32| match id {
        10 => Some((
            0,
            1,
            QueueBinding::new(
                10,
                crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0),
                Arc::new(|| false),
            ),
        )),
        _ => None,
    };
    const OAR256: u64 = 1 | 5 << 8;

    // Open-with-enable fails with NotFound before attach programs any
    // metric-set state: no jobs retire and no registers are written.
    let at = wire.chain(0x1000, &[(7, 10), (4, OAR256), (3, config)]);
    assert_eq!(
        ready(open(Some(backend.clone()), at, &wire, &queues, DENY, None)),
        Err(Error::Fs(FsError::NotFound))
    );
    assert!(backend.jobs.lock().is_empty());
    assert!(backend.hw.take().is_empty());
    assert_eq!(backend.hw.get(0x2360), 0);
    assert_eq!(backend.hw.get(0x2960), 0);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_per_context_open_with_dead_queue_fails_clean
);

fn smoke_oa_syncs_infence_outfence_and_user_fence() -> TestResult {
    use crate::drm::syncobj::{BinaryFence, SyncObjTable};

    let backend = Backend::new(device(53, MTL, 1270));
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);
    let table = Arc::new(IrqSafeSpinLock::new(SyncObjTable::new()));

    // 1. Create in-fence (pre-signalled) and out-fence syncobjs:
    let in_fence = BinaryFence::signalled();
    let in_handle = table.lock().create_with_fence(in_fence).unwrap();
    let out_handle = table.lock().create(0).unwrap();

    // Setup 48-byte drm_xe_sync entries in wire memory at 0x6000:
    let sync_addr = 0x6000u64;
    let mut sync_bytes = [0u8; 48 * 2];
    // Sync 0: flags=0, handle=in_handle
    put32(&mut sync_bytes, 8, 0); // kind = 0 (SYNCOBJ)
    put32(&mut sync_bytes, 12, 0); // flags = 0 (IN)
    put64(&mut sync_bytes, 16, u64::from(in_handle));
    // Sync 1: flags=1, handle=out_handle
    put32(&mut sync_bytes, 48 + 8, 0); // kind = 0
    put32(&mut sync_bytes, 48 + 12, 1); // flags = 1 (OUT)
    put64(&mut sync_bytes, 48 + 16, u64::from(out_handle));
    wire.put(sync_addr, &sync_bytes);

    let props = [
        (2u32, 1u64),
        (4, A24U40),
        (3, config),
        (12, 128 << 10),
        (10, 2), // num_syncs = 2
        (11, sync_addr),
    ];
    let at = wire.chain(0x1000, &props);
    let fd = ready(open(
        Some(backend.clone()),
        at,
        &wire,
        &none,
        ALLOW,
        Some(table.clone()),
    ))
    .unwrap();
    assert_eq!(fd, 41);
    let file = wire.file();

    // Verify out-fence syncobj was published:
    let out_core = table.lock().get(out_handle).unwrap().core().clone();
    assert!(out_core.fence().is_some_and(|f| f.is_signalled()));

    // 2. Test CONFIG ioctl on stream file with user-fence:
    let config2 = add(&backend, &wire, 2, &[(0x9884, 2)]);
    let user_fence_addr = 0x8000u64;
    wire.put(user_fence_addr, &0u64.to_le_bytes());

    // Single sync entry at 0x6100: user-fence
    let mut uf_sync = [0u8; 48];
    put32(&mut uf_sync, 8, 2); // kind = 2 (USER_FENCE)
    put32(&mut uf_sync, 12, 1); // flags = 1 (OUT)
    put64(&mut uf_sync, 16, user_fence_addr); // handle = memory address
    put64(&mut uf_sync, 24, 0x1234_5678_9abc_def0); // point = value to write
    wire.put(0x6100, &uf_sync);

    let cfg_props = [(3u32, config2), (10, 1), (11, 0x6100)];
    let cfg_at = wire.chain(0x2000, &cfg_props);
    assert_eq!(ready(file.ioctl_user(CONFIG, cfg_at, &wire)), Ok(config));

    // Verify user-fence value was written:
    let mut read_uf = [0u8; 8];
    wire.read(user_fence_addr, &mut read_uf).unwrap();
    assert_eq!(u64::from_le_bytes(read_uf), 0x1234_5678_9abc_def0);

    // 3. Invalid sync parameters:
    // num_syncs > MAX_SYNCS (2):
    let bad_props = [
        (2u32, 1u64),
        (4, A24U40),
        (3, config),
        (12, 128 << 10),
        (10, 3), // num_syncs > 2 -> invalid
        (11, sync_addr),
    ];
    let bad_at = wire.chain(0x3000, &bad_props);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            bad_at,
            &wire,
            &none,
            ALLOW,
            Some(table.clone()),
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    // num_syncs == 0 with property 10:
    let bad_props0 = [
        (2u32, 1u64),
        (4, A24U40),
        (3, config),
        (12, 128 << 10),
        (10, 0),
        (11, sync_addr),
    ];
    let bad_at0 = wire.chain(0x3100, &bad_props0);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            bad_at0,
            &wire,
            &none,
            ALLOW,
            Some(table.clone()),
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    // syncs == 0 with num_syncs != 0:
    let bad_props_nosync = [
        (2u32, 1u64),
        (4, A24U40),
        (3, config),
        (12, 128 << 10),
        (10, 1),
    ];
    let bad_at_nosync = wire.chain(0x3200, &bad_props_nosync);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            bad_at_nosync,
            &wire,
            &none,
            ALLOW,
            Some(table.clone()),
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    drop(file);
    backend.poll(1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_syncs_infence_outfence_and_user_fence
);

fn smoke_oa_media_gt_oam_unit1_stream_support() -> TestResult {
    let mut mtl = device(54, MTL, 1270);
    mtl.media_engines = Some(EngineSet::of(&[Engine::Vcs0, Engine::Vcs1, Engine::Vecs0]));
    mtl.media_timestamp = Some(19_200_000);
    assert!(mtl.has_oam());

    let backend = Backend::new(mtl);
    let wire = Wire::new();
    let config = add(&backend, &wire, 1, &[(0x9888, 1)]);

    // Media exec queue: queue 20 has class 2 (VCS), width 1.
    // Render exec queue: queue 10 has class 0 (RCS), width 1.
    let queues = |id: u32| match id {
        20 => Some((
            2,
            1,
            QueueBinding::new(
                20,
                crate::intel_gpu_user::UserContext::for_engine(Engine::Vcs0),
                Arc::new(|| true),
            ),
        )),
        10 => Some((
            0,
            1,
            QueueBinding::new(
                10,
                crate::intel_gpu_user::UserContext::for_engine(Engine::Rcs0),
                Arc::new(|| true),
            ),
        )),
        _ => None,
    };

    // Formats:
    // MPEC 192-byte format (format 8): kind MPEC (4), select 1, counter_size 0, bc 0
    let mpec192 = 4u64 | (1u64 << 8);
    // MPEC 128-byte format (format 9): kind MPEC (4), select 2, counter_size 0, bc 0
    let mpec128 = 4u64 | (2u64 << 8);
    let oag256 = A24U40;

    // 1. Open OAM Unit 1 stream with media exec queue and MPEC format succeeds:
    let oam_props = [
        (1u32, 1u64), // oa_unit = 1 (OAM)
        (7, 20),      // exec_queue = 20 (VCS)
        (4, mpec192), // MPEC 192-byte format
        (3, config),
        (12, 128 << 10),
    ];
    let at = wire.chain(0x1000, &oam_props);
    let fd = ready(open(Some(backend.clone()), at, &wire, &queues, ALLOW, None)).unwrap();
    assert_eq!(fd, 41);
    let oam_file = wire.file();
    let oam_session = session_of(&backend);
    assert_eq!(oam_session.oa_unit(), 1);
    assert_eq!(oam_session.format.kind, MPEC);
    assert_eq!(oam_session.engine(), Engine::Vcs0);

    // 2. While OAM Unit 1 is active, another open on Unit 1 returns Busy:
    let at_busy = wire.chain(0x1100, &oam_props);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_busy,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::Busy))
    );

    // 3. Concurrency: While OAM Unit 1 is active, Unit 0 (OAG) can be opened simultaneously!
    let oag_props = [
        (1u32, 0u64), // oa_unit = 0 (OAG)
        (2, 1),       // sample = true
        (4, oag256),  // OAG format
        (3, config),
        (12, 128 << 10),
    ];
    let at_oag = wire.chain(0x1200, &oag_props);
    let fd_oag = ready(open(
        Some(backend.clone()),
        at_oag,
        &wire,
        &queues,
        ALLOW,
        None,
    ))
    .unwrap();
    assert_eq!(fd_oag, 41);
    let oag_file = wire.file();

    // Both units active on card 54:
    assert!(ACTIVE[54][0].load(Ordering::Acquire));
    assert!(ACTIVE[54][1].load(Ordering::Acquire));

    // Trying to open Unit 0 again also returns Busy:
    let at_oag_busy = wire.chain(0x1300, &oag_props);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_oag_busy,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::Busy))
    );

    // Close Unit 1: Unit 1 becomes idle while Unit 0 remains active:
    drop(oam_file);
    assert!(!ACTIVE[54][1].load(Ordering::Acquire));
    assert!(ACTIVE[54][0].load(Ordering::Acquire));

    // Now Unit 1 can be opened again with MPEC 128:
    let oam128_props = [
        (1u32, 1u64),
        (7, 20),
        (4, mpec128),
        (3, config),
        (12, 128 << 10),
    ];
    let at_oam128 = wire.chain(0x1400, &oam128_props);
    let fd_oam128 = ready(open(
        Some(backend.clone()),
        at_oam128,
        &wire,
        &queues,
        ALLOW,
        None,
    ))
    .unwrap();
    assert_eq!(fd_oam128, 41);
    let oam_file2 = wire.file();
    drop(oam_file2);
    drop(oag_file);
    assert!(!ACTIVE[54][0].load(Ordering::Acquire));
    assert!(!ACTIVE[54][1].load(Ordering::Acquire));

    // 4. Reject non-MPEC formats on OAM Unit 1:
    let non_mpec_on_oam = [
        (1u32, 1u64),
        (7, 20),
        (4, oag256), // OAG format on OAM
        (3, config),
        (12, 128 << 10),
    ];
    let at_bad_fmt = wire.chain(0x1500, &non_mpec_on_oam);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_bad_fmt,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    // 5. Reject MPEC formats on OAG Unit 0:
    let mpec_on_oag = [
        (1u32, 0u64),
        (7, 10),
        (4, mpec192), // MPEC format on OAG
        (3, config),
        (12, 128 << 10),
    ];
    let at_mpec_oag = wire.chain(0x1600, &mpec_on_oag);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_mpec_oag,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    // 6. Reject periodic timer sampling on OAM Unit 1:
    let sample_on_oam = [
        (1u32, 1u64),
        (7, 20),
        (4, mpec192),
        (2, 1), // sample = true -> rejected on OAM
        (3, config),
        (12, 128 << 10),
    ];
    let at_sample_oam = wire.chain(0x1700, &sample_on_oam);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_sample_oam,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    let exp_on_oam = [
        (1u32, 1u64),
        (7, 20),
        (4, mpec192),
        (5, 5), // exponent = 5 -> rejected on OAM
        (3, config),
        (12, 128 << 10),
    ];
    let at_exp_oam = wire.chain(0x1800, &exp_on_oam);
    assert_eq!(
        ready(open(
            Some(backend.clone()),
            at_exp_oam,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    // 7. Reject oa_unit == 1 on device without media engines (no OAM):
    let mtl_no_oam = device(55, MTL, 1270);
    assert!(!mtl_no_oam.has_oam());
    let backend_no_oam = Backend::new(mtl_no_oam);
    let at_no_oam = wire.chain(0x1900, &oam_props);
    assert_eq!(
        ready(open(
            Some(backend_no_oam),
            at_no_oam,
            &wire,
            &queues,
            ALLOW,
            None
        )),
        Err(Error::Fs(FsError::InvalidData))
    );

    backend.poll(1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_media_gt_oam_unit1_stream_support
);
