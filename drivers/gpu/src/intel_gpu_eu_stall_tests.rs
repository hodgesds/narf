//! Real Collector/descriptor conversations; literal Xe2 masked register and
//!64-byte record vectors from Linux b90c984d xe_eu_stall.c and register ABI.
use super::*;
use crate::intel_gpu_rcs::GpuAllocator;
use crate::{intel_gpu_guc_boot::BootError, intel_gpu_rcs::SubmitError};
use alloc::{collections::BTreeMap, sync::Weak};
use core::{
    future::Future,
    sync::atomic::{AtomicU32, AtomicUsize},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Registers {
    selector: u32,
    held: bool,
    busy: bool,
    regs: BTreeMap<(usize, u64), u32>,
    writes: Vec<(usize, u64, u32)>,
    accesses: usize,
    fail_read: Option<(usize, u64)>,
    drop_write: Option<(usize, u64)>,
    fail_restore: bool,
}
struct Shared {
    state: IrqSafeSpinLock<Registers>,
    memory: IrqSafeSpinLock<Option<Arc<Memory>>>,
    live: AtomicUsize,
    allocations: AtomicUsize,
    freed: AtomicUsize,
    coherent: AtomicBool,
    extent: AtomicU32,
    base: AtomicU32,
    group: u8,
}
impl Shared {
    fn new(group: u8) -> Arc<Self> {
        Arc::new(Self {
            state: IrqSafeSpinLock::new(Registers {
                selector: 0x80000605,
                ..Default::default()
            }),
            memory: IrqSafeSpinLock::new(None),
            live: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            freed: AtomicUsize::new(0),
            coherent: AtomicBool::new(true),
            extent: AtomicU32::new(0),
            base: AtomicU32::new(0x10000000),
            group,
        })
    }
    fn put(&self, dss: usize, reg: u64, value: u32) {
        self.state.lock().regs.insert((dss, reg), value);
    }
    fn get(&self, dss: usize, reg: u64) -> u32 {
        *self.state.lock().regs.get(&(dss, reg)).unwrap_or(&0)
    }
    fn pointer(&self, dss: usize, bytes: u32, dropped: bool) {
        assert_eq!(bytes & 63, 0);
        self.put(
            dss,
            0xe528,
            ((bytes >> 6) << 2) | if dropped { 2 } else { 0 },
        );
    }
    fn memory(&self) -> Arc<Memory> {
        self.memory.lock().as_ref().unwrap().clone()
    }
    fn restored(&self) {
        let state = self.state.lock();
        assert_eq!(state.selector, 0x80000605);
        assert!(!state.held, "MCR semaphore leaked");
    }
}
#[derive(Clone)]
struct Window(Arc<Shared>);
impl MmioWindow for Window {
    fn read32(&self, offset: u64) -> u32 {
        let mut state = self.0.state.lock();
        state.accesses += 1;
        match offset {
            0xfd0 => {
                if state.busy {
                    return 0;
                }
                assert!(!state.held);
                state.held = true;
                1
            }
            0xfd4 => state.selector,
            _ => {
                assert!(state.held);
                assert_ne!(
                    state.selector & 0x80000000,
                    0,
                    "reads use source unicast steering"
                );
                let dss = ((state.selector >> 8) & 15) as usize * usize::from(self.0.group)
                    + (state.selector & 15) as usize;
                if state.fail_read == Some((dss, offset)) {
                    return u32::MAX;
                }
                *state.regs.get(&(dss, offset)).unwrap_or(&0)
            }
        }
    }
    fn write32(&self, offset: u64, value: u32) {
        let mut state = self.0.state.lock();
        state.accesses += 1;
        match offset {
            0xfd0 => {
                assert_eq!(value, 1);
                assert!(state.held);
                state.held = false;
            }
            0xfd4 => {
                assert!(state.held);
                if !(state.fail_restore && value == 0x80000605) {
                    state.selector = value;
                }
            }
            _ => {
                assert!(state.held);
                assert_eq!(state.selector & 0x80000000, 0, "writes are source unicast");
                let dss = ((state.selector >> 8) & 15) as usize * usize::from(self.0.group)
                    + (state.selector & 15) as usize;
                state.writes.push((dss, offset, value));
                if state.drop_write == Some((dss, offset)) {
                    return;
                }
                let old = *state.regs.get(&(dss, offset)).unwrap_or(&0);
                let next = if matches!(offset, 0xe528 | 0xe52c | 0xe53c) {
                    let mask = value >> 16;
                    (old & !mask) | (value & mask)
                } else {
                    value
                };
                state.regs.insert((dss, offset), next);
            }
        }
    }
}
struct Memory {
    words: Vec<AtomicU32>,
    reads: AtomicUsize,
    drop_during_copy: AtomicBool,
    shared: Weak<Shared>,
    base: u32,
    pages: u32,
    coherent: bool,
}
impl Memory {
    fn record(&self, dss: usize, offset: usize, tag: u8) -> [u8; 64] {
        let bytes = core::array::from_fn(|i| tag.wrapping_add(i as u8));
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            let at = dss * PER_CORE + (offset + i * 4) % PER_CORE;
            self.words[at / 4].store(
                u32::from_le_bytes(word.try_into().unwrap()),
                Ordering::Release,
            );
        }
        bytes
    }
}
impl GpuBacking for Arc<Memory> {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn ggtt_offset(&self) -> u32 {
        self.base
    }
    fn size_pages(&self) -> u32 {
        self.pages
    }
    fn read32(&self, offset: u64) -> u32 {
        assert_eq!(offset & 3, 0);
        self.reads.fetch_add(1, Ordering::Relaxed);
        let value = self.words[offset as usize / 4].load(Ordering::Acquire);
        if self.drop_during_copy.swap(false, Ordering::AcqRel) {
            let shared = self.shared.upgrade().unwrap();
            let mut state = shared.state.lock();
            *state.regs.entry((0, 0xe528)).or_default() |= 2;
        }
        value
    }
    fn write32(&self, offset: u64, value: u32) {
        self.words[offset as usize / 4].store(value, Ordering::Release);
    }
}
#[derive(Clone)]
struct Allocator(Arc<Shared>);
impl GpuAllocator for Allocator {
    type Backing = Arc<Memory>;
    fn alloc(&mut self, pages: u32) -> Result<Self::Backing, SubmitError> {
        assert_eq!(self.0.live.load(Ordering::Relaxed), 0);
        let memory = Arc::new(Memory {
            words: (0..pages as usize * 1024)
                .map(|_| AtomicU32::new(0))
                .collect(),
            reads: AtomicUsize::new(0),
            drop_during_copy: AtomicBool::new(false),
            shared: Arc::downgrade(&self.0),
            base: self.0.base.load(Ordering::Relaxed),
            pages: pages + self.0.extent.load(Ordering::Relaxed),
            coherent: self.0.coherent.load(Ordering::Relaxed),
        });
        *self.0.memory.lock() = Some(memory.clone());
        self.0.live.store(1, Ordering::Relaxed);
        self.0.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(memory)
    }
    fn free(&mut self, backing: Self::Backing) {
        assert_eq!(self.0.live.swap(0, Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(
            self.0.memory.lock().as_ref().unwrap(),
            &backing
        ));
        self.0.memory.lock().take();
        self.0.freed.fetch_add(1, Ordering::Relaxed);
    }
    fn live_allocations(&self) -> usize {
        self.0.live.load(Ordering::Relaxed)
    }
    fn live_pages(&self) -> u32 {
        self.0.memory.lock().as_ref().map_or(0, |m| m.pages)
    }
}
impl BootAllocator for Allocator {
    fn sync_for_device(&mut self, _: &Self::Backing) -> Result<(), BootError> {
        Ok(())
    }
    fn sync_for_cpu(&mut self, _: &Self::Backing) -> Result<(), BootError> {
        Ok(())
    }
}
fn info(dss: u32, per_group: u8) -> Info {
    Info {
        card: 61,
        dss,
        per_group,
    }
}
fn config() -> Config {
    Config { rate: 4, wait: 1 }
}
fn fixture(layout: Info) -> (Arc<Shared>, Window, Collector<Allocator>) {
    let shared = Shared::new(layout.per_group);
    let collector = Collector::new(Allocator(shared.clone()), layout).unwrap();
    (shared.clone(), Window(shared), collector)
}
fn reset(collector: Collector<Allocator>, shared: &Shared) {
    // Hardware reset withdraws every sampler independently of any successful
    // host disable/readback; this is the model's separate stop-DMA event.
    {
        let mut state = shared.state.lock();
        state.held = false;
        for ((_, register), value) in &mut state.regs {
            if *register == 0xe520 {
                *value = 0;
            }
        }
    }
    // SAFETY: this independent device model has synchronously stopped every
    // sampler and withdrawn all DMA, standing for the required GT reset.
    unsafe { collector.release_after_reset() };
    assert_eq!(shared.live.load(Ordering::Relaxed), 0);
}

fn smoke_eu_stall_sparse_mcr_enable_disable_and_reopen_retains_mapping() -> TestResult {
    let layout = info(0x25, 4); // physical DSS0,2,5; fused holes remain in DMA layout
    let (shared, io, mut collector) = fixture(layout);
    assert_eq!(shared.memory().pages, 768);
    shared.pointer(0, 128, true);
    shared.pointer(2, PER_CORE as u32 - 64, false);
    let session = Session::new(layout, config()).unwrap();
    collector.attach(session.clone()).unwrap();
    collector.control(&io, &session, true, || true).unwrap();
    assert!(!collector.idle());
    assert!(session.enabled.load(Ordering::Acquire));
    shared.restored();
    for dss in [0, 2, 5] {
        assert_eq!(shared.get(dss, 0xe520), 0x10000012);
        assert_eq!(shared.get(dss, 0xe524), 0);
        assert_eq!(shared.get(dss, 0xe53c), 0x34);
        assert_eq!(shared.get(dss, 0xe528) & 2, 0);
        assert_eq!(shared.get(dss, 0xe52c), shared.get(dss, 0xe528) & 0xfffc);
    }
    assert!(shared
        .state
        .lock()
        .writes
        .iter()
        .all(|(dss, _, _)| [0, 2, 5].contains(dss)));
    assert_eq!(Session::new(layout, config()).unwrap_err(), FsError::Busy);
    collector.control(&io, &session, false, || true).unwrap();
    assert!(collector.idle());
    assert_eq!(session.read(&mut [0; 64]), Err(FsError::InvalidData));
    assert_eq!(shared.live.load(Ordering::Relaxed), 1);
    shared.pointer(0, 256, false);
    collector.control(&io, &session, true, || true).unwrap();
    assert_eq!(
        collector.read[0], 256,
        "reenable discards the previous sampling interval"
    );
    session.stop.store(true, Ordering::Release);
    collector.poll(&io, 0, || true).unwrap();
    assert!(collector.idle() && collector.session.is_none());
    shared.restored();
    drop(session);
    let next = Session::new(layout, config()).unwrap();
    collector.attach(next.clone()).unwrap();
    collector.control(&io, &next, true, || true).unwrap();
    assert_eq!(shared.allocations.load(Ordering::Relaxed), 1);
    assert_eq!(shared.live.load(Ordering::Relaxed), 1);
    reset(collector, &shared);
    assert_eq!(next.read(&mut [0; 64]), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_sparse_mcr_enable_disable_and_reopen_retains_mapping
);

fn smoke_eu_stall_circular_records_host_fifo_and_source_backpressure() -> TestResult {
    let layout = info(9, 2);
    let (shared, io, mut collector) = fixture(layout);
    shared.pointer(3, PER_CORE as u32 - 64, false);
    let session = Session::new(layout, config()).unwrap();
    collector.attach(session.clone()).unwrap();
    collector.control(&io, &session, true, || true).unwrap();
    let memory = shared.memory();
    let tail = memory.record(3, PER_CORE - 64, 0x30);
    let head = memory.record(3, 0, 0x70);
    shared.pointer(3, PER_CORE as u32 + 64, false);
    collector.poll(&io, 0, || true).unwrap();
    assert_eq!(shared.get(3, 0xe52c), ((PER_CORE as u32 + 64) >> 6) << 2);
    assert_eq!(collector.read[3], PER_CORE as u32 + 64);
    memory.record(3, 0, 0xff); // host copy must stay immutable
    assert_eq!(session.read(&mut [0; 63]), Err(FsError::InvalidData));
    let mut bytes = [0; 160];
    assert_eq!(session.read(&mut bytes), Ok(128));
    assert_eq!(&bytes[..64], &tail);
    assert_eq!(&bytes[64..128], &head);
    assert_eq!(session.read(&mut bytes), Err(FsError::WouldBlock));
    for tick in 1..=16u64 {
        let at = (tick as usize - 1) * CHUNK;
        for record in (0..CHUNK).step_by(64) {
            memory.record(0, at + record, tick as u8);
        }
        shared.pointer(0, tick as u32 * CHUNK as u32, false);
        collector.poll(&io, tick * POLL_NS, || true).unwrap();
    }
    assert_eq!(session.room(), 0);
    let before = shared.get(0, 0xe52c);
    let reads = memory.reads.load(Ordering::Relaxed);
    let next = memory.record(0, HOST_BYTES, 0xa0);
    shared.pointer(0, HOST_BYTES as u32 + 64, false);
    collector.poll(&io, 17 * POLL_NS, || true).unwrap();
    assert_eq!(
        shared.get(0, 0xe52c),
        before,
        "full host FIFO consumed GPU source data"
    );
    assert_eq!(memory.reads.load(Ordering::Relaxed), reads);
    assert_eq!(session.read(&mut [0; 64]), Ok(64));
    collector.poll(&io, 18 * POLL_NS, || true).unwrap();
    assert_eq!(session.room(), 0);
    assert_eq!(shared.get(0, 0xe52c), ((HOST_BYTES as u32 + 64) >> 6) << 2);
    let mut all = Vec::new();
    while session.room() != HOST_BYTES {
        let mut out = [0; 4096];
        let n = session.read(&mut out).unwrap();
        all.extend_from_slice(&out[..n]);
    }
    assert_eq!(&all[all.len() - 64..], &next);
    shared.restored();
    reset(collector, &shared);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_circular_records_host_fifo_and_source_backpressure
);

fn smoke_eu_stall_drop_notification_and_copy_race_never_ack_uncopied_data() -> TestResult {
    for during_copy in [false, true] {
        let layout = info(1, 4);
        let (shared, io, mut collector) = fixture(layout);
        let session = Session::new(layout, config()).unwrap();
        collector.attach(session.clone()).unwrap();
        collector.control(&io, &session, true, || true).unwrap();
        let memory = shared.memory();
        let expected = memory.record(0, 0, 0x40);
        shared.pointer(0, 64, !during_copy);
        memory
            .drop_during_copy
            .store(during_copy, Ordering::Release);
        let result = collector.poll(&io, 0, || true);
        if during_copy {
            assert_eq!(result, Ok(()));
            assert_eq!(shared.get(0, 0xe52c), 0);
            assert_eq!(session.room(), HOST_BYTES);
            assert!(!collector.idle());
            assert!(!collector.poisoned);
            assert_eq!(
                session.read(&mut [0; 64]),
                Err(crate::intel_gpu_user::io_error())
            );
            collector.poll(&io, POLL_NS, || true).unwrap();
            assert_eq!(
                session.read(&mut [0; 64]),
                Err(crate::intel_gpu_user::io_error())
            );
            let mut out = [0; 64];
            assert_eq!(session.read(&mut out), Ok(64));
            assert_eq!(out, expected);
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(shared.get(0, 0xe528) & 2, 0);
            assert_ne!(session.ready.mask() & POLL_ERR, 0);
            assert_eq!(
                session.read(&mut [0; 64]),
                Err(crate::intel_gpu_user::io_error())
            );
            let mut out = [0; 64];
            assert_eq!(session.read(&mut out), Ok(64));
            assert_eq!(out, expected);
            assert_eq!(session.ready.mask() & POLL_ERR, 0);
        }
        assert_eq!(shared.live.load(Ordering::Relaxed), 1);
        shared.restored();
        reset(collector, &shared);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_drop_notification_and_copy_race_never_ack_uncopied_data
);

fn smoke_eu_stall_partial_mmio_authority_loss_and_reset_keep_dma_owned() -> TestResult {
    for failure in 0..6 {
        let layout = info(0x21, 4);
        let (shared, io, mut collector) = fixture(layout);
        let session = Session::new(layout, config()).unwrap();
        collector.attach(session.clone()).unwrap();
        match failure {
            0 => shared.state.lock().drop_write = Some((5, 0xe520)),
            1 => shared.state.lock().fail_read = Some((5, 0xe528)),
            2 => shared.state.lock().fail_restore = true,
            3 => shared.state.lock().busy = true,
            _ => {}
        }
        let accesses = shared.state.lock().accesses;
        let result = collector.control(&io, &session, true, || failure != 4);
        if failure == 3 {
            assert_eq!(result, Err(FsError::WouldBlock));
            assert!(!collector.poisoned);
            shared.state.lock().busy = false;
            collector.control(&io, &session, true, || true).unwrap();
        } else if failure == 5 {
            assert_eq!(result, Ok(()));
            shared.state.lock().drop_write = Some((5, 0xe520));
            assert_eq!(collector.disable(&io, || true), Err(FsError::NoDevice));
        } else {
            assert_eq!(result, Err(FsError::NoDevice));
            assert!(collector.poisoned);
            assert_eq!(
                collector.control(&io, &session, true, || true),
                Err(FsError::NoDevice)
            );
        }
        if failure == 4 {
            assert_eq!(
                shared.state.lock().accesses,
                accesses,
                "denied authority touched MMIO"
            );
        }
        if failure != 3 {
            assert!(!collector.idle());
        }
        assert_eq!(shared.live.load(Ordering::Relaxed), 1);
        assert_eq!(shared.freed.load(Ordering::Relaxed), 0);
        reset(collector, &shared);
        assert_eq!(session.read(&mut [0; 64]), Err(FsError::NoDevice));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_partial_mmio_authority_loss_and_reset_keep_dma_owned
);

fn smoke_eu_stall_allocation_bounds_unexposed_drop_and_exposed_quarantine() -> TestResult {
    for failure in 0..3 {
        let layout = info(1, 4);
        let shared = Shared::new(4);
        match failure {
            0 => shared.coherent.store(false, Ordering::Relaxed),
            1 => shared.extent.store(1, Ordering::Relaxed),
            _ => shared.base.store(0xffff_f000, Ordering::Relaxed),
        }
        assert!(matches!(
            Collector::new(Allocator(shared.clone()), layout),
            Err(FsError::Unsupported)
        ));
        assert_eq!(shared.live.load(Ordering::Relaxed), 0);
        assert_eq!(shared.freed.load(Ordering::Relaxed), 1);
    }
    let (shared, _, collector) = fixture(info(1 << 31, 2));
    assert_eq!(
        shared.memory().pages,
        4096,
        "highest physical DSS bounds the sparse aperture"
    );
    drop(collector);
    assert_eq!(shared.live.load(Ordering::Relaxed), 0);
    let layout = info(1, 4);
    let (shared, io, mut collector) = fixture(layout);
    let session = Session::new(layout, config()).unwrap();
    collector.attach(session.clone()).unwrap();
    collector.control(&io, &session, true, || true).unwrap();
    drop(collector); // exposed DMA is deliberately quarantined, never Drop-freed
    assert_eq!(shared.live.load(Ordering::Relaxed), 1);
    assert_eq!(shared.freed.load(Ordering::Relaxed), 0);
    assert_eq!(session.read(&mut [0; 64]), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_allocation_bounds_unexposed_drop_and_exposed_quarantine
);

struct Wire {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    installed: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
    fail_install: AtomicBool,
}
impl Wire {
    fn new() -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(alloc::vec![0;1024]),
            installed: IrqSafeSpinLock::new(None),
            fail_install: AtomicBool::new(false),
        }
    }
    fn property(&self, at: u64, next: u64, key: u32, value: u64) {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&next.to_le_bytes());
        bytes[16..20].copy_from_slice(&key.to_le_bytes());
        bytes[24..32].copy_from_slice(&value.to_le_bytes());
        self.write(at, &bytes).unwrap();
    }
    fn opening(&self) {
        let mut bytes = [0; 32];
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&128u64.to_le_bytes());
        self.write(32, &bytes).unwrap();
        self.property(128, 160, 1, 0);
        self.property(160, 192, 2, 503);
        self.property(192, 0, 3, 1);
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
    fn nonblocking(&self) -> bool {
        false
    }
    fn install_file(&self, file: Arc<dyn FileOps>, cloexec: bool) -> Result<i32, FsError> {
        assert!(!cloexec);
        if self.fail_install.load(Ordering::Acquire) {
            return Err(FsError::NoSpace);
        }
        let mut slot = self.installed.lock();
        assert!(slot.is_none());
        *slot = Some(file);
        Ok(37)
    }
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("expected bounded synchronous EU-stall transaction"),
    }
}

fn smoke_eu_stall_query_properties_record_bounds_and_malformed_cursors() -> TestResult {
    let layout = info(0x21, 4);
    let bytes = query(layout).unwrap();
    assert_eq!(bytes.len(), 136);
    let qword = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    assert_eq!(
        (qword(0), qword(8), qword(16), qword(24), qword(72)),
        (0, 1, 64, 524288, 7)
    );
    assert!(bytes[32..72].iter().all(|byte| *byte == 0));
    for rate in 1..=7usize {
        assert_eq!(qword(80 + (rate - 1) * 8), rate as u64 * 251);
    }
    for bad in [
        info(0, 4),
        info(1, 0),
        info(1, 17),
        info(1 << 31, 1),
        Info { card: 64, ..layout },
    ] {
        assert_eq!(query(bad), Err(FsError::Unsupported));
    }
    let wire = Wire::new();
    wire.opening();
    assert_eq!(
        properties(layout, 128, &wire),
        Ok(Config { rate: 2, wait: 1 })
    );
    assert_eq!(properties(layout, 0, &wire), Err(FsError::InvalidData));
    for (key, value, error) in [
        (1, 1, FsError::InvalidData),
        (2, 250, FsError::InvalidData),
        (2, 2008, FsError::InvalidData),
        (3, 0, FsError::InvalidData),
        (3, layout.reports() + 1, FsError::InvalidData),
        (3, 2, FsError::Unsupported),
        (4, 0, FsError::InvalidData),
    ] {
        wire.property(128, 160, 1, 0);
        wire.property(160, 0, key, value);
        assert_eq!(properties(layout, 128, &wire), Err(error));
    }
    wire.property(128, 128, 1, 0);
    assert_eq!(properties(layout, 128, &wire), Err(FsError::InvalidData));
    wire.property(128, 1008, 1, 0);
    assert_eq!(properties(layout, 128, &wire), Err(FsError::BadAddress));
    wire.property(128, 0, 1, 0);
    wire.write(140, &1u32.to_le_bytes()).unwrap();
    assert_eq!(properties(layout, 128, &wire), Err(FsError::InvalidData));
    assert_eq!(
        Session::new(layout, Config { rate: 4, wait: 2 }).unwrap_err(),
        FsError::Unsupported
    );
    let (shared, io, mut collector) = fixture(layout);
    let session = Session::new(layout, config()).unwrap();
    collector.attach(session.clone()).unwrap();
    collector.control(&io, &session, true, || true).unwrap();
    shared.pointer(0, PER_CORE as u32 + 64, false); // impossible unread extent >one hardware ring
    assert_eq!(collector.poll(&io, 0, || true), Err(FsError::InvalidData));
    assert!(collector.poisoned && !collector.idle());
    assert_eq!(shared.memory().reads.load(Ordering::Relaxed), 0);
    assert_eq!(shared.get(0, 0xe52c), 0);
    assert_eq!(session.read(&mut [0; 64]), Err(FsError::NoDevice));
    reset(collector, &shared);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_query_properties_record_bounds_and_malformed_cursors
);

static ALLOWED: AtomicBool = AtomicBool::new(true);
fn allowed() -> bool {
    ALLOWED.load(Ordering::Acquire)
}
struct Backend {
    layout: Info,
    shared: Arc<Shared>,
    io: Window,
    collector: IrqSafeSpinLock<Option<Collector<Allocator>>>,
    pending_attach: AtomicBool,
    revoke: AtomicBool,
    calls: AtomicUsize,
}
impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EuStallFixtureBackend")
    }
}
impl Backend {
    fn new() -> Arc<Self> {
        let layout = info(1, 4);
        let (shared, io, collector) = fixture(layout);
        Arc::new(Self {
            layout,
            shared,
            io,
            collector: IrqSafeSpinLock::new(Some(collector)),
            pending_attach: AtomicBool::new(false),
            revoke: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        })
    }
    fn poll(&self) {
        self.collector
            .lock()
            .as_mut()
            .unwrap()
            .poll(&self.io, 0, || true)
            .unwrap();
    }
    fn reset(&self) {
        reset(self.collector.lock().take().unwrap(), &self.shared);
    }
}
impl UserBackend for Backend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn eu_stall_info(&self) -> Option<Info> {
        Some(self.layout)
    }
    fn eu_stall_control(&self, session: Arc<Session>, operation: Operation) -> FsFuture<'_, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            {
                let mut owner = self.collector.lock();
                let owner = owner.as_mut().unwrap();
                match operation {
                    Operation::Attach => owner.attach(session)?,
                    Operation::Enable => owner.control(&self.io, &session, true, || true)?,
                    Operation::Disable => owner.control(&self.io, &session, false, || true)?,
                }
            }
            if operation == Operation::Attach && self.pending_attach.load(Ordering::Acquire) {
                core::future::pending::<()>().await;
            }
            if self.revoke.load(Ordering::Acquire) {
                ALLOWED.store(false, Ordering::Release);
            }
            Ok(())
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
fn smoke_eu_stall_descriptor_current_authority_install_cancel_and_last_close() -> TestResult {
    ALLOWED.store(true, Ordering::Release);
    let gate = Gate { capable: allowed };
    let backend = Backend::new();
    let wire = Wire::new();
    wire.opening();
    ALLOWED.store(false, Ordering::Release);
    assert_eq!(
        ready(open_with_gate(backend.clone(), 32, &wire, gate)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    ALLOWED.store(true, Ordering::Release);
    wire.fail_install.store(true, Ordering::Release);
    assert_eq!(
        ready(open_with_gate(backend.clone(), 32, &wire, gate)),
        Err(FsError::NoSpace)
    );
    assert!(backend
        .collector
        .lock()
        .as_ref()
        .unwrap()
        .session
        .as_ref()
        .unwrap()
        .stop
        .load(Ordering::Acquire));
    backend.poll();
    assert!(!ACTIVE[61].load(Ordering::Acquire));
    wire.fail_install.store(false, Ordering::Release);
    backend.pending_attach.store(true, Ordering::Release);
    {
        let mut pending = Box::pin(open_with_gate(backend.clone(), 32, &wire, gate));
        assert!(pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        wire.property(160, 0, 2, 1757); // original copied configuration stays rate2
        assert_eq!(
            backend
                .collector
                .lock()
                .as_ref()
                .unwrap()
                .session
                .as_ref()
                .unwrap()
                .config
                .rate,
            2
        );
    }
    assert!(backend
        .collector
        .lock()
        .as_ref()
        .unwrap()
        .session
        .as_ref()
        .unwrap()
        .stop
        .load(Ordering::Acquire));
    backend.poll();
    assert!(!ACTIVE[61].load(Ordering::Acquire));
    backend.pending_attach.store(false, Ordering::Release);
    wire.opening();
    assert_eq!(
        ready(open_with_gate(backend.clone(), 32, &wire, gate)),
        Ok(37)
    );
    let file = wire.installed.lock().take().unwrap();
    let duplicate = file.clone();
    assert!(file.is_stream() && file.nonblock_read_eagain());
    assert_eq!(ready(file.read(0, &mut [0; 64])), Err(FsError::InvalidData));
    assert_eq!(ready(file.ioctl_user(0x6900, 0, &wire)), Ok(0));
    assert_eq!(ready(file.read(0, &mut [0; 64])), Err(FsError::WouldBlock));
    let record = backend.shared.memory().record(0, 0, 0x50);
    backend.shared.pointer(0, 64, false);
    backend.poll();
    assert_ne!(file.poll_readiness() & POLL_IN, 0);
    let mut output = [0; 64];
    assert_eq!(ready(duplicate.read(0, &mut output)), Ok(64));
    assert_eq!(output, record);
    assert_eq!(ready(file.ioctl_user(0x6901, 0, &wire)), Ok(0));
    assert!(backend.collector.lock().as_ref().unwrap().idle());
    backend.revoke.store(true, Ordering::Release);
    assert_eq!(
        ready(file.ioctl_user(0x6900, 0, &wire)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(
        ready(duplicate.read(0, &mut output)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(duplicate.poll_readiness(), POLL_ERR | POLL_HUP);
    backend.poll();
    drop(file);
    assert!(
        ACTIVE[61].load(Ordering::Acquire),
        "dup keeps the per-card permit"
    );
    drop(duplicate);
    assert!(!ACTIVE[61].load(Ordering::Acquire));
    backend.reset();
    ALLOWED.store(true, Ordering::Release);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_eu_stall",
    smoke_eu_stall_descriptor_current_authority_install_cancel_and_last_close
);
