use super::*;
use crate::amdgpu_navi48_interrupts as interrupts;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const GPU: u64 = 0x8_0000_4000;
const VA: u64 = 0xc_0000_0000;
struct Fake {
    index: u32,
    memory: Vec<u32>,
    target: Vec<u32>,
    dirty: bool,
    mapped: Arc<AtomicU32>,
    progress: Arc<AtomicU32>,
    eop: Arc<[AtomicU32; 3]>,
    emit_eop: bool,
    emit_cpu: bool,
    bells: Vec<u32>,
    complete: bool,
    corrupt: bool,
    rptr_stuck: bool,
    busy: bool,
    revoked: Option<Cap<BusDeviceCap, Write>>,
    regs: BTreeMap<u64, u32>,
}
impl Fake {
    fn execute(&mut self, pipe: usize, tail: u32) {
        assert!(!self.dirty);
        assert_eq!(self.mapped.load(Ordering::SeqCst) & (1 << pipe), 1 << pipe);
        let off = pipe * 3072;
        let m = &self.memory[off + 1024..];
        assert_eq!(
            u64::from(m[128]) | (u64::from(m[129]) << 32),
            GPU + pipe as u64 * 12288 + 4096
        );
        assert_eq!(m[130], 1);
        assert_eq!(m[131], 0);
        assert_eq!(m[135], if pipe == 0 { 0xa01 } else { 0x111 });
        assert_eq!(m[143], if pipe == 0 { 0x40000458 } else { 0x40000018 });
        assert_eq!(m[145], if pipe == 0 { 0x00a00709 } else { 0xd0308909 });
        assert_eq!(m[162], 0x100);
        assert_eq!(m[184], 0);
        assert_eq!(self.memory[off + 2562], tail);
        let mut cursor = self.memory[off + 2560] as usize;
        let mut writes = 0;
        while cursor < tail as usize {
            let words = &self.memory[off + cursor..];
            let header = words[0];
            assert_eq!(header >> 30, 3);
            let length = ((header >> 16) & 0x3fff) as usize + 2;
            assert!(cursor + length <= tail as usize);
            match (header >> 8) & 255 {
                0x37 => {
                    assert_eq!(words[1], 0x100500);
                    let address = u64::from(words[2]) | (u64::from(words[3]) << 32);
                    assert!(address >= VA + pipe as u64 * 4096);
                    assert!(address + (length as u64 - 4) * 4 <= VA + (pipe as u64 + 1) * 4096);
                    assert_eq!(address % 4, 0);
                    let index = ((address - VA) / 4) as usize;
                    self.target[index..index + length - 4].copy_from_slice(&words[4..length]);
                    writes += length - 4;
                }
                0x10 => {}
                0x49 => {
                    assert_eq!(length, 8);
                    assert_eq!(words[1], 0x06600514);
                    assert_eq!(words[2], 0x22000000);
                    let address = u64::from(words[3]) | (u64::from(words[4]) << 32);
                    assert_eq!(address, VA + pipe as u64 * 4096 + 4088);
                    assert_eq!(words[5], if pipe == 0 { 0x90701234 } else { 0x90705678 });
                    assert_eq!(&words[6..8], &[0, 0]);
                    assert_eq!(
                        self.regs[&if pipe == 0 { 0x17828 } else { 0x17894 }] & 0x84000000,
                        0x84000000
                    );
                    self.target[((address - VA) / 4) as usize] = words[5] ^ u32::from(self.corrupt);
                    if self.emit_eop {
                        self.eop[pipe].fetch_add(1, Ordering::SeqCst);
                    }
                    if self.emit_cpu {
                        self.eop[2].fetch_add(1, Ordering::SeqCst);
                    }
                    writes += 1;
                }
                _ => panic!("unexpected bootstrap PM4 opcode"),
            }
            cursor += length;
        }
        assert_eq!(writes, if tail == 256 { 17 } else { 1 });
        if self.corrupt {
            self.target[pipe * 1024 + 7] ^= 1;
        }
        if !self.rptr_stuck {
            self.memory[off + 2560] = tail;
        }
        // GC12 updates only the low 32 bits of its RPTR writeback.
        self.memory[off + 2561] = u32::MAX;
    }
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        match at {
            0x42400 => self.index,
            0x15850 => 0x800,
            0x15854 => 0xbff,
            0x604b4 => 0x7f000,
            0x17a00 | 0x17eac => u32::from(self.busy),
            _ => *self.regs.get(&at).unwrap_or(&0),
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        match at {
            0x42400 => self.index = v,
            0x7f000 => self.dirty = false,
            _ => panic!("unexpected CP register write"),
        }
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        assert!(!self.dirty);
        if map.phys.raw() == 0x90004000 {
            self.memory[(at / 4) as usize]
        } else {
            self.target[(at / 4) as usize]
        }
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, v: u32) {
        self.dirty = true;
        if map.phys.raw() == 0x90004000 {
            self.memory[(at / 4) as usize] = v;
        } else {
            self.target[(at / 4) as usize] = v;
        }
    }
    fn doorbell(&mut self, _: MmioRegion, offset: u32, v: u64) {
        assert!(v == 256 || v == 512);
        let pipe = match offset {
            0x116 => 0,
            6 => 1,
            _ => panic!("wrong CP doorbell"),
        };
        self.bells.push(offset);
        self.progress.store(1, Ordering::SeqCst);
        if self.complete {
            self.execute(pipe, v as u32);
        }
        if let Some(cap) = self.revoked {
            cap.revoke();
        }
    }
    async fn delay(&mut self) {
        assert_eq!(self.index, 0x32);
        narf_scheduler::yield_now().await;
    }
}
struct FakeMes {
    mapped: Arc<AtomicU32>,
    fail: Option<api::QueueType>,
    stall: Option<api::QueueType>,
}
impl Mapper for FakeMes {
    async fn map(&mut self, q: api::KernelQueue) -> Result<(), mes::Error> {
        let pipe = match q.kind {
            api::QueueType::Graphics => 0,
            api::QueueType::Compute => 1,
            _ => panic!("wrong MES queue type"),
        };
        assert_eq!((q.pipe, q.queue), (0, 0));
        assert_eq!(q.mqd, GPU + pipe * 12288 + 4096);
        assert_eq!(q.write_pointer, GPU + pipe * 12288 + 10248);
        assert_eq!(q.doorbell, if pipe == 0 { 0x116 } else { 6 });
        if self.fail == Some(q.kind) {
            return Err(mes::Error::Timeout);
        }
        if self.stall == Some(q.kind) {
            core::future::pending::<()>().await;
        }
        self.mapped.fetch_or(1 << pipe, Ordering::SeqCst);
        Ok(())
    }
}
fn fixture() -> (Pool, Engine<Fake>, FakeMes, gmc::Aperture, MmioRegion) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: 24576,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts all memory accesses, bookkeeping-only mapping.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let mapped = Arc::new(AtomicU32::new(0));
    let e = Engine {
        io: Fake {
            index: 0x32,
            memory: vec![u32::MAX; 6144],
            target: vec![u32::MAX; 2048],
            dirty: false,
            mapped: mapped.clone(),
            progress: Arc::new(AtomicU32::new(0)),
            eop: Arc::new(core::array::from_fn(|_| AtomicU32::new(0))),
            emit_eop: true,
            emit_cpu: true,
            bells: Vec::new(),
            complete: true,
            corrupt: false,
            rptr_stuck: false,
            busy: false,
            revoked: None,
            regs: BTreeMap::from([(0x17828, 0x84000000), (0x17894, 0x84000000)]),
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: 0x10000,
            hyp: 0x40000,
            nbio: 0x60000,
        },
        doorbells: map,
        memory: pool.reserve(24576).unwrap(),
        state: State::Prepared,
        proof: None,
        interrupt_result: None,
    };
    let mes = FakeMes {
        mapped,
        fail: None,
        stall: None,
    };
    let aperture = gmc::Aperture {
        start: VA,
        size: 2 << 20,
        source: VA,
        destination: VA + 4096,
    };
    let target = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90100000),
        len: 8192,
        ..map
    };
    (pool, e, mes, aperture, target)
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn gfx12_kernel_queues_execute_confirmed_writes_through_owned_translation() -> TestResult {
    let (pool, mut e, mut mes, aperture, target) = fixture();
    assert_eq!(
        run(e.initialize(&mut mes, aperture, target)),
        Ok(Proof {
            graphics_fence: 0x9070cafe,
            compute_fence: 0x9070beef,
            written_bytes: 128
        })
    );
    assert_eq!(e.state, State::Verified);
    assert_eq!(e.io.index, 0x32);
    assert_eq!(e.io.bells, [0x116, 6]);
    assert_eq!(
        run(e.initialize(&mut mes, aperture, target)),
        Err(Error::Busy)
    );
    drop(e);
    assert_eq!(pool.available(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queues_execute_confirmed_writes_through_owned_translation
);

fn gfx12_kernel_queues_refuse_inherited_hqds_and_bad_apertures() -> TestResult {
    for case in 0..3 {
        let (pool, mut e, mut mes, mut aperture, target) = fixture();
        let expected = match case {
            0 => {
                e.io.busy = true;
                Error::Busy
            }
            1 => {
                aperture.destination += 4096;
                Error::Invalid
            }
            _ => {
                e.authority.revoke();
                Error::Revoked
            }
        };
        assert_eq!(run(e.initialize(&mut mes, aperture, target)), Err(expected));
        assert_eq!(e.io.index, 0x32);
        assert!(e.io.bells.is_empty());
        assert_eq!(mes.mapped.load(Ordering::SeqCst), 0);
        drop(e);
        assert_eq!(pool.available(), 24576);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queues_refuse_inherited_hqds_and_bad_apertures
);

fn gfx12_kernel_queue_failures_keep_mapped_storage_and_no_success_report() -> TestResult {
    for case in 0..5 {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        let expected = match case {
            0 => {
                e.io.corrupt = true;
                Error::DataMismatch
            }
            1 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            2 => {
                e.io.complete = false;
                Error::Timeout
            }
            3 => {
                mes.fail = Some(api::QueueType::Compute);
                Error::Mes(mes::Error::Timeout)
            }
            _ => {
                e.io.revoked = Some(e.authority);
                Error::Revoked
            }
        };
        assert_eq!(run(e.initialize(&mut mes, aperture, target)), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.proof, None);
        assert_eq!(e.io.bells, [0x116]);
        assert_eq!(
            run(e.initialize(&mut mes, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queue_failures_keep_mapped_storage_and_no_success_report
);

fn gfx12_kernel_queue_cancellation_retains_pending_maps_and_submissions() -> TestResult {
    for case in 0..3 {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        match case {
            0 => mes.stall = Some(api::QueueType::Graphics),
            1 => mes.stall = Some(api::QueueType::Compute),
            _ => e.io.complete = false,
        };
        {
            let mut f = core::pin::pin!(e.initialize(&mut mes, aperture, target));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(
            e.state,
            match case {
                0 => State::Mapping(0),
                1 => State::Mapping(1),
                _ => State::Submitted(0),
            }
        );
        assert_eq!(
            run(e.initialize(&mut mes, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queue_cancellation_retains_pending_maps_and_submissions
);

struct FakeObserver {
    counters: Arc<[AtomicU32; 3]>,
    msi: bool,
    stall: bool,
    reject: bool,
}
impl FakeObserver {
    fn new(e: &Engine<Fake>) -> Self {
        Self {
            counters: e.io.eop.clone(),
            msi: true,
            stall: false,
            reject: false,
        }
    }
}
impl Observer for FakeObserver {
    async fn sample(
        &mut self,
        source: Source,
    ) -> Result<interrupts::Sample, crate::amdgpu_ih7::Error> {
        if self.stall {
            core::future::pending::<()>().await;
        }
        if self.reject {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        let pipe = match source {
            Source::Graphics => 0,
            Source::Compute => 1,
            Source::Sdma0 => panic!("unexpected SDMA sample"),
        };
        Ok(interrupts::Sample {
            source,
            count: self.counters[pipe].load(Ordering::SeqCst).into(),
            cpu: self.counters[2].load(Ordering::SeqCst).into(),
            vector: self.msi.then_some(0x60),
        })
    }
    async fn observed(
        &mut self,
        sample: interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        Ok(u64::from(
            self.counters[match sample.source {
                Source::Graphics => 0,
                Source::Compute => 1,
                Source::Sdma0 => panic!("unexpected SDMA sample"),
            }]
            .load(Ordering::SeqCst),
        ) == sample.count + 1
            && (!self.msi || u64::from(self.counters[2].load(Ordering::SeqCst)) != sample.cpu))
    }
}
fn gfx12_eop_proof_requires_each_engine_fence_vector_and_cpu_delivery() -> TestResult {
    for msi in [true, false] {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        observer.msi = msi;
        e.io.emit_cpu = msi;
        e.io.regs.insert(0x17828, 0x84100000);
        e.io.regs.insert(0x17894, 0x84200000);
        let expected = Ok(InterruptProof {
            fences: [0x90701234, 0x90705678],
            msi_verified: msi,
        });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            expected
        );
        assert_eq!(e.interrupt_result, Some(expected));
        assert_eq!(e.state, State::InterruptVerified);
        assert_eq!(e.io.bells, [0x116, 6, 0x116, 6]);
        assert_eq!(e.io.regs[&0x17828], 0x84100000);
        assert_eq!(e.io.regs[&0x17894], 0x84200000);
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_proof_requires_each_engine_fence_vector_and_cpu_delivery
);

fn gfx12_eop_missing_evidence_faults_and_revocation_never_report_success() -> TestResult {
    for case in 0..8 {
        let (pool, mut e, mut mes, mut aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        let expected = match case {
            0 => {
                e.io.emit_eop = false;
                Error::Timeout
            }
            1 => {
                e.io.emit_cpu = false;
                Error::Timeout
            }
            2 => {
                e.io.corrupt = true;
                Error::Timeout
            }
            3 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            4 => {
                e.io.revoked = Some(e.authority);
                Error::Revoked
            }
            5 => {
                observer.reject = true;
                Error::Interrupts(crate::amdgpu_ih7::Error::Protocol)
            }
            6 => {
                aperture.start = u64::MAX;
                aperture.source = u64::MAX;
                Error::Invalid
            }
            _ => {
                e.io.regs.insert(0x17828, 0);
                Error::Busy
            }
        };
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(expected)
        );
        assert_eq!(e.interrupt_result, Some(Err(expected)));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.io.bells.len(), if case >= 5 { 2 } else { 3 });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_missing_evidence_faults_and_revocation_never_report_success
);

fn gfx12_eop_cancellation_retains_sources_queues_and_prevents_replay() -> TestResult {
    for before_submit in [true, false] {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        observer.stall = before_submit;
        e.io.complete = false;
        {
            let mut f = core::pin::pin!(e.prove_interrupts(&mut observer, aperture, target));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.state, State::InterruptSubmitted(0));
        assert_eq!(e.interrupt_result, None);
        assert_eq!(e.io.bells.len(), if before_submit { 2 } else { 3 });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_cancellation_retains_sources_queues_and_prevents_replay
);
