use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Sample, Source};
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const VCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const GC: u64 = 0x50000;
const GPU: u64 = 0x8_0000_4000;
#[path = "amdgpu_jpeg_navi48_decode_tests.rs"]
mod decode_tests;
fn jpeg5_layout_rejects_wrong_mmhub_or_truncated_jpeg_banks() -> TestResult {
    let descriptor = || {
        let mut backing = vec![0; 0x80000 / 4];
        let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut backing);
        let nbif = &mut gpu.ip_blocks[2];
        (nbif.major, nbif.minor, nbif.revision) = (6, 3, 1);
        let mut vcn = gpu.ip_blocks[0];
        vcn.hw_id = ip::HW_ID_VCN;
        (vcn.major, vcn.minor, vcn.revision) = (5, 0, 0);
        vcn.base_addrs[1] = 0x18000;
        gpu.ip_blocks.push(vcn);
        gpu // Metadata only; no access into the expired register backing.
    };
    let gpu = descriptor();
    assert_eq!(Layout::resolve(&gpu).unwrap().vcn, 0x60000);
    for case in 0..7 {
        let mut gpu = descriptor();
        match case {
            0 => gpu.ip_blocks[1].minor = 2,
            1 => gpu.ip_blocks[1].num_bases = 0,
            2 => gpu.ip_blocks[5].base_addrs[1] = 0x20000 - 0x721,
            3 => gpu.ip_blocks[5].revision = 1,
            4 => gpu.ip_blocks.push(gpu.ip_blocks[5]),
            5 => gpu.chip.did = crate::amdgpu::NAVI22,
            _ => gpu.regs.len = 0x7f000,
        }
        assert!(Layout::resolve(&gpu).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_layout_rejects_wrong_mmhub_or_truncated_jpeg_banks
);
struct Fake {
    picture: decode_tests::Model,
    regs: BTreeMap<u64, u32>,
    memory: Vec<u8>,
    writes: Vec<(u64, u32)>,
    packets: BTreeMap<u32, u32>,
    dirty: bool,
    signals: Arc<[AtomicU32; 2]>,
    advance: bool,
    ib: bool,
    pitch: bool,
    fence: bool,
    cpu: bool,
    iv: bool,
    wide: bool,
    damage: bool,
    ignored: Option<u64>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Fake {
    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.memory[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn store(&mut self, at: u64, value: u32) {
        self.memory[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn execute(&mut self, offset: u64, len: u32) -> bool {
        for n in (0..len).step_by(2) {
            let header = self.word(offset + u64::from(n) * 4);
            let value = self.word(offset + u64::from(n + 1) * 4);
            let reg = header & 0x3ffff;
            match header >> 28 {
                0 => {
                    self.packets.insert(reg, value);
                    if reg == words::PITCH && self.pitch {
                        self.regs.insert(VCN + u64::from(PITCH) * 4, value);
                    }
                    if reg == 0x18000 {
                        let target = self.packets[&0x1bfff];
                        assert!(matches!(target, 0x69004 | 0x7f000));
                        self.regs.insert(u64::from(target), value);
                    }
                    if reg == 0x404d && value == 8 && self.fence {
                        let address = (u64::from(self.packets[&0x40ac]) << 32)
                            | u64::from(self.packets[&0x40ab]);
                        assert_eq!(address, GPU + FENCE);
                        self.store(FENCE, self.packets[&0x404e]);
                        if self.wide {
                            self.store(FENCE + 4, self.packets[&0x404f]);
                        }
                        if self.damage {
                            self.store(FENCE + 12, 1);
                        }
                    }
                }
                2 => {
                    assert_eq!(self.packets[&0x40a4], 0);
                    assert_eq!(self.packets[&0x40a6], 0);
                    assert_eq!(self.regs[&0x69004], 0x80010000);
                    if !self.ib {
                        return false;
                    }
                    let address =
                        (u64::from(self.packets[&0x40b7]) << 32) | u64::from(self.packets[&0x40b6]);
                    let dwords = self.packets[&0x4082];
                    if self.picture.contains(address) {
                        if !self.picture.execute(address, dwords) {
                            return false;
                        }
                        if self.picture.fault == 11 {
                            self.store(RING, 0);
                        }
                    } else {
                        assert_eq!(address, GPU + IB);
                        assert_eq!(dwords, 16);
                        assert!(self.execute(IB, 16));
                    }
                }
                3 => {
                    assert_eq!((header, value), (0x33004089, 2));
                }
                4 | 6 => {}
                7 => {
                    if self.iv {
                        self.signals[0].fetch_add(1, Ordering::AcqRel);
                    }
                    if self.cpu {
                        self.signals[1].fetch_add(1, Ordering::AcqRel);
                    }
                }
                _ => panic!("unexpected JPEG packet"),
            }
        }
        true
    }
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        if at == 0x7f000 {
            self.dirty = false;
        }
        if self.ignored == Some(at) {
            return;
        }
        self.regs.insert(at, value);
        if at == VCN + u64::from(DLDO_CONFIG) * 4 {
            let status = self
                .regs
                .entry(VCN + u64::from(DLDO_STATUS) * 4)
                .or_default();
            if value & 0x30 == 0x10 {
                *status &= !4;
            }
            if value & 0x30 == 0x20 {
                *status |= 4;
            }
        }
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        assert!(!self.dirty);
        if let Some(value) = self.picture.read(map, at) {
            return value;
        }
        self.word(at)
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32) {
        if self.picture.write(map, at, value) {
            self.dirty = true;
            return;
        }
        self.store(at, value);
        self.dirty = true;
    }
    fn memory_read8(&mut self, _: MmioRegion, _: u64) -> u8 {
        unreachable!()
    }
    fn memory_write8(&mut self, _: MmioRegion, _: u64, _: u8) {
        unreachable!()
    }
    fn doorbell(&mut self, at: u32, value: u32) {
        assert_eq!(at, DOORBELL);
        assert!(!self.dirty);
        assert_eq!(self.word(WRITEBACK), value);
        let previous = self.regs[&(VCN + u64::from(RPTR) * 4)];
        if self.advance && self.execute(RING + u64::from(previous) * 4, value - previous) {
            self.regs.insert(VCN + u64::from(RPTR) * 4, value);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
    }
    async fn delay(&mut self, _: u64) {
        let mut yielded = false;
        core::future::poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }
}
struct Irqs {
    signals: Arc<[AtomicU32; 2]>,
    stall_sample: bool,
    stall_observed: bool,
}
impl Observer for Irqs {
    async fn sample(&mut self, source: Source) -> Result<Sample, crate::amdgpu_ih7::Error> {
        assert_eq!(source, Source::Jpeg0);
        if self.stall_sample {
            core::future::pending::<()>().await;
        }
        Ok(Sample {
            source,
            count: u64::from(self.signals[0].load(Ordering::Acquire)),
            cpu: u64::from(self.signals[1].load(Ordering::Acquire)),
            vector: Some(64),
        })
    }
    async fn observed(&mut self, sample: Sample) -> Result<bool, crate::amdgpu_ih7::Error> {
        if self.stall_observed {
            core::future::pending::<()>().await;
        }
        Ok(
            u64::from(self.signals[0].load(Ordering::Acquire)) == sample.count + 1
                && u64::from(self.signals[1].load(Ordering::Acquire)) > sample.cpu,
        )
    }
}
fn fixture() -> (Pool, Engine<Fake>, Irqs) {
    fixture_capacity(BYTES * 2)
}
fn fixture_capacity(capacity: u64) -> (Pool, Engine<Fake>, Irqs) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: capacity,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake intercepts every access; the mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let signals = Arc::new([AtomicU32::new(7), AtomicU32::new(9)]);
    let io = Fake {
        picture: decode_tests::Model::default(),
        regs: BTreeMap::from([
            (NBIO + u64::from(RANGE) * 4, RANGE_VALUE),
            (VCN + u64::from(DLDO_CONFIG) * 4, 0x15500),
            (VCN + u64::from(DLDO_STATUS) * 4, 4),
            (VCN + u64::from(CLEAN) * 4, 0x1010f),
            (VCN + u64::from(STATUS) * 4, 1),
            (GC + 0x263e * 4, 0x545),
            (VCN + u64::from(CG_CTRL) * 4, 0x01010000),
            (VCN + u64::from(RPTR) * 4, 0),
        ]),
        memory: vec![0x5a; BYTES as usize],
        writes: Vec::new(),
        packets: BTreeMap::new(),
        dirty: false,
        signals: signals.clone(),
        advance: true,
        ib: true,
        pitch: true,
        fence: true,
        cpu: true,
        iv: true,
        wide: false,
        damage: false,
        ignored: None,
        revoke: None,
    };
    let observer = Irqs {
        signals,
        stall_sample: false,
        stall_observed: false,
    };
    let engine = Engine {
        io,
        authority: Cap::bootstrap(),
        layout: Layout {
            vcn: VCN,
            nbio: NBIO,
            gc: GC,
        },
        memory: pool.reserve(BYTES).unwrap(),
        pool: pool.clone(),
        decode_memory: None,
        state: State::Prepared,
        result: None,
        decode_result: None,
        seq: 0,
        wptr: 0,
    };
    (pool, engine, observer)
}
fn power() -> crate::amdgpu_smu_navi48::PowerStatus {
    crate::amdgpu_smu_navi48::PowerStatus {
        allowed: 0,
        enabled: 0,
        gfx_min_mhz: 0,
        gfx_max_mhz: 0,
        uclk_mhz: None,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = core::pin::pin!(f);
    for _ in 0..1_000_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return v;
        }
    }
    panic!("JPEG model did not finish")
}
fn jpeg5_static_transport_proves_direct_ib_and_irq_with_distinct_fence_words() -> TestResult {
    for wide in [false, true] {
        let (pool, mut e, mut irq) = fixture();
        e.io.wide = wide;
        for restart in [false, true] {
            if restart {
                e.seq = u32::MAX;
            }
            run(e.start(power())).unwrap();
            assert_eq!(
                e.io.regs[&(VCN + u64::from(DLDO_CONFIG) * 4)] & !0x30,
                0x15500
            );
            let proof = run(e.prove(&mut irq)).unwrap();
            assert_eq!(
                proof,
                Proof {
                    sequence: 1,
                    read_pointer: 80,
                    msi_verified: true
                }
            );
            assert_eq!(e.state, State::Verified);
            assert_eq!(e.result, Some(Ok(proof)));
            assert!(!e.memory.reusable_for_test());
            assert_eq!(e.io.word(FENCE + 4), if wide { 1 } else { 0 });
            assert_eq!(e.io.word(WRITEBACK), 80);
            assert_eq!(e.io.regs[&0x69004], 0x10000);
            run(e.stop()).unwrap();
            assert!(e.memory.reusable_for_test());
            assert_eq!(e.io.regs[&(NBIO + u64::from(RANGE) * 4)], RANGE_VALUE);
            assert!(e
                .io
                .writes
                .iter()
                .all(|(at, _)| *at != NBIO + u64::from(RANGE) * 4));
        }
        drop(e);
        assert_eq!(pool.available(), BYTES * 2);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_static_transport_proves_direct_ib_and_irq_with_distinct_fence_words
);
fn jpeg5_faults_keep_all_published_storage_and_close_stop() -> TestResult {
    for fault in 0..8 {
        let (pool, mut e, mut irq) = fixture();
        run(e.start(power())).unwrap();
        match fault {
            0 => e.io.advance = false,
            1 => e.io.ib = false,
            2 => e.io.pitch = false,
            3 => e.io.fence = false,
            4 => e.io.iv = false,
            5 => e.io.cpu = false,
            6 => e.io.damage = true,
            _ => e.io.revoke = Some(e.authority),
        }
        let expected = match fault {
            6 => Error::Readback,
            7 => Error::Revoked,
            _ => Error::Timeout,
        };
        assert_eq!(run(e.prove(&mut irq)), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_faults_keep_all_published_storage_and_close_stop
);
fn jpeg5_cancelled_start_or_proof_retains_backing_and_shared_range() -> TestResult {
    for phase in 0..3 {
        let (pool, mut e, mut irq) = fixture();
        if phase == 0 {
            let mut f = core::pin::pin!(e.start(power()));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            run(e.start(power())).unwrap();
            irq.stall_sample = phase == 1;
            irq.stall_observed = phase == 2;
            let mut f = core::pin::pin!(e.prove(&mut irq));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(
            e.state,
            if phase == 0 {
                State::Starting
            } else {
                State::Testing
            }
        );
        assert_eq!(
            e.wptr,
            match phase {
                0 => 0,
                1 => 16,
                _ => 80,
            }
        );
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_cancelled_start_or_proof_retains_backing_and_shared_range
);
fn jpeg5_retirement_requires_all_dma_clean_bits_and_no_mc_pending() -> TestResult {
    for missing in [1, 2, 4, 8, 0x100, 0x10000, 0] {
        let (pool, mut e, mut irq) = fixture();
        run(e.start(power())).unwrap();
        run(e.prove(&mut irq)).unwrap();
        e.io.regs.insert(
            VCN + u64::from(CLEAN) * 4,
            if missing == 0 {
                0x1011f
            } else {
                0x1010f & !missing
            },
        );
        assert_eq!(run(e.stop()), Err(Error::Timeout));
        assert!(!e.memory.reusable_for_test());
        assert_ne!(e.io.regs[&(VCN + u64::from(DB) * 4)] & (1 << 30), 0);
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_retirement_requires_all_dma_clean_bits_and_no_mc_pending
);
fn jpeg5_rejects_shared_range_policy_or_readback_before_publication() -> TestResult {
    let (_, mut e, _) = fixture();
    e.io.regs.insert(NBIO + u64::from(RANGE) * 4, 0);
    assert_eq!(run(e.start(power())), Err(Error::Busy));
    assert_eq!(e.state, State::Prepared);
    assert!(e.memory.reusable_for_test());
    let (_, mut e, _) = fixture();
    let mut p = power();
    p.enabled = 1 << 20;
    assert_eq!(run(e.start(p)), Err(Error::PowerPolicy(p.enabled)));
    assert!(e.memory.reusable_for_test());
    let (_, mut e, _) = fixture();
    e.io.ignored = Some(VCN + u64::from(CG_CTRL) * 4);
    assert_eq!(run(e.start(power())), Err(Error::Readback));
    assert!(!e.memory.reusable_for_test());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_rejects_shared_range_policy_or_readback_before_publication
);
