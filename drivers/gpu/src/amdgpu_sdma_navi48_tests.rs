use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const GC: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const HYP: u64 = 0x50000;
const OSS: u64 = 0x70000;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Missing {
    Fence,
    HardwarePointer,
    Writeback,
    Trap,
    Cpu,
}
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u32>,
    target: Vec<u32>,
    dirty: bool,
    invalidated: bool,
    complete: bool,
    corrupt: bool,
    fence_only: bool,
    progress: Arc<AtomicU32>,
    revoke: Option<(u64, u32, Cap<BusDeviceCap, Write>)>,
    signals: Arc<[AtomicU32; 2]>,
    omit: Option<Missing>,
    overshoot: bool,
    /// The engine completes a queue reset request.
    reset_clears: bool,
    fence_revoke: Option<Cap<BusDeviceCap, Write>>,
    fence_gone: bool,
    fence_reads: u32,
}
impl Fake {
    // Minimal independent decoder of the public SDMA6/7 SDMA packet ABI.
    // Every command address must translate into one of the two GMC test pages.
    fn execute(&mut self, end: u32) {
        assert!(!self.dirty, "unflushed command buffer");
        assert_eq!(self.regs[&(GC + 0x81 * 4)], 0x08000040);
        assert_eq!(self.regs[&(GC + 0x82 * 4)], 0);
        assert_eq!(self.regs[&(GC + 0x80 * 4)] & 0x0f803f3f, 0x801815);
        let index = |lo: u32, hi: u32| {
            let address = u64::from(lo) | (u64::from(hi) << 32);
            assert!((0xc_0000_0000..0xc_0000_2000).contains(&address));
            assert_eq!(address % 4, 0);
            ((address - 0xc_0000_0000) / 4) as usize
        };
        let irq = end == 192;
        let mut cursor = self.regs[&(GC + 0x83 * 4)] as usize / 4;
        while cursor < end as usize / 4 {
            let words = &self.memory[cursor..];
            cursor += match words[0] {
                0 => 1,
                2 => {
                    let dst = index(words[1], words[2]);
                    let count = words[3] as usize + 1;
                    self.target[dst..dst + count].copy_from_slice(&words[4..4 + count]);
                    4 + count
                }
                1 => {
                    assert_eq!(words[2], 0);
                    let count = (words[1] as usize + 1) / 4;
                    let src = index(words[3], words[4]);
                    let dst = index(words[5], words[6]);
                    self.target.copy_within(src..src + count, dst);
                    7
                }
                0x30005 => {
                    let dst = index(words[1], words[2]);
                    if !irq || self.omit != Some(Missing::Fence) {
                        self.target[dst] = words[3];
                    }
                    4
                }
                6 => {
                    assert!(irq);
                    assert_eq!(words[1], 0);
                    assert_eq!(self.regs[&(GC + 0x0d * 4)], 0x41);
                    if self.omit != Some(Missing::Trap) {
                        self.signals[0].fetch_add(1, Ordering::SeqCst);
                    }
                    if self.omit != Some(Missing::Cpu) {
                        self.signals[1].fetch_add(1, Ordering::SeqCst);
                    }
                    2
                }
                _ => panic!("incorrect SDMA header"),
            };
        }
        assert_eq!(cursor, end as usize / 4);
        if self.corrupt {
            self.target[1025] ^= 1;
        }
        if !self.fence_only {
            if !irq || self.omit != Some(Missing::HardwarePointer) {
                self.regs.insert(GC + 0x83 * 4, end);
                self.regs.insert(GC + 0x84 * 4, u32::from(self.overshoot));
            }
            if !irq || self.omit != Some(Missing::Writeback) {
                self.memory[1024] = end;
            }
        }
    }
}
impl Io for Fake {
    async fn halt_delay(&mut self) {
        narf_scheduler::yield_now().await;
    }
    fn read(&mut self, address: u64) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        self.regs.insert(address, value);
        if address == 0x7f000 {
            self.dirty = false;
            self.invalidated = true;
        }
        if address == GC + 0x6c * 4 && self.reset_clears {
            self.regs.insert(address, 0);
        }
        if address == HYP + 0x588e * 4 {
            self.progress
                .store(if value & 1 == 0 { 2 } else { 1 }, Ordering::SeqCst);
        }
        if address == GC + 0x85 * 4 && value != 0 {
            self.progress.store(3, Ordering::SeqCst);
            if self.complete {
                self.execute(value);
            }
        }
        if let Some((reg, want, cap)) = self.revoke {
            if reg == address && value == want {
                cap.revoke();
            }
        }
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        assert!(self.invalidated, "stale CPU HDP read");
        if map.phys.raw() == 0x90004000 {
            if offset == JOB_FENCE {
                self.fence_reads += 1;
                if self.fence_gone {
                    self.regs.insert(NBIO + 0xc3 * 4, u32::MAX);
                }
                if let Some(cap) = self.fence_revoke {
                    cap.revoke();
                }
            }
            self.memory[offset as usize / 4]
        } else {
            self.target[offset as usize / 4]
        }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        self.dirty = true;
        if map.phys.raw() == 0x90004000 {
            self.memory[offset as usize / 4] = value;
        } else {
            self.target[offset as usize / 4] = value;
        }
    }
}
fn fixture() -> (Pool, Engine<Fake>, gmc::Aperture, MmioRegion) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake performs every memory access; bookkeeping-only mapping.
    let pool = unsafe { Pool::from_owned_range(map, 0x8_0000_4000) }.unwrap();
    let mut regs = BTreeMap::new();
    for (reg, value) in [
        (0x1614, 0x800),
        (0x1615, 0xbff),
        (0x24, 1),
        (0x80, 0x80840000),
        (0x0d, 0xf0023f79),
        (0x35, 0xd0000191),
        (0x38, 0x010cec00),
    ] {
        regs.insert(GC + reg * 4, value);
    }
    regs.insert(NBIO + 0x12d * 4, 0x7f000);
    let engine = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0xffffffff; 2048],
            target: vec![0xffffffff; 2048],
            dirty: false,
            invalidated: false,
            complete: true,
            corrupt: false,
            fence_only: false,
            progress: Arc::new(AtomicU32::new(0)),
            revoke: None,
            signals: Arc::new([AtomicU32::new(5), AtomicU32::new(7)]),
            omit: None,
            overshoot: false,
            reset_clears: true,
            fence_revoke: None,
            fence_gone: false,
            fence_reads: 0,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: GC,
            nbio: NBIO,
            hyp: HYP,
            oss: OSS,
        },
        memory: pool.reserve(BYTES).unwrap(),
        state: State::Prepared,
        proof: None,
        interrupt_result: None,
        job_wptr: 0,
        job_seq: 0,
    };
    (
        pool,
        engine,
        gmc::Aperture {
            start: 0xc_0000_0000,
            size: 2 << 20,
            source: 0xc_0000_0000,
            destination: 0xc_0000_1000,
        },
        MmioRegion {
            phys: narf_memory::PhysAddr::new(0x90008000),
            ..map
        },
    )
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn sdma_navi48_executes_translated_packets_and_programs_gc_bank() -> TestResult {
    let (pool, mut engine, aperture, target) = fixture();
    let proof = run(engine.initialize(aperture, target)).unwrap();
    if proof
        != (Proof {
            copied_bytes: 64,
            fence: 0x90700048,
            read_pointer: 128,
        })
        || engine.state != State::Verified
    {
        return TestResult::Fail("SDMA proof missing");
    }
    // Golden GC12 offsets: RPTR and WPTR writebacks use the new register map,
    // RB_BASE is in 256-byte units, while the ring pointers are byte counts.
    for (reg, value) in [
        (0x81, 0x08000040),
        (0x82, 0),
        (0x88, 8),
        (0x87, 0x5000),
        (0x99, 8),
        (0x98, 0x5008),
        (0x80, 0x80841815),
        (0x85, 128),
        (0x86, 0),
        (0x89, 1),
        (0x8f, 0),
        (0x9b, 0),
        (0x0d, 0x40),
        (0x35, 0xd0000789),
        (0x38, 0xcec00),
        (0x2b, 1),
    ] {
        if engine.io.regs.get(&(GC + reg * 4)).copied() != Some(value) {
            return TestResult::Fail("SDMA register encoding");
        }
    }
    if engine.io.regs.get(&(HYP + 0x588e * 4)) != Some(&0)
        || engine
            .io
            .writes
            .iter()
            .any(|(a, _)| *a == GC + 0xda8 * 4 || *a == GC + 0x2a * 4 || *a == 0x40000 + 0xd1 * 4)
    {
        return TestResult::Fail("SDMA7 used a legacy MCU/reset/HDP register");
    }
    let count = engine.io.writes.len();
    if run(engine.initialize(aperture, target)) != Err(Error::Busy)
        || engine.io.writes.len() != count
    {
        return TestResult::Fail("SDMA replayed proof");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("live ring backing recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_executes_translated_packets_and_programs_gc_bank
);
fn sdma_navi48_rejects_live_queues_and_invalid_memory_before_halt() -> TestResult {
    for case in 0..13 {
        let (pool, mut engine, mut aperture, target) = fixture();
        match case {
            0..=7 => {
                engine.io.regs.insert(
                    GC + [0x80, 0xd8, 0x130, 0x188, 0x1e0, 0x238, 0x290, 0x2e8][case] * 4,
                    1,
                );
            }
            8 => {
                engine.io.regs.insert(GC + 0xda8 * 4, 1);
            }
            9 => {
                engine.io.regs.insert(GC + 0x24 * 4, 0);
            }
            10 => {
                engine.io.regs.insert(GC + 0x1615 * 4, u32::MAX);
            }
            11 => {
                aperture.destination += 4;
            }
            _ => {
                engine.authority.revoke();
            }
        }
        if run(engine.initialize(aperture, target)).is_ok()
            || !engine.io.writes.is_empty()
            || engine.io.memory[0] != u32::MAX
        {
            return TestResult::Fail("invalid preflight performed writes");
        }
        drop(engine);
        if pool.available() != BYTES {
            return TestResult::Fail("unused ring leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_rejects_live_queues_and_invalid_memory_before_halt
);
fn sdma_navi48_cancellation_retains_halt_and_published_ring() -> TestResult {
    for (progress, state) in [(1, State::Halted), (3, State::Submitted)] {
        let (pool, mut engine, aperture, target) = fixture();
        engine.io.complete = false;
        let observed = engine.io.progress.clone();
        {
            let mut future = core::pin::pin!(engine.initialize(aperture, target));
            let deadline = narf_time::Deadline::after_ms(100);
            loop {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled SDMA completed");
                }
                if observed.load(Ordering::SeqCst) == progress {
                    break;
                }
                if deadline.expired() {
                    return TestResult::Fail("could not reach cancellation stage");
                }
                run(delay(100));
            }
        }
        let count = engine.io.writes.len();
        if engine.state != state
            || run(engine.initialize(aperture, target)) != Err(Error::Busy)
            || engine.io.writes.len() != count
        {
            return TestResult::Fail("cancelled reset/submission replayed");
        }
        drop(engine);
        if pool.available() != 0 {
            return TestResult::Fail("cancelled ring reused");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_cancellation_retains_halt_and_published_ring
);
fn sdma_navi48_requires_fence_drain_data_and_live_authority() -> TestResult {
    for case in 0..5 {
        let (pool, mut engine, aperture, target) = fixture();
        let expected = match case {
            0 => {
                engine.io.corrupt = true;
                Error::DataMismatch
            }
            1 => {
                engine.io.complete = false;
                Error::Timeout
            }
            2 => {
                engine.io.fence_only = true;
                Error::Timeout
            }
            3 => {
                engine.io.revoke = Some((HYP + 0x588e * 4, 1, engine.authority));
                Error::Revoked
            }
            _ => {
                engine.io.revoke = Some((GC + 0x85 * 4, 128, engine.authority));
                Error::Revoked
            }
        };
        if run(engine.initialize(aperture, target)) != Err(expected)
            || engine.state != State::Failed
            || engine.proof.is_some()
        {
            return TestResult::Fail("incomplete/revoked/corrupt proof accepted");
        }
        if case == 3 && engine.io.writes.len() != 1 {
            return TestResult::Fail("reset continued after revocation");
        }
        drop(engine);
        if pool.available() != 0 {
            return TestResult::Fail("failed ring reused");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_requires_fence_drain_data_and_live_authority
);
fn sdma_navi48_layout_rejects_wrong_versions_and_bank_bounds() -> TestResult {
    let descriptor = || {
        let mut regs = vec![0; 0x80000 / 4];
        let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut regs);
        // Metadata-only layout resolution; no MMIO into this expired fixture.
        let mut sdma = gpu.ip_blocks[0];
        sdma.hw_id = ip::HW_ID_SDMA0;
        sdma.major = 7;
        sdma.minor = 0;
        sdma.revision = 1;
        sdma.base_addrs[0] = u32::MAX;
        gpu.ip_blocks.push(sdma);
        // OSSSYS 7.0, for the IH VMID LUT client jobs write.
        let mut oss = gpu.ip_blocks[0];
        oss.hw_id = ip::HW_ID_OSSSYS;
        (oss.major, oss.minor, oss.revision) = (7, 0, 0);
        oss.base_addrs[0] = 0x12000;
        gpu.ip_blocks.push(oss);
        gpu
    };
    for case in 0..8 {
        let mut g = descriptor();
        match case {
            0 => g.ip_blocks[5].revision = 2,
            1 => g.ip_blocks[0].revision = 2,
            2 => g.ip_blocks[0].num_bases = 1,
            3 => g.ip_blocks[2].num_bases = 2,
            4 => g.ip_blocks[0].base_addrs[0] = 0x20000 - 0x1615,
            5 => g.ip_blocks.push(g.ip_blocks[5]),
            6 => g.ip_blocks[0].base_addrs[1] = 0x20000 - 0x588e,
            _ => g.regs.len = 0x7f000,
        }
        if Layout::resolve(&g).is_ok() {
            return TestResult::Fail("unsupported SDMA7 register bank accepted");
        }
    }
    let mut g = descriptor();
    g.ip_blocks[0].base_addrs[1] = 0x14000;
    // Navi44 discovers SDMA 7.0.0 on GC 12.0.0, Navi48 7.0.1 on 12.0.1;
    // both revisions on either GC resolve one layout.
    for (rev, profile) in [0, 1]
        .into_iter()
        .flat_map(|rev| crate::amdgpu_rdna4::tests::Profile::ALL.map(move |p| (rev, p)))
    {
        profile.apply(&mut g);
        g.ip_blocks[5].revision = rev;
        let layout = Layout::resolve(&g).unwrap();
        if layout.gc != GC || layout.hyp != HYP {
            return TestResult::Fail("SDMA7 MCU did not use GC bank one");
        }
        if layout.oss != 0x12000 * 4 {
            return TestResult::Fail("SDMA7 client jobs' OSSSYS bank");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_layout_rejects_wrong_versions_and_bank_bounds
);

struct FakeObserver {
    signals: Arc<[AtomicU32; 2]>,
    msi: bool,
    stall: u8,
    reject: u8,
}
impl FakeObserver {
    fn new(e: &mut Engine<Fake>) -> Self {
        // Independent service owns this write, outside the SDMA engine.
        e.io.regs.insert(GC + 0x0d * 4, 0x41);
        e.io.writes.clear();
        Self {
            signals: e.io.signals.clone(),
            msi: true,
            stall: 0,
            reject: 0,
        }
    }
}
impl Observer for FakeObserver {
    async fn sample(
        &mut self,
        source: Source,
    ) -> Result<crate::amdgpu_navi48_interrupts::Sample, crate::amdgpu_ih7::Error> {
        assert_eq!(source, Source::Sdma0);
        if self.stall == 1 {
            core::future::pending::<()>().await;
        }
        if self.reject == 1 {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        Ok(crate::amdgpu_navi48_interrupts::Sample {
            source,
            count: self.signals[0].load(Ordering::SeqCst).into(),
            cpu: self.signals[1].load(Ordering::SeqCst).into(),
            vector: self.msi.then_some(0x60),
        })
    }
    async fn observed(
        &mut self,
        s: crate::amdgpu_navi48_interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        assert_eq!(s.source, Source::Sdma0);
        if self.stall == 2 {
            core::future::pending::<()>().await;
        }
        if self.reject == 2 {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        Ok(
            u64::from(self.signals[0].load(Ordering::SeqCst)) == s.count + 1
                && (!self.msi || u64::from(self.signals[1].load(Ordering::SeqCst)) != s.cpu),
        )
    }
}
fn sdma_navi48_trap_proof_requires_fresh_fence_drain_and_interrupt() -> TestResult {
    for msi in [false, true] {
        let (pool, mut e, a, map) = fixture();
        let initial = run(e.initialize(a, map)).unwrap();
        let mut o = FakeObserver::new(&mut e);
        o.msi = msi;
        // Old success values cannot substitute for the new submission.
        e.io.target[2045] = 0x90707a48;
        let proof = run(e.prove_interrupts(&mut o, a, map)).unwrap();
        assert_eq!(
            proof,
            InterruptProof {
                fence: 0x90707a48,
                read_pointer: 192,
                msi_verified: msi
            }
        );
        assert_eq!(e.state, State::InterruptVerified);
        assert_eq!(e.interrupt_result, Some(Ok(proof)));
        assert_eq!(e.proof, Some(initial));
        assert_eq!(
            &e.io.memory[32..48],
            &[0x30005, 0x1ff4, 0xc, 0x90707a48, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(e.io.target[2047], 0x90700048);
        assert_eq!(e.io.memory[1026], 192);
        assert!(!e.io.writes.iter().any(|&(at, _)| at == GC + 0x0d * 4));
        assert_eq!(run(e.prove_interrupts(&mut o, a, map)), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_trap_proof_requires_fresh_fence_drain_and_interrupt
);

fn sdma_navi48_trap_missing_evidence_faults_and_revocation_prevent_success() -> TestResult {
    for case in 0..10 {
        let (pool, mut e, a, map) = fixture();
        run(e.initialize(a, map)).unwrap();
        let mut o = FakeObserver::new(&mut e);
        // Fence omission must fail even when the page held the right value.
        e.io.target[2045] = 0x90707a48;
        let expected = match case {
            0..=4 => {
                e.io.omit = Some(
                    [
                        Missing::Fence,
                        Missing::HardwarePointer,
                        Missing::Writeback,
                        Missing::Trap,
                        Missing::Cpu,
                    ][case],
                );
                Error::Timeout
            }
            5 => {
                e.io.overshoot = true;
                Error::DataMismatch
            }
            6 => {
                e.io.revoke = Some((GC + 0x85 * 4, 192, e.authority));
                Error::Revoked
            }
            7 => {
                e.authority.revoke();
                Error::Revoked
            }
            _ => {
                o.reject = if case == 8 { 1 } else { 2 };
                Error::Interrupts(crate::amdgpu_ih7::Error::Protocol)
            }
        };
        assert_eq!(run(e.prove_interrupts(&mut o, a, map)), Err(expected));
        assert_eq!(e.state, State::Failed);
        assert_eq!(e.interrupt_result, Some(Err(expected)));
        assert!(e.proof.is_some());
        assert_eq!(run(e.prove_interrupts(&mut o, a, map)), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_trap_missing_evidence_faults_and_revocation_prevent_success
);

fn sdma_navi48_trap_preflight_rejects_wrong_aperture_and_ring_state() -> TestResult {
    for case in 0..11 {
        let (_, mut e, mut a, mut map) = fixture();
        run(e.initialize(a, map)).unwrap();
        let mut o = FakeObserver::new(&mut e);
        let expected = match case {
            0 => {
                a.start = u64::MAX;
                Error::Invalid
            }
            1 => {
                a.destination += 4096;
                Error::Invalid
            }
            2 => {
                a.size = 4096;
                Error::Invalid
            }
            3 => {
                map.len = 4096;
                Error::Invalid
            }
            4 => {
                a.start += 2 << 20;
                a.source = a.start;
                a.destination = a.start + 4096;
                Error::Invalid
            }
            5 => {
                e.io.regs.insert(GC + 0x0d * 4, 0x40);
                Error::Busy
            }
            6 => {
                e.io.regs.insert(GC + 0x80 * 4, 0);
                Error::Busy
            }
            7 => {
                e.io.regs.insert(GC + 0x85 * 4, 192);
                Error::Busy
            }
            8 => {
                e.io.regs.insert(GC + 0x84 * 4, 1);
                Error::Busy
            }
            9 => {
                e.io.memory[1025] = 1;
                Error::Busy
            }
            _ => {
                e.io.memory[1027] = 1;
                Error::Busy
            }
        };
        assert_eq!(run(e.prove_interrupts(&mut o, a, map)), Err(expected));
        assert!(!e
            .io
            .writes
            .iter()
            .any(|&(at, v)| at == GC + 0x85 * 4 && v == 192));
        assert_eq!(e.io.memory[32], 0);
        assert_eq!(e.io.target[2045], 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_trap_preflight_rejects_wrong_aperture_and_ring_state
);

fn sdma_navi48_trap_cancellation_quarantines_before_and_after_submission() -> TestResult {
    for stall in [1, 2] {
        let (pool, mut e, a, map) = fixture();
        run(e.initialize(a, map)).unwrap();
        let mut o = FakeObserver::new(&mut e);
        o.stall = stall;
        {
            let mut f = core::pin::pin!(e.prove_interrupts(&mut o, a, map));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.state, State::InterruptSubmitted);
        assert_eq!(e.interrupt_result, None);
        assert_eq!(e.io.memory[1026], if stall == 1 { 128 } else { 192 });
        assert_eq!(run(e.prove_interrupts(&mut o, a, map)), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_trap_cancellation_quarantines_before_and_after_submission
);

/// Every word of a client job's frame, against sdma_v7_0's ring functions:
/// pipeline sync, GFX hub flush through engine 11, LUT write, IBs padded so
/// each INDIRECT ends on an 8-dword boundary, and an uncached fence.
fn sdma_navi48_client_job_frame_matches_linux() -> TestResult {
    use crate::amdgpu_gfx12_queue::Job;
    let gc = (GC / 4) as u32;
    let oss = (OSS / 4) as u32;
    let fence = 0x8_0000_5040;
    let job = Job::new(
        3,
        0x42,
        0x1_0000_8001,
        &[(0x2_0000_1000, 64), (0x2_0000_2020, 8)],
    )
    .unwrap();
    let nbio = (NBIO / 4) as u32;
    let Ok(words) = job_words(&job, gc, oss, nbio, fence, 7) else {
        return TestResult::Fail("frame refused");
    };
    let mut want = vec![
        // Pipeline sync: memory poll, equal, until the fence reads 6.
        0x8000_0008 | 3 << 28,
        0x0000_5040,
        8,
        6,
        !0,
        0x0fff_0004,
        // Context 3's page-table base (0x168f/0x1690 + 2 * 3).
        14,
        (gc + 0x168f + 6) << 2,
        0x8001,
        14,
        (gc + 0x1690 + 6) << 2,
        1,
        // Engine 11's request, then its ACK for VMID 3.
        14,
        (gc + 0x1647 + 11) << 2,
        1 << 3 | 0x1f << 19,
        8 | 3 << 28,
        (gc + 0x1659 + 11) << 2,
        0,
        8,
        8,
        0x0fff_000a,
        // IH_VMID_0_LUT + 3.
        14,
        (oss + 3) << 2,
        0x42,
    ];
    // HDP flush: write REQ, wait on DONE, independent of VMID flushing.
    let hdp = [
        0x3400_0008,
        NBIO as u32 + 0x41c,
        NBIO as u32 + 0x418,
        0x400,
        0x400,
        0x0fff_000a,
    ];
    want.extend(hdp);
    // 30 dwords so far: four NOPs end the first INDIRECT at 40.
    want.extend([0; 4]);
    want.extend([4 | 3 << 16, 0x0000_1000, 2, 64, 0, 0]);
    // The second starts at 40: two NOPs, ending it at 48.
    want.extend([0; 2]);
    want.extend([4 | 3 << 16, 0x0000_2020, 2, 8, 0, 0]);
    want.extend([0x30005, 0x0000_5040, 8, 7]);
    if words[..want.len()] != want[..] || words[want.len()..].iter().any(|&w| w != 0) {
        return TestResult::Fail("client job frame");
    }
    // A reused VMID still flushes HDP; its IB is 8-dword aligned.
    let quiet = Job {
        flush: false,
        map_pasid: false,
        ..Job::new(3, 0x42, 0, &[(0x2_0000_1000, 64)]).unwrap()
    };
    let words = job_words(&quiet, gc, oss, nbio, fence, 7).unwrap();
    if words[..6] != hdp
        || words[6..10] != [0; 4]
        || words[10..20] != [4 | 3 << 16, 0x1000, 2, 64, 0, 0, 0x30005, 0x5040, 8, 7]
    {
        return TestResult::Fail("reused VMID frame");
    }
    // A memory sync: GCR_REQ, HDP flush, then NOPs aligning the INDIRECT.
    let synced = Job {
        mem_sync: true,
        ..quiet
    };
    let words = job_words(&synced, gc, oss, nbio, fence, 7).unwrap();
    if words[..5] != [17, 0, 0xc3a1_0000, 0, 0]
        || words[5..11] != hdp
        || words[11..18] != [0; 7]
        || words[18] != 4 | 3 << 16
    {
        return TestResult::Fail("memory sync frame");
    }
    for bad in [
        Job::new(0, 1, 0, &[(0x1000, 4)]).unwrap(),
        Job::new(3, 1, 0, &[(0x1010, 4)]).unwrap(),
        Job::new(3, 1, 0, &[(0x1000, 0)]).unwrap(),
        Job::new(3, 1, 0, &[(0x1000, 0x10_0000)]).unwrap(),
    ] {
        if job_words(&bad, gc, oss, nbio, fence, 1).is_ok() {
            return TestResult::Fail("bad job accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_sdma_navi48",
    sdma_navi48_client_job_frame_matches_linux
);

/// Client jobs fill 256-dword slots after the proofs' 48 dwords (the first
/// pads with NOPs), advance both byte pointers, refuse a job that would
/// overrun the CP's read pointer, and report the fence.
fn sdma_navi48_client_jobs_fill_the_ring() -> TestResult {
    use crate::amdgpu_gfx12_queue::Job;
    let (_pool, mut e, _aperture, _target) = fixture();
    let job = Job::new(2, 9, 0x1_0000_8001, &[(0x2_0000_1000, 16)]).unwrap();
    if e.submit(job) != Err(Error::Busy) {
        return TestResult::Fail("job before the proofs");
    }
    // As the interrupt proof leaves the ring: 192 bytes read and written.
    e.state = State::InterruptVerified;
    e.io.complete = false;
    e.io.memory.fill(0x5a5a_5a5a);
    e.io.memory[1024..1028].copy_from_slice(&[192, 0, 192, 0]);
    e.io.memory[(JOB_FENCE / 4) as usize] = 0;
    if e.submit(job) != Ok(1) {
        return TestResult::Fail("first job");
    }
    let want = job_words(
        &job,
        (GC / 4) as u32,
        (OSS / 4) as u32,
        (NBIO / 4) as u32,
        0x8_0000_4000 + JOB_FENCE,
        1,
    )
    .unwrap();
    if e.io.memory[48..256].iter().any(|&w| w != 0)
        || e.io.memory[256..512] != want[..]
        || e.io.memory[1026..1028] != [2048, 0]
        || e.io.regs[&(GC + 0x85 * 4)] != 2048
        || e.io.regs[&(GC + 0x86 * 4)] != 0
        || e.io.dirty
    {
        return TestResult::Fail("first job's slot and pointers");
    }
    // Slots at 512 and 768 fit beside the unread 48..1024; a fourth would
    // overwrite dwords the engine has not read.
    for seq in 2..=3 {
        if e.submit(job) != Ok(seq) {
            return TestResult::Fail("filling the ring");
        }
    }
    if e.submit(job) != Err(Error::Busy)
        || e.io.memory[1026] != 4096
        || e.io.regs[&(GC + 0x85 * 4)] != 4096
    {
        return TestResult::Fail("overrun refused without moving a pointer");
    }
    // The engine catches up: the next job wraps to slot 0.
    e.io.memory[1024] = 4096;
    e.io.memory[(JOB_FENCE / 4) as usize] = 3;
    if e.completed_job() != Ok(3) || e.submit(job) != Ok(4) || e.io.memory[1026] != 5120 {
        return TestResult::Fail("wrapped job");
    }
    if e.io.memory[..256]
        != job_words(
            &job,
            (GC / 4) as u32,
            (OSS / 4) as u32,
            (NBIO / 4) as u32,
            0x8_0000_4000 + JOB_FENCE,
            4,
        )
        .unwrap()[..]
    {
        return TestResult::Fail("wrapped slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_sdma_navi48",
    sdma_navi48_client_jobs_fill_the_ring
);

/// Kernel jobs as sdma_v7_0_emit_fill_buffer / emit_copy_buffer write them:
/// CONSTANT_FILL with COMPRESS and COPY_LINEAR with CPV, split at 1 GiB,
/// then the fence; empty, misaligned, overlapping or oversized jobs are
/// refused, and a kernel job takes the next slot and sequence.
fn sdma_navi48_kernel_jobs_fill_and_copy() -> TestResult {
    let fence = 0x8_0000_5040;
    let ops = [
        KernelOp::Fill {
            dst: 0x8_1000_0000,
            bytes: 4096,
            value: 0,
        },
        KernelOp::Copy {
            src: 0x8_0000_0000,
            dst: 0x9_0000_0000,
            bytes: (1 << 30) + 8,
        },
    ];
    let Ok(words) = kernel_words(&ops, fence, 9) else {
        return TestResult::Fail("kernel frame refused");
    };
    let want = [
        11 | 1 << 16,
        0x1000_0000,
        8,
        0,
        4095,
        1 | 1 << 19,
        (1 << 30) - 1,
        0,
        0,
        8,
        0,
        9,
        0,
        1 | 1 << 19,
        7,
        0,
        0x4000_0000,
        8,
        0x4000_0000,
        9,
        0,
        0x30005,
        0x5040,
        8,
        9,
    ];
    if words[..want.len()] != want || words[want.len()..].iter().any(|&w| w != 0) {
        return TestResult::Fail("kernel frame words");
    }
    let fill = |dst, bytes| KernelOp::Fill {
        dst,
        bytes,
        value: 0,
    };
    for bad in [
        &[][..],
        &[fill(0x1000, 0)],
        &[fill(0x1002, 4)],
        &[fill(0x1000, 6)],
        &[KernelOp::Copy {
            src: 0x1000,
            dst: 0x1800,
            bytes: 0x1000,
        }],
        &[fill(0x1000, 4); 51],
    ] {
        if kernel_words(bad, fence, 1).is_ok() {
            return TestResult::Fail("bad kernel job accepted");
        }
    }
    // Shares the ring with client jobs.
    let (_pool, mut e, _aperture, _target) = fixture();
    if e.submit_kernel(&ops) != Err(Error::Busy) {
        return TestResult::Fail("kernel job before the proofs");
    }
    e.state = State::InterruptVerified;
    e.io.complete = false;
    e.io.memory.fill(0);
    e.io.memory[1024..1028].copy_from_slice(&[192, 0, 192, 0]);
    if e.submit_kernel(&ops) != Ok(1)
        || e.io.memory[256..256 + 21] != want[..21]
        || e.io.memory[256 + 21..256 + 25] != [0x30005, 0x5040, 8, 1]
    {
        return TestResult::Fail("kernel job in the ring");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_sdma_navi48",
    sdma_navi48_kernel_jobs_fill_and_copy
);

/// sdma_v7_0_reset_queue: SDMA0_QUEUE_RESET_REQ until the engine clears it,
/// then the ring programmed again with both pointers (and their
/// writebacks) at the software write pointer, enabled and unhalted; the
/// ring test is a fence-only slot past the skipped ones. A request the
/// engine never completes fails the reset.
fn sdma_navi48_reset_resumes_past_the_queued_slots() -> TestResult {
    use crate::amdgpu_gfx12_queue::Job;
    let (_pool, mut e, _aperture, _target) = fixture();
    if run(e.reset_ring()) != Err(Error::Busy) {
        return TestResult::Fail("reset before the proofs");
    }
    e.state = State::InterruptVerified;
    e.io.complete = false;
    e.io.memory.fill(0);
    e.io.memory[1024..1028].copy_from_slice(&[192, 0, 192, 0]);
    let job = Job::new(2, 9, 0x1_0000_8001, &[(0x2_0000_1000, 16)]).unwrap();
    if e.submit(job) != Ok(1) {
        return TestResult::Fail("hung job");
    }
    e.io.writes.clear();
    if run(e.reset_ring()) != Ok(()) {
        return TestResult::Fail("reset");
    }
    let reg = |e: &Engine<Fake>, r: u64| e.io.regs[&(GC + r * 4)];
    if e.io.writes.first() != Some(&(GC + 0x6c * 4, 1))
        || [0x83, 0x84, 0x85, 0x86].map(|r| reg(&e, r)) != [2048, 0, 2048, 0]
        || e.io.memory[1024..1028] != [2048, 0, 2048, 0]
        || reg(&e, 0x80) & 1 != 1
        || reg(&e, 0x89) & 1 != 1
        || e.io.regs[&(HYP + 0x588e * 4)] & 3 != 0
        || reg(&e, 0x9b) != 0
    {
        return TestResult::Fail("ring programmed past the skipped slot");
    }
    let fence = 0x8_0000_4000 + JOB_FENCE;
    if e.submit_fence() != Ok(2)
        || e.io.memory[512..516] != [0x30005, fence as u32, (fence >> 32) as u32, 2]
        || e.io.memory[516..768].iter().any(|&w| w != 0)
        || reg(&e, 0x85) != 3072
    {
        return TestResult::Fail("ring test slot");
    }
    e.io.reset_clears = false;
    e.io.regs.insert(GC + 0x6c * 4, 0);
    if run(e.reset_ring()) != Err(Error::Timeout) {
        return TestResult::Fail("a reset the engine never completes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_sdma_navi48",
    sdma_navi48_reset_resumes_past_the_queued_slots
);

fn sdma_navi48_client_fences_reject_device_loss_and_revocation() -> TestResult {
    for case in 0..5 {
        let (pool, mut e, aperture, target) = fixture();
        run(e.initialize(aperture, target)).unwrap();
        let available = pool.available();
        e.io.memory[(JOB_FENCE / 4) as usize] = u32::MAX;
        e.io.fence_reads = 0;
        match case {
            1 => {
                e.io.regs.insert(NBIO + 0xc3 * 4, u32::MAX);
            }
            2 => e.io.fence_gone = true,
            3 => {
                e.authority.revoke();
            }
            4 => e.io.fence_revoke = Some(e.authority),
            _ => {}
        }
        let expected = match case {
            0 => Ok(u32::MAX),
            1 | 2 => Err(Error::DeviceGone),
            _ => Err(Error::Revoked),
        };
        assert_eq!(e.completed_job(), expected);
        assert_eq!(e.io.fence_reads, u32::from(!matches!(case, 1 | 3)));
        assert!(!e.memory.reusable_for_test());
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_sdma_navi48",
    sdma_navi48_client_fences_reject_device_loss_and_revocation
);
