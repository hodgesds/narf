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
        let mut cursor = 0;
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
                    self.target[dst] = words[3];
                    4
                }
                _ => panic!("incorrect SDMA header"),
            };
        }
        assert_eq!(cursor, end as usize / 4);
        if self.corrupt {
            self.target[1025] ^= 1;
        }
        if !self.fence_only {
            self.regs.insert(GC + 0x83 * 4, end);
            self.regs.insert(GC + 0x84 * 4, 0);
            self.memory[1024] = end;
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
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: GC,
            nbio: NBIO,
            hyp: HYP,
        },
        memory: pool.reserve(BYTES).unwrap(),
        state: State::Prepared,
        proof: None,
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
        (0x89, 0),
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
        gpu
    };
    for case in 0..8 {
        let mut g = descriptor();
        match case {
            0 => g.ip_blocks[5].revision = 2,
            1 => g.ip_blocks[0].revision = 0,
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
    for rev in [0, 1] {
        g.ip_blocks[5].revision = rev;
        let layout = Layout::resolve(&g).unwrap();
        if layout.gc != GC || layout.hyp != HYP {
            return TestResult::Fail("SDMA7 MCU did not use GC bank one");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi48",
    sdma_navi48_layout_rejects_wrong_versions_and_bank_bounds
);
