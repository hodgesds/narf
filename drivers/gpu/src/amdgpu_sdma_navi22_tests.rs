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
const HDP: u64 = 0x40000;
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
    traps: Vec<u32>,
    /// GPU address of the two translated test pages (the boot aperture).
    base: u64,
}
impl Fake {
    // Minimal independent decoder of the public Navi10 SDMA packet ABI.
    // Every command address must translate into one of the two GMC test pages.
    fn execute(&mut self, end: u32) {
        assert!(!self.dirty, "unflushed command buffer");
        assert_eq!(self.regs[&(GC + 0x81 * 4)], 0x08000040);
        assert_eq!(self.regs[&(GC + 0x82 * 4)], 0);
        assert_eq!(self.regs[&(GC + 0x80 * 4)] & 0x0f80323f, 0x801015);
        let base = self.base;
        let index = |lo: u32, hi: u32| {
            let address = u64::from(lo) | (u64::from(hi) << 32);
            assert!((base..base + 0x2000).contains(&address));
            assert_eq!(address % 4, 0);
            ((address - base) / 4) as usize
        };
        let mut cursor = *self.regs.get(&(GC + 0x83 * 4)).unwrap_or(&0) as usize / 4;
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
                6 => {
                    assert_eq!(self.regs[&(GC + 0x1c * 4)] & 1, 1, "trap disabled");
                    self.traps.push(words[1]);
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
            self.regs.insert(GC + 0x83 * 4, end);
            self.regs.insert(GC + 0x84 * 4, 0);
            self.memory[1024] = end;
        }
    }
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model executes the submitted packets synchronously in
        // write() (the RB_WPTR store), so the IB proof and the trap
        // completion both sample done on the first poll. A wait still
        // incomplete after sixteen polls is a designed non-completion
        // (complete = false) whose outcome is the timeout — reached by
        // count instead of burning the wall-clock deadline under the
        // spin executor (#879).
        Some(16)
    }
    async fn reset_delay(&mut self) {
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
        }
        if address == HDP + 0xd1 * 4 {
            self.invalidated = true;
        }
        if address == GC + 0xda8 * 4 {
            self.progress
                .store(if value == 0 { 2 } else { 1 }, Ordering::SeqCst);
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
        (0x16fc, 0x800),
        (0x16fd, 0xaff),
        (0x25, 1),
        (0x80, 0x80840000),
        (0x1c, 0xc2),
        (0x2a, 1),
        (0x3c, 0xd0000191),
        (0x48, 0x010cec00),
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
            traps: Vec::new(),
            base: 0xb_0000_0000,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: GC,
            nbio: NBIO,
            hdp: HDP,
            // The RX 6750 XT: 12272 MiB, below the 12 GiB FB_LOCATION_TOP.
            vram_size: 12272 << 20,
        },
        memory: pool.reserve(BYTES).unwrap(),
        state: State::Prepared,
        proof: None,
        trapped: false,
    };
    (
        pool,
        engine,
        gmc::Aperture {
            start: 0xb_0000_0000,
            size: 2 << 20,
            source: 0xb_0000_0000,
            destination: 0xb_0000_1000,
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
fn sdma_navi22_executes_translated_packets_and_programs_gc_bank() -> TestResult {
    let (pool, mut engine, aperture, target) = fixture();
    let proof = run(engine.initialize(aperture, target)).unwrap();
    if proof
        != (Proof {
            copied_bytes: 64,
            fence: 0x67500022,
            read_pointer: 128,
        })
        || engine.state != State::Verified
    {
        return TestResult::Fail("SDMA proof missing");
    }
    // Golden GC10.3 offsets: HI and LO for writeback/shadow are reversed,
    // RB_BASE is in 256-byte units, while the ring pointers are byte counts.
    for (reg, value) in [
        (0x81, 0x08000040),
        (0x82, 0),
        (0x88, 8),
        (0x89, 0x5000),
        (0xb2, 8),
        (0xb3, 0x5008),
        (0x80, 0x80841015),
        (0x85, 128),
        (0x86, 0),
        (0x87, 4),
        (0x92, 0),
        (0xb5, 0),
        (0x1c, 0x42),
        (0x2a, 0),
        (0x3c, 0xd0000793),
        (0x48, 0x010cec00),
    ] {
        if engine.io.regs.get(&(GC + reg * 4)).copied() != Some(value) {
            return TestResult::Fail("SDMA register encoding");
        }
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
    "drivers/gpu/sdma-navi22",
    sdma_navi22_executes_translated_packets_and_programs_gc_bank
);
fn sdma_navi22_rejects_live_queues_and_invalid_memory_before_reset() -> TestResult {
    for case in 0..9 {
        let (pool, mut engine, mut aperture, target) = fixture();
        match case {
            0..=3 => {
                engine
                    .io
                    .regs
                    .insert(GC + [0x80, 0xd8, 0x130, 0x188][case] * 4, 1);
            }
            4 => {
                engine.io.regs.insert(GC + 0xda8 * 4, 1);
            }
            5 => {
                // A boot aperture inside the FB aperture.
                aperture.start = 0x8_0020_0000;
                aperture.source = aperture.start;
                aperture.destination = aperture.start + 4096;
            }
            6 => {
                engine.io.regs.insert(GC + 0x16fd * 4, u32::MAX);
            }
            7 => {
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
    "drivers/gpu/sdma-navi22",
    sdma_navi22_rejects_live_queues_and_invalid_memory_before_reset
);
/// Linux puts this board's GART (and so NARF's boot aperture) at MC 0
/// (`GART: 512M 0x0-0x1FFFFFFF`), below the FB, and sdma_v5_2_start
/// soft-resets SDMA without requiring SDMA0_STATUS_REG.IDLE first.
fn sdma_navi22_accepts_linux_gart_aperture_and_busy_engine() -> TestResult {
    let (_pool, mut engine, _, target) = fixture();
    engine.io.regs.insert(GC + 0x25 * 4, 0);
    engine.io.base = 0;
    let aperture = gmc::Aperture {
        start: 0,
        size: 2 << 20,
        source: 0,
        destination: 0x1000,
    };
    if run(engine.initialize(aperture, target)).is_err() || engine.state != State::Verified {
        return TestResult::Fail("Linux GART placement or non-idle SDMA0 refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22",
    sdma_navi22_accepts_linux_gart_aperture_and_busy_engine
);
fn sdma_navi22_cancellation_retains_reset_and_published_ring() -> TestResult {
    for (progress, state) in [
        (1, State::ResetAsserted),
        (2, State::ResetReleased),
        (3, State::Submitted),
    ] {
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
    "drivers/gpu/sdma-navi22",
    sdma_navi22_cancellation_retains_reset_and_published_ring
);
fn sdma_navi22_requires_fence_drain_data_and_live_authority() -> TestResult {
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
                engine.io.revoke = Some((GC + 0xda8 * 4, 1 << 23, engine.authority));
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
    "drivers/gpu/sdma-navi22",
    sdma_navi22_requires_fence_drain_data_and_live_authority
);
fn sdma_navi22_layout_rejects_wrong_versions_and_bank_bounds() -> TestResult {
    for case in 0..7 {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        match case {
            0 => gpu.ip_blocks[3].revision = 1,
            1 => gpu.ip_blocks[0].revision = 1,
            2 => gpu.ip_blocks[5].minor = 2,
            3 => gpu.ip_blocks[4].num_bases = 2,
            4 => gpu.ip_blocks[0].base_addrs[0] = 0x20000 - 0x16fd,
            5 => gpu.ip_blocks.push(gpu.ip_blocks[3]),
            _ => gpu.regs.len = 0x7f000,
        }
        if Layout::resolve(&gpu).is_ok() {
            return TestResult::Fail("unsupported SDMA layout accepted");
        }
    }
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.ip_blocks[0].base_addrs[0] = 0x4000;
    gpu.ip_blocks[3].base_addrs[0] = u32::MAX;
    if Layout::resolve(&gpu).unwrap().gc != 0x10000 {
        return TestResult::Fail("SDMA used standalone IP bank");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22",
    sdma_navi22_layout_rejects_wrong_versions_and_bank_bounds
);
fn sdma_navi22_trap_enables_interrupt_once_after_verified_start() -> TestResult {
    let (pool, mut engine, aperture, target) = fixture();
    if run(engine.trap(0x22)) != Err(Error::Busy) || !engine.io.writes.is_empty() {
        return TestResult::Fail("trap before verified start");
    }
    run(engine.initialize(aperture, target)).unwrap();
    if run(engine.trap(0xf675_0022)) != Ok(())
        || engine.io.traps != [0x0675_0022]
        || engine.io.regs[&(GC + 0x83 * 4)] != 192
        || engine.io.regs[&(GC + 0x1c * 4)] & 1 != 1
        || engine.state != State::Verified
    {
        return TestResult::Fail("trap packet, context mask or enable");
    }
    let count = engine.io.writes.len();
    if run(engine.trap(1)) != Err(Error::Busy) || engine.io.writes.len() != count {
        return TestResult::Fail("trap replayed");
    }
    let (_pool2, mut stalled, aperture, target) = fixture();
    run(stalled.initialize(aperture, target)).unwrap();
    stalled.io.complete = false;
    if run(stalled.trap(1)) != Err(Error::Timeout) || stalled.state != State::Failed {
        return TestResult::Fail("stalled trap accepted");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("ring recycled after trap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22",
    sdma_navi22_trap_enables_interrupt_once_after_verified_start
);

/// amdgpu_gmc_vram_location: the FB aperture ends at fb_start +
/// mc_vram_size (MEMSIZE), not at the inherited FB_LOCATION_TOP. The SDMA
/// buffer must lie inside real VRAM even when TOP claims more.
fn sdma_navi22_fb_end_follows_memsize_not_fb_top() -> TestResult {
    let (_pool, mut engine, aperture, target) = fixture();
    // TOP still says 12 GiB; MEMSIZE covers less than the reserved buffer.
    engine.layout.vram_size = 0x4000;
    if run(engine.initialize(aperture, target)) != Err(Error::Invalid) {
        return TestResult::Fail("buffer beyond MEMSIZE accepted by FB_LOCATION_TOP");
    }
    let (_pool, mut engine, aperture, target) = fixture();
    if run(engine.initialize(aperture, target)).is_err() {
        return TestResult::Fail("12272 MiB VRAM refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22",
    sdma_navi22_fb_end_follows_memsize_not_fb_top
);

fn rdna2_gpu(profile: &crate::amdgpu_rdna2::Profile, did: u16) -> AmdGpu {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, did).unwrap();
    for block in &mut gpu.ip_blocks {
        match block.hw_id {
            ip::HW_ID_GC => {
                (block.major, block.minor, block.revision) = profile.gc_version;
                block.base_addrs[0] = (GC / 4) as u32;
            }
            ip::HW_ID_SDMA0 => {
                (block.major, block.minor, block.revision) = profile.sdma_version;
                block.base_addrs[0] = u32::MAX; // never used: SDMA0 is GC-relative
            }
            ip::HW_ID_NBIF => block.base_addrs[2] = (NBIO / 4) as u32,
            ip::HW_ID_HDP => block.base_addrs[0] = (HDP / 4) as u32,
            _ => {}
        }
    }
    gpu
}

fn rdna2_sdma_exact_layout_precedes_allocation_and_keeps_native_gate() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        for &did in profile.pci_ids {
            let gpu = rdna2_gpu(profile, did);
            let layout = Layout::resolve_rdna2(&gpu).unwrap();
            if layout.gc != GC || layout.nbio != NBIO || layout.hdp != HDP {
                return TestResult::Fail("RDNA2 SDMA used the wrong bank or standalone SDMA base");
            }
            let (pool, engine, _, _) = fixture();
            drop(engine);
            let authority = Cap::bootstrap();
            authority.revoke();
            // SAFETY: inert mapping; constructor must perform no device I/O.
            let sdma = unsafe { Sdma::new_rdna2(&gpu, authority, &pool) }.unwrap();
            if sdma.state() != State::Prepared || sdma.proof().is_some() {
                return TestResult::Fail("RDNA2 SDMA construction started the engine");
            }
            drop(sdma);
            if pool.available() != BYTES {
                return TestResult::Fail("unpublished RDNA2 SDMA ring leaked");
            }
            if did != crate::amdgpu::NAVI22 && Layout::resolve(&gpu).is_ok() {
                return TestResult::Fail("shared SDMA widened the native Navi22 gate");
            }
        }
        for id in [ip::HW_ID_GC, ip::HW_ID_SDMA0, ip::HW_ID_NBIF, ip::HW_ID_HDP] {
            for change in 0..3 {
                let mut gpu = rdna2_gpu(profile, profile.pci_ids[0]);
                let index = gpu.ip_blocks.iter().position(|ip| ip.hw_id == id).unwrap();
                match change {
                    0 => gpu.ip_blocks[index].major = 0xff,
                    1 => gpu.ip_blocks.push(gpu.ip_blocks[index]),
                    _ => {
                        gpu.ip_blocks.remove(index);
                    }
                }
                let (pool, engine, _, _) = fixture();
                drop(engine);
                // SAFETY: invalid metadata must reject before I/O or allocation.
                if unsafe { Sdma::new_rdna2(&gpu, Cap::bootstrap(), &pool) }.is_ok()
                    || pool.available() != BYTES
                {
                    return TestResult::Fail("invalid RDNA2 SDMA bank allocated backing");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_sdma_exact_layout_precedes_allocation_and_keeps_native_gate
);

fn rdna2_sdma_executes_translated_copy_and_fence_with_resolved_layout() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        for bytes in [4 << 30, 8 << 30, 12272 << 20, 12 << 30, 16 << 30] {
            let mut gpu = rdna2_gpu(profile, profile.pci_ids[0]);
            gpu.vram.size = bytes;
            let (_pool, mut engine, mut aperture, target) = fixture();
            engine.layout = Layout::resolve_rdna2(&gpu).unwrap();
            // Deliberately retain the fake's stale FB_LOCATION_TOP. Physical
            // VRAM size determines the end; the translated aperture sits after it.
            aperture.start = (0x8_0000_0000 + bytes).next_multiple_of(2 << 20);
            aperture.source = aperture.start;
            aperture.destination = aperture.start + 4096;
            engine.io.base = aperture.start;
            let proof = run(engine.initialize(aperture, target)).unwrap();
            if proof.copied_bytes != 64
                || proof.fence != SEQUENCE
                || proof.read_pointer != 128
                || engine.state != State::Verified
                || !engine.io.traps.is_empty()
            {
                return TestResult::Fail(
                    "RDNA2 translated SDMA proof failed or enabled interrupts",
                );
            }
            if run(engine.initialize(aperture, target)) != Err(Error::Busy) {
                return TestResult::Fail("RDNA2 SDMA replayed initialization");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_sdma_executes_translated_copy_and_fence_with_resolved_layout
);
