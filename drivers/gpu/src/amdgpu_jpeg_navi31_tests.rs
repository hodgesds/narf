use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{future::Future, sync::atomic::AtomicU32};
use narf_kernel_test::{kernel_test_in, TestResult};
const VCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const GC: u64 = 0x50000;
const GPU: u64 = 0x8_0000_4000;

struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u8>,
    doorbells: Vec<(u32, u32)>,
    delays: Arc<AtomicU32>,
    advance: bool,
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
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        self.regs.insert(at, value);
        // PGFSM model for the JPEG UVDJ field: power-on waits for 0,
        // power-off waits for 2<<0x16.
        if at == VCN + u64::from(PGFSM_CONFIG) * 4 {
            let status = match value {
                0x400000 => 0,
                0x800000 => 0x800000,
                _ => return,
            };
            self.regs.insert(VCN + u64::from(PGFSM_STATUS) * 4, status);
        }
    }
    fn memory_read(&mut self, _map: MmioRegion, at: u64) -> u32 {
        self.word(at)
    }
    fn memory_write(&mut self, _map: MmioRegion, at: u64, value: u32) {
        assert!(at < BYTES && at % 4 == 0);
        self.store(at, value);
    }
    fn memory_read8(&mut self, _map: MmioRegion, at: u64) -> u8 {
        self.memory[at as usize]
    }
    fn memory_write8(&mut self, _map: MmioRegion, at: u64, value: u8) {
        self.memory[at as usize] = value;
    }
    fn doorbell(&mut self, at: u32, value: u32) {
        assert_eq!(at, DOORBELL);
        assert_eq!(
            self.regs[&(NBIO + u64::from(NBIO_RANGE) * 4)] & NBIO_RANGE_MASK,
            NBIO_RANGE_VALUE
        );
        assert_eq!(
            self.regs[&(VCN + u64::from(DB_CTRL) * 4)] & 0x4fff_fffc,
            0x4000_0c44
        );
        self.doorbells.push((at, value));
        self.regs.insert(VCN + u64::from(WPTR) * 4, value);
        if self.advance {
            self.regs.insert(VCN + u64::from(RPTR) * 4, value);
        }
    }
    async fn delay(&mut self, _: u64) {
        self.delays.fetch_add(1, Ordering::SeqCst);
        narf_scheduler::yield_now().await;
    }
}
fn fixture(pg: bool, mgcg: bool) -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_4000),
        virt: 0,
        len: BYTES * 2,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts memory I/O; mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let regs = BTreeMap::from([
        (NBIO + u64::from(NBIO_RANGE) * 4, NBIO_RANGE_VALUE),
        (VCN + u64::from(CGC_GATE) * 4, CGC_GATE_ALL),
        (VCN + u64::from(CGC_CTRL) * 4, CGC_CTRL_DEC_MODE),
        (GC + 0x13de * 4, 0x545),
    ]);
    let e = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0x5a; BYTES as usize],
            doorbells: Vec::new(),
            delays: Arc::new(AtomicU32::new(0)),
            advance: true,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            vcn: VCN,
            nbio: NBIO,
            gc: GC,
        },
        memory: pool.reserve(BYTES).unwrap(),
        pg,
        mgcg,
        state: State::Prepared,
        addr_config: None,
        seq: 0,
        wptr: 0,
    };
    (pool, e)
}
fn run<T>(future: impl Future<Output = T>) -> T {
    // Boxed: block_on_spin holds its future by value, and the largest of
    // these engine futures put block_on_inner past the kernel frame budget
    // in some builds and under it in others (the budget counts that generic
    // frame whatever calls it).
    narf_scheduler::block_on_spin(alloc::boxed::Box::pin(future))
}
fn descriptor() -> AmdGpu {
    let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    gpu.regs.len = 0x80000;
    gpu.ip_blocks.clear();
    for (id, version, bases) in [
        (ip::HW_ID_VCN, (4, 0, 0), [0, 0x4000, 0]),
        (ip::HW_ID_NBIF, (7, 0, 0), [0, 0, 0xc000]),
        (ip::HW_ID_GC, (11, 0, 0), [0x10000, 0, 0]),
    ] {
        let mut b = [0; ip::MAX_BASE_ADDRS];
        b[..3].copy_from_slice(&bases);
        gpu.ip_blocks.push(ip::IpBlock {
            hw_id: id,
            instance: 0,
            major: version.0,
            minor: version.1,
            revision: version.2,
            sub_revision: 0,
            variant: 0,
            num_bases: 3,
            base_addrs: b,
        });
    }
    gpu
}

fn jpeg4_layout_resolves_navi31_banks_and_rejects_wrong_versions() -> TestResult {
    let gpu = descriptor();
    let layout = match Layout::resolve(&gpu) {
        Ok(layout) => layout,
        Err(_) => return TestResult::Fail("resolve failed on Navi31 descriptor"),
    };
    if layout.vcn != 0x10000 || layout.nbio != 0x30000 || layout.gc != 0x40000 {
        return TestResult::Fail("resolved banks do not match the descriptor");
    }
    let mut bad = descriptor();
    bad.ip_blocks[0].revision = 3;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("VCN 4.0.3 accepted");
    }
    let mut bad = descriptor();
    bad.ip_blocks[1].major = 6;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("NBIF 6 accepted");
    }
    let mut bad = descriptor();
    bad.ip_blocks[2].major = 12;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("GC 12 accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi31",
    jpeg4_layout_resolves_navi31_banks_and_rejects_wrong_versions
);

fn jpeg4_start_programs_jrbc_ring() -> TestResult {
    let (_pool, mut e) = fixture(true, false);
    if run(e.start()) != Ok(()) || e.state != State::Ready {
        return TestResult::Fail("start did not reach Ready");
    }
    if !e
        .io
        .writes
        .contains(&(VCN + u64::from(PGFSM_CONFIG) * 4, 1 << PGFSM_UVDJ_SHIFT))
    {
        return TestResult::Fail("JPEG PGFSM power-on not written");
    }
    if e.reg(JPEG_POWER_STATUS) != Ok(0)
        || e.reg(CGC_GATE) != Ok(0)
        || e.reg(CGC_CTRL) != Ok(CGC_CTRL_TIMERS | CGC_CTRL_DEC_MODE)
        || e.reg(ADDR_CONFIG) != Ok(0x545)
        || e.reg(JMI) != Ok(0)
        || e.reg(SYS_INT_EN) != Ok(SYS_INT_DJRBC)
        || e.reg(VMID) != Ok(0)
        || e.reg(CNTL) != Ok(0x2)
        || e.reg(BASE_LO) != Ok((GPU + RING) as u32)
        || e.reg(BASE_HI) != Ok(((GPU + RING) >> 32) as u32)
        || e.reg(RPTR) != Ok(0)
        || e.reg(SIZE) != Ok(RING_SIZE_DW)
        || e.reg(DB_CTRL) != Ok(0x4000_0c44)
    {
        return TestResult::Fail("JRBC ring, power or clock state is wrong");
    }
    // CNTL is written 0x3 (reset) before the ring base, then 0x2 (run).
    let cntl: Vec<usize> =
        e.io.writes
            .iter()
            .enumerate()
            .filter(|(_, w)| w.0 == VCN + u64::from(CNTL) * 4)
            .map(|(i, _)| i)
            .collect();
    if cntl.len() != 2 || e.io.writes[cntl[0]].1 != 0x3 || e.io.writes[cntl[1]].1 != 0x2 {
        return TestResult::Fail("JRBC CNTL sequence is not 0x3 then 0x2");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/jpeg-navi31", jpeg4_start_programs_jrbc_ring);

fn jpeg4_start_mgcg_sets_dyn_and_clears_dec_mode() -> TestResult {
    let (_pool, mut e) = fixture(true, true);
    if run(e.start()) != Ok(()) {
        return TestResult::Fail("MGCG start failed");
    }
    let ctrl = e.reg(CGC_CTRL).unwrap_or(u32::MAX);
    if ctrl & CGC_CTRL_DYN == 0 || ctrl & CGC_CTRL_DEC_MODE != 0 {
        return TestResult::Fail("MGCG clock gating did not set DYN and clear DEC_MODE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi31",
    jpeg4_start_mgcg_sets_dyn_and_clears_dec_mode
);

fn jpeg4_start_no_pg_skips_pgfsm() -> TestResult {
    let (_pool, mut e) = fixture(false, false);
    if run(e.start()) != Ok(()) || e.state != State::Ready {
        return TestResult::Fail("non-PG start did not reach Ready");
    }
    if e.io
        .writes
        .iter()
        .any(|w| w.0 == VCN + u64::from(PGFSM_CONFIG) * 4)
    {
        return TestResult::Fail("PGFSM written without PG support");
    }
    if e.reg(JPEG_POWER_STATUS) != Ok(0) {
        return TestResult::Fail("JPEG power status not cleared");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/jpeg-navi31", jpeg4_start_no_pg_skips_pgfsm);

fn jpeg4_start_rejects_unprogrammed_range() -> TestResult {
    let (_pool, mut e) = fixture(true, false);
    e.io.regs.insert(NBIO + u64::from(NBIO_RANGE) * 4, 0);
    if run(e.start()) != Err(Error::Busy) {
        return TestResult::Fail("unprogrammed NBIO range accepted");
    }
    let (_pool, mut e) = fixture(true, false);
    e.io.regs.insert(VCN + u64::from(DB_CTRL) * 4, 1 << 30);
    if run(e.start()) != Err(Error::Busy) {
        return TestResult::Fail("live JPEG doorbell accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi31",
    jpeg4_start_rejects_unprogrammed_range
);

fn jpeg4_prove_advances_ring() -> TestResult {
    let (_pool, mut e) = fixture(true, false);
    if run(e.start()) != Ok(()) {
        return TestResult::Fail("start failed");
    }
    match run(e.prove()) {
        Ok(proof) if proof.sequence == 1 && proof.read_pointer == 16 => {}
        _ => return TestResult::Fail("ring proof did not complete at wptr 16"),
    }
    if e.state != State::Verified || e.io.doorbells != vec![(DOORBELL, 16)] {
        return TestResult::Fail("prove did not verify or ring the doorbell once");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/jpeg-navi31", jpeg4_prove_advances_ring);

fn jpeg4_stop_resets_jmi_and_reenables_power_gating() -> TestResult {
    let (_pool, mut e) = fixture(true, false);
    if run(e.start()) != Ok(()) || run(e.prove()).is_err() {
        return TestResult::Fail("start/prove failed");
    }
    if run(e.stop()) != Ok(()) || e.state != State::Stopped {
        return TestResult::Fail("stop did not reach Stopped");
    }
    if e.reg(JMI) != Ok(JMI_SOFT_RESET)
        || e.reg(CGC_GATE) != Ok(CGC_GATE_ALL)
        || e.reg(JPEG_POWER_STATUS) != Ok(JPEG_POWER_MASK)
        || !e
            .io
            .writes
            .contains(&(VCN + u64::from(PGFSM_CONFIG) * 4, 2 << PGFSM_UVDJ_SHIFT))
    {
        return TestResult::Fail("stop left JMI, clock gating or power gating wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi31",
    jpeg4_stop_resets_jmi_and_reenables_power_gating
);

fn jpeg4_new_rejects_short_doorbells() -> TestResult {
    let gpu = descriptor();
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_4000),
        virt: 0,
        len: BYTES * 2,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts memory I/O; mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let short = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: (u64::from(DOORBELL)) * 4,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: cold owner on the descriptor; no live hardware.
    let short_new = unsafe { Jpeg::new(&gpu, Cap::bootstrap(), &pool, short, true, false) };
    if !matches!(short_new, Err(Error::Invalid)) {
        return TestResult::Fail("short doorbell BAR accepted");
    }
    let doorbells = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: (u64::from(DOORBELL) + 1) * 4,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: cold owner on the descriptor; no live hardware.
    if unsafe { Jpeg::new(&gpu, Cap::bootstrap(), &pool, doorbells, true, false) }.is_err() {
        return TestResult::Fail("valid Jpeg::new rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/jpeg-navi31", jpeg4_new_rejects_short_doorbells);
