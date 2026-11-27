use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{future::Future, sync::atomic::AtomicU32};
use narf_kernel_test::{kernel_test_in, TestResult};
const VCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const GC: u64 = 0x50000;
const GPU: u64 = 0x8_0000_4000;
const IMAGE: u64 = 0x8_1000_0000;

struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u8>,
    doorbells: Vec<(u32, u32)>,
    delays: Arc<AtomicU32>,
    boot: bool,
    advance: bool,
    fence: bool,
    traps: u32,
}
struct FakeSram {
    words: Vec<u32>,
    fail: bool,
}
impl Sram for FakeSram {
    async fn load(&mut self, words: &[u32]) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Sram(crate::amdgpu_psp_ring::Error::Unsupported));
        }
        self.words = words.to_vec();
        Ok(())
    }
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
        // PGFSM model: the status follows the config the engine wrote.
        if at == VCN + u64::from(PGFSM_CONFIG) * 4 {
            let status = match value {
                PGFSM_CONFIG_PG_ON => PGFSM_STATUS_PG_ON,
                PGFSM_CONFIG_ALL_ONE => 0,
                PGFSM_CONFIG_ALL_TWO => PGFSM_CONFIG_ALL_TWO,
                _ => return,
            };
            self.regs.insert(VCN + u64::from(PGFSM_STATUS) * 4, status);
        }
        // DPG pause model: ACK follows REQ; power status drops to the
        // PGFSM power-on value while paused, then back to 1 on delay.
        if at == VCN + u64::from(DPG_PAUSE) * 4 {
            self.regs.insert(
                at,
                (value & !DPG_PAUSE_ACK)
                    | if value & DPG_PAUSE_REQ != 0 {
                        DPG_PAUSE_ACK
                    } else {
                        0
                    },
            );
            let power = self.regs[&(VCN + u64::from(POWER_STATUS) * 4)];
            self.regs.insert(
                VCN + u64::from(POWER_STATUS) * 4,
                (power & !POWER_STATUS_MASK) | if value & DPG_PAUSE_REQ != 0 { 0x2 } else { 0x1 },
            );
        }
        // VCPU release boots the firmware: STATUS goes idle and the
        // firmware writes queue_status next to the CPU's queue_mode.
        if at == VCN + u64::from(VCPU) * 4 && value & VCPU_RESET == 0 && self.boot {
            self.regs.insert(VCN + u64::from(STATUS) * 4, 6);
            self.memory[SHARED as usize + 18] = 0xa5;
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
            0x4000_0c48
        );
        assert_eq!(self.regs[&(VCN + u64::from(RB_ENABLE) * 4)] & ALL_RBS, RB1);
        self.doorbells.push((at, value));
        // Hardware tracks the last doorbell value in WPTR.
        self.regs.insert(VCN + u64::from(WPTR) * 4, value);
        if !self.fence {
            return;
        }
        let mut p = self.regs[&(VCN + u64::from(RPTR) * 4)];
        while p != value {
            let at = RING + u64::from(p & 511) * 4;
            p = p.wrapping_add(match self.word(at) {
                0 | 1 => 1,
                3 => {
                    let address = u64::from(self.word(at + 4)) | u64::from(self.word(at + 8)) << 32;
                    assert!(address == GPU + FENCE || address == GPU + FENCE + 16);
                    self.store(address - GPU, self.word(at + 12));
                    4
                }
                4 => {
                    self.traps += 1;
                    1
                }
                op => panic!("unexpected VCN4 transport opcode {op}"),
            }) & 511;
        }
        if self.advance {
            self.regs.insert(VCN + u64::from(RPTR) * 4, value);
        }
        self.regs.insert(VCN + u64::from(STATUS) * 4, 2);
    }
    async fn delay(&mut self, _: u64) {
        // Paused hardware drops from power state 2 back to 1.
        let power = self.regs[&(VCN + u64::from(POWER_STATUS) * 4)];
        if power & POWER_STATUS_MASK == 0x2 {
            self.regs.insert(
                VCN + u64::from(POWER_STATUS) * 4,
                (power & !POWER_STATUS_MASK) | 0x1,
            );
        }
        self.delays.fetch_add(1, Ordering::SeqCst);
        narf_scheduler::yield_now().await;
    }
}
fn fixture(pg: bool) -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_4000),
        virt: 0,
        len: BYTES * 2,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts memory I/O; mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let regs = BTreeMap::from([
        (VCN + u64::from(VCPU) * 4, 1 << 28),
        (VCN + u64::from(STATUS) * 4, 0x2),
        (VCN + u64::from(LMI_STATUS) * 4, 0x24f),
        (GC + 0x13de * 4, 0x545),
    ]);
    let e = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0x5a; BYTES as usize],
            doorbells: Vec::new(),
            delays: Arc::new(AtomicU32::new(0)),
            boot: true,
            advance: true,
            fence: true,
            traps: 0,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            vcn: VCN,
            nbio: NBIO,
            gc: GC,
        },
        memory: pool.reserve(BYTES).unwrap(),
        firmware_bytes: 0x11000,
        pg,
        state: State::Prepared,
        addr_config: None,
        dpg: false,
        proof: None,
        wptr: 0,
        seq: 0,
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
fn block(id: u16, instance: u8, version: (u8, u8, u8), bases: [u32; 3]) -> ip::IpBlock {
    let mut b = [0u32; ip::MAX_BASE_ADDRS];
    b[..3].copy_from_slice(&bases);
    ip::IpBlock {
        hw_id: id,
        instance,
        major: version.0,
        minor: version.1,
        revision: version.2,
        sub_revision: 0,
        variant: 0,
        num_bases: 3,
        base_addrs: b,
    }
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
        gpu.ip_blocks.push(block(id, 0, version, bases));
    }
    gpu
}

fn vcn4_layout_resolves_navi31_banks_and_rejects_wrong_versions() -> TestResult {
    let gpu = descriptor();
    let layout = match Layout::resolve(&gpu) {
        Ok(layout) => layout,
        Err(_) => return TestResult::Fail("resolve failed on Navi31 descriptor"),
    };
    if layout.vcn != 0x10000 || layout.nbio != 0x30000 || layout.gc != 0x40000 {
        return TestResult::Fail("resolved banks do not match the descriptor");
    }
    // A second VCN instance is fine (instance 0 only is driven); a second
    // instance-0 block is not.
    let mut two_inst = descriptor();
    two_inst
        .ip_blocks
        .push(block(ip::HW_ID_VCN, 1, (4, 0, 0), [0, 0x8000, 0]));
    if Layout::resolve(&two_inst).is_err() {
        return TestResult::Fail("two VCN instances rejected");
    }
    let mut bad = descriptor();
    bad.ip_blocks[0].revision = 3;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("VCN 4.0.3 accepted");
    }
    let mut bad = descriptor();
    bad.ip_blocks[1] = block(ip::HW_ID_NBIF, 0, (6, 3, 1), [0, 0, 0xc000]);
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("NBIF 6.3.1 accepted");
    }
    let mut bad = descriptor();
    bad.ip_blocks[2].major = 12;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("GC 12 accepted");
    }
    let mut bad = descriptor();
    bad.regs.len = 0x10000;
    if !matches!(Layout::resolve(&bad), Err(Error::Unsupported)) {
        return TestResult::Fail("short BAR accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_layout_resolves_navi31_banks_and_rejects_wrong_versions
);

fn vcn4_firmware_name_and_gc_version() -> TestResult {
    if firmware_name((4, 0, 0)) != Some("amdgpu/vcn_4_0_0.bin")
        || firmware_name((4, 0, 4)) != Some("amdgpu/vcn_4_0_4.bin")
        || firmware_name((4, 0, 2)).is_some()
        || firmware_name((5, 0, 0)).is_some()
    {
        return TestResult::Fail("firmware name selection is wrong");
    }
    if version_for_gc((11, 0, 0)) != Some((4, 0, 0))
        || version_for_gc((11, 0, 3)) != Some((4, 0, 0))
        || version_for_gc((11, 0, 2)) != Some((4, 0, 4))
        || version_for_gc((11, 0, 1)).is_some()
        || version_for_gc((12, 0, 1)).is_some()
    {
        return TestResult::Fail("GC to VCN version mapping is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vcn-navi31", vcn4_firmware_name_and_gc_version);

fn vcn4_codec_caps_are_instance_zero_soc21_rows() -> TestResult {
    let caps = codec_caps();
    if caps.len() != 8 {
        return TestResult::Fail("caps table is not the eight soc21 instance-0 rows");
    }
    let has = |codec: Codec, w: u32, h: u32, enc: bool| {
        caps.iter()
            .any(|c| c.codec == codec && c.max_width == w && c.max_height == h && c.encode == enc)
    };
    if !has(Codec::Avc, 4096, 4096, false)
        || !has(Codec::Hevc, 8192, 4352, false)
        || !has(Codec::Jpeg, 16384, 16384, false)
        || !has(Codec::Vp9, 8192, 4352, false)
        || !has(Codec::Av1, 8192, 4352, false)
        || !has(Codec::Avc, 4096, 4096, true)
        || !has(Codec::Hevc, 8192, 4352, true)
        || !has(Codec::Av1, 8192, 4352, true)
    {
        return TestResult::Fail("caps rows do not match soc21 instance 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_codec_caps_are_instance_zero_soc21_rows
);

fn vcn4_static_boot_pg_sets_power_and_cache_windows() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(()) || e.state != State::Ready {
        return TestResult::Fail("static start did not reach Ready");
    }
    if !e
        .io
        .writes
        .contains(&(VCN + u64::from(PGFSM_CONFIG) * 4, PGFSM_CONFIG_PG_ON))
    {
        return TestResult::Fail("PG power-on config not written");
    }
    if e.reg(POWER_STATUS) != Ok(0x102) {
        return TestResult::Fail("POWER_STATUS is not PWR_ON|PG_EN");
    }
    for (lo, offset, size, address, bytes) in [
        (0x0244, 0x0180, 0x0181, IMAGE, 0x12000),
        (0x0270, 0x0182, 0x0183, GPU, 128 << 10),
        (0x0274, 0x0184, 0x0185, GPU + (128 << 10), 512 << 10),
        (0x0240, 0x0192, 0x0193, GPU + SHARED, 4096),
    ] {
        if e.io.regs[&(VCN + lo * 4)] != address as u32
            || e.io.regs[&(VCN + (lo + 1) * 4)] != (address >> 32) as u32
            || e.io.regs[&(VCN + offset * 4)] != 0
            || e.io.regs[&(VCN + size * 4)] != bytes
        {
            return TestResult::Fail("cache window does not match mc_resume");
        }
    }
    if e.io.word(SHARED) != FW_SHARED_PRESENT
        || e.io.memory[SHARED as usize + 16..SHARED as usize + 19] != [1, 0, 0xa5]
        || e.reg(ADDR_CONFIG) != Ok(0x545)
        || e.reg(RB_SIZE) != Ok(RING_SIZE_DW)
        || e.io.regs[&(NBIO + u64::from(NBIO_RANGE) * 4)] != NBIO_RANGE_VALUE
        || e.reg(DB_CTRL) != Ok(0x4000_0c48)
    {
        return TestResult::Fail("shared page, addr config, ring or range is wrong");
    }
    match run(e.prove()) {
        Ok(proof) if proof.sequence == 1 && proof.read_pointer == 64 => {}
        _ => return TestResult::Fail("fence proof did not complete at wptr 64"),
    }
    if e.state != State::Verified || e.io.traps != 1 {
        return TestResult::Fail("prove did not verify or trap once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_static_boot_pg_sets_power_and_cache_windows
);

fn vcn4_static_boot_no_pg_uses_all_ones_config() -> TestResult {
    let (_pool, mut e) = fixture(false);
    if run(e.start(IMAGE)) != Ok(()) || e.state != State::Ready {
        return TestResult::Fail("non-PG static start did not reach Ready");
    }
    if !e
        .io
        .writes
        .contains(&(VCN + u64::from(PGFSM_CONFIG) * 4, PGFSM_CONFIG_ALL_ONE))
    {
        return TestResult::Fail("all-ones PGFSM config not written");
    }
    if e.reg(POWER_STATUS) != Ok(0) {
        return TestResult::Fail("POWER_STATUS is not cleared without PG support");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_static_boot_no_pg_uses_all_ones_config
);

fn vcn4_start_rejects_live_ring_and_bad_image() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(0)) != Err(Error::Invalid) {
        return TestResult::Fail("zero image accepted");
    }
    if run(e.start(IMAGE + 1)) != Err(Error::Invalid) {
        return TestResult::Fail("unaligned image accepted");
    }
    e.io.regs.insert(VCN + u64::from(RB_ENABLE) * 4, RB1);
    if run(e.start(IMAGE)) != Err(Error::Busy) {
        return TestResult::Fail("live ring accepted");
    }
    let (_pool, mut e) = fixture(true);
    e.io.regs.insert(VCN + u64::from(VCPU) * 4, 0);
    if run(e.start(IMAGE)) != Err(Error::Busy) {
        return TestResult::Fail("VCPU out of reset accepted");
    }
    let (_pool, mut e) = fixture(true);
    e.io.regs
        .insert(NBIO + u64::from(NBIO_RANGE) * 4, NBIO_RANGE_VALUE);
    if run(e.start(IMAGE)) != Err(Error::Busy) {
        return TestResult::Fail("programmed NBIO range accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_start_rejects_live_ring_and_bad_image
);

fn vcn4_prove_times_out_when_fence_stalls() -> TestResult {
    let (_pool, mut e) = fixture(true);
    e.io.fence = false;
    if run(e.start(IMAGE)) != Ok(()) {
        return TestResult::Fail("start failed");
    }
    if run(e.prove()) != Err(Error::Timeout) || e.state != State::Failed(Error::Timeout) {
        return TestResult::Fail("stalled fence did not time out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_prove_times_out_when_fence_stalls
);

fn vcn4_stop_drains_and_reenables_power_gating() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(())
        || run(e.prove())
            != Ok(Proof {
                sequence: 1,
                read_pointer: 64,
            })
    {
        return TestResult::Fail("start/prove failed");
    }
    if run(e.stop()) != Ok(()) || e.state != State::Stopped {
        return TestResult::Fail("stop did not reach Stopped");
    }
    if e.reg(LMI2) != Ok(LMI2_STALL)
        || e.reg(VCPU) != Ok(VCPU_RESET)
        || e.reg(RESET) != Ok(RESET_LMI | RESET_LMI_UMC)
        || e.reg(STATUS) != Ok(0)
        || !e
            .io
            .writes
            .contains(&(VCN + u64::from(PGFSM_CONFIG) * 4, PGFSM_CONFIG_ALL_TWO))
        || e.reg(POWER_STATUS) != Ok(0x103)
    {
        return TestResult::Fail("stop left VCPU, LMI or power gating wrong");
    }
    if e.io.memory[SHARED as usize + 17] & FW_QUEUE_DPG_HOLD_OFF == 0 {
        return TestResult::Fail("DPG_HOLD_OFF not set in fw_shared");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_stop_drains_and_reenables_power_gating
);

fn vcn4_dpg_offset_remaps_soc15_windows() -> TestResult {
    if dpg::offset(0x1fa00, 0) != 0
        || dpg::offset(0x1fa00 + 0x25fc, 0) != 0x977
        || dpg::offset(0x22000, 0) != 0x8800
        || dpg::offset(0x1f800, 0) != 0xc000
        || dpg::offset(0x48200, 0) != 0
        || dpg::offset(0x48000, 0) != 0xc000
        || dpg::offset(VCN, VCPU) != ((VCN + u64::from(VCPU) * 4) as u32 >> 2)
    {
        return TestResult::Fail("SOC15 DPG offset remap is wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_dpg_offset_remaps_soc15_windows
);

fn vcn4_dpg_program_and_probe() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(())
        || run(e.prove())
            != Ok(Proof {
                sequence: 1,
                read_pointer: 64,
            })
    {
        return TestResult::Fail("start/prove failed");
    }
    let mut sram = FakeSram {
        words: Vec::new(),
        fail: false,
    };
    if run(e.enable_dpg(&mut sram, false)) != Ok(()) || !e.dpg || e.state != State::Ready {
        return TestResult::Fail("DPG upgrade did not reach Ready");
    }
    if sram.words.len() % 2 != 0 || sram.words.is_empty() || sram.words.len() > 128 {
        return TestResult::Fail("DPG program is not a valid SRAM list");
    }
    // First words are the DPG clock-gating disable, then VCPU bring-up.
    let at = |reg: u32| dpg::offset(VCN, reg);
    let find = |reg: u32| {
        sram.words
            .chunks_exact(2)
            .find(|pair| pair[0] == at(reg))
            .map(|pair| pair[1])
    };
    if sram.words[0] != at(CGC_CTRL)
        || sram.words[1] != CGC_CTRL_VALUE
        || sram.words[2] != at(CGC_GATE)
        || sram.words[3] != 0
        || find(VCPU) != Some(VCPU_PRB_TIMEOUT | VCPU_CLOCK | VCPU_RESET)
        || find(LMI) != Some(LMI_DPG)
        || find(MPC_CNTL) != Some(0x10)
        || find(MUXA0) != Some(0x40c_2040)
        || find(MUX) != Some(0x88)
        || find(ADDR_CONFIG) != Some(0x545)
        || find(LMI2) != Some(LMI2_DPG)
        // MASTINT appears twice (0, then VCPU_EN); the last pair enables it.
        || sram.words[sram.words.len() - 2] != at(MASTINT)
        || sram.words[sram.words.len() - 1] != MASTINT_VCPU_EN
        || find(RAS_CNTL).is_some()
    {
        return TestResult::Fail("DPG program words do not match vcn_v4_0_start_dpg_mode");
    }
    // Indirect placeholders: the PSP patches the firmware/stack windows.
    if find(CACHE_LO[0]) != Some(0) || find(CACHE_SIZE[0]) != Some(0) {
        return TestResult::Fail("DPG firmware window is not a PSP placeholder");
    }
    if e.io.word(FENCE + 16) != 0 || e.reg(RPTR) != Ok(64) {
        return TestResult::Fail("DPG probe did not execute and clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vcn-navi31", vcn4_dpg_program_and_probe);

fn vcn4_dpg_ras_words_and_sram_failure() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(()) {
        return TestResult::Fail("start failed");
    }
    let mut sram = FakeSram {
        words: Vec::new(),
        fail: false,
    };
    if run(e.enable_dpg(&mut sram, true)) != Ok(()) {
        return TestResult::Fail("RAS DPG upgrade failed");
    }
    let at = |reg: u32| dpg::offset(VCN, reg);
    let find = |reg: u32| {
        sram.words
            .chunks_exact(2)
            .find(|pair| pair[0] == at(reg))
            .map(|pair| pair[1])
    };
    if find(RAS_CNTL) != Some(RAS_VALUE) || find(SYS_INT_EN) != Some(RAS_SYS_INT_EN) {
        return TestResult::Fail("RAS words missing from the DPG program");
    }
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(()) {
        return TestResult::Fail("second start failed");
    }
    let mut failing = FakeSram {
        words: Vec::new(),
        fail: true,
    };
    if run(e.enable_dpg(&mut failing, false))
        != Err(Error::Sram(crate::amdgpu_psp_ring::Error::Unsupported))
        || e.state != State::Failed(Error::Sram(crate::amdgpu_psp_ring::Error::Unsupported))
    {
        return TestResult::Fail("SRAM failure did not fail the upgrade");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi31",
    vcn4_dpg_ras_words_and_sram_failure
);

fn vcn4_dpg_pause_and_stop() -> TestResult {
    let (_pool, mut e) = fixture(true);
    if run(e.start(IMAGE)) != Ok(()) {
        return TestResult::Fail("start failed");
    }
    let mut sram = FakeSram {
        words: Vec::new(),
        fail: false,
    };
    if run(e.enable_dpg(&mut sram, false)) != Ok(()) {
        return TestResult::Fail("DPG upgrade failed");
    }
    if run(e.stop()) != Ok(()) || e.state != State::Stopped {
        return TestResult::Fail("DPG stop did not reach Stopped");
    }
    if e.reg(POWER_STATUS) != Ok(0x101) {
        return TestResult::Fail("PG_MODE not cleared by DPG stop");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vcn-navi31", vcn4_dpg_pause_and_stop);

fn vcn4_new_rejects_short_doorbells() -> TestResult {
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
    let short_new = unsafe { Vcn::new(&gpu, Cap::bootstrap(), &pool, short, 0x11000, true) };
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
    if unsafe { Vcn::new(&gpu, Cap::bootstrap(), &pool, doorbells, 0x11000, true) }.is_err() {
        return TestResult::Fail("valid Vcn::new rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vcn-navi31", vcn4_new_rejects_short_doorbells);
