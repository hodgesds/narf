use super::*;
use crate::amdgpu_compute::{build_map_queue, RingKind};
use crate::amdgpu_gfx::{
    build_ring_test_packet, ring_test_scratch_dword, GfxStep, RING_TEST_EXPECT, RING_TEST_SEED,
};
use crate::amdgpu_mes::MesHwResources;
use crate::amdgpu_mes_hw::fill_hw_resources;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The corrected die↔GC pairing (lane 1): Navi31 is 11.0.0, Navi32 is
/// 11.0.3, Navi33 is 11.0.2 — not the pre-launch order that had 32/33
/// swapped.
fn cp_rdna3_die_gc_pairing() -> TestResult {
    if CpDie::Navi31.gc_version() != (11, 0, 0)
        || CpDie::Navi32.gc_version() != (11, 0, 3)
        || CpDie::Navi33.gc_version() != (11, 0, 2)
    {
        return TestResult::Fail("a die reports the wrong GC version");
    }
    if CpDie::Navi31.name() != "Navi31"
        || CpDie::Navi32.name() != "Navi32"
        || CpDie::Navi33.name() != "Navi33"
    {
        return TestResult::Fail("a die reports the wrong name");
    }
    // Every die in the table takes the MES-KIQ path.
    for die in [CpDie::Navi31, CpDie::Navi32, CpDie::Navi33] {
        if !uses_mes_kiq(die.gc_version()) {
            return TestResult::Fail("an RDNA3 die does not use MES-KIQ");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_die_gc_pairing);

/// The MES firmware triple per die, verbatim from `mes_v11_0.c`
/// `MODULE_FIRMWARE`.
fn cp_rdna3_mes_firmware_names() -> TestResult {
    let fw31 = CpDie::Navi31.mes_firmware();
    if fw31.mes != "amdgpu/gc_11_0_0_mes.bin"
        || fw31.mes_2 != "amdgpu/gc_11_0_0_mes_2.bin"
        || fw31.mes1 != "amdgpu/gc_11_0_0_mes1.bin"
    {
        return TestResult::Fail("the Navi31 MES triple names the wrong blobs");
    }
    let fw32 = CpDie::Navi32.mes_firmware();
    if fw32.mes != "amdgpu/gc_11_0_3_mes.bin"
        || fw32.mes_2 != "amdgpu/gc_11_0_3_mes_2.bin"
        || fw32.mes1 != "amdgpu/gc_11_0_3_mes1.bin"
    {
        return TestResult::Fail("the Navi32 MES triple names the wrong blobs");
    }
    let fw33 = CpDie::Navi33.mes_firmware();
    if fw33.mes != "amdgpu/gc_11_0_2_mes.bin"
        || fw33.mes_2 != "amdgpu/gc_11_0_2_mes_2.bin"
        || fw33.mes1 != "amdgpu/gc_11_0_2_mes1.bin"
    {
        return TestResult::Fail("the Navi33 MES triple names the wrong blobs");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_mes_firmware_names);

/// `uses_mes_kiq` is the discovery switch, transcribed: every GFX11/12
/// die in the switch, and the two near-misses that are not in it.
fn cp_rdna3_uses_mes_kiq() -> TestResult {
    for gc in [
        (11, 0, 0),
        (11, 0, 1),
        (11, 0, 2),
        (11, 0, 3),
        (11, 0, 4),
        (11, 5, 0),
        (11, 5, 4),
        (11, 5, 6),
        (11, 7, 0),
        (11, 7, 1),
        (12, 0, 0),
        (12, 0, 1),
        (12, 1, 0),
    ] {
        if !uses_mes_kiq(gc) {
            return TestResult::Fail("a MES-KIQ die is refused");
        }
    }
    // 11.5.5 is the hole in the 11.5 range; GFX9/10 never had MES-KIQ.
    for gc in [(11, 5, 5), (10, 3, 0), (9, 0, 0), (12, 2, 0), (11, 0, 5)] {
        if uses_mes_kiq(gc) {
            return TestResult::Fail("a non-MES-KIQ GC version is admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_uses_mes_kiq);

/// The MES ring identities, and the RLC setting for the KIQ ring.
fn cp_rdna3_mes_ring_identities() -> TestResult {
    if MES_SCHED_RING.me != 3 || MES_SCHED_RING.pipe != 0 || MES_SCHED_RING.queue != 0 {
        return TestResult::Fail("the scheduler ring is not me 3, pipe 0, queue 0");
    }
    if MES_KIQ_RING.me != 3 || MES_KIQ_RING.pipe != 1 || MES_KIQ_RING.queue != 0 {
        return TestResult::Fail("the KIQ ring is not me 3, pipe 1, queue 0");
    }
    if MES_RING_DWORDS != 1024 {
        return TestResult::Fail("a MES ring is not 1024 dwords");
    }
    // me 3 << 5 | pipe 1 << 3 | queue 0 | 0x80, over a live low byte.
    if kiq_rlc_schedulers_value(0xAABB_CC00) != 0xAABB_CCE8 {
        return TestResult::Fail("the KIQ RLC setting packs the wrong coordinate");
    }
    if kiq_rlc_schedulers_value(0) != 0xE8 {
        return TestResult::Fail("the KIQ RLC setting is not composed from zero");
    }
    // Doorbell indices are dword indices: mes_ringN << 1.
    if mes_doorbell_dw(0) != 0 || mes_doorbell_dw(3) != 6 {
        return TestResult::Fail("a MES doorbell index is not shifted to dwords");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_mes_ring_identities);

/// `build_rlc_start`: the handshake disable precedes the enable, the
/// enable sets only bit 0, and the 50 us wait ends the sequence.
fn cp_rdna3_rlc_start_sequence() -> TestResult {
    if (RLC_CNTL, RLC_PG_CNTL) != (0x4c00, 0x4c43) {
        return TestResult::Fail("RLC_CNTL 0x4c00, RLC_PG_CNTL 0x4c43");
    }
    if (RLC_ENABLE_F32, RLC_PG_SMU_HANDSHAKE_DISABLE) != (1, 1 << 23) {
        return TestResult::Fail("RLC_ENABLE_F32 is bit 0, the handshake disable bit 23");
    }
    if RLC_START_DELAY_US != 50 {
        return TestResult::Fail("gfx_v11_0_rlc_start waits 50 us after enabling");
    }
    // The GC BASE_IDX 1 base is discovery-resolved; 0xA000 is the example
    // base the ring-test docs use, and the sequence only adds offsets to it.
    let base = 0xA000;
    let seq = build_rlc_start(base, 0x0000_0000, 0x0000_0000, false);
    if seq.writes_to(base, RLC_PG_CNTL) != [RLC_PG_SMU_HANDSHAKE_DISABLE] {
        return TestResult::Fail("GFXOFF off must disable the RLC/SMU handshake first");
    }
    if seq.writes_to(base, RLC_CNTL) != [RLC_ENABLE_F32] {
        return TestResult::Fail("the RLC enable must set only RLC_ENABLE_F32");
    }
    // Order: handshake disable, enable, wait — and the wait is last.
    let mut pg_at = None;
    let mut cntl_at = None;
    let mut delay_at = None;
    for (i, step) in seq.steps.iter().enumerate() {
        match step {
            GfxStep::Write { addr, .. } if *addr == base + (RLC_PG_CNTL << 2) => pg_at = Some(i),
            GfxStep::Write { addr, .. } if *addr == base + (RLC_CNTL << 2) => cntl_at = Some(i),
            GfxStep::Delay { us } if *us == RLC_START_DELAY_US => delay_at = Some(i),
            _ => {}
        }
    }
    match (pg_at, cntl_at, delay_at) {
        (Some(p), Some(c), Some(d)) if p < c && c < d && d == seq.len() - 1 => {}
        _ => return TestResult::Fail("the RLC start writes are out of order"),
    }
    // Both writes are read-modify-writes: live bits survive.
    let seq = build_rlc_start(base, 0x0000_1234, 0x00FF_0000, false);
    if seq.writes_to(base, RLC_PG_CNTL) != [0x0000_1234 | RLC_PG_SMU_HANDSHAKE_DISABLE] {
        return TestResult::Fail("the handshake write must preserve the live register");
    }
    if seq.writes_to(base, RLC_CNTL) != [0x00FF_0000 | RLC_ENABLE_F32] {
        return TestResult::Fail("the enable write must preserve the live register");
    }
    // With GFXOFF on, there is no handshake write at all.
    let seq = build_rlc_start(base, 0, 0, true);
    if !seq.writes_to(base, RLC_PG_CNTL).is_empty() {
        return TestResult::Fail("GFXOFF on must not touch the handshake bit");
    }
    if seq.writes_to(base, RLC_CNTL) != [RLC_ENABLE_F32] {
        return TestResult::Fail("GFXOFF on still enables the RLC");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_rlc_start_sequence);

/// The KIQ ring-test packet, and the gfx-ring packet it differs from.
///
/// Both name the same register (`SCRATCH_REG0`, resolved 0xC040 off the
/// 0xA000 example base) and the same expected value; they differ in how
/// the CP is told to write it: SET_UCONFIG_REG with an aperture-relative
/// offset for gfx/compute rings, WRITE_DATA with the resolved address
/// and the KIQ `1 << 16` command for the KIQ ring.
fn cp_rdna3_kiq_ring_test_packet() -> TestResult {
    if KIQ_WREG_NO_INC_ADDR != 0x0001_0000 {
        return TestResult::Fail("the KIQ wreg command is 1 << 16");
    }
    let scratch = match ring_test_scratch_dword(0xA000) {
        Some(d) => d,
        None => return TestResult::Fail("the scratch dword did not resolve"),
    };
    if scratch != 0xC040 {
        return TestResult::Fail("SCRATCH_REG0 resolves to 0xC040 off the 0xA000 base");
    }
    let packet = build_kiq_ring_test_packet(scratch);
    // packet3(WRITE_DATA 0x37, 3) = (3 << 30) | (0x37 << 8) | (3 << 16).
    if packet != [0xC003_3700, 0x0001_0000, 0xC040, 0, 0xDEAD_BEEF] {
        return TestResult::Fail("the KIQ ring-test packet is not the emit_wreg transcription");
    }
    // The gfx-ring packet for the same base, for contrast: SET_UCONFIG_REG
    // with the aperture-relative offset 0x40, not the resolved address.
    let gfx = match build_ring_test_packet(0xA000) {
        Some(p) => p,
        None => return TestResult::Fail("the gfx ring-test packet did not build"),
    };
    if gfx != [0xC001_7900, 0x40, 0xDEAD_BEEF] {
        return TestResult::Fail("the gfx ring-test packet is not the SET_UCONFIG_REG form");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_kiq_ring_test_packet);

/// `decide_ring_test`: the seed is "not yet", the expected value is the
/// pass, anything else is corruption — including the all-ones read of a
/// register that does not exist.
fn cp_rdna3_ring_test_poll() -> TestResult {
    if decide_ring_test(&[]) != RingTestOutcome::Timeout {
        return TestResult::Fail("no polls is a timeout, not a pass");
    }
    if decide_ring_test(&[RING_TEST_SEED, RING_TEST_SEED]) != RingTestOutcome::Timeout {
        return TestResult::Fail("seed-only polls are a timeout");
    }
    if decide_ring_test(&[RING_TEST_EXPECT]) != (RingTestOutcome::Pass { polls: 1 }) {
        return TestResult::Fail("the expected value on the first poll passes at once");
    }
    if decide_ring_test(&[RING_TEST_SEED, RING_TEST_SEED, RING_TEST_EXPECT])
        != (RingTestOutcome::Pass { polls: 3 })
    {
        return TestResult::Fail("the pass counts the polls it took");
    }
    if decide_ring_test(&[RING_TEST_SEED, 0xFFFF_FFFF]) != RingTestOutcome::Corrupted(0xFFFF_FFFF) {
        return TestResult::Fail("an all-ones read is corruption, not a pass");
    }
    if decide_ring_test(&[0x0000_0000]) != RingTestOutcome::Corrupted(0) {
        return TestResult::Fail("a zero read is corruption, not a pass");
    }
    // Corruption beats a later pass: the register was written by something
    // else, and a subsequent expected value does not explain that away.
    if decide_ring_test(&[0x1234_5678, RING_TEST_EXPECT]) != RingTestOutcome::Corrupted(0x1234_5678)
    {
        return TestResult::Fail("corruption before the pass must still fail");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_ring_test_poll);

/// The RDNA3 MES topology through `fill_hw_resources`: the masks the
/// scheduler is told about.
///
/// One ME, one pipe per ME, one kernel graphics ring: the gfx mask
/// reserves that one slot (2 of 3). One MEC, four pipes, eight compute
/// rings: two reserved slots per pipe (0xC of 0xF) on four pipes. One
/// SDMA instance: queues 2..7 (0xFC). VMIDs 8..15 for the scheduler on
/// both hubs. Aggregated doorbells two dwords apart from zero.
fn cp_rdna3_topology_masks() -> TestResult {
    let mut res = MesHwResources::default();
    fill_hw_resources(&mut res, &RDNA3_TOPOLOGY);
    if res.vmid_mask_mmhub != 0xFF00 || res.vmid_mask_gfxhub != 0xFF00 {
        return TestResult::Fail("the scheduler owns VMIDs 8..15 on both hubs");
    }
    if res.gfx_hqd_mask != [0x2, 0] {
        return TestResult::Fail("the gfx mask reserves the one kernel graphics ring");
    }
    if res.compute_hqd_mask != [0xC, 0xC, 0xC, 0xC, 0, 0, 0, 0] {
        return TestResult::Fail("the compute mask reserves two slots per pipe on four pipes");
    }
    if res.sdma_hqd_mask != [0xFC, 0] {
        return TestResult::Fail("the SDMA mask is queues 2..7 on one instance");
    }
    if res.aggregated_doorbells != [0, 2, 4, 6, 8] {
        return TestResult::Fail("the aggregated doorbells are two dwords apart from zero");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_topology_masks);

/// `mes_v11_0_kiq_enable_queue`'s MAP_QUEUES packet for the scheduler
/// ring, through the existing `build_map_queue`: RingKind::Mes is
/// me 2, engine select 5; the sched ring is pipe 0, queue 0.
fn cp_rdna3_map_sched_ring_via_kiq() -> TestResult {
    let packet = build_map_queue(
        RingKind::Mes,
        MES_SCHED_RING.pipe as u8,
        MES_SCHED_RING.queue as u8,
        0x174,
        0x1234_0000_1000,
        0x1234_0000_4008,
    );
    // packet3(MAP_QUEUES 0xA2, 5) = (3 << 30) | (0xA2 << 8) | (5 << 16).
    // cfg = me 2 << 18 | eng_sel 5 << 26 | num_queues 1 << 29.
    if packet.as_slice()
        != [
            0xC005_A200,
            0x3408_0000,
            0x174 << 2,
            0x0000_1000,
            0x1234,
            0x0000_4008,
            0x1234,
        ]
    {
        return TestResult::Fail("the scheduler-ring MAP_QUEUES packet is wrong");
    }
    if RingKind::Mes.me_id() != 2 || RingKind::Mes.engine_sel() != 5 {
        return TestResult::Fail("the MES kind is me 2, engine select 5");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/cp_rdna3", cp_rdna3_map_sched_ring_via_kiq);
