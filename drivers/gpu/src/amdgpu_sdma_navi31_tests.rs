use super::*;
use crate::amdgpu_sdma::build_sdma6_ring_init;
use narf_kernel_test::{kernel_test_in, TestResult};

const GC_BASE: u32 = 0x0007_0000;
const GC_BASE_IDX1: u32 = 0x000B_0000;
const RING_PHYS: u64 = 0x0000_0001_2000_0000;
const RING_SIZE_DW: u32 = 2048;
const DOORBELL_IDX: u32 = 4;
const RPTR_PHYS: u64 = 0x0000_0002_3000_0000;
const WPTR_POLL_PHYS: u64 = 0x0000_0002_3000_1000;

fn params() -> Navi31RingInit {
    Navi31RingInit {
        gc_base: GC_BASE,
        gc_base_idx1: GC_BASE_IDX1,
        instance: 0,
        queue: 0,
        ring_phys: RING_PHYS,
        ring_size_dw: RING_SIZE_DW,
        doorbell_index: DOORBELL_IDX,
        use_doorbell: true,
        rptr_writeback_phys: RPTR_PHYS,
        wptr_poll_phys: WPTR_POLL_PHYS,
        watchdog_hang_100ms: 1,
        restore_wptr_bytes: None,
    }
}

fn sdma_navi31_revision_table_matches_linux_firmware_sets() -> TestResult {
    // Lane-1 corrected pairing (firmware-set evidence): Navi31 ↔ GC 11.0.0 /
    // SDMA 6.0.0, Navi32 ↔ GC 11.0.3 / SDMA 6.0.3, Navi33 ↔ GC 11.0.2 /
    // SDMA 6.0.2. The early patch tables had 32/33 swapped.
    let cases: &[(Navi3Die, (u8, u8, u8), (u8, u8, u8), &str)] = &[
        (
            Navi3Die::Navi31,
            (11, 0, 0),
            (6, 0, 0),
            "amdgpu/sdma_6_0_0.bin",
        ),
        (
            Navi3Die::Navi32,
            (11, 0, 3),
            (6, 0, 3),
            "amdgpu/sdma_6_0_3.bin",
        ),
        (
            Navi3Die::Navi33,
            (11, 0, 2),
            (6, 0, 2),
            "amdgpu/sdma_6_0_2.bin",
        ),
    ];
    for &(die, gc, sdma, fw) in cases {
        if die.gc_version() != gc || die.sdma_revision() != sdma {
            return TestResult::Fail("die version table mismatch");
        }
        if die_for_gc(gc.0, gc.1, gc.2) != Some(die) {
            return TestResult::Fail("die_for_gc mismatch");
        }
        if die_for_sdma_revision(sdma.0, sdma.1, sdma.2) != Some(die) {
            return TestResult::Fail("die_for_sdma_revision mismatch");
        }
        if !accepts_sdma_revision(sdma.0, sdma.1, sdma.2) {
            return TestResult::Fail("accepts_sdma_revision must accept the die");
        }
        if firmware_name_for_revision(sdma.0, sdma.1, sdma.2) != Some(fw) {
            return TestResult::Fail("firmware blob name mismatch");
        }
    }
    // (6, 0, 1) is Phoenix, not a Navi3 revision; (6, 0, 4) and (7, 0, 0)
    // are not revisions `sdma_v6_0.c` handles for any Navi3 die.
    for v in [(6, 0, 1), (6, 0, 4), (7, 0, 0), (6, 1, 0)] {
        if accepts_sdma_revision(v.0, v.1, v.2)
            || die_for_sdma_revision(v.0, v.1, v.2).is_some()
            || firmware_name_for_revision(v.0, v.1, v.2).is_some()
        {
            return TestResult::Fail("non-Navi3 SDMA revision accepted");
        }
    }
    if die_for_gc(11, 0, 1).is_some() || die_for_gc(12, 0, 0).is_some() {
        return TestResult::Fail("unknown GC version must map to no die");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_revision_table_matches_linux_firmware_sets
);

fn sdma_navi31_queue_stride_and_instance_offsets() -> TestResult {
    // `sdma_v6_0_get_reg_offset`: HYP_DEC range strides 0x20 per instance,
    // everything else strides 0x600 on instance 1 only.
    if reg_offset(0, 0x80) != 0x80 || reg_offset(1, 0x80) != 0x680 {
        return TestResult::Fail("instance-1 queue bank offset must be +0x600");
    }
    if reg_offset(0, 0x589A) != 0x589A || reg_offset(1, 0x589A) != 0x58BA {
        return TestResult::Fail("instance-1 HYP_DEC offset must be +0x20");
    }
    if reg_offset(1, 0x22) != 0x622 {
        return TestResult::Fail("instance-1 instance-level offset must be +0x600");
    }
    // Queue stride: QUEUE1_RB_CNTL 0xD8 − QUEUE0_RB_CNTL 0x80 = 0x58, and
    // QUEUE7 lands at 0x80 + 7*0x58 = 0x2E8 (`gc_11_0_0_offset.h:792`).
    if SDMA60_QUEUE_REG_STRIDE != 0x58 {
        return TestResult::Fail("queue register stride must be 0x58 dwords");
    }
    if 0x80 + 7 * SDMA60_QUEUE_REG_STRIDE != 0x2E8 {
        return TestResult::Fail("QUEUE7_RB_CNTL must be 0x2E8");
    }
    if SDMA60_QUEUES_PER_INSTANCE != 8 {
        return TestResult::Fail("8 queues per instance (hung-queue scan)");
    }
    // Doorbell range: `soc21.c` sets `sdma_doorbell_range = 20`.
    if SDMA60_DOORBELL_RANGE_PER_INSTANCE != 20 {
        return TestResult::Fail("doorbell range per instance must be 20");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_queue_stride_and_instance_offsets
);

fn sdma_navi31_ring_init_cold_sequence_matches_linux() -> TestResult {
    let seq = match build_navi31_sdma6_ring_init(params()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("ring-init failed on valid input"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    // CNTL without ENABLE: RB_SIZE log2(2048) = 11 at shift 1, RB_PRIV
    // 0x00800000, RPTR_WRITEBACK_ENABLE 0x00001000, F32_WPTR_POLL_ENABLE
    // 0x00000800. Legacy WPTR_POLL_ENABLE 0x00000100 stays clear.
    let cntl_no_enable: u32 = (11 << 1) | 0x0080_0000 | 0x0000_1000 | 0x0000_0800;
    if cntl_no_enable != 0x0080_1816 {
        return TestResult::Fail("CNTL composition mismatch");
    }
    let base = GC_BASE;
    let want: [(u32, u32); 25] = [
        // 1. SEM_WAIT_FAIL_TIMER_CNTL = 0.
        (base + 0x22 * 4, 0),
        // 2. RB_CNTL = 0 (disable).
        (base + 0x80 * 4, 0),
        // 3. RPTR/RPTR_HI/WPTR/WPTR_HI = 0.
        (base + 0x83 * 4, 0),
        (base + 0x84 * 4, 0),
        (base + 0x85 * 4, 0),
        (base + 0x86 * 4, 0),
        // 4. Wptr shadow (LO then HI; HI is the lower register id).
        (base + 0xB3 * 4, WPTR_POLL_PHYS as u32),
        (base + 0xB2 * 4, (WPTR_POLL_PHYS >> 32) as u32),
        // 5. Rptr writeback (HI first, as Linux writes it; LO masked).
        (base + 0x88 * 4, (RPTR_PHYS >> 32) as u32),
        (base + 0x89 * 4, RPTR_PHYS as u32 & 0xFFFF_FFFC),
        // 6. CNTL: size + priv + writeback + F32 poll.
        (base + 0x80 * 4, cntl_no_enable),
        // 7. Ring base.
        (base + 0x81 * 4, (RING_PHYS >> 8) as u32),
        (base + 0x82 * 4, (RING_PHYS >> 40) as u32),
        // 8. MINOR_PTR_UPDATE = 1, then the wptr write.
        (base + 0xB5 * 4, 1),
        (base + 0x85 * 4, 0),
        (base + 0x86 * 4, 0),
        // 9. Doorbell.
        (base + 0xAB * 4, DOORBELL_IDX << 2),
        (base + 0x92 * 4, 0x1000_0000),
        // 10. MINOR_PTR_UPDATE = 0.
        (base + 0xB5 * 4, 0),
        // 11. Watchdog: 1 unit of 100 ms.
        (base + 0x2E * 4, 1),
        // 12-13. UTCL1 tuning (reset-derived values, see the constants).
        (base + 0x3C * 4, 0x2C00_0689),
        (base + 0x3F * 4, 0x010C_EC00),
        // 14. F32 unhalt through the GC BASE_IDX-1 window, BEFORE enable.
        (GC_BASE_IDX1 + 0x589A * 4, 0x0808_4000),
        // 15. RB_CNTL |= RB_ENABLE.
        (base + 0x80 * 4, cntl_no_enable | 0x0000_0001),
        // 16. IB_CNTL: IB_ENABLE with the reset SWITCH_INSIDE_IB bit kept.
        (base + 0x8A * 4, 0x0000_0101),
    ];
    if w.len() != want.len() {
        return TestResult::Fail("cold ring-init must be exactly 25 writes");
    }
    for (i, (addr, value)) in want.into_iter().enumerate() {
        if (w[i].addr, w[i].value) != (addr, value) {
            return TestResult::Fail("cold ring-init write mismatch");
        }
    }
    // Cold-start derivations, pinned independently of the sequence above:
    // F32 default 0x08084001 minus HALT|TH1_RESET; UTCL1_CNTL default
    // 0x2c000288 with RESP_MODE 3 / REDO_DELAY 9; UTCL1_PAGE reproduces
    // its reset default 0x010cec00.
    if SDMA60_F32_CNTL_COLD_START != 0x0808_4000
        || SDMA60_UTCL1_CNTL_COLD_START != 0x2C00_0689
        || SDMA60_UTCL1_PAGE_COLD_START != 0x010C_EC00
        || SDMA60_IB_CNTL_COLD_START != 0x0000_0101
    {
        return TestResult::Fail("cold-start value derivation mismatch");
    }
    if SDMA60_F32_CNTL_COLD_START & (SDMA_F32_HALT | SDMA_F32_TH1_RESET) != 0 {
        return TestResult::Fail("F32 cold start must clear HALT and TH1_RESET");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_ring_init_cold_sequence_matches_linux
);

fn sdma_navi31_ring_init_instance1_queue3() -> TestResult {
    let mut p = params();
    p.instance = 1;
    p.queue = 3;
    let seq = match build_navi31_sdma6_ring_init(p) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("ring-init failed for instance 1 queue 3"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    // Instance 1 adds 0x600 dwords (0x1800 bytes); queue 3 adds 3*0x58
    // dwords (0x420 bytes) to per-queue regs only.
    let q = |rel_dword: u32| GC_BASE + (rel_dword + 0x600 + 3 * 0x58) * 4;
    let inst = |rel_dword: u32| GC_BASE + (rel_dword + 0x600) * 4;
    let checks: [(u32, u32); 8] = [
        (q(0x80), 0),                                      // RB_CNTL disable
        (q(0x81), (RING_PHYS >> 8) as u32),                // RB_BASE
        (q(0xAB), DOORBELL_IDX << 2),                      // DOORBELL_OFFSET
        (q(0x92), 0x1000_0000),                            // DOORBELL ENABLE
        (q(0x8A), 0x0000_0101),                            // IB_CNTL
        (inst(0x2E), 1),                                   // WATCHDOG (no queue stride)
        (inst(0x3C), 0x2C00_0689),                         // UTCL1_CNTL (no queue stride)
        (GC_BASE_IDX1 + (0x589A + 0x20) * 4, 0x0808_4000), // F32, HYP_DEC +0x20
    ];
    for (addr, value) in checks {
        if !w.iter().any(|x| x.addr == addr && x.value == value) {
            return TestResult::Fail("instance-1/queue-3 addressing mismatch");
        }
    }
    // No write may address the F32 through the BASE_IDX-0 window.
    if w.iter().any(|x| x.addr == GC_BASE + 0x589A * 4) {
        return TestResult::Fail("F32_CNTL must not be addressed from window 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_ring_init_instance1_queue3
);

fn sdma_navi31_ring_init_rejects_bad_inputs() -> TestResult {
    let mut p = params();
    // Bad instance / queue.
    p.instance = 2;
    if build_navi31_sdma6_ring_init(p).err() != Some(Navi31SdmaError::BadInstance) {
        return TestResult::Fail("instance 2 must be rejected");
    }
    p = params();
    p.queue = 8;
    if build_navi31_sdma6_ring_init(p).err() != Some(Navi31SdmaError::BadQueue) {
        return TestResult::Fail("queue 8 must be rejected");
    }
    // Bad watchdog: 0 (hang detection off) and 256 (overflows 8 bits).
    p = params();
    p.watchdog_hang_100ms = 0;
    if build_navi31_sdma6_ring_init(p).err() != Some(Navi31SdmaError::BadWatchdog) {
        return TestResult::Fail("watchdog 0 must be rejected");
    }
    p.watchdog_hang_100ms = 256;
    if build_navi31_sdma6_ring_init(p).err() != Some(Navi31SdmaError::BadWatchdog) {
        return TestResult::Fail("watchdog 256 must be rejected");
    }
    // Shared ring-parameter checks, via the SdmaError mapping.
    p = params();
    p.ring_size_dw = 2047;
    if build_navi31_sdma6_ring_init(p).err() != Some(Navi31SdmaError::Ring(SdmaError::BadRingSize))
    {
        return TestResult::Fail("non-power-of-two ring size must be rejected");
    }
    p = params();
    p.ring_phys = RING_PHYS + 1;
    if build_navi31_sdma6_ring_init(p).err()
        != Some(Navi31SdmaError::Ring(SdmaError::UnalignedRingPhys))
    {
        return TestResult::Fail("unaligned ring phys must be rejected");
    }
    // No-doorbell path: 24 writes, DOORBELL = 0, no OFFSET write.
    p = params();
    p.use_doorbell = false;
    let seq = match build_navi31_sdma6_ring_init(p) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("no-doorbell init failed"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    if w.len() != 24 {
        return TestResult::Fail("no-doorbell init must be 24 writes");
    }
    if !w
        .iter()
        .any(|x| x.addr == GC_BASE + 0x92 * 4 && x.value == 0)
    {
        return TestResult::Fail("no-doorbell init must write DOORBELL = 0");
    }
    if w.iter().any(|x| x.addr == GC_BASE + 0xAB * 4) {
        return TestResult::Fail("no-doorbell init must not write DOORBELL_OFFSET");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_ring_init_rejects_bad_inputs
);

fn sdma_navi31_ring_restore_preserves_wptr() -> TestResult {
    let mut owner = match Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 0)]) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner must accept Navi31 6.0.0"),
    };
    let seq = match owner.ring_init(params()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("owner ring_init failed"),
    };
    let _ = seq;
    // Restore without a programmed queue must fail closed.
    let mut fresh = match Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 0)]) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner must accept Navi31 6.0.0"),
    };
    if fresh.ring_restore(params(), 0x400).err() != Some(Navi31SdmaError::NotProgrammed) {
        return TestResult::Fail("restore of an unprogrammed queue must fail");
    }
    // Restore resumes both pointers at the software wptr, inside the
    // MINOR_PTR_UPDATE bracket, and re-enables the ring.
    let seq = match owner.ring_restore(params(), 0x400) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("owner ring_restore failed"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    if w.len() != 25 {
        return TestResult::Fail("restore must be 25 writes");
    }
    let minor = GC_BASE + 0xB5 * 4;
    let wptr = GC_BASE + 0x85 * 4;
    // Step 3 restores RPTR/WPTR to 0x400; step 8 writes WPTR 0x400 again.
    if w.iter()
        .filter(|x| x.addr == wptr && x.value == 0x400)
        .count()
        != 2
    {
        return TestResult::Fail("restore must write WPTR = 0x400 twice");
    }
    if !w
        .iter()
        .any(|x| x.addr == GC_BASE + 0x83 * 4 && x.value == 0x400)
    {
        return TestResult::Fail("restore must write RPTR = 0x400");
    }
    let set = w.iter().position(|x| x.addr == minor && x.value == 1);
    let cleared = w.iter().rposition(|x| x.addr == minor && x.value == 0);
    match (set, cleared) {
        (Some(a), Some(b)) if a < b => {}
        _ => return TestResult::Fail("restore must bracket wptr with MINOR_PTR_UPDATE"),
    }
    // Cold start never restores a wptr.
    let mut p = params();
    p.restore_wptr_bytes = Some(0x400);
    if owner.ring_init(p).err() != Some(Navi31SdmaError::RestoreInInit) {
        return TestResult::Fail("ring_init with a restore wptr must be rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_ring_restore_preserves_wptr
);

fn sdma_navi31_owner_validates_discovery() -> TestResult {
    // One instance, matching revision: accepted.
    let one = Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 0)]);
    if one.is_err() {
        return TestResult::Fail("Navi31 must accept 6.0.0");
    }
    // Two instances, both matching: accepted (count is discovery-driven).
    let two = Sdma60::from_discovery(Navi3Die::Navi32, &[(6, 0, 3), (6, 0, 3)]);
    match two {
        Ok(o) if o.instances() == 2 => {}
        _ => return TestResult::Fail("Navi32 must accept two 6.0.3 instances"),
    }
    // Wrong revision for the die: Phoenix 6.0.1 on Navi31, 6.0.3 on Navi31.
    if Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 1)]).is_ok()
        || Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 3)]).is_ok()
    {
        return TestResult::Fail("revision mismatch must be rejected");
    }
    // Mixed instances: one right, one wrong.
    if Sdma60::from_discovery(Navi3Die::Navi33, &[(6, 0, 2), (6, 0, 0)]).is_ok() {
        return TestResult::Fail("mixed-revision discovery must be rejected");
    }
    // No instances / too many instances.
    if Sdma60::from_discovery(Navi3Die::Navi31, &[]).err() != Some(Navi31SdmaError::NoInstances) {
        return TestResult::Fail("empty discovery must be rejected");
    }
    if Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 0), (6, 0, 0), (6, 0, 0)]).err()
        != Some(Navi31SdmaError::TooManyInstances)
    {
        return TestResult::Fail("three instances must be rejected");
    }
    // Owner bounds: instance 1 does not exist on a one-instance owner.
    let mut owner = match Sdma60::from_discovery(Navi3Die::Navi31, &[(6, 0, 0)]) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner must accept Navi31 6.0.0"),
    };
    if owner.revision() != (6, 0, 0) || owner.die() != Navi3Die::Navi31 {
        return TestResult::Fail("owner must report its die and revision");
    }
    let mut p = params();
    p.instance = 1;
    if owner.ring_init(p).err() != Some(Navi31SdmaError::BadInstance) {
        return TestResult::Fail("ring_init past the discovered count must fail");
    }
    if owner.is_programmed(0, 0) {
        return TestResult::Fail("nothing is programmed before ring_init");
    }
    if owner.ring_init(params()).is_err() || !owner.is_programmed(0, 0) {
        return TestResult::Fail("ring_init must mark the queue programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_owner_validates_discovery
);

fn sdma_navi31_sequence_contains_phoenix_writes() -> TestResult {
    // The Navi31 sequence is the Phoenix `build_sdma6_ring_init` sequence
    // plus the SEM/WATCHDOG/UTCL1 writes Linux makes, with two corrected
    // values (F32, IB_CNTL) and the F32 unhalt moved before RB_ENABLE, as
    // `sdma_v6_0_gfx_resume_instance` orders it.
    let phoenix = match build_sdma6_ring_init(
        GC_BASE,
        GC_BASE_IDX1,
        RING_PHYS,
        RING_SIZE_DW,
        DOORBELL_IDX,
        RPTR_PHYS,
        WPTR_POLL_PHYS,
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("Phoenix builder failed"),
    };
    let navi31 = match build_navi31_sdma6_ring_init(params()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("Navi31 builder failed"),
    };
    let pw: alloc::vec::Vec<_> = phoenix.iter().copied().collect();
    let nw: alloc::vec::Vec<_> = navi31.iter().copied().collect();
    let f32_addr = GC_BASE_IDX1 + 0x589A * 4;
    let ib_addr = GC_BASE + 0x8A * 4;
    // Every Phoenix write except F32 and IB_CNTL appears identically.
    for x in &pw {
        if x.addr == f32_addr || x.addr == ib_addr {
            continue;
        }
        if !nw.iter().any(|y| y.addr == x.addr && y.value == x.value) {
            return TestResult::Fail("Phoenix write missing from Navi31 sequence");
        }
    }
    // F32: same address, reset-derived value (not 0); IB_CNTL keeps the
    // reset SWITCH_INSIDE_IB bit.
    if !nw
        .iter()
        .any(|x| x.addr == f32_addr && x.value == 0x0808_4000)
    {
        return TestResult::Fail("Navi31 F32 must be the reset-derived value");
    }
    if pw
        .iter()
        .any(|x| x.addr == f32_addr && x.value == 0x0808_4000)
    {
        return TestResult::Fail("Phoenix F32 value must differ (it writes 0)");
    }
    if !nw.iter().any(|x| x.addr == ib_addr && x.value == 0x101) {
        return TestResult::Fail("Navi31 IB_CNTL must keep SWITCH_INSIDE_IB");
    }
    // Navi31 adds exactly four writes Linux makes: SEM, WATCHDOG, UTCL1 x2.
    if nw.len() != pw.len() + 4 {
        return TestResult::Fail("Navi31 must add exactly four writes");
    }
    // F32 position: before RB_ENABLE in Navi31 (Linux order), last in
    // Phoenix (Phoenix-builder deviation, not fixed here).
    let cntl = GC_BASE + 0x80 * 4;
    let navi31_f32 = nw.iter().position(|x| x.addr == f32_addr);
    let navi31_enable = nw
        .iter()
        .rposition(|x| x.addr == cntl && x.value & 0x1 != 0);
    let phoenix_f32 = pw.iter().position(|x| x.addr == f32_addr);
    match (navi31_f32, navi31_enable, phoenix_f32) {
        (Some(f), Some(e), Some(pf)) if f < e && pf == pw.len() - 1 => {}
        _ => return TestResult::Fail("F32 ordering mismatch"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi31",
    sdma_navi31_sequence_contains_phoenix_writes
);
