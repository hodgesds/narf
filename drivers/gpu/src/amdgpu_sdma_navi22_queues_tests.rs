use super::*;
use crate::amdgpu_cp_navi22::{
    tests::{cancel_at, enabled, hw, pool, r, run, sdma, Model, NBIO},
    FENCE, QUEUE_BYTES,
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn engine(model: Model) -> (Pool, Engine<Model>) {
    let pool = pool(1 << 20);
    let queues = [
        Queue::new(&pool, Kind::Sdma, doorbell::SDMA0, fence::Engine::Sdma0).unwrap(),
        Queue::new(&pool, Kind::Sdma, doorbell::SDMA1, fence::Engine::Sdma1).unwrap(),
    ];
    (
        pool,
        Engine {
            hw: hw(model),
            queues: queues.into(),
            state: State::Prepared,
            proof: Proof::default(),
        },
    )
}

fn sdma_queues_navi22_start_both_engines_with_doorbells_and_fences() -> TestResult {
    let mut model = enabled();
    // Idle cold-boot SDMA0 proof ring still enabled at rptr == wptr.
    model.regs.insert(sdma(0, SDMA0_GFX_RB_CNTL), 0x0080_1015);
    for reg in [SDMA0_GFX_RB_RPTR, SDMA0_GFX_RB_WPTR] {
        model.regs.insert(sdma(0, reg), 128);
    }
    let (pool, mut e) = engine(model);
    if run(e.start()).is_err() || run(e.test_ib()).is_err() || e.state != State::Verified {
        return TestResult::Fail("SDMA bring-up failed");
    }
    let m = &e.hw.io;
    for i in 0..2u32 {
        let q = &e.queues[i as usize];
        let index = [0x200, 0x214][i as usize];
        for (reg, value) in [
            (SDMA0_GFX_RB_CNTL, 0x0080_1017 * (1 - i) + 0x1017 * i),
            (SDMA0_GFX_RB_BASE, (q.address(0) >> 8) as u32),
            (SDMA0_GFX_RB_BASE_HI, 0),
            (SDMA0_GFX_RB_RPTR_ADDR_LO, q.address(RPTR) as u32),
            (SDMA0_GFX_RB_WPTR_POLL_ADDR_LO, q.address(WPTR) as u32),
            (SDMA0_GFX_RB_WPTR_POLL_CNTL, 4),
            (SDMA0_GFX_DOORBELL, 1 << 28),
            (SDMA0_GFX_DOORBELL_OFFSET, index << 2),
            (SDMA0_GFX_MINOR_PTR_UPDATE, 0),
            (SDMA0_CNTL, 0x4_0022),
            (SDMA0_UTCL1_CNTL, 0x612),
            (SDMA0_UTCL1_PAGE, 0x010f_e000),
            (SDMA0_F32_CNTL, 0),
            (SDMA0_GFX_IB_CNTL, 1),
            (SDMA0_PHASE2_QUANTUM, 0x2000),
            (SDMA0_SEM_WAIT_FAIL_TIMER_CNTL, 0),
        ] {
            if m.reg(sdma(i, reg)) != value {
                return TestResult::Fail("SDMA queue register encoding");
            }
        }
        if m.reg(NBIO + u64::from(0x1d0 + i) * 4) != ((index << 2) & 0xffc) | (20 << 16)
            || m.word(q.address(SCRATCH)) != 0xdead_beef
            || m.word(q.address(FENCE)) != 1
            || m.word(q.address(RPTR)) != 128
        {
            return TestResult::Fail("SDMA doorbell range or execution");
        }
    }
    let resets: alloc::vec::Vec<u32> = m
        .writes
        .iter()
        .filter(|&&(a, _)| a == r(GRBM_SOFT_RESET))
        .map(|&(_, v)| v)
        .collect();
    let first_minor = m
        .writes
        .iter()
        .position(|&(a, v)| a == sdma(0, SDMA0_GFX_MINOR_PTR_UPDATE) && v == 1)
        .unwrap();
    let first_enable = m
        .writes
        .iter()
        .position(|&(a, v)| a == sdma(0, SDMA0_GFX_RB_CNTL) && v & 1 != 0)
        .unwrap();
    if resets != [1 << 23, 0, 1 << 24, 0]
        || first_enable < first_minor
        || m.doorbells != [(0x200, 64), (0x214, 64), (0x200, 128), (0x214, 128)]
        || m.traps != 2
        || e.proof
            != (Proof {
                stopped: [true, false, false, false],
                ring: [true, true, false, false],
                ib_fence: [1, 1, 0, 0],
            })
    {
        return TestResult::Fail("SDMA reset/doorbell/IB sequence");
    }
    let count = m.writes.len();
    if run(e.start()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("SDMA queues replayed");
    }
    drop(e);
    if pool.available() != (1 << 20) - 2 * QUEUE_BYTES {
        return TestResult::Fail("live SDMA rings recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22-queues",
    sdma_queues_navi22_start_both_engines_with_doorbells_and_fences
);

fn sdma_queues_navi22_refuse_busy_engines_before_writes() -> TestResult {
    for case in 0..3 {
        let mut model = enabled();
        match case {
            0 => {
                model.regs.insert(sdma(1, SDMA0_GFX_RB_CNTL), 1);
                model.regs.insert(sdma(1, SDMA0_GFX_RB_WPTR), 64);
            }
            1 => {
                model.regs.insert(r(GRBM_SOFT_RESET), 1 << 24);
            }
            _ => {
                model.regs.insert(sdma(0, SDMA0_GFX_RB_CNTL), u32::MAX);
            }
        }
        let (pool, mut e) = engine(model);
        let expected = if case == 2 {
            Error::DeviceGone
        } else {
            Error::Busy
        };
        if run(e.start()) != Err(expected) || !e.hw.io.writes.is_empty() || e.state != State::Failed
        {
            return TestResult::Fail("busy SDMA engine was reprogrammed");
        }
        drop(e);
        if pool.available() != 1 << 20 {
            return TestResult::Fail("unused SDMA rings leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22-queues",
    sdma_queues_navi22_refuse_busy_engines_before_writes
);

fn sdma_queues_navi22_failures_and_cancellation_are_terminal() -> TestResult {
    for case in 0..4 {
        let mut model = enabled();
        let expected = match case {
            0 => {
                model.stalled[4] = true;
                Error::Timeout
            }
            1 => {
                model.drop_ib_writes = true;
                Error::DataMismatch
            }
            2 => {
                model.drop_fences = true;
                Error::Timeout
            }
            _ => {
                // NBIF SDMA doorbell aperture closed: no engine sees a doorbell.
                model.regs.insert(NBIO + 0xc0 * 4, 0);
                Error::Timeout
            }
        };
        let (_pool, mut e) = engine(model);
        let result = match run(e.start()) {
            Err(error) => Err(error),
            Ok(()) => run(e.test_ib()),
        };
        if result != Err(expected) || e.state != State::Failed {
            return TestResult::Fail("SDMA failure not terminal");
        }
        if case == 0
            && (e.proof.ring != [true, false, false, false] || e.hw.io.doorbells.len() != 2)
        {
            return TestResult::Fail("SDMA1 stall misattributed");
        }
    }
    let model = enabled();
    let progress = model.progress.clone();
    let (pool, mut e) = engine(model);
    if !cancel_at(e.start(), &progress, 1) {
        return TestResult::Fail("SDMA reset not reached");
    }
    let count = e.hw.io.writes.len();
    if e.state != State::Resetting
        || run(e.start()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("cancelled SDMA reset replayed");
    }
    drop(e);
    if pool.available() != (1 << 20) - 2 * QUEUE_BYTES {
        return TestResult::Fail("cancelled SDMA rings recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/sdma-navi22-queues",
    sdma_queues_navi22_failures_and_cancellation_are_terminal
);

fn rdna2_sdma_queues_discover_banks_and_prove_every_engine() -> TestResult {
    use crate::amdgpu_cp_navi22::tests::{rdna2_gpu, GC2};
    use crate::amdgpu_discovery as ip;
    for profile in crate::amdgpu_rdna2::PROFILES {
        for count in 1..=4usize {
            let mut gpu = rdna2_gpu(profile, profile.pci_ids[0]);
            let gc = gpu
                .ip_blocks
                .iter_mut()
                .find(|b| b.hw_id == ip::HW_ID_GC)
                .unwrap();
            gc.num_bases = 3;
            gc.base_addrs[2] = (GC2 / 4) as u32;
            let sdma0 = *gpu
                .ip_blocks
                .iter()
                .find(|b| b.hw_id == ip::HW_ID_SDMA0)
                .unwrap();
            for i in 1..count {
                let mut block = sdma0;
                block.instance = i as u8;
                gpu.ip_blocks.push(block);
            }
            let (layout, discovered) = resolve_rdna2(&gpu).unwrap();
            if discovered != count || (count > 2 && layout.sdma_high != Some(GC2)) {
                return TestResult::Fail("SDMA topology or GC2 bank was guessed");
            }
            let mut model = enabled();
            model.sdma_count = count as u32;
            let (pool, mut e) = engine(model);
            e.hw.layout = layout;
            e.queues.truncate(count.min(2));
            for i in 2..count {
                let index = [doorbell::SDMA2, doorbell::SDMA3][i - 2];
                let slot = [fence::Engine::Sdma2, fence::Engine::Sdma3][i - 2];
                e.queues
                    .push(Queue::new(&pool, Kind::Sdma, index, slot).unwrap());
            }
            if run(e.start()).is_err() || run(e.test_ib()).is_err() {
                return TestResult::Fail("discovered SDMA engine ring/IB proof failed");
            }
            for i in 0..4 {
                if e.proof.ring[i] != (i < count) || e.proof.ib_fence[i] != u32::from(i < count) {
                    return TestResult::Fail(
                        "SDMA proof included absent engine or missed active engine",
                    );
                }
            }
            let resets: alloc::vec::Vec<_> =
                e.hw.io
                    .writes
                    .iter()
                    .filter(|(a, _)| *a == r(GRBM_SOFT_RESET))
                    .map(|(_, v)| *v)
                    .collect();
            let expected: alloc::vec::Vec<_> =
                (0..count).flat_map(|i| [1 << (23 + i), 0]).collect();
            if resets != expected
                || e.hw.io.traps != count as u32
                || run(e.start()) != Err(Error::Busy)
            {
                return TestResult::Fail("SDMA reset coverage or replay guard failed");
            }
            crate::amdgpu_cp_navi22::enable_fence_irqs_for(&mut e.hw.io, layout, count).unwrap();
            for i in 0..count {
                if e.hw.io.reg(sdma(i as u32, SDMA0_CNTL)) & 1 == 0 {
                    return TestResult::Fail("SDMA completion source not armed");
                }
            }
            // Duplicate instance numbers and gaps must fail before allocation.
            gpu.ip_blocks.push(sdma0);
            if resolve_rdna2(&gpu).is_ok() {
                return TestResult::Fail("duplicate SDMA accepted");
            }
            gpu.ip_blocks.pop();
            gpu.ip_blocks
                .iter_mut()
                .find(|b| b.hw_id == ip::HW_ID_SDMA0)
                .unwrap()
                .instance = 4;
            if resolve_rdna2(&gpu).is_ok() {
                return TestResult::Fail("invalid SDMA topology accepted");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_sdma_queues_discover_banks_and_prove_every_engine
);

fn rdna2_sdma_numbered_hardware_ids_are_distinct_engines() -> TestResult {
    use crate::amdgpu_cp_navi22::tests::{doorbells, rdna2_gpu};
    use crate::amdgpu_discovery as ip;
    // RX 6750 XT discovery reports SDMA0_HWID:0 and SDMA1_HWID:0,
    // both 5.2.2. Instance numbers are local to each hardware ID.
    let ids = [
        ip::HW_ID_SDMA0,
        ip::HW_ID_SDMA1,
        ip::HW_ID_SDMA2,
        ip::HW_ID_SDMA3,
    ];
    for profile in crate::amdgpu_rdna2::PROFILES {
        for count in 1..=4 {
            let mut gpu = rdna2_gpu(profile, profile.pci_ids[0]);
            let sdma0 = *gpu.ip_blocks.iter().find(|b| b.hw_id == ids[0]).unwrap();
            for &id in &ids[1..count] {
                gpu.ip_blocks
                    .push(crate::amdgpu_discovery::IpBlock { hw_id: id, ..sdma0 });
            }
            if !matches!(resolve_rdna2(&gpu), Ok((_, found)) if found == count) {
                return TestResult::Fail(
                    "numbered SDMA hardware IDs mistaken for duplicate instances",
                );
            }
            let storage = pool(1 << 20);
            let authority = narf_capabilities::Cap::bootstrap();
            authority.revoke();
            // SAFETY: inert mappings, exclusive test pool; construction does
            // not access hardware, and authority is already revoked.
            let owner = match unsafe { Sdma::new_rdna2(&gpu, authority, &storage, doorbells()) } {
                Ok(owner) => owner,
                Err(_) => return TestResult::Fail("numbered SDMA queue preparation refused"),
            };
            if owner.engine.queues.len() != count {
                return TestResult::Fail("numbered SDMA engine omitted or invented");
            }
            drop(owner);
            if storage.available() != 1 << 20 {
                return TestResult::Fail("unpublished numbered SDMA queues leaked");
            }
            // Duplicate records, an ambiguous mixed encoding, foreign IP
            // revisions and a gap remain errors before any allocation/I/O.
            for case in 0..5 {
                let mut bad = rdna2_gpu(profile, profile.pci_ids[0]);
                bad.ip_blocks = gpu.ip_blocks.clone();
                let last = bad
                    .ip_blocks
                    .iter()
                    .position(|b| b.hw_id == ids[count - 1])
                    .unwrap();
                match case {
                    0 => bad.ip_blocks.push(bad.ip_blocks[last]),
                    1 => bad.ip_blocks[last].revision = 0xff,
                    2 => {
                        let mut alias = sdma0;
                        alias.instance = (count - 1) as u8;
                        bad.ip_blocks.push(alias);
                    }
                    3 => bad.ip_blocks[last].instance = 4,
                    _ => {
                        bad.ip_blocks.retain(|b| b.hw_id != ids[0]);
                    }
                }
                if resolve_rdna2(&bad).is_ok() {
                    return TestResult::Fail("invalid numbered SDMA topology accepted");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_sdma_numbered_hardware_ids_are_distinct_engines
);
