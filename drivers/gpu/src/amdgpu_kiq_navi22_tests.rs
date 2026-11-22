use super::*;
use crate::amdgpu_cp_navi22::{
    tests::{cancel_at, enabled, hw, pool, r, run, Model},
    FENCE, QUEUE_BYTES, SCRATCH, VM_FENCE,
};
use core::sync::atomic::Ordering;
use narf_kernel_test::{kernel_test_in, TestResult};

fn engine(model: Model) -> (Pool, Engine<Model>) {
    let pool = pool(1 << 20);
    let kiq = Queue::new(&pool, Kind::Cp, doorbell::KIQ, fence::Engine::Kiq).unwrap();
    let compute = Queue::new(&pool, Kind::Cp, doorbell::MEC_RING0, fence::Engine::Compute).unwrap();
    (
        pool,
        Engine {
            hw: hw(model),
            kiq,
            compute,
            state: State::Prepared,
            proof: Proof::default(),
            mqd_backup: None,
        },
    )
}

fn kiq_navi22_maps_compute_queue_and_runs_ring_and_ib_tests() -> TestResult {
    let mut model = enabled();
    model.regs.insert(r(RLC_CP_SCHEDULERS), 0x1234_5600);
    let (pool, mut e) = engine(model);
    if run(e.init_kiq()).is_err() || e.state != State::KiqReady {
        return TestResult::Fail("KIQ init failed");
    }
    {
        let m = &e.hw.io;
        let kiq = |reg| m.hqd(2, 1, 0, reg);
        let base = e.kiq.address(0);
        if m.reg(r(RLC_CP_SCHEDULERS)) != 0x1234_56c8
            || kiq(CP_HQD_ACTIVE) != 1
            || kiq(CP_HQD_PQ_BASE) != (base >> 8) as u32
            || kiq(CP_HQD_PQ_CONTROL) != 0xd000_090a
            || kiq(CP_HQD_EOP_CONTROL) != 8
            || kiq(CP_HQD_PQ_DOORBELL_CONTROL) != 1 << 30
            || kiq(CP_HQD_PERSISTENT_STATE) != 0x53 << 8
            || kiq(CP_MQD_BASE_ADDR) != e.kiq.address(MQD) as u32
            || kiq(CP_HQD_EOP_BASE_ADDR) != (e.kiq.address(EOP) >> 8) as u32
            || m.reg(r(CP_MEC_DOORBELL_RANGE_LOWER)) != 0
            || m.reg(r(CP_MEC_DOORBELL_RANGE_UPPER)) != 0x450
            || m.reg(r(CP_PQ_STATUS)) & 2 == 0
            || m.reg(r(CP_PQ_WPTR_POLL_CNTL)) & (1 << 31) != 0
            || m.reg(r(GRBM_GFX_CNTL)) != 0
            || m.word(e.kiq.address(MQD)) != 0xc031_0800
            || m.word(e.kiq.address(MQD + 130 * 4)) != 1
            || !m.doorbells.is_empty()
            || e.proof.dequeued
        {
            return TestResult::Fail("KIQ HQD/MQD programming");
        }
        // The doorbell is enabled only after every HQD pointer is written.
        let pos = |a: Reg| m.writes.iter().rposition(|&(w, _)| w == r(a)).unwrap();
        if pos(CP_HQD_PQ_DOORBELL_CONTROL) > pos(CP_HQD_ACTIVE)
            || pos(CP_HQD_PQ_BASE) > pos(CP_HQD_PQ_DOORBELL_CONTROL)
        {
            return TestResult::Fail("KIQ activation order");
        }
    }
    if run(e.map_compute()).is_err() || run(e.test_ib()).is_err() {
        return TestResult::Fail("compute map/test failed");
    }
    let m = &e.hw.io;
    let c = &e.compute;
    let field = |i: u64| m.word(c.address(MQD + i * 4));
    if m.reg(r(CP_MEC_CNTL)) != 0
        || m.resources != [1]
        || m.mapped.len() != 1
        || (m.mapped[0].me, m.mapped[0].pipe, m.mapped[0].queue) != (1, 0, 0)
        || m.mapped[0].doorbell != 6
        || m.mapped[0].mqd != c.address(MQD)
        || m.mapped[0].wptr != c.address(WPTR)
        || field(130) != 0
        || field(136) != (c.address(0) >> 8) as u32
        || field(143) != (1 << 30) | (6 << 2)
        || field(145) != 0xd000_090a
        || field(139) != c.address(RPTR) as u32
        || m.word(c.address(SCRATCH)) != 0xdead_beef
        || m.word(c.address(FENCE)) != 1
        || m.doorbells != [(0, 256), (0, 512), (6, 256), (6, 512)]
        || e.state != State::Verified
        || e.proof
            != (Proof {
                dequeued: false,
                kiq_ring: true,
                compute_ring: true,
                ib_fence: 1,
            })
    {
        return TestResult::Fail("KIQ MAP_QUEUES or compute execution");
    }
    let count = m.writes.len();
    if run(e.init_kiq()) != Err(Error::Busy)
        || run(e.map_compute()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("compute owner replayed");
    }
    drop(e);
    if pool.available() != (1 << 20) - 2 * QUEUE_BYTES {
        return TestResult::Fail("live MQD/ring storage recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_navi22_maps_compute_queue_and_runs_ring_and_ib_tests
);

/// gfx_v10_0_reset_kcq on a hung compute ring: KIQ UNMAP_QUEUES
/// (RESET_QUEUES), the HQD inactive, the MQD restored from its map-time
/// backup with an empty ring, MAP_QUEUES and both ring tests. The stalled
/// job never runs; force completion then shows the ring's last sequence on
/// both fences, and the queue executes again.
fn kiq_compute_reset_restores_an_empty_queue() -> TestResult {
    let (_pool, mut e) = engine(enabled());
    if run(e.init_kiq()).is_err() || run(e.map_compute()).is_err() || run(e.test_ib()).is_err() {
        return TestResult::Fail("compute bring-up");
    }
    let mqd = |e: &Engine<Model>| -> alloc::vec::Vec<u32> {
        (0..mqd::DWORDS as u64)
            .map(|i| e.hw.io.word(e.compute.address(MQD + i * 4)))
            .collect()
    };
    let backup = mqd(&e);
    if e.mqd_backup.as_deref() != Some(&backup[..]) {
        return TestResult::Fail("MQD backup differs from the mapped MQD");
    }
    // A job the engine never runs, and HQD state an unmap would save.
    e.hw.io.stalled[2] = true;
    let seq = e.compute.next_seq();
    let (hw, compute) = (&mut e.hw, &mut e.compute);
    hw.access(|io, l| {
        compute.emit(io, &pm4::release_mem(compute.address(FENCE), seq))?;
        compute.commit(io, l);
        Ok(())
    })
    .unwrap();
    e.hw.io
        .mem
        .insert(e.compute.address(MQD + 4 * 4), 0x0bad_0bad);
    e.hw.io.stalled[2] = false;
    e.hw.io.regs.insert(r(RLC_CNTL), 1);
    let unmapped = e.hw.io.unmapped;
    if run(e.reset_compute()).is_err() || e.state != State::Verified {
        return TestResult::Fail("compute reset failed");
    }
    let m = &e.hw.io;
    if m.unmapped != unmapped + 1
        || m.mapped.len() != 1
        || (m.mapped[0].me, m.mapped[0].doorbell) != (1, 6)
        || mqd(&e) != backup
        || m.word(e.compute.address(FENCE)) != seq - 1
        || m.writes.iter().filter(|w| w.0 == r(RLC_SAFE_MODE)).count() != 2
    {
        return TestResult::Fail("reset kept the hung queue's state or ran its job");
    }
    if e.force_complete_compute().is_err()
        || e.hw.io.word(e.compute.address(FENCE)) != seq
        || e.hw.io.word(e.compute.address(VM_FENCE)) != seq
    {
        return TestResult::Fail("force completion");
    }
    if run(crate::amdgpu_cp_navi22::ring_test(
        &mut e.hw,
        &mut e.compute,
    ))
    .is_err()
    {
        return TestResult::Fail("reset compute ring does not execute");
    }
    // A second reset needs the backup only; a failed one is terminal.
    e.hw.io.stalled[2] = true;
    if run(e.reset_compute()).is_ok() || e.state != State::Failed {
        return TestResult::Fail("a reset whose ring test fails left the queue usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_compute_reset_restores_an_empty_queue
);

/// gfx_v10_0_reset_kgq's KIQ half: CP_VMID_RESET for the VMID and the
/// mapped gfx queue, the MQD and register waits, the KIQ ring test; then
/// the queue's MAP_QUEUES (ENGINE_SEL 4). The KIQ stays verified.
fn kiq_resets_and_remaps_a_gfx_queue() -> TestResult {
    let (pool, mut e) = engine(enabled());
    if run(e.init_kiq()).is_err() || run(e.map_compute()).is_err() || run(e.test_ib()).is_err() {
        return TestResult::Fail("compute bring-up");
    }
    let gfx = Queue::new(&pool, Kind::Cp, doorbell::GFX_RING0, fence::Engine::Gfx).unwrap();
    let map = crate::amdgpu_cp_navi22::GfxQueueMap {
        pipe: 0,
        doorbell: gfx.doorbell,
        mqd: gfx.address(crate::amdgpu_cp_navi22::GFX_MQD),
        wptr: gfx.address(WPTR),
    };
    e.state = State::Mapped;
    if run(e.map_gfx(&[map])).is_err() {
        return TestResult::Fail("gfx map");
    }
    e.state = State::Verified;
    let gfx_mapped = |e: &Engine<Model>| e.hw.io.mapped.iter().filter(|q| q.me == 0).count();
    if run(e.reset_gfx_vmid(3, map)).is_err()
        || e.hw.io.vmid_resets != [1 << 3 | 1 << 16]
        || gfx_mapped(&e) != 0
        || e.state != State::Verified
    {
        return TestResult::Fail("KIQ VMID reset");
    }
    if run(e.remap_gfx(map)).is_err() || gfx_mapped(&e) != 1 || e.state != State::Verified {
        return TestResult::Fail("KIQ gfx remap");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/kiq-navi22", kiq_resets_and_remaps_a_gfx_queue);

fn kiq_navi22_dequeues_inherited_kiq_or_stops_bounded() -> TestResult {
    for stuck in [false, true] {
        let mut model = enabled();
        model.stuck_hqd = stuck;
        // KIQ HQD bank: GRBM select me 2, pipe 1, queue 0.
        model.regs.insert(r(CP_HQD_ACTIVE) | (9 << 40), 1);
        let (_pool, mut e) = engine(model);
        let result = run(e.init_kiq());
        let m = &e.hw.io;
        if stuck {
            if result != Err(Error::Timeout)
                || e.state != State::Failed
                || m.reg(r(GRBM_GFX_CNTL)) != 0
                || m.writes.iter().any(|&(a, _)| a == r(CP_HQD_PQ_BASE))
            {
                return TestResult::Fail("stuck KIQ reprogrammed or left selected");
            }
        } else if result.is_err()
            || !e.proof.dequeued
            || m.hqd(2, 1, 0, CP_HQD_DEQUEUE_REQUEST) != 0
            || m.hqd(2, 1, 0, CP_HQD_ACTIVE) != 1
        {
            return TestResult::Fail("inherited KIQ dequeue sequence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_navi22_dequeues_inherited_kiq_or_stops_bounded
);

fn kiq_navi22_failures_and_cancellation_are_terminal() -> TestResult {
    for case in 0..6 {
        let mut model = enabled();
        let expected = match case {
            0 => {
                model.stalled[1] = true;
                Error::Timeout
            }
            1 => {
                model.stalled[2] = true;
                Error::Timeout
            }
            2 => {
                model.drop_ib_writes = true;
                Error::DataMismatch
            }
            3 => {
                model.regs.insert(r(RLC_CP_SCHEDULERS), u32::MAX);
                Error::DeviceGone
            }
            4 => {
                model.drop_fences = true;
                Error::Timeout
            }
            _ => Error::Revoked,
        };
        let (_pool, mut e) = engine(model);
        if case == 5 {
            e.hw.io.revoke = Some((r(CP_MEC_CNTL), 0, e.hw.authority));
        }
        let result = match run(e.init_kiq()) {
            Err(error) => Err(error),
            Ok(()) => match run(e.map_compute()) {
                Err(error) => Err(error),
                Ok(()) => run(e.test_ib()),
            },
        };
        if result != Err(expected) || e.state != State::Failed {
            return TestResult::Fail("compute failure not terminal");
        }
        if case == 1 && !e.proof.kiq_ring {
            return TestResult::Fail("KIQ ring test should precede compute ring test");
        }
    }
    let mut model = enabled();
    model.stalled[1] = true;
    let progress = model.progress.clone();
    let (pool, mut e) = engine(model);
    run(e.init_kiq()).unwrap();
    // MAP_QUEUES and the KIQ ring test are both rung before the first wait.
    if !cancel_at(e.map_compute(), &progress, 2 << 16) {
        return TestResult::Fail("MAP_QUEUES not submitted");
    }
    let count = e.hw.io.writes.len();
    if e.state != State::Mapping
        || run(e.map_compute()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
        || progress.load(Ordering::SeqCst) != 2 << 16
    {
        return TestResult::Fail("cancelled MAP_QUEUES replayed");
    }
    drop(e);
    if pool.available() != (1 << 20) - 2 * QUEUE_BYTES {
        return TestResult::Fail("cancelled MQD recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_navi22_failures_and_cancellation_are_terminal
);

fn rdna2_kiq_maps_compute_and_runs_ring_and_ib_proofs() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        let gpu = crate::amdgpu_cp_navi22::tests::rdna2_gpu(profile, profile.pci_ids[0]);
        let resolved = Layout::resolve_rdna2(&gpu).unwrap();
        let (_pool, mut engine) = engine(enabled());
        engine.hw.layout = resolved;
        run(engine.init_kiq()).unwrap();
        run(engine.map_compute()).unwrap();
        run(engine.test_ib()).unwrap();
        if engine.state != State::Verified || run(engine.map_compute()) != Err(Error::Busy) {
            return TestResult::Fail("RDNA2 compute proof failed or queue mapping replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_kiq_maps_compute_and_runs_ring_and_ib_proofs
);

/// `amdgpu_gfx_enable_kgq`: one KIQ MAP_QUEUES per gfx ring with
/// ENGINE_SEL 4 and the ME0 encoding (ME field 1), consumed before the KIQ
/// ring test; only after the compute mapping, and a stopped KIQ is terminal.
fn kiq_navi22_maps_gfx_queues_with_engine_sel_4() -> TestResult {
    use crate::amdgpu_cp_navi22::GfxQueueMap;
    let maps = [
        GfxQueueMap {
            pipe: 0,
            doorbell: doorbell::GFX_RING0,
            mqd: 0x8000_1000,
            wptr: 0x8000_2008,
        },
        GfxQueueMap {
            pipe: 1,
            doorbell: doorbell::GFX_RING1,
            mqd: 0x8000_3000,
            wptr: 0x8000_4008,
        },
    ];
    let (_pool, mut e) = engine(enabled());
    if run(e.map_gfx(&maps)) != Err(Error::Busy) || !e.hw.io.mapped.is_empty() {
        return TestResult::Fail("gfx queues mapped before the KIQ was mapped");
    }
    if run(e.init_kiq()).is_err() || run(e.map_compute()).is_err() {
        return TestResult::Fail("KIQ/compute bring-up failed");
    }
    if run(e.map_gfx(&maps)).is_err() || e.state != State::Mapped {
        return TestResult::Fail("gfx MAP_QUEUES or KIQ ring test failed");
    }
    let gfx: alloc::vec::Vec<_> =
        e.hw.io
            .mapped
            .iter()
            .filter(|q| q.me == 0)
            .copied()
            .collect();
    if gfx.len() != 2
        || gfx.iter().zip(&maps).any(|(q, m)| {
            (q.pipe, q.queue, q.doorbell, q.mqd, q.wptr) != (m.pipe, 0, m.doorbell, m.mqd, m.wptr)
        })
    {
        return TestResult::Fail("gfx MAP_QUEUES fields");
    }
    // A KIQ whose ring test cannot complete leaves the owner Failed.
    e.hw.io.stalled[1] = true;
    if run(e.map_gfx(&maps)).is_ok() || e.state != State::Failed {
        return TestResult::Fail("stalled KIQ gfx mapping was not terminal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_navi22_maps_gfx_queues_with_engine_sel_4
);

/// Re-armed after a reset (a fresh model), the KIQ and compute owner maps
/// the same two queues again: sequences from zero, the same MQD backed up,
/// nothing more reserved.
fn kiq_rearm_maps_the_same_queues_again() -> TestResult {
    let up = |e: &mut Engine<Model>| {
        run(e.init_kiq()).is_ok()
            && run(e.map_compute()).is_ok()
            && run(e.test_ib()).is_ok()
            && e.state == State::Verified
    };
    let (pool, mut e) = engine(enabled());
    if !up(&mut e) {
        return TestResult::Fail("first compute bring-up");
    }
    let (seq, free, backup) = (e.compute.seq, pool.available(), e.mqd_backup.clone());
    // SAFETY: the model is replaced below, as a device reset would.
    unsafe { e.rearm() };
    if e.state != State::Prepared
        || (e.kiq.seq, e.compute.seq, e.compute.wptr) != (0, 0, 0)
        || e.mqd_backup.is_some()
    {
        return TestResult::Fail("re-arm kept the last run's state");
    }
    e.hw.io = enabled();
    if !up(&mut e) {
        return TestResult::Fail("re-armed compute bring-up");
    }
    if e.compute.seq != seq || e.mqd_backup != backup || pool.available() != free {
        return TestResult::Fail("re-armed compute left its queues or reserved more");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/kiq-navi22",
    kiq_rearm_maps_the_same_queues_again
);
