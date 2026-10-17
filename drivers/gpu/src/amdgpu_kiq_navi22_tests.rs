use super::*;
use crate::amdgpu_cp_navi22::{
    tests::{cancel_at, enabled, hw, pool, r, run, Model},
    FENCE, QUEUE_BYTES, SCRATCH,
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
