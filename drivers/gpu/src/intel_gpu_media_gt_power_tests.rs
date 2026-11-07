// MTL/Arrow standalone media GT (GT1) power management through the
// production MediaGuc/GuCGt/scheduler/Slpc owners on the GuC model. Literal
// identities follow MIT Linux b90c984d: xe_guc_pc.c::{mtl_init_fused_rp_values,
// mtl_get_rpe_freq,pc_adjust_freq_bounds,xe_guc_pc_start,
// xe_guc_pc_gucrc_disable}, xe_gt_idle.c::{xe_gt_idle_enable_pg,
// xe_gt_idle_disable_pg,xe_gt_idle_disable_c6}, xe_uc.c::xe_uc_load_hw,
// regs/xe_regs.h (MTL_MEDIAP_STATE_CAP, MTL_MPE_FREQUENCY),
// regs/xe_gt_regs.h (RC_CONTROL, RC_STATE, POWERGATE_ENABLE) and
// abi/guc_actions_slpc_abi.h, with GT1's GT registers at the GSI offset.
use super::media_gt_sched::{Hw, media_hw, media_tick, media_until, start_media};
use super::*;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_exec::PpgttProbeResult;
use crate::intel_gpu_gt::media::{MediaGuc, MediaGucError, MediaGucState, Retire, retire};
use crate::intel_gpu_guc_sched::SchedulingError;
use crate::intel_gpu_slpc::{FrequencyRange, Limits, PowerProfile, SlpcError, SlpcState};
use crate::intel_gpu_user::{UserBatch, UserContext};
use alloc::vec;
use core::sync::atomic::Ordering::Relaxed;

/// POWERGATE_ENABLE for VCS0, VCS2 and VECS0: MEDIA_POWERGATE_ENABLE plus
/// VDN_HCP/VDN_MFXVDENC_POWERGATE_ENABLE(0) and (2).
const MEDIA_PG: u32 = 0x19a;
/// GT1's RC_CONTROL, RC_STATE and POWERGATE_ENABLE at the GSI offset.
const GT1_RC_CONTROL: u64 = 0x38a090;
const GT1_RC_STATE: u64 = 0x38a094;
const GT1_PG: u64 = 0x38a210;

/// Every SLPC (0x3003) and GUCRC (0x3004) request the GuC model consumed:
/// (action, payload).
fn slpc_trace(w: &Window) -> Vec<(u16, Vec<u32>)> {
    w.0.borrow()
        .slpc_h2g
        .iter()
        .map(|request| (request[0] as u16, request[1..].to_vec()))
        .collect()
}

/// Queued, unconsumed H2G requests of one CT buffer, as (action, payload).
fn queued(memory: &Words) -> Vec<(u16, Vec<u32>)> {
    let words = memory.borrow();
    let (mut head, tail) = (words[0], words[1]);
    let mut requests = Vec::new();
    while head != tail {
        let count = words[1024 + head as usize] & 0xff;
        let request: Vec<u32> = (1..=count)
            .map(|i| words[1024 + ((head + i) & 1023) as usize])
            .collect();
        requests.push((request[0] as u16, request[1..].to_vec()));
        head = (head + count + 1) & 1023;
    }
    requests
}

fn slpc_shared(w: &Window) -> (u32, Words) {
    w.0.borrow()
        .memory
        .iter()
        .find(|(_, m)| m.borrow().len() == 2048 && m.borrow()[0] == 8192)
        .map(|(address, m)| (*address, m.clone()))
        .expect("SLPC shared data")
}

fn gt1_only(w: &Window) -> bool {
    w.0.borrow()
        .writes
        .iter()
        .all(|(reg, _)| media_owned(*reg) || (0x1c0000..0x200000).contains(reg))
}

/// After a verified stop reclaimed every allocation, restart GGTT placement
/// so the next media GuC's ADS lands where the CT model expects it.
fn reclaimed(w: &Window, arena: &Arena) {
    assert_eq!(arena.live_allocations(), 0);
    let mut d = w.0.borrow_mut();
    d.next = 0x2000_0000;
    d.synced.clear();
    d.cpu_synced.clear();
}

/// Run to the first terminal poll, asserting at every tick that GT1 is never
/// published before its SLPC start completed.
fn run_to_terminal(
    guc: &mut MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    from: u64,
) -> (u64, Poll<Result<MediaGucState, MediaGucError>>) {
    for tick in 0..2000 {
        let now = from + tick * 1_000_000;
        let polled = media_tick(guc, w, hw, now);
        if guc.publication().is_some() {
            assert!(
                guc.slpc_status().is_some(),
                "GT1 published before SLPC RUNNING"
            );
        }
        if polled.is_ready() {
            return (now, polled);
        }
    }
    panic!("media GuC made no progress");
}

/// Writes since `from` in order: C6 disable (RC_CONTROL, RC_STATE), then
/// powergating off, all before the media GuC reset (GRDOM_GUC).
fn assert_power_down_before_reset(w: &Window, from: usize) {
    let d = w.0.borrow();
    let writes = &d.writes[from..];
    let at = |pair: (u64, u32)| writes.iter().position(|w| *w == pair).expect("write");
    let (control, state, pg, reset) = (
        at((GT1_RC_CONTROL, 0)),
        at((GT1_RC_STATE, 0)),
        at((GT1_PG, 0)),
        at((0x38941c, 8)),
    );
    assert!(control < state && state < pg && pg < reset);
}

struct Fuses {
    cap: u32,
    efficient: u32,
    unstable: bool,
    reads: RefCell<Vec<u64>>,
}
impl MmioWindow for Fuses {
    fn read32(&self, register: u64) -> u32 {
        self.reads.borrow_mut().push(register);
        let reads = self.reads.borrow().len() as u32;
        match register {
            0x138020 => self.cap ^ u32::from(self.unstable && reads % 2 == 0),
            0x13802c => self.efficient,
            _ => panic!("unexpected media frequency register {register:x}"),
        }
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("frequency discovery wrote MMIO");
    }
}

fn fuses(cap: u32, efficient: u32) -> Fuses {
    Fuses {
        cap,
        efficient,
        unstable: false,
        reads: RefCell::new(Vec::new()),
    }
}

fn smoke_media_gt_slpc_limits_decode_gt1_fuses_only() -> TestResult {
    // MTL_RPN_CAP_MASK [24:16], MTL_RP0_CAP_MASK [8:0], MTL_RPE_MASK [8:0],
    // decode_freq = DIV_ROUND_CLOSEST(raw * 50, 3). Bits outside the fields
    // are ignored, and the media limits carry no workaround constraint.
    for (cap, efficient, expected) in [
        ((6 << 16) | 69, 30, (100, 500, 1150)),
        (0xfe06_fe45, 0xffff_fe1e, (100, 500, 1150)),
        ((336 << 16) | 496, 416, (5600, 6933, 8267)),
    ] {
        let window = fuses(cap, efficient);
        let limits = Limits::read_media(&window).unwrap();
        assert_eq!((limits.rpn_mhz, limits.rpe_mhz, limits.rp0_mhz), expected);
        assert_eq!((limits.min_mhz, limits.max_mhz), (expected.0, expected.2));
        assert_eq!(
            *window.reads.borrow(),
            [0x138020, 0x138020, 0x13802c, 0x13802c],
            "two stable samples of GT1's own fuses only"
        );
    }
    // Lost access, an absent RPn and an RPe outside RPn..RP0 never become
    // usable clocks.
    for (cap, efficient) in [
        (u32::MAX, 30),
        (69, 30),
        ((6 << 16) | 69, 3),
        ((6 << 16) | 69, 100),
        ((6 << 16) | 69, u32::MAX),
    ] {
        assert_eq!(
            Limits::read_media(&fuses(cap, efficient)),
            Err(SlpcError::Unavailable)
        );
    }
    let mut unstable = fuses((6 << 16) | 69, 30);
    unstable.unstable = true;
    assert_eq!(Limits::read_media(&unstable), Err(SlpcError::Unavailable));
    // The same BAR through both roles: GT0 reads MTL_RP_STATE_CAP and
    // MTL_GT_RPE_FREQUENCY, GT1 its MTL_MEDIAP_STATE_CAP and MTL_MPE_FREQUENCY.
    let (w, _) = model();
    w.0.borrow_mut().regs.extend([
        (0xd8c, (12 << 22) | (70 << 14)),
        (0x138000, (18 << 16) | 180),
        (0x13800c, 90),
        (0x138020, (6 << 16) | 69),
        (0x13802c, 30),
    ]);
    let gt0 = Limits::read(&w, MTL, 0x7d55).unwrap();
    assert_eq!((gt0.rpn_mhz, gt0.rpe_mhz, gt0.rp0_mhz), (300, 1500, 3000));
    let gt1 = Limits::read_media(&crate::intel_gpu_gt::media::MediaGsi::new(w.clone())).unwrap();
    assert_eq!((gt1.rpn_mhz, gt1.rpe_mhz, gt1.rp0_mhz), (100, 500, 1150));
    assert!(w.0.borrow().writes.is_empty());
    // xe_gt_idle_enable_pg: media enable with any VCS/VECS, both VDN bits per
    // present VCSn, nothing for VECS alone or an empty GT.
    use crate::intel_gpu_engine::EngineSet;
    use crate::intel_gpu_gt::media::powergate_enable;
    assert_eq!(
        powergate_enable(EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs0])),
        MEDIA_PG
    );
    assert_eq!(powergate_enable(EngineSet::of(&[Engine::Vecs1])), 0x2);
    assert_eq!(
        powergate_enable(EngineSet::of(&[Engine::Vcs7])),
        0x2 | 0b11 << 17
    );
    assert_eq!(powergate_enable(EngineSet::default()), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_slpc_limits_decode_gt1_fuses_only
);

fn smoke_media_gt_slpc_start_bounds_profile_and_rc6_on_media_guc() -> TestResult {
    SLPC_FIXTURE_MODE.store(0, Relaxed);
    let (w, arena) = media_model();
    // GT0's fuses as decoys: GT1's SLPC must use only its media copies.
    w.0.borrow_mut()
        .regs
        .extend([(0x138000, (18 << 16) | 180), (0x13800c, 90)]);
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = run_to_terminal(&mut guc, &w, &mut hw, 1);
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let status = guc.slpc_status().expect("confirmed GT1 SLPC");
    assert_eq!(
        (
            status.limits.rpn_mhz,
            status.limits.rpe_mhz,
            status.limits.rp0_mhz,
            status.limits.min_mhz,
            status.limits.max_mhz
        ),
        (100, 500, 1150, 100, 1150)
    );
    // Firmware defaults 900/3500 MHz: pc_adjust_freq_bounds lowers only the
    // max above RP0; the min stays as firmware set it.
    assert_eq!(
        status.range,
        FrequencyRange {
            min_mhz: 900,
            max_mhz: 1150
        }
    );
    assert_eq!(status.profile, PowerProfile::Base);
    let (address, _) = slpc_shared(&w);
    // xe_guc_pc_start on the media GuC: RESET with the shared data, the
    // task-state query, pc_set_max_freq(RP0), NARF's acknowledged readback,
    // GUCRC_FIRMWARE_CONTROL, the compute strategy and the Base profile.
    assert_eq!(
        slpc_trace(&w),
        [
            (0x3003, vec![0x002, address, 0]),
            (0x3003, vec![0x502, address, 0]),
            (0x3003, vec![0x602, 7, 1150]),
            (0x3003, vec![0x502, address, 0]),
            (0x3004, vec![1]),
            (0x3003, vec![0x602, 26, 1]),
            (0x3003, vec![0x602, 27, 0]),
        ]
    );
    {
        let d = w.0.borrow();
        assert_eq!(d.regs[&GT1_PG], MEDIA_PG, "xe_gt_idle_enable_pg on GT1");
        for reg in [0xa090, 0xa094, 0xa210] {
            assert!(!d.writes.iter().any(|(r, _)| *r == reg), "GT0 {reg:x}");
        }
    }
    assert!(gt1_only(&w));

    // GT1 MC6 residency (MTL_MEDIA_MC6 0x138048 in 1.28 us units) and actual
    // CAGF frequency (MTL_MIRROR_TARGET_WP1 0x380c60 bits [8:0] in 16.67 MHz units).
    w.0.borrow_mut()
        .regs
        .extend([(0x138048, 10_000), (0x380c60, (0xdead << 9) | 63)]);
    assert_eq!(guc.mc6_residency_ms(), Some(12));
    assert_eq!(guc.act_freq_mhz(), Some(1050));

    // Media-GT recovery: the stop first hands C6 back to the host
    // (xe_uc_gucrc_disable), disables C6 and powergating through GT1's window
    // and only then resets the media GuC.
    let from = w.0.borrow().writes.len();
    let ct = ct_memory(&w);
    guc.begin_stop(now + 1);
    assert_eq!(guc.slpc_status(), None);
    assert_eq!(guc.mc6_residency_ms(), None);
    assert_eq!(guc.act_freq_mhz(), None);
    assert_eq!(queued(&ct), [(0x3004, vec![0])]);
    assert_power_down_before_reset(&w, from);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    drop(guc);
    reclaimed(&w, &arena);

    // The recovery owner (one fresh media GuC) enables powergating and runs
    // the whole SLPC start again before GT1 publishes.
    let traced = slpc_trace(&w).len();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = run_to_terminal(&mut guc, &w, &mut hw, 1);
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert_eq!(slpc_trace(&w)[traced..].len(), 7);
    assert_eq!(slpc_trace(&w)[traced + 4], (0x3004, vec![1]));
    assert_eq!(
        w.0.borrow()
            .writes
            .iter()
            .filter(|write| **write == (GT1_PG, MEDIA_PG))
            .count(),
        2
    );

    // Suspend/park: the runtime's media retirement runs the same teardown
    // before the verified stop and drops the owner once it is proven.
    let from = w.0.borrow().writes.len();
    let ct = ct_memory(&w);
    let mut slot = Some(guc);
    assert_eq!(
        retire(&mut None, &mut slot, &w, now + 1, || true),
        Retire::Pending
    );
    assert_eq!(queued(&ct), [(0x3004, vec![0])]);
    assert_power_down_before_reset(&w, from);
    let mut done = false;
    for tick in 2..200 {
        media_hw(&w, &hw);
        match retire(&mut None, &mut slot, &w, now + tick, || true) {
            Retire::Done => {
                done = true;
                break;
            }
            Retire::Pending => {}
            Retire::Retained => return TestResult::Fail("media stop retained"),
        }
    }
    assert!(done && slot.is_none());
    assert_eq!(w.0.borrow().regs[&GT1_PG], 0);
    assert_eq!(w.0.borrow().regs[&GT1_RC_CONTROL], 0);
    assert!(gt1_only(&w));
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_slpc_start_bounds_profile_and_rc6_on_media_guc
);

fn smoke_media_gt_slpc_failures_stop_gt1_and_disable_c6() -> TestResult {
    // xe_uc_load_hw fails the uC load on any xe_guc_pc_start error: global
    // ERROR (1), no RUNNING within the extended start bound (3) and a
    // refused bound (4) stop GT1 before publication. GUCRC was never handed
    // to firmware, so no HOST_CONTROL is sent, but C6 and powergating are
    // still turned off before the media GuC reset.
    for mode in [1, 3, 4] {
        SLPC_FIXTURE_MODE.store(mode, Relaxed);
        let (w, arena) = media_model();
        let mut guc = start_media(&w, &arena);
        let mut hw = Hw::default();
        let (now, polled) = run_to_terminal(&mut guc, &w, &mut hw, 1);
        assert_eq!(polled, Poll::Ready(Err(MediaGucError::Slpc)), "mode {mode}");
        assert_eq!(guc.publication(), None);
        assert_eq!(guc.error(), Some(MediaGucError::Slpc));
        let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| {
            *p == Poll::Ready(Ok(MediaGucState::Stopped))
        });
        assert!(polled.is_ready());
        assert!(!slpc_trace(&w).iter().any(|(action, _)| *action == 0x3004));
        {
            let d = w.0.borrow();
            let enable = d.writes.iter().position(|w| *w == (GT1_PG, MEDIA_PG));
            let disable = d.writes.iter().position(|w| *w == (GT1_PG, 0));
            assert!(enable.unwrap() < disable.unwrap());
            assert!(d.writes.contains(&(GT1_RC_CONTROL, 0)));
        }
        assert!(gt1_only(&w));
        drop(guc);
        assert_eq!(arena.live_allocations(), 0);
    }

    // Unreadable GT1 fuses refuse before the shared data is allocated or any
    // SLPC request is sent; GT1 stops and powergating is undone.
    SLPC_FIXTURE_MODE.store(0, Relaxed);
    let (w, arena) = media_model();
    w.0.borrow_mut().regs.insert(0x138020, u32::MAX);
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = run_to_terminal(&mut guc, &w, &mut hw, 1);
    assert_eq!(
        polled,
        Poll::Ready(Err(MediaGucError::Gt(GtError::Scheduling(
            SchedulingError::Slpc(SlpcError::Unavailable)
        ))))
    );
    assert!(slpc_trace(&w).is_empty());
    assert!(
        !w.0.borrow()
            .memory
            .values()
            .any(|m| m.borrow().len() == 2048 && m.borrow()[0] == 8192)
    );
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert!(polled.is_ready());
    assert_eq!(w.0.borrow().regs[&GT1_PG], 0);
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // A refused compute strategy is not a start failure: xe_guc_pc_start
    // overwrites its result with the power profile's.
    SLPC_FIXTURE_MODE.store(11, Relaxed);
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = run_to_terminal(&mut guc, &w, &mut hw, 1);
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let trace = slpc_trace(&w);
    assert_eq!(
        trace[trace.len() - 2..],
        [(0x3003, vec![0x602, 26, 1]), (0x3003, vec![0x602, 27, 0]),]
    );
    assert_eq!(guc.slpc_status().unwrap().profile, PowerProfile::Base);
    SLPC_FIXTURE_MODE.store(0, Relaxed);

    // SLPC lost after publication (global state leaves RUNNING): as on GT0,
    // the confirmed status disappears and the published engines keep working.
    let (_, shared) = slpc_shared(&w);
    shared.borrow_mut()[1] = 5;
    let _ = media_tick(&mut guc, &w, &mut hw, now + 1);
    assert_eq!(guc.slpc_status(), None);
    let publication = guc.publication().expect("GT1 stays published");
    let context = UserContext::for_engine(Engine::Vcs2);
    let (batch, result) = PpgttProbeResult::prepare(MTL).unwrap();
    let (_, fence) = guc
        .submit_user(now + 2, context.clone(), UserBatch(batch), None)
        .unwrap();
    let (now, _) = media_until(&mut guc, &w, &mut hw, now + 3, |_| fence.result().is_some());
    assert_eq!(fence.result(), Some(Ok(())));
    assert_eq!(result.verify(), Ok(()));
    assert_eq!(context.check_epoch(publication.epoch), Ok(()));
    // GUCRC was handed to firmware, so the stop returns it.
    let ct = ct_memory(&w);
    guc.begin_stop(now + 1);
    assert_eq!(queued(&ct), [(0x3004, vec![0])]);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_slpc_failures_stop_gt1_and_disable_c6
);

fn smoke_media_gt_power_absent_leaves_gt0_slpc_and_stop_unchanged() -> TestResult {
    // GT0 (Primary role) keeps its main-GT start: fused MTL_RP_STATE_CAP
    // limits, clamped and programmed bounds, the profile and GUCRC last, no
    // strategy. Its stop programs no RC/powergate register and sends no
    // HOST_CONTROL: only a media owner that started power management does.
    SLPC_FIXTURE_MODE.store(0, Relaxed);
    let (w, arena, mut gt) = hardware_model(MTL, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    w.0.borrow_mut()
        .regs
        .extend([(0x138020, (6 << 16) | 69), (0x13802c, 30)]);
    gt.begin_slpc(30).unwrap();
    let mut registered = BTreeMap::new();
    for now in 31..63 {
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
    }
    assert_eq!(gt.slpc(), SlpcState::Running);
    let status = gt.slpc_status().unwrap();
    assert_eq!(
        (
            status.limits.rpn_mhz,
            status.limits.rpe_mhz,
            status.limits.rp0_mhz
        ),
        (300, 1500, 3000)
    );
    let events: Vec<(u16, u32, u32)> = slpc_trace(&w)
        .iter()
        .map(|(action, r)| (*action, r[0], if r[0] == 0x602 { r[1] } else { 0 }))
        .collect();
    assert_eq!(
        events,
        [
            (0x3003, 0x002, 0),
            (0x3003, 0x502, 0),
            (0x3003, 0x602, 28),
            (0x3003, 0x602, 6),
            (0x3003, 0x602, 7),
            (0x3003, 0x502, 0),
            (0x3003, 0x602, 27),
            (0x3004, 1, 0),
        ]
    );
    let from = w.0.borrow().writes.len();
    let ct = ct_memory(&w);
    hardware_stop(&mut gt, &w, 0xdfc);
    assert!(queued(&ct).is_empty(), "no GUCRC_HOST_CONTROL from GT0");
    assert!(!w.0.borrow().writes[from..].iter().any(|(reg, _)| matches!(
        reg,
        0xa090 | 0xa094 | 0xa210 | 0x38a090 | 0x38a094 | 0x38a210
    )));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    // Without narf.intel.media_gt=1 there is no media owner: retirement is
    // done without any MMIO.
    let (reads, writes) = (w.0.borrow().mmio_reads.get(), w.0.borrow().writes.len());
    assert_eq!(
        retire::<Window, Window, Arena>(&mut None, &mut None, &w, 0, || true),
        Retire::Done
    );
    assert_eq!(
        (w.0.borrow().mmio_reads.get(), w.0.borrow().writes.len()),
        (reads, writes)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_power_absent_leaves_gt0_slpc_and_stop_unchanged
);
