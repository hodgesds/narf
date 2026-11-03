//! Live repartitioning tests. The register model supplies only hardware
//! ACKs (PM demand, DBUF power, CDCLK lock/crawl) and a frame counter that
//! advances on every read; ordering is asserted from the write trace.
use super::*;
use crate::intel_gpu_pmdemand::Params;
use crate::intel_gpu_xelpg_resources::{commit, compute, PlaneRequest, Request};
use crate::intel_gpu_xelpg_wm::{Latency, Tiling};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Default)]
pub(crate) struct Live {
    regs: RefCell<BTreeMap<u64, u32>>,
    pub(crate) writes: RefCell<Vec<(u64, u32)>>,
    pub(crate) drop_write: Cell<u64>,
    nth: Cell<(u64, u32)>,
    seen: Cell<u32>,
    pub(crate) uncovered: Cell<u32>,
    /// `narf_arch::interrupts_enabled()` at every `PIPEDSL` sample and
    /// primary `PLANE_CTL` / `PLANE_SURF` / `CURBASE` write.
    pub(crate) irq_log: RefCell<Vec<(u64, bool)>>,
}

/// Registers whose access the IRQ log records: `PIPEDSL` (read) and the
/// primary `PLANE_CTL`, `PLANE_SURF` and `CURBASE` (written) of any pipe.
fn irq_logged(r: u64, write: bool) -> bool {
    (0..4u64).any(|p| {
        let base = 0x70000 + p * 0x1000;
        if write {
            [0x180, 0x19c, 0x084].iter().any(|o| r == base + o)
        } else {
            r == base
        }
    })
}

impl Live {
    pub(crate) fn new() -> Self {
        let hw = Self::default();
        hw.drop_write.set(u64::MAX);
        hw
    }
    pub(crate) fn set(&self, r: u64, v: u32) {
        self.regs.borrow_mut().insert(r, v);
    }
    pub(crate) fn get(&self, r: u64) -> u32 {
        *self.regs.borrow().get(&r).unwrap_or(&0)
    }
    /// Drop only the `n`th write to `r` (1-based).
    fn drop_nth(&self, r: u64, n: u32) {
        self.nth.set((r, n));
    }
    fn dropped(&self, r: u64) -> bool {
        let (reg, n) = self.nth.get();
        if r != reg {
            return false;
        }
        self.seen.set(self.seen.get() + 1);
        self.seen.get() == n
    }
    /// After every CDCLK register write the requested PM demand must cover
    /// the clock the hardware now runs (frequency and voltage level).
    fn monitor(&self, r: u64) {
        if ![0x46070, 0x46008, 0x46000].contains(&r) {
            return;
        }
        let khz = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(self);
        let held = crate::intel_gpu_pmdemand::Params::decode(self.get(0x45230), self.get(0x45234));
        if khz != 0
            && (u32::from(held.cdclk_freq_mhz) * 1000 < khz
                || held.voltage_index < crate::intel_gpu_xelpg_cdclk::voltage_level(khz))
        {
            self.uncovered.set(self.uncovered.get() + 1);
        }
    }
    pub(crate) fn first(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .position(|(o, _)| *o == r)
            .expect("register written")
    }
    pub(crate) fn last(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .rposition(|(o, _)| *o == r)
            .expect("register written")
    }
    pub(crate) fn wrote(&self, r: u64) -> bool {
        self.writes.borrow().iter().any(|(o, _)| *o == r)
    }
    pub(crate) fn light(&self, pipe: u64) {
        self.set(0x70008 + pipe * 0x1000, 0xc000_0000);
        self.set(0x70180 + pipe * 0x1000, 0x8000_0000);
        self.set(0x7019c + pipe * 0x1000, 0x0100_0000);
    }
}

impl MmioWindow for Live {
    fn read32(&self, r: u64) -> u32 {
        if irq_logged(r, false) {
            self.irq_log
                .borrow_mut()
                .push((r, narf_arch::interrupts_enabled()));
        }
        let v = self.get(r);
        if (0x70040..0x74000).contains(&r) && r & 0xfff == 0x040 {
            // PIPE_FRMCOUNT: every read observes a later frame.
            self.set(r, v.wrapping_add(1));
            return v;
        }
        if r == 0x46070 {
            let mut v = v;
            if v & (1 << 31) != 0 {
                v |= 1 << 30;
            }
            if v & (1 << 23) != 0 {
                v |= 1 << 22;
            }
            return v;
        }
        v
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if irq_logged(r, true) {
            self.irq_log
                .borrow_mut()
                .push((r, narf_arch::interrupts_enabled()));
        }
        if r == self.drop_write.get() || self.dropped(r) {
            return;
        }
        let mut stored = v;
        if r == 0x45234 {
            stored &= !(1 << 31);
        }
        if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) {
            stored = if v & (1 << 31) != 0 {
                v | (1 << 30)
            } else {
                v & !(1 << 30)
            };
        }
        if r == 0x46070 {
            stored &= !((1 << 30) | (1 << 22));
        }
        if (0x70000..0x74000).contains(&r) && r & 0xfff == 0x008 {
            // TRANSCONF STATE follows ENABLE.
            stored = (v & !(1 << 30)) | ((v >> 1) & (1 << 30));
        }
        if (0x70000..0x74000).contains(&r) && r & 0xfff == 0x19c {
            // PLANE_SURFLIVE latches the armed surface.
            self.set(r + 0x10, v);
        }
        self.set(r, stored);
        self.monitor(r);
    }
}

pub(crate) fn latency() -> Latency {
    Latency::adjust([6, 8, 10, 12, 14, 16], 0)
}

fn pipe_req(
    pixel: u32,
    (h, ht): (u16, u16),
    (v, vt): (u16, u16),
    port: u32,
    phy: u8,
) -> PipeRequest {
    let mut planes = [None; PLANES];
    planes[0] = Some(PlaneRequest {
        width: h,
        height: v,
        cpp: 4,
        tiling: Tiling::Linear,
    });
    PipeRequest {
        pixel_rate_khz: pixel,
        hdisplay: h,
        htotal: ht,
        vdisplay: v,
        vtotal: vt,
        planes,
        cursor_visible: false,
        port_clock_khz: port,
        combo_phy: Some(phy),
    }
}

fn panel() -> PipeRequest {
    pipe_req(65_000, (1024, 1344), (768, 806), 810_000, 0)
}

fn external() -> PipeRequest {
    pipe_req(74_250, (1280, 1650), (720, 750), 270_000, 1)
}

fn state(pipes: &[(usize, PipeRequest)]) -> State {
    let mut request = Request {
        pipes: [None; PIPES],
        min_cdclk_khz: 0,
    };
    for &(p, r) in pipes {
        request.pipes[p] = Some(r);
    }
    compute(&request, &latency()).unwrap()
}

/// Program `old` with every pipe off, then light the `lit` pipes.
pub(crate) fn programmed(old: &State, lit: &[u64]) -> Live {
    let hw = Live::new();
    commit(&hw, old).unwrap();
    for &p in lit {
        hw.light(p);
    }
    hw.writes.borrow_mut().clear();
    hw
}

fn assert_image(hw: &Live, image: &[(u64, u32)]) {
    for &(r, v) in image {
        assert_eq!(hw.get(r), v, "register {r:#x}");
    }
}

fn smoke_xelpg_live_plan_orders_ddb_and_refuses_cycles() -> TestResult {
    // order(): A must shrink before D can grow into A's old blocks.
    let e = |start, end| Entry { start, end };
    let current = [e(0, 1000), e(0, 0), e(0, 0), e(1000, 2048)];
    let target = [e(0, 500), e(0, 0), e(0, 0), e(500, 2048)];
    assert_eq!(
        order(current, target, 0x9, 0),
        Ok(vec![(0, true), (3, false)])
    );
    // Pending enables keep a vblank after the last changed lit pipe too.
    assert_eq!(
        order(current, target, 0x9, 0x2),
        Ok(vec![(0, true), (3, true)])
    );
    // Reverse pipe order when nothing blocks; unchanged pipes never wait.
    let grow = [e(0, 1000), e(0, 0), e(0, 0), e(1500, 2048)];
    assert_eq!(
        order(current, grow, 0x9, 0),
        Ok(vec![(3, true), (0, false)])
    );
    // Swapping halves can never be ordered: typed refusal, no writes.
    let swap = [e(1048, 2048), e(0, 0), e(0, 0), e(0, 1048)];
    assert_eq!(
        order(current, swap, 0x9, 0),
        Err(ResourceError::DdbOrdering)
    );
    // plan(): adding the external pipe shrinks the joined panel first,
    // then unjoins with the lit pipe selected; PM demand brackets all.
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    assert!(a.dbuf.joined && !ab.dbuf.joined);
    assert_eq!(a.cdclk, ab.cdclk);
    assert_eq!(
        plan(&a, &ab, 0x1),
        Ok(vec![
            Step::PmDemandPre,
            Step::UpdatePipe {
                pipe: 0,
                wait_vblank: true
            },
            Step::MbusUnjoin { select: Some(0) },
            Step::OffPipes,
            Step::PmDemandPost,
        ])
    );
    // Removing it joins before the panel regrows.
    assert_eq!(
        plan(&ab, &a, 0x1),
        Ok(vec![
            Step::PmDemandPre,
            Step::MbusJoin { select: Some(0) },
            Step::UpdatePipe {
                pipe: 0,
                wait_vblank: false
            },
            Step::OffPipes,
            Step::PmDemandPost,
        ])
    );
    // Two unjoined pipes keep their slices when a third is added: only
    // trackers/DBOX are rebalanced.
    let abc = state(&[
        (0, panel()),
        (1, external()),
        (2, pipe_req(74_250, (1280, 1650), (720, 750), 270_000, 2)),
    ]);
    let steps = plan(&ab, &abc, 0x3).unwrap();
    assert!(steps.contains(&Step::MbusRebalance));
    assert!(!steps
        .iter()
        .any(|s| matches!(s, Step::MbusJoin { .. } | Step::MbusUnjoin { .. })));
    // A raised CDCLK goes before the planes, a lowered one after them.
    let mut fast = panel();
    fast.pixel_rate_khz = 700_000;
    let big = state(&[(0, panel()), (1, fast)]);
    let steps = plan(&a, &big, 0x1).unwrap();
    assert!(steps.contains(&Step::CdclkPre) && !steps.contains(&Step::CdclkPost));
    let steps = plan(&big, &a, 0x1).unwrap();
    assert!(steps.contains(&Step::CdclkPost) && !steps.contains(&Step::CdclkPre));
    // Refusals: a lit pipe whose configuration changes, an empty or
    // non-common live set.
    let mut other = panel();
    other.cursor_visible = true;
    let changed = state(&[(0, other), (1, external())]);
    assert_eq!(plan(&a, &changed, 0x1), Err(ResourceError::LivePipeChanged));
    assert_eq!(plan(&a, &ab, 0), Err(ResourceError::Unsupported));
    assert_eq!(plan(&a, &ab, 0x2), Err(ResourceError::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_plan_orders_ddb_and_refuses_cycles
);

fn smoke_xelpg_live_adds_external_pipe_while_panel_stays_lit() -> TestResult {
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    let hw = programmed(&a, &[0]);
    commit_live(&hw, &a, &ab, 0x1).unwrap();
    // The panel is never stopped or disabled.
    assert!(!hw.wrote(0x70008) && !hw.wrote(0x70180));
    // PM demand pre, panel WM/DDB armed by SURF, MBUS unjoin, then the
    // external pipe's image, then PM demand post.
    let req = hw.first(0x45234);
    let panel_ddb = hw.first(0x7027c);
    let arm = hw.first(0x7019c);
    let unjoin = hw.first(0x4438c);
    let external_ddb = hw.first(0x7127c);
    assert!(req < panel_ddb && panel_ddb < arm && arm < unjoin && unjoin < external_ddb);
    // Pre-plane max(old, new) already equals the new demand here, so the
    // post-plane request is unchanged and not re-initiated.
    assert!(hw.last(0x45234) < panel_ddb);
    assert_eq!(hw.get(0x7019c), 0x0100_0000, "arm rewrites the live SURF");
    assert!(hw.wrote(0x70084), "cursor DDB armed by CURBASE");
    assert_image(&hw, &ab.pipe_registers(0, false).unwrap());
    assert_image(&hw, &ab.pipe_registers(1, false).unwrap());
    // Unjoined 2x2 hashing with the lit panel selected; both DBOXes
    // carry 8 A-credits; trackers drop to ratio 2.
    assert_eq!(hw.get(0x4438c) & dbuf::MBUS_CTL_MASK, 0);
    assert_eq!(hw.get(0x7003c), 0x0103_ca48);
    assert_eq!(hw.get(0x7103c), 0x0103_ca48);
    for r in dbuf::DBUF_CTL {
        assert_eq!(hw.get(r) & 0xc0ff_0000, 0xc041_0000);
    }
    assert_eq!(
        Params::decode(hw.get(0x45230), hw.get(0x45234)),
        ab.pmdemand
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_adds_external_pipe_while_panel_stays_lit
);

fn smoke_xelpg_live_panel_arm_runs_inside_irq_masked_evasion() -> TestResult {
    // intel_pipe_update_start/_end around the lit panel's WM/DDB update:
    // the scanline sample that leaves the evasion window, the image and
    // the SURF/CURBASE arm writes all run with local interrupts masked,
    // and the caller's interrupt state is restored afterwards.
    let irqs = narf_arch::interrupts_enabled();
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    let hw = programmed(&a, &[0]);
    hw.irq_log.borrow_mut().clear();
    if commit_live(&hw, &a, &ab, 0x1).is_err() {
        return TestResult::Fail("the live add must commit");
    }
    let log = hw.irq_log.borrow();
    let regs: Vec<u64> = log.iter().map(|(r, _)| *r).collect();
    if regs != [0x70000, 0x7019c, 0x70084] {
        return TestResult::Fail("one PIPEDSL(A) sample, then the SURF and CURBASE arms");
    }
    if irqs && log.iter().any(|(_, enabled)| *enabled) {
        return TestResult::Fail("evasion and arm writes must run IRQ-masked");
    }
    if narf_arch::interrupts_enabled() != irqs {
        return TestResult::Fail("the local interrupt state must be restored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_panel_arm_runs_inside_irq_masked_evasion
);

fn smoke_xelpg_live_removes_pipe_and_rejoins_before_growth() -> TestResult {
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    // The caller already stopped the external pipe.
    let hw = programmed(&ab, &[0]);
    commit_live(&hw, &ab, &a, 0x1).unwrap();
    assert!(!hw.wrote(0x70008) && !hw.wrote(0x70180));
    let join = hw.first(0x4438c);
    assert!(join < hw.first(0x7027c), "join precedes panel growth");
    assert_eq!(hw.get(0x4438c) & dbuf::MBUS_CTL_MASK, 0xc000_0000);
    assert_eq!(hw.get(0x7003c), 0x0103_ca4c);
    for r in dbuf::DBUF_CTL {
        assert_eq!(hw.get(r) & 0xc0ff_0000, 0xc043_0000);
    }
    assert_image(&hw, &a.pipe_registers(0, false).unwrap());
    for (r, v) in a.pipe_registers(1, false).unwrap() {
        assert_eq!((hw.get(r), v), (0, 0), "removed pipe cleared {r:#x}");
    }
    assert_eq!(Params::decode(hw.get(0x45230), hw.get(0x45234)), a.pmdemand);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_removes_pipe_and_rejoins_before_growth
);

type RefusalCase<'a> = (&'a dyn Fn(&Live), ResourceError);

fn smoke_xelpg_live_refuses_before_writes() -> TestResult {
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    let cases: [RefusalCase<'_>; 6] = [
        // Unknown firmware clock: Linux relocks only with all pipes off.
        (&|hw| hw.set(0x46000, 0), ResourceError::RequiresPipesOff),
        (&|hw| hw.set(0x70008, 0), ResourceError::Busy),
        (&|hw| hw.set(0x71008, 0xc000_0000), ResourceError::Busy),
        (&|hw| hw.set(0x43208, 1 << 31), ResourceError::Busy),
        (&|hw| hw.set(0x70b08, 1), ResourceError::Busy),
        (&|hw| hw.set(0x70240, 0x8000_0001), ResourceError::Diverged),
    ];
    for (setup, error) in cases {
        let hw = programmed(&a, &[0]);
        setup(&hw);
        assert_eq!(commit_live(&hw, &a, &ab, 0x1), Err(error));
        assert!(hw.writes.borrow().is_empty(), "{error:?} wrote");
    }
    // A different known clock than the programmed state is divergence.
    let hw = programmed(&a, &[0]);
    hw.set(0x46008, 0);
    hw.set(0x46000, (7 << 19) | 612);
    assert_eq!(commit_live(&hw, &a, &ab, 0x1), Err(ResourceError::Diverged));
    assert!(hw.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_refuses_before_writes
);

fn smoke_xelpg_live_failure_undoes_in_reverse_with_panel_lit() -> TestResult {
    let a = state(&[(0, panel())]);
    let ab = state(&[(0, panel()), (1, external())]);
    let hw = programmed(&a, &[0]);
    let before0 = hw.get(0x45230);
    let before1 = hw.get(0x45234);
    // The external pipe's DDB write fails after the panel shrank and the
    // MBUS unjoined: undo rejoins first, then regrows the panel.
    hw.drop_write.set(0x7127c);
    assert_eq!(commit_live(&hw, &a, &ab, 0x1), Err(ResourceError::Readback));
    assert!(!hw.wrote(0x70008) && !hw.wrote(0x70180));
    assert_image(&hw, &a.pipe_registers(0, false).unwrap());
    assert_eq!(hw.get(0x4438c) & dbuf::MBUS_CTL_MASK, 0xc000_0000);
    assert!(
        hw.last(0x4438c) < hw.last(0x7027c),
        "rejoin before regrowth"
    );
    assert_eq!(hw.get(0x7003c), 0x0103_ca4c);
    assert_eq!(hw.get(0x7103c), 0);
    for r in dbuf::DBUF_CTL {
        assert_eq!(hw.get(r) & 0xc0ff_0000, 0xc043_0000);
    }
    for (r, _) in ab.pipe_registers(1, false).unwrap() {
        assert_eq!(hw.get(r), 0, "external pipe restored {r:#x}");
    }
    assert_eq!((hw.get(0x45230), hw.get(0x45234)), (before0, before1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_failure_undoes_in_reverse_with_panel_lit
);

fn smoke_xelpg_live_failed_post_demand_undo_keeps_clock_covered() -> TestResult {
    // Removing a 700 MHz pipe lowers CDCLK 480 -> 172.8 MHz after the
    // planes; the post-plane request then fails with REQUEST1 lowered.
    let a = state(&[(0, panel())]);
    let mut fast = panel();
    fast.pixel_rate_khz = 700_000;
    let big = state(&[(0, panel()), (1, fast)]);
    assert!(big.cdclk.cdclk_khz > a.cdclk.cdclk_khz);
    let hw = programmed(&big, &[0]);
    hw.drop_nth(0x45230, 1);
    assert_eq!(
        commit_live(&hw, &big, &a, 0x1),
        Err(ResourceError::NoDevice)
    );
    // Undo re-raised max(old, new) before raising the clock back.
    assert_eq!(hw.uncovered.get(), 0, "PM demand covered every clock");
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        big.cdclk.cdclk_khz
    );
    assert_image(&hw, &big.pipe_registers(0, false).unwrap());
    assert_eq!(
        Params::decode(hw.get(0x45230), hw.get(0x45234)),
        big.pmdemand
    );
    assert!(!hw.wrote(0x70008) && !hw.wrote(0x70180));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_live",
    smoke_xelpg_live_failed_post_demand_undo_keeps_clock_covered
);
