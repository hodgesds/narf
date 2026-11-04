// Included in the real Xe-LPG modeset tests. Source literals are independent
// of the production constants/codecs. Hardware ACKs are modelled, not the
// modeset owner: every case calls the shared probe/resume dispatcher.
use alloc::collections::BTreeMap;

#[derive(Copy, Clone, Debug)]
enum MtlAccess {
    Read(u64, u32),
    Write(u64, u32),
}
#[derive(Debug)]
struct FailClosedMtl {
    mode: MtlFake,
    values: RefCell<BTreeMap<u64, u32>>,
    trace: RefCell<Vec<MtlAccess>>,
    current: Cell<bool>,
    lost_at: Cell<usize>,
    lose_read: Cell<u64>,
    lose_write: Cell<u64>,
    all_ones: Cell<u64>,
    drop_write: Cell<u64>,
    drop_enable: Cell<bool>,
    drop_normal: Cell<bool>,
    unlocked_cdclk: Cell<bool>,
    stop_stuck: Cell<bool>,
    enable_stuck: Cell<bool>,
    frame_stuck: Cell<bool>,
    live_stuck: Cell<bool>,
    idle_after_enable: Cell<bool>,
    delay_stop: Cell<u32>,
    delay_enable: Cell<u32>,
    stop_reads: Cell<u32>,
    enable_reads: Cell<u32>,
    stop_requested: Cell<bool>,
    enable_requested: Cell<bool>,
    torn_frames: Cell<u32>,
}
impl FailClosedMtl {
    fn new() -> Self {
        let mode = MtlFake::new(XeLpgPort::A);
        mode.pipeconf.set(1 << 31);
        mode.phy.write32(0x70180, 0x84000000);
        mode.phy.write32(0x7019c, 0x02000000);
        mode.phy.write32(0x70040, 0x37);
        Self {
            mode,
            values: RefCell::new(
                [
                    (0x510a0, 14 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                    // A real all-masked IMR is valid under current authority.
                    (0x44464, 0xffffffff),
                ]
                .into_iter()
                .collect(),
            ),
            trace: RefCell::new(Vec::new()),
            current: Cell::new(true),
            lost_at: Cell::new(usize::MAX),
            lose_read: Cell::new(u64::MAX),
            lose_write: Cell::new(u64::MAX),
            all_ones: Cell::new(u64::MAX),
            drop_write: Cell::new(u64::MAX),
            drop_enable: Cell::new(false),
            drop_normal: Cell::new(false),
            unlocked_cdclk: Cell::new(false),
            stop_stuck: Cell::new(false),
            enable_stuck: Cell::new(false),
            frame_stuck: Cell::new(false),
            live_stuck: Cell::new(false),
            idle_after_enable: Cell::new(false),
            delay_stop: Cell::new(0),
            delay_enable: Cell::new(0),
            stop_reads: Cell::new(0),
            enable_reads: Cell::new(0),
            stop_requested: Cell::new(false),
            enable_requested: Cell::new(false),
            torn_frames: Cell::new(0),
        }
    }
    fn resource(r: u64) -> bool {
        matches!(
            r,
            0x510a0
                | 0x45230
                | 0x45234
                | 0x46440
                | 0x46438
                | 0x4438c
                | 0x7003c
                | 0x44464
                | 0x44468
                | 0x4446c
                | 0x45780
                | 0x45784
                | 0x45788
                | 0x45008
                | 0x44fe8
                | 0x44300
                | 0x44304
                | 0x45004
                | 0x71008
                | 0x72008
                | 0x73008
        ) || ((0x70000..0x75000).contains(&r)
            && r & 0xfff >= 0x140
            && r & 0xfff <= 0x87c
            && r & 0xff < 0x80)
    }
    fn run(&self) -> Result<Mode, ModesetError> {
        // The exact same dispatcher called by real relight/probe. No fake
        // stop/result or test-only completion function replaces production.
        crate::intel_gpu_modeset::modeset_display(
            self,
            crate::intel_gpu::Generation::MeteorLake,
            &test_fb(),
            Some(&Mode::VESA_1024X768_60),
        )
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.trace
            .borrow()
            .iter()
            .filter_map(|a| match *a {
                MtlAccess::Write(off, value) if off == r => Some(value),
                _ => None,
            })
            .collect()
    }
    fn no_later_programming(&self) {
        for r in [
            0x70034, 0x45230, 0x45234, 0x44300, 0x46070, 0x64040, 0x46140, 0x60400,
        ] {
            assert!(self.written(r).is_empty(), "later stage wrote {r:#x}");
        }
        assert!(self.written(0x70008).iter().all(|v| v & (1 << 31) == 0));
    }
    fn record(&self, access: MtlAccess) {
        // A withheld hardware ACK must not allocate an unbounded read log.
        // Keep every write and the bounded read prefix; per-phase counters
        // still observe every ACK poll and raw current-loss asserts are exact.
        let mut trace = self.trace.borrow_mut();
        if trace.len() < 4096 || matches!(access, MtlAccess::Write(_, _)) {
            trace.push(access);
        }
    }
    fn lose(&self) {
        self.current.set(false);
        self.lost_at.set(self.trace.borrow().len());
    }
}
impl MmioWindow for FailClosedMtl {
    fn display_access_ok(&self) -> bool {
        self.current.get()
    }
    fn read32(&self, r: u64) -> u32 {
        assert!(self.current.get(), "raw read after current loss at {r:#x}");
        let mut value = if Self::resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else {
            self.mode.read32(r)
        };
        if r == 0x46070 && self.unlocked_cdclk.get() {
            value &= !(1 << 30);
        }
        if r == 0x70008 && self.stop_requested.get() {
            if self.enable_requested.get() {
                self.enable_reads.set(self.enable_reads.get() + 1);
                if self.enable_stuck.get() || self.delay_enable.get() != 0 {
                    value &= !(1 << 30);
                    self.delay_enable
                        .set(self.delay_enable.get().saturating_sub(1));
                }
            } else {
                self.stop_reads.set(self.stop_reads.get() + 1);
                if self.stop_stuck.get() || self.delay_stop.get() != 0 {
                    value |= 1 << 30;
                    self.delay_stop.set(self.delay_stop.get().saturating_sub(1));
                }
            }
        }
        if r == 0x70040 {
            if self.frame_stuck.get() {
                value = 0x37;
            }
            if self.enable_requested.get() && self.torn_frames.get() != 0 {
                value += self.torn_frames.get();
                self.torn_frames.set(self.torn_frames.get() - 1);
            }
        }
        if r == 0x64004 && self.idle_after_enable.get() && self.enable_requested.get() {
            value |= 1 << 7;
        }
        if r == 0x701ac && self.live_stuck.get() {
            value = 0x02000000;
        }
        if self.all_ones.get() == r {
            value = u32::MAX;
        }
        self.record(MtlAccess::Read(r, value));
        if self.lose_read.get() == r {
            self.lose();
        }
        value
    }
    fn write32(&self, r: u64, value: u32) {
        assert!(self.current.get(), "raw write after current loss at {r:#x}");
        self.record(MtlAccess::Write(r, value));
        if self.lose_write.get() == r {
            self.lose();
            return;
        }
        if self.drop_write.get() == r
            || (self.drop_enable.get() && r == 0x70008 && value & (1 << 31) != 0)
            || (self.drop_normal.get() && r == 0x60540 && value & 0x700 == 0x300)
        {
            return;
        }
        if r == 0x70008 {
            if value & (1 << 31) == 0 {
                self.stop_requested.set(true);
            } else {
                self.enable_requested.set(true);
            }
        }
        if Self::resource(r) {
            let mut observed = value;
            if r == 0x45234 {
                observed &= !(1 << 31);
            }
            if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) && value & (1 << 31) != 0 {
                observed |= 1 << 30;
            }
            self.values.borrow_mut().insert(r, observed);
        } else {
            self.mode.write32(r, value);
        }
    }
}

fn smoke_mtl_failclosed_actual_stop_and_pll_abort_later_programming() -> TestResult {
    // Stuck hardware STATE reproduces the old ignored-stop→resource
    // initialize(None)→CDCLK/PHY write bug through the actual dispatcher.
    let io = FailClosedMtl::new();
    io.stop_stuck.set(true);
    assert_eq!(io.run(), Err(ModesetError::PipelineStopUnavailable));
    assert!(io.stop_reads.get() > 1);
    io.no_later_programming();
    for r in [0x70180, 0x70008] {
        let io = FailClosedMtl::new();
        io.drop_write.set(r);
        assert_eq!(io.run(), Err(ModesetError::PipelineStopUnavailable));
        io.no_later_programming();
    }
    // A firmware ratio above the floor is not current clock evidence if
    // LOCK is absent. Fail before resource/CDCLK/port programming, not only
    // at a later frame observation.
    let io = FailClosedMtl::new();
    io.mode.cdclk_pll.set((1 << 31) | 34);
    io.unlocked_cdclk.set(true);
    assert_eq!(io.run(), Err(ModesetError::PllLockTimeout));
    for r in [0x45230, 0x45234, 0x44300, 0x46070, 0x64040, 0x46140] {
        assert!(io.written(r).is_empty(), "unlocked fast path wrote {r:#x}");
    }
    // Inherited size8 consumes the high eight waveform bits only. The
    // source rate is81,600, not old all16/popcount rate367,200; a200MHz
    // required floor must reprogram instead of taking the inherited fast path.
    let mut short_window_mode = Mode::VESA_1024X768_60;
    short_window_mode.pixel_clock_khz = 400_000;
    for refuse_squash in [false, true] {
        let io = FailClosedMtl::new();
        io.mode.cdclk_pll.set(0x80000022); // model supplies actual LOCK
        io.mode.phy.write32(0x46000, 0); // divide2
        io.mode.phy.write32(0x46008, 0x870080ff); // enable/window8/high waveform80
        assert_eq!(cdclk_current_khz(&io), 81_600);
        if refuse_squash {
            io.drop_write.set(0x46008);
        }
        let result = crate::intel_gpu_modeset::modeset_display(
            &io,
            Generation::MeteorLake,
            &test_fb(),
            Some(&short_window_mode),
        );
        // The owned display14 transaction classifies the non-table clock as
        // unknown (bxt_sanitize_cdclk) and takes the full source path: the
        // disable RMW keeps the ratio field, then lock at ratio16.
        if refuse_squash {
            assert_eq!(result, Err(ModesetError::PllLockTimeout));
            // The refused squash fails readback; the original ratio34 PLL is
            // restored through the same full disable/enable sequence.
            assert_eq!(
                io.written(0x46070),
                [0x22, 16, 0x80000010, 0x10, 0x22, 0x80000022]
            );
            assert_eq!(io.mode.read32(0x46070) & 0x800000ff, 0x80000022);
            assert!(
                io.written(0x64040).is_empty(),
                "no PHY after refused squash"
            );
        } else {
            assert_eq!(io.written(0x46070), [0x22, 16, 0x80000010]);
            assert_eq!(result, Ok(short_window_mode));
            assert_eq!(cdclk_current_khz(&io), 307_200);
            assert_eq!(io.mode.read32(0x46008), 0);
            assert!(!io.written(0x64040).is_empty());
        }
    }
    // Literal readout controls: inactive low bits do not affect size8;
    // window16 is retained, and full-product nearest rounding is source exact.
    let decode = MtlFake::new(XeLpgPort::A);
    decode.cdclk_pll.set(0x80000022);
    for (squash, expected) in [
        (0x87008000, 81_600),
        (0x870080ff, 81_600),
        (0x8f00ad5a, 367_200),
    ] {
        decode.phy.write32(0x46008, squash);
        assert_eq!(cdclk_current_khz(&decode), expected);
    }
    decode.cdclk_pll.set(0x80000001); // VCO38,400
    decode.phy.write32(0x46000, 3 << 22); // divider8
    decode.phy.write32(0x46008, 0x86008000); // size7, one active bit
    assert_eq!(cdclk_current_khz(&decode), 686); // nearest38,400/56
    let mut beyond = Mode::VESA_1024X768_60;
    beyond.pixel_clock_khz = 1_400_000; // floor700MHz > final source table rung652.8MHz
    let io = FailClosedMtl::new();
    io.mode.cdclk_pll.set((1 << 31) | 34); // acknowledged652.8MHz, still below floor
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::program_cdclk_floor(&io, &beyond),
        Err(ModesetError::PllLockTimeout)
    );
    assert_eq!(
        crate::intel_gpu_modeset::modeset_display(
            &io,
            Generation::MeteorLake,
            &test_fb(),
            Some(&beyond)
        ),
        Err(ModesetError::Dsc(
            crate::intel_gpu_xelpg_dsc::DscRefusal::SinkUnsupported
        ))
    );
    for r in [0x45230, 0x45234, 0x44300, 0x46070, 0x64040, 0x46140] {
        assert!(io.written(r).is_empty(), "missing source rung wrote {r:#x}");
    }
    // The owned display14 transaction no longer preserves a faster
    // firmware clock: CDCLK_CTL 0 is not bxt_cdclk_ctl(652.8MHz), so the
    // clock is unknown and the computed 172.8MHz rung is fully relocked
    // (squash off first, PLL RMW-disable, ratio16 lock, waveform, CTL).
    let io = FailClosedMtl::new();
    io.mode.cdclk_pll.set((1 << 31) | 34);
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert_eq!(io.written(0x46070), [0x22, 16, 0x80000010]);
    assert_eq!(io.written(0x46008), [0, 0x8f00ad5a]);
    assert_eq!(io.written(0x46000), [(7 << 19) | 344]);
    assert_eq!(cdclk_current_khz(&io), 172_800);
    // The clock helper also preserves acknowledged firmware current above
    // the local table; this is only the existing floor contract, not a new
    // complete display/link qualification for the synthetic high pixel rate.
    let inherited = MtlFake::new(XeLpgPort::A);
    inherited.cdclk_pll.set((1 << 31) | 40); //768MHz
    assert_eq!(program_cdclk_floor(&inherited, &beyond), Ok(()));
    assert!(inherited.writes_to(0x46070).is_empty());
    // Independent lane1 request/ACK catches the old ACK0-only helper.
    let io = FailClosedMtl::new();
    io.mode.phy.write32(0x640e0, (1 << 27) | (1 << 25));
    io.drop_write.set(0x640e0);
    assert_eq!(io.run(), Err(ModesetError::PllLockTimeout));
    io.no_later_programming();
    assert_eq!(io.written(0x70008).len(), 1, "one aliased CONF stop");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_modeset_xelpg",
    smoke_mtl_failclosed_actual_stop_and_pll_abort_later_programming
);

fn smoke_mtl_failclosed_actual_enable_needs_ack_live_and_fresh_frame() -> TestResult {
    let io = FailClosedMtl::new();
    io.delay_stop.set(4);
    io.delay_enable.set(5);
    io.torn_frames.set(4);
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert!(io.stop_reads.get() >= 5 && io.enable_reads.get() >= 6);
    assert_eq!(
        io.written(0x70008).len(),
        2,
        "one stop and one source enable"
    );
    assert!(io.written(0x45230).len() == 1 && !io.written(0x44300).is_empty());
    // Source image literals, independently repeated from register source.
    assert_eq!(io.mode.read32(0x70180), 0x84000000);
    assert_eq!(io.mode.read32(0x70188), 64);
    assert_eq!(io.mode.read32(0x70190), (767 << 16) | 1023);
    assert_eq!(io.mode.read32(0x7019c), 0x01000000);
    assert_eq!(io.mode.read32(0x701ac), 0x01000000);
    assert_eq!(io.mode.read32(0x70008) & 0xc0000000, 0xc0000000);
    assert!(
        io.written(0x64000).is_empty(),
        "no unmatched DDI disable/enable"
    );
    for failure in 0..6 {
        let io = FailClosedMtl::new();
        match failure {
            0 => io.enable_stuck.set(true),
            1 => io.frame_stuck.set(true),
            2 => io.live_stuck.set(true),
            3 => io.drop_enable.set(true),
            4 => io.drop_normal.set(true),
            _ => io.idle_after_enable.set(true),
        }
        assert_eq!(io.run(), Err(ModesetError::PipelineEnableUnavailable));
    }
    for r in [0x60400, 0x46140] {
        let io = FailClosedMtl::new();
        io.drop_write.set(r);
        assert_eq!(io.run(), Err(ModesetError::PipelineEnableUnavailable));
    }
    for r in [0x46070, 0x46008, 0x46000] {
        let io = FailClosedMtl::new();
        io.drop_write.set(r);
        assert_eq!(io.run(), Err(ModesetError::PllLockTimeout));
        assert!(
            io.written(0x64040).is_empty(),
            "no port PHY after CDCLK refusal"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_modeset_xelpg",
    smoke_mtl_failclosed_actual_enable_needs_ack_live_and_fresh_frame
);

fn smoke_mtl_failclosed_powered_ddi_current_and_allones_refusal() -> TestResult {
    // Literal address erratum binds the two register ranges independently.
    assert_eq!(XeLpgPort::A.buf_ctl1(), 0x64004);
    assert_eq!(XeLpgPort::B.buf_ctl1(), 0x64104);
    assert_eq!(XeLpgPort::Tc1.buf_ctl1(), 0x16f200);
    assert_eq!(XeLpgPort::Tc2.buf_ctl1(), 0x16f400);
    for idle in [false, true] {
        let io = FailClosedMtl::new();
        if idle {
            io.mode.phy.write32(0x64004, 1 << 7);
        } else {
            io.mode.phy.write32(0x64000, 0);
        }
        assert_eq!(io.run(), Err(ModesetError::PipelineStopUnavailable));
        assert!(io.written(0x70180).is_empty());
        io.no_later_programming();
        let trace = io.trace.borrow();
        let port = trace
            .iter()
            .position(|a| matches!(*a, MtlAccess::Read(0x64000, _)))
            .unwrap();
        assert!(trace[..port].iter().any(
            |a| matches!(*a, MtlAccess::Read(0x45404, value) if value & 0xc03 == 0xc03)
        ));
        // xelpdp_aux_power_well_enable: AUX_A is the 0x64010 bit-19
        // request; the ICL AUX2 well is never accessed on display 14.
        assert!(trace[..port]
            .iter()
            .any(|a| matches!(*a, MtlAccess::Write(0x64010, value) if value & (1 << 19) != 0)));
        assert!(!trace
            .iter()
            .any(|a| matches!(*a, MtlAccess::Read(0x45444, _) | MtlAccess::Write(0x45444, _))));
    }
    for off in [
        0x45404, 0x64000, 0x64004, 0x70180, 0x70008, 0x640e0, 0x510a0, 0x70040, 0x701ac,
    ] {
        let io = FailClosedMtl::new();
        io.all_ones.set(off);
        assert!(io.run().is_err(), "all-ones must not satisfy ACK {off:#x}");
        let trace = io.trace.borrow();
        let loss = trace
            .iter()
            .position(|a| matches!(*a, MtlAccess::Read(r, u32::MAX) if r == off))
            .unwrap();
        assert_eq!(
            trace.len(),
            loss + 1,
            "sticky guard suppresses later raw accesses"
        );
    }
    for write in [false, true] {
        let io = FailClosedMtl::new();
        if write {
            io.lose_write.set(0x70180);
        } else {
            io.lose_read.set(0x64000);
        }
        assert!(io.run().is_err());
        assert_eq!(io.trace.borrow().len(), io.lost_at.get());
        io.no_later_programming();
    }
    // Both canonical MTL and ARL pass the actual chip-aware resume entry;
    // PCI metadata selects this sequence, not a synthetic active-panel fact.
    for (did, asic) in [(0x7d40, "meteorlake"), (0x7d41, "arrowlake")] {
        let io = FailClosedMtl::new();
        let chip = crate::intel_gpu::ChipInfo {
            vid: 0x8086,
            did,
            generation: Generation::MeteorLake,
            asic,
        };
        assert_eq!(
            crate::intel_gpu_modeset::modeset_display_for_chip(
                &io,
                chip,
                &test_fb(),
                Some(&Mode::VESA_1024X768_60)
            ),
            Ok(Mode::VESA_1024X768_60)
        );
        assert!(io.written(0x64000).is_empty());
    }
    // The source-dependent newer profiles remain completely read-only refused.
    for generation in [Generation::LunarLake, Generation::PantherLake] {
        let io = FailClosedMtl::new();
        assert_eq!(
            crate::intel_gpu_modeset::modeset_display(
                &io,
                generation,
                &test_fb(),
                Some(&Mode::VESA_1024X768_60)
            ),
            Err(ModesetError::UnsupportedGeneration)
        );
        assert!(io.trace.borrow().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_modeset_xelpg",
    smoke_mtl_failclosed_powered_ddi_current_and_allones_refusal
);

fn smoke_mtl_failclosed_dispatch_runs_in_actual_executor_poll() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    // No scheduler init/reset, no permanent pump mutation, no bridge. The
    // spawned future calls the actual synchronous resume dispatcher while
    // CURRENT_TASK is published by the real scheduler poll boundary.
    let result = Arc::new(AtomicU32::new(0));
    let completed = result.clone();
    narf_scheduler::spawn(async move {
        let in_task = narf_scheduler::current_task_id() != narf_scheduler::TaskId::NONE;
        let io = FailClosedMtl::new();
        io.delay_stop.set(3);
        io.delay_enable.set(4);
        let good = io.run() == Ok(Mode::VESA_1024X768_60);
        let failed = FailClosedMtl::new();
        failed.drop_write.set(0x70180);
        let rejected = failed.run() == Err(ModesetError::PipelineStopUnavailable);
        failed.no_later_programming();
        completed.store(
            if in_task && good && rejected { 1 } else { 2 },
            Ordering::Release,
        );
    });
    let done = narf_scheduler::responsive_spin_until(
        || {
            narf_scheduler::poll_one_round_nested();
            result.load(Ordering::Acquire) != 0
        },
        narf_time::Deadline::after_ns(1_000_000_000),
    );
    assert!(done);
    assert_eq!(result.load(Ordering::Acquire), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_modeset_xelpg",
    smoke_mtl_failclosed_dispatch_runs_in_actual_executor_poll
);
