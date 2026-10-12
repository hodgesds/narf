use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const BASE: u64 = 0x10000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    stall: u8, // input clock, OTG clock, current master, busy
    retiring: [bool; 4],
    delay: [u8; 4],
    reject: Option<usize>,
    gone: Option<usize>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.gone == Some(self.writes.len()) {
            return u32::MAX;
        }
        for p in 0..4 {
            let ctrl = BASE + (0x1b43 + 0x80 * p) * 4;
            let clock = BASE + (0x1b84 + 0x80 * p) * 4;
            let input = BASE + (0x1ad0 + 0x10 * p) * 4;
            let old = *self.regs.get(&at).unwrap_or(&0);
            if at == input && old & 3 == 3 && self.stall & 1 == 0 {
                self.regs.insert(at, old | 4);
            }
            if at == clock && old & 3 == 3 && self.stall & 2 == 0 {
                self.regs.insert(at, old | 0x100);
            }
            if self.retiring[p as usize] && (at == ctrl || at == clock) {
                if self.delay[p as usize] != 0 {
                    self.delay[p as usize] -= 1;
                } else if (at == ctrl && self.stall & 4 == 0)
                    || (at == clock && self.stall & 8 == 0)
                {
                    *self.regs.entry(at).or_default() &= !0x10000;
                }
            }
        }
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert!((BASE + 0x530 * 4..=BASE + 0x1d1f * 4).contains(&at));
        self.writes.push((at, value));
        if self.reject == Some(self.writes.len()) {
            return;
        }
        self.regs.insert(at, value);
        for p in 0..4 {
            if at == BASE + (0x1b43 + 0x80 * p) * 4 && value & 1 == 0 {
                self.retiring[p as usize] = true;
            }
        }
        if let Some((n, cap)) = self.revoke {
            if n == self.writes.len() {
                cap.revoke();
            }
        }
    }
}
fn descriptor(words: &mut [u32]) -> AmdGpu {
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(words);
    let mut mp = gpu.ip_blocks[0];
    mp.hw_id = ip::HW_ID_MP1;
    (mp.major, mp.minor, mp.revision) = (14, 0, 2);
    mp.num_bases = 2;
    mp.base_addrs[1] = 0x16200;
    let mut dc = mp;
    dc.hw_id = ip::HW_ID_DCN;
    (dc.major, dc.minor, dc.revision) = (4, 1, 0);
    dc.num_bases = 4;
    dc.base_addrs[2] = (BASE / 4) as u32;
    dc.base_addrs[3] = 0xc000;
    gpu.ip_blocks.extend([mp, dc]);
    gpu
}
fn engine() -> Engine<Fake> {
    let mut words = vec![0; 0x80000 / 4];
    let gpu = descriptor(&mut words);
    Engine {
        io: Fake {
            regs: BTreeMap::new(),
            writes: Vec::new(),
            stall: 0,
            retiring: [false; 4],
            delay: [0; 4],
            reject: None,
            gone: None,
            revoke: None,
        },
        authority: Cap::bootstrap(),
        layout: Layout::resolve(&gpu).unwrap(),
        status: Status {
            state: State::Ready,
            pipes: [None; 4],
            retired: 0,
        },
    }
}
fn request(pipe: u8) -> Request {
    Request {
        pipe,
        signal: Signal::HpoDisplayPort,
        timing: Timing {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: 1080,
            v_total: 1125,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: false,
        },
        sync: GlobalSync {
            vstartup: 43,
            vupdate_offset: 1234,
            vupdate_width: 56,
            vready_offset: 78,
            pstate_keepout: 9,
        },
    }
}
fn clock(request: Request) -> dccg::Applied {
    dccg::Applied {
        request: dccg::Request {
            pipe: request.pipe,
            dpp_khz: 148_500,
            pixel: match request.signal {
                Signal::DisplayPort | Signal::HpoDisplayPort => dccg::PixelClock::DisplayPort {
                    pixel_hz: 148_500_000,
                },
                Signal::HdmiFrl => dccg::PixelClock::HdmiFrl {
                    pixel_hz: 148_500_000,
                },
                Signal::Tmds => dccg::PixelClock::Tmds {
                    divider: dccg::TmdsDivider::By2,
                },
            },
        },
        global: clocks::Applied {
            request: clocks::Request {
                displays: 1,
                display_khz: 600_000,
                dpp_khz: 300_000,
                dtb_khz: 600_000,
            },
            display_khz: 600_000,
            dpp_khz: 300_000,
            dtb_khz: 600_000,
            dcf_floor_khz: 1_200_000,
            memory_floor_khz: 1_200_000,
        },
        dpp_phase: 127,
        reference_hz: 720_000_000,
        integer: 0,
        phase: 148_500_000,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn reg(e: &Engine<Fake>, index: u64) -> u32 {
    *e.io.regs.get(&(BASE + index * 4)).unwrap_or(&0)
}

fn dcn401_otg_native_timing_all_pipes_and_signal_muxes() -> TestResult {
    for pipe in 0..4 {
        for (signal, control) in [
            (Signal::DisplayPort, 0x1000),
            (Signal::HpoDisplayPort, 0x201000),
            (Signal::Tmds, 0),
            (Signal::HdmiFrl, 0x200000),
        ] {
            let mut e = engine();
            let mut req = request(pipe);
            req.signal = signal;
            let c = clock(req);
            let p = u64::from(pipe);
            let o = |r| BASE + (r + 0x80 * p) * 4;
            let d = |r| BASE + (r + 0x10 * p) * 4;
            // Preserve independent PSTATE bits and clear inherited DSC/DRR.
            e.io.regs.insert(o(0x1b9f), 0x40000000);
            e.io.regs.insert(o(0x1b33), 0x12340013);
            e.io.regs.insert(d(0x1acc), 0x32);
            let applied = run(e.prepare(req, c)).unwrap();
            assert_eq!(
                e.io.writes,
                [
                    (d(0x1ad0), 3),
                    (o(0x1b84), 3),
                    (BASE + (0x530 + p) * 4, 0),
                    (d(0x1acb), 0xfff00000 | u32::from(pipe) << 16),
                    (o(0x1b2e), 0),
                    (d(0x1ad1), 0),
                    (o(0x1b33), 0),
                    (o(0x1b2a), 2199),
                    (o(0x1b2c), 44 << 16),
                    (o(0x1b2b), 192 << 16 | 2112),
                    (o(0x1b2d), 0),
                    (o(0x1b2f), 1124),
                    (o(0x1b30), 1124),
                    (o(0x1b31), 1124),
                    (o(0x1b39), 5 << 16),
                    (o(0x1b38), 41 << 16 | 1121),
                    (o(0x1b3a), 1),
                    (o(0x1b45), 0),
                    (o(0x1b43), control),
                    (o(0x1b85), 43),
                    (o(0x1b86), 56 << 16 | 1234),
                    (o(0x1b87), 78),
                    (o(0x1b9f), 0x40000009),
                    (BASE + (0x530 + p) * 4, 1121 << 16 | 1),
                    (d(0x1acc), 0),
                ]
            );
            assert_eq!(e.status.pipes[usize::from(pipe)], Some(applied));
            assert_eq!(e.status.state, State::Prepared);
            assert_eq!(reg(&e, 0x1b43 + 0x80 * p) & 0x10001, 0);
            assert_eq!(reg(&e, 0x530 + p) & 0x80000000, 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_native_timing_all_pipes_and_signal_muxes
);

fn dcn401_otg_odd_horizontal_boundaries_force_manual_no_divide() -> TestResult {
    for which in 0..4 {
        let mut r = request(0);
        match which {
            0 => r.timing.h_total += 1,
            1 => r.timing.h_front_porch += 1,
            2 => r.timing.h_active += 1,
            _ => r.timing.h_sync_width += 1,
        }
        let mut e = engine();
        run(e.prepare(r, clock(r))).unwrap();
        assert_eq!(reg(&e, 0x1b2e), 0x100);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_odd_horizontal_boundaries_force_manual_no_divide
);

fn dcn401_otg_rejects_malformed_timings_without_writes() -> TestResult {
    let mut cases = Vec::new();
    macro_rules! bad {
        ($field:ident, $value:expr) => {{
            let mut r = request(0);
            r.timing.$field = $value;
            cases.push(r);
        }};
    }
    bad!(pixel_clock_khz, 0);
    bad!(h_active, 0);
    bad!(v_active, 0);
    bad!(h_total, 0);
    bad!(v_total, 0);
    bad!(h_total, 32769);
    bad!(v_total, 32769);
    bad!(h_total, 1920);
    bad!(v_total, 1082);
    bad!(h_active, u32::MAX);
    bad!(h_front_porch, u32::MAX);
    bad!(v_front_porch, u32::MAX);
    bad!(v_front_porch, 0);
    bad!(h_sync_width, 3);
    bad!(v_sync_width, 0);
    bad!(h_sync_width, 193);
    bad!(v_sync_width, 42);
    let mut r = request(4);
    cases.push(r);
    r = request(0);
    r.sync.vstartup = 0;
    cases.push(r);
    r = request(0);
    r.sync.vstartup = 1024;
    cases.push(r);
    r = request(0);
    r.sync.vupdate_offset = 65536;
    cases.push(r);
    r = request(0);
    r.sync.vupdate_width = 1024;
    cases.push(r);
    r = request(0);
    r.sync.vready_offset = 65536;
    cases.push(r);
    r = request(0);
    r.sync.pstate_keepout = 32768;
    cases.push(r);
    for r in cases {
        let mut e = engine();
        assert_eq!(run(e.prepare(r, clock(r))), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    // Native maximum totals and zero FP2 remain representable.
    let mut r = request(0);
    r.timing.h_total = 32768;
    r.timing.v_total = 32768;
    let p = r.plan().unwrap();
    assert_eq!(p.vtg & 0xffff, 0);
    r.timing.h_front_porch = 0;
    assert!(r.plan().is_err(), "blank start must fit 15 bits");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_rejects_malformed_timings_without_writes
);

fn dcn401_otg_requires_retired_consumers_and_matching_clocks() -> TestResult {
    for (at, mask) in engine().layout.idle {
        for bit in (0..32).map(|i| 1u32 << i).filter(|b| mask & b != 0) {
            let mut e = engine();
            e.io.regs.insert(at, bit);
            assert_eq!(
                run(e.prepare(request(0), clock(request(0)))),
                Err(Error::Busy)
            );
            assert!(e.io.writes.is_empty());
        }
        let mut e = engine();
        e.io.regs.insert(at, u32::MAX);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::DeviceGone)
        );
        assert!(e.io.writes.is_empty());
    }
    for (index, value) in [(0x1b89, 1), (0x1b89, 0x100), (0x1b84, 0x10)] {
        let mut e = engine();
        e.io.regs.insert(BASE + index * 4, value);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert!(e.io.writes.is_empty());
    }
    for c in [
        {
            let mut c = clock(request(0));
            c.request.pipe = 1;
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::Disabled;
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::HdmiFrl {
                pixel_hz: 148_500_000,
            };
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::DisplayPort {
                pixel_hz: 148_500_001,
            };
            c
        },
        {
            let mut c = clock(request(0));
            c.global.display_khz = 148_499;
            c
        },
    ] {
        let mut e = engine();
        assert_eq!(run(e.prepare(request(0), c)), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_requires_retired_consumers_and_matching_clocks
);

fn dcn401_otg_clock_waits_and_cancellation_quarantine() -> TestResult {
    for (stall, at, writes) in [(1, BASE + 0x1ad0 * 4, 1), (2, BASE + 0x1b84 * 4, 2)] {
        let mut e = engine();
        e.io.stall = stall;
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Timeout(at))
        );
        assert_eq!(e.io.writes.len(), writes);
        assert_eq!(e.status.state, State::Failed(Error::Timeout(at)));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        let mut e = engine();
        e.io.stall = stall;
        let mut future = core::pin::pin!(e.prepare(request(0), clock(request(0))));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        // Dropping the future below preserves the in-flight state.
    }
    let mut e = engine();
    e.io.stall = 1;
    {
        let mut f = core::pin::pin!(e.prepare(request(0), clock(request(0))));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::Preparing(0));
    assert_eq!(
        run(e.prepare(request(0), clock(request(0)))),
        Err(Error::Busy)
    );
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_clock_waits_and_cancellation_quarantine
);

fn dcn401_otg_partial_write_failures_are_terminal() -> TestResult {
    for n in 1..=25 {
        let mut e = engine();
        e.io.gone = Some(n);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::DeviceGone)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        let mut e = engine();
        e.io.revoke = Some((n, e.authority));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Revoked)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::Revoked));
    }
    for (n, at) in [
        (1, 0x1ad0),
        (2, 0x1b84),
        (4, 0x1acb),
        (8, 0x1b2a),
        (19, 0x1b43),
        (24, 0x530),
    ] {
        let mut e = engine();
        e.io.reject = Some(n);
        let err = Error::Readback(BASE + at * 4);
        assert_eq!(run(e.prepare(request(0), clock(request(0)))), Err(err));
        assert_eq!(e.status.state, State::Failed(err));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_partial_write_failures_are_terminal
);

fn active(e: &mut Engine<Fake>, pipe: u8) {
    let p = u64::from(pipe);
    e.io.regs.insert(
        BASE + (0x1acb + 0x10 * p) * 4,
        u32::from(pipe) << 16 | 0x100,
    );
    e.io.regs.insert(BASE + (0x1ad1 + 0x10 * p) * 4, 0xabcd0055);
    e.io.regs.insert(BASE + (0x1b43 + 0x80 * p) * 4, 0x210201);
    e.io.regs.insert(BASE + (0x1b84 + 0x80 * p) * 4, 0x10103);
    e.io.regs.insert(BASE + (0x530 + p) * 4, 0x80000055);
    e.io.delay[usize::from(pipe)] = 3;
}
fn dcn401_otg_retirement_waits_for_current_master_and_busy() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        active(&mut e, pipe);
        let p = u64::from(pipe);
        run(e.retire(pipe)).unwrap();
        assert_eq!(
            e.io.writes,
            [
                (BASE + (0x1acb + 0x10 * p) * 4, 0xffff0100),
                (BASE + (0x1ad1 + 0x10 * p) * 4, 0xabcd0000),
                (BASE + (0x1b43 + 0x80 * p) * 4, 0x210200),
                (BASE + (0x530 + p) * 4, 0x55),
            ]
        );
        assert_eq!(reg(&e, 0x1b43 + 0x80 * p), 0x200200);
        assert_eq!(reg(&e, 0x1b84 + 0x80 * p), 0x103);
        assert_eq!(e.status.retired, 1 << pipe);
        assert_eq!(e.status.state, State::Retired);
        run(e.prepare(request(pipe), clock(request(pipe)))).unwrap();
        assert_eq!(e.status.retired, 0);
        run(e.retire(pipe)).unwrap();
        assert_eq!(e.status.pipes[usize::from(pipe)], None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_retirement_waits_for_current_master_and_busy
);

fn dcn401_otg_retirement_faults_and_cancel_never_release_resources() -> TestResult {
    for (stall, index) in [(4, 0x1b43), (8, 0x1b84)] {
        let mut e = engine();
        active(&mut e, 0);
        e.io.stall = stall;
        let err = Error::Timeout(BASE + index * 4);
        assert_eq!(run(e.retire(0)), Err(err));
        assert_eq!(e.status.state, State::Failed(err));
        assert_eq!(e.status.retired, 0);
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
    }
    for n in 1..=4 {
        let mut e = engine();
        active(&mut e, 0);
        e.io.gone = Some(n);
        assert_eq!(run(e.retire(0)), Err(Error::DeviceGone));
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.retired, 0);
        let mut e = engine();
        active(&mut e, 0);
        e.io.revoke = Some((n, e.authority));
        assert_eq!(run(e.retire(0)), Err(Error::Revoked));
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.retired, 0);
    }
    let mut e = engine();
    active(&mut e, 0);
    e.io.stall = 4;
    {
        let mut f = core::pin::pin!(e.retire(0));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::Retiring(0));
    assert_eq!(e.status.retired, 0);
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    // Live stream preflight must reject even a request to retire timing.
    for (at, mask) in engine().layout.idle {
        if (0..4)
            .any(|p| at == BASE + (0x1b43 + 0x80 * p) * 4 || at == BASE + (0x1b84 + 0x80 * p) * 4)
        {
            continue;
        }
        let mut e = engine();
        active(&mut e, 0);
        e.io.regs.insert(at, mask);
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_retirement_faults_and_cancel_never_release_resources
);

fn dcn401_otg_constructor_checks_native_discovery_without_writes() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let mut gpu = descriptor(&mut words);
    let before = words.clone();
    let cap = Cap::bootstrap();
    assert_eq!(
        // SAFETY: isolated model RAM; constructor never starts hardware.
        unsafe { Otg::new(&gpu, cap) }.unwrap().status().state,
        State::Ready
    );
    assert_eq!(words, before);
    for which in 0..5 {
        gpu = descriptor(&mut words);
        match which {
            0 => gpu.chip.did = crate::amdgpu::NAVI22,
            1 => gpu.ip_blocks.last_mut().unwrap().major = 3,
            2 => gpu.ip_blocks.last_mut().unwrap().num_bases = 2,
            3 => gpu.regs.len = 0x20000,
            _ => {
                let dc = *gpu.ip_blocks.last().unwrap();
                gpu.ip_blocks.push(dc);
            }
        }
        // SAFETY: same isolated RAM, invalid metadata must be rejected.
        assert!(unsafe { Otg::new(&gpu, cap) }.is_err());
    }
    gpu = descriptor(&mut words);
    cap.revoke();
    assert!(matches!(
        // SAFETY: model-only revoked constructor performs no MMIO.
        unsafe { Otg::new(&gpu, cap) },
        Err(Error::Revoked)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_constructor_checks_native_discovery_without_writes
);
