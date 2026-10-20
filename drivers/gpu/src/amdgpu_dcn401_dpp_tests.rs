use super::*;
#[path = "amdgpu_dcn401_mpc_tests.rs"]
mod mpc;

fn d(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x16b) * 4
}
// Golden native unity RGB register values; offsets/masks are independently
// asserted against AMD's headers by tests/dcn401_dpp.c.
const RGB: [(u64, u32); 30] = [
    (0xcd0, 0x24000101),
    (0xccf, 8),
    (0xcd7, 0),
    (0xcde, 0),
    (0xcee, 0),
    (0xced, 0),
    (0xcd1, 0),
    (0xcd2, 0),
    (0xcd3, 0),
    (0xcd4, 0x1f000),
    (0xcd5, 0x1f000),
    (0xcd6, 0x1f000),
    (0xd67, 0),
    (0xd68, 0),
    (0xd77, 0),
    (0xdc5, 0),
    (0xd75, 0),
    (0xd76, 0),
    (0xdc1, 0x1f000),
    (0xd19, 0),
    (0xd0a, 0),
    (0xd1e, 0),
    (0xd1f, 0x30041),
    (0xd20, 0x30041),
    (0xd08, 0),
    (0xd21, 0),
    (0xd22, 0x3f01),
    (0xd28, 0),
    (0xd29, 0),
    (0xd55, 0),
];
struct DppIo {
    memory: MemoryIo,
    pipe: u8,
    waking: u8,
    delay: [u8; 2],
    stall: u8,
}
impl Engine<DppIo> {
    fn fake(&mut self) -> &mut Fake {
        self.io.fake()
    }
}
impl DppIo {
    fn fake(&mut self) -> &mut Fake {
        &mut self.memory.surface.inner
    }
    fn accessible(&self, at: u64) {
        for p in 0..4 {
            if (d(p, 0xcc5)..d(p, 0xcc5 + 0x16b)).contains(&at) {
                assert_eq!(
                    self.memory.surface.inner.forbidden_hubps & (1 << p),
                    0,
                    "access to an unrelated powered-off pipe"
                );
            }
        }
    }
}
impl Io for DppIo {
    fn wait_poll_limit(&self) -> Option<u32> {
        // Acknowledgements advance on reads, not elapsed time. Retain the
        // delayed success, stuck acknowledgement and cancellation cases
        // without letting host scheduling turn fault injection into timeout.
        Some(8)
    }
    fn read(&mut self, at: u64) -> u32 {
        self.accessible(at);
        for (index, (r, mask)) in [(0xd25, 3), (0xd62, 0x30)].into_iter().enumerate() {
            if at == d(self.pipe, r)
                && self.waking & (1 << index) != 0
                && self.stall & (1 << index) == 0
            {
                if self.delay[index] == 0 {
                    *self.fake().regs.entry(at).or_default() &= !mask;
                    self.waking &= !(1 << index);
                } else {
                    self.delay[index] -= 1;
                }
            }
        }
        self.memory.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.accessible(at);
        let p = self.pipe;
        if at != d(p, 0xcc5) {
            assert_eq!(self.fake().regs[&d(p, 0xcc5)] & 0x10, 0x10);
        }
        assert_eq!(self.fake().regs[&h(p, 0x5f4)] & 0x1007, 3);
        assert_eq!(self.fake().regs[&h(p, 0x5f5)] & 1, 0);
        self.memory.write(at, value);
        let f = self.fake();
        if f.reject == Some(f.writes.len()) {
            return;
        }
        if at == d(p, 0xd24) {
            self.waking |= 1;
            *self.fake().regs.entry(d(p, 0xd25)).or_default() |= 3;
        }
        if at == d(p, 0xd62) {
            self.waking |= 2;
            *self.fake().regs.entry(d(p, 0xd62)).or_default() |= 0x30;
        }
        // Stopped timing does not latch CNVC/scaler/CM double buffers.
        for (written, pending, mask) in [
            (0xcd0, 0xcd0, 0x100000),
            (0xd1f, 0xd18, 1),
            (0xd67, 0xd67, 0x100),
        ] {
            if at == d(p, written) {
                *self.fake().regs.entry(d(p, pending)).or_default() |= mask;
            }
        }
    }
}
fn ready(p: u8) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_depth(p, ColorDepth::Bpc8)
}
/// The small default plane mode: a 65x3 surface on a 65x3-active timing.
fn small(p: u8) -> Mode {
    let mut t = request(p);
    t.timing.h_active = 65;
    t.timing.v_active = 3;
    Mode {
        surface: req(p),
        bytes: 8192,
        timing: t,
        clock: clock(t),
    }
}
fn ready_depth(
    p: u8,
    depth: ColorDepth,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_with(p, depth, small(p))
}
fn ready_with(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_range(p, depth, mode, false)
}
/// `ready_with` for a full- or limited-range blank request.
fn ready_range(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
    limited: bool,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    let (backing, pool, mut e, mut surfaces) = staged_with(p, mode.surface, mode.bytes);
    run(surfaces.prepare_memory(&mut e, p, || Ok(config()))).unwrap();
    let (t, clock) = (mode.timing, mode.clock);
    run(e.prepare(t, clock)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe: p,
            depth,
            limited,
            ycbcr420: mode.timing.ycbcr420,
        },
        clock,
    ))
    .unwrap();
    for (r, value) in RGB {
        e.io.surface
            .inner
            .regs
            .insert(d(p, r), 0x80000000 | (value ^ 1));
    }
    e.io.surface.inner.regs.insert(d(p, 0xcc5), 0x80050100);
    e.io.surface.inner.regs.insert(d(p, 0xd24), 3);
    e.io.surface.inner.regs.insert(d(p, 0xd62), 3);
    e.io.surface.inner.writes.clear();
    let engine = Engine {
        io: DppIo {
            memory: e.io,
            pipe: p,
            waking: 0,
            delay: [1, 2],
            stall: 0,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    (backing, pool, engine, surfaces, clock)
}
fn dcn401_dpp_stages_native_rgb_and_unity_scaling_on_all_pipes() -> TestResult {
    for p in 0..4 {
        let (_backing, pool, mut e, mut surfaces, clock) = ready(p);
        let mut checks = 0;
        let a = run(surfaces.prepare_dpp(&mut e, p, || {
            checks += 1;
            Ok((clock, config()))
        }))
        .unwrap();
        assert_eq!(checks, 2);
        assert_eq!(a.pending, 7);
        assert_eq!(a.line_buffer_config, 1);
        assert_eq!(e.status.dpps[p as usize], Some(a));
        assert_eq!(e.status.state, State::DppPrepared);
        assert_eq!(e.fake().regs[&d(p, 0xcc5)], 0x80050100);
        for (r, value) in RGB {
            let pending = match r {
                0xcd0 => 0x100000,
                0xd67 => 0x100,
                _ => 0,
            };
            assert_eq!(
                e.fake().regs[&d(p, r)],
                (if r == 0xd76 { 0 } else { 0x80000000 }) | value | pending
            );
        }
        assert_eq!(e.fake().writes.len(), 34);
        assert_eq!(e.fake().regs[&h(p, 0x613)] & 0x100, 0x100);
        assert_eq!(
            e.fake().regs[&(MPC_BASE + (0x2f2 + u64::from(p) * 4) * 4)] & 0xf,
            0xf
        );
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))),
            Err(Error::Busy)
        );
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_stages_native_rgb_and_unity_scaling_on_all_pipes
);

/// dpp401_dpp_setup's CNVC format and ALPHA_EN, and the line buffer's
/// alpha (lb_params.alpha_en = per_pixel_alpha), for every format; the
/// rest of the unity RGB state is the same for all of them.
fn dcn401_dpp_programs_every_format_as_linux() -> TestResult {
    for (format, _, _, _, _, cnvc, alpha_en, alpha) in LINUX_FORMATS {
        let p = 2;
        let mode = Mode {
            surface: SurfaceRequest { format, ..req(p) },
            ..small(p)
        };
        let (_backing, pool, mut e, mut surfaces, clock) = ready_with(p, ColorDepth::Bpc8, mode);
        let a = run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))).unwrap();
        assert_eq!(a.line_buffer_config, 1);
        for (r, value) in RGB {
            let value = match r {
                0xcd0 => 0x24000001 | alpha_en << 8 | 0x100000,
                0xccf => cnvc,
                0xd21 => u32::from(alpha) << 4,
                0xd67 => value | 0x100,
                _ => value,
            };
            assert_eq!(
                e.fake().regs[&d(p, r)],
                (if r == 0xd76 { 0 } else { 0x80000000 }) | value
            );
        }
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_programs_every_format_as_linux
);

fn dcn401_dpp_preflight_rejects_stale_owners_geometry_and_pending_updates() -> TestResult {
    let (_backing, _pool, mut e, mut surfaces, clock) = ready(0);
    for p in [1, 4, 255] {
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))),
            Err(Error::Invalid)
        );
    }
    for (c, memory) in [
        (
            dccg::Applied {
                dpp_phase: clock.dpp_phase ^ 1,
                ..clock
            },
            config(),
        ),
        (
            clock,
            DisplayContext {
                root: config().root + 4096,
                ..config()
            },
        ),
    ] {
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, 0, || Ok((c, memory)))),
            Err(Error::Invalid)
        );
    }
    let saved = e.status.blanks[0].unwrap();
    let mut mismatched = saved;
    mismatched.timing.request.timing.h_active += 1;
    e.status.blanks[0] = Some(mismatched);
    e.status.pipes[0] = Some(mismatched.timing);
    assert_eq!(
        run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))),
        Err(Error::Invalid)
    );
    e.status.blanks[0] = Some(saved);
    e.status.pipes[0] = Some(saved.timing);
    for (at, value) in [
        (d(0, 0xcd0), 0x100000),
        (d(0, 0xd18), 1),
        (d(0, 0xd67), 0x100),
        (d(0, 0xcc5), 0x10),
        (d(0, 0xcc5), 0x10000000),
        (d(0, 0xcc6), 0x1111),
        (d(0, 0xcf1), 1),
        (d(0, 0xcf1), 0x10000),
        (d(0, 0xd24), 0x30),
        (d(0, 0xd24), 0x10000000),
        (h(0, 0x60a), 0),
        (h(0, 0x5f4), 1),
        (BASE + 0x477 * 4, 0),
        (BASE + 0x1b2a * 4, 0),
        (BASE + 0x1840 * 4, 0x100),
        (MPC_BASE + 0x2f2 * 4, 0),
    ] {
        let old = e.fake().regs.insert(at, value);
        assert!(run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))).is_err());
        e.fake().regs.insert(at, old.unwrap_or(0));
    }
    assert!(e.fake().writes.is_empty());
    assert_eq!(e.status.state, State::BlankPrepared);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_preflight_rejects_stale_owners_geometry_and_pending_updates
);

fn dcn401_dpp_lost_writes_revocation_and_device_loss_quarantine() -> TestResult {
    for mode in 0..3 {
        for n in 1..=34 {
            let (_backing, pool, mut e, mut surfaces, clock) = ready(2);
            let authority = e.authority;
            match mode {
                0 => e.fake().reject = Some(n),
                1 => e.fake().revoke = Some((n, authority)),
                _ => e.fake().gone = Some(n),
            }
            let error = run(surfaces.prepare_dpp(&mut e, 2, || Ok((clock, config())))).unwrap_err();
            assert_eq!(e.status.state, State::Failed(error));
            assert!(matches!(
                error,
                Error::Readback(_) | Error::Revoked | Error::DeviceGone
            ));
            assert_eq!(e.status.dpps, [None; 4]);
            let count = e.fake().writes.len();
            assert_eq!(
                run(surfaces.prepare_dpp(&mut e, 2, || Ok((clock, config())))),
                Err(Error::Busy)
            );
            assert_eq!(e.fake().writes.len(), count);
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_lost_writes_revocation_and_device_loss_quarantine
);

fn dcn401_dpp_ram_wake_timeout_cancellation_and_late_changes_fail_closed() -> TestResult {
    for stage in 0..2 {
        for cancel in [false, true] {
            let (_backing, pool, mut e, mut surfaces, clock) = ready(1);
            e.io.stall = 1 << stage;
            e.io.delay = [0; 2];
            if cancel {
                let mut f =
                    core::pin::pin!(surfaces.prepare_dpp(&mut e, 1, || Ok((clock, config()))));
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                let at = d(1, if stage == 0 { 0xd25 } else { 0xd62 });
                assert_eq!(
                    run(surfaces.prepare_dpp(&mut e, 1, || Ok((clock, config())))),
                    Err(Error::Timeout(at))
                );
            }
            assert!(matches!(
                e.status.state,
                State::PreparingDpp(1) | State::Failed(Error::Timeout(_))
            ));
            assert_eq!(e.status.dpps, [None; 4]);
            assert_eq!(e.fake().writes.len(), 2 + stage);
            assert_eq!(e.fake().regs[&d(1, 0xcc5)] & 0x10, 0x10); // no speculative rollback
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    for (n, at, value) in [
        (2, BASE + 0x1b43 * 4, 1),
        (3, d(0, 0xcc6), 1),
        (34, d(0, 0xcd4), 0),
        (34, h(0, 0x60a), 0),
        (34, BASE + 0x477 * 4, 0),
    ] {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready(0);
        e.fake().after_write = Some((n, at, value));
        assert!(run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.dpps, [None; 4]);
    }
    let (_backing, _pool, mut e, mut surfaces, clock) = ready(3);
    let mut checks = 0;
    assert_eq!(
        run(surfaces.prepare_dpp(&mut e, 3, || {
            checks += 1;
            if checks == 1 {
                Ok((clock, config()))
            } else {
                Err(Error::PipeClocks(dccg::Error::Revoked))
            }
        })),
        Err(Error::PipeClocks(dccg::Error::Revoked))
    );
    assert_eq!(e.status.dpps, [None; 4]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_ram_wake_timeout_cancellation_and_late_changes_fail_closed
);
