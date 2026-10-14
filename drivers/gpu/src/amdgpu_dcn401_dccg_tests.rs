use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const BASE: u64 = 0x1000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    reject: Option<usize>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
    dentist_delay: u32,
    dentist_pending: bool,
    dentist_stall: bool,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if at == BASE + 0x64 * 4 && self.dentist_pending && !self.dentist_stall {
            if self.dentist_delay == 0 {
                *self.regs.entry(at).or_default() |= 1 << 19;
                self.dentist_pending = false;
            } else {
                self.dentist_delay -= 1;
            }
        }
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert!(
            (BASE..=BASE + 0xa8 * 4).contains(&at)
                || [0x10000 + 0x59 * 4, 0x10000 + 0x5a * 4].contains(&at),
            "write outside DCCG"
        );
        self.writes.push((at, value));
        if self.reject == Some(self.writes.len()) {
            return;
        }
        if at == BASE + 0x64 * 4 {
            // Dentist is a request/status register, not ordinary RAM.
            self.dentist_pending = true;
            self.regs.insert(at, value & !(1 << 19));
        } else {
            self.regs.insert(at, value);
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
    dc.base_addrs[1] = (BASE / 4) as u32;
    dc.base_addrs[2] = 0x4000;
    dc.base_addrs[3] = 0xc000;
    gpu.ip_blocks.extend([mp, dc]);
    gpu
}
fn engine() -> Engine<Fake> {
    let mut words = vec![0; 0x80000 / 4];
    let g = descriptor(&mut words);
    Engine {
        io: Fake {
            // 45 * 100 MHz VCO / (25 / 4) = 720 MHz DPREFCLK.
            regs: BTreeMap::from([(PLL, 45), (DPREF, 25)]),
            writes: Vec::new(),
            reject: None,
            revoke: None,
            dentist_delay: 0,
            dentist_pending: false,
            dentist_stall: false,
        },
        authority: Cap::bootstrap(),
        layout: Layout::resolve(&g).unwrap(),
        status: Status {
            state: State::Ready,
            pipes: [None; 4],
            routes: [None; 5],
            dscclk: 0,
        },
    }
}
fn clocks() -> clocks::Applied {
    clocks::Applied {
        request: clocks::Request {
            displays: 1,
            display_khz: 600_001,
            dpp_khz: 350_999,
            dtb_khz: 600_000,
        },
        display_khz: 601_000,
        dpp_khz: 351_000,
        dtb_khz: 600_000,
        dcf_floor_khz: 1_200_000,
        memory_floor_khz: 1_200_000,
    }
}
fn request(pipe: u8) -> Request {
    Request {
        pipe,
        dpp_khz: 148_500,
        pixel: PixelClock::DisplayPort {
            pixel_hz: 148_500_000,
        },
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn reg(e: &Engine<Fake>, r: u64) -> u32 {
    *e.io.regs.get(&(BASE + r * 4)).unwrap_or(&0)
}

fn dcn401_dccg_timing_references_check_live_dividers_and_state() -> TestResult {
    for pixel in [
        PixelClock::DisplayPort {
            pixel_hz: 148_500_000,
        },
        PixelClock::HdmiFrl {
            pixel_hz: 148_500_000,
        },
        PixelClock::Tmds {
            divider: TmdsDivider::By2,
        },
        PixelClock::Tmds {
            divider: TmdsDivider::By4,
        },
    ] {
        let mut e = engine();
        let mut req = request(2);
        req.pixel = pixel;
        let a = run(e.prepare(req, clocks())).unwrap();
        e.io.writes.clear();
        assert_eq!(e.current_pipe(2, clocks()), Ok(a));
        assert!(e.io.writes.is_empty());
        let mut stale = clocks();
        stale.display_khz += 1;
        assert_eq!(e.current_pipe(2, stale), Err(Error::Invalid));
        for state in [
            State::Ready,
            State::Applied,
            State::Applying,
            State::Failed(Error::Timeout),
        ] {
            e.status.state = state;
            assert_eq!(
                e.current_pipe(2, clocks()).is_ok(),
                matches!(state, State::Ready | State::Applied)
            );
        }
        e.status.state = State::Applied;
        *e.io.regs.entry(BASE + 0xa8 * 4).or_default() ^= 1 << 6;
        assert_eq!(
            e.current_pipe(2, clocks()),
            Err(Error::Readback(BASE + 0xa8 * 4))
        );
        assert!(matches!(e.status.state, State::Failed(_)));
    }
    // TMDS has no DP DTO modulus proof: verify the native disable and divider.
    for (r, bit) in [(0x80, 0x10), (0x6f, 1)] {
        let mut e = engine();
        let mut req = request(0);
        req.pixel = PixelClock::Tmds {
            divider: TmdsDivider::By2,
        };
        run(e.prepare(req, clocks())).unwrap();
        *e.io.regs.entry(BASE + r * 4).or_default() ^= bit;
        assert_eq!(
            e.current_pipe(0, clocks()),
            Err(Error::Readback(BASE + r * 4))
        );
    }
    let mut e = engine();
    let mut req = request(0);
    req.pixel = PixelClock::Disabled;
    req.dpp_khz = 0;
    run(e.prepare(req, clocks())).unwrap();
    assert_eq!(e.current_pipe(0, clocks()), Err(Error::Invalid));
    TestResult::Pass
}

fn dcn401_dccg_retained_references_validate_live_clocks_without_granting_writes() -> TestResult {
    for (changed, bit) in [
        (0x80, 0x10),
        (0x81, 1),
        (0x82, 1),
        (0x68, 1),
        (0x6f, 2),
        (0xa8, 1),
        (0x99, 1),
    ] {
        let mut e = engine();
        let a = run(e.prepare(request(0), clocks())).unwrap();
        // A trained backend blocks all existing programming and ordinary
        // idle-only references, but permits a read-only retained reference.
        e.io.regs.insert(e.layout.idle[2].0, 1);
        let writes = e.io.writes.len();
        assert_eq!(e.current_pipe(0, clocks()), Err(Error::Busy));
        assert_eq!(run(e.prepare(request(0), clocks())), Err(Error::Busy));
        assert_eq!(e.retained_pipe(0, clocks()), Ok(a));
        assert_eq!(e.io.writes.len(), writes);
        *e.io.regs.entry(BASE + changed * 4).or_default() ^= bit;
        assert!(matches!(
            e.retained_pipe(0, clocks()),
            Err(Error::Readback(_))
        ));
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.retained_pipe(0, clocks()), Err(Error::Busy));
    }
    let mut e = engine();
    run(e.prepare(request(0), clocks())).unwrap();
    e.authority.revoke();
    assert_eq!(e.retained_pipe(0, clocks()), Err(Error::Revoked));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_retained_references_validate_live_clocks_without_granting_writes
);
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_timing_references_check_live_dividers_and_state
);

fn dcn401_dccg_native_dp_dpp_layout_and_preservation() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        for r in [0x68, 0x69, 0x6f, 0xa8, 0xb6, 0x80 + 4 * u64::from(pipe)] {
            e.io.regs.insert(BASE + r * 4, 0x4000_0000);
        }
        e.io.regs.insert(0x10000 + 0x5a * 4, 0x4000_0000);
        let applied = run(e.prepare(request(pipe), clocks())).unwrap();
        assert_eq!(applied.dpp_phase, 108);
        assert_eq!(
            (applied.reference_hz, applied.integer, applied.phase),
            (720_000_000, 0, 148_500_000)
        );
        let p = u64::from(pipe);
        // Independent native register sequence, not values built with driver constants.
        assert_eq!(
            e.io.writes,
            [
                (BASE + (0x99 + p) * 4, 0xff006c),
                (BASE + 0xa8 * 4, 0x4000_0000 | 1 << (3 * pipe)),
                (BASE + 0x69 * 4, 0x4000_0000 | 1 << pipe),
                (
                    0x10000 + 0x5a * 4,
                    0x4000_0000 | 3 << (8 + 2 * pipe) | 3 << (20 + 2 * pipe)
                ),
                (BASE + 0x68 * 4, 0x4000_0000 | 4 << (3 * pipe)),
                (BASE + (0x81 + 4 * p) * 4, 148_500_000),
                (BASE + (0x82 + 4 * p) * 4, 720_000_000),
                (BASE + 0x6f * 4, 0x4000_0000),
                (BASE + (0x80 + 4 * p) * 4, 0x4000_1010),
            ]
        );
        assert_eq!(
            reg(&e, 0xb6),
            0x4000_0000,
            "legacy DTO enable register written"
        );
        assert_eq!(e.status.pipes[usize::from(pipe)], Some(applied));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_native_dp_dpp_layout_and_preservation
);

fn dcn401_dccg_integer_frl_and_parking_preserve_other_pipes() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        let mut req = request(pipe);
        req.pixel = PixelClock::HdmiFrl {
            pixel_hz: 1_485_000_000,
        };
        let p = run(e.prepare(req, clocks())).unwrap();
        assert_eq!(
            (p.reference_hz, p.integer, p.phase),
            (600_000_000, 2, 285_000_000)
        );
        assert_eq!(reg(&e, 0x6f), 2 << (5 * pipe + 1));
        assert_eq!(reg(&e, 0x68), 6 << (3 * pipe));
        req.dpp_khz = 0;
        req.pixel = PixelClock::Disabled;
        e.io.writes.clear();
        run(e.prepare(req, clocks())).unwrap();
        assert_eq!(
            e.io.writes,
            [
                (BASE + 0xa8 * 4, 0),
                (BASE + (0x80 + 4 * u64::from(pipe)) * 4, 0),
                (BASE + 0x68 * 4, 2 << (3 * pipe)),
            ]
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_integer_frl_and_parking_preserve_other_pipes
);

fn dcn401_dccg_tmds_waits_for_native_dentist_workaround() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        let mut req = request(pipe);
        req.pixel = PixelClock::Tmds {
            divider: TmdsDivider::By4,
        };
        e.io.regs.insert(BASE + 0x64 * 4, 0x0088_2525);
        e.io.regs.insert(BASE + 0x6f * 4, 7 << (5 * pipe + 1));
        e.io.dentist_delay = 3;
        let a = run(e.prepare(req, clocks())).unwrap();
        assert_eq!(a.reference_hz, 0);
        assert_eq!(reg(&e, 0x6f), 15 << (5 * pipe));
        assert_eq!(e.io.writes.last(), Some(&(BASE + 0x64 * 4, 0x0088_2525)));
        assert!(!e.io.dentist_pending);
        e.io.writes.clear();
        run(e.prepare(req, clocks())).unwrap();
        assert_eq!(e.io.writes.len(), 3, "unchanged divider must skip dentist");
        req.pixel = PixelClock::Tmds {
            divider: TmdsDivider::By2,
        };
        run(e.prepare(req, clocks())).unwrap();
        assert_eq!(reg(&e, 0x6f), 7 << (5 * pipe + 1));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_tmds_waits_for_native_dentist_workaround
);

fn dcn401_dccg_rejects_bad_plans_and_reference_snapshots_before_writes() -> TestResult {
    assert_eq!(dpref_hz(45, 25), Ok(720_000_000));
    assert_eq!(dpref_hz(0x8000_f02d, 25), Ok(728_000_000)); // fractional multiplier, ignored spine
    for (did, div) in [
        (8, 8),
        (63, 63),
        (64, 64),
        (95, 126),
        (96, 128),
        (125, 244),
        (126, 248),
        (127, 512),
    ] {
        assert_eq!(dpref_hz(45, did), Ok((18_000_000 / div) * 1000));
    }
    for (pll, did, err) in [
        (0, 25, Error::Invalid),
        (45, 0, Error::Invalid),
        (45, 7, Error::Invalid),
        (45, 128, Error::Invalid),
        (u32::MAX, 25, Error::DeviceGone),
        (45, u32::MAX, Error::DeviceGone),
        (511, 8, Error::Invalid),
    ] {
        assert_eq!(dpref_hz(pll, did), Err(err));
    }
    for case in 0..9 {
        let mut e = engine();
        let mut r = request(0);
        let mut g = clocks();
        match case {
            0 => r.pipe = 4,
            1 => r.dpp_khz = g.dpp_khz + 1,
            2 => r.dpp_khz = 0,
            3 => r.pixel = PixelClock::Disabled,
            4 => r.pixel = PixelClock::DisplayPort { pixel_hz: 0 },
            5 => {
                r.pixel = PixelClock::DisplayPort {
                    pixel_hz: 720_000_000 * 16,
                }
            }
            6 => {
                g.dtb_khz = 0;
                r.pixel = PixelClock::HdmiFrl { pixel_hz: 1 };
            }
            7 => {
                g.dtb_khz = u32::MAX;
                r.pixel = PixelClock::HdmiFrl { pixel_hz: 1 };
            }
            _ => {
                e.io.regs.insert(PLL, 0);
            }
        }
        assert_eq!(run(e.prepare(r, g)), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_rejects_bad_plans_and_reference_snapshots_before_writes
);

fn dcn401_dccg_all_live_consumers_block_programming() -> TestResult {
    let idle = engine().layout.idle;
    for (at, mask) in idle {
        for value in core::iter::once(u32::MAX)
            .chain((0..32).map(|bit| 1u32 << bit).filter(|v| mask & v != 0))
        {
            let mut e = engine();
            e.io.regs.insert(at, value);
            assert_eq!(
                run(e.prepare(request(0), clocks())),
                Err(if value == u32::MAX {
                    Error::DeviceGone
                } else {
                    Error::Busy
                })
            );
            assert!(e.io.writes.is_empty());
            assert_eq!(e.status.state, State::Ready);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_all_live_consumers_block_programming
);

fn dcn401_dccg_partial_failure_and_revocation_block_reuse() -> TestResult {
    let mut req = request(0);
    // A nonzero integer ensures ignoring any write changes its readback.
    req.pixel = PixelClock::DisplayPort {
        pixel_hz: 800_000_000,
    };
    for step in 1..=9 {
        for revoke in [false, true] {
            let mut e = engine();
            if revoke {
                e.io.revoke = Some((step, e.authority));
            } else {
                e.io.reject = Some(step);
            }
            let err = run(e.prepare(req, clocks())).unwrap_err();
            assert!(if revoke {
                err == Error::Revoked
            } else {
                matches!(err, Error::Readback(_))
            });
            assert_eq!(e.io.writes.len(), step);
            assert_eq!(e.status.state, State::Failed(err));
            assert_eq!(e.status.pipes, [None; 4]);
            assert_eq!(run(e.prepare(req, clocks())), Err(Error::Busy));
            assert_eq!(e.io.writes.len(), step);
        }
    }
    let mut e = engine();
    let old = run(e.prepare(req, clocks())).unwrap();
    e.io.regs.insert(BASE + 0xa8 * 4, u32::MAX);
    assert_eq!(run(e.prepare(req, clocks())), Err(Error::DeviceGone));
    assert_eq!(
        e.status.pipes[0],
        Some(old),
        "keep evidence without publishing failed pipe"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_partial_failure_and_revocation_block_reuse
);

fn dcn401_dccg_dentist_timeout_and_cancel_are_terminal() -> TestResult {
    for cancel in [false, true] {
        let mut e = engine();
        e.io.dentist_stall = true;
        let mut req = request(0);
        req.pixel = PixelClock::Tmds {
            divider: TmdsDivider::By4,
        };
        if cancel {
            let mut cx = Context::from_waker(Waker::noop());
            {
                let mut f = core::pin::pin!(e.prepare(req, clocks()));
                assert!(f.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(e.status.state, State::Applying);
        } else {
            assert_eq!(run(e.prepare(req, clocks())), Err(Error::Timeout));
            assert_eq!(e.status.state, State::Failed(Error::Timeout));
        }
        let n = e.io.writes.len();
        assert_eq!(run(e.prepare(req, clocks())), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.pipes, [None; 4]);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_dentist_timeout_and_cancel_are_terminal
);

fn dcn401_dccg_constructor_and_matching_global_owner_are_required() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let g = descriptor(&mut words);
    let before = words.clone();
    let cap = Cap::bootstrap();
    // SAFETY: owned RAM fixture, no constructor hardware writes.
    let mut d = unsafe { Dccg::new(&g, cap) }.unwrap();
    // SAFETY: matching retained fake device and exclusive DAL mailbox.
    let mut c = unsafe { clocks::ClockManager::new(&g, cap) }.unwrap();
    assert_eq!(
        run(d.prepare(&mut c, request(0))),
        Err(Error::Clocks(clocks::Error::Busy))
    );
    assert_eq!(words, before);
    for case in 0..5 {
        let mut g = descriptor(&mut words);
        let dc = g.ip_blocks.len() - 1;
        match case {
            0 => g.regs.len = DPREF + 3,
            1 => g.ip_blocks[dc].base_addrs[1] = 0x20000 - 0xa8,
            2 => g.chip.did = crate::amdgpu::NAVI22,
            3 => g.ip_blocks[dc].revision = 2,
            _ => g.ip_blocks.push(g.ip_blocks[dc]),
        }
        // SAFETY: metadata-only rejection before hardware access.
        assert!(unsafe { Dccg::new(&g, cap) }.is_err());
    }
    cap.revoke();
    // SAFETY: revoked capability must fail without touching registers.
    assert!(matches!(unsafe { Dccg::new(&g, cap) }, Err(Error::Revoked)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_dccg_constructor_and_matching_global_owner_are_required
);

fn dcn401_stream_routes_use_prepared_pipe_without_changing_its_reference() -> TestResult {
    for pipe in 0..4 {
        for stream in [
            Stream::HpoDp(0),
            Stream::HpoDp(1),
            Stream::HpoDp(2),
            Stream::HpoDp(3),
            Stream::HdmiFrl,
        ] {
            let mut e = engine();
            let mut req = request(pipe);
            if stream == Stream::HdmiFrl {
                req.pixel = PixelClock::HdmiFrl {
                    pixel_hz: 148_500_000,
                };
            }
            let plan = run(e.prepare(req, clocks())).unwrap();
            e.io.writes.clear();
            let route = StreamRoute {
                stream,
                pipe: Some(pipe),
            };
            e.route(route, clocks()).unwrap();
            if let Stream::HpoDp(i) = stream {
                assert_eq!(
                    e.io.writes,
                    [
                        (BASE + 0x69 * 4, (1 << pipe) | (3 << (6 + 2 * i))),
                        (BASE + 0x4a * 4, (8 | u32::from(pipe)) << (4 * i)),
                    ]
                );
            } else {
                assert_eq!(e.io.writes, [(0x10000 + 0x59 * 4, 8 | u32::from(pipe))]);
            }
            assert_eq!(e.status.routes[stream.slot().unwrap()], Some(route));
            assert_eq!(e.status.pipes[usize::from(pipe)], Some(plan));
            e.io.writes.clear();
            let parked = StreamRoute { stream, pipe: None };
            e.route(parked, clocks()).unwrap();
            let (at, shift) = e.route_register(stream).unwrap();
            assert_eq!((e.io.regs[&at] >> shift) & 15, u32::from(pipe));
            assert_eq!(e.status.routes[stream.slot().unwrap()], Some(parked));
            assert!(
                !e.io.writes.iter().any(|&(at, _)| at == BASE + 0x68 * 4),
                "route changed DPREF to DTB"
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_stream_routes_use_prepared_pipe_without_changing_its_reference
);

fn dcn401_stream_routes_reject_stale_or_changed_sources() -> TestResult {
    for case in 0..13 {
        let mut e = engine();
        run(e.prepare(request(2), clocks())).unwrap();
        e.io.writes.clear();
        let mut route = StreamRoute {
            stream: Stream::HpoDp(1),
            pipe: Some(2),
        };
        let mut g = clocks();
        match case {
            0 => route.stream = Stream::HpoDp(4),
            1 => route.pipe = Some(4),
            2 => route.pipe = Some(1),
            3 => route.stream = Stream::HdmiFrl,
            4 => g.dpp_khz += 1,
            5 => {
                e.io.regs.insert(BASE + (0x99 + 2) * 4, 0);
            }
            6 => {
                e.io.regs.insert(BASE + 0xa8 * 4, 0);
            }
            7 => {
                e.io.regs.insert(BASE + 0x68 * 4, 6 << 6);
            }
            8 => {
                e.io.regs.insert(BASE + (0x81 + 8) * 4, 0);
            }
            9 => {
                e.io.regs.insert(BASE + (0x82 + 8) * 4, 0);
            }
            10 => {
                e.io.regs.insert(BASE + 0x6f * 4, 2 << 11);
            }
            11 => {
                e.io.regs.insert(BASE + (0x80 + 8) * 4, 0);
            }
            _ => {
                e.io.regs.insert(DPREF, 26);
            }
        }
        let err = e.route(route, g).unwrap_err();
        if case <= 4 {
            assert_eq!(err, Error::Invalid);
            assert_eq!(e.status.state, State::Applied);
        } else {
            assert!(matches!(err, Error::Readback(_)));
            assert_eq!(e.status.state, State::Failed(err));
        }
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.routes, [None; 5]);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_stream_routes_reject_stale_or_changed_sources
);

fn dcn401_changing_pixel_clock_parks_all_matching_inherited_routes_first() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        let other = (pipe + 1) % 4;
        let dp = 0x4000_0000
            | (8 | u32::from(pipe))
            | ((8 | u32::from(other)) << 4)
            | ((8 | u32::from(pipe)) << 8);
        e.io.regs.insert(BASE + 0x4a * 4, dp);
        e.io.regs.insert(BASE + 0x69 * 4, 0x4000_3fc0);
        e.io.regs
            .insert(0x10000 + 0x59 * 4, 0x4000_0008 | u32::from(pipe));
        run(e.prepare(request(pipe), clocks())).unwrap();
        assert_eq!(
            &e.io.writes[..6],
            &[
                (BASE + 0x4a * 4, dp & !8),
                (BASE + 0x69 * 4, 0x4000_3f00),
                (BASE + 0x4a * 4, dp & !0x808),
                (BASE + 0x69 * 4, 0x4000_3300),
                (0x10000 + 0x59 * 4, 0x4000_0000 | u32::from(pipe)),
                (BASE + (0x99 + u64::from(pipe)) * 4, 0xff006c),
            ]
        );
        assert_eq!(reg(&e, 0x4a), dp & !0x808);
        assert_eq!(e.status.routes[1], None, "unrelated route disturbed");
        for (slot, stream) in [
            (0, Stream::HpoDp(0)),
            (2, Stream::HpoDp(2)),
            (4, Stream::HdmiFrl),
        ] {
            assert_eq!(
                e.status.routes[slot],
                Some(StreamRoute { stream, pipe: None })
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_changing_pixel_clock_parks_all_matching_inherited_routes_first
);

fn dcn401_routing_failure_or_revocation_prevents_clock_reuse() -> TestResult {
    for stream in [Stream::HpoDp(2), Stream::HdmiFrl] {
        let steps = if stream == Stream::HdmiFrl { 1 } else { 2 };
        for step in 1..=steps {
            for revoke in [false, true] {
                let mut e = engine();
                let mut req = request(3);
                if stream == Stream::HdmiFrl {
                    req.pixel = PixelClock::HdmiFrl {
                        pixel_hz: 148_500_000,
                    };
                }
                run(e.prepare(req, clocks())).unwrap();
                e.io.writes.clear();
                if revoke {
                    e.io.revoke = Some((step, e.authority));
                } else {
                    e.io.reject = Some(step);
                }
                let route = StreamRoute {
                    stream,
                    pipe: Some(3),
                };
                let err = e.route(route, clocks()).unwrap_err();
                assert!(if revoke {
                    err == Error::Revoked
                } else {
                    matches!(err, Error::Readback(_))
                });
                assert_eq!(e.status.state, State::Failed(err));
                assert_eq!(e.status.routes, [None; 5]);
                assert_eq!(e.io.writes.len(), step);
                assert_eq!(run(e.prepare(req, clocks())), Err(Error::Busy));
                assert_eq!(e.route(route, clocks()), Err(Error::Busy));
                assert_eq!(e.io.writes.len(), step);
            }
        }
    }
    let idle = engine().layout.idle;
    for (at, mask) in idle {
        let mut e = engine();
        run(e.prepare(request(0), clocks())).unwrap();
        e.io.writes.clear();
        e.io.regs.insert(at, mask);
        assert_eq!(
            e.route(
                StreamRoute {
                    stream: Stream::HpoDp(0),
                    pipe: Some(0)
                },
                clocks()
            ),
            Err(Error::Busy)
        );
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_routing_failure_or_revocation_prevents_clock_reuse
);

fn dcn401_inherited_route_retirement_failure_stops_before_dto_writes() -> TestResult {
    for step in 1..=5 {
        for revoke in [false, true] {
            let mut e = engine();
            e.io.regs.insert(BASE + 0x4a * 4, 0x808);
            e.io.regs.insert(BASE + 0x69 * 4, 0x3fc0);
            e.io.regs.insert(0x10000 + 0x59 * 4, 8);
            if revoke {
                e.io.revoke = Some((step, e.authority));
            } else {
                e.io.reject = Some(step);
            }
            let err = run(e.prepare(request(0), clocks())).unwrap_err();
            assert!(if revoke {
                err == Error::Revoked
            } else {
                matches!(err, Error::Readback(_))
            });
            assert_eq!(e.status.state, State::Failed(err));
            assert_eq!(e.io.writes.len(), step);
            assert_eq!(e.status.pipes, [None; 4]);
            assert!(!e
                .io
                .writes
                .iter()
                .any(|&(at, _)| (BASE + 0x80 * 4..=BASE + 0xa8 * 4).contains(&at)));
            assert_eq!(run(e.prepare(request(0), clocks())), Err(Error::Busy));
            assert_eq!(e.io.writes.len(), step);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_inherited_route_retirement_failure_stops_before_dto_writes
);

/// dcn401_enable_stream's 128b/132b stream clocks: DPSTREAMCLK from the
/// pipe, then SYMCLK32_SE from the PHY, no gate-disable writes (root clock
/// optimization is off); a route already on is refused; the disable order
/// is SYMCLK32_SE (to REFCLK) then DPSTREAMCLK.
fn dcn401_hpo_stream_clocks_follow_linux() -> TestResult {
    let (pipe, stream, phy) = (2u8, 1u8, 3u8);
    let mut e = engine();
    run(e.prepare(request(pipe), clocks())).unwrap();
    e.io.writes.clear();
    e.route_hpo_stream(stream, pipe, phy, clocks()).unwrap();
    let shift = 4 * u32::from(stream);
    if e.io.writes
        != [
            (BASE + 0x4a * 4, (8 | u32::from(pipe)) << shift),
            (BASE + 0x65 * 4, (8 | u32::from(phy)) << shift),
        ]
    {
        return TestResult::Fail("stream clock writes");
    }
    assert_eq!(
        e.route_hpo_stream(stream, pipe, phy, clocks()),
        Err(Error::Busy)
    );
    e.io.writes.clear();
    e.unroute_hpo_stream(stream).unwrap();
    if e.io.writes
        != [
            (BASE + 0x65 * 4, 0),
            (BASE + 0x4a * 4, u32::from(pipe) << shift),
        ]
    {
        return TestResult::Fail("stream clock disable");
    }
    // A pipe without a DP pixel clock has no stream to clock.
    let mut e = engine();
    let mut req = request(pipe);
    req.pixel = PixelClock::Tmds {
        divider: TmdsDivider::By4,
    };
    run(e.prepare(req, clocks())).unwrap();
    assert_eq!(
        e.route_hpo_stream(stream, pipe, phy, clocks()),
        Err(Error::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_hpo_stream_clocks_follow_linux
);

/// dccg401_set_hdmistreamclk: HDMISTREAMCLK0 from the pipe's retained FRL
/// pixel clock (enable and source in one update, no gate writes), refused
/// while on or for a non-FRL pipe; REFCLK turns it off, keeping the source.
fn dcn401_frl_stream_clock_follows_linux() -> TestResult {
    let pipe = 3u8;
    let mut e = engine();
    let mut req = request(pipe);
    req.pixel = PixelClock::HdmiFrl {
        pixel_hz: 148_500_000,
    };
    run(e.prepare(req, clocks())).unwrap();
    e.io.writes.clear();
    e.route_frl_stream(pipe, clocks()).unwrap();
    if e.io.writes != [(0x10000 + 0x59 * 4, 8 | u32::from(pipe))] {
        return TestResult::Fail("HDMISTREAMCLK route");
    }
    assert_eq!(e.route_frl_stream(pipe, clocks()), Err(Error::Busy));
    e.io.writes.clear();
    e.unroute_frl_stream().unwrap();
    if e.io.writes != [(0x10000 + 0x59 * 4, u32::from(pipe))] {
        return TestResult::Fail("HDMISTREAMCLK off");
    }
    let mut e = engine();
    run(e.prepare(request(pipe), clocks())).unwrap();
    assert_eq!(e.route_frl_stream(pipe, clocks()), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dccg",
    dcn401_frl_stream_clock_follows_linux
);

/// dccg401_set_dto_dscclk / set_ref_dscclk: the DTO (phase 1, modulo 1)
/// then its enable, only above a 48 MHz pixel clock; REFCLK clears both.
fn dcn401_dscclk_follows_linux() -> TestResult {
    let pipe = 3u8;
    let mut e = engine();
    run(e.prepare(request(pipe), clocks())).unwrap();
    if e.start_dscclk(pipe, clocks()) != Ok(true)
        || e.io.regs[&(BASE + 0x45 * 4)] & 0xff_00ff != 0x1_0001
        || e.io.regs[&(BASE + 0xa7 * 4)] & 0xf != 1 << pipe
        || e.status.dscclk != 1 << pipe
    {
        return TestResult::Fail("DSCCLK DTO");
    }
    assert_eq!(e.start_dscclk(pipe, clocks()), Err(Error::Busy));
    e.stop_dscclk(pipe).unwrap();
    if e.io.regs[&(BASE + 0x45 * 4)] & 0xff_00ff != 0
        || e.io.regs[&(BASE + 0xa7 * 4)] & 0xf != 0
        || e.status.dscclk != 0
    {
        return TestResult::Fail("DSCCLK REFCLK");
    }
    // A 25 MHz stream keeps DSCCLK on REFCLK.
    let mut e = engine();
    let mut slow = request(pipe);
    slow.pixel = PixelClock::DisplayPort {
        pixel_hz: 25_175_000,
    };
    run(e.prepare(slow, clocks())).unwrap();
    if e.start_dscclk(pipe, clocks()) != Ok(false) || e.status.dscclk != 0 {
        return TestResult::Fail("slow DSCCLK");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-dccg", dcn401_dscclk_follows_linux);
