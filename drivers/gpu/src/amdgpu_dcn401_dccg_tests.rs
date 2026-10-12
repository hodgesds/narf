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
            (BASE..=BASE + 0xa8 * 4).contains(&at) || at == 0x10000 + 0x5a * 4,
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
        for gone in [false, true] {
            let mut e = engine();
            e.io.regs.insert(at, if gone { u32::MAX } else { mask });
            assert_eq!(
                run(e.prepare(request(0), clocks())),
                Err(if gone { Error::DeviceGone } else { Error::Busy })
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
