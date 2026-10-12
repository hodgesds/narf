use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::task::{Context, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};
const MP1: u64 = 0x58800;
const DIO: u64 = 0x10000;
const HPO: u64 = 0x30000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    commands: Vec<(u32, u32)>,
    flags: [u32; 11],
    levels: [[u32; 8]; 11],
    interface: u32,
    header: u32,
    refuse: Option<usize>,
    stall: Option<usize>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
    actual: Option<u32>,
    clock: u32,
    ack_delay: usize,
    wrong_ack: bool,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert!([0x58a28, 0x589cc, 0x589d0].contains(&at), "non-DAL write");
        self.regs.insert(at, value);
        if at != 0x58a28 {
            return;
        }
        assert_eq!(self.regs[&0x589d0], 0, "stale response not cleared");
        let arg = self.regs[&0x589cc];
        self.commands.push((value, arg));
        let n = self.commands.len();
        if self.stall == Some(n) {
            return;
        }
        if self.refuse == Some(n) {
            self.regs.insert(0x589d0, 0xfd);
            return;
        }
        let response = match value {
            2 => 0x684c00,
            3 => self.interface,
            4 => self.header,
            11 if arg & 0xff == 0xff => self.flags[(arg >> 16) as usize],
            11 => self.levels[(arg >> 16) as usize][(arg & 0xff) as usize],
            9 => {
                self.clock = arg >> 16;
                self.actual.unwrap_or((arg & 0xffff) * 1000)
            }
            0x15 => {
                assert_eq!(arg, 0);
                if self.ack_delay > 0 {
                    self.ack_delay -= 1;
                    0
                } else if self.wrong_ack {
                    1 << 1
                } else {
                    1 << self.clock
                }
            }
            0xe => {
                assert!((1..=4).contains(&arg));
                0
            }
            0x1a => {
                assert_eq!(arg, 0);
                0
            }
            _ => panic!("wrong DCN401 DAL message"),
        };
        self.regs.insert(0x589cc, response);
        self.regs.insert(0x589d0, 1);
        if let Some((when, cap)) = self.revoke {
            if when == n {
                cap.revoke();
            }
        }
    }
}
fn engine() -> Engine<Fake> {
    Engine {
        authority: Cap::bootstrap(),
        layout: Layout {
            mp1: MP1,
            dio: DIO,
            hpo: HPO,
        },
        status: Status {
            state: State::Prepared,
            levels: None,
            applied: None,
        },
        io: Fake {
            regs: BTreeMap::from([(0x589d0, 1)]),
            commands: Vec::new(),
            flags: [2; 11],
            levels: [[100, 1200, 0, 0, 0, 0, 0, 0]; 11],
            interface: 1,
            header: 1,
            refuse: None,
            stall: None,
            revoke: None,
            actual: None,
            clock: 0,
            ack_delay: 0,
            wrong_ack: false,
        },
    }
}
fn power() -> smu::PowerStatus {
    smu::PowerStatus {
        allowed: 0xba,
        enabled: 0xba,
        gfx_min_mhz: 500,
        gfx_max_mhz: 3100,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn start(e: &mut Engine<Fake>) -> Levels {
    run(e.start(core::future::ready(Ok(power())))).unwrap()
}
fn request() -> Request {
    Request {
        displays: 1,
        display_khz: 600001,
        dpp_khz: 350999,
        dtb_khz: 600000,
    }
}
fn dcn401_dal_queries_native_ids_fine_grained_and_discrete_levels() -> TestResult {
    let mut e = engine();
    e.io.flags[7] = 0x90000000; // fine grained, low count ignored
    e.io.levels[7][0] = 0x40000064; // frequency in low 16 bits
    let levels = start(&mut e);
    assert_eq!(e.status.state, State::Ready);
    assert_eq!(
        (levels.firmware, levels.interface, levels.header),
        (0x684c00, 1, 1)
    );
    assert_eq!(
        e.io.commands[..6],
        [
            (2, 0),
            (3, 0),
            (4, 0),
            (11, 0x100ff),
            (11, 0x10000),
            (11, 0x10001)
        ]
    );
    for clock in [1, 2, 3, 6, 7, 9, 10] {
        assert!(e.io.commands.contains(&(11, clock << 16 | 0xff)));
    }
    assert!(!e.io.commands.iter().any(|&(m, a)| m == 11 && a >> 16 == 8));
    assert_eq!(levels.range(Clock::Dpp).mhz(), [100, 1200]);
    assert!(levels.range(Clock::Dpp).fine_grained);
    assert_eq!(levels.range(Clock::Dpp).flags, 0x90000000);
    assert_eq!(
        run(e.start(core::future::ready(Ok(power())))),
        Err(Error::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_dal_queries_native_ids_fine_grained_and_discrete_levels
);

fn dcn401_dal_refuses_malformed_versions_and_ranges_without_publication() -> TestResult {
    for case in 0..7 {
        let mut e = engine();
        let expected = match case {
            0 => {
                e.io.interface = 0x2e;
                Error::Interface(0x2e)
            }
            1 => {
                e.io.header = 2;
                Error::Interface(2)
            }
            2 => {
                e.io.flags[6] = 0;
                Error::Invalid
            }
            3 => {
                e.io.flags[6] = 9;
                Error::Invalid
            }
            4 => {
                e.io.flags[2] = 7;
                Error::Invalid
            }
            5 => {
                e.io.levels[7][1] = 99;
                Error::Invalid
            }
            _ => {
                e.io.levels[10][0] = 0;
                Error::Invalid
            }
        };
        assert_eq!(
            run(e.start(core::future::ready(Ok(power())))),
            Err(expected)
        );
        assert_eq!(e.status.state, State::Failed(expected));
        assert_eq!(e.status.levels, None);
        assert_eq!(
            run(e.start(core::future::ready(Ok(power())))),
            Err(Error::Busy)
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_dal_refuses_malformed_versions_and_ranges_without_publication
);

fn dcn401_all_legacy_hpo_and_frl_consumers_block_power_and_clock_writes() -> TestResult {
    let mut golden = Vec::new();
    for i in 0..4 {
        for (reg, stride, mask) in [
            (0x1b43, 0x80, 0x10001),
            (0x1b84, 0x80, 0x10000),
            (0x20bd, 0x124, 1),
            (0x2122, 0x124, 0x10001),
            (0x3685, 0xd4, 0x101),
            (0x367b, 0xd4, 1),
            (0x369f, 0xd4, 1),
            (0x2094, 0x124, 0xc10),
            (0x2095, 0x124, 1),
            (0x209b, 0x124, 1),
            (0x3623, 0xd4, 0x11111),
            (0x365d, 0xd4, 1),
        ] {
            golden.push((0x10000 + (reg + i * stride) * 4, mask));
        }
    }
    golden.extend([(0x3234c, 1), (0x32358, 1), (0x3237c, 1)]);
    assert_eq!(engine().layout.idle_registers().as_slice(), golden);
    for (at, mask) in golden {
        for value in core::iter::once(u32::MAX)
            .chain((0..32).map(|bit| 1u32 << bit).filter(|v| mask & v != 0))
        {
            let expected = if value == u32::MAX {
                Error::DeviceGone
            } else {
                Error::Busy
            };
            let mut e = engine();
            e.io.regs.insert(at, value);
            assert_eq!(
                run(e.start(async { panic!("power enabled over live display") })),
                Err(expected)
            );
            assert_eq!(e.status.state, State::Prepared);
            assert!(e.io.commands.is_empty());
            e.io.regs.insert(at, 0);
            start(&mut e);
            e.io.commands.clear();
            e.io.regs.insert(at, value);
            assert_eq!(run(e.prepare(request())), Err(expected));
            assert!(e.io.commands.is_empty());
            assert_eq!(e.status.state, State::Ready);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_all_legacy_hpo_and_frl_consumers_block_power_and_clock_writes
);

fn dcn401_floors_require_per_clock_ack_and_return_khz() -> TestResult {
    let mut e = engine();
    start(&mut e);
    e.io.commands.clear();
    let applied = run(e.prepare(request())).unwrap();
    assert_eq!(
        (applied.display_khz, applied.dpp_khz, applied.dtb_khz),
        (601000, 351000, 600000)
    );
    assert_eq!(
        (applied.dcf_floor_khz, applied.memory_floor_khz),
        (1200000, 1200000)
    );
    assert_eq!(e.status.applied, Some(applied));
    assert_eq!(e.status.state, State::Applied);
    assert_eq!(
        e.io.commands,
        [
            (14, 1),
            (9, 0x904b0),
            (21, 0),
            (9, 0x204b0),
            (21, 0),
            (26, 0),
            (9, 0x60259),
            (21, 0),
            (9, 0x7015f),
            (21, 0),
            (9, 0xa0258),
            (21, 0)
        ]
    );
    e.io.commands.clear();
    e.io.ack_delay = 2;
    run(e.prepare(request())).unwrap();
    assert_eq!(e.io.commands[2..5], [(21, 0); 3]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_floors_require_per_clock_ack_and_return_khz
);

fn dcn401_clock_requests_and_bad_actual_frequencies_fail_closed() -> TestResult {
    let mut e = engine();
    start(&mut e);
    e.io.commands.clear();
    for case in 0..6 {
        let mut r = request();
        match case {
            0 => r.displays = 0,
            1 => r.displays = 5,
            2 => r.display_khz = 0,
            3 => r.display_khz = 1200001,
            4 => r.dpp_khz = u32::MAX,
            _ => r.dtb_khz = 0,
        }
        assert_eq!(run(e.prepare(r)), Err(Error::Invalid));
        assert!(e.io.commands.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    for actual in [601, 600000, 1200001] {
        let mut e = engine();
        start(&mut e);
        e.io.actual = Some(actual);
        assert_eq!(
            run(e.prepare(request())),
            Err(Error::Frequency(Clock::Display, actual))
        );
        assert_eq!(e.status.applied, None);
        assert_eq!(run(e.prepare(request())), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_clock_requests_and_bad_actual_frequencies_fail_closed
);

fn dcn401_partial_failures_and_cancellation_never_replay_mailboxes() -> TestResult {
    let mut ready = engine();
    start(&mut ready);
    let start_count = ready.io.commands.len();
    for starting in [true, false] {
        let n = if starting { start_count } else { 12 };
        for step in 1..=n {
            for cancel in [false, true] {
                let mut e = engine();
                if !starting {
                    start(&mut e);
                    e.io.commands.clear();
                }
                if cancel {
                    e.io.stall = Some(step);
                } else {
                    e.io.refuse = Some(step);
                }
                if cancel {
                    let mut cx = Context::from_waker(Waker::noop());
                    if starting {
                        let mut f = core::pin::pin!(e.start(core::future::ready(Ok(power()))));
                        assert!(f.as_mut().poll(&mut cx).is_pending());
                    } else {
                        let mut f = core::pin::pin!(e.prepare(request()));
                        assert!(f.as_mut().poll(&mut cx).is_pending());
                    }
                    assert_eq!(
                        e.status.state,
                        if starting {
                            State::Starting
                        } else {
                            State::Applying
                        }
                    );
                } else {
                    let result = if starting {
                        run(e.start(core::future::ready(Ok(power())))).map(|_| ())
                    } else {
                        run(e.prepare(request())).map(|_| ())
                    };
                    assert_eq!(result, Err(Error::Rejected(0xfd)));
                    assert_eq!(e.status.state, State::Failed(Error::Rejected(0xfd)));
                }
                assert_eq!(e.io.commands.len(), step);
                assert_eq!(e.status.applied, None);
                assert_eq!(run(e.prepare(request())), Err(Error::Busy));
                assert_eq!(
                    run(e.start(core::future::ready(Ok(power())))),
                    Err(Error::Busy)
                );
                assert_eq!(e.io.commands.len(), step);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_partial_failures_and_cancellation_never_replay_mailboxes
);

fn dcn401_busy_timeouts_revocation_and_power_failures_retain_evidence() -> TestResult {
    let mut e = engine();
    e.io.regs.insert(0x589d0, 0);
    assert_eq!(
        run(e.start(core::future::ready(Ok(power())))),
        Err(Error::Timeout)
    );
    assert!(e.io.commands.is_empty());
    let mut e = engine();
    assert_eq!(
        run(e.start(core::future::ready(Err(smu::Error::Features(0))))),
        Err(Error::Power(smu::Error::Features(0)))
    );
    assert!(e.io.commands.is_empty());
    let mut e = engine();
    start(&mut e);
    e.io.commands.clear();
    e.io.wrong_ack = true;
    assert_eq!(
        run(e.prepare(request())),
        Err(Error::HardMinTimeout(Clock::Dcf))
    );
    assert!(!e.io.commands.iter().any(|&(m, a)| m == 9 && a >> 16 == 2));
    let mut e = engine();
    start(&mut e);
    e.io.commands.clear();
    e.io.stall = Some(3); // accepted floor, no reply to ReturnHardMinStatus
    assert_eq!(
        run(e.prepare(request())),
        Err(Error::HardMinTimeout(Clock::Dcf))
    );
    for step in 1..=12 {
        let mut e = engine();
        start(&mut e);
        e.io.commands.clear();
        e.io.revoke = Some((step, e.authority));
        assert_eq!(run(e.prepare(request())), Err(Error::Revoked));
        assert_eq!(e.io.commands.len(), step);
        assert_eq!(e.status.state, State::Failed(Error::Revoked));
        assert_eq!(e.status.applied, None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_busy_timeouts_revocation_and_power_failures_retain_evidence
);

fn descriptor(words: &mut [u32]) -> AmdGpu {
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(words);
    let mut mp1 = gpu.ip_blocks[0];
    mp1.hw_id = ip::HW_ID_MP1;
    mp1.major = 14;
    mp1.minor = 0;
    mp1.revision = 2;
    mp1.num_bases = 2;
    mp1.base_addrs[1] = 0x16200;
    let mut dcn = mp1;
    dcn.hw_id = ip::HW_ID_DCN;
    dcn.major = 4;
    dcn.minor = 1;
    dcn.revision = 0;
    dcn.num_bases = 4;
    dcn.base_addrs[2] = 0x4000;
    dcn.base_addrs[3] = 0xc000;
    gpu.ip_blocks.push(mp1);
    gpu.ip_blocks.push(dcn);
    gpu
}
fn dcn401_constructor_bounds_native_banks_and_live_authority() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let g = descriptor(&mut words);
    let before = words.clone();
    let cap = Cap::bootstrap();
    // SAFETY: owned RAM model; constructor only validates metadata/authority.
    let c = unsafe { ClockManager::new(&g, cap) }.unwrap();
    assert_eq!(c.status().state, State::Prepared);
    assert_eq!(words, before);
    for case in 0..9 {
        let mut g = descriptor(&mut words);
        let mp = g.ip_blocks.len() - 2;
        let dc = mp + 1;
        match case {
            0 => g.chip.did = crate::amdgpu::NAVI22,
            1 => g.ip_blocks[0].revision = 0,
            2 => g.ip_blocks[mp].base_addrs[1] = 0x16000,
            3 => g.ip_blocks[mp].revision = 1,
            4 => g.ip_blocks[dc].minor = 2,
            5 => g.ip_blocks[dc].num_bases = 3,
            6 => g.ip_blocks[dc].base_addrs[2] = 0x20000 - 0x391b,
            7 => g.ip_blocks[dc].base_addrs[3] = 0x20000 - 0x8df,
            _ => g.ip_blocks.push(g.ip_blocks[mp]),
        }
        // SAFETY: discovery-only rejection, no device accesses.
        let result = unsafe { ClockManager::new(&g, cap) };
        assert!(matches!(result, Err(Error::Unsupported)));
    }
    cap.revoke();
    // SAFETY: revoked capability must fail without hardware access.
    let result = unsafe { ClockManager::new(&g, cap) };
    assert!(matches!(result, Err(Error::Revoked)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_constructor_bounds_native_banks_and_live_authority
);

fn dcn401_fixed_clocks_do_not_issue_unsupported_dpm_commands() -> TestResult {
    let mut e = engine();
    e.io.flags = [1; 11];
    start(&mut e);
    e.io.commands.clear();
    let applied = run(e.prepare(Request {
        displays: 1,
        display_khz: 1,
        dpp_khz: 1,
        dtb_khz: 1,
    }))
    .unwrap();
    assert_eq!(
        (applied.display_khz, applied.dpp_khz, applied.dtb_khz),
        (100000, 100000, 100000)
    );
    assert_eq!(
        (applied.dcf_floor_khz, applied.memory_floor_khz),
        (100000, 100000)
    );
    assert_eq!(e.io.commands, [(14, 1)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_fixed_clocks_do_not_issue_unsupported_dpm_commands
);

fn dcn401_pipe_references_require_current_matching_idle_authority() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let g = descriptor(&mut words);
    let cap = Cap::bootstrap();
    // SAFETY: retained RAM fixture with exclusive clock/consumer registers.
    let mut c = unsafe { ClockManager::new(&g, cap) }.unwrap();
    let mut fake = engine();
    start(&mut fake);
    let applied = run(fake.prepare(request())).unwrap();
    c.0.status.applied = Some(applied);
    for state in [
        State::Prepared,
        State::Starting,
        State::Ready,
        State::Applying,
        State::Failed(Error::Timeout),
    ] {
        c.0.status.state = state;
        assert_eq!(
            c.pipe_clocks(g.regs),
            Err(Error::Busy),
            "historical clocks escaped"
        );
    }
    c.0.status.state = State::Applied;
    let mut other = g.regs;
    other.phys = narf_memory::PhysAddr::new(g.regs.phys.raw() + 4096);
    assert_eq!(c.pipe_clocks(other), Err(Error::Invalid));
    assert_eq!(c.pipe_clocks(g.regs), Ok(applied));
    let (at, mask) = c.0.layout.idle_registers()[0];
    words[at as usize / 4] = mask;
    assert_eq!(c.pipe_clocks(g.regs), Err(Error::Busy));
    words[at as usize / 4] = 0;
    cap.revoke();
    assert_eq!(c.pipe_clocks(g.regs), Err(Error::Revoked));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_pipe_references_require_current_matching_idle_authority
);
