use super::*;
#[path = "amdgpu_dcn401_power_tests.rs"]
mod power_tests;
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
    dc_limit: [u32; 11],
    umc_channels: u32,
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model answers every message synchronously in write() and
        // delays a hard-min acknowledgement by at most ack_delay further
        // message writes (fixtures use at most 2), so a wait still
        // unanswered after sixteen polls is a designed non-response whose
        // outcome is the timeout — reached by count instead of burning
        // the wall-clock deadline under the spin executor (#879).
        Some(16)
    }
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
                // Zero once no display is left (enter_display_off).
                assert!(arg <= 4);
                0
            }
            0x1a => {
                assert!(arg <= 1, "SetUclkPstateAllow takes 0 or 1");
                0
            }
            // ActiveUclkFclk / IdleUclkFclk: the UCLK floor is what
            // ReturnHardMinStatus then acknowledges.
            0x18 | 0x19 => {
                self.clock = 2;
                0
            }
            // SetMinDeepSleepDcfclk, SetDalDramAddrHigh/Low,
            // TransferTableDram2Smu.
            0xd | 5 | 6 => 0,
            8 => {
                assert_eq!(arg, 2, "TABLE_WATERMARKS");
                0
            }
            0xc => self.dc_limit[(arg >> 16) as usize],
            0x1c => {
                assert_eq!(arg, 0);
                self.umc_channels
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
        unanswered_ignored: false,
        layout: Layout {
            mp1: MP1,
            dccg: 0x20000,
            dio: DIO,
            hpo: HPO,
            pool: crate::amdgpu_rdna4::pipe_pool(),
            // No die: idle DPM stays off, so UCLK takes a hard minimum.
            chip: None,
        },
        status: Status {
            state: State::Prepared,
            levels: None,
            applied: None,
            bandwidth: Bandwidth::INIT,
            ignored: Ignored::default(),
            watermarks_ready: false,
            dynamic_power: false,
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
            dc_limit: [0; 11],
            umc_channels: 16,
        },
    }
}
fn power() -> smu::PowerStatus {
    smu::PowerStatus {
        allowed: 0xba,
        enabled: 0xba,
        gfx_min_mhz: 500,
        gfx_max_mhz: 3100,
        uclk_mhz: None,
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
        deep_sleep_dcfclk_khz: 0,
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

fn dcn401_dc_mode_limits_cap_floors_and_umc_channels_are_required() -> TestResult {
    let mut e = engine();
    e.io.levels[2] = [500, 1000, 1250, 0, 0, 0, 0, 0];
    e.io.flags[2] = 3;
    e.io.dc_limit[2] = 1000; // UCLK capped below the table maximum
    e.io.dc_limit[6] = 1200; // equal to the table maximum: no limit
    e.io.dc_limit[9] = 0; // none reported
    e.io.umc_channels = 12;
    let levels = start(&mut e);
    let tail: Vec<_> = e.io.commands[e.io.commands.len() - 6..].to_vec();
    if tail
        != [
            (12, 0x10000),
            (12, 0x20000),
            (12, 0x60000),
            (12, 0x90000),
            (12, 0xa0000),
            (0x1c, 0),
        ]
    {
        return TestResult::Fail("DC-mode/UMC query order");
    }
    if levels.umc_channels != 12
        || levels.range(Clock::Memory).mhz() != [500, 1000, 1250]
        || levels.range(Clock::Memory).max_khz() != 1_000_000
        || levels.range(Clock::Display).max_khz() != 1_200_000
        || levels.range(Clock::Dcf).dc_limit_mhz != 0
    {
        return TestResult::Fail("DC-mode limit not applied");
    }
    // The pinned memory floor honours the cap.
    let applied = run(e.prepare(request())).unwrap();
    if applied.memory_floor_khz != 1_000_000 {
        return TestResult::Fail("memory floor above DC-mode limit");
    }
    for channels in [0, 65] {
        let mut e = engine();
        e.io.umc_channels = channels;
        if run(e.start(core::future::ready(Ok(power())))) != Err(Error::Invalid)
            || e.status.levels.is_some()
        {
            return TestResult::Fail("unknown UMC channel count accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_dc_mode_limits_cap_floors_and_umc_channels_are_required
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
            (0x369f, 0xd4, 0x11),
            (0x2094, 0x124, 0x2c10),
            (0x2095, 0x124, 1),
            (0x209b, 0x124, 1),
            (0x3623, 0xd4, 0x11111),
            (0x365d, 0xd4, 1),
            (0x20bb, 0x124, if i == 0 { 0x3810 } else { 0x2810 }),
            (0x36b4, 0xd4, 3),
            (0x36b5, 0xd4, 0x1f1003),
            (0x2943, 0xd8, 0x3c3c3c3c),
            (0x2931, 0xd8, 0x6f0),
        ] {
            golden.push((0x10000 + (reg + i * stride) * 4, mask));
        }
    }
    golden.extend([
        (0x3234c, 0x1111),
        (0x32358, 0x100011),
        (0x3237c, 0x111),
        (0x3256c, 0x11),
        (0x32570, 3),
    ]);
    golden.push((0x20198, 0x8888));
    golden.push((0x10128, 1));
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
    // NumOfDisplays (the first message) and prepare's UCLK part of the
    // bandwidth sequence (the UCLK hard minimum, its acknowledgement and
    // SetUclkPstateAllow(0)): Linux ignores those results, so a refusal
    // there is logged and prepare completes.
    ready.io.commands.clear();
    run(ready.prepare(request())).unwrap();
    let sequence = ready.io.commands.clone();
    assert_eq!(sequence[0], (0xe, 1));
    let first = sequence.iter().position(|&(m, a)| m == 9 && a >> 16 == 2);
    let last = sequence.iter().position(|&c| c == (0x1a, 0));
    let ignored = |step: usize| match (first, last) {
        (Some(f), Some(l)) => step == 1 || (f + 1..=l + 1).contains(&step),
        _ => false,
    };
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
                    if !starting && ignored(step) {
                        assert_eq!(result, Ok(()));
                        assert_eq!(e.status.state, State::Applied);
                        continue;
                    }
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
            1 => g.ip_blocks[0].revision = 2,
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
        deep_sleep_dcfclk_khz: 0,
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
    e.io.commands.clear();
    let released = run(e.release()).unwrap();
    assert_eq!(e.io.commands, [(14, 0)]);
    assert_eq!(released.request.displays, 0);
    assert_eq!(
        (released.display_khz, released.dpp_khz, released.dtb_khz),
        (100000, 100000, 100000)
    );
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
        assert_eq!(c.retained_pipe_clocks(g.regs), Err(Error::Busy));
    }
    c.0.status.state = State::Applied;
    let mut other = g.regs;
    other.phys = narf_memory::PhysAddr::new(g.regs.phys.raw() + 4096);
    assert_eq!(c.pipe_clocks(other), Err(Error::Invalid));
    assert_eq!(c.retained_pipe_clocks(other), Err(Error::Invalid));
    assert_eq!(c.pipe_clocks(g.regs), Ok(applied));
    let (at, mask) = c.0.layout.idle_registers()[0];
    words[at as usize / 4] = mask;
    assert_eq!(c.pipe_clocks(g.regs), Err(Error::Busy));
    assert_eq!(c.retained_pipe_clocks(g.regs), Ok(applied));
    words[at as usize / 4] = 0;
    cap.revoke();
    assert_eq!(c.pipe_clocks(g.regs), Err(Error::Revoked));
    assert_eq!(c.retained_pipe_clocks(g.regs), Err(Error::Revoked));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_pipe_references_require_current_matching_idle_authority
);

/// One live update with a recording DTO step: the result and the DTO
/// references, in call order.
fn live(
    e: &mut Engine<Fake>,
    request: Request,
    lower: bool,
    held: &(dyn Fn(u64) -> bool + Sync),
) -> (Result<Applied, Error>, Vec<u32>) {
    let mut refs = Vec::new();
    let mut dto = |r: u32| {
        refs.push(r);
        Ok(())
    };
    let result = run(e.update_live(request, lower, held, &mut dto));
    (result, refs)
}

/// The hard-min messages (clock, MHz) a stretch of commands sent.
fn hard_mins(commands: &[(u32, u32)]) -> Vec<(u32, u32)> {
    commands
        .iter()
        .filter(|&&(m, _)| m == 9)
        .map(|&(_, a)| (a >> 16, a & 0xffff))
        .collect()
}

/// dcn401_update_clocks while displays run. prepare_bandwidth (not safe
/// to lower) sends the display count, raises DISPCLK and then the DPP DTO
/// reference before the DTOs (given the reference PMFW returned), and
/// leaves every lower request alone; optimize_bandwidth (safe to lower)
/// sends no count, lowers DISPCLK, then raises the DTOs for the lower
/// reference before lowering it and sets them again for the actual one.
/// Consumers other than the held ones must be idle.
fn dcn401_live_clock_updates_follow_dcn401_update_clocks() -> TestResult {
    let mut e = engine();
    start(&mut e);
    run(e.prepare(request())).unwrap();
    let busy = DIO + 0x1b43 * 4; // OTG0_MASTER_EN: a live display
    e.io.regs.insert(busy, 1);
    let up = Request {
        displays: 2,
        display_khz: 900_000,
        dpp_khz: 700_000,
        dtb_khz: 600_000,
        deep_sleep_dcfclk_khz: 0,
    };
    let (refused, refs) = live(&mut e, up, false, &|_| false);
    if refused != Err(Error::Busy) || !refs.is_empty() {
        return TestResult::Fail("busy consumer not held");
    }
    let held = move |at: u64| at == busy;
    let before = e.io.commands.len();
    let (applied, refs) = live(&mut e, up, false, &held);
    let applied = applied.unwrap();
    let sent = e.io.commands[before..].to_vec();
    // Count first, then DISPCLK (6) and DPPCLK (7); DTBCLK unchanged.
    if sent.first() != Some(&(0xe, 2))
        || hard_mins(&sent) != [(6, 900), (7, 700)]
        || refs != [700_000]
        || applied.request != up
        || (applied.display_khz, applied.dpp_khz) != (900_000, 700_000)
    {
        return TestResult::Fail("prepare raise order");
    }
    // A lower request in prepare changes nothing but refreshes the DTOs.
    let down = Request {
        displays: 1,
        display_khz: 300_000,
        dpp_khz: 200_000,
        dtb_khz: 600_000,
        deep_sleep_dcfclk_khz: 0,
    };
    let before = e.io.commands.len();
    let (kept, refs) = live(&mut e, down, false, &held);
    let kept = kept.unwrap();
    let sent = e.io.commands[before..].to_vec();
    if sent != [(0xe, 1)]
        || refs != [700_000]
        || (kept.request.display_khz, kept.request.dpp_khz) != (900_000, 700_000)
    {
        return TestResult::Fail("prepare lowered a clock");
    }
    // optimize: DISPCLK lowered, the DTOs raised for the lower reference
    // before it falls, then set for the reference PMFW reports.
    e.io.actual = Some(310_000);
    let before = e.io.commands.len();
    let (low, refs) = live(&mut e, down, true, &held);
    let low = low.unwrap();
    let sent = e.io.commands[before..].to_vec();
    if sent.iter().any(|&(m, _)| m == 0xe)
        || hard_mins(&sent) != [(6, 300), (7, 200)]
        || refs != [200_000, 310_000]
        || low.dpp_khz != 310_000
        || low.request.dpp_khz != 200_000
    {
        return TestResult::Fail("optimize lower order");
    }
    // A failed DTO step leaves the owner failed.
    e.io.actual = None;
    let mut fail = |_: u32| Err::<(), Error>(Error::Dto);
    if run(e.update_live(up, false, &held, &mut fail)) != Err(Error::Dto)
        || e.status.state != State::Failed(Error::Dto)
    {
        return TestResult::Fail("failed DTO step");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_live_clock_updates_follow_dcn401_update_clocks
);

/// A started owner on a Navi48 die whose PMFW (0x684c00) trusts idle DPM,
/// UCLK levels 96/456/772/1258 MHz and FCLK 300-2500 MHz.
fn idle_dpm_engine() -> Engine<Fake> {
    let mut e = engine();
    e.layout.chip = Some(crate::amdgpu_rdna4::Rdna4Chip::Navi48);
    e.io.flags[2] = 4;
    e.io.levels[2] = [96, 456, 772, 1258, 0, 0, 0, 0];
    e.io.levels[3] = [300, 2500, 0, 0, 0, 0, 0, 0];
    start(&mut e);
    e
}
/// DPMM's minimums for a 1080p60 vactive configuration at 96 MHz UCLK.
fn pstate_bw() -> Bandwidth {
    Bandwidth {
        uclk_pstate: true,
        fclk_pstate: true,
        dramclk_khz: 96_000,
        idle_dramclk_khz: 96_000,
        fclk_khz: 300_000,
        idle_fclk_khz: 300_000,
        deep_sleep_dcfclk_khz: 10_673,
    }
}
fn bw(
    e: &mut Engine<Fake>,
    b: Bandwidth,
    lower: bool,
) -> (Result<Applied, Error>, Vec<(u32, u32)>) {
    let before = e.io.commands.len();
    let held = |at: u64| at == DIO + 0x1b43 * 4;
    let result = run(e.update_bandwidth(b, lower, &held));
    (result, e.io.commands[before..].to_vec())
}

/// dcn401_update_clocks' bandwidth sequence with idle DPM (PMFW 0x681800 or
/// later on Navi48): the pinned prepare floors UCLK and FCLK at their
/// highest active and idle levels and disallows switching; optimize then
/// allows it before lowering both floor pairs to DPMM's, and a later
/// prepare raises them again before disallowing.
fn dcn401_bandwidth_sequence_follows_idle_dpm() -> TestResult {
    let mut e = idle_dpm_engine();
    e.io.commands.clear();
    let applied = run(e.prepare(request())).unwrap();
    let (fmax, umax) = (2500u32, 1258u32);
    if e.io.commands[..9]
        != [
            (0xe, 1),
            (9, 9 << 16 | 1200),
            (0x15, 0),
            (0x18, fmax << 16 | umax),
            (0x15, 0),
            (0x19, fmax << 16 | umax),
            (0x15, 0),
            (0x1a, 0),
            (9, 6 << 16 | 601),
        ]
        || applied.memory_floor_khz != 1_258_000
        || applied.uclk_pstate
        || hard_mins(&e.io.commands).iter().any(|&(c, _)| c == 2)
    {
        return TestResult::Fail("pinned prepare with idle DPM");
    }
    // A live display keeps running: prepare never gains P-state support.
    e.io.regs.insert(DIO + 0x1b43 * 4, 1);
    let (kept, sent) = bw(&mut e, pstate_bw(), false);
    if sent != [(0xd, 11)] || kept.map(|a| a.uclk_pstate) != Ok(false) {
        return TestResult::Fail("prepare allowed UCLK switching");
    }
    // A refused SetMinDeepSleepDcfclk is ignored like Linux's.
    let refused = e.io.commands.len() + 1;
    e.io.refuse = Some(refused);
    let deeper = Bandwidth {
        deep_sleep_dcfclk_khz: 20_000,
        ..pstate_bw()
    };
    let (kept, sent) = bw(&mut e, deeper, false);
    if sent != [(0xd, 20)]
        || kept.is_err()
        || e.status.ignored.last != Some((0xd, Error::Rejected(0xfd)))
    {
        return TestResult::Fail("refused deep-sleep DCFCLK");
    }
    // optimize: the deep-sleep DCFCLK lowered again, allow, then the
    // active and idle floors.
    let (low, sent) = bw(&mut e, pstate_bw(), true);
    let low = low.unwrap();
    if sent
        != [
            (0xd, 11),
            (0x1a, 1),
            (0x18, 300 << 16 | 96),
            (0x15, 0),
            (0x19, 300 << 16 | 96),
            (0x15, 0),
        ]
        || !low.uclk_pstate
        || low.memory_floor_khz != 96_000
        || e.status.bandwidth != pstate_bw()
    {
        return TestResult::Fail("optimize lowered UCLK/FCLK");
    }
    // Nothing changed: nothing sent.
    if !bw(&mut e, pstate_bw(), true).1.is_empty() {
        return TestResult::Fail("unchanged bandwidth resent");
    }
    // Re-pin before an unsupported configuration: floors to the maximum,
    // then switching disallowed.
    let pinned = Bandwidth {
        deep_sleep_dcfclk_khz: 10_673,
        ..Bandwidth::pinned(&e.status.levels.unwrap())
    };
    let (high, sent) = bw(&mut e, pinned, false);
    let high = high.unwrap();
    if sent
        != [
            (0x18, fmax << 16 | umax),
            (0x15, 0),
            (0x19, fmax << 16 | umax),
            (0x15, 0),
            (0x1a, 0),
        ]
        || high.uclk_pstate
        || high.memory_floor_khz != 1_258_000
    {
        return TestResult::Fail("re-pin order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_bandwidth_sequence_follows_idle_dpm
);

/// Without idle DPM (an unknown die or older PMFW) UCLK takes a hard
/// minimum: the active DPMM level once switching is allowed, the maximum
/// again before it is disallowed. FCLK follows DCFCLK, unsent.
fn dcn401_bandwidth_sequence_without_idle_dpm_uses_uclk_hard_min() -> TestResult {
    let mut e = engine();
    e.io.flags[2] = 4;
    e.io.levels[2] = [96, 456, 772, 1258, 0, 0, 0, 0];
    start(&mut e);
    run(e.prepare(request())).unwrap();
    if hard_mins(&e.io.commands)
        .contains(&(2, 1258))
        .then_some(())
        .is_none()
        || !e.io.commands.contains(&(0x1a, 0))
        || e.io.commands.iter().any(|&(m, _)| m == 0x18 || m == 0x19)
    {
        return TestResult::Fail("pinned prepare without idle DPM");
    }
    let (low, sent) = bw(&mut e, pstate_bw(), true);
    if sent != [(0xd, 11), (0x1a, 1), (9, 2 << 16 | 96), (0x15, 0)]
        || low.map(|a| (a.uclk_pstate, a.memory_floor_khz)) != Ok((true, 96_000))
    {
        return TestResult::Fail("UCLK hard minimum lowered");
    }
    // A higher DPMM level is raised in prepare while switching stays on.
    let raised = Bandwidth {
        dramclk_khz: 456_000,
        idle_dramclk_khz: 456_000,
        ..pstate_bw()
    };
    let (up, sent) = bw(&mut e, raised, false);
    if sent != [(9, 2 << 16 | 456), (0x15, 0)]
        || up.map(|a| (a.uclk_pstate, a.memory_floor_khz)) != Ok((true, 456_000))
    {
        return TestResult::Fail("UCLK raised in prepare");
    }
    // dcn401_smu_set_hard_min_by_freq's result is unread for UCLK: a refused
    // floor is logged and the sequence goes on (SetUclkPstateAllow(0) still
    // follows), the owner reusable.
    e.io.refuse = Some(e.io.commands.len() + 1);
    let pinned = Bandwidth::pinned(&e.status.levels.unwrap());
    let (pinned_up, sent) = bw(&mut e, pinned, false);
    if pinned_up.map(|a| a.uclk_pstate) != Ok(false)
        || sent.first() != Some(&(9, 2 << 16 | 1258))
        || sent.last() != Some(&(0x1a, 0))
        || e.status.state != State::Applied
        || e.status.ignored.count != 1
        || e.status.ignored.last != Some((9, Error::Rejected(0xfd)))
    {
        return TestResult::Fail("refused UCLK floor ignored");
    }
    // A refused SetUclkPstateAllow is ignored as well.
    e.io.refuse = Some(e.io.commands.len() + 1);
    let (allowed, _) = bw(&mut e, pstate_bw(), true);
    if allowed.map(|a| a.uclk_pstate) != Ok(true)
        || e.status.ignored.last != Some((0x1a, Error::Rejected(0xfd)))
        || e.status.state != State::Applied
    {
        return TestResult::Fail("refused SetUclkPstateAllow ignored");
    }
    // A floor PMFW never acknowledges (ReturnHardMinStatus without the
    // UCLK bit for a second) is logged, not raised.
    e.io.wrong_ack = true;
    let (unacked, _) = bw(&mut e, pinned, false);
    e.io.wrong_ack = false;
    if unacked.is_err() || e.status.ignored.last != Some((9, Error::HardMinTimeout(Clock::Memory)))
    {
        return TestResult::Fail("unacknowledged UCLK floor ignored");
    }
    // Revocation is still a failure, and the owner is not reused.
    e.io.revoke = Some((e.io.commands.len() + 1, e.authority));
    let (failed, _) = bw(&mut e, pstate_bw(), true);
    if failed != Err(Error::Revoked) || e.status.state != State::Failed(Error::Revoked) {
        return TestResult::Fail("revoked bandwidth step");
    }
    if bw(&mut e, pinned, false).0 != Err(Error::Busy) {
        return TestResult::Fail("failed owner reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_bandwidth_sequence_without_idle_dpm_uses_uclk_hard_min
);

/// dcn401_notify_wm_ranges: set A as a clock range and set 1A as the
/// dummy P-state set, sent through the DAL table transfer.
fn dcn401_watermark_ranges_reach_pmfw() -> TestResult {
    let t = ClockManager::wm_range_table();
    let mut golden = [0u8; WM_TABLE_BYTES];
    golden[8] = 2;
    golden[9] = 1;
    if t != golden {
        return TestResult::Fail("WatermarksExternal_t");
    }
    let mut e = engine();
    if run(e.notify_wm_ranges(0x8_0040_1000)) != Err(Error::Busy) {
        return TestResult::Fail("ranges before the DPM query");
    }
    start(&mut e);
    e.io.commands.clear();
    if run(e.notify_wm_ranges(0x8_0040_1000)).is_err()
        || e.io.commands != [(5, 8), (6, 0x0040_1000), (8, 2)]
    {
        return TestResult::Fail("watermark table transfer");
    }
    // The dcn401_smu_* helpers return nothing: a refusal is logged and the
    // remaining messages are sent.
    e.io.commands.clear();
    e.io.refuse = Some(2);
    if run(e.notify_wm_ranges(0x8_0040_1000)).is_err()
        || e.io.commands != [(5, 8), (6, 0x0040_1000), (8, 2)]
        || e.status.ignored.last != Some((6, Error::Rejected(0xfd)))
        || e.status.state != State::Ready
    {
        return TestResult::Fail("refused watermark message");
    }
    // The display still lights: the pre-modeset floors apply as before.
    if run(e.prepare(request())).is_err() || e.status.state != State::Applied {
        return TestResult::Fail("prepare after a refused watermark notify");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-clk", dcn401_watermark_ranges_reach_pmfw);

/// Linux's void DAL helpers ignore a post-write timeout and the following
/// send replaces the unanswered transaction after its readiness wait. This
/// permission comes only from a completed ignored-result helper: an unknown
/// busy mailbox and a cancelled transaction remain unusable.
fn dcn401_sent_optional_timeouts_continue_without_reusing_cancelled_commands() -> TestResult {
    let mut e = engine();
    start(&mut e);
    e.io.commands.clear();
    e.io.stall = Some(1);
    assert_eq!(run(e.notify_wm_ranges(0x8_0040_1000)), Ok(()));
    assert_eq!(e.io.commands, [(5, 8), (6, 0x0040_1000), (8, 2)]);
    assert_eq!(e.status.state, State::Ready);
    assert_eq!(e.status.ignored.last, Some((5, Error::Timeout)));
    assert!(!e.unanswered_ignored);

    // A timeout at the end of a void sequence may be followed by prepare's
    // required DCF/DISP/DPP/DTB responses, each still validated normally.
    e.io.commands.clear();
    e.io.stall = Some(3);
    assert_eq!(run(e.notify_wm_ranges(0x8_0040_1000)), Ok(()));
    assert!(e.unanswered_ignored);
    assert_eq!(e.status.ignored.last, Some((8, Error::Timeout)));
    assert!(run(e.prepare(request())).is_ok());
    assert_eq!(e.status.state, State::Applied);
    assert!(!e.unanswered_ignored);

    // ReturnHardMinStatus is also optional when the UCLK floor's returned
    // frequency is unread; a timed-out status must not fail a live owner.
    e.io.commands.clear();
    e.io.stall = Some(4);
    let (updated, sent) = bw(&mut e, pstate_bw(), true);
    assert!(updated.is_ok());
    assert_eq!(sent, [(0xd, 11), (0x1a, 1), (9, 2 << 16 | 96), (0x15, 0)]);
    assert_eq!(e.status.state, State::Applied);
    assert_eq!(
        e.status.ignored.last,
        Some((9, Error::HardMinTimeout(Clock::Memory)))
    );
    assert!(e.unanswered_ignored);

    // Cancellation never creates the timeout exception. The state transition
    // also protects watermark notifications, which previously stayed Ready.
    for step in 1..=3 {
        let mut e = engine();
        start(&mut e);
        e.io.commands.clear();
        e.io.stall = Some(step);
        // The model's poll cap bounds the stalled send's settled wait
        // (#879), so the first poll pends inside it by construction.
        {
            let mut cx = Context::from_waker(Waker::noop());
            let mut f = core::pin::pin!(e.notify_wm_ranges(0x8_0040_1000));
            assert!(f.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(e.io.commands.len(), step);
        assert_eq!(e.status.state, State::Applying);
        assert!(!e.unanswered_ignored);
        assert_eq!(run(e.prepare(request())), Err(Error::Busy));
        assert_eq!(run(e.notify_wm_ranges(0)), Err(Error::Busy));
        assert_eq!(e.io.commands.len(), step);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_sent_optional_timeouts_continue_without_reusing_cancelled_commands
);

/// dcn401_smu_send_msg_with_param waits only for a nonzero DAL_RESP and
/// then sends: a fresh owner sends over a refusal an earlier owner left
/// there. A refused NumOfDisplays or SetMinDeepSleepDcfclk is ignored, as
/// Linux never reads either result, and a message that was never sent is
/// never counted as refused.
fn dcn401_dal_sends_after_any_response_and_ignores_count_refusals() -> TestResult {
    let mut e = engine();
    e.io.regs.insert(0x589d0, 0xfd);
    if run(e.start(core::future::ready(Ok(power())))).is_err()
        || e.io.commands.first() != Some(&(2, 0))
        || e.status.ignored.count != 0
    {
        return TestResult::Fail("fresh owner over a stale refusal");
    }
    e.io.commands.clear();
    e.io.refuse = Some(1);
    if run(e.prepare(request())).is_err()
        || e.status.state != State::Applied
        || e.io.commands.first() != Some(&(0xe, 1))
        || e.status.ignored.last != Some((0xe, Error::Rejected(0xfd)))
    {
        return TestResult::Fail("refused NumOfDisplays in prepare");
    }
    for (k, message) in [(1, 0xe), (2, 0xd)] {
        e.io.commands.clear();
        e.io.refuse = Some(k);
        let count = e.status.ignored.count;
        let up = Request {
            deep_sleep_dcfclk_khz: 20_000 + k as u32 * 1000,
            ..request()
        };
        let (applied, _) = live(&mut e, up, false, &|_| false);
        if applied.is_err()
            || e.status.state != State::Applied
            || e.io.commands.get(k - 1).map(|c| c.0) != Some(message)
            || e.io.commands.len() != 2
            || e.status.ignored.count != count + 1
            || e.status.ignored.last != Some((message, Error::Rejected(0xfd)))
        {
            return TestResult::Fail("refused live count or deep-sleep DCFCLK");
        }
    }
    // PMFW never answering before the write: nothing sent, nothing ignored.
    e.io.commands.clear();
    e.io.regs.insert(0x589d0, 0);
    let count = e.status.ignored.count;
    if run(e.command_ignored(0xd, 5)) != Err(Error::Timeout)
        || !e.io.commands.is_empty()
        || e.status.ignored.count != count
    {
        return TestResult::Fail("unsent message counted as refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_dal_sends_after_any_response_and_ignores_count_refusals
);

/// The display owner's side of `bandwidth::pin_uclk` over a real clock
/// owner: what `ColdBoot` does through `update_live_display_bandwidth` and
/// `disable_display_fams2`, with each step recorded in order.
struct PinOwner {
    e: Engine<Fake>,
    steps: Vec<&'static str>,
    firmware: bool,
    refuse_firmware: bool,
}
impl crate::amdgpu_navi48_boot::bandwidth::UclkPin for PinOwner {
    fn firmware_active(&self) -> bool {
        self.firmware
    }
    fn clock_status(&self) -> Result<Status, crate::amdgpu_dcn401_otg::Error> {
        Ok(self.e.status)
    }
    async fn raise_bandwidth(
        &mut self,
        bandwidth: Bandwidth,
    ) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
        self.steps.push("clocks");
        let held = |at: u64| at == DIO + 0x1b43 * 4;
        self.e
            .update_bandwidth(bandwidth, false, &held)
            .await
            .map(|_| ())
            .map_err(crate::amdgpu_dcn401_otg::Error::Clocks)
    }
    async fn disable_fams2(&mut self) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
        self.steps.push("fams2");
        if self.refuse_firmware {
            return Err(crate::amdgpu_dcn401_otg::Error::Busy);
        }
        self.firmware = false;
        Ok(())
    }
}
/// A pin's result, the DAL messages it sent and the owner steps it ran.
type Pinned = (
    Result<(), crate::amdgpu_dcn401_otg::Error>,
    Vec<(u32, u32)>,
    Vec<&'static str>,
);
/// `pin_uclk` from the owner and the DAL messages and steps it ran.
fn pin(o: &mut PinOwner) -> Pinned {
    let before = o.e.io.commands.len();
    o.steps.clear();
    let result = run(crate::amdgpu_navi48_boot::bandwidth::pin_uclk(o));
    (
        result,
        o.e.io.commands[before..].to_vec(),
        core::mem::take(&mut o.steps),
    )
}

/// Every ColdBoot configuration change pins first. A fresh display owner,
/// as cold boot, S3 resume and runtime resume each build one, has nothing
/// to pin: dcn401_init_clocks' P-state support is DC's software state, not
/// something PMFW was told. So retire_inherited_display (clocks not
/// started), the first modeset (pinned before it starts and prepares the
/// clocks) and a modeset after resume (a new owner, whatever the old one
/// allowed) pin with no message, and the prepare that follows disallows
/// switching itself. Only once a bandwidth sequence allowed switching does
/// the pin run Linux's prepare_bandwidth: the clocks raised with switching
/// disallowed, then FAMS2 disabled.
fn dcn401_fresh_display_owners_pin_like_linux_prepare_bandwidth() -> TestResult {
    let fresh = || PinOwner {
        e: engine(),
        steps: Vec::new(),
        firmware: false,
        refuse_firmware: false,
    };
    // retire_inherited_display on cold boot: the clocks not started.
    let mut o = fresh();
    if !o.e.status.bandwidth.uclk_pstate || o.e.status.levels.is_some() {
        return TestResult::Fail("fresh owner state");
    }
    if pin(&mut o) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("retire_inherited_display on a fresh owner");
    }
    // The first modeset: pinned before prepare_configuration starts the
    // clocks, and again (a retry) once they started but are not prepared.
    if pin(&mut o) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("first modeset before the clocks start");
    }
    start(&mut o.e);
    if o.e.status.state != State::Ready || pin(&mut o) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("first modeset on started clocks");
    }
    // prepare disallows switching itself (Linux's first prepare_bandwidth).
    o.e.io.commands.clear();
    run(o.e.prepare(request())).unwrap();
    if !o.e.io.commands.contains(&(0x1a, 0)) || o.e.status.uclk_switching() {
        return TestResult::Fail("prepare from dcn401_init_clocks' state");
    }
    // Lit and pinned: nothing to pin for the next change.
    o.e.io.regs.insert(DIO + 0x1b43 * 4, 1);
    if pin(&mut o) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("pinned owner pinned again");
    }
    // The display monitor's optimize allows switching: the next change
    // raises and disallows, and only then disables FAMS2.
    let (allowed, _) = bw(&mut o.e, pstate_bw(), true);
    if allowed.map(|a| a.uclk_pstate) != Ok(true) || !o.e.status.uclk_switching() {
        return TestResult::Fail("optimize allowed switching");
    }
    let (result, sent, steps) = pin(&mut o);
    if result.is_err()
        || steps != ["clocks", "fams2"]
        || sent.last() != Some(&(0x1a, 0))
        || hard_mins(&sent) != [(2, 1200)]
        || o.e.status.uclk_switching()
        || o.e.status.applied.map(|a| a.memory_floor_khz) != Some(1_200_000)
    {
        return TestResult::Fail("pin while switching");
    }
    // After S3 or runtime resume the new owner is fresh again, whatever the
    // old one allowed: the relight's pins send nothing until its prepare.
    let (allowed, _) = bw(&mut o.e, pstate_bw(), true);
    if allowed.is_err() || !o.e.status.uclk_switching() {
        return TestResult::Fail("old owner switching before suspend");
    }
    // A teardown on an owner that failed while switching: the pin cannot
    // run (Busy, nothing sent), which a configuration change returns and a
    // teardown only logs before it goes on.
    o.e.status.state = State::Failed(Error::Timeout);
    let before = o.e.io.commands.len();
    let busy = Err(crate::amdgpu_dcn401_otg::Error::Clocks(Error::Busy));
    if pin(&mut o).0 != busy
        || run(crate::amdgpu_navi48_boot::bandwidth::pin_uclk_for_teardown(
            &mut o,
        )) != busy
        || o.e.io.commands.len() != before
    {
        return TestResult::Fail("teardown pin on a failed owner");
    }
    let mut resumed = fresh();
    if pin(&mut resumed) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("relight after resume, clocks not started");
    }
    start(&mut resumed.e);
    if pin(&mut resumed) != (Ok(()), Vec::new(), Vec::new()) {
        return TestResult::Fail("relight after resume, clocks started");
    }
    // A failed start leaves nothing applied either.
    let mut failed = fresh();
    failed.e.io.refuse = Some(1);
    if run(failed.e.start(core::future::ready(Ok(power())))).is_ok()
        || pin(&mut failed) != (Ok(()), Vec::new(), Vec::new())
    {
        return TestResult::Fail("failed start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_fresh_display_owners_pin_like_linux_prepare_bandwidth
);

/// dcn401_update_clocks' optimize once no stream is left (DML21's
/// min-clock state): NumOfDisplays(0), DCFCLK at its lowest level, the
/// deep-sleep DCFCLK zero, then switching allowed before the UCLK floor
/// drops to its lowest level. Only with every consumer retired, once, and
/// the next configuration's pin and prepare disallow switching again.
fn dcn401_no_display_left_releases_like_dcn401_update_clocks() -> TestResult {
    let mut e = engine();
    if run(e.release()) != Err(Error::Busy) || !e.io.commands.is_empty() {
        return TestResult::Fail("release before the clocks were prepared");
    }
    start(&mut e);
    let lit = Request {
        deep_sleep_dcfclk_khz: 10_673,
        ..request()
    };
    run(e.prepare(lit)).unwrap();
    // A display still lit: nothing is sent.
    let busy = DIO + 0x1b43 * 4;
    e.io.regs.insert(busy, 1);
    e.io.commands.clear();
    if run(e.release()) != Err(Error::Busy)
        || !e.io.commands.is_empty()
        || e.status.state != State::Applied
    {
        return TestResult::Fail("release under a lit display");
    }
    e.io.regs.insert(busy, 0);
    let released = run(e.release());
    if e.io.commands
        != [
            (0xe, 0),
            (9, 9 << 16 | 100),
            (0x15, 0),
            (0xd, 0),
            (0x1a, 1),
            (9, 2 << 16 | 100),
            (0x15, 0),
            (9, 10 << 16 | 100),
            (0x15, 0),
            (9, 6 << 16 | 100),
            (0x15, 0),
            (9, 7 << 16 | 100),
            (0x15, 0),
        ]
    {
        return TestResult::Fail("no-display optimize sequence");
    }
    let Ok(released) = released else {
        return TestResult::Fail("no-display optimize failed");
    };
    if released.request.displays != 0
        || released.dcf_floor_khz != 100_000
        || released.memory_floor_khz != 100_000
        || !released.uclk_pstate
        || !e.status.uclk_switching()
        || !e.status.bandwidth.fclk_pstate
        || e.status.bandwidth.deep_sleep_dcfclk_khz != 0
        || (released.display_khz, released.dpp_khz, released.dtb_khz) != (100_000, 100_000, 100_000)
        || (
            released.request.display_khz,
            released.request.dpp_khz,
            released.request.dtb_khz,
        ) != (100_000, 100_000, 100_000)
    {
        return TestResult::Fail("no-display optimize state");
    }
    // Once only.
    e.io.commands.clear();
    if run(e.release()) != Ok(released) || !e.io.commands.is_empty() {
        return TestResult::Fail("second release");
    }
    // The next modeset's prepare counts its display and disallows again.
    run(e.prepare(request())).unwrap();
    if e.io.commands.first() != Some(&(0xe, 1))
        || !e.io.commands.contains(&(0x1a, 0))
        || e.status.uclk_switching()
    {
        return TestResult::Fail("prepare after the release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_no_display_left_releases_like_dcn401_update_clocks
);

fn dcn401_no_display_release_tracks_actual_rates_and_fails_closed() -> TestResult {
    for chip in crate::amdgpu_rdna4::Rdna4Chip::ALL {
        let mut e = idle_dpm_engine();
        e.layout.chip = Some(chip);
        run(e.prepare(request())).unwrap();
        e.io.commands.clear();
        // Actual rates need not equal the requested floor. Only the requested
        // first levels are remembered as floors, as Linux's clks do.
        e.io.actual = Some(101_000);
        let released = run(e.release()).unwrap();
        assert_eq!(
            hard_mins(&e.io.commands),
            [(9, 100), (10, 100), (6, 100), (7, 100)]
        );
        assert!(e.io.commands.contains(&(0x18, 300 << 16 | 96)));
        assert!(e.io.commands.contains(&(0x19, 0)));
        assert_eq!(
            (released.display_khz, released.dpp_khz, released.dtb_khz),
            (101_000, 101_000, 101_000)
        );
        assert_eq!(released.request.display_khz, 100_000);
        assert_eq!(released.request.dpp_khz, 100_000);
        assert_eq!(released.request.dtb_khz, 100_000);
    }
    let mut e = engine();
    start(&mut e);
    let previous = run(e.prepare(request())).unwrap();
    e.io.commands.clear();
    run(e.release()).unwrap();
    let sequence = e.io.commands;
    for step in 1..=sequence.len() {
        let mut e = engine();
        start(&mut e);
        run(e.prepare(request())).unwrap();
        e.io.commands.clear();
        e.io.stall = Some(step);
        {
            let mut cx = Context::from_waker(Waker::noop());
            let mut f = core::pin::pin!(e.release());
            assert!(f.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(e.status.state, State::Applying);
        assert_eq!(e.status.applied, Some(previous));
        assert_eq!(run(e.release()), Err(Error::Busy));
        assert_eq!(run(e.prepare(request())), Err(Error::Busy));
        assert_eq!(e.io.commands.len(), step);
    }
    // Rejected display floors and their required status results are fatal;
    // the partly released owner must be retained without retry or rollback.
    let first_display = sequence
        .iter()
        .position(|&(message, arg)| message == 9 && arg >> 16 == Clock::Dtb as u32)
        .unwrap()
        + 1;
    for step in first_display..=sequence.len() {
        let mut e = engine();
        start(&mut e);
        run(e.prepare(request())).unwrap();
        e.io.commands.clear();
        e.io.refuse = Some(step);
        assert_eq!(run(e.release()), Err(Error::Rejected(0xfd)));
        assert_eq!(e.status.state, State::Failed(Error::Rejected(0xfd)));
        assert_eq!(e.status.applied, Some(previous));
        assert_eq!(e.io.commands.len(), step);
        assert_eq!(run(e.release()), Err(Error::Busy));
    }
    let mut e = engine();
    start(&mut e);
    run(e.prepare(request())).unwrap();
    e.io.actual = Some(99_999);
    assert_eq!(run(e.release()), Err(Error::Frequency(Clock::Dtb, 99_999)));
    assert_eq!(
        e.status.state,
        State::Failed(Error::Frequency(Clock::Dtb, 99_999))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_no_display_release_tracks_actual_rates_and_fails_closed
);

fn dcn401_pin_retires_a_firmware_schedule_before_any_new_configuration() -> TestResult {
    let mut o = PinOwner {
        e: engine(),
        steps: Vec::new(),
        firmware: true,
        refuse_firmware: true,
    };
    start(&mut o.e);
    run(o.e.prepare(request())).unwrap();
    assert!(!o.e.status.uclk_switching());
    let (result, messages, steps) = pin(&mut o);
    assert_eq!(result, Err(crate::amdgpu_dcn401_otg::Error::Busy));
    assert!(messages.is_empty());
    assert_eq!(steps, ["fams2"]);
    assert!(o.firmware);
    o.refuse_firmware = false;
    assert_eq!(pin(&mut o), (Ok(()), Vec::new(), vec!["fams2"]));
    assert!(!o.firmware);
    o.firmware = true;
    o.e.status.state = State::Applying;
    assert_eq!(
        pin(&mut o),
        (
            Err(crate::amdgpu_dcn401_otg::Error::Busy),
            Vec::new(),
            Vec::new()
        )
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-clk",
    dcn401_pin_retires_a_firmware_schedule_before_any_new_configuration
);
