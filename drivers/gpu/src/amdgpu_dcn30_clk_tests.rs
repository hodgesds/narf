use super::*;
use alloc::vec::Vec;
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    response: u32,
    arg: u32,
    pll: u32,
    header: u32,
    count: u32,
    range: [u32; 2],
    commands: Vec<(u32, u32)>,
    reads: usize,
    idle: bool,
    refuse: Option<u32>,
    refuse_clock: Option<Clock>,
    stall: Option<u32>,
    underclock: bool,
    display_only: bool,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        self.reads += 1;
        match reg {
            RESPONSE => self.response,
            ARGUMENT => self.arg,
            PLL => self.pll,
            _ => panic!("non-DAL register"),
        }
    }
    fn write(&mut self, reg: u32, value: u32) {
        match reg {
            RESPONSE => self.response = value,
            ARGUMENT => self.arg = value,
            MESSAGE => {
                assert_eq!(self.response, 0);
                self.commands.push((value, self.arg));
                if self.stall == Some(value) {
                    return;
                }
                self.response = if self.display_only
                    && (matches!(value, 0xd | 0xe | 0x10)
                        || (value == 9 && matches!(self.arg >> 16, 1 | 3)))
                {
                    // PMFW can refuse optional notifications and the SOC/FCLK
                    // floors that dcn3_update_clocks never requests.
                    0xff
                } else if self.refuse == Some(value)
                    || (value == HARD_MIN
                        && self
                            .refuse_clock
                            .is_some_and(|c| self.arg >> 16 == c as u32))
                {
                    0xfd
                } else {
                    1
                };
                if let Some(cap) = self.revoke {
                    cap.revoke();
                }
                self.arg = match value {
                    GET_VERSION => 0x413f00,
                    GET_INTERFACE => 0xe,
                    GET_HEADER => self.header,
                    DPM_BY_INDEX if self.arg & 0xff == 0xff => self.count,
                    DPM_BY_INDEX => self
                        .range
                        .get((self.arg & 0xff) as usize)
                        .copied()
                        .unwrap_or(0),
                    HARD_MIN => (self.arg & 0xffff).saturating_sub(u32::from(self.underclock)),
                    DEEP_SLEEP_MIN | DISPLAYS | 0x10 => 0,
                    _ => panic!("non-DAL command"),
                };
            }
            _ => panic!("wrong DAL address"),
        }
    }
    fn idle(&mut self) -> Result<(), Error> {
        self.reads += 1;
        if self.idle {
            Ok(())
        } else {
            Err(Error::Busy)
        }
    }
}
struct Sink {
    programmed: Option<(u8, u8)>,
    error: Option<Error>,
    stall: bool,
}
impl Sink {
    fn new() -> Self {
        Self {
            programmed: None,
            error: None,
            stall: false,
        }
    }
}
impl Dentist for Sink {
    async fn program(&mut self, disp: u8, dpp: u8) -> Result<(), Error> {
        self.programmed = Some((disp, dpp));
        if self.stall {
            core::future::pending::<()>().await;
        }
        self.error.map_or(Ok(()), Err)
    }
}
fn engine() -> Engine<Fake> {
    Engine {
        authority: Cap::bootstrap(),
        state: State::Dormant,
        levels: None,
        applied: None,
        phy_floor_mhz: 0,
        io: Fake {
            response: 1,
            arg: 0,
            pll: 36 | 0x8000_0000,
            header: 1,
            count: 2,
            range: [100, 1200],
            commands: Vec::new(),
            reads: 0,
            idle: true,
            refuse: None,
            refuse_clock: None,
            stall: None,
            underclock: false,
            display_only: false,
            revoke: None,
        },
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn navi22_dal_reads_scalar_levels_and_actual_pll() -> TestResult {
    let mut e = engine();
    let levels = run(e.start(core::future::ready(Ok(())))).unwrap();
    if levels.vco_khz != 3_650_000
        || levels.firmware != 0x413f00
        || levels.interface != 0xe
        || levels.range(Clock::Memory).mhz() != [100, 1200]
        || e.state != State::Ready
    {
        return TestResult::Fail("DAL levels/PLL layout");
    }
    // Exact ids / packed PPCLK index, independent of the command constants.
    if e.io.commands[..6]
        != [
            (2, 0),
            (3, 0),
            (4, 0),
            (11, 0x100ff),
            (11, 0x10000),
            (11, 0x10001),
        ]
    {
        return TestResult::Fail("DAL command wire protocol");
    }
    let n = e.io.commands.len();
    if run(e.start(core::future::ready(Ok(())))) != Err(Error::Busy) || e.io.commands.len() != n {
        return TestResult::Fail("DAL handshake repeated");
    }
    let mut fine = engine();
    fine.io.count = 1 << 31;
    let levels = run(fine.start(core::future::ready(Ok(())))).unwrap();
    if !levels.range(Clock::Pixel).fine_grained || levels.range(Clock::Pixel).mhz().len() != 2 {
        return TestResult::Fail("fine-grained endpoints not queried");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_reads_scalar_levels_and_actual_pll
);
fn navi22_dentist_plan_rounds_up_without_exceeding_board() -> TestResult {
    let l = run(engine().start(core::future::ready(Ok(())))).unwrap();
    let p = l.plan(148_500, 148_500, 300_001).unwrap();
    if p.display_did != 0x51
        || p.display_khz != 148_979
        || p.pixel_khz != 148_979
        || l.ceiling(Clock::Display) != Ok(1_123_076)
    {
        return TestResult::Fail("DENTIST quantization or board ceiling");
    }
    for (did, expected) in [
        (8, 8),
        (63, 63),
        (64, 64),
        (95, 126),
        (96, 128),
        (125, 244),
        (126, 248),
        (127, 512),
    ] {
        if divider(did) != expected {
            return TestResult::Fail("DENTIST range boundary");
        }
    }
    for khz in [0, 1_150_000, u32::MAX] {
        if l.plan(khz, 100_000, 100_000).is_ok() {
            return TestResult::Fail("unrepresentable/overclock admitted");
        }
    }
    if vco(0).is_ok() || vco(u32::MAX) != Err(Error::DeviceGone) || vco(61).is_ok() {
        return TestResult::Fail("invalid PLL invented a default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dentist_plan_rounds_up_without_exceeding_board
);
fn navi22_dal_pins_memory_before_programming_global_dividers() -> TestResult {
    let mut e = engine();
    let l = run(e.start(core::future::ready(Ok(())))).unwrap();
    let p = l.plan(148_500, 148_500, 300_001).unwrap();
    e.io.commands.clear();
    let mut sink = Sink::new();
    run(e.prepare(p, &mut sink)).unwrap();
    if e.io.commands
        != [
            (14, 1),
            (9, 0x8012d),
            (13, 301),
            (9, 0x204b0),
            (9, 0xa0095),
            (9, 0x90095),
        ]
        || sink.programmed != Some((0x51, 0x51))
        || e.state != State::Configured
        || e.applied != Some(p)
    {
        return TestResult::Fail("display count / memory floors / DENTIST ordering");
    }
    e.io.idle = false;
    let n = e.io.commands.len();
    if run(e.prepare(p, &mut sink)) != Err(Error::Busy) || e.io.commands.len() != n {
        return TestResult::Fail("live stream clock changed");
    }
    e.io.idle = true;
    let mut wrong = p;
    wrong.pixel_khz += 1;
    if run(e.prepare(wrong, &mut sink)) != Err(Error::Invalid) || e.io.commands.len() != n {
        return TestResult::Fail("forged plan admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_pins_memory_before_programming_global_dividers
);
fn navi22_dal_uses_display_floors_and_tolerates_optional_refusals() -> TestResult {
    let mut e = engine();
    let levels = run(e.start(core::future::ready(Ok(())))).unwrap();
    let plan = levels.plan(148_500, 148_500, 300_001).unwrap();
    e.io.commands.clear();
    e.io.display_only = true;
    let mut sink = Sink::new();
    if run(e.prepare(plan, &mut sink)).is_err()
        || e.state != State::Configured
        || e.applied != Some(plan)
        || sink.programmed != Some((0x51, 0x51))
    {
        return TestResult::Fail("optional DAL refusal prevented native clocks");
    }
    // Linux dcn3_update_clocks: DCFCLK, deep-sleep hint, pinned UCLK,
    // DPPCLK and DISPCLK; no separate SOC/FCLK floor or DF C-state message.
    if e.io.commands
        != [
            (14, 1),
            (9, 0x8012d),
            (13, 301),
            (9, 0x204b0),
            (9, 0xa0095),
            (9, 0x90095),
        ]
    {
        return TestResult::Fail("non-DCN DAL requests or required floors omitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_uses_display_floors_and_tolerates_optional_refusals
);
fn navi22_dal_checks_each_required_floor_and_bounds_before_writing() -> TestResult {
    for clock in [Clock::Dcf, Clock::Memory, Clock::Pixel, Clock::Display] {
        let mut e = engine();
        let l = run(e.start(core::future::ready(Ok(())))).unwrap();
        let p = l.plan(148_500, 148_500, 300_000).unwrap();
        e.io.refuse_clock = Some(clock);
        let mut sink = Sink::new();
        if run(e.prepare(p, &mut sink)) != Err(Error::Rejected(0xfd))
            || sink.programmed.is_some()
            || e.state != State::Failed
            || e.applied.is_some()
        {
            return TestResult::Fail("required floor rejection reached DENTIST");
        }
    }
    for clock in [Clock::Phy, Clock::Memory, Clock::Fabric] {
        let mut e = engine();
        run(e.start(core::future::ready(Ok(())))).unwrap();
        e.io.commands.clear();
        // A low link request keeps the board's minimum, as Linux does.
        run(e.runtime_floor(clock, 1)).unwrap();
        if e.io.commands != [(9, (clock as u32) << 16 | 100)] || e.state != State::Ready {
            return TestResult::Fail("floor below board minimum or owner not restored");
        }
        let n = e.io.reads;
        for invalid in [0, 1_200_001, u32::MAX] {
            if run(e.runtime_floor(clock, invalid)) != Err(Error::Invalid)
                || e.io.reads != n
                || e.state != State::Ready
            {
                return TestResult::Fail("invalid frequency touched DAL or poisoned owner");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_checks_each_required_floor_and_bounds_before_writing
);
fn navi22_dal_shared_phy_floor_never_drops_below_another_link() -> TestResult {
    let mut e = engine();
    run(e.start(core::future::ready(Ok(())))).unwrap();
    e.io.commands.clear();
    // HBR3 followed by RBR, then an HBR2 verification request. They share
    // one PHYCLK floor even when the clock owner is lent between pipelines.
    for khz in [810_000, 162_000, 540_000] {
        run(e.runtime_floor(Clock::Phy, khz)).unwrap();
    }
    if e.io.commands != [(9, 0xb032a); 3] || e.phy_floor_mhz != 810 {
        return TestResult::Fail("slower DP link lowered the shared PHYCLK floor");
    }
    e.io.refuse = Some(HARD_MIN);
    if run(e.runtime_floor(Clock::Phy, 900_000)) != Err(Error::Rejected(0xfd))
        || e.phy_floor_mhz != 810
        || e.state != State::Failed
    {
        return TestResult::Fail("refused PHY floor published or owner reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_shared_phy_floor_never_drops_below_another_link
);

fn navi22_dal_joint_preparation_reports_stream_count() -> TestResult {
    for count in 1..=6 {
        let mut e = engine();
        let l = run(e.start(core::future::ready(Ok(())))).unwrap();
        let p = l.plan(148_500, 148_500, 300_000).unwrap();
        e.io.commands.clear();
        run(e.prepare_displays(p, &mut Sink::new(), count)).unwrap();
        if e.io.commands.first() != Some(&(14, u32::from(count))) {
            return TestResult::Fail("wrong active-stream count sent to DAL");
        }
    }
    let mut e = engine();
    let l = run(e.start(core::future::ready(Ok(())))).unwrap();
    let p = l.plan(148_500, 148_500, 300_000).unwrap();
    let n = e.io.reads;
    for invalid in [0, 7, u8::MAX] {
        if run(e.prepare_displays(p, &mut Sink::new(), invalid)) != Err(Error::Invalid)
            || e.io.reads != n
        {
            return TestResult::Fail("invalid stream count touched hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_joint_preparation_reports_stream_count
);

fn navi22_dal_runtime_operations_retain_cancelled_transactions() -> TestResult {
    for state in [State::Ready, State::Configured] {
        for floor in [false, true] {
            let mut e = engine();
            run(e.start(core::future::ready(Ok(())))).unwrap();
            e.state = state;
            e.io.stall = Some(if floor { HARD_MIN } else { DISPLAYS });
            if floor {
                let mut f = core::pin::pin!(e.runtime_floor(Clock::Phy, 162_000));
                if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending {
                    return TestResult::Fail("runtime floor did not pend");
                }
            } else {
                let mut f = core::pin::pin!(e.runtime_command(DISPLAYS, 2));
                if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending {
                    return TestResult::Fail("runtime command did not pend");
                }
            }
            // Even a late reply cannot make a cancelled owner reusable.
            e.io.response = 1;
            let n = e.io.reads;
            if e.state != State::InFlight
                || run(e.runtime_floor(Clock::Phy, 162_000)) != Err(Error::Busy)
                || run(e.runtime_command(DISPLAYS, 2)) != Err(Error::Busy)
                || e.io.reads != n
            {
                return TestResult::Fail("cancelled runtime clock request replayed");
            }
        }
    }
    // An acknowledged optional refusal is safe to reuse, transport loss is not.
    let mut e = engine();
    run(e.start(core::future::ready(Ok(())))).unwrap();
    e.io.refuse = Some(DISPLAYS);
    if run(e.runtime_command(DISPLAYS, 2)) != Err(Error::Rejected(0xfd)) || e.state != State::Ready
    {
        return TestResult::Fail("acknowledged optional refusal retained as busy");
    }
    e.io.response = u32::MAX;
    if run(e.runtime_command(DISPLAYS, 2)) != Err(Error::DeviceGone) || e.state != State::Failed {
        return TestResult::Fail("lost runtime mailbox reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_runtime_operations_retain_cancelled_transactions
);
fn navi22_dal_bad_tables_rejection_and_revocation_fail_closed() -> TestResult {
    // dcn3_init_clocks tolerates a header/interface mismatch, a failed or
    // empty level query and odd values; it records them as reported.
    for odd in 0..6 {
        let mut e = engine();
        match odd {
            0 => e.io.header = 2,
            1 => e.io.count = 0,
            2 => e.io.count = 17,
            3 => e.io.range = [0, 1200],
            4 => e.io.range = [1200, 100],
            _ => e.io.refuse = Some(GET_HEADER),
        }
        let Ok(levels) = run(e.start(core::future::ready(Ok(())))) else {
            return TestResult::Fail("dcn3_init_clocks-tolerated DAL table refused");
        };
        let memory = levels.range(Clock::Memory).mhz();
        let expect: &[u16] = match odd {
            1 => &[],
            3 => &[0, 1200],
            4 => &[1200, 100],
            _ => &[100, 1200],
        };
        if e.state != State::Ready || (odd != 2 && memory != expect) || memory.len() > LEVELS {
            return TestResult::Fail("DAL levels not recorded as PMFW reported them");
        }
    }
    // An empty range is refused by the clock plan, not at start.
    let mut e = engine();
    e.io.count = 0;
    let levels = run(e.start(core::future::ready(Ok(())))).unwrap();
    if levels.plan(148_500, 148_500, 300_000).is_ok() {
        return TestResult::Fail("clock plan accepted an empty DPM table");
    }
    for bad in 0..3 {
        let mut e = engine();
        match bad {
            0 => e.io.refuse = Some(GET_VERSION),
            1 => e.io.revoke = Some(e.authority),
            _ => e.io.pll = u32::MAX,
        }
        if run(e.start(core::future::ready(Ok(())))).is_ok() || e.state != State::Failed {
            return TestResult::Fail("bad DAL inventory accepted");
        }
        let n = e.io.reads;
        if run(e.start(core::future::ready(Ok(())))) != Err(Error::Busy) || e.io.reads != n {
            return TestResult::Fail("failed owner reused");
        }
    }
    for bad in 0..4 {
        let mut e = engine();
        let l = run(e.start(core::future::ready(Ok(())))).unwrap();
        let p = l.plan(148_500, 148_500, 300_000).unwrap();
        let mut sink = Sink::new();
        match bad {
            0 => e.io.underclock = true,
            1 => e.io.refuse = Some(HARD_MIN),
            2 => {
                e.authority.revoke();
            }
            _ => sink.error = Some(Error::Timeout),
        }
        if run(e.prepare(p, &mut sink)).is_ok() || e.applied.is_some() {
            return TestResult::Fail("failed clock preparation published");
        }
        if bad < 3 && sink.programmed.is_some() {
            return TestResult::Fail("DENTIST written without voltage floor");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_bad_tables_rejection_and_revocation_fail_closed
);
fn navi22_dal_cancelled_mailbox_and_divider_remain_owned() -> TestResult {
    let mut e = engine();
    e.io.stall = Some(GET_VERSION);
    {
        let mut f = core::pin::pin!(e.start(core::future::ready(Ok(()))));
        if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending {
            return TestResult::Fail("stalled DAL did not wait asynchronously");
        }
    }
    let n = e.io.reads;
    if e.state != State::InFlight
        || run(e.start(core::future::ready(Ok(())))) != Err(Error::Busy)
        || e.io.reads != n
    {
        return TestResult::Fail("cancelled DAL command reissued");
    }
    let mut e = engine();
    let l = run(e.start(core::future::ready(Ok(())))).unwrap();
    let p = l.plan(148_500, 148_500, 300_000).unwrap();
    let mut sink = Sink::new();
    sink.stall = true;
    {
        let mut f = core::pin::pin!(e.prepare(p, &mut sink));
        if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending {
            return TestResult::Fail("divider did not pend");
        }
    }
    let n = e.io.reads;
    if e.state != State::InFlight
        || run(e.prepare(p, &mut sink)) != Err(Error::Busy)
        || e.io.reads != n
        || e.applied.is_some()
    {
        return TestResult::Fail("cancelled divider change reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_cancelled_mailbox_and_divider_remain_owned
);

fn navi22_dal_checks_all_six_streams_and_constructor_bounds() -> TestResult {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    let mut dcn = gpu.ip_blocks[0];
    dcn.hw_id = crate::amdgpu_discovery::HW_ID_DCN;
    dcn.major = 3;
    dcn.minor = 0;
    dcn.revision = 0;
    dcn.base_addrs[..3].copy_from_slice(&[0, 0x1000, 0x4000]);
    gpu.ip_blocks.push(dcn);
    let cap = Cap::bootstrap();
    // SAFETY: constructors only validate bounds, never access inert maps.
    unsafe {
        if ClockManager::new(&gpu, cap).is_err() {
            return TestResult::Fail("valid Navi22 clock layout refused");
        }
        gpu.regs.len = u64::from(PLL + 1) * 4 - 1;
        if ClockManager::new(&gpu, cap).is_ok() {
            return TestResult::Fail("truncated PLL accepted");
        }
    }
    let mut registers = alloc::vec![0u32; 0x260d];
    let mut io = Mmio {
        regs: crate::amdgpu_reg_window::Window::new(narf_bus::MmioRegion {
            virt: registers.as_mut_ptr() as u64,
            len: registers.len() as u64 * 4,
            ..gpu.regs
        }),
        mp1: 0,
        dcn: 0,
        pipes: 6,
    };
    for pipe in 0..6 {
        for (reg, bit) in [
            (0x1b41 + pipe * 0x80, 1),
            (0x1b86 + pipe * 0x80, 1 << 16),
            (0x210c + pipe * 0x100, 1),
            (0x210c + pipe * 0x100, 1 << 16),
        ] {
            registers[reg] = bit;
            if io.idle() != Err(Error::Busy) {
                return TestResult::Fail("active pipe overlooked");
            }
            registers[reg] = u32::MAX;
            if io.idle() != Err(Error::DeviceGone) {
                return TestResult::Fail("device removal overlooked");
            }
            registers[reg] = 0;
        }
    }
    if io.idle().is_err() {
        return TestResult::Fail("idle pipes refused");
    }
    let mut e = engine();
    e.io.idle = false;
    let mut called = false;
    if run(e.start(async {
        called = true;
        Ok(())
    })) != Err(Error::Busy)
        || called
        || !e.io.commands.is_empty()
    {
        return TestResult::Fail("power enabled with live scanout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-clk",
    navi22_dal_checks_all_six_streams_and_constructor_bounds
);
