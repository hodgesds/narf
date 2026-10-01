use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: Vec<u32>,
    table: Vec<u32>,
    writes: Vec<(u64, u32)>,
    /// Response the firmware returns for the next message, by message id.
    reject: Option<(u32, u32)>,
    reply: u32,
    fill: bool,
    zeroed: bool,
    gone: bool,
}
impl Fake {
    fn new() -> Self {
        let mut regs = vec![0; (RESPONSE + 1) as usize];
        regs[RESPONSE as usize] = STATUS_OK;
        Self {
            regs,
            table: vec![0xdead_beef; (TABLE_SIZE / 4) as usize],
            writes: Vec::new(),
            reject: None,
            reply: 0,
            fill: true,
            zeroed: false,
            gone: false,
        }
    }
    fn messages(&self) -> Vec<(u32, u32)> {
        // Reconstruct (message, param) pairs in submission order.
        let mut out = Vec::new();
        let mut param = 0;
        for (reg, value) in &self.writes {
            if *reg == PARAM {
                param = *value;
            }
            if *reg == MSG {
                out.push((*value, param));
            }
        }
        out
    }
}
fn table_words() -> [u32; (TABLE_SIZE / 4) as usize] {
    let mut words = [0u32; (TABLE_SIZE / 4) as usize];
    for (index, value) in [400u32, 600, 800].iter().enumerate() {
        words[index] = *value; // DcfClocks
        words[8 + index] = *value + 100; // DispClocks
        words[16 + index] = *value + 100; // DppClocks
        words[24 + index] = *value; // SocClocks
    }
    for index in 0..2 {
        words[56 + index * 4] = 800 + index as u32 * 400; // FClk
        words[57 + index * 4] = 800 + index as u32 * 400; // MemClk
    }
    words[72] = u32::from_le_bytes([3, 3, 3, 3]);
    words[73] = 2;
    words[74] = 200;
    words[75] = 2500;
    words
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.regs[reg as usize] = value;
        if reg != MSG {
            return;
        }
        // Firmware answers the transaction.
        self.regs[RESPONSE as usize] = match self.reject {
            Some((message, status)) if message == value => status,
            _ => STATUS_OK,
        };
        self.regs[PARAM as usize] = self.reply;
        if value == MSG_TRANSFER_TABLE_SMU2DRAM && self.fill {
            self.table.copy_from_slice(&table_words());
        }
    }
    fn read_table(&mut self, offset: u64) -> u32 {
        self.table[(offset / 4) as usize]
    }
    fn write_table(&mut self, offset: u64, value: u32) {
        if value == 0 && offset == 0 {
            self.zeroed = true;
        }
        self.table[(offset / 4) as usize] = value;
    }
}
#[derive(Default)]
struct Sink {
    /// Interleaved record of what the consumers saw, to prove ordering.
    events: Vec<(&'static str, u32)>,
    fail_dto: bool,
}
impl Consumers for Sink {
    fn dpp_dto(&mut self, global_dppclk_khz: u32) -> Result<(), Error> {
        self.events.push(("dto", global_dppclk_khz));
        if self.fail_dto {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    async fn notify(&mut self, clocks: Clocks) -> Result<(), Error> {
        self.events.push(("notify", clocks.dppclk_khz));
        Ok(())
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 8192,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping-only pool; Fake performs every memory access.
    let pool = unsafe { Pool::from_owned_range(map, 0x3_0000_1000) }.unwrap();
    let table = pool.reserve(TABLE_SIZE).unwrap();
    (
        pool,
        Engine {
            io: Fake::new(),
            authority: Cap::bootstrap(),
            table,
            clocks: Clocks::default(),
            levels: None,
        },
    )
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn started() -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture();
    engine.levels = Some(run(engine.read_levels()).unwrap());
    engine.io.writes.clear();
    (pool, engine)
}

fn dcn_clk_mailbox_uses_display_registers_and_reports_rejection() -> TestResult {
    let (_pool, mut engine) = fixture();
    engine.io.reply = 540;
    if run(engine.send(MSG_SET_DISPCLK, 600)) != Ok(540) {
        return TestResult::Fail("mailbox reply");
    }
    // The display mailbox is 67/83/91, and the response is cleared before the
    // parameter and message are written.
    if engine.io.writes
        != [
            (RESPONSE, STATUS_BUSY),
            (PARAM, 600),
            (MSG, MSG_SET_DISPCLK),
        ]
    {
        return TestResult::Fail("mailbox register sequence");
    }
    engine.io.writes.clear();
    engine.io.reject = Some((MSG_SET_DISPCLK, 0xff));
    if run(engine.send(MSG_SET_DISPCLK, 600)) != Err(Error::Rejected(0xff)) {
        return TestResult::Fail("rejection not surfaced");
    }
    // A rejected mailbox is left usable for the next command.
    if engine.io.writes.last() != Some(&(RESPONSE, STATUS_OK)) {
        return TestResult::Fail("rejected mailbox left busy");
    }
    engine.io.gone = true;
    if run(engine.send(MSG_TEST, 0)) != Err(Error::DeviceGone) {
        return TestResult::Fail("vanished device accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_mailbox_uses_display_registers_and_reports_rejection
);

fn dcn_clk_dpm_table_is_zeroed_published_and_validated() -> TestResult {
    let (_pool, mut engine) = fixture();
    let address = engine.table.address();
    let levels = match run(engine.read_levels()) {
        Ok(levels) => levels,
        Err(_) => return TestResult::Fail("valid DPM table rejected"),
    };
    if !engine.io.zeroed {
        return TestResult::Fail("table not zeroed before the transfer");
    }
    if engine.io.messages()
        != [
            (MSG_SET_DRAM_ADDR_HIGH, (address >> 32) as u32),
            (MSG_SET_DRAM_ADDR_LOW, address as u32),
            (MSG_TRANSFER_TABLE_SMU2DRAM, TABLE_DPMCLOCKS),
        ]
    {
        return TestResult::Fail("DPM table fetch sequence or GPU address");
    }
    if levels.max_dispclk_khz() != 900_000
        || levels.max_dppclk_khz() != 900_000
        || levels.max_dcfclk_khz() != 800_000
        || levels.max_fclk_khz() != 1_200_000
        || (levels.display_levels, levels.df_pstates) != (3, 2)
    {
        return TestResult::Fail("parsed DPM levels");
    }
    // Firmware that writes nothing must not look like a usable table.
    let (_pool, mut engine) = fixture();
    engine.io.fill = false;
    if run(engine.read_levels()) != Err(Error::Unsupported) {
        return TestResult::Fail("empty DPM table accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_dpm_table_is_zeroed_published_and_validated
);

fn dcn_clk_table_rejects_out_of_range_levels_and_counts() -> TestResult {
    for (word, value) in [
        (72u32, 9u32),                          // more DCFCLK levels than exist
        (72, u32::from_le_bytes([3, 0, 3, 3])), // no DISPCLK levels
        (73, 0),                                // no DF p-states
        (8, 1),                                 // DISPCLK level of 1 MHz
        (16, 100_000),                          // DPPCLK level at the ceiling
        (57, 0),                                // MemClk missing for p-state 0
    ] {
        let mut words = table_words();
        words[word as usize] = value;
        if parse(&words).is_ok() {
            return TestResult::Fail("invalid DPM table accepted");
        }
    }
    if parse(&table_words()).is_err() {
        return TestResult::Fail("valid table rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_table_rejects_out_of_range_levels_and_counts
);

fn dcn_clk_raises_global_clock_before_lowering_dividers() -> TestResult {
    let (_pool, mut engine) = started();
    let mut sink = Sink::default();
    let request = Clocks {
        dispclk_khz: 800_000,
        dppclk_khz: 800_000,
        dcfclk_khz: 600_000,
        deep_sleep_dcfclk_khz: 300_000,
        dtbclk_enabled: false,
    };
    let applied = match run(engine.apply(request, false, &mut sink)) {
        Ok(applied) => applied,
        Err(_) => return TestResult::Fail("clock raise rejected"),
    };
    if applied != request {
        return TestResult::Fail("applied clocks");
    }
    // Raising: DCFCLK floor, deep sleep, DISPCLK, global DPPCLK, then dividers.
    if engine.io.messages()
        != [
            (MSG_SET_HARD_MIN_DCFCLK, 600),
            (MSG_SET_MIN_DEEP_SLEEP_DCFCLK, 300),
            (MSG_SET_DISPCLK, 800),
            (MSG_SET_DPPCLK, 800),
        ]
    {
        return TestResult::Fail("raise ordering");
    }
    if sink.events != [("dto", 800_000), ("notify", 800_000)] {
        return TestResult::Fail("dividers programmed before the global raise");
    }
    // Lowering DPPCLK must raise the per-DPP dividers first.
    engine.io.writes.clear();
    let mut sink = Sink::default();
    let lower = Clocks {
        dppclk_khz: 400_000,
        ..request
    };
    if run(engine.apply(lower, true, &mut sink)).is_err() {
        return TestResult::Fail("clock lower rejected");
    }
    if sink.events.first() != Some(&("dto", 400_000))
        || engine.io.messages() != [(MSG_SET_DPPCLK, 400)]
    {
        return TestResult::Fail("global clock lowered before its dividers");
    }
    // Without permission to lower, a smaller request changes nothing.
    engine.io.writes.clear();
    let mut sink = Sink::default();
    if run(engine.apply(
        Clocks {
            dispclk_khz: 100_000,
            ..lower
        },
        false,
        &mut sink,
    ))
    .map(|c| c.dispclk_khz)
        != Ok(800_000)
    {
        return TestResult::Fail("unsafe lowering applied");
    }
    if engine
        .io
        .messages()
        .iter()
        .any(|(m, _)| *m == MSG_SET_DISPCLK)
    {
        return TestResult::Fail("DISPCLK lowered without permission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_raises_global_clock_before_lowering_dividers
);

fn dcn_clk_bounds_requests_by_dpm_and_tolerates_dcfclk_refusal() -> TestResult {
    let (_pool, mut engine) = started();
    let mut sink = Sink::default();
    // Nothing above the firmware's own DPM ceiling may be requested.
    for request in [
        Clocks {
            dispclk_khz: 1_000_000,
            ..Default::default()
        },
        Clocks {
            dppclk_khz: 1_000_000,
            ..Default::default()
        },
        Clocks {
            dcfclk_khz: 900_000,
            ..Default::default()
        },
        Clocks {
            dcfclk_khz: 400_000,
            deep_sleep_dcfclk_khz: 500_000,
            ..Default::default()
        },
    ] {
        if run(engine.apply(request, false, &mut sink)) != Err(Error::Invalid) {
            return TestResult::Fail("request beyond the DPM table accepted");
        }
    }
    if !engine.io.messages().is_empty() {
        return TestResult::Fail("rejected request still programmed clocks");
    }
    // The DPPCLK floor applies even when a caller asks for less.
    let mut sink = Sink::default();
    let applied = run(engine.apply(
        Clocks {
            dispclk_khz: 500_000,
            dppclk_khz: 20_000,
            ..Default::default()
        },
        false,
        &mut sink,
    ));
    if applied.map(|c| c.dppclk_khz) != Ok(DPPCLK_FLOOR_KHZ) {
        return TestResult::Fail("DPPCLK floor not applied");
    }
    // A BIOS with DCFCLK DPM disabled rejects the floor messages; the boot
    // clock already satisfies the request, so the modeset continues.
    let (_pool, mut engine) = started();
    engine.io.reject = Some((MSG_SET_HARD_MIN_DCFCLK, 0xff));
    let mut sink = Sink::default();
    if run(engine.apply(
        Clocks {
            dispclk_khz: 500_000,
            dppclk_khz: 500_000,
            dcfclk_khz: 600_000,
            ..Default::default()
        },
        false,
        &mut sink,
    ))
    .is_err()
    {
        return TestResult::Fail("DCFCLK refusal aborted the clock update");
    }
    if engine.clocks.dcfclk_khz != 0 {
        return TestResult::Fail("refused DCFCLK recorded as applied");
    }
    // A divider failure must abort rather than leave clocks and dividers apart.
    let (_pool, mut engine) = started();
    let mut sink = Sink {
        fail_dto: true,
        ..Default::default()
    };
    if run(engine.apply(
        Clocks {
            dispclk_khz: 500_000,
            dppclk_khz: 500_000,
            ..Default::default()
        },
        false,
        &mut sink,
    ))
    .is_ok()
    {
        return TestResult::Fail("divider failure ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_bounds_requests_by_dpm_and_tolerates_dcfclk_refusal
);
