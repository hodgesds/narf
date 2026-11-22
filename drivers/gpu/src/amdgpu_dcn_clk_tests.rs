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
    /// The DCN 3.1.5 model: MP1_C2PMSG_3 as written through SMN, how many of
    /// those writes to drop before one lands, and every SMN access.
    smn_msg: u32,
    drop_smn: u32,
    smn: Vec<(u32, u32)>,
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
            smn_msg: 0,
            drop_smn: 0,
            smn: Vec::new(),
        }
    }
    /// (message, param) pairs a DCN 3.1.5 engine sent, in order.
    fn messages_315(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let mut param = 0;
        let mut writes = self.writes.iter();
        for &(address, value) in &self.smn {
            if address != MSG_SMN_315 {
                continue;
            }
            // The parameter is the last PARAM_315 write before this message.
            for &(reg, v) in writes.by_ref() {
                if reg == PARAM_315 {
                    param = v;
                    break;
                }
            }
            if out.last() != Some(&(value, param)) {
                out.push((value, param));
            }
        }
        out
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
        words[59 + index * 4] = 1; // WckRatio 1:2
    }
    words[72] = u32::from_le_bytes([3, 3, 3, 3]);
    words[73] = 2;
    words[74] = 200;
    words[75] = 2500;
    words
}
/// A `DpmClocks_315_t`: three DCF/DISP/DPP/SOC levels, two DF p-states.
fn table_words_315() -> [u32; (TABLE_SIZE_315 / 4) as usize] {
    let mut words = [0u32; (TABLE_SIZE_315 / 4) as usize];
    for (index, value) in [400u32, 600, 800].iter().enumerate() {
        words[index] = *value; // DcfClocks
        words[4 + index] = *value + 200; // DispClocks
        words[8 + index] = *value + 200; // DppClocks
        words[12 + index] = *value; // SocClocks
        words[16 + index] = 900; // VClocks: not latched
    }
    for index in 0..2 {
        words[28 + index * 3] = 1600 + index as u32 * 400; // FClk
        words[29 + index * 3] = 2400 + index as u32 * 400; // MemClk
        words[30 + index * 3] = 3000; // Voltage
    }
    words[40] = u32::from_le_bytes([3, 3, 3, 3]);
    words[41] = 2;
    words[42] = 200;
    words[43] = 2200;
    words
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model answers every message synchronously in write():
        // RESPONSE leaves BUSY before settled()'s first read, exactly
        // like the dcn401/dcn30 clk models capped by #905. A wait
        // still BUSY after sixteen polls is a stuck mailbox whose
        // outcome is the timeout — reached by count instead of
        // burning the wall-clock deadline under the spin executor
        // (#879).
        Some(16)
    }
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
    fn read_smn(&mut self, address: u32) -> u32 {
        if address == MSG_SMN_315 {
            self.smn_msg
        } else {
            0
        }
    }
    fn write_smn(&mut self, address: u32, value: u32) {
        self.smn.push((address, value));
        if address != MSG_SMN_315 {
            return;
        }
        if self.drop_smn > 0 {
            self.drop_smn -= 1;
            return;
        }
        self.smn_msg = value;
        self.regs[RESPONSE_315 as usize] = match self.reject {
            Some((message, status)) if message == value => status,
            _ => STATUS_OK,
        };
        self.regs[PARAM_315 as usize] = self.reply;
        if value == MSG_TRANSFER_TABLE_SMU2DRAM && self.fill {
            self.table[..(TABLE_SIZE_315 / 4) as usize].copy_from_slice(&table_words_315());
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
            mailbox: Mailbox::Dcn314,
            table,
            clocks: Clocks::default(),
            levels: None,
            dprefclk_khz: DPREFCLK_KHZ,
            pstate_supported: true,
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
    // Double data rate times the 1:2 WCK ratio: 1200 MHz becomes 4800 MT/s.
    if levels.max_dram_speed_mts() != 4800 {
        return TestResult::Fail("DRAM data rate");
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

/// `dce_adjust_dp_ref_freq_for_ss` in Linux's 31.32 fixed point: the values
/// below are what Linux programs, computed by running its
/// `dc_fixpt_from_fraction` / `dc_fixpt_mul` sequence, not exact arithmetic.
fn clk_dp_dto_reference_follows_linux_fixed_point() -> TestResult {
    let spread = |percentage| {
        Some(Spread {
            percentage,
            divider: 1000,
        })
    };
    for (percentage, want) in [
        // The LUT's 0.375 %: exact is 598 875, Linux's rounding gives 598 874.
        (375, 598_874),
        (250, 599_250),
        (500, 598_500),
        (0, 600_000),
    ] {
        if dp_dto_reference_khz(600_000, spread(percentage)) != want {
            return TestResult::Fail("spread-adjusted DPREFCLK is not Linux's");
        }
    }
    if dp_dto_reference_khz(598_000, spread(375)) != 596_878 {
        return TestResult::Fail("spread-adjusted reference off 600 MHz");
    }
    // No spread, or a zero divider (Linux's guard), leaves the clock alone.
    if dp_dto_reference_khz(600_000, None) != 600_000
        || dp_dto_reference_khz(
            600_000,
            Some(Spread {
                percentage: 375,
                divider: 0,
            }),
        ) != 600_000
    {
        return TestResult::Fail("unspread reference changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    clk_dp_dto_reference_follows_linux_fixed_point
);

fn fixture_315() -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture();
    engine.mailbox = Mailbox::Dcn315;
    engine.dprefclk_khz = 0;
    engine.io.regs[RESPONSE_315 as usize] = STATUS_OK;
    (pool, engine)
}

/// `dcn315_smu_send_msg_with_param`: RESPONSE (C2PMSG_38) cleared to BUSY,
/// the parameter in C2PMSG_37, then the id written to MP1_C2PMSG_3 through
/// SMN and read back, retried up to five times; the reply is C2PMSG_37. A
/// rejection is reported but, unlike DCN 3.1.4, RESPONSE is not reset.
fn dcn_clk_dcn315_mailbox_writes_the_message_through_smn() -> TestResult {
    if (PARAM_315, RESPONSE_315, MSG_SMN_315) != (0x265, 0x266, 0x03b1_050c) {
        return TestResult::Fail("DCN 3.1.5 mailbox ids are not mp_13_0_5's / dcn315_smu.c's");
    }
    let (_pool, mut engine) = fixture_315();
    engine.io.reply = 1234;
    if run(engine.send(MSG_SET_DISPCLK, 600)) != Ok(1234) {
        return TestResult::Fail("DCN 3.1.5 message");
    }
    let writes = &engine.io.writes;
    let busy = writes
        .iter()
        .position(|&(r, v)| r == RESPONSE_315 && v == STATUS_BUSY);
    let param = writes.iter().position(|&(r, v)| r == PARAM_315 && v == 600);
    if busy.is_none() || param.is_none() || busy > param {
        return TestResult::Fail("RESPONSE cleared before the parameter");
    }
    if writes
        .iter()
        .any(|&(r, _)| r == MSG || r == PARAM || r == RESPONSE)
    {
        return TestResult::Fail("DCN 3.1.5 touched DCN 3.1.4's mailbox");
    }
    if engine.io.smn != [(MSG_SMN_315, MSG_SET_DISPCLK)] {
        return TestResult::Fail("message id not written once through SMN");
    }
    // A write that does not read back is retried, up to five times.
    engine.io.smn.clear();
    engine.io.drop_smn = 2;
    if run(engine.send(MSG_SET_DPPCLK, 300)).is_err() || engine.io.smn.len() != 3 {
        return TestResult::Fail("dropped message write not retried");
    }
    // Five lost writes leave the mailbox BUSY: a timeout, not a success. The
    // id differs from the last one that landed: a read-back cannot tell a
    // dropped write of the same id from a landed one, in Linux's protocol too.
    engine.io.smn.clear();
    engine.io.drop_smn = 5;
    engine.io.regs[RESPONSE_315 as usize] = STATUS_OK;
    if run(engine.send(MSG_SET_HARD_MIN_DCFCLK, 300)) != Err(Error::Timeout)
        || engine.io.smn.len() != 5
    {
        return TestResult::Fail("a message that never landed");
    }
    // Rejection: reported, and RESPONSE left as the firmware wrote it.
    let (_pool, mut engine) = fixture_315();
    engine.io.reject = Some((MSG_SET_HARD_MIN_DCFCLK, 0xfd));
    if run(engine.send(MSG_SET_HARD_MIN_DCFCLK, 400)) != Err(Error::Rejected(0xfd))
        || engine.io.regs[RESPONSE_315 as usize] != 0xfd
    {
        return TestResult::Fail("DCN 3.1.5 rejection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_dcn315_mailbox_writes_the_message_through_smn
);

/// DCN 3.1.5 start: test, version, then GetDprefclkFreq (0x13) for the DP
/// DTO's reference, then the 176-byte `DpmClocks_315_t`. Clock changes use
/// SetDtbClk 0x0A, and on both mailboxes DISPCLK is asked for no lower than
/// `min_disp_clk_khz` (100 MHz) while the request is what is recorded.
fn dcn_clk_dcn315_start_reads_dprefclk_and_the_four_level_table() -> TestResult {
    let (_pool, mut engine) = fixture_315();
    engine.io.reply = 598;
    let messages = |engine: &Engine<Fake>| engine.io.messages_315();
    let start = run(async {
        engine.send(MSG_TEST, 0).await?;
        engine.send(MSG_GET_VERSION, 0).await?;
        let mhz = engine.send(MSG_GET_DPREFCLK_315, 0).await?;
        engine.dprefclk_khz = mhz * 1000;
        engine.read_levels().await
    });
    let Ok(levels) = start else {
        return TestResult::Fail("DCN 3.1.5 start");
    };
    if engine.dprefclk_khz != 598_000 {
        return TestResult::Fail("DPREFCLK not taken from the firmware");
    }
    if !engine.io.zeroed
        || messages(&engine).iter().map(|m| m.0).collect::<Vec<_>>()
            != [
                MSG_TEST,
                MSG_GET_VERSION,
                MSG_GET_DPREFCLK_315,
                MSG_SET_DRAM_ADDR_HIGH,
                MSG_SET_DRAM_ADDR_LOW,
                MSG_TRANSFER_TABLE_SMU2DRAM,
            ]
    {
        return TestResult::Fail("DCN 3.1.5 start sequence");
    }
    if levels.dcfclk[..4] != [400, 600, 800, 0]
        || levels.dispclk[..4] != [600, 800, 1000, 0]
        || levels.socclk[..3] != [400, 600, 800]
        || (
            levels.fclk[0],
            levels.memclk[0],
            levels.fclk[1],
            levels.memclk[1],
        ) != (1600, 2400, 2000, 2800)
        || levels.df_pstates != 2
        || (levels.min_gfxclk, levels.max_gfxclk) != (200, 2200)
        || levels.max_dram_speed_mts() != 2800 * 2
    {
        return TestResult::Fail("DpmClocks_315_t parse");
    }
    // A count past the four-level layout is refused.
    let mut words = [0u32; (TABLE_SIZE / 4) as usize];
    words[..(TABLE_SIZE_315 / 4) as usize].copy_from_slice(&table_words_315());
    words[40] = u32::from_le_bytes([5, 3, 3, 3]);
    if parse_315(&words).is_ok() {
        return TestResult::Fail("five DCFCLK levels in a four-level table");
    }
    // SetDtbClk is 0x0A here, and a low DISPCLK asks PMFW for 100 MHz.
    engine.levels = Some(levels);
    engine.io.writes.clear();
    engine.io.smn.clear();
    let mut sink = Sink::default();
    let request = Clocks {
        dispclk_khz: 50_000,
        dppclk_khz: 100_000,
        dcfclk_khz: 400_000,
        deep_sleep_dcfclk_khz: 300_000,
        dtbclk_enabled: true,
    };
    let Ok(applied) = run(engine.apply(request, false, &mut sink)) else {
        return TestResult::Fail("DCN 3.1.5 apply");
    };
    let sent = messages(&engine);
    if !sent.contains(&(MSG_SET_DTBCLK_315, 1))
        || sent.iter().any(|m| m.0 == MSG_SET_DTBCLK)
        || !sent.contains(&(MSG_SET_DISPCLK, 100))
        || applied.dispclk_khz != 50_000
    {
        return TestResult::Fail("DCN 3.1.5 DTBCLK id or DISPCLK floor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_dcn315_start_reads_dprefclk_and_the_four_level_table
);

/// `dcn315_update_clocks`: "Lock pstate by requesting unsupported dcfclk if
/// change is unsupported" — SetHardMinDcfclkByFreq(10000 MHz) and the
/// sentinel recorded. DCN 3.1.4's clock manager has no such lock.
fn dcn_clk_dcn315_locks_pstate_with_an_unsupported_dcfclk() -> TestResult {
    let request = Clocks {
        dispclk_khz: 600_000,
        dppclk_khz: 600_000,
        dcfclk_khz: 400_000,
        deep_sleep_dcfclk_khz: 300_000,
        dtbclk_enabled: false,
    };
    let (_pool, mut engine) = fixture_315();
    engine.levels = Some(
        parse_315(&{
            let mut words = [0u32; (TABLE_SIZE / 4) as usize];
            words[..(TABLE_SIZE_315 / 4) as usize].copy_from_slice(&table_words_315());
            words
        })
        .unwrap(),
    );
    engine.pstate_supported = false;
    let mut sink = Sink::default();
    let Ok(applied) = run(engine.apply(request, false, &mut sink)) else {
        return TestResult::Fail("DCN 3.1.5 locked apply");
    };
    if !engine
        .io
        .messages_315()
        .contains(&(MSG_SET_HARD_MIN_DCFCLK, 10_000))
        || applied.dcfclk_khz != UNSUPPORTED_DCFCLK_KHZ
    {
        return TestResult::Fail("p-state not locked through DCFCLK");
    }
    let (_pool, mut phoenix) = started();
    phoenix.pstate_supported = false;
    let mut sink = Sink::default();
    match run(phoenix.apply(request, false, &mut sink)) {
        Ok(applied) if applied.dcfclk_khz == 400_000 => {}
        _ => return TestResult::Fail("DCN 3.1.4 must not lock p-state"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-clk",
    dcn_clk_dcn315_locks_pstate_with_an_unsupported_dcfclk
);
