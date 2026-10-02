use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    busy: bool,
    gone: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
            busy: false,
            gone: false,
        }
    }
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        self.values[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.values[reg as usize] = value;
    }
}
fn engine(instance: u8) -> Engine<Fake> {
    let mut io = Fake::new();
    // The vertical timing generator and OTG clock start quiescent.
    io.values[OTG_CLOCK_CONTROL as usize + instance as usize * OTG_STRIDE as usize] = 0;
    Engine {
        io,
        authority: Cap::bootstrap(),
        instance,
        state: State::Idle,
    }
}
fn timing() -> Timing {
    Timing {
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
        v_sync_positive: true,
    }
}
fn sync() -> GlobalSync {
    GlobalSync {
        v_startup_lines: 9,
        v_update_offset_pix: 550,
        v_update_width_pix: 247,
        v_ready_offset_pix: 328,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn otg_timing_counters_hold_one_less_than_the_total() -> TestResult {
    let mut otg = engine(0);
    if otg.program_timing(&timing(), &sync()).is_err() {
        return TestResult::Fail("1080p timing rejected");
    }
    let v = &otg.io.values;
    // Counters hold total - 1.
    if v[OTG_H_TOTAL as usize] != 2199 || v[OTG_V_TOTAL as usize] != 1124 {
        return TestResult::Fail("totals");
    }
    // With V_TOTAL_CONTROL off, min and max must match or a variable-refresh
    // range left by firmware would retime the stream.
    if v[OTG_V_TOTAL_MIN as usize] != 1124 || v[OTG_V_TOTAL_MAX as usize] != 1124 {
        return TestResult::Fail("V_TOTAL min/max not pinned");
    }
    // Blank starts after active plus front porch and ends an active later.
    if v[OTG_H_BLANK_START_END as usize] != 2112 | 192 << 16 {
        return TestResult::Fail("horizontal blank");
    }
    if v[OTG_V_BLANK_START_END as usize] != 1121 | 41 << 16 {
        return TestResult::Fail("vertical blank");
    }
    // Sync starts at zero and runs for its width.
    if v[OTG_H_SYNC_A as usize] != 44 << 16 || v[OTG_V_SYNC_A as usize] != 5 << 16 {
        return TestResult::Fail("sync position");
    }
    // The polarity field means negative, so a positive mode programs zero.
    if v[OTG_H_SYNC_A_CNTL as usize] & 1 != 0 || v[OTG_V_SYNC_A_CNTL as usize] & 1 != 0 {
        return TestResult::Fail("sync polarity inverted");
    }
    let mut negative = timing();
    negative.h_sync_positive = false;
    negative.v_sync_positive = false;
    let mut otg = engine(0);
    otg.program_timing(&negative, &sync()).unwrap();
    if otg.io.values[OTG_H_SYNC_A_CNTL as usize] & 1 != 1
        || otg.io.values[OTG_V_SYNC_A_CNTL as usize] & 1 != 1
    {
        return TestResult::Fail("negative polarity not programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-otg",
    otg_timing_counters_hold_one_less_than_the_total
);

fn otg_single_segment_and_global_sync() -> TestResult {
    let mut otg = engine(2);
    if otg.program_timing(&timing(), &sync()).is_err() {
        return TestResult::Fail("timing rejected");
    }
    let odm = |reg: u64| reg + 2 * ODM_STRIDE;
    let otg_reg = |reg: u64| reg + 2 * OTG_STRIDE;
    // One OPP segment feeds this OTG; the other three are parked.
    if otg.io.values[odm(OPTC_DATA_SOURCE_SELECT) as usize]
        != 2 << 16 | SEGMENT_PARKED << 20 | SEGMENT_PARKED << 24 | SEGMENT_PARKED << 28
    {
        return TestResult::Fail("segment source select");
    }
    // No ODM combine means no horizontal timing division and no memory split.
    if otg.io.values[otg_reg(OTG_H_TIMING_CNTL) as usize] & 3 != 0
        || otg.io.values[odm(OPTC_MEMORY_CONFIG) as usize] != 0
    {
        return TestResult::Fail("ODM bypass");
    }
    if otg.io.values[odm(OPTC_WIDTH_CONTROL) as usize] & 0x1fff != 1920 {
        return TestResult::Fail("segment width");
    }
    // DisplayPort counts from the blank's first line, with no field number.
    if otg.io.values[otg_reg(OTG_CONTROL) as usize] & (1 << 12 | 1 << 13) != 1 << 12 {
        return TestResult::Fail("start point or field number");
    }
    // Global sync, with the VUPDATE width in the upper half.
    if otg.io.values[otg_reg(OTG_VSTARTUP_PARAM) as usize] != 9
        || otg.io.values[otg_reg(OTG_VUPDATE_PARAM) as usize] != 550 | 247 << 16
        || otg.io.values[otg_reg(OTG_VREADY_PARAM) as usize] != 328
    {
        return TestResult::Fail("global sync");
    }
    // A zero VStartup would never give the detile buffer time to prefetch.
    if otg
        .program_global_sync(&GlobalSync {
            v_startup_lines: 0,
            ..sync()
        })
        .is_ok()
    {
        return TestResult::Fail("zero VStartup accepted");
    }
    // VSTARTUP is ten bits and the VUPDATE width ten; neither may wrap.
    for bad in [
        GlobalSync {
            v_startup_lines: 1024,
            ..sync()
        },
        GlobalSync {
            v_update_width_pix: 1024,
            ..sync()
        },
        GlobalSync {
            v_ready_offset_pix: 1 << 16,
            ..sync()
        },
    ] {
        if otg.program_global_sync(&bad).is_ok() {
            return TestResult::Fail("global sync field overflow accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-otg", otg_single_segment_and_global_sync);

fn otg_enable_sequences_vtg_before_master() -> TestResult {
    let mut otg = engine(1);
    // Enabling before a mode is programmed would start an undefined timing.
    if otg.enable().is_ok() {
        return TestResult::Fail("enabled an unprogrammed generator");
    }
    otg.program_timing(&timing(), &sync()).unwrap();
    otg.io.writes.clear();
    if otg.enable().is_err() {
        return TestResult::Fail("enable rejected");
    }
    if otg.state != State::Running {
        return TestResult::Fail("state after enable");
    }
    // The vertical timing generator must come up before the master enable.
    let vtg = VTG_CONTROL + 1;
    let control = OTG_CONTROL + OTG_STRIDE;
    let vtg_at = otg.io.writes.iter().position(|(r, _)| *r == vtg);
    let master_at = otg
        .io
        .writes
        .iter()
        .position(|(r, v)| *r == control && v & 1 != 0);
    if vtg_at.is_none() || master_at.is_none() || vtg_at >= master_at {
        return TestResult::Fail("master enable preceded the timing generator");
    }
    // The request stays disabled until the first line of the blank.
    if otg.io.values[control as usize] & 0x301 != 2 << 8 | 1 {
        return TestResult::Fail("disable point or master enable");
    }
    // Retiming a running generator would tear.
    if otg.program_timing(&timing(), &sync()) != Err(Error::Busy) {
        return TestResult::Fail("retimed a running generator");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-otg",
    otg_enable_sequences_vtg_before_master
);

fn otg_disable_parks_segments_and_waits_for_idle() -> TestResult {
    let mut otg = engine(0);
    otg.program_timing(&timing(), &sync()).unwrap();
    otg.enable().unwrap();
    if run(otg.disable()).is_err() {
        return TestResult::Fail("disable rejected");
    }
    if otg.state != State::Idle {
        return TestResult::Fail("state after disable");
    }
    // Every segment parked, the master enable dropped and the timing generator
    // stopped.
    if otg.io.values[OPTC_DATA_SOURCE_SELECT as usize]
        != SEGMENT_PARKED << 16 | SEGMENT_PARKED << 20 | SEGMENT_PARKED << 24 | SEGMENT_PARKED << 28
    {
        return TestResult::Fail("segments not parked");
    }
    if otg.io.values[OTG_CONTROL as usize] & 1 != 0
        || otg.io.values[VTG_CONTROL as usize] & 1 << 31 != 0
    {
        return TestResult::Fail("generator left running");
    }
    // A generator that never reports idle must time out, not be called stopped.
    let mut stuck = engine(0);
    stuck.program_timing(&timing(), &sync()).unwrap();
    stuck.enable().unwrap();
    stuck.io.values[OTG_CLOCK_CONTROL as usize] = 1 << 16;
    stuck.io.busy = true;
    if run(stuck.disable()) != Err(Error::Timeout) {
        return TestResult::Fail("busy generator reported as stopped");
    }
    if stuck.state == State::Idle {
        return TestResult::Fail("busy generator marked idle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-otg",
    otg_disable_parks_segments_and_waits_for_idle
);
