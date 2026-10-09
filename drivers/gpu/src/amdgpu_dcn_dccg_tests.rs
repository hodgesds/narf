use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    gone: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
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
fn dccg() -> Engine<Fake> {
    Engine {
        io: Fake::new(),
        authority: Cap::bootstrap(),
        reference_dppclk_khz: 0,
    }
}
fn dccg_pixel_rate_dividers_are_per_otg_three_bit_fields() -> TestResult {
    let mut dccg = dccg();
    // DisplayPort 8b/10b, one pixel per container, no ODM: divide by 1 then 4.
    // The divide-by-four code is 3, not 4.
    if dccg
        .set_pixel_rate_div(0, Divider::By1, Divider::By4)
        .is_err()
    {
        return TestResult::Fail("OTG0 divider rejected");
    }
    if dccg.io.values[OTG_PIXEL_RATE_DIV as usize] != 0b110 {
        return TestResult::Fail("OTG0 divider encoding");
    }
    // Each OTG owns three bits, so programming one must not disturb another.
    if dccg
        .set_pixel_rate_div(2, Divider::By1, Divider::By2)
        .is_err()
    {
        return TestResult::Fail("OTG2 divider rejected");
    }
    if dccg.io.values[OTG_PIXEL_RATE_DIV as usize] != 0b010_000_110 {
        return TestResult::Fail("OTG2 divider disturbed another OTG");
    }
    if dccg
        .set_pixel_rate_div(INSTANCES, Divider::By1, Divider::By4)
        .is_ok()
    {
        return TestResult::Fail("out-of-range OTG accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-dccg",
    dccg_pixel_rate_dividers_are_per_otg_three_bit_fields
);

fn dccg_dpp_divider_rounds_up_against_the_global_clock() -> TestResult {
    let mut dccg = dccg();
    // Without a reference clock there is nothing to divide, so the pipe is
    // parked rather than left on a stale ratio.
    if dccg.dpp_dto(0, 600_000).is_err() {
        return TestResult::Fail("unreferenced pipe not parked");
    }
    if dccg.io.values[DPPCLK_DTO_CTRL as usize] & 1 != 0 {
        return TestResult::Fail("pipe enabled without a reference clock");
    }
    dccg.reference_dppclk_khz = 600_000;
    // A pipe at the full global clock takes the whole modulo.
    if dccg.dpp_dto(1, 600_000).is_err() {
        return TestResult::Fail("full-rate pipe rejected");
    }
    if dccg.io.values[(DPPCLK0_DTO_PARAM + 1) as usize] != 0xff | 0xff << 16 {
        return TestResult::Fail("full-rate phase/modulo");
    }
    // Enable and double-buffer bits are four apart, per pipe.
    if dccg.io.values[DPPCLK_DTO_CTRL as usize] != 1 << 4 {
        return TestResult::Fail("pipe enable bit");
    }
    // Half rate rounds up: ceil(255 * 300000 / 600000) = 128, not 127.
    if dccg.dpp_dto(1, 300_000).is_err() {
        return TestResult::Fail("half-rate pipe rejected");
    }
    if dccg.io.values[(DPPCLK0_DTO_PARAM + 1) as usize] & 0xffff != 128 {
        return TestResult::Fail("divider rounded down and starved the pipe");
    }
    // A pipe cannot be asked for more than the global clock provides.
    if dccg.dpp_dto(1, 700_000).is_ok() {
        return TestResult::Fail("pipe above the global clock accepted");
    }
    // Requesting zero parks the pipe.
    if dccg.dpp_dto(1, 0).is_err() || dccg.io.values[DPPCLK_DTO_CTRL as usize] & 1 << 4 != 0 {
        return TestResult::Fail("zero request did not park the pipe");
    }
    if dccg.dpp_dto(INSTANCES, 600_000).is_ok() {
        return TestResult::Fail("out-of-range pipe accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-dccg",
    dccg_dpp_divider_rounds_up_against_the_global_clock
);

fn dccg_stream_clock_and_dentist_resync() -> TestResult {
    let mut dccg = dccg();
    // DPIA 2 fed from OTG 1, the case that distinguishes a correct source
    // select from an enable alone.
    if dccg.set_dp_stream_clock(2, 1, StreamClock::Dtbclk).is_err() {
        return TestResult::Fail("DPIA stream clock rejected");
    }
    // Four bits per DPIA; the enable sits above the three source-select bits,
    // and the select carries the OTG instance. Literal so that a wrong field
    // layout fails rather than being restated.
    if dccg.io.values[DPSTREAMCLK_CNTL as usize] != 0x0900 {
        return TestResult::Fail("DPIA stream clock must select its own OTG, not OTG 0");
    }
    // The OTG's DTBCLK_P mux has to be pointed at DTBCLK0 first, and source
    // select 2 is DTBCLK0 — zero would leave it on DPREFCLK. Three bits per
    // OTG, so OTG 1 occupies bits 5:3: select 2, enable set.
    if dccg.io.values[DTBCLK_P_CNTL as usize] != 0x0030 {
        return TestResult::Fail("DTBCLK_P mux not pointed at DTBCLK0 for the OTG");
    }
    if dccg
        .set_dp_stream_clock(2, 1, StreamClock::Disabled)
        .is_err()
        || dccg.io.values[DPSTREAMCLK_CNTL as usize] != 0
        || dccg.io.values[DTBCLK_P_CNTL as usize] != 0
    {
        return TestResult::Fail("DPIA stream clock not parked");
    }
    if dccg
        .set_dp_stream_clock(INSTANCES, 0, StreamClock::Dtbclk)
        .is_ok()
    {
        return TestResult::Fail("out-of-range DPIA accepted");
    }
    if dccg
        .set_dp_stream_clock(0, INSTANCES, StreamClock::Dtbclk)
        .is_ok()
    {
        return TestResult::Fail("out-of-range OTG accepted");
    }
    // A resync copies the divider DENTIST is really running into the request
    // field, so the DIO FIFOs restart against the live divider.
    dccg.io.values[DENTIST_DISPCLK_CNTL as usize] = 0x20 | 0x35 << 8;
    if dccg.resync_dio_fifo().is_err() {
        return TestResult::Fail("resync rejected");
    }
    if dccg.dispclk_dividers() != Ok((0x35, 0x35)) {
        return TestResult::Fail("resync did not adopt the live divider");
    }
    // A vanished device must not read as a divider of all ones.
    dccg.io.gone = true;
    if dccg.dispclk_dividers() != Err(Error::DeviceGone) {
        return TestResult::Fail("vanished device accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-dccg", dccg_stream_clock_and_dentist_resync);

fn dccg_single_pipe_consumer_tracks_the_global_clock() -> TestResult {
    let mut device = dccg();
    // The clock manager's divider callback must adopt the new global clock as
    // its reference, not divide against whatever was there before, which is
    // exactly what SinglePipe::dpp_dto does for the owned pipe.
    device.reference_dppclk_khz = 500_000;
    if device.dpp_dto(3, 500_000).is_err() {
        return TestResult::Fail("consumer divider rejected");
    }
    if device.reference_dppclk_khz != 500_000 {
        return TestResult::Fail("reference clock not adopted");
    }
    if device.io.values[DPPCLK_DTO_CTRL as usize] != 1 << 12 {
        return TestResult::Fail("consumer enabled the wrong pipe");
    }
    if device.io.values[(DPPCLK0_DTO_PARAM + 3) as usize] & 0xffff != 0xff {
        return TestResult::Fail("consumer did not run the pipe at full rate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-dccg",
    dccg_single_pipe_consumer_tracks_the_global_clock
);
