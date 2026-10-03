use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    /// The stream never reports stopped, to exercise the timeouts.
    stuck: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
            stuck: false,
        }
    }
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        let value = self.values[reg as usize];
        if reg % STRIDE == DP_VID_STREAM_CNTL % STRIDE && self.stuck {
            return value | 1 << 16;
        }
        value
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.values[reg as usize] = value;
    }
}
fn engine(instance: u8) -> Engine<Fake> {
    Engine {
        io: Fake::new(),
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
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn stream_main_attributes_describe_the_timing_to_the_sink() -> TestResult {
    let mut stream = engine(1);
    if stream.program(&timing(), Depth::Bpc8).is_err() {
        return TestResult::Fail("stream attributes rejected");
    }
    let at = |reg: u64| reg + STRIDE;
    let v = &stream.io.values;
    // Uncompressed RGB at eight bits per component.
    if v[at(DP_PIXEL_FORMAT) as usize] & 0x7 != PIXEL_ENCODING_RGB
        || v[at(DP_PIXEL_FORMAT) as usize] >> 24 & 0x7 != 1
    {
        return TestResult::Fail("pixel format");
    }
    // MISC0 carries the colorimetry depth in bits 7:5 of the byte at bit 24.
    if v[at(DP_MSA_COLORIMETRY) as usize] != 1 << 5 << 24 {
        return TestResult::Fail("colorimetry");
    }
    // No VSC SDP override and not Y-only.
    if v[at(DP_MSA_MISC) as usize] & 0xc0 != 0 {
        return TestResult::Fail("MISC1");
    }
    if v[at(DP_MSA_TIMING_PARAM1) as usize] != 1125 | 2200 << 16 {
        return TestResult::Fail("MSA totals");
    }
    // Active starts at sync plus back porch: 44 + (280 - 88 - 44) = 192, and
    // vertically at 1125 - 1080 - 4 = 41. Both match the timing generator's
    // blank-end counts.
    if v[at(DP_MSA_TIMING_PARAM2) as usize] != 41 | 192 << 16 {
        return TestResult::Fail("MSA active start");
    }
    if v[at(DP_MSA_TIMING_PARAM3) as usize] != 5 | 44 << 16 {
        return TestResult::Fail("MSA sync widths or polarity");
    }
    if v[at(DP_MSA_TIMING_PARAM4) as usize] != 1080 | 1920 << 16 {
        return TestResult::Fail("MSA active size");
    }
    // A negative-polarity mode sets both polarity bits, which mean "negative".
    let mut negative = timing();
    negative.h_sync_positive = false;
    negative.v_sync_positive = false;
    let mut stream = engine(1);
    stream.program(&negative, Depth::Bpc8).unwrap();
    let param3 = stream.io.values[at(DP_MSA_TIMING_PARAM3) as usize];
    if param3 & 1 << 15 == 0 || param3 & 1 << 31 == 0 {
        return TestResult::Fail("negative sync polarity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-stream",
    stream_main_attributes_describe_the_timing_to_the_sink
);

fn stream_rate_ratio_seeds_the_measurement_below_one() -> TestResult {
    let mut stream = engine(0);
    stream.program(&timing(), Depth::Bpc8).unwrap();
    // HBR2 is link-rate code 20, so 540000 kHz: M = 32768 * 148500 / 540000.
    if stream.program_rate(148_500, 20).is_err() {
        return TestResult::Fail("rate ratio rejected");
    }
    if stream.io.values[DP_VID_N as usize] != N_VID {
        return TestResult::Fail("N seed");
    }
    if stream.io.values[DP_VID_M as usize] != 9011 {
        return TestResult::Fail("M seed");
    }
    // The generator is disabled while M and N are seeded, then enabled.
    let gen_off = stream
        .io
        .writes
        .iter()
        .position(|(r, v)| *r == DP_VID_TIMING && v & 1 << 8 == 0);
    let m_at = stream.io.writes.iter().position(|(r, _)| *r == DP_VID_M);
    let gen_on = stream
        .io
        .writes
        .iter()
        .rposition(|(r, v)| *r == DP_VID_TIMING && v & 1 << 8 != 0);
    if gen_off.is_none() || m_at.is_none() || gen_off >= m_at || m_at >= gen_on {
        return TestResult::Fail("M and N seeded outside the disabled window");
    }
    // One pixel per container, so no N multiplier.
    if stream.io.values[DP_VID_TIMING as usize] >> 10 & 0x3 != 0 {
        return TestResult::Fail("N multiplier");
    }
    // A stream faster than its link cannot be carried: RBR is 162000 kHz.
    if stream.program_rate(300_000, 6) != Err(Error::Invalid) {
        return TestResult::Fail("stream faster than its link accepted");
    }
    if stream.program_rate(148_500, 0) != Err(Error::Invalid) {
        return TestResult::Fail("zero link rate accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-stream",
    stream_rate_ratio_seeds_the_measurement_below_one
);

fn stream_unblank_resets_the_steering_fifo_first() -> TestResult {
    let mut stream = engine(2);
    // An unprogrammed encoder has no attributes for the sink to read.
    if run(stream.unblank()) != Err(Error::Busy) {
        return TestResult::Fail("unblanked an unprogrammed encoder");
    }
    stream.program(&timing(), Depth::Bpc8).unwrap();
    stream.program_rate(148_500, 20).unwrap();
    stream.io.writes.clear();
    if run(stream.unblank()).is_err() {
        return TestResult::Fail("unblank rejected");
    }
    if stream.state != State::Streaming {
        return TestResult::Fail("state after unblank");
    }
    let cntl = DP_VID_STREAM_CNTL + 2 * STRIDE;
    let fifo = DP_STEER_FIFO + 2 * STRIDE;
    // The stream is stopped, the FIFO reset and released, and only then is the
    // stream enabled: a mode transition's overflow must not persist.
    let stop = stream
        .io
        .writes
        .iter()
        .position(|(r, v)| *r == cntl && v & 1 == 0);
    let reset = stream
        .io
        .writes
        .iter()
        .position(|(r, v)| *r == fifo && v & 1 != 0);
    let release = stream
        .io
        .writes
        .iter()
        .position(|(r, v)| *r == fifo && v & 1 == 0);
    let enable = stream
        .io
        .writes
        .iter()
        .rposition(|(r, v)| *r == cntl && v & 1 != 0);
    if stop.is_none() || reset.is_none() || release.is_none() || enable.is_none() {
        return TestResult::Fail("unblank sequence incomplete");
    }
    if !(stop < reset && reset < release && release < enable) {
        return TestResult::Fail("unblank ordering");
    }
    // Reprogramming a live stream would show corrupt pixels.
    if stream.program(&timing(), Depth::Bpc8) != Err(Error::Busy) {
        return TestResult::Fail("reprogrammed a live stream");
    }
    if run(stream.blank()).is_err() || stream.state != State::Programmed {
        return TestResult::Fail("blank rejected");
    }
    if stream.io.values[cntl as usize] & 1 != 0 {
        return TestResult::Fail("stream left enabled");
    }
    // An encoder that never reports stopped must time out rather than be
    // treated as quiet while it is still sending.
    let mut stuck = engine(2);
    stuck.program(&timing(), Depth::Bpc8).unwrap();
    stuck.io.stuck = true;
    if run(stuck.blank()) != Err(Error::Timeout) {
        return TestResult::Fail("live stream reported as stopped");
    }
    if run(stuck.unblank()) != Err(Error::Timeout) {
        return TestResult::Fail("unblank proceeded over a live stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-stream",
    stream_unblank_resets_the_steering_fifo_first
);

fn stream_rejects_timings_the_attributes_cannot_describe() -> TestResult {
    let mut stream = engine(0);
    for bad in [
        // Front porch plus sync exceeds the whole blank.
        Timing {
            h_front_porch: 250,
            h_sync_width: 44,
            ..timing()
        },
        // Active wider than the line.
        Timing {
            h_active: 2400,
            ..timing()
        },
        // Vertical active plus front porch exceeds the frame.
        Timing {
            v_active: 1124,
            v_front_porch: 4,
            ..timing()
        },
        // Beyond the 15-bit MSA counts.
        Timing {
            h_total: 0x8000,
            ..timing()
        },
    ] {
        if stream.program(&bad, Depth::Bpc8) != Err(Error::Invalid) {
            return TestResult::Fail("undescribable timing accepted");
        }
    }
    // Every supported depth has a distinct wire code and bit count.
    if Depth::Bpc6.code() != 0 || Depth::Bpc8.code() != 1 || Depth::Bpc10.code() != 2 {
        return TestResult::Fail("depth codes");
    }
    if Depth::Bpc6.bits_per_pixel() != 18
        || Depth::Bpc8.bits_per_pixel() != 24
        || Depth::Bpc10.bits_per_pixel() != 30
    {
        return TestResult::Fail("bits per pixel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-stream",
    stream_rejects_timings_the_attributes_cannot_describe
);
