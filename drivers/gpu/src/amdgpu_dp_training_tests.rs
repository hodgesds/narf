use super::*;
use alloc::{collections::VecDeque, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Default)]
struct Fake {
    status: VecDeque<[u8; 6]>,
    writes: Vec<(u32, Vec<u8>)>,
    settings: Vec<Settings>,
    patterns: Vec<u8>,
    levels: Vec<Vec<u8>>,
    delays: Vec<u32>,
    disabled: usize,
}
impl LinkIo for Fake {
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        if address != 0x202 {
            return Err(Error::Aux);
        }
        data.copy_from_slice(&self.status.pop_front().ok_or(Error::Aux)?);
        Ok(())
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        self.writes.push((address, data.to_vec()));
        Ok(())
    }
    async fn configure(&mut self, settings: Settings) -> Result<(), Error> {
        self.settings.push(settings);
        Ok(())
    }
    async fn pattern(&mut self, pattern: u8) -> Result<(), Error> {
        self.patterns.push(pattern);
        Ok(())
    }
    async fn tune(&mut self, lanes: &[u8]) -> Result<(), Error> {
        self.levels.push(lanes.to_vec());
        Ok(())
    }
    async fn disable(&mut self) -> Result<(), Error> {
        self.disabled += 1;
        Ok(())
    }
    async fn delay_us(&mut self, us: u32) {
        self.delays.push(us);
    }
}
fn limits() -> Limits {
    Limits {
        rate: 20,
        lanes: 4,
        pixel_clock_khz: 148500,
        bits_per_pixel: 24,
        dpia: false,
    }
}
fn caps() -> [u8; 16] {
    let mut caps = [0; 16];
    caps[0] = 0x12;
    caps[1] = 20;
    caps[2] = 0xc4;
    caps
}
fn train_fake(io: &mut Fake, limits: Limits) -> Result<Settings, Error> {
    narf_scheduler::block_on_spin(train(io, caps(), limits))
}
fn dp_async_source_sink_training_and_adjustment() -> TestResult {
    let mut io = Fake::default();
    io.status.extend([
        [0, 0, 0, 0, 0x95, 0],
        [0x11, 0x11, 0, 0, 0, 0],
        [0x77, 0x77, 1, 0, 0, 0],
    ]);
    if train_fake(&mut io, limits())
        != Ok(Settings {
            rate: 20,
            lanes: 4,
            enhanced: true,
        })
    {
        return TestResult::Fail("training failed");
    }
    if io.patterns != [1, 3, 0]
        || io.levels[1] != [0x31; 4]
        || io.writes.last() != Some(&(0x102, alloc::vec![0]))
    {
        return TestResult::Fail("source/sink pattern or common lane adjustment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-training",
    dp_async_source_sink_training_and_adjustment
);
fn dp_async_fallback_disables_source_and_keeps_bandwidth() -> TestResult {
    let mut io = Fake::default();
    io.status.extend([
        [0, 0, 0, 0, 0x33, 0x33],
        [0, 0, 0, 0, 0x33, 0x33],
        [0x11, 0x11, 0, 0, 0, 0],
        [0x77, 0x77, 1, 0, 0, 0],
    ]);
    if train_fake(&mut io, limits())
        != Ok(Settings {
            rate: 10,
            lanes: 4,
            enhanced: true,
        })
        || io.disabled != 1
    {
        return TestResult::Fail("rate fallback without source teardown");
    }
    let mut io = Fake::default();
    let mut over = limits();
    over.pixel_clock_khz = 2_000_000;
    if train_fake(&mut io, over) != Err(Error::Bandwidth) || !io.settings.is_empty() {
        return TestResult::Fail("unfittable mode programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-training",
    dp_async_fallback_disables_source_and_keeps_bandwidth
);
fn dp_async_requires_alignment_and_cleans_aux_failure() -> TestResult {
    let mut io = Fake::default();
    io.status.push_back([0x11, 0x11, 0, 0, 0, 0]);
    io.status.extend([[0x77, 0x77, 0, 0, 0, 0]; 6]);
    // EQ fails without interlane alignment, then fallback sees an AUX failure.
    if train_fake(&mut io, limits()) != Err(Error::Aux)
        || io.disabled != 2
        || io.patterns.last() == Some(&0)
    {
        return TestResult::Fail("missing alignment accepted or failed source retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-training",
    dp_async_requires_alignment_and_cleans_aux_failure
);
fn dp_async_dpia_transparent_does_not_drive_native_phy() -> TestResult {
    let mut io = Fake::default();
    io.status
        .extend([[0x11, 0x11, 0, 0, 0, 0], [0x77, 0x77, 1, 0, 0, 0]]);
    let mut tunnel = limits();
    tunnel.dpia = true;
    tunnel.rate = 6;
    if train_fake(&mut io, tunnel).is_err()
        || !io.levels.is_empty()
        || io.patterns != [0]
        || io.writes.iter().any(|(address, _)| *address == 0x103)
    {
        return TestResult::Fail("DPIA training drove local voltage settings");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-training",
    dp_async_dpia_transparent_does_not_drive_native_phy
);
