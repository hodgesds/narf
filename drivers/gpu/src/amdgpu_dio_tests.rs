use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register file for one DIO bank. `stuck` models a register that ignores
/// writes, so a failed read-back is distinguishable from a successful update.
struct Regs {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    stuck: Option<u64>,
}
impl Regs {
    fn new() -> Self {
        Self {
            values: vec![0; 0x2600],
            writes: Vec::new(),
            stuck: None,
        }
    }
}
impl Io for Regs {
    fn read(&mut self, reg: u64) -> u32 {
        self.values[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        if self.stuck != Some(reg) {
            self.values[reg as usize] = value;
        }
    }
}
#[derive(Default)]
struct Fw {
    commands: Vec<[u8; 64]>,
    status: VecDeque<[u8; 6]>,
    sink: Vec<(u32, Vec<u8>)>,
    typec: Option<(bool, bool, bool)>,
    defers: usize,
    fail_aux: bool,
}
impl Phy for Fw {
    async fn command(&mut self, command: [u8; 64]) -> Result<(), Error> {
        self.commands.push(command);
        Ok(())
    }
    async fn typec(&mut self, _: u8) -> Result<(bool, bool, bool), Error> {
        Ok(self.typec.unwrap_or((false, false, false)))
    }
    async fn aux(
        &mut self,
        _: Channel,
        _: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), AuxError> {
        if self.fail_aux {
            return Err(AuxError::Failed);
        }
        if self.defers > 0 {
            self.defers -= 1;
            return Err(AuxError::Defer);
        }
        if action == 0x90 {
            if address != 0x202 {
                return Err(AuxError::Failed);
            }
            data.copy_from_slice(&self.status.pop_front().ok_or(AuxError::Failed)?);
        } else {
            self.sink.push((address, data.to_vec()));
        }
        Ok(())
    }
}
fn route() -> Route {
    Route {
        channel: Channel::Legacy,
        aux: 2,
        backend: 1,
        frontend: 2,
        hpd: 3,
    }
}
fn encoder(route: Route) -> Encoder<Regs> {
    Encoder {
        io: Regs::new(),
        cap: Cap::bootstrap(),
        route,
        state: State::Disabled,
        settings: None,
    }
}
fn settings() -> Settings {
    Settings {
        rate: 20,
        lanes: 2,
        enhanced: true,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn dio_phy_command_payload_and_route_validation() -> TestResult {
    let native = phy_command(route(), settings(), 1, 0);
    if native[0] != 128
        || native[1] != 1
        || native[3] != 60
        || native[4] != 1
        || native[5] != 1
        || native[6] != 0
        || native[7] != 2
        || native[8..12] != 54000u32.to_le_bytes()
        || native[12] != 3
        || native[13] != 1 << 2
        || native[14] != 0x13
        || native[15..].iter().any(|b| *b != 0)
    {
        return TestResult::Fail("native DIG PHY payload");
    }
    // A drive-level request carries its level; other actions must not.
    if phy_command(route(), settings(), 11, 5)[6] != 5
        || phy_command(route(), settings(), 0, 5)[6] != 0
    {
        return TestResult::Fail("PHY drive level leaked into other actions");
    }
    let mut tunnel = route();
    tunnel.channel = Channel::Dpia;
    let dpia = phy_command(tunnel, settings(), 1, 0);
    if dpia[0] != 77 || dpia[1] != 0 || dpia[3] != 16 || dpia[14] != 2 {
        return TestResult::Fail("DPIA payload used a native transmitter descriptor");
    }
    if !valid(route()) || !valid(tunnel) {
        return TestResult::Fail("valid route rejected");
    }
    // A DPIA has four instances; native AUX has six. Neither accepts a
    // UCSI connector number beyond its own range.
    for bad in [
        Route {
            backend: 5,
            ..route()
        },
        Route {
            frontend: 5,
            ..route()
        },
        Route { hpd: 7, ..route() },
        Route { aux: 6, ..route() },
        Route { aux: 4, ..tunnel },
    ] {
        if valid(bad) {
            return TestResult::Fail("out-of-range route accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_phy_command_payload_and_route_validation
);

fn dio_update_targets_owned_backend_and_verifies_readback() -> TestResult {
    let mut source = encoder(route());
    // Every access is offset by the owned backend, never backend zero.
    if source.update(0x2108, 0x10, 0x10).is_err() {
        return TestResult::Fail("update rejected");
    }
    if source.io.writes != [(0x2208, 0x10)] {
        return TestResult::Fail("update ignored the backend stride");
    }
    if source.read(0x2108) != Ok(0x10) {
        return TestResult::Fail("read ignored the backend stride");
    }
    // An all-ones read is a vanished device, not a programmed value.
    source.io.values[0x2208] = u32::MAX;
    if source.update(0x2108, 0x10, 0).is_ok() {
        return TestResult::Fail("update accepted a vanished device");
    }
    source.io.values[0x2208] = 0;
    source.io.stuck = Some(0x2208);
    if source.update(0x2108, 0x10, 0x10).is_ok() {
        return TestResult::Fail("update accepted an unverified write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_update_targets_owned_backend_and_verifies_readback
);

fn dio_pattern_programs_training_and_video_paths() -> TestResult {
    let mut source = encoder(route());
    for (pattern, index) in [(1u8, 0u32), (2, 1), (3, 2), (7, 3)] {
        source.io.writes.clear();
        if source.pattern(pattern).is_err() {
            return TestResult::Fail("training pattern rejected");
        }
        if source.io.values[0x2218] & 3 != index || source.io.values[0x2208] & 0x10 != 0 {
            return TestResult::Fail("training pattern index or video enable");
        }
    }
    if source.pattern(4).is_ok() || source.pattern(0).is_ok() {
        return TestResult::Fail("unsupported pattern or video without settings accepted");
    }
    source.settings = Some(settings());
    if source.pattern(0).is_err() {
        return TestResult::Fail("video pattern rejected");
    }
    // Ordinary DP, enhanced framing from the negotiated settings, video on.
    if source.io.values[0x220f] != 0
        || source.io.values[0x2213] & 0x1103ffff != 0x2000 | 1 << 28
        || source.io.values[0x221e] & 0x3ff00 != 0x1ff00
        || source.io.values[0x2208] & 0x10 != 0x10
    {
        return TestResult::Fail("video path framing or enable");
    }
    let mut plain = encoder(route());
    plain.settings = Some(Settings {
        enhanced: false,
        ..settings()
    });
    if plain.pattern(0).is_err() || plain.io.values[0x2213] & 1 << 28 != 0 {
        return TestResult::Fail("enhanced framing programmed for a plain sink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_pattern_programs_training_and_video_paths
);

fn dio_configure_requires_phy_enable_acknowledgement() -> TestResult {
    let mut source = encoder(route());
    let mut fw = Fw::default();
    // Firmware has not brought the transmitter up: refuse to claim a link.
    if run(Adapter {
        source: &mut source,
        phy: &mut fw,
    }
    .configure(settings()))
    .is_ok()
    {
        return TestResult::Fail("configure accepted a disabled transmitter");
    }
    let mut source = encoder(route());
    source.io.values[0x21b2] = 1;
    let mut fw = Fw::default();
    if run(Adapter {
        source: &mut source,
        phy: &mut fw,
    }
    .configure(settings()))
    .is_err()
    {
        return TestResult::Fail("configure rejected an enabled transmitter");
    }
    if source.io.values[0x21b1] & 0x77f00 != 1 << 2 << 8
        || source.io.values[0x220b] & 3 != 1
        || source.io.values[0x221e] & 0x10 != 0x10
        || source.io.values[0x2217] & 0x30 != 0
    {
        return TestResult::Fail("frontend mux, lane count or FEC state");
    }
    if fw.commands.len() != 1 || fw.commands[0][5] != 1 {
        return TestResult::Fail("transmitter enable command");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_configure_requires_phy_enable_acknowledgement
);

fn dio_disable_detaches_frontend_only_when_phy_is_off() -> TestResult {
    let mut source = encoder(route());
    source.settings = Some(settings());
    source.state = State::Trained;
    source.io.values[0x21b1] = 0x7f00;
    source.io.values[0x21b2] = 1;
    let mut fw = Fw::default();
    // The PHY never went down: keep the frontend attached and stay failed.
    if run(source.disable(&mut fw)).is_ok()
        || source.io.values[0x21b1] != 0x7f00
        || source.state() != State::Failed
    {
        return TestResult::Fail("frontend detached while the PHY was live");
    }
    if fw.commands.len() != 1 || fw.commands[0][5] != 0 {
        return TestResult::Fail("PHY disable command");
    }
    source.io.values[0x21b2] = 0;
    if run(source.disable(&mut fw)).is_err()
        || source.io.values[0x21b1] & 0x7f00 != 0
        || source.state() != State::Disabled
        || source.settings.is_some()
    {
        return TestResult::Fail("disabled source retained its frontend or settings");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_disable_detaches_frontend_only_when_phy_is_off
);

fn dio_train_clamps_type_c_lanes_and_retries_deferred_aux() -> TestResult {
    let mut source = encoder(route());
    source.io.values[0x21b2] = 1;
    let mut fw = Fw {
        typec: Some((true, false, false)),
        defers: 3,
        ..Default::default()
    };
    fw.status
        .extend([[0x11, 0x11, 0, 0, 0, 0], [0x77, 0x77, 1, 0, 0, 0]]);
    let mut limits = Limits {
        rate: 20,
        lanes: 4,
        pixel_clock_khz: 148500,
        bits_per_pixel: 24,
        dpia: false,
    };
    let mut caps = [0; 16];
    caps[0] = 0x12;
    caps[1] = 20;
    caps[2] = 0xc4;
    caps[3] = 0;
    // A two-lane Type-C pin assignment must cap the link, not the sink's four.
    let trained = run(source.train(&mut fw, caps, limits));
    if trained
        != Ok(Settings {
            rate: 20,
            lanes: 2,
            enhanced: true,
        })
    {
        return TestResult::Fail("Type-C lane clamp or training result");
    }
    if source.state() != State::Trained || source.io.values[0x220b] & 3 != 1 {
        return TestResult::Fail("trained state or programmed lane count");
    }
    if !fw.sink.iter().any(|(a, d)| *a == 0x100 && d[1] == 2 | 0x80) {
        return TestResult::Fail("sink lane count/enhanced framing");
    }
    // Retraining an already-trained source needs an explicit disable first.
    if run(source.train(&mut fw, caps, limits)).is_ok() {
        return TestResult::Fail("retrained a live source");
    }
    // A disabled Type-C PHY carries no link at all. Nothing was programmed,
    // so the source stays reusable for a later plug instead of failing.
    let mut source = encoder(route());
    source.io.values[0x21b2] = 1;
    let mut off = Fw {
        typec: Some((true, true, false)),
        ..Default::default()
    };
    limits.lanes = 2;
    if run(source.train(&mut off, caps, limits)).is_ok()
        || source.state() != State::Disabled
        || !source.io.writes.is_empty()
        || !off.commands.is_empty()
    {
        return TestResult::Fail("trained over a disabled Type-C PHY");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dio",
    dio_train_clamps_type_c_lanes_and_retries_deferred_aux
);
