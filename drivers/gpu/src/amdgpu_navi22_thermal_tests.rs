use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn iv(client: u8, src: u8, context: u32) -> Iv {
    let mut dw = [0u32; 8];
    dw[0] = u32::from(client) | u32::from(src) << 8;
    dw[4] = context;
    Iv::decode(dw)
}
fn limits(shutdown_c: u16) -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 100_000,
        mem_emergency_milli: 105_000,
        software_shutdown_c: shutdown_c,
        fan_max_rpm: Some(3300),
        ppt_table_w: 203,
        thermal_controller: 0x13,
        dc_by_gpio: false,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Effect {
    Delay(u64),
    Hotspot,
    Ack,
    Acdc,
    PowerOff(Shutdown),
}
struct Model {
    hotspot: Option<i32>,
    limits: Option<Limits>,
    ack: Result<(), smu::Error>,
    effects: Vec<Effect>,
}
impl Platform for Model {
    async fn hotspot(&mut self) -> Option<i32> {
        self.effects.push(Effect::Hotspot);
        self.hotspot
    }
    fn limits(&self) -> Option<Limits> {
        self.limits
    }
    fn ack(&mut self) -> Result<(), smu::Error> {
        self.effects.push(Effect::Ack);
        self.ack
    }
    async fn reenable_acdc(&mut self) -> Result<(), smu::Error> {
        self.effects.push(Effect::Acdc);
        Ok(())
    }
    async fn delay_ms(&mut self, ms: u64) {
        self.effects.push(Effect::Delay(ms));
    }
    fn power_off(&mut self, reason: Shutdown) {
        self.effects.push(Effect::PowerOff(reason));
    }
}
fn model(hotspot: Option<i32>, limits: Option<Limits>) -> Model {
    Model {
        hotspot,
        limits,
        ack: Ok(()),
        effects: Vec::new(),
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn navi22_thermal_sources_match_smu_v11_0_register_irq_handler() -> TestResult {
    let ids: Vec<(u8, u8)> = SOURCES.iter().map(|s| (s.client, s.src)).collect();
    if ids != [(0x0f, 0), (0x0f, 1), (0x16, 83), (0x1f, 0xfe)] {
        return TestResult::Fail("THM L2H/H2L, SMUIO GPIO19, MP1 0xfe");
    }
    for (iv, action) in [
        (iv(0x0f, 0, 0), Action::ConfirmSoftwareCtf),
        (iv(0x0f, 1, 0), Action::UnderTemperature),
        (iv(0x0f, 9, 0), Action::UnknownThermal(9)),
        (iv(0x16, 83, 0), Action::PowerOff(Shutdown::HardwareCtf)),
        (iv(0x1f, 0xfe, 7), Action::SmuToDriver(7)),
        (iv(0x1f, 0x10, 7), Action::Ignore),
        (iv(0x14, 181, 0), Action::Ignore),
    ] {
        if classify(&iv) != action {
            return TestResult::Fail("IV classification");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-thermal",
    navi22_thermal_sources_match_smu_v11_0_register_irq_handler
);

fn navi22_thermal_escalates_exactly_as_linux() -> TestResult {
    // Hardware CTF: immediate power-off, no delay or telemetry.
    let mut m = model(Some(40_000), Some(limits(118)));
    run(handle(&mut m, &iv(0x16, 83, 0)));
    if m.effects != vec![Effect::PowerOff(Shutdown::HardwareCtf)] {
        return TestResult::Fail("HW CTF must power off at once");
    }
    // L2H with a cool hotspot after the delay: nothing.
    let mut m = model(Some(117_999), Some(limits(118)));
    run(handle(&mut m, &iv(0x0f, 0, 0)));
    if m.effects != vec![Effect::Delay(SWCTF_DELAY_MS), Effect::Hotspot] {
        return TestResult::Fail("transient L2H escalated");
    }
    // L2H confirmed at the limit.
    let mut m = model(Some(118_000), Some(limits(118)));
    run(handle(&mut m, &iv(0x0f, 0, 0)));
    if m.effects.last()
        != Some(&Effect::PowerOff(Shutdown::SoftwareCtf {
            hotspot_milli: Some(118_000),
        }))
    {
        return TestResult::Fail("SW CTF not escalated");
    }
    // Unreadable hotspot, no board limit, or no limits at all: escalate.
    for (hotspot, limits) in [
        (None, Some(limits(118))),
        (Some(20_000), Some(limits(0))),
        (Some(20_000), None),
    ] {
        let mut m = model(hotspot, limits);
        run(handle(&mut m, &iv(0x0f, 0, 0)));
        if !matches!(
            m.effects.last(),
            Some(Effect::PowerOff(Shutdown::SoftwareCtf { .. }))
        ) {
            return TestResult::Fail("smu_swctf_delayed_work_handler fallback");
        }
    }
    // H2L only logs.
    let mut m = model(Some(20_000), Some(limits(118)));
    run(handle(&mut m, &iv(0x0f, 1, 0)));
    if !m.effects.is_empty() {
        return TestResult::Fail("H2L had effects");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-thermal",
    navi22_thermal_escalates_exactly_as_linux
);

fn navi22_smu_to_driver_acks_before_context_handling() -> TestResult {
    let before = status();
    let mut m = model(None, Some(limits(118)));
    run(handle(&mut m, &iv(0x1f, 0xfe, CONTEXT_THERMAL_THROTTLING)));
    if m.effects != vec![Effect::Ack] || status().throttling != before.throttling + 1 {
        return TestResult::Fail("throttling context");
    }
    let mut m = model(None, Some(limits(118)));
    run(handle(&mut m, &iv(0x1f, 0xfe, CONTEXT_DC)));
    if m.effects != vec![Effect::Ack, Effect::Acdc] || status().ac != Some(false) {
        return TestResult::Fail("DC context must ack then re-arm AC/DC");
    }
    let mut m = model(None, Some(limits(118)));
    m.ack = Err(smu::Error::DeviceGone);
    run(handle(&mut m, &iv(0x1f, 0xfe, 0x2)));
    if m.effects != vec![Effect::Ack] || status().last_error != Some(smu::Error::DeviceGone) {
        return TestResult::Fail("unknown context / failed ack");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-thermal",
    navi22_smu_to_driver_acks_before_context_handling
);
