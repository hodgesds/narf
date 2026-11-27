use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Default)]
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    gone: bool,
    refuse: Option<u64>,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.gone {
            u32::MAX
        } else {
            *self.regs.get(&at).unwrap_or(&0)
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        self.writes.push((at, v));
        if self.refuse != Some(at) {
            self.regs.insert(at, v);
        }
    }
}
const L: Layout = Layout {
    thm: 0x100,
    mp: 0x1000,
};
fn limits() -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 108_000,
        mem_emergency_milli: 113_000,
        software_shutdown_c: 118,
        software_shutdown_offset_c: -10,
        fan_max_rpm: Some(3000),
        ppt_default_w: 300,
        ppt_min_w: 200,
        ppt_max_w: 340,
    }
}
fn engine() -> Engine<Fake> {
    Engine::new(Fake::default(), Cap::bootstrap(), L, limits())
}
fn event(client: u8, source: u8, context: u32) -> ih::Event {
    ih::Event {
        ih_ring: 0,
        vector: ih::Vector::decode([
            u32::from(client) | u32::from(source) << 8,
            0,
            0,
            0,
            context,
            0,
            0,
            0,
        ]),
    }
}
fn navi31_thermal_irq_arm_ack_and_fan_limits_match_smu130() -> TestResult {
    let mut e = engine();
    let ctrl = L.thm + u64::from(THERM_CTRL) * 4;
    let mp = L.mp + u64::from(MP_CTRL) * 4;
    e.io.regs.insert(ctrl, 0x0fff_ffff);
    e.io.regs.insert(mp, 0x8000_0001);
    e.arm().unwrap();
    assert_eq!(e.io.regs[&ctrl], 0xb8ff_0076);
    assert_eq!(e.io.regs[&(L.thm + u64::from(THERM_ENA) * 4)], CLEAR);
    assert_eq!(e.io.regs[&(L.mp + u64::from(MP_INT) * 4)] & 0x1ff, 0xfe);
    assert_eq!(e.io.regs[&mp], 0x8000_0000);
    let writes = e.io.writes.len();
    assert_eq!(e.handle(event(CLIENT_THM, 0, 0)).unwrap(), Outcome::SwCtf);
    assert_eq!(e.handle(event(CLIENT_THM, 1, 0)).unwrap(), Outcome::Ignored);
    // A foreign MP1 source is not acknowledged.
    assert_eq!(
        e.handle(event(CLIENT_MP1, 0xfd, FAN_ABNORMAL)).unwrap(),
        Outcome::Ignored
    );
    assert_eq!(e.io.writes.len(), writes);
    // The GPIO19 hardware CTF is classified, never acknowledged here.
    assert_eq!(
        e.handle(event(CLIENT_ROM_SMUIO, 83, 0)).unwrap(),
        Outcome::HwCtf
    );
    assert_eq!(
        e.handle(event(CLIENT_ROM_SMUIO, 0, 0)).unwrap(),
        Outcome::Ignored
    );
    assert_eq!(e.io.writes.len(), writes);
    e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, FAN_ABNORMAL))
        .unwrap();
    assert_eq!(e.io.regs[&mp], 0x8000_0100);
    assert_eq!(e.io.regs[&ctrl] & (0xff | TRIGGER_MASK), 108);
    assert!(e.status.fan_abnormal);
    e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, FAN_RECOVERY))
        .unwrap();
    assert_eq!(e.status.high_c, 118);
    assert!(!e.status.fan_abnormal);
    // AC/DC/throttling contexts only count.
    e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, 0x3)).unwrap();
    e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, 0x7)).unwrap();
    assert_eq!(
        (e.status.high, e.status.low, e.status.smu, e.status.hw_ctf),
        (1, 1, 4, 1)
    );
    e.stop().unwrap();
    assert_eq!(e.status.state, State::Stopped);
    assert_eq!(
        e.io.regs[&ctrl] & (INTH_MASK | INTL_MASK),
        INTH_MASK | INTL_MASK
    );
    assert_eq!(e.io.regs[&mp] & MP_MASK, MP_MASK);
    let writes = e.io.writes.len();
    assert_eq!(
        e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, FAN_ABNORMAL))
            .unwrap(),
        Outcome::Ignored
    );
    assert_eq!(e.io.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_thermal_irq_arm_ack_and_fan_limits_match_smu130
);
fn navi31_thermal_irq_failures_never_rearm_or_ack_foreign_sources() -> TestResult {
    let mut e = engine();
    e.authority.revoke();
    assert_eq!(e.arm(), Err(Error::Revoked));
    assert!(e.io.writes.is_empty());
    assert_eq!(e.arm(), Err(Error::Busy));
    let mut e = engine();
    e.io.gone = true;
    assert_eq!(e.arm(), Err(Error::DeviceGone));
    assert!(e.io.writes.is_empty());
    let mut e = engine();
    e.io.refuse = Some(L.thm + u64::from(THERM_CTRL) * 4);
    assert_eq!(e.arm(), Err(Error::Readback));
    assert_eq!(e.io.writes.len(), 1);
    let mut e = engine();
    e.arm().unwrap();
    e.io.gone = true;
    let writes = e.io.writes.len();
    assert_eq!(
        e.handle(event(CLIENT_MP1, SMU_TO_DRIVER, FAN_RECOVERY)),
        Err(Error::DeviceGone)
    );
    assert_eq!(e.io.writes.len(), writes);
    assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_thermal_irq_failures_never_rearm_or_ack_foreign_sources
);
fn navi31_thermal_fan_sequences_match_smu130() -> TestResult {
    // Fixture register values must never be u32::MAX: checked() reads it as DeviceGone.
    let mut e = engine();
    let ctrl1 = L.thm + u64::from(FDO_CTRL1) * 4;
    let ctrl0 = L.thm + u64::from(FDO_CTRL0) * 4;
    let ctrl2 = L.thm + u64::from(FDO_CTRL2) * 4;
    let tach = L.thm + u64::from(TACH_CTRL) * 4;
    e.io.regs.insert(ctrl1, 200); // FMAX_DUTY100
    e.io.regs.insert(ctrl2, 0x0000_ffff);
    // duty = speed * duty100 / 255.
    assert_eq!(e.set_fan_pwm(255).unwrap(), 200);
    assert_eq!(e.io.regs[&ctrl0] & 0xff, 200);
    assert_eq!(e.set_fan_pwm(128).unwrap(), 100);
    assert_eq!(e.io.regs[&ctrl0] & 0xff, 100);
    // Static mode: TMIN zeroed first, then FDO_PWM_MODE = STATIC (1).
    assert_eq!(e.io.regs[&ctrl2] & 0xff, 0);
    assert_eq!((e.io.regs[&ctrl2] >> 11) & 0x7, 1);
    // tach_period = 60 * 2500 * 10000 / (8 * 3000) = 62500.
    assert_eq!(e.set_fan_rpm(3000).unwrap(), 62_500);
    assert_eq!(e.io.regs[&tach], 62_500 << 3);
    assert_eq!((e.io.regs[&ctrl2] >> 11) & 0x7, 5);
    assert_eq!(fan_duty(255, 100), 100);
    assert_eq!(fan_duty(0, 100), 0);
    assert_eq!(tach_period(0), None);
    assert_eq!(tach_period(u32::MAX), None);
    assert_eq!(e.set_fan_rpm(0), Err(Error::Invalid));
    assert_eq!(e.set_static_mode(0), Err(Error::Invalid));
    // A board with no fan table cannot scale a duty.
    let mut e = engine();
    e.io.regs.insert(ctrl1, 0);
    assert_eq!(e.set_fan_pwm(255), Err(Error::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_thermal_fan_sequences_match_smu130
);
fn navi31_thermal_irq_layout_is_discovery_bound_and_version_pinned() -> TestResult {
    let mut words = alloc::vec![0; 0x80000 / 4];
    let mut gpu = crate::amdgpu_gfx_navi22::tests::gpu();
    gpu.regs.virt = words.as_mut_ptr() as u64;
    gpu.regs.len = (words.len() * 4) as u64;
    let mut bases = [0; ip::MAX_BASE_ADDRS];
    bases[0] = 0x7000;
    gpu.ip_blocks.push(ip::IpBlock {
        hw_id: ip::HW_ID_THM,
        instance: 0,
        major: 13,
        minor: 0,
        revision: 2,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 1,
    });
    let mp1 = gpu
        .ip_blocks
        .iter_mut()
        .find(|b| b.hw_id == ip::HW_ID_MP1)
        .unwrap();
    (mp1.major, mp1.minor, mp1.revision) = (13, 0, 0);
    mp1.base_addrs[0] = 0x8000;
    let before = words.clone();
    let monitor = Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).unwrap();
    assert_eq!(monitor.0.layout.thm, 0x7000 * 4);
    assert_eq!(monitor.0.layout.mp, 0x8000 * 4);
    assert_eq!(monitor.status().state, State::Prepared);
    assert_eq!(words, before);
    assert!(Monitor::new(&gpu, Cap::bootstrap(), None).is_none());
    assert!(Monitor::new(
        &gpu,
        Cap::bootstrap(),
        Some(Limits {
            software_shutdown_c: 0,
            ..limits()
        })
    )
    .is_none());
    // THM 13.0.3 does not exist; MP1 13.0.4 is the APU's, not Navi31's.
    // Neither resolves, and neither falls back to the other bank's version.
    gpu.ip_blocks.last_mut().unwrap().revision = 3;
    assert!(Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).is_none());
    gpu.ip_blocks.last_mut().unwrap().revision = 2;
    let mp1 = gpu
        .ip_blocks
        .iter_mut()
        .find(|b| b.hw_id == ip::HW_ID_MP1)
        .unwrap();
    mp1.revision = 4;
    assert!(Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).is_none());
    gpu.ip_blocks
        .iter_mut()
        .find(|b| b.hw_id == ip::HW_ID_MP1)
        .unwrap()
        .revision = 0;
    gpu.ip_blocks
        .iter_mut()
        .find(|b| b.hw_id == ip::HW_ID_MP1)
        .unwrap()
        .base_addrs[0] = 0x80000 / 4;
    assert!(Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_thermal_irq_layout_is_discovery_bound_and_version_pinned
);
