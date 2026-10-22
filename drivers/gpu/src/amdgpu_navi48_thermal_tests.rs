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
fn navi48_thermal_irq_arm_ack_and_fan_limits_match_smu14() -> TestResult {
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
    assert!(e.handle(event(src::CLIENT_THM, 0, 0)).unwrap());
    assert!(!e.handle(event(src::CLIENT_THM, 1, 0)).unwrap());
    assert!(!e
        .handle(event(src::CLIENT_MP1, 0xfd, FAN_ABNORMAL))
        .unwrap());
    assert_eq!(e.io.writes.len(), writes); // THM is not heuristically acknowledged.
    e.handle(event(src::CLIENT_MP1, SMU_TO_DRIVER, FAN_ABNORMAL))
        .unwrap();
    assert_eq!(e.io.regs[&mp], 0x8000_0100);
    assert_eq!(e.io.regs[&ctrl] & (0xff | TRIGGER_MASK), 108);
    assert!(e.status.fan_abnormal);
    e.handle(event(src::CLIENT_MP1, SMU_TO_DRIVER, FAN_RECOVERY))
        .unwrap();
    assert_eq!(e.status.high_c, 118);
    assert!(!e.status.fan_abnormal);
    assert_eq!((e.status.high, e.status.low, e.status.smu), (1, 1, 2));
    e.stop().unwrap();
    assert_eq!(e.status.state, State::Stopped);
    assert_eq!(
        e.io.regs[&ctrl] & (INTH_MASK | INTL_MASK),
        INTH_MASK | INTL_MASK
    );
    assert_eq!(e.io.regs[&mp] & MP_MASK, MP_MASK);
    let writes = e.io.writes.len();
    assert!(!e
        .handle(event(src::CLIENT_MP1, SMU_TO_DRIVER, FAN_ABNORMAL))
        .unwrap());
    assert_eq!(e.io.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_thermal_irq_arm_ack_and_fan_limits_match_smu14
);
fn navi48_thermal_irq_failures_never_rearm_or_ack_foreign_sources() -> TestResult {
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
        e.handle(event(src::CLIENT_MP1, SMU_TO_DRIVER, FAN_RECOVERY)),
        Err(Error::DeviceGone)
    );
    assert_eq!(e.io.writes.len(), writes);
    assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_thermal_irq_failures_never_rearm_or_ack_foreign_sources
);
fn rdna4_thermal_irq_layout_is_discovery_bound_and_optional_without_limits() -> TestResult {
    use crate::amdgpu_rdna4::tests::Profile;
    let mut words = alloc::vec![0; 0x80000 / 4];
    let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    gpu.regs.virt = words.as_mut_ptr() as u64;
    gpu.regs.len = (words.len() * 4) as u64;
    let mut bases = [0; ip::MAX_BASE_ADDRS];
    bases[0] = 0x7000;
    gpu.ip_blocks.push(ip::IpBlock {
        hw_id: ip::HW_ID_THM,
        instance: 0,
        major: 14,
        minor: 0,
        revision: 2,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 1,
    });
    for profile in Profile::ALL {
        profile.apply(&mut gpu);
        let before = words.clone();
        let monitor = Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).unwrap();
        assert_eq!(monitor.0.layout.thm, 0x7000 * 4);
        assert_eq!(monitor.status().state, State::Prepared);
        assert_eq!(words, before);
    }
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
    gpu.ip_blocks.last_mut().unwrap().base_addrs[0] = 0x80000 / 4;
    assert!(Monitor::new(&gpu, Cap::bootstrap(), Some(limits())).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    rdna4_thermal_irq_layout_is_discovery_bound_and_optional_without_limits
);
