use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");

#[derive(Default)]
struct Io {
    seed: u32,
    registers: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    stopped_at: Option<usize>,
    absent: Option<u64>,
}
impl RegisterIo for Io {
    fn authorized(&self) -> bool {
        self.stopped_at.is_none_or(|at| self.writes.len() < at)
    }
    fn read32(&mut self, register: u64) -> u32 {
        if !self.authorized() || self.absent == Some(register) {
            return u32::MAX;
        }
        self.registers.get(&register).copied().unwrap_or({
            if self.seed == 0 {
                0
            } else {
                self.seed ^ register as u32
            }
        })
    }
    fn write32(&mut self, register: u64, value: u32) {
        if self.authorized() {
            self.registers.insert(register, value);
            self.writes.push((register, value));
        }
    }
    fn delay_us(&mut self, _: u64) {
        panic!("channel preparation must not invent settling waits")
    }
}
fn image(spur: u16) -> [u8; EEPROM_4K_BYTES] {
    let mut image = [0; EEPROM_4K_BYTES];
    for entry in image[SPUR_OFFSET..120].chunks_exact_mut(4) {
        entry[..2].copy_from_slice(&0x8000u16.to_le_bytes());
    }
    image[SPUR_OFFSET..SPUR_OFFSET + 2].copy_from_slice(&spur.to_le_bytes());
    image
}
fn smoke_ath9k_channel_preparation_matches_complete_linux_traces() -> TestResult {
    if SPUR_OFFSET != 100 || CHANNEL_CASES.len() != 48 {
        return TestResult::Fail("independent packed EEPROM/channel oracle geometry changed");
    }
    for &(frequency, spur, seed, count, expected) in CHANNEL_CASES {
        let mut io = Io {
            seed,
            ..Default::default()
        };
        if prepare(&mut io, &image(spur), frequency).is_err() {
            return TestResult::Fail("native legacy20 channel preparation refused Linux case");
        }
        let mut hash = 0xcbf29ce484222325u64;
        for &(register, value) in &io.writes {
            for byte in (register as u32)
                .to_le_bytes()
                .into_iter()
                .chain(value.to_le_bytes())
            {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
            }
            if register + 4 > super::super::REQUIRED_BAR
                || matches!(register, 0x8 | 0x24 | 0x840 | 0x981c)
            {
                return TestResult::Fail(
                    "channel preparation escaped BAR or activated PHY/packet engines",
                );
            }
        }
        if io.writes.len() != count as usize || hash != expected {
            return TestResult::Fail(
                "channel mode/synth/slope/spur writes differ from original Linux C",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_channel_preparation_matches_complete_linux_traces
);

fn smoke_ath9k_channel_refusal_and_authority_loss_stop_publication() -> TestResult {
    for frequency in [0, 2411, 2413, 2473, 2484, 5180, u16::MAX] {
        let mut io = Io::default();
        if prepare(&mut io, &image(1120), frequency) != Err(BringUpError::BadCalibration)
            || !io.writes.is_empty()
        {
            return TestResult::Fail("unsupported channel wrote native registers");
        }
    }
    for stopped_at in 0..45 {
        let mut io = Io {
            stopped_at: Some(stopped_at),
            ..Default::default()
        };
        if prepare(&mut io, &image(1120), 2412) != Err(BringUpError::DeviceGone)
            || io.writes.len() != stopped_at
        {
            return TestResult::Fail("channel preparation continued after lost authority");
        }
    }
    for absent in [
        0x8048, 0x8344, 0x9804, 0xa204, 0x9874, 0x9814, 0x99d0, 0xa22c, 0x9920,
    ] {
        let mut io = Io {
            absent: Some(absent),
            ..Default::default()
        };
        if prepare(&mut io, &image(1120), 2412) != Err(BringUpError::DeviceGone) {
            return TestResult::Fail("absent channel register was treated as live hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_channel_refusal_and_authority_loss_stop_publication
);

fn smoke_ath9k_channel_native_revocation_precedes_invalid_mmio() -> TestResult {
    use narf_bus::{BarKind, BusDeviceCap, MmioRegion};
    use narf_capabilities::{Cap, Write};
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: super::super::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut registers = crate::ath9k::identity::Registers::new(region, cap);
    cap.revoke();
    if prepare(&mut registers, &image(1120), 2412) != Err(BringUpError::DeviceGone) {
        return TestResult::Fail("revoked native channel owner reached MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_channel_native_revocation_precedes_invalid_mmio
);
