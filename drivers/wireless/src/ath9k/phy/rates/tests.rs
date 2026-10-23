use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
#[derive(Default)]
struct Io {
    writes: Vec<(u64, u32)>,
    revoked: bool,
    stop_after: Option<usize>,
}
impl RegisterIo for Io {
    fn authorized(&self) -> bool {
        !self.revoked
    }
    fn read32(&mut self, _: u64) -> u32 {
        panic!("rate programming reads no MMIO")
    }
    fn write32(&mut self, r: u64, v: u32) {
        self.writes.push((r, v));
        if self.stop_after == Some(self.writes.len()) {
            self.revoked = true;
        }
    }
}
fn smoke_ath9k_ctl_target_rates_match_complete_linux_generators() -> TestResult {
    for (i, (bytes, golden)) in [
        (RATE_EEPROM_0, RATE_GOLDEN_0),
        (RATE_EEPROM_1, RATE_GOLDEN_1),
        (RATE_EEPROM_2, RATE_GOLDEN_2),
        (RATE_EEPROM_3, RATE_GOLDEN_3),
        (RATE_EEPROM_4, RATE_GOLDEN_4),
        (RATE_EEPROM_5, RATE_GOLDEN_5),
        (RATE_EEPROM_6, RATE_GOLDEN_6),
        (RATE_EEPROM_7, RATE_GOLDEN_7),
        (RATE_EEPROM_8, RATE_GOLDEN_8),
    ]
    .into_iter()
    .enumerate()
    {
        let frequency = [2412, 2422, 2437, 2442, 2462, 2467, 2412, 2407, 2442][i];
        let ctl = if i == 5 || i == 7 { 0xe2 } else { 0x12 };
        let ceiling = if i == 6 {
            0
        } else if i == 5 {
            32
        } else {
            40
        };
        let p = match plan(bytes.try_into().unwrap(), frequency, ctl, ceiling) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("valid native rate fixture rejected"),
        };
        if p.registers
            .iter()
            .zip(golden)
            .any(|(&(r, v), e)| [r as u32, v] != *e)
        {
            return TestResult::Fail(
                "target interpolation/CTL flags/power/offset differs from full Linux C oracle",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ctl_target_rates_match_complete_linux_generators
);
fn smoke_ath9k_rate_plan_rejects_bad_target_or_edges_before_mmio() -> TestResult {
    let image: [u8; EEPROM_4K_BYTES] = RATE_EEPROM_0.try_into().unwrap();
    for (at, value) in [
        (183, 255),
        (188, 112),
        (184, 64),
        (198, 255),
        (203, 112),
        (213, 255),
        (222, 112),
        (279 + 2, 112),
        (8, 0x01),
        (9, 0xff),
    ] {
        let mut bad = image;
        bad[at] = value;
        let mut io = Io::default();
        if program(&mut io, &bad, 2412, 20) != Err(BringUpError::BadCalibration)
            || !io.writes.is_empty()
        {
            return TestResult::Fail(match at {
                183 => "empty CCK target accepted",
                188 => "duplicate CCK pier accepted",
                184 => "excess CCK power accepted",
                198 => "empty OFDM target accepted",
                203 => "duplicate OFDM pier accepted",
                213 => "empty HT20 target accepted",
                222 => "duplicate HT20 pier accepted",
                281 => "duplicate CTL edges accepted",
                8 => "bad factory low byte accepted",
                _ => "bad factory high byte accepted",
            });
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_rate_plan_rejects_bad_target_or_edges_before_mmio
);
fn smoke_ath9k_rate_ceiling_below_antenna_gain_cannot_wrap_power() -> TestResult {
    let mut image: [u8; EEPROM_4K_BYTES] = RATE_EEPROM_8.try_into().unwrap();
    image[60] = 6;
    let p = plan(&image, 2442, 0x12, 0).unwrap();
    if p.registers[..6].iter().any(|r| r.1 != 0x0a0a0a0a) {
        return TestResult::Fail("antenna subtraction raised zero power ceiling");
    }
    let mut io = Io {
        stop_after: Some(3),
        ..Default::default()
    };
    if program(&mut io, &image, 2412, 0) != Err(BringUpError::DeviceGone) || io.writes.len() != 3 {
        return TestResult::Fail("revoked power preparation continued register writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_rate_ceiling_below_antenna_gain_cannot_wrap_power
);

fn smoke_ath9k_initial_ctl_matches_linux_all_factory_domains() -> TestResult {
    // The unmodified __ath_regd_init + ath_regd_get_band_ctl compiled from
    // local Linux produce this oracle over all 65,536 EEPROM identifiers.
    // Initial region is NL80211_DFS_UNSET; CTL_11G is applied by eeprom_4k.c.
    let mut hash = 0xcbf29ce484222325u64;
    let mut byte = |value: u8| {
        hash = (hash ^ u64::from(value)).wrapping_mul(0x100000001b3);
    };
    let mut success = 0;
    for raw in 0..=u16::MAX {
        let Ok(factory) = Factory::from_eeprom(u32::from(raw)) else {
            byte(0);
            continue;
        };
        success += 1;
        byte(1);
        for value in initial_ctl(factory).to_le_bytes() {
            byte(value);
        }
    }
    if hash != 0x6ddb71ef849e3ba2 || success != 611 {
        return TestResult::Fail("initial CTL differs from exhaustive native Linux oracle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_initial_ctl_matches_linux_all_factory_domains
);

fn smoke_ath9k_rate_programming_rejects_revoked_native_authority() -> TestResult {
    use narf_bus::{BarKind, BusDeviceCap, MmioRegion};
    use narf_capabilities::{Cap, Write};
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0, // Any native register access would fault.
        len: super::super::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut io = crate::ath9k::identity::Registers::new(region, cap);
    cap.revoke();
    if program(&mut io, RATE_EEPROM_0.try_into().unwrap(), 2412, 0) != Err(BringUpError::DeviceGone)
    {
        return TestResult::Fail("revoked native rate publication remained authorized");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_rate_programming_rejects_revoked_native_authority
);
