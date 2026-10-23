use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_ath10k_factory_regulatory_identity_matches_linux_all_u16() -> TestResult {
    // Independently compiled, unmodified __ath_regd_init and its lookup /
    // sanitization helpers over every 16-bit EEPROM value, not a copy of
    // the Rust resolver. Hash includes all success fields or a failure byte.
    let mut hash = 0xcbf29ce484222325u64;
    let mut byte = |value: u8| {
        hash = (hash ^ u64::from(value)).wrapping_mul(0x100000001b3);
    };
    let mut success = 0;
    for raw in 0..=u16::MAX {
        let Ok(f) = Factory::from_eeprom(u32::from(raw)) else {
            byte(0);
            continue;
        };
        success += 1;
        byte(1);
        for value in [f.eeprom, f.country, f.pair, f.ctl_5ghz, f.ctl_2ghz] {
            for value in value.to_le_bytes() {
                byte(value);
            }
        }
        for value in f.alpha2 {
            byte(value);
        }
    }
    if hash != 0xec8104beec6e96fc || success != 611 {
        return TestResult::Fail(
            "factory EEPROM identity differs from exhaustive native Linux oracle",
        );
    }
    if Factory::from_eeprom(0x1_0064).is_ok()
        || Factory::from_eeprom(0xffff).is_ok()
        || Factory::from_eeprom(0xc000).is_ok()
    {
        return TestResult::Fail("unsupported/ambiguous EEPROM identifier acquired a factory pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_factory_regulatory_identity_matches_linux_all_u16
);
