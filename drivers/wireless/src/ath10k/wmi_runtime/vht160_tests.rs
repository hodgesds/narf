//! Contiguous VHT160 geometry, native phymodes, peer flags and VDEV_START
//! channel words, authored from Linux ath10k mac.c / wmi.c.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A contiguous160 selection keeps the 80+80 shape: `center` is the
/// primary80 half (cfg80211 chandef `center_freq1` for that half), the
/// wide `center2` its adjacent half; 80+80 keeps its own segment center.
fn smoke_ath10k_vht160_profile_primary80_and_second_center() -> TestResult {
    use super::super::{primary80, second_center};
    // VHT160 channel 50 (5250) and 114 (5570), every 20 MHz primary.
    for (full, low, high) in [(5250u16, 5210u16, 5290u16), (5570, 5530, 5610)] {
        for primary in (full - 70..=full + 70).step_by(20) {
            let p80 = primary80(full, primary);
            let expected = if primary < full { low } else { high };
            if p80 != expected || primary80(full, p80) != p80 {
                return TestResult::Fail("contiguous160 primary80 half");
            }
            let other = if p80 == low { high } else { low };
            if second_center(Width::OneSixty, false, full, p80, None) != Some(other) {
                return TestResult::Fail("contiguous160 adjacent half");
            }
        }
    }
    // 80+80 (VHT Operation CCFS1 = ch155) keeps the separate segment.
    if second_center(Width::OneSixty, true, 5210, 5210, Some(155)) != Some(5775)
        || second_center(Width::Eighty, false, 5210, 5210, None).is_some()
    {
        return TestResult::Fail("80+80 or VHT80 second center");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht160",
    smoke_ath10k_vht160_profile_primary80_and_second_center
);
