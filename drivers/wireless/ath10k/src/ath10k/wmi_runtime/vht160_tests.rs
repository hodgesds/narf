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

fn wide(contiguous: bool, nss: u8) -> Wide {
    Wide {
        center2: if contiguous { 5290 } else { 5775 },
        contiguous,
        nss,
        rx_nss: nss,
        rx_sgi: false,
    }
}

/// Linux `chan_to_phymode` (VDEV_START) and `ath10k_mac_get_phymode_vht`
/// (PEER_ASSOC) for 160 MHz, and the 10.4 `peer_bw_rxnss_override` word.
/// The modes and `bw160` peer flag are the same in every WMI dialect map.
fn smoke_ath10k_vht160_phymodes_and_nss_override() -> TestResult {
    let c = wide(true, 2);
    let d = wide(false, 2);
    if c.start_mode() != 15 || d.start_mode() != 14 {
        return TestResult::Fail("VDEV_START VHT160 / VHT80_80 channel mode");
    }
    // Peer width set after the own-width intersection: 160-only (4) or
    // none (ext NSS) stays VHT160; 160+80+80 (8) is VHT80_80 in Linux.
    if c.peer_mode(4) != 15 || c.peer_mode(0) != 15 || c.peer_mode(8) != 14 || d.peer_mode(4) != 14
    {
        return TestResult::Fail("PEER_ASSOC VHT160 / VHT80_80 peer mode");
    }
    // NSS_MAP_ENABLE | (nss-1) in bits 0..2; bits 3..5 only for VHT80_80.
    if c.nss_override(15) != Some(0x8000_0001)
        || c.nss_override(14) != Some(0x8000_0009)
        || wide(true, 1).nss_override(15) != Some(0x8000_0000)
        || wide(true, 3).nss_override(15).is_some()
        || wide(true, 0).nss_override(15).is_some()
    {
        return TestResult::Fail("10.4 160 MHz NSS override word");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht160",
    smoke_ath10k_vht160_phymodes_and_nss_override
);
