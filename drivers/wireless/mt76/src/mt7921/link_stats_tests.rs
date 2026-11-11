//! CONNAC2 rate words and RCPI as GET_STATION reports them.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// P-RXV DW0 with the `MT_PRXV_*` fields.
fn prxv(mode: u32, idx: u32, nsts: u32, bw: u32, gi: u32) -> u32 {
    idx | nsts << 7 | bw << 12 | gi << 15 | mode << 24
}

/// `mt76_connac2_mac_fill_rx_rate` + `cfg80211_calculate_bitrate` for the
/// modes an MT7922 station receives, and refusal of reserved encodings.
fn mt7922_rx_rate_words_decode_as_cfg80211_rates() -> TestResult {
    let cases = [
        // CCK 11 Mb/s with the short-preamble bit, OFDM 54 Mb/s.
        (prxv(0, 7, 0, 0, 0), 110),
        (prxv(1, 12, 0, 0, 0), 540),
        // HT MCS15 (2 SS) 40 MHz SGI: 300 Mb/s.
        (prxv(2, 15, 1, 1, 1), 3000),
        // VHT MCS9 2 SS 80 MHz SGI: 866.7 Mb/s.
        (prxv(4, 9, 1, 2, 1), 8667),
        // HE-SU MCS11 2 SS 80 MHz 0.8 us: 1200.9 Mb/s.
        (prxv(8, 11, 1, 2, 0), 12009),
    ];
    for (word, want) in cases {
        if rx_rate(word).map(|r| r.bitrate_100kbps) != Some(want) {
            return TestResult::Fail("P-RXV rate differs from the cfg80211 rate");
        }
    }
    let he = rx_rate(prxv(8, 11, 1, 2, 0)).unwrap();
    let vht = rx_rate(prxv(4, 9, 1, 2, 1)).unwrap();
    if he.he_mcs != Some((11, 2, 0))
        || he.width_mhz != 80
        || vht.vht_mcs != Some((9, 2))
        || !vht.short_gi
        || rx_rate(prxv(2, 15, 1, 1, 1)).unwrap().ht_mcs != Some(15)
    {
        return TestResult::Fail("rate fields are not the nl80211 rate_info fields");
    }
    // HE DCM (idx bit 4) halves the rate.
    if rx_rate(prxv(8, 0x10 | 3, 0, 0, 0)).map(|r| (r.he_dcm, r.bitrate_100kbps))
        != rx_rate(prxv(8, 3, 0, 0, 0)).map(|r| (true, r.bitrate_100kbps / 2))
    {
        return TestResult::Fail("HE DCM");
    }
    for bad in [
        prxv(1, 3, 0, 0, 0),  // no such OFDM hw rate
        prxv(2, 32, 0, 0, 0), // HT MCS > 31
        prxv(4, 10, 0, 0, 0), // VHT MCS 10
        prxv(4, 0, 0, 5, 0),  // reserved width
        prxv(8, 12, 0, 0, 0), // HE MCS 12
        prxv(8, 0, 0, 0, 3),  // reserved HE GI
        prxv(5, 0, 0, 0, 0),  // reserved mode
    ] {
        if rx_rate(bad).is_some() {
            return TestResult::Fail("reserved rate word decoded");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mt7922_rx_rate_words_decode_as_cfg80211_rates
);

/// RCPI to dBm per chain, the strongest chain as SIGNAL, mac80211's EWMA as
/// SIGNAL_AVG, and the receive rate only from data frames.
fn mt7922_link_signal_and_average_follow_rcpi() -> TestResult {
    let mut stats = LinkStats::default();
    if stats.signal_dbm.is_some() || stats.signal_avg_dbm().is_some() {
        return TestResult::Fail("signal without a frame");
    }
    // RCPI 120 = -50 dBm on chain 0, 110 = -55 dBm on chain 1.
    stats.observe(Some(120 | 110 << 8), Some(prxv(4, 9, 1, 2, 1)), false);
    if stats.signal_dbm != Some(-50)
        || stats.chain_signal_dbm != [Some(-50), Some(-55)]
        || stats.signal_avg_dbm() != Some(-50)
        || stats.rx_rate.is_some()
    {
        return TestResult::Fail("first sample, or a beacon rate taken as RX bitrate");
    }
    // Eight -70 dBm frames pull the average most of the way, as
    // DECLARE_EWMA(signal, 10, 8) does.
    for _ in 0..8 {
        stats.observe(Some(80), Some(prxv(4, 9, 1, 2, 1)), true);
    }
    let avg = stats.signal_avg_dbm().unwrap_or(0);
    if stats.signal_dbm != Some(-70)
        || stats.chain_signal_dbm != [Some(-70), None]
        || !(-66..=-62).contains(&avg)
        || stats.rx_rate.map(|r| r.bitrate_100kbps) != Some(8667)
    {
        return TestResult::Fail("EWMA signal average or data rate");
    }
    // No valid chain: nothing changes.
    let before = stats;
    stats.observe(Some(230 << 8), None, true);
    if stats != before {
        return TestResult::Fail("invalid RCPI changed the statistics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mt7922_link_signal_and_average_follow_rcpi
);
