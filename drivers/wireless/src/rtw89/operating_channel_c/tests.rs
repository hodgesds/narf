use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
mod golden {
    include!("golden.rs");
}
/// (band, primary, width, center, center MHz, subband, gain band,
/// gain-offset band, chan_idx, pri_ch_idx, pri_sb_idx).
type Case = (Band, u8, Width, u8, u32, u8, usize, usize, u8, u8, u8);
/// Every geometry/TSSI derivation of a C profile against frozen Linux
/// 7.3-rc4 tables (golden.rs is generated from rtw8852c_rfk.c directly).
fn smoke_rtw89_c_operating_channel_matches_linux_geometry_and_tssi_groups() -> TestResult {
    // TSSI groups, every channel number of every band.
    for ch in 1..=253u8 {
        let c = usize::from(ch);
        if tssi_cck_group(ch) != golden::CCK[c]
            || tssi_ofdm_group(ch) != golden::OFDM[c]
            || tssi_trim_group(ch) != golden::TRIM[c]
            || tssi_6g_ofdm_group(ch) != golden::OFDM_6G[c]
            || tssi_6g_trim_group(ch) != golden::TRIM_6G[c]
        {
            return TestResult::Fail("C TSSI group differs from rtw8852c_rfk.c");
        }
    }
    // Channel lists: 2.4GHz 1..14, 28 5GHz (core.c), 59 6GHz primaries.
    let six: usize = (0..=255u8).filter(|&p| is_6ghz_primary(p)).count();
    let psc: usize = (0..=255u8).filter(|&p| is_psc(p)).count();
    if six != 59 || psc != 15 || !is_psc(5) || !is_psc(229) || is_psc(1) || is_psc(233) {
        return TestResult::Fail("C 6GHz primary/PSC set differs from Linux/802.11ax");
    }
    if Profile::new20(Band::Ghz5, 165).is_none()
        || Profile::new20(Band::Ghz5, 34).is_some()
        || Profile::new20(Band::Ghz6, 3).is_some()
        || Profile::new20(Band::Ghz2, 15).is_some()
    {
        return TestResult::Fail("C 20MHz channel admission differs from core.c lists");
    }
    // Frozen chandefs: (band, primary, width, center, MHz center, subband,
    // gain band, gain-offset band, chan_idx, pri_ch_idx, pri_sb_idx).
    let cases: [Case; 12] = [
        (Band::Ghz2, 1, Width::Mhz20, 1, 2412, 0, 0, 1, 1, 0, 0),
        (Band::Ghz2, 14, Width::Mhz20, 14, 2484, 0, 0, 1, 14, 0, 0),
        (Band::Ghz5, 36, Width::Mhz20, 36, 5180, 1, 1, 2, 0x20, 0, 0),
        (Band::Ghz5, 44, Width::Mhz80, 42, 5210, 1, 1, 2, 0x24, 1, 2),
        (
            Band::Ghz5,
            132,
            Width::Mhz40,
            134,
            5670,
            3,
            2,
            3,
            0x40,
            2,
            0,
        ),
        (
            Band::Ghz5,
            112,
            Width::Mhz160,
            114,
            5570,
            3,
            2,
            3,
            0x36,
            2,
            3,
        ),
        (
            Band::Ghz5,
            177,
            Width::Mhz80,
            171,
            5855,
            4,
            3,
            4,
            0x5e,
            3,
            3,
        ),
        (Band::Ghz6, 1, Width::Mhz20, 1, 5955, 5, 4, 5, 0x70, 0, 0),
        (Band::Ghz6, 37, Width::Mhz160, 47, 6185, 6, 4, 6, 0x82, 6, 1),
        (
            Band::Ghz6,
            101,
            Width::Mhz80,
            103,
            6465,
            8,
            5,
            8,
            0xa2,
            2,
            1,
        ),
        (
            Band::Ghz6,
            189,
            Width::Mhz40,
            187,
            6885,
            10,
            6,
            10,
            0xce,
            1,
            1,
        ),
        (
            Band::Ghz6,
            217,
            Width::Mhz80,
            215,
            7025,
            11,
            7,
            11,
            0xdc,
            1,
            2,
        ),
    ];
    for (band, primary, width, center, mhz, sub, gain, offset, idx, pri, sb) in cases {
        let profile = if width == Width::Mhz20 {
            Profile::new20(band, primary)
        } else {
            Profile::new_wide(band, primary, width)
        };
        let Some(p) = profile else {
            return TestResult::Fail("valid C chandef refused");
        };
        if p.center() != center
            || p.center_mhz() != mhz
            || p.subband() != sub
            || p.gain_band() != gain
            || p.gain_offset_band() != offset
            || p.chan_idx() != idx
            || p.pri_ch_idx() != pri
            || p.pri_sb_idx() != sb
            || p.occupied() != (mhz - width.mhz() / 2, mhz + width.mhz() / 2)
        {
            return TestResult::Fail("C chandef derivation differs from chan.c/phy.c");
        }
    }
    // Blocks that leave the Linux channel set are refused, never narrowed.
    if Profile::new_wide(Band::Ghz5, 140, Width::Mhz160).is_some()
        || Profile::new_wide(Band::Ghz6, 225, Width::Mhz80).is_some()
        || Profile::new_wide(Band::Ghz6, 233, Width::Mhz160).is_some()
        || Profile::new_wide(Band::Ghz6, 233, Width::Mhz40).is_some()
        || Profile::new_wide(Band::Ghz2, 1, Width::Mhz40).is_some()
        || Profile::new_2ghz_40(1, false).is_some()
        || Profile::new_2ghz_40(10, true).is_some()
        || Profile::new_2ghz_40(14, false).is_some()
    {
        return TestResult::Fail("C chandef outside the Linux channel set admitted");
    }
    // SCO terms: rtw8852c_ctrl_sco_cck thresholds and FC0 compensation.
    let one = Profile::INITIAL;
    let ht40 = Profile::new_2ghz_40(1, true).unwrap();
    let low = Profile::new_2ghz_40(9, false).unwrap();
    if one.sco_cck() != Some([0x1fe4f, 0x2bdac])
        || ht40.center() != 3
        || ht40.pri_ch_idx() != 2
        || ht40.sco_cck() != Some([0x2028a, 0x2c37e])
        || low.center() != 7
        || low.sco_cck() != Some([0x2028a, 0x2c37e])
        || Profile::new20(Band::Ghz2, 14).unwrap().sco_cck() != Some([0x20d8a, 0x2d29e])
        || Profile::new20(Band::Ghz5, 36).unwrap().sco_cck().is_some()
        || one.sco_fc0() != (2412, 109)
        || Profile::new20(Band::Ghz5, 36).unwrap().sco_fc0() != (5180, 51)
        || Profile::new20(Band::Ghz6, 1).unwrap().sco_fc0() != (5955, 44)
        || Profile::new20(Band::Ghz2, 14)
            .unwrap()
            .cck_pcoeff()
            .map(|c| c[0])
            != Some(0x3b13ff)
        || one.cck_pcoeff().map(|c| c[7]) != Some(0xffdff5)
        || Profile::new20(Band::Ghz6, 5)
            .unwrap()
            .cck_pcoeff()
            .is_some()
        || !one.cck_enabled()
        || one.rfsi_band() != 1
        || Profile::new20(Band::Ghz6, 5).unwrap().rfsi_band() != 0
    {
        return TestResult::Fail("C SCO/CCK/FC0 terms differ from rtw8852c.c");
    }
    // rtw89_phy_get_txsc / rtw8852c_set_channel_mac frozen cases.
    let mac = |band, primary, width| {
        Profile::new_wide(band, primary, width)
            .unwrap()
            .mac_program()
    };
    if Profile::INITIAL.mac_program() != (0, 0, 0x10)
        || ht40.mac_program() != (1, 2, 0x10)
        || mac(Band::Ghz5, 44, Width::Mhz80) != (2, 1 | (9 << 4), 3)
        || mac(Band::Ghz5, 36, Width::Mhz80) != (2, 4 | (10 << 4), 3)
        || mac(Band::Ghz5, 112, Width::Mhz160) != (3, 2 | (10 << 4) | (14 << 8), 3)
        || mac(Band::Ghz6, 61, Width::Mhz160) != (3, 7 | (11 << 4) | (13 << 8), 3)
        || mac(Band::Ghz6, 33, Width::Mhz160) != (3, 8 | (12 << 4) | (14 << 8), 3)
    {
        return TestResult::Fail("C MAC RFMOD/TXSC/TXRATE_CHK differs from rtw8852c.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_operating_channel_matches_linux_geometry_and_tssi_groups
);
