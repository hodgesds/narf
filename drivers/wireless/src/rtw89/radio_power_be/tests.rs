// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::super::radio_power_c::{
    ID_LMT_2GHZ, ID_LMT_5GHZ, ID_LMT_6GHZ, ID_LMT_RU_2GHZ, ID_LMT_RU_5GHZ, ID_LMT_RU_6GHZ,
    ID_TX_SHAPE_LMT, WW,
};
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn elm(id: u32, rfe: u8, size: u8, entries: &[&[u8]]) -> Element {
    let mut bytes = vec![0, 0, rfe, size];
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let mut row = e.to_vec();
        row.resize(usize::from(size), 0);
        bytes.extend_from_slice(&row);
    }
    Element {
        id,
        version: [0; 4],
        bytes,
    }
}

/// By-rate entry {band, nss, rs, shf, len, data[4], bw, ofdma}
/// (11-byte shipped layout).
fn byr(band: u8, nss: u8, rs: u8, shf: u8, data: &[i8], bw: u8, ofdma: u8) -> Vec<u8> {
    let mut e = vec![band, nss, rs, shf, data.len() as u8, 0, 0, 0, 0, bw, ofdma];
    for (i, &v) in data.iter().enumerate() {
        e[5 + i] = v as u8;
    }
    e
}

fn base(rfe: u8, tag: i8) -> Vec<Element> {
    vec![
        elm(
            ID_BYRATE,
            rfe,
            11,
            &[
                &byr(0, 0, RS_CCK, 0, &[tag, 2, 4, 6], 0, 0),
                &byr(1, 0, RS_CCK, 0, &[99, 99, 99, 99], 0, 0),
                &byr(0, 0, RS_OFDM, 4, &[-3, 8, 10, 12], 0, 0),
                &byr(0, 0, RS_MCS, 14, &[30, 32], 0, 0),
                &byr(0, 0, RS_MCS, 14, &[34, 36], 0, 1),
                &byr(0, 0, RS_MCS, 0, &[20, 22, 24, 26], 0, 0),
                &byr(0, 0, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(0, 1, RS_MCS, 8, &[30, 32, 34, 36], 0, 0),
                &byr(0, 1, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(0, 0, RS_OFDM, 0, &[8, 10, 12, 14], 1, 0),
                &byr(0, 0, RS_OFDM, 0, &[16, 18, 20, 22], 2, 0),
                &byr(1, 0, RS_OFDM, 0, &[20, 22, 24, 26], 0, 0),
                &byr(1, 1, RS_MCS, 8, &[30, 32, 34, 36], 0, 0),
                &byr(1, 1, RS_HEDCM, 0, &[40, 42], 0, 0),
                &byr(1, 0, RS_OFFSET, 0, &[-2, 2, 4, 6], 0, 0),
                &byr(1, 0, RS_OFFSET, 4, &[8, 10, 12, 14], 0, 0),
                // nss 2 is invalid for MCS: skipped, never an error.
                &byr(1, 2, RS_MCS, 0, &[77], 0, 0),
            ],
        ),
        elm(
            ID_LMT_2GHZ,
            rfe,
            7,
            &[
                // bw, nt, rs, bf, regd, ch_idx, v
                &[0, 0, RS_CCK, 0, WW, 5, 40],
                &[0, 0, RS_OFDM, 1, WW, 5, 36],
                &[0, 1, RS_MCS, 0, WW, 5, 30],
                // non-WW regd is not read (regd = WW, no country).
                &[0, 0, RS_OFDM, 1, 2, 5, 2],
                // last entry wins.
                &[0, 1, RS_MCS, 0, WW, 5, -6i8 as u8],
            ],
        ),
        elm(
            ID_LMT_5GHZ,
            rfe,
            7,
            &[
                // 80MHz center 42: mcs_20m at 36/40/44/48 (idx 0/2/4/6).
                &[0, 0, RS_MCS, 0, WW, 0, 50],
                &[0, 0, RS_MCS, 0, WW, 6, 52],
                &[1, 0, RS_MCS, 0, WW, 1, 44],
                &[1, 0, RS_MCS, 0, WW, 5, 40],
                &[2, 0, RS_MCS, 1, WW, 3, 34],
                // ofdm at primary 36.
                &[0, 1, RS_OFDM, 0, WW, 0, 28],
                // bw 4 is out of the 5GHz range: skipped.
                &[4, 0, RS_MCS, 0, WW, 3, 1],
            ],
        ),
        elm(
            ID_LMT_RU_2GHZ,
            rfe,
            5,
            &[&[0, 0, WW, 5, 20], &[2, 1, WW, 5, 18]],
        ),
        elm(
            ID_LMT_RU_5GHZ,
            rfe,
            5,
            &[&[1, 0, WW, 2, 24], &[2, 1, WW, 6, 26]],
        ),
        elm(
            ID_TX_SHAPE_LMT,
            rfe,
            4,
            &[&[0, 0, WW, 1], &[1, 1, WW, 2], &[1, 1, 3, 3]],
        ),
    ]
}

/// Six-GHz additions to [`base`]: a band-2 by-rate row in the same
/// BYRATE element (one element per ID: `select` keeps one), LMT_6GHZ
/// {bw, nt, rs, bf, regd, reg6, ch_idx, v} and LMT_RU_6GHZ
/// {ru, nt, regd, reg6, ch_idx, v}. ch37 = 6G idx 17.
fn six_set() -> Vec<Element> {
    let mut set = base(0, 10);
    set[0] = elm(
        ID_BYRATE,
        0,
        11,
        &[
            &byr(0, 0, RS_CCK, 0, &[10, 2, 4, 6], 0, 0),
            &byr(2, 0, RS_OFDM, 0, &[16, 18, 20, 22], 0, 0),
        ],
    );
    set.push(elm(
        ID_LMT_6GHZ,
        0,
        8,
        &[
            // ch37 = 6G idx 17. FCC (2) LPI (1) OFDM: own value.
            &[0, 0, RS_OFDM, 0, 2, 1, 17, 30],
            // MCS: no FCC/LPI value, so [WW][DFLT] is read.
            &[0, 0, RS_MCS, 0, WW, 0, 17, 24],
            // ETSI (1) STD (2) OFDM for the GB/UK case.
            &[0, 0, RS_OFDM, 0, 1, 2, 17, 40],
            // reg6 3 is out of range: skipped.
            &[0, 0, RS_OFDM, 0, 2, 3, 17, 2],
        ],
    ));
    set.push(elm(
        ID_LMT_RU_6GHZ,
        0,
        6,
        &[&[0, 0, 2, 1, 17, 22], &[1, 0, WW, 0, 17, 20]],
    ));
    set
}

fn pack(b: &[i8]) -> u32 {
    u32::from_le_bytes([b[0] as u8, b[1] as u8, b[2] as u8, b[3] as u8])
}

fn smoke_rtw89_be_byrate_stream_follows_phy_be() -> TestResult {
    let set = base(0, 10);
    let Some(ch6) = Channel::new(Band::Ghz2, 6, 6, Bw::Mhz20) else {
        return TestResult::Fail("2.4GHz ch6 refused");
    };
    let Ok(plan) = Plan::from_elements(&set, 5, ch6) else {
        return TestResult::Fail("default-RFE BE power elements refused");
    };
    let (words, offset, _, _, shape) = plan.parts();
    // bw0 nss0: CCK [5,1,2,3]; OFDM shf 4 [-2,4,5,6]; MCS 14/15
    // non-OFDMA [15,16] then OFDMA [17,18]; MCS 0..3 [10,11,12,13];
    // HEDCM [20,21] at bytes 30,31.
    if words[0] != 0x0302_0105
        || words[1] != 0
        || words[2] != pack(&[-2, 4, 5, 6])
        || words[3] != pack(&[15, 16, 17, 18])
        || words[4] != pack(&[10, 11, 12, 13])
        || words[7] != pack(&[0, 0, 20, 21])
    {
        return TestResult::Fail("2.4GHz BE byrate stream differs from rtw89_byr_spec_be");
    }
    // bw0 nss1: MCS shf 8 [15,16,17,18] at bytes 60..63; HEDCM
    // [20,21] at bytes 66,67. bw1 OFDM [4,5,6,7] at bytes 92..95;
    // bw2 OFDM [8,9,10,11] at bytes 176..179 (no CCK past 40MHz).
    if words[15] != pack(&[15, 16, 17, 18])
        || words[16] != pack(&[0, 0, 20, 21])
        || words[22] != 0
        || words[23] != pack(&[4, 5, 6, 7])
        || words[44] != pack(&[8, 9, 10, 11])
        || words[106] != 0
    {
        return TestResult::Fail("BE byrate stream bw/nss layout differs from phy_be.c");
    }
    if offset != [0; 8] || shape != [1, 0] {
        return TestResult::Fail("2.4GHz BE offset/shape differ");
    }

    let Some(wide) = Channel::new(Band::Ghz5, 36, 42, Bw::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz refused");
    };
    let Ok(plan5) = Plan::from_elements(&set, 0, wide) else {
        return TestResult::Fail("5GHz 80MHz BE power plan refused");
    };
    let (words, offset, _, _, shape) = plan5.parts();
    // 5GHz still reads CCK from the 2.4GHz band (never 99>>1); OFDM
    // from band 1; nss1 MCS/HEDCM from band 1.
    if words[0] != 0x0302_0105
        || words[1] != pack(&[10, 11, 12, 13])
        || words[15] != pack(&[15, 16, 17, 18])
        || words[16] != pack(&[0, 0, 20, 21])
    {
        return TestResult::Fail("5GHz BE byrate did not read CCK from band 2G");
    }
    // Offsets are read at bw 0 of the channel's band (HE..EHT).
    if offset != [-1, 1, 2, 3, 4, 5, 6, 7] || shape != [0, 2] {
        return TestResult::Fail("5GHz BE rate offsets/shape differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_byrate_stream_follows_phy_be
);

fn smoke_rtw89_be_limit_pages_follow_phy_be() -> TestResult {
    let set = base(0, 10);
    let Some(ch6) = Channel::new(Band::Ghz2, 6, 6, Bw::Mhz20) else {
        return TestResult::Fail("2.4GHz ch6 refused");
    };
    let Ok(plan) = Plan::from_elements(&set, 5, ch6) else {
        return TestResult::Fail("2.4GHz BE power plan refused");
    };
    let (_, _, limit, ru, _) = plan.parts();
    // limit page: cck_20m[nonbf] 40>>1, ofdm[bf] 36>>1; 2TX
    // mcs_20m[0] -6>>1; cck_40m unwritten.
    if limit[0][0] != 20 || limit[0][5] != 18 || limit[1][6] != -3 || limit[0][2] != 0 {
        return TestResult::Fail("2.4GHz 20MHz BE limit page differs from fill_txpwr_limit_20m_be");
    }
    // RU page: ru26[0] 20>>1; ru106 2TX section 0 18>>1 at offset 32.
    if ru[0][0] != 10 || ru[1][32] != 9 || ru[1][16] != 0 {
        return TestResult::Fail("2.4GHz BE RU page differs from fill_txpwr_limit_ru_20m_be");
    }

    let Some(wide) = Channel::new(Band::Ghz5, 36, 42, Bw::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz refused");
    };
    let Ok(plan5) = Plan::from_elements(&set, 0, wide) else {
        return TestResult::Fail("5GHz 80MHz BE power plan refused");
    };
    let (_, _, limit, ru, _) = plan5.parts();
    // mcs_20m[0]=ch36, [3]=ch48; mcs_40m[0]=38(idx1), [1]=46(idx5);
    // mcs_80m[1] bf=42(idx3); 0p5 = min(40@38, 40@46).
    // BE page offsets: mcs_20m 6, mcs_40m 38, mcs_80m 54, 0p5 68.
    if limit[0][6] != 25
        || limit[0][12] != 26
        || limit[0][38] != 22
        || limit[0][40] != 20
        || limit[0][55] != 17
        || limit[0][68] != 20
    {
        return TestResult::Fail("80MHz BE limit page differs from fill_txpwr_limit_80m_be");
    }
    // OFDM at primary 36 (2TX page, nonbf).
    if limit[1][4] != 14 {
        return TestResult::Fail("80MHz BE OFDM limit not read at the primary channel");
    }
    // RU: the 5GHz RU fixture has no ru26 rows, so every ru26
    // section reads 0 (`rtw89_phy_read_txpwr_limit_ru` has no
    // fallback past regd/WW); ru52 section 1 = ch40; ru106 2TX
    // section 3 = ch48.
    if ru[0][..16].iter().any(|&v| v != 0) || ru[0][17] != 12 || ru[1][35] != 13 {
        return TestResult::Fail("80MHz BE RU page differs from fill_txpwr_limit_ru_80m_be");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_limit_pages_follow_phy_be
);

fn smoke_rtw89_be_visit_emits_rtw8922a_set_txpwr_order() -> TestResult {
    let set = base(0, 10);
    let Some(wide) = Channel::new(Band::Ghz5, 36, 42, Bw::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz refused");
    };
    let Ok(plan) = Plan::from_elements(&set, 0, wide) else {
        return TestResult::Fail("5GHz 80MHz BE power plan refused");
    };
    let mut writes = Vec::new();
    if plan
        .visit(0, 1, |a, m, v| {
            writes.push((a, m, v));
            Ok(())
        })
        .is_err()
    {
        return TestResult::Fail("BE power visit failed");
    }
    // 107 byrate + 1 offset + 1 shape + 38 limit + 40 RU + 6 diff
    // + 2 ref + 2 SAR.
    if writes.len() != 197 {
        return TestResult::Fail("BE power program is not 197 writes");
    }
    // Offset pack: CCK 4, OFDM 3, HT 2, VHT 1, HE 0xf, EHT 7,
    // DLRU_HE 6, DLRU_EHT 5 (nibbles 0..7).
    if writes[0] != (0x11E00, u32::MAX, 0x0302_0105)
        || writes[106] != (0x11FA8, u32::MAX, 0)
        || writes[107] != (0x11A30, u32::MAX, 0x567f_1234)
        || writes[108] != (0x26C04, 0x3, 1)
        || writes[109] != (0x11FAC, u32::MAX, 0)
        || writes[110] != (0x11FB0, u32::MAX, 0x0019_0000)
        || writes[111] != (0x11FB4, u32::MAX, 0)
        || writes[112] != (0x11FB8, u32::MAX, 0x0000_001a)
        || writes[118] != (0x11FD0, u32::MAX, 0x0016_0000)
        || writes[126] != (0x11FF0, u32::MAX, 0x0000_0014)
        || writes[147] != (0x12048, u32::MAX, 0)
        || writes[151] != (0x12058, u32::MAX, 0x0000_0c00)
    {
        return TestResult::Fail("BE byrate/offset/shape/limit/RU writes differ");
    }
    // Diff (cv != CAV, offset 0): refs 0, TSSI-K 18 on both paths.
    if writes[187] != (0x2E628, 0x1ff, 0)
        || writes[188] != (0x2E628, 0x3_fe00, 0)
        || writes[189] != (0x2E6A0, 0x3ff0_0000, 18)
        || writes[190] != (0x2E728, 0x1ff, 0)
        || writes[192] != (0x2E7A0, 0x3ff0_0000, 18)
        || writes[193] != (0x11A20, 0x3fe, 0)
        || writes[194] != (0x11A20, 0x7_fc00, 0)
        || writes[195] != (0x2E61C, 0x1ff000, 126)
        || writes[196] != (0x2E71C, 0x1ff000, 126)
    {
        return TestResult::Fail("BE diff/ref/SAR writes differ from rtw8922a_set_txpwr");
    }
    // CAV cut, antenna-gain offset +4: pwr_ref 16<<2 = 64, ofst 62,
    // TSSI-K A 18, B 22.
    let mut cav = Vec::new();
    if plan
        .visit(4, 0, |a, m, v| {
            cav.push((a, m, v));
            Ok(())
        })
        .is_err()
        || cav[187].2 != 64
        || cav[189].2 != 18
        || cav[190].2 != 62
        || cav[192].2 != 22
    {
        return TestResult::Fail("BE CAV/ant-gain diff differs from rtw8922a_set_txpwr_diff");
    }
    // `rtw8922a_set_txpwr_ctrl` is the ref pair only; the TSSI reset
    // is the 0 -> 1 pulse on RSTA then RSTB (BE PHY window).
    let mut ctrl = Vec::new();
    if Plan::visit_ctrl(|a, m, v| {
        ctrl.push((a, m, v));
        Ok(())
    })
    .is_err()
        || ctrl != [(0x11A20, 0x3fe, 0), (0x11A20, 0x7_fc00, 0)]
        || tssi_reset_program()
            != [
                (0x2E60C, 1 << 16, 0),
                (0x2E60C, 1 << 16, 1),
                (0x2E70C, 1 << 16, 0),
                (0x2E70C, 1 << 16, 1),
            ]
    {
        return TestResult::Fail("BE txpwr_ctrl / tssi_reset program differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_visit_emits_rtw8922a_set_txpwr_order
);

fn smoke_rtw89_be_6ghz_plan_needs_regd_and_tpe() -> TestResult {
    let set = six_set();
    // ETSI (1) STD (2); FCC (2) LPI (1).
    let gb = SixGhzPower::for_test(1, 2);
    let us = SixGhzPower::for_test(2, 1);
    let Some(ch37) = Channel::new(Band::Ghz6, 37, 37, Bw::Mhz20) else {
        return TestResult::Fail("6GHz ch37 refused");
    };
    let Ok(plan) = Plan::from_elements_6ghz(&set, 5, ch37, us, None) else {
        return TestResult::Fail("6GHz LPI power plan refused");
    };
    let (words, _, limit, ru, _) = plan.parts();
    // byr[6G]: OFDM 16/18/20/22 rf -> 8/9/10/11 mac; CCK still 2.4GHz.
    if words[1] != pack(&[8, 9, 10, 11])
        || words[0] != 0x0302_0105
        || limit[0][4] != 15
        || limit[0][6] != 12
        || ru[0][0] != 11
        || ru[0][16] != 10
    {
        return TestResult::Fail("6GHz BE limits differ from rtw89_phy_read_txpwr_limit(6G)");
    }
    // STD with a TPE: min3 with dbm_to_mac(5) = 10; the bound identity
    // stays the TPE-free plan's; TPE is refused off STD or below -10dBm.
    let (Ok(sp), Ok(bare)) = (
        Plan::from_elements_6ghz(&set, 5, ch37, gb, Some(5)),
        Plan::from_elements_6ghz(&set, 5, ch37, gb, None),
    ) else {
        return TestResult::Fail("6GHz SP power plan refused");
    };
    let digest = |p: &Plan| {
        let mut h = narf_crypto::sha256::Sha256::new();
        p.bind(&mut h);
        h.finalize()
    };
    if sp.parts().2[0][4] != 10
        || bare.parts().2[0][4] != 20
        || digest(&sp) != digest(&bare)
        || digest(&bare) == digest(&plan)
        || Plan::from_elements_6ghz(&set, 5, ch37, us, Some(5)) != Err(Error::Policy)
        || Plan::from_elements_6ghz(&set, 5, ch37, gb, Some(-11)) != Err(Error::Policy)
        || Plan::from_elements(&set, 5, ch37) != Err(Error::Policy)
    {
        return TestResult::Fail(
            "6GHz BE TPE constraint differs from rtw89_phy_get_tpe_constraint",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_6ghz_plan_needs_regd_and_tpe
);

fn smoke_rtw89_be_channel_refusals() -> TestResult {
    let set = base(0, 10);
    let Some(ch6) = Channel::new(Band::Ghz2, 6, 6, Bw::Mhz20) else {
        return TestResult::Fail("2.4GHz ch6 refused");
    };
    let no_byrate: Vec<Element> = base(0, 10)
        .into_iter()
        .filter(|e| e.id != ID_BYRATE)
        .collect();
    let no_lmt: Vec<Element> = base(0, 10)
        .into_iter()
        .filter(|e| e.id != ID_LMT_2GHZ)
        .collect();
    if Channel::new(Band::Ghz2, 6, 6, Bw::Mhz80).is_some()
        || Channel::new(Band::Ghz5, 36, 42, Bw::Mhz320).is_some()
        || Channel::new(Band::Ghz2, 0, 6, Bw::Mhz20).is_some()
        || Channel::new(Band::Ghz6, 5, 5, Bw::Mhz320).is_none()
        || Channel::new(Band::Ghz5, 36, 42, Bw::Mhz160).is_none()
        || Plan::from_elements(&set, 255, ch6) != Err(Error::Policy)
        || Plan::from_elements(&no_byrate, 5, ch6) != Err(Error::Table)
        || Plan::from_elements(&no_lmt, 5, ch6) != Err(Error::Table)
    {
        return TestResult::Fail("BE channel/element refusals differ");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_channel_refusals);
