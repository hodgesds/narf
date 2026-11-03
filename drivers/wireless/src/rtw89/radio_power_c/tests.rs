// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

/// Byrate entry {band, nss, rs, shf, len, data[4]} (9-byte shipped layout).
fn byr(band: u8, nss: u8, rs: u8, shf: u8, data: &[i8]) -> Vec<u8> {
    let mut e = vec![band, nss, rs, shf, data.len() as u8, 0, 0, 0, 0];
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
            9,
            &[
                &byr(0, 0, RS_CCK, 0, &[tag, 2, 4, 6]),
                &byr(1, 0, RS_CCK, 0, &[99, 99, 99, 99]),
                &byr(0, 0, RS_OFDM, 4, &[-3, 8, 10, 12]),
                &byr(1, 0, RS_OFDM, 0, &[20, 22, 24, 26]),
                &byr(1, 1, RS_MCS, 8, &[30, 32, 34, 36]),
                &byr(1, 1, RS_HEDCM, 0, &[40, 42]),
                &byr(1, 0, RS_OFFSET, 0, &[-2, 2, 4, 6]),
                // nss 2 is invalid for MCS: skipped, never an error.
                &byr(1, 2, RS_MCS, 0, &[77]),
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

fn smoke_rtw89_c_txpwr_selection_follows_rtw89_fw_recognize_txpwr_from_elm() -> TestResult {
    let tagged = |rfe: u8, tag: u8| elm(ID_BYRATE, rfe, 9, &[&byr(0, 0, 0, 0, &[tag as i8])]);
    let pick = |set: &[Element], rfe: u8| -> Option<u8> {
        select(set, ID_BYRATE, rfe)
            .ok()
            .flatten()
            .map(|c| c.data[5])
    };
    // Exact RFE wins over a later default.
    let set = [tagged(0, 1), tagged(5, 2), tagged(0, 3)];
    if pick(&set, 5) != Some(2) {
        return TestResult::Fail("exact RFE element lost to a later default");
    }
    // Without a match, the last default wins.
    if pick(&set, 3) != Some(3) {
        return TestResult::Fail("last default element not taken without an exact match");
    }
    // Several exact matches: the last one wins.
    let set = [tagged(5, 1), tagged(0, 2), tagged(5, 3)];
    if pick(&set, 5) != Some(3) {
        return TestResult::Fail("last exact RFE element not taken");
    }
    // Neither default nor exact: nothing selected.
    if pick(&[tagged(7, 1)], 5).is_some() {
        return TestResult::Fail("foreign RFE element selected");
    }
    // A size-inconsistent header fails closed.
    let mut bad = tagged(0, 1);
    bad.bytes.push(0);
    if select(&[bad], ID_BYRATE, 0).is_ok() {
        return TestResult::Fail("malformed TXPWR element accepted");
    }
    // A wider entry is used only with an all-zero extension.
    let wide = Element {
        id: ID_TX_SHAPE_LMT,
        version: [0; 4],
        bytes: vec![
            0, 0, 0, 7, 2, 0, 0, 0, 1, 1, 0, 2, 0, 0, 0, 1, 1, 0, 3, 0, 0, 9,
        ],
    };
    let conf = select(core::slice::from_ref(&wide), ID_TX_SHAPE_LMT, 0)
        .ok()
        .flatten();
    let rows: Vec<[u8; 16]> = conf.map(|c| c.entries(5).collect()).unwrap_or_default();
    if rows.len() != 1 || rows[0][3] != 2 {
        return TestResult::Fail("nonzero entry extension not skipped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_txpwr_selection_follows_rtw89_fw_recognize_txpwr_from_elm
);

fn smoke_rtw89_c_set_txpwr_follows_rtw8852c_and_phy_ax() -> TestResult {
    let set = base(0, 10);
    let Some(ch6) = Profile::new20(Band::Ghz2, 6) else {
        return TestResult::Fail("2.4GHz ch6 refused");
    };
    let Ok(plan) = Plan::from_elements(&set, 5, ch6) else {
        return TestResult::Fail("default-RFE C power elements refused");
    };
    let (rate, offset, limit, ru, shape) = plan.parts();
    // CCK from band 2G, OFDM shf 4, >>1 arithmetic (rf factor 2, mac 1).
    if rate[..4] != [5, 1, 2, 3] || rate[4..12] != [0, 0, 0, 0, -2, 4, 5, 6] {
        return TestResult::Fail("2.4GHz CCK/OFDM byrate differs from rtw89_phy_read_txpwr_byrate");
    }
    // limit page: cck_20m[nonbf] 40>>1, ofdm[bf] 36>>1; 2TX mcs_20m[0] -6>>1.
    if limit[0][0] != 20 || limit[0][5] != 18 || limit[1][6] != -3 || limit[0][2] != 0 {
        return TestResult::Fail("2.4GHz 20MHz limit page differs from fill_txpwr_limit_20m_ax");
    }
    if ru[0][0] != 10 || ru[1][16] != 9 || ru[0][8] != 0 {
        return TestResult::Fail("2.4GHz RU page differs from fill_txpwr_limit_ru_20m_ax");
    }
    if shape != [1, 0] || offset != &[0; 5] {
        return TestResult::Fail("2.4GHz tx shape/offset differ");
    }

    let Some(wide) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz refused");
    };
    let Ok(plan5) = Plan::from_elements(&set, 0, wide) else {
        return TestResult::Fail("5GHz 80MHz C power plan refused");
    };
    let (rate, offset, limit, ru, shape) = plan5.parts();
    // 5GHz still reads CCK from the 2.4GHz band (never 99>>1).
    if rate[..4] != [5, 1, 2, 3] || rate[4..8] != [10, 11, 12, 13] {
        return TestResult::Fail("5GHz byrate did not take CCK from band 2G");
    }
    // nss1 MCS (28..40) shf 8 and nss1 HEDCM (40..44).
    if rate[36..40] != [15, 16, 17, 18] || rate[40..42] != [20, 21] {
        return TestResult::Fail("5GHz nss1 MCS/HEDCM byrate layout differs");
    }
    if offset != &[-1, 1, 2, 3, 0] {
        return TestResult::Fail("5GHz rate offsets differ");
    }
    // OFDM at primary 36 (nt 1 -> 2TX page, nonbf).
    if limit[1][4] != 14 {
        return TestResult::Fail("80MHz OFDM limit not read at the primary channel");
    }
    // mcs_20m[0]=ch36, [3]=ch48; mcs_40m[0]=38(idx1), [1]=46(idx5);
    // mcs_80m[0] bf=42(idx3); 0p5 = min(40@38, 40@46).
    if limit[0][6] != 25
        || limit[0][12] != 26
        || limit[0][22] != 22
        || limit[0][24] != 20
        || limit[0][31] != 17
        || limit[0][36] != 20
    {
        return TestResult::Fail("80MHz limit page differs from fill_txpwr_limit_80m_ax");
    }
    // RU 80MHz: ru52 at ch40 (idx2) slot 1; ru106 2TX at ch48 (idx6) slot 3.
    if ru[0][9] != 12 || ru[1][19] != 13 {
        return TestResult::Fail("80MHz RU page differs from fill_txpwr_limit_ru_80m_ax");
    }
    // Shape OFDM 2 (MID) from WW only.
    if shape != [0, 2] {
        return TestResult::Fail("5GHz tx shape not WW/OFDM");
    }

    // Program: byrate 11 words, offset, bandedge (level, 15 + cfg + 4
    // fast), DAC comp 2, limit 20 words, RU 12 words, ref 5, SAR 2.
    let mut writes = Vec::new();
    if plan5
        .visit(|a, m, v| {
            writes.push((a, m, v));
            Ok(())
        })
        .is_err()
    {
        return TestResult::Fail("5GHz program refused");
    }
    if writes.len() != 11 + 1 + 15 + 1 + 4 + 2 + 20 + 12 + 5 + 2
        || writes[0] != (0xd2c0, u32::MAX, u32::from_le_bytes([5, 1, 2, 3]))
        || writes[11] != (0xd204, 0xf_ffff, 0x321f)
        || writes[12] != (0xd910, 0xff, 0x24)
        || writes[27] != (0xd94c, 0xc000_0000, 2)
        || writes[28] != (0xd930, 0xff_0000, 0x24)
        || writes[32] != (0x1_58f8, 1 << 31, 1)
        || writes[34].0 != 0xd2ec
        || writes[54].0 != 0xd33c
        || writes[66] != (0xd200, 0xffffc00, 0)
        || writes[71] != (0x1_56cc, 0x1ff, 126)
        || writes[72] != (0x1_76cc, 0x1ff, 126)
    {
        return TestResult::Fail("5GHz C set_txpwr program differs from rtw8852c_set_txpwr");
    }
    // 2.4GHz adds the CCK DFIR (sharp for shape 1; ch14 sharp_14).
    let mut dfir = Vec::new();
    let _ = plan.visit(|a, m, v| {
        if m == 0xff_ffff {
            dfir.push((a, v));
        }
        Ok(())
    });
    if dfir.len() != 8 || dfir[0] != (0x1_45bc, 0x003D83FF) {
        return TestResult::Fail("2.4GHz DFIR differs from rtw8852c_bb_set_tx_shape_dfir");
    }

    // Missing element, 6GHz and unprovisioned RFE are refused.
    let partial: Vec<Element> = base(0, 1)
        .into_iter()
        .filter(|e| e.id != ID_LMT_RU_5GHZ)
        .collect();
    if Plan::from_elements(&partial, 0, wide).is_ok() {
        return TestResult::Fail("C power plan built without its RU limit element");
    }
    let Some(six) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 refused");
    };
    if Plan::from_elements(&set, 0, six) != Err(Error::Policy)
        || Plan::from_elements(&set, 255, ch6) != Err(Error::Policy)
    {
        return TestResult::Fail("6GHz or RFE 255 C power plan admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_set_txpwr_follows_rtw8852c_and_phy_ax
);
