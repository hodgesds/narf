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

/// Six-GHz additions to [`base`]: LMT_6GHZ {bw, nt, rs, bf, regd, reg6,
/// ch_idx, v}, LMT_RU_6GHZ {ru, nt, regd, reg6, ch_idx, v}, a 6GHz TX
/// shape row and a REGD element {alpha2, rule_2g, rule_5g, rule_6g, fmap}.
fn six_set(regd: bool) -> Vec<Element> {
    let mut set = base(0, 10);
    set.push(elm(
        ID_BYRATE,
        0,
        9,
        &[&byr(2, 0, RS_OFDM, 0, &[16, 18, 20, 22])],
    ));
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
    if regd {
        set.push(elm(
            ID_REGD,
            0,
            9,
            &[
                &[b'U', b'S', 2, 2, 2],
                &[b'G', b'B', 14, 14, 14],
                &[b'B', b'O', 2, 2, NA],
            ],
        ));
    }
    set
}

fn smoke_rtw8852c_6ghz_txpwr_follows_rtw89_regd_and_phy_6g() -> TestResult {
    use narf_wireless::reg::PowerType6Ghz;
    let set = six_set(true);
    // regd.c 6GHz policy without the rtw89 ACPI DSM.
    let us = SixGhzPower::new(&set, *b"US", Some(PowerType6Ghz::Lpi));
    let gb = SixGhzPower::new(&set, *b"GB", Some(PowerType6Ghz::Sp));
    if us.map(|p| (p.regd(), p.power())) != Ok((2, 1))
        || gb.map(|p| (p.regd(), p.power())) != Ok((ETSI, 2))
        || SixGhzPower::new(&set, *b"US", Some(PowerType6Ghz::Vlp)) != Err(Error::Policy)
        || SixGhzPower::new(&set, *b"US", None).map(|p| p.power()) != Ok(0)
        || SixGhzPower::new(&set, *b"BO", Some(PowerType6Ghz::Lpi)) != Err(Error::Policy)
        || SixGhzPower::new(&set, *b"ZZ", Some(PowerType6Ghz::Lpi)) != Err(Error::Policy)
        || SixGhzPower::new(&six_set(false), *b"US", Some(PowerType6Ghz::Lpi)) != Err(Error::Table)
    {
        return TestResult::Fail("C 6GHz regd/power-type policy differs from rtw89 regd.c");
    }
    let (Ok(us), Ok(gb)) = (us, gb) else {
        return TestResult::Fail("C 6GHz power context refused");
    };
    let Some(ch37) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 refused");
    };
    let Ok(plan) = Plan::from_elements_6ghz(&set, 5, ch37, us, None) else {
        return TestResult::Fail("C 6GHz LPI power plan refused");
    };
    let (byrate, _, limit, ru, _) = plan.parts();
    // byr[6G]: OFDM 16/18/20/22 rf -> 8/9/10/11 mac; CCK still from 2.4GHz.
    if byrate[4..8] != [8, 9, 10, 11]
        || byrate[0] != 5
        || limit[0][4] != 15
        || limit[0][6] != 12
        || ru[0][0] != 11
        || ru[0][8] != 10
    {
        return TestResult::Fail("C 6GHz limits differ from rtw89_phy_read_txpwr_limit(6G)");
    }
    let mut dfir = 0;
    if plan
        .visit(|a, _, _| {
            dfir += usize::from((0x1_45bc..=0x1_45d8).contains(&a));
            Ok(())
        })
        .is_err()
        || dfir != 0
    {
        return TestResult::Fail("C 6GHz program wrote the 2.4GHz CCK DFIR");
    }
    // 320MHz: Linux phy.c has no 320MHz TX power limit fill
    // (`rtw89_phy_fill_txpwr_limit_ax` / `_ru_ax` switch on 20/40/80/160
    // only), so the 320MHz limit and RU pages stay zero.
    let Some(wide320) = Profile::new_wide(Band::Ghz6, 29, Width::Mhz320) else {
        return TestResult::Fail("6GHz 320MHz profile refused");
    };
    let Ok(plan320) = Plan::from_elements_6ghz(&set, 5, wide320, us, None) else {
        return TestResult::Fail("C 6GHz 320MHz power plan refused");
    };
    let (_, _, limit320, ru320, _) = plan320.parts();
    if limit320.iter().flatten().any(|&v| v != 0) || ru320.iter().flatten().any(|&v| v != 0) {
        return TestResult::Fail("C 6GHz 320MHz limit/RU page is not zero");
    }
    // STD with a TPE: min3 with dbm_to_mac(5) = 10; the bound identity
    // stays the TPE-free plan's; TPE is refused off STD or below -10dBm.
    let (Ok(sp), Ok(bare)) = (
        Plan::from_elements_6ghz(&set, 5, ch37, gb, Some(5)),
        Plan::from_elements_6ghz(&set, 5, ch37, gb, None),
    ) else {
        return TestResult::Fail("C 6GHz SP power plan refused");
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
        return TestResult::Fail("C 6GHz TPE constraint differs from rtw89_phy_get_tpe_constraint");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_6ghz_txpwr_follows_rtw89_regd_and_phy_6g
);

/// rtw8851b.c `rtw8851b_set_txpwr` + `rtw8851b_set_txpwr_ctrl` from the
/// same firmware elements: nss0-only byrate, 1TX limit/RU pages, the
/// 2.4GHz DFIR and OFDM triangular shape, path-A reference only.
fn smoke_rtw89_n51_set_txpwr_follows_rtw8851b_and_phy_ax() -> TestResult {
    use super::super::operating_channel::{Profile as BProfile, Width as BWidth};
    use narf_wireless::association::channel::Band as WBand;
    let set = base(0, 10);
    let (Some(ch6), Some(ch14), Some(a80)) = (
        BProfile::new(WBand::Ghz2, 6),
        BProfile::new(WBand::Ghz2, 14),
        BProfile::new_5ghz(36, BWidth::Mhz80),
    ) else {
        return TestResult::Fail("RTL8851B power test profiles refused");
    };
    let Ok(plan) = Plan::from_elements_51(&set, 5, ch6) else {
        return TestResult::Fail("RTL8851B power elements refused");
    };
    let mut writes = Vec::new();
    if plan
        .visit_51(|a, m, v| {
            writes.push((a, m, v));
            Ok(())
        })
        .is_err()
    {
        return TestResult::Fail("RTL8851B power visit failed");
    }
    let by_rate = writes
        .iter()
        .filter(|w| (0xd2c0..0xd2ec).contains(&w.0))
        .count();
    let lmt = writes
        .iter()
        .filter(|w| (0xd2ec..0xd33c).contains(&w.0))
        .count();
    let ru = writes
        .iter()
        .filter(|w| (0xd33c..0xd36c).contains(&w.0))
        .count();
    if by_rate != 7 || lmt != 10 || ru != 6 {
        return TestResult::Fail("RTL8851B byrate/limit/RU are not the nss0 / 1TX pages");
    }
    // First byrate word: CCK [5, 1, 2, 3]; first limit word cck_20m 40>>1.
    if writes[0] != (0xd2c0, u32::MAX, u32::from_le_bytes([5, 1, 2, 3]))
        || !writes.contains(&(0xd2ec, u32::MAX, 20))
    {
        return TestResult::Fail("RTL8851B byrate / limit values differ");
    }
    // 2.4GHz shape: CCK idx 1 (sharp), OFDM idx 0.
    if !writes.contains(&(0x12300, u32::MAX, 0x023d_83ff))
        || !writes.contains(&(0x14494, 0x0300_0000, 0))
    {
        return TestResult::Fail("RTL8851B tx shape differs from rtw8851b_set_tx_shape");
    }
    let refs: Vec<_> = writes
        .iter()
        .filter(|w| matches!(w.0, 0xd200 | 0x15804 | 0x15808 | 0x17804 | 0x17808))
        .collect();
    if refs
        != [
            &(0xd200, 0x0fff_fc00, 0),
            &(0x15804, 0x07ff_ffff, (172 << 18) | (312 << 9)),
            &(0x15808, 0x07ff_ffff, (172 << 18) | (312 << 9)),
        ]
        || writes
            .iter()
            .any(|w| matches!(w.0, 0x156cc | 0x176cc | 0x158f8 | 0x178f8))
    {
        return TestResult::Fail("RTL8851B reference / C-only writes differ");
    }
    // Channel 14 takes sharp_14; 5GHz has no DFIR.
    let mut dfir = Vec::new();
    let ok14 = Plan::from_elements_51(&set, 5, ch14).and_then(|p| {
        p.visit_51(|a, _, v| {
            dfir.push((a, v));
            Ok(())
        })
    });
    if ok14.is_err() || !dfir.contains(&(0x12300, 0x023b_13ff)) {
        return TestResult::Fail("RTL8851B channel 14 DFIR differs");
    }
    let mut five = Vec::new();
    let ok80 = Plan::from_elements_51(&set, 0, a80).and_then(|p| {
        p.visit_51(|a, _, _| {
            five.push(a);
            Ok(())
        })
    });
    if ok80.is_err() || five.contains(&0x12300) {
        return TestResult::Fail("RTL8851B 5GHz 80MHz plan refused or wrote DFIR");
    }
    // Missing TX_SHAPE_LMT: no static rtw89_8851b_dflt_parms fallback.
    let partial: Vec<_> = set
        .into_iter()
        .filter(|e| e.id != ID_TX_SHAPE_LMT)
        .collect();
    if Plan::from_elements_51(&partial, 5, ch6).is_ok() {
        return TestResult::Fail("RTL8851B power accepted a container without TX_SHAPE_LMT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_set_txpwr_follows_rtw8851b_and_phy_ax
);
