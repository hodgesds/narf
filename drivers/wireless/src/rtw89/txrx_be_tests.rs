// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the BE TXWD/RXD codecs. Expected words are computed
//! in the test from the Linux `txrx.h` bit positions, never by calling
//! the encoder under test — so a shift error in production cannot be
//! masked by the same error in the fixture.

use super::txrx_be::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_be_txwd_encode() -> TestResult {
    // All-ones field values: any shift/mask error changes the word.
    let info = TxwdBeInfo {
        channel: 0xF,
        qsel: 0x3F,
        mac_id: 0x3FF,
        pkt_size: 0x3FFF,
    };
    let mut out = [0u8; 32];
    if encode_txwd_be(&info, &mut out).is_none() {
        return TestResult::Fail("BE TXWD encode rejected a 32-byte buffer");
    }
    // dword0 = WDINFO_EN (bit 22) | CH_DMA (bits 19..16).
    let dw0 = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    if dw0 != (1 << 22) | (0xF << 16) {
        return TestResult::Fail("BE TXWD dword0 routing bits wrong");
    }
    // dword1 zeroed (aggregation/security left to firmware defaults).
    if out[4..8] != [0, 0, 0, 0] {
        return TestResult::Fail("BE TXWD dword1 must be zeroed");
    }
    // dword2 = TXPKTSIZE (13..0) | QSEL_V1 (20..15) | MACID_V1 (31..22).
    // With all-ones fields this must be all-ones: a wrong _V1 shift
    // (e.g. the AX QSEL 22..17 / MACID 31..24 positions) breaks it.
    let dw2 = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
    if dw2 != 0xFFFF_FFFF {
        return TestResult::Fail("BE TXWD dword2 _V1 fields wrong");
    }
    if out[12..32] != [0; 20] {
        return TestResult::Fail("BE TXWD dwords 3..7 must be zeroed");
    }
    // A second, sparse case pins each field independently.
    let info = TxwdBeInfo {
        channel: 3,
        qsel: 7,
        mac_id: 5,
        pkt_size: 100,
    };
    let mut out = [0u8; 32];
    if encode_txwd_be(&info, &mut out).is_none() {
        return TestResult::Fail("BE TXWD sparse encode failed");
    }
    let dw0 = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    let dw2 = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
    if dw0 != (1 << 22) | (3 << 16) || dw2 != 100 | (7 << 15) | (5 << 22) {
        return TestResult::Fail("BE TXWD sparse fields wrong");
    }
    // Short buffer is rejected, not truncated.
    if encode_txwd_be(&info, &mut out[..31]).is_some() {
        return TestResult::Fail("BE TXWD encode accepted a short buffer");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_txwd_encode);

fn smoke_rtw89_be_rxd_decode() -> TestResult {
    // Words built by hand from txrx.h BE_RXD positions.
    let dw0: u32 = 1500 // RPKT_LEN 13..0
        | (2 << 14) // SHIFT 15..14
        | (1 << 18) // DRV_INFO_SZ 19..18
        | (3 << 20) // HDR_CNV_SZ 21..20
        | (2 << 22) // PHY_RPT_SZ 23..22
        | (4 << 24); // RPKT_TYPE 29..24
    let dw2: u32 = 0x1A5 // MAC_ID_V1 9..0
        | (1 << 12) // LAST_MSDU
        | (1 << 15) // REORDER
        | (0xABC << 16) // SEQ 27..16
        | (9 << 28); // TID 31..28
    let dw3: u32 = (1 << 6) // CRC32_ERR
        | (1 << 8) // HW_DEC
        | (1 << 10) // A1_MATCH
        | (1 << 11); // AMPDU
    let dw5: u32 = 0xDEAD_BEEF;
    let mut bytes = [0u8; 24];
    bytes[0..4].copy_from_slice(&dw0.to_le_bytes());
    bytes[8..12].copy_from_slice(&dw2.to_le_bytes());
    bytes[12..16].copy_from_slice(&dw3.to_le_bytes());
    bytes[20..24].copy_from_slice(&dw5.to_le_bytes());
    let info = match decode_rxd_be(&bytes) {
        Some(info) => info,
        None => return TestResult::Fail("BE RXD decode rejected a 24-byte buffer"),
    };
    if info.pkt_len != 1500
        || info.pkt_type != 4
        || info.shift != 2
        || info.drv_info_sz != 1
        || info.hdr_cnv_sz != 3
        || info.phy_rpt_sz != 2
    {
        return TestResult::Fail("BE RXD dword0 fields wrong");
    }
    if info.mac_id != 0x1A5
        || !info.last_msdu
        || info.amsdu_cut
        || !info.reorder
        || info.seq != 0xABC
        || info.tid != 9
    {
        return TestResult::Fail("BE RXD dword2 fields wrong");
    }
    if !info.crc32_err
        || info.icv_err
        || !info.hw_dec
        || info.sw_dec
        || !info.a1_match
        || !info.ampdu
    {
        return TestResult::Fail("BE RXD dword3 flags wrong");
    }
    if info.freerun_cnt != 0xDEAD_BEEF {
        return TestResult::Fail("BE RXD freerun counter wrong");
    }
    // The AX MAC_ID position (7..0) would also read 0xA5 here; the V1
    // 10-bit read (0x1A5) defeats that confusion.
    if decode_rxd_be(&bytes[..23]).is_some() {
        return TestResult::Fail("BE RXD decode accepted a short buffer");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_rxd_decode);

fn smoke_rtw89_be_txwd_info_eht_fields() -> TestResult {
    // Bit positions pinned from txrx.h, computed here, never by
    // calling the encoder: SWITCH bit 20, NLTF bits 22:21,
    // UL_EHT_USR_PRES bit 16.
    if INFO4_SW_EHT_NLTF_SWITCH != (1 << 20)
        || INFO4_SW_EHT_NLTF_MASK != (0x3 << 21)
        || INFO7_UL_EHT_USR_PRES != (1 << 16)
    {
        return TestResult::Fail("BE TXWD info EHT bit positions wrong");
    }
    // Fail-closed defaults: no override, no UL user -> (0, 0).
    if eht_info_fields(false, 0, false) != Some((0, 0)) {
        return TestResult::Fail("BE TXWD info EHT defaults must be (0, 0)");
    }
    // Switch + NLTF 2 + UL user: info4 = (1<<20)|(2<<21) = 0x500000,
    // info7 = 1<<16.
    if eht_info_fields(true, 2, true) != Some((0x50_0000, 0x1_0000)) {
        return TestResult::Fail("BE TXWD info EHT full case wrong");
    }
    // Switch alone: only bit 20.
    if eht_info_fields(true, 0, false) != Some((0x10_0000, 0)) {
        return TestResult::Fail("BE TXWD info EHT switch-only wrong");
    }
    // Bits are encoded as given even with the switch clear (the
    // caller controls both; firmware honors NLTF when SWITCH is set).
    if eht_info_fields(false, 2, false) != Some((0x40_0000, 0)) {
        return TestResult::Fail("BE TXWD info EHT switch-clear NLTF wrong");
    }
    // Out-of-range NLTF fails closed, never truncated to 2 bits.
    if eht_info_fields(true, 4, true).is_some() {
        return TestResult::Fail("BE TXWD info EHT must reject NLTF > 3");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_txwd_info_eht_fields
);

fn smoke_rtw89_be_txwd_info_v2_fill() -> TestResult {
    // All-ones inputs (within each field's width): any shift/mask
    // error changes a word. Expected words computed from the
    // Linux txrx.h bit positions, not from the fill under test.
    let info = TxwdInfoV2 {
        stbc: true,
        ldpc: true,
        dis_data_fb: true,
        port: 7,
        tx_cnt_lmt_en: true,
        tx_cnt_lmt: 0x3F,
        ampdu_num: 0xFF,
        a_ctrl_bsr: true,
        data_retry_lowest_rate: 0xFFF,
        sn: 0xF,
        ampdu_density: 7,
        sec_en: true,
        sec_cam_idx: 0xFF,
        report: true,
        is_bmc: false,
        nltf_switch: true,
        nltf: 3,
        ul_eht_usr_pres: true,
    };
    let mut out = [0u8; 32];
    if fill_txwd_info_v2(&info, &mut out).is_none() {
        return TestResult::Fail("TXWD_INFO v2 fill rejected valid inputs");
    }
    let dw = |o: &[u8], i: usize| u32::from_le_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
    // info0 = STBC | LDPC | DISDATAFB | PORT(6:4) | TXCNT_LMT_SEL |
    // TXCNT_LMT(21:16).
    let want0: u32 = (1 << 12) | (1 << 11) | (1 << 10) | (7 << 4) | (1 << 22) | (0x3F << 16);
    if dw(&out, 0) != want0 {
        return TestResult::Fail("TXWD_INFO info0 fields wrong");
    }
    // info1 = MAX_AGG_NUM | A_CTRL_BSR | DATA_RTY_LOWEST_RATE |
    // SW_DEFINE.
    let want1: u32 = 0xFF | (1 << 14) | (0xFFF << 16) | (0xF << 28);
    if dw(&out, 4) != want1 {
        return TestResult::Fail("TXWD_INFO info1 fields wrong");
    }
    // info2 = AMPDU_DENSITY | FORCE_KEY_EN | SEC_CAM_IDX | SPE_RPT_V1.
    let want2: u32 = (7 << 18) | (1 << 8) | 0xFF | (1 << 30);
    if dw(&out, 8) != want2 {
        return TestResult::Fail("TXWD_INFO info2 fields wrong");
    }
    // info3 zero (no Linux fill site).
    if dw(&out, 12) != 0 {
        return TestResult::Fail("TXWD_INFO info3 must stay zero");
    }
    // info4 = RTS_EN (unicast) | HW_RTS_EN | EHT NLTF switch + NLTF 3.
    let want4: u32 = (1 << 27) | (1 << 31) | (1 << 20) | (3 << 21);
    if dw(&out, 16) != want4 {
        return TestResult::Fail("TXWD_INFO info4 fields wrong");
    }
    // info5/6 zero (no Linux fill site).
    if dw(&out, 20) != 0 || dw(&out, 24) != 0 {
        return TestResult::Fail("TXWD_INFO info5/6 must stay zero");
    }
    // info7 = UL_EHT_USR_PRES only.
    if dw(&out, 28) != 1 << 16 {
        return TestResult::Fail("TXWD_INFO info7 fields wrong");
    }
    // Default (unicast, no overrides): only RTS_EN + HW_RTS_EN.
    let mut out = [0u8; 32];
    if fill_txwd_info_v2(&TxwdInfoV2::default(), &mut out).is_none() {
        return TestResult::Fail("TXWD_INFO v2 fill rejected defaults");
    }
    if dw(&out, 0) != 0 || dw(&out, 4) != 0 || dw(&out, 8) != 0 || dw(&out, 12) != 0 {
        return TestResult::Fail("TXWD_INFO default info0..3 must be zero");
    }
    if dw(&out, 16) != (1 << 27) | (1 << 31) {
        return TestResult::Fail("TXWD_INFO default info4 must be RTS_EN|HW_RTS_EN");
    }
    if dw(&out, 20) != 0 || dw(&out, 24) != 0 || dw(&out, 28) != 0 {
        return TestResult::Fail("TXWD_INFO default info5..7 must be zero");
    }
    // Broadcast: RTS_EN clears, HW_RTS_EN stays.
    let mut info = TxwdInfoV2::default();
    info.is_bmc = true;
    let mut out = [0u8; 32];
    if fill_txwd_info_v2(&info, &mut out).is_none() {
        return TestResult::Fail("TXWD_INFO v2 fill rejected broadcast");
    }
    if dw(&out, 16) != 1 << 31 {
        return TestResult::Fail("TXWD_INFO broadcast info4 must be HW_RTS_EN only");
    }
    // Fail-closed: each overflowing field refuses, never truncates.
    let mut out = [0u8; 32];
    let mut bad = TxwdInfoV2::default();
    bad.port = 8;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject port > 7");
    }
    let mut bad = TxwdInfoV2::default();
    bad.tx_cnt_lmt = 0x40;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject tx_cnt_lmt > 63");
    }
    let mut bad = TxwdInfoV2::default();
    bad.data_retry_lowest_rate = 0x1000;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject data_retry_lowest_rate > 4095");
    }
    let mut bad = TxwdInfoV2::default();
    bad.sn = 0x10;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject sn > 15");
    }
    let mut bad = TxwdInfoV2::default();
    bad.ampdu_density = 8;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject ampdu_density > 7");
    }
    let mut bad = TxwdInfoV2::default();
    bad.sec_cam_idx = 0x100;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject sec_cam_idx > 255");
    }
    let mut bad = TxwdInfoV2::default();
    bad.nltf = 4;
    if fill_txwd_info_v2(&bad, &mut out).is_some() {
        return TestResult::Fail("TXWD_INFO must reject nltf > 3");
    }
    // Short buffer refuses.
    if fill_txwd_info_v2(&TxwdInfoV2::default(), &mut out[..31]).is_some() {
        return TestResult::Fail("TXWD_INFO must reject a short buffer");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_txwd_info_v2_fill);
