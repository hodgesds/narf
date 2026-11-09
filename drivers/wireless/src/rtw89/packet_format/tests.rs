use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn smoke_rtw89_he_htc_txwd_uses_full_header_and_checks_control() -> TestResult {
    let mut bytes = frame(100, false);
    bytes[..2].copy_from_slice(&[0x88, 0xc1]);
    bytes[24..30].copy_from_slice(&[0x10, 0, 0x1b, 0, 0, 0]);
    bytes[30..38].copy_from_slice(&[1, 0, 0, 0x20, 0, 0, 0, 0]);
    let Ok((header, _)) = transmit_rate(&bytes, OWN, 0, 0, 0x1000, true, FIRMWARE_RA) else {
        return TestResult::Fail("native HE +HTC host CCMP rejected");
    };
    let body0 = u32::from_le_bytes(header[..4].try_into().unwrap());
    if (body0 >> 11) & 31 != 15
        || header[16..24] != [0; 8]
        || u32::from_le_bytes(header[28..32].try_into().unwrap()) & (1 << 14) == 0
    {
        return TestResult::Fail("TXWD +HTC header length or hardware security fields");
    }
    for (index, value) in [(0, 8), (24, 0), (26, 0), (32, 1), (33, 0)] {
        let mut bad = bytes.clone();
        bad[index] = value;
        if transmit_rate(&bad, OWN, 0, 0, 0x1000, true, FIRMWARE_RA).is_ok() {
            return TestResult::Fail("malformed HE +HTC or wrong CCMP offset admitted");
        }
    }
    if transmit_rate(&bytes, OWN, 0, 0, 0x1000, true, 0).is_ok()
        || classify(&bytes[..29], OWN).is_ok()
    {
        return TestResult::Fail("fixed legacy rate or incomplete +HTC admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/htc",
    smoke_rtw89_he_htc_txwd_uses_full_header_and_checks_control
);
fn frame(length: usize, management: bool) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..2].copy_from_slice(if management { &[0xb0, 0] } else { &[8, 1] });
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[10..16].copy_from_slice(&OWN);
    bytes[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    bytes
}
fn smoke_rtw89_b_packet_full_wd_info_matches_frozen_references() -> TestResult {
    for (index, expected) in HEADERS.iter().enumerate() {
        let bytes = frame(if index < 2 { 100 } else { 2304 }, index & 1 != 0);
        let result = transmit(
            &bytes,
            OWN,
            0,
            if index == 3 { 511 } else { index as u16 },
            if index >= 2 {
                0xf_1234_5000
            } else {
                0x1234_5000
            },
            index >= 2,
        );
        if result.as_ref().map(|(bytes, _)| bytes.as_slice()) != Ok(expected.as_slice()) {
            return TestResult::Fail(
                "B full body/info/WP/address-info differs from the frozen reference",
            );
        }
    }
    if descriptor(0xf_1234_5000) != Ok([64, 0, 0xc0, 0x43, 0, 0x50, 0x34, 0x12]) {
        return TestResult::Fail("B TXBD header-only extent or upper address/LS bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_full_wd_info_matches_frozen_references
);

fn smoke_rtw89_b_packet_raw_ccmp_extents_and_36bit_limits() -> TestResult {
    let mut bytes = frame(100, false);
    bytes[1] |= 64;
    // Nonzero PN, reserved byte zero, ExtIV set, pairwise key0.
    bytes[24..32].copy_from_slice(&[1, 0, 0, 0x20, 0, 0, 0, 0]);
    let Ok((header, _)) = transmit(&bytes, OWN, 0, 0, 0x1000, false) else {
        return TestResult::Fail("exact non-QoS host CCMP was rejected");
    };
    if header[16..24] != [0; 8] || header[32..36] != [0; 4] || header[3] != 0 {
        return TestResult::Fail("raw CCMP enabled hardware key/IV insertion");
    }
    for index in [0, 1, 22, 26, 27] {
        let mut bad = bytes.clone();
        match index {
            0 => bad[0] = 0x88,
            1 => bad[1] |= 2,
            22 => bad[22] |= 1,
            26 => bad[26] = 1,
            27 => bad[27] &= !0x20,
            _ => unreachable!(),
        }
        if transmit(&bad, OWN, 0, 0, 0x1000, false).is_ok() {
            return TestResult::Fail("raw CCMP accepted optional header or malformed IV");
        }
    }
    for length in [24, 31, 39, 47] {
        if transmit(&bytes[..length], OWN, 0, 0, 0x1000, false).is_ok() {
            return TestResult::Fail("raw CCMP accepted truncated IV/MIC/ciphertext");
        }
    }
    for address in [0, 0x1001, 0x10_0000_0000, DMA_MASK - 3] {
        if transmit(&bytes, OWN, 0, 0, address, false).is_ok() {
            return TestResult::Fail("B packet accepted invalid36-bit complete DMA extent");
        }
    }
    if transmit(&bytes, OWN, 1, 0, 0x1000, false).is_ok()
        || transmit(&bytes, OWN, 0, 512, 0x1000, false).is_ok()
    {
        return TestResult::Fail("packet profile widened MACID or native WD-page identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_raw_ccmp_extents_and_36bit_limits
);

fn smoke_rtw89_b_packet_qos_tid_selects_ach_qsel_and_tid_indicate() -> TestResult {
    // (TID, channel, QSEL, TID_INDICATE) per rtw89_core_get_qsel,
    // rtw89_core_get_ch_dma and rtw89_core_get_tid_indicate.
    let table: [(u8, u8, u8, bool); 8] = [
        (0, 0, 0, false),
        (1, 1, 1, false),
        (2, 1, 1, true),
        (3, 0, 0, true),
        (4, 2, 2, false),
        (5, 2, 2, true),
        (6, 3, 3, false),
        (7, 3, 3, true),
    ];
    for (tid, channel, qsel, indicate) in table {
        let mut bytes = frame(100, false);
        bytes[0] = 0x88;
        bytes[24] = tid;
        let Ok((header, queue)) = transmit_rate(&bytes, OWN, 0, 1, 0x1000, false, 11) else {
            return TestResult::Fail("QoS TID frame rejected");
        };
        let body0 = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let body2 = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        if queue.channel() != channel
            || queue.qsel() != qsel
            || (body0 >> 16) & 0x3f != u32::from(channel)
            || (body2 >> 17) & 0x3f != u32::from(qsel)
            || (body2 >> 23 & 1 == 1) != indicate
            || Queue::for_tid(tid) != queue
        {
            return TestResult::Fail("TID queue/QSEL/TID_INDICATE mapping differs");
        }
    }
    // TID0 keeps the frozen flags7 descriptor bit-for-bit (no indicate bit).
    let mut bytes = frame(100, false);
    bytes[0] = 0x88;
    let Ok((header, _)) = transmit(&bytes, OWN, 0, 1, 0x1000, false) else {
        return TestResult::Fail("BE/TID0 frame rejected");
    };
    if header[11] & 0x80 != 0 {
        return TestResult::Fail("TID0 gained TID_INDICATE");
    }
    // TID8..15, EOSP, ack policy and A-MSDU-present bits stay rejected.
    for control in [8u8, 0x10, 0x20, 0x80] {
        let mut bad = bytes.clone();
        bad[24] = control;
        if transmit(&bad, OWN, 0, 1, 0x1000, false).is_ok() {
            return TestResult::Fail("optional QoS control bits accepted");
        }
    }
    let mut bad = bytes.clone();
    bad[25] = 1;
    if transmit(&bad, OWN, 0, 1, 0x1000, false).is_ok() {
        return TestResult::Fail("QoS control high byte accepted");
    }
    if Queue::ordinary(false).len() != 2
        || Queue::ordinary(true)
            .iter()
            .fold(STOP_WPDMA, |m, q| m | q.stop_bit())
            != STOP_ALL
    {
        return TestResult::Fail("ordinary ring set or DMA stop mask differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_qos_tid_selects_ach_qsel_and_tid_indicate
);

fn smoke_rtw89_b_packet_txwd_ampdu_fields() -> TestResult {
    let mut qos = frame(100, false);
    qos[0] = 0x88;
    qos[24..26].fill(0);
    let agg = Agg {
        num: 63,
        density: 5,
    };
    let address = 0x1234_5000;
    let word = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let Ok((plain, _)) = transmit_rate(&qos, OWN, 0, 3, address, false, FIRMWARE_RA | 2) else {
        return TestResult::Fail("plain RA QoS TXWD");
    };
    let Ok((bytes, queue)) =
        transmit_agg(&qos, OWN, 0, 3, address, false, FIRMWARE_RA | 2, Some(agg))
    else {
        return TestResult::Fail("aggregated TXWD refused");
    };
    // BODY3 AGG_EN(12), INFO1 MAX_AGGNUM[7:0] beside DATA_RTY_LOWEST_RATE,
    // INFO2 AMPDU_DENSITY[20:18]; every other byte unchanged.
    let mut expected = plain.clone();
    expected[12..16].copy_from_slice(&(word(&plain, 12) | 1 << 12).to_le_bytes());
    expected[28..32].copy_from_slice(&(2u32 << 16 | 63).to_le_bytes());
    expected[32..36].copy_from_slice(&(5u32 << 18).to_le_bytes());
    if queue != Queue::Data
        || bytes != expected
        || word(&plain, 12) & 1 << 12 != 0
        || word(&plain, 32) != 0
    {
        return TestResult::Fail("TXWD A-MPDU fields differ");
    }
    // Only firmware-RA QoS DATA with a 3-bit density is aggregated.
    let wide = Agg { num: 1, density: 8 };
    let data = frame(100, false);
    let management = frame(100, true);
    if transmit_agg(&data, OWN, 0, 3, address, false, FIRMWARE_RA, Some(agg)).is_ok()
        || transmit_agg(&qos, OWN, 0, 3, address, false, 2, Some(agg)).is_ok()
        || transmit_agg(&qos, OWN, 0, 3, address, false, FIRMWARE_RA, Some(wide)).is_ok()
        || transmit_agg(&management, OWN, 0, 3, address, false, 0, Some(agg)).is_ok()
    {
        return TestResult::Fail("aggregation admitted outside firmware-RA QoS DATA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_txwd_ampdu_fields
);

fn smoke_rtw8852c_packet_txwd_v1_body_info_wp_and_addr_info() -> TestResult {
    let word = |bytes: &[u8], offset: usize| {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    };
    // Fixed-rate (CCK1) authentication on CH8, with a TX report.
    let bytes = frame(100, true);
    let Ok((header, queue)) = transmit_c(&bytes, OWN, 0, 5, 0x1234_5000, true, 0, None) else {
        return TestResult::Fail("C management TXWD refused");
    };
    let mut wp = [0u8; 8];
    wp[..2].copy_from_slice(&0x8005u16.to_le_bytes());
    if queue != Queue::Management
        || header.len() != 70
        // body0 v1: WD_INFO_EN, CH8, HDR_LLC_LEN 12, WD_PAGE; no HW SSN.
        || word(&header, 0) != (1 << 22 | 8 << 16 | 12 << 11 | 1 << 7)
        || word(&header, 4) != 1 << 26
        || word(&header, 8) != (0x12 << 17 | 100)
        || word(&header, 12) != 0x123
        || header[16..28] != [0; 12]
        // body7 v1: USE_RATE_V1 + DATA_RATE (CCK1 = 0).
        || word(&header, 28) != 1 << 31
        // info0 v1: DISDATAFB only; info3 SPE_RPT; info4 HW_RTS_EN|RTS_EN.
        || word(&header, 32) != 1 << 10
        || word(&header, 36) != 0
        || word(&header, 40) != 0
        || word(&header, 44) != 1 << 10
        || word(&header, 48) != (1 << 31 | 1 << 27)
        || word(&header, 52) != 0
        || header[56..64] != wp
        || header[64..66] != (100u16 | 1 << 15).to_le_bytes()
        || word(&header, 66) != 0x1234_5000
    {
        return TestResult::Fail("C v1 body/info/WP/address-info differs from Linux layout");
    }
    // OFDM6 fixed rate lands in body7 DATA_RATE.
    let Ok((header, _)) = transmit_c(&bytes, OWN, 0, 5, 0x1234_5000, false, OFDM6, None) else {
        return TestResult::Fail("C OFDM6 management TXWD refused");
    };
    if word(&header, 28) != (1 << 31 | u32::from(OFDM6) << 16) || word(&header, 44) != 0 {
        return TestResult::Fail("C OFDM6 rate or unrequested report");
    }
    // Firmware-RA non-QoS data on ACH0: no body7 rate, lowest rate in info1.
    let data = frame(2304, false);
    let Ok((header, queue)) = transmit_c(
        &data,
        OWN,
        0,
        7,
        0xf_1234_5000,
        false,
        FIRMWARE_RA | 4,
        None,
    ) else {
        return TestResult::Fail("C firmware-RA data TXWD refused");
    };
    if queue != Queue::Data
        || header.len() != 76
        || word(&header, 0) != (1 << 22 | 12 << 11 | 1 << 7)
        || word(&header, 4) != 2 << 26
        || word(&header, 28) != 0
        || word(&header, 32) != 0
        || word(&header, 36) != 4 << 16
        || header[64..66] != (2044u16 | 0xf << 11).to_le_bytes()
        || header[70..72] != (260u16 | 0xf << 11 | 1 << 15).to_le_bytes()
        || word(&header, 72) != 0x1234_5000 + 2044
    {
        return TestResult::Fail("C firmware-RA data or two-entry address info differs");
    }
    // WMM QoS BE/TID0 data (rtw89_core_fill_txdesc_v1 with sec_en false):
    // the v0 body2/info1 positions, no TID_INDICATE for TID0, no AGG_EN.
    let mut qos = frame(100, false);
    qos[0] = 0x88;
    qos[24..26].fill(0);
    let Ok((header, queue)) = transmit_c(&qos, OWN, 0, 1, 0x1000, false, FIRMWARE_RA | 4, None)
    else {
        return TestResult::Fail("C WMM QoS TID0 TXWD refused");
    };
    if queue != Queue::Data
        || word(&header, 8) & 1 << 23 != 0
        || word(&header, 12) & 1 << 12 != 0
        || word(&header, 28) != 0
        || word(&header, 32) != 0
        || word(&header, 36) != 4 << 16
    {
        return TestResult::Fail("C QoS TXWD differs from rtw89_core_fill_txdesc_v1");
    }
    // Originator A-MPDU (signed C Ampdu program): body3 AGG_EN, info1
    // MAX_AGGNUM, info2 AMPDU_DENSITY at the v0 positions
    // (`rtw89_build_txwd_body3`/`_info1`/`_info2_v1`), plus info0_v1 DATA_ER.
    let agg = Some(Agg {
        num: 63,
        density: 5,
    });
    let Ok((header, _)) = transmit_c(
        &qos,
        OWN,
        0,
        1,
        0x1000,
        false,
        FIRMWARE_RA | DATA_ER | 4,
        agg,
    ) else {
        return TestResult::Fail("C A-MPDU QoS TXWD refused");
    };
    if word(&header, 12) & 1 << 12 == 0
        || word(&header, 32) != 1 << 15
        || word(&header, 36) != (4 << 16 | 63)
        || word(&header, 40) != 5 << 18
        || word(&header, 28) != 0
    {
        return TestResult::Fail("C A-MPDU/ER TXWD differs from rtw89_core_fill_txdesc_v1");
    }
    // A-MSDU QoS, fixed-rate aggregation/ER, non-QoS aggregation and
    // descriptor bounds.
    let mut amsdu = qos.clone();
    amsdu[24] = 0x80;
    if transmit_c(&amsdu, OWN, 0, 1, 0x1000, false, FIRMWARE_RA, None).is_ok()
        || transmit_c(&qos, OWN, 0, 1, 0x1000, false, 4, agg).is_ok()
        || transmit_c(&data, OWN, 0, 1, 0x1000, false, DATA_ER, None).is_ok()
        || transmit_c(&data, OWN, 0, 1, 0x1000, false, FIRMWARE_RA, agg).is_ok()
        || descriptor_len(0xf_1234_5000, 70) != Ok([70, 0, 0xc0, 0x43, 0, 0x50, 0x34, 0x12])
        || descriptor_len(0x1000, C_HEADER_MAX + 1).is_ok()
        || descriptor(0xf_1234_5000) != descriptor_len(0xf_1234_5000, HEADER)
        || Queue::Data.regs_for(ChipId::Rtl8852C).desa_l != 0x1230
        || Queue::Management.regs_for(ChipId::Rtl8852C).desa_l != 0x1270
        || Queue::Data.regs_for(ChipId::Rtl8852C).idx != Queue::Data.regs().idx
    {
        return TestResult::Fail("C refusals, TXBD length or V1 ring registers differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_packet_txwd_v1_body_info_wp_and_addr_info
);

fn smoke_rtw8852a_packet_txwd_matches_b_v0_body_and_refuses_amsdu() -> TestResult {
    // A shares B's AX v0 TXWD body/info/WP/address-info layout, so the
    // frozen B references must reproduce byte-identically through
    // `transmit_a`.
    for (index, expected) in HEADERS.iter().enumerate() {
        let bytes = frame(if index < 2 { 100 } else { 2304 }, index & 1 != 0);
        let result = transmit_a(
            &bytes,
            OWN,
            0,
            if index == 3 { 511 } else { index as u16 },
            if index >= 2 {
                0xf_1234_5000
            } else {
                0x1234_5000
            },
            index >= 2,
            0,
            None,
        );
        if result.as_ref().map(|(bytes, _)| bytes.as_slice()) != Ok(expected.as_slice()) {
            return TestResult::Fail(
                "A full body/info/WP/address-info differs from the frozen B reference",
            );
        }
    }
    // A-MSDU QoS (control bit 0x80) has no A program; the 36-bit DMA mask
    // binds A like B; the AX ring registers are B's.
    let mut qos = frame(100, false);
    qos[0] = 0x88;
    qos[24..26].fill(0);
    let mut amsdu = qos.clone();
    amsdu[24] = 0x80;
    if transmit_a(&amsdu, OWN, 0, 1, 0x1000, false, FIRMWARE_RA, None).is_ok()
        || transmit_a(&qos, OWN, 0, 1, 0x10_0000_0000, false, FIRMWARE_RA, None).is_ok()
        || transmit_a(&qos, OWN, 0, 1, DMA_MASK - 3, false, FIRMWARE_RA, None).is_ok()
        || Queue::Data.regs_for(ChipId::Rtl8852A).desa_l != Queue::Data.regs().desa_l
        || Queue::Management.regs_for(ChipId::Rtl8852A).desa_l != Queue::Management.regs().desa_l
    {
        return TestResult::Fail("A A-MSDU admission, DMA mask or AX ring registers differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_packet_txwd_matches_b_v0_body_and_refuses_amsdu
);
