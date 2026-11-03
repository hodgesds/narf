// SPDX-License-Identifier: GPL-2.0-or-later
//! 5GHz TX A-MSDU admission, RA-report size bound and ADDBA A-MSDU bits.
use super::super::super::packet_format::{
    transmit_profile, Aggregation, DataProfile, Queue, VhtRates, MAX_MPDU, MAX_TX_MPDU,
};
use super::super::super::tx_ba::Originators;
use super::{max_rc_amsdu_len, ra_report_bitrate};
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn ht5() -> DataProfile {
    DataProfile {
        rates: 0xff0,
        qos: true,
        mcs: 0xff,
        rx_mcs: 0xff,
        band5: true,
        ..DataProfile::LEGACY
    }
}
fn qos(length: usize, qc: u8) -> Vec<u8> {
    let mut f = vec![0x5a; length];
    f[..4].copy_from_slice(&[0x88, 0x41, 0, 0]);
    f[4..10].copy_from_slice(&AP);
    f[10..16].copy_from_slice(&OWN);
    f[16..22].copy_from_slice(&AP);
    f[22..24].copy_from_slice(&(7u16 << 4).to_le_bytes());
    f[24..26].copy_from_slice(&[qc, 0]);
    f
}

fn smoke_rtw88_tx_amsdu_descriptor_admission_is_5ghz_only() -> TestResult {
    let p = ht5();
    let big = qos(3800, 0x80);
    let Ok((d, queue)) = transmit_profile(&big, OWN, 0, Some(4), p) else {
        return TestResult::Fail("5GHz HT A-MSDU MPDU above 2304 bytes refused");
    };
    if queue != Queue::Data || u16::from_le_bytes([d[0], d[1]]) != 3800 || d[5] & 0x1f != 0 {
        return TestResult::Fail("A-MSDU length/QSEL from the TID, not the A-MSDU bit");
    }
    let two = DataProfile {
        band5: false,
        rates: 0xfff,
        ..p
    };
    if transmit_profile(&big, OWN, 0, Some(4), two).is_ok()
        || transmit_profile(&qos(300, 0x80), OWN, 0, Some(4), two).is_ok()
    {
        return TestResult::Fail("2.4GHz admitted an A-MSDU (rtw_ops_can_aggregate_in_amsdu)");
    }
    if transmit_profile(&qos(MAX_MPDU + 1, 0), OWN, 0, Some(4), p).is_ok()
        || transmit_profile(&qos(MAX_TX_MPDU + 1, 0x80), OWN, 0, Some(4), p).is_ok()
        || transmit_profile(&qos(MAX_TX_MPDU, 0x80), OWN, 0, Some(4), p).is_err()
        || transmit_profile(&qos(300, 0x90), OWN, 0, Some(4), p).is_ok()
    {
        return TestResult::Fail("MPDU bound: plain 2304, A-MSDU 3891, no EOSP");
    }
    let legacy = DataProfile {
        mcs: 0,
        rx_mcs: 0,
        ..p
    };
    if transmit_profile(&qos(300, 0x80), OWN, 0, Some(4), legacy).is_ok() {
        return TestResult::Fail("A-MSDU without an HT/VHT association");
    }
    TestResult::Pass
}

fn smoke_rtw88_tx_amsdu_ra_report_bounds_max_rc_amsdu_len() -> TestResult {
    // body: id 0x0c, seq, rate_sgi, mac_id, byte2, status, byte4, ratio, bw.
    let report = |rate_sgi: u8, bw: u8| [0x0c, 0, rate_sgi, 0, 0, 0, 0, 0, bw];
    // OFDM54: 54Mbps < 55 -> 1 (no aggregation).
    if ra_report_bitrate(&report(11, 0)) != Some(540) || max_rc_amsdu_len(540) != 1 {
        return TestResult::Fail("legacy rate bound");
    }
    // HT MCS7 SGI20 = 72.2Mbps -> 1200.
    if ra_report_bitrate(&report(0x80 | 19, 0)) != Some(722) || max_rc_amsdu_len(722) != 1200 {
        return TestResult::Fail("HT20 MCS7 SGI");
    }
    // HT MCS15 40MHz SGI = 300Mbps -> 2600.
    if ra_report_bitrate(&report(0x80 | 27, 1)) != Some(3000) || max_rc_amsdu_len(3000) != 2600 {
        return TestResult::Fail("HT40 MCS15 SGI");
    }
    // VHT1SS MCS9 80MHz SGI = 433.3Mbps -> 3500.
    if ra_report_bitrate(&report(0x80 | 0x35, 2)) != Some(4333) || max_rc_amsdu_len(4333) != 3500 {
        return TestResult::Fail("VHT80 1SS MCS9 SGI");
    }
    // VHT2SS MCS9 80MHz LGI = 780Mbps -> unlimited.
    if ra_report_bitrate(&report(0x3f, 2)) != Some(7800) || max_rc_amsdu_len(7800) != 0 {
        return TestResult::Fail("VHT80 2SS MCS9");
    }
    let mut other = report(0x3f, 2);
    other[3] = 1;
    if ra_report_bitrate(&other).is_some()
        || ra_report_bitrate(&report(0x3f, 2)[..8]).is_some()
        || ra_report_bitrate(&report(0x40, 2)).is_some()
    {
        return TestResult::Fail("foreign mac_id / short report / unknown rate");
    }
    TestResult::Pass
}

fn smoke_rtw88_tx_ba_addba_amsdu_request_and_no_amsdu() -> TestResult {
    let mut tx = Originators::new();
    tx.want(0, 1);
    tx.request_amsdu(true);
    if tx.begin(0, OWN, AP, 5, 64, 0).is_err() {
        return TestResult::Fail("request");
    }
    let Some(request) = tx.next() else {
        return TestResult::Fail("request missing");
    };
    let p = u16::from_le_bytes([request[27], request[28]]);
    if p & 3 != 3 || super::super::super::packet_format::originator_control_tid(&request) != Some(0)
    {
        return TestResult::Fail("ADDBA request A-MSDU-supported bit / native admission");
    }
    if tx.submitted(&request).is_err() || !tx.amsdu_allowed(0) {
        return TestResult::Fail("submission");
    }
    // Response for TID0 accepted with A-MSDU not permitted (capab bit0 0).
    let mut response = vec![0xd0, 0, 0, 0];
    response.extend_from_slice(&OWN);
    response.extend_from_slice(&AP);
    response.extend_from_slice(&AP);
    response.extend_from_slice(&[0, 0, 3, 1, request[26], 0, 0, 2, 16, 0, 0]);
    if !tx.response(&response, OWN, AP) || tx.amsdu_allowed(0) || !tx.amsdu_allowed(1) {
        return TestResult::Fail("NO_AMSDU from a response without permission");
    }
    let mut off = Originators::new();
    off.want(0, 1);
    if off.begin(0, OWN, AP, 5, 64, 0).is_err()
        || off
            .next()
            .is_none_or(|r| u16::from_le_bytes([r[27], r[28]]) & 3 != 2)
    {
        return TestResult::Fail("2.4GHz request keeps the A-MSDU bit clear");
    }
    TestResult::Pass
}

fn smoke_rtw88_tx_amsdu_vht_aggregate_airtime_bound() -> TestResult {
    let vht = DataProfile {
        vht: Some(VhtRates {
            tx: 0x3ff,
            rx: 0x3ff,
        }),
        sgi: true,
        ..ht5()
    };
    let cfg = Aggregation {
        density: 0,
        count: 2,
        bytes: 8191,
        airtime: 4000,
    };
    // A VHT rate is bounded by the HT20 MCS7 airtime instead of indexing
    // past the HT table: two 3891-byte A-MSDU subframes fit 8191 bytes and
    // 4ms at 65Mbps; a third subframe exceeds the count.
    if !cfg.admits_lengths(vht, [1600usize, 1600].into_iter())
        || !cfg.admits_lengths(vht, [MAX_TX_MPDU, MAX_TX_MPDU].into_iter())
        || cfg.admits_lengths(vht, [MAX_TX_MPDU, MAX_TX_MPDU, 100].into_iter())
    {
        return TestResult::Fail("VHT A-MPDU airtime bound");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw88/tx_amsdu",
    smoke_rtw88_tx_amsdu_descriptor_admission_is_5ghz_only
);
kernel_test_in!(
    "drivers/wireless/rtw88/tx_amsdu",
    smoke_rtw88_tx_amsdu_ra_report_bounds_max_rc_amsdu_len
);
kernel_test_in!(
    "drivers/wireless/rtw88/tx_amsdu",
    smoke_rtw88_tx_ba_addba_amsdu_request_and_no_amsdu
);
kernel_test_in!(
    "drivers/wireless/rtw88/tx_amsdu",
    smoke_rtw88_tx_amsdu_vht_aggregate_airtime_bound
);
