// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AP-role TXWD: MACID/QSEL/CH9/port placement against core.c/txrx.h.
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
const PEER: [u8; 6] = [2, 9, 8, 7, 6, 5];

fn header(fc: [u8; 2], a1: [u8; 6], a3: [u8; 6], tail: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    bytes[..2].copy_from_slice(&fc);
    bytes[4..10].copy_from_slice(&a1);
    bytes[10..16].copy_from_slice(&OWN);
    bytes[16..22].copy_from_slice(&a3);
    bytes[22..24].copy_from_slice(&0x0120u16.to_le_bytes());
    bytes.extend_from_slice(tail);
    bytes
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn tx(mac_id: u8, port: u8, after_dtim: bool, rate: u8) -> ApTx {
    ApTx {
        mac_id,
        port,
        after_dtim,
        report: true,
        rate,
    }
}

fn smoke_rtw89_ap_txwd_macid_qsel_port_and_rates() -> TestResult {
    // FromDS QoS DATA TID5 to MACID3: VI_0 on ACH2, firmware RA.
    let mut qos = header([0x88, 0x02], PEER, [2, 0, 0, 0, 0, 7], &[5, 0]);
    qos.extend_from_slice(&[0xaa; 40]);
    let Ok((txwd, queue)) = transmit_ap(&qos, OWN, tx(3, 0, false, FIRMWARE_RA), 7, 0x1000) else {
        return TestResult::Fail("AP QoS data refused");
    };
    if queue != Queue::Video
        || (word(&txwd, 0) >> 16) & 0xf != 2
        || word(&txwd, 0) & 0xf != 0
        || word(&txwd, 8) >> 24 & 0x7f != 3
        || (word(&txwd, 8) >> 17) & 0x3f != 2
        || word(&txwd, 24) & (1 << 30 | 0x70) != 0
        || word(&txwd, 36) & (1 << 10) == 0
        || word(&txwd, 40) & (1 << 27) == 0
    {
        return TestResult::Fail("RTW89_TXWD_BODY0/2 MACID/QSEL/CH_DMA or INFO0/3/4");
    }
    // Group data after DTIM on port2: B0_HI / CH9, MULTIPORT_ID, no RTS.
    let group = header([0x08, 0x02], [0xff; 6], [2, 0, 0, 0, 0, 7], &[0xbb; 30]);
    let Ok((txwd, queue)) = transmit_ap(&group, OWN, tx(0, 2, true, 0), 8, 0x1000) else {
        return TestResult::Fail("after-DTIM group data refused");
    };
    if queue != Queue::High
        || queue.channel() != 9
        || queue.stop_bit() != STOP_CH9
        || (word(&txwd, 0) >> 16) & 0xf != 9
        || (word(&txwd, 8) >> 17) & 0x3f != 0x11
        || (word(&txwd, 24) >> 4) & 7 != 2
        || word(&txwd, 24) & (1 << 30) == 0
        || word(&txwd, 40) & (1 << 27) != 0
    {
        return TestResult::Fail("HIQ qsel/channel/port or group RTS_EN");
    }
    // Probe response to an unbound peer: B0_MGMT, HW SSN sel1/mode1, fixed.
    let probe = header([0x50, 0], PEER, OWN, &[0; 20]);
    let Ok((txwd, queue)) = transmit_ap(&probe, OWN, tx(0, 0, false, OFDM6), 9, 0x1000) else {
        return TestResult::Fail("probe response refused");
    };
    if queue != Queue::Management
        || word(&txwd, 0) & 0xf != 5
        || (word(&txwd, 24) >> 16) & 0x1ff != u32::from(OFDM6)
        || (word(&txwd, 24) >> 4) & 7 != 0
    {
        return TestResult::Fail("AP management TXWD");
    }
    // EOSP QoS-Null (U-APSD end of SP) is MGMT type in rtw89.
    let null = header([0xc8, 0x22], PEER, OWN, &[0x17, 0]);
    if transmit_ap(&null, OWN, tx(4, 0, false, 0), 10, 0x1000).map(|r| r.1) != Ok(Queue::Management)
    {
        return TestResult::Fail("EOSP QoS-Null with MoreData");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_txwd_macid_qsel_port_and_rates
);

fn smoke_rtw89_ap_txwd_refuses_station_and_misplaced_frames() -> TestResult {
    let qos = header([0x88, 0x02], PEER, [2, 0, 0, 0, 0, 7], &[0, 0, 1, 2, 3, 4]);
    let tods = header([0x08, 0x01], PEER, PEER, &[1, 2, 3]);
    let group = header([0x08, 0x02], [0xff; 6], PEER, &[1, 2, 3]);
    let group_probe = header([0x50, 0], [0xff; 6], OWN, &[0; 12]);
    let mut foreign = qos.clone();
    foreign[10] ^= 2;
    let mut frag = qos.clone();
    frag[1] |= 0x04;
    let cases: [(&[u8], ApTx, &str); 9] = [
        (&tods, tx(1, 0, false, 0), "ToDS data from an AP"),
        (&qos, tx(1, 0, true, 0), "unicast after DTIM"),
        (&qos, tx(1, 1, false, 0), "port without HIQ"),
        (&group, tx(0, 0, false, FIRMWARE_RA), "group firmware RA"),
        (&group_probe, tx(0, 0, false, 0), "group probe response"),
        (&foreign, tx(1, 0, false, 0), "foreign TA"),
        (&frag, tx(1, 0, false, 0), "MoreFrag"),
        (&qos, tx(128, 0, false, 0), "MACID out of range"),
        (&qos, tx(1, 0, false, DATA_ER | FIRMWARE_RA), "ER SU"),
    ];
    for (frame, tx, why) in cases {
        if transmit_ap(frame, OWN, tx, 1, 0x1000).is_ok() {
            return TestResult::Fail(why);
        }
    }
    let mut mgmt = header([0xb0, 0], PEER, OWN, &[0; 6]);
    if transmit_ap(&mgmt, OWN, tx(0, 0, false, FIRMWARE_RA), 1, 0x1000).is_ok() {
        return TestResult::Fail("management with firmware RA");
    }
    mgmt[16] ^= 2;
    if transmit_ap(&mgmt, OWN, tx(0, 0, false, 0), 1, 0x1000).is_ok() {
        return TestResult::Fail("management BSSID other than the AP");
    }
    // The station formatter still refuses every AP-only form.
    if classify(&qos, OWN).is_ok() || classify(&group, OWN).is_ok() {
        return TestResult::Fail("station formatter admitted FromDS");
    }
    if ap_queues(false) != [Queue::Data, Queue::Management, Queue::High]
        || AP_STOP_ALL & !STOP_ALL != STOP_CH9
    {
        return TestResult::Fail("AP ring set / stop mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_txwd_refuses_station_and_misplaced_frames
);
