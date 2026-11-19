// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AP role/join/beacon H2C words and queue placement against fw.c/core.c.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn link() -> ApLink {
    ApLink::new(1, 1, 0, 0).unwrap_or(ApLink {
        mac_id: 0xff,
        port: 0,
        mac_idx: 0,
        wmm: 0,
    })
}

fn smoke_rtw89_ap_wire_role_and_join_words_match_fw_masks() -> TestResult {
    let link = link();
    if link.mac_id != 1 || ApLink::new(1, 5, 0, 0).is_ok() || ApLink::new(1, 0, 0, 4).is_ok() {
        return TestResult::Fail("AX port/WMM field width");
    }
    // MACID1, SELF_ROLE_AP, TYPE_CHANGE, WIFI_ROLE_AP, band0, port1.
    if link.role_maintain(None, UpdMode::TypeChange) != 0x0008_4901u32.to_le_bytes() {
        return TestResult::Fail("AP self role_maintain");
    }
    // Peer MACID5: SELF_ROLE_AP_CLIENT, CREATE.
    if link.role_maintain(Some(5), UpdMode::Create) != 0x0008_4205u32.to_le_bytes() {
        return TestResult::Fail("AP client role_maintain");
    }
    // start_ap/stop_ap: vif join with dis_conn keeps NET_TYPE_AP_MODE.
    if link.join_info(None, true) != 0x4b20_0101u32.to_le_bytes() {
        return TestResult::Fail("AP vif join_info");
    }
    if link.join_info(Some(5), false) != 0x8b20_0005u32.to_le_bytes() {
        return TestResult::Fail("AP client connect join_info");
    }
    if link.join_info(Some(5), true) != 0x8820_0105u32.to_le_bytes() {
        return TestResult::Fail("AP client disconnect must report NET_TYPE_NO_LINK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_wire_role_and_join_words_match_fw_masks
);

fn smoke_rtw89_ap_wire_beacon_update_tim_offset_and_rate() -> TestResult {
    let link = link();
    let mut head = vec![0x80, 0, 0, 0];
    head.extend_from_slice(&[0xff; 6]);
    head.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    head.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    head.extend_from_slice(&[0, 0]);
    head.extend_from_slice(&[0; 8]); // timestamp
    head.extend_from_slice(&[100, 0, 0x01, 0x04]); // interval, capability
    head.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f']);
    let tim = [5, 4, 0, 2, 0, 0];
    let tail = [0xdd, 1, 0];
    let (beacon, at) = compose_beacon(&head, &tim, &tail);
    if at != 42 || beacon.len() != 51 {
        return TestResult::Fail("beacon composition");
    }
    let Ok(h2c) = link.beacon_update(&beacon, at, true, false) else {
        return TestResult::Fail("valid beacon refused");
    };
    if h2c[..4] != 0x9200_0001u32.to_le_bytes()
        || h2c[4..8] != 0x0000_0501u32.to_le_bytes()
        || h2c[8..12] != [0; 4]
        || h2c[12..] != beacon[..]
    {
        return TestResult::Fail("2.4GHz BCN_UPD words (port1, GRP_IE_OFST 18|BIT7, CCK1)");
    }
    let five = link
        .beacon_update(&beacon, at, false, false)
        .unwrap_or_default();
    let go = link
        .beacon_update(&beacon, at, true, true)
        .unwrap_or_default();
    if five.get(4..8) != Some(&0x0000_4501u32.to_le_bytes()[..]) || five.get(4..8) != go.get(4..8) {
        return TestResult::Fail("5GHz and P2P GO beacons use OFDM6");
    }
    if link.beacon_update(&beacon, 40, true, false) != Err(Error::Beacon)
        || link.beacon_update(&beacon[..20], 18, true, false) != Err(Error::Beacon)
    {
        return TestResult::Fail("TIM offset must point at the TIM element");
    }
    let mut long = vec![0u8; 24 + 0x80];
    long.extend_from_slice(&tim);
    if link.beacon_update(&long, 24 + 0x80, true, false) != Err(Error::Beacon) {
        return TestResult::Fail("TIM offset beyond 7-bit GRP_IE_OFST accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_wire_beacon_update_tim_offset_and_rate
);

fn smoke_rtw89_ap_wire_hiq_mgmt_and_ac_placement() -> TestResult {
    let link = link();
    let hiq = placement(&link, false, 0, true);
    let mgmt = placement(&link, true, 7, false);
    let hiq_mgmt = placement(&link, true, 7, true);
    if hiq
        != (Placement {
            qsel: 0x11,
            channel: 9,
            port: 1,
        })
        || hiq_mgmt != hiq
    {
        return TestResult::Fail("SEND_AFTER_DTIM must use B0_HI/CH9 and the vif port");
    }
    if mgmt
        != (Placement {
            qsel: 0x12,
            channel: 8,
            port: 0,
        })
    {
        return TestResult::Fail("management must use B0_MGMT/CH8 port0");
    }
    let qsels: Vec<u8> = (0..8)
        .map(|tid| placement(&link, false, tid, false).qsel)
        .collect();
    if qsels != vec![0, 1, 1, 0, 2, 2, 3, 3] {
        return TestResult::Fail("rtw89_core_get_qsel TID mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_wire_hiq_mgmt_and_ac_placement
);
