// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922A MLO link-lifecycle H2C builders.
//! Expected words are computed in the test from the Linux `fw.h` /
//! `cam.h` / `core.h` field layout, never by calling the encoder
//! under test. Reference: torvalds/linux @ cbbddb6
//! (`rtw89/fw.c`, `rtw89/cam.c`, `rtw89/cam.h`, `rtw89/core.h`,
//! `rtw89/core.c`, `include/linux/ieee80211-eht.h`).

use super::super::ap_wire::UpdMode;
use super::super::chip_8922a;
use super::super::efuse_be::{BeFactory, SecureInfo};
use super::super::eht::EhtStation;
use super::super::ra_mask::HeCaps;
use super::super::station_8922a::{
    admit, admit_legacy, admit_mld, Band, LegacyCaps, LinkRequest, MacIdPool, Request,
};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn factory() -> BeFactory {
    BeFactory {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        rfe_type: 0,
        xtal_cap: 0,
        country: [b'U', b'S'],
        phycap: [0u8; chip_8922a::PHYCAP_SIZE],
        cv: None,
        thermal_k: None,
        secure: SecureInfo::disabled(),
    }
}

fn facet() -> Result<EhtStation, TestResult> {
    EhtStation::new_8922ae().ok_or(TestResult::Fail("8922AE EHT facet must build"))
}

fn base_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz5,
        width_mhz: 160,
        primary: 36,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn link1_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
        band: Band::Ghz2,
        width_mhz: 40,
        primary: 6,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn two_links() -> [LinkRequest<'static>; 2] {
    [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: link1_req(),
        },
    ]
}

fn station_vif() -> VifLinkCtx {
    VifLinkCtx {
        own: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        port: 0,
        wmm: 0,
        trigger: true,
        bssid: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        addr_cam_idx: 5,
        bssid_cam_idx: 2,
        bssid_valid: true,
        ap_or_tdls: false,
        addr_cam_v0: true,
        macid_pause_sleep: true,
    }
}

fn word(body: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(body[index * 4..index * 4 + 4].try_into().unwrap())
}

fn smoke_rtw89_link_h2c_role_maintain() -> TestResult {
    // Station link 1 CREATE: macid 17 | CLIENT 0<<8 | CREATE 0<<10 |
    // STATION 1<<13 | mac_idx 1<<17 | port 0 = 0x00022011.
    let create = match role_maintain(
        17,
        SELF_ROLE_CLIENT,
        UpdMode::Create,
        WIFI_ROLE_STATION,
        1,
        0,
    ) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("station role CREATE refused"),
    };
    if create != [0x11, 0x20, 0x02, 0x00] {
        return TestResult::Fail("station role CREATE word wrong");
    }
    // AP peer REMOVE: macid 5 | AP_CLIENT 2<<8 | REMOVE 1<<10 |
    // AP 2<<13 | mac_idx 0 | port 1<<19 = 0x00084205.
    let remove = match role_maintain(5, 2, UpdMode::Remove, 2, 0, 1) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("AP peer role REMOVE refused"),
    };
    if remove != [0x05, 0x42, 0x08, 0x00] {
        return TestResult::Fail("AP peer role REMOVE word wrong");
    }
    // Out-of-field inputs refuse, never truncate.
    if role_maintain(
        17,
        SELF_ROLE_CLIENT,
        UpdMode::Create,
        WIFI_ROLE_STATION,
        1,
        8,
    )
    .is_ok()
        || role_maintain(
            17,
            SELF_ROLE_CLIENT,
            UpdMode::Create,
            WIFI_ROLE_STATION,
            2,
            0,
        )
        .is_ok()
        || role_maintain(
            32,
            SELF_ROLE_CLIENT,
            UpdMode::Create,
            WIFI_ROLE_STATION,
            1,
            0,
        )
        .is_ok()
        || role_maintain(17, 4, UpdMode::Create, WIFI_ROLE_STATION, 1, 0).is_ok()
        || role_maintain(17, SELF_ROLE_CLIENT, UpdMode::Create, 16, 1, 0).is_ok()
    {
        return TestResult::Fail("role_maintain accepted an out-of-field input");
    }
    TestResult::Pass
}

fn smoke_rtw89_link_h2c_default_dmac_v2() -> TestResult {
    let body = match default_dmac_tbl_v2(3) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("default DMAC v2 refused macid 3"),
    };
    if body.len() != 132 {
        return TestResult::Fail("default DMAC v2 length must be 132");
    }
    // c0 = MACID 3 | OP bit 7.
    if word(&body, 0) != 0x83 {
        return TestResult::Fail("default DMAC v2 c0 wrong");
    }
    // w0..w15 are zero (the skb is memset; the builder writes no values).
    for index in 1..17 {
        if word(&body, index) != 0 {
            return TestResult::Fail("default DMAC v2 value words must be zero");
        }
    }
    // m0..m12 carry their *_ALL masks; m13..m15 stay zero.
    let masks: [u32; 13] = [
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFE0,
        0xFFFF_FF0F,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0x0000_FFFF,
    ];
    for (m, want) in masks.iter().enumerate() {
        if word(&body, 17 + m) != *want {
            return TestResult::Fail("default DMAC v2 mask word wrong");
        }
    }
    for index in 30..33 {
        if word(&body, index) != 0 {
            return TestResult::Fail("default DMAC v2 m13..m15 must be zero");
        }
    }
    if default_dmac_tbl_v2(32).is_ok() {
        return TestResult::Fail("default DMAC v2 accepted macid 32");
    }
    TestResult::Pass
}

fn mld_assoc_join() -> JoinV1 {
    JoinV1 {
        macid: 17,
        dis_conn: false,
        mac_idx: 1,
        wmm: 0,
        trigger: true,
        port: 0,
        net_type: NET_TYPE_INFRA,
        wifi_role: WIFI_ROLE_STATION,
        self_role: SELF_ROLE_CLIENT,
        sta_type: StaType::Be,
        is_mld: true,
        main_macid: 1,
        init_ps: true,
        link_id: 1,
    }
}

fn smoke_rtw89_link_h2c_join_info_v1() -> TestResult {
    // MLD assoc, link 1: W0 = 17 | 1<<9 | 1<<12 | 2<<24 | 1<<26
    // = 0x06001211; W1 = BE 2 | IS_MLD 1<<3 | main 1<<4 | MLSR
    // 1<<12 | INIT_PS 1<<15 | padding 4<<16 | trans-delay 5<<19
    // | link 1<<25 = 0x022C901A; W2 = 0.
    let assoc = match join_info_v1(&mld_assoc_join()) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("MLD join-info assoc refused"),
    };
    if assoc.len() != 12 {
        return TestResult::Fail("join-info v1 length must be 12");
    }
    if assoc[0..4] != [0x11, 0x12, 0x00, 0x06] {
        return TestResult::Fail("MLD join-info assoc W0 wrong");
    }
    if assoc[4..8] != [0x1A, 0x90, 0x2C, 0x02] {
        return TestResult::Fail("MLD join-info assoc W1 wrong");
    }
    if assoc[8..12] != [0x00, 0x00, 0x00, 0x00] {
        return TestResult::Fail("MLD join-info assoc W2 must be zero");
    }
    // Disconnect: same W1 (IS_MLD / main / link id do not change),
    // W0 gains OP bit 8, loses TGR, net type NO_LINK:
    // 17 | 1<<8 | 1<<9 | 1<<26 = 0x04000311.
    let mut dis = mld_assoc_join();
    dis.dis_conn = true;
    dis.net_type = 0;
    dis.trigger = false;
    let dis = match join_info_v1(&dis) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("MLD join-info disconnect refused"),
    };
    if dis[0..4] != [0x11, 0x03, 0x00, 0x04] {
        return TestResult::Fail("MLD join-info disconnect W0 wrong");
    }
    if dis[4..8] != assoc[4..8] {
        return TestResult::Fail("MLD join-info disconnect W1 must equal assoc W1");
    }
    // Single-link assoc: macid 7, mac_idx 0, not MLD, main is its
    // own MACID, designated, link 0: W0 = 7 | 1<<12 | 2<<24 |
    // 1<<26 = 0x06001007; W1 = 2 | 7<<4 | 1<<12 | 4<<16 | 5<<19
    // = 0x002C1072.
    let single = match join_info_v1(&JoinV1 {
        macid: 7,
        dis_conn: false,
        mac_idx: 0,
        wmm: 0,
        trigger: true,
        port: 0,
        net_type: NET_TYPE_INFRA,
        wifi_role: WIFI_ROLE_STATION,
        self_role: SELF_ROLE_CLIENT,
        sta_type: StaType::Be,
        is_mld: false,
        main_macid: 7,
        init_ps: false,
        link_id: 0,
    }) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("single-link join-info refused"),
    };
    if single[0..4] != [0x07, 0x10, 0x00, 0x06] || single[4..8] != [0x72, 0x10, 0x2C, 0x00] {
        return TestResult::Fail("single-link join-info words wrong");
    }
    // Refusals: link id 15, port 8, wmm 4, mac_idx 2, macid 32,
    // main macid 32, net type 4.
    let mut bad = mld_assoc_join();
    bad.link_id = 15;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted link id 15");
    }
    bad = mld_assoc_join();
    bad.port = 8;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted port 8");
    }
    bad = mld_assoc_join();
    bad.wmm = 4;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted wmm 4");
    }
    bad = mld_assoc_join();
    bad.mac_idx = 2;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted mac_idx 2");
    }
    bad = mld_assoc_join();
    bad.macid = 32;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted macid 32");
    }
    bad = mld_assoc_join();
    bad.main_macid = 32;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted main macid 32");
    }
    bad = mld_assoc_join();
    bad.net_type = 4;
    if join_info_v1(&bad).is_ok() {
        return TestResult::Fail("join-info accepted net type 4");
    }
    TestResult::Pass
}

fn smoke_rtw89_link_h2c_macid_pause_sleep() -> TestResult {
    // macid 33: grp 1, bit 1<<1. Paused: pause_grp[1], mask[1],
    // sleep_grp[1], sleep_mask[1] all set (dwords 1, 5, 9, 13).
    let paused = match macid_pause_sleep(33, true) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("SLEEP pause refused macid 33"),
    };
    if paused.len() != 256 {
        return TestResult::Fail("SLEEP pause length must be 256");
    }
    for index in [1, 5, 9, 13] {
        if word(&paused, index) != 0x2 {
            return TestResult::Fail("SLEEP pause paused word wrong");
        }
    }
    for index in (0..64).filter(|i| ![1, 5, 9, 13].contains(i)) {
        if word(&paused, index) != 0 {
            return TestResult::Fail("SLEEP pause must leave other groups zero");
        }
    }
    // Unpaused: masks stay, pause/sleep groups clear.
    let unpaused = match macid_pause_sleep(33, false) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("SLEEP unpause refused macid 33"),
    };
    if word(&unpaused, 1) != 0 || word(&unpaused, 9) != 0 {
        return TestResult::Fail("SLEEP unpause must clear pause/sleep groups");
    }
    if word(&unpaused, 5) != 0x2 || word(&unpaused, 13) != 0x2 {
        return TestResult::Fail("SLEEP unpause must keep the masks");
    }
    if macid_pause_sleep(32, true).is_ok() {
        return TestResult::Fail("SLEEP pause accepted macid 32");
    }
    TestResult::Pass
}

fn assoc_cam_args() -> CamArgs {
    CamArgs {
        macid: 17,
        port: 0,
        phy_idx: 1,
        addr_cam_idx: 5,
        bssid_cam_idx: 2,
        net_type: NET_TYPE_INFRA,
        valid: true,
        bssid_valid: true,
        sma: [0x00, 0x11, 0x22, 0x33, 0x44, 0x56],
        tma: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
        bssid: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        aid: 7,
        trigger: true,
    }
}

fn smoke_rtw89_link_h2c_cam_v0_v1() -> TestResult {
    let body = match cam_v0(&assoc_cam_args()) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("CAM v0 refused the assoc args"),
    };
    if body.len() != 60 {
        return TestResult::Fail("CAM v0 length must be 60");
    }
    // W1 = idx 5 | entry len 0x20 << 16 (the 8922A short size,
    // not the AX 0x40). W2 = valid | INFRA 2<<1 | BB_SEL 1<<7 |
    // sma_hash 0x12<<16 | tma_hash 0x16<<24 = 0x16120085.
    if word(&body, 0) != 0 || word(&body, 1) != 0x0020_0005 {
        return TestResult::Fail("CAM v0 W0/W1 wrong");
    }
    if word(&body, 2) != 0x1612_0085 {
        return TestResult::Fail("CAM v0 W2 wrong");
    }
    if word(&body, 3) != 2 {
        return TestResult::Fail("CAM v0 W3 wrong");
    }
    if body[16..20] != [0x00, 0x11, 0x22, 0x33]
        || body[20..24] != [0x44, 0x56, 0x66, 0x77]
        || body[24..28] != [0x88, 0x99, 0xAA, 0xBC]
    {
        return TestResult::Fail("CAM v0 SMA/TMA words wrong");
    }
    if word(&body, 7) != 0 {
        return TestResult::Fail("CAM v0 W7 must be zero");
    }
    // W8 = macid 17 | TF_TRS 1<<14 = 0x4011. W9 = aid 7 |
    // SEC_NORMAL 2<<16 = 0x20007.
    if word(&body, 8) != 0x4011 || word(&body, 9) != 0x0002_0007 {
        return TestResult::Fail("CAM v0 W8/W9 wrong");
    }
    if word(&body, 10) != 0 || word(&body, 11) != 0 {
        return TestResult::Fail("CAM v0 security words must be zero");
    }
    // W12 = bssid idx 2 | len 0x08<<16. W13 = valid | BB_SEL
    // 1<<1 | MATCH_ALL 0x3f<<2 | bssid[0]<<16 | bssid[1]<<24 =
    // 0x776600FF. W14 = bssid[2..].
    if word(&body, 12) != 0x0008_0002 || word(&body, 13) != 0x7766_00FF {
        return TestResult::Fail("CAM v0 W12/W13 wrong");
    }
    if body[56..60] != [0x88, 0x99, 0xAA, 0xBB] {
        return TestResult::Fail("CAM v0 W14 wrong");
    }
    // Disconnect: net type NO_LINK, aid 0, trigger false, valid
    // stays: W2 = 0x16120081, W8 = 17, W9 = 0x20000.
    let mut dis = assoc_cam_args();
    dis.net_type = 0;
    dis.aid = 0;
    dis.trigger = false;
    let dis = match cam_v0(&dis) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("CAM v0 refused the disconnect args"),
    };
    if word(&dis, 2) != 0x1612_0081 || word(&dis, 8) != 17 || word(&dis, 9) != 0x0002_0000 {
        return TestResult::Fail("CAM v0 disconnect words wrong");
    }
    // v1: same 60 bytes, plus W15 = CON_DISCONN (4).
    let v1 = match cam_v1(&assoc_cam_args(), UpdMode::ConDisconn) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("CAM v1 refused the assoc args"),
    };
    if v1.len() != 64 || v1[..60] != body[..] || word(&v1, 15) != 4 {
        return TestResult::Fail("CAM v1 must append W15 = CON_DISCONN");
    }
    // Refusals: aid 0x1000, phy_idx 2, addr idx 128, bssid idx 20.
    let mut bad = assoc_cam_args();
    bad.aid = 0x1000;
    if cam_v0(&bad).is_ok() {
        return TestResult::Fail("CAM accepted aid 0x1000");
    }
    bad = assoc_cam_args();
    bad.phy_idx = 2;
    if cam_v0(&bad).is_ok() {
        return TestResult::Fail("CAM accepted phy_idx 2");
    }
    bad = assoc_cam_args();
    bad.addr_cam_idx = 128;
    if cam_v0(&bad).is_ok() {
        return TestResult::Fail("CAM accepted addr_cam_idx 128");
    }
    bad = assoc_cam_args();
    bad.bssid_cam_idx = 20;
    if cam_v0(&bad).is_ok() {
        return TestResult::Fail("CAM accepted bssid_cam_idx 20");
    }
    TestResult::Pass
}

fn smoke_rtw89_link_h2c_mld_transitions() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(result) => return result,
    };
    let mut pool = MacIdPool::new();
    let mld = match admit_mld(
        &f,
        facet,
        &mut pool,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        &two_links(),
    ) {
        Ok(mld) => mld,
        Err(_) => return TestResult::Fail("MLD admission refused the fixture links"),
    };
    if mld.base_macid != 0 {
        return TestResult::Fail("fresh pool must admit the MLD at base 0");
    }
    let vif0 = station_vif();
    let mut vif1 = station_vif();
    vif1.own = [0x00, 0x11, 0x22, 0x33, 0x44, 0x56];
    vif1.addr_cam_idx = 6;
    vif1.bssid_cam_idx = 3;
    // Station links send nothing on add or remove.
    for (id, vif) in [(0u8, &vif0), (1u8, &vif1)] {
        match mld_link_add_h2cs(&mld, id, vif) {
            Ok(add) => {
                if add.pause.is_some() || add.role.is_some() || add.dmac.is_some() {
                    return TestResult::Fail("station link-add must send no H2C");
                }
            }
            Err(_) => return TestResult::Fail("station link-add refused"),
        }
        match mld_link_remove_h2cs(&mld, id, vif) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return TestResult::Fail("station link-remove must send no H2C");
            }
            Err(_) => return TestResult::Fail("station link-remove refused"),
        }
    }
    // Assoc, link 0 (designated): join W0 = 0 | 1<<12 | 2<<24 |
    // 1<<26 = 0x06001000; W1 = BE 2 | IS_MLD 1<<3 | main 0 |
    // MLSR 1<<12 | padding 4<<16 | trans-delay 5<<19 =
    // 0x002C100A.
    let assoc0 = match mld_link_assoc_h2cs(&mld, 0, &vif0) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("MLD link 0 assoc refused"),
    };
    if assoc0.join[0..4] != [0x00, 0x10, 0x00, 0x06]
        || assoc0.join[4..8] != [0x0A, 0x10, 0x2C, 0x00]
    {
        return TestResult::Fail("MLD link 0 assoc join-info wrong");
    }
    let CamBody::V0(cam0) = assoc0.cam else {
        return TestResult::Fail("v0 firmware must select the 60-byte CAM");
    };
    // CAM link 0: W1 idx 5 | 0x20<<16; W2 valid | INFRA | hashes
    // 0x11/0x11 = 0x11110005; W8 = macid 0 | TF_TRS 1<<14.
    if word(&cam0, 1) != 0x0020_0005 || word(&cam0, 2) != 0x1111_0005 || word(&cam0, 8) != 0x4000 {
        return TestResult::Fail("MLD link 0 assoc CAM wrong");
    }
    // Assoc, link 1 (non-designated): join W0 = 16 | 1<<9 |
    // 1<<12 | 2<<24 | 1<<26 = 0x06001210; W1 gains INIT_PS
    // 1<<15 and LINK_ID 1<<25 = 0x022C901A. The two links must
    // differ exactly there — a single-link fixture would pass
    // with either index hard-coded.
    let assoc1 = match mld_link_assoc_h2cs(&mld, 1, &vif1) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("MLD link 1 assoc refused"),
    };
    if assoc1.join[0..4] != [0x10, 0x12, 0x00, 0x06]
        || assoc1.join[4..8] != [0x1A, 0x90, 0x2C, 0x02]
    {
        return TestResult::Fail("MLD link 1 assoc join-info wrong");
    }
    let CamBody::V0(cam1) = assoc1.cam else {
        return TestResult::Fail("v0 firmware must select the 60-byte CAM");
    };
    // CAM link 1: W1 idx 6 | 0x20<<16; W2 adds BB_SEL 1<<7,
    // hashes 0x12/0x16; W8 = macid 16 | TF_TRS.
    if word(&cam1, 1) != 0x0020_0006 || word(&cam1, 2) != 0x1612_0085 || word(&cam1, 8) != 0x4010 {
        return TestResult::Fail("MLD link 1 assoc CAM wrong");
    }
    // Disconnect, link 1: join W0 = 16 | 1<<8 | 1<<9 | 1<<26 =
    // 0x04000310, W1 unchanged; CAM net type NO_LINK, aid 0.
    let dis1 = match mld_link_disconnect_h2cs(&mld, 1, &vif1) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("MLD link 1 disconnect refused"),
    };
    if dis1.join[0..4] != [0x10, 0x03, 0x00, 0x04] || dis1.join[4..8] != assoc1.join[4..8] {
        return TestResult::Fail("MLD link 1 disconnect join-info wrong");
    }
    let CamBody::V0(dcam1) = dis1.cam else {
        return TestResult::Fail("v0 firmware must select the 60-byte CAM");
    };
    if word(&dcam1, 2) != 0x1612_0081 || word(&dcam1, 8) != 16 || word(&dcam1, 9) != 0x0002_0000 {
        return TestResult::Fail("MLD link 1 disconnect CAM wrong");
    }
    // Unknown link id refuses on every transition.
    if mld_link_assoc_h2cs(&mld, 7, &vif0).is_ok()
        || mld_link_disconnect_h2cs(&mld, 7, &vif0).is_ok()
        || mld_link_add_h2cs(&mld, 7, &vif0).is_ok()
        || mld_link_remove_h2cs(&mld, 7, &vif0).is_ok()
    {
        return TestResult::Fail("MLD transitions accepted unknown link id 7");
    }
    TestResult::Pass
}

fn smoke_rtw89_link_h2c_ap_tdls_transitions() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(result) => return result,
    };
    let mut pool = MacIdPool::new();
    let station = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(station) => station,
        Err(_) => return TestResult::Fail("single-link admission refused"),
    };
    // AP-mode VIF link: no trigger (the AP vif has no BSS HE
    // support to copy), v1 CAM (firmware >= 0.35.84.0), SLEEP
    // pause (firmware >= 0.34.11.0).
    let vif = VifLinkCtx {
        own: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        port: 0,
        wmm: 0,
        trigger: false,
        bssid: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        addr_cam_idx: 5,
        bssid_cam_idx: 2,
        bssid_valid: true,
        ap_or_tdls: true,
        addr_cam_v0: false,
        macid_pause_sleep: true,
    };
    let view = LinkView::for_station(&station, &vif);
    // Link-add: SLEEP unpause (masks set, pause/sleep clear) +
    // role CREATE (macid 0 | AP_CLIENT 2<<8 | AP 2<<13 = 0x4200)
    // + default DMAC (c0 = 0x80).
    let add = match link_add_h2cs(&view) {
        Ok(add) => add,
        Err(_) => return TestResult::Fail("AP link-add refused"),
    };
    let Some(MacidPause::Sleep(pause)) = add.pause else {
        return TestResult::Fail("SLEEP firmware must select the sleep pause body");
    };
    if word(&pause, 0) != 0 || word(&pause, 8) != 0 || word(&pause, 4) != 1 || word(&pause, 12) != 1
    {
        return TestResult::Fail("AP link-add SLEEP unpause words wrong");
    }
    if add.role != Some([0x00, 0x42, 0x00, 0x00]) {
        return TestResult::Fail("AP link-add role CREATE wrong");
    }
    match add.dmac {
        Some(dmac) if word(&dmac, 0) == 0x80 => {}
        _ => return TestResult::Fail("AP link-add default DMAC wrong"),
    }
    // Link-remove: role REMOVE (0x200 | 0x400 | 0x4000 = 0x4600).
    match link_remove_h2cs(&view) {
        Ok(Some(role)) if role == [0x00, 0x46, 0x00, 0x00] => {}
        _ => return TestResult::Fail("AP link-remove role REMOVE wrong"),
    }
    // Assoc: join W0 = 3<<24 | 2<<26 | 2<<30 = 0x8B000000
    // (AP_MODE, AP, AP_CLIENT, no trigger); CAM v1 with W15 = 4.
    let assoc = match link_assoc_h2cs(&view) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("AP link assoc refused"),
    };
    if assoc.join[0..4] != [0x00, 0x00, 0x00, 0x8B] {
        return TestResult::Fail("AP link assoc join-info wrong");
    }
    let CamBody::V1(cam) = assoc.cam else {
        return TestResult::Fail("v1 firmware must select the 64-byte CAM");
    };
    if word(&cam, 15) != 4 {
        return TestResult::Fail("AP link assoc CAM W15 must be CON_DISCONN");
    }
    // Disconnect: join W0 = 1<<8 | 2<<26 | 2<<30 = 0x88000100;
    // CAM valid cleared (deinit first), net type stays AP_MODE,
    // peer AID stays: W2 = 6 | hashes 0x11/0x11 = 0x11110006,
    // W9 = 0x20007.
    let dis = match link_disconnect_h2cs(&view) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("AP link disconnect refused"),
    };
    if dis.join[0..4] != [0x00, 0x01, 0x00, 0x88] {
        return TestResult::Fail("AP link disconnect join-info wrong");
    }
    let CamBody::V1(dcam) = dis.cam else {
        return TestResult::Fail("v1 firmware must select the 64-byte CAM");
    };
    if word(&dcam, 2) != 0x1111_0006 || word(&dcam, 9) != 0x0002_0007 {
        return TestResult::Fail("AP link disconnect CAM wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_link_h2c_legacy_sta_type() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let req = Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz2,
        width_mhz: 20,
        primary: 6,
        nss: 1,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: false,
        punctured: 0,
        peer_ies: &[],
        has_he: false,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    };
    // Legacy-only peer: STA_TYPE N/AC (0) in join W1.
    let legacy = match admit_legacy(
        &f,
        &LegacyCaps {
            supp_rates: 0xFFF,
            ht: None,
            vht: None,
            he: None,
            rssi: 40,
            er_cap: false,
        },
        &mut pool,
        &req,
    ) {
        Ok(station) => station,
        Err(_) => return TestResult::Fail("legacy admission refused"),
    };
    let assoc = match link_assoc_h2cs(&LinkView::for_legacy_station(&legacy, &station_vif())) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("legacy assoc refused"),
    };
    if assoc.join[4] & 0x07 != 0 {
        return TestResult::Fail("legacy-only link must report STA_TYPE N/AC");
    }
    // HE peer: STA_TYPE AX (1) in join W1.
    let he = match admit_legacy(
        &f,
        &LegacyCaps {
            supp_rates: 0xFFF,
            ht: None,
            vht: None,
            he: Some(HeCaps {
                rx_mcs_80: 0,
                rx_mcs_160: 0,
                rx_mcs_80p80: 0,
                has_80p80: false,
                stbc_under_80: false,
                ldpc_in_payload: false,
                dcm_16qam: false,
                partial_bw_er: false,
            }),
            rssi: 40,
            er_cap: false,
        },
        &mut pool,
        &req,
    ) {
        Ok(station) => station,
        Err(_) => return TestResult::Fail("HE legacy admission refused"),
    };
    let assoc = match link_assoc_h2cs(&LinkView::for_legacy_station(&he, &station_vif())) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("HE legacy assoc refused"),
    };
    if assoc.join[4] & 0x07 != 1 {
        return TestResult::Fail("HE link must report STA_TYPE AX");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_link_h2c_role_maintain);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_link_h2c_default_dmac_v2
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_link_h2c_join_info_v1);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_link_h2c_macid_pause_sleep
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_link_h2c_cam_v0_v1);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_link_h2c_mld_transitions
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_link_h2c_ap_tdls_transitions
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_link_h2c_legacy_sta_type
);
