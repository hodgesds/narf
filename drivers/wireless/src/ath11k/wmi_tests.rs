//! ath11k WMI + HTC offline tests.
//!
//! No hardware exists to check these layers against until the final
//! bring-up, so every expectation here is a literal derived by hand
//! from Linux `drivers/net/wireless/ath/ath11k/{wmi,htc,hw,core}.{c,h}`
//! (struct layouts, enum positions, builder bodies), never from the
//! NARF code under test. Each golden vector comments where its words
//! come from. Negative cases pin the Linux rejection points
//! (`ath11k_wmi_tlv_iter`, the per-event `tb[]` lookups, HTC header /
//! trailer checks, credit exhaustion).

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::htc::*;
use super::wmi::*;

macro_rules! ensure {
    ($c:expr, $m:literal) => {
        if !$c {
            return TestResult::Fail($m);
        }
    };
}

/// Little-endian words → bytes.
pub(super) fn le(ws: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ws.len() * 4);
    for w in ws {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

/// `[cmd_id] ++ body` — what `ath11k_wmi_cmd_send_nowait` hands HTC.
pub(super) fn frame(id: u32, body: &[u32]) -> Vec<u8> {
    let mut v = le(&[id]);
    v.extend_from_slice(&le(body));
    v
}

/// Test-side TLV (firmware direction): header `(tag << 16) | len`.
pub(super) fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = le(&[((tag as u32) << 16) | value.len() as u32]);
    v.extend_from_slice(value);
    v
}

pub(super) fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

pub(super) fn event(id: u32, tlvs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = le(&[id]);
    v.extend_from_slice(&cat(tlvs));
    v
}

/// 02:11:22:33:44:55 as the two `wmi_mac_addr` words.
const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_W0: u32 = 0x3322_1102;
const MAC_W1: u32 = 0x0000_5544;

// ── Identifier tables ───────────────────────────────────────────────

fn smoke_ath11k_wmi_cmd_ids_match_linux() -> TestResult {
    // WMI_TLV_CMD(grp) = (grp << 12) | 1; enumerators then +1 each.
    // Groups: START = SCAN = 0x3, PDEV 0x4, VDEV 0x5, PEER 0x6,
    // MGMT 0x7, STA_PS 0x9, REGULATORY 0x3a.
    let base = |g: u32| (g << 12) | 1;
    let table: &[(u32, u32, &str)] = &[
        (WMI_INIT_CMDID, 0x1, "INIT = 0x1 (explicit)"),
        (WMI_START_SCAN_CMDID, base(3), "START_SCAN = SCAN+0"),
        (WMI_STOP_SCAN_CMDID, base(3) + 1, "STOP_SCAN = SCAN+1"),
        (
            WMI_SCAN_CHAN_LIST_CMDID,
            base(3) + 2,
            "SCAN_CHAN_LIST = SCAN+2",
        ),
        (
            WMI_PDEV_SET_REGDOMAIN_CMDID,
            base(4),
            "PDEV_SET_REGDOMAIN = PDEV+0",
        ),
        // PDEV: SET_REGDOMAIN, SET_CHANNEL, SET_PARAM
        (
            WMI_PDEV_SET_PARAM_CMDID,
            base(4) + 2,
            "PDEV_SET_PARAM = PDEV+2",
        ),
        (
            WMI_PDEV_GET_TEMPERATURE_CMDID,
            base(4) + 15,
            "PDEV_GET_TEMPERATURE = PDEV+15",
        ),
        (
            WMI_PDEV_SET_HW_MODE_CMDID,
            base(4) + 29,
            "PDEV_SET_HW_MODE = PDEV+29",
        ),
        // VDEV: CREATE, DELETE, START_REQUEST, RESTART_REQUEST, UP,
        // STOP, DOWN, SET_PARAM, INSTALL_KEY
        (WMI_VDEV_CREATE_CMDID, base(5), "VDEV_CREATE"),
        (WMI_VDEV_DELETE_CMDID, base(5) + 1, "VDEV_DELETE"),
        (
            WMI_VDEV_START_REQUEST_CMDID,
            base(5) + 2,
            "VDEV_START_REQUEST",
        ),
        (
            WMI_VDEV_RESTART_REQUEST_CMDID,
            base(5) + 3,
            "VDEV_RESTART_REQUEST",
        ),
        (WMI_VDEV_UP_CMDID, base(5) + 4, "VDEV_UP"),
        (WMI_VDEV_STOP_CMDID, base(5) + 5, "VDEV_STOP"),
        (WMI_VDEV_DOWN_CMDID, base(5) + 6, "VDEV_DOWN"),
        (WMI_VDEV_SET_PARAM_CMDID, base(5) + 7, "VDEV_SET_PARAM"),
        (WMI_VDEV_INSTALL_KEY_CMDID, base(5) + 8, "VDEV_INSTALL_KEY"),
        // PEER: CREATE, DELETE, FLUSH_TIDS, SET_PARAM, ASSOC
        (WMI_PEER_CREATE_CMDID, base(6), "PEER_CREATE"),
        (WMI_PEER_DELETE_CMDID, base(6) + 1, "PEER_DELETE"),
        (WMI_PEER_SET_PARAM_CMDID, base(6) + 3, "PEER_SET_PARAM"),
        (WMI_PEER_ASSOC_CMDID, base(6) + 4, "PEER_ASSOC"),
        // MGMT: BCN_TX, PDEV_SEND_BCN, BCN_TMPL, BCN_FILTER_RX,
        // PRB_REQ_FILTER_RX, MGMT_TX, PRB_TMPL, MGMT_TX_SEND
        (WMI_MGMT_TX_SEND_CMDID, base(7) + 7, "MGMT_TX_SEND = MGMT+7"),
        (WMI_STA_POWERSAVE_MODE_CMDID, base(9), "STA_POWERSAVE_MODE"),
        (
            WMI_STA_POWERSAVE_PARAM_CMDID,
            base(9) + 1,
            "STA_POWERSAVE_PARAM",
        ),
        // REGULATORY: SET_CURRENT_COUNTRY, 11D_SCAN_START,
        // 11D_SCAN_STOP, SET_INIT_COUNTRY
        (
            WMI_SET_CURRENT_COUNTRY_CMDID,
            base(0x3a),
            "SET_CURRENT_COUNTRY",
        ),
        (WMI_11D_SCAN_START_CMDID, base(0x3a) + 1, "11D_SCAN_START"),
        (WMI_11D_SCAN_STOP_CMDID, base(0x3a) + 2, "11D_SCAN_STOP"),
        (
            WMI_SET_INIT_COUNTRY_CMDID,
            base(0x3a) + 3,
            "SET_INIT_COUNTRY",
        ),
    ];
    for &(got, want, _what) in table {
        if got != want {
            return TestResult::Fail("WMI command id differs from Linux enum wmi_tlv_cmd_id");
        }
    }
    // Literal spot checks (independent of the base() helper).
    ensure!(WMI_START_SCAN_CMDID == 0x3001, "START_SCAN literal");
    ensure!(WMI_VDEV_CREATE_CMDID == 0x5001, "VDEV_CREATE literal");
    ensure!(WMI_PDEV_SET_HW_MODE_CMDID == 0x401e, "SET_HW_MODE literal");
    ensure!(
        WMI_SET_CURRENT_COUNTRY_CMDID == 0x3a001,
        "SET_CURRENT_COUNTRY literal"
    );
    // Negative: the values the pre-rewrite wmi.rs used (groups shifted
    // by one, INIT inside the START group) must be gone.
    ensure!(WMI_INIT_CMDID != 0x3001, "INIT must not be 0x3001");
    ensure!(
        WMI_START_SCAN_CMDID != 0x4001,
        "START_SCAN must not be 0x4001"
    );
    ensure!(
        WMI_PEER_CREATE_CMDID != 0x7001,
        "PEER_CREATE must not be 0x7001"
    );
    ensure!(WMI_GRP_SCAN == WMI_GRP_START, "GRP_SCAN aliases GRP_START");
    ensure!(
        WMI_GRP_PDEV == 4 && WMI_GRP_VDEV == 5 && WMI_GRP_PEER == 6,
        "group numbers"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_cmd_ids_match_linux
);

fn smoke_ath11k_wmi_event_ids_match_linux() -> TestResult {
    let base = |g: u32| (g << 12) | 1;
    let table: &[(u32, u32)] = &[
        // START group events are explicit: 1, 2, 3.
        (WMI_SERVICE_READY_EVENTID, 0x1),
        (WMI_READY_EVENTID, 0x2),
        (WMI_SERVICE_AVAILABLE_EVENTID, 0x3),
        (WMI_SCAN_EVENTID, base(3)),
        // PDEV: TPC_CONFIG, CHANLIST_UPDATE, ... TEMPERATURE = +7,
        // SERVICE_READY_EXT = +8, SERVICE_READY_EXT2 = +33
        (WMI_PDEV_TEMPERATURE_EVENTID, base(4) + 7),
        (WMI_SERVICE_READY_EXT_EVENTID, base(4) + 8),
        (WMI_SERVICE_READY_EXT2_EVENTID, base(4) + 33),
        // VDEV: START_RESP, STOPPED, INSTALL_KEY_COMPLETE, MCC_BCN_INTVL,
        // TSF_REPORT, DELETE_RESP
        (WMI_VDEV_START_RESP_EVENTID, base(5)),
        (WMI_VDEV_STOPPED_EVENTID, base(5) + 1),
        (WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID, base(5) + 2),
        (WMI_VDEV_DELETE_RESP_EVENTID, base(5) + 5),
        // PEER: STA_KICKOUT, INFO, TX_FAIL_CNT_THR, ESTIMATED_LINKSPEED,
        // STATE, ASSOC_CONF, DELETE_RESP
        (WMI_PEER_STA_KICKOUT_EVENTID, base(6)),
        (WMI_PEER_ASSOC_CONF_EVENTID, base(6) + 5),
        (WMI_PEER_DELETE_RESP_EVENTID, base(6) + 6),
        // MGMT: RX, HOST_SWBA, TBTTOFFSET_UPDATE, OFFLOAD_BCN_TX_STATUS,
        // OFFLOAD_PROB_RESP_TX_STATUS, MGMT_TX_COMPLETION
        (WMI_MGMT_RX_EVENTID, base(7)),
        (WMI_MGMT_TX_COMPLETION_EVENTID, base(7) + 5),
        (WMI_ROAM_EVENTID, base(0xb)),
        // REGULATORY: REG_CHAN_LIST_CC, 11D_NEW_COUNTRY,
        // REG_CHAN_LIST_CC_EXT
        (WMI_REG_CHAN_LIST_CC_EVENTID, base(0x3a)),
        (WMI_11D_NEW_COUNTRY_EVENTID, base(0x3a) + 1),
        (WMI_REG_CHAN_LIST_CC_EXT_EVENTID, base(0x3a) + 2),
    ];
    for &(got, want) in table {
        if got != want {
            return TestResult::Fail("WMI event id differs from Linux enum wmi_tlv_event_id");
        }
    }
    ensure!(
        WMI_SERVICE_READY_EXT_EVENTID == 0x4009,
        "SERVICE_READY_EXT literal"
    );
    ensure!(
        WMI_SERVICE_READY_EXT2_EVENTID == 0x4022,
        "SERVICE_READY_EXT2 literal"
    );
    ensure!(WMI_MGMT_RX_EVENTID == 0x7001, "MGMT_RX literal");
    ensure!(
        WMI_REG_CHAN_LIST_CC_EXT_EVENTID == 0x3a003,
        "REG_CC_EXT literal"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_event_ids_match_linux
);

fn smoke_ath11k_wmi_tags_match_linux() -> TestResult {
    // enum wmi_tlv_tag: LAST_RESERVED = 15, arrays 16..19,
    // LAST_ARRAY_ENUM = 31, then SERVICE_READY_EVENT = 32 and +1 each
    // down the list; the later values are the enumerator positions.
    let table: &[(u16, u16)] = &[
        (WMI_TAG_LAST_RESERVED, 15),
        (WMI_TAG_ARRAY_UINT32, 0x10),
        (WMI_TAG_ARRAY_BYTE, 0x11),
        (WMI_TAG_ARRAY_STRUCT, 0x12),
        (WMI_TAG_ARRAY_FIXED_STRUCT, 0x13),
        (WMI_TAG_SERVICE_READY_EVENT, 0x20),
        (WMI_TAG_READY_EVENT, 0x23),
        (WMI_TAG_SCAN_EVENT, 0x24),
        (WMI_TAG_VDEV_START_RESPONSE_EVENT, 0x28),
        (WMI_TAG_VDEV_STOPPED_EVENT, 0x29),
        (WMI_TAG_VDEV_INSTALL_KEY_COMPLETE_EVENT, 0x2a),
        (WMI_TAG_PEER_STA_KICKOUT_EVENT, 0x2b),
        (WMI_TAG_MGMT_RX_HDR, 0x2c),
        (WMI_TAG_ROAM_EVENT, 0x30),
        (WMI_TAG_INIT_CMD, 0x4a),
        (WMI_TAG_RESOURCE_CONFIG, 0x4b),
        (WMI_TAG_WLAN_HOST_MEMORY_CHUNK, 0x4c),
        (WMI_TAG_START_SCAN_CMD, 0x4d),
        (WMI_TAG_STOP_SCAN_CMD, 0x4e),
        (WMI_TAG_SCAN_CHAN_LIST_CMD, 0x4f),
        (WMI_TAG_CHANNEL, 0x50),
        (WMI_TAG_PDEV_SET_REGDOMAIN_CMD, 0x51),
        (WMI_TAG_PDEV_SET_PARAM_CMD, 0x52),
        (WMI_TAG_VDEV_CREATE_CMD, 0x56),
        (WMI_TAG_VDEV_DELETE_CMD, 0x57),
        (WMI_TAG_VDEV_START_REQUEST_CMD, 0x58),
        (WMI_TAG_VDEV_UP_CMD, 0x5c),
        (WMI_TAG_VDEV_STOP_CMD, 0x5d),
        (WMI_TAG_VDEV_DOWN_CMD, 0x5e),
        (WMI_TAG_VDEV_SET_PARAM_CMD, 0x5f),
        (WMI_TAG_VDEV_INSTALL_KEY_CMD, 0x60),
        (WMI_TAG_PEER_CREATE_CMD, 0x61),
        (WMI_TAG_PEER_DELETE_CMD, 0x62),
        (WMI_TAG_PEER_SET_PARAM_CMD, 0x64),
        (WMI_TAG_PEER_ASSOC_COMPLETE_CMD, 0x65),
        (WMI_TAG_VHT_RATE_SET, 0x66),
        (WMI_TAG_STA_POWERSAVE_MODE_CMD, 0x6c),
        (WMI_TAG_STA_POWERSAVE_PARAM_CMD, 0x6d),
        (WMI_TAG_PDEV_GET_TEMPERATURE_CMD, 0x156),
        (WMI_TAG_PDEV_TEMPERATURE_EVENT, 0x157),
        (WMI_TAG_VDEV_TXRX_STREAMS, 0x19b),
        (WMI_TAG_MGMT_TX_SEND_CMD, 0x1a6),
        (WMI_TAG_MGMT_TX_COMPL_EVENT, 0x1a7),
        (WMI_TAG_SERVICE_READY_EXT_EVENT, 0x1ac),
        (WMI_TAG_PEER_ASSOC_CONF_EVENT, 0x1b2),
        (WMI_TAG_VDEV_DELETE_RESP_EVENT, 0x1c2),
        (WMI_TAG_PEER_DELETE_RESP_EVENT, 0x1c3),
        (WMI_TAG_PDEV_SET_HW_MODE_CMD, 0x203),
        (WMI_TAG_MAC_PHY_CAPABILITIES, 0x210),
        (WMI_TAG_HW_MODE_CAPABILITIES, 0x211),
        (WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, 0x212),
        (WMI_TAG_HAL_REG_CAPABILITIES_EXT, 0x213),
        (WMI_TAG_SOC_HAL_REG_CAPABILITIES, 0x214),
        (WMI_TAG_SERVICE_AVAILABLE_EVENT, 0x22f),
        (WMI_TAG_PDEV_BAND_TO_MAC, 0x24b),
        (WMI_TAG_SET_CURRENT_COUNTRY_CMD, 0x25f),
        (WMI_TAG_REGULATORY_RULE_STRUCT, 0x260),
        (WMI_TAG_REG_CHAN_LIST_CC_EVENT, 0x261),
        (WMI_TAG_11D_SCAN_START_CMD, 0x262),
        (WMI_TAG_11D_SCAN_STOP_CMD, 0x263),
        (WMI_TAG_TX_SEND_PARAMS, 0x284),
        (WMI_TAG_HE_RATE_SET, 0x285),
        (WMI_TAG_SET_INIT_COUNTRY_CMD, 0x287),
        (WMI_TAG_DMA_RING_CAPABILITIES, 0x2bf),
        (WMI_TAG_REGULATORY_RULE_EXT_STRUCT, 0x3a9),
        (WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT, 0x3aa),
    ];
    for &(got, want) in table {
        if got != want {
            return TestResult::Fail("WMI TLV tag differs from Linux enum wmi_tlv_tag");
        }
    }
    // Negative: the pre-rewrite (wrong) tag values.
    ensure!(WMI_TAG_INIT_CMD != 0x2c, "INIT_CMD must not be 0x2c");
    ensure!(
        WMI_TAG_ARRAY_STRUCT != 0x15,
        "ARRAY_STRUCT must not be 0x15"
    );
    ensure!(
        WMI_TAG_VDEV_TXRX_STREAMS != 0x68,
        "TXRX_STREAMS must not be 0x68"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_tags_match_linux);

fn smoke_ath11k_wmi_services_and_params_match_linux() -> TestResult {
    ensure!(WMI_MAX_SERVICE == 128, "WMI_MAX_SERVICE");
    ensure!(WMI_MAX_EXT_SERVICE == 256, "WMI_MAX_EXT_SERVICE");
    ensure!(WMI_MAX_EXT2_SERVICE == 384, "WMI_MAX_EXT2_SERVICE");
    ensure!(WMI_TLV_SERVICE_EXT2_MSG == 220, "SERVICE_EXT2_MSG");
    ensure!(
        WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT == 281,
        "REG_CC_EXT_EVENT_SUPPORT"
    );
    ensure!(WMI_SERVICE_BM_SIZE == 32, "WMI_SERVICE_BM_SIZE = (128+3)/4");
    // enum wmi_tlv_vdev_param starts at RTS_THRESHOLD = 0x1.
    ensure!(WMI_VDEV_PARAM_RTS_THRESHOLD == 1, "VDEV RTS");
    ensure!(WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD == 2, "VDEV FRAG");
    ensure!(WMI_VDEV_PARAM_BEACON_INTERVAL == 3, "VDEV BEACON_INTERVAL");
    ensure!(WMI_VDEV_PARAM_LISTEN_INTERVAL == 4, "VDEV LISTEN_INTERVAL");
    // RTS(1), FRAG, BEACON_INTERVAL, LISTEN_INTERVAL, MULTICAST_RATE,
    // MGMT_TX_RATE, SLOT_TIME, PREAMBLE, SWBA_TIME, STATS_UPDATE_PERIOD,
    // PWRSAVE_AGEOUT_TIME, HOST_SWBA_INTERVAL, DTIM_PERIOD = 13th = 0xd.
    ensure!(WMI_VDEV_PARAM_DTIM_PERIOD == 0xd, "VDEV DTIM_PERIOD");
    ensure!(WMI_VDEV_PARAM_DTIM_PERIOD != 0x9, "old wrong DTIM 9");
    // enum wmi_tlv_pdev_param starts at TX_CHAIN_MASK = 0x1.
    ensure!(WMI_PDEV_PARAM_TX_CHAIN_MASK == 1, "PDEV TX_CHAIN_MASK");
    ensure!(WMI_PDEV_PARAM_RX_CHAIN_MASK == 2, "PDEV RX_CHAIN_MASK");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_services_and_params_match_linux
);

fn smoke_ath11k_wmi_tlv_header_bits() -> TestResult {
    // WMI_TLV_TAG = GENMASK(31,16), WMI_TLV_LEN = GENMASK(15,0).
    ensure!(tlv_hdr(0x4a, 28) == 0x004a_001c, "tlv_hdr pack");
    ensure!(tlv_hdr_tag(0x03aa_0138) == 0x3aa, "tlv tag field");
    ensure!(tlv_hdr_len(0x03aa_0138) == 0x138, "tlv len field");
    // Length is masked to 16 bits like FIELD_PREP.
    ensure!(tlv_hdr(0x11, 0x1_0004) == 0x0011_0004, "len masked");
    // WMI_CMD_HDR_CMD_ID = GENMASK(23,0).
    let c = WmiCmd {
        cmd_id: 0xAB00_5001,
        buf: Vec::new(),
    };
    ensure!(c.frame() == le(&[0x0000_5001]), "cmd id masked to 24 bits");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_tlv_header_bits);

// ── Simple command goldens ──────────────────────────────────────────

fn smoke_ath11k_wmi_simple_cmd_goldens() -> TestResult {
    // struct wmi_pdev_set_param_cmd {tlv, pdev_id, param_id, value}
    ensure!(
        pdev_set_param_cmd(WMI_PDEV_PARAM_TX_CHAIN_MASK, 3, 0).frame()
            == frame(0x4003, &[0x0052_000c, 0, 1, 3]),
        "pdev_set_param golden"
    );
    // struct wmi_vdev_set_param_cmd {tlv, vdev_id, param_id, value}
    ensure!(
        vdev_set_param_cmd(1, WMI_VDEV_PARAM_DTIM_PERIOD, 2).frame()
            == frame(0x5008, &[0x005f_000c, 1, 0xd, 2]),
        "vdev_set_param golden"
    );
    // {tlv, vdev_id}
    ensure!(
        vdev_delete_cmd(2).frame() == frame(0x5002, &[0x0057_0004, 2]),
        "vdev_delete golden"
    );
    ensure!(
        vdev_stop_cmd(2).frame() == frame(0x5006, &[0x005d_0004, 2]),
        "vdev_stop golden"
    );
    ensure!(
        vdev_down_cmd(2).frame() == frame(0x5007, &[0x005e_0004, 2]),
        "vdev_down golden"
    );
    // struct wmi_peer_create_cmd {tlv, vdev_id, mac(8), peer_type}
    ensure!(
        peer_create_cmd(0, &MAC, peer_type::DEFAULT).frame()
            == frame(0x6001, &[0x0061_0010, 0, MAC_W0, MAC_W1, 0]),
        "peer_create golden"
    );
    // struct wmi_peer_delete_cmd {tlv, vdev_id, mac}
    ensure!(
        peer_delete_cmd(&MAC, 1).frame() == frame(0x6002, &[0x0062_000c, 1, MAC_W0, MAC_W1]),
        "peer_delete golden"
    );
    // struct wmi_peer_set_param_cmd {tlv, vdev_id, mac, param, value}
    ensure!(
        peer_set_param_cmd(&MAC, 0, peer_param::AUTHORIZE, 1).frame()
            == frame(0x6004, &[0x0064_0014, 0, MAC_W0, MAC_W1, 3, 1]),
        "peer_set_param golden"
    );
    // struct wmi_pdev_set_regdomain_cmd {tlv, pdev, rd, rd2g, rd5g,
    // ctl2g, ctl5g, dfs}
    let rd = PdevSetRegdomainParams {
        current_rd_in_use: 0x3a,
        current_rd_2g: 0x3a,
        current_rd_5g: 0x3b,
        ctl_2g: 0x10,
        ctl_5g: 0x20,
        dfs_domain: 1,
        pdev_id: 0,
    };
    ensure!(
        pdev_set_regdomain_cmd(&rd).frame()
            == frame(0x4001, &[0x0051_001c, 0, 0x3a, 0x3a, 0x3b, 0x10, 0x20, 1]),
        "pdev_set_regdomain golden"
    );
    // set_current_country: memcpy("US\0") into u32 new_alpha2.
    ensure!(
        set_current_country_cmd(0, *b"US\0").frame()
            == frame(0x3a001, &[0x025f_0008, 0, 0x0000_5355]),
        "set_current_country golden"
    );
    // init country: {tlv, pdev, init_cc_type, cc_info}
    ensure!(
        init_country_cmd(0, InitCountry::Alpha(*b"DE\0")).frame()
            == frame(0x3a004, &[0x0287_000c, 0, 0, 0x0000_4544]),
        "init_country alpha golden"
    );
    ensure!(
        init_country_cmd(0, InitCountry::CountryCode(840)).frame()
            == frame(0x3a004, &[0x0287_000c, 0, 1, 840]),
        "init_country cc golden"
    );
    ensure!(
        init_country_cmd(0, InitCountry::RegDomain(0x3a)).frame()
            == frame(0x3a004, &[0x0287_000c, 0, 2, 0x3a]),
        "init_country regdomain golden"
    );
    // 11d: {tlv, vdev, period, interval} / {tlv, vdev}
    ensure!(
        scan_11d_start_cmd(0, 86_400_000, 0).frame()
            == frame(0x3a002, &[0x0262_000c, 0, 86_400_000, 0]),
        "11d start golden"
    );
    ensure!(
        scan_11d_stop_cmd(0).frame() == frame(0x3a003, &[0x0263_0004, 0]),
        "11d stop golden"
    );
    // set_hw_mode: {tlv, pdev_id = SOC(0), hw_mode_index, num_band_to_mac}
    ensure!(
        set_hw_mode_cmd(hw_mode::DBS).frame() == frame(0x401e, &[0x0203_000c, 0, 1, 0]),
        "set_hw_mode golden"
    );
    // sta ps: {tlv, vdev, mode} / {tlv, vdev, param, value}
    ensure!(
        sta_powersave_mode_cmd(0, sta_ps_mode::ENABLED).frame()
            == frame(0x9001, &[0x006c_0008, 0, 1]),
        "sta ps mode golden"
    );
    ensure!(
        sta_powersave_param_cmd(0, sta_ps_param::INACTIVITY_TIME, 200).frame()
            == frame(0x9002, &[0x006d_000c, 0, 3, 200]),
        "sta ps param golden"
    );
    // temperature: {tlv, param = 0, pdev_id}
    ensure!(
        pdev_get_temperature_cmd(0).frame() == frame(0x4010, &[0x0156_0008, 0, 0]),
        "temperature golden"
    );
    // stop scan: {tlv, requestor, scan_id, req_type, vdev, pdev}
    ensure!(
        scan_stop_cmd(0, 0, 0xA000, 0, ScanCancel::Single).frame()
            == frame(0x3002, &[0x004e_0014, 0, 0xA000, 0, 0, 0]),
        "stop scan single golden"
    );
    ensure!(
        scan_stop_cmd(1, 2, 3, 0, ScanCancel::VdevAll).frame()
            == frame(0x3002, &[0x004e_0014, 2, 3, 0x0100_0000, 1, 0]),
        "stop scan vdev-all golden"
    );
    ensure!(
        scan_stop_cmd(1, 2, 3, 0, ScanCancel::PdevAll).frame()
            == frame(0x3002, &[0x004e_0014, 2, 3, 0x0400_0000, 1, 0]),
        "stop scan pdev-all golden"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_simple_cmd_goldens
);

// ── INIT ────────────────────────────────────────────────────────────

/// `struct wmi_resource_config` for WCN6855 (`ath11k_init_wmi_config_qca6390`
/// with num_vdevs = 2 + 1, num_rf_chains = 2, REG_CC_EXT advertised),
/// hand-filled field by field from hw.c / wmi.c.
pub(super) fn wcn6855_resource_config_words() -> Vec<u32> {
    vec![
        0x004b_0120, // tlv: RESOURCE_CONFIG, 292 - 4
        3,           // num_vdevs = hw_params.num_vdevs (2 + 1)
        16,          // num_peers
        3,           // num_offload_peers
        3,           // num_offload_reorder_buffs
        2,           // num_peer_keys = TARGET_NUM_PEER_KEYS
        32,          // num_tids
        16,          // ast_skid_limit = TARGET_AST_SKID_LIMIT
        3,           // tx_chain_mask = (1 << 2) - 1
        3,           // rx_chain_mask
        100,         // rx_timeout_pri[0] = TARGET_RX_TIMEOUT_LO_PRI
        100,         // [1]
        100,         // [2]
        40,          // [3] = TARGET_RX_TIMEOUT_HI_PRI
        1,           // rx_decap_mode = TARGET_DECAP_MODE_NATIVE_WIFI
        4,           // scan_max_pending_req
        3,           // bmiss_offload_max_vdev
        3,           // roam_offload_max_vdev
        8,           // roam_offload_max_ap_profiles
        0,           // num_mcast_groups
        0,           // num_mcast_table_elems
        0,           // mcast2ucast_mode
        1024,        // tx_dbg_log_size
        0,           // num_wds_entries
        0,           // dma_burst_size
        0,           // mac_aggr_delim (not set by qca6390 init)
        0,           // rx_skip_defrag_timeout_dup_detection_check
        0,           // vow_config
        2,           // gtk_offload_max_vdev
        0x400,       // num_msdu_desc
        0xa,         // max_frag_entries
        1,           // num_tdls_vdevs
        8,           // num_tdls_conn_table_entries
        2,           // beacon_tx_offload_max_vdev
        0x20,        // num_multicast_filter_entries
        0x16,        // num_wow_filters
        0,           // num_keep_alive_pattern
        0,           // keep_alive_pattern_size
        0,           // max_tdls_concurrent_sleep_sta
        0,           // max_tdls_concurrent_buffer_sta
        0,           // wmi_send_separate
        0,           // num_ocb_vdevs
        0,           // num_ocb_channels
        0,           // num_ocb_schedules
        0x20,        // flag1 = WMI_RSRC_CFG_FLAG1_BSS_CHANNEL_INFO_64
        0,           // smart_ant_cap
        0,           // bk_minfree
        0,           // be_minfree
        0,           // vi_minfree
        0,           // vo_minfree
        0,           // alloc_frag_desc_for_data_pkt
        0,           // num_ns_ext_tuples_cfg
        0,           // bpf_instruction_size
        0,           // max_bssid_rx_filters
        1,           // use_pdev_id
        0,           // max_num_dbs_scan_duty_cycle
        0,           // max_num_group_keys
        0,           // peer_map_unmap_v2_support
        0,           // sched_params
        0,           // twt_ap_pdev_count
        0,           // twt_ap_sta_count
        0,           // max_nlo_ssids
        0,           // num_pkt_filters
        0,           // num_max_sta_vdevs
        0,           // max_bssid_indicator
        0,           // ul_resp_config
        0,           // msdu_flow_override_config0
        0,           // msdu_flow_override_config1
        0x200,       // flags2 = WMI_RSRC_CFG_FLAG2_CALC_NEXT_DTIM_COUNT_SET
        0x10,        // host_service_flags = 1 << REG_CC_EXT(4)
        0,           // max_rnr_neighbours
        0,           // ema_max_vap_cnt
        0,           // ema_max_profile_period
    ]
}

fn smoke_ath11k_wmi_init_cmd_wcn6855_golden() -> TestResult {
    let words = wcn6855_resource_config_words();
    ensure!(
        words.len() * 4 == WMI_RESOURCE_CONFIG_SIZE,
        "resource config is 73 words"
    );
    let cfg = TargetResourceConfig::qca6390(3, 2, true);
    ensure!(cfg.to_wmi_bytes() == le(&words), "resource config golden");
    ensure!(cfg.rx_batchmode == 1, "rx_batchmode set (not transmitted)");

    let cmd = match init_cmd(&InitCmdParam::single_pdev(cfg)) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("init_cmd failed"),
    };
    // struct wmi_init_cmd {tlv(0x4a, 28), host_abi_vers[6] = 0,
    // num_host_mem_chunks = 0}, resource config, ARRAY_STRUCT len 0;
    // no hw-mode TLVs (single_pdev_only ⇒ hw_mode_id = MAX).
    let mut want = vec![0x004a_001c, 0, 0, 0, 0, 0, 0, 0];
    want.extend_from_slice(&words);
    want.push(0x0012_0000);
    ensure!(cmd.cmd_id == 0x1, "init cmd id");
    ensure!(cmd.buf.len() == 32 + 292 + 4, "init len = 328");
    ensure!(cmd.frame() == frame(0x1, &want), "init cmd golden");

    // Negative: without REG_CC_EXT the host_service_flags bit clears.
    let no_ext = TargetResourceConfig::qca6390(3, 2, false).to_wmi_bytes();
    ensure!(
        no_ext[276..280] == [0, 0, 0, 0],
        "host_service_flags 0 without REG_CC_EXT"
    );
    // 1 RF chain ⇒ chain masks 1.
    let one = TargetResourceConfig::qca6390(3, 1, false).to_wmi_bytes();
    ensure!(one[32..40] == le(&[1, 1])[..], "1 chain → masks 1");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_init_cmd_wcn6855_golden
);

fn smoke_ath11k_wmi_init_cmd_chunks_and_hw_mode() -> TestResult {
    let p = InitCmdParam {
        res_cfg: TargetResourceConfig::default(),
        mem_chunks: vec![
            HostMemChunk {
                paddr: 0x1_8000_0000,
                len: 0x10_0000,
                req_id: 1,
            },
            HostMemChunk {
                paddr: 0x9000_0000,
                len: 0x2000,
                req_id: 4,
            },
        ],
        hw_mode_id: hw_mode::DBS,
        band_to_mac: vec![
            BandToMac {
                pdev_id: 1,
                start_freq: 2412,
                end_freq: 2484,
            },
            BandToMac {
                pdev_id: 2,
                start_freq: 5180,
                end_freq: 7115,
            },
        ],
    };
    let cmd = match init_cmd(&p) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("init_cmd failed"),
    };
    // len = 32 + 4 + 292 + hw(16 + 4 + 2*16) + 16 * WMI_MAX_MEM_REQS(32)
    ensure!(
        cmd.buf.len() == 32 + 4 + 292 + 52 + 512,
        "reserves 32 chunks"
    );
    let b = &cmd.buf;
    ensure!(b[28..32] == le(&[2])[..], "num_host_mem_chunks = 2");
    let o = 32 + 292;
    let want = le(&[
        0x0012_0020, // ARRAY_STRUCT, 2 * 16
        0x004c_0010, // chunk tlv: len = sizeof(wlan_host_mem_chunk) = 16 (Linux quirk)
        1,           // req_id
        0x8000_0000, // ptr = lower 32 bits of paddr
        0x10_0000,   // size
        0x004c_0010,
        4,
        0x9000_0000,
        0x2000,
        0x0203_000c, // PDEV_SET_HW_MODE_CMD
        0,           // pdev_id (not set)
        1,           // hw_mode_index = DBS
        2,           // num_band_to_mac
        0x0012_0020, // ARRAY_STRUCT 2 * 16
        0x024b_000c,
        1,
        2412,
        2484,
        0x024b_000c,
        2,
        5180,
        7115,
    ]);
    ensure!(b[o..o + want.len()] == want[..], "chunk + hw mode layout");
    ensure!(
        b[o + want.len()..].iter().all(|&x| x == 0),
        "reserved tail zero"
    );
    // Negative: 33 chunks / 4 pdevs rejected.
    let mut too_many = p.clone();
    too_many.mem_chunks = vec![HostMemChunk::default(); 33];
    ensure!(init_cmd(&too_many).is_err(), "33 chunks rejected");
    let mut too_many = p;
    too_many.band_to_mac = vec![BandToMac::default(); 4];
    ensure!(init_cmd(&too_many).is_err(), "4 band_to_mac rejected");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_init_cmd_chunks_and_hw_mode
);

// ── VDEV ────────────────────────────────────────────────────────────

fn smoke_ath11k_wmi_vdev_create_golden() -> TestResult {
    let p = VdevCreateParams {
        if_id: 0,
        vdev_type: vdev_type::STA,
        subtype: vdev_subtype::NONE,
        chains_2g: Chains { tx: 2, rx: 2 },
        chains_5g: Chains { tx: 2, rx: 1 },
        pdev_id: 0,
        mbssid_flags: 0,
        mbssid_tx_vdev_id: 0,
    };
    let want = frame(
        0x5001,
        &[
            0x0056_0024, // VDEV_CREATE_CMD, 40 - 4
            0,           // vdev_id
            2,           // vdev_type STA
            0,           // subtype NONE
            MAC_W0,
            MAC_W1,
            2,           // num_cfg_txrx_streams = WMI_NUM_SUPPORTED_BAND_MAX
            0,           // pdev_id
            0,           // mbssid_flags
            0,           // mbssid_tx_vdev_id
            0x0012_0020, // ARRAY_STRUCT, 2 * 16
            0x019b_000c, // VDEV_TXRX_STREAMS, 16 - 4
            0,           // band 2G
            2,           // supported_tx_streams
            2,           // supported_rx_streams
            0x019b_000c,
            1, // band 5G
            2,
            1,
        ],
    );
    ensure!(
        vdev_create_cmd(&MAC, &p).frame() == want,
        "vdev_create golden"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_vdev_create_golden
);

fn he40_arg() -> VdevStartReqArg {
    VdevStartReqArg {
        vdev_id: 0,
        channel: ChannelArg {
            freq: 5180,
            band_center_freq1: 5190,
            band_center_freq2: 0,
            mode: phy_mode::MODE_11AX_HE40,
            allow_ht: true,
            allow_vht: true,
            allow_he: true,
            ht40plus: true,
            max_power: 30,
            max_reg_power: 23,
            max_antenna_gain: 0,
            ..Default::default()
        },
        bcn_intval: 100,
        dtim_period: 1,
        pref_rx_streams: 2,
        pref_tx_streams: 2,
        he_ops: 0x11,
        ssid: Some(b"narf".to_vec()),
        pmf_enabled: true,
        ..Default::default()
    }
}

fn smoke_ath11k_wmi_vdev_start_golden() -> TestResult {
    let arg = he40_arg();
    let chan = [
        0x0050_0018, // CHANNEL, 28 - 4
        5180,        // mhz
        5190,        // band_center_freq1
        0,           // band_center_freq2
        // info = MODE(17) | HT40_PLUS(6) | ALLOW_HT(11) | ALLOW_VHT(12) | ALLOW_HE(17)
        0x0002_1851,
        0x0017_1e00, // reg_info_1 = MAX_PWR 30 << 8 | MAX_REG_PWR 23 << 16
        0x0000_1e00, // reg_info_2 = ANT_MAX 0 | MAX_TX_PWR 30 << 8
    ];
    let mut body = vec![
        0x0058_0068, // VDEV_START_REQUEST_CMD, 108 - 4
        0,           // vdev_id
        0,           // requestor_id (never set)
        100,         // beacon_interval
        1,           // dtim_period
        0xa,         // flags = PMF_ENABLED | LDPC_RX_ENABLED
        4,           // ssid_len
        0x6672_616e, // "narf"
        0,
        0,
        0,
        0,
        0,
        0,
        0,    // ssid[1..8]
        0,    // bcn_tx_rate
        0,    // bcn_txpower
        0,    // num_noa_descriptors
        0,    // disable_hw_ack
        2,    // preferred_tx_streams
        2,    // preferred_rx_streams
        0x11, // he_ops
        0,    // cac_duration_ms
        0,    // regdomain
        0,    // min_data_rate
        0,    // mbssid_flags
        0,    // mbssid_tx_vdev_id
    ];
    body.extend_from_slice(&chan);
    body.push(0x0012_0000); // empty NoA ARRAY_STRUCT
    match vdev_start_cmd(&arg, false) {
        Ok(c) => ensure!(c.frame() == frame(0x5003, &body), "vdev_start golden"),
        Err(_) => return TestResult::Fail("vdev_start failed"),
    }
    // Restart: id 0x5004, SSID/hidden/PMF not filled, LDPC kept.
    let mut rbody = body.clone();
    rbody[5] = 0x8;
    rbody[6] = 0;
    rbody[7] = 0;
    match vdev_start_cmd(&arg, true) {
        Ok(c) => ensure!(c.frame() == frame(0x5004, &rbody), "vdev_restart golden"),
        Err(_) => return TestResult::Fail("vdev_restart failed"),
    }
    // HW crypto disabled + hidden SSID.
    let mut a2 = arg.clone();
    a2.hidden_ssid = true;
    a2.hw_crypto_disabled = true;
    match vdev_start_cmd(&a2, false) {
        Ok(c) => ensure!(
            c.buf[20..24] == le(&[0x1b])[..],
            "HIDDEN|PMF|LDPC|HW_ENC_DIS = 0x1b"
        ),
        Err(_) => return TestResult::Fail("vdev_start a2 failed"),
    }
    // Negative: SSID longer than 32 bytes.
    let mut bad = arg;
    bad.ssid = Some(vec![b'x'; 33]);
    ensure!(
        vdev_start_cmd(&bad, false).is_err(),
        "33-byte ssid rejected"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_vdev_start_golden
);

fn smoke_ath11k_wmi_put_channel_center_freqs() -> TestResult {
    // ath11k_wmi_put_wmi_channel HE160: cf1 = cf ± 40, cf2 = cf.
    let mut c = ChannelArg {
        freq: 5180,
        band_center_freq1: 5250,
        band_center_freq2: 9999,
        mode: phy_mode::MODE_11AX_HE160,
        ..Default::default()
    };
    let b = put_wmi_channel(&c);
    ensure!(
        b[8..16] == le(&[5210, 5250])[..],
        "HE160 below center: cf1-40"
    );
    c.freq = 5320;
    let b = put_wmi_channel(&c);
    ensure!(
        b[8..16] == le(&[5290, 5250])[..],
        "HE160 above center: cf1+40"
    );
    // 80+80 keeps cf2; others zero it.
    c.mode = phy_mode::MODE_11AC_VHT80_80;
    let b = put_wmi_channel(&c);
    ensure!(b[8..16] == le(&[5250, 9999])[..], "80+80 keeps cf2");
    c.mode = phy_mode::MODE_11AC_VHT80;
    let b = put_wmi_channel(&c);
    ensure!(b[8..16] == le(&[5250, 0])[..], "VHT80 zeroes cf2");
    // DFS / passive / adhoc / dfs_freq2 bits.
    c.passive = true;
    c.allow_ibss = true;
    c.chan_radar = true;
    c.freq2_radar = true;
    c.chan_change_cause_csa = true;
    let b = put_wmi_channel(&c);
    ensure!(
        b[16..20] == le(&[10 | 0x80 | 0x100 | 0x400 | 0x2_000 | 0x1_0000])[..],
        "info flag bits"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_put_channel_center_freqs
);

/// GTK WoW rekey offload has a fixed 52-byte command.  Linux
/// `ath11k_wmi_gtk_rekey_offload` keeps the key bytes unchanged on a
/// little-endian host and writes the host-order replay counter little-endian;
/// the status event reports that counter back as `(word1 << 32) | word0`.
fn smoke_ath11k_wmi_gtk_rekey_offload_golden() -> TestResult {
    let p = GtkRekeyOffloadParams {
        vdev_id: 7,
        kek: [0x11; 16],
        kck: [0x22; 16],
        replay_counter: 0x0102_0304_0506_0708,
    };
    let c = gtk_rekey_offload_cmd(7, gtk_offload_opcode::ENABLE, Some(&p));
    ensure!(c.cmd_id == 0x19001, "GTK offload command id");
    ensure!(c.buf.len() == 52, "GTK offload command size");
    ensure!(
        c.buf[..12] == le(&[0x005b_0030, 7, 0x0100_0000])[..],
        "GTK command header/vdev/opcode"
    );
    ensure!(c.buf[12..28] == p.kek, "GTK KEK bytes");
    ensure!(c.buf[28..44] == p.kck, "GTK KCK bytes");
    ensure!(
        c.buf[44..52] == [8, 7, 6, 5, 4, 3, 2, 1],
        "GTK replay counter is little-endian for WMI"
    );

    let status = gtk_rekey_offload_cmd(7, gtk_offload_opcode::REQUEST_STATUS, None);
    ensure!(
        status.buf[..12] == le(&[0x005b_0030, 7, 0x0400_0000])[..]
            && status.buf[12..].iter().all(|v| *v == 0),
        "GTK status request has a zeroed key payload"
    );

    let mut body = vec![0u8; WMI_GTK_OFFLOAD_STATUS_EVENT_PREFIX_SIZE];
    body[..20].copy_from_slice(&le(&[7, 0, 3, 0x0506_0708, 0x0102_0304]));
    let e = decode_gtk_offload_status(&tlv(WMI_TAG_GTK_OFFLOAD_STATUS_EVENT, &body));
    match e {
        Ok(s)
            if s.vdev_id == 7
                && s.refresh_count == 3
                && s.replay_counter_be() == [1, 2, 3, 4, 5, 6, 7, 8] => {}
        _ => return TestResult::Fail("GTK status replay counter decode"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_gtk_rekey_offload_golden
);

/// WoWLAN's control commands are fixed ABI structs except the bitmap
/// pattern, whose full 148-byte pattern/mask arrays Linux always sends.
/// These vectors are derived from `ath11k_wmi_wow_*`,
/// `ath11k_wmi_hw_data_filter_cmd`, and `ath11k_wmi_sta_keepalive`.
fn smoke_ath11k_wmi_wow_golden() -> TestResult {
    let enable = wow_enable_cmd();
    ensure!(
        enable.cmd_id == 0x13004 && enable.buf == le(&[0x0077_000c, 1, 0, 0]),
        "WoW enable command"
    );
    let wake = wow_wakeup_event_cmd(2, wow_event::DEAUTH, true);
    ensure!(
        wake == Ok(WmiCmd {
            cmd_id: 0x13003,
            buf: le(&[0x0089_000c, 2, 1, 1 << 2]),
        }),
        "WoW wake event command"
    );
    ensure!(
        wow_wakeup_event_cmd(0, wow_event::MAX, true).is_err(),
        "out-of-range WoW wake event"
    );
    let filter = hw_data_filter_cmd(
        2,
        hw_data_filter::DROP_NON_ARP_BROADCAST | hw_data_filter::DROP_NON_ICMPV6_MULTICAST,
        false,
    );
    ensure!(
        filter.cmd_id == 0x3b001 && filter.buf == le(&[0x026c_000c, 2, 0, u32::MAX]),
        "WoW data-filter disable programs all modes"
    );
    let keepalive = sta_keepalive_cmd(&StaKeepaliveParams {
        vdev_id: 2,
        enabled: true,
        method: sta_keepalive_method::NULL_FRAME,
        interval_secs: WMI_STA_KEEPALIVE_INTERVAL_DEFAULT,
        src_ipv4: 0,
        dst_ipv4: 0,
        dest_mac: [0; 6],
    });
    ensure!(
        keepalive.cmd_id == 0x1c005
            && keepalive.buf == le(&[0x007f_0010, 2, 1, 1, 30, 0x0080_0010, 0, 0, 0, 0]),
        "WoW null-frame keepalive command"
    );
    let pattern = wow_add_pattern_cmd(2, 3, &[0xaa, 0xbb], &[0xff, 0x00], 7);
    let Ok(pattern) = pattern else {
        return TestResult::Fail("WoW bitmap pattern rejected");
    };
    ensure!(
        pattern.cmd_id == 0x13001 && pattern.buf.len() == 360,
        "WoW pattern size"
    );
    ensure!(
        pattern.buf[..24] == le(&[0x00b3_000c, 2, 3, 0, 0x0012_013c, 0x00b4_0138])[..],
        "WoW pattern fixed headers"
    );
    ensure!(
        pattern.buf[24..26] == [0xaa, 0xbb]
            && pattern.buf[172..174] == [0xff, 0x00]
            && pattern.buf[320..336] == le(&[7, 2, 2, 3])[..],
        "WoW pattern placement"
    );
    ensure!(
        pattern.buf[336..360]
            == le(&[
                0x0012_0000,
                0x0012_0000,
                0x0012_0000,
                0x0010_0000,
                0x0010_0004,
                0
            ])[..],
        "WoW pattern optional arrays"
    );
    ensure!(
        wow_add_pattern_cmd(0, 0, &[], &[], 0).is_err()
            && wow_add_pattern_cmd(0, 0, &[1], &[1, 2], 0).is_err(),
        "WoW bitmap pattern bounds"
    );
    let arp_ns = ArpNsOffload {
        ipv4: vec![[192, 0, 2, 7]],
        ipv6: vec![
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        ],
        mac_addr: [0, 3, 0x7f, 1, 2, 3],
    };
    let arp_ns_cmd = arp_ns_offload_cmd(2, &arp_ns, true);
    let Ok(arp_ns_cmd) = arp_ns_cmd else {
        return TestResult::Fail("ARP/NS offload rejected a valid snapshot");
    };
    ensure!(
        arp_ns_cmd.cmd_id == 0x17001
            && arp_ns_cmd.buf.len() == 316
            && arp_ns_cmd.buf[..20] == le(&[0x007b_000c, 0, 2, 1, 0x0012_00a0])[..],
        "ARP/NS offload fixed header"
    );
    ensure!(
        arp_ns_cmd.buf[20..28] == le(&[0x007d_004c, 3])[..]
            && arp_ns_cmd.buf[28..44] == arp_ns.ipv6[0]
            && arp_ns_cmd.buf[60..76] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 7]
            && arp_ns_cmd.buf[92..100] == [0, 3, 0x7f, 1, 2, 3, 0, 0],
        "ARP/NS offload first NS tuple"
    );
    ensure!(
        arp_ns_cmd.buf[180..196] == le(&[0x0012_0030, 0x007c_0014, 1, 0x0702_00c0])[..]
            && arp_ns_cmd.buf[232..244] == le(&[0x0012_0050, 0x007d_004c, 3])[..],
        "ARP/NS offload ARP and extended NS arrays"
    );
    let wake = decode_wow_wakeup(&le(&[0x0031_0010, 2, 0, 10, 0]));
    ensure!(
        wake == Ok(WowWakeup {
            vdev_id: 2,
            flags: 0,
            reason: 10,
            data_len: 0,
        }),
        "WoW host wakeup decoder"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_wow_golden);

fn smoke_ath11k_wmi_vdev_up_golden() -> TestResult {
    let bssid = [0x00, 0x03, 0x7f, 0x01, 0x02, 0x03];
    // struct wmi_vdev_up_cmd {tlv, vdev, aid, bssid(8), tx_bssid(8), idx, cnt}
    let want = frame(
        0x5005,
        &[0x005c_0020, 0, 5, 0x017f_0300, 0x0000_0302, 0, 0, 0, 0],
    );
    ensure!(
        vdev_up_cmd(0, 5, &bssid, None, 0, 0, None).frame() == want,
        "vdev_up golden"
    );
    // Station non-transmitted BSS override replaces tx_bssid/idx/cnt.
    let ntx = NonTxBss {
        transmitter_bssid: MAC,
        bssid_index: 2,
        bssid_indicator: 3,
    };
    let want = frame(
        0x5005,
        &[
            0x005c_0020,
            0,
            5,
            0x017f_0300,
            0x0000_0302,
            MAC_W0,
            MAC_W1,
            2,
            3,
        ],
    );
    ensure!(
        vdev_up_cmd(0, 5, &bssid, Some(&bssid), 9, 9, Some(&ntx)).frame() == want,
        "vdev_up nontransmitted override"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_vdev_up_golden);

// ── PEER ASSOC / KEY ────────────────────────────────────────────────

fn assoc_params() -> PeerAssocParams {
    PeerAssocParams {
        vdev_id: 0,
        peer_new_assoc: 1,
        peer_associd: 1,
        peer_mac: MAC,
        peer_caps: 0x431,
        peer_listen_intval: 1,
        peer_ht_caps: 0x1ef,
        peer_max_mpdu: 65535,
        peer_mpdu_density: 0,
        peer_rate_caps: 0,
        peer_nss: 2,
        peer_vht_caps: 0x338001b2,
        peer_phymode: phy_mode::MODE_11AX_HE80,
        peer_legacy_rates: vec![0x0c, 0x12, 0x18],
        peer_ht_rates: (0..8).collect(),
        rx_max_rate: 780,
        rx_mcs_set: 0xfffa,
        tx_max_rate: 866,
        tx_mcs_set: 0xfffa,
        vht_capable: true,
        min_data_rate: 0,
        is_wme_set: true,
        qos_flag: true,
        ht_flag: true,
        bw_40: true,
        vht_flag: true,
        he_flag: true,
        auth_flag: true,
        need_ptk_4_way: true,
        is_assoc: true,
        is_pmf_enabled: true,
        peer_he_cap_macinfo: [0x1111, 0x2222],
        peer_he_ops: 0x3333,
        peer_he_cap_phyinfo: [0xa, 0xb, 0xc],
        peer_he_mcs: vec![(0xfffa, 0xfffa)],
        ..Default::default()
    }
}

fn smoke_ath11k_wmi_peer_assoc_golden() -> TestResult {
    let p = assoc_params();
    // flags: QOS|HT|40MHZ|VHT|HE (wme) | AUTH | PTK_4_WAY | PMF, then
    // AUTH cleared (need_ptk_4_way && is_assoc && hw crypto on).
    let flags = 0x2 | 0x1000 | 0x2000 | 0x0200_0000 | 0x400 | 0x4 | 0x0800_0000;
    ensure!(peer_assoc_flags(&p, false) == flags, "peer flags");
    let mut want: Vec<u32> = vec![
        0x0065_00a0, // PEER_ASSOC_COMPLETE_CMD, 164 - 4
        MAC_W0,
        MAC_W1,
        0,          // vdev_id
        1,          // peer_new_assoc
        1,          // peer_associd
        flags,      // peer_flags
        0x431,      // peer_caps
        1,          // peer_listen_intval
        0x1ef,      // peer_ht_caps
        65535,      // peer_max_mpdu
        0,          // peer_mpdu_density
        0,          // peer_rate_caps
        2,          // peer_nss
        0x338001b2, // peer_vht_caps
        18,         // peer_phymode HE80
        0,
        0, // peer_ht_info[2] (never written)
        3, // num_peer_legacy_rates
        8, // num_peer_ht_rates
        0, // peer_bw_rxnss_override
    ];
    want.extend_from_slice(&[0; 10]); // peer_ppet (zero)
    want.extend_from_slice(&[
        0x1111, // peer_he_cap_info = macinfo[0]
        0x3333, // peer_he_ops
        0xa,
        0xb,
        0xc,         // peer_he_cap_phy[3]
        1,           // peer_he_mcs = count
        0x2222,      // peer_he_cap_info_ext = macinfo[1]
        0,           // peer_he_cap_info_internal
        0,           // min_data_rate
        0,           // peer_he_caps_6ghz
        0x0011_0004, // ARRAY_BYTE legacy, roundup(3,4)
        0x0018_120c, // 0c 12 18 00
        0x0011_0008, // ARRAY_BYTE ht, 8
        0x0302_0100,
        0x0706_0504,
        0x0066_0014, // VHT_RATE_SET, 24 - 4
        866,         // rx_max_rate = param->tx_max_rate
        0xfffa,      // rx_mcs_set = param->tx_mcs_set
        780,         // tx_max_rate = param->rx_max_rate
        0xfffa,      // tx_mcs_set = param->rx_mcs_set
        0,           // tx_max_mcs_nss
        0x0012_000c, // ARRAY_STRUCT 1 * 12
        0x0285_0008, // HE_RATE_SET, 12 - 4
        0xfffa,      // rx_mcs_set
        0xfffa,      // tx_mcs_set
    ]);
    match peer_assoc_cmd(&p, false) {
        Ok(c) => {
            ensure!(c.buf.len() == 224, "assoc len 164+8+12+24+4+12");
            ensure!(c.frame() == frame(0x6005, &want), "peer_assoc golden");
        }
        Err(_) => return TestResult::Fail("peer_assoc failed"),
    }
    // Negative: 4 HE sets.
    let mut bad = p;
    bad.peer_he_mcs = vec![(0, 0); 4];
    ensure!(
        peer_assoc_cmd(&bad, false).is_err(),
        "4 HE rate sets rejected"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_peer_assoc_golden
);

fn smoke_ath11k_wmi_peer_assoc_flag_rules() -> TestResult {
    use super::wmi::peer_flags as f;
    let mut p = assoc_params();
    // hw crypto disabled keeps AUTH alongside PTK_4_WAY.
    ensure!(
        peer_assoc_flags(&p, true) & f::AUTH != 0,
        "AUTH kept with hw crypto off"
    );
    // No HT rates ⇒ HT cleared even though ht_flag.
    p.peer_ht_rates.clear();
    ensure!(
        peer_assoc_flags(&p, false) & f::HT == 0,
        "HT cleared without HT rates"
    );
    // safe mode drops PTK/GTK.
    p.need_gtk_2_way = true;
    p.safe_mode_enabled = true;
    let fl = peer_assoc_flags(&p, false);
    ensure!(
        fl & (f::NEED_PTK_4_WAY | f::NEED_GTK_2_WAY) == 0,
        "safe mode clears 4/2-way"
    );
    // !is_wme_set ⇒ none of the WME-gated bits.
    let mut q = assoc_params();
    q.is_wme_set = false;
    let fl = peer_assoc_flags(&q, false);
    ensure!(
        fl & (f::QOS | f::HT | f::VHT | f::HE | f::BW_40MHZ) == 0,
        "WME-gated bits off"
    );
    ensure!(fl & f::PMF != 0, "PMF independent of WME");
    // Without need_ptk_4_way, AUTH stays.
    q.need_ptk_4_way = false;
    ensure!(
        peer_assoc_flags(&q, false) & f::AUTH != 0,
        "AUTH stays without 4-way"
    );
    // vht_capable = false leaves the VHT rate set zero.
    let mut r = assoc_params();
    r.vht_capable = false;
    match peer_assoc_cmd(&r, false) {
        Ok(c) => ensure!(c.buf[188..208].iter().all(|&x| x == 0), "VHT rates zero"),
        Err(_) => return TestResult::Fail("assoc r failed"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_peer_assoc_flag_rules
);

fn smoke_ath11k_wmi_install_key_golden() -> TestResult {
    let key: Vec<u8> = (0x10..0x20).collect();
    let a = VdevInstallKeyArg {
        vdev_id: 0,
        macaddr: MAC,
        key_idx: 0,
        key_flags: WMI_KEY_PAIRWISE,
        key_cipher: cipher::AES_CCM,
        key_data: key,
        key_txmic_len: 0,
        key_rxmic_len: 0,
        key_rsc_counter: 0x0000_0001_0000_0002,
    };
    let mut want = vec![
        0x0060_0064, // VDEV_INSTALL_KEY_CMD, 104 - 4
        0,
        MAC_W0,
        MAC_W1,
        0, // key_idx
        0, // key_flags PAIRWISE
        4, // key_cipher AES_CCM
        2,
        1, // key_rsc_counter (u64 LE)
    ];
    want.extend_from_slice(&[0; 2 + 2 + 4 + 4]); // global rsc, tsc, wpi rsc/tsc
    want.extend_from_slice(&[
        16,          // key_len
        0,           // key_txmic_len
        0,           // key_rxmic_len
        0,           // is_group_key_id_valid
        0,           // group_key_id
        0x0011_0010, // ARRAY_BYTE 16
        0x1312_1110,
        0x1716_1514,
        0x1b1a_1918,
        0x1f1e_1d1c,
    ]);
    ensure!(
        vdev_install_key_cmd(&a).frame() == frame(0x5009, &want),
        "install key CCMP golden"
    );
    // WEP-40: key_len 5, ARRAY_BYTE len roundup = 8, pad zero.
    let mut w = a;
    w.key_cipher = cipher::WEP;
    w.key_data = vec![1, 2, 3, 4, 5];
    let c = vdev_install_key_cmd(&w);
    ensure!(c.buf.len() == 104 + 4 + 8, "WEP len");
    ensure!(c.buf[84..88] == le(&[5])[..], "key_len 5");
    ensure!(
        c.buf[104..116] == le(&[0x0011_0008, 0x0403_0201, 0x0000_0005])[..],
        "WEP key padded"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_install_key_golden
);

// ── SCAN ────────────────────────────────────────────────────────────

fn smoke_ath11k_wmi_scan_start_golden() -> TestResult {
    // ath11k_wmi_start_scan_init + ath11k_mac_op_hw_scan for a
    // single-pdev station: vdev 0, scan_id ATH11K_SCAN_ID,
    // FILTER_PROBE_REQ, one SSID, two channels, a 5-byte vendor IE.
    let mut p = ScanReqParams::start_scan_init(false, false);
    p.vdev_id = 0;
    p.scan_id = ATH11K_SCAN_ID;
    p.scan_ctrl_flags |= scan_flag::FILTER_PROBE_REQ;
    p.ssids = vec![b"narf".to_vec()];
    p.chan_list = vec![2412, 5180];
    p.extraie = vec![0xdd, 0x03, 0x00, 0x50, 0xf2];
    let mut want: Vec<u32> = vec![
        0x004d_009c, // START_SCAN_CMD, 160 - 4
        0xA000,      // scan_id
        1,           // scan_req_id
        0,           // vdev_id
        1,           // scan_priority LOW
        0x1f,        // notify: STARTED|COMPLETED|BSS_CHANNEL|FOREIGN_CHAN|DEQUEUED
        50,          // dwell_time_active
        150,         // dwell_time_passive
        50,          // min_rest_time
        500,         // max_rest_time
        0,           // repeat_probe_time
        0,           // probe_spacing_time
        0,           // idle_time
        20000,       // max_scan_time
        5,           // probe_delay
        0x30,        // scan_ctrl_flags: CHAN_STAT_EVENT | FILTER_PROBE_REQ
        0,           // burst_duration
        2,           // num_chan
        1,           // num_bssid (broadcast)
        1,           // num_ssids
        5,           // ie_len (unpadded)
        0,           // n_probes
        0,
        0, // mac_addr
        0,
        0, // mac_mask
    ];
    want.extend_from_slice(&[0; 8]); // ie_bitmap
    want.extend_from_slice(&[
        0,           // num_vendor_oui
        0,           // scan_ctrl_flags_ext
        0,           // dwell_time_active_2g
        40,          // dwell_time_active_6g
        30,          // dwell_time_passive_6g
        0,           // scan_start_offset
        0x0010_0008, // ARRAY_UINT32 2 channels
        2412,
        5180,
        0x0013_0024, // ARRAY_FIXED_STRUCT 1 * wmi_ssid(36)
        4,
        0x6672_616e,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x0013_0008, // ARRAY_FIXED_STRUCT 1 * wmi_mac_addr(8)
        0xffff_ffff,
        0x0000_ffff,
        0x0011_0008, // ARRAY_BYTE roundup(5, 4)
        0x5000_03dd,
        0x0000_00f2,
    ]);
    match scan_start_cmd(&p) {
        Ok(c) => {
            ensure!(c.buf.len() == 236, "scan start len");
            ensure!(c.frame() == frame(0x3001, &want), "scan start golden");
        }
        Err(_) => return TestResult::Fail("scan_start failed"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_scan_start_golden
);

fn smoke_ath11k_wmi_scan_start_variants() -> TestResult {
    // 11d preparing ⇒ MEDIUM; passive start-time service ⇒ ext flag.
    let p = ScanReqParams::start_scan_init(true, true);
    ensure!(p.scan_priority == scan_priority::MEDIUM, "11d prio medium");
    ensure!(p.scan_ctrl_flags_ext == 0x800, "ext passive start flag");
    // Bits Linux never copies are dropped; dwell mode lands in 23:21.
    let mut q = ScanReqParams::start_scan_init(false, false);
    q.scan_ctrl_flags =
        scan_flag::PASSIVE | scan_flag::BYPASS_DFS_CHN | scan_flag::CONTINUE_ON_ERROR;
    q.adaptive_dwell_time_mode = 2; // MODERATE
    q.bssid_list.clear();
    q.hint_s_ssid = vec![(0x11, 0xdead_beef)];
    q.hint_bssid = vec![HintBssid {
        freq_flags: 0x22,
        bssid: MAC,
    }];
    let c = match scan_start_cmd(&q) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("scan variant failed"),
    };
    ensure!(
        c.buf[60..64] == le(&[0x1 | (2 << 21)])[..],
        "PASSIVE + dwell, bypass/continue dropped"
    );
    // After the 160-byte struct: chan(0) ssid(0) bssid(0) ie(0) hdrs,
    // then s_ssid then bssid hints.
    let tail = le(&[
        0x0010_0000,
        0x0013_0000,
        0x0013_0000,
        0x0011_0000,
        0x0013_0008, // hint short ssid
        0x11,
        0xdead_beef,
        0x0013_000c, // hint bssid
        0x22,
        0, // bssid left zero: Linux's ether_addr_copy has its arguments reversed
        0,
    ]);
    ensure!(
        c.buf[160..] == tail[..],
        "hint TLVs and reversed-copy quirk"
    );
    // Negatives.
    let mut bad = ScanReqParams::start_scan_init(false, false);
    bad.ssids = vec![vec![0; 33]];
    ensure!(scan_start_cmd(&bad).is_err(), "33-byte scan ssid rejected");
    let mut bad = ScanReqParams::start_scan_init(false, false);
    bad.bssid_list = vec![[0; 6]; 5];
    ensure!(scan_start_cmd(&bad).is_err(), "5 bssids rejected");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_scan_start_variants
);

fn smoke_ath11k_wmi_scan_chan_list_golden() -> TestResult {
    let c1 = ChannelParam {
        mhz: 2412,
        cfreq1: 2412,
        allow_he: true,
        allow_vht: true, // ignored: HE wins
        phy_mode: phy_mode::MODE_11AX_HE20_2G,
        minpower: 0,
        maxpower: 30,
        maxregpower: 20,
        antennamax: 0,
        reg_class_id: 81,
        ..Default::default()
    };
    let c2 = ChannelParam {
        mhz: 5260,
        cfreq1: 5260,
        is_chan_passive: true,
        dfs_set: true,
        allow_vht: true,
        phy_mode: phy_mode::MODE_11AC_VHT20,
        maxpower: 24,
        maxregpower: 23,
        reg_class_id: 118,
        ..Default::default()
    };
    let want = frame(
        0x3003,
        &[
            0x004f_000c, // SCAN_CHAN_LIST_CMD, 16 - 4
            2,           // num_scan_chans
            0,           // flags (first send)
            0,           // pdev_id
            0x0012_0034, // ARRAY_STRUCT len = 2*28 - 4 (Linux quirk)
            0x0050_0018,
            2412,
            2412,
            0,
            0x0002_0015, // ALLOW_HE | MODE 21
            0x5114_1e00, // REG_CLS 81 | MAX_REG 20 | MAX 30 | MIN 0
            0x0000_1400, // MAX_TX_PWR = maxregpower 20 | ANT 0
            0x0050_0018,
            5260,
            5260,
            0,
            0x0000_1488, // PASSIVE | DFS | ALLOW_VHT | MODE 8
            0x7617_1800, // REG_CLS 118 | MAX_REG 23 | MAX 24
            0x0000_1700,
        ],
    );
    match scan_chan_list_cmds(0, &[c1, c2], 2048) {
        Ok(v) => {
            ensure!(v.len() == 1, "one command");
            ensure!(v[0].frame() == want, "scan chan list golden");
        }
        Err(_) => return TestResult::Fail("scan chan list failed"),
    }
    // Chunking: room for 2 per command (20 + 2*28 = 76).
    let chans = [c1; 5];
    match scan_chan_list_cmds(0, &chans, 76) {
        Ok(v) => {
            ensure!(v.len() == 3, "5 chans / 2 per cmd = 3 cmds");
            ensure!(
                v[0].buf[4..8] == le(&[2])[..] && v[2].buf[4..8] == le(&[1])[..],
                "counts"
            );
            ensure!(v[0].buf[8..12] == le(&[0])[..], "first: no APPEND");
            ensure!(v[1].buf[8..12] == le(&[1])[..], "second: APPEND flag");
            ensure!(v[2].buf[8..12] == le(&[1])[..], "third: APPEND flag");
        }
        Err(_) => return TestResult::Fail("chunked chan list failed"),
    }
    // Negative: max_msg_len below one channel.
    ensure!(
        scan_chan_list_cmds(0, &chans, 40).is_err(),
        "tiny max_msg_len rejected"
    );
    ensure!(
        matches!(scan_chan_list_cmds(0, &[], 40), Ok(v) if v.is_empty()),
        "empty list → no command"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_scan_chan_list_golden
);

// ── MGMT TX ─────────────────────────────────────────────────────────

fn smoke_ath11k_wmi_mgmt_send_golden() -> TestResult {
    let f: Vec<u8> = (0..30).collect();
    let want = frame(
        0x7008,
        &[
            0x01a6_0020, // MGMT_TX_SEND_CMD, 36 - 4
            0,           // vdev_id
            7,           // desc_id
            0,           // chanfreq
            0x2345_6780, // paddr_lo
            0x1,         // paddr_hi
            30,          // frame_len
            30,          // buf_len
            0,           // tx_params_valid
            0x0011_001e, // ARRAY_BYTE, len = 30 (unpadded)
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x0000_1d1c, // 2 bytes pad
        ],
    );
    ensure!(
        mgmt_send_cmd(0, 7, &f, 0x1_2345_6780, 0, false).frame() == want,
        "mgmt send golden"
    );
    // Long frame: only WMI_MGMT_SEND_DOWNLD_LEN (64) bytes inline, plus
    // TX_SEND_PARAMS with CFR_CAPTURE.
    let long: Vec<u8> = vec![0xab; 100];
    let c = mgmt_send_cmd(1, 2, &long, 0, 5180, true);
    ensure!(c.buf.len() == 36 + 4 + 64 + 12, "long len");
    ensure!(c.buf[12..16] == le(&[5180])[..], "chanfreq");
    ensure!(
        c.buf[24..36] == le(&[100, 64, 1])[..],
        "frame_len/buf_len/tx_params_valid"
    );
    ensure!(c.buf[36..40] == le(&[0x0011_0040])[..], "ARRAY_BYTE 64");
    ensure!(
        c.buf[104..116] == le(&[0x0284_0008, 0, 0x0020_0000])[..],
        "TX_SEND_PARAMS dword1 CFR"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_mgmt_send_golden);

// ── TLV walker ──────────────────────────────────────────────────────

fn smoke_ath11k_wmi_tlv_iter_rules() -> TestResult {
    // Two TLVs, no padding: a 3-byte ARRAY_BYTE immediately followed by
    // a header at offset 7 (Linux advances by exactly tlv_len).
    let mut buf = tlv(WMI_TAG_ARRAY_BYTE, &[1, 2, 3]);
    buf.extend_from_slice(&tlv(0x0999, &[9; 4])); // unknown tag, skipped by decoders
    let mut seen = Vec::new();
    let r = tlv_iter(&buf, |t| {
        seen.push((t.tag, t.offset, t.value.len()));
        Ok(())
    });
    ensure!(r.is_ok(), "walk ok");
    ensure!(seen == vec![(0x11, 4, 3), (0x999, 11, 4)], "unpadded walk");
    // Header truncated: 3 stray bytes.
    let mut b = tlv(WMI_TAG_ARRAY_BYTE, &[]);
    b.extend_from_slice(&[0, 0, 0]);
    ensure!(
        tlv_iter(&b, |_| Ok(())) == Err(WmiError::TlvHeaderTruncated { offset: 4 }),
        "truncated header"
    );
    // Length overrun.
    let mut b = tlv(WMI_TAG_ARRAY_BYTE, &[1, 2, 3, 4]);
    b.truncate(7);
    ensure!(
        matches!(
            tlv_iter(&b, |_| Ok(())),
            Err(WmiError::TlvOverrun { tag: 0x11, .. })
        ),
        "overrun"
    );
    // Policy minimum: SCAN_EVENT needs 28.
    let b = tlv(WMI_TAG_SCAN_EVENT, &[0; 24]);
    ensure!(
        tlv_iter(&b, |_| Ok(()))
            == Err(WmiError::TlvTooShort {
                tag: WMI_TAG_SCAN_EVENT,
                len: 24,
                min: 28
            }),
        "policy min"
    );
    ensure!(
        WmiError::TlvTooShort {
            tag: 0,
            len: 0,
            min: 0
        }
        .errno()
            == 22,
        "EINVAL"
    );
    ensure!(WmiError::Missing(0).errno() == 71, "EPROTO");
    ensure!(WmiError::TooMany(0).errno() == 105, "ENOBUFS");
    // Empty buffer is fine (Linux while (len > 0)).
    ensure!(tlv_iter(&[], |_| Ok(())).is_ok(), "empty ok");
    // Callback error stops the walk.
    let b = cat(&[tlv(1, &[]), tlv(2, &[])]);
    let mut n = 0;
    let r = tlv_iter(&b, |_| {
        n += 1;
        Err(WmiError::Invalid("stop"))
    });
    ensure!(r.is_err() && n == 1, "callback error stops");
    // tb[]: last one wins; tags >= WMI_TAG_MAX not recorded.
    let b = cat(&[
        tlv(WMI_TAG_VDEV_STOPPED_EVENT, &le(&[1])),
        tlv(WMI_TAG_VDEV_STOPPED_EVENT, &le(&[2])),
        tlv(WMI_TAG_MAX, &le(&[3])),
    ]);
    match TlvTable::parse(&b) {
        Ok(t) => {
            ensure!(
                t.get(WMI_TAG_VDEV_STOPPED_EVENT).map(|x| x.value) == Some(&le(&[2])[..]),
                "last wins"
            );
            ensure!(t.get(WMI_TAG_MAX).is_none(), "tag >= MAX ignored");
        }
        Err(_) => return TestResult::Fail("table parse"),
    }
    // split_event
    ensure!(
        split_event(&[1, 2, 3]) == Err(WmiError::ShortEvent),
        "short event"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_tlv_iter_rules);

fn smoke_ath11k_wmi_encoders_reparse() -> TestResult {
    // Every encoder output must walk cleanly under Linux's rules, the
    // command's first TLV carrying the right tag.
    let cmds = [
        vdev_create_cmd(&MAC, &VdevCreateParams::default()),
        vdev_up_cmd(0, 1, &MAC, None, 0, 0, None),
        peer_create_cmd(0, &MAC, 0),
        mgmt_send_cmd(0, 1, &[1, 2, 3], 0, 0, true),
        vdev_install_key_cmd(&VdevInstallKeyArg::default()),
    ];
    let tags = [
        WMI_TAG_VDEV_CREATE_CMD,
        WMI_TAG_VDEV_UP_CMD,
        WMI_TAG_PEER_CREATE_CMD,
        WMI_TAG_MGMT_TX_SEND_CMD,
        WMI_TAG_VDEV_INSTALL_KEY_CMD,
    ];
    for (c, &tag) in cmds.iter().zip(tags.iter()) {
        let mut first = None;
        if tlv_iter(&c.buf, |t| {
            first.get_or_insert(t.tag);
            Ok(())
        })
        .is_err()
        {
            // mgmt_send's ARRAY_BYTE is unpadded (len 3) and its 1-byte
            // pad then reads as a short header — exactly what Linux's own
            // walker would say; only that case may fail.
            if tag != WMI_TAG_MGMT_TX_SEND_CMD {
                return TestResult::Fail("encoder output does not walk");
            }
        }
        if first != Some(tag) {
            return TestResult::Fail("first TLV tag wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_encoders_reparse);

// ── SERVICE_READY / AVAILABLE ───────────────────────────────────────

pub(super) fn service_ready_fixed(num_rf_chains: u32) -> Vec<u8> {
    let mut w = vec![0u32; 32];
    w[0] = 0x0100_0042; // fw_build_vers
    w[9] = num_rf_chains; // @36
    w[10] = 0x19ef; // ht_cap_info @40
    w[19] = 64; // max_num_scan_channels @76
    w[26] = 1; // max_supported_macs @104
    w[29] = 0x0303_0303; // txrx_chainmask @116
    le(&w)
}

fn smoke_ath11k_wmi_service_ready_decode() -> TestResult {
    let mut bm = vec![0u32; 32];
    bm[0] = 0b0101; // services 0, 2
    bm[1] = 0x10; // bit 4 is outside the 4-bit window: ignored
    bm[31] = 0b1000; // service 127
    let ev = event(
        WMI_SERVICE_READY_EVENTID,
        &[
            tlv(WMI_TAG_SERVICE_READY_EVENT, &service_ready_fixed(2)),
            tlv(WMI_TAG_ARRAY_UINT32, &le(&bm)),
            tlv(WMI_TAG_ARRAY_UINT32, &le(&[0xffff_ffff; 32])), // second: ignored
        ],
    );
    let sr = match decode_event(&ev) {
        Ok(WmiEvent::ServiceReady(s)) => s,
        _ => return TestResult::Fail("service ready decode"),
    };
    let caps = match sr.caps {
        Some(c) => c,
        None => return TestResult::Fail("caps missing"),
    };
    ensure!(caps.num_rf_chains == 2, "num_rf_chains");
    ensure!(caps.ht_cap_info == 0x19ef, "ht_cap_info");
    ensure!(caps.max_num_scan_channels == 64, "max_num_scan_channels");
    ensure!(caps.max_supported_macs == 1, "max_supported_macs");
    ensure!(caps.txrx_chainmask == 0x0303_0303, "txrx_chainmask");
    ensure!(sr.fw_build_vers == 0x0100_0042, "fw_build_vers");
    let m = sr.svc_map;
    ensure!(
        m.test(0) && !m.test(1) && m.test(2) && m.test(127),
        "4-bit-per-word map"
    );
    ensure!(!m.test(4) && !m.test(8), "bits >= 4 ignored");
    // Negative: short bitmap (31 words) → EINVAL; short fixed → policy.
    let ev = cat(&[tlv(WMI_TAG_ARRAY_UINT32, &le(&[0; 31]))]);
    ensure!(decode_service_ready(&ev).is_err(), "short bitmap rejected");
    let ev = cat(&[tlv(WMI_TAG_SERVICE_READY_EVENT, &[0; 124])]);
    ensure!(
        matches!(
            decode_service_ready(&ev),
            Err(WmiError::TlvTooShort { min: 128, .. })
        ),
        "short fixed rejected"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_service_ready_decode
);

fn smoke_ath11k_wmi_service_available_decode() -> TestResult {
    // segment words carry 32 services each from WMI_MAX_SERVICE (128);
    // the trailing ARRAY_UINT32 from WMI_MAX_EXT_SERVICE (256).
    let seg = le(&[0, 0x1, 0, 0x1000_0000, 0x8000_0000]); // offset, bm[0..4]
    let ext2 = le(&[1 << 25, 0, 0, 0]); // 256 + 25 = 281
    let mut m = ServiceMap::default();
    let p = cat(&[
        tlv(WMI_TAG_SERVICE_AVAILABLE_EVENT, &seg),
        tlv(WMI_TAG_ARRAY_UINT32, &ext2),
    ]);
    ensure!(apply_service_available(&mut m, &p).is_ok(), "apply ok");
    ensure!(m.test(128), "segment bit 0 → 128");
    ensure!(
        m.test(220) && m.test(WMI_TLV_SERVICE_EXT2_MSG),
        "EXT2_MSG (128+92)"
    );
    ensure!(m.test(255), "word 3 bit 31 → 255");
    ensure!(
        m.test(WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT),
        "REG_CC_EXT 281"
    );
    ensure!(!m.test(129) && !m.test(282), "no stray bits");
    ensure!(!m.test(400), "out of range false");
    // Negative: short ext2 array; short segment TLV (policy 20).
    ensure!(
        apply_service_available(&mut m, &tlv(WMI_TAG_ARRAY_UINT32, &[0; 8])).is_err(),
        "short ext2 rejected"
    );
    ensure!(
        apply_service_available(&mut m, &tlv(WMI_TAG_SERVICE_AVAILABLE_EVENT, &[0; 16])).is_err(),
        "short segment rejected"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_service_available_decode
);

// ── SERVICE_READY_EXT ───────────────────────────────────────────────

fn hw_mode_cap(id: u32, phy_map: u32) -> Vec<u8> {
    tlv(WMI_TAG_HW_MODE_CAPABILITIES, &le(&[id, phy_map, 0]))
}

fn mac_phy(hw_mode_id: u32, pdev_id: u32, phy_id: u32, bands: u32, chains: u32) -> Vec<u8> {
    let mut w = vec![0u32; 59];
    w[0] = hw_mode_id;
    w[1] = pdev_id;
    w[2] = phy_id;
    w[4] = bands;
    w[5] = 7; // ampdu_density
    w[6] = 1; // max_bw_supported_2g
    w[12] = chains; // tx_chain_mask_2g
    w[13] = chains; // rx_chain_mask_2g
    w[14] = 3; // max_bw_supported_5g
    w[16] = 0x339b_79fa; // vht_cap_info_5g
    w[20] = chains; // tx_chain_mask_5g
    w[21] = chains; // rx_chain_mask_5g
    w[58] = 0b1_0101; // nss_ratio: enabled, info 0xa
    tlv(WMI_TAG_MAC_PHY_CAPABILITIES, &le(&w))
}

fn hal_reg(phy_id: u32, lo2: u32, hi2: u32, lo5: u32, hi5: u32) -> Vec<u8> {
    tlv(
        WMI_TAG_HAL_REG_CAPABILITIES_EXT,
        &le(&[phy_id, 0x6c, 0, 0, 0, 0, lo2, hi2, lo5, hi5]),
    )
}

/// WCN6855-shaped SERVICE_READY_EXT: SINGLE (phy 0, 2G+5G) and DBS
/// (phy 0 = 2G, phy 1 = 5G) modes, two phys.
pub(super) fn svc_rdy_ext_payload() -> Vec<u8> {
    cat(&[
        tlv(WMI_TAG_SERVICE_READY_EXT_EVENT, &[0; 76]),
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[2, 0])),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &cat(&[
                hw_mode_cap(hw_mode::SINGLE, 0x1),
                hw_mode_cap(hw_mode::DBS, 0x3),
            ]),
        ),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &cat(&[
                mac_phy(0, 1, 0, WMI_HOST_WLAN_2G_5G_CAP, 0x3),
                mac_phy(1, 1, 0, WMI_HOST_WLAN_2G_CAP, 0x1),
                mac_phy(1, 2, 1, WMI_HOST_WLAN_5G_CAP, 0x2),
            ]),
        ),
        tlv(WMI_TAG_SOC_HAL_REG_CAPABILITIES, &le(&[2])),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &cat(&[hal_reg(0, 2312, 2732, 0, 0), hal_reg(1, 0, 0, 5150, 7125)]),
        ),
        tlv(WMI_TAG_ARRAY_STRUCT, &[]), // chainmask combo
        tlv(WMI_TAG_ARRAY_STRUCT, &[]), // chainmask caps
        tlv(WMI_TAG_ARRAY_STRUCT, &[]), // OEM DMA ring caps
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &tlv(WMI_TAG_DMA_RING_CAPABILITIES, &le(&[1, 0, 16, 2048, 4])),
        ),
    ])
}

fn smoke_ath11k_wmi_service_ready_ext_wcn6855() -> TestResult {
    let p = svc_rdy_ext_payload();
    let e = match decode_service_ready_ext(&p, hw_mode::SINGLE, true) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("ext decode failed"),
    };
    // DBS (pri 1) beats the attach-time SINGLE (pri 5).
    ensure!(e.preferred_hw_mode == hw_mode::DBS, "preferred DBS");
    ensure!(e.pref_hw_mode_caps.phy_id_map == 0x3, "pref phy map");
    ensure!(e.mac_phy_caps.len() == 3, "3 mac phy caps (1 + 2 phys)");
    ensure!(e.param.num_hw_modes == 2 && e.param.num_phy == 2, "counts");
    // single_pdev_only: phys 1 and 2 (DBS) folded into pdevs[0].
    ensure!(e.num_radios == 1 && e.pdevs.len() == 1, "one radio");
    let pd = e.pdevs[0];
    ensure!(pd.pdev_id == 0, "pdev_id forced 0");
    ensure!(pd.supported_bands == 3, "2G | 5G accumulated");
    ensure!(
        pd.tx_chain_mask == 0x2 && pd.tx_chain_mask_shift == 1,
        "last (5G) chain mask"
    );
    ensure!(pd.vht_cap == 0x339b_79fa, "vht cap from 5G phy");
    ensure!(
        pd.nss_ratio_enabled == 1 && pd.nss_ratio_info == 0xa,
        "nss ratio fields"
    );
    ensure!(
        pd.band_2g.max_bw_supported == 1 && pd.band_5g.max_bw_supported == 3,
        "band caps"
    );
    ensure!(
        pd.band_6g.max_bw_supported == 3 && pd.band_6g.phy_id == 0,
        "6G mirrors 5G, phy_id untouched"
    );
    ensure!(pd.band_5g.phy_id == 1, "5G phy id");
    ensure!(e.target_pdev_ids == vec![(1, 1), (2, 2)], "target pdev ids");
    match e.hal_reg_cap(1) {
        Some(h) => ensure!(
            h.low_5ghz_chan == 5150 && h.high_5ghz_chan == 7125,
            "phy1 5G range"
        ),
        None => return TestResult::Fail("hal reg phy1"),
    }
    match e.hal_reg_cap(0) {
        Some(h) => ensure!(
            h.low_2ghz_chan == 2312 && h.eeprom_reg_domain == 0x6c,
            "phy0"
        ),
        None => return TestResult::Fail("hal reg phy0"),
    }
    ensure!(e.dma_ring_caps.len() == 1, "dma ring cap");
    ensure!(e.dma_ring_caps[0].pdev_id == 0, "DP_HW2SW_MACID(1) = 0");
    ensure!(e.dma_ring_caps[0].min_buf_sz == 2048, "dma min_buf_sz");
    // Non-single-pdev: two radios, real pdev ids.
    match decode_service_ready_ext(&p, hw_mode::MAX, false) {
        Ok(m) => {
            ensure!(m.num_radios == 2 && m.pdevs.len() >= 2, "two radios");
            ensure!(
                m.pdevs[0].pdev_id == 1 && m.pdevs[1].pdev_id == 2,
                "pdev ids"
            );
        }
        Err(_) => return TestResult::Fail("multi-pdev decode failed"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_service_ready_ext_wcn6855
);

fn smoke_ath11k_wmi_service_ready_ext_negative() -> TestResult {
    // Wrong tag inside the hw-mode array → EPROTO.
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &tlv(WMI_TAG_MAC_PHY_CAPABILITIES, &[0; 12]),
        ),
    ]);
    match decode_service_ready_ext(&p, hw_mode::SINGLE, true) {
        Err(e) => ensure!(
            e == WmiError::UnexpectedTag(WMI_TAG_MAC_PHY_CAPABILITIES) && e.errno() == 71,
            "EPROTO"
        ),
        Ok(_) => return TestResult::Fail("wrong tag accepted"),
    }
    // More hw modes than announced → ENOBUFS.
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &cat(&[hw_mode_cap(0, 1), hw_mode_cap(1, 3)]),
        ),
    ]);
    ensure!(
        decode_service_ready_ext(&p, hw_mode::SINGLE, true)
            == Err(WmiError::TooMany(WMI_TAG_HW_MODE_CAPABILITIES)),
        "ENOBUFS on extra hw mode"
    );
    // hw mode array before SOC_MAC_PHY_HW_MODE_CAPS: num_hw_modes 0 → ENOBUFS.
    let p = tlv(WMI_TAG_ARRAY_STRUCT, &hw_mode_cap(0, 1));
    ensure!(
        decode_service_ready_ext(&p, hw_mode::SINGLE, true).is_err(),
        "out of order"
    );
    // No preferred mode possible (initial MAX, no modes) → EINVAL.
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[0, 0])),
        tlv(WMI_TAG_ARRAY_STRUCT, &[]),
    ]);
    ensure!(
        matches!(
            decode_service_ready_ext(&p, hw_mode::MAX, true),
            Err(WmiError::Invalid(_))
        ),
        "no preferred mode"
    );
    // More MAC-PHY caps than phys in the hw modes → ENOBUFS.
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(WMI_TAG_ARRAY_STRUCT, &hw_mode_cap(1, 0x1)),
        tlv(
            WMI_TAG_ARRAY_STRUCT,
            &cat(&[mac_phy(1, 1, 0, 1, 1), mac_phy(1, 2, 1, 2, 1)]),
        ),
    ]);
    ensure!(
        decode_service_ready_ext(&p, hw_mode::SINGLE, true)
            == Err(WmiError::TooMany(WMI_TAG_MAC_PHY_CAPABILITIES)),
        "ENOBUFS on extra mac phy"
    );
    // SOC_HAL_REG before the arrays → EINVAL (pull_mac_phy_cap NULL caps).
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(WMI_TAG_SOC_HAL_REG_CAPABILITIES, &le(&[1])),
    ]);
    // pref caps are zero here (phy map 0) so no phys are pulled: Linux
    // accepts; force a phy map by giving DBS first:
    ensure!(
        decode_service_ready_ext(&p, hw_mode::SINGLE, true).is_ok(),
        "zero phy map pulls nothing"
    );
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(WMI_TAG_ARRAY_STRUCT, &hw_mode_cap(1, 0x1)),
        tlv(WMI_TAG_SOC_HAL_REG_CAPABILITIES, &le(&[1])),
    ]);
    ensure!(
        matches!(
            decode_service_ready_ext(&p, hw_mode::SINGLE, true),
            Err(WmiError::Invalid(_))
        ),
        "SOC_HAL_REG before MAC-PHY array"
    );
    // MAC-PHY with neither 2G nor 5G → EINVAL.
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(WMI_TAG_ARRAY_STRUCT, &hw_mode_cap(1, 0x1)),
        tlv(WMI_TAG_ARRAY_STRUCT, &mac_phy(1, 1, 0, 0, 1)),
        tlv(WMI_TAG_SOC_HAL_REG_CAPABILITIES, &le(&[1])),
    ]);
    ensure!(
        matches!(
            decode_service_ready_ext(&p, hw_mode::SINGLE, true),
            Err(WmiError::Invalid(_))
        ),
        "no band rejected"
    );
    // Only SINGLE advertised with attach-time SINGLE: pri not lower, so
    // pref caps stay zero and no radio caps are pulled (Linux keeps
    // num_radios = 1 with supported_bands = 0).
    let p = cat(&[
        tlv(WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS, &le(&[1, 0])),
        tlv(WMI_TAG_ARRAY_STRUCT, &hw_mode_cap(0, 0x1)),
        tlv(WMI_TAG_ARRAY_STRUCT, &mac_phy(0, 1, 0, 3, 3)),
        tlv(WMI_TAG_SOC_HAL_REG_CAPABILITIES, &le(&[1])),
    ]);
    match decode_service_ready_ext(&p, hw_mode::SINGLE, true) {
        Ok(e) => ensure!(
            e.preferred_hw_mode == hw_mode::SINGLE
                && e.num_radios == 1
                && e.pdevs[0].supported_bands == 0,
            "SINGLE-only keeps zero pref caps"
        ),
        Err(_) => return TestResult::Fail("single-only decode"),
    }
    // DMA ring cap with module_id >= WMI_DIRECT_BUF_MAX → EINVAL.
    let p = tlv(
        WMI_TAG_ARRAY_STRUCT,
        &tlv(WMI_TAG_DMA_RING_CAPABILITIES, &le(&[1, 2, 0, 0, 0])),
    );
    ensure!(decode_service_ready_ext2(&p).is_err(), "bad module id");
    let p = tlv(WMI_TAG_ARRAY_STRUCT, &tlv(WMI_TAG_CHANNEL, &[0; 20]));
    ensure!(decode_service_ready_ext2(&p).is_err(), "wrong dma tag");
    let p = tlv(
        WMI_TAG_ARRAY_STRUCT,
        &tlv(WMI_TAG_DMA_RING_CAPABILITIES, &le(&[0, 1, 8, 4096, 8])),
    );
    match decode_service_ready_ext2(&p) {
        Ok(v) => ensure!(
            v.len() == 1 && v[0].id == 1 && v[0].pdev_id == 0,
            "ext2 dma cap"
        ),
        Err(_) => return TestResult::Fail("ext2 decode"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_service_ready_ext_negative
);

// ── READY ───────────────────────────────────────────────────────────

fn smoke_ath11k_wmi_ready_decode() -> TestResult {
    // wmi_ready_event: abi[6] · mac(8) · status · num_dscp_table ·
    // num_extra_mac_addr · num_total_peers · num_extra_peers ·
    // max_ast_index · pktlog_defs_checksum
    let fixed = le(&[
        1,
        2,
        3,
        4,
        5,
        6,
        0x127f_0300,
        0x0000_5634, // 00:03:7f:12:34:56
        0,
        0,
        2,
        512,
        0,
        0x1000,
        0xcafe_babe,
    ]);
    let extra = le(&[0x017f_0300, 0x0000_0302, 0x027f_0300, 0x0000_0302]);
    let ev = event(
        WMI_READY_EVENTID,
        &[
            tlv(WMI_TAG_READY_EVENT, &fixed),
            tlv(WMI_TAG_ARRAY_FIXED_STRUCT, &extra),
        ],
    );
    let r = match decode_event(&ev) {
        Ok(WmiEvent::Ready(r)) => r,
        _ => return TestResult::Fail("ready decode"),
    };
    ensure!(
        r.mac_addr == [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56],
        "device MAC"
    );
    ensure!(r.fw_abi_vers == [1, 2, 3, 4, 5, 6], "abi");
    ensure!(
        r.num_extra_mac_addr == 2 && r.num_total_peers == 512,
        "counts"
    );
    ensure!(
        r.max_ast_index == 0x1000 && r.pktlog_defs_checksum == 0xcafe_babe,
        "tail"
    );
    ensure!(r.extra_mac_addrs.len() == 2, "extra addrs");
    ensure!(r.pdev_mac_addrs(1).is_none(), "single pdev ignores extras");
    ensure!(
        r.pdev_mac_addrs(2).map(|a| a[1][3]) == Some(0x02),
        "2 radios use extras"
    );
    ensure!(r.pdev_mac_addrs(3).is_none(), "fewer extras than radios");
    // Minimum (52-byte) READY: tail zero-extended.
    let ev = tlv(WMI_TAG_READY_EVENT, &fixed[..52]);
    match decode_ready(&ev) {
        Ok(r) => ensure!(
            r.max_ast_index == 0 && r.pktlog_defs_checksum == 0,
            "zero-extend"
        ),
        Err(_) => return TestResult::Fail("min ready"),
    }
    // Negatives.
    ensure!(
        matches!(
            decode_ready(&tlv(WMI_TAG_READY_EVENT, &fixed[..48])),
            Err(WmiError::TlvTooShort { min: 52, .. })
        ),
        "48-byte READY rejected"
    );
    ensure!(
        decode_ready(&[]) == Err(WmiError::Missing(WMI_TAG_READY_EVENT)),
        "missing READY"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_ready_decode);

// ── REG_CHAN_LIST ───────────────────────────────────────────────────

fn rule(start: u32, end: u32, bw: u32, pwr: u32, gain: u32, flags: u32) -> Vec<u8> {
    tlv(
        WMI_TAG_REGULATORY_RULE_STRUCT,
        &le(&[start | end << 16, bw | pwr << 16 | gain << 24, flags]),
    )
}

pub(super) fn ext_rule(start: u32, end: u32, bw: u32, pwr: u32, psd: u32) -> Vec<u8> {
    tlv(
        WMI_TAG_REGULATORY_RULE_EXT_STRUCT,
        &le(&[start | end << 16, bw | pwr << 16, 0, psd]),
    )
}

fn smoke_ath11k_wmi_reg_chan_list_decode() -> TestResult {
    // wmi_reg_chan_list_cc_event: status, phy_id, alpha2, num_phy,
    // country_id, domain_code, dfs_region, phybitmap, min/max bw 2g/5g,
    // num_2ghz, num_5ghz
    let fixed = le(&[7, 0, 0x0000_5355, 1, 840, 0x3a, 1, 0, 20, 40, 20, 160, 2, 1]);
    let rules = cat(&[
        rule(2402, 2472, 40, 30, 6, 0),
        rule(2457, 2482, 20, 20, 6, 0x2), // NO_IR
        rule(5170, 5250, 80, 23, 6, 0),
    ]);
    let ev = event(
        WMI_REG_CHAN_LIST_CC_EVENTID,
        &[
            tlv(WMI_TAG_REG_CHAN_LIST_CC_EVENT, &fixed),
            tlv(WMI_TAG_ARRAY_STRUCT, &rules),
        ],
    );
    let r = match decode_event(&ev) {
        Ok(WmiEvent::RegChanList(r)) => r,
        _ => return TestResult::Fail("reg chan list decode"),
    };
    ensure!(!r.is_ext_reg_event, "legacy");
    ensure!(r.alpha2 == *b"US", "alpha2");
    ensure!(
        r.status_code == 5,
        "unknown fw status 7 → REG_SET_CC_STATUS_FAIL"
    );
    ensure!(
        r.ctry_code == 840 && r.reg_dmn_pair == 0x3a && r.dfs_region == 1,
        "ids"
    );
    ensure!(r.max_bw_5ghz == 160, "bw");
    ensure!(
        r.rules_2ghz.len() == 2 && r.rules_5ghz.len() == 1,
        "rule split"
    );
    let x = r.rules_2ghz[1];
    ensure!(
        x.start_freq == 2457 && x.end_freq == 2482 && x.max_bw == 20,
        "rule freq/bw"
    );
    ensure!(
        x.reg_power == 20 && x.ant_gain == 6 && x.flags == 2,
        "rule pwr/gain/flags"
    );
    ensure!(r.rules_5ghz[0].start_freq == 5170, "5G rule");
    ensure!(cc_setting_code_to_reg(3) == 3, "status pass-through");
    // Negatives.
    let mut zero = fixed.clone();
    zero[48..56].copy_from_slice(&le(&[0, 0]));
    ensure!(
        decode_reg_chan_list(&cat(&[
            tlv(WMI_TAG_REG_CHAN_LIST_CC_EVENT, &zero),
            tlv(WMI_TAG_ARRAY_STRUCT, &[])
        ]))
        .is_err(),
        "no rules → EINVAL"
    );
    let mut many = fixed.clone();
    many[48..52].copy_from_slice(&le(&[5]));
    ensure!(
        decode_reg_chan_list(&cat(&[
            tlv(WMI_TAG_REG_CHAN_LIST_CC_EVENT, &many),
            tlv(WMI_TAG_ARRAY_STRUCT, &rules)
        ]))
        .is_err(),
        "rules past end rejected"
    );
    ensure!(
        decode_reg_chan_list(&tlv(WMI_TAG_ARRAY_STRUCT, &rules))
            == Err(WmiError::Missing(WMI_TAG_REG_CHAN_LIST_CC_EVENT)),
        "missing fixed TLV"
    );
    ensure!(
        decode_reg_chan_list(&tlv(WMI_TAG_REG_CHAN_LIST_CC_EVENT, &fixed[..52])).is_err(),
        "short fixed TLV"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_reg_chan_list_decode
);

pub(super) fn ext_fixed(n2: u32, n5: u32, n6_ap_lpi: u32, n6_cl_lpi_def: u32) -> Vec<u32> {
    let mut w = vec![0u32; 78];
    w[0] = 0; // status PASS
    w[2] = 0x0000_4544; // "DE"
    w[3] = 1;
    w[4] = 276;
    w[12] = n2;
    w[13] = n5;
    w[14] = 0; // client_type
    w[17] = 0x5; // domain_code_6ghz_ap_lpi
    w[18] = 0x6; // _sp
    w[19] = 0x7; // _vlp
    w[32] = 0x9; // super id
    w[33] = 20; // min_bw_6ghz_ap_sp
    w[34] = 160; // max sp
    w[35] = 21; // min lpi
    w[36] = 161; // max lpi
    w[47] = 22; // min_bw_6ghz_client_lpi[0]
    w[51] = 162; // max_bw_6ghz_client_lpi[0]
    w[64] = n6_ap_lpi; // num_6ghz_reg_rules_ap_lpi
    w[70] = n6_cl_lpi_def; // num_6ghz_reg_rules_client_lpi[DEFAULT]
    w
}

fn smoke_ath11k_wmi_reg_chan_list_ext_decode() -> TestResult {
    let fixed = ext_fixed(1, 2, 1, 1);
    let rules = cat(&[
        ext_rule(2402, 2482, 40, 20, 0),
        ext_rule(5170, 5730, 160, 23, 0),
        ext_rule(5945, 6425, 160, 24, 0), // a 6 GHz rule in the 5 GHz list
        ext_rule(5945, 6425, 320, 24, 0x0005_0001), // ap lpi, PSD eirp 5
        ext_rule(5945, 6425, 160, 18, 0x00fd_0001), // client lpi default, eirp -3
    ]);
    let ev = event(
        WMI_REG_CHAN_LIST_CC_EXT_EVENTID,
        &[
            tlv(WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT, &le(&fixed)),
            tlv(WMI_TAG_ARRAY_STRUCT, &rules),
        ],
    );
    let r = match decode_event(&ev) {
        Ok(WmiEvent::RegChanList(r)) => r,
        _ => return TestResult::Fail("reg ext decode"),
    };
    ensure!(
        r.is_ext_reg_event && r.alpha2 == *b"DE" && r.ctry_code == 276,
        "header"
    );
    ensure!(r.rules_2ghz.len() == 1, "2G rules");
    ensure!(
        r.rules_5ghz.len() == 1 && r.rules_5ghz[0].end_freq == 5730,
        "6G-in-5G rule dropped"
    );
    ensure!(r.rules_6ghz_ap[WMI_REG_INDOOR_AP].len() == 1, "AP LPI rule");
    ensure!(
        r.rules_6ghz_ap[WMI_REG_INDOOR_AP][0].max_bw == 320,
        "AP rule after skipped 5G entry"
    );
    ensure!(r.rules_6ghz_ap[WMI_REG_INDOOR_AP][0].psd_flag, "psd flag");
    ensure!(
        r.rules_6ghz_ap[WMI_REG_INDOOR_AP][0].psd_eirp == 5,
        "psd eirp"
    );
    let cl = &r.rules_6ghz_client[WMI_REG_INDOOR_AP][0];
    ensure!(
        cl.len() == 1 && cl[0].reg_power == 18 && cl[0].psd_eirp == -3,
        "client LPI rule"
    );
    ensure!(
        r.rules_6ghz_ap[WMI_REG_STANDARD_POWER_AP].is_empty(),
        "no SP"
    );
    ensure!(
        r.domain_code_6ghz_ap == [5, 6, 7] && r.domain_code_6ghz_super_id == 9,
        "domain codes"
    );
    ensure!(
        r.min_bw_6ghz_ap == [21, 20, 0] && r.max_bw_6ghz_ap == [161, 160, 0],
        "AP bw [lpi, sp, vlp]"
    );
    ensure!(
        r.min_bw_6ghz_client[WMI_REG_INDOOR_AP][0] == 22
            && r.max_bw_6ghz_client[WMI_REG_INDOOR_AP][0] == 162,
        "client bw"
    );
    // Negatives: per-band limits, zero total, rules past end.
    let lim = |w: &[u32]| {
        decode_reg_chan_list_ext(&cat(&[
            tlv(WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT, &le(w)),
            tlv(WMI_TAG_ARRAY_STRUCT, &rules),
        ]))
        .is_err()
    };
    ensure!(lim(&ext_fixed(11, 0, 0, 0)), "2G > MAX_REG_RULES");
    let mut w = ext_fixed(1, 0, 0, 0);
    w[63] = 6; // ap sp > MAX_6GHZ_REG_RULES
    ensure!(lim(&w), "6G AP > 5");
    let mut w = ext_fixed(1, 0, 0, 0);
    w[75] = 6; // client vlp subordinate > 5
    ensure!(lim(&w), "6G client > 5");
    ensure!(lim(&ext_fixed(0, 0, 0, 0)), "no rules");
    ensure!(lim(&ext_fixed(1, 2, 1, 2)), "rules past end");
    ensure!(
        decode_reg_chan_list_ext(&tlv(WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT, &le(&fixed)[..308]))
            .is_err(),
        "short ext fixed"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_reg_chan_list_ext_decode
);

// ── Small events ────────────────────────────────────────────────────

fn smoke_ath11k_wmi_small_event_decodes() -> TestResult {
    // VDEV_START_RESP: vdev, requestor, resp_type, status, chain_mask,
    // smps, mac_id, tx, rx, max_allowed_tx_power (s32)
    let ev = event(
        WMI_VDEV_START_RESP_EVENTID,
        &[tlv(
            WMI_TAG_VDEV_START_RESPONSE_EVENT,
            &le(&[0, 0, 1, 0, 3, 0, 0, 2, 2, (-2i32) as u32]),
        )],
    );
    match decode_event(&ev) {
        Ok(WmiEvent::VdevStartResp(r)) => ensure!(
            r.resp_type == WMI_VDEV_RESTART_RESP_EVENT
                && r.chain_mask == 3
                && r.max_allowed_tx_power == -2,
            "start resp fields"
        ),
        _ => return TestResult::Fail("start resp"),
    }
    let one = |id: u32, tag: u16, v: &[u32]| event(id, &[tlv(tag, &le(v))]);
    ensure!(
        decode_event(&one(
            WMI_VDEV_STOPPED_EVENTID,
            WMI_TAG_VDEV_STOPPED_EVENT,
            &[4]
        )) == Ok(WmiEvent::VdevStopped(4)),
        "stopped"
    );
    ensure!(
        decode_event(&one(
            WMI_VDEV_DELETE_RESP_EVENTID,
            WMI_TAG_VDEV_DELETE_RESP_EVENT,
            &[1]
        )) == Ok(WmiEvent::VdevDeleteResp(1)),
        "vdev delete resp"
    );
    ensure!(
        decode_event(&one(
            WMI_PEER_STA_KICKOUT_EVENTID,
            WMI_TAG_PEER_STA_KICKOUT_EVENT,
            &[MAC_W0, MAC_W1]
        )) == Ok(WmiEvent::PeerStaKickout(MAC)),
        "kickout"
    );
    ensure!(
        decode_event(&one(
            WMI_PEER_ASSOC_CONF_EVENTID,
            WMI_TAG_PEER_ASSOC_CONF_EVENT,
            &[0, MAC_W0, MAC_W1]
        )) == Ok(WmiEvent::PeerAssocConf(VdevPeer {
            vdev_id: 0,
            peer_macaddr: MAC
        })),
        "assoc conf"
    );
    ensure!(
        decode_event(&one(
            WMI_PEER_DELETE_RESP_EVENTID,
            WMI_TAG_PEER_DELETE_RESP_EVENT,
            &[1, MAC_W0, MAC_W1]
        )) == Ok(WmiEvent::PeerDeleteResp(VdevPeer {
            vdev_id: 1,
            peer_macaddr: MAC
        })),
        "peer delete resp"
    );
    match decode_event(&one(
        WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID,
        WMI_TAG_VDEV_INSTALL_KEY_COMPLETE_EVENT,
        &[0, MAC_W0, MAC_W1, 1, 1, 0],
    )) {
        Ok(WmiEvent::InstallKeyCompl(k)) => ensure!(
            k.macaddr == MAC && k.key_idx == 1 && k.key_flags == WMI_KEY_GROUP && k.status == 0,
            "install key compl"
        ),
        _ => return TestResult::Fail("install key compl"),
    }
    // SCAN: type, reason, freq, req_id, scan_id, vdev, tsf
    match decode_event(&one(
        WMI_SCAN_EVENTID,
        WMI_TAG_SCAN_EVENT,
        &[2, 1, 0, 1, 0xA000, 0, 77],
    )) {
        Ok(WmiEvent::Scan(s)) => ensure!(
            s.event_type == scan_event::COMPLETED
                && s.reason == scan_reason::CANCELLED
                && s.scan_id == 0xA000
                && s.tsf_timestamp == 77,
            "scan event"
        ),
        _ => return TestResult::Fail("scan event"),
    }
    match decode_event(&one(WMI_ROAM_EVENTID, WMI_TAG_ROAM_EVENT, &[0, 2, 60])) {
        Ok(WmiEvent::Roam(r)) => ensure!(r.reason == 2 && r.rssi == 60, "roam"),
        _ => return TestResult::Fail("roam"),
    }
    // MGMT_TX_COMPL: desc, status, pdev, ppdu, ack_rssi
    match decode_event(&one(
        WMI_MGMT_TX_COMPLETION_EVENTID,
        WMI_TAG_MGMT_TX_COMPL_EVENT,
        &[7, 0, 0, 99, 40],
    )) {
        Ok(WmiEvent::MgmtTxCompl(c)) => ensure!(
            c.desc_id == 7 && c.status == 0 && c.ack_rssi == 40,
            "tx compl"
        ),
        _ => return TestResult::Fail("tx compl"),
    }
    match decode_event(&one(
        WMI_PDEV_TEMPERATURE_EVENTID,
        WMI_TAG_PDEV_TEMPERATURE_EVENT,
        &[(-5i32) as u32, 0],
    )) {
        Ok(WmiEvent::PdevTemperature(t)) => ensure!(t.temp == -5, "temperature"),
        _ => return TestResult::Fail("temperature"),
    }
    // Negatives: missing TLV (EPROTO) / short TLV (policy or stricter).
    ensure!(
        decode_event(&one(WMI_SCAN_EVENTID, WMI_TAG_ROAM_EVENT, &[0, 0, 0]))
            == Err(WmiError::Missing(WMI_TAG_SCAN_EVENT)),
        "scan TLV missing"
    );
    ensure!(
        decode_event(&one(
            WMI_VDEV_START_RESP_EVENTID,
            WMI_TAG_VDEV_START_RESPONSE_EVENT,
            &[0; 9]
        ))
        .is_err(),
        "36-byte start resp rejected"
    );
    ensure!(
        decode_event(&one(
            WMI_PDEV_TEMPERATURE_EVENTID,
            WMI_TAG_PDEV_TEMPERATURE_EVENT,
            &[1]
        ))
        .is_err(),
        "short temperature rejected"
    );
    ensure!(
        decode_event(&one(
            WMI_MGMT_TX_COMPLETION_EVENTID,
            WMI_TAG_MGMT_TX_COMPL_EVENT,
            &[0; 4]
        ))
        .is_err(),
        "short tx compl rejected"
    );
    ensure!(
        decode_event(&le(&[0x9999])) == Ok(WmiEvent::Unhandled(0x9999)),
        "unhandled id"
    );
    ensure!(
        decode_event(&[0x01]) == Err(WmiError::ShortEvent),
        "short frame"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_small_event_decodes
);

fn mgmt_rx_hdr(channel: u32, snr: u32, buf_len: u32, status: u32, chan_freq: u32) -> Vec<u8> {
    // channel, snr, rate, phy_mode, buf_len, status, rssi_ctl[4],
    // flags, rssi, tsf_delta, rx_tsf_l32, rx_tsf_u32, pdev_id, chan_freq
    le(&[
        channel,
        snr,
        6000,
        0,
        buf_len,
        status,
        1,
        2,
        3,
        4,
        0,
        (-60i32) as u32,
        0,
        0,
        0,
        0,
        chan_freq,
    ])
}

fn smoke_ath11k_wmi_mgmt_rx_decode() -> TestResult {
    let f: Vec<u8> = (0..24).collect();
    let ev = event(
        WMI_MGMT_RX_EVENTID,
        &[
            tlv(WMI_TAG_MGMT_RX_HDR, &mgmt_rx_hdr(36, 50, 24, 0, 5180)),
            tlv(WMI_TAG_ARRAY_BYTE, &f),
            tlv(WMI_TAG_ARRAY_BYTE, &[0xee; 4]), // second byte array ignored
        ],
    );
    let m = match decode_event(&ev) {
        Ok(WmiEvent::MgmtRx(m)) => m,
        _ => return TestResult::Fail("mgmt rx decode"),
    };
    ensure!(m.frame == &f[..], "frame bytes");
    ensure!(
        m.rate == 6000 && m.rssi == -60 && m.rssi_ctl == [1, 2, 3, 4],
        "metadata"
    );
    match m.rx_status() {
        Some(s) => ensure!(
            s.band == Band::Ghz5 && s.freq == 5180 && s.signal == -45 && !s.mic_error,
            "5G status"
        ),
        None => return TestResult::Fail("status dropped"),
    }
    let st = |ch: u32, cf: u32, status: u32| {
        let p = cat(&[
            tlv(WMI_TAG_MGMT_RX_HDR, &mgmt_rx_hdr(ch, 30, 0, status, cf)),
            tlv(WMI_TAG_ARRAY_BYTE, &[]),
        ]);
        decode_mgmt_rx(&p).ok().and_then(|m| m.rx_status())
    };
    ensure!(
        st(14, 2484, 0).map(|s| (s.band, s.freq)) == Some((Band::Ghz2, 2484)),
        "ch14 2484"
    );
    ensure!(st(6, 2437, 0).map(|s| s.freq) == Some(2437), "ch6 2437");
    ensure!(
        st(1, 5955, 0).map(|s| (s.band, s.freq)) == Some((Band::Ghz6, 5955)),
        "6G by chan_freq"
    );
    ensure!(st(200, 0, 0).is_none(), "channel 200 dropped");
    ensure!(st(36, 5180, rx_status::ERR_CRC).is_none(), "CRC dropped");
    ensure!(
        st(36, 5180, rx_status::ERR_DECRYPT).is_none(),
        "decrypt dropped"
    );
    ensure!(
        st(36, 5180, rx_status::ERR_MIC).map(|s| s.mic_error) == Some(true),
        "MIC flagged"
    );
    // Negatives.
    let bad = cat(&[
        tlv(WMI_TAG_MGMT_RX_HDR, &mgmt_rx_hdr(36, 1, 100, 0, 0)),
        tlv(WMI_TAG_ARRAY_BYTE, &f),
    ]);
    ensure!(
        matches!(decode_mgmt_rx(&bad), Err(e) if e.errno() == 71),
        "buf_len past event → EPROTO"
    );
    let no_frame = tlv(WMI_TAG_MGMT_RX_HDR, &mgmt_rx_hdr(36, 1, 0, 0, 0));
    ensure!(
        decode_mgmt_rx(&no_frame) == Err(WmiError::Missing(WMI_TAG_ARRAY_BYTE)),
        "no frame"
    );
    ensure!(
        decode_mgmt_rx(&tlv(WMI_TAG_ARRAY_BYTE, &f)) == Err(WmiError::Missing(WMI_TAG_MGMT_RX_HDR)),
        "no hdr"
    );
    ensure!(
        decode_mgmt_rx(&tlv(WMI_TAG_MGMT_RX_HDR, &[0; 64])).is_err(),
        "short hdr"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_mgmt_rx_decode);

// ── HTC ─────────────────────────────────────────────────────────────

fn smoke_ath11k_htc_ids_and_layouts() -> TestResult {
    // SVC(group, idx) = group << 8 | idx
    ensure!(svc_id::RSVD_CTRL == 0x0001, "RSVD_CTRL");
    ensure!(svc_id::WMI_CONTROL == 0x0100, "WMI_CONTROL");
    ensure!(
        svc_id::WMI_DATA_BE == 0x0101 && svc_id::WMI_DATA_VO == 0x0104,
        "WMI data"
    );
    ensure!(
        svc_id::WMI_CONTROL_MAC1 == 0x0105 && svc_id::WMI_CONTROL_MAC2 == 0x0106,
        "MAC1/2"
    );
    ensure!(
        svc_id::NMI_CONTROL == 0x0200 && svc_id::NMI_DATA == 0x0201,
        "NMI"
    );
    ensure!(svc_id::HTT_DATA_MSG == 0x0300, "HTT");
    ensure!(
        svc_id::IPA_TX == 0x0500 && svc_id::PKT_LOG == 0x0600,
        "IPA/PKTLOG"
    );
    ensure!(svc_id::TEST_RAW_STREAMS == 0xfe00, "TEST");
    ensure!(
        msg_id::READY == 1 && msg_id::SETUP_COMPLETE_EX == 5 && msg_id::WAKEUP_FROM_SUSPEND == 8,
        "msg ids"
    );
    ensure!(ATH11K_HTC_EP_COUNT == 9, "EP count");
    // Header: eid | flags << 8 | len << 16 ; ctrl0 | ctrl1 << 8
    let h = HtcHdr {
        eid: 2,
        flags: ATH11K_HTC_FLAG_NEED_CREDIT_UPDATE,
        payload_len: 0x14,
        ctrl0: 0,
        ctrl1: 5,
    };
    ensure!(
        h.to_bytes() == [0x02, 0x01, 0x14, 0x00, 0x00, 0x05, 0x00, 0x00],
        "hdr golden"
    );
    ensure!(HtcHdr::parse(&h.to_bytes()) == Some(h), "hdr round trip");
    ensure!(HtcHdr::parse(&[0; 7]).is_none(), "short hdr");
    // Control messages.
    ensure!(
        connect_service_msg(svc_id::WMI_CONTROL, 0x100)
            == [0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00],
        "connect service golden"
    );
    ensure!(
        setup_complete_ex_msg(ATH11K_GLOBAL_DISABLE_CREDIT_FLOW, 0) == le(&[5, 2, 0]),
        "setup complete ex golden"
    );
    ensure!(
        ready_msg(15, 1792, 8) == le(&[0x000f_0001, 0x0008_0700]),
        "ready golden"
    );
    ensure!(
        ready_ext_msg(1, 2, 3, ATH11K_HTC_VERSION_2P1, 4)
            == le(&[0x0001_0001, 0x0003_0002, 0x0401]),
        "ready ext golden"
    );
    ensure!(
        HtcReady::parse(&ready_msg(15, 1792, 8))
            == Some(HtcReady {
                message_id: 1,
                credit_count: 15,
                credit_size: 1792,
                max_endpoints: 8
            }),
        "ready parse"
    );
    let resp = connect_service_resp_msg(svc_id::HTT_DATA_MSG, 0, 1, 1024, 0);
    ensure!(
        resp == le(&[0x0300_0003, 0x0400_0100, 0]),
        "conn resp golden"
    );
    ensure!(
        HtcConnSvcResp::parse(&resp).map(|r| (r.service_id, r.eid, r.max_msg_size))
            == Some((0x300, 1, 1024)),
        "conn resp parse"
    );
    ensure!(HtcConnSvcResp::parse(&resp[..11]).is_none(), "short resp");
    ensure!(
        credit_report_trailer(&[(2, 1)]) == [1, 4, 0, 0, 2, 1, 0, 0],
        "trailer golden"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htc_ids_and_layouts);

fn smoke_ath11k_htc_service_to_ce_map() -> TestResult {
    let m = &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390;
    ensure!(m.len() == 14, "svc_to_ce_map_len = 14");
    // hw.c order: VO, BK, BE, VI, WMI_CONTROL, RSVD_CTRL, HTT — each OUT then IN.
    let want: [(u32, u32, u32); 14] = [
        (0x104, 2, 3),
        (0x104, 1, 2),
        (0x102, 2, 3),
        (0x102, 1, 2),
        (0x101, 2, 3),
        (0x101, 1, 2),
        (0x103, 2, 3),
        (0x103, 1, 2),
        (0x100, 2, 3),
        (0x100, 1, 2),
        (0x001, 2, 0),
        (0x001, 1, 2),
        (0x300, 2, 4),
        (0x300, 1, 1),
    ];
    for (e, w) in m.iter().zip(want.iter()) {
        if (e.service_id, e.pipedir, e.pipenum) != *w {
            return TestResult::Fail("svc_to_ce_map entry differs from hw.c");
        }
    }
    ensure!(
        m[0].to_le_bytes() == [0x04, 0x01, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0],
        "wire form"
    );
    ensure!(
        map_service_to_pipe(m, svc_id::WMI_CONTROL) == Ok((3, 2)),
        "WMI ul 3 dl 2"
    );
    ensure!(
        map_service_to_pipe(m, svc_id::HTT_DATA_MSG) == Ok((4, 1)),
        "HTT ul 4 dl 1"
    );
    ensure!(
        map_service_to_pipe(m, svc_id::RSVD_CTRL) == Ok((0, 2)),
        "CTRL ul 0 dl 2"
    );
    ensure!(
        map_service_to_pipe(m, svc_id::PKT_LOG) == Err(HtcError::NoPipe(0x600)),
        "unmapped"
    );
    // A map with only one direction is ENOENT.
    let half = [m[0]];
    ensure!(
        matches!(map_service_to_pipe(&half, svc_id::WMI_DATA_VO), Err(e) if e.errno() == 2),
        "one direction only"
    );
    // wmi_ep_count switch.
    ensure!(wmi_ep_count(hw_mode::SINGLE, 3) == 1, "SINGLE → 1");
    ensure!(
        wmi_ep_count(hw_mode::DBS, 3) == 2 && wmi_ep_count(hw_mode::DBS_OR_SBS, 3) == 2,
        "DBS → 2"
    );
    ensure!(wmi_ep_count(hw_mode::DBS_SBS, 3) == 3, "DBS_SBS → 3");
    ensure!(
        wmi_ep_count(hw_mode::MAX, 3) == 3 && wmi_ep_count(hw_mode::SBS, 2) == 2,
        "default → max_radios"
    );
    ensure!(HtcConfig::wcn6855().wmi_ep_count == 1, "WCN6855 one WMI ep");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htc_service_to_ce_map
);

/// Run the WCN6855 handshake to Done: READY(credits, size), HTT on
/// eid 1, WMI on eid 2.
fn wcn6855_up(credits: u16, size: u16) -> Result<HtcHandshake, &'static str> {
    let mut hs = HtcHandshake::new(HtcConfig::wcn6855()).map_err(|_| "init")?;
    hs.on_rx(&target_frame(0, &ready_msg(credits, size, 8), &[]))
        .map_err(|_| "ready")?;
    hs.on_rx(&target_frame(
        0,
        &connect_service_resp_msg(svc_id::HTT_DATA_MSG, 0, 1, 1024, 0),
        &[],
    ))
    .map_err(|_| "htt")?;
    hs.on_rx(&target_frame(
        0,
        &connect_service_resp_msg(svc_id::WMI_CONTROL, 0, 2, 2048, 0),
        &[],
    ))
    .map_err(|_| "wmi")?;
    Ok(hs)
}

fn smoke_ath11k_htc_handshake_wcn6855() -> TestResult {
    let mut hs = match HtcHandshake::new(HtcConfig::wcn6855()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    ensure!(
        hs.services() == [0x300, 0x100],
        "plan: HTT then WMI_CONTROL"
    );
    // ath11k_htc_init: EP0 bound to RSVD_CTRL, flow off, pipes 0/2,
    // max_ep_message_len 0 (read from the zeroed dummy response).
    let ep0 = hs.htc.endpoints[0];
    ensure!(
        ep0.service_id == svc_id::RSVD_CTRL && !ep0.tx_credit_flow_enabled,
        "ep0 ctrl"
    );
    ensure!((ep0.ul_pipe_id, ep0.dl_pipe_id) == (0, 2), "ep0 pipes");
    ensure!(
        ep0.max_ep_message_len == 0 && ep0.max_tx_queue_depth == 2,
        "ep0 sizes"
    );
    ensure!(
        hs.htc.endpoints[1..]
            .iter()
            .all(|e| e.tx_credit_flow_enabled && !e.connected()),
        "others reset"
    );

    // READY: 15 credits of 1792 bytes.
    let a = match hs.on_rx(&target_frame(0, &ready_msg(15, 1792, 8), &[])) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("ready rx"),
    };
    ensure!(a.len() == 2, "Ready + Send");
    ensure!(
        matches!(a[0], HtcAction::Ready(r) if r.credit_count == 15 && r.credit_size == 1792),
        "ready action"
    );
    ensure!(
        hs.htc.total_transmit_credits == 1,
        "shadow regs clamp to 1 credit"
    );
    ensure!(hs.htc.target_credit_size == 1792, "credit size");
    ensure!(
        hs.htc.service_alloc_table[0] == (0x100, 1),
        "WMI_CONTROL gets 1"
    );
    // CONNECT HTT on EP0: hdr {eid 0, flags 0, len 8, seq 0},
    // msg {CONNECT_SERVICE | 0x300 << 16, RECV_ALLOC 0 | DISABLE_CREDIT_FLOW}.
    let want = le(&[0x0008_0000, 0x0000_0000, 0x0300_0002, 0x0000_0008]);
    match &a[1] {
        HtcAction::Send(tx) => ensure!(
            tx.pipe == 0 && tx.credits == 0 && tx.frame == want,
            "HTT connect golden"
        ),
        _ => return TestResult::Fail("expected send"),
    }
    ensure!(
        hs.state == HandshakeState::AwaitConnectResp(0x300),
        "await HTT"
    );

    let a = match hs.on_rx(&target_frame(
        0,
        &connect_service_resp_msg(0x300, 0, 1, 1024, 0),
        &[],
    )) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("htt resp"),
    };
    match a[0] {
        HtcAction::Connected(c) => ensure!(
            c.eid == 1
                && c.ul_pipe == 4
                && c.dl_pipe == 1
                && c.tx_credits == 0
                && !c.credit_flow
                && c.max_msg_len == 1024,
            "HTT connected"
        ),
        _ => return TestResult::Fail("expected HTT connected"),
    }
    // CONNECT WMI: seq 1, flags RECV_ALLOC(1) = 0x100, credit flow on.
    let want = le(&[0x0008_0000, 0x0000_0100, 0x0100_0002, 0x0000_0100]);
    match &a[1] {
        HtcAction::Send(tx) => ensure!(tx.frame == want, "WMI connect golden"),
        _ => return TestResult::Fail("expected WMI send"),
    }

    let a = match hs.on_rx(&target_frame(
        0,
        &connect_service_resp_msg(0x100, 0, 2, 2048, 0),
        &[],
    )) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("wmi resp"),
    };
    match a[0] {
        HtcAction::Connected(c) => ensure!(
            c.eid == 2
                && c.ul_pipe == 3
                && c.dl_pipe == 2
                && c.tx_credits == 1
                && c.credit_flow
                && c.max_msg_len == 2048,
            "WMI connected"
        ),
        _ => return TestResult::Fail("expected WMI connected"),
    }
    // SETUP_COMPLETE_EX: seq 2, len 12, {5, flags 0, 0}.
    let want = le(&[0x000c_0000, 0x0000_0200, 5, 0, 0]);
    match &a[1] {
        HtcAction::Send(tx) => ensure!(tx.pipe == 0 && tx.frame == want, "setup complete golden"),
        _ => return TestResult::Fail("expected setup send"),
    }
    ensure!(
        a.get(2) == Some(&HtcAction::SetupComplete),
        "setup complete action"
    );
    ensure!(hs.state == HandshakeState::Done, "done");
    ensure!(
        hs.htc.endpoint_for(svc_id::WMI_CONTROL).map(|e| e.eid) == Some(2),
        "lookup by svc"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htc_handshake_wcn6855
);

fn smoke_ath11k_htc_credit_exhaustion_and_replenish() -> TestResult {
    let mut hs = match wcn6855_up(15, 1792) {
        Ok(h) => h,
        Err(m) => return TestResult::Fail(m),
    };
    let cmd = pdev_set_param_cmd(1, 3, 0).frame(); // 20 bytes
                                                   // First WMI command spends the single credit: hdr flags
                                                   // NEED_CREDIT_UPDATE, seq 0 on ep 2, len 20.
    let tx = match hs.htc.send(2, &cmd) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("first send"),
    };
    ensure!(tx.pipe == 3 && tx.credits == 1, "1 credit on pipe 3");
    ensure!(
        tx.frame[..8] == [0x02, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00],
        "WMI hdr golden"
    );
    ensure!(tx.frame[8..] == cmd[..], "payload follows");
    // Second: out of credits → EAGAIN, nothing consumed, seq unchanged.
    match hs.htc.send(2, &cmd) {
        Err(e) => ensure!(
            e == HtcError::NoCredits {
                eid: 2,
                needed: 1,
                have: 0
            } && e.errno() == 11,
            "EAGAIN"
        ),
        Ok(_) => return TestResult::Fail("send without credits"),
    }
    ensure!(
        hs.htc.endpoints[2].seq_no == 1,
        "seq not advanced on failure"
    );
    // Credit report trailer on EP0 (trailer-only frame) replenishes.
    let a = match hs.on_rx(&target_frame(0, &[], &credit_report_trailer(&[(2, 1)]))) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("credit rx"),
    };
    ensure!(a == vec![HtcAction::TxCredits(2)], "TxCredits(2)");
    ensure!(hs.htc.endpoints[2].tx_credits == 1, "credit back");
    let tx2 = match hs.htc.send(2, &cmd) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("send after replenish"),
    };
    ensure!(tx2.frame[5] == 1, "seq 1");
    // CE send failure path returns the credit.
    hs.htc.revert_credits(&tx2);
    ensure!(hs.htc.endpoints[2].tx_credits == 1, "reverted");
    // Large payload needs DIV_ROUND_UP(len + 8, 1792) = 2 credits.
    let big = vec![0u8; 1785];
    match hs.htc.send(2, &big) {
        Err(HtcError::NoCredits {
            needed: 2, have: 1, ..
        }) => {}
        _ => return TestResult::Fail("1793 bytes need 2 credits"),
    }
    ensure!(
        hs.htc.send(2, &big[..1784]).map(|t| t.credits) == Ok(1),
        "1792 bytes = 1 credit"
    );
    // HTT endpoint has flow control off: no credits, no flag.
    let t = match hs.htc.send(1, &[0; 16]) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("htt send"),
    };
    ensure!(
        t.credits == 0 && t.frame[1] == 0 && t.pipe == 4,
        "HTT no credit, no flag"
    );
    // Data frame with an embedded credit trailer: delivered minus trailer.
    let f = target_frame(2, b"abcd", &credit_report_trailer(&[(2, 3), (1, 1)]));
    match hs.htc.rx(&f) {
        Ok(r) => {
            ensure!(r.credited == vec![2, 1], "credited eids");
            ensure!(
                r.kind
                    == HtcRxKind::Deliver {
                        eid: 2,
                        range: 8..12
                    },
                "deliver range"
            );
        }
        Err(_) => return TestResult::Fail("data rx"),
    }
    ensure!(hs.htc.endpoints[2].tx_credits == 3, "3 more credits");
    // Report for eid >= EP_COUNT stops the record (Linux break).
    let f = target_frame(0, &[], &credit_report_trailer(&[(9, 5), (2, 5)]));
    match hs.htc.rx(&f) {
        Ok(r) => ensure!(
            r.credited.is_empty() && r.kind == HtcRxKind::TrailerOnly,
            "eid 9 stops"
        ),
        Err(_) => return TestResult::Fail("eid9 trailer"),
    }
    ensure!(
        hs.htc.endpoints[2].tx_credits == 3,
        "no credits after break"
    );
    // Sequence number wraps at 256.
    hs.htc.endpoints[1].seq_no = 255;
    let a = hs.htc.send(1, &[]);
    let b = hs.htc.send(1, &[]);
    match (a, b) {
        (Ok(a), Ok(b)) => ensure!(a.frame[5] == 255 && b.frame[5] == 0, "seq wraps"),
        _ => return TestResult::Fail("wrap sends"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htc_credit_exhaustion_and_replenish
);

fn smoke_ath11k_htc_rx_rejections() -> TestResult {
    let mut hs = match wcn6855_up(15, 1792) {
        Ok(h) => h,
        Err(m) => return TestResult::Fail(m),
    };
    let htc = &mut hs.htc;
    ensure!(htc.rx(&[0; 7]) == Err(HtcError::ShortFrame), "short");
    let mut f = target_frame(9, &[0; 4], &[]);
    ensure!(htc.rx(&f) == Err(HtcError::InvalidEndpoint(9)), "eid 9");
    // payload_len + 8 > 4096
    f = HtcHdr {
        eid: 2,
        payload_len: 4089,
        ..Default::default()
    }
    .to_bytes()
    .to_vec();
    f.resize(8 + 4089, 0);
    ensure!(htc.rx(&f) == Err(HtcError::FrameTooLong(4097)), "too long");
    // Buffer shorter than payload_len.
    let mut f = target_frame(2, &[0; 8], &[]);
    f.truncate(12);
    ensure!(
        htc.rx(&f)
            == Err(HtcError::InsufficientLength {
                got: 4,
                expected: 8
            }),
        "insufficient"
    );
    // Trailer length < 4 or > payload.
    let mut f = target_frame(2, &[0; 4], &[1, 0, 0, 0]);
    f[4] = 3;
    ensure!(
        htc.rx(&f) == Err(HtcError::InvalidTrailerLen(3)),
        "trailer < 4"
    );
    let mut f = target_frame(2, &[0; 4], &[1, 0, 0, 0]);
    f[4] = 12;
    ensure!(
        htc.rx(&f) == Err(HtcError::InvalidTrailerLen(12)),
        "trailer > payload"
    );
    // Record length larger than what is left (Linux compares it to the
    // bytes left *including* the record header).
    let f = target_frame(0, &[], &[1, 9, 0, 0, 2, 1, 0, 0]);
    ensure!(htc.rx(&f) == Err(HtcError::InvalidRecord), "record overrun");
    // rlen == bytes left passes that check; only in-bounds reports count.
    let f = target_frame(0, &[], &[1, 8, 0, 0, 2, 1, 0, 0]);
    ensure!(
        htc.rx(&f).map(|r| r.credited) == Ok(vec![2]),
        "rlen == left accepted"
    );
    // Credit record shorter than one report.
    let f = target_frame(0, &[], &[1, 2, 0, 0, 2, 1, 0, 0]);
    ensure!(
        htc.rx(&f) == Err(HtcError::InvalidRecord),
        "short credit record"
    );
    // Unknown record id is skipped.
    let f = target_frame(0, &[], &[7, 0, 0, 0]);
    ensure!(
        htc.rx(&f).map(|r| r.kind) == Ok(HtcRxKind::TrailerOnly),
        "unknown record skipped"
    );
    // Data on an unconnected endpoint.
    let f = target_frame(5, &[0; 4], &[]);
    ensure!(
        htc.rx(&f) == Err(HtcError::NotConnected(5)),
        "unconnected eid"
    );
    // EP0 messages after setup.
    let f = target_frame(0, &le(&[msg_id::SEND_SUSPEND_COMPLETE as u32]), &[]);
    ensure!(
        htc.rx(&f).map(|r| r.kind) == Ok(HtcRxKind::SuspendComplete(true)),
        "suspend ack"
    );
    let f = target_frame(0, &le(&[msg_id::NACK_SUSPEND as u32]), &[]);
    ensure!(
        htc.rx(&f).map(|r| r.kind) == Ok(HtcRxKind::SuspendComplete(false)),
        "suspend nack"
    );
    let f = target_frame(0, &le(&[msg_id::WAKEUP_FROM_SUSPEND as u32]), &[]);
    ensure!(
        htc.rx(&f).map(|r| r.kind) == Ok(HtcRxKind::WakeupFromSuspend),
        "wakeup"
    );
    let f = target_frame(0, &le(&[0x77]), &[]);
    ensure!(
        htc.rx(&f).map(|r| r.kind) == Ok(HtcRxKind::IgnoredControl(0x77)),
        "ignored"
    );
    ensure!(
        htc.rx(&target_frame(0, &[1, 0], &[])) == Err(HtcError::ShortFrame),
        "EP0 msg < 4"
    );
    // TX to eid 9.
    ensure!(
        matches!(htc.send(9, &[]), Err(e) if e == HtcError::InvalidEndpoint(9) && e.errno() == 2),
        "send eid 9 ENOENT"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htc_rx_rejections);

fn smoke_ath11k_htc_handshake_failures() -> TestResult {
    let cfg = HtcConfig::wcn6855();
    // READY with zero credits → ECOMM.
    let mut hs = match HtcHandshake::new(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    match hs.on_rx(&target_frame(0, &ready_msg(0, 1792, 8), &[])) {
        Err(e) => ensure!(
            e == HtcError::BadReady && e.errno() == 70,
            "zero credits ECOMM"
        ),
        Ok(_) => return TestResult::Fail("zero credits accepted"),
    }
    // CONNECT_RESP while waiting for READY → bad READY.
    let mut hs = match HtcHandshake::new(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    ensure!(
        hs.on_rx(&target_frame(
            0,
            &connect_service_resp_msg(0x300, 0, 1, 1, 0),
            &[]
        )) == Err(HtcError::BadReady),
        "resp before ready"
    );
    // wait_target with nothing received.
    let mut h = match Htc::init(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    ensure!(
        h.wait_target() == Err(HtcError::NoControlResponse),
        "no response ETIMEDOUT"
    );
    // A second control message before the first is consumed is dropped.
    let r = target_frame(0, &ready_msg(4, 256, 8), &[]);
    ensure!(
        h.rx(&r).map(|x| x.kind) == Ok(HtcRxKind::Control(1)),
        "first stored"
    );
    ensure!(
        h.rx(&r).map(|x| x.kind) == Ok(HtcRxKind::UnsolicitedControl(1)),
        "second unsolicited"
    );
    ensure!(h.wait_target().is_ok() && !h.control_pending(), "consumed");
    // Connect failures.
    let resp_case = |resp: Vec<u8>| -> Result<HtcConnected, HtcError> {
        let mut h = Htc::init(cfg)?;
        h.rx(&target_frame(0, &ready_msg(4, 256, 8), &[]))?;
        h.wait_target()?;
        h.connect_service_request(svc_id::WMI_CONTROL, 0)?;
        h.rx(&target_frame(0, &resp, &[]))?;
        h.connect_service_complete()
    };
    ensure!(
        resp_case(connect_service_resp_msg(
            0x100,
            conn_status::NOT_FOUND,
            2,
            2048,
            0
        )) == Err(HtcError::ConnectRefused(1)),
        "refused"
    );
    ensure!(
        resp_case(connect_service_resp_msg(0x100, 0, 9, 2048, 0)) == Err(HtcError::BadAssignment),
        "eid 9"
    );
    ensure!(
        resp_case(connect_service_resp_msg(0x100, 0, 2, 0, 0)) == Err(HtcError::BadAssignment),
        "max msg 0"
    );
    ensure!(
        resp_case(connect_service_resp_msg(0x100, 0, 0, 2048, 0)) == Err(HtcError::BadAssignment),
        "eid 0 already RSVD_CTRL"
    );
    // A READY where the response belongs: wrong message id.
    ensure!(
        resp_case(ready_msg(4, 256, 8)) == Err(HtcError::BadConnectResp),
        "wrong msg id"
    );
    // 8-byte (short) response.
    let mut short = connect_service_resp_msg(0x100, 0, 2, 2048, 0);
    short.truncate(8);
    ensure!(
        resp_case(short) == Err(HtcError::BadConnectResp),
        "short resp"
    );
    match resp_case(connect_service_resp_msg(0x100, 0, 2, 2048, 0)) {
        Ok(c) => ensure!(c.eid == 2 && c.tx_credits == 1, "control case ok"),
        Err(_) => return TestResult::Fail("ok case"),
    }
    // Out-of-order calls.
    let mut h = match Htc::init(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    ensure!(
        h.connect_service_complete() == Err(HtcError::OutOfOrder),
        "complete w/o request"
    );
    ensure!(
        h.connect_service_request(svc_id::RSVD_CTRL, 0) == Err(HtcError::OutOfOrder),
        "RSVD_CTRL is local"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htc_handshake_failures
);

fn smoke_ath11k_htc_other_configs() -> TestResult {
    // No credit flow, three WMI endpoints, no shadow clamp.
    let cfg = HtcConfig {
        credit_flow: false,
        supports_shadow_regs: false,
        wmi_ep_count: 3,
        svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
    };
    let mut hs = match HtcHandshake::new(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init"),
    };
    ensure!(hs.services() == [0x300, 0x100, 0x105, 0x106], "4 services");
    let a = match hs.on_rx(&target_frame(0, &ready_msg(9, 2048, 8), &[])) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("ready"),
    };
    ensure!(hs.htc.total_transmit_credits == 9, "no clamp");
    ensure!(
        hs.htc.service_alloc_table[..3] == [(0x100, 3), (0x105, 3), (0x106, 3)],
        "9 credits split 3 ways"
    );
    ensure!(
        hs.htc.credit_allocation(0x105) == 3 && hs.htc.credit_allocation(0x300) == 0,
        "lookup"
    );
    ensure!(a.len() == 2, "ready + send");
    ensure!(
        hs.on_rx(&target_frame(
            0,
            &connect_service_resp_msg(0x300, 0, 1, 1024, 0),
            &[]
        ))
        .is_ok(),
        "HTT connected"
    );
    ensure!(
        hs.state == HandshakeState::AwaitConnectResp(0x100),
        "then WMI_CONTROL"
    );
    // The WMI connect frame sent after HTT: flags = 3 << 8 | 0x8.
    let mut h = match Htc::init(cfg) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init2"),
    };
    let _ = h.rx(&target_frame(0, &ready_msg(9, 2048, 8), &[]));
    let _ = h.wait_target();
    match h.connect_service_request(svc_id::WMI_CONTROL, 0) {
        Ok(tx) => ensure!(tx.frame[12..16] == le(&[0x0308])[..], "alloc 3 | DISABLE"),
        Err(_) => return TestResult::Fail("connect req"),
    }
    // SETUP_COMPLETE_EX carries GLOBAL_DISABLE_CREDIT_FLOW.
    match h.start() {
        Ok(tx) => ensure!(tx.frame[8..] == le(&[5, 2, 0])[..], "global disable flag"),
        Err(_) => return TestResult::Fail("start"),
    }
    // With credit_flow off, even a flow-enabled endpoint sends free.
    h.endpoints[3].tx_credits = 0;
    ensure!(
        h.send(3, &[0; 8]).map(|t| t.credits) == Ok(0),
        "no credit accounting"
    );
    // Before READY, a credit-flow endpoint cannot size credits.
    let mut h = match Htc::init(HtcConfig::wcn6855()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("init3"),
    };
    ensure!(
        h.send(2, &[0; 4]) == Err(HtcError::OutOfOrder),
        "no credit size yet"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htc_other_configs);

fn smoke_ath11k_htc_wmi_end_to_end() -> TestResult {
    // A WMI command through HTC, and a WMI event out of an HTC frame.
    let mut hs = match wcn6855_up(15, 1792) {
        Ok(h) => h,
        Err(m) => return TestResult::Fail(m),
    };
    let tx = match hs.htc.send(2, &vdev_delete_cmd(0).frame()) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("send"),
    };
    let want = [
        0x02, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00,
        0x00, // HTC: eid 2, NEED_CREDIT_UPDATE, len 12, seq 0
        0x02, 0x50, 0x00, 0x00, // wmi_cmd_hdr 0x5002
        0x04, 0x00, 0x57, 0x00, // VDEV_DELETE_CMD, len 4
        0x00, 0x00, 0x00, 0x00, // vdev_id 0
    ];
    ensure!(tx.frame == want, "HTC+WMI frame golden");
    let ev = event(
        WMI_VDEV_STOPPED_EVENTID,
        &[tlv(WMI_TAG_VDEV_STOPPED_EVENT, &le(&[0]))],
    );
    let f = target_frame(2, &ev, &[]);
    let a = match hs.on_rx(&f) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("rx"),
    };
    match a.as_slice() {
        [HtcAction::Deliver { eid: 2, range }] => {
            ensure!(
                decode_event(&f[range.clone()]) == Ok(WmiEvent::VdevStopped(0)),
                "event decodes"
            );
        }
        _ => return TestResult::Fail("expected one Deliver"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htc_wmi_end_to_end);
