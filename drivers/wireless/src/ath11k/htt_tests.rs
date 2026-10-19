//! HTT codec tests.
//!
//! Expected words are hand-derived from Linux
//! `drivers/net/wireless/ath/ath11k/{dp.h,dp_tx.c,dp_rx.c,mac.c}` (the
//! `htt_*` structs, `enum htt_*` values, filter macros and
//! `ath11k_dp_htt_htc_t2h_msg_handler`), not from the code under test.
//! The SRING_SETUP / RX_RING_SELECTION_CFG goldens of every ring WCN6855
//! configures are in `dp_tests.rs` (they need the rings set up).

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::hal::*;
use super::hal_tests::{wcn6855, RecIo};
use super::htt::step;
use super::htt::*;

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn smoke_ath11k_htt_ver_req_golden() -> TestResult {
    // struct htt_ver_req_cmd { ver_reg_info = MSG_ID(VERSION_REQ = 0) }
    check!(
        ver_req_msg() == [0, 0, 0, 0],
        "VERSION_REQ is one zero word"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htt_ver_req_golden);

fn smoke_ath11k_htt_ring_id_type() -> TestResult {
    use HalRingType as T;
    // rx_mac_buf_ring = true (WCN6855): ring 128 (SW2RXDMA0_BUF, mac 0)
    // is the host → FW buffer ring, every other RXDMA_BUF a HW ring.
    check!(
        get_ring_id_type(true, 0, 128, T::RxdmaBuf)
            == Ok((HttRingType::SwToSw, HttRingId::Host1ToFwRxbuf)),
        "refill ring = HOST1_TO_FW_RXBUF, SW_TO_SW"
    );
    for (mac, id) in [(0, 129), (1, 144)] {
        check!(
            get_ring_id_type(true, mac, id, T::RxdmaBuf)
                == Ok((HttRingType::SwToHw, HttRingId::RxdmaHostBuf)),
            "rx_mac_buf rings = RXDMA_HOST_BUF, SW_TO_HW"
        );
    }
    check!(
        get_ring_id_type(true, 0, 133, T::RxdmaDst)
            == Ok((HttRingType::HwToSw, HttRingId::RxdmaNonMonitorDest)),
        "RXDMA_DST"
    );
    check!(
        get_ring_id_type(true, 0, 131, T::RxdmaMonitorStatus)
            == Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorStatus)),
        "MONITOR_STATUS"
    );
    check!(
        get_ring_id_type(true, 0, 130, T::RxdmaMonitorBuf)
            == Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorBuf)),
        "MONITOR_BUF"
    );
    check!(
        get_ring_id_type(true, 0, 134, T::RxdmaMonitorDst)
            == Ok((HttRingType::HwToSw, HttRingId::RxdmaMonitorDest)),
        "MONITOR_DST"
    );
    check!(
        get_ring_id_type(true, 0, 135, T::RxdmaMonitorDesc)
            == Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorDesc)),
        "MONITOR_DESC"
    );
    // rx_mac_buf_ring = false: SW2RXDMA0/1 of the mac are HW rings ...
    check!(
        get_ring_id_type(false, 1, 128 + 15, T::RxdmaBuf)
            == Ok((HttRingType::SwToHw, HttRingId::RxdmaHostBuf)),
        "QCA6390-style host buffer ring"
    );
    // ... anything else is -EINVAL.
    let e = get_ring_id_type(false, 0, 131, T::RxdmaBuf).unwrap_err();
    check!(
        e.step == step::RING_ID && e.detail == 131 && e.errno == errno::EINVAL,
        "foreign RXDMA_BUF ring id rejected"
    );
    // Rings the DP never configures over HTT.
    for ty in [T::TclData, T::ReoDst, T::Wbm2SwRelease, T::CeSrc] {
        let e = get_ring_id_type(true, 0, 16, ty).unwrap_err();
        check!(
            e.step == step::RING_TYPE && e.detail == ty as u32 && e.errno == errno::EINVAL,
            "\"Unsupported ring type in DP\""
        );
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htt_ring_id_type);

fn smoke_ath11k_htt_srng_setup_rejects() -> TestResult {
    let hw = wcn6855();
    let hal = Hal::new(&hw).expect("hal");
    let _io = RecIo::default();
    let e = srng_setup_msg(&hal, true, 128, 0, HalRingType::RxdmaBuf).unwrap_err();
    check!(
        e.step == step::NO_RING && e.detail == 128,
        "SRING_SETUP of a ring that is not set up"
    );
    let e = rx_filter_setup_msg(
        &hal,
        true,
        131,
        0,
        HalRingType::RxdmaMonitorStatus,
        2048,
        &MON_STATUS_FILTER_DEFAULT,
    )
    .unwrap_err();
    check!(
        e.step == step::NO_RING,
        "RX_RING_SELECTION_CFG of a missing ring"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htt_srng_setup_rejects
);

fn smoke_ath11k_htt_ppdu_stats_cfg_golden() -> TestResult {
    // HTT_PPDU_STATS_TAG_DEFAULT = COMMON(0) | USR_COMMON(1) | USR_RATE(2)
    // | SCH_CMD_STATUS(5) | USR_COMPLTN_COMMON(6) | ACK_BA_STATUS(9)
    // | FLUSH(10) | USR_COMMON_ARRAY(11) = 0xe67.
    check!(
        HTT_PPDU_STATS_TAG_DEFAULT == 0x0e67,
        "PPDU stats default mask"
    );
    let m = ppdu_stats_cfg_msgs(0, 2, HTT_PPDU_STATS_TAG_DEFAULT);
    // msg = 0x11 | pdev_mask << 9 | mask << 16
    check!(
        m.len() == 2,
        "one message per RXDMA (num_rxdma_per_pdev = 2)"
    );
    check!(
        m[0] == 0x0e67_0211u32.to_le_bytes(),
        "pdev mask 1 (pdev_idx 0 + 0)"
    );
    check!(
        m[1] == 0x0e67_0411u32.to_le_bytes(),
        "pdev mask 2 (pdev_idx 0 + 1)"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htt_ppdu_stats_cfg_golden
);

fn smoke_ath11k_htt_mon_status_filter_default() -> TestResult {
    let f = MON_STATUS_FILTER_DEFAULT;
    // rx_filter = MPDU_START(0) | PPDU_END(9) | PPDU_END_STATUS_DONE(12)
    check!(f.rx_filter == 0x1201, "rx_filter");
    // FP mgmt flags0: ASSOC_REQ 0, ASSOC_RESP 3, REASSOC_REQ 6,
    // REASSOC_RESP 9, PROBE_REQ 12, PROBE_RESP 15, TIMING_ADV 18,
    // BEACON 24, ATIM 27.
    check!(f.pkt_filter_flags0 == 0x0904_9249, "pkt_filter_flags0");
    // flags1: DISASSOC 0, AUTH 3, DEAUTH 6, ACTION 9, ACTION_NOACK 12
    check!(f.pkt_filter_flags1 == 0x0000_1249, "pkt_filter_flags1");
    // flags2: CTRL_WRAPPER 21, BAR 24, BA 27
    check!(f.pkt_filter_flags2 == 0x0920_0000, "pkt_filter_flags2");
    // flags3: data MCAST 18 | UCAST 21 | NULL 24, ctrl PSPOLL 0, RTS 3,
    // CTS 6, ACK 9, CFEND 12, CFEND_ACK 15
    check!(f.pkt_filter_flags3 == 0x0124_9249, "pkt_filter_flags3");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htt_mon_status_filter_default
);

fn smoke_ath11k_htt_t2h_decode() -> TestResult {
    // VERSION_CONF: type 0, minor 15:8, major 23:16
    check!(
        decode_t2h(&words(&[0x0003_0500])) == Ok(HttT2h::VersionConf { major: 3, minor: 5 }),
        "VERSION_CONF"
    );
    // PEER_MAP v1: info = 0x03 | vdev 1 << 8 | peer 0x42 << 16,
    // mac_addr_l32 = 00:03:7f:12 (LE), info1 = h16 0x3456 | hw id 0x77 << 16
    let map = [0x0042_0103, 0x127f_0300, 0x0077_3456, 0x0000_beef];
    check!(
        decode_t2h(&words(&map[..3]))
            == Ok(HttT2h::PeerMap {
                v2: false,
                vdev_id: 1,
                peer_id: 0x42,
                mac: [0x00, 0x03, 0x7f, 0x12, 0x56, 0x34],
                ast_hash: 0,
                hw_peer_id: 0,
            }),
        "PEER_MAP v1 (ast_hash / hw_peer_id passed as 0)"
    );
    let mut map2 = map;
    map2[0] = (map2[0] & !0xff) | 0x1e;
    check!(
        decode_t2h(&words(&map2))
            == Ok(HttT2h::PeerMap {
                v2: true,
                vdev_id: 1,
                peer_id: 0x42,
                mac: [0x00, 0x03, 0x7f, 0x12, 0x56, 0x34],
                ast_hash: 0xbeef,
                hw_peer_id: 0x77,
            }),
        "PEER_MAP2"
    );
    check!(
        decode_t2h(&words(&[0x0042_0104, 0, 0]))
            == Ok(HttT2h::PeerUnmap {
                v2: false,
                peer_id: 0x42
            }),
        "PEER_UNMAP"
    );
    check!(
        decode_t2h(&words(&[0x0042_011f, 0, 0]))
            == Ok(HttT2h::PeerUnmap {
                v2: true,
                peer_id: 0x42
            }),
        "PEER_UNMAP2"
    );
    let e = decode_t2h(&words(&[0x1d])).unwrap_err();
    check!(
        e.step == step::T2H_TRUNCATED && e.detail == (0x1d << 16) | 4,
        "PPDU_STATS_IND requires its four-word header"
    );
    for ty in [0x1cu32, 0x08, 0x24] {
        check!(
            decode_t2h(&words(&[ty])) == Ok(HttT2h::Skipped(ty as u8)),
            "debug / pktlog / backpressure skipped"
        );
    }
    // RX_ADDBA (5), SEC_IND (0xb) and unknown types: "not handled".
    for ty in [0x05u32, 0x0b, 0x7f] {
        check!(
            decode_t2h(&words(&[ty])) == Ok(HttT2h::Unhandled(ty as u8)),
            "unhandled T2H type"
        );
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htt_t2h_decode);

fn smoke_ath11k_htt_ppdu_stats_decode() -> TestResult {
    // HTT PPDU header (type 0x1d, 116-byte TLV payload, pdev 0), then
    // COMMON(36), USR_RATE(28), USR_COMPLTN_COMMON(16), ACK_BA_STATUS(20).
    let msg = words(&[
        0x0074_001d,
        0x0000_0088,
        0,
        0,
        0x0002_4000,
        0x0000_0088,
        0,
        0,
        0x0000_0123,
        0,
        0,
        0,
        0,
        0x0001_c002,
        0x0042_0000,
        0,
        0x0000_0069,
        0,
        0,
        0x1245_1400,
        0,
        0x0001_0006,
        0x0042_0000,
        40,
        0x0007_0008,
        0x0000_0132,
        0x0001_4009,
        0x0000_0088,
        0x0000_0042,
        0xa000_0e00,
        0,
        1200,
    ]);
    let Ok(HttT2h::PpduStats(ppdu)) = decode_t2h(&msg) else {
        return TestResult::Fail("PPDU statistics indication rejected");
    };
    check!(
        ppdu.pdev_id == 0 && ppdu.ppdu_id == 0x88 && ppdu.tx_duration_us == Some(0x123),
        "PPDU common header"
    );
    let Some(user) = ppdu.users.first() else {
        return TestResult::Fail("PPDU user missing");
    };
    check!(
        user.peer_id == 0x42
            && user.rate
                == Some(HttPpduRate {
                    preamble: 4,
                    bandwidth: 4,
                    nss: 2,
                    mcs: 5,
                    gi: 2,
                    dcm: true,
                    ru_start: 0,
                    ru_end: 105,
                }),
        "PPDU HE user rate"
    );
    check!(
        user.completion
            == Some(HttPpduCompletion {
                ack_rssi: 40,
                mpdu_tried: 8,
                mpdu_success: 7,
                long_retries: 2,
                short_retries: 3,
                ampdu: true,
            })
            && user.ack_ba
                == Some(HttPpduAckBa {
                    successful_msdu: 7,
                    tid: 5,
                    success_bytes: 1200,
                }),
        "PPDU completion accounting"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_htt_ppdu_stats_decode
);

fn smoke_ath11k_htt_t2h_truncated() -> TestResult {
    let e = decode_t2h(&[]).unwrap_err();
    check!(
        e.step == step::T2H_TRUNCATED && e.errno == errno::EINVAL,
        "empty message"
    );
    let e = decode_t2h(&[0x00, 0x05, 0x03]).unwrap_err();
    check!(e.detail == 3, "3-byte message (type 0, len 3)");
    let e = decode_t2h(&words(&[0x0042_0103, 0x127f_0300])).unwrap_err();
    check!(
        e.step == step::T2H_TRUNCATED && e.detail == (0x03 << 16) | 8,
        "PEER_MAP without info1"
    );
    let e = decode_t2h(&words(&[0x0042_011e, 0, 0])).unwrap_err();
    check!(
        e.detail == (0x1e << 16) | 12,
        "PEER_MAP2 without info2 (ast hash)"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htt_t2h_truncated);

fn smoke_ath11k_htt_version_check() -> TestResult {
    let mut t = HttTarget::default();
    check!(t.version_ok() == Ok(false), "no VERSION_CONF yet");
    t.version_received = true;
    t.ver_major = 3;
    t.ver_minor = 0x47;
    check!(t.version_ok() == Ok(true), "HTT 3.x accepted");
    t.ver_major = 2;
    let e = t.version_ok().unwrap_err();
    check!(
        e.step == step::VERSION && e.detail == 0x0247 && e.errno == 95,
        "major != HTT_TARGET_VERSION_MAJOR is -EOPNOTSUPP"
    );
    let e = HttTarget::timeout_error();
    check!(
        e.step == step::VERSION_TIMEOUT && e.errno == 110,
        "timeout is -ETIMEDOUT"
    );
    check!(HTT_TARGET_VERSION_TIMEOUT_MS == 3000, "3 * HZ");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_htt_version_check);
