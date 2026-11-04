//! Gen2 station regressions (pure frame/RA inputs). Expectations follow
//! Linux `rtl8xxxu/core.c` (`rtl8xxxu_bss_info_changed` ramask) and
//! mac80211 `ieee80211_subif_start_xmit` header construction; nothing here
//! is a hardware receipt.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{legacy_peer, open_data, open_qos_data};
use crate::rtl8xxxu::rtl8192e_ra::Ra;

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const BSSID: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn smoke_rtl8xxxu_gen2_legacy_peer_ra() -> TestResult {
    let peer = legacy_peer(0xf0ff);
    if peer.mask() != 0x0ff || peer.ht || peer.sgi {
        return TestResult::Fail("legacy ramask");
    }
    // Admitted mask covers the peer: accepted on both 1T and 2T owners.
    if Ra::new(peer, 0xfff, 1, false).is_err() || Ra::new(peer, 0xfff, 2, false).is_err() {
        return TestResult::Fail("admitted legacy peer");
    }
    // A peer rate outside the signed admitted mask refuses (no narrowing).
    if Ra::new(peer, 0x0f0, 1, false).is_ok() {
        return TestResult::Fail("narrowed admitted mask");
    }
    // Legacy peers never request 40 MHz.
    if Ra::new(peer, 0xfff, 1, true).is_ok() {
        return TestResult::Fail("40 MHz legacy peer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_legacy_peer_ra
);

fn smoke_rtl8xxxu_gen2_open_data_header() -> TestResult {
    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x10; 6]);
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&[1, 2, 3]);
    let Some(mpdu) = open_data(&eth, OWN, BSSID, 5) else {
        return TestResult::Fail("IPv4 refused");
    };
    if mpdu[..4] != [8, 1, 0, 0]
        || mpdu[4..10] != BSSID
        || mpdu[10..16] != OWN
        || mpdu[16..22] != [0x10; 6]
        || mpdu[22..24] != [0x50, 0]
        || mpdu[24..32] != [0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]
        || mpdu[32..] != [1, 2, 3]
    {
        return TestResult::Fail("non-QoS ToDS header");
    }
    // EAPOL from the Ethernet client and a foreign source are refused.
    let mut eapol = eth.clone();
    eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
    let mut foreign = eth.clone();
    foreign[6] ^= 2;
    if open_data(&eapol, OWN, BSSID, 0).is_some() || open_data(&foreign, OWN, BSSID, 0).is_some() {
        return TestResult::Fail("EAPOL/foreign source admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_open_data_header
);

/// `rtl8xxxu_queue_select` / `rtl8xxxu_80211_to_rtl_queue` on txdesc40 QoS
/// DATA: BK2, BE0, VI5, VO7 in txdw1 QSEL; the QoS control carries the TID.
fn smoke_rtl8xxxu_gen2_wmm_qos_data_queues() -> TestResult {
    use crate::rtl8xxxu::packet_codec::Kind;
    use crate::rtl8xxxu::rtl8192e_packet::{transmit, TxControl};
    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x10; 6]);
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00, 1, 2, 3]);
    if open_qos_data(&eth, OWN, BSSID, 0, 8).is_some() {
        return TestResult::Fail("TID 8 admitted");
    }
    for (tid, queue) in [
        (0u8, 0u32),
        (1, 2),
        (2, 2),
        (3, 0),
        (4, 5),
        (5, 5),
        (6, 7),
        (7, 7),
    ] {
        let Some(mpdu) = open_qos_data(&eth, OWN, BSSID, 9, tid) else {
            return TestResult::Fail("QoS DATA refused");
        };
        if mpdu[..2] != [0x88, 1]
            || mpdu[22..24] != [0x90, 0]
            || mpdu[24..26] != [tid, 0]
            || mpdu[26..34] != [0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]
        {
            return TestResult::Fail("QoS ToDS header");
        }
        let Ok(packet) = transmit(&mpdu, Kind::Data, TxControl::default()) else {
            return TestResult::Fail("txdesc40 refused QoS DATA");
        };
        let txdw1 = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        if (txdw1 >> 8) & 0x1f != queue {
            return TestResult::Fail("txdesc40 AC queue");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_wmm_qos_data_queues
);
