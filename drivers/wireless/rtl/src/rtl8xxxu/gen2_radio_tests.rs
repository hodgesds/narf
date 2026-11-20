//! Gen2 station radio regressions (pure routing/conversion). Expectations
//! follow Linux `rtl8xxxu/core.c` (`rtl8xxxu_c2hcmd_callback`,
//! `rtl8xxxu_rx_addr_match`, `rtl8xxxu_parse_rxdesc24`); nothing here is a
//! hardware receipt.

use alloc::vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    admit, ht40_capability, ht40_local, ht_capability, ht_local, mpdu, route_c2h, rssi_match,
    station_admitted, C2hRoute,
};
use crate::rtl8xxxu::regs::ChipFamily;
use crate::rtl8xxxu::rtl8192e_packet::{C2h, Frame, RaReport};

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn report() -> RaReport {
    RaReport {
        rate: 12,
        sgi: false,
        macid: 0,
        ldpc: false,
        txbf: false,
        noisy: false,
        bandwidth40: None,
    }
}

fn smoke_rtl8xxxu_gen2_c2h_routing() -> TestResult {
    // RA reports route to Ra::report on both chips.
    for chip in [ChipFamily::Rtl8192eu, ChipFamily::Rtl8723bu] {
        if route_c2h(chip, C2h::RaReport(report())) != C2hRoute::Ra(report()) {
            return TestResult::Fail("RA report route");
        }
    }
    // C2H_8723B_BT_INFO (id 9) with its bt_info byte: BT path on 8723BU only.
    let bt = C2h::Other {
        id: 9,
        seq: 0,
        payload: vec![0, 0x11],
    };
    if route_c2h(ChipFamily::Rtl8723bu, bt.clone()) != C2hRoute::Bt(bt.clone()) {
        return TestResult::Fail("8723BU BT info route");
    }
    if route_c2h(ChipFamily::Rtl8192eu, bt) != C2hRoute::Ignore {
        return TestResult::Fail("8192EU has no BT coexistence");
    }
    // A BT-info body too short for the byte, and other ids, are ignored.
    let short = C2h::Other {
        id: 9,
        seq: 0,
        payload: vec![0],
    };
    let other = C2h::Other {
        id: 3,
        seq: 0,
        payload: vec![0, 0],
    };
    if route_c2h(ChipFamily::Rtl8723bu, short) != C2hRoute::Ignore
        || route_c2h(ChipFamily::Rtl8723bu, other) != C2hRoute::Ignore
    {
        return TestResult::Fail("unrouted C2H");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_c2h_routing
);

fn smoke_rtl8xxxu_gen2_rssi_match_and_mpdu() -> TestResult {
    let mut data = vec![0u8; 24];
    data[0] = 0x08;
    data[1] = 0x02;
    data[4..10].copy_from_slice(&LOCAL);
    data[10..16].copy_from_slice(&PEER);
    if !rssi_match(&data, LOCAL, PEER) {
        return TestResult::Fail("unicast from BSS");
    }
    let mut beacon = vec![0u8; 24];
    beacon[0] = 0x80;
    beacon[4..10].copy_from_slice(&[0xff; 6]);
    beacon[10..16].copy_from_slice(&PEER);
    if !rssi_match(&beacon, LOCAL, PEER) {
        return TestResult::Fail("beacon from BSS");
    }
    let mut foreign = data.clone();
    foreign[10] ^= 1;
    if rssi_match(&foreign, LOCAL, PEER) || rssi_match(&data[..23], LOCAL, PEER) {
        return TestResult::Fail("foreign/short frame");
    }
    let frame = Frame {
        bytes: data.clone(),
        phy: vec![1, 2],
        rate: 4,
        bandwidth40: false,
        tid: 0,
        qos: false,
        macid: 0,
        decrypted: false,
        amsdu: false,
        paggr: false,
        more_frag: false,
        ldpc: false,
        stbc: false,
        timestamp: 7,
    };
    let m = mpdu(frame);
    if m.bytes != data
        || m.phy != [1, 2]
        || m.rate != 4
        || m.ht
        || m.timestamp != 7
        || m.native.is_some()
        || !m.admitted(false)
    {
        return TestResult::Fail("legacy rxdesc24 MPDU conversion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_rssi_match_and_mpdu
);

fn frame(bytes: alloc::vec::Vec<u8>, rate: u8, qos: bool, tid: u8) -> Frame {
    Frame {
        bytes,
        phy: vec![],
        rate,
        bandwidth40: false,
        tid,
        qos,
        macid: 0,
        decrypted: false,
        amsdu: false,
        paggr: false,
        more_frag: false,
        ldpc: false,
        stbc: false,
        timestamp: 0,
    }
}

fn qos_data(qc: u8) -> alloc::vec::Vec<u8> {
    let mut b = vec![0x88, 0x02, 0, 0];
    b.extend_from_slice(&LOCAL);
    b.extend_from_slice(&PEER);
    b.extend_from_slice(&PEER);
    b.extend_from_slice(&[0x10, 0, qc, 0]);
    b.extend_from_slice(&[0xaa; 8]);
    b
}

/// Linux `rtl8xxxu_parse_rxdesc24` facts under the gen2 HT20 profile:
/// HT MCS only with an HT association and within the advertised streams,
/// A-MPDU members only on a recipient-session TID, standalone A-MSDU only
/// when descriptor and header agree, never 40 MHz.
fn smoke_rtl8xxxu_gen2_ht20_rx_admission() -> TestResult {
    let legacy = frame(qos_data(0), 4, true, 0);
    if !admit(&legacy, false, false, 0, 1) || !admit(&legacy, true, false, 0, 1) {
        return TestResult::Fail("legacy QoS DATA");
    }
    let mcs7 = frame(qos_data(0), 19, true, 0);
    if admit(&mcs7, false, false, 0, 1) || !admit(&mcs7, true, false, 0, 1) {
        return TestResult::Fail("HT MCS7 needs the HT association");
    }
    let mcs8 = frame(qos_data(0), 20, true, 0);
    if admit(&mcs8, true, false, 0, 1) || !admit(&mcs8, true, false, 0, 2) {
        return TestResult::Fail("MCS8 needs a second advertised stream");
    }
    let mut wide = frame(qos_data(0), 19, true, 0);
    wide.bandwidth40 = true;
    if admit(&wide, true, false, 0, 2) {
        return TestResult::Fail("40 MHz is not granted");
    }
    let mut member = frame(qos_data(5), 19, true, 5);
    member.paggr = true;
    if admit(&member, true, false, 0, 1)
        || admit(&member, true, false, 1, 1)
        || !admit(&member, true, false, 1 << 5, 1)
    {
        return TestResult::Fail("A-MPDU member needs the TID's session");
    }
    let m = mpdu(member);
    if !m.ht || !m.ba || !station_admitted(&m, true, false) || station_admitted(&m, false, false) {
        return TestResult::Fail("HT MPDU conversion");
    }
    let mut amsdu = frame(qos_data(0x83), 19, true, 3);
    amsdu.amsdu = true;
    if !admit(&amsdu, true, false, 0, 1) || admit(&amsdu, false, false, 0, 1) {
        return TestResult::Fail("standalone A-MSDU");
    }
    let mut inside = frame(qos_data(0x83), 19, true, 3);
    inside.amsdu = true;
    inside.paggr = true;
    if admit(&inside, true, false, 1 << 3, 1) {
        return TestResult::Fail("A-MSDU inside an A-MPDU");
    }
    // Header A-MSDU bit without the descriptor bit, and the converse.
    let header_only = frame(qos_data(0x83), 19, true, 3);
    let mut desc_only = frame(qos_data(3), 19, true, 3);
    desc_only.amsdu = true;
    if admit(&header_only, true, false, 0, 1) || admit(&desc_only, true, false, 0, 1) {
        return TestResult::Fail("A-MSDU descriptor/header disagreement");
    }
    let mut legacy_ba = mpdu(frame(qos_data(0), 4, true, 0));
    legacy_ba.ba = true;
    if station_admitted(&legacy_ba, true, false) {
        return TestResult::Fail("legacy-rate A-MPDU member");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ht20_rx_admission
);

/// Gen2 HT40 grant facts: 40 MHz DATA and standalone A-MSDU only under
/// an active wide grant; without it the 40 MHz frame is refused even
/// with an HT association.
fn smoke_rtl8xxxu_gen2_ht40_rx_admission() -> TestResult {
    let mut wide = frame(qos_data(0), 19, true, 0);
    wide.bandwidth40 = true;
    if !admit(&wide, true, true, 0, 2) || admit(&wide, true, false, 0, 2) {
        return TestResult::Fail("40 MHz DATA needs the wide grant");
    }
    let mut amsdu = frame(qos_data(0x83), 19, true, 3);
    amsdu.amsdu = true;
    amsdu.bandwidth40 = true;
    if !admit(&amsdu, true, true, 0, 1) || admit(&amsdu, true, false, 0, 1) {
        return TestResult::Fail("40 MHz standalone A-MSDU needs the wide grant");
    }
    let m = mpdu(wide);
    if !m.bandwidth40 || !station_admitted(&m, true, true) || station_admitted(&m, true, false) {
        return TestResult::Fail("40 MHz MPDU station gate needs the wide grant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ht40_rx_admission
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ht20_rx_admission
);

/// Linux core.c `sband->ht_cap` from the signed admitted MCS set: SGI_20,
/// 64K factor, 16 us density, rx_mask[1] only for a 2T record with 2SS rows.
fn smoke_rtl8xxxu_gen2_ht_local_capability() -> TestResult {
    const LEGACY: u32 = 0x0000_0fff;
    if ht_local(LEGACY, 1).is_some() || ht_local(LEGACY | 0x0ff0_0000, 1).is_some() {
        return TestResult::Fail("no 1SS MCS keeps the legacy station");
    }
    let body = |admitted, paths| ht_capability(admitted, paths).map(|ht| ht.capability_body());
    let Some(one) = body(LEGACY | 0x000f_f000, 1) else {
        return TestResult::Fail("8723BU 1T1R HT20");
    };
    if one[0] & 0x20 == 0 || one[0] & 0x42 != 0 || one[2] != 0x1f || one[3] != 0xff || one[4] != 0 {
        return TestResult::Fail("1SS SGI_20/64K/density16 capability");
    }
    let Some(two) = body(LEGACY | 0x0fff_f000, 2) else {
        return TestResult::Fail("8192EU 2T2R HT20");
    };
    if two[3] != 0xff || two[4] != 0xff {
        return TestResult::Fail("2T record with 2SS rows advertises rx_mask[1]");
    }
    let Some(two_no_2ss) = body(LEGACY | 0x000f_f000, 2) else {
        return TestResult::Fail("8192EU without 2SS rows");
    };
    if two_no_2ss[4] != 0 {
        return TestResult::Fail("2SS RX without admitted 2SS rows");
    }
    // HT40 under a wide grant: width + SGI_40 bits, MCS32 RX-only.
    let body40 = |admitted, paths| ht40_capability(admitted, paths).map(|ht| ht.capability_body());
    let Some(one40) = body40(LEGACY | 0x000f_f000, 1) else {
        return TestResult::Fail("8723BU 1T1R HT40");
    };
    if one40[0] & 0x62 != 0x62
        || one40[2] != 0x1f
        || one40[3] != 0xff
        || one40[4] != 0
        || one40[7] != 1
    {
        return TestResult::Fail("1SS HT40 width/SGI_40/MCS32 capability");
    }
    let Some(two40) = body40(LEGACY | 0x0fff_f000, 2) else {
        return TestResult::Fail("8192EU 2T2R HT40");
    };
    if two40[4] != 0xff || two40[7] != 1 {
        return TestResult::Fail("2SS HT40 rx_mask[1]/MCS32 capability");
    }
    if ht40_local(LEGACY, 1).is_some() {
        return TestResult::Fail("no 1SS MCS keeps the legacy station at HT40");
    }
    if ht40_capability(LEGACY | 0x000f_f000, 1)
        .unwrap()
        .with_tx_selection([255, 0, 0, 0, 1, 0, 0, 0, 0, 0])
        .is_ok()
    {
        return TestResult::Fail("MCS32 leaked into TX selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ht_local_capability
);

/// BlockAckReq admission (gen2 F9): a 20-byte BAR passes the descriptor
/// layer while shorter control frames do not; a MoreFrag or PAGGR BAR
/// still refuses; a BA passes admission here and is dropped by the
/// station gate, never by the descriptor layer.
fn smoke_rtl8xxxu_gen2_bar_admission() -> TestResult {
    let mut bar = vec![0x84, 0, 0, 0];
    bar.extend_from_slice(&LOCAL);
    bar.extend_from_slice(&PEER);
    bar.extend_from_slice(&0x3004u16.to_le_bytes());
    bar.extend_from_slice(&1600u16.to_le_bytes());
    if bar.len() != 20 || !admit(&frame(bar.clone(), 4, false, 0), false, false, 0, 1) {
        return TestResult::Fail("20-byte BAR admitted");
    }
    let mut frag = bar.clone();
    frag[1] = 4;
    if admit(&frame(frag, 4, false, 0), false, false, 0, 1) {
        return TestResult::Fail("fragmented BAR refused");
    }
    let mut paggr = frame(bar.clone(), 4, false, 0);
    paggr.paggr = true;
    if admit(&paggr, false, false, 0, 1) {
        return TestResult::Fail("PAGGR BAR refused");
    }
    let rts = vec![0xb4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if admit(&frame(rts, 4, false, 0), false, false, 0, 1) {
        return TestResult::Fail("short control frame refused");
    }
    let mut ba = vec![0x94, 0, 0, 0];
    ba.extend_from_slice(&LOCAL);
    ba.extend_from_slice(&PEER);
    ba.extend_from_slice(&0x3004u16.to_le_bytes());
    ba.extend_from_slice(&1600u16.to_le_bytes());
    ba.extend_from_slice(&[0; 8]);
    if ba.len() != 28 || !admit(&frame(ba, 4, false, 0), false, false, 0, 1) {
        return TestResult::Fail("BA admitted at descriptor layer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_bar_admission
);

/// Live-retune dispatch (gen2 F7): a receiving radio retunes live, a
/// stopped radio pays the cold lifecycle, a never-started radio only
/// relabels; a bound radio or a failed/parked one refuses.
fn smoke_rtl8xxxu_gen2_retune_path() -> TestResult {
    use super::{retune_path, Phase, RetunePath};
    if retune_path(Phase::Receiving, false) != Some(RetunePath::Live)
        || retune_path(Phase::Stopped, false) != Some(RetunePath::Cold)
        || retune_path(Phase::Prepared, false) != Some(RetunePath::Relabel)
        || retune_path(Phase::Receiving, true).is_some()
        || retune_path(Phase::Stopped, true).is_some()
        || retune_path(Phase::Failed, false).is_some()
        || retune_path(Phase::Parked, false).is_some()
    {
        return TestResult::Fail("retune dispatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_retune_path
);
