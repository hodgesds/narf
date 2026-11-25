//! MLO lifecycle smokes (MT7925/CONNAC3) over plan-level fixtures:
//! no session, no hardware. The UNI builders are fixture-validated
//! here; the native join path that drives the single-link dispatch
//! through the session is covered by `eht_tests`.
use super::*;
use crate::mt7921::association::{JoinPlan, Security};
use crate::mt7921::firmware_transport::{NicCapabilities, PhyCapabilities, Report};
use crate::mt7921::vif_slots::Vif;
use crate::mt7925::mcu::{
    UniBssHe, UniBssRlm, UniBssSec, BSS_SEC_MODE_WPA2_PSK, CONNAC3_CIPHER_AES_CCMP, RLM_BAND_5G,
    RLM_BW_160, RLM_BW_320, STA_REC_BA, STA_REC_BASIC_TLV_SIZE, STA_REC_EHT, STA_REC_EHT_MLD,
    STA_REC_EHT_MLD_TLV_SIZE, STA_REC_EHT_TLV_SIZE, STA_REC_MLD, STA_REC_MLD_TLV_SIZE,
    STA_REC_STATE_TLV_SIZE, STA_REQ_HDR_SIZE, UNI_BSS_MLD_TLV_SIZE, UNI_BSS_UPDATE_BOUND,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::rsn::RsnIe;

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const AID: u16 = 42;
const CHANNEL: u8 = 36;

fn info(chip_id: u16) -> RadioInfo {
    RadioInfo {
        chip_id,
        firmware: Report {
            version: [0; 10],
            build_date: [0; 15],
            patch_already_loaded: false,
            bytes_transferred: 0,
        },
        capabilities: NicCapabilities {
            mac: OWN,
            phy: PhyCapabilities {
                ht: true,
                vht: true,
                he: true,
                max_bandwidth: 3,
                spatial_streams: 2,
                bands: 3,
                tx_ldpc: true,
                rx_ldpc: true,
                tx_stbc: true,
                rx_stbc: true,
            },
            has_6ghz: true,
            chip_capabilities: 0,
        },
        hardware_type: 0,
        world_limit_commands: 0,
        channel_configuration: None,
    }
}

/// HT Capabilities (45) + HT Operation (61), copied from
/// `ht20_tests::elements` (that module is private to `ht20.rs`).
fn ht_elements(channel: u8) -> Vec<u8> {
    let mut ht = [0; 26];
    ht[0] = 0x77;
    ht[2] = 30;
    ht[3] = 0xff;
    ht[4] = 0xff;
    let mut operation = [0; 22];
    operation[0] = channel;
    operation[1] = 5;
    operation[6] = 0xff;
    let mut bytes = vec![45, 26];
    bytes.extend_from_slice(&ht);
    bytes.extend_from_slice(&[61, 22]);
    bytes.extend_from_slice(&operation);
    bytes
}

/// VHT Capabilities (191) + VHT Operation (192) for 80 MHz on
/// `primary`, copied from `vht_tests::elements`.
fn vht_elements(width: u8, primary: u8) -> (Vec<u8>, Vec<u8>) {
    let mut ht = ht_elements(primary);
    let secondary = primary + 4;
    ht[31] = if width == 0 {
        0
    } else if secondary > primary {
        5
    } else {
        7
    };
    let center = 42;
    let mut vht = vec![191, 12, 32, 0, 0, 1, 252, 255, 0, 0, 252, 255, 0, 0, 192, 5];
    vht.extend_from_slice(&[if width == 2 { 1 } else { 0 }, center, 0, 252, 255]);
    (ht, vht)
}

/// AP HE Capabilities (ext 35) + HE Operation (ext 36) with the
/// 160 MHz width set, copied from `eht_tests::he_elements160`.
fn he_elements160() -> Vec<u8> {
    let mut cap = vec![255, 26, 35];
    cap.extend_from_slice(&[0x01, 0, 0, 0x02, 0x40, 0]);
    let mut phy = [0u8; 11];
    phy[0] = 0x04 | 0x08;
    phy[1] = 0x20;
    phy[2] = 0x0c;
    phy[3] = 0x80;
    cap.extend_from_slice(&phy);
    cap.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff]);
    let params: u32 = 2 | (1023 << 4) | (5 << 24);
    let mut op = vec![255, 7, 36];
    op.extend_from_slice(&params.to_le_bytes());
    op.extend_from_slice(&0xfffcu16.to_le_bytes());
    cap.extend_from_slice(&op);
    cap
}

/// AP EHT Capabilities (ext 108) + EHT Operation (ext 106),
/// copied from `eht_tests::eht_elements`.
fn eht_elements(wide: bool) -> Vec<u8> {
    let mut cap = vec![255, if wide { 18 } else { 15 }, 108];
    cap.extend_from_slice(&[0x03, 0x00]);
    let mut phy = [0xE8, 0x0D, 0x09, 0xFE, 0x10, 0x61, 0, 0x36, 0x00];
    phy[6] = if wide { 0x3C } else { 0x1C };
    cap.extend_from_slice(&phy);
    cap.extend_from_slice(&[0x22, 0x22, 0x22]);
    if wide {
        cap.extend_from_slice(&[0x22, 0x22, 0x22]);
    }
    cap.extend_from_slice(&[255, 6, 106, 0x00, 0x11, 0x11, 0x11, 0x11]);
    cap
}

fn bss() -> ScanBss {
    let mut ies = vec![
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, CHANNEL,
    ];
    let rsn = RsnIe::wpa2_psk_ccmp().encode_body();
    ies.extend_from_slice(&[48, rsn.len() as u8]);
    ies.extend_from_slice(&rsn);
    let (ht, vht) = vht_elements(2, CHANNEL);
    ies.extend_from_slice(&ht);
    ies.extend_from_slice(&vht);
    ies.extend_from_slice(&he_elements160());
    ies.extend_from_slice(&eht_elements(true));
    ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: CHANNEL,
        band: None,
        signal_dbm: Some(-50),
        capability: 0x11,
        beacon_interval: 100,
        information_elements: ies,
    }
}

fn reply(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    frame
}

/// A plan associated on the wide BSS: HT/VHT/HE/EHT negotiated,
/// aid 42.
fn associated_plan() -> JoinPlan {
    let mut plan = JoinPlan::prepare(&bss(), OWN, b"narf", Security::Wpa2Psk { psk: [0x55; 32] })
        .expect("wide BSS prepares");
    plan.start_authentication().expect("auth starts");
    plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .expect("auth response");
    let mut body = vec![0x11, 0, 0, 0, 42, 0xc0, 1, 4, 0x82, 0x84, 0x8b, 0x96];
    let (ht, vht) = vht_elements(2, CHANNEL);
    body.extend_from_slice(&ht);
    body.extend_from_slice(&vht);
    body.extend_from_slice(&he_elements160());
    body.extend_from_slice(&eht_elements(true));
    assert_eq!(
        plan.association_response(&reply(0x10, &body)),
        Ok(Some(AID)),
        "wide association response accepted"
    );
    plan
}

fn sec() -> UniBssSec {
    UniBssSec {
        mode: BSS_SEC_MODE_WPA2_PSK,
        status: 6,
        cipher: CONNAC3_CIPHER_AES_CCMP,
    }
}

fn he(plan: &JoinPlan) -> Option<UniBssHe> {
    plan.he().map(|he| he.uni_bss_he(true))
}

fn rlm() -> UniBssRlm {
    UniBssRlm {
        control_channel: CHANNEL,
        center_chan: 42,
        center_chan2: 0,
        bw: RLM_BW_160,
        tx_streams: 2,
        rx_streams: 2,
        band: RLM_BAND_5G,
    }
}

/// Walk the TLV stream in `body` starting at `start` (the first
/// TLV offset; `len` is the total TLV size, header included —
/// the same walk as `vht_tests::record`).
fn find_tlv(body: &[u8], start: usize, tag: u16) -> Option<&[u8]> {
    let mut offset = start;
    while let Some(header) = body.get(offset..offset + 4) {
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < 4 {
            return None;
        }
        let tlv = body.get(offset..offset + len)?;
        if header[..2] == tag.to_le_bytes() {
            return Some(tlv);
        }
        offset += len;
    }
    None
}

fn mt76_mlo_capability_advertised() -> TestResult {
    let cap = MldCapability::advertised();
    if cap.max_simultaneous_links != MldCapability::MAX_SIMULTANEOUS_LINKS
        || cap.max_simultaneous_links != 2
        || cap.eml != EmlCaps::advertised()
        || cap.eml.emlsr
        || cap.eml.eml_cap != 0
    {
        return TestResult::Fail("advertised MLD capability is not 2 links, no EMLSR");
    }
    if !is_connac3(info(0x7925)) || is_connac3(info(0x7922)) || is_connac3(info(0x7961)) {
        return TestResult::Fail("is_connac3 keys on the wrong chip id");
    }
    if slot_time_us(6) != 20 || slot_time_us(36) != 9 || slot_time_us(1) != 20 {
        return TestResult::Fail("slot time is not 20us on 2.4 GHz / 9us on 5 GHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/mlo",
    mt76_mlo_capability_advertised
);

fn mt76_mlo_single_link_add_teardown() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    let messages = match station.add_link(
        &plan,
        Link::HOME,
        AID,
        true,
        &bss(),
        sec(),
        he(&plan),
        Some(rlm()),
    ) {
        Ok(messages) => messages,
        Err(_) => return TestResult::Fail("single-link add failed"),
    };
    if messages.len() != 2
        || messages[0].command != MloCommand::BssInfo
        || messages[1].command != MloCommand::StaUpdate
    {
        return TestResult::Fail("single-link add is not [BSS, STA]");
    }
    let bss_record = &messages[0].body;
    if bss_record.len() != UNI_BSS_UPDATE_BOUND || bss_record[0] != 0 {
        return TestResult::Fail("single-link BSS record bound or bss_idx wrong");
    }
    // MLD TLV present, not an MLD vif: [4] = 0xff (no primary),
    // [5] = bss_idx + 32, [6..12] = own MAC, [13] = 0xff (no
    // link id), [14] = 0 (no EMLSR).
    let Some(mld) = find_tlv(bss_record, 4, 26) else {
        return TestResult::Fail("single-link BSS record has no MLD TLV");
    };
    if mld.len() != UNI_BSS_MLD_TLV_SIZE
        || mld[4] != 0xff
        || mld[5] != 32
        || mld[6..12] != OWN
        || mld[13] != 0xff
        || mld[14] != 0
    {
        return TestResult::Fail("single-link BSS MLD TLV wrong");
    }
    let sta_record = &messages[1].body;
    if sta_record.len()
        != STA_REQ_HDR_SIZE
            + STA_REC_BASIC_TLV_SIZE
            + STA_REC_STATE_TLV_SIZE
            + plan.uni_cap_tlvs(true).len()
    {
        return TestResult::Fail("single-link STA record length wrong");
    }
    // The negotiated EHT record rides the UNI update; no MLD TLVs
    // on a single-link station.
    let Some(eht) = find_tlv(sta_record, STA_REQ_HDR_SIZE, STA_REC_EHT) else {
        return TestResult::Fail("single-link STA record has no EHT TLV");
    };
    if eht.len() != STA_REC_EHT_TLV_SIZE || eht[..] != plan.eht().unwrap().sta()[..] {
        return TestResult::Fail("single-link STA EHT TLV is not the negotiated profile");
    }
    if find_tlv(sta_record, STA_REQ_HDR_SIZE, STA_REC_MLD).is_some()
        || find_tlv(sta_record, STA_REQ_HDR_SIZE, STA_REC_EHT_MLD).is_some()
    {
        return TestResult::Fail("single-link STA record carries MLD TLVs");
    }
    if station.primary_state() != LinkState::Associated || station.is_mld() {
        return TestResult::Fail("single-link station state wrong after add");
    }
    let messages = match station.teardown(&bss(), sec()) {
        Ok(messages) => messages,
        Err(_) => return TestResult::Fail("single-link teardown failed"),
    };
    if messages.len() != 2
        || messages[0].command != MloCommand::StaUpdate
        || messages[1].command != MloCommand::BssInfo
    {
        return TestResult::Fail("single-link teardown is not [remove, BSS-disable]");
    }
    let remove = &messages[0].body;
    if remove.len() != 20 || u16::from_le_bytes([remove[2], remove[3]]) != 2 {
        return TestResult::Fail("single-link teardown remove wrong");
    }
    if messages[1].body[4 + 12] != 1 || station.primary_state() != LinkState::Idle {
        return TestResult::Fail("single-link teardown BSS-disable or state wrong");
    }
    if !station
        .teardown(&bss(), sec())
        .is_ok_and(|messages| messages.is_empty())
    {
        return TestResult::Fail("idle teardown is not empty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/mlo",
    mt76_mlo_single_link_add_teardown
);

fn mt76_mlo_secondary_join_leave() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .expect("primary add");
    let secondary = MldStation::new_secondary_link(1, 2).expect("secondary link");
    let messages = match station.join_secondary(
        &plan,
        secondary,
        AID,
        &bss(),
        sec(),
        he(&plan),
        Some(rlm()),
    ) {
        Ok(messages) => messages,
        Err(_) => return TestResult::Fail("secondary join failed"),
    };
    if messages.len() != 3
        || messages[0].command != MloCommand::BssInfo
        || messages[1].command != MloCommand::StaUpdate
        || messages[2].command != MloCommand::StaUpdate
    {
        return TestResult::Fail("secondary join is not [BSS(sec), STA(pri), STA(sec)]");
    }
    // Secondary BSS record: bss_idx 1, MLD vif.
    if messages[0].body[0] != 1 {
        return TestResult::Fail("secondary BSS record bss_idx wrong");
    }
    let Some(bss_mld) = find_tlv(&messages[0].body, 4, 26) else {
        return TestResult::Fail("secondary BSS record has no MLD TLV");
    };
    if bss_mld[4] != 0 || bss_mld[5] != 33 || bss_mld[6..12] != OWN || bss_mld[13] != 1 {
        return TestResult::Fail("secondary BSS MLD TLV wrong");
    }
    // Both STA updates carry the two-link MLD set, primary first.
    for (i, expected_wcid) in [(1, 1u16), (2, 2u16)] {
        let Some(mld) = find_tlv(&messages[i].body, STA_REQ_HDR_SIZE, STA_REC_MLD) else {
            return TestResult::Fail("joined STA update has no MLD TLV");
        };
        if mld.len() != STA_REC_MLD_TLV_SIZE
            || mld[4..10] != OWN
            || u16::from_le_bytes([mld[10], mld[11]]) != 1
            || u16::from_le_bytes([mld[12], mld[13]]) != 2
            || u16::from_le_bytes([mld[14], mld[15]]) != 1
            || mld[16] != 2
            || u16::from_le_bytes([mld[20], mld[21]]) != 1
            || mld[22] != 0
            || u16::from_le_bytes([mld[24], mld[25]]) != 2
            || mld[26] != 1
        {
            return TestResult::Fail("joined MLD TLV link set wrong");
        }
        if messages[i].body[1] != expected_wcid as u8 {
            return TestResult::Fail("joined STA update wcid wrong");
        }
    }
    if !station.is_mld() || station.secondary_state() != Some(LinkState::Associated) {
        return TestResult::Fail("station is not MLD after secondary join");
    }
    let messages = match station.leave_secondary(&bss(), sec()) {
        Ok(messages) => messages,
        Err(_) => return TestResult::Fail("secondary leave failed"),
    };
    if messages.len() != 2
        || messages[0].command != MloCommand::StaUpdate
        || messages[1].command != MloCommand::BssInfo
        || messages[0].body.len() != 20
        || messages[0].body[1] != 2
        || messages[1].body[0] != 1
        || messages[1].body[4 + 12] != 1
    {
        return TestResult::Fail("secondary leave is not [remove(sec), BSS-disable(sec)]");
    }
    if station.is_mld()
        || !station
            .leave_secondary(&bss(), sec())
            .is_ok_and(|messages| messages.is_empty())
    {
        return TestResult::Fail("second secondary leave is not empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921/mlo", mt76_mlo_secondary_join_leave);

fn mt76_mlo_join_guards() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    let secondary = MldStation::new_secondary_link(1, 2).expect("secondary link");
    // Primary must be associated before a secondary can join.
    if station
        .join_secondary(&plan, secondary, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .is_ok()
    {
        return TestResult::Fail("secondary joined before the primary associated");
    }
    station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            false,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .expect("primary pre-assoc add");
    if station
        .join_secondary(&plan, secondary, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .is_ok()
    {
        return TestResult::Fail("secondary joined while the primary is only Added");
    }
    // An associated link is not downgraded to a pre-association add.
    station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .expect("primary assoc add");
    if station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            false,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .is_ok()
    {
        return TestResult::Fail("associated primary downgraded to pre-assoc add");
    }
    // A second station record on the primary vif is not a link.
    let same_vif = Link::new(Vif::new(0).unwrap(), 3).unwrap();
    if station
        .add_link(
            &plan,
            same_vif,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .is_ok()
    {
        return TestResult::Fail("second record on the primary vif accepted as a link");
    }
    station
        .join_secondary(&plan, secondary, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .expect("secondary join");
    // No third link: the slot is taken.
    let third = MldStation::new_secondary_link(2, 3).expect("third link");
    if station
        .join_secondary(&plan, third, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .is_ok()
        || station
            .add_link(
                &plan,
                third,
                AID,
                true,
                &bss(),
                sec(),
                he(&plan),
                Some(rlm()),
            )
            .is_ok()
    {
        return TestResult::Fail("third link accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921/mlo", mt76_mlo_join_guards);

fn mt76_mlo_per_link_ba() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    // No BA before the link is associated.
    if station.tx_ba(Link::HOME, 0, true, true, 0, 64).is_ok() {
        return TestResult::Fail("TX BA accepted on an idle link");
    }
    station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .expect("primary add");
    let tx = match station.tx_ba(Link::HOME, 0, true, true, 0, 64) {
        Ok(message) => message,
        Err(_) => return TestResult::Fail("TX BA failed on an associated link"),
    };
    if tx.command != MloCommand::StaUpdate {
        return TestResult::Fail("TX BA is not a STA update");
    }
    let Some(ba) = find_tlv(&tx.body, STA_REQ_HDR_SIZE, STA_REC_BA) else {
        return TestResult::Fail("TX BA has no BA TLV");
    };
    if ba.len() != 16
        || ba[4] != 0
        || ba[5] != 1
        || ba[6] != 1
        || ba[7] != 1
        || u16::from_le_bytes([ba[8], ba[9]]) != 0
        || u16::from_le_bytes([ba[10], ba[11]]) != 64
        || tx.body[1] != 1
    {
        return TestResult::Fail("TX BA TLV fields wrong");
    }
    let rx = match station.rx_ba(Link::HOME, 5, false, true, 100, 256) {
        Ok(message) => message,
        Err(_) => return TestResult::Fail("RX BA failed on an associated link"),
    };
    let Some(ba) = find_tlv(&rx.body, STA_REQ_HDR_SIZE, STA_REC_BA) else {
        return TestResult::Fail("RX BA has no BA TLV");
    };
    if ba[4] != 5
        || ba[5] != 0
        || ba[6] != 0
        || ba[7] != 1 << 5
        || u16::from_le_bytes([ba[8], ba[9]]) != 100
        || u16::from_le_bytes([ba[10], ba[11]]) != 256
    {
        return TestResult::Fail("RX BA TLV fields wrong");
    }
    // TID and window bounds.
    if station.tx_ba(Link::HOME, 8, true, true, 0, 64).is_ok()
        || station.tx_ba(Link::HOME, 0, true, true, 0, 0).is_ok()
        || station.tx_ba(Link::HOME, 0, true, true, 0, 257).is_ok()
    {
        return TestResult::Fail("BA accepted an out-of-range TID or window");
    }
    // Per-link: the secondary's BA carries its own WCID/BSS.
    let secondary = MldStation::new_secondary_link(1, 2).expect("secondary link");
    station
        .join_secondary(&plan, secondary, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .expect("secondary join");
    let tx2 = station
        .tx_ba(secondary, 3, false, true, 7, 32)
        .expect("secondary TX BA");
    if tx2.body[0] != 1 || tx2.body[1] != 2 {
        return TestResult::Fail("secondary TX BA bss/wcid wrong");
    }
    let Some(ba) = find_tlv(&tx2.body, STA_REQ_HDR_SIZE, STA_REC_BA) else {
        return TestResult::Fail("secondary TX BA has no BA TLV");
    };
    if ba[4] != 3 || ba[7] != 1 << 3 {
        return TestResult::Fail("secondary TX BA TID wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921/mlo", mt76_mlo_per_link_ba);

fn mt76_mlo_refuses_320mhz() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    let mut wide = rlm();
    wide.bw = RLM_BW_320;
    if !matches!(
        station.add_link(
            &plan,
            Link::HOME,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(wide)
        ),
        Err(Error::UnsupportedFirmware)
    ) {
        return TestResult::Fail("320 MHz RLM accepted on a 160 MHz part");
    }
    if station.primary_state() != LinkState::Idle {
        return TestResult::Fail("failed 320 MHz add claimed the link");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921/mlo", mt76_mlo_refuses_320mhz);

fn mt76_mlo_eml_fail_closed() -> TestResult {
    let plan = associated_plan();
    let mut station = MldStation::new(Link::HOME, OWN);
    station
        .add_link(
            &plan,
            Link::HOME,
            AID,
            true,
            &bss(),
            sec(),
            he(&plan),
            Some(rlm()),
        )
        .expect("primary add");
    let secondary = MldStation::new_secondary_link(1, 2).expect("secondary link");
    let messages = station
        .join_secondary(&plan, secondary, AID, &bss(), sec(), he(&plan), Some(rlm()))
        .expect("secondary join");
    // No EMLSR: the EHT MLD TLV carries str_cap[0] = BIT(1) and
    // zero eml_cap bytes.
    let Some(eht_mld) = find_tlv(&messages[2].body, STA_REQ_HDR_SIZE, STA_REC_EHT_MLD) else {
        return TestResult::Fail("joined STA update has no EHT MLD TLV");
    };
    if eht_mld.len() != STA_REC_EHT_MLD_TLV_SIZE
        || eht_mld[5] != 0xff
        || eht_mld[7] != 1 << 1
        || eht_mld[10] != 0
        || eht_mld[11] != 0
    {
        return TestResult::Fail("EHT MLD TLV is not the no-EMLSR fallback");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921/mlo", mt76_mlo_eml_fail_closed);
