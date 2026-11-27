//! Native EHT station capability, records, P-RXV admission and teardown
//! over the production Session (Linux mt7925_init_eht_caps / sta_eht_tlv),
//! plus the per-chip 160 MHz station path on MT7925.
use super::*;
use crate::mt7921::association::TxPermission;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A 7925 radio: firmware reports HE/VHT/HT, two streams, all bands.
fn info7925(streams: u8) -> RadioInfo {
    RadioInfo {
        chip_id: 0x7925,
        firmware: Report {
            version: [0; 10],
            build_date: [0; 15],
            patch_already_loaded: false,
            bytes_transferred: 0,
        },
        capabilities: NicCapabilities {
            mac: [2, 0, 0xde, 0xad, 0xbe, 0xef],
            phy: PhyCapabilities {
                ht: true,
                vht: true,
                he: true,
                max_bandwidth: 3,
                spatial_streams: streams,
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

/// AP EHT Capabilities (ext 108) and EHT Operation (ext 106), 2 NSS.
/// The operation carries no information subfield, so the negotiated width
/// is the HE width; the basic set is one stream per range.
fn eht_elements(wide: bool) -> Vec<u8> {
    let mut cap = vec![255, if wide { 18 } else { 15 }, 108];
    cap.extend_from_slice(&[0x03, 0x00]); // EPCS_PRIO_ACCESS | OM_CONTROL
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

/// AP HE Capabilities (ext 35) and HE Operation (ext 36) with the 160 MHz
/// width set and 160 MHz MCS maps, mirroring `he_tests::he_elements`.
fn he_elements160() -> Vec<u8> {
    let mut cap = vec![255, 26, 35];
    cap.extend_from_slice(&[0x01, 0, 0, 0x02, 0x40, 0]); // HTC, OMI, AMSDU in AMPDU
    let mut phy = [0u8; 11];
    phy[0] = 0x04 | 0x08; // 40/80 MHz + 160 MHz in 5 GHz
    phy[1] = 0x20; // LDPC
    phy[2] = 0x0c; // STBC TX/RX <= 80MHz
    phy[3] = 0x80; // SU beamformer
    cap.extend_from_slice(&phy);
    cap.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff]);
    let params: u32 = 2 | (1023 << 4) | (5 << 24);
    let mut op = vec![255, 7, 36];
    op.extend_from_slice(&params.to_le_bytes());
    op.extend_from_slice(&0xfffcu16.to_le_bytes());
    cap.extend_from_slice(&op);
    cap
}

const LOCAL_EHT80: [u8; 17] = [
    255, 15, 108, 0x03, 0, 0xE8, 0x0D, 0x09, 0xFE, 0x10, 0x61, 0x1C, 0x36, 0, 0x22, 0x22, 0x22,
];
const LOCAL_EHT160: [u8; 20] = [
    255, 18, 108, 0x03, 0, 0xE8, 0x0D, 0x09, 0xFE, 0x10, 0x61, 0x3C, 0x36, 0, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
];
const STA_REC_EHT80: [u8; 40] = [
    0x22, 0, 40, 0, 0xff, 0, 0x03, 0x00, 0xE8, 0x0D, 0x09, 0xFE, 0x10, 0x61, 0x1C, 0x36, 0x00, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const STA_REC_EHT160: [u8; 40] = [
    0x22, 0, 40, 0, 0xff, 0, 0x03, 0x00, 0xE8, 0x0D, 0x09, 0xFE, 0x10, 0x61, 0x3C, 0x36, 0x00, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0, 0, 0, 0, 0, 0,
];

fn eht_data(mode: u32, mcs: u32, nss: u32, gi: u32, pn: u64) -> Vec<u8> {
    eht_data_w(mode, mcs, nss, gi, pn, 2)
}
fn eht_data_w(mode: u32, mcs: u32, nss: u32, gi: u32, pn: u64, width: u32) -> Vec<u8> {
    let mut packet = super::vht_tests::data(true, 2, 0, 1, pn);
    let rxv = (mode << 24) | (width << 12) | (gi << 15) | ((nss - 1) << 7) | mcs;
    packet[40..44].copy_from_slice(&rxv.to_le_bytes());
    packet
}

fn extend_bss(s: &mut NativeSession, b: &mut ScanBss, ht: &[u8], vht: &[u8], primary: u8) {
    s.backend.ht_reply = Some(ht.to_vec());
    s.backend.vht_reply = Some(vht.to_vec());
    let mut offset = 0;
    while offset < b.information_elements.len() {
        if b.information_elements[offset] == 3 {
            b.information_elements[offset + 2] = primary;
        }
        offset += 2 + usize::from(b.information_elements[offset + 1]);
    }
    b.information_elements.extend_from_slice(ht);
    b.information_elements.extend_from_slice(vht);
}

#[inline(never)]
fn prepared80_with(secure: bool, chip: u16, eht: bool) -> (NativeSession, ScanBss, TxPermission) {
    let (mut s, mut b) = super::wmm_tests::prepared_with_chip(true, secure, chip);
    s.backend.station_channel = 36;
    b.channel = 36;
    let (ht, vht) = super::vht_tests::elements(2, 36);
    extend_bss(&mut s, &mut b, &ht, &vht, 36);
    let he = super::he_tests::he_elements(true, Some(5));
    b.information_elements.extend_from_slice(&he);
    s.backend.vht_reply.as_mut().unwrap().extend_from_slice(&he);
    if eht {
        let eht = eht_elements(false);
        b.information_elements.extend_from_slice(&eht);
        s.backend
            .vht_reply
            .as_mut()
            .unwrap()
            .extend_from_slice(&eht);
    }
    let State::RadioReady(info) = s.state else {
        panic!("native EHT fixture radio");
    };
    let grant = TxPermission::from_ap(&super::vht_tests::domain(), info, &b).unwrap();
    (s, b, grant)
}

#[inline(never)]
fn prepared160(secure: bool) -> (NativeSession, ScanBss, TxPermission) {
    let (mut s, mut b) = super::wmm_tests::prepared_with_chip(true, secure, 0x7925);
    s.backend.station_channel = 36;
    b.channel = 36;
    let (ht, vht) = super::vht160_tests::elements(36, 50, false);
    extend_bss(&mut s, &mut b, &ht, &vht, 36);
    let he = he_elements160();
    b.information_elements.extend_from_slice(&he);
    s.backend.vht_reply.as_mut().unwrap().extend_from_slice(&he);
    let eht = eht_elements(true);
    b.information_elements.extend_from_slice(&eht);
    s.backend
        .vht_reply
        .as_mut()
        .unwrap()
        .extend_from_slice(&eht);
    let State::RadioReady(info) = s.state else {
        panic!("native EHT 160 fixture radio");
    };
    let grant = TxPermission::from_ap(&super::vht160_tests::domain(), info, &b).unwrap();
    (s, b, grant)
}

fn local_caps() -> Result<(), &'static str> {
    use crate::mt7921::eht::{local_eht, qualified};
    use crate::mt7921::vht::wide160;
    let info = info7925(2);
    if !qualified(info, true) || !qualified(info, false) {
        return Err("MT7925 does not qualify for EHT");
    }
    if qualified(info7925(2), true) && {
        let mut no_he = info7925(2);
        no_he.capabilities.phy.he = false;
        qualified(no_he, true)
    } {
        return Err("EHT without firmware HE");
    }
    let mut other = info7925(2);
    other.chip_id = 0x7922;
    if qualified(other, true) {
        return Err("MT7922 qualifies for EHT");
    }
    if !wide160(info) {
        return Err("wide160 chip gate");
    }
    // The negative case is the 80 MHz-only MT7921, not the MT7922: upstream
    // gates the 160 MHz HE caps on `is_mt7922()` (`mt76_chip(dev) ==
    // 0x7922`, mt7921/main.c `mt7921_init_he_caps`), so the 7922 is a
    // 160 MHz part too and `wide160` is true for it.
    let mut narrow = info7925(2);
    narrow.chip_id = 0x7921;
    if wide160(narrow) {
        return Err("wide160 chip gate");
    }
    // mt7925_init_eht_caps, 2 NSS, 5 GHz, 160 MHz. capability_body()
    // includes the extension-ID octet (108) — the constants above are
    // whole elements, so the comparison starts at [2..], not [3..].
    let body = local_eht(info, true, true).map_err(|_| "local EHT 160")?;
    if body.capability_body() != LOCAL_EHT160[2..] {
        return Err("local EHT 160 capability bytes");
    }
    // 80 MHz-only 5 GHz: no 160 set, MCS15 up to 80 MHz.
    let body = local_eht(info, true, false).map_err(|_| "local EHT 80")?;
    if body.capability_body() != LOCAL_EHT80[2..] {
        return Err("local EHT 80 capability bytes");
    }
    // One stream: 0x11 sets, no sounding dimensions above 80 MHz.
    let one = info7925(1);
    let body = local_eht(one, true, true).map_err(|_| "local EHT 1 NSS")?;
    let body = body.capability_body();
    if body[3..6] != [0xE8, 0x0D, 0x00] || body[7] != 0x00 || body[12..] != [0x11; 6] {
        return Err("local EHT 1 NSS capability bytes");
    }
    // 2.4 GHz: 20 MHz MCS15 only, no 160 set.
    let body = local_eht(info, false, false).map_err(|_| "local EHT 2.4")?;
    let body = body.capability_body();
    if body.len() != 15 || body[9] != 0x0C {
        return Err("local EHT 2.4 capability bytes");
    }
    // 320 MHz is never advertised: no 320 bit, no 320 set.
    let body = local_eht(info, true, true).map_err(|_| "local EHT 320")?;
    if body.capability().phy_capability()[0] & 0x02 != 0 || body.capability().mcs_nss().len() != 6 {
        return Err("local EHT advertises 320 MHz");
    }
    Ok(())
}
fn mt76_eht_local_caps_match_upstream_init() -> TestResult {
    local_caps().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_eht_local_caps_match_upstream_init
);

fn refused_320() -> Result<(), &'static str> {
    use crate::mt7921::eht::local_eht;
    let info = info7925(2);
    let local = crate::mt7921::vht::local(info).map_err(|_| "VHT local")?;
    let local = crate::mt7921::he::with_he(local, info, true, true).map_err(|_| "HE local")?;
    let eht320 = local_eht(info, true, true)
        .map_err(|_| "EHT local")?
        .with_320mhz([0x22, 0x22, 0x22])
        .map_err(|_| "320 set")?;
    if local.with_eht(eht320).is_ok() {
        return Err("LocalPhy accepted a 320 MHz EHT profile");
    }
    Ok(())
}
fn mt76_eht_320mhz_refused() -> TestResult {
    refused_320().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("drivers/wireless/mt7921", mt76_eht_320mhz_refused);

fn rxv(mode: u32, width: u32, rate: u32, nss: u32, gi: u32, stbc: u32, ldpc: bool) -> u32 {
    (mode << 24)
        | (width << 12)
        | (gi << 15)
        | ((nss - 1) << 7)
        | (stbc << 22)
        | rate
        | if ldpc { 1 << 11 } else { 0 }
}
fn admission() -> Result<(), &'static str> {
    use crate::mt7921::eht::{receive_allowed, EhtRx};
    let rx = EhtRx {
        nss: [2, 2, 2, 2],
        ldpc: true,
        stbc: true,
        mcs15: true,
    };
    for (mode, width, rate, nss, gi, stbc, ldpc) in [
        (13, 2, 13, 2, 0, 0, false),        // EHT SU MCS13 NSS2
        (15, 2, 7, 1, 2, 0, false),         // EHT MU MCS7 GI 3.2us
        (13, 2, 14 | 0x10, 1, 0, 0, false), // EHT SU MCS14 DCM
        (13, 2, 15 | 0x10, 1, 0, 0, false), // EHT SU MCS15 DCM
        (13, 2, 11, 2, 0, 1, false),        // STBC 1x2 -> one stream
        (13, 2, 11, 1, 0, 0, true),         // LDPC-coded
    ] {
        if !receive_allowed(2, rxv(mode, width, rate, nss, gi, stbc, ldpc), rx) {
            return Err("valid EHT PPDU rejected");
        }
    }
    for (mode, width, rate, nss, gi, stbc, ldpc) in [
        (14, 2, 7, 1, 0, 0, false),         // EHT_TRIG never admitted
        (13, 2, 14, 1, 0, 0, false),        // MCS14 without DCM
        (13, 2, 14 | 0x10, 2, 0, 0, false), // MCS14 DCM needs one stream
        (13, 2, 13, 3, 0, 0, false),        // three streams over the cap
        (13, 3, 7, 1, 0, 0, false),         // wider than the selection
        (13, 2, 7, 1, 3, 0, false),         // reserved GI
        (13, 2, 7 | 0x40, 1, 0, 0, false),  // reserved rate bit
        (13, 2, 7 | 0x20, 1, 0, 0, false),  // ER-SU bit is HE-only
        (13, 2, 7, 1, 0, 2, false),         // STBC 2x
        (13, 2, 12, 3, 0, 0, false),        // MCS12 range cap is 2
    ] {
        if receive_allowed(2, rxv(mode, width, rate, nss, gi, stbc, ldpc), rx) {
            return Err("invalid EHT PPDU admitted");
        }
    }
    // Without a local MCS 14/15 advertisement, DCM MCS is rejected.
    let no_mcs15 = EhtRx { mcs15: false, ..rx };
    if receive_allowed(2, rxv(13, 2, 14 | 0x10, 1, 0, 0, false), no_mcs15) {
        return Err("MCS14 DCM admitted without MCS15");
    }
    // Without LDPC, an LDPC-coded PPDU is rejected.
    let no_ldpc = EhtRx { ldpc: false, ..rx };
    if receive_allowed(2, rxv(13, 2, 7, 1, 0, 0, true), no_ldpc) {
        return Err("LDPC PPDU admitted without LDPC");
    }
    Ok(())
}
fn mt76_eht_receive_admission() -> TestResult {
    admission().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("drivers/wireless/mt7921", mt76_eht_receive_admission);

fn native80() -> Result<(), &'static str> {
    let (mut s, b, p) = prepared80_with(true, 0x7925, true);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42)
        || s.station.eht_profile.is_none()
        || s.station.he_profile.is_none()
    {
        return Err("native EHT association");
    }
    // The request carries the station's full EHT caps, not the 80 MHz
    // subset: upstream `mt7925_init_eht_caps` fills both the <=80 and
    // the 160 MHz MCS sets unconditionally, so a 160 MHz-capable
    // station advertises the 160 set even to an 80 MHz AP. The
    // negotiated width shows up in the STA record below (EHT80), not
    // by truncating the caps element.
    let f = &s.backend.frames;
    if !f
        .iter()
        .any(|(_, f)| f.first() == Some(&0) && f.windows(20).any(|ie| ie == LOCAL_EHT160))
    {
        return Err("mt7925_init_eht_caps station EHT Capabilities in request");
    }
    let Some((_, peer)) = f
        .iter()
        .find(|(_, f)| super::vht_tests::record(f, 0x22) == Some(&STA_REC_EHT80[..]))
    else {
        return Err("literal STA_REC_EHT");
    };
    // The 7925 join drives the UNI station update
    // (`mt7925_mcu_sta_cmd`): STA_REC_PHY (0x15, 12 bytes) with
    // `get_phy_mode_v2`'s OFDM | HT | VHT | HE | BE on 5 GHz, HE only
    // as STA_REC_HE_V2 (0x19, never the CONNAC2 STA_REC_HE 14), the
    // 16-byte STATE_V2, the HDR_TRANS tail, and no WTBL nesting.
    if super::vht_tests::record(peer, 0x15).is_none_or(|phy| phy.len() != 12 || phy[6] != 0xf8)
        || super::vht_tests::record(peer, 0x19).is_none_or(|he| he.len() != 28)
        || super::vht_tests::record(peer, 14).is_some()
        || super::vht_tests::record(peer, 7).is_none_or(|state| state.len() != 16)
        || super::vht_tests::record(peer, 0x2b).is_none()
        || super::vht_tests::record(peer, 13).is_some()
    {
        return Err("UNI STA update PHY/HE_V2/STATE_V2/HDR_TRANS or WTBL TLVs wrong");
    }
    // EHT SU MCS13 two streams, EHT MU and EHT SU MCS14 DCM are admitted.
    s.backend.packets.push_back(eht_data(13, 13, 2, 0, 9));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("EHT SU MCS13 NSS2 receive");
    }
    s.backend.packets.push_back(eht_data(15, 7, 1, 2, 10));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("EHT MU receive");
    }
    s.backend
        .packets
        .push_back(eht_data(13, 14 | 0x10, 1, 0, 11));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("EHT SU MCS14 DCM receive");
    }
    // EHT_TRIG, MCS14 without DCM, three streams and reserved GI are dropped.
    for (pn, (mode, mcs, nss, gi)) in [(14, 7, 1, 0), (13, 14, 1, 0), (13, 13, 3, 0), (13, 7, 1, 3)]
        .into_iter()
        .enumerate()
    {
        s.backend
            .packets
            .push_back(eht_data(mode, mcs, nss, gi, 12 + pn as u64));
        if s.receive_ethernet().ok().flatten().is_some() {
            return Err("invalid EHT PPDU admitted");
        }
    }
    let before = s.backend.frames.len();
    run(s.disassociate_station()).map_err(|_| "EHT teardown")?;
    if s.station.eht_profile.is_some()
        || s.backend.frames[before..]
            .iter()
            .any(|(_, f)| super::vht_tests::record(f, 0x22).is_some())
    {
        return Err("EHT teardown retained profile or record");
    }
    Ok(())
}
fn mt76_eht_station_caps_records_rx_and_teardown() -> TestResult {
    native80().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_eht_station_caps_records_rx_and_teardown
);

/// Scan the TLV stream of a Unified id-2 (BSS info) frame, the
/// same walk as `vht_tests::record` for id-3 frames: the body
/// starts at offset 48, the `bss_req_hdr` is 4 bytes, so the first
/// TLV is at 52.
fn record_bss(frame: &[u8], tag: u16) -> Option<&[u8]> {
    if frame.get(34..36) != Some(&[2, 0]) || frame.get(43) != Some(&7) {
        return None;
    }
    let mut offset = 52;
    while let Some(header) = frame.get(offset..offset + 4) {
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < 4 {
            return None;
        }
        let body = frame.get(offset..offset + len)?;
        if header[..2] == tag.to_le_bytes() {
            return Some(body);
        }
        offset += len;
    }
    None
}

fn uni_join_records() -> Result<(), &'static str> {
    let (mut s, b, p) = prepared80_with(true, 0x7925, true);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) {
        return Err("native UNI association");
    }
    let f = &s.backend.frames;
    // A Unified id-2 UNI BSS enable record: BASIC (tag 0), RLM
    // (tag 2) and MLD (tag 26) TLVs. The pre-auth record has no
    // RLM, so the RLM requirement selects the assoc-time one.
    let Some((_, bss)) = f
        .iter()
        .find(|(_, f)| record_bss(f, 0).is_some() && record_bss(f, 2).is_some())
    else {
        return Err("no UNI BSS enable record");
    };
    if record_bss(bss, 26).is_none() {
        return Err("UNI BSS record lacks MLD");
    }
    // A Unified id-3 UNI STA update with the negotiated EHT record
    // and no WTBL nesting.
    let Some((_, peer)) = f
        .iter()
        .find(|(_, f)| super::vht_tests::record(f, 0x22) == Some(&STA_REC_EHT80[..]))
    else {
        return Err("no UNI STA update with EHT record");
    };
    if super::vht_tests::record(peer, 13).is_some() {
        return Err("UNI STA update carries a WTBL TLV");
    }
    // The pairwise key is its own STA_REC_UPDATE with one KEY_V3
    // (CCMP, 16-byte key).
    if !f.iter().any(|(_, f)| {
        super::vht_tests::record(f, 0x27)
            .is_some_and(|tlv| tlv.len() == 68 && tlv[15] == 4 && tlv[17] == 16)
    }) {
        return Err("no pairwise KEY_V3 record");
    }
    let before = s.backend.frames.len();
    run(s.disassociate_station()).map_err(|_| "UNI teardown")?;
    // Teardown sends a UNI remove (REMOVE + MLD_OFF) and no EHT record.
    if !s.backend.frames[before..].iter().any(|(_, f)| {
        super::vht_tests::record(f, 0x25).is_some() && super::vht_tests::record(f, 0x23).is_some()
    }) || s.backend.frames[before..]
        .iter()
        .any(|(_, f)| super::vht_tests::record(f, 0x22).is_some())
    {
        return Err("UNI teardown remove or EHT record wrong");
    }
    Ok(())
}
fn mt76_mt7925_uni_station_join_records() -> TestResult {
    uni_join_records().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_mt7925_uni_station_join_records
);

fn native160() -> Result<(), &'static str> {
    let (mut s, b, p) = prepared160(true);
    if p.native_width() != 3 {
        return Err("160 grant");
    }
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42)
        || s.station
            .eht_profile
            .is_none_or(|profile| profile.width() != 3)
    {
        return Err("native EHT 160 association");
    }
    let f = &s.backend.frames;
    if !f
        .iter()
        .any(|(_, f)| f.first() == Some(&0) && f.windows(20).any(|ie| ie == LOCAL_EHT160))
    {
        return Err("mt7925_init_eht_caps 160 station EHT Capabilities in request");
    }
    if !f
        .iter()
        .any(|(_, f)| super::vht_tests::record(f, 0x22) == Some(&STA_REC_EHT160[..]))
    {
        return Err("literal STA_REC_EHT at 160 MHz");
    }
    s.backend.packets.push_back(eht_data_w(13, 11, 2, 0, 9, 3));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("EHT SU 160 MHz receive");
    }
    // A narrower 20 MHz MCS8 packet on the 160 MHz link is admitted.
    s.backend.packets.push_back(eht_data_w(13, 8, 1, 0, 10, 0));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("EHT SU 20 MHz receive on a 160 MHz link");
    }
    Ok(())
}
fn mt76_eht_160mhz_station_join() -> TestResult {
    native160().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("drivers/wireless/mt7921", mt76_eht_160mhz_station_join);

fn fallback() -> Result<(), &'static str> {
    // AP without EHT: no request element, no EHT record, EHT PPDUs dropped.
    let (mut s, b, p) = prepared80_with(true, 0x7925, false);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.station.eht_profile.is_some() {
        return Err("HE-only association negotiated EHT");
    }
    let f = &s.backend.frames;
    if f.iter().any(|(_, f)| {
        f.first() == Some(&0) && f.windows(3).any(|ie| ie[0] == 255 && ie[2] == 108)
            || super::vht_tests::record(f, 0x22).is_some()
    }) {
        return Err("EHT emitted without an EHT AP");
    }
    s.backend.packets.push_back(eht_data(13, 3, 1, 0, 9));
    if s.receive_ethernet().ok().flatten().is_some() {
        return Err("EHT PPDU admitted without EHT");
    }
    // MT7922 chip: the chip gate keeps EHT off even with an EHT AP.
    let (mut s, b, p) = prepared80_with(true, 0x7922, true);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.station.eht_profile.is_some() {
        return Err("MT7922 negotiated EHT");
    }
    // Firmware without HE in its PHY TLV never offers EHT.
    let (mut s, b, p) = prepared80_with(true, 0x7925, true);
    let State::RadioReady(mut info) = s.state else {
        return Err("radio");
    };
    info.capabilities.phy.he = false;
    s.state = State::RadioReady(info);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.station.eht_profile.is_some() {
        return Err("non-HE firmware still negotiated EHT");
    }
    Ok(())
}
fn mt76_eht_absent_on_ap_or_firmware_keeps_he_and_drops_eht_ppdus() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_eht_absent_on_ap_or_firmware_keeps_he_and_drops_eht_ppdus
);
