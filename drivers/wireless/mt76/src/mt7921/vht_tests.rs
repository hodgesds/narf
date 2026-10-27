//! Complete native VHT admission/records/packet ownership over real Session.
use super::*;
use crate::mt7921::association::{Security, TxPermission};
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(super) fn domain() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5895,
            max_bandwidth_mhz: 80,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
pub(super) fn elements(width: u8, primary: u8) -> (Vec<u8>, Vec<u8>) {
    let mut ht = super::ht20_tests::elements(primary);
    let secondary = if [
        36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173,
    ]
    .contains(&primary)
    {
        primary + 4
    } else {
        primary - 4
    };
    ht[31] = if width == 0 {
        0
    } else if secondary > primary {
        5
    } else {
        7
    };
    let center = if width == 2 {
        [42, 58, 106, 122, 138, 155, 171]
            .into_iter()
            .find(|&center| crate::mt7921::channel::block80(primary, center).is_some())
            .unwrap()
    } else if width == 1 {
        ((u16::from(primary) + u16::from(secondary)) / 2) as u8
    } else {
        0
    };
    let mut vht = vec![191, 12, 32, 0, 0, 1, 252, 255, 0, 0, 252, 255, 0, 0, 192, 5];
    vht.extend_from_slice(&[if width == 2 { 1 } else { 0 }, center, 0, 252, 255]);
    (ht, vht)
}
pub(super) fn full_elements(width: u8, primary: u8) -> (Vec<u8>, Vec<u8>) {
    let (ht, mut vht) = elements(width, primary);
    maps(&mut vht, 0xfffa, 0xfffa, 0xfffc);
    (ht, vht)
}
fn maps(ies: &mut [u8], rx: u16, tx: u16, basic: u16) {
    let mut offset = 0;
    while offset < ies.len() {
        let end = offset + 2 + usize::from(ies[offset + 1]);
        match ies[offset] {
            191 => {
                ies[offset + 6..offset + 8].copy_from_slice(&rx.to_le_bytes());
                ies[offset + 10..offset + 12].copy_from_slice(&tx.to_le_bytes());
            }
            192 => ies[offset + 5..offset + 7].copy_from_slice(&basic.to_le_bytes()),
            _ => {}
        }
        offset = end;
    }
}
fn ldpc(ies: &mut [u8], enabled: bool) {
    let mut offset = 0;
    while offset < ies.len() {
        match ies[offset] {
            45 => ies[offset + 2] = (ies[offset + 2] & !1) | u8::from(enabled),
            191 => ies[offset + 2] = (ies[offset + 2] & !16) | (u8::from(enabled) << 4),
            _ => {}
        }
        offset += 2 + usize::from(ies[offset + 1]);
    }
}
fn ht_rx2_basic(ies: &mut [u8], mandatory: bool) {
    let mut offset = 0;
    while offset < ies.len() {
        match ies[offset] {
            45 => ies[offset + 6] = 255, // AP RX MCS8..15, independently of our TX1.
            61 => ies[offset + 9] = u8::from(mandatory), // HT Basic MCS8.
            _ => {}
        }
        offset += 2 + usize::from(ies[offset + 1]);
    }
}
pub(super) fn prepared(width: u8, secure: bool) -> (Session<Model>, ScanBss, TxPermission) {
    let (mut session, mut bss) = super::wmm_tests::prepared(true, secure);
    session.backend.station_channel = 36;
    bss.channel = 36;
    let (ht, vht) = elements(width, 36);
    session.backend.ht_reply = Some(ht.clone());
    session.backend.vht_reply = Some(vht.clone());
    let mut offset = 0;
    while offset < bss.information_elements.len() {
        if bss.information_elements[offset] == 3 {
            bss.information_elements[offset + 2] = 36;
        }
        offset += 2 + usize::from(bss.information_elements[offset + 1]);
    }
    bss.information_elements.extend_from_slice(&ht);
    bss.information_elements.extend_from_slice(&vht);
    let State::RadioReady(info) = session.state else {
        panic!("native VHT fixture radio");
    };
    let grant = TxPermission::from_ap(&domain(), info, &bss).unwrap();
    (session, bss, grant)
}
fn security(secure: bool) -> Security {
    if secure {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    }
}
pub(super) fn join(
    s: &mut Session<Model>,
    b: &ScanBss,
    p: TxPermission,
    secure: bool,
) -> Result<u16, Error> {
    run(s.associate_station(b, b"narf", security(secure), p, &[]))
}
pub(super) fn record(frame: &[u8], tag: u16) -> Option<&[u8]> {
    if frame.get(34..36) != Some(&[3, 0]) || frame.get(43) != Some(&7) {
        return None;
    }
    let mut offset = 56;
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
fn tx() -> Vec<u8> {
    let mut b = vec![0x77; 60];
    b[..6].copy_from_slice(&AP);
    b[6..12].copy_from_slice(&OWN);
    b[12..14].copy_from_slice(&[8, 0]);
    b
}
pub(super) fn data(secure: bool, width: u8, rate: u8, nss: u8, pn: u64) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[..2].copy_from_slice(&[0x88, if secure { 0x42 } else { 2 }]);
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]);
    let mut packet = vec![0; if secure { 48 } else { 32 }];
    let r1 = 1 | (1u32 << 13) | if secure { (4 << 16) | (1 << 11) } else { 0 };
    packet[4..8].copy_from_slice(&r1.to_le_bytes());
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    if secure {
        packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    }
    let offset = if secure { 40 } else { 24 };
    let rxv = (4u32 << 24)
        | (u32::from(width) << 12)
        | (1 << 15)
        | (u32::from(nss - 1) << 7)
        | u32::from(rate);
    packet[offset..offset + 4].copy_from_slice(&rxv.to_le_bytes());
    packet.extend_from_slice(&frame);
    let len = packet.len() as u32;
    packet[..4].copy_from_slice(&((2 << 27) | len).to_le_bytes());
    packet
}

fn geometry() -> Result<(), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule};
    for (center, channels) in [
        (42, [36, 40, 44, 48]),
        (58, [52, 56, 60, 64]),
        (106, [100, 104, 108, 112]),
        (122, [116, 120, 124, 128]),
        (138, [132, 136, 140, 144]),
        (155, [149, 153, 157, 161]),
        (171, [165, 169, 173, 177]),
    ] {
        for primary in channels {
            let mut db = domain();
            let p = TxPermission::from_domain80(&db, primary, center).ok_or("canonical80 grant")?;
            let sku = p.rate_limits();
            if p.channels() != channels
                || p.center_channel() != center
                || p.native_width() != 2
                || p.domain_width() != 2
                || sku.len() != 692
                || sku[4..7] != [4, 2, 1]
                || (0..4).any(|i| {
                    sku[44 + 162 * i] != channels[i]
                        || sku[45 + 162 * i..44 + 162 * (i + 1)] != [34; 161]
                })
            {
                return Err("literal80 occupied geometry or four native SKU rows");
            }
            let edge = 5000 + 5 * u32::from(channels[3]) + 1;
            db.rules.push(RegRule {
                freq_start_mhz: edge,
                freq_end_mhz: edge + 8,
                max_bandwidth_mhz: 80,
                max_power_dbm: 12,
                flags: RegFlags::empty(),
            });
            if TxPermission::from_domain80(&db, primary, center).is_none_or(|p| p.power_dbm != 12)
                || p.current(&db)
            {
                return Err("outer80MHz lower ceiling not current");
            }
            for flags in [
                RegFlags::DFS,
                RegFlags::NO_IR,
                RegFlags::INDOOR_ONLY,
                RegFlags::from_bits_retain(16),
            ] {
                db.rules[1].flags = flags;
                if TxPermission::from_domain80(&db, primary, center).is_some() || p.current(&db) {
                    return Err("outer-only restriction erased");
                }
            }
        }
    }
    for (primary, center) in [(36, 46), (48, 58), (144, 155), (165, 155), (177, 175)] {
        if TxPermission::from_domain80(&domain(), primary, center).is_some() {
            return Err("noncanonical or discontinuous80 grant");
        }
    }
    Ok(())
}
fn mt76_vht80_all_primaries_literal_geometry_power_and_live_overlap() -> TestResult {
    geometry().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht80_all_primaries_literal_geometry_power_and_live_overlap
);

fn native() -> Result<(), &'static str> {
    for width in 0..=2 {
        for secure in [false, true] {
            let (mut s, b, p) = prepared(width, secure);
            if join(&mut s, &b, p, secure) != Ok(42)
                || s.vht_profile
                    .is_none_or(|v| v.width() != width || v.center() != p.center_channel())
            {
                return Err("native VHT association/width");
            }
            let f = &s.backend.frames;
            let switch = f
                .iter()
                .find(|(_, frame)| frame.len() >= 140 && frame[36] == 0xed && frame[41] == 8);
            if switch.is_none_or(|(_, frame)| {
                frame[64..69] != [36, p.center_channel(), width, 1, 2] || frame[74] != 1
            }) {
                return Err("literal VHT CHANNEL_SWITCH RX count (distinct from RLM mask)");
            }
            let expected = [10, 0, 16, 0, 32, 0, 0, 1, 252, 255, 252, 255, 0, 0, 0, 0];
            let peer = f.iter().find(|(_, f)| record(f, 10) == Some(&expected));
            let Some((_, peer)) = peer else {
                return Err("literal source16-byte STA_REC_VHT missing");
            };
            if record(peer, 0x15).is_none_or(|r| r[6] != 56)
                || record(peer, 7).is_none_or(|r| r[9] != width)
                || !peer
                    .windows(12)
                    .any(|r| r == [3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0])
            {
                return Err("VHT PHY/state/nestedWTBL native fields");
            }
            let rlm = f
                .iter()
                .find(|(_, f)| f.len() == 68 && f[34..36] == [2, 0] && f[52..56] == [2, 0, 16, 0]);
            if rlm.is_none_or(|(_, f)| {
                f[56..68]
                    != [
                        36,
                        p.center_channel(),
                        0,
                        width,
                        1,
                        3,
                        1,
                        if width != 0 { 4 } else { 0 },
                        if width != 0 { 1 } else { 0 },
                        1,
                        0,
                        0,
                    ]
            }) {
                return Err("literal VHT RLM/width/sourceSCO");
            }
            let request = f.iter().find(|(_, f)| f.first() == Some(&0));
            if request.is_none_or(|(_, f)| {
                f.windows(14).filter(|ie| ie[..2] == [191, 12]).count() != 1
                    || !f
                        .windows(14)
                        .any(|ie| ie == [191, 12, 48, 1, 0, 0, 250, 255, 0, 0, 254, 255, 0, 0])
            }) {
                return Err("actual local1SS VHT request encoding");
            }
            s.backend.packets.push_back(data(secure, width, 7, 1, 9));
            if s.receive_ethernet().ok().flatten().is_none() {
                return Err("native VHT data metadata/controlled-port RX");
            }
            s.backend.tx_ba_offer = Some((64, 0));
            if run(s.negotiate_transmit_ba()) != Ok(true) {
                return Err("VHT originator BA transaction");
            }
            run(s.send_ethernet(&tx())).map_err(|_| "VHT native802.3 transmit")?;
            if s.backend.data_aggregation.last() != Some(&true)
                || s.backend.data_protection.last() != Some(&secure)
                || s.backend.data_ba_disabled.last() != Some(&false)
            {
                return Err("native VHT packet changed BA/key ownership");
            }
            run(s.disassociate_station()).map_err(|_| "VHT native teardown")?;
            if s.vht_profile.is_some() || s.tx_ba.published() || s.station_permission.is_some() {
                return Err("VHT teardown retained admission");
            }
        }
    }
    Ok(())
}
fn mt76_vht20_40_80_source_records_open_wpa2_packets_and_ba() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht20_40_80_source_records_open_wpa2_packets_and_ba
);

fn narrow() -> Result<(), &'static str> {
    for response in [0, 1] {
        let (mut s, b, p) = prepared(2, true);
        let (ht, vht) = elements(response, 36);
        s.backend.ht_reply = Some(ht);
        s.backend.vht_reply = Some(vht);
        if join(&mut s, &b, p, true) != Ok(42)
            || s.vht_profile.is_none_or(|v| v.width() != response)
            || s.station_permission.is_none_or(|g| {
                g.native_width() != response
                    || !g.channels().iter().all(|ch| p.channels().contains(ch))
            })
        {
            return Err("response narrowing did not replace occupied grant");
        }
        let switches: Vec<_> = s
            .backend
            .frames
            .iter()
            .enumerate()
            .filter(|(_, (_, f))| f.get(36) == Some(&0xed) && f.get(41) == Some(&8))
            .collect();
        if switches.len() != 2
            || switches[0].1 .1[66] != 2
            || switches[1].1 .1[66] != response
            || switches.iter().any(|(_, (_, frame))| frame[68] != 2)
        {
            return Err("native response width did not actually retune");
        }
        let peer = s
            .backend
            .frames
            .iter()
            .position(|(_, f)| record(f, 10).is_some())
            .ok_or("narrowed native peer")?;
        if switches[1].0 >= peer {
            return Err("VHT peer/key port preceded complete channel retune");
        }
    }
    let (mut s, b, p) = prepared(1, false);
    let (ht, vht) = elements(2, 36);
    s.backend.ht_reply = Some(ht);
    s.backend.vht_reply = Some(vht);
    if join(&mut s, &b, p, false).is_ok() || s.vht_profile.is_some() {
        return Err("response gained occupied channels beyond original offer");
    }
    Ok(())
}
fn mt76_vht_response_width_shrink_retunes_before_peer_port_and_never_widens() -> TestResult {
    narrow().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_response_width_shrink_retunes_before_peer_port_and_never_widens
);

fn rx_bounds() -> Result<(), &'static str> {
    for (rate, nss, width, extra) in [
        (10, 1, 2, 0),
        (9, 1, 0, 0),
        (7, 3, 2, 0),
        (7, 1, 3, 0),
        (7, 1, 2, 1 << 11),
        (7, 1, 2, 1 << 22),
        (7, 1, 2, 1 << 24),
    ] {
        let (mut s, b, p) = prepared(2, true);
        if extra == 1 << 11 {
            let State::RadioReady(mut info) = s.state else {
                return Err("LDPC-disabled actual NIC fixture");
            };
            info.capabilities.phy.rx_ldpc = false;
            s.state = State::RadioReady(info);
        }
        if join(&mut s, &b, p, true) != Ok(42) {
            return Err("VHT RX bounds join");
        }
        let mut invalid = data(true, width, rate, nss, 9);
        let v = u32::from_le_bytes(invalid[40..44].try_into().unwrap()) | extra;
        invalid[40..44].copy_from_slice(&v.to_le_bytes());
        s.backend.packets.push_back(invalid);
        if s.receive_ethernet() != Ok(None) {
            return Err("unsupported VHT PPDU consumed/delivered");
        }
        s.backend.packets.push_back(data(true, 2, 7, 1, 9));
        if s.receive_ethernet().ok().flatten().is_none() {
            return Err("invalid PHY metadata consumed current CCMP PN");
        }
    }
    Ok(())
}
fn mt76_vht_native_ppdu_bounds_reject_before_replay_commit() -> TestResult {
    rx_bounds().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_native_ppdu_bounds_reject_before_replay_commit
);

fn mcs_native() -> Result<(), &'static str> {
    for secure in [false, true] {
        for selected in 0..=2 {
            for peer_rx in [0xfffc, 0xfffe] {
                let (mut s, mut b, p) = prepared(selected, secure);
                maps(&mut b.information_elements, peer_rx, 0xfffe, 0xfffc);
                maps(
                    s.backend.vht_reply.as_mut().unwrap(),
                    peer_rx,
                    0xfffe,
                    0xfffc,
                );
                if join(&mut s, &b, p, secure) != Ok(42) {
                    return Err("native MCS8/9 profile association");
                }
                let valid: u16 = if selected == 0 { 0xfffd } else { 0xfffe };
                let tx_map = if peer_rx == 0xfffc { 0xfffcu16 } else { valid };
                let peer = s
                    .backend
                    .frames
                    .iter()
                    .find_map(|(_, f)| record(f, 10))
                    .ok_or("native higher MCS peer record")?;
                if peer[8..10] != tx_map.to_le_bytes() || peer[10..12] != valid.to_le_bytes() {
                    return Err("directional native MCS maps or selected20MHz cap");
                }
                // AP RX0..7 must not reduce our implemented RX0..9. The AP
                // independently advertised TX0..9 in both bound frames.
                for width in 0..=selected {
                    let highest = if width == 0 { 8 } else { 9 };
                    s.backend.packets.push_back(data(
                        secure,
                        width,
                        highest,
                        1,
                        9 + u64::from(width),
                    ));
                    if s.receive_ethernet().ok().flatten().is_none() {
                        return Err("width-valid native higher MCS packet was not delivered");
                    }
                }
                run(s.send_ethernet(&tx())).map_err(|_| "MCS8/9 native firmware-rate data TX")?;
                run(s.disassociate_station()).map_err(|_| "higher MCS teardown")?;
            }
        }
    }
    Ok(())
}
fn mt76_vht_mcs8_9_native_directional_maps_actual_ppdu_width_and_packets() -> TestResult {
    mcs_native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_mcs8_9_native_directional_maps_actual_ppdu_width_and_packets
);

fn mcs_basic() -> Result<(), &'static str> {
    // Both the original and response mandatory map must survive native
    // width selection. A20MHz cap cannot silently remove required MCS9.
    for (scan_width, reply_width, scan_basic, reply_basic) in [
        (0, 0, 0xfffe, 0xfffc),
        (2, 0, 0xfffc, 0xfffe),
        (2, 0, 0xfffe, 0xfffc),
    ] {
        let (mut s, mut b, p) = prepared(scan_width, false);
        maps(&mut b.information_elements, 0xfffe, 0xfffe, scan_basic);
        let (ht, mut vht) = elements(reply_width, 36);
        maps(&mut vht, 0xfffe, 0xfffe, reply_basic);
        s.backend.ht_reply = Some(ht);
        s.backend.vht_reply = Some(vht);
        let before = s.backend.frames.len();
        if join(&mut s, &b, p, false).is_ok()
            || s.vht_profile.is_some()
            || matches!(s.state, State::Associated { .. })
            || s.backend.frames[before..]
                .iter()
                .any(|(_, f)| record(f, 10).is_some())
            || scan_width == 0 && s.backend.frames.len() != before
        {
            return Err("mandatory MCS9 at20MHz survived preflight/response narrowing");
        }
    }
    let (mut s, mut b, p) = prepared(2, false);
    maps(&mut b.information_elements, 0xfffe, 0xfffe, 0xfffd);
    let (ht, mut vht) = elements(0, 36);
    maps(&mut vht, 0xfffe, 0xfffe, 0xfffd);
    s.backend.ht_reply = Some(ht);
    s.backend.vht_reply = Some(vht);
    if join(&mut s, &b, p, false) != Ok(42)
        || s.vht_profile.is_none_or(|profile| profile.width() != 0)
    {
        return Err("mandatory MCS8 response narrowing was rejected");
    }
    // A richer response cannot restore rates omitted by either scan map.
    let (mut s, b, p) = prepared(2, false);
    maps(
        s.backend.vht_reply.as_mut().unwrap(),
        0xfffe,
        0xfffe,
        0xfffc,
    );
    if join(&mut s, &b, p, false) != Ok(42) {
        return Err("MCS scan/response binding fixture");
    }
    if s.backend
        .frames
        .iter()
        .find_map(|(_, f)| record(f, 10))
        .is_none_or(|peer| peer[8..12] != [252, 255, 252, 255])
    {
        return Err("response promoted directional native maps beyond scan");
    }
    Ok(())
}
fn mt76_vht_width_specific_basic_mcs_and_scan_response_maps_are_bound() -> TestResult {
    mcs_basic().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_width_specific_basic_mcs_and_scan_response_maps_are_bound
);

fn receive_nss() -> Result<(), &'static str> {
    for secure in [false, true] {
        for streams in [1u8, 2] {
            for selected in 0..=2 {
                let (mut s, mut b, p) = prepared(selected, secure);
                let State::RadioReady(mut info) = s.state else {
                    return Err("actual receive streams radio fixture");
                };
                info.capabilities.phy.spatial_streams = streams;
                s.state = State::RadioReady(info);
                maps(&mut b.information_elements, 0xfffa, 0xfffa, 0xfffc);
                maps(
                    s.backend.vht_reply.as_mut().unwrap(),
                    0xfffa,
                    0xfffa,
                    0xfffc,
                );
                ht_rx2_basic(&mut b.information_elements, streams == 2);
                ht_rx2_basic(s.backend.ht_reply.as_mut().unwrap(), streams == 2);
                if join(&mut s, &b, p, secure) != Ok(42) {
                    return Err("RX2/TX1 native association");
                }
                let rx = match (selected, streams) {
                    (0, 1) => 0xfffdu16,
                    (0, _) => 0xfff5,
                    (_, 1) => 0xfffe,
                    _ => 0xfffa,
                };
                let tx_map = if selected == 0 { 0xfffdu16 } else { 0xfffe };
                let peer = s
                    .backend
                    .frames
                    .iter()
                    .find_map(|(_, f)| record(f, 10))
                    .ok_or("RX2/TX1 peer")?;
                if peer[8..10] != tx_map.to_le_bytes()
                    || peer[10..12] != rx.to_le_bytes()
                    || s.vht_profile
                        .is_none_or(|profile| profile.state() != selected)
                {
                    return Err("actual RX NSS promoted TX NSS or lost directional map");
                }
                let request = s
                    .backend
                    .frames
                    .iter()
                    .find(|(_, f)| f.first() == Some(&0))
                    .ok_or("RX2 local association request")?;
                let body = request
                    .1
                    .windows(28)
                    .find(|ie| ie[..2] == [45, 26])
                    .ok_or("RX2 actual local HT companion")?;
                if body[5] != 255
                    || body[6] != if streams == 2 { 255 } else { 0 }
                    || body[17] != if streams == 2 { 3 } else { 1 }
                {
                    return Err("HT RX0..15 / TX0..7 asymmetry not encoded");
                }
                let mut pn = 9;
                for width in 0..=selected {
                    let highest = if width == 0 { 8 } else { 9 };
                    for nss in 1..=streams {
                        s.backend
                            .packets
                            .push_back(data(secure, width, highest, nss, pn));
                        if s.receive_ethernet().ok().flatten().is_none() {
                            return Err("actual bounded NSS VHT packet was not delivered");
                        }
                        pn += 1;
                    }
                }
                // Native HT uses global MCS indices; NSTS is not a second
                // copy of that index. Check its explicit consistency too.
                let width = selected.min(1);
                let mut packet = data(secure, width, streams * 8 - 1, streams, pn);
                let offset = if secure { 40 } else { 24 };
                let rxv = (2u32 << 24)
                    | (u32::from(width) << 12)
                    | (1 << 15)
                    | (u32::from(streams - 1) << 7)
                    | u32::from(streams * 8 - 1);
                packet[offset..offset + 4].copy_from_slice(&rxv.to_le_bytes());
                s.backend.packets.push_back(packet);
                if s.receive_ethernet().ok().flatten().is_none() {
                    return Err("native HT companion MCS0..15 receive bounds");
                }
                run(s.send_ethernet(&tx())).map_err(|_| "RX2 retained one-transmitter path")?;
                run(s.disassociate_station()).map_err(|_| "RX2 native teardown")?;
            }
        }
    }
    let (mut s, mut b, p) = prepared(2, false);
    let State::RadioReady(mut info) = s.state else {
        return Err("HT mandatory MCS8 actual NSS1 fixture");
    };
    info.capabilities.phy.spatial_streams = 1;
    s.state = State::RadioReady(info);
    ht_rx2_basic(&mut b.information_elements, true);
    ht_rx2_basic(s.backend.ht_reply.as_mut().unwrap(), true);
    let before = s.backend.frames.len();
    if join(&mut s, &b, p, false).is_ok() || s.backend.frames.len() != before {
        return Err("HT mandatory MCS8 invented actual two-stream receive support");
    }
    Ok(())
}
fn mt76_vht_actual_two_stream_receive_preserves_one_stream_transmit_and_ht_companion() -> TestResult
{
    receive_nss().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_actual_two_stream_receive_preserves_one_stream_transmit_and_ht_companion
);

fn invalid_receive_nss() -> Result<(), &'static str> {
    for (streams, mode, width, rate, nss) in [
        (1, 4, 2, 9, 2),
        (2, 4, 2, 9, 3),
        (2, 4, 0, 9, 2),
        (2, 2, 1, 15, 1),
        (2, 2, 1, 7, 2),
        (2, 2, 1, 16, 2),
        (2, 2, 2, 15, 2),
    ] {
        let (mut s, mut b, p) = prepared(2, true);
        let State::RadioReady(mut info) = s.state else {
            return Err("invalid receive NSS radio fixture");
        };
        info.capabilities.phy.spatial_streams = streams;
        s.state = State::RadioReady(info);
        maps(&mut b.information_elements, 0xfffa, 0xfffa, 0xfffc);
        maps(
            s.backend.vht_reply.as_mut().unwrap(),
            0xfffa,
            0xfffa,
            0xfffc,
        );
        if join(&mut s, &b, p, true) != Ok(42) {
            return Err("invalid receive NSS join");
        }
        let mut packet = data(true, width, rate, nss, 9);
        let mut rxv = u32::from_le_bytes(packet[40..44].try_into().unwrap());
        rxv = (rxv & !(15 << 24)) | (mode << 24);
        packet[40..44].copy_from_slice(&rxv.to_le_bytes());
        s.backend.packets.push_back(packet);
        if s.receive_ethernet() != Ok(None) {
            return Err("native invalid NSS/MCS pair was delivered");
        }
        s.backend.packets.push_back(data(true, 0, 8, 1, 9));
        if s.receive_ethernet().ok().flatten().is_none() {
            return Err("unsupported receive NSS/MCS consumed a CCMP PN");
        }
    }
    Ok(())
}
fn mt76_vht_receive_nss_and_ht_global_mcs_reject_before_replay_commit() -> TestResult {
    invalid_receive_nss().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_receive_nss_and_ht_global_mcs_reject_before_replay_commit
);

fn directional_ldpc() -> Result<(), &'static str> {
    for secure in [false, true] {
        for width in 0..=2 {
            for (rx, can_tx, scan, response) in [
                (false, false, true, true),
                (true, false, true, true),
                (false, true, true, true),
                (true, true, false, true),
                (true, true, true, false),
                (true, true, true, true),
            ] {
                let (mut s, mut b, p) = prepared(width, secure);
                let State::RadioReady(mut info) = s.state else {
                    return Err("directional LDPC NIC fixture");
                };
                info.capabilities.phy.rx_ldpc = rx;
                info.capabilities.phy.tx_ldpc = can_tx;
                s.state = State::RadioReady(info);
                ldpc(&mut b.information_elements, scan);
                ldpc(s.backend.ht_reply.as_mut().unwrap(), response);
                ldpc(s.backend.vht_reply.as_mut().unwrap(), response);
                if join(&mut s, &b, p, secure) != Ok(42) {
                    return Err("directional LDPC native association");
                }
                let transmit = can_tx && scan && response;
                let peer = s
                    .backend
                    .frames
                    .iter()
                    .find_map(|(_, f)| record(f, 10))
                    .ok_or("LDPC native peer record")?;
                if peer[4] & 16 != u8::from(transmit) << 4
                    || !s.backend.frames.iter().any(|(_, f)| {
                        f.windows(12).any(|tlv| {
                            tlv == [3, 0, 12, 0, u8::from(transmit), 0, 1, 0, 0, 0, 0, 0]
                        })
                    })
                    || !s.backend.frames.iter().any(|(_, f)| {
                        f.windows(12)
                            .any(|tlv| tlv[..6] == [2, 0, 12, 0, 1, u8::from(transmit)])
                    })
                {
                    return Err("LDPC native TX did not intersect NIC/scan/response");
                }
                let request = s
                    .backend
                    .frames
                    .iter()
                    .find(|(_, f)| f.first() == Some(&0))
                    .ok_or("LDPC local request")?;
                if request
                    .1
                    .windows(14)
                    .find(|ie| ie[..2] == [191, 12])
                    .is_none_or(|ie| ie[2] & 16 != u8::from(rx) << 4)
                    || request
                        .1
                        .windows(28)
                        .find(|ie| ie[..2] == [45, 26])
                        .is_none_or(|ie| ie[2] & 1 != u8::from(rx))
                {
                    return Err("LDPC local RX promise was replaced by peer RX/TX fact");
                }
                let mut coded = data(secure, width, if width == 0 { 8 } else { 9 }, 1, 9);
                let offset = if secure { 40 } else { 24 };
                let rxv =
                    u32::from_le_bytes(coded[offset..offset + 4].try_into().unwrap()) | (1 << 11);
                coded[offset..offset + 4].copy_from_slice(&rxv.to_le_bytes());
                s.backend.packets.push_back(coded);
                if s.receive_ethernet()
                    .map_err(|_| "LDPC receive service failure")?
                    .is_some()
                    != rx
                {
                    return Err("native LDPC RX did not follow the local receive promise");
                }
                let next = if rx { 10 } else { 9 };
                s.backend.packets.push_back(data(secure, 0, 8, 1, next));
                if s.receive_ethernet().ok().flatten().is_none() {
                    return Err("LDPC rejection consumed replay PN or blocked BCC fallback");
                }
                run(s.send_ethernet(&tx())).map_err(|_| "LDPC firmware-rate native TX")?;
                run(s.disassociate_station()).map_err(|_| "LDPC native teardown")?;
            }
        }
    }
    for byte in [32, 33, 35] {
        // PHY TLV payload offsets6/7/9 in the fixed NIC reply.
        let mut bytes = capabilities();
        bytes[byte] = 2;
        if NicCapabilities::parse(&bytes) != Err(Error::InvalidIdentity) {
            return Err("invalid directional LDPC NIC boolean was accepted");
        }
    }
    Ok(())
}
fn mt76_vht_ldpc_native_directional_nic_peer_records_and_receive_pn() -> TestResult {
    directional_ldpc().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_ldpc_native_directional_nic_peer_records_and_receive_pn
);

fn receive_stbc() -> Result<(), &'static str> {
    for enabled in [false, true] {
        for streams in [1, 2] {
            for (mode, width, rate, stbc, nsts, valid) in [
                (4, 0, 8, 1, 2, true),
                (4, 1, 9, 1, 2, true),
                (4, 2, 9, 1, 2, true),
                (2, 0, 7, 1, 2, true),
                (2, 1, 7, 1, 2, true),
                (4, 2, 9, 1, 1, false),
                (4, 2, 9, 1, 3, false),
                (4, 2, 9, 1, 4, false),
                (4, 2, 9, 2, 2, false),
                (4, 2, 9, 3, 2, false),
                (2, 1, 15, 1, 4, false),
                (4, 0, 9, 1, 2, false),
                (2, 2, 7, 1, 2, false),
                (1, 0, 11, 1, 2, false),
            ] {
                let (mut s, b, p) = prepared(2, true);
                let State::RadioReady(mut info) = s.state else {
                    return Err("STBC actual NIC fixture");
                };
                info.capabilities.phy.rx_stbc = enabled;
                info.capabilities.phy.spatial_streams = streams;
                s.state = State::RadioReady(info);
                if join(&mut s, &b, p, true) != Ok(42) {
                    return Err("STBC native association");
                }
                let request = s
                    .backend
                    .frames
                    .iter()
                    .find(|(_, f)| f.first() == Some(&0))
                    .ok_or("STBC actual local request")?;
                if request
                    .1
                    .windows(14)
                    .find(|ie| ie[..2] == [191, 12])
                    .is_none_or(|ie| ie[3] & 7 != u8::from(enabled) || ie[2] & 128 != 0)
                    || request
                        .1
                        .windows(28)
                        .find(|ie| ie[..2] == [45, 26])
                        .is_none_or(|ie| ie[3] & 3 != u8::from(enabled) || ie[2] & 128 != 0)
                {
                    return Err("RXSTBC1 promise promoted TX STBC or more receive data streams");
                }
                let mut packet = data(true, width, rate, nsts, 9);
                let mut rxv = u32::from_le_bytes(packet[40..44].try_into().unwrap());
                rxv = (rxv & !(15 << 24)) | (mode << 24) | (stbc << 22);
                packet[40..44].copy_from_slice(&rxv.to_le_bytes());
                s.backend.packets.push_back(packet);
                let accepted = enabled && valid;
                if s.receive_ethernet()
                    .map_err(|_| "STBC native receive service")?
                    .is_some()
                    != accepted
                {
                    return Err(
                        "STBC NSTS/data-NSS/rate/width admission disagreed with local promise",
                    );
                }
                s.backend
                    .packets
                    .push_back(data(true, 0, 8, 1, if accepted { 10 } else { 9 }));
                if s.receive_ethernet().ok().flatten().is_none() {
                    return Err("invalid STBC consumed a replay PN or blocked uncoded fallback");
                }
                run(s.disassociate_station()).map_err(|_| "STBC native teardown")?;
            }
        }
    }
    Ok(())
}
fn mt76_vht_ht_receive_stbc1_uses_two_space_time_streams_and_one_data_stream() -> TestResult {
    receive_stbc().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_ht_receive_stbc1_uses_two_space_time_streams_and_one_data_stream
);

fn failure() -> Result<(), &'static str> {
    let (mut reference, b, p) = prepared(2, true);
    if join(&mut reference, &b, p, true) != Ok(42) {
        return Err("VHT failure reference");
    }
    let first = reference
        .backend
        .frames
        .iter()
        .position(|(_, f)| record(f, 10).is_some())
        .ok_or("VHT peer reference")?;
    for cancel in [false, true] {
        let (mut s, b, p) = prepared(2, true);
        if cancel {
            s.backend.tx_stall_after = Some(first + 1);
            {
                let mut f = pin!(s.associate_station(&b, b"narf", security(true), p, &[]));
                if f.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return Err("VHT native receipt did not suspend");
                }
            }
        } else {
            s.backend.ba_error_tag = Some(10);
            if join(&mut s, &b, p, true).is_ok() {
                return Err("rejected VHT peer accepted");
            }
        }
        if s.vht_profile.is_some()
            || s.ht20_rx.as_ref().is_some_and(|r| r.active)
            || matches!(s.state, State::Associated { .. })
            || !s.backend.owner.published
        {
            return Err("failed/cancelled VHT restored producer or freed mappings");
        }
    }
    for stage in [first, first + 1] {
        let (mut s, b, p) = prepared(2, false);
        s.backend.deny_tx_after = Some(stage);
        if join(&mut s, &b, p, false) != Err(Error::Authority)
            || s.vht_profile.is_some()
            || s.station_permission.is_some()
        {
            return Err("VHT native publication crossed current policy");
        }
    }
    Ok(())
}
fn mt76_vht_native_receipt_rejection_cancel_and_policy_do_not_publish() -> TestResult {
    failure().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_native_receipt_rejection_cancel_and_policy_do_not_publish
);

fn changes() -> Result<(), &'static str> {
    for action in [false, true] {
        let (mut s, b, p) = prepared(2, false);
        if join(&mut s, &b, p, false) != Ok(42) {
            return Err("VHT change fixture");
        }
        let mut unchanged = vec![0; 36];
        unchanged[0] = 0x80;
        unchanged[4..10].copy_from_slice(&OWN);
        unchanged[10..16].copy_from_slice(&AP);
        unchanged[16..22].copy_from_slice(&AP);
        unchanged.extend_from_slice(&super::wmm_tests::PARAMETERS);
        let (ht, vht) = elements(2, 36);
        unchanged.extend_from_slice(&ht);
        unchanged.extend_from_slice(&vht);
        let mut packet = descriptor(&unchanged);
        packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
        s.backend.packets.push_back(packet);
        if s.receive_ethernet() != Ok(None) || s.peer_lost {
            return Err("unchanged AP PHY facts compared with local transmit intersection");
        }
        let mut frame = vec![0; if action { 27 } else { 36 }];
        frame[0] = if action { 0xd0 } else { 0x80 };
        frame[4..10].copy_from_slice(&OWN);
        frame[10..16].copy_from_slice(&AP);
        frame[16..22].copy_from_slice(&AP);
        if action {
            frame[24..27].copy_from_slice(&[21, 2, 1]);
        } else {
            let (ht, mut vht) = elements(2, 36);
            vht[2] ^= 32;
            frame.extend_from_slice(&ht);
            frame.extend_from_slice(&vht);
        }
        let mut packet = descriptor(&frame);
        packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
        s.backend.packets.push_back(packet);
        if s.receive_ethernet() != Err(Error::DeviceGone)
            || s.start_ethernet(&tx()) != Err(Error::DeviceGone)
        {
            return Err("bound VHT change kept packet admission");
        }
    }
    Ok(())
}
fn mt76_vht_bound_operation_or_opmode_change_closes_both_packet_owners() -> TestResult {
    changes().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_bound_operation_or_opmode_change_closes_both_packet_owners
);

fn capability() -> Result<(), &'static str> {
    for opaque_width in [0, 1, 2, 3, 255] {
        let (mut s, b, p) = prepared(2, false);
        let State::RadioReady(mut info) = s.state else {
            return Err("native capability state");
        };
        info.capabilities.phy.max_bandwidth = opaque_width;
        s.state = State::RadioReady(info);
        if join(&mut s, &b, p, false) != Ok(42) || s.vht_profile.is_none() {
            return Err("opaque PHY max_bw decoded as a command enum");
        }
    }
    for fact in 0..4 {
        let (mut s, b, p) = prepared(2, false);
        let State::RadioReady(mut info) = s.state else {
            return Err("missing-capability state");
        };
        match fact {
            0 => info.capabilities.phy.vht = false,
            1 => info.capabilities.phy.ht = false,
            2 => info.capabilities.phy.bands = 1,
            _ => info.capabilities.phy.spatial_streams = 0,
        }
        s.state = State::RadioReady(info);
        let before = s.backend.frames.len();
        if join(&mut s, &b, p, false).is_ok()
            || s.backend.frames.len() != before
            || s.vht_profile.is_some()
        {
            return Err("missing actual NIC VHT/HT/band/NSS admitted native80");
        }
    }
    let (s, b, _) = prepared(0, false);
    let State::RadioReady(info) = s.state else {
        return Err("VHT20 band qualification");
    };
    let mut db = domain();
    db.rules[0].max_bandwidth_mhz = 20;
    let p = TxPermission::from_ap(&db, info, &b).ok_or("legacy20 fallback grant")?;
    if p.vht_available() {
        return Err("all20MHz policy invented usable80MHz VHT qualification");
    }
    let mut bytes = capabilities();
    bytes[27] = 2; // TLV8 vht byte: invalid native boolean.
    if NicCapabilities::parse(&bytes) != Err(Error::InvalidIdentity) {
        return Err("invalid native capability value accepted");
    }
    Ok(())
}
fn mt76_vht_actual_nic_facts_common80_ceiling_and_opaque_width_are_distinct() -> TestResult {
    capability().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_actual_nic_facts_common80_ceiling_and_opaque_width_are_distinct
);

fn selectors() -> Result<(), &'static str> {
    for selector in [0xff, 0xfe, 0xfa] {
        let (mut s, mut b, p) = prepared(2, false);
        let mut offset = 0;
        let mut found = false;
        while offset < b.information_elements.len() {
            let end = offset + 2 + usize::from(b.information_elements[offset + 1]);
            if b.information_elements[offset] == 50 {
                b.information_elements.insert(end, selector);
                b.information_elements[offset + 1] += 1;
                found = true;
                break;
            }
            offset = end;
        }
        if !found {
            b.information_elements.extend_from_slice(&[50, 1, selector]);
        }
        let result = join(&mut s, &b, p, false);
        if selector == 0xfa {
            if result.is_ok() || s.vht_profile.is_some() {
                return Err("HE mandatory membership silently stripped");
            }
        } else if result != Ok(42) || s.vht_profile.is_none() {
            return Err("native completed VHT profile did not bind mandatory HT/VHT selector");
        }
    }
    for fault in 0..4 {
        let (mut s, b, p) = prepared(2, false);
        let vht = s.backend.vht_reply.as_mut().unwrap();
        match fault {
            0 => {
                vht[19] = 0;
                vht[20] = 0;
            }
            1 => vht[18] = 50,
            2 => {
                vht[6] = 255;
                vht[7] = 255;
            }
            _ => {
                vht[16] = 1;
                vht[17] = 58;
            }
        }
        if join(&mut s, &b, p, false).is_ok()
            || s.vht_profile.is_some()
            || matches!(s.state, State::Associated { .. })
        {
            return Err("incompatible response MCS/geometry left a partial associated producer");
        }
    }
    Ok(())
}
fn mt76_vht_mandatory_selectors_basic_maps_and_bound_response_fail_closed() -> TestResult {
    selectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_mandatory_selectors_basic_maps_and_bound_response_fail_closed
);

fn rekey() -> Result<(), &'static str> {
    let (mut s, b, p) = prepared(2, true);
    if join(&mut s, &b, p, true) != Ok(42) {
        return Err("VHT rekey association");
    }
    s.backend.packets.push_back(data(true, 2, 7, 1, 9));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("old VHT key PN fixture");
    }
    s.backend.tx_ba_offer = Some((64, 0));
    if run(s.negotiate_transmit_ba()) != Ok(true) {
        return Err("old VHT originator");
    }
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    let mut packet = descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol()));
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    s.backend.packets.push_back(packet);
    if s.receive_ethernet() != Ok(None) || !s.keys_pending() {
        return Err("actual VHT key challenge");
    }
    s.backend.access_point = None;
    s.backend.psk = [0x55; 32];
    s.backend.own_mac = OWN;
    s.backend.ap_mac = AP;
    s.backend.anonce = [0x55; 32];
    let before = s.backend.frames.len();
    run(s.service_keys()).map_err(|_| "VHT originator retirement before M2")?;
    if s.tx_ba.published()
        || s.tx_ba.active()
        || s.backend.frames[before..]
            .iter()
            .position(|(_, f)| extract_eapol(f).is_some())
            .is_none_or(|i| i < 3)
    {
        return Err("VHT key publication crossed old BA records");
    }
    if s.receive_ethernet() != Ok(None) || !s.keys_pending() {
        return Err("genuine VHT new-key M3");
    }
    run(s.service_keys()).map_err(|_| "VHT native PTK receipts")?;
    s.backend.packets.push_back(data(true, 2, 7, 1, 1));
    if s.receive_ethernet().ok().flatten().is_none() || s.vht_profile.is_none_or(|v| v.width() != 2)
    {
        return Err("new VHT key retained old PN or lost completed PHY context");
    }
    run(s.send_ethernet(&tx())).map_err(|_| "VHT new-key non-BA data")?;
    if s.backend.data_aggregation.last() != Some(&false) {
        return Err("VHT rekey revived old originator epoch");
    }
    Ok(())
}
fn mt76_vht_rekey_retires_ba_before_native_keys_and_preserves_fresh_pn_epoch() -> TestResult {
    rekey().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_rekey_retires_ba_before_native_keys_and_preserves_fresh_pn_epoch
);

fn fallback() -> Result<(), &'static str> {
    for (width, selector) in [(20, 0xff), (40, 0xff), (20, 0xfe)] {
        let (mut s, mut b, _) = prepared(2, false);
        b.information_elements.extend_from_slice(&[50, 1, selector]);
        // The fixture's default rates may already have Extended Rates.
        let mut offset = 0;
        let mut found = false;
        while offset + 3 < b.information_elements.len() - 3 {
            let end = offset + 2 + usize::from(b.information_elements[offset + 1]);
            if b.information_elements[offset] == 50 {
                b.information_elements.insert(end, selector);
                b.information_elements[offset + 1] += 1;
                found = true;
                break;
            }
            offset = end;
        }
        if found {
            b.information_elements
                .truncate(b.information_elements.len() - 3);
        }
        let mut db = domain();
        db.rules[0].max_bandwidth_mhz = width;
        let State::RadioReady(info) = s.state else {
            return Err("HT fallback radio");
        };
        let p = TxPermission::from_ap(&db, info, &b).ok_or("narrow native fallback permission")?;
        let before = s.backend.frames.len();
        let result = join(&mut s, &b, p, false);
        if selector == 0xfe {
            if result.is_ok() || s.backend.frames.len() != before {
                return Err("mandatory VHT selector downgraded to HT");
            }
        } else {
            if result != Ok(42)
                || s.vht_profile.is_some()
                || s.ht20_profile.is_none()
                || s.station_permission
                    .is_none_or(|g| g.native_width() != u8::from(width == 40))
                || s.backend
                    .frames
                    .iter()
                    .any(|(_, f)| record(f, 10).is_some())
            {
                return Err("typed HT fallback rejected mandatory HT or retained VHT/native80");
            }
            run(s.send_ethernet(&tx())).map_err(|_| "typedHT fallback non-BA data")?;
            if s.backend.data_ba_disabled.last() != Some(&true) {
                return Err("HT fallback enabled unnegotiated TX BA");
            }
        }
    }
    Ok(())
}
fn mt76_vht_narrow_policy_preserves_typed_ht_selector_fallback_without_vht_promise() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_vht_narrow_policy_preserves_typed_ht_selector_fallback_without_vht_promise
);
