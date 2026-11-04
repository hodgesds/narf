//! Explicit P2P wire fixtures, independent of host role booleans.
use alloc::{vec, vec::Vec};
pub(super) const DEVICE: [u8; 6] = [2, 0x47, 1, 2, 3, 4];
fn p2p(ies: &mut Vec<u8>, attrs: &[u8]) {
    ies.extend_from_slice(&[221, (4 + attrs.len()) as u8, 0x50, 0x6f, 0x9a, 9]);
    ies.extend_from_slice(attrs);
}
pub(super) fn decorate(mut config: narf_wireless::ApConfig) -> narf_wireless::ApConfig {
    let mut head = config.beacon_head[..36].to_vec();
    let mut raw = &config.beacon_head[36..];
    while !raw.is_empty() {
        let end = 2 + usize::from(raw[1]);
        if !matches!(raw[0], 1 | 50) {
            head.extend_from_slice(&raw[..end]);
        }
        raw = &raw[end..];
    }
    // P2P GO has6/12/24Mbps basic OFDM, with no CCK in advertised IEs.
    head.extend_from_slice(&[1, 3, 0x8c, 0x98, 0xb0]);
    let mut attrs = vec![2, 2, 0, 0x25, 1, 3, 6, 0];
    attrs.extend_from_slice(&DEVICE);
    p2p(&mut head, &attrs);
    config.beacon_head = head;
    let mut probe = config.beacon_head[..36].to_vec();
    probe[0] = 0x50;
    let mut raw = &config.beacon_head[36..];
    while !raw.is_empty() {
        let end = 2 + usize::from(raw[1]);
        if !(raw[0] == 221 && raw.get(2..6) == Some(&[0x50, 0x6f, 0x9a, 9])) {
            probe.extend_from_slice(&raw[..end]);
        }
        raw = &raw[end..];
    }
    let mut attrs = vec![2, 2, 0, 0x25, 1, 13, 17, 0];
    attrs.extend_from_slice(&DEVICE);
    attrs.extend_from_slice(&[0, 0, 0, 1, 0, 0x50, 0xf2, 4, 0, 1, 0]);
    p2p(&mut probe, &attrs);
    config.probe_resp = Some(probe);
    config
}
pub(super) fn notice(mac: u32, index: u8, active: bool) -> Vec<u8> {
    let mut out = vec![0; 44];
    out[..4].copy_from_slice(&mac.to_le_bytes());
    out[4..8].copy_from_slice(&u32::from(active).to_le_bytes());
    out[8..13].copy_from_slice(&[12, 15, 0, index, 0]);
    out[13] = 1;
    out[14..18].copy_from_slice(&5000u32.to_le_bytes());
    out[18..22].copy_from_slice(&10000u32.to_le_bytes());
    out[22..26].copy_from_slice(&0x12345678u32.to_le_bytes());
    out[40] = 0xff;
    out
}
pub(super) fn forge_probe(mut probe: Vec<u8>, peer: [u8; 6]) -> Vec<u8> {
    probe[4..10].copy_from_slice(&peer);
    // A host-only NoA must never acquire native authority at publication.
    p2p(&mut probe, &notice(0, 99, true)[8..26]);
    probe
}
pub(super) fn check_probe(
    frame: &[u8],
    own: [u8; 6],
    index: Option<u8>,
) -> Result<(), &'static str> {
    if frame.len() < 36 || frame[0] != 0x50 || frame[10..16] != own || frame[16..22] != own {
        return Err("GO native probe changed physical owner");
    }
    let attrs = &notice(0, 99, true)[8..26];
    if frame.windows(attrs.len()).any(|window| window == attrs) {
        return Err("GO host NoA was promoted into native receipt authority");
    }
    if let Some(index) = index {
        let expected = notice(0, index, true);
        if !frame.windows(18).any(|window| window == &expected[8..26]) {
            return Err("GO current native NoA absent from actual TX bytes");
        }
    } else if frame.windows(3).any(|window| window == [12, 15, 0]) {
        return Err("GO native clear retained an old NoA attribute");
    }
    Ok(())
}

/// Independent on-air group recipient. The firmware fixture has no access
/// to the host key owner or its PN; it verifies actual posted CCMP bytes.
pub(super) fn open_group(
    frame: &[u8],
    own: [u8; 6],
    gtk: [u8; 16],
    last: u64,
) -> Result<u64, &'static str> {
    let header = if frame.first() == Some(&0x88) { 26 } else { 24 };
    if frame.len() < header + 16 || frame[4] & 1 == 0 || frame[10..16] != own {
        return Err("GO group radio frame owner invalid");
    }
    let (pn, id) =
        narf_wireless::ccmp::decode_ccmp_header(frame[header..header + 8].try_into().unwrap())
            .map_err(|_| "GO group CCMP header invalid")?;
    if pn <= last || id != 1 {
        return Err("GO group native replay/key ID invalid");
    }
    let local = [2, 0x46, 5, 4, 3, 2];
    let mut key = narf_wireless::packet_key::Key::new(
        &gtk,
        1,
        narf_wireless::packet_key::Role::Group,
        local,
        own,
        last,
    )
    .map_err(|_| "GO independent group key")?;
    let mut wire = frame[header..].to_vec();
    let plain = key
        .unprotect(&frame[..header], &mut wire)
        .map_err(|_| "GO actual group MIC/decryption failed")?;
    if !plain.starts_with(&[0xaa, 0xaa, 3, 0, 0, 0]) {
        return Err("GO decrypted group SNAP differs");
    }
    if plain.get(6..8) == Some(&[8, 0]) {
        // Independently calculated UDP pseudo-header checksum for the
        // literal192.0.2.1:1000 ->192.0.2.2:2000, payload01/02/03 vector.
        if plain.get(8 + 20 + 6..8 + 20 + 8) != Some(&[0x6c, 0x1a]) {
            return Err("GO host CCMP sealed a partially checksummed UDP packet");
        }
    }
    Ok(pn)
}

pub(super) fn robust(own: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0xc0;
    frame[4..10].fill(255);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&own);
    frame[24] = 3;
    frame
}
pub(super) fn get_request(index: u8, ifindex: u32) -> Vec<u8> {
    fn attr(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend_from_slice(&((body.len() + 4) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(body);
        out.resize((out.len() + 3) & !3, 0);
    }
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    attr(&mut attrs, 8, &[index]);
    let mut request = Vec::new();
    request.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    request.extend_from_slice(&narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    request.extend_from_slice(&5u16.to_ne_bytes());
    request.extend_from_slice(&0x474f5039u32.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(&[9, 1, 0, 0]);
    request.extend_from_slice(&attrs);
    request
}
pub(super) fn check_key_reply(raw: &[u8], index: u8, pn: u64) -> Result<(), &'static str> {
    fn attr(mut raw: &[u8], kind: u16) -> Option<&[u8]> {
        while raw.len() >= 4 {
            let len = usize::from(u16::from_ne_bytes([raw[0], raw[1]]));
            if len < 4 || len > raw.len() {
                return None;
            }
            if u16::from_ne_bytes([raw[2], raw[3]]) & 0x3fff == kind {
                return Some(&raw[4..len]);
            }
            raw = raw.get((len + 3) & !3..)?;
        }
        None
    }
    if raw.len() < 20 || raw[16] != 11 || raw[8..12] != 0x474f5039u32.to_ne_bytes() {
        return Err("GO original GET_KEY reply sequence/command invalid");
    }
    let seq = pn.to_le_bytes();
    let cipher = if index <= 3 {
        narf_wireless::CIPHER_SUITE_CCMP
    } else {
        narf_wireless::CIPHER_SUITE_AES_CMAC
    };
    let attrs = &raw[20..];
    let nested = attr(attrs, 80).ok_or("GO GET_KEY nested metadata absent")?;
    if attr(attrs, 9) != Some(&cipher.to_ne_bytes())
        || attr(nested, 3) != Some(&cipher.to_ne_bytes())
        || attr(attrs, 7).is_some()
        || attr(nested, 1).is_some()
        || attr(attrs, 8) != Some(&[index])
        || attr(nested, 2) != Some(&[index])
        || attr(attrs, 10) != Some(&seq[..6])
        || attr(nested, 4) != Some(&seq[..6])
    {
        return Err("GO GET_KEY exported keybytes or lost actual group PN");
    }
    Ok(())
}

pub(super) fn udp_group(own: [u8; 6]) -> Vec<u8> {
    let mut out = vec![255; 6];
    out.extend_from_slice(&own);
    out.extend_from_slice(&[8, 0]);
    out.extend_from_slice(&[
        0x45, 0, 0, 31, 0, 0, 0, 0, 64, 17, 0xf6, 0xca, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    out.extend_from_slice(&[3, 0xe8, 7, 0xd0, 0, 11, 0, 0, 1, 2, 3]);
    out
}

/// Actual generic-netlink public forms, including the original WDEV and
/// NO_CCK flag used by P2P management clients. No synthetic interface ID.
pub(super) fn management_request(
    ifindex: u32,
    wiphy: u32,
    frequency: u32,
    frame: Option<&[u8]>,
    both_selectors: bool,
) -> Vec<u8> {
    fn attr(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend_from_slice(&((body.len() + 4) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(body);
        out.resize((out.len() + 3) & !3, 0);
    }
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    if both_selectors {
        let wdev = (u64::from(wiphy) << 32) | u64::from(ifindex);
        attr(&mut attrs, 153, &wdev.to_ne_bytes());
    }
    let command = if let Some(frame) = frame {
        attr(&mut attrs, 38, &frequency.to_ne_bytes());
        attr(&mut attrs, 51, frame);
        attr(&mut attrs, 135, &[]); // NO_CCK is a flag, never a host rate.
        59
    } else {
        attr(&mut attrs, 101, &0x40u16.to_ne_bytes());
        attr(&mut attrs, 91, b"\0");
        58
    };
    let mut out = Vec::new();
    out.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    out.extend_from_slice(&5u16.to_ne_bytes());
    out.extend_from_slice(&0x474f5055u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&[command, 1, 0, 0]);
    out.extend_from_slice(&attrs);
    out
}
pub(super) fn management_completed(
    messages: &[Vec<u8>],
    transmit: bool,
) -> Result<bool, &'static str> {
    for raw in messages {
        if raw.len() < 20 || raw[8..12] != 0x474f5055u32.to_ne_bytes() {
            continue;
        }
        if u16::from_ne_bytes(raw[4..6].try_into().unwrap()) == 2 {
            let error = i32::from_ne_bytes(raw[16..20].try_into().unwrap());
            if error != 0 {
                return Err("GO public P2P management command refused");
            }
            if !transmit {
                return Ok(true);
            }
        } else if transmit && raw[16] == 59 {
            return Ok(true);
        }
    }
    Ok(false)
}
