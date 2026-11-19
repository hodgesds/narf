//! Independent P2P GO management facts around the real FakeAp RSNA owner.
//! Only unprotected beacon/association metadata is appended; authenticated
//! key/data frames retain their original real MIC/AES/PN conversation.
use alloc::{vec, vec::Vec};
pub(super) const LOCAL_DEVICE: [u8; 6] = [2, 0x43, 1, 2, 3, 4];
pub(super) const PEER_DEVICE: [u8; 6] = [2, 0x44, 5, 6, 7, 8];
fn vendor(frame: &mut Vec<u8>, attrs: &[u8]) {
    frame.extend_from_slice(&[221, (4 + attrs.len()) as u8, 0x50, 0x6f, 0x9a, 9]);
    frame.extend_from_slice(attrs);
}
pub(super) fn request() -> Vec<u8> {
    let mut attrs = vec![2, 2, 0, 0x25, 0, 13, 17, 0];
    attrs.extend_from_slice(&LOCAL_DEVICE);
    attrs.extend_from_slice(&[0, 0, 0, 1, 0, 0x50, 0xf2, 4, 0, 1, 0]);
    let mut out = Vec::new();
    vendor(&mut out, &attrs);
    out
}
pub(super) fn beacon(mut frame: Vec<u8>, index: u8, ctwindow: Option<u8>) -> Vec<u8> {
    let mut attrs = vec![2, 2, 0, 0x25, 1, 3, 6, 0];
    attrs.extend_from_slice(&PEER_DEVICE);
    if let Some(window) = ctwindow {
        attrs.extend_from_slice(&[12, 2, 0, index, window]);
    }
    vendor(&mut frame, &attrs);
    frame
}
pub(super) fn response(frame: &mut Vec<u8>) {
    if frame.len() >= 30 && matches!(frame[0], 0x10 | 0x30) && frame[1] & 0xc7 == 0 {
        vendor(frame, &[0, 1, 0, 0]); // Actual P2P Status: success.
    }
}
pub(super) fn check_request(frame: &[u8]) -> Result<(), &'static str> {
    if frame.first() == Some(&0) {
        let ies = frame.get(28..).ok_or("P2P client request body")?;
        let attrs = super::p2p_go::attributes(ies)?;
        let info = super::p2p_go::unique(&attrs, 13)?
            .ok_or("P2P client request lost actual DeviceInfo")?;
        if info.get(..6) != Some(&LOCAL_DEVICE) {
            return Err("P2P client association changed protocol Device Address");
        }
    }
    Ok(())
}

pub(super) fn mac(stage: u8, body: &[u8]) -> Result<u8, &'static str> {
    if body.len() != 52 || body[..4] != [0; 4] {
        return Err("P2P client native MAC0 extent/identity");
    }
    let action = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let kind = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let window = u32::from_le_bytes(body[48..52].try_into().unwrap());
    if kind == 7 && body[36] == 0 && u32::from_le_bytes(body[20..24].try_into().unwrap()) & 32 != 0
    {
        return Err("CLIENT probe filter opened before actual association");
    }
    match (stage, action, kind) {
        (0 | 4, 1, 5) => Ok(stage),
        (0 | 4, 3, 5) => Ok(1),
        (1, 1, 7) if window == 32 => Ok(2),
        (2, 2, 7) if window <= 127 => Ok(2),
        (2, 3, 7) => Ok(3),
        (3, 1, 5) => Ok(4),
        _ => Err("P2P client firmware type/ADD-MODIFY-REMOVE/CTWindow order invalid"),
    }
}

pub(super) fn public_frame(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&peer);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&peer);
    frame.extend_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9, 0, 1]);
    frame.extend_from_slice(&request()[6..]);
    frame
}
pub(super) fn check_public(
    frame: &[u8],
    command: &[u8],
    own: [u8; 6],
    peer: [u8; 6],
    gen2: bool,
) -> Result<(), &'static str> {
    let expected = public_frame(own, peer);
    let mut actual = frame.to_vec();
    if actual.len() >= 24 {
        actual[22..24].fill(0);
    }
    let flags = if gen2 {
        u32::from_le_bytes(command[8..12].try_into().unwrap())
    } else {
        u32::from(u16::from_le_bytes(command[6..8].try_into().unwrap()))
    };
    let rate = u32::from_le_bytes(command[20..24].try_into().unwrap());
    if actual != expected || flags != 3 || rate & 0x3fff != 0x100 || rate >> 14 == 0 {
        return Err(
            "P2P public FRAME changed actual owner/body or native OFDM6/rate/encryption flags",
        );
    }
    Ok(())
}

pub(super) fn peer_action(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = public_frame(peer, own);
    frame[16..22].copy_from_slice(&peer);
    frame[40..46].copy_from_slice(&PEER_DEVICE);
    frame
}
pub(super) fn register_request(ifindex: u32, wiphy: u32, both: bool) -> Vec<u8> {
    let mut out = vec![0; 20];
    for (kind, body) in [
        (3u16, ifindex.to_ne_bytes().to_vec()),
        (
            153,
            ((u64::from(wiphy) << 32) | u64::from(ifindex))
                .to_ne_bytes()
                .to_vec(),
        ),
        (101, 0xd0u16.to_ne_bytes().to_vec()),
        (91, vec![4, 9]),
    ] {
        if kind == 153 && !both {
            continue;
        }
        out.extend_from_slice(&((4 + body.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&body);
        out.resize((out.len() + 3) & !3, 0);
    }
    let len = out.len() as u32;
    out[..4].copy_from_slice(&len.to_ne_bytes());
    out[4..6].copy_from_slice(&narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    out[6..8].copy_from_slice(&5u16.to_ne_bytes());
    out[8..12].copy_from_slice(&0x474f5055u32.to_ne_bytes());
    out[16] = 58;
    out[17] = 1;
    out
}
pub(super) fn received(messages: &[Vec<u8>], frame: &[u8]) -> usize {
    messages
        .iter()
        .filter(|b| {
            if b.len() < 20
                || b[4..6] != narf_wireless::nl80211::NL80211_FAMILY_ID.to_ne_bytes()
                || b[16] != 59
            {
                return false;
            }
            let mut attrs = &b[20..];
            while attrs.len() >= 4 {
                let n = usize::from(u16::from_ne_bytes([attrs[0], attrs[1]]));
                if n < 4 || n > attrs.len() {
                    return false;
                }
                if u16::from_ne_bytes([attrs[2], attrs[3]]) == 51 {
                    return &attrs[4..n] == frame;
                }
                let Some(next) = attrs.get((n + 3) & !3..) else {
                    return false;
                };
                attrs = next;
            }
            false
        })
        .count()
}

pub(super) fn probe_request(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = 0x40;
    frame[4..10].copy_from_slice(&own);
    frame[10..16].copy_from_slice(&peer);
    frame[16..22].fill(255);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&request());
    frame
}
pub(super) fn register_probe_request(ifindex: u32, wiphy: u32, both: bool) -> Vec<u8> {
    let mut request = register_request(ifindex, wiphy, both);
    let mut offset = 20;
    while offset + 4 <= request.len() {
        let n = usize::from(u16::from_ne_bytes([request[offset], request[offset + 1]]));
        match u16::from_ne_bytes([request[offset + 2], request[offset + 3]]) {
            101 => request[offset + 4..offset + 6].copy_from_slice(&0x40u16.to_ne_bytes()),
            91 => request[offset + 4..offset + 6].copy_from_slice(&[0, 0]),
            _ => {}
        }
        offset += (n + 3) & !3;
    }
    request
}
