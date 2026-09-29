//! Ethernet/802.11 conversion and receive admission for one BSS.

use super::scan_api::Mpdu;
use alloc::{vec, vec::Vec};

pub fn management(subtype: u8, local: [u8; 6], ap: [u8; 6], sequence: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    bytes[0] = subtype;
    bytes[4..10].copy_from_slice(&ap);
    bytes[10..16].copy_from_slice(&local);
    bytes[16..22].copy_from_slice(&ap);
    bytes[22..24].copy_from_slice(&((sequence & 0xfff) << 4).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

pub fn transmit(
    local: [u8; 6],
    ap: [u8; 6],
    sequence: u16,
    ethernet: &[u8],
    protected: bool,
) -> Option<Vec<u8>> {
    if !(14..=1514).contains(&ethernet.len())
        || ethernet[6..12] != local
        || u16::from_be_bytes([ethernet[12], ethernet[13]]) < 0x600
    {
        return None;
    }
    let mut bytes = management(8, local, ap, sequence, &[]);
    bytes[1] = 1 | if protected { 0x40 } else { 0 };
    bytes[16..22].copy_from_slice(&ethernet[..6]);
    bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    bytes.extend_from_slice(&ethernet[12..]);
    Some(bytes)
}

#[derive(Debug, Default)]
pub struct Replay {
    pub pairwise: [u64; 17],
    pub group: [[u64; 17]; 4],
    pub group_valid: [bool; 4],
    sequences: [Option<u16>; 17],
}

pub fn receive(
    mpdu: &Mpdu<'_>,
    local: [u8; 6],
    ap: [u8; 6],
    secure: bool,
    replay: &mut Replay,
) -> Option<Vec<u8>> {
    let frame = mpdu.frame;
    if frame.len() < 24
        || frame[0] & 0x0f != 8
        || frame[0] & 0x40 != 0
        || frame[1] & 7 != 2
        || frame[10..16] != ap
        || (frame[4..10] != local && frame[4] & 1 == 0)
        || frame[22] & 0xf != 0
        || mpdu.amsdu
    {
        return None;
    }
    let qos = frame[0] & 0x80 != 0;
    let tid = if qos {
        (*frame.get(24)? & 0xf) as usize
    } else {
        16
    };
    if qos && *frame.get(24)? & 0x80 != 0 {
        return None;
    } // no A-MSDU negotiation
    let header_len = 24
        + if qos {
            2 + if frame[1] & 0x80 != 0 { 4 } else { 0 }
        } else {
            0
        };
    let encrypted = frame[1] & 0x40 != 0;
    let mut update = None;
    let body = if encrypted {
        // Hardware authenticates CCM; the host maintains replay state
        // per key and TID. Never advance PN before MIC validation.
        if !secure || mpdu.status & 0x740 != 0x240 {
            return None;
        }
        let iv: &[u8; 8] = frame.get(header_len..header_len + 8)?.try_into().ok()?;
        let (pn, key_id) = narf_wireless::ccmp::decode_ccmp_header(iv).ok()?;
        let multicast = frame[4] & 1 != 0;
        let previous = if multicast {
            if !replay.group_valid[key_id as usize] {
                return None;
            }
            replay.group[key_id as usize][tid]
        } else {
            if key_id != 0 {
                return None;
            }
            replay.pairwise[tid]
        };
        if pn <= previous {
            return None;
        }
        update = Some((pn, key_id as usize, multicast));
        mpdu.body(header_len, 8)?
    } else {
        mpdu.body(header_len, 0)?
    };
    if body.len() < 8 || body[..6] != [0xaa, 0xaa, 3, 0, 0, 0] {
        return None;
    }
    // The controlled port never forwards plaintext data on a secured
    // BSS. EAPOL is consumed by the station controller, not by IP.
    if secure && !encrypted && body[6..8] != [0x88, 0x8e] {
        return None;
    }
    let sequence = u16::from_le_bytes(frame[22..24].try_into().ok()?);
    if frame[1] & 8 != 0 && replay.sequences[tid] == Some(sequence) {
        return None;
    }
    if let Some((pn, key, multicast)) = update {
        if multicast {
            replay.group[key][tid] = pn;
        } else {
            replay.pairwise[tid] = pn;
        }
    }
    replay.sequences[tid] = Some(sequence);
    let mut ethernet = Vec::with_capacity(body.len() + 6);
    ethernet.extend_from_slice(&frame[4..10]);
    ethernet.extend_from_slice(&frame[16..22]);
    ethernet.extend_from_slice(&body[6..]);
    Some(ethernet)
}
