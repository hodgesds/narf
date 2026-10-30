//! Native AP 802.11 cut-through descriptor and Ethernet framing.
//! This path carries software CCMP bytes unchanged: the Protected MAC bit
//! does not select a hardware key. Linux connac2 TXWI does that only when
//! mac80211 supplied info->control.hw_key. No TXD3_PROTECT/SN_VALID is set.
use crate::mt7921::{association::LegacyRate, firmware_transport::Error};
use alloc::{vec, vec::Vec};

pub(super) fn ethernet(
    own: [u8; 6],
    ethernet: &[u8],
    protected: bool,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if !(14..=1514).contains(&ethernet.len())
        || ethernet[..6] == [0; 6]
        || ethernet[6..12] == [0; 6]
        || ethernet[6] & 1 != 0
        || u16::from_be_bytes([ethernet[12], ethernet[13]]) < 0x600
    {
        return Err(Error::Bounds);
    }
    let mut header = vec![0; 24];
    header[0] = 0x08;
    header[1] = 2 | if protected { 0x40 } else { 0 };
    header[4..10].copy_from_slice(&ethernet[..6]);
    header[10..16].copy_from_slice(&own);
    header[16..22].copy_from_slice(&ethernet[6..12]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
    body.extend_from_slice(&ethernet[12..]);
    Ok((header, body))
}

pub(super) fn descriptor(
    frame: &[u8],
    payload: u64,
    token: u16,
    wcid: u8,
    rate: LegacyRate,
) -> Result<[u8; 64], Error> {
    if !(24..=4032).contains(&frame.len())
        || token == 0
        || token >= 8192
        || !(wcid <= 13 || wcid == 19)
        || payload
            .checked_add(frame.len() as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Bounds);
    }
    let kind = (frame[0] >> 2) & 3;
    let subtype = frame[0] >> 4;
    let data = kind == 2;
    let multicast = frame[4] & 1 != 0;
    let qos = data && subtype == 8;
    let header = if qos { 26 } else { 24 };
    if frame.len() <= header
        || frame[0] & 3 != 0
        || frame[1] & 0x84 != 0
        || frame[22] & 15 != 0
        || if data {
            !matches!(subtype, 0 | 8) || frame[1] & 3 != 2 || wcid == 0 || multicast != (wcid == 19)
        } else {
            kind != 0 || !matches!(subtype, 1 | 3 | 5 | 10 | 11 | 12 | 13) || frame[1] & 0x43 != 0
        }
        || qos && (frame[24] & 0xf0 != 0 || frame[25] != 0)
    {
        return Err(Error::Bounds);
    }
    let tid = if qos { frame[24] & 15 } else { 0 };
    let queue = if data {
        3 - u32::from(crate::mt7921::tx_priority::UP_TO_AC[usize::from(tid & 7)])
    } else {
        0x10
    };
    let fixed = !data || multicast;
    let words = [
        (frame.len() as u32 + 32) | (queue << 25),
        1 << 31 | u32::from(tid) << 20 | 2 << 16 | (header as u32 / 2) << 11 | u32::from(wcid),
        u32::from(fixed) << 31
            | u32::from(fixed) << 13
            | u32::from(multicast) << 10
            | u32::from(kind) << 4
            | u32::from(subtype),
        1 << 28 | 15 << 11 | u32::from(multicast),
        0,
        0,
        if fixed {
            4 | u32::from(rate.hardware()) << 16
        } else {
            0
        },
        u32::from(kind) << 20 | u32::from(subtype) << 16,
    ];
    let mut out = [0; 64];
    for (i, word) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out[32..34].copy_from_slice(&(token | 0x8000).to_le_bytes());
    out[40..44].copy_from_slice(&(payload as u32).to_le_bytes());
    out[44..46].copy_from_slice(&((frame.len() as u16) | 0x8000).to_le_bytes());
    Ok(out)
}

pub(super) fn to_ethernet(
    own: [u8; 6],
    peer: [u8; 6],
    header: &[u8],
    body: &[u8],
) -> Option<Vec<u8>> {
    if !matches!(header.len(), 24 | 26)
        || header[1] & 3 != 1
        || header[4..10] != own
        || header[10..16] != peer
        || header[16..22] == [0; 6]
        || body.len() < 8
        || body[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || u16::from_be_bytes([body[6], body[7]]) < 0x600
        || body.len() > 1508
    {
        return None;
    }
    let mut out = Vec::with_capacity(6 + 6 + body.len() - 6);
    out.extend_from_slice(&header[16..22]);
    out.extend_from_slice(&peer);
    out.extend_from_slice(&body[6..]);
    Some(out)
}
