//! Native unkeyed-WTBL RX metadata for the AP software-CCMP profile.
//!
//! Linux mt7921/mac.c::mt7921_mac_fill_rx leaves DECRYPTED unset when
//! SEC_MODE==0 or CM/CLM, preserving the on-air CCMP header/MIC for software
//! crypto. This decoder never treats such bytes as authenticated plaintext.
use crate::mt7921::channel;

#[derive(Debug)]
pub(super) struct Raw<'a> {
    pub frame: &'a [u8],
    pub channel: u8,
    pub band: channel::Band,
    pub wcid: u16,
    pub tid: u8,
    pub fragment: bool,
    pub signal_dbm: Option<i8>,
}
fn word(packet: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        packet.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
pub(super) fn decode(packet: &[u8], nss: u8) -> Option<Raw<'_>> {
    let r0 = word(packet, 0)?;
    let length = (r0 & 0xffff) as usize;
    if !(r0 >> 27 == 2 || r0 >> 27 == 7 && (r0 >> 16) & 15 == 1)
        || length < 24
        || length > packet.len()
    {
        return None;
    }
    let packet = &packet[..length];
    let r1 = word(packet, 4)?;
    let r2 = word(packet, 8)?;
    let channel = u8::try_from((word(packet, 12)? >> 8) & 0x1ff).ok()?;
    let (band, channel) = channel::from_rx_channel(channel)?;
    // CM/CLM alone report an unavailable crypto key/cipher, not successful
    // authentication. ICV/TKIP-MIC/FCS, another band and translated/partial
    // hardware A-MSDU are refused exactly as on the ordinary native path.
    let cipher = (r1 >> 16) & 31;
    let mismatch = r1 & (3 << 23) != 0;
    if !matches!(cipher, 0 | 4)
        || cipher != 0 && !mismatch
        || r1 & (15 << 25) != 0
        || r2 & ((1 << 13) | (7 << 23)) != 0
        || word(packet, 16)? & 3 != 0
    {
        return None;
    }
    let mut offset = 24;
    for (flag, size) in [(14, 16), (11, 16), (12, 8)] {
        if r1 & (1 << flag) != 0 {
            packet.get(offset..offset + size)?;
            offset += size;
        }
    }
    let mut signal_dbm = None;
    if r1 & (1 << 13) != 0 {
        packet.get(offset..offset + 8)?;
        let mut rcpi = word(packet, offset + 4)?;
        offset += 8;
        if r1 & (1 << 15) != 0 {
            packet.get(offset..offset + 72)?;
            rcpi = word(packet, offset + 24)?;
            offset += 72;
        }
        for chain in 0..nss.min(2) {
            let value = ((rcpi >> (chain * 8)) & 255) as i16;
            if (1..220).contains(&value) {
                let signal = (value / 2 - 110) as i8;
                signal_dbm = Some(signal_dbm.map_or(signal, |old: i8| old.max(signal)));
            }
        }
    } else if r1 & (1 << 15) != 0 {
        return None;
    }
    offset += 2 * ((r2 >> 14) & 3) as usize;
    let frame = packet.get(offset..)?;
    if cipher != 0 && frame.get(1)? & 0x40 == 0 {
        return None;
    }
    Some(Raw {
        frame,
        channel,
        band,
        wcid: (r1 & 0x3ff) as u16,
        tid: ((r2 >> 16) & 15) as u8,
        fragment: r2 & (1 << 27) != 0,
        signal_dbm,
    })
}
