//! Native control-device management bytes, independent of AP/station roles.
//! Linux mt76_connac_mac.c410..622 / mt76_connac2_mac.h OWN_MAC and TXP.
//! This codec creates no started wdev, CNM, RF, capture, key or port grant.
use crate::mt7921::{association::LegacyRate, firmware_transport::Error, vif_slots::Vif};

#[derive(Clone, Copy, Debug)]
pub(super) struct Header {
    pub tid: u8,
    pub subtype: u8,
    pub multicast: bool,
    pub add_ba: bool,
}
impl Header {
    pub fn prepare(frame: &[u8], local: [u8; 6]) -> Result<Self, Error> {
        if !(24..=4032).contains(&frame.len())
            || local == [0; 6]
            || local[0] & 1 != 0
            || frame[0] & 15 != 0
            || frame[1] & 0xc7 != 0
            || frame[22] & 15 != 0
            || frame[4..10] == [0; 6]
            || frame[10..16] != local
            || frame[16..22] == [0; 6]
        {
            return Err(Error::Bounds);
        }
        let subtype = frame[0] >> 4;
        if !matches!(subtype, 0 | 1 | 2 | 3 | 4 | 5 | 8 | 9 | 10 | 11 | 12 | 13) {
            return Err(Error::Bounds);
        }
        let add_ba = subtype == 13 && frame.len() >= 33 && frame[24..26] == [3, 0];
        let tid = if add_ba {
            ((u16::from_le_bytes([frame[27], frame[28]]) >> 2) & 15) as u8
        } else {
            0
        };
        if tid >= 8 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            tid,
            subtype,
            multicast: frame[4] & 1 != 0,
            add_ba,
        })
    }
}
/// Cut-through 802.11 header on the actual allocated VIF/OMAC/BMC. The
/// header's Protected bit never selects a hardware key: this device is
/// unkeyed. Neither manual SN nor data header translation is selected.
pub(super) fn descriptor(
    frame: &[u8],
    payload: u64,
    token: u16,
    vif: Vif,
    rate: LegacyRate,
    no_ack: bool,
) -> Result<[u8; 64], Error> {
    let local = frame
        .get(10..16)
        .ok_or(Error::Bounds)?
        .try_into()
        .map_err(|_| Error::Bounds)?;
    let header = Header::prepare(frame, local)?;
    if token == 0 || token >= 8192 {
        return Err(Error::Bounds);
    }
    if payload
        .checked_add(frame.len() as u64 - 1)
        .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::DmaAddress);
    }
    let words = [
        (frame.len() as u32 + 32) | (0x10 << 25),
        1 << 31
            | u32::from(vif.index()) << 24
            | u32::from(header.tid) << 20
            | 2 << 16
            | 12 << 11
            | u32::from(vif.bmc()),
        1 << 31 | 1 << 13 | u32::from(header.multicast) << 10 | u32::from(header.subtype),
        1 << 28 | 15 << 11 | u32::from(header.multicast || no_ack),
        0,
        u32::from(header.add_ba) << 14,
        4 | u32::from(rate.hardware()) << 16,
        u32::from(header.subtype) << 16,
    ];
    let mut out = [0; 64];
    for (i, word) in words.into_iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out[32..34].copy_from_slice(&(token | 0x8000).to_le_bytes());
    out[40..44].copy_from_slice(&(payload as u32).to_le_bytes());
    out[44..46].copy_from_slice(&((frame.len() as u16) | 0x8000).to_le_bytes());
    Ok(out)
}
