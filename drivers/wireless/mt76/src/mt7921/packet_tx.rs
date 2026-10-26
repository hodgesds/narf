//! CONNAC2 cut-through management TX and two-phase token retirement.
//! Linux ecd997b0189a: mt76_connac_mac.c, mt7921/{pci_mac,mac}.c.
use super::firmware_transport::Error;
use alloc::vec::Vec;

pub(super) const HEADER: usize = 64; // 32-byte TXD + 32-byte hardware TXP.
const TOKEN_LIMIT: u16 = 8192; // Linux MT7921_TOKEN_SIZE; zero is unused here.

/// Encode an unencrypted native frame at the selected AP basic rate.
/// Publication remains private to the hardware backend until association
/// supplies verified channel/power permission. This is not an injection API.
pub(super) fn management(
    frame: &[u8],
    payload: u64,
    token: u16,
    wcid: u16,
    rate: crate::mt7921::association::LegacyRate,
) -> Result<[u8; HEADER], Error> {
    if !(24..=4032).contains(&frame.len()) {
        return Err(Error::Bounds);
    }
    if payload
        .checked_add(frame.len() as u64 - 1)
        .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::DmaAddress);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let is_data = (fc & 0x0f == 0x08) && ((fc >> 4) & 15 == 0);
    let is_mgmt = (fc & 0x0f == 0x00) && matches!((fc >> 4) & 15, 0 | 2 | 4 | 10 | 11 | 12 | 13);
    if (!is_data && !is_mgmt) || token == 0 || token >= TOKEN_LIMIT || wcid >= 20 {
        return Err(Error::Bounds);
    }
    let subtype = u32::from((fc >> 4) & 15);
    let multicast = frame[4] & 1 != 0;
    let words = [
        (frame.len() as u32 + 32) | (0x10 << 25), // CT, LMAC ALTX0.
        (1 << 31) | (2 << 16) | (12 << 11) | u32::from(wcid),
        (1 << 31)
            | (1 << 13)
            | (u32::from(multicast) << 10)
            | subtype
            | if is_data { 2 << 4 } else { 0 },
        (1 << 28) | (15 << 11) | u32::from(multicast),
        0,
        0,
        4 | (u32::from(rate.hardware()) << 16),
        (if is_data { 2 << 20 } else { 0 }) | (subtype << 16),
    ];
    let mut bytes = [0; HEADER];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes[32..34].copy_from_slice(&(token | 0x8000).to_le_bytes());
    bytes[40..44].copy_from_slice(&(payload as u32).to_le_bytes());
    bytes[44..46].copy_from_slice(&((frame.len() as u16) | 0x8000).to_le_bytes());
    Ok(bytes)
}

/// Encode an 802.3 Ethernet frame for transmission on the WFDMA data queue.
pub(super) fn ethernet(
    frame: &[u8],
    payload: u64,
    token: u16,
    wcid: u16,
    protected: bool,
) -> Result<[u8; HEADER], Error> {
    ethernet_qos(frame, payload, token, wcid, protected, false)
}

/// The retained WMM profile maps every Ethernet frame to BE/TID 0.
/// Linux mt76_connac2_mac_write_txwi_8023 supplies QoS subtype in both
/// TXD2/TXD7, while mt76_connac_lmac_mapping(IEEE80211_AC_BE) is queue 1.
pub(super) fn ethernet_qos(
    frame: &[u8],
    payload: u64,
    token: u16,
    wcid: u16,
    protected: bool,
    qos: bool,
) -> Result<[u8; HEADER], Error> {
    if !(14..=1514).contains(&frame.len()) {
        return Err(Error::Bounds);
    }
    if payload
        .checked_add(frame.len() as u64 - 1)
        .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::DmaAddress);
    }
    if token == 0 || token >= TOKEN_LIMIT || wcid >= 20 {
        return Err(Error::Bounds);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype < 0x0600 {
        return Err(Error::Bounds);
    }
    let is_eth_802_3 = true;
    let words = [
        (frame.len() as u32 + 32) | (u32::from(qos) << 25),
        (1 << 31) | (u32::from(is_eth_802_3) << 15) | u32::from(wcid),
        (2 << 4) | if qos { 8 } else { 0 }, // DATA / QoS DATA; AP receiver is unicast.
        (1 << 28) | (15 << 11) | (u32::from(protected) << 1), // BA_DISABLE; installed PTK only.
        0,
        0,
        0,
        (2 << 20) | if qos { 8 << 16 } else { 0 },
    ];
    let mut bytes = [0; HEADER];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes[32..34].copy_from_slice(&(token | 0x8000).to_le_bytes());
    bytes[40..44].copy_from_slice(&(payload as u32).to_le_bytes());
    bytes[44..46].copy_from_slice(&((frame.len() as u16) | 0x8000).to_le_bytes());
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Completion {
    pub token: u16,
    pub status: u8,
}

/// Validate the whole variable-length release event before changing ownership.
pub(super) fn releases(bytes: &[u8]) -> Result<Vec<Completion>, Error> {
    if bytes.len() < 8 {
        return Err(Error::MalformedEvent);
    }
    let header = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let len = (header & 0xffff) as usize;
    if header >> 27 != 0 || len < 8 || len > bytes.len() || len > 4096 {
        return Err(Error::MalformedEvent);
    }
    let count = ((header >> 16) & 0x3ff) as usize;
    if count > (len - 8) / 4 {
        return Err(Error::MalformedEvent);
    }
    let mut records = Vec::with_capacity(count);
    let mut offset = 8;
    while records.len() < count {
        let value = bytes
            .get(offset..offset + 4)
            .filter(|_| offset + 4 <= len)
            .ok_or(Error::MalformedEvent)?;
        let value = u32::from_le_bytes(value.try_into().unwrap());
        offset += 4;
        if value & (1 << 31) != 0 {
            continue;
        } // WCID pair, not an MSDU.
        records.push(Completion {
            token: ((value >> 16) & 0x7fff) as u16,
            status: ((value >> 13) & 3) as u8,
        });
    }
    Ok(records)
}

#[derive(Debug)]
struct Pending {
    token: u16,
    dma: bool,
    firmware: Option<u8>,
}
/// A deliberately serialized first path: no slot reuse before BOTH proofs.
#[derive(Debug)]
pub(super) struct Tokens {
    next: u16,
    pending: Option<Pending>,
}
impl Tokens {
    pub fn new() -> Self {
        Self {
            next: 1,
            pending: None,
        }
    }
    pub fn available(&self) -> Result<u16, Error> {
        if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(self.next)
        }
    }
    pub fn begin(&mut self, token: u16) -> Result<(), Error> {
        if self.available()? != token {
            return Err(Error::Ring);
        }
        self.pending = Some(Pending {
            token,
            dma: false,
            firmware: None,
        });
        self.next = if token == TOKEN_LIMIT - 1 {
            1
        } else {
            token + 1
        };
        Ok(())
    }
    pub fn dma_done(&mut self) -> Result<(), Error> {
        self.pending.as_mut().ok_or(Error::Ring)?.dma = true;
        Ok(())
    }
    pub fn firmware_done(&mut self, records: &[Completion]) -> Result<(), Error> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        let mut status = pending.firmware;
        for record in records
            .iter()
            .filter(|record| record.token == pending.token)
        {
            if status.is_some_and(|old| old != record.status) {
                return Err(Error::MalformedEvent);
            }
            status = Some(record.status);
        }
        // Commit only after every matching record was validated.
        self.pending.as_mut().unwrap().firmware = status;
        Ok(())
    }
    pub fn finish(&mut self) -> Option<Completion> {
        let pending = self.pending.as_ref()?;
        if !pending.dma {
            return None;
        }
        let result = Completion {
            token: pending.token,
            status: pending.firmware?,
        };
        self.pending = None;
        Some(result)
    }
}
