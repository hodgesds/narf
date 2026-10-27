// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822CE PCI legacy packet formats, from Linux rtw88/{pci,tx,rx,fw}.
//! Parsing supplies no DMA, channel, peer, key or controlled-port authority.
use alloc::vec::Vec;
use core::ops::Range;

pub(super) const TX_DESC: usize = 48;
pub(super) const TX_BD: usize = 16;
pub(super) const RX_DESC: usize = 24;
pub(super) const RX_BD: usize = 8;
pub(super) const MAX_MPDU: usize = 2304;
pub(super) const MAX_HT_RX: usize = 26 + 16 + narf_wireless::amsdu::MAX_BYTES;
pub(super) const RX_BYTES: usize = 11454 + RX_DESC;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Aggregation {
    pub density: u8,
    pub count: u8,
    pub bytes: u16,
    pub airtime: u16,
}
impl Aggregation {
    pub(super) fn valid(self) -> bool {
        self.density <= 7
            && (1..=4).contains(&self.count)
            && (1560..=8191).contains(&self.bytes)
            && (2500..=4000).contains(&self.airtime)
    }
    /// Conservative complete HT20/1SS BCC PPDU bound. Include delimiter,
    /// hardware FCS, pad-to4, mixed preamble and density allowance. LGI bounds
    /// either negotiated GI; no firmware aggregate length or ACK is inferred.
    pub(super) fn admits(self, profile: DataProfile, frames: &[Vec<u8>]) -> bool {
        self.admits_lengths(profile, frames.iter().map(Vec::len))
    }
    pub(super) fn admits_lengths(
        self,
        profile: DataProfile,
        frames: impl ExactSizeIterator<Item = usize>,
    ) -> bool {
        const NDBPS: [usize; 8] = [26, 52, 78, 104, 156, 208, 234, 260];
        if !self.valid()
            || !profile.valid()
            || profile.mcs == 0
            || frames.len() == 0
            || frames.len() > usize::from(self.count)
        {
            return false;
        }
        let count = frames.len();
        let bytes = frames.into_iter().try_fold(0usize, |sum, length| {
            let aligned = length.checked_add(7)? & !3;
            sum.checked_add(4)?.checked_add(aligned)
        });
        let Some(bytes) = bytes else {
            return false;
        };
        if bytes > usize::from(self.bytes) {
            return false;
        }
        let symbols = (16 + bytes * 8 + 6).div_ceil(NDBPS[usize::from(profile.rate() - 12)]);
        bytes <= usize::from(self.bytes)
            && 36 + symbols * 4 + count * 16 <= usize::from(self.airtime)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Frame,
    Address,
    Metadata,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Queue {
    Management,
    Data,
}
impl Queue {
    pub(super) fn index(self) -> u16 {
        match self {
            Self::Management => 0x3b0,
            Self::Data => 0x3a8,
        }
    }
    pub(super) fn depth(self) -> usize {
        match self {
            Self::Management => 128,
            Self::Data => 256,
        }
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn unicast(address: &[u8]) -> bool {
    address.len() == 6 && address != [0; 6] && address[0] & 1 == 0
}
pub(super) fn classify(frame: &[u8], own: [u8; 6]) -> Result<Queue, Error> {
    classify_profile(frame, own, DataProfile::LEGACY)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DataProfile {
    pub rates: u16,
    pub qos: bool,
    pub mcs: u8,
    pub sgi: bool,
}
impl DataProfile {
    pub(super) const LEGACY: Self = Self {
        rates: 1,
        qos: false,
        mcs: 0,
        sgi: false,
    };
    pub(super) fn valid(self) -> bool {
        self.rates != 0
            && self.rates & !0xfff == 0
            && (self.mcs == 0 && !self.sgi || self.mcs != 0 && self.qos)
    }
    pub(super) fn rate_id(self) -> u8 {
        if self.mcs != 0 {
            return if self.rates & 15 == 0 { 5 } else { 3 };
        }
        if self.rates & 0xff0 == 0 {
            8
        } else if self.rates & 15 == 0 {
            7
        } else {
            6
        }
    }
    pub(super) fn rate(self) -> u8 {
        if self.mcs != 0 {
            return 12 + (7 - self.mcs.leading_zeros() as u8);
        }
        const KBPS: [u32; 12] = [
            1000, 2000, 5500, 11000, 6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000,
        ];
        KBPS.iter()
            .enumerate()
            .filter(|(i, _)| self.rates & (1 << i) != 0)
            .max_by_key(|(_, r)| **r)
            .map_or(0, |(i, _)| i as u8)
    }
    pub(super) fn response_mask(self) -> u32 {
        let rate = self.rate();
        let mut order = if rate >= 12 {
            rate - 12
        } else if rate >= 4 {
            rate - 4
        } else {
            rate
        };
        if rate >= 12 || order == 0 {
            order += 1;
        }
        ((1u32 << (u32::from(order) + 4)) - 1) & 0x15f
    }
}
fn classify_profile(frame: &[u8], own: [u8; 6], profile: DataProfile) -> Result<Queue, Error> {
    if !profile.valid() {
        return Err(Error::Metadata);
    }
    if profile.mcs != 0 && native_bar(frame) && frame[10..16] == own && frame[17] >> 4 == 0 {
        return Ok(Queue::Management);
    }
    if !(24..=MAX_MPDU).contains(&frame.len())
        || !unicast(&own)
        || frame[10..16] != own
        || frame[0] & 3 != 0
        || frame[1] & (4 | 16 | 32 | 128) != 0
        || frame[22] & 15 != 0
    {
        return Err(Error::Frame);
    }
    match frame[0] {
        // Management stays legacy. The separate qualified branch below may
        // admit only BE/TID0 QoS, without aggregation or fragmentation.
        0x00 | 0xb0 | 0xa0 | 0xc0 if frame[1] & (3 | 64) == 0 => Ok(Queue::Management),
        // mac80211 software-scan Probe Request: broadcast DA (W0 BMC) and
        // wildcard BSSID only; the caller requests no CCX report.
        0x40 if frame[1] == 0 && frame[4..10] == [255; 6] && frame[16..22] == [255; 6] => {
            Ok(Queue::Management)
        }
        0xd0 if profile.mcs != 0
            && frame.len() == 33
            && frame[1] == 0
            && frame[24..26] == [3, 1]
            && frame[27..29] == [37, 0] =>
        {
            Ok(Queue::Management)
        }
        0xd0 if profile.mcs != 0 && recipient_control(frame) => Ok(Queue::Management),
        0xd0 if profile.mcs != 0 && originator_control(frame) => Ok(Queue::Management),
        0x08 if frame[1] & 3 == 1 && unicast(&frame[4..10]) => Ok(Queue::Data),
        0x88 if profile.qos
            && frame.len() >= 26
            && frame[24..26] == [0, 0]
            && frame[1] & 3 == 1
            && unicast(&frame[4..10]) =>
        {
            Ok(Queue::Data)
        }
        _ => Err(Error::Frame),
    }
}
pub(super) fn originator_control(b: &[u8]) -> bool {
    if native_bar(b) {
        return b[17] >> 4 == 0;
    }
    if b.len() < 30 || b[..2] != [0xd0, 0] || b[24] != 3 {
        return false;
    }
    match (b.len(), b[25]) {
        (33, 0) => {
            let p = u16::from_le_bytes([b[27], b[28]]);
            p & 0x3f == 2 && (1..=64).contains(&(p >> 6)) && b[31] & 15 == 0
        }
        (30, 2) => b[26..30] == [0, 8, 39, 0],
        _ => false,
    }
}
/// Newly emitting recipient control is separately qualified by the retained
/// native Port, beyond the H data profile that only permits status37 decline.
pub(super) fn recipient_control(b: &[u8]) -> bool {
    if b.len() < 30 || b[..2] != [0xd0, 0] || b[24] != 3 {
        return false;
    }
    match (b.len(), b[25]) {
        (33, 1) => {
            let p = u16::from_le_bytes([b[29], b[30]]);
            b[27..29] == [0, 0] && p & 3 == 3 && (p >> 2) & 15 < 8 && (1..=64).contains(&(p >> 6))
        }
        (30, 2) => {
            let p = u16::from_le_bytes([b[26], b[27]]);
            p & 0xfff == 0 && p >> 12 < 8 && b[28..30] == [39, 0]
        }
        _ => false,
    }
}
pub(super) fn native_bar(b: &[u8]) -> bool {
    b.len() == 20
        && b[..2] == [0x84, 0]
        && unicast(&b[4..10])
        && unicast(&b[10..16])
        && u16::from_le_bytes([b[16], b[17]]) & 0xfff == 4
        && b[17] >> 4 < 8
        && b[18] & 15 == 0
}
/// Source PCI descriptors have no host checksum callback. Both PCI BD
/// segments refer to this one retained contiguous descriptor/body allocation.
pub(super) fn transmit(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    report: Option<u8>,
) -> Result<([u8; TX_DESC], Queue), Error> {
    transmit_profile(frame, own, mac_id, report, DataProfile::LEGACY)
}
pub(super) fn transmit_profile(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    report: Option<u8>,
    profile: DataProfile,
) -> Result<([u8; TX_DESC], Queue), Error> {
    let queue = classify_profile(frame, own, profile)?;
    if mac_id > 127 || report.is_some_and(|sequence| sequence & 3 != 0) {
        return Err(Error::Metadata);
    }
    let mut bytes = [0; TX_DESC];
    put(
        &mut bytes,
        0,
        frame.len() as u32
            | (TX_DESC as u32) << 16
            | u32::from(frame[4] & 1 != 0) << 24
            | 1 << 26
            | 1 << 31,
    );
    let qsel = match queue {
        Queue::Management => 18,
        Queue::Data => 0,
    };
    let ordinary = queue == Queue::Data && (report.is_none() || frame[0] == 0x88);
    if frame[0] == 0x88 && !ordinary {
        return Err(Error::Frame);
    }
    let rate_id = if ordinary { profile.rate_id() } else { 8 };
    // Source fixed-rate/no-fallback; management/EAPOL remain CCK1. QoS comes
    // from the actual26-byte frame, with TID0 selecting the same BE queue.
    put(
        &mut bytes,
        4,
        u32::from(mac_id) | qsel << 8 | u32::from(rate_id) << 16,
    );
    put(&mut bytes, 8, u32::from(report.is_some()) << 19);
    put(&mut bytes, 12, 1 << 8 | 1 << 10);
    put(
        &mut bytes,
        16,
        if ordinary {
            u32::from(profile.rate())
        } else {
            0
        },
    );
    put(&mut bytes, 24, u32::from(report.unwrap_or(0)));
    if ordinary && profile.mcs != 0 {
        put(&mut bytes, 20, u32::from(profile.sgi) << 4);
    }
    let sequence = if frame.len() == 20 {
        0
    } else {
        u16::from_le_bytes([frame[22], frame[23]]) >> 4
    };
    put(&mut bytes, 36, u32::from(sequence) << 12);
    Ok((bytes, queue))
}
pub(super) fn buffer_descriptor(address: u64, length: usize) -> Result<[u8; TX_BD], Error> {
    let extent = TX_DESC.checked_add(length).ok_or(Error::Address)?;
    if (!(24..=MAX_MPDU).contains(&length) && length != 20)
        || address == 0
        || address & 3 != 0
        || address
            .checked_add(extent as u64 - 1)
            .is_none_or(|last| last > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    let mut bytes = [0; TX_BD];
    put(
        &mut bytes,
        0,
        TX_DESC as u32 | (extent.div_ceil(128) as u32) << 16,
    );
    put(&mut bytes, 4, address as u32);
    put(&mut bytes, 8, length as u32);
    put(&mut bytes, 12, address as u32 + TX_DESC as u32);
    Ok(bytes)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Receive {
    /// Includes FCS for native Wi-Fi, exactly the control body for C2H.
    pub(super) payload: Range<usize>,
    pub(super) c2h: bool,
    pub(super) rate: u8,
}
pub(super) fn receive(descriptor: &[u8; RX_DESC]) -> Result<Receive, Error> {
    receive_profile(descriptor, false)
}
/// Call only after successful descriptor admission. Linux rx.c places the
/// single status record before driver-info bytes, after native shift bytes.
pub(super) fn phy_status(descriptor: &[u8; RX_DESC]) -> Option<Range<usize>> {
    if word(descriptor, 0) & (1 << 26) == 0 || word(descriptor, 8) & (1 << 28) != 0 {
        return None;
    }
    let start = RX_DESC + ((word(descriptor, 0) >> 24) & 3) as usize;
    Some(start..start + 32)
}
pub(super) fn receive_profile(descriptor: &[u8; RX_DESC], ht: bool) -> Result<Receive, Error> {
    let first = word(descriptor, 0);
    let length = (first & 0x3fff) as usize;
    let info = ((first >> 16) & 15) as usize;
    let shift = ((first >> 24) & 3) as usize;
    let c2h = word(descriptor, 8) & (1 << 28) != 0;
    let rate = (word(descriptor, 12) & 127) as u8;
    // Native driver allows exactly PHY_STATUS_SIZE (4) eight-byte blocks.
    if length == 0
        || info != 0 && info != 4
        || first & (1 << 26) != 0 && info == 0
        || first & (3 << 14) != 0
    {
        return Err(Error::Metadata);
    }
    if c2h {
        if length > 512 {
            return Err(Error::Metadata);
        }
    } else {
        let encryption = (first >> 20) & 7;
        let software = first & (1 << 27) != 0;
        if !(if ht { 24 } else { 28 }..=if ht { MAX_HT_RX + 4 } else { MAX_MPDU + 4 })
            .contains(&length)
            || rate >= if ht { 20 } else { 12 }
            || word(descriptor, 16) & 0x30 != 0
            || encryption != 0 && !(encryption == 4 && software)
        {
            return Err(Error::Metadata);
        }
    }
    let start = RX_DESC + info * 8 + shift;
    let end = start.checked_add(length).ok_or(Error::Metadata)?;
    if end > RX_BYTES {
        return Err(Error::Metadata);
    }
    Ok(Receive {
        payload: start..end,
        c2h,
        rate,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Report {
    pub(super) sequence: u8,
    pub(super) acknowledged: bool,
}
/// CCX is the firmware's radio result. A PCI TXBD read pointer alone is only
/// host-buffer consumption and cannot commit a WPA2 terminal reply.
pub(super) fn report(body: &[u8]) -> Result<Option<Report>, Error> {
    let payload = body.get(2..).ok_or(Error::Metadata)?;
    let (sequence, status) = match body[0] {
        0x03 => (*payload.get(6).ok_or(Error::Metadata)?, payload[0]),
        0xff => match *payload.first().ok_or(Error::Metadata)? {
            0x0f => (
                *payload.get(8).ok_or(Error::Metadata)?,
                *payload.get(9).ok_or(Error::Metadata)?,
            ),
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    Ok(Some(Report {
        sequence: sequence & 0xfc,
        acknowledged: status & 0xc0 == 0,
    }))
}

#[cfg(feature = "kernel-test")]
#[path = "packet_format/tests.rs"]
mod tests;
