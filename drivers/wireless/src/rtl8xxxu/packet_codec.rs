// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EU native MPDU/descriptor framing, from Linux rtl8xxxu/{core.c,rtl8xxxu.h}.
//! The rxdesc16 name is a generation identifier: its physical size is 24,
//! including DW4 and TSFL. Packet aggregation uses 128-byte record alignment.
use alloc::vec::Vec;

pub const RX_DESC: usize = 24;
pub const TX_DESC: usize = 32;
pub const MAX_TRANSFER: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Header,
    Descriptor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Management,
    Data,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mpdu {
    pub bytes: Vec<u8>,
    pub phy: Vec<u8>,
    pub rate: u8,
    pub ht: bool,
    pub bandwidth40: bool,
    pub tid: u8,
    pub decrypted: bool,
    pub timestamp: u32,
    pub(super) native: Option<[u32; 4]>,
}
impl Mpdu {
    /// Native rxdesc16 is authoritative for encoding/width. Its old PHY block
    /// contains SGI/RXSC, not a C21/C22 page or an independently reported channel.
    pub(super) fn admitted(&self, ht_profile: bool) -> bool {
        if self.decrypted || self.bandwidth40 {
            return false;
        }
        if let Some([d0, d1, d2, d3]) = self.native {
            if d1 & ((1 << 14) | (1 << 15) | (1 << 27)) != 0 || d2 & 0xf000 != 0 {
                return false;
            }
            let qos = self.bytes.first() == Some(&0x88);
            if qos != (d0 & (1 << 23) != 0) || d3 & ((1 << 10) | (1 << 11)) != 0 {
                return false;
            }
            if qos {
                let Some(q) = self.bytes.get(24..26) else {
                    return false;
                };
                if q[0] & 15 != self.tid
                    || q[0] & 0x70 != 0
                    || q[1] != 0
                    || (q[0] & 0x80 != 0) != (d1 & (1 << 13) != 0)
                {
                    return false;
                }
            } else if d1 & (1 << 13) != 0 {
                return false;
            }
        }
        if !self.ht {
            return self.rate <= 11;
        }
        if !ht_profile || !(12..=19).contains(&self.rate) {
            return false;
        }
        let Some([d0, d1, d2, d3]) = self.native else {
            return false;
        };
        if d3 & 0xf80 != 0 || d1 & ((1 << 14) | (1 << 15) | (1 << 27)) != 0 || d2 & 0xf000 != 0 {
            return false;
        }
        if (d0 & (1 << 26) != 0) == self.phy.is_empty()
            || !self.phy.is_empty() && (self.phy.len() != 32 || self.phy[27] & 0x0e != 0)
        {
            return false;
        }
        let b = &self.bytes;
        if b.len() < 24 || b[22] & 15 != 0 || b[1] & 4 != 0 {
            return false;
        }
        true
    }
}
impl narf_wireless::station_security::RawFrame for Mpdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        self.admitted(true)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Frame(Mpdu),
    Report { kind: u8, bytes: Vec<u8> },
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Parse one completed bulk transfer. Bad CRC/ICV frames are dropped, reports
/// never enter native 802.11 dispatch, and all descriptor extents are checked
/// before a callback can see bytes. The enclosing transport is single-channel.
pub fn receive(bytes: &[u8]) -> Result<Vec<Record>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_TRANSFER || bytes.len() < RX_DESC {
        return Err(Error::Length);
    }
    let first_count = ((word(bytes, 8) >> 16) & 255) as usize;
    // RX aggregation is disabled at init. Some single-packet descriptors
    // leave pkt_cnt zero; Linux still consumes the first record.
    let count = first_count.max(1);
    if count > MAX_TRANSFER / RX_DESC {
        return Err(Error::Descriptor);
    }
    let mut records = Vec::new();
    let mut at = 0;
    for index in 0..count {
        let desc = bytes.get(at..at + RX_DESC).ok_or(Error::Length)?;
        let d0 = word(desc, 0);
        let d1 = word(desc, 4);
        let d3 = word(desc, 12);
        let length = (d0 & 0x3fff) as usize;
        let info = ((d0 >> 16) & 15) as usize * 8;
        let shift = ((d0 >> 24) & 3) as usize;
        let start = at + RX_DESC + info + shift;
        let end = start.checked_add(length).ok_or(Error::Length)?;
        let body = bytes.get(start..end).ok_or(Error::Length)?;
        let report = ((d3 >> 14) & 3) as u8;
        if length == 0 {
            return Err(Error::Descriptor);
        }
        if report != 0 {
            // Reports carry no MPDU and cannot be interpreted as Ethernet,
            // EAPOL or association responses, even when their bytes resemble it.
            records.push(Record::Report {
                kind: report,
                // Linux queues the bytes immediately after rxdesc16 for
                // report handling; drvinfo/shift removal is MPDU-only.
                bytes: bytes[at + RX_DESC..end].to_vec(),
            });
        } else if d0 & ((1 << 14) | (1 << 15)) == 0 {
            // No multi-descriptor reassembly is enabled in this profile.
            if d0 & ((1 << 28) | (1 << 29)) != ((1 << 28) | (1 << 29)) || length < 10 {
                return Err(Error::Descriptor);
            }
            records.push(Record::Frame(Mpdu {
                bytes: body.to_vec(),
                phy: if d0 & (1 << 26) != 0 {
                    bytes[at + RX_DESC..at + RX_DESC + info].to_vec()
                } else {
                    Vec::new()
                },
                rate: (d3 & 63) as u8,
                ht: d3 & (1 << 6) != 0,
                bandwidth40: d3 & (1 << 9) != 0,
                tid: ((d1 >> 5) & 15) as u8,
                decrypted: d0 & (1 << 27) == 0 && d0 & (7 << 20) != 0,
                timestamp: word(desc, 20),
                native: Some([d0, d1, word(desc, 8), d3]),
            }));
        }
        if index + 1 < count {
            at = at + (end - at).next_multiple_of(128);
        } else if bytes.len() - end >= 128 {
            return Err(Error::Descriptor);
        }
    }
    Ok(records)
}

/// Native legacy 1Mbps, no hardware cipher and no aggregation. The station
/// admission policy must require a 2.4GHz/20MHz AP supporting the 1Mbps rate.
/// USB completion only acknowledges host delivery, not an on-air radio ACK.
pub fn transmit(frame: &[u8], kind: Kind) -> Result<Vec<u8>, Error> {
    transmit_rate(frame, kind, 0)
}
pub(super) fn transmit_rate(frame: &[u8], kind: Kind, rate: u8) -> Result<Vec<u8>, Error> {
    if rate > 19 || kind == Kind::Management && rate != 0 {
        return Err(Error::Header);
    }
    if frame.len() < 24 || frame.len() > MAX_TRANSFER - TX_DESC {
        return Err(Error::Length);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 3 != 0 || frame[22] & 15 != 0 || fc & 0x0400 != 0 {
        return Err(Error::Header);
    }
    let management = fc & 0x0c == 0;
    match kind {
        Kind::Management
            if !management
                || fc & 0x0300 != 0
                || !matches!(frame[0], 0x00 | 0x20 | 0xa0 | 0xb0 | 0xc0 | 0xd0) =>
        {
            return Err(Error::Header)
        }
        Kind::Data
            if !matches!(frame[0], 0x08 | 0x88)
                || frame[1] & 3 != 1
                || frame[0] == 0x88
                    && !matches!(frame.get(24..26), Some(&[tid, 0]) if tid & 0xf8 == 0) =>
        {
            return Err(Error::Header)
        }
        _ => (),
    }
    let mut out = alloc::vec![0;TX_DESC+frame.len()];
    out[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    out[2] = TX_DESC as u8;
    // Linux tests native DA (A3 for ToDS), not the AP receiver address.
    let destination = if fc & 0x0300 == 0x0100 {
        frame[16]
    } else {
        frame[4]
    };
    out[3] = 0x8c | destination & 1;
    // rtl8xxxu_queue_select: MGNT0x12, else the AC's TXDESC_QUEUE_*.
    let queue = if management {
        0x12
    } else {
        access_category(data_tid(frame)).0
    };
    out[4..8].copy_from_slice(&(u32::from(queue) << 8).to_le_bytes());
    out[8..12].copy_from_slice(&(1u32 << 16 | 1 << 24 | 1 << 25).to_le_bytes());
    out[12..16].copy_from_slice(
        &(u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4) << 16).to_le_bytes(),
    );
    out[16..20].copy_from_slice(
        &((1u32 << 8)
            | if rate >= 12 { 1 << 10 } else { 0 }
            | if frame[0] == 0x88 { 1 << 6 } else { 0 })
        .to_le_bytes(),
    ); // USE_DRIVER_RATE/DISABLE_DATA_FB/QOS
    out[20..24].copy_from_slice(
        &(if management {
            6u32 << 18 | 1 << 17
        } else {
            0x0001ff00 | u32::from(rate)
        })
        .to_le_bytes(),
    );
    out[30..32].copy_from_slice(&(1u16 << 13).to_le_bytes()); // ANTENNA_SELECT_C
    let checksum = out[..TX_DESC]
        .chunks_exact(2)
        .fold(0u16, |v, b| v ^ u16::from_le_bytes([b[0], b[1]]));
    out[28..30].copy_from_slice(&checksum.to_le_bytes());
    out[TX_DESC..].copy_from_slice(frame);
    Ok(out)
}

/// QoS TID of a DATA frame; non-QoS DATA uses mac80211's BE priority0.
pub(super) fn data_tid(frame: &[u8]) -> u8 {
    if frame.first() == Some(&0x88) {
        frame.get(24).map_or(0, |q| q & 7)
    } else {
        0
    }
}
/// Linux `ieee802_1d_to_ac` then `rtl8xxxu_80211_to_rtl_queue`: the
/// TXDESC_QUEUE_{BK2,BE0,VI5,VO7} selector and the
/// `rtl8xxxu_init_queue_priority` pipe class (0 VO, 1 VI, 2 BE/BK).
pub(super) const fn access_category(tid: u8) -> (u8, u8) {
    match tid & 7 {
        1 | 2 => (2, 2),
        4 | 5 => (5, 1),
        6 | 7 => (7, 0),
        _ => (0, 2),
    }
}
/// `rtl8xxxu_init_queue_priority` bulk-out index for a DATA pipe class and
/// `ep_tx_count`. One endpoint carries everything; two put VO/VI on
/// out_ep[0] and BE/BK on out_ep[1]; three put BE/BK on out_ep[2] and VI on
/// out_ep[1]. Upstream derives three-endpoint `vop` from `viq ^ 3`, so VO
/// shares VI's out_ep[1] even though TRXDMA_CTRL maps VOQ to HIGH.
pub(super) const fn data_endpoint(class: u8, count: u8) -> usize {
    match (count, class) {
        (2, 0 | 1) => 0,
        (2, _) => 1,
        (3, 0 | 1) => 1,
        (3, _) => 2,
        _ => 0,
    }
}
