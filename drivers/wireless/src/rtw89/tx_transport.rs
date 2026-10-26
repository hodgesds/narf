//! Bounded AX native TX ownership and PCI descriptor preparation.
//!
//! Linux `rtw89/pci.c::{rtw89_pci_txwd_submit,rtw89_pci_release_txwd_skb,
//! rtw89_pci_fill_txaddr_info,rtw89_pci_fill_txaddr_info_v1}`: consuming a
//! TX BD does not by itself release the packet. A matching RPQ release is
//! also required. This module never treats Ethernet bytes as native MPDUs.

use super::mac::ChipId;
use super::txrx::{encode_txwd, TxwdInfo};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    NoMemory,
    BadQueue,
    Full,
    BadIndex,
    StaleReport,
    ConflictingReport,
    BadFrame,
    BadDma,
    NotPublished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub slot: u16,
    pub sequence: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub sequence: u16,
    pub channel: u8,
    pub mac_id: u8,
    pub qsel: u8,
    pub status: u8,
}

struct Pending<T> {
    ticket: Ticket,
    mac_id: u8,
    qsel: u8,
    published: bool,
    dma_done: bool,
    status: Option<u8>,
    resource: Option<T>,
}

#[derive(Debug)]
pub struct Completion<T> {
    pub resource: T,
    pub status: u8,
}

pub struct TxQueue<T> {
    slots: Vec<Option<Pending<T>>>,
    channel: u8,
    wp: u16,
    rp: u16,
    next_sequence: u16,
}
impl<T> core::fmt::Debug for TxQueue<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89TxQueue")
            .field("channel", &self.channel)
            .field("depth", &self.slots.len())
            .field("wp", &self.wp)
            .field("rp", &self.rp)
            .finish()
    }
}
impl<T> TxQueue<T> {
    pub fn new(channel: u8, depth: u16) -> Result<Self, Error> {
        if channel >= 12 || !(2..=512).contains(&depth) {
            return Err(Error::BadQueue);
        }
        Ok(Self {
            slots: core::iter::repeat_with(|| None)
                .take(depth as usize)
                .collect(),
            channel,
            wp: 0,
            rp: 0,
            next_sequence: 0,
        })
    }
    pub fn write_pointer(&self) -> u16 {
        self.wp
    }
    pub fn is_full(&self) -> bool {
        (self.wp + 1) % self.slots.len() as u16 == self.rp || self.slots[self.wp as usize].is_some()
    }
    pub fn reserve(&mut self, resource: T, mac_id: u8, qsel: u8) -> Result<Ticket, (Error, T)> {
        if self.is_full() {
            return Err((Error::Full, resource));
        }
        if mac_id >= 128 || channel_for_qsel(qsel) != Ok(self.channel) {
            return Err((Error::BadFrame, resource));
        }
        // Never reuse an outstanding wire sequence, including on wrap.
        while self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.ticket.sequence == self.next_sequence)
        {
            self.next_sequence = (self.next_sequence + 1) & 0x7fff;
        }
        let ticket = Ticket {
            slot: self.wp,
            sequence: self.next_sequence,
        };
        self.next_sequence = (self.next_sequence + 1) & 0x7fff;
        self.slots[self.wp as usize] = Some(Pending {
            ticket,
            mac_id,
            qsel,
            published: false,
            dma_done: false,
            status: None,
            resource: Some(resource),
        });
        Ok(ticket)
    }
    pub fn reserved_mut(&mut self, ticket: Ticket) -> Result<&mut T, Error> {
        let entry = self
            .slots
            .get_mut(ticket.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::BadIndex)?;
        if entry.ticket != ticket || entry.published {
            return Err(Error::BadIndex);
        }
        entry.resource.as_mut().ok_or(Error::BadIndex)
    }
    pub fn publish(&mut self, ticket: Ticket) -> Result<(), Error> {
        let slot = self
            .slots
            .get_mut(ticket.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::BadIndex)?;
        if slot.ticket != ticket || slot.published || ticket.slot != self.wp {
            return Err(Error::BadIndex);
        }
        // Record retention before ringing a hardware doorbell.
        slot.published = true;
        self.wp = (self.wp + 1) % self.slots.len() as u16;
        Ok(())
    }
    pub fn abort(&mut self, ticket: Ticket) -> Result<T, Error> {
        let slot = self
            .slots
            .get(ticket.slot as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::BadIndex)?;
        if slot.ticket != ticket || slot.published {
            return Err(Error::BadIndex);
        }
        Ok(self.slots[ticket.slot as usize]
            .take()
            .unwrap()
            .resource
            .take()
            .unwrap())
    }
    fn retire(&mut self, index: usize) -> Option<Completion<T>> {
        let entry = self.slots[index].as_ref()?;
        if !entry.dma_done || entry.status.is_none() {
            return None;
        }
        let mut entry = self.slots[index].take()?;
        Some(Completion {
            resource: entry.resource.take()?,
            status: entry.status?,
        })
    }
    pub fn observe_read_pointer(&mut self, next: u16) -> Result<Vec<Completion<T>>, Error> {
        let depth = self.slots.len() as u16;
        if next >= depth {
            return Err(Error::BadIndex);
        }
        let advance = (next + depth - self.rp) % depth;
        let outstanding = (self.wp + depth - self.rp) % depth;
        if advance > outstanding {
            return Err(Error::BadIndex);
        }
        // Validate the entire update before mutating any ownership state.
        for offset in 0..advance {
            let index = ((self.rp + offset) % depth) as usize;
            if !self.slots[index]
                .as_ref()
                .is_some_and(|entry| entry.published && !entry.dma_done)
            {
                return Err(Error::BadIndex);
            }
        }
        let mut completed = Vec::new();
        for offset in 0..advance {
            let index = ((self.rp + offset) % depth) as usize;
            self.slots[index].as_mut().unwrap().dma_done = true;
            if let Some(done) = self.retire(index) {
                completed.push(done);
            }
        }
        self.rp = next;
        Ok(completed)
    }
    pub fn observe_report(&mut self, report: Report) -> Result<Option<Completion<T>>, Error> {
        if report.channel != self.channel || report.status > 3 {
            return Err(Error::StaleReport);
        }
        let index = self
            .slots
            .iter()
            .position(|entry| {
                entry.as_ref().is_some_and(|entry| {
                    entry.ticket.sequence == report.sequence
                        && entry.mac_id == report.mac_id
                        && entry.qsel == report.qsel
                })
            })
            .ok_or(Error::StaleReport)?;
        let entry = self.slots[index].as_mut().unwrap();
        if !entry.published {
            return Err(Error::NotPublished);
        }
        if entry.status.is_some_and(|old| old != report.status) {
            return Err(Error::ConflictingReport);
        }
        entry.status = Some(report.status);
        Ok(self.retire(index))
    }
}
impl<T> Drop for TxQueue<T> {
    fn drop(&mut self) {
        for entry in self.slots.iter_mut().flatten() {
            if entry.published {
                // No quiesce proof is available in Drop. Retain at most one
                // packet per configured slot until a future reset owner can
                // prove both DMA and firmware have stopped referencing it.
                if let Some(resource) = entry.resource.take() {
                    core::mem::forget(resource);
                }
            }
        }
    }
}

/// PCIe AX QSEL mapping from Linux `rtw89_core_get_ch_dma`. The four
/// per-TID groups share AC channels; they do not select channels 4..7.
fn channel_for_qsel(qsel: u8) -> Result<u8, Error> {
    match qsel {
        0..=15 => Ok(qsel % 4),
        0x12 => Ok(8),
        0x11 => Ok(9),
        0x1a => Ok(10),
        0x19 => Ok(11),
        _ => Err(Error::BadQueue),
    }
}

/// Decode an AX four-byte RPQ record (including 8852C). BE's eight-byte
/// record is intentionally unsupported.
pub fn parse_report(bytes: &[u8]) -> Result<Report, Error> {
    let word = u32::from_le_bytes(bytes.try_into().map_err(|_| Error::BadFrame)?);
    if word & (1 << 31) != 0 {
        return Err(Error::StaleReport);
    }
    let qsel = ((word >> 8) & 0x1f) as u8;
    let channel = channel_for_qsel(qsel)?;
    let status = ((word >> 13) & 7) as u8;
    if status > 3 {
        return Err(Error::StaleReport);
    }
    Ok(Report {
        sequence: ((word >> 16) & 0x7fff) as u16,
        channel,
        mac_id: word as u8,
        qsel,
        status,
    })
}

/// Prepare the complete native PCI TXWD + WP sequence + address-info header.
/// The BD references only this header; address info references a separately
/// bounded frame extent, not Ethernet data immediately following TXWD.
pub fn prepare_header(
    chip: ChipId,
    info: TxwdInfo,
    sequence: u16,
    frame_dma: u64,
    frame: &[u8],
) -> Result<Vec<u8>, Error> {
    if chip == ChipId::Rtl8922A {
        return Err(Error::BadQueue);
    }
    if sequence > 0x7fff
        || info.channel >= 12
        || info.mac_id >= 128
        || channel_for_qsel(info.qsel) != Ok(info.channel)
        || frame.len() < 24
        || frame.len() > 0x3fff
        || info.pkt_size as usize != frame.len()
        || frame[0] & 3 != 0
    {
        return Err(Error::BadFrame);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    // Initial transport profile: native management or ordinary non-QoS
    // three-address data, without fragmentation/HT-control extras. Only B's
    // retained ordinary station path admits already encrypted host CCMP.
    if !matches!(
        fc & 0x00fc,
        0x0000
            | 0x0010
            | 0x0020
            | 0x0030
            | 0x0040
            | 0x0050
            | 0x0080
            | 0x0090
            | 0x00a0
            | 0x00b0
            | 0x00c0
            | 0x00d0
            | 0x0008
            | 0x0088
    ) || fc & (0x8000 | 0x0400) != 0
        || fc & 0x0300 == 0x0300
        || frame[22] & 0xf != 0
    {
        return Err(Error::BadFrame);
    }
    if fc & 0x000c == 0 && fc & 0x0300 != 0 {
        return Err(Error::BadFrame);
    }
    let header_length = if fc & 0xfc == 0x88 {
        if chip != ChipId::Rtl8852B || frame.get(24..26) != Some(&[0, 0]) {
            return Err(Error::BadFrame);
        }
        26
    } else {
        24
    };
    if fc & 0x4000 != 0
        && (chip != ChipId::Rtl8852B
            || !matches!(fc & 0x00fc,8|0x88)
            || fc & 0x0300 != 0x0100
            //24 native header +8 CCMP IV +>=8 ciphertext +8 MIC.
            || frame.len() < header_length+24
            || frame[header_length+2] != 0
            || frame[header_length+3] & 0x3f != 0x20
            || [frame[header_length], frame[header_length+1], frame[header_length+4], frame[header_length+5], frame[header_length+6], frame[header_length+7]] == [0; 6])
    {
        return Err(Error::BadFrame);
    }
    // B uses the AX baseline descriptor encoding, but its retained/native
    // device mask is36 bits. Encoding capacity is not device DMA authority.
    let dma_mask = if matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8852C) {
        0xf_ffff_ffff
    } else {
        0xff_ffff_ffff
    };
    if frame_dma
        .checked_add(frame.len() as u64 - 1)
        .is_none_or(|last| last > dma_mask)
    {
        return Err(Error::BadDma);
    }
    let body = if chip == ChipId::Rtl8852C { 32 } else { 24 };
    let entries = if chip == ChipId::Rtl8852C {
        frame.len().div_ceil(2044)
    } else {
        1
    };
    let entry_size = if chip == ChipId::Rtl8852C { 6 } else { 8 };
    let mut header = alloc::vec![0;body+8+entries*entry_size];
    encode_txwd(&info, &mut header[..24]).ok_or(Error::BadFrame)?;
    let mut word = u32::from_le_bytes(header[..4].try_into().unwrap());
    word &= !(1 << 22); // No optional WD_INFO block is present.
    word |= 1 << 7; // PCI WD page, Linux rtw89_core_tx_update_descinfo.
    word |= (((header_length as u32) / 2) << 11) & 0xf800; // Source ieee80211_hdrlen/2.
    header[..4].copy_from_slice(&word.to_le_bytes());
    // Only the v1 body carries ADDR_INFO_NUM. Baseline uses the
    // count in its PCI address-info option and leaves BODY1 reserved.
    if chip == ChipId::Rtl8852C {
        header[4..8].copy_from_slice(&((entries as u32) << 26).to_le_bytes());
    }
    let sw_seq = (u16::from_le_bytes([frame[22], frame[23]]) >> 4) as u32;
    header[12..16].copy_from_slice(&sw_seq.to_le_bytes());
    header[body..body + 2].copy_from_slice(&(sequence | 0x8000).to_le_bytes());
    let mut remaining = frame.len();
    let mut dma = frame_dma;
    for entry in 0..entries {
        let start = body + 8 + entry * entry_size;
        if chip == ChipId::Rtl8852C {
            let len = remaining.min(2044);
            remaining -= len;
            let high = (dma >> 32) as u16;
            if high > 0xf {
                return Err(Error::BadDma);
            }
            let flags = len as u16 | (high << 11) | if remaining == 0 { 1 << 15 } else { 0 };
            header[start..start + 2].copy_from_slice(&flags.to_le_bytes());
            header[start + 2..start + 6].copy_from_slice(&(dma as u32).to_le_bytes());
            dma += len as u64;
        } else {
            header[start..start + 2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
            let flags = 0x8001 | (((dma >> 32) as u16) << 6);
            header[start + 2..start + 4].copy_from_slice(&flags.to_le_bytes());
            header[start + 4..start + 8].copy_from_slice(&(dma as u32).to_le_bytes());
        }
    }
    Ok(header)
}
