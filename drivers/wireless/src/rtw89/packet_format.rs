// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B ordinary PCI TXWD, WD-info, WP and address-info records.
//! Linux rtw89/core.c descriptor builders and pci.c::rtw89_pci_txwd_submit.
//! Formatting supplies no RF, peer, key, controlled-port or DMA authority.
use super::{dma, mac::ChipId, tx_transport, txrx::TxwdInfo};
use alloc::vec::Vec;

pub(super) const HEADER: usize = 24 + 24 + 8 + 8;
pub(super) const MAX_MPDU: usize = 2304;
pub(super) const DMA_MASK: u64 = 0xf_ffff_ffff;
pub(super) const DEPTH: u16 = 256;
pub(super) const IDENTITIES: u16 = 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Queue {
    Data,
    Management,
}
impl Queue {
    pub(super) fn channel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Management => 8,
        }
    }
    pub(super) fn qsel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Management => 0x12,
        }
    }
    pub(super) fn regs(self) -> dma::TxRingRegs {
        dma::addr_set_for_chip(ChipId::Rtl8852B).tx[self.channel() as usize]
    }
    pub(super) fn slot(self) -> usize {
        match self {
            Self::Data => 0,
            Self::Management => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Frame,
    Address,
    Metadata,
}
fn unicast(address: &[u8]) -> bool {
    address.len() == 6 && address != [0; 6] && address[0] & 1 == 0
}
pub(super) fn classify(frame: &[u8], own: [u8; 6]) -> Result<Queue, Error> {
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
        // One non-QoS three-address station. Optional modes are not admitted.
        0x00 | 0xb0 | 0xa0 | 0xc0 if frame[1] & (3 | 64) == 0 => Ok(Queue::Management),
        0x08 if frame[1] & 3 == 1 && unicast(&frame[4..10]) => Ok(Queue::Data),
        0x88 if frame[1] & 3 == 1
            && unicast(&frame[4..10])
            && frame.get(24..26) == Some(&[0, 0]) =>
        {
            Ok(Queue::Data)
        }
        _ => Err(Error::Frame),
    }
}
pub(super) fn extent(address: u64, length: usize) -> Result<(), Error> {
    if length == 0
        || address == 0
        || address & 3 != 0
        || address
            .checked_add(length as u64 - 1)
            .is_none_or(|last| last > DMA_MASK)
    {
        return Err(Error::Address);
    }
    Ok(())
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
/// Fixed CCK1,20MHz, port0, no hardware encryption or aggregation. All
/// reachable hardware RTS/CTS/ACK response rates remain the RF gate's duty.
pub(super) fn transmit(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
) -> Result<(Vec<u8>, Queue), Error> {
    transmit_rate(frame, own, mac_id, sequence, address, report, 0)
}
pub(super) fn transmit_rate(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
) -> Result<(Vec<u8>, Queue), Error> {
    let queue = classify(frame, own)?;
    if mac_id != 0 || sequence >= IDENTITIES || rate > 11 || queue == Queue::Management && rate != 0
    {
        return Err(Error::Metadata);
    }
    extent(address, frame.len())?;
    let baseline = tx_transport::prepare_header(
        ChipId::Rtl8852B,
        TxwdInfo {
            channel: queue.channel(),
            qsel: queue.qsel(),
            mac_id,
            pkt_size: frame.len() as u16,
        },
        sequence,
        address,
        frame,
    )
    .map_err(|_| Error::Frame)?;
    let mut bytes = alloc::vec![0; HEADER];
    bytes[..24].copy_from_slice(&baseline[..24]);
    bytes[48..].copy_from_slice(&baseline[24..]);
    let body0 = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Metadata)?);
    // Linux management uses hardware SSN selector1/mode1. Non-QoS data
    // retains the supplied host sequence; neither enables hardware crypto.
    put(
        &mut bytes,
        0,
        body0 | 1 << 22 | if queue == Queue::Management { 5 } else { 0 },
    );
    put(&mut bytes, 24, 1 << 30 | 1 << 10 | u32::from(rate) << 16); // Source DATA_RATE[24:16].
    put(&mut bytes, 36, u32::from(report) << 10);
    put(&mut bytes, 40, 1 << 31 | u32::from(frame[4] & 1 == 0) << 27);
    Ok((bytes, queue))
}
pub(super) fn descriptor(address: u64) -> Result<[u8; 8], Error> {
    extent(address, HEADER)?;
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&(HEADER as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(1 << 14 | ((address >> 32) as u16) << 6).to_le_bytes());
    bytes[4..].copy_from_slice(&(address as u32).to_le_bytes());
    Ok(bytes)
}

#[cfg(feature = "kernel-test")]
#[path = "packet_format/tests.rs"]
mod tests;
