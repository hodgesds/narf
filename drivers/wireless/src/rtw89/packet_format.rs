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
    /// Best effort, ACH0 / `RTW89_TX_QSEL_BE_0`.
    Data,
    /// Band0 management, CH8 / `RTW89_TX_QSEL_B0_MGMT`.
    Management,
    /// Background, ACH1 / `RTW89_TX_QSEL_BK_0`.
    Background,
    /// Video, ACH2 / `RTW89_TX_QSEL_VI_0`.
    Video,
    /// Voice, ACH3 / `RTW89_TX_QSEL_VO_0`.
    Voice,
}
impl Queue {
    /// `rtw89_core_get_qsel` + `rtw89_core_get_ch_dma` for a QoS TID.
    pub(super) fn for_tid(tid: u8) -> Self {
        match super::qos::Ac::of(tid) {
            super::qos::Ac::BestEffort => Self::Data,
            super::qos::Ac::Background => Self::Background,
            super::qos::Ac::Video => Self::Video,
            super::qos::Ac::Voice => Self::Voice,
        }
    }
    pub(super) fn channel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Background => 1,
            Self::Video => 2,
            Self::Voice => 3,
            Self::Management => 8,
        }
    }
    pub(super) fn qsel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Background => 1,
            Self::Video => 2,
            Self::Voice => 3,
            Self::Management => 0x12,
        }
    }
    pub(super) fn regs(self) -> dma::TxRingRegs {
        dma::addr_set_for_chip(ChipId::Rtl8852B).tx[self.channel() as usize]
    }
    /// `R_AX_PCIE_DMA_STOP1` bit for this channel (`B_AX_STOP_ACHn`/`CH8`).
    pub(super) fn stop_bit(self) -> u32 {
        1 << (8 + u32::from(self.channel()))
    }
    /// Ordinary rings: BE/MGMT always, BK/VI/VO only for the separately
    /// qualified all-AC QoS program.
    pub(super) fn ordinary(qos_all: bool) -> &'static [Self] {
        if qos_all {
            &[
                Self::Data,
                Self::Management,
                Self::Background,
                Self::Video,
                Self::Voice,
            ]
        } else {
            &[Self::Data, Self::Management]
        }
    }
}
/// `rate` flag for firmware rate adaptation (Linux data frames: USE_RATE=0,
/// DISDATAFB=0); the low bits carry `DATA_RTY_LOWEST_RATE`.
pub(super) const FIRMWARE_RA: u8 = 0x80;
/// With `FIRMWARE_RA`: `RTW89_TXWD_INFO0_DATA_ER` (Linux `desc_info->er_cap`
/// for an HE peer whose HE operation leaves ER SU enabled).
pub(super) const DATA_ER: u8 = 0x40;
/// `B_AX_STOP_WPDMA`.
pub(super) const STOP_WPDMA: u32 = 1 << 19;
/// Every ordinary TX stop bit this station can open (ACH0..3, CH8, WPDMA).
pub(super) const STOP_ALL: u32 = 0xf00 | 1 << 16 | STOP_WPDMA;
/// Wildcard-addressed probe request (`fc 0x40`, DA/BSSID broadcast) from
/// `own`. It has no peer; the packet owner admits it without a peer token.
pub(super) fn probe_request(frame: &[u8], own: [u8; 6]) -> bool {
    frame.len() >= 24
        && frame[0] == 0x40
        && frame[1] == 0
        && frame[4..10] == [0xff; 6]
        && frame[10..16] == own
        && frame[16..22] == [0xff; 6]
}
/// QoS TID of a QoS DATA header, if any.
pub(super) fn qos_tid(frame: &[u8]) -> Option<u8> {
    (frame.first() == Some(&0x88)).then(|| frame.get(24).map(|b| b & 0x0f))?
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
        // Association, authentication, disassociation, deauthentication and
        // (Block Ack) action frames.
        0x00 | 0xb0 | 0xa0 | 0xc0 | 0xd0 if frame[1] & (3 | 64) == 0 => Ok(Queue::Management),
        // Broadcast probe request of an active scan (see probe_request).
        0x40 if probe_request(frame, own) => Ok(Queue::Management),
        0x08 if frame[1] & 3 == 1 && unicast(&frame[4..10]) => Ok(Queue::Data),
        // QoS DATA: TID0..7, normal ack policy, no EOSP/A-MSDU/TXOP bits.
        0x88 if frame[1] & 3 == 1
            && unicast(&frame[4..10])
            && frame.get(24).is_some_and(|b| b & 0xf8 == 0)
            && frame.get(25) == Some(&0) =>
        {
            Ok(Queue::for_tid(frame[24]))
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
    let adaptive = rate & FIRMWARE_RA != 0;
    let er = rate & DATA_ER != 0;
    let index = rate & !(FIRMWARE_RA | DATA_ER);
    if mac_id != 0
        || sequence >= IDENTITIES
        || index > 11
        || er && !adaptive
        || queue == Queue::Management && rate != 0
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
    // RTW89_TXWD_BODY2_TID_INDICATE from rtw89_core_get_tid_indicate.
    if qos_tid(frame).is_some_and(super::qos::tid_indicate) {
        let body2 = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error::Metadata)?);
        put(&mut bytes, 8, body2 | 1 << 23);
    }
    // Linux management uses hardware SSN selector1/mode1. Non-QoS data
    // retains the supplied host sequence; neither enables hardware crypto.
    put(
        &mut bytes,
        0,
        body0 | 1 << 22 | if queue == Queue::Management { 5 } else { 0 },
    );
    if adaptive {
        // rtw89_build_txwd_info0/1 for data: firmware RA owns the rate;
        // INFO1 DATA_RTY_LOWEST_RATE[24:16] bounds hardware retry fallback.
        put(&mut bytes, 24, u32::from(er) << 15);
        put(&mut bytes, 28, u32::from(index) << 16);
    } else {
        put(&mut bytes, 24, 1 << 30 | 1 << 10 | u32::from(rate) << 16); // Source DATA_RATE[24:16].
    }
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
