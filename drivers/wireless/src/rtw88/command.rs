// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821C/RTL8822C packet H2C protocol, Linux rtw88/fw.c and fw.h.
//! Host DMA retirement alone is never an applied-command acknowledgement.
use super::{
    firmware_transport::{Error, Io},
    mac, phy,
};
pub(super) const BYTES: usize = 32;
#[derive(Default)]
pub(super) struct Ring {
    producer: u16,
    pending: bool,
}
impl Ring {
    pub(super) fn producer(&self) -> u16 {
        self.producer
    }
    pub(super) fn pending(&self) -> bool {
        self.pending
    }
    /// Commit occupancy before copying a reusable command or touching a BD.
    pub(super) fn reserve(&mut self, index: u32) -> Result<(u16, u16), Error> {
        if self.pending {
            return Err(Error::State);
        }
        let current = u32::from(self.producer);
        if index == u32::MAX {
            return Err(Error::Gone);
        }
        if index & 0x0fff_0fff != current | current << 16 {
            return Err(Error::Prerequisite);
        }
        let slot = self.producer;
        self.producer = (slot + 1) % 128;
        self.pending = true;
        Ok((slot, self.producer))
    }
    pub(super) fn poll(&mut self, index: u32) -> Result<bool, Error> {
        if !self.pending {
            return Err(Error::State);
        }
        if index == u32::MAX {
            return Err(Error::Gone);
        }
        let hardware = (index >> 16) & 0xfff;
        let previous = (u32::from(self.producer) + 127) % 128;
        if index & 0xfff != u32::from(self.producer)
            || (hardware != previous && hardware != u32::from(self.producer))
        {
            return Err(Error::Prerequisite);
        }
        if hardware == previous {
            return Ok(false);
        }
        self.pending = false;
        Ok(true)
    }
}
fn header(subcommand: u16, length: u16, sequence: u16) -> [u8; BYTES] {
    let mut packet = [0; BYTES];
    packet[..4].copy_from_slice(&(1u32 | 255 << 8 | u32::from(subcommand) << 16).to_le_bytes());
    packet[4..8].copy_from_slice(&(u32::from(length) | u32::from(sequence) << 16).to_le_bytes());
    packet
}
pub(super) fn general(info: mac::Info, sequence: u16) -> Result<[u8; BYTES], Error> {
    let boundary = info
        .firmware_tx_page
        .checked_sub(info.reserved_boundary)
        .ok_or(Error::State)?;
    let boundary = u8::try_from(boundary).map_err(|_| Error::State)?;
    let mut packet = header(13, 12, sequence);
    packet[10] = boundary;
    Ok(packet)
}
pub(super) fn phydm(info: phy::Info, sequence: u16) -> Result<[u8; BYTES], Error> {
    if info.paths != 2 {
        return Err(Error::Unsupported);
    }
    let mut packet = header(17, 16, sequence);
    packet[8] = info.rfe;
    packet[9] = 2; // FW_RF_2T2R (physical geometry, not the selected TX path).
    packet[10] = info.cut;
    // Linux's historical macro call names are reversed: RX_STATUS(antenna_tx),
    // TX_STATUS(antenna_rx). Retain those exact firmware bit positions.
    packet[11] = 1 | 3 << 4;
    Ok(packet)
}
pub(super) fn phydm8821c(info: super::phy8821c::Info, sequence: u16) -> Result<[u8; BYTES], Error> {
    if info.cut > 6 || !matches!(info.rfe, 0 | 2 | 4 | 6) {
        return Err(Error::Unsupported);
    }
    let mut packet = header(17, 16, sequence);
    packet[8] = info.rfe;
    packet[9] = 4; // fw.h::FW_RF_1T1R; this differs from the enum's host RF_1T1R=0.
    packet[10] = info.cut;
    packet[11] = 0x11; // source physical TX-A/RX-A antenna fields.
    Ok(packet)
}
pub(super) fn iqk8821c(sequence: u16) -> [u8; BYTES] {
    // rtw8821c_do_iqk: clear=0 and segment=0 before association.
    header(14, 9, sequence)
}
pub(super) fn iqk(sequence: u16) -> [u8; BYTES] {
    let mut packet = header(14, 9, sequence);
    packet[8] = 1; // clear previous calibration; nonsegmented current channel.
    packet
}
pub(super) fn descriptor() -> [u8; 48] {
    let mut bytes = [0; 48];
    // rtw_tx_write_data_h2c_get initializes only tx_pkt_size; PCI supplies qsel.
    bytes[..4].copy_from_slice(&32u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&(19u32 << 8).to_le_bytes());
    bytes
}
pub(super) async fn send(io: &mut impl Io, packet: &[u8; BYTES]) -> Result<(), Error> {
    io.submit_h2c(packet)?;
    for _ in 0..1000 {
        if io.poll_h2c()? {
            return Ok(());
        }
        io.delay_us(10).await;
    }
    Err(Error::Timeout)
}
