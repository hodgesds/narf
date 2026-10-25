// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware's actual boot-time hardware-feature report, Linux main.c/efuse.h.
use super::firmware_transport::{Error, Io};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Features {
    pub raw: [u8; 13],
    pub hci: u8,
    pub bandwidth: u8,
    pub streams: u8,
    pub antennas: u8,
    pub protocol: u8,
}
impl Features {
    fn decode(raw: [u8; 13]) -> Self {
        let word = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        Self {
            raw,
            hci: (word & 15) as u8,
            bandwidth: ((word >> 16) & 7) as u8,
            streams: ((word >> 19) & 3) as u8,
            antennas: ((word >> 21) & 7) as u8,
            protocol: ((word >> 26) & 3) as u8,
        }
    }
    pub(super) fn read(io: &mut impl Io) -> Result<Self, Error> {
        // Native claim writes0xfd before MCU boot, replacing any old report.
        // A successful firmware boot alone cannot fabricate this0x19 receipt.
        if io.read8(0x1a0)? != 0x19 {
            return Err(Error::Prerequisite);
        }
        let mut raw = [0; 13];
        for (index, byte) in raw.iter_mut().enumerate() {
            *byte = io.read8(0x1a2 + index as u16)?;
        }
        io.write8(0x1a0, 0)?;
        Ok(Self::decode(raw))
    }
}
