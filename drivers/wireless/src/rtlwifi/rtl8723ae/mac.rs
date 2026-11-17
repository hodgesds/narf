// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! RTL8723AE MAC setup with packet DMA and MAC gates left parked.
//!
//! `_rtl8712e_init_mac` after the power prefix and LLT, then
//! `_rtl8723e_hw_configure`. Ring bases and CR enable writes belong to the
//! retained packet owner. ASPM remains disabled; software crypto leaves
//! SECCFG zero. Qualified boards are RTL8723A, never the CSR-BC4 variant.
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const RCR: u32 = 0xf000_7a0e;
pub const TCR: u32 = 0x0000_3200;
pub const REG_RCR: u16 = 0x0608;
pub const REG_TCR: u16 = 0x0604;
pub const REG_APSD_CTRL: u16 = 0x0600;
pub const REG_MACID: u16 = 0x0610;
pub const REG_SECCFG: u16 = 0x0680;

/// `retry` continues the successful ePHY loop's count (1..99).
/// Linux's APSD busy wait has no failure result when it exhausts 200.
pub async fn init_mac(io: &impl Io, mut retry: u16) -> Result<(), Error> {
    if !(1..100).contains(&retry) {
        return Err(Error::State);
    }
    io.write32(0x0124, u32::MAX)?; // HISR W1C
    io.write8(0x012c, 0xff)?; // HISRE W1C
    io.write16(0x0116, 0x27ff)?;
    let old = u16::from_le_bytes([io.read8(0x010c)?, io.read8(0x010d)?]);
    io.write16(0x010c, (old & 0xf) | 0xf771)?;
    io.write8(0x0421, 0x1f)?;
    io.write32(REG_RCR, RCR)?;
    io.write16(0x06a4, u16::MAX)?; // RXFLTMAP2
    io.write32(REG_TCR, TCR)?;
    io.write8(0x04d0, 0)?;
    io.write8(0x0303, 0x74)?;
    io.write32(0x0304, 0)?; // INT_MIG
    let value = io.read8(REG_APSD_CTRL)?;
    io.write8(REG_APSD_CTRL, value & !(1 << 6))?;
    loop {
        retry += 1;
        let value = io.read8(REG_APSD_CTRL)?;
        if retry >= 200 || value & (1 << 7) == 0 {
            break;
        }
        io.delay_us(0).await;
    }
    io.write32(0x01c0, 0)?;
    Ok(())
}

pub fn trim_receive_config(io: &impl Io) -> Result<u32, Error> {
    let value = io.read32(REG_RCR)? & !((1 << 8) | (1 << 9));
    io.write32(REG_RCR, value)?;
    Ok(value)
}

/// `_rtl8723e_hw_configure` for the qualified RTL8723A BT type.
pub fn hw_configure(io: &impl Io) -> Result<(), Error> {
    io.write8(0x0480, 8)?;
    io.write8(0x0603, 4)?;
    io.write32(0x0440, 0x0fff)?;
    io.write8(0x051b, 9)?;
    io.write8(0x045c, 0)?;
    io.write16(0x0420, 0x1f80)?;
    io.write16(0x042a, 0x0707)?;
    io.write32(0x04cc, 0x0201_2802)?;
    io.write8(0x0423, 0xff)?;
    io.write32(0x0430, 0x0100_0000)?;
    io.write32(0x0434, 0x0706_0504)?;
    io.write32(0x0438, 0x0100_0000)?;
    io.write32(0x043c, 0x0706_0504)?;
    io.write32(0x0458, 0xb972_a841)?;
    io.write8(0x055a, 2)?;
    io.write8(0x055d, 0xff)?;
    io.write8(0x0550, 0x1f)?;
    io.write8(0x0541, 0xff)?;
    io.write8(0x0541, 0xff)?;
    io.write8(0x0512, 0x1c)?;
    io.write8(0x051a, 0x16)?;
    io.write16(0x0546, 0x0020)?;
    io.write16(0x0546, 0x0020)?;
    io.write32(0x0460, 0x0008_6666)?;
    io.write8(0x0640, 0x40)?;
    io.write16(0x0428, 0x1010)?;
    io.write16(0x063a, 0x1010)?;
    io.write16(0x0514, 0x1010)?;
    io.write16(0x0516, 0x1010)?;
    io.write32(0x0620, u32::MAX)?;
    io.write32(0x0624, u32::MAX)?;
    io.write32(0x0394, 1)?;
    Ok(())
}

pub fn station_identity(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    if mac[0] & 1 != 0 || *mac == [0; 6] {
        return Err(Error::State);
    }
    io.write8(REG_SECCFG, 0)?;
    for (i, value) in mac.iter().copied().enumerate() {
        let at = REG_MACID + i as u16;
        io.write8(at, value)?;
        if io.read8(at)? != value {
            return Err(Error::Readback);
        }
    }
    Ok(())
}
