// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE operational MAC profile while packet DMA is still parked.
//! Linux rtl8188ee/hw.c::_rtl88ee_init_mac/_rtl88ee_hw_configure. CR and
//! PCIe DMA admission are deferred to the retained native packet owner.
use super::{efuse::Factory, firmware_transport::Io, prepare::Error, radio};

// sw.c receive_config with hw_init's CRC/ICV-error admission cleared.
// APPFCS is explicit: the native RX adapter removes exactly four FCS bytes.
pub(super) const RCR: u32 = 0xf000_780e;
pub(super) const TCR: u32 = (1 << 9) | (1 << 15);

fn word(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    io.write_bytes(reg, &value.to_le_bytes())?;
    if u16::from_le_bytes([io.read8(reg)?, io.read8(reg + 1)?]) != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    if io.read8(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn dword(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write32(reg, value)?;
    if io.read32(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
pub(super) fn configure(io: &impl Io, factory: &Factory) -> Result<(), Error> {
    radio::parked(io).map_err(Error::Radio)?;
    // These are the remaining init_mac prefix operations, without repeating
    // the already owned power flow, firmware download or LLT reset.
    for (reg, set, clear) in [
        (0x004, 1 << 4, 0),
        (0x302, 1 << 2, 0),
        (0x369, 1 << 7, 0),
        (0x079, 1 << 1, 0),
        (0x4ec, 3, 0),
        (0x008, 1 << 3, 0),
        (0x041, 0, 1 << 4),
    ] {
        byte(io, reg, (io.read8(reg)? & !clear) | set)?;
    }
    byte(io, 0x4ed, 2)?;
    word(io, 0x4f0, 0xcdf0)?;
    byte(io, 0x367, 0x80)?;
    byte(io, 0x102, 0)?; // MSR: no station claimed before MLME.
    io.write32(0xb4, u32::MAX)?; // W1C status, not an acknowledgement of work.
    io.write32(0xbc, u32::MAX)?;
    let old = u16::from_le_bytes([io.read8(0x10c)?, io.read8(0x10d)?]);
    word(io, 0x10c, (old & 15) | 0xe771)?;
    dword(io, 0x608, RCR)?;
    word(io, 0x6a4, 0xffff)?;
    dword(io, 0x604, TCR)?;
    dword(io, 0x304, 0)?;
    dword(io, 0x1c0, 0)?;
    dword(io, 0x440, 0xfff)?; // Legacy CCK+OFDM only.
    byte(io, 0x423, 0)?; // Host sequence, no HWSEQ descriptor override.
    byte(io, 0x680, 0)?; // Software CCMP: no CAM encryption/decryption.
    byte(io, 0x4d0, 0)?; // No AMPDU/early-mode prefix in this profile.
    byte(io, 0x4d3, 0)?;
    byte(io, 0x652, 235)?; // Linux NAV upper bound ceil(30000/128).
    for (offset, value) in factory.mac.iter().copied().enumerate() {
        byte(io, 0x610 + offset as u16, value)?;
    }
    // hw_init's efuse_read_1byte(0x1fa) is guarded by this chip's
    // EFUSE_REAL_CONTENT_LEN=256 and returns ff without a physical read.
    // Consequently neither PA-bias branch is executed for RTL8188EE.
    radio::parked(io).map_err(Error::Radio)
}
