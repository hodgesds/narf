// SPDX-License-Identifier: GPL-2.0-or-later
//! Restrictive source RTL8821AE stop gates only. No reset, RF restore,
//! on-air receipt, DMA-idle proof or permission to reclaim retained mappings.
use crate::rtlwifi::firmware_transport::{Error, Io};
fn mask(io: &impl Io, r: u16) -> Result<(), Error> {
    io.write32(r, 0)?;
    if io.read32(r)? != 0 {
        return Err(Error::Gate);
    }
    Ok(())
}
fn byte(io: &impl Io, r: u16, v: u8) -> Result<(), Error> {
    io.write8(r, v)?;
    if io.read8(r)? != v {
        return Err(Error::Gate);
    }
    Ok(())
}
pub(in crate::rtlwifi) fn close(
    io: &impl Io,
    master: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    let mut first = Ok(());
    // Independent gates all run, each through CURRENT original PCI. A
    // denied firmware/N21C record never grants replacement cleanup authority.
    for result in [
        mask(io, 0xb0),
        mask(io, 0xb8),
        byte(io, 0x522, 0xff),
        byte(io, 0x301, 0xff),
        (|| {
            if io.read16(0x100)? == u16::MAX {
                return Err(Error::Gone);
            }
            let cr = io.read8(0x100)?;
            io.write8(0x100, cr & !0xcf)?;
            if io.read8(0x100)? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            Ok(())
        })(),
        master(),
    ] {
        if first.is_ok() {
            first = result;
        }
    }
    first
}
