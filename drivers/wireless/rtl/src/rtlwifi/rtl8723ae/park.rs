// SPDX-License-Identifier: GPL-2.0-or-later
//! Restrictive host admission closure only. Never a reset, RF restore,
//! on-air completion or DMA-idle/reclamation receipt.
use crate::rtlwifi::firmware_transport::{Error, Io};
fn mask(io: &impl Io, reg: u16) -> Result<(), Error> {
    io.write32(reg, 0)?;
    if io.read32(reg)? != 0 {
        return Err(Error::Gate);
    }
    Ok(())
}
pub(in crate::rtlwifi) fn close(
    io: &impl Io,
    master: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    let mut result = Ok(());
    // Attempt independent restrictive gates even if an earlier access was
    // denied. Each adapter effect must invoke CURRENT original PCI authority.
    for current in [
        mask(io, 0x3a8),
        mask(io, 0x3ac),
        (|| {
            io.write8(0x522, 0xff)?;
            if io.read8(0x522)? != 0xff {
                return Err(Error::Gate);
            }
            Ok(())
        })(),
        (|| {
            // CR low=ff is legitimate while Running (word02ff), so do not
            // mistake that byte for a lost function. Wordffff is not accepted.
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
        if result.is_ok() {
            result = current;
        }
    }
    result
}
