// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic RTL8822C RF register primitives, generic over [`RegIo`],
//! plus the self-contained calibration sequences built on them (currently the
//! one-shot ADC/DAC DC calibration, [`dack`]).
//!
//! The full channel/gain/IQK radio bring-up (`radio.c`) is interleaved with
//! native firmware-command and station-gating operations that `RegIo` cannot
//! express, so it stays in the consuming crate; only its pure-register
//! sub-sequences move here, one slice at a time.
use crate::{ChipError as Error, RegIo as Io};

pub mod b22;
pub mod dack;

/// A 32-bit read that maps the all-ones "device gone" pattern to an error.
pub(crate) async fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
/// Read-modify-write the `bits` field (right-justified `value`).
pub(crate) async fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = read(io, reg).await?;
    io.write32(reg, old & !bits | value << bits.trailing_zeros())
        .await
}
/// Read a 20-bit RF register over the direct (non-SIPI) aperture.
pub(crate) async fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
    let base = match path {
        0 => 0x3c00,
        1 => 0x4c00,
        _ => return Err(Error::Unsupported),
    };
    Ok(read(io, base + u16::from(address) * 4).await? & 0xfffff)
}
/// Write the `bits` field of an RF register (SIPI for RF0, direct otherwise),
/// matching `rtw_phy_write_rf_reg_mix`.
pub(crate) async fn rf(
    io: &mut impl Io,
    path: u8,
    address: u8,
    bits: u32,
    value: u32,
) -> Result<(), Error> {
    if path > 1 || bits == 0 || bits & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    if address == 0 {
        let shifted = value
            .checked_shl(bits.trailing_zeros())
            .ok_or(Error::Unsupported)?;
        if shifted & !bits != 0 {
            return Err(Error::Unsupported);
        }
        let data = if bits == 0xfffff {
            value
        } else {
            rf_read(io, path, 0).await? & !bits | shifted
        };
        io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data)
            .await?;
        io.delay_us(13).await;
    } else {
        mask(
            io,
            (if path == 0 { 0x3c00 } else { 0x4c00 }) + u16::from(address) * 4,
            bits,
            value,
        )
        .await?;
        io.delay_us(1).await;
    }
    Ok(())
}
