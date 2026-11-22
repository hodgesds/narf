// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821C ("C21") RF register primitives + TXAGC / retune programming,
//! generic over [`RegIo`]. The C21 RF-A aperture is SIPI-write 0xc90 /
//! direct-read 0x2800 (distinct from the C22 0x1808/0x3c00), and every SIPI
//! write is read back for confirmation.
//!
//! The channel/band programming (factory swing + `BandFacts`), the `Read32`
//! operating readbacks, and the envelope/command/grant calibration and station
//! steps stay in the consuming crate and call these over the bridge.
use crate::{ChipError as Error, RegIo as Io};

/// `rtw8821c_set_tx_power_index_by_rate` packs four source rate indices per
/// word at RF-A 0x1d00. C22's reference/difference registers are unrelated.
const TXAGC: [u16; 8] = [
    0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
];

/// RF-A RF18 bits under mask 0x70fff that Linux `rtw8821c_set_channel_rf`
/// programs: band (2.4GHz 0, 5GHz bits 16|8), channel byte, RFSI (bit17 on
/// 100..=140, bit18 above 140) and BW (20MHz bits 11:10 = 3, 40MHz bit11,
/// 80MHz bit10). `channel` is the RF center; `bw_mhz` other than 40/80 is 20.
pub const fn rf18_for(channel: u8, bw_mhz: u8) -> u32 {
    let band = if channel <= 14 { 0 } else { 1 << 16 | 1 << 8 };
    let rfsi = if channel >= 100 && channel <= 140 {
        1 << 17
    } else if channel > 140 {
        1 << 18
    } else {
        0
    };
    let bw = match bw_mhz {
        40 => 1 << 11,
        80 => 1 << 10,
        _ => 3 << 10,
    };
    band | rfsi | bw | channel as u32
}

async fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
/// `rtw_phy_read_rf` over the C21 direct-read aperture.
pub async fn rf_read(io: &mut impl Io, address: u8) -> Result<u32, Error> {
    Ok(read(io, 0x2800 + u16::from(address) * 4).await? & 0xfffff)
}
/// `rtw_phy_write_rf_reg_sipi` (0xc90) with a direct-read confirmation.
pub async fn rf(io: &mut impl Io, address: u8, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || bits & !0xfffff != 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let data = if bits == 0xfffff {
        value
    } else {
        (rf_read(io, address).await? & !bits) | (value << bits.trailing_zeros())
    };
    io.write32(0xc90, (u32::from(address) << 20) | data).await?;
    io.delay_us(13).await;
    // These channel/XTAL/control registers have stable fields. SIPI issuance
    // alone cannot establish that the chosen channel/calibration setup stuck.
    if rf_read(io, address).await? & bits != data & bits {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Linux `rtw8821c_set_channel` retune between 2.4GHz/20MHz primaries: only
/// `_rf` changes (RF LUTDBG/0x64, the RF18 channel byte and the XTALX2 toggle).
pub async fn retune_channel(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    if !(1..=13).contains(&ch) {
        return Err(Error::Unsupported);
    }
    let rf18 = (rf_read(io, 0x18).await? & !0x70fff) | rf18_for(ch, 20);
    rf(io, 0xdf, 1 << 6, 1).await?;
    rf(io, 0x64, 15, 15).await?;
    rf(io, 0x18, 0xfffff, rf18).await?;
    rf(io, 0xb8, 1 << 19, 0).await?;
    rf(io, 0xb8, 1 << 19, 1).await
}
/// A 32-bit little-endian field of `indices`, defensive against a non-4 slice
/// that the `slot < 3` bound makes unreachable.
fn word(indices: &[u8; 12], slot: usize) -> Result<u32, Error> {
    indices[slot * 4..slot * 4 + 4]
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| Error::Unsupported)
}
/// `rtw8821c_set_tx_power_index_by_rate` for the retained CCK1 profile: the
/// three coded index words, the rest cleared.
pub async fn write_txagc(io: &mut impl Io, indices: [u8; 12]) -> Result<(), Error> {
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let value = if slot < 3 { word(&indices, slot)? } else { 0 };
        io.write32(reg, value).await?;
    }
    Ok(())
}
/// RF18 on the retuned 20MHz primary `ch`, plus the [`verify_txagc`] readback
/// at the operating RRSR (0x1f).
pub async fn verify_retune(io: &mut impl Io, ch: u8, indices: [u8; 12]) -> Result<(), Error> {
    if rf_read(io, 0x18).await? & 0x70fff != rf18_for(ch, 20) {
        return Err(Error::Prerequisite);
    }
    verify_txagc(io, indices, 0x1f).await
}
/// TXAGC words of [`write_txagc`], REG_RRSR `rrsr` and the clean IQK
/// report (0x1bf0).
pub async fn verify_txagc(io: &mut impl Io, indices: [u8; 12], rrsr: u32) -> Result<(), Error> {
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let expected = if slot < 3 { word(&indices, slot)? } else { 0 };
        if read(io, reg).await? != expected {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x440).await? != rrsr || read(io, 0x1bf0).await? & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
