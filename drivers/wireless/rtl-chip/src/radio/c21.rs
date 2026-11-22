// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821C ("C21") RF register primitives + TXAGC / retune programming,
//! generic over [`RegIo`]. The C21 RF-A aperture is SIPI-write 0xc90 /
//! direct-read 0x2800 (distinct from the C22 0x1808/0x3c00), and every SIPI
//! write is read back for confirmation.
//!
//! The channel/band programming (factory swing + `BandFacts`), the `Read32`
//! operating readbacks, and the envelope/command/grant calibration and station
//! steps stay in the consuming crate and call these over the bridge.
use crate::band5::{self, Width};
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

// ── channel / band programming ─────────────────────────────────────────────

/// The band-dependent facts the channel programming needs, resolved by the
/// caller (the native `BandFacts.swing(ch)` -> `swing`, plus the 2.4GHz CCK
/// filter words and the RFE BTG flag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C21BandParams {
    pub swing: u16,
    pub filters: [u32; 3],
    pub btg: bool,
}

const BB_2G: [(u16, u32, u32); 6] = [
    (0x808, 1 << 28, 1),
    (0x454, 1 << 7, 0),
    (0xa80, 1 << 18, 0),
    (0x814, 0xfc00, 15),
    (0xc1c, 0xf00, 0),
    (0x860, 0x1ffe0000, 0x96a),
];

async fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = read(io, reg).await?;
    io.write32(reg, (old & !bits) | (value << bits.trailing_zeros()))
        .await
}

/// `_rxdfir` (ACBB0, ACBBRXFIR, TXDFIR, CHFIR) per width.
const fn rxdfir(width: Width) -> [(u16, u32, u32); 4] {
    let (acbbrx, txdfir, chfir) = match width {
        Width::Twenty => (2, 1, 0),
        Width::Forty(_) => (2, 0, 0),
        Width::Eighty(_) => (1, 0, 1),
    };
    [
        (0x948, 3 << 28, 2),
        (0x94c, 3 << 28, acbbrx),
        (0xc20, 1 << 31, txdfir),
        (0x8f0, 1 << 31, chfir),
    ]
}
/// `set_bw` ADCCLK (0x8ac) for `width` over the current value.
const fn adcclk(old: u32, width: Width) -> u32 {
    let sc = (width.sc() as u32 & 0xf) << 2;
    match width {
        Width::Twenty => (old & 0xffcffc00) | 0x10010000,
        Width::Forty(_) => (old & 0xff3ff300) | 0x20020000 | sc | 1,
        Width::Eighty(_) => (old & 0xfcffcf00) | 0x40040000 | sc | 2,
    }
}
/// Bits of 0x8ac that [`adcclk`] sets or clears for `width`.
const fn adcclk_mask(width: Width) -> u32 {
    match width {
        Width::Twenty => !0xffcffc00 | 0x10010000,
        Width::Forty(_) => !0xff3ff300 | 0x20020000,
        Width::Eighty(_) => !0xfcffcf00 | 0x40040000,
    }
}
async fn set_channel(
    io: &mut impl Io,
    ch: u8,
    width: Width,
    params: C21BandParams,
) -> Result<u16, Error> {
    let five = band5::band(ch).is_some();
    if !five && width != Width::Twenty {
        return Err(Error::Unsupported);
    }
    let swing = params.swing;
    if five {
        // Head of the RF center channel (`channel` is the center at 40/80).
        let txscale = band5::txscale8821c(ch).ok_or(Error::Unsupported)?;
        let clktrk = band5::clktrk8821c(ch).ok_or(Error::Unsupported)?;
        for (reg, bits, value) in [
            (0xa80, 1 << 18, 1),
            (0x454, 1 << 7, 1),
            (0x808, 1 << 28, 0),
            (0x814, 0xfc00, 15),
            (0xc1c, 0xf00, txscale),
            (0x860, 0x1ffe0000, clktrk),
        ] {
            mask(io, reg, bits, value).await?;
        }
    } else {
        for (reg, bits, value) in BB_2G {
            mask(io, reg, bits, value).await?;
        }
        io.write32(0xa24, params.filters[0]).await?;
        mask(io, 0xa28, 0xffff, params.filters[1] & 0xffff).await?;
        io.write32(0xaac, params.filters[2]).await?;
    }
    if let Width::Forty(sc) = width {
        mask(io, 0xa00, 1 << 4, u32::from(sc == 1)).await?;
    }
    let adc = read(io, 0x8ac).await?;
    io.write32(0x8ac, adcclk(adc, width)).await?;
    mask(io, 0x8c4, 1 << 30, 1).await?;
    mask(io, 0xc1c, 0xffe00000, u32::from(swing)).await?;
    io.write8(0x483, width.data_sc()).await?;
    mask(io, 0x668, 0x180, width.rfmod()).await?;
    mask(io, 0x24, 3 << 20, 0).await?;
    io.write8(0x55c, 80).await?;
    io.write8(0x638, 80).await?;
    let cck = io.read8(0x454).await?;
    if cck == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x454, (cck & !0x80) | u8::from(five) << 7)
        .await?;
    let rf18 = (rf_read(io, 0x18).await? & !0x70fff) | rf18_for(ch, width.mhz());
    mask(io, 0x1080, 1 << 16, 1).await?;
    mask(io, 0, 1 << 26, 1).await?;
    if five {
        // SWITCH_TO_WLA: RFECTL WL|WLA, BTG/CTRL/WLG clear; CCA/LNA kept.
        mask(io, 0xcb8, 0xf50000, 0xd0).await?;
        rf(io, 0xdf, 1 << 6, 0).await?;
    } else {
        let btg = params.btg;
        mask(io, 0xa84, 0xff0000, if btg { 0x0e } else { 0x12 }).await?;
        mask(io, 0xa80, 0xffff, if btg { 0xfc84 } else { 0x7532 }).await?;
        mask(io, 0xcb8, 0xf50000, if btg { 1 } else { 0x70 }).await?;
        rf(io, 0xdf, 1 << 6, 1).await?;
        rf(io, 0x64, 15, 15).await?;
    }
    rf(io, 0x18, 0xfffff, rf18).await?;
    rf(io, 0xb8, 1 << 19, 0).await?;
    rf(io, 0xb8, 1 << 19, 1).await?;
    for (reg, bits, value) in rxdfir(width) {
        mask(io, reg, bits, value).await?;
    }
    Ok(swing)
}
/// `rtw8821c_set_channel(ch, RTW_CHANNEL_WIDTH_20, 0)` on either band.
pub async fn set_channel20(io: &mut impl Io, ch: u8, params: C21BandParams) -> Result<u16, Error> {
    let five = band5::primary(ch);
    if !five && !(1..=13).contains(&ch) {
        return Err(Error::Unsupported);
    }
    set_channel(io, ch, Width::Twenty, params).await
}
/// `rtw8821c_set_channel(center, BW40|BW80, sc)` on 5GHz.
pub async fn wide5(
    io: &mut impl Io,
    center: u8,
    width: Width,
    params: C21BandParams,
) -> Result<u16, Error> {
    let ok = match width {
        Width::Forty(_) => band5::is_center40(center),
        Width::Eighty(_) => band5::is_center80(center),
        Width::Twenty => false,
    };
    if !ok || !width.valid() {
        return Err(Error::Unsupported);
    }
    set_channel(io, center, width, params).await
}
async fn verify_geometry_at(io: &mut impl Io, ch: u8, swing: u16, btg: bool) -> Result<(), Error> {
    if rf_read(io, 0x18).await? & 0x70fff != rf18_for(ch, 20)
        || read(io, 0xc1c).await? >> 21 != u32::from(swing)
        || read(io, 0x8ac).await? & (!0xffcffc00 | 0x10010000) != 0x10010000
        || read(io, 0xcb8).await? & 0xf50000 != if btg { 0x10000 } else { 0x700000 }
        || read(io, 0xa84).await? & 0xff0000 != if btg { 0xe0000 } else { 0x120000 }
        || read(io, 0xa80).await? & 0xffff != if btg { 0xfc84 } else { 0x7532 }
        || io.read8(0x100).await? & 0xcc != 0
        || io.read8(0x522).await? != 255
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Readback of [`set_channel20`] (band-dependent fields, RF18, swing).
pub async fn verify_channel20(
    io: &mut impl Io,
    ch: u8,
    params: C21BandParams,
) -> Result<(), Error> {
    let swing = params.swing;
    if !band5::primary(ch) {
        verify_geometry_at(io, ch, swing, params.btg).await?;
        // Fields a preceding 5GHz program changed.
        if read(io, 0x808).await? & (1 << 28) == 0
            || read(io, 0xa80).await? & (1 << 18) != 0
            || io.read8(0x454).await? & 0x80 != 0
            || (read(io, 0xc1c).await? >> 8) & 15 != 0
            || (read(io, 0x860).await? >> 17) & 0xfff != 0x96a
            || rf_read(io, 0xdf).await? & (1 << 6) == 0
        {
            return Err(Error::Prerequisite);
        }
        return Ok(());
    }
    let txscale = band5::txscale8821c(ch).ok_or(Error::Unsupported)?;
    let clktrk = band5::clktrk8821c(ch).ok_or(Error::Unsupported)?;
    if rf_read(io, 0x18).await? & 0x70fff != rf18_for(ch, 20)
        || rf_read(io, 0xdf).await? & (1 << 6) != 0
        || read(io, 0xc1c).await? >> 21 != u32::from(swing)
        || (read(io, 0xc1c).await? >> 8) & 15 != txscale
        || (read(io, 0x860).await? >> 17) & 0xfff != clktrk
        || read(io, 0xa80).await? & (1 << 18) == 0
        || read(io, 0x808).await? & (1 << 28) != 0
        || io.read8(0x454).await? & 0x80 == 0
        || read(io, 0x8ac).await? & (!0xffcffc00 | 0x10010000) != 0x10010000
        || read(io, 0xcb8).await? & 0xf50000 != 0xd00000
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Readback of [`wide5`].
pub async fn verify_wide5(
    io: &mut impl Io,
    center: u8,
    width: Width,
    params: C21BandParams,
) -> Result<(), Error> {
    let swing = params.swing;
    let txscale = band5::txscale8821c(center).ok_or(Error::Unsupported)?;
    let clktrk = band5::clktrk8821c(center).ok_or(Error::Unsupported)?;
    if width == Width::Twenty
        || rf_read(io, 0x18).await? & 0x70fff != rf18_for(center, width.mhz())
        || rf_read(io, 0xdf).await? & (1 << 6) != 0
        || read(io, 0xc1c).await? >> 21 != u32::from(swing)
        || (read(io, 0xc1c).await? >> 8) & 15 != txscale
        || (read(io, 0x860).await? >> 17) & 0xfff != clktrk
        || read(io, 0xa80).await? & (1 << 18) == 0
        || read(io, 0x808).await? & (1 << 28) != 0
        || io.read8(0x454).await? & 0x80 == 0
        || read(io, 0x8ac).await? & adcclk_mask(width) != adcclk(0, width) & adcclk_mask(width)
        || read(io, 0x8c4).await? & (1 << 30) == 0
        || io.read8(0x483).await? != width.data_sc()
        || (read(io, 0x668).await? >> 7) & 3 != width.rfmod()
        || read(io, 0xcb8).await? & 0xf50000 != 0xd00000
        || matches!(width, Width::Forty(sc) if (read(io, 0xa00).await? >> 4) & 1 != u32::from(sc == 1))
    {
        return Err(Error::Prerequisite);
    }
    for (reg, bits, value) in rxdfir(width) {
        if read(io, reg).await? & bits != value << bits.trailing_zeros() {
            return Err(Error::Prerequisite);
        }
    }
    Ok(())
}
/// `rtw8821c_set_channel(center, BW40, sc)` on the retained 2.4GHz C21.
pub async fn width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
    if !(3..=11).contains(&center) || !matches!(sc, 1 | 2) {
        return Err(Error::Unsupported);
    }
    mask(io, 0xa00, 1 << 4, u32::from(sc == 1)).await?;
    let adc = read(io, 0x8ac).await?;
    io.write32(
        0x8ac,
        (adc & 0xff3ff300) | 0x20020000 | u32::from(sc) << 2 | 1,
    )
    .await?;
    mask(io, 0x8c4, 1 << 30, 1).await?;
    io.write8(0x483, sc).await?;
    mask(io, 0x668, 0x180, 1).await?;
    mask(io, 0x24, 3 << 20, 0).await?;
    io.write8(0x55c, 80).await?;
    io.write8(0x638, 80).await?;
    let cck = io.read8(0x454).await?;
    if cck == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x454, cck & !0x80).await?;
    let rf18 = (rf_read(io, 0x18).await? & !0x70fff) | rf18_for(center, 40);
    rf(io, 0xdf, 1 << 6, 1).await?;
    rf(io, 0x64, 15, 15).await?;
    rf(io, 0x18, 0xfffff, rf18).await?;
    rf(io, 0xb8, 1 << 19, 0).await?;
    rf(io, 0xb8, 1 << 19, 1).await?;
    for (reg, bits, value) in [
        (0x948, 3 << 28, 2),
        (0x94c, 3 << 28, 2),
        (0xc20, 1 << 31, 0),
        (0x8f0, 1 << 31, 0),
    ] {
        mask(io, reg, bits, value).await?;
    }
    Ok(())
}
/// Readback of [`width40`].
pub async fn verify_width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
    if rf_read(io, 0x18).await? & 0x70fff != rf18_for(center, 40)
        || (read(io, 0xa00).await? >> 4) & 1 != u32::from(sc == 1)
        || read(io, 0x8ac).await? & (!0xff3ff300 | 0x20020000)
            != 0x20020000 | u32::from(sc) << 2 | 1
        || read(io, 0x8c4).await? & (1 << 30) == 0
        || io.read8(0x483).await? != sc
        || read(io, 0x668).await? & 0x180 != 0x80
        || read(io, 0x948).await? & (3 << 28) != 2 << 28
        || read(io, 0x94c).await? & (3 << 28) != 2 << 28
        || read(io, 0xc20).await? & (1 << 31) != 0
        || read(io, 0x8f0).await? & (1 << 31) != 0
        || read(io, 0x440).await? != 0x1f
        || read(io, 0x1bf0).await? & 0x100ff != 0
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

const DFIR: [(u16, u32, u32); 4] = [
    (0x948, 3 << 28, 2),
    (0x94c, 3 << 28, 2),
    (0xc20, 1 << 31, 1),
    (0x8f0, 1 << 31, 0),
];

/// `rtw8821c_set_channel` initial ch1/20MHz 2.4GHz program: the `ch_param`
/// CCK filters, factory swing and RFE BTG the caller resolved into `params`,
/// the RF-A switch, RF18, `_rxdfir` and cleared TXAGC. Returns the swing.
pub async fn channel(io: &mut impl Io, params: C21BandParams) -> Result<u16, Error> {
    for (reg, bits, value) in BB_2G {
        mask(io, reg, bits, value).await?;
    }
    io.write32(0xa24, params.filters[0]).await?;
    mask(io, 0xa28, 0xffff, params.filters[1] & 0xffff).await?;
    io.write32(0xaac, params.filters[2]).await?;
    let adc = read(io, 0x8ac).await?;
    io.write32(0x8ac, (adc & 0xffcffc00) | 0x10010000).await?;
    mask(io, 0x8c4, 1 << 30, 1).await?;
    let swing = params.swing;
    mask(io, 0xc1c, 0xffe00000, u32::from(swing)).await?;
    // rtw_set_channel_mac: no sideband for20MHz, source80MHz MAC clock.
    io.write8(0x483, 0).await?;
    mask(io, 0x668, 0x180, 0).await?;
    mask(io, 0x24, 3 << 20, 0).await?;
    io.write8(0x55c, 80).await?;
    io.write8(0x638, 80).await?;
    let cck = io.read8(0x454).await?;
    if cck == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x454, cck & !0x80).await?;
    let rf18 = (rf_read(io, 0x18).await? & !0x70fff) | rf18_for(1, 20);
    mask(io, 0x1080, 1 << 16, 1).await?;
    mask(io, 0, 1 << 26, 1).await?;
    let btg = params.btg;
    mask(io, 0xa84, 0xff0000, if btg { 0x0e } else { 0x12 }).await?;
    mask(io, 0xa80, 0xffff, if btg { 0xfc84 } else { 0x7532 }).await?;
    mask(io, 0xcb8, 0xf50000, if btg { 1 } else { 0x70 }).await?;
    rf(io, 0xdf, 1 << 6, 1).await?;
    rf(io, 0x64, 15, 15).await?;
    rf(io, 0x18, 0xfffff, rf18).await?;
    rf(io, 0xb8, 1 << 19, 0).await?;
    rf(io, 0xb8, 1 << 19, 1).await?;
    for (reg, bits, value) in DFIR {
        mask(io, reg, bits, value).await?;
    }
    for reg in TXAGC {
        io.write32(reg, 0).await?;
    }
    verify_channel(io, swing, btg).await?;
    Ok(swing)
}
async fn verify_channel(io: &mut impl Io, swing: u16, btg: bool) -> Result<(), Error> {
    verify_geometry(io, swing, btg).await?;
    for reg in TXAGC {
        if read(io, reg).await? != 0 {
            return Err(Error::Prerequisite);
        }
    }
    Ok(())
}
async fn verify_geometry(io: &mut impl Io, swing: u16, btg: bool) -> Result<(), Error> {
    verify_geometry_at(io, 1, swing, btg).await
}
