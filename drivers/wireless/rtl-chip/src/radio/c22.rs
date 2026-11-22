// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822C ("C22") channel/TRX register programming (`rtw8822c_set_channel`
//! and `rtw8822c_config_trx_mode`), generic over [`RegIo`]: the 2.4/5 GHz BB
//! heads, the 20/40/80 MHz tails, `_rf` RF18 and the measured readback checks.
//! No step opens MAC TX/RX, releases TXPAUSE or submits H2C.
//!
//! The DACK/IQK, gain, trim and firmware-command steps of the radio bring-up
//! stay in the consuming crate and call these sequences over the bridge.
use super::{mask, read, rf, rf_read};
use crate::band5::{self, Width};
use crate::{ChipError as Error, RegIo as Io};

/// `rtw8822c_set_channel_bb` REG_SC_O0 (0xc30[11:0]) for a 2.4GHz primary.
const fn scotrk(channel: u8) -> u32 {
    match channel {
        13 | 14 => 0x969,
        11 | 12 => 0x96a,
        _ => 0x9aa,
    }
}
/// `rtw8822c_set_channel_bb` REG_TXDFIR0 (0x808[6:4]) for a 2.4GHz primary.
const fn txdfir(channel: u8) -> u32 {
    if channel == 13 {
        3
    } else {
        1
    }
}

async fn reset(io: &mut impl Io) -> Result<(), Error> {
    let old = io.read16(2).await?;
    if old == u16::MAX {
        return Err(Error::Gone);
    }
    for value in [old | 1, old & !1, old | 1] {
        io.write16(2, value).await?;
    }
    Ok(())
}
/// `rtw8822c_bb_reset`: `BIT_FEN_BB_RSTB` set, clear, set.
pub async fn bb_reset(io: &mut impl Io) -> Result<(), Error> {
    reset(io).await
}
/// `rtw8822c_toggle_igi`.
pub async fn toggle_igi(io: &mut impl Io) -> Result<(), Error> {
    let igi = read(io, 0x1d70).await? & 0x7f;
    let lower = igi.checked_sub(2).ok_or(Error::Prerequisite)?;
    for value in [lower, igi] {
        mask(io, 0x1d70, 0x7f, value).await?;
        mask(io, 0x1d70, 0x7f00, value).await?;
    }
    Ok(())
}
pub async fn trx(io: &mut impl Io) -> Result<(), Error> {
    for reg in [0x1800, 0x4100] {
        mask(io, reg, 0xfffff, 0x33312).await?;
    }
    // Source config_rx_path(AB), config_tx_path(A,A,A,false).
    for (reg, bits, value) in [
        (0x1a2c, 0x00600000, 1),
        (0x1a2c, 0x00060000, 1),
        (0x1a04, 0x0f000000, 1),
        (0x1d30, 0x300, 1),
        (0x1d30, 0x600000, 1),
        (0xc44, 1 << 17, 1),
        (0xc54, 1 << 20, 1),
        (0xc38, 1 << 24, 1),
        (0x824, 0x0f000000, 3),
        (0x824, 0x000f0000, 3),
        (0x1a04, 0xf0000000, 8),
    ] {
        mask(io, reg, bits, value).await?;
    }
    reset(io).await?;
    mask(io, 0x820, 0xff, 0x11).await?;
    mask(io, 0x1e2c, 0xff, 0).await?;
    reset(io).await?;
    reset(io).await?;
    toggle_igi(io).await
}
pub async fn channel(io: &mut impl Io) -> Result<(), Error> {
    channel_to(io, 1).await
}
/// Linux `rtw8822c_set_channel` for one 2.4GHz/20MHz primary: `_bb`
/// (SCOTRK/TXDFIR per channel, channel14 never admitted), `rtw_set_channel_mac`,
/// `_rf` (RF18 channel byte) and `rtw8822c_toggle_igi`.
pub async fn channel_to(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    if !(1..=13).contains(&ch) {
        return Err(Error::Unsupported);
    }
    set_channel(io, ch, Width::Twenty).await
}
/// `rtw8822c_set_channel(center, RTW_CHANNEL_WIDTH_40, sc)` on 2.4GHz:
/// `sc` is `RTW_SC_20_UPPER` (1) or `RTW_SC_20_LOWER` (2).
pub async fn width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
    if !(3..=11).contains(&center) || !matches!(sc, 1 | 2) {
        return Err(Error::Unsupported);
    }
    set_channel(io, center, Width::Forty(sc)).await
}
/// Linux `rtw8822c_set_channel(ch, RTW_CHANNEL_WIDTH_20, 0)` on a 5GHz
/// primary: `_bb` 5GHz branch ([`bb_5g`]: CCK TX/RX checks on, RX IQ
/// weight, TXF4 bit20 clear, CCAMSK 0x22, TXDFIR0 3, OFDM RXAGC and SCOTRK
/// per band/channel), the BW20 tail, `rtw_set_channel_mac`, `_rf` (RF18 5GHz
/// band bits16|8, RFSI bit17 on 100..=144 / bit18 on 149..=177) and
/// `rtw8822c_toggle_igi`. A later 2.4GHz [`channel_to`] rewrites every
/// field this branch changes.
pub async fn channel5_to(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    if !band5::primary(ch) {
        return Err(Error::Unsupported);
    }
    set_channel(io, ch, Width::Twenty).await
}
/// `rtw8822c_set_channel(center, BW40|BW80, sc)` on 5GHz: the 5GHz `_bb`
/// head of the *center* channel (OFDM RXAGC by band, SCOTRK of the center),
/// the BW40 tail (CCKSB, TXBWCTL 5/sc, NBI on, SBD 1, PT_OPT 1) or BW80
/// tail (TXBWCTL 0xa/sc, SBD 6, PT_OPT 1; CCKSB, NBI, DFIRBW and TXCLK
/// untouched as in Linux), `rtw_set_channel_mac` (DATA_SC with TXSC_40M at
/// 80MHz, RFMOD 40/80), `_rf` (RF18 BW40 bit13 / BW80 bit12 on the center,
/// RXBB 0x10 / 0x8) and `rtw8822c_toggle_igi`. `center` must be the
/// center of a 5GHz 40MHz pair ([`band5::center40`]) or 80MHz block
/// ([`band5::center80`]).
pub async fn wide5_to(io: &mut impl Io, center: u8, width: Width) -> Result<(), Error> {
    let ok = match width {
        Width::Forty(_) => band5::is_center40(center),
        Width::Eighty(_) => band5::is_center80(center),
        Width::Twenty => false,
    };
    if !ok || !width.valid() {
        return Err(Error::Unsupported);
    }
    set_channel(io, center, width).await
}
/// `rtw8822c_set_channel_bb` 5GHz head: (reg, mask, value).
fn bb_5g(ch: u8) -> Option<[(u16, u32, u32); 9]> {
    let ofdm = band5::rxagc_ofdm8822c(ch)?;
    let scotrk = band5::scotrk8822c(ch)?;
    Some([
        (0x1a80, 1 << 18, 1),
        (0x454, 1 << 7, 1),
        (0x1a14, 0x300, 3),
        (0x1a9c, 1 << 20, 0),
        (0x1c80, 0x3f000000, 0x22),
        (0x808, 0x70, 3),
        (0x18ac, 0x1f0, ofdm),
        (0x41ac, 0x1f0, ofdm),
        (0xc30, 0xfff, scotrk),
    ])
}
/// Readback of [`channel5_to`] plus the RRSR and IGI-independent fields.
pub async fn verify_channel5(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let bb = bb_5g(ch).ok_or(Error::Unsupported)?;
    for path in 0..2u8 {
        if rf_read(io, path, 0x18).await? & 0x733ff != rf18_8822c(ch, 20) {
            return Err(Error::Prerequisite);
        }
    }
    for (reg, bits, value) in bb {
        if read(io, reg).await? & bits != value << bits.trailing_zeros() {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x9b0).await? & 0xffcf != 0
        || io.read8(0x483).await? != 0
        || read(io, 0x668).await? & 0x180 != 0
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Readback of [`wide5_to`]: RF18 of both paths, the center's 5GHz head,
/// the width tail fields Linux writes and the MAC sideband/RFMOD.
pub async fn verify_wide5(io: &mut impl Io, center: u8, width: Width) -> Result<(), Error> {
    let bb = bb_5g(center).ok_or(Error::Unsupported)?;
    for path in 0..2u8 {
        if rf_read(io, path, 0x18).await? & 0x733ff != rf18_8822c(center, width.mhz()) {
            return Err(Error::Prerequisite);
        }
    }
    for (reg, bits, value) in bb {
        if read(io, reg).await? & bits != value << bits.trailing_zeros() {
            return Err(Error::Prerequisite);
        }
    }
    let sc = u32::from(width.sc());
    let (txbw, sbd) = match width {
        Width::Forty(_) => (5, 1),
        Width::Eighty(_) => (0xa, 6),
        Width::Twenty => return Err(Error::Unsupported),
    };
    if read(io, 0x9b0).await? & 0xffcf != txbw | (sc | sc << 4) << 8
        || (read(io, 0x88c).await? >> 12) & 15 != sbd
        || read(io, 0xcbc).await? & (1 << 21) == 0
        || matches!(width, Width::Forty(_))
            && ((read(io, 0x1a00).await? >> 4) & 1 != u32::from(sc == 1)
                || read(io, 0x1abc).await? & (1 << 30) == 0)
        || io.read8(0x483).await? != width.data_sc()
        || (read(io, 0x668).await? >> 7) & 3 != width.rfmod()
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// RF18 bits under mask 0x733ff that Linux `rtw8822c_set_channel_rf`
/// programs: band (5GHz bits16|8), channel byte, RFSI (`IS_CH_5G_BAND_3`
/// bit17, `_4` bit18) and BW (20MHz bits13:12 = 3, 40MHz bit13, 80MHz
/// bit12).
pub const fn rf18_8822c(ch: u8, bw_mhz: u8) -> u32 {
    let band = if ch <= 14 { 0 } else { 1 << 16 | 1 << 8 };
    let rfsi = match band5::band(ch) {
        Some(4) => 1 << 18,
        Some(3) => 1 << 17,
        _ => 0,
    };
    let bw = match bw_mhz {
        40 => 2 << 12,
        80 => 1 << 12,
        _ => 3 << 12,
    };
    band | rfsi | bw | ch as u32
}
async fn set_channel(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    if let Some(bb) = bb_5g(ch) {
        for (reg, bits, value) in bb {
            mask(io, reg, bits, value).await?;
        }
    } else {
        if matches!(width, Width::Eighty(_)) {
            return Err(Error::Unsupported);
        }
        bb_2g(io, ch, width != Width::Twenty).await?;
    }
    set_channel_tail(io, ch, width).await
}
async fn bb_2g(io: &mut impl Io, ch: u8, wide: bool) -> Result<(), Error> {
    if !(1..=13).contains(&ch) {
        return Err(Error::Unsupported);
    }
    // rtw8822c_set_channel_bb 2.4GHz: RXAGC CCK/OFDM 5/6 at BW20, 4/0 at BW40.
    let (cck, ofdm) = if wide { (4, 0) } else { (5, 6) };
    for (reg, bits, value) in [
        (0x1a14, 0x300, 0),
        (0x1a9c, 1 << 20, 1),
        (0x454, 1 << 7, 0),
        (0x1a80, 1 << 18, 0),
        (0x1c80, 0x3f000000, 15),
        (0x18ac, 0xf000, cck),
        (0x41ac, 0xf000, cck),
        (0x18ac, 0x1f0, ofdm),
        (0x41ac, 0x1f0, ofdm),
        (0xc30, 0xfff, scotrk(ch)),
        (0x1a20, 0xffff0000, 0x5284),
        (0x1a24, u32::MAX, 0x3e18fec8),
        (0x1a28, 0xffff, 0x0a88),
        (0x1a98, 0xffff0000, 0xacc4),
        (0x1a9c, 0xffff, 0xc8b2),
        (0x1aa0, u32::MAX, 0x00faf0de),
        (0x1aac, u32::MAX, 0x00122344),
        (0x1ab0, u32::MAX, 0x0fffffff),
        (0x808, 0x70, txdfir(ch)),
    ] {
        mask(io, reg, bits, value).await?;
    }
    Ok(())
}
async fn set_channel_tail(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    match width {
        Width::Twenty => {
            for (reg, bits, value) in [
                (0x810, 0x3ff0, 0x19b),
                (0x9b0, 15, 0),
                (0x9b0, 0xffc0, 0),
                (0x9b4, 0x700, 7),
                (0x9b4, 0x700000, 6),
                (0x1abc, 1 << 30, 0),
                (0x88c, 0xf000, 1),
                (0xcbc, 1 << 21, 0),
            ] {
                mask(io, reg, bits, value).await?;
            }
        }
        Width::Eighty(sc) => {
            let sc = u32::from(sc);
            for (reg, bits, value) in [
                (0x9b0, 15, 0xa),
                (0x9b0, 0xc0, 0),
                (0x9b0, 0xff00, sc | sc << 4),
                (0x88c, 0xf000, 6),
                (0xcbc, 1 << 21, 1),
            ] {
                mask(io, reg, bits, value).await?;
            }
        }
        Width::Forty(sc) => {
            let sc = u32::from(sc);
            for (reg, bits, value) in [
                (0x1a00, 1 << 4, u32::from(sc == 1)),
                (0x9b0, 15, 5),
                (0x9b0, 0xc0, 0),
                (0x9b0, 0xff00, sc | sc << 4),
                (0x1abc, 1 << 30, 1),
                (0x88c, 0xf000, 1),
                (0xcbc, 1 << 21, 1),
            ] {
                mask(io, reg, bits, value).await?;
            }
        }
    }
    // rtw_set_channel_mac: DATA_SC txsc20 (txsc40 only at 80MHz), RFMOD.
    io.write8(0x483, width.data_sc()).await?;
    mask(io, 0x668, 0x180, width.rfmod()).await?;
    mask(io, 0x24, 3 << 20, 0).await?;
    io.write8(0x55c, 80).await?;
    io.write8(0x638, 80).await?;
    let check = io.read8(0x454).await?;
    if check == 255 {
        return Err(Error::Gone);
    }
    // BIT_CHECK_CCK_EN is set only on a 5GHz channel (`IS_CH_5G_BAND`).
    let cck_check = u8::from(band5::band(ch).is_some()) << 7;
    io.write8(0x454, (check & !(1 << 7)) | cck_check).await?;
    // rtw8822c_set_channel_rf: RF18 BW 20M=bits13:12 3, 40M=bit13; RXBB.
    // RF18 BW 80M=bit12, RXBB 0x8.
    let (bw, rxbb) = match width {
        Width::Twenty => (20, 0x18),
        Width::Forty(_) => (40, 0x10),
        Width::Eighty(_) => (80, 0x8),
    };
    let reg18 = (rf_read(io, 0, 0x18).await?
        & !((1 << 16) | (1 << 9) | (1 << 8) | 255 | (3 << 17) | (3 << 12)))
        | rf18_8822c(ch, bw);
    mask(io, 0x1c90, 1 << 8, 0).await?;
    for path in 0..2 {
        rf(io, path, 0xee, 4, 1).await?;
        rf(io, path, 0x33, 31, 0x12).await?;
        rf(io, path, 0x3f, 0xfffff, rxbb).await?;
        rf(io, path, 0xee, 4, 0).await?;
    }
    for path in 0..2 {
        rf(io, path, 0x18, 0xfffff, reg18).await?;
    }
    mask(io, 0x1c90, 1 << 8, 1).await?;
    mask(io, 0x1830, 1 << 29, 1).await?;
    mask(io, 0x4130, 1 << 29, 1).await?;
    toggle_igi(io).await
}
/// Readback of [`width40`] plus the per-path CCK references.
pub async fn verify_width40(
    io: &mut impl Io,
    center: u8,
    sc: u8,
    gains: [u8; 2],
) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        if rf_read(io, path as u8, 0x18).await? & 0x733ff != 0x2000 | u32::from(center)
            || (read(io, if path == 0 { 0x18a0 } else { 0x41a0 }).await? >> 16) & 127
                != u32::from(gain)
        {
            return Err(Error::Prerequisite);
        }
    }
    let sc = u32::from(sc);
    if read(io, 0xc30).await? & 0xfff != scotrk(center)
        || (read(io, 0x808).await? >> 4) & 7 != txdfir(center)
        || read(io, 0x9b0).await? & 0xffcf != 5 | (sc | sc << 4) << 8
        || (read(io, 0x1a00).await? >> 4) & 1 != u32::from(sc == 1)
        || read(io, 0x1abc).await? & (1 << 30) == 0
        || read(io, 0xcbc).await? & (1 << 21) == 0
        || u32::from(io.read8(0x483).await?) != sc
        || read(io, 0x668).await? & 0x180 != 0x80
        || read(io, 0x18ac).await? & 0xf1f0 != 0x4000
        || read(io, 0x41ac).await? & 0xf1f0 != 0x4000
        || read(io, 0x440).await? != 0x1f
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
