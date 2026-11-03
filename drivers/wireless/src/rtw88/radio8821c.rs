// SPDX-License-Identifier: GPL-2.0-or-later
//! C21 ch1/20 IQK and separately qualified awake radio continuations.
//! Linux rtw8821c.c/fw.c/mac.c/ps.c; the IQK envelope alone grants no packets.
use super::{
    band5::Width,
    calibration8821c::Envelope,
    efuse::Factory8821c,
    firmware_transport::{Error, Io},
    mac, phy8821c,
};
use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub channel: u8,
    pub bandwidth_mhz: u8,
    pub thermal_before: u8,
    pub thermal_after: u8,
    pub swing: u16,
    pub iqk_status: u32,
}
// rtw8821c_set_tx_power_index_by_rate: CCK, OFDM, HT1S and VHT1S words.
// Minimum coded indices are a deterministic calibration setup, never a dBm
// claim. The measured envelope must cover the firmware's own IQK power too.
const TXAGC: [u16; 8] = [
    0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
];
/// rtw8821c_set_tx_power_index_by_rate packs four source rate indices per
/// word at RF-A1d00. C22's reference/difference registers are unrelated.
/// RF-A RF18 bits under mask 0x70fff that Linux `rtw8821c_set_channel_rf`
/// programs: band (2.4GHz 0, 5GHz bits 16|8), channel byte, RFSI (bit17 on
/// 100..=140, bit18 above 140) and BW (20MHz bits 11:10 = 3, 40MHz bit11,
/// 80MHz bit10). `channel` is the RF center; `bw_mhz` other than 40/80 is 20.
pub(super) const fn rf18_for(channel: u8, bw_mhz: u8) -> u32 {
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
/// `channel` is the committed 20MHz primary whose RF18 the retune (or the
/// channel-1 base program) left in place.
pub(super) async fn operating_readback(
    read: impl super::firmware_transport::Read32,
    indices: [u8; 12],
    channel: u8,
) -> Result<(), Error> {
    operating_readback_ht(read, indices, [0; 8], channel).await
}
pub(super) async fn operating_readback_ht(
    read: impl super::firmware_transport::Read32,
    indices: [u8; 12],
    mcs: [u8; 8],
    channel: u8,
) -> Result<(), Error> {
    operating_readback_rf18(read, indices, mcs, [0; 12], rf18_for(channel, 20)).await
}
/// [`operating_readback_ht`] at the N2xB 40MHz pair: HT words are the HT40
/// selection and RF18 is BW40 (bit11) on the center channel.
pub(super) async fn operating_readback_wide(
    read: impl super::firmware_transport::Read32,
    indices: [u8; 12],
    mcs: [u8; 8],
    center: u8,
) -> Result<(), Error> {
    operating_readback_rf18(read, indices, mcs, [0; 12], rf18_for(center, 40)).await
}
/// [`operating_readback_ht`] at the N2xV 80MHz block: HT words keep the HT20
/// selection, the VHT words 0x1d2c..0x1d34 carry the record's VHT1SS
/// MCS0..9 (`vht::write_power`) and RF18 is BW80 (bit10) on the center.
pub(super) async fn operating_readback_vht(
    read: impl super::firmware_transport::Read32,
    indices: [u8; 12],
    mcs: [u8; 8],
    vht: [u8; 12],
    center: u8,
) -> Result<(), Error> {
    operating_readback_rf18(read, indices, mcs, vht, rf18_for(center, 80)).await
}
async fn operating_readback_rf18(
    mut read: impl super::firmware_transport::Read32,
    indices: [u8; 12],
    mcs: [u8; 8],
    vht: [u8; 12],
    rf18: u32,
) -> Result<(), Error> {
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let expected = if slot < 3 {
            u32::from_le_bytes(
                indices[slot * 4..slot * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        } else if slot < 5 {
            u32::from_le_bytes(
                mcs[(slot - 3) * 4..(slot - 3) * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        } else {
            u32::from_le_bytes(
                vht[(slot - 5) * 4..(slot - 5) * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        };
        if read.read32(reg).await? != expected {
            return Err(Error::Prerequisite);
        }
    }
    if read.read32(0x2860).await? & 0x70fff != rf18
        || read.read32(0x2820).await? & 0xfffff != 0
        || read.read32(0x1bf0).await? & 0x100ff != 0
        || read.read32(0x100).await? & 0x200 != 0
        || read.read32(0x680).await? & 0xcf != 0
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
const BB_2G: [(u16, u32, u32); 6] = [
    (0x808, 1 << 28, 1),
    (0x454, 1 << 7, 0),
    (0xa80, 1 << 18, 0),
    (0x814, 0xfc00, 15),
    (0xc1c, 0xf00, 0),
    (0x860, 0x1ffe0000, 0x96a),
];
const DFIR: [(u16, u32, u32); 4] = [
    (0x948, 3 << 28, 2),
    (0x94c, 3 << 28, 2),
    (0xc20, 1 << 31, 1),
    (0x8f0, 1 << 31, 0),
];
pub(super) fn bind_recipe(hash: &mut narf_crypto::sha256::Sha256) {
    hash.update(b"US non-SRRC; C21 RF-A SIPI c90 direct-read2800; source switch/calibration v2");
    hash.update(b"RF42 mask30000 trigger3; 2000000us source watchdog conversion before/after IQK");
    for (reg, mask, value) in BB_2G.into_iter().chain(DFIR) {
        hash.update(&reg.to_le_bytes());
        hash.update(&mask.to_le_bytes());
        hash.update(&value.to_le_bytes());
    }
    for reg in TXAGC {
        hash.update(&reg.to_le_bytes());
        hash.update(&0u32.to_le_bytes());
    }
    hash.update(&[0, 3, 6, 9]); // raw factory swing bins; no erased fallback.
    hash.update(&[0x00, 0x02, 0x6a, 0x01, 0x01, 0x01, 0xb6, 0x00]); // 0x200,16a,101,b6
}
async fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
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
pub(super) async fn rf_read(io: &mut impl Io, address: u8) -> Result<u32, Error> {
    Ok(read(io, 0x2800 + u16::from(address) * 4).await? & 0xfffff)
}
pub(super) async fn rf(io: &mut impl Io, address: u8, bits: u32, value: u32) -> Result<(), Error> {
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
async fn temperature(io: &mut impl Io, envelope: &Envelope) -> Result<u8, Error> {
    let value = ((rf_read(io, 0x42).await? & 0xfc00) >> 10) as u8;
    envelope
        .temperature(value)
        .map_err(Error::Calibration8821c)?;
    Ok(value)
}
/// rtw8821c_pwr_track triggers RF42[17:16]=3 on one watchdog pass and
/// consumes RF42[15:10] on the following pass (main.h:2-second interval).
/// There is no documented conversion-done bit: preserve that source wait,
/// then read the actual meter. A cached pre-trigger value is no fresh sample.
async fn convert_temperature(io: &mut impl Io, envelope: &Envelope) -> Result<u8, Error> {
    let old = rf_read(io, 0x42).await?;
    io.write32(0xc90, (0x42 << 20) | (old & !0x30000) | 0x30000)
        .await?;
    io.delay_us(13).await;
    io.delay_us(2_000_000).await;
    temperature(io, envelope).await
}
async fn channel(
    io: &mut impl Io,
    factory: &Factory8821c,
    phy: phy8821c::Info,
) -> Result<u16, Error> {
    for (reg, bits, value) in BB_2G {
        mask(io, reg, bits, value).await?;
    }
    io.write32(0xa24, phy.channel_filters[0]).await?;
    mask(io, 0xa28, 0xffff, phy.channel_filters[1] & 0xffff).await?;
    io.write32(0xaac, phy.channel_filters[2]).await?;
    let adc = read(io, 0x8ac).await?;
    io.write32(0x8ac, (adc & 0xffcffc00) | 0x10010000).await?;
    mask(io, 0x8c4, 1 << 30, 1).await?;
    let swing = [0x200u16, 0x16a, 0x101, 0xb6][usize::from(factory.swing_2g() / 3)];
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
    let btg = matches!(phy.rfe, 2 | 4);
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
/// Linux `rtw8821c_set_channel` retune between 2.4GHz/20MHz primaries on the
/// retained non-SRRC C21: `_bb`, `rtw_set_channel_mac`, `_rxdfir` and
/// `_bb_swing` are identical for channels 1..=13 (source `ch_param` CCK
/// filters, swing and DFIR stay as programmed), so only `_rf` changes: RF
/// LUTDBG/0x64, the RF18 channel byte and the XTALX2 bit19 toggle.
pub(super) async fn retune_channel(io: &mut impl Io, ch: u8) -> Result<(), Error> {
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
/// Retained C21 board facts a cross-band `rtw8821c_set_channel` needs:
/// the 2.4GHz CCK TX filter words Linux reads into `hal->ch_param` at
/// `phy_set_param`, `hal->rfe_btg` (RFE 2/4) and the raw factory swing
/// bytes `tx_bb_swing_setting_{2g,5g}` (map 0xc6/0xc7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BandFacts {
    pub(super) filters: [u32; 3],
    pub(super) btg: bool,
    pub(super) swing_2g: u8,
    pub(super) swing_5g: u8,
}
impl BandFacts {
    /// `rtw8821c_get_bb_swing`. Linux maps a byte above 9 to setting 0;
    /// this owner refuses it instead of inventing a swing for an erased cell.
    pub(super) fn swing(&self, channel: u8) -> Result<u16, Error> {
        let raw = if channel <= 14 {
            self.swing_2g
        } else {
            self.swing_5g
        };
        if raw > 9 {
            return Err(Error::Prerequisite);
        }
        Ok([0x200u16, 0x16a, 0x101, 0xb6][usize::from(raw / 3)])
    }
}
/// `rtw8821c_set_channel(ch, RTW_CHANNEL_WIDTH_20, 0)` non-SRRC on either
/// band, in Linux order: `_bb` (2.4GHz: RXPSEL bit28, CCK checks off,
/// RXCCAMSK, TXSCALE 0, CLKTRK 0x96a, `ch_param` CCK filters; 5GHz: CCK
/// TX/RX checks on, RXPSEL off, RXCCAMSK, TXSCALE/CLKTRK per channel) and
/// the BW20 `set_bw`; `_bb_swing` (band's factory swing); MAC (CCK_CHECK
/// set only on 5GHz); `_rf` (`rtw8821c_switch_rf_set` BTG/WLG on 2.4GHz,
/// WLA on 5GHz; LUTDBG bit6 1 + RF 0x64 0xf on 2.4GHz, LUTDBG 0 on 5GHz;
/// RF18; XTALX2 toggle); `_rxdfir` BW20. Returns the programmed swing.
/// `rtw8821c_pwrtrack_init` only resets the software tracking state.
pub(super) async fn set_channel20(
    io: &mut impl Io,
    ch: u8,
    facts: &BandFacts,
) -> Result<u16, Error> {
    let five = super::band5::primary(ch);
    if !five && !(1..=13).contains(&ch) {
        return Err(Error::Unsupported);
    }
    set_channel(io, ch, Width::Twenty, facts).await
}
/// `rtw8821c_set_channel(center, BW40|BW80, sc)` non-SRRC on 5GHz, in
/// Linux order: the 5GHz `_bb` head of the *center* channel (TXSCALE and
/// CLKTRK by center), `set_bw` BW40 (RXSB 0xa00[4] for sc 1, ADCCLK
/// `&0xff3ff300 | 0x20020000 | sc<<2 | 1`, ADC160[30]) or BW80 (ADCCLK
/// `&0xfcffcf00 | 0x40040000 | sc<<2 | 2`, ADC160[30]), `_bb_swing` (5GHz
/// factory swing), `rtw_set_channel_mac` (DATA_SC, RFMOD), `_rf` (WLA,
/// LUTDBG 0, RF18 BW40 bit11 / BW80 bit10 on the center, XTALX2 toggle)
/// and `_rxdfir` BW40 / BW80. Returns the programmed swing.
pub(super) async fn wide5(
    io: &mut impl Io,
    center: u8,
    width: Width,
    facts: &BandFacts,
) -> Result<u16, Error> {
    let ok = match width {
        Width::Forty(_) => super::band5::is_center40(center),
        Width::Eighty(_) => super::band5::is_center80(center),
        Width::Twenty => false,
    };
    if !ok || !width.valid() {
        return Err(Error::Unsupported);
    }
    set_channel(io, center, width, facts).await
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
    facts: &BandFacts,
) -> Result<u16, Error> {
    let five = super::band5::band(ch).is_some();
    if !five && width != Width::Twenty {
        return Err(Error::Unsupported);
    }
    let swing = facts.swing(ch)?;
    if five {
        // Head of the RF center channel (`channel` is the center at 40/80).
        let txscale = super::band5::txscale8821c(ch).ok_or(Error::Unsupported)?;
        let clktrk = super::band5::clktrk8821c(ch).ok_or(Error::Unsupported)?;
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
        io.write32(0xa24, facts.filters[0]).await?;
        mask(io, 0xa28, 0xffff, facts.filters[1] & 0xffff).await?;
        io.write32(0xaac, facts.filters[2]).await?;
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
        let btg = facts.btg;
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
/// Readback of [`set_channel20`] (band-dependent fields, RF18, swing).
pub(super) async fn verify_channel20(
    io: &mut impl Io,
    ch: u8,
    facts: &BandFacts,
) -> Result<(), Error> {
    let swing = facts.swing(ch)?;
    if !super::band5::primary(ch) {
        verify_geometry_at(io, ch, swing, facts.btg).await?;
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
    let txscale = super::band5::txscale8821c(ch).ok_or(Error::Unsupported)?;
    let clktrk = super::band5::clktrk8821c(ch).ok_or(Error::Unsupported)?;
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
/// Readback of [`wide5`]: RF18 at the center and width, the center's
/// 5GHz head, swing, `set_bw` ADCCLK/RXSB, MAC DATA_SC/RFMOD, WLA and
/// `_rxdfir`.
pub(super) async fn verify_wide5(
    io: &mut impl Io,
    center: u8,
    width: Width,
    facts: &BandFacts,
) -> Result<(), Error> {
    let swing = facts.swing(center)?;
    let txscale = super::band5::txscale8821c(center).ok_or(Error::Unsupported)?;
    let clktrk = super::band5::clktrk8821c(center).ok_or(Error::Unsupported)?;
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
/// `rtw8821c_set_channel(center, RTW_CHANNEL_WIDTH_40, sc)` on the retained
/// non-SRRC C21. The 2.4GHz `_bb` head and `_bb_swing` are identical for
/// every 2.4GHz channel (left as programmed); the BW40 `set_bw` branch
/// (RXSB bit4 for `RTW_SC_20_UPPER`, ADCCLK, ADC160), `rtw_set_channel_mac`
/// (DATA_SC, RFMOD_40M), `_rf` (RF18 BW40 bit11 + center, XTALX2 toggle)
/// and `_rxdfir` BW40 run.
pub(super) async fn width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
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
pub(super) async fn verify_width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
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
/// `rtw8821c_set_tx_power_index_by_rate` for the retained CCK/OFDM words;
/// HT/VHT words stay zero (no HT program on a noninitial channel).
pub(super) async fn write_txagc(io: &mut impl Io, indices: [u8; 12]) -> Result<(), Error> {
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let value = if slot < 3 {
            u32::from_le_bytes(
                indices[slot * 4..slot * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        } else {
            0
        };
        io.write32(reg, value).await?;
    }
    Ok(())
}
pub(super) async fn verify_retune(
    io: &mut impl Io,
    ch: u8,
    indices: [u8; 12],
) -> Result<(), Error> {
    if rf_read(io, 0x18).await? & 0x70fff != rf18_for(ch, 20) {
        return Err(Error::Prerequisite);
    }
    verify_txagc(io, indices, 0x1f).await
}
/// TXAGC words of [`write_txagc`], REG_RRSR `rrsr` and the clean IQK
/// report (0x1bf0).
pub(super) async fn verify_txagc(
    io: &mut impl Io,
    indices: [u8; 12],
    rrsr: u32,
) -> Result<(), Error> {
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let expected = if slot < 3 {
            u32::from_le_bytes(
                indices[slot * 4..slot * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        } else {
            0
        };
        if read(io, reg).await? != expected {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x440).await? != rrsr || read(io, 0x1bf0).await? & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
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
/// 2.4GHz/20MHz geometry on primary `ch`; TXPAUSE must still be 0xff.
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

/// Historical native preparation receipts; packet admission also requires the
/// retained current N21Q/N21P/N21S grants, not this copyable diagnostic value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StationInfo {
    pub channel: u8,
    pub bandwidth_mhz: u8,
    pub thermal: u8,
    pub response_rates: u16,
    pub identity: [u8; 32],
}
pub(super) async fn prepare_station(
    io: &mut impl Io,
    factory: &Factory8821c,
    phy: phy8821c::Info,
    iqk: Info,
    power: super::operating8821c::Info,
    grant: alloc::sync::Arc<super::station_power8821c::Grant>,
) -> Result<StationInfo, Error> {
    let mut io = StationChecked { io, grant: &grant };
    io.begin_station8821c()?;
    // C21's exact channel/RFE setup is retained from its completed IQK. Do
    // not replay the channel helper here: it deliberately zeros all TXAGC.
    verify_geometry(&mut io, iqk.swing, matches!(phy.rfe, 2 | 4)).await?;
    if read(&mut io, 0xf0).await? >> 12 & 15 != u32::from(phy.cut)
        || rf_read(&mut io, 8).await? != 0
        || read(&mut io, 0x1bf0).await? & 0x100ff != 0
        || factory.mac() != grant.own()
    {
        return Err(Error::Prerequisite);
    }
    let old = rf_read(&mut io, 0x42).await?;
    io.write32(0xc90, (0x42 << 20) | (old & !0x30000) | 0x30000)
        .await?;
    io.delay_us(13).await;
    io.delay_us(2_000_000).await;
    let thermal = ((rf_read(&mut io, 0x42).await? >> 10) & 63) as u8;
    grant.temperature(thermal)?;
    for (slot, reg) in TXAGC.into_iter().enumerate() {
        let expected = if slot < 3 {
            u32::from_le_bytes(
                power.indices[slot * 4..slot * 4 + 4]
                    .try_into()
                    .map_err(|_| Error::State)?,
            )
        } else {
            0
        };
        if read(&mut io, reg).await? != expected {
            return Err(Error::Prerequisite);
        }
    }
    // Source rtw8821c band switch also admits OFDM response rates. This
    // initial station uses CCK1 data/management and the same conservative
    // response mask as the existing source rtw88 legacy station profile.
    io.write32(0x440, 0x1f).await?;
    super::radio::software_crypto(&mut io).await?;
    super::radio::awake(&mut io).await?;
    verify_geometry(&mut io, iqk.swing, matches!(phy.rfe, 2 | 4)).await?;
    if read(&mut io, 0x440).await? != 0x1f
        || io.read8(0x303).await? & 0xf7 != 0xf7
        || io.read32(0xb0).await.ok() != Some(0)
        || io.read32(0xb8).await.ok() != Some(0)
        || io.read32(0x10b8).await.ok() != Some(0)
    {
        return Err(Error::Prerequisite);
    }
    grant.temperature(((rf_read(&mut io, 0x42).await? >> 10) & 63) as u8)?;
    io.finish_station8821c(super::power_policy::Gate::c21(grant.clone()))?;
    Ok(StationInfo {
        channel: 1,
        bandwidth_mhz: 20,
        thermal,
        response_rates: 0x1f,
        identity: grant.identity(),
    })
}
struct StationChecked<'a, I> {
    io: &'a mut I,
    grant: &'a super::station_power8821c::Grant,
}
#[async_trait::async_trait]
// SAFETY: the retained backend owns every published buffer, and every native
// register operation executes inside all three current signed source invokes.
unsafe impl<I: Io> Io for StationChecked<'_, I> {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn read8(&mut self, r: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.read8(r))
    }
    fn read16(&mut self, r: u16) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.read16(r))
    }
    fn read32(&mut self, r: u16) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.read32(r))
    }
    fn write8(
        &mut self,
        r: u16,
        v: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.write8(r, v))
    }
    fn write16(
        &mut self,
        r: u16,
        v: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.write16(r, v))
    }
    fn write32(
        &mut self,
        r: u16,
        v: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let grant = self.grant;
        super::firmware_transport::enclosed(move |op| grant.invoke(op), self.io.write32(r, v))
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::State)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        self.grant.invoke(|| self.io.begin_station8821c())
    }
    fn finish_station8821c(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        self.grant.invoke(|| self.io.finish_station8821c(gate))
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await
    }
}
pub(super) async fn prepare(
    io: &mut impl Io,
    factory: &Factory8821c,
    mac: mac::Info,
    phy: phy8821c::Info,
    envelope: &Envelope,
) -> Result<Info, Error> {
    io.begin_calibration8821c()?;
    let cfg = read(io, 0xf0).await?;
    if cfg & (1 << 27) != 0 || (cfg >> 12) & 15 != u32::from(phy.cut) {
        return Err(Error::Unsupported);
    }
    let thermal_before = convert_temperature(io, envelope).await?;
    let swing = channel(io, factory, phy).await?;
    // A stale marker cannot establish this attempt's completion. Source C21
    // clear=0 is retained; do not clear a stale done receipt to make it fresh.
    if rf_read(io, 8).await? == 0xabcde {
        return Err(Error::Prerequisite);
    }
    io.begin_commands()?;
    super::command::send(io, &super::command::general(mac, 0)?).await?;
    super::command::send(io, &super::command::phydm8821c(phy, 1)?).await?;
    super::command::send(io, &super::command::iqk8821c(2)).await?;
    let mut completed = false;
    for attempt in 0..300 {
        temperature(io, envelope).await?;
        if rf_read(io, 8).await? == 0xabcde {
            completed = true;
            break;
        }
        if attempt < 299 {
            io.delay_us(20000).await;
        }
    }
    if !completed {
        return Err(Error::Timeout);
    }
    rf(io, 8, 0xfffff, 0).await?;
    let status = read(io, 0x1bf0).await?;
    // Linux reports these diagnostics; this initial hardware-testing profile
    // additionally refuses failed or reloaded results as a fresh IQK receipt.
    if status & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    let thermal_after = convert_temperature(io, envelope).await?;
    verify_channel(io, swing, matches!(phy.rfe, 2 | 4)).await?;
    io.park_radio().await?;
    io.finish_calibration8821c()?;
    Ok(Info {
        channel: 1,
        bandwidth_mhz: 20,
        thermal_before,
        thermal_after,
        swing,
        iqk_status: status,
    })
}

/// Encloses every native operation in a measured calibration envelope (C21
/// `N21Q` by default; B22 `N2BQ` through `calibration8822b`).
pub(super) struct Checked<'a, I, F, E = Envelope> {
    pub io: &'a mut I,
    pub envelope: &'a E,
    pub policy: F,
}
#[async_trait::async_trait]
// SAFETY: current measured authority/policy encloses every underlying native
// operation; the retained backend alone owns DMA and its terminal receipts.
unsafe impl<I: Io, F, E: super::calibration8821c::Enclosure> Io for Checked<'_, I, F, E>
where
    F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
{
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn read8(&mut self, r: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(move |op| envelope.invoke(policy, op), self.io.read8(r))
    }
    fn read16(&mut self, r: u16) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.read16(r),
        )
    }
    fn read32(&mut self, r: u16) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.read32(r),
        )
    }
    fn write8(
        &mut self,
        r: u16,
        v: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.write8(r, v),
        )
    }
    fn write16(
        &mut self,
        r: u16,
        v: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.write16(r, v),
        )
    }
    fn write32(
        &mut self,
        r: u16,
        v: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.write32(r, v),
        )
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::State)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.begin_calibration8821c())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.begin_commands())
    }
    fn submit_h2c(
        &mut self,
        p: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.submit_h2c(p),
        )
    }
    fn poll_h2c(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.poll_h2c(),
        )
    }
    fn park_radio(&mut self) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        let (envelope, policy) = (self.envelope, &self.policy);
        super::firmware_transport::enclosed(
            move |op| envelope.invoke(policy, op),
            self.io.park_radio(),
        )
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.finish_calibration8821c())
    }
    // The B22 awake-station program (`radio8822b::prepare_station`) runs
    // through this adapter enclosed by its `N2BS` grant.
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.begin_station8821c())
    }
    fn finish_station8821c(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.finish_station8821c(gate))
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
}
