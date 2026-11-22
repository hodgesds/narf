// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") BB/RF register programming after the PHY tables, generic
//! over [`RegIo`]: the `rtw8822b_phy_set_param` tail (`finish_set_param`), the
//! `rtw8822b_set_channel` program and the measured readback checks. No step
//! opens MAC TX/RX, releases TXPAUSE or submits H2C; RF access uses the 8822B
//! direct window (0x2800/0x2c00) and SIPI writes.
//!
//! The command/mailbox/envelope-coupled calibration and station steps stay in
//! the consuming crate and call these sequences over the bridge.
use super::{mask, read};
use crate::band5::Width;
use crate::{ChipError as Error, RegIo as Io};

/// `BB_PATH_A | BB_PATH_B`: `rtw_hal` 2T2R antenna_tx/antenna_rx.
pub const PATH_AB: u8 = 3;
/// `rtw8822b_txscale_tbl`.
pub const TXSCALE: [u32; 37] = [
    0x081, 0x088, 0x090, 0x099, 0x0a2, 0x0ac, 0x0b6, 0x0c0, 0x0cc, 0x0d8, 0x0e5, 0x0f2, 0x101,
    0x110, 0x120, 0x131, 0x143, 0x156, 0x16a, 0x180, 0x197, 0x1af, 0x1c8, 0x1e3, 0x200, 0x21e,
    0x23e, 0x261, 0x285, 0x2ab, 0x2d3, 0x2fe, 0x32b, 0x35c, 0x38e, 0x3c4, 0x3fe,
];
/// `rtw_phy_write_rf_reg_sipi` RF aperture (`RF_SIPI`).
const RF_SIPI: [u16; 2] = [0x0c90, 0x0e90];
/// `bf.c` registers used by `rtw8822b_phy_bf_init` (`rtw_bf_phy_init`).
const REG_MU_TX_CTL: u16 = 0x14c0;
const REG_WMAC_MU_BF_OPTION: u16 = 0x167c;
const REG_WMAC_MU_BF_CTL: u16 = 0x1680;
const REG_TXBF_CTRL: u16 = 0x042c;
const REG_NDPA_OPT_CTRL: u16 = 0x045f;
const REG_BBPSF_CTRL: u16 = 0x06dc;
const DESC_RATE6M: u32 = 4;

/// The factory-selected B22 profile the register programming needs (`rfe`
/// selects the `rtw8822b_rfe_info` entry, `cut` the CCA variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct B22Params {
    pub cut: u8,
    pub rfe: u8,
}

/// Software state the `rtw8822b_phy_set_param` tail derives from hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Init {
    /// `rtw_phy_init`: `dm_info->igi_history[0]` from `rtw8822b_dig[0]`
    /// (0xc50 & 0x7f).
    pub igi: u8,
    /// `rtw8822b_pwrtrack_init`: `default_ofdm_index` (24 if 0xc1c[31:21]
    /// is not a `rtw8822b_txscale_tbl` value).
    pub default_ofdm_index: u8,
}

/// `rtw_phy_write_rf_reg_sipi` for 8822B (RF0/RF1 SIPI aperture).
pub async fn rf_write(io: &mut impl Io, path: u8, address: u16, data: u32) -> Result<(), Error> {
    if path > 1 || data & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    let word = ((u32::from(address & 0xff) << 20) | data) & 0x0fff_ffff;
    io.write32(RF_SIPI[usize::from(path)], word).await?;
    io.delay_us(13).await;
    Ok(())
}
/// `rtw_phy_read_rf` over `rf_base_addr` with the full `RFREG_MASK`.
async fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
    let base: u16 = match path {
        0 => 0x2800,
        1 => 0x2c00,
        _ => return Err(Error::Unsupported),
    };
    Ok(read(io, base + (u16::from(address) << 2)).await? & 0xfffff)
}
/// `rtw_phy_write_rf_reg_sipi`: a partial mask merges the direct readback.
async fn rf(io: &mut impl Io, path: u8, address: u8, bits: u32, value: u32) -> Result<(), Error> {
    if path > 1 || bits == 0 || bits & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    let shifted = value
        .checked_shl(bits.trailing_zeros())
        .ok_or(Error::Unsupported)?;
    if shifted & !bits != 0 {
        return Err(Error::Unsupported);
    }
    let data = if bits == 0xfffff {
        value
    } else {
        rf_read(io, path, address).await? & !bits | shifted
    };
    rf_write(io, path, u16::from(address), data).await
}
/// `_rtw_write32s_mask`: 0xc00-0xcff and 0xe00-0xeff share a layout.
async fn mask_s(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if !(0xc00..0xd00).contains(&reg) {
        return Err(Error::Unsupported);
    }
    mask(io, reg, bits, value).await?;
    mask(io, reg + 0x200, bits, value).await
}
const fn rfe_efem(rfe: u8) -> Result<bool, Error> {
    match rfe {
        2 => Ok(true),
        3 | 5 => Ok(false),
        _ => Err(Error::Unsupported),
    }
}

/// `rtw8822b_toggle_igi`.
async fn toggle_igi(io: &mut impl Io, rx: u8) -> Result<(), Error> {
    let igi = read(io, 0xc50).await? & 0x7f;
    let low = igi.wrapping_sub(2) & 0x7f;
    mask(io, 0xc50, 0x7f, low).await?;
    mask(io, 0xc50, 0x7f, igi).await?;
    mask(io, 0xe50, 0x7f, low).await?;
    mask(io, 0xe50, 0x7f, igi).await?;
    mask(io, 0x808, 0xff, 0).await?;
    mask(io, 0x808, 0xff, u32::from(rx | rx << 4)).await
}

/// `rtw8822b_set_channel_rfe_efem` / `_ifem`. Linux tests `IS_CH_2G_BAND`
/// (`channel <= 14`), so channel 0 (no channel yet set) selects 2.4 GHz.
async fn rfe(
    io: &mut impl Io,
    params: B22Params,
    channel: u8,
    tx: u8,
    rx: u8,
) -> Result<(), Error> {
    let efem = rfe_efem(params.rfe)?;
    let two_g = channel <= 14;
    match (efem, two_g) {
        (true, true) => {
            mask_s(io, 0xcb0, 0xffffff, 0x705770).await?;
            mask_s(io, 0xcb4, 0xff00, 0x57).await?;
            mask_s(io, 0xcb8, 1 << 4, 0).await?;
        }
        (true, false) => {
            mask_s(io, 0xcb0, 0xffffff, 0x177517).await?;
            mask_s(io, 0xcb4, 0xff00, 0x75).await?;
            mask_s(io, 0xcb8, 1 << 5, 0).await?;
        }
        (false, true) => {
            mask_s(io, 0xcb0, 0xffffff, 0x745774).await?;
            mask_s(io, 0xcb4, 0xff00, 0x57).await?;
        }
        (false, false) => {
            mask_s(io, 0xcb0, 0xffffff, 0x477547).await?;
            mask_s(io, 0xcb4, 0xff00, 0x75).await?;
        }
    }
    mask_s(io, 0xcbc, 0xc00 | 0x3f, 0).await?;
    let trsw = if !efem && !two_g {
        0xa5a5
    } else if rx == PATH_AB || tx == PATH_AB {
        0xa501
    } else if rx == tx {
        0xa500
    } else {
        0xa005
    };
    mask_s(io, 0xca0, 0xffff, trsw).await
}

/// `cca_ifem_ccut`, `cca_efem_ccut`, `cca_ifem_ccut_ext`: (82c, 830, 838)
/// per `CCUT_IDX_{1R_2G, 2R_2G, 1R_5G, 2R_5G}`.
const CCA_IFEM: [[u32; 4]; 3] = [
    [0x75C97010, 0x75C97010, 0x75C97010, 0x75C97010],
    [0x79a0eaaa, 0x79A0EAAC, 0x79a0eaaa, 0x79a0eaaa],
    [0x87765541, 0x87746341, 0x87765541, 0x87746341],
];
const CCA_EFEM: [[u32; 4]; 3] = [
    [0x75B86010, 0x75B76010, 0x75B86010, 0x75B76010],
    [0x79A0EAA8, 0x79A0EAAC, 0x79A0EAA8, 0x79a0eaaa],
    [0x87766451, 0x87766431, 0x87766451, 0x87766431],
];
const CCA_IFEM_EXT: [[u32; 4]; 3] = [
    [0x75da8010, 0x75da8010, 0x75da8010, 0x75da8010],
    [0x79a0eaaa, 0x97A0EAAC, 0x79a0eaaa, 0x79a0eaaa],
    [0x87765541, 0x86666341, 0x87765561, 0x86666361],
];
const fn is_5g_mid(ch: u8) -> bool {
    matches!(ch, 52..=64 | 100..=144)
}

/// `rtw8822b_set_channel_cca` (`cut_version` B is 1).
async fn cca(
    io: &mut impl Io,
    params: B22Params,
    channel: u8,
    width: Width,
    rx: u8,
) -> Result<(), Error> {
    let efem = rfe_efem(params.rfe)?;
    let two_g = channel <= 14;
    // rtw8822b_rfe_info[2] = I2GE5G (2 GHz ifem, 5 GHz efem); [3]/[5] ext.
    let table = match (efem, two_g) {
        (true, true) => &CCA_IFEM,
        (true, false) => &CCA_EFEM,
        (false, _) => &CCA_IFEM_EXT,
    };
    let one = rx == 1 || rx == 2;
    let col = match (two_g, one) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let (is_ifem, is_efem) = if efem { (two_g, !two_g) } else { (true, false) };
    let ext = !efem;
    let forty = matches!(width, Width::Forty(_));
    let mut r830 = table[1][col];
    if is_ifem
        && ((params.cut == 1 && matches!(col, 1 | 3) && forty)
            || (!ext && col == 3 && forty)
            || (params.rfe == 5 && col == 3))
    {
        r830 = 0x79a0ea28;
    }
    mask(io, 0x82c, u32::MAX, table[0][col]).await?;
    mask(io, 0x830, u32::MAX, r830).await?;
    mask(io, 0x838, u32::MAX, table[2][col]).await?;
    if is_efem && params.cut != 1 {
        mask(io, 0x83c, u32::MAX, 0x9194b2b9).await?;
    }
    if width == Width::Twenty && is_5g_mid(channel) {
        mask(io, 0x838, 0xf0, 4).await?;
    }
    Ok(())
}

/// `rtw8822b_config_trx_mode(tx, rx, is_tx2_path = false)`; `current` is
/// `hal.current_channel` (0 before any `rtw_set_channel`).
async fn config_trx_mode(
    io: &mut impl Io,
    params: B22Params,
    tx: u8,
    rx: u8,
    current: u8,
) -> Result<(), Error> {
    if !matches!(tx, 1..=3) || !matches!(rx, 1..=3) {
        return Err(Error::Unsupported);
    }
    rfe_efem(params.rfe)?;
    let agc = |path: u8| {
        if (tx | rx) & path != 0 {
            0x3231
        } else {
            0x1111
        }
    };
    mask(io, 0xc08, 0xffff, agc(1)).await?;
    mask(io, 0xe08, 0xffff, agc(2)).await?;
    mask(io, 0x93c, 3 << 18, 3).await?;
    mask(io, 0x80c, 3 << 28, 1).await?;
    mask(io, 0x80c, 1 << 30, 1).await?;
    if tx & 1 != 0 {
        mask(io, 0x93c, 0xfff00000, 0x001).await?;
        mask(io, 0xa04, 0xf0000000, 0x8).await?;
    } else if tx & 2 != 0 {
        mask(io, 0x93c, 0xfff00000, 0x002).await?;
        mask(io, 0xa04, 0xf0000000, 0x4).await?;
    }
    let single_tx = tx == 1 || tx == 2;
    mask(io, 0x940, 0xfff0, if single_tx { 0x01 } else { 0x43 }).await?;
    mask(io, 0x80c, 0xff, u32::from(tx << 4 | tx)).await?;
    // is_tx2_path is false and mp_mode is off: no 0x043/0xc override.
    mask(io, 0xa2c, 1 << 22, 0).await?;
    mask(io, 0xa2c, 1 << 18, 0).await?;
    if rx & 1 != 0 {
        mask(io, 0xa04, 0x0f000000, 0).await?;
    } else if rx & 2 != 0 {
        mask(io, 0xa04, 0x0f000000, 5).await?;
    }
    mask(io, 0x808, 0xff, u32::from(rx << 4 | rx)).await?;
    let mrc = u32::from(!(rx == 1 || rx == 2));
    mask(io, 0x1904, 1 << 16, mrc).await?;
    mask(io, 0x800, 1 << 28, mrc).await?;
    mask(io, 0x850, 1 << 23, mrc).await?;
    let mut ready = false;
    for _ in 0..100 {
        rf(io, 0, 0xef, 0xfffff, 0x80000).await?;
        rf(io, 0, 0x33, 0xfffff, 0x00001).await?;
        io.delay_us(2).await;
        if rf_read(io, 0, 0x33).await? == 0x00001 {
            ready = true;
            break;
        }
    }
    // Linux WARNs "write RF mode table fail" and skips the remainder; a
    // retained continuation refuses instead of reporting a programmed path.
    if !ready {
        return Err(Error::Timeout);
    }
    for (address, value) in [
        (0xef, 0x80000),
        (0x33, 0x00001),
        (0x3e, 0x00034),
        (0x3f, 0x4080c),
        (0xef, 0x00000),
        (0xef, 0x00000),
    ] {
        rf(io, 0, address, 0xfffff, value).await?;
    }
    toggle_igi(io, rx).await?;
    cca(io, params, 1, Width::Twenty, rx).await?;
    rfe(io, params, current, tx, rx).await
}

/// `rtw_phy_init` hardware effects for 8822B: IGI history from
/// `rtw8822b_dig[0]` and `rtw8822b_adaptivity_init`.
async fn phy_init(io: &mut impl Io) -> Result<u8, Error> {
    let igi = (read(io, 0xc50).await? & 0x7f) as u8;
    // rtw_phy_set_edcca_th(RTW8822B_EDCCA_MAX, RTW8822B_EDCCA_MAX) over
    // rtw8822b_edcca_th (0x8a4 byte0/byte1, offset 0).
    mask(io, 0x8a4, 0xff, 0x7f).await?;
    mask(io, 0x8a4, 0xff00, 0x7f).await?;
    mask(io, 0x520, 1 << 15, 0).await?;
    mask(io, 0x524, 1 << 11, 1).await?;
    mask(io, 0x944, 3 << 28, 1).await?;
    mask(io, 0x8a0, 3, 0).await?;
    mask(io, 0x8dc, 1 << 5, 1).await?;
    Ok(igi)
}

/// `rtw8822b_phy_rfe_init`.
async fn rfe_init(io: &mut impl Io) -> Result<(), Error> {
    mask(io, 0x64, 3 << 28, 3).await?;
    mask(io, 0x4c, 3 << 25, 0).await?;
    mask(io, 0x40, 1 << 2, 1).await?;
    mask(io, 0x1990, 0x3f, 0x30).await?;
    mask(io, 0x1990, 3 << 10, 3).await?;
    mask(io, 0x974, 0x3f, 0x3f).await?;
    mask(io, 0x974, 3 << 10, 3).await
}

/// `rtw8822b_pwrtrack_init` / `rtw8822b_get_swing_index`.
pub async fn pwrtrack_init(io: &mut impl Io) -> Result<u8, Error> {
    let swing = read(io, 0xc1c).await? >> 21;
    Ok(TXSCALE
        .iter()
        .position(|&v| v == swing)
        .map_or(24, |i| i as u8))
}

/// `rtw8822b_phy_bf_init`: `bf.c::rtw_bf_phy_init` plus the grouping bitmap.
async fn bf_init(io: &mut impl Io) -> Result<(), Error> {
    let mut mu = io.read32(REG_MU_TX_CTL).await?;
    mu |= 1 << 16;
    mu = mu & !(0xf << 12) | 0xa << 12;
    mu &= !(1 << 7);
    mu &= !0x3f;
    io.write32(REG_MU_TX_CTL, mu).await?;
    io.write8(REG_WMAC_MU_BF_OPTION, 3 << 4 | 1 << 6).await?;
    io.write16(REG_WMAC_MU_BF_CTL, 0).await?;
    let txbf = io.read32(REG_TXBF_CTRL).await?;
    io.write32(REG_TXBF_CTRL, txbf | 1 << 30).await?;
    io.write8(REG_NDPA_OPT_CTRL, 0x10).await?;
    mask(io, REG_BBPSF_CTRL, 0x3f << 24, DESC_RATE6M).await?;
    if io.read32(REG_MU_TX_CTL).await? != mu
        || io.read8(REG_WMAC_MU_BF_OPTION).await? != 0x70
        || io.read8(REG_NDPA_OPT_CTRL).await? != 0x10
        || io.read32(REG_BBPSF_CTRL).await? >> 24 & 0x3f != DESC_RATE6M
    {
        return Err(Error::Prerequisite);
    }
    io.write32(0x1c94, 0xafffafff).await
}

/// The `rtw8822b_phy_set_param` tail after the RXPSEL release, with the
/// 2T2R `hal.antenna_tx/rx` = `BB_PATH_AB` and no channel yet programmed.
pub async fn finish_set_param(io: &mut impl Io, params: B22Params) -> Result<Init, Error> {
    config_trx_mode(io, params, PATH_AB, PATH_AB, 0).await?;
    let igi = phy_init(io).await?;
    rfe_init(io).await?;
    let default_ofdm_index = pwrtrack_init(io).await?;
    bf_init(io).await?;
    Ok(Init {
        igi,
        default_ofdm_index,
    })
}

/// 8822B channels admitted by `rtw8822b_set_channel_rf` without its WARN.
pub const fn valid_channel(ch: u8) -> bool {
    matches!(ch, 1..=14 | 36..=48 | 52..=64 | 100..=144 | 149..=177) && (ch <= 14 || ch % 2 == 0)
}

/// `rtw8822b_set_channel_bb`.
async fn channel_bb(
    io: &mut impl Io,
    params: B22Params,
    ch: u8,
    width: Width,
) -> Result<(), Error> {
    if ch <= 14 {
        mask(io, 0x808, 1 << 28, 1).await?;
        mask(io, 0x454, 1 << 7, 0).await?;
        mask(io, 0xa80, 1 << 18, 0).await?;
        mask(io, 0x814, 0xfc00, 15).await?;
        mask(io, 0x958, 0x1f, 0).await?;
        mask(io, 0x860, 0x1ffe0000, 0x96a).await?;
        if ch == 14 {
            io.write32(0xa24, 0x00006577).await?;
            mask(io, 0xa28, 0xffff, 0).await?;
        } else {
            io.write32(0xa24, 0x384f6577).await?;
            mask(io, 0xa28, 0xffff, 0x1525).await?;
        }
        mask(io, 0xcbc, 0x300, 2).await?;
    } else {
        mask(io, 0xa80, 1 << 18, 1).await?;
        mask(io, 0x454, 1 << 7, 1).await?;
        mask(io, 0x808, 1 << 28, 0).await?;
        mask(io, 0x814, 0xfc00, 34).await?;
        let gg = match ch {
            36..=64 => 1,
            100..=144 => 2,
            _ => 3,
        };
        mask(io, 0x958, 0x1f, gg).await?;
        let clk = match ch {
            36..=48 => 0x494,
            52..=64 => 0x453,
            100..=116 => 0x452,
            _ => 0x412,
        };
        mask(io, 0x860, 0x1ffe0000, clk).await?;
        mask(io, 0xcbc, 0x300, 1).await?;
    }
    let old = read(io, 0x8ac).await?;
    let sc = u32::from(width.sc() & 0xf) << 2;
    match width {
        Width::Twenty => io.write32(0x8ac, old & 0xffcffc00).await?,
        Width::Forty(sc20) => {
            let rxsb = read(io, 0xa00).await?;
            let rxsb = if sc20 == 1 {
                rxsb | 1 << 4
            } else {
                rxsb & !(1 << 4)
            };
            io.write32(0xa00, rxsb).await?;
            let old = read(io, 0x8ac).await?;
            io.write32(0x8ac, old & 0xff3ff300 | sc | 1).await?;
        }
        Width::Eighty(_) => io.write32(0x8ac, old & 0xfcefcf00 | sc | 2).await?,
    }
    mask(io, 0x8c4, 1 << 30, 1).await?;
    if matches!(width, Width::Eighty(_)) && matches!(params.rfe, 2 | 3) {
        mask(io, 0x840, 0xf000, 6).await?;
        mask(io, 0x8c8, 1 << 10, 1).await?;
    }
    Ok(())
}

/// `mac.c::rtw_set_channel_mac` (3081 WCPU, so the AFE/USTIME part runs).
async fn channel_mac(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    io.write8(0x483, width.data_sc()).await?;
    let trx = read(io, 0x668).await? & !(3 << 7);
    // BIT_RFMOD_40M BIT(7) / BIT_RFMOD_80M BIT(8) (`Width::rfmod` is the
    // unshifted field).
    io.write32(0x668, trx | width.rfmod() << 7).await?;
    // BIT_MAC_CLK_SEL = MAC_CLK_HW_DEF_80M (0).
    let afe = read(io, 0x24).await? & !(3 << 20);
    io.write32(0x24, afe).await?;
    io.write8(0x55c, 80).await?;
    io.write8(0x638, 80).await?;
    let cck = io.read8(0x454).await?;
    if cck == 255 {
        return Err(Error::Gone);
    }
    let cck = if ch > 14 {
        cck | 1 << 7
    } else {
        cck & !(1 << 7)
    };
    io.write8(0x454, cck).await
}

const LOW_BAND: [u8; 15] = [
    0x7, 0x6, 0x6, 0x5, 0x0, 0x0, 0x7, 0xff, 0x6, 0x5, 0x0, 0x0, 0x7, 0x6, 0x6,
];
const MIDDLE_BAND: [u8; 23] = [
    0x6, 0x5, 0x0, 0x0, 0x7, 0x6, 0x6, 0xff, 0x0, 0x0, 0x7, 0x6, 0x6, 0x5, 0x0, 0xff, 0x7, 0x6,
    0x6, 0x5, 0x0, 0x0, 0x7,
];
const HIGH_BAND: [u8; 15] = [
    0x5, 0x5, 0x0, 0x7, 0x7, 0x6, 0x5, 0xff, 0x0, 0x7, 0x7, 0x6, 0x5, 0x5, 0x0,
];

/// `rtw8822b_set_channel_rf` RF18 (band, channel, RFSI, BW) for `old`.
pub const fn rf18(old: u32, ch: u8, width: Width) -> u32 {
    let mut v = old & !((1 << 16 | 3 << 8) | 0xff | 3 << 17 | 3 << 10);
    if ch > 14 {
        v |= 1 << 16 | 1 << 8;
    }
    v |= ch as u32;
    if ch > 144 {
        v |= 1 << 18;
    } else if ch >= 80 {
        v |= 1 << 17;
    }
    v | match width {
        Width::Twenty => 3 << 10,
        Width::Forty(_) => 1 << 11,
        Width::Eighty(_) => 1 << 10,
    }
}
/// `rtw8822b_set_channel_rf` RF 0xbe[17:15] entry.
pub const fn rf_be(ch: u8) -> Option<u8> {
    let v = match ch {
        0..=14 => 0,
        36..=64 => LOW_BAND[((ch - 36) >> 1) as usize],
        100..=144 => MIDDLE_BAND[((ch - 100) >> 1) as usize],
        149..=177 => HIGH_BAND[((ch - 149) >> 1) as usize],
        _ => return None,
    };
    Some(v)
}

/// `rtw8822b_set_channel_rf` (`rf_type` 2T2R writes RF18 on both paths).
async fn channel_rf(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    // 0xff table holes (no 8822B centre) are refused rather than shifted
    // past RFBE_MASK as the unchecked Linux write would.
    let be = rf_be(ch).filter(|&v| v != 0xff).ok_or(Error::Unsupported)?;
    let reg18 = rf18(rf_read(io, 0, 0x18).await?, ch, width);
    rf(io, 0, 0xbe, 7 << 15, u32::from(be)).await?;
    rf(io, 0, 0xdf, 1 << 18, u32::from(ch == 144)).await?;
    rf(io, 0, 0x18, 0xfffff, reg18).await?;
    rf(io, 1, 0x18, 0xfffff, reg18).await?;
    rf(io, 0, 0xb8, 1 << 19, 0).await?;
    rf(io, 0, 0xb8, 1 << 19, 1).await
}

/// `rtw8822b_set_channel_rxdfir`.
async fn rxdfir(io: &mut impl Io, width: Width) -> Result<(), Error> {
    let (acbb0, fir, tx) = match width {
        Width::Forty(_) => (1, 0, 0),
        Width::Eighty(_) => (2, 1, 0),
        Width::Twenty => (2, 2, 1),
    };
    mask(io, 0x948, 3 << 28, acbb0).await?;
    mask(io, 0x94c, 3 << 28, fir).await?;
    mask_s(io, 0xc20, 1 << 31, tx).await
}

/// `rtw8822b_set_channel(center, bw, primary_chan_idx)` for 2T2R.
pub async fn set_channel(
    io: &mut impl Io,
    params: B22Params,
    center: u8,
    width: Width,
) -> Result<(), Error> {
    rfe_efem(params.rfe)?;
    if !valid_channel(center)
        || rf_be(center).is_none_or(|v| v == 0xff)
        || !width.valid()
        || (center <= 14 && width.mhz() == 80)
    {
        return Err(Error::Unsupported);
    }
    channel_bb(io, params, center, width).await?;
    channel_mac(io, center, width).await?;
    channel_rf(io, center, width).await?;
    rxdfir(io, width).await?;
    toggle_igi(io, PATH_AB).await?;
    cca(io, params, center, width, PATH_AB).await?;
    rfe(io, params, center, PATH_AB, PATH_AB).await
}

/// `rtw8822b_set_tx_power_index_by_rate` words for one path: four rate
/// indices per word at `offset_txagc[path]` (0x1d00 / 0x1d80) + `rate & 0xfc`,
/// indexed by DESC_RATE (`__RTW_RATE_SECTION_2SS_MAX`). Indices are
/// caller-supplied coded values (`max_power_index` 0x3f), never dBm.
pub async fn write_txagc(io: &mut impl Io, path: u8, indices: &[u8; 64]) -> Result<(), Error> {
    let base: u16 = match path {
        0 => 0x1d00,
        1 => 0x1d80,
        _ => return Err(Error::Unsupported),
    };
    if indices.iter().any(|&v| v > 0x3f) {
        return Err(Error::Unsupported);
    }
    // rtw_rate_section CCK/OFDM/HT1S/HT2S (0x00..0x1b) and VHT1S/VHT2S
    // (0x2c..0x3f); HT3S/HT4S (0x1c..0x2b) are beyond 2SS and never written.
    for (word, rates) in indices.chunks_exact(4).enumerate() {
        if (7..11).contains(&word) {
            continue;
        }
        let value = u32::from_le_bytes([rates[0], rates[1], rates[2], rates[3]]);
        io.write32(base + (word as u16) * 4, value).await?;
    }
    Ok(())
}

/// Retune readback of a 20MHz `rtw8822b_set_channel(ch)`: RF18 band/channel/
/// BW on both paths, RF-A 0xbe[17:15] (`rtw8822b_set_channel_rf`), 0x8ac
/// 20MHz (`_bb`) and CCK_CHECK 0x454 bit7 on 5GHz only
/// (`rtw_set_channel_mac`).
pub async fn verify_channel20(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let expect = rf18(0, ch, Width::Twenty) & 0x70fff;
    for path in 0..2 {
        if rf_read(io, path, 0x18).await? & 0x70fff != expect {
            return Err(Error::Prerequisite);
        }
    }
    let be = rf_be(ch).filter(|&v| v != 0xff).ok_or(Error::Unsupported)?;
    let cck = io.read8(0x454).await?;
    if (rf_read(io, 0, 0xbe).await? >> 15) & 7 != u32::from(be)
        || read(io, 0x8ac).await? & !0xffcffc00 != 0
        || cck == 255
        || (cck & 0x80 != 0) != (ch > 14)
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
/// Readback of `rtw8822b_set_channel(center, BW40/BW80, sc)`: RF18
/// band/channel/BW on both paths, RF-A 0xbe[17:15], `_bb` 0x8ac (cleared
/// fields plus `sc << 2 | bw`) and, at 40MHz, REG_RXSB 0xa00[4] (set for
/// `RTW_SC_20_UPPER`), `rtw_set_channel_mac` REG_DATA_SC 0x483 and 0x668
/// BIT_RFMOD, and CCK_CHECK 0x454 bit7 on 5GHz only. 20MHz is
/// [`verify_channel20`].
pub async fn verify_channel(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    let (keep, set) = match width {
        Width::Twenty => return verify_channel20(io, ch).await,
        Width::Forty(_) => (0xff3ff300u32, 1u32),
        Width::Eighty(_) => (0xfcefcf00, 2),
    };
    let expect = rf18(0, ch, width) & 0x70fff;
    for path in 0..2 {
        if rf_read(io, path, 0x18).await? & 0x70fff != expect {
            return Err(Error::Prerequisite);
        }
    }
    let be = rf_be(ch).filter(|&v| v != 0xff).ok_or(Error::Unsupported)?;
    let sc = u32::from(width.sc() & 0xf) << 2;
    let cck = io.read8(0x454).await?;
    if (rf_read(io, 0, 0xbe).await? >> 15) & 7 != u32::from(be)
        || read(io, 0x8ac).await? & !keep != sc | set
        || io.read8(0x483).await? != width.data_sc()
        || (read(io, 0x668).await? >> 7) & 3 != width.rfmod()
        || cck == 255
        || (cck & 0x80 != 0) != (ch > 14)
    {
        return Err(Error::Prerequisite);
    }
    if let Width::Forty(sc20) = width {
        if (read(io, 0xa00).await? & 1 << 4 != 0) != (sc20 == 1) {
            return Err(Error::Prerequisite);
        }
    }
    Ok(())
}
/// Both paths' measured `N2BP` TXAGC words (`rtw8822b_set_tx_power_index_by_rate`).
pub async fn verify_txagc(io: &mut impl Io, tables: [[u8; 64]; 2]) -> Result<(), Error> {
    for (path, table) in tables.iter().enumerate() {
        let base = if path == 0 { 0x1d00 } else { 0x1d80 };
        for (word, rates) in table.chunks_exact(4).enumerate() {
            if (7..11).contains(&word) {
                continue;
            }
            let value = u32::from_le_bytes([rates[0], rates[1], rates[2], rates[3]]);
            if read(io, base + word as u16 * 4).await? != value {
                return Err(Error::Prerequisite);
            }
        }
    }
    Ok(())
}
