//! Exact B common PMAC helpers used only by source TSSI alignment.
use super::{regs::*, tables, Access, Calibration, Error, Interface};
#[derive(Clone, Copy)]
pub(super) struct Backup {
    tx: u32,
    rx: u32,
    rf: [u32; 4],
    power: u32,
}
pub(super) fn backup<I: Interface>(a: &mut Access<'_, I>) -> Result<Backup, Error> {
    Ok(Backup {
        tx: a.bb(R_TXPATH_SEL, B_TXPATH_SEL_MSK)?,
        rx: a.bb(R_CHBW_MOD_V1, B_ANT_RX_SEG0)?,
        rf: [
            a.bb(R_P0_RFMODE, u32::MAX)?,
            a.bb(R_P0_RFMODE_FTM_RX, u32::MAX)?,
            a.bb(R_P1_RFMODE, u32::MAX)?,
            a.bb(R_P1_RFMODE_FTM_RX, u32::MAX)?,
        ],
        power: super::signed9(a.bb(R_TXPWR, B_TXPWR_MSK)?) as u32,
    })
}
pub(super) fn restore<I: Interface>(a: &mut Access<'_, I>, saved: Backup) -> Result<(), Error> {
    a.wm(R_TXPATH_SEL, B_TXPATH_SEL_MSK, saved.tx)?;
    a.wm(
        R_TXNSS_MAP,
        B_TXNSS_MAP_MSK,
        if saved.tx == 3 { 4 } else { 0 },
    )?;
    a.wm(R_CHBW_MOD_V1, B_ANT_RX_SEG0, saved.rx)?;
    a.wm(R_MAC_SEL, B_MAC_SEL_PWR_EN, 1)?;
    for (address, value) in [
        R_P0_RFMODE,
        R_P0_RFMODE_FTM_RX,
        R_P1_RFMODE,
        R_P1_RFMODE_FTM_RX,
    ]
    .into_iter()
    .zip(saved.rf)
    {
        a.wm(address, u32::MAX, value)?;
    }
    a.wm(R_TXPWR, B_TXPWR_MSK, saved.power)
}
pub(super) fn mode_tmac<I: Interface>(a: &mut Access<'_, I>) -> Result<(), Error> {
    for (address, mask) in [
        (R_PMAC_GNT, B_PMAC_GNT_TXEN),
        (R_PMAC_GNT, B_PMAC_GNT_RXEN),
        (R_PMAC_RX_CFG1, B_PMAC_OPT1_MSK),
        (R_PMAC_RXMOD, B_PMAC_RXMOD_MSK),
        (R_MAC_SEL, B_MAC_SEL_DPD_EN),
        (R_MAC_SEL, B_MAC_SEL_MOD),
        (R_MAC_SEL, B_MAC_SEL_PWR_EN),
    ] {
        a.wm(address, mask, 0)?;
    }
    if a.bb(R_PMAC_GNT, B_PMAC_GNT_TXEN | B_PMAC_GNT_RXEN)? != 0
        || a.bb(R_MAC_SEL, B_MAC_SEL_MOD | B_MAC_SEL_PWR_EN)? != 0
    {
        return Err(Error::Register(super::power::Error::Access));
    }
    Ok(())
}
pub(super) fn stop<I: Interface>(a: &mut Access<'_, I>) -> Result<(), Error> {
    a.wm(R_PMAC_TX_PRD, B_PMAC_PTX_EN, 0)?;
    a.wm(R_PD_CTRL, B_PD_HIT_DIS, 0)?;
    a.clear(R_RXCCA, B_RXCCA_DIS)?;
    if a.bb(R_PMAC_TX_PRD, B_PMAC_PTX_EN)? != 0 {
        return Err(Error::Register(super::power::Error::Access));
    }
    Ok(())
}
pub(super) async fn transmit<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    power: i16,
    calibration: &Calibration,
    bases: [i8; 2],
) -> Result<(), Error> {
    if !matches!(path, 0 | 1 | 14) {
        return Err(Error::Table);
    }
    for &(address, mask, value) in tables::PMAC_PLCP {
        a.wm(address, mask, value)?;
    }
    a.wm(R_MAC_SEL, B_MAC_SEL_MOD, 7)?;
    if path < 2 {
        a.wm(R_TXPATH_SEL, B_TXPATH_SEL_MSK, u32::from(path) + 1)?;
        a.wm(R_TXNSS_MAP, B_TXNSS_MAP_MSK, 0)?;
    }
    rx_path(a, path, calibration, bases)?;
    a.wm(R_MAC_SEL, B_MAC_SEL_PWR_EN, 1)?;
    a.wm(R_TXPWR, B_TXPWR_MSK, power as u32)?;
    a.wm(R_PMAC_GNT, B_PMAC_GNT_TXEN, 1)?;
    a.wm(R_PMAC_GNT, B_PMAC_GNT_RXEN, 1)?;
    a.wm(R_PMAC_RX_CFG1, B_PMAC_OPT1_MSK, 0x3f)?;
    a.wm(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0)?;
    a.wm(R_PD_CTRL, B_PD_HIT_DIS, 1)?;
    a.set(R_RXCCA, B_RXCCA_DIS)?;
    a.wm(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;
    a.wm(R_PMAC_TX_PRD, B_PMAC_PTX_EN, 1)?;
    a.wm(R_PMAC_TX_PRD, B_PMAC_TX_PRD_MSK, 5000)?;
    a.wm(R_PMAC_TX_CNT, B_PMAC_TX_CNT_MSK, 100)?;
    if a.bb(R_PMAC_TX_PRD, B_PMAC_PTX_EN)? != 1
        || a.bb(R_PMAC_TX_PRD, B_PMAC_TX_PRD_MSK)? != 5000
        || a.bb(R_PMAC_TX_CNT, B_PMAC_TX_CNT_MSK)? != 100
    {
        return Err(Error::Register(super::power::Error::Access));
    }
    a.wm(R_PMAC_TX_CTRL, B_PMAC_TXEN_DIS, 1)?;
    a.wm(R_PMAC_TX_CTRL, B_PMAC_TXEN_DIS, 0)?;
    Ok(())
}
fn rx_path<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    calibration: &Calibration,
    bases: [i8; 2],
) -> Result<(), Error> {
    // RF_PATH_ABCD(14) in the source second measurement leaves path selection
    // unchanged while still applying gain, BTG, power and reset controls.
    if path < 2 || path == 4 {
        let value = if path == 4 { 3 } else { u32::from(path) + 1 };
        let nss = u32::from(path == 4);
        a.wm(R_CHBW_MOD_V1, B_ANT_RX_SEG0, value)?;
        a.wm(R_FC0_BW_V1, B_ANT_RX_1RCCA_SEG0, value)?;
        a.wm(R_FC0_BW_V1, B_ANT_RX_1RCCA_SEG1, value)?;
        a.wm(R_RXHT_MCS_LIMIT, B_RXHT_MCS_LIMIT, nss)?;
        a.wm(R_RXVHT_MCS_LIMIT, B_RXVHT_MCS_LIMIT, nss)?;
        a.wm(R_RXHE, B_RXHE_USER_MAX, 4)?;
        a.wm(R_RXHE, B_RXHE_MAX_NSS, nss)?;
        a.wm(R_RXHE, B_RXHETB_MAX_NSS, nss)?;
    }
    gain_offset(a, calibration, bases)?;
    btg(a, path == 1 || path == 4)?;
    let (address, mask) = if path == 0 {
        (R_P0_TXPW_RSTB, B_P0_TXPW_RSTB_MANON | B_P0_TXPW_RSTB_TSSI)
    } else {
        (R_P1_TXPW_RSTB, B_P1_TXPW_RSTB_MANON | B_P1_TXPW_RSTB_TSSI)
    };
    a.wm(address, mask, 1)?;
    a.wm(address, mask, 3)
}
pub(super) fn configure_ab<I: Interface>(
    a: &mut Access<'_, I>,
    calibration: &Calibration,
    bases: [i8; 2],
) -> Result<(), Error> {
    rx_path(a, 4, calibration, bases)?;
    for (address, mask, value) in [
        (R_P0_RFMODE, B_P0_RFMODE_ORI_TXRX_FTM_TX, 0x1233312),
        (R_P0_RFMODE_FTM_RX, B_P0_RFMODE_FTM_RX, 0x333),
        (R_P1_RFMODE, B_P1_RFMODE_ORI_TXRX_FTM_TX, 0x1233312),
        (R_P1_RFMODE_FTM_RX, B_P1_RFMODE_FTM_RX, 0x333),
        (R_RXHT_MCS_LIMIT, B_RXHT_MCS_LIMIT, 1),
        (R_RXVHT_MCS_LIMIT, B_RXVHT_MCS_LIMIT, 1),
        (R_RXHE, B_RXHE_MAX_NSS, 1),
        (R_RXHE, B_RXHETB_MAX_NSS, 1),
        (R_MAC_SEL, B_MAC_SEL_MOD, 0),
    ] {
        a.wm(address, mask, value)?;
    }
    Ok(())
}
fn gain_offset<I: Interface>(
    a: &mut Access<'_, I>,
    c: &Calibration,
    bases: [i8; 2],
) -> Result<(), Error> {
    if c.comp_valid {
        for (path, address) in [R_P0_AGC_RSVD, R_P1_AGC_RSVD].into_iter().enumerate() {
            a.wm(
                address,
                255,
                (i32::from(c.gain_comp[path][0]) * 4).clamp(-128, 127) as u32,
            )?;
        }
    }
    if c.offset_valid {
        let base = i32::from(bases[0]);
        for (path, address) in [R_PATH0_G_TIA1_LNA6_OP1DB_V1, R_PATH1_G_TIA1_LNA6_OP1DB_V1]
            .into_iter()
            .enumerate()
        {
            let offset = -i32::from(c.gain_offset[path][1]);
            a.wm(
                address,
                B_PATH0_R_G_OFST_MASK,
                (-(offset * 4 + (base >> 2))).clamp(-128, 127) as u32,
            )?;
        }
        // Initial source hal.antenna_rx is RF_AB, so compensation chooses A;
        // temporary single-path PMAC selection does not rewrite that HAL fact.
        let ofdm = -i32::from(c.gain_offset[0][1]);
        let cck = -i32::from(c.gain_offset[0][0]);
        a.wm(
            R_P0_RPL1,
            B_P0_RPL1_BIAS_MASK,
            (ofdm * 16 + base).clamp(-128, 127) as u32,
        )?;
        a.wm(
            R_P1_RPL1,
            B_P0_RPL1_BIAS_MASK,
            (ofdm * 16 + i32::from(bases[1])).clamp(-128, 127) as u32,
        )?;
        a.wm(
            R_RX_RPL_OFST,
            B_RX_RPL_OFST_CCK_MASK,
            (cck * 8 + (base >> 1)).clamp(-64, 63) as u32,
        )?;
    }
    Ok(())
}
fn btg<I: Interface>(a: &mut Access<'_, I>, enable: bool) -> Result<(), Error> {
    for (address, mask, value) in if enable {
        &[
            (R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1, 1),
            (R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1, 0),
            (R_PATH1_G_LNA6_OP1DB_V1, B_PATH1_G_LNA6_OP1DB_V1, 0x20),
            (
                R_PATH1_G_TIA0_LNA6_OP1DB_V1,
                B_PATH1_G_TIA0_LNA6_OP1DB_V1,
                0x30,
            ),
            (R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1, 1),
            (R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1, 1),
            (R_PMAC_GNT, B_PMAC_GNT_P1, 0),
            (R_CHBW_MOD_V1, B_BT_SHARE, 1),
            (R_FC0_BW_V1, B_ANT_RX_BT_SEG0, 2),
            (R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK, 1),
            (R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN, 1),
        ][..]
    } else {
        &[
            (R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1, 0),
            (R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1, 0),
            (R_PATH1_G_LNA6_OP1DB_V1, B_PATH1_G_LNA6_OP1DB_V1, 0x1a),
            (
                R_PATH1_G_TIA0_LNA6_OP1DB_V1,
                B_PATH1_G_TIA0_LNA6_OP1DB_V1,
                0x2a,
            ),
            (R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1, 0),
            (R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1, 0),
            (R_PMAC_GNT, B_PMAC_GNT_P1, 0xc),
            (R_CHBW_MOD_V1, B_BT_SHARE, 0),
            (R_FC0_BW_V1, B_ANT_RX_BT_SEG0, 0),
            (R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK, 1),
            (R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN, 0),
        ][..]
    } {
        a.wm(*address, *mask, *value)?;
    }
    Ok(())
}
