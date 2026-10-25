// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Initial RTL8852B PHY0/channel1/20MHz/RF_AB DPK, with no reload/tracking.
//! Both paths run actual NCTL/AGC/IDL. Missing FEM facts never grant a bypass.
use super::{
    power,
    rfk::{self, Interface},
    rfk_tables as tables,
    tssi::{self, Access},
};
use rfk::Error;
#[path = "dpk/regs.rs"]
mod regs;
use regs::*;
pub(super) const RECIPE: [u8; 32] = tssi::RECIPE;
const BB: [u32; 3] = [0x2344, 0x5800, 0x7800];
const RF: [u32; 11] = [0xde, 0xdf, 0x8b, 0x90, 0x97, 0x85, 0x1e, 0, 2, 5, 0x10005];
const KIP: [u32; 3] = [0x813c, 0x8124, 0x8120];
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Calibrating,
    Calibrated,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Path {
    pub thermal: u8,
    pub txagc: u8,
    pub pwsf: u16,
    pub gain: u8,
    pub correlation_index: u8,
    pub correlation: u8,
    pub dc: [u16; 2],
}
#[derive(Default)]
pub(super) struct Dpk {
    state: State,
    results: [Path; 2],
}
impl Dpk {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn results(&self) -> Option<&[Path; 2]> {
        (self.state == State::Calibrated).then_some(&self.results)
    }
    /// # Safety
    /// The same exclusive actual B PHY0/ch1/20/RF_AB factory/channel/basic/IQK/
    /// TSSI owner remains live, with no packet/reset/retune/other RFK producer.
    /// `cut` and `gain` are copied from its completed actual Factory/Rfk result;
    /// every source calibration emission is covered by current signed policy.
    pub(super) async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        cut: u8,
        gain: u8,
        tssi: &tssi::Tssi,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        if cut > 15 || !matches!(gain, 0x5b | 0x7f) || tssi.results().is_none() {
            return Err(Error::Table);
        }
        io.admit()?;
        self.state = State::Calibrating;
        io.begin(rfk::Kind::Dpk).await?;
        let saved = io.pause().await?;
        let mut a = Access(io);
        a.rx_idle().await?;
        let mut bb = [0; 3];
        let mut kip = [[0; 3]; 2];
        let mut rf = [[0; 11]; 2];
        for (i, address) in BB.into_iter().enumerate() {
            bb[i] = a.bb(address, u32::MAX)?;
        }
        for path in 0..2 {
            for (i, address) in KIP.into_iter().enumerate() {
                kip[path][i] = a.bb(address + ((path as u32) << 8), u32::MAX)?;
            }
            for (i, address) in RF.into_iter().enumerate() {
                rf[path][i] = a.rr(path as u8, address, 0xfffff).await?;
            }
            a.wm(R_P0_TSSI_TRK + ((path as u32) << 13), B_P0_TSSI_TRK_EN, 1)?;
        }
        a.table(tables::DPK_AFE_DEFS).await?;
        let mut results = [Path::default(); 2];
        for path in 0..2 {
            results[path as usize] = calibrate(&mut a, path, gain).await?;
            on(&mut a, path)?;
        }
        a.table(tables::DPK_AFE_RESTORE_DEFS).await?;
        for (address, value) in BB.into_iter().zip(bb) {
            a.wm(address, u32::MAX, value)?;
        }
        for path in 0..2 {
            a.table(tables::DPK_KIP_DEFS).await?;
            if cut > 0 {
                a.wm(R_DPD_COM + ((path as u32) << 8), B_DPD_COM_OF, 1)?;
            }
            for (address, value) in KIP.into_iter().zip(kip[path]) {
                a.wm(address + ((path as u32) << 8), u32::MAX, value)?;
            }
            for (address, value) in RF.into_iter().zip(rf[path]) {
                a.wr(path as u8, address, 0xfffff, value).await?;
            }
            a.wm(R_P0_TSSI_TRK + ((path as u32) << 13), B_P0_TSSI_TRK_EN, 0)?;
        }
        a.0.admit()?;
        a.0.resume(saved).await?;
        a.0.end(rfk::Kind::Dpk).await?;
        a.0.admit()?;
        self.results = results;
        self.state = State::Calibrated;
        Ok(())
    }
}
async fn one_shot<I: Interface>(a: &mut Access<'_, I>, path: u8, id: u8) -> Result<(), Error> {
    // Source clears this completion byte between commands. An old completed
    // NCTL owner cannot authorize another trigger, even if bff8 is still55.
    // Do not assume the command register itself remains stable after a write.
    if a.bb(R_NCTL_N1, 255)? == 0x55 {
        return Err(Error::Terminal);
    }
    a.wm(
        R_NCTL_CFG,
        u32::MAX,
        (u32::from(id) << 8) | (0x19 + (u32::from(path) << 4)),
    )?;
    a.poll(0xbff8, 255, 0x55, 1, 20_000).await?;
    a.delay(1).await?;
    a.wm(R_KIP_RPT1, u32::MAX, 0x30000)?;
    a.poll(0x80fc, 0xffff, 0x8000, 1, 2000).await?;
    a.wm(R_NCTL_N1, 255, 0)?;
    if a.bb(R_NCTL_N1, 255)? != 0 {
        return Err(Error::Terminal);
    }
    Ok(())
}
fn order<I: Interface>(a: &mut Access<'_, I>) -> Result<u32, Error> {
    let value = a.bb(R_LDL_NORM, B_LDL_NORM_OP)?;
    if value > 3 {
        return Err(Error::Table);
    }
    Ok(3 >> value)
}
fn on<I: Interface>(a: &mut Access<'_, I>, path: u8) -> Result<(), Error> {
    let value = order(a)? << 1 | 1;
    let address = R_DPD_CH0A + (u32::from(path) << 8);
    a.wm(address, 0xff000000, value)?;
    if a.bb(address, 0xff000000)? != value {
        return Err(power::Error::Access.into());
    }
    Ok(())
}
async fn txagc<I: Interface>(a: &mut Access<'_, I>, path: u8, value: u8) -> Result<(), Error> {
    a.wr(path, RR_TXAGC, 0xfffff, u32::from(value)).await?;
    a.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 1)?;
    one_shot(a, path, 0x19).await?;
    a.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 0)
}
async fn set_offset<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    offset: i8,
) -> Result<u8, Error> {
    // Source u8/s8 integer promotions happen in signed int, then clamp.
    let current = a.rr(path, RR_TXAGC, 0xfffff).await? as u8;
    let value = (i32::from(current) - i32::from(offset)).clamp(0x2e, 0x3f) as u8;
    txagc(a, path, value).await?;
    Ok(value)
}
fn table<I: Interface>(a: &mut Access<'_, I>, path: u8) -> Result<(), Error> {
    a.wm(R_DPD_CH0 + (u32::from(path) << 8), 0xff000000, 0x90)
}
fn signed12(value: u32) -> i32 {
    ((value << 20) as i32) >> 20
}
async fn sync<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    result: &mut Path,
) -> Result<(), Error> {
    one_shot(a, path, 0x10).await?;
    a.clear(R_KIP_RPT1, B_KIP_RPT1_SEL)?;
    result.correlation_index = a.bb(R_RPT_COM, B_PRT_COM_CORI)? as u8;
    result.correlation = a.bb(R_RPT_COM, B_PRT_COM_CORV)? as u8;
    a.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 9)?;
    result.dc = [
        signed12(a.bb(R_RPT_COM, B_PRT_COM_DCI)?).unsigned_abs() as u16,
        signed12(a.bb(R_RPT_COM, B_PRT_COM_DCQ)?).unsigned_abs() as u16,
    ];
    if result.dc[0] > 200 || result.dc[1] > 200 || result.correlation < 170 {
        return Err(Error::Table);
    }
    Ok(())
}
fn dgain_offset(value: u16) -> i8 {
    let bounds = [
        0xbf1, 0xaa5, 0x97d, 0x875, 0x789, 0x6b7, 0x5fc, 0x556, 0x4c1, 0x43d, 0x3c7, 0x35e, 0x2ac,
        0x262, 0x220,
    ];
    if value >= bounds[1] {
        return 6;
    }
    for (index, bound) in bounds[2..].iter().copied().enumerate() {
        if value >= bound {
            return 5 - index as i8;
        }
    }
    -8
}
fn pas<I: Interface>(a: &mut Access<'_, I>) -> Result<bool, Error> {
    a.wm(R_KIP_RPT1, 0xff0000, 6)?;
    a.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 0)?;
    a.wm(R_DPK_CFG3, 0xff0000, 8)?;
    a.wm(R_DPK_CFG3, 0xff000000, 0)?;
    let first = [
        signed12(a.bb(R_RPT_COM, 0xffff0000)?).unsigned_abs(),
        signed12(a.bb(R_RPT_COM, 0xffff)?).unsigned_abs(),
    ];
    a.wm(R_DPK_CFG3, 0xff000000, 0x1f)?;
    let last = [
        signed12(a.bb(R_RPT_COM, 0xffff0000)?).unsigned_abs(),
        signed12(a.bb(R_RPT_COM, 0xffff)?).unsigned_abs(),
    ];
    let energy = |iq: [u32; 2]| iq[0] * iq[0] + iq[1] * iq[1];
    Ok(energy(first) >= energy(last) * 8 / 5)
}
async fn agc<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    result: &mut Path,
) -> Result<u8, Error> {
    let (mut step, mut count, mut limited) = (0, 0, false);
    let (mut dgain, mut tx, mut gl) = (0u16, 0x38u8, 0u8);
    // Exact source201 dispatch limit and six gain-adjustment count. Exhaustion
    // without a source exit cannot become a completed path in this owner.
    for _ in 0..201 {
        match step {
            0 => {
                sync(a, path, result).await?;
                a.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
                dgain = a.bb(R_RPT_COM, B_PRT_COM_DCI)? as u16;
                step = if limited { 2 } else { 1 };
            }
            1 => {
                let current = a.rr(path, RR_MOD, 0x3e0).await? as i32;
                let offset = dgain_offset(dgain);
                let sum = current + i32::from(offset);
                limited |= !(0..=31).contains(&sum);
                a.wr(path, RR_MOD, 0x3e0, sum.clamp(0, 31) as u32).await?;
                if offset != 0 || count == 0 {
                    a.wm(R_RXIQC + (u32::from(path) << 8), B_RXIQC_BYPASS2, 1)?;
                    a.wm(R_RXIQC + (u32::from(path) << 8), B_RXIQC_BYPASS, 1)?;
                }
                step = if !(342..=1922).contains(&dgain) { 0 } else { 2 };
                count += 1;
            }
            2 => {
                table(a, path)?;
                one_shot(a, path, 0x13).await?;
                a.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 6)?;
                a.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 1)?;
                gl = a.bb(R_RPT_COM, B_PRT_COM_GL)? as u8;
                step = if gl == 0 && pas(a)? || gl >= 7 {
                    3
                } else if gl == 0 {
                    4
                } else {
                    5
                };
            }
            3 => {
                if tx == 0x2e {
                    return Ok(tx);
                }
                tx = set_offset(a, path, 3).await?;
                step = 2;
                count += 1;
            }
            4 => {
                if tx == 0x3f {
                    return Ok(tx);
                }
                tx = set_offset(a, path, -2).await?;
                step = 2;
                count += 1;
            }
            5 => return set_offset(a, path, gl as i8).await,
            _ => return Err(Error::Table),
        }
        if count >= 6 {
            return Ok(tx);
        }
    }
    Err(power::Error::Timeout.into())
}
async fn calibrate<I: Interface>(a: &mut Access<'_, I>, path: u8, gain: u8) -> Result<Path, Error> {
    let mut result = Path {
        gain,
        ..Path::default()
    };
    a.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
    a.wr(path, RR_BBDC, RR_BBDC_SEL, 0).await?;
    a.wm(R_NCTL_RPT, u32::MAX, 0x80)?;
    a.wm(R_KIP_SYSCFG, u32::MAX, 0x807f030a)?;
    a.wm(R_CFIR_SYS + (u32::from(path) << 8), u32::MAX, 0xce000a08)?;
    txagc(a, path, 0x38).await?;
    a.wr(path, RR_MOD, 0xfffff, 0x50220).await?;
    a.wr(path, RR_RXBB, RR_RXBB_FATT, 0xf2).await?;
    a.wr(path, RR_LUTDBG, RR_LUTDBG_TIA, 1).await?;
    a.wr(path, RR_TIA, RR_TIA_N6, 1).await?;
    a.wr(path, RR_RCKD, RR_RCKD_BW, 1).await?;
    a.wr(path, RR_BTC, RR_BTC_TXBB, 1).await?;
    a.wr(path, RR_BTC, RR_BTC_RXBB, 0).await?;
    a.wr(path, RR_RXBB2, RR_EN_TIA_IDA, 3).await?;
    a.wr(path, RR_DCK1, RR_DCK1_CLR, 0).await?;
    a.wr(path, RR_DCK, RR_DCK_LV, 0).await?;
    a.wr(path, RR_DCK, RR_DCK_LV, 1).await?;
    a.delay(1000).await?;
    a.wm(R_TPG_MOD, B_TPG_MOD_F, 1)?;
    one_shot(a, path, 0x16).await?;
    let mode = a.rr(path, RR_MOD, 0xfffff).await?;
    a.wm(R_KIP_MOD, B_KIP_MOD, mode)?;
    a.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 1)?;
    one_shot(a, path, 0x15).await?;
    a.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 0)?;
    a.wm(R_KIP_RPT1, B_KIP_RPT1_SEL_V1, 8)?;
    table(a, path)?;
    result.txagc = agc(a, path, &mut result).await?;
    for value in [1, 0, 1] {
        a.wr(path, RR_TM, RR_TM_TRI, value).await?;
    }
    a.delay(200).await?;
    result.thermal = a.rr(path, RR_TM, RR_TM_VAL).await? as u8;
    a.wm(R_LDL_NORM, B_LDL_NORM_OP, 0)?;
    a.wm(R_LDL_NORM, B_LDL_NORM_PN, 3)?;
    a.wm(R_MDPK_SYNC, B_MDPK_SYNC_MAN, 1)?;
    one_shot(a, path, 0x11).await?;
    a.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
    fill(a, path, &mut result)?;
    Ok(result)
}
fn fill<I: Interface>(a: &mut Access<'_, I>, path: u8, result: &mut Path) -> Result<(), Error> {
    let offset = u32::from(path) << 8;
    a.wm(R_COEF_SEL + offset, B_COEF_SEL_MDPD, 0)?;
    a.wm(R_TXAGC_RFK + offset, 0x3f00, u32::from(result.txagc))?;
    result.pwsf = 0x78;
    a.wm(R_DPD_BND + offset, 0x1ff0000, u32::from(result.pwsf))?;
    a.wm(R_LOAD_COEF + offset, B_LOAD_COEF_MDPD, 1)?;
    a.wm(R_LOAD_COEF + offset, B_LOAD_COEF_MDPD, 0)?;
    a.wm(
        R_DPD_CH0A + offset,
        u32::MAX,
        if result.gain == 0x7f {
            0x007f7f7f
        } else {
            0x005b5b5b
        },
    )?;
    let value = order(a)?;
    a.wm(R_DPD_CH0A + offset, B_DPD_ORDER_V1, value)?;
    a.wm(R_DPD_V1 + offset, u32::MAX, 0)?;
    a.wm(R_MDPK_SYNC, B_MDPK_SYNC_SEL, 0)?;
    if a.bb(R_TXAGC_RFK + offset, 0x3f00)? != u32::from(result.txagc)
        || a.bb(R_DPD_BND + offset, 0x1ff0000)? != 0x78
    {
        return Err(power::Error::Access.into());
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "dpk/tests.rs"]
mod tests;
