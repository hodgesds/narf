// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact one-shot B PHY0/channel1/20MHz/RF_AB TSSI with real PMAC alignment.
//! Source calibration inputs and measurements do not grant ordinary RF TX.
use super::{
    factory_b::Calibration,
    power,
    rfk::{self, Interface},
    rfk_tables as recipe,
};
pub(super) use rfk::Error;
#[path = "tssi/access.rs"]
mod access;
#[path = "tssi/inputs.rs"]
mod inputs;
#[path = "tssi/pmac.rs"]
mod pmac;
#[path = "tssi/regs.rs"]
mod regs;
#[path = "tssi/tables.rs"]
mod tables;
pub(super) use access::Access;
pub(super) use inputs::Tracking;
use regs::*;
pub(super) const RECIPE: [u8; 32] = tables::RECIPE;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Calibrating,
    Calibrated,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Results {
    pub cw: [[u32; 2]; 2],
    pub alignment: [[u32; 4]; 2],
    pub thermal: [[u32; 16]; 2],
    pub de: [[i16; 2]; 2],
}
#[derive(Default)]
pub(super) struct Tssi {
    state: State,
    results: Results,
}
impl Tssi {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn results(&self) -> Option<&Results> {
        (self.state == State::Calibrated).then_some(&self.results)
    }
    /// # Safety
    /// Same retained B PHY0/ch1/20/RF_AB factory/channel/NCTL/basic/IQK owner.
    /// Inputs are its actual factory snapshot, selected firmware tracking and
    /// post-table gain bases; current signed envelope covers source PMAC
    /// HT20-MCS7 power48/20 as well as every source RF operation. No packet,
    /// retune/reset/tracking or other RFK producer may run concurrently.
    pub(super) async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        calibration: &Calibration,
        tracking: &Tracking,
        gain_bases: [i8; 2],
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        io.admit()?;
        self.state = State::Calibrating;
        io.begin(rfk::Kind::Tssi).await?;
        let mut access = Access(io);
        disable(&mut access)?;
        let mut result = Results::default();
        for path in 0..2 {
            access.wr(path, RR_TXPOW, RR_TXPOW_TXG, 1).await?;
            access.table(recipe::TSSI_SYS_DEFS).await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_SYS_A_DEFS_2G
                } else {
                    recipe::TSSI_SYS_B_DEFS_2G
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_INIT_TXPWR_DEFS_A
                } else {
                    recipe::TSSI_INIT_TXPWR_DEFS_B
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_INIT_TXPWR_HE_TB_DEFS_A
                } else {
                    recipe::TSSI_INIT_TXPWR_HE_TB_DEFS_B
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_DCK_DEFS_A
                } else {
                    recipe::TSSI_DCK_DEFS_B
                })
                .await?;
            result.thermal[path as usize] = thermal(
                &mut access,
                path,
                calibration.thermal[path as usize],
                tracking,
            )?;
            access
                .table(if path == 0 {
                    recipe::TSSI_DAC_GAIN_DEFS_A
                } else {
                    recipe::TSSI_DAC_GAIN_DEFS_B
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_SLOPE_A_DEFS_2G
                } else {
                    recipe::TSSI_SLOPE_B_DEFS_2G
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_ALIGN_A_2G_ALL_DEFS
                } else {
                    recipe::TSSI_ALIGN_B_2G_ALL_DEFS
                })
                .await?;
            access
                .table(if path == 0 {
                    recipe::TSSI_SLOPE_DEFS_A
                } else {
                    recipe::TSSI_SLOPE_DEFS_B
                })
                .await?;
            access.0.admit()?;
            let saved = access.0.pause().await?;
            access.rx_idle().await?;
            let measured = alignment(&mut access, path, calibration, gain_bases).await;
            // A returned failure may close PMAC synchronously while authority
            // remains. Cancellation retains Calibrating; outer Native closes.
            if measured.is_err() {
                let _ = pmac::stop(&mut access);
            }
            let resumed = access.0.resume(saved).await;
            let (cw, values) = measured?;
            resumed?;
            result.cw[path as usize] = cw;
            result.alignment[path as usize] = values;
        }
        enable(&mut access).await?;
        result.de = de(&mut access, calibration)?;
        access.0.admit()?;
        access.0.end(rfk::Kind::Tssi).await?;
        access.0.admit()?;
        self.results = result;
        self.state = State::Calibrated;
        Ok(())
    }
}
fn disable<I: Interface>(a: &mut Access<'_, I>) -> Result<(), Error> {
    for (address, mask, value) in [
        (R_P0_TSSI_AVG, B_P0_TSSI_EN, 0),
        (R_P0_TSSI_TRK, B_P0_TSSI_RFC, 1),
        (R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_CLR, 1),
        (R_P1_TSSI_AVG, B_P1_TSSI_EN, 0),
        (R_P1_TSSI_TRK, B_P1_TSSI_RFC, 1),
        (R_P1_TSSI_MV_AVG, B_P1_TSSI_MV_CLR, 1),
    ] {
        a.wm(address, mask, value)?;
    }
    Ok(())
}
fn thermal_words(thermal: u8, up: &[i8; 30], down: &[i8; 30]) -> [u32; 16] {
    let mut bytes = [0i8; 64];
    if thermal != 255 {
        for (j, byte) in bytes[..32].iter_mut().enumerate() {
            *byte = down[j.min(29)].wrapping_neg();
        }
        for (j, byte) in bytes[32..].iter_mut().rev().enumerate() {
            *byte = up[(j + 1).min(29)];
        }
    }
    core::array::from_fn(|i| u32::from_le_bytes(core::array::from_fn(|j| bytes[i * 4 + j] as u8)))
}
fn thermal<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    value: u8,
    tracking: &Tracking,
) -> Result<[u32; 16], Error> {
    let (meter, dis, trk, mask, rfctm, rfmask, ready, base) = if path == 0 {
        (
            R_P0_TMETER,
            B_P0_TMETER_DIS,
            B_P0_TMETER_TRK,
            B_P0_TMETER,
            R_P0_RFCTM,
            B_P0_RFCTM_VAL,
            R_P0_RFCTM_RDY,
            R_P0_TSSI_BASE,
        )
    } else {
        (
            R_P1_TMETER,
            B_P1_TMETER_DIS,
            B_P1_TMETER_TRK,
            B_P1_TMETER,
            R_P1_RFCTM,
            B_P1_RFCTM_VAL,
            R_P1_RFCTM_RDY,
            R_TSSI_THOF,
        )
    };
    a.wm(meter, dis, 0)?;
    a.wm(meter, trk, 1)?;
    let current = if value == 255 { 32 } else { u32::from(value) };
    a.wm(meter, mask, current)?;
    a.wm(rfctm, rfmask, current)?;
    let words = thermal_words(
        value,
        &tracking.up[path as usize],
        &tracking.down[path as usize],
    );
    for (i, word) in words.iter().copied().enumerate() {
        a.write(base + i as u32 * 4, word)?;
    }
    a.wm(rfctm, ready, 1)?;
    a.wm(rfctm, ready, 0)?;
    Ok(words)
}
async fn enable<I: Interface>(a: &mut Access<'_, I>) -> Result<(), Error> {
    for path in 0..2 {
        let (control, bypass, mv, mix, clr, avg, en, trk, rfc, offset, offset_en) = if path == 0 {
            (
                R_P0_TSSIC,
                B_P0_TSSIC_BYPASS,
                R_P0_TSSI_MV_AVG,
                B_P0_TSSI_MV_MIX,
                B_P0_TSSI_MV_CLR,
                R_P0_TSSI_AVG,
                B_P0_TSSI_EN,
                R_P0_TSSI_TRK,
                B_P0_TSSI_RFC,
                B_P0_TSSI_OFT,
                B_P0_TSSI_OFT_EN,
            )
        } else {
            (
                R_P1_TSSIC,
                B_P1_TSSIC_BYPASS,
                R_P1_TSSI_MV_AVG,
                B_P1_RFCTM_DEL,
                B_P1_TSSI_MV_CLR,
                R_P1_TSSI_AVG,
                B_P1_TSSI_EN,
                R_P1_TSSI_TRK,
                B_P1_TSSI_RFC,
                B_P1_TSSI_OFT,
                B_P1_TSSI_OFT_EN,
            )
        };
        a.wm(control, bypass, 0)?;
        a.wm(mv, mix, 0x10)?;
        a.wm(mv, clr, 0)?;
        a.wm(avg, en, 0)?;
        a.wm(avg, en, 1)?;
        a.wr(path, RR_TXGA_V1, RR_TXGA_V1_TRK_EN, 1).await?;
        a.wm(trk, rfc, 3)?;
        a.wm(trk, offset, 0xc0)?;
        a.wm(trk, offset_en, 0)?;
        a.wm(trk, offset_en, 1)?;
        if a.bb(avg, en)? != 1 || a.bb(trk, rfc)? != 3 || a.bb(trk, offset_en)? != 1 {
            return Err(Error::Register(power::Error::Access));
        }
    }
    Ok(())
}
fn de<I: Interface>(
    a: &mut Access<'_, I>,
    calibration: &Calibration,
) -> Result<[[i16; 2]; 2], Error> {
    let mut values = [[0; 2]; 2];
    for (path, value) in values.iter_mut().enumerate() {
        let trim = i16::from(calibration.tssi_trim[path][0]);
        let cck = i16::from(calibration.tssi_cck[path][0]) + trim;
        let ofdm = i16::from(calibration.tssi_mcs[path][0]) + trim;
        let offset = (path as u32) << 13;
        for address in [0x5858, 0x5860] {
            a.wm(address + offset, 0x3ff000, cck as u32)?;
        }
        for address in [0x5838, 0x5840, 0x5848, 0x5850, 0x5828, 0x5830] {
            a.wm(address + offset, 0x3ff000, ofdm as u32)?;
        }
        if a.bb(0x5858 + offset, 0x3ff000)? != cck as u32 & 0x3ff
            || a.bb(0x5838 + offset, 0x3ff000)? != ofdm as u32 & 0x3ff
        {
            return Err(Error::Register(power::Error::Access));
        }
        *value = [cck, ofdm];
    }
    Ok(values)
}
fn signed9(value: u32) -> i32 {
    ((value << 23) as i32) >> 23
}
fn alignment_fields(cw: [u32; 2], defaults: [u32; 3]) -> [i32; 3] {
    let difference = cw[0] as i32 - 56 - cw[1] as i32;
    core::array::from_fn(|i| signed9(defaults[i]) + difference)
}
async fn alignment<I: Interface>(
    a: &mut Access<'_, I>,
    path: u8,
    calibration: &Calibration,
    bases: [i8; 2],
) -> Result<([u32; 2], [u32; 4]), Error> {
    let saved = pmac::backup(a)?;
    let regs = [
        0x5820, 0x7820, 0x4978, 0x58e4, 0x78e4, 0x49c0, 0x0d18, 0x0d80,
    ];
    let mut backup = [0; 8];
    for (i, register) in regs.iter().copied().enumerate() {
        backup[i] = a.bb(register, u32::MAX)?;
    }
    a.wm(R_P0_TSSI_AVG, B_P0_TSSI_AVG, 8)?;
    a.wm(R_P1_TSSI_AVG, B_P1_TSSI_AVG, 8)?;
    a.wm(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_AVG, 2)?;
    a.wm(R_P1_TSSI_MV_AVG, B_P1_TSSI_MV_AVG, 2)?;
    let measured = async {
        let mut cw = [0; 2];
        for index in 0..2 {
            let trigger = 0x5820 + (u32::from(path) << 13);
            a.wm(trigger, B_P0_TSSI_EN, 0)?;
            if a.bb(trigger, B_P0_TSSI_EN)? != 0 {
                return Err(power::Error::Access.into());
            }
            a.wm(trigger, B_P0_TSSI_EN, 1)?;
            if a.bb(trigger, B_P0_TSSI_EN)? != 1 {
                return Err(power::Error::Access.into());
            }
            a.bb(R_TX_COUNTER, 0xffff)?;
            a.bb(trigger, u32::MAX)?;
            pmac::transmit(
                a,
                if index == 0 { path } else { 14 },
                [48, 20][index],
                calibration,
                bases,
            )
            .await?;
            a.bb(R_TX_COUNTER, 0xffff)?;
            let report = 0x1c18 + (u32::from(path) << 13);
            let mut ready = false;
            for _ in 0..100 {
                if a.bb(report, B_TSSI_CWRPT_RDY)? != 0 {
                    ready = true;
                    break;
                }
                a.delay(30).await?;
                a.bb(R_TX_COUNTER, 0xffff)?;
            }
            if !ready {
                pmac::stop(a)?;
                return Err(Error::Register(power::Error::Timeout));
            }
            cw[index] = a.bb(report, B_TSSI_CWRPT)?;
            pmac::stop(a)?;
            a.bb(R_TX_COUNTER, 0xffff)?;
        }
        let default = 0x5630 + (u32::from(path) << 13);
        let defaults = [
            a.bb(default, 0x3ff00000)?,
            a.bb(default, 0x000ffc00)?,
            a.bb(default, 0x3ff)?,
        ];
        let fields = alignment_fields(cw, defaults);
        let encoded = ((fields[0] as u32) << B_P1_TSSI_ALIM11.trailing_zeros() & B_P1_TSSI_ALIM11)
            | ((fields[1] as u32) << B_P1_TSSI_ALIM12.trailing_zeros() & B_P1_TSSI_ALIM12)
            | ((fields[2] as u32) << B_P1_TSSI_ALIM13.trailing_zeros() & B_P1_TSSI_ALIM13);
        let offset = u32::from(path) << 13;
        a.wm(R_P0_TSSI_ALIM1 + offset, B_P0_TSSI_ALIM1, encoded)?;
        a.wm(R_P0_TSSI_ALIM2 + offset, B_P0_TSSI_ALIM2, encoded)?;
        let mut values = [0; 4];
        for (i, address) in [
            R_P0_TSSI_ALIM1,
            R_P0_TSSI_ALIM3,
            R_P0_TSSI_ALIM2,
            R_P0_TSSI_ALIM4,
        ]
        .into_iter()
        .enumerate()
        {
            values[i] = a.bb(address + offset, u32::MAX)?;
        }
        // Source caches the same four live values by channel as well as band.
        for address in [
            R_P0_TSSI_ALIM1,
            R_P0_TSSI_ALIM3,
            R_P0_TSSI_ALIM2,
            R_P0_TSSI_ALIM4,
        ] {
            a.bb(address + offset, u32::MAX)?;
        }
        Ok((cw, values))
    }
    .await;
    for (register, value) in regs.into_iter().zip(backup) {
        a.wm(register, u32::MAX, value)?;
    }
    pmac::restore(a, saved)?;
    pmac::mode_tmac(a)?;
    measured
}
pub(super) fn stop_pmac(io: &mut impl Interface) -> Result<(), Error> {
    let mut access = Access(io);
    pmac::stop(&mut access)?;
    pmac::mode_tmac(&mut access)
}
/// # Safety
/// Same retained initial B PHY0/channel1/20MHz owner, actual factory gain
/// snapshot/bases and RF_AB/rx_nss2 source profile. No concurrent producer.
/// This source BB path setup is neither calibration nor ordinary TX authority.
pub(super) unsafe fn configure_rx_ab(
    io: &mut impl Interface,
    calibration: &Calibration,
    gain_bases: [i8; 2],
) -> Result<(), Error> {
    pmac::configure_ab(&mut Access(io), calibration, gain_bases)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tssi/tests.rs"]
pub(super) mod tests;
