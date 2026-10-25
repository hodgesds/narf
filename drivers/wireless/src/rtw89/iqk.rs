// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One-shot RTL8852B initial PHY0/channel1/20MHz, RF-AB wideband IQK.
//! Linux rtw8852b_rfk.c, including path-local backup and restore. The enclosing
//! native owner supplies measured emission/coexistence/current-policy authority.
use super::{
    power,
    rfk::{Error, Interface, Kind},
};
#[path = "iqk/registers.rs"]
mod registers;
use registers::*;
#[path = "iqk/recipe.rs"]
mod recipe;
#[path = "iqk/tables.rs"]
mod tables;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Failed,
    Calibrated,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Path {
    pub coarse_failed: bool,
    pub fine_failed: bool,
    pub lok_failed: bool,
    pub tx_failed: bool,
    pub rx_failed: bool,
    pub restore_failed: bool,
    pub attempts: u8,
    pub idac: u32,
    pub vbuf: u32,
    pub tx_cfir: u32,
    pub rx_cfir: u32,
    pub enable: u32,
    pub tx_iqc: u32,
    pub rx_iqc: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Results {
    pub paths: [Path; 2],
    pub runs: u8,
    pub failures: u8,
    pub synth_1_to_2: bool,
    pub bb_backup: [[u32; 3]; 2],
    pub rf_backup: [[u32; 11]; 2],
}
#[derive(Default)]
pub(super) struct Iqk {
    state: State,
    results: Results,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn bb(&mut self, address: u32, mask: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let value = self.0.read32(0x10000 + address)?;
        if value == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok((value & mask) >> mask.trailing_zeros())
    }
    fn wm(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.bb(address, u32::MAX)?;
        self.0.admit()?;
        self.0.write32(
            0x10000 + address,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )?;
        Ok(())
    }
    async fn rr(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.0.admit()?;
        self.0.rf_read(path, address, mask).await
    }
    async fn wr(&mut self, path: u8, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(path, address, mask, value).await
    }
    async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
    fn table(&mut self, entries: &[(u32, u32, u32)]) -> Result<(), Error> {
        for &(address, mask, value) in entries {
            self.wm(address, mask, value)?;
            if self.bb(address, mask)? != value {
                return Err(Error::Terminal);
            }
        }
        Ok(())
    }
    async fn check_cal(&mut self) -> Result<bool, Error> {
        let start = self.0.now_us();
        loop {
            if self.bb(0xbff8, 0xff)? == 0x55 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 8200 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
        self.delay(200).await?;
        let failed = self.bb(R_NCTL_RPT, B_NCTL_RPT_FLG)? != 0;
        self.wm(R_NCTL_N1, 0xff, 0)?;
        if self.bb(R_NCTL_N1, 0xff)? != 0 {
            return Err(Error::Terminal);
        }
        Ok(failed)
    }
    fn trigger(&mut self, command: u32) -> Result<(), Error> {
        // Source clears NCTL_N1 byte0 after each completion. Refuse a stale
        // completed owner, without assuming the command register is stable.
        if self.bb(R_NCTL_N1, 0xff)? == 0x55 {
            return Err(Error::Terminal);
        }
        self.wm(R_NCTL_CFG, u32::MAX, command)
    }
    async fn shot(&mut self, path: u8, kind: u8) -> Result<bool, Error> {
        let command = match kind {
            1 | 2 | 8 => {
                self.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 1)?;
                (match kind {
                    1 => 0x108,
                    2 => 0x208,
                    _ => 0x308,
                }) | (1 << (4 + path))
            }
            3 => {
                self.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 0)?;
                0x808 | (1 << (4 + path))
            }
            5 => {
                self.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 1)?;
                0xb08 | (1 << (4 + path))
            }
            _ => return Err(Error::Table),
        };
        self.trigger(command + 1)?;
        self.delay(1).await?;
        let failed = self.check_cal().await?;
        self.wm(R_P0_RFCTM, B_P0_RFCTM_EN, 0)?;
        Ok(failed)
    }
    async fn tx_clock(&mut self) -> Result<(), Error> {
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
        self.wm(R_P1_DBGMOD, B_P1_DBGMOD_ON, 1)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x1f)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x13)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 1)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x41)
    }
    async fn rx_clock(&mut self) -> Result<(), Error> {
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
        self.wm(R_P1_DBGMOD, B_P1_DBGMOD_ON, 1)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x0f)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 3)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0xa001)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0xa041)?;
        self.wm(R_P0_RXCK, B_P0_RXCK_VAL, 1)?;
        self.wm(R_P0_RXCK, B_P0_RXCK_ON, 1)?;
        self.wm(R_P1_RXCK, B_P1_RXCK_VAL, 1)?;
        self.wm(R_P1_RXCK, B_P1_RXCK_ON, 1)?;
        self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_ON, 1)?;
        self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_VAL, 0)
    }
    async fn tx_setting(&mut self, path: u8) -> Result<(), Error> {
        for (address, mask, value) in [
            (RR_XALNA2, RR_XALNA2_SW2, 0),
            (RR_TXG1, RR_TXG1_ATT2, 0),
            (RR_TXG1, RR_TXG1_ATT1, 0),
            (RR_TXG2, RR_TXG2_ATT0, 1),
            (RR_TXGA, RR_TXGA_LOK_EXT, 0),
            (RR_LUTWE, RR_LUTWE_LOK, 1),
            (RR_LUTWA, RR_LUTWA_M1, 0),
            (RR_MOD, RR_MOD_IQK, 0x403e),
        ] {
            self.wr(path, address, mask, value).await?;
        }
        self.delay(1).await
    }
    async fn lok(&mut self, path: u8, result: &mut Path) -> Result<(), Error> {
        self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x21)?;
        self.wr(path, RR_TXIG, RR_TXIG_GR0, 0).await?;
        self.wr(path, RR_TXIG, RR_TXIG_GR1, 6).await?;
        self.wr(path, RR_TXIG, RR_TXIG_TG, 0).await?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, 9)?;
        result.coarse_failed = self.shot(path, 1).await?;
        self.wr(path, RR_TXIG, RR_TXIG_TG, 0x12).await?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, 0x24)?;
        let vbuffer0 = self.shot(path, 8).await?;
        self.wr(path, RR_TXIG, RR_TXIG_TG, 0).await?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, 9)?;
        self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x21)?;
        result.fine_failed = self.shot(path, 2).await?;
        self.wr(path, RR_TXIG, RR_TXIG_TG, 0x12).await?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, 0x24)?;
        let vbuffer1 = self.shot(path, 8).await?;
        result.idac = self.rr(path, RR_TXMO, RFREG_MASK).await?;
        result.vbuf = self.rr(path, RR_LOKVB, RFREG_MASK).await?;
        let field = |value, mask: u32| (value & mask) >> mask.trailing_zeros();
        result.lok_failed = !(2..=0x1d).contains(&field(result.idac, RR_TXMO_COI))
            || !(2..=0x1d).contains(&field(result.idac, RR_TXMO_COQ))
            || !(2..=0x3d).contains(&field(result.vbuf, RR_LOKVB_COI))
            || !(2..=0x3d).contains(&field(result.vbuf, RR_LOKVB_COQ));
        // Source uses the final measured bounds to decide the bias retry. Keep
        // that decision, but never grant readiness on a failed VBUFFER shot.
        result.restore_failed |= vbuffer0 || vbuffer1;
        Ok(())
    }
    async fn by_path(&mut self, path: u8, result: &mut Path) -> Result<(), Error> {
        let offset = u32::from(path) << 8;
        self.tx_clock().await?;
        for bias in 1..=3 {
            result.attempts = bias;
            self.wr(path, RR_LUTWE, RFREG_MASK, 2).await?;
            self.wr(path, RR_LUTWA, RFREG_MASK, 0).await?;
            self.wr(path, RR_LUTWD0, RFREG_MASK, u32::from(bias))
                .await?;
            self.wr(path, RR_LUTWE, RFREG_MASK, 0).await?;
            self.wr(path, RR_TXVBUF, RR_TXVBUF_DACEN, 1).await?;
            self.tx_setting(path).await?;
            self.lok(path, result).await?;
            if !result.lok_failed {
                break;
            }
        }
        for group in 0..4 {
            self.wr(path, RR_TXIG, RR_TXIG_GR0, 0).await?;
            self.wr(path, RR_TXIG, RR_TXIG_GR1, [4, 4, 6, 6][group])
                .await?;
            self.wr(path, RR_TXIG, RR_TXIG_TG, [8, 14, 6, 14][group])
                .await?;
            self.wm(R_KIP_IQP + offset, u32::MAX, [9, 18, 27, 36][group])?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_SET, 1)?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_G2, 0)?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_GP, group as u32)?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            let failed = self.shot(path, 3).await?;
            self.wm(
                R_IQKINF,
                1 << (8 + group + usize::from(path) * 4),
                u32::from(failed),
            )?;
            result.tx_failed |= failed;
        }
        result.tx_cfir = if result.tx_failed {
            0x40000002
        } else {
            0x40000000
        };
        self.wm(
            R_IQK_RES + offset,
            B_IQK_RES_TXCFIR,
            if result.tx_failed { 0 } else { 5 },
        )?;
        self.rx_clock().await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, 0xc).await?;
        self.wr(path, RR_RXK, RR_RXK_SEL2G, 1).await?;
        let channel = self.rr(path, RR_CFGCH, RFREG_MASK).await?;
        self.wr(path, RR_RSV4, RFREG_MASK, channel).await?;
        for group in 0..4 {
            self.wr(
                path,
                RR_MOD,
                RR_MOD_RGM,
                [0x212, 0x21c, 0x350, 0x360][group],
            )
            .await?;
            self.wr(path, RR_RXBB, RR_RXBB_C2G, [0, 0, 0x28, 0x5f][group])
                .await?;
            self.wr(path, RR_RXBB, RR_RXBB_C1G, [3, 3, 2, 1][group])
                .await?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_SET, 0)?;
            self.wm(R_CFIR_LUT + offset, B_CFIR_LUT_GP_V1, group as u32)?;
            let failed = self.shot(path, 5).await?;
            self.wm(
                R_IQKINF,
                1 << (16 + group + usize::from(path) * 4),
                u32::from(failed),
            )?;
            result.rx_failed |= failed;
        }
        self.wr(path, RR_RXK, RR_RXK_SEL5G, 0).await?;
        result.rx_cfir = if result.rx_failed {
            0x40000002
        } else {
            0x40000000
        };
        self.wm(
            R_IQK_RES + offset,
            B_IQK_RES_RXCFIR,
            if result.rx_failed { 0 } else { 5 },
        )?;
        Ok(())
    }
    fn info(&mut self, path: u8, results: &mut Results) -> Result<(), Error> {
        let result = &mut results.paths[usize::from(path)];
        for (mask, failed) in [
            (B_IQKINF_FCOR, result.coarse_failed),
            (B_IQKINF_FFIN, result.fine_failed),
            (B_IQKINF_FTX, result.tx_failed),
            (B_IQKINF_F_RX, result.rx_failed),
        ] {
            self.wm(R_IQKINF, mask << (path * 4), u32::from(failed))?;
        }
        let offset = u32::from(path) << 8;
        result.enable = self.bb(R_IQK_RES + offset, u32::MAX)?;
        result.tx_iqc = self.bb(R_TXIQC + offset, u32::MAX)?;
        result.rx_iqc = self.bb(R_RXIQC + offset, u32::MAX)?;
        self.wm(R_IQKINF2, B_IQKINF2_KCNT, u32::from(results.runs))?;
        if self.bb(R_IQKINF, B_IQKINF_FAIL << (path * 4))? != 0 {
            results.failures += 1;
        }
        self.wm(
            R_IQKINF2,
            B_IQKINF2_FCNT << (path * 4),
            u32::from(results.failures),
        )
    }
    async fn restore(&mut self, path: u8, result: &mut Path) -> Result<(), Error> {
        let offset = u32::from(path) << 8;
        self.wm(R_TXIQC + offset, u32::MAX, result.tx_cfir)?;
        self.wm(R_RXIQC + offset, u32::MAX, result.rx_cfir)?;
        self.trigger(0xe19 + (u32::from(path) << 4))?;
        result.restore_failed |= self.check_cal().await?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.wm(R_NCTL_RPT, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x80000000)?;
        self.wm(R_CFIR_SYS, B_IQK_RES_K, 0)?;
        self.wm(R_IQRSN, B_IQRSN_K1, 0)?;
        self.wm(R_IQRSN, B_IQRSN_K2, 0)?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0).await?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, 3).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 1).await?;
        self.wr(path, RR_BBDC, RR_BBDC_SEL, 1).await
    }
}
impl Iqk {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn results(&self) -> Option<&Results> {
        (self.state == State::Calibrated).then_some(&self.results)
    }
    pub(super) fn diagnostics(&self) -> &Results {
        &self.results
    }
    /// # Safety
    /// Exact RTL8852B PHY0/nonDBCC/channel1/20MHz RF-AB after actual channel,
    /// basic RFK and NCTL loading. Interface must enforce the full measured IQK
    /// emission recipe/current board policy and real coexistence at every access.
    /// The enclosing native one-shot attempt owns shutdown and retains all DMA
    /// on failure/cancellation; no concurrent PHY/packet/reset/PM owner exists.
    pub(super) async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Failed;
        io.admit()?;
        io.begin(Kind::Iqk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        for path in 0..2 {
            let start = access.0.now_us();
            while access.rr(path, RR_MOD, RR_MOD_MASK).await? == 2 {
                if access.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                access.delay(2).await?;
            }
        }
        access.wm(R_IQKINF, u32::MAX, 0)?;
        for path in 0..2 {
            let p = usize::from(path);
            // Native coexistence maps this nested event to IQK ONESHOT_START.
            access.0.admit()?;
            access.0.begin(Kind::IqkPath).await?;
            self.results.runs += 1;
            access.rr(path, RR_CFGCH, RFREG_MASK).await?;
            self.results.synth_1_to_2 = access.bb(R_CIRST, B_CIRST_SYN)? == 1;
            access.wm(R_IQKINF, B_IQKINF_VER, 0x2a)?;
            access.wm(R_IQKCH, B_IQKCH_BAND << (path * 16), 0)?;
            access.wm(R_IQKCH, B_IQKCH_BW << (path * 16), 0)?;
            access.wm(R_IQKCH, B_IQKCH_CH << (path * 16), 1)?;
            for (index, &register) in tables::BACKUP_BB.iter().enumerate() {
                self.results.bb_backup[p][index] = access.bb(register, u32::MAX)?;
            }
            for (index, &register) in tables::BACKUP_RF.iter().enumerate() {
                self.results.rf_backup[p][index] = access.rr(path, register, RFREG_MASK).await?;
            }
            access.table(tables::SET)?;
            let offset = u32::from(path) << 8;
            access.wm(R_COEF_SEL + offset, B_COEF_SEL_IQC, 0)?;
            access.wm(R_CFIR_LUT + offset, B_CFIR_LUT_G3, 0)?;
            access.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
            access.wr(path, RR_BBDC, RR_BBDC_SEL, 0).await?;
            access.wm(R_NCTL_RPT, u32::MAX, 0x80)?;
            access.wm(R_KIP_SYSCFG, u32::MAX, 0x81ff010a)?;
            access.by_path(path, &mut self.results.paths[p]).await?;
            access.info(path, &mut self.results)?;
            access.restore(path, &mut self.results.paths[p]).await?;
            access.table(tables::RESTORE)?;
            for (index, &register) in tables::BACKUP_BB.iter().enumerate() {
                access.wm(register, u32::MAX, self.results.bb_backup[p][index])?;
                if access.bb(register, u32::MAX)? != self.results.bb_backup[p][index] {
                    return Err(Error::Terminal);
                }
            }
            for (index, &register) in tables::BACKUP_RF.iter().enumerate() {
                access
                    .wr(path, register, RFREG_MASK, self.results.rf_backup[p][index])
                    .await?;
            }
            access.0.admit()?;
            access.0.end(Kind::IqkPath).await?;
        }
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Iqk).await?;
        if self.results.paths.iter().any(|p| {
            p.coarse_failed
                || p.fine_failed
                || p.lok_failed
                || p.tx_failed
                || p.rx_failed
                || p.restore_failed
        }) {
            return Err(Error::Terminal);
        }
        access.0.admit()?;
        self.state = State::Calibrated;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "iqk/tests.rs"]
pub(super) mod tests;
