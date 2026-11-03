// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE BB/RF, TX power and channel tests (software models only; no
//! device, RF acceptance or emission measurement is implied).

use super::channel::{self, ChannelType, Operating};
use super::phy::{self, ByRate, Path};
use super::tables;
use super::txpower::{self, Efuse, Width};
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

/// BB register file plus a two-path RF model behind the LSSI/HSSI ports.
pub(super) struct RfState {
    pub regs: Vec<u8>,
    pub rf: [[u32; 256]; 2],
    /// RF writes in order: (path, addr, data).
    pub rf_writes: Vec<(usize, u8, u32)>,
    /// RF addresses whose stored value is corrupted on write (`^ mask`).
    pub stuck: Vec<(u8, u32)>,
    pub w32: Vec<(u16, u32)>,
}

#[derive(Clone)]
pub(super) struct RfFake(pub Arc<IrqSafeSpinLock<RfState>>);

impl RfFake {
    pub fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(RfState {
            regs: vec![0; 0x1000],
            rf: [[0; 256]; 2],
            rf_writes: Vec::new(),
            stuck: Vec::new(),
            w32: Vec::new(),
        })))
    }
}

fn put32(regs: &mut [u8], at: u16, v: u32) {
    let r = usize::from(at);
    regs[r..r + 4].copy_from_slice(&v.to_le_bytes());
}

#[async_trait::async_trait]
impl Io for RfFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.regs[r],
            g.regs[r + 1],
            g.regs[r + 2],
            g.regs[r + 3],
        ]))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        self.0.lock().regs[usize::from(reg)] = value;
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        put32(&mut g.regs, reg, value);
        g.w32.push((reg, value));
        let path = match reg {
            phy::RFPGA0_XA_LSSIPARAMETER => Some(0),
            phy::RFPGA0_XB_LSSIPARAMETER => Some(1),
            _ => None,
        };
        if let Some(p) = path {
            let addr = ((value >> 20) & 0xff) as u8;
            let mut data = value & 0xf_ffff;
            if let Some((_, m)) = g.stuck.iter().find(|(a, _)| *a == addr) {
                data ^= *m;
            }
            g.rf[p][usize::from(addr)] = data;
            g.rf_writes.push((p, addr, value & 0xf_ffff));
        }
        let read = match reg {
            phy::RFPGA0_XA_HSSIPARAMETER2 => Some(0),
            phy::RFPGA0_XB_HSSIPARAMETER2 => Some(1),
            _ => None,
        };
        if let Some(p) = read {
            if value & phy::BLSSIREADEDGE != 0 {
                let addr = ((value >> 23) & 0xff) as usize;
                let v = g.rf[p][addr];
                let (rb, pi) = if p == 0 {
                    (phy::RFPGA0_XA_LSSIREADBACK, phy::TRANSCEIVEA_HSPI_READBACK)
                } else {
                    (phy::RFPGA0_XB_LSSIREADBACK, phy::TRANSCEIVEB_HSPI_READBACK)
                };
                put32(&mut g.regs, rb, v);
                put32(&mut g.regs, pi, v);
            }
        }
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}

/// LSSI write word and HSSI read-edge read-back on both paths.
fn smoke_rtl8192ee_rf_serial_read_write_both_paths() -> TestResult {
    let io = RfFake::new();
    let r = narf_scheduler::block_on(async {
        phy::set_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK, 0x1_2c07).await?;
        phy::set_rf(&io, Path::B, 0x18, 0x3ff, 0x0_0005).await?;
        Ok::<_, crate::rtlwifi::prepare::Error>((
            phy::get_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?,
            phy::get_rf(&io, Path::B, 0x18, phy::RFREG_OFFSET_MASK).await?,
        ))
    });
    match r {
        Ok((0x1_2c07, 0x0_0005)) => {}
        _ => return TestResult::Fail("RF read-back through HSSI/LSSI"),
    }
    let g = io.0.lock();
    // 0x840 carries (addr << 20) | data.
    if !g.w32.contains(&(phy::RFPGA0_XA_LSSIPARAMETER, 0x0181_2c07)) {
        return TestResult::Fail("path A LSSI word");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_rf_serial_read_write_both_paths
);

/// `_rtl92ee_config_rf_reg`: `0xb6` and `0xb2` re-write at most six times;
/// `0xb2` retries also write RF `0x18 = 0x0fc07`.
fn smoke_rtl8192ee_rf_reg_b6_b2_retry_bounds() -> TestResult {
    let io = RfFake::new();
    io.0.lock().stuck = vec![(0xb6, 0x100), (0xb2, 0x1)];
    let r = narf_scheduler::block_on(async {
        phy::config_rf_reg(&io, Path::A, 0xb6, 0x4_9f00).await?;
        phy::config_rf_reg(&io, Path::B, 0xb2, 0x0_7a3c).await
    });
    if r.is_err() {
        return TestResult::Fail("config_rf_reg failed");
    }
    let g = io.0.lock();
    let b6 = g
        .rf_writes
        .iter()
        .filter(|w| w.0 == 0 && w.1 == 0xb6)
        .count();
    let b2 = g
        .rf_writes
        .iter()
        .filter(|w| w.0 == 1 && w.1 == 0xb2)
        .count();
    let r18 = g
        .rf_writes
        .iter()
        .filter(|w| **w == (1, 0x18, 0x0fc07))
        .count();
    if b6 != 7 || b2 != 7 || r18 != 6 {
        return TestResult::Fail("retry counts differ from Linux (1 + 6)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_rf_reg_b6_b2_retry_bounds
);

/// PHY_REG_PG store, BCD bases and relative conversion on the shipped table.
fn smoke_rtl8192ee_phy_reg_pg_by_rate_configuration() -> TestResult {
    let by = ByRate::from_pg(tables::PHY_REG_PG);
    // OFDM base from 0xe04 byte 3 (0x28 -> 28); CCK base from 0x86c byte 3.
    if by.base[0][phy::RF_1TX][1] != 28 || by.base[0][phy::RF_1TX][0] != 32 {
        return TestResult::Fail("txpwr_by_rate_base_24g path A");
    }
    // 0xe00 0x34343636 relative to 28.
    if by.offset[0][phy::RF_1TX][0] != 0x0606_0808 {
        return TestResult::Fail("relative OFDM 6-18M");
    }
    if phy::to_relative(0x3232_3200, 1, 3, 32) != 0
        || phy::to_relative(0x3400_0012, 3, 3, 30) != 0x0400_0012
        || phy::rate_section_index(0xc24) != 1
        || phy::rate_section_index(0x86c) != 3
    {
        return TestResult::Fail("relative conversion / section index");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_phy_reg_pg_by_rate_configuration
);

fn power_map() -> Vec<u8> {
    let mut map = vec![0xffu8; 512];
    for rf in 0..2 {
        let at = txpower::EEPROM_TX_PWR_INX + rf * txpower::PATH_STRIDE;
        for (i, b) in map[at..at + 6].iter_mut().enumerate() {
            *b = 0x20 + i as u8;
        }
        for (i, b) in map[at + 6..at + 11].iter_mut().enumerate() {
            *b = 0x30 + i as u8;
        }
        map[at + 11] = 0xf2; // bw20 -1, ofdm +2
        map[at + 12] = 0x1e; // bw40[1] +1, bw20[1] -2
        map[at + 13] = 0x00;
    }
    map[txpower::EEPROM_THERMAL_METER] = 0x22;
    map[txpower::EEPROM_RF_BOARD_OPTION] = 0xc1;
    map
}

/// `_rtl8192ee_read_power_value_fromprom` 2.4 GHz decode and the
/// autoload-fail refusal.
fn smoke_rtl8192ee_efuse_tx_power_decode() -> TestResult {
    let map = power_map();
    let e = match Efuse::from_logical(&map) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("provisioned power map refused"),
    };
    if e.cck[1][13] != 0x25 || e.cck[1][12] != 0x24 || e.ht40_1s[0][13] != 0x34 {
        return TestResult::Fail("channel-14 group selection");
    }
    if e.ht20_diff[0][0] != 0xff || e.legacy_ht_diff[0][0] != 2 {
        return TestResult::Fail("signed nibble diffs");
    }
    if e.ht40_diff[0][1] != 1 || e.ht20_diff[0][1] != 0xfe || e.ht40_diff[0][0] != 0 {
        return TestResult::Fail("second-count diffs");
    }
    if e.thermal_meter != 0x22 || e.regulatory != 1 {
        return TestResult::Fail("thermal / regulatory");
    }
    let mut bad = map.clone();
    bad[txpower::EEPROM_TX_PWR_INX + 1] = 0xff;
    if Efuse::from_logical(&bad).is_ok() {
        return TestResult::Fail("autoload-fail power map admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_efuse_tx_power_decode
);

/// `_rtl92ee_set_txpower_index` map and `_rtl92ee_get_txpower_index`.
fn smoke_rtl8192ee_txagc_map_and_index() -> TestResult {
    if txpower::txagc(0, 0x00) != Some((0xe08, 1))
        || txpower::txagc(0, 0x03) != Some((0x86c, 3))
        || txpower::txagc(1, 0x00) != Some((0x838, 1))
        || txpower::txagc(1, 0x03) != Some((0x86c, 0))
        || txpower::txagc(0, 0x0b) != Some((0xe04, 3))
        || txpower::txagc(1, 0x1b) != Some((0x868, 3))
        || txpower::txagc(1, 0x10) != Some((0x848, 0))
    {
        return TestResult::Fail("TXAGC register/lane map");
    }
    let e = match Efuse::from_logical(&power_map()) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("power map refused"),
    };
    let by = ByRate::from_pg(tables::PHY_REG_PG);
    // MCS8 at 20 MHz on channel 6 (group 2): 0x32 + (-1) + (-2) + by-rate.
    let want = 0x32u8
        .wrapping_add(0xff)
        .wrapping_add(0xfe)
        .wrapping_add(txpower::by_rate_diff(&by, 0, 0x14))
        .min(0x3f);
    if txpower::index(&e, &by, 0, 0x14, Width::W20, 6) != want {
        return TestResult::Fail("HT 2SS 20 MHz index");
    }
    let io = RfFake::new();
    if txpower::set_level(&io, &e, &by, Width::W40, 6).is_err() {
        return TestResult::Fail("set_level failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_txagc_map_and_index
);

/// `rtl_op_config` wide channel, `sw_chnl` RF 0x18 low bits and the 40 MHz
/// `set_bw_mode_callback` writes.
fn smoke_rtl8192ee_channel_and_bw40() -> TestResult {
    if Operating::new(1, ChannelType::Ht40Minus).is_ok()
        || Operating::new(11, ChannelType::Ht40Plus).is_ok()
        || Operating::new(15, ChannelType::Ht20).is_ok()
    {
        return TestResult::Fail("invalid 2.4 GHz operating points admitted");
    }
    let op = match Operating::new(6, ChannelType::Ht40Plus) {
        Ok(op) => op,
        Err(_) => return TestResult::Fail("ch6 HT40+ refused"),
    };
    if op.wide != 8 || op.prime_sc != channel::PRIME_LOWER {
        return TestResult::Fail("wide channel / prime_sc");
    }
    let e = match Efuse::from_logical(&power_map()) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("power map refused"),
    };
    let by = ByRate::from_pg(tables::PHY_REG_PG);
    let io = RfFake::new();
    {
        let mut g = io.0.lock();
        g.regs[usize::from(channel::REG_BWOPMODE)] = 0x04;
        g.regs[usize::from(channel::REG_RRSR + 2)] = 0xff;
        g.rf[0][0x18] = 0x0_0c01;
        g.rf[1][0x18] = 0x0_0c01;
    }
    let mut chnlval = [0x0_0c01u32, 0x0_0c01];
    if narf_scheduler::block_on(channel::configure(&io, &e, &by, &op, &mut chnlval)).is_err() {
        return TestResult::Fail("configure failed");
    }
    let g = io.0.lock();
    if g.regs[usize::from(channel::REG_BWOPMODE)] != 0
        || g.regs[usize::from(channel::REG_RRSR + 2)] != 0x90 | (1 << 5)
    {
        return TestResult::Fail("BWOPMODE / RRSR sub-channel");
    }
    if g.rf[0][0x18] != 0x0_0408 || g.rf[1][0x18] != 0x0_0408 {
        return TestResult::Fail("RF 0x18 channel/bandwidth bits");
    }
    if (g.regs[0x81b] >> 2) & 3 != 2 || g.regs[0x900] & 1 != 1 {
        return TestResult::Fail("0x818[27:26] / RFPGA1_RFMOD");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_channel_and_bw40
);

/// `_rtl92ee_phy_simularity_compare`: signed odd entries, the zero-RX
/// candidate rule and per-section copies into `result[3]`.
fn smoke_rtl8192ee_iqk_simularity_compare() -> TestResult {
    use super::iqk::simularity_compare;
    let mut r = [[0u32; 8]; 4];
    r[0] = [0x100, 0x3fe, 0x100, 0x10, 0x100, 0, 0x100, 0];
    r[1] = [0x101, 0x002, 0x100, 0x10, 0x100, 0, 0x100, 0];
    if !simularity_compare(&mut r, 0, 1) {
        return TestResult::Fail("-2 and +2 are within MAX_TOLERANCE");
    }
    r[1][2] = 0x120;
    r[3] = [0; 8];
    if simularity_compare(&mut r, 0, 1) || r[3][0] != 0x100 || r[3][2] != 0 || r[3][4] != 0x100 {
        return TestResult::Fail("path A RX mismatch must not copy RX, but TX/B");
    }
    // c2 RX all zero names c1 as the path-A RX candidate; the [3] mismatch
    // still sets the bitmap, so only the agreeing TX section is copied.
    let mut r = [[0u32; 8]; 4];
    r[0] = [0x100, 0, 0x120, 0x10, 0, 0, 0, 0];
    r[1] = [0x101, 0, 0, 0, 0, 0, 0, 0];
    if simularity_compare(&mut r, 0, 1) || r[3][0] != 0x100 || r[3][1] != 0 {
        return TestResult::Fail("zero-RX candidate selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_iqk_simularity_compare
);

/// Full `rtl92ee_phy_iq_calibrate(false)` on an idle model: runs 0 and 1
/// agree (candidate 0), MAC/BB backups reloaded after run 1.
fn smoke_rtl8192ee_iqk_full_run_restores_backups() -> TestResult {
    let io = RfFake::new();
    {
        let mut g = io.0.lock();
        g.regs[0x522] = 0x12;
        g.regs[0xc04] = 0x33;
        g.regs[0x85c] = 0x44;
    }
    let report = match narf_scheduler::block_on(super::iqk::calibrate(&io)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("calibrate failed on the model"),
    };
    if report.final_candidate != 0 {
        return TestResult::Fail("identical runs must select candidate 0");
    }
    let g = io.0.lock();
    if g.regs[0x522] != 0x12 || g.regs[0xc04] != 0x33 || g.regs[0x85c] != 0x44 {
        return TestResult::Fail("MAC/BB/ADDA backups not reloaded");
    }
    if g.regs[usize::from(super::iqk::RFPGA0_IQK) + 3] != 0 {
        return TestResult::Fail("left in IQK mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_iqk_full_run_restores_backups
);
