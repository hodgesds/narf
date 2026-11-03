// SPDX-License-Identifier: GPL-2.0-or-later
//! rtlwifi BT-coexistence glue tests (software models only; no BT
//! firmware, antenna or coexistence behaviour on hardware is implied).

use super::btc::*;
use crate::rtlwifi::prepare::Error;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register-file model of the `btc_coexist` HAL.
#[derive(Default)]
pub(crate) struct FakeHal {
    pub regs: BTreeMap<u16, u8>,
    /// (reg, value, width) in order.
    pub writes: Vec<(u16, u32, u8)>,
    pub h2c: Vec<(u8, Vec<u8>)>,
    pub rf: Vec<(u8, u32, u32, u32)>,
    pub mp: Vec<MpReport>,
    pub lps: Vec<(bool, LpsCtrl)>,
    pub ampdu: Vec<AmpduCfg>,
    pub now: u64,
    pub delays: u32,
}

impl FakeHal {
    pub fn get(&self, reg: u16, width: u8) -> u32 {
        (0..width).fold(0, |v, i| {
            v | u32::from(self.regs.get(&(reg + u16::from(i))).copied().unwrap_or(0)) << (8 * i)
        })
    }
    fn put(&mut self, reg: u16, value: u32, width: u8) {
        for i in 0..width {
            self.regs
                .insert(reg + u16::from(i), (value >> (8 * i)) as u8);
        }
        self.writes.push((reg, value, width));
    }
    pub fn last(&self, reg: u16) -> Option<u32> {
        self.writes.iter().rev().find(|w| w.0 == reg).map(|w| w.1)
    }
}

impl Hal for FakeHal {
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        Ok(self.get(reg, 1) as u8)
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        Ok(self.get(reg, 2) as u16)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        Ok(self.get(reg, 4))
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.put(reg, value.into(), 1);
        Ok(())
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        self.put(reg, value.into(), 2);
        Ok(())
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.put(reg, value, 4);
        Ok(())
    }
    async fn set_rf(&mut self, path: u8, reg: u32, mask: u32, data: u32) -> Result<(), Error> {
        self.rf.push((path, reg, mask, data));
        Ok(())
    }
    async fn get_rf(&mut self, _path: u8, _reg: u32, _mask: u32) -> Result<u32, Error> {
        Ok(0)
    }
    async fn fill_h2c(&mut self, id: u8, cmd: &[u8]) -> Result<(), Error> {
        self.h2c.push((id, cmd.to_vec()));
        Ok(())
    }
    async fn wait_bt_mp(&mut self, _wait_ms: u32) -> Result<Option<MpReport>, Error> {
        Ok(if self.mp.is_empty() {
            None
        } else {
            Some(self.mp.remove(0))
        })
    }
    async fn delay_ms(&mut self, _ms: u32) {
        self.delays += 1;
    }
    async fn lps_leave(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        self.lps.push((false, ctrl));
        Ok(Some([0, 2, 4, 0, 0x0c, 0x40, 0]))
    }
    async fn lps_enter(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        self.lps.push((true, ctrl));
        Ok(Some([1, 0, 2, 0, ctrl.rpwm_val, ctrl.lps_val, 0]))
    }
    fn rx_ampdu_apply(&mut self, cfg: AmpduCfg) {
        self.ampdu.push(cfg);
    }
    fn now_ms(&mut self) -> u64 {
        self.now
    }
}

pub(crate) fn pg(ant_num: u8, bt_exist: bool) -> HwPg {
    HwPg {
        bt_exist,
        ant_num,
        single_ant_path: 1,
        chip_type: ChipType::Rtl8723b,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    }
}

/// `exhalbtc_bind_bt_coex_withadapter` + `exhalbtc_initlize_variables`
/// defaults; `halbtc_bitmask_write_1byte`; `halbtc_get_wifi_bw` /
/// `link_status` / `central_chnl`.
fn smoke_rtlwifi_btc_bind_bitmask_and_wifi_queries() -> TestResult {
    let btc = BtCoexist::bind(pg(1, true));
    let b = btc.board_info;
    if !btc.binded
        || b.pg_ant_num != 1
        || b.btdm_ant_num != 1
        || b.btdm_ant_pos != BTC_ANTENNA_AT_MAIN_PORT
        || b.single_ant_path != 1
        || b.tfbga_package
        || btc.bt_info.agg_buf_size != 5
        || btc.statistics.cnt_bind != 1
    {
        return TestResult::Fail("bind defaults");
    }
    let mut p = pg(2, true);
    p.package_type = 4;
    if !BtCoexist::bind(p).board_info.tfbga_package {
        return TestResult::Fail("package 4 is TFBGA");
    }
    let mut btc = btc;
    let mut hal = FakeHal::default();
    hal.regs.insert(0x67, 0xa5);
    let mut cx = Ctx::new(&mut btc, &mut hal);
    if cx.write_1byte_bitmask(0x67, 0x30, 0x2).is_err() {
        return TestResult::Fail("bitmask write");
    }
    // (0xa5 & !0x30) | (2 << 4) = 0xa5.
    if hal.last(0x67) != Some(0xa5) {
        return TestResult::Fail("bitmask RMW");
    }
    let mut w = WifiInfo {
        station_linked: true,
        ap_client_connected: true,
        mode: WifiMode::G,
        chan_bw: ChanBw::Ht20_40,
        ..WifiInfo::default()
    };
    if w.bw() != WifiBw::Legacy || w.link_status() != 0x2_0003 || w.central_chnl() != 1 {
        return TestResult::Fail("legacy bw / link status / central chnl");
    }
    w.mode = WifiMode::N;
    w.current_channel = 6;
    if w.bw() != WifiBw::Ht40 || w.central_chnl() != 6 || !w.connected() {
        return TestResult::Fail("HT40 / channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc_bind_bitmask_and_wifi_queries
);

/// `halbtc_send_bt_mp_operation` header bytes, `halbtc_set_bt_reg`'s
/// value-then-address pair, `rtl_btc_btmpinfo_notify` version decode and
/// the timeout path.
fn smoke_rtlwifi_btc_mp_operation_and_bt_reg() -> TestResult {
    let mut btc = BtCoexist::bind(pg(1, true));
    let mut hal = FakeHal::default();
    hal.mp.push(MpReport::new(&[1, 0, 0x00, 0, 0]));
    hal.mp.push(MpReport::new(&[1, 0, 0x00, 0, 0]));
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.set_bt_reg(BtReg::Rf, 0x3c, 0x01c0)).is_err() {
            return TestResult::Fail("set_bt_reg");
        }
    }
    if hal.h2c.len() != 2
        || hal.h2c[0] != (0x67, alloc::vec![0x00, BT_OP_WRITE_REG_VALUE, 0xc0, 0x01])
        || hal.h2c[1] != (0x67, alloc::vec![0x00, BT_OP_WRITE_REG_ADDR, 0x00, 0x3c])
    {
        return TestResult::Fail("BT reg H2C 0x67 bodies");
    }
    // Version response: seq 0xe in tmp_buf[2][7:4].
    hal.h2c.clear();
    hal.mp.push(MpReport::new(&[1, 0, 0xe0, 0x34, 0x12, 0x07]));
    let ver = {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        narf_scheduler::block_on(cx.bt_patch_version())
    };
    if ver != Ok(0x1234)
        || btc.bt_info.bt_fw_ver != 7
        || hal.h2c != [(0x67, alloc::vec![0xe0, BT_OP_GET_BT_VERSION, 0, 0])]
    {
        return TestResult::Fail("BT patch version query");
    }
    // Cached: no second H2C.
    let again = {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        narf_scheduler::block_on(cx.bt_patch_version())
    };
    if again != Ok(0x1234) || hal.h2c.len() != 1 {
        return TestResult::Fail("patch version cached");
    }
    // A timed-out value write skips the address write.
    hal.h2c.clear();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.set_bt_reg(BtReg::Rf, 0x2c, 0));
    }
    if hal.h2c.len() != 1 {
        return TestResult::Fail("timeout stops set_bt_reg");
    }
    // Not from BT firmware / short: not accepted.
    if btc.btmpinfo_notify(&[0, 0, 0xe0, 1]) || btc.btmpinfo_notify(&[1, 0, 0xe0]) {
        return TestResult::Fail("btmpinfo extid / length gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc_mp_operation_and_bt_reg
);

/// `halbtc_{leave,enter,normal}_lps` flags + `rtl_btc_record_pwr_mode`,
/// the AP-mode refusal and `halbtc_aggregation_check`'s 8 s gate.
fn smoke_rtlwifi_btc_lps_actions_and_aggregation() -> TestResult {
    let mut btc = BtCoexist::bind(pg(1, true));
    let mut hal = FakeHal::default();
    btc.bt_info.lps_val = 0x50;
    btc.bt_info.rpwm_val = 0x04;
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.enter_lps()).is_err() {
            return TestResult::Fail("enter lps");
        }
    }
    if !btc.bt_info.bt_ctrl_lps
        || !btc.bt_info.bt_lps_on
        || btc.pwr_mode_val[..7] != [1, 0, 2, 0, 0x04, 0x50, 0]
        || !hal.lps[0].0
        || !hal.lps[0].1.bt_lps_on
    {
        return TestResult::Fail("enter lps flags / record");
    }
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.normal_lps());
    }
    if btc.bt_info.bt_ctrl_lps || btc.bt_info.bt_lps_on || hal.lps.len() != 2 || hal.lps[1].0 {
        return TestResult::Fail("normal lps");
    }
    btc.wifi.ap_mode = true;
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.leave_lps());
    }
    if hal.lps.len() != 2 || btc.bt_info.bt_ctrl_lps {
        return TestResult::Fail("AP mode keeps LPS");
    }
    // Aggregation: first check acts on the ctrl-size change.
    btc.bt_info.bt_ctrl_agg_buf_size = true;
    btc.bt_info.agg_buf_size = 8;
    hal.now = 10_000;
    Ctx::new(&mut btc, &mut hal).aggregation_check();
    if hal.ampdu.len() != 1 || hal.ampdu[0].agg_size != 8 || !hal.ampdu[0].ctrl_agg_size {
        return TestResult::Fail("aggregation apply");
    }
    btc.bt_info.agg_buf_size = 4;
    hal.now = 18_000;
    Ctx::new(&mut btc, &mut hal).aggregation_check();
    if hal.ampdu.len() != 1 {
        return TestResult::Fail("8 s gate");
    }
    hal.now = 18_001;
    Ctx::new(&mut btc, &mut hal).aggregation_check();
    if hal.ampdu.len() != 2 || hal.ampdu[1].agg_size != 4 {
        return TestResult::Fail("after 8 s");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc_lps_actions_and_aggregation
);
