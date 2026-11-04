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

// ── halbtc8723b1ant ───────────────────────────────────────────────────────

use super::b8723b1ant::{ap_tdma, ps_tdma_bytes, wifi_duration_adjust, B8723b1Ant, BtStatus};

fn h2c_last(hal: &FakeHal, id: u8) -> Option<Vec<u8>> {
    hal.h2c
        .iter()
        .rev()
        .find(|h| h.0 == id)
        .map(|h| h.1.clone())
}

/// Connected 8723BE station with a Linux-era firmware (>= 0x180000).
fn coex_1ant() -> (BtCoexist, FakeHal, B8723b1Ant) {
    let mut btc = BtCoexist::bind(pg(1, true));
    btc.wifi.fw_version = 0x24;
    btc.wifi.station_linked = true;
    btc.wifi.current_channel = 6;
    (btc, FakeHal::default(), B8723b1Ant::new())
}

/// `halbtc8723b1ant_ps_tdma` byte selection, `wifi_duration_adjust` and the
/// `set_fw_ps_tdma` AP-mode rewrite.
fn smoke_rtlwifi_btc8723b1ant_ps_tdma_tables() -> TestResult {
    if wifi_duration_adjust(3, 0) != 5
        || wifi_duration_adjust(3, 40) != -10
        || wifi_duration_adjust(50, 40) != -10
        || wifi_duration_adjust(50, 50) != -15
        || wifi_duration_adjust(25, 50) != -15
        || wifi_duration_adjust(10, 36) != -10
        || wifi_duration_adjust(10, 0) != 0
    {
        return TestResult::Fail("wifi_duration_adjust");
    }
    // (turn_on, type, force_lps_on, adj, slave_a2dp, scan_ap_num, bytes)
    type Case = (bool, u8, bool, i8, bool, u8, [u8; 5]);
    let cases: [Case; 9] = [
        (true, 2, false, 5, false, 10, [0x61, 0x32, 0x03, 0x11, 0x10]),
        (
            true,
            2,
            true,
            -10,
            false,
            10,
            [0x51, 0x23, 0x03, 0x10, 0x50],
        ),
        (
            true,
            101,
            false,
            0,
            false,
            10,
            [0xe3, 0x3a, 0x03, 0x71, 0x10],
        ),
        (true, 32, false, 0, true, 10, [0x61, 0x35, 0x03, 0x11, 0x11]),
        (true, 13, false, 0, false, 2, [0x51, 0x40, 0x03, 0x10, 0x10]),
        (true, 14, false, 0, false, 2, [0x51, 0x30, 0x03, 0x10, 0x50]),
        (
            true,
            99,
            false,
            0,
            false,
            10,
            [0x51, 0x1a, 0x1a, 0x00, 0x11],
        ),
        (false, 8, false, 0, false, 10, [0x08, 0, 0, 0, 0]),
        (false, 1, false, 0, false, 10, [0, 0, 0, 0x48, 0]),
    ];
    for (on, ty, lps, adj, slave, aps, want) in cases {
        if ps_tdma_bytes(on, ty, lps, adj, slave, aps) != want {
            return TestResult::Fail("ps_tdma byte table");
        }
    }
    if ap_tdma([0x51, 0x1a, 0x1a, 0, 0x50], true) != [0x61, 0x1a, 0x1a, 0, 0x30]
        || ap_tdma([0x51, 0x1a, 0x1a, 0, 0x50], false) != [0x51, 0x1a, 0x1a, 0, 0x50]
        || ap_tdma([0x61, 1, 1, 1, 0x50], true) != [0x61, 1, 1, 1, 0x50]
    {
        return TestResult::Fail("AP-mode TDMA rewrite");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b1ant_ps_tdma_tables
);

/// `ex_btc8723b1ant_power_on_setting` on an S0 (aux) PCI board, then
/// `rtl_btc_init_hw_config` with `bt_exist == 0` (`wifi_only`):
/// `init_hw_config` + `init_coex_dm` + the BT info query.
fn smoke_rtlwifi_btc8723b1ant_power_on_and_init_hw_config() -> TestResult {
    let (mut btc, mut hal, mut a) = coex_1ant();
    btc.bt_exist = false;
    hal.regs.insert(0x2, 0x10);
    hal.regs.insert(0x4c, 0x00);
    hal.regs.insert(0x4f, 0x01);
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.power_on_setting(&mut a)).is_err() {
            return TestResult::Fail("power on");
        }
    }
    if !btc.stop_coex_dm
        || btc.board_info.btdm_ant_pos != BTC_ANTENNA_AT_AUX_PORT
        || hal.last(0x67) != Some(0x20)
        || hal.writes.iter().all(|w| *w != (0x2, 0x13, 2))
        || hal.last(0x765) != Some(0x18)
        || hal.last(0x76e) != Some(0x4)
        || hal.last(0x948) != Some(0)
        || hal.last(0x384) != Some(1)
    {
        return TestResult::Fail("power_on_setting S0 writes");
    }
    hal.writes.clear();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.init_hw_config(&mut a)).is_err() {
            return TestResult::Fail("init hw config");
        }
    }
    let ids: Vec<u8> = hal.h2c.iter().map(|h| h.0).collect();
    if btc.stop_coex_dm
        || !btc.initialized
        // TDMA off(8) → PTA path (0x765 != 0 ⇒ 0x6e [0]), then the
        // init path's 0x6e [1] and antenna-select 0x65.
        || ids != [0x60, 0x6e, 0x6e, 0x65, 0x61]
        || hal.h2c[0].1 != [0x08, 0, 0, 0, 0]
        || hal.h2c[1].1 != [0]
        || hal.h2c[2].1 != [1]
        || hal.h2c[3].1 != [1, 0]
        || hal.rf != [(BTC_RF_A, 0x1, 0xfffff, 0x780)]
        // WIFI path on the aux port without the external switch.
        || hal.last(0x948) != Some(0x280)
        || hal.last(0x4c).map(|v| v & (3 << 23)) != Some(1 << 23)
        || hal.last(0x6c0) != Some(0x5555_5555)
        || hal.last(0x6c8) != Some(0x00ff_ffff)
        || hal.last(0x6cc) != Some(0x3)
        || hal.last(0x790) != Some(0x5)
        || hal.last(0x778) != Some(0x1)
        || !a.sta.c2h_bt_info_req_sent
    {
        return TestResult::Fail("init_hwconfig(wifi_only) sequence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b1ant_power_on_and_init_hw_config
);

/// A BT-response A2DP-busy `bt_info` C2H with a connected idle station:
/// profile parse, `bt_status`, `limited_tx/rx`, low-penalty RA and the
/// A2DP-only idle TDMA 32 / coex table 4.
fn smoke_rtlwifi_btc8723b1ant_bt_info_a2dp_connected() -> TestResult {
    let (mut btc, mut hal, mut a) = coex_1ant();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.power_on_setting(&mut a));
        let _ = narf_scheduler::block_on(cx.init_hw_config(&mut a));
    }
    hal.h2c.clear();
    // src BT_RSP; CONNECTION | ACL_BUSY | A2DP; TRx mask set; ext BIT4
    // (auto report on); bit pool 48.
    let info = [0x01, 0x49, 0x40, 0x30, 0x10, 0x00, 0x30];
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.bt_info_notify(&mut a, &info)).is_err() {
            return TestResult::Fail("bt_info notify");
        }
    }
    if !a.sta.a2dp_exist
        || a.sta.num_of_profile != 1
        || a.dm.bt_status != BtStatus::AclBusy
        || a.sta.a2dp_bit_pool != 0x30
        || !btc.bt_link_info.a2dp_only
        || !btc.bt_info.bt_busy
        || btc.bt_info.ra_mask != 0x3
        || hal.last(0x434) != Some(0x0403_0201)
        || hal.last(0x456) != Some(0x38)
        || h2c_last(&hal, 0x69) != Some(alloc::vec![0x6, 0x1, 0x00, 0xf7, 0xf8, 0xf9])
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0x61, 0x35, 0x03, 0x11, 0x11])
        || hal.last(0x6c4) != Some(0x5a5a_5a5a)
        || h2c_last(&hal, 0x67).is_some()
    {
        return TestResult::Fail("A2DP connected-idle mechanism");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b1ant_bt_info_a2dp_connected
);

/// `ex_btc8723b1ant_periodical` without auto report: a BT info query per
/// period and, after two all-zero counter periods, `bt_disabled` with the
/// Wi-Fi-only action; then `rtl_btc_ips_notify(ERFOFF)`.
fn smoke_rtlwifi_btc8723b1ant_periodical_bt_disable_and_ips() -> TestResult {
    let (mut btc, mut hal, mut a) = coex_1ant();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.init_hw_config(&mut a));
    }
    hal.h2c.clear();
    for _ in 0..2 {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.periodical(&mut a)).is_err() {
            return TestResult::Fail("periodical");
        }
    }
    let queries = hal.h2c.iter().filter(|h| h.0 == 0x61).count();
    if queries != 2
        || !a.sta.bt_disabled
        || !btc.bt_info.bt_disabled
        || btc.statistics.cnt_periodical != 2
    {
        return TestResult::Fail("BT disable monitor");
    }
    if hal.last(0x6c0) != Some(0x5555_5555)
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0x08, 0, 0, 0, 0])
    {
        return TestResult::Fail("action_wifi_only");
    }
    hal.regs.insert(0x4f, 0x01);
    hal.regs.insert(0x4e, 0x80);
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.ips_notify(&mut a, true)).is_err() {
            return TestResult::Fail("ips enter");
        }
    }
    if !a.sta.under_ips
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0, 0, 0, 0, 0])
        || hal.last(0x4c).map(|v| v & (3 << 23)) != Some(0)
        || btc.statistics.cnt_ips_notify != 1
    {
        return TestResult::Fail("IPS enter: BT path, wifi_off, TDMA off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b1ant_periodical_bt_disable_and_ips
);

// ── halbtc8723b2ant ───────────────────────────────────────────────────────

use super::b8723b2ant::{
    action_algorithm, adjust_initial_type, ps_tdma_bytes as ps_tdma_bytes_2ant, rssi_state,
    wifi_duration_adjust as wifi_duration_adjust_2ant, BtStatus as BtStatus2, CoexAlgo, Rtl8723b,
};

/// Connected, busy 8723BE station on a dual-antenna board with a
/// Linux-era firmware (>= 0x180000) and a strong signal.
fn coex_2ant() -> (BtCoexist, FakeHal, Rtl8723b) {
    let mut btc = BtCoexist::bind(pg(2, true));
    btc.wifi.fw_version = 0x24;
    btc.wifi.station_linked = true;
    btc.wifi.busy = true;
    btc.wifi.current_channel = 6;
    btc.wifi.undec_sm_pwdb = 60;
    (btc, FakeHal::default(), Rtl8723b::default())
}

/// `btc8723b2ant_ps_tdma` bytes and `wifi_duration_adjust`,
/// `tdma_duration_adjust`'s first type, `action_algorithm` and the
/// 2/3-level RSSI state machines.
fn smoke_rtlwifi_btc8723b2ant_tables_and_algorithm() -> TestResult {
    if wifi_duration_adjust_2ant(3, 0) != 5
        || wifi_duration_adjust_2ant(10, 0) != 0
        || wifi_duration_adjust_2ant(30, 0) != -5
        || wifi_duration_adjust_2ant(50, 0) != -10
        || wifi_duration_adjust_2ant(3, 40) != -10
        || wifi_duration_adjust_2ant(3, 48) != -15
    {
        return TestResult::Fail("wifi_duration_adjust");
    }
    if ps_tdma_bytes_2ant(true, 1, 0, 1) != [0xe3, 0x3c, 0x03, 0xf1, 0x91]
        || ps_tdma_bytes_2ant(true, 9, -15, 0) != [0xe3, 0x2d, 0x03, 0xf1, 0x90]
        || ps_tdma_bytes_2ant(true, 101, 5, 0) != [0xd3, 0x3f, 0x03, 0x70, 0x50]
        || ps_tdma_bytes_2ant(true, 122, 0, 1) != [0xe3, 0x35, 0x03, 0x71, 0x11]
        || ps_tdma_bytes_2ant(true, 16, 0, 0) != [0xe3, 0x10, 0x03, 0x70, 0x90]
        || ps_tdma_bytes_2ant(true, 8, 0, 0) != [0xa3, 0x10, 0x03, 0x70, 0x90]
        || ps_tdma_bytes_2ant(true, 99, 0, 0) != [0xe3, 0x3c, 0x03, 0xf1, 0x90]
        || ps_tdma_bytes_2ant(false, 1, 0, 0) != [0, 0, 0, 0x48, 0]
        || ps_tdma_bytes_2ant(false, 0, 0, 0) != [0, 0, 0, 0x40, 0]
    {
        return TestResult::Fail("ps_tdma bytes");
    }
    if adjust_initial_type(true, true, 1) != 13
        || adjust_initial_type(true, false, 3) != 11
        || adjust_initial_type(false, true, 2) != 6
        || adjust_initial_type(false, false, 7) != 3
    {
        return TestResult::Fail("adjust initial type");
    }
    let mut l = BtLinkInfo {
        bt_link_exist: true,
        a2dp_exist: true,
        ..BtLinkInfo::default()
    };
    if action_algorithm(&l, false) != CoexAlgo::A2dp {
        return TestResult::Fail("A2DP");
    }
    l.pan_exist = true;
    if action_algorithm(&l, false) != CoexAlgo::PanEdrA2dp {
        return TestResult::Fail("PAN(EDR)+A2DP");
    }
    l.hid_exist = true;
    if action_algorithm(&l, false) != CoexAlgo::HidA2dpPanEdr
        || action_algorithm(&l, true) != CoexAlgo::HidA2dp
    {
        return TestResult::Fail("HID+A2DP+PAN");
    }
    l.sco_exist = true;
    if action_algorithm(&l, false) != CoexAlgo::PanEdrHid
        || action_algorithm(&l, true) != CoexAlgo::Undefined
    {
        return TestResult::Fail("all four");
    }
    if rssi_state(RssiState::High, 40, 2, 42, 0) != RssiState::Low
        || rssi_state(RssiState::Low, 43, 2, 42, 0) != RssiState::StayLow
        || rssi_state(RssiState::Low, 44, 2, 42, 0) != RssiState::High
        || rssi_state(RssiState::StayLow, 50, 3, 46, 37) != RssiState::StayLow
        || rssi_state(RssiState::Low, 30, 3, 20, 37) != RssiState::Medium
        || rssi_state(RssiState::Medium, 39, 3, 20, 37) != RssiState::High
    {
        return TestResult::Fail("rssi state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b2ant_tables_and_algorithm
);

/// `exhalbtc_*` dispatch by `btdm_ant_num` and `ex_btc8723b2ant_power_on`
/// / `init_hwconfig` / `init_coex_dm` on a PCI S0 board.
fn smoke_rtlwifi_btc8723b2ant_power_on_and_init_hw_config() -> TestResult {
    let (mut btc, mut hal, mut a) = coex_2ant();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.pre_load_firmware(&mut a)).is_err()
            || narf_scheduler::block_on(cx.power_on_setting(&mut a)).is_err()
            || narf_scheduler::block_on(cx.init_hw_config(&mut a)).is_err()
        {
            return TestResult::Fail("power on / init");
        }
    }
    if hal.last(0x384) != Some(0x5)
        || hal.last(0x948) != Some(0x0)
        || btc.board_info.btdm_ant_pos != BTC_ANTENNA_AT_AUX_PORT
        || !btc.auto_report_2ant
        || !btc.initialized
    {
        return TestResult::Fail("power on / pre-load");
    }
    if hal.last(0x790) != Some(0x5)
        || hal.last(0x930) != Some(0x77)
        || hal.last(0x4c).map(|v| v & (3 << 23)) != Some(1 << 23)
        || hal.last(0x778) != Some(0x3)
        || h2c_last(&hal, 0x6e) != Some(alloc::vec![1])
        || h2c_last(&hal, 0x65) != Some(alloc::vec![1, 0])
        || hal.last(0x6c0) != Some(0x5555_5555)
        || hal.last(0x6c4) != Some(0x5555_5555)
    {
        return TestResult::Fail("init_hwconfig");
    }
    if h2c_last(&hal, 0x60) != Some(alloc::vec![0, 0, 0, 0x48, 0])
        || h2c_last(&hal, 0x64) != Some(alloc::vec![6])
        || h2c_last(&hal, 0x62) != Some(alloc::vec![0])
        // Low-penalty RA off equals its zeroed previous state: not sent.
        || h2c_last(&hal, 0x69).is_some()
    {
        return TestResult::Fail("init_coex_dm");
    }
    // The 1-antenna algorithm stays untouched on a 2-antenna board.
    if a.one.dm.cur_ps_tdma != 0 || a.two.dm.cur_ps_tdma != 1 {
        return TestResult::Fail("dispatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b2ant_power_on_and_init_hw_config
);

/// A BT-response A2DP-busy `bt_info` with a busy station: `action_a2dp`
/// (native power save, coex table 7, `tdma_duration_adjust` from type 1),
/// then three retry-free periodicals step the adjust up to type 71 with
/// the bit-pool duration adjust; IPS enter turns the radio over to BT.
fn smoke_rtlwifi_btc8723b2ant_a2dp_tdma_adjust_and_ips() -> TestResult {
    let (mut btc, mut hal, mut a) = coex_2ant();
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        let _ = narf_scheduler::block_on(cx.power_on_setting(&mut a));
        let _ = narf_scheduler::block_on(cx.init_hw_config(&mut a));
    }
    hal.h2c.clear();
    // src BT_RSP; CONNECTION | ACL_BUSY | A2DP; no retries; RSSI 0x20
    // (74); ext BIT4; bit pool 48.
    let info = [0x01, 0x49, 0x00, 0x20, 0x10, 0x00, 0x30];
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.bt_info_notify(&mut a, &info)).is_err() {
            return TestResult::Fail("bt_info notify");
        }
    }
    let t = &a.two;
    if !t.sta.a2dp_exist
        || t.sta.bt_rssi != 74
        || t.sta.a2dp_bit_pool != 0x30
        || t.dm.bt_status != BtStatus2::AclBusy
        || t.dm.cur_algorithm != CoexAlgo::A2dp
        || !t.dm.auto_tdma_adjust
        || t.dm.ps_tdma_du_adj_type != 1
        || !btc.bt_info.bt_busy
        || !btc.bt_info.limited_dig
        || !btc.bt_link_info.a2dp_only
        || hal.last(0x6c0) != Some(0x55dd_55dd)
        || hal.last(0x6c4) != Some(0x5ada_5ada)
        || h2c_last(&hal, 0x62) != Some(alloc::vec![2])
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0xe3, 0x3c, 0x03, 0xf1, 0x90])
    {
        return TestResult::Fail("A2DP action");
    }
    for _ in 0..3 {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.periodical(&mut a)).is_err() {
            return TestResult::Fail("periodical");
        }
    }
    let t = &a.two;
    if t.dm.cur_ps_tdma != 71
        || t.dm.ps_tdma_du_adj_type != 71
        || t.st.n != 3
        || t.st.up != 0
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0xe3, 0x2d, 0x03, 0xf1, 0x90])
        || h2c_last(&hal, 0x6e) != Some(alloc::vec![0])
        || hal.last(0x76e) != Some(0xc)
        || h2c_last(&hal, 0x61).is_some()
    {
        return TestResult::Fail("duration adjust up");
    }
    {
        let mut cx = Ctx::new(&mut btc, &mut hal);
        if narf_scheduler::block_on(cx.ips_notify(&mut a, true)).is_err() {
            return TestResult::Fail("ips enter");
        }
    }
    if !a.two.sta.under_ips
        || h2c_last(&hal, 0x63) != Some(alloc::vec![1])
        || h2c_last(&hal, 0x6e) != Some(alloc::vec![1])
        || h2c_last(&hal, 0x60) != Some(alloc::vec![0, 0, 0, 0x48, 0])
        || hal.rf.last() != Some(&(BTC_RF_A, 0x1, 0xfffff, 0x0))
        || hal.last(0x6c0) != Some(0x5555_5555)
    {
        return TestResult::Fail("IPS enter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_rtlwifi_btc8723b2ant_a2dp_tdma_adjust_and_ips
);
