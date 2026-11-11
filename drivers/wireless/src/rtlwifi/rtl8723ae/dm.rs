// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE Bluetooth-coexistence mechanism trees (the "tree lane" the
//! pass-1 owner in `coex.rs` deferred).
//!
//! Linux `rtl8723ae/hal_btc.c` splits the 8723A coexistence mechanism in
//! two halves: the watchdog DM (`rtl8723e_dm_bt_coexist_8723`) runs the
//! 1-ant / 2-ant mechanism trees over HW-counter monitors, and the
//! firmware-event path parses `BtInfo` and triggers the periodical. This
//! module is the first half: the query / counter-monitor / enable-check
//! prologue, the 2-ant dispatch (common action, HID/SCO/eSCO, FTP/A2DP,
//! inquiry/page monitor), the 1-ant path (an empty stub in Linux —
//! ported as a no-op, not invented), the `set_bt_dm` apply path with its
//! FW/MMIO setters, and the `_8723a` all-off sequences.
//!
//! ## What is ported here (grounded, `hal_btc.c` line numbers at
//! torvalds/linux @ 05441d6)
//!
//! | Linux source | NARF item |
//! |---|---|
//! | `rtl8723e_dm_bt_coexist_8723` (:1613) | [`Owner::run_mechanism`] |
//! | `rtl8723e_dm_init_bt_coexist` (`dm.c:795`, incl. the `RF_RCK1`/`RF_RCK2` origin reads) | [`Owner::mech_init`] |
//! | `rtl8723e_dm_bt_set_sw_rf_rx_lpf_corner` (:178, `RF90_PATH_A` `0x1e`) | [`Owner::set_sw_rf_rx_lpf_corner`] |
//! | `rtl8723e_dm_bt_query_bt_information` (:1506) | [`Owner::query_bt_information`] (H2C `0x38`) |
//! | `rtl8723e_dm_bt_bt_hw_counters_monitor` (:1521) | [`Owner::counters_monitor`] (`0x770`/`0x774`) |
//! | `rtl8723e_dm_bt_bt_enable_disable_check` (:1560) | [`Owner::enable_disable_check`] |
//! | `rtl8723e_dm_bt_is_2_ant_common_action` (:273) | [`Owner::common_action`] |
//! | `rtl8723e_dm_bt_2_ant_hid_sco_esco` (:968) | [`Owner::hid_sco_esco`] |
//! | `rtl8723e_dm_bt_2_ant_ftp_a2dp` (:1144) | [`Owner::ftp_a2dp`] |
//! | `rtl8723e_dm_bt_inq_page_monitor` (:1358) | [`Owner::inq_page_monitor`] (10 s window) |
//! | `_rtl8723e_dm_bt_coexist_2_ant` (:1404) | [`Owner::coexist_2_ant`] |
//! | `_rtl8723e_dm_bt_coexist_1_ant` (:1468) | [`Owner::coexist_1_ant`] (Linux stub) |
//! | `rtl8723e_dm_bt_set_bt_dm` (:632) | [`Owner::set_bt_dm`] (dedup, hold, all-off, apply order, 30 ms delay) |
//! | `rtl8723e_dm_bt_{hw,fw,sw}_coex_all_off_8723a` (:1473-1510) | [`Owner::all_off_hw`] / [`Owner::all_off_fw`] / [`Owner::all_off_sw`] |
//! | `rtl8723e_btdm_coex_all_off` (`hal_bt_coexist.c:490`) | [`Owner::all_off_combined`] (FW, then SW, then HW) |
//! | `rtl_8723e_bt_wifi_media_status_notify` (:45) | [`Owner::media_status`] (H2C `0x19`) |
//! | `rtl8723e_dm_bt_turn_off_bt_coexist_before_enter_lps` (:14) | [`Owner::turn_off_before_lps`] |
//!
//! ## Deliberately NOT ported here
//!
//! - The watchdog's outer gate (`rfpwr_state == ERFON`, firmware awake,
//!   no RF change in progress, `dm.c:787`): the caller enforces it —
//!   the owner carries no firmware power state — and the counter-enable
//!   writes the outer watchdog makes (`0x76e = 0x0c` after each run) are
//!   part of [`Owner::run_mechanism`].
//! - The two `get_hw_reg` reads at the top of `set_bt_dm`
//!   (`HW_VAR_FW_PSMODE_STATUS`, `HW_VAR_FWLPS_RF_ON`): Linux reads them
//!   and never uses the values in that function, so NARF omits them.
//! - The per-packet BT gate: Linux `reject_ap_aggregated_packet` is an
//!   empty stub; [`Owner::reject_ap_aggregated_packet`] is the same stub.
//!
//! ## Deviations from Linux, each deliberate
//!
//! - `bt_active_zero_cnt` saturates instead of wrapping at 255: only the
//!   `>= 2` threshold is observable, so saturation is behaviorally
//!   identical and cannot panic.
//! - The counter-level `cstate_h` clear mask omits `LEVEL_3` exactly as
//!   Linux does (`hal_btc.c:940` clears bits 0–2 only), so a level-3 bit
//!   sticks until a later level write sets another bit. Pinned by a
//!   test; do not "fix" it without a Linux-side reference.
//! - `run_mechanism` returns [`RunOutcome`] (whether it ran, and the
//!   dispatched profile) instead of Linux's `void`: the watchdog caller
//!   and the tests need to know what ran.

use super::coex::{state, Error, Owner, WifiTraffic};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::rtl8723be::phy::{get_rf, rf_serial_write, Path as RfPath, RFREG_OFFSET_MASK};

/// `reg.h::RF_RCK1` — the RX LPF corner register.
pub const RF_RCK1: u32 = 0x1e;
/// `reg.h::RF_RCK2`.
pub const RF_RCK2: u32 = 0x1f;
/// `hal_btc.c::rtl8723e_dm_bt_set_sw_rf_rx_lpf_corner` shrink value
/// (`0x1e[7:4] = 1111 ==> [11:4]`).
pub const RF_LPF_SHRINK: u32 = 0xf0ff7;

/// High-priority BT TX/RX counters (`hal_bt_coexist.h:16`).
pub const REG_HIGH_PRIORITY_TXRX: u16 = 0x0770;
/// Low-priority BT TX/RX counters (`hal_bt_coexist.h:17`).
pub const REG_LOW_PRIORITY_TXRX: u16 = 0x0774;
/// Counter-statistics enable (`dm.c` init / outer watchdog).
pub const REG_COUNTER_76E: u16 = 0x076e;
/// Counter-statistics enable, second byte (`dm.c` init).
pub const REG_COUNTER_778: u16 = 0x0778;
/// PTA mode register (`hal_btc.c` `set_hw_pta_mode`).
pub const REG_PTA_MODE: u16 = 0x0040;
/// PTA on value: GPIO 0/1/2/3/8 pins for BT.
pub const PTA_ON: u8 = 0x20;
/// Coexistence table registers (`set_coex_table`).
pub const REG_COEX_TABLE_6C0: u16 = 0x06c0;
pub const REG_COEX_TABLE_6C8: u16 = 0x06c8;
pub const REG_COEX_TABLE_6CC: u16 = 0x06cc;
/// TX-rate-adapt penalty register (`0x4fd`).
pub const REG_RATE_ADAPT_PENALTY: u16 = 0x04fd;
/// SW DAC-swing BB register (`set_sw_full_time_dac_swing`).
pub const REG_SW_DAC_SWING: u16 = 0x0880;
/// SW DAC-swing BB mask (`0xff000000`).
pub const SW_DAC_SWING_MASK: u32 = 0xff000000;
/// SW DAC-swing off value.
pub const SW_DAC_SWING_OFF_LVL: u32 = 0xc0;
/// FW DAC-swing register written on the RSSI-1-high path (`0x883`).
pub const REG_FW_DAC_SWING: u16 = 0x0883;
/// FW DAC-swing RSSI-1-high value.
pub const FW_DAC_SWING_RSSI1_HIGH: u8 = 0x40;

/// BT TX/RX counter thresholds (`hal_btc.h:14-16`).
pub const BT_TXRX_CNT_THRES_1: u32 = 1200;
pub const BT_TXRX_CNT_THRES_2: u32 = 1400;
pub const BT_TXRX_CNT_THRES_3: u32 = 3000;
/// BT TX/RX counter levels (`hal_btc.h:18-24`).
pub const BT_TXRX_CNT_LEVEL_0: u8 = 0;
pub const BT_TXRX_CNT_LEVEL_1: u8 = 1;
pub const BT_TXRX_CNT_LEVEL_2: u8 = 2;
pub const BT_TXRX_CNT_LEVEL_3: u8 = 3;
/// `cstate_h` counter-level bits (`hal_bt_coexist.h:160-163`).
pub const CNT_LEVEL_0: u32 = 1 << 0;
pub const CNT_LEVEL_1: u32 = 1 << 1;
pub const CNT_LEVEL_2: u32 = 1 << 2;
pub const CNT_LEVEL_3: u32 = 1 << 3;

/// Inquiry/page window (`inq_page_monitor`: 10 s).
pub const INQ_PAGE_TIMEOUT_MS: u64 = 10_000;
/// Consecutive all-zero counter reads before BT counts as disabled.
pub const BT_DISABLE_ZERO_LIMIT: u8 = 2;
/// `set_bt_dm` settle delay (`mdelay(30)`).
pub const SET_BT_DM_DELAY_US: u64 = 30_000;

/// H2C element-ids used by the mechanism setters.
pub const H2C_QUERY_BT_INFO: u8 = 0x38;
pub const H2C_MEDIA_STATUS: u8 = 0x19;
pub const H2C_FW_3A: u8 = 0x3a;
pub const H2C_DEC_BT_PWR: u8 = 0x21;
pub const H2C_TWO_ANT_HID: u8 = 0x15;
pub const H2C_TDMA_UPDATE: u8 = 0x26;
pub const H2C_TDMA_CTRL: u8 = 0x14;
pub const H2C_IGNORE_WLAN_ACT: u8 = 0x25;
pub const H2C_TRA_TDMA: u8 = 0x33;
pub const H2C_DAC_SWING_LEVEL: u8 = 0x29;
pub const H2C_BT_HID_INFO: u8 = 0x24;
pub const H2C_BT_RETRY_INDEX: u8 = 0x23;
pub const H2C_WLAN_ACT_HI: u8 = 0x22;
pub const H2C_WLAN_ACT_LO: u8 = 0x11;

/// TDMA antenna selection (`hal_btc.h:35-36`).
pub const TDMA_2ANT: u8 = 0;
pub const TDMA_1ANT: u8 = 1;
/// TDMA NAV selection (`hal_btc.h:37-38`).
pub const TDMA_NAV_OFF: u8 = 0;
pub const TDMA_NAV_ON: u8 = 1;
/// TDMA DAC-swing selection (`hal_btc.h:39-40`).
pub const TDMA_DAC_SWING_OFF: u8 = 0;
pub const TDMA_DAC_SWING_ON: u8 = 1;

/// `BTINFO` profile bits (`hal_bt_coexist.h:104-111`).
pub const BTINFO_FTP: u8 = 1 << 7;
pub const BTINFO_A2DP: u8 = 1 << 6;
pub const BTINFO_HID: u8 = 1 << 5;
pub const BTINFO_SCO_BUSY: u8 = 1 << 4;
pub const BTINFO_ACL_BUSY: u8 = 1 << 3;
pub const BTINFO_SCO_ESCO: u8 = 1 << 1;

/// Coexistence mechanism / profile action (`hal_bt_coexist.h:137-148`,
/// `BT_COEX_MECH_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mech {
    /// No profile action.
    None = 0,
    /// SCO profile.
    Sco = 1,
    /// HID profile.
    Hid = 2,
    /// A2DP profile.
    A2dp = 3,
    /// PAN profile.
    Pan = 4,
    /// HID + A2DP.
    HidA2dp = 5,
    /// HID + PAN.
    HidPan = 6,
    /// PAN + A2DP.
    PanA2dp = 7,
    /// HID / SCO / eSCO.
    HidScoEsco = 8,
    /// FTP / A2DP.
    FtpA2dp = 9,
    /// Common action (idle / Wi-Fi-only / BT-only-no-link).
    Common = 10,
}

/// `struct btdm_8723` (`wifi.h:1531`): the mechanism's desired hardware
/// state. `Default` is `btdm_structure_reload` (`hal_btc.c:221`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Btdm {
    /// Whole mechanism off.
    pub all_off: bool,
    /// AGC table enabled.
    pub agc_table_en: bool,
    /// ADC (BB) back-off on.
    pub adc_back_off_on: bool,
    /// 2-antenna HID mode enabled.
    pub b2_ant_hid_en: bool,
    /// Low-penalty TX rate adaptation.
    pub low_penalty_rate_adaptive: bool,
    /// RF RX LPF corner shrunk (`RF90_PATH_A` `0x1e`).
    pub rf_rx_lpf_shrink: bool,
    /// Reject aggregated packets (Linux stub — always a no-op).
    pub reject_aggre_pkt: bool,
    /// Traditional TDMA on (B-cut only).
    pub tra_tdma_on: bool,
    /// Traditional TDMA NAV (`TDMA_NAV_*`).
    pub tra_tdma_nav: u8,
    /// Traditional TDMA antenna (`TDMA_*ANT`).
    pub tra_tdma_ant: u8,
    /// TDMA on.
    pub tdma_on: bool,
    /// TDMA antenna (`TDMA_*ANT`).
    pub tdma_ant: u8,
    /// TDMA NAV (`TDMA_NAV_*`).
    pub tdma_nav: u8,
    /// TDMA DAC swing (`TDMA_DAC_SWING_*`).
    pub tdma_dac_swing: u8,
    /// FW DAC-swing level.
    pub fw_dac_swing_lvl: u8,
    /// PS-TDMA on.
    pub ps_tdma_on: bool,
    /// PS-TDMA byte row (sent as the `0x3a` payload).
    pub ps_tdma_byte: [u8; 5],
    /// HW PTA mode on.
    pub pta_on: bool,
    /// Coexistence table `0x6c0`.
    pub val_0x6c0: u32,
    /// Coexistence table `0x6c8`.
    pub val_0x6c8: u32,
    /// Coexistence table `0x6cc` (written as a byte).
    pub val_0x6cc: u32,
    /// SW DAC swing on.
    pub sw_dac_swing_on: bool,
    /// SW DAC-swing level.
    pub sw_dac_swing_lvl: u32,
    /// WLAN_ACT high duration (ms).
    pub wlan_act_hi: u32,
    /// WLAN_ACT low duration (3 × 625 µs units).
    pub wlan_act_lo: u32,
    /// BT retry index.
    pub bt_retry_index: u32,
    /// Decrease BT power.
    pub dec_bt_pwr: bool,
    /// Ignore WLAN_ACT.
    pub ignore_wlan_act: bool,
}

impl Default for Btdm {
    /// `rtl8723e_dm_bt_btdm_structure_reload` (`hal_btc.c:221`).
    fn default() -> Self {
        Self {
            all_off: false,
            agc_table_en: false,
            adc_back_off_on: false,
            b2_ant_hid_en: false,
            low_penalty_rate_adaptive: false,
            rf_rx_lpf_shrink: false,
            reject_aggre_pkt: false,
            tra_tdma_on: false,
            tra_tdma_nav: TDMA_NAV_OFF,
            tra_tdma_ant: TDMA_2ANT,
            tdma_on: false,
            tdma_ant: TDMA_2ANT,
            tdma_nav: TDMA_NAV_OFF,
            tdma_dac_swing: TDMA_DAC_SWING_OFF,
            fw_dac_swing_lvl: 0x20,
            ps_tdma_on: false,
            ps_tdma_byte: [0x0, 0x0, 0x0, 0x8, 0x0],
            pta_on: true,
            val_0x6c0: 0x5a5aaaaa,
            val_0x6c8: 0xcc,
            val_0x6cc: 0x3,
            sw_dac_swing_on: false,
            sw_dac_swing_lvl: 0xc0,
            wlan_act_hi: 0x20,
            wlan_act_lo: 0x10,
            bt_retry_index: 2,
            dec_bt_pwr: false,
            ignore_wlan_act: false,
        }
    }
}

impl Btdm {
    /// `rtl8723e_dm_bt_btdm_structure_reload_all_off` (`hal_btc.c:264`).
    pub fn all_off() -> Self {
        Self {
            all_off: true,
            pta_on: false,
            wlan_act_hi: 0x10,
            ..Default::default()
        }
    }
}

/// Runtime inputs to one mechanism run. Linux reads these from
/// `rtlpriv` (link info, PHY state, jiffies, chip version); NARF passes
/// them explicitly so the mechanism stays a pure function of its inputs
/// plus the owner's stored state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MechInputs {
    /// Wi-Fi traffic / mode inputs (`check_wifi_state`).
    pub wifi: WifiTraffic,
    /// `mgnt_link_status_query() == RT_MEDIA_CONNECT`.
    pub linked: bool,
    /// Undecorated smoothed RX power (`rtl8723e_dm_bt_get_rx_ss`:
    /// linked average RSSI, else entry-minimum smoothed power). Both
    /// RSSI variants read this same value in Linux.
    pub pwdb: i32,
    /// Monotonic clock (ms) for the inquiry/page window.
    pub now_ms: u64,
    /// `IS_VENDOR_8723_A_CUT(version)`: traditional TDMA is B-cut only.
    pub a_cut: bool,
}

/// Outcome of one [`Owner::run_mechanism`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunOutcome {
    /// False when the board has no BT strap (Linux's early return).
    pub ran: bool,
    /// Dispatched profile action; [`Mech::None`] for the 1-ant stub and
    /// for a gated-off run.
    pub action: Mech,
}

impl Owner {
    /// Watchdog init (`rtl8723e_dm_init_bt_coexist`, `dm.c`): zeroes the
    /// coexistence state, enables the counter statistics (`0x76e =
    /// 0x04`, `0x778 = 0x03`) and PTA (`0x40 = 0x20`). It first reads the
    /// RF origins exactly as Linux (`rtl_get_rfreg`: `RF_RCK1` mask
    /// `0xfffff` into [`Owner::rf_origin_1e`], `RF_RCK2` mask `0xf0`
    /// into [`Owner::rf_origin_1f`]). Idempotent via `mech_init_set`. Note the state zeroing mirrors Linux's
    /// first-watchdog behavior even though `bind` starts from
    /// `BT_IDLE`: the first mechanism run restarts from zero.
    pub async fn mech_init<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        if self.mech_init_set {
            return Ok(());
        }
        self.rf_origin_1e = Some(get_rf(io, RfPath::A, RF_RCK1, RFREG_OFFSET_MASK).await?);
        self.rf_origin_1f = Some(get_rf(io, RfPath::A, RF_RCK2, 0xf0).await?);
        self.cstate = 0;
        self.prev_cstate = 0;
        self.cstate_h = 0;
        self.prev_cstate_h = 0;
        self.lps_counter = 0;
        io.write8(REG_COUNTER_76E, 0x04)?;
        io.write8(REG_COUNTER_778, 0x03)?;
        io.write8(REG_PTA_MODE, PTA_ON)?;
        self.mech_init_set = true;
        Ok(())
    }

    /// Watchdog entry (`rtl8723e_dm_bt_coexist`, `dm.c:818`, plus
    /// `rtl8723e_dm_bt_coexist_8723`, `hal_btc.c:1613`): query, counters,
    /// enable-check, then the antenna-count dispatch, then the
    /// previous-state snapshot when the state changed, then the outer
    /// watchdog's counter write (`0x76e = 0x0c`). Returns
    /// `ran == false` without touching hardware when the board has no
    /// BT strap. The caller enforces the outer watchdog's gate
    /// (`rfpwr_state == ERFON`, firmware awake, no RF change).
    pub async fn run_mechanism<I: Io>(
        &mut self,
        io: &I,
        inputs: MechInputs,
    ) -> Result<RunOutcome, Error> {
        if !self.coexistence {
            return Ok(RunOutcome {
                ran: false,
                action: Mech::None,
            });
        }
        if !self.mech_init_set {
            self.mech_init(io).await?;
        }
        self.query_bt_information(io).await?;
        self.counters_monitor(io)?;
        self.enable_disable_check();
        let action = match self.ant_num {
            super::adapter::AntNum::X2 => self.coexist_2_ant(io, inputs).await?,
            super::adapter::AntNum::X1 => {
                self.coexist_1_ant();
                Mech::None
            }
        };
        if self.is_coexist_state_changed() {
            self.prev_cstate = self.cstate;
            self.prev_cstate_h = self.cstate_h;
        }
        io.write8(REG_COUNTER_76E, 0x0c)?;
        Ok(RunOutcome { ran: true, action })
    }

    /// `rtl8723e_dm_bt_query_bt_information` (`hal_btc.c:1506`): H2C
    /// `0x38` `[0x01]`; marks the BT-info request sent (cleared by the
    /// next `ingest`, exactly as Linux's `parse_bt_info` clears it).
    pub async fn query_bt_information<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.req_sent = true;
        self.h2c_fill(io, H2C_QUERY_BT_INFO, &[0x01]).await
    }

    /// `rtl8723e_dm_bt_bt_hw_counters_monitor` (`hal_btc.c:1521`):
    /// `0x770`/`0x774` split into TX (low half) / RX (high half); when
    /// `lps_counter > 1` each counter is reduced modulo it (Linux's
    /// LPS-averaging step; no in-tree producer bumps `lps_counter` yet,
    /// so the branch is dormant until an LPS caller lands). Resets
    /// `lps_counter` to 0. The commented-out `0x76e = 0x0c` write in
    /// Linux stays commented out here: the outer watchdog does it.
    pub fn counters_monitor<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        let hp = io.read32(REG_HIGH_PRIORITY_TXRX)?;
        let lp = io.read32(REG_LOW_PRIORITY_TXRX)?;
        let mut hp_tx = hp & 0xffff;
        let mut hp_rx = hp >> 16;
        let mut lp_tx = lp & 0xffff;
        let mut lp_rx = lp >> 16;
        if self.lps_counter > 1 {
            hp_tx %= self.lps_counter;
            hp_rx %= self.lps_counter;
            lp_tx %= self.lps_counter;
            lp_rx %= self.lps_counter;
        }
        self.hp_tx = hp_tx;
        self.hp_rx = hp_rx;
        self.lp_tx = lp_tx;
        self.lp_rx = lp_rx;
        self.lps_counter = 0;
        Ok(())
    }

    /// `rtl8723e_dm_bt_bt_enable_disable_check` (`hal_btc.c:1560`):
    /// all four counters zero, all `0xeaea`, or all `0xffff` mean BT is
    /// not alive; two consecutive dead reads mark it disabled.
    pub fn enable_disable_check(&mut self) {
        let all_zero = self.hp_tx == 0 && self.hp_rx == 0 && self.lp_tx == 0 && self.lp_rx == 0;
        let all_eaea = self.hp_tx == 0xeaea
            && self.hp_rx == 0xeaea
            && self.lp_tx == 0xeaea
            && self.lp_rx == 0xeaea;
        let all_ffff = self.hp_tx == 0xffff
            && self.hp_rx == 0xffff
            && self.lp_tx == 0xffff
            && self.lp_rx == 0xffff;
        if all_zero || all_eaea || all_ffff {
            self.bt_active_zero_cnt = self.bt_active_zero_cnt.saturating_add(1);
            if self.bt_active_zero_cnt >= BT_DISABLE_ZERO_LIMIT {
                self.cur_bt_disabled = true;
            }
        } else {
            self.bt_active_zero_cnt = 0;
            self.cur_bt_disabled = false;
        }
        if self.pre_bt_disabled != self.cur_bt_disabled {
            self.pre_bt_disabled = self.cur_bt_disabled;
        }
    }

    /// BT TX/RX counter level (`hal_btc.c:925`): high + low totals
    /// against 1200 / 1400 / 3000, writing the level bit into `cstate_h`.
    /// The clear mask omits `LEVEL_3` exactly as Linux does, so a
    /// level-3 bit sticks until another level bit is written alongside
    /// it — pinned by a test, do not "fix" without a Linux reference.
    pub fn counter_level(&mut self) -> u8 {
        let total = self.hp_tx + self.hp_rx + self.lp_tx + self.lp_rx;
        self.cstate_h &= !(CNT_LEVEL_0 | CNT_LEVEL_1 | CNT_LEVEL_2);
        if total >= BT_TXRX_CNT_THRES_3 {
            self.cstate_h |= CNT_LEVEL_3;
            BT_TXRX_CNT_LEVEL_3
        } else if total >= BT_TXRX_CNT_THRES_2 {
            self.cstate_h |= CNT_LEVEL_2;
            BT_TXRX_CNT_LEVEL_2
        } else if total >= BT_TXRX_CNT_THRES_1 {
            self.cstate_h |= CNT_LEVEL_1;
            BT_TXRX_CNT_LEVEL_1
        } else {
            self.cstate_h |= CNT_LEVEL_0;
            BT_TXRX_CNT_LEVEL_0
        }
    }

    /// `rtl8723e_dm_bt_is_wifi_busy` (`hal_btc.c:79`).
    pub fn is_wifi_busy(&self, wifi: WifiTraffic) -> bool {
        wifi.busy || wifi.rx_busy || wifi.tx_busy
    }

    /// `rtl8723e_dm_bt_need_to_dec_bt_pwr` (`hal_btc.c:110`): a live
    /// Wi-Fi link sets the `DEC_BT_POWER` cstate bit and reports that
    /// BT power must drop; otherwise the bit clears.
    pub fn need_to_dec_bt_pwr(&mut self, linked: bool) -> bool {
        if linked {
            self.cstate |= state::DEC_BT_POWER;
            true
        } else {
            self.cstate &= !state::DEC_BT_POWER;
            false
        }
    }

    /// `rtl8723e_dm_bt_reset_action_profile_state` (`hal_btc.c:1390`):
    /// clears the profile and BT-info action bits before dispatch.
    pub fn reset_action_profile_state(&mut self) {
        self.cstate &=
            !(state::PROFILE_HID | state::PROFILE_A2DP | state::PROFILE_PAN | state::PROFILE_SCO);
        self.cstate &=
            !(state::BTINFO_COMMON | state::BTINFO_B_HID_SCOESCO | state::BTINFO_B_FTP_A2DP);
    }

    /// `rtl8723e_dm_bt_inq_page_monitor` (`hal_btc.c:1358`): an
    /// inquiry/page flag starts the window (setting the `BT_INQ_PAGE`
    /// bit); 10 s later the window closes and the bit clears. Times are
    /// the caller's monotonic milliseconds.
    pub fn inq_page_monitor(&mut self, now_ms: u64) {
        if self.inquiry_page && self.inq_page_start_ms.is_none() {
            self.cstate |= state::BT_INQ_PAGE;
            self.inq_page_start_ms = Some(now_ms);
        }
        if let Some(start) = self.inq_page_start_ms {
            if now_ms.wrapping_sub(start) >= INQ_PAGE_TIMEOUT_MS {
                self.inq_page_start_ms = None;
                self.cstate &= !state::BT_INQ_PAGE;
            }
        }
    }

    /// `rtl8723e_dm_bt_is_2_ant_common_action` (`hal_btc.c:273`):
    /// idle+idle → all-off; Wi-Fi busy + BT idle → low-penalty,
    /// Wi-Fi-only table; BT busy without a Wi-Fi link → shrink, BT-only
    /// table. Returns false only for BT busy *with* a link, where the
    /// profile actions take over. Applies via `set_bt_dm` when common
    /// and the state changed.
    pub async fn common_action<I: Io>(
        &mut self,
        io: &I,
        inputs: MechInputs,
    ) -> Result<bool, Error> {
        let mut btdm = Btdm::default();
        let wifi_busy = self.is_wifi_busy(inputs.wifi);
        let mut common = false;
        if !wifi_busy && !self.bt_busy {
            btdm = Btdm::all_off();
            common = true;
        } else if wifi_busy && !self.bt_busy {
            btdm.low_penalty_rate_adaptive = true;
            btdm.rf_rx_lpf_shrink = false;
            btdm.reject_aggre_pkt = false;
            btdm.agc_table_en = false;
            btdm.adc_back_off_on = false;
            btdm.sw_dac_swing_on = false;
            btdm.pta_on = true;
            btdm.val_0x6c0 = 0x5a5aaaaa;
            btdm.val_0x6c8 = 0xcccc;
            btdm.val_0x6cc = 0x3;
            btdm.tdma_on = false;
            btdm.tdma_dac_swing = TDMA_DAC_SWING_OFF;
            btdm.b2_ant_hid_en = false;
            common = true;
        } else if self.bt_busy {
            if inputs.linked {
                common = false;
            } else {
                btdm.rf_rx_lpf_shrink = true;
                btdm.low_penalty_rate_adaptive = false;
                btdm.reject_aggre_pkt = false;
                btdm.agc_table_en = false;
                btdm.adc_back_off_on = false;
                btdm.sw_dac_swing_on = false;
                btdm.pta_on = true;
                btdm.val_0x6c0 = 0x55555555;
                btdm.val_0x6c8 = 0x0000ffff;
                btdm.val_0x6cc = 0x3;
                btdm.tdma_on = false;
                btdm.tdma_dac_swing = TDMA_DAC_SWING_OFF;
                btdm.b2_ant_hid_en = false;
                common = true;
            }
        }
        if self.need_to_dec_bt_pwr(inputs.linked) {
            btdm.dec_bt_pwr = true;
        }
        if common {
            self.cstate |= state::BTINFO_COMMON;
        }
        if common && self.is_coexist_state_changed() {
            self.set_bt_dm(io, btdm, inputs.a_cut).await?;
        }
        Ok(common)
    }

    /// PS-TDMA byte row for one counter level (`hal_btc.c` action
    /// tables): level 2 → `5/5`, level 1 → `a/a`, anything else
    /// (levels 0 *and* 3 — Linux's `else` arm) → `f/f`. `byte3` is the
    /// caller's action bit (`0x02` HID/SCO, `0x81`/`0x00` FTP/A2DP,
    /// `0x83` inquiry override).
    fn ps_tdma_row(cnt_lvl: u8, byte3: u8) -> [u8; 5] {
        let (b1, b2) = match cnt_lvl {
            BT_TXRX_CNT_LEVEL_2 => (0x5, 0x5),
            BT_TXRX_CNT_LEVEL_1 => (0xa, 0xa),
            _ => (0xf, 0xf),
        };
        [0xa3, b1, b2, byte3, 0x80]
    }

    /// `rtl8723e_dm_bt_2_ant_hid_sco_esco` (`hal_btc.c:968`): shrink +
    /// low penalty, `0x55555555`/`0xffff`/`0x3` table. HT40 keys the
    /// PS-TDMA row off the counter level alone; HT20/legacy keys the SW
    /// mechanism off RSSI (47) and the PS row's `0x83` bit off RSSI-1
    /// (27, writing `0x883 = 0x40` when high). An open inquiry/page
    /// window or counter level 3 forces `[a3,5,5,2,80]`.
    pub async fn hid_sco_esco<I: Io>(&mut self, io: &I, inputs: MechInputs) -> Result<(), Error> {
        let mut btdm = Btdm {
            rf_rx_lpf_shrink: true,
            low_penalty_rate_adaptive: true,
            reject_aggre_pkt: false,
            ..Default::default()
        };
        let cnt_lvl = self.counter_level();
        btdm.val_0x6c0 = 0x55555555;
        btdm.val_0x6c8 = 0xffff;
        btdm.val_0x6cc = 0x3;
        if inputs.wifi.bw40 {
            btdm.agc_table_en = false;
            btdm.adc_back_off_on = false;
            btdm.sw_dac_swing_on = false;
            btdm.ps_tdma_on = true;
            btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, 0x02);
        } else {
            let rssi = self.rssi_state(inputs.pwdb, 2, 47, 0);
            let rssi1 = self.rssi_state1(inputs.pwdb, 2, 27, 0);
            if matches!(
                rssi,
                super::coex::RssiState::High | super::coex::RssiState::StayHigh
            ) {
                btdm.agc_table_en = true;
                btdm.adc_back_off_on = true;
                btdm.sw_dac_swing_on = false;
            } else {
                btdm.agc_table_en = false;
                btdm.adc_back_off_on = false;
                btdm.sw_dac_swing_on = false;
            }
            btdm.ps_tdma_on = true;
            if matches!(
                rssi1,
                super::coex::RssiState::High | super::coex::RssiState::StayHigh
            ) {
                io.write8(REG_FW_DAC_SWING, FW_DAC_SWING_RSSI1_HIGH)?;
                btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, 0x83);
            } else {
                btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, 0x02);
            }
        }
        if self.need_to_dec_bt_pwr(inputs.linked) {
            btdm.dec_bt_pwr = true;
        }
        if self.inq_page_start_ms.is_some() || cnt_lvl == BT_TXRX_CNT_LEVEL_3 {
            btdm.ps_tdma_on = true;
            btdm.ps_tdma_byte = [0xa3, 0x5, 0x5, 0x02, 0x80];
        }
        if self.is_coexist_state_changed() {
            self.set_bt_dm(io, btdm, inputs.a_cut).await?;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_2_ant_ftp_a2dp` (`hal_btc.c:1144`): shrink +
    /// low penalty, `0x55555555`/`0xffff`/`0x3` table. HT40 keys RSSI
    /// (37) into the PS row's `0x81`/`0x00` bit with back-off always
    /// on; HT20/legacy keys the SW mechanism off RSSI (47) and the PS
    /// row's `0x81` bit off RSSI-1 (27, writing `0x883 = 0x40` when
    /// high). The inquiry/level-3 override forces `[a3,5,5,83,80]`.
    pub async fn ftp_a2dp<I: Io>(&mut self, io: &I, inputs: MechInputs) -> Result<(), Error> {
        let mut btdm = Btdm {
            rf_rx_lpf_shrink: true,
            low_penalty_rate_adaptive: true,
            reject_aggre_pkt: false,
            ..Default::default()
        };
        let cnt_lvl = self.counter_level();
        btdm.val_0x6c0 = 0x55555555;
        btdm.val_0x6c8 = 0xffff;
        btdm.val_0x6cc = 0x3;
        if inputs.wifi.bw40 {
            let rssi = self.rssi_state(inputs.pwdb, 2, 37, 0);
            btdm.agc_table_en = false;
            btdm.adc_back_off_on = true;
            btdm.sw_dac_swing_on = false;
            btdm.ps_tdma_on = true;
            let byte3 = if matches!(
                rssi,
                super::coex::RssiState::High | super::coex::RssiState::StayHigh
            ) {
                0x81
            } else {
                0x00
            };
            btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, byte3);
        } else {
            let rssi = self.rssi_state(inputs.pwdb, 2, 47, 0);
            let rssi1 = self.rssi_state1(inputs.pwdb, 2, 27, 0);
            if matches!(
                rssi,
                super::coex::RssiState::High | super::coex::RssiState::StayHigh
            ) {
                btdm.agc_table_en = true;
                btdm.adc_back_off_on = true;
                btdm.sw_dac_swing_on = false;
            } else {
                btdm.agc_table_en = false;
                btdm.adc_back_off_on = false;
                btdm.sw_dac_swing_on = false;
            }
            btdm.ps_tdma_on = true;
            if matches!(
                rssi1,
                super::coex::RssiState::High | super::coex::RssiState::StayHigh
            ) {
                io.write8(REG_FW_DAC_SWING, FW_DAC_SWING_RSSI1_HIGH)?;
                btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, 0x81);
            } else {
                btdm.ps_tdma_byte = Self::ps_tdma_row(cnt_lvl, 0x00);
            }
        }
        if self.need_to_dec_bt_pwr(inputs.linked) {
            btdm.dec_bt_pwr = true;
        }
        if self.inq_page_start_ms.is_some() || cnt_lvl == BT_TXRX_CNT_LEVEL_3 {
            btdm.ps_tdma_on = true;
            btdm.ps_tdma_byte = [0xa3, 0x5, 0x5, 0x83, 0x80];
        }
        if self.is_coexist_state_changed() {
            self.set_bt_dm(io, btdm, inputs.a_cut).await?;
        }
        Ok(())
    }

    /// `_rtl8723e_dm_bt_coexist_2_ant` (`hal_btc.c:1404`): wifi-state
    /// refresh, inquiry/page monitor, profile-bit reset, then the
    /// common action or the profile dispatch on the last BT-info
    /// original byte. The undefined case sets the `HID_SCOESCO` bit
    /// *and* runs the HID/SCO action, exactly as Linux does.
    pub async fn coexist_2_ant<I: Io>(
        &mut self,
        io: &I,
        inputs: MechInputs,
    ) -> Result<Mech, Error> {
        self.check_wifi_state(&inputs.wifi);
        // Linux only logs when a BT-info request is still outstanding
        // (`c2h_bt_info_req_sent`); the dispatch proceeds regardless.
        let original = self.bt_info_original;
        self.inq_page_monitor(inputs.now_ms);
        self.reset_action_profile_state();
        if self.common_action(io, inputs).await? {
            self.profile_case = Mech::Common;
            self.profile_action = Mech::Common;
            return Ok(Mech::Common);
        }
        if original & (BTINFO_HID | BTINFO_SCO_BUSY | BTINFO_SCO_ESCO) != 0 {
            self.cstate |= state::BTINFO_B_HID_SCOESCO;
            self.profile_case = Mech::HidScoEsco;
            self.profile_action = Mech::HidScoEsco;
            self.hid_sco_esco(io, inputs).await?;
            Ok(Mech::HidScoEsco)
        } else if original & (BTINFO_FTP | BTINFO_A2DP) != 0 {
            self.cstate |= state::BTINFO_B_FTP_A2DP;
            self.profile_case = Mech::FtpA2dp;
            self.profile_action = Mech::FtpA2dp;
            self.ftp_a2dp(io, inputs).await?;
            Ok(Mech::FtpA2dp)
        } else {
            self.cstate |= state::BTINFO_B_HID_SCOESCO;
            self.profile_case = Mech::None;
            self.profile_action = Mech::None;
            self.hid_sco_esco(io, inputs).await?;
            Ok(Mech::None)
        }
    }

    /// `_rtl8723e_dm_bt_coexist_1_ant` (`hal_btc.c:1468`): an empty
    /// stub in Linux. Ported as a no-op so the 1-ant dispatch shape
    /// stays visible and no behavior is invented.
    pub fn coexist_1_ant(&mut self) {}

    /// `rtl8723e_dm_bt_set_bt_dm` (`hal_btc.c:632`): deduplicate against
    /// the saved setting (identical → no writes at all), then the hold
    /// gate (ignore WLAN_ACT only), then the all-off gate (combined
    /// sequences only), then the apply order — reject stub, rate-adapt
    /// penalty, RF LPF corner, AGC table, BB
    /// back-off, retry index, DAC-swing level, WLAN_ACT, coex table,
    /// PTA mode, the exclusive 2-ant-HID / TDMA / PS-TDMA / none
    /// branch, the 30 ms settle, SW DAC swing, BT power decrease.
    pub async fn set_bt_dm<I: Io>(&mut self, io: &I, btdm: Btdm, a_cut: bool) -> Result<(), Error> {
        if btdm == self.saved_btdm {
            return Ok(());
        }
        self.saved_btdm = btdm;
        if self.hold_for_bt_operation {
            self.set_fw_ignore_wlan_act(io, true).await?;
            return Ok(());
        }
        if btdm.all_off {
            self.all_off_combined(io, a_cut).await?;
            return Ok(());
        }
        self.reject_ap_aggregated_packet(btdm.reject_aggre_pkt);
        self.set_penalty_tx_rate_adapt(io, btdm.low_penalty_rate_adaptive)?;
        self.set_sw_rf_rx_lpf_corner(io, btdm.rf_rx_lpf_shrink)?;
        if btdm.agc_table_en {
            self.agc_table(io, true)?;
        } else {
            self.agc_table(io, false)?;
        }
        if btdm.adc_back_off_on {
            self.bb_back_off(io, true)?;
        } else {
            self.bb_back_off(io, false)?;
        }
        self.set_fw_bt_retry_index(io, btdm.bt_retry_index).await?;
        self.set_fw_dac_swing_level(io, btdm.fw_dac_swing_lvl)
            .await?;
        self.set_fw_wlan_act(io, btdm.wlan_act_hi, btdm.wlan_act_lo)
            .await?;
        self.set_coex_table(io, btdm.val_0x6c0, btdm.val_0x6c8, btdm.val_0x6cc)?;
        self.set_hw_pta_mode(io, btdm.pta_on)?;
        if btdm.b2_ant_hid_en {
            self.set_fw_tra_tdma_ctrl(
                io,
                btdm.tra_tdma_on,
                btdm.tra_tdma_ant,
                btdm.tra_tdma_nav,
                a_cut,
            )
            .await?;
            self.set_fw_tdma_ctrl(io, false, btdm.tdma_ant, btdm.tdma_nav, btdm.tdma_dac_swing)
                .await?;
            self.set_fw_ignore_wlan_act(io, btdm.ignore_wlan_act)
                .await?;
            self.set_fw_3a(io, 0x0, 0x0, 0x0, 0x8, 0x0).await?;
            self.set_fw_bt_hid_info(io, true).await?;
            self.set_fw_2_ant_hid(io, true, true).await?;
        } else if btdm.tdma_on {
            self.set_fw_bt_hid_info(io, false).await?;
            self.set_fw_2_ant_hid(io, false, false).await?;
            self.set_fw_ignore_wlan_act(io, btdm.ignore_wlan_act)
                .await?;
            self.set_fw_3a(io, 0x0, 0x0, 0x0, 0x8, 0x0).await?;
            self.set_fw_tra_tdma_ctrl(
                io,
                btdm.tra_tdma_on,
                btdm.tra_tdma_ant,
                btdm.tra_tdma_nav,
                a_cut,
            )
            .await?;
            self.set_fw_tdma_ctrl(io, true, btdm.tdma_ant, btdm.tdma_nav, btdm.tdma_dac_swing)
                .await?;
        } else if btdm.ps_tdma_on {
            self.set_fw_bt_hid_info(io, false).await?;
            self.set_fw_2_ant_hid(io, false, false).await?;
            self.set_fw_tra_tdma_ctrl(
                io,
                btdm.tra_tdma_on,
                btdm.tra_tdma_ant,
                btdm.tra_tdma_nav,
                a_cut,
            )
            .await?;
            self.set_fw_tdma_ctrl(io, false, btdm.tdma_ant, btdm.tdma_nav, btdm.tdma_dac_swing)
                .await?;
            self.set_fw_ignore_wlan_act(io, btdm.ignore_wlan_act)
                .await?;
            self.set_fw_3a(
                io,
                btdm.ps_tdma_byte[0],
                btdm.ps_tdma_byte[1],
                btdm.ps_tdma_byte[2],
                btdm.ps_tdma_byte[3],
                btdm.ps_tdma_byte[4],
            )
            .await?;
        } else {
            self.set_fw_bt_hid_info(io, false).await?;
            self.set_fw_2_ant_hid(io, false, false).await?;
            self.set_fw_tra_tdma_ctrl(
                io,
                btdm.tra_tdma_on,
                btdm.tra_tdma_ant,
                btdm.tra_tdma_nav,
                a_cut,
            )
            .await?;
            self.set_fw_tdma_ctrl(io, false, btdm.tdma_ant, btdm.tdma_nav, btdm.tdma_dac_swing)
                .await?;
            self.set_fw_ignore_wlan_act(io, btdm.ignore_wlan_act)
                .await?;
            self.set_fw_3a(io, 0x0, 0x0, 0x0, 0x8, 0x0).await?;
        }
        io.delay_us(SET_BT_DM_DELAY_US).await;
        self.set_sw_full_time_dac_swing(io, btdm.sw_dac_swing_on, btdm.sw_dac_swing_lvl)?;
        self.set_fw_dec_bt_pwr(io, btdm.dec_bt_pwr).await?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_3a` (`hal_btc.c:90`): H2C `0x3a`.
    pub async fn set_fw_3a<I: Io>(
        &mut self,
        io: &I,
        b1: u8,
        b2: u8,
        b3: u8,
        b4: u8,
        b5: u8,
    ) -> Result<(), Error> {
        self.h2c_fill(io, H2C_FW_3A, &[b1, b2, b3, b4, b5]).await
    }

    /// `rtl8723e_dm_bt_set_coex_table` (`hal_btc.c:144`): `0x6c0` /
    /// `0x6c8` dwords, `0x6cc` as a byte.
    pub fn set_coex_table<I: Io>(
        &mut self,
        io: &I,
        val_0x6c0: u32,
        val_0x6c8: u32,
        val_0x6cc: u32,
    ) -> Result<(), Error> {
        io.write32(REG_COEX_TABLE_6C0, val_0x6c0)?;
        io.write32(REG_COEX_TABLE_6C8, val_0x6c8)?;
        io.write8(REG_COEX_TABLE_6CC, val_0x6cc as u8)?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_hw_pta_mode` (`hal_btc.c:163`): `0x40 =
    /// 0x20` on (GPIO pins for BT), `0x00` off. Turning PTA on clears
    /// the HW all-off wrapper flag, as in Linux.
    pub fn set_hw_pta_mode<I: Io>(&mut self, io: &I, on: bool) -> Result<(), Error> {
        if on {
            io.write8(REG_PTA_MODE, PTA_ON)?;
            self.hw_all_off = false;
        } else {
            io.write8(REG_PTA_MODE, 0x00)?;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_sw_rf_rx_lpf_corner` (`hal_btc.c:178`):
    /// shrink writes `RF90_PATH_A` `0x1e = 0xf0ff7`; resume restores
    /// [`Owner::rf_origin_1e`]. Both go through
    /// `rtl8723_phy_rf_serial_write` (full mask). Shrink clears the SW
    /// all-off wrapper flag, as in Linux.
    ///
    /// Deliberate deviation: Linux resumes with whatever
    /// `bt_rfreg_origin_1e` holds, which is zero when an IPS all-off
    /// runs before the first watchdog init. NARF skips the resume write
    /// until [`Owner::mech_init`] captured the origin rather than
    /// clobbering the RF RCK1 value with zero.
    pub fn set_sw_rf_rx_lpf_corner<I: Io>(&mut self, io: &I, shrink: bool) -> Result<(), Error> {
        if shrink {
            rf_serial_write(io, RfPath::A, RF_RCK1, RF_LPF_SHRINK)?;
            self.sw_all_off = false;
        } else if let Some(origin) = self.rf_origin_1e {
            rf_serial_write(io, RfPath::A, RF_RCK1, origin)?;
        }
        Ok(())
    }

    /// `dm_bt_set_sw_penalty_tx_rate_adapt` (`hal_btc.c:199`):
    /// `0x4fd` BIT(0) always set; BIT(2) clear = low penalty, set =
    /// normal. Low penalty clears the SW all-off wrapper flag.
    pub fn set_penalty_tx_rate_adapt<I: Io>(
        &mut self,
        io: &I,
        low_penalty: bool,
    ) -> Result<(), Error> {
        let mut v = io.read8(REG_RATE_ADAPT_PENALTY)?;
        v |= 1 << 0;
        if low_penalty {
            v &= !(1 << 2);
            self.sw_all_off = false;
        } else {
            v |= 1 << 2;
        }
        io.write8(REG_RATE_ADAPT_PENALTY, v)?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_sw_full_time_dac_swing` (`hal_btc.c:355`):
    /// BB `0x880` top byte (`halbtc_set_bbreg` semantics: `(old &
    /// !mask) | (data << mask.trailing_zeros())`). On clears the SW
    /// all-off wrapper flag; off writes `0xc0`.
    pub fn set_sw_full_time_dac_swing<I: Io>(
        &mut self,
        io: &I,
        on: bool,
        lvl: u32,
    ) -> Result<(), Error> {
        let old = io.read32(REG_SW_DAC_SWING)?;
        let data = if on { lvl } else { SW_DAC_SWING_OFF_LVL };
        io.write32(
            REG_SW_DAC_SWING,
            (old & !SW_DAC_SWING_MASK) | (data << SW_DAC_SWING_MASK.trailing_zeros()),
        )?;
        if on {
            self.sw_all_off = false;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_dec_bt_pwr` (`hal_btc.c:375`): H2C
    /// `0x21` `[BIT(1) iff decrease]`. Decreasing clears the FW
    /// all-off wrapper flag.
    pub async fn set_fw_dec_bt_pwr<I: Io>(&mut self, io: &I, dec: bool) -> Result<(), Error> {
        let byte = if dec { 0x02 } else { 0x00 };
        self.h2c_fill(io, H2C_DEC_BT_PWR, &[byte]).await?;
        if dec {
            self.fw_all_off = false;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_2_ant_hid` (`hal_btc.c:395`): H2C `0x15`
    /// `[BIT(0) enable | BIT(1) DAC swing]`. Enabling clears the FW
    /// all-off wrapper flag.
    pub async fn set_fw_2_ant_hid<I: Io>(
        &mut self,
        io: &I,
        enable: bool,
        dac_swing_on: bool,
    ) -> Result<(), Error> {
        let mut byte = 0u8;
        if enable {
            byte |= 1 << 0;
        }
        if dac_swing_on {
            byte |= 1 << 1;
        }
        self.h2c_fill(io, H2C_TWO_ANT_HID, &[byte]).await?;
        if enable {
            self.fw_all_off = false;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_tdma_ctrl` (`hal_btc.c:416`): H2C `0x26`
    /// `[BIT(0) update iff enable]` first, then H2C `0x14` `[BIT(0)
    /// enable | BIT(1) 1-ant | BIT(2) NAV on | BIT(4) DAC swing on]`.
    /// Enabling clears the FW all-off wrapper flag.
    pub async fn set_fw_tdma_ctrl<I: Io>(
        &mut self,
        io: &I,
        enable: bool,
        ant: u8,
        nav: u8,
        dac_swing: u8,
    ) -> Result<(), Error> {
        if enable {
            self.h2c_fill(io, H2C_TDMA_UPDATE, &[0x01]).await?;
            let mut byte = 1 << 0;
            if ant == TDMA_1ANT {
                byte |= 1 << 1;
            }
            if nav == TDMA_NAV_ON {
                byte |= 1 << 2;
            }
            if dac_swing == TDMA_DAC_SWING_ON {
                byte |= 1 << 4;
            }
            self.h2c_fill(io, H2C_TDMA_CTRL, &[byte]).await?;
            self.fw_all_off = false;
        } else {
            self.h2c_fill(io, H2C_TDMA_UPDATE, &[0x00]).await?;
            self.h2c_fill(io, H2C_TDMA_CTRL, &[0x00]).await?;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_ignore_wlan_act` (`hal_btc.c:483`): H2C
    /// `0x25` `[BIT(0) iff enable]`. Enabling clears the FW all-off
    /// wrapper flag.
    pub async fn set_fw_ignore_wlan_act<I: Io>(
        &mut self,
        io: &I,
        enable: bool,
    ) -> Result<(), Error> {
        let byte = if enable { 0x01 } else { 0x00 };
        self.h2c_fill(io, H2C_IGNORE_WLAN_ACT, &[byte]).await?;
        if enable {
            self.fw_all_off = false;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_tra_tdma_ctrl` (`hal_btc.c:506`): H2C
    /// `0x33` `[BIT(0) enable | BIT(1) 1-ant, NAV-on bit in byte 1]`.
    /// B-cut only: on an A-cut board Linux returns without writing
    /// anything, and so does this. Enabling clears the FW all-off
    /// wrapper flag.
    pub async fn set_fw_tra_tdma_ctrl<I: Io>(
        &mut self,
        io: &I,
        enable: bool,
        ant: u8,
        nav: u8,
        a_cut: bool,
    ) -> Result<(), Error> {
        if a_cut {
            return Ok(());
        }
        if enable {
            let mut byte0 = 1 << 0;
            if ant == TDMA_1ANT {
                byte0 |= 1 << 1;
            }
            let byte1 = if nav == TDMA_NAV_ON { 0x01 } else { 0x00 };
            self.h2c_fill(io, H2C_TRA_TDMA, &[byte0, byte1]).await?;
            self.fw_all_off = false;
        } else {
            self.h2c_fill(io, H2C_TRA_TDMA, &[0x00, 0x00]).await?;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_dac_swing_level` (`hal_btc.c:560`): H2C
    /// `0x29` `[level]`.
    pub async fn set_fw_dac_swing_level<I: Io>(&mut self, io: &I, lvl: u8) -> Result<(), Error> {
        self.h2c_fill(io, H2C_DAC_SWING_LEVEL, &[lvl]).await
    }

    /// `rtl8723e_dm_bt_set_fw_bt_hid_info` (`hal_btc.c:575`): H2C
    /// `0x24` `[BIT(0) iff enable]`. Enabling clears the FW all-off
    /// wrapper flag.
    pub async fn set_fw_bt_hid_info<I: Io>(&mut self, io: &I, enable: bool) -> Result<(), Error> {
        let byte = if enable { 0x01 } else { 0x00 };
        self.h2c_fill(io, H2C_BT_HID_INFO, &[byte]).await?;
        if enable {
            self.fw_all_off = false;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_set_fw_bt_retry_index` (`hal_btc.c:594`): H2C
    /// `0x23` `[index]`.
    pub async fn set_fw_bt_retry_index<I: Io>(&mut self, io: &I, index: u32) -> Result<(), Error> {
        self.h2c_fill(io, H2C_BT_RETRY_INDEX, &[index as u8]).await
    }

    /// `rtl8723e_dm_bt_set_fw_wlan_act` (`hal_btc.c:609`): H2C `0x22`
    /// `[hi]` (ms) then H2C `0x11` `[lo]` (3 × 625 µs units).
    pub async fn set_fw_wlan_act<I: Io>(&mut self, io: &I, hi: u32, lo: u32) -> Result<(), Error> {
        self.h2c_fill(io, H2C_WLAN_ACT_HI, &[hi as u8]).await?;
        self.h2c_fill(io, H2C_WLAN_ACT_LO, &[lo as u8]).await?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_reject_ap_aggregated_packet`
    /// (`hal_bt_coexist.c:14`): an empty stub in Linux, and an empty
    /// stub here. No packet is ever rejected on this path.
    pub fn reject_ap_aggregated_packet(&mut self, _reject: bool) {}

    /// `rtl8723e_dm_bt_hw_coex_all_off_8723a` (`hal_btc.c:1473`):
    /// coex table `0x5a5aaaaa`/`0xcc`/`0x3` + PTA on. (Linux's HW
    /// all-off leaves PTA enabled.)
    pub fn all_off_hw<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.set_coex_table(io, 0x5a5aaaaa, 0xcc, 0x3)?;
        self.set_hw_pta_mode(io, true)?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_fw_coex_all_off_8723a` (`hal_btc.c:1479`): the
    /// FW command sequence, in Linux order.
    pub async fn all_off_fw<I: Io>(&mut self, io: &I, a_cut: bool) -> Result<(), Error> {
        self.set_fw_ignore_wlan_act(io, false).await?;
        self.set_fw_3a(io, 0x0, 0x0, 0x0, 0x8, 0x0).await?;
        self.set_fw_2_ant_hid(io, false, false).await?;
        self.set_fw_tra_tdma_ctrl(io, false, TDMA_2ANT, TDMA_NAV_OFF, a_cut)
            .await?;
        self.set_fw_tdma_ctrl(io, false, TDMA_2ANT, TDMA_NAV_OFF, TDMA_DAC_SWING_OFF)
            .await?;
        self.set_fw_dac_swing_level(io, 0).await?;
        self.set_fw_bt_hid_info(io, false).await?;
        self.set_fw_bt_retry_index(io, 2).await?;
        self.set_fw_wlan_act(io, 0x10, 0x10).await?;
        self.set_fw_dec_bt_pwr(io, false).await?;
        Ok(())
    }

    /// `rtl8723e_dm_bt_sw_coex_all_off_8723a` (`hal_btc.c:1495`):
    /// AGC off, BB back-off off, reject stub (no-op), rate-adapt
    /// normal, RF LPF resume, SW DAC swing off.
    pub fn all_off_sw<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.agc_table(io, false)?;
        self.bb_back_off(io, false)?;
        self.reject_ap_aggregated_packet(false);
        self.set_penalty_tx_rate_adapt(io, false)?;
        self.set_sw_rf_rx_lpf_corner(io, false)?;
        self.set_sw_full_time_dac_swing(io, false, SW_DAC_SWING_OFF_LVL)?;
        Ok(())
    }

    /// `rtl8723e_btdm_coex_all_off` (`hal_bt_coexist.c:490`): FW, then
    /// SW, then HW — that order, not the wrapper order.
    pub async fn all_off_combined<I: Io>(&mut self, io: &I, a_cut: bool) -> Result<(), Error> {
        self.all_off_fw(io, a_cut).await?;
        self.all_off_sw(io)?;
        self.all_off_hw(io)?;
        Ok(())
    }

    /// `rtl_8723e_bt_wifi_media_status_notify` (`hal_btc.c:45`): H2C
    /// `0x19` `[connected, channel-if-linked, 0x30 if HT40 else
    /// 0x20]`. No-op on boards without the BT strap, as in Linux.
    pub async fn media_status<I: Io>(
        &mut self,
        io: &I,
        connected: bool,
        linked: bool,
        channel: u8,
        bw40: bool,
    ) -> Result<(), Error> {
        if !self.coexistence {
            return Ok(());
        }
        let byte0 = u8::from(connected);
        let byte1 = if linked { channel } else { 0 };
        let byte2 = if bw40 { 0x30 } else { 0x20 };
        self.h2c_fill(io, H2C_MEDIA_STATUS, &[byte0, byte1, byte2])
            .await
    }

    /// `rtl8723e_dm_bt_turn_off_bt_coexist_before_enter_lps`
    /// (`hal_btc.c:14`): on an inactive-PS transition, zero the
    /// coexistence state and run the combined all-off. No-op when the
    /// board has no BT strap or PS is not inactive.
    pub async fn turn_off_before_lps<I: Io>(
        &mut self,
        io: &I,
        a_cut: bool,
        inactive_ps: bool,
    ) -> Result<(), Error> {
        if !self.coexistence || !inactive_ps {
            return Ok(());
        }
        self.cstate = 0;
        self.prev_cstate = 0;
        self.cstate_h = 0;
        self.prev_cstate_h = 0;
        self.all_off_combined(io, a_cut).await?;
        Ok(())
    }
}
