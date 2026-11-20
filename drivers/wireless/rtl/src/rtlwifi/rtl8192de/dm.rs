// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE dynamic mechanism (`rtl92d_dm_init` / `rtl92d_dm_watchdog`,
//! `rtl8192de/dm.c`).
//!
//! Software-only driver state: no register is written here. Linux
//! `rtl92d_dm_init` (`rtl8192de/dm.c:1215`) sets the DM type to
//! `DM_TYPE_BYDRIVER`, runs the shared `rtl_dm_diginit(hw, 0x20)`
//! (`core.c:1948`) with the 92D receive-gain override
//! (`DM_DIG_FA_UPPER` / `DM_DIG_FA_LOWER`), then the four sub-inits
//! (`rtl92d_dm_init_dynamic_txpower`, `rtl92d_dm_init_edca_turbo`,
//! `rtl92d_dm_init_rate_adaptive_mask`,
//! `rtl92d_dm_initialize_txpower_tracking`).
//!
//! The DM watchdog (`rtl92d_dm_watchdog`, `dm.c:1229`, only with
//! `rfpwr_state == ERFON`, firmware out of power save and awake, no RF
//! change in progress) runs, in order: [`pwdb_monitor`],
//! [`false_alarm_statistics`], [`find_minimum_rssi`], [`dig`],
//! [`dynamic_txpower_step`] and [`check_edca_turbo`]. Commented out in
//! Linux and not composed here: dynamic BB power saving, TX-power
//! tracking thermal meter, `refresh_rate_adaptive_mask` and interrupt
//! migration. The `rtl92d_set_qos` entry point is the same
//! `rtl92d_dm_init_edca_turbo` state ([`super::station::edca_turbo_init`]
//! returns its `current_turbo_edca` flag).
//!
//! [`rx_pwdb`] is `trx.c::_rtl92de_query_rxphystatus` `rx_pwdb_all`
//! (the value the RX path smooths into `undec_sm_pwdb`): OFDM
//! `((pwdb_all >> 1) & 0x7f) - 106`; CCK the report-based
//! `rx_pwr_all` with the +6 CCK gain diff and the offset table (no
//! `!cck_highpwr` post-table boost — the 92D omits it, unlike the
//! 88EE). `rtl_signal_scale_mapping` is not composed: no NARF
//! consumer takes the scaled signal strength; the station rate
//! adaptation consumes `rx_pwdb_all` directly.

use super::super::rate_adaptive::rx_power_percentage;
use super::phy::{
    get_bb, set_bb, MASKBYTE0, MASKBYTE2, MASKBYTE3, MASKDWORD, RCCK0_CCA, RCCK0_FACOUNTERLOWER,
    RCCK0_FACOUNTERUPPER, RCCK0_FALSEALARMREPORT, ROFDM0_FRAMESYNC, ROFDM0_LSTF,
    ROFDM0_PHYCOUNTER1, ROFDM0_XAAGCCORE1, ROFDM0_XBAGCCORE1, ROFDM1_LSTF, ROFDM_PHYCOUNTER2,
    ROFDM_PHYCOUNTER3,
};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `DM_DIG_FA_TH0` (`rtl8192de/dm.h:21`).
pub const DM_DIG_FA_TH0: u32 = 0x100;
/// `DM_DIG_FA_TH1` (`rtl8192de/dm.h:22`).
pub const DM_DIG_FA_TH1: u32 = 0x400;
/// `DM_DIG_FA_TH2` (`rtl8192de/dm.h:23`).
pub const DM_DIG_FA_TH2: u32 = 0x600;
/// `TXHIGHPWRLEVEL_LEVEL1` (`rtl8192de/dm.h:39`).
pub const TXHIGHPWRLEVEL_LEVEL1: u8 = 1;
/// `TXHIGHPWRLEVEL_LEVEL2` (`rtl8192de/dm.h:40`).
pub const TXHIGHPWRLEVEL_LEVEL2: u8 = 2;
/// `TX_POWER_NEAR_FIELD_THRESH_LVL2` (`rtl8192de/dm.h:47`).
pub const TX_POWER_NEAR_FIELD_THRESH_LVL2: i64 = 74;
/// `TX_POWER_NEAR_FIELD_THRESH_LVL1` (`rtl8192de/dm.h:48`).
pub const TX_POWER_NEAR_FIELD_THRESH_LVL1: i64 = 67;
/// 5 GHz near-field threshold, level 2 (`rtl8192de/dm.c:513`, `0x33`).
pub const TX_POWER_NEAR_FIELD_THRESH_LVL2_5G: i64 = 0x33;
/// 5 GHz near-field threshold, level 1 (`rtl8192de/dm.c:518`, `0x2b`).
pub const TX_POWER_NEAR_FIELD_THRESH_LVL1_5G: i64 = 0x2b;
/// `HAL_DM_HIPWR_DISABLE` (`rtl8192de/dm.h:8`, BIT(1)).
pub const HAL_DM_HIPWR_DISABLE: u8 = 1 << 1;
/// `DIG_STA_CONNECT` (`core.h`, second of the `dig_connect_state` enum).
pub const DIG_STA_CONNECT: u8 = 1;
/// `CCK_PD_STAGE_HIGHRSSI` (`core.h`).
pub const CCK_PD_STAGE_HIGHRSSI: u8 = 1;
/// `REG_EDCA_BE_PARAM` (`rtl8192de/reg.h:219`).
pub const REG_EDCA_BE_PARAM: u16 = 0x0508;
/// `edca_be_ul` / `edca_be_dl` base (`rtl8192de/dm.c:600`).
pub const EDCA_BE_PARAM: u32 = 0x5ea42b;
/// Forced TXOP limit for WEP/TKIP (`rtl8192de/dm.c:613`, `0x005e0000`).
pub const EDCA_TXOP_FORCE: u32 = 0x005e0000;

/// `DM_DIG_FA_UPPER` (`rtl8192de/dm.h`): DIG receive-gain ceiling.
pub const DM_DIG_FA_UPPER: u8 = 0x32;
/// `DM_DIG_FA_LOWER` (`rtl8192de/dm.h`): DIG receive-gain floor.
pub const DM_DIG_FA_LOWER: u8 = 0x20;
/// `DM_RATR_STA_INIT` (`rtl8192de/dm.h`): rate-adaptive start state.
pub const DM_RATR_STA_INIT: u8 = 0;
/// `DM_TYPE_BYDRIVER` (`rtl8192de/dm.h`).
pub const DM_TYPE_BYDRIVER: u8 = 1;
/// `TXHIGHPWRLEVEL_NORMAL` (`rtl8192de/dm.h`).
pub const TXHIGHPWRLEVEL_NORMAL: u8 = 0;

/// Shared DIG thresholds (`core.h`).
pub const DM_DIG_THRESH_LOW: u8 = 35;
/// Shared DIG thresholds (`core.h`).
pub const DM_DIG_THRESH_HIGH: u8 = 40;
/// Shared DIG thresholds (`core.h`).
pub const DM_FALSEALARM_THRESH_LOW: u16 = 400;
/// Shared DIG thresholds (`core.h`).
pub const DM_FALSEALARM_THRESH_HIGH: u16 = 1000;
/// `DM_DIG_MAX` (`core.h`); overridden by [`DM_DIG_FA_UPPER`] on 92D.
pub const DM_DIG_MAX: u8 = 0x3e;
/// `DM_DIG_MIN` (`core.h`); overridden by [`DM_DIG_FA_LOWER`] on 92D.
pub const DM_DIG_MIN: u8 = 0x1e;
/// `DM_DIG_BACKOFF_DEFAULT` (`core.h`).
pub const DM_DIG_BACKOFF_DEFAULT: i8 = 10;
/// `DM_DIG_BACKOFF_MAX` (`core.h`).
pub const DM_DIG_BACKOFF_MAX: i8 = 12;
/// `DM_DIG_BACKOFF_MIN` (`core.h`).
pub const DM_DIG_BACKOFF_MIN: i8 = -4;

/// `DIG_EXT_PORT_STAGE_MAX` (`core.h`).
pub const DIG_EXT_PORT_STAGE_MAX: u8 = 4;
/// `DIG_STA_DISCONNECT` (`core.h`, first of the `dig_connect_state` enum).
pub const DIG_STA_DISCONNECT: u8 = 0;
/// `DIG_MULTISTA_DISCONNECT` (`core.h`).
pub const DIG_MULTISTA_DISCONNECT: u8 = 3;
/// `CCK_PD_STAGE_MAX` (`core.h`).
pub const CCK_PD_STAGE_MAX: u8 = 4;
/// `CCK_PD_STAGE_LOWRSSI` (`core.h`).
pub const CCK_PD_STAGE_LOWRSSI: u8 = 0;

/// The shared DIG table (`struct dig_t`, `core.h`), as
/// `rtl_dm_diginit(hw, 0x20)` leaves it before the 92D
/// receive-gain override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigTable {
    pub dig_enable_flag: bool,
    pub dig_ext_port_stage: u8,
    pub cur_igvalue: u8,
    pub pre_igvalue: u8,
    pub cur_sta_cstate: u8,
    pub presta_cstate: u8,
    pub curmultista_cstate: u8,
    pub rssi_lowthresh: u8,
    pub rssi_highthresh: u8,
    pub fa_lowthresh: u16,
    pub fa_highthresh: u16,
    pub rx_gain_max: u8,
    pub rx_gain_min: u8,
    pub back_val: i8,
    pub back_range_max: i8,
    pub back_range_min: i8,
    pub pre_cck_cca_thres: u8,
    pub cur_cck_cca_thres: u8,
    pub forbidden_igi: u8,
    pub large_fa_hit: u32,
    pub recover_cnt: u32,
    pub dig_min_0: u8,
    pub dig_min_1: u8,
    pub media_connect_0: bool,
    pub media_connect_1: bool,
    pub bt30_cur_igi: u8,
    pub pre_cck_pd_state: u8,
    pub cur_cck_pd_state: u8,
    pub pre_cck_fa_state: u8,
    pub cur_cck_fa_state: u8,
    /// `min_undec_pwdb_for_dm` (`struct dig_t`, `core.h`): the minimum
    /// undec-PWDB the watchdog steps read, from [`find_minimum_rssi`].
    pub min_undec_pwdb_for_dm: i64,
    /// `last_min_undec_pwdb_for_dm` (`struct dig_t`, `core.h`): the
    /// previous pass's minimum (early-mode only; `earlymode_enable`
    /// is false here, so it is carried but never read).
    pub last_min_undec_pwdb_for_dm: i64,
}

impl DigTable {
    /// `rtl_dm_diginit(hw, cur_igvalue)` (`core.c:1948`).
    pub const fn init(cur_igvalue: u8) -> Self {
        Self {
            dig_enable_flag: true,
            dig_ext_port_stage: DIG_EXT_PORT_STAGE_MAX,
            cur_igvalue,
            pre_igvalue: 0,
            cur_sta_cstate: DIG_STA_DISCONNECT,
            presta_cstate: DIG_STA_DISCONNECT,
            curmultista_cstate: DIG_MULTISTA_DISCONNECT,
            rssi_lowthresh: DM_DIG_THRESH_LOW,
            rssi_highthresh: DM_DIG_THRESH_HIGH,
            fa_lowthresh: DM_FALSEALARM_THRESH_LOW,
            fa_highthresh: DM_FALSEALARM_THRESH_HIGH,
            rx_gain_max: DM_DIG_MAX,
            rx_gain_min: DM_DIG_MIN,
            back_val: DM_DIG_BACKOFF_DEFAULT,
            back_range_max: DM_DIG_BACKOFF_MAX,
            back_range_min: DM_DIG_BACKOFF_MIN,
            pre_cck_cca_thres: 0xff,
            cur_cck_cca_thres: 0x83,
            forbidden_igi: DM_DIG_MIN,
            large_fa_hit: 0,
            recover_cnt: 0,
            dig_min_0: 0x25,
            dig_min_1: 0x25,
            media_connect_0: false,
            media_connect_1: false,
            bt30_cur_igi: 0x32,
            pre_cck_pd_state: CCK_PD_STAGE_MAX,
            cur_cck_pd_state: CCK_PD_STAGE_LOWRSSI,
            pre_cck_fa_state: 0,
            cur_cck_fa_state: 0,
            min_undec_pwdb_for_dm: 0,
            last_min_undec_pwdb_for_dm: 0,
        }
    }
}

/// `rtl92d_dm_init_dynamic_txpower` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicTxPower {
    pub enable: bool,
    pub last_dtp_lvl: u8,
    pub highpower_lvl: u8,
}

impl DynamicTxPower {
    /// `rtl92d_dm_init_dynamic_txpower` (`rtl8192de/dm.c:456`).
    pub const fn init() -> Self {
        Self {
            enable: true,
            last_dtp_lvl: TXHIGHPWRLEVEL_NORMAL,
            highpower_lvl: TXHIGHPWRLEVEL_NORMAL,
        }
    }
}

/// `rtl92d_dm_init_edca_turbo` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdcaTurbo {
    pub current_turbo_edca: bool,
    pub is_any_nonbepkts: bool,
    pub is_cur_rdlstate: bool,
    /// `last_txok_cnt` (`rtl8192de/dm.c:596`, a file-static u64 in
    /// Linux — per-owner state here).
    pub last_tx_bytes: u64,
    /// `last_rxok_cnt` (`rtl8192de/dm.c:597`).
    pub last_rx_bytes: u64,
}

impl EdcaTurbo {
    /// `rtl92d_dm_init_edca_turbo` (`rtl8192de/dm.c:582`).
    pub const fn init() -> Self {
        Self {
            current_turbo_edca: false,
            is_any_nonbepkts: false,
            is_cur_rdlstate: false,
            last_tx_bytes: 0,
            last_rx_bytes: 0,
        }
    }
}

/// `rtl92d_dm_init_rate_adaptive_mask` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateAdaptiveMask {
    pub ratr_state: u8,
    pub pre_ratr_state: u8,
    pub useramask: bool,
}

impl RateAdaptiveMask {
    /// `rtl92d_dm_init_rate_adaptive_mask` (`rtl8192de/dm.c:1202`):
    /// `useramask` follows the DM type (driver-owned here).
    pub const fn init(dm_type: u8) -> Self {
        Self {
            ratr_state: DM_RATR_STA_INIT,
            pre_ratr_state: DM_RATR_STA_INIT,
            useramask: dm_type == DM_TYPE_BYDRIVER,
        }
    }
}

/// `rtl92d_dm_initialize_txpower_tracking` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPowerTracking {
    pub tracking: bool,
    pub trackinginit: bool,
    pub track_control: bool,
}

impl TxPowerTracking {
    /// `rtl92d_dm_initialize_txpower_tracking`
    /// (`rtl8192de/dm.c:1168`).
    pub const fn init() -> Self {
        Self {
            tracking: true,
            trackinginit: false,
            track_control: true,
        }
    }
}

/// The `rtlpriv->dm` / `dm_digtable` runtime state after
/// `rtl92d_dm_init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dm {
    pub dm_type: u8,
    pub dm_initialgain_enable: bool,
    pub dig: DigTable,
    pub dynamic_txpower: DynamicTxPower,
    pub edca_turbo: EdcaTurbo,
    pub rate_adaptive: RateAdaptiveMask,
    pub txpower_tracking: TxPowerTracking,
}

impl Dm {
    /// `rtl92d_dm_init` (`rtl8192de/dm.c:1215`): DM type by driver,
    /// DIG init at `0x20` with the 92D receive-gain override, then
    /// the dynamic-TX-power, EDCA-turbo, rate-adaptive-mask and
    /// TX-power-tracking sub-inits. `dm_initialgain_enable` is set
    /// by `rtl_dm_diginit`, matching
    /// [`super::lifecycle::SwVars::dm_initialgain_enable`].
    pub const fn new() -> Self {
        let mut dig = DigTable::init(0x20);
        dig.rx_gain_max = DM_DIG_FA_UPPER;
        dig.rx_gain_min = DM_DIG_FA_LOWER;
        Self {
            dm_type: DM_TYPE_BYDRIVER,
            dm_initialgain_enable: true,
            dig,
            dynamic_txpower: DynamicTxPower::init(),
            edca_turbo: EdcaTurbo::init(),
            rate_adaptive: RateAdaptiveMask::init(DM_TYPE_BYDRIVER),
            txpower_tracking: TxPowerTracking::init(),
        }
    }
}

// The sub-state types expose `const fn` initializers rather than
// `Default`, so the manual impl delegates to `const fn new()`
// instead of a derive.
impl Default for Dm {
    fn default() -> Self {
        Self::new()
    }
}

/// `struct false_alarm_statistics` (`wifi.h`): the decoded
/// false-alarm counters `rtl92d_dm_false_alarm_counter_statistics`
/// leaves behind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FalseAlarm {
    pub cnt_fast_fsync_fail: u32,
    pub cnt_sb_search_fail: u32,
    pub cnt_parity_fail: u32,
    pub cnt_rate_illegal: u32,
    pub cnt_crc8_fail: u32,
    pub cnt_mcs_fail: u32,
    pub cnt_ofdm_fail: u32,
    pub cnt_cck_fail: u32,
    pub cnt_all: u32,
}

/// `rtl92d_dm_false_alarm_counter_statistics`
/// (`rtl8192de/dm.c:132`): hold the page C/D counters, read the six
/// OFDM components and (2.4 GHz only) the CCK counter, then reset
/// them. The CCK page acquire/release
/// (`rtl92d_acquire_cckandrw_pagea_ctl`, `phy.h:83`) is spinlock-only
/// on interface index 1 — no register effect — so it is omitted in
/// this single-threaded owner.
pub fn false_alarm_statistics(io: &impl Io, band_5g: bool) -> Result<FalseAlarm, Error> {
    set_bb(io, ROFDM0_LSTF, 1 << 31, 1)?;
    set_bb(io, ROFDM1_LSTF, 1 << 31, 1)?;
    let framesync = get_bb(io, ROFDM0_FRAMESYNC, MASKDWORD)?;
    let cnt_fast_fsync_fail = framesync & 0xffff;
    let cnt_sb_search_fail = (framesync >> 16) & 0xffff;
    let phy1 = get_bb(io, ROFDM0_PHYCOUNTER1, MASKDWORD)?;
    let cnt_parity_fail = (phy1 >> 16) & 0xffff;
    let phy2 = get_bb(io, ROFDM_PHYCOUNTER2, MASKDWORD)?;
    let cnt_rate_illegal = phy2 & 0xffff;
    let cnt_crc8_fail = (phy2 >> 16) & 0xffff;
    let phy3 = get_bb(io, ROFDM_PHYCOUNTER3, MASKDWORD)?;
    let cnt_mcs_fail = phy3 & 0xffff;
    let cnt_ofdm_fail = cnt_parity_fail
        + cnt_rate_illegal
        + cnt_crc8_fail
        + cnt_mcs_fail
        + cnt_fast_fsync_fail
        + cnt_sb_search_fail;
    let cnt_cck_fail = if band_5g {
        0
    } else {
        let lower = get_bb(io, RCCK0_FACOUNTERLOWER, MASKBYTE0)?;
        let upper = get_bb(io, RCCK0_FACOUNTERUPPER, MASKBYTE3)?;
        lower + ((upper & 0xff) << 8)
    };
    let cnt_all = cnt_fast_fsync_fail
        + cnt_sb_search_fail
        + cnt_parity_fail
        + cnt_rate_illegal
        + cnt_crc8_fail
        + cnt_mcs_fail
        + cnt_cck_fail;
    set_bb(io, ROFDM1_LSTF, 0x0800_0000, 1)?;
    set_bb(io, ROFDM1_LSTF, 0x0800_0000, 0)?;
    set_bb(io, ROFDM0_LSTF, 1 << 31, 0)?;
    set_bb(io, ROFDM1_LSTF, 1 << 31, 0)?;
    if !band_5g {
        set_bb(io, RCCK0_FALSEALARMREPORT, 0x0000_c000, 0)?;
        set_bb(io, RCCK0_FALSEALARMREPORT, 0x0000_c000, 2)?;
    }
    Ok(FalseAlarm {
        cnt_fast_fsync_fail,
        cnt_sb_search_fail,
        cnt_parity_fail,
        cnt_rate_illegal,
        cnt_crc8_fail,
        cnt_mcs_fail,
        cnt_ofdm_fail,
        cnt_cck_fail,
        cnt_all,
    })
}

/// `rtl92d_dm_find_minimum_rssi` (`rtl8192de/dm.c:214`).
/// `UNDEC_SM_PWDB` is `entry_min_undec_sm_pwdb` (`dm.c:13`: the
/// per-entry minimum), `undec_sm_pwdb` the smoothed PWDB. For a
/// station: linked → the smoothed PWDB; unlinked → the entry
/// minimum (0 once the entry is gone). The first Linux branch
/// (unlinked with entry minimum 0 → 0) is subsumed by the else
/// below, which writes the same value. AP/ADHOC branches do not
/// apply to this station-only owner.
pub const fn find_minimum_rssi(
    linked: bool,
    undec_sm_pwdb: i64,
    entry_min_undec_sm_pwdb: i64,
) -> i64 {
    if linked {
        undec_sm_pwdb
    } else {
        entry_min_undec_sm_pwdb
    }
}

/// `rtl92d_dm_dig` (`rtl8192de/dm.c:348`) without the register
/// writes: the initial-gain adjust from `cnt_all` (u8 wrapping
/// arithmetic, as in C) and the abnormally-large-false-alarm
/// handling (`cnt_all > 10000`: `large_fa_hit`, `forbidden_igi`,
/// `rx_gain_min`, `recover_cnt`), then the clamp to
/// `DM_DIG_MAX` / `rx_gain_min`. The early-mode block is skipped:
/// `earlymode_enable` is false in NARF. The caller gates on
/// `dm_initialgain_enable` and station mode.
pub fn dig_adjust(dig: &mut DigTable, cnt_all: u32, linked: bool) {
    dig.cur_sta_cstate = if linked {
        DIG_STA_CONNECT
    } else {
        DIG_STA_DISCONNECT
    };
    let mut value_igi = dig.cur_igvalue;
    if cnt_all < DM_DIG_FA_TH0 {
        value_igi = value_igi.wrapping_sub(1);
    } else if cnt_all < DM_DIG_FA_TH1 {
        // +0.
    } else if cnt_all < DM_DIG_FA_TH2 {
        value_igi = value_igi.wrapping_add(1);
    } else {
        value_igi = value_igi.wrapping_add(2);
    }
    if cnt_all > 10_000 {
        dig.large_fa_hit += 1;
        if dig.forbidden_igi < dig.cur_igvalue {
            dig.forbidden_igi = dig.cur_igvalue;
            dig.large_fa_hit = 1;
        }
        if dig.large_fa_hit >= 3 {
            dig.rx_gain_min = if dig.forbidden_igi >= DM_DIG_MAX {
                DM_DIG_MAX
            } else {
                dig.forbidden_igi + 1
            };
            dig.recover_cnt = 3600;
        }
    } else if dig.recover_cnt != 0 {
        dig.recover_cnt -= 1;
    } else if dig.large_fa_hit == 0 {
        if dig.forbidden_igi.wrapping_sub(1) < DM_DIG_FA_LOWER {
            dig.forbidden_igi = DM_DIG_FA_LOWER;
            dig.rx_gain_min = DM_DIG_FA_LOWER;
        } else {
            dig.forbidden_igi -= 1;
            dig.rx_gain_min = dig.forbidden_igi + 1;
        }
    } else if dig.large_fa_hit == 3 {
        dig.large_fa_hit = 0;
    }
    if value_igi > DM_DIG_MAX {
        value_igi = DM_DIG_MAX;
    } else if value_igi < dig.rx_gain_min {
        value_igi = dig.rx_gain_min;
    }
    dig.cur_igvalue = value_igi;
}

/// `rtl92d_dm_write_dig` (`rtl8192de/dm.c:307`): with DIG disabled
/// `pre_igvalue` becomes `0x17` and nothing is written; otherwise
/// the A/B AGC core registers follow `cur_igvalue` when it moved.
pub fn write_dig(io: &impl Io, dig: &mut DigTable) -> Result<(), Error> {
    if !dig.dig_enable_flag {
        dig.pre_igvalue = 0x17;
        return Ok(());
    }
    if dig.pre_igvalue != dig.cur_igvalue {
        set_bb(io, ROFDM0_XAAGCCORE1, 0x7f, u32::from(dig.cur_igvalue))?;
        set_bb(io, ROFDM0_XBAGCCORE1, 0x7f, u32::from(dig.cur_igvalue))?;
        dig.pre_igvalue = dig.cur_igvalue;
    }
    Ok(())
}

/// `rtl92d_dm_cck_packet_detection_thresh`
/// (`rtl8192de/dm.c:252`): the CCK packet-detection threshold from
/// `min_undec_pwdb_for_dm` and the connect state (25 when the
/// previous stage was LOWRSSI, 20 otherwise; LOW when
/// disconnected), writing `RCCK0_CCA` `MASKBYTE2` `0x83` (LOW) /
/// `0xcd` (HIGH) only on a stage change. The CCK page
/// acquire/release is spinlock-only (see
/// [`false_alarm_statistics`]) and omitted.
pub fn cck_packet_detection_thresh(io: &impl Io, dig: &mut DigTable) -> Result<(), Error> {
    if dig.cur_sta_cstate == DIG_STA_CONNECT {
        let threshold = if dig.pre_cck_pd_state == CCK_PD_STAGE_LOWRSSI {
            25
        } else {
            20
        };
        dig.cur_cck_pd_state = if dig.min_undec_pwdb_for_dm <= threshold {
            CCK_PD_STAGE_LOWRSSI
        } else {
            CCK_PD_STAGE_HIGHRSSI
        };
    } else {
        dig.cur_cck_pd_state = CCK_PD_STAGE_LOWRSSI;
    }
    if dig.pre_cck_pd_state != dig.cur_cck_pd_state {
        let value = if dig.cur_cck_pd_state == CCK_PD_STAGE_LOWRSSI {
            0x83
        } else {
            0xcd
        };
        set_bb(io, RCCK0_CCA, MASKBYTE2, value)?;
        dig.pre_cck_pd_state = dig.cur_cck_pd_state;
    }
    Ok(())
}

/// `rtl92d_dm_dig` (`rtl8192de/dm.c:348`) as a whole: the adjust,
/// the write, and the CCK packet-detection threshold (2.4 GHz
/// only). The caller gates on `dm_initialgain_enable`.
pub fn dig(
    io: &impl Io,
    dig: &mut DigTable,
    cnt_all: u32,
    linked: bool,
    band_5g: bool,
) -> Result<(), Error> {
    dig_adjust(dig, cnt_all, linked);
    write_dig(io, dig)?;
    if !band_5g {
        cck_packet_detection_thresh(io, dig)?;
    }
    Ok(())
}

/// `rtl92d_dm_dynamic_txpower` (`rtl8192de/dm.c:463`): the high-power
/// level for `pwdb` (2.4 GHz: `>= 74` LEVEL2, `< 71` and `>= 67`
/// LEVEL1, `< 62` NORMAL, otherwise hold; 5 GHz: `>= 0x33` LEVEL2,
/// `0x2b..0x33` LEVEL1, `< 0x2b` NORMAL). Disabled
/// (`!enable` or `dm_flag & HAL_DM_HIPWR_DISABLE`) forces NORMAL
/// without touching `last_dtp_lvl`; unlinked with a zero entry
/// minimum forces NORMAL and resets `last_dtp_lvl`. Returns whether
/// the TX power level must be re-programmed (level changed since the
/// last pass). `pwdb` is the station's smoothed PWDB when linked,
/// the entry minimum otherwise (see [`find_minimum_rssi`]).
///
/// Note: in this Linux version `dynamic_txhighpower_lvl` is never
/// consumed by `rtl92d_phy_set_txpower_level` — the re-program
/// writes the same levels — so the observable effect is the level
/// state machine and the re-program call itself.
pub fn dynamic_txpower_step(
    state: &mut DynamicTxPower,
    enable: bool,
    dm_flag: u8,
    linked: bool,
    entry_min_undec_sm_pwdb: i64,
    undec_sm_pwdb: i64,
    band_5g: bool,
) -> bool {
    if !enable || dm_flag & HAL_DM_HIPWR_DISABLE != 0 {
        state.highpower_lvl = TXHIGHPWRLEVEL_NORMAL;
        return false;
    }
    if !linked && entry_min_undec_sm_pwdb == 0 {
        state.highpower_lvl = TXHIGHPWRLEVEL_NORMAL;
        state.last_dtp_lvl = TXHIGHPWRLEVEL_NORMAL;
        return false;
    }
    let pwdb = if linked {
        undec_sm_pwdb
    } else {
        entry_min_undec_sm_pwdb
    };
    let level = if band_5g {
        if pwdb >= TX_POWER_NEAR_FIELD_THRESH_LVL2_5G {
            TXHIGHPWRLEVEL_LEVEL2
        } else if pwdb >= TX_POWER_NEAR_FIELD_THRESH_LVL1_5G {
            TXHIGHPWRLEVEL_LEVEL1
        } else {
            TXHIGHPWRLEVEL_NORMAL
        }
    } else if pwdb >= TX_POWER_NEAR_FIELD_THRESH_LVL2 {
        TXHIGHPWRLEVEL_LEVEL2
    } else if (TX_POWER_NEAR_FIELD_THRESH_LVL1..TX_POWER_NEAR_FIELD_THRESH_LVL2 - 3).contains(&pwdb)
    {
        TXHIGHPWRLEVEL_LEVEL1
    } else if pwdb < TX_POWER_NEAR_FIELD_THRESH_LVL1 - 5 {
        TXHIGHPWRLEVEL_NORMAL
    } else {
        state.highpower_lvl
    };
    let changed = level != state.last_dtp_lvl;
    state.highpower_lvl = level;
    state.last_dtp_lvl = level;
    changed
}

/// The action `rtl92d_dm_check_edca_turbo` takes on one watchdog
/// pass: write `REG_EDCA_BE_PARAM`, restore the AC parameters
/// (`set_hw_reg(HW_VAR_AC_PARAM, AC0_BE)` — for the 92D that is
/// `rtl92d_set_qos`, i.e. `rtl92d_dm_init_edca_turbo` only, no
/// register write), or keep the current parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdcaTurboAction {
    Write(u32),
    RestoreAcParam,
    Keep,
}

/// `rtl92d_dm_check_edca_turbo` (`rtl8192de/dm.c:592`): the EDCA
/// turbo decision from the unicast DATA byte totals since the last
/// pass (download when `cur_rxok > 4 * cur_txok`, upload
/// otherwise), writing `REG_EDCA_BE_PARAM` only on a direction
/// change or on first entry. The WEP/TKIP TXOP force is composed
/// as written but is a no-op for the `0x5ea42b` base: its high half
/// is already non-zero, so the `0x005e` force never fires. The
/// `is_any_nonbepkts` flag is always cleared on exit, and the byte
/// totals are always latched — including on the unlinked exit.
pub fn check_edca_turbo(
    turbo: &mut EdcaTurbo,
    linked: bool,
    disable_framebursting: bool,
    pairwise_wep_tkip: bool,
    tx_bytes_unicast: u64,
    rx_bytes_unicast: u64,
) -> EdcaTurboAction {
    let mut action = EdcaTurboAction::Keep;
    if !linked {
        turbo.current_turbo_edca = false;
    } else {
        let mut edca_be_ul = EDCA_BE_PARAM;
        let mut edca_be_dl = EDCA_BE_PARAM;
        if !disable_framebursting && pairwise_wep_tkip {
            if edca_be_ul & 0xffff_0000 == 0 {
                edca_be_ul |= EDCA_TXOP_FORCE;
            }
            if edca_be_dl & 0xffff_0000 == 0 {
                edca_be_dl |= EDCA_TXOP_FORCE;
            }
        }
        if !turbo.is_any_nonbepkts && !disable_framebursting {
            let cur_txok = tx_bytes_unicast.wrapping_sub(turbo.last_tx_bytes);
            let cur_rxok = rx_bytes_unicast.wrapping_sub(turbo.last_rx_bytes);
            if cur_rxok > cur_txok.saturating_mul(4) {
                if !turbo.is_cur_rdlstate || !turbo.current_turbo_edca {
                    action = EdcaTurboAction::Write(edca_be_dl);
                    turbo.is_cur_rdlstate = true;
                }
            } else if turbo.is_cur_rdlstate || !turbo.current_turbo_edca {
                action = EdcaTurboAction::Write(edca_be_ul);
                turbo.is_cur_rdlstate = false;
            }
            turbo.current_turbo_edca = true;
        } else if turbo.current_turbo_edca {
            // `set_hw_reg(HW_VAR_AC_PARAM, AC0_BE)` is
            // `rtl92d_dm_init_edca_turbo` only: it resets all three
            // EDCA-turbo flags (no register write).
            action = EdcaTurboAction::RestoreAcParam;
            turbo.current_turbo_edca = false;
            turbo.is_cur_rdlstate = false;
        }
    }
    turbo.is_any_nonbepkts = false;
    turbo.last_tx_bytes = tx_bytes_unicast;
    turbo.last_rx_bytes = rx_bytes_unicast;
    action
}

/// `rtl92d_dm_pwdb_monitor` (`rtl8192de/dm.c:570`) H2C payload for
/// `useramask` (true on the 92D: `useramask` follows the DM type
/// `DM_TYPE_BYDRIVER`): `(undec_sm_pwdb << 16) | 0x100`, 3 bytes
/// little-endian, sent as `H2C_RSSI_REPORT` (cmd 5).
pub fn pwdb_monitor_payload(undec_sm_pwdb: i64) -> [u8; 3] {
    let temp = ((undec_sm_pwdb as u32) << 16) | 0x100;
    let bytes = temp.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

/// `trx.c::_rtl92de_query_rxphystatus` `rx_pwdb_all` from the 28-byte
/// `rx_fwinfo_92d` PHY status (`trx.h:371`): byte 4 `pwdb_all`, byte
/// 5 `cfosho[0]` / `cck_agc_rpt` (the CCK overlay
/// `phy_sts_cck_8192d`, `def.h:151`, shares the same bytes).
/// `cck_highpwr` is BB `RFPGA0_XA_HSSIPARAMETER2` (0x824) BIT(9)
/// read while RF is on. OFDM/HT: `rx_pwr_all = ((pwdb_all >> 1) &
/// 0x7f) - 106`. CCK: `rx_pwr_all` from the report base (-46 / -26 /
/// -12 / +16) minus the AGC bits, then `+6` for the CCK gain diff
/// (capped at 100) and the offset table (35-42: -2, 27-34: -6,
/// 15-26: -8, 5-14: -4). No `!cck_highpwr` post-table boost: the
/// 92D omits it, unlike the 88EE. Returns `None` when fewer than
/// 6 status bytes are present.
pub fn rx_pwdb(phy: &[u8], cck: bool, cck_highpwr: bool) -> Option<u8> {
    if phy.len() < 6 {
        return None;
    }
    if !cck {
        return Some(rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 106));
    }
    let agc = phy[5];
    let rx_pwr_all = if !cck_highpwr {
        let report = (agc & 0xc0) >> 6;
        let base = match report {
            3 => -46,
            2 => -26,
            1 => -12,
            _ => 16,
        };
        base - i32::from(agc & 0x3e)
    } else {
        let report = (phy[5] & 0x60) >> 5;
        let base = match report {
            3 => -46,
            2 => -26,
            1 => -12,
            _ => 16,
        };
        base - (i32::from(agc & 0x1f) << 1)
    };
    let mut pwdb = rx_power_percentage(rx_pwr_all).saturating_add(6).min(100);
    pwdb = match pwdb {
        35..=42 => pwdb - 2,
        27..=34 => pwdb - 6,
        15..=26 => pwdb - 8,
        5..=14 => pwdb - 4,
        _ => pwdb,
    };
    Some(pwdb)
}
