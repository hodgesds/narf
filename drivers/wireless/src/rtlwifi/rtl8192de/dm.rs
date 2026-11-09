// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE dynamic mechanism init (`rtl92d_dm_init`, `rtl8192de/dm.c`).
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
//! The DM watchdog (`rtl92d_dm_watchdog`: DIG, dynamic TX power,
//! EDCA turbo, thermal tracking) is a later lane; this module owns
//! only the init-time state the watchdog reads. The `rtl92d_set_qos`
//! entry point is the same `rtl92d_dm_init_edca_turbo` state
//! ([`super::station::edca_turbo_init`] returns its
//! `current_turbo_edca` flag).

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
}

impl EdcaTurbo {
    /// `rtl92d_dm_init_edca_turbo` (`rtl8192de/dm.c:582`).
    pub const fn init() -> Self {
        Self {
            current_turbo_edca: false,
            is_any_nonbepkts: false,
            is_cur_rdlstate: false,
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
