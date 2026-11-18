// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE dynamic-mechanism pieces of the station watchdog.
//!
//! - [`rx_pwdb`] — `trx.c::_rtl8723be_query_rxphystatus` `rx_pwdb_all` (the
//!   value `rtl_process_pwdb` smooths into `undec_sm_pwdb`): OFDM
//!   `((cck_sig_qual_ofdm_pwdb_all >> 1) & 0x7f) - 110`; CCK the 8723BE
//!   four-entry LNA table (`6 ⇒ -34`, `4 ⇒ -14`, `1 ⇒ 6`, `0 ⇒ 16`, each
//!   `- 2 * vga`; any other LNA index leaves `rx_pwr_all = 0`) through
//!   `rtl_query_rxpwrpercentage`, capped at 100. There is no `cck_highpwr`
//!   step: Linux reads BB `0x824` BIT(9) and discards it.
//! - [`ra_state`] — `dm.c::rtl8723be_dm_refresh_rate_adaptive_mask`: high
//!   `high_rssi_thresh_for_ra` (50), low `low2high_rssi_thresh_for_ra40m`,
//!   which `rtl8723be_dm_init_rate_adaptive_mask` never sets (it sets
//!   `low_rssi_thresh_for_ra40m`), so the zeroed `rtl_priv` gives 0;
//!   `go_up_gap` 5 raises high from MIDDLE and both from LOW. This is the
//!   RTL8821AE rule ([`super::super::rate_adaptive`]'s
//!   `refresh_rtl8821ae`), reproduced exactly.
//!
//! Watchdog order (`rtl8723be_dm_watchdog`, only with `rfpwr_state ==
//! ERFON`, firmware out of power save and awake, no RF change in progress):
//! common info, false-alarm statistics, RSSI monitor, DIG, dynamic EDCCA,
//! CCK PD, **RA mask refresh**, EDCA turbo, ATC switch, TX-power tracking,
//! dynamic TX power (empty in Linux). This profile composes the common
//! info, false-alarm statistics, RSSI monitor, DIG, dynamic EDCCA, CCK PD
//! and RA mask refresh steps, EDCA turbo, both ATC branches and
//! the (empty) dynamic-TX-power step. Explicit NBTH-qualified tracking now
//! occupies the source thermal slot through tracking_packet.rs, with its own
//! BBSWING/LCK/IQK program; ordinary NAPC never enables it. The retained watchdog only invokes
//! these steps when linked (the `station.rs` gate, as for RTL8192CE), so
//! the unlinked branches run in fixtures, not in production.

use super::super::rate_adaptive::{rx_power_percentage, STA_HIGH, STA_LOW, STA_MIDDLE};
use super::{mac, phy};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub(crate) mod edca;

/// `DM_DIG_FA_TH0/TH1/TH2` (`rtl8723be/dm.h`).
pub const DM_DIG_FA_TH0: u32 = 0x200;
pub const DM_DIG_FA_TH1: u32 = 0x300;
pub const DM_DIG_FA_TH2: u32 = 0x400;
/// `DM_DIG_MIN` / `DM_DIG_MAX` / `DM_DIG_MAX_AP` (`core.h`).
pub const DM_DIG_MIN: u8 = 0x1e;
pub const DM_DIG_MAX: u8 = 0x3e;
pub const DM_DIG_MAX_AP: u8 = 0x32;
/// `CFO_THRESHOLD_XTAL` / `CFO_THRESHOLD_ATC` (`rtl8723be/dm.h`).
pub const CFO_THRESHOLD_XTAL: i32 = 10;
pub const CFO_THRESHOLD_ATC: i32 = 80;
/// `ATC_STATUS_OFF` (0, "enable") / `ATC_STATUS_ON` (1, "disable")
/// (`rtl8723be/dm.h`; the names are inverted: OFF enables CFO tracking).
pub const ATC_STATUS_OFF: u8 = 0;
pub const ATC_STATUS_ON: u8 = 1;
/// False-alarm BB registers (`rtl8723be/dm.h`).
pub const DM_REG_CCK_FA_RST_11N: u16 = 0xA2C;
pub const DM_REG_CCK_FA_MSB_11N: u16 = 0xA58;
pub const DM_REG_CCK_CCA_CNT_11N: u16 = 0xA60;
pub const DM_REG_OFDM_FA_HOLDC_11N: u16 = 0xC00;
pub const DM_REG_OFDM_FA_RSTC_11N: u16 = 0xC0C;
pub const DM_REG_OFDM_FA_TYPE1_11N: u16 = 0xCF0;
pub const DM_REG_OFDM_FA_RSTD_11N: u16 = 0xD00;
pub const DM_REG_OFDM_FA_TYPE2_11N: u16 = 0xDA0;
pub const DM_REG_OFDM_FA_TYPE3_11N: u16 = 0xDA4;
pub const DM_REG_OFDM_FA_TYPE4_11N: u16 = 0xDA8;
/// `ROFDM0_XAAGCCORE1` / `ROFDM0_XBAGCCORE1` / `ROFDM0_ECCATHRESHOLD` /
/// `RCCK0_CCA` / `ROFDM1_CFOTRACKING` / `REG_MAC_PHY_CTRL`
/// (`rtl8723be/reg.h`).
pub const ROFDM0_XAAGCCORE1: u16 = 0xC50;
pub const ROFDM0_XBAGCCORE1: u16 = 0xC58;
pub const ROFDM0_ECCATHRESHOLD: u16 = 0xC4C;
pub const RCCK0_CCA: u16 = 0xA08;
pub const ROFDM1_CFOTRACKING: u16 = 0xD2C;
pub const REG_MAC_PHY_CTRL: u16 = 0x002c;
/// RSSI-report byte for the non-`useramask` path
/// (`rtl8723be_dm_check_rssi_monitor`).
pub const RSSI_REPORT_BYTE: u16 = 0x4fe;

/// The `dig_t` + `rtl_dm` fields the composed `rtl8723be_dm_watchdog`
/// steps read and write. Fields the generic ODM paths use but no 8723BE
/// step reads are not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dm {
    /// `rtl_dm_diginit` `cur_igvalue` (live BB read at init).
    pub cur_igvalue: u8,
    pub pre_igvalue: u8,
    pub media_connect_0: bool,
    pub dig_min_0: u8,
    pub rx_gain_max: u8,
    pub rx_gain_min: u8,
    /// `dig_t->rssi_val_min` (`find_minimum_rssi` output).
    pub rssi_val_min: u8,
    /// `dig_t->min_undec_pwdb_for_dm` (`find_minimum_rssi` output).
    pub min_undec_pwdb_for_dm: u8,
    pub forbidden_igi: u8,
    pub large_fa_hit: u32,
    pub recover_cnt: u32,
    pub pre_cck_cca_thres: u8,
    pub cur_cck_cca_thres: u8,
    /// `dig_t->stop_dig` (`write_dig` gate; never set on this profile).
    pub stop_dig: bool,
    /// `dm->one_entry_only` (`common_info_self_update` output).
    pub one_entry_only: bool,
    /// `rtlhal->pre_edcca_enable` (`dynamic_edcca` input; see that fn).
    pub pre_edcca_enable: bool,
    /// `rtldm->crystal_cap` (`dm_init_dynamic_atc_switch` input).
    pub crystal_cap: u8,
    /// Factory cap captured before the first tracking adjustment.
    pub default_crystal_cap: u8,
    /// `rtldm->atc_status` (`dm_init_dynamic_atc_switch` input).
    pub atc_status: u8,
    pub cfo_threshold: i32,
    pub cfo_ave_pre: i32,
    pub packet_count_pre: u32,
    pub large_cfo_hit: bool,
    pub is_freeze: bool,
    /// `dm->useramask` (`DM_TYPE_BYDRIVER` ⇒ true; driver RA).
    pub useramask: bool,
}

impl Dm {
    /// `rtl8723be_dm_init`'s DM parts: `rtl_dm_diginit` with the live
    /// `ROFDM0_XAAGCCORE1` IGI, `dm_init_dynamic_atc_switch` with the live
    /// crystal cap (the PHY init programmed the efuse cap into
    /// `REG_MAC_PHY_CTRL[23:12]`) and CFO-track bit.
    pub fn init(io: &impl Io) -> Result<Self, Error> {
        let cur_igvalue = phy::get_bb(io, ROFDM0_XAAGCCORE1, 0x7f)? as u8;
        let crystal_cap = (phy::get_bb(io, REG_MAC_PHY_CTRL, 0xFFF000)? & 0x3f) as u8;
        let atc_status = phy::get_bb(io, ROFDM1_CFOTRACKING, 0x800)? as u8;
        Ok(Self {
            cur_igvalue,
            pre_igvalue: 0,
            media_connect_0: false,
            dig_min_0: 0x25,
            rx_gain_max: DM_DIG_MAX,
            rx_gain_min: DM_DIG_MIN,
            rssi_val_min: 0,
            min_undec_pwdb_for_dm: 0,
            forbidden_igi: DM_DIG_MIN,
            large_fa_hit: 0,
            recover_cnt: 0,
            pre_cck_cca_thres: 0xff,
            cur_cck_cca_thres: 0x83,
            stop_dig: false,
            one_entry_only: false,
            pre_edcca_enable: false,
            crystal_cap,
            default_crystal_cap: crystal_cap,
            atc_status,
            cfo_threshold: 10,
            cfo_ave_pre: 0,
            packet_count_pre: 0,
            large_cfo_hit: false,
            is_freeze: false,
            useramask: true,
        })
    }
}

/// `rtl8723be_dm_common_info_self_update`: station + linked ⇒ one entry.
/// (The AP/adhoc/mesh entry count never applies: the retained owner is a
/// station with a single peer.)
pub fn common_info(linked: bool) -> bool {
    linked
}

/// `struct false_alarm_statistics` fields the composed steps read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FalseAlarm {
    pub cnt_ofdm_fail: u32,
    pub cnt_cck_fail: u32,
    pub cnt_cck_cca: u32,
    pub cnt_all: u32,
    pub cnt_cca_all: u32,
}

/// `rtl8723be_dm_false_alarm_counter_statistics`: hold + read the OFDM
/// counters, pulse the CCK counters, read the CCK fail/CCA counts, then
/// reset. `cnt_all` includes the fast-fsync and SB-search counts, unlike
/// RTL8192CE (`rtl92c_dm_false_alarm_counter_statistics`).
pub fn false_alarm(io: &impl Io) -> Result<FalseAlarm, Error> {
    mac::set_bbreg(io, DM_REG_OFDM_FA_HOLDC_11N, 1 << 31, 1)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTD_11N, 1 << 31, 1)?;
    let r1 = phy::get_bb(io, DM_REG_OFDM_FA_TYPE1_11N, phy::MASKDWORD)?;
    let cnt_fast_fsync_fail = r1 & 0xffff;
    let cnt_sb_search_fail = (r1 >> 16) & 0xffff;
    let r2 = phy::get_bb(io, DM_REG_OFDM_FA_TYPE2_11N, phy::MASKDWORD)?;
    let cnt_ofdm_cca = r2 & 0xffff;
    let cnt_parity_fail = (r2 >> 16) & 0xffff;
    let r3 = phy::get_bb(io, DM_REG_OFDM_FA_TYPE3_11N, phy::MASKDWORD)?;
    let cnt_rate_illegal = r3 & 0xffff;
    let cnt_crc8_fail = (r3 >> 16) & 0xffff;
    let cnt_mcs_fail = phy::get_bb(io, DM_REG_OFDM_FA_TYPE4_11N, phy::MASKDWORD)? & 0xffff;
    let cnt_ofdm_fail = cnt_parity_fail
        + cnt_rate_illegal
        + cnt_crc8_fail
        + cnt_mcs_fail
        + cnt_fast_fsync_fail
        + cnt_sb_search_fail;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, 1 << 12, 1)?;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, 1 << 14, 1)?;
    let mut cnt_cck_fail = phy::get_bb(io, DM_REG_CCK_FA_RST_11N, 0xff)?;
    cnt_cck_fail += (phy::get_bb(io, DM_REG_CCK_FA_MSB_11N, 0xff00_0000)? & 0xff) << 8;
    let cca = phy::get_bb(io, DM_REG_CCK_CCA_CNT_11N, phy::MASKDWORD)?;
    let cnt_cck_cca = ((cca & 0xff) << 8) | ((cca & 0xff00) >> 8);
    let cnt_all = cnt_fast_fsync_fail
        + cnt_sb_search_fail
        + cnt_parity_fail
        + cnt_rate_illegal
        + cnt_crc8_fail
        + cnt_mcs_fail
        + cnt_cck_fail;
    let cnt_cca_all = cnt_ofdm_cca + cnt_cck_cca;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTC_11N, 1 << 31, 1)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTC_11N, 1 << 31, 0)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTD_11N, 1 << 27, 1)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTD_11N, 1 << 27, 0)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_HOLDC_11N, 1 << 31, 0)?;
    mac::set_bbreg(io, DM_REG_OFDM_FA_RSTD_11N, 1 << 31, 0)?;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, (1 << 13) | (1 << 12), 0)?;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, (1 << 13) | (1 << 12), 2)?;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, (1 << 15) | (1 << 14), 0)?;
    mac::set_bbreg(io, DM_REG_CCK_FA_RST_11N, (1 << 15) | (1 << 14), 2)?;
    Ok(FalseAlarm {
        cnt_ofdm_fail,
        cnt_cck_fail,
        cnt_cck_cca,
        cnt_all,
        cnt_cca_all,
    })
}

/// `rtl8723be_dm_check_rssi_monitor` + `find_minimum_rssi`: the single
/// station entry's min/max PWDB is `undec_sm_pwdb` when linked, else 0;
/// `dig.rssi_val_min` takes the minimum. Returns the `H2C_RSSIBE_REPORT`
/// body (`[0, 0x20, pwdb]`) when `useramask`, else writes the PWDB byte
/// to `0x4fe` and returns `None`.
pub fn rssi_monitor(
    io: &impl Io,
    dm: &mut Dm,
    undec_sm_pwdb: i64,
    linked: bool,
) -> Result<Option<[u8; 3]>, Error> {
    let pwdb = if linked {
        undec_sm_pwdb.clamp(0, 255) as u8
    } else {
        0
    };
    dm.min_undec_pwdb_for_dm = pwdb;
    dm.rssi_val_min = dm.min_undec_pwdb_for_dm;
    if dm.useramask {
        Ok(Some([0, 0x20, undec_sm_pwdb.clamp(0, 255) as u8]))
    } else {
        io.write8(RSSI_REPORT_BYTE, undec_sm_pwdb.clamp(0, 255) as u8)?;
        Ok(None)
    }
}

/// `rtl8723be_dm_dig` + `rtl8723be_dm_write_dig`: the IGI state machine.
/// `act_scanning` is always false in the retained flow (scans only run
/// with the station Passive, never while the watchdog runs linked), so
/// the early return is vacuous here. `current_igi` arithmetic is C `u8`
/// wrap (`wrapping_add`/`wrapping_sub`); the link-state comparisons use
/// `i32` (C promotes `u8` to `int`).
pub fn dig(io: &impl Io, dm: &mut Dm, linked: bool, cnt_all: u32) -> Result<(), Error> {
    let dm_dig_max: u8 = 0x5a;
    let dm_dig_min: u8 = DM_DIG_MIN;
    let dig_maxofmin: u8 = DM_DIG_MAX_AP;
    let dig_min_0;
    let bfirstconnect = linked && !dm.media_connect_0;
    let bfirstdisconnect = !linked && dm.media_connect_0;
    let mut current_igi = dm.cur_igvalue;
    if linked {
        let rssi = i32::from(dm.rssi_val_min);
        dm.rx_gain_max = if rssi + 10 > i32::from(dm_dig_max) {
            dm_dig_max
        } else if rssi + 10 < i32::from(dm_dig_min) {
            dm_dig_min
        } else {
            (rssi + 10) as u8
        };
        if dm.one_entry_only {
            let offset = 12i32;
            dig_min_0 = if rssi - offset < i32::from(dm_dig_min) {
                dm_dig_min
            } else if rssi - offset > i32::from(dig_maxofmin) {
                dig_maxofmin
            } else {
                (rssi - offset) as u8
            };
        } else {
            dig_min_0 = dm_dig_min;
        }
    } else {
        dm.rx_gain_max = dm_dig_max;
        dig_min_0 = dm_dig_min;
    }
    if cnt_all > 10000 {
        if dm.large_fa_hit != 3 {
            dm.large_fa_hit += 1;
        }
        if dm.forbidden_igi < current_igi {
            dm.forbidden_igi = current_igi;
            dm.large_fa_hit = 1;
        }
        if dm.large_fa_hit >= 3 {
            dm.rx_gain_min = if i32::from(dm.forbidden_igi) + 1 > i32::from(dm.rx_gain_max) {
                dm.rx_gain_max
            } else {
                dm.forbidden_igi.wrapping_add(1)
            };
            dm.recover_cnt = 3600;
        }
    } else if dm.recover_cnt != 0 {
        dm.recover_cnt -= 1;
    } else if dm.large_fa_hit < 3 {
        if i32::from(dm.forbidden_igi) - 1 < i32::from(dig_min_0) {
            dm.forbidden_igi = dig_min_0;
            dm.rx_gain_min = dig_min_0;
        } else {
            dm.forbidden_igi = dm.forbidden_igi.wrapping_sub(1);
            dm.rx_gain_min = dm.forbidden_igi.wrapping_add(1);
        }
    } else {
        dm.large_fa_hit = 0;
    }
    if dm.rx_gain_min > dm.rx_gain_max {
        dm.rx_gain_min = dm.rx_gain_max;
    }
    if linked {
        if bfirstconnect {
            current_igi = if dm.rssi_val_min <= dig_maxofmin {
                dm.rssi_val_min
            } else {
                dig_maxofmin
            };
            dm.large_fa_hit = 0;
        } else if cnt_all > DM_DIG_FA_TH2 {
            current_igi = current_igi.wrapping_add(4);
        } else if cnt_all > DM_DIG_FA_TH1 {
            current_igi = current_igi.wrapping_add(2);
        } else if cnt_all < DM_DIG_FA_TH0 {
            current_igi = current_igi.wrapping_sub(2);
        }
    } else if bfirstdisconnect {
        current_igi = dm.rx_gain_min;
    } else if cnt_all > 10000 {
        current_igi = current_igi.wrapping_add(4);
    } else if cnt_all > 8000 {
        current_igi = current_igi.wrapping_add(2);
    } else if cnt_all < 500 {
        current_igi = current_igi.wrapping_sub(2);
    }
    if current_igi > dm.rx_gain_max {
        current_igi = dm.rx_gain_max;
    } else if current_igi < dm.rx_gain_min {
        current_igi = dm.rx_gain_min;
    }
    write_dig(io, dm, current_igi)?;
    dm.media_connect_0 = linked;
    dm.dig_min_0 = dig_min_0;
    Ok(())
}

/// `rtl8723be_dm_write_dig`: no write while `stop_dig`; RF_1T1R writes
/// path A only (`ROFDM0_XAAGCCORE1`).
fn write_dig(io: &impl Io, dm: &mut Dm, current_igi: u8) -> Result<(), Error> {
    if dm.stop_dig {
        return Ok(());
    }
    if dm.cur_igvalue != current_igi {
        mac::set_bbreg(io, ROFDM0_XAAGCCORE1, 0x7f, u32::from(current_igi))?;
    }
    dm.pre_igvalue = dm.cur_igvalue;
    dm.cur_igvalue = current_igi;
    Ok(())
}

/// `rtl8723be_dm_dynamic_edcca`: the FW-PS-mode gate is the caller's (the
/// watchdog only runs with the firmware out of power save). Both paths
/// above 0x28 write the enable bytes; both below 0x25 write the disable
/// bytes only while `pre_edcca_enable` — which Linux v6.1 never sets for
/// 8723BE (only `rtl8192ee/dm.c` assigns it), so the disable branch is
/// dead in the mirrored code and the flag stays false.
pub fn dynamic_edcca(io: &impl Io, pre_edcca_enable: bool) -> Result<(), Error> {
    let reg_c50 = phy::get_bb(io, ROFDM0_XAAGCCORE1, 0xff)? as u8;
    let reg_c58 = phy::get_bb(io, ROFDM0_XBAGCCORE1, 0xff)? as u8;
    if reg_c50 > 0x28 && reg_c58 > 0x28 {
        if !pre_edcca_enable {
            io.write8(ROFDM0_ECCATHRESHOLD, 0x03)?;
            io.write8(ROFDM0_ECCATHRESHOLD + 2, 0x00)?;
        }
    } else if reg_c50 < 0x25 && reg_c58 < 0x25 && pre_edcca_enable {
        io.write8(ROFDM0_ECCATHRESHOLD, 0x7f)?;
        io.write8(ROFDM0_ECCATHRESHOLD + 2, 0x7f)?;
    }
    Ok(())
}

/// `rtl8723be_dm_cck_packet_detection_thresh`: the CCK CCA threshold from
/// `rssi_val_min` when linked, else from the CCK fail count; a change
/// writes `RCCK0_CCA` byte 2.
pub fn cck_packet_detection_thresh(
    io: &impl Io,
    dm: &mut Dm,
    linked: bool,
    cnt_cck_fail: u32,
) -> Result<(), Error> {
    let cur = if linked {
        if dm.rssi_val_min > 25 {
            0xcd
        } else if dm.rssi_val_min > 10 || cnt_cck_fail > 1000 {
            0x83
        } else {
            0x40
        }
    } else if cnt_cck_fail > 1000 {
        0x83
    } else {
        0x40
    };
    if dm.cur_cck_cca_thres != cur {
        mac::set_bbreg(io, RCCK0_CCA, 0x00ff_0000, u32::from(cur))?;
    }
    dm.pre_cck_cca_thres = dm.cur_cck_cca_thres;
    dm.cur_cck_cca_thres = cur;
    Ok(())
}

/// `rtl8723be_dm_dynamic_atc_switch`, unlinked branch only: enable CFO
/// tracking when off, then — unless BT is enabled — re-apply the crystal
/// cap when it drifted. Linux compares the cached cap against the efuse
/// cap; the retained owner has no efuse access (the cap lives in the
/// factory, not the owner), so the cached cap — initialised from the live
/// `REG_MAC_PHY_CTRL` field the PHY init programmed from efuse — is
/// compared against a fresh read of that field instead. The only writer
/// of the field in the retained driver is this step, so the two
/// comparisons coincide before tracking. After tracking the saved
/// default restores the factory cap rather than the last adjustment.
pub fn atc_switch_unlinked(io: &impl Io, dm: &mut Dm, bt_disabled: bool) -> Result<(), Error> {
    if dm.atc_status == ATC_STATUS_OFF {
        mac::set_bbreg(io, ROFDM1_CFOTRACKING, 1 << 11, u32::from(ATC_STATUS_ON))?;
        dm.atc_status = ATC_STATUS_ON;
    }
    if !bt_disabled {
        return Ok(());
    }
    let live = (phy::get_bb(io, REG_MAC_PHY_CTRL, 0xFFF000)? & 0x3f) as u8;
    if dm.crystal_cap != dm.default_crystal_cap || dm.default_crystal_cap != live {
        dm.crystal_cap = dm.default_crystal_cap;
        let cap = u32::from(dm.default_crystal_cap & 0x3f);
        mac::set_bbreg(io, REG_MAC_PHY_CTRL, 0xFFF000, cap | (cap << 6))?;
    }
    Ok(())
}

/// `trx.c::_rtl8723be_query_rxphystatus` CFO state. Keep it outside the
/// lazily initialized watchdog so the first RX samples are not lost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cfo {
    pub tail: [i8; 2],
    pub packet_count: u32,
}

impl Cfo {
    /// Only error-free non-CCK frames matching the programmed BSSID
    /// contribute. RXD error gates are applied by the native caller.
    pub(crate) fn observe(&mut self, phy: &[u8], frame: &[u8], bssid: [u8; 6], cck: bool) {
        if cck || frame.len() < 24 || bssid == [0; 6] {
            return;
        }
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        if fc & 0x0c == 0x04 {
            return;
        }
        let address = if fc & 0x0100 != 0 {
            4
        } else if fc & 0x0200 != 0 {
            10
        } else {
            16
        };
        if frame[address..address + 6] != bssid {
            return;
        }
        let Some(tails) = phy.get(9..11) else {
            return;
        };
        self.tail = [tails[0] as i8, tails[1] as i8];
        self.packet_count = self.packet_count.wrapping_add(1);
    }
}

/// Linked `rtl8723be_dm_dynamic_atc_switch` for the admitted RF_1T1R
/// profile: signed path-A CFO in 3125/1280 kHz units, one-cycle large
/// jump filter, 10/20 kHz crystal hysteresis, 0..63 cap and strict
/// (-80, 80) kHz ATC-disable window (`dm.c`, `dm.h`).
pub(crate) fn atc_switch_linked(io: &impl Io, dm: &mut Dm, cfo: &Cfo) -> Result<(), Error> {
    if cfo.packet_count == dm.packet_count_pre {
        return Ok(());
    }
    dm.packet_count_pre = cfo.packet_count;
    let average = i32::from(cfo.tail[0]) * 3125 / 1280;
    if (dm.cfo_ave_pre - average).abs() > 20 && !dm.large_cfo_hit {
        dm.large_cfo_hit = true;
        return Ok(());
    }
    dm.large_cfo_hit = false;
    dm.cfo_ave_pre = average;
    if (-dm.cfo_threshold..=dm.cfo_threshold).contains(&average) && !dm.is_freeze {
        if dm.cfo_threshold == 10 {
            dm.cfo_threshold = 20;
            dm.is_freeze = true;
        } else {
            dm.cfo_threshold = 10;
        }
    }
    let adjustment = if average > dm.cfo_threshold && dm.crystal_cap < 63 {
        ((average - 10) >> 1) + 1
    } else if average < -dm.cfo_threshold && dm.crystal_cap > 0 {
        ((average + 10) >> 1) - 1
    } else {
        0
    };
    if adjustment != 0 {
        dm.is_freeze = false;
        let cap = (i32::from(dm.crystal_cap) + adjustment).clamp(0, 63) as u8;
        mac::set_bbreg(io, REG_MAC_PHY_CTRL, 0xFFF000, u32::from(cap) * 0x41)?;
        dm.crystal_cap = cap;
    }
    let atc = u8::from(!(-79..=79).contains(&average));
    if dm.atc_status != atc {
        mac::set_bbreg(io, ROFDM1_CFOTRACKING, 1 << 11, u32::from(atc))?;
        dm.atc_status = atc;
    }
    Ok(())
}

/// `rtl8723be_dm_dynamic_txpower`: empty in Linux ("8723BE does not
/// support ODM_BB_DYNAMIC_TXPWR"). Composed by vacuity.
pub fn dynamic_txpower() {}

/// `p_ra->high_rssi_thresh_for_ra`.
pub const HIGH_RSSI_THRESH_FOR_RA: i64 = 50;
/// `p_ra->low2high_rssi_thresh_for_ra40m` (never initialised ⇒ 0).
pub const LOW2HIGH_RSSI_THRESH_FOR_RA40M: i64 = 0;
const GO_UP_GAP: i64 = 5;

/// `rtl8723be_dm_refresh_rate_adaptive_mask`: the new `ratr_state` for
/// `undec_sm_pwdb` when it differs from `pre_ratr_state`. The state is
/// passed unchanged as `rtl8723be_update_hal_rate_mask`'s `rssi_level`.
pub fn ra_state(rssi: i64, current: u8) -> Option<u8> {
    let (mut high, mut low) = (HIGH_RSSI_THRESH_FOR_RA, LOW2HIGH_RSSI_THRESH_FOR_RA40M);
    match current {
        STA_MIDDLE => high += GO_UP_GAP,
        STA_LOW => {
            high += GO_UP_GAP;
            low += GO_UP_GAP;
        }
        _ => {}
    }
    let state = if rssi > high {
        STA_HIGH
    } else if rssi > low {
        STA_MIDDLE
    } else {
        STA_LOW
    };
    (state != current).then_some(state)
}

/// `_rtl8723be_query_rxphystatus` `rx_pwdb_all` from the PHY status
/// (`struct phy_status_rpt`: byte 4 `cck_sig_qual_ofdm_pwdb_all`, byte 5
/// `cck_agc_rpt_ofdm_cfosho_a`).
pub fn rx_pwdb(phy: &[u8], cck: bool) -> Option<u8> {
    if phy.len() < 6 {
        return None;
    }
    if !cck {
        return Some(rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 110));
    }
    let agc = phy[5];
    let vga = i32::from(agc & 0x1f);
    let power = match (agc & 0xe0) >> 5 {
        6 => -34 - 2 * vga,
        4 => -14 - 2 * vga,
        1 => 6 - 2 * vga,
        0 => 16 - 2 * vga,
        _ => 0,
    };
    Some(rx_power_percentage(power).min(100))
}
