// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE host-to-firmware commands (`rtl92d_fill_h2c_cmd`).
//!
//! - [`Mailbox::fill`] — `rtl92d_fill_h2c_cmd`
//!   (`rtl8192d/fw_common.c`): refused while the radio is off
//!   (`rfpwr_state == ERFOFF` or `inactive_pwrstate == ERFOFF`);
//!   one write attempt with `_rtl92d_check_fw_read_last_h2c`
//!   (`REG_HMETFR` bit `boxnum` clear) with up to 99 re-checks 10 us
//!   apart, each followed by Linux's `0x1BF` read; byte-wise box
//!   writes (1–3 bytes: BIT(7) of the id clear; 4–5 bytes: BIT(7)
//!   set, the first two bytes into `REG_HMEBOX_EXT_n` first);
//!   `last_hmeboxnum` rotation. Unlike Linux (which logs and returns),
//!   a box the firmware never drained or a length outside 1..=5
//!   poisons the mailbox with [`Error::CommandTimeout`] /
//!   [`Error::Descriptor`]. The `h2c_setinprogress` spinlock is not
//!   modelled: the mailbox is owned by one caller, which serializes
//!   fills.
//! - [`joinbss`] — `rtl92d_set_fw_joinbss_report_cmd`
//!   (`H2C_JOINBSSRPT`, one byte: `RT_MEDIA_CONNECT` /
//!   `RT_MEDIA_DISCONNECT`).
//! - [`rate_mask`] / [`update_hal_rate_mask`] —
//!   `rtl92de_update_hal_rate_mask` (`rtl8192de/hw.c`): the
//!   multi-station rate-id / MAC-id send (`H2C_RA_MASK`, 5 bytes).
//!   The admitted-subset gate refuses a mask that names an
//!   unadmitted rate or is empty, and never narrows the peer's
//!   rates: the envelope's full-order admitted set is the same bit
//!   layout as the firmware bitmap (CCK 0..3, OFDM 4..11, MCS0-7
//!   12..19, MCS8-15 20..27).
//! - [`set_rpwm`] / [`enter_leisure`] / [`leave_leisure`] — the
//!   92D LPS path. Linux v6.1 has no `rtl92d_set_fw_pwrmode_cmd`
//!   definition and no `HW_VAR_FW_LPS_ACTION` case for this chip,
//!   so the firmware power-mode command (`H2C_SETPWRMODE`) is
//!   never sent on 92D; the enter/leave is the RPWM byte alone
//!   (`HW_VAR_SET_RPWM` → `H2C_PWRM`, 1 byte: `0x02` RF-off on
//!   enter, `0x0c` RF-on on leave, the FW-LPS protocol bytes shared
//!   with the 92CE handler), with `fw_current_inpsmode` recorded by
//!   the caller. [`pwrmode`] is the payload the firmware would
//!   receive on a chip that sends it, kept so the LPS state record
//!   (`fwctrl_psmode` DTIM, awake interval 5) is pinned in one
//!   place — it is not sent on 92D.
//! - RDG: dead in upstream Linux v6.1 — `mac->rdg_en` is never
//!   assigned (only read in `hw.c` and `trx.c`), so the RDG/HTC
//!   descriptor bits are never enabled. The descriptor rule lives
//!   in [`super::trx`] behind an `rdg_en` input that stays false
//!   unless a later lane grounds a reason to set it.

use super::rate::WirelessMode;
use super::{Band, RfType};
use crate::rtlwifi::channel_power;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_HMEBOX_EXT_0: u16 = 0x0088;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;

/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_SETPWRMODE: u8 = 1;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_JOINBSSRPT: u8 = 2;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_RSVDPAGE: u8 = 3;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_RSSI_REPORT: u8 = 5;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_RA_MASK: u8 = 6;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_MAC_MODE_SEL: u8 = 9;
/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_PWRM: u8 = 15;

/// `FW_PS_ACTIVE_MODE` / `FW_PS_DTIM_MODE` (`wifi.h`).
pub const FW_PS_ACTIVE_MODE: u8 = 0;
pub const FW_PS_DTIM_MODE: u8 = 3;

/// `MAX_LPS_AWAKE_INTERVAL` (`rtl92d_init_sw_vars`
/// `reg_max_lps_awakeintvl`).
pub const MAX_LPS_AWAKE_INTERVAL: u8 = 5;

/// `RATR_INX_*` (`wifi.h`).
pub const RATR_INX_WIRELESS_NGB: u8 = 0;
pub const RATR_INX_WIRELESS_NG: u8 = 1;
pub const RATR_INX_WIRELESS_NB: u8 = 2;
pub const RATR_INX_WIRELESS_N: u8 = 3;
pub const RATR_INX_WIRELESS_GB: u8 = 4;
pub const RATR_INX_WIRELESS_G: u8 = 5;
pub const RATR_INX_WIRELESS_B: u8 = 6;
pub const RATR_INX_WIRELESS_MC: u8 = 7;
pub const RATR_INX_WIRELESS_A: u8 = 8;
pub const RATR_INX_WIRELESS_AC_24N: u8 = 9;

/// `H2C_RSVDPAGE` (`wifi.h` `enum rtl8192c_h2c_cmd`).
pub const H2C_RSVDPAGE: u8 = 3;

/// `RT_MEDIA_CONNECT` / `RT_MEDIA_DISCONNECT`.
pub const MEDIA_CONNECT: u8 = 1;
pub const MEDIA_DISCONNECT: u8 = 0;

/// The H2C mailbox state (`rtlhal->last_hmeboxnum`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub last_hmeboxnum: u8,
}

impl Mailbox {
    pub fn new() -> Self {
        Self { last_hmeboxnum: 0 }
    }

    fn fw_read_last(&self, io: &impl Io) -> Result<bool, Error> {
        let v = io.read8(REG_HMETFR)?;
        Ok((v >> self.last_hmeboxnum) & 1 == 0)
    }

    /// `rtl92d_fill_h2c_cmd`. `rf_on` is false when `rfpwr_state` or
    /// `inactive_pwrstate` is `ERFOFF`: the command is dropped without
    /// a write, as in Linux.
    pub async fn fill(
        &mut self,
        io: &impl Io,
        element_id: u8,
        cmd: &[u8],
        rf_on: bool,
    ) -> Result<(), Error> {
        if !rf_on {
            return Ok(());
        }
        if !(1..=5).contains(&cmd.len()) || self.last_hmeboxnum > 3 {
            return Err(Error::Descriptor);
        }
        let boxnum = self.last_hmeboxnum;
        let box_reg = REG_HMEBOX_0 + u16::from(boxnum) * 4;
        let box_extreg = REG_HMEBOX_EXT_0 + u16::from(boxnum) * 2;
        let mut wait_h2c_limit = 100u8;
        let mut isfw_read = self.fw_read_last(io)?;
        while !isfw_read {
            wait_h2c_limit = wait_h2c_limit.saturating_sub(1);
            if wait_h2c_limit == 0 {
                return Err(Error::CommandTimeout);
            }
            io.delay_us(10).await;
            isfw_read = self.fw_read_last(io)?;
            let _ = io.read8(0x1bf)?;
        }
        let mut boxcontent = [0u8; 4];
        let mut boxextcontent = [0u8; 2];
        boxcontent[0] = element_id;
        if cmd.len() <= 3 {
            boxcontent[0] &= !(1 << 7);
            boxcontent[1..1 + cmd.len()].copy_from_slice(cmd);
            for (idx, value) in boxcontent.into_iter().enumerate() {
                io.write8(box_reg + idx as u16, value)?;
            }
        } else {
            boxcontent[0] |= 1 << 7;
            boxextcontent.copy_from_slice(&cmd[..2]);
            boxcontent[1..1 + (cmd.len() - 2)].copy_from_slice(&cmd[2..]);
            for (idx, value) in boxextcontent.into_iter().enumerate() {
                io.write8(box_extreg + idx as u16, value)?;
            }
            for (idx, value) in boxcontent.into_iter().enumerate() {
                io.write8(box_reg + idx as u16, value)?;
            }
        }
        self.last_hmeboxnum = boxnum + 1;
        if self.last_hmeboxnum == 4 {
            self.last_hmeboxnum = 0;
        }
        Ok(())
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// `rtl92d_set_fw_joinbss_report_cmd` (`mstatus` =
/// [`MEDIA_CONNECT`] / [`MEDIA_DISCONNECT`]).
pub async fn joinbss(
    mailbox: &mut Mailbox,
    io: &impl Io,
    mstatus: u8,
    rf_on: bool,
) -> Result<(), Error> {
    mailbox.fill(io, H2C_JOINBSSRPT, &[mstatus], rf_on).await
}

// ── Rate mask (`rtl92de_update_hal_rate_mask`) ──────────────────────────

/// The `ieee80211_sta` + `rtl_sta_info` fields
/// `rtl92de_update_hal_rate_mask` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub mode: WirelessMode,
    /// `supp_rates[0]` (2.4 GHz) / `supp_rates[1]` (5 GHz), 12
    /// legacy bits each.
    pub supp_rates: [u32; 2],
    /// `ht_cap.mcs.rx_mask[0..2]`.
    pub rx_mask: [u8; 2],
    pub sgi20: bool,
    pub sgi40: bool,
    /// `sta_entry->mimo_ps == IEEE80211_SMPS_STATIC`.
    pub mimo_ps_static: bool,
    /// `mac->opmode == AP || ADHOC`: the MAC id is `aid + 1`
    /// (a station is always MAC id 0).
    pub ap_or_adhoc: bool,
    /// `sta->aid` (only read when `ap_or_adhoc`).
    pub aid: u8,
}

/// The `rtl92de_update_hal_rate_mask` send: the 5-byte
/// `H2C_RA_MASK` payload, the rate-table index it carries, and the
/// MAC id it was addressed to. Linux stores `ratr_index` into
/// `sta_entry` only when `macid != 0`; a station keeps rate-id 0
/// in the descriptor path (see [`super::trx::rate_id_macid`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateMask {
    pub payload: [u8; 5],
    pub ratr_index: u8,
    pub mac_id: u8,
}

/// `rtl92de_update_hal_rate_mask` payload for `peer` on `band`
/// with `rf_type`, `bw40` (`curtxbw_40mhz`; on a station Linux
/// takes `mac->bw_40`, not the peer's bandwidth) and `rssi_level`.
/// `update_bw` is unused by Linux on this chip.
pub fn rate_mask(peer: &Peer, rf_type: RfType, band: Band, bw40: bool, rssi_level: u8) -> RateMask {
    let mut bitmap = match band {
        Band::On5Ghz => peer.supp_rates[1] << 4,
        Band::On2Ghz => peer.supp_rates[0],
    };
    bitmap |= (u32::from(peer.rx_mask[1]) << 20) | (u32::from(peer.rx_mask[0]) << 12);
    let mac_id = if peer.ap_or_adhoc { peer.aid + 1 } else { 0 };
    let mut shortgi = false;
    let ratr_index = match peer.mode {
        WirelessMode::B => {
            bitmap &= if bitmap & 0x0c != 0 { 0x0d } else { 0x0f };
            RATR_INX_WIRELESS_B
        }
        WirelessMode::G => {
            bitmap &= match rssi_level {
                1 => 0x0000_0f00,
                2 => 0x0000_0ff0,
                _ => 0x0000_0ff5,
            };
            RATR_INX_WIRELESS_GB
        }
        WirelessMode::A => {
            bitmap &= 0x0000_0ff0;
            RATR_INX_WIRELESS_G
        }
        WirelessMode::N24g | WirelessMode::N5g => {
            let index = if peer.mode == WirelessMode::N24g {
                RATR_INX_WIRELESS_NGB
            } else {
                RATR_INX_WIRELESS_NG
            };
            if peer.mimo_ps_static {
                bitmap &= match rssi_level {
                    1 => 0x0007_0000,
                    2 => 0x0007_f000,
                    _ => 0x0007_f005,
                };
            } else {
                let (low, mid, high) = match (rf_type, bw40) {
                    (RfType::OneT1R, true) => (0x000f_0000, 0x000f_f000, 0x000f_f015),
                    (RfType::OneT1R, false) => (0x000f_0000, 0x000f_f000, 0x000f_f005),
                    (RfType::TwoT2R, true) => (0x0f0f_0000, 0x0f0f_f000, 0x0f0f_f015),
                    (RfType::TwoT2R, false) => (0x0f0f_0000, 0x0f0f_f000, 0x0f0f_f005),
                };
                bitmap &= match rssi_level {
                    1 => low,
                    2 => mid,
                    _ => high,
                };
            }
            if (bw40 && peer.sgi40) || (!bw40 && peer.sgi20) {
                // Short GI only when the peer is MAC id 0; MAC id 1
                // forces it off, and higher ids leave it off.
                if mac_id == 0 {
                    shortgi = true;
                }
            }
            index
        }
        WirelessMode::Unknown => {
            // Linux's narrow `0x000ff0ff` applies only to
            // `RF_1T2R`, which NARF's `RfType` merges into
            // `OneT1R` (RF_1T1R takes the wide mask); the wide
            // mask is used for both variants here.
            bitmap &= 0x0f0f_f0ff;
            RATR_INX_WIRELESS_NGB
        }
    };
    let word = (bitmap & 0x0fff_ffff) | (u32::from(ratr_index) << 28);
    let b = word.to_le_bytes();
    RateMask {
        payload: [
            b[0],
            b[1],
            b[2],
            b[3],
            mac_id | if shortgi { 0x20 } else { 0 } | 0x80,
        ],
        ratr_index,
        mac_id,
    }
}

/// `rtl92de_update_hal_rate_mask` send. `admitted` is the
/// envelope's admitted set in firmware-bitmap layout (the low 28
/// bits of [`super::envelope::Permission::admitted_rates`]); a
/// mask naming an unadmitted rate, or an empty mask, is refused
/// with [`Error::Power`] (`Policy`) and nothing is sent — the
/// firmware never receives a rate the board was not measured for.
pub async fn update_hal_rate_mask(
    mailbox: &mut Mailbox,
    io: &impl Io,
    peer: &Peer,
    rf_type: RfType,
    band: Band,
    bw40: bool,
    rssi_level: u8,
    admitted: u32,
    rf_on: bool,
) -> Result<RateMask, Error> {
    let mask = rate_mask(peer, rf_type, band, bw40, rssi_level);
    let rates = u32::from_le_bytes([
        mask.payload[0],
        mask.payload[1],
        mask.payload[2],
        mask.payload[3],
    ]) & 0x0fff_ffff;
    if rates == 0 || rates & !admitted != 0 {
        return Err(Error::Power(channel_power::Error::Policy));
    }
    mailbox.fill(io, H2C_RA_MASK, &mask.payload, rf_on).await?;
    Ok(mask)
}

// ── RPWM / LPS (`HW_VAR_SET_RPWM` → `H2C_PWRM`) ─────────────────────────

/// `rtl92d_set_fw_pwrmode_cmd(mode)` payload, `[mode, 1,
/// MAX_LPS_AWAKE_INTERVAL]` (mirroring the 92CE port). Kept to pin
/// the LPS state record; Linux v6.1 never sends it on 92D — there
/// is no `rtl92d_set_fw_pwrmode_cmd` definition — so no caller
/// fills it into the mailbox.
pub const fn pwrmode(mode: u8) -> [u8; 3] {
    [mode, 1, MAX_LPS_AWAKE_INTERVAL]
}

/// `HW_VAR_SET_RPWM`: `rtl92d_fill_h2c_cmd(hw, H2C_PWRM, 1, val)`.
/// Unlike the 92CE port, this is a firmware command, not the
/// `0x3dc` register toggle — 92D has no `REG_PCIE_HRPWM`.
pub async fn set_rpwm(
    mailbox: &mut Mailbox,
    io: &impl Io,
    value: u8,
    rf_on: bool,
) -> Result<(), Error> {
    mailbox.fill(io, H2C_PWRM, &[value], rf_on).await
}

/// The 92D LPS enter (`rtl_lps_set_psmode`, firmware-control LPS,
/// `rtl92d` `HW_VAR_FW_LPS_ACTION` is a no-op so the RPWM byte is
/// the whole send): RF off (`0x02`). The caller records
/// `fw_current_inpsmode = true` (`HW_VAR_FW_PSMODE_STATUS`) and
/// keeps `fwctrl_psmode` (DTIM) as the power mode; the guards are
/// `rtl_lps_set_psmode`'s (not adhoc, linked, firmware-control LPS,
/// report-linked) and belong to the station owner.
pub async fn enter_leisure(mailbox: &mut Mailbox, io: &impl Io, rf_on: bool) -> Result<(), Error> {
    set_rpwm(mailbox, io, 0x02, rf_on).await
}

/// The 92D LPS leave: RF on (`0x0c`), power mode back to
/// [`FW_PS_ACTIVE_MODE`]. The caller records
/// `fw_current_inpsmode = false`.
pub async fn leave_leisure(mailbox: &mut Mailbox, io: &impl Io, rf_on: bool) -> Result<(), Error> {
    set_rpwm(mailbox, io, 0x0c, rf_on).await
}
