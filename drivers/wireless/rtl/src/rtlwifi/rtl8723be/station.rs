// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE station MAC registers for the retained packet owner.
//!
//! Exact `rtl8723be/hw.c`: `_rtl8723be_stop_tx_beacon`,
//! `_rtl8723be_enable_bcn_sub_func`, `_rtl8723be_set_media_status`
//! (STATION / UNSPECIFIED), `rtl8723be_set_check_bssid`,
//! `rtl8723be_set_network_type`, `rtl8723be_set_hw_reg`
//! `HW_VAR_{BSSID,BASIC_RATE,SLOT_TIME,SIFS,ACK_PREAMBLE,RCR,AID}`,
//! `rtl8723be_update_channel_access_setting` and `rtl8723be_set_qos` (the
//! fixed BK/VI/VO EDCA rows mac80211's `conf_tx` triggers for every AC; BE
//! is never written).
//!
//! `HW_VAR_SLOT_TIME`'s four `HW_VAR_AC_PARAM` calls run
//! `rtl8723_dm_init_edca_turbo` (software state only) and reach
//! `HW_VAR_ACM_CTRL` only when `acm_method != EACMWAY2_SW`; `pci.c` sets
//! `EACMWAY2_SW`, so no register write results. LED control is not
//! composed.

use super::h2c;
use super::mac::REG_RCR;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `MSR` (`REG_CR + 2`) and its link types.
pub const MSR: u16 = 0x0102;
pub const MSR_NOLINK: u8 = 0x00;
pub const MSR_INFRA: u8 = 0x02;
pub const REG_TDECTRL: u16 = 0x0208;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_SPEC_SIFS: u16 = 0x0428;
pub const REG_RRSR: u16 = 0x0440;
pub const REG_INIRTS_RATE_SEL: u16 = 0x0480;
pub const REG_EDCA_VO_PARAM: u16 = 0x0500;
pub const REG_EDCA_VI_PARAM: u16 = 0x0504;
pub const REG_EDCA_BK_PARAM: u16 = 0x050c;
pub const REG_BCNTCFG: u16 = 0x0510;
pub const REG_SIFS_CTX: u16 = 0x0514;
pub const REG_SIFS_TRX: u16 = 0x0516;
pub const REG_SLOT: u16 = 0x051b;
pub const REG_TBTT_PROHIBIT: u16 = 0x0540;
pub const REG_BSSID: u16 = 0x0618;
pub const REG_MAC_SPEC_SIFS: u16 = 0x063a;
pub const REG_RESP_SIFS_OFDM: u16 = 0x063e;
pub const REG_TRXPTCL_CTL: u16 = 0x0668;
pub const REG_CAMCMD: u16 = 0x0670;
pub const REG_BCN_PSR_RPT: u16 = 0x06a8;
/// `RCR_CBSSID_DATA` / `RCR_CBSSID_BCN`.
pub const RCR_CBSSID_DATA: u32 = 1 << 6;
pub const RCR_CBSSID_BCN: u32 = 1 << 7;
/// `rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)` into `REG_CAMCMD`.
pub const CAM_RESET: u32 = 0xc000_0000;

/// `rtlpci->receive_config` and `rtlpci->reg_bcn_ctrl_val` caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveConfig {
    pub rcr: u32,
    pub bcn_ctrl: u8,
}

/// `_rtl8723be_stop_tx_beacon`.
pub fn stop_tx_beacon(io: &impl Io) -> Result<(), Error> {
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0x64)?;
    let prohibit = io.read8(REG_TBTT_PROHIBIT + 2)?;
    io.write8(REG_TBTT_PROHIBIT + 2, prohibit & !1)?;
    Ok(())
}

/// `_rtl8723be_set_media_status` for `NL80211_IFTYPE_STATION` (`linked`:
/// MSR_INFRA, `link_state >= MAC80211_LINKED`) or a station without a link
/// / `NL80211_IFTYPE_UNSPECIFIED` (MSR_NOLINK): the MSR low bits are read
/// first, then `_rtl8723be_stop_tx_beacon` and
/// `_rtl8723be_enable_bcn_sub_func` (both link types), the MSR write and
/// `REG_BCNTCFG + 1 = 0x66`.
pub fn set_media_status(
    io: &impl Io,
    receive: &mut ReceiveConfig,
    linked: bool,
) -> Result<(), Error> {
    let msr = io.read8(MSR)? & 0xfc;
    stop_tx_beacon(io)?;
    h2c::set_bcn_ctrl(io, &mut receive.bcn_ctrl, 0, 1 << 1)?;
    io.write8(MSR, msr | if linked { MSR_INFRA } else { MSR_NOLINK })?;
    io.write8(REG_BCNTCFG + 1, 0x66)?;
    Ok(())
}

/// `rtl8723be_set_check_bssid` over the cached `receive_config` (the caller
/// guarantees `rfpwr_state == ERFON`). `HW_VAR_RCR` writes the register and
/// the cache.
pub fn set_check_bssid(
    io: &impl Io,
    receive: &mut ReceiveConfig,
    check: bool,
) -> Result<(), Error> {
    if check {
        let rcr = receive.rcr | RCR_CBSSID_DATA | RCR_CBSSID_BCN;
        io.write32(REG_RCR, rcr)?;
        receive.rcr = rcr;
        h2c::set_bcn_ctrl(io, &mut receive.bcn_ctrl, 0, 1 << 4)
    } else {
        let rcr = receive.rcr & !(RCR_CBSSID_DATA | RCR_CBSSID_BCN);
        h2c::set_bcn_ctrl(io, &mut receive.bcn_ctrl, 1 << 4, 0)?;
        io.write32(REG_RCR, rcr)?;
        receive.rcr = rcr;
        Ok(())
    }
}

/// `rtl8723be_set_network_type(NL80211_IFTYPE_STATION)`: the media status
/// then `rtl8723be_set_check_bssid(linked)`.
pub fn network_type_station(
    io: &impl Io,
    receive: &mut ReceiveConfig,
    linked: bool,
) -> Result<(), Error> {
    set_media_status(io, receive, linked)?;
    set_check_bssid(io, receive, linked)
}

/// `HW_VAR_BSSID`.
pub fn set_bssid(io: &impl Io, bssid: [u8; 6]) -> Result<(), Error> {
    for (index, value) in bssid.into_iter().enumerate() {
        io.write8(REG_BSSID + index as u16, value)?;
    }
    Ok(())
}

/// `rtl8723be_set_qos` for AC1_BK, AC0_BE (no write), AC2_VI, AC3_VO.
pub fn set_qos_all(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_EDCA_BK_PARAM, 0xa44f)?;
    io.write32(REG_EDCA_VI_PARAM, 0x5e_4322)?;
    io.write32(REG_EDCA_VO_PARAM, 0x2f_3222)?;
    Ok(())
}

/// `HW_VAR_BASIC_RATE`: `(rates & 0x15f) | 0x01` as the two RRSR low
/// bytes and `REG_INIRTS_RATE_SEL` = the index of its highest set bit.
/// Returns `(rate_cfg, rate_index)`.
pub fn basic_rate(rates: u16) -> (u16, u8) {
    let cfg = (rates & 0x15f) | 0x01;
    (cfg, (15 - cfg.leading_zeros()) as u8)
}

/// `rtl8723be_update_channel_access_setting`: `HW_VAR_SLOT_TIME` (the four
/// `HW_VAR_AC_PARAM` are no-ops, see the module note) and `HW_VAR_SIFS`
/// with `sifs_timer` `0x0a0a` (`!ht_enable`) / `0x0e0e`; HW_VAR_SIFS writes
/// `REG_RESP_SIFS_OFDM` as `0x0e0e` without HT and the timer with it.
pub fn channel_access(io: &impl Io, slot: u8, ht: bool) -> Result<(), Error> {
    io.write8(REG_SLOT, slot)?;
    let sifs: u16 = if ht { 0x0e0e } else { 0x0a0a };
    let [lo, hi] = sifs.to_le_bytes();
    io.write8(REG_SIFS_CTX + 1, lo)?;
    io.write8(REG_SIFS_TRX + 1, hi)?;
    io.write8(REG_SPEC_SIFS + 1, lo)?;
    io.write8(REG_MAC_SPEC_SIFS + 1, lo)?;
    io.write16(REG_RESP_SIFS_OFDM, if ht { sifs } else { 0x0e0e })?;
    Ok(())
}

/// `HW_VAR_ACK_PREAMBLE`: `REG_TRXPTCL_CTL + 2` BIT(1) set for a short
/// preamble, cleared (`& 0xFD`) otherwise.
pub fn ack_preamble(io: &impl Io, short: bool) -> Result<(), Error> {
    let value = io.read8(REG_TRXPTCL_CTL + 2)?;
    io.write8(
        REG_TRXPTCL_CTL + 2,
        if short { value | 0x02 } else { value & 0xfd },
    )?;
    Ok(())
}

/// `rtl_op_bss_info_changed` `BSS_CHANGED_ERP_PREAMBLE`
/// (`HW_VAR_ACK_PREAMBLE`) and `BSS_CHANGED_ERP_SLOT` (`HW_VAR_SLOT_TIME`
/// to `REG_SLOT`; its `HW_VAR_AC_PARAM` loop writes nothing) for the changed
/// `(use_short_preamble, use_short_slot)` flags only.
pub fn erp_changed(io: &impl Io, old: (bool, bool), new: (bool, bool)) -> Result<(), Error> {
    if old.0 != new.0 {
        ack_preamble(io, new.0)?;
    }
    if old.1 != new.1 {
        io.write8(REG_SLOT, if new.1 { 9 } else { 20 })?;
    }
    Ok(())
}

/// Authentication-time `BSS_CHANGED_BASIC_RATES` / ERP and the `conf_tx`
/// rows for a 2.4 GHz station (the BSSID is [`set_bssid`]): RRSR and
/// `INIRTS_RATE_SEL` ([`basic_rate`] of `rates` — Linux passes
/// `sta->supp_rates[0]`), slot and ACK preamble from
/// `ieee80211_handle_bss_capability` of `capability` and the BSS ERP octet
/// `erp` (`rtl8192ee::station::erp_timing`), SIFS (`ht` = `ht_enable`) and
/// the fixed `set_qos` rows. `basic` must name 1 Mb/s and only rates the
/// RRSR mask keeps. Returns the programmed `(short_preamble, short_slot)`.
pub fn configure_rates(
    io: &impl Io,
    rates: u16,
    basic: u16,
    capability: u16,
    erp: Option<u8>,
    ht: bool,
) -> Result<(bool, bool), Error> {
    if rates & basic & 1 == 0 || basic & !0x15f != 0 || rates & !0xfff != 0 {
        return Err(Error::Packet);
    }
    let (cfg, index) = basic_rate(rates);
    let [lo, hi] = cfg.to_le_bytes();
    io.write8(REG_RRSR, lo)?;
    io.write8(REG_RRSR + 1, hi)?;
    io.write8(REG_INIRTS_RATE_SEL, index)?;
    let timing = crate::rtlwifi::rtl8192ee::station::erp_timing(capability, erp);
    channel_access(io, if timing.1 { 9 } else { 20 }, ht)?;
    set_qos_all(io)?;
    ack_preamble(io, timing.0)?;
    Ok(timing)
}

/// `HW_VAR_AID` (`REG_BCN_PSR_RPT` word: `& 0xC000 | assoc_id`).
pub fn set_aid(io: &impl Io, aid: u16) -> Result<(), Error> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let previous = u16::from_le_bytes([io.read8(REG_BCN_PSR_RPT)?, io.read8(REG_BCN_PSR_RPT + 1)?]);
    io.write16(REG_BCN_PSR_RPT, (previous & 0xc000) | aid)?;
    Ok(())
}
