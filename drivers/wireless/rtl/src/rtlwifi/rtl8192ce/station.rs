// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE station MAC registers for the retained packet
//! owner.
//!
//! Exact `rtl8192ce/hw.c`: `rtl92ce_set_network_type` (STATION:
//! `_rtl92ce_set_media_status`, [`super::ps::set_media_status`], then
//! `rtl92ce_set_check_bssid(link)`), `rtl92ce_set_hw_reg`
//! `HW_VAR_{BSSID,BASIC_RATE,SLOT_TIME,SIFS,ACK_PREAMBLE,RCR}`,
//! `rtl92ce_update_channel_access_setting` and `rtl92ce_set_qos` (the
//! fixed BK/VI/VO EDCA rows mac80211's `conf_tx` triggers for every AC; BE
//! is never written).
//!
//! `HW_VAR_SLOT_TIME`'s four `HW_VAR_AC_PARAM` calls run
//! `rtl92c_dm_init_edca_turbo` (software state only) and reach
//! `HW_VAR_ACM_CTRL` only when `acm_method != EACMWAY2_SW`; `pci.c` sets
//! `EACMWAY2_SW`, so no register write results. LED control is not
//! composed.

use super::mac::REG_RCR;
use super::ps::{self, BcnCtrl};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_SPEC_SIFS: u16 = 0x0428;
pub const REG_RRSR: u16 = 0x0440;
pub const REG_INIRTS_RATE_SEL: u16 = 0x0480;
pub const REG_EDCA_VO_PARAM: u16 = 0x0500;
pub const REG_EDCA_VI_PARAM: u16 = 0x0504;
pub const REG_EDCA_BK_PARAM: u16 = 0x050c;
pub const REG_SIFS_CTX: u16 = 0x0514;
pub const REG_SIFS_TRX: u16 = 0x0516;
pub const REG_SLOT: u16 = 0x051b;
pub const REG_BSSID: u16 = 0x0618;
pub const REG_MAC_SPEC_SIFS: u16 = 0x063a;
pub const REG_RESP_SIFS_OFDM: u16 = 0x063e;
pub const REG_CAMCMD: u16 = 0x0670;
/// `RCR_CBSSID_DATA` / `RCR_CBSSID_BCN`.
pub const RCR_CBSSID_DATA: u32 = 1 << 6;
pub const RCR_CBSSID_BCN: u32 = 1 << 7;
/// `rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)` into `REG_CAMCMD`.
pub const CAM_RESET: u32 = 0xc000_0000;

/// `rtl92ce_set_check_bssid` over the cached `rtlpci->receive_config`
/// (the caller guarantees `rfpwr_state == ERFON`: the owner is running
/// with the radio on). `HW_VAR_RCR` writes the register and the cache.
pub fn set_check_bssid(
    io: &impl Io,
    receive_config: &mut u32,
    bcn: &mut BcnCtrl,
    check: bool,
) -> Result<(), Error> {
    if check {
        let rcr = *receive_config | RCR_CBSSID_DATA | RCR_CBSSID_BCN;
        io.write32(REG_RCR, rcr)?;
        *receive_config = rcr;
        bcn.set(io, 0, 1 << 4)
    } else {
        let rcr = *receive_config & !(RCR_CBSSID_DATA | RCR_CBSSID_BCN);
        bcn.set(io, 1 << 4, 0)?;
        io.write32(REG_RCR, rcr)?;
        *receive_config = rcr;
        Ok(())
    }
}

/// `rtl92ce_set_network_type(NL80211_IFTYPE_STATION)`:
/// `_rtl92ce_set_media_status` (MSR INFRA when `linked`, else NOLINK),
/// then `rtl92ce_set_check_bssid(linked)`.
pub fn network_type_station(
    io: &impl Io,
    receive_config: &mut u32,
    bcn: &mut BcnCtrl,
    linked: bool,
) -> Result<(), Error> {
    ps::set_media_status(io, bcn, linked)?;
    set_check_bssid(io, receive_config, bcn, linked)
}

/// `HW_VAR_BSSID`.
pub fn set_bssid(io: &impl Io, bssid: [u8; 6]) -> Result<(), Error> {
    for (index, value) in bssid.into_iter().enumerate() {
        io.write8(REG_BSSID + index as u16, value)?;
    }
    Ok(())
}

/// `rtl92ce_set_qos` for AC1_BK, AC0_BE (no write), AC2_VI, AC3_VO.
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

/// `rtl92ce_update_channel_access_setting`: `HW_VAR_SLOT_TIME` (the four
/// `HW_VAR_AC_PARAM` are no-ops, see the module note) and `HW_VAR_SIFS`
/// with `sifs_timer` `0x0a0a` (`!ht_enable`) / `0x1010`;
/// `REG_RESP_SIFS_OFDM` is `0x0e0e` without HT and the timer with it.
pub fn channel_access(io: &impl Io, slot: u8, ht: bool) -> Result<(), Error> {
    io.write8(REG_SLOT, slot)?;
    let sifs: u16 = if ht { 0x1010 } else { 0x0a0a };
    let [lo, hi] = sifs.to_le_bytes();
    io.write8(REG_SIFS_CTX + 1, lo)?;
    io.write8(REG_SIFS_TRX + 1, hi)?;
    io.write8(REG_SPEC_SIFS + 1, lo)?;
    io.write8(REG_MAC_SPEC_SIFS + 1, lo)?;
    io.write16(REG_RESP_SIFS_OFDM, if ht { sifs } else { 0x0e0e })?;
    Ok(())
}

/// `HW_VAR_ACK_PREAMBLE`: `REG_RRSR + 2 = (cur_40_prime_sc << 5) |
/// (short ? 0x80 : 0)` (the whole byte, as Linux).
pub fn ack_preamble(io: &impl Io, prime_sc: u8, short: bool) -> Result<(), Error> {
    io.write8(REG_RRSR + 2, (prime_sc << 5) | if short { 0x80 } else { 0 })?;
    Ok(())
}

/// `rtl_op_bss_info_changed` `BSS_CHANGED_ERP_SLOT` (`HW_VAR_SLOT_TIME`
/// to `REG_SLOT`; its `HW_VAR_AC_PARAM` loop writes nothing) and
/// `BSS_CHANGED_ERP_PREAMBLE` (`HW_VAR_ACK_PREAMBLE`) for the changed
/// `(use_short_preamble, use_short_slot)` flags only
/// (`rtl8192ee::station::erp_timing` is the shared mac80211
/// `ieee80211_handle_bss_capability` derivation).
pub fn erp_changed(
    io: &impl Io,
    old: (bool, bool),
    new: (bool, bool),
    prime_sc: u8,
) -> Result<(), Error> {
    if old.0 != new.0 {
        ack_preamble(io, prime_sc, new.0)?;
    }
    if old.1 != new.1 {
        io.write8(REG_SLOT, if new.1 { 9 } else { 20 })?;
    }
    Ok(())
}

/// Authentication-time `BSS_CHANGED_BASIC_RATES` / ERP and the `conf_tx`
/// rows for a 2.4 GHz legacy-or-HT station (the BSSID is [`set_bssid`]): RRSR and
/// `INIRTS_RATE_SEL` ([`basic_rate`] of `rates` — Linux passes
/// `sta->supp_rates[0]`, the peer's supported set), slot and ACK preamble
/// from `ieee80211_handle_bss_capability` of `capability` and the BSS ERP
/// octet `erp` (9 us slot with the short-slot bit 0x400, else 20; with an
/// ERP element the preamble is short unless Barker bit 2, else capability
/// 0x20), SIFS (`ht` = `ht_enable`), the fixed `set_qos` rows, at the
/// programmed `prime_sc`. `basic` must name 1 Mb/s (the 2.4 GHz
/// `rate_control_send_low` rate) and only rates the RRSR mask keeps.
pub fn configure_rates(
    io: &impl Io,
    rates: u16,
    basic: u16,
    capability: u16,
    erp: Option<u8>,
    ht: bool,
    prime_sc: u8,
) -> Result<(), Error> {
    if rates & basic & 1 == 0 || basic & !0x15f != 0 || rates & !0xfff != 0 {
        return Err(Error::Packet);
    }
    let (cfg, index) = basic_rate(rates);
    let [lo, hi] = cfg.to_le_bytes();
    io.write8(REG_RRSR, lo)?;
    io.write8(REG_RRSR + 1, hi)?;
    io.write8(REG_INIRTS_RATE_SEL, index)?;
    let (short_preamble, short_slot) =
        crate::rtlwifi::rtl8192ee::station::erp_timing(capability, erp);
    channel_access(io, if short_slot { 9 } else { 20 }, ht)?;
    set_qos_all(io)?;
    ack_preamble(io, prime_sc, short_preamble)
}
