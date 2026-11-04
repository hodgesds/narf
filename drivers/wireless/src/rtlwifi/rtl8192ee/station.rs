// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE station MAC registers for the retained packet owner.
//!
//! Exact `rtl8192ee/hw.c`: `_rtl92ee_set_media_status` (STATION),
//! `rtl92ee_set_network_type` / `rtl92ee_set_check_bssid`,
//! `_rtl92ee_stop_tx_beacon`, `_rtl92ee_enable_bcn_sub_func`,
//! `rtl92ee_set_hw_reg` `HW_VAR_{BSSID,BASIC_RATE,SLOT_TIME,SIFS,
//! ACK_PREAMBLE,RCR}`, `rtl92ee_update_channel_access_setting` and
//! `rtl92ee_set_qos` (the fixed BK/VI/VO EDCA rows mac80211's `conf_tx`
//! triggers for every AC; BE is never written).
//!
//! `HW_VAR_AC_PARAM` only reaches `HW_VAR_ACM_CTRL` when `acm_method !=
//! EACMWAY2_SW`; `pci.c` sets `EACMWAY2_SW`, so no register write results.
//! LED control (`led_control`) is not composed.

use super::h2c;
use super::mac::{RECEIVE_CONFIG, REG_RCR};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const MSR: u16 = 0x0102;
pub const MSR_INFRA: u8 = 0x02;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_SPEC_SIFS: u16 = 0x0428;
pub const REG_RRSR: u16 = 0x0440;
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
pub const REG_CAMCMD: u16 = 0x0670;
/// `RCR_CBSSID_DATA` / `RCR_CBSSID_BCN`.
pub const RCR_CBSSID_DATA: u32 = 1 << 6;
pub const RCR_CBSSID_BCN: u32 = 1 << 7;
/// `rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)` into `REG_CAMCMD`.
pub const CAM_RESET: u32 = 0xc000_0000;

/// `rtlpci->receive_config` and `reg_bcn_ctrl_val` as the owner caches
/// them (`HW_VAR_RCR` updates the cache with every write).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveConfig {
    pub rcr: u32,
}

impl Default for ReceiveConfig {
    fn default() -> Self {
        Self {
            rcr: RECEIVE_CONFIG,
        }
    }
}

impl ReceiveConfig {
    /// `rtl92ee_set_check_bssid` (the caller guarantees `rfpwr_state ==
    /// ERFON`: the owner is running with the radio on).
    pub fn set_check_bssid(
        &mut self,
        io: &impl Io,
        bcn_ctrl: &mut u8,
        check: bool,
    ) -> Result<(), Error> {
        if check {
            let rcr = self.rcr | RCR_CBSSID_DATA | RCR_CBSSID_BCN;
            io.write32(REG_RCR, rcr)?;
            self.rcr = rcr;
            h2c::set_bcn_ctrl(io, bcn_ctrl, 0, 1 << 4)
        } else {
            let rcr = self.rcr & !(RCR_CBSSID_DATA | RCR_CBSSID_BCN);
            h2c::set_bcn_ctrl(io, bcn_ctrl, 1 << 4, 0)?;
            io.write32(REG_RCR, rcr)?;
            self.rcr = rcr;
            Ok(())
        }
    }
}

/// `_rtl92ee_stop_tx_beacon`.
pub fn stop_tx_beacon(io: &impl Io) -> Result<(), Error> {
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0x64)?;
    let prohibit = io.read8(REG_TBTT_PROHIBIT + 2)?;
    io.write8(REG_TBTT_PROHIBIT + 2, prohibit & !1)?;
    Ok(())
}

/// `rtl92ee_set_network_type(NL80211_IFTYPE_STATION)`:
/// `_rtl92ee_set_media_status` (MSR INFRA when `linked`, else NOLINK; stop
/// TX beacon and enable the beacon sub-function in both; `REG_BCNTCFG + 1
/// = 0x66`), then `rtl92ee_set_check_bssid(linked)`. Unlike 8821AE the
/// 8192EE media status does not clear `REG_BCN_CTRL`.
pub fn network_type_station(
    io: &impl Io,
    receive: &mut ReceiveConfig,
    bcn_ctrl: &mut u8,
    linked: bool,
) -> Result<(), Error> {
    let msr = io.read8(MSR)? & 0xfc;
    stop_tx_beacon(io)?;
    h2c::set_bcn_ctrl(io, bcn_ctrl, 0, 1 << 1)?;
    io.write8(MSR, msr | if linked { MSR_INFRA } else { 0 })?;
    io.write8(REG_BCNTCFG + 1, 0x66)?;
    receive.set_check_bssid(io, bcn_ctrl, linked)
}

/// `HW_VAR_BSSID`.
pub fn set_bssid(io: &impl Io, bssid: [u8; 6]) -> Result<(), Error> {
    for (index, value) in bssid.into_iter().enumerate() {
        io.write8(REG_BSSID + index as u16, value)?;
    }
    Ok(())
}

/// `rtl92ee_set_qos` for AC1_BK, AC0_BE (no write), AC2_VI, AC3_VO.
pub fn set_qos_all(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_EDCA_BK_PARAM, 0xa44f)?;
    io.write32(REG_EDCA_VI_PARAM, 0x5e_4322)?;
    io.write32(REG_EDCA_VO_PARAM, 0x2f_3222)?;
    Ok(())
}

/// `HW_VAR_BASIC_RATE`: `(rates & 0x15f) | 0x01`, then `| 0xd` and
/// `& ~BIT(1)`, written as the two RRSR low bytes.
pub fn basic_rate(rates: u16) -> u16 {
    (((rates & 0x15f) | 0x01) | 0xd) & !(1 << 1)
}

/// `rtl92ee_update_channel_access_setting`: `HW_VAR_SLOT_TIME` (the four
/// `HW_VAR_AC_PARAM` are no-ops, see the module note) and `HW_VAR_SIFS`
/// with `sifs_timer` `0x0a0a` (`!ht_enable`) / `0x0e0e`; `REG_RESP_SIFS_OFDM`
/// is `0x0e0e` without HT and the timer (also `0x0e0e`) with it.
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

/// `HW_VAR_ACK_PREAMBLE`: `REG_RRSR + 2 = (cur_40_prime_sc << 5) |
/// (short ? 0x80 : 0)` (the whole byte, as Linux).
pub fn ack_preamble(io: &impl Io, prime_sc: u8, short: bool) -> Result<(), Error> {
    io.write8(REG_RRSR + 2, (prime_sc << 5) | if short { 0x80 } else { 0 })?;
    Ok(())
}

/// The ERP element's single octet (`WLAN_EID_ERP_INFO`), or `None`
/// without one; a malformed or repeated element is refused.
pub fn erp_octet(mut ies: &[u8]) -> Result<Option<u8>, Error> {
    let mut erp = None;
    while !ies.is_empty() {
        let head = ies.get(..2).ok_or(Error::Packet)?;
        let end = 2 + usize::from(head[1]);
        let body = ies.get(2..end).ok_or(Error::Packet)?;
        if head[0] == 42 && (body.len() != 1 || erp.replace(body[0]).is_some()) {
            return Err(Error::Packet);
        }
        ies = &ies[end..];
    }
    Ok(erp)
}

/// mac80211 `ieee80211_handle_bss_capability` on 2.4 GHz:
/// `(use_short_preamble, use_short_slot)`. With a valid ERP element the
/// preamble is short unless `WLAN_ERP_BARKER_PREAMBLE` (bit 2) is set;
/// without one it follows `WLAN_CAPABILITY_SHORT_PREAMBLE` (0x20). The
/// slot follows `WLAN_CAPABILITY_SHORT_SLOT_TIME` (0x400).
pub fn erp_timing(capability: u16, erp: Option<u8>) -> (bool, bool) {
    let short_preamble = match erp {
        Some(octet) => octet & 0x04 == 0,
        None => capability & 0x20 != 0,
    };
    (short_preamble, capability & 0x400 != 0)
}

/// `rtl_op_bss_info_changed` `BSS_CHANGED_ERP_SLOT` (`HW_VAR_SLOT_TIME`:
/// `RTL_SLOT_TIME_9`/`_20` to `REG_SLOT`; its `HW_VAR_AC_PARAM` loop
/// writes nothing, module note) and `BSS_CHANGED_ERP_PREAMBLE`
/// (`HW_VAR_ACK_PREAMBLE`) for the changed flags only.
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

/// Authentication-time `BSS_CHANGED_BSSID` / `BASIC_RATES` / ERP and the
/// `conf_tx` rows for a 2.4 GHz legacy-or-HT station: BSSID, RRSR
/// ([`basic_rate`] of `rates` — Linux passes `sta->supp_rates[0]`, the
/// peer's supported set, not the BSS basic set), slot and ACK preamble
/// from [`erp_timing`] of `capability` and the BSS ERP octet `erp` (9 us
/// slot with the short-slot capability, else 20), SIFS (`ht` =
/// `ht_enable`), the fixed `set_qos` rows, at the programmed `prime_sc`.
/// `basic` must name 1 Mb/s (the 2.4 GHz `rate_control_send_low` rate)
/// and only rates the RRSR mask keeps.
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
    let [lo, hi] = basic_rate(rates).to_le_bytes();
    io.write8(REG_RRSR, lo)?;
    io.write8(REG_RRSR + 1, hi)?;
    let (short_preamble, short_slot) = erp_timing(capability, erp);
    channel_access(io, if short_slot { 9 } else { 20 }, ht)?;
    set_qos_all(io)?;
    ack_preamble(io, prime_sc, short_preamble)
}
