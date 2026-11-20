// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE station-mode register chains (`rtl92de_set_network_type`,
//! `rtl92de_set_check_bssid`, `rtl92d_linked_set_reg` helpers,
//! `rtl92de_set_hw_reg` / `rtl92d_set_hw_reg` / `rtl92de_get_hw_reg`).
//!
//! Exact `rtl8192de/hw.c` + `rtl8192d/hw_common.c`:
//!
//! - `_rtl92de_set_media_status`: MSR low two bits per type
//!   (NOLINK / ADHOC / INFRA / AP), stop/resume TX beacon around it,
//!   `REG_BCNTCFG + 1 = 0x00` on AP else `0x66`. LED control is not
//!   composed.
//! - `rtl92de_set_check_bssid`: over the cached `rtlpci->
//!   receive_config`, refused while the radio is off; `HW_VAR_RCR`
//!   writes the register and the cache, `REG_BCN_CTRL` BIT(4) follows
//!   (set after the RCR write on check, cleared before it on uncheck).
//! - `rtl92de_set_network_type`: media status, then check-BSSID on
//!   the link state (never for AP).
//! - `rtl92d_stop_tx_beacon` / `rtl92d_resume_tx_beacon`
//!   (`FWHW_TXQ_CTRL + 2` BIT(6), `REG_BCN_MAX_ERR`, `REG_TBTT_
//!   PROHIBIT`).
//! - `HW_VAR_{BSSID,BASIC_RATE,SLOT_TIME,SIFS,ACK_PREAMBLE,RCR,
//!   AMPDU_MIN_SPACE,SHORTGI_DENSITY,AMPDU_FACTOR,RETRY_LIMIT,
//!   DUAL_TSF_RST,AID,WPA_CONFIG}` and the DE `HW_VAR_{AC_PARAM,
//!   ACM_CTRL,H2C_FW_JOINBSSRPT,CORRECT_TSF,INT_MIGRATION,INT_AC}`
//!   cases. `HW_VAR_WPA_CONFIG` is software crypto (`REG_SECCFG` 0,
//!   [`super::mac::station_identity`]) and is not re-ported here.
//! - `rtl92de_set_beacon_related_registers` /
//!   `rtl92de_set_beacon_interval`, `rtl92de_update_interrupt_mask`,
//!   `rtl92de_suspend` / `rtl92de_resume` (the `REG_MAC_PHY_CTRL_
//!   NORMAL` byte).
//! - `HW_VAR_AC_PARAM` runs `rtl92d_dm_init_edca_turbo` (software
//!   state only) and reaches `HW_VAR_ACM_CTRL` only when
//!   `acm_method != EACMWAY2_SW`; `pci.c` sets `EACMWAY2_SW`, so no
//!   register write results — [`acm_ctrl`] is the direct
//!   `HW_VAR_ACM_CTRL` write.
//! - `HW_VAR_H2C_FW_JOINBSSRPT`: the `REG_CR + 1` / `REG_BCN_CTRL` /
//!   `REG_FWHW_TXQ_CTRL + 2` dance, the reserved-page packet upload
//!   ([`super::rsvd_page::set_fw_rsvdpagepkt`]) between the two beacon
//!   halves, and the join-bss H2C command.
//! - `rtl92d_set_qos` is `rtl92d_dm_init_edca_turbo` only (software
//!   state; [`edca_turbo_init`]); the `REG_EDCA_BE_PARAM` turbo write
//!   lives in the DM watchdog (`rtl92d_dm_check_edca_turbo`), a later
//!   lane. No fixed BK/VI/VO EDCA rows are written on this family.

use super::h2c::{self, Mailbox};
use super::mac::{
    REG_AGGLEN_LMT, REG_AMPDU_MIN_SPACE, REG_ATIMWND, REG_BCN_CTRL, REG_BCN_MAX_ERR,
    REG_FWHW_TXQ_CTRL, REG_HIMR, REG_HIMRE, REG_INIRTS_RATE_SEL, REG_INT_MIG, REG_MAC_SPEC_SIFS,
    REG_RCR, REG_RL, REG_RRSR, REG_SIFS_CTX, REG_SIFS_TRX, REG_SLOT, REG_SPEC_SIFS,
    REG_TBTT_PROHIBIT,
};
use super::power::REG_CR;
use super::{ampdu_factor_base, MacPhyMode};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `MSR` (`REG_CR + 2`).
pub const REG_MSR: u16 = REG_CR + 2;
pub const REG_BCNTCFG: u16 = 0x0510;
pub const REG_BCN_INTERVAL: u16 = 0x0554;
pub const REG_DUAL_TSF_RST: u16 = 0x0553;
pub const REG_RXTSF_OFFSET_CCK: u16 = 0x055e;
pub const REG_RXTSF_OFFSET_OFDM: u16 = 0x055f;
pub const REG_TSFTR: u16 = 0x0560;
pub const REG_ACMHWCTRL: u16 = 0x05c0;
pub const REG_BSSID: u16 = 0x0618;
pub const REG_RESP_SIFS_OFDM: u16 = 0x063e;
pub const REG_BCN_PSR_RPT: u16 = 0x06a8;

/// `MSR_*` (`rtl8192d/reg.h`).
pub const MSR_NOLINK: u8 = 0x00;
pub const MSR_ADHOC: u8 = 0x01;
pub const MSR_INFRA: u8 = 0x02;
pub const MSR_AP: u8 = 0x03;

/// `RCR_CBSSID_DATA` / `RCR_CBSSID_BCN`.
pub const RCR_CBSSID_DATA: u32 = 1 << 6;
pub const RCR_CBSSID_BCN: u32 = 1 << 7;

/// `REG_BCN_CTRL` reset value (`_rtl92de_hw_configure`).
pub const BCN_CTRL_INIT: u8 = 0x1f;

/// `RETRY_LIMIT_*_SHIFT`.
pub const RETRY_LIMIT_SHORT_SHIFT: u8 = 8;
pub const RETRY_LIMIT_LONG_SHIFT: u8 = 0;

/// `ACMH` bits (`rtl8192d/reg.h`).
pub const ACMHW_HWEN: u8 = 1 << 0;
pub const ACMHW_BEQEN: u8 = 1 << 1;
pub const ACMHW_VIQEN: u8 = 1 << 2;
pub const ACMHW_VOQEN: u8 = 1 << 3;

/// `AC0_BE` / `AC1_BK` / `AC2_VI` / `AC3_VO` (`wifi.h`).
pub const AC_BE: u8 = 0;
pub const AC_BK: u8 = 1;
pub const AC_VI: u8 = 2;
pub const AC_VO: u8 = 3;

/// `RT_AC_INT_MASKS` (`rtl8192d/def.h`): VIDOK | VODOK | BEDOK | BKDOK.
pub const RT_AC_INT_MASKS: u32 = (1 << 2) | (1 << 1) | (1 << 3) | (1 << 4);

/// `REG_MAC_PHY_CTRL_NORMAL` (`rtl8192de.rs`).
pub const REG_MAC_PHY_CTRL_NORMAL: u16 = super::REG_MAC_PHY_CTRL_NORMAL;

/// The cached `REG_BCN_CTRL` byte (`rtlpci->reg_bcn_ctrl_val`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BcnCtrl(pub u8);

impl Default for BcnCtrl {
    fn default() -> Self {
        Self(BCN_CTRL_INIT)
    }
}

impl BcnCtrl {
    /// `_rtl92de_set_bcn_ctrl_reg`: set bits, clear bits, write back.
    pub fn set(&mut self, io: &impl Io, set_bits: u8, clear_bits: u8) -> Result<(), Error> {
        self.0 |= set_bits;
        self.0 &= !clear_bits;
        io.write8(REG_BCN_CTRL, self.0)?;
        Ok(())
    }
}

/// `rtl92d_stop_tx_beacon` (`rtl8192d/hw_common.c`).
pub fn stop_tx_beacon(io: &impl Io) -> Result<(), Error> {
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    io.write8(REG_BCN_MAX_ERR, 0xff)?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0x64)?;
    let tbtt = io.read8(REG_TBTT_PROHIBIT + 2)?;
    Ok(io.write8(REG_TBTT_PROHIBIT + 2, tbtt & !(1 << 0))?)
}

/// `rtl92d_resume_tx_beacon` (`rtl8192d/hw_common.c`).
pub fn resume_tx_beacon(io: &impl Io) -> Result<(), Error> {
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq | (1 << 6))?;
    io.write8(REG_BCN_MAX_ERR, 0x0a)?;
    io.write8(REG_TBTT_PROHIBIT + 1, 0xff)?;
    let tbtt = io.read8(REG_TBTT_PROHIBIT + 2)?;
    Ok(io.write8(REG_TBTT_PROHIBIT + 2, tbtt | (1 << 0))?)
}

/// `nl80211_iftype` values `_rtl92de_set_media_status` handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Unspecified,
    Station,
    Adhoc,
    Ap,
}

/// `_rtl92de_set_media_status` for a station (`linked` = `link_state
/// \>= MAC80211_LINKED`) or `NL80211_IFTYPE_UNSPECIFIED` (`linked`
/// false). LED control is not composed.
pub fn set_media_status(io: &impl Io, bcn: &mut BcnCtrl, kind: MediaKind) -> Result<(), Error> {
    let msr = io.read8(REG_MSR)? & 0xfc;
    let (mode, ap) = match kind {
        MediaKind::Unspecified => {
            stop_tx_beacon(io)?;
            bcn.set(io, 0, 1 << 1)?;
            (MSR_NOLINK, false)
        }
        MediaKind::Station => {
            stop_tx_beacon(io)?;
            bcn.set(io, 0, 1 << 1)?;
            (MSR_INFRA, false)
        }
        MediaKind::Adhoc => {
            resume_tx_beacon(io)?;
            bcn.set(io, 1 << 1, 0)?;
            (MSR_ADHOC, false)
        }
        MediaKind::Ap => {
            resume_tx_beacon(io)?;
            bcn.set(io, 1 << 1, 0)?;
            (MSR_AP, true)
        }
    };
    io.write8(REG_MSR, msr | mode)?;
    Ok(io.write8(REG_BCNTCFG + 1, if ap { 0x00 } else { 0x66 })?)
}

/// `rtl92de_set_check_bssid` over the cached `rtlpci->receive_config`
/// (the caller guarantees `rf_on`: the owner is running with the radio
/// on). `HW_VAR_RCR` writes the register and the cache.
pub fn set_check_bssid(
    io: &impl Io,
    receive_config: &mut u32,
    bcn: &mut BcnCtrl,
    check: bool,
    rf_on: bool,
) -> Result<(), Error> {
    if !rf_on {
        return Ok(());
    }
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

/// `rtl92de_set_network_type`: media status, then check-BSSID on the
/// link state (never for AP).
pub fn set_network_type(
    io: &impl Io,
    receive_config: &mut u32,
    bcn: &mut BcnCtrl,
    kind: MediaKind,
    linked: bool,
    rf_on: bool,
) -> Result<(), Error> {
    set_media_status(io, bcn, kind)?;
    if kind != MediaKind::Ap {
        set_check_bssid(io, receive_config, bcn, linked, rf_on)?;
    }
    Ok(())
}

/// `HW_VAR_BSSID`.
pub fn set_bssid(io: &impl Io, bssid: [u8; 6]) -> Result<(), Error> {
    for (index, value) in bssid.into_iter().enumerate() {
        io.write8(REG_BSSID + index as u16, value)?;
    }
    Ok(())
}

/// `HW_VAR_BASIC_RATE`: `(rates & 0x15f)` with the Cisco `0x01` rule,
/// and the index of its highest set bit (Linux's shift loop: 0 for an
/// empty set). Returns `(rate_cfg, rate_index)`.
pub fn basic_rate(rates: u16, cisco: bool) -> (u16, u8) {
    let mut cfg = rates & 0x15f;
    if cisco && (cfg & 0x150) == 0 {
        cfg |= 0x01;
    }
    let mut index = 0u8;
    let mut rest = cfg;
    while rest > 0x1 {
        rest >>= 1;
        index += 1;
    }
    (cfg, index)
}

/// `HW_VAR_BASIC_RATE` write: RRSR low bytes, then
/// `REG_INIRTS_RATE_SEL` only when the firmware version is above
/// `0xe` (`rtlhal->fw_version`).
pub fn set_basic_rate(io: &impl Io, rates: u16, cisco: bool, fw_version: u16) -> Result<(), Error> {
    let (cfg, index) = basic_rate(rates, cisco);
    let [lo, hi] = cfg.to_le_bytes();
    io.write8(REG_RRSR, lo)?;
    io.write8(REG_RRSR + 1, hi)?;
    if fw_version > 0xe {
        io.write8(REG_INIRTS_RATE_SEL, index)?;
    }
    Ok(())
}

/// `HW_VAR_AID`: `REG_BCN_PSR_RPT` keeps its top two bits, the
/// association ID fills the rest (word access, as Linux).
pub fn set_aid(io: &impl Io, assoc_id: u16) -> Result<(), Error> {
    let lo = io.read8(REG_BCN_PSR_RPT)?;
    let hi = io.read8(REG_BCN_PSR_RPT + 1)?;
    let v = (u16::from_le_bytes([lo, hi]) & 0xc000) | assoc_id;
    io.write16(REG_BCN_PSR_RPT, v)?;
    Ok(())
}

/// `HW_VAR_RETRY_LIMIT`: `REG_RL = limit << 8 | limit`.
pub fn set_retry_limit(io: &impl Io, limit: u8) -> Result<(), Error> {
    io.write16(
        REG_RL,
        (u16::from(limit) << RETRY_LIMIT_SHORT_SHIFT)
            | (u16::from(limit) << RETRY_LIMIT_LONG_SHIFT),
    )?;
    Ok(())
}

/// `HW_VAR_DUAL_TSF_RST`: `REG_DUAL_TSF_RST = BIT(0) | BIT(1)`.
pub fn dual_tsf_rst(io: &impl Io) -> Result<(), Error> {
    io.write8(REG_DUAL_TSF_RST, (1 << 0) | (1 << 1))?;
    Ok(())
}

/// `HW_VAR_AMPDU_MIN_SPACE`: writes only for a spacing `<= 7`;
/// returns the new `min_space_cfg`.
pub fn ampdu_min_space(io: &impl Io, min_space_cfg: u8, spacing: u8) -> Result<u8, Error> {
    if spacing <= 7 {
        let next = (min_space_cfg & 0xf8) | spacing;
        io.write8(REG_AMPDU_MIN_SPACE, next)?;
        Ok(next)
    } else {
        Ok(min_space_cfg)
    }
}

/// `HW_VAR_SHORTGI_DENSITY`: `min_space_cfg = minspace_cfg |
/// (density << 3)`; returns the new value.
pub fn shortgi_density(io: &impl Io, minspace_cfg: u8, density: u8) -> Result<u8, Error> {
    let next = minspace_cfg | (density << 3);
    io.write8(REG_AMPDU_MIN_SPACE, next)?;
    Ok(next)
}

/// `HW_VAR_AMPDU_FACTOR`: the mode's AMPDU-factor base with each
/// byte's nibbles clamped to `factor` (`factor <= 3` only, else no
/// write). Returns the written word, or `None` when refused.
pub fn ampdu_factor(io: &impl Io, mode: MacPhyMode, factor: u8) -> Result<Option<u32>, Error> {
    if factor > 3 {
        return Ok(None);
    }
    let mut word = ampdu_factor_base(mode);
    let limit = (1u32 << (factor + 2)).min(0xf) as u8;
    let mut bytes = word.to_le_bytes();
    for byte in bytes.iter_mut() {
        if (*byte & 0xf0) > (limit << 4) {
            *byte = (*byte & 0x0f) | (limit << 4);
        }
        if (*byte & 0x0f) > limit {
            *byte = (*byte & 0xf0) | limit;
        }
    }
    word = u32::from_le_bytes(bytes);
    io.write32(REG_AGGLEN_LMT, word)?;
    Ok(Some(word))
}

/// `HW_VAR_ACM_CTRL` value: `acm_ctrl | (acm_method == 2 ? 0x0 : 0x1)`,
/// then the per-AC enable bit set or cleared by `acm`. AC1_BK has no
/// bit and is refused, as in Linux.
pub fn acm_ctrl_value(current: u8, acm_method_sw: bool, acm: bool, e_aci: u8) -> Result<u8, Error> {
    let bit = match e_aci {
        AC_BE => ACMHW_BEQEN,
        AC_VI => ACMHW_VIQEN,
        AC_VO => ACMHW_VOQEN,
        _ => return Err(Error::State),
    };
    let mut ctrl = current | if acm_method_sw { 0x0 } else { 0x1 };
    if acm {
        ctrl |= bit;
    } else {
        ctrl &= !bit;
    }
    Ok(ctrl)
}

/// `HW_VAR_ACM_CTRL` write.
pub fn acm_ctrl(
    io: &impl Io,
    current: u8,
    acm_method_sw: bool,
    acm: bool,
    e_aci: u8,
) -> Result<(), Error> {
    let value = acm_ctrl_value(current, acm_method_sw, acm, e_aci)?;
    io.write8(REG_ACMHWCTRL, value)?;
    Ok(())
}

/// `rtl92d_dm_init_edca_turbo` (`rtl92d_set_qos`): software state only
/// — `current_turbo_edca` is cleared, no register is written.
pub fn edca_turbo_init() -> bool {
    false
}

/// `rtl92d_update_channel_access_setting`: `HW_VAR_SLOT_TIME` (the four
/// `HW_VAR_AC_PARAM` calls are no-ops on PCI, see the module note) and
/// `HW_VAR_SIFS` with `sifs_timer` `0x0a0a` (`!ht_enable`) / `0x1010`;
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

/// Rate-configuration inputs for [`configure_rates`]: the peer's
/// supported set and the basic set, the BSS capability and ERP octet,
/// HT enable and the programmed prime subcarrier, plus the firmware
/// version and Cisco flag for the basic-rate write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateConfig {
    /// Peer's supported rates (Linux passes `sta->supp_rates[0]`).
    pub rates: u16,
    /// Basic rates; must name 1 Mb/s (the 2.4 GHz
    /// `rate_control_send_low` rate) and only rates the RRSR mask keeps.
    pub basic: u16,
    /// BSS capability word (slot and ACK preamble source).
    pub capability: u16,
    /// BSS ERP octet, if an ERP element is present.
    pub erp: Option<u8>,
    /// HT enabled (`ht_enable`).
    pub ht: bool,
    /// Programmed prime subcarrier.
    pub prime_sc: u8,
    /// Firmware version for the basic-rate write.
    pub fw_version: u16,
    /// Cisco-compatibility flag for the basic-rate write.
    pub cisco: bool,
}

/// Authentication-time `BSS_CHANGED_BASIC_RATES` / ERP and the channel
/// access rows for a 2.4 GHz legacy-or-HT station (the BSSID is
/// [`set_bssid`]): RRSR and `INIRTS_RATE_SEL` ([`basic_rate`] of
/// `rates` — Linux passes `sta->supp_rates[0]`, the peer's supported
/// set), slot and ACK preamble from `ieee80211_handle_bss_capability`
/// of `capability` and the BSS ERP octet `erp` (9 us slot with the
/// short-slot bit 0x400, else 20; with an ERP element the preamble is
/// short unless Barker bit 2, else capability 0x20), SIFS (`ht` =
/// `ht_enable`), at the programmed `prime_sc`. `basic` must name
/// 1 Mb/s (the 2.4 GHz `rate_control_send_low` rate) and only rates
/// the RRSR mask keeps.
pub fn configure_rates(io: &impl Io, config: RateConfig) -> Result<(), Error> {
    let RateConfig {
        rates,
        basic,
        capability,
        erp,
        ht,
        prime_sc,
        fw_version,
        cisco,
    } = config;
    if rates & basic & 1 == 0 || basic & !0x15f != 0 || rates & !0xfff != 0 {
        return Err(Error::Packet);
    }
    set_basic_rate(io, rates, cisco, fw_version)?;
    let (short_preamble, short_slot) =
        crate::rtlwifi::rtl8192ee::station::erp_timing(capability, erp);
    channel_access(io, if short_slot { 9 } else { 20 }, ht)?;
    ack_preamble(io, prime_sc, short_preamble)
}

/// `HW_VAR_CORRECT_TSF` read (`rtl92d_get_hw_reg`): `REG_TSFTR` as a
/// `u64` (high dword first, as Linux reads it).
pub fn read_tsf(io: &impl Io) -> Result<u64, Error> {
    let hi = io.read32(REG_TSFTR + 4)?;
    let lo = io.read32(REG_TSFTR)?;
    Ok((u64::from(hi) << 32) | u64::from(lo))
}

/// `HW_VAR_CORRECT_TSF` write: stop/resume TX beacon around the TSF
/// write when `ibss`, with `REG_BCN_CTRL` BIT(3) cleared then set.
pub fn correct_tsf(io: &impl Io, bcn: &mut BcnCtrl, tsf: u64, ibss: bool) -> Result<(), Error> {
    if ibss {
        stop_tx_beacon(io)?;
    }
    bcn.set(io, 0, 1 << 3)?;
    io.write32(REG_TSFTR, tsf as u32)?;
    io.write32(REG_TSFTR + 4, (tsf >> 32) as u32)?;
    bcn.set(io, 1 << 3, 0)?;
    if ibss {
        resume_tx_beacon(io)?;
    }
    Ok(())
}

/// `HW_VAR_FWLPS_RF_ON` read (`rtl92d_get_hw_reg`): true when the
/// radio is off, else true only when `REG_RCR` bits 16–18 are clear.
pub fn fwlps_rf_on(rf_on: bool, rcr: u32) -> bool {
    if !rf_on {
        true
    } else {
        rcr & 0x0007_0000 == 0
    }
}

/// `HW_VAR_INT_MIGRATION`: `REG_INT_MIG = 0xfe000fa0` (25 ns * 0xfa0 =
/// 100 us for 0xf packets) or 0. Returns the new
/// `dm.interrupt_migration` state.
pub fn int_migration(io: &impl Io, enable: bool) -> Result<bool, Error> {
    io.write32(REG_INT_MIG, if enable { 0xfe00_0fa0 } else { 0 })?;
    Ok(enable)
}

/// `rtl92de_update_interrupt_mask`: `irq_mask[0]` add/remove, then
/// disable + enable interrupt with the live masks.
pub fn update_interrupt_mask(
    io: &impl Io,
    mask: &mut (u32, u32),
    add: u32,
    rm: u32,
) -> Result<(), Error> {
    if add != 0 {
        mask.0 |= add;
    }
    if rm != 0 {
        mask.0 &= !rm;
    }
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    io.write32(REG_HIMR, mask.0)?;
    Ok(io.write32(REG_HIMRE, mask.1)?)
}

/// `HW_VAR_INT_AC`: disable the four AC interrupts to gain CPU
/// utilization under heavy RX, else re-enable them.
pub fn int_ac(io: &impl Io, mask: &mut (u32, u32), disable: bool) -> Result<(), Error> {
    if disable {
        update_interrupt_mask(io, mask, 0, RT_AC_INT_MASKS)
    } else {
        update_interrupt_mask(io, mask, RT_AC_INT_MASKS, 0)
    }
}

/// `rtl92de_set_beacon_related_registers`: interrupts off, ATIM window
/// 2, beacon interval, `REG_BCNTCFG = 0x660f`, RX TSF offsets (OFDM
/// `0x30` on 5 GHz, `0x20` else), `0x606 = 0x30`.
pub fn set_beacon_related_registers(
    io: &impl Io,
    beacon_interval: u16,
    band_5g: bool,
) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    io.write16(REG_ATIMWND, 2)?;
    io.write16(REG_BCN_INTERVAL, beacon_interval)?;
    io.write16(REG_BCNTCFG, 0x660f)?;
    io.write8(REG_RXTSF_OFFSET_CCK, 0x20)?;
    io.write8(REG_RXTSF_OFFSET_OFDM, if band_5g { 0x30 } else { 0x20 })?;
    Ok(io.write8(0x0606, 0x30)?)
}

/// `rtl92de_set_beacon_interval`: interrupts off, interval, on.
pub fn set_beacon_interval(
    io: &impl Io,
    mask: (u32, u32),
    beacon_interval: u16,
) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    io.write16(REG_BCN_INTERVAL, beacon_interval)?;
    io.write32(REG_HIMR, mask.0)?;
    Ok(io.write32(REG_HIMRE, mask.1)?)
}

/// `rtl92de_suspend`: save the `REG_MAC_PHY_CTRL_NORMAL` byte.
pub fn suspend(io: &impl Io) -> Result<u8, Error> {
    Ok(io.read8(REG_MAC_PHY_CTRL_NORMAL)?)
}

/// `rtl92de_resume`: restore the saved byte.
pub fn resume(io: &impl Io, saved: u8) -> Result<(), Error> {
    io.write8(REG_MAC_PHY_CTRL_NORMAL, saved)?;
    Ok(())
}

/// `HW_VAR_H2C_FW_JOINBSSRPT` (`rtl92de_set_hw_reg`) + the join-bss
/// H2C command. On connect: the AID write, `REG_CR + 1` BIT(0),
/// `REG_BCN_CTRL` BIT(3) clear / BIT(4) set, `REG_FWHW_TXQ_CTRL + 2`
/// BIT(6) clear (restored afterwards when it was set), then the
/// reserved-page packet upload ([`super::rsvd_page::set_fw_rsvdpagepkt`]:
/// patched pages into the caller's buffer, beacon descriptor 0, the
/// beacon doorbell, the `H2C_RSVDPAGE` location command), then BIT(3)
/// set / BIT(4) clear and `REG_CR + 1` BIT(0) clear. The H2C report is
/// sent after the upload.
pub async fn join_bss_report(
    io: &impl Io,
    mailbox: &mut Mailbox,
    bcn: &mut BcnCtrl,
    assoc_id: u16,
    mstatus: u8,
    rf_on: bool,
    upload: super::rsvd_page::Upload<'_>,
) -> Result<(), Error> {
    if mstatus == h2c::MEDIA_CONNECT {
        set_aid(io, assoc_id)?;
        let tmp_regcr = io.read8(REG_CR + 1)?;
        io.write8(REG_CR + 1, tmp_regcr | (1 << 0))?;
        bcn.set(io, 0, 1 << 3)?;
        bcn.set(io, 1 << 4, 0)?;
        let tmp_reg422 = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
        let recover = tmp_reg422 & (1 << 6) != 0;
        io.write8(REG_FWHW_TXQ_CTRL + 2, tmp_reg422 & !(1 << 6))?;
        super::rsvd_page::set_fw_rsvdpagepkt(io, mailbox, upload, assoc_id, rf_on).await?;
        bcn.set(io, 1 << 3, 0)?;
        bcn.set(io, 0, 1 << 4)?;
        if recover {
            io.write8(REG_FWHW_TXQ_CTRL + 2, tmp_reg422)?;
        }
        io.write8(REG_CR + 1, tmp_regcr & !(1 << 0))?;
    }
    h2c::joinbss(mailbox, io, mstatus, rf_on).await
}
