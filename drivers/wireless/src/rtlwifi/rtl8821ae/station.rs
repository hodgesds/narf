// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE station MAC registers for the retained packet owner.
//!
//! Exact `rtl8821ae/hw.c`: `_rtl8821ae_set_media_status` (STATION),
//! `rtl8821ae_set_network_type` / `rtl8821ae_set_check_bssid`,
//! `_rtl8821ae_stop_tx_beacon`, `_rtl8821ae_enable_bcn_sub_func`,
//! `rtl8821ae_set_hw_reg` `HW_VAR_{BSSID,BASIC_RATE,SLOT_TIME,SIFS,R2T_SIFS,
//! ACK_PREAMBLE,AID}`, `rtl8821ae_update_channel_access_setting`,
//! `rtl8821ae_set_qos` (the fixed BK/VI/VO EDCA rows mac80211's `conf_tx`
//! triggers for every AC) and the `rtl8821ae_set_fw_rsvdpagepkt` page bodies.
//!
//! `HW_VAR_AC_PARAM` only calls `rtl8821ae_dm_init_edca_turbo` (software
//! state) and skips `HW_VAR_ACM_CTRL` because `pci.c` sets
//! `acm_method = EACMWAY2_SW`; no register write results.

use super::h2c;
use super::mac::ReceiveConfig;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const MSR: u16 = 0x0102;
pub const MSR_INFRA: u8 = 0x02;
pub const REG_TDECTRL: u16 = 0x0208;
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
pub const REG_TRXPTCL_CTL: u16 = 0x0668;
pub const REG_CAMCMD: u16 = 0x0670;
pub const REG_BCN_PSR_RPT: u16 = 0x06a8;

/// Reserved-page indices (`fw.c` `*_PG`, 256-byte pages).
pub const PSPOLL_PG: u8 = 1;
pub const NULL_PG: u8 = 2;
pub const QOSNULL_PG: u8 = 3;
pub const BT_QOSNULL_PG: u8 = 4;
/// `256 * (BT_QOSNULL_PG + 1) - 40`: the `!dl_whole_packets` upload length.
pub const RSVD_PAGE_LEN: usize = 256 * (BT_QOSNULL_PG as usize + 1) - 40;

fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    Ok(())
}

/// `_rtl8821ae_stop_tx_beacon`.
pub fn stop_tx_beacon(io: &impl Io) -> Result<(), Error> {
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    byte(io, REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
    byte(io, REG_TBTT_PROHIBIT + 1, 0x64)?;
    let prohibit = io.read8(REG_TBTT_PROHIBIT + 2)?;
    byte(io, REG_TBTT_PROHIBIT + 2, prohibit & !1)
}

/// `rtl8821ae_set_network_type(NL80211_IFTYPE_STATION)`:
/// `_rtl8821ae_set_media_status` (REG_BCN_CTRL dword cleared without
/// touching the cached value, stop TX beacon, enable the beacon
/// sub-function, MSR INFRA, BCNTCFG+1 = 0x66; LED control is omitted),
/// then `rtl8821ae_set_check_bssid(linked)`.
pub fn network_type_station(
    io: &impl Io,
    receive: &mut ReceiveConfig,
    linked: bool,
) -> Result<(), Error> {
    let msr = io.read8(MSR)? & 0xfc;
    io.write32(h2c::REG_BCN_CTRL, 0)?;
    stop_tx_beacon(io)?;
    h2c::set_bcn_ctrl(io, &mut receive.bcn_ctrl, 0, 1 << 1)?;
    byte(io, MSR, msr | MSR_INFRA)?;
    byte(io, REG_BCNTCFG + 1, 0x66)?;
    receive.set_check_bssid(io, linked)
}

/// `HW_VAR_BSSID`.
pub fn set_bssid(io: &impl Io, bssid: [u8; 6]) -> Result<(), Error> {
    for (index, value) in bssid.into_iter().enumerate() {
        byte(io, REG_BSSID + index as u16, value)?;
    }
    Ok(())
}

/// `rtl8821ae_set_qos` for AC1_BK, AC0_BE (no write), AC2_VI, AC3_VO.
pub fn set_qos_all(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_EDCA_BK_PARAM, 0xa44f)?;
    io.write32(REG_EDCA_VI_PARAM, 0x5e_4322)?;
    io.write32(REG_EDCA_VO_PARAM, 0x2f_3222)?;
    Ok(())
}

/// `HW_VAR_SIFS` with `val[0]`.
fn sifs(io: &impl Io, value: u8) -> Result<(), Error> {
    for reg in [
        REG_SIFS_CTX + 1,
        REG_SIFS_TRX + 1,
        REG_SPEC_SIFS + 1,
        REG_MAC_SPEC_SIFS + 1,
        REG_RESP_SIFS_OFDM + 1,
        REG_RESP_SIFS_OFDM,
    ] {
        byte(io, reg, value)?;
    }
    Ok(())
}

/// Legacy station association registers: `HW_VAR_BASIC_RATE`
/// (`RRSR = supp_rates & 0x15f`), `rtl8821ae_update_channel_access_setting`
/// (`HW_VAR_SLOT_TIME` + four `HW_VAR_AC_PARAM`, `HW_VAR_SIFS` 0x0a for
/// `WIRELESS_MODE_G` else 0x0e, `HW_VAR_R2T_SIFS` 0x0a), the conf_tx
/// `set_qos` rows and `HW_VAR_ACK_PREAMBLE`. `rates` is the legacy
/// intersection (bit 0 = 1 Mb/s), `basic` the BSS basic set; `ht` is an HT
/// peer (`mac->mode = WIRELESS_MODE_N_24G`, so SIFS 0x0e).
pub fn configure_rates(
    io: &impl Io,
    rates: u16,
    basic: u16,
    capability: u16,
    ht: bool,
) -> Result<(), Error> {
    if rates & 1 == 0 || basic & 1 == 0 || basic & !0x15f != 0 || rates & !0xfff != 0 {
        return Err(Error::Packet);
    }
    io.write16(REG_RRSR, basic & 0x15f)?;
    let slot = if capability & 0x400 != 0 { 9 } else { 20 };
    byte(io, REG_SLOT, slot)?;
    // core.c sets mac->mode WIRELESS_MODE_B for supp_rates <= 0xf.
    let mode_g = !ht && rates > 0xf;
    sifs(io, if mode_g { 0x0a } else { 0x0e })?;
    byte(io, REG_RESP_SIFS_OFDM + 1, 0x0a)?;
    set_qos_all(io)?;
    let preamble = io.read8(REG_TRXPTCL_CTL + 2)?;
    byte(
        io,
        REG_TRXPTCL_CTL + 2,
        if capability & 0x20 != 0 {
            preamble | 2
        } else {
            preamble & !2
        },
    )
}

/// `HW_VAR_AID` (`REG_BCN_PSR_RPT[13:0]`).
pub fn set_aid(io: &impl Io, aid: u16) -> Result<(), Error> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let previous = u16::from_le_bytes([io.read8(REG_BCN_PSR_RPT)?, io.read8(REG_BCN_PSR_RPT + 1)?]);
    io.write16(REG_BCN_PSR_RPT, (previous & 0xc000) | aid)?;
    Ok(())
}

/// `rtl8821ae_set_fw_rsvdpagepkt(hw, false, false)` page bodies: beacon
/// A2/A3, PS-Poll AID/BSSID/TA, Null, QoS-Null and BT-QoS-Null A1/A2/A3,
/// truncated to the uploaded [`RSVD_PAGE_LEN`].
pub fn reserved_pages(
    own: [u8; 6],
    bssid: [u8; 6],
    aid: u16,
) -> Result<[u8; RSVD_PAGE_LEN], Error> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let mut bytes = [0u8; RSVD_PAGE_LEN];
    bytes.copy_from_slice(&super::rsvd_page::TEMPLATE[..RSVD_PAGE_LEN]);
    bytes[10..16].copy_from_slice(&own);
    bytes[16..22].copy_from_slice(&bssid);
    let at = usize::from(PSPOLL_PG) * 256;
    bytes[at + 2..at + 4].copy_from_slice(&(aid | 0xc000).to_le_bytes());
    bytes[at + 4..at + 10].copy_from_slice(&bssid);
    bytes[at + 10..at + 16].copy_from_slice(&own);
    for page in [NULL_PG, QOSNULL_PG, BT_QOSNULL_PG] {
        let at = usize::from(page) * 256;
        bytes[at + 4..at + 10].copy_from_slice(&bssid);
        bytes[at + 10..at + 16].copy_from_slice(&own);
        bytes[at + 16..at + 22].copy_from_slice(&bssid);
    }
    Ok(bytes)
}

/// `rtl8821ae_tx_fill_cmddesc` for a reserved-page body at `address`:
/// FIRST/LAST, `pkt_size`, offset 40, USE_RATE + `DESC_RATE1M` + DISFB,
/// BW 0, HWSEQ_EN, `QSLT_BEACON`, buffer size/address, MACID 0. Returns
/// descriptor dwords 0..=10 with OWN clear.
pub fn command_descriptor(length: u16, address: u32) -> [u32; 11] {
    let mut dw = [0u32; 11];
    dw[0] = u32::from(length) | (40 << 16) | (1 << 26) | (1 << 27);
    dw[1] = u32::from(super::trx::QSLT_BEACON) << 8;
    dw[3] = (1 << 8) | (1 << 10);
    dw[7] = u32::from(length);
    dw[8] = 1 << 15;
    dw[10] = address;
    dw
}
