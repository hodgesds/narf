// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! C21/C22 VHT SU and MU beamformee (`bf.c`), bound only on an N2xV VHT80
//! association whose AP is an SU (or MU) beamformer.
//!
//! Linux 7.3-rc4 sources:
//! - `main.c::rtw_init_vht_cap`: SU and MU beamformee with
//!   `hal.bfee_sts_cap` 3 (four NDP space-time streams).
//! - `mac80211.c::rtw_ops_bss_info_changed` (`BSS_CHANGED_ASSOC`):
//!   `rtw_bf_assoc` on association, `rtw_bf_disassoc` on loss;
//!   `rtw_bf_assoc` prefers MU when the local cap and the AP's
//!   `IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE` agree (`p_aid` from the
//!   BSSID, `aid` the association ID), else binds SU when the AP's
//!   `IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE` is set, `sound_dim` from the
//!   AP's sounding-dimensions field, first free SU register (index 0).
//! - `bf.c::rtw_bf_enable_bfee_mu` (`rtw_bf_init_bfer_entry_mu`,
//!   `rtw_bf_cfg_sounding` at 6M, RX filter maps) and
//!   `rtw_bf_remove_bfee_mu` (`rtw_bf_del_bfer_entry_mu`, then
//!   `rtw_bf_del_sounding` since no SU/MU count remains on the single vif);
//!   both chips use these generic paths (`rtw88{21,22}c_bf_config_bfee_mu`).
//! - `BSS_CHANGED_MU_GROUPS` -> `bf.c::rtw_bf_set_gid_table` ->
//!   `rtw_bf_cfg_mu_bfee`, driven by mac80211
//!   `vht.c::ieee80211_process_mu_groups` (see [`gid_management`]).
//! - `bf.c::rtw_bf_phy_init` (chip MAC/PHY init on C21/C22; here performed
//!   once before the first SU enable, since the retained init does not).
//! - `bf.c::rtw_bf_enable_bfee_su` / `rtw_bf_remove_bfee_su`;
//!   `rtw8822c.c::rtw8822c_bf_enable_bfee_su` additionally sets
//!   `BIT_WMAC_USE_NDPARATE`, CSI_RSC 0, clears the AP-mode bit12 and writes
//!   `REG_CSI_RRSR` 0x550; `rtw8821c.c` uses the generic path.
use super::firmware_transport::{Error, Io};

const REG_TXBF_CTRL: u16 = 0x042c;
const REG_NDPA_OPT_CTRL: u16 = 0x045f;
const REG_BBPSF_CTRL: u16 = 0x06dc;
const REG_ASSOCIATED_BFMER0_INFO: u16 = 0x06e4;
const REG_TX_CSI_RPT_PARAM_BW20: u16 = 0x06f4;
const REG_SND_PTCL_CTRL: u16 = 0x0718;
const REG_RXFLTMAP4: u16 = 0x068a;
const REG_RXFLTMAP0: u16 = 0x06a0;
const REG_RXFLTMAP1: u16 = 0x06a2;
const REG_ASSOCIATED_BFMER0_INFO_HI: u16 = REG_ASSOCIATED_BFMER0_INFO + 4;
const REG_MU_TX_CTL: u16 = 0x14c0;
const REG_MU_STA_GID_VLD: u16 = 0x14c4;
const REG_MU_STA_USER_POS_INFO: u16 = 0x14c8;
const REG_CSI_RRSR: u16 = 0x1678;
const REG_WMAC_MU_BF_OPTION: u16 = 0x167c;
const REG_WMAC_MU_BF_CTL: u16 = 0x1680;
const BIT_MASK_BEAMFORM: u8 = 0x9f;
const RTW_SND_CTRL_SOUNDING: u8 = 0x9b;
const RTW_SND_CTRL_REMOVE: u8 = 0x98;
const RTW_NDP_RX_STANDBY_TIME: u8 = 0x70;
/// `rtw_bf_cfg_sounding` NDP RX standby time.
const MU_NDP_RX_STANDBY_TIME: u8 = 0x26;
const BIT_WMAC_USE_NDPARATE: u32 = 1 << 30;
const BIT_RXFLTMAP0_ACTIONNOACK: u16 = 1 << 14;
const BIT_RXFLTMAP1_BF: u16 = 1 << 4 | 1 << 5;
const BIT_RXFLTMAP1_BF_REPORT_POLL: u16 = 1 << 4;
const BIT_RXFLTMAP4_BF_REPORT_POLL: u8 = 1 << 4;
const BIT_MASK_R_MU_TABLE_VALID: u8 = 0x3f;
const BIT_EN_MU_MIMO: u8 = 1 << 7;
const DESC_RATE6M: u32 = 4;

/// `hal.bfee_sts_cap` 3: VHT Beamformee STS field 3, four NDP STS.
pub(super) const BFEE_STS: u8 = 4;

/// `struct rtw_bfee::role` for a bound entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// SU register index 0; raw AP sounding-dimensions field (`nr_index`).
    Su { sound_dim: u8 },
    /// The single MU beamformer entry (`bfer_mu_max_num` 1).
    Mu {
        /// `(bssid[5] << 1) | (bssid[4] >> 7)`.
        p_aid: u16,
        /// `vif->cfg.aid & 0xfff` (`param.my_aid`).
        aid: u16,
    },
}

/// One beamformer entry (`struct rtw_bfee`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Bfee {
    pub(super) mac: [u8; 6],
    pub(super) role: Role,
    /// `hweight8(hal.antenna_rx) - 1`: 1 on 2R C22, 0 on 1R C21.
    pub(super) nc_index: u8,
}
fn nc_index(did: u16) -> Option<u8> {
    match did {
        0xc822 => Some(1),
        0xc821 => Some(0),
        _ => None,
    }
}
impl Bfee {
    /// `rtw_bf_assoc` SU branch for an AP advertising `sounding` (1..=8)
    /// sounding dimensions.
    pub(super) fn su(did: u16, bssid: [u8; 6], sounding: u8) -> Option<Self> {
        let nc_index = nc_index(did)?;
        (1..=8).contains(&sounding).then_some(Self {
            mac: bssid,
            role: Role::Su {
                sound_dim: sounding - 1,
            },
            nc_index,
        })
    }
    /// `rtw_bf_assoc` MU branch for association ID `aid` (1..=2007).
    pub(super) fn mu(did: u16, bssid: [u8; 6], aid: u16) -> Option<Self> {
        let nc_index = nc_index(did)?;
        (1..=2007).contains(&aid).then_some(Self {
            mac: bssid,
            role: Role::Mu {
                p_aid: u16::from(bssid[5]) << 1 | u16::from(bssid[4] >> 7),
                aid: aid & 0xfff,
            },
            nc_index,
        })
    }
    pub(super) fn is_mu(self) -> bool {
        matches!(self.role, Role::Mu { .. })
    }
    /// `csi_param`, codebook 1 (802.11ac), grouping 0: SU coefficient
    /// size 3 with the AP's `nr_index`; MU coefficient size 0, `nr_index` 1.
    pub(super) fn csi_param(self) -> u16 {
        let (coef, nr) = match self.role {
            Role::Su { sound_dim } => (3, sound_dim),
            Role::Mu { .. } => (0, 1),
        };
        coef << 10 | 1 << 8 | u16::from(nr) << 3 | u16::from(self.nc_index)
    }
}

fn mask8(io: &mut impl Io, reg: u16, bits: u8, value: u8) -> Result<(), Error> {
    let old = io.read8(reg)?;
    io.write8(reg, old & !bits | value & bits)
}

/// `rtw_bf_phy_init`.
pub(super) fn phy_init(io: &mut impl Io) -> Result<(), Error> {
    let mut mu = io.read32(REG_MU_TX_CTL)?;
    mu |= 1 << 16;
    mu = mu & !(0xf << 12) | 0xa << 12;
    mu &= !(1 << 7);
    mu &= !0x3f;
    io.write32(REG_MU_TX_CTL, mu)?;
    io.write8(REG_WMAC_MU_BF_OPTION, 3 << 4 | 1 << 6)?;
    io.write16(REG_WMAC_MU_BF_CTL, 0)?;
    let txbf = io.read32(REG_TXBF_CTRL)?;
    io.write32(REG_TXBF_CTRL, txbf | 1 << 30)?;
    io.write8(REG_NDPA_OPT_CTRL, 0x10)?;
    super::radio::mask(io, REG_BBPSF_CTRL, 0x3f << 24, DESC_RATE6M)?;
    if io.read32(REG_MU_TX_CTL)? != mu
        || io.read8(REG_WMAC_MU_BF_OPTION)? != 0x70
        || io.read8(REG_NDPA_OPT_CTRL)? != 0x10
        || io.read32(REG_BBPSF_CTRL)? >> 24 & 0x3f != DESC_RATE6M
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw_chip_config_bfee(.., true)` for an SU entry at register index 0.
pub(super) fn enable_su(io: &mut impl Io, did: u16, b: Bfee) -> Result<(), Error> {
    mask8(
        io,
        REG_SND_PTCL_CTRL,
        BIT_MASK_BEAMFORM,
        RTW_SND_CTRL_SOUNDING,
    )?;
    for (i, byte) in b.mac.into_iter().enumerate() {
        io.write8(REG_ASSOCIATED_BFMER0_INFO + i as u16, byte)?;
    }
    io.write16(REG_TX_CSI_RPT_PARAM_BW20, b.csi_param())?;
    io.write8(REG_SND_PTCL_CTRL + 3, RTW_NDP_RX_STANDBY_TIME)?;
    if did == 0xc822 {
        // Station net type: AP-mode bit12 clear; CSI_RSC 0 is ORed in
        // (`csi_rsc << 13`), leaving bits 13..14 as they were.
        let psf = io.read32(REG_BBPSF_CTRL)? | BIT_WMAC_USE_NDPARATE;
        io.write32(REG_BBPSF_CTRL, psf & !(1 << 12))?;
        io.write32(REG_CSI_RRSR, 0x550)?;
    }
    readback(io, did, b)
}

/// The enabled entry is still programmed (SU or MU per `b.role`).
pub(super) fn readback(io: &mut impl Io, did: u16, b: Bfee) -> Result<(), Error> {
    if b.is_mu() {
        return readback_mu(io, did, b);
    }
    let mut mac = [0; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = io.read8(REG_ASSOCIATED_BFMER0_INFO + i as u16)?;
    }
    if io.read8(REG_SND_PTCL_CTRL)? & BIT_MASK_BEAMFORM != RTW_SND_CTRL_SOUNDING
        || mac != b.mac
        || io.read16(REG_TX_CSI_RPT_PARAM_BW20)? != b.csi_param()
        || io.read8(REG_SND_PTCL_CTRL + 3)? != RTW_NDP_RX_STANDBY_TIME
        || did == 0xc822
            && (io.read32(REG_BBPSF_CTRL)? & (BIT_WMAC_USE_NDPARATE | 1 << 12)
                != BIT_WMAC_USE_NDPARATE
                || io.read32(REG_CSI_RRSR)? != 0x550)
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw_bf_disassoc` -> `rtw_chip_config_bfee(.., false)` for `b.role`.
pub(super) fn remove(io: &mut impl Io, b: Bfee) -> Result<(), Error> {
    if b.is_mu() {
        remove_mu(io)
    } else {
        remove_su(io)
    }
}

/// `rtw_bf_remove_bfee_su` for register index 0 (`rtw_bf_disassoc`).
pub(super) fn remove_su(io: &mut impl Io) -> Result<(), Error> {
    mask8(
        io,
        REG_SND_PTCL_CTRL,
        BIT_MASK_BEAMFORM,
        RTW_SND_CTRL_REMOVE,
    )?;
    io.write32(REG_ASSOCIATED_BFMER0_INFO, 0)?;
    io.write16(REG_ASSOCIATED_BFMER0_INFO + 4, 0)?;
    io.write16(REG_TX_CSI_RPT_PARAM_BW20, 0)
}

/// `rtw_chip_config_bfee(.., true)` for the MU entry:
/// `rtw_bf_enable_bfee_mu`.
///
/// RX filter maps: Linux rewrites `REG_RXFLTMAP1` from `hal.rxfltmap1`,
/// the value its chip `mac_init` wrote (C22 0xffff, C21 0x0fff). The
/// retained C21 init is followed by the source MAC table (0x6a2/0x6a3 =
/// 0xff), so its register holds 0xffff that `rx_ba::readback` relies on and
/// the Linux shadow is stale. The shadow here is the retained register, so
/// both chips end with the source result `shadow | BIT_RXFLTMAP1_BF` and the
/// upper control-subtype bits stay as the init left them.
pub(super) fn enable_mu(io: &mut impl Io, did: u16, b: Bfee) -> Result<(), Error> {
    let Role::Mu { p_aid, aid } = b.role else {
        return Err(Error::State);
    };
    // rtw_bf_init_bfer_entry_mu
    for (i, byte) in b.mac.into_iter().enumerate() {
        io.write8(REG_ASSOCIATED_BFMER0_INFO + i as u16, byte)?;
    }
    io.write16(REG_ASSOCIATED_BFMER0_INFO + 6, p_aid)?;
    io.write16(REG_TX_CSI_RPT_PARAM_BW20, b.csi_param())?;
    // csi_length_sel HAL_CSI_SEG_4K (0) at bits 13:12; bits 15:14 kept.
    let ctl = io.read16(REG_WMAC_MU_BF_CTL)? & 0xc000 | aid;
    io.write16(REG_WMAC_MU_BF_CTL, ctl)?;
    // rtw_bf_cfg_sounding(DESC_RATE6M): CSI_RSC_PRIMARY_20M_BW (0) on C22,
    // CSI_RSC_FOLLOW_RX_PACKET_BW (1) otherwise; station net type.
    let csi_rsc = u32::from(did != 0xc822);
    let psf = io.read32(REG_BBPSF_CTRL)? | BIT_WMAC_USE_NDPARATE | csi_rsc << 13;
    mask8(
        io,
        REG_SND_PTCL_CTRL,
        BIT_MASK_BEAMFORM,
        RTW_SND_CTRL_SOUNDING,
    )?;
    io.write8(REG_SND_PTCL_CTRL + 3, MU_NDP_RX_STANDBY_TIME)?;
    let shadow = io.read16(REG_RXFLTMAP1)? & !BIT_RXFLTMAP1_BF_REPORT_POLL;
    io.write16(REG_RXFLTMAP1, shadow)?;
    let flt4 = io.read8(REG_RXFLTMAP4)?;
    io.write8(REG_RXFLTMAP4, flt4 & !BIT_RXFLTMAP4_BF_REPORT_POLL)?;
    io.write32(REG_BBPSF_CTRL, psf & !(1 << 12))?;
    // Accept action_no_ack; accept NDPA and BF report poll.
    let flt0 = io.read16(REG_RXFLTMAP0)?;
    io.write16(REG_RXFLTMAP0, flt0 | BIT_RXFLTMAP0_ACTIONNOACK)?;
    io.write16(REG_RXFLTMAP1, shadow | BIT_RXFLTMAP1_BF)?;
    readback_mu(io, did, b)
}

fn readback_mu(io: &mut impl Io, did: u16, b: Bfee) -> Result<(), Error> {
    let Role::Mu { p_aid, aid } = b.role else {
        return Err(Error::State);
    };
    let mut mac = [0; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = io.read8(REG_ASSOCIATED_BFMER0_INFO + i as u16)?;
    }
    let rsc = if did == 0xc822 { 0 } else { 1 << 13 };
    let psf = io.read32(REG_BBPSF_CTRL)?;
    if mac != b.mac
        || io.read16(REG_ASSOCIATED_BFMER0_INFO + 6)? != p_aid
        || io.read16(REG_TX_CSI_RPT_PARAM_BW20)? != b.csi_param()
        || io.read16(REG_WMAC_MU_BF_CTL)? & 0x3fff != aid
        || io.read8(REG_SND_PTCL_CTRL)? & BIT_MASK_BEAMFORM != RTW_SND_CTRL_SOUNDING
        || io.read8(REG_SND_PTCL_CTRL + 3)? != MU_NDP_RX_STANDBY_TIME
        || psf & (BIT_WMAC_USE_NDPARATE | 1 << 12 | rsc) != BIT_WMAC_USE_NDPARATE | rsc
        || io.read8(REG_RXFLTMAP4)? & BIT_RXFLTMAP4_BF_REPORT_POLL != 0
        || io.read16(REG_RXFLTMAP0)? & BIT_RXFLTMAP0_ACTIONNOACK == 0
        || io.read16(REG_RXFLTMAP1)? & BIT_RXFLTMAP1_BF != BIT_RXFLTMAP1_BF
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw_bf_remove_bfee_mu`: `rtw_bf_del_bfer_entry_mu`, then
/// `rtw_bf_del_sounding` (the disassociating vif was the only SU/MU count).
/// The CSI parameter word, `REG_BBPSF_CTRL` and the RX filter maps keep
/// their values, as in Linux.
pub(super) fn remove_mu(io: &mut impl Io) -> Result<(), Error> {
    mask8(
        io,
        REG_SND_PTCL_CTRL,
        BIT_MASK_BEAMFORM,
        RTW_SND_CTRL_REMOVE,
    )?;
    io.write32(REG_ASSOCIATED_BFMER0_INFO, 0)?;
    io.write32(REG_ASSOCIATED_BFMER0_INFO_HI, 0)?;
    io.write16(REG_WMAC_MU_BF_CTL, 0)?;
    io.write8(REG_MU_TX_CTL, 0)?;
    mask8(io, REG_SND_PTCL_CTRL, BIT_MASK_BEAMFORM, 0)
}

/// `struct ieee80211_mu_group_data`: 64-bit membership and 2-bit user
/// positions (`WLAN_MEMBERSHIP_LEN` 8, `WLAN_USER_POSITION_LEN` 16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct MuGroup {
    pub(super) membership: [u8; 8],
    pub(super) position: [u8; 16],
}

/// VHT Group ID Management action (category 21, action 1) from the AP,
/// individually addressed to `own`; `None` for anything else.
///
/// mac80211 admission (`rx.c::ieee80211_rx_h_action`): the frame comes from
/// the associated AP station entry, carries at least
/// `IEEE80211_MIN_ACTION_SIZE(vht_group_notif)` (24 + 2 + 8 + 16) bytes, and
/// is queued to `iface.c` -> `vht.c::ieee80211_process_mu_groups`, which
/// acts only for the `mu_mimo_owner` link (MU beamformee advertised in the
/// association request) and only when membership or position changed.
/// VHT is a non-robust category, so the frame is unprotected.
pub(super) fn gid_management(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<MuGroup> {
    if b.len() < 50
        || b[0] != 0xd0
        // No ToDS/FromDS/MoreFrag/Protected.
        || b[1] & 0x47 != 0
        || b[4..10] != own
        || b[10..16] != ap
        || b[16..22] != ap
        || b[22] & 15 != 0
        || b[24] != 21
        || b[25] != 1
    {
        return None;
    }
    let mut g = MuGroup::default();
    g.membership.copy_from_slice(&b[26..34]);
    g.position.copy_from_slice(&b[34..50]);
    Some(g)
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// `rtw_bf_set_gid_table` -> `rtw_bf_cfg_mu_bfee` for an MU entry: MU STA
/// table 0 gets membership[0..4] and positions[0..8], table 1
/// membership[4..8] and positions[8..16] (the `memcpy` into
/// `given_gid_tab[2]` / `given_user_pos[4]`, little-endian words).
pub(super) fn set_gid(io: &mut impl Io, g: &MuGroup) -> Result<(), Error> {
    let valid = io.read8(REG_MU_TX_CTL)? & !BIT_MASK_R_MU_TABLE_VALID;
    let ctl = (valid | 1 | 2) & !BIT_EN_MU_MIMO;
    io.write8(REG_MU_TX_CTL, ctl)?;
    let sel = io.read8(REG_MU_TX_CTL + 1)? & 0xf8;
    for table in 0..2 {
        io.write8(REG_MU_TX_CTL + 1, sel | table as u8)?;
        io.write32(REG_MU_STA_GID_VLD, le32(&g.membership[table * 4..]))?;
        io.write32(REG_MU_STA_USER_POS_INFO, le32(&g.position[table * 8..]))?;
        io.write32(
            REG_MU_STA_USER_POS_INFO + 4,
            le32(&g.position[table * 8 + 4..]),
        )?;
    }
    // Readback of the control byte and the last-selected table (1); table 0
    // is not reselected for readback, which Linux never does.
    if io.read8(REG_MU_TX_CTL)? != ctl
        || io.read8(REG_MU_TX_CTL + 1)? != sel | 1
        || io.read32(REG_MU_STA_GID_VLD)? != le32(&g.membership[4..])
        || io.read32(REG_MU_STA_USER_POS_INFO)? != le32(&g.position[8..])
        || io.read32(REG_MU_STA_USER_POS_INFO + 4)? != le32(&g.position[12..])
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "bf_tests.rs"]
mod tests;
