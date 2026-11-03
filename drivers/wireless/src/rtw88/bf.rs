// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! C21/C22 VHT SU beamformee (`bf.c`), bound only on an N2xV VHT80
//! association whose AP is an SU beamformer.
//!
//! Linux 7.3-rc4 sources:
//! - `main.c::rtw_init_vht_cap`: SU (and MU) beamformee with
//!   `hal.bfee_sts_cap` 3 (four NDP space-time streams). The station
//!   advertises SU only: MU needs `rtw_bf_set_gid_table` over VHT Group ID
//!   Management, which is not ported.
//! - `mac80211.c::rtw_ops_bss_info_changed` (`BSS_CHANGED_ASSOC`):
//!   `rtw_bf_assoc` on association, `rtw_bf_disassoc` on loss;
//!   `rtw_bf_assoc` binds SU when the local cap and the AP's
//!   `IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE` agree, `sound_dim` from the
//!   AP's sounding-dimensions field, first free SU register (index 0).
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
const REG_MU_TX_CTL: u16 = 0x14c0;
const REG_CSI_RRSR: u16 = 0x1678;
const REG_WMAC_MU_BF_OPTION: u16 = 0x167c;
const REG_WMAC_MU_BF_CTL: u16 = 0x1680;
const BIT_MASK_BEAMFORM: u8 = 0x9f;
const RTW_SND_CTRL_SOUNDING: u8 = 0x9b;
const RTW_SND_CTRL_REMOVE: u8 = 0x98;
const RTW_NDP_RX_STANDBY_TIME: u8 = 0x70;
const BIT_WMAC_USE_NDPARATE: u32 = 1 << 30;
const DESC_RATE6M: u32 = 4;

/// `hal.bfee_sts_cap` 3: VHT Beamformee STS field 3, four NDP STS.
pub(super) const BFEE_STS: u8 = 4;

/// One SU beamformer entry (`struct rtw_bfee`, register index 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Bfee {
    pub(super) mac: [u8; 6],
    /// Raw AP sounding-dimensions field (`nr_index`).
    pub(super) sound_dim: u8,
    /// `hweight8(hal.antenna_rx) - 1`: 1 on 2R C22, 0 on 1R C21.
    pub(super) nc_index: u8,
}
impl Bfee {
    /// `rtw_bf_assoc` SU branch for an AP advertising `sounding` (1..=8)
    /// sounding dimensions.
    pub(super) fn su(did: u16, bssid: [u8; 6], sounding: u8) -> Option<Self> {
        let nc_index = match did {
            0xc822 => 1,
            0xc821 => 0,
            _ => return None,
        };
        (1..=8).contains(&sounding).then_some(Self {
            mac: bssid,
            sound_dim: sounding - 1,
            nc_index,
        })
    }
    /// `csi_param`: coefficient size 3, codebook 1 (802.11ac), grouping 0.
    pub(super) fn csi_param(self) -> u16 {
        3 << 10 | 1 << 8 | u16::from(self.sound_dim) << 3 | u16::from(self.nc_index)
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

/// The enabled SU entry is still programmed.
pub(super) fn readback(io: &mut impl Io, did: u16, b: Bfee) -> Result<(), Error> {
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

#[cfg(feature = "kernel-test")]
#[path = "bf_tests.rs"]
mod tests;
