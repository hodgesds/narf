// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Original Linux B RF terminal controls SHA256 f96e5550c1373476b6f5390cc23ebd2bcbece520fb4262b0ef4169d52d7ce47e
pub(super) const B_AX_AFC_AFEDIG: u32 = 0x20000;
pub(super) const B_AX_FEN_BBRSTB: u32 = 0x1;
pub(super) const B_AX_FEN_BB_GLB_RSTN: u32 = 0x2;
pub(super) const B_MAC_SEL_DPD_EN: u32 = 0x400;
pub(super) const B_MAC_SEL_MOD: u32 = 0x1c;
pub(super) const B_MAC_SEL_PWR_EN: u32 = 0x10000;
pub(super) const B_NCTL_N1_CIP: u32 = 0xff;
pub(super) const B_P0_RFCTM_EN: u32 = 0x20000000;
pub(super) const B_PMAC_CTX_EN: u32 = 0x1;
pub(super) const B_PMAC_GNT_RXEN: u32 = 0x10000;
pub(super) const B_PMAC_GNT_TXEN: u32 = 0x1;
pub(super) const B_PMAC_OPT1_MSK: u32 = 0xfff;
pub(super) const B_PMAC_PTX_EN: u32 = 0x10;
pub(super) const B_PMAC_RXMOD_MSK: u32 = 0xf0;
pub(super) const MASKDWORD: u32 = 0xffffffff;
pub(super) const R_AX_SYS_FUNC_EN: u32 = 0x2;
pub(super) const R_AX_WLRF_CTRL: u32 = 0x2f0;
pub(super) const R_KIP_SYSCFG: u32 = 0x8088;
pub(super) const R_MAC_SEL: u32 = 0x9a4;
pub(super) const R_NCTL_N1: u32 = 0x8010;
pub(super) const R_NCTL_RPT: u32 = 0x8008;
pub(super) const R_P0_RFCTM: u32 = 0x5864;
pub(super) const R_PMAC_GNT: u32 = 0x980;
pub(super) const R_PMAC_RXMOD: u32 = 0x994;
pub(super) const R_PMAC_RX_CFG1: u32 = 0x988;
pub(super) const R_PMAC_TX_PRD: u32 = 0x9c4;
