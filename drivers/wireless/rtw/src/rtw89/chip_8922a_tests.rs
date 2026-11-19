// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922A chip container. Every value below is
//! copied from the Linux `rtw8922a_chip_info` text, not from the
//! container under test: the test re-derives the numbers from the
//! Linux source lines cited in `chip_8922a.rs`.

use super::chip_8922a::*;
use super::mac::ChipId;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_8922a_container_identity() -> TestResult {
    if CHIP != ChipId::Rtl8922A {
        return TestResult::Fail("8922A container is not for ChipId::Rtl8922A");
    }
    if FIFO_SIZE != 589824 || SMALL_FIFO_SIZE || DLE_SCC_RSVD_SIZE != 0 {
        return TestResult::Fail("8922A FIFO geometry wrong");
    }
    if MAX_AMSDU_LIMIT != 8000
        || MAX_VHT_MPDU_CAP != 11454
        || MAX_EHT_MPDU_CAP != 7991
        || MAX_TX_AGG_NUM != 128
        || MAX_RX_AGG_NUM != 64
    {
        return TestResult::Fail("8922A aggregation limits wrong");
    }
    if RSVD_PLE_OFST != 0x8f800 || WDE_QEMPTY_ACQ_GRPNUM != 4 || WDE_QEMPTY_MGQ_GRPSEL != 4 {
        return TestResult::Fail("8922A PLE/WDE constants wrong");
    }
    if RF_BASE_ADDR != [0xe000, 0xf000] || THERMAL_TH != [0xad, 0xb4] {
        return TestResult::Fail("8922A RF base / thermal thresholds wrong");
    }
    if TXPWR_FACTOR_BB != 3 || TXPWR_FACTOR_RF != 2 || TXPWR_FACTOR_MAC != 1 {
        return TestResult::Fail("8922A TX power factors wrong");
    }
    if SUPPORT_MACID_NUM != 32 || SUPPORT_LINK_NUM != 2 || SUPPORT_CHANCTX_NUM != 2 || !SUPPORT_RNR
    {
        return TestResult::Fail("8922A MAC/link/chanctx counts wrong");
    }
    if !SUPPORT_BANDS_2GHZ || !SUPPORT_BANDS_5GHZ || !SUPPORT_BANDS_6GHZ {
        return TestResult::Fail("8922A must support 2G/5G/6G");
    }
    // 320 MHz is NOT in the Linux support_bandwidths mask for this chip.
    if SUPPORT_BANDWIDTHS_MHZ != [20, 40, 80, 160] {
        return TestResult::Fail("8922A bandwidths must be exactly 20/40/80/160");
    }
    if !SUPPORT_UNII4
        || !SUPPORT_ANT_GAIN
        || !SUPPORT_TAS
        || !SUPPORT_SAR_BY_ANT
        || SUPPORT_NOISE
        || SUPPORT_FW_CMD_OFLD
    {
        return TestResult::Fail("8922A support flags wrong");
    }
    if !HW_SEC_HDR || !HW_MGMT_TX_ENCRYPT || !HW_TKIP_CRYPTO || HW_MLO_BMC_CRYPTO {
        return TestResult::Fail("8922A hardware crypto flags wrong");
    }
    if RF_PATH_NUM != 2 || TX_NSS != 2 || RX_NSS != 2 {
        return TestResult::Fail("8922A must be 2TX/2RX");
    }
    if ACAM_NUM != 128
        || BCAM_NUM != 20
        || SCAM_NUM != 32
        || BACAM_NUM != 24
        || BACAM_DYNAMIC_NUM != 8
        || BACAM_VER != 1
        || ADDRCAM_VER != 0
        || PPDU_MAX_USR != 16
    {
        return TestResult::Fail("8922A CAM counts wrong");
    }
    if SEC_CTRL_EFUSE_SIZE != 4
        || PHYSICAL_EFUSE_SIZE != 0x1300
        || LOGICAL_EFUSE_SIZE != 0x70000
        || LIMIT_EFUSE_SIZE != 0x40000
        || DAV_PHY_EFUSE_SIZE != 0
        || DAV_LOG_EFUSE_SIZE != 0
    {
        return TestResult::Fail("8922A EFUSE geometry wrong");
    }
    if PHYCAP_ADDR != 0x1700 || PHYCAP_SIZE != 0x38 {
        return TestResult::Fail("8922A PHY-cap window wrong");
    }
    if PARA_VER != 0xf || WLCX_DESIRED != 0x07110000 || SCBD != 0x1 || MAILBOX != 0x1 {
        return TestResult::Fail("8922A para/scb/mailbox wrong");
    }
    if !PS_MODE_RFOFF || !PS_MODE_CLK_GATED || !PS_MODE_PWR_GATED {
        return TestResult::Fail("8922A power modes wrong");
    }
    if H2C_CCTL_FUNC_ID != 0x11
        || HCI_FUNC_EN_ADDR != 0x7880
        || H2C_DESC_SIZE != 24
        || TXWD_BODY_SIZE != 32
        || TXWD_INFO_SIZE != 32
        || H2C_CTRL_REG != 0x7160
        || C2H_CTRL_REG != 0x7164
        || UDM_COUNTER_REG != 0x01F5
        || DMA_CH_MASK != 0
    {
        return TestResult::Fail("8922A H2C/C2H register block wrong");
    }
    if FW_BASENAME != "rtw89/rtw8922a_fw" || FW_FORMAT_MAX != 4 {
        return TestResult::Fail("8922A firmware name/format wrong");
    }
    // EFUSE block table: offsets pack (page, page_offset); every
    // 8922A block has page_offset 0.
    let want: [(u32, u32); 8] = [
        (0x00000, 0x310),
        (0x10000, 0x240),
        (0x20000, 0x4800),
        (0x30000, 0x890),
        (0x40000, 0x200),
        (0x50000, 0x80),
        (0x60000, 0x0),
        (0x70000, 0x10),
    ];
    for (i, (off, size)) in want.iter().enumerate() {
        let b = EFUSE_BLOCKS[i];
        if b.offset != *off || b.size != *size {
            return TestResult::Fail("8922A EFUSE block table entry wrong");
        }
        if b.offset & 0xFFFF != 0 {
            return TestResult::Fail("8922A EFUSE block page_offset must be 0");
        }
        if efuse_block_kind(i)
            != Some(match i {
                0 => EfuseBlockKind::Sys,
                1 => EfuseBlockKind::Rf,
                2 => EfuseBlockKind::HciDigPcieSdio,
                3 => EfuseBlockKind::HciDigUsb,
                4 => EfuseBlockKind::HciPhyPcie,
                5 => EfuseBlockKind::HciPhyUsb3,
                6 => EfuseBlockKind::HciPhyUsb2,
                _ => EfuseBlockKind::Adie,
            })
        {
            return TestResult::Fail("8922A EFUSE block kind order wrong");
        }
    }
    if efuse_block_kind(8).is_some() {
        return TestResult::Fail("8922A EFUSE block table must have 8 entries");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_container_identity
);
