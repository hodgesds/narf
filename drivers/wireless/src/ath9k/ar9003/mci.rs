// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! AR9003 MCI (Message Coexistence Interface) Bluetooth coexistence:
//! `ar9003_mci.c` plus the `btcoex.c` MCI glue, for the AR9462/AR9565
//! parts that carry `ATH9K_HW_CAP_MCI` (`ar9003.rs::HW_CAP_MCI`).
//!
//! The MCI block (registers `0x1800..0x1a78`, `reg_mci.h`) exchanges
//! short messages with the Bluetooth core over a dedicated serial link:
//! WLAN sends commands through `AR_MCI_COMMAND0`/`AR_MCI_TX_PAYLOAD0..3`
//! and receives GPM (general-purpose message) slots through a 16-entry
//! DMA ring (`AR_MCI_GPM_0`/`AR_MCI_GPM_1`, 16 bytes per slot). The
//! hardware raises `ATH9K_INT_MCI` (`ar9003::irq::ATH9K_INT_MCI`) via
//! the async-cause MCI bit; `get_isr` latches the raw/RX-message causes
//! and `handle_interrupt` is the `mci.c::ath_mci_intr` bottom half.
//!
//! Message formats, GPM coex framing, the BTCOEX control values and the
//! GPIO observation muxing are all transcribed from Linux
//! `drivers/net/wireless/ath/ath9k/{ar9003_mci.c,ar9003_mci.h,reg_mci.h,
//! btcoex.c,btcoex.h,hw.h,reg.h,ar9003_phy.h}` @ `cbbddb6` and
//! `drivers/wireless/specification/ath9k.md` §3.12. Nothing here is
//! inferred from production code or the fixture: every constant below
//! names its Linux header.
//!
//! Out of scope, recorded in §3.12: the AIC states (`ar9003_aic.c`
//! hard-disables AIC, so they read 0 here exactly as in Linux) and
//! the live-owner wiring (the owner holding a `Btcoex`, routing
//! `irq::Events::mci` into `get_isr`/`handle_interrupt`, applying the
//! computed duty-cycle scheme, and recording HT state on channel
//! change). The driver-layer BT profile list and duty-cycle scheme
//! (`mci.c` `ath_mci_profile`/`ath_mci_update_scheme`) live in
//! `Mci.profiles` below; there is no mac80211 consumer in-tree.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::btcoex::StompType;
use super::{field, rmw, Chip};
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `reg_mci.h::AR_MCI_COMMAND0`.
const AR_MCI_COMMAND0: u64 = 0x1800;
const AR_MCI_COMMAND0_HEADER: u32 = 0xff;
const AR_MCI_COMMAND0_HEADER_S: u32 = 0;
const AR_MCI_COMMAND0_LEN: u32 = 0x1f00;
const AR_MCI_COMMAND0_LEN_S: u32 = 8;
const AR_MCI_COMMAND0_DISABLE_TIMESTAMP: u32 = 0x2000;
const AR_MCI_COMMAND0_DISABLE_TIMESTAMP_S: u32 = 13;
/// `reg_mci.h::AR_MCI_COMMAND2`.
const AR_MCI_COMMAND2: u64 = 0x1808;
const AR_MCI_COMMAND2_RESET_TX: u32 = 0x01;
const AR_MCI_COMMAND2_RESET_RX: u32 = 0x02;
const AR_MCI_COMMAND2_RESET_REQ_WAKEUP: u32 = 0x400;
/// `reg_mci.h::AR_MCI_TX_CTRL`.
const AR_MCI_TX_CTRL: u64 = 0x1810;
const AR_MCI_TX_CTRL_CLK_DIV: u32 = 0x03;
const AR_MCI_TX_CTRL_CLK_DIV_S: u32 = 0;
const AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE: u32 = 0x04;
/// `reg_mci.h::AR_MCI_MSG_ATTRIBUTES_TABLE`.
const AR_MCI_MSG_ATTRIBUTES_TABLE: u64 = 0x1814;
const AR_MCI_MSG_ATTRIBUTES_TABLE_CHECKSUM_S: u32 = 0;
const AR_MCI_MSG_ATTRIBUTES_TABLE_INVALID_HDR_S: u32 = 16;
/// `reg_mci.h::AR_MCI_SCHD_TABLE_0` / `AR_MCI_SCHD_TABLE_1`.
const AR_MCI_SCHD_TABLE_0: u64 = 0x1818;
/// `reg_mci.h::AR_MCI_GPM_0` / `AR_MCI_GPM_1`.
const AR_MCI_GPM_0: u64 = 0x1820;
const AR_MCI_GPM_1: u64 = 0x1824;
const AR_MCI_GPM_WRITE_PTR: u32 = 0xffff_0000;
const AR_MCI_GPM_WRITE_PTR_S: u32 = 16;
/// `reg_mci.h::AR_MCI_INTERRUPT_RAW`.
const AR_MCI_INTERRUPT_RAW: u64 = 0x1828;
/// `reg_mci.h::AR_MCI_INTERRUPT_EN`.
const AR_MCI_INTERRUPT_EN: u64 = 0x182c;
const AR_MCI_INTERRUPT_SW_MSG_DONE: u32 = 0x0000_0001;
const AR_MCI_INTERRUPT_RX_INVALID_HDR: u32 = 0x0000_0008;
const AR_MCI_INTERRUPT_RX_HW_MSG_FAIL: u32 = 0x0000_0010;
const AR_MCI_INTERRUPT_RX_SW_MSG_FAIL: u32 = 0x0000_0020;
const AR_MCI_INTERRUPT_TX_HW_MSG_FAIL: u32 = 0x0000_0080;
const AR_MCI_INTERRUPT_TX_SW_MSG_FAIL: u32 = 0x0000_0100;
const AR_MCI_INTERRUPT_RX_MSG: u32 = 0x0000_0200;
const AR_MCI_INTERRUPT_REMOTE_SLEEP_UPDATE: u32 = 0x0000_0400;
const AR_MCI_INTERRUPT_BT_PRI: u32 = 0x07ff_f800;
const AR_MCI_INTERRUPT_CONT_INFO_TIMEOUT: u32 = 0x8000_0000;
/// `reg_mci.h::AR_MCI_INTERRUPT_RX_MSG_RAW`.
const AR_MCI_INTERRUPT_RX_MSG_RAW: u64 = 0x1838;
/// `reg_mci.h::AR_MCI_INTERRUPT_RX_MSG_EN`.
const AR_MCI_INTERRUPT_RX_MSG_EN: u64 = 0x183c;
const AR_MCI_INTERRUPT_RX_MSG_REMOTE_RESET: u32 = 0x0000_0001;
const AR_MCI_INTERRUPT_RX_MSG_CONT_INFO: u32 = 0x0000_0008;
const AR_MCI_INTERRUPT_RX_MSG_CONT_RST: u32 = 0x0000_0010;
const AR_MCI_INTERRUPT_RX_MSG_SCHD_INFO: u32 = 0x0000_0020;
const AR_MCI_INTERRUPT_RX_MSG_GPM: u32 = 0x0000_0100;
const AR_MCI_INTERRUPT_RX_MSG_LNA_INFO: u32 = 0x0000_0200;
const AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING: u32 = 0x0000_0400;
const AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING: u32 = 0x0000_0800;
const AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE: u32 = 0x0000_1000;
/// `reg_mci.h::AR_MCI_RX_STATUS`.
const AR_MCI_RX_STATUS: u64 = 0x1844;
const AR_MCI_RX_LAST_SCHD_MSG_INDEX: u32 = 0x0000_0f00;
const AR_MCI_RX_LAST_SCHD_MSG_INDEX_S: u32 = 8;
const AR_MCI_RX_REMOTE_SLEEP: u32 = 0x0000_1000;
const AR_MCI_RX_REMOTE_SLEEP_S: u32 = 12;
/// `reg_mci.h::AR_MCI_CONT_STATUS`.
const AR_MCI_CONT_STATUS: u64 = 0x1848;
/// `reg_mci.h::AR_MCI_BT_PRI0..3` / `AR_MCI_BT_PRI`.
const AR_MCI_BT_PRI0: u64 = 0x184c;
const AR_MCI_BT_PRI1: u64 = 0x1850;
const AR_MCI_BT_PRI2: u64 = 0x1854;
const AR_MCI_BT_PRI3: u64 = 0x1858;
const AR_MCI_BT_PRI: u64 = 0x185c;
/// `reg_mci.h::AR_MCI_TX_PAYLOAD0..3`.
const AR_MCI_TX_PAYLOAD0: u64 = 0x1898;
/// `reg_mci.h::AR_BTCOEX_CTRL`.
const AR_BTCOEX_CTRL: u64 = 0x18ac;
const AR_BTCOEX_CTRL_AR9462_MODE_S: u32 = 0;
const AR_BTCOEX_CTRL_WBTIMER_EN_S: u32 = 1;
const AR_BTCOEX_CTRL_MCI_MODE_EN: u32 = 0x0000_0004;
const AR_BTCOEX_CTRL_LNA_SHARED_S: u32 = 3;
const AR_BTCOEX_CTRL_PA_SHARED_S: u32 = 4;
const AR_BTCOEX_CTRL_ONE_STEP_LOOK_AHEAD_EN: u32 = 0x0000_0020;
const AR_BTCOEX_CTRL_ONE_STEP_LOOK_AHEAD_EN_S: u32 = 5;
const AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN: u32 = 0x0000_0040;
const AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN_S: u32 = 6;
const AR_BTCOEX_CTRL_NUM_ANTENNAS_S: u32 = 7;
const AR_BTCOEX_CTRL_RX_CHAIN_MASK_S: u32 = 9;
const AR_BTCOEX_CTRL_AGGR_THRESH: u32 = 0x0000_7000;
const AR_BTCOEX_CTRL_AGGR_THRESH_S: u32 = 12;
const AR_BTCOEX_CTRL_REDUCE_TXPWR: u32 = 0x2000_0000;
const AR_BTCOEX_CTRL_REDUCE_TXPWR_S: u32 = 29;
/// `reg_mci.h::AR_BTCOEX_WL_WEIGHTS0..3` (`AR_MCI_COEX_WL_WEIGHTS(i)`).
pub(super) const AR_BTCOEX_WL_WEIGHTS0: u64 = 0x18b0;
pub(super) const AR_BTCOEX_WL_WEIGHTS1: u64 = 0x18b4;
pub(super) const AR_BTCOEX_WL_WEIGHTS2: u64 = 0x18b8;
pub(super) const AR_BTCOEX_WL_WEIGHTS3: u64 = 0x18bc;
/// `reg_mci.h::AR_BTCOEX_MAX_TXPWR(x)`.
const AR_BTCOEX_MAX_TXPWR0: u64 = 0x18c0;
/// `reg_mci.h::AR_BTCOEX_WL_LNA` / `AR_BTCOEX_RFGAIN_CTRL`.
const AR_BTCOEX_WL_LNA: u64 = 0x1940;
const AR_BTCOEX_WL_LNA_TIMEOUT: u32 = 0x003f_ffff;
const AR_BTCOEX_WL_LNA_TIMEOUT_S: u32 = 0;
/// `reg_mci.h::AR_BTCOEX_CTRL2`.
const AR_BTCOEX_CTRL2: u64 = 0x1948;
const AR_BTCOEX_CTRL2_TXPWR_THRESH: u32 = 0x0007_f800;
const AR_BTCOEX_CTRL2_TXPWR_THRESH_S: u32 = 11;
const AR_BTCOEX_CTRL2_TX_CHAIN_MASK: u32 = 0x0038_0000;
const AR_BTCOEX_CTRL2_TX_CHAIN_MASK_S: u32 = 19;
const AR_BTCOEX_CTRL2_RX_DEWEIGHT: u32 = 0x0040_0000;
const AR_BTCOEX_CTRL2_RX_DEWEIGHT_S: u32 = 22;
const AR_BTCOEX_CTRL2_GPIO_OBS_SEL: u32 = 0x0080_0000;
const AR_BTCOEX_CTRL2_GPIO_OBS_SEL_S: u32 = 23;
const AR_BTCOEX_CTRL2_MAC_BB_OBS_SEL: u32 = 0x0100_0000;
const AR_BTCOEX_CTRL2_MAC_BB_OBS_SEL_S: u32 = 24;
const AR_BTCOEX_CTRL2_DESC_BASED_TXPWR_ENABLE: u32 = 0x0200_0000;
const AR_BTCOEX_CTRL2_DESC_BASED_TXPWR_ENABLE_S: u32 = 25;
/// `reg_mci.h::AR_BTCOEX_CTRL_SPDT_ENABLE` / `AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL`
/// (bits of `AR_PHY_GLB_CONTROL`, not of `AR_BTCOEX_CTRL`).
const AR_BTCOEX_CTRL_SPDT_ENABLE: u32 = 0x0000_0001;
const AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL: u32 = 0x0000_0002;
/// `reg_mci.h::AR_BTCOEX_RC`.
const AR_BTCOEX_RC: u64 = 0x194c;
/// `reg_mci.h::AR_MCI_SCHD_TABLE_2`.
const AR_MCI_SCHD_TABLE_2: u64 = 0x1a5c;
const AR_MCI_SCHD_TABLE_2_MEM_BASED: u32 = 0x0000_0001;
const AR_MCI_SCHD_TABLE_2_MEM_BASED_S: u32 = 0;
const AR_MCI_SCHD_TABLE_2_HW_BASED: u32 = 0x0000_0002;
const AR_MCI_SCHD_TABLE_2_HW_BASED_S: u32 = 1;
/// `reg_mci.h::AR_BTCOEX_CTRL3`.
const AR_BTCOEX_CTRL3: u64 = 0x1a60;
const AR_BTCOEX_CTRL3_CONT_INFO_TIMEOUT: u32 = 0x0000_0fff;
const AR_BTCOEX_CTRL3_CONT_INFO_TIMEOUT_S: u32 = 0;
/// `reg_mci.h::AR_MCI_MISC`.
const AR_MCI_MISC: u64 = 0x1a74;
const AR_MCI_MISC_HW_FIX_EN: u32 = 0x0000_0001;
const AR_MCI_MISC_HW_FIX_EN_S: u32 = 0;
/// `reg_mci.h::AR_MCI_DBG_CNT_CTRL`.
const AR_MCI_DBG_CNT_CTRL: u64 = 0x1a78;
const AR_MCI_DBG_CNT_CTRL_ENABLE: u32 = 0x0000_0001;
const AR_MCI_DBG_CNT_CTRL_ENABLE_S: u32 = 0;
const AR_MCI_DBG_CNT_CTRL_BT_LINKID: u32 = 0x0000_07f8;
const AR_MCI_DBG_CNT_CTRL_BT_LINKID_S: u32 = 3;
/// `reg_mci.h::MCI_STAT_ALL_BT_LINKID`.
const MCI_STAT_ALL_BT_LINKID: u32 = 0xffff;
/// `reg_mci.h::AR_MCI_INTERRUPT_DEFAULT`.
const AR_MCI_INTERRUPT_DEFAULT: u32 = AR_MCI_INTERRUPT_SW_MSG_DONE
    | AR_MCI_INTERRUPT_RX_INVALID_HDR
    | AR_MCI_INTERRUPT_RX_HW_MSG_FAIL
    | AR_MCI_INTERRUPT_RX_SW_MSG_FAIL
    | AR_MCI_INTERRUPT_TX_HW_MSG_FAIL
    | AR_MCI_INTERRUPT_TX_SW_MSG_FAIL
    | AR_MCI_INTERRUPT_RX_MSG
    | AR_MCI_INTERRUPT_REMOTE_SLEEP_UPDATE
    | AR_MCI_INTERRUPT_CONT_INFO_TIMEOUT;
/// `reg_mci.h::AR_MCI_INTERRUPT_MSG_FAIL_MASK`.
const AR_MCI_INTERRUPT_MSG_FAIL_MASK: u32 = AR_MCI_INTERRUPT_RX_HW_MSG_FAIL
    | AR_MCI_INTERRUPT_RX_SW_MSG_FAIL
    | AR_MCI_INTERRUPT_TX_HW_MSG_FAIL
    | AR_MCI_INTERRUPT_TX_SW_MSG_FAIL;
/// `reg_mci.h::AR_MCI_INTERRUPT_RX_MSG_DEFAULT`.
const AR_MCI_INTERRUPT_RX_MSG_DEFAULT: u32 = AR_MCI_INTERRUPT_RX_MSG_GPM
    | AR_MCI_INTERRUPT_RX_MSG_REMOTE_RESET
    | AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING
    | AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING
    | AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE;

/// `reg.h::AR_QUIET1` (`ar9003_mci.c` MCI enable) and
/// `reg.h::AR_QUIET1_QUIET_ACK_CTS_ENABLE`.
pub(super) const AR_QUIET1: u64 = 0x80fc;
pub(super) const AR_QUIET1_QUIET_ACK_CTS_ENABLE: u32 = 0x0002_0000;
/// `reg.h::AR_PCU_MISC` and `reg.h::AR_PCU_BT_ANT_PREVENT_RX`.
const AR_PCU_MISC: u64 = 0x8120;
const AR_PCU_BT_ANT_PREVENT_RX: u32 = 0x0010_0000;
const AR_PCU_BT_ANT_PREVENT_RX_S: u32 = 20;
/// `reg.h::AR_SELFGEN_MASK`.
const AR_SELFGEN_MASK: u64 = 0x832c;
/// `ar9003_phy.h::AR_PHY_TIMING4` (`AR_CHAN_BASE + 0xc`) and
/// `AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT`.
const AR_PHY_TIMING4: u64 = 0x980c;
const AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT: u32 = 16;
/// `reg.h::AR_OBS_BUS_CTRL`.
const AR_OBS_BUS_CTRL: u64 = 0x8068;
/// `reg.h::AR_TSF_L32` (RX-recovery rate limit in `MCI_STATE_RECOVER_RX`).
const AR_TSF_L32: u64 = 0x804c;
/// `reg.h::AR_DIAG_SW` (also a local const in `calib.rs`/`mac.rs`/`phy.rs`).
const AR_DIAG_SW: u64 = 0x8048;
/// `reg.h::AR_DIAG_OBS_PT_SEL1` / `AR_DIAG_OBS_PT_SEL2` (fields of `AR_DIAG_SW`).
const AR_DIAG_OBS_PT_SEL1: u32 = 0x000c_0000;
const AR_DIAG_OBS_PT_SEL1_S: u32 = 18;
const AR_DIAG_OBS_PT_SEL2: u32 = 0x0800_0000;
const AR_DIAG_OBS_PT_SEL2_S: u32 = 27;
/// `reg.h::AR_MACMISC` and its observation-bus fields.
const AR_MACMISC: u64 = 0x0058;
const AR_MACMISC_MISC_OBS_BUS_LSB: u32 = 0x0000_7000;
const AR_MACMISC_MISC_OBS_BUS_LSB_S: u32 = 12;
const AR_MACMISC_MISC_OBS_BUS_MSB: u32 = 0x0003_8000;
const AR_MACMISC_MISC_OBS_BUS_MSB_S: u32 = 15;
/// `ar9003_phy.h::AR_PHY_TEST_CTL_STATUS` (`AR_SM_BASE + 0x164`; the
/// AR9561 `0x160` form does not apply to any in-tree part) and
/// `AR_PHY_TEST_CTL_DEBUGPORT_SEL`.
const AR_PHY_TEST_CTL_STATUS: u64 = 0xa364;
const AR_PHY_TEST_CTL_DEBUGPORT_SEL: u32 = 0xe000_0000;
const AR_PHY_TEST_CTL_DEBUGPORT_SEL_S: u32 = 29;
/// `ar9003_phy.h::AR_GLB_BASE` (`AR_GLB_GPIO_CONTROL`) and
/// `AR_PHY_GLB_CONTROL` (`AR_GLB_BASE + 0x44`).
const AR_GLB_GPIO_CONTROL: u64 = 0x20000;
const AR_PHY_GLB_CONTROL: u64 = 0x20044;
/// `reg_mci.h::AR_GLB_WLAN_UART_INTF_EN` / `AR_GLB_DS_JTAG_DISABLE`
/// (fields of `AR_PHY_GLB_CONTROL`).
const AR_GLB_WLAN_UART_INTF_EN: u32 = 0x0002_0000;
const AR_GLB_WLAN_UART_INTF_EN_S: u32 = 17;
const AR_GLB_DS_JTAG_DISABLE: u32 = 0x0004_0000;
const AR_GLB_DS_JTAG_DISABLE_S: u32 = 18;
/// `reg.h::AR_GPIO_INPUT_EN_VAL` (AR9300 2.0+, `0x405c`) and
/// `reg.h::AR_GPIO_JTAG_DISABLE`.
const AR_GPIO_INPUT_EN_VAL: u64 = 0x405c;
const AR_GPIO_JTAG_DISABLE: u32 = 0x0002_0000;
/// `reg.h::AR_GPIO_OE_OUT` (AR9300 2.0+, `0x4050`) and
/// `reg.h::AR_GPIO_OE_OUT_DRV_ALL` (2 bits per pin).
const AR_GPIO_OE_OUT: u64 = 0x4050;
const AR_GPIO_OE_OUT_DRV_ALL: u32 = 0x3;
/// `reg.h::AR_GPIO_OUTPUT_MUX1..3` (AR9300 2.0+: `0x4068`/`0x406c`/`0x4070`);
/// one 5-bit field per pin, `(gpio % 6) * 5`.
const AR_GPIO_OUTPUT_MUX1: u64 = 0x4068;
const AR_GPIO_OUTPUT_MUX2: u64 = 0x406c;
const AR_GPIO_OUTPUT_MUX3: u64 = 0x4070;
/// `reg.h::AR_OBS` (AR9300 2.0+, `0x4088`).
const AR_OBS: u64 = 0x4088;
/// `hw.h::AR_GPIO_OUTPUT_MUX_AS_*` values used by the MCI observation setup.
const GPIO_MUX_OUTPUT: u32 = 0;
const GPIO_MUX_MCI_WLAN_DATA: u32 = 0x16;
const GPIO_MUX_MCI_WLAN_CLK: u32 = 0x17;
const GPIO_MUX_MCI_BT_DATA: u32 = 0x18;
const GPIO_MUX_MCI_BT_CLK: u32 = 0x19;
const GPIO_MUX_WL_IN_TX: u32 = 0x14;
const GPIO_MUX_WL_IN_RX: u32 = 0x13;
const GPIO_MUX_BT_IN_TX: u32 = 9;
const GPIO_MUX_BT_IN_RX: u32 = 8;

/// `ar9003_mci.h::MCI_FLAG_DISABLE_TIMESTAMP`.
pub const MCI_FLAG_DISABLE_TIMESTAMP: u32 = 0x0000_0001;
/// `ar9003_mci.h::MCI_RECOVERY_DUR_TSF` (100 ms, in TSF µs).
const MCI_RECOVERY_DUR_TSF: u32 = 100 * 1000;
/// `ar9003_mci.h::MCI_GPM_COEX_MAJOR_VERSION_DEFAULT` /
/// `MCI_GPM_COEX_MINOR_VERSION_DEFAULT` (remote BT default; also the
/// `btcoex::init_mci` initial BT version).
pub(super) const MCI_GPM_COEX_MAJOR_VERSION_DEFAULT: u8 = 3;
pub(super) const MCI_GPM_COEX_MINOR_VERSION_DEFAULT: u8 = 0;
// NOTE: `ar9003_mci.h` also declares `MCI_GPM_COEX_MAJOR/MINOR_VERSION_WLAN`
// (3.0), but Linux never assigns `mci->wlan_ver_major/minor` anywhere:
// `ath9k_hw_btcoex_init_mci` leaves them zeroed, so
// `send_coex_version_response` answers 0.0. This port keeps that exact
// behavior rather than "fixing" it; see §3.12.
/// `ar9003_mci.h::MCI_NUM_BT_CHANNELS`.
const MCI_NUM_BT_CHANNELS: u16 = 79;
/// `ar9003_mci.h::MCI_BT_MCI_FLAGS_*` (BT-side MCI flags word).
const MCI_BT_MCI_FLAGS_UPDATE_CORR: u32 = 0x0000_0002;
const MCI_BT_MCI_FLAGS_UPDATE_HDR: u32 = 0x0000_0004;
const MCI_BT_MCI_FLAGS_UPDATE_PLD: u32 = 0x0000_0008;
const MCI_BT_MCI_FLAGS_MCI_MODE: u32 = 0x0000_0400;
/// `ar9003_mci.h::MCI_TOGGLE_BT_MCI_FLAGS`.
const MCI_TOGGLE_BT_MCI_FLAGS: u32 = MCI_BT_MCI_FLAGS_UPDATE_CORR
    | MCI_BT_MCI_FLAGS_UPDATE_HDR
    | MCI_BT_MCI_FLAGS_UPDATE_PLD
    | MCI_BT_MCI_FLAGS_MCI_MODE;
/// `ar9003_mci.h::MCI_2G_FLAGS_*` / `MCI_5G_FLAGS_*`.
const MCI_2G_FLAGS_CLEAR_MASK: u32 = 0x0000_0000;
const MCI_2G_FLAGS_SET_MASK: u32 = MCI_TOGGLE_BT_MCI_FLAGS;
const MCI_5G_FLAGS_CLEAR_MASK: u32 = MCI_TOGGLE_BT_MCI_FLAGS;
const MCI_5G_FLAGS_SET_MASK: u32 = 0x0000_0000;
/// `ar9003_mci.h::ATH_MCI_CONFIG_*` (the `mci->config` word).
const ATH_MCI_CONFIG_CONCUR_TX: u32 = 0x0000_0003;
const ATH_MCI_CONFIG_MCI_OBS_MCI: u32 = 0x0000_0004;
const ATH_MCI_CONFIG_MCI_OBS_TXRX: u32 = 0x0000_0008;
const ATH_MCI_CONFIG_MCI_OBS_BT: u32 = 0x0000_0010;
const ATH_MCI_CONFIG_DISABLE_MCI_CAL: u32 = 0x0000_0020;
const ATH_MCI_CONFIG_DISABLE_OSLA: u32 = 0x0000_0040;
const ATH_MCI_CONFIG_DISABLE_FTP_STOMP: u32 = 0x0000_0080;
const ATH_MCI_CONFIG_AGGR_THRESH: u32 = 0x0000_0700;
const ATH_MCI_CONFIG_AGGR_THRESH_S: u32 = 8;
const ATH_MCI_CONFIG_DISABLE_AGGR_THRESH: u32 = 0x0000_0800;
const ATH_MCI_CONFIG_CLK_DIV: u32 = 0x0000_3000;
const ATH_MCI_CONFIG_CLK_DIV_S: u32 = 12;
/// `ar9003_mci.h::ATH_MCI_CONFIG_DISABLE_TUNING`.
const ATH_MCI_CONFIG_DISABLE_TUNING: u32 = 0x0000_4000;
const ATH_MCI_CONFIG_ANT_ARCH: u32 = 0x0700_0000;
const ATH_MCI_CONFIG_ANT_ARCH_S: u32 = 24;
const ATH_MCI_CONFIG_MCI_STAT_DBG: u32 = 0x2000_0000;
/// `ar9003_mci.h::ATH_MCI_CONFIG_MCI_OBS_MASK`.
const ATH_MCI_CONFIG_MCI_OBS_MASK: u32 =
    ATH_MCI_CONFIG_MCI_OBS_MCI | ATH_MCI_CONFIG_MCI_OBS_TXRX | ATH_MCI_CONFIG_MCI_OBS_BT;
/// `ar9003_mci.h::ATH_MCI_CONFIG_MCI_OBS_GPIO` (value ORed into
/// `AR_GLB_GPIO_CONTROL` by the observation setup).
const ATH_MCI_CONFIG_MCI_OBS_GPIO: u32 = 0x0000_002f;
/// `ar9003_mci.h::ATH_MCI_ANT_ARCH_*`.
const ATH_MCI_ANT_ARCH_1_ANT_PA_LNA_SHARED: u32 = 0x01;
const ATH_MCI_ANT_ARCH_2_ANT_PA_LNA_SHARED: u32 = 0x03;

/// `ar9003_mci.h::MCI_GPM_NOMORE` / `MCI_GPM_MORE` / `MCI_GPM_INVALID`.
const MCI_GPM_NOMORE: bool = false;
const MCI_GPM_MORE: bool = true;
const MCI_GPM_INVALID: u32 = 0xffff_ffff;
/// `mci.h::ATH_MCI_GPM_MAX_ENTRY` (16 slots) and
/// `mci.h::ATH_MCI_GPM_BUF_SIZE` (16 entries × 16 bytes).
pub const MCI_GPM_MAX_ENTRY: usize = 16;
const MCI_GPM_BUF_BYTES: usize = MCI_GPM_MAX_ENTRY * 16;
/// `ar9003_mci.h::MCI_GPM_RSVD_PATTERN` / `MCI_GPM_RSVD_PATTERN32`:
/// the byte/word a free GPM slot is filled with.
const MCI_GPM_RSVD_PATTERN: u8 = 0xfe;
const MCI_GPM_RSVD_PATTERN32: u32 = 0xfefe_fefe;
/// `btcoex.h::ATH_BTCOEX_HT20_MAX_TXPOWER` / `ATH_BTCOEX_HT40_MAX_TXPOWER`.
const ATH_BTCOEX_HT20_MAX_TXPOWER: u16 = 0x14;
const ATH_BTCOEX_HT40_MAX_TXPOWER: u16 = 0x10;
/// `regd.h::CTL_2GHT20` / `CTL_2GHT40` (the `ctlmode` values
/// `get_max_txpower` keys on).
const CTL_2GHT20: u8 = 5;
const CTL_2GHT40: u8 = 7;

/// `ar9003_mci.h::MCI_FLAG_DISABLE_TIMESTAMP` wait quantum for
/// `wait_for_interrupt`: Linux polls every `udelay(10)`.
const MCI_WAIT_QUANTUM_US: u64 = 10;
/// `ar9003_mci.c::ar9003_mci_set_power_awake` spins at most
/// `AH_WAIT_TIMEOUT` (100000) × `AH_TIME_QUANTUM` (10 µs) waiting for a
/// register to stop reading `0xdeadbeef` after power-on; the fixture
/// models the settled value, so this bound (1000 × 10 µs) only matters
/// for a dead card, where Linux proceeds with the stale value anyway.
const POWER_AWAKE_WAIT_BOUND: u32 = 1000;

/// `ar9003_mci.h::enum mci_message_header` (payload length in the comment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Msg {
    /// `MCI_LNA_CTRL`, len 0.
    LnaCtrl = 0x10,
    /// `MCI_CONT_NACK`, len 0.
    ContNack = 0x20,
    /// `MCI_CONT_INFO`, len 4.
    ContInfo = 0x30,
    /// `MCI_CONT_RST`, len 0.
    ContRst = 0x40,
    /// `MCI_SCHD_INFO`, len 16.
    SchdInfo = 0x50,
    /// `MCI_CPU_INT`, len 4.
    CpuInt = 0x60,
    /// `MCI_SYS_WAKING`, len 0.
    SysWaking = 0x70,
    /// `MCI_GPM`, len 16.
    Gpm = 0x80,
    /// `MCI_LNA_INFO`, len 1.
    LnaInfo = 0x90,
    /// `MCI_LNA_STATE`.
    LnaState = 0x94,
    /// `MCI_LNA_TAKE`.
    LnaTake = 0x98,
    /// `MCI_LNA_TRANS`.
    LnaTrans = 0x9c,
    /// `MCI_SYS_SLEEPING`, len 0.
    SysSleeping = 0xa0,
    /// `MCI_REQ_WAKE`, len 0.
    ReqWake = 0xc0,
    /// `MCI_DEBUG_16`, len 2.
    Debug16 = 0xfe,
    /// `MCI_REMOTE_RESET`, len 16.
    RemoteReset = 0xff,
}

/// `ar9003_mci.h::enum mci_gpm_subtype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum GpmSubtype {
    /// `MCI_GPM_BT_CAL_REQ`.
    BtCalReq = 0,
    /// `MCI_GPM_BT_CAL_GRANT`.
    BtCalGrant = 1,
    /// `MCI_GPM_BT_CAL_DONE`.
    BtCalDone = 2,
    /// `MCI_GPM_WLAN_CAL_REQ`.
    WlanCalReq = 3,
    /// `MCI_GPM_WLAN_CAL_GRANT`.
    WlanCalGrant = 4,
    /// `MCI_GPM_WLAN_CAL_DONE`.
    WlanCalDone = 5,
    /// `MCI_GPM_COEX_AGENT`.
    CoexAgent = 0x0c,
    /// `MCI_GPM_RSVD_PATTERN`.
    RsvdPattern = 0xfe,
    /// `MCI_GPM_BT_DEBUG`.
    BtDebug = 0xff,
}

/// `ar9003_mci.h::enum mci_gpm_coex_opcode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum GpmCoexOpcode {
    /// `MCI_GPM_COEX_VERSION_QUERY`.
    VersionQuery = 0,
    /// `MCI_GPM_COEX_VERSION_RESPONSE`.
    VersionResponse = 1,
    /// `MCI_GPM_COEX_STATUS_QUERY`.
    StatusQuery = 2,
    /// `MCI_GPM_COEX_HALT_BT_GPM`.
    HaltBtGpm = 3,
    /// `MCI_GPM_COEX_WLAN_CHANNELS`.
    WlanChannels = 4,
    /// `MCI_GPM_COEX_BT_PROFILE_INFO`.
    BtProfileInfo = 5,
    /// `MCI_GPM_COEX_BT_STATUS_UPDATE`.
    BtStatusUpdate = 6,
    /// `MCI_GPM_COEX_BT_UPDATE_FLAGS`.
    BtUpdateFlags = 7,
    /// `MCI_GPM_COEX_NOOP`.
    Noop = 8,
}

/// `ar9003_mci.h::enum ath_mci_gpm_coex_profile_type`, in Linux order.
/// Driver-layer (`mci.c::ath_mci_profile`): the BT profile a
/// `BT_PROFILE_INFO` GPM reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::ath9k) enum GpmCoexProfile {
    /// `MCI_GPM_COEX_PROFILE_UNKNOWN`.
    Unknown = 0,
    /// `MCI_GPM_COEX_PROFILE_RFCOMM`.
    Rfcomm = 1,
    /// `MCI_GPM_COEX_PROFILE_A2DP`.
    A2dp = 2,
    /// `MCI_GPM_COEX_PROFILE_HID`.
    Hid = 3,
    /// `MCI_GPM_COEX_PROFILE_BNEP`.
    Bnep = 4,
    /// `MCI_GPM_COEX_PROFILE_VOICE`.
    Voice = 5,
    /// `MCI_GPM_COEX_PROFILE_A2DPVO`.
    A2dpVo = 6,
    /// `MCI_GPM_COEX_PROFILE_MAX` (sentinel, never a real profile).
    Max = 7,
}

impl GpmCoexProfile {
    /// Decode a profile-type byte; `None` for the `MAX` sentinel and
    /// anything above it (Linux rejects `type >= MAX` as illegal).
    pub(super) fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Unknown,
            1 => Self::Rfcomm,
            2 => Self::A2dp,
            3 => Self::Hid,
            4 => Self::Bnep,
            5 => Self::Voice,
            6 => Self::A2dpVo,
            _ => return None,
        })
    }
}

/// `ar9003_mci.h::MCI_GPM_COEX_B_PROFILE_*` (byte offsets of the
/// profile-info fields in a 16-byte GPM payload; the 10-byte
/// `ath_mci_profile_info` image is bytes 6..16).
const MCI_GPM_COEX_B_PROFILE_TYPE: usize = 6;
const MCI_GPM_COEX_B_PROFILE_LINKID: usize = 7;
const MCI_GPM_COEX_B_PROFILE_STATE: usize = 8;
const MCI_GPM_COEX_B_PROFILE_ROLE: usize = 9;
const MCI_GPM_COEX_B_PROFILE_RATE: usize = 10;
const MCI_GPM_COEX_B_PROFILE_VOTYPE: usize = 11;
/// `ar9003_mci.h::MCI_GPM_COEX_H_PROFILE_T` (the `T` field is a
/// little-endian u16 at bytes 12..13).
const MCI_GPM_COEX_H_PROFILE_T: usize = 12;
const MCI_GPM_COEX_B_PROFILE_W: usize = 14;
const MCI_GPM_COEX_B_PROFILE_A: usize = 15;
/// `ar9003_mci.h::MCI_GPM_COEX_B_STATUS_*` (status-update fields).
const MCI_GPM_COEX_B_STATUS_TYPE: usize = 6;
const MCI_GPM_COEX_B_STATUS_LINKID: usize = 7;
const MCI_GPM_COEX_B_STATUS_STATE: usize = 8;

/// `mci.h::ATH_MCI_MAX_ACL_PROFILE` / `ATH_MCI_MAX_SCO_PROFILE` /
/// `ATH_MCI_MAX_PROFILE` (at most 7 ACL + 1 SCO profiles).
const ATH_MCI_MAX_ACL_PROFILE: u8 = 7;
const ATH_MCI_MAX_SCO_PROFILE: u8 = 1;
const ATH_MCI_MAX_PROFILE: usize = 8;
/// `mci.h::ATH_MCI_DEF_BT_PERIOD` (default BT period, ms).
const ATH_MCI_DEF_BT_PERIOD: u32 = 40;
/// `mci.h::ATH_MCI_BDR_DUTY_CYCLE` (extra duty for a non-EDR profile).
const ATH_MCI_BDR_DUTY_CYCLE: u32 = 20;
/// `mci.h::ATH_MCI_MAX_DUTY_CYCLE` (duty-cycle cap, percent).
const ATH_MCI_MAX_DUTY_CYCLE: u32 = 90;
/// `mci.h::ATH_MCI_INQUIRY_PRIO` (concurrent-TX priority while a
/// management link is critical).
const ATH_MCI_INQUIRY_PRIO: u8 = 62;
/// `mci.h::ATH_MCI_HI_PRIO` (voice-priority floor for the LOW stomp).
const ATH_MCI_HI_PRIO: u8 = 60;
/// `btcoex.h::ATH_BTCOEX_STOMP_MAX`: one TX-priority byte per stomp
/// type (mirrors `btcoex::STOMP_MAX`).
const CONCUR_TXPRIO_LEN: usize = 5;

/// `mci.c::ath_mci_duty_cycle`: duty cycle (percent) by profile count.
const ATH_MCI_DUTY_CYCLE: [u8; 9] = [55, 50, 60, 70, 80, 85, 90, 95, 98];
/// `mci.c::ath_mci_add_profile::voice_priority`: voice TX priority by
/// voice type (`voice_type >= 9` falls back to 110).
const ATH_MCI_VOICE_PRIORITY: [u8; 9] = [110, 110, 110, 112, 110, 110, 114, 116, 118];

/// `mci.h::struct ath_mci_profile_info`: one BT profile, as carried by
/// a `BT_PROFILE_INFO` GPM. The 10-byte payload image maps field for
/// field (`type`, `conn_handle`, `start`, `master`, `edr`,
/// `voice_type`, `T`, `W`, `A`); a nonzero state/role/rate byte reads
/// as true.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct ProfileInfo {
    /// Profile type.
    pub(super) profile: GpmCoexProfile,
    /// BT connection handle (the list key).
    pub(super) conn_handle: u8,
    /// Profile started (`STATE` byte) rather than stopped.
    pub(super) start: bool,
    /// BT is master (`ROLE` byte).
    pub(super) master: bool,
    /// EDR rate (`RATE` byte); false means a basic-rate profile.
    pub(super) edr: bool,
    /// Voice type (SCO only).
    pub(super) voice_type: u8,
    /// Voice `Tvoice` / HID `Tsniff`, in slots.
    pub(super) t: u16,
    /// Voice `Wvoice` / HID sniff timeout, in slots.
    pub(super) w: u8,
    /// HID sniff attempt, in slots.
    pub(super) a: u8,
}

impl ProfileInfo {
    /// Parse the 10-byte profile image at bytes 6..16 of a GPM slot.
    /// Callers validate the type byte first; an unmapped type reads
    /// back as `Unknown` here and never reaches the list.
    pub(super) fn from_gpm(gpm: &[u8]) -> Self {
        Self {
            profile: GpmCoexProfile::from_u8(gpm[MCI_GPM_COEX_B_PROFILE_TYPE])
                .unwrap_or(GpmCoexProfile::Unknown),
            conn_handle: gpm[MCI_GPM_COEX_B_PROFILE_LINKID],
            start: gpm[MCI_GPM_COEX_B_PROFILE_STATE] != 0,
            master: gpm[MCI_GPM_COEX_B_PROFILE_ROLE] != 0,
            edr: gpm[MCI_GPM_COEX_B_PROFILE_RATE] != 0,
            voice_type: gpm[MCI_GPM_COEX_B_PROFILE_VOTYPE],
            t: u16::from_le_bytes([
                gpm[MCI_GPM_COEX_H_PROFILE_T],
                gpm[MCI_GPM_COEX_H_PROFILE_T + 1],
            ]),
            w: gpm[MCI_GPM_COEX_B_PROFILE_W],
            a: gpm[MCI_GPM_COEX_B_PROFILE_A],
        }
    }
}

/// `mci.h::struct ath_mci_profile_status`: one BT status update, as
/// carried by a `BT_STATUS_UPDATE` GPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct ProfileStatus {
    /// Link-status update (`STATUS_TYPE` byte); those are not handled.
    pub(super) is_link: bool,
    /// BT connection handle.
    pub(super) conn_handle: u8,
    /// Link is critical (`STATUS_STATE` byte).
    pub(super) is_critical: bool,
}

impl ProfileStatus {
    /// Parse the status-update fields at bytes 6..8 of a GPM slot.
    pub(super) fn from_gpm(gpm: &[u8]) -> Self {
        Self {
            is_link: gpm[MCI_GPM_COEX_B_STATUS_TYPE] != 0,
            conn_handle: gpm[MCI_GPM_COEX_B_STATUS_LINKID],
            is_critical: gpm[MCI_GPM_COEX_B_STATUS_STATE] != 0,
        }
    }
}

/// `mci.h::struct ath_mci_profile`: the driver-layer BT profile list,
/// plus the duty-cycle scheme `update_scheme` selects from it
/// (`struct ath_btcoex` fields in Linux). The list is a fixed 8-slot
/// array (no allocation): the add caps admit at most 7 ACL + 1 SCO
/// entries, so a slot is always free when an add is allowed. The
/// scheme outputs are stored here for the owner to apply (weights via
/// `btcoex::bt_stomp`, enable/disable); this module performs no
/// hardware writes for the scheme.
#[derive(Clone, Debug)]
pub(in crate::ath9k) struct ProfileList {
    /// Live profiles, keyed by connection handle.
    pub(super) entries: [Option<ProfileInfo>; ATH_MCI_MAX_PROFILE],
    /// Critical-link bitmap, one bit per connection handle
    /// (`DECLARE_BITMAP(status, ATH_MCI_MAX_PROFILE)`).
    pub(super) status: [bool; ATH_MCI_MAX_PROFILE],
    /// Aggregation limit, in 0.25 ms units.
    pub(super) aggr_limit: u16,
    /// Number of critical management links.
    pub(super) num_mgmt: u8,
    /// Number of SCO profiles (voice + A2DP-voice).
    pub(super) num_sco: u8,
    /// Number of A2DP profiles.
    pub(super) num_a2dp: u8,
    /// Number of HID profiles.
    pub(super) num_hid: u8,
    /// Number of PAN (BNEP) profiles.
    pub(super) num_pan: u8,
    /// Number of other ACL profiles (RFCOMM).
    pub(super) num_other_acl: u8,
    /// Number of basic-rate (non-EDR) A2DP profiles.
    pub(super) num_bdr: u8,
    /// Voice TX priority (from the voice-type table on add).
    pub(super) voice_priority: u8,
    /// Selected BT duty cycle, percent.
    pub(super) duty_cycle: u8,
    /// Selected BT coexistence period, ms.
    pub(super) btcoex_period: u32,
    /// Selected WLAN no-stomp airtime, ms.
    pub(super) btcoex_no_stomp: u32,
    /// Selected BT stomp type.
    pub(super) bt_stomp_type: StompType,
    /// Concurrent-TX priority per stomp type, for the owner to apply
    /// via `btcoex::set_concur_txprio`.
    pub(super) concur_txprio: [u8; CONCUR_TXPRIO_LEN],
}

impl ProfileList {
    /// Empty list. The zeroed state matches Linux (`ath_softc` is
    /// `kzalloc`'d): no duty cycle or period until the first scheme
    /// run, stomp type `ALL` (the zero value).
    pub(super) fn new() -> Self {
        Self {
            entries: [None; ATH_MCI_MAX_PROFILE],
            status: [false; ATH_MCI_MAX_PROFILE],
            aggr_limit: 0,
            num_mgmt: 0,
            num_sco: 0,
            num_a2dp: 0,
            num_hid: 0,
            num_pan: 0,
            num_other_acl: 0,
            num_bdr: 0,
            voice_priority: 0,
            duty_cycle: 0,
            btcoex_period: 0,
            btcoex_no_stomp: 0,
            bt_stomp_type: StompType::All,
            concur_txprio: [0; CONCUR_TXPRIO_LEN],
        }
    }

    /// `mci.h::NUM_PROF`: total live profiles.
    pub(super) fn num_profiles(&self) -> u8 {
        self.num_other_acl + self.num_a2dp + self.num_hid + self.num_pan + self.num_sco
    }

    /// `mci.c::ath_mci_find_profile`: the entry for a handle, if any.
    pub(super) fn find(&self, conn_handle: u8) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|info| info.conn_handle == conn_handle))
    }

    /// `mci.h::INC_PROF`: count a profile by type (A2DP without EDR
    /// also counts as basic-rate). Counts are bounded by the 8-entry
    /// list, so saturation is unreachable in a consistent flow; it
    /// only guards against a malformed BT stream panicking the driver.
    fn inc(&mut self, info: &ProfileInfo) {
        match info.profile {
            GpmCoexProfile::Rfcomm => self.num_other_acl = self.num_other_acl.saturating_add(1),
            GpmCoexProfile::A2dp => {
                self.num_a2dp = self.num_a2dp.saturating_add(1);
                if !info.edr {
                    self.num_bdr = self.num_bdr.saturating_add(1);
                }
            }
            GpmCoexProfile::Hid => self.num_hid = self.num_hid.saturating_add(1),
            GpmCoexProfile::Bnep => self.num_pan = self.num_pan.saturating_add(1),
            GpmCoexProfile::Voice | GpmCoexProfile::A2dpVo => {
                self.num_sco = self.num_sco.saturating_add(1)
            }
            GpmCoexProfile::Unknown | GpmCoexProfile::Max => {}
        }
    }

    /// `mci.h::DEC_PROF`: uncount a profile by type.
    fn dec(&mut self, info: &ProfileInfo) {
        match info.profile {
            GpmCoexProfile::Rfcomm => self.num_other_acl = self.num_other_acl.saturating_sub(1),
            GpmCoexProfile::A2dp => {
                self.num_a2dp = self.num_a2dp.saturating_sub(1);
                if !info.edr {
                    self.num_bdr = self.num_bdr.saturating_sub(1);
                }
            }
            GpmCoexProfile::Hid => self.num_hid = self.num_hid.saturating_sub(1),
            GpmCoexProfile::Bnep => self.num_pan = self.num_pan.saturating_sub(1),
            GpmCoexProfile::Voice | GpmCoexProfile::A2dpVo => {
                self.num_sco = self.num_sco.saturating_sub(1)
            }
            GpmCoexProfile::Unknown | GpmCoexProfile::Max => {}
        }
    }

    /// `mci.c::ath_mci_add_profile`: admit a profile, subject to the
    /// SCO/ACL caps (only a `VOICE` profile may take the SCO slot;
    /// anything else counts against the 7 ACL slots). Sets the voice
    /// priority for voice profiles. False when the cap refuses it.
    pub(super) fn add(&mut self, info: &ProfileInfo) -> bool {
        if self.num_sco == ATH_MCI_MAX_SCO_PROFILE && info.profile == GpmCoexProfile::Voice {
            return false;
        }
        if self.num_profiles() - self.num_sco == ATH_MCI_MAX_ACL_PROFILE
            && info.profile != GpmCoexProfile::Voice
        {
            return false;
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return false;
        };
        *slot = Some(*info);
        self.inc(info);
        if info.profile == GpmCoexProfile::Voice {
            self.voice_priority = if (info.voice_type as usize) < ATH_MCI_VOICE_PRIORITY.len() {
                ATH_MCI_VOICE_PRIORITY[info.voice_type as usize]
            } else {
                110
            };
        }
        true
    }

    /// `mci.c::ath_mci_del_profile`: drop the entry at `idx`.
    pub(super) fn remove(&mut self, idx: usize) {
        if let Some(entry) = self.entries[idx].take() {
            self.dec(&entry);
        }
    }

    /// `mci.c::ath_mci_flush_profile`: drop every profile and reset
    /// the aggregation limit and management count. The critical-link
    /// bitmap and voice priority are left alone, exactly as in Linux
    /// (the bitmap is rebuilt by later status updates).
    pub(super) fn flush(&mut self) {
        self.aggr_limit = 0;
        self.num_mgmt = 0;
        for idx in 0..ATH_MCI_MAX_PROFILE {
            if let Some(entry) = self.entries[idx].take() {
                self.dec(&entry);
            }
        }
    }

    /// `mci.c::ath_mci_process_profile`: apply a profile-info update.
    /// A known handle whose type changed is uncounted under the old
    /// type and counted under the new one; a `start` update adds a new
    /// handle (false when the cap refuses it), a stop removes it.
    /// Returns whether the scheme must be re-run.
    pub(super) fn process_profile(&mut self, info: &ProfileInfo) -> bool {
        let found = self.find(info.conn_handle);
        if let Some(idx) = found {
            if let Some(old) = self.entries[idx] {
                if old.profile != info.profile {
                    self.dec(&old);
                    self.inc(info);
                }
                self.entries[idx] = Some(*info);
            }
        }
        if info.start {
            if found.is_none() && !self.add(info) {
                return false;
            }
        } else if let Some(idx) = found {
            self.remove(idx);
        }
        self.set_concur_txprio();
        true
    }

    /// `mci.c::ath_mci_process_status`: apply a status update. Link
    /// updates are ignored, as are updates for a handle that already
    /// has a profile and handles at or above `ATH_MCI_MAX_PROFILE`.
    /// Otherwise the handle's critical bit is set or cleared and the
    /// management count rebuilt from the bitmap. Returns whether the
    /// management count changed (and so the scheme must be re-run).
    pub(super) fn process_status(&mut self, status: &ProfileStatus) -> bool {
        if status.is_link {
            return false;
        }
        if self.find(status.conn_handle).is_some() {
            return false;
        }
        if status.conn_handle as usize >= ATH_MCI_MAX_PROFILE {
            return false;
        }
        self.status[status.conn_handle as usize] = status.is_critical;
        let old_num_mgmt = self.num_mgmt;
        self.num_mgmt = 0;
        for bit in self.status {
            if bit {
                self.num_mgmt += 1;
            }
        }
        self.set_concur_txprio();
        old_num_mgmt != self.num_mgmt
    }

    /// `mci.c::ath_mci_set_concur_txprio`: compute the concurrent-TX
    /// priority per stomp type from the live profiles. A critical
    /// management link pins `ALL` (and `NONE` when no PAN/other-ACL
    /// profile is live) to the inquiry priority; otherwise the RFCOMM
    /// / A2DP / HID / PAN priorities (50/90/94/52) and the voice
    /// priority fold in via `update_stomp_txprio`.
    pub(super) fn set_concur_txprio(&mut self) {
        let mut txprio = [0u8; CONCUR_TXPRIO_LEN];
        if self.num_mgmt != 0 {
            txprio[StompType::All as usize] = ATH_MCI_INQUIRY_PRIO;
            if self.num_pan == 0 && self.num_other_acl == 0 {
                txprio[StompType::None as usize] = ATH_MCI_INQUIRY_PRIO;
            }
        } else {
            // RFCOMM, A2DP, HID, PAN.
            const PROF_PRIO: [u8; 4] = [50, 90, 94, 52];
            txprio[StompType::Low as usize] = 0xff;
            txprio[StompType::None as usize] = 0xff;
            if self.num_sco != 0 {
                update_stomp_txprio(self.voice_priority, &mut txprio);
            }
            if self.num_other_acl != 0 {
                update_stomp_txprio(PROF_PRIO[0], &mut txprio);
            }
            if self.num_a2dp != 0 {
                update_stomp_txprio(PROF_PRIO[1], &mut txprio);
            }
            if self.num_hid != 0 {
                update_stomp_txprio(PROF_PRIO[2], &mut txprio);
            }
            if self.num_pan != 0 {
                update_stomp_txprio(PROF_PRIO[3], &mut txprio);
            }
            if txprio[StompType::None as usize] == 0xff {
                txprio[StompType::None as usize] = 0;
            }
            if txprio[StompType::Low as usize] == 0xff {
                txprio[StompType::Low as usize] = 0;
            }
        }
        self.concur_txprio = txprio;
    }
}

/// `mci.c::ath_mci_update_stomp_txprio`: fold one profile priority
/// into the per-stomp table (lowest wins for `NONE`, highest for
/// `ALL`, highest above `HI_PRIO` for `LOW`).
fn update_stomp_txprio(cur_txprio: u8, stomp_txprio: &mut [u8; CONCUR_TXPRIO_LEN]) {
    if cur_txprio < stomp_txprio[StompType::None as usize] {
        stomp_txprio[StompType::None as usize] = cur_txprio;
    }
    if cur_txprio > stomp_txprio[StompType::All as usize] {
        stomp_txprio[StompType::All as usize] = cur_txprio;
    }
    if cur_txprio > ATH_MCI_HI_PRIO && cur_txprio < stomp_txprio[StompType::Low as usize] {
        stomp_txprio[StompType::Low as usize] = cur_txprio;
    }
}

/// `ar9003_mci.h::MCI_GPM_COEX_QUERY_BT_ALL_INFO`.
const MCI_GPM_COEX_QUERY_BT_ALL_INFO: u8 = 1 << 0;
/// `ar9003_mci.h::MCI_GPM_COEX_QUERY_BT_TOPOLOGY`.
const MCI_GPM_COEX_QUERY_BT_TOPOLOGY: u8 = 1 << 1;
/// `ar9003_mci.h::MCI_GPM_COEX_B_GPM_TYPE` / `MCI_GPM_COEX_B_GPM_OPCODE`
/// (byte offsets of the type/opcode in a 16-byte GPM payload).
const MCI_GPM_COEX_B_GPM_TYPE: usize = 4;
const MCI_GPM_COEX_B_GPM_OPCODE: usize = 5;
/// `ar9003_mci.h::MCI_GPM_WLAN_CAL_W_SEQUENCE` (word index of the WLAN
/// calibration sequence in a cal GPM).
const MCI_GPM_WLAN_CAL_W_SEQUENCE: usize = 2;
/// `ar9003_mci.h::MCI_GPM_COEX_B_MAJOR_VERSION` /
/// `MCI_GPM_COEX_B_MINOR_VERSION` (version query/response bytes).
const MCI_GPM_COEX_B_MAJOR_VERSION: usize = 6;
const MCI_GPM_COEX_B_MINOR_VERSION: usize = 7;
/// `ar9003_mci.h::MCI_GPM_COEX_B_BT_BITMAP` (status-query bitmap byte).
const MCI_GPM_COEX_B_BT_BITMAP: usize = 6;
/// `ar9003_mci.h::MCI_GPM_COEX_B_HALT_STATE` (halt/unhalt byte).
const MCI_GPM_COEX_B_HALT_STATE: usize = 6;
/// `ar9003_mci.h::MCI_GPM_COEX_W_BT_FLAGS` /
/// `MCI_GPM_COEX_B_BT_FLAGS_OP` (update-flags payload: flags word at
/// byte 6, op byte at byte 10).
const MCI_GPM_COEX_W_BT_FLAGS: usize = 6;
const MCI_GPM_COEX_B_BT_FLAGS_OP: usize = 10;
/// `ar9003_mci.h::MCI_GPM_COEX_B_CHANNEL_MAP` (first byte of the
/// 79-bit BT channel map in a WLAN-channels GPM).
const MCI_GPM_COEX_B_CHANNEL_MAP: usize = 6;

/// `ar9003_mci.h::enum mci_gpm_coex_halt_bt_gpm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum HaltBtGpm {
    /// `MCI_GPM_COEX_BT_GPM_UNHALT`.
    Unhalt = 0,
    /// `MCI_GPM_COEX_BT_GPM_HALT`.
    Halt = 1,
}

/// `ar9003_mci.h::enum mci_gpm_coex_bt_update_flags_op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum BtFlagsOp {
    /// `MCI_GPM_COEX_BT_FLAGS_READ`.
    Read = 0,
    /// `MCI_GPM_COEX_BT_FLAGS_SET`.
    Set = 1,
    /// `MCI_GPM_COEX_BT_FLAGS_CLEAR`.
    Clear = 2,
}

/// `ar9003_mci.h::enum mci_bt_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum BtState {
    /// `MCI_BT_SLEEP`.
    Sleep = 0,
    /// `MCI_BT_AWAKE`.
    Awake = 1,
    /// `MCI_BT_CAL_START`.
    CalStart = 2,
    /// `MCI_BT_CAL`.
    Cal = 3,
}

/// `ar9003_mci.h::enum mci_state_type`, in Linux order. Only the cases
/// `ar9003_mci_state` implements return non-zero; the rest hit the
/// `default` arm and read 0, exactly as in Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum MciState {
    /// `MCI_STATE_ENABLE`.
    Enable = 0,
    /// `MCI_STATE_INIT_GPM_OFFSET`.
    InitGpmOffset = 1,
    /// `MCI_STATE_CHECK_GPM_OFFSET`.
    CheckGpmOffset = 2,
    /// `MCI_STATE_NEXT_GPM_OFFSET`.
    NextGpmOffset = 3,
    /// `MCI_STATE_LAST_GPM_OFFSET`.
    LastGpmOffset = 4,
    /// `MCI_STATE_BT`.
    Bt = 5,
    /// `MCI_STATE_SET_BT_SLEEP`.
    SetBtSleep = 6,
    /// `MCI_STATE_SET_BT_AWAKE`.
    SetBtAwake = 7,
    /// `MCI_STATE_SET_BT_CAL_START`.
    SetBtCalStart = 8,
    /// `MCI_STATE_SET_BT_CAL`.
    SetBtCal = 9,
    /// `MCI_STATE_LAST_SCHD_MSG_OFFSET`.
    LastSchdMsgOffset = 10,
    /// `MCI_STATE_REMOTE_SLEEP`.
    RemoteSleep = 11,
    /// `MCI_STATE_CONT_STATUS`.
    ContStatus = 12,
    /// `MCI_STATE_RESET_REQ_WAKE`.
    ResetReqWake = 13,
    /// `MCI_STATE_SEND_WLAN_COEX_VERSION`.
    SendWlanCoexVersion = 14,
    /// `MCI_STATE_SET_BT_COEX_VERSION`.
    SetBtCoexVersion = 15,
    /// `MCI_STATE_SEND_WLAN_CHANNELS`.
    SendWlanChannels = 16,
    /// `MCI_STATE_SEND_VERSION_QUERY`.
    SendVersionQuery = 17,
    /// `MCI_STATE_SEND_STATUS_QUERY`.
    SendStatusQuery = 18,
    /// `MCI_STATE_NEED_FLUSH_BT_INFO`.
    NeedFlushBtInfo = 19,
    /// `MCI_STATE_SET_CONCUR_TX_PRI`.
    SetConcurTxPri = 20,
    /// `MCI_STATE_RECOVER_RX`.
    RecoverRx = 21,
    /// `MCI_STATE_NEED_FTP_STOMP`.
    NeedFtpStomp = 22,
    /// `MCI_STATE_NEED_TUNING`.
    NeedTuning = 23,
    /// `MCI_STATE_NEED_STAT_DEBUG`.
    NeedStatDebug = 24,
    /// `MCI_STATE_SHARED_CHAIN_CONCUR_TX`.
    SharedChainConcurTx = 25,
    /// `MCI_STATE_AIC_CAL`.
    AicCal = 26,
    /// `MCI_STATE_AIC_START`.
    AicStart = 27,
    /// `MCI_STATE_AIC_CAL_RESET`.
    AicCalReset = 28,
    /// `MCI_STATE_AIC_CAL_SINGLE`.
    AicCalSingle = 29,
    /// `MCI_STATE_IS_AR9462`.
    IsAr9462 = 30,
    /// `MCI_STATE_IS_AR9565_1ANT`.
    IsAr9565_1Ant = 31,
    /// `MCI_STATE_IS_AR9565_2ANT`.
    IsAr9565_2Ant = 32,
    /// `MCI_STATE_WLAN_WEAK_SIGNAL`.
    WlanWeakSignal = 33,
    /// `MCI_STATE_SET_WLAN_PS_STATE`.
    SetWlanPsState = 34,
    /// `MCI_STATE_GET_WLAN_PS_STATE`.
    GetWlanPsState = 35,
    /// `MCI_STATE_DEBUG`.
    Debug = 36,
    /// `MCI_STATE_STAT_DEBUG`.
    StatDebug = 37,
    /// `MCI_STATE_ALLOW_FCS`.
    AllowFcs = 38,
    /// `MCI_STATE_SET_2G_CONTENTION`.
    Set2gContention = 39,
}

/// The 2.4 GHz HT40 sideband for `update_wlan_channels`
/// (`mci.c::ath9k_mci_update_wlan_channels`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Ht40 {
    /// 20 MHz (`IS_CHAN_HT40` false).
    None,
    /// `IS_CHAN_HT40PLUS`.
    Plus,
    /// `IS_CHAN_HT40MINUS`.
    Minus,
}

/// `btcoex.h::struct ath9k_hw_mci`: the MCI engine state. The GPM ring
/// is owned here as a fixed 16-slot buffer (`ATH_MCI_GPM_BUF_SIZE` 256
/// bytes); `setup` records the DMA addresses the hardware walks.
#[derive(Clone, Debug)]
pub(in crate::ath9k) struct Mci {
    /// The part this engine drives (BTCOEX_CTRL/OSLA/stat selection).
    pub(super) chip: Chip,
    /// Latched `AR_MCI_INTERRUPT_RAW` bits (`get_isr` accumulates).
    pub(super) raw_intr: u32,
    /// Latched `AR_MCI_INTERRUPT_RX_MSG_RAW` bits.
    pub(super) rx_msg_intr: u32,
    /// Latched `AR_MCI_CONT_STATUS` (read when a CONT_INFO arrives).
    pub(super) cont_status: u32,
    /// `AR_MCI_GPM_0` DMA address.
    pub(super) gpm_addr: u32,
    /// GPM ring length in 16-byte slots (`ATH_MCI_GPM_MAX_ENTRY`).
    pub(super) gpm_len: u32,
    /// Next GPM slot to read.
    pub(super) gpm_idx: u32,
    /// `AR_MCI_SCHD_TABLE_0` DMA address.
    pub(super) sched_addr: u32,
    /// WLAN channel map sent to BT (4 dwords; byte 6 of the GPM
    /// payload is BT channel 0 — see `update_wlan_channels`).
    pub(super) wlan_channels: [u32; 4],
    /// WLAN calibration request sequence.
    pub(super) wlan_cal_seq: u32,
    /// WLAN calibration done sequence.
    pub(super) wlan_cal_done: u32,
    /// `ATH_MCI_CONFIG_*` word (`init_mci` default `0x2201` on AR9462,
    /// `0xa4c1` otherwise).
    pub(super) config: u32,
    /// The GPM ring itself (DMA buffer in Linux).
    pub(super) gpm_buf: [u8; MCI_GPM_BUF_BYTES],
    /// `ar9003_mci_reset` completed (`prep_interface` ran).
    pub(super) ready: bool,
    /// A 2G/5G switch is pending (`send_2g5g_status` still to send).
    pub(super) update_2g5g: bool,
    /// Current band is 2.4 GHz.
    pub(super) is_2g: bool,
    /// Current channel uses HT (`IS_CHAN_HT`). The owner records it
    /// on channel change alongside `is_2g`; nothing sets it yet, so
    /// the scheme uses the non-HT branch until then.
    pub(super) is_ht: bool,
    /// BT profile/status info is stale; re-query on next `check_bt`.
    pub(super) query_bt: bool,
    /// Driver-layer BT profile list (`mci.c::ath_mci_profile`) and the
    /// duty-cycle scheme it selects (`ath_mci_update_scheme`).
    pub(super) profiles: ProfileList,
    /// An UNHALT GPM is owed to BT.
    pub(super) unhalt_bt_gpm: bool,
    /// A HALT GPM was sent and not yet unhalted.
    pub(super) halted_bt_gpm: bool,
    /// BT info must be re-fetched (`MCI_STATE_NEED_FLUSH_BT_INFO`).
    pub(super) need_flush_btinfo: bool,
    /// BT coex version was learned (`VERSION_RESPONSE` seen).
    pub(super) bt_version_known: bool,
    /// WLAN channels changed; re-send on next `check_bt`.
    pub(super) wlan_channels_update: bool,
    /// Local WLAN coex version. Linux never assigns this, so it stays
    /// 0.0 and the version response answers 0.0 (see
    /// `send_coex_version_response`).
    pub(super) wlan_ver_major: u8,
    /// Local WLAN coex version (0.0, see above).
    pub(super) wlan_ver_minor: u8,
    /// Remote BT coex version (default 3.0 until learned).
    pub(super) bt_ver_major: u8,
    /// Remote BT coex version (default 3.0 until learned).
    pub(super) bt_ver_minor: u8,
    /// Remote BT power/calibration state.
    pub(super) bt_state: BtState,
    /// FTP stomp is active (`ATH_BTCOEX_STOMP_LOW_FTP` weights apply).
    pub(super) stomp_ftp: bool,
    /// Concurrent WLAN+BT TX is active (TX-power cap applies).
    pub(super) concur_tx: bool,
    /// TSF of the last RX recovery (`MCI_RECOVERY_DUR_TSF` rate limit).
    pub(super) last_recovery: u32,
}

impl Mci {
    /// Zeroed engine for `chip`; `btcoex::init_mci` fills the Linux
    /// defaults (`ath9k_hw_btcoex_init_mci`).
    pub(in crate::ath9k) fn new(chip: Chip) -> Self {
        Self {
            chip,
            raw_intr: 0,
            rx_msg_intr: 0,
            cont_status: 0,
            gpm_addr: 0,
            gpm_len: 0,
            gpm_idx: 0,
            sched_addr: 0,
            wlan_channels: [0; 4],
            wlan_cal_seq: 0,
            wlan_cal_done: 0,
            config: 0,
            gpm_buf: [0; MCI_GPM_BUF_BYTES],
            ready: false,
            update_2g5g: false,
            is_2g: false,
            is_ht: false,
            query_bt: false,
            profiles: ProfileList::new(),
            unhalt_bt_gpm: false,
            halted_bt_gpm: false,
            need_flush_btinfo: false,
            bt_version_known: false,
            wlan_channels_update: false,
            wlan_ver_major: 0,
            wlan_ver_minor: 0,
            bt_ver_major: 0,
            bt_ver_minor: 0,
            bt_state: BtState::Sleep,
            stomp_ftp: false,
            concur_tx: false,
            last_recovery: 0,
        }
    }

    /// `MCI_ANT_ARCH_PA_LNA_SHARED(mci)`: the configured antenna
    /// architecture shares the PA/LNA between WLAN and BT.
    pub(super) fn pa_lna_shared(&self) -> bool {
        let arch = (self.config & ATH_MCI_CONFIG_ANT_ARCH) >> ATH_MCI_CONFIG_ANT_ARCH_S;
        arch == ATH_MCI_ANT_ARCH_1_ANT_PA_LNA_SHARED || arch == ATH_MCI_ANT_ARCH_2_ANT_PA_LNA_SHARED
    }
}

/// What `end_reset` found: BT slept through calibration, or BT woke
/// during it and the channel must be recalibrated
/// (`ar9003_mci_end_reset` clears the TXIQ/TXCL/RTT done flags and runs
/// `ath9k_hw_init_cal` in that case; the caller owns the calibration
/// run here and re-arms the gain/DC/IQ-cal bit with
/// `set_timing4_gain_dc_iq_cal` afterwards).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum EndReset {
    /// BT did not wake; no recalibration.
    Idle,
    /// BT woke during calibration; recalibrate the channel.
    RecalibrationNeeded,
}

/// What `handle_interrupt` (`mci.c::ath_mci_intr`) found. A BT
/// calibration request while awake asks the owner for an MCI reset
/// (Linux queues `RESET_TYPE_MCI`); the GPM count is the number of
/// GPM slots consumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct InterruptOutcome {
    /// BT sent `MCI_GPM_BT_CAL_REQ` while awake.
    pub reset_requested: bool,
    /// GPM slots walked (and recycled) by this call.
    pub gpm_seen: u32,
}

// GPM payload byte access. Send payloads are `[u32; 4]` words (little
// endian, as the `AR_MCI_TX_PAYLOAD` registers hold them); received
// GPMs are byte slices of `gpm_buf`.
fn put_byte(payload: &mut [u32; 4], index: usize, value: u8) {
    let word = index / 4;
    let shift = (index % 4) * 8;
    payload[word] = (payload[word] & !(0xffu32 << shift)) | ((u32::from(value)) << shift);
}

fn get_byte(payload: &[u32], index: usize) -> u8 {
    let word = index / 4;
    let shift = (index % 4) * 8;
    // Short payloads read 0 (Linux sends zero-initialised 4-word
    // payloads; `queue_unsent_gpm` may see a shorter slice).
    let w = payload.get(word).copied().unwrap_or(0);
    ((w >> shift) & 0xff) as u8
}

/// `ar9003_mci.h::MCI_GPM_SET_TYPE_OPCODE`: GPM byte 4 is the type,
/// byte 5 the opcode.
fn gpm_set_type_opcode(payload: &mut [u32; 4], ty: u8, opcode: u8) {
    put_byte(payload, MCI_GPM_COEX_B_GPM_TYPE, ty);
    put_byte(payload, MCI_GPM_COEX_B_GPM_OPCODE, opcode);
}

/// `ar9003_mci.h::MCI_GPM_SET_CAL_TYPE`: a calibration GPM carries
/// only its type (byte 4).
fn gpm_set_cal_type(payload: &mut [u32; 4], cal_type: u8) {
    put_byte(payload, MCI_GPM_COEX_B_GPM_TYPE, cal_type);
}

/// `ar9003_mci.h::MCI_GPM_IS_CAL_TYPE`: the type is a calibration
/// subtype (`MCI_GPM_WLAN_CAL_DONE` or below).
fn gpm_is_cal_type(ty: u8) -> bool {
    ty <= GpmSubtype::WlanCalDone as u8
}

/// `ar9003_mci.h::MCI_GPM_RECYCLE`: mark a consumed slot free by
/// writing the reserved pattern into its second word (bytes 4..8).
fn recycle_gpm(mci: &mut Mci, offset: usize) {
    mci.gpm_buf[offset + 4..offset + 8].copy_from_slice(&MCI_GPM_RSVD_PATTERN32.to_le_bytes());
}

/// `REG_SET_BIT` for a plain write-only register bit (no error: the
/// read is guarded against the removed-card `u32::MAX`).
fn set_bit_raw(io: &mut impl RegisterIo, register: u64, bit: u32) {
    let value = io.read32(register);
    if value != u32::MAX {
        io.write32(register, value | bit);
    }
}

/// `REG_CLR_BIT`, same guard as `set_bit_raw`.
fn clear_bit_raw(io: &mut impl RegisterIo, register: u64, bit: u32) {
    let value = io.read32(register);
    if value != u32::MAX {
        io.write32(register, value & !bit);
    }
}

/// `ar9003_mci.c::ar9003_mci_reset_req_wakeup`: pulse
/// `AR_MCI_COMMAND2_RESET_REQ_WAKEUP` for 1 µs. The read is guarded
/// against the removed-card `u32::MAX` (Linux reads `0xdeadbeef` there)
/// so the hot wait path stays infallible.
fn reset_req_wakeup(io: &mut impl RegisterIo) {
    set_bit_raw(io, AR_MCI_COMMAND2, AR_MCI_COMMAND2_RESET_REQ_WAKEUP);
    io.delay_us(1);
    clear_bit_raw(io, AR_MCI_COMMAND2, AR_MCI_COMMAND2_RESET_REQ_WAKEUP);
}

/// `ar9003_mci.c::ar9003_mci_wait_for_interrupt`: poll `address` for
/// `bit` every 10 µs until `timeout` (µs) runs out; returns the
/// remaining timeout, 0 on timeout. A seen bit is cleared (write-1-to-
/// clear); on `AR_MCI_INTERRUPT_RX_MSG_RAW` a `REQ_WAKE` also pulses
/// the wakeup reset, and `SYS_SLEEPING`/`SYS_WAKING` also raise
/// `REMOTE_SLEEP_UPDATE` plus `RX_MSG` on the raw register.
fn wait_for_interrupt(io: &mut impl RegisterIo, address: u64, bit: u32, mut timeout: u32) -> u32 {
    while timeout > 0 {
        if io.read32(address) & bit == 0 {
            io.delay_us(MCI_WAIT_QUANTUM_US);
            timeout = timeout.saturating_sub(MCI_WAIT_QUANTUM_US as u32);
            continue;
        }
        io.write32(address, bit);
        if address == AR_MCI_INTERRUPT_RX_MSG_RAW {
            if bit & AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE != 0 {
                reset_req_wakeup(io);
            }
            if bit & (AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING | AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING)
                != 0
            {
                io.write32(AR_MCI_INTERRUPT_RAW, AR_MCI_INTERRUPT_REMOTE_SLEEP_UPDATE);
            }
            io.write32(AR_MCI_INTERRUPT_RAW, AR_MCI_INTERRUPT_RX_MSG);
        }
        return timeout;
    }
    0
}

/// Arguments for [`send_message`]: the message to send (`header`, `flag`,
/// `payload` of `len` bytes) plus how to send it (`wait_done` waits on
/// `SW_MSG_DONE`; `check_bt` refuses the send while BT sleeps).
pub(in crate::ath9k) struct SendMessageParams<'a> {
    pub(in crate::ath9k) header: Msg,
    pub(in crate::ath9k) flag: u32,
    pub(in crate::ath9k) payload: &'a [u32],
    pub(in crate::ath9k) len: u8,
    pub(in crate::ath9k) wait_done: bool,
    pub(in crate::ath9k) check_bt: bool,
}

/// `ar9003_mci.c::ar9003_mci_send_message`: send one MCI message.
/// `payload` is the little-endian words for `AR_MCI_TX_PAYLOAD0..3`
/// (`len` bytes; a short slice only writes the words it holds — callers
/// always pass the full `len / 4` words). Returns false (and queues
/// the GPM for later, see `queue_unsent_gpm`) when MCI mode is off or
/// BT sleeps and `check_bt` is set, or when `wait_done` times out on
/// `SW_MSG_DONE`.
pub(in crate::ath9k) fn send_message(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    args: SendMessageParams<'_>,
) -> bool {
    let SendMessageParams {
        header,
        flag,
        payload,
        len,
        wait_done,
        check_bt,
    } = args;
    let saved_mci_int_en = io.read32(AR_MCI_INTERRUPT_EN);
    let regval = io.read32(AR_BTCOEX_CTRL);
    if regval == 0xdeadbeef || regval == u32::MAX || regval & AR_BTCOEX_CTRL_MCI_MODE_EN == 0 {
        queue_unsent_gpm(mci, header, payload, true);
        return false;
    }
    if check_bt && mci.bt_state == BtState::Sleep {
        queue_unsent_gpm(mci, header, payload, true);
        return false;
    }
    if wait_done {
        io.write32(AR_MCI_INTERRUPT_EN, 0);
    }
    // Clear SW_MSG_DONE (and any stale message-fail bits) before waiting.
    io.write32(
        AR_MCI_INTERRUPT_RAW,
        AR_MCI_INTERRUPT_SW_MSG_DONE | AR_MCI_INTERRUPT_MSG_FAIL_MASK,
    );
    let mut i = 0;
    while (i * 4) < usize::from(len) {
        if let Some(word) = payload.get(i) {
            io.write32(AR_MCI_TX_PAYLOAD0 + (i as u64) * 4, *word);
        }
        i += 1;
    }
    io.write32(
        AR_MCI_COMMAND0,
        ((flag & MCI_FLAG_DISABLE_TIMESTAMP) << AR_MCI_COMMAND0_DISABLE_TIMESTAMP_S)
            & AR_MCI_COMMAND0_DISABLE_TIMESTAMP
            | ((u32::from(len) << AR_MCI_COMMAND0_LEN_S) & AR_MCI_COMMAND0_LEN)
            | ((u32::from(header as u8) << AR_MCI_COMMAND0_HEADER_S) & AR_MCI_COMMAND0_HEADER),
    );
    let mut msg_sent = false;
    if wait_done
        && wait_for_interrupt(io, AR_MCI_INTERRUPT_RAW, AR_MCI_INTERRUPT_SW_MSG_DONE, 500) == 0
    {
        queue_unsent_gpm(mci, header, payload, true);
    } else {
        queue_unsent_gpm(mci, header, payload, false);
        msg_sent = true;
    }
    if wait_done {
        io.write32(AR_MCI_INTERRUPT_EN, saved_mci_int_en);
    }
    msg_sent
}

/// `ar9003_mci.c::ar9003_mci_remote_reset`: `MCI_REMOTE_RESET` with the
/// all-ones payload, then 5 µs.
fn remote_reset(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    let payload = [0xffff_ffffu32, 0xffff_ffff, 0xffff_ffff, 0xffff_ff00];
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::RemoteReset,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: false,
        },
    );
    io.delay_us(5);
}

/// `ar9003_mci.c::ar9003_mci_send_lna_transfer`: `MCI_LNA_TRANS` with a
/// zero word.
fn send_lna_transfer(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    let payload = [0x0000_0000u32];
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::LnaTrans,
            flag: 0,
            payload: &payload,
            len: 1,
            wait_done,
            check_bt: false,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_req_wake`: `MCI_REQ_WAKE` with the
/// timestamp disabled, then 5 µs.
fn send_req_wake(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::ReqWake,
            flag: MCI_FLAG_DISABLE_TIMESTAMP,
            payload: &[],
            len: 0,
            wait_done,
            check_bt: false,
        },
    );
    io.delay_us(5);
}

/// `ar9003_mci.c::ar9003_mci_send_sys_waking`: `MCI_SYS_WAKING` with the
/// timestamp disabled.
fn send_sys_waking(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::SysWaking,
            flag: MCI_FLAG_DISABLE_TIMESTAMP,
            payload: &[],
            len: 0,
            wait_done,
            check_bt: false,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_lna_take`: `MCI_LNA_TAKE` with the
/// `0x70000000` word.
fn send_lna_take(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    let payload = [0x7000_0000u32];
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::LnaTake,
            flag: 0,
            payload: &payload,
            len: 1,
            wait_done,
            check_bt: false,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_sys_sleeping`: `MCI_SYS_SLEEPING`
/// with the timestamp disabled.
fn send_sys_sleeping(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::SysSleeping,
            flag: MCI_FLAG_DISABLE_TIMESTAMP,
            payload: &[],
            len: 0,
            wait_done,
            check_bt: false,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_coex_version_query`: ask BT for its
/// coex version, unless it is already known or BT sleeps.
fn send_coex_version_query(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    if mci.bt_version_known || mci.bt_state == BtState::Sleep {
        return;
    }
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::VersionQuery as u8,
    );
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_coex_version_response`: answer a BT
/// version query with the local WLAN version. NOTE: Linux never assigns
/// `mci->wlan_ver_major/minor`, so this answers 0.0 — kept verbatim.
fn send_coex_version_response(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::VersionResponse as u8,
    );
    put_byte(
        &mut payload,
        MCI_GPM_COEX_B_MAJOR_VERSION,
        mci.wlan_ver_major,
    );
    put_byte(
        &mut payload,
        MCI_GPM_COEX_B_MINOR_VERSION,
        mci.wlan_ver_minor,
    );
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_coex_wlan_channels`: send the current
/// WLAN channel map, unless no update is pending or BT sleeps. The
/// type/opcode are written into `mci.wlan_channels` itself (Linux
/// sends `&mci->wlan_channels[0]`), then overwritten with `0xff`/`0xff`
/// once sent.
fn send_coex_wlan_channels(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    if !mci.wlan_channels_update || mci.bt_state == BtState::Sleep {
        return;
    }
    gpm_set_type_opcode(
        &mut mci.wlan_channels,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::WlanChannels as u8,
    );
    let payload = mci.wlan_channels;
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    );
    gpm_set_type_opcode(&mut mci.wlan_channels, 0xff, 0xff);
}

/// `ar9003_mci.c::ar9003_mci_send_coex_bt_status_query`: ask BT for its
/// status (`query_type` bitmap). A failed send re-arms the flush when
/// the query covers BT info; a successful info query clears `query_bt`.
fn send_coex_bt_status_query(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    wait_done: bool,
    query_type: u8,
) {
    if mci.bt_state == BtState::Sleep {
        return;
    }
    let query_btinfo =
        query_type & (MCI_GPM_COEX_QUERY_BT_ALL_INFO | MCI_GPM_COEX_QUERY_BT_TOPOLOGY) != 0;
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::StatusQuery as u8,
    );
    put_byte(&mut payload, MCI_GPM_COEX_B_BT_BITMAP, query_type);
    if !send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    ) && query_btinfo
    {
        mci.need_flush_btinfo = true;
    }
    if query_btinfo {
        mci.query_bt = false;
    }
}

/// `ar9003_mci.c::ar9003_mci_send_coex_halt_bt_gpm`: HALT (or UNHALT)
/// BT's GPM stream. Halting also re-arms the BT-info query, the
/// unhalt and the flush.
fn send_coex_halt_bt_gpm(io: &mut impl RegisterIo, mci: &mut Mci, halt: bool, wait_done: bool) {
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::HaltBtGpm as u8,
    );
    if halt {
        mci.query_bt = true;
        // Send the next unhalt no matter whether the halt lands.
        mci.unhalt_bt_gpm = true;
        mci.need_flush_btinfo = true;
        put_byte(
            &mut payload,
            MCI_GPM_COEX_B_HALT_STATE,
            HaltBtGpm::Halt as u8,
        );
    } else {
        put_byte(
            &mut payload,
            MCI_GPM_COEX_B_HALT_STATE,
            HaltBtGpm::Unhalt as u8,
        );
    }
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    );
}

/// `ar9003_mci.c::ar9003_mci_send_coex_bt_flags`: a `BT_UPDATE_FLAGS`
/// GPM carrying the 4-byte flags word (little endian at byte 6) and
/// the read/set/clear op (byte 10).
fn send_coex_bt_flags(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    wait_done: bool,
    opcode: BtFlagsOp,
    bt_flags: u32,
) -> bool {
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::BtUpdateFlags as u8,
    );
    put_byte(&mut payload, MCI_GPM_COEX_B_BT_FLAGS_OP, opcode as u8);
    for i in 0..4 {
        put_byte(
            &mut payload,
            MCI_GPM_COEX_W_BT_FLAGS + i,
            ((bt_flags >> (i * 8)) & 0xff) as u8,
        );
    }
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done,
            check_bt: true,
        },
    )
}

/// `ar9003_mci.c::ar9003_mci_queue_unsent_gpm`: when a GPM could not be
/// sent (MCI off, BT asleep, or `SW_MSG_DONE` timeout), remember what
/// it was so the next `check_bt` retries it: an update-flags GPM
/// (other than READ) re-arms the 2G/5G switch, a WLAN-channels GPM
/// re-arms the channels update, and a halt/unhalt GPM re-arms the
/// halt state. `queue` is false once the message actually went out.
fn queue_unsent_gpm(mci: &mut Mci, header: Msg, payload: &[u32], queue: bool) {
    if header != Msg::Gpm || payload.len() < 2 {
        return;
    }
    let ty = get_byte(payload, MCI_GPM_COEX_B_GPM_TYPE);
    let opcode = get_byte(payload, MCI_GPM_COEX_B_GPM_OPCODE);
    if ty != GpmSubtype::CoexAgent as u8 {
        return;
    }
    if opcode == GpmCoexOpcode::BtUpdateFlags as u8 {
        if get_byte(payload, MCI_GPM_COEX_B_BT_FLAGS_OP) == BtFlagsOp::Read as u8 {
            return;
        }
        mci.update_2g5g = queue;
    } else if opcode == GpmCoexOpcode::WlanChannels as u8 {
        mci.wlan_channels_update = queue;
    } else if opcode == GpmCoexOpcode::HaltBtGpm as u8 {
        if get_byte(payload, MCI_GPM_COEX_B_HALT_STATE) == HaltBtGpm::Unhalt as u8 {
            mci.unhalt_bt_gpm = queue;
            if !queue {
                mci.halted_bt_gpm = false;
            }
        }
        if get_byte(payload, MCI_GPM_COEX_B_HALT_STATE) == HaltBtGpm::Halt as u8 {
            mci.halted_bt_gpm = !queue;
        }
    }
}

/// `ar9003_mci.c::ar9003_mci_disable_interrupt` / `enable_interrupt`.
fn disable_interrupt(io: &mut impl RegisterIo) {
    io.write32(AR_MCI_INTERRUPT_EN, 0);
    io.write32(AR_MCI_INTERRUPT_RX_MSG_EN, 0);
}

fn enable_interrupt(io: &mut impl RegisterIo) {
    io.write32(AR_MCI_INTERRUPT_EN, AR_MCI_INTERRUPT_DEFAULT);
    io.write32(AR_MCI_INTERRUPT_RX_MSG_EN, AR_MCI_INTERRUPT_RX_MSG_DEFAULT);
}

/// `ar9003_mci.c::ar9003_mci_check_int`: every bit of `ints` is set in
/// `AR_MCI_INTERRUPT_RX_MSG_RAW`.
fn check_int(io: &mut impl RegisterIo, ints: u32) -> bool {
    io.read32(AR_MCI_INTERRUPT_RX_MSG_RAW) & ints == ints
}

/// `ar9003_mci.c::ar9003_mci_get_interrupt`: the latched raw/RX-message
/// causes (`get_isr` accumulated them), cleared on read.
pub(in crate::ath9k) fn get_interrupt(mci: &mut Mci) -> (u32, u32) {
    let raw = mci.raw_intr;
    let rx_msg = mci.rx_msg_intr;
    mci.raw_intr = 0;
    mci.rx_msg_intr = 0;
    (raw, rx_msg)
}

/// `ar9003_mci.c::ar9003_mci_get_isr`: latch the MCI interrupt causes
/// into `mci` and clear them in hardware; also latches `CONT_STATUS`
/// on a `CONT_INFO`. Returns false on a `0xdeadbeef` (removed-card)
/// read, in which case nothing is latched and the caller must not
/// report `ATH9K_INT_MCI`. Called by `ar9003::irq::cause` via the
/// owner when `irq::Events::mci` is set.
pub(in crate::ath9k) fn get_isr(io: &mut impl RegisterIo, mci: &mut Mci) -> bool {
    let rx_msg_intr = io.read32(AR_MCI_INTERRUPT_RX_MSG_RAW);
    let raw_intr = io.read32(AR_MCI_INTERRUPT_RAW);
    if raw_intr == 0xdeadbeef
        || rx_msg_intr == 0xdeadbeef
        || raw_intr == u32::MAX
        || rx_msg_intr == u32::MAX
    {
        return false;
    }
    mci.rx_msg_intr |= rx_msg_intr;
    mci.raw_intr |= raw_intr;
    if rx_msg_intr & AR_MCI_INTERRUPT_RX_MSG_CONT_INFO != 0 {
        mci.cont_status = io.read32(AR_MCI_CONT_STATUS);
    }
    io.write32(AR_MCI_INTERRUPT_RX_MSG_RAW, rx_msg_intr);
    io.write32(AR_MCI_INTERRUPT_RAW, raw_intr);
    true
}

/// `ar9003_mci.c::ar9003_mci_is_gpm_valid`: the slot at `msg_index`
/// holds a real GPM (not the reserved pattern). Out-of-range slots
/// read invalid; Linux trusts the ring bounds instead.
fn is_gpm_valid(mci: &Mci, msg_index: u32) -> bool {
    if msg_index == MCI_GPM_INVALID || msg_index as usize >= MCI_GPM_MAX_ENTRY {
        return false;
    }
    let offset = (msg_index as usize) << 4;
    mci.gpm_buf[offset + MCI_GPM_COEX_B_GPM_TYPE] != MCI_GPM_RSVD_PATTERN
}

/// `hw.c::ath9k_hw_gpio_request_out` on an AR9003 (non-SoC, non-7010):
/// output-enable drive ALL (2 bits per pin in `AR_GPIO_OE_OUT`) plus
/// the 5-bit output-mux field (`AR_GPIO_OUTPUT_MUX1..3`, pin `> 11` in
/// MUX3, `> 5` in MUX2, else MUX1, at `(gpio % 6) * 5`). The pre-
/// AR9280-2.0 legacy mux shuffle does not apply to any AR9003 part.
fn gpio_request_out(io: &mut impl RegisterIo, gpio: u32, mux: u32) -> Result<(), BringUpError> {
    let addr = if gpio > 11 {
        AR_GPIO_OUTPUT_MUX3
    } else if gpio > 5 {
        AR_GPIO_OUTPUT_MUX2
    } else {
        AR_GPIO_OUTPUT_MUX1
    };
    let shift = (gpio % 6) * 5;
    rmw(
        io,
        AR_GPIO_OE_OUT,
        AR_GPIO_OE_OUT_DRV_ALL << (gpio * 2),
        AR_GPIO_OE_OUT_DRV_ALL << (gpio * 2),
    )?;
    field(io, addr, 0x1f << shift, shift, mux)?;
    Ok(())
}

/// `ar9003_mci.c::ar9003_mci_observation_set_up`: route the MCI (or
/// TX/RX, or BT) observation signals to GPIO pins 0..3 (and 5 for
/// TX/RX) and program the observation-bus selectors. No `config` OBS
/// bit means no observation at all — nothing is written.
fn observation_set_up(io: &mut impl RegisterIo, mci: &Mci) -> Result<(), BringUpError> {
    if mci.config & ATH_MCI_CONFIG_MCI_OBS_MCI != 0 {
        gpio_request_out(io, 3, GPIO_MUX_MCI_WLAN_DATA)?;
        gpio_request_out(io, 2, GPIO_MUX_MCI_WLAN_CLK)?;
        gpio_request_out(io, 1, GPIO_MUX_MCI_BT_DATA)?;
        gpio_request_out(io, 0, GPIO_MUX_MCI_BT_CLK)?;
    } else if mci.config & ATH_MCI_CONFIG_MCI_OBS_TXRX != 0 {
        gpio_request_out(io, 3, GPIO_MUX_WL_IN_TX)?;
        gpio_request_out(io, 2, GPIO_MUX_WL_IN_RX)?;
        gpio_request_out(io, 1, GPIO_MUX_BT_IN_TX)?;
        gpio_request_out(io, 0, GPIO_MUX_BT_IN_RX)?;
        gpio_request_out(io, 5, GPIO_MUX_OUTPUT)?;
    } else if mci.config & ATH_MCI_CONFIG_MCI_OBS_BT != 0 {
        gpio_request_out(io, 3, GPIO_MUX_BT_IN_TX)?;
        gpio_request_out(io, 2, GPIO_MUX_BT_IN_RX)?;
        gpio_request_out(io, 1, GPIO_MUX_MCI_BT_DATA)?;
        gpio_request_out(io, 0, GPIO_MUX_MCI_BT_CLK)?;
    } else {
        return Ok(());
    }
    rmw(io, AR_GPIO_INPUT_EN_VAL, 0, AR_GPIO_JTAG_DISABLE)?;
    field(
        io,
        AR_PHY_GLB_CONTROL,
        AR_GLB_DS_JTAG_DISABLE,
        AR_GLB_DS_JTAG_DISABLE_S,
        1,
    )?;
    field(
        io,
        AR_PHY_GLB_CONTROL,
        AR_GLB_WLAN_UART_INTF_EN,
        AR_GLB_WLAN_UART_INTF_EN_S,
        0,
    )?;
    rmw(io, AR_GLB_GPIO_CONTROL, 0, ATH_MCI_CONFIG_MCI_OBS_GPIO)?;
    field(
        io,
        AR_BTCOEX_CTRL2,
        AR_BTCOEX_CTRL2_GPIO_OBS_SEL,
        AR_BTCOEX_CTRL2_GPIO_OBS_SEL_S,
        0,
    )?;
    field(
        io,
        AR_BTCOEX_CTRL2,
        AR_BTCOEX_CTRL2_MAC_BB_OBS_SEL,
        AR_BTCOEX_CTRL2_MAC_BB_OBS_SEL_S,
        1,
    )?;
    io.write32(AR_OBS, 0x4b);
    field(
        io,
        AR_DIAG_SW,
        AR_DIAG_OBS_PT_SEL1,
        AR_DIAG_OBS_PT_SEL1_S,
        0x03,
    )?;
    field(
        io,
        AR_DIAG_SW,
        AR_DIAG_OBS_PT_SEL2,
        AR_DIAG_OBS_PT_SEL2_S,
        0x01,
    )?;
    field(
        io,
        AR_MACMISC,
        AR_MACMISC_MISC_OBS_BUS_LSB,
        AR_MACMISC_MISC_OBS_BUS_LSB_S,
        0x02,
    )?;
    field(
        io,
        AR_MACMISC,
        AR_MACMISC_MISC_OBS_BUS_MSB,
        AR_MACMISC_MISC_OBS_BUS_MSB_S,
        0x03,
    )?;
    field(
        io,
        AR_PHY_TEST_CTL_STATUS,
        AR_PHY_TEST_CTL_DEBUGPORT_SEL,
        AR_PHY_TEST_CTL_DEBUGPORT_SEL_S,
        0x07,
    )?;
    Ok(())
}

/// `ar9003_mci.c::ar9003_mci_sync_bt_state`: re-read the remote sleep
/// bit; when BT is awake, re-query its version and channels and send
/// any owed UNHALT.
fn sync_bt_state(io: &mut impl RegisterIo, mci: &mut Mci) -> Result<(), BringUpError> {
    let cur = state(io, mci, MciState::RemoteSleep)?;
    let cur_bt_state = if cur == BtState::Sleep as u32 {
        BtState::Sleep
    } else {
        BtState::Awake
    };
    if mci.bt_state != cur_bt_state {
        mci.bt_state = cur_bt_state;
    }
    if mci.bt_state != BtState::Sleep {
        send_coex_version_query(io, mci, true);
        send_coex_wlan_channels(io, mci, true);
        if mci.unhalt_bt_gpm {
            send_coex_halt_bt_gpm(io, mci, false, true);
        }
    }
    Ok(())
}

/// `ar9003_mci.c::ar9003_mci_check_bt`: the periodic MCI poll — sync
/// BT state, run a pending 2G/5G switch, and flag BT info for
/// re-fetch when BT is awake and a profile/status update arrived.
pub(in crate::ath9k) fn check_bt(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
) -> Result<(), BringUpError> {
    if !mci.ready {
        return Ok(());
    }
    sync_bt_state(io, mci)?;
    switch_2g5g(io, mci, true)?;
    if mci.bt_state == BtState::Awake && mci.query_bt {
        mci.need_flush_btinfo = true;
    }
    Ok(())
}

/// `mci.c::ath_mci_msg` (profile arms only): the driver-layer
/// reaction to a received coex-agent GPM. When BT info was flagged
/// stale, the profile list is flushed and a status query re-arms the
/// re-fetch; profile-info GPMs update the list (illegal types —
/// `UNKNOWN` or `>= MAX` — are ignored) and status-update GPMs
/// maintain the critical-link bitmap. Either change re-runs the
/// duty-cycle scheme. Other coex opcodes are hw-layer only and are
/// left to `process_gpm_extra`.
fn process_profile_msg(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    gpm_opcode: u8,
    gpm: &[u8],
) -> Result<(), BringUpError> {
    if state(io, mci, MciState::NeedFlushBtInfo)? != 0 && state(io, mci, MciState::Enable)? != 0 {
        mci.profiles.flush();
        state(io, mci, MciState::SendStatusQuery)?;
    }
    let mut rerun_scheme = false;
    if gpm_opcode == GpmCoexOpcode::BtProfileInfo as u8 {
        let Some(profile) = GpmCoexProfile::from_u8(gpm[MCI_GPM_COEX_B_PROFILE_TYPE]) else {
            return Ok(());
        };
        if profile == GpmCoexProfile::Unknown {
            return Ok(());
        }
        rerun_scheme = mci.profiles.process_profile(&ProfileInfo::from_gpm(gpm));
    } else if gpm_opcode == GpmCoexOpcode::BtStatusUpdate as u8 {
        rerun_scheme = mci.profiles.process_status(&ProfileStatus::from_gpm(gpm));
    }
    if rerun_scheme {
        update_scheme(mci);
    }
    Ok(())
}

/// `mci.c::ath_mci_adjust_aggr_limit`: shrink the aggregation limit
/// to half the WLAN airtime when the airtime is 4 ms or less, so an
/// aggregate still fits without colliding with BT traffic. Airtime is
/// in ms; the limit is in 0.25 ms units.
fn adjust_aggr_limit(mci: &mut Mci) {
    let profiles = &mut mci.profiles;
    let wlan_airtime = profiles.btcoex_period * (100 - u32::from(profiles.duty_cycle)) / 100;
    if wlan_airtime <= 4
        && (profiles.aggr_limit == 0 || u32::from(profiles.aggr_limit) > 2 * wlan_airtime)
    {
        profiles.aggr_limit = (2 * wlan_airtime) as u16;
    }
}

/// `mci.c::ath_mci_update_scheme`: select the duty-cycle scheme from
/// the live profiles and store it on the list for the owner to apply.
/// With tuning enabled (`ATH_MCI_CONFIG_DISABLE_TUNING` clear) the
/// duty cycle comes from the profile-count table with the single-SCO
/// / single-PAN-or-other-ACL / single-HID / two-profile /
/// three-or-more special cases (single PAN takes 40% on AR9565, 35%
/// otherwise) and the period resets to the default; with tuning
/// disabled the previous duty cycle, period and stomp type stand. The
/// 2 GHz tail still runs either way (HT adjusts the aggregation
/// limit, non-HT halves the period), 5 GHz returns before the BDR
/// bonus, and on 2 GHz a basic-rate profile adds 20% duty capped at
/// 90% and the no-stomp airtime is recomputed.
///
/// Deliberate deviation: Linux defers this to the `mci_work`
/// workqueue and then pauses the btcoex timer, disables/enables the
/// hw coexistence and resumes the timer. There is no workqueue or
/// btcoex timer in-tree, so the scheme runs inline here (pure state,
/// no hardware writes) and the owner applies the stored outputs
/// (`bt_stomp` for the stomp type, enable/disable).
fn update_scheme(mci: &mut Mci) {
    if mci.config & ATH_MCI_CONFIG_DISABLE_TUNING == 0 {
        let is_ar9565 = mci.chip == Chip::Ar9565;
        let profiles = &mut mci.profiles;
        profiles.aggr_limit = 0;
        let num_profile = profiles.num_profiles();
        profiles.duty_cycle = ATH_MCI_DUTY_CYCLE[num_profile as usize];
        profiles.btcoex_period = ATH_MCI_DEF_BT_PERIOD;
        profiles.bt_stomp_type = if num_profile != 0 {
            StompType::Low
        } else if profiles.num_mgmt != 0 {
            StompType::All
        } else {
            StompType::Low
        };
        if num_profile == 1 {
            // The only live entry (copied: the scheme mutates the
            // list below, so no borrow is held across it).
            let info = *profiles
                .entries
                .iter()
                .flatten()
                .next()
                .expect("one profile is live");
            if profiles.num_sco != 0 {
                if info.t == 12 {
                    profiles.aggr_limit = 8;
                } else if info.t == 6 {
                    profiles.aggr_limit = 6;
                    profiles.duty_cycle = 30;
                } else {
                    profiles.aggr_limit = 6;
                }
            } else if profiles.num_pan != 0 || profiles.num_other_acl != 0 {
                profiles.duty_cycle = if is_ar9565 { 40 } else { 35 };
                profiles.btcoex_period = 53;
            } else if profiles.num_hid != 0 {
                profiles.duty_cycle = 30;
                profiles.aggr_limit = 6;
            }
        } else if num_profile == 2 {
            if profiles.num_hid == 2 {
                profiles.duty_cycle = 30;
            }
            profiles.aggr_limit = 6;
        } else if num_profile >= 3 {
            profiles.aggr_limit = 4;
        }
    }
    if mci.is_2g {
        if mci.is_ht {
            adjust_aggr_limit(mci);
        } else {
            mci.profiles.btcoex_period >>= 1;
        }
    }
    // Linux pauses the btcoex timer and disables hw coexistence here;
    // 5 GHz returns before the BDR bonus below.
    if !mci.is_2g {
        return;
    }
    let mut duty_cycle = u32::from(mci.profiles.duty_cycle);
    if mci.profiles.num_bdr != 0 {
        duty_cycle += ATH_MCI_BDR_DUTY_CYCLE;
    }
    if duty_cycle > ATH_MCI_MAX_DUTY_CYCLE {
        duty_cycle = ATH_MCI_MAX_DUTY_CYCLE;
    }
    mci.profiles.duty_cycle = duty_cycle as u8;
    mci.profiles.btcoex_no_stomp = mci.profiles.btcoex_period * (100 - duty_cycle) / 100;
}

/// `ar9003_mci.c::ar9003_mci_process_gpm_extra`: the hw-level reaction
/// to a received coex-agent GPM — answer version queries, learn the BT
/// version from responses, re-send WLAN channels on a status query,
/// and flag BT info for re-fetch on profile/status updates. The
/// driver-layer profile bookkeeping for those updates lives in
/// `process_profile_msg` (`mci.c::ath_mci_msg`), called alongside this
/// from `handle_interrupt`; see §3.12.
fn process_gpm_extra(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    gpm_type: u8,
    gpm_opcode: u8,
    gpm: &[u8],
) {
    if gpm_type != GpmSubtype::CoexAgent as u8 {
        return;
    }
    if gpm_opcode == GpmCoexOpcode::VersionQuery as u8 {
        send_coex_version_response(io, mci, true);
    } else if gpm_opcode == GpmCoexOpcode::VersionResponse as u8 {
        mci.bt_ver_major = gpm[MCI_GPM_COEX_B_MAJOR_VERSION];
        mci.bt_ver_minor = gpm[MCI_GPM_COEX_B_MINOR_VERSION];
        mci.bt_version_known = true;
    } else if gpm_opcode == GpmCoexOpcode::StatusQuery as u8 {
        mci.wlan_channels_update = true;
        send_coex_wlan_channels(io, mci, true);
    } else if gpm_opcode == GpmCoexOpcode::BtProfileInfo as u8
        || gpm_opcode == GpmCoexOpcode::BtStatusUpdate as u8
    {
        mci.query_bt = true;
    }
}

/// `ar9003_mci.c::ar9003_mci_wait_for_gpm`: wait up to `time_out` (µs)
/// for a GPM of `gpm_type`/`gpm_opcode` (calibration GPMs match on
/// type alone). While waiting for a BT calibration grant, a BT
/// calibration request is answered with a WLAN grant and the wait
/// retargets at the BT calibration done. Any other GPM seen on the
/// way gets the `process_gpm_extra` treatment; leftover GPMs are
/// drained the same way. Returns the remaining timeout, 0 on timeout.
fn wait_for_gpm(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    mut gpm_type_want: u8,
    gpm_opcode_want: u8,
    mut time_out: u32,
) -> u32 {
    let b_is_bt_cal_done = gpm_type_want == GpmSubtype::BtCalDone as u8;
    let mut more_data = if time_out != 0 {
        MCI_GPM_NOMORE
    } else {
        MCI_GPM_MORE
    };
    let mut pending: Option<usize> = None;
    while time_out > 0 {
        if let Some(off) = pending.take() {
            recycle_gpm(mci, off);
        }
        if !more_data {
            time_out = wait_for_interrupt(
                io,
                AR_MCI_INTERRUPT_RX_MSG_RAW,
                AR_MCI_INTERRUPT_RX_MSG_GPM,
                time_out,
            );
        }
        if time_out == 0 {
            break;
        }
        let (offset, more) = get_next_gpm_offset(io, mci);
        more_data = more;
        if offset == MCI_GPM_INVALID {
            continue;
        }
        let off = offset as usize;
        pending = Some(off);
        let recv_type = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_TYPE];
        let recv_opcode = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_OPCODE];
        if gpm_is_cal_type(recv_type) {
            if recv_type == gpm_type_want {
                if gpm_type_want == GpmSubtype::BtCalDone as u8 && !b_is_bt_cal_done {
                    gpm_type_want = GpmSubtype::BtCalGrant as u8;
                    continue;
                }
                break;
            }
        } else if recv_type == gpm_type_want && recv_opcode == gpm_opcode_want {
            break;
        }
        if gpm_type_want == GpmSubtype::BtCalGrant as u8 && recv_type == GpmSubtype::BtCalReq as u8
        {
            let mut payload = [0u32; 4];
            gpm_set_cal_type(&mut payload, GpmSubtype::WlanCalGrant as u8);
            gpm_type_want = GpmSubtype::BtCalDone as u8;
            send_message(
                io,
                mci,
                SendMessageParams {
                    header: Msg::Gpm,
                    flag: 0,
                    payload: &payload,
                    len: 16,
                    wait_done: false,
                    check_bt: false,
                },
            );
            continue;
        }
        let slot: [u8; 16] = mci.gpm_buf[off..off + 16]
            .try_into()
            .expect("GPM slot is 16 bytes");
        process_gpm_extra(io, mci, recv_type, recv_opcode, &slot);
    }
    if let Some(off) = pending.take() {
        recycle_gpm(mci, off);
    }
    while more_data == MCI_GPM_MORE {
        let (offset, more) = get_next_gpm_offset(io, mci);
        more_data = more;
        if offset == MCI_GPM_INVALID {
            break;
        }
        let off = offset as usize;
        let recv_type = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_TYPE];
        let recv_opcode = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_OPCODE];
        if !gpm_is_cal_type(recv_type) {
            let slot: [u8; 16] = mci.gpm_buf[off..off + 16]
                .try_into()
                .expect("GPM slot is 16 bytes");
            process_gpm_extra(io, mci, recv_type, recv_opcode, &slot);
        }
        recycle_gpm(mci, off);
    }
    time_out
}

/// `ar9003_mci_prep_interface`: wake BT, sync the GPM ring and take the
/// LNA when the interface is prepared for a reset or resume. The
/// redundant-`SYS_WAKING` clear runs whenever the wake handshake
/// succeeded; `awake` tracks that (Linux reaches the same block via the
/// `clear_redunt` label from both the wake and the timeout paths).
fn prep_interface(io: &mut impl RegisterIo, mci: &mut Mci) {
    mci.bt_state = BtState::Sleep;
    let saved_mci_int_en = io.read32(AR_MCI_INTERRUPT_EN);
    io.write32(AR_MCI_INTERRUPT_EN, 0);
    let rx_msg = io.read32(AR_MCI_INTERRUPT_RX_MSG_RAW);
    io.write32(AR_MCI_INTERRUPT_RX_MSG_RAW, rx_msg);
    let raw = io.read32(AR_MCI_INTERRUPT_RAW);
    io.write32(AR_MCI_INTERRUPT_RAW, raw);
    remote_reset(io, mci, true);
    send_req_wake(io, mci, true);
    let mut awake = false;
    if wait_for_interrupt(
        io,
        AR_MCI_INTERRUPT_RX_MSG_RAW,
        AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING,
        500,
    ) != 0
    {
        awake = true;
        mci.bt_state = BtState::Awake;
        send_sys_waking(io, mci, true);
        io.delay_us(10);
        io.write32(AR_MCI_BT_PRI0, 0xffff_ffff);
        io.write32(AR_MCI_BT_PRI1, 0xffff_ffff);
        io.write32(AR_MCI_BT_PRI2, 0xffff_ffff);
        io.write32(AR_MCI_BT_PRI3, 0xffff_ffff);
        io.write32(AR_MCI_BT_PRI, 0x0000_00ff);
        io.write32(
            AR_MCI_INTERRUPT_RX_MSG_RAW,
            AR_MCI_INTERRUPT_RX_MSG_CONT_RST,
        );
        io.write32(AR_MCI_INTERRUPT_RAW, AR_MCI_INTERRUPT_BT_PRI);
        if mci.is_2g && mci.pa_lna_shared() {
            send_lna_transfer(io, mci, true);
            io.delay_us(5);
        }
        if mci.is_2g && !mci.update_2g5g && mci.pa_lna_shared() {
            wait_for_interrupt(
                io,
                AR_MCI_INTERRUPT_RX_MSG_RAW,
                AR_MCI_INTERRUPT_RX_MSG_LNA_INFO,
                150,
            );
        }
    }
    // Clear the extra redundant SYS_WAKING from BT.
    if awake
        && io.read32(AR_MCI_INTERRUPT_RX_MSG_RAW) & AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING != 0
        && io.read32(AR_MCI_INTERRUPT_RX_MSG_RAW) & AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING == 0
    {
        io.write32(
            AR_MCI_INTERRUPT_RX_MSG_RAW,
            AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING,
        );
        io.write32(AR_MCI_INTERRUPT_RAW, AR_MCI_INTERRUPT_REMOTE_SLEEP_UPDATE);
    }
    io.write32(AR_MCI_INTERRUPT_EN, saved_mci_int_en);
}

/// `ar9003_mci_set_full_sleep`: halt BT GPM traffic and mark the MCI
/// link down for a full sleep.
pub(in crate::ath9k) fn set_full_sleep(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
) -> Result<(), BringUpError> {
    if state(io, mci, MciState::Enable)? != 0
        && mci.bt_state != BtState::Sleep
        && !mci.halted_bt_gpm
    {
        send_coex_halt_bt_gpm(io, mci, true, true);
    }
    mci.ready = false;
    Ok(())
}

/// `ar9003_mci_mute_bt`: silence the BT weights, take the LNA back and
/// put BT to sleep for a full-sleep reset.
fn mute_bt(io: &mut impl RegisterIo, mci: &mut Mci) -> Result<(), BringUpError> {
    io.write32(AR_MCI_MSG_ATTRIBUTES_TABLE, 0xffff_0000);
    io.write32(AR_BTCOEX_WL_WEIGHTS0, 0xffff_ffff);
    io.write32(AR_BTCOEX_WL_WEIGHTS1, 0xffff_ffff);
    io.write32(AR_BTCOEX_WL_WEIGHTS2, 0xffff_ffff);
    io.write32(AR_BTCOEX_WL_WEIGHTS3, 0xffff_ffff);
    rmw(io, AR_MCI_TX_CTRL, 0, AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE)?;
    io.delay_us(10);
    if mci.pa_lna_shared() {
        send_lna_take(io, mci, true);
        io.delay_us(5);
    }
    send_sys_sleeping(io, mci, true);
    Ok(())
}

/// `ar9003_mci_osla_setup`: program the one-step look-ahead tables and
/// the aggregation threshold.
fn osla_setup(io: &mut impl RegisterIo, mci: &Mci, enable: bool) -> Result<(), BringUpError> {
    if !enable {
        rmw(io, AR_BTCOEX_CTRL, AR_BTCOEX_CTRL_ONE_STEP_LOOK_AHEAD_EN, 0)?;
        return Ok(());
    }
    field(
        io,
        AR_MCI_SCHD_TABLE_2,
        AR_MCI_SCHD_TABLE_2_HW_BASED,
        AR_MCI_SCHD_TABLE_2_HW_BASED_S,
        1,
    )?;
    field(
        io,
        AR_MCI_SCHD_TABLE_2,
        AR_MCI_SCHD_TABLE_2_MEM_BASED,
        AR_MCI_SCHD_TABLE_2_MEM_BASED_S,
        1,
    )?;
    if mci.chip == Chip::Ar9565 {
        field(
            io,
            AR_MCI_MISC,
            AR_MCI_MISC_HW_FIX_EN,
            AR_MCI_MISC_HW_FIX_EN_S,
            1,
        )?;
    }
    if mci.config & ATH_MCI_CONFIG_DISABLE_AGGR_THRESH == 0 {
        let thresh = (mci.config & ATH_MCI_CONFIG_AGGR_THRESH) >> ATH_MCI_CONFIG_AGGR_THRESH_S;
        field(
            io,
            AR_BTCOEX_CTRL,
            AR_BTCOEX_CTRL_AGGR_THRESH,
            AR_BTCOEX_CTRL_AGGR_THRESH_S,
            thresh,
        )?;
        field(
            io,
            AR_BTCOEX_CTRL,
            AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN,
            AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN_S,
            1,
        )?;
    } else {
        field(
            io,
            AR_BTCOEX_CTRL,
            AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN,
            AR_BTCOEX_CTRL_TIME_TO_NEXT_BT_THRESH_EN_S,
            0,
        )?;
    }
    field(
        io,
        AR_BTCOEX_CTRL,
        AR_BTCOEX_CTRL_ONE_STEP_LOOK_AHEAD_EN,
        AR_BTCOEX_CTRL_ONE_STEP_LOOK_AHEAD_EN_S,
        1,
    )?;
    Ok(())
}

/// `ar9003_mci_stat_setup`: enable the AR9565 MCI debug counters when
/// `ATH_MCI_CONFIG_MCI_STAT_DBG` is set.
fn stat_setup(io: &mut impl RegisterIo, mci: &Mci) -> Result<(), BringUpError> {
    if mci.chip != Chip::Ar9565 {
        return Ok(());
    }
    if mci.config & ATH_MCI_CONFIG_MCI_STAT_DBG != 0 {
        field(
            io,
            AR_MCI_DBG_CNT_CTRL,
            AR_MCI_DBG_CNT_CTRL_ENABLE,
            AR_MCI_DBG_CNT_CTRL_ENABLE_S,
            1,
        )?;
        field(
            io,
            AR_MCI_DBG_CNT_CTRL,
            AR_MCI_DBG_CNT_CTRL_BT_LINKID,
            AR_MCI_DBG_CNT_CTRL_BT_LINKID_S,
            MCI_STAT_ALL_BT_LINKID,
        )?;
    } else {
        field(
            io,
            AR_MCI_DBG_CNT_CTRL,
            AR_MCI_DBG_CNT_CTRL_ENABLE,
            AR_MCI_DBG_CNT_CTRL_ENABLE_S,
            0,
        )?;
    }
    Ok(())
}

/// `ar9003_mci_set_btcoex_ctrl` for AR9565 with one shared PA/LNA
/// antenna: `AR_BTCOEX_CTRL` becomes `0x29b`.
fn set_btcoex_ctrl_9565_1ant(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let regval = (1 << AR_BTCOEX_CTRL_AR9462_MODE_S)
        | (1 << AR_BTCOEX_CTRL_WBTIMER_EN_S)
        | (1 << AR_BTCOEX_CTRL_PA_SHARED_S)
        | (1 << AR_BTCOEX_CTRL_LNA_SHARED_S)
        | (1 << AR_BTCOEX_CTRL_NUM_ANTENNAS_S)
        | (1 << AR_BTCOEX_CTRL_RX_CHAIN_MASK_S);
    field(
        io,
        AR_BTCOEX_CTRL2,
        AR_BTCOEX_CTRL2_TX_CHAIN_MASK,
        AR_BTCOEX_CTRL2_TX_CHAIN_MASK_S,
        0x1,
    )?;
    io.write32(AR_BTCOEX_CTRL, regval);
    Ok(())
}

/// `ar9003_mci_set_btcoex_ctrl` for AR9565 with two antennas:
/// `AR_BTCOEX_CTRL` becomes `0x303`.
fn set_btcoex_ctrl_9565_2ant(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let regval = (1 << AR_BTCOEX_CTRL_AR9462_MODE_S)
        | (1 << AR_BTCOEX_CTRL_WBTIMER_EN_S)
        | (2 << AR_BTCOEX_CTRL_NUM_ANTENNAS_S)
        | (1 << AR_BTCOEX_CTRL_RX_CHAIN_MASK_S);
    field(
        io,
        AR_BTCOEX_CTRL2,
        AR_BTCOEX_CTRL2_TX_CHAIN_MASK,
        AR_BTCOEX_CTRL2_TX_CHAIN_MASK_S,
        0x0,
    )?;
    io.write32(AR_BTCOEX_CTRL, regval);
    Ok(())
}

/// `ar9003_mci_set_btcoex_ctrl` for AR9462: `AR_BTCOEX_CTRL` becomes
/// `0x71b`.
fn set_btcoex_ctrl_9462(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let regval = (1 << AR_BTCOEX_CTRL_AR9462_MODE_S)
        | (1 << AR_BTCOEX_CTRL_WBTIMER_EN_S)
        | (1 << AR_BTCOEX_CTRL_PA_SHARED_S)
        | (1 << AR_BTCOEX_CTRL_LNA_SHARED_S)
        | (2 << AR_BTCOEX_CTRL_NUM_ANTENNAS_S)
        | (3 << AR_BTCOEX_CTRL_RX_CHAIN_MASK_S);
    io.write32(AR_BTCOEX_CTRL, regval);
    Ok(())
}

/// `ar9003_mci_reset`: program the GPM/schedule buffers, the BTCOEX
/// control word, OSLA, the LNA timeout and the MCI TX/RX reset pulses,
/// then prepare the interface and enable the MCI interrupt.
pub(in crate::ath9k) fn reset(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    en_int: bool,
    is_2g: bool,
    is_full_sleep: bool,
) -> Result<(), BringUpError> {
    let ctrl = io.read32(AR_BTCOEX_CTRL);
    if ctrl == 0xdeadbeef || ctrl == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_MCI_GPM_0, mci.gpm_addr);
    io.write32(AR_MCI_GPM_1, mci.gpm_len);
    io.write32(AR_MCI_SCHD_TABLE_0, mci.sched_addr);
    if mci.chip == Chip::Ar9565 {
        let ant = (mci.config & ATH_MCI_CONFIG_ANT_ARCH) >> ATH_MCI_CONFIG_ANT_ARCH_S;
        if ant == ATH_MCI_ANT_ARCH_1_ANT_PA_LNA_SHARED {
            set_btcoex_ctrl_9565_1ant(io)?;
        } else {
            set_btcoex_ctrl_9565_2ant(io)?;
        }
    } else {
        set_btcoex_ctrl_9462(io)?;
    }
    if is_2g && mci.config & ATH_MCI_CONFIG_DISABLE_OSLA == 0 {
        osla_setup(io, mci, true)?;
    } else {
        osla_setup(io, mci, false)?;
    }
    rmw(io, AR_PHY_GLB_CONTROL, 0, AR_BTCOEX_CTRL_SPDT_ENABLE)?;
    field(
        io,
        AR_BTCOEX_CTRL3,
        AR_BTCOEX_CTRL3_CONT_INFO_TIMEOUT,
        AR_BTCOEX_CTRL3_CONT_INFO_TIMEOUT_S,
        20,
    )?;
    field(
        io,
        AR_BTCOEX_CTRL2,
        AR_BTCOEX_CTRL2_RX_DEWEIGHT,
        AR_BTCOEX_CTRL2_RX_DEWEIGHT_S,
        0,
    )?;
    field(
        io,
        AR_PCU_MISC,
        AR_PCU_BT_ANT_PREVENT_RX,
        AR_PCU_BT_ANT_PREVENT_RX_S,
        0,
    )?;
    field(
        io,
        AR_BTCOEX_WL_LNA,
        AR_BTCOEX_WL_LNA_TIMEOUT,
        AR_BTCOEX_WL_LNA_TIMEOUT_S,
        0x3d090,
    )?;
    if mci.config & ATH_MCI_CONFIG_CONCUR_TX != 0 {
        field(
            io,
            AR_BTCOEX_CTRL2,
            AR_BTCOEX_CTRL2_DESC_BASED_TXPWR_ENABLE,
            AR_BTCOEX_CTRL2_DESC_BASED_TXPWR_ENABLE_S,
            0,
        )?;
        field(
            io,
            AR_BTCOEX_CTRL2,
            AR_BTCOEX_CTRL2_TXPWR_THRESH,
            AR_BTCOEX_CTRL2_TXPWR_THRESH_S,
            0x7f,
        )?;
        field(
            io,
            AR_BTCOEX_CTRL,
            AR_BTCOEX_CTRL_REDUCE_TXPWR,
            AR_BTCOEX_CTRL_REDUCE_TXPWR_S,
            0,
        )?;
        for i in 0..8u64 {
            io.write32(AR_BTCOEX_MAX_TXPWR0 + i * 4, 0x7f7f_7f7f);
        }
    }
    let clk_div = (mci.config & ATH_MCI_CONFIG_CLK_DIV) >> ATH_MCI_CONFIG_CLK_DIV_S;
    field(
        io,
        AR_MCI_TX_CTRL,
        AR_MCI_TX_CTRL_CLK_DIV,
        AR_MCI_TX_CTRL_CLK_DIV_S,
        clk_div,
    )?;
    rmw(io, AR_BTCOEX_CTRL, 0, AR_BTCOEX_CTRL_MCI_MODE_EN)?;
    let mut regval = io.read32(AR_MCI_COMMAND2);
    if regval == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    regval |= AR_MCI_COMMAND2_RESET_TX;
    io.write32(AR_MCI_COMMAND2, regval);
    io.delay_us(1);
    regval &= !AR_MCI_COMMAND2_RESET_TX;
    io.write32(AR_MCI_COMMAND2, regval);
    if is_full_sleep {
        mute_bt(io, mci)?;
        io.delay_us(100);
    }
    check_gpm_offset(io, mci);
    regval |= AR_MCI_COMMAND2_RESET_RX;
    io.write32(AR_MCI_COMMAND2, regval);
    io.delay_us(1);
    regval &= !AR_MCI_COMMAND2_RESET_RX;
    io.write32(AR_MCI_COMMAND2, regval);
    state(io, mci, MciState::InitGpmOffset)?;
    io.write32(
        AR_MCI_MSG_ATTRIBUTES_TABLE,
        (0xe801 << AR_MCI_MSG_ATTRIBUTES_TABLE_INVALID_HDR_S)
            | (0x0000 << AR_MCI_MSG_ATTRIBUTES_TABLE_CHECKSUM_S),
    );
    if mci.pa_lna_shared() {
        rmw(io, AR_MCI_TX_CTRL, AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE, 0)?;
    } else {
        rmw(io, AR_MCI_TX_CTRL, 0, AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE)?;
    }
    observation_set_up(io, mci)?;
    mci.ready = true;
    prep_interface(io, mci);
    stat_setup(io, mci)?;
    if en_int {
        enable_interrupt(io);
    }
    // AIC is hard-disabled in Linux (`ar9003_aic.c` returns false), so
    // no `ar9003_aic_start_normal` runs here.
    Ok(())
}

/// `ar9003_mci_stop_bt`: mute BT and turn the BTCOEX control off unless
/// the card is saving a full-sleep state.
pub(in crate::ath9k) fn stop_bt(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    save_fullsleep: bool,
) -> Result<(), BringUpError> {
    disable_interrupt(io);
    if mci.ready && !save_fullsleep {
        mute_bt(io, mci)?;
        io.delay_us(20);
        io.write32(AR_BTCOEX_CTRL, 0);
    }
    mci.bt_state = BtState::Sleep;
    mci.ready = false;
    Ok(())
}

/// `ar9003_mci_send_2g5g_status`: tell BT whether WLAN is on 2G or 5G
/// by toggling the band flag, when the link is awake and the update is
/// enabled.
fn send_2g5g_status(io: &mut impl RegisterIo, mci: &mut Mci, wait_done: bool) {
    if !mci.update_2g5g || mci.bt_state == BtState::Sleep {
        return;
    }
    let (to_clear, to_set) = if mci.is_2g {
        (MCI_2G_FLAGS_CLEAR_MASK, MCI_2G_FLAGS_SET_MASK)
    } else {
        (MCI_5G_FLAGS_CLEAR_MASK, MCI_5G_FLAGS_SET_MASK)
    };
    if to_clear != 0 {
        send_coex_bt_flags(io, mci, wait_done, BtFlagsOp::Clear, to_clear);
    }
    if to_set != 0 {
        send_coex_bt_flags(io, mci, wait_done, BtFlagsOp::Set, to_set);
    }
}

/// `ar9003_mci_2g5g_switch`: move the LNA/SPDT/OSLA state between the
/// 2G and 5G configurations after a band change.
pub(in crate::ath9k) fn switch_2g5g(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    force: bool,
) -> Result<(), BringUpError> {
    if !mci.update_2g5g && !force {
        return Ok(());
    }
    if mci.is_2g {
        send_2g5g_status(io, mci, true);
        send_lna_transfer(io, mci, true);
        io.delay_us(5);
        rmw(io, AR_MCI_TX_CTRL, AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE, 0)?;
        rmw(io, AR_PHY_GLB_CONTROL, AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL, 0)?;
        if mci.config & ATH_MCI_CONFIG_DISABLE_OSLA == 0 {
            osla_setup(io, mci, true)?;
        }
        if mci.chip == Chip::Ar9462 {
            io.write32(AR_SELFGEN_MASK, 0x02);
        }
    } else {
        send_lna_take(io, mci, true);
        io.delay_us(5);
        rmw(io, AR_MCI_TX_CTRL, 0, AR_MCI_TX_CTRL_DISABLE_LNA_UPDATE)?;
        rmw(io, AR_PHY_GLB_CONTROL, 0, AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL)?;
        osla_setup(io, mci, false)?;
        send_2g5g_status(io, mci, true);
    }
    Ok(())
}

/// `ar9003_mci_init_cal_req`: ask BT for a WLAN calibration window and
/// wait up to 50 ms for the grant. When no grant arrives the caller
/// must not reuse the previous calibration.
pub(in crate::ath9k) fn init_cal_req(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    is_reusable: &mut bool,
) {
    if mci.bt_state != BtState::Awake || mci.config & ATH_MCI_CONFIG_DISABLE_MCI_CAL != 0 {
        return;
    }
    let mut payload = [0u32; 4];
    gpm_set_cal_type(&mut payload, GpmSubtype::WlanCalReq as u8);
    payload[MCI_GPM_WLAN_CAL_W_SEQUENCE] = mci.wlan_cal_seq;
    mci.wlan_cal_seq = mci.wlan_cal_seq.wrapping_add(1);
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: false,
        },
    );
    if wait_for_gpm(io, mci, GpmSubtype::BtCalGrant as u8, 0, 50000) == 0 {
        *is_reusable = false;
    }
}

/// `ar9003_mci_init_cal_done`: report that WLAN calibration finished.
pub(in crate::ath9k) fn init_cal_done(io: &mut impl RegisterIo, mci: &mut Mci) {
    if mci.bt_state != BtState::Awake || mci.config & ATH_MCI_CONFIG_DISABLE_MCI_CAL != 0 {
        return;
    }
    let mut payload = [0u32; 4];
    gpm_set_cal_type(&mut payload, GpmSubtype::WlanCalDone as u8);
    payload[MCI_GPM_WLAN_CAL_W_SEQUENCE] = mci.wlan_cal_done;
    mci.wlan_cal_done = mci.wlan_cal_done.wrapping_add(1);
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: false,
        },
    );
}

/// `ar9003_mci_setup`: fill the DMA GPM buffer with the reserved
/// pattern, then run a full-sleep reset with the interrupt enabled.
pub(in crate::ath9k) fn setup(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    gpm_addr: u32,
    sched_addr: u32,
) -> Result<(), BringUpError> {
    mci.gpm_addr = gpm_addr;
    // `mci.c::ath_mci_setup` fills the whole DMA buffer with the
    // reserved pattern before the hw setup runs.
    mci.gpm_buf.fill(MCI_GPM_RSVD_PATTERN);
    mci.gpm_len = MCI_GPM_MAX_ENTRY as u32;
    mci.sched_addr = sched_addr;
    reset(io, mci, true, true, true)
}

/// `ar9003_mci_cleanup`: turn off MCI and Jupiter mode, disable the MCI
/// interrupt.
pub(in crate::ath9k) fn cleanup(io: &mut impl RegisterIo) {
    io.write32(AR_BTCOEX_CTRL, 0x00);
    disable_interrupt(io);
}

/// `ar9003_mci_state`: the state machine the driver layer drives
/// (`mci.c::ath_mci_state` callers).
pub(in crate::ath9k) fn state(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    state_type: MciState,
) -> Result<u32, BringUpError> {
    let mut value = 0u32;
    match state_type {
        MciState::Enable => {
            if mci.ready {
                value = io.read32(AR_BTCOEX_CTRL);
                if value == 0xdeadbeef || value == u32::MAX {
                    value = 0;
                }
            }
            value &= AR_BTCOEX_CTRL_MCI_MODE_EN;
        }
        MciState::InitGpmOffset => {
            value = (io.read32(AR_MCI_GPM_1) & AR_MCI_GPM_WRITE_PTR) >> AR_MCI_GPM_WRITE_PTR_S;
            if value < mci.gpm_len {
                mci.gpm_idx = value;
            } else {
                mci.gpm_idx = 0;
            }
        }
        MciState::LastSchdMsgOffset => {
            value = (io.read32(AR_MCI_RX_STATUS) & AR_MCI_RX_LAST_SCHD_MSG_INDEX)
                >> AR_MCI_RX_LAST_SCHD_MSG_INDEX_S;
            value <<= 4;
        }
        MciState::RemoteSleep => {
            value = if (io.read32(AR_MCI_RX_STATUS) & AR_MCI_RX_REMOTE_SLEEP)
                >> AR_MCI_RX_REMOTE_SLEEP_S
                != 0
            {
                BtState::Sleep as u32
            } else {
                BtState::Awake as u32
            };
        }
        MciState::SetBtAwake => {
            mci.bt_state = BtState::Awake;
            send_coex_version_query(io, mci, true);
            send_coex_wlan_channels(io, mci, true);
            if mci.unhalt_bt_gpm {
                send_coex_halt_bt_gpm(io, mci, false, true);
            }
            switch_2g5g(io, mci, false)?;
        }
        MciState::ResetReqWake => {
            reset_req_wakeup(io);
            mci.update_2g5g = true;
            if mci.config & ATH_MCI_CONFIG_MCI_OBS_MASK != 0
                && io.read32(AR_GLB_GPIO_CONTROL) & ATH_MCI_CONFIG_MCI_OBS_GPIO
                    != ATH_MCI_CONFIG_MCI_OBS_GPIO
            {
                observation_set_up(io, mci)?;
            }
        }
        MciState::SendWlanCoexVersion => send_coex_version_response(io, mci, true),
        MciState::SendVersionQuery => send_coex_version_query(io, mci, true),
        MciState::SendStatusQuery => {
            send_coex_bt_status_query(io, mci, true, MCI_GPM_COEX_QUERY_BT_TOPOLOGY);
        }
        MciState::RecoverRx => {
            let tsf = io.read32(AR_TSF_L32);
            if tsf.wrapping_sub(mci.last_recovery) <= MCI_RECOVERY_DUR_TSF {
                // (MCI) ignore Rx recovery.
            } else {
                mci.last_recovery = tsf;
                prep_interface(io, mci);
                mci.query_bt = true;
                mci.need_flush_btinfo = true;
                send_coex_wlan_channels(io, mci, true);
                switch_2g5g(io, mci, false)?;
            }
        }
        MciState::NeedFtpStomp => {
            value = u32::from(mci.config & ATH_MCI_CONFIG_DISABLE_FTP_STOMP == 0);
        }
        MciState::NeedFlushBtInfo => {
            value = u32::from(!mci.unhalt_bt_gpm && mci.need_flush_btinfo);
            mci.need_flush_btinfo = false;
        }
        // AIC is hard-disabled in Linux (`ar9003_aic.c` returns false),
        // so these read 0 exactly as in Linux.
        MciState::AicCal | MciState::AicStart | MciState::AicCalReset | MciState::AicCalSingle => {}
        _ => {}
    }
    Ok(value)
}

/// `ar9003_mci_bt_gain_ctrl`: hand the LNA to BT for a gain-control
/// operation and force a 2G/5G status refresh on the next scan.
pub(in crate::ath9k) fn bt_gain_ctrl(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
) -> Result<(), BringUpError> {
    send_lna_take(io, mci, true);
    io.delay_us(50);
    rmw(io, AR_PHY_GLB_CONTROL, 0, AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL)?;
    mci.is_2g = false;
    mci.update_2g5g = true;
    send_2g5g_status(io, mci, true);
    // Force another 2g5g update at next scanning.
    mci.update_2g5g = true;
    Ok(())
}

/// `ar9003_mci_set_power_awake`: work around the LNA-control race on
/// power-up by toggling `AR_BTCOEX_RC` bit 0 when BT is asleep and the
/// LNA control value is 2. The two deadbeef loops are bounded here
/// (`POWER_AWAKE_WAIT_BOUND` iterations); Linux loops forever on a dead
/// card, which this port refuses to do.
pub(in crate::ath9k) fn set_power_awake(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let mut btcoex_ctrl2 = 0u32;
    for _ in 0..POWER_AWAKE_WAIT_BOUND {
        btcoex_ctrl2 = io.read32(AR_BTCOEX_CTRL2);
        if btcoex_ctrl2 != 0xdeadbeef {
            break;
        }
        io.delay_us(10);
    }
    io.write32(AR_BTCOEX_CTRL2, btcoex_ctrl2 | AR_BTCOEX_CTRL2_GPIO_OBS_SEL);
    let mut diag_sw = 0u32;
    for _ in 0..POWER_AWAKE_WAIT_BOUND {
        diag_sw = io.read32(AR_DIAG_SW);
        if diag_sw != 0xdeadbeef {
            break;
        }
        io.delay_us(10);
    }
    io.write32(AR_DIAG_SW, diag_sw | (1 << 27) | (1 << 19) | (1 << 18));
    let lna_ctrl = io.read32(AR_OBS_BUS_CTRL) & 0x3;
    let bt_sleep =
        (io.read32(AR_MCI_RX_STATUS) & AR_MCI_RX_REMOTE_SLEEP) >> AR_MCI_RX_REMOTE_SLEEP_S != 0;
    io.write32(AR_BTCOEX_CTRL2, btcoex_ctrl2);
    io.write32(AR_DIAG_SW, diag_sw);
    if bt_sleep && lna_ctrl == 2 {
        rmw(io, AR_BTCOEX_RC, 0, 0x1)?;
        rmw(io, AR_BTCOEX_RC, 0x1, 0)?;
        io.delay_us(50);
    }
    Ok(())
}

/// `ar9003_mci_check_gpm_offset`: if BT wrote new GPMs while the driver
/// was away, mark the BT info stale and restart the walk from slot 0.
pub(in crate::ath9k) fn check_gpm_offset(io: &mut impl RegisterIo, mci: &mut Mci) {
    let offset = (io.read32(AR_MCI_GPM_1) & AR_MCI_GPM_WRITE_PTR) >> AR_MCI_GPM_WRITE_PTR_S;
    if mci.gpm_idx == offset {
        return;
    }
    mci.query_bt = true;
    mci.need_flush_btinfo = true;
    mci.gpm_idx = 0;
}

/// `ar9003_mci_get_next_gpm_offset`: find the next valid GPM slot to
/// read, skipping reserved slots, and return its byte offset plus
/// whether more GPMs follow. `MCI_GPM_INVALID` when none remain.
pub(in crate::ath9k) fn get_next_gpm_offset(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
) -> (u32, bool) {
    io.write32(AR_MCI_INTERRUPT_RX_MSG_RAW, AR_MCI_INTERRUPT_RX_MSG_GPM);
    let gpm_ptr = (io.read32(AR_MCI_GPM_1) & AR_MCI_GPM_WRITE_PTR) >> AR_MCI_GPM_WRITE_PTR_S;
    let mut offset = gpm_ptr;
    if offset == 0 {
        offset = mci.gpm_len - 1;
    } else if offset >= mci.gpm_len {
        if offset != 0xffff {
            offset = 0;
        }
    } else {
        offset -= 1;
    }
    if offset == 0xffff || gpm_ptr == mci.gpm_idx {
        return (MCI_GPM_INVALID, MCI_GPM_NOMORE);
    }
    let mut more_gpm;
    loop {
        if offset != mci.gpm_idx {
            more_gpm = MCI_GPM_MORE;
        } else {
            more_gpm = MCI_GPM_NOMORE;
        }
        let mut temp_index = mci.gpm_idx;
        if temp_index >= mci.gpm_len {
            temp_index = 0;
        }
        mci.gpm_idx += 1;
        if mci.gpm_idx >= mci.gpm_len {
            mci.gpm_idx = 0;
        }
        if is_gpm_valid(mci, temp_index) {
            offset = temp_index;
            break;
        }
        if more_gpm == MCI_GPM_NOMORE {
            offset = MCI_GPM_INVALID;
            break;
        }
    }
    if offset != MCI_GPM_INVALID {
        offset <<= 4;
    }
    (offset, more_gpm)
}

/// `ar9003_mci_set_bt_version`: record the BT controller version
/// reported in a coex-version GPM.
pub(in crate::ath9k) fn set_bt_version(mci: &mut Mci, major: u8, minor: u8) {
    mci.bt_ver_major = major;
    mci.bt_ver_minor = minor;
    mci.bt_version_known = true;
}

/// `ar9003_mci_send_wlan_channels`: mark the channel map dirty and
/// send it to BT.
pub(in crate::ath9k) fn send_wlan_channels(io: &mut impl RegisterIo, mci: &mut Mci) {
    mci.wlan_channels_update = true;
    send_coex_wlan_channels(io, mci, true);
}

/// `ar9003_mci_get_max_txpower`: the concurrent-TX power cap for a 2G
/// HT20/HT40 channel, or `None` when concurrent TX is off or the mode
/// has no cap. Linux returns -1 in those cases.
pub(in crate::ath9k) fn get_max_txpower(mci: &Mci, ctlmode: u8) -> Option<u16> {
    if !mci.concur_tx {
        return None;
    }
    if ctlmode == CTL_2GHT20 {
        Some(ATH_BTCOEX_HT20_MAX_TXPOWER)
    } else if ctlmode == CTL_2GHT40 {
        Some(ATH_BTCOEX_HT40_MAX_TXPOWER)
    } else {
        None
    }
}

/// Clear one BT channel bit in the WLAN channel map
/// (`mci.c::MCI_GPM_CLR_CHANNEL_BIT`): the map starts at payload byte
/// `MCI_GPM_COEX_B_CHANNEL_MAP`, so BT channel `i` is payload bit
/// `48 + i`.
fn clear_channel_bit(map: &mut [u32; 4], bt_chan: u16) {
    let bit = MCI_GPM_COEX_B_CHANNEL_MAP * 8 + usize::from(bt_chan);
    map[bit / 32] &= !(1u32 << (bit % 32));
}

/// `ath_mci_update_wlan_channels` (`mci.c`): rebuild the WLAN channel
/// map for the current channel and send it to BT. `channel_mhz` is the
/// channel centre frequency; Linux skips non-2GHz channels
/// (`IS_CHAN_2GHZ` is `!CHANNEL_5GHZ`, and 2.4 GHz channels are all
/// below 4000 MHz while 5 GHz channels start at 5180 MHz). With
/// `allow_all` the map stays fully open; otherwise the WLAN channel
/// (±20 MHz for HT40, plus a 7-channel guard) is cleared from it.
pub(in crate::ath9k) fn update_wlan_channels(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    channel_mhz: u16,
    ht40: Ht40,
    allow_all: bool,
) -> Result<(), BringUpError> {
    if channel_mhz >= 4000 {
        return Ok(());
    }
    let mut channelmap = [0x0000_0000u32, 0xffff_0000, 0xffff_ffff, 0x7fff_ffff];
    if !allow_all {
        let wlan_chan = i32::from(channel_mhz) - 2402;
        let mut chan_start = wlan_chan - 10;
        let mut chan_end = wlan_chan + 10;
        match ht40 {
            Ht40::Plus => chan_end += 20,
            Ht40::Minus => chan_start -= 20,
            Ht40::None => {}
        }
        chan_start -= 7;
        chan_end += 7;
        if chan_start < 0 {
            chan_start = 0;
        }
        if chan_end >= i32::from(MCI_NUM_BT_CHANNELS) {
            chan_end = i32::from(MCI_NUM_BT_CHANNELS) - 1;
        }
        let mut i = chan_start;
        while i < chan_end {
            clear_channel_bit(&mut channelmap, i as u16);
            i += 1;
        }
    }
    mci.wlan_channels = channelmap;
    send_wlan_channels(io, mci);
    state(io, mci, MciState::SendVersionQuery)?;
    Ok(())
}

/// Handle one BT calibration GPM inside the interrupt bottom half
/// (`ath_mci_cal_msg`): a BT calibration request while awake starts a
/// reset (`InterruptOutcome.reset_requested`), a grant answers with
/// WLAN calibration done.
fn cal_msg(io: &mut impl RegisterIo, mci: &mut Mci, subtype: u8, outcome: &mut InterruptOutcome) {
    if subtype == GpmSubtype::BtCalReq as u8 {
        if mci.bt_state == BtState::Awake {
            mci.bt_state = BtState::CalStart;
            outcome.reset_requested = true;
        }
    } else if subtype == GpmSubtype::BtCalGrant as u8 {
        let mut payload = [0u32; 4];
        gpm_set_cal_type(&mut payload, GpmSubtype::WlanCalDone as u8);
        send_message(
            io,
            mci,
            SendMessageParams {
                header: Msg::Gpm,
                flag: 0,
                payload: &payload,
                len: 16,
                wait_done: false,
                check_bt: true,
            },
        );
    }
}

/// Record that the band changed, requesting a 2G/5G update when the
/// previous band differs (`ath_mci_2g5g_changed`).
fn two_g5g_changed(mci: &mut Mci, is_2g: bool) {
    if !mci.update_2g5g && mci.is_2g != is_2g {
        mci.update_2g5g = true;
    }
    mci.is_2g = is_2g;
}

/// `ar9003_mci_start_reset`: grant BT the calibration window and wait
/// up to 25 ms for its calibration-done GPM. Returns true when a
/// calibration reset actually ran.
pub(in crate::ath9k) fn start_reset(io: &mut impl RegisterIo, mci: &mut Mci, is_2g: bool) -> bool {
    two_g5g_changed(mci, is_2g);
    if mci.bt_state != BtState::CalStart {
        return false;
    }
    mci.bt_state = BtState::Cal;
    // MCI FIX: disable mci interrupt here, to avoid SW_MSG_DONE or
    // RX_MSG bits triggering MCI_INT reentry.
    disable_interrupt(io);
    let mut payload = [0u32; 4];
    gpm_set_cal_type(&mut payload, GpmSubtype::WlanCalGrant as u8);
    send_message(
        io,
        mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: false,
        },
    );
    // Wait for BT calibration to complete (25 ms).
    wait_for_gpm(io, mci, GpmSubtype::BtCalDone as u8, 0, 25000);
    mci.bt_state = BtState::Awake;
    enable_interrupt(io);
    true
}

/// `ar9003_mci_end_reset`: after a reset, wake BT back up when it
/// requested a reset while WLAN was on 2G. Returns
/// `EndReset::RecalibrationNeeded` when the caller must re-run
/// calibration; the caller re-arms the TIMING4 gain/DC/IQ-cal bit via
/// `set_timing4_gain_dc_iq_cal` afterwards.
pub(in crate::ath9k) fn end_reset(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
    is_2g: bool,
) -> Result<EndReset, BringUpError> {
    if !mci.ready {
        return Ok(EndReset::Idle);
    }
    if !is_2g || mci.bt_state != BtState::Sleep {
        enable_interrupt(io);
        return Ok(EndReset::Idle);
    }
    if !check_int(io, AR_MCI_INTERRUPT_RX_MSG_REMOTE_RESET)
        && !check_int(io, AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE)
    {
        enable_interrupt(io);
        return Ok(EndReset::Idle);
    }
    io.write32(
        AR_MCI_INTERRUPT_RX_MSG_RAW,
        AR_MCI_INTERRUPT_RX_MSG_REMOTE_RESET | AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE,
    );
    remote_reset(io, mci, true);
    send_sys_waking(io, mci, true);
    io.delay_us(1);
    if is_2g {
        send_lna_transfer(io, mci, true);
    }
    mci.bt_state = BtState::Awake;
    // Linux clears the TXIQ/TXCL/RTT done flags and re-runs calibration
    // here; the caller owns that run and re-arms the bit afterwards.
    field(
        io,
        AR_PHY_TIMING4,
        1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
        AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
        0,
    )?;
    enable_interrupt(io);
    Ok(EndReset::RecalibrationNeeded)
}

/// Re-arm (or clear) the `AR_PHY_TIMING4` gain/DC/IQ-calibration bit
/// `end_reset` clears before the recalibration run.
pub(in crate::ath9k) fn set_timing4_gain_dc_iq_cal(
    io: &mut impl RegisterIo,
    enable: bool,
) -> Result<(), BringUpError> {
    field(
        io,
        AR_PHY_TIMING4,
        1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
        AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
        u32::from(enable),
    )
}

/// `ath_mci_intr`: the MCI interrupt bottom half. Walks the GPM ring,
/// dispatching calibration GPMs to the cal handshake and coex-agent
/// GPMs to the profile handler, and reports whether a BT calibration
/// reset was requested. HW-message bits (LNA control/info, CONT
/// info/nack/rst) are already cleared in hardware by `get_isr`; Linux
/// only logs CONT_INFO here and sends a driver-level NOOP on
/// invalid-header/cont-timeout, neither of which has a hw effect.
pub(in crate::ath9k) fn handle_interrupt(
    io: &mut impl RegisterIo,
    mci: &mut Mci,
) -> Result<InterruptOutcome, BringUpError> {
    let mut outcome = InterruptOutcome::default();
    let (mci_int, mut mci_int_rxmsg) = get_interrupt(mci);
    if state(io, mci, MciState::Enable)? == 0 {
        state(io, mci, MciState::InitGpmOffset)?;
        return Ok(outcome);
    }
    if mci_int_rxmsg & AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE != 0 {
        let payload = [0xffff_ffffu32, 0xffff_ffff, 0xffff_ffff, 0xffff_ff00];
        send_message(
            io,
            mci,
            SendMessageParams {
                header: Msg::RemoteReset,
                flag: 0,
                payload: &payload,
                len: 16,
                wait_done: true,
                check_bt: false,
            },
        );
        send_message(
            io,
            mci,
            SendMessageParams {
                header: Msg::SysWaking,
                flag: 0,
                payload: &[],
                len: 0,
                wait_done: true,
                check_bt: false,
            },
        );
        mci_int_rxmsg &= !AR_MCI_INTERRUPT_RX_MSG_REQ_WAKE;
        state(io, mci, MciState::ResetReqWake)?;
        state(io, mci, MciState::SetBtAwake)?;
    }
    if mci_int_rxmsg & AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING != 0 {
        mci_int_rxmsg &= !AR_MCI_INTERRUPT_RX_MSG_SYS_WAKING;
        if mci.bt_state == BtState::Sleep
            && state(io, mci, MciState::RemoteSleep)? != BtState::Sleep as u32
        {
            state(io, mci, MciState::SetBtAwake)?;
        }
    }
    if mci_int_rxmsg & AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING != 0 {
        mci_int_rxmsg &= !AR_MCI_INTERRUPT_RX_MSG_SYS_SLEEPING;
        if mci.bt_state == BtState::Awake
            && state(io, mci, MciState::RemoteSleep)? != BtState::Awake as u32
        {
            mci.bt_state = BtState::Sleep;
        }
    }
    let mut skip_gpm = false;
    if mci_int & (AR_MCI_INTERRUPT_RX_INVALID_HDR | AR_MCI_INTERRUPT_CONT_INFO_TIMEOUT) != 0 {
        state(io, mci, MciState::RecoverRx)?;
        skip_gpm = true;
    }
    if mci_int_rxmsg & AR_MCI_INTERRUPT_RX_MSG_SCHD_INFO != 0 {
        mci_int_rxmsg &= !AR_MCI_INTERRUPT_RX_MSG_SCHD_INFO;
        state(io, mci, MciState::LastSchdMsgOffset)?;
    }
    if mci_int_rxmsg & AR_MCI_INTERRUPT_RX_MSG_GPM != 0 {
        // (No local clear: the GPM walk is the last use of the latched
        // cause here. Linux clears the bit before its trailing CONT_INFO
        // handling, which has no hw effect in this port.)
        let mut more_data = MCI_GPM_MORE;
        while more_data == MCI_GPM_MORE {
            let (offset, more) = get_next_gpm_offset(io, mci);
            more_data = more;
            if offset == MCI_GPM_INVALID {
                break;
            }
            let off = offset as usize;
            let subtype = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_TYPE];
            let opcode = mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_OPCODE];
            if !skip_gpm {
                if gpm_is_cal_type(subtype) {
                    cal_msg(io, mci, subtype, &mut outcome);
                } else if subtype == GpmSubtype::CoexAgent as u8 {
                    let slot: [u8; 16] = mci.gpm_buf[off..off + 16]
                        .try_into()
                        .expect("GPM slot is 16 bytes");
                    process_gpm_extra(io, mci, subtype, opcode, &slot);
                    process_profile_msg(io, mci, opcode, &slot)?;
                }
            }
            outcome.gpm_seen += 1;
            recycle_gpm(mci, off);
        }
    }
    Ok(outcome)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
