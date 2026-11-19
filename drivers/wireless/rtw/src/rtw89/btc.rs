//! RTW89 BT-coexistence H2C — Stage-10.
//!
//! The Realtek combo chips (8852A/B/C, 8851B, 8922A) ship an embedded
//! BT firmware that needs WLAN-side coexistence hints sent via a
//! dedicated H2C subprotocol. Linux routes these through the standard
//! H2C path but with a per-BT class space (`enum rtw89_btc_btf_h2c_class`,
//! `fw.h:2345`):
//!
//! - `BTFC_SET` (0x10) — write-side commands.
//! - `BTFC_GET` (0x11) — read-back commands.
//! - `BTFC_FW_EVENT` (0x12) — events from BT firmware.
//!
//! Each `SET` command takes a `CXHDR` (type + len, `fw.h:2419`)
//! followed by a per-command payload. The `cxdrvinfo` sub-enum
//! (`fw.h:2379`) keys the payloads.
//!
//! ## What lands here
//!
//! - Class + drvinfo constants.
//! - 2-byte CXHDR + 3-byte v7 CXHDR encoders.
//! - Empty-payload SET helpers (CTRL, INIT, RUN — the three the
//!   driver fires at bring-up).
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/fw.h:2345..2422` — class/set/cxdrvinfo enums + CXHDR.
//! - Linux `rtw89/coex.c::rtw89_btc_fw_set_drv_info` — the SET path
//!   that wraps each cxdrvinfo into a SET command.

#![allow(dead_code)]

use super::h2c::H2cBuilder;
use super::txrx::H2C_HEADER_LEN;

// ── Class IDs ────────────────────────────────────────────────────────

/// `BTFC_SET` (0x10) — write-side BT-coex commands. `fw.h:2346`.
pub const BTFC_SET: u8 = 0x10;
/// `BTFC_GET` (0x11) — read-side. `fw.h:2347`.
pub const BTFC_GET: u8 = 0x11;
/// `BTFC_FW_EVENT` (0x12) — events. `fw.h:2348`.
pub const BTFC_FW_EVENT: u8 = 0x12;

// ── SET sub-commands ────────────────────────────────────────────────
//
// Per `enum rtw89_btc_btf_set` (`fw.h:2351`).

pub const SET_REPORT_EN: u8 = 0x0;
pub const SET_SLOT_TABLE: u8 = 0x1;
pub const SET_MREG_TABLE: u8 = 0x2;
pub const SET_CX_POLICY: u8 = 0x3;
pub const SET_GPIO_DBG: u8 = 0x4;
pub const SET_DRV_INFO: u8 = 0x5;
pub const SET_DRV_EVENT: u8 = 0x6;
pub const SET_BT_WREG_ADDR: u8 = 0x7;
pub const SET_BT_WREG_VAL: u8 = 0x8;
pub const SET_BT_RREG_ADDR: u8 = 0x9;
pub const SET_BT_WL_CH_INFO: u8 = 0xA;
pub const SET_BT_INFO_REPORT: u8 = 0xB;
pub const SET_BT_IGNORE_WLAN_ACT: u8 = 0xC;
pub const SET_BT_TX_PWR: u8 = 0xD;
pub const SET_BT_LNA_CONSTRAIN: u8 = 0xE;
pub const SET_BT_QUERY_DEV_LIST: u8 = 0xF;
pub const SET_BT_QUERY_DEV_INFO: u8 = 0x10;
pub const SET_BT_PSD_REPORT: u8 = 0x11;
pub const SET_H2C_TEST: u8 = 0x12;
pub const SET_IOFLD_RF: u8 = 0x13;
pub const SET_IOFLD_BB: u8 = 0x14;
pub const SET_IOFLD_MAC: u8 = 0x15;
pub const SET_IOFLD_SCBD: u8 = 0x16;
pub const SET_H2C_MACRO: u8 = 0x17;

// ── cxdrvinfo sub-types ─────────────────────────────────────────────
//
// Per `enum rtw89_btc_cxdrvinfo` (`fw.h:2379`).

pub const CXDRVINFO_INIT: u8 = 0;
pub const CXDRVINFO_ROLE: u8 = 1;
pub const CXDRVINFO_DBCC: u8 = 2;
pub const CXDRVINFO_SMAP: u8 = 3;
pub const CXDRVINFO_RFK: u8 = 4;
pub const CXDRVINFO_RUN: u8 = 5;
pub const CXDRVINFO_CTRL: u8 = 6;
pub const CXDRVINFO_SCAN: u8 = 7;
pub const CXDRVINFO_TRX: u8 = 8;
pub const CXDRVINFO_TXPWR: u8 = 9;
pub const CXDRVINFO_FDDT: u8 = 0xA;
pub const CXDRVINFO_MLO: u8 = 0xB;
pub const CXDRVINFO_OSI: u8 = 0xC;

// ── CXHDR ───────────────────────────────────────────────────────────

/// `rtw89_h2c_cxhdr` — 2-byte header. `fw.h:2419`.
pub const CXHDR_LEN: usize = 2;
/// `rtw89_h2c_cxhdr_v7` — 3-byte header (adds version). `fw.h:2424`.
pub const CXHDR_V7_LEN: usize = 3;

/// Encode a 2-byte CXHDR into `out`.
pub fn encode_cxhdr(cxtype: u8, len: u8, out: &mut [u8]) -> Option<()> {
    if out.len() < CXHDR_LEN {
        return None;
    }
    out[0] = cxtype;
    out[1] = len;
    Some(())
}

/// Encode a 3-byte v7 CXHDR (type, ver, len) into `out`.
pub fn encode_cxhdr_v7(cxtype: u8, ver: u8, len: u8, out: &mut [u8]) -> Option<()> {
    if out.len() < CXHDR_V7_LEN {
        return None;
    }
    out[0] = cxtype;
    out[1] = ver;
    out[2] = len;
    Some(())
}

// ── BT-Coex H2C builder ─────────────────────────────────────────────
//
// All BTC commands ride the standard H2C transport. The category here
// is `H2C_CAT_OUTSRC` (BTC lives in the outsourced firmware blob);
// the class is `BTFC_SET` etc.

use super::h2c::H2C_CAT_OUTSRC;

/// Build a BTC SET H2C with a CXHDR + payload. `func` is the
/// cxdrvinfo sub-type (`CXDRVINFO_*`).
pub fn make_btc_set_h2c(func: u8, seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_OUTSRC, BTFC_SET, func).with_seq(seq)
}

/// Build a complete BT-coex SET command into `out`:
///
/// `[H2C 8-byte header] [CXHDR 2 bytes] [payload]`
///
/// Returns total wire length.
pub fn build_btc_set_cmd(cxtype: u8, seq: u8, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let cmd_payload_len = CXHDR_LEN + payload.len();
    let total = H2C_HEADER_LEN + cmd_payload_len;
    if out.len() < total {
        return None;
    }
    let h2c = make_btc_set_h2c(cxtype, seq);
    let mut cxpayload = [0u8; 256];
    if payload.len() + CXHDR_LEN > cxpayload.len() {
        return None;
    }
    encode_cxhdr(cxtype, payload.len() as u8, &mut cxpayload[..CXHDR_LEN])?;
    cxpayload[CXHDR_LEN..CXHDR_LEN + payload.len()].copy_from_slice(payload);
    h2c.build(&cxpayload[..cmd_payload_len], out)
}

// ── Pre-built bring-up commands ─────────────────────────────────────

/// Build a `CXDRVINFO_INIT` SET — the first BTC command driver sends.
/// Payload shape (`struct rtw89_btc_wl_role_info`) is large in Linux;
/// the AX baseline accepts a zero-payload init followed by ROLE.
pub fn make_btc_init_h2c(seq: u8) -> H2cBuilder {
    make_btc_set_h2c(CXDRVINFO_INIT, seq).with_done_ack(true)
}

/// Build a `CXDRVINFO_CTRL` SET — control toggles (manual/test mode).
pub fn make_btc_ctrl_h2c(seq: u8) -> H2cBuilder {
    make_btc_set_h2c(CXDRVINFO_CTRL, seq)
}

/// Build a `CXDRVINFO_RUN` SET — kick the BTC state machine.
pub fn make_btc_run_h2c(seq: u8) -> H2cBuilder {
    make_btc_set_h2c(CXDRVINFO_RUN, seq).with_done_ack(true)
}

/// Build a `CXDRVINFO_SCAN` SET — scan-start hint to the BT firmware
/// so it can stagger its own channel hops.
pub fn make_btc_scan_h2c(seq: u8) -> H2cBuilder {
    make_btc_set_h2c(CXDRVINFO_SCAN, seq)
}

/// Build a `CXDRVINFO_TRX` SET — sent on every traffic-state change so
/// BT firmware can adapt the time-slicing.
pub fn make_btc_trx_h2c(seq: u8) -> H2cBuilder {
    make_btc_set_h2c(CXDRVINFO_TRX, seq)
}
