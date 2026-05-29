//! RTW89 H2C (Host-to-Card) command dispatch — Stage-6.
//!
//! The rtw89 firmware exposes a category/class/function command space.
//! Every H2C command goes through the 8-byte header from
//! `txrx::encode_h2c_header` followed by a payload appropriate to the
//! (category, class, function) tuple.
//!
//! This module enumerates the categories and the classes/functions
//! we'll actually use during association + data path bring-up, plus
//! provides a `H2cBuilder` that wraps `encode_h2c_header` and produces
//! a ready-to-DMA byte buffer.
//!
//! ## Categories
//!
//! - **`H2C_CAT_TEST` (0x0)** — debug exception triggers.
//! - **`H2C_CAT_MAC` (0x1)** — most MAC commands (FW info, FW download,
//!   frame exchange, joininfo, scan offload).
//! - **`H2C_CAT_OUTSRC` (0x2)** — rate adaptation, RF tables, RFK
//!   offloads (TSSI / IQK / DPK).
//!
//! ## Classes (subset we use)
//!
//! ### MAC category
//! - `H2C_CL_FW_INFO` (0) — `LOG_CFG`, `MAC_GENERAL_PKT`.
//! - `H2C_CL_MAC_WOW` (1) — keep-alive, GTK/ARP offload.
//! - `H2C_CL_MAC_PS` (2) — LPS parameters.
//! - `H2C_CL_MAC_FWDL` (3) — firmware download (`FWHDR_DL`).
//! - `H2C_CL_MAC_FR_EXCHG` (5) — `BCN_UPD`, `CCTLINFO_UD`.
//! - `H2C_CL_MAC_ADDR_CAM_UPDATE` (6) — address-CAM updates.
//! - `H2C_CL_MAC_MEDIA_RPT` (8) — `JOININFO`, `FWROLE_MAINTAIN`.
//! - `H2C_CL_MAC_FW_OFLD` (9) — packet offload, scan offload.
//!
//! ### OUTSRC category
//! - `H2C_CL_OUTSRC_RA` (1) — `RA_MACIDCFG`.
//! - `H2C_CL_OUTSRC_DM` (2) — DM (digital monitor) configs.
//! - `H2C_CL_OUTSRC_RF_FW_RFK` (0xB) — RF calibration offloads.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/fw.h:4505..4730` — category/class/function constants.
//! - Linux `rtw89/fw.c::rtw89_h2c_pkt_set_hdr` (~L1564) — header builder.
//! - Linux `rtw89/fw.c::rtw89_fw_h2c_*` — per-command senders.

#![allow(dead_code)]

use super::txrx::{encode_h2c_header, FWCMD_TYPE_H2C, H2C_HEADER_LEN};

// ── Category constants ──────────────────────────────────────────────

/// `H2C_CAT_TEST` (0x0) — test category. `fw.h:4505`.
pub const H2C_CAT_TEST: u8 = 0x0;
/// `H2C_CAT_MAC` (0x1) — MAC category. `fw.h:4511`.
pub const H2C_CAT_MAC: u8 = 0x1;
/// `H2C_CAT_OUTSRC` (0x2) — outsourced (rate / RF) category. `fw.h:4694`.
pub const H2C_CAT_OUTSRC: u8 = 0x2;

// ── MAC-category class constants ────────────────────────────────────

/// `H2C_CL_FW_INFO` (0). `fw.h:4514`.
pub const H2C_CL_FW_INFO: u8 = 0x0;
/// `H2C_FUNC_LOG_CFG` (0). `fw.h:4515`. Class 0, function 0.
pub const H2C_FUNC_LOG_CFG: u8 = 0x0;
/// `H2C_FUNC_MAC_GENERAL_PKT` (1). `fw.h:4516`.
pub const H2C_FUNC_MAC_GENERAL_PKT: u8 = 0x1;

/// `H2C_CL_MAC_WOW` (1). `fw.h:4519`.
pub const H2C_CL_MAC_WOW: u8 = 0x1;
/// `H2C_FUNC_KEEP_ALIVE` (0). `fw.h:4521`.
pub const H2C_FUNC_KEEP_ALIVE: u8 = 0x0;

/// `H2C_CL_MAC_PS` (2). `fw.h:4542`.
pub const H2C_CL_MAC_PS: u8 = 0x2;
/// `H2C_FUNC_MAC_LPS_PARM` (0). `fw.h:4544`.
pub const H2C_FUNC_MAC_LPS_PARM: u8 = 0x0;

/// `H2C_CL_MAC_FWDL` (3). `fw.h:4560`.
pub const H2C_CL_MAC_FWDL: u8 = 0x3;
/// `H2C_FUNC_MAC_FWHDR_DL` (0). `fw.h:4561`.
pub const H2C_FUNC_MAC_FWHDR_DL: u8 = 0x0;

/// `H2C_CL_MAC_FR_EXCHG` (5). `fw.h:4564`.
pub const H2C_CL_MAC_FR_EXCHG: u8 = 0x5;
/// `H2C_FUNC_MAC_CCTLINFO_UD` (2). `fw.h:4565`. CMAC table update.
pub const H2C_FUNC_MAC_CCTLINFO_UD: u8 = 0x2;
/// `H2C_FUNC_MAC_BCN_UPD` (5). `fw.h:4566`. Beacon template update.
pub const H2C_FUNC_MAC_BCN_UPD: u8 = 0x5;
/// `H2C_FUNC_MAC_DCTLINFO_UD_V1` (9). `fw.h:4567`. DMAC table v1.
pub const H2C_FUNC_MAC_DCTLINFO_UD_V1: u8 = 0x9;

/// `H2C_CL_MAC_ADDR_CAM_UPDATE` (6). `fw.h:4575`.
pub const H2C_CL_MAC_ADDR_CAM_UPDATE: u8 = 0x6;
/// `H2C_FUNC_MAC_ADDR_CAM_UPD` (0). `fw.h:4576`.
pub const H2C_FUNC_MAC_ADDR_CAM_UPD: u8 = 0x0;

/// `H2C_CL_MAC_MEDIA_RPT` (8). `fw.h:4579`.
pub const H2C_CL_MAC_MEDIA_RPT: u8 = 0x8;
/// `H2C_FUNC_MAC_JOININFO` (0). `fw.h:4580`. Sent on assoc.
pub const H2C_FUNC_MAC_JOININFO: u8 = 0x0;
/// `H2C_FUNC_MAC_FWROLE_MAINTAIN` (4). `fw.h:4581`.
pub const H2C_FUNC_MAC_FWROLE_MAINTAIN: u8 = 0x4;

/// `H2C_CL_MAC_FW_OFLD` (9). `fw.h:4585`.
pub const H2C_CL_MAC_FW_OFLD: u8 = 0x9;
/// `H2C_FUNC_PACKET_OFLD` (0x1). `fw.h:4587`.
pub const H2C_FUNC_PACKET_OFLD: u8 = 0x1;
/// `H2C_FUNC_OFLD_CFG` (0x14). `fw.h:4591`. Offload-config setup.
pub const H2C_FUNC_OFLD_CFG: u8 = 0x14;
/// `H2C_FUNC_SCANOFLD` (0x17). `fw.h:4593`. AX scan offload.
pub const H2C_FUNC_SCANOFLD: u8 = 0x17;
/// `H2C_FUNC_SCANOFLD_BE` (0x2C). `fw.h:4600`. BE scan offload.
pub const H2C_FUNC_SCANOFLD_BE: u8 = 0x2C;
/// `H2C_FUNC_ADD_SCANOFLD_CH` (0x16). `fw.h:4592`.
pub const H2C_FUNC_ADD_SCANOFLD_CH: u8 = 0x16;

// ── OUTSRC-category class constants ─────────────────────────────────

/// `H2C_CL_OUTSRC_RA` (0x1). `fw.h:4696`.
pub const H2C_CL_OUTSRC_RA: u8 = 0x1;
/// `H2C_FUNC_OUTSRC_RA_MACIDCFG` (0). `fw.h:4697`.
pub const H2C_FUNC_OUTSRC_RA_MACIDCFG: u8 = 0x0;

/// `H2C_CL_OUTSRC_DM` (0x2). `fw.h:4699`. DM (Digital Monitor).
pub const H2C_CL_OUTSRC_DM: u8 = 0x2;

/// `H2C_CL_OUTSRC_RF_REG_A` (0x8). `fw.h:4704`.
pub const H2C_CL_OUTSRC_RF_REG_A: u8 = 0x8;
/// `H2C_CL_OUTSRC_RF_REG_B` (0x9). `fw.h:4705`.
pub const H2C_CL_OUTSRC_RF_REG_B: u8 = 0x9;
/// `H2C_CL_OUTSRC_RF_FW_RFK` (0xB). `fw.h:4710`.
pub const H2C_CL_OUTSRC_RF_FW_RFK: u8 = 0xB;
/// `H2C_FUNC_RFK_IQK_OFFLOAD` (0x1). `fw.h:4714`.
pub const H2C_FUNC_RFK_IQK_OFFLOAD: u8 = 0x1;

// ── DRV_GEN category (driver-only, internal) ────────────────────────
//
// The driver uses a synthetic "category" for in-driver dispatch
// without sending a real H2C — the `H2C_CAT_CTL_DRV_GEN` value Linux
// uses internally is 0xFF; we shadow it here.

/// `H2C_CAT_CTL_DRV_GEN` — synthetic driver-only category. Used
/// internally to flag "no H2C should fire" for control-plane events.
pub const H2C_CAT_CTL_DRV_GEN: u8 = 0xFF;

// ── Builder ──────────────────────────────────────────────────────────

/// One H2C command staged in a byte buffer. The buffer carries the
/// 8-byte header in slots `[0..8]` followed by the payload in
/// `[8..total_len]`.
#[derive(Debug)]
pub struct H2cBuilder {
    /// (cat, class, func) addressing.
    pub cat: u8,
    pub class: u8,
    pub func: u8,
    /// Sequence number — drv increments on every send.
    pub seq: u8,
    /// Acknowledgement requests.
    pub rec_ack: bool,
    pub done_ack: bool,
}

impl H2cBuilder {
    /// New builder for the given (cat, class, func), with default
    /// seq=0 and no acks. Mirrors the early-in-init `LOG_CFG` shape.
    pub const fn new(cat: u8, class: u8, func: u8) -> Self {
        Self {
            cat,
            class,
            func,
            seq: 0,
            rec_ack: false,
            done_ack: false,
        }
    }

    /// Override sequence number.
    pub const fn with_seq(mut self, seq: u8) -> Self {
        self.seq = seq;
        self
    }

    /// Request done_ack from the firmware. Used for commands that the
    /// driver needs to wait on before sending the next.
    pub const fn with_done_ack(mut self, enable: bool) -> Self {
        self.done_ack = enable;
        self
    }

    /// Request rec_ack from the firmware.
    pub const fn with_rec_ack(mut self, enable: bool) -> Self {
        self.rec_ack = enable;
        self
    }

    /// Build the full command into `out`. Returns the total wire-byte
    /// length on success or `None` if `out` is too small.
    ///
    /// Layout: 8 bytes header, then `payload`.
    pub fn build(&self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        let total = H2C_HEADER_LEN + payload.len();
        if out.len() < total {
            return None;
        }
        encode_h2c_header(
            self.cat,
            self.class,
            self.func,
            self.seq,
            payload.len() as u16,
            self.rec_ack,
            self.done_ack,
            &mut out[..H2C_HEADER_LEN],
        )?;
        out[H2C_HEADER_LEN..total].copy_from_slice(payload);
        Some(total)
    }
}

// ── Sequence allocator ──────────────────────────────────────────────

/// Single-counter sequence allocator. The firmware doesn't actually
/// care about sequence ordering across categories (Linux's
/// `rtw89_h2c_pkt_set_hdr` increments a single per-rtwdev counter).
/// We keep the same shape for simplicity.
#[derive(Debug, Default)]
pub struct H2cSeqAllocator {
    counter: core::sync::atomic::AtomicU8,
}

impl H2cSeqAllocator {
    /// New allocator. The counter starts at 0; first `next()` returns 0.
    pub const fn new() -> Self {
        Self {
            counter: core::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Take the next sequence number, wrapping at 256.
    pub fn next(&self) -> u8 {
        self.counter
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }
}

// ── Pre-baked command builders ──────────────────────────────────────

/// `LOG_CFG` H2C — sent early during init to configure firmware
/// logging level. Class `H2C_CL_FW_INFO`, function `H2C_FUNC_LOG_CFG`.
/// The payload is implementation-defined; Linux sends an array of
/// per-class log-level masks. Stage 6 ships a stub payload.
pub fn make_log_cfg_h2c(seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_MAC, H2C_CL_FW_INFO, H2C_FUNC_LOG_CFG).with_seq(seq)
}

/// `OFLD_CFG` H2C — sent in `rtw89_fw_h2c_set_ofld_cfg` at the tail
/// of `rtw89_mac_init` (mac.c:4282). Configures the firmware offload
/// modules. Class `H2C_CL_MAC_FW_OFLD`, function `H2C_FUNC_OFLD_CFG`.
pub fn make_ofld_cfg_h2c(seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_MAC, H2C_CL_MAC_FW_OFLD, H2C_FUNC_OFLD_CFG)
        .with_seq(seq)
        .with_done_ack(true)
}

/// `JOININFO` H2C — sent on association complete to tell the firmware
/// who the connected STA is. Class `H2C_CL_MAC_MEDIA_RPT`, function
/// `H2C_FUNC_MAC_JOININFO`.
pub fn make_joininfo_h2c(seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_MAC, H2C_CL_MAC_MEDIA_RPT, H2C_FUNC_MAC_JOININFO)
        .with_seq(seq)
        .with_done_ack(true)
}

/// `RA_MACIDCFG` H2C — rate-adaptation initial config. Class
/// `H2C_CL_OUTSRC_RA`, function `H2C_FUNC_OUTSRC_RA_MACIDCFG`. Sent
/// after JOININFO during association.
pub fn make_ra_macidcfg_h2c(seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_OUTSRC, H2C_CL_OUTSRC_RA, H2C_FUNC_OUTSRC_RA_MACIDCFG)
        .with_seq(seq)
}

/// `SCANOFLD` H2C — scan-offload start/stop. Class `H2C_CL_MAC_FW_OFLD`,
/// function `H2C_FUNC_SCANOFLD` for AX or `H2C_FUNC_SCANOFLD_BE` for BE.
pub fn make_scanofld_h2c(seq: u8, is_be: bool) -> H2cBuilder {
    let func = if is_be { H2C_FUNC_SCANOFLD_BE } else { H2C_FUNC_SCANOFLD };
    H2cBuilder::new(H2C_CAT_MAC, H2C_CL_MAC_FW_OFLD, func).with_seq(seq)
}

/// `FWHDR_DL` H2C — firmware header download. Class `H2C_CL_MAC_FWDL`,
/// function `H2C_FUNC_MAC_FWHDR_DL`. Used during firmware upload.
pub fn make_fwhdr_dl_h2c(seq: u8) -> H2cBuilder {
    H2cBuilder::new(H2C_CAT_MAC, H2C_CL_MAC_FWDL, H2C_FUNC_MAC_FWHDR_DL)
        .with_seq(seq)
        .with_done_ack(true)
}

/// `_ = FWCMD_TYPE_H2C` — keep the import alive in users that don't
/// branch on delivery type.
pub const fn drop_delivery_type() {
    let _ = FWCMD_TYPE_H2C;
}
