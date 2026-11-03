//! RTL8821AE per-chip constants.
//!
//! RTL8821AE is a 1T1R 802.11ac (Wi-Fi 5) PCIe NIC covering both 2.4 GHz
//! and 5 GHz bands.  Shipped from ~2014 in mid-range laptops.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8821ae/reg.h`  — register offsets
//! - `rtlwifi/rtl8821ae/def.h`  — rate / VHT constants
//!
//! ## Retained-runtime foundation (`rtl8821ae/`)
//!
//! Exact Linux-derived pieces the retained RTL8821AE owner is built from;
//! none of them is wired to probe or advertises a capability by itself:
//!
//! - [`pwrseq`] — PCI rows of every `rtl8821A_*_flow` (`pwrseq.{c,h}`).
//! - [`tables`] / [`headerfile`] — MAC/BB/AGC/RF-A/power-by-rate arrays and
//!   the conditional `__rtl8821ae_phy_config_with_headerfile` walker,
//!   qualified by SYS_CFG + factory EFUSE ([`headerfile::Condition`]).
//! - [`power_limit`] — `RTL8821AE_TXPWR_LMT` per-regulation/band/bandwidth
//!   limits; 63 ("unspecified") is never admitted as a limit.
//! - [`fw`] — `rtl8821aefw_29.bin` / `rtl8821aefw.bin` /
//!   `rtl8821aefw_wowlan.bin` header validation and the `rtl8821ae_download_fw`
//!   page/self-reset sequence.
//! - [`llt`] — `_rtl8821ae_llt_table_init` boundary/RQPN sequence.
//! - [`trx`] — 40-byte TX / 24-byte RX status descriptors (`trx.h`).
//! - [`mac`] / [`phy`] — parked `rtl8821ae_hw_init` hardware steps: the
//!   `_rtl8821ae_init_mac` remainder, MAC/PHY_REG/AGC/RADIOA table walks, BB
//!   enable, crystal cap, `_rtl8821ae_read_rfe_type`, `_rtl8821ae_hw_configure`.
//! - [`c2h`] — C2H packet parsing (`rtl_c2h_content_parsing`): TX reports
//!   (`rtl_tx_report_handler` V1) and RA reports
//!   (`rtl8821ae_c2h_ra_report_handler`).

#![allow(dead_code)]

pub mod c2h;
pub mod fw;
pub mod headerfile;
pub mod llt;
pub mod mac;
pub mod phy;
pub mod power_limit;
pub mod pwrseq;
pub(crate) mod tables;
pub mod trx;

#[cfg(any(test, feature = "kernel-test"))]
mod tests;

/// PCI device ID.
pub const DEV_ID: u16 = super::regs::RTL_DEV_8821AE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (512 bytes).
/// Source: `rtl8821ae/hw.c`.
pub const EFUSE_MAP_SIZE: usize = 512;

// ── VHT/HT rate constants ─────────────────────────────────────────────────
//
// Source: `rtl8821ae/def.h`.

/// VHT 1SS MCS0.
pub const MGN_VHT1SS_MCS0: u8 = 0x90;
/// VHT 1SS MCS9.
pub const MGN_VHT1SS_MCS9: u8 = 0x99;
/// VHT 2SS MCS0.
pub const MGN_VHT2SS_MCS0: u8 = 0x9A;
/// VHT 2SS MCS9.
pub const MGN_VHT2SS_MCS9: u8 = 0xA3;

// ── TX/RX descriptor ─────────────────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
