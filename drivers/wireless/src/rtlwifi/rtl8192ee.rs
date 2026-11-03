//! RTL8192EE per-chip constants.
//!
//! RTL8192EE is a 2T2R 802.11n PCIe NIC from ~2014, effectively a die shrink
//! of the RTL8192CE with a revised power-management controller.  It shipped
//! in many mid-range laptops circa 2014–2016.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8192ee/reg.h`  — register offsets
//! - `rtlwifi/rtl8192ee/def.h`  — chip-version, rate, qsel constants
//!
//! ## Retained-runtime foundation (`rtl8192ee/`)
//!
//! Exact Linux-derived pieces a retained RTL8192EE owner is built from. None
//! is reachable from probe as a WLAN capability: `0x818b` stays diagnostic.
//!
//! - [`pwrseq`] — PCI rows of every `rtl8192E_*_flow` (`pwrseq.{c,h}`).
//! - [`fw`] — `rtl8192eefw.bin` header validation and the
//!   `rtl92ee_download_fw` page/self-reset sequence.
//! - [`adapter`] — `rtl92ee_read_eeprom_info` / `_rtl92ee_read_adapter_info`
//!   factory facts; test chips and unprovisioned maps yield none.
//! - [`trx`] — new-TRX-flow TX/RX buffer descriptors, TX descriptor, RX
//!   status and the read/write-pointer helpers (`trx.{c,h}`, `pci.c`).
//! - [`mac`] — the `_rtl92ee_init_mac` remainder (auto LLT, BD ring bases
//!   and counts) with the `REG_CR` release deferred to the packet owner.
//! - [`phy`] — MAC/PHY_REG/AGC/RADIOA/RADIOB configuration with the RF
//!   serial writer (`0xb6`/`0xb2` read-back retries) and the PHY_REG_PG
//!   power-by-rate store (`phy.c`, `rf.c`).
//! - [`txpower`] — factory TX power decode and the TXAGC writes
//!   (`_rtl92ee_read_txpower_info_from_hwpg`, `rtl92ee_phy_set_txpower_level`).
//! - [`channel`] — `rtl92ee_phy_sw_chnl` and `rtl92ee_phy_set_bw_mode` (20/40).
//! - [`iqk`] — `rtl92ee_phy_iq_calibrate` (paths A and B, three-run
//!   similarity selection, matrix fill, result-register recovery) and
//!   `_rtl92ee_phy_lc_calibrate`.
//! - `packet_owner.rs` — the BD-ring profile of the retained owner, mounted
//!   as `prepare::packet::ee92` (allocation, publication, TXBD_IDX
//!   doorbells, RXQ_TXBD_IDX consumption and the deferred DMA releases).

#![allow(dead_code)]

pub mod adapter;
pub mod channel;
pub mod fw;
pub mod headerfile;
pub mod iqk;
pub mod mac;
pub mod phy;
pub mod pwrseq;
pub mod tables;
pub mod trx;
pub mod txpower;

#[cfg(any(test, feature = "kernel-test"))]
mod phy_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// PCI device ID.
pub const DEV_ID: u16 = super::regs::RTL_DEV_8192EE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size.  8192EE uses the same 16 KiB window as the earlier
/// chips (`rtl8192ee/reg.h` defines the same `RTL_MEM_MAPPED_IO_RANGE` value).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (512 bytes).
/// Source: `rtl8192ee/hw.c`.
pub const EFUSE_MAP_SIZE: usize = 512;

// ── TX descriptor ring count ──────────────────────────────────────────────
//
// Source: `rtlwifi/pci.h::TX_DESC_NUM_92E`.

/// TX descriptor count for 8192EE (larger ring than older chips).
pub const TX_DESC_NUM: usize = 512;

/// RX descriptor count.
/// Source: `rtl8192ee/def.h::RX_DESC_NUM_92E`.
pub const RX_DESC_NUM: usize = 512;

// ── Queue-select values ───────────────────────────────────────────────────
//
// Source: `rtl8192ee/def.h::rtl_desc_qsel`.

pub use super::regs::{QSLT_BE, QSLT_BK, QSLT_CMD, QSLT_HIGH, QSLT_MGNT, QSLT_VI, QSLT_VO};

// ── Rate descriptors ──────────────────────────────────────────────────────
//
// Source: `rtl8192ee/def.h::rtl_desc92c_rate`.

/// CCK 1 Mbps.
pub const RATE_1M: u8 = 0x00;
/// CCK 2 Mbps.
pub const RATE_2M: u8 = 0x01;
/// CCK 5.5 Mbps.
pub const RATE_5_5M: u8 = 0x02;
/// CCK 11 Mbps.
pub const RATE_11M: u8 = 0x03;
/// OFDM 6 Mbps.
pub const RATE_6M: u8 = 0x04;
/// OFDM 54 Mbps.
pub const RATE_54M: u8 = 0x0B;
/// HT MCS0.
pub const RATE_MCS0: u8 = 0x0C;
/// HT MCS15.
pub const RATE_MCS15: u8 = 0x1B;

// ── Chip version ──────────────────────────────────────────────────────────
//
// Source: `rtl8192ee/def.h::enum version_8192e`.

/// Test chip 2T2R.
pub const VERSION_TEST_2T2R: u16 = 0x0024;
/// Normal production 2T2R.
pub const VERSION_NORMAL_2T2R: u16 = 0x102C;

// ── TX/RX descriptor re-exports ───────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
