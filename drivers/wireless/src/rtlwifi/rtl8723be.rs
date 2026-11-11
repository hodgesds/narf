//! RTL8723BE per-chip constants.
//!
//! RTL8723BE is a 1T1R 802.11n + Bluetooth 4.0 combo PCIe NIC from ~2013.
//! Extremely common in Intel-platform laptops from that era (HP, Lenovo,
//! Acer).  The RTL8723AE is the earlier (A-cut) sibling with device ID
//! 0x8723; both share this driver class.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8723be/reg.h`  — register offsets
//! - `rtlwifi/rtl8723be/def.h`  — chip-version constants
//! - `rtlwifi/rtl8723ae/reg.h`  — A-cut (device 0x8723), near-identical
//!
//! ## Retained runtime (`rtl8723be/`, in progress)
//!
//! Exact Linux `rtl8723be` + `rtl8723com` pieces the native RTL8723BE owner
//! is built from. RTL8723BE is not admitted yet (probe keeps it diagnostic).
//!
//! - [`version`] — `_rtl8723be_read_chip_version` (`CHIP_8723B` required;
//!   every cut, SMIC vendor bit) and the `rtl8723befw_36.bin` /
//!   `rtl8723befw.bin` names.
//! - [`adapter`] — `rtl8723be_read_eeprom_info` / `_rtl8723be_read_adapter_info`
//!   factory facts, the BT-coexist / antenna-number / single-antenna-path
//!   facts of `rtl8723be_read_bt_coexist_info_from_hwpg`, thermal meter,
//!   regulatory, package type and the OEM rule.
//! - [`pwrseq`] — PCI rows of every `rtl8723B_*_flow` (`pwrseq.{c,h}`).
//! - [`fw`] — header validation and `rtl8723_download_fw` with the
//!   8723BE 8051 self-reset.
//! - [`trx`] — 64-byte linked TX ring entries (40-byte descriptor, buffer at
//!   dword 10, next link at dword 12), `rtl8723be_tx_fill_desc` /
//!   `rtl8723be_tx_fill_cmddesc` and the `rtl8723be_rx_query_desc` status.
//! - [`llt`] — `_rtl8723be_llt_table_init` (boundary 245).
//! - [`mac`] — the `_rtl8723be_init_mac` remainder in its three segments
//!   around the owner's `REG_CR` writes and LLT, `_rtl8723be_hw_configure`
//!   and the station address.
//! - [`tables`] — `table.c` PHY_REG / PHY_REG_PG / RADIOA / MAC / AGCTAB,
//!   generated verbatim.
//! - [`phy`] — BB/RF access, `_rtl8723be_check_positive` table walks and
//!   the MAC / BB / RF6052 configuration.
//! - [`channel`] — `rtl8723be_phy_set_rfpath_switch`, LC calibration,
//!   20/40 MHz bandwidth, the channel RF write and the [`channel::Grant`]
//!   operating point `Prepared::configure_rtl8723be_channel` programs.
//! - [`iqk`] — `rtl8723be_phy_iq_calibrate` over S1 / S0.
//! - [`txpower`] — EFUSE power areas, the PHY_REG_PG by-rate store and
//!   `rtl8723be_phy_set_txpower_level`.
//! - [`init`] — the `rtl8723be_hw_init` tail through the `ERFON` block,
//!   run by `Prepared::configure_rtl8723be`.
//! - [`h2c`] — `_rtl8723be_fill_h2c_command` boxes, `SETPWRMODE` (with the
//!   BT-controlled LPS form), RPWM, the 1T1R station RA mask and the PCI
//!   interrupt profile with the HSISR write.
//! - [`c2h`] — `rtl_c2h_content_parsing` for this chip (BT info / MP to
//!   the coexistence owner, RA report ignored).
//! - [`coex`] — the coexistence owner: `btc_coexist`, the RTL8723B
//!   1-/2-antenna dispatch, the chip's H2C mailbox and every Linux
//!   `rtl_btc_ops` call site (power-on, `bt_hw_init`, IPS, LPS with the
//!   BT-controlled `SETPWRMODE`, scan, connect, media status, special
//!   packet / EAPOL, watchdog, C2H BT info / MP, halt).
//! - [`dm`] — `_rtl8723be_query_rxphystatus` PWDB and the
//!   `rtl8723be_dm_refresh_rate_adaptive_mask` thresholds.
//! - [`envelope`] — signed per-board NAPC power envelopes (2.4 GHz
//!   only), minting the [`envelope::Permission`] the packet owner
//!   transmits under and the [`channel::Grant`] that programs the
//!   channel (measured indices capped at the Linux factory indices).
//! - [`packet`] — the BE packet owner: single-MPDU TX descriptor fill,
//!   RX descriptor query, RX C2H dispatch into the coexistence owner
//!   (BE has no firmware-event mailbox; C2H arrives via `rpt_sel` RX
//!   statuses), the `C2hSource` queue for the coexistence MP wait,
//!   and the station-owner notify calls, all under firmware +
//!   envelope + grant admission.

#![allow(dead_code)]

pub mod adapter;
pub mod btc;
pub mod c2h;
pub mod channel;
pub mod coex;
pub mod dm;
pub mod envelope;
pub mod fw;
pub mod h2c;
pub mod init;
pub mod iqk;
pub mod llt;
pub mod mac;
pub mod packet;
pub mod phy;
pub mod pwrseq;
pub mod rsvd_page;
pub mod station;
pub mod tables;
pub mod trx;
pub mod txpower;
pub mod version;

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// PCI device ID for RTL8723BE (B-cut).
pub const DEV_ID_BE: u16 = super::regs::RTL_DEV_8723BE;

/// PCI device ID for RTL8723AE (A-cut sibling).
pub const DEV_ID_AE: u16 = super::regs::RTL_DEV_8723AE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (256 bytes for 8723 series).
/// Source: `rtl8723be/hw.c`.
pub const EFUSE_MAP_SIZE: usize = 256;

// ── Bluetooth coexistence ─────────────────────────────────────────────────
//
// The 8723BE has an internal BT co-existence controller.  These register
// bits are used by the BT co-ex code; included here for future reference.

/// `REG_LEDCFG0` offset — shared with btcoex in `rtl8723be/hw.c`.
pub use super::regs::REG_HISR;

// ── TX/RX descriptor re-exports ───────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
