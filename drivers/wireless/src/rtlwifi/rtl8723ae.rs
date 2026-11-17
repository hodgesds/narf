//! RTL8723AE (`rtl8723ae` + `rtl8723com`) retained runtime, in progress.
//!
//! RTL8723AE (PCI `0x8723`) is the 1T1R 802.11n + Bluetooth combo of the
//! RTL8192C generation: 92CE-style linked TX rings, its own `pwrseq` flows,
//! `rtl8723com` firmware download / PHY helpers and its own BT coexistence
//! (`hal_btc.c` + `hal_bt_coexist.c`). Probe admits it under qualification
//! (qualified 8723-series version with `BT_FUNC`, provisioned EFUSE map
//! whose MAC is the factory identity); its firmware owner runs
//! `run_8723ae`, retaining cold MAC/LLT and BB/RF setup across firmware
//! download without opening packet DMA/MAC gates. Station admission (`prepare_rtl8723ae`,
//! `prepare::Chip::Rtl8723ae`, packet path) is still open.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8723ae/{hw,sw,pwrseq,reg,def}.{c,h}`
//! - `rtlwifi/rtl8723com/fw_common.{c,h}`
//!
//! ## Modules
//!
//! - [`init`] — retained, terminal cold initialization in source order:
//!   LLT/MAC before firmware download, then MAC/BB/RF tables and UMC/default
//!   programming. Factory identity, coex/IQK and calibrated TX power remain
//!   deferred; TablesReady grants no station or emission authority.
//! - [`tables`] — exact AE MAC/PHY/PG/AGC/RF programming data.
//! - [`llt`] / [`mac`] — AE queue boundaries and parked MAC defaults.
//! - [`phy`] — AE BB/RF configuration, channel/bandwidth primitives and LCK.
//! - [`iqk`] / [`txpower`] — source IQK and factory/RF6052 preparation
//!   owners with terminal failure handling; not invoked by firmware-only
//!   startup or a station, and not signed emission grants.
//!
//! - [`version`] — `_rtl8723e_read_chip_version` (normal 8723-series parts
//!   only), the `def.h` predicates and the `rtl8723e_init_sw_vars`
//!   firmware selection (`rtl8723fw.bin` / `rtl8723fw_B.bin`).
//! - [`adapter`] — `rtl8723e_read_eeprom_info` / `_rtl8723e_read_adapter_info`
//!   factory facts, `rtl8723e_read_bt_coexist_info_from_hwpg` and the OEM
//!   rule.
//! - [`pwrseq`] — PCI rows of every `rtl8723A_*_flow` (`pwrseq.{c,h}`).
//! - [`power`] — the `_rtl8712e_init_mac` segment after the enable flow
//!   (PCIe/eMAC bits and the ePHY MDIO loop).
//! - [`fw`] — header validation and `rtl8723_download_fw` with
//!   `rtl8723ae_firmware_selfreset`.
//! - [`c2h`] — the firmware-event mailbox (`rtl_8723e_c2h_command_handle`):
//!   header/close-byte protocol over `REG_C2HEVT_MSG_NORMAL`, BT info
//!   parse, RSSI / operation-mode / unknown ids consumed without effect.
//!   Caller: [`packet::Owner::service_c2h`], which schedules `c2h::drain`
//!   when `irq::IsrStatus::c2h_pending` is set. It has no production
//!   caller yet (only fixture tests): the chip is not admitted, so no IRQ
//!   station path reaches it.
//! - [`coex`] — the 8723AE Bluetooth-coexistence owner (pass 1): board
//!   binding, `BtInfo` ingestion, the periodical decision, and the DM
//!   primitives (`hal_bt_coexist.c`, including the RF halves through the
//!   `rtl8723com` LSSI writer).
//! - [`dm`] — the 1-ant / 2-ant mechanism trees (`hal_btc.c`) over the
//!   coex owner.
//! - [`envelope`] — signed per-board NAPC power envelopes (2.4 GHz
//!   only), minting the [`envelope::Permission`] the packet owner
//!   transmits under.
//! - [`packet`] — the AE packet owner: 92CE-style TX descriptor fill,
//!   RX descriptor query, firmware + envelope admission gates, and the
//!   mailbox service entry.

#![allow(dead_code)]

pub mod adapter;
pub mod c2h;
pub mod coex;
pub mod dm;
pub mod envelope;
pub mod fw;
pub mod init;
pub mod iqk;
pub mod llt;
pub mod mac;
pub mod packet;
pub mod phy;
pub mod power;
pub mod pwrseq;
pub mod tables;
pub mod txpower;
pub mod version;

#[cfg(any(test, feature = "kernel-test"))]
mod preparation_tests;
#[cfg(any(test, feature = "kernel-test"))]
mod runtime_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// PCI device ID (`rtl8723ae/sw.c` `rtl8723e_pci_ids`).
pub const DEV_ID: u16 = super::regs::RTL_DEV_8723AE;

/// Mapped IO range size (`pci.h::RTL_MEM_MAPPED_IO_RANGE_8192CE`, used by
/// every rtlwifi PCI chip of this generation).
pub const MMIO_SIZE: usize = 0x4000;
