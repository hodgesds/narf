//! RTL8723AE (`rtl8723ae` + `rtl8723com`) retained runtime, in progress.
//!
//! RTL8723AE (PCI `0x8723`) is the 1T1R 802.11n + Bluetooth combo of the
//! RTL8192C generation: 92CE-style linked TX rings, its own `pwrseq` flows,
//! `rtl8723com` firmware download / PHY helpers and its own BT coexistence
//! (`hal_btc.c` + `hal_bt_coexist.c`). Probe admits it under qualification
//! (qualified 8723-series version with `BT_FUNC`, provisioned EFUSE map
//! whose MAC is the factory identity); its firmware owner runs
//! `run_8723ae`, retaining cold MAC/LLT and BB/RF setup across firmware
//! download without opening packet DMA/MAC gates. Registered NAQR preparation
//! and NASR-qualified original rings/MAC/coexistence handoff are composed.
//! Native legacy20 MLME/data require the separate joint station grant and
//! retained final live receipt; CPU/ring readiness alone admits no station.
//! Physical calibration/measurement assets and interoperability remain external.
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
//!   owners with terminal failure handling; retained NAQR preparation runs
//!   them before separate NASR station admission. They grant no emission alone.
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
//!   The actual separately qualified native packet branch drains this from
//!   AE IRQ/polled status into the same retained coexistence owner; no event
//!   is a TX-ACK receipt. The earlier diagnostic packet owner also exposes it.
//! - [`coex`] — the 8723AE Bluetooth-coexistence owner (pass 1): board
//!   binding, `BtInfo` ingestion, the periodical decision, and the DM
//!   primitives (`hal_bt_coexist.c`, including the RF halves through the
//!   `rtl8723com` LSSI writer).
//! - [`dm`] — the 1-ant / 2-ant mechanism trees (`hal_btc.c`) over the
//!   coex owner.
//! - [`envelope`] — original signed per-board NAPC power envelopes. Native
//!   admission adds distinct NAQR/NASR sources, actual factory caps and its
//!   own independent worst-case station/coexistence measurements.
//! - [`packet`] — earlier diagnostic packet owner. The actual retained
//!   native branch is mounted under prepare::packet from packet_owner.rs,
//!   with own AE descriptor/IRQ/H2C/current-policy and lifetime boundaries.

#![allow(dead_code)]

pub mod adapter;
pub mod c2h;
pub mod coex;
pub mod dm;
pub mod envelope;
pub(super) mod factory;
pub mod fw;
pub mod h2c;
pub(crate) mod ht;
pub mod init;
pub mod iqk;
pub mod irq;
pub mod llt;
pub mod mac;
pub mod packet;
pub(in crate::rtlwifi) mod park;
pub mod phy;
pub mod power;
pub mod ps;
pub mod pwrseq;
pub(super) mod radio_policy;
pub mod radio_switch;
pub(in crate::rtlwifi) mod reserved;
mod source_program;
pub mod station;
pub(in crate::rtlwifi) mod station_owner;
pub(crate) mod station_policy;
pub mod supervision;
pub mod tables;
pub mod trx;
pub mod txpower;
pub mod version;
/// Provisioning name and binding for a separately signed preparation recipe.
pub use radio_policy::Request as PreparationRequest;
/// Separate native station/coexistence measurement recipe request.
pub use station_policy::Request as StationRequest;

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

// Private original cold/factory/lifecycle continuation and sealed native handoff.
mod checked;
pub(in crate::rtlwifi) mod cold_storage;
pub(in crate::rtlwifi) mod retained;
