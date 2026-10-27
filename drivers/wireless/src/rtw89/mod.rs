//! RTW89 PCIe discovery and retained RTL8852B initial station.
//!
//! Targets the Realtek 11ax silicon found on current Zen3+ / Phoenix
//! HawkPoint1 laptops:
//!
//! - **RTL8852AE** — 2x2 Wi-Fi 6 (`10ec:8852`).
//! - **RTL8852BE** — 2x2 Wi-Fi 6 budget cut (`10ec:b852`, `10ec:b85b`).
//! - **RTL8852CE** — 2x2 Wi-Fi 6E (`10ec:c852`).
//! - **RTL8851BE** — 1x1 Wi-Fi 6 (`10ec:b851`).
//! - **RTL8922AE** — 2x2 Wi-Fi 7 (`10ec:8922`, `10ec:892b`). The "BE"
//!   generation; we still match it under rtw89 because Linux does.
//!
//! RTL8852B retains the same reset/cold/factory/firmware/radio owner through
//! actual PHY capability, source calibration and measured signed qualification
//! into an awake channel1 legacy20 TX-A/RX-AB Open/WPA2 station. Native TXBD/RPQ
//! receipts drive host RSNA/CCMP and the registered kernel DHCP/IP path. The
//! bounded first profile uses fixed1Mbps and512 identities per queue, with a
//! fresh reset lifecycle after terminal closure. Physical acceptance and exact
//! deployment assets remain required. Other AX/BE profiles are diagnostic or
//! preparation paths; no packet or radio authority follows from ID matching.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later as of
//! 2026-05-20 per the root `LICENSE`)
//!
//! - Linux `drivers/net/wireless/realtek/rtw89/pci.c`
//!   — `rtw89_pci_claim_device` (~L3340..L3420, `bar_id = 2`),
//!   — `rtw89_pci_id_table` (per-chip `*_pci.c` files).
//! - Linux `drivers/net/wireless/realtek/rtw89/mac.c`
//!   — `rtw89_mac_pwr_on` (~L1575..L1590),
//!   — `rtw89_mac_power_switch` (~L1510..L1573),
//!   — `rtw89_mac_pwr_seq` (~L1259..L1330).
//! - Linux `drivers/net/wireless/realtek/rtw89/efuse.c`
//!   — `rtw89_dump_physical_efuse_map_ddv` (~L113..L138)
//!   (the per-byte `EFUSE_CTRL` access loop),
//!   — `rtw89_switch_efuse_bank` (~L40..L65).
//! - Linux `drivers/net/wireless/realtek/rtw89/reg.h`
//!   — `R_AX_*` offsets,
//!   — `B_AX_EF_*` mask definitions,
//!   — `R_AX_SYS_CFG1::B_AX_CHIP_VER_MASK`.
//! - Linux `drivers/net/wireless/realtek/rtw89/core.h`
//!   — `enum rtw89_core_chip_id`.
//! - Linux `drivers/net/wireless/realtek/rtw89/txrx.h`
//!   — `RTW89_TXCH_*` (13 TX) + `RTW89_RXCH_*` (2 RX) — channel
//!   counts the Stage-2 ring code will use.

#![allow(dead_code)]

extern crate alloc;

mod bdram;
mod bootstrap;
pub mod btc;
mod calibration_policy;
pub mod chan;
mod channel_bb;
mod channel_rf;
mod channel_transition;
mod coex_native;
mod cold;
mod cold_native;
mod command_native;
mod command_queue;
pub mod datapath;
mod ddv;
pub mod dma;
mod download_dma;
mod download_plan;
mod dpk;
pub mod efuse;
mod factory;
mod factory_b;
mod fifo;
mod fifo_regs;
mod firmware_boot;
mod firmware_phycap;
mod firmware_registry;
pub mod fw;
pub mod fwdl;
pub mod h2c;
mod interface;
mod iqk;
mod irq;
pub mod mac;
pub mod mac_init;
mod mac_runtime;
mod mac_runtime_regs;
mod packet_core;
mod packet_format;
pub mod pci;
mod pci_basic;
mod pci_basic_regs;
mod pci_reset;
mod pcie;
mod pcie_native;
mod pcie_regs;
pub mod phy;
mod phy_access;
mod phy_operating;
pub mod phy_table;
mod power;
mod power_native;
mod power_regs;
mod power_tables;
mod prepared;
mod qos;
mod radio_assets;
mod radio_full;
mod radio_gain;
mod radio_init;
mod radio_policy;
mod radio_power;
mod radio_shutdown;
mod radio_stop;
mod radio_table;
mod radio_tables_b;
mod radio_trim;
mod rf_access;
mod rfk;
mod rfk_regs;
mod rfk_tables;
mod rx_dma;
mod rx_packet;
mod scheduler_mailbox;
mod secure;
mod startup;
mod station;
#[cfg(feature = "kernel-test")]
mod station_composition_tests;
pub(super) mod station_control;
mod station_lifecycle;
mod tssi;
pub mod tx_transport;
pub mod txrx;

#[cfg(any(test, feature = "kernel-test"))]
mod tx_transport_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod fwdl_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod power_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod ddv_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod pci_authority_tests;

pub use mac::{ChipGeneration, ChipId, MacError};
pub use pci::{name_for, probe, register_pci_driver, Rtw89Device};

// ── PCI ids exported so `lib.rs` and tests don't have to dig into the
//    `pci` submodule for them. ─────────────────────────────────────────

/// Realtek vendor id (`PCI_VENDOR_ID_REALTEK`).
pub const REALTEK_VENDOR: u16 = 0x10EC;

/// RTL8852AE — Wi-Fi 6 2x2. `rtw89/rtw8852ae.c`.
pub const RTL_DEV_8852AE: u16 = 0x8852;
/// RTL8852AE-VT (vendor-specific PCIe subsystem). `rtw89/rtw8852ae.c`.
pub const RTL_DEV_8852AE_VT: u16 = 0xA85A;
/// RTL8852BE — Wi-Fi 6 2x2. `rtw89/rtw8852be.c`.
pub const RTL_DEV_8852BE: u16 = 0xB852;
/// RTL8852BE alternate PCI ID with the same B-chip profile. Linux's
/// distinct RTL8852BT ID is0xb520 and is not claimed here.
pub const RTL_DEV_8852BE_ALT: u16 = 0xB85B;
/// RTL8852CE — Wi-Fi 6E 2x2. `rtw89/rtw8852ce.c`.
pub const RTL_DEV_8852CE: u16 = 0xC852;
/// RTL8851BE — Wi-Fi 6 1x1. `rtw89/rtw8851be.c`.
pub const RTL_DEV_8851BE: u16 = 0xB851;
/// RTL8922AE — Wi-Fi 7 2x2 (the "BE" gen). `rtw89/rtw8922ae.c`.
pub const RTL_DEV_8922AE: u16 = 0x8922;
/// RTL8922AE alt subsystem. `rtw89/rtw8922ae.c`.
pub const RTL_DEV_8922AE_ALT: u16 = 0x892B;

/// All currently-supported PCI device IDs (Realtek vendor `0x10EC`).
/// Order is broad-rollout-first so the boot probe log lists the most
/// common parts at the top.
pub const ALL_DEV_IDS: &[u16] = &[
    RTL_DEV_8852AE,
    RTL_DEV_8852AE_VT,
    RTL_DEV_8852BE,
    RTL_DEV_8852BE_ALT,
    RTL_DEV_8852CE,
    RTL_DEV_8851BE,
    RTL_DEV_8922AE,
    RTL_DEV_8922AE_ALT,
];

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
mod efuse_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
