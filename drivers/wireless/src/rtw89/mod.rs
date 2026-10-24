//! Realtek RTW89 family Wi-Fi 6 (802.11ax) PCIe — Stage-0/1 driver.
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
//! ## Scope (this commit set)
//!
//! 1. PCI device match via the existing `bus::driver_match` table.
//! 2. **BAR2** Device MMIO mapping (both rtw88 and rtw89 use BAR2). Linux `pci.c:rtw89_pci_claim_device` walks
//!    `bar_id = 2` directly.
//! 3. Diagnostic baseline power prologue; complete AX power-on/off and
//!    DLE/HFC primitives await the composed boot owner.
//! 4. Chip-ID detection from `R_AX_SYS_CFG1` so subsequent stages can
//!    branch on the AX (8852A/B/C, 8851B) vs BE (8922A) generation.
//! 5. EFUSE read for MAC + the 6-byte address copy. Logical map
//!    offsets follow the per-chip layout in
//!    `rtw89/rtw8852a.h::rtw8852ae_efuse`.
//! 6. Retained unpublished ring storage, without a registered NIC or IRQ.
//! 7. Checked immutable secure firmware plans and native CH12 ownership,
//!    still inactive pending full PCIe/BDRAM/WCPU composition and RF/MLME.
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
pub mod btc;
pub mod chan;
mod command_native;
mod command_queue;
pub mod datapath;
mod ddv;
pub mod dma;
mod download_plan;
pub mod efuse;
mod fifo;
mod fifo_regs;
mod firmware_boot;
mod firmware_registry;
pub mod fw;
pub mod fwdl;
pub mod h2c;
pub mod mac;
pub mod mac_init;
pub mod pci;
pub mod phy;
mod phy_access;
pub mod phy_table;
mod power;
mod power_native;
mod power_regs;
mod power_tables;
mod prepared;
mod secure;
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
