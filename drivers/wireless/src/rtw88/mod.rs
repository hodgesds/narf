//! Realtek RTW88 family Wi-Fi 5 PCIe — baseline driver.
//!
//! Targets the three chips most common on AMD Zen2 laptops:
//!
//! - **RTL8821CE** — Wi-Fi 5 1x1 (`10ec:c821`).
//! - **RTL8822CE** — Wi-Fi 5 2x2 (`10ec:c822`).
//! - **RTL8822BE** — Wi-Fi 5 2x2, older B-cut (`10ec:b822`).
//!
//! ## Scope (this commit)
//!
//! 1. PCI device match via the existing `bus::driver_match` table.
//! 2. BAR0 (register) + BAR2 (data) MMIO mapping.
//! 3. Baseline power-on sequence + chip-reset (CR.OPEN re-arm).
//! 4. EFUSE read — MAC address from logical offset 0.
//! 5. `HwNic` registry stub — `narf-net::iface::register` with a
//!    send-fn that returns `Err(())` so the iface shows up but
//!    can't actually transmit yet.
//!
//! Firmware load + RF/PHY init + TX/RX rings are explicitly **not**
//! part of this baseline — they need the `narf-firmware` blob path
//! and a follow-up bring-up that doesn't fit cleanly in one commit.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - Linux `drivers/net/wireless/realtek/rtw88/pci.c`
//!     — `rtw_pci_probe`, `rtw_pci_id_table` (v6.6 ~L1620..L1750)
//! - Linux `drivers/net/wireless/realtek/rtw88/main.c`
//!     — `rtw_power_on` (v6.6 ~L1900..L2100)
//! - Linux `drivers/net/wireless/realtek/rtw88/mac.c`
//!     — `rtw_pwr_seq_parser`, `rtw_mac_init` (v6.6 ~L140..L280)
//! - Linux `drivers/net/wireless/realtek/rtw88/efuse.c`
//!     — `rtw_efuse_read` (v6.6 ~L50..L200)
//! - Linux `drivers/net/wireless/realtek/rtw88/reg.h`
//!     — REG_* offsets
//! - Linux `drivers/net/wireless/realtek/rtw88/rtw8822c.c` /
//!   `rtw8821c.c` — per-chip PWR-seq tables (only the cross-chip
//!   prologue is used here)
//! - Realtek public RTL8822C datasheet — vendor signage on register
//!   names

#![allow(dead_code)]

extern crate alloc;

pub mod efuse;
pub mod pci;
pub mod power;
pub mod regs;

pub use pci::{name_for, probe, register_pci_driver, Rtw88Device};
pub use regs::{REALTEK_VENDOR, RTL_DEV_8821CE, RTL_DEV_8822BE, RTL_DEV_8822CE};

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
