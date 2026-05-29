//! Realtek rtlwifi PCIe Wi-Fi family.
//!
//! Covers the legacy Realtek PCIe Wi-Fi generation that shipped circa
//! 2010–2017, predating the `rtw88` driver rewrite.  Supported chips:
//!
//! | Chip        | PCI ID | Standard        | Notes                   |
//! |-------------|--------|-----------------|-------------------------|
//! | RTL8188EE   | 0x8179 | 802.11n 1T1R    | Budget 2.4 GHz          |
//! | RTL8192CE   | 0x8178 | 802.11n 2T2R    | Common 2.4 GHz          |
//! | RTL8192CE   | 0x8176 | 802.11n 2T2R    | Alternate DID           |
//! | RTL8192DE   | 0x8193 | 802.11n 2T2R    | Dual-band               |
//! | RTL8192EE   | 0x818B | 802.11n 2T2R    | 2014 refresh            |
//! | RTL8723AE   | 0x8723 | 802.11n 1T1R+BT | Combo A-cut             |
//! | RTL8723BE   | 0xB723 | 802.11n 1T1R+BT | Combo B-cut             |
//! | RTL8821AE   | 0x8821 | 802.11ac 1T1R   | Wi-Fi 5                 |
//! | RTL8822BE   | 0xB822 | 802.11ac 2T2R   | Wi-Fi 5 (legacy bind)   |
//!
//! ## Scope (this commit)
//!
//! 1. PCI device-ID table — all 9 IDs registered with `narf-bus`.
//! 2. BAR0 MMIO mapping — 16 KiB window for all chips.
//! 3. EFUSE read — per-byte LDO-switched access (`REG_EFUSE_CTRL` / `REG_EFUSE_TEST`).
//! 4. Per-chip register-bank / MMIO-size constants.
//! 5. TX descriptor layout (BE queue) + RX descriptor layout.
//! 6. Firmware blob-name resolver.
//!
//! ## Deferred
//!
//! - Power-on / chip-reset sequence (power.rs follow-up).
//! - Firmware download via H2C page-write.
//! - TX/RX ring initialisation and DMA setup.
//! - MSI / INTx IRQ routing.
//! - Bluetooth co-existence (8723AE/BE).
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/pci.c` — probe, BAR mapping, queue init
//! - `rtlwifi/efuse.c` — EFUSE byte-access and LDO power-switch
//! - `rtlwifi/rtl8188ee/reg.h`, `def.h`, `trx.h`
//! - `rtlwifi/rtl8192ee/reg.h`, `def.h`, `fw.h`
//! - `rtlwifi/rtl8821ae/def.h`

#![allow(dead_code)]

extern crate alloc;

pub mod efuse;
pub mod fw;
pub mod pci;
pub mod regs;

pub mod rtl8188ee;
pub mod rtl8192ce;
pub mod rtl8192ee;
pub mod rtl8723be;
pub mod rtl8821ae;
pub mod rtl8822be;

pub use pci::{name_for, probe, register_pci_driver, RtlwifiDevice};
pub use regs::{REALTEK_VENDOR, ALL_DEV_IDS};

/// Entry point invoked from `drivers/wireless/src/lib.rs`.
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
