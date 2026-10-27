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
//!
//! RTL8822BE (0xB822) is not in this family: it belongs to `rtw88`
//! (`specification/rtlwifi.md` §1) and must never be matched here.
//!
//! ## Scope (this commit)
//!
//! 1. PCI device-ID table — all 8 IDs registered with `narf-bus`.
//! 2. BAR2 control mapping and verifiably parked PCI bus mastering.
//! 3. EFUSE read — per-byte LDO-switched access (`REG_EFUSE_CTRL` / `REG_EFUSE_TEST`).
//! 4. Per-chip register-bank / MMIO-size constants.
//! 5. TX descriptor layout (BE queue) + RX descriptor layout.
//! 6. Retained RTL8188EE authenticated paged firmware and inactive linked-ring/LLT owner.
//!    Other silicon profiles remain diagnostic.
//!
//! ## Deferred
//!
//! - Complete power/reset flows for silicon beyond RTL8188EE.
//! - Firmware transport for the remaining legacy parts.
//! - Active DMA, complete MAC/BB/RF/calibration and station packet runtime.
//! - MSI / INTx IRQ routing.
//! - Bluetooth co-existence (8723AE/BE).
//!
//! Until those firmware-backed paths exist, the registered diagnostic
//! interface remains down: scan, association, and configuration return
//! `WirelessError::NotSupported` rather than claiming a usable WLAN.
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

pub mod btcoex;
pub mod channel;
pub mod channel_power;
pub mod dma;
pub mod efuse;
mod firmware_native;
pub mod firmware_transport;
pub mod fw;
pub mod h2c;
mod ht;
mod interface;
pub use ht::Request as Ht20Request;
pub mod irq;
pub mod mac;
mod packet_mac;
pub mod pci;
pub mod phy;
pub mod power;
pub mod prepare;
mod prepare_native;
pub mod radio;
pub mod regs;
pub mod rf;
pub mod rx;
mod station_control;
pub mod tx;
pub mod vht;
pub(crate) mod wmm;

pub mod rtl8188ee;
pub mod rtl8192ce;
pub mod rtl8192ee;
pub mod rtl8723be;
pub mod rtl8821ae;

pub use pci::{name_for, probe, register_pci_driver, RtlwifiDevice};
pub use regs::{ALL_DEV_IDS, REALTEK_VENDOR};

/// Entry point invoked from `drivers/wireless/src/lib.rs`.
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
mod efuse_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
