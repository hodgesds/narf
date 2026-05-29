//! MediaTek MT7921 / MT7922 / MT7961 Wi-Fi 6E (CONNAC 2.0) PCIe.
//!
//! Targets the MediaTek silicon shipping in current AMD-Zen / Phoenix
//! HawkPoint1 laptops:
//!
//! - **MT7921** — Wi-Fi 6 2x2 (`14c3:0608`, `14c3:0616`).
//! - **MT7961** — Wi-Fi 6E 2x2 (`14c3:7961`). Re-tags to MT7920 at
//!   runtime when `MT_HW_BOUND[7]` is set (DBDC bond).
//! - **MT7922** — Wi-Fi 6E 2x2, newer cut (`14c3:7922`, also
//!   `0e8d:7922` for the ITTIM-vendor SKU).
//!
//! ## Scope reached (this commit set)
//!
//! - **Stage 0** — PCI device-id table for the 5 known IDs, BAR0
//!   mapping, presence test via `MT_PCIE_MAC_INT_ENABLE`, chip-id +
//!   revision read via the L1 remap, MT7920 re-tagging.
//! - **Stage 1** — driver-own / FW-own handshake against
//!   `MT_CONN_ON_LPCTL`, L0s-disable on the PCIe MAC, firmware-blob
//!   name resolution for (patch + RAM code), trusted-loader authority
//!   open. Real patch-apply is deferred to Stage 2.
//! - **Stage 2 scaffolding** — TX/RX ring queue-id constants
//!   (`MT7921_TXQ_AC_*` / `MT7921_TXQ_BMC`, `MT7921_RXQ_DATA` /
//!   `MT7921_RXQ_MCU_EVENT`), `MCU_EXT_CMD` header byte encoder.
//!
//! ## Out of scope (deferred — explicit)
//!
//! - DMA ring memory allocation + descriptor encoding. Needs
//!   `narf_memory::dma_alloc` ring helpers + WFDMA0 register
//!   programming (`MT_WFDMA0_RING_BASE_*`).
//! - MCU patch-apply + RAM-code download (depends on FWDL ring).
//! - EFUSE read (depends on alive MCU).
//! - 802.11 association / scan / management — those land via the
//!   shared `narf-wireless` crate once the MCU mailbox is live.
//!
//! ## Provenance
//!
//! All adaptation from Linux `drivers/net/wireless/mediatek/mt76/`
//! (GPL-2.0). NARF is GPL-2.0-or-later since 2026-05-20; per-file
//! provenance lives next to the constants and code that consume it.

#![allow(dead_code)]

extern crate alloc;

pub mod dma;
pub mod mac;
pub mod mcu;
pub mod pci;
pub mod regs;
pub mod txrx;

pub use pci::{
    firmware_blobs_for, l1_remap, name_for, probe, register_pci_driver, Mt7921Device, ProbeError,
};
pub use regs::{
    ALL_DEV_IDS, ITTIM_VENDOR, MTK_DEV_MT7920, MTK_DEV_MT7921, MTK_DEV_MT7921_ALT,
    MTK_DEV_MT7922, MTK_DEV_MT7961, MTK_VENDOR,
};

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
