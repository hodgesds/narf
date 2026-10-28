//! MediaTek MT7921 / MT7922 / MT7961 Wi-Fi 6E (CONNAC 2.0) PCIe.
//!
//! Targets the MediaTek silicon shipping in current AMD-Zen / Phoenix
//! HawkPoint1 laptops:
//!
//! - **MT7921** — Wi-Fi 6 2x2 (`14c3:0608`).
//! - **MT7961** — Wi-Fi 6E 2x2 (`14c3:7961`). Re-tags to MT7920 at
//!   runtime when `MT_HW_BOUND[7]` is set (DBDC bond).
//! - **MT7922** — Wi-Fi 6E 2x2, newer cut (`14c3:7922`, `14c3:0616`, also
//!   `0e8d:7922` for the ITTIM-vendor SKU).
//!
//! ## Implemented bringup
//!
//! PCI discovery validates the BAR and checked CONNAC2 register windows,
//! obtains ownership and defers firmware work until the late init stage.
//! `firmware_transport` owns coherent WM/FWDL/MCU rings and performs bounded
//! patch/RAM download through the live MCU protocol. Published allocations
//! survive failure or cancellation until verified DMA shutdown.
//!
//! Post-firmware initialization reads real NIC/EFUSE identity, applies
//! package-selected world limits and initializes the MAC/WTBL. Passive
//! scanning is connected to nl80211; management TX has a private retained
//! cut-through backend. The retained legacy station profile connects Open/WPA2
//! association, controlled-port keys and bounded kernel/frame-ring RX/TX service.
//! Reset/recovery retires old DMA before firmware reload on x86_64/aarch64.
//! Broader radio modes remain software work. The older `full_bring_up` boundary intentionally returns `NotImplemented`;
//! firmware-only initialization uses the retained transport owner instead.
//!
//! ## Provenance
//!
//! All adaptation from Linux `drivers/net/wireless/mediatek/mt76/`
//! (GPL-2.0). NARF is GPL-2.0-or-later since 2026-05-20; per-file
//! provenance lives next to the constants and code that consume it.

#![allow(dead_code)]

pub mod association;
pub mod bringup;
pub(crate) mod channel;
pub mod cmd;
pub mod dma;
mod firmware_assets;
mod firmware_parser_tests;
pub mod firmware_transport;
pub mod fwdl;
pub(crate) mod he;
pub(crate) mod ht20;
pub mod mac;
pub mod mcu;
mod packet_tx;
pub mod pci;
mod registers;
mod registers_tests;
pub mod regs;
pub(crate) mod tx_priority;
pub mod txrx;
pub(crate) mod vht;

pub use pci::{
    firmware_blobs_for, l1_remap, name_for, probe, register_pci_driver, Mt7921Device, ProbeError,
};
pub use regs::{
    ALL_DEV_IDS, ITTIM_VENDOR, MTK_DEV_MT7920, MTK_DEV_MT7921, MTK_DEV_MT7921_ALT, MTK_DEV_MT7922,
    MTK_DEV_MT7961, MTK_VENDOR,
};

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
    narf_init::register_with_budget(
        narf_init::Stage::Late,
        "mt76-firmware",
        firmware_transport::start_boot,
        60_000,
    );
}

// Co-located smokes. The whole `mt7921` module compiles only under the
// crate's `builtin` feature, which pulls `narf-kernel-test`, so the smokes are
// always available here — they register into `narf.tests` via `kernel_test_in!`
// (same shape as `drivers/net/i40e/src/i40e/tests.rs`).
pub mod tests;
