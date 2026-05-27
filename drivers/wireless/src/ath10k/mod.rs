//! Qualcomm Atheros 802.11ac (ath10k) PCIe driver.
//!
//! Targets the QCA988X / QCA6174 / QCA6164 / QCA99X0 / QCA9377 /
//! QCA9888 / QCA9984 family — the original 802.11ac Wave-1 + Wave-2
//! Qualcomm-Atheros silicon that still ships on a huge installed
//! base of laptops, mini-PCs, and APs.
//!
//! ## Architecture (1 paragraph)
//!
//! ath10k devices expose a *single* BAR0 register window. The host
//! talks to the device's on-board firmware over **Copy Engines (CE)**
//! — programmable DMA pipes. CE0/CE1 carry HTC control messages
//! (the framing layer); CE2/CE3 carry WMI commands (the actual
//! Wi-Fi MAC commands — scan, associate, set-channel, ...); CE4/CE5
//! carry HTT data (TX/RX frames). The driver:
//!   1. Soft-resets the SoC.
//!   2. Loads the chip-specific BDF/OTP/Cal blobs (firmware).
//!   3. Sets up the 8 CE rings.
//!   4. Performs the HTC handshake.
//!   5. Tells the firmware about WMI services.
//!   6. Receives a "ready" WMI event, then starts behaving as a
//!      normal Wi-Fi NIC over HTT.
//!
//! ## Stage 0 (this commit)
//!
//! - PCI match table (vendor 0x168c + Ubiquiti rebadge).
//! - BAR0 mapping.
//! - `SOC_GLOBAL_RESET_ADDRESS` soft-reset.
//! - `SOC_CHIP_ID` readback + decoded `(hw_rev, chip_id, rev)`
//!   logging.
//! - "Firmware required at /firmware/ath10k/<NAME>/" hint.
//!
//! CE ring setup, HTC handshake, and WMI dispatch land in
//! follow-up commits.
//!
//! ## References (Linux v6.10, ISC-licensed — NARF is
//! GPL-2.0-or-later post 2026-05-20, so direct adaptation is in-
//! policy per `memory/MEMORY.md::feedback_no_gpl_links.md`)
//!
//! - `drivers/net/wireless/ath/ath10k/pci.c` — `ath10k_pci_probe`,
//!   `ath10k_pci_id_table` (lines ~57..97 v6.10).
//! - `drivers/net/wireless/ath/ath10k/hw.h` — base-address +
//!   register-offset constants (lines ~860..1020).

#![allow(dead_code)]

extern crate alloc;

pub mod hw;
pub mod pci;

pub use hw::{HwRev, ALL_PCI_MATCHES, ATHEROS_VENDOR, UBNT_VENDOR};
pub use pci::{name_for, probe, register_pci_driver, Ath10kDevice, ProbeError};

/// Entry point invoked from the wireless crate's `register_initcalls`.
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
