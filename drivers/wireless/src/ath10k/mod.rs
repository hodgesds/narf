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
//! ## Stage 0 (prior commit)
//!
//! - PCI match table (vendor 0x168c + Ubiquiti rebadge).
//! - BAR0 mapping.
//! - `SOC_GLOBAL_RESET_ADDRESS` soft-reset.
//! - `SOC_CHIP_ID` readback + decoded `(hw_rev, chip_id, rev)`
//!   logging.
//!
//! ## Stage 1 (prior commit)
//!
//! - Copy-Engine (CE) descriptor + ring-config structs.
//! - `program_src_ring` / `program_dst_ring` / `halt_pipe`
//!   register-programming helpers, abstracted over a mockable
//!   `Ath10kMmio` trait so the CE setup code is unit-testable.
//! - Default per-pipe configuration table mirroring Linux's
//!   `host_ce_config_wlan`.
//!
//! ## Stage 2 (prior commit)
//!
//! - HTC frame builder/parser (8-byte header + ConnectService /
//!   SetupComplete bodies).
//! - WMI command-id codec (24-bit cmd_id + 8-bit plt_priv).
//! - WMI Encoder for command-frame assembly; EventFrame decoder for
//!   firmware → host responses.
//! - `run_handshake` / `wmi_send` return `Err(NotImplemented)`.
//!
//! ## Stage 3 (this commit)
//!
//! - HTT RX ring setup command (`htt.rs`): ring layout, encode,
//!   and RX-indication decode. Reference: `htt.h` / `htt_rx.c`.
//! - WMI VDEV_CREATE + VDEV_SET_PARAM command builders (`wmi.rs`).
//!   Reference: `wmi.c::ath10k_wmi_vdev_create_send` (line 7146).
//!
//! ## References (Linux v6.10)
//!
//! - `drivers/net/wireless/ath/ath10k/pci.c` — `ath10k_pci_probe`,
//!   `ath10k_pci_id_table` (lines ~57..97 v6.10).
//! - `drivers/net/wireless/ath/ath10k/hw.h` — base-address +
//!   register-offset constants (lines ~860..1020).

#![allow(dead_code)]

extern crate alloc;

pub mod ce;
pub mod htc;
pub mod htt;
pub mod hw;
pub mod pci;
pub mod wmi;

pub use hw::{HwRev, ALL_PCI_MATCHES, ATHEROS_VENDOR, UBNT_VENDOR};
pub use pci::{name_for, probe, register_pci_driver, Ath10kDevice, ProbeError};

/// Entry point invoked from the wireless crate's `register_initcalls`.
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
