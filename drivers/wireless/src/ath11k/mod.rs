//! Qualcomm ath11k — 802.11ax (Wi-Fi 6 / 6E) PCIe.
//!
//! Matches exactly Linux's `ath11k_pci_id_table`:
//!
//! - **QCA6390** (`17cb:1101`) — Wi-Fi 6 2x2.
//! - **WCN6855** (`17cb:1103`) — Wi-Fi 6E; also enumerates the
//!   QCA2066 and QCA6698AQ variants, told apart by
//!   `TCSR_SOC_HW_SUB_VER`. Lenovo's QCNFA765 M.2 module is a WCN6855.
//! - **QCN9074** (`17cb:1104`) — Wi-Fi 6 stand-alone NIC.
//!
//! WCN7850 (`17cb:1107`) is an ath12k part and is not claimed here.
//!
//! Layers:
//!
//! 1. [`pci`] — vendor/device match, BAR0 mapping, direct vs.
//!    sliding-window register access, hw_rev resolution.
//! 2. [`power`] — reset / LTSSM / L1SS power-up sequence.
//! 3. [`mhi`] — Modem-Host-Interface ring + channel-table data.
//! 4. [`wmi`] — WMI TLV frame builder / decoder.
//! 5. [`dp`] — data-path ring descriptor layouts (TCL / REO / WBM).
//!
//! ## Status
//!
//! Probe identifies the chip and its firmware directory, allocates
//! MSI and runs Linux's power-up sequence, then stops: no MHI host, firmware boot, QMI, CE/HTC/WMI transport or
//! data path yet, so no network interface is registered.
//!
//! ## References
//!
//! Post-2026-05-20 GPL relicense permits direct citation; ath11k
//! itself is BSD-3-Clause-Clear (a permissive license compatible
//! with NARF's GPL-2.0-or-later):
//! - `drivers/net/wireless/ath/ath11k/pci.c`,
//! - `drivers/net/wireless/ath/ath11k/mhi.{c,h}`,
//! - `drivers/net/wireless/ath/ath11k/wmi.{c,h}`,
//! - `drivers/net/wireless/ath/ath11k/dp.{c,h}`,
//! - `drivers/net/wireless/ath/ath11k/hal_desc.h`,
//! - `drivers/net/wireless/ath/ath11k/core.{c,h}`.

#![allow(dead_code)]

extern crate alloc;

pub mod board;
pub mod ce;
pub mod core;
pub mod dp;
pub mod dp_ring;
pub mod hal;
pub mod htc;
pub mod htt;
pub mod hw;
pub mod mac;
pub mod mac_frame;
pub mod mac_peer;
pub mod mac_reg;
pub mod mhi;
pub mod mhi_host;
pub mod pci;
pub mod power;
pub mod qmi;
pub mod qmi_client;
pub mod qmi_wlfw;
pub mod qrtr;
pub mod wlfw;
pub mod wmi;
pub mod wmi_ids;

pub use hw::{
    chip_for_pci_id, name_for, ChipInfo, HwRev, ATH11K_DEV_QCA6390, ATH11K_DEV_QCN9074,
    ATH11K_DEV_WCN6855, QCOM_VENDOR,
};
pub use pci::{probe, register_pci_driver, Ath11kDevice, ProbeError};

/// Entry point invoked from the wireless crate's
/// `register_initcalls` (one level up in
/// `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod ce_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod core_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod dp_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod hal_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod htt_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod mac_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod mhi_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod qmi_handshake_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod qmi_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
#[cfg(any(test, feature = "kernel-test"))]
pub mod wmi_tests;
