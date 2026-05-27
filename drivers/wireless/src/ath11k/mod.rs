//! Qualcomm ath11k — 802.11ax (Wi-Fi 6 / 6E) PCIe.
//!
//! Targets the four chip families that ship in the AMD-laptop
//! ecosystem NARF cares about:
//!
//! - **QCA6390** (`17cb:1101`) — Wi-Fi 6 2x2.
//! - **QCN9074** (`17cb:1104`) — Wi-Fi 6 stand-alone NIC.
//! - **WCN6855** / QCA2066 (`17cb:1103`, `17cb:1105`) — Wi-Fi 6E.
//! - **WCN7850** (`17cb:1107`) — Wi-Fi 6E / 7 (used in HawkPoint1
//!   laptops; ath12k upstream but ath11k can probe).
//! - **QCN6122 / QCN9224** (`17cb:1109`) — extension series.
//!
//! Architecture in three layers:
//!
//! 1. [`pci`] — vendor/device match, BAR0 mapping, the sliding
//!    32 KiB register window the chip exposes for its 4 MiB
//!    register file, SoC global-reset prologue, and the hw_rev
//!    refinement step (decode TCSR major/minor → `HwRev`).
//! 2. [`mhi`] — Modem-Host-Interface ring + state-machine
//!    scaffolding. ath11k is firmware-driven via MHI rather than
//!    ath10k's Copy Engines; channel/event configs + TRE packers
//!    live here.
//! 3. [`wmi`] — Wireless Management Interface TLV frame
//!    builder / decoder. The control plane for everything past
//!    INIT.
//! 4. [`dp`] — Data-path ring descriptor layouts (TCL / REO /
//!    WBM). Sizes + `#[repr(C)]` structs only; live ring
//!    allocation lands with Stage-2.
//!
//! ## Scope (this commit)
//!
//! Stage 0+1:
//!   - PCI device-id match registration.
//!   - BAR0 mapping + the sliding-window register API.
//!   - SoC global reset + LTSSM enable prologue (per the Linux
//!     pci.c bring-up path).
//!   - hw_rev resolution + log line.
//!
//! Stage 2 (deferred — gated at `Err(ProbeError::NotImplemented)`):
//!   - MHI controller register + start.
//!   - Firmware load (AMSS image via `narf-firmware`).
//!   - WMI INIT handshake.
//!   - DP ring allocation + REO/TQM/TCL programming.
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

pub mod dp;
pub mod hw;
pub mod mhi;
pub mod pci;
pub mod wmi;

pub use hw::{
    chip_for_pci_id, name_for, ChipInfo, HwRev, ATH11K_DEV_QCA2066, ATH11K_DEV_QCA6390,
    ATH11K_DEV_QCN6122, ATH11K_DEV_QCN9074, ATH11K_DEV_WCN6855, ATH11K_DEV_WCN7850, QCOM_VENDOR,
};
pub use pci::{probe, register_pci_driver, Ath11kDevice, ProbeError};

/// Entry point invoked from the wireless crate's
/// `register_initcalls` (one level up in
/// `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
