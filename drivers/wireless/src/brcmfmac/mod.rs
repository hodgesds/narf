//! Broadcom FullMAC PCIe — `brcmfmac` PCIe-bus path.
//!
//! Targets the PCIe-attached Broadcom FullMAC Wi-Fi parts. SDIO-attached
//! relatives (CYW43439, the BCM43xxx mobile family) live in
//! `crate::cyw43439`; this crate covers the desktop / Apple / enterprise
//! parts that ride PCIe and speak the **msgbuf** protocol over Broadcom's
//! H2D / D2H common-ring layout.
//!
//! ## Stage progression
//!
//! - **Stage 0 (this commit)** — PCI device match table (vendor
//!   `0x14E4`, the BCM43602 / 4350 / 4356 / 4358 / 4365 / 4366 / 4371 /
//!   4378 / 4387 family), BAR0 (32 KiB register window) map, and a
//!   soft-reset prologue via the PCIE2 mailbox-int / mailbox-mask
//!   registers. Firmware-blob name lookup is included so the data-path
//!   follow-up has a stable hook.
//! - **Stage 1 (next)** — Common-ring SPSC index dance + the per-ring
//!   layout table from `msgbuf.h`.
//! - **Stage 2 (after)** — msgbuf protocol encoders/decoders (IOCTL
//!   request/response + WL event); firmware-load stub.
//!
//! TX/RX data path, flow-ring management, cfg80211 attach, scan/assoc
//! and the firmware-side console reader are explicitly **not** in
//! Stage-0 / Stage-1.
//!
//! ## References (all ISC / BSD-3 / GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c`
//!     — `brcmf_pcie_probe`, register window + soft-reset
//!       (v6.6 ~L117..L300 for the register map, ~L2700..L2780 for
//!       the PCI ID table).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/chip.c`
//!     — chip-id read protocol (consulted by the Stage-1 ChipCommon
//!       walker that lands in the next commit).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/include/brcm_hw_ids.h`
//!     — the canonical PCIe device-id table (lines 16..101).
//!
//! NARF is GPL-2.0-or-later (root `LICENSE`), so direct reference to
//! these ISC / GPL-2.0 Linux files is in-policy.

#![allow(dead_code)]

extern crate alloc;

pub mod pcie;

pub use pcie::{name_for, probe, register_pci_driver, BrcmfmacDevice, BROADCOM_VENDOR};

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}
