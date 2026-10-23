//! Broadcom FullMAC PCIe — `brcmfmac` PCIe-bus path.
//!
//! Targets the PCIe-attached Broadcom FullMAC Wi-Fi parts. SDIO-attached
//! relatives (CYW43439, the BCM43xxx mobile family) live in
//! `crate::cyw43439`; this crate covers the desktop / Apple / enterprise
//! parts that ride PCIe and speak the **msgbuf** protocol over Broadcom's
//! H2D / D2H common-ring layout.
//!
//! PCI ownership now clears inherited bus mastering, retains authority,
//! discovers actual AI cores through the serialized BAR0 window, and
//! parks interrupts using the discovered PCIe core revision. This does
//! not reset the chip or publish a usable network interface. The other
//! modules contain wire/cursor helpers; firmware activation, owned DMA
//! rings, flow rings, station lifecycle, and recovery remain software
//! work. See `specification/brcmfmac.md` for the ordered dependency list.
//!
//! ## References (all ISC / BSD-3 / GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c`
//!   — `brcmf_pcie_probe`, register window + soft-reset
//!   (v6.6 ~L117..L300 for the register map, ~L2700..L2780 for
//!   the PCI ID table).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/commonring.c`
//!   — `brcmf_commonring_*` ring index dance (entire file).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/msgbuf.c`
//!   — `msgbuf_*` message structs + IOCTL flow
//!   (v6.6 ~L30..L180).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/msgbuf.h`
//!   — per-ring depth + item-size table (~L10..L23).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/bus.h`
//!   — `BRCMF_{H2D,D2H}_MSGRING_*` ring-id assignment (~L14..L26).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/include/brcm_hw_ids.h`
//!   — the canonical PCIe device-id table (lines 16..101).
//!
//! NARF is GPL-2.0-or-later (root `LICENSE`), so direct reference to
//! these ISC / GPL-2.0 Linux files is in-policy.

#![allow(dead_code)]

extern crate alloc;

pub mod bus;
pub mod cfg80211;
pub mod chip;
pub mod connect;
pub mod firmware;
pub mod fweh;
pub mod fwil;
pub mod msgbuf;
pub mod pcie;
pub mod ringbuf;
pub mod shared;

pub use pcie::{name_for, probe, register_pci_driver, BrcmfmacDevice, BROADCOM_VENDOR};

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}
