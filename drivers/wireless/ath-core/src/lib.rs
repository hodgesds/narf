// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared Atheros/Qualcomm Wi-Fi code.
//!
//! The driver-agnostic half of the ath family, factored out of the
//! `narf-drivers-wireless` facade so per-driver crates depend on this crate
//! rather than on the facade that aggregates them (or on each other). The
//! facade re-exports `qualcomm_pci`/`qualcomm_regulatory`, and the ath11k
//! driver re-exports the items promoted here out of its `tx_hdr`/`board`/`wmi`
//! modules, so existing in-tree references are unaffected.

#![no_std]

extern crate alloc;

pub mod board;
pub mod eth;
#[cfg(feature = "kernel")]
pub mod qualcomm_pci;
pub mod qualcomm_regulatory;
pub mod wmi_nlo;
