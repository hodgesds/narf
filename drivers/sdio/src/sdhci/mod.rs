// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI host-controller sub-modules.
//!
//! - [`regs`]    — MMIO register offsets and bit constants.
//! - [`cmd`]     — Command-word encoders for CMD0/3/5/7/52/53.
//! - [`probe`]   — PCI class 0x080500 device-match logic.
//! - [`voltage`] — 1.8 V signalling switch helpers.

pub mod cmd;
pub mod probe;
pub mod regs;
pub mod voltage;
