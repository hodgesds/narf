// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI SDIO host controller driver for NARF.
//!
//! Owned standard SDHCI PIO execution, 3.3-V one-bit SDIO enumeration,
//! checked function access and PCI function-driver dispatch. See
//! `specification/spec.md` for the supported profile and remaining platform,
//! vendor-quirk, DMA and hotplug work. CYW43439 consumes this live host.
//!
//! ## References
//!
//! - SD Host Controller Simplified Specification v4.20 (SD Association).
//! - SDIO Simplified Specification v3.00 (SD Association).
//! - Linux `drivers/mmc/host/sdhci.{c,h}` (GPL-2.0-or-later, adapted).
//! - Linux `drivers/mmc/core/sdio{.c,_cis.c,_ops.c}` (GPL-2.0-or-later, adapted).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(dead_code)]

extern crate alloc;

pub mod card;
pub mod host;
pub mod native;
pub mod pio;
pub mod sdhci;
pub mod sdio;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

// Re-export the most-used types at crate root for convenience.
pub use host::SdhciHost;
pub use sdhci::probe::{probe_device, ProbeResult};
pub use sdhci::regs::PCI_CLASS_SDHCI;
pub use sdhci::voltage::SignalVoltage;
pub use sdio::cccr::{CccrInfo, FBR_BLKSZ_0, FBR_CIS_PTR_0, FBR_STD_IF};
pub use sdio::function::{SdioError, SdioFunction};
