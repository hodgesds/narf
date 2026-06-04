// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI SDIO host controller driver for NARF.
//!
//! ## What this crate provides
//!
//! 1. **PCI probe** (`sdhci::probe`) — matches class 0x080500, extracts BAR0.
//! 2. **SDHCI register map** (`sdhci::regs`) — all MMIO offsets + bit masks.
//! 3. **Bus command encoders** (`sdhci::cmd`) — CMD0/3/5/7/52/53 argument
//!    words, R4/R5 response decoding.
//! 4. **1.8 V switch helpers** (`sdhci::voltage`) — power-control and
//!    host-control-2 register values for the UHS-I voltage transition.
//! 5. **Host state** (`host`) — `SdhciHost` struct: capabilities decode,
//!    clock-divider calculation, RCA/OCR storage.
//! 6. **SDIO protocol** (`sdio::cccr`) — CCCR + FBR register addresses,
//!    CIS tuple decoders (MANFID, FUNCID, FUNCE).
//! 7. **`SdioFunction` trait** (`sdio::function`) — per-function CMD52/53
//!    surface consumed by chip drivers (e.g. cyw43439 bridge).
//!
//! ## Deferred
//!
//! - UHS-II (CMD11 + re-tuning loop, eMMC HS400, SD secure erase).
//! - DMA ring / ADMA2 descriptor management.
//! - Live MMIO register I/O (needs `narf-bus` MMIO cap surface);
//!   encoders here are pure computation that can be unit-tested without HW.
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

pub mod host;
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
