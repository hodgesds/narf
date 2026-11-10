//! SEC2 — Security Engine 2 (Falcon-based).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/sec2/base.c`**
//!   — generic `nvkm_sec2_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/sec2/gp102.c`** —
//!   Pascal/Volta SEC2 (loads HDCP firmware + Falcon ucode
//!   signing).
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/sec2/tu102.c`** —
//!   Turing SEC2 (used by the booter to set up WPR2 before GSP
//!   takes over).
//!
//! SEC2 is a Falcon at BAR0 0x840000. The host driver stages
//! signed firmware (vendor-supplied) and uses SEC2 to:
//!
//! - Verify and load other Falcon firmwares (PMU, GSP booters).
//! - Run HDCP 2.x key exchange for protected video output.
//! - Bootstrap WPR2 on Turing+ before handing control to GSP.

#![allow(dead_code)]

use crate::falcon::{Falcon, FALCON_BASE_SEC2};

/// SEC2 commands — message-types written to MAILBOX0 to ask the
/// firmware to do work. Cite
/// `include/subdev/sec2.h::NV_SEC2_CMD_*`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Sec2Cmd {
    /// Verify and load another Falcon firmware blob.
    LoadFw = 0x0001,
    /// Boot the WPR2 region (Turing+).
    BootWpr2 = 0x0002,
    /// Run HDCP 2.x key exchange.
    HdcpKx = 0x0010,
}

/// SEC2 handle. Wraps a Falcon at SEC2's base.
#[derive(Debug)]
pub struct Sec2<'a> {
    pub falcon: Falcon<'a>,
}

impl<'a> Sec2<'a> {
    pub const fn new(bar0: &'a narf_driver_runtime::MmioRegion) -> Self {
        Self {
            falcon: Falcon::new(bar0, FALCON_BASE_SEC2, "sec2"),
        }
    }
}
