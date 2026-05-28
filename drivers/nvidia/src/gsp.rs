//! GSP — GPU System Processor (Turing+).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/base.c`**
//!   — generic `nvkm_gsp_*`. The host driver stages a signed
//!   bootloader ("booter load"), waits for WPR2 to assert, then
//!   feeds the GSP firmware blob and the RM (Resource Manager)
//!   message-queue config.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/gsp/tu102.c`** — Turing
//!   GSP bring-up (cited above): WPR2_HI scratch readback +
//!   booter_load + booter_unload Falcons.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/gsp/ga102.c`** /
//!   **`ad102.c`** — Ampere / Ada additions; RISC-V mode bits on
//!   the boot Falcon.
//!
//! ## Overview
//!
//! On Turing+ the GPU has a dedicated processor ("GSP") that
//! takes over almost every register write the host driver used
//! to do directly. The host:
//!
//! 1. Stages signed bootloader code into the boot Falcon's IMEM.
//! 2. Releases the boot Falcon; it sets up WPR2 (Window of
//!    Protected Regions 2) in VRAM and runs FWSEC.
//! 3. The GSP firmware runs inside WPR2 and exposes an RPC
//!    message queue.
//! 4. Host writes RPC messages into a ring (`MsgQ`) the firmware
//!    polls; firmware reports completion + events back through a
//!    separate ring.
//!
//! After GSP comes up, the host driver is basically a thin
//! message-pump for RPCs.

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FalconError, FALCON_BASE_GSP};

/// Per-engine `NV_PFALCON_FBIF_*` (FB interface) base offset
/// inside the GSP Falcon block. The host writes the WPR2 region
/// descriptor here. Cite `nvkm/subdev/gsp/tu102.c` &
/// `nvkm/falcon/v1.c::*_fbif`.
pub const FBIF_OFFSET: u64 = 0x0000_0600;

/// `NV_PGC6_AON_SECURE_SCRATCH_GROUP_05` — WPR2 hi address
/// scratch. Used to detect whether WPR2 is set up.
/// Cite `tu102.c::tu102_gsp_booter_unload` line "0x1fa828".
pub const WPR2_HI_SCRATCH: u64 = 0x001F_A828;

/// RPC message types — Nouveau's `rm/r535/nvrm/msgfn.h` aliases.
/// Stage 1 only exposes the canonical control set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GspRpcFn {
    /// `NV_VGPU_MSG_FUNCTION_NOP` — link-test ping.
    Nop = 0x0001,
    /// `NV_VGPU_MSG_FUNCTION_SET_REGISTRY` — register key write.
    SetRegistry = 0x0002,
    /// `NV_VGPU_MSG_FUNCTION_ALLOC_ROOT` — allocate the root
    /// handle that subsequent RPCs descend from.
    AllocRoot = 0x0003,
    /// `NV_VGPU_MSG_EVENT_GSP_INIT_DONE` — firmware reports
    /// init done.
    EventInitDone = 0x1001,
}

/// GSP RPC message-queue ring shape. Cite
/// `nvkm/subdev/gsp/r535/r535.c::r535_gsp_msgq_*`.
///
/// The firmware reserves two queues — host→GSP (cmdq) and
/// GSP→host (msgq) — at fixed VRAM offsets handed to it via the
/// bootloader scratch fields. Both are SPSC rings with a
/// CPU-visible mailbox at the head.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GspRpcRing {
    /// Phys address (VRAM) of the ring base.
    pub base_phys: u64,
    /// Ring size in bytes. Must be a power of two.
    pub size_bytes: u32,
    /// Read pointer the firmware advances.
    pub rptr: u32,
    /// Write pointer the host advances.
    pub wptr: u32,
}

impl GspRpcRing {
    pub const fn new(base_phys: u64, size_bytes: u32) -> Self {
        Self {
            base_phys,
            size_bytes,
            rptr: 0,
            wptr: 0,
        }
    }

    /// True if this entry is empty (no work).
    pub const fn is_empty(&self) -> bool {
        self.rptr == self.wptr
    }

    /// True if the ring is full — wptr + 1 == rptr (mod size).
    pub const fn is_full(&self, msg_bytes: u32) -> bool {
        let next = self.wptr.wrapping_add(msg_bytes) & (self.size_bytes - 1);
        next == self.rptr
    }
}

/// GSP handle. Wraps a Falcon at the GSP base + ring descriptors.
pub struct Gsp<'a> {
    pub falcon: Falcon<'a>,
    pub cmdq: GspRpcRing,
    pub msgq: GspRpcRing,
}

impl<'a> core::fmt::Debug for Gsp<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gsp")
            .field("falcon_base", &FALCON_BASE_GSP)
            .field("cmdq", &self.cmdq)
            .field("msgq", &self.msgq)
            .finish()
    }
}

impl<'a> Gsp<'a> {
    pub const fn new(
        bar0: &'a narf_driver_runtime::MmioRegion,
        cmdq: GspRpcRing,
        msgq: GspRpcRing,
    ) -> Self {
        Self {
            falcon: Falcon::new(bar0, FALCON_BASE_GSP, "gsp"),
            cmdq,
            msgq,
        }
    }

    /// Pre-flight check: family must be Turing+ to have a GSP.
    pub fn family_has_gsp(family: ChipFamily) -> bool {
        family.has_gsp()
    }

    /// Read WPR2_HI scratch — non-zero means WPR2 is set up,
    /// i.e. the booter Falcon has run. Cite tu102.c line
    /// "0x1fa828".
    ///
    /// # Safety
    /// `bar0` is mapped and covers offset WPR2_HI_SCRATCH.
    pub unsafe fn wpr2_active(&self) -> bool {
        // SAFETY: caller's responsibility.
        unsafe { self.falcon.bar0.read32(WPR2_HI_SCRATCH) != 0 }
    }

    /// Wait for `wpr2_active` to flip true.
    ///
    /// # Safety
    /// Same.
    pub unsafe fn wait_wpr2(&self, max_polls: u32) -> Result<(), FalconError> {
        for _ in 0..max_polls {
            // SAFETY: caller's responsibility.
            if unsafe { self.wpr2_active() } {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(FalconError::IdleTimeout)
    }
}
