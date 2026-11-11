//! PMU — Power Management microcontroller (Falcon-based).
//!
//! ## Reference — the no-firmware model (corrected 2026-11-10, G2)
//!
//! The PMU on Maxwell/Pascal is **not** host-staged. Upstream
//! Nouveau loads no PMU firmware on these parts:
//!
//! - `drivers/gpu/drm/nouveau/nvkm/subdev/pmu/gp102.c` — the Pascal
//!   firmware-interface list is a single entry,
//!   `{ -1, gm200_pmu_nofw, &gp102_pmu }`; `gm200_pmu_nofw` just
//!   warns "firmware unavailable" and returns 0.
//! - Same for Maxwell: `gm200.c` (`gm200_pmu_nofw`) and `gm107.c`
//!   (`gf100_pmu_nofw`); Fermi's `gf100.c` is also `nofw`, and its
//!   firmware is built-in fuc microcode (`.code`/`.data` in the
//!   `gf100_pmu` func struct), not a file.
//! - The PMU runs firmware the board/VBIOS loaded (PREOS):
//!   `nvkm/subdev/pmu/base.c::nvkm_pmu_fan_controlled` notes the
//!   "board-loaded, or VBIOS PMU/PREOS" firmware. Nouveau's
//!   `nvkm_pmu_init` is a no-op for gp102 (its func struct has no
//!   `.init`); the driver only constructs the Falcon handle plus
//!   the command/message queues and talks to the already-running
//!   PMU.
//! - `linux-firmware` ships **no** `nvidia/*/pmu/` blobs for any
//!   chip (checked 2026-11-10 on the current kernel.org mirror:
//!   `nvidia/gp107/` is `gr/` only, `nvidia/tu102/` is
//!   `acr/gr/gsp/nvdec/sec2/`). The signed blobs that do ship are
//!   per-engine ACR/LS loads (GR FECS/GPCCS, SEC2, GSP, NVDEC),
//!   not PMU staging.
//!
//! The previous staging model in this file was wrong and is deleted:
//! `stage_pmu_from_firmware` loaded `desc.bin` bytes as the DMEM
//! image, but a desc is a *descriptor*, never firmware payload —
//! `nvkm/nvfw/flcn.c::flcn_bl_dmem_desc` and
//! `nvkm/nvfw/ls.c::nvfw_ls_desc` parse it as code/data DMA bases,
//! sizes, entry point, and signature offsets. `sig.bin` was never
//! opened. Resetting the live PMU Falcon and loading those bytes
//! would have destroyed the VBIOS-loaded firmware, and the blobs
//! do not exist to load in the first place.
//!
//! The probe-time PMU step is therefore an **attach, not a load**:
//! check the PMU engine is enabled in `PMC_ENABLE`
//! (`Pmu::engine_enabled`, grounded on `nvkm/subdev/mc/gk104.c`
//! `gk104_mc_reset[]` via `gp100_mc`, tested by
//! `nv04_mc_device_enabled` against BAR0+0x200) and record the
//! result on the device. The live PMU's init handshake is a Falcon
//! message-queue message (`nv_pmu_init_msg`, `msg_type` 0 — see
//! `drivers/gpu/drm/nouveau/include/nvfw/pmu.h`), not a MAILBOX0
//! magic: the old `PMU_INIT_MAGIC` (`0x55554441`) appears in no
//! Nouveau PMU source and `wait_for_init` was deleted as
//! ungrounded. Wiring the msgq init message is later work (G12);
//! the attach check is what probe can soundly do today.
//!
//! `Pmu::bring_up` (reset → stage → start) is retained as the
//! halted-Falcon staging primitive for a future post-reset
//! re-stage (G12), once an ACR signed-loader path exists to parse
//! desc properly. It must never be called on the live
//! VBIOS-loaded PMU at probe.

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FalconError, FALCON_BASE_PMU};
use crate::mc::{PMC_ENABLE, PMC_ENABLE_PMU};

/// PMU bring-up handle. Wraps a `Falcon` rooted at the PMU base.
pub struct Pmu<'a> {
    pub falcon: Falcon<'a>,
}

impl<'a> core::fmt::Debug for Pmu<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pmu")
            .field("falcon_base", &FALCON_BASE_PMU)
            .finish()
    }
}

impl<'a> Pmu<'a> {
    pub const fn new(bar0: &'a narf_driver_runtime::MmioRegion) -> Self {
        Self {
            falcon: Falcon::new(bar0, FALCON_BASE_PMU, "pmu"),
        }
    }

    /// Probe-time liveness check for the VBIOS-loaded PMU: true iff
    /// the PMU engine is enabled in `PMC_ENABLE` (BAR0+0x200).
    ///
    /// Grounded on `nvkm/subdev/mc/gk104.c` (`gk104_mc_reset[]`:
    /// `{ 0x00002000, NVKM_SUBDEV_PMU, 0, true }`), the reset map
    /// `gp100_mc` uses, tested by `nv04_mc_device_enabled` as
    /// `(rd32(0x200) & mask) == mask`. The VBIOS enables the PMU
    /// at POST, so a set bit means the board-loaded firmware is
    /// running; a clear bit means the engine is held in reset (or
    /// GSP-owned on Ampere/Ada, where the Falcon stays in reset
    /// by design) and no PMU messaging is possible yet.
    ///
    /// # Safety
    /// `bar0` covers the PMC block.
    pub unsafe fn engine_enabled(&self) -> bool {
        // SAFETY: caller's responsibility.
        let v = unsafe { self.falcon.bar0.read32(PMC_ENABLE) };
        v & PMC_ENABLE_PMU != 0
    }

    /// Stage firmware into a HALTED Falcon and start it. Returns
    /// once the Falcon is released; completion is observed by the
    /// caller's msgq work, not here (see the module docs).
    ///
    /// # Safety
    /// Exclusive access to BAR0 + the PMU Falcon. The firmware
    /// images are pre-validated by the caller.
    ///
    /// # Warning — do not call on a live PMU
    /// This resets the Falcon and overwrites IMEM/DMEM. On
    /// Maxwell/Pascal the PMU runs VBIOS-loaded firmware and the
    /// host must never stage it (see the module docs: Nouveau is
    /// `nofw` here and linux-firmware ships no PMU blobs). The
    /// only legitimate future caller is a post-reset re-stage
    /// (G12) once an ACR signed-loader path parses `desc`
    /// properly. Probe uses `engine_enabled` instead.
    pub unsafe fn bring_up(
        &self,
        family: ChipFamily,
        imem_img: &[u8],
        dmem_img: &[u8],
        bootvec: u32,
        imem_tag: u16,
    ) -> Result<(), FalconError> {
        // Per nvkm/subdev/pmu/ga102.c, on Ampere+ the GSP runs the
        // PMU duties — the PMU Falcon stays in reset. The host
        // driver returns success without staging.
        if matches!(family, ChipFamily::Ampere | ChipFamily::Ada) {
            return Ok(());
        }
        // SAFETY: caller's responsibility. No completion poll
        // here: the old MAILBOX0-magic poll (`0x55554441`) is
        // ungrounded — the value appears in no Nouveau PMU source,
        // and the real init handshake is a msgq message (see the
        // module docs). Completion observation belongs to the
        // future msgq work (G12); this primitive only stages and
        // starts.
        unsafe { self.falcon.bring_up(imem_img, dmem_img, bootvec, imem_tag) }
    }
}
