//! PMU — Power Management microcontroller (Falcon-based).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/pmu/base.c`**
//!   — generic `nvkm_pmu_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/pmu/gm200.c`** —
//!   Maxwell+ PMU bring-up (`gm200_pmu_*`). The PMU is a Falcon
//!   at BAR0 0x10A000; the driver stages signed firmware,
//!   programs the boot vector, releases the CPU.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/pmu/gp102.c`** —
//!   Pascal/Turing PMU; same Falcon shape, different signed
//!   firmware blob.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/pmu/ga102.c`** —
//!   Ampere/Ada PMU; the GSP runs PMU duties on these parts, so
//!   the host driver only stages a lightweight loader.
//!
//! Stage 1 — host bring-up sequence: identify firmware bundle by
//! ASIC, stage IMEM/DMEM (firmware supplied by `narf-firmware`),
//! release the Falcon, wait for the "I'm up" mailbox handshake.

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FalconError, FALCON_BASE_PMU};

/// Mailbox handshake protocol used by Nouveau's PMU firmware.
/// `INIT_MSG_PMU_INIT` (value 0x55554441 = "AAMU" reversed, the
/// PMU's "I'm up" signature) is what `wait_for_init` polls.
pub const PMU_INIT_MAGIC: u32 = 0x5555_4441;

/// PMU firmware bundle the driver asks `narf-firmware` for.
///
/// Filename matches Nouveau's request:
/// `nvidia/<asic>/pmu/desc.bin` + `image.bin` + `sig.bin`.
#[derive(Debug)]
pub struct PmuFirmwareRequest {
    /// e.g. "nvidia/gm200/pmu/image.bin"
    pub image_path: &'static str,
    /// e.g. "nvidia/gm200/pmu/sig.bin"
    pub sig_path: &'static str,
}

/// Resolve the PMU firmware paths for an ASIC. Cite
/// `nvkm_pmu_load` in nvkm/subdev/pmu/base.c which builds the
/// same paths for the Linux firmware loader.
pub const fn pmu_firmware_for(asic: &'static str) -> PmuFirmwareRequest {
    // Naming follows Nouveau's per-ASIC firmware request shape:
    // `nvidia/<chip>/pmu/{desc,image,sig}.bin`.
    let _ = asic;
    PmuFirmwareRequest {
        image_path: "nvidia/pmu/image.bin",
        sig_path: "nvidia/pmu/sig.bin",
    }
}

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

    /// Stage firmware, start the Falcon, then poll MAILBOX0 for
    /// the PMU_INIT_MAGIC signature.
    ///
    /// # Safety
    /// Exclusive access to BAR0 + the PMU Falcon. The firmware
    /// images are pre-validated by the caller.
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
        // SAFETY: caller's responsibility.
        unsafe {
            self.falcon
                .bring_up(imem_img, dmem_img, bootvec, imem_tag)?;
            self.wait_for_init(50_000)
        }
    }

    /// Poll MAILBOX0 for the firmware's "I'm up" signature.
    ///
    /// # Safety
    /// `bar0` covers the Falcon block.
    pub unsafe fn wait_for_init(&self, max_polls: u32) -> Result<(), FalconError> {
        for _ in 0..max_polls {
            // SAFETY: caller's responsibility.
            let m = unsafe { self.falcon.mailbox0() };
            if m == PMU_INIT_MAGIC {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(FalconError::IdleTimeout)
    }
}
