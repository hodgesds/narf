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
/// Filenames match Nouveau's request:
/// `nvidia/<asic>/pmu/desc.bin` + `image.bin` + `sig.bin`.
#[derive(Debug)]
pub struct PmuFirmwareRequest {
    /// e.g. "nvidia/gm200/pmu/image.bin"
    pub image_path: &'static str,
    /// e.g. "nvidia/gm200/pmu/sig.bin"
    pub sig_path: &'static str,
    /// e.g. "nvidia/gm200/pmu/desc.bin"
    pub desc_path: &'static str,
}

/// Resolve the PMU firmware paths for an ASIC. Cite
/// `nvkm_pmu_load` in nvkm/subdev/pmu/base.c which builds the
/// same paths for the Linux firmware loader.
pub fn pmu_firmware_for(asic: &'static str) -> PmuFirmwareRequest {
    // Naming follows Nouveau's per-ASIC firmware request shape:
    // `nvidia/<chip>/pmu/{desc,image,sig}.bin`. The ASIC tag is
    // baked into the path so per-chip-revision firmware can ship
    // alongside legacy blobs.
    match asic {
        "gm107" => PmuFirmwareRequest {
            image_path: "nvidia/gm107/pmu/image.bin",
            sig_path: "nvidia/gm107/pmu/sig.bin",
            desc_path: "nvidia/gm107/pmu/desc.bin",
        },
        "gm200" => PmuFirmwareRequest {
            image_path: "nvidia/gm200/pmu/image.bin",
            sig_path: "nvidia/gm200/pmu/sig.bin",
            desc_path: "nvidia/gm200/pmu/desc.bin",
        },
        "gm204" => PmuFirmwareRequest {
            image_path: "nvidia/gm204/pmu/image.bin",
            sig_path: "nvidia/gm204/pmu/sig.bin",
            desc_path: "nvidia/gm204/pmu/desc.bin",
        },
        "gm206" => PmuFirmwareRequest {
            image_path: "nvidia/gm206/pmu/image.bin",
            sig_path: "nvidia/gm206/pmu/sig.bin",
            desc_path: "nvidia/gm206/pmu/desc.bin",
        },
        "gp102" => PmuFirmwareRequest {
            image_path: "nvidia/gp102/pmu/image.bin",
            sig_path: "nvidia/gp102/pmu/sig.bin",
            desc_path: "nvidia/gp102/pmu/desc.bin",
        },
        "gp104" => PmuFirmwareRequest {
            image_path: "nvidia/gp104/pmu/image.bin",
            sig_path: "nvidia/gp104/pmu/sig.bin",
            desc_path: "nvidia/gp104/pmu/desc.bin",
        },
        "gp106" => PmuFirmwareRequest {
            image_path: "nvidia/gp106/pmu/image.bin",
            sig_path: "nvidia/gp106/pmu/sig.bin",
            desc_path: "nvidia/gp106/pmu/desc.bin",
        },
        "gp107" => PmuFirmwareRequest {
            image_path: "nvidia/gp107/pmu/image.bin",
            sig_path: "nvidia/gp107/pmu/sig.bin",
            desc_path: "nvidia/gp107/pmu/desc.bin",
        },
        "gv100" => PmuFirmwareRequest {
            image_path: "nvidia/gv100/pmu/image.bin",
            sig_path: "nvidia/gv100/pmu/sig.bin",
            desc_path: "nvidia/gv100/pmu/desc.bin",
        },
        "tu102" => PmuFirmwareRequest {
            image_path: "nvidia/tu102/pmu/image.bin",
            sig_path: "nvidia/tu102/pmu/sig.bin",
            desc_path: "nvidia/tu102/pmu/desc.bin",
        },
        "tu104" | "tu106" | "tu116" | "tu117" => PmuFirmwareRequest {
            image_path: "nvidia/tu102/pmu/image.bin",
            sig_path: "nvidia/tu102/pmu/sig.bin",
            desc_path: "nvidia/tu102/pmu/desc.bin",
        },
        "ga102" | "ga104" | "ga106" => PmuFirmwareRequest {
            image_path: "nvidia/ga102/pmu/image.bin",
            sig_path: "nvidia/ga102/pmu/sig.bin",
            desc_path: "nvidia/ga102/pmu/desc.bin",
        },
        "ad102" | "ad103" | "ad104" | "ad106" => PmuFirmwareRequest {
            image_path: "nvidia/ad102/pmu/image.bin",
            sig_path: "nvidia/ad102/pmu/sig.bin",
            desc_path: "nvidia/ad102/pmu/desc.bin",
        },
        _ => PmuFirmwareRequest {
            image_path: "nvidia/pmu/image.bin",
            sig_path: "nvidia/pmu/sig.bin",
            desc_path: "nvidia/pmu/desc.bin",
        },
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

// ── Firmware-staging orchestrator ───────────────────────────────
//
// Cite `nvkm/subdev/pmu/base.c::nvkm_pmu_load`: pulls each of the
// three blobs (image / sig / desc), validates the image, programs
// IMEM + DMEM, releases the Falcon, polls for INIT_MSG.
//
// The path here uses NARF's `narf-firmware` cap to resolve the
// blob bytes. We expose the orchestrator as a typed flow so the
// caller doesn't have to wire each step.

/// Outcome of a PMU staging attempt.
#[derive(Debug)]
pub enum PmuStageError {
    /// One of the firmware blobs wasn't in the registry.
    Firmware(narf_firmware::FirmwareError),
    /// Falcon staging failed mid-flight.
    Falcon(FalconError),
    /// Image bytes weren't 4-aligned.
    BadAlignment,
}

impl From<FalconError> for PmuStageError {
    fn from(e: FalconError) -> Self {
        PmuStageError::Falcon(e)
    }
}

impl From<narf_firmware::FirmwareError> for PmuStageError {
    fn from(e: narf_firmware::FirmwareError) -> Self {
        PmuStageError::Firmware(e)
    }
}

/// Full PMU bring-up driver: resolve firmware via the registry,
/// stage IMEM + DMEM, run the Falcon, poll INIT_MSG. Mirrors
/// `nvkm_pmu_load` then `nvkm_falcon_start`.
///
/// Ampere/Ada PMU is GSP-owned — we no-op early in that case so
/// the caller can blanket-call regardless of family.
///
/// # Safety
/// `bar0` covers the PMU Falcon block exclusively. The firmware
/// registry cap is live (caller has authority to call `open`).
pub unsafe fn stage_pmu_from_firmware(
    bar0: &narf_driver_runtime::MmioRegion,
    family: ChipFamily,
    asic: &'static str,
    fw_auth: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
) -> Result<(), PmuStageError> {
    if matches!(family, ChipFamily::Ampere | ChipFamily::Ada) {
        // GSP handles PMU duties; nothing to stage on the PMU
        // Falcon itself.
        return Ok(());
    }
    let req = pmu_firmware_for(asic);
    // Resolve the image + DMEM-side data blobs through the
    // firmware registry. Each blob owns its bytes through the cap
    // until the view is dropped.
    let image_cap = narf_firmware::open(req.image_path, fw_auth)?;
    let desc_cap = narf_firmware::open(req.desc_path, fw_auth)?;
    let image_view = narf_firmware::view_of(&image_cap)?;
    let desc_view = narf_firmware::view_of(&desc_cap)?;
    let image = image_view.bytes;
    let dmem = desc_view.bytes;
    if image.len() & 3 != 0 || dmem.len() & 3 != 0 {
        return Err(PmuStageError::BadAlignment);
    }
    let pmu = Pmu::new(bar0);
    // SAFETY: caller's responsibility.
    unsafe {
        pmu.bring_up(family, image, dmem, 0, 0)?;
    }
    Ok(())
}
