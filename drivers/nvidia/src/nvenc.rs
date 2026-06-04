//! NVENC — video encoder engine. Same Falcon shape as NVDEC.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/nvenc/base.c`**
//!   — `nvkm_nvenc_new_` entry; mirrors NVDEC's bring-up.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/nvenc/gm107.c`** —
//!   Maxwell NVENC0.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/nvenc/tu102.c`** —
//!   Turing NVENC; class `0xc1b7`-derived.
//!
//! ## Method ids (cl90b7 family)
//!
//! Same shape as NVDEC. The application id selects H264 / HEVC /
//! AV1; the firmware uses a per-codec setup buffer the host stages
//! into VRAM.

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FALCON_BASE_NVENC0};

// ── NVENC class ids ──────────────────────────────────────────────
//
// Cited Nouveau's `include/nvif/class.h` — NVxxB7 family for
// encoder.

/// MAXWELL_NVENC_A.
pub const NVENC_CLASS_MAXWELL_A: u32 = 0x0000_a0b7;
/// PASCAL_NVENC_A.
pub const NVENC_CLASS_PASCAL_A: u32 = 0x0000_c0b7;
/// VOLTA_NVENC_A.
pub const NVENC_CLASS_VOLTA_A: u32 = 0x0000_c3b7;
/// TURING_NVENC_A.
pub const NVENC_CLASS_TURING_A: u32 = 0x0000_c4b7;
/// AMPERE_NVENC_A.
pub const NVENC_CLASS_AMPERE_A: u32 = 0x0000_c7b7;
/// ADA_NVENC_A.
pub const NVENC_CLASS_ADA_A: u32 = 0x0000_c9b7;

/// Map a chip family to its primary NVENC class.
pub const fn nvenc_class_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Maxwell => Some(NVENC_CLASS_MAXWELL_A),
        ChipFamily::Pascal => Some(NVENC_CLASS_PASCAL_A),
        ChipFamily::Volta => Some(NVENC_CLASS_VOLTA_A),
        ChipFamily::Turing => Some(NVENC_CLASS_TURING_A),
        ChipFamily::Ampere => Some(NVENC_CLASS_AMPERE_A),
        ChipFamily::Ada => Some(NVENC_CLASS_ADA_A),
        _ => None,
    }
}

/// NVENC instance count per family.
pub const fn nvenc_instance_count(family: ChipFamily) -> u8 {
    match family {
        ChipFamily::Maxwell | ChipFamily::Pascal => 1,
        ChipFamily::Volta => 3,
        ChipFamily::Turing => 1,
        ChipFamily::Ampere => 3,
        ChipFamily::Ada => 3,
        _ => 0,
    }
}

// ── NVENC method ids ─────────────────────────────────────────────

pub const NVENC_SET_APPLICATION_ID: u16 = 0x0100;
pub const NVENC_SET_CONTROL_PARAMS: u16 = 0x0108;
pub const NVENC_SET_DRV_PIC_SETUP_OFFSET: u16 = 0x010C;
pub const NVENC_EXECUTE: u16 = 0x0300;
pub const NVENC_SEMAPHORE_A: u16 = 0x0400;
pub const NVENC_SEMAPHORE_B: u16 = 0x0404;
pub const NVENC_SEMAPHORE_C: u16 = 0x0408;
pub const NVENC_SEMAPHORE_D: u16 = 0x040C;

/// Application ids for encoder. Same enum as NVDEC for the codecs
/// the encoder supports.
pub const NVENC_APPID_H264: u32 = 3;
pub const NVENC_APPID_HEVC: u32 = 7;
pub const NVENC_APPID_AV1: u32 = 9;

pub const NVENC_EXECUTE_NOTIFY_ON: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvencCodec {
    H264,
    Hevc,
    Av1,
}

impl NvencCodec {
    pub const fn app_id(self) -> u32 {
        match self {
            NvencCodec::H264 => NVENC_APPID_H264,
            NvencCodec::Hevc => NVENC_APPID_HEVC,
            NvencCodec::Av1 => NVENC_APPID_AV1,
        }
    }
}

/// Stage one NVENC encode submission into the pushbuffer:
/// 1. Bind class.
/// 2. SET_APPLICATION_ID.
/// 3. SET_CONTROL_PARAMS + SET_DRV_PIC_SETUP_OFFSET.
/// 4. EXECUTE.
pub fn stage_nvenc_encode(
    pb: &mut crate::pb::PbBuilder<'_>,
    class_id: u32,
    codec: NvencCodec,
    pic_setup_phys: u64,
    control_params: u32,
) -> Result<(), crate::pb::PbError> {
    // SET_OBJECT (re-uses GR's method id, which is 0).
    pb.write_inc(crate::gr::GR_SET_OBJECT, &[class_id])?;
    // SET_APPLICATION_ID.
    pb.write_inc(NVENC_SET_APPLICATION_ID, &[codec.app_id()])?;
    // SET_CONTROL_PARAMS + SET_DRV_PIC_SETUP_OFFSET (2 consecutive
    // words at 0x0108).
    pb.write_inc(
        NVENC_SET_CONTROL_PARAMS,
        &[control_params, (pic_setup_phys >> 8) as u32],
    )?;
    pb.write_inc(NVENC_EXECUTE, &[NVENC_EXECUTE_NOTIFY_ON])?;
    Ok(())
}

/// Stage SEMAPHORE_RELEASE for the encoder.
pub fn stage_nvenc_semaphore_release(
    pb: &mut crate::pb::PbBuilder<'_>,
    sem_phys: u64,
    payload: u32,
) -> Result<(), crate::pb::PbError> {
    pb.write_inc(
        NVENC_SEMAPHORE_A,
        &[
            (sem_phys >> 32) as u32,
            (sem_phys & 0xFFFF_FFFF) as u32,
            payload,
            1, // OPERATION = RELEASE
        ],
    )
}

// ── Firmware bundle ──────────────────────────────────────────────

#[derive(Debug)]
pub struct NvencFirmwareRequest {
    pub video_codec: NvencCodec,
    pub image_path: &'static str,
    pub sig_path: Option<&'static str>,
}

pub const fn nvenc_firmware_for(codec: NvencCodec) -> NvencFirmwareRequest {
    let image = match codec {
        NvencCodec::H264 => "nvidia/nvenc/h264.bin",
        NvencCodec::Hevc => "nvidia/nvenc/hevc.bin",
        NvencCodec::Av1 => "nvidia/nvenc/av1.bin",
    };
    NvencFirmwareRequest {
        video_codec: codec,
        image_path: image,
        sig_path: None,
    }
}

/// Falcon base for NVENC instance `i`. NVENC0 = 0x844000;
/// per-instance stride is 0x4000.
pub const fn nvenc_falcon_base(i: u8) -> u64 {
    FALCON_BASE_NVENC0 + (i as u64) * 0x4000
}

pub fn nvenc_falcon<'a>(bar0: &'a narf_driver_runtime::MmioRegion, instance: u8) -> Falcon<'a> {
    Falcon::new(bar0, nvenc_falcon_base(instance), "nvenc")
}
