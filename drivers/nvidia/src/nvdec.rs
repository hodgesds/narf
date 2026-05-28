//! NVDEC — video decoder engine. Per-family Falcon-based.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/nvdec/base.c`**
//!   — generic `nvkm_nvdec_new_` entry; calls `nvkm_falcon_ctor`
//!   for the Falcon at the per-family base.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/nvdec/gm107.c`** —
//!   Maxwell NVDEC0; the Falcon block lives at the base passed via
//!   `nvkm_nvdec_new_(... 0 ...)` which falls back to NVDEC base
//!   `0x00084000` (verified via the device-base.c table — the addr
//!   argument 0 means "lookup from device".)
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/nvdec/tu102.c`** —
//!   Turing NVDEC; supports the `0xc1b7` class (NVC1B7) and
//!   `0xc2b7` on Ampere.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/nvdec/ga102.c`** —
//!   Ampere/Ada NVDEC; class `0xc7b7` / `0xc9b7`.
//!
//! ## Method ids (cl90b7 family)
//!
//! NVDEC's submission interface is method-driven via the host
//! pushbuffer like GR/CE. The methods are stable across decoder
//! classes:
//!
//! | method | name                  | purpose                  |
//! |--------|-----------------------|--------------------------|
//! | 0x100  | SET_APPLICATION_ID    | bind codec (H264/HEVC/…) |
//! | 0x108  | SET_CONTROL_PARAMS    | per-frame control struct |
//! | 0x10C  | SET_DRV_PIC_SETUP_OFFSET | per-frame setup buf  |
//! | 0x114  | SET_PICTURE_INDEX     | frame index for DPB      |
//! | 0x300  | EXECUTE               | start decode             |
//! | 0x400  | SEMAPHORE_A           | fence release high       |
//! | 0x404  | SEMAPHORE_B           | fence release low        |
//! | 0x408  | SEMAPHORE_C           | fence payload            |
//! | 0x40C  | SEMAPHORE_D           | fence operation          |

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FALCON_BASE_NVDEC0};

// ── NVDEC engine class ids (cl90b7 family) ───────────────────────
//
// Cited Nouveau's `include/nvif/class.h` — NVxxB7 family.

/// MAXWELL_NVDEC_A — cl9090 / 90b7 family Maxwell decoder.
pub const NVDEC_CLASS_MAXWELL_A: u32 = 0x0000_90b7;
/// PASCAL_NVDEC_A.
pub const NVDEC_CLASS_PASCAL_A: u32 = 0x0000_b0b7;
/// VOLTA_NVDEC_A.
pub const NVDEC_CLASS_VOLTA_A: u32 = 0x0000_c3b7;
/// TURING_NVDEC_A — also called NVC1B7.
pub const NVDEC_CLASS_TURING_A: u32 = 0x0000_c1b7;
/// AMPERE_NVDEC_A.
pub const NVDEC_CLASS_AMPERE_A: u32 = 0x0000_c7b7;
/// ADA_NVDEC_A.
pub const NVDEC_CLASS_ADA_A: u32 = 0x0000_c9b7;

/// Map a chip family to its primary NVDEC class.
pub const fn nvdec_class_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Maxwell => Some(NVDEC_CLASS_MAXWELL_A),
        ChipFamily::Pascal => Some(NVDEC_CLASS_PASCAL_A),
        ChipFamily::Volta => Some(NVDEC_CLASS_VOLTA_A),
        ChipFamily::Turing => Some(NVDEC_CLASS_TURING_A),
        ChipFamily::Ampere => Some(NVDEC_CLASS_AMPERE_A),
        ChipFamily::Ada => Some(NVDEC_CLASS_ADA_A),
        _ => None,
    }
}

/// Number of NVDEC instances per family. Cited per-ASIC device
/// `base.c` table.
pub const fn nvdec_instance_count(family: ChipFamily) -> u8 {
    match family {
        ChipFamily::Maxwell | ChipFamily::Pascal | ChipFamily::Volta => 1,
        ChipFamily::Turing => 3,
        ChipFamily::Ampere => 3,
        ChipFamily::Ada => 5,
        _ => 0,
    }
}

// ── NVDEC method ids ─────────────────────────────────────────────

pub const NVDEC_SET_APPLICATION_ID: u16 = 0x0100;
pub const NVDEC_SET_CONTROL_PARAMS: u16 = 0x0108;
pub const NVDEC_SET_DRV_PIC_SETUP_OFFSET: u16 = 0x010C;
pub const NVDEC_SET_IN_BUF_BASE_OFFSET: u16 = 0x0110;
pub const NVDEC_SET_PICTURE_INDEX: u16 = 0x0114;
pub const NVDEC_EXECUTE: u16 = 0x0300;
pub const NVDEC_SEMAPHORE_A: u16 = 0x0400;
pub const NVDEC_SEMAPHORE_B: u16 = 0x0404;
pub const NVDEC_SEMAPHORE_C: u16 = 0x0408;
pub const NVDEC_SEMAPHORE_D: u16 = 0x040C;

/// SET_APPLICATION_ID payload values. Cite NVIDIA Video Codec SDK:
/// the application id is a small enum naming the codec.
pub const NVDEC_APPID_MPEG2: u32 = 1;
pub const NVDEC_APPID_VC1: u32 = 2;
pub const NVDEC_APPID_H264: u32 = 3;
pub const NVDEC_APPID_MPEG4: u32 = 4;
pub const NVDEC_APPID_VP8: u32 = 5;
pub const NVDEC_APPID_HEVC: u32 = 7;
pub const NVDEC_APPID_VP9: u32 = 8;
pub const NVDEC_APPID_AV1: u32 = 9;

/// EXECUTE data word — bit 0 = "process whole frame" (the only
/// supported mode for compressed streams). Cite NVIDIA's
/// `NVCxxxB7_EXECUTE_NOTIFY_ON`.
pub const NVDEC_EXECUTE_NOTIFY_ON: u32 = 1 << 0;

// ── Firmware bundle naming ───────────────────────────────────────

/// NVDEC firmware path per ASIC. Mirrors Nouveau's
/// `nvkm/engine/nvdec/*` request paths (used by Linux firmware
/// loader).
#[derive(Debug)]
pub struct NvdecFirmwareRequest {
    pub video_codec: NvdecCodec,
    pub image_path: &'static str,
    pub sig_path: Option<&'static str>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvdecCodec {
    H264,
    Hevc,
    Vp9,
    Av1,
}

impl NvdecCodec {
    pub const fn app_id(self) -> u32 {
        match self {
            NvdecCodec::H264 => NVDEC_APPID_H264,
            NvdecCodec::Hevc => NVDEC_APPID_HEVC,
            NvdecCodec::Vp9 => NVDEC_APPID_VP9,
            NvdecCodec::Av1 => NVDEC_APPID_AV1,
        }
    }
}

/// Resolve the NVDEC firmware request for a given codec. The exact
/// file layout matches Nouveau's "nvidia/<asic>/nvdec/codec.bin"
/// shape; Stage 1 returns the canonical name without committing to
/// an ASIC-versioned subdir (the caller can prepend it).
pub const fn nvdec_firmware_for(codec: NvdecCodec) -> NvdecFirmwareRequest {
    let image = match codec {
        NvdecCodec::H264 => "nvidia/nvdec/h264.bin",
        NvdecCodec::Hevc => "nvidia/nvdec/hevc.bin",
        NvdecCodec::Vp9 => "nvidia/nvdec/vp9.bin",
        NvdecCodec::Av1 => "nvidia/nvdec/av1.bin",
    };
    NvdecFirmwareRequest {
        video_codec: codec,
        image_path: image,
        sig_path: None,
    }
}

// ── Submission helpers ───────────────────────────────────────────

/// Stage one NVDEC decode submission into the pushbuffer:
/// 1. Bind class (SET_OBJECT — uses `gr::GR_SET_OBJECT` method id).
/// 2. Programme SET_APPLICATION_ID for the codec.
/// 3. Programme SET_DRV_PIC_SETUP_OFFSET + control params + picture
///    index.
/// 4. EXECUTE with NOTIFY.
///
/// Caller is responsible for the per-codec control/setup blobs the
/// firmware reads (`pic_setup_phys` is the VRAM byte offset).
pub fn stage_nvdec_decode(
    pb: &mut crate::pb::PbBuilder<'_>,
    class_id: u32,
    codec: NvdecCodec,
    pic_setup_phys: u64,
    control_params: u32,
    pic_index: u32,
) -> Result<(), crate::pb::PbError> {
    // SET_OBJECT (re-uses GR's method id, which is 0).
    pb.write_inc(crate::gr::GR_SET_OBJECT, &[class_id])?;
    // SET_APPLICATION_ID (1 word).
    pb.write_inc(NVDEC_SET_APPLICATION_ID, &[codec.app_id()])?;
    // SET_CONTROL_PARAMS + SET_DRV_PIC_SETUP_OFFSET + SET_IN_BUF_BASE_OFFSET
    // + SET_PICTURE_INDEX (4 consecutive words at 0x0108).
    pb.write_inc(
        NVDEC_SET_CONTROL_PARAMS,
        &[
            control_params,
            (pic_setup_phys >> 8) as u32,
            0,
            pic_index,
        ],
    )?;
    // EXECUTE.
    pb.write_inc(NVDEC_EXECUTE, &[NVDEC_EXECUTE_NOTIFY_ON])?;
    Ok(())
}

/// Stage a SEMAPHORE_RELEASE at the tail of an NVDEC submission.
/// Cite cl9090::SEMAPHORE_D_OPERATION_RELEASE.
pub fn stage_nvdec_semaphore_release(
    pb: &mut crate::pb::PbBuilder<'_>,
    sem_phys: u64,
    payload: u32,
) -> Result<(), crate::pb::PbError> {
    pb.write_inc(
        NVDEC_SEMAPHORE_A,
        &[
            (sem_phys >> 32) as u32,
            (sem_phys & 0xFFFF_FFFF) as u32,
            payload,
            1, // OPERATION = RELEASE
        ],
    )
}

// ── Per-instance Falcon base ─────────────────────────────────────
//
// Cite `nvkm/engine/nvdec/gm107.c::gm107_nvdec` + base.c device
// table. NVDEC0 base = 0x84000; NVDEC1 = 0x848000 on Turing+;
// per-instance stride is 0x4000.

/// Falcon base for NVDEC instance `i`. Cite per-ASIC NVDEC files.
pub const fn nvdec_falcon_base(i: u8) -> u64 {
    FALCON_BASE_NVDEC0 + (i as u64) * 0x4000
}

/// Build a Falcon handle for NVDEC instance `i`. Caller drives the
/// firmware load via `falcon::Falcon::bring_up`.
pub fn nvdec_falcon<'a>(
    bar0: &'a narf_driver_runtime::MmioRegion,
    instance: u8,
) -> Falcon<'a> {
    Falcon::new(bar0, nvdec_falcon_base(instance), "nvdec")
}
