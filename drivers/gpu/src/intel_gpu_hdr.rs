//! Intel Display HDR Metadata and Output Colorimetry (Colorspace & Broadcast RGB).
//!
//! Provides CTA-861-G Dynamic Range and Mastering (DRM) InfoFrame generation
//! and hardware programming across Intel Gen12, Display 13 (ADL), Display 14 (Xe_LPG),
//! Display 20 (Xe2), and Display 30 (Xe3).
//!
//! References:
//! - CTA-861-G §6.9: Dynamic Range and Mastering InfoFrame (Type 0x87, 26 payload bytes).
//! - Intel PRMs Vol. 12/14 (Display Engine):
//!   `VIDEO_DIP_CTL` (+0x200), `VIDEO_DIP_AVI_DATA` (+0x220), `VIDEO_DIP_DRM_DATA` (+0x260).
//! - Linux `drivers/gpu/drm/i915/display/intel_hdmi.c`: `intel_hdmi_compute_drm_infoframe`.
//! - Linux `drivers/gpu/drm/i915/display/intel_display.c`: `bdw_set_pipe_misc`.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_hdr::HdrOutputMetadata;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pipes::{Pipe, Transcoder};

// ── Register Offsets & Constants ─────────────────────────────────────────────

/// `VIDEO_DIP_CTL` offset relative to the transcoder timing base.
pub const VIDEO_DIP_CTL_OFFSET: u64 = 0x200;
/// `VIDEO_DIP_AVI_DATA` offset relative to the transcoder timing base (32 bytes).
pub const VIDEO_DIP_AVI_DATA_OFFSET: u64 = 0x220;
/// `VIDEO_DIP_DRM_DATA` offset relative to the transcoder timing base (32 bytes, 8 DWORDs).
pub const VIDEO_DIP_DRM_DATA_OFFSET: u64 = 0x260;

/// `VIDEO_DIP_CTL` bit 12: AVI InfoFrame enable.
pub const VIDEO_DIP_ENABLE_AVI: u32 = 1 << 12;
/// `VIDEO_DIP_CTL` bit 16: GCP enable.
pub const VIDEO_DIP_ENABLE_GCP: u32 = 1 << 16;
/// `VIDEO_DIP_CTL` bit 19: GLK/TGL+ Dynamic Range and Mastering (DRM) InfoFrame enable.
pub const VIDEO_DIP_ENABLE_DRM_GLK: u32 = 1 << 19;
/// `VIDEO_DIP_CTL` bit 16..17: transmission frequency (1 = once per vsync, 2 = every 2 vsyncs).
pub const VIDEO_DIP_FREQ_1VSYNC: u32 = 1 << 16;
pub const VIDEO_DIP_FREQ_2VSYNC: u32 = 2 << 16;

/// `PIPE_MISC` offset relative to the pipe base.
pub const PIPE_MISC_OFFSET: u64 = 0x30;
/// `PIPE_MISC` bit 23: HDR mode precision (10/12-bit color pipeline precision).
pub const PIPE_MISC_HDR_MODE_PRECISION: u32 = 1 << 23;

/// CTA-861-G Dynamic Range and Mastering InfoFrame Type.
pub const HDMI_INFOFRAME_TYPE_DRM: u8 = 0x87;
/// CTA-861-G Dynamic Range and Mastering InfoFrame Version.
pub const HDMI_INFOFRAME_VERSION_DRM: u8 = 0x01;
/// CTA-861-G Dynamic Range and Mastering InfoFrame payload length in bytes.
pub const HDMI_DRM_INFOFRAME_SIZE: u8 = 26;

// ── Colorspace Constants (DRM_MODE_COLORIMETRY_*) ───────────────────────────

pub const COLORSPACE_DEFAULT: u32 = 0;
pub const COLORSPACE_SMPTE_170M_YCC: u32 = 1;
pub const COLORSPACE_BT709_YCC: u32 = 2;
pub const COLORSPACE_XVYCC_601: u32 = 3;
pub const COLORSPACE_XVYCC_709: u32 = 4;
pub const COLORSPACE_SYCC_601: u32 = 5;
pub const COLORSPACE_OPYCC_601: u32 = 6;
pub const COLORSPACE_OPRGB: u32 = 7;
pub const COLORSPACE_BT2020_CYCC: u32 = 8;
pub const COLORSPACE_BT2020_RGB: u32 = 9;
pub const COLORSPACE_BT2020_YCC: u32 = 10;
pub const COLORSPACE_DCI_P3_RGB_D65: u32 = 11;
pub const COLORSPACE_DCI_P3_RGB_THEATER: u32 = 12;

/// Whether the specified colorspace is wide-gamut (BT.2020 or DCI-P3).
pub const fn is_wide_gamut(colorspace: u32) -> bool {
    matches!(
        colorspace,
        COLORSPACE_BT2020_CYCC
            | COLORSPACE_BT2020_RGB
            | COLORSPACE_BT2020_YCC
            | COLORSPACE_DCI_P3_RGB_D65
            | COLORSPACE_DCI_P3_RGB_THEATER
    )
}

// ── CTA-861-G DRM InfoFrame Generation ──────────────────────────────────────

/// Pack a 32-byte (8 DWORD) buffer containing the CTA-861-G Dynamic Range and
/// Mastering InfoFrame (header, checksum, and 26-byte payload) for `VIDEO_DIP_DRM_DATA`.
pub fn pack_drm_infoframe(meta: &HdrOutputMetadata) -> [u32; 8] {
    let f = &meta.hdmi_metadata_type1;
    let mut raw = [0u8; 32];

    raw[0] = HDMI_INFOFRAME_TYPE_DRM;
    raw[1] = HDMI_INFOFRAME_VERSION_DRM;
    raw[2] = HDMI_DRM_INFOFRAME_SIZE;

    raw[4] = f.eotf;
    raw[5] = f.metadata_type;

    let mut at = 6;
    let mut put = |v: u16| {
        raw[at..at + 2].copy_from_slice(&v.to_le_bytes());
        at += 2;
    };

    for (x, y) in f.display_primaries {
        put(x);
        put(y);
    }
    put(f.white_point.0);
    put(f.white_point.1);
    put(f.max_display_mastering_luminance);
    put(f.min_display_mastering_luminance);
    put(f.max_cll);
    put(f.max_fall);

    // Compute checksum so sum of first 30 bytes (header + 26 payload) is 0 mod 256.
    let sum = raw[..30].iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    raw[3] = 0u8.wrapping_sub(sum);

    // Convert into 8 little-endian DWORDs
    core::array::from_fn(|i| {
        let o = i * 4;
        u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]])
    })
}

/// Update an AVI InfoFrame's colorimetry and quantization range fields.
pub fn update_avi_colorimetry(avi: &mut [u8; 17], colorspace: u32, broadcast_rgb: u8) {
    if is_wide_gamut(colorspace) {
        // Extended colorimetry valid (C0, C1 = 11 in DB2 bits 7:6)
        avi[5] |= 3 << 6;
        // Clear previous extended colorimetry bits (DB3 bits 6:4)
        avi[6] &= !(7 << 4);
        match colorspace {
            COLORSPACE_BT2020_YCC | COLORSPACE_BT2020_CYCC => {
                avi[6] |= 5 << 4; // BT.2020 YCC (0b101)
            }
            COLORSPACE_BT2020_RGB | COLORSPACE_DCI_P3_RGB_D65 | COLORSPACE_DCI_P3_RGB_THEATER => {
                avi[6] |= 6 << 4; // BT.2020 RGB (0b110)
            }
            _ => {}
        }
    }

    // Set quantization range in DB3 bits 3:2
    avi[6] &= !(3 << 2);
    match broadcast_rgb {
        1 => avi[6] |= 2 << 2, // Full range
        2 => avi[6] |= 1 << 2, // Limited range (16-235)
        _ => avi[6] |= 2 << 2, // Auto (RGB default is full)
    }

    // Recompute AVI infoframe checksum at byte 3
    avi[3] = 0;
    let sum = avi.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    avi[3] = 0u8.wrapping_sub(sum);
}

// ── Hardware Register Programming ────────────────────────────────────────────

/// Program or clear the Dynamic Range and Mastering (DRM) InfoFrame registers.
pub fn program_drm_infoframe(
    io: &(impl MmioWindow + ?Sized),
    trans: Transcoder,
    pipe: Pipe,
    metadata: Option<&HdrOutputMetadata>,
) {
    let trans_base = trans.base();
    let pipe_base = pipe.base();

    if let Some(meta) = metadata {
        let dwords = pack_drm_infoframe(meta);
        for (i, &dw) in dwords.iter().enumerate() {
            io.write32(trans_base + VIDEO_DIP_DRM_DATA_OFFSET + (i as u64) * 4, dw);
        }

        // Enable DRM InfoFrame transmission (every 2 vsyncs)
        let cur_ctl = io.read32(trans_base + VIDEO_DIP_CTL_OFFSET);
        io.write32(
            trans_base + VIDEO_DIP_CTL_OFFSET,
            cur_ctl | VIDEO_DIP_ENABLE_DRM_GLK | VIDEO_DIP_FREQ_2VSYNC,
        );

        // ST.2084 (PQ) or BT.2100 HLG require 10/12-bit pipeline precision
        if meta.hdmi_metadata_type1.eotf >= 2 {
            let cur_misc = io.read32(pipe_base + PIPE_MISC_OFFSET);
            io.write32(
                pipe_base + PIPE_MISC_OFFSET,
                cur_misc | PIPE_MISC_HDR_MODE_PRECISION,
            );
        }
    } else {
        // Disable DRM InfoFrame
        let cur_ctl = io.read32(trans_base + VIDEO_DIP_CTL_OFFSET);
        io.write32(
            trans_base + VIDEO_DIP_CTL_OFFSET,
            cur_ctl & !VIDEO_DIP_ENABLE_DRM_GLK,
        );

        // Zero DRM data registers
        for i in 0..8 {
            io.write32(trans_base + VIDEO_DIP_DRM_DATA_OFFSET + (i as u64) * 4, 0);
        }

        // Disable HDR mode precision in PIPE_MISC if enabled
        let cur_misc = io.read32(pipe_base + PIPE_MISC_OFFSET);
        io.write32(
            pipe_base + PIPE_MISC_OFFSET,
            cur_misc & !PIPE_MISC_HDR_MODE_PRECISION,
        );
    }
}

/// Program the AVI InfoFrame on a transcoder with colorspace and broadcast RGB settings.
pub fn program_avi_colorspace(
    io: &(impl MmioWindow + ?Sized),
    trans: Transcoder,
    colorspace: u32,
    broadcast_rgb: u8,
) {
    let trans_base = trans.base();
    let avi_data_off = trans_base + VIDEO_DIP_AVI_DATA_OFFSET;

    // Read current 32-byte AVI image from MMIO
    let mut avi_image = [0u8; 32];
    for i in 0..8 {
        let dw = io.read32(avi_data_off + (i as u64) * 4);
        avi_image[i * 4..(i + 1) * 4].copy_from_slice(&dw.to_le_bytes());
    }

    // Default AVI infoframe if empty
    if avi_image[0] != 0x82 {
        avi_image[0] = 0x82;
        avi_image[1] = 2;
        avi_image[2] = 13;
        avi_image[4] = 1 << 4;
        avi_image[5] = (2 << 6) | (2 << 4) | 8;
        avi_image[6] = 2 << 2;
    }

    let mut avi_frame = [0u8; 17];
    avi_frame.copy_from_slice(&avi_image[..17]);
    update_avi_colorimetry(&mut avi_frame, colorspace, broadcast_rgb);
    avi_image[..17].copy_from_slice(&avi_frame);

    // Disable AVI in DIP_CTL before data write
    let ctl_off = trans_base + VIDEO_DIP_CTL_OFFSET;
    let cur_ctl = io.read32(ctl_off);
    io.write32(ctl_off, cur_ctl & !VIDEO_DIP_ENABLE_AVI);

    // Write updated 32-byte image
    for i in 0..8 {
        let dw = u32::from_le_bytes([
            avi_image[i * 4],
            avi_image[i * 4 + 1],
            avi_image[i * 4 + 2],
            avi_image[i * 4 + 3],
        ]);
        io.write32(avi_data_off + (i as u64) * 4, dw);
    }

    // Re-enable AVI
    io.write32(ctl_off, cur_ctl | VIDEO_DIP_ENABLE_AVI);
}

// ── State Tracking & Driver Dispatch ─────────────────────────────────────────

/// A requested connector color / HDR update from DRM KMS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelConnectorColorRequest {
    pub connector: u32,
    pub colorspace: u32,
    pub broadcast_rgb: u8,
    pub hdr_output_metadata: Option<alloc::vec::Vec<u8>>,
}

/// Global connector color and HDR state for Intel GPU connectors.
#[derive(Debug)]
pub struct IntelConnectorColorState {
    colorspace: [AtomicU32; 4],
    broadcast_rgb: [AtomicU8; 4],
    hdr_metadata: [IrqSafeSpinLock<Option<HdrOutputMetadata>>; 4],
}

impl Default for IntelConnectorColorState {
    fn default() -> Self {
        Self::new()
    }
}

impl IntelConnectorColorState {
    pub const fn new() -> Self {
        Self {
            colorspace: [
                AtomicU32::new(COLORSPACE_DEFAULT),
                AtomicU32::new(COLORSPACE_DEFAULT),
                AtomicU32::new(COLORSPACE_DEFAULT),
                AtomicU32::new(COLORSPACE_DEFAULT),
            ],
            broadcast_rgb: [
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
            ],
            hdr_metadata: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
        }
    }

    fn connector_index(connector: u32) -> Option<usize> {
        match connector {
            1..=4 => Some((connector - 1) as usize),
            _ => None,
        }
    }

    pub fn set_colorspace(&self, connector: u32, value: u32) {
        if let Some(idx) = Self::connector_index(connector) {
            self.colorspace[idx].store(value, Ordering::SeqCst);
        }
    }

    pub fn colorspace(&self, connector: u32) -> u32 {
        Self::connector_index(connector)
            .map(|idx| self.colorspace[idx].load(Ordering::SeqCst))
            .unwrap_or(COLORSPACE_DEFAULT)
    }

    pub fn set_broadcast_rgb(&self, connector: u32, value: u8) {
        if let Some(idx) = Self::connector_index(connector) {
            self.broadcast_rgb[idx].store(value, Ordering::SeqCst);
        }
    }

    pub fn broadcast_rgb(&self, connector: u32) -> u8 {
        Self::connector_index(connector)
            .map(|idx| self.broadcast_rgb[idx].load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    pub fn set_hdr_metadata(&self, connector: u32, meta: Option<HdrOutputMetadata>) {
        if let Some(idx) = Self::connector_index(connector) {
            *self.hdr_metadata[idx].lock() = meta;
        }
    }

    pub fn hdr_metadata(&self, connector: u32) -> Option<HdrOutputMetadata> {
        Self::connector_index(connector).and_then(|idx| *self.hdr_metadata[idx].lock())
    }
}

pub static CONNECTOR_COLOR_STATE: IntelConnectorColorState = IntelConnectorColorState::new();

/// Retain and apply an Intel connector's color / HDR update from atomic commit or set_property.
pub fn request_connector_color(req: IntelConnectorColorRequest) {
    let meta = req
        .hdr_output_metadata
        .as_deref()
        .and_then(|blob| HdrOutputMetadata::from_blob(blob).ok());

    CONNECTOR_COLOR_STATE.set_colorspace(req.connector, req.colorspace);
    CONNECTOR_COLOR_STATE.set_broadcast_rgb(req.connector, req.broadcast_rgb);
    CONNECTOR_COLOR_STATE.set_hdr_metadata(req.connector, meta);

    // Reprogram active transcoder/pipe hardware if controller is initialized
    crate::intel_gpu::with_controller(|dev| {
        let io = dev.mode_window();
        let trans = Transcoder::A;
        let pipe = Pipe::A;

        program_drm_infoframe(&io, trans, pipe, meta.as_ref());
        program_avi_colorspace(&io, trans, req.colorspace, req.broadcast_rgb);
    });
}

/// Retain and apply an Intel connector's Broadcast RGB property change.
pub fn request_broadcast_rgb(connector: u32, value: u8) {
    CONNECTOR_COLOR_STATE.set_broadcast_rgb(connector, value);
    let colorspace = CONNECTOR_COLOR_STATE.colorspace(connector);

    crate::intel_gpu::with_controller(|dev| {
        let io = dev.mode_window();
        let trans = Transcoder::A;
        program_avi_colorspace(&io, trans, colorspace, value);
    });
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_hdr_tests.rs"]
mod tests;
