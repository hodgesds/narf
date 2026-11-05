//! Native kernel test fixtures for Intel GPU Display HDR Metadata & Output Colorimetry.

use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    amdgpu_hdr::{HdrMetadataInfoframe, HdrOutputMetadata},
    intel_gpu_aux::MmioWindow,
    intel_gpu_hdr::{
        pack_drm_infoframe, program_drm_infoframe, update_avi_colorimetry, COLORSPACE_BT2020_RGB,
        COLORSPACE_BT2020_YCC, CONNECTOR_COLOR_STATE, HDMI_DRM_INFOFRAME_SIZE,
        HDMI_INFOFRAME_TYPE_DRM, HDMI_INFOFRAME_VERSION_DRM, PIPE_MISC_HDR_MODE_PRECISION,
        PIPE_MISC_OFFSET, VIDEO_DIP_CTL_OFFSET, VIDEO_DIP_DRM_DATA_OFFSET,
        VIDEO_DIP_ENABLE_DRM_GLK, VIDEO_DIP_FREQ_2VSYNC,
    },
    intel_gpu_pipes::{Pipe, Transcoder},
};

// ── Test MMIO Fixture ────────────────────────────────────────────────────────

#[derive(Debug)]
struct MockMmio {
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: Cell<usize>,
}

impl MockMmio {
    fn new() -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            reads: Cell::new(0),
        }
    }

    fn written(&self, reg: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(r, _)| *r == reg)
            .map(|(_, v)| *v)
            .collect()
    }
}

impl MmioWindow for MockMmio {
    fn read32(&self, offset: u64) -> u32 {
        self.reads.set(self.reads.get() + 1);
        self.values.borrow().get(&offset).copied().unwrap_or(0)
    }

    fn write32(&self, offset: u64, value: u32) {
        self.values.borrow_mut().insert(offset, value);
        self.writes.borrow_mut().push((offset, value));
    }

    fn display_access_ok(&self) -> bool {
        true
    }
}

// ── Helper to build test HDR metadata ────────────────────────────────────────

fn test_hdr10_metadata() -> HdrOutputMetadata {
    HdrOutputMetadata {
        metadata_type: 0,
        hdmi_metadata_type1: HdrMetadataInfoframe {
            eotf: 2,          // SMPTE ST 2084 (PQ / HDR10)
            metadata_type: 0, // Type 1
            display_primaries: [
                (17000, 34000), // Green (x: 0.340, y: 0.680)
                (7500, 3000),   // Blue  (x: 0.150, y: 0.060)
                (34000, 16000), // Red   (x: 0.680, y: 0.320)
            ],
            white_point: (15635, 16450), // D65 (x: 0.3127, y: 0.3290)
            max_display_mastering_luminance: 1000, // 1000 nits
            min_display_mastering_luminance: 50, // 0.0050 nits
            max_cll: 1000,               // 1000 nits
            max_fall: 400,               // 400 nits
        },
    }
}

// ── Native Kernel Tests ──────────────────────────────────────────────────────

fn smoke_intel_hdr_infoframe_pack() -> TestResult {
    let meta = test_hdr10_metadata();
    let dwords = pack_drm_infoframe(&meta);

    // Convert the 8 DWORDs back to bytes to verify header, checksum, and payload
    let mut bytes = [0u8; 32];
    for (i, dw) in dwords.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&dw.to_le_bytes());
    }

    // Header validation
    if bytes[0] != HDMI_INFOFRAME_TYPE_DRM {
        return TestResult::Fail("DRM InfoFrame type must be 0x87");
    }
    if bytes[1] != HDMI_INFOFRAME_VERSION_DRM {
        return TestResult::Fail("DRM InfoFrame version must be 1");
    }
    if bytes[2] != HDMI_DRM_INFOFRAME_SIZE {
        return TestResult::Fail("DRM InfoFrame payload size must be 26");
    }

    // Checksum validation: sum of first 30 bytes mod 256 must be 0
    let sum = bytes[..30].iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    if sum != 0 {
        return TestResult::Fail("DRM InfoFrame checksum must sum to 0 mod 256");
    }

    // Payload verification
    if bytes[4] != 2 {
        return TestResult::Fail("EOTF must be 2 (ST 2084)");
    }
    if bytes[5] != 0 {
        return TestResult::Fail("Metadata type must be 0 (Type 1)");
    }

    let u16_val = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    if u16_val(6) != 17000 || u16_val(8) != 34000 {
        return TestResult::Fail("Primary 0 mismatch");
    }
    if u16_val(18) != 15635 || u16_val(20) != 16450 {
        return TestResult::Fail("White point mismatch");
    }
    if u16_val(22) != 1000 || u16_val(24) != 50 {
        return TestResult::Fail("Mastering luminance mismatch");
    }
    if u16_val(26) != 1000 || u16_val(28) != 400 {
        return TestResult::Fail("MaxCLL / MaxFALL mismatch");
    }

    TestResult::Pass
}

fn smoke_intel_hdr_register_programming() -> TestResult {
    let io = MockMmio::new();
    let trans = Transcoder::A;
    let pipe = Pipe::A;
    let meta = test_hdr10_metadata();

    // 1. Program HDR metadata
    program_drm_infoframe(&io, trans, pipe, Some(&meta));

    // Verify 8 DWORDs written to VIDEO_DIP_DRM_DATA
    for i in 0..8 {
        let reg = trans.base() + VIDEO_DIP_DRM_DATA_OFFSET + (i as u64) * 4;
        let writes = io.written(reg);
        if writes.is_empty() {
            return TestResult::Fail("DRM data register must be written");
        }
    }

    // Verify VIDEO_DIP_CTL has enable and frequency flags set
    let ctl = io.read32(trans.base() + VIDEO_DIP_CTL_OFFSET);
    if ctl & VIDEO_DIP_ENABLE_DRM_GLK == 0 {
        return TestResult::Fail("VIDEO_DIP_CTL must set VIDEO_DIP_ENABLE_DRM_GLK");
    }
    if ctl & VIDEO_DIP_FREQ_2VSYNC == 0 {
        return TestResult::Fail("VIDEO_DIP_CTL must set VIDEO_DIP_FREQ_2VSYNC");
    }

    // Verify PIPE_MISC has PIPE_MISC_HDR_MODE_PRECISION set
    let misc = io.read32(pipe.base() + PIPE_MISC_OFFSET);
    if misc & PIPE_MISC_HDR_MODE_PRECISION == 0 {
        return TestResult::Fail("PIPE_MISC must set PIPE_MISC_HDR_MODE_PRECISION for ST 2084");
    }

    // 2. Clear HDR metadata (None)
    program_drm_infoframe(&io, trans, pipe, None);

    // Verify VIDEO_DIP_CTL cleared enable bit
    let ctl_cleared = io.read32(trans.base() + VIDEO_DIP_CTL_OFFSET);
    if ctl_cleared & VIDEO_DIP_ENABLE_DRM_GLK != 0 {
        return TestResult::Fail("VIDEO_DIP_CTL must clear VIDEO_DIP_ENABLE_DRM_GLK");
    }

    // Verify DRM data registers zeroed
    for i in 0..8 {
        let reg = trans.base() + VIDEO_DIP_DRM_DATA_OFFSET + (i as u64) * 4;
        if io.read32(reg) != 0 {
            return TestResult::Fail("DRM data registers must be zeroed when disabled");
        }
    }

    // Verify PIPE_MISC cleared HDR mode precision
    let misc_cleared = io.read32(pipe.base() + PIPE_MISC_OFFSET);
    if misc_cleared & PIPE_MISC_HDR_MODE_PRECISION != 0 {
        return TestResult::Fail("PIPE_MISC must clear PIPE_MISC_HDR_MODE_PRECISION");
    }

    TestResult::Pass
}

fn smoke_intel_colorspace_and_broadcast_rgb_avi() -> TestResult {
    // Initial standard 1080p AVI frame (RGB, ITU-709, full range)
    let mut avi = [0u8; 17];
    avi[0] = 0x82;
    avi[1] = 2;
    avi[2] = 13;
    avi[4] = 1 << 4;
    avi[5] = (2 << 6) | (2 << 4) | 8; // ITU-709 (2), 16:9 (2)
    avi[6] = 2 << 2; // Full range (2)

    // Test BT.2020 RGB + Limited Range
    update_avi_colorimetry(&mut avi, COLORSPACE_BT2020_RGB, 2);

    // Verify DB2 (index 5) has extended colorimetry indicator (3 << 6)
    if (avi[5] >> 6) & 3 != 3 {
        return TestResult::Fail("AVI DB2 must indicate extended colorimetry (0b11)");
    }

    // Verify DB3 (index 6) has BT.2020 RGB (6 << 4) and limited range (1 << 2)
    let ext_color = (avi[6] >> 4) & 7;
    let q_range = (avi[6] >> 2) & 3;
    if ext_color != 6 {
        return TestResult::Fail("AVI DB3 must indicate BT.2020 RGB extended colorimetry (6)");
    }
    if q_range != 1 {
        return TestResult::Fail("AVI DB3 must indicate Limited quantization range (1)");
    }

    // Verify checksum is valid
    let sum = avi.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    if sum != 0 {
        return TestResult::Fail("Updated AVI infoframe checksum must be valid (sum to 0)");
    }

    // Test BT.2020 YCC + Full Range
    update_avi_colorimetry(&mut avi, COLORSPACE_BT2020_YCC, 1);
    let ext_color_ycc = (avi[6] >> 4) & 7;
    let q_range_full = (avi[6] >> 2) & 3;
    if ext_color_ycc != 5 {
        return TestResult::Fail("AVI DB3 must indicate BT.2020 YCC extended colorimetry (5)");
    }
    if q_range_full != 2 {
        return TestResult::Fail("AVI DB3 must indicate Full quantization range (2)");
    }

    TestResult::Pass
}

fn smoke_intel_connector_color_state_roundtrip() -> TestResult {
    let connector = 3;
    CONNECTOR_COLOR_STATE.set_colorspace(connector, COLORSPACE_BT2020_RGB);
    CONNECTOR_COLOR_STATE.set_broadcast_rgb(connector, 1);

    let meta = test_hdr10_metadata();
    CONNECTOR_COLOR_STATE.set_hdr_metadata(connector, Some(meta));

    if CONNECTOR_COLOR_STATE.colorspace(connector) != COLORSPACE_BT2020_RGB {
        return TestResult::Fail("Colorspace state roundtrip failed");
    }
    if CONNECTOR_COLOR_STATE.broadcast_rgb(connector) != 1 {
        return TestResult::Fail("Broadcast RGB state roundtrip failed");
    }
    match CONNECTOR_COLOR_STATE.hdr_metadata(connector) {
        Some(read_meta) => {
            if read_meta.hdmi_metadata_type1.eotf != 2
                || read_meta.hdmi_metadata_type1.max_cll != 1000
            {
                return TestResult::Fail("HDR metadata contents mismatch");
            }
        }
        None => return TestResult::Fail("HDR metadata must be present"),
    }

    // Clear state
    CONNECTOR_COLOR_STATE.set_hdr_metadata(connector, None);
    if CONNECTOR_COLOR_STATE.hdr_metadata(connector).is_some() {
        return TestResult::Fail("HDR metadata must be None after clear");
    }

    TestResult::Pass
}

// ── Kernel Test Registrations ────────────────────────────────────────────────

kernel_test_in!("drivers/gpu/intel_gpu_hdr", smoke_intel_hdr_infoframe_pack);
kernel_test_in!(
    "drivers/gpu/intel_gpu_hdr",
    smoke_intel_hdr_register_programming
);
kernel_test_in!(
    "drivers/gpu/intel_gpu_hdr",
    smoke_intel_colorspace_and_broadcast_rgb_avi
);
kernel_test_in!(
    "drivers/gpu/intel_gpu_hdr",
    smoke_intel_connector_color_state_roundtrip
);
