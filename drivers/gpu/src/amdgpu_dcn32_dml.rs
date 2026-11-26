//! DCN 3.2 display mode library (DML32) — Navi31/32/33 single-plane validate.
//!
//! The classic DML (`using_dml2=false` in Linux's `dcn32_resource.c`): the
//! SoC/IP bounding boxes are `dcn3_2_soc` / `dcn3_2_ip`
//! (`dc/dml/dcn32/dcn32_fpu.c`), and the per-DCN parameters live on
//! [`Dcn`] (`amdgpu_dml.rs`): DET 256 KiB, downspread 0.5%, 8 tile
//! repeaters, Z8 (285, 320) µs, line buffer 1171920 bits @ 57 bpp fixed,
//! 32 line-buffer lines, round-trip ping latency 263 DCFCLK cycles, fabric
//! return 64 bytes, ideal percentages 90 / 20, pipeline delays 47 / 28 /
//! 125, and the WM_A latencies (400, 42.97, 49.94) µs.
//!
//! Scope is one plane on one pipe, packed linear RGB, no ODM, no MPC, no
//! DSC, no SubVP — the surface the shared fixed-point core models. The
//! full VBA port (multi-pipe, ODM, SubVP, DSC-in-DML) is out of scope;
//! `dcn32_validate_bandwidth` in Linux calls the full
//! `dml32_ModeSupport` / `dml32_ModeSupportAndSystemConfiguration`, which
//! this does not reproduce. The `MIN_DST_Y_NEXT_START` terms that need
//! WritebackDelay/TSetup (`display_mode_vba_32.c`) are likewise a remainder
//! — see `amdgpu_dml_regs.rs`.
//!
//! Memory: Navi31/32/33 carry GDDR6, which the shared
//! [`crate::amdgpu_dml::MemoryKind`] has no
//! variant for. On DCN 3.2 the WM_A latencies are identical for both kinds,
//! so the caller passes [`crate::amdgpu_dml::MemoryKind::Ddr5`] as the stand-in; the channel
//! count (24) and width (2 bytes) are the binding platform values from
//! `dcn3_2_soc` and are checked here.

use crate::amdgpu_dml::{
    ClockState, Config, Dcn, DramChangeSupport, Error, Geometry, Memory, Prefetch, Requirements,
    Watermarks,
};

/// `dcn3_2_soc` clock ceilings, in kHz (`dcn32_fpu.c`).
pub const MAX_DISPCLK_KHZ: u32 = 2_150_000;
pub const MAX_DPPCLK_KHZ: u32 = 2_150_000;
pub const MAX_DCFCLK_KHZ: u32 = 1_564_000;
pub const MAX_SOCCLK_KHZ: u32 = 1_200_000;
pub const MAX_DTBCLK_KHZ: u32 = 1_564_000;
/// `dcn3_2_soc.dscclk_mhz` is 716.667; the DSC owner works in whole kHz.
pub const MAX_DSCCLK_KHZ: u32 = 716_667;
/// `dcn3_2_soc.phyclk_mhz` (DP 8b/10b); D18 is 667 and D32 (UHBR) is 625.
pub const MAX_PHYCLK_KHZ: u32 = 810_000;
pub const MAX_PHYCLK_D18_KHZ: u32 = 667_000;
pub const MAX_PHYCLK_D32_KHZ: u32 = 625_000;
/// `dcn3_2_soc.dram_speed_mts` and `dcn3_2_soc.num_chans` /
/// `dram_channel_width_bytes`.
pub const MAX_DRAM_MTS: u32 = 18_000;
pub const NUM_CHANS: u32 = 24;
pub const DRAM_CHANNEL_WIDTH_BYTES: u32 = 2;
/// `dcn3_2_soc.dispclk_dppclk_vco_speed_mhz` — the VCO the clock manager
/// reports; the DENTIST FbMult register decode is a remainder (the masks are
/// absent from the reference tree).
pub const VCO_KHZ: u32 = 4_300_000;
/// `dcn3_2_ip`: at most 4 DSC engines, 6016 pixels per DSC line.
pub const MAX_DSC_UNITS: u32 = 4;
pub const MAX_DSC_LINE_PIXELS: u32 = 6016;

/// The validated single-plane configuration, in the units the register
/// layers derive their fields from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validation {
    pub geometry: Geometry,
    pub requirements: Requirements,
    pub watermarks: Watermarks,
    pub prefetch: Prefetch,
    pub dram_change: DramChangeSupport,
}

/// The DCN 3.2 DML owner: one plane, one pipe, packed linear RGB.
#[derive(Debug)]
pub struct Dml32;

impl Dml32 {
    /// Validate one plane against the DCN 3.2 bounding box. `max_dispclk_khz`
    /// is the clock manager's DC-mode DISPCLK limit for this state (capped at
    /// 1950 MHz by the DALSMC tables); the SoC ceiling (2150 MHz) is checked
    /// separately. Returns [`Error::Unsupported`] when a clock requirement
    /// exceeds its SoC ceiling, [`Error::Invalid`] for a malformed
    /// configuration or a memory shape that is not Navi31/32/33's.
    pub fn validate(
        config: &Config,
        memory: &Memory,
        clocks: &ClockState,
        max_dispclk_khz: u32,
    ) -> Result<Validation, Error> {
        if !matches!(config.dcn, Dcn::Dcn320 | Dcn::Dcn321) {
            return Err(Error::Unsupported);
        }
        // Navi31/32/33's memory is 24 channels of 2-byte GDDR6 at up to
        // 18 GT/s (`dcn3_2_soc`); the kind is a stand-in (see the module
        // docs) and is not checked.
        if memory.channels != NUM_CHANS
            || memory.channel_width_bytes != DRAM_CHANNEL_WIDTH_BYTES
            || memory.speed_mts > MAX_DRAM_MTS
        {
            return Err(Error::Invalid);
        }
        let geometry = config.geometry()?;
        let requirements = config.requirements(&geometry, max_dispclk_khz)?;
        if requirements.dispclk_khz > MAX_DISPCLK_KHZ
            || requirements.dppclk_khz > MAX_DPPCLK_KHZ
            || requirements.deep_sleep_dcfclk_khz > MAX_DCFCLK_KHZ
        {
            return Err(Error::Unsupported);
        }
        if clocks.dcfclk_khz > MAX_DCFCLK_KHZ
            || clocks.socclk_khz > MAX_SOCCLK_KHZ
            || clocks.dispclk_khz > MAX_DISPCLK_KHZ
            || clocks.dppclk_khz > MAX_DPPCLK_KHZ
        {
            return Err(Error::Unsupported);
        }
        let watermarks = config.watermarks(memory, clocks)?;
        let prefetch = config.prefetch(&geometry, clocks, &watermarks)?;
        // No compression buffer on a no-DSC plane: `unbounded=false`,
        // `compbuf_kbytes=0`.
        let dram_change = config.dram_clock_change(&geometry, &watermarks, &prefetch, false, 0);
        Ok(Validation {
            geometry,
            requirements,
            watermarks,
            prefetch,
            dram_change,
        })
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use crate::amdgpu_dml::{Format, MemoryKind, Plane, Timing};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn mode_4k60() -> (Config, Memory, ClockState) {
        let timing = Timing {
            pixel_clock_khz: 594_000,
            h_active: 3840,
            h_total: 4400,
            h_front_porch: 176,
            h_sync_width: 88,
            v_active: 2160,
            v_total: 2250,
            v_front_porch: 8,
            v_sync_width: 10,
            h_sync_positive: false,
            v_sync_positive: false,
        };
        let plane = Plane {
            format: Format::Rgb32,
            surface_width: 3840,
            surface_height: 2160,
            viewport_width: 3840,
            viewport_height: 2160,
            pitch: 3840,
            h_taps: 1,
            v_taps: 1,
        };
        let config = Config {
            dcn: Dcn::Dcn320,
            timing,
            plane,
            dentist_vco_khz: VCO_KHZ,
            cursors: 0,
        };
        // GDDR6 has no `MemoryKind` variant; on DCN 3.2 both kinds share
        // the WM_A row, so Ddr5 is the stand-in.
        let memory = Memory {
            kind: MemoryKind::Ddr5,
            channels: NUM_CHANS,
            channel_width_bytes: DRAM_CHANNEL_WIDTH_BYTES,
            speed_mts: MAX_DRAM_MTS,
        };
        let clocks = ClockState {
            dcfclk_khz: MAX_DCFCLK_KHZ,
            fclk_khz: 1_200_000,
            socclk_khz: MAX_SOCCLK_KHZ,
            dispclk_khz: 1_950_000,
            dppclk_khz: 1_950_000,
            deep_sleep_dcfclk_khz: 800_000,
        };
        (config, memory, clocks)
    }

    fn dcn32_dml_validate_4k60() -> TestResult {
        let (config, memory, clocks) = mode_4k60();
        let v = match Dml32::validate(&config, &memory, &clocks, 1_950_000) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("DCN32 DML32 4K60 validate failed"),
        };
        // DET 256 KiB, and the DISPCLK requirement carries the downspread
        // (0.5%) and ramping (1.0%) margins above the 594 MHz pixel clock.
        if v.geometry.det_buffer_bytes != 256 * 1024 {
            return TestResult::Fail("DCN32 DML32 DET size wrong");
        }
        if v.requirements.dispclk_khz <= 594_000 || v.requirements.dispclk_khz > MAX_DISPCLK_KHZ {
            return TestResult::Fail("DCN32 DML32 DISPCLK requirement wrong");
        }
        if v.requirements.dppclk_khz > MAX_DPPCLK_KHZ {
            return TestResult::Fail("DCN32 DML32 DPPCLK requirement wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dml", dcn32_dml_validate_4k60);

    fn dcn32_dml_refuses_non_32() -> TestResult {
        let (mut config, memory, clocks) = mode_4k60();
        config.dcn = Dcn::Dcn315;
        if Dml32::validate(&config, &memory, &clocks, 1_950_000).is_ok() {
            return TestResult::Fail("DCN32 DML32 accepted a DCN 3.1.5 config");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dml", dcn32_dml_refuses_non_32);

    fn dcn32_dml_refuses_wrong_memory() -> TestResult {
        let (config, mut memory, clocks) = mode_4k60();
        memory.channels = 16;
        if Dml32::validate(&config, &memory, &clocks, 1_950_000).is_ok() {
            return TestResult::Fail("DCN32 DML32 accepted 16 DRAM channels");
        }
        memory.channels = NUM_CHANS;
        memory.speed_mts = MAX_DRAM_MTS + 1;
        if Dml32::validate(&config, &memory, &clocks, 1_950_000).is_ok() {
            return TestResult::Fail("DCN32 DML32 accepted DRAM above 18 GT/s");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dml", dcn32_dml_refuses_wrong_memory);

    fn dcn32_dml_refuses_clock_over_ceiling() -> TestResult {
        let (config, memory, mut clocks) = mode_4k60();
        clocks.dcfclk_khz = MAX_DCFCLK_KHZ + 1;
        if Dml32::validate(&config, &memory, &clocks, 1_950_000).is_ok() {
            return TestResult::Fail("DCN32 DML32 accepted DCFCLK above 1564 MHz");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dml",
        dcn32_dml_refuses_clock_over_ceiling
    );
}
