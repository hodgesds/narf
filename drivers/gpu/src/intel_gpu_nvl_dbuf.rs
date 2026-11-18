//! Nova Lake-S Display 35 buffer allocation for unscaled XR24 primary scanout.
//!
//! Linux 7.0-rc7 selects xe2_lpd_display for GMD 35.00: four 1024-block
//! DBUF slices, adlp_allowed_dbufs and five universal planes per pipe.
//! skl_watermark.c, skl_prefill.c and intel_cdclk.c supply the per-plane
//! and per-pipe inputs. The register images describe a full modeset with
//! every pipe off. Power, PM demand and live DDB transitions have separate
//! owners.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use alloc::{boxed::Box, vec::Vec};

use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pipes::Pipe;
use crate::intel_gpu_xelpg_cdclk::{self as cdclk, Rung};
use crate::intel_gpu_xelpg_dbuf::{self as dbuf, PipeInput, PlaneInput, PIPES, PLANES};
use crate::intel_gpu_xelpg_resources::ResourceError;
use crate::intel_gpu_xelpg_wm::{self as wm, Latency, Surface, Tiling, Timing};

#[derive(Clone, Copy)]
pub(crate) struct NovaScanout {
    pub(crate) mode: Mode,
    pub(crate) tiling: Tiling,
    /// Lines available for prefill after VRR timing-generator adjustment.
    pub(crate) guardband: u16,
    pub(crate) cursor_visible: bool,
}

impl NovaScanout {
    fn pipe_input(self, latency: &Latency, active: u32) -> Result<PipeInput, ResourceError> {
        let mode = self.mode;
        // intel_mode_valid and intel_cpu_transcoder_mode_valid bound the
        // timings. The actual single-pipe XR24 plane uses xe3_plane_max_width
        // and icl_plane_max_height, including the latter's 4320-line limit.
        let hblank = mode.h_total.saturating_sub(mode.h_active);
        let vblank = mode.v_total.saturating_sub(mode.v_active);
        let horizontal = (64..=6144).contains(&mode.h_active)
            && hblank >= 32
            && mode.h_total <= 16384
            && mode.h_active < mode.h_sync_start
            && mode.h_sync_start <= mode.h_sync_end
            && mode.h_sync_end <= mode.h_total;
        let vertical = (1..=4320).contains(&mode.v_active)
            && vblank >= 5
            && mode.v_total <= 8192
            && mode.v_active <= mode.v_sync_start
            && mode.v_sync_start <= mode.v_sync_end
            && mode.v_sync_end <= mode.v_total;
        // ceil(htotal * 1000 / pixel_clock_khz) <= 64 us.
        let line_fits = u64::from(mode.h_total) * 1000 <= u64::from(mode.pixel_clock_khz) * 64;
        if !horizontal
            || !vertical
            || !line_fits
            || !(1..=vblank).contains(&self.guardband)
            || !matches!(self.tiling, Tiling::Linear | Tiling::Tile4)
        {
            return Err(ResourceError::Unsupported);
        }
        let timing = Timing {
            pixel_rate_khz: mode.pixel_clock_khz,
            htotal: mode.h_total.into(),
            vtotal: mode.v_total.into(),
            vblank_start: (mode.v_total - self.guardband).into(),
        };
        let primary = Surface {
            width: mode.h_active.into(),
            cpp: 4,
            tiling: self.tiling,
        };
        let mut primary_wm = wm::plane_display35(timing, primary, latency)?;
        let mut cursor_wm = wm::plane_display35(timing, wm::CURSOR, latency)?;
        wm::check_vblank_display35(timing, latency, &mut [&mut primary_wm, &mut cursor_wm])?;
        let mut planes = [None; PLANES];
        planes[0] = Some(PlaneInput {
            wm: primary_wm,
            rel_data_rate: u64::from(mode.h_active) * u64::from(mode.v_active) * 4,
            data_rate: mode.pixel_clock_khz * 4,
        });
        Ok(PipeInput {
            hdisplay: mode.h_active,
            planes,
            cursor_wm,
            cursor_alloc: wm::cursor_allocation_display35(timing, latency, active)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct NovaDbufPlan {
    active_pipes: u8,
    enabled_slices: u8,
    joined: bool,
    mbus_fields: u32,
    /// First display-35 clock rung meeting the supplied floor and scanout demand.
    pub(crate) clock: Rung,
    /// All plane and cursor WM/DDB images in pipe order, skipping fused pipes.
    pub(crate) plane_registers: Vec<(u64, u32)>,
}

impl NovaDbufPlan {
    /// `available_pipes` is the runtime, fuse-qualified pipe mask.
    /// Latencies are 13-bit hardware fields. Pass zero block time when
    /// SAGV is unavailable. A computed SAGV watermark alone cannot admit a
    /// memory bandwidth point.
    pub(crate) fn compute(
        scanouts: &[Option<NovaScanout>; PIPES],
        available_pipes: u8,
        raw_latency: [u16; wm::LEVELS],
        sagv_block_us: u16,
        min_cdclk_khz: u32,
    ) -> Result<Self, ResourceError> {
        if available_pipes >> PIPES != 0
            || raw_latency.iter().any(|&v| v > 0x1fff)
            || sagv_block_us > 0x1fff
        {
            return Err(ResourceError::Unsupported);
        }
        let latency = Latency::adjust_display35(raw_latency, sagv_block_us);
        let active = scanouts.iter().flatten().count() as u32;
        // The per-pipe watermarks and the resulting DDB allocations coexist
        // during allocation. Keep the four-pipe scratch array off the kernel stack.
        let mut inputs = Box::new([None; PIPES]);
        let mut floor = min_cdclk_khz;
        for (pipe, scanout) in scanouts.iter().enumerate() {
            let Some(scanout) = scanout else { continue };
            if available_pipes & (1 << pipe) == 0 {
                return Err(ResourceError::Unsupported);
            }
            inputs[pipe] = Some(scanout.pipe_input(&latency, active)?);
            // With one 4-byte primary at 1:1, two pixels per CDCLK also
            // covers the CRTC read-bandwidth floor (pixel_rate * 4 * 10 / 512).
            floor = floor.max(cdclk::pixel_rate_to_cdclk(scanout.mode.pixel_clock_khz));
        }
        let dbuf = dbuf::compute(&inputs)?;
        let clock = cdclk::calc_nova_lake_cdclk(floor.max(dbuf.bw_min_cdclk(&inputs)))
            .ok_or(ResourceError::CdclkUnsatisfiable)?;
        let mut plane_registers = Vec::new();
        for (pipe, scanout) in scanouts.iter().enumerate() {
            if available_pipes & (1 << pipe) != 0 {
                let visible = scanout.is_some_and(|s| s.cursor_visible);
                plane_registers.extend(
                    dbuf.pipe_wm_registers(pipe, visible, true)
                        .ok_or(ResourceError::Unsupported)?,
                );
            }
        }
        Ok(Self {
            active_pipes: dbuf.active_pipes,
            enabled_slices: dbuf.enabled_slices,
            joined: dbuf.joined,
            mbus_fields: cdclk::nova_lake_mbus_ctl(dbuf.mbus_ctl(), clock),
            clock,
            plane_registers,
        })
    }

    pub(crate) fn mbus_ctl(&self, old: u32) -> u32 {
        (old & !(dbuf::MBUS_CTL_MASK | cdclk::NOVA_LAKE_MBUS_THROTTLE_MASK)) | self.mbus_fields
    }

    pub(crate) fn dbuf_ctl(&self, slice: usize, old: u32) -> Option<u32> {
        if slice >= dbuf::SLICES {
            return None;
        }
        let request = if self.enabled_slices & (1 << slice) != 0 {
            dbuf::DBUF_POWER_REQUEST
        } else {
            0
        };
        Some(
            cdclk::nova_lake_dbuf_ctl(old & !dbuf::DBUF_POWER_REQUEST, self.clock, self.joined)
                | request,
        )
    }

    pub(crate) fn dbox(&self, pipe: Pipe) -> Option<u32> {
        (self.active_pipes & (1 << pipe as u8) != 0)
            .then(|| crate::intel_gpu_xe2lpd::dbox(self.joined))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn scanout() -> NovaScanout {
        NovaScanout {
            mode: Mode::VESA_1024X768_60,
            tiling: Tiling::Linear,
            guardband: 38,
            cursor_visible: false,
        }
    }

    fn reg(plan: &NovaDbufPlan, addr: u64) -> Option<u32> {
        plan.plane_registers
            .iter()
            .find(|r| r.0 == addr)
            .map(|r| r.1)
    }

    fn smoke_nvl_joined_primary_and_cursor() -> TestResult {
        let pipes = [Some(scanout()), None, None, None];
        let plan = NovaDbufPlan::compute(&pipes, 0x1, [99, 0, 0, 0, 0, 0], 20, 0).unwrap();
        assert_eq!(plan.clock.cdclk_khz, 151_200);
        assert_eq!(plan.plane_registers.len(), 65);
        // At 65 MHz, 6 us fits in one line: 1024 XR24 pixels take
        // ceil(4096/512)+1 = 9 blocks. SAGV at 26 us takes two lines.
        assert_eq!(reg(&plan, 0x70240), Some(0xa000_4009));
        assert_eq!(reg(&plan, 0x70258), Some(0xa000_8012));
        assert_eq!(reg(&plan, 0x70274), Some(0x800b_0015));
        assert_eq!(reg(&plan, 0x7027c), Some(0x0fdf_0000));
        assert_eq!(reg(&plan, 0x7017c), Some(0x0fff_0fe0));
        assert_eq!(reg(&plan, 0x70140), Some(0));
        assert_eq!(reg(&plan, 0x70674), Some(0));
        assert_eq!(plan.mbus_ctl(1), 0xdc00_a001);
        for slice in 0..4 {
            assert_eq!(plan.dbuf_ctl(slice, 0x407f_0010), Some(0x806b_0010));
        }
        assert_eq!(plan.dbuf_ctl(4, 0), None);
        assert_eq!(plan.dbox(Pipe::A), Some(0x0103_0a4c));
        assert_eq!(plan.dbox(Pipe::D), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nvl_dbuf",
        smoke_nvl_joined_primary_and_cursor
    );

    fn smoke_nvl_shared_bank_and_fused_pipes() -> TestResult {
        let b = NovaScanout {
            cursor_visible: true,
            ..scanout()
        };
        let c = NovaScanout {
            tiling: Tiling::Tile4,
            ..scanout()
        };
        let pipes = [None, Some(b), Some(c), None];
        let plan = NovaDbufPlan::compute(&pipes, 0x7, [0; 6], 0, 0).unwrap();
        assert_eq!(plan.plane_registers.len(), 3 * 65);
        // B and C split S3/S4 by width. Their hardware entries are
        // relative to that MBUS bank; each cursor reserves eight blocks.
        assert_eq!(reg(&plan, 0x7127c), Some(0x03f7_0000));
        assert_eq!(reg(&plan, 0x7117c), Some(0x03ff_03f8));
        assert_eq!(reg(&plan, 0x71140), Some(0x8000_4002));
        assert_eq!(reg(&plan, 0x7227c), Some(0x07f7_0400));
        assert_eq!(reg(&plan, 0x72240), Some(0xa001_0020));
        assert_eq!(reg(&plan, 0x72140), Some(0));
        assert_eq!(reg(&plan, 0x7027c), Some(0));
        assert_eq!(reg(&plan, 0x7327c), None);
        assert_eq!(plan.mbus_ctl(0), 0x1c00_a000);
        assert_eq!(plan.dbuf_ctl(0, 0), Some(0x8005_0000));
        assert_eq!(plan.dbuf_ctl(1, u32::MAX), Some(0x3fe5_ffff));
        assert_eq!(plan.dbuf_ctl(3, 0), Some(0x8005_0000));
        assert_eq!(plan.dbox(Pipe::B), Some(0x0103_0a48));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nvl_dbuf",
        smoke_nvl_shared_bank_and_fused_pipes
    );

    fn smoke_nvl_guardband_and_admission_limits() -> TestResult {
        let plan = |s, mask, raw, floor| {
            NovaDbufPlan::compute(&[None, None, None, s], mask, raw, 0, floor)
        };
        let pipe = scanout();
        assert_eq!(
            plan(None, 0xf, [0; 6], 0).unwrap_err(),
            ResourceError::Unsupported
        );
        assert_eq!(
            plan(Some(pipe), 7, [0; 6], 0).unwrap_err(),
            ResourceError::Unsupported
        );
        assert_eq!(
            plan(Some(pipe), 0xf, [u16::MAX; 6], 0).unwrap_err(),
            ResourceError::Unsupported
        );
        assert_eq!(
            plan(Some(pipe), 0xf, [0; 6], 787_201).unwrap_err(),
            ResourceError::CdclkUnsatisfiable
        );
        let too_wide = NovaScanout {
            mode: Mode {
                h_active: 6145,
                h_sync_start: 6160,
                h_sync_end: 6200,
                h_total: 6300,
                pixel_clock_khz: 148_500,
                ..pipe.mode
            },
            ..pipe
        };
        assert_eq!(
            plan(Some(too_wide), 8, [0; 6], 0).unwrap_err(),
            ResourceError::Unsupported
        );
        let too_tall = NovaScanout {
            mode: Mode {
                v_active: 4321,
                v_sync_start: 4325,
                v_sync_end: 4330,
                v_total: 4400,
                ..pipe.mode
            },
            ..pipe
        };
        assert_eq!(
            plan(Some(too_tall), 8, [0; 6], 0).unwrap_err(),
            ResourceError::Unsupported
        );
        // At Nova's 151.2 MHz prefill rung the fixed delay and four
        // Tile4 lines consume just over three scanlines at this timing.
        let tight = NovaScanout {
            mode: Mode {
                h_total: 1100,
                h_sync_end: 1080,
                ..pipe.mode
            },
            tiling: Tiling::Tile4,
            guardband: 3,
            ..pipe
        };
        assert_eq!(
            plan(Some(tight), 8, [0; 6], 0).unwrap_err(),
            ResourceError::VblankTooShort
        );
        let fits = NovaScanout {
            guardband: 4,
            ..tight
        };
        assert!(plan(Some(fits), 8, [0; 6], 0).is_ok());
        let plan = plan(Some(pipe), 8, [0; 6], 787_200).unwrap();
        assert_eq!(plan.clock.cdclk_khz, 787_200);
        assert_eq!(reg(&plan, 0x7327c), Some(0x07df_0000));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nvl_dbuf",
        smoke_nvl_guardband_and_admission_limits
    );

    #[test]
    fn nova_dbuf_register_fixtures() {
        assert!(matches!(
            smoke_nvl_joined_primary_and_cursor(),
            TestResult::Pass
        ));
        assert!(matches!(
            smoke_nvl_shared_bank_and_fused_pipes(),
            TestResult::Pass
        ));
        assert!(matches!(
            smoke_nvl_guardband_and_admission_limits(),
            TestResult::Pass
        ));
    }
}
