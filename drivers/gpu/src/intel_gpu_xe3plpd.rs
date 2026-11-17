//! Disconnected Display 35 (Xe3P_LPD) plane and transcoder dialect.
//!
//! Pinned source: local Linux 7.0-rc7
//! `i915/display/{intel_display.c,intel_plane.c,skl_universal_plane.c}`.
//! These helpers capture only the branches that must not inherit Display 30
//! behavior: no `TRANS_VSYNCSHIFT` write or transcoder interlace field,
//! linear horizontal reflection is allowed while Tile4 reflection is not,
//! and semiplanar YUV restores vertical 2x subsampling. They form no MMIO
//! transaction and grant no Nova Lake programming authority.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::intel_gpu_xelpg_wm::Tiling;

const TRANSCONF_ENABLE: u32 = 1 << 31;

/// The Display-35 transcoder decisions made by `intel_set_transcoder_timings`,
/// `hsw_set_transconf` and `intel_pipe_is_interlaced`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TranscoderDialect {
    /// `None`: Display 35 does not write `TRANS_VSYNCSHIFT`.
    pub(crate) vsyncshift: Option<u32>,
    /// Base `TRANSCONF`; Display 35 contributes no interlace bits.
    pub(crate) transconf: u32,
    /// Hardware state readback never reports an interlaced pipe.
    pub(crate) read_interlaced: bool,
}

/// Pure Display-35 transcoder plan. `mode_interlaced` is intentionally ignored:
/// Linux omits both progressive and interlaced `TRANSCONF` fields at version
/// 35 and `intel_pipe_is_interlaced` returns false without reading the register.
pub(crate) const fn transcoder_dialect(
    needs_modeset: bool,
    _mode_interlaced: bool,
) -> TranscoderDialect {
    TranscoderDialect {
        vsyncshift: None,
        transconf: if needs_modeset { 0 } else { TRANSCONF_ENABLE },
        read_interlaced: false,
    }
}

/// The format facts used by `intel_plane_check_src_coordinates`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaneFormat {
    Rgb565,
    /// NV12 and the P0xx semiplanar family.
    YuvSemiplanar,
    /// The format's ordinary DRM horizontal/vertical subsampling.
    Other {
        hsub: u8,
        vsub: u8,
    },
}

/// Display-35 plane source-coordinate and reflection inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaneSource {
    pub(crate) format: PlaneFormat,
    pub(crate) tiling: Tiling,
    pub(crate) reflect_x: bool,
    pub(crate) rotated_90_or_270: bool,
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

/// Effective macro-pixel alignment after Display-35 overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaneSampling {
    pub(crate) hsub: u8,
    pub(crate) vsub: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaneRefusal {
    /// Display 20+ forbids horizontal reflection of Tile4 surfaces.
    Tile4Reflection,
    InvalidFormatSubsampling,
    SourceSubsampling,
}

/// Display-35 portions of `skl_plane_check_fb` and
/// `intel_plane_check_src_coordinates`. Linear reflection is admitted; Tile4
/// reflection is refused. The returned sampling is useful to a future live
/// plane transaction, but this function itself performs no MMIO.
pub(crate) const fn check_plane(source: PlaneSource) -> Result<PlaneSampling, PlaneRefusal> {
    if source.reflect_x && matches!(source.tiling, Tiling::Tile4) {
        return Err(PlaneRefusal::Tile4Reflection);
    }

    let (mut hsub, mut vsub) = match source.format {
        PlaneFormat::Rgb565 if source.rotated_90_or_270 => (2, 2),
        // Display 20/30 temporarily use 1x1 (with an odd-x WA on those exact
        // versions); Display 35 restores vertical chroma alignment only.
        PlaneFormat::YuvSemiplanar => (1, 2),
        PlaneFormat::Rgb565 => (1, 1),
        PlaneFormat::Other { hsub, vsub } => (hsub, vsub),
    };
    if hsub == 0 || vsub == 0 {
        return Err(PlaneRefusal::InvalidFormatSubsampling);
    }
    if source.rotated_90_or_270 {
        let sub = if hsub > vsub { hsub } else { vsub };
        hsub = sub;
        vsub = sub;
    }
    if source.x % hsub as u32 != 0
        || source.width % hsub as u32 != 0
        || source.y % vsub as u32 != 0
        || source.height % vsub as u32 != 0
    {
        return Err(PlaneRefusal::SourceSubsampling);
    }
    Ok(PlaneSampling { hsub, vsub })
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn source(format: PlaneFormat, tiling: Tiling) -> PlaneSource {
        PlaneSource {
            format,
            tiling,
            reflect_x: false,
            rotated_90_or_270: false,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        }
    }

    fn smoke_nvl_display35_transcoder_omits_legacy_fields() -> TestResult {
        assert_eq!(
            transcoder_dialect(true, false),
            TranscoderDialect {
                vsyncshift: None,
                transconf: 0,
                read_interlaced: false,
            }
        );
        assert_eq!(
            transcoder_dialect(true, true),
            transcoder_dialect(true, false)
        );
        assert_eq!(transcoder_dialect(false, true).transconf, TRANSCONF_ENABLE);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_transcoder_omits_legacy_fields
    );

    fn smoke_nvl_display35_plane_reflection_and_subsampling() -> TestResult {
        let mut linear = source(PlaneFormat::Other { hsub: 1, vsub: 1 }, Tiling::Linear);
        linear.reflect_x = true;
        assert_eq!(check_plane(linear), Ok(PlaneSampling { hsub: 1, vsub: 1 }));
        assert_eq!(
            check_plane(PlaneSource {
                tiling: Tiling::Tile4,
                ..linear
            }),
            Err(PlaneRefusal::Tile4Reflection)
        );
        assert!(check_plane(PlaneSource {
            tiling: Tiling::X,
            ..linear
        })
        .is_ok());

        let mut yuv = source(PlaneFormat::YuvSemiplanar, Tiling::Linear);
        yuv.x = 1;
        yuv.width = 1919;
        assert_eq!(check_plane(yuv), Ok(PlaneSampling { hsub: 1, vsub: 2 }));
        yuv.y = 1;
        assert_eq!(check_plane(yuv), Err(PlaneRefusal::SourceSubsampling));
        yuv.y = 0;
        yuv.rotated_90_or_270 = true;
        assert_eq!(check_plane(yuv), Err(PlaneRefusal::SourceSubsampling));

        let mut rgb565 = source(PlaneFormat::Rgb565, Tiling::Linear);
        rgb565.x = 1;
        assert!(check_plane(rgb565).is_ok());
        rgb565.rotated_90_or_270 = true;
        assert_eq!(check_plane(rgb565), Err(PlaneRefusal::SourceSubsampling));
        assert_eq!(
            check_plane(source(
                PlaneFormat::Other { hsub: 0, vsub: 1 },
                Tiling::Linear,
            )),
            Err(PlaneRefusal::InvalidFormatSubsampling)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_plane_reflection_and_subsampling
    );
}
