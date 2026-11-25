//! Display 35 (Xe3P_LPD) firmware primary readout and programming dialect.
//!
//! Pinned source: local Linux 7.0-rc7
//! `i915/display/{intel_display.c,intel_plane.c,skl_universal_plane.c,
//! intel_fifo_underrun.c,intel_display_regs.h,intel_fbc.c,intel_fbc_regs.h,
//! intel_display_power.c,intel_dpll_mgr.c,intel_color.c,
//! intel_color_pipeline.c}`.
//! These helpers capture only the branches that must not inherit Display 30
//! behavior: no `TRANS_VSYNCSHIFT` write or transcoder interlace field,
//! linear horizontal reflection is allowed while Tile4 reflection is not,
//! semiplanar YUV restores vertical 2x subsampling, and the four Display-35
//! underrun latches have exact decode/write-one-to-clear images.
//!
//! ## Owned modeset
//!
//! [`modeset`] and [`takeover`] run the display-14 orchestrator
//! (`intel_gpu_modeset_xelpg`) dispatched on
//! [`crate::intel_gpu_xe2lpd::DisplayIp::NovaLakeS`] over [`View`]: the
//! Pipe-A eDP on port A, with its port PLL, transmitters and signal levels on
//! the LT PHY (`intel_lt_phy_pll_enable`, `intel_lt_phy_set_signal_levels`)
//! and the display-35 CDCLK, DBUF and watermark owners (Linux 7.4-rc4). A
//! CMTG left armed by firmware is refused, as is a primary the modeset cannot
//! scan out unchanged. Nothing here has run on silicon.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::{intel_gpu_pipes::Pipe, intel_gpu_xelpg_wm::Tiling};

/// Firmware's origin-aligned, opaque linear primary, observed before GT reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FirmwarePrimary {
    pub(crate) format: crate::drm::card::PixelFormat,
    pub(crate) geometry: crate::intel_gpu_scanout::Geometry,
    pub(crate) gtt_offset: u32,
}

/// Read one Pipe A plane state under the caller's live display-35 route proof.
/// Linux 7.0-rc7 and 7.4-rc1: skl_get_initial_plane_config,
/// skl_plane_stride_mult, intel_get_pipe_src_size and skl_universal_plane_regs.h.
pub(crate) fn read_firmware_primary(
    io: &(impl crate::intel_gpu_aux::MmioWindow + ?Sized),
) -> Result<FirmwarePrimary, crate::intel_gpu_lt_phy::RouteRefusal> {
    use crate::intel_gpu_lt_phy::RouteRefusal;
    use crate::intel_gpu_pipes as pipes;
    let read = |off| {
        if !io.display_access_ok() {
            return Err(RouteRefusal::Ip(crate::intel_gpu_xe2lpd::IpError::NoDevice));
        }
        let value = io.read32(off);
        if value == u32::MAX || !io.display_access_ok() {
            Err(RouteRefusal::Ip(crate::intel_gpu_xe2lpd::IpError::NoDevice))
        } else {
            Ok(value)
        }
    };
    let pipe = Pipe::A.trans_base();
    let plane = Pipe::A.base() + pipes::PLANE_PRIMARY_OFFSET;
    // intel_ddi_get_encoder_pipes requires the port buffer as well as the
    // transcoder assignment. An armed SST transcoder alone can be stale.
    let port = crate::intel_gpu_xelpg::XeLpgPort::A;
    let ddi = read(pipe + pipes::TRANS_DDI_FUNC_CTL_OFFSET)?;
    if ddi & (0xff00_0000 | (1 << 15)) != 0x8a00_0000
        || read(port.ddi_buf_ctl())? & crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE == 0
    {
        return Err(RouteRefusal::PanelRoute);
    }
    // skl_get_initial_plane_config excludes joined CRTCs. Check Pipe A's
    // ICL_PIPE_DSS_CTL1 big/ultra and uncompressed joiner enables.
    if read(0x78000)? & ((1 << 29) | (1 << 23) | (3 << 20)) != 0 {
        return Err(RouteRefusal::PanelRoute);
    }
    let ctl = read(plane + pipes::PLANE_CTL_OFFSET)?;
    if ctl & pipes::PLANE_CTL_ENABLE == 0 {
        return Err(RouteRefusal::PrimaryDark);
    }
    // PLANE_CTL: check ICL format, render/media decompression, tiling,
    // async flip, reflection and rotation. Alpha lives in PLANE_COLOR_CTL.
    let fetch_mask = (31 << 23) | (1 << 15) | (7 << 10) | (3 << 8) | (1 << 4) | 3;
    if ctl & fetch_mask != pipes::PixelFormat::Argb8888.encode_for_plane_ctl()
        || read(plane + 0x4c)? & (3 << 4) != 0
        || read(plane + pipes::PLANE_OFFSET_OFFSET)? != 0
        || read(plane + pipes::PLANE_POS_OFFSET)? != 0
    {
        return Err(RouteRefusal::PrimaryLayout);
    }
    let size = read(plane + pipes::PLANE_SIZE_OFFSET)?;
    let src = read(pipe + pipes::PIPE_SRCSZ_OFFSET)?;
    let width = (size & 0xffff) + 1;
    let height = (size >> 16) + 1;
    let pitch = (read(plane + pipes::PLANE_STRIDE_OFFSET)? & 0xfff) * 64;
    let surface = read(plane + pipes::PLANE_SURF_OFFSET)?;
    // The armed SURF and latched SURFLIVE must name the same GGTT page.
    // Reject protected and asynchronous updates. GGTT offset zero is valid.
    if surface & 0xfff != 0 || read(plane + 0x2c)? != surface {
        return Err(RouteRefusal::PrimarySurface);
    }
    if width > 16_384
        || height > 16_384
        || size.rotate_left(16) != src
        || pitch < width * 4
        || u64::from(surface) + u64::from(height) * u64::from(pitch) > 1 << 32
    {
        return Err(RouteRefusal::PrimaryLayout);
    }
    Ok(FirmwarePrimary {
        format: if ctl & (1 << 20) == 0 {
            crate::drm::card::PixelFormat::Xrgb8888
        } else {
            crate::drm::card::PixelFormat::Xbgr8888
        },
        geometry: crate::intel_gpu_scanout::Geometry {
            width,
            height,
            pitch,
        },
        gtt_offset: surface,
    })
}

const TRANSCONF_ENABLE: u32 = 1 << 31;
/// `MTL_MEM_SS_INFO_GLOBAL`.
pub(crate) const MEM_SS_INFO_GLOBAL: u64 = 0x45700;
/// `XE3P_ECC_IMPACTING_DE`.
pub(crate) const ECC_IMPACTING_DE: u32 = 1 << 12;
/// Display 35 uses `xe3lpd_sa_info`, not Wildcat's 30.02 table.
pub(crate) const DEPROGBWLIMIT_GBPS: i64 = crate::intel_gpu_xe3lpd::DEPROGBWLIMIT_GBPS;

/// Per-pipe Display-35 underrun debug registers.
pub(crate) const UNDERRUN_DBG1_A: u64 = 0x70064;
pub(crate) const UNDERRUN_DBG2_A: u64 = 0x70068;
pub(crate) const GEN12_DCPR_STATUS_1: u64 = 0x46440;
pub(crate) const FBC_UNDERRUN_DECMPR: u32 = 1 << 27;
pub(crate) const UNDERRUN_FRAME_LINE_COUNTERS_FROZEN: u32 = 1 << 31;
pub(crate) const XE3P_UNDERRUN_PKGC: u32 = 1 << 21;

/// Source capability branches that a future Display-35 core-init/readout path
/// must not inherit from Display 30.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoreCapabilities {
    /// `intel_pch_reset_handshake` returns before touching its legacy register.
    pub(crate) pch_reset_handshake: bool,
    /// `intel_dpll_init` installs no shared manager; PLLs live in each LT PHY.
    pub(crate) shared_dplls: bool,
    /// `skl_get_config` does not read gamma/CSC enables from bottom color.
    /// This does not imply that the register is absent from commit-arm writes.
    pub(crate) read_bottom_color_enables: bool,
    /// `HAS_UNDERRUN_DBG_INFO` gates the Display-35 decoder below.
    pub(crate) underrun_debug: bool,
}

pub(crate) const CORE_CAPABILITIES: CoreCapabilities = CoreCapabilities {
    pch_reset_handshake: false,
    shared_dplls: false,
    read_bottom_color_enables: false,
    underrun_debug: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColorPlaneKind {
    Primary,
    Overlay,
    Cursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lut3dInterpolation {
    Tetrahedral,
}

/// Display-35 primary-plane colorop inserted between plane CSC and post-CSC
/// LUT. `edge_size = 17` represents 17^3 = 4913 RGB entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lut3dCapability {
    pub(crate) edge_size: u8,
    pub(crate) entries: u16,
    pub(crate) interpolation: Lut3dInterpolation,
    pub(crate) allow_bypass: bool,
}

/// `intel_color_pipeline_register_plane` plus
/// `intel_color_crtc_has_3dlut`: only primary planes on Pipes A/B receive the
/// Display-35 3D LUT colorop.
pub(crate) const fn plane_lut3d(pipe: Pipe, kind: ColorPlaneKind) -> Option<Lut3dCapability> {
    if matches!(pipe, Pipe::A | Pipe::B) && matches!(kind, ColorPlaneKind::Primary) {
        Some(Lut3dCapability {
            edge_size: 17,
            entries: 17 * 17 * 17,
            interpolation: Lut3dInterpolation::Tetrahedral,
            allow_bypass: true,
        })
    } else {
        None
    }
}

/// `UNDERRUN_DBG1(pipe)`; the source A/B addresses establish a 0x1000 stride.
pub(crate) const fn underrun_dbg1(pipe: Pipe) -> u64 {
    UNDERRUN_DBG1_A + pipe as u64 * 0x1000
}

/// `UNDERRUN_DBG2(pipe)`; the source A/B addresses establish a 0x1000 stride.
pub(crate) const fn underrun_dbg2(pipe: Pipe) -> u64 {
    UNDERRUN_DBG2_A + pipe as u64 * 0x1000
}

/// Six-plane masks decoded from `UNDERRUN_DBG1`: bit 0 is the cursor and bits
/// 1--5 are universal planes 1--5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UnderrunPlaneCauses {
    pub(crate) dbuf_block_not_valid: u8,
    pub(crate) ddb_empty: u8,
    pub(crate) dbuf_not_filled: u8,
    pub(crate) below_wm0: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnderrunCounters {
    /// Eleven-bit frame count from bits 30:20.
    pub(crate) frame: u16,
    /// Twenty-bit line count from bits 19:0.
    pub(crate) line: u32,
}

/// Decoded, latched Display-35 underrun evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UnderrunSnapshot {
    pub(crate) planes: UnderrunPlaneCauses,
    pub(crate) counters: Option<UnderrunCounters>,
    pub(crate) fbc_decompressing: bool,
    pub(crate) package_c_state_blocked_memory: bool,
}

/// Exact write-one-to-clear images. `None` means Linux performs no write for
/// that register because its corresponding latch was clear or no FBC belongs
/// to the pipe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UnderrunClear {
    pub(crate) dbg1: Option<u32>,
    pub(crate) dbg2: Option<u32>,
    pub(crate) fbc_debug: Option<u32>,
    pub(crate) dcpr_status1: Option<u32>,
}

/// Pure `read_underrun_dbg_info` decode. `fbc_debug` is `None` when
/// `intel_fbc_for_pipe` finds no FBC instance. The DBG1 clear deliberately
/// echoes the complete nonzero value, while the other three clear images carry
/// only their source W1C bit.
pub(crate) const fn underrun_snapshot(
    dbg1: u32,
    dbg2: u32,
    fbc_debug: Option<u32>,
    dcpr_status1: u32,
) -> (UnderrunSnapshot, UnderrunClear) {
    let counters_frozen = dbg2 & UNDERRUN_FRAME_LINE_COUNTERS_FROZEN != 0;
    let fbc_decompressing = match fbc_debug {
        Some(value) => value & FBC_UNDERRUN_DECMPR != 0,
        None => false,
    };
    let package_c_state_blocked_memory = dcpr_status1 & XE3P_UNDERRUN_PKGC != 0;
    (
        UnderrunSnapshot {
            planes: UnderrunPlaneCauses {
                dbuf_block_not_valid: ((dbg1 >> 24) & 0x3f) as u8,
                ddb_empty: ((dbg1 >> 16) & 0x3f) as u8,
                dbuf_not_filled: ((dbg1 >> 8) & 0x3f) as u8,
                below_wm0: (dbg1 & 0x3f) as u8,
            },
            counters: if counters_frozen {
                Some(UnderrunCounters {
                    frame: ((dbg2 >> 20) & 0x7ff) as u16,
                    line: dbg2 & 0x000f_ffff,
                })
            } else {
                None
            },
            fbc_decompressing,
            package_c_state_blocked_memory,
        },
        UnderrunClear {
            dbg1: if dbg1 != 0 { Some(dbg1) } else { None },
            dbg2: if counters_frozen {
                Some(UNDERRUN_FRAME_LINE_COUNTERS_FROZEN)
            } else {
                None
            },
            fbc_debug: if fbc_decompressing {
                Some(FBC_UNDERRUN_DECMPR)
            } else {
                None
            },
            dcpr_status1: if package_c_state_blocked_memory {
                Some(XE3P_UNDERRUN_PKGC)
            } else {
                None
            },
        },
    )
}

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

/// Integrated memory type decoded by `xelpdp_get_dram_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DramType {
    Ddr4,
    Ddr5,
    Lpddr5,
    Lpddr4,
    Ddr3,
    Lpddr3,
}

/// Display-35 facts from `MTL_MEM_SS_INFO_GLOBAL` that precede
/// `tgl_get_bw_info(..., xe3lpd_sa_info)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BandwidthProfile {
    pub(crate) dram_type: DramType,
    pub(crate) populated_channels: u8,
    pub(crate) enabled_qgv_points: u8,
    pub(crate) deprogbwlimit_gbps: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BandwidthRefusal {
    NoDevice,
    UnknownDramType(u8),
    /// Linux 7.0-rc7 warns because Bspec supplies no derating instructions.
    /// A future NARF Display-35 transaction instead refuses to invent one.
    EccImpactingDisplay,
}

/// Pure Display-35 decode/admission for `MTL_MEM_SS_INFO_GLOBAL`. Linux uses
/// `xe3lpd_sa_info` after warning on ECC that impacts display bandwidth. NARF
/// fails closed on that bit until a source-qualified derating rule exists.
pub(crate) const fn bandwidth_profile(raw: u32) -> Result<BandwidthProfile, BandwidthRefusal> {
    if raw == u32::MAX {
        return Err(BandwidthRefusal::NoDevice);
    }
    let dram_type = match (raw & 0xf) as u8 {
        0 => DramType::Ddr4,
        1 => DramType::Ddr5,
        2 => DramType::Lpddr5,
        3 => DramType::Lpddr4,
        4 => DramType::Ddr3,
        5 => DramType::Lpddr3,
        other => return Err(BandwidthRefusal::UnknownDramType(other)),
    };
    if raw & ECC_IMPACTING_DE != 0 {
        return Err(BandwidthRefusal::EccImpactingDisplay);
    }
    Ok(BandwidthProfile {
        dram_type,
        populated_channels: ((raw >> 4) & 0xf) as u8,
        enabled_qgv_points: ((raw >> 8) & 0xf) as u8,
        deprogbwlimit_gbps: DEPROGBWLIMIT_GBPS,
    })
}

// ── Owned modeset ────────────────────────────────────────────────

/// `TRANS_CMTG_CTL(TRANSCODER_A)` and its `CMTG_ENABLE`.
const TRANS_CMTG_CTL_A: u64 = 0x6fa88;
const CMTG_ENABLE: u32 = 1 << 31;
/// `TRANS_DDI_FUNC_CTL2(TRANSCODER_A)` and its `CMTG_SECONDARY_MODE`.
const TRANS_DDI_FUNC_CTL2_A: u64 = 0x60404;
const CMTG_SECONDARY_MODE: u32 = 1 << 3;

/// The display-35 register view of the owned modeset. DDI A and B's PHY and
/// AUX registers move into the PICA block as on display 20 and 30
/// (`__xe2lpd_port_idx`, [`crate::intel_gpu_xe3lpd::pica_port_reg`]), and the
/// platform's LT PHY (`HAS_LT_PHY`) is behind every port, so no Cx0
/// sequence takes it. Wa_15015404425's read flush is Lunar Lake's and early
/// Panther Lake's only. Construct it only for the exact Nova Lake-S route.
pub(crate) struct View<'a, M: MmioWindow + ?Sized>(pub(crate) &'a M);

impl<M: MmioWindow + ?Sized> MmioWindow for View<'_, M> {
    fn display_access_ok(&self) -> bool {
        self.0.display_access_ok()
    }
    fn has_lt_phy(&self) -> bool {
        true
    }
    fn read32(&self, off: u64) -> u32 {
        self.0
            .read32(crate::intel_gpu_xe3lpd::pica_port_reg(off).unwrap_or(off))
    }
    fn write32(&self, off: u64, val: u32) {
        self.0.write32(
            crate::intel_gpu_xe3lpd::pica_port_reg(off).unwrap_or(off),
            val,
        )
    }
}

/// The owned modeset's read-only admission: an LT-PHY view, display 35.00,
/// and no CMTG on transcoder A. `intel_cmtg_sanitize` retires a firmware
/// CMTG, and needs a modeset when the transcoder is its secondary; this
/// route refuses an armed one and leaves the firmware display as it is.
fn admit(mmio: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
    use crate::intel_gpu_xe2lpd::DisplayIp;
    if !mmio.has_lt_phy() || mmio.cx0_xe3() {
        return Err(ModesetError::UnsupportedGeneration);
    }
    if DisplayIp::read_all(mmio) != Ok(DisplayIp::NovaLakeS) {
        return Err(ModesetError::UnsupportedGeneration);
    }
    let cmtg = mmio.read32(TRANS_CMTG_CTL_A);
    let ctl2 = mmio.read32(TRANS_DDI_FUNC_CTL2_A);
    if cmtg == u32::MAX || ctl2 == u32::MAX || !mmio.display_access_ok() {
        return Err(ModesetError::PipelineStopUnavailable);
    }
    if cmtg & CMTG_ENABLE != 0 || ctl2 & CMTG_SECONDARY_MODE != 0 {
        return Err(ModesetError::DisplayResourceUnavailable);
    }
    Ok(())
}

fn orchestrator<M: MmioWindow + ?Sized>(
    mmio: &M,
) -> crate::intel_gpu_modeset_xelpg::XeLpgModeset<'_, M> {
    crate::intel_gpu_modeset_xelpg::XeLpgModeset::new(mmio, crate::intel_gpu_xelpg::XeLpgPort::A)
        .with_display_ip(crate::intel_gpu_xe2lpd::DisplayIp::NovaLakeS)
}

/// The display-35 owned Pipe-A eDP modeset at `mode`, or at the panel's
/// EDID preferred mode without one. `mmio` must be a [`View`].
pub(crate) fn modeset<M: MmioWindow + ?Sized>(
    mmio: &M,
    fb: &Framebuffer,
    mode: Option<&Mode>,
) -> Result<Mode, ModesetError> {
    admit(mmio)?;
    let mut ms = orchestrator(mmio);
    match mode {
        Some(mode) => ms.modeset_fixed(fb, mode),
        None => ms.modeset(fb, None),
    }
}

/// The boot option requesting the owned display-35 modeset on top of the
/// firmware route ([`crate::intel_gpu_lt_phy::OPT_IN`]).
pub(crate) const MODESET_OPT_IN: &str = "narf.intel.nvl_modeset";

/// `narf.intel.nvl_modeset=1`, with the strict grammar of Intel's other
/// destructive route gates.
pub(crate) fn modeset_requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, MODESET_OPT_IN)
}

/// Why the probe kept the firmware display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TakeoverRefusal {
    /// No VBT in the ACPI OpRegion: port A's output type is unknown.
    NoVbt,
    /// The VBT gives port A no eDP output (a desktop board may route a DP
    /// connector there); the orchestrator drives only an eDP panel.
    PortANotEdp,
    /// [`takeover`] refused or failed.
    Modeset(ModesetError),
}

/// The probe's owned-modeset step. Port A must be the VBT's eDP output
/// (`intel_dp_is_port_edp`): the orchestrator sequences the panel's PPS,
/// takes the eDP link rates and the LT PHY's eDP signal table. Then
/// [`takeover`] over `io`, the function's BAR window.
pub(crate) fn take_over_for_probe(
    io: &(impl MmioWindow + ?Sized),
    primary: &FirmwarePrimary,
    asls: Option<u32>,
) -> Result<Mode, TakeoverRefusal> {
    use crate::intel_gpu_vbt::{discover, port, VbtPlatform};
    let (vbt, _) = asls.and_then(discover).ok_or(TakeoverRefusal::NoVbt)?;
    // Display 35 takes `xelpd_port_mapping`, as Meteor Lake does.
    if !vbt
        .encoder(VbtPlatform::MeteorLake, port::A)
        .is_some_and(|encoder| encoder.edp)
    {
        return Err(TakeoverRefusal::PortANotEdp);
    }
    takeover(&View(io), primary).map_err(TakeoverRefusal::Modeset)
}

/// Take over the firmware primary in place: the owned modeset at the panel's
/// EDID preferred mode, scanning out the firmware surface unchanged. A
/// preferred mode of another size, or a primary the owned plane cannot
/// describe (only XR24 is), is refused after the AUX read and before any
/// other write; the fixed-mode route then keeps the firmware display.
pub(crate) fn takeover<M: MmioWindow + ?Sized>(
    mmio: &M,
    primary: &FirmwarePrimary,
) -> Result<Mode, ModesetError> {
    admit(mmio)?;
    if primary.format != crate::drm::card::PixelFormat::Xrgb8888 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    let fb = Framebuffer {
        phys_addr: u64::from(primary.gtt_offset),
        stride_bytes: primary.geometry.pitch,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    let mut ms = orchestrator(mmio);
    let mode = ms.preferred_mode()?;
    if (u32::from(mode.h_active), u32::from(mode.v_active))
        != (primary.geometry.width, primary.geometry.height)
    {
        return Err(ModesetError::InvalidFramebuffer);
    }
    ms.modeset_fixed(&fb, &mode)
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_xe3plpd_modeset_tests.rs"]
mod modeset_tests;

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

    fn smoke_nvl_display35_bandwidth_ecc_is_fail_closed() -> TestResult {
        assert_eq!((MEM_SS_INFO_GLOBAL, ECC_IMPACTING_DE), (0x45700, 1 << 12));
        assert_eq!(DEPROGBWLIMIT_GBPS, 65);
        assert_eq!(
            bandwidth_profile((4 << 8) | (8 << 4) | 2),
            Ok(BandwidthProfile {
                dram_type: DramType::Lpddr5,
                populated_channels: 8,
                enabled_qgv_points: 4,
                deprogbwlimit_gbps: 65,
            })
        );
        assert_eq!(
            bandwidth_profile(ECC_IMPACTING_DE | (4 << 8) | (8 << 4) | 2),
            Err(BandwidthRefusal::EccImpactingDisplay)
        );
        assert_eq!(
            bandwidth_profile(6),
            Err(BandwidthRefusal::UnknownDramType(6))
        );
        assert_eq!(bandwidth_profile(u32::MAX), Err(BandwidthRefusal::NoDevice));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_bandwidth_ecc_is_fail_closed
    );

    fn smoke_nvl_display35_underrun_decode_and_w1c_images() -> TestResult {
        assert_eq!(
            [Pipe::A, Pipe::B, Pipe::C, Pipe::D].map(underrun_dbg1),
            [0x70064, 0x71064, 0x72064, 0x73064]
        );
        assert_eq!(
            [Pipe::A, Pipe::B, Pipe::C, Pipe::D].map(underrun_dbg2),
            [0x70068, 0x71068, 0x72068, 0x73068]
        );
        assert_eq!(GEN12_DCPR_STATUS_1, 0x46440);

        let dbg1 = (1 << 24) | (2 << 16) | (4 << 8) | 8;
        let dbg2 = UNDERRUN_FRAME_LINE_COUNTERS_FROZEN | (0x3ab << 20) | 0xabcde;
        let (snapshot, clear) =
            underrun_snapshot(dbg1, dbg2, Some(FBC_UNDERRUN_DECMPR), XE3P_UNDERRUN_PKGC);
        assert_eq!(
            snapshot,
            UnderrunSnapshot {
                planes: UnderrunPlaneCauses {
                    dbuf_block_not_valid: 1,
                    ddb_empty: 2,
                    dbuf_not_filled: 4,
                    below_wm0: 8,
                },
                counters: Some(UnderrunCounters {
                    frame: 0x3ab,
                    line: 0xabcde,
                }),
                fbc_decompressing: true,
                package_c_state_blocked_memory: true,
            }
        );
        assert_eq!(
            clear,
            UnderrunClear {
                dbg1: Some(dbg1),
                dbg2: Some(1 << 31),
                fbc_debug: Some(1 << 27),
                dcpr_status1: Some(1 << 21),
            }
        );

        let (snapshot, clear) = underrun_snapshot(0, 0x7fff_ffff, None, 0);
        assert_eq!(snapshot, UnderrunSnapshot::default());
        assert_eq!(clear, UnderrunClear::default());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_underrun_decode_and_w1c_images
    );

    fn smoke_nvl_display35_core_and_color_capabilities() -> TestResult {
        assert_eq!(
            CORE_CAPABILITIES,
            CoreCapabilities {
                pch_reset_handshake: false,
                shared_dplls: false,
                read_bottom_color_enables: false,
                underrun_debug: true,
            }
        );
        let lut = Lut3dCapability {
            edge_size: 17,
            entries: 4_913,
            interpolation: Lut3dInterpolation::Tetrahedral,
            allow_bypass: true,
        };
        assert_eq!(plane_lut3d(Pipe::A, ColorPlaneKind::Primary), Some(lut));
        assert_eq!(plane_lut3d(Pipe::B, ColorPlaneKind::Primary), Some(lut));
        assert_eq!(plane_lut3d(Pipe::C, ColorPlaneKind::Primary), None);
        assert_eq!(plane_lut3d(Pipe::D, ColorPlaneKind::Primary), None);
        assert_eq!(plane_lut3d(Pipe::A, ColorPlaneKind::Overlay), None);
        assert_eq!(plane_lut3d(Pipe::A, ColorPlaneKind::Cursor), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_core_and_color_capabilities
    );

    use crate::intel_gpu_xe2lpd::DisplayIp;
    use crate::intel_gpu_xelpg_cdclk::{self as cdclk, Current, Step};
    use crate::intel_gpu_xelpg_resources as res;
    use crate::intel_gpu_xelpg_wm::{self as wm, Latency};

    /// A register file that only answers reads.
    struct Regs(alloc::collections::BTreeMap<u64, u32>);
    impl crate::intel_gpu_aux::MmioWindow for Regs {
        fn read32(&self, off: u64) -> u32 {
            self.0.get(&off).copied().unwrap_or(0)
        }
        fn write32(&self, _: u64, _: u32) {}
    }

    /// 35.00 is admitted only by the widened decoder; it shares every
    /// display-30 branch and takes the `xe3p_lpd_cdclk_table`.
    fn smoke_nvl_display35_ip_dispatch() -> TestResult {
        let gmd = 35 << 22;
        assert_eq!(DisplayIp::decode_all(gmd), Ok(DisplayIp::NovaLakeS));
        assert!(DisplayIp::decode(gmd).is_err());
        let ip = DisplayIp::NovaLakeS;
        assert_eq!(ip.ver(), 35);
        assert!(ip.is_display30() && ip.is_display35() && ip.xe2_plus());
        assert!(!DisplayIp::Xe3Lpd.is_display35());
        assert_eq!(ip.pipe_count(), 4);
        assert_eq!(cdclk::max_cdclk_khz(ip), 787_200);
        assert_eq!(cdclk::voltage_level_ip(ip, 787_200), 0);
        for khz in [0, 151_200, 300_000, 787_200] {
            assert_eq!(
                cdclk::calc_cdclk_ip(ip, khz),
                cdclk::calc_nova_lake_cdclk(khz)
            );
        }
        assert_eq!(cdclk::calc_cdclk_ip(ip, 787_201), None);
        let low = cdclk::calc_cdclk_ip(ip, 0).unwrap();
        assert_eq!(
            (low.cdclk_khz, low.ratio, low.waveform),
            (151_200, 21, 0xa4a4)
        );
        assert_eq!(
            cdclk::ctl_value_ip(ip, low),
            crate::intel_gpu_xe2lpd::MDCLK_SOURCE_SEL_CDCLK_PLL
        );
        // Wa_13012396614 covers 35.00: CD2XCLK before the PLL disable.
        let unknown = Current {
            known: None,
            pll: 0x8000_0022,
            squash: 0,
            ctl: 0x0200_0517,
            actual_khz: 652_800,
        };
        assert_eq!(
            cdclk::plan_ip(ip, &unknown, low),
            alloc::vec![
                Step::MdclkCd2x,
                Step::PllDisable,
                Step::PllEnable { ratio: 21 },
                Step::Squash { waveform: 0xa4a4 },
                Step::Ctl { value: 1 << 25 },
            ]
        );
        assert_eq!(
            crate::intel_gpu_pmdemand::Layout::for_ip(ip),
            crate::intel_gpu_pmdemand::Layout::Xe3
        );
        assert_eq!(
            crate::intel_gpu_xe3lpd::parent(ip, crate::intel_gpu_xe3lpd::Well::PwB),
            Some(crate::intel_gpu_xe3lpd::Well::Pw1)
        );
        assert!(crate::intel_gpu_xe3lpd::dc_off_domains(ip)
            .contains(&crate::intel_gpu_xe3lpd::Domain::Aux));
        // No external route drives an LT port.
        let profile = crate::intel_gpu_xelpg_external::ExternalDisplayProfile::for_ip(ip);
        for port in [
            crate::intel_gpu_xelpg::XeLpgPort::A,
            crate::intel_gpu_xelpg::XeLpgPort::B,
            crate::intel_gpu_xelpg::XeLpgPort::Tc1,
            crate::intel_gpu_xelpg::XeLpgPort::Tc2,
        ] {
            assert!(!profile.admits_port(port));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_ip_dispatch
    );

    /// `narf.intel.nvl_modeset=1` is its own strict option: the firmware
    /// route's option does not request it.
    fn smoke_nvl_modeset_opt_in_grammar() -> TestResult {
        use narf_boot::args::KernelCmdline;
        assert!(modeset_requested(KernelCmdline::new(
            "quiet narf.intel.nvl_display=1 narf.intel.nvl_modeset=1"
        )));
        for line in [
            "",
            "narf.intel.nvl_display=1",
            "narf.intel.nvl_modeset",
            "narf.intel.nvl_modeset=0",
            "narf.intel.nvl_modeset=01",
            "-- narf.intel.nvl_modeset=1",
            "narf.intel.nvl_modeset=1 narf.intel.nvl_modeset=1",
        ] {
            assert!(!modeset_requested(KernelCmdline::new(line)), "{line}");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_modeset_opt_in_grammar
    );

    /// Display 35 reads its latencies without the reported level 0, and its
    /// QGV decode takes Wa_16030862157 and refuses ECC that costs display
    /// bandwidth; display 30 keeps the raw level 0 and the 8-channel cap.
    fn smoke_nvl_display35_latency_and_qgv() -> TestResult {
        let lpddr5_16ch = (2 << 8) | (0xf << 4) | 2;
        let regs = Regs(
            [
                (wm::LATENCY_REGS[0], (4 << 16) | 9),
                (wm::LATENCY_REGS[1], (12 << 16) | 8),
                (wm::LATENCY_REGS[2], (30 << 16) | 20),
                (wm::LATENCY_SAGV, 11),
                (crate::intel_gpu_xelpg_bw::MEM_SS_INFO_GLOBAL, lpddr5_16ch),
                (crate::intel_gpu_xelpg_bw::QGV_POINT_BASE, 0x0a0a_0060),
                (crate::intel_gpu_xelpg_bw::QGV_POINT_BASE + 4, 0x0000_2010),
                (crate::intel_gpu_xelpg_bw::QGV_POINT_BASE + 8, 0x0a0a_0080),
                (crate::intel_gpu_xelpg_bw::QGV_POINT_BASE + 12, 0x0000_2010),
            ]
            .into_iter()
            .collect(),
        );
        let nova = Latency::read_ip(&regs, DisplayIp::NovaLakeS).unwrap();
        let ptl = Latency::read_ip(&regs, DisplayIp::Xe3Lpd).unwrap();
        // Level 0 dropped: WaWmMemoryReadLatency adds 6 us to every level.
        assert_eq!(nova.levels, [6, 10, 14, 18, 26, 36]);
        assert_eq!(ptl.levels, [9, 9, 9, 12, 20, 30]);
        assert_eq!(nova.sagv_block_us, 11);
        let (n, p) = (nova.qgv.unwrap(), ptl.qgv.unwrap());
        assert_eq!((n.num_channels, n.max_numchannels), (16, 16));
        assert_eq!((p.num_channels, p.max_numchannels), (15, 8));
        let mut ecc = regs;
        ecc.0.insert(
            crate::intel_gpu_xelpg_bw::MEM_SS_INFO_GLOBAL,
            lpddr5_16ch | ECC_IMPACTING_DE,
        );
        assert_eq!(
            Latency::read_ip(&ecc, DisplayIp::NovaLakeS),
            Err(narf_filesystem::FsError::Unsupported)
        );
        assert!(Latency::read_ip(&ecc, DisplayIp::Xe3Lpd).is_ok());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_latency_and_qgv
    );

    /// The operational resource computation on display 35 agrees with the
    /// display-35 buffer plan for one unscaled XR24 primary: CDCLK, every
    /// plane/cursor WM and DDB image, the DBUF trackers and the DBOX.
    fn smoke_nvl_display35_resource_state_matches_dbuf_plan() -> TestResult {
        use crate::intel_gpu_modeset::Mode;
        use crate::intel_gpu_nvl_dbuf::{NovaDbufPlan, NovaScanout};
        let mode = Mode::VESA_1024X768_60;
        let guardband = 38;
        let raw = [99, 0, 0, 0, 0, 0];
        let plan = NovaDbufPlan::compute(
            &[
                Some(NovaScanout {
                    mode,
                    tiling: Tiling::Linear,
                    guardband,
                    cursor_visible: false,
                }),
                None,
                None,
                None,
            ],
            0xf,
            raw,
            20,
            0,
        )
        .unwrap();
        let latency = Latency::adjust_display35(raw, 20);
        let mut request = crate::intel_gpu_display_resources::request(&mode, Tiling::Linear, 0);
        if let Some(pipe) = request.pipes[0].as_mut() {
            pipe.combo_phy = None;
        }
        let state = res::compute_ip_vblank(
            DisplayIp::NovaLakeS,
            &request,
            &latency,
            [Some(mode.v_total - guardband), None, None, None],
        )
        .unwrap();
        assert_eq!(state.cdclk, plan.clock);
        assert_eq!(state.ip, DisplayIp::NovaLakeS);
        let registers = state.plane_registers().unwrap();
        assert_eq!(registers.len(), plan.plane_registers.len());
        for (reg, value) in &plan.plane_registers {
            assert_eq!(
                registers.iter().find(|(r, _)| r == reg).map(|(_, v)| *v),
                Some(*value),
                "{reg:#x}"
            );
        }
        for slice in 0..4 {
            assert_eq!(
                Some(state.dbuf_ctl(slice, 0x407f_0010, state.dbuf.enabled_slices)),
                plan.dbuf_ctl(slice, 0x407f_0010)
            );
        }
        assert_eq!(Some(state.dbox(0)), plan.dbox(Pipe::A));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe3plpd",
        smoke_nvl_display35_resource_state_matches_dbuf_plan
    );
}
